/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "osal.h"

#define AP6256_OSAL_POOL_TAG  '6256'

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Ap6256WorkItemCreate)
#pragma alloc_text(PAGE, Ap6256WorkItemFlush)
#pragma alloc_text(PAGE, Ap6256WorkItemDestroy)
#pragma alloc_text(PAGE, Ap6256RegQueryValue)
#pragma alloc_text(PAGE, Ap6256RegQueryUnicodeString)
#pragma alloc_text(PAGE, Ap6256TimerCreate)
#pragma alloc_text(PAGE, Ap6256TimerDestroy)
#endif

static IO_WORKITEM_ROUTINE Ap6256WorkItemThunk;

static VOID
Ap6256WorkItemThunk(_In_ PDEVICE_OBJECT DeviceObject, _In_opt_ PVOID Context)
{
    PAP6256_WORKITEM workItem = (PAP6256_WORKITEM)Context;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (workItem == NULL) {
        return;
    }

    InterlockedExchange(&workItem->Pending, 0);

    workItem->Routine(workItem->Context);

    KeSetEvent(&workItem->Idle, IO_NO_INCREMENT, FALSE);
    InterlockedDecrement(&workItem->Outstanding);
}

_Use_decl_annotations_
NTSTATUS
Ap6256WorkItemCreate(PAP6256_WORKITEM WorkItem, PDEVICE_OBJECT DeviceObject,
                     PAP6256_WORKITEM_ROUTINE Routine, PVOID Context)
{
    PAGED_CODE();

    RtlZeroMemory(WorkItem, sizeof(*WorkItem));

    WorkItem->Item = IoAllocateWorkItem(DeviceObject);
    if (WorkItem->Item == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    WorkItem->DeviceObject = DeviceObject;
    WorkItem->Routine = Routine;
    WorkItem->Context = Context;

    KeInitializeEvent(&WorkItem->Idle, SynchronizationEvent, FALSE);
    WorkItem->Queue = DelayedWorkQueue;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
Ap6256WorkItemEnqueue(PAP6256_WORKITEM WorkItem)
{
    if (WorkItem->Item == NULL) {
        return;
    }

    if (InterlockedExchange(&WorkItem->Pending, 1) != 0) {
        return;
    }

    InterlockedIncrement(&WorkItem->Outstanding);

    IoQueueWorkItem(WorkItem->Item, Ap6256WorkItemThunk, WorkItem->Queue, WorkItem);
}

_Use_decl_annotations_
VOID
Ap6256WorkItemFlush(PAP6256_WORKITEM WorkItem)
{
    LARGE_INTEGER timeout;

    PAGED_CODE();

    if (WorkItem->Item == NULL) {
        return;
    }

    timeout.QuadPart = -(50 * 10 * 1000);
    while (InterlockedCompareExchange(&WorkItem->Outstanding, 0, 0) != 0) {
        (VOID)KeWaitForSingleObject(&WorkItem->Idle, Executive, KernelMode,
                                    FALSE, &timeout);
    }
}

_Use_decl_annotations_
VOID
Ap6256WorkItemDestroy(PAP6256_WORKITEM WorkItem)
{
    PAGED_CODE();

    if (WorkItem->Item == NULL) {
        return;
    }

    Ap6256WorkItemFlush(WorkItem);

    IoFreeWorkItem(WorkItem->Item);
    WorkItem->Item = NULL;
    WorkItem->DeviceObject = NULL;
    WorkItem->Routine = NULL;
    WorkItem->Context = NULL;
}

_Use_decl_annotations_
NTSTATUS
Ap6256RegQueryValue(PDEVICE_OBJECT Pdo, PCWSTR ValueName, ULONG BufferLength,
                    PVOID Buffer, PULONG ValueLength, PULONG ValueType)
{
    HANDLE key = NULL;
    UNICODE_STRING name;
    PKEY_VALUE_PARTIAL_INFORMATION info = NULL;
    ULONG infoLength;
    ULONG resultLength = 0;
    NTSTATUS status;

    PAGED_CODE();

    if (ValueLength != NULL) {
        *ValueLength = 0;
    }
    if (ValueType != NULL) {
        *ValueType = REG_NONE;
    }

    status = IoOpenDeviceRegistryKey(Pdo, PLUGPLAY_REGKEY_DRIVER, KEY_READ, &key);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    infoLength = FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) + BufferLength;
    info = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePool2(
        POOL_FLAG_PAGED, infoLength, AP6256_OSAL_POOL_TAG);
    if (info == NULL) {
        ZwClose(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&name, ValueName);
    status = ZwQueryValueKey(key, &name, KeyValuePartialInformation,
                             info, infoLength, &resultLength);
    ZwClose(key);

    if (NT_SUCCESS(status)) {
        if (ValueType != NULL) {
            *ValueType = info->Type;
        }
        if (info->DataLength > BufferLength) {
            status = STATUS_BUFFER_OVERFLOW;
        } else {
            if (Buffer != NULL && info->DataLength != 0) {
                RtlCopyMemory(Buffer, info->Data, info->DataLength);
            }
            if (ValueLength != NULL) {
                *ValueLength = info->DataLength;
            }
        }
    }

    ExFreePoolWithTag(info, AP6256_OSAL_POOL_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS
Ap6256RegQueryUnicodeString(PDEVICE_OBJECT Pdo, PCWSTR ValueName,
                            PUNICODE_STRING Value)
{
    ULONG length = 0;
    ULONG type = REG_NONE;
    NTSTATUS status;

    PAGED_CODE();

    Value->Length = 0;

    status = Ap6256RegQueryValue(Pdo, ValueName, Value->MaximumLength,
                                 Value->Buffer, &length, &type);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (type != REG_SZ && type != REG_EXPAND_SZ) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    if ((length % sizeof(WCHAR)) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    while (length >= sizeof(WCHAR) &&
           Value->Buffer[(length / sizeof(WCHAR)) - 1] == L'\0') {
        length -= sizeof(WCHAR);
    }

    Value->Length = (USHORT)length;
    return STATUS_SUCCESS;
}

static KDEFERRED_ROUTINE Ap6256TimerDpc;

_Use_decl_annotations_
static VOID
Ap6256TimerDpc(PKDPC Dpc, PVOID Context, PVOID Arg1, PVOID Arg2)
{
    PAP6256_TIMER timer = (PAP6256_TIMER)Context;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Arg1);
    UNREFERENCED_PARAMETER(Arg2);

    if (timer == NULL) {
        return;
    }

    if (InterlockedExchange(&timer->Armed, 0) != 0) {
        Ap6256WorkItemEnqueue(&timer->Work);
    }
}

_Use_decl_annotations_
NTSTATUS
Ap6256TimerCreate(PAP6256_TIMER Timer, PDEVICE_OBJECT DeviceObject,
                  PAP6256_WORKITEM_ROUTINE Routine, PVOID Context)
{
    NTSTATUS status;

    PAGED_CODE();

    RtlZeroMemory(Timer, sizeof(*Timer));
    status = Ap6256WorkItemCreate(&Timer->Work, DeviceObject, Routine, Context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    KeInitializeTimer(&Timer->Timer);
    KeInitializeDpc(&Timer->Dpc, Ap6256TimerDpc, Timer);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
Ap6256TimerStart(PAP6256_TIMER Timer, ULONG DueTimeMs)
{
    LARGE_INTEGER due;

    if (!Ap6256WorkItemValid(&Timer->Work)) {
        return;
    }

    due.QuadPart = -((LONGLONG)DueTimeMs * 10000);
    InterlockedExchange(&Timer->Armed, 1);
    (VOID)KeSetTimer(&Timer->Timer, due, &Timer->Dpc);
}

_Use_decl_annotations_
VOID
Ap6256TimerStop(PAP6256_TIMER Timer, BOOLEAN Wait)
{
    if (!Ap6256WorkItemValid(&Timer->Work)) {
        return;
    }

    InterlockedExchange(&Timer->Armed, 0);
    (VOID)KeCancelTimer(&Timer->Timer);

    if (Wait) {

        KeFlushQueuedDpcs();
        Ap6256WorkItemFlush(&Timer->Work);
    }
}

_Use_decl_annotations_
VOID
Ap6256TimerDestroy(PAP6256_TIMER Timer)
{
    PAGED_CODE();

    Ap6256TimerStop(Timer, TRUE);
    Ap6256WorkItemDestroy(&Timer->Work);
}
