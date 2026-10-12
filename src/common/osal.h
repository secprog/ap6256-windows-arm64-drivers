/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include <ntddk.h>

typedef KMUTEX AP6256_LOCK, *PAP6256_LOCK;

FORCEINLINE
VOID
Ap6256LockInit(_Out_ PAP6256_LOCK Lock)
{
    KeInitializeMutex(Lock, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
FORCEINLINE
VOID
Ap6256LockAcquire(_Inout_ PAP6256_LOCK Lock)
{

    (VOID)KeWaitForSingleObject(Lock, Executive, KernelMode, FALSE, NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
FORCEINLINE
VOID
Ap6256LockRelease(_Inout_ PAP6256_LOCK Lock)
{
    (VOID)KeReleaseMutex(Lock, FALSE);
}

typedef VOID AP6256_WORKITEM_ROUTINE(_In_ PVOID Context);
typedef AP6256_WORKITEM_ROUTINE *PAP6256_WORKITEM_ROUTINE;

typedef struct _AP6256_WORKITEM {
    PIO_WORKITEM             Item;
    PDEVICE_OBJECT           DeviceObject;
    PAP6256_WORKITEM_ROUTINE Routine;
    PVOID                    Context;

    volatile LONG            Pending;
    volatile LONG            Outstanding;
    KEVENT                   Idle;

    WORK_QUEUE_TYPE          Queue;
} AP6256_WORKITEM, *PAP6256_WORKITEM;

FORCEINLINE
VOID
Ap6256WorkItemMakeCritical(_Inout_ PAP6256_WORKITEM WorkItem)
{
    WorkItem->Queue = CriticalWorkQueue;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256WorkItemCreate(_Out_ PAP6256_WORKITEM WorkItem,
                     _In_ PDEVICE_OBJECT DeviceObject,
                     _In_ PAP6256_WORKITEM_ROUTINE Routine,
                     _In_opt_ PVOID Context);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256WorkItemEnqueue(_Inout_ PAP6256_WORKITEM WorkItem);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WorkItemFlush(_Inout_ PAP6256_WORKITEM WorkItem);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WorkItemDestroy(_Inout_ PAP6256_WORKITEM WorkItem);

FORCEINLINE
BOOLEAN
Ap6256WorkItemValid(_In_ const AP6256_WORKITEM *WorkItem)
{
    return (WorkItem->Item != NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256RegQueryValue(_In_ PDEVICE_OBJECT Pdo,
                    _In_ PCWSTR ValueName,
                    _In_ ULONG BufferLength,
                    _Out_writes_bytes_to_opt_(BufferLength, *ValueLength) PVOID Buffer,
                    _Out_opt_ PULONG ValueLength,
                    _Out_opt_ PULONG ValueType);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256RegQueryUnicodeString(_In_ PDEVICE_OBJECT Pdo,
                            _In_ PCWSTR ValueName,
                            _Inout_ PUNICODE_STRING Value);

typedef struct _AP6256_TIMER {
    KTIMER          Timer;
    KDPC            Dpc;
    AP6256_WORKITEM Work;

    volatile LONG   Armed;
} AP6256_TIMER, *PAP6256_TIMER;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256TimerCreate(_Out_ PAP6256_TIMER Timer,
                  _In_ PDEVICE_OBJECT DeviceObject,
                  _In_ PAP6256_WORKITEM_ROUTINE Routine,
                  _In_opt_ PVOID Context);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256TimerStart(_Inout_ PAP6256_TIMER Timer, _In_ ULONG DueTimeMs);

_When_(Wait != FALSE, _IRQL_requires_max_(PASSIVE_LEVEL))
_When_(Wait == FALSE, _IRQL_requires_max_(DISPATCH_LEVEL))
VOID
Ap6256TimerStop(_Inout_ PAP6256_TIMER Timer, _In_ BOOLEAN Wait);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256TimerDestroy(_Inout_ PAP6256_TIMER Timer);

FORCEINLINE
BOOLEAN
Ap6256TimerValid(_In_ const AP6256_TIMER *Timer)
{
    return Ap6256WorkItemValid(&Timer->Work);
}
