/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ap6256.h"
#include "public.h"
#include "kmdf_driver.h"
#include "bcdc.h"
#include "datapath.h"
#include "version.h"
#include "buildstamp.h"

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL Ap6256EvtIoDeviceControl;
static EVT_WDF_OBJECT_CONTEXT_CLEANUP Ap6256EvtDeviceCryptoCleanup;
static EVT_WDF_OBJECT_CONTEXT_CLEANUP Ap6256EvtDriverTraceCleanup;

_Use_decl_annotations_
static VOID Ap6256EvtDriverTraceCleanup(WDFOBJECT Object)
{
    UNREFERENCED_PARAMETER(Object);
    Ap6256TraceCleanup();
}

_Use_decl_annotations_
static VOID Ap6256EvtDeviceCryptoCleanup(WDFOBJECT Object)
{

    Ap6256HostCipherStoreClose(&Ap6256GetDeviceContext((WDFDEVICE)Object)->HostCipherStore);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Ap6256EvtDeviceAdd)
#endif

_Use_decl_annotations_
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_OBJECT_ATTRIBUTES attributes;
    NTSTATUS status;

    status = Ap6256TraceInitialize();
    if (!NT_SUCCESS(status))
        TraceWarn(TRACE_DRIVER, "ETW registration failed 0x%08X\n", status);

    TraceDiag("v%s built %s loading\n", AP6256_VER_STR, AP6256_BUILD_STAMP);

    WDF_DRIVER_CONFIG_INIT(&config, Ap6256EvtDeviceAdd);
    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.EvtCleanupCallback = Ap6256EvtDriverTraceCleanup;
    attributes.ExecutionLevel = WdfExecutionLevelPassive;

    status = WdfDriverCreate(DriverObject, RegistryPath, &attributes,
                             &config, WDF_NO_HANDLE);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "WdfDriverCreate failed 0x%08X\n", status);
        Ap6256TraceCleanup();
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256EvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDF_PNPPOWER_EVENT_CALLBACKS pnpCallbacks;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFDEVICE device;
    PAP6256_DEVICE_CONTEXT ctx;
    WDF_IO_QUEUE_CONFIG queueConfig;

    UNREFERENCED_PARAMETER(Driver);
    PAGED_CODE();

    WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpCallbacks);
    pnpCallbacks.EvtDevicePrepareHardware = Ap6256EvtPrepareHardware;
    pnpCallbacks.EvtDeviceReleaseHardware = Ap6256EvtReleaseHardware;
    pnpCallbacks.EvtDeviceD0Entry         = Ap6256EvtD0Entry;
    pnpCallbacks.EvtDeviceD0EntryPostInterruptsEnabled = Ap6256EvtD0EntryPostInterruptsEnabled;
    pnpCallbacks.EvtDeviceD0Exit          = Ap6256EvtD0Exit;
    WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpCallbacks);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_NETWORK);

    status = Ap6256ModelDeviceInitConfig(DeviceInit);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "NetDeviceInitConfig failed 0x%08X\n", status);
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, AP6256_DEVICE_CONTEXT);

    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    attributes.EvtCleanupCallback = Ap6256EvtDeviceCryptoCleanup;

    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "WdfDeviceCreate failed 0x%08X\n", status);
        return status;
    }

    ctx = Ap6256GetDeviceContext(device);
    RtlZeroMemory(ctx, sizeof(*ctx));
    ctx->Device = device;
    ctx->Sdio.Function1BlockSize = AP6256_F1_BLOCKSIZE;
    ctx->Sdio.Function2BlockSize = AP6256_F2_BLOCKSIZE;
    ctx->FirmwareState = Ap6256FwNotLoaded;

    ctx->Fdo        = WdfDeviceWdmGetDeviceObject(device);
    ctx->Pdo        = WdfDeviceWdmGetPhysicalDevice(device);
    ctx->NextDevice = WdfDeviceWdmGetAttachedDevice(device);
    Ap6256TraceLoadDebugSettings(ctx->Pdo);
    TraceDiag("v%s built %s device initialized, WinDbg level selected\n",
              AP6256_VER_STR, AP6256_BUILD_STAMP);

    Ap6256LockInit(&ctx->Sdio.Lock);
    Ap6256LockInit(&ctx->Sdio.TxLock);
    Ap6256LockInit(&ctx->Bcdc.Lock);
    Ap6256LockInit(&ctx->TdlsLock);
    Ap6256LockInit(&ctx->PnoLock);
    Ap6256LockInit(&ctx->WlfcLifetimeLock);
    KeInitializeSpinLock(&ctx->Sdio.TxStateLock);
    KeInitializeSpinLock(&ctx->HostFipsLock);
    KeInitializeMutex(&ctx->HostCipherControlLock, 0);
    status = Ap6256HostCipherStoreInit(&ctx->HostCipherStore);
    if (!NT_SUCCESS(status)) {

        TraceError(TRACE_DRIVER, "host cipher provider unavailable 0x%08X\n", status);
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = Ap6256EvtIoDeviceControl;
    status = WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, NULL);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "WdfIoQueueCreate failed 0x%08X\n", status);
        return status;
    }

    status = WdfDeviceCreateDeviceInterface(device, &GUID_DEVINTERFACE_AP6256, NULL);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "CreateDeviceInterface failed 0x%08X\n", status);
        return status;
    }

    status = Ap6256ModelDeviceCreateAdapter(ctx);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "NetAdapterCreate failed 0x%08X\n", status);
        return status;
    }

#if defined(AP6256_ENABLE_WIFICX)
    {
        WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS idle;
        WDF_DEVICE_POWER_POLICY_WAKE_SETTINGS wake;
        WDF_DEVICE_POWER_POLICY_IDLE_SETTINGS_INIT(&idle, IdleCanWakeFromS0);
        idle.DxState = PowerDeviceD2;
        status = WdfDeviceAssignS0IdleSettings(device, &idle);
        if (!NT_SUCCESS(status)) return status;
        WDF_DEVICE_POWER_POLICY_WAKE_SETTINGS_INIT(&wake);
        wake.DxState = PowerDeviceD2;
        status = WdfDeviceAssignSxWakeSettings(device, &wake);
        if (!NT_SUCCESS(status)) return status;
    }
#endif
    TraceInfo(TRACE_DRIVER, "device added\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Ap6256EvtIoDeviceControl(WDFQUEUE Queue, WDFREQUEST Request, size_t OutputBufferLength,
                              size_t InputBufferLength, ULONG IoControlCode)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(WdfIoQueueGetDevice(Queue));
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PVOID outBuf = NULL;
    size_t outLen = 0;
    ULONG_PTR info = 0;

    UNREFERENCED_PARAMETER(InputBufferLength);

    switch (IoControlCode) {
    case IOCTL_AP6256_GET_CHIP_INFO:
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(AP6256_CHIP_INFO), &outBuf, &outLen);
        if (NT_SUCCESS(status) && outLen >= sizeof(AP6256_CHIP_INFO)) {
            PAP6256_CHIP_INFO ci = (PAP6256_CHIP_INFO)outBuf;
            RtlZeroMemory(ci, sizeof(*ci));
            ci->ChipId = ctx->Chip.ChipId;
            ci->ChipRev = ctx->Chip.ChipRev;
            ci->RamBase = ctx->Chip.RamBase;
            ci->RamSize = ctx->Chip.RamSize;
            ci->CoreCount = ctx->Chip.CoreCount;
            ci->FirmwareState = (UINT32)ctx->FirmwareState;
            RtlCopyMemory(ci->Name, ctx->Chip.Name, sizeof(ci->Name));
            info = sizeof(*ci);
        }
        break;

    case IOCTL_AP6256_GET_MAC:
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(ctx->MacAddress), &outBuf, &outLen);
        if (NT_SUCCESS(status) && outLen >= sizeof(ctx->MacAddress)) {
            RtlCopyMemory(outBuf, ctx->MacAddress, sizeof(ctx->MacAddress));
            info = sizeof(ctx->MacAddress);
        }
        break;

    case IOCTL_AP6256_GET_FW_STATE:
        status = WdfRequestRetrieveOutputBuffer(Request, sizeof(UINT32), &outBuf, &outLen);
        if (NT_SUCCESS(status) && outLen >= sizeof(UINT32)) {
            *(UINT32*)outBuf = (UINT32)ctx->FirmwareState;
            info = sizeof(UINT32);
        }
        break;

    default:
        break;
    }

    UNREFERENCED_PARAMETER(OutputBufferLength);
    WdfRequestCompleteWithInformation(Request, status, info);
}
