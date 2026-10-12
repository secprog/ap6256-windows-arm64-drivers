/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ap6256.h"

#include "sdio.h"
#include "chip.h"
#include "firmware.h"
#include "bcdc.h"
#include "datapath.h"
#include "wifi_ops.h"
#include "../common/netadapter.h"
#include "wdi_tal.h"
#include "version.h"
#include "buildstamp.h"
#include "model.h"

typedef struct _AP6256_HANG_DIAGNOSIS {
    KSPIN_LOCK Lock;
    AP6256_FW_CRASH Crash;
} AP6256_HANG_DIAGNOSIS;
static AP6256_HANG_DIAGNOSIS Ap6256HangDiagnosis;

VOID Ap6256ModelRecordFirmwareCrash(PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    KeAcquireSpinLock(&Ap6256HangDiagnosis.Lock, &irql);
    Ap6256HangDiagnosis.Crash = Ctx->FirmwareCrash;
    KeReleaseSpinLock(&Ap6256HangDiagnosis.Lock, irql);
}

static NDIS_HANDLE Ap6256MiniportDriverHandle = NULL;

static MINIPORT_SET_OPTIONS                Ap6256NdisSetOptions;

static MINIPORT_UNLOAD                     Ap6256NdisUnload;
static MINIPORT_OID_REQUEST                Ap6256NdisOidRequest;
static MINIPORT_RESET                      Ap6256NdisResetEx;
static MINIPORT_DEVICE_PNP_EVENT_NOTIFY    Ap6256NdisDevicePnPEventNotify;
static MINIPORT_SHUTDOWN                   Ap6256NdisShutdownEx;
static MINIPORT_CANCEL_OID_REQUEST         Ap6256NdisCancelOidRequest;
static MINIPORT_DIRECT_OID_REQUEST         Ap6256NdisDirectOidRequest;
static MINIPORT_CANCEL_DIRECT_OID_REQUEST  Ap6256NdisCancelDirectOidRequest;

static MINIPORT_WDI_ALLOCATE_ADAPTER         Ap6256WdiAllocateAdapter;
static MINIPORT_WDI_FREE_ADAPTER             Ap6256WdiFreeAdapter;
static MINIPORT_WDI_OPEN_ADAPTER             Ap6256WdiOpenAdapter;
static MINIPORT_WDI_CLOSE_ADAPTER            Ap6256WdiCloseAdapter;
static MINIPORT_WDI_START_ADAPTER_OPERATION  Ap6256WdiStartOperation;
static MINIPORT_WDI_STOP_ADAPTER_OPERATION   Ap6256WdiStopOperation;
static MINIPORT_WDI_TAL_TXRX_INITIALIZE      Ap6256WdiTalTxRxInitialize;
static MINIPORT_WDI_TAL_TXRX_DEINITIALIZE    Ap6256WdiTalTxRxDeinitialize;
static MINIPORT_WDI_ADAPTER_HANG_DIAGNOSE    Ap6256WdiHangDiagnose;

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, Ap6256NdisUnload)
#pragma alloc_text(PAGE, Ap6256WdiAllocateAdapter)
#pragma alloc_text(PAGE, Ap6256WdiFreeAdapter)
#pragma alloc_text(PAGE, Ap6256WdiOpenAdapter)
#pragma alloc_text(PAGE, Ap6256WdiCloseAdapter)
#endif

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiAllocateAdapter(NDIS_HANDLE NdisMiniportHandle,
                         NDIS_HANDLE MiniportDriverContext,
                         PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters,
                         PNDIS_WDI_INIT_PARAMETERS NdisWdiInitParameters,
                         PNDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES RegistrationAttributes)
{
    PAP6256_DEVICE_CONTEXT ctx;

    UNREFERENCED_PARAMETER(MiniportDriverContext);
    UNREFERENCED_PARAMETER(MiniportInitParameters);
    PAGED_CODE();

    TraceDiag("AllocateAdapter entered\n");

    ctx = (PAP6256_DEVICE_CONTEXT)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, sizeof(AP6256_DEVICE_CONTEXT), AP6256_POOL_TAG);
    if (ctx == NULL) {
        TraceDiag("AllocateAdapter failed: no pool for the device context\n");
        return NDIS_STATUS_RESOURCES;
    }

    ctx->MiniportHandle = NdisMiniportHandle;
    ctx->Sdio.Function1BlockSize = AP6256_F1_BLOCKSIZE;
    ctx->Sdio.Function2BlockSize = AP6256_F2_BLOCKSIZE;
    ctx->FirmwareState = Ap6256FwNotLoaded;

    NdisMGetDeviceProperty(NdisMiniportHandle, &ctx->Pdo, &ctx->Fdo,
                           &ctx->NextDevice, NULL, NULL);
    Ap6256TraceLoadDebugSettings(ctx->Pdo);
    TraceDiag("v%s built %s device initialized (WDI), WinDbg level selected\n",
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
    {
        NTSTATUS cryptoStatus = Ap6256HostCipherStoreInit(&ctx->HostCipherStore);
        if (!NT_SUCCESS(cryptoStatus))
            TraceError(TRACE_DRIVER, "host cipher provider unavailable 0x%08X\n", cryptoStatus);
    }
    KeInitializeSpinLock(&ctx->TalStateLock);
    KeInitializeEvent(&ctx->TalIdle, NotificationEvent, TRUE);

    if (NdisWdiInitParameters != NULL) {
        ctx->WdiOsVersion            = NdisWdiInitParameters->WdiVersion;
        ctx->WdiOpenAdapterComplete  = NdisWdiInitParameters->OpenAdapterCompleteHandler;
        ctx->WdiCloseAdapterComplete = NdisWdiInitParameters->CloseAdapterCompleteHandler;

        TraceDiag("WDI init parameters: OS WDI contract %u.%u.%u\n",
                  (ULONG)((ctx->WdiOsVersion >> 16) & 0xFF),
                  (ULONG)((ctx->WdiOsVersion >> 8) & 0xFF),
                  (ULONG)(ctx->WdiOsVersion & 0xFF));
    } else {
        TraceDiag("WDI init parameters: none supplied\n");
    }

    if (!NT_SUCCESS(Ap6256NetWdiCreate(ctx))) {
        TraceDiag("AllocateAdapter failed: command state could not be created\n");
        Ap6256HostCipherStoreClose(&ctx->HostCipherStore);
        ExFreePoolWithTag(ctx, AP6256_POOL_TAG);
        return NDIS_STATUS_RESOURCES;
    }

    RegistrationAttributes->Header.Type =
        NDIS_OBJECT_TYPE_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES;
    RegistrationAttributes->Header.Revision =
        NDIS_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    RegistrationAttributes->Header.Size =
        NDIS_SIZEOF_MINIPORT_ADAPTER_REGISTRATION_ATTRIBUTES_REVISION_2;
    RegistrationAttributes->MiniportAdapterContext = (NDIS_HANDLE)ctx;
    RegistrationAttributes->AttributeFlags =
        NDIS_MINIPORT_ATTRIBUTES_HARDWARE_DEVICE |
        NDIS_MINIPORT_ATTRIBUTES_NO_HALT_ON_SUSPEND;
    RegistrationAttributes->CheckForHangTimeInSeconds = 0;
    RegistrationAttributes->InterfaceType = NdisInterfaceInternal;

    TraceInfo(TRACE_DRIVER, "WDI adapter allocated\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID
Ap6256WdiFreeAdapter(NDIS_HANDLE MiniportAdapterContext)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext;

    PAGED_CODE();

    if (ctx == NULL) {
        return;
    }

    Ap6256NetWdiDestroy(ctx);
    Ap6256HostCipherStoreClose(&ctx->HostCipherStore);

    TraceInfo(TRACE_DRIVER, "WDI adapter freed\n");
    ExFreePoolWithTag(ctx, AP6256_POOL_TAG);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WdiChipUp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN OnCommandWorker)
{
    NTSTATUS status = Ap6256SdBusAcquireInterface(Ctx);

    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_DRIVER, "SD bus interface failed 0x%08X\n", status);
        return status;
    }

    Ctx->Sdio.BackplaneWindow = MAXULONG;
    Ctx->Sdio.ClockOn = FALSE;
    Ctx->Sdio.HostBlockLength = 0;
    Ctx->Sdio.MaxBlocksPerCmd53 = 511;
    RtlZeroMemory(Ctx->Sdio.MaxTransferBytes, sizeof(Ctx->Sdio.MaxTransferBytes));
    Ctx->Sdio.HostRegs = Ap6256SdioMapHostRegisters();

    Ctx->SdioVendorId = AP6256_SDIO_VENDOR_BROADCOM;
    Ctx->SdioDeviceId = AP6256_SDIO_DEVICE_43455;

    status = Ap6256BringUpChip(Ctx, OnCommandWorker);
    if (!NT_SUCCESS(status)) {
        Ap6256SdBusReleaseInterface(Ctx);
        Ap6256SdioUnmapHostRegisters(Ctx->Sdio.HostRegs);
        Ctx->Sdio.HostRegs = NULL;
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WdiChipDown(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                        _In_ BOOLEAN OnCommandWorker)
{

    Ctx->LowPowerArmed = FALSE;
    Ctx->SavedLowPowerStateValid = FALSE;

    Ap6256TearDownChip(Ctx, OnCommandWorker);
    Ap6256BcdcDestroy(Ctx);
    Ap6256DatapathDestroy(Ctx);
    Ap6256SdBusReleaseInterface(Ctx);
    Ap6256SdioUnmapHostRegisters(Ctx->Sdio.HostRegs);
    Ctx->Sdio.HostRegs = NULL;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiOpenAdapter(NDIS_HANDLE MiniportAdapterContext,
                     PNDIS_MINIPORT_INIT_PARAMETERS MiniportInitParameters)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext;
    NDIS_WDI_OPEN_ADAPTER_COMPLETE_HANDLER complete;
    NDIS_HANDLE miniport;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(MiniportInitParameters);
    PAGED_CODE();

    TraceDiag("open adapter requested\n");

    status = Ap6256WdiChipUp(ctx, FALSE);

    TraceDiag("open adapter -> 0x%08X, completing\n", status);

    complete = ctx->WdiOpenAdapterComplete;
    miniport = ctx->MiniportHandle;
    if (complete == NULL) {
        TraceError(TRACE_DRIVER,
                   "no OpenAdapterComplete handler; WDI will wait forever\n");
        return NDIS_STATUS_SUCCESS;
    }

    complete(miniport,
             NT_SUCCESS(status) ? NDIS_STATUS_SUCCESS : NDIS_STATUS_FAILURE);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiCloseAdapter(NDIS_HANDLE MiniportAdapterContext)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext;
    NDIS_WDI_CLOSE_ADAPTER_COMPLETE_HANDLER complete;
    NDIS_HANDLE miniport;

    PAGED_CODE();

    TraceDiag("close adapter requested\n");

    Ap6256WdiChipDown(ctx, FALSE);

    TraceDiag("close adapter done, completing\n");

    complete = ctx->WdiCloseAdapterComplete;
    miniport = ctx->MiniportHandle;
    if (complete == NULL) {
        TraceError(TRACE_DRIVER,
                   "no CloseAdapterComplete handler; WDI will wait forever\n");
        return NDIS_STATUS_SUCCESS;
    }

    complete(miniport, NDIS_STATUS_SUCCESS);

    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiStartOperation(NDIS_HANDLE MiniportAdapterContext)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    TraceInfo(TRACE_DRIVER, "WDI start operation\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID
Ap6256WdiStopOperation(NDIS_HANDLE MiniportAdapterContext)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    TraceInfo(TRACE_DRIVER, "WDI stop operation\n");
}

static MINIPORT_WDI_POST_ADAPTER_PAUSE   Ap6256WdiPostPause;
static MINIPORT_WDI_POST_ADAPTER_RESTART Ap6256WdiPostRestart;

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiPostPause(NDIS_HANDLE MiniportAdapterContext,
                   PNDIS_MINIPORT_PAUSE_PARAMETERS PauseParameters)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(PauseParameters);

    TraceInfo(TRACE_DRIVER, "NDIS PAUSED the data path\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiPostRestart(NDIS_HANDLE MiniportAdapterContext,
                     PNDIS_MINIPORT_RESTART_PARAMETERS RestartParameters)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RestartParameters);

    TraceInfo(TRACE_DRIVER, "NDIS RESTARTED the data path\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiTalTxRxInitialize(NDIS_HANDLE MiniportAdapterContext,
                           NDIS_HANDLE NdisMiniportDataPathHandle,
                           PNDIS_WDI_DATA_API NdisWdiDataPathApi,
                           PTAL_TXRX_HANDLE pMiniportTalTxRxContext,
                           PNDIS_MINIPORT_WDI_DATA_HANDLERS pMiniportDataHandlers,
                           UINT32 *pMiniportWdiFrameMetadataExtraSpace)
{
    return Ap6256WdiTalInitialize(MiniportAdapterContext, NdisMiniportDataPathHandle,
                                  NdisWdiDataPathApi, pMiniportTalTxRxContext,
                                  pMiniportDataHandlers,
                                  pMiniportWdiFrameMetadataExtraSpace);
}

_Use_decl_annotations_
static VOID
Ap6256WdiTalTxRxDeinitialize(TAL_TXRX_HANDLE MiniportTalTxRxContext)
{
    Ap6256WdiTalDeinitialize(MiniportTalTxRxContext);
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256NdisSetOptions(NDIS_HANDLE NdisDriverHandle, NDIS_HANDLE DriverContext)
{
    UNREFERENCED_PARAMETER(NdisDriverHandle);
    UNREFERENCED_PARAMETER(DriverContext);

    TraceDiag("NDIS called SetOptions\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256NdisOidRequest(NDIS_HANDLE MiniportAdapterContext, PNDIS_OID_REQUEST OidRequest)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext;

    OidRequest->MiniportReserved[0] = FALSE;

    if (OidRequest->RequestType != NdisRequestMethod) {

        TraceInfo(TRACE_NETADAPTER, "non-WDI OID request type %u\n",
                  (ULONG)OidRequest->RequestType);
        return NDIS_STATUS_NOT_SUPPORTED;
    }

    return Ap6256NetWdiOidRequest(ctx, OidRequest);
}

_Use_decl_annotations_
static VOID
Ap6256NdisCancelOidRequest(NDIS_HANDLE MiniportAdapterContext, PVOID RequestId)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(RequestId);
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256NdisDirectOidRequest(NDIS_HANDLE MiniportAdapterContext,
                           PNDIS_OID_REQUEST OidRequest)
{

    if (OidRequest->RequestType == NdisRequestMethod) {
        TraceVerbose(TRACE_DRIVER, "direct OID request: method OID 0x%08X\n",
                     (ULONG)OidRequest->DATA.METHOD_INFORMATION.Oid);
    } else {
        TraceVerbose(TRACE_DRIVER, "direct OID request: type %u\n",
                     (ULONG)OidRequest->RequestType);
    }

    if (OidRequest->RequestType != NdisRequestMethod) {
        return NDIS_STATUS_NOT_SUPPORTED;
    }
    OidRequest->MiniportReserved[0] = TRUE;
    return Ap6256NetWdiOidRequest(
        (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext, OidRequest);
}

_Use_decl_annotations_
static VOID
Ap6256NdisCancelDirectOidRequest(NDIS_HANDLE MiniportAdapterContext,
                                 PVOID RequestId)
{
    TraceDiag("direct OID request cancelled\n");
    Ap6256NdisCancelOidRequest(MiniportAdapterContext, RequestId);
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256NdisResetEx(NDIS_HANDLE MiniportAdapterContext, PBOOLEAN AddressingReset)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    *AddressingReset = FALSE;
    return NDIS_STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
static VOID
Ap6256NdisDevicePnPEventNotify(NDIS_HANDLE MiniportAdapterContext,
                               PNET_DEVICE_PNP_EVENT NetDevicePnPEvent)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(NetDevicePnPEvent);
}

_Use_decl_annotations_
static VOID
Ap6256NdisShutdownEx(NDIS_HANDLE MiniportAdapterContext, NDIS_SHUTDOWN_ACTION ShutdownAction)
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    UNREFERENCED_PARAMETER(ShutdownAction);
}

_Use_decl_annotations_
static VOID
Ap6256NdisUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PAGED_CODE();

    if (Ap6256MiniportDriverHandle != NULL) {
        NdisMDeregisterWdiMiniportDriver(Ap6256MiniportDriverHandle);
        Ap6256MiniportDriverHandle = NULL;
    }
    Ap6256TraceCleanup();
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256WdiHangDiagnose(NDIS_HANDLE MiniportDriverContext,
                      eDiagnoseLevel DiagnoseLevel,
                      UINT32 BufferSize,
                      UINT8 *FirmwareBlob,
                      UINT32 *pOutputSize)
{
    AP6256_HANG_DIAGNOSIS* diagnosis = (AP6256_HANG_DIAGNOSIS*)MiniportDriverContext;
    KIRQL irql;

    TraceDiag("hang diagnose: level %u, buffer %u byte(s)\n",
              (ULONG)DiagnoseLevel, (ULONG)BufferSize);

    *pOutputSize = 0;
    if (diagnosis != &Ap6256HangDiagnosis || FirmwareBlob == NULL ||
        BufferSize < sizeof(diagnosis->Crash)) return NDIS_STATUS_SUCCESS;
    KeAcquireSpinLock(&diagnosis->Lock, &irql);
    if (diagnosis->Crash.Magic == AP6256_CRASH_MAGIC) {
        RtlCopyMemory(FirmwareBlob, &diagnosis->Crash, sizeof(diagnosis->Crash));
        *pOutputSize = sizeof(diagnosis->Crash);
    }
    KeReleaseSpinLock(&diagnosis->Lock, irql);
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NDIS_MINIPORT_DRIVER_CHARACTERISTICS chars;
    NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS wdiChars;
    NDIS_STATUS status;

    status = Ap6256TraceInitialize();
    if (!NT_SUCCESS(status))
        TraceWarn(TRACE_DRIVER, "ETW registration failed 0x%08X\n", status);
    KeInitializeSpinLock(&Ap6256HangDiagnosis.Lock);

    TraceDiag("v%s built %s loading (WDI NDIS miniport)\n",
              AP6256_VER_STR, AP6256_BUILD_STAMP);

    RtlZeroMemory(&chars, sizeof(chars));
    chars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_DRIVER_CHARACTERISTICS;
    chars.Header.Revision = NDIS_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;
    chars.Header.Size = NDIS_SIZEOF_MINIPORT_DRIVER_CHARACTERISTICS_REVISION_2;

    chars.MajorNdisVersion = 6;
    chars.MinorNdisVersion = 50;
    chars.MajorDriverVersion = AP6256_VER_MAJOR;
    chars.MinorDriverVersion = AP6256_VER_MINOR;

    chars.SetOptionsHandler              = Ap6256NdisSetOptions;
    chars.UnloadHandler                  = Ap6256NdisUnload;
    chars.OidRequestHandler              = Ap6256NdisOidRequest;
    chars.ResetHandlerEx                 = Ap6256NdisResetEx;
    chars.DevicePnPEventNotifyHandler    = Ap6256NdisDevicePnPEventNotify;
    chars.ShutdownHandlerEx              = Ap6256NdisShutdownEx;
    chars.CancelOidRequestHandler        = Ap6256NdisCancelOidRequest;

    chars.DirectOidRequestHandler        = Ap6256NdisDirectOidRequest;
    chars.CancelDirectOidRequestHandler  = Ap6256NdisCancelDirectOidRequest;

    RtlZeroMemory(&wdiChars, sizeof(wdiChars));
    wdiChars.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_WDI_CHARACTERISTICS;
    wdiChars.Header.Revision = NDIS_MINIPORT_DRIVER_WDI_CHARACTERISTICS_REVISION_1;
    wdiChars.Header.Size = NDIS_SIZEOF_MINIPORT_WDI_CHARACTERISTICS_REVISION_1;
    wdiChars.WdiVersion = AP6256_WDI_VERSION;

    wdiChars.AllocateAdapterHandler      = Ap6256WdiAllocateAdapter;
    wdiChars.FreeAdapterHandler          = Ap6256WdiFreeAdapter;
    wdiChars.OpenAdapterHandler          = Ap6256WdiOpenAdapter;
    wdiChars.CloseAdapterHandler         = Ap6256WdiCloseAdapter;
    wdiChars.StartOperationHandler       = Ap6256WdiStartOperation;
    wdiChars.StopOperationHandler        = Ap6256WdiStopOperation;
    wdiChars.PostPauseHandler            = Ap6256WdiPostPause;
    wdiChars.PostRestartHandler          = Ap6256WdiPostRestart;

    wdiChars.HangDiagnoseHandler         = Ap6256WdiHangDiagnose;
    wdiChars.TalTxRxInitializeHandler    = Ap6256WdiTalTxRxInitialize;
    wdiChars.TalTxRxDeinitializeHandler  = Ap6256WdiTalTxRxDeinitialize;

    TraceDiag("registering: WDI contract %u.%u.%u, NDIS %u.%u, "
              "chars rev %u size %u, wdi chars rev %u size %u\n",
              (ULONG)((AP6256_WDI_VERSION >> 16) & 0xFF),
              (ULONG)((AP6256_WDI_VERSION >> 8) & 0xFF),
              (ULONG)(AP6256_WDI_VERSION & 0xFF),
              (ULONG)chars.MajorNdisVersion, (ULONG)chars.MinorNdisVersion,
              (ULONG)chars.Header.Revision, (ULONG)chars.Header.Size,
              (ULONG)wdiChars.Header.Revision, (ULONG)wdiChars.Header.Size);

    status = NdisMRegisterWdiMiniportDriver(DriverObject, RegistryPath, &Ap6256HangDiagnosis,
                                            &chars, &wdiChars,
                                            &Ap6256MiniportDriverHandle);
    if (status != NDIS_STATUS_SUCCESS) {

        if (status == STATUS_NOT_SUPPORTED) {
            TraceDiag("WDI registration refused: no WDI port driver on this "
                      "image (wdiwifi.sys absent - WLAN feature not installed)\n");
        } else {
            TraceDiag("NdisMRegisterWdiMiniportDriver failed 0x%08X\n", status);
        }
        Ap6256TraceCleanup();
        return (NTSTATUS)status;
    }

    TraceDiag("NdisMRegisterWdiMiniportDriver succeeded; waiting for NDIS to "
              "start the device\n");
    return STATUS_SUCCESS;
}
