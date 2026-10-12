/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "kmdf_driver.h"
#include "sdio.h"
#include "bcdc.h"
#include "datapath.h"
#if defined(AP6256_ENABLE_WIFICX)
#include "netadapter_internal.h"
#endif

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, Ap6256EvtPrepareHardware)
#pragma alloc_text(PAGE, Ap6256EvtReleaseHardware)
#endif

_Use_decl_annotations_
NTSTATUS Ap6256EvtPrepareHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesRaw,
                                  WDFCMRESLIST ResourcesTranslated)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    NTSTATUS status;

    UNREFERENCED_PARAMETER(ResourcesRaw);
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PAGED_CODE();

    status = Ap6256SdBusAcquireInterface(ctx);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ctx->Sdio.BackplaneWindow = MAXULONG;
    ctx->Sdio.ClockOn = FALSE;
    ctx->Sdio.HostBlockLength = 0;
    ctx->Sdio.MaxBlocksPerCmd53 = 511;
    RtlZeroMemory(ctx->Sdio.MaxTransferBytes, sizeof(ctx->Sdio.MaxTransferBytes));

    ctx->Sdio.HostRegs = Ap6256SdioMapHostRegisters();

    ctx->SdioVendorId = AP6256_SDIO_VENDOR_BROADCOM;
    ctx->SdioDeviceId = AP6256_SDIO_DEVICE_43455;
    TraceInfo(TRACE_DEVICE, "prepare hardware: SDIO %04X:%04X\n",
              ctx->SdioVendorId, ctx->SdioDeviceId);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256EvtReleaseHardware(WDFDEVICE Device, WDFCMRESLIST ResourcesTranslated)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    UNREFERENCED_PARAMETER(ResourcesTranslated);
    PAGED_CODE();

    Ap6256TearDownChip(ctx, FALSE);

    Ap6256BcdcDestroy(ctx);
    Ap6256DatapathDestroy(ctx);

    Ap6256SdBusReleaseInterface(ctx);
    Ap6256SdioUnmapHostRegisters(ctx->Sdio.HostRegs);
    ctx->Sdio.HostRegs = NULL;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256EvtD0Entry(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    TraceInfo(TRACE_POWER, "D0Entry (from %d)\n", PreviousState);
#if defined(AP6256_ENABLE_WIFICX)
    if (ctx->LowPowerArmed) {
        PAP6256_WIFI wifi = Ap6256WifiFromDevice(ctx);

        if (wifi && wifi->HardwareAvailable && !wifi->Stopping &&
            !ctx->Go.NativeStateUncertain) {
            NTSTATUS status = Ap6256WifiCxResumePower(ctx);
            if (NT_SUCCESS(status)) return status;
        }
        Ap6256TearDownChip(ctx, FALSE);
    }
#endif
    return Ap6256BringUpChip(ctx, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256EvtD0Exit(WDFDEVICE Device, WDF_POWER_DEVICE_STATE TargetState)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    TraceInfo(TRACE_POWER, "D0Exit (to %d)\n", TargetState);
#if defined(AP6256_ENABLE_WIFICX)
    if (TargetState == WdfPowerDeviceD2 && ctx->LowPowerArmed) return STATUS_SUCCESS;
#endif
    Ap6256TearDownChip(ctx, FALSE);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256EvtD0EntryPostInterruptsEnabled(WDFDEVICE Device, WDF_POWER_DEVICE_STATE PreviousState)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    NTSTATUS status;
    UNREFERENCED_PARAMETER(PreviousState);
#if defined(AP6256_ENABLE_WIFICX)
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(ctx);
    if (wifi && wifi->RetainedResume) {wifi->RetainedResume = FALSE; return STATUS_SUCCESS;}
#endif
    status = Ap6256ModelHardwareReady(ctx);
    if (!NT_SUCCESS(status)) Ap6256TearDownChip(ctx, FALSE);
#if defined(AP6256_ENABLE_WIFICX)
    else if (wifi && wifi->HardwareAvailable && !wifi->Stopping) {

        wifi->PowerStateDx = FALSE;
    }
#endif
    return status;
}
