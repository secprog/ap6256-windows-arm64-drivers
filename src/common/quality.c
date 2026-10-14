#include "quality.h"
#include "wifi_ops.h"
#include "bcdc.h"
#include "sdpcm.h"

static BOOLEAN Ap6256QualityForceOff(_In_reads_(AP6256_GROUP_PORT + 1) const UINT32* Hints)
{
    UINT32 port;
    for (port = 0; port <= AP6256_GROUP_PORT; ++port) {
        if (Hints[port] == AP6256_QUALITY_LOW_LATENCY ||
            Hints[port] == AP6256_QUALITY_HIGH_THROUGHPUT ||
            Hints[port] == AP6256_QUALITY_NO_POWER_SAVE) return TRUE;
    }
    return FALSE;
}

static UINT32 Ap6256QualityHighPort(_In_reads_(AP6256_GROUP_PORT + 1) const UINT32* Hints)
{
    UINT32 port;
    for (port = 0; port <= AP6256_GROUP_PORT; ++port) {
        if (Hints[port] == AP6256_QUALITY_HIGH_THROUGHPUT) return port;
    }
    return MAXUINT32;
}

_Use_decl_annotations_
VOID Ap6256QualityInitialize(PAP6256_DEVICE_CONTEXT Ctx)
{
    RtlZeroMemory(&Ctx->ConnectionQuality, sizeof(Ctx->ConnectionQuality));
    KeInitializeMutex(&Ctx->ConnectionQuality.Lock, 0);
    Ctx->ConnectionQuality.Initialized = TRUE;
}

static NTSTATUS Ap6256QualityReadScalar(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ PCSTR Name, _Out_ PUINT32 Value, _In_ BOOLEAN Probe,
    _Out_opt_ PBOOLEAN Unsupported)
{
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    *Value = 0;
    if (Unsupported != NULL) *Unsupported = FALSE;
    status = Probe ? Ap6256BcdcProbeIovar(Ctx, Name, Value, sizeof(*Value), &result)
                   : Ap6256BcdcGetIovarResultIf(Ctx, 0, Name, Value, sizeof(*Value), &result);
    if (!NT_SUCCESS(status)) {
        if (Unsupported != NULL)
            *Unsupported = (BOOLEAN)(result.FirmwareReply && result.FirmwareError &&
                result.FirmwareStatus == -23);
        return status;
    }
    return result.FirmwareReply && !result.FirmwareError && result.PayloadLength >= sizeof(*Value)
        ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

static NTSTATUS Ap6256QualityWriteScalar(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ PCSTR Name, _In_ UINT32 Value)
{
    UINT32 actual;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, Name, &Value, sizeof(Value));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256QualityReadScalar(Ctx, Name, &actual, FALSE, NULL);
    if (!NT_SUCCESS(status)) return status;
    return actual == Value ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

static NTSTATUS Ap6256QualityRestoreMchan(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Algorithm, _In_ UINT32 Bandwidth)
{
    UINT32 currentAlgorithm = 0, currentBandwidth = 0;
    NTSTATUS status = Ap6256QualityReadScalar(Ctx, "mchan_algo", &currentAlgorithm, FALSE, NULL);
    if (NT_SUCCESS(status)) status = Ap6256QualityReadScalar(Ctx, "mchan_bw", &currentBandwidth, FALSE, NULL);
    if (!NT_SUCCESS(status)) return status;
    if (currentAlgorithm > 3u || currentBandwidth > 100u) return STATUS_DEVICE_PROTOCOL_ERROR;
    if (currentBandwidth != Bandwidth) {
        if (currentAlgorithm == 3u) {
            status = Ap6256QualityWriteScalar(Ctx, "mchan_algo", 1u);
            if (!NT_SUCCESS(status)) return status;
            currentAlgorithm = 1u;
        }
        status = Ap6256QualityWriteScalar(Ctx, "mchan_bw", Bandwidth);
        if (!NT_SUCCESS(status)) return status;
    }
    return currentAlgorithm == Algorithm ? STATUS_SUCCESS
        : Ap6256QualityWriteScalar(Ctx, "mchan_algo", Algorithm);
}

static NTSTATUS Ap6256QualityReadGroupPm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _Out_ PUINT32 Value)
{
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    *Value = 0;
    status = Ap6256BcdcQueryDcmdResultIf(Ctx, IfIndex, BRCMF_C_GET_PM,
        Value, sizeof(*Value), &result);
    if (!NT_SUCCESS(status)) return status;
    return result.FirmwareReply && !result.FirmwareError &&
        result.PayloadLength >= sizeof(*Value) && *Value <= 2u
        ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

static NTSTATUS Ap6256QualityWriteGroupPm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ UINT32 Value)
{
    UINT32 actual = 0;
    NTSTATUS status = Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SET_PM, &Value, sizeof(Value));
    if (NT_SUCCESS(status)) status = Ap6256QualityReadGroupPm(Ctx, IfIndex, &actual);
    if (NT_SUCCESS(status) && actual != Value) status = STATUS_DEVICE_PROTOCOL_ERROR;
    return status;
}

static NTSTATUS Ap6256QualityApplyLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(AP6256_GROUP_PORT + 1) const UINT32* Hints, _In_ BOOLEAN WantPowerSave)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    UINT32 high = Ap6256QualityHighPort(Hints);
    UINT32 previousAlgorithm = 0, previousBandwidth = 0, enabled = 0;
    BOOLEAN unsupported = FALSE, changedMchan = FALSE, saveMchan = FALSE;
    BOOLEAN forceOff = Ap6256QualityForceOff(Hints);
    BOOLEAN changedGroup = FALSE, saveGroup = FALSE, clearGroup = FALSE;
    UINT32 groupIfIndex = Ctx->Go.IfIndex, previousGroupPm = 0;
    NTSTATUS status, rollback;

    if (high != MAXUINT32 || quality->MchanSaved) {
        if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9 ||
            !Ctx->FirmwareNativeManagement) return STATUS_NOT_SUPPORTED;
        status = Ap6256QualityReadScalar(Ctx, "mchan", &enabled, TRUE, &unsupported);
        if (!NT_SUCCESS(status) && !unsupported) return status;
        if (!NT_SUCCESS(status) || enabled == 0) {
            if (quality->MchanSaved) return STATUS_DEVICE_NOT_READY;
            return STATUS_NOT_SUPPORTED;
        } else {
            status = Ap6256QualityReadScalar(Ctx, "mchan_algo", &previousAlgorithm, FALSE, NULL);
            if (!NT_SUCCESS(status)) return status;
            status = Ap6256QualityReadScalar(Ctx, "mchan_bw", &previousBandwidth, FALSE, NULL);
            if (!NT_SUCCESS(status)) return status;
            if (previousAlgorithm > 3 || previousBandwidth > 100) return STATUS_DEVICE_PROTOCOL_ERROR;
            saveMchan = (BOOLEAN)(high != MAXUINT32 && !quality->MchanSaved);
            if (high != MAXUINT32) {
                UINT32 bandwidth = high == AP6256_STATION_PORT ? 75u : 25u;
                status = STATUS_SUCCESS;
                changedMchan = (BOOLEAN)(previousAlgorithm != 1u || previousBandwidth != bandwidth);
                if (previousAlgorithm != 1u)
                    status = Ap6256QualityWriteScalar(Ctx, "mchan_algo", 1u);
                if (NT_SUCCESS(status) && previousBandwidth != bandwidth)
                    status = Ap6256QualityWriteScalar(Ctx, "mchan_bw", bandwidth);
            } else {
                changedMchan = (BOOLEAN)(previousAlgorithm != quality->SavedMchanAlgorithm ||
                    previousBandwidth != quality->SavedMchanBandwidth);
                status = Ap6256QualityRestoreMchan(Ctx, quality->SavedMchanAlgorithm,
                    quality->SavedMchanBandwidth);
            }
            if (!NT_SUCCESS(status)) goto restore;
        }
    }
    if (Ctx->Go.FirmwareReady && Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT &&
        (forceOff || quality->GroupPmSaved)) {
        if (groupIfIndex == 0 || groupIfIndex >= 16u) {
            status = STATUS_INVALID_DEVICE_STATE;
            goto restore;
        }
        status = Ap6256QualityReadGroupPm(Ctx, groupIfIndex, &previousGroupPm);
        if (!NT_SUCCESS(status)) goto restore;
        saveGroup = (BOOLEAN)(forceOff &&
            (!quality->GroupPmSaved || quality->GroupPmIfIndex != groupIfIndex));
        if (forceOff || quality->GroupPmIfIndex == groupIfIndex) {
            changedGroup = TRUE;
            status = Ap6256QualityWriteGroupPm(Ctx, groupIfIndex,
                forceOff ? 0u : quality->SavedGroupPm);
            if (!NT_SUCCESS(status)) goto restore;
        }
        clearGroup = (BOOLEAN)!forceOff;
    } else if (!Ctx->Go.FirmwareReady || Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_CLIENT) {
        clearGroup = TRUE;
    }
    status = Ap6256WifiProgramPowerSave(Ctx, WantPowerSave, forceOff);
    if (!NT_SUCCESS(status)) goto restore;
    if (saveMchan) {
        quality->SavedMchanAlgorithm = previousAlgorithm;
        quality->SavedMchanBandwidth = previousBandwidth;
        quality->MchanSaved = TRUE;
    } else if (high == MAXUINT32) {
        quality->MchanSaved = FALSE;
    }
    if (saveGroup) {
        quality->SavedGroupPm = previousGroupPm;
        quality->GroupPmIfIndex = groupIfIndex;
        quality->GroupPmSaved = TRUE;
    } else if (clearGroup) {
        quality->GroupPmSaved = FALSE;
    }
    return STATUS_SUCCESS;

restore:
    if (changedGroup) {
        rollback = Ap6256QualityWriteGroupPm(Ctx, groupIfIndex, previousGroupPm);
        if (!NT_SUCCESS(rollback)) {
            if (!quality->GroupPmSaved) {
                quality->SavedGroupPm = previousGroupPm;
                quality->GroupPmIfIndex = groupIfIndex;
                quality->GroupPmSaved = TRUE;
            }
            TraceWarn(TRACE_NETADAPTER, "connection quality group power restore failed 0x%08X\n", rollback);
        }
    }
    if (changedMchan) {
        rollback = Ap6256QualityRestoreMchan(Ctx, previousAlgorithm, previousBandwidth);
        if (!NT_SUCCESS(rollback)) {
            if (!quality->MchanSaved) {
                quality->SavedMchanAlgorithm = previousAlgorithm;
                quality->SavedMchanBandwidth = previousBandwidth;
                quality->MchanSaved = TRUE;
            }
            TraceWarn(TRACE_NETADAPTER, "connection quality scheduler restore failed 0x%08X\n", rollback);
        }
    }
    rollback = Ap6256WifiProgramPowerSave(Ctx, quality->PowerSaveRequested,
        Ap6256QualityForceOff(quality->Hints));
    if (!NT_SUCCESS(rollback))
        TraceWarn(TRACE_NETADAPTER, "connection quality power restore failed 0x%08X\n", rollback);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256QualitySetPort(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Port, UINT32 Hint)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    UINT32 hints[AP6256_GROUP_PORT + 1], high;
    BOOLEAN wantPower;
    NTSTATUS status;
    if (!quality->Initialized) return STATUS_DEVICE_NOT_READY;
    if (Port > AP6256_GROUP_PORT || Hint < AP6256_QUALITY_AUTO_POWER_SAVE ||
        Hint > AP6256_QUALITY_NO_POWER_SAVE) return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    RtlCopyMemory(hints, quality->Hints, sizeof(hints));
    high = Ap6256QualityHighPort(hints);
    if (Hint == AP6256_QUALITY_HIGH_THROUGHPUT && high != MAXUINT32 && high != Port) {
        status = STATUS_DEVICE_BUSY;
    } else {
        hints[Port] = Hint;
        wantPower = Hint == AP6256_QUALITY_AUTO_POWER_SAVE ? TRUE : quality->PowerSaveRequested;
        status = Ap6256QualityApplyLocked(Ctx, hints, wantPower);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(quality->Hints, hints, sizeof(hints));
            quality->PowerSaveRequested = wantPower;
        }
    }
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256QualityForgetPort(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Port)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    UINT32 hints[AP6256_GROUP_PORT + 1];
    NTSTATUS status = STATUS_SUCCESS;
    if (!quality->Initialized || Port > AP6256_GROUP_PORT) return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    RtlCopyMemory(hints, quality->Hints, sizeof(hints));
    hints[Port] = 0;
    if (Port == AP6256_GROUP_PORT && !Ctx->Go.FirmwareReady) quality->GroupPmSaved = FALSE;
    if (Ctx->FirmwareState == Ap6256FwRunning && Ctx->DatapathRunning && !Ctx->FirmwareHalted &&
        !Ctx->FirmwareIoQuiesced)
        status = Ap6256QualityApplyLocked(Ctx, hints, quality->PowerSaveRequested);
    RtlCopyMemory(quality->Hints, hints, sizeof(hints));
    if (Ap6256QualityHighPort(hints) == MAXUINT32 &&
        (Ctx->FirmwareState != Ap6256FwRunning || Ctx->FirmwareHalted)) quality->MchanSaved = FALSE;
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
    return status;
}

_Use_decl_annotations_
VOID Ap6256QualityResetFirmware(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    if (!quality->Initialized) return;
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    quality->MchanSaved = FALSE;
    quality->GroupPmSaved = FALSE;
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
}

_Use_decl_annotations_
VOID Ap6256QualityForgetGroupFirmware(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    if (!quality->Initialized) return;
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    quality->GroupPmSaved = FALSE;
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256QualityReapply(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    NTSTATUS status;
    if (!quality->Initialized) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    status = Ap6256QualityApplyLocked(Ctx, quality->Hints, quality->PowerSaveRequested);
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPowerSave(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Enabled)
{
    AP6256_CONNECTION_QUALITY* quality = &Ctx->ConnectionQuality;
    BOOLEAN powerTransition = (BOOLEAN)(Ctx->FirmwareIoQuiesced != 0 &&
        Ctx->PowerThread == KeGetCurrentThread());
    NTSTATUS status;
    if (!quality->Initialized) return Ap6256WifiProgramPowerSave(Ctx, Enabled, FALSE);
    (VOID)KeWaitForSingleObject(&quality->Lock, Executive, KernelMode, FALSE, NULL);
    if (!powerTransition)
        status = Ap6256QualityApplyLocked(Ctx, quality->Hints, Enabled);
    else
        status = Ap6256WifiProgramPowerSave(Ctx, Enabled,
            powerTransition ? FALSE : Ap6256QualityForceOff(quality->Hints));
    if (NT_SUCCESS(status) && !powerTransition) quality->PowerSaveRequested = Enabled;
    (VOID)KeReleaseMutex(&quality->Lock, FALSE);
    return status;
}
