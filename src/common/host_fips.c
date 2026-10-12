/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_fips.h"
#include "bcdc.h"
#include "wlfc.h"

#define FIPS_ABI 0x31504648u
typedef struct _AP6256_FIPS_MODE {
    UINT32 Abi, Bytes, Enabled;
    AP6256_FIPS_SESSION Session;
} AP6256_FIPS_MODE;
C_ASSERT(sizeof(AP6256_FIPS_MODE) == 32);

static NTSTATUS Ap6256FipsFrameHt(const UCHAR* Frame, ULONG Length, const UCHAR* Bssid, BOOLEAN* Ht)
{
    ULONG offset = 12;
    BOOLEAN found = FALSE;
    *Ht = FALSE;
    if (!Frame || Length < 12) return STATUS_INVALID_PARAMETER;

    if (Length >= 36 && (Frame[0] == 0x80 || Frame[0] == 0x50) && Frame[1] == 0 &&
        RtlEqualMemory(Frame + 10, Bssid, 6) && RtlEqualMemory(Frame + 16, Bssid, 6)) offset = 36;
    while (offset < Length) {
        ULONG size;
        if (Length - offset < 2 || (size = Frame[offset + 1]) > Length - offset - 2)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        if (Frame[offset] == 45) {
            if (size != 26 || found) return STATUS_DEVICE_PROTOCOL_ERROR;
            found = TRUE;
        }
        offset += 2 + size;
    }
    *Ht = found;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsCandidateHt(const UCHAR* Beacon, ULONG BeaconLength,
    const UCHAR* Probe, ULONG ProbeLength, const UCHAR* Bssid, BOOLEAN* Ht)
{
    BOOLEAN beaconHt = FALSE, probeHt = FALSE;
    NTSTATUS status;
    *Ht = FALSE;

    if (!BeaconLength && !ProbeLength) return STATUS_SUCCESS;
    if ((BeaconLength && !Beacon) || (ProbeLength && !Probe))
        return STATUS_INVALID_PARAMETER;
    if (BeaconLength) {
        status = Ap6256FipsFrameHt(Beacon, BeaconLength, Bssid, &beaconHt);
        if (!NT_SUCCESS(status)) return status;
    }
    if (ProbeLength) {
        status = Ap6256FipsFrameHt(Probe, ProbeLength, Bssid, &probeHt);
        if (!NT_SUCCESS(status)) return status;
    }
    if (BeaconLength && ProbeLength && beaconHt != probeHt) return STATUS_DEVICE_PROTOCOL_ERROR;
    *Ht = BeaconLength ? beaconHt : probeHt;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsCheckVendorIes(const UCHAR* Ies, ULONG Length)
{
    const UCHAR* element = Ies;
    ULONG remaining = Length;
    if (Length && !Ies) return STATUS_INVALID_PARAMETER;
    while (remaining) {
        ULONG size;
        if (remaining < 2 || (size = element[1]) > remaining - 2)
            return STATUS_INVALID_PARAMETER;

        if (element[0] != 221 || size < 3) return STATUS_NOT_SUPPORTED;
        if (size >= 4 && remaining >= 6 && element[2] == 0 && element[3] == 0x50 && element[4] == 0xf2 && element[5] == 2)
            return STATUS_NOT_SUPPORTED;
        element += 2 + size; remaining -= 2 + size;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsSetQos(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, BOOLEAN Ht)
{
    UINT32 value = Ht ? 0 : 1, readback = 0;
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wme_bss_disable", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wme_bss_disable", &readback, sizeof(readback), &result);
    if (!NT_SUCCESS(status)) return status;
    return result.FirmwareReply && !result.FirmwareError && result.PayloadLength >= sizeof(readback) &&
        readback == value ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsVerifySecurity(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Wsec, UINT32 WpaAuth)
{
    const UINT32 commands[] = {BRCMF_C_GET_AUTH, BRCMF_C_GET_WSEC,
        BRCMF_C_GET_WPA_AUTH, BRCMF_C_GET_INFRA};
    const UINT32 expected[] = {0, Wsec, WpaAuth, 1};
    AP6256_BCDC_QUERY_RESULT result;
    UINT32 i, value;
    NTSTATUS status;
    for (i = 0; i < RTL_NUMBER_OF(commands); ++i) {
        value = 0; RtlZeroMemory(&result, sizeof(result));
        status = Ap6256BcdcQueryDcmdResultIf(Ctx, IfIndex, commands[i], &value, sizeof(value), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(value) ||
            value != expected[i]) return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    value = 0; RtlZeroMemory(&result, sizeof(result));
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "mfp", &value, sizeof(value), &result);
    if (!NT_SUCCESS(status)) return status;
    return result.FirmwareReply && !result.FirmwareError && result.PayloadLength >= sizeof(value) &&
        !value ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

_Use_decl_annotations_
BOOLEAN Ap6256FipsSnapshot(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_FIPS_SESSION* Session)
{
    KIRQL irql;
    BOOLEAN valid = FALSE;
    RtlZeroMemory(Session, sizeof(*Session));
    if (IfIndex >= RTL_NUMBER_OF(Ctx->HostFipsSessions)) return FALSE;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    if (!(Ctx->HostFipsBlockedMask & (1u << IfIndex))) {
        *Session = Ctx->HostFipsSessions[IfIndex];
        valid = Session->Generation != 0;
    }
    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    return valid;
}

_Use_decl_annotations_
BOOLEAN Ap6256FipsActive(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    KIRQL irql;
    BOOLEAN active;
    if (IfIndex >= RTL_NUMBER_OF(Ctx->HostFipsSessions)) return FALSE;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    active = (BOOLEAN)(Ctx->HostFipsSessions[IfIndex].Generation ||
        (Ctx->HostFipsBlockedMask & (1u << IfIndex)));
    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    return active;
}

_Use_decl_annotations_
BOOLEAN Ap6256FipsRetired(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    KIRQL irql;
    BOOLEAN retired;
    if (IfIndex >= RTL_NUMBER_OF(Ctx->HostFipsSessions)) return FALSE;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    retired = (BOOLEAN)((Ctx->HostFipsRetiredMask & (1u << IfIndex)) != 0);
    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    return retired;
}

_Use_decl_annotations_
VOID Ap6256FipsReset(PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    RtlZeroMemory(Ctx->HostFipsSessions, sizeof(Ctx->HostFipsSessions));
    Ctx->HostFipsBlockedMask = 0;
    Ctx->HostFipsRetiredMask = 0;
    Ctx->HostFipsReady = FALSE;

    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsQualify(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN PatchVerified)
{
    UINT32 caps[4] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    Ap6256FipsReset(Ctx);
    if (!PatchVerified) return STATUS_SUCCESS;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wdi_fips_caps", caps, sizeof(caps), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(caps) ||
        caps[0] != FIPS_ABI || caps[1] != sizeof(caps) || caps[2] != 7 ||
        caps[3] != AP6256_FIPS_MAX_MPDU_BYTES) return STATUS_DEVICE_PROTOCOL_ERROR;
    Ctx->HostFipsReady = TRUE;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256FipsMode(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const AP6256_FIPS_MODE* Mode)
{
    AP6256_FIPS_MODE readback = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wdi_fips_mode", Mode, sizeof(*Mode));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_fips_mode", &readback,
        sizeof(readback), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(readback) ||
        !RtlEqualMemory(&readback, Mode, sizeof(readback))) return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256FipsEnd(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, BOOLEAN Retiring)
{
    AP6256_FIPS_MODE mode = {FIPS_ABI, sizeof(mode), 0, {0}};
    KIRQL irql;
    NTSTATUS status;
    if (IfIndex >= RTL_NUMBER_OF(Ctx->HostFipsSessions)) return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    if (!Ctx->HostFipsSessions[IfIndex].Generation && !(Ctx->HostFipsBlockedMask & (1u << IfIndex))) {
        KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
        return STATUS_SUCCESS;
    }
    Ctx->HostFipsBlockedMask |= 1u << IfIndex;
    Ctx->HostFipsRetiredMask &= ~(1u << IfIndex);
    RtlZeroMemory(&Ctx->HostFipsSessions[IfIndex], sizeof(Ctx->HostFipsSessions[IfIndex]));
    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    Ap6256WlfcCancel(Ctx, IfIndex ? AP6256_GROUP_PORT : AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
    status = Ap6256FipsMode(Ctx, IfIndex, &mode);
    if (NT_SUCCESS(status)) {
        KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
        if (Retiring) Ctx->HostFipsRetiredMask |= 1u << IfIndex;
        else Ctx->HostFipsBlockedMask &= ~(1u << IfIndex);
        KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsStop(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    return Ap6256FipsEnd(Ctx, IfIndex, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsRetire(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{

    return Ap6256FipsEnd(Ctx, IfIndex, TRUE);
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Station, const UCHAR* Bssid)
{
    AP6256_FIPS_MODE mode = {FIPS_ABI, sizeof(mode), 1, {0}};
    AP6256_FIPS_FRAME_VIEW view;
    UCHAR probe[25] = {8, 1};
    KIRQL irql;
    NTSTATUS status;
    if (!Ctx->HostFipsReady || IfIndex >= RTL_NUMBER_OF(Ctx->HostFipsSessions)) return STATUS_NOT_SUPPORTED;
    status = Ap6256FipsStop(Ctx, IfIndex);
    if (!NT_SUCCESS(status)) return status;
    mode.Session.Generation = 1;
    mode.Session.IfIndex = (UCHAR)IfIndex;
    RtlCopyMemory(mode.Session.Station, Station, 6); RtlCopyMemory(mode.Session.Bssid, Bssid, 6);
    RtlCopyMemory(probe + 4, Bssid, 6); RtlCopyMemory(probe + 10, Station, 6);
    if (!Ap6256FipsValidateFrame(&mode.Session, AP6256_FIPS_TX, probe, sizeof(probe), &view))
        return STATUS_INVALID_PARAMETER;
    KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
    mode.Session.Generation = ++Ctx->HostFipsNextGeneration;
    if (!mode.Session.Generation) mode.Session.Generation = ++Ctx->HostFipsNextGeneration;
    Ctx->HostFipsBlockedMask |= 1u << IfIndex;
    KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    if (!IfIndex) {
        UCHAR config[56] = {0}, key[36] = {0};
        UINT32 i;

        status = Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_gtk_config", config, sizeof(config));
        if (!NT_SUCCESS(status)) return status;
        for (i = 0; i < 6; i++) {
            UINT32 management = i >= 4;
            RtlCopyMemory(key, &i, 4); RtlCopyMemory(key + 4, &management, 4);
            status = Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_gtk_key", key, sizeof(key));
            if (!NT_SUCCESS(status)) return status;
        }
    }
    status = Ap6256FipsMode(Ctx, IfIndex, &mode);
    if (NT_SUCCESS(status)) {
        KeAcquireSpinLock(&Ctx->HostFipsLock, &irql);
        Ctx->HostFipsSessions[IfIndex] = mode.Session;
        Ctx->HostFipsBlockedMask &= ~(1u << IfIndex);
        KeReleaseSpinLock(&Ctx->HostFipsLock, irql);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256FipsPrepareTx(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, UCHAR* Buffer,
    ULONG Capacity, ULONG* Length, UCHAR* Priority, UCHAR* Exemption)
{
    AP6256_FIPS_SESSION session;
    AP6256_FIPS_FRAME_VIEW view;
    ULONG length = *Length;
    if (!Ap6256FipsSnapshot(Ctx, IfIndex, &session))
        return Ap6256FipsActive(Ctx, IfIndex) ? STATUS_DEVICE_NOT_READY : STATUS_NOT_SUPPORTED;
    if (Capacity < AP6256_FIPS_TX_HEADER_BYTES || length > Capacity - AP6256_FIPS_TX_HEADER_BYTES ||
        !Ap6256FipsValidateFrame(&session, AP6256_FIPS_TX, Buffer, length, &view))
        return STATUS_INVALID_BUFFER_SIZE;
    *Priority = view.Tid & 7u; *Exemption = AP6256_FIPS_BCDC_TX_EXEMPT;
    RtlMoveMemory(Buffer + AP6256_FIPS_TX_HEADER_BYTES, Buffer, length);
    if (!Ap6256FipsWriteHeader(&session, AP6256_FIPS_TX, 0, Buffer + AP6256_FIPS_TX_HEADER_BYTES,
        length, Buffer, Capacity)) return STATUS_INVALID_PARAMETER;
    *Length = length + AP6256_FIPS_TX_HEADER_BYTES;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN Ap6256FipsTxCurrent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Wire, ULONG Length)
{
    AP6256_FIPS_SESSION session;
    AP6256_FIPS_FRAME_VIEW view;
    return Ap6256FipsSnapshot(Ctx, IfIndex, &session) &&
        Ap6256FipsReadEnvelope(&session, AP6256_FIPS_TX, Wire, Length, &view);
}

_Use_decl_annotations_
BOOLEAN Ap6256FipsBcdcTxCurrent(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Bcdc, ULONG Length)
{
    ULONG skip;
    UINT32 ifIndex;
    if (!Bcdc || Length < 4) return FALSE;
    skip = 4u + 4u * Bcdc[3];
    if (skip > Length) return FALSE;
    ifIndex = Bcdc[2] & 15u;
    return (Bcdc[0] & 3u) == AP6256_FIPS_BCDC_TX_EXEMPT ?
        Ap6256FipsTxCurrent(Ctx, ifIndex, Bcdc + skip, Length - skip) : !Ap6256FipsActive(Ctx, ifIndex);
}
