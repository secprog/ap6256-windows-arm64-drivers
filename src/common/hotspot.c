/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "hotspot.h"
#include "host_fips.h"
#include "bcdc.h"
#include "p2p.h"
#include "tdls.h"

_Use_decl_annotations_
BOOLEAN Ap6256GoParseAssocResult(const UCHAR* Data, ULONG Length,
                                 AP6256_GO_ASSOC_RESULT* Result)
{
    UINT32 fields[8];
    ULONG i;
    RtlZeroMemory(Result, sizeof(*Result));
    if (Data == NULL || Length < 34) return FALSE;
    RtlCopyMemory(fields, Data, sizeof(fields));
    for (i = 0; i < 6; i += 2) {
        if (fields[i + 1] != 0 &&
            (fields[i] < 34 || fields[i] > Length || fields[i + 1] > Length - fields[i]))
            return FALSE;
    }
    if (fields[3] < 6) return FALSE;
    Result->Response = Data + fields[2];
    Result->ResponseLength = fields[3];
    Result->StatusCode = (UINT16)(Result->Response[2] | ((UINT16)Result->Response[3] << 8));
    if (fields[5] != 0) {
        Result->Beacon = Data + fields[4];
        Result->BeaconLength = fields[5];
    }
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN Ap6256GoIesValid(const UCHAR* Ies, ULONG Length)
{
    if (Ies == NULL) return (BOOLEAN)(Length == 0);
    while (Length >= 2) {
        ULONG size = (ULONG)Ies[1] + 2;
        if (size > Length) return FALSE;
        Ies += size;
        Length -= size;
    }
    return (BOOLEAN)(Length == 0);
}

_Use_decl_annotations_
BOOLEAN Ap6256GoAssociationAllowed(const AP6256_AP_PARAMS* Params,
    const UCHAR* Ies, ULONG Length)
{
    BOOLEAN p2p = FALSE;
    if (Ies == NULL) return (BOOLEAN)(Length == 0 && !Params->RejectNonP2pClients);

    while (Length >= 2) {
        ULONG size = (ULONG)Ies[1] + 2;
        if (size > Length) return FALSE;
        if (Length >= 6 && Ies[0] == 221 && size >= 6 && Ies[2] == 0x50 &&
            Ies[3] == 0x6f && Ies[4] == 0x9a && Ies[5] == 9) p2p = TRUE;
        Ies += size;
        Length -= size;
    }
    return (BOOLEAN)(Length == 0 && (!Params->RejectNonP2pClients || p2p));
}

static BOOLEAN Ap6256GoAppendIeBytes(PUCHAR Buffer, PULONG Length, ULONG Capacity,
    const UCHAR* Bytes, ULONG Count)
{
    if (*Length > Capacity || Count > Capacity - *Length ||
        !Ap6256GoIesValid(Bytes, Count)) return FALSE;
    if (Count) RtlCopyMemory(Buffer + *Length, Bytes, Count);
    *Length += Count;
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoBuildAutoAssoc(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_AP_PARAMS* Params, const AP6256_AP_PEER_INFO* Info,
    const UCHAR* Ies, ULONG Length, AP6256_GO_AUTO_ASSOC* Assoc)
{

    UCHAR rsn[] = {48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
    UCHAR rates[20], ssid[34], channel[3];
    ULONG rateLength = 0, i;
    UINT16 value;
    RtlZeroMemory(Assoc, sizeof(*Assoc));
    if (Length == 0 || Length > AP6256_GO_ASSOC_IE_MAX || !Ap6256GoIesValid(Ies, Length) ||
        Info->SsidLength != Params->SsidLength || Info->SsidLength > 32 ||
        !RtlEqualMemory(Info->Ssid, Params->Ssid, Info->SsidLength) ||
        Info->RateCount == 0 || Info->RateCount > 16 || Info->Aid == 0 || Info->Aid > 2007 ||
        Info->BeaconPeriod == 0 || Info->BeaconLength > sizeof(Info->Beacon) ||
        !Ap6256GoIesValid(Info->Beacon, Info->BeaconLength) ||
        (Params->Security != Ap6256SecurityWpa2Host && Params->Security != Ap6256SecurityOpen))
        return STATUS_DEVICE_DATA_ERROR;

    RtlCopyMemory(Assoc->Request, &Info->Capability, 2);
    RtlCopyMemory(Assoc->Request + 2, &Info->ListenInterval, 2);
    RtlCopyMemory(Assoc->Request + 4, Ies, Length);
    Assoc->RequestLength = Length + 4;

    value = (UINT16)(Info->ApCapability & ~0x10u);
    if (Params->Security == Ap6256SecurityWpa2Host) value |= 0x10u;
    TraceDiag("hotspot: association capability base 0x%04X effective 0x%04X\n",
        (ULONG)Info->ApCapability, (ULONG)value);
    RtlCopyMemory(Assoc->Response, &value, 2);

    RtlCopyMemory(Assoc->Beacon + 8, &Info->BeaconPeriod, 2);
    RtlCopyMemory(Assoc->Beacon + 10, &value, 2);
    Assoc->BeaconLength = AP6256_BEACON_FIXED_LEN;

    value = Info->Aid | 0xc000u;
    RtlCopyMemory(Assoc->Response + 4, &value, 2);
    Assoc->ResponseLength = 6;
    rates[rateLength++] = 1;
    rates[rateLength++] = (UCHAR)min(Info->RateCount, 8u);
    for (i = 0; i < min(Info->RateCount, 8u); ++i) rates[rateLength++] = Info->Rates[i];
    if (Info->RateCount > 8) {
        rates[rateLength++] = 50;
        rates[rateLength++] = (UCHAR)(Info->RateCount - 8);
        for (i = 8; i < Info->RateCount; ++i) rates[rateLength++] = Info->Rates[i];
    }
    if (!Ap6256GoAppendIeBytes(Assoc->Response, &Assoc->ResponseLength,
            sizeof(Assoc->Response), rates, rateLength)) return STATUS_BUFFER_TOO_SMALL;
    if (Info->BeaconLength) {
        if (!Ap6256GoAppendIeBytes(Assoc->Beacon, &Assoc->BeaconLength,
                sizeof(Assoc->Beacon), Info->Beacon, Info->BeaconLength))
            return STATUS_BUFFER_TOO_SMALL;
    } else {

        if (Params->Security == Ap6256SecurityWpa2Host) {
            BOOLEAN wmm;
            NTSTATUS status = Ap6256WifiGetApWmmEnabled(Ctx, &wmm);
            if (!NT_SUCCESS(status)) return status;

            rsn[20] = wmm ? 0x0c : 0;
            TraceDiag("hotspot: fallback RSN capabilities 0x%04X WMM %u\n",
                (ULONG)rsn[20], (ULONG)wmm);
        }
        ssid[0] = 0; ssid[1] = (UCHAR)Info->SsidLength;
        RtlCopyMemory(ssid + 2, Info->Ssid, Info->SsidLength);
        channel[0] = 3; channel[1] = 1; channel[2] = (UCHAR)Ctx->Go.Channel;
        if (!Ap6256GoAppendIeBytes(Assoc->Beacon, &Assoc->BeaconLength, sizeof(Assoc->Beacon),
                ssid, Info->SsidLength + 2) ||
            !Ap6256GoAppendIeBytes(Assoc->Beacon, &Assoc->BeaconLength, sizeof(Assoc->Beacon),
                rates, rateLength) ||
            (Ctx->Go.Channel <= 14 && !Ap6256GoAppendIeBytes(Assoc->Beacon, &Assoc->BeaconLength,
                sizeof(Assoc->Beacon), channel, sizeof(channel))) ||
            (Params->Security == Ap6256SecurityWpa2Host && !Ap6256GoAppendIeBytes(Assoc->Beacon,
                &Assoc->BeaconLength, sizeof(Assoc->Beacon), rsn, sizeof(rsn))))
            return STATUS_BUFFER_TOO_SMALL;
        for (i = 0; i < 2; ++i) {
            const AP6256_P2P_IE_SLOT* slot = i == 0 ? &Ctx->Go.P2p.DriverIes[Ap6256P2pFrameBeacon]
                : &Ctx->Go.P2p.HostIes[Ap6256P2pFrameBeacon];
            if (!Ap6256GoAppendIeBytes(Assoc->Beacon, &Assoc->BeaconLength,
                    sizeof(Assoc->Beacon), slot->Bytes, slot->Length)) return STATUS_BUFFER_TOO_SMALL;
        }
    }
    for (i = 0; i < 2; ++i) {
        const AP6256_P2P_IE_SLOT* slot = i == 0 ? &Ctx->Go.P2p.DriverIes[Ap6256P2pFrameAssocResponse]
            : &Ctx->Go.P2p.HostIes[Ap6256P2pFrameAssocResponse];
        if (!Ap6256GoAppendIeBytes(Assoc->Response, &Assoc->ResponseLength,
                sizeof(Assoc->Response), slot->Bytes, slot->Length)) return STATUS_BUFFER_TOO_SMALL;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoDisconnectPeer(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address,
                                 UINT16 Reason)
{
    UCHAR request[12] = {0};
    UINT32 reason = Reason;
    if (!Ctx->Go.FirmwareReady) return STATUS_DEVICE_NOT_READY;
    RtlCopyMemory(request, &reason, sizeof(reason));
    RtlCopyMemory(request + sizeof(reason), Address, 6);
    return Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, 201  ,
                              request, sizeof(request));
}

_Use_decl_annotations_
NTSTATUS Ap6256WaitFirmwareInterface(PAP6256_DEVICE_CONTEXT Ctx,
                                      UINT32 BssIndex, PUINT32 IfIndex)
{
    ULONG attempt;
    LARGE_INTEGER delay;
    *IfIndex = 0;
    if (BssIndex == 0 || BssIndex >= RTL_NUMBER_OF(Ctx->FirmwareIfMap))
        return STATUS_INVALID_PARAMETER;
    delay.QuadPart = -100000;
    for (attempt = 0; attempt < 100; ++attempt) {
        LONG mapping = InterlockedCompareExchange(&Ctx->FirmwareIfMap[BssIndex], 0, 0);
        if (mapping > 1 && mapping <= 16) {
            *IfIndex = (UINT32)(mapping - 1);
            return STATUS_SUCCESS;
        }
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
    TraceError(TRACE_NETADAPTER, "hotspot: no IF event for bsscfg %u\n", BssIndex);
    return STATUS_IO_TIMEOUT;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoPrepare(PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 one = 1;
    NTSTATUS status, upStatus;

    status = Ap6256WifiRadioUpDown(Ctx, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovar(Ctx, "apsta", &one, sizeof(one));
    upStatus = Ap6256WifiRadioUpDown(Ctx, TRUE);
    return NT_SUCCESS(status) ? upStatus : status;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoSetBsscfg(PAP6256_DEVICE_CONTEXT Ctx, PCSTR Name,
                            const VOID* Data, ULONG Length)
{
    CHAR name[64];
    PUCHAR payload;
    SIZE_T size;
    NTSTATUS status;
    if (!Ctx->Go.FirmwareReady) return STATUS_DEVICE_NOT_READY;
    if (Length > AP6256_BCDC_TX_MAXLEN - sizeof(UINT32) - sizeof(name))
        return STATUS_INVALID_BUFFER_SIZE;
    status = RtlStringCbPrintfA(name, sizeof(name), "bsscfg:%s", Name);
    if (!NT_SUCCESS(status)) return status;
    size = (SIZE_T)Length + sizeof(UINT32);
    payload = ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_BCDC_TX_MAXLEN, AP6256_POOL_TAG);
    if (payload == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(payload, &Ctx->Go.BssIndex, sizeof(UINT32));
    if (Length) RtlCopyMemory(payload + sizeof(UINT32), Data, Length);
    status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, name, payload, Length + sizeof(UINT32));
    RtlSecureZeroMemory(payload, size);
    ExFreePoolWithTag(payload, AP6256_POOL_TAG);
    if (!NT_SUCCESS(status)) TraceDiag("hotspot: %s if %u bsscfg %u -> 0x%08X\n",
        Name, Ctx->Go.IfIndex, Ctx->Go.BssIndex, status);
    return status;
}

static VOID Ap6256P2pTraceMemory(PAP6256_DEVICE_CONTEXT Ctx, const CHAR* Stage)
{
    CHAR text[320] = {0};
    NTSTATUS status;
    if (Ctx->FirmwareHalted || !Ctx->FirmwareFtmPatchVerified ||
        Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9)
        return;

    status = Ap6256BcdcGetIovar(Ctx, "memuse", text, sizeof(text));
    text[sizeof(text) - 1] = 0;
    TraceDiag("p2p memory %s: status 0x%08X %s\n", Stage, status,
              NT_SUCCESS(status) ? text : "");
}

_Use_decl_annotations_
NTSTATUS Ap6256GoCreate(PAP6256_DEVICE_CONTEXT Ctx)
{

    UCHAR request[10] = {0};
    UCHAR reply[20] = {0};
    UINT16 role = Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT ? 0u : AP6256_P2P_IF_GO;
    UINT16 channel;
    UINT32 chanspec = 0, one = 1;
    NTSTATUS status;
    if (!Ctx->FirmwareP2pSupported) return STATUS_NOT_SUPPORTED;
    if (Ctx->Go.NativeStateUncertain) return STATUS_DEVICE_HARDWARE_ERROR;
    if (Ctx->Go.FirmwareReady) return STATUS_SUCCESS;
    status = Ap6256TdlsSetBlocked(Ctx, TRUE);
    if (!NT_SUCCESS(status)) return status;
    (VOID)Ap6256WifiGetChanspec(Ctx, &chanspec);
    channel = (UINT16)chanspec;
    RtlCopyMemory(request, Ctx->Go.Address, 6);
    RtlCopyMemory(request + 6, &role, sizeof(role));
    RtlCopyMemory(request + 8, &channel, sizeof(channel));
    Ap6256P2pTraceMemory(Ctx, "before p2p_ifadd");
    status = Ap6256BcdcSetIovar(Ctx, "p2p_ifadd", request, sizeof(request));
    if (!NT_SUCCESS(status)) {
        Ap6256P2pTraceMemory(Ctx, "after p2p_ifadd refusal");
        goto failed;
    }
    RtlCopyMemory(reply, Ctx->Go.Address, 6);
    status = Ap6256BcdcGetIovar(Ctx, "p2p_if", reply, sizeof(reply));
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(&Ctx->Go.BssIndex, reply, sizeof(UINT32));
        status = Ap6256WaitFirmwareInterface(Ctx, Ctx->Go.BssIndex, &Ctx->Go.IfIndex);
    }
    if (NT_SUCCESS(status)) {
        Ctx->Go.FirmwareReady = TRUE;

        RtlZeroMemory(&Ctx->PowerSaveDx[1], sizeof(Ctx->PowerSaveDx[1]));
        if (role == AP6256_P2P_IF_GO)
            status = Ap6256GoSetBsscfg(Ctx, "ap_isolate", &one, sizeof(one));
    }
    if (NT_SUCCESS(status)) goto done;
failed:
    {
        AP6256_BCDC_QUERY_RESULT deleteResult = {0};
        NTSTATUS deleteStatus = Ap6256BcdcSetIovarResultIf(
            Ctx, 0, "p2p_ifdel", Ctx->Go.Address, 6, &deleteResult);
        BOOLEAN absent = deleteResult.FirmwareReply && deleteResult.FirmwareError &&
                         deleteResult.FirmwareStatus == -30;
        Ctx->Go.FirmwareReady = FALSE;
        Ctx->Go.NativeStateUncertain = (BOOLEAN)(!NT_SUCCESS(deleteStatus) && !absent);

        if (NT_SUCCESS(deleteStatus) || absent) (VOID)Ap6256TdlsSetBlocked(Ctx, FALSE);
        TraceDiag("P2P: create cleanup: status 0x%08X firmware %d reply %u absent %u\n",
            deleteStatus, deleteResult.FirmwareStatus, (ULONG)deleteResult.FirmwareReply,
            (ULONG)absent);
    }
done:
    TraceDiag("P2P: create role %u if %u bsscfg %u -> 0x%08X\n",
              (ULONG)role, Ctx->Go.IfIndex, Ctx->Go.BssIndex, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoVerifySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _In_ const AP6256_AP_PARAMS* Params)
{
    UINT32 auth = 0, wsec = 0, wpaAuth = 0;
    UINT32 wsecRestrict = 0;
    UINT32 expectedRestrict = (Params->Security == Ap6256SecurityWpa2Host ||
        Params->ExcludeUnencrypted) ? 1u : 0u;
    UINT32 expectedWsec = (Params->Security == Ap6256SecurityWpa2Host ? 4u : 0u) |
        (Ctx->Go.WpsEnabled ? 0x40u : 0u);
    UINT32 expectedWpaAuth = Params->Security == Ap6256SecurityWpa2Host ? 0x80u : 0u;
    NTSTATUS status;
    status = Ap6256BcdcQueryDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_GET_AUTH, &auth, sizeof(auth));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcQueryDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_GET_WSEC, &wsec, sizeof(wsec));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcQueryDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_GET_WPA_AUTH, &wpaAuth, sizeof(wpaAuth));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcQueryDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_GET_WEP_RESTRICT,
                                  &wsecRestrict, sizeof(wsecRestrict));
    if (!NT_SUCCESS(status)) return status;
    TraceDiag("hotspot: security if %u auth %u wsec 0x%X/0x%X wpa_auth 0x%X/0x%X (wanted/got)\n",
              Ctx->Go.IfIndex, auth, expectedWsec, wsec, expectedWpaAuth, wpaAuth);
    TraceDiag("hotspot: privacy if %u bsscfg %u OS exclude %u restrict %u/%u (wanted/got, command 81)\n",
              Ctx->Go.IfIndex, Ctx->Go.BssIndex, (ULONG)Params->ExcludeUnencrypted,
              expectedRestrict, wsecRestrict);
    if (auth != 0 || (wsec & 0x147u) != expectedWsec || wpaAuth != expectedWpaAuth ||
        wsecRestrict != expectedRestrict)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256GoWideChanspecMatches(_In_ UINT8 IoType,
    _In_ UINT32 Chanspec, _In_ UINT32 Primary)
{
    UINT32 center = Chanspec & 0xffu;
    UINT32 sideband = (Chanspec >> 8) & 7u;
    UINT32 width = Chanspec & 0x3800u;
    if (IoType != 2 || (Chanspec & 0xffffc000u) != 0xc000u) return FALSE;
    if (width == 0x1800u) {
        if (sideband > 1 || (center != 38 && center != 46 &&
            center != 151 && center != 159)) return FALSE;
        return (BOOLEAN)(Primary == center - 2 + 4 * sideband);
    }
    if (width == 0x2000u) {
        if (sideband > 3 || (center != 42 && center != 155)) return FALSE;
        return (BOOLEAN)(Primary == center - 6 + 4 * sideband);
    }
    return FALSE;
}

static UINT32 Ap6256GoSharedChanspec(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Primary, _In_ UINT32 Fallback)
{
    UINT32 station = 0, selected = Fallback;
    UINT32* list;
    ULONG index;

    const ULONG bytes = AP6256_BCDC_TX_MAXLEN - 16;
    NTSTATUS status;
    if (!Ctx->FirmwareLinkUp || Primary <= 14 || Ctx->D11IoType != 2)
        return Fallback;
    status = Ap6256WifiGetChanspec(Ctx, &station);
    if (!NT_SUCCESS(status) ||
        !Ap6256GoWideChanspecMatches(Ctx->D11IoType, station, Primary)) return Fallback;

    list = (UINT32*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, AP6256_POOL_TAG);
    if (list == NULL) return Fallback;
    status = Ap6256BcdcGetIovar(Ctx, "chanspecs", list, bytes);
    if (NT_SUCCESS(status)) {
        if (list[0] > bytes / sizeof(*list) - 1) {
            status = STATUS_DEVICE_PROTOCOL_ERROR;
        } else {
            for (index = 1; index <= list[0]; ++index) {
                if (list[index] == station) {
                    selected = station;
                    break;
                }
            }
        }
    }
    TraceDiag("hotspot: shared bandwidth primary %u station 0x%X selected 0x%X list -> 0x%08X\n",
        Primary, station, selected, status);
    ExFreePoolWithTag(list, AP6256_POOL_TAG);
    return selected;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoStart(PAP6256_DEVICE_CONTEXT Ctx, PAP6256_AP_PARAMS Params)
{
    struct { UINT32 Length; UCHAR Ssid[32]; } ssid;
    UINT32 bss[2], value, chanspec = 0;
    AP6256_SCAN_CHANNEL channel = {0};
    UINT16 narrowChanspec;
    NTSTATUS status;
    if (!Ctx->Go.Created || Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_GO ||
        Params->SsidLength == 0 || Params->SsidLength > 32)
        return STATUS_INVALID_PARAMETER;
    if (Params->Security != Ap6256SecurityWpa2Host && Params->Security != Ap6256SecurityOpen)
        return STATUS_NOT_SUPPORTED;
    status = Ap6256GoCreate(Ctx);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256FipsStop(Ctx, Ctx->Go.IfIndex);
    if (!NT_SUCCESS(status)) return status;

    if (Ctx->FirmwareLinkUp && !Ctx->FirmwareMchanSupported) {
        UINT32 primary = 0;
        status = Ap6256WifiGetChannel(Ctx, &primary);
        if (!NT_SUCCESS(status)) return status;
        if (primary == 0 || primary != Params->Channel) return STATUS_DEVICE_BUSY;
    }
    if (Params->Channel == 0 || Params->Channel > 165) return STATUS_INVALID_PARAMETER;
    channel.Number = (UINT16)Params->Channel;
    channel.Band = Params->Channel <= 14 ? Ap6256ScanBand2G : Ap6256ScanBand5G;
    status = Ap6256EncodeChanspec(Ctx->D11IoType, &channel, &narrowChanspec);
    if (!NT_SUCCESS(status)) return status;
    chanspec = Ap6256GoSharedChanspec(Ctx, Params->Channel, narrowChanspec);
    status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "chanspec", &chanspec, sizeof(chanspec));
    if (!NT_SUCCESS(status) && chanspec != narrowChanspec) {
        TraceDiag("hotspot: wide chanspec 0x%X rejected 0x%08X; retry 20 MHz 0x%X\n",
            chanspec, status, (ULONG)narrowChanspec);
        chanspec = narrowChanspec;
        status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "chanspec", &chanspec, sizeof(chanspec));
    }
    if (!NT_SUCCESS(status)) return status;
    value = 0;
    status = Ap6256GoSetBsscfg(Ctx, "auth", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = Params->Security == Ap6256SecurityWpa2Host ? 0x80u : 0u;
    status = Ap6256GoSetBsscfg(Ctx, "wpa_auth", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = (Params->Security == Ap6256SecurityWpa2Host ? 4u : 0u) |
        (Ctx->Go.WpsEnabled ? 0x40u : 0u);
    status = Ap6256GoSetBsscfg(Ctx, "wsec", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;

    value = (Params->Security == Ap6256SecurityWpa2Host || Params->ExcludeUnencrypted) ? 1u : 0u;
    status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_WEP_RESTRICT,
                                &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    if (Params->BeaconPeriod) {
        value = Params->BeaconPeriod;
        status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_BCNPRD, &value, sizeof(value));
        if (!NT_SUCCESS(status)) return status;
    }
    if (Params->DtimPeriod) {
        value = Params->DtimPeriod;
        status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_DTIMPRD, &value, sizeof(value));
        if (!NT_SUCCESS(status)) return status;
    }
    RtlZeroMemory(&ssid, sizeof(ssid));
    ssid.Length = Params->SsidLength;
    RtlCopyMemory(ssid.Ssid, Params->Ssid, ssid.Length);
    status = Ap6256GoSetBsscfg(Ctx, "ssid", &ssid, sizeof(ssid));
    if (!NT_SUCCESS(status)) return status;
    Ctx->Go.P2p.OperatingChannel = (UCHAR)Params->Channel;
    if (Ctx->Go.P2p.OperatingChannel <= 14) Ctx->Go.P2p.OperatingClass = 81;
    else if (Ctx->Go.P2p.OperatingChannel <= 48) Ctx->Go.P2p.OperatingClass = 115;
    else if (Ctx->Go.P2p.OperatingChannel <= 64) Ctx->Go.P2p.OperatingClass = 118;
    else if (Ctx->Go.P2p.OperatingChannel <= 144) Ctx->Go.P2p.OperatingClass = 121;
    else if (Ctx->Go.P2p.OperatingChannel <= 161) Ctx->Go.P2p.OperatingClass = 124;
    else Ctx->Go.P2p.OperatingClass = 125;
    status = Ap6256P2pBuildIesFor(Ctx, &Ctx->Go.P2p, Ctx->Go.IfIndex);
    if (!NT_SUCCESS(status)) return status;
    bss[0] = Ctx->Go.BssIndex;
    bss[1] = 1;
    Ctx->Go.Stopping = FALSE;
    status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "bss", bss, sizeof(bss));
    if (NT_SUCCESS(status)) {
        Ctx->Go.Channel = Params->Channel;
        Ctx->Go.Started = TRUE;
        status = Ap6256GoVerifySecurity(Ctx, Params);
        Ap6256WifiTraceApBss(Ctx, Ctx->Go.IfIndex);
    }
    TraceDiag("hotspot: start GO if %u bsscfg %u chanspec 0x%X -> 0x%08X\n",
              Ctx->Go.IfIndex, Ctx->Go.BssIndex, chanspec, status);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoStop(PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 bss[2] = {Ctx->Go.BssIndex, 0};
    NTSTATUS status = STATUS_SUCCESS;
    if (Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT)
        return Ap6256ClientDisconnect(Ctx, 3);
    Ctx->Go.Stopping = TRUE;
    if (Ctx->Go.FirmwareReady)
        status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "bss", bss, sizeof(bss));
    if (NT_SUCCESS(status)) Ctx->Go.Started = FALSE;

    if (NT_SUCCESS(status) && Ctx->Go.FirmwareReady &&
        !(Ctx->FirmwareFtmPatchVerified && Ctx->Chip.ChipId == 0x4345 &&
          Ctx->Chip.ChipRev == 9)) {
        UINT32 zero = 0;
        (VOID)Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "key_remove_all", NULL, 0);
        (VOID)Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_KEY_PRIMARY, &zero, sizeof(zero));
    } else if (NT_SUCCESS(status) && Ctx->Go.FirmwareReady) {
        TraceDiag("hotspot: verified BSS-down owns GO key cleanup\n");
    }
    if (!NT_SUCCESS(status)) Ctx->Go.Stopping = FALSE;
    TraceDiag("hotspot: stop GO if %u -> 0x%08X\n", Ctx->Go.IfIndex, status);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256GoDelete(PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN wasReady = Ctx->Go.FirmwareReady;
    if (Ctx->Go.NativeStateUncertain) return STATUS_DEVICE_HARDWARE_ERROR;
    if (Ctx->Go.FirmwareReady) {
        status = Ap6256FipsRetire(Ctx, Ctx->Go.IfIndex);
        if (!NT_SUCCESS(status)) return status;
    }
    if (Ctx->Go.FirmwareReady) {
        status = Ap6256GoStop(Ctx);
        if (!NT_SUCCESS(status)) return status;
        status = Ap6256BcdcSetIovar(Ctx, "p2p_ifdel", Ctx->Go.Address, 6);
        if (NT_SUCCESS(status) && Ctx->Go.BssIndex < RTL_NUMBER_OF(Ctx->FirmwareIfMap)) {
            ULONG attempt;
            LARGE_INTEGER delay;
            delay.QuadPart = -100000;
            for (attempt = 0; attempt < 100; ++attempt) {
                if (InterlockedCompareExchange(&Ctx->FirmwareIfMap[Ctx->Go.BssIndex], 0, 0) == 0) break;
                (VOID)KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }

            Ctx->Go.FirmwareReady = FALSE;
            if (attempt == 100) {
                InterlockedExchange(&Ctx->FirmwareIfMap[Ctx->Go.BssIndex], 0);
                status = STATUS_IO_TIMEOUT;
            }
        }
    }
    if (NT_SUCCESS(status)) {
        Ctx->Go.FirmwareReady = FALSE;
        Ctx->Go.Started = FALSE;
        Ap6256P2pForgetIesFor(&Ctx->Go.P2p);

        if (wasReady) (VOID)Ap6256TdlsSetBlocked(Ctx, FALSE);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256GroupChangeMode(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Mode)
{
    UINT32 previous = Ctx->Go.Mode;
    NTSTATUS status;
    if (Mode != AP6256_WDI_OPMODE_P2P_CLIENT && Mode != AP6256_WDI_OPMODE_P2P_GO)
        return STATUS_NOT_SUPPORTED;
    if (!Ctx->Go.Created || Ctx->Go.Started) return STATUS_INVALID_DEVICE_STATE;
    if (Mode == previous) return Ap6256GoCreate(Ctx);
    Ap6256P2pReleaseIesFor(Ctx, &Ctx->Go.P2p, Ctx->Go.IfIndex);
    status = Ap6256GoDelete(Ctx);
    if (!NT_SUCCESS(status)) {

        Ctx->Go.NativeStateUncertain = TRUE;
        return status;
    }
    Ctx->Go.Mode = Mode;
    status = Ap6256GoCreate(Ctx);
    if (!NT_SUCCESS(status)) {
        Ctx->Go.Mode = previous;
        (VOID)Ap6256GoCreate(Ctx);
    }
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256ClientConnect(PAP6256_DEVICE_CONTEXT Ctx,
                              const AP6256_CONNECT_PARAMS* Params)
{

    UCHAR join[50] = {0};
    UINT32 value;
    UINT16 chanspec;
    AP6256_SCAN_CHANNEL channel;
    NTSTATUS status;
    BOOLEAN hadFips = Ap6256FipsActive(Ctx, Ctx->Go.IfIndex);
    if (!Ctx->Go.Created || !Ctx->Go.FirmwareReady ||
        Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_CLIENT)
        return STATUS_INVALID_DEVICE_STATE;
    if (!Params->BssidValid || Params->SsidLength == 0 || Params->SsidLength > 32 ||
        Params->Channel == 0 || Params->Channel > 165)
        return STATUS_INVALID_PARAMETER;
    if (Params->Security != Ap6256SecurityOpen && Params->Security != Ap6256SecurityWpa2Host)
        return STATUS_NOT_SUPPORTED;
    if (Params->HostFips && (!Ctx->HostFipsReady || Params->Mfp != Ap6256MfpNone)) return STATUS_NOT_SUPPORTED;
    if (Params->HostFips) {
        status = Ap6256FipsCheckVendorIes(Params->AssociationVendorIes, Params->AssociationVendorIesLength);
        if (!NT_SUCCESS(status)) return status;
    }
    channel.Number = (UINT16)Params->Channel;
    channel.Band = Params->Channel <= 14 ? Ap6256ScanBand2G : Ap6256ScanBand5G;
    status = Ap6256EncodeChanspec(Ctx->D11IoType, &channel, &chanspec);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256FipsStop(Ctx, Ctx->Go.IfIndex);
    if (!NT_SUCCESS(status)) return status;
    value = 0;
    status = Ap6256GoSetBsscfg(Ctx, "auth", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = Params->Security == Ap6256SecurityWpa2Host ? 0x80u : 0u;
    status = Ap6256GoSetBsscfg(Ctx, "wpa_auth", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = (Params->Security == Ap6256SecurityWpa2Host ? 4u : 0u) |
        (Ctx->Go.WpsEnabled ? 0x40u : 0u) | (Params->Mfp != Ap6256MfpNone ? 0x200u : 0u);
    status = Ap6256GoSetBsscfg(Ctx, "wsec", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = (UINT32)Params->Mfp;
    status = Ap6256GoSetBsscfg(Ctx, "mfp", &value, sizeof(value));
    if (!NT_SUCCESS(status) && (value != 0 || Params->HostFips)) return status;
    if (Params->HostFips || hadFips) {
        status = Ap6256FipsSetQos(Ctx, Ctx->Go.IfIndex, Params->HostFips ? Params->HostFipsHt : TRUE);
        if (!NT_SUCCESS(status)) return status;
    }

    value = 1;
    status = Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "roam_off", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_INFRA, &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    if (Params->HostFips) {
        status = Ap6256FipsVerifySecurity(Ctx, Ctx->Go.IfIndex,
            (Params->Security == Ap6256SecurityWpa2Host ? 4u : 0u) | (Ctx->Go.WpsEnabled ? 0x40u : 0u),
            Params->Security == Ap6256SecurityWpa2Host ? 0x80u : 0u);
        if (!NT_SUCCESS(status)) return status;
    }
    RtlCopyMemory(join, &Params->SsidLength, sizeof(UINT32));
    RtlCopyMemory(join + 4, Params->Ssid, Params->SsidLength);
    RtlCopyMemory(join + 36, Params->Bssid, 6);
    RtlCopyMemory(join + 44, &value, sizeof(value));
    RtlCopyMemory(join + 48, &chanspec, sizeof(chanspec));
    Ctx->Go.Stopping = FALSE;
    if (Params->HostFips) {
        status = Ap6256FipsBegin(Ctx, Ctx->Go.IfIndex, Ctx->Go.Address, Params->Bssid);
        if (!NT_SUCCESS(status)) return status;
    }
    status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_SSID, join, sizeof(join));
    if (Params->HostFips && !NT_SUCCESS(status)) (VOID)Ap6256FipsStop(Ctx, Ctx->Go.IfIndex);
    TraceDiag("P2P client: join if %u bsscfg %u channel %u -> 0x%08X\n",
              Ctx->Go.IfIndex, Ctx->Go.BssIndex, Params->Channel, status);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256ClientDisconnect(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Reason)
{
    UCHAR scb[12] = {0};
    NTSTATUS status = STATUS_SUCCESS;
    Ctx->Go.Stopping = TRUE;
    (VOID)Ap6256FipsRetire(Ctx, Ctx->Go.IfIndex);
    if (Ctx->Go.FirmwareReady) {

        RtlCopyMemory(scb, &Reason, sizeof(Reason));
        RtlCopyMemory(scb + 4, Ctx->Go.ClientBssid, 6);
        if (Ctx->Go.Started || Ctx->Go.ClientConnected)
            status = Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_DISASSOC, scb, sizeof(scb));
        if (NT_SUCCESS(status)) {
            UINT32 zero = 0;
            (VOID)Ap6256BcdcSetIovarIf(Ctx, Ctx->Go.IfIndex, "key_remove_all", NULL, 0);
            (VOID)Ap6256BcdcSetDcmdIf(Ctx, Ctx->Go.IfIndex, BRCMF_C_SET_KEY_PRIMARY, &zero, sizeof(zero));
        }
    }
    if (NT_SUCCESS(status)) Ctx->Go.Started = FALSE;
    else Ctx->Go.Stopping = FALSE;
    TraceDiag("P2P client: disconnect if %u reason %u -> 0x%08X\n",
              Ctx->Go.IfIndex, Reason, status);
    return status;
}
