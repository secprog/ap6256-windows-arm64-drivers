/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"

static NTSTATUS Ap6256MboWithdraw(PAP6256_WIFI Wifi)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (Wifi->Mbo.AssociationInstalled) {
        status = Ap6256WifiSetStationVendorIes(Wifi->Ctx, AP6256_P2P_IE_ASSOC_REQ, FALSE,
            Wifi->Mbo.AssociationIes, Wifi->Mbo.AssociationIesLength);
        if (!NT_SUCCESS(status)) return status;
        Wifi->Mbo.AssociationInstalled = FALSE;
    }
    if (Wifi->Mbo.ProbeInstalled) {
        status = Ap6256WifiSetStationVendorIes(Wifi->Ctx, AP6256_P2P_IE_PROBE_REQ, FALSE,
            Wifi->Mbo.ProbeIe, Wifi->Mbo.ProbeIeLength);
        if (NT_SUCCESS(status)) Wifi->Mbo.ProbeInstalled = FALSE;
    }
    return status;
}

static NTSTATUS Ap6256MboReplace(PAP6256_WIFI Wifi, UINT32 Mask,
    UCHAR* Owned, ULONG* OwnedLength, BOOLEAN* Installed, const UCHAR* Next, ULONG Length)
{
    NTSTATUS status;
    BOOLEAN previous = *Installed;
    if (previous && *OwnedLength == Length && RtlEqualMemory(Owned, Next, Length))
        return STATUS_SUCCESS;
    if (previous) {
        status = Ap6256WifiSetStationVendorIes(Wifi->Ctx, Mask, FALSE, Owned, *OwnedLength);
        if (!NT_SUCCESS(status)) return status;
        *Installed = FALSE;
    }
    if (Length) {
        status = Ap6256WifiSetStationVendorIes(Wifi->Ctx, Mask, TRUE, Next, Length);
        if (!NT_SUCCESS(status)) {
            if (previous) {
                NTSTATUS restore = Ap6256WifiSetStationVendorIes(Wifi->Ctx, Mask, TRUE, Owned, *OwnedLength);
                *Installed = NT_SUCCESS(restore);
                if (!NT_SUCCESS(restore)) {
                    Wifi->Mbo.Enabled = FALSE;
                    TraceDiag("MBO: template restore failed 0x%08X, disabling capability\n", restore);
                }
            }
            return status;
        }
        *Installed = TRUE;
    }
    if(Length) RtlCopyMemory(Owned, Next, Length);
    *OwnedLength = Length;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256MboTemplates(PAP6256_WIFI Wifi, const UCHAR* Probe, ULONG ProbeLength,
    const UCHAR* Association, ULONG AssociationLength)
{
    UCHAR oldProbe[AP6256_MBO_IE_MAX];
    ULONG oldLength = Wifi->Mbo.ProbeInstalled ? Wifi->Mbo.ProbeIeLength : 0;
    NTSTATUS status;
    RtlCopyMemory(oldProbe, Wifi->Mbo.ProbeIe, oldLength);
    status = Ap6256MboReplace(Wifi, AP6256_P2P_IE_PROBE_REQ, Wifi->Mbo.ProbeIe,
        &Wifi->Mbo.ProbeIeLength, &Wifi->Mbo.ProbeInstalled, Probe, ProbeLength);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256MboReplace(Wifi, AP6256_P2P_IE_ASSOC_REQ, Wifi->Mbo.AssociationIes,
        &Wifi->Mbo.AssociationIesLength, &Wifi->Mbo.AssociationInstalled, Association, AssociationLength);
    if (!NT_SUCCESS(status)) {
        NTSTATUS restore = Ap6256MboReplace(Wifi, AP6256_P2P_IE_PROBE_REQ, Wifi->Mbo.ProbeIe,
            &Wifi->Mbo.ProbeIeLength, &Wifi->Mbo.ProbeInstalled, oldProbe, oldLength);
        if (!NT_SUCCESS(restore)) Wifi->Mbo.Enabled = FALSE;
    }
    return status;
}

static NTSTATUS Ap6256MboBandPreferences(const AP6256_MBO_PREFERENCES* Requested,
    LONG Bands, AP6256_MBO_PREFERENCES* Effective)
{
    AP6256_MBO_CHANNEL channels[AP6256_MBO_CHANNEL_MAX];
    ULONG count = Requested->Count, channel, i;
    UCHAR cellular = Requested->CellularCapability ? Requested->CellularCapability : 3;
    if (count > AP6256_MBO_CHANNEL_MAX) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(channels, Requested->Channels, count * sizeof(channels[0]));
    for (channel = 1; channel <= 165; channel++) {
        UCHAR op = 0;
        if (channel <= 14 && (Bands & AP6256_DISALLOW_BAND_2G) &&
            Ap6256ChannelSupported(Ap6256ScanBand2G, channel)) op = channel == 14 ? 82 : 81;
        else if (channel > 14 && (Bands & AP6256_DISALLOW_BAND_5G) &&
            Ap6256ChannelSupported(Ap6256ScanBand5G, channel))
            op = channel <= 48 ? 115 : (channel <= 64 ? 118 : (channel <= 144 ? 121 : 125));
        if (!op) continue;
        for (i = 0; i < count; i++)
            if (channels[i].OperatingClass == op && channels[i].Channel == channel) break;
        if (i == count) {
            if (count == AP6256_MBO_CHANNEL_MAX) return STATUS_BUFFER_OVERFLOW;
            ++count;
        }
        channels[i].OperatingClass = op; channels[i].Channel = (UCHAR)channel;
        channels[i].Preference = 0; channels[i].Reason = 0;
    }
    return Ap6256MboSetPreferences(Effective, cellular, channels, count);
}

static NTSTATUS Ap6256MboReplaceOwnIe(const UCHAR* Ies, ULONG Length,
    const UCHAR* Ie, ULONG IeLength, UCHAR* Result, ULONG Capacity, ULONG* ResultLength)
{
    ULONG offset = 0, written = 0;
    while (offset < Length) {
        ULONG size;
        if (Length - offset < 2 || Ies[offset + 1] > Length - offset - 2)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        size = 2u + Ies[offset + 1];
        if (!(size >= 6 && Ies[offset] == 221 &&
            RtlEqualMemory(Ies + offset + 2, "\x50\x6f\x9a\x16", 4))) {
            if (size > Capacity - written) return STATUS_BUFFER_OVERFLOW;
            RtlCopyMemory(Result + written, Ies + offset, size); written += size;
        }
        offset += size;
    }
    if (IeLength > Capacity - written) return STATUS_BUFFER_OVERFLOW;
    RtlCopyMemory(Result + written, Ie, IeLength);
    *ResultLength = written + IeLength;
    return STATUS_SUCCESS;
}

NTSTATUS Ap6256MboInitialize(PAP6256_WIFI Wifi)
{
    NTSTATUS status;
    if (!Wifi->Ctx->FirmwareNativeManagement || !Wifi->Ctx->FirmwareBssTransitionEnabled ||
        !Wifi->Ctx->FirmwareMfpSupported || !Wifi->Ctx->FirmwareMboTransport) return STATUS_NOT_SUPPORTED;
    if (!Wifi->Mbo.RequestedPreferences.CellularCapability) {

        status = Ap6256MboSetPreferences(&Wifi->Mbo.RequestedPreferences, 3, NULL, 0);
        if (!NT_SUCCESS(status)) return status;
    }
    status = Ap6256MboBandPreferences(&Wifi->Mbo.RequestedPreferences,
        InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0), &Wifi->Mbo.Preferences);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256MboWithdraw(Wifi);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256MboBuildIe(&Wifi->Mbo.Preferences, Wifi->Mbo.ProbeIe,
        sizeof(Wifi->Mbo.ProbeIe), &Wifi->Mbo.ProbeIeLength);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256WifiSetStationVendorIes(Wifi->Ctx, AP6256_P2P_IE_PROBE_REQ, TRUE,
        Wifi->Mbo.ProbeIe, Wifi->Mbo.ProbeIeLength);
    Wifi->Mbo.ProbeInstalled = NT_SUCCESS(status);
    Wifi->Mbo.Enabled = NT_SUCCESS(status);
    TraceDiag("MBO: station vendor-IE registration -> 0x%08X, enabled %u\n", status, (ULONG)Wifi->Mbo.Enabled);
    return status;
}

VOID Ap6256MboDisassociated(PAP6256_WIFI Wifi)
{
    NTSTATUS status=Ap6256MboReplace(Wifi,AP6256_P2P_IE_ASSOC_REQ,
        Wifi->Mbo.AssociationIes,&Wifi->Mbo.AssociationIesLength,
        &Wifi->Mbo.AssociationInstalled,NULL,0);
    if(!NT_SUCCESS(status)) {
        Wifi->Mbo.Enabled=FALSE;
        TraceDiag("MBO: association template cleanup failed 0x%08X\n",status);
    } else Wifi->Mbo.AssociationOwnMbo=FALSE;
}

VOID Ap6256MboReset(PAP6256_WIFI Wifi)
{
    KIRQL irql;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);

    RtlZeroMemory(Wifi->Mbo.Scan, sizeof(Wifi->Mbo.Scan));
    RtlZeroMemory(Wifi->Mbo.Retry, sizeof(Wifi->Mbo.Retry));
    RtlZeroMemory(&Wifi->Mbo.AssociatedAp, sizeof(Wifi->Mbo.AssociatedAp));
    RtlZeroMemory(&Wifi->Mbo.Transition, sizeof(Wifi->Mbo.Transition));
    Wifi->Mbo.Associated = Wifi->Mbo.Enabled = FALSE;
    Wifi->Mbo.ProbeInstalled = Wifi->Mbo.AssociationInstalled = FALSE;
    Wifi->Mbo.ProbeIeLength = Wifi->Mbo.AssociationIesLength = 0;
    Wifi->Mbo.AssociationOwnMbo = FALSE;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
}

VOID Ap6256MboScanResult(PAP6256_WIFI Wifi, const AP6256_BSS* Bss)
{
    AP6256_MBO_AP ap;
    ULONG i, selected = 0, offset = 0;
    ULONGLONG oldest = ~((ULONGLONG)0), now = (ULONGLONG)Ap6256InterruptTimeMs();
    BOOLEAN secure = FALSE;
    KIRQL irql;
    if (!NT_SUCCESS(Ap6256MboParseIes(Bss->Ies, Bss->IesLength, &ap))) return;
    while (offset < Bss->IesLength) {
        if (Bss->Ies[offset] == 48) secure = TRUE;
        offset += 2u + Bss->Ies[offset + 1];
    }
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    for (i = 0; i < AP6256_MBO_AP_MAX; i++) {
        if (RtlEqualMemory(Wifi->Mbo.Scan[i].Bssid, Bss->Bssid, 6)) { selected = i; break; }
        if (Wifi->Mbo.Scan[i].Seen < oldest) { selected = i; oldest = Wifi->Mbo.Scan[i].Seen; }
    }
    RtlCopyMemory(Wifi->Mbo.Scan[selected].Bssid, Bss->Bssid, 6);
    Wifi->Mbo.Scan[selected].Seen = now;
    Wifi->Mbo.Scan[selected].Ap = ap;
    Wifi->Mbo.Scan[selected].Secure = secure;
    Wifi->Mbo.Scan[selected].PmfCapable = Ap6256WifiIesPmfCapable(Bss->Ies, Bss->IesLength);
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
}

BOOLEAN Ap6256MboJoinBlocked(PAP6256_WIFI Wifi, const UCHAR* Bssid)
{
    ULONG i;
    KIRQL irql;
    ULONGLONG now = (ULONGLONG)Ap6256InterruptTimeMs();
    BOOLEAN blocked;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    blocked = Ap6256MboRetryBlocked(&Wifi->Mbo, Bssid, now);
    for (i = 0; !blocked && i < AP6256_MBO_AP_MAX; i++) {
        const AP6256_MBO_SCAN_AP* scan = &Wifi->Mbo.Scan[i];
        if (scan->Ap.Present && scan->Ap.AssociationDisallowed && scan->Seen <= now &&
            now - scan->Seen <= 30000 && RtlEqualMemory(scan->Bssid, Bssid, 6))
            blocked = TRUE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    return blocked;
}

NTSTATUS Ap6256MboCopyVendorIes(AP6256_CONNECT_PARAMS* Params, const UCHAR* Ies, ULONG Length)
{
    ULONG offset = 0;
    AP6256_MBO_AP ap;
    NTSTATUS status;
    if (!Length) return STATUS_SUCCESS;
    if (!Ies || Length > sizeof(Params->AssociationVendorIes) - Params->AssociationVendorIesLength)
        return STATUS_INVALID_PARAMETER;
    status = Ap6256MboParseIes(Ies, Length, &ap);
    if (!NT_SUCCESS(status)) return status;
    while (offset < Length) {
        if (Ies[offset] != 221 || Ies[offset + 1] < 3) return STATUS_INVALID_PARAMETER;
        offset += 2u + Ies[offset + 1];
    }
    RtlCopyMemory(Params->AssociationVendorIes + Params->AssociationVendorIesLength, Ies, Length);
    Params->AssociationVendorIesLength += Length;
    status = Ap6256MboParseIes(Params->AssociationVendorIes, Params->AssociationVendorIesLength, &ap);
    if (!NT_SUCCESS(status)) Params->AssociationVendorIesLength -= Length;
    return status;
}

NTSTATUS Ap6256MboPrepareJoin(PAP6256_WIFI Wifi, const AP6256_CONNECT_PARAMS* Params)
{
    AP6256_MBO_AP ap = {0};
    AP6256_MBO_PREFERENCES requested, preferences;
    UCHAR ie[AP6256_MBO_IE_MAX];
    UCHAR association[AP6256_STATION_VENDOR_IE_MAX];
    ULONG ieLength = 0, assocLength = Params->AssociationVendorIesLength, i;
    const UCHAR* publicIes = Params->Security == Ap6256SecurityOweHost ? Params->OweExtra : Params->AssociationVendorIes;
    ULONG publicLength = Params->Security == Ap6256SecurityOweHost ? Params->OweExtraLength : Params->AssociationVendorIesLength;
    BOOLEAN allowed = Wifi->Mbo.Enabled;
    KIRQL irql;
    NTSTATUS status;
    if (assocLength > sizeof(association)) return STATUS_INVALID_PARAMETER;
    if (Params->BssidValid && Ap6256MboJoinBlocked(Wifi, Params->Bssid)) return STATUS_NETWORK_UNREACHABLE;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    requested = Wifi->Mbo.RequestedPreferences;
    for (i = 0; i < AP6256_MBO_AP_MAX; i++) {
        if (Params->BssidValid && RtlEqualMemory(Wifi->Mbo.Scan[i].Bssid, Params->Bssid, 6) &&
            Wifi->Mbo.Scan[i].Secure && (!Wifi->Mbo.Scan[i].PmfCapable || Params->Mfp == Ap6256MfpNone))
            allowed = FALSE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    if (Params->Security != Ap6256SecurityOpen && Params->Mfp == Ap6256MfpNone) allowed = FALSE;
    status = Ap6256MboParseIes(publicIes, publicLength, &ap);
    if (!NT_SUCCESS(status)) return status;
    if (ap.Present) {
        if (!allowed) return STATUS_NOT_SUPPORTED;
        status = Ap6256MboPreferencesFromIes(publicIes, publicLength, &requested);
        if (!NT_SUCCESS(status)) return status;
    }
    status = Ap6256MboBandPreferences(&requested,
        InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0), &preferences);
    if (!NT_SUCCESS(status)) return status;

    if (Wifi->Mbo.Enabled) {
        status = Ap6256MboBuildIe(&preferences, ie, sizeof(ie), &ieLength);
        if (!NT_SUCCESS(status)) return status;
    }
    RtlCopyMemory(association, Params->AssociationVendorIes, assocLength);

    if (allowed && !ap.Present) {
        if (ieLength > sizeof(association) - assocLength) return STATUS_BUFFER_OVERFLOW;
        RtlCopyMemory(association + assocLength, ie, ieLength); assocLength += ieLength;
    }
    status = Ap6256MboTemplates(Wifi, ie, ieLength, association, assocLength);
    if (!NT_SUCCESS(status)) return status;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    Wifi->Mbo.RequestedPreferences = requested; Wifi->Mbo.Preferences = preferences;
    Wifi->Mbo.AssociationOwnMbo = allowed && !ap.Present;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    return STATUS_SUCCESS;
}

VOID Ap6256MboAssociation(PAP6256_WIFI Wifi, BOOLEAN Success, const UCHAR* Bssid,
    const AP6256_ASSOC_FRAMES* Frames, BOOLEAN Pmf)
{
    AP6256_MBO_AP ap = {0};
    KIRQL irql;
    if (Success && Frames->Beacon && Frames->BeaconLength >= AP6256_BEACON_FIXED_LEN &&
        RtlEqualMemory(Frames->BeaconBssid, Bssid, 6)) {
        (VOID)Ap6256MboParseIes(Frames->Beacon + AP6256_BEACON_FIXED_LEN,
            Frames->BeaconLength - AP6256_BEACON_FIXED_LEN, &ap);
    }
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    Wifi->Mbo.Associated = Success && Wifi->Mbo.Enabled && ap.Present &&
        (Wifi->AuthAlgorithm == WDI_AUTH_ALGO_80211_OPEN || Pmf);
    Wifi->Mbo.AssociatedAp = ap;
    RtlZeroMemory(&Wifi->Mbo.Transition, sizeof(Wifi->Mbo.Transition));
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
}

VOID Ap6256MboBtmRequest(PAP6256_WIFI Wifi, const UCHAR* Peer, const UCHAR* Body, ULONG Length)
{
    AP6256_MBO_AP ap;
    UCHAR token;
    KIRQL irql;
    if (!NT_SUCCESS(Ap6256MboParseBtmRequest(Body, Length, &ap, &token))) return;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    if (Wifi->Mbo.Associated && Wifi->ConnectionActive && Wifi->ConnectBssidValid &&
        RtlEqualMemory(Peer, Wifi->ConnectBssid, 6)) {
        Wifi->Mbo.Transition = ap;
        if (ap.RetrySeconds) Ap6256MboRememberRetry(&Wifi->Mbo, Peer, ap.RetrySeconds,
            (ULONGLONG)Ap6256InterruptTimeMs());
    }
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
}

NTSTATUS Ap6256MboExtendResponse(PAP6256_WIFI Wifi, const UCHAR* Peer, UCHAR* Body,
    ULONG Capacity, ULONG* Length)
{
    AP6256_MBO_AP ap;
    BOOLEAN associated;
    ULONG tail;
    KIRQL irql;
    NTSTATUS status;
    if (*Length < 5 || Body[0] != 10 || Body[1] != 8 || Body[3] == 0) return STATUS_SUCCESS;
    status = Ap6256MboParseIes(Body + 5, *Length - 5, &ap);
    if (!NT_SUCCESS(status)) return status;
    if (ap.Attributes & AP6256_MBO_ATTR(7)) return STATUS_SUCCESS;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    associated = Wifi->Mbo.Associated && Wifi->ConnectionActive && Wifi->ConnectBssidValid &&
        RtlEqualMemory(Peer, Wifi->ConnectBssid, 6);
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    if (!associated) return STATUS_SUCCESS;

    if (*Length > Capacity) return STATUS_BUFFER_TOO_SMALL;
    status = Ap6256MboBuildReject(0, Body + *Length, Capacity - *Length, &tail);
    if (NT_SUCCESS(status)) *Length += tail;
    return status;
}

NTSTATUS Ap6256MboSetBands(PAP6256_WIFI Wifi, LONG Bands, BOOLEAN Notify)
{
    AP6256_MBO_PREFERENCES preferences, previous;
    ULONG length, ieLength, assocLength = Wifi->Mbo.AssociationIesLength;
    UCHAR body[768], peer[6], token, ie[AP6256_MBO_IE_MAX];
    UCHAR association[AP6256_STATION_VENDOR_IE_MAX];
    UINT32 associatedChannel;
    BOOLEAN associated;
    KIRQL irql;
    NTSTATUS status;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    previous = Wifi->Mbo.Preferences;
    associated = Wifi->Mbo.Associated && Wifi->ConnectionActive && Wifi->ConnectBssidValid;
    RtlCopyMemory(peer, Wifi->ConnectBssid, 6); associatedChannel = Wifi->ConnectChannel;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    status = Ap6256MboBandPreferences(&Wifi->Mbo.RequestedPreferences, Bands, &preferences);
    if (!NT_SUCCESS(status)) return status;
    if (Wifi->Mbo.Enabled) {
        status = Ap6256MboBuildIe(&preferences, ie, sizeof(ie), &ieLength);
        if (!NT_SUCCESS(status)) return status;
        if (Wifi->Mbo.AssociationOwnMbo) {
            status = Ap6256MboReplaceOwnIe(Wifi->Mbo.AssociationIes, assocLength,
                ie, ieLength, association, sizeof(association), &assocLength);
            if (!NT_SUCCESS(status)) return status;
        } else RtlCopyMemory(association, Wifi->Mbo.AssociationIes, assocLength);
        status = Ap6256MboTemplates(Wifi, ie, ieLength, association, assocLength);
        if (!NT_SUCCESS(status)) return status;
    }

    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    Wifi->Mbo.Preferences = preferences;
    token = ++Wifi->Mbo.DialogToken;
    if (!token) token = ++Wifi->Mbo.DialogToken;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    if (!Notify || !associated || RtlEqualMemory(&previous, &preferences, sizeof(preferences))) return STATUS_SUCCESS;
    status = Ap6256MboBuildNotification(&preferences, token, body, sizeof(body), &length);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256WifiSendActionFrame(Wifi->Ctx, 0, associatedChannel, 100,
        peer, peer, (UINT32)InterlockedIncrement(&Wifi->ActionFramePacketId), body, length);
    TraceDiag("MBO: preference notification submission -> 0x%08X\n", status);
    return STATUS_SUCCESS;
}
