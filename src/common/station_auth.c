/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"

static BOOLEAN Ap6256StationSaeLive(PAP6256_WIFI Wifi, LONG Generation);
static NTSTATUS Ap6256StationSaeNotice(PAP6256_WIFI Wifi, const AP6256_SAE_OUTPUT* Output);
static VOID Ap6256StationSaeFailed(PAP6256_WIFI Wifi, UINT32 Reason);
static NTSTATUS Ap6256StationSaeOutput(PAP6256_WIFI Wifi, const AP6256_SAE_OUTPUT* Output);
#include "sae_station.inc"
#include "ft_station.inc"

BOOLEAN Ap6256HostFbtAvailable(_In_ PAP6256_WIFI Wifi)
{
    return Wifi->Ctx->FirmwareFtPatchVerified && Wifi->Ctx->FirmwareHostFt;
}

BOOLEAN Ap6256HostSaeAvailable(_In_ PAP6256_WIFI Wifi)
{
    return (Wifi->Ctx->FirmwareExternalAuth || Wifi->Ctx->FirmwarePrivateSae) &&
           Wifi->Ctx->FirmwareMfpSupported && Wifi->TlvContext.PeerVersion >= WDI_VERSION_1_1_10;
}

BOOLEAN Ap6256HostOweAvailable(_In_ PAP6256_WIFI Wifi)
{
    return Wifi->Ctx->FirmwareOwePatchVerified && Wifi->Ctx->FirmwareHostOwe &&
           Wifi->Ctx->FirmwareMfpSupported && Wifi->TlvContext.PeerVersion >= WDI_VERSION_1_1_10;
}

VOID Ap6256ModelCancelAuthentication(PAP6256_WIFI Wifi)
{

    (VOID) Ap6256FtEnd(Wifi->Ctx, &Wifi->Auth.Ft, FALSE);
    Ap6256StationSaeCancel(Wifi);
    (VOID) Ap6256OweEnd(Wifi->Ctx, FALSE);
}

NTSTATUS Ap6256ModelValidateCandidates(PAP6256_WIFI Wifi, const AP6256_CONNECT_PARAMS* candidates,
                                       ULONG candidateCount, BOOLEAN isRoam)
{

    return Ap6256FtValidateCandidates(Wifi, candidates, candidateCount, isRoam);
}

NTSTATUS Ap6256ModelCopyAuthenticationCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate,
                                                const WDI_TASK_CONNECT_PARAMETERS* parameters,
                                                BOOLEAN sae, BOOLEAN owe,
                                                AP6256_CONNECT_PARAMS* output)
{

    NTSTATUS status = STATUS_SUCCESS;
    if (sae || owe || output->HostCipher) {
        status = Ap6256SaeCopyPmkid((BOOLEAN)candidate->Optional.PMKID_IsPresent,
                                    candidate->PMKID.pElements, candidate->PMKID.ElementCount,
                                    output->Pmkid, &output->PmkidValid);
        if (!NT_SUCCESS(status))
            return status;
        if (sae && output->PmkidValid) {
            status = Ap6256SaeCopyCachedH2e(
                candidate,
                parameters->ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent
                    ? parameters->ConnectParameters.AssociationRequestVendorIE.pElements
                    : NULL,
                parameters->ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent
                    ? parameters->ConnectParameters.AssociationRequestVendorIE.ElementCount
                    : 0,
                &output->SaeCachedH2e);
            if (!NT_SUCCESS(status))
                return status;
        }
    }
    return status;
}

NTSTATUS Ap6256ModelCopyFtCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate,
                                    BOOLEAN isRoam, AP6256_CONNECT_PARAMS* output)
{

    NTSTATUS status = STATUS_SUCCESS;
    status = Ap6256FtCopyCandidate(candidate, isRoam, output);
    if (!NT_SUCCESS(status))
        return status;
    return status;
}

VOID Ap6256ModelConnectionLost(PAP6256_WIFI Wifi)
{
    Ap6256FtConnectionLost(&Wifi->Auth.Ft);
}

BOOLEAN Ap6256ModelRejectStationEvent(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx,
                                      UCHAR FirmwareEvent, UINT32 FirmwareGeneration,
                                      const UCHAR* Peer)
{
    AP6256_HC_STORE_SESSION owner;
    BOOLEAN hostOwner;
    if (!FirmwareEvent) return FALSE;
    hostOwner = Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, 0, &owner);
    if (FirmwareEvent == AP6256_STATION_EVENT_HOST_CIPHER)
        return !hostOwner || !FirmwareGeneration ||
            InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
            FirmwareGeneration != owner.Generation || !Peer || !Wifi->ConnectBssidValid ||
            !RtlEqualMemory(Peer, owner.Bssid, 6) ||
            !RtlEqualMemory(Peer, Wifi->ConnectBssid, 6);

    if (FirmwareEvent != 1 || hostOwner || Wifi->Auth.HostCipherGeneration) return TRUE;
    return FirmwareEvent &&
           (FirmwareGeneration
                ? !Ctx->FirmwarePrivateSae ||
                      FirmwareGeneration != Wifi->Auth.SaeEventGeneration || Peer == NULL ||
                      !Wifi->ConnectBssidValid || !RtlEqualMemory(Peer, Wifi->ConnectBssid, 6)
                : Wifi->Auth.SaeFirmwareGeneration != 0 ||
                      (Wifi->Auth.SaeEventGeneration != 0 && Wifi->ConnectTask.Active &&
                       !Wifi->ConnectDeparting));
}

VOID Ap6256ModelCompleteAuthentication(PAP6256_WIFI Wifi)
{

    Ap6256StationSaeCancel(Wifi);
    (VOID) Ap6256OweEnd(Wifi->Ctx, FALSE);
}

BOOLEAN Ap6256ModelRetryAssociation(PAP6256_WIFI Wifi)
{
    return Ap6256StationSaeFallback(Wifi);
}

BOOLEAN Ap6256ModelStaleLinkEvent(PAP6256_WIFI Wifi, UCHAR FirmwareEvent,
                                  UINT32 FirmwareGeneration)
{
    AP6256_HC_STORE_SESSION owner;
    BOOLEAN hostOwner;
    if (!FirmwareEvent) return FALSE;
    hostOwner = Ap6256HostCipherStoreSnapshot(&Wifi->Ctx->HostCipherStore, 0, &owner);
    if (FirmwareEvent == AP6256_STATION_EVENT_HOST_CIPHER)
        return !hostOwner || !FirmwareGeneration ||
            InterlockedCompareExchange(&Wifi->Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
            FirmwareGeneration != owner.Generation || !Wifi->ConnectBssidValid ||
            !RtlEqualMemory(owner.Bssid, Wifi->ConnectBssid, 6);
    if (FirmwareEvent != 1 || hostOwner || Wifi->Auth.HostCipherGeneration) return TRUE;
    return (FirmwareEvent &&
            (FirmwareGeneration ? FirmwareGeneration != Wifi->Auth.SaeEventGeneration
                                : Wifi->Auth.SaeFirmwareGeneration != 0 ||
                                      (Wifi->Auth.SaeEventGeneration != 0 &&
                                       Wifi->ConnectTask.Active && !Wifi->ConnectDeparting)));
}

NTSTATUS Ap6256StationStartNext(_In_ PAP6256_WIFI Wifi)
{
    NTSTATUS status = STATUS_NETWORK_UNREACHABLE;
    while (Wifi->ConnectTask.Active && Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount) {
        AP6256_CONNECT_PARAMS* p = &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex];
        KIRQL irql;
        if (Wifi->Stopping || !Wifi->HardwareAvailable)
            return STATUS_CANCELLED;
        if (Ap6256InterruptTimeMs() >= Wifi->ConnectTask.DeadlineMs)
            return STATUS_IO_TIMEOUT;
        status = Ap6256FtEnd(Wifi->Ctx, &Wifi->Auth.Ft, FALSE);
        if (!NT_SUCCESS(status) || Wifi->Auth.Ft.Phase == Ap6256FtAbortRequired)
            return NT_SUCCESS(status) ? STATUS_DEVICE_BUSY : status;
        Ap6256StationSaeCancel(Wifi);
        (VOID) Ap6256OweEnd(Wifi->Ctx, FALSE);
        if (Wifi->Auth.SaeNeedsAbort)
            return STATUS_DEVICE_BUSY;
        if (Wifi->Ctx->FirmwareOweGeneration)
            return STATUS_DEVICE_BUSY;
        status = Ap6256MboPrepareJoin(Wifi, p);
        if (status == STATUS_NETWORK_UNREACHABLE) {
            ++Wifi->ConnectCandidateIndex;
            continue;
        }
        if (!NT_SUCCESS(status)) return status;
        KeAcquireSpinLock(&Wifi->CommandLock, &irql);
        InterlockedIncrement(&Wifi->ConnectGeneration);
        Wifi->Auth.SaeEventGeneration = 0;
        Wifi->Auth.HostCipherGeneration = 0;
        Wifi->ConnectBssidValid = p->BssidValid;
        RtlCopyMemory(Wifi->ConnectBssid, p->Bssid, 6);
        Wifi->ConnectChannel = p->Channel;
        Wifi->ConnectionActive = FALSE;
        KeReleaseSpinLock(&Wifi->CommandLock, irql);
        if (p->Security == Ap6256SecuritySaeHost) {
            status = Ap6256StationSaeArm(Wifi, p);
            if (!NT_SUCCESS(status))
                return status;
        }
        TraceDiag("station join: candidate %u/%u, channel %u\n", Wifi->ConnectCandidateIndex + 1,
                  Wifi->ConnectCandidateCount, p->Channel);
        if (p->FastTransition) {
            AP6256_CONNECT_FT_SETUP setup = {0};
            setup.State = &Wifi->Auth.Ft;
            setup.PortId = Wifi->ConnectTask.Header.PortId;
            setup.TransactionId = Wifi->ConnectTask.Header.TransactionId;
            setup.Reassociation = p->FtReassociation;
            RtlCopyMemory(setup.Mde, p->FtMde, sizeof(setup.Mde));
            RtlCopyMemory(setup.Fte, p->FtFte, p->FtFteLength);
            setup.FteLength = p->FtFteLength;
            RtlCopyMemory(setup.PmkR0Name, p->FtPmkR0Name, 16);
            status = Ap6256WifiConnectFt(Wifi->Ctx, p, &setup);
        } else
            status = Ap6256WifiConnect(Wifi->Ctx, p);
        if (NT_SUCCESS(status) && p->HostCipher) {
            AP6256_HC_STORE_SESSION session;
            AP6256_HC_PROFILE_CONTROL profile;
            status = Ap6256HostCipherReadProfile(Wifi->Ctx, 0, &session, &profile);
            if (NT_SUCCESS(status) && (profile.Akm != p->HostCipherAkm || profile.Mfp != (UINT32)p->Mfp ||
                !RtlEqualMemory(session.Bssid, p->Bssid, 6) ||
                !RtlEqualMemory(session.Station, Wifi->Ctx->MacAddress, 6))) status = STATUS_DEVICE_PROTOCOL_ERROR;
            if (NT_SUCCESS(status)) Wifi->Auth.HostCipherGeneration = session.Generation;
            else {
                (VOID)Ap6256HostCipherEnd(Wifi->Ctx, 0, FALSE);
                (VOID)Ap6256WifiDisconnect(Wifi->Ctx);
            }
        }
        if (NT_SUCCESS(status))
            return status;
        (VOID) Ap6256IndicateAssociation(Wifi, &Wifi->ConnectTask.Header,
                                         Wifi->ConnectTask.RequestId, FALSE);
        if (Ap6256StationSaeFallback(Wifi))
            continue;
        ++Wifi->ConnectCandidateIndex;
    }
    Ap6256StationSaeCancel(Wifi);
    (VOID) Ap6256OweEnd(Wifi->Ctx, FALSE);
    return status;
}

static BOOLEAN Ap6256HostCipherAssociationProfile(PAP6256_WIFI Wifi, const UCHAR Bssid[6])
{
    AP6256_HC_STORE_SESSION session;
    AP6256_HC_PROFILE_CONTROL profile;
    const AP6256_CONNECT_PARAMS* p;
    WDI_AUTH_ALGORITHM algorithm;
    if (!Wifi->ConnectTask.Active || Wifi->ConnectCandidateIndex >= Wifi->ConnectCandidateCount ||
        !Wifi->Auth.HostCipherGeneration) return FALSE;
    p = &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex];
    if (!p->HostCipher || p->HostFips || p->FastTransition || !p->BssidValid ||
        !RtlEqualMemory(p->Bssid, Bssid, 6) ||
        !NT_SUCCESS(Ap6256HostCipherReadProfile(Wifi->Ctx, 0, &session, &profile)) ||
        session.Generation != Wifi->Auth.HostCipherGeneration ||
        !RtlEqualMemory(session.Bssid, Bssid, 6) ||
        !RtlEqualMemory(session.Station, Wifi->Ctx->MacAddress, 6) ||
        profile.Akm != p->HostCipherAkm || profile.Mfp != (UINT32)p->Mfp) return FALSE;
    algorithm = profile.Akm == 1 ? WDI_AUTH_ALGO_RSNA : profile.Akm == 2 ? WDI_AUTH_ALGO_RSNA_PSK :
        profile.Akm == 5 ? WDI_AUTH_ALGO_WPA3_ENT : profile.Akm == 8 ? WDI_AUTH_ALGO_WPA3_SAE :
        profile.Akm == 12 ? WDI_AUTH_ALGO_WPA3_ENT_192 : profile.Akm == 18 ? WDI_AUTH_ALGO_OWE : WDI_AUTH_ALGO_UNKNOWN;
    return Wifi->AuthAlgorithm == algorithm && Wifi->UnicastCipher == WDI_CIPHER_ALGO_GCMP_256 &&
        Wifi->MulticastCipher == WDI_CIPHER_ALGO_GCMP_256;
}

static BOOLEAN Ap6256HostCipherAssociationRsn(const AP6256_CONNECT_PARAMS* Params,
    const AP6256_ASSOC_FRAMES* Frames, const UCHAR Bssid[6])
{
    AP6256_HC_RSN request, ap, response;
    const UCHAR* p;
    ULONG fixed = Frames->ReAssociation ? 10u : 4u, n, size;
    BOOLEAN responseRsn = FALSE;
    if (!Frames->AssocRequest || Frames->AssocRequestLength < fixed || Frames->AssocRequestLength > AP6256_HC_MAX_FRAME ||
        !Frames->Beacon || Frames->BeaconLength < 12 || !RtlEqualMemory(Frames->BeaconBssid, Bssid, 6) ||
        Frames->BeaconLength > AP6256_HC_MAX_FRAME ||
        !Frames->AssocResponse || Frames->AssocResponseLength < 6 ||
        Frames->AssocResponseLength > AP6256_HC_MAX_FRAME ||
        Frames->AssocResponse[2] || Frames->AssocResponse[3] ||
        (Frames->PeerStatusValid && Frames->PeerStatusCode) ||
        !Ap6256HostCipherRsnRead(Frames->AssocRequest + fixed, Frames->AssocRequestLength - fixed, &request) ||
        !Ap6256HostCipherRsnMatch(&request, Params->HostCipherAkm, (UINT32)Params->Mfp, 1) ||
        !Ap6256HostCipherRsnRead(Frames->Beacon + 12, Frames->BeaconLength - 12, &ap) ||
        !Ap6256HostCipherRsnMatch(&ap, Params->HostCipherAkm, (UINT32)Params->Mfp, 0) ||
        (Params->PmkidValid ? !Ap6256HostCipherRsnPmkid(&request, Params->Pmkid, 1) : request.PmkidCount != 0))
        return FALSE;
    p = Frames->AssocResponse + 6; n = Frames->AssocResponseLength - 6;

    while (n) {
        if (n < 2 || (size = (ULONG)p[1] + 2) > n) return FALSE;
        if (p[0] == 48) responseRsn = TRUE;
        p += size; n -= size;
    }
    return !responseRsn || (Ap6256HostCipherRsnRead(Frames->AssocResponse + 6,
        Frames->AssocResponseLength - 6, &response) &&
        Ap6256HostCipherRsnMatch(&response, Params->HostCipherAkm, (UINT32)Params->Mfp, 0));
}

static NTSTATUS Ap6256StationAssociationDisconnect(PAP6256_WIFI Wifi, BOOLEAN HostCipher)
{
    if (HostCipher) {
        (VOID)Ap6256HostCipherEnd(Wifi->Ctx, 0, FALSE);
        Wifi->Auth.HostCipherGeneration = 0;
    }
    return Ap6256WifiDisconnect(Wifi->Ctx);
}

_Use_decl_annotations_
BOOLEAN
Ap6256IndicateAssociation(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header,
                          _In_opt_ PVOID RequestId, _In_ BOOLEAN Success)
{
    WDI_INDICATION_ASSOCIATION_RESULT_LIST list;
    WDI_ASSOCIATION_RESULT_CONTAINER result;
    WDI_PHY_TYPE phyType;
    UCHAR bssid[6];
    UINT32 channel = 0;
    WDI_CHANNEL_NUMBER requestedChannel;
    WDI_AUTH_ALGORITHM authAlgorithm;
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    NDIS_STATUS ndisStatus;
    KIRQL oldIrql;
    AP6256_ASSOC_FRAMES frames;
    BOOLEAN owePeerFailure = FALSE;
    BOOLEAN indicationDelivered = FALSE;
    UINT32 hostCipherGeneration = Wifi->Auth.HostCipherGeneration;
    BOOLEAN hostCipher = Wifi->UnicastCipher == WDI_CIPHER_ALGO_GCMP_256 ||
                         Wifi->MulticastCipher == WDI_CIPHER_ALGO_GCMP_256;

    RtlZeroMemory(&list, sizeof(list));
    RtlZeroMemory(&result, sizeof(result));
    RtlZeroMemory(bssid, sizeof(bssid));
    RtlZeroMemory(&frames, sizeof(frames));

    if (Success && !NT_SUCCESS(Ap6256WifiGetBssid(Wifi->Ctx, bssid))) {
        Success = FALSE;
    }
    if (Success && Wifi->ConnectTask.Active &&
        Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount &&
        Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].BssidValid &&
        !RtlEqualMemory(bssid, Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].Bssid, 6)) {
        (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
        Success = FALSE;
    }

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    requestedChannel = Wifi->ConnectChannel;
    authAlgorithm = Wifi->AuthAlgorithm;
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);

    if (!Success && authAlgorithm == WDI_AUTH_ALGO_OWE && Wifi->Ctx->FirmwareOweGeneration &&
        Wifi->ConnectTask.Active && Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount) {
        const AP6256_CONNECT_PARAMS* candidate =
            &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex];
        Ap6256WifiGetAssocFrames(Wifi->Ctx, &frames);
        owePeerFailure = frames.PeerStatusValid && frames.PeerStatusCode != 0 &&
                         RtlEqualMemory(candidate->Bssid, Wifi->Ctx->FirmwareOwePeer, 6) &&
                         Ap6256OweRequestValid(candidate, &frames);
        if (!owePeerFailure)
            Ap6256WifiFreeAssocFrames(&frames);
    }
    if (Success && requestedChannel == 0 &&
        !NT_SUCCESS(Ap6256WifiGetChannel(Wifi->Ctx, &channel))) {
        TraceWarn(TRACE_NETADAPTER, "no channel for the association result: the connect request "
                                    "named none and the firmware query failed\n");
    }

    if (Success) {
        PCSTR rejection = Ap6256ConnectBssRejection(
            Wifi, bssid, requestedChannel != 0 ? requestedChannel : channel);

        if (rejection != NULL) {
            TraceWarn(TRACE_NETADAPTER,
                      "association REJECTED: the firmware joined "
                      "%02X:%02X:%02X:%02X:%02X:%02X and %s\n",
                      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], rejection);
            (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
            Success = FALSE;
        }
    }
    if (Success) {
        Ap6256WifiGetAssocFrames(Wifi->Ctx, &frames);
        if (hostCipher && (!Ap6256HostCipherAssociationProfile(Wifi, bssid) ||
            !Ap6256HostCipherAssociationRsn(&Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex], &frames, bssid))) {
            TraceDiag("host cipher: association rejected without current public profile and actual GCMP/GMAC RSNEs\n");
            (VOID)Ap6256StationAssociationDisconnect(Wifi, TRUE);
            Success = FALSE;
        }
        if (Success && authAlgorithm == WDI_AUTH_ALGO_WPA3_SAE) {
            const AP6256_CONNECT_PARAMS* candidate =
                Wifi->ConnectTask.Active &&
                        Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount
                    ? &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex]
                    : NULL;
            BOOLEAN cached = candidate != NULL && candidate->PmkidValid &&
                             candidate->Security == Ap6256SecuritySaeHost &&
                             Wifi->Auth.SaeGeneration == Wifi->ConnectGeneration &&
                             Ap6256InterruptTimeMs() < Wifi->Auth.SaeCachedDeadlineMs &&
                             RtlEqualMemory(candidate->Bssid, bssid, 6);
            BOOLEAN exchanged = Wifi->Auth.Sae.State == Ap6256SaeAccepted &&
                                Wifi->Auth.SaeFirmwareReleased &&
                                Wifi->Auth.Sae.Generation == Wifi->ConnectGeneration &&
                                RtlEqualMemory(Wifi->Auth.Sae.Peer, bssid, 6);
            if ((!cached && !exchanged) || frames.AssocRequest == NULL ||
                (!hostCipher && !Ap6256SaeAssociationRsn(frames.AssocRequest, frames.AssocRequestLength,
                                         frames.ReAssociation)) ||
                (cached && !hostCipher &&
                 !Ap6256SaeAssociationPmkid(frames.AssocRequest, frames.AssocRequestLength,
                                            frames.ReAssociation, candidate->Pmkid)) ||
                !Ap6256SaeAssociationH2e(frames.AssocRequest, frames.AssocRequestLength,
                                         frames.ReAssociation,
                                         cached ? candidate->SaeCachedH2e : Wifi->Auth.Sae.H2e)) {
                TraceDiag("SAE: association rejected without verified exchange/cache and matching "
                          "SAE/CCMP/PMF/H2E IEs\n");
                (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
                Success = FALSE;
            }
        }
        if (Success && authAlgorithm == WDI_AUTH_ALGO_OWE) {
            const AP6256_CONNECT_PARAMS* candidate =
                Wifi->ConnectTask.Active &&
                        Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount
                    ? &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex]
                    : NULL;
            if (candidate == NULL || !Wifi->Ctx->FirmwareOweGeneration ||
                !RtlEqualMemory(Wifi->Ctx->FirmwareOwePeer, bssid, 6) ||
                !Ap6256OweAssociationValid(candidate, &frames)) {
                TraceDiag("OWE: association rejected without matching RSN/DH/cache/PMF evidence\n");
                (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
                Success = FALSE;
            }
        }
        if (Success && hostCipher) {
            const AP6256_CONNECT_PARAMS* candidate = &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex];
            if (candidate->Mfp != Ap6256MfpNone)
                result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_BIP_GMAC_256;
        } else if (Success && authAlgorithm != WDI_AUTH_ALGO_80211_OPEN) {
            BOOLEAN pmf = FALSE;
            NTSTATUS pmfStatus = Ap6256WifiAssocPmf(&frames, bssid, &pmf);
            if (!NT_SUCCESS(pmfStatus) ||
                ((authAlgorithm == WDI_AUTH_ALGO_WPA3_SAE || authAlgorithm == WDI_AUTH_ALGO_OWE) &&
                 !pmf)) {
                TraceWarn(TRACE_NETADAPTER,
                          "association rejected: PMF negotiation evidence unavailable or "
                          "unsupported (0x%08X)\n",
                          pmfStatus);
                (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
                Success = FALSE;
            } else if (pmf) {
                result.AssociationResultParameters.MulticastMgmtCipherAlgorithm =
                    WDI_CIPHER_ALGO_BIP;
            }
        }

        if (Success && authAlgorithm == WDI_AUTH_ALGO_WPA3_SAE &&
            !NT_SUCCESS(Ap6256StationSaeComplete(Wifi))) {
            (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
            result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_NONE;
            Success = FALSE;
        }
    }
    if (Wifi->ConnectTask.Active && Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount &&
        Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].FastTransition) {
        if (Success && (!Ap6256FtAssociationValid(&Wifi->Auth.Ft, &frames) ||
                        !RtlEqualMemory(bssid, Wifi->Auth.Ft.Owner.Bssid, 6)))
            Success = FALSE;
        if (!NT_SUCCESS(Ap6256FtEnd(Wifi->Ctx, &Wifi->Auth.Ft, Success)))
            Success = FALSE;
        if (!Success) {
            Ap6256FtConnectionLost(&Wifi->Auth.Ft);
            (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
        }
    }
    if (authAlgorithm == WDI_AUTH_ALGO_OWE && !NT_SUCCESS(Ap6256OweEnd(Wifi->Ctx, Success))) {
        Success = FALSE;
        result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_NONE;
        (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
    }
    if (hostCipher && (!Success || !Ap6256HostCipherAssociationProfile(Wifi, bssid))) {
        (VOID)Ap6256StationAssociationDisconnect(Wifi, TRUE);
        Success = FALSE;
        result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_NONE;
    }
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (!Success && Wifi->ConnectBssidValid) {
        RtlCopyMemory(bssid, Wifi->ConnectBssid, sizeof(bssid));
    }
    RtlCopyMemory(result.BSSID.Address, bssid, sizeof(bssid));
    result.AssociationResultParameters.AssociationStatus =
        Success
            ? WDI_ASSOC_STATUS_SUCCESS
            : (owePeerFailure ? WDI_ASSOC_STATUS_ASSOC_FAILED_BY_PEER : WDI_ASSOC_STATUS_FAILURE);
    result.AssociationResultParameters.AuthAlgorithm = Wifi->AuthAlgorithm;
    result.AssociationResultParameters.UnicastCipherAlgorithm = Wifi->UnicastCipher;
    result.AssociationResultParameters.MulticastDataCipherAlgorithm = Wifi->MulticastCipher;
    Wifi->MulticastMgmtCipher = result.AssociationResultParameters.MulticastMgmtCipherAlgorithm;
    result.AssociationResultParameters.PortAuthorized =
        Success && Wifi->AuthAlgorithm == WDI_AUTH_ALGO_80211_OPEN;
    if (Success && channel != 0) {
        Wifi->ConnectChannel = (WDI_CHANNEL_NUMBER)channel;
    }
    result.AssociationResultParameters.BandID =
        Wifi->ConnectChannel == 0
            ? WDI_BAND_ID_UNKNOWN
            : (Wifi->ConnectChannel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000);
    if (Success)
        RtlCopyMemory(Wifi->ConnectBssid, bssid, sizeof(bssid));
    Wifi->ConnectBssidValid = Success;
    Wifi->ConnectionActive = Success;
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    Ap6256MboAssociation(Wifi, Success, bssid, &frames,
        result.AssociationResultParameters.MulticastMgmtCipherAlgorithm == WDI_CIPHER_ALGO_BIP ||
        result.AssociationResultParameters.MulticastMgmtCipherAlgorithm == WDI_CIPHER_ALGO_BIP_GMAC_256);

    Ap6256ModelSetStationBssid(Wifi, Success ? bssid : NULL);

    if (Success && result.AssociationResultParameters.PortAuthorized) {
        (VOID) Ap6256WifiSetPowerSave(Wifi->Ctx, TRUE);
    }

    if (Success) {
        Ap6256WifiTraceAssocList(Wifi->Ctx);
    }

    if (Success) {
        if (!Ap6256ModelCreateStationPeer(Wifi, bssid)) {
            TraceError(TRACE_NETADAPTER, "association downgraded to failure: the datapath peer "
                                         "could not be created\n");
            Success = FALSE;
            KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
            Wifi->ConnectionActive = FALSE;
            Wifi->ConnectBssidValid = FALSE;
            KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
            result.AssociationResultParameters.AssociationStatus = WDI_ASSOC_STATUS_FAILURE;
            result.AssociationResultParameters.PortAuthorized = FALSE;
            result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_NONE;
            Wifi->MulticastMgmtCipher = WDI_CIPHER_ALGO_NONE;
            Ap6256ModelSetStationBssid(Wifi, (const UCHAR*)NULL);
            Ap6256FtConnectionLost(&Wifi->Auth.Ft);
            (VOID) Ap6256StationAssociationDisconnect(Wifi, hostCipher);
        }
    } else {
        Ap6256ModelDeleteStationPeer(Wifi);
    }
    if (Success && hostCipher && (!Ap6256HostCipherAssociationProfile(Wifi, bssid) ||
        !NT_SUCCESS(Ap6256HostCipherConfirmAssociation(Wifi->Ctx, 0, Wifi->Auth.HostCipherGeneration,
            Wifi->Ctx->MacAddress, bssid,
            Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].HostCipherAkm,
            (UINT32)Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].Mfp)))) {
        Success = FALSE;
        KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
        Wifi->ConnectionActive = Wifi->ConnectBssidValid = FALSE;
        Wifi->MulticastMgmtCipher = WDI_CIPHER_ALGO_NONE;
        KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
        result.AssociationResultParameters.AssociationStatus = WDI_ASSOC_STATUS_FAILURE;
        result.AssociationResultParameters.PortAuthorized = FALSE;
        result.AssociationResultParameters.MulticastMgmtCipherAlgorithm = WDI_CIPHER_ALGO_NONE;
        Ap6256ModelDeleteStationPeer(Wifi);
        Ap6256ModelSetStationBssid(Wifi, (const UCHAR*)NULL);
        (VOID)Ap6256StationAssociationDisconnect(Wifi, TRUE);
    }

    TraceInfo(TRACE_NETADAPTER,
              "association result: %s %02X:%02X:%02X:%02X:%02X:%02X "
              "channel %u auth %u unicast %u multicast %u port %s\n",
              Success ? "ASSOCIATED" : "FAILED", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
              bssid[5], (ULONG)Wifi->ConnectChannel,
              (ULONG)result.AssociationResultParameters.AuthAlgorithm,
              (ULONG)result.AssociationResultParameters.UnicastCipherAlgorithm,
              (ULONG)result.AssociationResultParameters.MulticastDataCipherAlgorithm,
              result.AssociationResultParameters.PortAuthorized
                  ? "authorized"
                  : "unauthorized (host supplicant owes the keys)");

    if (Success || owePeerFailure) {
        Ap6256ModelUpdateReceiveContext(Wifi);

        result.AssociationResultParameters.ReAssociation = frames.ReAssociation;
        result.AssociationResultParameters.StatusCode = frames.PeerStatusCode;

        result.AssociationResultParameters.WMMQoSEnabled = frames.WmmNegotiated;

        TraceDiag("association result: %s, peer status code %u, management "
                  "cipher %u, WMM %s\n",
                  frames.ReAssociation ? "REASSOCIATION" : "association",
                  (ULONG)frames.PeerStatusCode,
                  (ULONG)result.AssociationResultParameters.MulticastMgmtCipherAlgorithm,
                  frames.WmmNegotiated ? "negotiated" : "not negotiated");

        if (frames.AssocRequest != NULL) {
            result.Optional.AssociationRequestFrame_IsPresent = TRUE;
            result.AssociationRequestFrame.ElementCount = frames.AssocRequestLength;
            result.AssociationRequestFrame.pElements = frames.AssocRequest;
            result.AssociationRequestFrame.MemoryInternallyAllocated = FALSE;
        }
        if (frames.AssocResponse != NULL) {
            result.Optional.AssociationResponseFrame_IsPresent = TRUE;
            result.AssociationResponseFrame.ElementCount = frames.AssocResponseLength;
            result.AssociationResponseFrame.pElements = frames.AssocResponse;
            result.AssociationResponseFrame.MemoryInternallyAllocated = FALSE;
        }
        if (frames.Beacon != NULL) {
            result.Optional.BeaconProbeResponse_IsPresent = TRUE;
            result.BeaconProbeResponse.ElementCount = frames.BeaconLength;
            result.BeaconProbeResponse.pElements = frames.Beacon;
            result.BeaconProbeResponse.MemoryInternallyAllocated = FALSE;
        }
    }

    phyType = result.AssociationResultParameters.BandID == WDI_BAND_ID_5000
                  ? WDI_PHY_TYPE_VHT
                  : (result.AssociationResultParameters.BandID == WDI_BAND_ID_2400
                         ? WDI_PHY_TYPE_HT
                         : WDI_PHY_TYPE_UNKNOWN);
    result.ActivePhyTypeList.ElementCount = 1;
    result.ActivePhyTypeList.pElements = &phyType;
    result.ActivePhyTypeList.MemoryInternallyAllocated = FALSE;
    list.AssociationResults.ElementCount = 1;
    list.AssociationResults.pElements = &result;
    list.AssociationResults.MemoryInternallyAllocated = FALSE;

    ndisStatus = GenerateWdiIndicationAssociationResult(&list, 0, &Wifi->TlvContext,
                                                        &generatedLength, &generated);
    if (ndisStatus == NDIS_STATUS_SUCCESS && generated != NULL && generatedLength != 0) {
        NTSTATUS sendStatus = Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_ASSOCIATION_RESULT,
                                                            Header, WDI_TRANSACTION_ID_UNSOLICIT,
                                                            RequestId, generated, generatedLength);
        if (!NT_SUCCESS(sendStatus)) {
            TraceError(TRACE_NETADAPTER,
                       "association result indication REFUSED 0x%08X "
                       "(%u bytes)\n",
                       sendStatus, generatedLength);
        } else indicationDelivered = TRUE;
    } else {
        TraceWarn(TRACE_NETADAPTER, "association indication generation failed 0x%08X\n",
                  ndisStatus);
    }
    FreeGenerated(generated);
    Ap6256WifiFreeAssocFrames(&frames);
    if (Success && hostCipher && !indicationDelivered) {
        BOOLEAN matched = FALSE;

        (VOID)Ap6256HostCipherEndGeneration(Wifi->Ctx, 0, hostCipherGeneration, &matched);
        Success = FALSE;
        if (matched) {
            BOOLEAN cleanup = FALSE;
            KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
            if (Wifi->Auth.HostCipherGeneration == hostCipherGeneration) {
                Wifi->ConnectionActive = Wifi->ConnectBssidValid = FALSE;
                Wifi->MulticastMgmtCipher = WDI_CIPHER_ALGO_NONE;
                Wifi->Auth.HostCipherGeneration = 0;
                cleanup = TRUE;
            }
            KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
            if (cleanup) {
                Ap6256ModelDeleteStationPeer(Wifi);
                Ap6256ModelSetStationBssid(Wifi, (const UCHAR*)NULL);
                (VOID)Ap6256WifiDisconnect(Wifi->Ctx);
            }
        }
    }
    return Success;
}

VOID Ap6256DrainCommandQueue(PAP6256_WIFI wifi)
{
    if (InterlockedCompareExchange(&wifi->CommandDraining, 1, 0) != 0)
        return;
    for (;;) {
        AP6256_REQUEST request = NULL;
        LONG generation = 0, saeLost = 0;
        AP6256_FT_EVENT* ftEvent = NULL;
        AP6256_FT_OWNER ftOwner = {0};
        AP6256_SAE_EVENT saeEvent = {0};
        PVOID modelEvent = NULL;
        BOOLEAN ftLost = FALSE, modelLost = FALSE;
        enum { Command, Ft, Sae, Model } kind;
        KIRQL oldIrql;

        KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
        if (wifi->Auth.FtEventsLost || wifi->Auth.FtTail != wifi->Auth.FtHead) {
            kind = Ft;
            ftLost = wifi->Auth.FtEventsLost;
            if (ftLost) {
                ftOwner = wifi->Auth.FtLostOwner;
                wifi->Auth.FtEventsLost = FALSE;
            } else {
                ftEvent = wifi->Auth.FtEvents[wifi->Auth.FtTail++ % RTL_NUMBER_OF(wifi->Auth.FtEvents)];
            }
        } else if (wifi->Auth.SaeLostGeneration || wifi->Auth.SaeTail != wifi->Auth.SaeHead) {
            kind = Sae;
            saeLost = wifi->Auth.SaeLostGeneration;
            if (saeLost) wifi->Auth.SaeLostGeneration = 0;
            else saeEvent = wifi->Auth.SaeQueue[wifi->Auth.SaeTail++ % AP6256_SAE_QUEUE_DEPTH];
        } else if (Ap6256ModelTakeCommandEvent(wifi, &modelEvent, &modelLost)) {
            kind = Model;
        } else if (wifi->CommandTail != wifi->CommandHead) {
            kind = Command;
            ULONG slot = wifi->CommandTail++ & (AP6256_CMDQ_DEPTH - 1);
            request = wifi->CommandPending[slot];
            generation = wifi->CommandSaeGeneration[slot];
        } else {
            InterlockedExchange(&wifi->CommandDraining, 0);
            KeReleaseSpinLock(&wifi->CommandLock, oldIrql);
            break;
        }
        KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

        if (kind == Ft) {
            Ap6256StationFtEvent(wifi, ftEvent, ftLost ? &ftOwner : NULL);
            if (ftEvent) ExFreePoolWithTag(ftEvent, AP6256_POOL_TAG);
        } else if (kind == Sae) {
            if (saeLost) {
                Ap6256LockAcquire(&wifi->ConnectLock);
                if (Ap6256StationSaeLive(wifi, saeLost))
                    Ap6256StationSaeFailed(wifi, WDI_SAE_STATUS_FAILURE);
                Ap6256LockRelease(&wifi->ConnectLock);
            } else Ap6256StationSaeEvent(wifi, &saeEvent);
        } else if (kind == Model) {
            Ap6256ModelProcessCommandEvent(wifi, modelEvent, modelLost);
        } else if (wifi->Stopping) {
            Ap6256CompleteRequest(wifi, request, STATUS_CANCELLED);
        } else {
            Ap6256ProcessCommand(wifi, request, generation);
        }
    }
}

VOID Ap6256StationAuthStop(PAP6256_WIFI Wifi)
{
    if (AP6256_TIMER_OK(Wifi->Auth.SaeTimer))
        AP6256_TIMER_STOP(Wifi->Auth.SaeTimer, TRUE);
    Ap6256LockAcquire(&Wifi->ConnectLock);
    Ap6256ModelCancelAuthentication(Wifi);
    Ap6256FtConnectionLost(&Wifi->Auth.Ft);
    Ap6256LockRelease(&Wifi->ConnectLock);
}

VOID Ap6256StationAuthFreeEvents(PAP6256_WIFI Wifi)
{
    AP6256_FT_EVENT* pending[2];
    ULONG count = 0, index;
    KIRQL irql;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    while (Wifi->Auth.FtTail != Wifi->Auth.FtHead) {
        pending[count++] = Wifi->Auth.FtEvents[
            Wifi->Auth.FtTail++ % RTL_NUMBER_OF(Wifi->Auth.FtEvents)];
    }
    Wifi->Auth.FtEventsLost = FALSE;
    Wifi->Auth.SaeTail = Wifi->Auth.SaeHead;
    Wifi->Auth.SaeLostGeneration = 0;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    for (index = 0; index < count; ++index)
        ExFreePoolWithTag(pending[index], AP6256_POOL_TAG);
}
