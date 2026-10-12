/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

static NTSTATUS Ap6256FtCopyCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* Entry,
    BOOLEAN Roam, AP6256_CONNECT_PARAMS* Parameters)
{
    const WDI_BYTE_BLOB* mde;
    AP6256_FT_STATE validation = {0};
    BOOLEAN initial = (BOOLEAN)Entry->Optional.FTInitialAssocParameters_IsPresent;
    BOOLEAN reassoc = (BOOLEAN)Entry->Optional.FTReAssocParameters_IsPresent;
    NTSTATUS status;
    if (!initial && !reassoc) return STATUS_SUCCESS;
    if (initial == reassoc || Roam != reassoc ||
        Parameters->Security != Ap6256SecurityWpa2Enterprise)
        return STATUS_INVALID_PARAMETER;
    mde = reassoc ? &Entry->FTReAssocParameters.MDE : &Entry->FTInitialAssocParameters.MDE;
    if (mde->pElements == NULL || mde->ElementCount != AP6256_FT_MDE_LENGTH)
        return STATUS_INVALID_PARAMETER;
    if (reassoc) {
        validation.MobilityDomainValid = TRUE;
        RtlCopyMemory(validation.MobilityDomain, mde->pElements + 2, 2);
    }
    status = Ap6256FtValidateBegin(&validation, Entry->BSSID.Address, reassoc,
        mde->pElements, mde->ElementCount,
        reassoc ? Entry->FTReAssocParameters.FTE.pElements : NULL,
        reassoc ? Entry->FTReAssocParameters.FTE.ElementCount : 0,
        reassoc ? Entry->FTReAssocParameters.PMKR0Name.pmkname.Name : NULL,
        reassoc ? 16u : 0u);
    if (!NT_SUCCESS(status)) return status;
    Parameters->FastTransition = TRUE;
    Parameters->FtReassociation = reassoc;
    RtlCopyMemory(Parameters->FtMde, mde->pElements, AP6256_FT_MDE_LENGTH);
    if (reassoc) {
        Parameters->FtFteLength = Entry->FTReAssocParameters.FTE.ElementCount;
        RtlCopyMemory(Parameters->FtFte, Entry->FTReAssocParameters.FTE.pElements,
            Parameters->FtFteLength);
        RtlCopyMemory(Parameters->FtPmkR0Name, Entry->FTReAssocParameters.PMKR0Name.pmkname.Name, 16);
    }
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256FtValidateCandidates(PAP6256_WIFI Wifi,
    const AP6256_CONNECT_PARAMS* Candidates, ULONG Count, BOOLEAN Roam)
{
    ULONG index;
    if (Wifi->Auth.Ft.Phase == Ap6256FtAbortRequired) return STATUS_DEVICE_BUSY;
    if (Roam && Wifi->Auth.Ft.MobilityDomainValid && Count == 0)
        return STATUS_INVALID_PARAMETER;
    for (index = 0; index < Count; ++index) {
        const AP6256_CONNECT_PARAMS* p = Candidates + index;
        NTSTATUS status;
        if (!p->FastTransition) {
            if (Roam && Wifi->Auth.Ft.MobilityDomainValid) return STATUS_INVALID_PARAMETER;
            continue;
        }
        if (!Ap6256HostFbtAvailable(Wifi)) return STATUS_NOT_SUPPORTED;
        status = Ap6256FtValidateBegin(&Wifi->Auth.Ft, p->Bssid, p->FtReassociation,
            p->FtMde, sizeof(p->FtMde), p->FtReassociation ? p->FtFte : NULL,
            p->FtFteLength, p->FtReassociation ? p->FtPmkR0Name : NULL,
            p->FtReassociation ? 16u : 0u);
        if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256FtTaskLive(PAP6256_WIFI Wifi)
{
    KIRQL irql;
    BOOLEAN live;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    live = Wifi->ConnectTask.Active && Wifi->ConnectTaskIsRoam &&
        Wifi->ConnectTask.Header.PortId == Wifi->Auth.Ft.Owner.PortId &&
        Wifi->ConnectTask.Header.TransactionId == Wifi->Auth.Ft.Owner.TransactionId &&
        Wifi->ConnectTask.DeadlineMs != 0 &&
        Ap6256InterruptTimeMs() < Wifi->ConnectTask.DeadlineMs;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    return live && !Wifi->Stopping && Wifi->HardwareAvailable;
}

static VOID Ap6256FtFailTask(PAP6256_WIFI Wifi, const AP6256_FT_OWNER* Owner,
    NTSTATUS Status)
{
    WDI_MESSAGE_HEADER header;
    PVOID requestId = NULL;
    (VOID)Ap6256FtEnd(Wifi->Ctx, &Wifi->Auth.Ft, FALSE);
    if (!Ap6256ClaimMatchingTask(Wifi, &Wifi->ConnectTask,
        Owner->TransactionId, Owner->PortId, &header, &requestId)) return;
    Wifi->ConnectCandidateCount = 0;
    Wifi->ConnectDeparting = FALSE;
    InterlockedIncrement(&Wifi->ConnectGeneration);
    Ap6256FtConnectionLost(&Wifi->Auth.Ft);
    (VOID)Ap6256WifiDisconnect(Wifi->Ctx);
    (VOID)Ap6256IndicateAssociation(Wifi, &header, requestId, FALSE);
    (VOID)Ap6256SendIndicationRq(Wifi, WDI_INDICATION_ROAM_COMPLETE,
        &header, header.TransactionId, requestId,
        NT_SUCCESS(Status) ? STATUS_UNSUCCESSFUL : Status, NULL, 0);
}

static NTSTATUS Ap6256IndicateFtAuthentication(PAP6256_WIFI Wifi,
    const AP6256_FT_EVENT* Event)
{
    WDI_INDICATION_FT_ASSOC_PARAMS_NEEDED_PARAMETERS parameters;
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    NTSTATUS status;
    status = Ap6256FtAcceptAuthentication(&Wifi->Auth.Ft, &Event->Owner,
        Event->Bodies, Event->RequestLength,
        Event->Bodies + Event->RequestLength, Event->ResponseLength);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlCopyMemory(parameters.BssId.Address, Event->Owner.Bssid, 6);
    parameters.AuthRequest.pElements = (PUCHAR)Event->Bodies;
    parameters.AuthRequest.ElementCount = Event->RequestLength;
    parameters.AuthResponse.pElements = (PUCHAR)Event->Bodies + Event->RequestLength;
    parameters.AuthResponse.ElementCount = Event->ResponseLength;
    status = Ap6256NdisToNtStatus(GenerateWdiIndicationFtAssocParamsNeededFromIhv(
        &parameters, 0, &Wifi->TlvContext, &generatedLength, &generated));
    if (NT_SUCCESS(status)) status = Ap6256SendIndicationRq(Wifi,
        WDI_INDICATION_FT_ASSOC_PARAMS_NEEDED, &Wifi->ConnectTask.Header,
        Wifi->ConnectTask.Header.TransactionId, Wifi->ConnectTask.RequestId,
        STATUS_SUCCESS, generated, generatedLength);
    FreeGenerated(generated);
    if (!NT_SUCCESS(status)) Wifi->Auth.Ft.HostReplyOutstanding = FALSE;
    return status;
}

static VOID Ap6256StationFtEvent(PAP6256_WIFI Wifi,
    const AP6256_FT_EVENT* Event, const AP6256_FT_OWNER* LostOwner)
{
    const AP6256_FT_OWNER* owner = LostOwner != NULL ? LostOwner : &Event->Owner;
    NTSTATUS status;
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (Ap6256FtOwnerMatches(&Wifi->Auth.Ft, owner) && Ap6256FtTaskLive(Wifi) &&
        Wifi->Auth.Ft.Phase == Ap6256FtAuthenticating) {
        status = LostOwner != NULL ? STATUS_INSUFFICIENT_RESOURCES :
            Ap6256IndicateFtAuthentication(Wifi, Event);
        if (!NT_SUCCESS(status)) Ap6256FtFailTask(Wifi, owner, status);
    }
    Ap6256LockRelease(&Wifi->ConnectLock);
}

_Use_decl_annotations_
VOID Ap6256NetFtEvent(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Peer,
    const UCHAR* Body, ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    AP6256_FT_EVENT* event;
    KIRQL irql;
    BOOLEAN queued = FALSE;
    if (wifi == NULL || Peer == NULL || !Ctx->FirmwareHostFt ||
        Length > AP6256_FT_FW_HEADER + 2 * AP6256_FT_FW_AUTH_MAX) return;
    event = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*event), AP6256_POOL_TAG);
    if (event == NULL) return;
    if (!Ap6256FtDecodeEvent(Body, Length, event) ||
        !RtlEqualMemory(Peer, event->Owner.Bssid, 6)) goto Done;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (!wifi->Stopping && wifi->HardwareAvailable) {
        if ((ULONG)(wifi->Auth.FtHead - wifi->Auth.FtTail) < RTL_NUMBER_OF(wifi->Auth.FtEvents)) {
            wifi->Auth.FtEvents[wifi->Auth.FtHead++ % RTL_NUMBER_OF(wifi->Auth.FtEvents)] = event;
            event = NULL;
        } else if (!wifi->Auth.FtEventsLost) {
            wifi->Auth.FtLostOwner = event->Owner;
            wifi->Auth.FtEventsLost = TRUE;
        }
        queued = TRUE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
Done:
    if (event != NULL) ExFreePoolWithTag(event, AP6256_POOL_TAG);
    if (queued) AP6256_CMDQ_KICK(wifi);
}

VOID Ap6256HandleSetFastBssTransition(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
    const WDI_MESSAGE_HEADER* Header, const UCHAR* Tlv, ULONG TlvLength)
{
    WDI_SET_FAST_BSS_TRANSITION_PARAMETERS_COMMAND parameters;
    AP6256_FT_OWNER previousOwner;
    AP6256_FT_PHASE previousPhase;
    NTSTATUS status;
    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(ParseWdiSetFastBssTransitionParameters(
        TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    Ap6256LockAcquire(&Wifi->ConnectLock);
    previousPhase = Wifi->Auth.Ft.Phase;
    previousOwner = Wifi->Auth.Ft.Owner;
    if (!Ap6256HostFbtAvailable(Wifi)) status = STATUS_NOT_SUPPORTED;
    else if (Header->PortId != AP6256_STATION_PORT ||
        Header->PortId != Wifi->Auth.Ft.Owner.PortId ||
        (Wifi->Auth.Ft.Phase != Ap6256FtDrainingHost &&
         Wifi->Auth.Ft.Phase != Ap6256FtAbortRequired && !Ap6256FtTaskLive(Wifi)))
        status = STATUS_INVALID_DEVICE_STATE;
    else if (!NT_SUCCESS(status)) {
        if (Wifi->Auth.Ft.Phase == Ap6256FtWaitingHost) {
            Wifi->Auth.Ft.HostReplyOutstanding = FALSE;
            (VOID)Ap6256FtEnd(Wifi->Ctx, &Wifi->Auth.Ft, FALSE);
        } else if (Wifi->Auth.Ft.HostReplyOutstanding &&
            (Wifi->Auth.Ft.Phase == Ap6256FtDrainingHost || Wifi->Auth.Ft.Phase == Ap6256FtAbortRequired)) {
            (VOID)Ap6256FtFinish(Wifi->Ctx, &Wifi->Auth.Ft, &previousOwner, 1,
                NULL, 0, NULL, 0, NULL, 0);
        }
    } else status = Ap6256FtFinish(Wifi->Ctx, &Wifi->Auth.Ft, &previousOwner, parameters.status,
        parameters.Optional.RSNIE_IsPresent ? parameters.RSNIE.pElements : NULL,
        parameters.Optional.RSNIE_IsPresent ? parameters.RSNIE.ElementCount : 0,
        parameters.Optional.MDE_IsPresent ? parameters.MDE.pElements : NULL,
        parameters.Optional.MDE_IsPresent ? parameters.MDE.ElementCount : 0,
        parameters.Optional.FTE_IsPresent ? parameters.FTE.pElements : NULL,
        parameters.Optional.FTE_IsPresent ? parameters.FTE.ElementCount : 0);
    if (previousPhase == Ap6256FtWaitingHost &&
        Wifi->Auth.Ft.Phase != Ap6256FtWaitingHost && Wifi->Auth.Ft.Phase != Ap6256FtResumed)
        Ap6256FtFailTask(Wifi, &previousOwner, status);
    Ap6256LockRelease(&Wifi->ConnectLock);
    CleanupParsedWdiSetFastBssTransitionParameters(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}
