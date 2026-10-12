/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

VOID Ap6256ClearGoEvents(PAP6256_WIFI Wifi)
{
    KIRQL irql;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    ++Wifi->Model.GoEventGeneration;
    while (Wifi->Model.GoEventTail != Wifi->Model.GoEventHead) {
        AP6256_GO_EVENT* event =
            Wifi->Model.GoEvents[Wifi->Model.GoEventTail++ % AP6256_GO_EVENT_DEPTH];
        ExFreePoolWithTag(event, AP6256_POOL_TAG);
    }
    Wifi->Model.GoEventsLost = FALSE;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
}

VOID Ap6256ForgetGoAutoAssoc(PAP6256_WIFI Wifi, const UCHAR* Address)
{
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc); ++i) {
        AP6256_GO_AUTO_ASSOC* assoc = Wifi->Model.GoAutoAssoc[i];
        if (assoc != NULL && (Address == NULL || RtlEqualMemory(Address, assoc->Address, 6))) {
            Wifi->Model.GoAutoAssoc[i] = NULL;
            ExFreePoolWithTag(assoc, AP6256_POOL_TAG);
        }
    }
}

static VOID Ap6256GoRejectPeer(PAP6256_WIFI Wifi, const UCHAR* Address, UINT16 Reason)
{
    NTSTATUS status;
    if (Wifi->Stopping || !Wifi->HardwareAvailable) return;
    status = Ap6256GoDisconnectPeer(Wifi->Ctx, Address, Reason);
    if (!NT_SUCCESS(status)) {
        Wifi->Ctx->Go.NativeStateUncertain = TRUE;
        Ap6256NetFirmwareHalted(Wifi->Ctx);
    }
}

static VOID Ap6256GoAutoAssociation(PAP6256_WIFI Wifi, const UCHAR* Address, const UCHAR* Ies,
                                    ULONG Length)
{
    AP6256_AP_PEER_INFO* info;
    AP6256_GO_AUTO_ASSOC* assoc;
    WDI_INDICATION_AP_ASSOCIATION_REQUEST_PARAMETERS p;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0, slot;
    NTSTATUS status;
    if (!Wifi->ApStarted || Wifi->Model.GoNativeAssociation || !Ap6256MacIsValidUnicast(Address))
        return;

    Ap6256ForgetGoAutoAssoc(Wifi, Address);
    Ap6256CxGroupPeerDelete(Wifi->Ctx, Address);
    for (slot = 0; slot < RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc); ++slot)
        if (Wifi->Model.GoAutoAssoc[slot] == NULL)
            break;
    if (slot == RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc) || Length == 0 ||
        Length > AP6256_GO_ASSOC_IE_MAX || !Ap6256GoIesValid(Ies, Length)) {
        Ap6256GoRejectPeer(Wifi, Address, 1);
        TraceDiag("hotspot: autonomous association rejected: slots/IE data\n");
        return;
    }
    if (!Ap6256GoAssociationAllowed(&Wifi->GoApParams, Ies, Length)) {

        Ap6256GoRejectPeer(Wifi, Address, 1);
        TraceDiag("hotspot: legacy client rejected by START_AP policy\n");
        return;
    }
    info =
        (AP6256_AP_PEER_INFO*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*info), AP6256_POOL_TAG);
    assoc = (AP6256_GO_AUTO_ASSOC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*assoc),
                                                   AP6256_POOL_TAG);
    status = info != NULL && assoc != NULL ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
    if (NT_SUCCESS(status)) {
        status = Ap6256WifiGetApPeerInfo(Wifi->Ctx, Address, info);
        if (!NT_SUCCESS(status))
            TraceDiag("hotspot: association peer/BSS metadata failed 0x%08X\n", status);
    }

    if (NT_SUCCESS(status) && (InterlockedCompareExchange(&Wifi->Stopping, 0, 0) != 0 ||
                               InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) == 0))
        status = STATUS_CANCELLED;
    if (NT_SUCCESS(status)) {
        status = Ap6256GoVerifySecurity(Wifi->Ctx, &Wifi->GoApParams);
        if (!NT_SUCCESS(status))
            TraceDiag("hotspot: association security readback failed 0x%08X\n", status);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256GoBuildAutoAssoc(Wifi->Ctx, &Wifi->GoApParams, info, Ies, Length, assoc);
        if (!NT_SUCCESS(status))
            TraceDiag("hotspot: association frame conversion failed 0x%08X\n", status);
    }
    if (info != NULL)
        ExFreePoolWithTag(info, AP6256_POOL_TAG);

    if (NT_SUCCESS(status) && (InterlockedCompareExchange(&Wifi->Stopping, 0, 0) != 0 ||
                               InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) == 0))
        status = STATUS_CANCELLED;
    RtlZeroMemory(&p, sizeof(p));
    RtlZeroMemory(&header, sizeof(header));
    if (NT_SUCCESS(status)) {
        assoc->Token = ++Wifi->Model.GoAssocToken;
        if (assoc->Token == 0)
            assoc->Token = ++Wifi->Model.GoAssocToken;
        RtlCopyMemory(assoc->Address, Address, 6);
        RtlCopyMemory(p.IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address, Address, 6);
        p.IncomingRequestInfo.AssocRequestFrame.pElements = assoc->Request;
        p.IncomingRequestInfo.AssocRequestFrame.ElementCount = assoc->RequestLength;
        p.IncomingRequestInfo.Optional.AssocRequestDeviceContext_IsPresent = TRUE;
        p.IncomingRequestInfo.AssocRequestDeviceContext.pElements = (UINT8*)&assoc->Token;
        p.IncomingRequestInfo.AssocRequestDeviceContext.ElementCount = sizeof(assoc->Token);
        status = Ap6256NdisToNtStatus(GenerateWdiIndicationApAssociationRequestReceived(
            &p, 0, &Wifi->TlvContext, &generatedLength, &generated));
    }
    if (NT_SUCCESS(status)) {
        Wifi->Model.GoAutoAssoc[slot] = assoc;
        header.PortId = AP6256_GROUP_PORT;
        status = Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED,
                                               &header, WDI_TRANSACTION_ID_UNSOLICIT, NULL,
                                               generated, generatedLength);
        if (!NT_SUCCESS(status))
            Wifi->Model.GoAutoAssoc[slot] = NULL;
    }
    TraceDiag("hotspot: autonomous association %02X:%02X:%02X:%02X:%02X:%02X IEs %u -> 0x%08X\n",
              Address[0], Address[1], Address[2], Address[3], Address[4], Address[5], Length,
              status);
    FreeGenerated(generated);
    if (!NT_SUCCESS(status)) {
        if (assoc != NULL)
            ExFreePoolWithTag(assoc, AP6256_POOL_TAG);
        if (!Wifi->Stopping && Wifi->HardwareAvailable)
            Ap6256GoRejectPeer(Wifi, Address, 1);
    }
}

VOID Ap6256CancelGoAssociation(PAP6256_WIFI Wifi, NTSTATUS Status)
{
    Ap6256ClearGoEvents(Wifi);
    Ap6256ForgetGoAutoAssoc(Wifi, NULL);
    AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
    Ap6256FailStartedTask(Wifi, &Wifi->ApAssocTask,
                          WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE, Status);
}

static VOID Ap6256GoIndicateDisassociation(PAP6256_WIFI Wifi, const UCHAR* Address, UINT16 Reason)
{
    WDI_INDICATION_DISASSOCIATION_PARAMETERS p;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG length = 0;
    RtlZeroMemory(&p, sizeof(p));
    RtlZeroMemory(&header, sizeof(header));
    header.PortId = AP6256_GROUP_PORT;
    Ap6256ForgetGoAutoAssoc(Wifi, Address);
    if (RtlEqualMemory(Wifi->ApPendingAssocMac, Address, 6)) {
        AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
        Ap6256FailStartedTask(Wifi, &Wifi->ApAssocTask,
                              WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                              STATUS_CONNECTION_DISCONNECTED);
    }
    Ap6256CxGroupPeerDelete(Wifi->Ctx, Address);
    RtlCopyMemory(p.DisconnectIndicationParameters.MacAddress.Address, Address, 6);
    p.DisconnectIndicationParameters.DisassociationWABIReason = WDI_ASSOC_STATUS_PEER_DISASSOCIATED;
    TraceDiag("hotspot: peer disconnected, 802.11 reason %u\n", (ULONG)Reason);
    p.Optional.NeedPeerStateCleanup_IsPresent = TRUE;
    p.NeedPeerStateCleanup = TRUE;
    if (GenerateWdiIndicationDisassociation(&p, 0, &Wifi->TlvContext, &length, &generated) ==
        NDIS_STATUS_SUCCESS) {
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_DISASSOCIATION, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated, length);
    }
    FreeGenerated(generated);
}

static VOID Ap6256CxApAssocTimeout(PAP6256_WIFI wifi)
{
    WDI_MESSAGE_HEADER header;
    PVOID requestId = NULL;
    UCHAR address[6];
    KIRQL irql;
    BOOLEAN expired;
    RtlZeroMemory(&header, sizeof(header));
    RtlZeroMemory(address, sizeof(address));
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    expired = wifi->ApAssocTask.Active && wifi->ApAssocTask.DeadlineMs != 0 &&
              Ap6256InterruptTimeMs() >= wifi->ApAssocTask.DeadlineMs;
    if (expired) {
        header = wifi->ApAssocTask.Header;
        requestId = wifi->ApAssocTask.RequestId;
        RtlCopyMemory(address, wifi->ApPendingAssocMac, 6);
        wifi->ApAssocTask.Active = FALSE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (expired) {
        Ap6256GoRejectPeer(wifi, address, 1);
        Ap6256CxGroupPeerDelete(wifi->Ctx, address);
        TraceDiag("hotspot: association response timed out\n");
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                                      &header, header.TransactionId, requestId, STATUS_IO_TIMEOUT,
                                      NULL, 0);
    }
}

static VOID Ap6256OnApAssocTimeout(PAP6256_WIFI wifi)
{
    PAP6256_CX_ADAPTER role;
    if (wifi->Stopping || !wifi->HardwareAvailable) return;
    role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    if (!role) return;
    Ap6256CxApAssocTimeout(wifi);
    ExReleaseRundownProtection(&role->Rundown);
}

static VOID Ap6256CxQueueGoEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
                                             UINT32 Status, UINT32 Reason, UINT16 Flags,
                                             const UCHAR* Address, const UCHAR* Data, ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    AP6256_GO_EVENT* event = NULL;
    KIRQL irql;
    if (wifi == NULL)
        return;
    TraceDiag("hotspot: event %u status %u reason %u if %u bsscfg %u bytes %u\n", EventType, Status,
              Reason, Ctx->Go.IfIndex, Ctx->Go.BssIndex, Length);
    if (Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT) {
        if (Ctx->Go.Stopping || !Ctx->Go.Started)
            return;
        if (EventType == BRCMF_E_LINK)
            Ap6256NetQueueLinkEvent(Ctx, Status == 0 && (Flags & 1u) ? AP6256_LINK_CLIENT_UP
                                                                     : AP6256_LINK_CLIENT_DOWN);
        else if (EventType == BRCMF_E_SET_SSID)
            Ap6256NetQueueLinkEvent(Ctx,
                                    Status == 0 ? AP6256_LINK_CLIENT_UP : AP6256_LINK_CLIENT_DOWN);
        else if (EventType == BRCMF_E_DEAUTH || EventType == BRCMF_E_DEAUTH_IND ||
                 EventType == BRCMF_E_DISASSOC || EventType == BRCMF_E_DISASSOC_IND)
            Ap6256NetQueueLinkEvent(Ctx, AP6256_LINK_CLIENT_DOWN);
        return;
    }
    switch (EventType) {
    case BRCMF_E_ASSOC_IND:
    case BRCMF_E_REASSOC_IND:
    case BRCMF_E_PRE_ASSOC_IND:
    case BRCMF_E_PRE_REASSOC_IND:
    case BRCMF_E_ASSOC_IND_NDIS:
    case BRCMF_E_REASSOC_IND_NDIS:
    case BRCMF_E_DEAUTH:
    case BRCMF_E_DEAUTH_IND:
    case BRCMF_E_DISASSOC:
    case BRCMF_E_DISASSOC_IND:
    case BRCMF_E_LINK:
    case BRCMF_E_DFS_AP_STOP:
    case BRCMF_E_DFS_AP_RESUME:
        break;
    default:
        return;
    }
    if (InterlockedCompareExchange(&wifi->Stopping, 0, 0) != 0 ||
        InterlockedCompareExchange(&wifi->HardwareAvailable, 0, 0) == 0 || !AP6256_CMDQ_OK(wifi))
        return;
    if (Length <= AP6256_GO_EVENT_MAX && (Length == 0 || Data != NULL)) {
        event = (AP6256_GO_EVENT*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, FIELD_OFFSET(AP6256_GO_EVENT, Data) + Length, AP6256_POOL_TAG);
        if (event != NULL) {
            event->Type = EventType;
            event->Status = Status;
            event->Reason = Reason;
            event->Flags = Flags;
            event->Length = Length;
            RtlCopyMemory(event->Address, Address, 6);
            if (Length)
                RtlCopyMemory(event->Data, Data, Length);
        }
    }
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (InterlockedCompareExchange(&wifi->Stopping, 0, 0) == 0 &&
        InterlockedCompareExchange(&wifi->HardwareAvailable, 0, 0) != 0) {
        if (event != NULL &&
            (ULONG)(wifi->Model.GoEventHead - wifi->Model.GoEventTail) < AP6256_GO_EVENT_DEPTH) {
            event->Generation = wifi->Model.GoEventGeneration;
            wifi->Model.GoEvents[wifi->Model.GoEventHead++ % AP6256_GO_EVENT_DEPTH] = event;
            event = NULL;
        } else
            wifi->Model.GoEventsLost = TRUE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (event != NULL)
        ExFreePoolWithTag(event, AP6256_POOL_TAG);
    AP6256_CMDQ_KICK(wifi);
}

VOID Ap6256NetGoEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
                                             UINT32 Status, UINT32 Reason, UINT16 Flags,
                                             const UCHAR* Address, const UCHAR* Data, ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    PAP6256_CX_ADAPTER role;
    if (!wifi || wifi->Stopping || !wifi->HardwareAvailable) return;
    role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    if (!role) return;
    Ap6256CxQueueGoEvent(Ctx, EventType, Status, Reason, Flags, Address, Data, Length);
    ExReleaseRundownProtection(&role->Rundown);
}

static VOID Ap6256ProcessGoEvent(PAP6256_WIFI wifi, const AP6256_GO_EVENT* Event)
{
    PAP6256_DEVICE_CONTEXT Ctx = wifi->Ctx;
    UINT32 EventType = Event->Type, Status = Event->Status, Reason = Event->Reason;
    UINT16 Flags = Event->Flags;
    const UCHAR* Address = Event->Address;
    const UCHAR* Data = Event->Data;
    ULONG Length = Event->Length;
    if (Event->Generation != wifi->Model.GoEventGeneration ||
        (EventType != BRCMF_E_DFS_AP_RESUME && (Ctx->Go.Stopping || !wifi->ApStarted)))
        return;
    switch (EventType) {
    case BRCMF_E_ASSOC_IND:
    case BRCMF_E_REASSOC_IND:
        if (Status == 0 && Reason == 0) {
            if (EventType == BRCMF_E_REASSOC_IND && !wifi->Model.GoNativeAssociation)
                Ap6256GoIndicateDisassociation(wifi, Address, 1);
            Ap6256GoAutoAssociation(wifi, Address, Data, Length);
        }
        break;
    case BRCMF_E_PRE_ASSOC_IND:
    case BRCMF_E_PRE_REASSOC_IND:
        if (Status != 0 || Reason != 0)
            break;
        wifi->Model.GoNativeAssociation = TRUE;
        Ap6256NetApAssociationRequest(Ctx, Address, (BOOLEAN)(EventType == BRCMF_E_PRE_REASSOC_IND),
                                      Data, Length);
        break;
    case BRCMF_E_ASSOC_IND_NDIS:
    case BRCMF_E_REASSOC_IND_NDIS: {
        WDI_MESSAGE_HEADER header;
        PVOID requestId = NULL;
        WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE_PARAMETERS p;
        AP6256_GO_ASSOC_RESULT result;
        UINT8* generated = NULL;
        ULONG length = 0;
        NTSTATUS status = STATUS_UNSUCCESSFUL, delivered;
        WDI_PHY_TYPE phy;
        BOOLEAN matched, accepted;
        KIRQL irql;
        RtlZeroMemory(&header, sizeof(header));
        KeAcquireSpinLock(&wifi->CommandLock, &irql);
        matched = wifi->ApAssocTask.Active && RtlEqualMemory(Address, wifi->ApPendingAssocMac, 6);
        if (matched) {
            header = wifi->ApAssocTask.Header;
            requestId = wifi->ApAssocTask.RequestId;
            wifi->ApAssocTask.Active = FALSE;
        }
        accepted = wifi->Model.ApAssocAccept;
        phy = wifi->Model.ApAssocPhy;
        KeReleaseSpinLock(&wifi->CommandLock, irql);
        if (!matched)
            break;
        AP6256_TIMER_STOP(wifi->Model.ApAssocTimer, FALSE);
        RtlZeroMemory(&p, sizeof(p));
        if (Status == 0 && Ap6256GoParseAssocResult(Data, Length, &result)) {
            RtlCopyMemory(p.AssocResponseResult.PeerMACAddress.Address, Address, 6);
            p.AssocResponseResult.IsReassociationRequest =
                (BOOLEAN)(EventType == BRCMF_E_REASSOC_IND_NDIS);
            p.AssocResponseResult.IsReAssociationResponse =
                p.AssocResponseResult.IsReassociationRequest;
            p.AssocResponseResult.AuthAlgorithm = wifi->ApSecurity == Ap6256SecurityWpa2Host
                                                      ? WDI_AUTH_ALGO_RSNA_PSK
                                                      : WDI_AUTH_ALGO_80211_OPEN;
            p.AssocResponseResult.UnicastCipherAlgorithm =
                wifi->ApSecurity == Ap6256SecurityWpa2Host ? WDI_CIPHER_ALGO_CCMP
                                                           : WDI_CIPHER_ALGO_NONE;
            p.AssocResponseResult.MulticastCipherAlgorithm =
                p.AssocResponseResult.UnicastCipherAlgorithm;
            p.AssocResponseFrame.pElements = (UINT8*)result.Response;
            p.AssocResponseFrame.ElementCount = result.ResponseLength;
            p.BeaconIEs.pElements = (UINT8*)result.Beacon;
            p.BeaconIEs.ElementCount = result.BeaconLength;
            p.ActivePhyList.pElements = &phy;
            p.ActivePhyList.ElementCount = 1;
            accepted = accepted && result.StatusCode == 0;
            status = Ap6256NdisToNtStatus(GenerateWdiIndicationSendApAssociationResponseComplete(
                &p, 0, &wifi->TlvContext, &length, &generated));
            if (NT_SUCCESS(status) && accepted &&
                !Ap6256CxGroupPeerCreate(Ctx, Address,
                                       phy == WDI_PHY_TYPE_VHT    ? AP6256_PHY_ID_VHT
                                       : phy == WDI_PHY_TYPE_HT   ? AP6256_PHY_ID_HT
                                       : phy == WDI_PHY_TYPE_OFDM ? AP6256_PHY_ID_OFDM
                                                                  : AP6256_PHY_ID_ERP))
                status = STATUS_INSUFFICIENT_RESOURCES;
        } else if (Status == 0) {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
        delivered = Ap6256SendIndicationRq(wifi, WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                                            &header, header.TransactionId, requestId, status,
                                            NT_SUCCESS(status) ? generated : NULL,
                                            NT_SUCCESS(status) ? length : 0);

        if (NT_SUCCESS(status) && accepted && NT_SUCCESS(delivered))
            Ap6256CxGroupRxOpen(Ctx, Address);
        else {
            Ap6256CxGroupPeerDelete(Ctx, Address);
            if (accepted)
                Ap6256GoRejectPeer(wifi, Address, 1);
        }
        FreeGenerated(generated);
        break;
    }
    case BRCMF_E_DEAUTH:
    case BRCMF_E_DEAUTH_IND:
    case BRCMF_E_DISASSOC:
    case BRCMF_E_DISASSOC_IND:
        if (wifi->ApStarted)
            Ap6256GoIndicateDisassociation(wifi, Address, (UINT16)Reason);
        break;
    case BRCMF_E_LINK:

        if ((Flags & 1u) == 0 && Ctx->Go.Started && !Ctx->Go.Stopping)
            Ap6256NetApStopped(Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
        break;
    case BRCMF_E_DFS_AP_STOP:
        Ap6256NetApStopped(Ctx, AP6256_AP_STOP_FREQUENCY_NOT_AVAILABLE);
        break;
    case BRCMF_E_DFS_AP_RESUME:
        Ap6256NetApCanSustain(Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
        break;
    default:
        break;
    }
}

static BOOLEAN
Ap6256ClientAssociation(PAP6256_WIFI Wifi, const WDI_MESSAGE_HEADER* Header, PVOID RequestId,
                        BOOLEAN Success)
{
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    WDI_INDICATION_ASSOCIATION_RESULT_LIST list = {0};
    WDI_ASSOCIATION_RESULT_CONTAINER result = {0};
    AP6256_ASSOC_FRAMES frames = {0};
    WDI_PHY_TYPE phy = ctx->Go.Channel <= 14 ? WDI_PHY_TYPE_HT : WDI_PHY_TYPE_VHT;
    UCHAR bssid[6] = {0};
    UINT32 channel = 0;
    UINT8* generated = NULL;
    ULONG length = 0;
    NTSTATUS status;
    if (Success) {
        Success = NT_SUCCESS(Ap6256WifiGetBssidIf(ctx, ctx->Go.IfIndex, bssid)) &&
                  RtlEqualMemory(bssid, ctx->Go.ClientBssid, 6) &&
                  NT_SUCCESS(Ap6256WifiGetChannelIf(ctx, ctx->Go.IfIndex, &channel)) &&
                  channel == ctx->Go.Channel;
        if (Success) {
            Ap6256WifiGetAssocFramesIf(ctx, ctx->Go.IfIndex, &frames);

            Success = frames.AssocRequest != NULL && frames.AssocResponse != NULL &&
                      frames.PeerStatusCode == 0;
        }
    }
    RtlCopyMemory(result.BSSID.Address, ctx->Go.ClientBssid, 6);
    result.AssociationResultParameters.AssociationStatus =
        Success ? WDI_ASSOC_STATUS_SUCCESS : WDI_ASSOC_STATUS_FAILURE;
    result.AssociationResultParameters.AuthAlgorithm =
        ctx->Go.ClientSecure ? WDI_AUTH_ALGO_RSNA_PSK : WDI_AUTH_ALGO_80211_OPEN;
    result.AssociationResultParameters.UnicastCipherAlgorithm =
        ctx->Go.ClientSecure ? WDI_CIPHER_ALGO_CCMP : WDI_CIPHER_ALGO_NONE;
    result.AssociationResultParameters.MulticastDataCipherAlgorithm =
        result.AssociationResultParameters.UnicastCipherAlgorithm;
    result.AssociationResultParameters.MulticastMgmtCipherAlgorithm =
        ctx->Go.ClientMfp ? WDI_CIPHER_ALGO_BIP : WDI_CIPHER_ALGO_NONE;
    result.AssociationResultParameters.PortAuthorized = Success && !ctx->Go.ClientSecure;
    result.AssociationResultParameters.BandID =
        ctx->Go.Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000;
    result.AssociationResultParameters.ReAssociation = frames.ReAssociation;
    result.AssociationResultParameters.StatusCode = frames.PeerStatusCode;
    result.AssociationResultParameters.WMMQoSEnabled = frames.WmmNegotiated;
    if (Success) {
        result.Optional.AssociationRequestFrame_IsPresent = TRUE;
        result.AssociationRequestFrame.pElements = frames.AssocRequest;
        result.AssociationRequestFrame.ElementCount = frames.AssocRequestLength;
        result.Optional.AssociationResponseFrame_IsPresent = TRUE;
        result.AssociationResponseFrame.pElements = frames.AssocResponse;
        result.AssociationResponseFrame.ElementCount = frames.AssocResponseLength;
        if (frames.Beacon != NULL) {
            result.Optional.BeaconProbeResponse_IsPresent = TRUE;
            result.BeaconProbeResponse.pElements = frames.Beacon;
            result.BeaconProbeResponse.ElementCount = frames.BeaconLength;
        }
    }
    result.ActivePhyTypeList.pElements = &phy;
    result.ActivePhyTypeList.ElementCount = 1;
    list.AssociationResults.pElements = &result;
    list.AssociationResults.ElementCount = 1;
    status = Ap6256NdisToNtStatus(
        GenerateWdiIndicationAssociationResult(&list, 0, &Wifi->TlvContext, &length, &generated));
    if (NT_SUCCESS(status) && generated != NULL)
        status = Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_ASSOCIATION_RESULT, Header,
                                               WDI_TRANSACTION_ID_UNSOLICIT, RequestId, generated,
                                               length);
    else
        status = STATUS_INSUFFICIENT_RESOURCES;
    FreeGenerated(generated);
    Ap6256WifiFreeAssocFrames(&frames);
    TraceDiag("P2P client: association %s if %u channel %u indication 0x%08X\n",
              Success ? "success" : "failed", ctx->Go.IfIndex, ctx->Go.Channel, status);
    return Success && NT_SUCCESS(status);
}

static VOID Ap6256ClientLinkState(PAP6256_WIFI Wifi)
{
    WDI_INDICATION_LINK_STATE_CHANGE_PARAMETERS p = {0};
    WDI_MESSAGE_HEADER header = {0};
    UINT8* generated = NULL;
    ULONG length = 0;
    UINT32 rate = 0;
    INT32 rssi = -100;
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    (VOID) Ap6256BcdcQueryDcmdIf(ctx, ctx->Go.IfIndex, BRCMF_C_GET_RATE, &rate, sizeof(rate));
    (VOID) Ap6256BcdcQueryDcmdIf(ctx, ctx->Go.IfIndex, BRCMF_C_GET_RSSI, &rssi, sizeof(rssi));
    ctx->Go.ClientRssiDbm = (CHAR)max(-128, min(127, rssi));
    RtlCopyMemory(p.LinkStateChangeParameters.PeerMACAddress.Address, ctx->Go.ClientBssid, 6);
    p.LinkStateChangeParameters.TxLinkSpeed = rate * 500u;
    p.LinkStateChangeParameters.RxLinkSpeed = rate * 500u;
    p.LinkStateChangeParameters.LinkQuality = (UINT8)Ap6256LinkQualityFromRssi(rssi);
    header.PortId = AP6256_GROUP_PORT;
    if (GenerateWdiIndicationLinkStateChange(&p, 0, &Wifi->TlvContext, &length, &generated) ==
        NDIS_STATUS_SUCCESS)
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_LINK_STATE_CHANGE, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated, length);
    FreeGenerated(generated);
}

static NTSTATUS Ap6256ClientAppendVendorIes(AP6256_CONNECT_PARAMS* Params,
                                            const UCHAR* Ies, ULONG Length)
{

    if (Params->AssociationVendorIesLength > AP6256_P2P_VENDOR_IE_MAX ||
        Length > AP6256_P2P_VENDOR_IE_MAX - Params->AssociationVendorIesLength ||
        !Ap6256P2pVendorIesValid(Ies, Length))
        return STATUS_INVALID_PARAMETER;
    if (Length != 0)
        RtlCopyMemory(Params->AssociationVendorIes + Params->AssociationVendorIesLength, Ies, Length);
    Params->AssociationVendorIesLength += Length;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256ClientStartAttempt(PAP6256_WIFI Wifi)
{
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    AP6256_CONNECT_PARAMS* p = &Wifi->Model.ClientCandidates[Wifi->Model.ClientCandidateIndex];
    KIRQL irql;
    if (ctx->FirmwareLinkUp && !ctx->FirmwareMchanSupported) {
        UINT32 station = 0;
        NTSTATUS status = Ap6256WifiGetChannel(ctx, &station);
        if (!NT_SUCCESS(status))
            return status;
        if (station == 0 || station != p->Channel)
            return STATUS_DEVICE_BUSY;
    }
    InterlockedIncrement(&Wifi->Model.GroupGeneration);
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    RtlCopyMemory(ctx->Go.ClientBssid, p->Bssid, 6);
    ctx->Go.Channel = p->Channel;
    ctx->Go.ClientSecure = p->Security == Ap6256SecurityWpa2Host;
    ctx->Go.ClientMfp = p->Mfp != Ap6256MfpNone;
    ctx->Go.ClientConnected = FALSE;
    ctx->Go.Started = TRUE;
    ctx->Go.Stopping = FALSE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    if (!Ap6256CxGroupPeerCreate(ctx, p->Bssid,
                               p->Channel <= 14 ? AP6256_PHY_ID_HT : AP6256_PHY_ID_VHT))
        return STATUS_INSUFFICIENT_RESOURCES;
    {
        NTSTATUS status = Ap6256QuiesceP2pListen(Wifi);
        if (NT_SUCCESS(status))
            status = Ap6256P2pSetHostIesFor(ctx, &ctx->Go.P2p, ctx->Go.IfIndex,
                                          Ap6256P2pFrameAssocRequest,
                                          p->AssociationVendorIes, p->AssociationVendorIesLength);
        if (NT_SUCCESS(status))
            status = Ap6256P2pBuildIesFor(ctx, &ctx->Go.P2p, ctx->Go.IfIndex);
        return NT_SUCCESS(status) ? Ap6256ClientConnect(ctx, p) : status;
    }
}

static NTSTATUS Ap6256CxDisconnectClient(PAP6256_WIFI Wifi, UINT32 Reason)
{
    NTSTATUS status = Ap6256ClientDisconnect(Wifi->Ctx, Reason);
    if (!NT_SUCCESS(status)) {

        Wifi->Ctx->Go.NativeStateUncertain = TRUE;
        if (Wifi->HardwareAvailable) Ap6256NetFirmwareHalted(Wifi->Ctx);
    }
    return status;
}

static VOID Ap6256ClientAttemptResult(PAP6256_WIFI Wifi, BOOLEAN Up, NTSTATUS FailureStatus)
{
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    WDI_MESSAGE_HEADER header;
    PVOID requestId;
    if (!Wifi->Model.ClientConnectTask.Active)
        return;
    header = Wifi->Model.ClientConnectTask.Header;
    requestId = Wifi->Model.ClientConnectTask.RequestId;
    for (;;) {
        BOOLEAN connected = Ap6256ClientAssociation(Wifi, &header, requestId, Up);
        if (connected) {
            ctx->Go.ClientConnected = TRUE;
            Ap6256IndicateP2pGroupChannel(Wifi, &header, requestId, ctx->Go.Channel);
            AP6256_TIMER_STOP(Wifi->Model.ClientConnectTimer, FALSE);
            (VOID) Ap6256ClaimTask(Wifi, &Wifi->Model.ClientConnectTask, &header, &requestId);

            if (!NT_SUCCESS(Ap6256SendIndicationRq(Wifi, WDI_INDICATION_CONNECT_COMPLETE, &header,
                                                   header.TransactionId, requestId, STATUS_SUCCESS,
                                                   NULL, 0))) {
                (VOID) Ap6256CancelClientLocked(Wifi, STATUS_CANCELLED, 3);
                return;
            }
            Ap6256CxGroupRxOpen(ctx, ctx->Go.ClientBssid);
            Ap6256ClientLinkState(Wifi);
            return;
        }
        InterlockedIncrement(&Wifi->Model.GroupGeneration);
        if (!NT_SUCCESS(Ap6256CxDisconnectClient(Wifi, 3))) {
            FailureStatus = STATUS_IO_DEVICE_ERROR;
            Wifi->Model.ClientCandidateIndex = Wifi->Model.ClientCandidateCount;
        }
        Ap6256CxGroupPeerDelete(ctx, NULL);
        if (++Wifi->Model.ClientCandidateIndex >= Wifi->Model.ClientCandidateCount)
            break;
        FailureStatus = Ap6256ClientStartAttempt(Wifi);
        if (NT_SUCCESS(FailureStatus))
            return;
        Up = FALSE;
    }
    AP6256_TIMER_STOP(Wifi->Model.ClientConnectTimer, FALSE);
    (VOID) Ap6256ClaimTask(Wifi, &Wifi->Model.ClientConnectTask, &header, &requestId);
    (VOID) Ap6256SendIndicationRq(Wifi, WDI_INDICATION_CONNECT_COMPLETE, &header,
                                  header.TransactionId, requestId, FailureStatus, NULL, 0);
}

NTSTATUS Ap6256CancelClientLocked(PAP6256_WIFI Wifi, NTSTATUS CompletionStatus, UINT32 Reason)
{
    WDI_MESSAGE_HEADER header;
    PVOID requestId;
    NTSTATUS status;
    BOOLEAN pending;
    if (Wifi->Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_CLIENT)
        return STATUS_SUCCESS;
    Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
    InterlockedIncrement(&Wifi->Model.GroupGeneration);
    AP6256_TIMER_STOP(Wifi->Model.ClientConnectTimer, FALSE);
    pending = Ap6256ClaimTask(Wifi, &Wifi->Model.ClientConnectTask, &header, &requestId);
    status = Ap6256CxDisconnectClient(Wifi, Reason);
    Ap6256CxGroupPeerDelete(Wifi->Ctx, NULL);
    if (pending) {
        (VOID) Ap6256ClientAssociation(Wifi, &header, requestId, FALSE);
        (VOID) Ap6256SendIndicationRq(Wifi, WDI_INDICATION_CONNECT_COMPLETE, &header,
                                      header.TransactionId, requestId, CompletionStatus, NULL, 0);
    }
    if (Wifi->Ctx->Go.ClientConnected)
        Ap6256GoIndicateDisassociation(Wifi, Wifi->Ctx->Go.ClientBssid, (UINT16)Reason);
    Wifi->Ctx->Go.ClientConnected = FALSE;
    Wifi->Model.ClientCandidateCount = 0;
    return status;
}

NTSTATUS Ap6256CancelClient(PAP6256_WIFI Wifi, NTSTATUS CompletionStatus, UINT32 Reason)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    status = Ap6256CancelClientLocked(Wifi, CompletionStatus, Reason);
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    return status;
}

static VOID Ap6256CxClientLinkWork(PAP6256_WIFI Wifi, BOOLEAN Up, LONG Generation)
{
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    if (Generation == Wifi->Model.GroupGeneration && Wifi->HardwareAvailable &&
        Wifi->Ctx->Go.Created && Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT &&
        !Wifi->Ctx->Go.Stopping) {
        if (Wifi->Model.ClientConnectTask.Active)
            Ap6256ClientAttemptResult(Wifi, Up, STATUS_UNSUCCESSFUL);
        else if (!Up && Wifi->Ctx->Go.ClientConnected)
            (VOID) Ap6256CancelClientLocked(Wifi, STATUS_UNSUCCESSFUL, 1);
    }
    Ap6256LockRelease(&Wifi->Model.GroupLock);
}

VOID Ap6256ClientLinkWork(PAP6256_WIFI Wifi, BOOLEAN Up, LONG Generation)
{
    PAP6256_CX_ADAPTER role;
    if (Wifi->Stopping || !Wifi->HardwareAvailable) return;
    role = Ap6256CxAcquireRole(Wifi, AP6256_GROUP_PORT);
    if (!role) return;
    Ap6256CxClientLinkWork(Wifi, Up, Generation);
    ExReleaseRundownProtection(&role->Rundown);
}

static VOID Ap6256CxClientConnectTimeout(PAP6256_WIFI wifi)
{
    Ap6256LockAcquire(&wifi->Model.GroupLock);
    if (wifi->Model.ClientConnectTask.Active && wifi->Model.ClientConnectTask.DeadlineMs != 0 &&
        Ap6256InterruptTimeMs() >= wifi->Model.ClientConnectTask.DeadlineMs)
        (VOID) Ap6256CancelClientLocked(wifi, STATUS_IO_TIMEOUT, 3);
    Ap6256LockRelease(&wifi->Model.GroupLock);
}

static VOID Ap6256OnClientConnectTimeout(PAP6256_WIFI wifi)
{
    PAP6256_CX_ADAPTER role;
    if (wifi->Stopping || !wifi->HardwareAvailable) return;
    role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    if (!role) return;
    Ap6256CxClientConnectTimeout(wifi);
    ExReleaseRundownProtection(&role->Rundown);
}

VOID Ap6256HandleClientConnect(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                               PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength)
{
    WDI_TASK_CONNECT_PARAMETERS p = {0};
    AP6256_CONNECT_PARAMS base = {0};
    NTSTATUS status;
    BOOLEAN open, secure;
    ULONG i;
    LONG bands = InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0);
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);

    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx) {
        status = STATUS_DEVICE_NOT_READY;
        goto complete;
    }
    if (!ctx->Go.Created || !ctx->Go.FirmwareReady ||
        ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_CLIENT) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto complete;
    }

    if (ctx->Go.Started || Wifi->Model.ClientConnectTask.Active || Wifi->ConnectTask.Active) {
        status = STATUS_DEVICE_BUSY;
        goto complete;
    }
    status = Ap6256NdisToNtStatus(ParseWdiTaskConnect(TlvLength, Tlv, &Wifi->TlvContext, &p));
    if (!NT_SUCCESS(status))
        goto complete;
    if (p.ConnectParameters.SSIDList.ElementCount != 1 ||
        p.ConnectParameters.SSIDList.pElements == NULL ||
        p.ConnectParameters.SSIDList.pElements[0].ElementCount == 0 ||
        p.ConnectParameters.SSIDList.pElements[0].ElementCount > sizeof(base.Ssid) ||
        p.ConnectParameters.SSIDList.pElements[0].pElements == NULL ||
        p.PreferredBSSEntryList.ElementCount == 0 || p.PreferredBSSEntryList.pElements == NULL ||
        p.PreferredBSSEntryList.ElementCount > RTL_NUMBER_OF(Wifi->Model.ClientCandidates)) {
        status = STATUS_INVALID_PARAMETER;
        goto complete;
    }
    open =
        Ap6256AlgorithmPresent(&p.ConnectParameters.AuthenticationAlgorithms,
                               WDI_AUTH_ALGO_80211_OPEN) &&
        Ap6256CipherPresent(&p.ConnectParameters.UnicastCipherAlgorithms, WDI_CIPHER_ALGO_NONE) &&
        Ap6256CipherPresent(&p.ConnectParameters.MulticastCipherAlgorithms, WDI_CIPHER_ALGO_NONE);
    secure =
        Ap6256AlgorithmPresent(&p.ConnectParameters.AuthenticationAlgorithms,
                               WDI_AUTH_ALGO_RSNA_PSK) &&
        Ap6256CipherPresent(&p.ConnectParameters.UnicastCipherAlgorithms, WDI_CIPHER_ALGO_CCMP) &&
        Ap6256CipherPresent(&p.ConnectParameters.MulticastCipherAlgorithms, WDI_CIPHER_ALGO_CCMP);
    if ((!open && !secure) || (p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled &&
        (!Wifi->Ctx->HostFipsReady || p.ConnectParameters.ConnectionSettings.MFPEnabled))) {
        status = STATUS_NOT_SUPPORTED;
        goto complete;
    }
    base.SsidLength = p.ConnectParameters.SSIDList.pElements[0].ElementCount;
    RtlCopyMemory(base.Ssid, p.ConnectParameters.SSIDList.pElements[0].pElements, base.SsidLength);
    base.Security = secure ? Ap6256SecurityWpa2Host : Ap6256SecurityOpen;
    base.Mfp = p.ConnectParameters.ConnectionSettings.MFPEnabled ? Ap6256MfpCapable : Ap6256MfpNone;
    base.BssidValid = TRUE;
    base.HostFips = p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled != 0;
    if ((p.ConnectParameters.Optional.AllowedBSSIDs_IsPresent &&
         p.ConnectParameters.AllowedBSSIDs.ElementCount &&
         p.ConnectParameters.AllowedBSSIDs.pElements == NULL) ||
        (p.ConnectParameters.Optional.DisallowedBSSIDs_IsPresent &&
         p.ConnectParameters.DisallowedBSSIDs.ElementCount &&
         p.ConnectParameters.DisallowedBSSIDs.pElements == NULL)) {
        status = STATUS_INVALID_PARAMETER;
        goto complete;
    }
    if (p.ConnectParameters.Optional.UnavailableBandList_IsPresent) {
        if (p.ConnectParameters.UnavailableBandList.ElementCount &&
            p.ConnectParameters.UnavailableBandList.pElements == NULL) {
            status = STATUS_INVALID_PARAMETER;
            goto complete;
        }
        for (i = 0; i < p.ConnectParameters.UnavailableBandList.ElementCount; ++i) {
            WDI_BAND_ID band = p.ConnectParameters.UnavailableBandList.pElements[i];
            if (band == WDI_BAND_ID_2400)
                bands |= AP6256_DISALLOW_BAND_2G;
            if (band == WDI_BAND_ID_5000)
                bands |= AP6256_DISALLOW_BAND_5G;
        }
    }
    if (p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent) {
        status = Ap6256ClientAppendVendorIes(&base,
            p.ConnectParameters.AssociationRequestVendorIE.pElements,
            p.ConnectParameters.AssociationRequestVendorIE.ElementCount);
        if (!NT_SUCCESS(status))
            goto complete;
    }
    Wifi->Model.ClientCandidateCount = 0;
    Wifi->Model.ClientCandidateIndex = 0;
    for (i = 0; i < p.PreferredBSSEntryList.ElementCount; ++i) {
        WDI_CONNECT_BSS_ENTRY_CONTAINER* bss = &p.PreferredBSSEntryList.pElements[i];
        WDI_BAND_ID band =
            bss->ChannelInfo.ChannelNumber <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000;
        if ((bss->ChannelInfo.BandId != WDI_BAND_ID_UNKNOWN && bss->ChannelInfo.BandId != band) ||
            !Ap6256MacIsValidUnicast(bss->BSSID.Address) || Ap6256BandIsMasked(bands, band) ||
            !Ap6256ChannelSupported(band == WDI_BAND_ID_2400 ? Ap6256ScanBand2G : Ap6256ScanBand5G,
                                    bss->ChannelInfo.ChannelNumber))
            continue;
        if (p.ConnectParameters.Optional.DisallowedBSSIDs_IsPresent &&
            Ap6256AddressInList(bss->BSSID.Address, &p.ConnectParameters.DisallowedBSSIDs))
            continue;
        if (p.ConnectParameters.Optional.AllowedBSSIDs_IsPresent &&
            !Ap6256AddressListIsUnrestricted(&p.ConnectParameters.AllowedBSSIDs) &&
            !Ap6256AddressInList(bss->BSSID.Address, &p.ConnectParameters.AllowedBSSIDs))
            continue;
        base.Channel = bss->ChannelInfo.ChannelNumber;
        RtlCopyMemory(base.Bssid, bss->BSSID.Address, 6);
        Wifi->Model.ClientCandidates[Wifi->Model.ClientCandidateCount] = base;
        if (bss->Optional.AssociationRequestVendorIE_IsPresent) {
            status = Ap6256ClientAppendVendorIes(
                &Wifi->Model.ClientCandidates[Wifi->Model.ClientCandidateCount],
                bss->AssociationRequestVendorIE.pElements,
                bss->AssociationRequestVendorIE.ElementCount);
            if (!NT_SUCCESS(status)) {
                Wifi->Model.ClientCandidateCount = 0;
                goto complete;
            }
        }
        status = Ap6256CopyFipsCandidate(bss, &Wifi->Model.ClientCandidates[Wifi->Model.ClientCandidateCount]);
        if (!NT_SUCCESS(status)) goto complete;
        ++Wifi->Model.ClientCandidateCount;
    }
    if (!Wifi->Model.ClientCandidateCount) {
        status = STATUS_NETWORK_UNREACHABLE;
        goto complete;
    }
    status =
        Ap6256BeginTask(Wifi, &Wifi->Model.ClientConnectTask, Header, Ap6256RequestGetId(Request));
    if (!NT_SUCCESS(status))
        goto complete;
    Ap6256SetTaskDeadline(Wifi, &Wifi->Model.ClientConnectTask, AP6256_CONNECT_TIMEOUT_MS);
    CleanupParsedWdiTaskConnect(&p);
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
    AP6256_TIMER_START(Wifi->Model.ClientConnectTimer, AP6256_CONNECT_TIMEOUT_MS);
    status = Ap6256ClientStartAttempt(Wifi);
    if (!NT_SUCCESS(status))
        Ap6256ClientAttemptResult(Wifi, FALSE, status);
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    return;
complete:
    CleanupParsedWdiTaskConnect(&p);
    TraceDiag("P2P client: connect refused 0x%08X\n", status);
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    Ap6256CompleteRequest(Wifi, Request, status);
}

static BOOLEAN Ap6256GoAutoVendorIesMatch(const AP6256_GO_AUTO_ASSOC* Assoc, const UCHAR* Ies,
                                          ULONG Length)
{
    ULONG offset = 0;
    if (!Ap6256P2pVendorIesValid(Ies, Length))
        return FALSE;
    while (offset < Length) {
        ULONG scan = 6, size = (ULONG)Ies[offset + 1] + 2;
        BOOLEAN found = FALSE;
        while (scan + 2 <= Assoc->ResponseLength) {
            ULONG count = (ULONG)Assoc->Response[scan + 1] + 2;
            if (count > Assoc->ResponseLength - scan)
                return FALSE;
            if (count == size && RtlEqualMemory(Assoc->Response + scan, Ies + offset, size)) {
                found = TRUE;
                break;
            }
            scan += count;
        }
        if (!found)
            return FALSE;
        offset += size;
    }
    return TRUE;
}

VOID Ap6256HandleGoAutoResponse(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                const WDI_MESSAGE_HEADER* Header,
                                WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE_PARAMETERS* P,
                                WDI_PHY_TYPE Phy, NTSTATUS ParseStatus)
{
    WDI_MESSAGE_HEADER header = *Header;
    PVOID requestId = Ap6256RequestGetId(Request);
    AP6256_GO_AUTO_ASSOC* assoc = NULL;
    WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE_PARAMETERS p;
    ULONGLONG token = 0;
    ULONG slot, generatedLength = 0;
    UINT8* generated = NULL;
    NTSTATUS status = ParseStatus, delivered;
    BOOLEAN accept = (BOOLEAN)(P->AssocResponseParameters.AcceptRequest != 0);
    UINT16 reason = P->AssocResponseParameters.ReasonCode;
    if (P->IncomingRequestInfo.AssocRequestDeviceContext.ElementCount == sizeof(token) &&
        P->IncomingRequestInfo.AssocRequestDeviceContext.pElements != NULL)
        RtlCopyMemory(&token, P->IncomingRequestInfo.AssocRequestDeviceContext.pElements,
                      sizeof(token));
    if (NT_SUCCESS(status)) {
        for (slot = 0; slot < RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc); ++slot) {
            AP6256_GO_AUTO_ASSOC* candidate = Wifi->Model.GoAutoAssoc[slot];
            if (candidate != NULL && candidate->Token == token &&
                RtlEqualMemory(candidate->Address,
                               P->IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address,
                               6)) {
                assoc = candidate;
                Wifi->Model.GoAutoAssoc[slot] = NULL;
                break;
            }
        }
        if (assoc == NULL)
            status = STATUS_CONNECTION_DISCONNECTED;
    }
    if (!NT_SUCCESS(status)) {
        TraceDiag("hotspot: stale autonomous association decision -> 0x%08X\n", status);
        CleanupParsedWdiTaskSendApAssociationResponse(P);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }
    if (P->IncomingRequestInfo.AssocRequestParams.IsReassociationRequest ||
        P->IncomingRequestInfo.AssocRequestFrame.ElementCount != assoc->RequestLength ||
        P->IncomingRequestInfo.AssocRequestFrame.pElements == NULL ||
        !RtlEqualMemory(P->IncomingRequestInfo.AssocRequestFrame.pElements, assoc->Request,
                        assoc->RequestLength))
        status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(status) &&
        (!accept || (P->Optional.WFDAssociationStatus_IsPresent && P->WFDAssociationStatus != 0)))
        status = STATUS_CONNECTION_REFUSED;
    if (NT_SUCCESS(status) && P->Optional.VendorIEs_IsPresent &&
        !Ap6256GoAutoVendorIesMatch(assoc, P->VendorIEs.pElements, P->VendorIEs.ElementCount)) {
        NTSTATUS templateStatus = Ap6256P2pSetHostIesFor(
            Wifi->Ctx, &Wifi->Ctx->Go.P2p, Wifi->Ctx->Go.IfIndex, Ap6256P2pFrameAssocResponse,
            P->VendorIEs.pElements, P->VendorIEs.ElementCount);
        status = NT_SUCCESS(templateStatus) ? STATUS_NOT_SUPPORTED : templateStatus;
        TraceDiag("hotspot: autonomous response needs new vendor IEs; staged for retry -> 0x%08X\n",
                  status);
    }
    RtlZeroMemory(&p, sizeof(p));
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(p.AssocResponseResult.PeerMACAddress.Address, assoc->Address, 6);
        p.AssocResponseResult.AuthAlgorithm = Wifi->ApSecurity == Ap6256SecurityWpa2Host
                                                  ? WDI_AUTH_ALGO_RSNA_PSK
                                                  : WDI_AUTH_ALGO_80211_OPEN;
        p.AssocResponseResult.UnicastCipherAlgorithm = Wifi->ApSecurity == Ap6256SecurityWpa2Host
                                                           ? WDI_CIPHER_ALGO_CCMP
                                                           : WDI_CIPHER_ALGO_NONE;
        p.AssocResponseResult.MulticastCipherAlgorithm =
            p.AssocResponseResult.UnicastCipherAlgorithm;
        p.AssocResponseFrame.pElements = assoc->Response;
        p.AssocResponseFrame.ElementCount = assoc->ResponseLength;
        p.BeaconIEs.pElements = assoc->Beacon;
        p.BeaconIEs.ElementCount = assoc->BeaconLength;
        TraceDiag("hotspot: association bodies request %u response %u beacon %u interval %u "
                  "capability 0x%04X\n",
                  assoc->RequestLength, assoc->ResponseLength, assoc->BeaconLength,
                  (ULONG)(assoc->Beacon[8] | ((UINT16)assoc->Beacon[9] << 8)),
                  (ULONG)(assoc->Beacon[10] | ((UINT16)assoc->Beacon[11] << 8)));
        p.ActivePhyList.pElements = &Phy;
        p.ActivePhyList.ElementCount = 1;
        status = Ap6256NdisToNtStatus(GenerateWdiIndicationSendApAssociationResponseComplete(
            &p, 0, &Wifi->TlvContext, &generatedLength, &generated));
    }

    CleanupParsedWdiTaskSendApAssociationResponse(P);
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
    if (NT_SUCCESS(status) && (InterlockedCompareExchange(&Wifi->Stopping, 0, 0) != 0 ||
                               InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) == 0))
        status = STATUS_CANCELLED;
    if (NT_SUCCESS(status) &&
        !Ap6256CxGroupPeerCreate(Wifi->Ctx, assoc->Address,
                               Phy == WDI_PHY_TYPE_VHT    ? AP6256_PHY_ID_VHT
                               : Phy == WDI_PHY_TYPE_HT   ? AP6256_PHY_ID_HT
                               : Phy == WDI_PHY_TYPE_OFDM ? AP6256_PHY_ID_OFDM
                                                          : AP6256_PHY_ID_ERP))
        status = STATUS_INSUFFICIENT_RESOURCES;
    delivered = Ap6256SendIndicationRq(Wifi, WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                                       &header, header.TransactionId, requestId, status,
                                       NT_SUCCESS(status) ? generated : NULL,
                                       NT_SUCCESS(status) ? generatedLength : 0);
    TraceDiag("hotspot: autonomous association complete accept %u -> 0x%08X (delivery 0x%08X)\n",
              (ULONG)accept, status, delivered);
    if (NT_SUCCESS(status) && NT_SUCCESS(delivered))
        Ap6256CxGroupRxOpen(Wifi->Ctx, assoc->Address);
    else {
        Ap6256CxGroupPeerDelete(Wifi->Ctx, assoc->Address);
        if (!Wifi->Stopping && Wifi->HardwareAvailable)
            Ap6256GoRejectPeer(Wifi, assoc->Address,
                                  !accept && reason != 0 ? reason : 1);
    }
    FreeGenerated(generated);
    ExFreePoolWithTag(assoc, AP6256_POOL_TAG);
}

VOID Ap6256HandleSendApAssociationResponse(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE_PARAMETERS p;
    UCHAR address[6];
    BOOLEAN accept;
    UINT16 reason;
    NTSTATUS status;
    ULONG offset;
    WDI_PHY_TYPE phy = Wifi->Ctx->Go.Channel > 14 ? WDI_PHY_TYPE_OFDM : WDI_PHY_TYPE_ERP;
    RtlZeroMemory(&p, sizeof(p));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskSendApAssociationResponse(TlvLength, Tlv, &Wifi->TlvContext, &p));
    if (NT_SUCCESS(status) && (Header->PortId != AP6256_GROUP_PORT || !Wifi->ApStarted))
        status = STATUS_INVALID_DEVICE_STATE;
    RtlCopyMemory(address, p.IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address, 6);
    accept = (BOOLEAN)(p.AssocResponseParameters.AcceptRequest != 0);
    reason = p.AssocResponseParameters.ReasonCode;
    if (NT_SUCCESS(status) && !Ap6256MacIsValidUnicast(address))
        status = STATUS_INVALID_PARAMETER;

    offset = p.IncomingRequestInfo.AssocRequestParams.IsReassociationRequest ? 10u : 4u;
    while (p.IncomingRequestInfo.AssocRequestFrame.pElements != NULL &&
           offset + 2 <= p.IncomingRequestInfo.AssocRequestFrame.ElementCount) {
        const UCHAR* ie = p.IncomingRequestInfo.AssocRequestFrame.pElements + offset;
        ULONG size = (ULONG)ie[1] + 2;
        if (size > p.IncomingRequestInfo.AssocRequestFrame.ElementCount - offset)
            break;
        if (ie[0] == 45 && ie[1] >= 26 && phy != WDI_PHY_TYPE_VHT)
            phy = WDI_PHY_TYPE_HT;
        if (ie[0] == 191 && ie[1] >= 12 && Wifi->Ctx->Go.Channel > 14)
            phy = WDI_PHY_TYPE_VHT;
        offset += size;
    }
    if (p.IncomingRequestInfo.Optional.AssocRequestDeviceContext_IsPresent) {
        Ap6256HandleGoAutoResponse(Wifi, Request, Header, &p, phy, status);
        return;
    }

    for (offset = 0; NT_SUCCESS(status) && offset < RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc);
         ++offset) {
        if (Wifi->Model.GoAutoAssoc[offset] != NULL &&
            RtlEqualMemory(Wifi->Model.GoAutoAssoc[offset]->Address, address, 6))
            status = STATUS_INVALID_PARAMETER;
    }
    if (NT_SUCCESS(status) && Wifi->ApAssocTask.Active)
        status = STATUS_DEVICE_BUSY;
    if (NT_SUCCESS(status)) {
        Wifi->Ctx->Go.P2p.AssocStatus =
            p.Optional.WFDAssociationStatus_IsPresent ? p.WFDAssociationStatus : 0;
        status = Ap6256P2pBuildIesFor(Wifi->Ctx, &Wifi->Ctx->Go.P2p, Wifi->Ctx->Go.IfIndex);
        if (NT_SUCCESS(status))
            status = Ap6256P2pSetHostIesFor(
                Wifi->Ctx, &Wifi->Ctx->Go.P2p, Wifi->Ctx->Go.IfIndex, Ap6256P2pFrameAssocResponse,
                p.Optional.VendorIEs_IsPresent ? p.VendorIEs.pElements : NULL,
                p.Optional.VendorIEs_IsPresent ? p.VendorIEs.ElementCount : 0);
    }
    if (NT_SUCCESS(status)) {
        if (Wifi->ApAssocTask.Active)
            status = STATUS_DEVICE_BUSY;
        else {
            AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
            status = Ap6256BeginTask(Wifi, &Wifi->ApAssocTask, Header, Ap6256RequestGetId(Request));
        }
    }
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(Wifi->ApPendingAssocMac, address, 6);
        Wifi->Model.ApAssocAccept = accept;
        Wifi->Model.ApAssocPhy = phy;
        Ap6256SetTaskDeadline(Wifi, &Wifi->ApAssocTask, 1500);
    }
    CleanupParsedWdiTaskSendApAssociationResponse(&p);
    Ap6256CompleteRequest(Wifi, Request, status);
    if (!NT_SUCCESS(status))
        return;
    AP6256_TIMER_START(Wifi->Model.ApAssocTimer, 1500);
    status =
        Ap6256WifiSendAssocDecisionIf(Wifi->Ctx, Wifi->Ctx->Go.IfIndex, address, accept, reason);
    if (!NT_SUCCESS(status)) {
        AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
        Ap6256FailStartedTask(Wifi, &Wifi->ApAssocTask,
                              WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE, status);
    }
}

NTSTATUS Ap6256ModelChangeGroupMode(PAP6256_WIFI Wifi, UINT32 wdiMode)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);

    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx)
        status = STATUS_DEVICE_NOT_READY;
    else if (Wifi->Ctx->Go.NativeStateUncertain)
        status = STATUS_DEVICE_HARDWARE_ERROR;
    else {
        if (!Wifi->Model.ClientConnectTask.Active && !Wifi->Ctx->Go.Started && Wifi->Ctx->Go.Created)
            Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
        status = Wifi->Model.ClientConnectTask.Active ? STATUS_DEVICE_BUSY
                                                      : Ap6256GroupChangeMode(Wifi->Ctx, wdiMode);
        if (NT_SUCCESS(status))
            InterlockedIncrement(&Wifi->Model.GroupGeneration);
        else if (Wifi->Ctx->Go.NativeStateUncertain) {

            Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
            if (Wifi->HardwareAvailable) Ap6256NetFirmwareHalted(Wifi->Ctx);
        }
    }
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    return status;
}

VOID Ap6256ModelChangeGroupModeCompleted(PAP6256_WIFI Wifi, UINT32 PreviousMode,
                                       NTSTATUS CompletionStatus)
{
    NTSTATUS rollbackStatus;
    if (NT_SUCCESS(CompletionStatus)) return;

    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx ||
        Wifi->Ctx->Go.NativeStateUncertain)
        rollbackStatus = STATUS_DEVICE_NOT_READY;
    else
        rollbackStatus = Ap6256GroupChangeMode(Wifi->Ctx, PreviousMode);
    if (NT_SUCCESS(rollbackStatus)) {
        InterlockedIncrement(&Wifi->Model.GroupGeneration);
        Ap6256RecomputePortModes(Wifi);
    } else {
        Wifi->Ctx->Go.NativeStateUncertain = TRUE;
        if (Wifi->HardwareAvailable) Ap6256NetFirmwareHalted(Wifi->Ctx);
    }
    Ap6256LockRelease(&Wifi->Model.GroupLock);
}

BOOLEAN Ap6256ModelConnectPort(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                               PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength,
                               BOOLEAN isRoam)
{

    if (Header->PortId == AP6256_GROUP_PORT && !isRoam) {
        Ap6256HandleClientConnect(Wifi, Request, Header, Tlv, TlvLength);
        return TRUE;
    }
    if (Header->PortId != AP6256_STATION_PORT) {
        Ap6256CompleteRequest(Wifi, Request, STATUS_INVALID_DEVICE_STATE);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN Ap6256ModelDisconnectPort(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                  PWDI_MESSAGE_HEADER Header,
                                  WDI_TASK_DISCONNECT_PARAMETERS* parameters, NTSTATUS status)
{

    if (NT_SUCCESS(status) && Header->PortId == AP6256_GROUP_PORT) {
        WDI_MESSAGE_HEADER completedHeader = *Header;
        PVOID requestId = Ap6256RequestGetId(Request);
        UCHAR address[6];
        UINT16 reason = parameters->DisconnectParameters.Disassociation80211Reason;
        RtlCopyMemory(address, parameters->DisconnectParameters.MacAddress.Address, 6);
        TraceDiag("hotspot: Windows requested disconnect %02X:%02X:%02X:%02X:%02X:%02X reason %u "
                  "mode 0x%X\n",
                  address[0], address[1], address[2], address[3], address[4], address[5],
                  (ULONG)reason, Wifi->Ctx->Go.Mode);
        status = Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT
                     ? Ap6256CancelClient(Wifi, STATUS_CANCELLED, reason)
                     : Ap6256GoDisconnectPeer(Wifi->Ctx, address, reason);
        CleanupParsedWdiTaskDisconnect(parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        if (NT_SUCCESS(status)) {

            (VOID)
                Ap6256SendIndicationRq(Wifi, WDI_INDICATION_DISCONNECT_COMPLETE, &completedHeader,
                                       completedHeader.TransactionId, requestId, status, NULL, 0);
        }
        return TRUE;
    }
    return FALSE;
}

VOID Ap6256ModelDeleteGroup(PAP6256_WIFI Wifi)
{

    (VOID) Ap6256CancelClient(Wifi, STATUS_CANCELLED, 3);
    Ap6256CancelGoAssociation(Wifi, STATUS_CANCELLED);
    Ap6256CxGroupPeerDelete(Wifi->Ctx, NULL);
}

VOID Ap6256ModelResetGroupPeers(PAP6256_WIFI Wifi)
{

    Ap6256CancelGoAssociation(Wifi, STATUS_CANCELLED);
    Ap6256CxGroupPeerDelete(Wifi->Ctx, NULL);
}

static NTSTATUS Ap6256CxStopGoChecked(PAP6256_WIFI Wifi)
{
    NTSTATUS status = Ap6256GoStop(Wifi->Ctx);
    if (!NT_SUCCESS(status)) {
        Wifi->Ctx->Go.NativeStateUncertain = TRUE;
        if (Wifi->HardwareAvailable) Ap6256NetFirmwareHalted(Wifi->Ctx);
    }
    return status;
}

NTSTATUS Ap6256ModelResetGroup(PAP6256_WIFI Wifi)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx)
        status = STATUS_DEVICE_NOT_READY;
    else if (Wifi->Ctx->Go.NativeStateUncertain)
        status = STATUS_DEVICE_HARDWARE_ERROR;
    else
        status = Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT
                     ? Ap6256CancelClientLocked(Wifi, STATUS_CANCELLED, 3)
                     : Ap6256CxStopGoChecked(Wifi);
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    return status;
}

NTSTATUS Ap6256ModelResetGroupAddress(PAP6256_WIFI Wifi, const UCHAR* Address)
{
    UCHAR previous[6];
    NTSTATUS status;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx) {
        status = STATUS_DEVICE_NOT_READY;
        goto done;
    }
    if (Wifi->Ctx->Go.NativeStateUncertain) {
        status = STATUS_DEVICE_HARDWARE_ERROR;
        goto done;
    }
    RtlCopyMemory(previous, Wifi->Ctx->Go.Address, sizeof(previous));
    status = Ap6256GoDelete(Wifi->Ctx);
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(Wifi->Ctx->Go.Address, Address, sizeof(previous));
        status = Ap6256GoCreate(Wifi->Ctx);
        if (NT_SUCCESS(status))
            Ap6256ModelGroupAddressChanged(Wifi);
        else
            RtlCopyMemory(Wifi->Ctx->Go.Address, previous, sizeof(previous));
    }
    if (!NT_SUCCESS(status)) {

        Wifi->Ctx->Go.NativeStateUncertain = TRUE;
        if (Wifi->HardwareAvailable) Ap6256NetFirmwareHalted(Wifi->Ctx);
    }
done:
    Ap6256LockRelease(&Wifi->Model.GroupLock);
    return status;
}

VOID Ap6256ModelStopApPeers(PAP6256_WIFI Wifi, NTSTATUS status)
{

    if (NT_SUCCESS(status)) {
        Ap6256CancelGoAssociation(Wifi, STATUS_CANCELLED);
        Ap6256CxGroupPeerDelete(Wifi->Ctx, NULL);
    }
}

BOOLEAN Ap6256ModelGroupConnecting(PAP6256_WIFI Wifi)
{

    return Wifi->Model.ClientConnectTask.Active;
}

VOID Ap6256ModelApStarted(PAP6256_WIFI Wifi, NTSTATUS status)
{

    if (NT_SUCCESS(status)) {
        Wifi->Model.GoNativeAssociation = FALSE;
        Ap6256CxSetRoleLink(Wifi, AP6256_GROUP_PORT, TRUE);
    }
}

NTSTATUS Ap6256ModelStartApBegin(PAP6256_WIFI Wifi)
{
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx) {
        Ap6256LockRelease(&Wifi->Model.GroupLock);
        return STATUS_DEVICE_NOT_READY;
    }
    if (Wifi->Ctx->Go.NativeStateUncertain) {
        Ap6256LockRelease(&Wifi->Model.GroupLock);
        return STATUS_DEVICE_HARDWARE_ERROR;
    }
    return STATUS_SUCCESS;
}

VOID Ap6256ModelStartApEnd(PAP6256_WIFI Wifi)
{
    Ap6256LockRelease(&Wifi->Model.GroupLock);
}

NTSTATUS Ap6256ModelStartApHardware(PAP6256_WIFI Wifi, PAP6256_AP_PARAMS Params)
{
    NTSTATUS status = Ap6256GoStart(Wifi->Ctx, Params);
    if (!NT_SUCCESS(status)) (VOID) Ap6256CxStopGoChecked(Wifi);
    return status;
}

VOID Ap6256ModelStartApCompleted(PAP6256_WIFI Wifi, NTSTATUS StartStatus, NTSTATUS CompletionStatus)
{
    if (NT_SUCCESS(StartStatus) && !NT_SUCCESS(CompletionStatus)) {

        Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
        (VOID) Ap6256CxStopGoChecked(Wifi);
        Ap6256ModelApStopped(Wifi, Wifi->Ctx);
        Wifi->ApStarted = FALSE;
    }
}

NTSTATUS Ap6256ModelStartApPeer(PAP6256_WIFI Wifi, NTSTATUS status)
{

    if (NT_SUCCESS(status)) {
        const UCHAR multicast[6] = {255, 255, 255, 255, 255, 255};
        if (!Ap6256CxGroupPeerCreate(Wifi->Ctx, multicast, 0)) {
            (VOID) Ap6256CxStopGoChecked(Wifi);
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return status;
}

NTSTATUS Ap6256ModelStartInterfaces(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx)
{

    NTSTATUS status = STATUS_SUCCESS;
    if (Ctx->Go.NativeStateUncertain) return STATUS_DEVICE_HARDWARE_ERROR;
    if (Wifi->P2pPortCreated) {
        status = Ap6256WifiP2pSetDiscoveryInterface(Ctx, TRUE, NULL);
        if (!NT_SUCCESS(status))
            return status;
    }
    if (Ctx->Go.Created) {
        status = Ap6256GoCreate(Ctx);
        if (!NT_SUCCESS(status))
            return status;
        Ap6256ModelGroupAddressChanged(Wifi);
    }
    return status;
}

VOID Ap6256ModelStampLinkEvent(PAP6256_WIFI Wifi, UCHAR Code)
{

    if (Code == AP6256_LINK_CLIENT_UP || Code == AP6256_LINK_CLIENT_DOWN)
        Wifi->LinkGenerations[Wifi->LinkHead & (AP6256_LINKQ_DEPTH - 1)] =
            InterlockedCompareExchange(&Wifi->Model.GroupGeneration, 0, 0);
}

VOID Ap6256ModelApStopped(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx)
{

    Ap6256ClearGoEvents(Wifi);
    Ap6256ForgetGoAutoAssoc(Wifi, NULL);
    Ap6256CxGroupPeerDelete(Ctx, NULL);
    AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, FALSE);
    Ap6256FailStartedTask(Wifi, &Wifi->ApAssocTask,
                          WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                          STATUS_CONNECTION_DISCONNECTED);
}

BOOLEAN Ap6256ModelClientLinkEvent(PAP6256_WIFI Wifi, UCHAR code, LONG generation)
{

    if (code == AP6256_LINK_CLIENT_UP || code == AP6256_LINK_CLIENT_DOWN) {
        Ap6256ClientLinkWork(Wifi, code == AP6256_LINK_CLIENT_UP, generation);
        return TRUE;
    }
    return FALSE;
}

BOOLEAN Ap6256ModelTakeCommandEvent(PAP6256_WIFI Wifi, PVOID* Event, BOOLEAN* Lost)
{
    *Lost = Wifi->Model.GoEventsLost;
    if (*Lost) return TRUE;
    if (Wifi->Model.GoEventTail == Wifi->Model.GoEventHead) return FALSE;
    *Event = Wifi->Model.GoEvents[Wifi->Model.GoEventTail++ % AP6256_GO_EVENT_DEPTH];
    return TRUE;
}

VOID Ap6256ModelProcessCommandEvent(PAP6256_WIFI wifi, PVOID Event, BOOLEAN lost)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    if (role && !wifi->Stopping && wifi->HardwareAvailable) {
        if (lost) {
            TraceDiag("hotspot: GO event queue lost state; stopping AP\n");
            NTSTATUS status;
            Ap6256ClearGoEvents(wifi);
            status = Ap6256GoStop(wifi->Ctx);
            if (!NT_SUCCESS(status)) {

                wifi->Ctx->Go.NativeStateUncertain = TRUE;
                Ap6256NetFirmwareHalted(wifi->Ctx);
            }
            Ap6256NetApStopped(wifi->Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
        } else if (Event != NULL) Ap6256ProcessGoEvent(wifi, Event);
    } else if (lost) Ap6256ClearGoEvents(wifi);
    if (role) ExReleaseRundownProtection(&role->Rundown);
    if (Event != NULL) ExFreePoolWithTag(Event, AP6256_POOL_TAG);
}
