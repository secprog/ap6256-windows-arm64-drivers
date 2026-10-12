/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"
#include "host_cipher_transport.h"
#include "capability_tables.h"

_Use_decl_annotations_
VOID Ap6256NetFirmwareHalted(PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER header;
    NDIS_STATUS_INDICATION indication;
    if (wifi == NULL || wifi->Stopping) return;
    InterlockedExchange(&wifi->HardwareAvailable, 0);

    RtlZeroMemory(&header, sizeof(header));
    header.PortId = 0xffff;
    header.Status = NDIS_STATUS_SUCCESS;
    RtlZeroMemory(&indication, sizeof(indication));
    indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    indication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;
    indication.SourceHandle = Ctx->MiniportHandle;
    indication.StatusCode = NDIS_STATUS_WDI_INDICATION_FIRMWARE_STALLED;
    indication.StatusBuffer = &header;
    indication.StatusBufferSize = sizeof(header);
    TraceDiag("firmware stalled: indicating adapter port 65535 for Windows reset recovery\n");
    NdisMIndicateStatusEx(Ctx->MiniportHandle, &indication);
}

static AP6256_WORKITEM_ROUTINE Ap6256CommandWorker;
static AP6256_WORKITEM_ROUTINE Ap6256ActionFrameCompleteWorker;
static AP6256_WORKITEM_ROUTINE Ap6256EvtScanTimeout;
static AP6256_WORKITEM_ROUTINE Ap6256EvtConnectTimeout;
static AP6256_WORKITEM_ROUTINE Ap6256EvtDisconnectTimeout;
static AP6256_WORKITEM_ROUTINE Ap6256EvtActionFrameTimeout;
static AP6256_WORKITEM_ROUTINE Ap6256EvtP2pDiscoverTick;
static AP6256_WORKITEM_ROUTINE Ap6256EvtP2pListenTick;
static AP6256_WORKITEM_ROUTINE Ap6256EvtFtmTick;

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_reads_bytes_(Length) PUCHAR Frame,
                                                            _In_ ULONG Length, _In_ UCHAR Priority,
                                                            _In_ UINT32 IfIndex);
static VOID Ap6256GoAutoAssociation(PAP6256_WIFI Wifi, const UCHAR* Address, const UCHAR* Ies,
                                    ULONG Length);
static VOID Ap6256GoIndicateDisassociation(PAP6256_WIFI Wifi, const UCHAR* Address, UINT16 Reason);
static VOID Ap6256EvtApAssocTimeout(PVOID Context);
static VOID Ap6256ProcessGoEvent(PAP6256_WIFI wifi, const AP6256_GO_EVENT* Event);
static VOID Ap6256ActionFrameCompleteWorker(_In_ PVOID Context);
static VOID Ap6256LinkWorker(_In_ PVOID Context);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetHardwareStop(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ NTSTATUS CompletionStatus,
                                                              _In_ BOOLEAN OnCommandWorker);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetTxKick(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)

static BOOLEAN
Ap6256ClientAssociation(PAP6256_WIFI Wifi, const WDI_MESSAGE_HEADER* Header, PVOID RequestId,
                        BOOLEAN Success);
static VOID Ap6256ClientLinkState(PAP6256_WIFI Wifi);
static NTSTATUS Ap6256ClientStartAttempt(PAP6256_WIFI Wifi);
static VOID Ap6256ClientAttemptResult(PAP6256_WIFI Wifi, BOOLEAN Up, NTSTATUS FailureStatus);
static VOID Ap6256EvtClientConnectTimeout(PVOID Context);
_IRQL_requires_max_(PASSIVE_LEVEL)
static UINT32 Ap6256WakeReasonCode(_In_ UINT32 FirmwareStatus,
                                                                      _In_ BOOLEAN PacketValid);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256IndicateWakeReason(_In_ PAP6256_WIFI Wifi, _In_ UINT32 FirmwareStatus,
                         _In_ const AP6256_WAKE_PACKET* Packet, _In_ BOOLEAN PacketValid);
_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256PowerSleepIsHot(_In_ PAP6256_WIFI Wifi);
static BOOLEAN Ap6256GoAutoVendorIesMatch(const AP6256_GO_AUTO_ASSOC* Assoc, const UCHAR* Ies,
                                          ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)

static VOID
Ap6256FillBandInfo(_Out_ WDI_BAND_INFO_CONTAINER* Band, _In_ WDI_BAND_ID BandId,
                   _In_reads_(PhyCount) const WDI_PHY_TYPE* Phys, _In_ ULONG PhyCount,
                   _In_reads_(ChannelCount) const WDI_CHANNEL_MAPPING_ENTRY* Channels,
                   _In_ ULONG ChannelCount, _In_reads_(WidthCount) const UINT32* Widths,
                   _In_ ULONG WidthCount);
static VOID Ap6256FillPhyInfo(_Out_ WDI_PHY_INFO_CONTAINER* Phy, _In_ WDI_PHY_TYPE PhyType,
                              _Out_writes_(RateCount) WDI_DATA_RATE_LIST* Rates,
                              _In_reads_(RateCount) const UINT16* RateValues, _In_ ULONG RateCount);
static VOID Ap6256CompleteQuery(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                _In_ NDIS_STATUS GenerateStatus, _In_opt_ UINT8* Generated,
                                _In_ ULONG GeneratedLength, _In_ PCSTR What);
static VOID Ap6256CommandWorker(_In_ PVOID Context);
_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
Ap6256NetWdiOidRequest(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PNDIS_OID_REQUEST OidRequest);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetWdiCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetWdiDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx);
static VOID Ap6256EvtScanTimeout(_In_ PVOID Context);
static VOID Ap6256EvtConnectTimeout(_In_ PVOID Context);
static VOID Ap6256EvtDisconnectTimeout(_In_ PVOID Context);
static VOID Ap6256EvtActionFrameTimeout(_In_ PVOID Context);
static VOID Ap6256EvtP2pDiscoverTick(_In_ PVOID Context);
static VOID Ap6256EvtP2pListenTick(PVOID Context);

#define AP6256_WDI_POWER_D0 0x00000001u
#define AP6256_WDI_POWER_D2 0x00000003u
#define AP6256_WDI_POWER_D3 0x00000004u

PVOID Ap6256RequestGetId(_In_ AP6256_REQUEST Request)
{
    return Request != NULL ? Request->RequestId : NULL;
}

PAP6256_WIFI Ap6256WifiFromDevice(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    return (PAP6256_WIFI)InterlockedCompareExchangePointer((PVOID volatile*)&Ctx->NetAdapter, NULL,
                                                           NULL);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256CompleteRequest(_In_opt_ PAP6256_WIFI Wifi,
                                                               _In_ AP6256_REQUEST Request,
                                                               _In_ NTSTATUS Status)
{
    PWDI_MESSAGE_HEADER header;
    NDIS_STATUS ndisStatus = Ap6256NtToNdisStatus(Status);
    const ULONG oid = (ULONG)Request->DATA.METHOD_INFORMATION.Oid;

    if (Wifi == NULL) {

        NT_ASSERT(FALSE);
        return;
    }

    header = (PWDI_MESSAGE_HEADER)Request->DATA.METHOD_INFORMATION.InformationBuffer;
    if (header != NULL && Request->DATA.METHOD_INFORMATION.OutputBufferLength >= sizeof(*header)) {
        header->Status = ndisStatus;
        if (Request->DATA.METHOD_INFORMATION.BytesWritten < sizeof(*header)) {
            Request->DATA.METHOD_INFORMATION.BytesWritten = sizeof(*header);
        }
    } else {
        Request->DATA.METHOD_INFORMATION.BytesWritten = 0;
        Request->DATA.METHOD_INFORMATION.BytesNeeded = sizeof(*header);
    }

    TraceVerbose(TRACE_NETADAPTER, "WDI M3 OID 0x%08X status 0x%08X\n", oid, ndisStatus);
    if (Request->MiniportReserved[0])
        NdisMDirectOidRequestComplete(Wifi->Ctx->MiniportHandle, Request, ndisStatus);
    else
        NdisMOidRequestComplete(Wifi->Ctx->MiniportHandle, Request, ndisStatus);

    TraceVerbose(TRACE_NETADAPTER, "WDI M3 returned OID 0x%08X\n", oid);
}

NTSTATUS Ap6256SendIndicationRq(_In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId,
                                _In_ const WDI_MESSAGE_HEADER* OriginalHeader,
                                _In_ UINT32 TransactionId, _In_opt_ PVOID RequestId,
                                _In_ NTSTATUS CompletionStatus,
                                _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv,
                                _In_ ULONG TlvLength)
{
    PUCHAR buffer;
    PWDI_MESSAGE_HEADER header;
    SIZE_T total;
    NDIS_STATUS_INDICATION indication;

    if (OriginalHeader == NULL || TlvLength > MAXULONG - sizeof(WDI_MESSAGE_HEADER) ||
        (TlvLength != 0 && Tlv == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    total = sizeof(WDI_MESSAGE_HEADER) + (SIZE_T)TlvLength;

    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, AP6256_POOL_TAG);
    if (buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(buffer, total);
    header = (PWDI_MESSAGE_HEADER)buffer;
    header->PortId = OriginalHeader->PortId;
    header->Reserved = OriginalHeader->Reserved;
    header->Status = Ap6256NtToNdisStatus(CompletionStatus);
    header->TransactionId = TransactionId;
    header->IhvSpecificId = OriginalHeader->IhvSpecificId;
    if (TlvLength != 0) {
        RtlCopyMemory(buffer + sizeof(*header), Tlv, TlvLength);
    }

    RtlZeroMemory(&indication, sizeof(indication));
    indication.Header.Type = NDIS_OBJECT_TYPE_STATUS_INDICATION;
    indication.Header.Revision = NDIS_STATUS_INDICATION_REVISION_1;
    indication.Header.Size = NDIS_SIZEOF_STATUS_INDICATION_REVISION_1;

    indication.RequestId = RequestId;
    indication.SourceHandle = Wifi->Ctx->MiniportHandle;
    indication.PortNumber = 0;
    indication.StatusCode = WDI_DEFINE_INDICATION(MessageId);
    indication.StatusBuffer = buffer;
    indication.StatusBufferSize = (ULONG)total;

    TraceVerbose(TRACE_NETADAPTER,
                 "--> %s (id %u) status 0x%08X txn %u port %u, %u TLV byte(s), "
                 "requestId %p\n",
                 Ap6256IndicationName(MessageId), (ULONG)MessageId, header->Status, TransactionId,
                 (ULONG)header->PortId, TlvLength, RequestId);

    NdisMIndicateStatusEx(Wifi->Ctx->MiniportHandle, &indication);
    TraceVerbose(TRACE_NETADAPTER, "WDI indication returned id %u txn %u\n", (ULONG)MessageId,
                 TransactionId);
    ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256WdiRxFlush(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_reads_bytes_(Length) PUCHAR Frame,
                                                            _In_ ULONG Length, _In_ UCHAR Priority,
                                                            _In_ UINT32 IfIndex)
{

    Ap6256WdiRxIndicate(Ctx, Frame, Length, Priority, IfIndex);
}

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
    Ap6256TalGoPeerDelete(Wifi->Ctx, Address);
    for (slot = 0; slot < RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc); ++slot)
        if (Wifi->Model.GoAutoAssoc[slot] == NULL)
            break;
    if (slot == RTL_NUMBER_OF(Wifi->Model.GoAutoAssoc) || Length == 0 ||
        Length > AP6256_GO_ASSOC_IE_MAX || !Ap6256GoIesValid(Ies, Length)) {
        (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, Address, 1);
        TraceDiag("hotspot: autonomous association rejected: slots/IE data\n");
        return;
    }
    if (!Ap6256GoAssociationAllowed(&Wifi->GoApParams, Ies, Length)) {

        (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, Address, 1);
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
            (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, Address, 1);
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
    Ap6256TalGoPeerDelete(Wifi->Ctx, Address);
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

static VOID Ap6256EvtApAssocTimeout(PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
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
        (VOID) Ap6256GoDisconnectPeer(wifi->Ctx, address, 1);
        Ap6256TalGoPeerDelete(wifi->Ctx, address);
        TraceDiag("hotspot: association response timed out\n");
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                                      &header, header.TransactionId, requestId, STATUS_IO_TIMEOUT,
                                      NULL, 0);
    }
}

_Use_decl_annotations_
VOID Ap6256NetGoEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
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
        NTSTATUS status = STATUS_UNSUCCESSFUL;
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
                !Ap6256TalGoPeerCreate(Ctx, Address,
                                       phy == WDI_PHY_TYPE_VHT    ? AP6256_PHY_ID_VHT
                                       : phy == WDI_PHY_TYPE_HT   ? AP6256_PHY_ID_HT
                                       : phy == WDI_PHY_TYPE_OFDM ? AP6256_PHY_ID_OFDM
                                                                  : AP6256_PHY_ID_ERP))
                status = STATUS_INSUFFICIENT_RESOURCES;
        } else if (Status == 0) {
            status = STATUS_INVALID_BUFFER_SIZE;
        }
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                                      &header, header.TransactionId, requestId, status,
                                      NT_SUCCESS(status) ? generated : NULL,
                                      NT_SUCCESS(status) ? length : 0);
        if (NT_SUCCESS(status) && accepted)
            Ap6256TalGoRxOpen(Ctx, Address);
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

static VOID Ap6256ActionFrameCompleteWorker(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    KIRQL irql;
    if (wifi == NULL || wifi->Ctx == NULL)
        return;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (wifi->ActionFrameEventDraining) {
        KeReleaseSpinLock(&wifi->CommandLock, irql);
        return;
    }
    wifi->ActionFrameEventDraining = TRUE;
    for (;;) {
        AP6256_ACTION_TX_EVENT event;
        if (wifi->ActionFrameEventOverflow) {
            event.PacketId = wifi->ActionFrameOverflowPacketId;
            event.Status = 0xffffffffu;
            wifi->ActionFrameEventOverflow = FALSE;
        } else if (wifi->ActionFrameEventCount != 0) {
            event = wifi->ActionFrameEvents[wifi->ActionFrameEventHead];
            wifi->ActionFrameEventHead =
                (wifi->ActionFrameEventHead + 1u) % AP6256_ACTION_EVENT_COUNT;
            wifi->ActionFrameEventCount--;
        } else {
            wifi->ActionFrameEventDraining = FALSE;
            KeReleaseSpinLock(&wifi->CommandLock, irql);
            return;
        }
        KeReleaseSpinLock(&wifi->CommandLock, irql);
        Ap6256NetActionFrameComplete(wifi->Ctx, event.PacketId, event.Status);
        KeAcquireSpinLock(&wifi->CommandLock, &irql);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)

static VOID Ap6256LinkWorker(_In_ PVOID Context)
{
    Ap6256LinkWork((PAP6256_WIFI)Context);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetHardwareStop(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ NTSTATUS CompletionStatus,
                                                              _In_ BOOLEAN OnCommandWorker)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER scanHeader;
    WDI_MESSAGE_HEADER connectHeader;
    WDI_MESSAGE_HEADER disconnectHeader;
    WDI_MESSAGE_HEADER indicationHeader;
    PVOID scanRequestId;
    PVOID connectRequestId;
    PVOID disconnectRequestId;
    BOOLEAN scanPending;
    BOOLEAN connectPending;
    BOOLEAN disconnectPending;
    BOOLEAN hadConnection;
    KIRQL oldIrql;

    if (wifi == NULL)
        return;
    InterlockedExchange(&wifi->HardwareAvailable, 0);
    RtlZeroMemory(wifi->ArpOffloadValid, sizeof(wifi->ArpOffloadValid));
    RtlZeroMemory(wifi->ArpOffloadIds, sizeof(wifi->ArpOffloadIds));
    RtlZeroMemory(wifi->ArpOffloads, sizeof(wifi->ArpOffloads));
    RtlZeroMemory(wifi->NsOffloads, sizeof(wifi->NsOffloads));
    wifi->NsOffloadCount = 0;
    wifi->GtkOffloadValid = FALSE;
    wifi->GtkOffloadId = 0;
    RtlSecureZeroMemory(&wifi->GtkOffload, sizeof(wifi->GtkOffload));
    RtlZeroMemory(&scanHeader, sizeof(scanHeader));
    RtlZeroMemory(&connectHeader, sizeof(connectHeader));
    RtlZeroMemory(&disconnectHeader, sizeof(disconnectHeader));
    RtlZeroMemory(&indicationHeader, sizeof(indicationHeader));

    Ap6256WorkItemFlush(&wifi->LinkWorkItem);
    if (!OnCommandWorker) {
        Ap6256WorkItemFlush(&wifi->CommandWorkItem);
    }

    Ap6256CancelActionFrame(wifi, CompletionStatus);
    (VOID)Ap6256FtmCancel(wifi,FALSE,0,0,CompletionStatus);
    AP6256_TIMER_STOP(wifi->P2pDiscoverTimer, TRUE);
    AP6256_TIMER_STOP(wifi->P2pListenTimer, TRUE);
    Ap6256LockAcquire(&wifi->P2pLock);
    Ap6256ServiceStop(wifi, TRUE);
    wifi->P2pDiscovering = FALSE;
    wifi->Ctx->P2p.Listening = FALSE;
    wifi->Ctx->P2p.DiscoverPhase = Ap6256P2pDiscoverIdle;
    InterlockedExchange(&wifi->Ctx->P2p.DiscoverScanPending, 0);
    AP6256_TIMER_STOP(wifi->P2pListenTimer, FALSE);
    AP6256_TIMER_STOP(wifi->P2pDiscoverTimer, FALSE);
    Ap6256LockRelease(&wifi->P2pLock);
    Ap6256StationAuthStop(wifi);
    Ap6256MboReset(wifi);
    AP6256_TIMER_STOP(wifi->ScanTimer, TRUE);
    AP6256_TIMER_STOP(wifi->ConnectTimer, TRUE);
    AP6256_TIMER_STOP(wifi->DisconnectTimer, TRUE);

    AP6256_TIMER_STOP(wifi->Model.ClientConnectTimer, TRUE);
    (VOID) Ap6256CancelClient(wifi, CompletionStatus, 3);
    Ap6256CancelGoAssociation(wifi, CompletionStatus);
    if (wifi->ApStarted)
        Ap6256NetApStopped(Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
    Ap6256TalGoPeerDelete(Ctx, NULL);
    Ap6256P2pReleaseIesFor(Ctx, &Ctx->Go.P2p, Ctx->Go.IfIndex);
    Ap6256P2pReleaseIes(Ctx);
    (VOID) Ap6256GoDelete(Ctx);
    Ap6256P2pForgetIesFor(&Ctx->Go.P2p);
    Ap6256P2pForgetIesFor(&Ctx->P2p);
    wifi->ApStarted = FALSE;
    Ap6256FailStartedTask(wifi, &wifi->P2pDiscoverTask, WDI_INDICATION_P2P_DISCOVERY_COMPLETE,
                          CompletionStatus);
    scanPending = Ap6256ClaimTask(wifi, &wifi->ScanTask, &scanHeader, &scanRequestId);
    connectPending = Ap6256ClaimConnectTask(wifi, Ap6256ConnectClaimAny, 0, 0, &connectHeader,
                                            &connectRequestId);
    disconnectPending =
        Ap6256ClaimTask(wifi, &wifi->DisconnectTask, &disconnectHeader, &disconnectRequestId);

    KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
    indicationHeader = wifi->IndicationHeader;
    hadConnection = wifi->ConnectionActive;
    wifi->ConnectionActive = FALSE;
    KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

    Ap6256FlushSoftwareQueues(wifi);

    if (scanPending) {
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SCAN_COMPLETE, &scanHeader,
                                      scanHeader.TransactionId, scanRequestId, CompletionStatus,
                                      NULL, 0);
    }
    if (connectPending) {
        Ap6256IndicateAssociation(wifi, &connectHeader, connectRequestId, FALSE);
        (VOID) Ap6256SendIndicationRq(wifi, Ap6256ConnectCompletionId(wifi), &connectHeader,
                                      connectHeader.TransactionId, connectRequestId,
                                      CompletionStatus, NULL, 0);
    }
    if (disconnectPending) {
        Ap6256IndicateDisassociation(wifi, &disconnectHeader);
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_DISCONNECT_COMPLETE, &disconnectHeader,
                                      disconnectHeader.TransactionId, disconnectRequestId,
                                      CompletionStatus, NULL, 0);
    } else if (hadConnection && !connectPending) {
        Ap6256IndicateDisassociation(wifi, &indicationHeader);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetTxKick(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256WlfcKick(Ctx);

    Ap6256WdiTxResume(Ctx);
}

NTSTATUS Ap6256GetRequestView(_In_ AP6256_REQUEST Request, _Out_ PWDI_MESSAGE_HEADER* Header,
                              _Outptr_result_bytebuffer_(*TlvLength) const UCHAR** Tlv,
                              _Out_ PULONG TlvLength)
{
    ULONG inputLength = Request->DATA.METHOD_INFORMATION.InputBufferLength;
    PUCHAR buffer = (PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer;
    if (buffer == NULL || inputLength < sizeof(WDI_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Header = (PWDI_MESSAGE_HEADER)buffer;
    *Tlv = buffer + sizeof(WDI_MESSAGE_HEADER);
    *TlvLength = inputLength - sizeof(WDI_MESSAGE_HEADER);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)

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
    if (!Ap6256TalGoPeerCreate(ctx, p->Bssid,
                               p->Channel <= 14 ? AP6256_PHY_ID_HT : AP6256_PHY_ID_VHT))
        return STATUS_INSUFFICIENT_RESOURCES;
    {
        NTSTATUS status = Ap6256QuiesceP2pListen(Wifi);
        return NT_SUCCESS(status) ? Ap6256ClientConnect(ctx, p) : status;
    }
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
            (VOID) Ap6256SendIndicationRq(Wifi, WDI_INDICATION_CONNECT_COMPLETE, &header,
                                          header.TransactionId, requestId, STATUS_SUCCESS, NULL, 0);
            Ap6256TalGoRxOpen(ctx, ctx->Go.ClientBssid);
            Ap6256ClientLinkState(Wifi);
            return;
        }
        InterlockedIncrement(&Wifi->Model.GroupGeneration);
        if (!NT_SUCCESS(Ap6256ClientDisconnect(ctx, 3))) {
            FailureStatus = STATUS_IO_DEVICE_ERROR;
            Wifi->Model.ClientCandidateIndex = Wifi->Model.ClientCandidateCount;
        }
        Ap6256TalGoPeerDelete(ctx, NULL);
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
    InterlockedIncrement(&Wifi->Model.GroupGeneration);
    AP6256_TIMER_STOP(Wifi->Model.ClientConnectTimer, FALSE);
    pending = Ap6256ClaimTask(Wifi, &Wifi->Model.ClientConnectTask, &header, &requestId);
    status = Ap6256ClientDisconnect(Wifi->Ctx, Reason);
    Ap6256TalGoPeerDelete(Wifi->Ctx, NULL);
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

VOID Ap6256ClientLinkWork(PAP6256_WIFI Wifi, BOOLEAN Up, LONG Generation)
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

static VOID Ap6256EvtClientConnectTimeout(PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    Ap6256LockAcquire(&wifi->Model.GroupLock);
    if (wifi->Model.ClientConnectTask.Active && wifi->Model.ClientConnectTask.DeadlineMs != 0 &&
        Ap6256InterruptTimeMs() >= wifi->Model.ClientConnectTask.DeadlineMs)
        (VOID) Ap6256CancelClientLocked(wifi, STATUS_IO_TIMEOUT, 3);
    Ap6256LockRelease(&wifi->Model.GroupLock);
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
    const UCHAR* ies = NULL;
    ULONG ieLength = 0;
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
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
        status = Ap6256CopyFipsCandidate(bss, &Wifi->Model.ClientCandidates[Wifi->Model.ClientCandidateCount]);
        if (!NT_SUCCESS(status)) goto complete;
        ++Wifi->Model.ClientCandidateCount;
    }
    if (!Wifi->Model.ClientCandidateCount) {
        status = STATUS_NETWORK_UNREACHABLE;
        goto complete;
    }
    if (p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent) {
        ies = p.ConnectParameters.AssociationRequestVendorIE.pElements;
        ieLength = p.ConnectParameters.AssociationRequestVendorIE.ElementCount;
    }
    if (base.HostFips) {
        status = Ap6256FipsCheckVendorIes(ies, ieLength);
        if (!NT_SUCCESS(status)) goto complete;
    }
    status = Ap6256P2pSetHostIesFor(ctx, &ctx->Go.P2p, ctx->Go.IfIndex, Ap6256P2pFrameAssocRequest,
                                    ies, ieLength);
    if (NT_SUCCESS(status))
        status = Ap6256P2pBuildIesFor(ctx, &ctx->Go.P2p, ctx->Go.IfIndex);
    if (!NT_SUCCESS(status))
        goto complete;
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

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleAbortRequest(_In_ PAP6256_WIFI Wifi,
                                                                 _In_ AP6256_REQUEST Request,
                                                                 _In_reads_bytes_(TlvLength)
                                                                     const UCHAR* Tlv,
                                                                 _In_ ULONG TlvLength)
{
    WDI_TASK_ABORT_PARAMETERS parameters;
    WDI_MESSAGE_HEADER taskHeader;
    NTSTATUS status;
    BOOLEAN claimed = FALSE;
    UINT16 completionId = 0;
    PVOID taskRequestId = NULL;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&taskHeader, sizeof(taskHeader));
    status =
        Ap6256NdisToNtStatus(ParseWdiAbortTask(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (NT_SUCCESS(status) && parameters.CancelParameters.OriginalTaskOID==OID_WDI_TASK_REQUEST_FTM) {
        UINT32 transaction=parameters.CancelParameters.OriginalTransactionId;
        WDI_PORT_ID port=parameters.CancelParameters.OriginalPortId;
        CleanupParsedWdiAbortTask(&parameters);Ap6256CompleteRequest(Wifi,Request,STATUS_SUCCESS);
        (VOID)Ap6256FtmCancel(Wifi,TRUE,transaction,port,STATUS_CANCELLED);return;
    }
    if (NT_SUCCESS(status) && parameters.CancelParameters.OriginalPortId == AP6256_GROUP_PORT &&
        parameters.CancelParameters.OriginalTaskOID == OID_WDI_TASK_CONNECT) {
        Ap6256LockAcquire(&Wifi->Model.GroupLock);
        claimed = Wifi->Model.ClientConnectTask.Active &&
                  Wifi->Model.ClientConnectTask.Header.TransactionId ==
                      parameters.CancelParameters.OriginalTransactionId;
        CleanupParsedWdiAbortTask(&parameters);
        Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
        if (claimed)
            (VOID) Ap6256CancelClientLocked(Wifi, STATUS_CANCELLED, 3);
        Ap6256LockRelease(&Wifi->Model.GroupLock);
        return;
    }
    if (NT_SUCCESS(status)) {
        if (parameters.CancelParameters.OriginalTaskOID == OID_WDI_TASK_SCAN) {
            AP6256_TIMER_STOP(Wifi->ScanTimer, TRUE);
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->ScanTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);
            completionId = WDI_INDICATION_SCAN_COMPLETE;
        } else if (parameters.CancelParameters.OriginalTaskOID == OID_WDI_TASK_CONNECT ||
                   parameters.CancelParameters.OriginalTaskOID == OID_WDI_TASK_ROAM) {

            claimed = Ap6256ClaimConnectTask(
                Wifi, Ap6256ConnectClaimMatching, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);
            completionId = Ap6256ConnectCompletionId(Wifi);
        } else if (parameters.CancelParameters.OriginalTaskOID ==
                       OID_WDI_TASK_SEND_REQUEST_ACTION_FRAME ||
                   parameters.CancelParameters.OriginalTaskOID ==
                       OID_WDI_TASK_SEND_RESPONSE_ACTION_FRAME ||
                   parameters.CancelParameters.OriginalTaskOID ==
                       OID_WDI_TASK_P2P_SEND_REQUEST_ACTION_FRAME ||
                   parameters.CancelParameters.OriginalTaskOID ==
                       OID_WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME) {

            AP6256_TIMER_STOP(Wifi->ActionFrameTimer, TRUE);
            Ap6256LockAcquire(&Wifi->ActionFrameLock);
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->ActionFrameTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);
            completionId = Wifi->ActionFrameCompleteId;
            if (claimed) {

                AP6256_TIMER_STOP(Wifi->ActionFrameTimer, FALSE);
                (VOID) Ap6256WifiAbortOffChannel(Wifi->Ctx);
                Ap6256FreeActionFrame(Wifi);
            } else if (Wifi->ActionFrameTask.Active) {

                LONGLONG delay = Wifi->ActionFrameAcked
                                     ? Wifi->ActionFrameDwellDeadline - Ap6256InterruptTimeMs()
                                     : (LONGLONG)Wifi->ActionFrameRetryMs;
                AP6256_TIMER_START(Wifi->ActionFrameTimer, (ULONG)max(1ll, delay));
            }
            Ap6256LockRelease(&Wifi->ActionFrameLock);
        } else if (parameters.CancelParameters.OriginalTaskOID ==
                   OID_WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE) {
            AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->ApAssocTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);
            completionId = WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE;
            if (claimed) {
                (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, Wifi->ApPendingAssocMac, 1);
                Ap6256TalGoPeerDelete(Wifi->Ctx, Wifi->ApPendingAssocMac);
            }
        } else if (parameters.CancelParameters.OriginalTaskOID == OID_WDI_TASK_P2P_DISCOVER) {

            AP6256_TIMER_STOP(Wifi->P2pDiscoverTimer, TRUE);
            Ap6256LockAcquire(&Wifi->P2pLock);
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->P2pDiscoverTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);
            completionId = WDI_INDICATION_P2P_DISCOVERY_COMPLETE;
            if (!claimed && Wifi->P2pDiscovering)
                AP6256_TIMER_START(Wifi->P2pDiscoverTimer, 100);
            Ap6256LockRelease(&Wifi->P2pLock);
        }

        TraceDiag("abort task: OID 0x%08X txn %u port %u -> %s\n",
                  parameters.CancelParameters.OriginalTaskOID,
                  parameters.CancelParameters.OriginalTransactionId,
                  (ULONG)parameters.CancelParameters.OriginalPortId,
                  claimed ? "cancelled" : "no matching task in flight");
    } else {
        TraceError(TRACE_NETADAPTER, "abort task: TLV parse failed 0x%08X\n", status);
    }
    CleanupParsedWdiAbortTask(&parameters);

    Ap6256CompleteRequest(Wifi, Request, status);
    if (!NT_SUCCESS(status) || !claimed)
        return;

    if (completionId == WDI_INDICATION_SCAN_COMPLETE) {
        NTSTATUS abortStatus = Ap6256WifiScanAbort(Wifi->Ctx);
        if (!NT_SUCCESS(abortStatus)) {
            TraceWarn(TRACE_NETADAPTER, "firmware scan abort failed 0x%08X\n", abortStatus);
        }
    } else if (completionId == WDI_INDICATION_CONNECT_COMPLETE ||
               completionId == WDI_INDICATION_ROAM_COMPLETE) {
        (VOID) Ap6256WifiDisconnect(Wifi->Ctx);
        if (Wifi->ConnectionActive)
            Ap6256IndicateDisassociation(Wifi, &taskHeader);
        else
            Ap6256IndicateAssociation(Wifi, &taskHeader, taskRequestId, FALSE);
    } else if (completionId == WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE) {

    } else if (completionId == WDI_INDICATION_P2P_DISCOVERY_COMPLETE) {
        Ap6256LockAcquire(&Wifi->P2pLock);
        Ap6256P2pStopDiscovery(Wifi->Ctx);
        Wifi->P2pDiscovering = FALSE;
        Ap6256ServiceStop(Wifi, FALSE);
        Ap6256LockRelease(&Wifi->P2pLock);
        TraceDiag("P2P discovery aborted: txn %u port %u, %ld indicated, %ld dropped\n",
                  taskHeader.TransactionId, taskHeader.PortId,
                  InterlockedCompareExchange(&Wifi->ScanIndicated, 0, 0),
                  InterlockedCompareExchange(&Wifi->ScanDropped, 0, 0));
    } else {

    }

    (VOID) Ap6256SendIndicationRq(
        Wifi, completionId, &taskHeader, taskHeader.TransactionId, taskRequestId,
        completionId == WDI_INDICATION_SCAN_COMPLETE ? STATUS_SUCCESS : STATUS_CANCELLED, NULL, 0);
}

VOID Ap6256FlushSoftwareQueues(_In_ PAP6256_WIFI Wifi)
{

    Ap6256TalRxFlushQueue(Wifi->Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static UINT32 Ap6256WakeReasonCode(_In_ UINT32 FirmwareStatus,
                                                                      _In_ BOOLEAN PacketValid)
{
    if (PacketValid)
        return WDI_WAKE_REASON_CODE_PACKET;
    if ((FirmwareStatus & AP6256_WAKE_ON_NLO_DISCOVERY) != 0) {
        return WDI_WAKE_REASON_CODE_NLO_DISCOVERY;
    }
    if ((FirmwareStatus & AP6256_WAKE_ON_AP_ASSOCIATION_LOST) != 0) {
        return WDI_WAKE_REASON_CODE_AP_ASSOCIATION_LOST;
    }
    if ((FirmwareStatus & AP6256_WAKE_ON_GTK_HANDSHAKE_ERROR) != 0) {
        return WDI_WAKE_REASON_CODE_GTK_HANDSHAKE_ERROR;
    }
    if ((FirmwareStatus & AP6256_WAKE_ON_4WAY_HANDSHAKE_REQUEST) != 0) {
        return WDI_WAKE_REASON_CODE_4WAY_HANDSHAKE_REQUEST;
    }
    return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256IndicateWakeReason(_In_ PAP6256_WIFI Wifi, _In_ UINT32 FirmwareStatus,
                         _In_ const AP6256_WAKE_PACKET* Packet, _In_ BOOLEAN PacketValid)
{
    WDI_INDICATION_WAKE_REASON_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT32 code = Ap6256WakeReasonCode(FirmwareStatus, PacketValid);
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;

    if (code == 0) {
        TraceInfo(TRACE_NETADAPTER, "wake was not this adapter's doing (status 0x%08X)\n",
                  FirmwareStatus);
        return;
    }

    RtlZeroMemory(&parameters, sizeof(parameters));
    parameters.WakeEventCode = code;
    if (PacketValid) {
        parameters.Optional.WakePacket_IsPresent = TRUE;
        parameters.WakePacket.ElementCount = Packet->SavedLength;
        parameters.WakePacket.pElements = (UINT8*)(ULONG_PTR)Packet->Packet;
        parameters.Optional.WakePacketPatternId_IsPresent = TRUE;
        parameters.WakePacketPatternId = Packet->PatternId;
    }

    if (GenerateWdiIndicationWakeReason(&parameters, 0, &Wifi->TlvContext, &generatedLength,
                                        &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        RtlZeroMemory(&header, sizeof(header));
        header.PortId = Wifi->PortNumber;
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_WAKE_REASON, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
        TraceInfo(TRACE_NETADAPTER, "wake reason 0x%04X, %u byte(s) of packet from pattern %u\n",
                  code, PacketValid ? Packet->SavedLength : 0, PacketValid ? Packet->PatternId : 0);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256PowerSleepIsHot(_In_ PAP6256_WIFI Wifi)
{
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;

    if (Ap6256FipsActive(ctx, 0) || Ap6256HostCipherPacketActive(ctx, 0)) return FALSE;
    if (!ctx->FirmwareLinkUp)
        return (BOOLEAN)(Ap6256PnoWindowsActive(ctx) &&
                         (ctx->WakeMediaSpecificEvents & AP6256_WAKE_ON_NLO_DISCOVERY) != 0);
    return (BOOLEAN)(ctx->WakeEnabledPatterns != 0 || ctx->WakeEnabledOffloads != 0 ||
                     ctx->WakeUpFlags != 0 || ctx->WakeMediaSpecificEvents != 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandlePowerRequest(_In_ PAP6256_WIFI Wifi,
                                                                 _In_ AP6256_REQUEST Request,
                                                                 _In_reads_bytes_(TlvLength)
                                                                     const UCHAR* Tlv,
                                                                 _In_ ULONG TlvLength)
{
    WDI_SET_POWER_PARAMETERS parameters;
    WDI_SET_POWER_RESULTS results;
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    ULONG outputLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
    UINT32 powerState = AP6256_WDI_POWER_D0;
    NDIS_STATUS ndisStatus;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&results, sizeof(results));

    if (NT_SUCCESS(Ap6256NdisToNtStatus(
            ParseWdiSetPowerState(TlvLength, Tlv, &Wifi->TlvContext, &parameters)))) {
        powerState = (UINT32)parameters.PowerState;

        if (parameters.Optional.WakeEventMask_IsPresent) {
            Wifi->Ctx->WakeEnabledPatterns = parameters.WakeEventMask.EnabledWoLPacketPatterns;
            Wifi->Ctx->WakeEnabledOffloads = parameters.WakeEventMask.EnabledProtocolOffloads;
            Wifi->Ctx->WakeUpFlags = parameters.WakeEventMask.WakeUpFlags;
            Wifi->Ctx->WakeMediaSpecificEvents = parameters.WakeEventMask.MediaSpecificWakeUpEvents;
            TraceInfo(TRACE_NETADAPTER,
                      "wake armed: patterns 0x%08X offloads 0x%08X flags "
                      "0x%08X media 0x%08X\n",
                      Wifi->Ctx->WakeEnabledPatterns, Wifi->Ctx->WakeEnabledOffloads,
                      Wifi->Ctx->WakeUpFlags, Wifi->Ctx->WakeMediaSpecificEvents);
        } else if (powerState != AP6256_WDI_POWER_D0) {
            Wifi->Ctx->WakeEnabledPatterns = 0;
            Wifi->Ctx->WakeEnabledOffloads = 0;
            Wifi->Ctx->WakeUpFlags = 0;
            Wifi->Ctx->WakeMediaSpecificEvents = 0;
        }
    } else {

        TraceWarn(TRACE_NETADAPTER, "set power TLVs unparseable; assuming D0\n");
    }
    CleanupParsedWdiSetPowerState(&parameters);

    if (powerState == AP6256_WDI_POWER_D0) {
        if (Wifi->Ctx->LowPowerArmed) {

            UINT32 wakeStatus = 0;
            AP6256_WAKE_PACKET packet;
            BOOLEAN packetValid = FALSE;

            status = Ap6256WifiResumeFromWake(Wifi->Ctx, &wakeStatus, &packet, &packetValid);
            if (NT_SUCCESS(status)) {
                Wifi->PowerStateDx = FALSE;
                Ap6256IndicateWakeReason(Wifi, wakeStatus, &packet, packetValid);
            } else {
                Ap6256WdiChipDown(Wifi->Ctx, TRUE);
                status = Ap6256WdiChipUp(Wifi->Ctx, TRUE);
                if (NT_SUCCESS(status)) {
                    Wifi->PowerStateDx = FALSE;
                    (VOID)Ap6256NetHardwareStart(Wifi->Ctx);
                    results.Optional.bResumeRequired_IsPresent = TRUE;
                    results.bResumeRequired = TRUE;
                }
            }
        } else if (Wifi->PowerStateDx) {
            status = Ap6256WdiChipUp(Wifi->Ctx, TRUE);
            if (NT_SUCCESS(status)) {
                Wifi->PowerStateDx = FALSE;
                (VOID) Ap6256NetHardwareStart(Wifi->Ctx);
                results.Optional.bResumeRequired_IsPresent = TRUE;
                results.bResumeRequired = TRUE;
                TraceInfo(TRACE_NETADAPTER, "D0: chip back up, resume required\n");
            } else {

                TraceError(TRACE_NETADAPTER, "D0 bring-up failed 0x%08X\n", status);
            }
        }
    } else {
        Ap6256PnoResultsPower(Wifi->Ctx, FALSE);
        if (!Wifi->PowerStateDx) {
            if (powerState == AP6256_WDI_POWER_D2 && Ap6256PowerSleepIsHot(Wifi)) {

                ULONG index;
                NTSTATUS wakeStatus = STATUS_SUCCESS;
                BOOLEAN arpOffload = (BOOLEAN)(
                    (Wifi->Ctx->WakeEnabledOffloads &
                     NDIS_PM_PROTOCOL_OFFLOAD_ARP_SUPPORTED) != 0);
                BOOLEAN nsOffload = (BOOLEAN)(
                    (Wifi->Ctx->WakeEnabledOffloads &
                     NDIS_PM_PROTOCOL_OFFLOAD_NS_SUPPORTED) != 0);

                for (index = 0; index < Wifi->WolPatternCount; index++) {
                    status = Ap6256WifiEnablePacketFilter(
                        Wifi->Ctx, Wifi->WolPatternIds[index],
                        (BOOLEAN)(Wifi->Ctx->WakeEnabledPatterns != 0));
                    if (!NT_SUCCESS(status) && NT_SUCCESS(wakeStatus))
                        wakeStatus = status;
                }
                Wifi->PowerStateDx = TRUE;
                status = Ap6256WifiSuspendForWake(
                    Wifi->Ctx, Wifi->Ctx->WakeMediaSpecificEvents,
                    arpOffload, nsOffload);
                if (!NT_SUCCESS(status) && NT_SUCCESS(wakeStatus))
                    wakeStatus = status;
                Wifi->PowerStateDx = TRUE;
                if (NT_SUCCESS(wakeStatus)) {
                    TraceInfo(TRACE_NETADAPTER,
                              "D%u: chip left up, %u wake pattern(s) armed\n",
                              powerState == AP6256_WDI_POWER_D2 ? 2u : 3u,
                              Wifi->WolPatternCount);
                } else {
                    TraceError(TRACE_NETADAPTER,
                               "D%u: wake setup failed 0x%08X; falling back to cold resume\n",
                               powerState == AP6256_WDI_POWER_D2 ? 2u : 3u,
                               wakeStatus);
                    Ap6256WdiChipDown(Wifi->Ctx, TRUE);
                }
            } else {

                Ap6256WdiChipDown(Wifi->Ctx, TRUE);
                Wifi->PowerStateDx = TRUE;
                TraceInfo(TRACE_NETADAPTER, "D%u: chip down\n",
                          powerState == AP6256_WDI_POWER_D2 ? 2u : 3u);
            }
        }
    }

    ndisStatus =
        GenerateWdiSetPowerState(&results, 0, &Wifi->TlvContext, &generatedLength, &generated);
    if (ndisStatus == NDIS_STATUS_SUCCESS && generated != NULL &&
        outputLength >= generatedLength + sizeof(WDI_MESSAGE_HEADER)) {
        RtlCopyMemory((PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer +
                          sizeof(WDI_MESSAGE_HEADER),
                      generated, generatedLength);
        Request->DATA.METHOD_INFORMATION.BytesWritten =
            sizeof(WDI_MESSAGE_HEADER) + generatedLength;
    }
    FreeGenerated(generated);

    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
    if (powerState == AP6256_WDI_POWER_D0 && !Wifi->PowerStateDx)
        Ap6256PnoResultsPower(Wifi->Ctx, TRUE);
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
        !Ap6256TalGoPeerCreate(Wifi->Ctx, assoc->Address,
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
        Ap6256TalGoRxOpen(Wifi->Ctx, assoc->Address);
    else {
        Ap6256TalGoPeerDelete(Wifi->Ctx, assoc->Address);
        if (!Wifi->Stopping && Wifi->HardwareAvailable)
            (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, assoc->Address,
                                          !accept && reason != 0 ? reason : 1);
    }
    FreeGenerated(generated);
    ExFreePoolWithTag(assoc, AP6256_POOL_TAG);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
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

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleIhvRequest(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ const WDI_MESSAGE_HEADER* Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    const UCHAR* ihvData = NULL;
    ULONG ihvLength = 0;
    ULONG offset = 0;

    while (offset < TlvLength) {
        UINT16 type, length;
        if (TlvLength < 4 || offset > TlvLength - 4)
            goto invalid;
        type = (UINT16)(Tlv[offset] | ((UINT16)Tlv[offset + 1] << 8));
        length = (UINT16)(Tlv[offset + 2] | ((UINT16)Tlv[offset + 3] << 8));
        if (length > TlvLength - offset - 4)
            goto invalid;

        if (type == AP6256_WDI_TLV_IHV_DATA) {
            if (ihvData != NULL)
                goto invalid;
            ihvData = Tlv + offset + 4;
            ihvLength = length;
        }
        offset += 4u + length;
    }

    if (ihvData == NULL)
        goto invalid;

    {
        UINT32 magic = 0;
        AP6256_TDLS_STATUS result;
        AP6256_PNO_STATUS pnoResult;
        AP6256_PNO_RESULT_REPLY* scanResult = NULL;
        AP6256_PNO_REQUEST pnoHeader = {0};
        NTSTATUS status;
        ULONG resultLength, needed;
        const VOID* resultData;
        PUCHAR output;
        if (ihvLength >= sizeof(magic))
            RtlCopyMemory(&magic, ihvData, sizeof(magic));
        if (magic != AP6256_TDLS_MAGIC && magic != AP6256_PNO_MAGIC) {
            Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
            return;
        }
        resultLength = magic == AP6256_PNO_MAGIC ? sizeof(pnoResult) : sizeof(result);
        if (magic == AP6256_PNO_MAGIC && ihvLength >= sizeof(pnoHeader)) {
            RtlCopyMemory(&pnoHeader, ihvData, sizeof(pnoHeader));
            if (pnoHeader.Operation == AP6256_PNO_READ_RESULT ||
                pnoHeader.Operation == AP6256_PNO_FETCH_BATCH)
                resultLength = sizeof(*scanResult);
        }
        needed = sizeof(WDI_MESSAGE_HEADER) + 4 + resultLength;
        if (Header->PortId != AP6256_STATION_PORT)
            goto invalid;
        if (Request->DATA.METHOD_INFORMATION.OutputBufferLength < needed) {
            Request->DATA.METHOD_INFORMATION.BytesNeeded = needed;
            Ap6256CompleteRequest(Wifi, Request, STATUS_BUFFER_TOO_SMALL);
            return;
        }
        if (magic == AP6256_PNO_MAGIC) {
            if (resultLength == sizeof(*scanResult)) {
                scanResult = (AP6256_PNO_RESULT_REPLY*)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, sizeof(*scanResult), AP6256_POOL_TAG);
                if (scanResult == NULL) {
                    Ap6256CompleteRequest(Wifi, Request, STATUS_INSUFFICIENT_RESOURCES);
                    return;
                }
                status = Ap6256PnoResultControl(Wifi->Ctx, ihvData, ihvLength, scanResult);
                resultData = scanResult;
            } else {
                status = Ap6256PnoControl(Wifi->Ctx, ihvData, ihvLength, &pnoResult);
                resultData = &pnoResult;
            }
        } else {
            status = Ap6256TdlsControl(Wifi->Ctx, ihvData, ihvLength, &result);
            resultData = &result;
        }
        if (NT_SUCCESS(status)) {
            output = (PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer +
                     sizeof(WDI_MESSAGE_HEADER);
            output[0] = (UCHAR)(AP6256_WDI_TLV_IHV_DATA & 0xffu);
            output[1] = (UCHAR)(AP6256_WDI_TLV_IHV_DATA >> 8);
            output[2] = (UCHAR)resultLength;
            output[3] = (UCHAR)(resultLength >> 8);
            RtlCopyMemory(output + 4, resultData, resultLength);
            Request->DATA.METHOD_INFORMATION.BytesWritten = needed;
        }
        if (scanResult != NULL)
            ExFreePoolWithTag(scanResult, AP6256_POOL_TAG);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

invalid:
    Ap6256CompleteRequest(Wifi, Request, Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA));
}

_IRQL_requires_max_(PASSIVE_LEVEL)

static VOID
Ap6256FillBandInfo(_Out_ WDI_BAND_INFO_CONTAINER* Band, _In_ WDI_BAND_ID BandId,
                   _In_reads_(PhyCount) const WDI_PHY_TYPE* Phys, _In_ ULONG PhyCount,
                   _In_reads_(ChannelCount) const WDI_CHANNEL_MAPPING_ENTRY* Channels,
                   _In_ ULONG ChannelCount, _In_reads_(WidthCount) const UINT32* Widths,
                   _In_ ULONG WidthCount)
{
    RtlZeroMemory(Band, sizeof(*Band));
    Band->BandCapabilities.BandID = BandId;
    Band->BandCapabilities.BandState = TRUE;

    Band->ValidPhyTypes.ElementCount = PhyCount;
    Band->ValidPhyTypes.pElements = (WDI_PHY_TYPE*)Phys;
    Band->ValidChannelTypes.ElementCount = ChannelCount;
    Band->ValidChannelTypes.pElements = (WDI_CHANNEL_MAPPING_ENTRY*)Channels;
    Band->ChannelWidthList.ElementCount = WidthCount;
    Band->ChannelWidthList.pElements = (UINT32*)Widths;
}

static VOID Ap6256FillPhyInfo(_Out_ WDI_PHY_INFO_CONTAINER* Phy, _In_ WDI_PHY_TYPE PhyType,
                              _Out_writes_(RateCount) WDI_DATA_RATE_LIST* Rates,
                              _In_reads_(RateCount) const UINT16* RateValues, _In_ ULONG RateCount)
{
    ULONG index;

    RtlZeroMemory(Phy, sizeof(*Phy));
    Phy->PhyCapabilities.PhyType = PhyType;
    Phy->PhyCapabilities.MPDUMaxLength = AP6256_FRAME_MAX;

    Phy->TxPowerLevelList.ElementCount = RTL_NUMBER_OF(Ap6256TxPowerLevels);
    Phy->TxPowerLevelList.pElements = (UINT32*)Ap6256TxPowerLevels;

    for (index = 0; index < RateCount; index++) {
        Rates[index].DataRateFlag = WDI_DATA_RATE_RX_RATE | WDI_DATA_RATE_TX_RATE;
        Rates[index].DataRateValue = RateValues[index];
    }
    Phy->DataRateList.ElementCount = RateCount;
    Phy->DataRateList.pElements = Rates;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleGetCapabilities(_In_ PAP6256_WIFI Wifi,
                                                                    _In_ AP6256_REQUEST Request)
{
    WDI_GET_ADAPTER_CAPABILITIES_PARAMETERS caps;
    WDI_BAND_INFO_CONTAINER bands[2];
    WDI_PHY_INFO_CONTAINER phys[5];
    WDI_MAC_ADDRESS p2pInterfaces[1];
    WDI_DATA_RATE_LIST ratesB[RTL_NUMBER_OF(Ap6256RatesB)];
    WDI_DATA_RATE_LIST ratesOfdm[RTL_NUMBER_OF(Ap6256RatesOfdm)];
    static const CHAR firmwareVersion[] = "BCM43456";
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    ULONG outputLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
    NDIS_STATUS ndisStatus;
    NTSTATUS status;

    RtlZeroMemory(&caps, sizeof(caps));

    caps.Optional.CommunicationAttributes_IsPresent = TRUE;
    caps.CommunicationAttributes.Optional.CommunicationCapabilities_IsPresent = TRUE;
    caps.CommunicationAttributes.CommunicationCapabilities.MaxCommandSize = 0x2000;

    caps.InterfaceAttributes.InterfaceCapabilities.MTUSize = 1500;
    caps.InterfaceAttributes.InterfaceCapabilities.MaxMultiCastListSize = 32;
    caps.InterfaceAttributes.InterfaceCapabilities.BackFillSize = 0;

    if (Ap6256MacIsValue(Wifi->Ctx->MacAddress, 0x00)) {
        NTSTATUS macStatus = Ap6256FirmwareQueryMacAddress(Wifi->Ctx, Wifi->Ctx->MacAddress);
        if (!NT_SUCCESS(macStatus)) {
            TraceError(TRACE_NETADAPTER, "no station MAC for capabilities 0x%08X\n", macStatus);
        }
    }

    RtlCopyMemory(caps.InterfaceAttributes.InterfaceCapabilities.Address.Address,
                  Wifi->Ctx->PermanentMacAddressValid ? Wifi->Ctx->PermanentMacAddress
                                                      : Wifi->Ctx->MacAddress,
                  sizeof(caps.InterfaceAttributes.InterfaceCapabilities.Address.Address));

    {
        UINT32 maxHalfMbps = 0;
        UINT32 maxKbps = AP6256_LINK_SPEED / 1000;

        if (NT_SUCCESS(Ap6256WifiGetMaxLinkRate(Wifi->Ctx, &maxHalfMbps)) && maxHalfMbps != 0) {
            maxKbps = maxHalfMbps * 500u;
        }
        caps.InterfaceAttributes.InterfaceCapabilities.MaxTxRate = maxKbps;
        caps.InterfaceAttributes.InterfaceCapabilities.MaxRxRate = maxKbps;
        TraceDiag("capabilities: max rate %u kbps%s\n", maxKbps,
                  maxHalfMbps != 0 ? "" : " (firmware did not say)");
    }
    caps.InterfaceAttributes.InterfaceCapabilities.HardwareRadioState = Wifi->HardwareRadioState;
    caps.InterfaceAttributes.InterfaceCapabilities.SoftwareRadioState = Wifi->SoftwareRadioState;
    caps.InterfaceAttributes.InterfaceCapabilities.NumRxStreams = 1;
    caps.InterfaceAttributes.InterfaceCapabilities.NumTxStreams = 1;
    caps.InterfaceAttributes.InterfaceCapabilities.NumChannels =
        Wifi->Ctx->FirmwareMchanSupported ? 2 : 1;

    caps.InterfaceAttributes.InterfaceCapabilities.ActionFramesSupported = 1;

    caps.InterfaceAttributes.InterfaceCapabilities.Support_eCSA = 1;

    caps.InterfaceAttributes.InterfaceCapabilities.CannotSupportMiracastSink =
        !Wifi->Ctx->FirmwareP2pSupported;

    caps.InterfaceAttributes.InterfaceCapabilities.FastTransitionSupported =
        Ap6256HostFbtAvailable(Wifi);

    switch (Wifi->Ctx->BtCoexMode) {
    case 1:
    case 2:
    case 3:
        caps.InterfaceAttributes.InterfaceCapabilities.BluetoothCoexistenceSupport =
            WDI_BLUETOOTH_COEXISTENCE_PERFORMANCE_MAINTAINED;
        break;
    case 4:
        caps.InterfaceAttributes.InterfaceCapabilities.BluetoothCoexistenceSupport =
            WDI_BLUETOOTH_COEXISTENCE_WIFI_DEGRADED_TO_1x1;
        break;
    case 5:
        caps.InterfaceAttributes.InterfaceCapabilities.BluetoothCoexistenceSupport =
            WDI_BLUETOOTH_COEXISTENCE_WIFI_THROUGHPUT_DEGRADED;
        break;
    default:
        caps.InterfaceAttributes.InterfaceCapabilities.BluetoothCoexistenceSupport =
            WDI_BLUETOOTH_COEXISTENCE_MUTUALLY_EXCLUSIVE;
        break;
    }
    caps.InterfaceAttributes.FirmwareVersion.ElementCount = RTL_NUMBER_OF(firmwareVersion);
    caps.InterfaceAttributes.FirmwareVersion.pElements = (CHAR*)firmwareVersion;

    {
        UINT32 maxKeys = 0;

        if (NT_SUCCESS(Ap6256WifiGetMaxKeys(Wifi->Ctx, &maxKeys)) && maxKeys > 4) {
            caps.StationAttributes.StationCapabilities.KeyMappingTableSize = maxKeys - 4;
            caps.StationAttributes.StationCapabilities.MaxNumPerSTA = maxKeys / 2;
        } else {
            TraceInfo(TRACE_NETADAPTER, "wsec_info has no key count; reporting 16 mapping keys\n");
            caps.StationAttributes.StationCapabilities.KeyMappingTableSize = 16;
            caps.StationAttributes.StationCapabilities.MaxNumPerSTA = 4;
        }
    }

    caps.StationAttributes.StationCapabilities.ScanSSIDListSize = 4;
    caps.StationAttributes.StationCapabilities.DesiredBSSIDListSize = 1;
    caps.StationAttributes.StationCapabilities.DesiredSSIDListSize = 1;
    caps.StationAttributes.StationCapabilities.PrivacyExemptionListSize = 1;
    caps.StationAttributes.StationCapabilities.DefaultKeyTableSize = 4;
    caps.StationAttributes.StationCapabilities.WEPKeyValueMaxLength = 13;
    caps.StationAttributes.StationCapabilities.SupportedQOSFlags =
        Ap6256WifiWmmEnabled(Wifi->Ctx) ? 1u : 0u;

    caps.StationAttributes.StationCapabilities.AutoPowerSaveMode = 1;
    caps.StationAttributes.StationCapabilities.uMaxNetworkOffloadListSize = AP6256_NLO_NETWORK_MAX;

    caps.StationAttributes.StationCapabilities.MFPCapable =
        Wifi->Ctx->FirmwareMfpSupported ? 1u : 0u;
    WDI_ALGO_PAIRS stationPairs[RTL_NUMBER_OF(Ap6256AlgoPairs)];
    WDI_ALGO_PAIRS managementPairs[RTL_NUMBER_OF(Ap6256MgmtAlgoPairs)];
    ULONG stationCount =
        Ap6256CopyAlgoPairs(Wifi, Ap6256AlgoPairs, RTL_NUMBER_OF(Ap6256AlgoPairs), stationPairs);
    ULONG managementCount = Ap6256CopyAlgoPairs(
        Wifi, Ap6256MgmtAlgoPairs, RTL_NUMBER_OF(Ap6256MgmtAlgoPairs), managementPairs);
    caps.StationAttributes.Optional.UnicastAlgorithms_IsPresent = TRUE;
    caps.StationAttributes.UnicastAlgorithms.ElementCount = stationCount;
    caps.StationAttributes.UnicastAlgorithms.pElements = stationPairs;
    caps.StationAttributes.Optional.MulticastDataAlgorithms_IsPresent = TRUE;
    caps.StationAttributes.MulticastDataAlgorithms.ElementCount = stationCount;
    caps.StationAttributes.MulticastDataAlgorithms.pElements = stationPairs;
    caps.StationAttributes.Optional.MulticastManagementAlgorithms_IsPresent = TRUE;
    caps.StationAttributes.MulticastManagementAlgorithms.ElementCount = managementCount;
    caps.StationAttributes.MulticastManagementAlgorithms.pElements = managementPairs;

    caps.InterfaceAttributes.InterfaceCapabilities.SAEAuthenticationSupported =
        Ap6256HostSaeAvailable(Wifi);

    caps.InterfaceAttributes.InterfaceCapabilities.BSSTransitionSupported =
        Wifi->Ctx->FirmwareNativeManagement && Wifi->Ctx->FirmwareBssTransitionEnabled;
    caps.InterfaceAttributes.InterfaceCapabilities.IPDockingSupported = FALSE;
    caps.InterfaceAttributes.InterfaceCapabilities.MBOSupported = Wifi->Mbo.Enabled &&
        Wifi->Ctx->FirmwareNativeManagement && Wifi->Ctx->FirmwareBssTransitionEnabled &&
        Wifi->Ctx->FirmwareMfpSupported;

    caps.InterfaceAttributes.InterfaceCapabilities.BeaconReportsImplemented =
        Wifi->Ctx->FirmwareNativeManagement;
    caps.StationAttributes.StationCapabilities.FTMAsInitiatorSupport = Wifi->Ctx->FirmwareFtmSupported;
    caps.StationAttributes.StationCapabilities.FTMNumberOfSupportedTargets =
        Wifi->Ctx->FirmwareFtmSupported ? AP6256_FTM_TARGET_MAX : 0;
    caps.StationAttributes.StationCapabilities.HostWPA3FIPSModeEnabled = FALSE;

    caps.StationAttributes.StationCapabilities.HostFIPSModeImplemented =
        Wifi->Ctx->HostFipsReady ? DOT11_EXTSTA_ATTRIBUTES_SAFEMODE_OID_SUPPORTED : 0;
    TraceDiag("capabilities: MFP %s, SAE %s, %u unicast / %u management "
              "algo pair(s)\n",
              caps.StationAttributes.StationCapabilities.MFPCapable ? "yes" : "no",
              caps.InterfaceAttributes.InterfaceCapabilities.SAEAuthenticationSupported ? "yes"
                                                                                        : "no",
              stationCount, managementCount);

    caps.Optional.DatapathAttributes_IsPresent = TRUE;
    caps.DatapathAttributes.Optional.DataPathCapabilities_IsPresent = TRUE;

    caps.DatapathAttributes.DataPathCapabilities.InterconnectType = WDI_INTERCONNECT_MESSAGE_BASED;

    caps.DatapathAttributes.DataPathCapabilities.MaxNumPeers = AP6256_GO_PEERS + 1u;

    caps.DatapathAttributes.DataPathCapabilities.TxMaxScatterGatherElementsPerFrame = 1;

    caps.DatapathAttributes.DataPathCapabilities.TxTargetPriorityQueueing = 1;
    caps.DatapathAttributes.DataPathCapabilities.TxExplicitSendCompleteFlagRequired = 1;
    caps.DatapathAttributes.DataPathCapabilities.TxMinEffectiveFrameSize = 1;
    caps.DatapathAttributes.DataPathCapabilities.TxFrameSizeGranularity = 1;
    caps.DatapathAttributes.DataPathCapabilities.RxTxForwarding = 0;
    caps.DatapathAttributes.DataPathCapabilities.RxMaxThroughput = 1000;

    const BOOLEAN advertiseSecondaryRoles = Wifi->Ctx->FirmwareP2pSupported;
    TraceDiag("hotspot: WDI capabilities GO %u, clients %u\n", advertiseSecondaryRoles,
              advertiseSecondaryRoles ? AP6256_GO_CLIENTS : 0u);

    caps.Optional.VirtualizationAttributes_IsPresent = advertiseSecondaryRoles;
    caps.VirtualizationAttributes.VirtualizationCapabilities.ExtSTACount = 1;
    caps.VirtualizationAttributes.VirtualizationCapabilities.WiFiDirectGroupCount = 1;
    caps.VirtualizationAttributes.VirtualizationCapabilities.APCount = 0;
    caps.VirtualizationAttributes.VirtualizationCapabilities.SimultaneousGoCount = 1;
    caps.VirtualizationAttributes.VirtualizationCapabilities
        .SimultaneousMultiChannelOperationLimit = Wifi->Ctx->FirmwareMchanSupported ? 2 : 1;
    caps.VirtualizationAttributes.VirtualizationCapabilities.SimultaneousSTAWFDClientCount = 2;

    caps.Optional.APAttributes_IsPresent = advertiseSecondaryRoles;

    caps.APAttributes.APCapabilities.ScanSSIDListSize =
        caps.StationAttributes.StationCapabilities.ScanSSIDListSize;
    caps.APAttributes.APCapabilities.DesiredSSIDListSize = 1;
    caps.APAttributes.APCapabilities.PrivacyExemptionListSize = 1;
    caps.APAttributes.APCapabilities.AssociationTableSize = AP6256_GO_CLIENTS;
    caps.APAttributes.APCapabilities.KeyMappingTableSize =
        caps.StationAttributes.StationCapabilities.KeyMappingTableSize;
    caps.APAttributes.APCapabilities.DefaultKeyTableSize = 4;
    caps.APAttributes.APCapabilities.WEPKeyValueMaxLength = 13;
    caps.APAttributes.APCapabilities.RadarDetectionSupported = FALSE;
    caps.APAttributes.UnicastAlgorithms.ElementCount = 2;
    caps.APAttributes.UnicastAlgorithms.pElements = (WDI_ALGO_PAIRS*)Ap6256AlgoPairs;
    caps.APAttributes.MulticastDataAlgorithms.ElementCount = 2;
    caps.APAttributes.MulticastDataAlgorithms.pElements = (WDI_ALGO_PAIRS*)Ap6256AlgoPairs;

    caps.Optional.P2PAttributes_IsPresent = advertiseSecondaryRoles;
    caps.P2PAttributes.P2PCapabilities.ConcurrentGOCount = 1;
    caps.P2PAttributes.P2PCapabilities.ConcurrentClientCount = AP6256_P2P_CLIENT_ROLES;
    TraceDiag("hotspot: native WLAN contract GO roles %u client roles %u AP scan SSIDs %u\n",
              advertiseSecondaryRoles ? caps.P2PAttributes.P2PCapabilities.ConcurrentGOCount : 0u,
              advertiseSecondaryRoles ? caps.P2PAttributes.P2PCapabilities.ConcurrentClientCount
                                      : 0u,
              caps.APAttributes.APCapabilities.ScanSSIDListSize);
    caps.P2PAttributes.P2PCapabilities.WPSVersionSupport = 2;
    caps.P2PAttributes.P2PCapabilities.ServiceDiscoverySupported = Wifi->Ctx->FirmwareServiceOffload;
    caps.P2PAttributes.P2PCapabilities.ServiceNameDiscoverySupported = Wifi->Ctx->FirmwareServiceOffload;
    caps.P2PAttributes.P2PCapabilities.ServiceInformationDiscoverySupported = Wifi->Ctx->FirmwareServiceOffload;
    caps.P2PAttributes.P2PCapabilities.ServiceNameAdvertisementsMaxBytesSupported = Wifi->Ctx->FirmwareServiceOffload ? AP6256_SERVICE_MAX * AP6256_SERVICE_NAME_MAX : 0;
    caps.P2PAttributes.P2PCapabilities.ServiceInformationAdvertisementsMaxBytesSupported = Wifi->Ctx->FirmwareServiceOffload ? AP6256_SERVICE_MAX * AP6256_SERVICE_INFO_MAX : 0;
    caps.P2PAttributes.P2PCapabilities.BackgroundDiscoverySupported = FALSE;
    caps.P2PAttributes.P2PCapabilities.ClientDiscoverabilitySupported = FALSE;
    caps.P2PAttributes.P2PCapabilities.InfrastructureManagementSupported = FALSE;
    caps.P2PAttributes.P2PCapabilities.MaxSecondaryAdapterTypeListSize =
        (UINT8)AP6256_P2P_SECONDARY_MAX;
    RtlCopyMemory(caps.P2PAttributes.P2PCapabilities.DeviceAddress, Wifi->Ctx->P2p.DeviceAddress,
                  sizeof(caps.P2PAttributes.P2PCapabilities.DeviceAddress));
    caps.P2PAttributes.P2PCapabilities.DiscoveryFilterListSize = 2;

    caps.P2PAttributes.P2PCapabilities.GOClientTableSize = (UINT8)AP6256_GO_CLIENTS;
    caps.P2PAttributes.P2PCapabilities.MaxVendorSpecificExtensionIESize = AP6256_P2P_VENDOR_IE_MAX;
    caps.P2PAttributes.P2PCapabilities.PassiveAvailabilityListenStateSupported = FALSE;
    caps.P2PAttributes.P2PCapabilities.OperatingChannelUpdatesSupported = FALSE;

    caps.P2PAttributes.P2PCapabilities.GOon5GHzBandSupported = advertiseSecondaryRoles;
    TraceDiag("hotspot: GO on 5 GHz capability %u\n",
              (ULONG)caps.P2PAttributes.P2PCapabilities.GOon5GHzBandSupported);

    RtlZeroMemory(p2pInterfaces, sizeof(p2pInterfaces));
    RtlCopyMemory(p2pInterfaces[0].Address, Wifi->Ctx->P2p.DeviceAddress, 6);
    p2pInterfaces[0].Address[0] |= 0x02u;
    p2pInterfaces[0].Address[5] ^= 0x80;
    caps.P2PAttributes.InterfaceAddressList.ElementCount = RTL_NUMBER_OF(p2pInterfaces);
    caps.P2PAttributes.InterfaceAddressList.pElements = p2pInterfaces;
    TraceDiag("hotspot: WDI group ports %u, interface addresses %u\n",
              advertiseSecondaryRoles
                  ? caps.VirtualizationAttributes.VirtualizationCapabilities.WiFiDirectGroupCount
                  : 0u,
              advertiseSecondaryRoles ? caps.P2PAttributes.InterfaceAddressList.ElementCount : 0u);

    {
        UINT32 wowl = Wifi->Ctx->WowlCapabilities;
        UINT32 patterns = 0;
        UINT32 offloads = 0;
        UINT32 wakeEvents = 0;
        UINT32 mediaEvents = 0;

        if ((wowl & AP6256_WOWL_MAGIC) != 0) {
            patterns |= NDIS_PM_WOL_MAGIC_PACKET_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_NET) != 0) {
            patterns |= NDIS_PM_WOL_BITMAP_PATTERN_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_EAPID) != 0) {
            patterns |= NDIS_PM_WOL_EAPOL_REQUEST_ID_MESSAGE_SUPPORTED;
        }

        if ((wowl & AP6256_WOWL_ARP_OFFLOAD) != 0 &&
            Wifi->Ctx->FirmwareArpOffloadSupported) {
            offloads |= NDIS_PM_PROTOCOL_OFFLOAD_ARP_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_ARP_OFFLOAD) != 0 &&
            Wifi->Ctx->FirmwareNdOffloadSupported) {
            offloads |= NDIS_PM_PROTOCOL_OFFLOAD_NS_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_KEY_ROTATION) != 0 && Wifi->Ctx->FirmwareGtkOffloadSupported)
            offloads |= NDIS_PM_PROTOCOL_OFFLOAD_80211_RSN_REKEY_SUPPORTED;

        if ((wowl & (AP6256_WOWL_DISCONNECT | AP6256_WOWL_BEACON)) ==
            (AP6256_WOWL_DISCONNECT | AP6256_WOWL_BEACON)) {
            wakeEvents |= NDIS_PM_WAKE_ON_MEDIA_DISCONNECT_SUPPORTED;
            mediaEvents |= NDIS_WLAN_WAKE_ON_AP_ASSOCIATION_LOST_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_GTK_FAILURE) != 0) {
            mediaEvents |= NDIS_WLAN_WAKE_ON_GTK_HANDSHAKE_ERROR_SUPPORTED;
        }
        if ((wowl & AP6256_WOWL_M1) != 0) {
            mediaEvents |= NDIS_WLAN_WAKE_ON_4WAY_HANDSHAKE_REQUEST_SUPPORTED |
                           NDIS_WLAN_WAKE_ON_NLO_DISCOVERY_SUPPORTED;
        }

        if (patterns != 0 || offloads != 0 || mediaEvents != 0) {
            caps.Optional.PmCapabilities_IsPresent = TRUE;
            caps.PmCapabilities.Flags = 1;
            caps.PmCapabilities.SupportedWoLPacketPatterns = patterns;
            caps.PmCapabilities.NumTotalWoLPatterns =
                patterns != 0 ? Ap6256WolPatternCeiling(Wifi) : 0;
            caps.PmCapabilities.MaxWoLPatternSize = patterns != 0 ? AP6256_WOL_PATTERN_BYTES : 0;
            caps.PmCapabilities.MaxWoLPatternOffset = 0;
            caps.PmCapabilities.MaxWoLPacketSaveBuffer =
                patterns != 0 ? AP6256_WOL_PATTERN_BYTES : 0;
            caps.PmCapabilities.SupportedProtocolOffloads = offloads;
            caps.PmCapabilities.NumArpOffloadIPv4Addresses =
                (offloads & NDIS_PM_PROTOCOL_OFFLOAD_ARP_SUPPORTED) != 0 ? AP6256_ARP_OFFLOAD_SLOTS
                                                                         : 0;
            caps.PmCapabilities.NumNSOffloadIPv6Addresses =
                (offloads & NDIS_PM_PROTOCOL_OFFLOAD_NS_SUPPORTED) != 0
                    ? AP6256_NS_OFFLOAD_ADDRESSES
                    : 0;
            caps.PmCapabilities.SupportedWakeUpEvents = wakeEvents;
            caps.PmCapabilities.MediaSpecificWakeUpEvents = mediaEvents;
        }

        TraceDiag("capabilities: wowl 0x%08X -> patterns 0x%08X, offloads "
                  "0x%08X, media wake 0x%08X\n",
                  wowl, patterns, offloads, mediaEvents);
    }

    Ap6256FillBandInfo(&bands[0], WDI_BAND_ID_2400, Ap6256Phy24, RTL_NUMBER_OF(Ap6256Phy24),
                       Ap6256ChannelMap24, RTL_NUMBER_OF(Ap6256ChannelMap24), Ap6256Widths24,
                       RTL_NUMBER_OF(Ap6256Widths24));
    Ap6256FillBandInfo(&bands[1], WDI_BAND_ID_5000, Ap6256Phy5, RTL_NUMBER_OF(Ap6256Phy5),
                       Ap6256ChannelMap5, RTL_NUMBER_OF(Ap6256ChannelMap5), Ap6256Widths5,
                       RTL_NUMBER_OF(Ap6256Widths5));
    caps.Optional.BandInfo_IsPresent = TRUE;
    caps.BandInfo.ElementCount = RTL_NUMBER_OF(bands);
    caps.BandInfo.pElements = bands;

    Ap6256FillPhyInfo(&phys[0], WDI_PHY_TYPE_HRDSSS, ratesB, Ap6256RatesB,
                      RTL_NUMBER_OF(Ap6256RatesB));
    Ap6256FillPhyInfo(&phys[1], WDI_PHY_TYPE_ERP, ratesOfdm, Ap6256RatesOfdm,
                      RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256FillPhyInfo(&phys[2], WDI_PHY_TYPE_OFDM, ratesOfdm, Ap6256RatesOfdm,
                      RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256FillPhyInfo(&phys[3], WDI_PHY_TYPE_HT, ratesOfdm, Ap6256RatesOfdm,
                      RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256FillPhyInfo(&phys[4], WDI_PHY_TYPE_VHT, ratesOfdm, Ap6256RatesOfdm,
                      RTL_NUMBER_OF(Ap6256RatesOfdm));
    caps.Optional.PhyInfo_IsPresent = TRUE;
    caps.PhyInfo.ElementCount = RTL_NUMBER_OF(phys);
    caps.PhyInfo.pElements = phys;

    ndisStatus = GenerateWdiGetAdapterCapabilities(&caps, 0, &Wifi->TlvContext, &generatedLength,
                                                   &generated);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(TRACE_NETADAPTER, "capability TLV generation failed 0x%08X\n", ndisStatus);
        Ap6256CompleteRequest(Wifi, Request, Ap6256NdisToNtStatus(ndisStatus));
        return;
    }

    if (outputLength >= generatedLength + sizeof(WDI_MESSAGE_HEADER)) {
        RtlCopyMemory((PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer +
                          sizeof(WDI_MESSAGE_HEADER),
                      generated, generatedLength);
        Request->DATA.METHOD_INFORMATION.BytesWritten =
            sizeof(WDI_MESSAGE_HEADER) + generatedLength;
        status = STATUS_SUCCESS;
        TraceInfo(TRACE_NETADAPTER, "adapter capabilities: %u TLV bytes\n", generatedLength);
    } else {
        Request->DATA.METHOD_INFORMATION.BytesNeeded = sizeof(WDI_MESSAGE_HEADER) + generatedLength;
        status = STATUS_BUFFER_TOO_SMALL;
        TraceWarn(TRACE_NETADAPTER, "capability buffer %u too small; %u needed\n", outputLength,
                  (ULONG)(sizeof(WDI_MESSAGE_HEADER) + generatedLength));
    }

    FreeGenerated(generated);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16 Ap6256RequestGetMessageId(_In_ AP6256_REQUEST Request)
{
    return (UINT16)(Request->DATA.METHOD_INFORMATION.Oid & 0xFFFF);
}

static VOID Ap6256CompleteQuery(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                _In_ NDIS_STATUS GenerateStatus, _In_opt_ UINT8* Generated,
                                _In_ ULONG GeneratedLength, _In_ PCSTR What)
{
    ULONG outputLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
    NTSTATUS status;

    if (GenerateStatus != NDIS_STATUS_SUCCESS || Generated == NULL) {
        TraceError(TRACE_NETADAPTER, "%s TLV generation failed 0x%08X\n", What, GenerateStatus);
        Ap6256CompleteRequest(Wifi, Request, Ap6256NdisToNtStatus(GenerateStatus));
        FreeGenerated(Generated);
        return;
    }

    if (outputLength >= GeneratedLength + sizeof(WDI_MESSAGE_HEADER)) {
        RtlCopyMemory((PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer +
                          sizeof(WDI_MESSAGE_HEADER),
                      Generated, GeneratedLength);
        Request->DATA.METHOD_INFORMATION.BytesWritten =
            sizeof(WDI_MESSAGE_HEADER) + GeneratedLength;
        status = STATUS_SUCCESS;
    } else {
        Request->DATA.METHOD_INFORMATION.BytesNeeded = sizeof(WDI_MESSAGE_HEADER) + GeneratedLength;
        status = STATUS_BUFFER_TOO_SMALL;
    }

    FreeGenerated(Generated);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256HandleGetNextActionFrameDialogToken(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request)
{
    WDI_GET_NEXT_ACTION_FRAME_DIALOG_TOKEN_PARAMETERS results;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    LONG token;

    RtlZeroMemory(&results, sizeof(results));

    token = InterlockedIncrement(&Wifi->NextActionFrameDialogToken) & 0xFF;
    if (token == 0) {
        token = InterlockedIncrement(&Wifi->NextActionFrameDialogToken) & 0xFF;
    }
    results.NextDialogToken = (UINT8)token;

    TraceInfo(TRACE_NETADAPTER, "next action-frame dialog token: %u\n",
              (ULONG)results.NextDialogToken);

    Ap6256CompleteQuery(Wifi, Request,
                        GenerateWdiGetNextActionFrameDialogToken(&results, 0, &Wifi->TlvContext,
                                                                 &generatedLength, &generated),
                        generated, generatedLength, "next action-frame dialog token");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleGetPmProtocolOffload(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
    const UCHAR* Tlv, ULONG TlvLength)
{
    UCHAR* generated = NULL;
    ULONG length = 0;
    NTSTATUS status = Ap6256GeneratePmOffload(Wifi, Tlv, TlvLength, &generated, &length);
    Ap6256CompleteQuery(Wifi, Request, Ap6256NtToNdisStatus(status),
        generated, length, "PM protocol offload");
}

_IRQL_requires_max_(PASSIVE_LEVEL)

VOID Ap6256HandleGetGroupStatistics(PAP6256_WIFI Wifi, AP6256_REQUEST Request)
{
    WDI_GET_STATISTICS_PARAMETERS result = {0};
    WDI_MAC_STATISTICS_CONTAINER peer = {0};
    WDI_PHY_STATISTICS_CONTAINER phy[AP6256_PHY_COUNT] = {0};
    WDI_PHY_STATISTICS_CONTAINER* current;
    UCHAR ifCounters[AP6256_IF_COUNTER_BYTES];
    UINT8* generated = NULL;
    ULONG length = 0;
    NDIS_STATUS status;
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    if (!ctx->Go.Created || !ctx->Go.FirmwareReady) {
        Ap6256CompleteRequest(Wifi, Request, STATUS_INVALID_DEVICE_STATE);
        return;
    }
    phy[AP6256_PHY_ID_HRDSSS].PhyType = WDI_PHY_TYPE_HRDSSS;
    phy[AP6256_PHY_ID_ERP].PhyType = WDI_PHY_TYPE_ERP;
    phy[AP6256_PHY_ID_OFDM].PhyType = WDI_PHY_TYPE_OFDM;
    phy[AP6256_PHY_ID_HT].PhyType = WDI_PHY_TYPE_HT;
    phy[AP6256_PHY_ID_VHT].PhyType = WDI_PHY_TYPE_VHT;
    current = &phy[ctx->Go.Channel <= 14 ? AP6256_PHY_ID_HT : AP6256_PHY_ID_VHT];
    if (ctx->Go.ClientConnected)
        RtlCopyMemory(peer.MACAddress.Address, ctx->Go.ClientBssid, 6);
    else
        RtlFillMemory(peer.MACAddress.Address, 6, 255);
    if (NT_SUCCESS(Ap6256WifiGetIfCountersIf(ctx, ctx->Go.IfIndex, ifCounters))) {
        peer.TransmittedFrameCount = AP6256_IF_U64(AP6256_IF_TX_FRAME);
        peer.ReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_FRAME);
        current->TransmittedFrameCount = AP6256_IF_U64(AP6256_IF_PHY_TX_FRAME);
        current->ReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_FRAME);
        current->GroupTransmittedFrameCount = AP6256_IF_U64(AP6256_IF_TX_MULTI);
        current->GroupReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_MULTI);
        current->FailedCount = AP6256_IF_U64(AP6256_IF_TX_FAIL);
        current->RetryCount = AP6256_IF_U64(AP6256_IF_TX_RETRY);
        current->MultipleRetryCount = AP6256_IF_U64(AP6256_IF_TX_RETRIES);
        current->TransmittedFragmentCount = AP6256_IF_U64(AP6256_IF_TX_FRAG);
    }
    result.PeerMACStatistics.ElementCount = 1;
    result.PeerMACStatistics.pElements = &peer;
    result.PhyStatistics.ElementCount = RTL_NUMBER_OF(phy);
    result.PhyStatistics.pElements = phy;
    status = GenerateWdiGetStatistics(&result, 0, &Wifi->TlvContext, &length, &generated);
    if (ctx->Go.ClientConnected)
        Ap6256ClientLinkState(Wifi);
    Ap6256CompleteQuery(Wifi, Request, status, generated, length, "P2P statistics");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleGetStatistics(_In_ PAP6256_WIFI Wifi,
                                                                  _In_ AP6256_REQUEST Request)
{
    static const UCHAR broadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    WDI_GET_STATISTICS_PARAMETERS results;
    WDI_MAC_STATISTICS_CONTAINER peer;
    WDI_PHY_STATISTICS_CONTAINER phy[AP6256_PHY_COUNT];
    UINT32 macCounters[AP6256_MAC_COUNTER_DWORDS];
    ULONG macCounterCount = 0;
    UCHAR ifCounters[AP6256_IF_COUNTER_BYTES];
    BOOLEAN haveMac;
    BOOLEAN haveIf;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    ULONG outputLength = Request->DATA.METHOD_INFORMATION.OutputBufferLength;
    NDIS_STATUS ndisStatus;
    NTSTATUS status;
    ULONG tx, rx, i;
    BOOLEAN haveBssid = FALSE;
    WDI_PHY_STATISTICS_CONTAINER* current;

    RtlZeroMemory(&results, sizeof(results));
    RtlZeroMemory(&peer, sizeof(peer));
    RtlZeroMemory(phy, sizeof(phy));

    haveMac =
        (BOOLEAN)(NT_SUCCESS(Ap6256WifiGetMacCounters(Wifi->Ctx, macCounters, &macCounterCount)) &&
                  macCounterCount > AP6256_CNT_TX_LIFETIME);
    haveIf = (BOOLEAN)NT_SUCCESS(Ap6256WifiGetIfCounters(Wifi->Ctx, ifCounters));

    if (Wifi->ConnectionActive) {
        Ap6256WifiTraceLinkRate(Wifi->Ctx);
    }

    tx = (ULONG)InterlockedCompareExchange(&Wifi->Ctx->TxFrames, 0, 0);
    rx = (ULONG)InterlockedCompareExchange(&Wifi->Ctx->RxFrames, 0, 0);

    for (i = 0; i < 6; i++) {
        if (Wifi->Ctx->TalBssid[i] != 0) {
            haveBssid = TRUE;
            break;
        }
    }
    RtlCopyMemory(peer.MACAddress.Address, haveBssid ? Wifi->Ctx->TalBssid : broadcast, 6);
    peer.TransmittedFrameCount = tx;
    peer.ReceivedFrameCount = rx;

    phy[AP6256_PHY_ID_HRDSSS].PhyType = WDI_PHY_TYPE_HRDSSS;
    phy[AP6256_PHY_ID_ERP].PhyType = WDI_PHY_TYPE_ERP;
    phy[AP6256_PHY_ID_OFDM].PhyType = WDI_PHY_TYPE_OFDM;
    phy[AP6256_PHY_ID_HT].PhyType = WDI_PHY_TYPE_HT;
    phy[AP6256_PHY_ID_VHT].PhyType = WDI_PHY_TYPE_VHT;

    current = &phy[Wifi->Ctx->TalPhyId < AP6256_PHY_COUNT ? Wifi->Ctx->TalPhyId : AP6256_PHY_ID_HT];
    current->TransmittedFrameCount = tx;
    current->ReceivedFrameCount = rx;

    {
        AP6256_PKT_COUNTS counts;
        UINT32 rateHalfMbps = 0;
        UINT32 maxRateHalfMbps = 0;
        INT32 noiseDbm = 0;

        if (NT_SUCCESS(Ap6256WifiGetPacketCounts(Wifi->Ctx, &counts))) {
            peer.TransmittedFrameCount = counts.TxGood;
            peer.ReceivedFrameCount = counts.RxGood;

            current->TransmittedFrameCount = counts.TxGood;
            current->ReceivedFrameCount = counts.RxGood;
            current->FailedCount = counts.TxBad;
            current->FCSErrorCount = counts.RxBad;
            current->PromiscuousReceivedFrameCount = counts.RxOtherCastGood;
        }

        if (haveMac) {
            peer.WEPExcludedCount = macCounters[AP6256_CNT_WEP_EXCLUDED];
            peer.TKIPLocalMICFailures = macCounters[AP6256_CNT_TKIP_MIC];
            peer.TKIPReplays = macCounters[AP6256_CNT_TKIP_REPLAY];
            peer.TKIPICVErrorCount = macCounters[AP6256_CNT_TKIP_ICV];
            peer.CCMPReplays = macCounters[AP6256_CNT_CCMP_REPLAY];

            peer.CCMPDecryptErrors = macCounters[AP6256_CNT_DECRYPT_ERR];
            peer.WEPUndecryptableCount = macCounters[AP6256_CNT_WEP_UNDECRYPTABLE];
            peer.WEPICVErrorCount = macCounters[AP6256_CNT_WEP_ICV];
            peer.DecryptSuccessCount = macCounters[AP6256_CNT_DECRYPT_OK];
            peer.DecryptFailureCount = macCounters[AP6256_CNT_DECRYPT_FAIL];

            peer.CCMPFormatErrors = macCounters[AP6256_CNT_CCMP_FORMAT];

            current->MaxTXLifetimeExceededCount = macCounters[AP6256_CNT_TX_LIFETIME];
            current->RTSSuccessCount = macCounters[AP6256_CNT_RTS_OK];
            current->RTSFailureCount = macCounters[AP6256_CNT_RTS_FAIL];
            current->ACKFailureCount = macCounters[AP6256_CNT_ACK_FAIL];
            current->FrameDuplicateCount = macCounters[AP6256_CNT_RX_DUP];
            current->ReceivedFragmentCount = macCounters[AP6256_CNT_RX_FRAG];
            current->FCSErrorCount = macCounters[AP6256_CNT_FCS_ERROR];
        }

        if (haveIf) {
            peer.TransmittedFrameCount = AP6256_IF_U64(AP6256_IF_TX_FRAME);
            peer.ReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_FRAME);

            current->TransmittedFrameCount = AP6256_IF_U64(AP6256_IF_PHY_TX_FRAME);
            current->GroupTransmittedFrameCount = AP6256_IF_U64(AP6256_IF_TX_MULTI);
            current->FailedCount = AP6256_IF_U64(AP6256_IF_TX_FAIL);
            current->RetryCount = AP6256_IF_U64(AP6256_IF_TX_RETRY);
            current->MultipleRetryCount = AP6256_IF_U64(AP6256_IF_TX_RETRIES);
            current->TransmittedFragmentCount = AP6256_IF_U64(AP6256_IF_TX_FRAG);
            current->ReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_FRAME);
            current->GroupReceivedFrameCount = AP6256_IF_U64(AP6256_IF_RX_MULTI);
        }

        (VOID) Ap6256WifiGetMaxLinkRate(Wifi->Ctx, &maxRateHalfMbps);
        (VOID) Ap6256WifiGetLinkRate(Wifi->Ctx, &rateHalfMbps);
        (VOID) Ap6256WifiGetPhyNoise(Wifi->Ctx, &noiseDbm);

        {
            INT32 linkRssi = 0;

            if (NT_SUCCESS(Ap6256WifiGetRssi(Wifi->Ctx, &linkRssi))) {
                if (linkRssi <= -100)
                    Wifi->Ctx->LastRssi = 0;
                else if (linkRssi >= -50)
                    Wifi->Ctx->LastRssi = 100;
                else
                    Wifi->Ctx->LastRssi = (UINT8)(2 * (linkRssi + 100));

                if (linkRssi < -128)
                    Wifi->Ctx->LastRssiDbm = (CHAR)-128;
                else if (linkRssi > 127)
                    Wifi->Ctx->LastRssiDbm = (CHAR)127;
                else
                    Wifi->Ctx->LastRssiDbm = (CHAR)linkRssi;
            }
        }

        TraceVerbose(TRACE_NETADAPTER,
                     "statistics: firmware tx %u/%u rx %u/%u ocast %u; "
                     "driver tx %u rx %u; rate %u.%u of %u.%u Mbps, "
                     "noise %d dBm\n",
                     counts.TxGood, counts.TxBad, counts.RxGood, counts.RxBad,
                     counts.RxOtherCastGood, tx, rx, rateHalfMbps / 2u, (rateHalfMbps % 2u) * 5u,
                     maxRateHalfMbps / 2u, (maxRateHalfMbps % 2u) * 5u, noiseDbm);
    }

    results.PeerMACStatistics.ElementCount = 1;
    results.PeerMACStatistics.pElements = &peer;
    results.PhyStatistics.ElementCount = AP6256_PHY_COUNT;
    results.PhyStatistics.pElements = phy;

    ndisStatus =
        GenerateWdiGetStatistics(&results, 0, &Wifi->TlvContext, &generatedLength, &generated);
    if (ndisStatus != NDIS_STATUS_SUCCESS) {
        TraceError(TRACE_NETADAPTER, "statistics TLV generation failed 0x%08X\n", ndisStatus);
        Ap6256CompleteRequest(Wifi, Request, Ap6256NdisToNtStatus(ndisStatus));
        return;
    }

    if (outputLength >= generatedLength + sizeof(WDI_MESSAGE_HEADER)) {
        RtlCopyMemory((PUCHAR)Request->DATA.METHOD_INFORMATION.InformationBuffer +
                          sizeof(WDI_MESSAGE_HEADER),
                      generated, generatedLength);
        Request->DATA.METHOD_INFORMATION.BytesWritten =
            sizeof(WDI_MESSAGE_HEADER) + generatedLength;
        status = STATUS_SUCCESS;
    } else {
        Request->DATA.METHOD_INFORMATION.BytesNeeded = sizeof(WDI_MESSAGE_HEADER) + generatedLength;
        status = STATUS_BUFFER_TOO_SMALL;
    }

    FreeGenerated(generated);
    Ap6256CompleteRequest(Wifi, Request, status);
}

static VOID Ap6256CommandWorker(PVOID Context)
{
    Ap6256DrainCommandQueue((PAP6256_WIFI)Context);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
Ap6256NetWdiOidRequest(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PNDIS_OID_REQUEST OidRequest)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    NTSTATUS status;

    TraceDiag("WDI receive OID 0x%08X, input %u, output %u, draining %ld\n",
              (ULONG)OidRequest->DATA.METHOD_INFORMATION.Oid,
              OidRequest->DATA.METHOD_INFORMATION.InputBufferLength,
              OidRequest->DATA.METHOD_INFORMATION.OutputBufferLength,
              wifi != NULL ? InterlockedCompareExchange(&wifi->CommandDraining, 0, 0) : 0);
    status = Ap6256QueueCommand(wifi, OidRequest);

    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "WDI command 0x%08X not queued 0x%08X\n",
                  (ULONG)OidRequest->DATA.METHOD_INFORMATION.Oid, status);
        return Ap6256NtToNdisStatus(status);
    }
    return NDIS_STATUS_PENDING;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetWdiCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi;
    NTSTATUS status;

    wifi = (PAP6256_WIFI)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*wifi), AP6256_POOL_TAG);
    if (wifi == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    wifi->Ctx = Ctx;
    KeInitializeSpinLock(&wifi->CommandLock);
    KeInitializeSpinLock(&wifi->LinkLock);
    Ap6256LockInit(&wifi->ActionFrameLock);
    Ap6256LockInit(&wifi->ConnectLock);
    Ap6256LockInit(&wifi->P2pLock);
    Ap6256LockInit(&wifi->Ftm.Lock);
    Ap6256LockInit(&wifi->Model.GroupLock);
    wifi->TlvContext.AllocationContext = 0;

    wifi->TlvContext.PeerVersion = min(Ctx->WdiOsVersion, AP6256_WDI_VERSION);
    TraceDiag("TLV contract: encoding at %u.%u.%u, OS reports %u.%u.%u\n",
              (ULONG)((wifi->TlvContext.PeerVersion >> 16) & 0xFF),
              (ULONG)((wifi->TlvContext.PeerVersion >> 8) & 0xFF),
              (ULONG)(wifi->TlvContext.PeerVersion & 0xFF),
              (ULONG)((Ctx->WdiOsVersion >> 16) & 0xFF), (ULONG)((Ctx->WdiOsVersion >> 8) & 0xFF),
              (ULONG)(Ctx->WdiOsVersion & 0xFF));

    wifi->SoftwareRadioState = TRUE;
    wifi->HardwareRadioState = TRUE;

    wifi->RxCoalesceMaxDelay = MAXULONG;

    status = Ap6256WorkItemCreate(&wifi->CommandWorkItem, Ctx->Fdo, Ap6256CommandWorker, wifi);
    if (NT_SUCCESS(status)) {
        status = Ap6256WorkItemCreate(&wifi->LinkWorkItem, Ctx->Fdo, Ap6256LinkWorker, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->Auth.SaeTimer, Ctx->Fdo, Ap6256StationSaeTimer, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->Ftm.Timer,Ctx->Fdo,Ap6256EvtFtmTick,wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->ScanTimer, Ctx->Fdo, Ap6256EvtScanTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->ConnectTimer, Ctx->Fdo, Ap6256EvtConnectTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status =
            Ap6256TimerCreate(&wifi->DisconnectTimer, Ctx->Fdo, Ap6256EvtDisconnectTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->Model.ClientConnectTimer, Ctx->Fdo,
                                   Ap6256EvtClientConnectTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status =
            Ap6256TimerCreate(&wifi->Model.ApAssocTimer, Ctx->Fdo, Ap6256EvtApAssocTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status =
            Ap6256TimerCreate(&wifi->ActionFrameTimer, Ctx->Fdo, Ap6256EvtActionFrameTimeout, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256WorkItemCreate(&wifi->ActionFrameCompleteWorker, Ctx->Fdo,
                                      Ap6256ActionFrameCompleteWorker, wifi);
    }
    if (NT_SUCCESS(status)) {
        status =
            Ap6256TimerCreate(&wifi->P2pDiscoverTimer, Ctx->Fdo, Ap6256EvtP2pDiscoverTick, wifi);
    }
    if (NT_SUCCESS(status)) {
        status = Ap6256TimerCreate(&wifi->P2pListenTimer, Ctx->Fdo, Ap6256EvtP2pListenTick, wifi);
    }
    if (!NT_SUCCESS(status)) {
        Ap6256TimerDestroy(&wifi->Ftm.Timer);
        Ap6256TimerDestroy(&wifi->P2pListenTimer);
        Ap6256TimerDestroy(&wifi->P2pDiscoverTimer);
        Ap6256WorkItemDestroy(&wifi->ActionFrameCompleteWorker);
        Ap6256TimerDestroy(&wifi->Model.ClientConnectTimer);
        Ap6256TimerDestroy(&wifi->Model.ApAssocTimer);
        Ap6256TimerDestroy(&wifi->ActionFrameTimer);
        Ap6256TimerDestroy(&wifi->DisconnectTimer);
        Ap6256TimerDestroy(&wifi->ConnectTimer);
        Ap6256TimerDestroy(&wifi->Auth.SaeTimer);
        Ap6256TimerDestroy(&wifi->ScanTimer);
        Ap6256WorkItemDestroy(&wifi->LinkWorkItem);
        Ap6256WorkItemDestroy(&wifi->CommandWorkItem);
        ExFreePoolWithTag(wifi, AP6256_POOL_TAG);
        return status;
    }

    InterlockedExchangePointer((PVOID volatile*)&Ctx->NetAdapter, wifi);
    TraceInfo(TRACE_NETADAPTER, "WDI adapter state ready\n");
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetWdiDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi;
    AP6256_REQUEST pending[AP6256_CMDQ_DEPTH];
    ULONG count = 0;
    ULONG index;
    KIRQL oldIrql;

    wifi = (PAP6256_WIFI)InterlockedExchangePointer((PVOID volatile*)&Ctx->NetAdapter, NULL);
    if (wifi == NULL) {
        return;
    }

    InterlockedExchange(&wifi->Stopping, 1);
    (VOID)Ap6256FtmCancel(wifi,FALSE,0,0,STATUS_CANCELLED);
    AP6256_TIMER_STOP(wifi->P2pDiscoverTimer, TRUE);
    AP6256_TIMER_STOP(wifi->P2pListenTimer, TRUE);
    Ap6256LockAcquire(&wifi->P2pLock);
    Ap6256ServiceStop(wifi, TRUE);
    wifi->P2pDiscovering = FALSE;
    wifi->Ctx->P2p.Listening = FALSE;
    wifi->Ctx->P2p.DiscoverPhase = Ap6256P2pDiscoverIdle;
    InterlockedExchange(&wifi->Ctx->P2p.DiscoverScanPending, 0);
    AP6256_TIMER_STOP(wifi->P2pListenTimer, FALSE);
    AP6256_TIMER_STOP(wifi->P2pDiscoverTimer, FALSE);
    Ap6256LockRelease(&wifi->P2pLock);
    AP6256_TIMER_STOP(wifi->Auth.SaeTimer, TRUE);
    AP6256_TIMER_STOP(wifi->ScanTimer, TRUE);
    AP6256_TIMER_STOP(wifi->ConnectTimer, TRUE);
    AP6256_TIMER_STOP(wifi->DisconnectTimer, TRUE);
    AP6256_TIMER_STOP(wifi->Model.ClientConnectTimer, TRUE);
    AP6256_TIMER_STOP(wifi->Model.ApAssocTimer, TRUE);
    AP6256_TIMER_STOP(wifi->ActionFrameTimer, TRUE);
    AP6256_TIMER_STOP(wifi->P2pDiscoverTimer, TRUE);

    Ap6256WorkItemFlush(&wifi->LinkWorkItem);
    Ap6256WorkItemFlush(&wifi->CommandWorkItem);
    Ap6256WorkItemFlush(&wifi->ActionFrameCompleteWorker);
    Ap6256ClearGoEvents(wifi);
    Ap6256ForgetGoAutoAssoc(wifi, NULL);

    Ap6256LockAcquire(&wifi->ConnectLock);
    (VOID) Ap6256FtEnd(wifi->Ctx, &wifi->Auth.Ft, FALSE);
    (VOID) Ap6256OweEnd(wifi->Ctx, FALSE);
    Ap6256FtConnectionLost(&wifi->Auth.Ft);
    Ap6256LockRelease(&wifi->ConnectLock);

    while (wifi->Auth.FtTail != wifi->Auth.FtHead) {
        AP6256_FT_EVENT* event =
            wifi->Auth.FtEvents[wifi->Auth.FtTail++ % RTL_NUMBER_OF(wifi->Auth.FtEvents)];
        ExFreePoolWithTag(event, AP6256_POOL_TAG);
    }

    KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
    while (wifi->CommandTail != wifi->CommandHead && count < RTL_NUMBER_OF(pending)) {
        pending[count++] = wifi->CommandPending[wifi->CommandTail & (AP6256_CMDQ_DEPTH - 1)];
        wifi->CommandTail++;
    }
    wifi->ScanTask.Active = FALSE;
    wifi->ConnectTask.Active = FALSE;
    wifi->Model.ClientConnectTask.Active = FALSE;
    wifi->DisconnectTask.Active = FALSE;
    KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

    for (index = 0; index < count; index++) {
        Ap6256CompleteRequest(wifi, pending[index], STATUS_CANCELLED);
    }

    for (index = 0; index < AP6256_RX_COALESCE_FILTERS; index++) {
        if (wifi->RxCoalesceFilters[index].Fields != NULL) {
            ExFreePoolWithTag(wifi->RxCoalesceFilters[index].Fields, AP6256_POOL_TAG);
            wifi->RxCoalesceFilters[index].Fields = NULL;
        }
    }

    Ap6256LockAcquire(&wifi->ActionFrameLock);
    Ap6256FreeActionFrame(wifi);
    Ap6256LockRelease(&wifi->ActionFrameLock);
    Ap6256P2pReleaseIesFor(wifi->Ctx, &wifi->Ctx->Go.P2p, wifi->Ctx->Go.IfIndex);
    Ap6256P2pReleaseIes(wifi->Ctx);
    Ap6256P2pForgetIesFor(&wifi->Ctx->Go.P2p);
    Ap6256P2pForgetIesFor(&wifi->Ctx->P2p);

    Ap6256TimerDestroy(&wifi->P2pListenTimer);
    Ap6256TimerDestroy(&wifi->P2pDiscoverTimer);
    Ap6256WorkItemDestroy(&wifi->ActionFrameCompleteWorker);
    Ap6256TimerDestroy(&wifi->Ftm.Timer);
    Ap6256TimerDestroy(&wifi->Model.ClientConnectTimer);
    Ap6256TimerDestroy(&wifi->Model.ApAssocTimer);
    Ap6256TimerDestroy(&wifi->ActionFrameTimer);
    Ap6256TimerDestroy(&wifi->DisconnectTimer);
    Ap6256TimerDestroy(&wifi->ConnectTimer);
    Ap6256TimerDestroy(&wifi->Auth.SaeTimer);
    Ap6256TimerDestroy(&wifi->ScanTimer);
    Ap6256WorkItemDestroy(&wifi->LinkWorkItem);
    Ap6256WorkItemDestroy(&wifi->CommandWorkItem);
    ExFreePoolWithTag(wifi, AP6256_POOL_TAG);
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
        status = Wifi->Model.ClientConnectTask.Active ? STATUS_DEVICE_BUSY
                                                      : Ap6256GroupChangeMode(Wifi->Ctx, wdiMode);
        if (NT_SUCCESS(status))
            InterlockedIncrement(&Wifi->Model.GroupGeneration);
        else if (Wifi->Ctx->Go.NativeStateUncertain && Wifi->HardwareAvailable)
            Ap6256NetFirmwareHalted(Wifi->Ctx);
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
    Ap6256TalGoPeerDelete(Wifi->Ctx, NULL);
}

_Use_decl_annotations_
VOID Ap6256ModelGroupAddressChanged(PAP6256_WIFI Wifi)
{

    UNREFERENCED_PARAMETER(Wifi);
}

VOID Ap6256ModelResetGroupPeers(PAP6256_WIFI Wifi)
{

    Ap6256CancelGoAssociation(Wifi, STATUS_CANCELLED);
    Ap6256TalGoPeerDelete(Wifi->Ctx, NULL);
}

NTSTATUS Ap6256ModelResetGroup(PAP6256_WIFI Wifi)
{

    NTSTATUS status;
    status = Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT
                 ? Ap6256CancelClient(Wifi, STATUS_CANCELLED, 3)
                 : Ap6256GoStop(Wifi->Ctx);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256ModelResetGroupAddress(PAP6256_WIFI Wifi, const UCHAR* Address)
{
    NTSTATUS status = Ap6256GoDelete(Wifi->Ctx);
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(Wifi->Ctx->Go.Address, Address, 6);
        status = Ap6256GoCreate(Wifi->Ctx);
        if (NT_SUCCESS(status)) Ap6256ModelGroupAddressChanged(Wifi);
    }
    return status;
}

VOID Ap6256ModelStopApPeers(PAP6256_WIFI Wifi, NTSTATUS status)
{

    if (NT_SUCCESS(status)) {
        Ap6256CancelGoAssociation(Wifi, STATUS_CANCELLED);
        Ap6256TalGoPeerDelete(Wifi->Ctx, NULL);
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
    }
}

NTSTATUS Ap6256ModelStartApBegin(PAP6256_WIFI Wifi)
{
    UNREFERENCED_PARAMETER(Wifi);
    return STATUS_SUCCESS;
}

VOID Ap6256ModelStartApEnd(PAP6256_WIFI Wifi)
{
    UNREFERENCED_PARAMETER(Wifi);
}

NTSTATUS Ap6256ModelStartApHardware(PAP6256_WIFI Wifi, PAP6256_AP_PARAMS Params)
{
    NTSTATUS status = Ap6256GoStart(Wifi->Ctx, Params);
    if (!NT_SUCCESS(status)) (VOID) Ap6256GoStop(Wifi->Ctx);
    return status;
}

VOID Ap6256ModelStartApCompleted(PAP6256_WIFI Wifi, NTSTATUS StartStatus, NTSTATUS CompletionStatus)
{
    UNREFERENCED_PARAMETER(Wifi);
    UNREFERENCED_PARAMETER(StartStatus);
    UNREFERENCED_PARAMETER(CompletionStatus);
}

NTSTATUS Ap6256ModelStartApPeer(PAP6256_WIFI Wifi, NTSTATUS status)
{

    if (NT_SUCCESS(status)) {
        const UCHAR multicast[6] = {255, 255, 255, 255, 255, 255};
        if (!Ap6256TalGoPeerCreate(Wifi->Ctx, multicast, 0)) {
            (VOID) Ap6256GoStop(Wifi->Ctx);
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    return status;
}

NTSTATUS Ap6256ModelStartInterfaces(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx)
{

    NTSTATUS status = STATUS_SUCCESS;
    if (Wifi->P2pPortCreated) {
        status = Ap6256WifiP2pSetDiscoveryInterface(Ctx, TRUE, NULL);
        if (!NT_SUCCESS(status))
            return status;
    }
    if (Ctx->Go.Created) {
        status = Ap6256GoCreate(Ctx);
        if (!NT_SUCCESS(status))
            return status;
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
    Ap6256TalGoPeerDelete(Ctx, NULL);
    AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, FALSE);
    Ap6256FailStartedTask(Wifi, &Wifi->ApAssocTask,
                          WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,
                          STATUS_CONNECTION_DISCONNECTED);
}

VOID Ap6256ModelDeleteStationPeer(PAP6256_WIFI Wifi)
{

    Ap6256TalSetBssid(Wifi->Ctx, NULL);

    Ap6256TalPeerDelete(Wifi->Ctx);
}

BOOLEAN Ap6256ModelClientLinkEvent(PAP6256_WIFI Wifi, UCHAR code, LONG generation)
{

    if (code == AP6256_LINK_CLIENT_UP || code == AP6256_LINK_CLIENT_DOWN) {
        Ap6256ClientLinkWork(Wifi, code == AP6256_LINK_CLIENT_UP, generation);
        return TRUE;
    }
    return FALSE;
}

VOID Ap6256ModelSetLinkState(PAP6256_WIFI Wifi, BOOLEAN LinkUp)
{
    UNREFERENCED_PARAMETER(Wifi);
    UNREFERENCED_PARAMETER(LinkUp);
}

VOID Ap6256ModelOpenStationReceive(PAP6256_WIFI Wifi, BOOLEAN associated)
{

    if (associated)
        Ap6256TalRxOpen(Wifi->Ctx);
}

BOOLEAN Ap6256ModelLinkUsable(PAP6256_WIFI Wifi)
{
    UNREFERENCED_PARAMETER(Wifi);
    return TRUE;
}

BOOLEAN Ap6256ModelDispatchCommand(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                   PWDI_MESSAGE_HEADER header, const UCHAR* tlv, ULONG tlvLength,
                                   UINT16 messageId)
{
    switch (messageId) {
    case WDI_SET_POWER_STATE:
        Ap6256HandlePowerRequest(Wifi, Request, tlv, tlvLength);
        return TRUE;
    case WDI_GET_ADAPTER_CAPABILITIES:

        Ap6256HandleGetCapabilities(Wifi, Request);
        return TRUE;
    case WDI_GET_STATISTICS:
        if (header->PortId == AP6256_GROUP_PORT)
            Ap6256HandleGetGroupStatistics(Wifi, Request);
        else
            Ap6256HandleGetStatistics(Wifi, Request);
        return TRUE;
    case WDI_GET_NEXT_ACTION_FRAME_DIALOG_TOKEN:
        Ap6256HandleGetNextActionFrameDialogToken(Wifi, Request);
        return TRUE;
    case WDI_GET_PM_PROTOCOL_OFFLOAD:
        Ap6256HandleGetPmProtocolOffload(Wifi, Request, tlv, tlvLength);
        return TRUE;
    case WDI_GET_AUTO_POWER_SAVE:
        {
            UCHAR* generated = NULL;
            ULONG length = 0;
            NTSTATUS status = Ap6256GeneratePowerSave(Wifi, header->PortId, &generated, &length);
            Ap6256CompleteQuery(Wifi, Request, Ap6256NtToNdisStatus(status),
                                generated, length, "auto power save");
        }
        return TRUE;
    default:
        return FALSE;
    }
}

static VOID Ap6256EvtScanTimeout(_In_ PVOID Context)
{
    Ap6256OnScanTimeout(Context);
}

static VOID Ap6256EvtConnectTimeout(_In_ PVOID Context)
{
    Ap6256OnConnectTimeout(Context);
}

static VOID Ap6256EvtDisconnectTimeout(_In_ PVOID Context)
{
    Ap6256OnDisconnectTimeout(Context);
}

static VOID Ap6256EvtActionFrameTimeout(_In_ PVOID Context)
{
    Ap6256OnActionFrameTimeout(Context);
}

static VOID Ap6256EvtP2pDiscoverTick(_In_ PVOID Context)
{
    Ap6256OnP2pDiscoverTick(Context);
}

static VOID Ap6256EvtP2pListenTick(PVOID Context)
{
    Ap6256OnP2pListenTick(Context);
}
static VOID Ap6256EvtFtmTick(PVOID Context) { Ap6256OnFtmTick(Context); }

VOID Ap6256ModelSetStationBssid(PAP6256_WIFI Wifi, const UCHAR* Bssid)
{
    Ap6256TalSetBssid(Wifi->Ctx, Bssid);
}

BOOLEAN Ap6256ModelCreateStationPeer(PAP6256_WIFI Wifi, const UCHAR* Bssid)
{
    return Ap6256TalPeerCreate(Wifi->Ctx, Bssid);
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
    if (!wifi->Stopping && wifi->HardwareAvailable) {
        if (lost) {
            TraceDiag("hotspot: GO event queue lost state; stopping AP\n");
            Ap6256ClearGoEvents(wifi);
            (VOID) Ap6256GoStop(wifi->Ctx);
            Ap6256NetApStopped(wifi->Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
        } else Ap6256ProcessGoEvent(wifi, Event);
    } else if (lost) Ap6256ClearGoEvents(wifi);
    if (Event != NULL) ExFreePoolWithTag(Event, AP6256_POOL_TAG);
}

VOID Ap6256ModelUpdateReceiveContext(PAP6256_WIFI Wifi)
{

        INT32 rssiDbm = 0;

        if (NT_SUCCESS(Ap6256WifiGetRssi(Wifi->Ctx, &rssiDbm))) {
            UINT8 quality;

            if (rssiDbm <= -100)
                quality = 0;
            else if (rssiDbm >= -50)
                quality = 100;
            else
                quality = (UINT8)(2 * (rssiDbm + 100));

            Wifi->Ctx->LastRssi = quality;

            if (rssiDbm < -128)
                Wifi->Ctx->LastRssiDbm = (CHAR)-128;
            else if (rssiDbm > 127)
                Wifi->Ctx->LastRssiDbm = (CHAR)127;
            else
                Wifi->Ctx->LastRssiDbm = (CHAR)rssiDbm;

            TraceInfo(TRACE_NETADAPTER, "link signal %d dBm -> PPDU RSSI %d dBm, link quality %u\n",
                      rssiDbm, (LONG)Wifi->Ctx->LastRssiDbm, (ULONG)quality);
        }

        {
            WDI_CHANNEL_NUMBER ch = Wifi->ConnectChannel;

            if (ch == 0) {
                Wifi->Ctx->TalPhyId = AP6256_PHY_ID_HT;
                Wifi->Ctx->TalChannelFreq = 0;
            } else if (ch <= 14) {
                Wifi->Ctx->TalPhyId = AP6256_PHY_ID_HT;
                Wifi->Ctx->TalChannelFreq = (ch == 14) ? 2484u : (2412u + ((ULONG)ch - 1u) * 5u);
            } else {
                Wifi->Ctx->TalPhyId = AP6256_PHY_ID_VHT;
                Wifi->Ctx->TalChannelFreq = 5000u + (ULONG)ch * 5u;
            }

            TraceDiag("receive context: phy id %u, channel %u -> %u MHz\n", Wifi->Ctx->TalPhyId,
                      (ULONG)ch, Wifi->Ctx->TalChannelFreq);
        }

}
