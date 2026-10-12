/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"
#include "../common/native_frame.inc"
#include "host_fips.h"
#include "host_cipher_transport.h"

_Use_decl_annotations_
VOID Ap6256NetFirmwareHalted(PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER header;
    NTSTATUS status;
    if (wifi == NULL || wifi->Stopping) return;
    InterlockedExchange(&wifi->HardwareAvailable, 0);
    RtlZeroMemory(&header, sizeof(header));
    header.PortId = 0xffff;
    status = Ap6256SendIndicationRq(wifi, WDI_INDICATION_FIRMWARE_STALLED,
        &header, 0, NULL, STATUS_SUCCESS, NULL, 0);
    TraceDiag("firmware stalled: WiFiCx adapter indication status 0x%08X\n", status);
}
#include "capability_tables.h"

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AP6256_WIFI, Ap6256GetWifiContext)
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AP6256_QUEUE_CONTEXT, Ap6256GetQueueContext)

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AP6256_CX_ADAPTER, Ap6256GetRoleContext)
static EVT_WDF_OBJECT_CONTEXT_CLEANUP Ap6256EvtEngineCleanup;
static EVT_WDF_TIMER Ap6256EvtApAssocTimeout, Ap6256EvtClientConnectTimeout;
static BOOLEAN Ap6256CxGroupPeerCreate(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address, UINT32 Phy);
static VOID Ap6256CxGroupPeerDelete(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address);
static VOID Ap6256CxGroupRxOpen(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address);
static BOOLEAN Ap6256ClientAssociation(PAP6256_WIFI Wifi, const WDI_MESSAGE_HEADER* Header, PVOID RequestId, BOOLEAN Success);
static VOID Ap6256ClientLinkState(PAP6256_WIFI Wifi);
static NTSTATUS Ap6256ClientStartAttempt(PAP6256_WIFI Wifi);
static VOID Ap6256ClientAttemptResult(PAP6256_WIFI Wifi, BOOLEAN Up, NTSTATUS FailureStatus);
static VOID Ap6256GoIndicateDisassociation(PAP6256_WIFI Wifi, const UCHAR* Address, UINT16 Reason);
static VOID Ap6256ProcessGoEvent(PAP6256_WIFI Wifi, const AP6256_GO_EVENT* Event);
static VOID Ap6256OnApAssocTimeout(PAP6256_WIFI Wifi);
static VOID Ap6256OnClientConnectTimeout(PAP6256_WIFI Wifi);
VOID Ap6256ClearGoEvents(PAP6256_WIFI Wifi);
VOID Ap6256ForgetGoAutoAssoc(PAP6256_WIFI Wifi, const UCHAR* Address);
VOID Ap6256CancelGoAssociation(PAP6256_WIFI Wifi, NTSTATUS Status);
NTSTATUS Ap6256CancelClient(PAP6256_WIFI Wifi, NTSTATUS Status, UINT32 Reason);
static NTSTATUS Ap6256CxPrepareTx(PAP6256_QUEUE_CONTEXT Queue, NET_PACKET_WIFI_EXEMPTION_ACTION* Exemption, PAP6256_FRAME Frame);
static NTSTATUS Ap6256CxTransmit(PAP6256_QUEUE_CONTEXT Queue, PAP6256_FRAME Frame);
static BOOLEAN Ap6256CxFrameCurrent(PAP6256_CX_ADAPTER Role, const AP6256_FRAME* Frame);
static NTSTATUS Ap6256CxEncapsulateRx(PAP6256_CX_ADAPTER Role, const AP6256_FRAME* Frame,
    PUCHAR Out, ULONG Capacity, PULONG OutLength, PULONG HeaderLength);
static VOID Ap6256CxNotifyTx(PAP6256_QUEUE_CONTEXT Queue);
static VOID Ap6256CxFlushTxWorkers(PAP6256_WIFI Wifi);
static VOID Ap6256CxUnpublishQueue(PAP6256_QUEUE_CONTEXT Queue);
static VOID Ap6256CxStopQueue(PAP6256_QUEUE_CONTEXT Queue);
static VOID Ap6256CxQueueTx(PAP6256_QUEUE_CONTEXT Queue);
static VOID Ap6256CxQuiesceRole(PAP6256_WIFI Wifi, UINT16 Port);
static PAP6256_CX_ADAPTER Ap6256CxAcquireRole(PAP6256_WIFI Wifi, UINT16 Port);
static NTSTATUS Ap6256CxInternalPort(PAP6256_WIFI Wifi, UINT32 External, WDI_PORT_ID* Internal);
static VOID Ap6256CxSetRoleLink(PAP6256_WIFI Wifi, UINT16 Port, BOOLEAN Up);

typedef struct _AP6256_WFD_CONTEXT { PAP6256_DEVICE_CONTEXT Ctx; } AP6256_WFD_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(AP6256_WFD_CONTEXT, Ap6256GetWfdContext)
static EVT_WDF_OBJECT_CONTEXT_CLEANUP Ap6256EvtWfdCleanup;

static WDI_PORT_ID Ap6256WifiCxExternalPort(PAP6256_DEVICE_CONTEXT Ctx,WDI_PORT_ID Port)
{
    if (Port==AP6256_STATION_PORT) return Ctx->WifiStationPortId;
    if (Port==AP6256_DISCOVERY_PORT) return Ctx->WifiDirectPortId;
    if (Port==AP6256_GROUP_PORT) return Ctx->WifiGroupPortId;
    return Port;
}

static EVT_PACKET_QUEUE_ADVANCE Ap6256EvtTxAdvance;
static EVT_PACKET_QUEUE_ADVANCE Ap6256EvtRxAdvance;
static EVT_PACKET_QUEUE_SET_NOTIFICATION_ENABLED Ap6256EvtQueueSetNotify;
static EVT_PACKET_QUEUE_START Ap6256EvtQueueStart;
static EVT_PACKET_QUEUE_STOP Ap6256EvtQueueStop;
static EVT_PACKET_QUEUE_CANCEL Ap6256EvtTxCancel;
static EVT_PACKET_QUEUE_CANCEL Ap6256EvtRxCancel;
static EVT_NET_ADAPTER_CREATE_TXQUEUE Ap6256EvtCreateTxQueue;
static EVT_NET_ADAPTER_CREATE_RXQUEUE Ap6256EvtCreateRxQueue;
static EVT_WDF_WORKITEM Ap6256EvtTxWorkItem;
static EVT_WDF_WORKITEM Ap6256EvtCommandWorkItem;
static EVT_WDF_WORKITEM Ap6256EvtLinkWorkItem;
static EVT_WDF_WORKITEM Ap6256EvtActionFrameCompleteWorkItem;
static EVT_WDF_TIMER Ap6256EvtScanTimeout;
static EVT_WDF_TIMER Ap6256EvtConnectTimeout;
static EVT_WDF_TIMER Ap6256EvtDisconnectTimeout;
static EVT_WDF_TIMER Ap6256EvtActionFrameTimeout;
static EVT_WDF_TIMER Ap6256EvtP2pDiscoverTick;
static EVT_WDF_TIMER Ap6256EvtP2pListenTick;
static EVT_WDF_TIMER Ap6256EvtFtmTick;
static EVT_WDF_OBJECT_CONTEXT_CLEANUP Ap6256EvtAdapterCleanup;
static EVT_WIFI_DEVICE_SEND_COMMAND Ap6256EvtWifiSendCommand;
static EVT_WIFI_DEVICE_CREATE_ADAPTER Ap6256EvtWifiCreateAdapter;
static EVT_WIFI_DEVICE_CREATE_WIFIDIRECTDEVICE Ap6256EvtWifiCreateWfdDevice;

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_reads_bytes_(Length) PUCHAR Frame,
                                                            _In_ ULONG Length, _In_ UCHAR Priority,
                                                            _In_ UINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetHardwareStop(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ NTSTATUS CompletionStatus,
                                                              _In_ BOOLEAN OnCommandWorker);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetTxKick(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)

static NTSTATUS
Ap6256CopyTxPacket(_In_ PAP6256_QUEUE_CONTEXT QueueContext, _In_ NET_RING const* FragmentRing,
                   _In_ NET_PACKET const* Packet, _Out_ PAP6256_FRAME Frame,
                   _Out_ PUINT32 NextFragmentIndex);
static VOID Ap6256SetPhyInfo(_Out_ WIFI_PHY_INFO* PhyInfo, _In_ WDI_PHY_TYPE PhyType,
                             _In_reads_(RateCount) const UINT16* Rates, _In_ ULONG RateCount);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256SetWifiCapabilities(_In_ WDFDEVICE Device);
static EVT_WDF_TIMER Ap6256EvtSaeTimeout;
_Use_decl_annotations_
static VOID Ap6256EvtWfdCleanup(WDFOBJECT Object)
{
    PAP6256_DEVICE_CONTEXT ctx=Ap6256GetWfdContext(Object)->Ctx;
    PAP6256_WIFI wifi;
    if (!ctx) return;
    wifi=Ap6256WifiFromDevice(ctx);
    if (wifi && !wifi->Stopping) {
        AP6256_TIMER_STOP(wifi->P2pListenTimer,TRUE);
        AP6256_TIMER_STOP(wifi->P2pDiscoverTimer,TRUE);
        Ap6256LockAcquire(&wifi->P2pLock);
        wifi->P2pDiscovering=FALSE;ctx->P2p.Listening=FALSE;
        if (wifi->HardwareAvailable) Ap6256P2pStopDiscovery(ctx);
        Ap6256ServiceStop(wifi,TRUE);
        Ap6256FailStartedTask(wifi,&wifi->P2pDiscoverTask,WDI_INDICATION_P2P_DISCOVERY_COMPLETE,STATUS_CANCELLED);
        if (wifi->HardwareAvailable) (VOID)Ap6256WifiP2pSetDiscoveryInterface(ctx,FALSE,NULL);
        wifi->P2pPortCreated=FALSE;wifi->P2pPortMode=0;
        Ap6256LockRelease(&wifi->P2pLock);
    }
    ctx->WifiDirectDevice=NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256NetDeviceInitConfig(_In_ PWDFDEVICE_INIT DeviceInit);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetAdapterCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx);

PVOID Ap6256RequestGetId(_In_ AP6256_REQUEST Request)
{
    UNREFERENCED_PARAMETER(Request);
    return NULL;
}

PAP6256_WIFI Ap6256WifiFromDevice(PAP6256_DEVICE_CONTEXT Ctx)
{
    WDFOBJECT engine = (WDFOBJECT)InterlockedCompareExchangePointer((PVOID volatile*)&Ctx->WifiEngine, NULL, NULL);
    return engine ? Ap6256GetWifiContext(engine) : NULL;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256CompleteRequest(_In_opt_ PAP6256_WIFI Wifi,
                                                               _In_ AP6256_REQUEST Request,
                                                               _In_ NTSTATUS Status)
{
    if (Wifi) {
        UINT input=0,output=0;PWDI_MESSAGE_HEADER h=(PWDI_MESSAGE_HEADER)WifiRequestGetInOutBuffer(Request,&input,&output);
        if (h && input>=sizeof(*h) && output>=sizeof(*h))
            h->PortId=Ap6256WifiCxExternalPort(Wifi->Ctx,h->PortId);
    }
    WifiRequestComplete(Request, Status, NT_SUCCESS(Status) ? sizeof(WDI_MESSAGE_HEADER) : 0);
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
    WDF_OBJECT_ATTRIBUTES attributes;
    WDFMEMORY memory;
    NTSTATUS status;

    if (OriginalHeader == NULL || TlvLength > MAXULONG - sizeof(WDI_MESSAGE_HEADER) ||
        (TlvLength != 0 && Tlv == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    total = sizeof(WDI_MESSAGE_HEADER) + (SIZE_T)TlvLength;

    WDF_OBJECT_ATTRIBUTES_INIT(&attributes);
    attributes.ParentObject = Wifi->Ctx->Device;
    status = WdfMemoryCreate(&attributes, NonPagedPoolNx, AP6256_POOL_TAG, total, &memory,
                             (PVOID*)&buffer);
    if (!NT_SUCCESS(status))
        return status;

    RtlZeroMemory(buffer, total);
    header = (PWDI_MESSAGE_HEADER)buffer;
    header->PortId = Ap6256WifiCxExternalPort(Wifi->Ctx,OriginalHeader->PortId);
    header->Reserved = OriginalHeader->Reserved;
    header->Status = Ap6256NtToNdisStatus(CompletionStatus);
    header->TransactionId = TransactionId;
    header->IhvSpecificId = OriginalHeader->IhvSpecificId;
    if (TlvLength != 0) {
        RtlCopyMemory(buffer + sizeof(*header), Tlv, TlvLength);
    }

    UNREFERENCED_PARAMETER(RequestId);
    WifiDeviceReceiveIndication(Wifi->Ctx->Device, MessageId, memory);
    WdfObjectDelete(memory);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)

_Use_decl_annotations_
static VOID Ap6256EvtActionFrameCompleteWorkItem(WDFWORKITEM WorkItem)
{
    NETADAPTER adapter = (NETADAPTER)WdfWorkItemGetParentObject(WorkItem);
    PAP6256_WIFI wifi = Ap6256GetWifiContext(adapter);
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

_Use_decl_annotations_
static VOID Ap6256EvtLinkWorkItem(WDFWORKITEM WorkItem)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext((NETADAPTER)WdfWorkItemGetParentObject(WorkItem));

    if (wifi != NULL) {
        Ap6256LinkWork(wifi);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    NET_ADAPTER_LINK_LAYER_ADDRESS address;

    if (wifi == NULL || wifi->Model.Adapter == NULL)
        return;
    NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(&address, sizeof(Ctx->MacAddress), Ctx->MacAddress);
    NetAdapterSetCurrentLinkLayerAddress(wifi->Model.Adapter, &address);
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
    NET_ADAPTER_LINK_STATE state;
    KIRQL oldIrql;

    if (wifi == NULL)
        return;
    InterlockedExchange(&wifi->HardwareAvailable, 0);
    RtlZeroMemory(&scanHeader, sizeof(scanHeader));
    RtlZeroMemory(&connectHeader, sizeof(connectHeader));
    RtlZeroMemory(&disconnectHeader, sizeof(disconnectHeader));
    RtlZeroMemory(&indicationHeader, sizeof(indicationHeader));

    if (wifi->LinkWorkItem != NULL)
        WdfWorkItemFlush(wifi->LinkWorkItem);
    if (!OnCommandWorker && wifi->CommandWorkItem != NULL) {
        WdfWorkItemFlush(wifi->CommandWorkItem);
    }
    Ap6256CxFlushTxWorkers(wifi);
    Ap6256ModelDeleteStationPeer(wifi);
    Ap6256CxQuiesceRole(wifi, AP6256_GROUP_PORT);
    (VOID)Ap6256CancelClient(wifi, CompletionStatus, 3);
    Ap6256CancelGoAssociation(wifi, CompletionStatus);
    Ap6256CxGroupPeerDelete(Ctx, NULL);

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
    NET_ADAPTER_LINK_STATE_INIT_DISCONNECTED(&state);
    if (wifi->Model.Adapter) NetAdapterSetLinkState(wifi->Model.Adapter, &state);

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

static NTSTATUS
Ap6256CopyTxPacket(_In_ PAP6256_QUEUE_CONTEXT QueueContext, _In_ NET_RING const* FragmentRing,
                   _In_ NET_PACKET const* Packet, _Out_ PAP6256_FRAME Frame,
                   _Out_ PUINT32 NextFragmentIndex)
{
    UINT32 fragmentIndex = Packet->FragmentIndex;
    ULONG total = 0;
    UINT32 count;
    NTSTATUS status;

    Frame->Length = 0;
    Frame->FipsGeneration = 0;
    Frame->HostCipher = FALSE;
    *NextFragmentIndex = fragmentIndex;
    if (Packet->FragmentCount == 0 || Packet->FragmentCount > AP6256_MAX_TX_FRAGMENTS ||
        NetRingGetRangeCount(FragmentRing, fragmentIndex, FragmentRing->EndIndex) <
            Packet->FragmentCount) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    for (count = 0; count < Packet->FragmentCount; count++) {
        NET_FRAGMENT const* fragment = NetRingGetFragmentAtIndex(FragmentRing, fragmentIndex);
        NET_FRAGMENT_VIRTUAL_ADDRESS const* virtualAddress =
            NetExtensionGetFragmentVirtualAddress(&QueueContext->VirtualAddress, fragmentIndex);
        ULONG length = (ULONG)fragment->ValidLength;

        if (virtualAddress == NULL || virtualAddress->VirtualAddress == NULL ||
            fragment->Offset > fragment->Capacity ||
            fragment->ValidLength > fragment->Capacity - fragment->Offset ||
            length > sizeof(Frame->Data) - total) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        RtlCopyMemory(Frame->Data + total,
                      (PUCHAR)virtualAddress->VirtualAddress + fragment->Offset, length);
        total += length;
        fragmentIndex = NetRingIncrementIndex(FragmentRing, fragmentIndex);
    }

    *NextFragmentIndex = fragmentIndex;

    Frame->Length = total;
    if (Ap6256HostCipherPacketActive(QueueContext->Wifi->Ctx,
        QueueContext->Role->LogicalPort == AP6256_STATION_PORT ? 0 : QueueContext->Wifi->Ctx->Go.IfIndex)) {

        Frame->HostCipher = TRUE; return STATUS_SUCCESS;
    }
    status = Ap6256FipsPrepareTx(QueueContext->Wifi->Ctx,
        QueueContext->Role->LogicalPort == AP6256_STATION_PORT ? 0 : QueueContext->Wifi->Ctx->Go.IfIndex,
        Frame->Data, (ULONG)sizeof(Frame->Data), &Frame->Length, &Frame->Priority, &Frame->Exemption);
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(&Frame->FipsGeneration, Frame->Data + 8, sizeof(Frame->FipsGeneration));
        return STATUS_SUCCESS;
    }
    if (status != STATUS_NOT_SUPPORTED) return status;
    status = Ap6256Tal80211ToEthernet(Frame->Data, total, &Frame->Length);
    if (!NT_SUCCESS(status)) return status;
    if (Frame->Length > AP6256_FRAME_MAX) {
        Frame->Length = 0;
        return STATUS_INVALID_BUFFER_SIZE;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID Ap6256EvtTxAdvance(NETPACKETQUEUE Queue)
{
    PAP6256_QUEUE_CONTEXT queueContext = Ap6256GetQueueContext(Queue);
    PAP6256_WIFI wifi = queueContext->Wifi;
    NET_RING_COLLECTION const* rings = NetTxQueueGetRingCollection(Queue);
    NET_RING* packetRing = NetRingCollectionGetPacketRing(rings);
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(rings);
    BOOLEAN enqueued = FALSE;

    if (InterlockedCompareExchange(&wifi->HardwareAvailable, 0, 0) == 0 ||
        InterlockedCompareExchange(&wifi->Stopping, 0, 0) != 0 ||
        !queueContext->TxEnabled || queueContext->Closing || queueContext->Role->Closing) {
        return;
    }

    while (packetRing->NextIndex != packetRing->EndIndex) {
        UINT32 packetIndex = packetRing->NextIndex;
        NET_PACKET* packet = NetRingGetPacketAtIndex(packetRing, packetIndex);
        AP6256_FRAME frame;
        UINT32 nextFragment = fragmentRing->NextIndex;
        UINT32 packetFragmentEnd = fragmentRing->NextIndex;
        NTSTATUS status;
        KIRQL oldIrql;

        RtlZeroMemory(&frame, sizeof(frame));

        KeAcquireSpinLock(&queueContext->TxLock, &oldIrql);
        if ((ULONG)(queueContext->TxHead - queueContext->TxTail) >= AP6256_TXQ_DEPTH) {
            KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
            break;
        }
        KeReleaseSpinLock(&queueContext->TxLock, oldIrql);

        if (packet->Ignore) {

            packetRing->NextIndex = NetRingIncrementIndex(packetRing, packetIndex);
            continue;
        } else {
            if (packet->FragmentCount == 0 || packet->FragmentCount > AP6256_MAX_TX_FRAGMENTS ||
                packet->FragmentIndex != fragmentRing->NextIndex ||
                NetRingGetRangeCount(fragmentRing, packet->FragmentIndex, fragmentRing->EndIndex) <
                    packet->FragmentCount) {
                TraceError(TRACE_NETADAPTER,
                           "invalid TX fragment ownership; leaving packet queued\n");
                break;
            }
            packetFragmentEnd =
                NetRingAdvanceIndex(fragmentRing, packet->FragmentIndex, packet->FragmentCount);
            nextFragment = packetFragmentEnd;
            status = Ap6256CopyTxPacket(queueContext, fragmentRing, packet, &frame, &nextFragment);
            if (!NT_SUCCESS(status)) {

                nextFragment = packetFragmentEnd;
            }
        }

        if (NT_SUCCESS(status)) {
            NET_PACKET_WIFI_EXEMPTION_ACTION* exemption =
                WifiExtensionGetExemptionAction(&queueContext->ExemptionAction, packetIndex);
            status = Ap6256CxPrepareTx(queueContext, exemption, &frame);
        }
        if (NT_SUCCESS(status)) {
            PAP6256_FRAME slot;
            KeAcquireSpinLock(&queueContext->TxLock, &oldIrql);
            if ((ULONG)(queueContext->TxHead - queueContext->TxTail) >= AP6256_TXQ_DEPTH) {
                KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
                break;
            }
            slot = &queueContext->TxPending[queueContext->TxHead & (AP6256_TXQ_DEPTH - 1)];
            *slot = frame;
            queueContext->TxHead++;
            KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
            enqueued = TRUE;
        } else {
            TraceWarn(TRACE_NETADAPTER, "dropping malformed TX packet (0x%08X)\n", status);
        }

        fragmentRing->NextIndex = nextFragment;
        packetRing->NextIndex = NetRingIncrementIndex(packetRing, packetIndex);
    }

    packetRing->BeginIndex = packetRing->NextIndex;
    fragmentRing->BeginIndex = fragmentRing->NextIndex;
    if (enqueued)
        Ap6256CxQueueTx(queueContext);
}

_Use_decl_annotations_
static VOID Ap6256EvtTxWorkItem(WDFWORKITEM WorkItem)
{
    PAP6256_QUEUE_CONTEXT queueContext = Ap6256GetQueueContext(WdfWorkItemGetParentObject(WorkItem));
    PAP6256_WIFI wifi = queueContext->Wifi;
    AP6256_FRAME frame;
    BOOLEAN consumed = FALSE;

    for (;;) {
        KIRQL wakeIrql;
        KeAcquireSpinLock(&queueContext->TxLock, &wakeIrql);
        queueContext->TxWakePending = 0;
        KeReleaseSpinLock(&queueContext->TxLock, wakeIrql);
        for (;;) {
        KIRQL oldIrql;
        NTSTATUS status;
        ULONG tail;

        if (InterlockedCompareExchange(&wifi->HardwareAvailable, 0, 0) == 0 ||
            InterlockedCompareExchange(&wifi->Stopping, 0, 0) != 0 ||
            !queueContext->TxEnabled || queueContext->Closing || queueContext->Role->Closing) {
            break;
        }
        KeAcquireSpinLock(&queueContext->TxLock, &oldIrql);
        if (queueContext->TxTail == queueContext->TxHead) {
            KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
            break;
        }
        tail = queueContext->TxTail;
        frame = queueContext->TxPending[tail & (AP6256_TXQ_DEPTH - 1)];
        KeReleaseSpinLock(&queueContext->TxLock, oldIrql);

        status = Ap6256CxTransmit(queueContext, &frame);
        if (status == STATUS_DEVICE_BUSY || status == STATUS_DEVICE_NOT_READY ||
            status == STATUS_POWER_STATE_INVALID) {
            break;
        }

        KeAcquireSpinLock(&queueContext->TxLock, &oldIrql);
        if (queueContext->TxTail == tail && queueContext->TxTail != queueContext->TxHead)
            queueContext->TxTail++;
        KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
        consumed = TRUE;

        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER, "dropping TX frame after SDIO failure 0x%08X\n", status);
        }
        }
        KeAcquireSpinLock(&queueContext->TxLock, &wakeIrql);
        if (queueContext->TxWakePending && queueContext->TxEnabled && !queueContext->Closing &&
            !queueContext->Role->Closing && queueContext->Role->DataEnabled &&
            wifi->HardwareAvailable && !wifi->Stopping) {
            KeReleaseSpinLock(&queueContext->TxLock, wakeIrql);
            continue;
        }
        queueContext->TxRunning = 0;
        KeReleaseSpinLock(&queueContext->TxLock, wakeIrql);
        break;
    }
    if (consumed) {
        Ap6256CxNotifyTx(queueContext);
    }
}

_Use_decl_annotations_
static VOID Ap6256EvtRxAdvance(NETPACKETQUEUE Queue)
{
    PAP6256_QUEUE_CONTEXT queueContext = Ap6256GetQueueContext(Queue);
    PAP6256_CX_ADAPTER role = queueContext->Role;
    NET_RING_COLLECTION const* rings = NetRxQueueGetRingCollection(Queue);
    NET_RING* packetRing = NetRingCollectionGetPacketRing(rings);
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(rings);
    UINT32 packetIndex = packetRing->BeginIndex;
    UINT32 fragmentIndex = fragmentRing->BeginIndex;
    KIRQL oldIrql;

    fragmentRing->NextIndex = fragmentRing->EndIndex;

    KeAcquireSpinLock(&role->RxLock, &oldIrql);
    while (packetIndex != packetRing->EndIndex && fragmentIndex != fragmentRing->NextIndex &&
           role->RxTail != role->RxHead) {
        PAP6256_FRAME source = &role->RxPending[role->RxTail & (AP6256_RXQ_DEPTH - 1)];
        NET_FRAGMENT* fragment = NetRingGetFragmentAtIndex(fragmentRing, fragmentIndex);
        NET_FRAGMENT_VIRTUAL_ADDRESS* virtualAddress =
            NetExtensionGetFragmentVirtualAddress(&queueContext->VirtualAddress, fragmentIndex);
        NET_PACKET* packet = NetRingGetPacketAtIndex(packetRing, packetIndex);
        ULONG nativeLength = 0, headerLength = 0;

        fragment->Offset = 0;
        if (virtualAddress != NULL && virtualAddress->VirtualAddress != NULL &&
            Ap6256CxFrameCurrent(role, source) && NT_SUCCESS(Ap6256CxEncapsulateRx(role, source,
                (PUCHAR)virtualAddress->VirtualAddress, (ULONG)fragment->Capacity, &nativeLength, &headerLength))) {
            fragment->ValidLength = nativeLength;
            packet->FragmentIndex = fragmentIndex;
            packet->FragmentCount = 1;
            packet->Layout.Layer2HeaderLength = (UINT16)headerLength;
            packet->Layout.Layer3HeaderLength = 0;
            packet->Layout.Layer4HeaderLength = 0;
            packet->Layout.Layer2Type = NetPacketLayer2TypeIeee80211;
            packet->Layout.Layer3Type = NetPacketLayer3TypeUnspecified;
            packet->Layout.Layer4Type = NetPacketLayer4TypeUnspecified;
            packet->Ignore = 0;
        } else {
            fragment->ValidLength = 0;
            packet->Ignore = 1;
        }

        role->RxTail++;
        packetIndex = NetRingIncrementIndex(packetRing, packetIndex);
        fragmentIndex = NetRingIncrementIndex(fragmentRing, fragmentIndex);
    }
    KeReleaseSpinLock(&role->RxLock, oldIrql);

    packetRing->BeginIndex = packetIndex;
    fragmentRing->BeginIndex = fragmentIndex;
}

_Use_decl_annotations_
static VOID Ap6256EvtQueueSetNotify(NETPACKETQUEUE Queue, BOOLEAN NotificationEnabled)
{
    PAP6256_QUEUE_CONTEXT q = Ap6256GetQueueContext(Queue);
    InterlockedExchange(&q->NotificationEnabled, NotificationEnabled ? 1 : 0);
    if (NotificationEnabled && q->Started && !q->Closing && !q->Role->Closing) {
        if (q->IsTx) NetTxQueueNotifyMoreCompletedPacketsAvailable(Queue);
        else NetRxQueueNotifyMoreReceivedPacketsAvailable(Queue);
    }
}

_Use_decl_annotations_
static VOID Ap6256EvtTxCancel(NETPACKETQUEUE Queue)
{
    PAP6256_QUEUE_CONTEXT queueContext = Ap6256GetQueueContext(Queue);
    NET_RING_COLLECTION const* rings = NetTxQueueGetRingCollection(Queue);
    NET_RING* packetRing = NetRingCollectionGetPacketRing(rings);
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(rings);
    KIRQL oldIrql;

    Ap6256CxStopQueue(queueContext);
    Ap6256CxUnpublishQueue(queueContext);
    Ap6256WlfcCancelAndWait(queueContext->Wifi->Ctx, queueContext->Role->LogicalPort, AP6256_WLFC_ANY, queueContext);
    KeAcquireSpinLock(&queueContext->TxLock, &oldIrql);
    queueContext->TxTail = queueContext->TxHead;
    KeReleaseSpinLock(&queueContext->TxLock, oldIrql);
    packetRing->NextIndex = packetRing->EndIndex;
    packetRing->BeginIndex = packetRing->EndIndex;
    fragmentRing->NextIndex = fragmentRing->EndIndex;
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
}

_Use_decl_annotations_
static VOID Ap6256EvtRxCancel(NETPACKETQUEUE Queue)
{
    PAP6256_QUEUE_CONTEXT queueContext = Ap6256GetQueueContext(Queue);
    PAP6256_CX_ADAPTER role = queueContext->Role;
    NET_RING_COLLECTION const* rings = NetRxQueueGetRingCollection(Queue);
    NET_RING* packetRing = NetRingCollectionGetPacketRing(rings);
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(rings);
    KIRQL oldIrql;
    UINT32 packetIndex;

    Ap6256CxStopQueue(queueContext);
    Ap6256CxUnpublishQueue(queueContext);
    KeAcquireSpinLock(&role->RxLock, &oldIrql);
    role->RxTail = role->RxHead;
    KeReleaseSpinLock(&role->RxLock, oldIrql);

    packetIndex = packetRing->BeginIndex;
    while (packetIndex != packetRing->EndIndex) {
        NET_PACKET* packet = NetRingGetPacketAtIndex(packetRing, packetIndex);
        packet->Ignore = 1;
        packetIndex = NetRingIncrementIndex(packetRing, packetIndex);
    }
    packetRing->BeginIndex = packetRing->EndIndex;
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
    fragmentRing->NextIndex = fragmentRing->EndIndex;
}

NTSTATUS Ap6256GetRequestView(_In_ AP6256_REQUEST Request, _Out_ PWDI_MESSAGE_HEADER* Header,
                              _Outptr_result_bytebuffer_(*TlvLength) const UCHAR** Tlv,
                              _Out_ PULONG TlvLength)
{
    UINT inputLength = 0;
    UINT outputLength = 0;
    PUCHAR buffer = (PUCHAR)WifiRequestGetInOutBuffer(Request, &inputLength, &outputLength);

    UNREFERENCED_PARAMETER(outputLength);
    if (buffer == NULL || inputLength < sizeof(WDI_MESSAGE_HEADER)) {
        return STATUS_INVALID_PARAMETER;
    }
    *Header = (PWDI_MESSAGE_HEADER)buffer;
    *Tlv = buffer + sizeof(WDI_MESSAGE_HEADER);
    *TlvLength = inputLength - sizeof(WDI_MESSAGE_HEADER);
    return STATUS_SUCCESS;
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
    if (NT_SUCCESS(status)) {
        WDI_PORT_ID internal;
        status = Ap6256CxInternalPort(Wifi, parameters.CancelParameters.OriginalPortId, &internal);
        if (NT_SUCCESS(status)) parameters.CancelParameters.OriginalPortId = internal;
    }
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
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->ScanTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);

            if (claimed) AP6256_TIMER_STOP(Wifi->ScanTimer, TRUE);
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
            claimed = Ap6256ClaimMatchingTask(
                Wifi, &Wifi->ApAssocTask, parameters.CancelParameters.OriginalTransactionId,
                parameters.CancelParameters.OriginalPortId, &taskHeader, &taskRequestId);

            if (claimed) AP6256_TIMER_STOP(Wifi->Model.ApAssocTimer, TRUE);
            completionId = WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE;
            if (claimed) {
                (VOID) Ap6256GoDisconnectPeer(Wifi->Ctx, Wifi->ApPendingAssocMac, 1);
                Ap6256CxGroupPeerDelete(Wifi->Ctx, Wifi->ApPendingAssocMac);
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
        NTSTATUS status;
        UINT outputLength = 0;
        const UINT needed = sizeof(WDI_MESSAGE_HEADER) + 4 + sizeof(result);
        PUCHAR buffer, output;
        if (ihvLength >= sizeof(magic))
            RtlCopyMemory(&magic, ihvData, sizeof(magic));
        if (magic != AP6256_TDLS_MAGIC) {
            Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
            return;
        }
        if (Header->PortId != AP6256_STATION_PORT)
            goto invalid;
        buffer = (PUCHAR)WifiRequestGetInOutBuffer(Request, NULL, &outputLength);
        if (buffer == NULL) {
            Ap6256CompleteRequest(Wifi, Request, STATUS_INVALID_PARAMETER);
            return;
        }
        if (outputLength < needed) {

            WifiRequestSetBytesNeeded(Request, needed);
            Ap6256CompleteRequest(Wifi, Request, STATUS_BUFFER_OVERFLOW);
            return;
        }
        status = Ap6256TdlsControl(Wifi->Ctx, ihvData, ihvLength, &result);
        if (!NT_SUCCESS(status)) {
            Ap6256CompleteRequest(Wifi, Request, status);
            return;
        }
        ((PWDI_MESSAGE_HEADER)buffer)->Status = NDIS_STATUS_SUCCESS;
        output = buffer + sizeof(WDI_MESSAGE_HEADER);
        output[0] = (UCHAR)(AP6256_WDI_TLV_IHV_DATA & 0xffu);
        output[1] = (UCHAR)(AP6256_WDI_TLV_IHV_DATA >> 8);
        output[2] = (UCHAR)sizeof(result);
        output[3] = 0;
        RtlCopyMemory(output + 4, &result, sizeof(result));

        WifiRequestComplete(Request, STATUS_SUCCESS, needed);
        return;
    }

invalid:
    Ap6256CompleteRequest(Wifi, Request, Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA));
}

_IRQL_requires_max_(PASSIVE_LEVEL)

UINT16
Ap6256RequestGetMessageId(_In_ AP6256_REQUEST Request)
{
    return WifiRequestGetMessageId(Request);
}

_Use_decl_annotations_
static VOID Ap6256EvtCommandWorkItem(WDFWORKITEM WorkItem)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfWorkItemGetParentObject(WorkItem));
    Ap6256LockAcquire(&wifi->Model.AdapterLock);
    Ap6256DrainCommandQueue(wifi);
    Ap6256LockRelease(&wifi->Model.AdapterLock);
}

_Use_decl_annotations_
static VOID Ap6256EvtWifiSendCommand(WDFDEVICE Device, WIFIREQUEST Request)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ap6256GetDeviceContext(Device));
    UINT input = 0, output = 0;
    PWDI_MESSAGE_HEADER h = (PWDI_MESSAGE_HEADER)WifiRequestGetInOutBuffer(Request, &input, &output);
    WDI_PORT_ID internal;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (!wifi) { WifiRequestComplete(Request, STATUS_DEVICE_NOT_READY, 0); return; }
    Ap6256LockAcquire(&wifi->Model.AdapterLock);
    if (h && input >= sizeof(*h) && output >= sizeof(*h)) {
        status = Ap6256CxInternalPort(wifi, h->PortId, &internal);
        if (NT_SUCCESS(status)) { h->PortId = internal; status = Ap6256QueueCommand(wifi, Request); }
        else { Ap6256LockRelease(&wifi->Model.AdapterLock); WifiRequestComplete(Request, status, 0); return; }
    }
    if (!NT_SUCCESS(status)) Ap6256CompleteRequest(wifi, Request, status);
    Ap6256LockRelease(&wifi->Model.AdapterLock);
}

#include "wowl_power.inc"

static VOID Ap6256SetPhyInfo(_Out_ WIFI_PHY_INFO* PhyInfo, _In_ WDI_PHY_TYPE PhyType,
                             _In_reads_(RateCount) const UINT16* Rates, _In_ ULONG RateCount)
{
    ULONG index;
    RtlZeroMemory(PhyInfo, sizeof(*PhyInfo));
    PhyInfo->PhyType = PhyType;
    PhyInfo->NumberDataRateEntries = min(RateCount, (ULONG)WDI_MAX_DATA_RATE_ENTRIES);
    for (index = 0; index < PhyInfo->NumberDataRateEntries; index++) {
        PhyInfo->DataRateList[index].DataRateFlag = WDI_DATA_RATE_RX_RATE | WDI_DATA_RATE_TX_RATE;
        PhyInfo->DataRateList[index].DataRateValue = Rates[index];
    }
}

static NTSTATUS Ap6256SetWifiCapabilities(_In_ WDFDEVICE Device)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    AP6256_WIFI* gate = ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*gate), AP6256_POOL_TAG);
    WDI_ALGO_PAIRS pairs[RTL_NUMBER_OF(Ap6256AlgoPairs)];
    WDI_ALGO_PAIRS management[RTL_NUMBER_OF(Ap6256MgmtAlgoPairs)];
    ULONG count, managementCount, index;
    BOOLEAN sae, ftSupported;
    C_ASSERT(RTL_NUMBER_OF(Ap6256AlgoPairs) <= RTL_NUMBER_OF(ctx->WifiAuthCipher));
    C_ASSERT(RTL_NUMBER_OF(Ap6256MgmtAlgoPairs) <= RTL_NUMBER_OF(ctx->WifiMgmtCipher));
    if (gate == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    gate->Ctx = ctx;
    gate->TlvContext.PeerVersion = WifiDeviceGetOsWdiVersion(Device);
    sae = Ap6256HostSaeAvailable(gate);
    ftSupported = Ap6256HostFbtAvailable(gate);
    count = Ap6256CopyAlgoPairs(gate, Ap6256AlgoPairs, RTL_NUMBER_OF(Ap6256AlgoPairs), pairs);
    managementCount = Ap6256CopyAlgoPairs(gate, Ap6256MgmtAlgoPairs,
        RTL_NUMBER_OF(Ap6256MgmtAlgoPairs), management);
    ExFreePoolWithTag(gate, AP6256_POOL_TAG);
    for (index = 0; index < count; ++index) {
        ctx->WifiAuthCipher[index].AuthAlgoId = (DOT11_AUTH_ALGORITHM)pairs[index].AuthAlgorithm;
        ctx->WifiAuthCipher[index].CipherAlgoId = (DOT11_CIPHER_ALGORITHM)pairs[index].CipherAlgorithm;
    }
    for (index = 0; index < managementCount; ++index) {
        ctx->WifiMgmtCipher[index].AuthAlgoId = (DOT11_AUTH_ALGORITHM)management[index].AuthAlgorithm;
        ctx->WifiMgmtCipher[index].CipherAlgoId = (DOT11_CIPHER_ALGORITHM)management[index].CipherAlgorithm;
    }

    WIFI_DEVICE_CAPABILITIES deviceCaps;
    WIFI_STATION_CAPABILITIES stationCaps;
    WIFI_BAND_CAPABILITIES bandCaps;
    WIFI_BAND_INFO bandInfo[2];
    WIFI_PHY_CAPABILITIES phyCaps;
    WIFI_PHY_INFO phyInfo[5];
    NTSTATUS status;

    WIFI_DEVICE_CAPABILITIES_INIT(&deviceCaps);

    deviceCaps.SAEAuthenticationSupported = sae;
    deviceCaps.FastTransitionSupported = ftSupported;
    deviceCaps.MBOSupported = ctx->FirmwareMboTransport;
    deviceCaps.HardwareRadioState = TRUE;
    deviceCaps.SoftwareRadioState = TRUE;
    RtlCopyMemory(deviceCaps.FirmwareVersion, "BCM43456", sizeof("BCM43456"));
    deviceCaps.NumRxStreams = 1;
    deviceCaps.NumTxStreams = 1;
    deviceCaps.NumRadios = 1;
    deviceCaps.BluetoothCoexistenceSupport = WDI_BLUETOOTH_COEXISTENCE_WIFI_THROUGHPUT_DEGRADED;
    status = WifiDeviceSetDeviceCapabilities(Device, &deviceCaps);
    if (!NT_SUCCESS(status))
        return status;

    WIFI_STATION_CAPABILITIES_INIT(&stationCaps);
    stationCaps.ScanSSIDListSize = 16;
    stationCaps.DesiredSSIDListSize = 1;
    stationCaps.KeyMappingTableSize = 16;
    stationCaps.DefaultKeyTableSize = 4;
    stationCaps.MaxNumPerSTA = 4;
    stationCaps.NumSupportedUnicastAlgorithms = count;
    stationCaps.UnicastAlgorithmsList = ctx->WifiAuthCipher;
    stationCaps.NumSupportedMulticastDataAlgorithms = count;
    stationCaps.MulticastDataAlgorithmsList = ctx->WifiAuthCipher;
    stationCaps.MFPCapable = ctx->FirmwareMfpSupported;
    stationCaps.HostFIPSModeImplemented = ctx->HostFipsReady ? DOT11_EXTSTA_ATTRIBUTES_SAFEMODE_OID_SUPPORTED : 0;
    stationCaps.FTMAsInitiatorSupport=ctx->FirmwareFtmSupported;
    stationCaps.FTMNumberOfSupportedTargets=ctx->FirmwareFtmSupported?AP6256_FTM_TARGET_MAX:0;
    stationCaps.NumSupportedMulticastMgmtAlgorithms = managementCount;
    stationCaps.MulticastMgmtAlgorithmsList = ctx->WifiMgmtCipher;
    status = WifiDeviceSetStationCapabilities(Device, &stationCaps);
    if (!NT_SUCCESS(status))
        return status;

    RtlZeroMemory(bandInfo, sizeof(bandInfo));
    bandInfo[0].BandID = WDI_BAND_ID_2400;
    bandInfo[0].BandState = TRUE;
    bandInfo[0].NumValidPhyTypes = RTL_NUMBER_OF(Ap6256Phy24);
    bandInfo[0].ValidPhyTypeList = (WDI_PHY_TYPE*)Ap6256Phy24;
    bandInfo[0].NumValidChannelTypes = RTL_NUMBER_OF(Ap6256ChannelMap24);
    bandInfo[0].ValidChannelTypes = (WDI_CHANNEL_MAPPING_ENTRY*)Ap6256ChannelMap24;
    bandInfo[0].NumChannelWidths = RTL_NUMBER_OF(Ap6256Widths24);
    bandInfo[0].ChannelWidthList = (UINT32*)Ap6256Widths24;
    bandInfo[1].BandID = WDI_BAND_ID_5000;
    bandInfo[1].BandState = TRUE;
    bandInfo[1].NumValidPhyTypes = RTL_NUMBER_OF(Ap6256Phy5);
    bandInfo[1].ValidPhyTypeList = (WDI_PHY_TYPE*)Ap6256Phy5;
    bandInfo[1].NumValidChannelTypes = RTL_NUMBER_OF(Ap6256ChannelMap5);
    bandInfo[1].ValidChannelTypes = (WDI_CHANNEL_MAPPING_ENTRY*)Ap6256ChannelMap5;
    bandInfo[1].NumChannelWidths = RTL_NUMBER_OF(Ap6256Widths5);
    bandInfo[1].ChannelWidthList = (UINT32*)Ap6256Widths5;
    WIFI_BAND_CAPABILITIES_INIT(&bandCaps);
    bandCaps.NumBands = RTL_NUMBER_OF(bandInfo);
    bandCaps.BandInfoList = bandInfo;
    status = WifiDeviceSetBandCapabilities(Device, &bandCaps);
    if (!NT_SUCCESS(status))
        return status;

    Ap6256SetPhyInfo(&phyInfo[0], WDI_PHY_TYPE_HRDSSS, Ap6256RatesB, RTL_NUMBER_OF(Ap6256RatesB));
    Ap6256SetPhyInfo(&phyInfo[1], WDI_PHY_TYPE_ERP, Ap6256RatesOfdm,
                     RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256SetPhyInfo(&phyInfo[2], WDI_PHY_TYPE_OFDM, Ap6256RatesOfdm,
                     RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256SetPhyInfo(&phyInfo[3], WDI_PHY_TYPE_HT, Ap6256RatesOfdm, RTL_NUMBER_OF(Ap6256RatesOfdm));
    Ap6256SetPhyInfo(&phyInfo[4], WDI_PHY_TYPE_VHT, Ap6256RatesOfdm,
                     RTL_NUMBER_OF(Ap6256RatesOfdm));
    WIFI_PHY_CAPABILITIES_INIT(&phyCaps);
    phyCaps.NumPhyTypes = RTL_NUMBER_OF(phyInfo);
    phyCaps.PhyInfoList = phyInfo;
    status=WifiDeviceSetPhyCapabilities(Device,&phyCaps);
    if (NT_SUCCESS(status) && ctx->FirmwareP2pSupported) {
        WIFI_WIFIDIRECT_CAPABILITIES wfd;
        WIFI_WIFIDIRECT_CAPABILITIES_INIT(&wfd);

        wfd.WFDRoleCount=1; wfd.ConcurrentGOCount=1; wfd.ConcurrentClientCount=1;
        wfd.GOClientTableSize=AP6256_GO_CLIENTS;
        wfd.AssociationTableSize=AP6256_GO_CLIENTS;
        wfd.ScanSSIDListSize=1; wfd.DesiredSSIDListSize=1;
        wfd.PrivacyExemptionListSize=16; wfd.DefaultKeyTableSize=4;
        wfd.GOon5GHzBandSupported=TRUE; wfd.OperatingChannelUpdatesSupported=TRUE;
        ctx->WifiGroupCipher[0].AuthAlgoId=DOT11_AUTH_ALGO_80211_OPEN;
        ctx->WifiGroupCipher[0].CipherAlgoId=DOT11_CIPHER_ALGO_NONE;
        ctx->WifiGroupCipher[1].AuthAlgoId=DOT11_AUTH_ALGO_RSNA_PSK;
        ctx->WifiGroupCipher[1].CipherAlgoId=DOT11_CIPHER_ALGO_CCMP;
        wfd.NumSupportedUnicastAlgorithms=2; wfd.UnicastAlgorithms=ctx->WifiGroupCipher;
        wfd.NumSupportedMulticastDataAlgorithms=2; wfd.MulticastDataAlgorithms=ctx->WifiGroupCipher;
        wfd.ServiceDiscoverySupported=ctx->FirmwareServiceOffload;
        wfd.ServiceNameDiscoverySupported=ctx->FirmwareServiceOffload;
        wfd.ServiceInformationDiscoverySupported=ctx->FirmwareServiceOffload;
        wfd.ServiceNameAdvertisementsMaxBytesSupported=ctx->FirmwareServiceOffload ? AP6256_SERVICE_MAX*AP6256_SERVICE_NAME_MAX : 0;
        wfd.ServiceInformationAdvertisementsMaxBytesSupported=ctx->FirmwareServiceOffload ? AP6256_SERVICE_MAX*AP6256_SERVICE_INFO_MAX : 0;
        RtlCopyMemory(wfd.DeviceAddress,ctx->P2p.DeviceAddress,6);
        wfd.DiscoveryFilterListSize=1;
        wfd.MaxVendorSpecificExtensionIESize=AP6256_P2P_VENDOR_IE_MAX;
        status=WifiDeviceSetWiFiDirectCapabilities(Device,&wfd);
    }
    return status;
}

_Use_decl_annotations_

static VOID Ap6256EvtEngineCleanup(WDFOBJECT AdapterObject)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(AdapterObject);
    AP6256_REQUEST pending[AP6256_CMDQ_DEPTH];
    ULONG count = 0;
    ULONG index;
    KIRQL oldIrql;

    InterlockedExchange(&wifi->Stopping, 1);
    InterlockedExchange(&wifi->HardwareAvailable, 0);

    Ap6256StationAuthFreeEvents(wifi);
    Ap6256ClearGoEvents(wifi);
    Ap6256ForgetGoAutoAssoc(wifi, NULL);
    if (wifi->Ctx != NULL) {
        InterlockedCompareExchangePointer((PVOID volatile*)&wifi->Ctx->WifiEngine, NULL,
                                          AdapterObject);
    }

    KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
    while (wifi->CommandTail != wifi->CommandHead && count < RTL_NUMBER_OF(pending)) {
        pending[count++] = wifi->CommandPending[wifi->CommandTail & (AP6256_CMDQ_DEPTH - 1)];
        wifi->CommandTail++;
    }
    wifi->ScanTask.Active = FALSE;
    wifi->ConnectTask.Active = FALSE;
    wifi->DisconnectTask.Active = FALSE;
    wifi->Ftm.Task.Active = FALSE;
    KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

    for (index = 0; index < count; index++) {
        Ap6256CompleteRequest(wifi, pending[index], STATUS_CANCELLED);
    }
}

_Use_decl_annotations_
static NTSTATUS Ap6256EvtWifiCreateWfdDevice(WDFDEVICE Device,
                                                                    WIFIDIRECT_DEVICE_INIT* WfdInit)
{
    PAP6256_DEVICE_CONTEXT ctx=Ap6256GetDeviceContext(Device);
    PAP6256_WIFI wifi=Ap6256WifiFromDevice(ctx);WDF_OBJECT_ATTRIBUTES attributes;
    WIFIDIRECTDEVICE wfd;NTSTATUS status;ULONG port;
    if (!wifi || !wifi->HardwareAvailable || !ctx->FirmwareP2pSupported)
        return STATUS_DEVICE_NOT_READY;
    if (ctx->WifiDirectDevice || wifi->P2pPortCreated) return STATUS_OBJECT_NAME_COLLISION;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes,AP6256_WFD_CONTEXT);
    attributes.EvtCleanupCallback=Ap6256EvtWfdCleanup;
    attributes.ExecutionLevel=WdfExecutionLevelPassive;
    status=WifiDirectDeviceCreate(WfdInit,&attributes,&wfd);
    if (!NT_SUCCESS(status)) return status;
    status=WifiDirectDeviceInitialize(wfd);
    if (!NT_SUCCESS(status)) { WdfObjectDelete(wfd);return status; }
    port=WifiDirectDeviceGetPortId(wfd);
    if (port>MAXUSHORT || port==0xffffu ||
        (wifi->Model.Roles[0] && port==wifi->Model.Roles[0]->PortId) ||
        (wifi->Model.Roles[1] && port==wifi->Model.Roles[1]->PortId)) { WdfObjectDelete(wfd);return STATUS_NOT_SUPPORTED; }
    Ap6256LockAcquire(&wifi->P2pLock);
    status=Ap6256WifiP2pSetDiscoveryInterface(ctx,TRUE,NULL);
    if (NT_SUCCESS(status)) {
        ctx->WifiDirectPortId=(UINT16)port;ctx->WifiDirectDevice=wfd;
        Ap6256GetWfdContext(wfd)->Ctx=ctx;
        wifi->P2pPortCreated=TRUE;wifi->P2pPortNumber=AP6256_DISCOVERY_PORT;
        wifi->P2pPortMode=AP6256_WDI_OPMODE_P2P_DEVICE;
        RtlCopyMemory(wifi->P2pPortAddress,ctx->P2p.DeviceAddress,6);
    }
    Ap6256LockRelease(&wifi->P2pLock);
    if (!NT_SUCCESS(status)) WdfObjectDelete(wfd);
    TraceDiag("WiFiCx service device: port %u -> 0x%08X\n",ctx->WifiDirectPortId,status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256NetDeviceInitConfig(_In_ PWDFDEVICE_INIT DeviceInit)
{
    WDF_POWER_POLICY_EVENT_CALLBACKS callbacks;
    WDF_POWER_POLICY_EVENT_CALLBACKS_INIT(&callbacks);
    callbacks.EvtDeviceArmWakeFromS0 = Ap6256WifiCxArmS0;
    callbacks.EvtDeviceArmWakeFromSx = Ap6256WifiCxArmSx;
    callbacks.EvtDeviceDisarmWakeFromS0 = Ap6256WifiCxDisarmS0;
    callbacks.EvtDeviceDisarmWakeFromSx = Ap6256WifiCxDisarmSx;
    WdfDeviceInitSetPowerPolicyEventCallbacks(DeviceInit, &callbacks);
    NTSTATUS status = NetDeviceInitConfig(DeviceInit);
    return NT_SUCCESS(status) ? WifiDeviceInitConfig(DeviceInit) : status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetAdapterCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    WIFI_DEVICE_CONFIG config;
    NTSTATUS status;

    status = Ap6256FirmwareQueryMacAddress(Ctx, Ctx->MacAddress);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER, "cannot obtain station MAC from NVRAM 0x%08X\n", status);
        return status;
    }

    WIFI_DEVICE_CONFIG_INIT(&config, AP6256_WDI_VERSION, Ap6256EvtWifiSendCommand,
                            Ap6256EvtWifiCreateAdapter, Ap6256EvtWifiCreateWfdDevice);
    status = WifiDeviceInitialize(Ctx->Device, &config);
    if (!NT_SUCCESS(status))
        return status;
    return STATUS_SUCCESS;
}

VOID Ap6256ModelDeleteStationPeer(PAP6256_WIFI Wifi)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, AP6256_STATION_PORT);
    NET_EUI48_ADDRESS peer, multicast = {{255,255,255,255,255,255}};
    BOOLEAN remove;
    KIRQL irql;
    Ap6256CxQuiesceRole(Wifi, AP6256_STATION_PORT);
    Ap6256LockAcquire(&Wifi->Model.PeerLock);
    KeAcquireSpinLock(&Wifi->Ctx->TalStateLock, &irql);
    remove = Wifi->Model.StationPeerCreated;
    RtlCopyMemory(peer.Value, Wifi->Model.StationPeerAddress, 6);
    Wifi->Model.StationPeerCreated = FALSE; ++Wifi->Model.StationPeerGeneration;
    KeReleaseSpinLock(&Wifi->Ctx->TalStateLock, irql);
    if (remove) {
        Ap6256WlfcCancelAndWait(Wifi->Ctx, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
        if (role) { WifiAdapterRemovePeer(role->Adapter, &peer); WifiAdapterRemovePeer(role->Adapter, &multicast); }
    }
    Ap6256LockRelease(&Wifi->Model.PeerLock);
    if (role) ExReleaseRundownProtection(&role->Rundown);
}

VOID Ap6256ModelSetLinkState(PAP6256_WIFI Wifi, BOOLEAN LinkUp)
{ Ap6256CxSetRoleLink(Wifi, AP6256_STATION_PORT, LinkUp); }

VOID Ap6256ModelOpenStationReceive(PAP6256_WIFI Wifi, BOOLEAN associated)
{
    UNREFERENCED_PARAMETER(Wifi);
    UNREFERENCED_PARAMETER(associated);
}

BOOLEAN Ap6256ModelLinkUsable(PAP6256_WIFI Wifi)
{
    return Wifi->Model.Adapter != NULL;
}

BOOLEAN Ap6256ModelDispatchCommand(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                   PWDI_MESSAGE_HEADER header, const UCHAR* tlv, ULONG tlvLength,
                                   UINT16 messageId)
{
    if ((header->PortId == AP6256_STATION_PORT && (!Wifi->Model.Roles[0] || Wifi->Model.Roles[0]->Closing)) ||
        (header->PortId == AP6256_GROUP_PORT && (!Wifi->Model.Roles[1] || Wifi->Model.Roles[1]->Closing))) {
        Ap6256CompleteRequest(Wifi, Request, STATUS_CANCELLED); return TRUE;
    }
    if (messageId == WDI_TASK_STOP_AP && header->PortId == AP6256_GROUP_PORT &&
        Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO)
        Ap6256CxQuiesceRole(Wifi, AP6256_GROUP_PORT);
    if (messageId == WDI_GET_PM_PROTOCOL_OFFLOAD || messageId == WDI_GET_AUTO_POWER_SAVE) {
        UCHAR* generated = NULL; ULONG length = 0; UINT output = 0;
        NTSTATUS status = messageId == WDI_GET_AUTO_POWER_SAVE
            ? Ap6256GeneratePowerSave(Wifi, header->PortId, &generated, &length)
            : Ap6256GeneratePmOffload(Wifi, tlv, tlvLength, &generated, &length);
        PUCHAR buffer = (PUCHAR)WifiRequestGetInOutBuffer(Request, NULL, &output);
        ULONG needed = sizeof(WDI_MESSAGE_HEADER) + length;
        if (NT_SUCCESS(status) && (!buffer || output < needed)) {
            WifiRequestSetBytesNeeded(Request, needed); status = STATUS_BUFFER_OVERFLOW;
        }
        if (NT_SUCCESS(status)) {
            header->Status = NDIS_STATUS_SUCCESS;
            header->PortId = Ap6256WifiCxExternalPort(Wifi->Ctx, header->PortId);
            if (length) RtlCopyMemory(buffer + sizeof(*header), generated, length);
            WifiRequestComplete(Request, STATUS_SUCCESS, needed);
        } else Ap6256CompleteRequest(Wifi, Request, status);
        if (generated) { RtlSecureZeroMemory(generated, length); FreeGenerated(generated); }
        return TRUE;
    }
    UNREFERENCED_PARAMETER(Wifi);
    UNREFERENCED_PARAMETER(Request);
    UNREFERENCED_PARAMETER(header);
    UNREFERENCED_PARAMETER(tlv);
    UNREFERENCED_PARAMETER(tlvLength);
    UNREFERENCED_PARAMETER(messageId);
    return FALSE;
}

_Use_decl_annotations_
static VOID Ap6256EvtScanTimeout(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnScanTimeout(wifi);
}

_Use_decl_annotations_
static VOID Ap6256EvtConnectTimeout(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnConnectTimeout(wifi);
}

_Use_decl_annotations_
static VOID Ap6256EvtDisconnectTimeout(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnDisconnectTimeout(wifi);
}

_Use_decl_annotations_
static VOID Ap6256EvtActionFrameTimeout(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnActionFrameTimeout(wifi);
}

_Use_decl_annotations_
static VOID Ap6256EvtP2pDiscoverTick(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnP2pDiscoverTick(wifi);
}

_Use_decl_annotations_
static VOID Ap6256EvtP2pListenTick(WDFTIMER Timer)
{
    PAP6256_WIFI wifi = Ap6256GetWifiContext(WdfTimerGetParentObject(Timer));
    Ap6256OnP2pListenTick(wifi);
}
_Use_decl_annotations_
static VOID Ap6256EvtFtmTick(WDFTIMER Timer) {
    Ap6256OnFtmTick(Ap6256GetWifiContext(WdfTimerGetParentObject(Timer)));
}

VOID Ap6256ModelSetStationBssid(PAP6256_WIFI Wifi, const UCHAR* Bssid)
{
    UNREFERENCED_PARAMETER(Wifi);
    UNREFERENCED_PARAMETER(Bssid);
}

BOOLEAN Ap6256ModelCreateStationPeer(PAP6256_WIFI Wifi, const UCHAR* Bssid)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, AP6256_STATION_PORT);
    NET_EUI48_ADDRESS peer, multicast = {{255,255,255,255,255,255}};
    KIRQL irql;
    if (!role) return FALSE;
    RtlCopyMemory(peer.Value, Bssid, 6);
    Ap6256ModelDeleteStationPeer(Wifi);
    Ap6256LockAcquire(&Wifi->Model.PeerLock);
    if (role->Closing || !Wifi->HardwareAvailable || Wifi->Stopping) {
        Ap6256LockRelease(&Wifi->Model.PeerLock); ExReleaseRundownProtection(&role->Rundown); return FALSE;
    }
    KeAcquireSpinLock(&Wifi->Ctx->TalStateLock, &irql);
    RtlCopyMemory(Wifi->Model.StationPeerAddress, Bssid, 6);
    Wifi->Model.StationPeerCreated = TRUE; ++Wifi->Model.StationPeerGeneration;
    KeReleaseSpinLock(&Wifi->Ctx->TalStateLock, irql);
    InterlockedExchange(&role->DataEnabled, 1);
    WifiAdapterAddPeer(role->Adapter, &peer);
    WifiAdapterAddPeer(role->Adapter, &multicast);
    Ap6256LockRelease(&Wifi->Model.PeerLock);
    ExReleaseRundownProtection(&role->Rundown);
    return TRUE;
}

_Use_decl_annotations_
static VOID Ap6256EvtSaeTimeout(WDFTIMER Timer)
{
    Ap6256StationSaeTimer(Ap6256GetWifiContext(WdfTimerGetParentObject(Timer)));
}

_Use_decl_annotations_
NTSTATUS Ap6256ModelHardwareReady(PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    if (Ctx->WifiCapabilitiesSet) return STATUS_SUCCESS;
    status = Ap6256SetWifiCapabilities(Ctx->Device);
    if (NT_SUCCESS(status)) Ctx->WifiCapabilitiesSet = TRUE;
    return status;
}

VOID Ap6256ModelUpdateReceiveContext(PAP6256_WIFI Wifi)
{
    UNREFERENCED_PARAMETER(Wifi);
}

static NTSTATUS Ap6256CxCreateEngine(PAP6256_DEVICE_CONTEXT ctx)
{
    WDFOBJECT engine;
    PAP6256_WIFI wifi;
    NTSTATUS status;
    WDF_OBJECT_ATTRIBUTES attributes, workItemAttributes, timerAttributes;
    WDF_WORKITEM_CONFIG workItemConfig;
    WDF_TIMER_CONFIG timerConfig;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, AP6256_WIFI);
    attributes.ParentObject = ctx->Device;
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    attributes.EvtCleanupCallback = Ap6256EvtEngineCleanup;
    status = WdfObjectCreate(&attributes, &engine);
    if (!NT_SUCCESS(status)) return status;
    wifi = Ap6256GetWifiContext(engine);
    wifi->Ctx = ctx;
    wifi->Model.Object = engine;
    Ap6256LockInit(&wifi->Model.AdapterLock);
    Ap6256LockInit(&wifi->Model.GroupLock);
    Ap6256LockInit(&wifi->Model.PeerLock);
    KeInitializeSpinLock(&wifi->Model.RoleLock);
    KeInitializeSpinLock(&ctx->TalStateLock);
    KeInitializeSpinLock(&wifi->CommandLock);
    Ap6256LockInit(&wifi->ActionFrameLock);
    Ap6256LockInit(&wifi->ConnectLock);
    Ap6256LockInit(&wifi->P2pLock);
    Ap6256LockInit(&wifi->Ftm.Lock);
    wifi->TlvContext.AllocationContext = 0;
    wifi->TlvContext.PeerVersion = WifiDeviceGetOsWdiVersion(ctx->Device);
    wifi->SoftwareRadioState = TRUE;
    wifi->HardwareRadioState = TRUE;

    WDF_WORKITEM_CONFIG_INIT(&workItemConfig, Ap6256EvtCommandWorkItem);
    workItemConfig.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
    workItemAttributes.ParentObject = engine;
    status = WdfWorkItemCreate(&workItemConfig, &workItemAttributes, &wifi->CommandWorkItem);
    if (!NT_SUCCESS(status))
        goto fail;

    KeInitializeSpinLock(&wifi->LinkLock);
    WDF_WORKITEM_CONFIG_INIT(&workItemConfig, Ap6256EvtLinkWorkItem);
    workItemConfig.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
    workItemAttributes.ParentObject = engine;
    status = WdfWorkItemCreate(&workItemConfig, &workItemAttributes, &wifi->LinkWorkItem);
    if (!NT_SUCCESS(status))
        goto fail;

    WDF_OBJECT_ATTRIBUTES_INIT(&timerAttributes);
    timerAttributes.ParentObject = engine;
    timerAttributes.ExecutionLevel = WdfExecutionLevelPassive;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtSaeTimeout);
    timerConfig.AutomaticSerialization = FALSE;
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->Auth.SaeTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig,Ap6256EvtFtmTick);
    status=WdfTimerCreate(&timerConfig,&timerAttributes,&wifi->Ftm.Timer);
    if(!NT_SUCCESS(status)) goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtScanTimeout);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->ScanTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtConnectTimeout);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->ConnectTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtDisconnectTimeout);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->DisconnectTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtActionFrameTimeout);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->ActionFrameTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_WORKITEM_CONFIG_INIT(&workItemConfig, Ap6256EvtActionFrameCompleteWorkItem);
    workItemConfig.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&workItemAttributes);
    workItemAttributes.ParentObject = engine;
    status =
        WdfWorkItemCreate(&workItemConfig, &workItemAttributes, &wifi->ActionFrameCompleteWorker);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtP2pListenTick);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->P2pListenTimer);
    if (!NT_SUCCESS(status))
        goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtP2pDiscoverTick);
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->P2pDiscoverTimer);
    if (!NT_SUCCESS(status))
        goto fail;

    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtClientConnectTimeout);
    timerConfig.AutomaticSerialization = FALSE;
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->Model.ClientConnectTimer);
    if (!NT_SUCCESS(status)) goto fail;
    WDF_TIMER_CONFIG_INIT(&timerConfig, Ap6256EvtApAssocTimeout);
    timerConfig.AutomaticSerialization = FALSE;
    status = WdfTimerCreate(&timerConfig, &timerAttributes, &wifi->Model.ApAssocTimer);
    if (!NT_SUCCESS(status)) goto fail;
    InterlockedExchangePointer((PVOID volatile*)&ctx->WifiEngine, engine);
    return STATUS_SUCCESS;
fail:
    WdfObjectDelete(engine);
    return status;
}

#include "role_adapter.inc"
#include "group_engine.inc"

static VOID Ap6256EvtApAssocTimeout(WDFTIMER Timer) { Ap6256OnApAssocTimeout(Ap6256GetWifiContext(WdfTimerGetParentObject(Timer))); }
static VOID Ap6256EvtClientConnectTimeout(WDFTIMER Timer) { Ap6256OnClientConnectTimeout(Ap6256GetWifiContext(WdfTimerGetParentObject(Timer))); }
