/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

static PAP6256_CX_ADAPTER Ap6256CxAcquireRole(PAP6256_WIFI Wifi, UINT16 Port)
{
    PAP6256_CX_ADAPTER role = NULL;
    KIRQL irql;
    ULONG slot = Port == AP6256_STATION_PORT ? 0u : 1u;
    if (Port != AP6256_STATION_PORT && Port != AP6256_GROUP_PORT) return NULL;
    KeAcquireSpinLock(&Wifi->Model.RoleLock, &irql);
    role = Wifi->Model.Roles[slot];
    if (role && (role->Closing || !role->Ready || !ExAcquireRundownProtection(&role->Rundown))) role = NULL;
    KeReleaseSpinLock(&Wifi->Model.RoleLock, irql);
    return role;
}

static PAP6256_QUEUE_CONTEXT Ap6256CxAcquireQueue(PAP6256_CX_ADAPTER Role, ULONG Slot)
{
    PAP6256_QUEUE_CONTEXT q;
    KIRQL irql;
    KeAcquireSpinLock(&Role->QueueLock, &irql);
    q = Slot == AP6256_CX_TX_QUEUES ? Role->RxQueue : Role->TxQueues[Slot];
    if (q && (q->Closing || !q->Started || !ExAcquireRundownProtection(&q->Rundown))) q = NULL;
    KeReleaseSpinLock(&Role->QueueLock, irql);
    return q;
}

static VOID Ap6256CxNotifyTx(PAP6256_QUEUE_CONTEXT Queue)
{
    if (!Queue->Closing && !Queue->Role->Closing && Queue->NotificationEnabled)
        NetTxQueueNotifyMoreCompletedPacketsAvailable(Queue->Queue);
}

VOID Ap6256NotifyRxQueue(PAP6256_WIFI Wifi)
{
    ULONG i;
    for (i = 0; i < 2; ++i) {
        PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, i ? AP6256_GROUP_PORT : AP6256_STATION_PORT);
        if (role) {
            PAP6256_QUEUE_CONTEXT q = Ap6256CxAcquireQueue(role, AP6256_CX_TX_QUEUES);
            if (q) {
                if (q->NotificationEnabled) NetRxQueueNotifyMoreReceivedPacketsAvailable(q->Queue);
                ExReleaseRundownProtection(&q->Rundown);
            }
            ExReleaseRundownProtection(&role->Rundown);
        }
    }
}

static BOOLEAN Ap6256CxStampFrame(PAP6256_CX_ADAPTER Role, PAP6256_FRAME Frame,
                                   const UCHAR* PeerAddress, BOOLEAN Receive)
{
    PAP6256_WIFI wifi = Role->Wifi;
    PAP6256_DEVICE_CONTEXT ctx = wifi->Ctx;
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;
    if (Role->Closing || !Role->Ready || !Role->DataEnabled || !wifi->HardwareAvailable || wifi->Stopping) return FALSE;
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    Frame->Generation = Role->Generation;
    if (Role->LogicalPort == AP6256_STATION_PORT) {
        if (wifi->Model.StationPeerCreated && (Receive || (PeerAddress[0] & 1u) ||
            RtlEqualMemory(PeerAddress, wifi->Model.StationPeerAddress, 6))) {
            Frame->Peer = AP6256_WLFC_ANY;
            Frame->PeerGeneration = wifi->Model.StationPeerGeneration;
            found = TRUE;
        }
    } else if (ctx->Go.FirmwareReady && ctx->Go.Started && !ctx->Go.Stopping) {
        const UCHAR* address = PeerAddress;
        if (Receive && ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT) address = ctx->Go.ClientBssid;
        for (i = 0; i < AP6256_GO_PEERS; ++i) {
            AP6256_GO_PEER* peer = &ctx->Go.Peers[i];
            if (peer->Active && !peer->DeletePending && RtlEqualMemory(peer->Address, address, 6) &&
                (!Receive || peer->RxOpen)) {
                Frame->Peer = (UINT16)(i + 1);
                Frame->PeerGeneration = peer->RxGeneration;
                found = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    return found;
}

static BOOLEAN Ap6256CxFrameCurrent(PAP6256_CX_ADAPTER Role, const AP6256_FRAME* Frame)
{
    PAP6256_WIFI wifi = Role->Wifi;
    PAP6256_DEVICE_CONTEXT ctx = wifi->Ctx;
    BOOLEAN valid = FALSE;
    KIRQL irql;
    UINT32 ifIndex = Role->LogicalPort == AP6256_STATION_PORT ? 0 : ctx->Go.IfIndex;
    if (!Ap6256RawGenerationCurrent(ctx, ifIndex, Frame->FipsGeneration, Frame->HostCipher)) return FALSE;
    if (Role->Closing || !Role->Ready || !Role->DataEnabled || Frame->Generation != Role->Generation ||
        !wifi->HardwareAvailable || wifi->Stopping) return FALSE;
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    if (Role->LogicalPort == AP6256_STATION_PORT) {
        valid = wifi->Model.StationPeerCreated &&
            Frame->PeerGeneration == wifi->Model.StationPeerGeneration;
    } else if (Frame->Peer > 0 && Frame->Peer <= AP6256_GO_PEERS && ctx->Go.FirmwareReady &&
               ctx->Go.Started && !ctx->Go.Stopping) {
        const AP6256_GO_PEER* peer = &ctx->Go.Peers[Frame->Peer - 1];
        valid = peer->Active && !peer->DeletePending && Frame->PeerGeneration == peer->RxGeneration;
    }
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    return valid;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS Ap6256CxEncapsulateRx(PAP6256_CX_ADAPTER Role, const AP6256_FRAME* Frame,
    PUCHAR Out, ULONG Capacity, PULONG OutLength, PULONG HeaderLength)
{
    PAP6256_WIFI wifi = Role->Wifi;
    PAP6256_DEVICE_CONTEXT ctx = wifi->Ctx;
    ULONG payloadLength, payloadOffset;
    UINT16 etherType, sequence;
    BOOLEAN addSnap, groupOwner;
    UCHAR bssid[6];
    KIRQL irql;

    *OutLength = *HeaderLength = 0;
    if (Frame->FipsGeneration) {
        AP6256_FIPS_FRAME_VIEW view;
        UINT32 ifIndex = Role->LogicalPort == AP6256_STATION_PORT ? 0 : ctx->Go.IfIndex;
        if (Frame->HostCipher) {
            ULONG generation;
            BOOLEAN hostCipher;
            if (!Ap6256RawRxRead(ctx, ifIndex, Frame->Data, Frame->Length, &view, &generation, &hostCipher) ||
                !hostCipher || generation != Frame->FipsGeneration) return STATUS_CONNECTION_DISCONNECTED;
        } else if (!Ap6256RawRxFrame(ctx, ifIndex, Frame->FipsGeneration, FALSE, Frame->Data, Frame->Length, &view))
                return STATUS_CONNECTION_DISCONNECTED;
        if (Capacity < view.Length) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(Out, view.Frame, view.Length);
        *OutLength = view.Length; *HeaderLength = view.HeaderLength;
        return STATUS_SUCCESS;
    }
    if (Frame->Length < AP6256_ETH_HDR_LEN || Frame->Length > AP6256_FRAME_MAX)
        return STATUS_INVALID_BUFFER_SIZE;
    etherType = (UINT16)(((UINT16)Frame->Data[12] << 8) | Frame->Data[13]);
    payloadLength = Frame->Length - AP6256_ETH_HDR_LEN;
    addSnap = (BOOLEAN)(etherType >= AP6256_ETH_TYPE_MIN);
    payloadOffset = AP6256_80211_HDR_MIN + (addSnap ? AP6256_LLC_SNAP_LEN : 0);
    if (Capacity < payloadOffset + payloadLength) return STATUS_BUFFER_TOO_SMALL;

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    groupOwner = Role->LogicalPort == AP6256_GROUP_PORT && ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO;
    RtlCopyMemory(bssid, Role->LogicalPort == AP6256_STATION_PORT ? wifi->Model.StationPeerAddress :
        groupOwner ? ctx->Go.Address : ctx->Go.ClientBssid, sizeof(bssid));
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    if ((bssid[0] & 1u) || RtlEqualMemory(bssid, "\0\0\0\0\0\0", 6)) return STATUS_DEVICE_NOT_READY;

    RtlZeroMemory(Out, AP6256_80211_HDR_MIN);
    Out[0] = 0x08;
    Out[1] = groupOwner ? 0x01 : 0x02;
    RtlCopyMemory(Out + 4, groupOwner ? bssid : Frame->Data, 6);
    RtlCopyMemory(Out + 10, groupOwner ? Frame->Data + 6 : bssid, 6);
    RtlCopyMemory(Out + 16, groupOwner ? Frame->Data : Frame->Data + 6, 6);
    sequence = (UINT16)(InterlockedIncrement(&Role->RxSequence) & 0x0FFF);
    Out[22] = (UCHAR)((sequence << 4) & 0xF0);
    Out[23] = (UCHAR)(sequence >> 4);
    if (addSnap) {
        Out[24] = 0xAA; Out[25] = 0xAA; Out[26] = 0x03;
        RtlCopyMemory(Out + 27, (etherType == AP6256_ETH_TYPE_AARP || etherType == AP6256_ETH_TYPE_IPX) ?
            Ap6256OuiBridgeTunnel : Ap6256OuiRfc1042, 3);
        Out[30] = (UCHAR)(etherType >> 8); Out[31] = (UCHAR)etherType;
    }
    RtlCopyMemory(Out + payloadOffset, Frame->Data + AP6256_ETH_HDR_LEN, payloadLength);
    *OutLength = payloadOffset + payloadLength;

    *HeaderLength = addSnap ? payloadOffset : 0;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256CxPrepareTx(PAP6256_QUEUE_CONTEXT Queue,
    NET_PACKET_WIFI_EXEMPTION_ACTION* Exemption, PAP6256_FRAME Frame)
{
    if (!Exemption || Queue->Priority > 7) return STATUS_INVALID_PARAMETER;
    if (Frame->HostCipher && !Frame->FipsGeneration) {
        NTSTATUS status;
        UINT32 ifIndex = Queue->Role->LogicalPort == AP6256_STATION_PORT ? 0 : Queue->Wifi->Ctx->Go.IfIndex;
        if (Exemption->ExemptionAction > WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE) return STATUS_INVALID_PARAMETER;
        Frame->Exemption = (UCHAR)Exemption->ExemptionAction;
        status = Ap6256RawPrepareTx(Queue->Wifi->Ctx, ifIndex, Frame->Data, (ULONG)sizeof(Frame->Data),
            &Frame->Length, &Frame->Priority, &Frame->Exemption);
        if (!NT_SUCCESS(status)) return status;
        RtlCopyMemory(&Frame->FipsGeneration, Frame->Data + 8, sizeof(Frame->FipsGeneration));
    }
    if (Frame->FipsGeneration) {
        if (Frame->Exemption != AP6256_FIPS_BCDC_TX_EXEMPT || Frame->Priority > 7) return STATUS_INVALID_PARAMETER;
        return Ap6256CxStampFrame(Queue->Role, Frame, Queue->PeerAddress, FALSE)
            ? STATUS_SUCCESS : STATUS_CONNECTION_DISCONNECTED;
    }
    switch (Exemption->ExemptionAction) {
    case WDI_EXEMPT_NO_EXEMPTION: Frame->Exemption = BCDC_DATA_EXEMPT_NONE; break;
    case WDI_EXEMPT_ALWAYS: Frame->Exemption = BCDC_DATA_EXEMPT_ALWAYS; break;
    case WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE: Frame->Exemption = BCDC_DATA_EXEMPT_ON_NO_KEY; break;
    default: return STATUS_NOT_SUPPORTED;
    }
    Frame->Priority = Queue->Priority;
    return Ap6256CxStampFrame(Queue->Role, Frame, Queue->PeerAddress, FALSE)
        ? STATUS_SUCCESS : STATUS_CONNECTION_DISCONNECTED;
}

static NTSTATUS Ap6256CxTransmit(PAP6256_QUEUE_CONTEXT Queue, PAP6256_FRAME Frame)
{
    PAP6256_CX_ADAPTER role = Queue->Role;
    PAP6256_DEVICE_CONTEXT ctx = Queue->Wifi->Ctx;
    if (!Queue->TxEnabled || !Ap6256CxFrameCurrent(role, Frame)) return STATUS_CANCELLED;
    return Ap6256DatapathTransmitEx(ctx, Frame->Data, Frame->Length, Frame->Priority, Frame->Exemption,
        (UCHAR)(role->LogicalPort == AP6256_GROUP_PORT ? ctx->Go.IfIndex : 0),
        role->LogicalPort, Frame->Peer, Queue);
}

VOID Ap6256NetRxIndicate(PAP6256_DEVICE_CONTEXT Ctx, PUCHAR Frame, ULONG Length,
                          UCHAR Priority, UINT32 IfIndex)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    PAP6256_CX_ADAPTER role;
    PAP6256_QUEUE_CONTEXT q;
    AP6256_FRAME packet;
    BOOLEAN queued = FALSE;
    KIRQL irql;
    AP6256_FIPS_FRAME_VIEW view = {0};
    ULONG rawGeneration;
    BOOLEAN hostCipher;
    BOOLEAN raw = Ap6256RawRxRead(Ctx, IfIndex, Frame, Length, &view, &rawGeneration, &hostCipher);
    if (!wifi || Length < 14 || Priority > 7) return;
    if (raw && !hostCipher) {
        Frame = (PUCHAR)view.Frame; Length = view.Length;
    } else if (!raw && (Length > AP6256_FRAME_MAX || !Ap6256RawGenerationCurrent(Ctx, IfIndex, 0, FALSE))) return;
    if (IfIndex != 0 && (!Ctx->Go.FirmwareReady || IfIndex != Ctx->Go.IfIndex)) return;
    role = Ap6256CxAcquireRole(wifi, IfIndex ? AP6256_GROUP_PORT : AP6256_STATION_PORT);
    if (!role) return;
    q = Ap6256CxAcquireQueue(role, AP6256_CX_TX_QUEUES);
    if (!q) { ExReleaseRundownProtection(&role->Rundown); return; }
    RtlZeroMemory(&packet, sizeof(packet));
    packet.Priority = Priority;
    packet.Length = Length;
    packet.FipsGeneration = raw ? rawGeneration : 0;
    packet.HostCipher = hostCipher;
    if (Ap6256CxStampFrame(role, &packet, raw ? view.Frame + 10 : Frame + 6, TRUE)) {
        RtlCopyMemory(packet.Data, Frame, Length);
        KeAcquireSpinLock(&role->RxLock, &irql);
        if ((ULONG)(role->RxHead - role->RxTail) < AP6256_RXQ_DEPTH && !role->Closing) {
            role->RxPending[role->RxHead++ & (AP6256_RXQ_DEPTH - 1)] = packet;
            queued = TRUE;
        }
        KeReleaseSpinLock(&role->RxLock, irql);
    }
    if (queued && q->NotificationEnabled) NetRxQueueNotifyMoreReceivedPacketsAvailable(q->Queue);
    ExReleaseRundownProtection(&q->Rundown);
    ExReleaseRundownProtection(&role->Rundown);
}

VOID Ap6256NetTxKick(PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    ULONG i, j;
    Ap6256WlfcKick(Ctx);
    if (!wifi || !wifi->HardwareAvailable || wifi->Stopping) return;
    for (i = 0; i < 2; ++i) {
        PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(wifi, i ? AP6256_GROUP_PORT : AP6256_STATION_PORT);
        if (!role) continue;
        for (j = 0; j < AP6256_CX_TX_QUEUES; ++j) {
            PAP6256_QUEUE_CONTEXT q = Ap6256CxAcquireQueue(role, j);
            if (q) {
                Ap6256CxQueueTx(q);
                ExReleaseRundownProtection(&q->Rundown);
            }
        }
        ExReleaseRundownProtection(&role->Rundown);
    }
}

static VOID Ap6256CxQueueTx(PAP6256_QUEUE_CONTEXT q)
{
    KIRQL irql;
    BOOLEAN enqueue = FALSE;
    KeAcquireSpinLock(&q->TxLock, &irql);
    if (q->TxEnabled && !q->Closing && !q->Role->Closing && q->Role->DataEnabled &&
        q->Wifi->HardwareAvailable && !q->Wifi->Stopping) {
        q->TxWakePending = 1;
        if (!q->TxRunning) { q->TxRunning = 1; enqueue = TRUE; }
    }
    KeReleaseSpinLock(&q->TxLock, irql);
    if (enqueue) WdfWorkItemEnqueue(q->TxWorkItem);
}

static VOID Ap6256CxQuiesceRole(PAP6256_WIFI Wifi, UINT16 Port)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, Port);
    ULONG i;
    KIRQL irql;
    if (!role) return;
    InterlockedExchange(&role->DataEnabled, 0);
    InterlockedIncrement(&role->Generation);
    KeAcquireSpinLock(&role->RxLock, &irql);
    role->RxTail = role->RxHead;
    KeReleaseSpinLock(&role->RxLock, irql);
    for (i = 0; i < AP6256_CX_TX_QUEUES; ++i) {
        PAP6256_QUEUE_CONTEXT q = Ap6256CxAcquireQueue(role, i);
        if (!q) continue;
        WdfWorkItemFlush(q->TxWorkItem);
        KeAcquireSpinLock(&q->TxLock, &irql);
        q->TxTail = q->TxHead;
        KeReleaseSpinLock(&q->TxLock, irql);
        Ap6256WlfcCancelAndWait(Wifi->Ctx, Port, AP6256_WLFC_ANY, q);
        ExReleaseRundownProtection(&q->Rundown);
    }
    Ap6256CxSetRoleLink(Wifi, Port, FALSE);
    ExReleaseRundownProtection(&role->Rundown);
}

static VOID Ap6256CxFlushTxWorkers(PAP6256_WIFI Wifi)
{
    ULONG i, j;
    for (i = 0; i < 2; ++i) {
        PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, i ? AP6256_GROUP_PORT : AP6256_STATION_PORT);
        if (!role) continue;
        for (j = 0; j < AP6256_CX_TX_QUEUES; ++j) {
            PAP6256_QUEUE_CONTEXT q = Ap6256CxAcquireQueue(role, j);
            if (q) { WdfWorkItemFlush(q->TxWorkItem); ExReleaseRundownProtection(&q->Rundown); }
        }
        ExReleaseRundownProtection(&role->Rundown);
    }
}

VOID Ap6256FlushSoftwareQueues(PAP6256_WIFI Wifi)
{
    ULONG i, j;
    for (i = 0; i < 2; ++i) {
        PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, i ? AP6256_GROUP_PORT : AP6256_STATION_PORT);
        KIRQL irql;
        if (!role) continue;
        InterlockedIncrement(&role->Generation);
        KeAcquireSpinLock(&role->RxLock, &irql);
        role->RxTail = role->RxHead;
        KeReleaseSpinLock(&role->RxLock, irql);
        for (j = 0; j < AP6256_CX_TX_QUEUES; ++j) {
            PAP6256_QUEUE_CONTEXT q = Ap6256CxAcquireQueue(role, j);
            if (q) {
                KeAcquireSpinLock(&q->TxLock, &irql);
                q->TxTail = q->TxHead;
                KeReleaseSpinLock(&q->TxLock, irql);
                Ap6256WlfcCancelAndWait(Wifi->Ctx, role->LogicalPort, AP6256_WLFC_ANY, q);
                ExReleaseRundownProtection(&q->Rundown);
            }
        }
        ExReleaseRundownProtection(&role->Rundown);
    }
}

static VOID Ap6256EvtQueueStart(NETPACKETQUEUE Queue)
{
    PAP6256_QUEUE_CONTEXT q = Ap6256GetQueueContext(Queue);
    KIRQL irql;
    if (q->Closing || q->Role->Closing) return;

    if (q->IsTx) {
        NET_EUI48_ADDRESS peer = WifiTxQueueGetDemuxPeerAddress(Queue);
        q->Priority = WifiTxQueueGetDemuxWmmInfo(Queue);
        RtlCopyMemory(q->PeerAddress, peer.Value, 6);
    }
    if (q->RundownClosed) { ExReInitializeRundownProtection(&q->Rundown); q->RundownClosed = FALSE; }
    KeAcquireSpinLock(&q->Role->QueueLock, &irql);
    InterlockedExchange(&q->Started, 1);
    KeReleaseSpinLock(&q->Role->QueueLock, irql);
    if (q->IsTx) InterlockedExchange(&q->TxEnabled, 1);
}

static VOID Ap6256CxStopQueue(PAP6256_QUEUE_CONTEXT q)
{
    KIRQL irql;
    InterlockedExchange(&q->Started, 0);
    InterlockedExchange(&q->TxEnabled, 0);
    InterlockedExchange(&q->NotificationEnabled, 0);
    if (!q->RundownClosed) {
        ExWaitForRundownProtectionRelease(&q->Rundown);
        q->RundownClosed = TRUE;
    }
    if (q->IsTx) {
        if (q->TxWorkItem) WdfWorkItemFlush(q->TxWorkItem);
        KeAcquireSpinLock(&q->TxLock, &irql);
        q->TxTail = q->TxHead;
        KeReleaseSpinLock(&q->TxLock, irql);
        Ap6256WlfcCancelAndWait(q->Wifi->Ctx, q->Role->LogicalPort, AP6256_WLFC_ANY, q);
    } else {
        KeAcquireSpinLock(&q->Role->RxLock, &irql);
        q->Role->RxTail = q->Role->RxHead;
        KeReleaseSpinLock(&q->Role->RxLock, irql);
    }
}

static VOID Ap6256EvtQueueStop(NETPACKETQUEUE Queue)
{
    Ap6256CxStopQueue(Ap6256GetQueueContext(Queue));
}

static VOID Ap6256CxUnpublishQueue(PAP6256_QUEUE_CONTEXT q)
{
    PAP6256_CX_ADAPTER role = q->Role;
    ULONG i;
    KIRQL irql;
    BOOLEAN first;
    if (!role) return;
    first = (BOOLEAN)(InterlockedExchange(&q->Closing, 1) == 0);
    InterlockedExchange(&q->TxEnabled, 0);
    InterlockedExchange(&q->NotificationEnabled, 0);
    KeAcquireSpinLock(&role->QueueLock, &irql);
    if (q->IsTx) {
        for (i = 0; i < AP6256_CX_TX_QUEUES; ++i) if (role->TxQueues[i] == q) role->TxQueues[i] = NULL;
    } else if (role->RxQueue == q) role->RxQueue = NULL;
    KeReleaseSpinLock(&role->QueueLock, irql);
    if (first && !q->RundownClosed) { ExWaitForRundownProtectionRelease(&q->Rundown); q->RundownClosed = TRUE; }
}

static VOID Ap6256EvtQueueCleanup(WDFOBJECT Object)
{
    PAP6256_QUEUE_CONTEXT q = Ap6256GetQueueContext(Object);
    if (!q->Role) return;

    Ap6256CxUnpublishQueue(q);
    if (q->IsTx) Ap6256WlfcCancelAndWait(q->Wifi->Ctx, q->Role->LogicalPort, AP6256_WLFC_ANY, q);
}

static NTSTATUS Ap6256EvtCreateTxQueue(NETADAPTER Adapter, NETTXQUEUE_INIT* Init)
{
    PAP6256_CX_ADAPTER role = Ap6256GetRoleContext(Adapter);
    WDF_OBJECT_ATTRIBUTES attributes, workAttributes;
    NET_PACKET_QUEUE_CONFIG config;
    NET_EXTENSION_QUERY query;
    NETPACKETQUEUE queue;
    PAP6256_QUEUE_CONTEXT q;
    WDF_WORKITEM_CONFIG work;
    ULONG i;
    KIRQL irql;
    NTSTATUS status;
    if (role->Closing) return STATUS_INVALID_DEVICE_STATE;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, AP6256_QUEUE_CONTEXT);
    attributes.EvtCleanupCallback = Ap6256EvtQueueCleanup;
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    NET_PACKET_QUEUE_CONFIG_INIT(&config, Ap6256EvtTxAdvance, Ap6256EvtQueueSetNotify, Ap6256EvtTxCancel);
    config.EvtStart = Ap6256EvtQueueStart;
    config.EvtStop = Ap6256EvtQueueStop;
    status = NetTxQueueCreate(Init, &attributes, &config, &queue);
    if (!NT_SUCCESS(status)) return status;
    q = Ap6256GetQueueContext(queue);
    q->Wifi = role->Wifi; q->Role = role; q->Queue = queue; q->IsTx = TRUE;
    ExInitializeRundownProtection(&q->Rundown);
    KeInitializeSpinLock(&q->TxLock);
    NET_EXTENSION_QUERY_INIT(&query, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME,
        NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetTxQueueGetExtension(queue, &query, &q->VirtualAddress);
    NET_EXTENSION_QUERY_INIT(&query, NET_PACKET_EXTENSION_WIFI_EXEMPTION_ACTION_NAME,
        NET_PACKET_EXTENSION_WIFI_EXEMPTION_ACTION_VERSION_1, NetExtensionTypePacket);
    NetTxQueueGetExtension(queue, &query, &q->ExemptionAction);
    if (!q->VirtualAddress.Enabled || !q->ExemptionAction.Enabled) { WdfObjectDelete(queue); return STATUS_NOT_SUPPORTED; }
    WDF_WORKITEM_CONFIG_INIT(&work, Ap6256EvtTxWorkItem);
    work.AutomaticSerialization = FALSE;
    WDF_OBJECT_ATTRIBUTES_INIT(&workAttributes); workAttributes.ParentObject = queue;
    status = WdfWorkItemCreate(&work, &workAttributes, &q->TxWorkItem);
    if (!NT_SUCCESS(status)) { WdfObjectDelete(queue); return status; }
    KeAcquireSpinLock(&role->QueueLock, &irql);
    for (i = 0; i < AP6256_CX_TX_QUEUES; ++i) if (!role->TxQueues[i]) break;
    if (i != AP6256_CX_TX_QUEUES && !role->Closing) role->TxQueues[i] = q;
    else status = STATUS_INSUFFICIENT_RESOURCES;
    KeReleaseSpinLock(&role->QueueLock, irql);
    if (!NT_SUCCESS(status)) WdfObjectDelete(queue);
    return status;
}

static NTSTATUS Ap6256EvtCreateRxQueue(NETADAPTER Adapter, NETRXQUEUE_INIT* Init)
{
    PAP6256_CX_ADAPTER role = Ap6256GetRoleContext(Adapter);
    WDF_OBJECT_ATTRIBUTES attributes;
    NET_PACKET_QUEUE_CONFIG config;
    NET_EXTENSION_QUERY query;
    NETPACKETQUEUE queue;
    PAP6256_QUEUE_CONTEXT q;
    KIRQL irql;
    NTSTATUS status;
    if (role->Closing) return STATUS_INVALID_DEVICE_STATE;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, AP6256_QUEUE_CONTEXT);
    attributes.EvtCleanupCallback = Ap6256EvtQueueCleanup;
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    NET_PACKET_QUEUE_CONFIG_INIT(&config, Ap6256EvtRxAdvance, Ap6256EvtQueueSetNotify, Ap6256EvtRxCancel);
    config.EvtStart = Ap6256EvtQueueStart;
    config.EvtStop = Ap6256EvtQueueStop;
    status = NetRxQueueCreate(Init, &attributes, &config, &queue);
    if (!NT_SUCCESS(status)) return status;
    q = Ap6256GetQueueContext(queue); q->Wifi = role->Wifi; q->Role = role; q->Queue = queue;
    ExInitializeRundownProtection(&q->Rundown);
    NET_EXTENSION_QUERY_INIT(&query, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME,
        NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetRxQueueGetExtension(queue, &query, &q->VirtualAddress);
    if (!q->VirtualAddress.Enabled) { WdfObjectDelete(queue); return STATUS_NOT_SUPPORTED; }
    KeAcquireSpinLock(&role->QueueLock, &irql);
    if (!role->RxQueue && !role->Closing) role->RxQueue = q;
    else status = STATUS_OBJECT_NAME_COLLISION;
    KeReleaseSpinLock(&role->QueueLock, irql);
    if (!NT_SUCCESS(status)) WdfObjectDelete(queue);
    return status;
}

static VOID Ap6256CxSetRoleLink(PAP6256_WIFI Wifi, UINT16 Port, BOOLEAN Up)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, Port);
    NET_ADAPTER_LINK_STATE state;
    if (!role) return;
    if (Up) NET_ADAPTER_LINK_STATE_INIT(&state, AP6256_LINK_SPEED, MediaConnectStateConnected,
        MediaDuplexStateFull, NetAdapterPauseFunctionTypeUnsupported, NetAdapterAutoNegotiationFlagNone);
    else NET_ADAPTER_LINK_STATE_INIT_DISCONNECTED(&state);
    NetAdapterSetLinkState(role->Adapter, &state);
    ExReleaseRundownProtection(&role->Rundown);
}

_Use_decl_annotations_
VOID Ap6256ModelGroupAddressChanged(PAP6256_WIFI Wifi)
{
    PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(Wifi, AP6256_GROUP_PORT);
    NET_ADAPTER_LINK_LAYER_ADDRESS address;
    if (!role) return;
    NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(&address, 6, Wifi->Ctx->Go.Address);
    NetAdapterSetCurrentLinkLayerAddress(role->Adapter, &address);
    ExReleaseRundownProtection(&role->Rundown);
}

static BOOLEAN Ap6256CxAddGroupPeerLocked(PAP6256_CX_ADAPTER Role, const UCHAR* Address, UINT32 Phy)
{
    PAP6256_DEVICE_CONTEXT ctx = Role->Wifi->Ctx;
    NET_EUI48_ADDRESS mac;
    ULONG i, first = (Address[0] & 1u) ? 0u : 1u, limit = first ? AP6256_GO_PEERS : 1u;
    BOOLEAN added = FALSE;
    KIRQL irql;
    if (Role->Closing || !Role->Ready || !Role->Wifi->HardwareAvailable || Role->Wifi->Stopping ||
        !ctx->Go.FirmwareReady || !ctx->Go.Started || ctx->Go.Stopping) return FALSE;
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    for (i = first; i < limit; ++i)
        if (ctx->Go.Peers[i].Active && !ctx->Go.Peers[i].DeletePending &&
            RtlEqualMemory(ctx->Go.Peers[i].Address, Address, 6)) break;
    if (i == limit) {
        for (i = first; i < limit; ++i) if (!ctx->Go.Peers[i].Active && !ctx->Go.Peers[i].DeletePending) break;
        if (i != limit) {
            AP6256_GO_PEER* peer = &ctx->Go.Peers[i];
            RtlCopyMemory(peer->Address, Address, 6); peer->PhyId = Phy; peer->Active = TRUE;
            peer->RxOpen = (BOOLEAN)(i == 0); ++peer->RxGeneration; added = TRUE;
        }
    }
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    if (i == limit) return FALSE;
    InterlockedExchange(&Role->DataEnabled, 1);
    if (added) { RtlCopyMemory(mac.Value, Address, 6); WifiAdapterAddPeer(Role->Adapter, &mac); }
    return TRUE;
}

static BOOLEAN Ap6256CxGroupPeerCreate(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address, UINT32 Phy)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    PAP6256_CX_ADAPTER role;
    const UCHAR multicast[6] = {255,255,255,255,255,255};
    BOOLEAN added;
    if (!wifi) return FALSE;
    role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    if (!role) return FALSE;
    Ap6256LockAcquire(&wifi->Model.PeerLock);
    added = Ap6256CxAddGroupPeerLocked(role, multicast, 0);
    if (added && !(Address[0] & 1u)) added = Ap6256CxAddGroupPeerLocked(role, Address, Phy);
    Ap6256LockRelease(&wifi->Model.PeerLock);
    ExReleaseRundownProtection(&role->Rundown);
    return added;
}

static VOID Ap6256CxGroupPeerDelete(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    PAP6256_CX_ADAPTER role;
    ULONG i;
    KIRQL irql;
    if (!wifi) return;
    if (!Address) Ap6256CxQuiesceRole(wifi, AP6256_GROUP_PORT);
    role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);
    Ap6256LockAcquire(&wifi->Model.PeerLock);
    for (i = 0; i < AP6256_GO_PEERS; ++i) {
        NET_EUI48_ADDRESS mac;
        BOOLEAN remove;
        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        remove = Ctx->Go.Peers[i].Active && (!Address || RtlEqualMemory(Address, Ctx->Go.Peers[i].Address, 6));
        if (remove) {
            RtlCopyMemory(mac.Value, Ctx->Go.Peers[i].Address, 6);
            Ctx->Go.Peers[i].Active = FALSE; Ctx->Go.Peers[i].RxOpen = FALSE;
            Ctx->Go.Peers[i].DeletePending = TRUE; ++Ctx->Go.Peers[i].RxGeneration;
        }
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        if (remove) {
            Ap6256WlfcCancelAndWait(Ctx, AP6256_GROUP_PORT, (UINT16)(i + 1), NULL);
            if (role) WifiAdapterRemovePeer(role->Adapter, &mac);
            KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
            Ctx->Go.Peers[i].DeletePending = FALSE;
            KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        }
    }
    Ap6256LockRelease(&wifi->Model.PeerLock);
    if (role) ExReleaseRundownProtection(&role->Rundown);
}

static VOID Ap6256CxGroupRxOpen(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address)
{
    ULONG i;
    KIRQL irql;
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    for (i = 1; i < AP6256_GO_PEERS; ++i)
        if (Ctx->Go.Peers[i].Active && RtlEqualMemory(Address, Ctx->Go.Peers[i].Address, 6)) Ctx->Go.Peers[i].RxOpen = TRUE;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    Ap6256CxSetRoleLink(Ap6256WifiFromDevice(Ctx), AP6256_GROUP_PORT, TRUE);
}

static NTSTATUS Ap6256CxInternalPort(PAP6256_WIFI Wifi, UINT32 External, WDI_PORT_ID* Internal)
{
    ULONG i;
    KIRQL irql;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (External == 0xffffu) { *Internal = 0xffff; return STATUS_SUCCESS; }

    KeAcquireSpinLock(&Wifi->Model.RoleLock, &irql);
    for (i = 0; i < 2; ++i) {
        PAP6256_CX_ADAPTER role = Wifi->Model.Roles[i];
        if (role && role->Ready && !role->Closing && External == role->PortId) {
            *Internal = role->LogicalPort; status = STATUS_SUCCESS; break;
        }
    }
    KeReleaseSpinLock(&Wifi->Model.RoleLock, irql);
    if (!NT_SUCCESS(status) && Wifi->Ctx->WifiDirectDevice && External == Wifi->Ctx->WifiDirectPortId) {
        *Internal = AP6256_DISCOVERY_PORT; status = STATUS_SUCCESS;
    }
    return status;
}

static VOID Ap6256CxCancelRoleTasks(PAP6256_WIFI Wifi, UINT16 Port)
{
    if (Wifi->ScanTask.Active && Wifi->ScanTask.Header.PortId == Port) {
        AP6256_TIMER_STOP(Wifi->ScanTimer, TRUE);
        (VOID)Ap6256WifiScanAbort(Wifi->Ctx);
        Ap6256FailStartedTask(Wifi, &Wifi->ScanTask, WDI_INDICATION_SCAN_COMPLETE, STATUS_CANCELLED);
    }
    if (Wifi->ActionFrameTask.Active && Wifi->ActionFrameTask.Header.PortId == Port) {
        Ap6256CancelActionFrame(Wifi, STATUS_CANCELLED);
        WdfWorkItemFlush(Wifi->ActionFrameCompleteWorker);
    }
    if (Wifi->Ftm.Task.Active && Wifi->Ftm.Task.Header.PortId == Port)
        (VOID)Ap6256FtmCancel(Wifi, FALSE, 0, 0, STATUS_CANCELLED);
}

static VOID Ap6256EvtAdapterCleanup(WDFOBJECT Object)
{
    PAP6256_CX_ADAPTER role = Ap6256GetRoleContext(Object);
    PAP6256_WIFI wifi = role->Wifi;
    PAP6256_DEVICE_CONTEXT ctx;
    ULONG slot;
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    if (!wifi) return;
    if (!role->Registered) { WdfObjectDereference(wifi->Model.Object); return; }
    ctx = wifi->Ctx; slot = role->LogicalPort == AP6256_STATION_PORT ? 0u : 1u;
    InterlockedExchange(&role->Closing, 1);
    InterlockedExchange(&role->DataEnabled, 0);
    ExWaitForRundownProtectionRelease(&role->Rundown);
    if (wifi->HardwareAvailable && !wifi->Stopping) {
        WdfWorkItemFlush(wifi->CommandWorkItem);
        WdfWorkItemFlush(wifi->LinkWorkItem);
        WdfWorkItemFlush(wifi->ActionFrameCompleteWorker);
    }
    Ap6256LockAcquire(&wifi->Model.AdapterLock);
    Ap6256WlfcCancelAndWait(ctx, role->LogicalPort, AP6256_WLFC_ANY, NULL);
    if (wifi->HardwareAvailable && !wifi->Stopping) Ap6256CxCancelRoleTasks(wifi, role->LogicalPort);
    if (role->LogicalPort == AP6256_GROUP_PORT) {

        Ap6256LockAcquire(&wifi->Model.GroupLock);
        if (wifi->HardwareAvailable && !wifi->Stopping) {
            NTSTATUS cancelStatus;
            if (wifi->PowerStateDx || ctx->Go.NativeStateUncertain) {

                if (role->FirmwareCreated || ctx->Go.FirmwareReady) {
                    ctx->Go.NativeStateUncertain = TRUE;
                    status = STATUS_DEVICE_NOT_READY;
                }
                ctx->Go.FirmwareReady = FALSE;
            }
            cancelStatus = Ap6256CancelClientLocked(wifi, STATUS_CANCELLED, 3);
            if (NT_SUCCESS(status)) status = cancelStatus;
            Ap6256CancelGoAssociation(wifi, STATUS_CANCELLED);
            if (NT_SUCCESS(status) && !wifi->PowerStateDx && !ctx->Go.NativeStateUncertain) {
                Ap6256P2pReleaseIesFor(ctx, &ctx->Go.P2p, ctx->Go.IfIndex);
                if (role->FirmwareCreated) status = Ap6256GoDelete(ctx);
            } else {
                Ap6256P2pForgetIesFor(&ctx->Go.P2p);
            }
        }
        if (!NT_SUCCESS(status)) ctx->Go.NativeStateUncertain = TRUE;
        ctx->Go.Created = FALSE; ctx->Go.Started = FALSE; ctx->Go.ClientConnected = FALSE;
        ctx->Go.FirmwareReady = FALSE; wifi->ApStarted = FALSE;
        Ap6256CxGroupPeerDelete(ctx, NULL);
        Ap6256LockRelease(&wifi->Model.GroupLock);
    } else {
        if (wifi->HardwareAvailable && !wifi->Stopping) {
            Ap6256StationAuthStop(wifi);
            Ap6256FailStartedTask(wifi, &wifi->ConnectTask, Ap6256ConnectCompletionId(wifi), STATUS_CANCELLED);
            Ap6256FailStartedTask(wifi, &wifi->DisconnectTask, WDI_INDICATION_DISCONNECT_COMPLETE, STATUS_CANCELLED);
            status = Ap6256WifiDisconnect(ctx);
        }
        wifi->ConnectionActive = FALSE; wifi->PortCreated = FALSE; wifi->StationPortMode = 0;
        wifi->Model.StationPeerCreated = FALSE; ++wifi->Model.StationPeerGeneration;
        wifi->Model.Adapter = NULL;
        InterlockedCompareExchangePointer((PVOID volatile*)&ctx->NetAdapter, NULL, Object);
    }
    {
        NTSTATUS qualityStatus = Ap6256QualityForgetPort(ctx, role->LogicalPort);
        if (!NT_SUCCESS(qualityStatus))
            TraceWarn(TRACE_NETADAPTER, "deleted WiFiCx port %u quality restore failed 0x%08X\n",
                (ULONG)role->LogicalPort, qualityStatus);
    }
    KeAcquireSpinLock(&wifi->Model.RoleLock, &irql);
    if (wifi->Model.Roles[slot] == role) wifi->Model.Roles[slot] = NULL;
    KeReleaseSpinLock(&wifi->Model.RoleLock, irql);
    Ap6256RecomputePortModes(wifi);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER, "WiFiCx role teardown uncertain: port %u status 0x%08X\n", role->PortId, status);
        if (slot) ctx->Go.NativeStateUncertain = TRUE;
        Ap6256NetFirmwareHalted(ctx);
    }
    Ap6256LockRelease(&wifi->Model.AdapterLock);
    WdfObjectDereference(wifi->Model.Object);
}

static NTSTATUS Ap6256EvtWifiCreateAdapter(WDFDEVICE Device, NETADAPTER_INIT* Init)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(ctx);
    PAP6256_CX_ADAPTER role;
    WIFI_ADAPTER_TYPE type = WifiAdapterInitGetType(Init);
    NET_ADAPTER_DATAPATH_CALLBACKS callbacks;
    WIFI_ADAPTER_TX_DEMUX demux;
    WDF_OBJECT_ATTRIBUTES attributes;
    NETADAPTER adapter;
    NET_ADAPTER_LINK_LAYER_CAPABILITIES link;
    NET_ADAPTER_LINK_LAYER_ADDRESS address;
    NET_ADAPTER_LINK_STATE state;
    NET_ADAPTER_TX_CAPABILITIES tx;
    NET_ADAPTER_RX_CAPABILITIES rx;
    ULONG port, slot;
    KIRQL irql;
    NTSTATUS status;
    if (type != WIFI_ADAPTER_EXTENSIBLE_STATION && type != WIFI_ADAPTER_WIFI_DIRECT_ROLE) return STATUS_NOT_SUPPORTED;
    if (type == WIFI_ADAPTER_WIFI_DIRECT_ROLE && !ctx->FirmwareP2pSupported) return STATUS_NOT_SUPPORTED;
    if (!wifi) {
        status = Ap6256CxCreateEngine(ctx);
        if (!NT_SUCCESS(status)) return status;
        wifi = Ap6256WifiFromDevice(ctx);
    }
    Ap6256LockAcquire(&wifi->Model.AdapterLock);
    slot = type == WIFI_ADAPTER_EXTENSIBLE_STATION ? 0u : 1u;
    if (ctx->Go.NativeStateUncertain) {
        Ap6256LockRelease(&wifi->Model.AdapterLock); return STATUS_DEVICE_HARDWARE_ERROR;
    }
    if (wifi->Stopping || wifi->Model.Roles[slot] || (slot && ctx->Go.Created)) {
        Ap6256LockRelease(&wifi->Model.AdapterLock); return STATUS_OBJECT_NAME_COLLISION;
    }
    NET_ADAPTER_DATAPATH_CALLBACKS_INIT(&callbacks, Ap6256EvtCreateTxQueue, Ap6256EvtCreateRxQueue);
    NetAdapterInitSetDatapathCallbacks(Init, &callbacks);
    WIFI_ADAPTER_TX_PEER_ADDRESS_DEMUX_INIT(&demux, (UINT8)(slot ? AP6256_GO_PEERS : 2));
    WifiAdapterInitAddTxDemux(Init, &demux);
    WIFI_ADAPTER_TX_WMMINFO_DEMUX_INIT(&demux); WifiAdapterInitAddTxDemux(Init, &demux);
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, AP6256_CX_ADAPTER);
    attributes.ExecutionLevel = WdfExecutionLevelPassive;
    attributes.EvtCleanupCallback = Ap6256EvtAdapterCleanup;
    status = NetAdapterCreate(Init, &attributes, &adapter);
    if (!NT_SUCCESS(status)) { Ap6256LockRelease(&wifi->Model.AdapterLock); return status; }
    role = Ap6256GetRoleContext(adapter);
    role->Wifi = wifi; role->Adapter = adapter; role->LogicalPort = slot ? AP6256_GROUP_PORT : AP6256_STATION_PORT;
    role->Generation = 1;
    ExInitializeRundownProtection(&role->Rundown);
    KeInitializeSpinLock(&role->RxLock); KeInitializeSpinLock(&role->QueueLock);
    WdfObjectReference(wifi->Model.Object);
    status = WifiAdapterInitialize(adapter);
    if (!NT_SUCCESS(status)) goto fail;
    port = WifiAdapterGetPortId(adapter);
    if (port > MAXUSHORT || port == 0xffffu ||
        (ctx->WifiDirectDevice && port == ctx->WifiDirectPortId) ||
        (wifi->Model.Roles[1-slot] && port == wifi->Model.Roles[1-slot]->PortId)) {
        status = STATUS_NOT_SUPPORTED; goto fail;
    }
    role->PortId = (UINT16)port;
    if (slot) {

        Ap6256LockAcquire(&wifi->Model.GroupLock);
        if (wifi->Stopping || wifi->PowerStateDx) {
            status = STATUS_DEVICE_NOT_READY;
            Ap6256LockRelease(&wifi->Model.GroupLock);
            goto fail;
        }
        if (ctx->Go.NativeStateUncertain) {
            status = STATUS_DEVICE_HARDWARE_ERROR;
            Ap6256LockRelease(&wifi->Model.GroupLock);
            goto fail;
        }
        ctx->WifiGroupPortId = role->PortId;
        RtlCopyMemory(ctx->Go.Address, ctx->P2p.DeviceAddress, 6);
        ctx->Go.Address[0] |= 2; ctx->Go.Address[5] ^= 0x80;
        ctx->Go.P2p = ctx->P2p;
        RtlZeroMemory(ctx->Go.P2p.DriverIes, sizeof(ctx->Go.P2p.DriverIes));
        RtlZeroMemory(ctx->Go.P2p.HostIes, sizeof(ctx->Go.P2p.HostIes));
        ctx->Go.Mode = AP6256_WDI_OPMODE_P2P_GO;
        status = Ap6256GoCreate(ctx);
        if (NT_SUCCESS(status)) {
            ctx->Go.Created = TRUE; role->FirmwareCreated = TRUE;
        }
        Ap6256LockRelease(&wifi->Model.GroupLock);
        if (!NT_SUCCESS(status)) goto fail;
    } else {
        ctx->WifiStationPortId = role->PortId;
        wifi->PortCreated = TRUE; wifi->PortNumber = AP6256_STATION_PORT; wifi->StationPortMode = AP6256_WDI_OPMODE_STA;
        wifi->Model.Adapter = adapter;
        InterlockedExchangePointer((PVOID volatile*)&ctx->NetAdapter, adapter);
    }
    NET_ADAPTER_LINK_LAYER_CAPABILITIES_INIT(&link, AP6256_LINK_SPEED, AP6256_LINK_SPEED);
    NetAdapterSetLinkLayerCapabilities(adapter, &link); NetAdapterSetLinkLayerMtuSize(adapter, 1500);
    NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(&address, 6, slot ? ctx->Go.Address : ctx->MacAddress);
    NetAdapterSetPermanentLinkLayerAddress(adapter, &address); NetAdapterSetCurrentLinkLayerAddress(adapter, &address);
    NET_ADAPTER_TX_CAPABILITIES_INIT(&tx, slot ? AP6256_CX_TX_QUEUES : AP6256_CX_STA_TX_QUEUES);
    tx.MaximumNumberOfFragments = AP6256_MAX_TX_FRAGMENTS;
    NET_ADAPTER_RX_CAPABILITIES_INIT_SYSTEM_MANAGED(&rx, AP6256_FIPS_MAX_MPDU_BYTES, 1);
    NetAdapterSetDataPathCapabilities(adapter, &tx, &rx);
    NET_ADAPTER_LINK_STATE_INIT_DISCONNECTED(&state); NetAdapterSetLinkState(adapter, &state);
    role->Registered = TRUE;
    KeAcquireSpinLock(&wifi->Model.RoleLock, &irql); wifi->Model.Roles[slot] = role; KeReleaseSpinLock(&wifi->Model.RoleLock, irql);
    status = wifi->HardwareAvailable ? STATUS_SUCCESS : Ap6256NetHardwareStart(ctx);
    if (!NT_SUCCESS(status)) goto fail;
    if (!slot) Ap6256WifiCxSetPowerCapabilities(adapter, ctx);
    Ap6256RecomputePortModes(wifi);
    status = NetAdapterStart(adapter);
    if (!NT_SUCCESS(status)) goto fail;
    InterlockedExchange(&role->Ready, 1);
    Ap6256LockRelease(&wifi->Model.AdapterLock);
    TraceDiag("WiFiCx data adapter: logical %u framework %u started\n", role->LogicalPort, role->PortId);
    return STATUS_SUCCESS;
fail:

    if (role->FirmwareCreated && !wifi->HardwareAvailable && !wifi->Stopping) {
        NTSTATUS rollbackStatus;
        Ap6256LockAcquire(&wifi->Model.GroupLock);
        rollbackStatus = wifi->PowerStateDx ? STATUS_DEVICE_NOT_READY : Ap6256GoDelete(ctx);
        if (NT_SUCCESS(rollbackStatus)) role->FirmwareCreated = FALSE;
        else ctx->Go.NativeStateUncertain = TRUE;
        Ap6256LockRelease(&wifi->Model.GroupLock);
    }
    if (ctx->Go.NativeStateUncertain) Ap6256NetFirmwareHalted(ctx);
    Ap6256LockRelease(&wifi->Model.AdapterLock);
    WdfObjectDelete(adapter);
    return status;
}
