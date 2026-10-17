/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ap6256.h"

#include "datapath.h"
#include "../common/netadapter.h"
#include "wdi_tal.h"
#include "wifi_ops.h"
#include "wlfc.h"
#include "host_fips.h"
#include "host_cipher_transport.h"

#define AP6256_TAL_MAX_OUTSTANDING_TRANSFERS  100

#define AP6256_TAL_RX_QUEUE_LIMIT             256

#define AP6256_RX_BATCH                       16

#define AP6256_TAL_PEER_ID ((WDI_PEER_ID)0)
#define RX_PORT(n) ((UINT16)((ULONG_PTR)(n)->MiniportReserved[1] & 0xffffu))
#define RX_PEER(n) ((UINT16)(((ULONG_PTR)(n)->MiniportReserved[1] >> 16) & 0x7fffu))
#define RX_FIPS_GENERATION(n) ((UINT32)((ULONG_PTR)(n)->MiniportReserved[1] >> 32))
#define RX_HOST_CIPHER(n) ((BOOLEAN)(((ULONG_PTR)(n)->MiniportReserved[1] >> 31) & 1u))

typedef struct _AP6256_RX_ROUTE {
    UINT16 PortId;
    UINT16 PeerId;
    UINT32 PhyId;
    BOOLEAN Ready;
    ULONGLONG PortGeneration;
    ULONGLONG PeerGeneration;
} AP6256_RX_ROUTE;

#if AP6256_TRACE_DATAPATH
#define AP6256_TAL_TRACE_BUDGET MAXLONG
#else
#define AP6256_TAL_TRACE_BUDGET 16
#endif

static const PCSTR Ap6256TalTraceSlotNames[Ap6256TraceSlotCount] = {
    "TxTalSend", "TxSendComplete", "TxDescInit", "TxDescDeInit",
    "TxQueueInOrder", "TxPeerBacklog", "TxComplete", "TxBuildFail",
    "RxReturn", "RxPpduRssi", "RxClaimDenied", "RxPullStopped",
    "RxNotifyPaused", "RxIndicate", "RxIndicateDone", "RxFrameDump",
    "RxNblBuilt", "RxBuildFail", "RxFiltered", "RxRefused",
    "RxResumed", "RxQueueFull", "RxStale"
};

static BOOLEAN Ap6256TalTraceSlot(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ AP6256_TRACE_SLOT Slot)
{
    LONG count;

    if (Ctx == NULL) return FALSE;
    count = InterlockedIncrement(&Ctx->TalTrace[Slot]);
    if (count == AP6256_TAL_TRACE_BUDGET) {
        TraceWarn(TRACE_NETADAPTER,
                  "trace site %s: occurrence %d is the last one printed; "
                  "later ones are only counted (TalTrace[%u])\n",
                  Ap6256TalTraceSlotNames[Slot], count, (ULONG)Slot);
    }
    return (BOOLEAN)(count <= AP6256_TAL_TRACE_BUDGET);
}

static VOID Ap6256TalCount(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ AP6256_TAL_CALL Call)
{
    if (Ctx != NULL) {
        (VOID)InterlockedIncrement(&Ctx->TalCalls[Call]);
    }
}

#if AP6256_TRACE_DATAPATH

static VOID Ap6256TalDumpCallCensus(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ PCSTR Reason)
{
    static const PCSTR callNames[Ap6256CallCount] = {
        "TxAbort", "RxStop", "RxFlush", "RxRestart",
        "RxResume", "RxThrottle", "TalStart", "TalStop",
        "AddPort", "DeletePort", "SetPortOpMode", "ResetPort",
        "PeerConfig", "PeerDeleteConfirm",
        "^RxInorderData", "^PeerCreate", "^PeerDelete", "^TxDequeue",
        "^TxTransferCompl", "^TxSendComplete", "^TxSendPause",
        "^TxSendRestart", "^TxAbortConfirm", "^RxFlushConfirm",
        "^AllocMetadata", "^FreeMetadata"
    };
    ULONG i;

    if (Ctx == NULL) return;

    TraceInfo(TRACE_NETADAPTER, "==== TAL call census: %s ====\n", Reason);

    for (i = 0; i < (ULONG)Ap6256CallCount; i += 2) {
        TraceInfo(TRACE_NETADAPTER, "  %-18s %-8d %-18s %d\n",
                  callNames[i], Ctx->TalCalls[i],
                  (i + 1 < (ULONG)Ap6256CallCount) ? callNames[i + 1] : "",
                  (i + 1 < (ULONG)Ap6256CallCount) ? Ctx->TalCalls[i + 1] : 0);
    }
    for (i = 0; i < (ULONG)Ap6256TraceSlotCount; i += 2) {
        TraceInfo(TRACE_NETADAPTER, "  %-18s %-8d %-18s %d\n",
                  Ap6256TalTraceSlotNames[i], Ctx->TalTrace[i],
                  (i + 1 < (ULONG)Ap6256TraceSlotCount)
                      ? Ap6256TalTraceSlotNames[i + 1] : "",
                  (i + 1 < (ULONG)Ap6256TraceSlotCount)
                      ? Ctx->TalTrace[i + 1] : 0);
    }
    TraceInfo(TRACE_NETADAPTER,
              "  frames: rx %d (eapol %d) pulls %d | tx %d (eapol %d) "
              "requests %d passes %d\n",
              Ctx->TalRxFrames, Ctx->TalRxEapol, Ctx->TalRxPulls,
              Ctx->TalTxFrames, Ctx->TalTxEapol, Ctx->TalTxRequests,
              Ctx->TalTxPasses);
    TraceInfo(TRACE_NETADAPTER,
              "  state: started %u stopped %u paused %u rxopen %u peer %u "
              "port %u(valid %u) queued %u\n",
              (ULONG)Ctx->TalStarted, (ULONG)Ctx->RxStopped,
              (ULONG)Ctx->RxPaused, (ULONG)Ctx->TalRxOpen,
              (ULONG)Ctx->TalPeerCreated, (ULONG)Ctx->TalPortId,
              (ULONG)Ctx->TalPortValid, Ctx->RxQueueCount);
    TraceInfo(TRACE_NETADAPTER, "==== end census ====\n");
}
#else
#define Ap6256TalDumpCallCensus(Ctx, Reason) ((VOID)0)
#endif

#if AP6256_TRACE_DATAPATH

static PCSTR Ap6256TalTxStatusName(_In_ WDI_TX_FRAME_STATUS Status)
{
    switch (Status) {
    case WDI_TxFrameStatus_Ok:                 return "OK";
    case WDI_TxFrameStatus_TransferFailed:     return "TRANSFER FAILED";
    case WDI_TxFrameStatus_TransferCancelled:  return "TRANSFER CANCELLED";
    default:                                   return "?";
    }
}
#endif

#define AP6256_TAL_MAX_FRAME_SIZE             2048u

#include "../common/native_frame.inc"

#define AP6256_RX_CONTEXT_ALIGN    8u

#define AP6256_TX_PAUSE_REASON     WDI_TX_PAUSE_REASON_IHV_START

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
Ap6256TalEthernetTo80211(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_reads_bytes_(EthLength) const UCHAR *Eth,
                         _In_ ULONG EthLength, _In_ UINT32 IfIndex,
                         _Out_writes_bytes_to_(Capacity, *OutLength) PUCHAR Out,
                         _In_ ULONG Capacity,
                         _Out_ PULONG OutLength)
{
    UINT16 etherType;
    ULONG payloadLength;
    ULONG payloadOffset;
    BOOLEAN addSnap;
    UINT16 sequence;
    UCHAR bssid[6];
    BOOLEAN groupOwner = IfIndex != 0 && Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO;
    KIRQL irql;

    *OutLength = 0;

    if (EthLength < AP6256_ETH_HDR_LEN) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    etherType = (UINT16)(((UINT16)Eth[12] << 8) | Eth[13]);
    payloadLength = EthLength - AP6256_ETH_HDR_LEN;
    addSnap = (BOOLEAN)(etherType >= AP6256_ETH_TYPE_MIN);

    payloadOffset = AP6256_80211_HDR_MIN + (addSnap ? AP6256_LLC_SNAP_LEN : 0);
    if (Capacity < payloadOffset + payloadLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    RtlCopyMemory(bssid, IfIndex == 0 ? Ctx->TalBssid : groupOwner ? Ctx->Go.Address : Ctx->Go.ClientBssid, sizeof(bssid));
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);

    RtlZeroMemory(Out, AP6256_80211_HDR_MIN);
    Out[0] = 0x08;
    Out[1] = groupOwner ? 0x01 : 0x02;
    RtlCopyMemory(Out + 4,  Eth,     6);
    RtlCopyMemory(Out + 10, bssid,   6);
    RtlCopyMemory(Out + 16, Eth + 6, 6);
    if (groupOwner) {
        RtlCopyMemory(Out + 4, bssid, 6);
        RtlCopyMemory(Out + 10, Eth + 6, 6);
        RtlCopyMemory(Out + 16, Eth, 6);
    }

    sequence = (UINT16)(InterlockedIncrement(&Ctx->TalRxSequence) & 0x0FFF);
    Out[22] = (UCHAR)((sequence << 4) & 0xF0);
    Out[23] = (UCHAR)(sequence >> 4);

    if (addSnap) {
        Out[24] = 0xAA;
        Out[25] = 0xAA;
        Out[26] = 0x03;
        RtlCopyMemory(Out + 27,
                      (etherType == AP6256_ETH_TYPE_AARP ||
                       etherType == AP6256_ETH_TYPE_IPX) ?
                          Ap6256OuiBridgeTunnel : Ap6256OuiRfc1042, 3);
        Out[30] = (UCHAR)(etherType >> 8);
        Out[31] = (UCHAR)(etherType & 0xFF);
    }

    RtlCopyMemory(Out + payloadOffset, Eth + AP6256_ETH_HDR_LEN, payloadLength);
    *OutLength = payloadOffset + payloadLength;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
Ap6256TalSetBssid(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR *Bssid)
{
    KIRQL irql;

    if (Bssid != NULL) {
        TraceInfo(TRACE_NETADAPTER,
                  "TAL BSS is now %02X:%02X:%02X:%02X:%02X:%02X\n",
                  Bssid[0], Bssid[1], Bssid[2], Bssid[3], Bssid[4], Bssid[5]);
    } else {
        TraceInfo(TRACE_NETADAPTER, "TAL BSS cleared\n");
    }

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (Bssid != NULL) {
        RtlCopyMemory(Ctx->TalBssid, Bssid, sizeof(Ctx->TalBssid));
    } else {
        RtlZeroMemory(Ctx->TalBssid, sizeof(Ctx->TalBssid));
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
}

static PCSTR Ap6256TalNdisStatusName(NDIS_STATUS Status)
{
    switch (Status) {
    case NDIS_STATUS_SUCCESS:        return "SUCCESS";
    case NDIS_STATUS_PENDING:        return "PENDING";
    case NDIS_STATUS_PAUSED:         return "PAUSED";
    case NDIS_STATUS_FAILURE:        return "FAILURE";
    case NDIS_STATUS_RESOURCES:      return "RESOURCES";
    case NDIS_STATUS_NOT_ACCEPTED:   return "NOT_ACCEPTED";
    case NDIS_STATUS_INVALID_STATE:  return "INVALID_STATE";
    case NDIS_STATUS_INVALID_PARAMETER: return "INVALID_PARAMETER";
    case NDIS_STATUS_INVALID_DATA:   return "INVALID_DATA";
    case NDIS_STATUS_INVALID_LENGTH: return "INVALID_LENGTH";
    case NDIS_STATUS_NOT_SUPPORTED:  return "NOT_SUPPORTED";
    case NDIS_STATUS_CLOSING:        return "CLOSING";
    case NDIS_STATUS_MEDIA_BUSY:     return "MEDIA_BUSY";
    case NDIS_STATUS_MEDIA_DISCONNECTED: return "MEDIA_DISCONNECTED";
    case NDIS_STATUS_LOW_POWER_STATE:    return "LOW_POWER_STATE";
    default:                         return "status";
    }
}

#if AP6256_TRACE_DATAPATH

static VOID Ap6256TalHexLine(_In_ PCSTR What,
                             _In_reads_bytes_(Length) const UCHAR* Bytes,
                             _In_ ULONG Length)
{
    ULONG n = Length > 32 ? 32 : Length;
    UCHAR b[32];

    RtlZeroMemory(b, sizeof(b));
    if (n != 0) RtlCopyMemory(b, Bytes, n);

    TraceData("%s (%u bytes): "
              "%02X%02X%02X%02X%02X%02X%02X%02X "
              "%02X%02X%02X%02X%02X%02X%02X%02X "
              "%02X%02X%02X%02X%02X%02X%02X%02X "
              "%02X%02X%02X%02X%02X%02X%02X%02X\n",
              What, Length,
              b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
              b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
              b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23],
              b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]);
}

static VOID Ap6256TalDumpRxState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ PCSTR Reason)
{
    TraceData("rx state at %s: started %u stopped %u paused %u rxopen %u "
              "peer %u(deleting %u) port %u(valid %u) queued %u active %u "
              "txAbortConfirmOwed %u\n",
              Reason, (ULONG)Ctx->TalStarted, (ULONG)Ctx->RxStopped,
              (ULONG)Ctx->RxPaused, (ULONG)Ctx->TalRxOpen,
              (ULONG)Ctx->TalPeerCreated, (ULONG)Ctx->TalPeerDeletePending,
              (ULONG)Ctx->TalPortId, (ULONG)Ctx->TalPortValid,
              Ctx->RxQueueCount, Ctx->RxIndicationsActive,
              (ULONG)Ctx->TxAbortConfirmNeeded);
}
#else
#define Ap6256TalHexLine(What, Bytes, Length)   ((VOID)0)
#define Ap6256TalDumpRxState(Ctx, Reason)       ((VOID)0)
#endif

static VOID Ap6256TalDumpDataApi(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const struct { PCSTR Name; ULONG Offset; } api[] = {
        { "TxDequeueIndication",        FIELD_OFFSET(NDIS_WDI_DATA_API, TxDequeueIndication) },
        { "TxTransferCompleteInd",      FIELD_OFFSET(NDIS_WDI_DATA_API, TxTransferCompleteIndication) },
        { "TxSendCompleteIndication",   FIELD_OFFSET(NDIS_WDI_DATA_API, TxSendCompleteIndication) },
        { "TxQueryRATIDState",          FIELD_OFFSET(NDIS_WDI_DATA_API, TxQueryRATIDState) },
        { "TxSendPauseIndication",      FIELD_OFFSET(NDIS_WDI_DATA_API, TxSendPauseIndication) },
        { "TxSendRestartIndication",    FIELD_OFFSET(NDIS_WDI_DATA_API, TxSendRestartIndication) },
        { "TxReleaseFrameIndication",   FIELD_OFFSET(NDIS_WDI_DATA_API, TxReleaseFrameIndication) },
        { "TxInjectFrameIndication",    FIELD_OFFSET(NDIS_WDI_DATA_API, TxInjectFrameIndication) },
        { "TxAbortConfirm",             FIELD_OFFSET(NDIS_WDI_DATA_API, TxAbortConfirm) },
        { "RxInorderDataIndication",    FIELD_OFFSET(NDIS_WDI_DATA_API, RxInorderDataIndication) },
        { "RxStopConfirm",              FIELD_OFFSET(NDIS_WDI_DATA_API, RxStopConfirm) },
        { "RxFlushConfirm",             FIELD_OFFSET(NDIS_WDI_DATA_API, RxFlushConfirm) },
        { "PeerCreateIndication",       FIELD_OFFSET(NDIS_WDI_DATA_API, PeerCreateIndication) },
        { "PeerDeleteIndication",       FIELD_OFFSET(NDIS_WDI_DATA_API, PeerDeleteIndication) },
        { "AllocateWiFiFrameMetaData",  FIELD_OFFSET(NDIS_WDI_DATA_API, AllocateWiFiFrameMetaData) },
        { "FreeWiFiFrameMetaData",      FIELD_OFFSET(NDIS_WDI_DATA_API, FreeWiFiFrameMetaData) },
    };
    const UCHAR* base = (const UCHAR*)&Ctx->WdiDataApi;
    ULONG i;

    TraceDiag("WDI data API: header type 0x%02X rev %u size %u\n",
              Ctx->WdiDataApi.Header.Type, Ctx->WdiDataApi.Header.Revision,
              Ctx->WdiDataApi.Header.Size);
    for (i = 0; i < RTL_NUMBER_OF(api); i++) {
        PVOID fn = *(PVOID const*)(base + api[i].Offset);
        TraceDiag("  %-26s %s\n", api[i].Name,
                  fn != NULL ? "present" : "MISSING");
    }
}

static PNET_BUFFER_LIST
Ap6256TalBuildRxNbl(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                    _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
                    _In_ UCHAR Priority, _In_ UINT32 IfIndex, _In_ UINT32 PhyId)
{
    PNET_BUFFER_LIST nbl;
    PMDL mdl;
    PUCHAR buffer;
    PWDI_FRAME_METADATA metadata;
    PDOT11_EXTSTA_RECV_CONTEXT recvContext;
    NDIS_NET_BUFFER_LIST_8021Q_INFO qos;
    ULONG frameCapacity;
    ULONG capacity;
    ULONG contextOffset;
    ULONG encapLength = 0;
    PUCHAR envelope = Frame;
    ULONG prefix;
    AP6256_FIPS_FRAME_VIEW fipsView = {0};
    ULONG rawGeneration;
    BOOLEAN hostCipher;
    BOOLEAN raw = Ap6256RawRxRead(Ctx, IfIndex, Frame, Length, &fipsView, &rawGeneration, &hostCipher);
    prefix = hostCipher ? AP6256_HC_WIRE_HEADER : 0;

    if (raw) {
        Frame = (PUCHAR)fipsView.Frame;
        Length = fipsView.Length;
    } else if (!Ap6256RawGenerationCurrent(Ctx, IfIndex, 0, FALSE)) return NULL;

    if (Ctx->RxNblPool == NULL ||
        Length < AP6256_ETH_HDR_LEN || Length > (raw ? AP6256_FIPS_MAX_MPDU_BYTES : AP6256_TAL_MAX_FRAME_SIZE) ||
        Ctx->WdiDataApi.AllocateWiFiFrameMetaData == NULL) {
        return NULL;
    }

    frameCapacity = Length + AP6256_RX_ENCAP_GROWTH;
    capacity = prefix + frameCapacity + AP6256_RX_CONTEXT_ALIGN +
               (ULONG)sizeof(DOT11_EXTSTA_RECV_CONTEXT);
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, capacity, AP6256_POOL_TAG);
    if (buffer == NULL) {
        return NULL;
    }

    if (raw) {
        if (prefix) RtlCopyMemory(buffer, envelope, prefix);
        RtlCopyMemory(buffer + prefix, Frame, Length); encapLength = Length;
    }
    else if (!NT_SUCCESS(Ap6256TalEthernetTo80211(Ctx, Frame, Length, IfIndex,
                                             buffer, frameCapacity, &encapLength))) {
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
        return NULL;
    }

    mdl = IoAllocateMdl(buffer + prefix, encapLength, FALSE, FALSE, NULL);
    if (mdl == NULL) {
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
        return NULL;
    }
    MmBuildMdlForNonPagedPool(mdl);

    nbl = NdisAllocateNetBufferAndNetBufferList(Ctx->RxNblPool, 0, 0, mdl, 0, encapLength);
    if (nbl == NULL) {
        IoFreeMdl(mdl);
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
        return NULL;
    }

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxFrameDump)) {
        Ap6256TalHexLine("rx frame to WDI", buffer + prefix, encapLength);
    }
#endif

    Ap6256TalCount(Ctx, Ap6256CallUpAllocMetadata);
    metadata = Ctx->WdiDataApi.AllocateWiFiFrameMetaData(Ctx->WdiDataPathHandle);
    if (metadata == NULL) {
        NdisFreeNetBufferList(nbl);
        IoFreeMdl(mdl);
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
        return NULL;
    }

    metadata->pNBL = nbl;
    metadata->u.rxMetaData.PayloadType = raw && fipsView.Fragmented ? WDI_FRAME_MSDU_FRAGMENT : WDI_FRAME_MSDU;
    nbl->MiniportReserved[0] = metadata;
    nbl->MiniportReserved[1] = (PVOID)((ULONG_PTR)hostCipher << 31);

    contextOffset = (prefix + encapLength + (AP6256_RX_CONTEXT_ALIGN - 1)) &
                    ~(AP6256_RX_CONTEXT_ALIGN - 1);
    NT_ASSERT(contextOffset + sizeof(DOT11_EXTSTA_RECV_CONTEXT) <= capacity);

    recvContext = (PDOT11_EXTSTA_RECV_CONTEXT)(buffer + contextOffset);
    RtlZeroMemory(recvContext, sizeof(*recvContext));
    recvContext->Header.Type     = NDIS_OBJECT_TYPE_DEFAULT;
    recvContext->Header.Revision = DOT11_EXTSTA_RECV_CONTEXT_REVISION_1;
    recvContext->Header.Size     = sizeof(DOT11_EXTSTA_RECV_CONTEXT);

    recvContext->uReceiveFlags = 0;
    recvContext->uPhyId = PhyId;
    recvContext->uChCenterFrequency = IfIndex == 0 ? Ctx->TalChannelFreq :
        Ctx->Go.Channel == 14 ? 2484u : Ctx->Go.Channel <= 13 ?
        2407u + Ctx->Go.Channel * 5u : 5000u + Ctx->Go.Channel * 5u;

    recvContext->usNumberOfMPDUsReceived = raw ? 1 : (USHORT)
        ((((USHORT)buffer[23] << 8 | buffer[22]) & 0x000Fu) + 1u);

    recvContext->lRSSI = IfIndex == 0 ? (LONG)Ctx->LastRssiDbm : (LONG)Ctx->Go.ClientRssiDbm;
    recvContext->ucDataRate = 0;
    recvContext->uSizeMediaSpecificInfo = 0;
    recvContext->pvMediaSpecificInfo = NULL;
    recvContext->ullTimestamp = 0;

    NET_BUFFER_LIST_INFO(nbl, MediaSpecificInformation) = recvContext;

    qos.Value = NULL;
    qos.WLanTagHeader.WMMInfo = Priority & 0x0Fu;
    NET_BUFFER_LIST_INFO(nbl, Ieee8021QNetBufferListInfo) = qos.Value;

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxNblBuilt)) {
        TraceData("rx nbl %p: nb %p mdl %p mdlbytes %u datalen %u "
                  "metadata %p payload %s src %p\n",
                  nbl, NET_BUFFER_LIST_FIRST_NB(nbl), mdl,
                  MmGetMdlByteCount(mdl), encapLength, metadata,
                  metadata->u.rxMetaData.PayloadType == WDI_FRAME_MSDU
                      ? "MSDU" : "other",
                  nbl->SourceHandle);
        TraceData("rx recv context %p: phy %u freq %u MHz mpdus %u rssi %d dBm "
                  "flags 0x%08X, wmm %u\n",
                  recvContext, recvContext->uPhyId,
                  recvContext->uChCenterFrequency,
                  (ULONG)recvContext->usNumberOfMPDUsReceived,
                  recvContext->lRSSI, recvContext->uReceiveFlags,
                  (ULONG)(Priority & 0x0Fu));
    }
#endif
    return nbl;
}

static VOID
Ap6256TalFreeRxNbl(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PNET_BUFFER_LIST Nbl)
{
    PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    PMDL mdl = (nb != NULL) ? NET_BUFFER_FIRST_MDL(nb) : NULL;
    PUCHAR buffer = (mdl != NULL) ? (PUCHAR)MmGetMdlVirtualAddress(mdl) : NULL;
    PWDI_FRAME_METADATA metadata = (PWDI_FRAME_METADATA)Nbl->MiniportReserved[0];
    if (buffer && RX_HOST_CIPHER(Nbl)) buffer -= AP6256_HC_WIRE_HEADER;

    if (metadata != NULL && Ctx->WdiDataApi.FreeWiFiFrameMetaData != NULL) {
        Nbl->MiniportReserved[0] = NULL;
        Ap6256TalCount(Ctx, Ap6256CallUpFreeMetadata);
        Ctx->WdiDataApi.FreeWiFiFrameMetaData(Ctx->WdiDataPathHandle, metadata);
    }

    NdisFreeNetBufferList(Nbl);
    if (mdl != NULL) {
        IoFreeMdl(mdl);
    }
    if (buffer != NULL) {
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
Ap6256TalFlushRxQueue(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    if (Ctx != NULL && Ctx->RxQueueCount != 0) {
        TraceWarn(TRACE_NETADAPTER, "receive queue flushed, %u frame(s) "
                  "discarded\n", Ctx->RxQueueCount);
    }
    PNET_BUFFER_LIST head;
    KIRQL irql;

    KeAcquireSpinLock(&Ctx->RxQueueLock, &irql);
    head = Ctx->RxQueueHead;
    Ctx->RxQueueHead = NULL;
    Ctx->RxQueueTail = NULL;
    Ctx->RxQueueCount = 0;
    KeReleaseSpinLock(&Ctx->RxQueueLock, irql);

    while (head != NULL) {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(head);
        NET_BUFFER_LIST_NEXT_NBL(head) = NULL;
        Ap6256TalFreeRxNbl(Ctx, head);
        head = next;
    }
}

static VOID Ap6256TalFlushPortRx(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer)
{
    PNET_BUFFER_LIST *link, nbl, discard = NULL;
    KIRQL irql, queueIrql;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if ((Port == WDI_PORT_ANY || Port == AP6256_STATION_PORT) &&
        (Peer == WDI_PEER_ANY || Peer == AP6256_TAL_PEER_ID))
        Ctx->StationRxGeneration++;
    if (Port == WDI_PORT_ANY || Port == AP6256_GROUP_PORT) {
        if (Peer == WDI_PEER_ANY) Ctx->GroupRxGeneration++;
        else if (Peer > 0 && Peer <= AP6256_GO_PEERS)
            Ctx->Go.Peers[Peer - 1].RxGeneration++;
    }
    KeAcquireSpinLock(&Ctx->RxQueueLock, &queueIrql);
    link = &Ctx->RxQueueHead;
    Ctx->RxQueueTail = NULL;
    while ((nbl = *link) != NULL) {
        if ((Port == WDI_PORT_ANY || RX_PORT(nbl) == Port) &&
            (Peer == WDI_PEER_ANY || RX_PEER(nbl) == Peer)) {
            *link = NET_BUFFER_LIST_NEXT_NBL(nbl);
            NET_BUFFER_LIST_NEXT_NBL(nbl) = discard;
            discard = nbl;
            Ctx->RxQueueCount--;
        } else {
            Ctx->RxQueueTail = nbl;
            link = &NET_BUFFER_LIST_NEXT_NBL(nbl);
        }
    }
    KeReleaseSpinLock(&Ctx->RxQueueLock, queueIrql);
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    while (discard) {
        nbl = discard; discard = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        Ap6256TalFreeRxNbl(Ctx, nbl);
    }
}

static VOID
Ap6256TalNotifyRxWaiting(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_ WDI_RX_INDICATION_LEVEL Level,
                         _Inout_ NDIS_STATUS* WifiStatus)
{
    KIRQL pauseIrql;
    BOOLEAN paused;
    BOOLEAN stopped;

    if (Ctx->WdiDataApi.RxInorderDataIndication == NULL) return;

    KeAcquireSpinLock(&Ctx->TalStateLock, &pauseIrql);
    paused = Ctx->RxPaused;
    stopped = Ctx->RxStopped;
    KeReleaseSpinLock(&Ctx->TalStateLock, pauseIrql);

    if (stopped) {
#if AP6256_TRACE_DATAPATH
        if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxNotifyPaused)) {
            TraceData("receive not notified: receive is stopped, %u frame(s) "
                      "waiting for RxRestart\n", Ctx->RxQueueCount);
        }
#endif
        return;
    }

    if (paused) {

#if AP6256_TRACE_DATAPATH
        if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxNotifyPaused)) {
            TraceData("receive not notified: WDI is paused, %u frame(s) "
                      "waiting for RxResume\n", Ctx->RxQueueCount);
        }
#endif
        return;
    }

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxIndicate)) {
        TraceData("rx indicate: handle %p level %u peer 0x%04X tid 0x%02X "
                  "throttle NULL, %u frame(s) queued\n",
                  Ctx->WdiDataPathHandle, (ULONG)Level,
                  (ULONG)WDI_PEER_ANY, (ULONG)WDI_EXT_TID_UNKNOWN,
                  Ctx->RxQueueCount);
    }
#endif

    Ap6256TalCount(Ctx, Ap6256CallUpRxInorderData);

#pragma warning(push)
#pragma warning(disable:6387)
    Ctx->WdiDataApi.RxInorderDataIndication(Ctx->WdiDataPathHandle,
                                            Level,
                                            WDI_PEER_ANY,
                                            WDI_EXT_TID_UNKNOWN,
                                            NULL,
                                            WifiStatus);
#pragma warning(pop)

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxIndicateDone)) {
        TraceData("rx indicate answered %s (0x%08X)\n",
                  Ap6256TalNdisStatusName(*WifiStatus), *WifiStatus);
    }
#endif

    if (*WifiStatus == NDIS_STATUS_PAUSED) {
        KIRQL irql;

        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        Ctx->RxPaused = TRUE;
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxRefused)) {
            TraceWarn(TRACE_NETADAPTER,
                      "receive paused by WDI; holding frames until RxResume\n");
        }

        Ap6256TalDumpRxState(Ctx, "the pause");
        Ap6256TalDumpCallCensus(Ctx, "WDI paused receive");
    } else if (*WifiStatus != NDIS_STATUS_SUCCESS) {
        if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxRefused)) {
            TraceWarn(TRACE_NETADAPTER,
                      "receive indication answered %s (0x%08X)\n",
                      Ap6256TalNdisStatusName(*WifiStatus), *WifiStatus);
        }
    }
}

static BOOLEAN
Ap6256TalRxClaim(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    BOOLEAN claimed = FALSE;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (Ctx->TalStarted && Ctx->TalApiOpen) {
        Ctx->RxIndicationsActive++;
        KeClearEvent(&Ctx->TalIdle);
        claimed = TRUE;
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);

    if (!claimed && Ap6256TalTraceSlot(Ctx, Ap6256TraceRxClaimDenied)) {
        TraceWarn(TRACE_NETADAPTER,
                  "receive DROPPED: the data path is not started "
                  "(stopped %u, paused %u)\n",
                  (ULONG)Ctx->RxStopped, (ULONG)Ctx->RxPaused);
    }
    return claimed;
}

static VOID
Ap6256TalRxRelease(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    NT_ASSERT(Ctx->RxIndicationsActive != 0);
    Ctx->RxIndicationsActive--;
    if (Ctx->RxIndicationsActive == 0 && Ctx->TalUpcallsActive == 0) {
        (VOID)KeSetEvent(&Ctx->TalIdle, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
}

static BOOLEAN
Ap6256TalUpcallClaim(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    BOOLEAN claimed = FALSE;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (Ctx->TalApiOpen) {
        Ctx->TalUpcallsActive++;
        KeClearEvent(&Ctx->TalIdle);
        claimed = TRUE;
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    return claimed;
}

static VOID
Ap6256TalUpcallRelease(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    NT_ASSERT(Ctx->TalUpcallsActive != 0);
    Ctx->TalUpcallsActive--;
    if (Ctx->RxIndicationsActive == 0 && Ctx->TalUpcallsActive == 0) {
        (VOID)KeSetEvent(&Ctx->TalIdle, IO_NO_INCREMENT, FALSE);
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256TalWaitIdle(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                  _In_ BOOLEAN ReceiveOnly,
                  _In_ PCSTR Reason)
{
    LARGE_INTEGER timeout;
    ULONG rounds = 0;

    timeout.QuadPart = -(50 * 10 * 1000);
    for (;;) {
        KIRQL irql;
        ULONG receives;
        ULONG upcalls;

        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        receives = Ctx->RxIndicationsActive;
        upcalls = Ctx->TalUpcallsActive;
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);

        if (receives == 0 && (ReceiveOnly || upcalls == 0)) {
            break;
        }
        if (rounds != 0 && (rounds % 40u) == 0) {
            TraceWarn(TRACE_NETADAPTER,
                      "%s: still waiting after %u ms for %u receive "
                      "indication(s) and %u other call(s) into WDI\n",
                      Reason, rounds * 50u, receives, upcalls);
        }
        (VOID)KeWaitForSingleObject(&Ctx->TalIdle, Executive, KernelMode,
                                    FALSE, &timeout);
        rounds++;
    }
}

static VOID
Ap6256TalRxIndicateQueued(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ WDI_RX_INDICATION_LEVEL Level,
                          _In_ PCSTR Reason)
{
    NDIS_STATUS wifiStatus = NDIS_STATUS_SUCCESS;
    KIRQL irql;
    ULONG waiting;

    if (Ctx == NULL) return;

    KeAcquireSpinLock(&Ctx->RxQueueLock, &irql);
    waiting = Ctx->RxQueueCount;
    KeReleaseSpinLock(&Ctx->RxQueueLock, irql);
    if (waiting == 0) return;

    if (!Ap6256TalRxClaim(Ctx)) {
        TraceVerbose(TRACE_NETADAPTER,
                     "%s: %u held frame(s) not indicated, the receive path is "
                     "stopped\n", Reason, waiting);
        return;
    }
    TraceVerbose(TRACE_NETADAPTER, "%s; indicating %u frame(s) held for it\n",
                 Reason, waiting);
    Ap6256TalNotifyRxWaiting(Ctx, Level, &wifiStatus);
    Ap6256TalRxRelease(Ctx);
}

static VOID
Ap6256TalRxQueueRefreshHeld(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR bssid[6];
    PNET_BUFFER_LIST nbl;
    KIRQL irql;
    ULONG patched = 0;
    ULONG refreshed = 0;
    ULONG phyId;
    ULONG channelFreq;
    LONG  rssiDbm;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    RtlCopyMemory(bssid, Ctx->TalBssid, sizeof(bssid));
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);

    phyId = Ctx->TalPhyId;
    channelFreq = Ctx->TalChannelFreq;
    rssiDbm = (LONG)Ctx->LastRssiDbm;

    KeAcquireSpinLock(&Ctx->RxQueueLock, &irql);
    for (nbl = Ctx->RxQueueHead; nbl != NULL;
         nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
        if (RX_PORT(nbl) != AP6256_STATION_PORT) continue;
        PNET_BUFFER nb = NET_BUFFER_LIST_FIRST_NB(nbl);
        PMDL mdl = (nb != NULL) ? NET_BUFFER_FIRST_MDL(nb) : NULL;
        PDOT11_EXTSTA_RECV_CONTEXT recvContext;
        PUCHAR frame;

        if (mdl == NULL || MmGetMdlByteCount(mdl) < AP6256_80211_HDR_MIN) {
            continue;
        }
        frame = (PUCHAR)MmGetMdlVirtualAddress(mdl);
        if (frame == NULL) continue;
        if (RtlCompareMemory(frame + 10, bssid, 6) != 6) {
            RtlCopyMemory(frame + 10, bssid, 6);
            patched++;
        }

        recvContext = (PDOT11_EXTSTA_RECV_CONTEXT)
            NET_BUFFER_LIST_INFO(nbl, MediaSpecificInformation);
        if (recvContext != NULL &&
            (recvContext->uPhyId != phyId ||
             recvContext->uChCenterFrequency != channelFreq ||
             recvContext->lRSSI != rssiDbm)) {
            recvContext->uPhyId = phyId;
            recvContext->uChCenterFrequency = channelFreq;
            recvContext->lRSSI = rssiDbm;
            refreshed++;
        }
    }
    KeReleaseSpinLock(&Ctx->RxQueueLock, irql);

    if (patched != 0 || refreshed != 0) {
        TraceInfo(TRACE_NETADAPTER,
                  "held frames: address 2 of %u rewritten to "
                  "%02X:%02X:%02X:%02X:%02X:%02X; receive context of %u "
                  "refreshed to phy %u, %u MHz, %d dBm\n", patched,
                  bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5],
                  refreshed, phyId, channelFreq, rssiDbm);
    }
}

static BOOLEAN Ap6256TalResolveRxPeer(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Source, AP6256_RX_ROUTE* Route)
{
    KIRQL irql;
    ULONG i;
    BOOLEAN found = FALSE;
    RtlZeroMemory(Route, sizeof(*Route));
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (IfIndex == 0) {
        Route->PortId = AP6256_STATION_PORT;
        Route->PhyId = Ctx->TalPhyId;
        Route->PortGeneration = Ctx->StationRxGeneration;
        Route->Ready = (BOOLEAN)(Ctx->TalPeerCreated && Ctx->TalRxOpen);
        found = TRUE;
    } else if (Ctx->Go.TalAdded && Ctx->Go.Started && Ctx->Go.FirmwareReady && Ctx->Go.IfIndex == IfIndex) {
        const UCHAR* peerAddress = Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_CLIENT ? Ctx->Go.ClientBssid : Source;
        for (i = 1; i < AP6256_GO_PEERS; ++i) {
            if (Ctx->Go.Peers[i].Active && RtlEqualMemory(Ctx->Go.Peers[i].Address, peerAddress, 6)) {
                Route->PortId = AP6256_GROUP_PORT;
                Route->PeerId = (UINT16)(i + 1);
                Route->Ready = Ctx->Go.Peers[i].RxOpen;
                Route->PhyId = Ctx->Go.Peers[i].PhyId;
                Route->PortGeneration = Ctx->GroupRxGeneration;
                Route->PeerGeneration = Ctx->Go.Peers[i].RxGeneration;
                found = TRUE;
                break;
            }
        }
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    return found;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                    _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
                    _In_ UCHAR Priority, _In_ UINT32 IfIndex)
{
    PNET_BUFFER_LIST nbl;
    NDIS_STATUS wifiStatus = NDIS_STATUS_SUCCESS;
    KIRQL irql, queueIrql;
    BOOLEAN queued = FALSE;
    BOOLEAN currentRoute;
    AP6256_RX_ROUTE route;
    AP6256_FIPS_FRAME_VIEW fipsView = {0};
    ULONG rawGeneration;
    BOOLEAN hostCipher;
    BOOLEAN raw = Ap6256RawRxRead(Ctx, IfIndex, Frame, Length, &fipsView, &rawGeneration, &hostCipher);
    if (Length < 14) return;
    if (!raw && !Ap6256RawGenerationCurrent(Ctx, IfIndex, 0, FALSE)) return;

    if (!Ap6256TalRxClaim(Ctx)) return;
    if (!Ap6256TalResolveRxPeer(Ctx, IfIndex, raw ? fipsView.Frame + 10 : Frame + 6, &route)) goto done;

    {
        LONG count = InterlockedIncrement(&Ctx->TalRxFrames);
        ULONG ethertype = !raw && Length >= 14 ?
            (((ULONG)Frame[12] << 8) | Frame[13]) : 0u;

        if (ethertype == 0x888Eu) {
            if (Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO && IfIndex == Ctx->Go.IfIndex)
                TraceVerbose(TRACE_DRIVER, "hotspot: EAPOL RX if %u peer %u bytes %u\n", IfIndex, (ULONG)route.PeerId, Length);

            TraceVerbose(TRACE_NETADAPTER,
                      "rx EAPOL #%d (frame %d, %u bytes) from "
                      "%02X:%02X:%02X:%02X:%02X:%02X\n",
                      InterlockedIncrement(&Ctx->TalRxEapol), count, Length,
                      Frame[6], Frame[7], Frame[8], Frame[9], Frame[10],
                      Frame[11]);
        } else {
            TraceData("rx frame #%d: %u bytes, ethertype 0x%04X\n",
                      count, Length, ethertype);
        }
    }

    nbl = Ap6256TalBuildRxNbl(Ctx, Frame, Length, Priority, IfIndex, route.PhyId);
    if (nbl == NULL) {

        if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxBuildFail)) {
            TraceError(TRACE_NETADAPTER,
                       "rx frame DROPPED: could not build the NBL (%u bytes, "
                       "pool %s, metadata allocator %s)\n", Length,
                       Ctx->RxNblPool != NULL ? "present" : "MISSING",
                       Ctx->WdiDataApi.AllocateWiFiFrameMetaData != NULL
                           ? "present" : "MISSING");
        }
        goto done;
    }

    nbl->MiniportReserved[1] = (PVOID)(ULONG_PTR)
        ((ULONG_PTR)route.PortId | ((ULONG_PTR)route.PeerId << 16) |
        ((ULONG_PTR)hostCipher << 31) | ((ULONG_PTR)(raw ? rawGeneration : 0) << 32));

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (route.PortId == AP6256_STATION_PORT) {
        currentRoute = Ctx->StationRxGeneration == route.PortGeneration;
        route.Ready = (BOOLEAN)(Ctx->TalPeerCreated && Ctx->TalRxOpen);
    } else {
        currentRoute = Ctx->Go.TalAdded && Ctx->Go.Started && Ctx->Go.FirmwareReady &&
            Ctx->Go.IfIndex == IfIndex && Ctx->GroupRxGeneration == route.PortGeneration &&
            route.PeerId > 0 && route.PeerId <= AP6256_GO_PEERS &&
            Ctx->Go.Peers[route.PeerId - 1].Active &&
            Ctx->Go.Peers[route.PeerId - 1].RxGeneration == route.PeerGeneration;
        if (currentRoute) route.Ready = Ctx->Go.Peers[route.PeerId - 1].RxOpen;
    }
    KeAcquireSpinLock(&Ctx->RxQueueLock, &queueIrql);
    if (currentRoute && Ctx->RxQueueCount < AP6256_TAL_RX_QUEUE_LIMIT) {
        if (Ctx->RxQueueTail != NULL) {
            NET_BUFFER_LIST_NEXT_NBL(Ctx->RxQueueTail) = nbl;
        } else {
            Ctx->RxQueueHead = nbl;
        }
        Ctx->RxQueueTail = nbl;
        Ctx->RxQueueCount++;
        queued = TRUE;
    }
    KeReleaseSpinLock(&Ctx->RxQueueLock, queueIrql);
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);

    if (!queued) {

        if (!currentRoute) {
            if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxStale))
                TraceDiag("receive discarded after flush/peer change: port %u peer %u\n",
                    (ULONG)route.PortId, (ULONG)route.PeerId);
        } else if (Ap6256TalTraceSlot(Ctx, Ap6256TraceRxQueueFull)) {
            TraceWarn(TRACE_NETADAPTER, "rx queue full (%u); frame dropped\n",
                      AP6256_TAL_RX_QUEUE_LIMIT);
        }
        Ap6256TalFreeRxNbl(Ctx, nbl);
        goto done;
    }

    if (!raw) Ap6256TraceHotspotPacket(Ctx, Ap6256GoDataRxQueued, IfIndex, Frame, Length, STATUS_SUCCESS);
    if (route.Ready) {
        if (!raw && Frame[12] == 0x88 && Frame[13] == 0x8e) {
            Ctx->RxBatched = 0;
            Ap6256TalNotifyRxWaiting(Ctx, WDI_RX_INDICATION_PASSIVE, &wifiStatus);
        } else if (Ctx->RxBatching && ++Ctx->RxBatched < AP6256_RX_BATCH) {

        } else {
            Ctx->RxBatched = 0;

            Ap6256TalNotifyRxWaiting(Ctx, WDI_RX_INDICATION_PASSIVE, &wifiStatus);
        }
    } else {

        TraceData("rx frame held: %s (%u queued)\n",
                  Ctx->TalPeerCreated ? "connection not announced yet"
                                      : "no datapath peer yet",
                  Ctx->RxQueueCount);
    }

done:

    Ap6256TalRxRelease(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL || Ctx->RxBatched == 0) return;
    Ctx->RxBatched = 0;
    if ((!Ctx->TalPeerCreated || !Ctx->TalRxOpen) && !Ctx->Go.Started) return;
    Ap6256TalRxIndicateQueued(Ctx, WDI_RX_INDICATION_PASSIVE, "receive batch");
}

static VOID
Ap6256TalCompleteOneNbl(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                        _In_ PNET_BUFFER_LIST Nbl,
                        _In_ WDI_TX_FRAME_STATUS FrameStatus)
{
    PWDI_FRAME_METADATA metadata = (PWDI_FRAME_METADATA)Nbl->MiniportReserved[0];
    WDI_FRAME_ID frameId = 0;
    BOOLEAN sendComplete = FALSE;

    if (metadata != NULL) {
        sendComplete = metadata->u.txMetaData.bTxCompleteRequired;
        frameId = metadata->FrameID;
    }

    NET_BUFFER_LIST_NEXT_NBL(Nbl) = NULL;

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(Ctx, Ap6256TraceTxComplete)) {
        TraceData("tx frame completed: %s (frame id %u, send complete %s)\n",
                  Ap6256TalTxStatusName(FrameStatus), (ULONG)frameId,
                  sendComplete ? "owed" : "not requested");
    }
#endif
    if (Ctx->WdiDataApi.TxTransferCompleteIndication != NULL) {
        Ap6256TalCount(Ctx, Ap6256CallUpTxTransferComplete);
#if AP6256_TRACE_DATAPATH
        TraceData("-> WDI TxTransferComplete: nbl %p status %s\n",
                  Nbl, Ap6256TalTxStatusName(FrameStatus));
#endif
        Ctx->WdiDataApi.TxTransferCompleteIndication(Ctx->WdiDataPathHandle,
                                                     FrameStatus, Nbl);
    }

    if (sendComplete && FrameStatus == WDI_TxFrameStatus_Ok &&
        Ctx->WdiDataApi.TxSendCompleteIndication != NULL) {
        Ap6256TalCount(Ctx, Ap6256CallUpTxSendComplete);
#if AP6256_TRACE_DATAPATH
        TraceData("-> WDI TxSendComplete: frame id %u status %s\n",
                  (ULONG)frameId, Ap6256TalTxStatusName(FrameStatus));
#endif
        Ctx->WdiDataApi.TxSendCompleteIndication(Ctx->WdiDataPathHandle,
                                                 FrameStatus, 1, &frameId, NULL);
    }
}

static VOID
Ap6256TalCompleteChain(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                       _In_opt_ PNET_BUFFER_LIST Nbls,
                       _In_ WDI_TX_FRAME_STATUS FrameStatus)
{
    while (Nbls != NULL) {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(Nbls);
        Ap6256TalCompleteOneNbl(Ctx, Nbls, FrameStatus);
        Nbls = next;
    }
}

static UINT16
Ap6256TalTxCredit(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    UINT16 credit;
    UINT8 window;

    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &irql);
    window = (UINT8)(Ctx->Sdio.MaxTxSeq - Ctx->Sdio.TxSeq);
    if (Ctx->Sdio.TxFlowStopped ||
        (Ctx->Sdio.FlowControl & (1u << AP6256_TX_PRIORITY)) != 0 ||
        (window & 0x80u) != 0 || window < 2u) {
        credit = 0;
    } else {
        credit = (UINT16)(window - 1u);
    }
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, irql);
    if (Ap6256WlfcEnabled(Ctx)) return Ap6256WlfcRoom(Ctx);
    return credit;
}

#if AP6256_TRACE_DATAPATH

static VOID
Ap6256TalTraceTxCredit(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Reason)
{
    KIRQL irql;
    BOOLEAN flowStopped;
    UINT32 flowControl;
    UINT8 maxSeq, seq;

    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &irql);
    flowStopped = Ctx->Sdio.TxFlowStopped;
    flowControl = Ctx->Sdio.FlowControl;
    maxSeq = Ctx->Sdio.MaxTxSeq;
    seq = Ctx->Sdio.TxSeq;
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, irql);

    TraceData("%s: window %u..%u, flow %s, fc mask 0x%08X, priority %u %s\n",
              Reason, (ULONG)seq, (ULONG)maxSeq,
              flowStopped ? "STOPPED" : "open", flowControl,
              (ULONG)AP6256_TX_PRIORITY,
              (flowControl & (1u << AP6256_TX_PRIORITY)) != 0 ? "BLOCKED"
                                                              : "clear");
}
#else
#define Ap6256TalTraceTxCredit(Ctx, Reason) ((VOID)0)
#endif

_IRQL_requires_max_(DISPATCH_LEVEL)
static BOOLEAN
Ap6256TalTxAborting(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    BOOLEAN aborting;

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    aborting = Ctx->TxAborting;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    return aborting;
}

typedef struct _AP6256_TAL_TX_CHAIN {
    AP6256_TX_GLOM_FRAME Frames[AP6256_TX_GLOM_MAX_FRAMES];
    PNET_BUFFER_LIST     Owners[AP6256_TX_GLOM_MAX_FRAMES];
    ULONG                Count;
    ULONG                Used;
    ULONG                Limit;
} AP6256_TAL_TX_CHAIN, *PAP6256_TAL_TX_CHAIN;

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256TalPackFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                   _Inout_ PAP6256_TAL_TX_CHAIN Chain,
                   _In_ PNET_BUFFER Nb,
                   _In_ PNET_BUFFER_LIST Owner)
{
    ULONG length = NET_BUFFER_DATA_LENGTH(Nb);
    ULONG hdrLen = Ap6256TxHdrLen(Ctx);
    ULONG headroom = hdrLen + sizeof(BCDC_DATA_HEADER);
    ULONG offset = Chain->Used;
    PUCHAR payload;
    PUCHAR frame;
    PBCDC_DATA_HEADER bdc;
    ULONG ethLength = 0;
    ULONG wireLength;
    NTSTATUS status;
    LONG count;
    ULONG ethertype;
    UINT32 ifIndex;
    UCHAR exemption;
    UCHAR priority = AP6256_TX_PRIORITY;
    BOOLEAN raw = FALSE;
    PWDI_FRAME_METADATA metadata = (PWDI_FRAME_METADATA)Owner->MiniportReserved[0];
    if (metadata == NULL) return STATUS_INVALID_PARAMETER;

    switch (metadata->u.txMetaData.ExemptionAction) {
    case WDI_EXEMPT_NO_EXEMPTION: exemption = BCDC_DATA_EXEMPT_NONE; break;
    case WDI_EXEMPT_ALWAYS: exemption = BCDC_DATA_EXEMPT_ALWAYS; break;
    case WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE:
        exemption = BCDC_DATA_EXEMPT_ON_NO_KEY; break;
    default: return STATUS_INVALID_PARAMETER;
    }
    if (metadata->u.txMetaData.PortID == AP6256_STATION_PORT) {
        ifIndex = 0;
    } else if (metadata->u.txMetaData.PortID == AP6256_GROUP_PORT &&
               Ctx->Go.FirmwareReady && Ctx->Go.Started) {
        ifIndex = Ctx->Go.IfIndex;
    } else return STATUS_INVALID_DEVICE_STATE;

    if (length < AP6256_80211_HDR_MIN || length > AP6256_FIPS_MAX_MPDU_BYTES) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Chain->Count >= AP6256_TX_GLOM_MAX_FRAMES) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    if (offset > Ctx->TxScratchSize || headroom + length + AP6256_FIPS_TX_HEADER_BYTES > Ctx->TxScratchSize - offset) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    payload = Ctx->TxScratch + offset + headroom;
    frame = (PUCHAR)NdisGetDataBuffer(Nb, length, payload, 1, 0);
    if (frame == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    if (frame != payload) {
        RtlCopyMemory(payload, frame, length);
    }

    ethLength = length;
    status = Ap6256RawPrepareTx(Ctx, ifIndex, payload, Ctx->TxScratchSize - offset - headroom,
        &ethLength, &priority, &exemption);
    raw = NT_SUCCESS(status);
    if (status == STATUS_NOT_SUPPORTED) status = Ap6256Tal80211ToEthernet(payload, length, &ethLength);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    if (ethLength == 0 || ethLength > (raw ? AP6256_FIPS_MAX_MPDU_BYTES + AP6256_FIPS_TX_HEADER_BYTES : 1600u)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    wireLength = headroom + ethLength;

    if (Chain->Count != 0 && offset + wireLength > Chain->Limit) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    bdc = (PBCDC_DATA_HEADER)(Ctx->TxScratch + offset + hdrLen);
    bdc->Flags = (UCHAR)((BCDC_DCMD_PROTO_VERSION << BCDC_DATA_FLAG_PROTO_SHIFT) |
                         exemption);
    bdc->Priority = priority;
    bdc->Flags2 = (UCHAR)ifIndex;
    bdc->DataOffset = 0;

    Chain->Frames[Chain->Count].Offset = offset;
    Chain->Frames[Chain->Count].WireLength = wireLength;
    Chain->Owners[Chain->Count] = Owner;
    Chain->Count++;
    Chain->Used = (offset + wireLength + 3u) & ~3u;
    if (!raw) Ap6256TraceHotspotPacket(Ctx, Ap6256GoDataTxQueued, ifIndex, payload, ethLength, STATUS_SUCCESS);

    count = InterlockedIncrement(&Ctx->TalTxFrames);
    ethertype = !raw && ethLength >= 14 ?
        (((ULONG)payload[12] << 8) | payload[13]) : 0u;
    if (ethertype == 0x888Eu) {
        if (Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO && ifIndex == Ctx->Go.IfIndex) {
            ULONG keyInfo = ethLength >= 21 && payload[15] == 3 ?
                ((ULONG)payload[19] << 8) | payload[20] : 0;
            TraceVerbose(TRACE_DRIVER, "hotspot: EAPOL TX queued if %u bytes %u exempt %u "
                "bdc 0x%02X keyinfo 0x%04X dst %02X:%02X:%02X:%02X:%02X:%02X\n",
                ifIndex, ethLength, (ULONG)metadata->u.txMetaData.ExemptionAction,
                (ULONG)bdc->Flags, keyInfo, payload[0], payload[1], payload[2],
                payload[3], payload[4], payload[5]);
        }

        TraceVerbose(TRACE_NETADAPTER,
                  "tx EAPOL #%d (frame %d, %u bytes)\n",
                  InterlockedIncrement(&Ctx->TalTxEapol), count, ethLength);
    } else {
        TraceData("tx frame #%d: %u bytes, ethertype 0x%04X\n",
                  count, ethLength, ethertype);
    }
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256TalTxNblAborting(PAP6256_DEVICE_CONTEXT Ctx, PNET_BUFFER_LIST Nbl)
{
    PWDI_FRAME_METADATA meta = (PWDI_FRAME_METADATA)Nbl->MiniportReserved[0];
    BOOLEAN aborting;
    KIRQL irql;
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    aborting = Ctx->TxAborting && meta != NULL &&
        (Ctx->TxAbortPort == WDI_PORT_ANY || meta->u.txMetaData.PortID == Ctx->TxAbortPort) &&
        (Ctx->TxAbortPeer == WDI_PEER_ANY || meta->u.txMetaData.PeerID == Ctx->TxAbortPeer);
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    return aborting;
}

static BOOLEAN Ap6256TalTxSamePeer(PNET_BUFFER_LIST A, PNET_BUFFER_LIST B)
{
    PWDI_FRAME_METADATA a = (PWDI_FRAME_METADATA)A->MiniportReserved[0];
    PWDI_FRAME_METADATA b = (PWDI_FRAME_METADATA)B->MiniportReserved[0];
    return a != NULL && b != NULL && a->u.txMetaData.PortID == b->u.txMetaData.PortID &&
        a->u.txMetaData.PeerID == b->u.txMetaData.PeerID;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static WDI_TX_FRAME_STATUS
Ap6256TalTxFlushChain(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                      _Inout_ PAP6256_TAL_TX_CHAIN Chain,
                      _In_opt_ PNET_BUFFER_LIST DeferredNbl)
{
    ULONG done = 0;
    ULONG i;
    BOOLEAN cancelled = FALSE;
    WDI_TX_FRAME_STATUS deferredStatus = WDI_TxFrameStatus_Ok;

    while (done < Chain->Count) {
        ULONG sent = 0;
        ULONG base = Chain->Frames[done].Offset;
        AP6256_TX_GLOM_FRAME frames[AP6256_TX_GLOM_MAX_FRAMES];
        NTSTATUS status;

        if (Ap6256TalTxNblAborting(Ctx, Chain->Owners[done])) {
            cancelled = TRUE;
            break;
        }

        for (i = done; i < Chain->Count; i++) {
            frames[i - done] = Chain->Frames[i];
            frames[i - done].Offset -= base;
        }
        status = Ap6256DatapathSendGlom(Ctx, Ctx->TxScratch + base,
            Ctx->TxScratchSize - base, frames, Chain->Count - done, &sent);

        if (NT_SUCCESS(status) && (sent == 0 || sent > Chain->Count - done))
            status = STATUS_DEVICE_PROTOCOL_ERROR;
        for (i = done; i < Chain->Count &&
             (!NT_SUCCESS(status) || i - done < sent); i++) {
            ULONG hdrLen = Ap6256TxHdrLen(Ctx);
            ULONG headroom = hdrLen + sizeof(BCDC_DATA_HEADER);
            const UCHAR* bdc = Ctx->TxScratch + Chain->Frames[i].Offset + hdrLen;
            const UCHAR* ether = bdc + sizeof(BCDC_DATA_HEADER);
            if ((bdc[0] & 3u) != AP6256_FIPS_BCDC_TX_EXEMPT && Chain->Frames[i].WireLength >= headroom)
                Ap6256TraceHotspotPacket(Ctx, Ap6256GoDataTxTransfer,
                    (UINT32)(bdc[2] & 0x0fu), ether,
                    Chain->Frames[i].WireLength - headroom, status);
            if ((bdc[0] & 3u) != AP6256_FIPS_BCDC_TX_EXEMPT && Chain->Frames[i].WireLength >= headroom + 14u &&
                ether[12] == 0x88 && ether[13] == 0x8e) {
                TraceVerbose(TRACE_DRIVER, "EAPOL TX transfer if %u bytes %u bdc 0x%02X "
                    "-> 0x%08X submitted %u\n", (ULONG)(bdc[2] & 0x0fu),
                    Chain->Frames[i].WireLength - headroom, (ULONG)bdc[0],
                    status, (ULONG)NT_SUCCESS(status));
            }
        }
        if (!NT_SUCCESS(status)) {
            if (status != STATUS_DEVICE_BUSY) {
                TraceWarn(TRACE_NETADAPTER, "tx failed 0x%08X (%u frame(s))\n",
                          status, Chain->Count - done);
            } else {
                TraceData("tx chain: window shut with %u frame(s) left\n",
                          Chain->Count - done);
            }
            break;
        }
        done += sent;
    }

    for (i = 0; i < Chain->Count; ) {
        PNET_BUFFER_LIST nbl = Chain->Owners[i];
        ULONG last = i;
        WDI_TX_FRAME_STATUS frameStatus;

        while (last + 1 < Chain->Count && Chain->Owners[last + 1] == nbl) {
            last++;
        }
        if (last < done) {
            frameStatus = WDI_TxFrameStatus_Ok;
        } else if (cancelled) {
            frameStatus = WDI_TxFrameStatus_TransferCancelled;
        } else {
            frameStatus = WDI_TxFrameStatus_TransferFailed;
        }

        if (nbl == DeferredNbl) {
            deferredStatus = frameStatus;
        } else {
            Ap6256TalCompleteOneNbl(Ctx, nbl, frameStatus);
        }
        i = last + 1;
    }

    Chain->Count = 0;
    Chain->Used = 0;
    return deferredStatus;
}

static VOID
Ap6256TalTxPauseIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Pause)
{
    WDI_PORT_ID port;
    for (port = AP6256_STATION_PORT; port <= AP6256_GROUP_PORT; port += 2) {
        if (port == AP6256_STATION_PORT ? !Ctx->TalPortValid : !Ctx->Go.TalAdded) continue;
    if (Pause) {
        if (Ctx->WdiDataApi.TxSendPauseIndication != NULL) {
            Ap6256TalCount(Ctx, Ap6256CallUpTxSendPause);
            Ctx->WdiDataApi.TxSendPauseIndication(Ctx->WdiDataPathHandle,
                                                  port, WDI_PEER_ANY,
                                                  WDI_EXT_TID_UNKNOWN,
                                                  AP6256_TX_PAUSE_REASON);
        }
    } else if (Ctx->WdiDataApi.TxSendRestartIndication != NULL) {
        Ap6256TalCount(Ctx, Ap6256CallUpTxSendRestart);
        Ctx->WdiDataApi.TxSendRestartIndication(Ctx->WdiDataPathHandle,
                                                port, WDI_PEER_ANY,
                                                WDI_EXT_TID_UNKNOWN,
                                                AP6256_TX_PAUSE_REASON);
    }

    TraceData("tx %s -> WDI: port %u peer 0x%04X tid 0x%02X reason 0x%08X\n",
              Pause ? "pause" : "restart", (ULONG)port, WDI_PEER_ANY,
              WDI_EXT_TID_UNKNOWN, (ULONG)AP6256_TX_PAUSE_REASON);
    }
}

static VOID
Ap6256TalTxResumePort(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ WDI_PORT_ID PortId)
{
    if (Ctx == NULL) return;

    UNREFERENCED_PARAMETER(PortId);

    if (Ctx->TxPaused == 0) return;

    Ctx->TxPaused = 0;
    TraceInfo(TRACE_NETADAPTER,
              "transmit was paused when the port went down; restarting "
              "WDI so the pause does not outlive the port\n");
    Ap6256TalTxPauseIndicate(Ctx, FALSE);
}

typedef struct _AP6256_WLFC_NBL {
    PAP6256_DEVICE_CONTEXT Ctx;
    KSPIN_LOCK Lock;
    volatile LONG References;
    ULONG Transfers, Sends;
    BOOLEAN Sealed, TransferClaimed, TransferIndicated, SendClaimed, SendRequired;
    WDI_TX_FRAME_STATUS TransferStatus, SendStatus;
    WDI_FRAME_ID FrameId;
    PNET_BUFFER_LIST Nbl;
} AP6256_WLFC_NBL;

static VOID Ap6256TalWlfcRelease(AP6256_WLFC_NBL* Group)
{
    if (InterlockedDecrement(&Group->References) == 0)
        ExFreePoolWithTag(Group, AP6256_POOL_TAG);
}

static VOID Ap6256TalWlfcComplete(AP6256_WLFC_NBL* Group)
{
    PAP6256_DEVICE_CONTEXT ctx = Group->Ctx;
    KIRQL irql;
    PNET_BUFFER_LIST nbl = NULL;
    WDI_FRAME_ID frameId;
    WDI_TX_FRAME_STATUS transferStatus, sendStatus;
    BOOLEAN send = FALSE;
    KeAcquireSpinLock(&Group->Lock, &irql);
    transferStatus = Group->TransferStatus;
    if (Group->Sealed && Group->Transfers == 0 && !Group->TransferClaimed) {
        Group->TransferClaimed = TRUE;
        nbl = Group->Nbl;
        Group->Nbl = NULL;
    }
    KeReleaseSpinLock(&Group->Lock, irql);
    if (nbl != NULL) {
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        if (ctx->WdiDataApi.TxTransferCompleteIndication != NULL) {
            Ap6256TalCount(ctx, Ap6256CallUpTxTransferComplete);
            ctx->WdiDataApi.TxTransferCompleteIndication(ctx->WdiDataPathHandle, transferStatus, nbl);
        }

        KeAcquireSpinLock(&Group->Lock, &irql);
        Group->TransferIndicated = TRUE;
        KeReleaseSpinLock(&Group->Lock, irql);
    }
    KeAcquireSpinLock(&Group->Lock, &irql);
    frameId = Group->FrameId; sendStatus = Group->SendStatus;
    if (Group->Sealed && Group->TransferIndicated && Group->Sends == 0 &&
        !Group->SendClaimed) {
        Group->SendClaimed = TRUE;
        send = Group->SendRequired && Group->TransferStatus == WDI_TxFrameStatus_Ok;
    }
    KeReleaseSpinLock(&Group->Lock, irql);
    if (send && ctx->WdiDataApi.TxSendCompleteIndication != NULL) {
        Ap6256TalCount(ctx, Ap6256CallUpTxSendComplete);
        ctx->WdiDataApi.TxSendCompleteIndication(ctx->WdiDataPathHandle, sendStatus, 1, &frameId, NULL);
    }
}

static VOID Ap6256TalWlfcResult(PVOID Cookie, AP6256_WLFC_COMPLETION Completion,
    AP6256_WLFC_RESULT Result)
{
    AP6256_WLFC_NBL* group = (AP6256_WLFC_NBL*)Cookie;
    WDI_TX_FRAME_STATUS status;
    KIRQL irql;
    if (Completion == Ap6256WlfcTransfer) {
        status = Result == Ap6256WlfcOk ? WDI_TxFrameStatus_Ok :
            Result == Ap6256WlfcCancelled ? WDI_TxFrameStatus_TransferCancelled : WDI_TxFrameStatus_TransferFailed;
        KeAcquireSpinLock(&group->Lock, &irql);
        NT_ASSERT(group->Transfers != 0);
        group->Transfers--;
        if (status != WDI_TxFrameStatus_Ok && group->TransferStatus == WDI_TxFrameStatus_Ok)
            group->TransferStatus = status;
    } else {
        status = Result == Ap6256WlfcOk ? WDI_TxFrameStatus_Ok :
            Result == Ap6256WlfcNoAck ? WDI_TxFrameStatus_NoAck :
            Result == Ap6256WlfcCancelled ? WDI_TxFrameStatus_SendCancelled : WDI_TxFrameStatus_Discard;
        KeAcquireSpinLock(&group->Lock, &irql);
        NT_ASSERT(group->Sends != 0);
        group->Sends--;
        if (status != WDI_TxFrameStatus_Ok) group->SendStatus = status;
    }
    KeReleaseSpinLock(&group->Lock, irql);
    Ap6256TalWlfcComplete(group);
    Ap6256TalWlfcRelease(group);
}

_Use_decl_annotations_
VOID Ap6256TalWlfcAbortProgress(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    BOOLEAN confirm = FALSE;
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (Ctx->TxAbortConfirmNeeded && Ctx->TxPassesActive == 0 &&
        Ap6256WlfcPending(Ctx, Ctx->TxAbortPort, Ctx->TxAbortPeer) == 0) {
        Ctx->TxAbortConfirmNeeded = FALSE;
        Ap6256WlfcAbortEnd(Ctx);
        Ctx->TxAborting = FALSE;
        confirm = TRUE;
    }
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    if (confirm && Ctx->WdiDataApi.TxAbortConfirm != NULL) {
        Ap6256TalCount(Ctx, Ap6256CallUpTxAbortConfirm);
        Ctx->WdiDataApi.TxAbortConfirm(Ctx->WdiDataPathHandle);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256TalWlfcQueue(PAP6256_DEVICE_CONTEXT Ctx, PNET_BUFFER_LIST Nbls)
{
    while (Nbls != NULL) {
        PNET_BUFFER_LIST nbl = Nbls;
        PWDI_FRAME_METADATA meta = (PWDI_FRAME_METADATA)nbl->MiniportReserved[0];
        AP6256_WLFC_NBL* group;
        PNET_BUFFER nb;
        UCHAR exemption = 0, ifIndex = 0;
        KIRQL irql;
        BOOLEAN failed = FALSE;
        Nbls = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        if (meta == NULL || Ap6256TalTxNblAborting(Ctx, nbl)) {
            Ap6256TalCompleteOneNbl(Ctx, nbl, WDI_TxFrameStatus_TransferCancelled);
            continue;
        }
        switch (meta->u.txMetaData.ExemptionAction) {
        case WDI_EXEMPT_NO_EXEMPTION: exemption = BCDC_DATA_EXEMPT_NONE; break;
        case WDI_EXEMPT_ALWAYS: exemption = BCDC_DATA_EXEMPT_ALWAYS; break;
        case WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE: exemption = BCDC_DATA_EXEMPT_ON_NO_KEY; break;
        default: failed = TRUE; break;
        }
        if (meta->u.txMetaData.PortID == AP6256_STATION_PORT) ifIndex = 0;
        else if (meta->u.txMetaData.PortID == AP6256_GROUP_PORT && Ctx->Go.FirmwareReady && Ctx->Go.Started)
            ifIndex = (UCHAR)Ctx->Go.IfIndex;
        else failed = TRUE;
        group = (AP6256_WLFC_NBL*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*group), AP6256_POOL_TAG);
        if (group == NULL) {
            Ap6256TalCompleteOneNbl(Ctx, nbl, WDI_TxFrameStatus_TransferFailed);
            continue;
        }
        group->Ctx = Ctx; group->Nbl = nbl; group->FrameId = meta->FrameID;
        group->SendRequired = meta->u.txMetaData.bTxCompleteRequired;
        group->References = 1;
        KeInitializeSpinLock(&group->Lock);
        for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL && !failed; nb = NET_BUFFER_NEXT_NB(nb)) {
            ULONG length = NET_BUFFER_DATA_LENGTH(nb), ethernet = 0, qos;
            PUCHAR source;
            UINT16 fc;
            UCHAR priority = AP6256_TX_PRIORITY;
            UCHAR frameExemption = exemption;
            NTSTATUS status;
            if (length < AP6256_80211_HDR_MIN || length > AP6256_FIPS_MAX_MPDU_BYTES ||
                length > Ctx->TxScratchSize || Ap6256TalTxNblAborting(Ctx, nbl)) { failed = TRUE; break; }
            source = NdisGetDataBuffer(nb, length, Ctx->TxScratch, 1, 0);
            if (source == NULL) { failed = TRUE; break; }
            if (source != Ctx->TxScratch) RtlCopyMemory(Ctx->TxScratch, source, length);
            fc = (UINT16)(Ctx->TxScratch[0] | ((UINT16)Ctx->TxScratch[1] << 8));
            qos = AP6256_80211_HDR_MIN;
            if ((fc & (AP6256_FC_TODS | AP6256_FC_FROMDS)) == (AP6256_FC_TODS | AP6256_FC_FROMDS)) qos += 6;
            if ((fc & AP6256_FC_SUBTYPE_QOS) && qos + 2 <= length)
                priority = Ctx->TxScratch[qos] & 7u;
            ethernet = length;
            status = Ap6256RawPrepareTx(Ctx, ifIndex, Ctx->TxScratch, Ctx->TxScratchSize,
                &ethernet, &priority, &frameExemption);
            if (status == STATUS_NOT_SUPPORTED) status = Ap6256Tal80211ToEthernet(Ctx->TxScratch, length, &ethernet);
            if (!NT_SUCCESS(status)) { failed = TRUE; break; }
            KeAcquireSpinLock(&group->Lock, &irql);
            group->Transfers++; group->Sends++;
            InterlockedExchangeAdd(&group->References, 2);
            KeReleaseSpinLock(&group->Lock, irql);
            status = Ap6256WlfcEnqueue(Ctx, Ctx->TxScratch, ethernet, priority, frameExemption,
                ifIndex, meta->u.txMetaData.PortID, meta->u.txMetaData.PeerID, Ap6256TalWlfcResult, group);
            if (!NT_SUCCESS(status)) {
                KeAcquireSpinLock(&group->Lock, &irql);
                group->Transfers--; group->Sends--;
                KeReleaseSpinLock(&group->Lock, irql);
                Ap6256TalWlfcRelease(group); Ap6256TalWlfcRelease(group);
                failed = TRUE;
            }
        }
        if (NET_BUFFER_LIST_FIRST_NB(nbl) == NULL) failed = TRUE;

        if (Ap6256TalTxNblAborting(Ctx, nbl)) failed = TRUE;
        if (failed) Ap6256WlfcCancel(Ctx, AP6256_WLFC_ANY, AP6256_WLFC_ANY, group);
        KeAcquireSpinLock(&group->Lock, &irql);
        if (failed) group->TransferStatus = WDI_TxFrameStatus_TransferFailed;
        group->Sealed = TRUE;
        KeReleaseSpinLock(&group->Lock, irql);
        Ap6256TalWlfcComplete(group);
        Ap6256TalWlfcRelease(group);
    }
}

static VOID
Ap6256TalTxPass(_In_ PAP6256_DEVICE_CONTEXT ctx)
{
    PNET_BUFFER_LIST nbls = NULL;
    UINT16 credit;

    if (ctx->HostTxQuiesced != 0) return;
    credit = Ap6256TalTxCredit(ctx);

    if (credit == 0) {
        if (ctx->TxPaused == 0) {
            Ap6256TalTraceTxCredit(ctx, "tx pass has no credit, pausing WDI");
            ctx->TxPaused = 1;
            Ap6256TalTxPauseIndicate(ctx, TRUE);
        }

        if (Ap6256TalTxCredit(ctx) != 0) {
            InterlockedExchange(&ctx->TxPassRerun, 1);
        }
        return;
    }

    if (ctx->TxPaused != 0) {
        ctx->TxPaused = 0;
        Ap6256TalTraceTxCredit(ctx, "tx credit is back, restarting WDI");
        Ap6256TalTxPauseIndicate(ctx, FALSE);
    }

    InterlockedExchange(&ctx->TxEmptyDequeueCredit, -1);
    if (ctx->WdiDataApi.TxDequeueIndication != NULL) {
        Ap6256TalCount(ctx, Ap6256CallUpTxDequeue);
        TraceData("-> WDI TxDequeue: asking for up to %u frame(s)\n",
                  (ULONG)credit);
        ctx->WdiDataApi.TxDequeueIndication(ctx->WdiDataPathHandle,
                                            WDI_QUANTUM_INVALID,
                                            WDI_TX_MAX_FRAME_COUNT_INVALID,
                                            credit,
                                            &nbls);
    }

#if AP6256_TRACE_DATAPATH
    if (InterlockedIncrement(&ctx->TalTxPasses) <= AP6256_TAL_TRACE_BUDGET) {
        ULONG got = 0;
        PNET_BUFFER_LIST walk;

        for (walk = nbls; walk != NULL; walk = NET_BUFFER_LIST_NEXT_NBL(walk)) {
            got++;
        }
        TraceData("tx pass #%d: credit %u -> WDI gave %u frame(s)\n",
                  ctx->TalTxPasses, (ULONG)credit, got);
    }
#endif

    if (nbls == NULL) {

        InterlockedExchange(&ctx->TxEmptyDequeueCredit, (LONG)credit);
        if (Ap6256TalTxCredit(ctx) > credit)
            InterlockedExchange(&ctx->TxPassRerun, 1);
        return;
    }

    if (!ctx->DatapathRunning) {
        Ap6256TalCompleteChain(ctx, nbls, WDI_TxFrameStatus_TransferFailed);
        return;
    }

    if (Ap6256WlfcEnabled(ctx)) {
        Ap6256TalWlfcQueue(ctx, nbls);
        return;
    }

    {
        AP6256_TAL_TX_CHAIN chain;
        PNET_BUFFER_LIST nbl = nbls;

        chain.Count = 0;
        chain.Used = 0;
        chain.Limit = Ap6256DatapathTxGlomBytes(ctx);

        while (nbl != NULL) {
            PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(nbl);
            ULONG countBefore = chain.Count;
            ULONG usedBefore = chain.Used;
            PNET_BUFFER nb;
            NTSTATUS status = STATUS_SUCCESS;
            WDI_TX_FRAME_STATUS failureStatus = WDI_TxFrameStatus_TransferFailed;

            if (chain.Count != 0 && !Ap6256TalTxSamePeer(chain.Owners[0], nbl)) {
                (VOID)Ap6256TalTxFlushChain(ctx, &chain, NULL);
                countBefore = 0;
                usedBefore = 0;
            }
            if (Ap6256TalTxNblAborting(ctx, nbl)) {
                (VOID)Ap6256TalTxFlushChain(ctx, &chain, NULL);
                Ap6256TalCompleteOneNbl(ctx, nbl, WDI_TxFrameStatus_TransferCancelled);
                nbl = next;
                continue;
            }

            nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (nb == NULL) status = STATUS_INVALID_BUFFER_SIZE;
            for (; nb != NULL; nb = NET_BUFFER_NEXT_NB(nb)) {
                status = Ap6256TalPackFrame(ctx, &chain, nb, nbl);
                if (status == STATUS_BUFFER_TOO_SMALL) {

                    WDI_TX_FRAME_STATUS prefixStatus =
                        Ap6256TalTxFlushChain(ctx, &chain, nbl);
                    countBefore = 0;
                    usedBefore = 0;
                    if (prefixStatus != WDI_TxFrameStatus_Ok) {
                        failureStatus = prefixStatus;
                        status = STATUS_UNSUCCESSFUL;
                        break;
                    }
                    if (Ap6256TalTxNblAborting(ctx, nbl)) {
                        failureStatus = WDI_TxFrameStatus_TransferCancelled;
                        status = STATUS_CANCELLED;
                        break;
                    }
                    status = Ap6256TalPackFrame(ctx, &chain, nb, nbl);
                }
                if (!NT_SUCCESS(status)) {
                    break;
                }
            }

            if (!NT_SUCCESS(status)) {
                chain.Count = countBefore;
                chain.Used = usedBefore;
                TraceWarn(TRACE_NETADAPTER, "tx NBL incomplete 0x%08X, frame status %u\n",
                          status, (ULONG)failureStatus);
                Ap6256TalCompleteOneNbl(ctx, nbl, failureStatus);
            }
            nbl = next;
        }

        if (chain.Count != 0) {
            (VOID)Ap6256TalTxFlushChain(ctx, &chain, NULL);
        }
    }

    if (!Ap6256TalTxAborting(ctx) && Ap6256TalTxCredit(ctx) != 0) {
        InterlockedExchange(&ctx->TxPassRerun, 1);
    }
}

static VOID
Ap6256TalTxCountedPass(_In_ PAP6256_DEVICE_CONTEXT ctx)
{
    KIRQL irql;
    BOOLEAN confirmAbort = FALSE;

    TraceData("tx worker: started %u aborting %u credit %u\n",
              (ULONG)ctx->TalStarted, (ULONG)ctx->TxAborting,
              (ULONG)Ap6256TalTxCredit(ctx));

    if (!ctx->TalStarted) {
        TraceWarn(TRACE_NETADAPTER,
                  "tx worker: leaving, the TAL data path is not started\n");
        return;
    }

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    ctx->TxPassesActive++;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    Ap6256LockAcquire(&ctx->TxPassLock);
    if (!Ap6256TalTxAborting(ctx)) {
        Ap6256TalTxPass(ctx);
    }
    Ap6256LockRelease(&ctx->TxPassLock);

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    NT_ASSERT(ctx->TxPassesActive != 0);
    if (--ctx->TxPassesActive == 0 && ctx->TxAbortConfirmNeeded &&
        Ap6256WlfcPending(ctx, ctx->TxAbortPort, ctx->TxAbortPeer) == 0) {
        ctx->TxAbortConfirmNeeded = FALSE;
        Ap6256WlfcAbortEnd(ctx);
        ctx->TxAborting = FALSE;
        confirmAbort = TRUE;
    }
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    if (confirmAbort && ctx->WdiDataApi.TxAbortConfirm != NULL) {
        Ap6256TalCount(ctx, Ap6256CallUpTxAbortConfirm);
        TraceInfo(TRACE_NETADAPTER, "-> WDI TxAbortConfirm\n");
        ctx->WdiDataApi.TxAbortConfirm(ctx->WdiDataPathHandle);
    }
}

static VOID
Ap6256TalTxWorker(_In_ PVOID Context)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)Context;
    LONG keyFence;

    InterlockedExchange(&ctx->TxPassRerun, 0);

    keyFence = InterlockedCompareExchange(&ctx->TxKeyFenceRequested, 0, 0);
    Ap6256TalTxCountedPass(ctx);
    InterlockedExchange(&ctx->TxKeyFenceCompleted, keyFence);

    InterlockedExchange(&ctx->TxPassScheduled, 0);
    if (InterlockedCompareExchange(&ctx->TxPassRerun, 0, 0) != 0 &&
        InterlockedCompareExchange(&ctx->TxPassScheduled, 1, 0) == 0) {
        Ap6256WorkItemEnqueue(&ctx->TxWorker);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID
Ap6256TalTxSchedule(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    InterlockedExchange(&Ctx->TxPassRerun, 1);
    if (InterlockedCompareExchange(&Ctx->TxPassScheduled, 1, 0) == 0) {
        Ap6256WorkItemEnqueue(&Ctx->TxWorker);
    }
}

_Use_decl_annotations_
NTSTATUS Ap6256NetTxSynchronize(PAP6256_DEVICE_CONTEXT Ctx, ULONGLONG Deadline)
{
    LARGE_INTEGER interval;
    ULONG ticket;
    if (!Ctx->TalStarted || !Ctx->DatapathRunning || Ctx->HostTxQuiesced != 0)
        return STATUS_DEVICE_NOT_READY;
    ticket = (ULONG)InterlockedIncrement(&Ctx->TxKeyFenceRequested);
    interval.QuadPart = -10000ll;
    Ap6256TalTxSchedule(Ctx);
    for (;;) {
        ULONG completed = (ULONG)InterlockedCompareExchange(&Ctx->TxKeyFenceCompleted, 0, 0);
        if (!Ctx->TalStarted || !Ctx->DatapathRunning || Ctx->HostTxQuiesced != 0)
            return STATUS_DEVICE_NOT_READY;
        if ((LONG)(completed - ticket) >= 0) return STATUS_SUCCESS;
        if (KeQueryInterruptTime() >= Deadline) {
            TraceWarn(TRACE_NETADAPTER, "key update blocked by the WDI transmit queue\n");
            return STATUS_IO_TIMEOUT;
        }
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256WdiTxResume(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    LONG emptyCredit;
    if (!Ctx->TalStarted) {
        return;
    }
    if (InterlockedCompareExchange(&Ctx->TxPaused, 0, 0) == 0) {
        emptyCredit = InterlockedCompareExchange(&Ctx->TxEmptyDequeueCredit, 0, 0);
        if (emptyCredit < 0 || Ap6256TalTxCredit(Ctx) <= (UINT16)emptyCredit)
            return;
    }
    Ap6256TalTxSchedule(Ctx);
}

static MINIPORT_WDI_TX_ABORT                       Ap6256TalTxAbort;
static MINIPORT_WDI_TX_TARGET_DESC_INIT            Ap6256TalTxTargetDescInit;
static MINIPORT_WDI_TX_TARGET_DESC_DEINIT          Ap6256TalTxTargetDescDeInit;
static MINIPORT_WDI_TX_DATA_SEND                   Ap6256TalTxDataSend;
static MINIPORT_WDI_TX_TAL_SEND                    Ap6256TalTxTalSend;
static MINIPORT_WDI_TX_TAL_SEND_COMPLETE           Ap6256TalTxTalSendComplete;
static MINIPORT_WDI_TX_TAL_QUEUE_IN_ORDER          Ap6256TalTxQueueInOrder;
static MINIPORT_WDI_TX_PEER_BACKLOG                Ap6256TalTxPeerBacklog;
static MINIPORT_WDI_RX_STOP                        Ap6256TalRxStop;
static MINIPORT_WDI_RX_FLUSH                       Ap6256TalRxFlush;
static MINIPORT_WDI_RX_RESTART                     Ap6256TalRxRestart;
static MINIPORT_WDI_RX_GET_MPDUS                   Ap6256TalRxGetMpdus;
static MINIPORT_WDI_RX_RETURN_FRAMES               Ap6256TalRxReturnFrames;
static MINIPORT_WDI_RX_RESUME                      Ap6256TalRxResume;
static MINIPORT_WDI_RX_THROTTLE                    Ap6256TalRxThrottle;
static MINIPORT_WDI_RX_PPDU_RSSI                   Ap6256TalRxPpduRssi;
static MINIPORT_WDI_TAL_TXRX_START                 Ap6256TalTxRxStart;
static MINIPORT_WDI_TAL_TXRX_STOP                  Ap6256TalTxRxStop;
static MINIPORT_WDI_TAL_TXRX_ADD_PORT              Ap6256TalTxRxAddPort;
static MINIPORT_WDI_TAL_TXRX_DELETE_PORT           Ap6256TalTxRxDeletePort;
static MINIPORT_WDI_TAL_TXRX_SET_PORT_OPMODE       Ap6256TalTxRxSetPortOpMode;
static MINIPORT_WDI_TAL_TXRX_RESET_PORT            Ap6256TalTxRxResetPort;
static MINIPORT_WDI_TAL_TXRX_PEER_CONFIG           Ap6256TalTxRxPeerConfig;
static MINIPORT_WDI_TAL_TXRX_PEER_DELETE_CONFIRM   Ap6256TalTxRxPeerDeleteConfirm;

_Use_decl_annotations_
static VOID
Ap6256TalTxDataSend(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                    WDI_PEER_ID PeerId, WDI_EXTENDED_TID ExTid,
                    UINT16 NumQueueFrames, UINT32 NumActiveFrames,
                    BOOLEAN bRobustnessFlag)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    UNREFERENCED_PARAMETER(bRobustnessFlag);
    UNREFERENCED_PARAMETER(PortId);
    UNREFERENCED_PARAMETER(PeerId);
    UNREFERENCED_PARAMETER(ExTid);
    UNREFERENCED_PARAMETER(NumQueueFrames);
    UNREFERENCED_PARAMETER(NumActiveFrames);

#if AP6256_TRACE_DATAPATH
    if (InterlockedIncrement(&ctx->TalTxRequests) <= AP6256_TAL_TRACE_BUDGET) {
        TraceData("tx request #%d: WDI has frames for port %u peer %u tid %u "
                  "(%u queued, %u active)\n",
                  ctx->TalTxRequests, (ULONG)PortId, (ULONG)PeerId,
                  (ULONG)ExTid, (ULONG)NumQueueFrames, NumActiveFrames);
        Ap6256TalTraceTxCredit(ctx, "tx request credit");
    }
#endif

    Ap6256TalTxSchedule(ctx);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxTalSend(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                   WDI_PEER_ID PeerId, WDI_EXTENDED_TID ExTid,
                   UINT16 NumQueueFrames, UINT32 NumActiveFrames,
                   BOOLEAN bRobustnessFlag)
{

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxTalSend)) {
        TraceData("tx TAL send: port %u peer %u tid %u (%u queued, %u active)\n",
                  (ULONG)PortId, (ULONG)PeerId, (ULONG)ExTid,
                  (ULONG)NumQueueFrames, NumActiveFrames);
    }
#endif
    Ap6256TalTxDataSend(MiniportTalTxRxContext, PortId, PeerId, ExTid,
                        NumQueueFrames, NumActiveFrames, bRobustnessFlag);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxTalSendComplete(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                           PNET_BUFFER_LIST pNBL, WDI_TX_FRAME_STATUS TxFrameStatus)
{
    UNREFERENCED_PARAMETER(MiniportTalTxRxContext);
    UNREFERENCED_PARAMETER(pNBL);
    UNREFERENCED_PARAMETER(TxFrameStatus);

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxSendComplete)) {
        TraceData("tx TAL send complete: %s\n",
                  Ap6256TalTxStatusName(TxFrameStatus));
    }
#endif
}

_Use_decl_annotations_
static VOID
Ap6256TalTxAbort(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                 WDI_PEER_ID PeerId, NDIS_STATUS *pWifiStatus)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    KIRQL irql;
    BOOLEAN pending;

    Ap6256TalCount(ctx, Ap6256CallTxAbort);

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    pending = (BOOLEAN)(ctx->TxPassesActive != 0 || Ap6256WlfcPending(ctx, PortId, PeerId) != 0);
    if (pending) {
        ctx->TxAbortPort = PortId;
        ctx->TxAbortPeer = PeerId;
        ctx->TxAborting = TRUE;
        ctx->TxAbortConfirmNeeded = TRUE;
        Ap6256WlfcAbortBegin(ctx, PortId, PeerId);
    }
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    *pWifiStatus = pending ? NDIS_STATUS_PENDING : NDIS_STATUS_SUCCESS;
    TraceInfo(TRACE_NETADAPTER,
              "WDI aborted transmit on port %u peer %u -> %s\n",
              (ULONG)PortId, (ULONG)PeerId, pending ? "PENDING" : "SUCCESS");
}

_Use_decl_annotations_
static VOID
Ap6256TalTxTargetDescInit(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                          PNET_BUFFER_LIST pNBL, NDIS_STATUS *pWifiStatus)
{
    PNET_BUFFER_LIST nbl;
    ULONG counted = 0;
    ULONG missing = 0;
    NDIS_STATUS result = NDIS_STATUS_SUCCESS;

    for (nbl = pNBL; nbl != NULL; nbl = NET_BUFFER_LIST_NEXT_NBL(nbl)) {
        PWDI_FRAME_METADATA metadata =
            (PWDI_FRAME_METADATA)nbl->MiniportReserved[0];

        if (metadata != NULL) {
            PNET_BUFFER nb;
            ULONG cost = 0;
            for (nb = NET_BUFFER_LIST_FIRST_NB(nbl); nb != NULL;
                 nb = NET_BUFFER_NEXT_NB(nb)) {
                if (++cost == WDI_TX_CREDIT_INVALID) break;
            }

            if (cost == 0 || cost == WDI_TX_CREDIT_INVALID ||
                (cost > AP6256_WLFC_CAPACITY &&
                 Ap6256WlfcEnabled((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext))) {
                metadata->u.txMetaData.TxCost = 0;
                result = NDIS_STATUS_INVALID_DATA;
            } else {
                metadata->u.txMetaData.TxCost = (UINT16)cost;
            }
            counted++;
        } else {
            missing++;
            result = NDIS_STATUS_INVALID_DATA;
        }
    }

    if (missing != 0) {
        TraceWarn(TRACE_NETADAPTER,
                  "tx descriptor init: %u NBL(s) with no frame metadata\n",
                  missing);
    }

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxDescInit)) {
        TraceData("tx descriptor init: %u NBL(s), cost per buffer, status 0x%08X\n",
                  counted, result);
    }
#endif
    UNREFERENCED_PARAMETER(MiniportTalTxRxContext);

    *pWifiStatus = result;
}

_Use_decl_annotations_
static VOID
Ap6256TalTxTargetDescDeInit(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                            PNET_BUFFER_LIST pNBL)
{
    UNREFERENCED_PARAMETER(MiniportTalTxRxContext);
    UNREFERENCED_PARAMETER(pNBL);

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxDescDeInit)) {
        TraceData("tx descriptor released\n");
    }
#endif
}

_Use_decl_annotations_
static VOID
Ap6256TalTxQueueInOrder(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                        WDI_PEER_ID PeerId, UINT32 ExTidBitmask)
{
    UNREFERENCED_PARAMETER(MiniportTalTxRxContext);
    UNREFERENCED_PARAMETER(PeerId);
    UNREFERENCED_PARAMETER(ExTidBitmask);

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxQueueInOrder)) {
        TraceData("tx queue in order: peer %u tid mask 0x%08X\n",
                  (ULONG)PeerId, ExTidBitmask);
    }
#endif
}

_Use_decl_annotations_
static VOID
Ap6256TalTxPeerBacklog(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                       WDI_PEER_ID PeerId, BOOLEAN bBacklogged)
{
    UNREFERENCED_PARAMETER(MiniportTalTxRxContext);
    UNREFERENCED_PARAMETER(PortId);
    UNREFERENCED_PARAMETER(PeerId);
    UNREFERENCED_PARAMETER(bBacklogged);

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                           Ap6256TraceTxPeerBacklog)) {
        TraceData("tx peer backlog: port %u peer %u %s\n",
                  (ULONG)PortId, (ULONG)PeerId,
                  bBacklogged ? "BACKLOGGED" : "drained");
    }
#endif
}

_Use_decl_annotations_
static VOID
Ap6256TalRxStop(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                NDIS_STATUS *pWifiStatus)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    KIRQL irql;

    UNREFERENCED_PARAMETER(PortId);
    Ap6256TalCount(ctx, Ap6256CallRxStop);

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    if (PortId == WDI_PORT_ANY) {
        ctx->StationRxStopped = TRUE;
        ctx->Go.RxStopped = TRUE;
    }
    else if (PortId == AP6256_GROUP_PORT) ctx->Go.RxStopped = TRUE;
    else if (PortId == AP6256_STATION_PORT) ctx->StationRxStopped = TRUE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    *pWifiStatus = NDIS_STATUS_SUCCESS;
    TraceInfo(TRACE_NETADAPTER, "WDI stopped receive on port %u -> SUCCESS\n",
              (ULONG)PortId);
}

_Use_decl_annotations_
static VOID
Ap6256TalRxFlush(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    Ap6256TalCount(ctx, Ap6256CallRxFlush);
    TraceInfo(TRACE_NETADAPTER, "WDI flushed receive on port %u\n",
              (ULONG)PortId);
    Ap6256TalFlushPortRx(ctx, PortId, WDI_PEER_ANY);
    if (ctx->WdiDataApi.RxFlushConfirm != NULL) {
        Ap6256TalCount(ctx, Ap6256CallUpRxFlushConfirm);
        TraceInfo(TRACE_NETADAPTER, "-> WDI RxFlushConfirm\n");
        ctx->WdiDataApi.RxFlushConfirm(ctx->WdiDataPathHandle);
    } else {
        TraceWarn(TRACE_NETADAPTER,
                  "RxFlushConfirm MISSING; WDI was not told the flush "
                  "finished\n");
    }
}

_Use_decl_annotations_
static VOID
Ap6256TalRxRestart(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    KIRQL irql;

    Ap6256TalCount(ctx, Ap6256CallRxRestart);
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    if (PortId == WDI_PORT_ANY) {
        ctx->RxStopped = FALSE; ctx->StationRxStopped = FALSE; ctx->Go.RxStopped = FALSE;
    } else if (PortId == AP6256_GROUP_PORT) ctx->Go.RxStopped = FALSE;
    else if (PortId == AP6256_STATION_PORT) ctx->StationRxStopped = FALSE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    TraceInfo(TRACE_NETADAPTER, "WDI restarted receive on port %u\n",
              (ULONG)PortId);
    Ap6256TalRxIndicateQueued(ctx,
                              KeGetCurrentIrql() > PASSIVE_LEVEL
                                  ? WDI_RX_INDICATION_DISPATCH_GENERAL
                                  : WDI_RX_INDICATION_PASSIVE,
                              "receive restarted");
}

_Use_decl_annotations_
static VOID

Ap6256TalRxResume(TAL_TXRX_HANDLE MiniportTalTxRxContext)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    KIRQL irql;
    BOOLEAN wasPaused;

    Ap6256TalCount(ctx, Ap6256CallRxResume);
    Ap6256TalDumpCallCensus(ctx, "WDI resumed receive");
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    wasPaused = ctx->RxPaused;
    ctx->RxPaused = FALSE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    if (Ap6256TalTraceSlot(ctx, Ap6256TraceRxResumed)) {
        TraceInfo(TRACE_NETADAPTER, "WDI resumed receive (was %s)\n",
                  wasPaused ? "paused" : "running");
    }

    Ap6256TalRxIndicateQueued(ctx, WDI_RX_INDICATION_FROM_RX_RESUME_FRAMES,
                              "receive resumed");
}

static BOOLEAN Ap6256TalRxOwnerCurrent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, PNET_BUFFER_LIST Nbl)
{
    PNET_BUFFER nb;
    ULONG length, generation;
    PUCHAR frame;
    BOOLEAN hostCipher;
    AP6256_FIPS_FRAME_VIEW view;
    if (!Ap6256RawGenerationCurrent(Ctx, IfIndex, RX_FIPS_GENERATION(Nbl), RX_HOST_CIPHER(Nbl))) return FALSE;
    if (!RX_HOST_CIPHER(Nbl)) return TRUE;
    nb = NET_BUFFER_LIST_FIRST_NB(Nbl);
    length = NET_BUFFER_DATA_LENGTH(nb);
    frame = NdisGetDataBuffer(nb, length, NULL, 1, 0);

    return frame && frame == MmGetMdlVirtualAddress(NET_BUFFER_FIRST_MDL(nb)) &&
        length == MmGetMdlByteCount(NET_BUFFER_FIRST_MDL(nb)) &&
        Ap6256RawRxRead(Ctx, IfIndex, frame - AP6256_HC_WIRE_HEADER,
            length + AP6256_HC_WIRE_HEADER, &view, &generation, &hostCipher) &&
        hostCipher && generation == RX_FIPS_GENERATION(Nbl);
}

_Use_decl_annotations_
static VOID
Ap6256TalRxGetMpdus(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PEER_ID PeerId,
                    WDI_EXTENDED_TID ExTid, PNET_BUFFER_LIST *ppNBL)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    PNET_BUFFER_LIST *link, nbl, tail = NULL, retired = NULL;
#if AP6256_TRACE_DATAPATH
    ULONG groupFrames = 0;
#endif
    KIRQL irql, queueIrql;
    UNREFERENCED_PARAMETER(ExTid);
    *ppNBL = NULL;
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    KeAcquireSpinLock(&ctx->RxQueueLock, &queueIrql);
    link = &ctx->RxQueueHead;
    ctx->RxQueueTail = NULL;
    while ((nbl = *link) != NULL) {
        UINT16 port = RX_PORT(nbl), peer = RX_PEER(nbl);
        UINT32 ifIndex = port == AP6256_STATION_PORT ? 0 : ctx->Go.IfIndex;
        BOOLEAN rawCurrent = Ap6256TalRxOwnerCurrent(ctx, ifIndex, nbl);
        if (!rawCurrent) {
            *link = NET_BUFFER_LIST_NEXT_NBL(nbl);
            NET_BUFFER_LIST_NEXT_NBL(nbl) = retired; retired = nbl; ctx->RxQueueCount--;
            continue;
        }
        BOOLEAN ready = port == AP6256_STATION_PORT
            ? (ctx->TalPeerCreated && ctx->TalRxOpen && !ctx->StationRxStopped)
            : (port == AP6256_GROUP_PORT && ctx->Go.Started && !ctx->Go.RxStopped &&
               peer > 0 && peer <= AP6256_GO_PEERS && ctx->Go.Peers[peer - 1].Active &&
               ctx->Go.Peers[peer - 1].RxOpen);
        if (!ctx->RxStopped && ready && (PeerId == WDI_PEER_ANY || PeerId == peer)) {
            *link = NET_BUFFER_LIST_NEXT_NBL(nbl);
            NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
            if (tail) NET_BUFFER_LIST_NEXT_NBL(tail) = nbl; else *ppNBL = nbl;
            tail = nbl; ctx->RxQueueCount--;
#if AP6256_TRACE_DATAPATH
            if (port == AP6256_GROUP_PORT) groupFrames++;
#endif
        } else {
            ctx->RxQueueTail = nbl;
            link = &NET_BUFFER_LIST_NEXT_NBL(nbl);
        }
    }
    KeReleaseSpinLock(&ctx->RxQueueLock, queueIrql);
    KeReleaseSpinLock(&ctx->TalStateLock, irql);
    while (retired) {
        nbl = retired; retired = NET_BUFFER_LIST_NEXT_NBL(nbl);
        NET_BUFFER_LIST_NEXT_NBL(nbl) = NULL;
        Ap6256TalFreeRxNbl(ctx, nbl);
    }
#if AP6256_TRACE_DATAPATH
    if (groupFrames != 0 && ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO &&
        InterlockedCompareExchange(&ctx->Go.DataTrace[Ap6256GoDataRxWdi], 0, 0) < 16 &&
        InterlockedIncrement(&ctx->Go.DataTrace[Ap6256GoDataRxWdi]) <= 16)
        TraceData("hotspot data rx-WDI: peer %u pulled %u frame(s)\n", (ULONG)PeerId, groupFrames);
#endif
}

_Use_decl_annotations_
static VOID
Ap6256TalRxReturnFrames(TAL_TXRX_HANDLE MiniportTalTxRxContext, PNET_BUFFER_LIST pNBL)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

#if AP6256_TRACE_DATAPATH
    {
        ULONG returned = 0;
        PNET_BUFFER_LIST walk;

        for (walk = pNBL; walk != NULL; walk = NET_BUFFER_LIST_NEXT_NBL(walk)) {
            returned++;
        }
        if (Ap6256TalTraceSlot(ctx, Ap6256TraceRxReturn)) {
            TraceData("WDI returned %u receive frame(s), head %p\n",
                      returned, pNBL);
            Ap6256TalDumpRxState(ctx, "the return");
        }
    }
#endif

    while (pNBL != NULL) {
        PNET_BUFFER_LIST next = NET_BUFFER_LIST_NEXT_NBL(pNBL);
        NET_BUFFER_LIST_NEXT_NBL(pNBL) = NULL;
        Ap6256TalFreeRxNbl(ctx, pNBL);
        pNBL = next;
    }
}

_Use_decl_annotations_
static VOID
Ap6256TalRxThrottle(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                    WDI_RX_THROTTLE_LEVEL RxThrottleLevel)
{
    Ap6256TalCount((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                   Ap6256CallRxThrottle);

    TraceVerbose(TRACE_NETADAPTER, "WDI receive throttle level %u\n",
                 (ULONG)RxThrottleLevel);
}

_Use_decl_annotations_
static VOID
Ap6256TalRxPpduRssi(TAL_TXRX_HANDLE MiniportTalTxRxContext, PNET_BUFFER_LIST pNBL,
                    UINT8 *pRssi)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    *pRssi = pNBL != NULL && RX_PORT(pNBL) == AP6256_GROUP_PORT
        ? (UINT8)ctx->Go.ClientRssiDbm : (UINT8)ctx->LastRssiDbm;

#if AP6256_TRACE_DATAPATH
    if (Ap6256TalTraceSlot(ctx, Ap6256TraceRxPpduRssi)) {
        TraceData("WDI asked for PPDU RSSI -> %d dBm (0x%02X)\n",
                  (LONG)ctx->LastRssiDbm, (ULONG)(UINT8)ctx->LastRssiDbm);
    }
#endif
}

_Use_decl_annotations_
static NDIS_STATUS
Ap6256TalTxRxStart(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                   PWDI_TXRX_TARGET_CONFIGURATION pWifiTxRxConfiguration,
                   PTAL_TXRX_PARAMETERS pTalTxRxParameters)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    UNREFERENCED_PARAMETER(pWifiTxRxConfiguration);
    Ap6256TalCount(ctx, Ap6256CallTalStart);

    if (pTalTxRxParameters != NULL) {
        pTalTxRxParameters->MaxOutstandingTransfers =
            AP6256_TAL_MAX_OUTSTANDING_TRANSFERS;
    }

    ctx->TxPaused = 0;
    InterlockedExchange(&ctx->TxEmptyDequeueCredit, -1);
    ctx->RxStopped = FALSE;
    ctx->TalStarted = TRUE;
    TraceInfo(TRACE_NETADAPTER, "WDI TAL data path started\n");
    return NDIS_STATUS_SUCCESS;
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxStop(TAL_TXRX_HANDLE MiniportTalTxRxContext)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    KIRQL irql;

    Ap6256TalCount(ctx, Ap6256CallTalStop);
    Ap6256TalDumpCallCensus(ctx, "TAL data path stopping");
    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    ctx->TalStarted = FALSE;
    ctx->RxStopped = TRUE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    Ap6256TalWaitIdle(ctx, TRUE, "TAL data path stop");

    Ap6256WorkItemFlush(&ctx->TxWorker);
    Ap6256WlfcDrain(ctx);
    Ap6256TimerStop(&ctx->RxOpenTimer, TRUE);
    Ap6256TalFlushRxQueue(ctx);

    RtlZeroMemory(ctx->Go.Peers, sizeof(ctx->Go.Peers));

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    ctx->TalPeerDeletePending = FALSE;
    ctx->TxAborting = FALSE;
    ctx->TxAbortConfirmNeeded = FALSE;
    ctx->TxPaused = 0;
    InterlockedExchange(&ctx->TxEmptyDequeueCredit, -1);
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    TraceInfo(TRACE_NETADAPTER, "WDI TAL data path stopped\n");
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxAddPort(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                     WDI_OPERATION_MODE OpMode)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    UNREFERENCED_PARAMETER(OpMode);
    Ap6256TalCount(ctx, Ap6256CallAddPort);

    if (ctx != NULL && PortId == AP6256_STATION_PORT) {
        ctx->TalPortId = PortId;
        ctx->TalPortValid = TRUE;
        ctx->StationRxStopped = FALSE;
    }
    if (ctx != NULL && PortId == AP6256_GROUP_PORT) {
        ctx->Go.TalAdded = TRUE;
        ctx->Go.RxStopped = FALSE;
    }
    TraceDiag("WDI port %u added, op mode %u; TAL context %p handle %p\n",
              (ULONG)PortId, (ULONG)OpMode, ctx, ctx->WdiDataPathHandle);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxDeletePort(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    Ap6256TalCount(ctx, Ap6256CallDeletePort);
    Ap6256TalDumpCallCensus(ctx, "WDI deleting the port");

    Ap6256TalTxResumePort(ctx, PortId);

    Ap6256WlfcCancel(ctx, PortId, AP6256_WLFC_ANY, NULL);

    if (ctx != NULL && ctx->TalPortValid && ctx->TalPortId == PortId) {
        Ap6256TalPeerDelete(ctx);
        ctx->TalPortValid = FALSE;
    }
    if (ctx != NULL && PortId == AP6256_GROUP_PORT) {
        Ap6256TalGoPeerDelete(ctx, NULL);
        ctx->Go.TalAdded = FALSE;
    }
    Ap6256TalFlushPortRx(ctx, PortId, WDI_PEER_ANY);
    TraceInfo(TRACE_NETADAPTER, "WDI port %u deleted\n", (ULONG)PortId);
}

_Use_decl_annotations_
BOOLEAN
Ap6256TalPeerCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                    _In_reads_(6) const UCHAR* Bssid)
{
    WDI_MAC_ADDRESS peerAddr;
    KIRQL irql;
    BOOLEAN created, samePeer, deletePending;

    if (Ctx == NULL || Bssid == NULL) return FALSE;
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    created = Ctx->TalPeerCreated;
    samePeer = (BOOLEAN)RtlEqualMemory(Ctx->TalPeerAddress, Bssid, 6);
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    if (created) {

        if (samePeer) return TRUE;
        Ap6256TalPeerDelete(Ctx);
    }

    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    deletePending = Ctx->TalPeerDeletePending;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    if (deletePending) {
        TraceError(TRACE_NETADAPTER,
                   "datapath peer NOT created: peer %u is still being deleted "
                   "and WDI has not confirmed it\n", (ULONG)AP6256_TAL_PEER_ID);
        return FALSE;
    }
    if (!Ap6256TalUpcallClaim(Ctx)) {
        TraceWarn(TRACE_NETADAPTER,
                  "datapath peer NOT created: the TAL data path is being "
                  "torn down\n");
        return FALSE;
    }
    if (!Ctx->TalPortValid || Ctx->WdiDataApi.PeerCreateIndication == NULL ||
        Ctx->WdiDataPathHandle == NULL) {
        TraceError(TRACE_NETADAPTER,
                   "datapath peer NOT created: port %s, handle %s, "
                   "PeerCreateIndication %s\n",
                   Ctx->TalPortValid ? "known" : "UNKNOWN",
                   Ctx->WdiDataPathHandle != NULL ? "present" : "MISSING",
                   Ctx->WdiDataApi.PeerCreateIndication != NULL ? "present"
                                                                : "MISSING");
        Ap6256TalUpcallRelease(Ctx);
        return FALSE;
    }

    RtlZeroMemory(&peerAddr, sizeof(peerAddr));
    RtlCopyMemory(peerAddr.Address, Bssid, 6);

    TraceDiag("peer create -> WDI: handle %p port %u peer %u addr "
              "%02X:%02X:%02X:%02X:%02X:%02X (sizeof %u)\n",
              Ctx->WdiDataPathHandle, (ULONG)Ctx->TalPortId,
              (ULONG)AP6256_TAL_PEER_ID,
              peerAddr.Address[0], peerAddr.Address[1], peerAddr.Address[2],
              peerAddr.Address[3], peerAddr.Address[4], peerAddr.Address[5],
              (ULONG)sizeof(peerAddr));

    Ap6256TalCount(Ctx, Ap6256CallUpPeerCreate);
    Ctx->WdiDataApi.PeerCreateIndication(Ctx->WdiDataPathHandle, Ctx->TalPortId,
                                         AP6256_TAL_PEER_ID, peerAddr);
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    RtlCopyMemory(Ctx->TalPeerAddress, Bssid, sizeof(Ctx->TalPeerAddress));
    Ctx->TalPeerCreated = TRUE;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    Ap6256TalUpcallRelease(Ctx);
    TraceInfo(TRACE_NETADAPTER,
              "datapath peer %u created on port %u for "
              "%02X:%02X:%02X:%02X:%02X:%02X\n",
              (ULONG)AP6256_TAL_PEER_ID, (ULONG)Ctx->TalPortId,
              Bssid[0], Bssid[1], Bssid[2], Bssid[3], Bssid[4], Bssid[5]);

    return TRUE;
}

#define AP6256_RX_OPEN_DELAY_MS 150u

_Use_decl_annotations_
VOID
Ap6256TalRxOpen(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    if (Ctx == NULL || !Ctx->TalPeerCreated || Ctx->TalRxOpen) return;

    if (!Ap6256TalUpcallClaim(Ctx)) return;
    Ctx->TalRxOpen = TRUE;

    Ap6256TalRxQueueRefreshHeld(Ctx);

    TraceInfo(TRACE_NETADAPTER,
              "connection announced; %u held frame(s) queued for release in "
              "%u ms\n", Ctx->RxQueueCount, AP6256_RX_OPEN_DELAY_MS);
    Ap6256TalDumpCallCensus(Ctx, "connection announced");
    Ap6256TimerStart(&Ctx->RxOpenTimer, AP6256_RX_OPEN_DELAY_MS);
    Ap6256TalUpcallRelease(Ctx);
}

static VOID
Ap6256TalRxOpenWorker(_In_ PVOID Context)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)Context;

    if (ctx == NULL) return;
    Ap6256TalRxIndicateQueued(ctx, WDI_RX_INDICATION_PASSIVE,
                              "connection announced");
}

_Use_decl_annotations_
VOID
Ap6256TalRxFlushQueue(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx == NULL) return;
    Ap6256WlfcCancel(Ctx, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);

    if (!Ap6256TalUpcallClaim(Ctx)) return;
    Ap6256TalFlushPortRx(Ctx, AP6256_STATION_PORT, WDI_PEER_ANY);
    Ap6256TalUpcallRelease(Ctx);
}

_Use_decl_annotations_
VOID
Ap6256TalPeerDelete(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NDIS_STATUS wifiStatus = NDIS_STATUS_SUCCESS;
    KIRQL irql;

    if (Ctx == NULL) return;
    Ap6256WlfcCancel(Ctx, AP6256_STATION_PORT, AP6256_TAL_PEER_ID, NULL);
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    if (!Ctx->TalPeerCreated) {
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        return;
    }
    Ctx->TalPeerCreated = FALSE;
    Ctx->TalRxOpen = FALSE;

    Ctx->TalPeerDeletePending = TRUE;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);

    if (!Ap6256TalUpcallClaim(Ctx)) {
        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        Ctx->TalPeerDeletePending = FALSE;
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        return;
    }

    Ap6256TalFlushPortRx(Ctx, AP6256_STATION_PORT, AP6256_TAL_PEER_ID);
    if (Ctx->WdiDataApi.PeerDeleteIndication == NULL ||
        Ctx->WdiDataPathHandle == NULL) {
        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        Ctx->TalPeerDeletePending = FALSE;
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        Ap6256TalUpcallRelease(Ctx);
        return;
    }
    Ap6256TalCount(Ctx, Ap6256CallUpPeerDelete);
    Ap6256TalDumpCallCensus(Ctx, "deleting the datapath peer");
    Ctx->WdiDataApi.PeerDeleteIndication(Ctx->WdiDataPathHandle, Ctx->TalPortId,
                                         AP6256_TAL_PEER_ID, &wifiStatus);

    if (wifiStatus != NDIS_STATUS_PENDING) {
        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        Ctx->TalPeerDeletePending = FALSE;
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    }
    TraceInfo(TRACE_NETADAPTER, "datapath peer %u deleted -> 0x%08X%s\n",
              (ULONG)AP6256_TAL_PEER_ID, wifiStatus,
              Ctx->TalPeerDeletePending ? " (pending confirmation)" : "");
    Ap6256TalUpcallRelease(Ctx);
}

_Use_decl_annotations_
BOOLEAN Ap6256TalGoPeerCreate(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address, UINT32 PhyId)
{
    ULONG i, first = (Address[0] & 1) ? 0u : 1u;
    ULONG limit = first == 0 ? 1u : AP6256_GO_PEERS;
    WDI_MAC_ADDRESS mac;
    KIRQL irql;
    if (!Ap6256TalUpcallClaim(Ctx)) return FALSE;
    if (!Ctx->Go.TalAdded || !Ctx->WdiDataApi.PeerCreateIndication) {
        Ap6256TalUpcallRelease(Ctx); return FALSE;
    }
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    for (i = first; i < limit; ++i) {
        if (Ctx->Go.Peers[i].DeletePending && RtlEqualMemory(Ctx->Go.Peers[i].Address, Address, 6)) {
            KeReleaseSpinLock(&Ctx->TalStateLock, irql);
            Ap6256TalUpcallRelease(Ctx); return FALSE;
        }
        if (Ctx->Go.Peers[i].Active && RtlEqualMemory(Ctx->Go.Peers[i].Address, Address, 6)) {
            Ctx->Go.Peers[i].RxOpen = (BOOLEAN)(i == 0);
            Ctx->Go.Peers[i].PhyId = PhyId;
            KeReleaseSpinLock(&Ctx->TalStateLock, irql);
            Ap6256TalUpcallRelease(Ctx); return TRUE;
        }
    }
    for (i = first; i < limit; ++i)
        if (!Ctx->Go.Peers[i].Active && !Ctx->Go.Peers[i].DeletePending) break;
    if (i == limit) {
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        Ap6256TalUpcallRelease(Ctx); return FALSE;
    }
    RtlCopyMemory(Ctx->Go.Peers[i].Address, Address, 6);
    Ctx->Go.Peers[i].RxGeneration++;
    Ctx->Go.Peers[i].Active = TRUE;
    Ctx->Go.Peers[i].RxOpen = (BOOLEAN)(i == 0);
    Ctx->Go.Peers[i].PhyId = PhyId;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    RtlCopyMemory(mac.Address, Address, 6);
    Ctx->WdiDataApi.PeerCreateIndication(Ctx->WdiDataPathHandle, AP6256_GROUP_PORT, (WDI_PEER_ID)(i + 1), mac);
    TraceDiag("hotspot: peer %u created on port %u\n", i + 1, AP6256_GROUP_PORT);
    Ap6256TalUpcallRelease(Ctx);
    return TRUE;
}

_Use_decl_annotations_
VOID Ap6256TalGoPeerDelete(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address)
{
    ULONG i;
    KIRQL irql;
    if (!Ap6256TalUpcallClaim(Ctx)) return;
    for (i = 0; i < AP6256_GO_PEERS; ++i) {
        NDIS_STATUS status = NDIS_STATUS_SUCCESS;
        BOOLEAN remove;
        KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
        remove = Ctx->Go.Peers[i].Active &&
            (Address == NULL || RtlEqualMemory(Address, Ctx->Go.Peers[i].Address, 6));
        if (remove) {
            Ctx->Go.Peers[i].Active = FALSE;
            Ctx->Go.Peers[i].RxOpen = FALSE;
            Ctx->Go.Peers[i].DeletePending = TRUE;
        }
        KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        if (!remove) continue;
        Ap6256WlfcCancel(Ctx, AP6256_GROUP_PORT, (UINT16)(i + 1), NULL);
        Ap6256TalFlushPortRx(Ctx, AP6256_GROUP_PORT, (UINT16)(i + 1));
        if (Ctx->WdiDataApi.PeerDeleteIndication)
            Ctx->WdiDataApi.PeerDeleteIndication(Ctx->WdiDataPathHandle,
                AP6256_GROUP_PORT, (WDI_PEER_ID)(i + 1), &status);
        if (status != NDIS_STATUS_PENDING) {
            KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
            Ctx->Go.Peers[i].DeletePending = FALSE;
            KeReleaseSpinLock(&Ctx->TalStateLock, irql);
        }
    }
    Ap6256TalUpcallRelease(Ctx);
}

_Use_decl_annotations_
VOID Ap6256TalGoRxOpen(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Address)
{
    ULONG i;
    KIRQL irql;
    if (!Ap6256TalUpcallClaim(Ctx)) return;
    KeAcquireSpinLock(&Ctx->TalStateLock, &irql);
    for (i = 1; i < AP6256_GO_PEERS; ++i)
        if (Ctx->Go.Peers[i].Active && RtlEqualMemory(Address, Ctx->Go.Peers[i].Address, 6))
            Ctx->Go.Peers[i].RxOpen = TRUE;
    KeReleaseSpinLock(&Ctx->TalStateLock, irql);
    Ap6256TimerStart(&Ctx->RxOpenTimer, AP6256_RX_OPEN_DELAY_MS);
    Ap6256TalUpcallRelease(Ctx);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxSetPortOpMode(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                           WDI_PORT_ID PortId, WDI_OPERATION_MODE Opmode)
{
    Ap6256TalCount((PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext,
                   Ap6256CallSetPortOpMode);

    TraceInfo(TRACE_NETADAPTER, "WDI port %u operation mode %u\n",
              (ULONG)PortId, (ULONG)Opmode);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxResetPort(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    Ap6256TalCount(ctx, Ap6256CallResetPort);
    TraceInfo(TRACE_NETADAPTER, "WDI reset port %u\n", (ULONG)PortId);

    Ap6256TalTxResumePort(ctx, PortId);

}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxPeerConfig(TAL_TXRX_HANDLE MiniportTalTxRxContext, WDI_PORT_ID PortId,
                        WDI_PEER_ID PeerId, PWDI_TXRX_PEER_CFG pPeerCfg)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    UNREFERENCED_PARAMETER(PortId);
    Ap6256TalCount(ctx, Ap6256CallPeerConfig);

    TraceInfo(TRACE_NETADAPTER,
              "WDI peer %u configured on port %u, QoS %u\n",
              (ULONG)PeerId, (ULONG)PortId,
              (pPeerCfg != NULL) ? (ULONG)pPeerCfg->PeerQoSConfig : 0xFFFFFFFFu);
    Ap6256TalDumpCallCensus(ctx, "WDI configured the peer");

    UNREFERENCED_PARAMETER(ctx);
}

_Use_decl_annotations_
static VOID
Ap6256TalTxRxPeerDeleteConfirm(TAL_TXRX_HANDLE MiniportTalTxRxContext,
                               WDI_PORT_ID PortId, WDI_PEER_ID PeerId)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;

    UNREFERENCED_PARAMETER(PortId);
    Ap6256TalCount(ctx, Ap6256CallPeerDeleteConfirm);

    if (ctx != NULL && PortId == AP6256_GROUP_PORT && PeerId > 0 && PeerId <= AP6256_GO_PEERS) {
        KIRQL irql;
        KeAcquireSpinLock(&ctx->TalStateLock, &irql);
        ctx->Go.Peers[PeerId - 1].DeletePending = FALSE;
        KeReleaseSpinLock(&ctx->TalStateLock, irql);
        return;
    }
    if (ctx != NULL && PortId == AP6256_STATION_PORT && PeerId == AP6256_TAL_PEER_ID) {
        KIRQL irql;
        BOOLEAN wasPending;
        KeAcquireSpinLock(&ctx->TalStateLock, &irql);
        wasPending = ctx->TalPeerDeletePending;
        ctx->TalPeerDeletePending = FALSE;
        KeReleaseSpinLock(&ctx->TalStateLock, irql);
        TraceInfo(TRACE_NETADAPTER,
                  "datapath peer %u deletion confirmed (pending %u)\n",
                  (ULONG)PeerId, (ULONG)wasPending);
    } else {
        TraceWarn(TRACE_NETADAPTER,
                  "datapath peer %u deletion confirmed, but no deletion was "
                  "pending\n", (ULONG)PeerId);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
Ap6256WdiTalInitialize(_In_ NDIS_HANDLE MiniportAdapterContext,
                       _In_ NDIS_HANDLE NdisMiniportDataPathHandle,
                       _In_ PNDIS_WDI_DATA_API NdisWdiDataPathApi,
                       _Out_ PTAL_TXRX_HANDLE pMiniportTalTxRxContext,
                       _Inout_ PNDIS_MINIPORT_WDI_DATA_HANDLERS pMiniportDataHandlers,
                       _Out_ UINT32 *pMiniportWdiFrameMetadataExtraSpace)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportAdapterContext;
    NDIS_MINIPORT_WDI_DATA_HANDLERS handlers;
    NET_BUFFER_LIST_POOL_PARAMETERS poolParams;
    NTSTATUS status;

    *pMiniportTalTxRxContext = NULL;
    *pMiniportWdiFrameMetadataExtraSpace = 0;

    RtlZeroMemory(&poolParams, sizeof(poolParams));
    poolParams.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
    poolParams.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
    poolParams.ProtocolId = NDIS_PROTOCOL_ID_DEFAULT;
    poolParams.fAllocateNetBuffer = TRUE;
    poolParams.PoolTag = AP6256_POOL_TAG;

    ctx->RxNblPool = NdisAllocateNetBufferListPool(ctx->MiniportHandle, &poolParams);
    if (ctx->RxNblPool == NULL) {
        TraceError(TRACE_NETADAPTER, "RX NBL pool allocation failed\n");
        return NDIS_STATUS_RESOURCES;
    }
    TraceDiag("rx NBL pool %p: protocol %u allocateNb %u contextSize %u "
              "tag 0x%08X\n", ctx->RxNblPool,
              (ULONG)poolParams.ProtocolId, (ULONG)poolParams.fAllocateNetBuffer,
              (ULONG)poolParams.ContextSize, poolParams.PoolTag);

    status = Ap6256WorkItemCreate(&ctx->TxWorker, ctx->Fdo, Ap6256TalTxWorker, ctx);
    if (NT_SUCCESS(status)) {
        Ap6256WorkItemMakeCritical(&ctx->TxWorker);
    }
    if (!NT_SUCCESS(status)) {
        NdisFreeNetBufferListPool(ctx->RxNblPool);
        ctx->RxNblPool = NULL;
        return NDIS_STATUS_RESOURCES;
    }

    status = Ap6256TimerCreate(&ctx->RxOpenTimer, ctx->Fdo,
                               Ap6256TalRxOpenWorker, ctx);
    if (!NT_SUCCESS(status)) {
        Ap6256WorkItemDestroy(&ctx->TxWorker);
        NdisFreeNetBufferListPool(ctx->RxNblPool);
        ctx->RxNblPool = NULL;
        return NDIS_STATUS_RESOURCES;
    }

    Ap6256LockInit(&ctx->TxPassLock);
    KeInitializeSpinLock(&ctx->RxQueueLock);
    ctx->RxQueueHead = NULL;
    ctx->RxQueueTail = NULL;
    ctx->RxQueueCount = 0;
    ctx->RxStopped = TRUE;
    ctx->TalStarted = FALSE;

    ctx->WdiDataPathHandle = NdisMiniportDataPathHandle;

    RtlZeroMemory(&ctx->WdiDataApi, sizeof(ctx->WdiDataApi));
    {
        ULONG apiSize = (ULONG)sizeof(NDIS_WDI_DATA_API);
        ULONG peerSize = (ULONG)NdisWdiDataPathApi->Header.Size;

        if (peerSize != 0 && peerSize < apiSize) {
            TraceWarn(TRACE_NETADAPTER,
                      "WDI data API is %u byte(s), smaller than the %u this "
                      "driver was built against; copying %u and leaving the "
                      "rest NULL\n",
                      peerSize, apiSize, peerSize);
            apiSize = peerSize;
        }
        RtlCopyMemory(&ctx->WdiDataApi, NdisWdiDataPathApi, apiSize);
    }

    Ap6256TalDumpDataApi(ctx);

    RtlZeroMemory(&handlers, sizeof(handlers));
    handlers.Header.Type = NDIS_OBJECT_TYPE_MINIPORT_WDI_DATA_HANDLERS;
    handlers.Header.Revision = NDIS_OBJECT_TYPE_MINIPORT_WDI_DATA_HANDLERS_REVISION_1;
    handlers.Header.Size = NDIS_SIZEOF_MINIPORT_WDI_DATA_HANDLERS_REVISION_1;

    handlers.TxAbortHandler            = Ap6256TalTxAbort;
    handlers.TxTargetDescInitHandler   = Ap6256TalTxTargetDescInit;
    handlers.TxTargetDescDeInitHandler = Ap6256TalTxTargetDescDeInit;
    handlers.TxDataSendHandler         = Ap6256TalTxDataSend;
    handlers.TxTalSendHandler          = Ap6256TalTxTalSend;
    handlers.TxTalSendCompleteHandler  = Ap6256TalTxTalSendComplete;
    handlers.TxTalQueueInOrderHandler  = Ap6256TalTxQueueInOrder;
    handlers.TxPeerBacklogHandler      = Ap6256TalTxPeerBacklog;

    handlers.RxStopHandler             = Ap6256TalRxStop;
    handlers.RxFlushHandler            = Ap6256TalRxFlush;
    handlers.RxRestartHandler          = Ap6256TalRxRestart;
    handlers.RxGetMpdusHandler         = Ap6256TalRxGetMpdus;
    handlers.RxReturnFramesHandler     = Ap6256TalRxReturnFrames;
    handlers.RxResumeHandler           = Ap6256TalRxResume;
    handlers.RxThrottleHandler         = Ap6256TalRxThrottle;
    handlers.RxPpduRssiHandler         = Ap6256TalRxPpduRssi;

    handlers.TalTxRxStartHandler              = Ap6256TalTxRxStart;
    handlers.TalTxRxStopHandler               = Ap6256TalTxRxStop;
    handlers.TalTxRxAddPortHandler            = Ap6256TalTxRxAddPort;
    handlers.TalTxRxDeletePortHandler         = Ap6256TalTxRxDeletePort;
    handlers.TalTxRxSetPortOpModeHandler      = Ap6256TalTxRxSetPortOpMode;
    handlers.TalTxRxResetPortHandler          = Ap6256TalTxRxResetPort;
    handlers.TalTxRxPeerConfigHandler         = Ap6256TalTxRxPeerConfig;
    handlers.TalTxRxPeerDeleteConfirmHandler  = Ap6256TalTxRxPeerDeleteConfirm;

    RtlCopyMemory(pMiniportDataHandlers, &handlers, sizeof(handlers));
    *pMiniportTalTxRxContext = (TAL_TXRX_HANDLE)ctx;

    {
        KIRQL irql;

        KeAcquireSpinLock(&ctx->TalStateLock, &irql);
        ctx->TalApiOpen = TRUE;
        KeReleaseSpinLock(&ctx->TalStateLock, irql);
    }

    TraceInfo(TRACE_NETADAPTER, "WDI TAL data path initialized\n");
    return NDIS_STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiTalDeinitialize(_In_ TAL_TXRX_HANDLE MiniportTalTxRxContext)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)MiniportTalTxRxContext;
    KIRQL irql;

    if (ctx == NULL) {
        return;
    }

    KeAcquireSpinLock(&ctx->TalStateLock, &irql);
    ctx->TalStarted = FALSE;
    ctx->RxStopped = TRUE;
    ctx->TalApiOpen = FALSE;
    KeReleaseSpinLock(&ctx->TalStateLock, irql);

    Ap6256TalWaitIdle(ctx, FALSE, "TAL data path deinitialize");

    Ap6256WorkItemDestroy(&ctx->TxWorker);
    Ap6256WlfcStop(ctx);
    Ap6256TimerDestroy(&ctx->RxOpenTimer);
    Ap6256TalFlushRxQueue(ctx);

    if (ctx->RxNblPool != NULL) {
        NdisFreeNetBufferListPool(ctx->RxNblPool);
        ctx->RxNblPool = NULL;
    }

    ctx->WdiDataPathHandle = NULL;
    RtlZeroMemory(&ctx->WdiDataApi, sizeof(ctx->WdiDataApi));
    TraceInfo(TRACE_NETADAPTER, "WDI TAL data path deinitialized\n");
}
