/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "datapath.h"
#include "host_fips.h"
#include "host_cipher_transport.h"
#include "host_cipher_event.h"
#include "pno.h"
#include "sae_fw.h"
#include "sdio.h"
#include "bcdc.h"
#include "wifi_ops.h"
#include "tdls.h"
#include "netadapter.h"
#include "model.h"
#include "ft_fw.h"
#include "wlfc.h"
#include "firmware.h"

AP6256_WORKITEM_ROUTINE Ap6256FrameWorker;

#define AP6256_RX_BUFFER_SIZE 65536u

#define AP6256_FIRSTREAD      256u

#define AP6256_RX_EMPTY_POLLS 5u

#define AP6256_RX_PASS_LIMIT  128u

#define AP6256_TX_BUFFER_SIZE 40960u

#define AP6256_TX_GLOM_MIN_BYTES     1024u
#define AP6256_TX_GLOM_ROOM          (2048u + 512u)

static __forceinline ULONG Ap6256Align4(_In_ ULONG Value)
{
    return (Value + 3u) & ~3u;
}

static __forceinline ULONG Ap6256Align16(_In_ ULONG Value)
{
    return (Value + 15u) & ~15u;
}

static ULONG Ap6256AlignTransfer(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Value)
{
    ULONG blockSize = Ctx->Sdio.Function2BlockSize;
    ULONG alignment = sizeof(UINT32);

    if (blockSize != 0 && blockSize <= 512 && Value > blockSize) {
        alignment = blockSize;
    }
    if (Value > MAXULONG - (alignment - 1)) {
        return 0;
    }
    return ((Value + alignment - 1) / alignment) * alignment;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathInit(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    if (Ctx->RxScratch == NULL) {
        Ctx->RxScratch = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, AP6256_RX_BUFFER_SIZE, AP6256_POOL_TAG);
        if (Ctx->RxScratch == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Ctx->RxScratchSize = AP6256_RX_BUFFER_SIZE;
    }
    if (Ctx->TxScratch == NULL) {
        Ctx->TxScratch = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, AP6256_TX_BUFFER_SIZE, AP6256_POOL_TAG);
        if (Ctx->TxScratch == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Ctx->TxScratchSize = AP6256_TX_BUFFER_SIZE;
    }

    if (!Ap6256WorkItemValid(&Ctx->FrameWorker)) {
        status = Ap6256WorkItemCreate(&Ctx->FrameWorker, Ctx->Fdo,
                                      Ap6256FrameWorker, Ctx);
        if (NT_SUCCESS(status)) {
            Ap6256WorkItemMakeCritical(&Ctx->FrameWorker);
        }
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_NETADAPTER, "work item create failed 0x%08X\n", status);
            return status;
        }
    }

    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);

        Ctx->Sdio.TxSeq = 0xff;
        Ctx->Sdio.RxSeq = 0;
        Ctx->Sdio.MaxTxSeq = 0;
        Ctx->Sdio.FlowControl = 0;
        Ctx->Sdio.TxFlowStopped = FALSE;
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
    }

    Ctx->Sdio.TxGlom = FALSE;
    Ctx->Sdio.TxGlomBytes = 0;
    Ctx->GlomCount = 0;
    Ctx->GlomTotalLength = 0;
    Ctx->GlomErrors = 0;
    Ctx->RxNextLength = 0;
    Ctx->RxSkip = FALSE;
    Ctx->RxSkipSince = 0;
    Ctx->RxBatching = FALSE;
    Ctx->RxBatched = 0;
    Ctx->DatapathRunning = FALSE;
    status = Ap6256WatchdogCreate(Ctx);
    if (!NT_SUCCESS(status)) return status;
    return Ap6256WlfcCreate(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathStart(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    LONG heldOff;

    Ctx->RxSkip = FALSE;
    Ctx->GlomCount = 0;
    Ctx->GlomTotalLength = 0;
    Ctx->GlomErrors = 0;
    Ctx->RxNextLength = 0;
    Ctx->DatapathRunning = TRUE;

    heldOff = InterlockedExchange(&Ctx->IsrHeldOff, 0);
    if (Ap6256WorkItemValid(&Ctx->FrameWorker)) {
        Ap6256WorkItemEnqueue(&Ctx->FrameWorker);
    }

    TraceInfo(TRACE_NETADAPTER, "data path started (%d interrupt(s) held off)\n",
              heldOff);
    Ap6256WatchdogStart(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathStop(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ctx->DatapathRunning = FALSE;
    Ap6256WatchdogStop(Ctx);
    Ap6256WorkItemFlush(&Ctx->FrameWorker);
    Ap6256WlfcStop(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256WatchdogDestroy(Ctx);
    Ap6256WorkItemDestroy(&Ctx->FrameWorker);
    Ap6256WlfcDestroy(Ctx);

    if (Ctx->RxScratch != NULL) {
        ExFreePoolWithTag(Ctx->RxScratch, AP6256_POOL_TAG);
        Ctx->RxScratch = NULL;
        Ctx->RxScratchSize = 0;
    }
    if (Ctx->TxScratch != NULL) {
        ExFreePoolWithTag(Ctx->TxScratch, AP6256_POOL_TAG);
        Ctx->TxScratch = NULL;
        Ctx->TxScratchSize = 0;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256DatapathOnInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx->DatapathRunning && Ap6256WorkItemValid(&Ctx->FrameWorker)) {
        Ap6256WorkItemEnqueue(&Ctx->FrameWorker);
        return;
    }

    InterlockedIncrement(&Ctx->IsrHeldOff);
}

#define AP6256_RETRY_CHANNEL(Channel) \
    ((Channel) == SDPCM_CONTROL_CHANNEL || (Channel) == SDPCM_EVENT_CHANNEL)

#define AP6256_RXSKIP_LIMIT_MS      2000u

static VOID Ap6256DropGlom(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ctx->GlomCount = 0;
    Ctx->GlomTotalLength = 0;
    Ctx->GlomErrors = 0;
}

static VOID Ap6256RxFrameFailed(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ BOOLEAN Abort,
                                _In_ BOOLEAN Retransmit)
{

    Ctx->RxNextLength = 0;

    if (Ctx->GlomCount != 0) {
        Abort = TRUE;
        if (Ctx->GlomErrors++ < 3) {
            Retransmit = TRUE;
        } else {
            TraceWarn(TRACE_NETADAPTER,
                      "glom superframe lost %u times; descriptor dropped\n",
                      Ctx->GlomErrors);
            Ap6256DropGlom(Ctx);
            Retransmit = FALSE;
        }
    }
    Ap6256SdioRxFail(Ctx, Abort, Retransmit);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ReadSdpcmFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                     _Out_ PUCHAR* Payload, _Out_ PULONG PayloadLen,
                                     _Out_ PUCHAR Channel,
                                     _Out_ PULONG TransferLength, _Out_ PULONG DataOffset)
{
    NTSTATUS status;
    PSDPCM_HW_HEADER hw;
    PSDPCM_SW_HEADER sw;
    ULONG frameLen;
    ULONG transferLen;
    ULONG doffset;
    ULONG needed;
    ULONG readLen;
    ULONG expected = 0;
    BOOLEAN readAhead = FALSE;
    UCHAR channel;
    BOOLEAN glom = (Ctx->GlomCount != 0);

    *Payload = NULL;
    *PayloadLen = 0;
    *Channel = 0xFF;
    *TransferLength = 0;
    *DataOffset = 0;

    if (Ctx->RxScratch == NULL || Ctx->RxScratchSize < AP6256_FIRSTREAD) {
        return STATUS_DEVICE_NOT_READY;
    }

    if (glom) {
        expected = Ap6256AlignTransfer(Ctx, Ctx->GlomTotalLength);
        readAhead = TRUE;
    } else if (Ctx->RxNextLength >= SDPCM_HDRLEN) {
        expected = Ap6256AlignTransfer(Ctx, Ctx->RxNextLength);
        readAhead = TRUE;
    }

    if (readAhead && (expected < SDPCM_HDRLEN ||
                      expected > Ctx->RxScratchSize)) {
        readAhead = FALSE;
    }

    if (readAhead) {
        readLen = expected;
        status = Ap6256SdioFrameRW(Ctx, FALSE, Ctx->RxScratch, readLen);
    } else {

        readLen = AP6256_FIRSTREAD;
        RtlZeroMemory(Ctx->RxScratch, AP6256_FIRSTREAD);
        status = Ap6256SdioFrameReadHeader(Ctx, Ctx->RxScratch, readLen);
    }
    if (!NT_SUCCESS(status)) {

        TraceWarn(TRACE_NETADAPTER, "frame %s read (%u byte(s)) failed 0x%08X\n",
                  readAhead ? "read-ahead" : "header", readLen, status);
        Ap6256RxFrameFailed(Ctx, TRUE, TRUE);
        return status;
    }
    hw = (PSDPCM_HW_HEADER)Ctx->RxScratch;
    if (hw->FrameLength == 0) {
        Ctx->RxNextLength = 0;
        return STATUS_NO_MORE_ENTRIES;
    }
    if ((UINT16)(hw->FrameLength ^ hw->FrameLengthInverted) != 0xFFFF) {

        TraceWarn(TRACE_NETADAPTER, "bad SDPCM hw header len=0x%04X ~len=0x%04X\n",
                  hw->FrameLength, hw->FrameLengthInverted);
        Ap6256RxFrameFailed(Ctx, FALSE, FALSE);
        return STATUS_DEVICE_DATA_ERROR;
    }
    frameLen = hw->FrameLength;
    if (frameLen < SDPCM_HDRLEN) {
        TraceWarn(TRACE_NETADAPTER, "SDPCM frame of %u byte(s) is shorter than "
                  "its header\n", frameLen);
        Ap6256RxFrameFailed(Ctx, FALSE, FALSE);
        return STATUS_DEVICE_DATA_ERROR;
    }

    sw = (PSDPCM_SW_HEADER)(Ctx->RxScratch + SDPCM_HWHDR_LEN);
    channel = (UCHAR)(sw->ChannelAndFlags & SDPCM_CHANNEL_MASK);
    if (!Ctx->DatapathRunning || Ctx->Sdio.Sleeping ||
        (channel == SDPCM_DATA_CHANNEL && Ctx->HostTxQuiesced != 0))
        return STATUS_DEVICE_NOT_READY;
    needed = Ap6256Align4(frameLen);

    if (glom) {

        if (channel != SDPCM_GLOM_CHANNEL ||
            (sw->ChannelAndFlags & 0x80) != 0 ||
            Ap6256AlignTransfer(Ctx, needed) < readLen) {
            TraceWarn(TRACE_NETADAPTER, "glom superframe of %u byte(s) expected; "
                      "channel %u frame of %u byte(s) arrived\n",
                      Ctx->GlomTotalLength, (ULONG)channel, frameLen);
            Ap6256RxFrameFailed(Ctx, TRUE, TRUE);
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    } else if (readAhead &&
               Ap6256AlignTransfer(Ctx, Ap6256Align16(needed)) < readLen) {

        TraceWarn(TRACE_NETADAPTER, "read-ahead of %u byte(s) for a %u-byte "
                  "frame on channel %u; asked for it again\n",
                  readLen, frameLen, (ULONG)channel);
        Ap6256RxFrameFailed(Ctx, TRUE, TRUE);
        return STATUS_DEVICE_DATA_ERROR;
    }

    if (needed > readLen) {
        ULONG tail = Ap6256AlignTransfer(Ctx, needed - readLen);
        if (tail == 0 || tail > Ctx->RxScratchSize - readLen) {

            TraceWarn(TRACE_NETADAPTER, "frame of %u byte(s) on channel %u does "
                      "not fit the %u-byte receive buffer\n",
                      needed, (ULONG)channel, Ctx->RxScratchSize);
            Ap6256RxFrameFailed(Ctx, FALSE, AP6256_RETRY_CHANNEL(channel));
            return STATUS_BUFFER_OVERFLOW;
        }
        status = Ap6256SdioFrameRW(Ctx, FALSE, Ctx->RxScratch + readLen, tail);
        if (!NT_SUCCESS(status)) {

            TraceWarn(TRACE_NETADAPTER, "frame body read (%u byte(s), channel "
                      "%u) failed 0x%08X\n", tail, (ULONG)channel, status);
            Ap6256RxFrameFailed(Ctx, TRUE, AP6256_RETRY_CHANNEL(channel));
            return status;
        }
        readLen += tail;
    }
    transferLen = readLen;

    doffset = sw->DataOffset;
    if (doffset < SDPCM_HDRLEN || doffset > frameLen) {

        TraceWarn(TRACE_NETADAPTER, "bad SDPCM data offset %u in a %u-byte "
                  "frame on channel %u\n", doffset, frameLen, (ULONG)channel);
        Ap6256RxFrameFailed(Ctx, FALSE, FALSE);
        return STATUS_DEVICE_DATA_ERROR;
    }

    {
        KIRQL oldIrql;
        UINT8 maxTx = sw->BusDataCredit;
        KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);

        if ((UINT8)(maxTx - Ctx->Sdio.TxSeq) > 0x70) {
            maxTx = Ctx->Sdio.MaxTxSeq;
        }
        Ctx->Sdio.MaxTxSeq = maxTx;
        Ctx->Sdio.FlowControl = sw->FlowControl;
        Ctx->Sdio.RxSeq = (UINT8)(sw->Sequence + 1);
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
    }
    Ap6256NetTxKick(Ctx);
    Ap6256WlfcKick(Ctx);

    Ctx->RxNextLength = (ULONG)sw->NextLength << 4;

    *Channel = channel;
    *Payload = Ctx->RxScratch + doffset;
    *PayloadLen = frameLen - doffset;
    *TransferLength = transferLen;
    *DataOffset = doffset;
    return STATUS_SUCCESS;
}

#pragma pack(push, 1)
typedef struct _BRCM_ETH_HEADER {
    UINT16 Subtype;
    UINT16 Length;
    UINT8 Version;
    UINT8 Oui[3];
    UINT16 UserSubtype;
} BRCM_ETH_HEADER, *PBRCM_ETH_HEADER;
#pragma pack(pop)

C_ASSERT(sizeof(BRCM_ETH_HEADER) == 10);

static UINT16 Ap6256ReadBe16(_In_reads_bytes_(sizeof(UINT16)) const UINT8* Data)
{
    UINT16 value;
    RtlCopyMemory(&value, Data, sizeof(value));
    return RtlUshortByteSwap(value);
}

static UINT32 Ap6256ReadBe32(_In_reads_bytes_(sizeof(UINT32)) const UINT8* Data)
{
    UINT32 value;
    RtlCopyMemory(&value, Data, sizeof(value));
    return RtlUlongByteSwap(value);
}

static NTSTATUS Ap6256PullBcdcData(_In_reads_bytes_(Length) PUCHAR Payload,
                                   _In_ ULONG Length, _Out_ PUCHAR* Frame,
                                   _Out_ PULONG FrameLength,
                                   _Out_ PUCHAR Priority, _Out_ PUINT32 IfIndex)
{
    PBCDC_DATA_HEADER bdc;
    ULONG headerLength;

    *Frame = NULL;
    *FrameLength = 0;
    *Priority = 0;
    *IfIndex = 0;
    if (Length < sizeof(BCDC_DATA_HEADER)) return STATUS_DEVICE_DATA_ERROR;

    bdc = (PBCDC_DATA_HEADER)Payload;
    if ((bdc->Flags >> BCDC_DATA_FLAG_PROTO_SHIFT) != BCDC_DCMD_PROTO_VERSION) {
        return STATUS_REVISION_MISMATCH;
    }
    if (bdc->DataOffset > (MAXULONG - sizeof(*bdc)) / sizeof(UINT32)) {
        return STATUS_INTEGER_OVERFLOW;
    }
    headerLength = sizeof(*bdc) + ((ULONG)bdc->DataOffset * sizeof(UINT32));
    if (headerLength > Length) return STATUS_DEVICE_DATA_ERROR;

    *Frame = Payload + headerLength;
    *FrameLength = Length - headerLength;
    *Priority = (UCHAR)(bdc->Priority & 0x07u);
    *IfIndex = bdc->Flags2 & 0x0fu;
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256ParseActionRx(const UCHAR* Data, ULONG Length,
    const UCHAR* Source, UINT16* Chanspec, const UCHAR** Body, ULONG* BodyLength)
{
    ULONG offset = 16;
    *Body = NULL;
    *BodyLength = 0;
    if (Data == NULL || Length < offset + 2) return FALSE;
    *Chanspec = (UINT16)(((UINT16)Data[2] << 8) | Data[3]);
    if (Data[offset] == 0xd0) {
        if (Source == NULL || Length < offset + 24 + 2 || (Data[offset + 1] & 3u) != 0 ||
            !RtlEqualMemory(Data + offset + 10, Source, 6)) return FALSE;
        offset += 24;
    }
    *Body = Data + offset;
    *BodyLength = Length - offset;
    return TRUE;
}

static PCSTR Ap6256EventName(_In_ UINT32 EventType)
{
    switch (EventType) {
    case 0:  return "SET_SSID";
    case 1:  return "JOIN";
    case 2:  return "START";
    case 3:  return "AUTH";
    case 4:  return "AUTH_IND";
    case 5:  return "DEAUTH";
    case 6:  return "DEAUTH_IND";
    case 7:  return "ASSOC";
    case 8:  return "ASSOC_IND";
    case 9:  return "REASSOC";
    case 10: return "REASSOC_IND";
    case 11: return "DISASSOC";
    case 12: return "DISASSOC_IND";
    case 13: return "QUIET_START";
    case 14: return "QUIET_END";
    case 15: return "BEACON_RX";
    case 16: return "LINK";
    case 17: return "MIC_ERROR";
    case 18: return "NDIS_LINK";
    case 19: return "ROAM";
    case 20: return "TXFAIL";
    case 21: return "PMKID_CACHE";
    case 22: return "RETROGRADE_TSF";
    case 23: return "PRUNE";
    case 24: return "AUTOAUTH";
    case 25: return "EAPOL_MSG";
    case 26: return "SCAN_COMPLETE";
    case 71: return "PROBERESP_MSG";
    case 31: return "BCNLOST_MSG";
    case 40: return "RADIO";
    case 45: return "SCAN_CONFIRM_IND";
    case 46: return "PSK_SUP";
    case 64: return "AP_STARTED";
    case 65: return "DFS_AP_STOP";
    case 66: return "DFS_AP_RESUME";
    case 80: return "CSA_COMPLETE_IND";
    case 85: return "ASSOC_IND_NDIS";
    case 86: return "REASSOC_IND_NDIS";
    case 54: return "IF";
    case 56: return "RSSI";
    case 55: return "P2P_DISC_LISTEN_COMPLETE";
    case 59: return "ACTION_FRAME";
    case 60: return "ACTION_FRAME_COMPLETE";
    case 69: return "ESCAN_RESULT";
    case 70: return "ACTION_FRAME_OFF_CHAN_COMPLETE";
    case 72: return "P2P_PROBREQ_MSG";
    case 75: return "ACTION_FRAME_RX";
    case 77: return "RM_COMPLETE";
    case 90: return "ACTION_FRAME_RX_NDIS";
    case 92: return "TDLS_PEER_EVENT";
    case 105: return "P2PO_ADD_DEVICE";
    case 106: return "P2PO_DEL_DEVICE";
    case 141: return "RRM";
    default: return "event";
    }
}

static PCSTR Ap6256EventStatusName(_In_ UINT32 Status)
{
    switch (Status) {
    case 0:  return "SUCCESS";
    case 1:  return "FAIL";
    case 2:  return "TIMEOUT";
    case 3:  return "NO_NETWORKS";
    case 4:  return "ABORT";
    case 5:  return "NO_ACK";
    case 6:  return "UNSOLICITED";
    case 7:  return "ATTEMPT";
    case 8:  return "PARTIAL";
    case 9:  return "NEWSCAN";
    case 10: return "NEWASSOC";
    default: return "status";
    }
}

static BOOLEAN Ap6256TraceTxFailure(_In_reads_bytes_(Length) const UCHAR* Data,
                                    _In_ ULONG Length)
{
    UCHAR detail[72];
    const UCHAR* header;
    const UCHAR* txs;
    UINT16 fc, frameLength, sequence, attempts, longAttempts, rtsAttempts, phyError;
    PCSTR name;
    if (Length == 0) return FALSE;
    if (Data == NULL || Length != sizeof(detail) || Data[0] != 'T' ||
        Data[1] != 'X' || Data[2] != 'F' || Data[3] != '1') {
        TraceWarn(TRACE_NETADAPTER, "TXFAIL detail: unrecognized payload (%u bytes)\n", Length);
        return FALSE;
    }
    RtlCopyMemory(detail, Data, sizeof(detail));
    header = detail + 8;
    txs = detail + 32;
    frameLength = (UINT16)(detail[4] | ((UINT16)detail[5] << 8));
    if (frameLength < 24) {
        TraceWarn(TRACE_NETADAPTER, "TXFAIL detail: invalid MAC length %u\n", (ULONG)frameLength);
        return FALSE;
    }
    fc = (UINT16)(header[0] | ((UINT16)header[1] << 8));
    sequence = (UINT16)((header[22] | ((UINT16)header[23] << 8)) >> 4);
    attempts = (UINT16)(txs[0x1c] | ((UINT16)txs[0x1d] << 8));
    longAttempts = (UINT16)(txs[0x22] | ((UINT16)txs[0x23] << 8));
    rtsAttempts = (UINT16)(txs[0x1a] | ((UINT16)txs[0x1b] << 8));
    phyError = (UINT16)(txs[6] | ((UINT16)txs[7] << 8));
    switch (fc & 0xfcu) {
    case 0x50: name = "probe response"; break;
    case 0x40: name = "probe request"; break;
    case 0xd0: name = "action"; break;
    case 0xb0: name = "authentication"; break;
    case 0x00: name = "association request"; break;
    case 0x10: name = "association response"; break;
    case 0xa0: name = "disassociation"; break;
    case 0xc0: name = "deauthentication"; break;
    default: name = (fc & 0x0cu) == 8 ? "data" : (fc & 0x0cu) == 4 ? "control" : "management"; break;
    }
    TraceDiag("TXFAIL detail: %s FC 0x%04X seq %u MAC bytes %u FIFO %u tag BSS %d "
        "suppression %u ack %d attempts %u/%u RTS %u PHY 0x%04X\n",
        name, (ULONG)fc, (ULONG)sequence, (ULONG)frameLength, (ULONG)detail[6],
        (LONG)(CHAR)detail[7], (ULONG)txs[0x18], (LONG)(CHAR)txs[0x19],
        (ULONG)attempts, (ULONG)longAttempts, (ULONG)rtsAttempts, (ULONG)phyError);
    TraceDiag("TXFAIL addresses: to %02X:%02X:%02X:%02X:%02X:%02X "
        "transmitter %02X:%02X:%02X:%02X:%02X:%02X "
        "addr3 %02X:%02X:%02X:%02X:%02X:%02X\n",
        header[4], header[5], header[6], header[7], header[8], header[9],
        header[10], header[11], header[12], header[13], header[14], header[15],
        header[16], header[17], header[18], header[19], header[20], header[21]);
    return TRUE;
}

static BOOLEAN Ap6256ActionFrameIsP2pMirror(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length)
{
    return Ctx->Chip.ChipId == 0x4345 && Ctx->Chip.ChipRev == 9 &&
        Ctx->FirmwareNativeManagement && Body != NULL && Length >= 8 &&
        Body[0] == 4 && Body[1] == 9 && Body[2] == 0x50 && Body[3] == 0x6f &&
        Body[4] == 0x9a && Body[5] == 9 && Body[6] <= 8;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_reads_bytes_(Length) PUCHAR Payload, _In_ ULONG Length)
{
    const ULONG kEthHdr = 14;
    ULONG off = kEthHdr + sizeof(BRCM_ETH_HEADER);
    PBRCM_ETH_HEADER bcm;
    PBRCMF_EVENT_MSG evt;
    UINT32 eventType, status, declaredBodyLength;
    PUCHAR eventBody;
    ULONG eventBodyLen;

    if (Length < off + sizeof(BRCMF_EVENT_MSG)) {
        TraceWarn(TRACE_NETADAPTER, "runt event frame (%u bytes)\n", Length);
        return;
    }
    if (Ap6256ReadBe16(Payload + 12) != ETHER_TYPE_BRCM) {
        TraceVerbose(TRACE_NETADAPTER,
                     "event channel frame is not BRCM (ethertype 0x%04X)\n",
                     Ap6256ReadBe16(Payload + 12));
        return;
    }

    bcm = (PBRCM_ETH_HEADER)(Payload + kEthHdr);
    if (Ap6256ReadBe16((PUCHAR)&bcm->Subtype) != BCMILCP_SUBTYPE_VENDOR_LONG ||
        bcm->Oui[0] != 0x00 || bcm->Oui[1] != 0x10 || bcm->Oui[2] != 0x18 ||
        Ap6256ReadBe16((PUCHAR)&bcm->UserSubtype) != BCMILCP_BCM_SUBTYPE_EVENT) {
        TraceVerbose(TRACE_NETADAPTER,
                     "event frame subtype/OUI mismatch (0x%04X %02X:%02X:%02X "
                     "0x%04X)\n",
                     Ap6256ReadBe16((PUCHAR)&bcm->Subtype),
                     bcm->Oui[0], bcm->Oui[1], bcm->Oui[2],
                     Ap6256ReadBe16((PUCHAR)&bcm->UserSubtype));
        return;
    }

    evt = (PBRCMF_EVENT_MSG)(Payload + off);

    eventType = Ap6256ReadBe32((PUCHAR)&evt->EventType);
    status = Ap6256ReadBe32((PUCHAR)&evt->Status);
    declaredBodyLength = Ap6256ReadBe32((PUCHAR)&evt->DataLen);
    eventBody = (PUCHAR)evt + sizeof(BRCMF_EVENT_MSG);
    eventBodyLen = Length - (off + sizeof(BRCMF_EVENT_MSG));
    if (declaredBodyLength > eventBodyLen) {
        TraceWarn(TRACE_NETADAPTER, "event %u body overruns frame (%u > %u)\n",
                  eventType, declaredBodyLength, eventBodyLen);
        return;
    }
    eventBodyLen = declaredBodyLength;
    if (eventType == BRCMF_E_FIFO_CREDIT_MAP || eventType == BRCMF_E_BCMC_CREDIT_SUPPORT) {
        Ap6256WlfcEvent(Ctx, eventType, eventBody, eventBodyLen);
        return;
    }

    if ((eventType == BRCMF_E_ESCAN_RESULT && status == BRCMF_E_STATUS_PARTIAL) ||
        eventType == BRCMF_E_RADIO || eventType == BRCMF_E_PROBERESP_MSG) {
        TraceVerbose(TRACE_NETADAPTER,
                     "event: %s (%u) status %s (%u) from "
                     "%02X:%02X:%02X:%02X:%02X:%02X, %u byte(s)\n",
                     Ap6256EventName(eventType), eventType,
                     Ap6256EventStatusName(status), status,
                     evt->Address[0], evt->Address[1], evt->Address[2],
                     evt->Address[3], evt->Address[4], evt->Address[5],
                     eventBodyLen);
    } else {
        TraceInfo(TRACE_NETADAPTER,
                  "event: %s (%u) status %s (%u) reason %u flags 0x%04X %s "
                  "%02X:%02X:%02X:%02X:%02X:%02X, %u byte(s)\n",
                  Ap6256EventName(eventType), eventType,
                  Ap6256EventStatusName(status), status,
                  Ap6256ReadBe32((PUCHAR)&evt->Reason),
                  Ap6256ReadBe16((PUCHAR)&evt->Flags),
                  eventType == BRCMF_E_TXFAIL ? "to" : "from",
                  evt->Address[0], evt->Address[1], evt->Address[2],
                  evt->Address[3], evt->Address[4], evt->Address[5],
                  eventBodyLen);
    }

    if (eventType == BRCMF_E_TXFAIL) (VOID)Ap6256TraceTxFailure(eventBody, eventBodyLen);

    if (eventType == BRCMF_E_RRM || eventType == BRCMF_E_RM_COMPLETE) {

        UCHAR prefix[16] = {0};
        RtlCopyMemory(prefix, eventBody, min(eventBodyLen, sizeof(prefix)));
        TraceDiag("RRM event %u: if %u bsscfg %u bytes %u prefix "
            "%02X %02X %02X %02X %02X %02X %02X %02X "
            "%02X %02X %02X %02X %02X %02X %02X %02X\n",
            eventType, evt->IfIdx, evt->BssCfgIdx, eventBodyLen,
            prefix[0], prefix[1], prefix[2], prefix[3], prefix[4], prefix[5],
            prefix[6], prefix[7], prefix[8], prefix[9], prefix[10], prefix[11],
            prefix[12], prefix[13], prefix[14], prefix[15]);
    }

    if (Ap6256ModelRouteGroupEvent(Ctx, evt, eventType, status, eventBody, eventBodyLen)) return;

    if ((Ap6256ReadBe32((PUCHAR)&evt->AuthType) & AP6256_SAE_OWNER_AUTH_FLAG) &&
        (eventType == BRCMF_E_SET_SSID || eventType == BRCMF_E_AUTH ||
         eventType == BRCMF_E_ASSOC || eventType == BRCMF_E_REASSOC ||
         eventType == BRCMF_E_LINK || eventType == BRCMF_E_DEAUTH ||
         eventType == BRCMF_E_DEAUTH_IND || eventType == BRCMF_E_DISASSOC ||
         eventType == BRCMF_E_DISASSOC_IND)) {
        UINT32 owner = 0;
        UCHAR peer[6] = {0};
        BOOLEAN terminal = FALSE, up = FALSE, linkEvent = TRUE, hostCipherOwner = FALSE;
        if (evt->IfIdx != 0 || evt->BssCfgIdx != 0) return;
        if (Ap6256HostCipherEventRead(eventBody, eventBodyLen, &owner, peer)) {
            if (InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1) return;
            hostCipherOwner = TRUE;
        } else if (!Ctx->FirmwareSaePatchVerified ||
                   !Ap6256SaePrivateOwner(eventBody, eventBodyLen, &owner, peer)) return;
        switch (eventType) {
        case BRCMF_E_LINK:
            up = (Ap6256ReadBe16((PUCHAR)&evt->Flags) & 1) != 0;
            break;
        case BRCMF_E_SET_SSID:

            up = (BOOLEAN)(status == BRCMF_E_STATUS_SUCCESS);
            terminal = !up;
            if (up) TraceDiag("SAE: owned SET_SSID success; scheduling association for firmware session %u\n",
                owner);
            break;
        case BRCMF_E_AUTH:
        case BRCMF_E_ASSOC:
        case BRCMF_E_REASSOC:
            terminal = (BOOLEAN)(status != BRCMF_E_STATUS_SUCCESS);
            linkEvent = terminal;
            break;
        case BRCMF_E_DEAUTH:
        case BRCMF_E_DEAUTH_IND:
        case BRCMF_E_DISASSOC:
        case BRCMF_E_DISASSOC_IND:
            break;
        default:
            return;
        }
        if (linkEvent) {
            if (hostCipherOwner)
                Ap6256NetStationHostCipherEvent(Ctx, up, terminal, peer, owner);
            else
                Ap6256NetStationFirmwareEvent(Ctx, up, terminal, peer, owner);
        }
        return;
    }

    if (Ap6256ModelRouteAuthEvent(Ctx, evt, eventType, status, eventBody, eventBodyLen)) return;
    switch (eventType) {
    case AP6256_CYW_EXT_AUTH_REQ:
    case AP6256_CYW_EXT_AUTH_RX:
    case AP6256_CYW_MGMT_TX_STATUS:
    case AP6256_CYW_MGMT_OFFCHAN_DONE:
        if (evt->IfIdx == 0 && evt->BssCfgIdx == 0 && Ctx->FirmwareExternalAuth)
            Ap6256NetSaeEvent(Ctx, eventType, status, evt->Address, eventBody, eventBodyLen);
        break;
    case BRCMF_E_TDLS_PEER_EVENT:
        Ap6256TdlsPeerEvent(Ctx, evt->IfIdx, status,
            Ap6256ReadBe32((PUCHAR)&evt->Reason), evt->Address);
        break;

    case BRCMF_E_LINK: {
        BOOLEAN up = (Ap6256ReadBe16((PUCHAR)&evt->Flags) & 0x0001) != 0;
        TraceInfo(TRACE_NETADAPTER, "event: LINK %s (status %u)\n", up ? "UP" : "DOWN", status);

        if (!up) {
            TraceDiag("link down: status %u reason %u from "
                      "%02X:%02X:%02X:%02X:%02X:%02X (firmware link was %s)\n",
                      status, Ap6256ReadBe32((PUCHAR)&evt->Reason),
                      evt->Address[0], evt->Address[1], evt->Address[2],
                      evt->Address[3], evt->Address[4], evt->Address[5],
                      Ctx->FirmwareLinkUp ? "up" : "not up");
        }
        Ap6256NetStationFirmwareEvent(Ctx, up, FALSE, evt->Address, 0);
        break;
    }

    case BRCMF_E_ASSOC_IND:
    case BRCMF_E_REASSOC_IND:

    case BRCMF_E_PRE_ASSOC_IND:
    case BRCMF_E_PRE_REASSOC_IND:

        Ap6256ModelAssociationEvent(Ctx, evt, eventType, eventBody, eventBodyLen);
        break;

    case BRCMF_E_ASSOC_IND_NDIS:
    case BRCMF_E_REASSOC_IND_NDIS:
        TraceInfo(TRACE_NETADAPTER,
                  "event: %s (status %u): the association response is on the "
                  "air\n", Ap6256EventName(eventType), status);
        break;

    case BRCMF_E_GAS_FRAGMENT_RX:
    case BRCMF_E_GAS_COMPLETE:
        Ap6256NetServiceEvent(Ctx, eventType, status,
            Ap6256ReadBe32((PUCHAR)&evt->Reason), evt->Address, eventBody, eventBodyLen);
        break;
    case BRCMF_E_ACTION_FRAME_RX: {
        const UCHAR* body;
        ULONG length;
        UINT16 chanspec;
        if (!Ap6256ParseActionRx(eventBody, eventBodyLen, evt->Address,
                                 &chanspec, &body, &length)) {
            TraceWarn(TRACE_NETADAPTER, "invalid action receive event (%u bytes)\n", eventBodyLen);
            break;
        }
        Ap6256NetActionFrameReceived(Ctx, evt->IfIdx, evt->BssCfgIdx,
            evt->Address, chanspec, body, length);
        break;
    }

    case BRCMF_E_ACTION_FRAME:
        if (Ap6256ActionFrameIsP2pMirror(Ctx, eventBody, eventBodyLen)) {
            TraceVerbose(TRACE_NETADAPTER, "P2P raw action mirror (%u bytes); RX uses event 75\n",
                eventBodyLen);
            break;
        }
        TraceWarn(TRACE_NETADAPTER, "unclassified %s receive variant (%u bytes)\n",
            Ap6256EventName(eventType), eventBodyLen);
        break;
    case BRCMF_E_ACTION_FRAME_RX_NDIS:
        TraceWarn(TRACE_NETADAPTER,
                  "unclassified %s receive variant (%u bytes)\n",
                  Ap6256EventName(eventType), eventBodyLen);
        break;

    case BRCMF_E_ACTION_FRAME_COMPLETE: {
        UINT32 packetId = 0;

        if (eventBodyLen < sizeof(UINT32)) {
            TraceDiag("action TX status missing packet ID: %u byte(s)\n", eventBodyLen);
            break;
        }
        RtlCopyMemory(&packetId, eventBody, sizeof(packetId));
        TraceInfo(TRACE_NETADAPTER,
                  "action frame transmit complete: packet %u status %u\n",
                  packetId, status);
        Ap6256NetActionFrameCompleteQueue(Ctx, packetId, status);
        break;
    }

    case BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE:
        TraceInfo(TRACE_NETADAPTER, "action frame off-channel dwell ended: status %u\n", status);
        break;

    case BRCMF_E_ESCAN_RESULT: {
        if (status == BRCMF_E_STATUS_PARTIAL) {
            AP6256_BSS bss;
            NTSTATUS s = Ap6256WifiOnEscanResult(
                Ctx, eventBody, eventBodyLen, &bss);
            if (NT_SUCCESS(s)) {
                Ap6256NetScanResult(Ctx, &bss);
            } else {
                if (InterlockedCompareExchange(&Ctx->P2p.DiscoverScanPending, 0, 0) != 0) {
                    TraceDiag("P2P partial result rejected: status 0x%08X bytes %u sync %u\n",
                              s, eventBodyLen, (UINT16)Ctx->ScanSyncId);
                } else {
                    TraceWarn(TRACE_NETADAPTER,
                              "invalid partial escan result 0x%08X\n", s);
                }
            }
        } else {
            NTSTATUS completionStatus;
            UINT16 eventSync = 0;

            if (!Ap6256WifiEscanEventIsCurrent(Ctx, eventBody, eventBodyLen,
                                               &eventSync)) {
                TraceDiag("escan completion for sync_id %u ignored: the "
                          "current scan is sync_id %u\n",
                          eventSync, (UINT16)Ctx->ScanSyncId);
                break;
            }

            completionStatus = STATUS_SUCCESS;
            if (InterlockedCompareExchange(&Ctx->P2p.DiscoverScanPending, 0, 0) != 0) {
                TraceDiag("P2P firmware scan end: sync %u event status %u\n",
                          eventSync, status);
            }

            Ap6256NetScanComplete(Ctx, completionStatus);
        }
        break;
    }

    case BRCMF_E_IF: {
        if (eventBodyLen >= sizeof(BRCMF_IF_EVENT) && eventBody != NULL) {
            const BRCMF_IF_EVENT* ifEvent = (const BRCMF_IF_EVENT*)eventBody;

            TraceInfo(TRACE_NETADAPTER,
                      "event: IF %s ifidx %u bsscfg %u role %u\n",
                      ifEvent->Action == BRCMF_E_IF_ADD ? "add" :
                      ifEvent->Action == BRCMF_E_IF_DEL ? "del" : "change",
                      ifEvent->IfIndex, ifEvent->BssCfgIndex, ifEvent->Role);

            if (ifEvent->BssCfgIndex < RTL_NUMBER_OF(Ctx->FirmwareIfMap) && ifEvent->IfIndex < 16) {
                InterlockedExchange(&Ctx->FirmwareIfMap[ifEvent->BssCfgIndex],
                    ifEvent->Action == BRCMF_E_IF_DEL ? 0 : (LONG)ifEvent->IfIndex + 1);
            }
            if (Ctx->P2pBssValid &&
                ifEvent->BssCfgIndex == (UCHAR)Ctx->P2pBssIndex) {
                if (ifEvent->Action == BRCMF_E_IF_DEL) {
                    Ctx->P2pInterfaceValid = FALSE;
                } else {
                    Ctx->P2pInterfaceIndex = ifEvent->IfIndex;
                    Ctx->P2pInterfaceValid = TRUE;
                }
            }
        }
        break;
    }

    case BRCMF_E_RSSI: {
        INT32 level = (INT32)Ap6256ReadBe32((PUCHAR)&evt->Reason);

        TraceInfo(TRACE_NETADAPTER,
                  "event: RSSI crossed (level %d, trigger %d dBm)\n",
                  level, Ctx->RoamRssiTriggerDbm);
        if (Ctx->FirmwareLinkUp && level <= Ctx->RoamRssiTriggerDbm) {
            Ap6256NetRoamingNeeded(Ctx, AP6256_ROAM_LOW_LINK_QUALITY);
        }
        break;
    }

    case BRCMF_E_MIC_ERROR: {
        UINT16 flags = Ap6256ReadBe16((PUCHAR)&evt->Flags);

        TraceWarn(TRACE_NETADAPTER,
                  "event: MIC_ERROR (status %u) flags 0x%04X%s\n",
                  status, flags,
                  (flags & BRCMF_EVENT_MSG_FLUSHTXQ)
                      ? " - firmware asked for a transmit flush" : "");
        Ap6256NetTkipMicFailure(
            Ctx, evt->Address,
            Ap6256ReadBe32((PUCHAR)&evt->AuthType),
            (BOOLEAN)((flags & BRCMF_EVENT_MSG_GROUP) != 0));
        break;
    }

    case BRCMF_E_DFS_AP_STOP:
        TraceWarn(TRACE_NETADAPTER,
                  "event: DFS_AP_STOP (status %u): radar on the operating "
                  "channel\n", status);

        Ap6256ModelDfsStopEvent(Ctx, evt, eventType, status, eventBody, eventBodyLen);
        break;

    case BRCMF_E_DFS_AP_RESUME:
        TraceInfo(TRACE_NETADAPTER,
                  "event: DFS_AP_RESUME (status %u): the channel is usable "
                  "again\n", status);
        Ap6256NetApCanSustain(Ctx, AP6256_AP_CAN_SUSTAIN_IHV);
        break;

    case BRCMF_E_NDIS_LINK:
    case BRCMF_E_REASSOC:
    case BRCMF_E_CSA_COMPLETE_IND:
        TraceInfo(TRACE_NETADAPTER,
                  "event: %s (status %u): re-reading the link state\n",
                  Ap6256EventName(eventType), status);
        if (Ctx->FirmwareLinkUp) Ap6256NetLinkStateRefresh(Ctx);
        break;

    case BRCMF_E_BCNLOST_MSG:
        TraceDiag("beacons lost: status %u, firmware link %s\n",
                  status, Ctx->FirmwareLinkUp ? "up" : "not up");
        if (Ctx->FirmwareLinkUp) {
            Ap6256NetLinkStateRefresh(Ctx);
            Ap6256NetRoamingNeeded(Ctx, AP6256_ROAM_ASSOCIATION_LOST);
        }
        break;

    case BRCMF_E_ROAM:
        TraceInfo(TRACE_NETADAPTER, "event: ROAM (status %u)\n", status);
        if (status == BRCMF_E_STATUS_SUCCESS && Ctx->FirmwareLinkUp) {
            Ap6256NetLinkStateRefresh(Ctx);
        }
        break;

    case BRCMF_E_RADIO:
        TraceVerbose(TRACE_NETADAPTER, "event: RADIO (status %u)\n", status);
        Ap6256NetRadioChanged(Ctx);
        break;

    case BRCMF_E_SCAN_CONFIRM_IND:
        TraceInfo(TRACE_NETADAPTER,
                  "event: SCAN_CONFIRM_IND (status %u)\n", status);
        Ap6256NetScanComplete(Ctx, STATUS_SUCCESS);
        break;

    case BRCMF_E_PSK_SUP:

        if (evt->IfIdx == 0 && evt->BssCfgIdx == 0 &&
            Ap6256HostCipherPacketActive(Ctx, 0)) break;
        TraceInfo(TRACE_NETADAPTER, "event: PSK_SUP status %u\n", status);
        if (status == BRCMF_E_STATUS_FWSUP_COMPLETED) {
            Ctx->SupplicantComplete = TRUE;
            if (Ctx->FirmwareLinkUp) Ap6256NetLinkChange(Ctx, TRUE);
        } else if (status == BRCMF_E_STATUS_FAIL ||
                   status == BRCMF_E_STATUS_TIMEOUT) {
            TraceDiag("firmware supplicant failed: status %u reason %u\n",
                      status, Ap6256ReadBe32((PUCHAR)&evt->Reason));
            Ctx->SupplicantComplete = FALSE;
            Ap6256NetStationFirmwareEvent(Ctx, FALSE, TRUE, evt->Address, 0);
        }
        break;
    case BRCMF_E_DEAUTH:
    case BRCMF_E_DEAUTH_IND:
    case BRCMF_E_DISASSOC:
    case BRCMF_E_DISASSOC_IND:

        TraceDiag("%s: status %u, 802.11 reason %u, from "
                  "%02X:%02X:%02X:%02X:%02X:%02X\n",
                  (eventType == BRCMF_E_DEAUTH) ? "DEAUTH" :
                  (eventType == BRCMF_E_DEAUTH_IND) ? "DEAUTH_IND" :
                  (eventType == BRCMF_E_DISASSOC) ? "DISASSOC" : "DISASSOC_IND",
                  status, Ap6256ReadBe32((PUCHAR)&evt->Reason),
                  evt->Address[0], evt->Address[1], evt->Address[2],
                  evt->Address[3], evt->Address[4], evt->Address[5]);
        Ap6256NetStationFirmwareEvent(Ctx, FALSE, FALSE, evt->Address, 0);
        break;
    case BRCMF_E_SET_SSID:
        TraceInfo(TRACE_NETADAPTER, "event: SET_SSID (status %u)\n", status);
        if (status != BRCMF_E_STATUS_SUCCESS) {
            TraceDiag("join failed: SET_SSID status %u reason %u\n",
                      status, Ap6256ReadBe32((PUCHAR)&evt->Reason));
            Ap6256NetStationFirmwareEvent(Ctx, FALSE, TRUE, evt->Address, 0);
        }
        break;
    case BRCMF_E_PFN_NET_FOUND:
    case BRCMF_E_PFN_BEST_BATCHING:
    case BRCMF_E_PFN_GSCAN_FULL_RESULT:
    case BRCMF_E_PFN_SWC:
        if (evt->IfIdx == 0 && evt->BssCfgIdx == 0 && status == BRCMF_E_STATUS_SUCCESS)
            Ap6256PnoResultEvent(Ctx, eventType, eventBody, eventBodyLen);
        break;
    default:

        break;
    }
}

_Use_decl_annotations_
VOID Ap6256TraceHotspotPacket(PAP6256_DEVICE_CONTEXT Ctx,
    AP6256_GO_DATA_STAGE Stage, UINT32 IfIndex, const UCHAR* Frame,
    ULONG Length, NTSTATUS Status)
{
#if AP6256_TRACE_DATAPATH

    static const PCSTR names[] = { "rx-bus", "rx-filter-drop", "rx-queued",
        "tx-queued", "tx-transfer", "rx-WDI" };
    ULONG type, protocol = 0, sourcePort = 0, destPort = 0, arp = 0;
    LONG slot;
    if ((ULONG)Stage >= Ap6256GoDataStageCount ||
        (IfIndex != 0 && IfIndex != Ctx->Go.IfIndex) ||
        !Ctx->Go.Started || Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_GO ||
        Length < 14) return;
    type = ((ULONG)Frame[12] << 8) | Frame[13];
    if (type == 0x0800) {
        volatile LONG* budget = &Ctx->Go.Ipv4Trace[IfIndex == 0 ? 0 : 1][Stage];
        UCHAR source[4] = {0}, dest[4] = {0};
        ULONG total = 0, id = 0, fragments = 0, sum = 0, dnsId = 0, dnsReply = 0;
        ULONG header = 0, tcpFlags = 0;
        BOOLEAN valid = FALSE, checksumValid = FALSE, dns = FALSE;
        if (InterlockedCompareExchange(budget, 0, 0) >= 16) return;
        slot = InterlockedIncrement(budget);
        if (slot > 16) return;
        if (Length >= 34 && (Frame[14] >> 4) == 4) {

            UCHAR prefix[80] = {0};
            ULONG copied = min(Length - 14, (ULONG)sizeof(prefix));
            ULONG offset;
            RtlCopyMemory(prefix, Frame + 14, copied);
            header = (prefix[0] & 15u) * 4u;
            total = ((ULONG)prefix[2] << 8) | prefix[3];
            id = ((ULONG)prefix[4] << 8) | prefix[5];
            fragments = ((ULONG)prefix[6] << 8) | prefix[7];
            protocol = prefix[9];
            RtlCopyMemory(source, prefix + 12, sizeof(source));
            RtlCopyMemory(dest, prefix + 16, sizeof(dest));
            if (header >= 20 && header <= Length - 14 &&
                total >= header && total <= Length - 14) {
                valid = TRUE;
                for (offset = 0; offset + 1 < header; offset += 2)
                    sum += ((ULONG)prefix[offset] << 8) | prefix[offset + 1];
                while ((sum >> 16) != 0) sum = (sum & 0xffffu) + (sum >> 16);
                checksumValid = sum == 0xffffu;
                offset = header;

                if ((fragments & 0x1fffu) == 0 && total - header >= 8 &&
                    copied >= offset + 8 &&
                    (protocol == 17 || protocol == 6)) {
                    sourcePort = ((ULONG)prefix[offset] << 8) | prefix[offset + 1];
                    destPort = ((ULONG)prefix[offset + 2] << 8) | prefix[offset + 3];
                    if (protocol == 17) {
                        ULONG udpLength = ((ULONG)prefix[offset + 4] << 8) | prefix[offset + 5];
                        if ((fragments & 0x2000u) == 0 &&
                            udpLength >= 20 && udpLength <= total - header &&
                            copied >= offset + 20 &&
                            (sourcePort == 53 || destPort == 53)) {
                            dns = TRUE;
                            dnsId = ((ULONG)prefix[offset + 8] << 8) | prefix[offset + 9];
                            dnsReply = (prefix[offset + 10] >> 7) & 1u;
                        }
                    } else if (total - header >= 20 && copied >= offset + 20) {
                        tcpFlags = prefix[offset + 13];
                    }
                }
            }
        }
        TraceData("hotspot IPv4 %s #%d if %u %u.%u.%u.%u>%u.%u.%u.%u "
            "bytes %u iplen %u id 0x%04X proto %u ports %u>%u "
            "valid %u hdrsum %u frag 0x%04X DNS %u id 0x%04X reply %u TCP 0x%02X -> 0x%08X\n",
            names[Stage], slot, IfIndex, source[0], source[1], source[2], source[3],
            dest[0], dest[1], dest[2], dest[3], Length, total, id, protocol,
            sourcePort, destPort, (ULONG)valid, (ULONG)checksumValid, fragments,
            (ULONG)dns, dnsId, dnsReply, tcpFlags, Status);
        return;
    }
    if (IfIndex == 0) return;
    if (type != 0x0806 && type != 0x86dd) return;
    if (InterlockedCompareExchange(&Ctx->Go.DataTrace[Stage], 0, 0) >= 16) return;
    slot = InterlockedIncrement(&Ctx->Go.DataTrace[Stage]);
    if (slot > 16) return;
    if (type == 0x0806 && Length >= 42) {
        arp = ((ULONG)Frame[20] << 8) | Frame[21];
    }
    TraceData("hotspot data %s #%d if %u bytes %u eth 0x%04X proto %u UDP %u>%u ARP %u "
        "dst %02X:%02X:%02X:%02X:%02X:%02X src %02X:%02X:%02X:%02X:%02X:%02X -> 0x%08X\n",
        names[Stage], slot, IfIndex, Length, type, protocol, sourcePort, destPort, arp,
        Frame[0], Frame[1], Frame[2], Frame[3], Frame[4], Frame[5],
        Frame[6], Frame[7], Frame[8], Frame[9], Frame[10], Frame[11], Status);
#else
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Stage);
    UNREFERENCED_PARAMETER(IfIndex);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Length);
    UNREFERENCED_PARAMETER(Status);
#endif
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256IndicateRx(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_reads_bytes_(Length) PUCHAR Payload, _In_ ULONG Length,
                             _In_ UCHAR Priority, _In_ UINT32 IfIndex)
{
    ULONG filter;
    ULONG needed;

    if (Length < 14) {
        TraceWarn(TRACE_NETADAPTER,
                  "rx frame DROPPED: %u bytes is shorter than an Ethernet "
                  "header\n", Length);
        return;
    }

    if (Payload[12] == 0x88 && Payload[13] == 0x8e) {
        TraceDiag("EAPOL RX bus if %u bytes %u dst %02X:%02X:%02X:%02X:%02X:%02X "
            "src %02X:%02X:%02X:%02X:%02X:%02X\n", IfIndex, Length,
            Payload[0], Payload[1], Payload[2], Payload[3], Payload[4], Payload[5],
            Payload[6], Payload[7], Payload[8], Payload[9], Payload[10], Payload[11]);
    }

    if (IfIndex != 0 && (!Ctx->Go.FirmwareReady || IfIndex != Ctx->Go.IfIndex)) return;
    Ap6256TraceHotspotPacket(Ctx, Ap6256GoDataRxBus, IfIndex, Payload, Length, STATUS_SUCCESS);
    filter = (ULONG)InterlockedCompareExchange(
        IfIndex == 0 ? &Ctx->PacketFilter : &Ctx->Go.PacketFilter, 0, 0);
    if ((filter & AP6256_RXF_PROMISCUOUS) == 0) {
        if (Payload[0] == 0xFF && Payload[1] == 0xFF && Payload[2] == 0xFF &&
            Payload[3] == 0xFF && Payload[4] == 0xFF && Payload[5] == 0xFF) {
            needed = AP6256_RXF_BROADCAST;
        } else if ((Payload[0] & 1) != 0) {
            needed = AP6256_RXF_MULTICAST | AP6256_RXF_ALL_MULTICAST;
        } else {
            needed = AP6256_RXF_DIRECTED;
        }
        if ((filter & needed) == 0) {
            Ap6256TraceHotspotPacket(Ctx, Ap6256GoDataRxFiltered, IfIndex,
                Payload, Length, STATUS_ACCESS_DENIED);
            if (Payload[12] == 0x88 && Payload[13] == 0x8e)
                TraceDiag("EAPOL RX filtered if %u needs 0x%03X filter 0x%03X\n",
                    IfIndex, needed, filter);

            if (InterlockedIncrement(&Ctx->RxFiltered) <= 12) {
                TraceWarn(TRACE_NETADAPTER,
                          "rx frame DROPPED by the packet filter: "
                          "dest %02X:%02X:%02X:%02X:%02X:%02X needs 0x%03X, "
                          "filter is 0x%03X\n",
                          Payload[0], Payload[1], Payload[2], Payload[3],
                          Payload[4], Payload[5], needed, filter);
            }
            return;
        }
    }

    InterlockedIncrement(&Ctx->RxFrames);
    Ap6256NetRxIndicate(Ctx, Payload, Length, Priority, IfIndex);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256DispatchBcdcFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UCHAR Channel,
                                    _In_reads_bytes_(Length) PUCHAR Payload,
                                    _In_ ULONG Length)
{
    PUCHAR frame;
    ULONG frameLength;
    UCHAR priority;
    UINT32 ifIndex;
    NTSTATUS status;

    if (Length == 0) {
        return;
    }

    status = Ap6256PullBcdcData(Payload, Length, &frame, &frameLength, &priority, &ifIndex);
    if (!NT_SUCCESS(status)) {

        TraceWarn(TRACE_NETADAPTER,
                  "invalid BCDC data header 0x%08X (channel %u, %u bytes)\n",
                  status, (ULONG)Channel, Length);
        return;
    }

    if (!Ap6256WlfcSignals(Ctx, Payload + sizeof(BCDC_DATA_HEADER),
        (ULONG)((PBCDC_DATA_HEADER)Payload)->DataOffset * 4u)) return;
    if (frameLength == 0) return;
    if (Channel == SDPCM_DATA_CHANNEL) {
        if (((PBCDC_DATA_HEADER)Payload)->Flags2 & AP6256_FIPS_BCDC_RX_FLAGS2) {
            if (frameLength >= 4 && RtlEqualMemory(frame, "HCW1", 4)) {
                Ap6256HostCipherReceiveManagement(Ctx, ifIndex, frame, frameLength); return;
            }
            AP6256_FIPS_SESSION session;
            AP6256_FIPS_FRAME_VIEW view;
            ULONG filter, needed;
            const UCHAR* address;
            if (!Ap6256FipsSnapshot(Ctx, ifIndex, &session) ||
                !Ap6256FipsReadEnvelope(&session, AP6256_FIPS_RX, frame, frameLength, &view)) return;
            address = view.Frame + 4;
            filter = (ULONG)InterlockedCompareExchange(ifIndex == 0 ? &Ctx->PacketFilter :
                &Ctx->Go.PacketFilter, 0, 0);
            needed = RtlEqualMemory(address, "\xff\xff\xff\xff\xff\xff", 6) ?
                AP6256_RXF_BROADCAST : (address[0] & 1u) ?
                AP6256_RXF_MULTICAST | AP6256_RXF_ALL_MULTICAST : AP6256_RXF_DIRECTED;
            if (!(filter & AP6256_RXF_PROMISCUOUS) && !(filter & needed)) {
                InterlockedIncrement(&Ctx->RxFiltered); return;
            }

            InterlockedIncrement(&Ctx->RxFrames);
            Ap6256NetRxIndicate(Ctx, frame, frameLength, view.Tid & 7u, ifIndex);
            return;
        }
        if (Ap6256FipsActive(Ctx, ifIndex) || Ap6256HostCipherPacketActive(Ctx, ifIndex)) return;
        Ap6256IndicateRx(Ctx, frame, frameLength, priority, ifIndex);
    } else if (Channel == SDPCM_EVENT_CHANNEL) {
        Ap6256HandleEvent(Ctx, frame, frameLength);
    }
}

static NTSTATUS Ap6256StoreGlomDescriptor(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                           _In_reads_bytes_(Length) PUCHAR Payload,
                                           _In_ ULONG Length)
{
    ULONG count;
    ULONG total = 0;
    ULONG index;

    if (Length == 0 || (Length & 1u) != 0) return STATUS_DEVICE_DATA_ERROR;
    count = Length / sizeof(UINT16);
    if (count > RTL_NUMBER_OF(Ctx->GlomLengths)) return STATUS_BUFFER_OVERFLOW;

    for (index = 0; index < count; index++) {
        UINT16 subLength;
        RtlCopyMemory(&subLength, Payload + index * sizeof(subLength), sizeof(subLength));
        if (subLength < SDPCM_HDRLEN || (index == 0 && subLength < 2 * SDPCM_HDRLEN) ||
            total > Ctx->RxScratchSize - subLength) {
            Ctx->GlomCount = 0;
            Ctx->GlomTotalLength = 0;
            return STATUS_DEVICE_DATA_ERROR;
        }
        Ctx->GlomLengths[index] = subLength;
        total += subLength;
    }

    Ctx->GlomCount = count;
    Ctx->GlomTotalLength = total;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256HandleGlomSuperframe(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                            _In_ ULONG TransferLength,
                                            _In_ ULONG OuterDataOffset)
{
    ULONG index;
    ULONG segmentStart = 0;
    ULONG segmentEnd = 0;
    NTSTATUS status = STATUS_SUCCESS;

    if (Ctx->GlomCount == 0) return STATUS_DEVICE_PROTOCOL_ERROR;

    for (index = 0; index < Ctx->GlomCount; index++) {
        PSDPCM_HW_HEADER hw;
        PSDPCM_SW_HEADER sw;
        ULONG dataOffset;
        ULONG available;
        UCHAR channel;

        if (segmentEnd > MAXULONG - Ctx->GlomLengths[index]) {
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }
        segmentEnd += Ctx->GlomLengths[index];
        segmentStart = (index == 0) ? OuterDataOffset
                                    : segmentEnd - Ctx->GlomLengths[index];
        if (segmentStart > segmentEnd || segmentEnd > TransferLength ||
            segmentEnd - segmentStart < SDPCM_HDRLEN) {
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }

        available = segmentEnd - segmentStart;
        hw = (PSDPCM_HW_HEADER)(Ctx->RxScratch + segmentStart);
        if (hw->FrameLength < SDPCM_HDRLEN || hw->FrameLength > available ||
            (UINT16)(hw->FrameLength ^ hw->FrameLengthInverted) != 0xffff) {
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }
        sw = (PSDPCM_SW_HEADER)((PUCHAR)hw + SDPCM_HWHDR_LEN);
        dataOffset = sw->DataOffset;
        channel = (UCHAR)(sw->ChannelAndFlags & SDPCM_CHANNEL_MASK);
        if (dataOffset < SDPCM_HDRLEN || dataOffset > hw->FrameLength ||
            (channel != SDPCM_DATA_CHANNEL && channel != SDPCM_EVENT_CHANNEL)) {
            status = STATUS_DEVICE_DATA_ERROR;
            break;
        }

        {
            KIRQL oldIrql;
            KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);
            Ctx->Sdio.RxSeq = (UINT8)(sw->Sequence + 1);
            KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
        }
        if (channel == SDPCM_DATA_CHANNEL) {
            InterlockedIncrement64(&Ctx->Sdio.StatRxFrames);
        }
        Ap6256DispatchBcdcFrame(Ctx, channel, (PUCHAR)hw + dataOffset,
                                hw->FrameLength - dataOffset);
    }

    Ctx->GlomCount = 0;
    Ctx->GlomTotalLength = 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ProcessHostMailbox(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                         _In_ UINT32 SdiodBase,
                                         _Inout_ PUINT32 InterruptStatus)
{
    UINT32 mailboxData;
    NTSTATUS status;

    status = Ap6256SdioReadBackplane32(
        Ctx, SdiodBase + SD_REG_TOHOSTMAILBOXDATA, &mailboxData);
    if (!NT_SUCCESS(status)) return status;

    status = Ap6256SdioWriteBackplane32(
        Ctx, SdiodBase + SD_REG_TOSBMAILBOX, SMB_INT_ACK);

    if ((mailboxData & HMB_DATA_FWHALT) != 0) {
        if (!NT_SUCCESS(status))
            TraceError(TRACE_FIRMWARE, "firmware halt mailbox ACK failed 0x%08X\n", status);
        Ap6256FirmwareHalt(Ctx, mailboxData, *InterruptStatus);
        return STATUS_DEVICE_HARDWARE_ERROR;
    }
    if (!NT_SUCCESS(status)) return status;

    if ((mailboxData & (HMB_DATA_DEVREADY | HMB_DATA_FWREADY)) != 0) {
        UINT32 version = (mailboxData & HMB_DATA_VERSION_MASK) >>
                         HMB_DATA_VERSION_SHIFT;
        if (version != SDPCM_PROT_VERSION) {
            TraceError(TRACE_FIRMWARE,
                       "SDPCM protocol mismatch (dongle=%u host=%u)\n",
                       version, SDPCM_PROT_VERSION);
            return STATUS_REVISION_MISMATCH;
        }
    }

    if ((mailboxData & HMB_DATA_FC) != 0) {
        KIRQL oldIrql;
        KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);
        Ctx->Sdio.FlowControl = (UINT8)((mailboxData & HMB_DATA_FCDATA_MASK) >>
                                        HMB_DATA_FCDATA_SHIFT);
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
        Ap6256NetTxKick(Ctx);
    }
    if ((mailboxData & HMB_DATA_NAKHANDLED) != 0) {

        if (Ctx->RxSkip) {
            TraceWarn(TRACE_NETADAPTER, "NAK handled; retransmission expected\n");
        } else {
            TraceWarn(TRACE_NETADAPTER, "unexpected NAKHANDLED\n");
        }
        Ctx->RxSkip = FALSE;
        *InterruptStatus |= I_HMB_FRAME_IND;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256FramePass(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 sdiodBase, intstatus, newstatus;
    NTSTATUS status;
    int guard;

    if (!Ctx->DatapathRunning || Ctx->Chip.SdiodCore == NULL ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0) goto done;
    sdiodBase = Ctx->Chip.SdiodCore->Base;

    status = Ap6256SdioReadBackplane32(Ctx, sdiodBase + SD_REG_INTSTATUS, &intstatus);
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "intstatus read failed 0x%08X\n", status);
        goto done;
    }
    intstatus &= SDPCM_HOSTINTMASK;
    if (intstatus != 0) {
        status = Ap6256SdioWriteBackplane32(Ctx, sdiodBase + SD_REG_INTSTATUS,
                                            intstatus);
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER, "intstatus clear failed 0x%08X\n", status);
            goto done;
        }
    }

    newstatus = intstatus;
    if ((intstatus & I_HMB_FC_CHANGE) != 0) {

        status = Ap6256SdioReadBackplane32(
            Ctx, sdiodBase + SD_REG_INTSTATUS, &newstatus);
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER, "flow-control status re-read failed 0x%08X\n",
                      status);
            newstatus = I_HMB_FC_CHANGE;
        } else {
            newstatus &= SDPCM_HOSTINTMASK;
            intstatus |= newstatus;
        }
    }

    {
        KIRQL oldIrql;
        KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);
        Ctx->Sdio.TxFlowStopped =
            (newstatus & (I_HMB_FC_STATE | I_HMB_FC_CHANGE)) != 0;
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
        Ap6256NetTxKick(Ctx);
    }

    if ((intstatus & I_HMB_HOST_INT) != 0) {
        status = Ap6256ProcessHostMailbox(Ctx, sdiodBase, &intstatus);
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER, "host mailbox failed 0x%08X\n", status);
            goto done;
        }
    }

    if (Ctx->RxSkip) {

        ULONGLONG waitedMs = (KeQueryInterruptTime() - Ctx->RxSkipSince) / 10000u;
        if (waitedMs >= AP6256_RXSKIP_LIMIT_MS) {
            TraceWarn(TRACE_NETADAPTER, "NAK not acknowledged after %I64u ms; "
                      "reading again\n", waitedMs);
            Ctx->RxSkip = FALSE;
            intstatus |= I_HMB_FRAME_IND;
        }
    }

    if ((intstatus & I_HMB_FRAME_IND) != 0 && !Ctx->RxSkip) {

        ULONG framesThisPass = 0;
        ULONG emptyPolls = 0;

        Ctx->RxBatching = TRUE;
        InterlockedIncrement64(&Ctx->Sdio.StatPasses);

        for (guard = 0; guard < AP6256_RX_PASS_LIMIT && !Ctx->RxSkip; guard++) {
            PUCHAR payload;
            ULONG payloadLen;
            ULONG transferLength;
            ULONG dataOffset;
            UCHAR channel;

            Ap6256LockAcquire(&Ctx->Sdio.Lock);
            status = Ap6256ReadSdpcmFrame(Ctx, &payload, &payloadLen, &channel,
                                          &transferLength, &dataOffset);
            Ap6256LockRelease(&Ctx->Sdio.Lock);
            if (!NT_SUCCESS(status) && status != STATUS_NO_MORE_ENTRIES) {

                TraceWarn(TRACE_NETADAPTER, "frame read failed 0x%08X\n", status);
            }

            if (!NT_SUCCESS(status)) {
                if (status == STATUS_NO_MORE_ENTRIES && framesThisPass > 1 &&
                    emptyPolls < min(AP6256_RX_EMPTY_POLLS, framesThisPass - 1)) {
                    emptyPolls++;
                    InterlockedIncrement64(&Ctx->Sdio.StatEmptyPolls);
                    continue;
                }
                break;
            }
            framesThisPass++;
            emptyPolls = 0;

            switch (channel) {
            case SDPCM_DATA_CHANNEL:
                InterlockedIncrement64(&Ctx->Sdio.StatRxFrames);
                Ap6256DispatchBcdcFrame(Ctx, channel, payload, payloadLen);
                break;
            case SDPCM_EVENT_CHANNEL:
                Ap6256DispatchBcdcFrame(Ctx, channel, payload, payloadLen);
                break;
            case SDPCM_CONTROL_CHANNEL:
                Ap6256BcdcProcessControlFrame(Ctx, payload, payloadLen);
                break;
            case SDPCM_GLOM_CHANNEL: {
                PSDPCM_SW_HEADER sw = (PSDPCM_SW_HEADER)(
                    Ctx->RxScratch + SDPCM_HWHDR_LEN);
                if ((sw->ChannelAndFlags & 0x80) != 0) {
                    status = Ap6256StoreGlomDescriptor(Ctx, payload, payloadLen);
                } else {
                    status = Ap6256HandleGlomSuperframe(
                        Ctx, transferLength, dataOffset);
                }
                if (!NT_SUCCESS(status)) {
                    TraceWarn(TRACE_NETADAPTER, "invalid glom frame 0x%08X\n", status);
                }
                break;
            }
            default:
                TraceVerbose(TRACE_NETADAPTER, "frame on channel %u (%u bytes)\n",
                             channel, payloadLen);
                break;
            }
        }
    }

    Ctx->RxBatching = FALSE;
    Ap6256NetRxFlush(Ctx);

done:
    return;
}

_Use_decl_annotations_
VOID Ap6256FrameWorker(PVOID Context)
{
    PAP6256_DEVICE_CONTEXT Ctx = (PAP6256_DEVICE_CONTEXT)Context;
    BOOLEAN acknowledge = FALSE;

    if (InterlockedCompareExchange(&Ctx->FrameDraining, 1, 0) != 0) {
        InterlockedExchange(&Ctx->FrameRerun, 1);
        return;
    }

    for (;;) {
        InterlockedExchange(&Ctx->FrameRerun, 0);

        if (InterlockedExchange(&Ctx->Watchdog.PollRequested, 0) == 0 ||
            InterlockedCompareExchange(&Ctx->Sdio.IsrCount, 0, 0) !=
            InterlockedCompareExchange(&Ctx->Watchdog.PollIsr, 0, 0) ||
            Ap6256WatchdogCheckPending(Ctx)) {
            acknowledge = TRUE;
            Ap6256FramePass(Ctx);
        }

        if (InterlockedCompareExchange(&Ctx->FrameRerun, 0, 0) == 0) {
            InterlockedExchange(&Ctx->FrameDraining, 0);

            if (InterlockedCompareExchange(&Ctx->FrameRerun, 0, 0) == 0 ||
                InterlockedCompareExchange(&Ctx->FrameDraining, 1, 0) != 0) {
                break;
            }
        }
    }

    Ap6256SdioTraceBusStats(Ctx);
    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0)
        Ap6256WatchdogStop(Ctx);

    if (acknowledge) Ap6256SdBusAckInterrupt(Ctx);
}

static BOOLEAN Ap6256TxGlomConfigured(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG value = 1;
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    NTSTATUS status;

    status = Ap6256RegQueryValue(Ctx->Pdo, L"TxGlom", sizeof(value),
                                 &value, &valueLength, &valueType);
    if (NT_SUCCESS(status) && valueType == REG_DWORD &&
        valueLength == sizeof(value)) {
        return value != 0;
    }
    return TRUE;
}

static ULONG Ap6256TxGlomBytesConfigured(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG value = 0;
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    ULONG most = Ctx->TxScratchSize > AP6256_TX_GLOM_ROOM ?
                 Ctx->TxScratchSize - AP6256_TX_GLOM_ROOM : 0;
    NTSTATUS status;

    status = Ap6256RegQueryValue(Ctx->Pdo, L"TxGlomBytes", sizeof(value),
                                 &value, &valueLength, &valueType);
    if (NT_SUCCESS(status) && valueType == REG_DWORD &&
        valueLength == sizeof(value) && value >= AP6256_TX_GLOM_MIN_BYTES) {
        return min(value, most);
    }
    return most;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG Ap6256DatapathTxGlomBytes(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG cap = Ctx->Sdio.TxGlomBytes;
    ULONG hostCap = Ctx->Sdio.MaxTransferBytes[AP6256_SDIO_FUNC_DATA];
    ULONG blockSize = Ctx->Sdio.Function2BlockSize;
    ULONG room;

    if (cap == 0) {
        cap = Ctx->TxScratchSize;
    }

    if (hostCap != 0 && hostCap < cap) {
        cap = hostCap;
    }
    if (blockSize != 0 && cap > 511u * blockSize) {
        cap = 511u * blockSize;
    }
    if (Ctx->Sdio.MaxBlocksPerCmd53 != 0 && blockSize != 0 &&
        Ctx->Sdio.MaxBlocksPerCmd53 * blockSize < cap) {
        cap = Ctx->Sdio.MaxBlocksPerCmd53 * blockSize;
    }

    room = Ctx->TxScratchSize > AP6256_TX_GLOM_ROOM ?
           Ctx->TxScratchSize - AP6256_TX_GLOM_ROOM : 0;
    if (cap > room) {
        cap = room;
    }
    if (blockSize != 0 && cap > blockSize) {
        cap -= cap % blockSize;
    }
    return cap;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathEnableTxGlom(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 on = 1;
    NTSTATUS status;

    if (!Ap6256TxGlomConfigured(Ctx)) {
        TraceDiag("tx glom: off by registry TxGlom; one frame per write\n");
        return STATUS_SUCCESS;
    }

    status = Ap6256BcdcSetIovar(Ctx, "bus:rxglom", &on, sizeof(on));
    if (!NT_SUCCESS(status)) {
        TraceDiag("tx glom: bus:rxglom negotiation failed (0x%08X); one frame "
                  "per write\n", status);
        return STATUS_SUCCESS;
    }

    Ap6256LockAcquire(&Ctx->Bcdc.Lock);
    Ap6256LockAcquire(&Ctx->Sdio.TxLock);
    Ctx->Sdio.TxGlom = TRUE;
    Ctx->Sdio.TxGlomBytes = Ap6256TxGlomBytesConfigured(Ctx);
    Ap6256LockRelease(&Ctx->Sdio.TxLock);
    Ap6256LockRelease(&Ctx->Bcdc.Lock);

    TraceDiag("tx glom: on, up to %u frame(s) or %u bytes per write, "
              "header %u bytes\n",
              AP6256_TX_GLOM_MAX_FRAMES, Ap6256DatapathTxGlomBytes(Ctx),
              Ap6256TxHdrLen(Ctx));
    return STATUS_SUCCESS;
}

static VOID Ap6256FillSwHeader(_Out_ PSDPCM_SW_HEADER Sw, _In_ UINT8 Sequence,
                               _In_ UCHAR Channel, _In_ ULONG DataOffset)
{
    RtlZeroMemory(Sw, sizeof(*Sw));
    Sw->Sequence = Sequence;
    Sw->ChannelAndFlags = Channel;
    Sw->DataOffset = (UINT8)DataOffset;
}

#define AP6256_CONTROL_TX_RETRIES 2u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathSendSdpcm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Inout_updates_bytes_(TransferLength) PUCHAR Frame,
                                 _In_ ULONG TransferLength)
{
    PSDPCM_HW_HEADER hw;
    PSDPCM_SW_HEADER sw;
    ULONG hdrLen;
    ULONG wireLength;
    UCHAR channel;
    UCHAR priority = 0;
    NTSTATUS status;
    KIRQL oldIrql;
    UINT8 creditDelta;
    ULONG retries = 0;

    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0)
        return STATUS_DEVICE_HARDWARE_ERROR;
    if (Frame == NULL || TransferLength < SDPCM_HDRLEN) {
        return STATUS_INVALID_PARAMETER;
    }
    hdrLen = Ap6256TxHdrLen(Ctx);
    if (TransferLength < hdrLen) {
        return STATUS_INVALID_PARAMETER;
    }
    hw = (PSDPCM_HW_HEADER)Frame;
    sw = (PSDPCM_SW_HEADER)(Frame + hdrLen - SDPCM_SWHDR_LEN);
    wireLength = hw->FrameLength;
    if (wireLength < hdrLen || wireLength > TransferLength ||
        (UINT16)(hw->FrameLength ^ hw->FrameLengthInverted) != 0xffff ||
        Ap6256Align4(wireLength) > TransferLength) {
        return STATUS_DEVICE_DATA_ERROR;
    }

    channel = (UCHAR)(sw->ChannelAndFlags & SDPCM_CHANNEL_MASK);
    if (channel == SDPCM_DATA_CHANNEL) {
        PBCDC_DATA_HEADER bdc;
        if (sw->DataOffset < hdrLen ||
            sw->DataOffset > wireLength - sizeof(BCDC_DATA_HEADER)) {
            return STATUS_DEVICE_DATA_ERROR;
        }
        bdc = (PBCDC_DATA_HEADER)(Frame + sw->DataOffset);
        priority = (UCHAR)(bdc->Priority & 0x07);
    }

    Ap6256LockAcquire(&Ctx->Sdio.TxLock);
    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_DEVICE_HARDWARE_ERROR;
    }
    if (!Ctx->DatapathRunning || Ctx->Sdio.Sleeping ||
        (channel == SDPCM_DATA_CHANNEL && Ctx->HostTxQuiesced != 0)) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_DEVICE_NOT_READY;
    }
    if (channel == SDPCM_DATA_CHANNEL &&
        !Ap6256RawBcdcTxCurrent(Ctx, Frame + sw->DataOffset, wireLength - sw->DataOffset)) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_CANCELLED;
    }
    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);

    creditDelta = (UINT8)(Ctx->Sdio.MaxTxSeq - Ctx->Sdio.TxSeq);
    if (creditDelta == 0 || (creditDelta & 0x80) != 0 ||
        (channel == SDPCM_DATA_CHANNEL &&
         (creditDelta < 2 ||
          Ctx->Sdio.TxFlowStopped ||
          (Ctx->Sdio.FlowControl & (1u << priority)) != 0))) {
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_DEVICE_BUSY;
    }
    sw->Sequence = Ctx->Sdio.TxSeq;
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);

    if (Ctx->Sdio.TxGlom) {
        PSDPCM_HW_EXT ext = (PSDPCM_HW_EXT)(Frame + SDPCM_HWHDR_LEN);

        ext->LengthAndLast = (wireLength - SDPCM_HWHDR_LEN) | SDPCM_HWEXT_LASTFRM;
        ext->TailPad = (TransferLength - wireLength) << SDPCM_HWEXT_TAILPAD_SHIFT;
        hw->FrameLength = (UINT16)TransferLength;
        hw->FrameLengthInverted = (UINT16)~TransferLength;
    }

    for (;;) {
        if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0) {
            status = STATUS_DEVICE_HARDWARE_ERROR;
            break;
        }
        status = Ap6256SdioFrameRW(Ctx, TRUE, Frame, TransferLength);
        if (NT_SUCCESS(status)) {
            KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);
            Ctx->Sdio.TxSeq = (UINT8)(Ctx->Sdio.TxSeq + 1);
            KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
            InterlockedIncrement64(&Ctx->Sdio.StatTxFrames);
            break;
        }

        Ap6256SdioTxFail(Ctx);

        if (channel != SDPCM_CONTROL_CHANNEL || status != STATUS_CRC_ERROR ||
            !Ctx->DatapathRunning || retries == AP6256_CONTROL_TX_RETRIES) {
            break;
        }
        retries++;
        TraceDiag("control TX CRC: retry %u/%u, sequence %u\n",
                  retries, AP6256_CONTROL_TX_RETRIES, sw->Sequence);
    }

    if (Ctx->Sdio.TxGlom) {
        hw->FrameLength = (UINT16)wireLength;
        hw->FrameLengthInverted = (UINT16)~wireLength;
    }
    Ap6256LockRelease(&Ctx->Sdio.TxLock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathSendGlom(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _Inout_updates_bytes_(BufferSize) PUCHAR Buffer,
                                _In_ ULONG BufferSize,
                                _In_reads_(Count) const AP6256_TX_GLOM_FRAME* Frames,
                                _In_ ULONG Count,
                                _Out_ PULONG Sent)
{
    ULONG hdrLen = Ap6256TxHdrLen(Ctx);
    ULONG headroom = hdrLen + sizeof(BCDC_DATA_HEADER);
    ULONG most = Ctx->Sdio.TxGlom ? AP6256_TX_GLOM_MAX_FRAMES : 1u;
    ULONG n, i, lastEnd, transferLength;
    UCHAR savedTail[512];
    ULONG savedOffset = 0, savedLength = 0;
    UINT8 window, seq;
    KIRQL oldIrql;
    NTSTATUS status;

    *Sent = 0;
    if (!Ctx->DatapathRunning || Ctx->Sdio.Sleeping || Ctx->HostTxQuiesced != 0)
        return STATUS_DEVICE_NOT_READY;
    if (Buffer == NULL || Frames == NULL || Count == 0 ||
        Count > AP6256_TX_GLOM_MAX_FRAMES) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Frames[0].Offset != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    lastEnd = 0;
    for (i = 0; i < Count; i++) {
        ULONG gap = Ap6256Align4(lastEnd);

        if ((Frames[i].Offset & 3u) != 0 || Frames[i].WireLength < headroom ||
            Frames[i].WireLength > MAXUINT16 || Frames[i].WireLength > BufferSize ||
            Frames[i].Offset > BufferSize - Frames[i].WireLength ||
            Frames[i].Offset < gap || Frames[i].Offset - gap > 3u) {
            return STATUS_INVALID_PARAMETER;
        }
        lastEnd = Frames[i].Offset + Frames[i].WireLength;
    }

    Ap6256LockAcquire(&Ctx->Sdio.TxLock);
    if (!Ctx->DatapathRunning || Ctx->Sdio.Sleeping || Ctx->HostTxQuiesced != 0) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_DEVICE_NOT_READY;
    }
    for (i = 0; i < Count; ++i) {
        if (!Ap6256RawBcdcTxCurrent(Ctx, Buffer + Frames[i].Offset + hdrLen,
            Frames[i].WireLength - hdrLen)) {
            Ap6256LockRelease(&Ctx->Sdio.TxLock);
            return STATUS_CANCELLED;
        }
    }
    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);

    window = (UINT8)(Ctx->Sdio.MaxTxSeq - Ctx->Sdio.TxSeq);
    if ((window & 0x80u) != 0 || window < 2u) {
        n = 0;
    } else {

        n = Count;
        if (n > most) {
            n = most;
        }
        if (n > (ULONG)window - 1u) {
            n = (ULONG)window - 1u;
        }
    }
    __analysis_assume(n <= Count);
    seq = Ctx->Sdio.TxSeq;
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
    if (n == 0) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_DEVICE_BUSY;
    }

    lastEnd = Frames[n - 1].Offset + Frames[n - 1].WireLength;
    transferLength = Ap6256AlignTransfer(Ctx, lastEnd);
    if (transferLength == 0 || transferLength > BufferSize ||
        transferLength > MAXUINT16) {
        Ap6256LockRelease(&Ctx->Sdio.TxLock);
        return STATUS_BUFFER_OVERFLOW;
    }

    if (n < Count && transferLength > Frames[n].Offset) {
        savedOffset = Frames[n].Offset;
        savedLength = transferLength - savedOffset;
        if (savedLength > sizeof(savedTail)) {
            Ap6256LockRelease(&Ctx->Sdio.TxLock);
            return STATUS_BUFFER_OVERFLOW;
        }
        RtlCopyMemory(savedTail, Buffer + savedOffset, savedLength);
    }
    if (transferLength > lastEnd) {
        RtlZeroMemory(Buffer + lastEnd, transferLength - lastEnd);
    }

    {
        PSDPCM_HW_EXT prevExt = NULL;
        ULONG prevEnd = 0;

        for (i = 0; i < n; i++) {
            PUCHAR frame = Buffer + Frames[i].Offset;
            PSDPCM_HW_HEADER hw = (PSDPCM_HW_HEADER)frame;
            ULONG len = Frames[i].WireLength;

            hw->FrameLength = (UINT16)len;
            hw->FrameLengthInverted = (UINT16)~len;
            Ap6256FillSwHeader((PSDPCM_SW_HEADER)(frame + hdrLen - SDPCM_SWHDR_LEN),
                               (UINT8)(seq + i), SDPCM_DATA_CHANNEL, hdrLen);
            if (Ctx->Sdio.TxGlom) {
                PSDPCM_HW_EXT ext = (PSDPCM_HW_EXT)(frame + SDPCM_HWHDR_LEN);

                ext->LengthAndLast = (len - SDPCM_HWHDR_LEN) |
                                     ((i + 1 == n) ? SDPCM_HWEXT_LASTFRM : 0u);
                ext->TailPad = 0;

                if (prevExt != NULL) {
                    ULONG pad = Frames[i].Offset - prevEnd;

                    prevExt->TailPad = pad << SDPCM_HWEXT_TAILPAD_SHIFT;
                    if (pad != 0) {
                        RtlZeroMemory(Buffer + prevEnd, pad);
                    }
                }
                prevExt = ext;
            }
            prevEnd = Frames[i].Offset + len;
        }

        if (prevExt != NULL) {
            prevExt->TailPad = (transferLength - prevEnd) << SDPCM_HWEXT_TAILPAD_SHIFT;
        }
    }

    if (Ctx->Sdio.TxGlom) {
        PSDPCM_HW_HEADER hw = (PSDPCM_HW_HEADER)Buffer;

        hw->FrameLength = (UINT16)transferLength;
        hw->FrameLengthInverted = (UINT16)~transferLength;
    }

    status = Ap6256SdioFrameRW(Ctx, TRUE, Buffer, transferLength);
    if (savedLength != 0)
        RtlCopyMemory(Buffer + savedOffset, savedTail, savedLength);
    if (NT_SUCCESS(status)) {
        KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &oldIrql);
        Ctx->Sdio.TxSeq = (UINT8)(Ctx->Sdio.TxSeq + n);
        KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, oldIrql);
        InterlockedAdd64(&Ctx->Sdio.StatTxFrames, (LONGLONG)n);
        *Sent = n;
    } else {
        Ap6256SdioTxFail(Ctx);
    }
    Ap6256LockRelease(&Ctx->Sdio.TxLock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathTransmit(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length)
{
    PUCHAR buf;
    PSDPCM_HW_HEADER hw;
    PSDPCM_SW_HEADER sw;
    PBCDC_DATA_HEADER bdc;
    ULONG wireLength;
    ULONG transferLength;
    ULONG hdrLen = Ap6256TxHdrLen(Ctx);
    ULONG headroom = hdrLen + sizeof(BCDC_DATA_HEADER);
    NTSTATUS status;

    if (Length == 0 || Length > 1600) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Ap6256WlfcEnabled(Ctx)) {
        return Ap6256WlfcEnqueue(Ctx, Frame, Length, AP6256_TX_PRIORITY,
            BCDC_DATA_EXEMPT_NONE, 0, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL, NULL);
    }
    wireLength = headroom + Length;
    transferLength = Ap6256AlignTransfer(Ctx, wireLength);
    if (transferLength == 0 || wireLength > MAXUINT16) {
        return STATUS_INTEGER_OVERFLOW;
    }

    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, transferLength,
                                  AP6256_POOL_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buf, transferLength);

    hw  = (PSDPCM_HW_HEADER)buf;
    sw  = (PSDPCM_SW_HEADER)(buf + hdrLen - SDPCM_SWHDR_LEN);
    bdc = (PBCDC_DATA_HEADER)(buf + hdrLen);

    hw->FrameLength = (UINT16)wireLength;
    hw->FrameLengthInverted = (UINT16)~wireLength;

    sw->ChannelAndFlags = SDPCM_DATA_CHANNEL;
    sw->DataOffset = (UINT8)hdrLen;

    bdc->Flags = (BCDC_DCMD_PROTO_VERSION << BCDC_DATA_FLAG_PROTO_SHIFT);
    bdc->Priority = AP6256_TX_PRIORITY;
    bdc->Flags2 = 0;
    bdc->DataOffset = 0;

    RtlCopyMemory(buf + headroom, Frame, Length);

    status = Ap6256DatapathSendSdpcm(Ctx, buf, transferLength);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&Ctx->TxFrames);
    } else {
        TraceWarn(TRACE_NETADAPTER, "tx failed 0x%08X\n", status);
    }

    ExFreePoolWithTag(buf, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathSuspend(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ctx->DatapathRunning = FALSE;
    Ap6256WatchdogStop(Ctx);
    Ap6256WorkItemFlush(&Ctx->FrameWorker);

    Ap6256LockAcquire(&Ctx->Sdio.TxLock);
    Ap6256LockRelease(&Ctx->Sdio.TxLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathResume(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ctx->DatapathRunning = TRUE;
    InterlockedExchange(&Ctx->IsrHeldOff, 0);
    if (Ap6256WorkItemValid(&Ctx->FrameWorker)) Ap6256WorkItemEnqueue(&Ctx->FrameWorker);
    Ap6256WatchdogStart(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathTransmitEx(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
    UCHAR Priority, UCHAR Exemption, UCHAR IfIndex, UINT16 Port, UINT16 Peer, PVOID Cookie)
{
    PUCHAR buf;
    PSDPCM_HW_HEADER hw;
    PSDPCM_SW_HEADER sw;
    PBCDC_DATA_HEADER bdc;
    ULONG wireLength;
    ULONG transferLength;
    ULONG hdrLen = Ap6256TxHdrLen(Ctx);
    ULONG headroom = hdrLen + sizeof(BCDC_DATA_HEADER);
    NTSTATUS status;

    if (Length < 14 || Priority > 7 || IfIndex > 15 ||
        (Exemption == AP6256_FIPS_BCDC_TX_EXEMPT ? !Ap6256RawTxCurrent(Ctx, IfIndex, Frame, Length) :
        (Length > 1600 || Ap6256FipsActive(Ctx, IfIndex) || Ap6256HostCipherPacketActive(Ctx, IfIndex) ||
        (Exemption != BCDC_DATA_EXEMPT_NONE && Exemption != BCDC_DATA_EXEMPT_ALWAYS && Exemption != BCDC_DATA_EXEMPT_ON_NO_KEY)))) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Ap6256WlfcEnabled(Ctx)) {
        return Ap6256WlfcEnqueue(Ctx, Frame, Length, Priority,
            Exemption, IfIndex, Port, Peer, NULL, Cookie);
    }
    wireLength = headroom + Length;
    transferLength = Ap6256AlignTransfer(Ctx, wireLength);
    if (transferLength == 0 || wireLength > MAXUINT16) {
        return STATUS_INTEGER_OVERFLOW;
    }

    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, transferLength,
                                  AP6256_POOL_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(buf, transferLength);

    hw  = (PSDPCM_HW_HEADER)buf;
    sw  = (PSDPCM_SW_HEADER)(buf + hdrLen - SDPCM_SWHDR_LEN);
    bdc = (PBCDC_DATA_HEADER)(buf + hdrLen);

    hw->FrameLength = (UINT16)wireLength;
    hw->FrameLengthInverted = (UINT16)~wireLength;

    sw->ChannelAndFlags = SDPCM_DATA_CHANNEL;
    sw->DataOffset = (UINT8)hdrLen;

    bdc->Flags = (BCDC_DCMD_PROTO_VERSION << BCDC_DATA_FLAG_PROTO_SHIFT) | Exemption;
    bdc->Priority = Priority;
    bdc->Flags2 = IfIndex;
    bdc->DataOffset = 0;

    RtlCopyMemory(buf + headroom, Frame, Length);

    status = Ap6256DatapathSendSdpcm(Ctx, buf, transferLength);
    if (NT_SUCCESS(status)) {
        InterlockedIncrement(&Ctx->TxFrames);
    } else {
        TraceWarn(TRACE_NETADAPTER, "tx failed 0x%08X\n", status);
    }

    ExFreePoolWithTag(buf, AP6256_POOL_TAG);
    return status;
}
