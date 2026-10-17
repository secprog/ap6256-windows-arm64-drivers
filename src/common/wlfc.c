/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "wlfc.h"
#include "bcdc.h"
#include "datapath.h"
#include "netadapter.h"
#include "model.h"
#include "host_fips.h"
#include "host_cipher_transport.h"

#define WLFC_FIFOS 6u
#define WLFC_PEERS 32u
#define WLFC_IFS 16u
#define WLFC_TIMEOUT (10ull * 10000000ull)
#define WLFC_FLAGS 0x0eu
#define WLFC_TAG_HOST 0x08000000u
#define WLFC_TAG_REQUESTED 0x10000000u
#define WLFC_TAG_GEN 0x80000000u
#define WLFC_STATUS_FLAGS(s) (((s) >> 27) & 15u)
#define WLFC_STATUS_SLOT(s) ((UINT16)((s) >> 8))

typedef enum { WlfcFree, WlfcQueued, WlfcWriting, WlfcFlight,
    WlfcSuppressed, WlfcDone, WlfcCreditWait } WLFC_STATE;
typedef struct {
    BOOLEAN Used, Closed, Blocked;
    UCHAR Handle, IfIndex, Address[6], Generation;
    UCHAR RequestedCredit, RequestedPacket, AcBitmap, LastBitmap;
    ULONG Transit, Suppressed, Identity;
} WLFC_PEER;
typedef struct {
    WLFC_STATE State;
    UINT32 Tag;
    ULONG Length, Retries, PeerIdentity;
    UINT16 Port, Peer;
    UCHAR Priority, Exemption, IfIndex, Fifo, Request;
    BOOLEAN Bound;
    UCHAR Node, Handle;
    BOOLEAN Debited, Cancelled, TransferReady, TransferOk, TransferNotified;
    BOOLEAN PendingStatus, Notifying;
    AP6256_WLFC_RESULT Result;
    UINT32 Status;
    ULONGLONG Order, Deadline;
    AP6256_WLFC_CALLBACK Callback;
    PVOID Cookie;
    UCHAR Destination[6];
    UCHAR Ethernet[AP6256_FIPS_TX_HEADER_BYTES + AP6256_FIPS_MAX_MPDU_BYTES];
} WLFC_PACKET;
typedef enum { WlfcExplicit, WlfcImplicit, WlfcRefund } WLFC_RETURN;
typedef struct {
    ULONG Debits, Explicit, Implicit, Refunds, Clamped, Statuses, Waits;
} WLFC_FIFO_STATS;

typedef struct _AP6256_WLFC {
    PAP6256_DEVICE_CONTEXT Ctx;
    KSPIN_LOCK Lock;
    AP6256_LOCK WorkerLock;
    AP6256_WORKITEM Worker;
    AP6256_TIMER Timer;
    BOOLEAN Enabled, Running, BcmcCredit;
    BOOLEAN Aborting, RoomReleased;
    UINT16 AbortPort, AbortPeer;
    LONG Credit[WLFC_FIFOS];
    UCHAR Limit[WLFC_FIFOS], Sequence[WLFC_FIFOS], NextFifo;
    BOOLEAN InterfaceClosed[WLFC_IFS];
    WLFC_PEER Nodes[WLFC_PEERS], Interfaces[WLFC_IFS];
    WLFC_PEER Orphan;
    UINT16 NextSlot;
    ULONGLONG NextOrder;
    ULONG Used, Stale, Malformed, Statuses, Suppressions, CreditReturns, Timeouts;
    ULONG Completed, NoAck, Discarded, NextPeerIdentity;
    WLFC_FIFO_STATS FifoStats[WLFC_FIFOS];
    ULONGLONG NextReport;
    WLFC_PACKET Packets[AP6256_WLFC_CAPACITY];
    UCHAR Wire[40960];
} AP6256_WLFC;

static WLFC_PEER* WlfcPeer(AP6256_WLFC* W, const WLFC_PACKET* P)
{
    ULONG i;
    if (P->Bound) {
        WLFC_PEER* peer;
        if (P->Node == 255) return &W->Interfaces[P->IfIndex];
        peer = &W->Nodes[P->Node];
        return peer->Used && peer->Identity == P->PeerIdentity &&
            peer->Handle == P->Handle && peer->IfIndex == P->IfIndex &&
            RtlCompareMemory(peer->Address, P->Destination, 6) == 6 ? peer : &W->Orphan;
    }
    for (i = 0; i < WLFC_PEERS; i++) {
        WLFC_PEER* n = &W->Nodes[i];
        if (n->Used && n->IfIndex == P->IfIndex &&
            RtlCompareMemory(n->Address, P->Destination, 6) == 6) return n;
    }
    return &W->Interfaces[P->IfIndex];
}

static VOID WlfcReturn(AP6256_WLFC* W, UCHAR Fifo, ULONG Count, WLFC_RETURN Kind)
{
    WLFC_FIFO_STATS* stats = &W->FifoStats[Fifo];
    W->Credit[Fifo] += (LONG)Count;
    if (W->Credit[Fifo] > W->Limit[Fifo]) {
        stats->Clamped += (ULONG)(W->Credit[Fifo] - W->Limit[Fifo]);
        W->Credit[Fifo] = W->Limit[Fifo];
    }
    if (Kind == WlfcExplicit) stats->Explicit += Count;
    else if (Kind == WlfcImplicit) stats->Implicit += Count;
    else stats->Refunds += Count;
    W->CreditReturns += Count;
}

static VOID WlfcRetire(AP6256_WLFC* W, WLFC_PACKET* P, AP6256_WLFC_RESULT Result)
{
    if (P->State == WlfcFlight || P->State == WlfcWriting) {
        WLFC_PEER* peer = WlfcPeer(W, P);
        if (peer->Transit != 0) peer->Transit--;
    } else if (P->State == WlfcSuppressed) {
        WLFC_PEER* peer = WlfcPeer(W, P);
        if (peer->Suppressed != 0) peer->Suppressed--;
    }
    P->State = WlfcDone;
    P->Result = P->Cancelled ? Ap6256WlfcCancelled : Result;
    W->Completed++;
    if (P->Result == Ap6256WlfcNoAck) W->NoAck++;
    if (P->Result == Ap6256WlfcDiscard) W->Discarded++;
    if (!P->TransferReady) {
        P->TransferReady = TRUE;
        P->TransferOk = FALSE;
    }
}

static VOID WlfcStatus(AP6256_WLFC* W, WLFC_PACKET* P, UINT32 Status)
{
    ULONG flags = WLFC_STATUS_FLAGS(Status);
    WLFC_PEER* peer = WlfcPeer(W, P);
    BOOLEAN suppression = (BOOLEAN)(flags == 1 || flags == 2);
    BOOLEAN retired = (BOOLEAN)(P->State == WlfcDone || P->State == WlfcCreditWait);
    if (P->Request == 1) {

        if (P->Debited) WlfcReturn(W, P->Fifo, 1, WlfcImplicit);
        if (peer->Closed && peer->RequestedCredit < 255) peer->RequestedCredit++;
    }
    P->Request = 0;
    P->Debited = FALSE;
    W->Statuses++;
    W->FifoStats[P->Fifo].Statuses++;
    if (W->Statuses <= 8) TraceVerbose(TRACE_DRIVER, "WLFC TX status: tag 0x%08X flags %u fifo %u slot %u\n",
        Status, flags, (ULONG)P->Fifo, (ULONG)WLFC_STATUS_SLOT(P->Tag));

    if (retired) {
        if (P->State == WlfcCreditWait) {
            P->State = WlfcFree;
            W->RoomReleased = TRUE;
        }
        return;
    }
    if (P->Cancelled) { WlfcRetire(W, P, Ap6256WlfcCancelled); return; }
    if (suppression && P->Retries < 32) {
        if (peer->Transit != 0) peer->Transit--;
        peer->Blocked = TRUE;
        peer->Suppressed++;
        peer->Generation = (UCHAR)(Status >> 31);
        P->Tag = (P->Tag & ~WLFC_TAG_GEN) | (Status & WLFC_TAG_GEN);
        P->State = WlfcSuppressed;
        P->Retries++;
        W->Suppressions++;
    } else {
        WlfcRetire(W, P, flags == 0 || flags == 5 ? Ap6256WlfcOk :
            flags == 4 ? Ap6256WlfcNoAck : Ap6256WlfcDiscard);
    }
}

static VOID WlfcTxStatus(AP6256_WLFC* W, UINT32 Status, ULONG Count)
{
    ULONG index, c;
    UINT16 slot = WLFC_STATUS_SLOT(Status);
    UCHAR fifo = (UCHAR)((Status >> 24) & 7u);
    for (c = 0; c < Count; c++, slot++) {
        WLFC_PACKET* p = NULL;
        for (index = 0; index < AP6256_WLFC_CAPACITY; index++) {
            WLFC_PACKET* candidate = &W->Packets[index];
            if (candidate->State != WlfcFree &&
                (candidate->State != WlfcDone || (candidate->Request == 1 && candidate->Debited)) &&
                WLFC_STATUS_SLOT(candidate->Tag) == slot && candidate->Fifo == fifo) {
                p = candidate;
                break;
            }
        }

        if (p == NULL || (c == 0 && (UCHAR)p->Tag != (UCHAR)Status) ||
            p->PendingStatus ||
            (p->State != WlfcWriting && p->State != WlfcFlight &&
             !((p->State == WlfcDone || p->State == WlfcCreditWait) &&
               p->Request == 1 && p->Debited) &&
             !(p->State == WlfcSuppressed && WLFC_STATUS_FLAGS(Status) == 5))) {
            W->Stale++;
            if (c == 0) return;
            continue;
        }
        if (p->State == WlfcWriting || p->Notifying) {
            p->Status = Status;
            p->PendingStatus = TRUE;
        } else {
            WlfcStatus(W, p, Status);
        }
    }
}

static BOOLEAN WlfcLength(UCHAR Type, UCHAR Length)
{
    switch (Type) {
    case 1: case 2: case 8: case 9: case 10: return Length == 1;
    case 3: return Length == 2 || Length == 3;
    case 13: return Length == 3;
    case 4: case 5: return Length == 4;
    case 6: case 7: return Length == 8;
    case 11: return Length == WLFC_FIFOS;
    case 12: return Length == 2;
    case 14: return Length == 10;
    case 18: return Length == 6;
    case 19: return Length == 5;
    default: return TRUE;
    }
}

_Use_decl_annotations_
BOOLEAN Ap6256WlfcSignals(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Signals, ULONG Length)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG offset = 0, i;
    KIRQL irql;
    if (w == NULL || Length == 0) return TRUE;

    while (offset < Length) {
        UCHAR type = Signals[offset++], length;
        if (type == 255) continue;
        if (offset == Length) goto malformed;
        length = Signals[offset++];
        if (length > Length - offset || !WlfcLength(type, length)) goto malformed;
        if (type == 19 && (Signals[offset + 4] == 0 ||
            Signals[offset + 4] > AP6256_WLFC_CAPACITY)) goto malformed;
        if ((type == 4 || type == 19) &&
            (WLFC_STATUS_FLAGS((UINT32)Signals[offset + 3] << 24) > 5 ||
             ((Signals[offset + 3] & 7u) >= WLFC_FIFOS))) goto malformed;
        offset += length;
    }
    KeAcquireSpinLock(&w->Lock, &irql);
    offset = 0;
    while (offset < Length) {
        UCHAR type = Signals[offset++], length;
        const UCHAR* data;
        WLFC_PEER* peer;
        if (type == 255) continue;
        length = Signals[offset++];
        data = Signals + offset;
        switch (type) {
        case 4: case 19: {
            UINT32 status;
            RtlCopyMemory(&status, data, sizeof(status));
            if (w->Enabled) WlfcTxStatus(w, status, type == 19 ? data[4] : 1);
            break;
        }
        case 11:
            if (w->Enabled && w->Running)
                for (i = 0; i < WLFC_FIFOS; i++) WlfcReturn(w, (UCHAR)i, data[i], WlfcExplicit);
            break;
        case 6: case 7:
            peer = &w->Nodes[data[0] & 31u];
            if (data[1] >= WLFC_IFS) break;
            if (type == 7 && (!peer->Used || peer->Handle != data[0] ||
                peer->IfIndex != data[1] || RtlCompareMemory(peer->Address, data + 2, 6) != 6)) break;
            if (type == 6 && peer->Used && peer->Handle == data[0] &&
                peer->IfIndex == data[1] && RtlCompareMemory(peer->Address, data + 2, 6) == 6) break;

            if (peer->Used && (type == 7 || peer->Handle != data[0] ||
                peer->IfIndex != data[1] ||
                RtlCompareMemory(peer->Address, data + 2, 6) != 6)) {
                for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
                    WLFC_PACKET* p = &w->Packets[i];
                    if (p->State != WlfcFree && p->State != WlfcDone &&
                        p->State != WlfcCreditWait && WlfcPeer(w, p) == peer) {
                        p->Cancelled = TRUE;
                        if (p->State != WlfcWriting) WlfcRetire(w, p, Ap6256WlfcCancelled);
                    }
                }
            }
            RtlZeroMemory(peer, sizeof(*peer));
            if (type == 6) {
                WLFC_PEER* existing = NULL;
                ULONG k;
                for (k = 0; k < WLFC_PEERS; k++) {
                    WLFC_PEER* candidate = &w->Nodes[k];
                    if (candidate != peer && candidate->Used && candidate->IfIndex == data[1] &&
                        RtlCompareMemory(candidate->Address, data + 2, 6) == 6) {
                        existing = candidate; *peer = *candidate;
                        peer->Transit = peer->Suppressed = 0;
                        break;
                    }
                }
                peer->Used = TRUE; peer->Handle = data[0]; peer->IfIndex = data[1];
                if (existing == NULL) {
                    peer->AcBitmap = 0xff;
                    peer->Identity = ++w->NextPeerIdentity;
                }
                peer->LastBitmap = 0;
                RtlCopyMemory(peer->Address, data + 2, 6);

                for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
                    WLFC_PACKET* p = &w->Packets[i];
                    WLFC_PEER* previous;
                    if (!p->Bound || p->Cancelled || p->State == WlfcFree || p->State == WlfcDone ||
                        p->State == WlfcCreditWait || p->IfIndex != data[1] || RtlCompareMemory(p->Destination, data + 2, 6) != 6) continue;
                    previous = WlfcPeer(w, p);
                    if (p->State == WlfcWriting || p->State == WlfcFlight) {
                        if (previous->Transit) previous->Transit--;
                        peer->Transit++;
                    } else if (p->State == WlfcSuppressed) {
                        if (previous->Suppressed) previous->Suppressed--;
                        peer->Suppressed++; peer->Blocked = TRUE;
                        peer->Generation = (UCHAR)(p->Tag >> 31);
                    }
                    p->Node = data[0] & 31u; p->Handle = data[0];
                    p->PeerIdentity = peer->Identity;
                }
                if (existing != NULL) RtlZeroMemory(existing, sizeof(*existing));
            }
            break;
        case 1: case 2:
            peer = &w->Nodes[data[0] & 31u];
            if (peer->Used && peer->Handle == data[0]) {
                peer->Closed = (BOOLEAN)(type == 2);
                peer->RequestedCredit = peer->RequestedPacket = 0;
                peer->AcBitmap = 0xff;
            }
            break;
        case 9: case 10:
            if (data[0] < WLFC_IFS) w->InterfaceClosed[data[0]] = (BOOLEAN)(type == 10);
            break;
        case 3: case 13:
            peer = &w->Nodes[data[1] & 31u];
            if (peer->Used && peer->Handle == data[1]) {
                if (type == 3) peer->RequestedCredit = data[0];
                else peer->RequestedPacket = data[0];
                peer->AcBitmap = length == 3 ? data[2] : 0xff;
            }
            break;
        default: break;
        }
        offset += length;
    }
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256WlfcKick(Ctx);
    return TRUE;
malformed:
    KeAcquireSpinLock(&w->Lock, &irql);
    w->Malformed++;
    KeReleaseSpinLock(&w->Lock, irql);
    TraceWarn(TRACE_NETADAPTER, "WLFC: malformed signal stream (%u bytes)\n", Length);
    return FALSE;
}

_Use_decl_annotations_
VOID Ap6256WlfcEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Event,
    const UCHAR* Body, ULONG Length)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG i;
    KIRQL irql;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    if (!w->Enabled || !w->Running) {
        KeReleaseSpinLock(&w->Lock, irql);
        return;
    }
    if (Event == BRCMF_E_FIFO_CREDIT_MAP && Body != NULL && Length == WLFC_FIFOS) {
        for (i = 0; i < WLFC_FIFOS; i++) {

            w->Credit[i] += (LONG)Body[i] - (LONG)w->Limit[i];
            w->Limit[i] = Body[i];
            if (w->Credit[i] > w->Limit[i]) w->Credit[i] = w->Limit[i];
        }
    } else if (Event == BRCMF_E_BCMC_CREDIT_SUPPORT) {
        w->BcmcCredit = TRUE;
    }
    KeReleaseSpinLock(&w->Lock, irql);
    if (Event == BRCMF_E_FIFO_CREDIT_MAP && Body != NULL && Length == WLFC_FIFOS)
        TraceDiag("WLFC FIFO map: BK=%u BE=%u VI=%u VO=%u BCMC=%u ATIM=%u\n",
            (ULONG)Body[0], (ULONG)Body[1], (ULONG)Body[2], (ULONG)Body[3], (ULONG)Body[4], (ULONG)Body[5]);
    Ap6256WlfcKick(Ctx);
}

_Use_decl_annotations_
BOOLEAN Ap6256WlfcEnabled(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    BOOLEAN enabled;
    KIRQL irql;
    if (w == NULL) return FALSE;
    KeAcquireSpinLock(&w->Lock, &irql);
    enabled = w->Enabled && w->Running;
    KeReleaseSpinLock(&w->Lock, irql);
    return enabled;
}

_Use_decl_annotations_
UINT16 Ap6256WlfcRoom(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    UINT16 room = 0;
    ULONG i;
    KIRQL irql;
    if (w == NULL) return 0;
    KeAcquireSpinLock(&w->Lock, &irql);
    if (w->Enabled && w->Running) for (i = 0; i < AP6256_WLFC_CAPACITY; i++)
        if (w->Packets[i].State == WlfcFree) room++;
    KeReleaseSpinLock(&w->Lock, irql);
    return room;
}

_Use_decl_annotations_
VOID Ap6256WlfcKick(PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx->Wlfc != NULL) Ap6256WorkItemEnqueue(&Ctx->Wlfc->Worker);
}

_Use_decl_annotations_
NTSTATUS Ap6256WlfcEnqueue(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Ethernet, ULONG Length, UCHAR Priority, UCHAR Exemption,
    UCHAR IfIndex, UINT16 Port, UINT16 Peer, AP6256_WLFC_CALLBACK Callback, PVOID Cookie)
{
    static const UCHAR map[8] = {1, 0, 0, 1, 2, 2, 3, 3};
    AP6256_WLFC* w = Ctx->Wlfc;
    UCHAR destination[6];
    ULONG i;
    KIRQL irql;
    NTSTATUS status = STATUS_DEVICE_BUSY;
    if (Ctx->HostTxQuiesced != 0) return STATUS_DEVICE_NOT_READY;
    if (Length < 14 || Priority > 7 || IfIndex >= WLFC_IFS ||
        (Exemption == AP6256_FIPS_BCDC_TX_EXEMPT ? !Ap6256RawDestination(Ctx, IfIndex, Ethernet, Length, destination) :
        (Length > 1600 || Ap6256FipsActive(Ctx, IfIndex) || Ap6256HostCipherPacketActive(Ctx, IfIndex))))
        return STATUS_INVALID_PARAMETER;
    if (w == NULL) return STATUS_INVALID_DEVICE_STATE;
    KeAcquireSpinLock(&w->Lock, &irql);
    if (Ctx->HostTxQuiesced != 0) status = STATUS_DEVICE_NOT_READY;
    else if (!w->Enabled || !w->Running) status = STATUS_INVALID_DEVICE_STATE;
    else if (w->Aborting && (w->AbortPort == AP6256_WLFC_ANY || w->AbortPort == Port) &&
        (w->AbortPeer == AP6256_WLFC_ANY || w->AbortPeer == Peer)) status = STATUS_CANCELLED;
    else for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &w->Packets[i];
        UINT16 slot;
        ULONG attempt, k;
        if (p->State != WlfcFree) continue;
        RtlZeroMemory(p, FIELD_OFFSET(WLFC_PACKET, Ethernet));
        RtlCopyMemory(p->Destination, Exemption == AP6256_FIPS_BCDC_TX_EXEMPT ? destination : Ethernet, 6);
        p->Fifo = (IfIndex != 0 && (p->Destination[0] & 1u)) ? 4 : map[Priority];

        slot = w->NextSlot;
        for (attempt = 0; attempt <= AP6256_WLFC_CAPACITY; attempt++) {
            BOOLEAN occupied = FALSE;
            slot = w->NextSlot++;
            if (w->NextSlot == 0) for (k = 0; k < WLFC_FIFOS; k++) w->Sequence[k]++;
            for (k = 0; k < AP6256_WLFC_CAPACITY; k++)
                if (w->Packets[k].State != WlfcFree && WLFC_STATUS_SLOT(w->Packets[k].Tag) == slot)
                    occupied = TRUE;
            if (!occupied) break;
        }
        p->Tag = ((UINT32)p->Fifo << 24) | ((UINT32)slot << 8) |
            w->Sequence[p->Fifo]++ | WLFC_TAG_HOST;
        p->Priority = Priority; p->Exemption = Exemption; p->IfIndex = IfIndex;
        p->Port = Port; p->Peer = Peer; p->Callback = Callback; p->Cookie = Cookie;
        p->Length = Length; p->Order = w->NextOrder++;
        p->Deadline = KeQueryInterruptTime() + WLFC_TIMEOUT;
        RtlCopyMemory(p->Ethernet, Ethernet, Length);
        p->State = WlfcQueued;
        w->Used++;
        status = STATUS_SUCCESS;
        break;
    }
    KeReleaseSpinLock(&w->Lock, irql);
    if (NT_SUCCESS(status)) Ap6256WlfcKick(Ctx);
    return status;
}

_Use_decl_annotations_
VOID Ap6256WlfcCancel(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer, PVOID Cookie)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG i;
    KIRQL irql;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &w->Packets[i];
        if (p->State == WlfcFree || p->State == WlfcDone || p->State == WlfcCreditWait) continue;
        if (Cookie != NULL ? p->Cookie != Cookie :
            ((Port != AP6256_WLFC_ANY && p->Port != Port) ||
             (Peer != AP6256_WLFC_ANY && p->Peer != Peer))) continue;
        p->Cancelled = TRUE;
        if (p->State != WlfcWriting) WlfcRetire(w, p, Ap6256WlfcCancelled);
    }
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256WlfcKick(Ctx);
}

_Use_decl_annotations_
VOID Ap6256WlfcCancelAndWait(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer, PVOID Cookie)
{
    AP6256_WLFC* w;
    Ap6256LockAcquire(&Ctx->WlfcLifetimeLock);
    w = Ctx->Wlfc;
    if (w != NULL) {
        Ap6256WlfcCancel(Ctx, Port, Peer, Cookie);

        Ap6256LockAcquire(&w->WorkerLock);
        Ap6256LockRelease(&w->WorkerLock);
    }
    Ap6256LockRelease(&Ctx->WlfcLifetimeLock);
}

_Use_decl_annotations_
ULONG Ap6256WlfcPending(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG i, count = 0;
    KIRQL irql;
    if (w == NULL) return 0;
    KeAcquireSpinLock(&w->Lock, &irql);
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &w->Packets[i];
        if (p->State != WlfcFree && p->State != WlfcCreditWait &&
            (Port == AP6256_WLFC_ANY || p->Port == Port) &&
            (Peer == AP6256_WLFC_ANY || p->Peer == Peer)) count++;
    }
    KeReleaseSpinLock(&w->Lock, irql);
    return count;
}

_Use_decl_annotations_
VOID Ap6256WlfcAbortBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    KIRQL irql;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    w->AbortPort = Port; w->AbortPeer = Peer; w->Aborting = TRUE;
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256WlfcCancel(Ctx, Port, Peer, NULL);
}

_Use_decl_annotations_
NTSTATUS Ap6256WlfcWaitEapol(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    AP6256_WLFC* w;
    NTSTATUS status = STATUS_SUCCESS;
    ULONGLONG deadline;
    LARGE_INTEGER interval;
    KIRQL irql;
    ULONG i, pending;
    BOOLEAN running;
    if (IfIndex >= WLFC_IFS) return STATUS_INVALID_PARAMETER;
    interval.QuadPart = -10000ll;
    deadline = KeQueryInterruptTime() + 9500000ull;
    status = Ap6256NetTxSynchronize(Ctx, deadline);
    if (!NT_SUCCESS(status)) return status;
    Ap6256LockAcquire(&Ctx->WlfcLifetimeLock);
    w = Ctx->Wlfc;
    if (w == NULL) goto done;
    for (;;) {
        pending = 0;
        KeAcquireSpinLock(&w->Lock, &irql);
        running = w->Running && w->Enabled;
        for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
            WLFC_PACKET* p = &w->Packets[i];
            if ((p->State == WlfcQueued || p->State == WlfcWriting ||
                 p->State == WlfcFlight || p->State == WlfcSuppressed) &&
                p->IfIndex == IfIndex &&
                p->Exemption != AP6256_FIPS_BCDC_TX_EXEMPT && p->Length >= 18 &&
                p->Ethernet[12] == 0x88 && p->Ethernet[13] == 0x8e)
                pending++;
        }
        KeReleaseSpinLock(&w->Lock, irql);
        if (pending == 0) break;
        if (!running || !Ctx->DatapathRunning || Ctx->HostTxQuiesced != 0) {
            status = STATUS_DEVICE_NOT_READY;
            break;
        }
        if (KeQueryInterruptTime() >= deadline) {
            status = STATUS_IO_TIMEOUT;
            TraceWarn(TRACE_NETADAPTER, "key update blocked by %u pending EAPOL frame(s) on if %u\n",
                pending, IfIndex);
            break;
        }
        Ap6256WlfcKick(Ctx);
        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
done:
    Ap6256LockRelease(&Ctx->WlfcLifetimeLock);
    return status;
}

_Use_decl_annotations_
VOID Ap6256WlfcAbortEnd(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    KIRQL irql;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    w->Aborting = FALSE;
    KeReleaseSpinLock(&w->Lock, irql);
}

static BOOLEAN WlfcNotify(AP6256_WLFC* W)
{
    ULONG i;
    BOOLEAN progress = FALSE;
    KIRQL irql;
    KeAcquireSpinLock(&W->Lock, &irql);
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &W->Packets[i];
        BOOLEAN transfer, done, transferOk, cancelled;
        AP6256_WLFC_RESULT result;
        AP6256_WLFC_CALLBACK callback;
        PVOID cookie;
        transfer = p->TransferReady && !p->TransferNotified;
        done = (BOOLEAN)(p->State == WlfcDone);
        if ((!transfer && !done) || p->State == WlfcWriting || p->Notifying) {
            continue;
        }
        p->Notifying = TRUE;
        if (transfer) p->TransferNotified = TRUE;
        callback = p->Callback; cookie = p->Cookie;
        transferOk = p->TransferOk; result = p->Result;
        cancelled = p->Cancelled;
        KeReleaseSpinLock(&W->Lock, irql);
        if (callback != NULL) {
            if (transfer) callback(cookie, Ap6256WlfcTransfer,
                transferOk ? Ap6256WlfcOk : cancelled ? Ap6256WlfcCancelled : Ap6256WlfcTransferFailed);
            if (done) callback(cookie, Ap6256WlfcSend, result);
        }
        KeAcquireSpinLock(&W->Lock, &irql);
        p->Notifying = FALSE;
        if (p->PendingStatus && (p->State == WlfcFlight || p->State == WlfcDone)) {
            p->PendingStatus = FALSE;
            WlfcStatus(W, p, p->Status);
        }
        if (done) {

            p->State = W->Running && p->Request == 1 && p->Debited ? WlfcCreditWait : WlfcFree;
            p->Callback = NULL; p->Cookie = NULL;
            W->Used--;
        }
        progress = TRUE;
    }
    KeReleaseSpinLock(&W->Lock, irql);
    return progress;
}

static UCHAR WlfcBitmap(AP6256_WLFC* W, WLFC_PEER* Peer)
{
    UCHAR bitmap = 0;
    ULONG i;
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &W->Packets[i];
        if ((p->State == WlfcQueued || p->State == WlfcSuppressed) &&
            WlfcPeer(W, p) == Peer) bitmap |= (UCHAR)(1u << p->Fifo);
    }
    return bitmap;
}

static ULONG WlfcBuild(AP6256_WLFC* W, WLFC_PACKET* P, ULONG Offset,
    UCHAR Handle, UCHAR Bitmap, BOOLEAN Tim)
{
    ULONG hdr = Ap6256TxHdrLen(W->Ctx), signals = Tim ? 12 : 8;
    ULONG length = hdr + sizeof(BCDC_DATA_HEADER) + signals + (P ? P->Length : 0);
    PUCHAR wire = W->Wire + Offset, tlv;
    PBCDC_DATA_HEADER bdc;
    PSDPCM_HW_HEADER hw = (PSDPCM_HW_HEADER)wire;
    PSDPCM_SW_HEADER sw = (PSDPCM_SW_HEADER)(wire + hdr - SDPCM_SWHDR_LEN);
    UINT32 tag = P ? P->Tag : 0;
    RtlZeroMemory(wire, hdr + sizeof(BCDC_DATA_HEADER) + signals);
    hw->FrameLength = (UINT16)length;
    hw->FrameLengthInverted = (UINT16)~length;
    sw->ChannelAndFlags = SDPCM_DATA_CHANNEL;
    sw->DataOffset = (UCHAR)hdr;
    bdc = (PBCDC_DATA_HEADER)(wire + hdr);
    bdc->Flags = (UCHAR)((BCDC_DCMD_PROTO_VERSION << BCDC_DATA_FLAG_PROTO_SHIFT) |
        (P ? P->Exemption : 0));
    bdc->Priority = P ? P->Priority : AP6256_TX_PRIORITY;
    bdc->Flags2 = P ? P->IfIndex : W->Nodes[Handle & 31u].IfIndex;
    bdc->DataOffset = (UCHAR)(signals / 4);
    tlv = (PUCHAR)(bdc + 1);
    tlv[0] = 5; tlv[1] = 4;
    RtlCopyMemory(tlv + 2, &tag, sizeof(tag));
    if (Tim) { tlv[6] = 12; tlv[7] = 2; tlv[8] = Handle; tlv[9] = Bitmap; }
    tlv[signals - 2] = tlv[signals - 1] = 255;
    if (P) RtlCopyMemory(tlv + signals, P->Ethernet, P->Length);
    return length;
}

static VOID WlfcReport(AP6256_WLFC* W, BOOLEAN Final)
{
    WLFC_FIFO_STATS stats[WLFC_FIFOS];
    LONG credit[WLFC_FIFOS];
    UCHAR limit[WLFC_FIFOS];
    ULONG queued[WLFC_FIFOS] = {0}, flight[WLFC_FIFOS] = {0}, held[WLFC_FIFOS] = {0};
    ULONG i;
    KIRQL irql;
    ULONGLONG now = KeQueryInterruptTime();
    KeAcquireSpinLock(&W->Lock, &irql);
    if (!Final && (!W->Running || now < W->NextReport)) {
        KeReleaseSpinLock(&W->Lock, irql);
        return;
    }
    W->NextReport = now + WLFC_TIMEOUT;
    RtlCopyMemory(stats, W->FifoStats, sizeof(stats));
    RtlCopyMemory(credit, W->Credit, sizeof(credit));
    RtlCopyMemory(limit, W->Limit, sizeof(limit));
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
        WLFC_PACKET* p = &W->Packets[i];
        if (p->State == WlfcQueued || p->State == WlfcSuppressed) queued[p->Fifo]++;
        if (p->State == WlfcFlight || p->State == WlfcWriting) flight[p->Fifo]++;
        if (p->State == WlfcCreditWait ||
            (p->State == WlfcDone && p->Request == 1 && p->Debited)) held[p->Fifo]++;
    }
    KeReleaseSpinLock(&W->Lock, irql);
    for (i = 0; i < WLFC_FIFOS; i++) TraceDiag(
        "WLFC FIFO %u: limit=%u available=%d queued=%u flight=%u held=%u "
        "debits=%u explicit=%u implicit=%u refunds=%u clamped=%u statuses=%u waits=%u\n",
        i, (ULONG)limit[i], credit[i], queued[i], flight[i], held[i],
        stats[i].Debits, stats[i].Explicit, stats[i].Implicit, stats[i].Refunds,
        stats[i].Clamped, stats[i].Statuses, stats[i].Waits);
}

static VOID WlfcWorker(PVOID Context)
{
    AP6256_WLFC* w = (AP6256_WLFC*)Context;
    PAP6256_DEVICE_CONTEXT ctx = w->Ctx;
    KIRQL irql;
    ULONG round;
    Ap6256LockAcquire(&w->WorkerLock);
    for (round = 0; round < AP6256_WLFC_CAPACITY; round++) {
        AP6256_TX_GLOM_FRAME frames[AP6256_TX_GLOM_MAX_FRAMES];
        WLFC_PACKET* packets[AP6256_TX_GLOM_MAX_FRAMES];
        ULONG count = 0, used = 0, sent = 0, i, n, busCredit;
        ULONG byteLimit = Ap6256DatapathTxGlomBytes(ctx);
        UCHAR flow, timHandle = 0, timBitmap = 0;
        BOOLEAN stopped, running, roomReleased, notified, tim = FALSE;
        NTSTATUS status;
        ULONGLONG now = KeQueryInterruptTime();
        if (ctx->HostTxQuiesced != 0) break;
        KeAcquireSpinLock(&w->Lock, &irql);
        for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
            WLFC_PACKET* p = &w->Packets[i];
            if (p->State != WlfcFree && p->State != WlfcDone &&
                p->State != WlfcWriting && p->State != WlfcCreditWait && now >= p->Deadline) {
                w->Timeouts++;

                WlfcRetire(w, p, Ap6256WlfcTimeout);
            }
        }
        running = w->Running && w->Enabled;
        KeReleaseSpinLock(&w->Lock, irql);
        notified = WlfcNotify(w);
        KeAcquireSpinLock(&w->Lock, &irql);
        roomReleased = w->RoomReleased; w->RoomReleased = FALSE;
        KeReleaseSpinLock(&w->Lock, irql);
        if (notified || roomReleased) Ap6256NetTxKick(ctx);
        if (!running || !ctx->DatapathRunning) break;
        KeAcquireSpinLock(&ctx->Sdio.TxStateLock, &irql);
        busCredit = (UCHAR)(ctx->Sdio.MaxTxSeq - ctx->Sdio.TxSeq);
        flow = ctx->Sdio.FlowControl; stopped = ctx->Sdio.TxFlowStopped;
        KeReleaseSpinLock(&ctx->Sdio.TxStateLock, irql);
        if (stopped || busCredit < 2 || busCredit >= 128) break;
        busCredit--;
        KeAcquireSpinLock(&w->Lock, &irql);
        if (!w->Running || !w->Enabled) { KeReleaseSpinLock(&w->Lock, irql); break; }

        if (!(flow & (1u << AP6256_TX_PRIORITY))) for (i = 0; i < WLFC_PEERS; i++) {
            WLFC_PEER* peer = &w->Nodes[i];
            UCHAR bitmap;
            if (!peer->Used || !peer->Closed) continue;
            bitmap = WlfcBitmap(w, peer);
            if (bitmap == peer->LastBitmap) continue;
            tim = TRUE; timHandle = peer->Handle; timBitmap = bitmap;
            frames[0].Offset = 0;
            frames[0].WireLength = WlfcBuild(w, NULL, 0, timHandle, bitmap, TRUE);
            count = 1;
            break;
        }
        if (!tim) for (n = 0; n < busCredit && count < AP6256_TX_GLOM_MAX_FRAMES; n++) {
            WLFC_PACKET* pick = NULL;
            WLFC_PEER* peer;
            ULONG f;
            for (f = 0; f < 5 && pick == NULL; f++) {
                UCHAR fifo = (UCHAR)((w->NextFifo + f) % 5);
                if (w->Credit[fifo] <= 0 && (fifo != 4 || w->BcmcCredit)) {
                    for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
                        WLFC_PACKET* blocked = &w->Packets[i];
                        if ((blocked->State == WlfcQueued || blocked->State == WlfcSuppressed) &&
                            blocked->Fifo == fifo) { w->FifoStats[fifo].Waits++; break; }
                    }
                    continue;
                }
                for (i = 0; i < AP6256_WLFC_CAPACITY; i++) {
                    WLFC_PACKET* p = &w->Packets[i];
                    if ((p->State != WlfcQueued && p->State != WlfcSuppressed) ||
                        p->Fifo != fifo || (flow & (1u << p->Priority)) ||
                        w->InterfaceClosed[p->IfIndex]) continue;
                    if (p->Exemption == AP6256_FIPS_BCDC_TX_EXEMPT &&
                        !Ap6256RawTxCurrent(ctx, p->IfIndex, p->Ethernet, p->Length)) {
                        WlfcRetire(w, p, Ap6256WlfcCancelled); continue;
                    }
                    if (w->Aborting && (w->AbortPort == AP6256_WLFC_ANY || w->AbortPort == p->Port) &&
                        (w->AbortPeer == AP6256_WLFC_ANY || w->AbortPeer == p->Peer)) continue;
                    peer = WlfcPeer(w, p);
                    if (peer->Blocked) {
                        if (peer->Transit != 0) continue;
                        if (peer->Suppressed == 0) peer->Blocked = FALSE;
                        else if (p->State != WlfcSuppressed) continue;
                    }
                    if (!(peer->AcBitmap & (1u << fifo)) || (peer->Closed &&
                        peer->RequestedCredit == 0 && peer->RequestedPacket == 0)) continue;
                    if (pick == NULL || (p->State == WlfcSuppressed && pick->State != WlfcSuppressed) ||
                        (p->State == pick->State && p->Order < pick->Order)) pick = p;
                }
            }
            if (pick == NULL) break;
            if (count != 0 && used + Ap6256TxHdrLen(ctx) + sizeof(BCDC_DATA_HEADER) + 8 + pick->Length >
                byteLimit) break;
            if (used + Ap6256TxHdrLen(ctx) + sizeof(BCDC_DATA_HEADER) + 8 + pick->Length + 512 >
                sizeof(w->Wire)) break;
            peer = WlfcPeer(w, pick);
            if (!pick->Bound) {
                pick->Bound = TRUE; pick->Node = 255; pick->PeerIdentity = peer->Identity;
                for (i = 0; i < WLFC_PEERS; i++) if (peer == &w->Nodes[i]) {
                    pick->Node = (UCHAR)i; pick->Handle = peer->Handle; break;
                }
            }
            pick->Request = 0;
            if (peer->Closed && peer->RequestedCredit) { peer->RequestedCredit--; pick->Request = 1; }
            else if (peer->Closed && peer->RequestedPacket) { peer->RequestedPacket--; pick->Request = 2; }
            pick->Tag = (pick->Tag & ~(WLFC_TAG_GEN | WLFC_TAG_REQUESTED)) |
                ((UINT32)peer->Generation << 31) | (pick->Request ? WLFC_TAG_REQUESTED : 0);
            pick->Debited = (BOOLEAN)(pick->Fifo != 4 || w->BcmcCredit);
            if (pick->Debited) {
                w->Credit[pick->Fifo]--;
                w->FifoStats[pick->Fifo].Debits++;
            }
            peer->Transit++;
            if (pick->State == WlfcSuppressed && peer->Suppressed) peer->Suppressed--;
            pick->State = WlfcWriting;
            frames[count].Offset = used;
            frames[count].WireLength = WlfcBuild(w, pick, used, 0, 0, FALSE);
            packets[count] = pick;
            used = (used + frames[count].WireLength + 3u) & ~3u;
            count++;
            w->NextFifo = (UCHAR)((pick->Fifo + 1) % 5);
        }
        KeReleaseSpinLock(&w->Lock, irql);
        if (count == 0) break;
        status = Ap6256DatapathSendGlom(ctx, w->Wire, sizeof(w->Wire), frames, count, &sent);
        KeAcquireSpinLock(&w->Lock, &irql);
        if (tim) {
            WLFC_PEER* peer = &w->Nodes[timHandle & 31u];
            if (sent && peer->Used && peer->Handle == timHandle) peer->LastBitmap = timBitmap;
        } else for (i = 0; i < count; i++) {
            WLFC_PACKET* p = packets[i];
            WLFC_PEER* peer = WlfcPeer(w, p);
            if (i < sent || p->PendingStatus) {
                p->State = WlfcFlight;
                if (!p->TransferReady) {
                    p->TransferReady = TRUE; p->TransferOk = TRUE;
                    InterlockedIncrement(&ctx->TxFrames);
                }
                if (p->PendingStatus) {
                    p->PendingStatus = FALSE;
                    WlfcStatus(w, p, p->Status);
                } else if (p->Cancelled) WlfcRetire(w, p, Ap6256WlfcCancelled);
            } else {
                if (peer->Transit) peer->Transit--;
                if (p->Debited) WlfcReturn(w, p->Fifo, 1, WlfcRefund);
                p->Debited = FALSE;
                if (p->Request == 1 && peer->Closed && peer->RequestedCredit < 255) peer->RequestedCredit++;
                if (p->Request == 2 && peer->Closed && peer->RequestedPacket < 255) peer->RequestedPacket++;
                p->Request = 0;
                p->State = p->Retries ? WlfcSuppressed : WlfcQueued;
                if (p->State == WlfcSuppressed) peer->Suppressed++;
                if (p->Cancelled || (!NT_SUCCESS(status) && status != STATUS_DEVICE_BUSY &&
                    status != STATUS_DEVICE_NOT_READY)) WlfcRetire(w, p, Ap6256WlfcTransferFailed);
            }
        }
        KeReleaseSpinLock(&w->Lock, irql);
        if (sent == 0) { (VOID)WlfcNotify(w); break; }
    }
    (VOID)WlfcNotify(w);

    WlfcReport(w, FALSE);
    Ap6256ModelWlfcAbortProgress(ctx);
    Ap6256LockRelease(&w->WorkerLock);
}

static VOID WlfcTimer(PVOID Context)
{
    AP6256_WLFC* w = (AP6256_WLFC*)Context;
    KIRQL irql;
    Ap6256WlfcKick(w->Ctx);
    KeAcquireSpinLock(&w->Lock, &irql);
    if (w->Running) Ap6256TimerStart(&w->Timer, 100);
    KeReleaseSpinLock(&w->Lock, irql);
}

_Use_decl_annotations_
NTSTATUS Ap6256WlfcCreate(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w;
    NTSTATUS status;
    Ap6256LockAcquire(&Ctx->WlfcLifetimeLock);
    if (Ctx->Wlfc != NULL) { Ap6256WlfcStop(Ctx); status = STATUS_SUCCESS; goto done; }
    w = (AP6256_WLFC*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*w), AP6256_POOL_TAG);
    if (w == NULL) { status = STATUS_INSUFFICIENT_RESOURCES; goto done; }
    w->Ctx = Ctx;
    KeInitializeSpinLock(&w->Lock);
    Ap6256LockInit(&w->WorkerLock);
    status = Ap6256WorkItemCreate(&w->Worker, Ctx->Fdo, WlfcWorker, w);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(w, AP6256_POOL_TAG); goto done; }
    Ap6256WorkItemMakeCritical(&w->Worker);
    status = Ap6256TimerCreate(&w->Timer, Ctx->Fdo, WlfcTimer, w);
    if (!NT_SUCCESS(status)) {
        Ap6256WorkItemDestroy(&w->Worker); ExFreePoolWithTag(w, AP6256_POOL_TAG); goto done;
    }
    Ctx->Wlfc = w;
done:
    Ap6256LockRelease(&Ctx->WlfcLifetimeLock);
    return status;
}

_Use_decl_annotations_
VOID Ap6256WlfcDrain(PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx->Wlfc == NULL) return;
    Ap6256WlfcCancel(Ctx, AP6256_WLFC_ANY, AP6256_WLFC_ANY, NULL);
    Ap6256WorkItemFlush(&Ctx->Wlfc->Worker);
    Ap6256WlfcAbortEnd(Ctx);
}

_Use_decl_annotations_
VOID Ap6256WlfcStop(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    KIRQL irql;
    BOOLEAN wasEnabled;
    ULONG i;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    wasEnabled = w->Enabled;
    w->Running = FALSE; w->Enabled = FALSE;
    w->Aborting = FALSE;
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256TimerStop(&w->Timer, TRUE);
    Ap6256WlfcDrain(Ctx);
    if (wasEnabled) WlfcReport(w, TRUE);

    KeAcquireSpinLock(&w->Lock, &irql);
    for (i = 0; i < AP6256_WLFC_CAPACITY; i++)
        if (w->Packets[i].State == WlfcCreditWait) w->Packets[i].State = WlfcFree;
    KeReleaseSpinLock(&w->Lock, irql);
    if (wasEnabled) TraceDiag("WLFC totals: statuses=%u completed=%u suppressed=%u noack=%u "
        "discard=%u credit-returns=%u stale=%u malformed=%u timeout=%u pending=%u\n",
        w->Statuses, w->Completed, w->Suppressions, w->NoAck, w->Discarded,
        w->CreditReturns, w->Stale, w->Malformed, w->Timeouts, w->Used);
}

_Use_decl_annotations_
VOID Ap6256WlfcDestroy(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w;
    Ap6256LockAcquire(&Ctx->WlfcLifetimeLock);
    w = Ctx->Wlfc;
    if (w != NULL) {
        Ap6256WlfcStop(Ctx);
        Ap6256TimerDestroy(&w->Timer);
        Ap6256WorkItemDestroy(&w->Worker);
        Ctx->Wlfc = NULL;
        ExFreePoolWithTag(w, AP6256_POOL_TAG);
    }
    Ap6256LockRelease(&Ctx->WlfcLifetimeLock);
}

static NTSTATUS WlfcRead(PAP6256_DEVICE_CONTEXT Ctx, PCSTR Name, PULONG Value)
{
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, Name, Value, sizeof(*Value), &result);

    if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(*Value))) status = STATUS_DEVICE_PROTOCOL_ERROR;
    if (!NT_SUCCESS(status)) TraceDiag("WLFC: %s GET failed 0x%08X; reply %u "
        "error %u firmware %d bytes %u\n", Name, status, result.FirmwareReply,
        result.FirmwareError, result.FirmwareStatus, result.PayloadLength);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WlfcConfigure(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG old = 0, value = 0, modeCapabilities = 0, i;
    KIRQL irql;
    NTSTATUS status;
    UCHAR eventMask[16] = {0};
    AP6256_BCDC_QUERY_RESULT eventResult = {0};
    if (w == NULL) return STATUS_INVALID_DEVICE_STATE;
    Ap6256WlfcStop(Ctx);
    KeAcquireSpinLock(&w->Lock, &irql);
    RtlZeroMemory(w->Credit, sizeof(w->Credit)); RtlZeroMemory(w->Limit, sizeof(w->Limit));
    RtlZeroMemory(w->FifoStats, sizeof(w->FifoStats));
    w->NextReport = KeQueryInterruptTime() + WLFC_TIMEOUT;
    RtlZeroMemory(w->Nodes, sizeof(w->Nodes)); RtlZeroMemory(w->Interfaces, sizeof(w->Interfaces));
    RtlZeroMemory(w->InterfaceClosed, sizeof(w->InterfaceClosed));
    for (i = 0; i < WLFC_IFS; i++) w->Interfaces[i].AcBitmap = 0xff;
    w->BcmcCredit = FALSE; w->RoomReleased = FALSE;
    KeReleaseSpinLock(&w->Lock, irql);
    status = WlfcRead(Ctx, "tlv", &old);
    if (!NT_SUCCESS(status)) {
        if (status == STATUS_NOT_SUPPORTED) {
            TraceDiag("WLFC: firmware has no tlv control; legacy TX\n");
            return STATUS_SUCCESS;
        }
        return status;
    }

    value = old & ~0x7eu;
    status = Ap6256BcdcSetIovar(Ctx, "tlv", &value, sizeof(value));
    if (NT_SUCCESS(status)) status = WlfcRead(Ctx, "tlv", &value);
    if (!NT_SUCCESS(status) || (value & 0x7eu) != 0) return STATUS_DEVICE_PROTOCOL_ERROR;

    status = WlfcRead(Ctx, "wlfc_mode", &value);
    if (NT_SUCCESS(status)) {
        modeCapabilities = value;
        value = 0;
        status = Ap6256BcdcSetIovar(Ctx, "wlfc_mode", &value, sizeof(value));
        if (NT_SUCCESS(status)) status = WlfcRead(Ctx, "wlfc_mode", &value);

        if (NT_SUCCESS(status) && value != 0 && value != modeCapabilities)
            status = STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (!NT_SUCCESS(status)) {

        value = old & ~0x7eu;
        status = Ap6256BcdcSetIovar(Ctx, "tlv", &value, sizeof(value));
        if (NT_SUCCESS(status)) status = WlfcRead(Ctx, "tlv", &value);
        if (!NT_SUCCESS(status) || (value & 8u)) return STATUS_DEVICE_PROTOCOL_ERROR;
        TraceDiag("WLFC: unverified tag mode; host signalling disabled\n");
        return STATUS_SUCCESS;
    }
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs", eventMask,
        sizeof(eventMask), &eventResult);
    if (!NT_SUCCESS(status) || !eventResult.FirmwareReply || eventResult.FirmwareError ||
        eventResult.PayloadLength < sizeof(eventMask)) return STATUS_DEVICE_PROTOCOL_ERROR;
    eventMask[74 / 8] |= (1u << (74 & 7));
    eventMask[127 / 8] |= (1u << (127 & 7));
    status = Ap6256BcdcSetIovar(Ctx, "event_msgs", eventMask, sizeof(eventMask));
    if (NT_SUCCESS(status)) status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs",
        eventMask, sizeof(eventMask), &eventResult);
    if (!NT_SUCCESS(status) || !eventResult.FirmwareReply || eventResult.FirmwareError ||
        eventResult.PayloadLength < sizeof(eventMask) ||
        !(eventMask[74 / 8] & (1u << (74 & 7))) ||
        !(eventMask[127 / 8] & (1u << (127 & 7)))) return STATUS_DEVICE_PROTOCOL_ERROR;
    KeAcquireSpinLock(&w->Lock, &irql);
    w->Enabled = TRUE; w->Running = TRUE;
    KeReleaseSpinLock(&w->Lock, irql);
    value = (old & ~0x7eu) | WLFC_FLAGS;
    status = Ap6256BcdcSetIovar(Ctx, "tlv", &value, sizeof(value));
    if (NT_SUCCESS(status)) status = WlfcRead(Ctx, "tlv", &value);
    if (!NT_SUCCESS(status) || (value & 0x7eu) != WLFC_FLAGS) {
        Ap6256WlfcStop(Ctx);
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    Ap6256TimerStart(&w->Timer, 100);
    TraceDiag("WLFC: packet tags, firmware TX status and six FIFO credits enabled (tlv=0x%X)\n", value);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcResumeRetained(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONGLONG Slept)
{
    AP6256_WLFC* w = Ctx->Wlfc;
    ULONG i;
    KIRQL irql;
    if (w == NULL) return;
    KeAcquireSpinLock(&w->Lock, &irql);
    for (i = 0; i < AP6256_WLFC_CAPACITY; ++i)
        if (w->Packets[i].State != WlfcFree) w->Packets[i].Deadline += Slept;
    KeReleaseSpinLock(&w->Lock, irql);
    Ap6256WlfcKick(Ctx);
}
