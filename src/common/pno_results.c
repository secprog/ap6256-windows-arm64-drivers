/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "pno.h"
#include "bcdc.h"
#include "netadapter.h"

#define PNO_QUEUE 16u
#define PNO_BATCH_WIRE 0xffffffffu

static UINT16 PnoU16(const UCHAR* p) { UINT16 v; RtlCopyMemory(&v,p,2); return v; }
static UINT32 PnoU32(const UCHAR* p) { UINT32 v; RtlCopyMemory(&v,p,4); return v; }
static BOOLEAN PnoAddress(const UCHAR* p)
{
    static const UCHAR zero[6] = {0};
    return (BOOLEAN)((p[0] & 1) == 0 && !RtlEqualMemory(p,zero,6));
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoDecodeResult(UINT32 Event, const UCHAR* Data, ULONG Length,
    ULONG Index, AP6256_PNO_RESULT* Result, UINT32* Count, UINT32* Status)
{
    const UCHAR* entry;
    UINT32 stride, n, state, i;
    RtlZeroMemory(Result,sizeof(*Result));
    *Count = *Status = 0;
    if (Length < 12) return STATUS_INVALID_BUFFER_SIZE;
    if (PnoU32(Data) != 1) return STATUS_REVISION_MISMATCH;
    state = PnoU32(Data+4); n = PnoU32(Data+8);
    if (Event == BRCMF_E_PFN_SWC) {

        if (n == 0 || n > 16 || state == 0 || state > n || Length != 12+18*state)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        *Count = state; *Status = n;
        if (Index >= state) return STATUS_NO_MORE_ENTRIES;
        entry = Data+12+18*Index;
        Result->Kind = 4; Result->Flags = PnoU16(entry);
        Result->Channel = PnoU16(entry+2);
        RtlCopyMemory(Result->Bssid,entry+4,6);
        Result->RssiCount = 8;
        RtlCopyMemory(Result->RssiHistory,entry+10,8);
        Result->Rssi = (CHAR)entry[17];
    } else {
        if (state > 1 || n > 32) return STATUS_DEVICE_PROTOCOL_ERROR;
        *Count = n; *Status = state;
        stride = Event == PNO_BATCH_WIRE ? 52 : 44;
        if (Event != PNO_BATCH_WIRE && Event != BRCMF_E_PFN_NET_FOUND &&
            Event != BRCMF_E_PFN_GSCAN_FULL_RESULT) return STATUS_NOT_SUPPORTED;
        if (Event != PNO_BATCH_WIRE && n == 1 && Length >= 56+128) {
            UINT32 bssLength, offset, ieLength;

            entry = Data+56;
            if (state != 1 || PnoU32(entry) != 109) return STATUS_DEVICE_PROTOCOL_ERROR;
            bssLength = PnoU32(entry+4); offset = PnoU16(entry+116);
            ieLength = PnoU32(entry+120);
            if (bssLength < 128 || bssLength != Length-56 || entry[18] > 32 ||
                offset < 128 || offset > bssLength || ieLength > bssLength-offset ||
                ieLength > sizeof(Result->Ies)) return STATUS_DEVICE_PROTOCOL_ERROR;
            for (i=0; i<ieLength;) {
                if (ieLength-i < 2 || entry[offset+i+1] > ieLength-i-2)
                    return STATUS_DEVICE_PROTOCOL_ERROR;
                i += 2+entry[offset+i+1];
            }
            if (Index != 0) return STATUS_NO_MORE_ENTRIES;
            Result->Kind = 3;
            RtlCopyMemory(Result->Bssid,entry+8,6);
            Result->SsidLength = entry[18];
            RtlCopyMemory(Result->Ssid,entry+19,Result->SsidLength);
            Result->Channel = entry[88] ? entry[88] : (PnoU16(entry+72)&255);
            Result->Rssi = (INT16)PnoU16(entry+78);
            Result->BeaconPeriod = PnoU16(entry+14); Result->Capability = PnoU16(entry+16);
            Result->Flags = entry[96]; Result->AgeMilliseconds = 1000u*PnoU16(Data+54);
            Result->IesLength = ieLength;
            RtlCopyMemory(Result->Ies,entry+offset,ieLength);

            if (Data[19] > 32 || Data[19] != Result->SsidLength ||
                !RtlEqualMemory(Data+12,Result->Bssid,6) ||
                !RtlEqualMemory(Data+20,Result->Ssid,Result->SsidLength))
                return STATUS_DEVICE_PROTOCOL_ERROR;
        } else {
            if (Event == BRCMF_E_PFN_GSCAN_FULL_RESULT || Length != 12+stride*n)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            if (Index >= n) return STATUS_NO_MORE_ENTRIES;
            entry = Data+12+stride*Index;
            Result->Kind = stride == 52 ? 2 : 1;
            RtlCopyMemory(Result->Bssid,entry,6);
            Result->Channel = entry[6]; Result->SsidLength = entry[7];
            if (Result->SsidLength > 32) return STATUS_DEVICE_PROTOCOL_ERROR;
            RtlCopyMemory(Result->Ssid,entry+8,Result->SsidLength);
            Result->Rssi = (INT16)PnoU16(entry+(stride==52 ? 42 : 40));
            Result->AgeMilliseconds = stride==52 ? PnoU32(entry+44) : 1000u*PnoU16(entry+42);
            if (stride==52) Result->Flags = PnoU16(entry+40);
        }
        if (Result->Rssi > 0 || Result->Rssi < -127) return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (!PnoAddress(Result->Bssid) || Result->Channel == 0 || Result->Channel > 255)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

typedef struct _AP6256_PNO_STATE {
    KSPIN_LOCK Lock;
    AP6256_WORKITEM Work;
    PAP6256_DEVICE_CONTEXT Ctx;
    BOOLEAN Closing, Active, Windows, Batch, D0, Indicated, HaveBss, Fetch;
    UINT32 Generation, Sequence, Dropped, Head, Count;
    AP6256_NLO_PARAMS Networks;
    AP6256_BSS Bss;
    UINT32 SwcCount, SwcTotal;
    ULONGLONG SwcTime;
    struct { UCHAR Bytes[18]; } Swc[16];
    AP6256_PNO_RESULT Queue[PNO_QUEUE];
} AP6256_PNO_STATE;

static VOID PnoPush(AP6256_PNO_STATE* s, AP6256_PNO_RESULT* r)
{
    if (s->Count == PNO_QUEUE) {
        s->Head = (s->Head+1)%PNO_QUEUE; --s->Count; ++s->Dropped;
    }
    r->Sequence = ++s->Sequence;
    s->Queue[(s->Head+s->Count)%PNO_QUEUE] = *r; ++s->Count;
}

static VOID PnoWindowsBss(AP6256_PNO_STATE* s, const AP6256_PNO_RESULT* r)
{
    ULONG i, offset;
    BOOLEAN ssidPresent=FALSE;
    if (!s->Windows || s->Indicated || s->HaveBss || r->Kind != 3) return;

    for (offset=0; offset+2<=r->IesLength; offset+=2+r->Ies[offset+1]) {
        if (r->Ies[offset]==0 && r->Ies[offset+1]==r->SsidLength && r->SsidLength!=0 &&
            RtlEqualMemory(r->Ies+offset+2,r->Ssid,r->SsidLength)) ssidPresent=TRUE;
    }
    if (!ssidPresent) return;
    for (i=0; i<s->Networks.NetworkCount; ++i) {
        const AP6256_NLO_NETWORK* net = &s->Networks.Networks[i];
        if (net->SsidLength == r->SsidLength && RtlEqualMemory(net->Ssid,r->Ssid,r->SsidLength)) {
            AP6256_BSS* b = &s->Bss;
            RtlZeroMemory(b,sizeof(*b));
            RtlCopyMemory(b->Bssid,r->Bssid,6); RtlCopyMemory(b->Ssid,r->Ssid,r->SsidLength);
            b->SsidLength=r->SsidLength; b->Channel=r->Channel; b->Rssi=r->Rssi;
            b->BeaconPeriod=r->BeaconPeriod; b->Capability=r->Capability;
            b->FromBeacon=(BOOLEAN)((r->Flags&1)!=0); b->FromCache=(BOOLEAN)((r->Flags&2)!=0);
            b->IesLength=r->IesLength; RtlCopyMemory(b->Ies,r->Ies,r->IesLength);
            s->HaveBss=TRUE; return;
        }
    }
}

static NTSTATUS PnoFetch(AP6256_PNO_STATE* s)
{
    UCHAR* wire;
    AP6256_PNO_RESULT* record;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG pass, i;
    if (!s->Active || !s->Batch || s->Closing || !s->D0) return STATUS_DEVICE_NOT_READY;
    wire=(UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,1500,AP6256_POOL_TAG);
    record=(AP6256_PNO_RESULT*)ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*record),AP6256_POOL_TAG);
    if (wire==NULL || record==NULL) status=STATUS_INSUFFICIENT_RESOURCES;
    for (pass=0; NT_SUCCESS(status) && pass<8; ++pass) {
        AP6256_BCDC_QUERY_RESULT reply={0};
        UINT32 count, state, decodedLength;
        KIRQL irql;
        RtlZeroMemory(wire,1500);
        status=Ap6256BcdcGetIovarResultIf(s->Ctx,0,"pfnlbest",wire,1500,&reply);
        if (!NT_SUCCESS(status)) break;
        if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength<12 || reply.PayloadLength>1509) {
            status=STATUS_DEVICE_PROTOCOL_ERROR; break;
        }

        count=PnoU32(wire+8);
        if (count>32 || 12+52*count>min(reply.PayloadLength,1500u)) {
            status=STATUS_DEVICE_PROTOCOL_ERROR; break;
        }
        decodedLength=12+52*count;
        status=Ap6256PnoDecodeResult(PNO_BATCH_WIRE,wire,decodedLength,0,record,&count,&state);
        if (status==STATUS_NO_MORE_ENTRIES && count==0 && state==1) { status=STATUS_SUCCESS; break; }
        if (!NT_SUCCESS(status)) break;

        for (i=1; i<count && NT_SUCCESS(status); ++i)
            status=Ap6256PnoDecodeResult(PNO_BATCH_WIRE,wire,decodedLength,i,record,&count,&state);
        if (!NT_SUCCESS(status)) break;
        KeAcquireSpinLock(&s->Lock,&irql);
        for (i=0; i<count; ++i) {
            (VOID)Ap6256PnoDecodeResult(PNO_BATCH_WIRE,wire,decodedLength,i,record,&count,&state);
            PnoPush(s,record);
        }
        KeReleaseSpinLock(&s->Lock,irql);
        if (state==1) break;
        if (count==0) { status=STATUS_DEVICE_PROTOCOL_ERROR; break; }
    }
    if (NT_SUCCESS(status) && pass==8) status=STATUS_BUFFER_OVERFLOW;
    if (wire!=NULL) ExFreePoolWithTag(wire,AP6256_POOL_TAG);
    if (record!=NULL) ExFreePoolWithTag(record,AP6256_POOL_TAG);
    return status;
}

static VOID PnoWorker(PVOID Context)
{
    AP6256_PNO_STATE* s=(AP6256_PNO_STATE*)Context;
    AP6256_BSS* b;
    BOOLEAN fetch, deliver;
    KIRQL irql;
    Ap6256LockAcquire(&s->Ctx->PnoLock);
    KeAcquireSpinLock(&s->Lock,&irql);
    fetch=(BOOLEAN)(s->Fetch && s->Active && s->D0 && !s->Closing);
    if (fetch || !s->Active || s->Closing) s->Fetch=FALSE;
    deliver=(BOOLEAN)(s->HaveBss && s->Windows && !s->Indicated && s->Active && s->D0 && !s->Closing);
    KeReleaseSpinLock(&s->Lock,irql);
    if (fetch) {
        NTSTATUS status=PnoFetch(s);
        if (!NT_SUCCESS(status)) TraceWarn(TRACE_NETADAPTER,"PNO batch retrieval 0x%08X\n",status);
    }
    b=deliver ? (AP6256_BSS*)ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*b),AP6256_POOL_TAG) : NULL;
    if (b!=NULL) {
        KeAcquireSpinLock(&s->Lock,&irql); *b=s->Bss; KeReleaseSpinLock(&s->Lock,irql);
        if (NT_SUCCESS(Ap6256NetNloDiscovery(s->Ctx,b))) {
            KeAcquireSpinLock(&s->Lock,&irql); s->Indicated=TRUE; s->HaveBss=FALSE;
            KeReleaseSpinLock(&s->Lock,irql);
        }
        ExFreePoolWithTag(b,AP6256_POOL_TAG);
    }
    Ap6256LockRelease(&s->Ctx->PnoLock);
}

static NTSTATUS PnoSetResultEvents(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Enable)
{
    UCHAR mask[36] = {1,0,18,18};
    AP6256_BCDC_QUERY_RESULT reply = {0};
    NTSTATUS status;
    ULONG length;
    status=Ap6256BcdcGetIovarResultIf(Ctx,0,"event_msgs_ext",mask,sizeof(mask),&reply);
    if (!NT_SUCCESS(status)) return status;
    if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength<22 ||
        reply.PayloadLength>sizeof(mask)+14 || mask[2]!=18 || mask[3]!=18)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    length=4u+mask[2];

    mask[0]=1; mask[1]=3;
    if (Enable) mask[4+134/8]|=0xc0;
    else mask[4+134/8]&=0x3f;
    status=Ap6256BcdcSetIovar(Ctx,"event_msgs_ext",mask,length);
    if (!NT_SUCCESS(status)) return status;
    RtlZeroMemory(mask,sizeof(mask)); mask[0]=1; mask[2]=18; mask[3]=18;
    status=Ap6256BcdcGetIovarResultIf(Ctx,0,"event_msgs_ext",mask,sizeof(mask),&reply);
    if (!NT_SUCCESS(status)) return status;
    if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength<22 ||
        reply.PayloadLength>sizeof(mask)+14 || mask[2]!=18 || mask[3]!=18 ||
        (mask[4+134/8]&0xc0)!=(Enable ? 0xc0 : 0)) return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Ap6256PnoEnableResultEvents(PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    Ctx->FirmwarePnoExtendedEvents=FALSE;
    if (!Ctx->FirmwareEnhancedPnoSupported || !Ctx->FirmwarePnoGscanSupported) return;
    status=PnoSetResultEvents(Ctx,TRUE);
    Ctx->FirmwarePnoExtendedEvents=(BOOLEAN)NT_SUCCESS(status);
    TraceInfo(TRACE_NETADAPTER,"PNO extended events readback %s (0x%08X)\n",
        Ctx->FirmwarePnoExtendedEvents ? "verified" : "unavailable",status);
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoResultsInitialize(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_PNO_STATE* s;
    NTSTATUS status;
    if (Ctx->PnoState!=NULL) return STATUS_SUCCESS;
    s=(AP6256_PNO_STATE*)ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*s),AP6256_POOL_TAG);
    if (s==NULL) return STATUS_INSUFFICIENT_RESOURCES;
    KeInitializeSpinLock(&s->Lock); s->Ctx=Ctx; s->D0=TRUE;
    status=Ap6256WorkItemCreate(&s->Work,Ctx->Fdo,PnoWorker,s);
    if (!NT_SUCCESS(status)) { ExFreePoolWithTag(s,AP6256_POOL_TAG); return status; }
    Ctx->PnoState=s; return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Ap6256PnoResultsReset(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_PNO_STATE* s=Ctx->PnoState; KIRQL irql;
    if (s==NULL) return;
    KeAcquireSpinLock(&s->Lock,&irql);
    ++s->Generation; s->Active=s->Windows=s->Batch=s->HaveBss=s->Indicated=s->Fetch=FALSE;
    s->Count=s->Head=s->Dropped=s->SwcCount=s->SwcTotal=0;
    RtlZeroMemory(&s->Networks,sizeof(s->Networks));
    KeReleaseSpinLock(&s->Lock,irql);
}

_Use_decl_annotations_
VOID Ap6256PnoResultsCommit(PAP6256_DEVICE_CONTEXT Ctx, const AP6256_NLO_PARAMS* Params, BOOLEAN Batch)
{
    AP6256_PNO_STATE* s=Ctx->PnoState; KIRQL irql;
    if (s==NULL) return;
    KeAcquireSpinLock(&s->Lock,&irql);
    s->Networks=*Params; s->Windows=Params->WindowsRequest; s->Batch=Batch;
    s->Active=TRUE;
    KeReleaseSpinLock(&s->Lock,irql);
}

_Use_decl_annotations_
VOID Ap6256PnoResultsPower(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN D0)
{
    AP6256_PNO_STATE* s=Ctx->PnoState; KIRQL irql;
    if (s==NULL) return;
    Ap6256LockAcquire(&Ctx->PnoLock);
    KeAcquireSpinLock(&s->Lock,&irql); s->D0=D0;
    if (D0 && !s->Closing) Ap6256WorkItemEnqueue(&s->Work);
    KeReleaseSpinLock(&s->Lock,irql);
    if (Ctx->FirmwarePnoExtendedEvents && !s->Closing &&
        Ctx->FirmwareState==Ap6256FwRunning && Ctx->DatapathRunning) {
        NTSTATUS status=PnoSetResultEvents(Ctx,D0);
        if (!NT_SUCCESS(status)) TraceWarn(TRACE_NETADAPTER,"PNO power event mask unverified 0x%08X\n",status);
    }
    Ap6256LockRelease(&Ctx->PnoLock);
}

_Use_decl_annotations_
BOOLEAN Ap6256PnoWindowsActive(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_PNO_STATE* s=Ctx->PnoState; KIRQL irql; BOOLEAN active=FALSE;
    if (s!=NULL) {
        KeAcquireSpinLock(&s->Lock,&irql); active=(BOOLEAN)(s->Active && s->Windows && !s->Closing);
        KeReleaseSpinLock(&s->Lock,irql);
    }
    return active;
}

_Use_decl_annotations_
VOID Ap6256PnoResultEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Event, const UCHAR* Data, ULONG Length)
{
    AP6256_PNO_STATE* s=Ctx->PnoState;
    AP6256_PNO_RESULT r;
    KIRQL irql;
    UINT32 count=0, state=0, i, j;
    NTSTATUS status=STATUS_SUCCESS;
    if (s==NULL || !Ctx->FirmwareEnhancedPnoSupported) return;
    KeAcquireSpinLock(&s->Lock,&irql);
    if (!s->Active || s->Closing) { KeReleaseSpinLock(&s->Lock,irql); return; }
    if (Event==BRCMF_E_PFN_BEST_BATCHING) {
        if (s->Batch) { s->Fetch=TRUE; Ap6256WorkItemEnqueue(&s->Work); }
        KeReleaseSpinLock(&s->Lock,irql); return;
    }
    status=Ap6256PnoDecodeResult(Event,Data,Length,0,&r,&count,&state);
    for (i=1; NT_SUCCESS(status) && i<count; ++i)
        status=Ap6256PnoDecodeResult(Event,Data,Length,i,&r,&count,&state);
    if (NT_SUCCESS(status) && Event==BRCMF_E_PFN_SWC) {
        ULONGLONG now=KeQueryInterruptTime();
        if (s->SwcTotal!=state || now-s->SwcTime>10ull*10000000ull) s->SwcCount=0;
        s->SwcTotal=state; s->SwcTime=now;
        if (count>state-s->SwcCount) status=STATUS_DEVICE_PROTOCOL_ERROR;

        for (i=0; NT_SUCCESS(status) && i<count; ++i) {
            const UCHAR* mac=Data+12+18*i+4;
            for (j=0; j<i; ++j) if (RtlEqualMemory(mac,Data+12+18*j+4,6)) status=STATUS_DEVICE_PROTOCOL_ERROR;
            for (j=0; j<s->SwcCount; ++j) if (RtlEqualMemory(mac,s->Swc[j].Bytes+4,6)) status=STATUS_DEVICE_PROTOCOL_ERROR;
        }
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(&s->Swc[s->SwcCount],Data+12,18*count); s->SwcCount+=count;
            if (s->SwcCount==state) {

                UCHAR complete[12+18*16]={0};
                UINT32 one=1;
                RtlCopyMemory(complete,&one,4); RtlCopyMemory(complete+4,&state,4); RtlCopyMemory(complete+8,&state,4);
                RtlCopyMemory(complete+12,s->Swc,18*state);
                for (i=0; i<state; ++i) {
                    (VOID)Ap6256PnoDecodeResult(Event,complete,12+18*state,i,&r,&count,&state); PnoPush(s,&r);
                }
                s->SwcCount=s->SwcTotal=0;
            }
        }
    } else if (NT_SUCCESS(status)) {
        for (i=0; i<count; ++i) {
            (VOID)Ap6256PnoDecodeResult(Event,Data,Length,i,&r,&count,&state); PnoPush(s,&r);

            if (Event==BRCMF_E_PFN_NET_FOUND) PnoWindowsBss(s,&r);
        }
        if (s->HaveBss && s->D0) Ap6256WorkItemEnqueue(&s->Work);
    }
    if (!NT_SUCCESS(status) && status!=STATUS_NO_MORE_ENTRIES) {
        ++s->Dropped; s->SwcCount=s->SwcTotal=0;
    }
    KeReleaseSpinLock(&s->Lock,irql);
    if (!NT_SUCCESS(status) && status!=STATUS_NO_MORE_ENTRIES)
        TraceWarn(TRACE_NETADAPTER,"PNO event %u rejected 0x%08X (%u bytes)\n",Event,status,Length);
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoResultControl(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Data, ULONG Length,
    AP6256_PNO_RESULT_REPLY* Reply)
{
    AP6256_PNO_REQUEST h;
    AP6256_PNO_STATE* s=Ctx->PnoState;
    KIRQL irql;
    NTSTATUS status=STATUS_SUCCESS;
    RtlZeroMemory(Reply,sizeof(*Reply)); Reply->Version=1;
    if (Length!=sizeof(h)) return STATUS_INVALID_BUFFER_SIZE;
    RtlCopyMemory(&h,Data,sizeof(h));
    if (h.Magic!=AP6256_PNO_MAGIC || h.Version!=1 ||
        (h.Operation!=AP6256_PNO_READ_RESULT && h.Operation!=AP6256_PNO_FETCH_BATCH))
        return STATUS_INVALID_PARAMETER;
    if (!Ctx->FirmwareEnhancedPnoSupported) return STATUS_NOT_SUPPORTED;
    if (s==NULL) return STATUS_DEVICE_NOT_READY;
    Ap6256LockAcquire(&Ctx->PnoLock);
    if (h.Operation==AP6256_PNO_FETCH_BATCH) status=PnoFetch(s);
    KeAcquireSpinLock(&s->Lock,&irql);

    if (h.Operation==AP6256_PNO_READ_RESULT && s->Count!=0) {
        Reply->Result=s->Queue[s->Head]; s->Head=(s->Head+1)%PNO_QUEUE; --s->Count;
    }
    Reply->Remaining=s->Count; Reply->Dropped=s->Dropped; Reply->Generation=s->Generation;
    KeReleaseSpinLock(&s->Lock,irql);
    Ap6256LockRelease(&Ctx->PnoLock); return status;
}

_Use_decl_annotations_
VOID Ap6256PnoResultsQuiesce(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_PNO_STATE* s=Ctx->PnoState; KIRQL irql;
    if (s==NULL) return;
    Ap6256LockAcquire(&Ctx->PnoLock);
    KeAcquireSpinLock(&s->Lock,&irql); s->Closing=TRUE; s->Active=FALSE;
    KeReleaseSpinLock(&s->Lock,irql);
    Ap6256LockRelease(&Ctx->PnoLock);
    Ap6256WorkItemFlush(&s->Work);
}

_Use_decl_annotations_
VOID Ap6256PnoResultsDestroy(PAP6256_DEVICE_CONTEXT Ctx)
{

    AP6256_PNO_STATE* s=Ctx->PnoState;
    if (s==NULL) return;
    Ap6256WorkItemDestroy(&s->Work); Ctx->PnoState=NULL;
    ExFreePoolWithTag(s,AP6256_POOL_TAG);
}
