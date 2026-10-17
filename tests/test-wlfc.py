# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Compile the production WLFC engine and WDI ownership bridge.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util
import hashlib
import argparse
import json
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tx', Path(__file__).with_name('test-wdi-transmit.py'))
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstdarg>
#undef _IRQL_requires_max_
#define _IRQL_requires_max_(x)
#undef _Use_decl_annotations_
#define _Use_decl_annotations_
#define TraceDiag(...) CaptureDiag(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceFrameDiag(...) CaptureDiag(__VA_ARGS__)
#define TraceFrameInfo(...) ((void)0)
#define TraceWarn(...) ((void)0)
#define TraceData(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define WDI_TX_CREDIT_INVALID 0xffff
typedef void* TAL_TXRX_HANDLE;
typedef LONG NDIS_STATUS;
#define NDIS_STATUS_SUCCESS 0
#define NDIS_STATUS_INVALID_DATA ((LONG)0xc0010015)
#define NT_ASSERT assert
#define AP6256_POOL_TAG 0
#define POOL_FLAG_NON_PAGED 0
#define ExAllocatePool2(f,n,t) calloc(1,n)
#define ExFreePoolWithTag(p,t) free(p)
#define NT_SUCCESS(s) ((LONG)(s)>=0)
typedef LONG NTSTATUS;
typedef int KIRQL;
#define MAXULONG 0xffffffffUL
typedef int AP6256_LOCK;
static int spinDepth;
static std::vector<std::string> diagnostics;
static void CaptureDiag(const char* format,...) {
    if(!strncmp(format,"WLFC FIFO ",10)&&strncmp(format,"WLFC FIFO map",13))assert(spinDepth==0);
    char text[1024];va_list args;va_start(args,format);vsnprintf(text,sizeof(text),format,args);va_end(args);
    diagnostics.emplace_back(text);
}
static ULONGLONG clockNow;
static void (*delayHook)();
#define KernelMode 0
static NTSTATUS KeDelayExecutionThread(int,BOOLEAN,LARGE_INTEGER* interval) {
    assert(spinDepth==0 && interval->QuadPart<0);
    clockNow+=(ULONGLONG)-interval->QuadPart;
    if(delayHook)delayHook();
    return 0;
}
static void KeInitializeSpinLock(KSPIN_LOCK*) {}
static void KeAcquireSpinLock(KSPIN_LOCK*,KIRQL* i) { *i=0;spinDepth++; }
static void KeReleaseSpinLock(KSPIN_LOCK*,KIRQL) { assert(spinDepth>0);spinDepth--; }
static ULONGLONG KeQueryInterruptTime() { return clockNow; }
#define RtlCompareMemory MockCompareMemory
static SIZE_T MockCompareMemory(const void* a,const void* b,SIZE_T n) { return memcmp(a,b,n)==0?n:0; }
static void Ap6256LockInit(int*) {}
static void Ap6256LockAcquire(int*) { assert(spinDepth==0); }
static void Ap6256LockRelease(int*) {}
struct Work { void (*Routine)(PVOID);PVOID Context;bool Pending; };
static bool inlineWorker,workerRunning,txFenceDeferred;
VOID Ap6256TalTxWorker(PVOID);
static void Ap6256WorkItemFlush(Work* w);
typedef Work AP6256_WORKITEM;
struct Timer { bool Armed; };
typedef Timer AP6256_TIMER;
static NTSTATUS Ap6256WorkItemCreate(Work* w,PVOID,void(*fn)(PVOID),PVOID c) { w->Routine=fn;w->Context=c;return 0; }
static void Ap6256WorkItemMakeCritical(Work*) {}
static void Ap6256WorkItemEnqueue(Work* w) {
    w->Pending=true;if((inlineWorker || (w->Routine==Ap6256TalTxWorker && !txFenceDeferred))&&!workerRunning){assert(spinDepth==0);Ap6256WorkItemFlush(w);}
}
static void Ap6256WorkItemFlush(Work* w) {
    unsigned bound=1000;assert(!workerRunning);workerRunning=true;
    while(w->Pending){assert(bound--);w->Pending=false;w->Routine(w->Context);}workerRunning=false;
}
static void Ap6256WorkItemDestroy(Work* w) { Ap6256WorkItemFlush(w); }
static NTSTATUS Ap6256TimerCreate(Timer*,PVOID,void(*)(PVOID),PVOID) { return 0; }
static void Ap6256TimerStart(Timer* t,ULONG) { t->Armed=true; }
static void Ap6256TimerStop(Timer* t,BOOLEAN) { t->Armed=false; }
static void Ap6256TimerDestroy(Timer*) {}
struct _AP6256_WLFC;
struct NB { NB* Next; std::vector<UCHAR> Bytes; };
struct NBL { NBL* Next; NB* First; void* MiniportReserved[2]; };
typedef NB* PNET_BUFFER;
typedef NBL* PNET_BUFFER_LIST;
#define NET_BUFFER_LIST_NEXT_NBL(n) ((n)->Next)
#define NET_BUFFER_LIST_FIRST_NB(n) ((n)->First)
#define NET_BUFFER_NEXT_NB(n) ((n)->Next)
#define NET_BUFFER_DATA_LENGTH(n) ((ULONG)(n)->Bytes.size())
static PUCHAR NdisGetDataBuffer(NB* n,ULONG len,PUCHAR,UCHAR,ULONG) { assert(len==n->Bytes.size());return n->Bytes.data(); }
'''
MOCK = r'''
struct Device {
    volatile LONG HostTxQuiesced=0;
    BOOLEAN TalStarted;Work TxWorker;volatile LONG TxPassScheduled,TxPassRerun,TxKeyFenceRequested,TxKeyFenceCompleted;AP6256_LOCK TxPassLock;AP6256_LOCK WlfcLifetimeLock;_AP6256_WLFC* Wlfc;void* Fdo;BOOLEAN DatapathRunning;volatile LONG TxFrames;
    KSPIN_LOCK TalStateLock;ULONG TxPassesActive;BOOLEAN TxAborting,TxAbortConfirmNeeded;
    UINT16 TxAbortPort,TxAbortPeer;
    PUCHAR TxScratch;ULONG TxScratchSize;
    struct { BOOLEAN FirmwareReady,Started;UINT32 IfIndex; } Go;
    struct { KSPIN_LOCK TxStateLock;UCHAR MaxTxSeq,TxSeq,FlowControl;BOOLEAN TxFlowStopped,TxGlom; } Sdio;
    struct {
        void (*TxTransferCompleteIndication)(PVOID,WDI_TX_FRAME_STATUS,NBL*);
        void (*TxSendCompleteIndication)(PVOID,WDI_TX_FRAME_STATUS,UINT16,WDI_FRAME_ID*,PVOID);
        void (*TxAbortConfirm)(PVOID);
    } WdiDataApi;
    PVOID WdiDataPathHandle;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static unsigned kicks,abortConfirms,transferIndications,sendIndications;
static void (*transferHook)();
static WDI_TX_FRAME_STATUS lastTransfer,lastSend;
static WDI_FRAME_ID lastId;
static ULONG fwTlv,fwMode;
static UCHAR fwEvents[16];
static bool missingEvents;
static bool modeUnsupported,badReadback,paddedReplies;
struct AP6256_BCDC_QUERY_RESULT {BOOLEAN FirmwareReply,FirmwareError;LONG FirmwareStatus;ULONG PayloadLength;};
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32,PCSTR name,PVOID buffer,ULONG length,AP6256_BCDC_QUERY_RESULT* r) {
    r->FirmwareReply=TRUE;r->PayloadLength=paddedReplies?ULONG(strlen(name)+1+length):length;
    if(!strcmp(name,"event_msgs")){
        assert(length==16);memcpy(buffer,fwEvents,length);r->PayloadLength=length;
        if(missingEvents)((PUCHAR)buffer)[15]&=0x7f;return 0;
    }
    auto v=(PULONG)buffer;
    if(!strcmp(name,"wlfc_mode")&&modeUnsupported)return STATUS_NOT_SUPPORTED;
    *v=!strcmp(name,"tlv")?fwTlv:0x1c;
    if(badReadback)*v^=8;return 0;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const void* p,ULONG length) {
    if(!strcmp(name,"event_msgs")){assert(length==16);memcpy(fwEvents,p,length);return 0;}
    if(!strcmp(name,"tlv"))memcpy(&fwTlv,p,4);else memcpy(&fwMode,p,4);return 0;
}
static void Ap6256NetTxKick(Device*) { kicks++; }
NTSTATUS Ap6256NetTxSynchronize(Device*,ULONGLONG);
static BOOLEAN Ap6256TalTxAborting(Device* d) {return d->TxAborting;}
static void Ap6256TalTxPass(Device*);
static void Ap6256TalCount(Device*,int) {}
#define Ap6256CallUpTxTransferComplete 1
#define Ap6256CallUpTxSendComplete 2
#define Ap6256CallUpTxAbortConfirm 3
#define Ap6256CallTxDescInit 4
static bool Ap6256TalTxNblAborting(Device* d,NBL* n) {
    auto m=(PWDI_FRAME_METADATA)n->MiniportReserved[0];
    return d->TxAborting && (d->TxAbortPort==0xffff||d->TxAbortPort==m->u.txMetaData.PortID) &&
        (d->TxAbortPeer==0xffff||d->TxAbortPeer==m->u.txMetaData.PeerID);
}
static void Transfer(PVOID,WDI_TX_FRAME_STATUS s,NBL*) {
    assert(spinDepth==0);transferIndications++;lastTransfer=s;if(transferHook)transferHook();
}
static void Send(PVOID,WDI_TX_FRAME_STATUS s,UINT16 n,WDI_FRAME_ID* id,PVOID) {
    assert(spinDepth==0 && n==1 && transferIndications>0);sendIndications++;lastSend=s;lastId=*id;
}
static void Confirm(PVOID) { assert(spinDepth==0);abortConfirms++; }
static void Ap6256TalCompleteOneNbl(Device*,NBL* n,WDI_TX_FRAME_STATUS s) { Transfer(NULL,s,n); }
static void Ap6256TalWlfcAbortProgress(Device*);
static ULONG Ap6256TxHdrLen(Device* d) { return d->Sdio.TxGlom?20:12; }
static ULONG Ap6256DatapathTxGlomBytes(Device*) { return 32768; }
static NTSTATUS Ap6256DatapathSendGlom(Device*,PUCHAR,ULONG,const AP6256_TX_GLOM_FRAME*,ULONG,PULONG);
'''
TEST = r'''
struct Wire { UINT32 Tag; UCHAR Fifo,Priority,IfIndex,Exemption;std::vector<UCHAR> Ethernet; };
static std::vector<Wire> writes;
static bool earlyStatus,cancelInWrite;
static NTSTATUS busResult;
static ULONG busPrefix=MAXULONG;
static unsigned timWrites;
static void (*completionHook)();
static std::vector<AP6256_WLFC_RESULT> transfers,sends;
static void Completion(PVOID,AP6256_WLFC_COMPLETION c,AP6256_WLFC_RESULT r) {
    assert(spinDepth==0);(c==Ap6256WlfcTransfer?transfers:sends).push_back(r);if(completionHook)completionHook();
}
static void Status(Device* d,UINT32 tag,unsigned flags,bool generation=false) {
    UCHAR bytes[8]={4,4};UINT32 status=(tag&0x07ffffff)|(flags<<27)|(generation?0x80000000u:0);
    memcpy(bytes+2,&status,4);bytes[6]=bytes[7]=255;assert(Ap6256WlfcSignals(d,bytes,8));
}
static void Credits(Device* d,std::initializer_list<UCHAR> values) {
    assert(values.size()==6);std::vector<UCHAR> bytes={11,6};bytes.insert(bytes.end(),values);
    assert(Ap6256WlfcSignals(d,bytes.data(),8));
}
static void Map(Device* d,std::initializer_list<UCHAR> values) {
    std::vector<UCHAR> b(values);assert(b.size()==6);Ap6256WlfcEvent(d,74,b.data(),6);
}
static NTSTATUS Ap6256DatapathSendGlom(Device* d,PUCHAR b,ULONG size,const AP6256_TX_GLOM_FRAME* f,ULONG count,PULONG sent) {
    assert(spinDepth==0);*sent=busResult?0:count;if(busPrefix<*sent)*sent=busPrefix;
    for(ULONG i=0;i<*sent;i++) {
        assert(f[i].Offset+f[i].WireLength<=size);
        auto hdr=Ap6256TxHdrLen(d);auto bd=(BCDC_DATA_HEADER*)(b+f[i].Offset+hdr);
        assert(bd->DataOffset==2||bd->DataOffset==3);
        auto tlv=(UCHAR*)(bd+1);assert(tlv[0]==5&&tlv[1]==4);
        UINT32 tag;memcpy(&tag,tlv+2,4);
        if(bd->DataOffset==3) {assert(tag==0 && tlv[6]==12 && tlv[7]==2);timWrites++;continue;}
        assert(tlv[6]==255&&tlv[7]==255);
        Wire w={tag,(UCHAR)((tag>>24)&7),bd->Priority,bd->Flags2,(UCHAR)(bd->Flags&0x0f),{}};
        ULONG len=f[i].WireLength-hdr-4-8;
        w.Ethernet.assign(tlv+8,tlv+8+len);writes.push_back(w);
        if(earlyStatus)Status(d,tag,0);
        if(cancelInWrite)Ap6256WlfcCancel(d,0xffff,0xffff,NULL);
    }
    d->Sdio.TxSeq=(UCHAR)(d->Sdio.TxSeq+*sent);
    return busResult;
}
static void Pump(Device* d) { Ap6256WlfcKick(d);Ap6256WorkItemFlush(&d->Wlfc->Worker); }
static void Init(Device& d) {
    memset(&d,0,sizeof(d));fwTlv=0;fwMode=8;modeUnsupported=badReadback=missingEvents=false;
    paddedReplies=true;
    memset(fwEvents,0,16);fwEvents[0]=1;fwEvents[7]=8;
    earlyStatus=cancelInWrite=inlineWorker=workerRunning=false;busResult=0;busPrefix=MAXULONG;clockNow=0;
    writes.clear();transfers.clear();sends.clear();diagnostics.clear();timWrites=0;completionHook=NULL;delayHook=NULL;
    transferIndications=sendIndications=abortConfirms=0;transferHook=NULL;
    d.TxWorker={Ap6256TalTxWorker,&d,false};txFenceDeferred=false;
    d.TalStarted=TRUE;d.DatapathRunning=TRUE;d.Sdio.MaxTxSeq=120;d.TxScratchSize=40960;
    d.TxScratch=(PUCHAR)calloc(1,d.TxScratchSize);d.WdiDataPathHandle=&d;
    d.WdiDataApi={Transfer,Send,Confirm};
    assert(NT_SUCCESS(Ap6256WlfcCreate(&d)));assert(NT_SUCCESS(Ap6256WlfcConfigure(&d)));
    assert(fwMode==0 && (fwTlv&0x7e)==14 && Ap6256WlfcEnabled(&d));
    assert(fwEvents[0]==1&&fwEvents[7]==8&&fwEvents[9]==4&&fwEvents[15]==128);
}
static void End(Device& d) { Ap6256WlfcDestroy(&d);free(d.TxScratch);assert(spinDepth==0); }
static void Queue(Device& d,UCHAR priority=3,UCHAR ifIndex=0,UINT16 port=0,UINT16 peer=0) {
    UCHAR e[60]={2,3,4,5,6,7,8,9,10,11,12,13,8,0};
    assert(NT_SUCCESS(Ap6256WlfcEnqueue(&d,e,60,priority,BCDC_DATA_EXEMPT_ALWAYS,ifIndex,port,peer,Completion,NULL)));
}
static void RequestedPeer(Device& d) {
    UCHAR add[]={6,8,0x21,1,2,3,4,5,6,7},close[]={2,1,0x21},request[]={3,2,1,0x21};
    assert(Ap6256WlfcSignals(&d,add,sizeof(add)));
    assert(Ap6256WlfcSignals(&d,close,sizeof(close)));
    assert(Ap6256WlfcSignals(&d,request,sizeof(request)));
}
static void CancelledCreditTest() {
    Device d;Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});
    Queue(d,3,1,2,1);Pump(&d);assert(writes.size()==1);
    UINT32 tag=writes[0].Tag;assert(d.Wlfc->Credit[1]==0);
    Ap6256WlfcCancel(&d,2,1,NULL);Pump(&d);
    assert(sends.size()==1&&sends[0]==Ap6256WlfcCancelled);
    assert(Ap6256WlfcPending(&d,2,1)==0&&d.Wlfc->Used==0);
    assert(d.Wlfc->Credit[1]==0);
    auto kickBefore=kicks;Status(&d,tag,0);Pump(&d);
    assert(kicks>kickBefore);
    assert(d.Wlfc->Credit[1]==1&&d.Wlfc->Nodes[1].RequestedCredit==1);
    assert(sends.size()==1&&transfers.size()==1);
    Queue(d,3,1,2,1);Pump(&d);assert(writes.size()==2);
    Status(&d,writes.back().Tag,0);Pump(&d);End(d);
}
static Device* lateDevice;
static void ReturnWhileNotifying() {
    completionHook=NULL;Status(lateDevice,writes.back().Tag,0);
}
static void CreditLifecycleTests() {
    Device d;UINT32 tag;

    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);
    tag=writes.back().Tag;Ap6256WlfcCancel(&d,2,1,NULL);Status(&d,tag,0);Pump(&d);
    assert(d.Wlfc->Credit[1]==1&&sends.size()==1&&d.Wlfc->Used==0);
    Status(&d,tag,0);Pump(&d);assert(d.Wlfc->Credit[1]==1&&sends.size()==1);End(d);



    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);
    Ap6256WlfcCancel(&d,2,1,NULL);lateDevice=&d;completionHook=ReturnWhileNotifying;Pump(&d);
    assert(d.Wlfc->Credit[1]==1&&sends.size()==1&&d.Wlfc->Used==0);End(d);


    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});earlyStatus=cancelInWrite=true;
    Queue(d,3,1,2,1);Pump(&d);assert(d.Wlfc->Credit[1]==1&&sends.size()==1);
    assert(sends[0]==Ap6256WlfcCancelled);End(d);
    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});cancelInWrite=true;
    Queue(d,3,1,2,1);Pump(&d);tag=writes.back().Tag;
    assert(d.Wlfc->Credit[1]==0&&Ap6256WlfcRoom(&d)==AP6256_WLFC_CAPACITY-1);
    Status(&d,tag,2);Pump(&d);assert(d.Wlfc->Credit[1]==1&&sends.size()==1&&writes.size()==1);End(d);



    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);
    tag=writes.back().Tag;clockNow=WLFC_TIMEOUT+1;Pump(&d);
    assert(sends.size()==1&&sends[0]==Ap6256WlfcTimeout&&d.Wlfc->Credit[1]==0);
    assert(d.Wlfc->Used==0&&Ap6256WlfcPending(&d,2,1)==0);
    clockNow+=WLFC_TIMEOUT;Pump(&d);assert(sends.size()==1&&d.Wlfc->Credit[1]==0);
    Status(&d,tag,4);Pump(&d);assert(d.Wlfc->Credit[1]==1&&sends.size()==1);End(d);



    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);tag=writes.back().Tag;
    UCHAR del[]={7,8,0x21,1,2,3,4,5,6,7},add[]={6,8,0x21,1,2,3,4,5,6,7},close[]={2,1,0x21};
    assert(Ap6256WlfcSignals(&d,del,sizeof(del)));Pump(&d);
    assert(Ap6256WlfcSignals(&d,add,sizeof(add))&&Ap6256WlfcSignals(&d,close,sizeof(close)));
    Status(&d,tag,0);Pump(&d);assert(d.Wlfc->Credit[1]==1&&d.Wlfc->Nodes[1].RequestedCredit==0);
    assert(sends.size()==1);End(d);




    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);tag=writes.back().Tag;
    Ap6256WlfcCancel(&d,2,1,NULL);Pump(&d);d.Wlfc->NextSlot=WLFC_STATUS_SLOT(tag);
    Queue(d);assert(WLFC_STATUS_SLOT(d.Wlfc->Packets[1].Tag)!=WLFC_STATUS_SLOT(tag));
    Ap6256WlfcStop(&d);assert(d.Wlfc->Used==0);
    for(auto& p:d.Wlfc->Packets)assert(p.State==WlfcFree);
    auto before=d.Wlfc->Credit[1];Credits(&d,{0,1,0,0,0,0});Map(&d,{0,100,0,0,0,0});
    assert(d.Wlfc->Credit[1]==before&&d.Wlfc->Limit[1]==1);
    assert(NT_SUCCESS(Ap6256WlfcConfigure(&d))&&d.Wlfc->Credit[1]==0);
    Status(&d,tag,0);assert(d.Wlfc->Credit[1]==0);End(d);


    Init(d);RequestedPeer(d);UCHAR packet[]={13,3,1,0x21,0xff},clear[]={3,2,0,0x21};
    assert(Ap6256WlfcSignals(&d,clear,sizeof(clear))&&Ap6256WlfcSignals(&d,packet,sizeof(packet)));
    Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);tag=writes.back().Tag;
    Ap6256WlfcCancel(&d,2,1,NULL);Pump(&d);Status(&d,tag,0);
    assert(d.Wlfc->Credit[1]==0);Credits(&d,{0,1,0,0,0,0});assert(d.Wlfc->Credit[1]==1);End(d);



    Init(d);RequestedPeer(d);Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);busResult=STATUS_DEVICE_BUSY;Pump(&d);
    assert(d.Wlfc->Credit[1]==1&&d.Wlfc->Nodes[1].RequestedCredit==1&&writes.empty());
    Ap6256WlfcCancel(&d,2,1,NULL);Pump(&d);assert(Ap6256WlfcRoom(&d)==AP6256_WLFC_CAPACITY);End(d);
}
static void DetachedCapacityTest() {
    Device d;Init(d);RequestedPeer(d);UCHAR grant[]={3,2,128,0x21};
    assert(Ap6256WlfcSignals(&d,grant,sizeof(grant)));Map(&d,{0,128,0,0,0,7});
    for(unsigned i=0;i<AP6256_WLFC_CAPACITY;i++)Queue(d,3,1,2,1);
    unsigned bound=8;while(writes.size()!=AP6256_WLFC_CAPACITY) {
        assert(bound--);d.Sdio.MaxTxSeq=(UCHAR)(d.Sdio.TxSeq+120);Pump(&d);
    }
    Ap6256WlfcDrain(&d);assert(d.Wlfc->Used==0&&sends.size()==128&&Ap6256WlfcRoom(&d)==0);
    UCHAR e[60]={2};assert(Ap6256WlfcEnqueue(&d,e,60,3,0,0,0,0,NULL,NULL)==STATUS_DEVICE_BUSY);
    UCHAR compressed[7]={19,5};UINT32 status=writes[0].Tag&0x07ffffff;
    memcpy(compressed+2,&status,4);compressed[6]=128;
    assert(Ap6256WlfcSignals(&d,compressed,sizeof(compressed)));Pump(&d);
    assert(d.Wlfc->Credit[1]==128&&Ap6256WlfcRoom(&d)==AP6256_WLFC_CAPACITY);
    assert(d.Wlfc->Nodes[1].RequestedCredit==128&&sends.size()==128);
    assert(Ap6256WlfcSignals(&d,compressed,sizeof(compressed)));assert(d.Wlfc->Credit[1]==128);


    Credits(&d,{0,0,0,0,0,9});assert(d.Wlfc->Credit[5]==7);
    assert(d.Wlfc->FifoStats[5].Explicit==9&&d.Wlfc->FifoStats[5].Clamped==9);
    End(d);
}
static void SustainedCreditTests() {
    Device d;Init(d);Map(&d,{3,5,2,4,3,0});Ap6256WlfcEvent(&d,127,NULL,0);
    const UCHAR priority[4]={1,3,4,7};UCHAR multicast[60]={1};
    unsigned cursor=0;UINT32 epochTag=0;bool wrapped=false;
    for(unsigned round=0;round<2000;round++) {
        for(unsigned j=0;j<8;j++) {
            for(auto p:priority)Queue(d,p);
            assert(NT_SUCCESS(Ap6256WlfcEnqueue(&d,multicast,60,3,0,1,2,1,Completion,NULL)));
        }
        if(round%17==0) {busResult=STATUS_DEVICE_BUSY;d.Sdio.MaxTxSeq=(UCHAR)(d.Sdio.TxSeq+120);Pump(&d);busResult=0;}
        unsigned bound=20;
        while(d.Wlfc->Used) {
            assert(bound--);d.Sdio.MaxTxSeq=(UCHAR)(d.Sdio.TxSeq+120);Pump(&d);
            if(!d.Wlfc->Used)break;
            unsigned end=(unsigned)writes.size();assert(end>cursor);UCHAR returned[6]={};
            for(unsigned j=cursor;j<end;j++)returned[writes[j].Fifo]++;
            if(round&1)Credits(&d,{returned[0],returned[1],returned[2],returned[3],returned[4],0});
            for(unsigned j=end;j>cursor;j--)Status(&d,writes[j-1].Tag,0);
            if(!(round&1))Credits(&d,{returned[0],returned[1],returned[2],returned[3],returned[4],0});
            for(unsigned j=cursor;j<end;j++) {
                if(WLFC_STATUS_SLOT(writes[j].Tag)==0) {
                    if(!epochTag)epochTag=writes[j].Tag;
                    else {assert((UCHAR)epochTag!=(UCHAR)writes[j].Tag);Status(&d,epochTag,0);wrapped=true;}
                }
            }
            cursor=end;
        }
        for(unsigned f=0;f<5;f++)assert(d.Wlfc->Credit[f]==d.Wlfc->Limit[f]);
        assert(Ap6256WlfcRoom(&d)==AP6256_WLFC_CAPACITY);
        clockNow+=300000;
    }
    assert(cursor==80000&&transfers.size()==80000&&sends.size()==80000&&wrapped);
    for(unsigned f=0;f<5;f++) {
        auto& s=d.Wlfc->FifoStats[f];assert(s.Statuses==16000&&s.Explicit==16000);
        assert(s.Implicit==0&&s.Clamped==0&&s.Debits==s.Explicit+s.Refunds&&s.Waits>0);
    }
    unsigned reports=0;for(auto& line:diagnostics)if(line.find("WLFC FIFO 1:")==0)reports++;
    assert(reports>=5&&reports<=6);
    End(d);
    puts("WLFC sustained: 80000 packets, five FIFOs, credit/status reordering, busy refunds and tag wrap passed");
}
static void CoreTests() {
    Device compact;Init(compact);paddedReplies=false;
    assert(NT_SUCCESS(Ap6256WlfcConfigure(&compact))&&Ap6256WlfcEnabled(&compact));End(compact);
    Device d;Init(d);Map(&d,{1,1,1,1,1,0});

    Queue(d,1);Queue(d,3);Queue(d,4);Queue(d,7);Pump(&d);
    assert(writes.size()==4&&transfers.size()==4&&sends.empty());
    bool seen[4]={};for(auto& w:writes){assert(w.Fifo<4);seen[w.Fifo]=true;assert(w.Exemption==BCDC_DATA_EXEMPT_ALWAYS);Status(&d,w.Tag,w.Fifo==2?4:0);}
    Pump(&d);for(auto b:seen)assert(b);assert(sends.size()==4);
    assert(d.Wlfc->Credit[0]==0&&d.Wlfc->Credit[1]==0&&d.Wlfc->Credit[2]==0&&d.Wlfc->Credit[3]==0);
    Queue(d,3);Pump(&d);assert(writes.size()==4);
    Credits(&d,{0,1,0,0,0,0});Pump(&d);assert(writes.size()==5&&writes.back().Fifo==1);

    UCHAR malformed[]={11,6,0,1,0,0,0,0,4,4,0};
    assert(!Ap6256WlfcSignals(&d,malformed,sizeof(malformed)));assert(d.Wlfc->Credit[1]==0);

    auto tag=writes.back().Tag;Status(&d,tag,4);Status(&d,tag,4);Pump(&d);
    assert(sends.back()==Ap6256WlfcNoAck&&d.Wlfc->Used==0);
    End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});earlyStatus=true;Queue(d);Pump(&d);
    assert(transfers.size()==1&&sends.size()==1&&sends[0]==Ap6256WlfcOk&&d.Wlfc->Used==0);
    End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);Pump(&d);tag=writes.back().Tag;
    Status(&d,tag,2,true);Pump(&d);assert(sends.empty()&&writes.size()==1);
    Credits(&d,{0,1,0,0,0,0});Pump(&d);
    assert(writes.size()==2&&(writes.back().Tag&0x80000000u)&&transfers.size()==1);
    Status(&d,writes.back().Tag,0,true);Pump(&d);assert(sends.size()==1&&sends[0]==Ap6256WlfcOk);
    End(d);

    Init(d);Map(&d,{0,3,0,0,0,0});Queue(d);Queue(d);Queue(d);Pump(&d);
    UCHAR compressed[8]={19,5};UINT32 s=writes[0].Tag&0x07ffffff;
    memcpy(compressed+2,&s,4);compressed[6]=3;compressed[7]=255;
    assert(Ap6256WlfcSignals(&d,compressed,8));Pump(&d);assert(sends.size()==3&&d.Wlfc->Used==0);
    End(d);

    Init(d);Map(&d,{0,2,0,0,0,0});Queue(d);Queue(d);busPrefix=1;Pump(&d);
    assert(writes.size()==2&&transfers.size()==2);End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);busResult=STATUS_DEVICE_BUSY;Pump(&d);
    assert(transfers.empty()&&d.Wlfc->Credit[1]==1);busResult=STATUS_CRC_ERROR;Pump(&d);
    assert(transfers.size()==1&&transfers[0]==Ap6256WlfcTransferFailed&&sends.size()==1&&d.Wlfc->Used==0);End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);cancelInWrite=true;Pump(&d);
    assert(transfers.size()==1&&sends.size()==1&&sends[0]==Ap6256WlfcCancelled);End(d);

    Init(d);Queue(d,3,0,0,0);Queue(d,3,1,2,1);Ap6256WlfcCancel(&d,2,1,NULL);Pump(&d);
    assert(sends.size()==1&&d.Wlfc->Used==1);clockNow=WLFC_TIMEOUT+1;Pump(&d);
    assert(sends.size()==2&&sends.back()==Ap6256WlfcTimeout&&d.Wlfc->Used==0);End(d);

    Init(d);Map(&d,{0,10,0,0,0,0});for(int i=0;i<10;i++)Queue(d);Pump(&d);
    Map(&d,{0,5,0,0,0,0});assert(d.Wlfc->Credit[1]==-5);
    Credits(&d,{0,5,0,0,0,0});assert(d.Wlfc->Credit[1]==0);End(d);

    Init(d);UCHAR add[]={6,8,0x21,1,2,3,4,5,6,7};UCHAR close[]={2,1,0x21};
    assert(Ap6256WlfcSignals(&d,add,10)&&Ap6256WlfcSignals(&d,close,3));
    Map(&d,{0,1,0,0,0,0});Queue(d,3,1,2,1);Pump(&d);assert(writes.empty()&&timWrites==1);
    UCHAR request[]={3,2,1,0x21};assert(Ap6256WlfcSignals(&d,request,4));Pump(&d);
    assert(writes.size()==1&&(writes[0].Tag&0x10000000));Status(&d,writes[0].Tag,0);Pump(&d);
    assert(d.Wlfc->Credit[1]==1&&sends.size()==1);End(d);

    Init(d);modeUnsupported=true;assert(NT_SUCCESS(Ap6256WlfcConfigure(&d))&&!Ap6256WlfcEnabled(&d)&&!(fwTlv&8));End(d);
    Init(d);badReadback=true;assert(!NT_SUCCESS(Ap6256WlfcConfigure(&d))&&!Ap6256WlfcEnabled(&d));End(d);
    Init(d);missingEvents=true;assert(!NT_SUCCESS(Ap6256WlfcConfigure(&d))&&!Ap6256WlfcEnabled(&d));End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});UCHAR ifClose[]={10,1,0},ifOpen[]={9,1,0};
    assert(Ap6256WlfcSignals(&d,ifClose,3));Queue(d);Pump(&d);assert(writes.empty());
    assert(Ap6256WlfcSignals(&d,ifOpen,3));Pump(&d);assert(writes.size()==1);End(d);

    Init(d);for(unsigned i=0;i<AP6256_WLFC_CAPACITY;i++)Queue(d);
    assert(Ap6256WlfcRoom(&d)==0);UCHAR e[60]={2};
    assert(Ap6256WlfcEnqueue(&d,e,60,3,0,0,0,0,NULL,NULL)==STATUS_DEVICE_BUSY);
    Ap6256WlfcDrain(&d);assert(sends.size()==AP6256_WLFC_CAPACITY&&d.Wlfc->Used==0);End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);d.Sdio.MaxTxSeq=1;Pump(&d);assert(writes.empty());
    d.Sdio.MaxTxSeq=10;d.Sdio.FlowControl=1<<3;Pump(&d);assert(writes.empty());
    d.Sdio.FlowControl=0;Pump(&d);assert(writes.size()==1);End(d);

    Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);Pump(&d);tag=writes[0].Tag;
    UCHAR descriptor[]={6,8,0x21,0,2,3,4,5,6,7};
    assert(Ap6256WlfcSignals(&d,descriptor,10));assert(d.Wlfc->Nodes[1].Transit==1&&d.Wlfc->Interfaces[0].Transit==0);
    assert(Ap6256WlfcSignals(&d,descriptor,10));assert(d.Wlfc->Nodes[1].Transit==1);
    descriptor[2]=0x22;assert(Ap6256WlfcSignals(&d,descriptor,10));
    assert(!d.Wlfc->Nodes[1].Used&&d.Wlfc->Nodes[2].Transit==1);
    descriptor[0]=7;descriptor[2]=0x42;assert(Ap6256WlfcSignals(&d,descriptor,10));
    assert(d.Wlfc->Nodes[2].Used);
    Status(&d,tag,0);Pump(&d);assert(d.Wlfc->Nodes[2].Transit==0&&sends.size()==1);End(d);

    Init(d);UCHAR multicast[60]={1};
    assert(NT_SUCCESS(Ap6256WlfcEnqueue(&d,multicast,60,3,0,1,2,1,Completion,NULL)));
    Pump(&d);assert(writes.size()==1&&writes[0].Fifo==4&&d.Wlfc->Credit[4]==0);
    Status(&d,writes[0].Tag,0);Pump(&d);Ap6256WlfcEvent(&d,127,NULL,0);
    assert(NT_SUCCESS(Ap6256WlfcEnqueue(&d,multicast,60,3,0,1,2,1,Completion,NULL)));
    Pump(&d);assert(writes.size()==1);Map(&d,{0,0,0,0,1,0});Pump(&d);
    assert(writes.size()==2&&d.Wlfc->Credit[4]==0);End(d);

    Init(d);Queue(d);Ap6256WlfcAbortBegin(&d,0,0);
    assert(Ap6256WlfcEnqueue(&d,e,60,3,0,0,0,0,NULL,NULL)==STATUS_CANCELLED);
    assert(NT_SUCCESS(Ap6256WlfcEnqueue(&d,e,60,3,0,1,2,1,NULL,NULL)));
    Pump(&d);assert(d.Wlfc->Used==1);Ap6256WlfcAbortEnd(&d);Queue(d);End(d);

    Init(d);Queue(d);auto oldTag=d.Wlfc->Packets[0].Tag;d.Wlfc->NextSlot=0;
    Queue(d);assert(WLFC_STATUS_SLOT(d.Wlfc->Packets[1].Tag)!=WLFC_STATUS_SLOT(oldTag));
    d.Wlfc->NextSlot=0xffff;Queue(d);Queue(d);
    assert(WLFC_STATUS_SLOT(d.Wlfc->Packets[2].Tag)==0xffff);
    assert(WLFC_STATUS_SLOT(d.Wlfc->Packets[3].Tag)!=0&&WLFC_STATUS_SLOT(d.Wlfc->Packets[3].Tag)!=1);
    End(d);
}
static NB MakeNb() {
    NB n={};n.Bytes.resize(24+8+46);n.Bytes[0]=8;n.Bytes[1]=1;
    UCHAR da[6]={2,3,4,5,6,7};memcpy(n.Bytes.data()+16,da,6);
    UCHAR snap[8]={0xaa,0xaa,3,0,0,0,8,0};memcpy(n.Bytes.data()+24,snap,8);return n;
}
static Device* hookDevice;
static void StatusInsideTransfer() {
    for(auto& w:writes)Status(hookDevice,w.Tag,0);
    transferHook=NULL;
}
static void WdiTests() {
    Device d;Init(d);Map(&d,{0,2,0,0,0,0});NB a=MakeNb(),b=MakeNb();a.Next=&b;
    WDI_FRAME_METADATA meta={};meta.FrameID=123;meta.u.txMetaData.bTxCompleteRequired=TRUE;
    NBL n={};n.First=&a;n.MiniportReserved[0]=&meta;
    Ap6256TalWlfcQueue(&d,&n);assert(transferIndications==0);Pump(&d);
    assert(transferIndications==1&&lastTransfer==WDI_TxFrameStatus_Ok&&sendIndications==0);
    Status(&d,writes[0].Tag,0);Pump(&d);assert(sendIndications==0);
    Status(&d,writes[1].Tag,4);Pump(&d);assert(sendIndications==1&&lastSend==WDI_TxFrameStatus_NoAck&&lastId==123);
    End(d);
    Init(d);Map(&d,{0,2,0,0,0,0});earlyStatus=true;Ap6256TalWlfcQueue(&d,&n);Pump(&d);
    assert(transferIndications==1&&sendIndications==1&&lastSend==WDI_TxFrameStatus_Ok);End(d);

    Init(d);Map(&d,{0,2,0,0,0,0});earlyStatus=inlineWorker=true;
    Ap6256TalWlfcQueue(&d,&n);assert(transferIndications==1&&sendIndications==1&&d.Wlfc->Used==0);
    inlineWorker=false;End(d);

    Init(d);Map(&d,{0,2,0,0,0,0});hookDevice=&d;transferHook=StatusInsideTransfer;
    Ap6256TalWlfcQueue(&d,&n);Pump(&d);
    assert(transferIndications==1&&sendIndications==1&&d.Wlfc->Used==0);End(d);
    Init(d);Ap6256TalWlfcQueue(&d,&n);d.TxAbortConfirmNeeded=TRUE;d.TxAborting=TRUE;d.TxAbortPort=0;d.TxAbortPeer=0;
    Ap6256WlfcCancel(&d,0,0,NULL);assert(abortConfirms==0);Pump(&d);
    assert(transferIndications==1&&lastTransfer==WDI_TxFrameStatus_TransferCancelled&&sendIndications==0&&abortConfirms==1);
    End(d);

    Init(d);Map(&d,{0,2,0,0,0,0});b.Bytes.clear();Ap6256TalWlfcQueue(&d,&n);Pump(&d);
    assert(transferIndications==1&&lastTransfer==WDI_TxFrameStatus_TransferFailed&&sendIndications==0);End(d);

    Init(d);std::vector<NB> buffers(AP6256_WLFC_CAPACITY+1);NDIS_STATUS descriptorStatus;
    for(unsigned i=0;i<AP6256_WLFC_CAPACITY;i++)buffers[i].Next=&buffers[i+1];
    n.First=buffers.data();Ap6256TalTxTargetDescInit(&d,&n,&descriptorStatus);
    assert(descriptorStatus==NDIS_STATUS_INVALID_DATA&&meta.u.txMetaData.TxCost==0);
    buffers[AP6256_WLFC_CAPACITY-1].Next=NULL;Ap6256TalTxTargetDescInit(&d,&n,&descriptorStatus);
    assert(descriptorStatus==NDIS_STATUS_SUCCESS&&meta.u.txMetaData.TxCost==AP6256_WLFC_CAPACITY);End(d);
}
static void RetainedSleepTest() {
    Device d;Init(d);Map(&d,{0,1,0,0,0,0});Queue(d);Pump(&d);
    assert(writes.size()==1&&sends.empty()&&d.Wlfc->Used==1);
    ULONGLONG before=0;ULONG slot=0;
    for(;slot<AP6256_WLFC_CAPACITY;slot++)if(d.Wlfc->Packets[slot].State!=WlfcFree){before=d.Wlfc->Packets[slot].Deadline;break;}
    assert(slot<AP6256_WLFC_CAPACITY);d.HostTxQuiesced=1;
    UCHAR frame[60]={};
    assert(Ap6256WlfcEnqueue(&d,frame,60,3,BCDC_DATA_EXEMPT_ALWAYS,0,0,0,Completion,NULL)==STATUS_DEVICE_NOT_READY);
    ULONGLONG asleep=50000000;clockNow+=asleep;Pump(&d);
    assert(sends.empty()&&writes.size()==1&&d.Wlfc->Used==1);
    Ap6256WlfcResumeRetained(&d,asleep);assert(d.Wlfc->Packets[slot].Deadline==before+asleep);
    d.HostTxQuiesced=0;Pump(&d);assert(sends.empty());
    Status(&d,writes[0].Tag,0);Pump(&d);assert(sends.size()==1&&sends[0]==Ap6256WlfcOk);End(d);
    puts("PASS: retained sleep preserves owners and deadlines; new host traffic stays quiesced");
}
static Device* eapolDevice;
static unsigned eapolTicks;
static bool eapolReplacement;
static void (*synchronizeHook)(Device*);
static void Ap6256TalTxPass(Device* d) {if(synchronizeHook)synchronizeHook(d);}
static void SynchronizeEapol(Device* d) {
    assert(spinDepth==0 && d->TxPassesActive==1);
    UCHAR f[113]={};f[12]=0x88;f[13]=0x8e;
    assert(Ap6256WlfcEnqueue(d,f,sizeof(f),3,BCDC_DATA_EXEMPT_ALWAYS,7,2,1,Completion,NULL)==0);
    synchronizeHook=NULL;
}
static void EapolProgress() {
    ++eapolTicks;
    Pump(eapolDevice);
    if(eapolTicks==3 && eapolReplacement) {
        UCHAR f[113]={};f[12]=0x88;f[13]=0x8e;
        assert(Ap6256WlfcEnqueue(eapolDevice,f,sizeof(f),3,BCDC_DATA_EXEMPT_ALWAYS,7,2,1,Completion,NULL)==0);
        Status(eapolDevice,writes[0].Tag,0);
    }
    if(eapolTicks==5)for(auto& p:eapolDevice->Wlfc->Packets)
        if(p.State==WlfcFlight && p.IfIndex==7)Status(eapolDevice,p.Tag,0);
}
static void EapolBarrierTests(int argc) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    if(argc==1) {
        Device d;Init(d);Map(&d,{9,54,19,9,9,0});
        eapolDevice=&d;eapolTicks=0;eapolReplacement=false;delayHook=EapolProgress;
        synchronizeHook=SynchronizeEapol;
        assert(Ap6256WlfcWaitEapol(&d,7)==0 && eapolTicks==5 && synchronizeHook==NULL);
        delayHook=NULL;End(d);
    }
    {
        Device d;Init(d);Map(&d,{9,54,19,9,9,0});
        UCHAR f[113]={};f[12]=0x88;f[13]=0x8e;
        assert(Ap6256WlfcEnqueue(&d,f,sizeof(f),3,BCDC_DATA_EXEMPT_ALWAYS,7,2,1,Completion,NULL)==0);
        eapolDevice=&d;eapolTicks=0;eapolReplacement=true;delayHook=EapolProgress;
        assert(Ap6256WlfcWaitEapol(&d,7)==0 && eapolTicks==5 && writes.size()==2);
        eapolReplacement=false;delayHook=NULL;End(d);
    }
    {
        Device d;Init(d);txFenceDeferred=true;
        assert(Ap6256WlfcWaitEapol(&d,0)==STATUS_IO_TIMEOUT && clockNow==9500000);
        assert(d.TxKeyFenceCompleted==0 && d.TxKeyFenceRequested==1);
        txFenceDeferred=false;Ap6256WorkItemFlush(&d.TxWorker);
        assert(Ap6256WlfcWaitEapol(&d,0)==0 && d.TxKeyFenceCompleted==2);
        d.TalStarted=FALSE;assert(Ap6256WlfcWaitEapol(&d,0)==STATUS_DEVICE_NOT_READY);
        d.TalStarted=TRUE;d.TxKeyFenceRequested=MAXLONG;d.TxKeyFenceCompleted=MAXLONG;
        assert(Ap6256WlfcWaitEapol(&d,0)==0 && (ULONG)d.TxKeyFenceCompleted==0x80000000UL);
        d.TxKeyFenceRequested=-1;d.TxKeyFenceCompleted=-1;
        assert(Ap6256WlfcWaitEapol(&d,0)==0 && d.TxKeyFenceCompleted==0);End(d);
    }
    Device d;Init(d);assert(Ap6256WlfcWaitEapol(&d,16)==STATUS_INVALID_PARAMETER);
    assert(Ap6256WlfcWaitEapol(&d,0)==0 && clockNow==0);
    UCHAR frame[99]={2,3,4,5,6,7};frame[12]=0x88;frame[13]=0x8e;
    Map(&d,{9,54,19,9,9,0});
    assert(Ap6256WlfcEnqueue(&d,frame,sizeof(frame),3,BCDC_DATA_EXEMPT_ALWAYS,7,2,1,Completion,NULL)==0);
    assert(Ap6256WlfcWaitEapol(&d,0)==0 && clockNow==0);
    eapolDevice=&d;eapolTicks=0;delayHook=EapolProgress;
    assert(Ap6256WlfcWaitEapol(&d,7)==0 && eapolTicks==5 && clockNow==50000);
    delayHook=NULL;Pump(&d);End(d);
    for(auto state:{WlfcQueued,WlfcWriting,WlfcFlight,WlfcSuppressed}) {
        Init(d);assert(Ap6256WlfcEnqueue(&d,frame,sizeof(frame),3,BCDC_DATA_EXEMPT_ALWAYS,0,0,0,Completion,NULL)==0);
        auto& p=d.Wlfc->Packets[0];p.State=state;
        assert(Ap6256WlfcWaitEapol(&d,0)==STATUS_IO_TIMEOUT && clockNow==9500000);
        assert(p.State==state && d.Wlfc->Used==1 && writes.empty());
        p.State=WlfcQueued;d.HostTxQuiesced=1;assert(Ap6256WlfcWaitEapol(&d,0)==STATUS_DEVICE_NOT_READY);
        d.HostTxQuiesced=0;d.DatapathRunning=FALSE;assert(Ap6256WlfcWaitEapol(&d,0)==STATUS_DEVICE_NOT_READY);
        d.DatapathRunning=TRUE;End(d);
    }
    Init(d);Queue(d);assert(Ap6256WlfcWaitEapol(&d,0)==0 && clockNow==0);End(d);
    puts("PASS: per-interface EAPOL barrier waits for firmware completion; all pending states block, timeout never cancels or invents completion");
}
int main(int argc,char**) { EapolBarrierTests(argc);RetainedSleepTest();CancelledCreditTest();CreditLifecycleTests();DetachedCapacityTest();SustainedCreditTests();CoreTests();WdiTests();puts("WLFC core and WDI ownership tests passed"); }
'''

def sha_previous(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    ROOT = args.source_root.resolve()
    tx.ROOT = ROOT
    out = (args.output or output_dir('wlfc')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    wdk = read_source_text(tx.INC / 'km/dot11wdi.h')
    text = PRE
    for name in ('WDI_PORT_ID', 'WDI_PEER_ID', 'WDI_FRAME_ID', 'WDI_EXTENDED_TID'):
        text += re.search('typedef [^;\\n]+ ' + name + ';', wdk)[0] + '\n'
    for name in ('WDI_EXEMPTION_ACTION_TYPE', 'WDI_FRAME_PAYLOAD_TYPE', 'WDI_TXRX_MPDU_PN', 'WDI_TX_FRAME_STATUS', 'WDI_TX_METADATA', 'WDI_RX_METADATA', 'WDI_FRAME_METADATA'):
        text += tx.declaration(wdk, name)
    sd = read_source_text(ROOT / 'src/common/sdpcm.h')
    tal = read_source_text(ROOT / 'src/wdi/wdi_tal.c')
    dp = read_source_text(ROOT / 'src/common/datapath.h')
    for (source, pattern) in ((sd, '^#define (?:SDPCM_|BCDC_DATA_|BCDC_DCMD_PROTO_VERSION|BRCMF_E_FIFO_CREDIT_MAP|BRCMF_E_BCMC_CREDIT_SUPPORT)[^\\n]+'), (tal, '^#define AP6256_(?:FC_|80211_|LLC_|ETH_|TAL_MAX_FRAME_SIZE)[^\\n]+'), (dp, '^#define AP6256_TX_(?:GLOM_MAX_FRAMES|PRIORITY)[^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += '#define AP6256_STATION_PORT 0\n#define AP6256_GROUP_PORT 2\n#pragma pack(push,1)\n'
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'SDPCM_HW_EXT', 'BCDC_DATA_HEADER'):
        text += tx.declaration(sd, name)
    text += '#pragma pack(pop)\n' + tx.declaration(dp, 'AP6256_TX_GLOM_FRAME') + MOCK
    text += read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    text += r'''

static BOOLEAN Ap6256FipsActive(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256FipsTxCurrent(Device*,UINT32,const UCHAR*,ULONG) {return FALSE;}
#define Ap6256RawTxCurrent Ap6256FipsTxCurrent
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256RawDestination(Device*,UINT32,const UCHAR*,ULONG,UCHAR*) {return FALSE;}
static NTSTATUS Ap6256FipsPrepareTx(Device*,UINT32,UCHAR*,ULONG,ULONG*,UCHAR*,UCHAR*) {return STATUS_NOT_SUPPORTED;}
#define Ap6256RawPrepareTx Ap6256FipsPrepareTx
'''
    text += re.sub('^#(?:include|pragma)[^\\n]*\\n', '', read_source_text(ROOT / 'src/common/wlfc.h'), flags=re.M)
    text += '#define AP6256_ENABLE_WDI\n'
    engine = read_source_text(ROOT / 'src/common/wlfc.c')
    text += re.sub('^#include[^\\n]*\\n', '', engine, flags=re.M)
    text += '\n'.join(re.findall('^static const UCHAR Ap6256Oui[^\\n]+', tal, re.M)) + '\n'
    text += tx.function('wdi_tal.c', 'Ap6256Tal80211ToEthernet')
    text += tx.declaration(tal, 'AP6256_WLFC_NBL')
    for name in ('Ap6256TalWlfcRelease', 'Ap6256TalWlfcComplete', 'Ap6256TalWlfcResult', 'Ap6256TalWlfcAbortProgress', 'Ap6256TalWlfcQueue', 'Ap6256TalTxTargetDescInit'):
        text += tx.function('wdi_tal.c', name)
    text += tx.function('wdi_tal.c', 'Ap6256TalTxCountedPass')
    text += tx.function('wdi_tal.c', 'Ap6256TalTxWorker')
    text += tx.function('wdi_tal.c', 'Ap6256TalTxSchedule')
    text += tx.function('wdi_tal.c', 'Ap6256NetTxSynchronize')
    text += TEST
    source = out / 'tests.cpp'
    write_text(source, text, encoding='utf-8')
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/wd4505', '/Od', '/MT', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um')]
    command += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')

    def run_logged(cmd, name):
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        write_bytes(out / name, result.stdout)
        print(result.stdout.decode(errors='replace'), end='')
        result.check_returncode()
        return result
    run_logged(command, 'compile.log')
    result = run_logged([str(out / 'tests.exe')], 'run.log')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    assert b'WLFC sustained: 80000 packets' in result.stdout
    write_text(out / 'receipt.json', json.dumps(dict(source_root=str(ROOT), test_sha256=sha(Path(__file__)), wlfc_sha256=sha(ROOT / 'src/common/wlfc.c'), wlfc_header_sha256=sha(ROOT / 'src/common/wlfc.h'), wdi_tal_sha256=sha(ROOT / 'src/wdi/wdi_tal.c'), fixture_sha256=sha(source), executable_sha256=sha(out / 'tests.exe'), compile_log_sha256=sha(out / 'compile.log'), run_log_sha256=sha(out / 'run.log'), exit_code=result.returncode, sustained_packets=80000, transmit_fifos=[0, 1, 2, 3, 4], atim_decoder_tested=True, full_detached_capacity=128, cancelled_requested_credit_negative_control=True, board_tested=False, firmware_radio_fixture=True), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
