# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Test production WDI packing, chain flushing and SDPCM writes in user mode.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
from pathlib import Path
import argparse
import json
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <array>
#include <string>
#include <map>
#include <memory>
typedef LONG NTSTATUS;
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_SUCCESS ((NTSTATUS)0)
#undef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xc0000206)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_BUFFER_OVERFLOW ((NTSTATUS)0x80000005)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xc0000186)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_CANCELLED ((NTSTATUS)0xc0000120)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define MAXULONG 0xffffffffUL
static std::vector<std::string> logs;
static void trace(const char* f,...) { char b[512];va_list a;va_start(a,f);vsnprintf(b,sizeof(b),f,a);va_end(a);logs.emplace_back(b); }
#define TraceDiag(...) trace(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceFrameDiag(...) trace(__VA_ARGS__)
#define TraceFrameInfo(t,...) trace(__VA_ARGS__)
#define TraceData(...) trace(__VA_ARGS__)
#define TraceInfo(t,...) trace(__VA_ARGS__)
#define TraceWarn(t,...) trace(__VA_ARGS__)
struct NBL;
struct NB { std::vector<UCHAR> bytes; bool fragmented=false,unmapped=false; NB* next=nullptr; NBL* owner=nullptr; };
typedef NB* PNET_BUFFER;
struct NBL { void* MiniportReserved[2]={}; bool cancel=false,completed=false; NB* first=nullptr; NBL* next=nullptr; };
typedef NBL* PNET_BUFFER_LIST;
#define NET_BUFFER_DATA_LENGTH(n) ((ULONG)(n)->bytes.size())
#define NET_BUFFER_LIST_FIRST_NB(n) ((assert(!(n)->completed)),(n)->first)
#define NET_BUFFER_LIST_NEXT_NBL(n) ((assert(!(n)->completed)),(n)->next)
#define NET_BUFFER_NEXT_NB(n) ((assert(!(n)->owner || !(n)->owner->completed)),(n)->next)
typedef void* TAL_TXRX_HANDLE;
typedef LONG NDIS_STATUS;
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xc0010015)
#define WDI_TX_CREDIT_INVALID 0xffff
#define WDI_QUANTUM_INVALID 0xffffffff
#define WDI_TX_MAX_FRAME_COUNT_INVALID 0xff
#define Ap6256CallUpTxDequeue 0
static void* NdisGetDataBuffer(NB* n,ULONG length,void* dest,ULONG align,ULONG offset) {
    assert(length==n->bytes.size() && align==1 && offset==0);
    if(n->unmapped)return nullptr;
    if(n->fragmented){memcpy(dest,n->bytes.data(),length);return dest;}
    return n->bytes.data();
}
typedef int KIRQL;
static void KeAcquireSpinLock(int* l,KIRQL* i){assert(!*l);*l=1;*i=0;}
static void KeReleaseSpinLock(int* l,KIRQL){assert(*l);*l=0;}
static void Ap6256LockAcquire(int* l){assert(!*l);*l=1;}
static void Ap6256LockRelease(int* l){assert(*l);*l=0;}
struct Device {
    volatile LONG HostTxQuiesced=0;
    struct { BOOLEAN FirmwareReady,Started;UINT32 IfIndex,Mode; } Go;
    struct { BOOLEAN Sleeping=FALSE;BOOLEAN TxGlom;ULONG Function2BlockSize;UINT8 MaxTxSeq,TxSeq;
        int TxLock,TxStateLock;LONG64 StatTxFrames;BOOLEAN TxFlowStopped;UCHAR FlowControl; } Sdio;
    PUCHAR TxScratch;ULONG TxScratchSize;LONG TalTxFrames,TalTxEapol;
    struct { void (*TxDequeueIndication)(void*,UINT32,UINT8,UINT16,NBL**); } WdiDataApi;
    void* WdiDataPathHandle; LONG TxPaused,TxPassRerun,TxEmptyDequeueCredit; BOOLEAN DatapathRunning,TalStarted;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
'''
MOCKS = r'''
static std::vector<std::vector<UCHAR>> expected;
static size_t delivered;
static unsigned bus_calls,fail_call;
static bool replenish;
static unsigned abort_call;
static bool abort_active;
static NBL* dequeue_head;
static ULONG batch_limit;
static unsigned schedules,dequeue_credit_gain;
static std::map<NBL*,WDI_TX_FRAME_STATUS> completions;
static unsigned rd16(const UCHAR* p){return p[0]|(unsigned(p[1])<<8);}
static unsigned rd32(const UCHAR* p){return rd16(p)|(rd16(p+2)<<16);}
static NTSTATUS Ap6256SdioFrameRW(Device* c,BOOLEAN write,PUCHAR bytes,ULONG length) {
    assert(write && c->Sdio.TxLock && !c->Sdio.TxStateLock);
    ++bus_calls;
    assert(rd16(bytes)==(c->Sdio.TxGlom?length:rd16(bytes)));
    assert((rd16(bytes)^rd16(bytes+2))==0xffff);
    ULONG offset=0,frames=0;
    do {
        assert(offset+24<=length);
        unsigned wire=c->Sdio.TxGlom?(rd32(bytes+offset+4)&0xffffff)+4:rd16(bytes+offset);
        unsigned hdr=c->Sdio.TxGlom?20:12;
        assert(wire>=hdr+18 && offset+wire<=length);
        const UCHAR* sw=bytes+offset+hdr-8;
        assert(sw[0]==UINT8(c->Sdio.TxSeq+frames) && sw[1]==2 && sw[3]==hdr);
        assert(delivered+frames<expected.size());
        const auto& want=expected[delivered+frames];
        assert(wire-hdr==want.size() && !memcmp(bytes+offset+hdr,want.data(),want.size()));
        ULONG pad=c->Sdio.TxGlom?rd32(bytes+offset+8)>>16:length-wire;
        bool last=!c->Sdio.TxGlom || !!(rd32(bytes+offset+4)&0x1000000);
        assert(offset+wire+pad<=length);
        for(ULONG j=offset+wire;j<offset+wire+pad;j++)assert(bytes[j]==0);
        offset+=wire+pad;++frames;
        if(last){assert(offset==length);break;}
    } while(offset<length);
    if(fail_call==bus_calls)return STATUS_IO_TIMEOUT;
    delivered+=frames;
    if(replenish)c->Sdio.MaxTxSeq=UINT8(c->Sdio.MaxTxSeq+frames);
    if(abort_call==bus_calls)abort_active=true;
    return 0;
}
static void Ap6256SdioTxFail(Device*){}
static BOOLEAN Ap6256TalTxNblAborting(Device*,NBL* n){return (BOOLEAN)(n->cancel || abort_active);}
static BOOLEAN Ap6256TalTxAborting(Device*){return (BOOLEAN)abort_active;}
static void Ap6256TalCompleteOneNbl(Device*,NBL* n,WDI_TX_FRAME_STATUS s){assert(!completions.count(n));completions[n]=s;n->completed=true;n->MiniportReserved[0]=nullptr;}
static void Ap6256TalCompleteChain(Device* c,NBL* n,WDI_TX_FRAME_STATUS s){while(n){auto next=n->next;Ap6256TalCompleteOneNbl(c,n,s);n=next;}}
static void Ap6256TalCount(Device*,int){}
static void Ap6256TalTraceTxCredit(Device*,const char*){}
static void Ap6256TalTxPauseIndicate(Device*,BOOLEAN){}
static ULONG Ap6256DatapathTxGlomBytes(Device*){return batch_limit;}
static void Ap6256TalTxSchedule(Device*){++schedules;}
VOID Ap6256WdiTxResume(Device*);
static void dequeue(void* handle,UINT32,UINT8,UINT16 credit,NBL** out){
    *out=nullptr;NBL* last=nullptr;
    while(dequeue_head){
        auto meta=(WDI_FRAME_METADATA*)dequeue_head->MiniportReserved[0];
        unsigned cost=meta && meta->u.txMetaData.TxCost?meta->u.txMetaData.TxCost:1;
        if(cost>credit)break;
        credit=UINT16(credit-cost);
        if(!*out)*out=dequeue_head;
        last=dequeue_head;dequeue_head=dequeue_head->next;
    }
    if(last)last->next=nullptr;
    if(dequeue_credit_gain){
        auto c=(Device*)handle;c->Sdio.MaxTxSeq=UINT8(c->Sdio.MaxTxSeq+dequeue_credit_gain);
        dequeue_credit_gain=0;Ap6256WdiTxResume(c);
    }
}
'''
TEST = r'''
struct Frame {
    NB nb;NBL nbl;WDI_FRAME_METADATA metadata={};std::vector<UCHAR> wire;
    Frame(unsigned id,UINT16 port,unsigned action,unsigned size,bool multicast=false,bool eapol=true) {
        assert(size>=21 && size<=1600);
        UCHAR da[6]={0xa0,0xd3,0x65,0xa0,0x51,UCHAR(id)};
        UCHAR sa[6]={0x42,0xd9,0x5a,0x8c,0x35,0x7e};
        UCHAR bssid[6]={2,3,4,5,6,7};
        if(multicast)memset(da,0xff,6);
        nb.bytes.resize(size+18);nb.bytes[0]=8;nb.bytes[1]=port==2?2:1;
        memcpy(nb.bytes.data()+4,port==2?da:bssid,6);
        memcpy(nb.bytes.data()+10,port==2?bssid:sa,6);
        memcpy(nb.bytes.data()+16,port==2?sa:da,6);
        UCHAR snap[8]={0xaa,0xaa,3,0,0,0,UCHAR(eapol?0x88:8),UCHAR(eapol?0x8e:0)};
        memcpy(nb.bytes.data()+24,snap,8);
        for(unsigned i=32;i<nb.bytes.size();i++)nb.bytes[i]=UCHAR(i+id);
        nb.bytes[32]=2;nb.bytes[33]=3;
        nb.bytes[37]=0;nb.bytes[38]=0x8a;
        metadata.u.txMetaData.PortID=port;metadata.u.txMetaData.PeerID=2;
        metadata.u.txMetaData.ExemptionAction=(WDI_EXEMPTION_ACTION_TYPE)action;
        nbl.MiniportReserved[0]=&metadata;
        nbl.first=&nb;nb.owner=&nbl;
        wire={UCHAR(0x20|action),0,UCHAR(port==2?7:0),0};
        wire.insert(wire.end(),da,da+6);wire.insert(wire.end(),sa,sa+6);
        wire.push_back(snap[6]);wire.push_back(snap[7]);
        wire.insert(wire.end(),nb.bytes.begin()+32,nb.bytes.end());
        assert(wire.size()==size+4);
    }
};
static std::array<UCHAR,40960> scratch;
static Device setup(bool glom=true,unsigned block=512,unsigned credit=2) {
    Device c={};c.Go.FirmwareReady=c.Go.Started=TRUE;c.Go.IfIndex=7;
    c.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;c.TxScratch=scratch.data();c.TxScratchSize=(ULONG)scratch.size();
    c.Sdio.TxGlom=(BOOLEAN)glom;c.Sdio.Function2BlockSize=block;c.Sdio.TxSeq=254;c.Sdio.MaxTxSeq=UINT8(254+credit);
    scratch.fill(0xcd);expected.clear();delivered=0;bus_calls=fail_call=0;replenish=true;completions.clear();logs.clear();
    abort_call=0;abort_active=false;dequeue_head=nullptr;batch_limit=32768;
    schedules=dequeue_credit_gain=0;c.TxEmptyDequeueCredit=-1;
    c.DatapathRunning=c.TalStarted=TRUE;c.WdiDataApi.TxDequeueIndication=dequeue;
    return c;
}
static void pack(Device& c,AP6256_TAL_TX_CHAIN& chain,Frame& f) {
    auto saved=f.nb.bytes;auto meta=f.metadata;
    assert(Ap6256TalPackFrame(&c,&chain,&f.nb,&f.nbl)==0);
    assert(saved==f.nb.bytes && !memcmp(&meta,&f.metadata,sizeof(meta)));
    expected.push_back(f.wire);
    const auto& d=chain.Frames[chain.Count-1];
    assert(d.WireLength==Ap6256TxHdrLen(&c)+f.wire.size());
    assert(!memcmp(c.TxScratch+d.Offset+Ap6256TxHdrLen(&c),f.wire.data(),f.wire.size()));
}
static void run_pass(Device& c){c.WdiDataPathHandle=&c;c.TxPassRerun=0;Ap6256TalTxPass(&c);}
static void batching() {


    for(bool glom:{false,true})for(unsigned limit:{1024u,32768u})for(unsigned buffers:{2u,4u,40u}) {
        auto c=setup(glom,512,100);batch_limit=limit;
        Frame before(1,2,0,601,false,false),after(99,2,0,211,false,false);
        std::vector<std::unique_ptr<Frame>> frames;
        for(unsigned i=0;i<buffers;i++)frames.emplace_back(new Frame(i+2,2,0,251,false,false));
        auto owner=&frames[0]->nbl;
        before.nbl.next=owner;owner->next=&after.nbl;
        expected.push_back(before.wire);
        for(unsigned i=0;i<buffers;i++) {
            frames[i]->nb.owner=owner;
            if(i+1<buffers)frames[i]->nb.next=&frames[i+1]->nb;
            expected.push_back(frames[i]->wire);
        }
        expected.push_back(after.wire);dequeue_head=&before.nbl;
        run_pass(c);
        assert(delivered==buffers+2 && completions.size()==3);
        for(auto& v:completions)assert(v.second==WDI_TxFrameStatus_Ok);
    }
    puts("PASS: production TX pass preserves all buffers across byte/count boundaries and completes each NBL once");
}
static void batching_failures() {
    for(unsigned mode=0;mode<4;mode++){
        auto c=setup(true,512,20);batch_limit=1024;
        std::vector<std::unique_ptr<Frame>> frames;
        for(unsigned i=0;i<5;i++)frames.emplace_back(new Frame(i+1,2,0,251,false,false));
        auto owner=&frames[0]->nbl;
        for(unsigned i=0;i<5;i++){
            frames[i]->nb.owner=owner;
            if(i<4)frames[i]->nb.next=&frames[i+1]->nb;
            expected.push_back(frames[i]->wire);
        }
        if(mode<2)fail_call=mode+1;
        if(mode==2)abort_call=1;
        if(mode==3)frames[4]->nb.unmapped=true;
        dequeue_head=owner;run_pass(c);
        assert(delivered==(mode==0?0u:3u) && completions.size()==1);
        assert(completions.at(owner)==(mode==2?WDI_TxFrameStatus_TransferCancelled:WDI_TxFrameStatus_TransferFailed));
    }
    {
        auto c=setup();Frame f(1,2,0,251);f.nbl.first=nullptr;
        dequeue_head=&f.nbl;run_pass(c);
        assert(bus_calls==0 && completions.size()==1 && completions.at(&f.nbl)==WDI_TxFrameStatus_TransferFailed);
    }
    puts("PASS: prefix/final write failure, abort, late mapping failure and empty NBL return ownership once without success");
}
static void costs() {
    auto c=setup();Frame a(1,0,0,100),b(2,0,0,100),d(3,0,0,100);
    a.nbl.next=&b.nbl;b.nb.next=&d.nb;d.nb.owner=&b.nbl;
    NDIS_STATUS status=(NDIS_STATUS)-1;
    Ap6256TalTxTargetDescInit(&c,&a.nbl,&status);
    assert(status==NDIS_STATUS_SUCCESS && a.metadata.u.txMetaData.TxCost==1 && b.metadata.u.txMetaData.TxCost==2);
    a.nbl.next=nullptr;a.nbl.first=nullptr;
    Ap6256TalTxTargetDescInit(&c,&a.nbl,&status);assert(status==NDIS_STATUS_INVALID_DATA);
    a.nbl.first=&a.nb;a.nbl.MiniportReserved[0]=nullptr;
    Ap6256TalTxTargetDescInit(&c,&a.nbl,&status);assert(status==NDIS_STATUS_INVALID_DATA);
    std::vector<NB> many(WDI_TX_CREDIT_INVALID);
    for(size_t i=0;i+1<many.size();i++)many[i].next=&many[i+1];
    a.nbl.MiniportReserved[0]=&a.metadata;a.nbl.first=many.data();
    Ap6256TalTxTargetDescInit(&c,&a.nbl,&status);assert(status==NDIS_STATUS_INVALID_DATA);
    puts("PASS: TX descriptor credit counts the buffers actually submitted for every NBL");
}
static void credit_wait() {
    for(bool during_dequeue:{false,true}){
        auto c=setup(true,512,2);Frame a(1,2,0,113),b(2,2,0,113),d(3,2,0,113);
        a.nb.next=&b.nb;b.nb.next=&d.nb;b.nb.owner=d.nb.owner=&a.nbl;
        NDIS_STATUS status;
        Ap6256TalTxTargetDescInit(&c,&a.nbl,&status);assert(status==0);
        dequeue_head=&a.nbl;expected={a.wire,b.wire,d.wire};
        if(during_dequeue)dequeue_credit_gain=2;
        run_pass(c);
        assert(bus_calls==0 && completions.empty() && c.TxPaused==0 && c.TxEmptyDequeueCredit==1);
        if(during_dequeue){
            assert(schedules==0 && c.TxPassRerun==1);
        } else {
            for(unsigned i=0;i<20;i++)Ap6256WdiTxResume(&c);
            assert(schedules==0 && c.TxPassRerun==0);
            c.Sdio.MaxTxSeq=UINT8(c.Sdio.MaxTxSeq+1);Ap6256WdiTxResume(&c);
            assert(schedules==1);run_pass(c);
            assert(bus_calls==0 && c.TxEmptyDequeueCredit==2 && c.TxPassRerun==0);
            c.Sdio.MaxTxSeq=UINT8(c.Sdio.MaxTxSeq+1);Ap6256WdiTxResume(&c);assert(schedules==2);
        }
        run_pass(c);assert(delivered==3 && completions.size()==1 && completions.at(&a.nbl)==WDI_TxFrameStatus_Ok);
        run_pass(c);auto count=schedules;
        for(unsigned i=0;i<20;i++)Ap6256WdiTxResume(&c);
        assert(c.TxPaused==0 && schedules==count && c.TxPassRerun==0);

        Frame fresh(4,2,0,113);expected.push_back(fresh.wire);dequeue_head=&fresh.nbl;run_pass(c);
        assert(delivered==4 && completions.at(&fresh.nbl)==WDI_TxFrameStatus_Ok);
    }
    puts("PASS: credit growth retries an expensive queued NBL, including update-during-dequeue; idle/unchanged-credit stays unpaused without rerun");
}
static void partial_abort() {
    auto c=setup(false,512,10);AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;
    Frame a(1,2,0,701),b(2,2,0,113),d(3,2,0,113);
    pack(c,chain,a);pack(c,chain,b);pack(c,chain,d);abort_call=1;
    Ap6256TalTxFlushChain(&c,&chain,FALSE);
    assert(delivered==1 && completions.size()==3);
    assert(completions.at(&a.nbl)==WDI_TxFrameStatus_Ok);
    assert(completions.at(&b.nbl)==WDI_TxFrameStatus_TransferCancelled && completions.at(&d.nbl)==WDI_TxFrameStatus_TransferCancelled);
    puts("PASS: an abort cancels only the unsent suffix of a partially transferred batch");
}
int main(int argc,char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    static_assert(offsetof(WDI_TX_METADATA,ExemptionAction)==16,"WDK metadata layout");
    std::string selected=argc>1?argv[1]:"all";
    if(selected=="batching" || selected=="all")batching();
    if(selected=="batching-failures" || selected=="all")batching_failures();
    if(selected=="costs" || selected=="all")costs();
    if(selected=="partial-abort" || selected=="all")partial_abort();
    if(selected=="credit-wait" || selected=="all")credit_wait();
    if(selected!="all")return 0;

    for(UINT16 port:{UINT16(0),UINT16(2)})for(unsigned action=0;action<3;action++)
    for(bool fragmented:{false,true})for(bool eapol:{false,true})for(bool multicast:{false,true}) {
        auto c=setup();AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;
        Frame f(1,port,action,113,multicast,eapol);f.nb.fragmented=fragmented;
        pack(c,chain,f);Ap6256TalTxFlushChain(&c,&chain,FALSE);
        assert(delivered==1 && chain.Count==0 && chain.Used==0 && completions[&f.nbl]==WDI_TxFrameStatus_Ok);
    }
    puts("PASS: real WDK metadata -> production 802.11 conversion -> BCDC/SDPCM bytes; 48 policy/port/buffer/address/EtherType cases");

    for(bool glom:{false,true})for(unsigned block:{0u,64u,256u,512u})for(unsigned credit:{2u,3u,8u}) {
        auto c=setup(glom,block,credit);AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;
        Frame a(1,2,0,701,false,false),b(2,2,1,113),d(3,2,2,1299),e(4,2,1,113);
        pack(c,chain,a);pack(c,chain,b);pack(c,chain,d);pack(c,chain,e);
        auto old=chain;Ap6256TalTxFlushChain(&c,&chain,FALSE);
        assert(delivered==4 && completions.size()==4 && c.Sdio.StatTxFrames==4 && c.Sdio.TxSeq==2);
        for(auto& v:completions)assert(v.second==WDI_TxFrameStatus_Ok);
        assert(!memcmp(old.Frames,chain.Frames,4*sizeof(chain.Frames[0])));
        if(!glom || credit==2)assert(bus_calls==4);
    }
    puts("PASS: partial writes preserve subsequent EAPOL bytes, absolute offsets and zero wire padding; glom on/off, 4 alignments, 3 credit windows and sequence wrap");

    for(unsigned mode=0;mode<3;mode++) {
        auto c=setup();AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;
        Frame a(1,2,1,701),b(2,2,1,113),d(3,2,1,113);
        pack(c,chain,a);pack(c,chain,b);pack(c,chain,d);
        std::vector<UCHAR> remaining(c.TxScratch+chain.Frames[1].Offset,c.TxScratch+chain.Used);
        if(mode==0)fail_call=1;else if(mode==1)fail_call=2;else replenish=false;
        Ap6256TalTxFlushChain(&c,&chain,FALSE);
        assert(delivered==(mode==0?0u:1u));
        assert(completions[&a.nbl]==(mode==0?WDI_TxFrameStatus_TransferFailed:WDI_TxFrameStatus_Ok));
        assert(completions[&b.nbl]==WDI_TxFrameStatus_TransferFailed && completions[&d.nbl]==WDI_TxFrameStatus_TransferFailed);
        if(mode==0)assert(!memcmp(c.TxScratch+chain.Frames[1].Offset,remaining.data(),remaining.size()));
        bool reported=false;for(const auto& line:logs)if(line.find("submitted 0")!=std::string::npos)reported=true;assert(reported);
    }
    {
        auto c=setup();AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;Frame f(1,2,1,113);
        pack(c,chain,f);f.nbl.cancel=true;Ap6256TalTxFlushChain(&c,&chain,FALSE);
        assert(bus_calls==0 && completions[&f.nbl]==WDI_TxFrameStatus_TransferCancelled);
    }

    for(unsigned mode=0;mode<7;mode++) {
        auto c=setup();AP6256_TAL_TX_CHAIN chain={};chain.Limit=32768;Frame f(1,2,1,113);
        if(mode==0)f.metadata.u.txMetaData.ExemptionAction=(WDI_EXEMPTION_ACTION_TYPE)3;
        if(mode==1)f.metadata.u.txMetaData.ExemptionAction=(WDI_EXEMPTION_ACTION_TYPE)-1;
        if(mode==2)f.nbl.MiniportReserved[0]=nullptr;
        if(mode==3)f.metadata.u.txMetaData.PortID=1;
        if(mode==4)c.Go.Started=FALSE;
        if(mode==5)c.Go.FirmwareReady=FALSE;
        if(mode==6)f.nb.unmapped=true;
        assert(!NT_SUCCESS(Ap6256TalPackFrame(&c,&chain,&f.nb,&f.nbl)) && chain.Count==0 && chain.Used==0);
    }
    {
        auto c=setup();ULONG sent=999;AP6256_TX_GLOM_FRAME bad={0,100};
        assert(Ap6256DatapathSendGlom(&c,c.TxScratch,32,&bad,1,&sent)==STATUS_INVALID_PARAMETER && sent==0 && bus_calls==0);
        assert(Ap6256DatapathSendGlom(&c,c.TxScratch,c.TxScratchSize,&bad,33,&sent)==STATUS_INVALID_PARAMETER);
    }
    puts("PASS: failure/busy/cancel completion, restored tail on failure, invalid metadata and undersized buffer rejection");
}
'''

def declaration(source, name):
    return re.search('typedef (?:struct|enum|union) _' + name + '\\s*\\{[\\s\\S]*?^\\}[^;]+;', source, re.M)[0] + '\n'

def function(file, name):
    source = read_source_text(ROOT / 'src' / file).replace('static __forceinline', 'static')
    matches = list(re.finditer('^(?:static\\s+)?(?:[A-Z][A-Za-z0-9_]*\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{', source, re.M))
    if not matches:
        raise ValueError(name)
    match = matches[-1]
    signature = match[0][:-1].replace('static ', '')
    chunk = source[match.end() - 1:]
    clean = re.sub('//[^\\n]*|/\\*[\\s\\S]*?\\*/|"(?:\\\\.|[^"\\\\])*"', lambda m: ' ' * len(m[0]), chunk)
    depth = 0
    for (i, c) in enumerate(clean):
        depth += (c == '{') - (c == '}')
        if depth == 0:
            return signature + chunk[:i + 1] + '\n'
    raise ValueError(name)

def main():
    global ROOT
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--case', choices=('all', 'batching', 'batching-failures', 'costs', 'partial-abort', 'credit-wait'), default='all')
    args = parser.parse_args()
    ROOT = args.source_root.resolve()
    out = (args.output or output_dir('wdi-transmit')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    wdk = read_source_text(INC / 'km/dot11wdi.h')
    text = PRE
    text += read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    text += r'''
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)

static NTSTATUS Ap6256FipsPrepareTx(Device*,UINT32,UCHAR*,ULONG,ULONG*,UCHAR*,UCHAR*) {return STATUS_NOT_SUPPORTED;}
static BOOLEAN Ap6256FipsBcdcTxCurrent(Device*,const UCHAR*,ULONG) {return TRUE;}
#define Ap6256RawBcdcTxCurrent Ap6256FipsBcdcTxCurrent
#define Ap6256RawPrepareTx Ap6256FipsPrepareTx
'''
    for name in ('WDI_PORT_ID', 'WDI_PEER_ID', 'WDI_FRAME_ID', 'WDI_EXTENDED_TID'):
        text += re.search('typedef [^;\\n]+ ' + name + ';', wdk)[0] + '\n'
    for name in ('WDI_EXEMPTION_ACTION_TYPE', 'WDI_FRAME_PAYLOAD_TYPE', 'WDI_TXRX_MPDU_PN', 'WDI_TX_FRAME_STATUS', 'WDI_TX_METADATA', 'WDI_RX_METADATA', 'WDI_FRAME_METADATA'):
        text += declaration(wdk, name)
    sd = read_source_text(ROOT / 'src/common/sdpcm.h')
    tal = read_source_text(ROOT / 'src/wdi/wdi_tal.c')
    dp = read_source_text(ROOT / 'src/common/datapath.h')
    for (source, pattern) in ((sd, '^#define (?:SDPCM_|BCDC_DATA_|BCDC_DCMD_PROTO_VERSION)[^\\n]+'), (tal, '^#define AP6256_(?:FC_|80211_|LLC_|ETH_|TAL_MAX_FRAME_SIZE)[^\\n]+'), (dp, '^#define AP6256_TX_(?:GLOM_MAX_FRAMES|PRIORITY)[^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += '#define AP6256_STATION_PORT 0\n#define AP6256_GROUP_PORT 2\n'
    text += declaration(read_source_text(ROOT / 'src/common/ap6256.h'), 'AP6256_GO_DATA_STAGE')
    text += 'static void Ap6256TraceHotspotPacket(Device*,AP6256_GO_DATA_STAGE,UINT32,const UCHAR*,ULONG,NTSTATUS) {}\n'
    wh = read_source_text(ROOT / 'src/common/wifi_ops.h')
    text += re.search('^#define AP6256_WDI_OPMODE_P2P_GO[^\\n]+', wh, re.M)[0] + '\n'
    text += '#pragma pack(push,1)\n'
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'SDPCM_HW_EXT', 'BCDC_DATA_HEADER'):
        text += declaration(sd, name)
    text += '#pragma pack(pop)\n' + declaration(dp, 'AP6256_TX_GLOM_FRAME') + declaration(tal, 'AP6256_TAL_TX_CHAIN')
    text += '\n'.join(re.findall('^static const UCHAR Ap6256Oui[^\\n]+', tal, re.M)) + '\n' + MOCKS
    for (file, name) in [('datapath.h', 'Ap6256TxHdrLen'), ('datapath.c', 'Ap6256Align4'), ('datapath.c', 'Ap6256AlignTransfer'), ('datapath.c', 'Ap6256FillSwHeader'), ('datapath.c', 'Ap6256DatapathSendGlom'), ('wdi_tal.c', 'Ap6256Tal80211ToEthernet'), ('wdi_tal.c', 'Ap6256TalPackFrame'), ('wdi_tal.c', 'Ap6256TalTxSamePeer'), ('wdi_tal.c', 'Ap6256TalTxFlushChain'), ('wdi_tal.c', 'Ap6256TalTxCredit'), ('wdi_tal.c', 'Ap6256TalTxPass'), ('wdi_tal.c', 'Ap6256WdiTxResume'), ('wdi_tal.c', 'Ap6256TalTxTargetDescInit')]:
        text += function(file, name)
    if 'Ap6256WlfcEnabled' in tal:
        text = re.search('^#define AP6256_WLFC_CAPACITY[^\\n]+', read_source_text(ROOT / 'src/common/wlfc.h'), re.M)[0] + '\n' + text
        text = re.sub('(UINT16\\s+Ap6256TalTxCredit)', r'''static bool Ap6256WlfcEnabled(Device*) { return false; }
static UINT16 Ap6256WlfcRoom(Device*) { return 0; }
static void Ap6256TalWlfcQueue(Device*,PNET_BUFFER_LIST) { assert(false); }
\1''', text, count=1)
    text += TEST
    src = out / 'tests.cpp'
    write_bytes(src, text.encode())
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(VC / 'include')] + ['/I' + str(INC / f) for f in ('ucrt', 'shared', 'um')] + [str(src), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command), encoding='utf-8')
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe'), args.case], check=True)
if __name__ == '__main__':
    main()
