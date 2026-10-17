# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise production receive, peer and flush interleavings.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
PRE = r'''
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <functional>
typedef LONG NDIS_STATUS;
typedef UINT16 WDI_PEER_ID,WDI_PORT_ID;
typedef UINT32 WDI_EXTENDED_TID;
typedef void* TAL_TXRX_HANDLE;
typedef int KIRQL;
struct Lock {bool held=false;};
struct NBL {NBL* next=nullptr;void* MiniportReserved[2]={};UCHAR source[6]={};bool freed=false;};
typedef NBL* PNET_BUFFER_LIST;
struct WDI_MAC_ADDRESS {UCHAR Address[6];};
#define NDIS_STATUS_SUCCESS 0
#define NDIS_STATUS_PENDING 0x103
#define STATUS_SUCCESS 0
#define WDI_PEER_ANY 65535
#define WDI_PORT_ANY 65535
#define WDI_RX_INDICATION_PASSIVE 0
#define WDI_RX_INDICATION_DISPATCH_GENERAL 1
#define PASSIVE_LEVEL 0
#define TRACE_NETADAPTER 0
#define AP6256_TAL_PEER_ID 0
#define AP6256_RX_BATCH 16
#define AP6256_TAL_RX_QUEUE_LIMIT 256
#define Ap6256TraceRxBuildFail 0
#define Ap6256TraceRxQueueFull 1
#define Ap6256TraceRxStale 2
#define NET_BUFFER_LIST_NEXT_NBL(n) ((n)->next)
#undef RtlEqualMemory
#define RtlEqualMemory(a,b,n) (!memcmp(a,b,n))
#define RtlCompareMemory(a,b,n) (memcmp(a,b,n)?0u:(SIZE_T)(n))
static void trace(const char*,...) {}
#define TraceDiag(...) trace(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceFrameDiag(...) trace(__VA_ARGS__)
#define TraceFrameInfo(t,...) trace(__VA_ARGS__)
#define TraceInfo(t,...) trace(__VA_ARGS__)
#define TraceWarn(t,...) trace(__VA_ARGS__)
#define TraceError(t,...) trace(__VA_ARGS__)
#define TraceData(...) trace(__VA_ARGS__)
#define Ap6256TalCount(...) ((void)0)
#define Ap6256TalDumpCallCensus(...) ((void)0)
#define Ap6256TraceEapol(...) ((void)0)
#define Ap6256TalTraceEapolRxNbl(...) ((void)0)
'''
MOCK = r'''
struct DeleteReturn;
struct Device {
    struct {
        BOOLEAN Started,FirmwareReady,TalAdded,RxStopped;
        UINT32 IfIndex,Mode;UCHAR ClientBssid[6];
        LONG DataTrace[Ap6256GoDataStageCount];AP6256_GO_PEER Peers[AP6256_GO_PEERS];
    } Go;
    Lock TalStateLock,RxQueueLock;
    ULONGLONG StationRxGeneration,GroupRxGeneration;
    UINT32 TalPhyId;BOOLEAN TalPeerCreated,TalRxOpen,StationRxStopped,RxStopped;
    BOOLEAN TalStarted,TalApiOpen,RxBatching,TalPeerDeletePending,TalPortValid;
    UCHAR TalBssid[6],TalPeerAddress[6];
    ULONG RxBatched,RxQueueCount;LONG TalRxFrames,TalRxEapol;
    NBL *RxQueueHead,*RxQueueTail;void* RxNblPool;
    WDI_PORT_ID TalPortId;void* WdiDataPathHandle;
    struct {
        void (*PeerCreateIndication)(void*,UINT16,UINT16,WDI_MAC_ADDRESS);
        DeleteReturn (*PeerDeleteIndication)(void*,UINT16,UINT16,NDIS_STATUS*);
        void (*RxFlushConfirm)(void*);
        void* AllocateWiFiFrameMetaData;
    } WdiDataApi;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static Device* current;
static std::vector<NBL*> allocated;
static std::function<void()> build_hook,queue_hook,claim_hook,delete_hook;
static unsigned claims,upcalls,notifications,flushes,creates,deletes;
static bool fail_build,pending_delete;
static UCHAR last_created[6];
struct Cancellation {UINT16 Port,Peer;};
static std::vector<Cancellation> cancellations;



struct DeleteReturn {
    ~DeleteReturn() {if(delete_hook){auto hook=delete_hook;delete_hook={};hook();}}
};
static const UCHAR a[]={2,1,2,3,4,5},b[]={2,1,2,3,4,6},other[]={2,1,2,3,4,7};
static void unlocked() {assert(!current->TalStateLock.held && !current->RxQueueLock.held);}
static void Ap6256WlfcCancel(Device*,UINT16 port,UINT16 peer,PVOID cookie) {
    unlocked();assert(!cookie);
    assert((port==AP6256_STATION_PORT && peer==AP6256_TAL_PEER_ID) ||
        (port==AP6256_GROUP_PORT && peer>0 && peer<=AP6256_GO_PEERS));
    cancellations.push_back({port,peer});
}
static void KeAcquireSpinLock(Lock* l,KIRQL* irql) {
    assert(!l->held);*irql=0;
    if(l==&current->TalStateLock)assert(!current->RxQueueLock.held);
    if(l==&current->RxQueueLock && queue_hook && !current->TalStateLock.held) {
        auto hook=queue_hook;queue_hook={};hook();
    }
    l->held=true;
}
static void KeReleaseSpinLock(Lock* l,KIRQL) {assert(l->held);l->held=false;}
static int KeGetCurrentIrql() {return 0;}
static BOOLEAN Ap6256TalUpcallClaim(Device* c) {if(!c->TalApiOpen)return FALSE;upcalls++;return TRUE;}
static void Ap6256TalUpcallRelease(Device*) {assert(upcalls);upcalls--;}
static BOOLEAN Ap6256TalRxClaim(Device* c) {
    if(claim_hook){auto hook=claim_hook;claim_hook={};hook();}
    if(!c->TalStarted || !c->TalApiOpen)return FALSE;claims++;return TRUE;
}
static void Ap6256TalRxRelease(Device*) {assert(claims);claims--;}
static BOOLEAN Ap6256TalTraceSlot(Device*,int) {return TRUE;}
static void Ap6256TraceHotspotPacket(Device*,AP6256_GO_DATA_STAGE,UINT32,const UCHAR*,ULONG,LONG) {}
static void Ap6256TalNotifyRxWaiting(Device*,int,NDIS_STATUS*) {unlocked();notifications++;}
static void Ap6256TalRxIndicateQueued(Device*,int,const char*) {unlocked();}
static void Ap6256TalFreeRxNbl(Device*,NBL* n) {unlocked();assert(!n->freed);n->freed=true;}
static NBL* Ap6256TalBuildRxNbl(Device*,UCHAR* frame,ULONG,UCHAR,UINT32,UINT32) {
    unlocked();assert(claims==1);
    if(build_hook){auto hook=build_hook;build_hook={};hook();}
    if(fail_build)return nullptr;
    auto n=new NBL;memcpy(n->source,frame+6,6);allocated.push_back(n);return n;
}
static void created(void*,UINT16 port,UINT16 peer,WDI_MAC_ADDRESS address) {
    unlocked();assert((port==2 && peer>=1 && peer<=9)||(port==0 && peer==0));
    memcpy(last_created,address.Address,6);creates++;
}
static DeleteReturn deleted(void*,UINT16 port,UINT16 peer,NDIS_STATUS* status) {
    unlocked();assert((port==2 && peer>=1 && peer<=9)||(port==0 && peer==0));
    assert(!cancellations.empty() && cancellations.back().Port==port &&
        cancellations.back().Peer==peer);
    deletes++;*status=pending_delete?NDIS_STATUS_PENDING:NDIS_STATUS_SUCCESS;
    return {};
}
static void flushed(void*) {unlocked();flushes++;}
'''
TEST = r'''
static void setup(Device& c) {
    for(auto n:allocated){assert(n->freed);delete n;}allocated.clear();
    c={};current=&c;claims=upcalls=notifications=flushes=creates=deletes=0;
    cancellations.clear();
    build_hook=queue_hook=claim_hook=delete_hook={};fail_build=pending_delete=false;
    c.Go.Started=c.Go.FirmwareReady=c.Go.TalAdded=TRUE;c.Go.IfIndex=7;
    c.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;
    c.TalStarted=c.TalApiOpen=c.TalPeerCreated=c.TalRxOpen=TRUE;
    c.TalPortValid=TRUE;memcpy(c.TalBssid,a,6);memcpy(c.TalPeerAddress,a,6);
    c.TalPhyId=3;c.WdiDataPathHandle=&c;c.RxNblPool=&c;
    c.WdiDataApi.PeerCreateIndication=created;c.WdiDataApi.PeerDeleteIndication=deleted;
    c.WdiDataApi.RxFlushConfirm=flushed;
}
static void peer(Device& c,const UCHAR* address) {
    assert(Ap6256TalGoPeerCreate(&c,address,4));
    for(auto& p:c.Go.Peers)if(p.Active && !memcmp(p.Address,address,6))p.RxOpen=TRUE;
}
static void receive(Device& c,const UCHAR* source,UINT32 iface=7) {
    UCHAR frame[60]={};memcpy(frame+6,source,6);frame[12]=8;
    Ap6256WdiRxIndicate(&c,frame,sizeof(frame),0,iface);assert(!claims && !upcalls);
}
static void drain(Device& c,unsigned count) {
    NBL* chain=nullptr;Ap6256TalRxGetMpdus(&c,WDI_PEER_ANY,31,&chain);unsigned actual=0;
    while(chain){auto next=chain->next;Ap6256TalFreeRxNbl(&c,chain);chain=next;actual++;}
    assert(actual==count && c.RxQueueCount==0 && !c.RxQueueHead && !c.RxQueueTail);
}
int main(int argc,char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    const char* test=argc>1?argv[1]:"all";Device c={};
    if(!strcmp(test,"all") || !strcmp(test,"peer-identity")) {


        setup(c);c.TalPeerCreated=FALSE;Ap6256TalSetBssid(&c,a);
        assert(Ap6256TalPeerCreate(&c,a));assert(creates==1 && !memcmp(last_created,a,6));
        assert(Ap6256TalPeerCreate(&c,a));assert(creates==1 && !deletes);
        Ap6256TalSetBssid(&c,b);assert(Ap6256TalPeerCreate(&c,b));
        assert(deletes==1 && creates==2 && !memcmp(last_created,b,6));

        Ap6256TalSetBssid(&c,nullptr);assert(Ap6256TalPeerCreate(&c,b));
        assert(deletes==1 && creates==2);

        pending_delete=true;Ap6256TalSetBssid(&c,a);
        assert(!Ap6256TalPeerCreate(&c,a));assert(c.TalPeerDeletePending && creates==2);
        Ap6256TalTxRxPeerDeleteConfirm(&c,2,2);assert(c.TalPeerDeletePending);
        Ap6256TalTxRxPeerDeleteConfirm(&c,0,3);assert(c.TalPeerDeletePending);
        Ap6256TalTxRxPeerDeleteConfirm(&c,0,0);assert(!c.TalPeerDeletePending);
        assert(Ap6256TalPeerCreate(&c,a));assert(creates==3 && !memcmp(last_created,a,6));
    }
    if(!strcmp(test,"all") || !strcmp(test,"peer-confirm")) {

        setup(c);pending_delete=true;receive(c,a,0);
        delete_hook=[&]{Ap6256TalTxRxPeerDeleteConfirm(&c,0,0);};
        Ap6256TalPeerDelete(&c);
        assert(!c.TalPeerDeletePending && !c.TalPeerCreated && !c.TalRxOpen);
        assert(deletes==1 && c.RxQueueCount==0 && allocated[0]->freed);
        assert(Ap6256TalPeerCreate(&c,b));assert(creates==1);

        setup(c);Ap6256TalPeerDelete(&c);assert(!c.TalPeerDeletePending && deletes==1);
        Ap6256TalPeerDelete(&c);assert(deletes==1);
        setup(c);pending_delete=true;Ap6256TalPeerDelete(&c);
        assert(c.TalPeerDeletePending && !Ap6256TalPeerCreate(&c,b));
        Ap6256TalTxRxPeerDeleteConfirm(&c,0,0);assert(Ap6256TalPeerCreate(&c,b));
        assert(deletes==1 && creates==1);

        setup(c);c.WdiDataApi.PeerDeleteIndication=nullptr;Ap6256TalPeerDelete(&c);
        assert(!c.TalPeerCreated && !c.TalPeerDeletePending && !deletes);
    }
    if(!strcmp(test,"all") || !strcmp(test,"reuse")) {
        for(bool same_mac:{false,true})for(bool deferred:{false,true}) {
            setup(c);peer(c,a);
            build_hook=[&]{pending_delete=deferred;Ap6256TalGoPeerDelete(&c,a);
                if(deferred){assert(!Ap6256TalGoPeerCreate(&c,a,4));
                    Ap6256TalTxRxPeerDeleteConfirm(&c,2,2);}
                peer(c,same_mac?a:b);};
            receive(c,a);
            assert(c.RxQueueCount==0 && allocated.size()==1 && allocated[0]->freed);
            receive(c,same_mac?a:b);drain(c,1);
        }
    }
    if(!strcmp(test,"all") || !strcmp(test,"flush")) {
        for(UINT32 iface:{0u,7u})for(UINT16 port:{(UINT16)0,(UINT16)2,(UINT16)WDI_PORT_ANY}) {
            setup(c);peer(c,a);bool affected=port==WDI_PORT_ANY || port==(iface?2:0);
            build_hook=[&]{Ap6256TalRxFlush(&c,port);};receive(c,a,iface);
            assert(flushes==1 && c.RxQueueCount==(affected?0u:1u));drain(c,affected?0:1);
            receive(c,a,iface);drain(c,1);
        }
    }
    if(!strcmp(test,"all") || !strcmp(test,"station")) {
        setup(c);receive(c,a,0);assert(c.RxQueueCount==1);
        Ap6256TalPeerDelete(&c);assert(c.RxQueueCount==0 && allocated[0]->freed);
        c.TalPeerCreated=c.TalRxOpen=TRUE;receive(c,b,0);drain(c,1);
        setup(c);build_hook=[&]{Ap6256TalPeerDelete(&c);c.TalPeerCreated=c.TalRxOpen=TRUE;};
        receive(c,a,0);assert(c.RxQueueCount==0 && allocated[0]->freed);
    }
    if(!strcmp(test,"all") || !strcmp(test,"controls")) {


        setup(c);peer(c,a);claim_hook=[&]{Ap6256TalGoPeerDelete(&c,a);
            memset(c.Go.Peers,0,sizeof(c.Go.Peers));peer(c,b);};
        receive(c,a);assert(allocated.empty() && !c.RxQueueCount);

        setup(c);peer(c,a);peer(c,other);
        build_hook=[&]{Ap6256TalGoPeerDelete(&c,other);};receive(c,a);drain(c,1);


        setup(c);peer(c,a);queue_hook=[&]{Ap6256TalGoPeerDelete(&c,a);peer(c,b);};
        receive(c,a);assert(queue_hook);queue_hook={};Ap6256TalGoPeerDelete(&c,a);drain(c,0);

        for(UINT32 iface:{0u,7u}) {
            setup(c);peer(c,a);NDIS_STATUS s;
            Ap6256TalRxStop(&c,iface?2:0,&s);assert(s==0);receive(c,a,iface);
            NBL* chain=nullptr;Ap6256TalRxGetMpdus(&c,WDI_PEER_ANY,31,&chain);assert(!chain && c.RxQueueCount==1);
            Ap6256TalRxRestart(&c,iface?2:0);drain(c,1);
        }


        setup(c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;memcpy(c.Go.ClientBssid,a,6);peer(c,a);
        receive(c,b);drain(c,1);
        build_hook=[&]{Ap6256TalGoPeerDelete(&c,a);peer(c,a);};receive(c,b);
        assert(c.RxQueueCount==0 && allocated.back()->freed);
        setup(c);peer(c,a);c.Go.Peers[1].RxOpen=FALSE;receive(c,a);
        assert(c.RxQueueCount==1 && !notifications);c.Go.Peers[1].RxOpen=TRUE;drain(c,1);
        setup(c);c.TalPeerCreated=c.TalRxOpen=FALSE;receive(c,a,0);
        assert(c.RxQueueCount==1 && !notifications);c.TalPeerCreated=c.TalRxOpen=TRUE;drain(c,1);
        setup(c);peer(c,a);fail_build=true;receive(c,a);assert(allocated.empty());
        fail_build=false;receive(c,a,8);assert(allocated.empty());
        c.TalStarted=FALSE;receive(c,a);assert(allocated.empty());
        setup(c);peer(c,a);c.RxBatching=TRUE;
        for(unsigned i=0;i<256;i++)receive(c,a);
        receive(c,a);assert(c.RxQueueCount==256 && allocated.back()->freed);drain(c,256);
    }
    setup(c);puts("PASS: receive lifetime, peer reuse, flush boundaries, port isolation and stop/hold controls");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=output_dir('rx-lifetime'))
    parser.add_argument('--case', default='all')
    args = parser.parse_args()
    (hot, tx) = (module('test-hotspot'), module('test-wdi-transmit'))
    hot.ROOT = args.source_root
    src = args.source_root / 'src'
    header = read_source_text(src / 'ap6256.h', encoding='utf-8')
    tal = read_source_text(src / 'wdi_tal.c', encoding='utf-8')
    wifi = read_source_text(src / 'wifi_ops.h', encoding='utf-8')
    text = PRE + read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    for (source, pattern) in ((header, '^#define AP6256_(?:STATION_PORT|GROUP_PORT|GO_PEERS|GO_CLIENTS)\\s+[^\\n]+'), (wifi, '^#define AP6256_WDI_OPMODE_P2P_(?:GO|CLIENT)\\s+[^\\n]+'), (tal, '^#define RX_(?:PORT|PEER|FIPS_GENERATION)\\([^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += tx.declaration(header, 'AP6256_GO_PEER') + tx.declaration(header, 'AP6256_GO_DATA_STAGE')
    modern = 'AP6256_RX_ROUTE' in tal
    if modern:
        text += tx.declaration(tal, 'AP6256_RX_ROUTE')
    text += MOCK
    text += r'''


static BOOLEAN Ap6256RawGenerationCurrent(Device*,UINT32,ULONG generation,BOOLEAN hostCipher) {return generation==0 && !hostCipher;}
static BOOLEAN Ap6256RawRxRead(Device*,UINT32,const UCHAR*,ULONG,AP6256_FIPS_FRAME_VIEW*,ULONG*,BOOLEAN*) {return FALSE;}
static BOOLEAN Ap6256TalRxOwnerCurrent(Device*,UINT32,NBL*) {return TRUE;}
static __inline BOOLEAN Ap6256FipsSnapshot(Device*,UINT32,AP6256_FIPS_SESSION*) {return FALSE;}
int Ap6256FipsReadEnvelope(const AP6256_FIPS_SESSION*,UCHAR,const UCHAR*,UINT32,AP6256_FIPS_FRAME_VIEW*) {assert(false);return 0;}
'''
    signatures = ['VOID Ap6256TalFlushPortRx(Device* Ctx,UINT16 Port,UINT16 Peer)', 'BOOLEAN Ap6256TalResolveRxPeer(Device* Ctx,UINT32 IfIndex,const UCHAR* Source,AP6256_RX_ROUTE* Route)' if modern else 'BOOLEAN Ap6256TalResolveRxPeer(Device* Ctx,UINT32 IfIndex,const UCHAR* Source,UINT16* Peer,UINT32* PhyId,BOOLEAN* Ready)', 'VOID Ap6256WdiRxIndicate(Device* Ctx,PUCHAR Frame,ULONG Length,UCHAR Priority,UINT32 IfIndex)', 'VOID Ap6256TalRxGetMpdus(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PEER_ID PeerId,WDI_EXTENDED_TID ExTid,PNET_BUFFER_LIST* ppNBL)', 'BOOLEAN Ap6256TalGoPeerCreate(Device* Ctx,const UCHAR* Address,UINT32 PhyId)', 'VOID Ap6256TalGoPeerDelete(Device* Ctx,const UCHAR* Address)', 'VOID Ap6256TalTxRxPeerDeleteConfirm(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId,WDI_PEER_ID PeerId)', 'VOID Ap6256TalPeerDelete(Device* Ctx)', 'VOID Ap6256TalSetBssid(Device* Ctx,const UCHAR* Bssid)', 'BOOLEAN Ap6256TalPeerCreate(Device* Ctx,const UCHAR* Bssid)', 'VOID Ap6256TalRxFlush(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId)', 'VOID Ap6256TalRxStop(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId,NDIS_STATUS* pWifiStatus)', 'VOID Ap6256TalRxRestart(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId)']
    for signature in signatures:
        name = re.search('(Ap6256\\w+)\\(', signature)[1]
        text += signature + '\n' + hot.body('wdi_tal.c', name) + '\n'
    text += TEST
    args.output.mkdir(parents=True, exist_ok=True)
    cpp = args.output / 'tests.cpp'
    write_bytes(cpp, text.encode())
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um')]
    command += [str(cpp), '/Fe:' + str(args.output / 'tests.exe'), '/Fo:' + str(args.output / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    subprocess.run(command, check=True)
    subprocess.run([str(args.output / 'tests.exe'), args.case], check=True)
if __name__ == '__main__':
    main()
