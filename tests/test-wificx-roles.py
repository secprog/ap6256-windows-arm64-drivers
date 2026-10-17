# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute production WiFiCx role routing, packet ownership and peer lifetimes.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]
OUT = output_dir('wificx-roles')
MOCKS = r'''
#include <mutex>
#include <condition_variable>
#include <thread>
#include <atomic>
#include <vector>
#include <array>
#include <algorithm>
#undef min
#undef max
#define TraceWarn(...) ((void)0)
#define TraceError(...) ((void)0)
#define AP6256_STATION_PORT 0u
#define AP6256_GROUP_PORT 2u
#define AP6256_DISCOVERY_PORT 1u
#define AP6256_GO_CLIENTS 8u
#define AP6256_GO_PEERS 9u
#define AP6256_FRAME_MAX 1600u
#define AP6256_TXQ_DEPTH 64u
#define AP6256_RXQ_DEPTH 32u
#define AP6256_WLFC_ANY 0xffffu
#define AP6256_WDI_OPMODE_P2P_CLIENT 8u
#define AP6256_WDI_OPMODE_P2P_GO 16u
#define AP6256_LINK_SPEED 100000000u
#define AP6256_POOL_TAG 1u
#define POOL_FLAG_NON_PAGED 1u
#define SDPCM_SWHDR_LEN 8u
#define SDPCM_DATA_CHANNEL 2u
#define BCDC_DCMD_PROTO_VERSION 2u
#define BCDC_DATA_FLAG_PROTO_SHIFT 4u
#define BCDC_DATA_EXEMPT_NONE 0u
#define BCDC_DATA_EXEMPT_ALWAYS 1u
#define BCDC_DATA_EXEMPT_ON_NO_KEY 2u
#define NT_SUCCESS(s) ((LONG)(s)>=0)
#define STATUS_SUCCESS ((LONG)0)
#define STATUS_INVALID_BUFFER_SIZE ((LONG)0xc0000206)
#define STATUS_BUFFER_TOO_SMALL ((LONG)0xc0000023)
#define STATUS_NOT_SUPPORTED ((LONG)0xc00000bb)
#define STATUS_CONNECTION_DISCONNECTED ((LONG)0xc000020c)
#define STATUS_CANCELLED ((LONG)0xc0000120)
#define STATUS_DEVICE_BUSY ((LONG)0x80000011)
#define STATUS_DEVICE_NOT_READY ((LONG)0xc00000a3)
#define STATUS_POWER_STATE_INVALID ((LONG)0xc00002d3)
#define STATUS_INVALID_DEVICE_STATE ((LONG)0xc0000184)
#define STATUS_INSUFFICIENT_RESOURCES ((LONG)0xc000009a)
typedef LONG NTSTATUS;
typedef int KIRQL;
#define KSPIN_LOCK HostSpinLock
struct HostSpinLock {std::mutex Lock;};
typedef std::mutex AP6256_LOCK;
struct EX_RUNDOWN_REF {std::mutex Lock;std::condition_variable Changed;unsigned Users=0;bool Closed=false;};
static void ExInitializeRundownProtection(EX_RUNDOWN_REF*) {}
static void ExReInitializeRundownProtection(EX_RUNDOWN_REF* r) {std::lock_guard<std::mutex> g(r->Lock);assert(r->Closed && !r->Users);r->Closed=false;}
static BOOLEAN ExAcquireRundownProtection(EX_RUNDOWN_REF* r) {std::lock_guard<std::mutex> g(r->Lock);if(r->Closed)return FALSE;++r->Users;return TRUE;}
static void ExReleaseRundownProtection(EX_RUNDOWN_REF* r) {std::lock_guard<std::mutex> g(r->Lock);assert(r->Users);--r->Users;r->Changed.notify_all();}
static void ExWaitForRundownProtectionRelease(EX_RUNDOWN_REF* r) {std::unique_lock<std::mutex> g(r->Lock);r->Closed=true;r->Changed.wait(g,[&]{return !r->Users;});}
static thread_local unsigned spinDepth;
static void KeAcquireSpinLock(KSPIN_LOCK* l,KIRQL* irql) {l->Lock.lock();++spinDepth;*irql=0;}
static void KeReleaseSpinLock(KSPIN_LOCK* l,KIRQL) {assert(spinDepth);--spinDepth;l->Lock.unlock();}
static void Ap6256LockAcquire(AP6256_LOCK* l) {assert(!spinDepth);l->lock();}
static void Ap6256LockRelease(AP6256_LOCK* l) {l->unlock();}
struct Wifi;typedef Wifi* PAP6256_WIFI;
struct _AP6256_CX_ADAPTER;struct _AP6256_QUEUE_CONTEXT;
typedef _AP6256_CX_ADAPTER* NETADAPTER;
typedef _AP6256_QUEUE_CONTEXT* NETPACKETQUEUE;
typedef NETPACKETQUEUE WDFWORKITEM;
struct NET_EXTENSION {ULONG Value=0;};
'''
BOUNDARY = r'''
struct Device {
    Wifi* Engine=nullptr;KSPIN_LOCK TalStateLock;LONG TxFrames=0;
    KSPIN_LOCK HostFipsLock;AP6256_FIPS_SESSION HostFipsSessions[16]={};UINT32 HostFipsBlockedMask=0;
    struct {BOOLEAN FirmwareReady=TRUE,Started=TRUE,Stopping=FALSE;UINT32 Mode=AP6256_WDI_OPMODE_P2P_GO,IfIndex=7;
        UCHAR Address[6]={};UCHAR ClientBssid[6]={};AP6256_GO_PEER Peers[AP6256_GO_PEERS]={};} Go;
    PVOID WifiDirectDevice=nullptr;UINT16 WifiDirectPortId=19;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi {
    Device* Ctx=nullptr;LONG HardwareAvailable=1,Stopping=0;
    struct {KSPIN_LOCK RoleLock;PAP6256_CX_ADAPTER Roles[2]={};AP6256_LOCK PeerLock;
        BOOLEAN StationPeerCreated=FALSE;UCHAR StationPeerAddress[6]={};ULONGLONG StationPeerGeneration=0;} Model;
};
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->Engine;}
static PAP6256_QUEUE_CONTEXT Ap6256GetQueueContext(WDFWORKITEM q) {return q;}
static WDFWORKITEM WdfWorkItemGetParentObject(WDFWORKITEM q) {return q;}
struct NET_ADAPTER_LINK_STATE {BOOLEAN Up=FALSE;};
#define MediaConnectStateConnected 1
#define MediaDuplexStateFull 1
#define NetAdapterPauseFunctionTypeUnsupported 0
#define NetAdapterAutoNegotiationFlagNone 0
static void NET_ADAPTER_LINK_STATE_INIT(NET_ADAPTER_LINK_STATE* s,ULONG,int,int,int,int) {s->Up=TRUE;}
static void NET_ADAPTER_LINK_STATE_INIT_DISCONNECTED(NET_ADAPTER_LINK_STATE* s) {s->Up=FALSE;}
struct PeerCall {NETADAPTER Role;std::array<UCHAR,6> Address;bool Add;};
static std::vector<PeerCall> peerCalls;
static std::vector<NETADAPTER> rxNotifies,txNotifies,downLinks;
static void WifiAdapterAddPeer(NETADAPTER r,const NET_EUI48_ADDRESS* a) {assert(!spinDepth);PeerCall c={r,{},true};memcpy(c.Address.data(),a->Value,6);peerCalls.push_back(c);}
static void WifiAdapterRemovePeer(NETADAPTER r,const NET_EUI48_ADDRESS* a) {assert(!spinDepth);PeerCall c={r,{},false};memcpy(c.Address.data(),a->Value,6);peerCalls.push_back(c);}
static void NetAdapterSetLinkState(NETADAPTER r,const NET_ADAPTER_LINK_STATE* s) {assert(!spinDepth);if(!s->Up)downLinks.push_back(r);}
static void NetRxQueueNotifyMoreReceivedPacketsAvailable(NETPACKETQUEUE q) {assert(!q->Closing);rxNotifies.push_back(q->Role);}
static void NetTxQueueNotifyMoreCompletedPacketsAvailable(NETPACKETQUEUE q) {assert(!q->Closing);txNotifies.push_back(q->Role);}
struct Cancel {UINT16 Port,Peer;PVOID Cookie;};static std::vector<Cancel> cancels;
static void Ap6256WlfcCancel(Device*,UINT16 p,UINT16 peer,PVOID c) {assert(!spinDepth);cancels.push_back({p,peer,c});}
static void Ap6256WlfcCancelAndWait(Device* d,UINT16 p,UINT16 peer,PVOID c) {Ap6256WlfcCancel(d,p,peer,c);}
static std::vector<NETPACKETQUEUE> scheduled;
static ULONG enqueueCount;
static NET_EUI48_ADDRESS demuxPeer={};static UCHAR demuxPriority=0;
static NET_EUI48_ADDRESS WifiTxQueueGetDemuxPeerAddress(NETPACKETQUEUE q) {assert(q->IsTx && !q->Started);return demuxPeer;}
static UCHAR WifiTxQueueGetDemuxWmmInfo(NETPACKETQUEUE q) {assert(q->IsTx && !q->Started);return demuxPriority;}
static void Ap6256EvtTxWorkItem(WDFWORKITEM);
static void Ap6256CxQueueTx(PAP6256_QUEUE_CONTEXT);
static void Ap6256CxSetRoleLink(PAP6256_WIFI,UINT16,BOOLEAN);
static void Ap6256ModelDeleteStationPeer(PAP6256_WIFI);
static void WdfWorkItemEnqueue(WDFWORKITEM q) {assert(!q->Closing && q->TxRunning && !spinDepth);++enqueueCount;if(std::find(scheduled.begin(),scheduled.end(),q)==scheduled.end())scheduled.push_back(q);}
static void WdfWorkItemFlush(WDFWORKITEM q) {assert(!spinDepth);auto it=std::find(scheduled.begin(),scheduled.end(),q);if(it!=scheduled.end()){scheduled.erase(it);Ap6256EvtTxWorkItem(q);}}
static ULONG Ap6256TxHdrLen(Device*) {return 12;}
static ULONG Ap6256AlignTransfer(Device*,ULONG n) {return (n+3u)&~3u;}
static PUCHAR ExAllocatePool2(ULONG,SIZE_T n,ULONG) {return (PUCHAR)calloc(1,n);}
static void ExFreePoolWithTag(PVOID p,ULONG) {free(p);}
static bool wlfc=true,injectWake=false;
static NTSTATUS nextStatus=0;
struct Tx {UCHAR Priority,Exemption,IfIndex;UINT16 Port,Peer;PVOID Cookie;std::vector<UCHAR> Bytes;};
static std::vector<Tx> transmits;static std::vector<UCHAR> wire;
static BOOLEAN Ap6256WlfcEnabled(Device*) {return (BOOLEAN)wlfc;}
static NTSTATUS Ap6256WlfcEnqueue(Device*,PUCHAR b,ULONG n,UCHAR priority,UCHAR ex,UCHAR idx,UINT16 port,UINT16 peer,PVOID owner,PVOID cookie) {
    assert(!owner && !spinDepth);NTSTATUS result=nextStatus;nextStatus=0;
    if(injectWake){injectWake=false;Ap6256CxQueueTx((PAP6256_QUEUE_CONTEXT)cookie);}
    if(NT_SUCCESS(result))transmits.push_back({priority,ex,idx,port,peer,cookie,std::vector<UCHAR>(b,b+n)});
    return result;
}
static NTSTATUS Ap6256DatapathSendSdpcm(Device*,PUCHAR b,ULONG n) {wire.assign(b,b+n);return STATUS_SUCCESS;}
'''
TEST = r'''
static void roleInit(PAP6256_CX_ADAPTER r,Wifi* w,UINT16 logical,UINT16 external) {
    r->Wifi=w;r->Adapter=r;r->LogicalPort=logical;r->PortId=external;r->Ready=1;r->Registered=TRUE;r->Generation=1;
    ExInitializeRundownProtection(&r->Rundown);w->Model.Roles[logical==AP6256_STATION_PORT?0:1]=r;
}
static void queueInit(PAP6256_QUEUE_CONTEXT q,PAP6256_CX_ADAPTER r,bool tx,ULONG slot=0) {
    q->Wifi=r->Wifi;q->Role=r;q->Queue=q;q->TxWorkItem=q;q->IsTx=(BOOLEAN)tx;q->TxEnabled=(LONG)tx;q->NotificationEnabled=1;q->Started=1;
    ExInitializeRundownProtection(&q->Rundown);if(tx)r->TxQueues[slot]=q;else r->RxQueue=q;
}
int main() {
    auto w=new Wifi{};auto d=new Device{};w->Ctx=d;d->Engine=w;
    auto sta=new AP6256_CX_ADAPTER{};auto group=new AP6256_CX_ADAPTER{};
    roleInit(sta,w,0,37);roleInit(group,w,2,2);
    auto sx=new AP6256_QUEUE_CONTEXT{};auto gx=new AP6256_QUEUE_CONTEXT{};
    auto sr=new AP6256_QUEUE_CONTEXT{};auto gr=new AP6256_QUEUE_CONTEXT{};
    queueInit(sx,sta,true);queueInit(gx,group,true);queueInit(sr,sta,false);queueInit(gr,group,false);
    UCHAR ap[6]={2,1,2,3,4,5},client[6]={2,9,8,7,6,5},other[6]={2,4,4,4,4,4};
    memcpy(sx->PeerAddress,ap,6);memcpy(gx->PeerAddress,client,6);
    assert(Ap6256ModelCreateStationPeer(w,ap));assert(peerCalls.size()==2 && sta->DataEnabled);
    assert(Ap6256CxGroupPeerCreate(d,client,4));assert(peerCalls.size()==4 && group->DataEnabled);
    assert(Ap6256CxGroupPeerCreate(d,client,4) && peerCalls.size()==4);
    WDI_PORT_ID logical=0;
    assert(Ap6256CxInternalPort(w,37,&logical)==0 && logical==0);
    assert(Ap6256CxInternalPort(w,2,&logical)==0 && logical==2);
    d->WifiDirectDevice=w;assert(Ap6256CxInternalPort(w,19,&logical)==0 && logical==1);
    assert(Ap6256CxInternalPort(w,0xffff,&logical)==0 && logical==0xffff);
    assert(Ap6256CxInternalPort(w,0,&logical)==STATUS_INVALID_DEVICE_STATE);
    group->Closing=1;assert(Ap6256CxInternalPort(w,2,&logical)==STATUS_INVALID_DEVICE_STATE);group->Closing=0;
    AP6256_FRAME sf={},gf={};sf.Length=gf.Length=60;
    NET_PACKET_WIFI_EXEMPTION_ACTION ex={};
    for(UCHAR priority=0;priority<8;++priority)for(ULONG action=0;action<3;++action) {
        sx->Priority=gx->Priority=priority;ex.ExemptionAction=(UINT8)action;
        assert(Ap6256CxPrepareTx(sx,&ex,&sf)==0 && sf.Priority==priority && sf.Exemption==action);
        assert(Ap6256CxPrepareTx(gx,&ex,&gf)==0 && gf.Priority==priority && gf.Exemption==action && gf.Peer==2);
        assert(Ap6256CxTransmit(sx,&sf)==0 && transmits.back().IfIndex==0 && transmits.back().Port==0);
        assert(Ap6256CxTransmit(gx,&gf)==0 && transmits.back().IfIndex==7 && transmits.back().Port==2 && transmits.back().Peer==2 && transmits.back().Cookie==gx);
        wlfc=false;assert(Ap6256CxTransmit(gx,&gf)==0);auto b=(BCDC_DATA_HEADER*)(wire.data()+12);
        assert(b->Flags==((2u<<4)|action) && b->Priority==priority && b->Flags2==7 && wire.size()>=76);
        auto hw=(SDPCM_HW_HEADER*)wire.data();assert(hw->FrameLength==76 && ((UINT32)hw->FrameLengthInverted ^ hw->FrameLength)==0xffffu);
        wlfc=true;
    }
    ex.ExemptionAction=(UINT8)3;assert(Ap6256CxPrepareTx(gx,&ex,&gf)==STATUS_NOT_SUPPORTED);
    ex.ExemptionAction=WDI_EXEMPT_ALWAYS;gx->Priority=8;assert(Ap6256CxPrepareTx(gx,&ex,&gf)==STATUS_INVALID_PARAMETER);gx->Priority=6;
    UCHAR frame[60]={};memcpy(frame+6,client,6);
    Ap6256NetRxIndicate(d,frame,60,6,7);assert(gr->Role->RxHead==0);
    Ap6256CxGroupRxOpen(d,client);Ap6256NetRxIndicate(d,frame,60,6,7);
    assert(group->RxHead==1 && sta->RxHead==0 && group->RxPending[0].Peer==2 && group->RxPending[0].Priority==6 && !memcmp(group->RxPending[0].Data,frame,60));
    Ap6256NetRxIndicate(d,frame,60,0,0);assert(sta->RxHead==1 && group->RxHead==1);
    Ap6256NetRxIndicate(d,frame,60,0,8);assert(sta->RxHead==1 && group->RxHead==1);
    Ap6256NetRxIndicate(d,frame,13,0,0);Ap6256NetRxIndicate(d,frame,60,8,7);assert(sta->RxHead==1 && group->RxHead==1);

    d->Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;memcpy(d->Go.ClientBssid,client,6);memcpy(frame+6,other,6);
    Ap6256NetRxIndicate(d,frame,60,5,7);assert(group->RxHead==2 && group->RxPending[1].Peer==2);
    d->Go.Mode=AP6256_WDI_OPMODE_P2P_GO;
    assert(Ap6256CxPrepareTx(gx,&ex,&gf)==0);auto old=gf;auto stationGeneration=w->Model.StationPeerGeneration;
    Ap6256CxGroupPeerDelete(d,client);assert(!Ap6256CxFrameCurrent(group,&old) && Ap6256CxTransmit(gx,&old)==STATUS_CANCELLED);
    assert(w->Model.StationPeerGeneration==stationGeneration && Ap6256CxFrameCurrent(sta,&sf));
    assert(Ap6256CxGroupPeerCreate(d,client,4));Ap6256CxGroupRxOpen(d,client);
    assert(Ap6256CxPrepareTx(gx,&ex,&gf)==0 && gf.PeerGeneration!=old.PeerGeneration && !Ap6256CxFrameCurrent(group,&old));

    gx->TxPending[0]=gf;gx->TxHead=1;nextStatus=STATUS_DEVICE_BUSY;injectWake=true;ULONG before=enqueueCount;
    Ap6256CxQueueTx(gx);Ap6256CxQueueTx(gx);assert(enqueueCount==before+1);
    WdfWorkItemFlush(gx);assert(gx->TxTail==1 && !gx->TxRunning && !injectWake);

    gx->TxPending[1]=gf;gx->TxHead=2;nextStatus=STATUS_DEVICE_BUSY;
    Ap6256CxQueueTx(gx);WdfWorkItemFlush(gx);assert(gx->TxTail==1 && !gx->TxRunning);
    Ap6256CxQueueTx(gx);WdfWorkItemFlush(gx);assert(gx->TxTail==2);

    auto restarted=new AP6256_QUEUE_CONTEXT{};queueInit(restarted,group,true,1);
    restarted->TxPending[0]=gf;restarted->TxHead=1;Ap6256EvtQueueStop(restarted);
    assert(!restarted->Started && !restarted->TxEnabled && restarted->TxTail==1 && !restarted->Closing && !Ap6256CxAcquireQueue(group,1));
    memcpy(demuxPeer.Value,client,6);demuxPriority=3;Ap6256EvtQueueStart(restarted);
    assert(restarted->Started && restarted->TxEnabled && restarted->Priority==3 && !memcmp(restarted->PeerAddress,client,6));
    assert(Ap6256CxAcquireQueue(group,1)==restarted);ExReleaseRundownProtection(&restarted->Rundown);

    sx->TxPending[0]=sf;sx->TxHead=1;gx->TxPending[2]=gf;gx->TxHead=3;
    ULONG stationRx=sta->RxHead;auto n=cancels.size();Ap6256CxQuiesceRole(w,2);
    assert(group->RxTail==group->RxHead && gx->TxTail==gx->TxHead && !group->DataEnabled && sta->DataEnabled && sx->TxTail==0 && sta->RxHead==stationRx);
    for(auto i=n;i<cancels.size();++i)assert(cancels[i].Port==2);
    assert(Ap6256CxFrameCurrent(sta,&sf) && !Ap6256CxFrameCurrent(group,&gf));

    auto held=Ap6256CxAcquireQueue(sta,0);assert(held==sx);std::atomic<bool> finished=false;
    std::thread cancel([&]{Ap6256CxUnpublishQueue(sx);finished=true;});
    while(!InterlockedCompareExchange(&sx->Closing,0,0))std::this_thread::yield();
    assert(!finished && !Ap6256CxAcquireQueue(sta,0));ExReleaseRundownProtection(&held->Rundown);cancel.join();assert(finished && !sta->TxQueues[0]);
    assert(Ap6256CxAcquireQueue(group,0)==gx);ExReleaseRundownProtection(&gx->Rundown);
    auto additions=peerCalls.size();d->Go.Started=FALSE;assert(!Ap6256CxGroupPeerCreate(d,other,4) && peerCalls.size()==additions);d->Go.Started=TRUE;
    d->Engine=nullptr;assert(!Ap6256CxGroupPeerCreate(d,other,4));d->Engine=w;
    Ap6256CxGroupPeerDelete(d,nullptr);assert(sta->DataEnabled && w->Model.StationPeerCreated);
    Ap6256ModelDeleteStationPeer(w);assert(!sta->DataEnabled && !w->Model.StationPeerCreated);
    assert(!spinDepth && scheduled.empty());
    printf("PASS: production role/ifindex isolation, all 24 WMM/exemption combinations on WLFC and direct wire TX, client RX, peer reuse, stale packets, TX wake handoff, busy retry, scoped quiesce and concurrent queue rundown\n");
    delete sx;delete gx;delete sr;delete gr;delete restarted;delete sta;delete group;delete w;delete d;
}
'''

def typed(text, name):
    return re.search('typedef (?:struct|union) _' + name + '\\s*\\{[\\s\\S]*?\\} ' + name + '(?:, \\*P' + name + ')?;', text)[0] + '\n'

def build_source():
    spec = importlib.util.spec_from_file_location('cap', AP / 'tests/test-wdi-capabilities.py')
    cap = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cap)
    text = '#pragma warning(disable:4505)\n' + cap.PREAMBLE.split('struct Device {')[0] + MOCKS
    internal = (AP / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig')
    for name in ('AP6256_FRAME_MAX', 'AP6256_TXQ_DEPTH', 'AP6256_RXQ_DEPTH', 'AP6256_MAX_TX_FRAGMENTS'):
        declaration = re.search('^#define ' + name + '[^\\n]+', internal, re.M)[0]
        prior = re.search('^#define ' + name + '[^\\n]+', text, re.M)
        text = text.replace(prior[0], declaration) if prior else text + declaration + '\n'
    types = (INC / 'km/netcx/kmdf/adapter/2.5/netadaptercxtypes.h').read_text(encoding='utf-8-sig')
    text += typed(types, 'NET_EUI48_ADDRESS')
    ext = (INC / 'shared/netcx/shared/1.0/net/wifi/exemptionactiontypes.h').read_text(encoding='utf-8-sig')
    text += typed(ext, 'NET_PACKET_WIFI_EXEMPTION_ACTION')
    hdr = (AP / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    text += typed(hdr, 'AP6256_GO_PEER')
    wire = (AP / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    text += '#pragma pack(push,1)\n'
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'BCDC_DATA_HEADER'):
        text += typed(wire, name)
    text += '#pragma pack(pop)\n'
    text += (AP / 'src/common/host_fips_wire.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    text += (AP / 'src/wificx/netmodel_state.h').read_text(encoding='utf-8-sig').split('typedef struct _AP6256_MODEL_STATE')[0].replace('#pragma once', '')
    text += (AP / 'src/common/host_fips_wire.c').read_text(encoding='utf-8-sig').replace('#include "host_fips_wire.h"', '')
    text += BOUNDARY
    fips = _functions((AP / 'src/common/host_fips.c').read_text(encoding='utf-8-sig'))
    for name in ('Ap6256FipsSnapshot', 'Ap6256FipsActive', 'Ap6256FipsPrepareTx', 'Ap6256FipsTxCurrent'):
        text += fips[name] + '\n'
    text += r'''

#define Ap6256RawTxCurrent Ap6256FipsTxCurrent
#define Ap6256RawPrepareTx Ap6256FipsPrepareTx
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) {return FALSE;}


static BOOLEAN Ap6256RawGenerationCurrent(Device* d,UINT32 i,ULONG g,BOOLEAN hc) {
 AP6256_FIPS_SESSION s;
 if(hc)return FALSE;
 return g?Ap6256FipsSnapshot(d,i,&s)&&s.Generation==g:!Ap6256FipsActive(d,i);
}
static BOOLEAN Ap6256RawRxRead(Device* d,UINT32 i,const UCHAR* p,ULONG n,
 AP6256_FIPS_FRAME_VIEW* v,ULONG* g,BOOLEAN* hc) {
 AP6256_FIPS_SESSION s;memset(v,0,sizeof(*v));*g=0;*hc=FALSE;
 if(!Ap6256FipsSnapshot(d,i,&s)||!Ap6256FipsReadEnvelope(&s,2,p,n,v))return FALSE;
 *g=s.Generation;return TRUE;
}
static BOOLEAN Ap6256RawRxFrame(Device* d,UINT32 i,ULONG g,BOOLEAN hc,const UCHAR* p,ULONG n,AP6256_FIPS_FRAME_VIEW* v) {
 AP6256_FIPS_SESSION s;return Ap6256RawGenerationCurrent(d,i,g,hc)&&Ap6256FipsSnapshot(d,i,&s)&&Ap6256FipsValidateFrame(&s,2,p,n,v);
}
'''
    text += (AP / 'src/common/native_frame.inc').read_text(encoding='utf-8-sig')
    functions = _functions((AP / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig') + '\n' + (AP / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig') + '\n' + (AP / 'src/common/datapath.c').read_text(encoding='utf-8-sig'))
    names = ('Ap6256DatapathTransmitEx', 'Ap6256CxAcquireRole', 'Ap6256CxAcquireQueue', 'Ap6256CxStampFrame', 'Ap6256CxFrameCurrent', 'Ap6256CxEncapsulateRx', 'Ap6256CxPrepareTx', 'Ap6256CxTransmit', 'Ap6256NetRxIndicate', 'Ap6256CxQueueTx', 'Ap6256CxNotifyTx', 'Ap6256EvtTxWorkItem', 'Ap6256CxSetRoleLink', 'Ap6256CxQuiesceRole', 'Ap6256EvtQueueStart', 'Ap6256CxStopQueue', 'Ap6256EvtQueueStop', 'Ap6256CxUnpublishQueue', 'Ap6256CxAddGroupPeerLocked', 'Ap6256CxGroupPeerCreate', 'Ap6256CxGroupPeerDelete', 'Ap6256CxGroupRxOpen', 'Ap6256CxInternalPort', 'Ap6256ModelDeleteStationPeer', 'Ap6256ModelCreateStationPeer')
    for name in names:
        text += functions[name].replace('static VOID Ap6256ModelDeleteStationPeer', 'VOID Ap6256ModelDeleteStationPeer') + '\n'
    return (text, names)

def main():
    (text, names) = build_source()
    text += TEST
    OUT.mkdir(parents=True, exist_ok=True)
    cpp = OUT / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(OUT / 'tests.exe'), '/Fo:' + str(OUT / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    write_text(OUT / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    subprocess.run([str(OUT / 'tests.exe')], check=True, timeout=30)
    receipt = {'functions': list(names), 'board_verified': False, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'checks': 'role/routing/exemption/peer/wake/rundown', 'result': 'passed'}
    write_text(OUT / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
if __name__ == '__main__':
    main()
