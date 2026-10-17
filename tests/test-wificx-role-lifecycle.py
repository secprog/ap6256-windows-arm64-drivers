# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Production WiFiCx adapter factory, disposal and asynchronous role admission.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
base = module('roles_base', ROOT / 'tests/test-wificx-roles.py')
OUT = output_dir('wificx-role-lifecycle')
EXTRA = r'''
#include <map>
static bool engineChildrenLive=true;
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceInfo(...) ((void)0)
#define AP6256_CMDQ_OK(w) TRUE
#define AP6256_AP_CAN_SUSTAIN_IHV 1u
#define STATUS_OBJECT_NAME_COLLISION ((LONG)0xc0000035)
#define STATUS_DEVICE_HARDWARE_ERROR ((LONG)0xc0000185)
#define MAXUSHORT 65535u
struct Device;
typedef Device* WDFDEVICE;
typedef PVOID WDFOBJECT;
typedef PVOID AP6256_REQUEST;
struct NETTXQUEUE_INIT {};struct NETRXQUEUE_INIT {};
struct NETADAPTER_INIT {WIFI_ADAPTER_TYPE Type;UINT32 Port;UINT8 PeerRange=0;bool Wmm=false;};
struct NativeP2p {UCHAR DeviceAddress[6]={2,1,2,3,4,9};PVOID DriverIes[4]={},HostIes[4]={};};
struct Task {BOOLEAN Active=FALSE;WDI_MESSAGE_HEADER Header={};ULONGLONG DeadlineMs=0;PVOID RequestId=nullptr;};
struct NET_ADAPTER_DATAPATH_CALLBACKS {int Value;};
struct WIFI_ADAPTER_TX_DEMUX {UINT8 Range=0;bool Wmm=false;};
struct WDF_OBJECT_ATTRIBUTES {int ExecutionLevel=0;void(*EvtCleanupCallback)(WDFOBJECT)=nullptr;};
struct NET_ADAPTER_LINK_LAYER_CAPABILITIES {int Value;};
struct NET_ADAPTER_LINK_LAYER_ADDRESS {USHORT Length=0;UCHAR Address[32]={};};
struct NET_ADAPTER_TX_CAPABILITIES {ULONG QueueCount=0,MaximumNumberOfFragments=0;};
struct NET_ADAPTER_RX_CAPABILITIES {ULONG MaximumFrameSize=0;};
#define AP6256_MAX_TX_FRAGMENTS 16u
#define AP6256_WDI_OPMODE_STA 1u
static void KeInitializeSpinLock(KSPIN_LOCK*) {}
static void ExFreePoolWithTag(PVOID p,ULONG) {free(p);}
#define WdfExecutionLevelPassive 0
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(a,t) (*(a)=WDF_OBJECT_ATTRIBUTES{})
#define NET_ADAPTER_DATAPATH_CALLBACKS_INIT(c,t,r) ((void)(c),(void)(&(t)),(void)(&(r)))
static void WIFI_ADAPTER_TX_PEER_ADDRESS_DEMUX_INIT(WIFI_ADAPTER_TX_DEMUX* d,UINT8 n) {d->Range=n;d->Wmm=false;}
static void WIFI_ADAPTER_TX_WMMINFO_DEMUX_INIT(WIFI_ADAPTER_TX_DEMUX* d) {d->Wmm=true;}
static void WifiAdapterInitAddTxDemux(NETADAPTER_INIT* i,WIFI_ADAPTER_TX_DEMUX* d) {if(d->Wmm)i->Wmm=true;else i->PeerRange=d->Range;}
static WIFI_ADAPTER_TYPE WifiAdapterInitGetType(NETADAPTER_INIT* i) {return i->Type;}
static void NetAdapterInitSetDatapathCallbacks(NETADAPTER_INIT*,NET_ADAPTER_DATAPATH_CALLBACKS*) {}
static void NET_ADAPTER_LINK_LAYER_CAPABILITIES_INIT(NET_ADAPTER_LINK_LAYER_CAPABILITIES*,ULONG,ULONG) {}
static void NET_ADAPTER_TX_CAPABILITIES_INIT(NET_ADAPTER_TX_CAPABILITIES* c,ULONG n) {c->QueueCount=n;}
static void NET_ADAPTER_RX_CAPABILITIES_INIT_SYSTEM_MANAGED(NET_ADAPTER_RX_CAPABILITIES* c,ULONG n,ULONG) {c->MaximumFrameSize=n;}
static void NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(NET_ADAPTER_LINK_LAYER_ADDRESS* a,USHORT n,const UCHAR* p) {a->Length=n;memcpy(a->Address,p,n);}
'''
BOUNDARY = r'''
static void Ap6256EvtTxWorkItem(WDFWORKITEM) {assert(false);}
static LONG engineRefs=0;
static NTSTATUS createStatus=0,initializeStatus=0,startStatus=0,nativeCreateStatus=0,nativeDeleteStatus=0,hardwareStatus=0;
static bool nativeRollbackUncertain=false;
static unsigned engineCreates=0,adapterCreates=0,disposes=0,nativeCreates=0,nativeDeletes=0,stationDisconnects=0,halts=0;
static unsigned processEvents=0,clearEvents=0,queuedEvents=0,assocTimeouts=0,clientLinks=0,clientTimeouts=0;
static unsigned groupCancels=0,actionCancels=0,ftmCancels=0,scanAborts=0;
static ULONG ftmPort=0;
static UINT64 clockNow=0;
static bool blockEvent=false,eventEntered=false,eventRelease=false;
static std::mutex eventLock;static std::condition_variable eventChanged;
static std::map<NETADAPTER,NETADAPTER_INIT*> inits;
static std::map<NETADAPTER,NET_ADAPTER_LINK_LAYER_ADDRESS> currentAddresses,permanentAddresses;
static std::map<NETADAPTER,ULONG> queueCounts;
static std::vector<UINT16> failedPorts;
static NETADAPTER lastAdapter=nullptr;
static NTSTATUS Ap6256QualityForgetPort(Device*,UINT32) {return STATUS_SUCCESS;}
static PAP6256_DEVICE_CONTEXT Ap6256GetDeviceContext(WDFDEVICE d) {return d;}
static PAP6256_CX_ADAPTER Ap6256GetRoleContext(WDFOBJECT o) {return (PAP6256_CX_ADAPTER)o;}
static void WdfObjectReference(WDFOBJECT) {++engineRefs;}
static void WdfObjectDereference(WDFOBJECT) {assert(engineRefs>0);--engineRefs;}
static void Ap6256EvtAdapterCleanup(WDFOBJECT);
static void WdfObjectDelete(NETADAPTER a) {Ap6256EvtAdapterCleanup(a);++disposes;}
static NTSTATUS Ap6256CxCreateEngine(Device*) {++engineCreates;return STATUS_INSUFFICIENT_RESOURCES;}
static NTSTATUS NetAdapterCreate(NETADAPTER_INIT* i,WDF_OBJECT_ATTRIBUTES* attrs,NETADAPTER* out) {
    ++adapterCreates;assert(attrs->EvtCleanupCallback==Ap6256EvtAdapterCleanup);
    if(!NT_SUCCESS(createStatus))return createStatus;
    lastAdapter=new AP6256_CX_ADAPTER{};lastAdapter->Adapter=lastAdapter;inits[lastAdapter]=i;*out=lastAdapter;return 0;
}
static NTSTATUS WifiAdapterInitialize(NETADAPTER a) {assert(inits.count(a));return initializeStatus;}
static UINT32 WifiAdapterGetPortId(NETADAPTER a) {return inits.at(a)->Port;}
static void NetAdapterSetLinkLayerCapabilities(NETADAPTER,NET_ADAPTER_LINK_LAYER_CAPABILITIES*) {}
static void NetAdapterSetLinkLayerMtuSize(NETADAPTER,ULONG n) {assert(n==1500);}
static void NetAdapterSetPermanentLinkLayerAddress(NETADAPTER a,NET_ADAPTER_LINK_LAYER_ADDRESS* p) {permanentAddresses[a]=*p;}
static void NetAdapterSetCurrentLinkLayerAddress(NETADAPTER a,NET_ADAPTER_LINK_LAYER_ADDRESS* p) {assert(!spinDepth);currentAddresses[a]=*p;}
static void NetAdapterSetDataPathCapabilities(NETADAPTER a,NET_ADAPTER_TX_CAPABILITIES* tx,NET_ADAPTER_RX_CAPABILITIES* rx) {
    auto i=inits.at(a);assert(i->Wmm && i->PeerRange);

    assert(tx->QueueCount>=(ULONG)i->PeerRange*8u+1u);
    assert(tx->MaximumNumberOfFragments==16 && rx->MaximumFrameSize==8192);queueCounts[a]=tx->QueueCount;
}
static NTSTATUS NetAdapterStart(NETADAPTER a) {assert(!a->Ready && a->Registered && a->Wifi->Model.Roles[a->LogicalPort==0?0:1]==a);return startStatus;}
static NTSTATUS Ap6256EvtCreateTxQueue(NETADAPTER,NETTXQUEUE_INIT*) {return 0;}
static NTSTATUS Ap6256EvtCreateRxQueue(NETADAPTER,NETRXQUEUE_INIT*) {return 0;}
static NTSTATUS Ap6256GoCreate(Device* d) {++nativeCreates;if(!NT_SUCCESS(nativeCreateStatus)){d->Go.NativeStateUncertain=(BOOLEAN)nativeRollbackUncertain;return nativeCreateStatus;}d->Go.FirmwareReady=TRUE;return 0;}
static NTSTATUS Ap6256GoDelete(Device* d) {++nativeDeletes;if(NT_SUCCESS(nativeDeleteStatus))d->Go.FirmwareReady=FALSE;return nativeDeleteStatus;}
static NTSTATUS Ap6256GoStop(Device* d) {d->Go.Started=FALSE;return 0;}
static NTSTATUS Ap6256WifiDisconnect(Device*) {++stationDisconnects;return 0;}
static NTSTATUS Ap6256NetHardwareStart(Device* d) {if(NT_SUCCESS(hardwareStatus))d->Engine->HardwareAvailable=1;return hardwareStatus;}
static void Ap6256NetFirmwareHalted(Device* d) {++halts;d->Engine->HardwareAvailable=0;}
static void Ap6256WifiCxSetPowerCapabilities(NETADAPTER,Device*) {}
static void Ap6256RecomputePortModes(Wifi*) {}
static void Ap6256P2pReleaseIesFor(Device*,NativeP2p*,UINT32) {}
static void Ap6256StationAuthStop(Wifi*) {assert(engineChildrenLive);}
static NTSTATUS Ap6256CancelClientLocked(Wifi*,NTSTATUS,UINT32) {assert(engineChildrenLive);++groupCancels;return 0;}
static void Ap6256CancelGoAssociation(Wifi*,NTSTATUS) {assert(engineChildrenLive);}
static void Ap6256P2pForgetIesFor(NativeP2p*) {}
static UINT16 Ap6256ConnectCompletionId(Wifi*) {return 2;}
static void Ap6256FailStartedTask(Wifi*,Task* t,UINT16,NTSTATUS) {if(t->Active)failedPorts.push_back(t->Header.PortId);t->Active=FALSE;}
static void timerStop(PVOID,BOOLEAN) {assert(engineChildrenLive);}
#define AP6256_TIMER_STOP timerStop
static NTSTATUS Ap6256WifiScanAbort(Device*) {++scanAborts;return 0;}
static void Ap6256CancelActionFrame(Wifi* w,NTSTATUS) {assert(engineChildrenLive);++actionCancels;w->ActionFrameTask.Active=FALSE;}
static NTSTATUS Ap6256FtmCancel(Wifi* w,BOOLEAN,UINT32,ULONG port,NTSTATUS) {++ftmCancels;ftmPort=port;w->Ftm.Task.Active=FALSE;return 0;}
static void Ap6256ProcessGoEvent(Wifi*,PVOID) {
    ++processEvents;std::unique_lock<std::mutex> g(eventLock);eventEntered=true;eventChanged.notify_all();
    if(blockEvent)eventChanged.wait(g,[]{return eventRelease;});
}
static void Ap6256ClearGoEvents(Wifi*) {++clearEvents;}
static void Ap6256NetApStopped(Device*,UINT32) {}
static void Ap6256CxQueueGoEvent(Device*,UINT32,UINT32,UINT32,UINT16,const UCHAR*,const UCHAR*,ULONG) {++queuedEvents;}
static void Ap6256CxApAssocTimeout(Wifi*) {++assocTimeouts;}
static void Ap6256CxClientLinkWork(Wifi*,BOOLEAN,LONG) {++clientLinks;}
static void Ap6256CxClientConnectTimeout(Wifi*) {++clientTimeouts;}
static NTSTATUS Ap6256WifiP2pSetDiscoveryInterface(Device*,BOOLEAN,PVOID) {return 0;}
'''
TEST = r'''
static void resetFaults() {createStatus=initializeStatus=startStatus=nativeCreateStatus=nativeDeleteStatus=hardwareStatus=0;nativeRollbackUncertain=false;}
static NETADAPTER create(Wifi* w,WIFI_ADAPTER_TYPE type,UINT32 port,NTSTATUS expected=0) {
    auto init=new NETADAPTER_INIT{type,port};auto before=lastAdapter;
    NTSTATUS status=Ap6256EvtWifiCreateAdapter(w->Ctx,init);assert(status==expected);
    if(!NT_SUCCESS(status))return nullptr;assert(lastAdapter!=before);return lastAdapter;
}
int main() {
    auto w=new Wifi{};auto d=new Device{};d->Engine=w;w->Ctx=d;w->Model.Object=w;w->CommandWorkItem=(WDFWORKITEM)1;w->LinkWorkItem=(WDFWORKITEM)2;w->ActionFrameCompleteWorker=(WDFWORKITEM)3;
    UCHAR stationMac[6]={2,1,1,1,1,1};memcpy(d->MacAddress,stationMac,6);
    unsigned oldCreates=adapterCreates;
    create(w,(WIFI_ADAPTER_TYPE)99,37,STATUS_NOT_SUPPORTED);assert(adapterCreates==oldCreates && engineRefs==0);
    d->FirmwareP2pSupported=FALSE;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,73,STATUS_NOT_SUPPORTED);d->FirmwareP2pSupported=TRUE;
    d->Engine=nullptr;create(w,WIFI_ADAPTER_EXTENSIBLE_STATION,37,STATUS_INSUFFICIENT_RESOURCES);assert(engineCreates==1 && engineRefs==0);d->Engine=w;
    createStatus=STATUS_INSUFFICIENT_RESOURCES;create(w,WIFI_ADAPTER_EXTENSIBLE_STATION,37,createStatus);assert(engineRefs==0);resetFaults();
    initializeStatus=STATUS_NOT_SUPPORTED;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,73,initializeStatus);
    assert(engineRefs==0 && nativeCreates==0 && stationDisconnects==0 && !w->Model.Roles[1]);resetFaults();
    for(UINT32 port:{65535u,65536u}){create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,port,STATUS_NOT_SUPPORTED);assert(engineRefs==0 && !nativeCreates);}
    d->WifiDirectDevice=w;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,19,STATUS_NOT_SUPPORTED);assert(engineRefs==0);
    auto sta=create(w,WIFI_ADAPTER_EXTENSIBLE_STATION,37);assert(engineRefs==1 && sta->Ready && sta->LogicalPort==0 && w->Model.Adapter==sta && d->NetAdapter==sta && queueCounts[sta]==17);
    sta->DataEnabled=1;w->Model.StationPeerCreated=TRUE;w->Model.StationPeerGeneration=23;
    const auto stationGeneration=w->Model.StationPeerGeneration;
    create(w,WIFI_ADAPTER_EXTENSIBLE_STATION,39,STATUS_OBJECT_NAME_COLLISION);
    create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,37,STATUS_NOT_SUPPORTED);assert(engineRefs==1 && stationDisconnects==0);
    nativeCreateStatus=STATUS_DEVICE_NOT_READY;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,73,nativeCreateStatus);
    assert(engineRefs==1 && sta->DataEnabled && w->Model.Roles[0]==sta && !w->Model.Roles[1] && !d->Go.Created);resetFaults();

    auto deletesBefore=nativeDeletes;startStatus=STATUS_DEVICE_NOT_READY;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,73,startStatus);
    assert(nativeDeletes==deletesBefore+1 && engineRefs==1 && !w->Model.Roles[1] && sta->Ready && sta->DataEnabled && w->Model.StationPeerGeneration==stationGeneration);resetFaults();
    auto group=create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,73);assert(engineRefs==2 && group->Ready && group->LogicalPort==2 && queueCounts[group]==73 && d->Go.Created);
    create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,75,STATUS_OBJECT_NAME_COLLISION);
    UCHAR newMac[6]={2,3,4,5,6,7};auto permanent=permanentAddresses[group];memcpy(d->Go.Address,newMac,6);
    Ap6256ModelGroupAddressChanged(w);assert(!memcmp(currentAddresses[group].Address,newMac,6) && !memcmp(currentAddresses[sta].Address,stationMac,6) && !memcmp(permanentAddresses[group].Address,permanent.Address,6));

    UCHAR mac[6]={};Ap6256NetGoEvent(d,1,0,0,0,mac,nullptr,0);assert(queuedEvents==1);
    Ap6256OnApAssocTimeout(w);Ap6256ClientLinkWork(w,TRUE,1);Ap6256OnClientConnectTimeout(w);assert(assocTimeouts==1 && clientLinks==1 && clientTimeouts==1);
    Ap6256ModelProcessCommandEvent(w,calloc(1,16),FALSE);assert(processEvents==1);
    group->Closing=1;Ap6256NetGoEvent(d,1,0,0,0,mac,nullptr,0);Ap6256OnApAssocTimeout(w);Ap6256ClientLinkWork(w,TRUE,1);Ap6256OnClientConnectTimeout(w);Ap6256ModelProcessCommandEvent(w,calloc(1,16),FALSE);
    assert(queuedEvents==1 && assocTimeouts==1 && clientLinks==1 && clientTimeouts==1 && processEvents==1);group->Closing=0;

    w->ScanTask.Active=TRUE;w->ScanTask.Header.PortId=0;w->ActionFrameTask.Active=TRUE;w->ActionFrameTask.Header.PortId=2;
    w->Ftm.Task.Active=TRUE;w->Ftm.Task.Header.PortId=0;
    WdfObjectDelete(group);assert(engineRefs==1 && !w->Model.Roles[1] && w->Model.Roles[0]==sta && sta->Ready && sta->DataEnabled && w->Model.Adapter==sta && d->NetAdapter==sta && !stationDisconnects);
    assert(w->ScanTask.Active && !w->ActionFrameTask.Active && w->Ftm.Task.Active && actionCancels==1 && !scanAborts && !ftmCancels);
    group=create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,77);group->DataEnabled=1;
    WdfObjectDelete(sta);assert(engineRefs==1 && !w->Model.Roles[0] && w->Model.Roles[1]==group && group->Ready && group->DataEnabled && !w->Model.Adapter && !d->NetAdapter && w->HardwareAvailable);
    assert(!w->ScanTask.Active && !w->Ftm.Task.Active && scanAborts==1 && ftmCancels==1 && stationDisconnects==1);
    sta=create(w,WIFI_ADAPTER_EXTENSIBLE_STATION,39);assert(engineRefs==2 && d->NetAdapter==sta);

    WdfObjectDelete(group);w->HardwareAvailable=0;hardwareStatus=STATUS_DEVICE_NOT_READY;deletesBefore=nativeDeletes;
    create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,79,hardwareStatus);assert(nativeDeletes==deletesBefore+1 && engineRefs==1 && w->Model.Roles[0]==sta && !w->Model.Roles[1]);resetFaults();w->HardwareAvailable=1;

    group=create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,81);nativeDeleteStatus=STATUS_DEVICE_NOT_READY;WdfObjectDelete(group);
    assert(d->Go.NativeStateUncertain && !w->HardwareAvailable && !w->Model.Roles[1] && engineRefs==1 && halts);
    auto createsBefore=nativeCreates;create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,83,STATUS_DEVICE_HARDWARE_ERROR);
    assert(nativeCreates==createsBefore && Ap6256ModelStartInterfaces(w,d)==STATUS_DEVICE_HARDWARE_ERROR);resetFaults();

    d->Go.NativeStateUncertain=FALSE;w->HardwareAvailable=1;group=create(w,WIFI_ADAPTER_WIFI_DIRECT_ROLE,83);assert(engineRefs==2);

    blockEvent=true;eventEntered=false;eventRelease=false;std::atomic<bool> disposed{false};
    std::thread event([&]{Ap6256ModelProcessCommandEvent(w,calloc(1,16),FALSE);});
    {std::unique_lock<std::mutex> g(eventLock);eventChanged.wait(g,[]{return eventEntered;});}
    std::thread disposal([&]{WdfObjectDelete(group);disposed=true;});
    while(!InterlockedCompareExchange(&group->Closing,0,0))std::this_thread::yield();assert(!disposed && !Ap6256CxAcquireRole(w,2));
    {std::lock_guard<std::mutex> g(eventLock);eventRelease=true;}eventChanged.notify_all();event.join();disposal.join();
    assert(disposed && engineRefs==1 && !w->Model.Roles[1]);blockEvent=false;

    engineChildrenLive=false;w->Stopping=1;w->HardwareAvailable=0;WdfObjectDelete(sta);assert(engineRefs==0 && !w->Model.Roles[0]);
    puts("PASS WiFiCx production factory, rollback, MAC, event lifetime, scoped tasks and sibling role disposal");
}
'''

def build_source():
    cap = module('cap_lifecycle', ROOT / 'tests/test-wdi-capabilities.py')
    sdk = (base.INC / 'km/wificx/1.2/wificx.h').read_text(encoding='utf-8-sig')
    adapter_type = re.search('typedef enum _WIFI_ADAPTER_TYPE[\\s\\S]*?} WIFI_ADAPTER_TYPE;', sdk)[0]
    wire = (ROOT / 'src/common/host_fips_wire.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    text = '#pragma warning(disable:4505)\n' + cap.PREAMBLE.split('struct Device {')[0] + wire + base.MOCKS + adapter_type + '\n' + EXTRA
    text += base.typed((base.INC / 'km/netcx/kmdf/adapter/2.5/netadaptercxtypes.h').read_text(encoding='utf-8-sig'), 'NET_EUI48_ADDRESS')
    text += base.typed((base.INC / 'shared/netcx/shared/1.0/net/wifi/exemptionactiontypes.h').read_text(encoding='utf-8-sig'), 'NET_PACKET_WIFI_EXEMPTION_ACTION')
    text += base.typed((ROOT / 'src/common/ap6256.h').read_text(encoding='utf-8-sig'), 'AP6256_GO_PEER')
    codec = (ROOT / 'src/common/native_frame.inc').read_text(encoding='utf-8-sig')
    text += codec[:codec.index('static const UCHAR Ap6256Oui')]
    text += (ROOT / 'src/wificx/netmodel_state.h').read_text(encoding='utf-8-sig').split('typedef struct _AP6256_MODEL_STATE')[0].replace('#pragma once', '')
    boundary = base.BOUNDARY
    boundary = boundary.replace('Wifi* Engine=nullptr;', 'Wifi* Engine=nullptr;PVOID NetAdapter=nullptr;BOOLEAN FirmwareP2pSupported=TRUE;UINT16 WifiGroupPortId=0,WifiStationPortId=0;UCHAR MacAddress[6]={};NativeP2p P2p;')
    boundary = boundary.replace('BOOLEAN FirmwareReady=TRUE,Started=TRUE,Stopping=FALSE;', 'BOOLEAN FirmwareReady=FALSE,Started=FALSE,Stopping=FALSE,Created=FALSE,NativeStateUncertain=FALSE,ClientConnected=FALSE;NativeP2p P2p;')
    boundary = boundary.replace('Device* Ctx=nullptr;LONG HardwareAvailable=1,Stopping=0;', 'Device* Ctx=nullptr;LONG HardwareAvailable=1,Stopping=0;BOOLEAN PowerStateDx=FALSE,PortCreated=FALSE,P2pPortCreated=TRUE,ConnectionActive=FALSE,ApStarted=FALSE;ULONG PortNumber=0,StationPortMode=0;Task ScanTask,ConnectTask,DisconnectTask,ActionFrameTask;struct {Task Task;} Ftm;PVOID ScanTimer=nullptr;WDFWORKITEM CommandWorkItem=nullptr,LinkWorkItem=nullptr,ActionFrameCompleteWorker=nullptr;')
    boundary = boundary.replace('AP6256_LOCK PeerLock;', 'AP6256_LOCK PeerLock,AdapterLock,GroupLock;PVOID Object=nullptr;NETADAPTER Adapter=nullptr;')
    boundary = boundary[:boundary.index('static ULONG Ap6256TxHdrLen')]
    boundary = re.sub('^static void WdfWorkItemFlush[^\\n]+$', 'static void WdfWorkItemFlush(WDFWORKITEM q) {assert(q && engineChildrenLive && !spinDepth);}', boundary, flags=re.M)
    text += boundary + BOUNDARY
    source = (ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig')
    functions = _functions(source)
    names = ('Ap6256CxAcquireRole', 'Ap6256CxAcquireQueue', 'Ap6256CxSetRoleLink', 'Ap6256CxQuiesceRole', 'Ap6256CxGroupPeerDelete', 'Ap6256CxCancelRoleTasks', 'Ap6256EvtAdapterCleanup', 'Ap6256EvtWifiCreateAdapter', 'Ap6256ModelGroupAddressChanged', 'Ap6256NetGoEvent', 'Ap6256OnApAssocTimeout', 'Ap6256ClientLinkWork', 'Ap6256OnClientConnectTimeout', 'Ap6256ModelProcessCommandEvent', 'Ap6256ModelStartInterfaces')
    for name in names:
        text += functions[name] + '\n'
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    (text, names) = build_source()
    if None == 'station-budget':
        text = text.replace('slot ? AP6256_CX_TX_QUEUES : AP6256_CX_STA_TX_QUEUES', 'slot ? AP6256_CX_TX_QUEUES : 16u')
    if None == 'group-mac':
        text = text.replace('NetAdapterSetCurrentLinkLayerAddress(role->Adapter, &address);', '(void)address;')
    if None == 'startup-unwind':
        old = r'''    if (role->FirmwareCreated && !wifi->HardwareAvailable && !wifi->Stopping) {
        NTSTATUS rollbackStatus;
        Ap6256LockAcquire(&wifi->Model.GroupLock);
        rollbackStatus = wifi->PowerStateDx ? STATUS_DEVICE_NOT_READY : Ap6256GoDelete(ctx);
        if (NT_SUCCESS(rollbackStatus)) role->FirmwareCreated = FALSE;
        else ctx->Go.NativeStateUncertain = TRUE;
        Ap6256LockRelease(&wifi->Model.GroupLock);
    }
'''
        assert text.count(old) == 1
        text = text.replace(old, '')
    if None == 'event-rundown':
        old = 'if (role) ExReleaseRundownProtection(&role->Rundown);\n    if (Event != NULL)'
        assert text.count(old) == 1
        text = text.replace(old, 'if (Event != NULL)')
        old = 'PAP6256_CX_ADAPTER role = Ap6256CxAcquireRole(wifi, AP6256_GROUP_PORT);\n    if (role &&'
        assert text.count(old) == 1
        text = text.replace(old, 'PAP6256_CX_ADAPTER role = wifi->Model.Roles[1];\n    if (role &&')
    out = OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')], timeout=30)
    assert run.returncode == 0, run.returncode
    write_text(out / 'receipt.json', json.dumps({'result': 'passed', 'negative_control': None, 'functions': names, 'board_verified': False, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest()}, indent=2), encoding='utf-8')
if __name__ == '__main__':
    main()
