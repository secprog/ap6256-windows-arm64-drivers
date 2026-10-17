# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute the actual WiFiCx adapter factory/cleanup with native group and wake paths.'
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
mode = module('factory_mode', ROOT / 'tests/test-wificx-group-mode.py')
life = module('factory_life', ROOT / 'tests/test-wificx-role-lifecycle.py')
OUT = output_dir('wificx-factory-power')
EXTRA = r'''
#include <map>
struct NETTXQUEUE_INIT {};struct NETRXQUEUE_INIT {};
struct NETADAPTER_INIT {WIFI_ADAPTER_TYPE Type;UINT32 Port;UINT8 PeerRange=0;bool Wmm=false;};
struct NET_ADAPTER_DATAPATH_CALLBACKS {int Value;};
struct WIFI_ADAPTER_TX_DEMUX {UINT8 Range=0;bool Wmm=false;};
struct WDF_OBJECT_ATTRIBUTES {int ExecutionLevel=0;void(*EvtCleanupCallback)(WDFOBJECT)=nullptr;};
struct NET_ADAPTER_LINK_LAYER_CAPABILITIES {int Value;};
struct NET_ADAPTER_TX_CAPABILITIES {ULONG QueueCount=0,MaximumNumberOfFragments=0;};
struct NET_ADAPTER_RX_CAPABILITIES {ULONG MaximumFrameSize=0;};
#define AP6256_MAX_TX_FRAGMENTS 16u
#define MAXUSHORT 65535u
#define STATUS_OBJECT_NAME_COLLISION ((LONG)0xc0000035)
#define WdfExecutionLevelPassive 0
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(a,t) (*(a)=WDF_OBJECT_ATTRIBUTES{})
#define NET_ADAPTER_DATAPATH_CALLBACKS_INIT(c,t,r) ((void)(c),(void)(&(t)),(void)(&(r)))
static void KeInitializeSpinLock(KSPIN_LOCK*) {}
static void WIFI_ADAPTER_TX_PEER_ADDRESS_DEMUX_INIT(WIFI_ADAPTER_TX_DEMUX* d,UINT8 n){d->Range=n;d->Wmm=false;}
static void WIFI_ADAPTER_TX_WMMINFO_DEMUX_INIT(WIFI_ADAPTER_TX_DEMUX* d){d->Wmm=true;}
static void WifiAdapterInitAddTxDemux(NETADAPTER_INIT* i,WIFI_ADAPTER_TX_DEMUX* d){if(d->Wmm)i->Wmm=true;else i->PeerRange=d->Range;}
static WIFI_ADAPTER_TYPE WifiAdapterInitGetType(NETADAPTER_INIT* i){return i->Type;}
static void NetAdapterInitSetDatapathCallbacks(NETADAPTER_INIT*,NET_ADAPTER_DATAPATH_CALLBACKS*){}
static void NET_ADAPTER_LINK_LAYER_CAPABILITIES_INIT(NET_ADAPTER_LINK_LAYER_CAPABILITIES*,ULONG,ULONG){}
static void NET_ADAPTER_TX_CAPABILITIES_INIT(NET_ADAPTER_TX_CAPABILITIES* c,ULONG n){c->QueueCount=n;}
static void NET_ADAPTER_RX_CAPABILITIES_INIT_SYSTEM_MANAGED(NET_ADAPTER_RX_CAPABILITIES* c,ULONG n,ULONG){c->MaximumFrameSize=n;}
static void NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(NET_ADAPTER_LINK_LAYER_ADDRESS* a,USHORT n,const UCHAR* p){a->Length=n;memcpy(a->Address,p,n);}
'''
BOUNDARY = r'''
static VOID factoryScheduleWake(Device* d){
 assert(!factoryWakeActor.joinable());
 beforeLock=[d](AP6256_LOCK* lock){if(lock==&d->Engine->Model.GroupLock)factoryActorAtGroup=true;};
 factoryWakeActor=std::thread([d]{factoryWakeStatus=Ap6256WifiCxArmWake(d);});
 while(!factoryActorAtGroup.load())std::this_thread::yield();


 if(!heldLocks.count(&d->Engine->Model.GroupLock))factoryWakeActor.join();
}
static LONG engineRefs=0;
static NTSTATUS createStatus=0,initializeStatus=0,startStatus=0,hardwareStatus=0;
static unsigned adapterCreates=0,disposes=0,hardwareStarts=0;
static bool wakeAtInitialize=false;
static thread_local std::set<AP6256_LOCK*> heldLocks;
static std::map<NETADAPTER,NETADAPTER_INIT*> inits;
static std::map<NETADAPTER,NET_ADAPTER_LINK_LAYER_ADDRESS> currentAddresses,permanentAddresses;
static std::map<NETADAPTER,ULONG> queueCounts;
static std::vector<std::unique_ptr<AP6256_CX_ADAPTER>> allocations;
static NETADAPTER lastAdapter=nullptr;
static PAP6256_CX_ADAPTER Ap6256GetRoleContext(WDFOBJECT o){return (PAP6256_CX_ADAPTER)o;}
static void WdfObjectReference(WDFOBJECT){++engineRefs;}
static void WdfObjectDereference(WDFOBJECT){assert(engineRefs>0);--engineRefs;}
static VOID Ap6256EvtAdapterCleanup(WDFOBJECT);
static void WdfObjectDelete(NETADAPTER a){Ap6256EvtAdapterCleanup(a);++disposes;}
static NTSTATUS Ap6256CxCreateEngine(Device*){assert(false);return STATUS_INSUFFICIENT_RESOURCES;}
static NTSTATUS NetAdapterCreate(NETADAPTER_INIT* i,WDF_OBJECT_ATTRIBUTES* attrs,NETADAPTER* out){
 ++adapterCreates;assert(attrs->EvtCleanupCallback==Ap6256EvtAdapterCleanup);
 if(!NT_SUCCESS(createStatus))return createStatus;
 allocations.push_back(std::make_unique<AP6256_CX_ADAPTER>());lastAdapter=allocations.back().get();
 lastAdapter->Adapter=lastAdapter;inits[lastAdapter]=i;*out=lastAdapter;return 0;
}
static NTSTATUS WifiAdapterInitialize(NETADAPTER a){assert(inits.count(a));if(wakeAtInitialize){wakeAtInitialize=false;assert(Ap6256WifiCxArmWake(a->Wifi->Ctx)==0);}return initializeStatus;}
static UINT32 WifiAdapterGetPortId(NETADAPTER a){return inits.at(a)->Port;}
static void NetAdapterSetLinkLayerCapabilities(NETADAPTER,NET_ADAPTER_LINK_LAYER_CAPABILITIES*){}
static void NetAdapterSetLinkLayerMtuSize(NETADAPTER,ULONG n){assert(n==1500);}
static void NetAdapterSetPermanentLinkLayerAddress(NETADAPTER a,NET_ADAPTER_LINK_LAYER_ADDRESS* p){permanentAddresses[a]=*p;}
static void NetAdapterSetCurrentLinkLayerAddress(NETADAPTER a,NET_ADAPTER_LINK_LAYER_ADDRESS* p){assert(!spinDepth);currentAddresses[a]=*p;}
static void NetAdapterSetDataPathCapabilities(NETADAPTER a,NET_ADAPTER_TX_CAPABILITIES* tx,NET_ADAPTER_RX_CAPABILITIES* rx){
 auto i=inits.at(a);assert(i->Wmm && i->PeerRange);assert(tx->QueueCount>=(ULONG)i->PeerRange*8u+1u);
 assert(tx->MaximumNumberOfFragments==16 && rx->MaximumFrameSize==8192);queueCounts[a]=tx->QueueCount;
}
static NTSTATUS NetAdapterStart(NETADAPTER a){assert(!a->Ready && a->Registered && a->Wifi->Model.Roles[a->LogicalPort==0?0:1]==a);return startStatus;}
static NTSTATUS Ap6256EvtCreateTxQueue(NETADAPTER,NETTXQUEUE_INIT*){return 0;}
static NTSTATUS Ap6256EvtCreateRxQueue(NETADAPTER,NETRXQUEUE_INIT*){return 0;}
static NTSTATUS Ap6256NetHardwareStart(Device* d){++hardwareStarts;if(NT_SUCCESS(hardwareStatus))d->Engine->HardwareAvailable=1;return hardwareStatus;}
static void Ap6256WifiCxSetPowerCapabilities(NETADAPTER,Device*){}
static void Ap6256StationAuthStop(Wifi*){assert(false);}
static UINT16 Ap6256ConnectCompletionId(Wifi*){assert(false);return 0;}
static NTSTATUS Ap6256WifiDisconnect(Device*){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiScanAbort(Device*){assert(false);return STATUS_NOT_SUPPORTED;}
static void Ap6256CancelActionFrame(Wifi*,NTSTATUS){assert(false);}
'''
TEST = r'''
static void factoryCase(ULONG n){
 fprintf(stderr,"factory/power case %lu\n",n);
 allocations.clear();inits.clear();currentAddresses.clear();permanentAddresses.clear();queueCounts.clear();heldLocks.clear();
 createStatus=initializeStatus=startStatus=hardwareStatus=0;adapterCreates=disposes=hardwareStarts=0;lastAdapter=nullptr;wakeAtInitialize=false;factoryWakeAtGet=n==15;factoryWakeAtIes=n==17;factoryActorAtGroup=false;factoryWakeStatus=STATUS_UNSUCCESSFUL;
 for(auto& plan:addPlans)plan=ModeAddPlan{};addCalls=deleteCalls=cleanupCalls=getCalls=interfaceWaits=tdlsBlocks=tdlsRestores=0;
 strictSleepTransport=true;nativeControlAttempts=0;nativePresent=false;deleteFail=deleteEventLost=false;deleteEffect=true;tdlsBlocked=false;beforeLock=nullptr;actorDone=false;suspends=forgetCalls=0;suspendStatus=forgetStatus=0;
 modeDeliveryFail=false;modeCompletionsAccepted=0;
 auto owned=std::make_unique<Fixture>();auto& f=*owned;modeDeliveryDevice=&f.d;engineRefs=1;
 f.d.Device=&f.d;f.d.Go.Created=f.d.Go.FirmwareReady=FALSE;f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.d.FirmwareIfMap[2]=0;
 f.w.Model.Roles[1]=nullptr;f.w.Model.Object=&f.w;f.w.Model.Adapter=&f.station;f.d.NetAdapter=&f.station;f.w.LinkWorkItem=f.w.ActionFrameCompleteWorker=&f.gtx;
 f.w.ApStarted=FALSE;f.w.PortCreated=TRUE;f.w.StationPortMode=AP6256_WDI_OPMODE_STA;f.w.P2pPortCreated=TRUE;f.w.P2pPortMode=AP6256_WDI_OPMODE_P2P_DEVICE;
 const UCHAR mac[6]={2,1,2,3,4,9};memcpy(f.d.MacAddress,mac,6);memcpy(f.d.P2p.DeviceAddress,mac,6);Ap6256RecomputePortModes(&f.w);f.stationTraffic();
 if(n==1 || n==4)f.w.HardwareAvailable=0;
 if(n==2)initializeStatus=STATUS_NOT_SUPPORTED;
 if(n==3 || n==9)startStatus=STATUS_NOT_SUPPORTED;
 if(n==4)hardwareStatus=STATUS_DEVICE_NOT_READY;
 if(n==5){addPlans[1].fail=true;addPlans[1].effect=false;}
 if(n==6)addPlans[1].fail=true;
 if(n==7)addPlans[1].eventLost=true;
 if(n==8){addPlans[1].fail=true;addPlans[1].cleanupFail=true;}
 if(n==9){deleteFail=true;deleteEffect=true;}
 if(n==13)assert(Ap6256WifiCxArmWake(&f.d)==0);
 if(n==14)wakeAtInitialize=true;
 NETADAPTER_INIT init={WIFI_ADAPTER_WIFI_DIRECT_ROLE,73};NTSTATUS status=Ap6256EvtWifiCreateAdapter(&f.d,&init);if(factoryWakeActor.joinable())factoryWakeActor.join();beforeLock=nullptr;
 fprintf(stderr,"create %08lx native %u attempts %lu hw %ld dx %u uncertain %u refs %ld ADD %u DEL %u cleanup %u\n",status,(unsigned)nativePresent,nativeControlAttempts,f.w.HardwareAvailable,(unsigned)f.w.PowerStateDx,(unsigned)f.d.Go.NativeStateUncertain,engineRefs,addCalls,deleteCalls,cleanupCalls);
 if(n==13 || n==14){assert(status==STATUS_DEVICE_NOT_READY && !nativeControlAttempts && !f.w.Model.Roles[1] && !f.d.Go.Created && !f.d.Go.NativeStateUncertain && f.w.HardwareAvailable && engineRefs==1);return;}
 if(n>=2 && n<=9){assert(!NT_SUCCESS(status) && !f.w.Model.Roles[1] && engineRefs==1);if(n==8 || n==9)assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);else assert(!nativePresent && !f.d.Go.FirmwareReady && f.w.HardwareAvailable==(n==4?0:1));if(n==7)assert(interfaceWaits==100);return;}
 assert(status==0 && lastAdapter && lastAdapter->Ready && lastAdapter->Registered && lastAdapter->FirmwareCreated && engineRefs==2 && f.w.Model.Roles[1]==lastAdapter);
 assert(nativePresent && f.d.Go.Created && f.d.Go.FirmwareReady && nativeRole==1 && f.d.Go.IfIndex==7 && lastAdapter->PortId==73 && f.d.WifiGroupPortId==73 && queueCounts[lastAdapter]==AP6256_CX_TX_QUEUES);
 UCHAR expected[6];memcpy(expected,mac,6);expected[0]|=2;expected[5]^=0x80;
 assert(!memcmp(f.d.Go.Address,expected,6) && !memcmp(currentAddresses[lastAdapter].Address,expected,6) && !memcmp(permanentAddresses[lastAdapter].Address,expected,6));if(!f.w.PowerStateDx)f.stationTraffic();
 if(n==15){assert(factoryWakeStatus==0 && f.w.PowerStateDx && f.d.LowPowerArmed && !f.d.Go.NativeStateUncertain && f.w.HardwareAvailable);return;}
 if(n==10){deleteFail=true;deleteEffect=true;}
 if(n==11)deleteEventLost=true;
 if(n==12){f.d.Go.Started=TRUE;f.w.ApStarted=TRUE;apDevice=&f.d;apBssUp=true;apFailDown=true;}
 OpaqueRequest clientRequest;
 if(n>=18){
  OpaqueRequest change;modeTask(f,change,AP6256_WDI_OPMODE_P2P_CLIENT);assert(change.Status==0 && nativeRole==0);
  if(n!=21){f.connect(clientRequest,TRUE,1);assert(clientRequest.Status==0 && f.w.Model.ClientConnectTask.Active);
   if(n==19){Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected && count(WDI_INDICATION_CONNECT_COMPLETE)==1);}
   if(n==20)failStep=ioStep+1;
  }
 }
 ULONG attempts=nativeControlAttempts;
 if(n==16 || n==21){assert(Ap6256WifiCxArmWake(&f.d)==0);attempts=nativeControlAttempts;}
 WdfObjectDelete(lastAdapter);if(factoryWakeActor.joinable())factoryWakeActor.join();beforeLock=nullptr;
 fprintf(stderr,"cleanup native %u attempts %lu hw %ld dx %u uncertain %u refs %ld DEL %u\n",(unsigned)nativePresent,nativeControlAttempts,f.w.HardwareAvailable,(unsigned)f.w.PowerStateDx,(unsigned)f.d.Go.NativeStateUncertain,engineRefs,deleteCalls);
 assert(!f.w.Model.Roles[1] && !f.d.Go.Created && !f.d.Go.FirmwareReady && engineRefs==1 && lastAdapter->Closing && !lastAdapter->DataEnabled);
 if(n==10 || n==11 || n==12 || n==16 || n==20 || n==21){assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);if(n==16 || n==21)assert(nativeControlAttempts==attempts && nativePresent);}
 else{assert(!nativePresent && !f.d.Go.NativeStateUncertain && f.w.HardwareAvailable);if(!f.w.PowerStateDx)f.stationTraffic();}
 if(n>=18){assert(!f.w.Model.ClientConnectTask.Active && !f.timer.Armed && !f.d.Go.ClientConnected);
  if(n!=21){assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1);if(n!=19)assert(lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status==STATUS_CANCELLED);}
  for(auto& peer:f.d.Go.Peers)assert(!peer.Active && !peer.RxOpen);
 }
 assert(f.w.Model.Roles[0]==&f.station && f.w.Model.StationPeerGeneration==13 && f.d.NetAdapter==&f.station);
 assert(heldLocks.empty() && f.w.Model.GroupLock.try_lock());f.w.Model.GroupLock.unlock();
}
int main(int argc,char** argv){if(argc>1){factoryCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<22;++n)factoryCase(n);puts("PASS: 22 actual factory/cleanup/native-group/wake cases with strict BCDC admission and preserved station ownership");return 0;}
'''

def build_source():
    (text, names) = mode.build_source()
    text = '#include <set>\n' + text
    text = text.replace('int main(int argc,char** argv)', 'int groupModeMain(int argc,char** argv)')
    text = text.replace('struct GroupPowerDevice;using Device=GroupPowerDevice;', r'''struct FactoryP2p {UCHAR DeviceAddress[6]={};UCHAR OperatingChannel=0,OperatingClass=0;UINT32 AssocStatus=0;AP6256_P2P_IE_SLOT DriverIes[Ap6256P2pFrameMax]={},HostIes[Ap6256P2pFrameMax]={};};
struct GroupPowerDevice;using Device=GroupPowerDevice;''')
    text = text.replace('Wifi* Engine=nullptr;Device* Device=nullptr;', 'Wifi* Engine=nullptr;PVOID NetAdapter=nullptr;UINT16 WifiGroupPortId=0,WifiStationPortId=37;UCHAR MacAddress[6]={};FactoryP2p P2p;Device* Device=nullptr;')
    text = text.replace('struct {UCHAR OperatingChannel=0,OperatingClass=0;UINT32 AssocStatus=0;AP6256_P2P_IE_SLOT DriverIes[Ap6256P2pFrameMax]={},HostIes[Ap6256P2pFrameMax]={};} P2p;', 'FactoryP2p P2p;')
    text = text.replace('BOOLEAN PowerStateDx=FALSE;', 'BOOLEAN ConnectionActive=FALSE,PowerStateDx=FALSE;')
    text = text.replace('AP6256_WDI_TASK ConnectTask={},ApAssocTask={};', 'AP6256_WDI_TASK ScanTask={},DisconnectTask={},ActionFrameTask={};AP6256_TIMER_OBJ ScanTimer=nullptr;WDFWORKITEM LinkWorkItem=nullptr,ActionFrameCompleteWorker=nullptr;UINT32 PortNumber=0;AP6256_WDI_TASK ConnectTask={},ApAssocTask={};')
    sdk = (mode.power.group.base.INC / 'km/wificx/1.2/wificx.h').read_text(encoding='utf-8-sig')
    adapter_type = re.search('typedef enum _WIFI_ADAPTER_TYPE[\\s\\S]*?} WIFI_ADAPTER_TYPE;', sdk)[0]
    text += '\n' + adapter_type + '\n' + EXTRA + BOUNDARY
    text = text.replace('static void Ap6256Lock', 'static VOID Ap6256Lock')
    functions = _functions(text)
    text = text.replace(functions['Ap6256LockAcquire'], 'static void Ap6256LockAcquire(AP6256_LOCK* l){assert(!spinDepth);if(beforeLock)beforeLock(l);l->lock();heldLocks.insert(l);}')
    text = text.replace(functions['Ap6256LockRelease'], 'static void Ap6256LockRelease(AP6256_LOCK* l){assert(heldLocks.erase(l)==1);l->unlock();}')
    text = text.replace('static void Ap6256LockAcquire(', 'static thread_local std::set<AP6256_LOCK*> heldLocks;\nstatic void Ap6256LockAcquire(', 1)
    text = text.replace('static thread_local std::set<AP6256_LOCK*> heldLocks;\nstatic std::map<', 'static std::map<', 1)
    functions = _functions(text)
    for name in ('Ap6256BcdcSetIovarResultIf', 'Ap6256BcdcGetIovar', 'Ap6256TdlsSetBlocked'):
        old = functions[name]
        brace = old.index('{')
        guard = ('if(factoryWakeAtGet){factoryWakeAtGet=false;factoryScheduleWake(d);}' if name == 'Ap6256BcdcGetIovar' else '') + '++nativeControlAttempts;NTSTATUS admission=modeControlAdmission(d);if(!NT_SUCCESS(admission))return admission;'
        if name == 'Ap6256TdlsSetBlocked':
            oldname = old.replace('Device*,BOOLEAN block', 'Device* d,BOOLEAN block')
            brace = oldname.index('{')
        else:
            oldname = old
        replacement = oldname[:brace + 1] + guard + oldname[brace + 1:]
        text = text.replace(old, replacement)
    functions = _functions(text)
    old = functions['Ap6256P2pReleaseIesFor']
    text = text.replace(old, old.replace('Device*,PVOID', 'Device* d,PVOID').replace('{assert(iface==7);', '{if(factoryWakeAtIes){factoryWakeAtIes=false;factoryScheduleWake(d);}assert(iface==7);'))
    text = text.replace('static UINT16 nativeRole=0;', r'''static bool factoryWakeAtGet=false,factoryWakeAtIes=false;static std::atomic<bool> factoryActorAtGroup{false};static NTSTATUS factoryWakeStatus=STATUS_UNSUCCESSFUL;static std::thread factoryWakeActor;static VOID factoryScheduleWake(Device*);
static UINT16 nativeRole=0;''')
    source = (ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig')
    functions = _functions(source)
    for name in ('Ap6256ModelDeleteGroup', 'Ap6256CxCancelRoleTasks', 'Ap6256EvtAdapterCleanup', 'Ap6256EvtWifiCreateAdapter'):
        text += functions[name] + '\n'
        names.append(name)
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(22))
    args = parser.parse_args()
    (text, names) = build_source()
    old_hashes = {}
    out = OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    base = mode.power.group.base
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64'), 'advapi32.lib', str(base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    case = args.case if args.case is not None else {'create-admission': 14, 'native-create-sleep': 15, 'cleanup-asleep': 16, 'native-delete-sleep': 17}.get(None)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(case)] if case is not None else []), capture_output=True, text=True, timeout=45)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/wificx/role_adapter.inc', 'src/wificx/group_engine.inc', 'src/wificx/wowl_power.inc', 'src/common/hotspot.c', 'src/common/netadapter.c', 'src/common/bcdc.c', 'src/common/netadapter_internal.h', 'src/wificx/netmodel_state.h', 'tests/test-wificx-factory-power.py', 'tests/test-wificx-role-lifecycle.py', 'tests/test-wificx-group-mode.py', 'tests/test-wificx-group-power.py', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-roles.py')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'sdk_header_sha256': mode.power.HEADERS, 'boundary': __doc__, 'board_verified': False, 'case': case, 'negative_control': None, 'negative_source_sha256': old_hashes or None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
