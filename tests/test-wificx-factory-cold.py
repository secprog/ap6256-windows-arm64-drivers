# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Combine actual WiFiCx factory/native role and cold D0/hardware lifecycle.'
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
factory = module('cold_factory', ROOT / 'tests/test-wificx-factory-power.py')
stop = module('cold_stop', ROOT / 'tests/test-wificx-hardware-stop.py')
group = factory.mode.power.group
OUT = output_dir('wificx-factory-cold')
BOUNDARY = r'''
static NTSTATUS coldCapabilityStatus=0,coldRadioStatus=0;
static bool coldHaltDuringMbo=false;
static unsigned coldCapabilityCalls=0,coldDiscoveryCalls=0,coldRadioCalls=0;
static NTSTATUS Ap6256SetWifiCapabilities(WDFDEVICE d){++coldCapabilityCalls;assert(d->Engine->HardwareAvailable);return coldCapabilityStatus;}
static NTSTATUS Ap6256WifiSetRadioState(Device*,BOOLEAN on){assert(!on);++coldRadioCalls;return coldRadioStatus;}
static NTSTATUS Ap6256MboInitialize(Wifi* w){if(coldHaltDuringMbo){w->Ctx->FirmwareHalted=1;Ap6256NetFirmwareHalted(w->Ctx);}return 0;}
static NTSTATUS Ap6256WifiP2pSetDiscoveryInterface(Device*,BOOLEAN on,PVOID){assert(on);++coldDiscoveryCalls;return 0;}
static VOID Ap6256TearDownChip(Device* d,BOOLEAN worker){
 ++coldStops;d->PowerThread=KeGetCurrentThread();

 Ap6256NetHardwareStop(d,STATUS_POWER_STATE_INVALID,worker);

 nativePresent=false;d->LowPowerArmed=FALSE;d->FirmwareIoQuiesced=0;d->PowerThread=nullptr;
 d->Go.FirmwareReady=FALSE;d->Go.Started=FALSE;memset(d->FirmwareIfMap,0,sizeof(d->FirmwareIfMap));
}
static NTSTATUS Ap6256BringUpChip(Device* d,BOOLEAN worker){
 ++coldStarts;if(!NT_SUCCESS(coldStatus)){Ap6256TearDownChip(d,worker);return coldStatus;}


 nativePresent=false;d->FirmwareHalted=0;d->Go.NativeStateUncertain=FALSE;
 d->Go.FirmwareReady=FALSE;d->LowPowerArmed=FALSE;d->FirmwareIoQuiesced=0;d->PowerThread=nullptr;
 memset(d->FirmwareIfMap,0,sizeof(d->FirmwareIfMap));
 NTSTATUS status=Ap6256NetHardwareStart(d);if(!NT_SUCCESS(status))Ap6256TearDownChip(d,worker);return status;
}
static NTSTATUS Ap6256WifiResumeFromWake(Device* d,UINT32* reason,AP6256_WAKE_PACKET*,BOOLEAN* valid){
 ++resumes;*reason=0;*valid=FALSE;
 if(NT_SUCCESS(resumeStatus)){d->LowPowerArmed=FALSE;d->FirmwareIoQuiesced=0;d->PowerThread=nullptr;}
 return resumeStatus;
}
static void WifiAdapterReportWakeReason(NETADAPTER,WIFI_WAKE_REASON_TYPE){assert(false);}
static void NetAdapterReportWakeReasonPacket(NETADAPTER,const NET_ADAPTER_WAKE_REASON_PACKET*){assert(false);}
static void Ap6256PnoResultsPower(Device*,BOOLEAN on){assert(on);}
static NTSTATUS WdfMemoryCreate(WDF_OBJECT_ATTRIBUTES*,int,int,ULONG,WDFMEMORY*,PVOID*){assert(false);return STATUS_INSUFFICIENT_RESOURCES;}
'''
TEST = r'''
static void coldFactoryCase(ULONG n){
 fprintf(stderr,"factory/cold case %lu\n",n);
 allocations.clear();inits.clear();currentAddresses.clear();permanentAddresses.clear();queueCounts.clear();heldLocks.clear();
 createStatus=initializeStatus=startStatus=hardwareStatus=0;adapterCreates=disposes=hardwareStarts=0;lastAdapter=nullptr;wakeAtInitialize=factoryWakeAtGet=factoryWakeAtIes=false;factoryActorAtGroup=false;
 for(auto& plan:addPlans)plan=ModeAddPlan{};addCalls=deleteCalls=cleanupCalls=getCalls=interfaceWaits=tdlsBlocks=tdlsRestores=0;
 strictSleepTransport=true;nativeControlAttempts=0;nativePresent=false;deleteFail=deleteEventLost=false;deleteEffect=true;tdlsBlocked=false;beforeLock=nullptr;actorDone=false;
 suspends=resumes=coldStops=coldStarts=readyCalls=forgetCalls=0;suspendStatus=resumeStatus=coldStatus=forgetStatus=0;
 coldCapabilityStatus=coldRadioStatus=0;coldHaltDuringMbo=false;coldCapabilityCalls=coldDiscoveryCalls=coldRadioCalls=0;
 modeDeliveryFail=false;modeCompletionsAccepted=0;
 auto owned=std::make_unique<Fixture>();auto& f=*owned;modeDeliveryDevice=&f.d;engineRefs=1;
 f.d.Device=&f.d;f.d.Go.Created=f.d.Go.FirmwareReady=FALSE;f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.d.FirmwareIfMap[2]=0;
 f.d.WifiCapabilitiesSet=TRUE;f.w.Model.Roles[1]=nullptr;f.w.Model.Object=&f.w;f.w.Model.Adapter=&f.station;f.d.NetAdapter=&f.station;
 f.w.LinkWorkItem=f.w.ActionFrameCompleteWorker=&f.gtx;f.w.ApStarted=FALSE;f.w.PortCreated=TRUE;f.w.StationPortMode=AP6256_WDI_OPMODE_STA;f.w.P2pPortCreated=TRUE;f.w.P2pPortMode=AP6256_WDI_OPMODE_P2P_DEVICE;
 const UCHAR mac[6]={2,1,2,3,4,9};memcpy(f.d.MacAddress,mac,6);memcpy(f.d.P2p.DeviceAddress,mac,6);Ap6256RecomputePortModes(&f.w);f.stationTraffic();
 NETADAPTER_INIT init={WIFI_ADAPTER_WIFI_DIRECT_ROLE,73};assert(Ap6256EvtWifiCreateAdapter(&f.d,&init)==0);auto role=lastAdapter;
 assert(role && role->Ready && role->FirmwareCreated && f.w.Model.Roles[1]==role && nativePresent && engineRefs==2);
 f.gtx.Role=role;role->TxQueues[0]=&f.gtx;f.rx.Role=role;role->RxQueue=&f.rx;
 OpaqueRequest connect,change,ap;
 if(n==1 || n==2 || n==3){modeTask(f,change,AP6256_WDI_OPMODE_P2P_CLIENT);assert(change.Status==0);}
 if(n==2 || n==3){f.connect(connect,TRUE,1);assert(connect.Status==0 && f.w.Model.ClientConnectTask.Active);if(n==3)Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);}
 if(n==4){startAp(f,ap);assert(ap.Status==0 && f.w.ApStarted && role->DataEnabled);}
 AP6256_FRAME oldStation={};oldStation.Length=64;memcpy(oldStation.Data,f.w.Model.StationPeerAddress,6);oldStation.Data[6]=2;oldStation.Data[12]=8;NET_PACKET_WIFI_EXEMPTION_ACTION exemption={};assert(Ap6256CxPrepareTx(&f.tx,&exemption,&oldStation)==0);
 const LONG roleGeneration=role->Generation,groupGeneration=f.w.Model.GroupGeneration;
 const UCHAR expectedMode=(UCHAR)(f.d.Go.Mode==AP6256_WDI_OPMODE_P2P_GO?1:0);
 if(n==5 || n==6 || n==7){assert(Ap6256WifiCxArmWake(&f.d)==0);assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD2)==0 && !coldStops);}
 else if(n!=8){assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD3)==0 && coldStops==1 && !f.w.HardwareAvailable);}
 if(n==5)resumeStatus=STATUS_IO_DEVICE_ERROR;
 if(n==7){WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && engineRefs==1);}
 if(n==8){deleteFail=true;deleteEffect=true;WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && engineRefs==1);deleteFail=false;


  assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD3)==0 && coldStops==1);
 }
 if(n==9 || n==10){addPlans[2].fail=true;addPlans[2].effect=n==10;addPlans[2].cleanupFail=n==10;}
 if(n==11){f.d.WifiCapabilitiesSet=FALSE;coldCapabilityStatus=STATUS_IO_DEVICE_ERROR;}
 if(n==12){f.w.SoftwareRadioState=FALSE;coldRadioStatus=STATUS_IO_DEVICE_ERROR;}
 if(n==13)coldHaltDuringMbo=true;
 if(n==14){f.w.HardwareAvailable=0;f.w.PowerStateDx=TRUE;f.d.Go.NativeStateUncertain=TRUE;}
 if(n==15)addPlans[2].eventLost=true;
 NTSTATUS entry=Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2);
 fprintf(stderr,"entry %08lx native %u hw %ld dx %u uncertain %u starts %u stops %u resumes %u ADD %u\n",entry,(unsigned)nativePresent,f.w.HardwareAvailable,(unsigned)f.w.PowerStateDx,(unsigned)f.d.Go.NativeStateUncertain,coldStarts,coldStops,resumes,addCalls);
 if(n==9 || n==10 || n==12 || n==13 || n==15){
  assert(!NT_SUCCESS(entry) && !f.w.HardwareAvailable && !f.d.Go.FirmwareReady && !role->DataEnabled && !f.station.DataEnabled);
  assert(!f.w.Model.ClientConnectTask.Active && !f.w.ApAssocTask.Active);if(n==10)assert(f.d.Go.NativeStateUncertain);
  WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && engineRefs==1);return;
 }
 assert(entry==0);NTSTATUS ready=Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2);
 if(n==11){assert(!NT_SUCCESS(ready) && !f.w.HardwareAvailable && !f.d.Go.FirmwareReady && !role->DataEnabled);WdfObjectDelete(role);assert(engineRefs==1);return;}
 assert(ready==0 && f.w.HardwareAvailable && !f.w.PowerStateDx && !f.w.RetainedResume && !f.d.Go.NativeStateUncertain);
 if(n==6){assert(!coldStarts && !coldStops && resumes==1 && nativePresent && f.d.Go.FirmwareReady && role->Generation==roleGeneration && f.w.Model.StationPeerGeneration==13);f.stationTraffic();WdfObjectDelete(role);assert(engineRefs==1 && !nativePresent);return;}
 assert(coldStarts==1 && !f.w.Model.StationPeerCreated && !f.station.DataEnabled && !Ap6256CxFrameCurrent(&f.station,&oldStation));
 assert(!f.w.Model.ClientConnectTask.Active && !f.timer.Armed && !f.apTimer.Armed && !f.d.Go.ClientConnected);
 for(auto& peer:f.d.Go.Peers)assert(!peer.Active && !peer.RxOpen);
 assert(f.w.Model.Roles[0]==&f.station && f.d.NetAdapter==&f.station && f.station.Ready);
 if(n==7 || n==8){assert(!f.w.Model.Roles[1] && !f.d.Go.Created && !nativePresent && addCalls==1 && !f.d.Go.FirmwareReady);return;}
 assert(f.w.Model.Roles[1]==role && role->Ready && !role->Closing && !role->DataEnabled && f.d.Go.Created && f.d.Go.FirmwareReady && nativePresent && nativeRole==expectedMode);
 assert(role->Generation>roleGeneration && !memcmp(currentAddresses[role].Address,f.d.Go.Address,6));


 if(expectedMode==0)assert(f.w.Model.GroupGeneration>groupGeneration);
 else assert(f.w.Model.GroupGeneration==groupGeneration);
 if(n==2)assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1 && lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status==STATUS_POWER_STATE_INVALID);
 if(n==3)assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1 && count(WDI_INDICATION_DISASSOCIATION)==1);
 WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && !f.d.Go.Created && !nativePresent && !f.d.Go.NativeStateUncertain && engineRefs==1 && heldLocks.empty());
}
int main(int argc,char** argv){if(argc>1){coldFactoryCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<16;++n)coldFactoryCase(n);puts("PASS: 16 actual factory/native-group/hardware-stop-start/D0 callback lifecycle cases");return 0;}
'''

def build_source():
    (text, names) = factory.build_source()
    text = text.replace('int main(int argc,char** argv)', 'int factoryPowerMain(int argc,char** argv)')
    text = text.replace('static void Ap6256', 'static VOID Ap6256')

    def change(old, new):
        nonlocal text
        assert text.count(old) == 1, (old[:120], text.count(old))
        text = text.replace(old, new)
    phase = group.typed_enum((ROOT / 'src/common/p2p.h').read_text(encoding='utf-8-sig'), 'AP6256_P2P_DISCOVER_PHASE')
    claim = group.typed_enum((ROOT / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig'), 'AP6256_CONNECT_CLAIM')
    change('struct FactoryP2p {', phase + claim + 'struct FactoryP2p {BOOLEAN Listening=FALSE;AP6256_P2P_DISCOVER_PHASE DiscoverPhase=Ap6256P2pDiscoverIdle;LONG DiscoverScanPending=0;')
    change('Device* Device=nullptr;', 'Device* Device=nullptr;BOOLEAN WifiCapabilitiesSet=FALSE;')
    change('BOOLEAN ConnectionActive=FALSE,PowerStateDx=FALSE;', 'BOOLEAN ConnectionActive=FALSE,PowerStateDx=FALSE,RetainedResume=FALSE,SoftwareRadioState=TRUE,P2pDiscovering=FALSE,ConnectDeparting=FALSE,ConnectTaskIsRoam=FALSE;ULONG ConnectCandidateCount=0;LONG ConnectGeneration=0;HostTimer StopTimers[5]={};AP6256_LOCK P2pLock;AP6256_WDI_TASK P2pDiscoverTask={};')
    change('AP6256_TIMER_OBJ ScanTimer=nullptr;', 'AP6256_TIMER_OBJ ScanTimer=&StopTimers[2],P2pDiscoverTimer=&StopTimers[0],P2pListenTimer=&StopTimers[1],ConnectTimer=&StopTimers[3],DisconnectTimer=&StopTimers[4];')
    change('h->PortId==(id==WDI_INDICATION_FIRMWARE_STALLED?0xffff:2)', '(id==WDI_INDICATION_FIRMWARE_STALLED?h->PortId==0xffff:h->PortId<=2)')
    declarations = r'''NTSTATUS Ap6256NetHardwareStart(Device*);VOID Ap6256NetHardwareStop(Device*,NTSTATUS,BOOLEAN);NTSTATUS Ap6256ModelStartInterfaces(Wifi*,Device*);NTSTATUS Ap6256ModelHardwareReady(Device*);
static NTSTATUS Ap6256MboInitialize(Wifi*);static NTSTATUS Ap6256WifiSetRadioState(Device*,BOOLEAN);static NTSTATUS Ap6256SetWifiCapabilities(WDFDEVICE);
'''
    anchor = _functions(text)['Ap6256TearDownChip']
    change(anchor, declarations + anchor)
    functions = _functions(text)
    change('struct WDF_OBJECT_ATTRIBUTES {', 'struct WDF_OBJECT_ATTRIBUTES {PVOID ParentObject=nullptr;')
    header = group.base.INC / 'km/netcx/kmdf/adapter/2.5/netadapter.h'
    sdk = header.read_text(encoding='utf-8-sig')
    extra = 'typedef NETADAPTER WDFMEMORY;\n' + group.base.typed(sdk, 'NET_ADAPTER_WAKE_REASON_PACKET') + factory.mode.power.sdk_init(sdk, 'NET_ADAPTER_WAKE_REASON_PACKET_INIT')
    extra += group.typed_enum((group.base.INC / 'km/wificx/1.2/wificx.h').read_text(encoding='utf-8-sig'), 'WIFI_WAKE_REASON_TYPE')
    extra += '\n#define WDF_OBJECT_ATTRIBUTES_INIT(a) (*(a)=WDF_OBJECT_ATTRIBUTES{})\n'
    text += '\n' + extra + '\n#define NonPagedPoolNx 0\n' + BOUNDARY[BOUNDARY.index('static void WifiAdapterReportWakeReason'):].replace('static void Ap6256', 'static VOID Ap6256')
    counters = stop.BOUNDARIES[:stop.BOUNDARIES.index('static VOID')] + BOUNDARY[:BOUNDARY.index('static NTSTATUS Ap6256SetWifiCapabilities')]
    insertion = _functions(text)['Ap6256TearDownChip']
    change(insertion, counters + insertion)

    def put(name, body, production=False):
        nonlocal text
        functions = _functions(text)
        if name in functions:
            text = text.replace(functions[name], body)
        else:
            text += '\n' + body + '\n'
        if production and name not in names:
            names.append(name)
    change('template<class... T> static NTSTATUS Ap6256FtmCancel(T...){assert(false);return STATUS_NOT_SUPPORTED;}', 'static NTSTATUS Ap6256FtmCancel(Wifi*,BOOLEAN,UINT32,UINT16,NTSTATUS);')
    for (name, body) in _functions(stop.BOUNDARIES).items():
        put(name, body)
    for (name, body) in _functions(BOUNDARY).items():
        put(name, body)
    common = _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))
    role = _functions((ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig'))
    engine = _functions((ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig'))
    cx = _functions((ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig'))
    power = _functions((ROOT / 'src/wificx/wowl_power.inc').read_text(encoding='utf-8-sig'))
    device = _functions((ROOT / 'src/common/kmdf_device.c').read_text(encoding='utf-8-sig'))
    wdf = (group.base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h').read_text(encoding='utf-8-sig')
    text += re.search('typedef enum _WDF_POWER_DEVICE_STATE\\s*\\{[\\s\\S]*?\\} WDF_POWER_DEVICE_STATE, \\*PWDF_POWER_DEVICE_STATE;', wdf)[0] + '\n'
    for (table, selected) in ((common, ('Ap6256ClaimMatchingTask', 'Ap6256ClaimExpiredTask', 'Ap6256ClaimConnectTask', 'Ap6256ConnectCompletionId')), (role, ('Ap6256CxFlushTxWorkers', 'Ap6256ModelGroupAddressChanged')), (engine, ('Ap6256ModelStartInterfaces',)), (cx, ('Ap6256NetHardwareStop', 'Ap6256ModelHardwareReady')), (common, ('Ap6256NetHardwareStart',)), (power, ('Ap6256WifiCxResumePower',)), (device, ('Ap6256EvtD0Entry', 'Ap6256EvtD0Exit', 'Ap6256EvtD0EntryPostInterruptsEnabled'))):
        for name in selected:
            put(name, table[name], True)
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(16))
    args = parser.parse_args()
    (text, names) = build_source()
    old_hashes = {}
    case = args.case
    out = OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    base = group.base
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64'), 'advapi32.lib', str(base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(case)] if case is not None else []), capture_output=True, text=True, timeout=45)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/common/kmdf_device.c', 'src/common/device.c', 'src/common/firmware.c', 'src/common/bcdc.c', 'src/common/netadapter.c', 'src/common/hotspot.c', 'src/common/netadapter_internal.h', 'src/wificx/netadapter.c', 'src/wificx/role_adapter.inc', 'src/wificx/group_engine.inc', 'src/wificx/wowl_power.inc', 'src/wificx/netmodel_state.h', 'tests/test-wificx-factory-cold.py', 'tests/test-wificx-factory-power.py', 'tests/test-wificx-hardware-stop.py', 'tests/test-wificx-cold-power.py', 'tests/test-wificx-group-mode.py', 'tests/test-wificx-group-power.py', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-roles.py')
    headers = dict(factory.mode.power.HEADERS)
    headers[str(base.INC / 'km/netcx/kmdf/adapter/2.5/netadapter.h')] = hashlib.sha256((base.INC / 'km/netcx/kmdf/adapter/2.5/netadapter.h').read_bytes()).hexdigest()
    headers[str(base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h')] = hashlib.sha256((base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h').read_bytes()).hexdigest()
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'sdk_header_sha256': headers, 'boundary': __doc__, 'board_verified': False, 'case': case, 'negative_control': None, 'negative_source_sha256': old_hashes or None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
