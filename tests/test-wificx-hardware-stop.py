# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute actual WiFiCx hardware-stop plus cold D0/role rebuild integration.'
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
cold = module('stop_cold', ROOT / 'tests/test-wificx-cold-power.py')
power = module('stop_power', ROOT / 'tests/test-wificx-group-power.py')
group = cold.group
OUT = output_dir('wificx-hardware-stop')
BOUNDARIES = r'''
static NTSTATUS Ap6256WifiLeaveForPowerDown(Device*) {return 0;}
static unsigned actionStops=0,ftmStops=0,serviceStops=0,authStops=0,mboStops=0,softwareFlushes=0,authCancels=0,stationAssociations=0,stationDisassociations=0;
static VOID Ap6256CancelActionFrame(Wifi* w,NTSTATUS){assert(!w->HardwareAvailable);++actionStops;}
static NTSTATUS Ap6256FtmCancel(Wifi* w,BOOLEAN,UINT32,UINT16,NTSTATUS){assert(!w->HardwareAvailable);++ftmStops;return 0;}
static VOID Ap6256ServiceStop(Wifi* w,BOOLEAN stop){assert(stop && !w->HardwareAvailable);++serviceStops;}
static VOID Ap6256StationAuthStop(Wifi* w){assert(!w->HardwareAvailable);++authStops;}
static VOID Ap6256MboReset(Wifi* w){assert(!w->HardwareAvailable);++mboStops;}
static VOID Ap6256ModelCancelAuthentication(Wifi*){++authCancels;}
static VOID Ap6256FlushSoftwareQueues(Wifi* w){assert(!w->HardwareAvailable);++softwareFlushes;}
static VOID Ap6256IndicateAssociation(Wifi*,const WDI_MESSAGE_HEADER* h,PVOID r,BOOLEAN success){assert(h->PortId==0 && r && !success);++stationAssociations;}
static VOID Ap6256IndicateDisassociation(Wifi*,const WDI_MESSAGE_HEADER* h){assert(h->PortId==0);++stationDisassociations;}
'''
TEST = r'''
static void beginStopTask(Wifi* w,AP6256_WDI_TASK* task,UINT16 port,UINT32 tx,PVOID request){WDI_MESSAGE_HEADER h={};h.PortId=port;h.TransactionId=tx;assert(Ap6256BeginTask(w,task,&h,request)==0);Ap6256SetTaskDeadline(w,task,1000);}
static ULONG indicationCount(UINT16 id,UINT16 port){return (ULONG)std::count_if(indications.begin(),indications.end(),[&](const Indication& i){return i.Id==id && i.Header.PortId==port;});}
static void stopCase(ULONG mode,bool worker){
 fprintf(stderr,"hardware stop case %lu worker %u\n",mode,(unsigned)worker);auto owned=std::make_unique<Fixture>();auto& f=*owned;
 f.d.Device=&f.d;f.w.Model.Adapter=&f.station;f.w.ConnectionActive=TRUE;f.w.IndicationHeader.PortId=0;f.w.P2pDiscovering=TRUE;f.d.P2p.Listening=TRUE;f.d.P2p.DiscoverScanPending=1;
 AP6256_QUEUE_CONTEXT command={},link={};f.w.CommandWorkItem=&command;f.w.LinkWorkItem=&link;selfFlush=worker?&command:nullptr;hardwareFlushes.clear();
 actionStops=ftmStops=serviceStops=authStops=mboStops=softwareFlushes=authCancels=stationAssociations=stationDisassociations=0;
 OpaqueRequest client,ap,scan,discover,connect,disconnect;
 if(mode==1 || mode==2 || mode==5 || mode==7){f.connect(client,TRUE,1);if(mode!=1)Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);}
 if(mode==3 || mode==4 || mode==6)startAp(f,ap);
 if(mode==4){UCHAR peer[]={2,5,5,5,5,5};assert(Ap6256CxGroupPeerCreate(&f.d,peer,1));beginStopTask(&f.w,&f.w.ApAssocTask,2,802,&ap);f.apTimer.Armed=true;}
 if(mode==5)failStep=ioStep+1;
 if(mode==6){beginStopTask(&f.w,&f.w.ScanTask,2,803,&scan);beginStopTask(&f.w,&f.w.P2pDiscoverTask,1,804,&discover);beginStopTask(&f.w,&f.w.DisconnectTask,0,805,&disconnect);}
 if(mode==7){beginStopTask(&f.w,&f.w.ConnectTask,0,806,&connect);f.w.ConnectCandidateCount=2;f.w.ConnectDeparting=TRUE;}
 for(auto& timer:f.w.StopTimers)timer.Armed=true;
 AP6256_FRAME stale={};stale.Length=64;const UCHAR multicast[6]={0xff,0xff,0xff,0xff,0xff,0xff};memcpy(stale.Data,f.d.Go.Mode==AP6256_WDI_OPMODE_P2P_GO?multicast:f.d.Go.ClientBssid,6);memcpy(f.gtx.PeerAddress,stale.Data,6);NET_PACKET_WIFI_EXEMPTION_ACTION ex={};if(f.group.DataEnabled)assert(Ap6256CxPrepareTx(&f.gtx,&ex,&stale)==0);
 ULONG before=(ULONG)indications.size();Ap6256NetHardwareStop(&f.d,STATUS_POWER_STATE_INVALID,worker);
 assert(!f.w.HardwareAvailable && !f.station.DataEnabled && !f.group.DataEnabled && !f.w.Model.StationPeerCreated && !f.w.ConnectionActive);
 assert(f.station.Ready && f.group.Ready && f.w.Model.Roles[0]==&f.station && f.w.Model.Roles[1]==&f.group);
 for(auto& peer:f.d.Go.Peers)assert(!peer.Active);assert(!f.timer.Armed && !f.apTimer.Armed);for(auto& timer:f.w.StopTimers)assert(!timer.Armed);
 assert(!f.w.Model.ClientConnectTask.Active && !f.w.ApAssocTask.Active && !f.w.ScanTask.Active && !f.w.ConnectTask.Active && !f.w.DisconnectTask.Active && !f.w.P2pDiscoverTask.Active);
 assert(!f.w.P2pDiscovering && !f.d.P2p.Listening && !f.d.P2p.DiscoverScanPending && f.d.P2p.DiscoverPhase==Ap6256P2pDiscoverIdle);
 assert(actionStops==1 && ftmStops==1 && serviceStops==1 && authStops==1 && mboStops==1 && softwareFlushes==1);
 assert(std::count(hardwareFlushes.begin(),hardwareFlushes.end(),&link)==1 && std::count(hardwareFlushes.begin(),hardwareFlushes.end(),&command)==(worker?0:1));
 if(mode==1)assert(indicationCount(WDI_INDICATION_CONNECT_COMPLETE,2)==1 && lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status==STATUS_POWER_STATE_INVALID);
 if(mode==2 || mode==5 || mode==7)assert(indicationCount(WDI_INDICATION_DISASSOCIATION,2)==1);
 if(mode==4)assert(indicationCount(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE,2)==1);
 if(mode==6){assert(indicationCount(WDI_INDICATION_SCAN_COMPLETE,2)==1 && indicationCount(WDI_INDICATION_P2P_DISCOVERY_COMPLETE,1)==1 && indicationCount(WDI_INDICATION_DISCONNECT_COMPLETE,0)==1 && stationDisassociations==1);}
 if(mode==7){assert(indicationCount(WDI_INDICATION_CONNECT_COMPLETE,0)==1 && stationAssociations==1 && authCancels==1 && f.w.ConnectGeneration==1 && !f.w.ConnectCandidateCount && !f.w.ConnectDeparting);}
 if(mode==5)assert(f.d.Go.NativeStateUncertain && !count(WDI_INDICATION_FIRMWARE_STALLED));
 if(mode==0 || mode==1 || mode==2 || mode==3 || mode==4 || mode==5)assert(stationDisassociations==1);
 for(ULONG n=before;n<indications.size();++n){auto& i=indications[n];if(i.Id!=WDI_INDICATION_DISASSOCIATION && i.Id!=WDI_INDICATION_ASSOCIATION_RESULT)assert(i.Status==STATUS_POWER_STATE_INVALID);}
 assert(!Ap6256CxFrameCurrent(&f.group,&stale) && !NT_SUCCESS(Ap6256CxTransmit(&f.gtx,&stale)));ULONG indicationsAfter=(ULONG)indications.size();Ap6256NetHardwareStop(&f.d,STATUS_POWER_STATE_INVALID,worker);assert(indications.size()==indicationsAfter);
 selfFlush=nullptr;apDevice=nullptr;
}
int main(){assert(coldPowerMain()==0);for(ULONG n=0;n<8;++n)for(bool worker:{false,true})stopCase(n,worker);puts("PASS: 28 actual WiFiCx hardware-stop/cold-D0 integration cases: group and station peers/tasks, native cleanup failure, timers, worker self-flush, repeated stop and role rebuild");return 0;}
'''

def build_source():
    (text, names) = cold.build_source()
    text = text.replace('int main(int argc,char** argv){if(argc>1)', 'int coldPowerMain(int argc=0,char** argv=nullptr){if(argc>1)')
    assert 'int coldPowerMain(' in text
    text = text.replace('static void WdfWorkItemFlush(WDFWORKITEM q) {assert(!spinDepth);', r'''static std::vector<WDFWORKITEM> hardwareFlushes;static WDFWORKITEM selfFlush=nullptr;
static void WdfWorkItemFlush(WDFWORKITEM q) {assert(!spinDepth && q!=selfFlush);hardwareFlushes.push_back(q);''')
    text = text.replace('BOOLEAN PowerStateDx=FALSE;', 'BOOLEAN PowerStateDx=FALSE,ConnectionActive=FALSE,P2pDiscovering=FALSE,ConnectDeparting=FALSE,ConnectTaskIsRoam=FALSE;ULONG ConnectCandidateCount=0;LONG ConnectGeneration=0;HostTimer StopTimers[5]={};AP6256_TIMER_OBJ P2pDiscoverTimer=&StopTimers[0],P2pListenTimer=&StopTimers[1],ScanTimer=&StopTimers[2],ConnectTimer=&StopTimers[3],DisconnectTimer=&StopTimers[4];AP6256_LOCK P2pLock;WDFWORKITEM LinkWorkItem=nullptr;AP6256_WDI_TASK ScanTask={},DisconnectTask={},P2pDiscoverTask={};')
    phase = group.typed_enum((ROOT / 'src/common/p2p.h').read_text(encoding='utf-8-sig'), 'AP6256_P2P_DISCOVER_PHASE')
    claim = group.typed_enum((ROOT / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig'), 'AP6256_CONNECT_CLAIM')
    text = text.replace('struct ColdDevice;', phase + claim + 'struct ColdDevice;')
    text = text.replace('PVOID WifiDirectDevice=nullptr;', 'struct {BOOLEAN Listening=FALSE;AP6256_P2P_DISCOVER_PHASE DiscoverPhase=Ap6256P2pDiscoverIdle;LONG DiscoverScanPending=0;} P2p;PVOID WifiDirectDevice=nullptr;')
    old = 'h->PortId==(id==WDI_INDICATION_FIRMWARE_STALLED?0xffff:2)'
    new = '(id==WDI_INDICATION_FIRMWARE_STALLED?h->PortId==0xffff:h->PortId<=2)'
    assert old in text
    text = text.replace(old, new)
    text += BOUNDARIES
    common = _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))
    cx = _functions((ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig'))
    hardware = _functions((ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig'))
    for (table, selected) in ((common, ('Ap6256ClaimMatchingTask', 'Ap6256ClaimExpiredTask', 'Ap6256ClaimConnectTask', 'Ap6256ConnectCompletionId')), (cx, ('Ap6256CxFlushTxWorkers',)), (hardware, ('Ap6256NetHardwareStop',))):
        for name in selected:
            if name not in _functions(text):
                text += table[name] + '\n'
                names.append(name)
    mock = _functions(text)['Ap6256TearDownChip']
    actual = mock.replace('d->Engine->HardwareAvailable=0;Ap6256ModelDeleteStationPeer(d->Engine);Ap6256CxQuiesceRole(d->Engine,2);Ap6256CancelGoAssociation(d->Engine,STATUS_POWER_STATE_INVALID);Ap6256CxGroupPeerDelete(d,nullptr);', 'Ap6256NetHardwareStop(d,STATUS_POWER_STATE_INVALID,worker);')
    assert actual != mock
    text = text.replace(mock, 'VOID Ap6256NetHardwareStop(Device*,NTSTATUS,BOOLEAN);\n' + actual)
    start = power.TEST.index('static void startAp(')
    end = power.TEST.index('static void powerCase(')
    text += power.TEST[start:end]
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    args = parser.parse_args()
    (text, names) = build_source()
    out = OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(group.base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(group.base.VC / 'include')]
    command += ['/I' + str(group.base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(group.base.VC / 'lib/x64'), '/LIBPATH:' + str(group.base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(group.base.LIB / 'um/x64'), 'advapi32.lib', str(group.base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')], capture_output=True, text=True, timeout=40)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/wificx/netadapter.c', 'src/wificx/role_adapter.inc', 'src/wificx/group_engine.inc', 'src/common/netadapter.c', 'src/common/kmdf_device.c', 'src/common/device.c', 'src/common/hotspot.c', 'src/common/netadapter_internal.h', 'tests/test-wificx-hardware-stop.py', 'tests/test-wificx-cold-power.py', 'tests/test-wificx-group-power.py', 'tests/test-wificx-group-integration.py')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'boundary': __doc__, 'board_verified': False, 'negative_control': None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
