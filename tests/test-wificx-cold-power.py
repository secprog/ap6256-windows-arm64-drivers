# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise WiFiCx D0/cold-ready callbacks and role rebuild with actual source.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, json, re, subprocess, shutil
from driver_sources import _functions
import importlib.util
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cold_group', ROOT / 'tests/test-wificx-group-integration.py')
group = importlib.util.module_from_spec(spec)
spec.loader.exec_module(group)
OUT = output_dir('wificx-cold-power')
BOUNDARIES = r'''
typedef PVOID WDFDEVICE;
static Device* Ap6256GetDeviceContext(WDFDEVICE h) {return static_cast<Device*>(h);}
struct NET_ADAPTER_LINK_LAYER_ADDRESS {UCHAR Bytes[6];};
static unsigned addressUpdates=0,discoveries=0,creates=0,starts=0,stops=0,resumes=0,capabilities=0,radios=0;
static NTSTATUS resumeStatus=STATUS_IO_DEVICE_ERROR,coldStatus=0,createStatus=0,capabilityStatus=0,radioStatus=0;
static bool haltDuringMbo=false,inCold=false;
static void NET_ADAPTER_LINK_LAYER_ADDRESS_INIT(NET_ADAPTER_LINK_LAYER_ADDRESS* a,ULONG n,const UCHAR* bytes) {assert(n==6);memcpy(a->Bytes,bytes,6);}
static void NetAdapterSetCurrentLinkLayerAddress(NETADAPTER a,const NET_ADAPTER_LINK_LAYER_ADDRESS* bytes) {assert(a && a->LogicalPort==2 && !memcmp(bytes->Bytes,a->Wifi->Ctx->Go.Address,6));++addressUpdates;}
static NTSTATUS Ap6256WifiP2pSetDiscoveryInterface(Device*,BOOLEAN enabled,PVOID) {assert(enabled && inCold);++discoveries;return 0;}
static NTSTATUS Ap6256WifiSetRadioState(Device*,BOOLEAN enabled) {assert(!enabled);++radios;return radioStatus;}
static NTSTATUS Ap6256MboInitialize(Wifi* w) {if(haltDuringMbo){w->Ctx->FirmwareHalted=1;Ap6256NetFirmwareHalted(w->Ctx);}return 0;}
static NTSTATUS Ap6256SetWifiCapabilities(WDFDEVICE h) {assert(Ap6256GetDeviceContext(h)->Engine->HardwareAvailable);++capabilities;return capabilityStatus;}
static NTSTATUS Ap6256WifiCxResumePower(Device* d) {++resumes;if(NT_SUCCESS(resumeStatus)){d->Engine->PowerStateDx=FALSE;d->Engine->RetainedResume=TRUE;d->LowPowerArmed=FALSE;}return resumeStatus;}
static VOID Ap6256TearDownChip(Device* d,BOOLEAN worker) {
 assert(!worker);++stops;d->Engine->HardwareAvailable=0;Ap6256ModelDeleteStationPeer(d->Engine);Ap6256CxQuiesceRole(d->Engine,2);Ap6256CancelGoAssociation(d->Engine,STATUS_POWER_STATE_INVALID);Ap6256CxGroupPeerDelete(d,nullptr);
 d->LowPowerArmed=FALSE;d->Go.FirmwareReady=FALSE;d->Go.Started=FALSE;d->Go.ClientConnected=FALSE;
}
NTSTATUS Ap6256NetHardwareStart(Device*);
static NTSTATUS Ap6256BringUpChip(Device* d,BOOLEAN worker) {
 assert(!worker);++starts;if(!NT_SUCCESS(coldStatus))return coldStatus;

 d->FirmwareHalted=0;d->Go.NativeStateUncertain=FALSE;inCold=true;NTSTATUS status=Ap6256NetHardwareStart(d);inCold=false;
 if(!NT_SUCCESS(status))Ap6256TearDownChip(d,FALSE);return status;
}
'''
TEST = r'''
static void resetCold() {addressUpdates=discoveries=creates=starts=stops=resumes=capabilities=radios=0;resumeStatus=STATUS_IO_DEVICE_ERROR;coldStatus=createStatus=capabilityStatus=radioStatus=0;haltDuringMbo=inCold=false;}
static void coldCase(ULONG mode) {
 fprintf(stderr,"cold power case %lu\n",mode);resetCold();auto owned=std::make_unique<Fixture>();auto& f=*owned;f.d.Device=&f.d;f.w.P2pPortCreated=TRUE;f.w.PowerStateDx=mode!=0 && mode!=4;f.w.HardwareAvailable=0;f.d.Go.FirmwareReady=FALSE;f.d.Go.NativeStateUncertain=TRUE;f.d.WifiCapabilitiesSet=mode!=0 && mode!=4;f.station.DataEnabled=0;f.w.Model.StationPeerCreated=FALSE;
 if(mode==1 || mode==2 || mode==3 || mode==5 || mode==6){f.d.LowPowerArmed=TRUE;f.w.HardwareAvailable=1;f.d.Go.FirmwareReady=TRUE;f.d.Go.NativeStateUncertain=FALSE;}
 if(mode==2)createStatus=STATUS_IO_DEVICE_ERROR;
 if(mode==3)resumeStatus=0;
 if(mode==4)capabilityStatus=STATUS_IO_DEVICE_ERROR;
 if(mode==5)haltDuringMbo=true;
 if(mode==6){f.w.SoftwareRadioState=FALSE;radioStatus=STATUS_IO_DEVICE_ERROR;}
 if(mode>=7){f.d.LowPowerArmed=TRUE;f.w.HardwareAvailable=mode==8;f.d.Go.FirmwareReady=TRUE;f.d.Go.NativeStateUncertain=TRUE;resumeStatus=0;}
 NTSTATUS entry=Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2);
 if(mode==2 || mode==5 || mode==6){assert(!NT_SUCCESS(entry) && !f.w.HardwareAvailable && f.w.PowerStateDx && !f.d.Go.FirmwareReady);return;}
 assert(entry==0 && f.w.HardwareAvailable);NTSTATUS ready=Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2);
 if(mode==4){assert(!NT_SUCCESS(ready) && stops==1 && !f.w.HardwareAvailable && !f.w.PowerStateDx);return;}
 assert(ready==0 && !f.w.PowerStateDx && !f.w.RetainedResume && f.w.HardwareAvailable);
 assert(f.w.Model.Roles[0]==&f.station && f.w.Model.Roles[1]==&f.group && f.station.Ready && f.group.Ready);
 if(mode==3){assert(resumes==1 && !starts && !stops && !creates && !capabilities);return;}
 assert(starts==1 && creates==1 && discoveries==1 && addressUpdates==1 && f.d.Go.FirmwareReady && !f.d.Go.NativeStateUncertain);
 assert(capabilities==(mode==0?1u:0u));assert(stops==((mode==1 || mode>=7)?1u:0u));assert(resumes==(mode==1?1u:0u));assert(!f.group.DataEnabled);
 OpaqueRequest r;f.connect(r,TRUE,1);assert(r.Status==0 && f.w.Model.ClientConnectTask.Active);assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0);
}
static void exitCase(WDF_POWER_DEVICE_STATE state,bool armed) {
 resetCold();auto owned=std::make_unique<Fixture>();auto& f=*owned;f.d.Device=&f.d;f.d.LowPowerArmed=armed;assert(Ap6256EvtD0Exit(&f.d,state)==0);
 if(state==WdfPowerDeviceD2 && armed){assert(!stops && f.w.HardwareAvailable && f.d.Go.FirmwareReady);}else{assert(stops==1 && !f.w.HardwareAvailable && !f.d.Go.FirmwareReady && !f.station.DataEnabled && !f.group.DataEnabled);}
}
int main(int argc,char** argv){if(argc>1){coldCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<9;++n)coldCase(n);exitCase(WdfPowerDeviceD2,true);exitCase(WdfPowerDeviceD2,false);exitCase(WdfPowerDeviceD3,true);puts("PASS: 12 actual WiFiCx D0/cold-ready/interface rebuild, retained-resume, failure-gating and D2/D3 exit cases");return 0;}
'''

def build_source():
    (text, names) = group.build_source()
    text = text.replace('int main(int argc,char** argv)', 'int groupIntegrationMain(int argc,char** argv)')
    text = text.replace('struct Device {', 'struct ColdDevice;using Device=ColdDevice;\nstruct ColdDevice {')
    text = text.replace('Wifi* Engine=nullptr;KSPIN_LOCK TalStateLock;', 'Wifi* Engine=nullptr;PVOID Device=nullptr;LONG FirmwareHalted=0;BOOLEAN LowPowerArmed=FALSE,WifiCapabilitiesSet=FALSE;KSPIN_LOCK TalStateLock;')
    text = text.replace('AP6256_MODEL_STATE Model={};WDFWORKITEM', 'BOOLEAN RetainedResume=FALSE,SoftwareRadioState=TRUE,P2pPortCreated=FALSE;AP6256_LOCK ConnectLock;\n AP6256_MODEL_STATE Model={};WDFWORKITEM')
    old = 'static NTSTATUS Ap6256GoCreate(Device* d) {assert(d->Go.Created && d->Go.FirmwareReady);return d->Go.NativeStateUncertain?STATUS_DEVICE_HARDWARE_ERROR:STATUS_SUCCESS;}'
    new = 'static NTSTATUS Ap6256GoCreate(Device* d) {if(inCold){++creates;if(NT_SUCCESS(createStatus))d->Go.FirmwareReady=TRUE;return createStatus;}assert(d->Go.Created && d->Go.FirmwareReady);return d->Go.NativeStateUncertain?STATUS_DEVICE_HARDWARE_ERROR:STATUS_SUCCESS;}'
    assert text.count(old) == 1
    text = text.replace(old, 'static bool inCold=false;static unsigned creates=0;static NTSTATUS createStatus=0;\n' + new)
    boundaries = BOUNDARIES.replace(',creates=0', '').replace(',createStatus=0', '').replace(',inCold=false', '')
    text += group.base.typed_enum((group.base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h').read_text(encoding='utf-8-sig'), 'WDF_POWER_DEVICE_STATE') if hasattr(group.base, 'typed_enum') else re.search('typedef enum _WDF_POWER_DEVICE_STATE\\s*\\{[\\s\\S]*?\\} WDF_POWER_DEVICE_STATE, \\*PWDF_POWER_DEVICE_STATE;', (group.base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h').read_text(encoding='utf-8-sig'))[0] + '\n'
    text += boundaries
    functions = {**_functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig')), **_functions((ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig')), **_functions((ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig')), **_functions((ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig')), **_functions((ROOT / 'src/common/kmdf_device.c').read_text(encoding='utf-8-sig'))}
    for name in ('Ap6256ModelGroupAddressChanged', 'Ap6256ModelStartInterfaces', 'Ap6256NetHardwareStart', 'Ap6256ModelHardwareReady', 'Ap6256EvtD0Entry', 'Ap6256EvtD0Exit', 'Ap6256EvtD0EntryPostInterruptsEnabled'):
        names.append(name)
        text += functions[name] + '\n'
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(9))
    args = parser.parse_args()
    (text, names) = build_source()
    out = OUT / 'current'
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(group.base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(group.base.VC / 'include')]
    command += ['/I' + str(group.base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(group.base.VC / 'lib/x64'), '/LIBPATH:' + str(group.base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(group.base.LIB / 'um/x64'), 'advapi32.lib', str(group.base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(args.case)] if args.case is not None else []), capture_output=True, text=True, timeout=40)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/common/kmdf_device.c', 'src/common/netadapter.c', 'src/wificx/netadapter.c', 'src/wificx/group_engine.inc', 'src/wificx/role_adapter.inc', 'src/wificx/netmodel_state.h', 'src/wificx/wowl_power.inc', 'src/common/firmware.c', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-cold-power.py')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'board_verified': False, 'boundary': __doc__, 'expect_regression': False, 'negative_control': None, 'entry_negative': False, 'case': args.case, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None or False else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
