# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute actual WiFiCx wake arming and GO/client admission across sleep.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('power_group', ROOT / 'tests/test-wificx-group-integration.py')
group = importlib.util.module_from_spec(spec)
spec.loader.exec_module(group)
OUT = output_dir('wificx-group-power')
NET = group.base.INC / 'km/netcx/kmdf/adapter/2.5'
WIFI = group.base.INC / 'km/wificx/1.2'
HEADERS = {}

def header(path):
    HEADERS[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return path.read_text(encoding='utf-8-sig')

def sdk_init(source, name):
    match = re.search('\\binline\\s+void\\s+' + re.escape(name) + '\\s*\\(', source)
    assert match, name
    brace = source.index('{', match.end())
    depth = 1
    end = brace + 1
    while depth:
        if source[end] == '{':
            depth += 1
        elif source[end] == '}':
            depth -= 1
        end += 1
    return source[match.start():end] + '\n'

def typed_union(source, name):
    return re.search('typedef union _' + name + '\\s*\\{[\\s\\S]*?\\} ' + name + ';', source)[0] + '\n'
BOUNDARIES = r'''
typedef Device* WDFDEVICE;
typedef PVOID NETPOWEROFFLOAD,NETWAKESOURCE,WIFIPOWEROFFLOAD,WIFIWAKESOURCE;
static Device* Ap6256GetDeviceContext(WDFDEVICE d){return d;}
static unsigned suspends=0,resumes=0,coldStops=0,coldStarts=0,readyCalls=0,forgetCalls=0;
static NTSTATUS suspendStatus=0,resumeStatus=0,coldStatus=0,forgetStatus=0;
static bool sleepSawGroup=false,actorDone=false;
static constexpr UINT32 NetAdapterWakeMagicPatternId=0xfffffffeu,NetAdapterWakeEapolPatternId=0xfffffffdu;
static void NetDeviceGetPowerOffloadList(WDFDEVICE,NET_POWER_OFFLOAD_LIST*){}
static SIZE_T NetPowerOffloadListGetCount(const NET_POWER_OFFLOAD_LIST*){return 0;}
static NETPOWEROFFLOAD NetPowerOffloadListGetElement(const NET_POWER_OFFLOAD_LIST*,SIZE_T){assert(false);return nullptr;}
static NETADAPTER NetPowerOffloadGetAdapter(NETPOWEROFFLOAD){assert(false);return nullptr;}
static NET_POWER_OFFLOAD_TYPE NetPowerOffloadGetType(NETPOWEROFFLOAD){assert(false);return NetPowerOffloadTypeArp;}
static void NetPowerOffloadGetArpParameters(NETPOWEROFFLOAD,NET_POWER_OFFLOAD_ARP_PARAMETERS*){assert(false);}
static void NetPowerOffloadGetNSParameters(NETPOWEROFFLOAD,NET_POWER_OFFLOAD_NS_PARAMETERS*){assert(false);}
static void WifiDeviceGetPowerOffloadList(WDFDEVICE,WIFI_POWER_OFFLOAD_LIST*){}
static SIZE_T WifiPowerOffloadListGetCount(const WIFI_POWER_OFFLOAD_LIST*){return 0;}
static WIFIPOWEROFFLOAD WifiPowerOffloadListGetElement(const WIFI_POWER_OFFLOAD_LIST*,SIZE_T){assert(false);return nullptr;}
static NETADAPTER WifiPowerOffloadGetAdapter(WIFIPOWEROFFLOAD){assert(false);return nullptr;}
static WIFI_POWER_OFFLOAD_TYPE WifiPowerOffloadGetType(WIFIPOWEROFFLOAD){assert(false);return WifiPowerOffloadType80211RsnRekey;}
static void WifiPowerOffloadGet80211RSNRekeyParameters(WIFIPOWEROFFLOAD,WIFI_POWER_OFFLOAD_80211RSNREKEY_PARAMETERS*){assert(false);}
static void NetDeviceGetWakeSourceList(WDFDEVICE,NET_WAKE_SOURCE_LIST*){}
static SIZE_T NetWakeSourceListGetCount(const NET_WAKE_SOURCE_LIST*){return 0;}
static NETWAKESOURCE NetWakeSourceListGetElement(const NET_WAKE_SOURCE_LIST*,SIZE_T){assert(false);return nullptr;}
static NETADAPTER NetWakeSourceGetAdapter(NETWAKESOURCE){assert(false);return nullptr;}
static NET_WAKE_SOURCE_TYPE NetWakeSourceGetType(NETWAKESOURCE){assert(false);return NetWakeSourceTypeMagicPacket;}
static void NetWakeSourceGetBitmapParameters(NETWAKESOURCE,NET_WAKE_SOURCE_BITMAP_PARAMETERS*){assert(false);}
static void WifiDeviceGetWakeSourceList(WDFDEVICE,WIFI_WAKE_SOURCE_LIST*){}
static SIZE_T WifiWakeSourceListGetCount(const WIFI_WAKE_SOURCE_LIST*){return 0;}
static WIFIWAKESOURCE WifiWakeSourceListGetElement(const WIFI_WAKE_SOURCE_LIST*,SIZE_T){assert(false);return nullptr;}
static NETADAPTER WifiWakeSourceGetAdapter(WIFIWAKESOURCE){assert(false);return nullptr;}
static WIFI_WAKE_SOURCE_TYPE WifiWakeSourceGetType(WIFIWAKESOURCE){assert(false);return WifiWakeSourceTypeNloDiscovery;}
static NTSTATUS Ap6256WifiRemoveWolPattern(Device*,UINT32){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiRemoveNsOffload(Device*,UINT32){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiRemoveArpOffload(Device*,ULONG){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiRemoveGtkOffload(Device* d){assert(d->Engine->PowerStateDx);++forgetCalls;return forgetStatus;}
static NTSTATUS Ap6256WifiAddArpOffload(Device*,const AP6256_ARP_OFFLOAD*,ULONG){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiAddNsOffload(Device*,const AP6256_NS_OFFLOAD*){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256BuildGtkOffload(Wifi*,const WDI_PM_RSN_KEY_INFO_CONTAINER*,AP6256_GTK_OFFLOAD*){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiAddGtkOffload(Device*,const AP6256_GTK_OFFLOAD*){assert(false);return STATUS_NOT_SUPPORTED;}
static ULONG Ap6256WolPatternCeiling(Wifi*){return AP6256_WOL_PATTERN_MAX;}
static NTSTATUS Ap6256WifiAddWolBitmapPattern(Device*,UINT32,const UCHAR*,ULONG,const UCHAR*,ULONG){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiAddWolMagicPattern(Device*,UINT32){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiAddWolEapolPattern(Device*,UINT32){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiEnablePacketFilter(Device*,UINT32,BOOLEAN){assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n){assert(n==4 && *(const UINT32*)p==0 && (!strcmp(name,"arpoe") || !strcmp(name,"ndoe")));return 0;}
static NTSTATUS Ap6256WifiSuspendForWake(Device* d,UINT32 events,BOOLEAN arp,BOOLEAN ns){assert(d->Engine->PowerStateDx && !events && !arp && !ns);++suspends;sleepSawGroup=d->Go.Started;d->LowPowerArmed=TRUE;return suspendStatus;}
static NTSTATUS Ap6256WifiResumeFromWake(Device* d,UINT32*,AP6256_WAKE_PACKET*,BOOLEAN*){++resumes;if(NT_SUCCESS(resumeStatus))d->LowPowerArmed=FALSE;return resumeStatus;}
static VOID Ap6256TearDownChip(Device* d,BOOLEAN worker){assert(!worker && d->Engine->Model.GroupLock.try_lock());d->Engine->Model.GroupLock.unlock();assert(d->Engine->ConnectLock.try_lock());d->Engine->ConnectLock.unlock();++coldStops;d->Engine->HardwareAvailable=0;d->LowPowerArmed=FALSE;}
static NTSTATUS Ap6256BringUpChip(Device* d,BOOLEAN worker){assert(!worker);++coldStarts;if(NT_SUCCESS(coldStatus)){d->Engine->HardwareAvailable=1;d->Go.NativeStateUncertain=FALSE;}return coldStatus;}
static NTSTATUS Ap6256ModelHardwareReady(Device*){++readyCalls;return 0;}
'''
TEST = r'''
static void startAp(Fixture& f,OpaqueRequest& request){
 f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.w.ApStarted=FALSE;apDevice=&f.d;
 WDI_TASK_START_AP_PARAMETERS p={};UCHAR ssid[]={'t','e','s','t'};p.DesiredSSID.pElements=ssid;p.DesiredSSID.ElementCount=4;
 auto auth=WDI_AUTH_ALGO_RSNA_PSK;auto cipher=WDI_CIPHER_ALGO_CCMP;
 p.AuthenticationAlgorithms.pElements=&auth;p.AuthenticationAlgorithms.ElementCount=1;p.UnicastCipherAlgorithms.pElements=&cipher;p.UnicastCipherAlgorithms.ElementCount=1;p.MulticastCipherAlgorithms.pElements=&cipher;p.MulticastCipherAlgorithms.ElementCount=1;
 p.StaticParameters.BeaconPeriod=100;p.StaticParameters.DTIMPeriod=2;p.StaticParameters.ExcludeUnencrypted=TRUE;p.StaticParameters.AcceptNonP2PClients=TRUE;p.StaticParameters.MustUseSpecifiedChannels=TRUE;
 p.Optional.AdvertisedOperatingChannel_IsPresent=TRUE;p.AdvertisedOperatingChannel.ChannelNumber=36;p.AdvertisedOperatingChannel.OperatingClass=115;
 UCHAR* bytes=nullptr;ULONG length=0;assert(GenerateWdiTaskStartApToIhv(&p,0,&f.w.TlvContext,&length,&bytes)==0 && bytes);
 WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=901;Ap6256HandleStartAp(&f.w,&request,&h,bytes,length);FreeGenerated(bytes);assert(request.Completions==1);
 assert(count(WDI_INDICATION_START_AP_COMPLETE)==1 && lastIndication(WDI_INDICATION_START_AP_COMPLETE).Status==request.Status);
}
static void powerCase(ULONG mode){
 fprintf(stderr,"group power case %lu\n",mode);suspends=resumes=coldStops=coldStarts=readyCalls=forgetCalls=0;suspendStatus=resumeStatus=coldStatus=forgetStatus=0;sleepSawGroup=actorDone=false;beforeLock=nullptr;
 auto owned=std::make_unique<Fixture>();auto& f=*owned;f.d.Device=&f.d;f.w.ApStarted=FALSE;OpaqueRequest actor;
 hostCipherPowerMode=mode==15?1:mode==16?2:0;
 if(mode==17)f.d.HostFipsSessions[0].Generation=17;
 if(mode==1 || mode==2){beforeLock=[&](AP6256_LOCK* lock){if(lock==&f.w.ConnectLock && !actorDone){actorDone=true;if(mode==1)f.connect(actor,TRUE,1);else startAp(f,actor);assert(actor.Completions==1 && actor.Status==0 && f.d.Go.Started);}};}
 if(mode==5)f.connect(actor,TRUE,1);
 if(mode==6)startAp(f,actor);
 if(mode==7)f.w.HardwareAvailable=0;
 if(mode==8)f.w.Stopping=1;
 if(mode==9)f.d.Go.NativeStateUncertain=TRUE;
 if(mode==11 || mode==12 || mode==13)suspendStatus=STATUS_IO_DEVICE_ERROR;
 if(mode==12 || mode==13)resumeStatus=STATUS_IO_DEVICE_ERROR;
 if(mode==13)coldStatus=STATUS_IO_DEVICE_ERROR;
 if(mode==14)f.d.FirmwareWowlAdapter=FALSE;
 NTSTATUS status=Ap6256WifiCxArmWake(&f.d);
 assert(f.w.Model.GroupLock.try_lock());f.w.Model.GroupLock.unlock();assert(f.w.ConnectLock.try_lock());f.w.ConnectLock.unlock();
 if(mode==1 || mode==2 || (mode>=5 && mode<=9) || mode>=14){assert(status==STATUS_NOT_SUPPORTED && !suspends && !forgetCalls && !f.w.PowerStateDx && !f.d.LowPowerArmed);}
 else if(mode>=11 && mode<=13){assert(status==STATUS_IO_DEVICE_ERROR && !f.w.PowerStateDx && !f.d.LowPowerArmed);assert(coldStarts==(mode>=12?1u:0u) && coldStops==coldStarts && readyCalls==(mode==12?1u:0u));if(mode==13){f.connect(actor,TRUE,1);assert(actor.Status==STATUS_DEVICE_NOT_READY && io.empty());}else{f.connect(actor,TRUE,1);assert(actor.Status==0 && f.d.Go.Started);}}
 else {
  assert(status==0 && suspends==1 && forgetCalls==1 && f.w.PowerStateDx && f.d.LowPowerArmed && !sleepSawGroup);
  if(mode==3){f.connect(actor,TRUE,1);assert(actor.Status==STATUS_DEVICE_NOT_READY && io.empty() && !f.d.Go.Started && !f.w.Model.ClientConnectTask.Active && !f.group.DataEnabled);}
  if(mode==4){startAp(f,actor);assert(actor.Status==STATUS_DEVICE_NOT_READY && io.empty() && !f.d.Go.Started && !f.w.ApStarted && !f.group.DataEnabled);}
  if(mode==10){assert(Ap6256WifiCxArmWake(&f.d)==0 && suspends==1 && forgetCalls==1);}
 }
 beforeLock=nullptr;apDevice=nullptr;
}
int main(int argc,char** argv){if(argc>1){powerCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<18;++n)powerCase(n);puts("PASS: 18 actual WiFiCx GO/client/wake admission cases including active/retired host crypto and Host FIPS");return 0;}
'''

def build_source():
    (text, names) = group.build_source()
    text = text.replace('int main(int argc,char** argv)', 'int groupIntegrationMain(int argc,char** argv)')
    old_owner = _functions(text)['Ap6256HostCipherPacketActive']
    text = text.replace(old_owner, r'''static UINT32 hostCipherPowerMode=0;
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32 i){assert(i==0);return hostCipherPowerMode!=0;}
''')
    text = text.replace('#include <mutex>', '#include <functional>\n#include <mutex>')
    text = text.replace('typedef std::mutex AP6256_LOCK;', 'typedef std::mutex AP6256_LOCK;\nstatic std::function<void(AP6256_LOCK*)> beforeLock;')
    text = text.replace('assert(!spinDepth);l->lock();', 'assert(!spinDepth);if(beforeLock)beforeLock(l);l->lock();')
    ops = (ROOT / 'src/common/wifi_ops.h').read_text(encoding='utf-8-sig')
    internal = (ROOT / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig')
    types = re.search('^#define WIFI_STRUCTURE_SIZE\\(StructName\\).*sizeof\\(StructName\\).*', header(WIFI / 'wififuncenum.h'), re.M)[0] + '\n'
    for source in (ops, internal, (ROOT / 'src/common/netadapter.h').read_text(encoding='utf-8-sig')):
        for line in source.splitlines():
            if re.match('^#define AP6256_(?:ARP_OFFLOAD_SLOTS|NS_OFFLOAD_ADDRESSES|WAKE_PACKET_BYTES|WOL_PATTERN_MAX|WOL_PATTERN_BYTES|WAKE_ON_)', line) and line.split()[1] not in text:
                types += line + '\n'
    for name in ('AP6256_ARP_OFFLOAD', 'AP6256_NS_OFFLOAD', 'AP6256_GTK_OFFLOAD', 'AP6256_WAKE_PACKET'):
        types += group.base.typed(ops, name)
    cxTypes = header(NET / 'netadaptercxtypes.h')
    for name in ('NET_IPV4_ADDRESS', 'NET_IPV6_ADDRESS'):
        types += typed_union(cxTypes, name)
    types += group.base.typed(header(NET / 'netadapter.h'), 'NET_ADAPTER_LINK_LAYER_ADDRESS')
    for (path, records, enums) in ((NET / 'netpoweroffloadlist.h', ('NET_POWER_OFFLOAD_LIST',), ()), (NET / 'netwakesourcelist.h', ('NET_WAKE_SOURCE_LIST',), ()), (NET / 'netpoweroffload.h', ('NET_POWER_OFFLOAD_ARP_PARAMETERS', 'NET_POWER_OFFLOAD_NS_PARAMETERS'), ('NET_POWER_OFFLOAD_TYPE',)), (NET / 'netwakesource.h', ('NET_WAKE_SOURCE_BITMAP_PARAMETERS',), ('NET_WAKE_SOURCE_TYPE',)), (WIFI / 'wificxpoweroffloadlist.h', ('WIFI_POWER_OFFLOAD_LIST',), ()), (WIFI / 'wificxwakesourcelist.h', ('WIFI_WAKE_SOURCE_LIST',), ()), (WIFI / 'wificxpoweroffload.h', ('WIFI_POWER_OFFLOAD_80211RSNREKEY_PARAMETERS',), ('WIFI_POWER_OFFLOAD_TYPE',)), (WIFI / 'wificxwakesource.h', (), ('WIFI_WAKE_SOURCE_TYPE',))):
        source = header(path)
        if 'WIFI_RSN_MAX_CIPHER_KEY_LENGTH' in source:
            types += re.search('^#define WIFI_RSN_MAX_CIPHER_KEY_LENGTH[^\\n]*', source, re.M)[0] + '\n'
        for name in enums:
            types += group.typed_enum(source, name)
        for name in records:
            types += group.base.typed(source, name)
            types += sdk_init(source, name + '_INIT')
    nd = header(group.base.INC / 'shared/ntddndis.h')
    for name in ('NDIS_PM_PROTOCOL_OFFLOAD_ARP_SUPPORTED', 'NDIS_PM_PROTOCOL_OFFLOAD_NS_SUPPORTED', 'NDIS_PM_PROTOCOL_OFFLOAD_80211_RSN_REKEY_SUPPORTED'):
        types += '#ifndef ' + name + '\n' + re.search('^#define\\s+' + name + '[^\\n]*', nd, re.M)[0] + '\n#endif\n'
    types += (ROOT / 'src/common/power_stats.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    text = text.replace('struct Device {', types + 'struct GroupPowerDevice;using Device=GroupPowerDevice;\nstruct GroupPowerDevice {\n AP6256_POWER_SAVE_DX PowerSaveDx[2]={};')
    text = text.replace('Wifi* Engine=nullptr;KSPIN_LOCK TalStateLock;', 'Wifi* Engine=nullptr;Device* Device=nullptr;BOOLEAN FirmwareWowlAdapter=TRUE,LowPowerArmed=FALSE;UINT32 WakeEnabledPatterns=0,WakeEnabledOffloads=0,WakeMediaSpecificEvents=0;KSPIN_LOCK TalStateLock;')
    extra = 'AP6256_LOCK ConnectLock;ULONG WolPatternCount=0,WolPatternIds[AP6256_WOL_PATTERN_MAX]={},NsOffloadCount=0;WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER NsOffloads[AP6256_NS_OFFLOAD_ADDRESSES]={};WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER ArpOffloads[AP6256_ARP_OFFLOAD_SLOTS]={};BOOLEAN ArpOffloadValid[AP6256_ARP_OFFLOAD_SLOTS]={};ULONG ArpOffloadIds[AP6256_ARP_OFFLOAD_SLOTS]={};BOOLEAN GtkOffloadValid=FALSE;ULONG GtkOffloadId=0;AP6256_GTK_OFFLOAD GtkOffload={};'
    if 'BOOLEAN PowerStateDx=FALSE;' not in text:
        extra = 'BOOLEAN PowerStateDx=FALSE;' + extra
    text = text.replace('AP6256_MODEL_STATE Model={};WDFWORKITEM', extra + 'AP6256_MODEL_STATE Model={};WDFWORKITEM')
    text += BOUNDARIES
    functions = _functions((ROOT / 'src/wificx/wowl_power.inc').read_text(encoding='utf-8-sig'))
    for name in ('Ap6256WifiCxForgetSleepRecords', 'Ap6256WifiCxArmWake'):
        names.append(name)
        text += functions[name].replace('= {0};', '= {};') + '\n'
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(15))
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    (text, names) = build_source()
    out = args.output_dir or OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    negative = None
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(group.base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(group.base.VC / 'include')]
    command += ['/I' + str(group.base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(group.base.VC / 'lib/x64'), '/LIBPATH:' + str(group.base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(group.base.LIB / 'um/x64'), 'advapi32.lib', str(group.base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(args.case)] if args.case is not None else []), capture_output=True, text=True, timeout=40)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/wificx/wowl_power.inc', 'src/wificx/group_engine.inc', 'src/common/netadapter.c', 'src/common/netadapter_internal.h', 'src/wdi/netadapter.c', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-group-power.py')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'sdk_header_sha256': HEADERS, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'boundary': __doc__, 'board_verified': False, 'case': args.case, 'negative_control': None, 'negative_source_sha256': hashlib.sha256(negative.read_bytes()).hexdigest() if negative else None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
