# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute the unchanged shared mode dispatcher, Microsoft codec and native role change.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('mode_power', ROOT / 'tests/test-wificx-group-power.py')
power = importlib.util.module_from_spec(spec)
spec.loader.exec_module(power)
OUT = output_dir('wificx-group-mode')
GLOBALS = r'''
struct ModeAddPlan {bool fail=false,effect=true,getFail=false,eventLost=false,isolateFail=false,cleanupFail=false,bssInvalid=false;};
static ModeAddPlan addPlans[4]={};static unsigned addCalls=0,deleteCalls=0,cleanupCalls=0,getCalls=0,interfaceWaits=0,tdlsBlocks=0,tdlsRestores=0;
static bool nativePresent=true,deleteFail=false,deleteEffect=true,deleteEventLost=false,tdlsBlocked=true;
static UINT16 nativeRole=0;static bool strictSleepTransport=false;static ULONG nativeControlAttempts=0;
static bool modeDeliveryFail=false;static ULONG modeDeliveryStage=0,modeCompletionsAccepted=0;static Device* modeDeliveryDevice=nullptr;
static NTSTATUS Ap6256WifiCxArmWake(Device*);
VOID Ap6256RecomputePortModes(Wifi*);
'''
BOUNDARIES = r'''
static NTSTATUS Ap6256QualityReapply(Device*){return 0;}
static NTSTATUS Ap6256QualityForgetPort(Device*,UINT32){return 0;}
static VOID Ap6256QualityForgetGroupFirmware(Device*){}
static NTSTATUS KeDelayExecutionThread(int,BOOLEAN alert,const LARGE_INTEGER* delay){assert(!alert && delay->QuadPart==-100000);++interfaceWaits;return 0;}
#define KernelMode 0
static VOID Ap6256P2pTraceMemory(Device*,PCSTR){}
static VOID Ap6256P2pForgetIesFor(PVOID){}
static VOID Ap6256P2pReleaseIesFor(Device*,PVOID,UINT32 iface){assert(iface==7);}
static NTSTATUS Ap6256TdlsSetBlocked(Device*,BOOLEAN block){tdlsBlocked=block!=0;if(block)++tdlsBlocks;else ++tdlsRestores;return 0;}
static NTSTATUS Ap6256BcdcSetIovarResultIf(Device* d,UINT32 iface,PCSTR name,const VOID* p,ULONG n,AP6256_BCDC_QUERY_RESULT* result){
 assert(!spinDepth && iface==0 && !strcmp(name,"p2p_ifdel") && n==6 && !memcmp(p,d->Go.Address,6));++cleanupCalls;memset(result,0,sizeof(*result));
 if(addPlans[addCalls].cleanupFail)return STATUS_IO_TIMEOUT;
 result->FirmwareReply=TRUE;if(!nativePresent){result->FirmwareError=TRUE;result->FirmwareStatus=-30;return STATUS_NOT_FOUND;}
 nativePresent=false;d->FirmwareIfMap[2]=0;return 0;
}
static UINT16 Ap6256RequestGetMessageId(AP6256_REQUEST r){assert(r && r->Magic==0xcafed00d);return WDI_TASK_CHANGE_OPERATION_MODE;}
static NTSTATUS Ap6256GetRequestView(AP6256_REQUEST r,PWDI_MESSAGE_HEADER* h,const UCHAR** tlv,ULONG* n){assert(r && requestHeader && requestBytes && requestLength>=sizeof(*requestHeader));*h=requestHeader;*tlv=requestBytes+sizeof(*requestHeader);*n=requestLength-(ULONG)sizeof(*requestHeader);return 0;}
'''
PRIMARY = r'''
static NTSTATUS Ap6256BcdcSetIovar(Device* d,PCSTR name,const VOID* p,ULONG n){
 ++nativeControlAttempts;if(strictSleepTransport){NTSTATUS admission=modeControlAdmission(d);if(!NT_SUCCESS(admission))return admission;}assert(!spinDepth && !inRx);
 if(!strcmp(name,"arpoe") || !strcmp(name,"ndoe")){assert(n==4 && *(const UINT32*)p==0);return 0;}
 if(!strcmp(name,"p2p_ifdel")){
  assert(n==6 && !memcmp(p,d->Go.Address,6));++deleteCalls;io.push_back({0,0,name,std::vector<UCHAR>((const UCHAR*)p,(const UCHAR*)p+n)});
  if(!deleteFail || deleteEffect){nativePresent=false;if(!deleteEventLost)d->FirmwareIfMap[2]=0;}
  return deleteFail?STATUS_IO_TIMEOUT:0;
 }
 assert(!strcmp(name,"p2p_ifadd") && n==10 && !memcmp(p,d->Go.Address,6));++addCalls;assert(addCalls<4);
 UINT16 role=0,channel=0;memcpy(&role,(const UCHAR*)p+6,2);memcpy(&channel,(const UCHAR*)p+8,2);assert(role<=1 && channel==0xd024);
 io.push_back({0,0,name,std::vector<UCHAR>((const UCHAR*)p,(const UCHAR*)p+n)});auto& plan=addPlans[addCalls];
 if(!plan.fail || plan.effect){nativePresent=true;nativeRole=role;if(!plan.eventLost)d->FirmwareIfMap[2]=8;}
 return plan.fail?STATUS_IO_TIMEOUT:0;
}
'''
GET = r'''
static NTSTATUS Ap6256BcdcGetIovar(Device* d,PCSTR name,PVOID out,ULONG n){
 assert(!spinDepth && !inRx);
 if(!strcmp(name,"p2p_if")){assert(n==20 && !memcmp(out,d->Go.Address,6) && nativePresent);++getCalls;if(addPlans[addCalls].getFail)return STATUS_IO_DEVICE_ERROR;UINT32 bss=addPlans[addCalls].bssInvalid?0u:2u;memcpy(out,&bss,4);return 0;}
 assert(!strcmp(name,"wme") && n==4);++metadataReads;if(failWme)return STATUS_IO_TIMEOUT;*(UINT32*)out=1;return 0;
}
'''
TEST = r'''
static void modeTask(Fixture& f,OpaqueRequest& request,UINT32 mode,bool poison=false){
 WDI_TASK_CHANGE_OPERATION_MODE_PARAMETERS p={};p.OperationMode=(WDI_OPERATION_MODE_CONTAINER)mode;
 PUCHAR bytes=nullptr;ULONG n=0;assert(GenerateWdiTaskChangeOperationModeToIhv(&p,sizeof(WDI_MESSAGE_HEADER),&f.w.TlvContext,&n,&bytes)==0 && bytes);
 WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=933;h.IhvSpecificId=0xabcdef;
 requestHeader=&h;requestBytes=bytes;requestLength=n;poisonAtM3=poison;
 Ap6256ProcessCommand(&f.w,&request,0);assert(request.Completions==1);FreeGenerated(bytes);requestHeader=nullptr;requestBytes=nullptr;
}
static void modeCase(ULONG mode){
 fprintf(stderr,"group mode case %lu\n",mode);auto owned=std::make_unique<Fixture>();auto& f=*owned;
 for(auto& plan:addPlans)plan=ModeAddPlan{};addCalls=deleteCalls=cleanupCalls=getCalls=interfaceWaits=tdlsBlocks=tdlsRestores=0;
 strictSleepTransport=mode==37;nativeControlAttempts=0;modeDeliveryFail=false;modeCompletionsAccepted=0;modeDeliveryStage=mode;modeDeliveryDevice=&f.d;nativePresent=true;deleteFail=deleteEventLost=false;deleteEffect=true;tdlsBlocked=true;beforeLock=nullptr;actorDone=false;suspends=forgetCalls=0;suspendStatus=forgetStatus=0;
 f.d.Device=&f.d;f.d.FirmwareIfMap[2]=8;f.w.ApStarted=FALSE;f.w.PortCreated=TRUE;f.w.StationPortMode=AP6256_WDI_OPMODE_STA;f.w.P2pPortCreated=TRUE;f.w.P2pPortMode=AP6256_WDI_OPMODE_P2P_DEVICE;f.w.P2pPortNumber=1;
 UINT32 previous=mode==1 || mode==3 || mode==6 || mode==28?AP6256_WDI_OPMODE_P2P_GO:AP6256_WDI_OPMODE_P2P_CLIENT;
 UINT32 target=previous==AP6256_WDI_OPMODE_P2P_GO?AP6256_WDI_OPMODE_P2P_CLIENT:AP6256_WDI_OPMODE_P2P_GO;
 f.d.Go.Mode=previous;nativeRole=previous==AP6256_WDI_OPMODE_P2P_GO?1:0;Ap6256RecomputePortModes(&f.w);
 const UINT32 unionBefore=f.w.PortOperationMode;const LONG generation=f.w.Model.GroupGeneration;const ULONG stationTxBefore=(ULONG)transmits.size();
 UCHAR originalMac[6];memcpy(originalMac,f.d.Go.Address,6);f.stationTraffic();
 if(mode==2 || mode==3 || mode==27 || mode==28 || mode==36)target=previous;
 if(mode==4)target=AP6256_WDI_OPMODE_STA;
 if(mode==5)f.d.Go.Created=FALSE;
 if(mode==6 || mode==7){f.d.Go.Started=TRUE;f.group.DataEnabled=1;f.w.ApStarted=mode==6;}
 if(mode==8)f.w.Model.ClientConnectTask.Active=TRUE;
 if(mode==9 || mode==10){deleteFail=true;deleteEffect=mode==10;}
 if(mode==11)deleteEventLost=true;
 if(mode==12){addPlans[1].fail=true;addPlans[1].effect=false;}
 if(mode==13)addPlans[1].fail=true;
 if(mode==14)addPlans[1].getFail=true;
 if(mode==15)addPlans[1].eventLost=true;
 if(mode==16)addPlans[1].isolateFail=true;
 if(mode==17){addPlans[1].fail=true;addPlans[1].cleanupFail=true;}
 if(mode==18 || mode==30){addPlans[1].fail=addPlans[2].fail=true;addPlans[1].effect=addPlans[2].effect=false;}
 if(mode==19){addPlans[1].getFail=true;addPlans[2].getFail=addPlans[2].cleanupFail=true;}
 if(mode==20)f.w.PowerStateDx=TRUE;
 if(mode==21)f.w.HardwareAvailable=0;
 if(mode==22)f.w.Stopping=1;
 if(mode==23)f.d.Go.NativeStateUncertain=TRUE;
 if(mode==24 || mode==25 || mode==26 || mode==37){beforeLock=[&](AP6256_LOCK* lock){if(lock!=&f.w.Model.GroupLock || actorDone)return;actorDone=true;if(mode==24 || mode==37){assert(Ap6256WifiCxArmWake(&f.d)==0 && f.w.PowerStateDx && f.d.LowPowerArmed);}else if(mode==25)Ap6256NetFirmwareHalted(&f.d);else f.w.Stopping=1;};}
 if(mode>=32 && mode<=36)modeDeliveryFail=true;
 if(mode==29)addPlans[1].bssInvalid=true;
 if(mode==27 || mode==28){nativePresent=false;f.d.Go.FirmwareReady=FALSE;f.d.FirmwareIfMap[2]=0;}
 OpaqueRequest request;modeTask(f,request,target,mode==0);beforeLock=nullptr;
 const bool success=mode<4 || mode==27 || mode==28 || mode==31 || (mode>=32 && mode<=36);
 const bool quarantine=mode==9 || mode==10 || mode==11 || mode==17 || mode==19 || (mode>=33 && mode<=35);
 fprintf(stderr,"observed status %08lx host-mode %lu native-role %u present %u hw %ld dx %u uncertain %u ADD %u DEL %u cleanup %u\n",request.Status,f.d.Go.Mode,(unsigned)nativeRole,(unsigned)nativePresent,f.w.HardwareAvailable,(unsigned)f.w.PowerStateDx,(unsigned)f.d.Go.NativeStateUncertain,addCalls,deleteCalls,cleanupCalls);
 assert((request.Status==0)==success && count(WDI_INDICATION_CHANGE_OPERATION_MODE_COMPLETE)==(success?1u:0u));
 assert(f.w.Model.Roles[0]==&f.station && f.w.Model.Roles[1]==&f.group && f.group.PortId==73 && f.station.PortId==37 && !memcmp(originalMac,f.d.Go.Address,6));
 assert(f.w.Model.StationPeerGeneration==13 && f.station.Ready && f.station.DataEnabled && f.w.StationPortMode==AP6256_WDI_OPMODE_STA && f.w.P2pPortMode==AP6256_WDI_OPMODE_P2P_DEVICE);
 if(success){auto& done=lastIndication(WDI_INDICATION_CHANGE_OPERATION_MODE_COMPLETE);assert(done.Header.PortId==2 && done.Header.TransactionId==933 && done.Header.IhvSpecificId==0xabcdef && done.Bytes.empty());if(mode<32){assert(modeCompletionsAccepted==1 && f.d.Go.Mode==target && f.d.Go.FirmwareReady && nativePresent && nativeRole==(target==AP6256_WDI_OPMODE_P2P_GO?1:0) && f.w.Model.GroupGeneration==generation+1 && f.w.PortOperationMode==(AP6256_WDI_OPMODE_STA|AP6256_WDI_OPMODE_P2P_DEVICE|target));}
  else{assert(!modeCompletionsAccepted);if(mode==32 || mode==36){assert(f.d.Go.Mode==previous && f.d.Go.FirmwareReady && nativePresent && nativeRole==0 && f.w.Model.GroupGeneration==generation+2 && f.w.PortOperationMode==unionBefore);}else{assert(f.d.Go.Mode==target && f.w.Model.GroupGeneration==generation+1);}}}
 else{assert(f.d.Go.Mode==previous && f.w.Model.GroupGeneration==generation && f.w.PortOperationMode==unionBefore);}
 if(quarantine){assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && count(WDI_INDICATION_FIRMWARE_STALLED)==1 && !f.group.DataEnabled);}
 else if(mode!=23)assert(!f.d.Go.NativeStateUncertain);
 if((mode>=12 && mode<=16) || mode==29){assert(addCalls==2 && cleanupCalls==1 && nativePresent && f.d.Go.FirmwareReady && nativeRole==0 && !count(WDI_INDICATION_FIRMWARE_STALLED));}
 if(mode==37)assert(!nativeControlAttempts && io.empty() && f.w.PowerStateDx && f.d.FirmwareIoQuiesced && f.w.HardwareAvailable && !f.d.Go.NativeStateUncertain && request.Status==STATUS_DEVICE_NOT_READY);
 if(mode==17)assert(addCalls==1 && cleanupCalls==1);
 if(mode==34)assert(addCalls==3 && cleanupCalls==1);
 if(mode==35)assert(suspends==1 && f.w.PowerStateDx && f.d.LowPowerArmed);
 if(mode==36)assert(!addCalls && !deleteCalls);
 if(mode==18 || mode==30){assert(addCalls==2 && cleanupCalls==2 && !nativePresent && !f.d.Go.FirmwareReady && !f.d.Go.NativeStateUncertain && f.w.HardwareAvailable && !count(WDI_INDICATION_FIRMWARE_STALLED));}
 if(mode==11 || mode==15)assert(interfaceWaits==100);
 if(mode>=20 && mode<=26){assert(!addCalls && !deleteCalls && !cleanupCalls && io.empty());if(mode==24)assert(suspends==1 && f.w.PowerStateDx && f.d.LowPowerArmed);}
 if(mode==6 || mode==7)assert(f.group.DataEnabled && f.d.Go.Started);
 if(mode==8)assert(f.w.Model.ClientConnectTask.Active);
 if(mode==30){addCalls=0;for(auto& plan:addPlans)plan=ModeAddPlan{};OpaqueRequest retry;modeTask(f,retry,previous);assert(retry.Status==0 && nativePresent && f.d.Go.FirmwareReady && f.d.Go.Mode==previous && nativeRole==0);}
 if(mode==32){modeDeliveryFail=false;addCalls=0;OpaqueRequest retry;modeTask(f,retry,target);assert(retry.Status==0 && f.d.Go.Mode==target && modeCompletionsAccepted==1 && !f.d.Go.NativeStateUncertain);}
 if(mode==31){for(ULONG n=0;n<100;++n){addCalls=0;UINT32 next=f.d.Go.Mode==AP6256_WDI_OPMODE_P2P_GO?AP6256_WDI_OPMODE_P2P_CLIENT:AP6256_WDI_OPMODE_P2P_GO;OpaqueRequest repeat;modeTask(f,repeat,next);assert(repeat.Status==0 && f.d.Go.FirmwareReady && nativePresent && !memcmp(originalMac,f.d.Go.Address,6));f.stationTraffic();}}
 if(f.w.HardwareAvailable && !f.w.Stopping && !f.w.PowerStateDx){f.stationTraffic();assert(transmits.size()>=stationTxBefore+2);}
 assert(f.w.Model.GroupLock.try_lock());f.w.Model.GroupLock.unlock();assert(f.w.ConnectLock.try_lock());f.w.ConnectLock.unlock();
}
int main(int argc,char** argv){if(argc>1){modeCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<38;++n)modeCase(n);puts("PASS: 38 unchanged-dispatcher/codec/native GO-client mode cases, including 100 role alternations, rollback, lost replies/events and actual pre-lock wake actor; station ownership survives confirmed cleanup");return 0;}
'''

def build_source(frontend='wificx'):
    (text, names) = power.build_source()
    text = text.replace('int main(int argc,char** argv)', 'int groupPowerMain(int argc,char** argv)')
    text = text.replace('BOOLEAN FirmwareLinkUp=TRUE,', 'BOOLEAN FirmwareP2pSupported=TRUE;LONG FirmwareHalted=0,FirmwareIoQuiesced=0;PVOID PowerThread=nullptr;LONG FirmwareIfMap[16]={};BOOLEAN FirmwareLinkUp=TRUE,')
    text = text.replace('BOOLEAN ApStarted=TRUE;', 'BOOLEAN PortCreated=FALSE,P2pPortCreated=FALSE;UINT32 StationPortMode=0,P2pPortMode=0,PortOperationMode=0,P2pPortNumber=1;struct {AP6256_WDI_TASK Task={};} Ftm;BOOLEAN ApStarted=TRUE;')
    control = _functions((ROOT / 'src/common/bcdc.c').read_text(encoding='utf-8-sig'))
    bcdc = control.get('Ap6256BcdcDcmdTransaction', control['Ap6256BcdcDcmdWithResult'])
    admission = bcdc[bcdc.index('    if (InterlockedCompareExchange(&Ctx->FirmwareHalted'):bcdc.index('    if (Length > AP6256_BCDC_MAXBUF)')]
    gate = 'static PVOID KeGetCurrentThread(){return (PVOID)1;}\nstatic NTSTATUS modeControlAdmission(Device* Ctx){\n' + admission + '    return STATUS_SUCCESS;\n}\n'
    text = text.replace('struct Io {', GLOBALS + gate + 'struct Io {')
    text = text.replace('assert(!spinDepth && !inRx && iface==7);const UCHAR* p=', '++nativeControlAttempts;if(strictSleepTransport){NTSTATUS admission=modeControlAdmission(modeDeliveryDevice);if(!NT_SUCCESS(admission))return admission;}assert(!spinDepth && !inRx && iface==7);const UCHAR* p=')
    text = text.replace('++suspends;sleepSawGroup=d->Go.Started;', '++suspends;if(strictSleepTransport)d->FirmwareIoQuiesced=1;sleepSawGroup=d->Go.Started;')
    functions = _functions(text)
    text = text.replace(functions['Ap6256GoCreate'], 'NTSTATUS Ap6256GoCreate(Device*);')
    text = text.replace(functions['Ap6256BcdcSetIovar'], PRIMARY)
    text = text.replace(functions['Ap6256BcdcGetIovar'], GET)
    text = text.replace('indications.push_back({id,*h,tx,request,status,b});', 'indications.push_back({id,*h,tx,request,status,b});if(id==WDI_INDICATION_CHANGE_OPERATION_MODE_COMPLETE){if(modeDeliveryFail){if(modeDeliveryStage==33){deleteFail=true;deleteEffect=true;}if(modeDeliveryStage==34){addPlans[2].fail=true;addPlans[2].effect=false;}if(modeDeliveryStage==35)assert(Ap6256WifiCxArmWake(modeDeliveryDevice)==0);return STATUS_INSUFFICIENT_RESOURCES;}++modeCompletionsAccepted;}')
    text = text.replace('return nativeIo(iface,0,name,p,n);', 'if(!strcmp(name,"bsscfg:ap_isolate") && addPlans[addCalls].isolateFail)return STATUS_IO_DEVICE_ERROR;return nativeIo(iface,0,name,p,n);')
    text += '\n#undef TraceVerbose\n#define TraceVerbose(...) ((void)0)\n' + power.group.base.typed((ROOT / 'src/common/bcdc.h').read_text(encoding='utf-8-sig'), 'AP6256_BCDC_QUERY_RESULT') + '\n'
    for name in ('STATUS_NOT_FOUND', 'STATUS_POWER_STATE_INVALID'):
        text += '\n#ifndef ' + name + '\n' + re.search('^#define ' + name + '[^\\n]*', (power.group.base.INC / 'shared/ntstatus.h').read_text(encoding='utf-8-sig'), re.M)[0] + '\n#endif\n'
    ops = (ROOT / 'src/common/wifi_ops.h').read_text(encoding='utf-8-sig')
    for name in ('AP6256_P2P_IF_GO', 'AP6256_WDI_OPMODE_STA', 'AP6256_WDI_OPMODE_P2P_DEVICE'):
        definition = re.search('^#define\\s+' + name + '[^\\n]*', ops, re.M)[0]
        text += '\n#ifndef ' + name + '\n' + definition + '\n#endif\n'
    text += BOUNDARIES
    native = _functions((ROOT / 'src/common/hotspot.c').read_text(encoding='utf-8-sig'))
    common_source = (ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig')
    common = _functions(common_source)
    cx = _functions((ROOT / ('src/wdi/netadapter.c' if frontend == 'wdi' else 'src/wificx/group_engine.inc')).read_text(encoding='utf-8-sig'))
    for (table, selected) in ((native, ('Ap6256WaitFirmwareInterface', 'Ap6256GoCreate', 'Ap6256GoDelete', 'Ap6256GroupChangeMode')), (cx, ('Ap6256ModelChangeGroupMode', 'Ap6256ModelChangeGroupModeCompleted')), (common, ('Ap6256RecomputePortModes', 'Ap6256HandleChangeOperationMode'))):
        for name in selected:
            if name not in table:
                continue
            names.append(name)
            text += table[name].replace('= {0};', '= {};') + '\n'
    dispatcher = common['Ap6256ProcessCommand']
    existing = _functions(text)
    macros = common_source[common_source.index('#define AP6256_ACK_CASE'):common_source.index('static BOOLEAN Ap6256BandIsDisallowed')]
    for name in sorted(set(re.findall('\\b(Ap6256\\w+)\\s*\\(', dispatcher + macros)) - set(existing) - {'Ap6256ProcessCommand'}):
        text += 'template<class... T> static NTSTATUS ' + name + '(T...){assert(false);return STATUS_NOT_SUPPORTED;}\n'
    text += macros + dispatcher + '\n'
    names.append('Ap6256ProcessCommand')
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(38))
    parser.add_argument('--frontend', choices=('wificx', 'wdi'), default='wificx')
    args = parser.parse_args()
    (text, names) = build_source(args.frontend)
    out = OUT / ((args.frontend + '-' if args.frontend == 'wdi' else '') + (None or 'current'))
    out.mkdir(parents=True, exist_ok=True)
    old_hashes = {}
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    base = power.group.base
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64'), 'advapi32.lib', str(base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    case = args.case if args.case is not None else {'wake-admission': 24, 'lost-delete-reply': 10, 'lost-delete-event': 11, 'uncertain-create': 17, 'completion-rollback': 32, 'completion-cleanup': 33, 'strict-wake-admission': 37}.get(None)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(case)] if case is not None else []), capture_output=True, text=True, timeout=45)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/wificx/group_engine.inc', 'src/wificx/role_adapter.inc', 'src/wificx/wowl_power.inc', 'src/common/netadapter.c', 'src/common/hotspot.c', 'src/common/bcdc.c', 'src/common/netadapter_internal.h', 'src/common/wifi_ops.h', 'src/common/hotspot.h', 'src/common/bcdc.h', 'src/common/ap6256.h', 'src/common/netadapter.h', 'src/wificx/netmodel_state.h', 'src/wdi/netadapter.c', 'tests/test-wificx-group-mode.py', 'tests/test-wificx-group-power.py', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-roles.py')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'sdk_header_sha256': power.HEADERS, 'boundary': __doc__, 'board_verified': False, 'frontend_mode_hook': args.frontend, 'case': case, 'negative_control': None, 'negative_source_sha256': old_hashes or None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if None or False else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
