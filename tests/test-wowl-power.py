# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"""Execute retained SDIO and wake lifecycle code with hardware fault injection."""
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import runpy, subprocess, re
from driver_sources import _functions, read_source_text
ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(ROOT / 'tests/test-wowl-offloads.py'))
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <map>
#include <string>
#include <vector>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((LONG)(s)>=0)
#define MAXULONG 0xffffffffu
#define STATUS_SUCCESS ((LONG)0)
#define STATUS_IO_TIMEOUT ((LONG)0xc00000b5)
#define STATUS_DEVICE_NOT_READY ((LONG)0xc00000a3)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((LONG)0xc0000182)
#define STATUS_DEVICE_PROTOCOL_ERROR ((LONG)0xc0000186)
#define TraceInfo(...) ((void)0)
#define TraceError(...) ((void)0)
#define TraceWarn(...) ((void)0)
#define PASSIVE_LEVEL 0
#define AP6256_SLEEP_LISTEN_MS 1000u
#define AP6256_PM_RSN_REKEY 0x80u
#define AP6256_PACKET_FILTER_SLEEP 8u
#define AP6256_PKT_FILTER_MODE_SLEEP 1u
#define AP6256_PKT_FILTER_MODE_AWAKE 0u
#define AP6256_WAKE_PACKET_NET 1u
struct Core {UINT32 Base,Rev;};typedef Core* PAP6256_CORE;
struct Device {
 struct {BOOLEAN RetentionInitialized=FALSE,SaveRestoreEnabled=FALSE,Sleeping=FALSE,ClockOn=TRUE,SepIntSaved=FALSE;UCHAR AwakeSepInt=0;UINT32 BackplaneWindow=0;} Sdio;
 struct {Core* ChipCommon;UINT32 CcCaps=0,PmuCaps=0,PmuRev=0,ChipId=BRCM_CC_4345_CHIP_ID;} Chip;
 struct {int Lock=0;} Bcdc;
 BOOLEAN HostFips=FALSE;UINT32 HostCipherMode=0;
 PVOID PowerThread=nullptr; LONG HostTxQuiesced=0,FirmwareIoQuiesced=0;
 BOOLEAN SavedPowerSaveValid=FALSE,SavedRoamOffValid=FALSE,SavedBeaconListenValid=FALSE,SavedD0FilterValid=FALSE;
 UINT32 SavedPowerSaveMode=0,SavedRoamOff=0,SavedBeaconListenDtim=0,SavedD0FilterEnable=0;
 BOOLEAN LowPowerArmed=FALSE,SavedLowPowerStateValid=FALSE;
 BOOLEAN FirmwareWowlAdapter=TRUE,FirmwareGtkOffloadSupported=TRUE,FirmwareArpOffloadSupported=TRUE,FirmwareNdOffloadSupported=TRUE;
 UINT32 PacketFilterMask=4,WakeEnabledOffloads=AP6256_PM_RSN_REKEY;
 ULONGLONG RetainedSleepStarted=0;
 AP6256_POWER_SAVE_DX PowerSaveDx[2]={};
 struct {BOOLEAN FirmwareReady=FALSE,NativeStateUncertain=FALSE;UINT32 IfIndex=7;} Go;
};typedef Device* PAP6256_DEVICE_CONTEXT;
struct AP6256_WAKE_PACKET {UINT32 Type,PatternId,OriginalLength,SavedLength;UCHAR Packet[128];};
Core fakeCc={0x18000000u,40},fakePmu={0x18012000u,20};
std::map<UINT32,UINT32> bp;std::map<UINT32,UCHAR> f0,f1;
std::map<std::string,UINT32> settings;
UINT32 failWrite=0;bool stuck=false,failClock=false,run=true,failPm=false;
bool failPowerStats=false;
std::string failGet,failSet;unsigned clockRequests=0;ULONGLONG now=100,extended=0;
std::vector<std::pair<std::string,UINT32>> writes;
void reset(){bp.clear();f0.clear();f1.clear();settings.clear();writes.clear();failWrite=0;stuck=failClock=failPm=failPowerStats=false;run=true;failGet.clear();failSet.clear();clockRequests=0;now=100;extended=0;
 bp[fakeCc.Base+CC_CAPABILITIES]=CC_CAP_PMU;bp[fakeCc.Base+CC_CAPABILITIES_EXT]=0x40;
 bp[fakePmu.Base+CC_PMU_CAPABILITIES]=20;bp[fakePmu.Base+CC_CHIPCONTROL_ADDR]=7;bp[fakePmu.Base+CC_CHIPCONTROL_DATA]=4;
 f0[SDIO_CCCR_BRCM_SEPINT]=2;f1[SBSDIO_FUNC1_SLEEPCSR]=3;f1[SBSDIO_FUNC1_CHIPCLKCSR]=2;
 settings["bcn_li_dtim"]=2;settings["roam_off"]=1;settings["d0_filter_enable"]=3;
}
Core* Ap6256ChipGetCore(void*,UINT32 id){assert(id==0x827);return &fakePmu;}
NTSTATUS Ap6256SdioReadBackplane32(Device*,UINT32 a,UINT32* p){*p=bp[a];return 0;}
NTSTATUS Ap6256SdioWriteBackplane32(Device*,UINT32 a,UINT32 v){bp[a]=v;return a==failWrite?STATUS_IO_TIMEOUT:0;}
NTSTATUS Ap6256SdioReadF0(Device*,UINT32 a,UCHAR* p){*p=f0[a];return 0;}
NTSTATUS Ap6256SdioWriteF0(Device*,UINT32 a,UCHAR v){f0[a]=v;return a==failWrite?STATUS_IO_TIMEOUT:0;}
NTSTATUS Ap6256SdioReadF1(Device*,UINT32 a,UCHAR* p){*p=f1[a];return 0;}
NTSTATUS Ap6256SdioWriteF1(Device*,UINT32 a,UCHAR v){
 if(!stuck)f1[a]=(a==SBSDIO_FUNC1_SLEEPCSR && v==1)?3:v;
 return a==failWrite?STATUS_IO_TIMEOUT:0;
}
void Ap6256StallUs(ULONG){}
NTSTATUS Ap6256SdioEnableBackplaneClock(Device* d,BOOLEAN ht){assert(ht&&!d->Sdio.ClockOn);++clockRequests;if(failClock)return STATUS_IO_TIMEOUT;d->Sdio.ClockOn=TRUE;return 0;}
NTSTATUS Ap6256SdioDisableBackplaneClock(Device* d){d->Sdio.ClockOn=FALSE;return 0;}
PVOID KeGetCurrentThread(){return (PVOID)1;}
ULONGLONG KeQueryInterruptTime(){return now;}
void Ap6256LockAcquire(int* l){assert(!*l);*l=1;}
void Ap6256LockRelease(int* l){assert(*l);*l=0;}
NTSTATUS Ap6256BcdcGetIovar(Device*,const char* n,PVOID p,ULONG len){assert(len==4);*(UINT32*)p=settings[n];return failGet==n?STATUS_IO_TIMEOUT:0;}
NTSTATUS Ap6256BcdcSetIovar(Device*,const char* n,const VOID* p,ULONG len){assert(len==4);UINT32 v=*(const UINT32*)p;settings[n]=v;writes.emplace_back(n,v);return failSet==n?STATUS_IO_TIMEOUT:0;}
NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 c,PVOID p,ULONG len){assert(len==4);*(UINT32*)p=c==BRCMF_C_GET_PM?1:c==BRCMF_C_GET_BCNPRD?100:2;return c==BRCMF_C_GET_PM&&failPm?STATUS_IO_TIMEOUT:0;}
NTSTATUS Ap6256BcdcSetDcmd(Device*,UINT32 c,const VOID* p,ULONG){assert(c==BRCMF_C_SET_PM);writes.emplace_back("pm",*(const UINT32*)p);return 0;}
NTSTATUS Ap6256WifiSetPowerSave(Device* d,BOOLEAN e){UINT32 v=e?2:0;return Ap6256BcdcSetDcmd(d,BRCMF_C_SET_PM,&v,4);}
NTSTATUS Ap6256WifiEnableProtocolOffloads(Device* d,BOOLEAN a,BOOLEAN n){UINT32 v=a;NTSTATUS s=Ap6256BcdcSetIovar(d,"arpoe",&v,4);v=n;if(NT_SUCCESS(s))s=Ap6256BcdcSetIovar(d,"ndoe",&v,4);return s;}
NTSTATUS Ap6256WifiArmWakeEvents(Device*,UINT32){return 0;}
NTSTATUS Ap6256WifiSetMasterPacketFilter(Device*,UINT32){return 0;}
NTSTATUS Ap6256WifiSetPacketFilterMode(Device*,UINT32){return 0;}
NTSTATUS Ap6256WifiConfigureEvents(Device*){return 0;}
NTSTATUS Ap6256WifiReadWakeEvents(Device*,UINT32* p){*p=2;return 0;}
NTSTATUS Ap6256WifiReadWakePacket(Device*,AP6256_WAKE_PACKET* p){memset(p,0,sizeof(*p));return 0;}
void Ap6256DatapathSuspend(Device* d){assert(d->HostTxQuiesced&&d->FirmwareIoQuiesced);run=false;}
void Ap6256DatapathResume(Device* d){assert(!d->Sdio.Sleeping);run=true;}
void Ap6256WlfcResumeRetained(Device*,ULONGLONG t){extended=t;}
NTSTATUS Ap6256QualityReapply(Device* d){assert(!d->FirmwareIoQuiesced && !d->PowerThread);return 0;}
void Ap6256NetTxKick(Device* d){assert(!d->HostTxQuiesced&&!d->FirmwareIoQuiesced);}
NTSTATUS Ap6256WifiGetPowerSaveStats(Device* d,UINT32 iface,PAP6256_POWER_SAVE_STATS p){
 assert(d->PowerThread==KeGetCurrentThread()&&!d->Sdio.Sleeping&&d->HostTxQuiesced&&d->FirmwareIoQuiesced);
 assert(iface==0||iface==7);memset(p,0,sizeof(*p));
 p->Mode=iface?0:2;p->ListenInterval=(UCHAR)(iface?1:2*settings["bcn_li_dtim"]);
 return failPowerStats?STATUS_IO_TIMEOUT:0;
}
'''
TEST = r'''
int main(){
 reset();Device d;d.Chip.ChipCommon=&fakeCc;
 assert(!Ap6256SdioInitializeRetention(&d));assert(d.Sdio.SaveRestoreEnabled&&bp[fakePmu.Base+CC_CHIPCONTROL_ADDR]==7);
 assert(!Ap6256SdioSetSleep(&d,TRUE));assert(d.Sdio.Sleeping&&!d.Sdio.ClockOn&&f0[SDIO_CCCR_BRCM_SEPINT]==7&&f1[SBSDIO_FUNC1_SLEEPCSR]==0);
 assert(!Ap6256SdioSetSleep(&d,FALSE));assert(!d.Sdio.Sleeping&&d.Sdio.ClockOn&&clockRequests==1&&f0[SDIO_CCCR_BRCM_SEPINT]==2&&d.Sdio.BackplaneWindow==MAXULONG);
 for(UINT32 address:{(UINT32)SDIO_CCCR_BRCM_SEPINT,(UINT32)SBSDIO_FUNC1_SLEEPCSR}){
  reset();Device x;x.Chip.ChipCommon=&fakeCc;assert(!Ap6256SdioInitializeRetention(&x));failWrite=address;
  assert(Ap6256SdioSetSleep(&x,TRUE)==STATUS_IO_TIMEOUT&&x.Sdio.Sleeping);
  failWrite=0;assert(!Ap6256SdioSetSleep(&x,FALSE));assert(clockRequests==1&&!x.Sdio.Sleeping&&f0[SDIO_CCCR_BRCM_SEPINT]==2);
 }
 reset();stuck=true;assert(Ap6256SdioSetKso(&d,FALSE)==STATUS_IO_TIMEOUT);stuck=false;
 reset();Device old;old.Chip.ChipCommon=&fakeCc;bp[fakePmu.Base+CC_PMU_CAPABILITIES]=16;
 assert(!Ap6256SdioSetSleep(&old,TRUE)&&!old.Sdio.SaveRestoreEnabled&&!old.Sdio.ClockOn);
 assert(!Ap6256SdioSetSleep(&old,FALSE)&&old.Sdio.ClockOn);
 reset();Device x;x.Chip.ChipCommon=&fakeCc;
 assert(!Ap6256WifiSuspendForWake(&x,2,TRUE,TRUE));assert(!run&&x.LowPowerArmed&&x.Sdio.Sleeping&&x.PowerThread==nullptr&&settings["wdi_wowl_sleep"]==3);
 assert(x.PowerSaveDx[0].Seen&&x.PowerSaveDx[0].Valid&&x.PowerSaveDx[0].Mode==2&&x.PowerSaveDx[0].ListenInterval==10&&!x.PowerSaveDx[1].Seen);
 now=1100;UINT32 reason;AP6256_WAKE_PACKET packet;BOOLEAN valid;
 assert(!Ap6256WifiResumeFromWake(&x,&reason,&packet,&valid));assert(run&&!x.LowPowerArmed&&!x.HostTxQuiesced&&!x.FirmwareIoQuiesced&&reason==2&&!valid&&extended==1000);
 assert(settings["bcn_li_dtim"]==2&&settings["roam_off"]==1&&settings["d0_filter_enable"]==3&&settings["arpoe"]==0&&settings["ndoe"]==0);
 assert(x.PowerSaveDx[0].ListenInterval==10);

 for(int failure=0;failure<3;failure++){
  reset();Device bad;bad.Chip.ChipCommon=&fakeCc;failPm=failure==0;failGet=failure==1?"roam_off":failure==2?"bcn_li_dtim":"";
  bad.PowerSaveDx[0]={TRUE,TRUE,19,0,1};
  assert(Ap6256WifiSuspendForWake(&bad,2,FALSE,FALSE)==STATUS_IO_TIMEOUT);
  assert(bad.PowerSaveDx[0].ListenInterval==19&&bad.PowerSaveDx[0].Mode==1);
  writes.clear();failGet.clear();failPm=false;assert(!Ap6256WifiResumeFromWake(&bad,&reason,&packet,&valid));
  std::string unavailable=failure==0?"pm":failure==1?"roam_off":"bcn_li_dtim";
  for(auto& w:writes)assert(w.first!=unavailable);
 }
 reset();Device fail;fail.Chip.ChipCommon=&fakeCc;assert(!Ap6256WifiSuspendForWake(&fail,2,TRUE,TRUE));
 failClock=true;assert(Ap6256WifiResumeFromWake(&fail,&reason,&packet,&valid)==STATUS_IO_TIMEOUT);
 assert(!run&&fail.HostTxQuiesced&&fail.FirmwareIoQuiesced&&fail.LowPowerArmed);
 failClock=false;failSet="ndoe";assert(Ap6256WifiResumeFromWake(&fail,&reason,&packet,&valid)==STATUS_IO_TIMEOUT);
 reset();Device measure;measure.Chip.ChipCommon=&fakeCc;failPowerStats=true;
 assert(!Ap6256WifiSuspendForWake(&measure,2,FALSE,FALSE));assert(measure.PowerSaveDx[0].Seen&&!measure.PowerSaveDx[0].Valid);
 reset();Device owner;owner.Chip.ChipCommon=&fakeCc;owner.Go.FirmwareReady=TRUE;
 assert(!Ap6256WifiSuspendForWake(&owner,2,FALSE,FALSE));assert(owner.PowerSaveDx[1].Seen&&owner.PowerSaveDx[1].Valid&&owner.PowerSaveDx[1].Mode==0&&owner.PowerSaveDx[1].ListenInterval==1);
 reset();Device bus;bus.Chip.ChipCommon=&fakeCc;bus.PowerSaveDx[0]={TRUE,TRUE,19,0,1};failWrite=SDIO_CCCR_BRCM_SEPINT;
 assert(Ap6256WifiSuspendForWake(&bus,2,FALSE,FALSE)==STATUS_IO_TIMEOUT&&bus.PowerSaveDx[0].ListenInterval==19);
 for(unsigned mode=1;mode<=3;++mode){
  reset();Device blocked;blocked.Chip.ChipCommon=&fakeCc;
  blocked.HostFips=mode==1;blocked.HostCipherMode=mode==1?0:mode-1;
  assert(Ap6256WifiSuspendForWake(&blocked,2,TRUE,TRUE)==STATUS_NOT_SUPPORTED);
  assert(writes.empty() && !clockRequests && !blocked.LowPowerArmed && !blocked.Sdio.Sleeping &&
         !blocked.HostTxQuiesced && !blocked.FirmwareIoQuiesced && !blocked.PowerThread && run);
 }
 puts("PASS: 3 host-crypto retained-sleep refusals before quiesce, firmware writes or bus transitions");
 puts("PASS: production SR qualification, KSO timeouts, lost ACK recovery, saved-state failures and retained D2 lifecycle");
 puts("PASS: measured last-Dx staging, successful bus commit, failed prepare/bus preservation, missing measurement and group ownership");
}
'''

def main():
    sdio = _functions(read_source_text(ROOT / 'src/common/sdio.c'))
    ops = _functions(read_source_text(ROOT / 'src/common/wifi_ops.c'))
    constants = ''
    for name in ['chipregs.h', 'hwids.h', 'sdpcm.h']:
        constants += '\n'.join(re.findall('^#define (?:CC_(?:CAPABILITIES(?:_EXT)?|CAP_PMU|PMU_CAPABILITIES|CHIPCONTROL_ADDR|CHIPCONTROL_DATA)|BRCM_CC_4345(?:4)?_CHIP_ID|SDIO_CCCR_BRCM_(?:CARDCAP(?:_CMD14_(?:SUPPORT|EXT))?|SEPINT(?:_MASK|_OE|_ACT_HI)?)|SBSDIO_(?:FUNC1_(?:WAKEUPCTRL|SLEEPCSR(?:_KSO_(?:EN|MASK)|_DEVON_MASK)?|CHIPCLKCSR)|FORCE_HT|ALP_AVAIL_REQ)|BRCMF_C_(?:GET_(?:PM|BCNPRD|DTIMPRD)|SET_PM))\\s+[^\\n]+', (ROOT / 'src/common' / name).read_text(encoding='utf-8-sig'), re.M)) + '\n'
    definitions = (ROOT / 'src/common/power_stats.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    pre = PRE.replace('struct Core {', definitions + '\nstruct Core {')
    capture = _functions((ROOT / 'src/common/power_stats.inc').read_text(encoding='utf-8-sig'))['Ap6256PowerCaptureDx']
    code = constants + pre + r'''
#define STATUS_NOT_SUPPORTED ((LONG)0xc00000bb)
static BOOLEAN Ap6256FipsActive(Device* d,UINT32 i) {assert(i==0);return d->HostFips;}
static BOOLEAN Ap6256HostCipherPacketActive(Device* d,UINT32 i) {assert(i==0);return d->HostCipherMode!=0;}
''' + capture + ''.join((sdio[n] for n in ['Ap6256SdioInitializeRetention', 'Ap6256SdioSetKso', 'Ap6256SdioSetSleep']))
    code += ''.join((ops[n] for n in ['Ap6256WifiStretchBeaconListen', 'Ap6256WifiSuspendForWake', 'Ap6256WifiResumeFromWake'])) + TEST
    out = output_dir('wowl-power')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    (VC, INC, LIB) = (BASE['VC'], BASE['INC'], BASE['LIB'])
    cmd = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(VC / 'include')]
    cmd += ['/I' + str(INC / n) for n in ['ucrt', 'shared', 'um']]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
