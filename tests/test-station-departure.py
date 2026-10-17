# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import json
import re
import subprocess
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]
(INC, LIB) = (INC, LIB)
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <algorithm>
typedef LONG NTSTATUS;
typedef void* NDIS_HANDLE;
typedef int NDIS_SHUTDOWN_ACTION;
#define NdisShutdownPowerOff 0
#define NdisShutdownBugCheck 1
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_POWER_STATE_INVALID ((NTSTATUS)0xc00002d3)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define MAXULONG 0xffffffffUL
#define PASSIVE_LEVEL 0
#define KernelMode 0
#define Ap6256FwNotLoaded 0
#define Ap6256FwRunning 1
#define AP6256_RADIO_UPDOWN_ARG 1u
#define AP6256_STATION_PORT 0u
#define AP6256_WLFC_ANY 255u
#define SD_REG_HOSTINTMASK 0x24u
#define SD_REG_INTSTATUS 0x20u
#define SDIO_CCCR_IEN_FUNC0 1u
#define SDIO_CCCR_IEN_FUNC1 2u
#define SDIO_CCCR_IEN_FUNC2 4u
#define WL_RADIO_SW_DISABLE 1u
#define BRCMF_C_UP 2u
#define BRCMF_C_DOWN 3u
#define BRCMF_C_DISASSOC 52u
#define BRCMF_C_GET_RADIO 37u
#define BRCMF_C_SET_RADIO 38u
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceInfo(...) ((void)0)
struct Core {UINT32 Base;};
struct Device {
    struct {void* BusInterface;bool Sleeping,ClockOn,RetentionInitialized,SaveRestoreEnabled,SepIntSaved;ULONG BackplaneWindow;} Sdio;
    struct {Core* SdiodCore;Core* ArmCore;} Chip;
    struct {bool FirmwareReady,Started;} Go;
    struct {bool Configured;LONG Generation;} HostCipherStore;
    bool FirmwareHostCipherPatchVerified,DatapathRunning,FirmwareLinkUp,SupplicantComplete,ConnectionRequiresSupplicant;
    bool LowPowerArmed,FirmwareWowlAdapter,FirmwareGtkOffloadSupported,P2pBssValid,Fips;
    ULONG WowlCapabilities,D11IoType;
    LONG FirmwareIoQuiesced,HostTxQuiesced,FirmwareHalted,FirmwareIfMap[16];
    int FirmwareState;
    int NativeKeyLock;
    BOOLEAN NativeDeparturePending;
    void* PowerThread;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static std::vector<std::string> ops;
static unsigned irql;
static NTSTATUS command_status=STATUS_SUCCESS,sleep_status=STATUS_SUCCESS;
static bool keys=true,radio_enabled=true,admission=true,native_recovery=false;
static int grace;
static void mark(const char* s){ops.emplace_back(s);}
static void Ap6256LockAcquire(int* p){++*p;}
static void Ap6256LockRelease(int* p){assert(*p>0);--*p;}
static void Ap6256WifiForgetNativeKeys(Device* c){c->NativeDeparturePending=false;mark("forget-native-keys");}
static unsigned KeGetCurrentIrql(){return irql;}
static void* KeGetCurrentThread(){return (void*)1;}
static LONG InterlockedCompareExchange(LONG* p,LONG value,LONG compare){LONG old=*p;if(old==compare)*p=value;return old;}
static LONG InterlockedExchange(LONG* p,LONG value){LONG old=*p;*p=value;return old;}
static bool Ap6256HostCipherStoreActive(decltype(Device::HostCipherStore)* s,UINT32 i){assert(i==0);return s->Configured;}
static bool Ap6256FipsActive(Device* c,UINT32 i){assert(i==0);return c->Fips;}
static NTSTATUS Ap6256NativeDeparture(Device* c,const UCHAR*,UINT32,BOOLEAN* handled){*handled=(BOOLEAN)native_recovery;if(!native_recovery)return 0;mark(c->FirmwareHostCipherPatchVerified?"native-qualified-recovery":"native-unqualified-recovery");return c->FirmwareHostCipherPatchVerified?0:STATUS_DEVICE_NOT_READY;}
static NTSTATUS Ap6256WifiClearSecurityState(Device* c){assert(c->FirmwareHostCipherPatchVerified);c->NativeDeparturePending=false;mark("native-security-cleanup");return 0;}
static void Ap6256WlfcCancel(Device*,UINT32 port,UINT32 scope,void* peer){assert(port==0 && scope==255 && !peer);mark("cancel-station-tx");}
static NTSTATUS Ap6256BcdcSetDcmd(Device* c,UINT32 cmd,void* p,ULONG n){
    assert(irql==0 && c->Sdio.BusInterface);
    if(cmd==BRCMF_C_DISASSOC){assert(keys && radio_enabled && !c->HostCipherStore.Configured && !c->Fips && !p && !n);mark("departure");return command_status;}
    assert(p && n==4);
    if(cmd==BRCMF_C_SET_RADIO){mark("set-radio");radio_enabled=(*(UINT32*)p&1)==0;}
    else {assert(*(UINT32*)p==1);assert(cmd==BRCMF_C_UP || cmd==BRCMF_C_DOWN);mark(cmd==BRCMF_C_UP?"up":"down");if(cmd==BRCMF_C_DOWN)radio_enabled=false;}
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 cmd,void* p,ULONG n){assert(cmd==BRCMF_C_GET_RADIO && n==4);*(UINT32*)p=radio_enabled?0:1;mark("get-radio");return STATUS_SUCCESS;}
static NTSTATUS Ap6256WifiUp(Device*){mark("wifi-up");return STATUS_SUCCESS;}
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER* d){assert(irql==0 && !mode && !alert && d->QuadPart==-5000000LL && keys && radio_enabled);mark("grace");++grace;return STATUS_SUCCESS;}
static void Ap6256HostCipherFirmwareRetire(Device* c){c->HostCipherStore.Generation=0;mark("retire-host-owner");}
static NTSTATUS Ap6256SdioSetSleep(Device* c,BOOLEAN sleep){assert(!sleep);mark("wake");if(NT_SUCCESS(sleep_status))c->Sdio.Sleeping=false;return sleep_status;}
static void Ap6256DatapathResume(Device*){mark("resume-datapath");}
static void Ap6256PnoResultsQuiesce(Device*){mark("quiesce-pno");}
NTSTATUS Ap6256WifiLeaveForPowerDown(Device*);
static void Ap6256NetHardwareStop(Device* Ctx,NTSTATUS status,BOOLEAN){assert(status==STATUS_POWER_STATE_INVALID);admission=false;mark("stop-workers");HARDWARE_STOP_HOOK;(void)Ctx;}
static NTSTATUS Ap6256SdioWriteBackplane32(Device*,UINT32,UINT32){mark("mask-irq");return STATUS_SUCCESS;}
static NTSTATUS Ap6256SdioReadBackplane32(Device*,UINT32,UINT32* value){*value=1;return STATUS_SUCCESS;}
static NTSTATUS Ap6256SdioReadF0(Device*,UINT32,UCHAR* value){*value=15;return STATUS_SUCCESS;}
static NTSTATUS Ap6256SdioWriteF0(Device*,UINT32,UCHAR value){assert(value==9);mark("mask-card-irq");return STATUS_SUCCESS;}
static void Ap6256DatapathStop(Device* c){c->DatapathRunning=false;mark("stop-datapath");}
static void Ap6256HostCipherStoreStopAll(decltype(Device::HostCipherStore)* s){s->Configured=false;keys=false;mark("retire-keys");}
static void Ap6256PnoResultsDestroy(Device*){mark("destroy-pno");}
static void Ap6256BcdcCleanup(Device*){mark("cleanup-bcdc");}
static NTSTATUS Ap6256SdBusDisableFunction(Device*,UINT32 f){mark(f==2?"disable-f2":"disable-f1");return STATUS_SUCCESS;}
static NTSTATUS Ap6256ChipSetPassive(Device*){mark("halt-arm");return STATUS_SUCCESS;}
static NTSTATUS Ap6256SdioDisableBackplaneClock(Device*){mark("clock-off");return STATUS_SUCCESS;}
static void setup(Device& c){c={};c.FirmwareState=Ap6256FwRunning;c.DatapathRunning=c.FirmwareLinkUp=true;c.Sdio.BusInterface=&c;c.Sdio.ClockOn=true;static Core core={0x1000};c.Chip.SdiodCore=c.Chip.ArmCore=&core;ops.clear();irql=0;command_status=sleep_status=STATUS_SUCCESS;keys=radio_enabled=admission=true;native_recovery=false;grace=0;}
static int pos(const char* s){auto i=std::find(ops.begin(),ops.end(),s);return i==ops.end()?-1:(int)(i-ops.begin());}
'''
MAIN = r'''
int main(int argc,char** argv){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);Device c={};
    const std::string mode=argc>1?argv[1]:"current";
    if(mode=="qualification-negative"){
        setup(c);native_recovery=true;c.FirmwareHostCipherPatchVerified=true;c.NativeDeparturePending=true;c.FirmwareLinkUp=false;
        Ap6256TearDownChip(&c,FALSE);
        assert(pos("native-unqualified-recovery")>=0&&pos("native-security-cleanup")==-1);
        puts("EXPECTED-REGRESSION: frozen historical clears qualification before pending native departure recovery");return 17;
    }
    setup(c);Ap6256WifiSetRadioState(&c,FALSE);
    if(mode=="radio-negative") {assert(pos("departure")==-1 && pos("set-radio")>=0);puts("EXPECTED-REGRESSION: radio disabled without departure");return 17;}
    if(mode=="current") {assert(pos("departure")>=0 && pos("departure")<pos("grace") && pos("grace")<pos("set-radio") && pos("set-radio")<pos("down"));assert(grace==1);}
    setup(c);Ap6256TearDownChip(&c,FALSE);
    if(mode=="teardown-negative"){assert(pos("departure")==-1 && pos("down")>=0);puts("EXPECTED-REGRESSION: chip stopped without departure");return 17;}
    if(mode=="current") {
        assert(pos("stop-workers")<pos("departure") && pos("departure")<pos("grace") && pos("grace")<pos("down"));
        assert(pos("down")<pos("mask-irq") && pos("mask-irq")<pos("stop-datapath") && pos("stop-datapath")<pos("retire-keys"));
        assert(pos("retire-keys")<pos("disable-f2") && pos("disable-f2")<pos("halt-arm") && pos("halt-arm")<pos("clock-off"));
        assert(!admission && !keys && !radio_enabled && !c.PowerThread && c.FirmwareState==Ap6256FwNotLoaded && grace==1);
        ops.clear();Ap6256TearDownChip(&c,FALSE);assert(pos("departure")==-1);
    }
    setup(c);Ap6256NdisShutdownEx(&c,NdisShutdownPowerOff);
    if(mode=="shutdown-negative"){assert(ops.empty());puts("EXPECTED-REGRESSION: normal shutdown callback did nothing");return 17;}
    if(mode!="current")return 0;
    assert(pos("departure")>=0 && pos("grace")<pos("down") && !c.DatapathRunning);
    for(unsigned level: {0u,2u,15u}) {
        setup(c);irql=level;Ap6256NdisShutdownEx((void*)1,NdisShutdownBugCheck);assert(ops.empty());
        if(level){Ap6256NdisShutdownEx((void*)1,NdisShutdownPowerOff);assert(ops.empty());}
    }
    setup(c);Ap6256NdisShutdownEx(nullptr,NdisShutdownPowerOff);assert(ops.empty());
    for(int state=0;state<9;++state){
        setup(c);
        if(state==0)c.FirmwareState=Ap6256FwNotLoaded;
        if(state==1)c.DatapathRunning=false;
        if(state==2)c.Sdio.BusInterface=nullptr;
        if(state==3)c.Sdio.Sleeping=true;
        if(state==4)c.FirmwareHalted=1;
        if(state==5)c.HostCipherStore.Configured=true;
        if(state==6)c.Fips=true;
        if(state==7)c.FirmwareLinkUp=false;
        if(state==8)irql=2;
        (void)Ap6256WifiLeaveForPowerDown(&c);assert(ops.empty() && !grace);
    }
    setup(c);command_status=STATUS_UNSUCCESSFUL;assert(Ap6256WifiLeaveForPowerDown(&c)==command_status);assert(pos("departure")>=0 && !grace && keys && radio_enabled);
    setup(c);c.FirmwareLinkUp=false;c.NativeDeparturePending=true;assert(Ap6256WifiLeaveForPowerDown(&c)==0);assert(pos("departure")==-1 && grace==1 && !c.NativeDeparturePending && !c.NativeKeyLock);
    setup(c);command_status=STATUS_UNSUCCESSFUL;Ap6256WifiSetRadioState(&c,FALSE);assert(pos("down")>=0 && !grace);
    setup(c);Ap6256WifiSetRadioState(&c,TRUE);assert(pos("departure")==-1 && pos("wifi-up")>=0 && !grace);
    setup(c);c.Sdio.Sleeping=true;Ap6256TearDownChip(&c,TRUE);assert(pos("wake")<pos("resume-datapath") && pos("resume-datapath")<pos("departure") && grace==1);
    setup(c);c.Sdio.Sleeping=true;sleep_status=STATUS_UNSUCCESSFUL;Ap6256TearDownChip(&c,TRUE);assert(pos("departure")==-1 && !grace);
    for(bool host: {false,true}){setup(c);c.HostCipherStore.Configured=host;c.Fips=!host;Ap6256TearDownChip(&c,FALSE);assert(pos("departure")==-1 && !grace);}
    setup(c);native_recovery=true;c.FirmwareHostCipherPatchVerified=true;c.NativeDeparturePending=true;c.FirmwareLinkUp=false;
    Ap6256TearDownChip(&c,FALSE);
    assert(pos("native-qualified-recovery")>=0&&pos("native-qualified-recovery")<pos("native-security-cleanup")&&pos("native-security-cleanup")<pos("down"));
    assert(!c.FirmwareHostCipherPatchVerified&&!c.NativeDeparturePending&&pos("native-unqualified-recovery")==-1&&!grace);
    puts("PASS: native departure before radio/key removal, 500 ms grace, shutdown IRQL guards, wake/failure/idle/raw-owner gates and idempotent teardown");
}
'''

def fixture(old=None):
    definitions = [('src/common/wifi_ops.c', 'Ap6256WifiRadioUpDown'), ('src/common/wifi_ops.c', 'Ap6256WifiLeaveForPowerDown'), ('src/common/wifi_ops.c', 'Ap6256WifiSetRadioState'), ('src/common/device.c', 'Ap6256TearDownChip'), ('src/wdi/ndis_miniport.c', 'Ap6256NdisShutdownEx')]
    hardware = _functions(((old or AP) / 'src/wdi/netadapter.c').read_text(encoding='utf-8-sig'))['Ap6256NetHardwareStop']
    hook = '(VOID)Ap6256WifiLeaveForPowerDown(Ctx)' if 'Ap6256WifiLeaveForPowerDown(Ctx)' in hardware else '(void)0'
    if not old:
        for frontend in ('wdi', 'wificx'):
            body = _functions((AP / 'src' / frontend / 'netadapter.c').read_text(encoding='utf-8-sig'))['Ap6256NetHardwareStop']
            assert body.index('CommandWorkItem);') < body.index('Ap6256WifiLeaveForPowerDown(Ctx)') < body.index('Ap6256StationAuthStop(wifi)')
            assert body.index('Ap6256WifiLeaveForPowerDown(Ctx)') < body.index('Ap6256IndicateDisassociation(')
    result = PRE.replace('HARDWARE_STOP_HOOK', hook)
    for (path, name) in definitions:
        source = (old or AP) / path
        functions = _functions(source.read_text(encoding='utf-8-sig'))
        if name not in functions:
            assert old and name == 'Ap6256WifiLeaveForPowerDown'
            functions = _functions((AP / path).read_text(encoding='utf-8-sig'))
        function = functions[name]
        function = re.sub('(?m)^_Use_decl_annotations_\\s*', '', function)
        result += function + '\n'
    return result + MAIN

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for (label, root) in [('current', None)]:
        folder = args.output_dir / label
        folder.mkdir(exist_ok=True)
        cpp = folder / 'test.cpp'
        write_text(cpp, fixture(root), encoding='utf-8')
        exe = folder / 'test.exe'
        command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/wd4310', '/Od', '/MT', '/I' + str(VC / 'include')]
        command += ['/I' + str(INC / f) for f in ('ucrt', 'shared', 'um')]
        command += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(folder / 'test.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
        result = subprocess.run(command, capture_output=True)
        write_bytes(folder / 'compile.log', result.stdout + result.stderr)
        if result.returncode:
            print((result.stdout + result.stderr).decode(errors='replace'))
            result.check_returncode()
        cases = ['current'] if root is None else ['qualification-negative'] if label == 'historical-qualification-negative' else ['radio-negative', 'teardown-negative', 'shutdown-negative']
        for case in cases:
            result = subprocess.run([str(exe), case], capture_output=True)
            output = result.stdout + result.stderr
            write_bytes(folder / (case + '.log'), output)
            print(output.decode(errors='replace'), end='')
            assert result.returncode == (0 if root is None else 17)
            if root:
                assert b'EXPECTED-REGRESSION:' in output
            records.append(dict(name=label, case=case, exit_code=result.returncode))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    paths = ['src/common/wifi_ops.c', 'src/common/device.c', 'src/wdi/ndis_miniport.c', 'src/wdi/netadapter.c', 'src/wificx/netadapter.c']
    report = dict(passed=True, board_verified=False, records=records, source_sha256={p: sha(AP / p) for p in paths}, limits='Departure, radio state, teardown and shutdown ordering.')
    write_text(args.output_dir / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
