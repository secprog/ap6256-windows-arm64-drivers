# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
CONTROL = runpy.run_path(str(ROOT / 'tests/test-control-retry.py'))
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <vector>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TRACE_NETADAPTER 0
#define TraceInfo(...) ((void)0)
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceWarn(...) ((void)0)
#define Executive 0
#define KernelMode 0
struct KMUTEX {std::mutex* mutex;};
static thread_local bool held=false;
static void KeInitializeMutex(KMUTEX* m,int) {m->mutex=new std::mutex;}
static NTSTATUS KeWaitForSingleObject(KMUTEX* m,int,int,BOOLEAN,void*) {m->mutex->lock();assert(!held);held=true;return 0;}
static LONG KeReleaseMutex(KMUTEX* m,BOOLEAN) {assert(held);held=false;m->mutex->unlock();return 0;}
static PVOID KeGetCurrentThread() {return (PVOID)(ULONG_PTR)GetCurrentThreadId();}
enum {Ap6256FwRunning=1};
'''
MOCK = r'''
struct Device {
    PVOID Pdo=nullptr;
    AP6256_CONNECTION_QUALITY ConnectionQuality{};
    struct {UINT32 ChipId=0x4345,ChipRev=9;} Chip;
    struct {BOOLEAN Started=FALSE,ClientConnected=FALSE,FirmwareReady=FALSE;UINT32 Channel=6,IfIndex=3,Mode=0,BssIndex=3;BOOLEAN NativeStateUncertain=FALSE;UCHAR Address[6]={2,3,4,5,6,7};struct {int dummy;} P2p;} Go;
    LONG FirmwareIfMap[16]={};int PowerSaveDx[2]={};BOOLEAN FirmwareP2pSupported=TRUE;
    BOOLEAN FirmwareNativeManagement=TRUE,FirmwareLinkUp=FALSE,DatapathRunning=TRUE;
    LONG FirmwareIoQuiesced=0,FirmwareHalted=0;
    PVOID PowerThread=nullptr;
    int FirmwareState=Ap6256FwRunning;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static UINT32 fwAlgorithm,fwBandwidth,wirePm,groupPm,fwChannel=6;
static bool unavailable,disabled,shortReply,mismatch,noReply;
static std::string failName,nextFailName;static bool failSet,nextFailSet;
static unsigned writes,pmWrites,deleteDelays;static bool deleteLost;
static std::vector<std::string> commands;
static NTSTATUS fault(PCSTR name,bool set,AP6256_BCDC_QUERY_RESULT* r) {
    if(r)*r={TRUE,FALSE,0,shortReply?0u:4u};
    if(failName==name && set==failSet) {
        failName=nextFailName;failSet=nextFailSet;nextFailName.clear();if(r)*r={(BOOLEAN)(noReply?FALSE:TRUE),(BOOLEAN)(noReply?FALSE:TRUE),-16,0};
        return noReply?STATUS_IO_TIMEOUT:STATUS_UNSUCCESSFUL;
    }
    return 0;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 iface,PCSTR name,PVOID out,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(held && !iface && n==4);commands.emplace_back(std::string("G ")+name);
    NTSTATUS s=fault(name,false,r);if(!NT_SUCCESS(s))return s;
    UINT32 v;
    if(!strcmp(name,"mchan")) {
        if(unavailable){*r={TRUE,TRUE,-23,0};return STATUS_UNSUCCESSFUL;}
        v=disabled?0u:1u;
    } else if(!strcmp(name,"mchan_algo"))v=fwAlgorithm;
    else {assert(!strcmp(name,"mchan_bw"));v=fwBandwidth;}
    memcpy(out,&v,4);return 0;
}
static NTSTATUS Ap6256BcdcProbeIovar(Device* d,PCSTR name,PVOID p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    return Ap6256BcdcGetIovarResultIf(d,0,name,p,n,r);
}
static Device* lastDevice;
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n) {
    if(!strcmp(name,"p2p_ifdel")){assert(!held && n==6);if(!deleteLost)ZeroMemory((void*)lastDevice->FirmwareIfMap,sizeof(lastDevice->FirmwareIfMap));return fault("native_delete",true,nullptr);}
    if(!strcmp(name,"p2p_ifadd")){assert(!held && n==10);return fault("native_add",true,nullptr);}
    assert(held && n==4);++writes;commands.emplace_back(std::string("S ")+name);
    NTSTATUS s=fault(name,true,nullptr);if(!NT_SUCCESS(s))return s;
    UINT32 v;memcpy(&v,p,4);
    if(mismatch) {mismatch=false;return 0;}
    if(!strcmp(name,"mchan_algo")){assert(v<=3);fwAlgorithm=v;}
    else {assert(!strcmp(name,"mchan_bw") && v<=100);if(fwAlgorithm!=3)fwBandwidth=v;}
    return 0;
}
static NTSTATUS Ap6256RegQueryValue(PVOID,PCWSTR,ULONG n,PVOID p,PULONG length,PULONG type) {
    assert(n>=4);UINT32 v=2;memcpy(p,&v,4);*length=4;*type=REG_DWORD;return 0;
}
static NTSTATUS Ap6256BcdcSetDcmd(Device*,UINT32 c,PVOID p,ULONG n) {
    assert(held && c==BRCMF_C_SET_PM && n==4);++pmWrites;
    NTSTATUS s=fault("pm",true,nullptr);if(NT_SUCCESS(s))memcpy(&wirePm,p,4);return s;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device*,UINT32 i,UINT32 c,PVOID p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(held && c==BRCMF_C_GET_PM && n==4 && i<=3);
    NTSTATUS s=fault(i ? "group_pm" : "pm",false,r);if(NT_SUCCESS(s))memcpy(p,i ? &groupPm : &wirePm,4);return s;
}
static NTSTATUS Ap6256BcdcSetDcmdIf(Device*,UINT32 i,UINT32 c,PVOID p,ULONG n) {
    assert(held && i==3 && c==BRCMF_C_SET_PM && n==4);
    NTSTATUS s=fault("group_pm",true,nullptr);if(NT_SUCCESS(s))memcpy(&groupPm,p,4);return s;
}
static NTSTATUS Ap6256BcdcGetIovar(Device*,PCSTR name,PVOID p,ULONG n) {assert(!strcmp(name,"p2p_if") && n==20);UINT32 v=3;memcpy(p,&v,4);return 0;}
static NTSTATUS Ap6256BcdcSetIovarResultIf(Device* d,UINT32 i,PCSTR name,const VOID* p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(!i);*r={TRUE,FALSE,0,0};return Ap6256BcdcSetIovar(d,name,p,n);
}
static NTSTATUS Ap6256TdlsSetBlocked(Device*,BOOLEAN){return 0;}
static NTSTATUS Ap6256WifiGetChanspec(Device*,PUINT32 c){*c=0x1006;return 0;}
static void Ap6256P2pTraceMemory(Device*,PCSTR){}
static NTSTATUS Ap6256WaitFirmwareInterface(Device*,UINT32 b,PUINT32 i){assert(b==3);*i=3;return 0;}
static NTSTATUS Ap6256GoSetBsscfg(Device*,PCSTR,const VOID*,ULONG){return 0;}
static NTSTATUS Ap6256FipsRetire(Device*,UINT32){return 0;}
static NTSTATUS Ap6256GoStop(Device* d){d->Go.Started=FALSE;return 0;}
static void Ap6256P2pForgetIesFor(PVOID){}
static NTSTATUS KeDelayExecutionThread(int,BOOLEAN,LARGE_INTEGER*){++deleteDelays;return 0;}
'''
TEST = r'''
static void fresh(Device& d,UINT32 algo=0,UINT32 bw=50) {
    delete d.ConnectionQuality.Lock.mutex;d.ConnectionQuality={};
    Ap6256QualityInitialize(&d);d.ConnectionQuality.PowerSaveRequested=TRUE;fwAlgorithm=algo;fwBandwidth=bw;wirePm=groupPm=2;
    unavailable=disabled=shortReply=mismatch=noReply=false;failName.clear();nextFailName.clear();nextFailSet=false;writes=pmWrites=0;commands.clear();
    d.FirmwareIoQuiesced=d.FirmwareHalted=0;d.PowerThread=nullptr;d.FirmwareState=Ap6256FwRunning;
    d.DatapathRunning=TRUE;d.FirmwareNativeManagement=TRUE;d.Chip.ChipId=0x4345;d.Chip.ChipRev=9;
    d.FirmwareLinkUp=d.Go.Started=d.Go.ClientConnected=d.Go.FirmwareReady=FALSE;d.Go.Mode=0;d.Go.IfIndex=d.Go.BssIndex=3;d.Go.NativeStateUncertain=FALSE;fwChannel=6;lastDevice=&d;deleteDelays=0;deleteLost=false;ZeroMemory((void*)d.FirmwareIfMap,sizeof(d.FirmwareIfMap));
}
int main() {
    Device d;fresh(d);
    assert(Ap6256QualitySetPort(&d,2,3)==0 && fwAlgorithm==1 && fwBandwidth==25 && wirePm==0);
    assert(d.ConnectionQuality.MchanSaved && d.ConnectionQuality.SavedMchanAlgorithm==0);
    assert(Ap6256QualitySetPort(&d,0,1)==0 && wirePm==0 && fwBandwidth==25);
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==0);
    UINT32 before=writes;
    assert(Ap6256QualitySetPort(&d,0,3)==STATUS_DEVICE_BUSY && writes==before && d.ConnectionQuality.Hints[0]==1);
    assert(Ap6256QualitySetPort(&d,2,1)==0 && fwAlgorithm==0 && fwBandwidth==50 && wirePm==2 && !d.ConnectionQuality.MchanSaved);
    puts("PASS: group priority, cross-port AUTO and key power requests, one HIGH limit and exact restore");
    fresh(d,3,63);
    assert(Ap6256QualitySetPort(&d,0,3)==0 && fwBandwidth==75 && fwAlgorithm==1);
    assert(Ap6256QualitySetPort(&d,0,1)==0 && fwBandwidth==63 && fwAlgorithm==3 && wirePm==2);
    for(UINT32 hint:{2u,4u}) {
        fresh(d);assert(Ap6256QualitySetPort(&d,2,hint)==0 && wirePm==0 && !writes);
        assert(Ap6256QualitySetPort(&d,0,1)==0 && wirePm==0);
        assert(Ap6256QualityForgetPort(&d,2)==0 && wirePm==2);
    }
    for(const std::string name:{"mchan","mchan_algo","mchan_bw","pm"}) {
        for(bool set:{false,true}) {
            if(name=="mchan" && set)continue;
            fresh(d);failName=name;failSet=set;
            assert(!NT_SUCCESS(Ap6256QualitySetPort(&d,2,3)));
            assert(!d.ConnectionQuality.Hints[2] && !d.ConnectionQuality.MchanSaved);
            assert(fwAlgorithm==0 && fwBandwidth==50 && wirePm==2);
        }
    }
    fresh(d);failName="pm";failSet=false;nextFailName="mchan_bw";nextFailSet=true;
    assert(!NT_SUCCESS(Ap6256QualitySetPort(&d,2,3)) && !d.ConnectionQuality.Hints[2]);
    assert(d.ConnectionQuality.MchanSaved && fwBandwidth==25 && fwAlgorithm==1);
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && fwBandwidth==50 && !d.ConnectionQuality.MchanSaved);
    fresh(d);mismatch=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_DEVICE_PROTOCOL_ERROR && !d.ConnectionQuality.Hints[2]);
    assert(fwAlgorithm==0 && fwBandwidth==50);
    fresh(d);shortReply=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_DEVICE_PROTOCOL_ERROR && !writes);
    fresh(d);failName="mchan";failSet=false;noReply=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_IO_TIMEOUT && !writes);
    fresh(d);fwAlgorithm=4;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_DEVICE_PROTOCOL_ERROR && !writes);
    fresh(d);fwBandwidth=101;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_DEVICE_PROTOCOL_ERROR && !writes);
    puts("PASS: transport and firmware failures, short payloads, out-of-range state and write/readback mismatch roll back");
    fresh(d);d.Chip.ChipRev=6;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_NOT_SUPPORTED && !writes);
    fresh(d);unavailable=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_NOT_SUPPORTED && !d.ConnectionQuality.Hints[2]);
    fresh(d);disabled=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_NOT_SUPPORTED && !d.ConnectionQuality.Hints[2]);
    fresh(d);d.FirmwareLinkUp=d.Go.Started=TRUE;fwChannel=36;unavailable=true;
    assert(Ap6256QualitySetPort(&d,2,3)==STATUS_NOT_SUPPORTED && !d.ConnectionQuality.Hints[2]);
    fresh(d);assert(Ap6256QualitySetPort(&d,0,1)==0);assert(Ap6256QualitySetPort(&d,2,3)==0);
    d.FirmwareIoQuiesced=1;d.PowerThread=KeGetCurrentThread();
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==2 && d.ConnectionQuality.Hints[2]==3);
    d.PowerThread=nullptr;d.FirmwareIoQuiesced=0;
    assert(Ap6256QualityReapply(&d)==0 && wirePm==0 && fwBandwidth==25);
    d.FirmwareIoQuiesced=1;before=writes;
    assert(Ap6256QualityForgetPort(&d,2)==0 && writes==before && d.ConnectionQuality.MchanSaved);
    d.FirmwareIoQuiesced=0;
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && fwAlgorithm==0 && fwBandwidth==50 && wirePm==2);
    assert(!d.ConnectionQuality.MchanSaved);
    fresh(d);assert(Ap6256QualitySetPort(&d,2,3)==0);
    Ap6256QualityResetFirmware(&d);fwAlgorithm=2;fwBandwidth=47;
    assert(d.ConnectionQuality.Hints[2]==3 && !d.ConnectionQuality.MchanSaved);
    assert(Ap6256QualityReapply(&d)==0 && fwBandwidth==25 && wirePm==0);
    assert(Ap6256QualityForgetPort(&d,2)==0 && fwAlgorithm==2 && fwBandwidth==47);
    puts("PASS: chip/image qualification, concurrency rejection, Dx override, deferred delete restore and firmware recovery");
    fresh(d);d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;d.Go.FirmwareReady=d.Go.ClientConnected=TRUE;
    assert(Ap6256QualitySetPort(&d,2,3)==0 && groupPm==0 && d.ConnectionQuality.GroupPmSaved);
    assert(Ap6256QualitySetPort(&d,0,1)==0 && groupPm==0 && wirePm==0);
    assert(Ap6256QualitySetPort(&d,2,1)==0 && groupPm==2 && !d.ConnectionQuality.GroupPmSaved);
    for(bool set:{false,true}) {
        fresh(d);d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;d.Go.FirmwareReady=TRUE;
        failName="group_pm";failSet=set;
        assert(!NT_SUCCESS(Ap6256QualitySetPort(&d,2,3)) && !d.ConnectionQuality.Hints[2]);
        assert(groupPm==2 && fwAlgorithm==0 && fwBandwidth==50 && wirePm==2);
    }
    fresh(d);d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;d.Go.FirmwareReady=TRUE;
    assert(Ap6256QualitySetPort(&d,2,3)==0 && d.ConnectionQuality.GroupPmSaved);
    Ap6256QualityForgetGroupFirmware(&d);d.Go.FirmwareReady=FALSE;
    assert(!d.ConnectionQuality.GroupPmSaved && d.ConnectionQuality.Hints[2]==3);
    assert(Ap6256QualitySetPort(&d,2,1)==0 && fwBandwidth==50);
    puts("PASS: group-client PM uses its firmware interface; saved PM restores, failed writes roll back and deleted firmware state is retired");
    fresh(d);d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;
    assert(Ap6256QualitySetPort(&d,2,3)==0 && !d.ConnectionQuality.GroupPmSaved);
    assert(Ap6256GoCreate(&d)==0 && d.Go.FirmwareReady && groupPm==0 && d.ConnectionQuality.GroupPmSaved);
    failName="native_delete";failSet=true;
    assert(!NT_SUCCESS(Ap6256GoDelete(&d)) && d.ConnectionQuality.GroupPmSaved && d.Go.FirmwareReady);
    assert(Ap6256GoDelete(&d)==0 && !d.ConnectionQuality.GroupPmSaved && !d.Go.FirmwareReady);
    assert(Ap6256GoCreate(&d)==0 && d.ConnectionQuality.GroupPmSaved);
    d.FirmwareIfMap[3]=4;deleteLost=true;
    assert(Ap6256GoDelete(&d)==STATUS_IO_TIMEOUT && deleteDelays==100 && !d.ConnectionQuality.GroupPmSaved);
    assert(Ap6256QualityForgetPort(&d,2)==0 && fwAlgorithm==0 && fwBandwidth==50);
    fresh(d);d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;
    assert(Ap6256QualitySetPort(&d,2,3)==0);
    failName="group_pm";failSet=false;
    assert(!NT_SUCCESS(Ap6256GoCreate(&d)) && !d.Go.FirmwareReady && !d.Go.NativeStateUncertain);
    puts("PASS: production group create reapplies held policy; refused deletion retains PM cache, accepted/lost deletion retires it and failed creation rolls back");
    fresh(d);assert(Ap6256QualitySetPort(&d,2,3)==0);
    std::thread a([&](){for(int i=0;i<100;i++)assert(Ap6256QualitySetPort(&d,0,1)==0);});
    std::thread b([&](){for(int i=0;i<100;i++)assert(Ap6256WifiSetPowerSave(&d,TRUE)==0);});
    a.join();b.join();assert(wirePm==0 && fwBandwidth==25);
    assert(Ap6256QualitySetPort(&d,3,3)==STATUS_INVALID_PARAMETER);
    assert(Ap6256QualitySetPort(&d,2,0)==STATUS_INVALID_PARAMETER);
    assert(Ap6256QualitySetPort(&d,2,5)==STATUS_INVALID_PARAMETER);
    puts("PASS: concurrent property/key requests serialize and preserve the high-throughput power policy");
    delete d.ConnectionQuality.Lock.mutex;
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    paths = [ROOT / 'src/common' / n for n in ('quality.c', 'quality.h', 'ap6256.h', 'wifi_ops.c', 'bcdc.h', 'sdpcm.h')]
    (quality, header, context, wifi, bcdc, sdpcm) = [p.read_text(encoding='utf-8-sig') for p in paths]
    constants = '\n'.join(re.findall('^#define (?:AP6256_(?:QUALITY_\\w+|\\w+_PORT|PM_\\w+)|BRCMF_C_(?:SET|GET)_PM)\\s+[^\\n]+', header + '\n' + context + '\n' + wifi + '\n' + sdpcm, re.M)) + '\n#define AP6256_WDI_OPMODE_P2P_CLIENT 0x10u\n#define AP6256_P2P_IF_GO 1u\n'
    code = PRE + '\n' + constants + '\n' + CONTROL['declaration'](context, 'AP6256_CONNECTION_QUALITY')
    code += CONTROL['declaration'](bcdc, 'AP6256_BCDC_QUERY_RESULT') + MOCK
    f = _functions(wifi)
    code += f['Ap6256WifiConfiguredPowerSave'] + f['Ap6256WifiProgramPowerSave']
    code += re.sub('^#include[^\\n]+\\n', '', quality, flags=re.M)
    group = _functions((ROOT / 'src/common/hotspot.c').read_text(encoding='utf-8'))
    code += group['Ap6256GoCreate'] + group['Ap6256GoDelete'] + TEST
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    (vc, inc, lib) = [CONTROL[n] for n in ('VC', 'INC', 'LIB')]
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / n) for n in ('ucrt', 'shared', 'um')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    compiled = subprocess.run(cmd, capture_output=True)
    write_bytes(out / 'compile.log', compiled.stdout + compiled.stderr)
    if compiled.returncode:
        print((compiled.stdout + compiled.stderr).decode(errors='replace'))
        compiled.check_returncode()
    ran = subprocess.run([str(out / 'tests.exe')], capture_output=True, timeout=30)
    write_bytes(out / 'runtime.log', ran.stdout + ran.stderr)
    print((ran.stdout + ran.stderr).decode(errors='replace'))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    write_text(out / 'receipt.json', json.dumps(dict(passed=ran.returncode == 0, board_verified=False, sources={str(p.relative_to(ROOT)): sha(p) for p in paths + [ROOT / 'src/common/hotspot.c']}, test_sha256=sha(Path(__file__)), cpp_sha256=sha(cpp), exe_sha256=sha(out / 'tests.exe')), indent=2) + '\n', encoding='utf-8')
    ran.check_returncode()
if __name__ == '__main__':
    main()
