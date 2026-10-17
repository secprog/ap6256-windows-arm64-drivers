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
#include <stdarg.h>
#include <vector>
#include <string>
typedef LONG NTSTATUS;typedef NTSTATUS* PNTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TRACE_NETADAPTER 0
#define MAXULONG 0xffffffffUL
static std::vector<std::string> warnings;
static void warning(const char* f,...) {char b[512];va_list a;va_start(a,f);vsnprintf(b,sizeof(b),f,a);va_end(a);warnings.emplace_back(b);}
#define TraceWarn(t,...) warning(__VA_ARGS__)
#define TraceInfo(...) ((void)0)
#define TraceVerbose(...) ((void)0)
struct Device {
    struct {UINT32 ChipId=0x4345,ChipRev=9;} Chip;
    BOOLEAN FirmwareNativeManagement=TRUE,FirmwareLinkUp=FALSE;
    UINT8 D11IoType=2;INT32 RoamRssiTriggerDbm=0;
    volatile LONG BeaconLossTimeoutSeconds=0;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static UINT32 testChanspec,beaconTimeout;
static INT32 testRssi;
static ULONG roamQueries,indications;
static UINT32 lastBand;
static std::string failGet,failSet;
static bool shortReply,absentReply,wrongReadback;
static std::vector<UINT32> dcmds;
static std::vector<std::string> testIovars;
static std::vector<UCHAR> rssiRequest;
static NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 c,PVOID p,ULONG n) {
    dcmds.push_back(c);assert(c!=BRCMF_C_GET_KEY_PRIMARY);
    memset(p,0,n);return 0;
}
static NTSTATUS Ap6256BcdcSetDcmd(Device*,UINT32 c,PVOID,ULONG n) {
    assert(n==4 && c!=BRCMF_C_SET_SCB_TIMEOUT);dcmds.push_back(c);return 0;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 i,PCSTR name,PVOID p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(!i && n==4);testIovars.emplace_back(std::string("G ")+name);
    *r={(BOOLEAN)!absentReply,FALSE,0,shortReply?0u:4u};
    if(failGet==name)return STATUS_IO_TIMEOUT;
    UINT32 v=(!strcmp(name,"chanspec"))?testChanspec:beaconTimeout;
    if(wrongReadback && !strcmp(name,"bcn_timeout"))++v;
    memcpy(p,&v,4);return 0;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n) {
    testIovars.emplace_back(std::string("S ")+name);
    assert(strcmp(name,"scan_unassoc_time_default") && strcmp(name,"bcn_thresh"));
    if(failSet==name)return STATUS_UNSUCCESSFUL;
    if(!strcmp(name,"bcn_timeout")){assert(n==4);memcpy(&beaconTimeout,p,4);}
    if(!strcmp(name,"rssi_event"))rssiRequest.assign((const UCHAR*)p,(const UCHAR*)p+n);
    return 0;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device*,UINT32 i,UINT32 c,PVOID p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(!i && c==BRCMF_C_GET_ROAM_TRIGGER && n==8);++roamQueries;
    INT32* words=(INT32*)p;lastBand=words[1];assert(lastBand==1 || lastBand==2);
    *r={(BOOLEAN)!absentReply,FALSE,0,shortReply?0u:4u};
    if(failGet=="trigger")return STATUS_IO_TIMEOUT;
    words[0]=testRssi;return 0;
}
static void Ap6256NetActionFrameReceived(Device*,UCHAR,UCHAR,const UCHAR*,UINT16 c,const UCHAR* p,ULONG n) {
    assert(c==0x1006 && n==137 && p[0]==4 && p[1]==9);++indications;
}
'''
TEST = r'''
static void reset() {
    warnings.clear();dcmds.clear();testIovars.clear();rssiRequest.clear();
    testChanspec=0x1006;testRssi=-67;beaconTimeout=0;roamQueries=0;lastBand=0;
    failGet.clear();failSet.clear();shortReply=absentReply=wrongReadback=false;
}
int main() {
    Device d;reset();Ap6256WifiAssertStationRole(&d);Ap6256WifiConfigureScanTimes(&d);
    assert(!dcmds.empty());Ap6256WifiInventory(&d);
    for(UINT32 c:dcmds)assert(c!=BRCMF_C_GET_BSSID && c!=BRCMF_C_GET_KEY_PRIMARY && c!=BRCMF_C_SET_SCB_TIMEOUT);
    d.FirmwareLinkUp=TRUE;dcmds.clear();Ap6256WifiInventory(&d);
    bool queried=false;for(UINT32 c:dcmds)if(c==BRCMF_C_GET_BSSID)queried=true;
    assert(queried);puts("PASS: startup skips AP-only timeout, primary-key predicate and unassociated BSSID; preserves associated inventory and numbered scan dwell");
    for(UINT8 io:std::initializer_list<UINT8>{1,2})for(bool five:{false,true}) {
        reset();d.D11IoType=io;testChanspec=io==1?(five?0x1b24u:0x2b06u):(five?0xd024u:0x1006u);
        INT32 rssi=0;assert(Ap6256WifiGetRoamTrigger(&d,&rssi)==0 && rssi==-67 && lastBand==(five?1u:2u));
    }
    d.D11IoType=2;
    for(UINT32 ch:{0u,0x1000u,0x5006u,0x9006u,0x11006u}) {
        reset();testChanspec=ch;INT32 rssi=123;
        assert(!NT_SUCCESS(Ap6256WifiGetRoamTrigger(&d,&rssi)) && rssi==-80 && !roamQueries);
    }
    for(INT32 bad:{-129,-128,0,1,INT32(0x7fffffff)}) {
        reset();testRssi=bad;INT32 rssi=123;
        assert(Ap6256WifiGetRoamTrigger(&d,&rssi)==STATUS_DEVICE_PROTOCOL_ERROR && rssi==-80);
    }
    for(const std::string name:{"chanspec","trigger"}) {
        reset();failGet=name;INT32 rssi=123;
        assert(Ap6256WifiGetRoamTrigger(&d,&rssi)==STATUS_IO_TIMEOUT && rssi==-80);
    }
    for(bool absent:{false,true}) {
        reset();shortReply=!absent;absentReply=absent;INT32 rssi=123;
        assert(Ap6256WifiGetRoamTrigger(&d,&rssi)==STATUS_DEVICE_PROTOCOL_ERROR && rssi==-80);
    }
    puts("PASS: both D11 band formats, explicit per-band query, invalid/truncated replies and RSSI fallback");
    reset();Ap6256WifiArmRoamTriggers(&d);
    assert(beaconTimeout==4 && warnings.empty() && d.RoamRssiTriggerDbm==-67);
    assert(rssiRequest.size()==16 && rssiRequest[4]==2 && (CHAR)rssiRequest[5]==-128 && (CHAR)rssiRequest[6]==-67);
    for(int failure=0;failure<4;failure++) {
        reset();if(failure==0)failSet="bcn_timeout";
        if(failure==1)failGet="bcn_timeout";
        if(failure==2)wrongReadback=true;
        if(failure==3)shortReply=true;
        Ap6256WifiArmRoamTriggers(&d);assert(!warnings.empty() && rssiRequest.size()==16);
    }
    puts("PASS: native four-second beacon timeout is written and read back; RSSI arming survives advisory failures");
    d.BeaconLossTimeoutSeconds=3;reset();Ap6256WifiArmRoamTriggers(&d);
    assert(beaconTimeout==3 && warnings.empty() && d.BeaconLossTimeoutSeconds==3);
    reset();beaconTimeout=10;assert(Ap6256WifiRestoreUnreachableThreshold(&d)==0);
    assert(beaconTimeout==3 && d.BeaconLossTimeoutSeconds==3);
    reset();failGet="bcn_timeout";assert(Ap6256WifiRestoreUnreachableThreshold(&d)==STATUS_IO_TIMEOUT);
    assert(d.BeaconLossTimeoutSeconds==3);
    d.BeaconLossTimeoutSeconds=0;
    reset();assert(Ap6256WifiRestoreUnreachableThreshold(&d)==0 && testIovars.empty());
    for(UINT32 value:{0u,1u,999u,1001u,2999u,3001u,0xffffffffu}) {
        reset();assert(Ap6256WifiApplyUnreachableThreshold(&d,value)==STATUS_NOT_SUPPORTED);
        assert(testIovars.empty());
    }
    for(UINT32 value:{1000u,3000u,4000u,65535000u,4294967000u}) {
        reset();assert(Ap6256WifiApplyUnreachableThreshold(&d,value)==0);
        assert(beaconTimeout==value/1000u && warnings.empty());
    }
    puts("PASS: configured three-second timeout survives association arming; whole-second limits reject before I/O");
    std::vector<UCHAR> raw(137,0);UCHAR head[]={4,9,0x50,0x6f,0x9a,9,8,1};memcpy(raw.data(),head,8);
    UCHAR source[6]={2,3,4,5,6,7};
    reset();Dispatch(&d,59,raw.data(),(ULONG)raw.size(),source);
    assert(warnings.empty() && !indications);
    std::vector<UCHAR> full(16+raw.size(),0);full[2]=0x10;full[3]=6;memcpy(full.data()+16,raw.data(),raw.size());
    Dispatch(&d,75,full.data(),(ULONG)full.size(),source);
    assert(indications==1 && warnings.empty());
    for(ULONG n=0;n<8;n++)assert(!Ap6256ActionFrameIsP2pMirror(&d,raw.data(),n));
    for(int field=0;field<7;field++) {
        auto bad=raw;bad[field]^=0x80;assert(!Ap6256ActionFrameIsP2pMirror(&d,bad.data(),(ULONG)bad.size()));
        Dispatch(&d,59,bad.data(),(ULONG)bad.size(),source);
    }
    for(UCHAR a:std::initializer_list<UCHAR>{32,33}) {auto other=raw;other[1]=a;assert(!Ap6256ActionFrameIsP2pMirror(&d,other.data(),(ULONG)other.size()));}
    d.Chip.ChipRev=6;assert(!Ap6256ActionFrameIsP2pMirror(&d,raw.data(),137));d.Chip.ChipRev=9;
    d.FirmwareNativeManagement=FALSE;assert(!Ap6256ActionFrameIsP2pMirror(&d,raw.data(),137));d.FirmwareNativeManagement=TRUE;
    Dispatch(&d,90,raw.data(),137,source);assert(indications==1 && warnings.size()==8);
    Dispatch(&d,75,full.data(),17,source);assert(indications==1 && warnings.size()==9);
    assert(!Ap6256ActionFrameIsP2pMirror(&d,nullptr,137));
    puts("PASS: recognized 137-byte mirror plus 153-byte metadata RX indicate exactly once; malformed/unknown/GAS/other-image variants retain warning");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    files = [ROOT / 'src/common' / n for n in ('wifi_ops.c', 'datapath.c', 'bcdc.h', 'sdpcm.h')]
    (wifi, data, bcdc, sdpcm) = [p.read_text(encoding='utf-8-sig') for p in files]
    constants = '\n'.join(re.findall('^#define (?:BRCMF_[CE]_\\w+|BRCMU_(?:CHSPEC_\\w+|D11\\w+_IOTYPE)|AP6256_(?:SCAN_\\w+|SHORT_RETRY_LIMIT|LONG_RETRY_LIMIT|ASSOCLIST_MAX|ROAM_RSSI_DEFAULT_DBM|RSSI_EVENT_\\w+|BEACON_LOSS_TIMEOUT_SECONDS))\\s+[^\\n]+', wifi + '\n' + sdpcm, re.M))
    (prefix, mocks) = PRE.split('struct Device', 1)
    code = constants + '\n' + prefix + CONTROL['declaration'](bcdc, 'AP6256_BCDC_QUERY_RESULT') + 'struct Device' + mocks
    for name in ('WLC_SSID', 'BRCMF_RATESET', 'BRCMF_ASSOCLIST', 'BRCMF_RSSI_EVENT'):
        code += CONTROL['declaration'](wifi, name) + '\n'
    f = _functions(wifi)
    for name in ('Ap6256WifiSetU32', 'Ap6256WifiQueryU32', 'Ap6256WifiAssertStationRole', 'Ap6256WifiInventory', 'Ap6256WifiConfigureScanTimes', 'Ap6256WifiGetRoamTrigger', 'Ap6256WifiArmRssiEvent', 'Ap6256WifiValidateUnreachableThreshold', 'Ap6256WifiReadBeaconTimeout', 'Ap6256WifiApplyUnreachableThreshold', 'Ap6256WifiRestoreUnreachableThreshold', 'Ap6256WifiArmRoamTriggers'):
        code += f[name] + '\n'
    f = _functions(data)
    for name in ('Ap6256ParseActionRx', 'Ap6256EventName', 'Ap6256ActionFrameIsP2pMirror'):
        code += f[name] + '\n'
    start = data.index('    case BRCMF_E_ACTION_FRAME_RX: {')
    end = data.index('    case BRCMF_E_ACTION_FRAME_COMPLETE:', start)
    branch = data[start:end]
    code += r'''static void Dispatch(Device* Ctx,UINT32 eventType,PUCHAR eventBody,ULONG eventBodyLen,const UCHAR* source) {struct {UCHAR IfIdx=1,BssCfgIdx=1,Address[6];} e;memcpy(e.Address,source,6);auto evt=&e;switch(eventType) {
''' + branch + '\ndefault:assert(false);}}\n' + TEST
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    (vc, inc, lib) = [CONTROL[k] for k in ('VC', 'INC', 'LIB')]
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / n) for n in ('ucrt', 'shared', 'um')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    built = subprocess.run(cmd, capture_output=True)
    write_bytes(out / 'compile.log', built.stdout + built.stderr)
    if built.returncode:
        print((built.stdout + built.stderr).decode(errors='replace'))
        built.check_returncode()
    ran = subprocess.run([str(out / 'tests.exe')], capture_output=True, timeout=30)
    write_bytes(out / 'runtime.log', ran.stdout + ran.stderr)
    print((ran.stdout + ran.stderr).decode(errors='replace'))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    write_text(out / 'receipt.json', json.dumps(dict(passed=ran.returncode == 0, board_verified=False, source_sha256={str(p.relative_to(ROOT)): sha(p) for p in files}, test_sha256=sha(Path(__file__)), cpp_sha256=sha(cpp), exe_sha256=sha(out / 'tests.exe')), indent=2) + '\n', encoding='utf-8')
    ran.check_returncode()
if __name__ == '__main__':
    main()
