# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import hashlib
import json
from pathlib import Path
import runpy
import subprocess
from driver_sources import _functions
from wdi_test_support import contract_preamble
ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(ROOT / 'tests/test-p2p-wdi.py'))
CONTROL = runpy.run_path(str(ROOT / 'tests/test-control-retry.py'))
MOCK = r'''
struct Device {struct {BOOLEAN Created=TRUE;} Go;};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi {Device* Ctx;TLV_CONTEXT TlvContext{};BOOLEAN PortCreated=TRUE,P2pPortCreated=TRUE;
    BOOLEAN RoamLinkQualityThresholdValid=FALSE;UINT32 RoamLinkQualityThreshold=0;};
typedef Wifi* PAP6256_WIFI;typedef void* AP6256_REQUEST;
static NTSTATUS result,backendStatus;
static UINT32 capturedPort,capturedHint,backendCalls;
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s){return (NTSTATUS)s;}
static void Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s){result=s;}
static NTSTATUS Ap6256QualitySetPort(Device*,UINT32 p,UINT32 h) {
    ++backendCalls;capturedPort=p;capturedHint=h;
    return h>=1 && h<=4 ? backendStatus : STATUS_NOT_SUPPORTED;
}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN){return backendStatus;}
'''
TEST = r'''
static void request(Wifi& w,UINT16 port,WDI_CONNECTION_QUALITY_HINT hint,bool low=true,bool malformed=false) {
    WDI_SET_CONNECTION_QUALITY_PARAMETERS p={};p.Quality=hint;
    p.Optional.LowLatencyParameters_IsPresent=low;
    p.LowLatencyParameters.RoamingNeededLinkQualityThreshold=42;
    p.LowLatencyParameters.MaximumOffChannelOperationTime=50;
    ULONG n=0;UCHAR* wire=nullptr;WDI_MESSAGE_HEADER h={};h.PortId=port;
    assert(GenerateWdiSetConnectionQualityToIhv(&p,0,&w.TlvContext,&n,&wire)==0);
    assert(n>1);result=0x12345678;
    Ap6256HandleSetConnectionQuality(&w,&h,nullptr,wire,malformed ? n-1 : n);
    FreeGenerated(wire);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    static_assert(WDI_CONNECTION_QUALITY_HIGH_THROUGHPUT==3,"SDK quality numbering");
    Device d;Wifi w={};w.Ctx=&d;
    for(ULONG version:{WDI_VERSION_1_0,AP6256_TEST_WDI_VERSION}) {
        w.TlvContext.PeerVersion=version;
        for(UINT16 port:std::initializer_list<UINT16>{0,1,2})for(UINT32 value:{3u,1u,2u,4u}) {
            UINT32 before=backendCalls;backendStatus=0;
            request(w,port,(WDI_CONNECTION_QUALITY_HINT)value);
            assert(result==0 && backendCalls==before+1 && capturedPort==port && capturedHint==value);
            if(port==0)assert(w.RoamLinkQualityThresholdValid==(value==2));
            if(port==0 && value==2)assert(w.RoamLinkQualityThreshold==42);
        }
        for(UINT16 port:std::initializer_list<UINT16>{3,0xffff}) {
            UINT32 before=backendCalls;request(w,port,WDI_CONNECTION_QUALITY_HIGH_THROUGHPUT);
            assert(result==STATUS_INVALID_DEVICE_STATE && backendCalls==before);
        }
        for(UINT16 port:std::initializer_list<UINT16>{0,1,2}) {
            w.PortCreated=FALSE;w.P2pPortCreated=FALSE;d.Go.Created=FALSE;
            UINT32 before=backendCalls;request(w,port,WDI_CONNECTION_QUALITY_HIGH_THROUGHPUT);
            assert(result==STATUS_INVALID_DEVICE_STATE && backendCalls==before);
            w.PortCreated=w.P2pPortCreated=d.Go.Created=TRUE;
        }
        UINT32 before=backendCalls;w.RoamLinkQualityThresholdValid=TRUE;w.RoamLinkQualityThreshold=57;
        request(w,0,WDI_CONNECTION_QUALITY_LOW_LATENCY,false);
        assert(!NT_SUCCESS(result) && backendCalls==before && w.RoamLinkQualityThresholdValid && w.RoamLinkQualityThreshold==57);
        request(w,2,WDI_CONNECTION_QUALITY_HIGH_THROUGHPUT,true,true);
        assert(!NT_SUCCESS(result) && backendCalls==before);
        backendStatus=STATUS_DEVICE_BUSY;
        request(w,0,WDI_CONNECTION_QUALITY_HIGH_THROUGHPUT);
        assert(result==STATUS_DEVICE_BUSY && w.RoamLinkQualityThresholdValid && w.RoamLinkQualityThreshold==57);
        backendStatus=0;request(w,2,WDI_CONNECTION_QUALITY_LOW_LATENCY);
        assert(result==0 && w.RoamLinkQualityThreshold==57);
    }
    puts("PASS: real Microsoft codec at original/current WDI contracts accepts HIGH=3 and routes by port; invalid/malformed/absent ports and failed policy preserve station state");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source', type=Path, default=ROOT / 'src/common/netadapter.c')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    f = _functions(args.source.read_text(encoding='utf-8-sig'))['Ap6256HandleSetConnectionQuality']
    body = f[f.index('{') + 1:]
    code = contract_preamble() + BASE['PRE'] + '\n#include <initializer_list>\n' + MOCK
    code += r'''static VOID Ap6256HandleSetConnectionQuality(Wifi* Wifi,PWDI_MESSAGE_HEADER Header,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength) {(void)Header;
''' + body + '\n' + TEST
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    (vc, inc, lib) = [CONTROL[n] for n in ('VC', 'INC', 'LIB')]
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / n) for n in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    built = subprocess.run(cmd, capture_output=True)
    write_bytes(out / 'compile.log', built.stdout + built.stderr)
    if built.returncode:
        print((built.stdout + built.stderr).decode(errors='replace'))
        built.check_returncode()
    ran = subprocess.run([str(out / 'tests.exe')], capture_output=True, timeout=30)
    write_bytes(out / 'runtime.log', ran.stdout + ran.stderr)
    print((ran.stdout + ran.stderr).decode(errors='replace'))
    assert ran.returncode == 0
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    write_text(out / 'receipt.json', json.dumps(dict(passed=True, expected_failure=False, board_verified=False, source_sha256=sha(args.source), test_sha256=sha(Path(__file__)), cpp_sha256=sha(cpp), exe_sha256=sha(out / 'tests.exe'), runtime_exit_code=ran.returncode), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
