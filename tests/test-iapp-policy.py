# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import subprocess
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('iapp_tx', AP / 'tests/test-wdi-transmit.py')
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#undef _IRQL_requires_max_
#define _IRQL_requires_max_(x)
#undef RtlEqualMemory
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
typedef LONG NTSTATUS;
#define TraceWarn(...) ((void)0)
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceFrameDiag(...) ((void)0)
#define Ap6256TraceEapol(...) ((void)0)
#define Ap6256TraceHotspotPacket(...) ((void)0)
#define AP6256_RXF_PROMISCUOUS 0x80u
#define AP6256_RXF_BROADCAST 8u
#define AP6256_RXF_MULTICAST 2u
#define AP6256_RXF_ALL_MULTICAST 4u
#define AP6256_RXF_DIRECTED 1u
struct Device {LONG RxFrames=0,RxFiltered=0,PacketFilter=0x8f;struct {bool FirmwareReady=true;UINT32 IfIndex=7;LONG PacketFilter=0x8f;}Go;};
typedef Device* PAP6256_DEVICE_CONTEXT;
static unsigned received;
static void Ap6256NetRxIndicate(Device*,UCHAR*,ULONG,UCHAR,UINT32){++received;}
'''
TEST = r'''
int main(int argc,char**) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    const UCHAR body[]={0,1,0xaf,0x81,1,0};
    for(unsigned iface:{0u,7u})for(unsigned changed=0;changed<8;++changed){
        Device d;received=0;UCHAR ethernet[20]={};ethernet[0]=0xff;ethernet[13]=6;memcpy(ethernet+14,body,6);
        if(changed<6)ethernet[14+changed]^=1;
        if(changed==6)ethernet[0]=2;
        Ap6256IndicateRx(&d,ethernet,sizeof(ethernet),0,iface);
        if(argc==1)assert(received==(changed==7?0u:1u));
        UCHAR native[30]={};native[0]=8;memcpy(native+4,ethernet,6);memcpy(native+24,ethernet+14,6);ULONG length=99;
        NTSTATUS status=Ap6256Tal80211ToEthernet(native,sizeof(native),&length);
        assert(changed==7?(status==STATUS_NOT_SUPPORTED && length==0):(status==0 && length==20));
    }
    for(unsigned n=0;n<30;++n){UCHAR native[30]={};native[0]=8;native[4]=0xff;memcpy(native+24,body,6);ULONG length=99;
        assert(Ap6256Tal80211ToEthernet(native,n,&length)==(n<24?STATUS_INVALID_BUFFER_SIZE:STATUS_SUCCESS));}
    puts("PASS: production RX/TX IAPP reflection guards, both interfaces, byte mutations, unicast and short payload boundaries");
}
'''

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--source', type=Path, default=AP / 'src/common')
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=True)
    converter = (a.source / 'native_frame.inc').read_text(encoding='utf-8-sig')
    rx = _functions((a.source / 'datapath.c').read_text(encoding='utf-8-sig'))['Ap6256IndicateRx']
    cpp = a.output / 'test.cpp'
    write_text(cpp, PRE + converter + rx + TEST, encoding='utf-8')
    exe = a.output / 'test.exe'
    cmd = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/W4', '/WX', '/wd4100', '/EHsc', '/Od', '/MT', '/I' + str(tx.VC / 'include')]
    cmd += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um')]
    cmd += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(a.output / 'test.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    subprocess.run(cmd, check=True)
    result = subprocess.run([str(exe)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout.decode(errors='replace'))
    result.check_returncode()
    sha = lambda f: hashlib.sha256(f.read_bytes()).hexdigest()
    write_text(a.output / 'receipt.json', json.dumps(dict(test_sha256=sha(Path(__file__)), converter_sha256=sha(a.source / 'native_frame.inc'), datapath_sha256=sha(a.source / 'datapath.c'), fixture_sha256=sha(cpp), expected_missing=False, board_tested=False), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
