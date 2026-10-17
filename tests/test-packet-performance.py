# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from test_support import write_text, write_bytes
from pathlib import Path
import difflib
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
import sys

import argparse
AP = Path(__file__).resolve().parents[1]
OUT = None
sys.path.insert(0,str(AP / "tests"))
def module(name):
    spec = importlib.util.spec_from_file_location(name, AP / 'tests' / (name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function_text(source, name):
    match = re.search(r'^(?:static\s+)?(?:[A-Z][A-Za-z0-9_]*\s+)+' +
        re.escape(name) + r'\s*\([^;]*?\)\s*\{', source, re.M)
    assert match, name
    chunk = source[match.end()-1:]
    clean = re.sub(r'//[^\n]*|/\*[\s\S]*?\*/|"(?:\\.|[^"\\])*"',
        lambda m: ' ' * len(m[0]), chunk)
    depth = 0
    for index, char in enumerate(clean):
        depth += (char == '{') - (char == '}')
        if depth == 0:
            return source[match.start():match.end()-1] + chunk[:index+1]
    raise ValueError(name)


COUNTERS = r'''
static unsigned long long acquired_locks, zeroed_bytes;
static void measured_zero(void* target,SIZE_T bytes) {zeroed_bytes+=bytes;memset(target,0,bytes);}
#undef RtlZeroMemory
#define RtlZeroMemory(p,n) measured_zero(p,n)
'''


def run_engine(root, name, previous=None):
    test = module('test-wlfc')
    if previous is not None:
        from driver_sources import _fixture
        previous=_fixture(previous,AP,'wdi').replace('->Model.','->').replace('->Auth.','->')
        original=test.read_source_text
        test.read_source_text=lambda path,*a,**kw: previous if Path(path).name=='wlfc.c' else original(path,*a,**kw)
    test.PRE = test.PRE.replace('static int spinDepth;', 'static int spinDepth;\n' + COUNTERS)
    test.PRE = test.PRE.replace('{ *i=0;spinDepth++; }', '{ *i=0;spinDepth++;++acquired_locks; }')
    test.TEST += r'''
struct PerformanceReport {
    ~PerformanceReport(){printf("PERF-COUNTS zero_bytes=%llu lock_acquires=%llu packet_size=%zu payload_capacity=%zu\n",
        zeroed_bytes,acquired_locks,sizeof(WLFC_PACKET),sizeof(((WLFC_PACKET*)0)->Ethernet));}
};
static PerformanceReport performance_report;
'''
    old_argv = sys.argv
    try:
        sys.argv = ['test-wlfc.py', '--source-root', str(root), '--output', str(OUT / name)]
        test.main()
    finally:
        sys.argv = old_argv
    log = (OUT / name / 'run.log').read_text()
    found = re.search(r'PERF-COUNTS zero_bytes=(\d+) lock_acquires=(\d+) packet_size=(\d+) payload_capacity=(\d+)', log)
    assert found
    return dict(zip(('zero_bytes', 'lock_acquires', 'packet_size', 'payload_capacity'), map(int, found.groups())))


def compile_run(source, folder):
    tx = module('test-wdi-transmit')
    folder.mkdir(parents=True, exist_ok=True)
    cpp = folder / 'test.cpp'
    write_bytes(cpp,source.encode())
    exe = folder / 'test.exe'
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc',
        '/W4', '/WX', '/wd4100', '/wd4505', '/O2', '/MT', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / part) for part in ('ucrt', 'shared', 'um')]
    command += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(folder / 'test.obj'), '/link',
        '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'),
        '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    result = subprocess.run(command, capture_output=True)
    (folder / 'compile.log').write_bytes(result.stdout + result.stderr)
    if result.returncode:
        print((result.stdout + result.stderr).decode(errors='replace'))
        result.check_returncode()
    run = subprocess.run([str(exe)], capture_output=True)
    (folder / 'run.log').write_bytes(run.stdout + run.stderr)
    print((run.stdout + run.stderr).decode(errors='replace'))
    run.check_returncode()


EXTRA_TEST = r'''
static AP6256_WLFC* reentrant_queue;
static unsigned reentrant_calls;
static void reenter_notify() {assert(spinDepth==0);assert(!WlfcNotify(reentrant_queue));reentrant_calls++;}
int main() {
    Device d={};
    auto a=new AP6256_WLFC{};auto b=new AP6256_WLFC{};
    auto packet=new WLFC_PACKET{};
    a->Ctx=b->Ctx=&d;
    const unsigned lengths[]={14,60,64,511,512,1514,1600,8192,8352};
    unsigned comparisons=0;
    for(unsigned glom=0;glom<2;glom++)for(unsigned tim=0;tim<2;tim++)
    for(unsigned seed=1;seed<=12;seed++)for(unsigned length:lengths) {
        d.Sdio.TxGlom=(BOOLEAN)glom;
        packet->Length=length;packet->Tag=seed*0x1234567u;packet->Priority=(UCHAR)(seed&7);
        packet->IfIndex=(UCHAR)(seed&15);packet->Exemption=(UCHAR)(seed&3);
        for(unsigned i=0;i<length;i++)packet->Ethernet[i]=(UCHAR)(i*seed+13);
        for(unsigned present=0;present<2;present++) {
            memset(a->Wire,0xa5,sizeof(a->Wire));memset(b->Wire,0xa5,sizeof(b->Wire));
            unsigned baseline=BaselineBuild(a,present?packet:nullptr,4,0,0x5a,tim!=0);
            unsigned proposed=WlfcBuild(b,present?packet:nullptr,4,0,0x5a,tim!=0);
            assert(baseline==proposed && !memcmp(a->Wire+4,b->Wire+4,baseline));
            for(unsigned i=0;i<4;i++)assert(b->Wire[i]==0xa5);
            assert(b->Wire[4+proposed]==0xa5);
            comparisons++;
        }
    }
    memset(a,0,sizeof(*a));memset(b,0,sizeof(*b));a->Ctx=b->Ctx=&d;
    unsigned long long before=acquired_locks;
    assert(!BaselineNotify(a));unsigned long long old_locks=acquired_locks-before;
    before=acquired_locks;assert(!WlfcNotify(b));unsigned long long new_locks=acquired_locks-before;
    assert(old_locks==128 && new_locks==1);
    printf("POISON-CHECKS wire_cases=%u empty_notify_locks=%llu->%llu\n",comparisons,old_locks,new_locks);
    delete packet;delete a;delete b;
    Device oldDevice,newDevice;Init(oldDevice);Init(newDevice);
    unsigned reuse=0;
    const unsigned normalLengths[]={14,60,64,511,512,1514,1600};
    for(unsigned seed=1;seed<=12;seed++)for(unsigned length:normalLengths) {
        auto oldPacket=&oldDevice.Wlfc->Packets[0];auto newPacket=&newDevice.Wlfc->Packets[0];
        memset(oldPacket,0xc3,sizeof(*oldPacket));memset(newPacket,0xc3,sizeof(*newPacket));
        oldPacket->State=newPacket->State=WlfcFree;
        UCHAR data[1600];for(unsigned i=0;i<length;i++)data[i]=(UCHAR)(seed*i+5);
        data[0]&=0xfe;data[12]=8;data[13]=0;
        assert(NT_SUCCESS(BaselineEnqueue(&oldDevice,data,length,(UCHAR)(seed&7),0,0,0,0,Completion,nullptr)));
        assert(NT_SUCCESS(Ap6256WlfcEnqueue(&newDevice,data,length,(UCHAR)(seed&7),0,0,0,0,Completion,nullptr)));
        assert(!memcmp(oldPacket,newPacket,FIELD_OFFSET(WLFC_PACKET,Ethernet)));
        assert(!memcmp(oldPacket->Ethernet,newPacket->Ethernet,length));
        for(unsigned i=length;i<sizeof(newPacket->Ethernet);i++)assert(newPacket->Ethernet[i]==0xc3);
        memset(oldDevice.Wlfc->Wire,0xa5,sizeof(oldDevice.Wlfc->Wire));
        memset(newDevice.Wlfc->Wire,0xa5,sizeof(newDevice.Wlfc->Wire));
        unsigned oldSize=BaselineBuild(oldDevice.Wlfc,oldPacket,0,0,0,FALSE);
        unsigned newSize=WlfcBuild(newDevice.Wlfc,newPacket,0,0,0,FALSE);
        assert(oldSize==newSize && !memcmp(oldDevice.Wlfc->Wire,newDevice.Wlfc->Wire,oldSize));
        assert(newDevice.Wlfc->Wire[newSize]==0xa5);
        oldPacket->State=newPacket->State=WlfcFree;
        oldDevice.Wlfc->Used=newDevice.Wlfc->Used=0;reuse++;
    }
    End(oldDevice);End(newDevice);
    Device nested;Init(nested);Map(&nested,{0,1,0,0,0,0});Queue(nested);
    reentrant_queue=nested.Wlfc;completionHook=reenter_notify;Pump(&nested);
    assert(transfers.size()==1 && sends.empty());Status(&nested,writes.back().Tag,0);Pump(&nested);
    assert(reentrant_calls==2 && transfers.size()==1 && sends.size()==1);completionHook=nullptr;End(nested);
    printf("REUSE-CHECKS poisoned_packet_cases=%u metadata_and_wire_equal=1\n",reuse);
}
'''


def extra_checks(before):
    source = (OUT / 'candidate-engine/tests.cpp').read_text()
    source = source[:source.index('int main(')]
    source += function_text(before, 'WlfcBuild').replace('WlfcBuild(', 'BaselineBuild(', 1) + '\n'
    source += function_text(before, 'WlfcNotify').replace('WlfcNotify(', 'BaselineNotify(', 1) + '\n'
    source += function_text(before, 'Ap6256WlfcEnqueue').replace('Ap6256WlfcEnqueue(', 'BaselineEnqueue(', 1) + '\n'
    source += EXTRA_TEST
    compile_run(source, OUT / 'poison-and-locks')




def regression_control(source):
    source=source.replace('RtlZeroMemory(p, FIELD_OFFSET(WLFC_PACKET, Ethernet));','RtlZeroMemory(p, sizeof(*p));')
    source=source.replace('RtlZeroMemory(wire, hdr + sizeof(BCDC_DATA_HEADER) + signals);','RtlZeroMemory(wire, length);')
    old=function_text(source,'WlfcNotify')
    new=old.replace('    KeAcquireSpinLock(&W->Lock, &irql);\n    for (','    for (',1)
    new=new.replace('        PVOID cookie;','        PVOID cookie;\n        KeAcquireSpinLock(&W->Lock, &irql);',1)
    new=new.replace('            continue;','            KeReleaseSpinLock(&W->Lock, irql);\n            continue;',1)
    new=new.replace('        progress = TRUE;','        KeReleaseSpinLock(&W->Lock, irql);\n        progress = TRUE;',1)
    new=new.replace('    KeReleaseSpinLock(&W->Lock, irql);\n    return progress;','    return progress;',1)
    return source.replace(old,new)


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();OUT=args.output.resolve();OUT.mkdir(parents=True,exist_ok=True)
    current=AP/'src/common/wlfc.c'
    before=regression_control(current.read_text(encoding='utf-8-sig'))
    baseline=run_engine(AP,'baseline-engine',before)
    candidate=run_engine(AP,'candidate-engine')
    extra_checks(before)
    assert candidate['zero_bytes'] < baseline['zero_bytes']
    assert candidate['lock_acquires'] < baseline['lock_acquires']
    result=dict(passed=True,board_verified=False,sustained_packets_per_engine=80000,
        wire_comparisons=864,poisoned_reused_packets=84,reentrant_callbacks=True,
        baseline=baseline,candidate=candidate,
        zero_bytes_saved=baseline['zero_bytes']-candidate['zero_bytes'],
        lock_acquires_saved=baseline['lock_acquires']-candidate['lock_acquires'],
        source_sha256=sha(current),control_sha256=hashlib.sha256(before.encode()).hexdigest())
    write_text(OUT/'result.json',json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))
