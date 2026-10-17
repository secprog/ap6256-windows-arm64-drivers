# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from test_support import write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re
from driver_sources import _functions

AP = Path(__file__).resolve().parents[1]
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cassert>
#include <cstdio>
#define NT_SUCCESS(s) (((LONG)(s)) >= 0)
#define AP6256_SDIO_FUNC_DATA 2
#define TRACE_SDIO 4
#define TRACE_DRIVER 1
struct Device {struct {
    LONG IsrCount;
    LONGLONG StatWrites,StatWriteBytes,StatWriteUs,StatHdrReads,StatHdrReadUs;
    LONGLONG StatBodyReads,StatBodyReadBytes,StatBodyReadUs,StatOtherCmd53,StatOtherUs;
} Sdio;} device;
struct Packet {ULONG Information,ResponseLength;} packet;
struct Interface {PVOID Context;} interface;
static bool enabled,flip;
static LONG result;
static LONGLONG frequency=1000000;
static unsigned qpc,bus,atoms,diags;
static LONGLONG times;
static BOOLEAN Ap6256TraceInformationEnabled(ULONG category) {
    assert(category==(TRACE_SDIO|TRACE_DRIVER));return (BOOLEAN)enabled;
}
static LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER* f) {
    if(f)f->QuadPart=frequency;
    LARGE_INTEGER t;t.QuadPart=1000+250*qpc++;return t;
}
static LONG SdBusSubmitRequest(PVOID,Packet*) {bus++;if(flip)enabled=!enabled;return result;}
static LONGLONG add(LONGLONG* p,LONGLONG n) {atoms++;return *p+=n;}
#undef InterlockedIncrement64
#undef InterlockedAdd64
#define InterlockedIncrement64(p) add(p,1)
#define InterlockedAdd64(p,n) add(p,n)
template<class... Args> static void diag(const char*,ULONG,ULONG,const char*,ULONGLONG us,Args...) {
    diags++;times=(LONGLONG)us;
}
#define TraceDiag(...) diag(__VA_ARGS__)
static void reset(bool logging,LONG status) {
    memset(&device,0,sizeof(device));qpc=bus=atoms=diags=0;times=-1;
    enabled=logging;result=status;flip=false;frequency=1000000;
}
'''

TEST = r'''
int main() {
    unsigned cases=0;
    for(unsigned logging=0;logging<2;logging++)for(unsigned failure=0;failure<2;failure++)
    for(unsigned function=1;function<=2;function++)for(unsigned write=0;write<2;write++)
    for(unsigned byteMode=0;byteMode<2;byteMode++) {
        reset(logging!=0,failure?-1:0);
        LONG status=Candidate((UCHAR)function,(BOOLEAN)write,(BOOLEAN)byteMode);
        assert(status==result && bus==1);
        unsigned expectedAtoms=(!logging)?0:((function==2&&(write||!byteMode))?3:2);
        assert(qpc==(logging?2u:0u) && atoms==expectedAtoms && diags==(logging&&failure?1u:0u));
        if(logging) {
            if(function==2&&write)assert(device.Sdio.StatWrites==1&&device.Sdio.StatWriteBytes==512&&device.Sdio.StatWriteUs==250);
            else if(function==2&&byteMode)assert(device.Sdio.StatHdrReads==1&&device.Sdio.StatHdrReadUs==250);
            else if(function==2)assert(device.Sdio.StatBodyReads==1&&device.Sdio.StatBodyReadBytes==512&&device.Sdio.StatBodyReadUs==250);
            else assert(device.Sdio.StatOtherCmd53==1&&device.Sdio.StatOtherUs==250);
        }
        if(logging&&failure)assert(times==250);
        cases++;
    }
    reset(false,0);Baseline(2,TRUE,FALSE);assert(qpc==2&&atoms==3&&bus==1);
    reset(true,-1);frequency=0;Candidate(2,FALSE,FALSE);
    assert(qpc==2&&atoms==3&&bus==1&&times==0);cases++;
    reset(true,0);flip=true;Candidate(2,TRUE,FALSE);
    assert(!enabled&&qpc==2&&atoms==3&&bus==1);cases++;
    reset(false,0);flip=true;Candidate(2,TRUE,FALSE);
    assert(enabled&&qpc==0&&atoms==0&&bus==1);cases++;
    printf("PASS: %u actual CMD53 timing/accounting cases; quiet path 0 timer calls/0 diagnostic updates; baseline overhead reproduced\n",cases);
}
'''


def extract(body, name):
    if name=='Baseline':
        body=body.replace('if (traceStats) submitStart','submitStart').replace('if (traceStats) submitEnd','submitEnd')
        body=body.replace('if (traceStats) {','{').replace(' && traceStats','')
    start = body.index('        if (traceStats) submitStart' if name == 'Candidate' else '        submitStart')
    end = body.index('        if (!Write) {\n            KeFlushIoBuffers', start)
    declarations = re.search(r'^\s*LARGE_INTEGER submitStart[^;]+;', body, re.M)[0] + '\n'
    if name == 'Candidate':
        declarations += re.search(r'^\s*BOOLEAN traceStats = [^;]+;', body, re.M)[0] + '\n'
    declarations += '    LONGLONG submitUs=0;\n'
    return ('static LONG ' + name + '(UCHAR Function,BOOLEAN Write,BOOLEAN ByteMode) {\n'
        '    auto Ctx=&device;auto iface=&interface;ULONG chunk=512;BOOLEAN blockMode=FALSE;LONG status;\n' +
        declarations + body[start:end] + '    return status;\n}\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser();parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args();out = args.output.resolve();out.mkdir(parents=True, exist_ok=True)
    script = AP / 'tests/test-packet-performance.py'
    spec = importlib.util.spec_from_file_location('costs', script)
    costs = importlib.util.module_from_spec(spec);spec.loader.exec_module(costs)
    current = AP / 'src/common/sdbus_glue.c'
    body=_functions(current.read_text(encoding='utf-8-sig'))['Ap6256SdBusCmd53Mode']
    source = PRE + extract(body, 'Baseline') + extract(body, 'Candidate') + TEST
    costs.compile_run(source, out)
    result = dict(passed=True, board_verified=False, cases=35, actual_cmd53_timing_block=True,
        disabled_per_transfer_timer_calls=0, disabled_diagnostic_atomic_updates=0,
        single_transfer_call_preserved=True, failure_status_preserved=True,
        source_sha256=hashlib.sha256(current.read_bytes()).hexdigest(),
        regression_control_generated_from_current_source=True)
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
