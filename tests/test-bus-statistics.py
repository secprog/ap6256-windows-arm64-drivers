# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import json
import subprocess
from driver_sources import _functions
import importlib.util
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('tx', ROOT / 'tests/test-wdi-transmit.py')
tx = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tx)
FIELDS = 'StatHdrReads StatHdrReadUs StatBodyReads StatBodyReadBytes StatBodyReadUs StatWrites StatWriteBytes StatWriteUs StatOtherCmd53 StatOtherUs StatRxFrames StatTxFrames StatPasses StatEmptyPolls'.split()
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <vector>
#include <cassert>
#include <cstdio>
#undef _IRQL_requires_max_
#define _IRQL_requires_max_(x)
#define TRACE_SDIO 0
#define AP6256_BUS_STATS_PERIOD_MS 5000u
struct Device { struct {
AP6256_STAT_FIELDS
volatile LONG IsrCount=0;
LONG StatIsrSnapshot=0;
ULONGLONG StatPrintedAt=0;
} Sdio; };
typedef Device* PAP6256_DEVICE_CONTEXT;
static ULONGLONG clock100ns=100000000;
static ULONGLONG KeQueryInterruptTime() { return clock100ns; }
static std::vector<std::vector<LONGLONG>> samples;
template<class... Args> static void TraceInfo(ULONG,const char*,Args... args) {
    samples.push_back({(LONGLONG)args...});
}
'''
TEST = r'''
int main() {
    Device d={};
    for(auto field:fields(d)) *field=137415;
    d.Sdio.StatOtherUs=53173000;d.Sdio.IsrCount=210;
    Ap6256SdioTraceBusStats(&d);
    bool clean=d.Sdio.StatIsrSnapshot==210;
    for(auto field:fields(d)) clean=clean && *field==0;
    if(AP6256_EXPECT_BASELINE_BUG) {
        assert(!clean && samples.empty());
        puts("PASS: frozen historical negative control retains startup totals beyond its new window baseline");
        return 0;
    }
    assert(clean && samples.empty() && d.Sdio.StatPrintedAt==clock100ns);
    d.Sdio.StatRxFrames=9;d.Sdio.StatHdrReads=5;d.Sdio.StatHdrReadUs=5000;
    d.Sdio.StatBodyReads=2;d.Sdio.StatBodyReadBytes=4096;d.Sdio.StatBodyReadUs=2000;
    d.Sdio.StatTxFrames=3;d.Sdio.StatWrites=2;d.Sdio.StatWriteBytes=2048;d.Sdio.StatWriteUs=3000;
    d.Sdio.StatOtherCmd53=4;d.Sdio.StatOtherUs=4000;
    d.Sdio.StatPasses=4;d.Sdio.StatEmptyPolls=2;d.Sdio.IsrCount=214;
    clock100ns+=4999*10000ull;Ap6256SdioTraceBusStats(&d);
    assert(samples.empty() && d.Sdio.StatOtherCmd53==4 && d.Sdio.StatOtherUs==4000);
    clock100ns+=10000;Ap6256SdioTraceBusStats(&d);
    const std::vector<LONGLONG> expected={5000,9,5,1000,2,4,1000,3,2,2,1500,4,1000,14,4,4,2};
    assert(samples.size()==1 && samples[0]==expected);
    for(auto field:fields(d)) assert(*field==0);
    assert(d.Sdio.StatIsrSnapshot==214);
    clock100ns+=5000*10000ull;Ap6256SdioTraceBusStats(&d);
    assert(samples.size()==1 && d.Sdio.StatPrintedAt==clock100ns);
    d.Sdio.StatPrintedAt=0;
    for(auto field:fields(d)) *field=999;
    d.Sdio.IsrCount=400;
    clock100ns+=30000*10000ull;Ap6256SdioTraceBusStats(&d);
    for(auto field:fields(d)) assert(*field==0);
    assert(samples.size()==1 && d.Sdio.StatIsrSnapshot==400);
    d.Sdio.StatTxFrames=1;d.Sdio.StatWrites=1;d.Sdio.StatWriteUs=7000;d.Sdio.IsrCount=401;
    clock100ns+=5000*10000ull;Ap6256SdioTraceBusStats(&d);
    assert(samples.size()==2 && samples[1][0]==5000 && samples[1][13]==7 && samples[1][14]==1);
    puts("PASS: production bus-statistics startup/reset baselines, exact first window, pre-deadline retention, idle window and ISR deltas");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, default=ROOT / 'src/common/sdio.c')
    parser.add_argument('--output', type=Path, default=output_dir('bus-statistics'))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    source = args.source.read_text(encoding='utf-8-sig')
    functions = _functions(source)
    fields = '\n'.join(('volatile LONGLONG ' + field + '=0;' for field in FIELDS))
    text = PRE.replace('AP6256_STAT_FIELDS', fields)
    text += '#define AP6256_EXPECT_BASELINE_BUG ' + str(int(False)) + '\n'
    text += '\n'.join((functions[name] for name in ('Ap6256StatTake', 'Ap6256StatAverage', 'Ap6256SdioTraceBusStats')))
    text += '\nstatic std::vector<volatile LONGLONG*> fields(Device& d) { return {'
    text += ','.join(('&d.Sdio.' + field for field in FIELDS)) + '}; }\n' + TEST
    cpp = args.output / 'tests.cpp'
    write_bytes(cpp, text.encode())
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / name) for name in ('ucrt', 'shared', 'um')]
    command += [str(cpp), '/Fe:' + str(args.output / 'tests.exe'), '/Fo:' + str(args.output / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64')]
    subprocess.run(command, check=True)
    subprocess.run([str(args.output / 'tests.exe')], check=True)
    receipt = {'source_sha256': hashlib.sha256(args.source.read_bytes()).hexdigest(), 'source': str(args.source), 'passed': True, 'negative_control': False, 'board_verified': False, 'production_functions_executed': 3}
    write_text(args.output / 'result.json', json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
