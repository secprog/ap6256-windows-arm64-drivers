# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise the production Advanced-page setting through native PM SET/GET.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import csv
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
#include <vector>
#include <string>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TRACE_NETADAPTER 0
#define TraceInfo(...) ((void)0)
#define TraceWarn(...) ((void)0)
struct Device {PVOID Pdo;};
typedef Device* PAP6256_DEVICE_CONTEXT;
static std::vector<UCHAR> registryBytes;
static ULONG registryType,registryQueries,sets,gets,wirePm;
static NTSTATUS registryStatus,setStatus,getStatus;
struct AP6256_BCDC_QUERY_RESULT {BOOLEAN FirmwareReply,FirmwareError; INT32 FirmwareStatus; ULONG PayloadLength;};
static bool pmMismatch,pmShort;
static PVOID lastPdo;
static NTSTATUS Ap6256RegQueryValue(PVOID pdo,PCWSTR name,ULONG capacity,
                                  PVOID data,PULONG length,PULONG type) {
    assert(!wcscmp(name,L"PowerSaveMode"));registryQueries++;lastPdo=pdo;
    *length=0;*type=REG_NONE;
    if(!NT_SUCCESS(registryStatus))return registryStatus;
    if(registryBytes.size()>capacity)return STATUS_BUFFER_OVERFLOW;
    *length=(ULONG)registryBytes.size();*type=registryType;
    if(*length)memcpy(data,registryBytes.data(),*length);
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetDcmd(Device* d,UINT32 command,PVOID data,ULONG length) {
    assert(d->Pdo==lastPdo || !registryQueries);
    assert(command==BRCMF_C_SET_PM && length==4);sets++;memcpy(&wirePm,data,4);
    return setStatus;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device*,UINT32 iface,UINT32 command,PVOID data,ULONG length,AP6256_BCDC_QUERY_RESULT* result) {
    assert(!iface);*result={TRUE,FALSE,0,pmShort?0u:4u};
    assert(command==BRCMF_C_GET_PM && length==4);gets++;UINT32 value=wirePm^(pmMismatch?1u:0u);memcpy(data,&value,4);
    return getStatus;
}
static void reset(ULONG type,const std::vector<UCHAR>& data,NTSTATUS status=0) {
    registryType=type;registryBytes=data;registryStatus=status;
    sets=gets=registryQueries=wirePm=0;setStatus=getStatus=0;lastPdo=nullptr;pmMismatch=pmShort=false;
}
'''
TEST = r'''
int main() {
    Device d={(PVOID)0x1234};
    for(UCHAR mode=0;mode<3;mode++) {

        reset(REG_SZ,{(UCHAR)('0'+mode),0,0,0});
        assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==mode);
        assert(registryQueries==1 && sets==1 && gets==1 && lastPdo==d.Pdo);

        reset(REG_DWORD,{mode,0,0,0});
        assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==mode);
    }
    puts("PASS: all three Advanced-page strings and legacy DWORDs select the actual native PM SET/GET");
    for(ULONG type:{REG_SZ,REG_DWORD,REG_BINARY,REG_MULTI_SZ,REG_EXPAND_SZ,REG_NONE}) {
        for(const std::vector<UCHAR>& bytes:{std::vector<UCHAR>{}, {0}, {0,0},
            {0,0,0}, {3,0,0,0}, {0xff,0xff,0xff,0xff}, {'9',0,0,0},
            {'1',0,'x',0}, {'1',1,0,0}, {'0',0,'1',0,0,0}, {'1',0,0,0,0,0}}) {
            reset(type,bytes);
            assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==2);
        }
    }
    for(NTSTATUS failure:{STATUS_OBJECT_NAME_NOT_FOUND,STATUS_ACCESS_DENIED,STATUS_INSUFFICIENT_RESOURCES}) {
        reset(REG_SZ,{'1',0,0,0},failure);
        assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==2);
    }

    reset(REG_SZ,{'1',0,0,0});
    assert(Ap6256WifiSetPowerSave(&d,FALSE)==0 && !registryQueries && wirePm==0);

    reset(REG_SZ,{'1',0,0,0});
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==1);
    registryBytes={'0',0,0,0};
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==0 && wirePm==0 && registryQueries==2);
    Device other={(PVOID)0x5678};
    registryBytes={'2',0,0,0};
    assert(Ap6256WifiSetPowerSave(&other,TRUE)==0 && lastPdo==other.Pdo && wirePm==2);
    reset(REG_SZ,{'1',0,0,0});setStatus=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==STATUS_IO_TIMEOUT && sets==1 && gets==0);
    reset(REG_SZ,{'1',0,0,0});getStatus=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==STATUS_IO_TIMEOUT && sets==1 && gets==1);
    reset(REG_SZ,{'1',0,0,0});pmMismatch=true;
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==STATUS_DEVICE_PROTOCOL_ERROR);
    reset(REG_SZ,{'0',0,0,0});pmShort=true;
    assert(Ap6256WifiSetPowerSave(&d,TRUE)==STATUS_DEVICE_PROTOCOL_ERROR);
    puts("PASS: invalid settings, per-device changes and rejected/truncated/mismatched PM readback");
}
'''

def verify_inf(path):
    sections = {}
    section = None
    for raw in path.read_text(encoding='utf-8-sig').splitlines():
        line = raw.split(';', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.lower()
            sections[section] = []
        elif section:
            sections[section].append(line)
    install = '\n'.join(sections['[ap6256.install]'])
    assert re.search('Characteristics\\s*=\\s*0x84', install)
    assert re.search('AddReg\\s*=.*AP6256.NdisReg.*AP6256.Params.reg', install)
    entries = [next(csv.reader([line], skipinitialspace=True)) for line in sections['[ap6256.ndisreg]']]
    values = {(r[1].lower(), r[2].lower()): r[4] for r in entries}
    prefix = 'ndi\\params\\powersavemode'
    assert values[prefix, 'type'] == 'enum'
    assert values[prefix, 'default'] == '2' and values[prefix, 'optional'] == '0'
    assert {r[2]: r[4] for r in entries if r[1].lower() == prefix + '\\enum'} == {'0': '%PowerSaveDisabled%', '1': '%PowerSaveMaximum%', '2': '%PowerSaveFast%'}
    strings = '\n'.join(sections['[strings]'])
    assert re.search('PowerSaveLevel\\s*=\\s*"Power Save Level"', strings)
    root = next((next(csv.reader([line], skipinitialspace=True)) for line in sections['[ap6256.params.reg]'] if re.search(',\\s*PowerSaveMode\\s*,', line, re.I)))
    assert root == ['HKR', '', 'PowerSaveMode', '0x00000002', '2']

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, default=output_dir('power-save-settings'))
    args = parser.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    source = args.source_root.resolve() / 'src/common/wifi_ops.c'
    text = source.read_text(encoding='utf-8-sig')
    for name in ('ap6256.inf', 'ap6256-wificx.inf'):
        verify_inf(ROOT / 'inf' / name)
    functions = _functions(text)
    constants = '\n'.join(re.findall('^#define (?:AP6256_PM_\\w+|BRCMF_C_(?:SET|GET)_PM)\\s+[^\\n]+', text + '\n' + (ROOT / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig'), re.M))
    if 'Ap6256WifiProgramPowerSave' in functions:
        power = functions['Ap6256WifiProgramPowerSave'] + '\nstatic NTSTATUS Ap6256WifiSetPowerSave(Device* d,BOOLEAN e) {return Ap6256WifiProgramPowerSave(d,e,FALSE);}'
        test = TEST
    else:
        power = functions['Ap6256WifiSetPowerSave']
        test = TEST[:TEST.index("    reset(REG_SZ,{'1',0,0,0});getStatus=STATUS_IO_TIMEOUT;")] + '\n}\n'
        power = power.replace('Ap6256BcdcQueryDcmd(Ctx,', 'Ap6256BcdcQueryDcmdCompat(Ctx,')
        power = r'''static NTSTATUS Ap6256BcdcQueryDcmdCompat(Device* d,UINT32 c,PVOID p,ULONG n) {AP6256_BCDC_QUERY_RESULT r;return Ap6256BcdcQueryDcmdResultIf(d,0,c,p,n,&r);}
''' + power
    code = constants + '\n' + PRE + functions['Ap6256WifiConfiguredPowerSave'] + power + test
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf8')
    (vc, inc, lib) = [CONTROL[k] for k in ('VC', 'INC', 'LIB')]
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / n) for n in ('ucrt', 'shared', 'um')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    compiled = subprocess.run(cmd, text=True, capture_output=True)
    write_text(out / 'compile.log', compiled.stdout + compiled.stderr, encoding='utf8')
    compiled.check_returncode()
    ran = subprocess.run([str(out / 'tests.exe')], text=True, capture_output=True)
    write_text(out / 'runtime.log', ran.stdout + ran.stderr, encoding='utf8')
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    report = dict(source=str(source), source_sha256=sha(source), test_sha256=sha(Path(__file__)), cpp_sha256=sha(cpp), exe_sha256=sha(out / 'tests.exe'), exit_code=ran.returncode, expected_failure=False, board_verified=False, boundary=__doc__)
    write_text(out / 'receipt.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(ran.stdout + ran.stderr, end='')
    assert (ran.returncode != 0) == False
if __name__ == '__main__':
    main()
