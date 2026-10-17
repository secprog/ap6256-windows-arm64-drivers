# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute the real Advanced-page decoder and debugger gate with SDK ETW.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, csv, hashlib, importlib.util, io, json, re, subprocess
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('trace_test', ROOT / 'tests/test-production-tracing.py')
trace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(trace)

def verify_inf(path):
    sections = {}
    section = None
    for line in path.read_text(encoding='utf-8-sig').splitlines():
        line = line.split(';', 1)[0].strip()
        if not line:
            continue
        if line.startswith('['):
            section = line.strip('[]').lower()
            sections[section] = []
        elif section:
            sections[section].append(line)
    install = sections['ap6256.install.ntarm64'] if 'ap6256.install.ntarm64' in sections else sections['ap6256.install']
    assert any(('ap6256.ndisreg' in n.lower() and n.lower().startswith('addreg') for n in install))
    characteristic = next((n.split('=', 1)[1].strip() for n in install if n.lower().startswith('characteristics')))
    assert int(characteristic, 0) & 128
    rows = [next(csv.reader(io.StringIO(n), skipinitialspace=True)) for n in sections['ap6256.ndisreg'] if n.lower().startswith('hkr,')]
    values = {(r[1].lower(), r[2].lower()): r[4] for r in rows if len(r) >= 5}
    base = 'ndi\\params\\debugloglevel'
    assert values[base, 'type'] == 'enum' and values[base, 'default'] == '0' and (values[base, 'optional'] == '0')
    assert {(key[1], value) for (key, value) in values.items() if key[0] == base + '\\enum'} == {(str(n), '%' + name + '%') for (n, name) in enumerate(('DebugLogDisabled', 'DebugLogErrors', 'DebugLogWarnings', 'DebugLogInformation', 'DebugLogVerbose'))}
    root = [next(csv.reader(io.StringIO(n), skipinitialspace=True)) for n in sections['ap6256.params.reg'] if 'DebugLogLevel' in n]
    assert len(root) == 1 and root[0][1] == '' and (int(root[0][3], 0) == 0) and (root[0][4] == '0')
    return {'software_instance_key': True, 'default_disabled': True, 'upgrade_selection_preserved': False, 'cleanup_upgrade_resets_to_disabled': True, 'levels': 5}
MOCK = r'''
static std::vector<UCHAR> registry_bytes;static ULONG registry_type,registry_queries;
static NTSTATUS registry_status;static PDEVICE_OBJECT queried_pdo;
static NTSTATUS Ap6256RegQueryValue(PDEVICE_OBJECT pdo,PCWSTR name,ULONG capacity,
    PVOID data,PULONG bytes,PULONG type) {
    assert(!wcscmp(name,L"DebugLogLevel"));++registry_queries;queried_pdo=pdo;
    *bytes=0;*type=REG_NONE;if(!NT_SUCCESS(registry_status))return registry_status;
    if(registry_bytes.size()>capacity)return STATUS_BUFFER_OVERFLOW;
    *bytes=ULONG(registry_bytes.size());*type=registry_type;
    if(*bytes)memcpy(data,registry_bytes.data(),*bytes);return 0;
}
'''
TEST = r'''
static void load(ULONG type,const std::vector<UCHAR>& bytes,NTSTATUS status=0) {
    registry_type=type;registry_bytes=bytes;registry_status=status;
    registry_queries=0;queried_pdo=nullptr;
    Ap6256TraceLoadDebugSettings((PDEVICE_OBJECT)0x1234);
    assert(registry_queries==1 && queried_pdo==(PDEVICE_OBJECT)0x1234);
}
static void check(unsigned mode) {
    unsigned before=debug_calls;
    TraceError(TRACE_DRIVER,"error");TraceWarn(TRACE_DRIVER,"warning");
    TraceInfo(TRACE_DRIVER,"info");TraceVerbose(TRACE_DRIVER,"verbose");TraceDiag("startup");
    TraceData("packet");
    const unsigned counts[]={0,1,2,4,5};
    assert(debug_calls-before==(counts[mode]+(AP6256_TRACE_DATAPATH && mode==4 ? 1u : 0u)));
}
int main() {
    check(0);assert(NT_SUCCESS(Ap6256TraceInitialize()));check(0);
    for(UCHAR mode=0;mode<=4;++mode) {
        load(REG_SZ,{UCHAR('0'+mode),0,0,0});check(mode);
        load(REG_DWORD,{mode,0,0,0});check(mode);
    }
    for(ULONG type:{REG_SZ,REG_DWORD,REG_BINARY,REG_MULTI_SZ,REG_EXPAND_SZ,REG_NONE})
        for(const std::vector<UCHAR>& bytes:{std::vector<UCHAR>{},{0},{0,0},{0,0,0},
            {5,0,0,0},{255,255,255,255},{'9',0,0,0},{'2',1,0,0},{'2',0,'x',0},{'2',0,0,0,0,0}}) {
            load(type,bytes);check(0);
        }
    for(NTSTATUS status:{STATUS_OBJECT_NAME_NOT_FOUND,STATUS_ACCESS_DENIED,STATUS_INSUFFICIENT_RESOURCES,STATUS_BUFFER_OVERFLOW}) {
        load(REG_DWORD,{4,0,0,0},status);check(0);
    }
    load(REG_SZ,{'4',0,0,0});check(4);
    Ap6256TraceLoadDebugSettings(nullptr);check(0);
    load(REG_SZ,{'1',0,0,0});check(1);load(REG_SZ,{'0',0,0,0});check(0);
    Ap6256TraceCleanup();check(0);
    Ap6256TraceSetDebugLevel(0xffffffffu);check(0);
    fail_register=true;assert(!NT_SUCCESS(Ap6256TraceInitialize()));check(0);
    Ap6256TraceCleanup();check(0);
    puts("PASS: Advanced-page strings/DWORDs, invalid/missing/failure defaults, restart reread and all debugger gates");
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--force-windbg', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    infs = {p.name: verify_inf(p) for p in (ROOT / 'inf/ap6256.inf', ROOT / 'inf/ap6256-wificx.inf')}
    write_text(out / 'ntddk.h', trace.SHIM, encoding='utf-8')
    body = re.sub('^#include[^\\n]*', '', (ROOT / 'src/common/debug_settings.c').read_text(encoding='utf-8-sig'), flags=re.M)
    source_root = ROOT
    code = '#include "' + str(ROOT / 'src/common/trace.c').replace('\\', '/') + '"\n' + MOCK + '\n' + body + '\n' + TEST
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    tx = trace.tx
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(out), '/I' + str(tx.VC / 'include')] + ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um', 'km')] + [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib']
    if args.force_windbg:
        command[1:1] = ['/DAP6256_FORCE_WINDBG=1', '/DAP6256_TRACE_DATAPATH=1']
    write_text(out / 'compile-command.json', json.dumps(command, indent=2) + '\n', encoding='utf-8')
    result = subprocess.run(command, capture_output=True, text=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        print(result.stdout + result.stderr)
        raise SystemExit(result.returncode)
    run = subprocess.run([str(out / 'tests.exe')], capture_output=True, text=True)
    write_text(out / 'run.log', run.stdout + run.stderr, encoding='utf-8')
    receipt = {'passed': run.returncode == 0, 'exit_code': run.returncode, 'expected_failure': bool(None), 'infs': infs, 'board_verified': False, 'forced_windbg': False, 'retired_force_macro_attempted': args.force_windbg, 'packet_trace_enabled': args.force_windbg, 'fixtures': ['registry transport', 'kernel IRQL/debugger', 'ETW system calls'], 'source_sha256': {n: hashlib.sha256((source_root / n).read_bytes()).hexdigest() for n in ('src/common/debug_settings.c', 'src/common/trace.c', 'src/common/trace.h', 'inf/ap6256.inf', 'inf/ap6256-wificx.inf')}, 'test_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
    print(run.stdout + run.stderr)
    raise SystemExit(run.returncode)
if __name__ == '__main__':
    main()
