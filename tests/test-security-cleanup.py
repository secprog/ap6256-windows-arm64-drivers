# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Run production PMF flag calculations and key-cleanup ordering.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, struct, subprocess, sys, zipfile
AP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('control', AP / 'tests/test-control-retry.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
MOCK = r'''
static UINT32 mock_wsec;
static NTSTATUS get_status,set_status,key_status;
static std::vector<std::string> operations;
static BOOLEAN Ap6256HostCipherStoreActive(decltype(Device::HostCipherStore)* s,UINT32){return s->Configured;}
static BOOLEAN Ap6256FipsActive(Device* d,UINT32){return d->Fips;}
static NTSTATUS remove_key(Device* d,ULONG id,BOOLEAN pairwise,BOOLEAN management,const UCHAR* peer){
    operations.emplace_back(std::string("delete:")+(management?"bip":pairwise?"ptk":"gtk"));
    if(NT_SUCCESS(key_status))for(auto& k:d->NativeKeys)if(k.Valid&&k.KeyId==id&&k.Pairwise==pairwise&&k.Management==management&&!memcmp(k.PeerAddress,peer,6))k.Valid=false;
    return key_status;
}
static NTSTATUS Ap6256WifiDeleteCcmpKeyIf(Device* d,UINT32,ULONG id,BOOLEAN pairwise,const UCHAR* peer){return remove_key(d,id,pairwise,FALSE,peer);}
static NTSTATUS Ap6256WifiDeleteBipKeyIf(Device* d,UINT32,ULONG id,const UCHAR* peer){return remove_key(d,id,FALSE,TRUE,peer);}
static NTSTATUS Ap6256BcdcGetIovar(Device*,PCSTR name,PVOID p,ULONG n) {
    assert(n==4);operations.emplace_back(std::string("get:")+name);
    if(!strcmp(name,"wsec")) { memcpy(p,&mock_wsec,4);return get_status; }
    assert(!strcmp(name,"wme_bss_disable"));*(UINT32*)p=1;return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n) {
    operations.emplace_back(std::string("set:")+name);
    if(!strcmp(name,"wsec")) { assert(n==4);if(NT_SUCCESS(set_status))memcpy(&mock_wsec,p,4);return set_status; }
    if(!strcmp(name,"key_remove_all")) { assert(p==nullptr && n==0);return key_status; }
    if(!strcmp(name,"pmkid_info")) { assert(n==AP6256_PMKID_CLEAR_BYTES);for(ULONG i=0;i<n;++i)assert(((UCHAR*)p)[i]==0);return STATUS_SUCCESS; }
    assert(!strcmp(name,"wme_bss_disable") && n==4 && *(UINT32*)p==0);return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetDcmd(Device*,UINT32 command,const VOID* p,ULONG n) {
    assert(command==BRCMF_C_SET_KEY_PRIMARY && n==4 && *(UINT32*)p==0);
    operations.emplace_back("set:primary-key");return key_status;
}
NTSTATUS Ap6256WifiSetBssWmm(Device*,BOOLEAN);
static void setup(UINT32 value) { mock_wsec=value;get_status=set_status=key_status=STATUS_SUCCESS;operations.clear(); }
'''
TEST = r'''
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    Device c={};
    for(UINT32 v:{0x4u,0x204u,0x604u,0xa04u,0xe04u,0xf4fu,0x400u}) {
        setup(v);assert(Ap6256WifiSetMfpWsecBit(&c,FALSE)==0);
        assert(mock_wsec==(v&~0x600u));
        assert(operations.size()==((v&0x600u)?2u:1u));
        operations.clear();assert(Ap6256WifiSetMfpWsecBit(&c,FALSE)==0);
        assert(operations==std::vector<std::string>({"get:wsec"}));
        setup(v);assert(Ap6256WifiSetMfpWsecBit(&c,TRUE)==0 && mock_wsec==(v|0x200u));
    }
    puts("PASS: production cleanup clears capable/required together, preserves all other bits and avoids redundant writes");
    setup(0xe04);c.NativeKeys[0].Valid=c.NativeKeys[1].Valid=c.NativeKeys[2].Valid=TRUE;
    c.NativeKeys[0].Pairwise=TRUE;c.NativeKeys[1].KeyId=2;c.NativeKeys[2].KeyId=5;c.NativeKeys[2].Management=TRUE;
    assert(Ap6256WifiClearSecurityState(&c)==0&&mock_wsec==0x804);
    assert(operations==std::vector<std::string>({"delete:ptk","delete:gtk","delete:bip","get:wsec","set:wsec","get:wme_bss_disable","set:wme_bss_disable","set:pmkid_info"}));
    puts("PASS: complete production disconnect cleanup keeps key, WMM and PMKID order");
    setup(0xe04);get_status=STATUS_IO_TIMEOUT;assert(Ap6256WifiSetMfpWsecBit(&c,FALSE)==STATUS_IO_TIMEOUT && mock_wsec==0xe04 && operations.size()==1);
    setup(0xe04);set_status=STATUS_CRC_ERROR;assert(Ap6256WifiSetMfpWsecBit(&c,FALSE)==STATUS_CRC_ERROR && mock_wsec==0xe04 && operations.size()==2);
    setup(0xe04);set_status=key_status=STATUS_CRC_ERROR;Ap6256WifiClearSecurityState(&c);
    assert(mock_wsec==0xe04 && operations.back()=="set:pmkid_info");
    puts("PASS: transport failures propagate and best-effort disconnect still completes its later cleanup steps");
}
'''

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source-root', type=Path, default=AP)
    p.add_argument('--output-dir', type=Path, default=output_dir('security-cleanup'))
    a = p.parse_args()
    root = a.source_root.resolve()
    out = a.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    text = control.PRE.split('struct Device {')[0] + '\nstruct Device { struct {BOOLEAN Configured=FALSE;} HostCipherStore;BOOLEAN Fips=FALSE; };typedef Device* PAP6256_DEVICE_CONTEXT;\n'
    import native_key_fixture
    text = native_key_fixture.context(text)
    sources = [root / 'src/common/wifi_ops.c', root / 'src/common/wifi_ops.h', root / 'src/common/sdpcm.h', root / 'src/common/ap6256.h']
    merged = '\n'.join((x.read_text(encoding='utf-8-sig') for x in sources))
    for name in ('WSEC_MFP_CAPABLE', 'WSEC_MFP_REQUIRED', 'AP6256_PMKID_CLEAR_BYTES', 'BRCMF_C_SET_KEY_PRIMARY'):
        text += re.search('^#define ' + name + '\\s+[^\\n]+', merged, re.M)[0] + '\n'
    text += MOCK
    functions = ['Ap6256WifiSetMfpWsecBit', 'Ap6256WifiClearSecurityState', 'Ap6256WifiSetBssWmm']
    for name in functions:
        text += control.function(root, 'common/wifi_ops.c', name)
    source = out / 'tests.cpp'
    write_text(source, text + TEST, encoding='utf-8')
    cmd = [str(control.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/wd4505', '/I' + str(control.VC / 'include')]
    cmd += ['/I' + str(control.INC / x) for x in ('ucrt', 'shared', 'um')]
    cmd += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(control.VC / 'lib/x64'), '/LIBPATH:' + str(control.LIB / 'ucrt/x64'), '/LIBPATH:' + str(control.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2), encoding='utf-8')
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
    result = dict(passed=True, board_verified=False, limits=['PMF flags, key cleanup and transport-error propagation.'])
    result.update(test_sha256=sha(Path(__file__)), source_sha256={str(x.relative_to(root)): sha(x) for x in sources}, compiled_sha256=sha(source), functions=functions, board_modified=False)
    write_text(out / 'receipt.json', json.dumps(result, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
