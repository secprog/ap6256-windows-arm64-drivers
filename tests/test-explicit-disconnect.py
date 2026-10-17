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
import re
import subprocess
from driver_sources import _functions
from wdi_test_support import contract_preamble
AP = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, AP / 'tests' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
MOCKS = r'''
#define KernelMode 0
#define AP6256_WLFC_ANY 255u
static UINT32 mock_wsec=0xe04;
static unsigned grace,legacy_requests;
static NTSTATUS departure_status,fallback_status,delay_status,raw_status;
static bool raw_handled,event_during_command;
static void Ap6256WlfcCancel(Device*,UINT32 port,UINT32 scope,void* p){assert(port==0&&scope==255&&!p);}
static BOOLEAN Ap6256HostCipherStoreActive(decltype(Device::HostCipherStore)* s,UINT32 i){assert(i==0);return s->Configured;}
static NTSTATUS Ap6256HostCipherDisconnect(Device*,UINT32 i,const UCHAR*,UINT32,BOOLEAN* handled){assert(i==0);*handled=(BOOLEAN)raw_handled;return raw_status;}
static NTSTATUS Ap6256HostCipherEnd(Device*,UINT32 i,BOOLEAN keep){assert(i==0&&!keep);return 0;}
static NTSTATUS Ap6256FipsRetire(Device*,UINT32 i){assert(i==0);return 0;}
static NTSTATUS Ap6256NativeDeparture(Device*,const UCHAR*,UINT32,BOOLEAN* handled){*handled=FALSE;return 0;}
static NTSTATUS Ap6256BcdcSetDcmd(Device* d,UINT32 command,const VOID* p,ULONG n){
    if(command==BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON){
        assert(n==12&&((const BRCMF_SCB_VAL*)p)->Value==3);
        assert(!memcmp(((const BRCMF_SCB_VAL*)p)->Address,peer,6));
        if(NT_SUCCESS(departure_status)){pendingRadioFrame=true;if(event_during_command)d->FirmwareLinkUp=false;}
        return departure_status;
    }
    if(command==BRCMF_C_DISASSOC){assert(!p&&!n);if(NT_SUCCESS(fallback_status))pendingRadioFrame=true;return fallback_status;}
    if(command==BRCMF_C_SET_KEY_PRIMARY){assert(n==4);++legacy_requests;return STATUS_INVALID_PARAMETER;}
    assert(command==BRCMF_C_SCB_DEAUTHORIZE&&n==6);
    if(departing&&(!grace||pendingRadioFrame))badOrder=true;
    return Ap6256BcdcSetDcmdIf(d,0,command,p,n);
}
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER* delay){
    assert(mode==0&&!alert&&delay->QuadPart==-5000000LL&&pendingRadioFrame);
    assert((mock_wsec&0x600)==0x600&&installed.size()>=3);++grace;
    if(delay_status==0)pendingRadioFrame=false;
    return delay_status;
}
static NTSTATUS Ap6256BcdcGetIovar(Device*,PCSTR name,PVOID p,ULONG n){
    assert(n==4);
    if(!strcmp(name,"wsec")){*(UINT32*)p=mock_wsec;return 0;}
    assert(!strcmp(name,"wme_bss_disable"));*(UINT32*)p=0;return 0;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n){
    if(!strcmp(name,"key_remove_all")){assert(!p&&!n);++legacy_requests;return STATUS_NOT_SUPPORTED;}
    if(!strcmp(name,"wsec")){assert(n==4);if(pendingRadioFrame)badOrder=true;mock_wsec=*(const UINT32*)p;return 0;}
    if(!strcmp(name,"pmkid_info")){assert(n==AP6256_PMKID_CLEAR_BYTES);return 0;}
    assert(!strcmp(name,"wme_bss_disable")&&n==4);return 0;
}
'''
SETUP = r'''
static unsigned tracked(Device& d){unsigned n=0;for(auto& k:d.NativeKeys)n+=!!k.Valid;return n;}
static void setup(Device& d){
    d={};d.FirmwareLinkUp=d.SupplicantComplete=true;mock_wsec=0xe04;grace=legacy_requests=0;
    departure_status=fallback_status=delay_status=raw_status=0;raw_handled=false;event_during_command=true;
    pendingRadioFrame=departing=badOrder=false;eapolBarrierStatus=0;eapolBarrierCalls=0;
    fail_id=-1;fail_delete=fail_command=fail_iovar=false;calls.clear();installed.clear();seeds.clear();
    authorizations=deauthorizations=0;
}
static AP6256_CCMP_KEY data_key(ULONG id,BOOLEAN pairwise,UINT32 iface=0){
    AP6256_CCMP_KEY k={};k.KeyId=id;k.Pairwise=pairwise;k.IfIndex=iface;
    memcpy(k.PeerAddress,peer,6);memset(k.Key,0x5a,16);return k;
}
static void keys(Device& d){
    auto p=data_key(0,TRUE);assert(Ap6256WifiAddCcmpKey(&d,&p)==0);
    auto g=data_key(2,FALSE);assert(Ap6256WifiAddCcmpKey(&d,&g)==0);
    AP6256_BIP_KEY b={};b.KeyId=5;b.KeyLength=16;memset(b.Key,0x6a,16);assert(Ap6256WifiAddBipKey(&d,&b)==0);
    auto other=data_key(1,FALSE,1);assert(Ap6256WifiAddCcmpKey(&d,&other)==0);
    assert(tracked(d)==3&&installed.size()==4&&d.NativeKeyLock==0);
}
'''
MAIN = r'''
int main(){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);Device d={};
    setup(d);keys(d);departing=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0);
    assert(grace==1&&!badOrder&&!pendingRadioFrame&&!d.NativeDeparturePending&&!d.FirmwareLinkUp);
    assert(!tracked(d)&&installed.size()==1&&installed.begin()->first.rfind("1:",0)==0);
    assert(mock_wsec==0x804&&!legacy_requests&&d.NativeKeyLock==0);
    puts("PASS: production reason-preserving departure drains before deauthorization, key removal and PMF change despite immediate link-down; foreign interface retained");
    setup(d);keys(d);departing=true;departure_status=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&grace==1&&!badOrder&&!tracked(d)&&!legacy_requests);
    setup(d);keys(d);departing=true;departure_status=fallback_status=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&!grace&&tracked(d)==3&&mock_wsec==0xe04);
    assert(!d.NativeDeparturePending&&d.NativeKeyLock==0);
    puts("PASS: native fallback drains; failed departure preserves keys and PMF");
    for(auto failure:{STATUS_IO_TIMEOUT,(NTSTATUS)0x101}){
        setup(d);keys(d);departing=true;delay_status=failure;
        assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&d.NativeDeparturePending&&tracked(d)==3&&mock_wsec==0xe04);
        auto count=calls.size();assert(Ap6256WifiHasNativeKeys(&d));
        assert(Ap6256WifiClearSecurityState(&d)==STATUS_DEVICE_BUSY&&calls.size()==count);
        auto key=data_key(0,TRUE);assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_DEVICE_BUSY&&calls.size()==count);
        assert(Ap6256WifiDeleteCcmpKeyIf(&d,0,0,TRUE,peer)==STATUS_DEVICE_BUSY&&calls.size()==count);
        delay_status=0;assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0&&!tracked(d)&&!d.NativeDeparturePending&&!badOrder);
    }
    puts("PASS: interrupted drain blocks cleanup, new keys and reconnect admission until a successful retry");
    setup(d);keys(d);departing=true;fail_delete=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&tracked(d)==3&&mock_wsec==0xe04&&!d.NativeDeparturePending&&!badOrder);
    fail_delete=false;assert(Ap6256WifiClearSecurityState(&d)==0&&!tracked(d)&&installed.size()==1&&mock_wsec==0x804);
    assert(Ap6256WifiClearSecurityState(&d)==0&&!legacy_requests&&d.NativeKeyLock==0);
    puts("PASS: partial cleanup failures retain metadata and PMF, propagate failure, and retry without touching foreign keys");
    setup(d);auto k=data_key(0,TRUE);fail_command=fail_iovar=true;
    assert(Ap6256WifiAddCcmpKey(&d,&k)==STATUS_IO_TIMEOUT&&!tracked(d));
    fail_command=false;fail_iovar=false;
    for(unsigned i=0;i<AP6256_NATIVE_KEY_SLOTS;i++){k.PeerAddress[5]=(UCHAR)(i+1);assert(Ap6256WifiAddCcmpKey(&d,&k)==0);}
    auto count=calls.size();k.PeerAddress[5]=100;
    assert(Ap6256WifiAddCcmpKey(&d,&k)==STATUS_INSUFFICIENT_RESOURCES&&calls.size()==count&&tracked(d)==AP6256_NATIVE_KEY_SLOTS);
    k.PeerAddress[5]=1;assert(Ap6256WifiAddCcmpKey(&d,&k)==0&&tracked(d)==AP6256_NATIVE_KEY_SLOTS);
    assert(Ap6256WifiDeleteCcmpKeyIf(&d,0,0,TRUE,k.PeerAddress)==0&&tracked(d)==AP6256_NATIVE_KEY_SLOTS-1);
    Ap6256WifiForgetNativeKeys(&d);assert(!Ap6256WifiHasNativeKeys(&d)&&!tracked(d)&&!d.NativeKeyLock);
    puts("PASS: failed writes are not remembered, key identity/replacement/deletion is bounded, full inventory rejects before firmware I/O, and firmware reset forgets metadata");
    setup(d);keys(d);raw_handled=true;raw_status=STATUS_IO_TIMEOUT;d.HostCipherStore.Configured=true;
    count=calls.size();assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==STATUS_IO_TIMEOUT&&!grace&&calls.size()==count&&tracked(d)==3&&mock_wsec==0xe04);
    assert(Ap6256WifiClearSecurityState(&d)==STATUS_NOT_SUPPORTED&&calls.size()==count);
    puts("PASS: raw host-cipher ownership never falls back to native departure or cleanup");
}
'''
NEGATIVE = r'''
int main(){
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);Device d={};setup(d);keys(d);departing=true;
    assert(Ap6256WifiDisconnectWithReason(&d,peer,3)==0);
    assert(badOrder&&!grace&&legacy_requests==2&&pendingRadioFrame&&tracked(d)==3);
    puts("EXPECTED-REGRESSION: frozen historical deauthorizes before departure, omits the drain, and issues unsupported cleanup before PMF removal");
    return 17;
}
'''

def fixture(negative=False):
    keys = module('test-cipher-keys')
    source = keys.build_source()
    assert source.endswith(keys.TEST)
    source = source[:-len(keys.TEST)]
    source = re.sub('\\bzero\\b', 'key_zero_address', source)
    source = 'static bool pendingRadioFrame=false,departing=false,badOrder=false;\n' + source
    source = source.replace('struct Device {', r'''struct Device {
BOOLEAN FirmwareLinkUp=FALSE,SupplicantComplete=FALSE,ConnectionRequiresSupplicant=FALSE;struct {BOOLEAN Configured=FALSE;} HostCipherStore;''')
    anchor = 'assert(n==164);bool deleting=le32(p+4)==0;'
    assert source.count(anchor) == 1
    source = source.replace(anchor, 'assert(n==164);if(pendingRadioFrame)badOrder=true;bool deleting=le32(p+4)==0;')
    ctx = (AP / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    sd = (AP / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    ops = (AP / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig')
    tx = module('test-wdi-transmit')
    source += tx.declaration(ops, 'BRCMF_SCB_VAL') + '\n'
    for name in ('BRCMF_C_DISASSOC', 'BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON', 'BRCMF_C_SET_KEY_PRIMARY', 'AP6256_PMKID_CLEAR_BYTES', 'WSEC_MFP_CAPABLE', 'WSEC_MFP_REQUIRED'):
        source += re.search('^#define ' + name + '\\s+[^\\n]+', ctx + '\n' + sd + '\n' + ops, re.M)[0] + '\n'
    source += MOCKS
    current = _functions(ops)
    for name in ('Ap6256WifiHasNativeKeys', 'Ap6256WifiForgetNativeKeys', 'Ap6256WifiSetMfpWsecBit', 'Ap6256WifiSetBssWmm'):
        source += current[name] + '\n'
    table = current
    for name in ('Ap6256WifiClearSecurityState', 'Ap6256WifiDisconnectWithReason'):
        source += table[name] + '\n'
    return source + SETUP + MAIN

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output-dir', type=Path, required=True)
    args = parser.parse_args()
    tx = module('test-wdi-transmit')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    records = []
    for (name, negative) in (('current', False),):
        folder = args.output_dir / name
        folder.mkdir(exist_ok=True)
        cpp = folder / 'test.cpp'
        write_text(cpp, contract_preamble() + fixture(False), encoding='utf-8')
        exe = folder / 'test.exe'
        cmd = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(tx.VC / 'include')]
        cmd += ['/I' + str(tx.INC / s) for s in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
        cmd += [str(cpp), '/Fe:' + str(exe), '/Fo:' + str(folder / 'test.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib', str(tx.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
        build = subprocess.run(cmd, capture_output=True)
        write_bytes(folder / 'compile.log', build.stdout + build.stderr)
        if build.returncode:
            print((build.stdout + build.stderr).decode(errors='replace'))
            build.check_returncode()
        run = subprocess.run([str(exe)], capture_output=True)
        write_bytes(folder / 'run.log', run.stdout + run.stderr)
        print((run.stdout + run.stderr).decode(errors='replace'), end='')
        assert run.returncode == 0, run.returncode
        records.append(dict(case=name, exit_code=run.returncode))
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    paths = ['src/common/wifi_ops.c', 'src/common/wifi_ops.h', 'src/common/ap6256.h', 'src/common/device.c', 'src/wdi/ndis_miniport.c', 'src/common/kmdf_driver.c']
    write_text(args.output_dir / 'result.json', json.dumps(dict(passed=True, board_verified=False, records=records, source_sha256={p: sha(AP / p) for p in paths}, test_sha256=sha(Path(__file__)), limits='Disconnect ordering, key inventory, key writers/deleters, PMF flags and cleanup.'), indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
