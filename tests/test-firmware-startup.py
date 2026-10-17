# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from test_support import write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

from driver_sources import _functions
from toolchain import VC, INC, LIB

ROOT = Path(__file__).resolve().parents[1]

PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <string>
typedef LONG NTSTATUS;
#pragma warning(disable:4505)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TraceDiag(...) ((void)0)
#define TraceError(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define AP6256_POOL_TAG 0
#define POOL_FLAG_NON_PAGED 0
#define AP6256_FW_IMAGE_NAME L"synthetic"
#define AP6256_FW_IMAGE_NAME_CY L"synthetic"
#define AP6256_FW_NVRAM_NAME L"synthetic-nvram"
#define AP6256_FW_NVRAM_NAME_CY L"synthetic-nvram"
#define AP6256_FW_RTECDC_SUFFIX L"synthetic"
#define AP6256_FW_NVRAM_SUFFIX L"synthetic-nvram"
#define AP6256_FW_MAX_SIZE (1024u*1024u)
#define AP6256_NVRAM_MAX_SIZE (32u*1024u)
enum {Ap6256FwDownloading,Ap6256FwRunning,Ap6256FwError};
struct Device {
    struct {UINT32 RamBase=0x10000,RamSize=4096;} Chip;
    int FirmwareState=Ap6256FwError;
    BOOLEAN FirmwareEnhancedPnoSupported=TRUE,FirmwarePnoDelaySupported=TRUE;
    BOOLEAN FirmwarePnoGscanSupported=TRUE,FirmwareNativeManagement=TRUE;
    BOOLEAN FirmwareSaePatchVerified=TRUE,FirmwareExternalAuth=TRUE;
    BOOLEAN FirmwarePrivateSaeAbi=TRUE,FirmwarePrivateSae=TRUE;
    BOOLEAN FirmwareHostFt=TRUE,FirmwareFtPatchVerified=TRUE;
    BOOLEAN FirmwareOwePatchVerified=TRUE,FirmwareHostOwe=TRUE;
    BOOLEAN FirmwareServicePatchVerified=TRUE,FirmwareServiceOffload=TRUE;
    BOOLEAN FirmwareFtmPatchVerified=TRUE,FirmwareFtmSupported=TRUE;
    BOOLEAN FirmwareHostCipherPatchVerified=TRUE,FirmwareBssTransitionEnabled=TRUE;
    UINT32 FirmwareOweGeneration=99,FirmwareOweNextGeneration=100;
    UCHAR FirmwareOwePeer[6]={2,1,2,3,4,5};
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static std::map<PVOID,size_t> pools;
static std::vector<UCHAR> image,raw,ram;
static std::vector<std::string> events;
static std::string fail;
static NTSTATUS failure;
static unsigned mask,allocations,failAllocation,writes,starts,readBeforeStart,checks;
static bool held,started;
static NTSTATUS event(const char* name) {events.emplace_back(name);return fail==name?failure:0;}
static PUCHAR ExAllocatePool2(int,size_t bytes,int) {
    if(++allocations==failAllocation)return nullptr;
    PUCHAR p=(PUCHAR)calloc(1,bytes);assert(p);pools[p]=bytes;return p;
}
static VOID ExFreePoolWithTag(PVOID p,int) {assert(pools.erase(p)==1);free(p);}
static NTSTATUS Ap6256LoadArtifact(Device*,PCWSTR name,PCWSTR,PCWSTR*,ULONG,ULONG,PUCHAR* p,PULONG n) {
    bool firmware=!wcscmp(name,L"DongleImagePath");NTSTATUS s=event(firmware?"image":"nvram");
    if(!NT_SUCCESS(s))return s;
    const auto& data=firmware?image:raw;*n=(ULONG)data.size();
    *p=ExAllocatePool2(0,data.size()?data.size():1,0);
    if(!*p)return STATUS_INSUFFICIENT_RESOURCES;
    if(data.size())memcpy(*p,data.data(),data.size());return 0;
}
static VOID Ap6256QualityResetFirmware(Device*) {assert(event("quality")==0);}
static VOID Ap6256HostCipherFirmwareRetire(Device*) {assert(event("retire")==0);}
static VOID Ap6256FipsReset(Device*) {assert(event("fips")==0);}
static BOOLEAN Ap6256StatusIsVolumeGone(NTSTATUS) {return FALSE;}
static VOID Ap6256PnoIdentify(Device* d,PUCHAR,ULONG) {d->FirmwareEnhancedPnoSupported=TRUE;events.emplace_back("identify");}
static NTSTATUS prepare(unsigned index,PUCHAR* p,PULONG n,BOOLEAN* patched) {
    NTSTATUS s=event(("prepare-"+std::to_string(index)).c_str());if(!NT_SUCCESS(s))return s;
    *patched=!!(mask&(1u<<index));
    if(index<2||!*patched)return 0;
    PUCHAR grown=ExAllocatePool2(0,*n+4,0);if(!grown)return STATUS_INSUFFICIENT_RESOURCES;
    memcpy(grown,*p,*n);memset(grown+*n,(int)index,4);ExFreePoolWithTag(*p,0);*p=grown;*n+=4;return 0;
}
static NTSTATUS Ap6256PrepareNativeManagement(Device*,PUCHAR p,ULONG n,BOOLEAN* flag){return prepare(0,&p,&n,flag);}
static NTSTATUS Ap6256PnoPrepareInitialDelay(Device*,PUCHAR p,ULONG n,BOOLEAN* flag){return prepare(1,&p,&n,flag);}
static NTSTATUS Ap6256PrepareSae(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(2,p,n,flag);}
static NTSTATUS Ap6256PrepareFt(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(3,p,n,flag);}
static NTSTATUS Ap6256PrepareOwe(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(4,p,n,flag);}
static NTSTATUS Ap6256PrepareService(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(5,p,n,flag);}
static NTSTATUS Ap6256PrepareFtm(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(6,p,n,flag);}
static NTSTATUS Ap6256PrepareHostCiphers(Device*,PUCHAR* p,PULONG n,BOOLEAN* flag){return prepare(7,p,n,flag);}
static NTSTATUS Ap6256ChipSetPassive(Device*){NTSTATUS s=event("passive");if(NT_SUCCESS(s))held=true;return s;}
static NTSTATUS Ap6256SdioRamRW(Device* d,BOOLEAN write,UINT32 address,PUCHAR p,ULONG n) {
    if(!write){if(!started)++readBeforeStart;return STATUS_IO_DEVICE_ERROR;}
    assert(held&&!started&&address>=d->Chip.RamBase&&size_t(address-d->Chip.RamBase)+n<=ram.size());
    NTSTATUS s=event(writes++==0?"write-image":"write-nvram");if(!NT_SUCCESS(s))return s;
    memcpy(ram.data()+address-d->Chip.RamBase,p,n);return 0;
}
static NTSTATUS Ap6256SdioWriteBackplane32(Device* d,UINT32 address,UINT32 token) {
    assert(held&&!started&&address==d->Chip.RamBase+d->Chip.RamSize-4);
    assert((UINT16)token==(UINT16)(~token>>16));return event("token");
}
static NTSTATUS Ap6256ChipSetActive(Device*,UINT32 reset) {
    assert(held&&reset==*(const UINT32*)image.data());++starts;
    NTSTATUS s=event("active");if(NT_SUCCESS(s)){held=false;started=true;}return s;
}
static NTSTATUS Ap6256WaitForShared(Device*){assert(started);return event("shared");}
static NTSTATUS Ap6256SdioEnableBackplaneClock(Device*,BOOLEAN enabled){assert(started&&enabled);return event("clock");}
'''

TEST = r'''
static void reset() {
    assert(pools.empty());ram.assign(4096,0xcc);image.assign(128,0x5a);
    const char nv[]="boardrev=1\n# synthetic test input\nmacaddr=02:01:02:03:04:05\n";
    raw.assign(nv,nv+sizeof(nv)-1);events.clear();fail.clear();mask=255;
    failure=STATUS_IO_DEVICE_ERROR;allocations=failAllocation=writes=starts=readBeforeStart=0;held=started=false;
}
static void verify(const Device& d,bool ok) {
    assert(pools.empty()&&readBeforeStart==0);
    const BOOLEAN flags[]={d.FirmwareNativeManagement,d.FirmwarePnoDelaySupported,d.FirmwareSaePatchVerified,
        d.FirmwareFtPatchVerified,d.FirmwareOwePatchVerified,d.FirmwareServicePatchVerified,
        d.FirmwareFtmPatchVerified,d.FirmwareHostCipherPatchVerified};
    for(unsigned i=0;i<8;++i)assert(!!flags[i]==(ok&&!!(mask&(1u<<i))));
    assert(d.FirmwareState==(ok?Ap6256FwRunning:Ap6256FwError));
    assert(!d.FirmwarePnoGscanSupported&&!d.FirmwarePrivateSaeAbi&&!d.FirmwarePrivateSae&&!d.FirmwareExternalAuth);
    assert(!d.FirmwareHostFt&&!d.FirmwareHostOwe&&!d.FirmwareServiceOffload&&!d.FirmwareFtmSupported);
    assert(!d.FirmwareOweGeneration&&!d.FirmwareOweNextGeneration&&!d.FirmwareBssTransitionEnabled);
    for(UCHAR byte:d.FirmwareOwePeer)assert(!byte);
    ++checks;
}
static void recover() {reset();Device d;assert(Ap6256FirmwareDownload(&d)==0);verify(d,true);}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    for(unsigned flags=0;flags<256;++flags){reset();mask=flags;Device d;assert(Ap6256FirmwareDownload(&d)==0);verify(d,true);assert(starts==1&&writes==2);}
    const unsigned goodAllocations=allocations;
    const std::vector<std::string> expected={"quality","retire","fips","image","nvram","identify",
        "prepare-0","prepare-1","prepare-2","prepare-3","prepare-4","prepare-5","prepare-6","prepare-7",
        "passive","write-image","write-nvram","token","active","shared","clock"};
    assert(events==expected);
    for(const char* stage:{"image","nvram","prepare-0","prepare-1","prepare-2","prepare-3","prepare-4",
        "prepare-5","prepare-6","prepare-7","passive","write-image","write-nvram","token","active","shared","clock"}) {
        for(NTSTATUS status:{STATUS_IO_DEVICE_ERROR,STATUS_INSUFFICIENT_RESOURCES,STATUS_NOT_SUPPORTED}) {
            reset();fail=stage;failure=status;Device d;assert(Ap6256FirmwareDownload(&d)==status);verify(d,false);
            assert(events.back()==stage);recover();
        }
    }
    for(unsigned at=1;at<=goodAllocations;++at){reset();failAllocation=at;Device d;assert(Ap6256FirmwareDownload(&d)==STATUS_INSUFFICIENT_RESOURCES);verify(d,false);recover();}
    for(unsigned bytes:{0u,3u,4097u}){reset();image.resize(bytes);Device d;assert(Ap6256FirmwareDownload(&d)==STATUS_INVALID_IMAGE_FORMAT);verify(d,false);assert(!starts);recover();}
    reset();{Device d;d.Chip.RamBase=0xfffffff0u;assert(Ap6256FirmwareDownload(&d)==STATUS_DEVICE_CONFIGURATION_ERROR);verify(d,false);assert(!starts);}recover();
    reset();image.resize(4092);{Device d;mask=0;assert(Ap6256FirmwareDownload(&d)==STATUS_INVALID_IMAGE_FORMAT);verify(d,false);assert(!starts);}recover();
    reset();raw.resize(5000,'x');{Device d;assert(Ap6256FirmwareDownload(&d)==STATUS_INVALID_IMAGE_FORMAT);verify(d,false);assert(!starts);}recover();
    printf("PASS: %u startup ordering, allocation/write failures, flag publication and recovery cases\n",checks);
}
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    path = ROOT / 'src/common/firmware.c'
    functions = _functions(path.read_text(encoding='utf-8-sig'))
    original = functions['Ap6256FirmwareDownload']
    variants = [('current', original),
                ('readback-control', original.replace('    status = Ap6256ChipSetActive(Ctx, resetVector);',
                  '    (void)Ap6256SdioRamRW(Ctx, FALSE, Ctx->Chip.RamBase, fw, 4);\n    status = Ap6256ChipSetActive(Ctx, resetVector);')),
                ('cleanup-control', original.replace('    Ctx->FirmwareNativeManagement = FALSE;', ''))]
    results = []
    for name, function in variants:
        assert name == 'current' or function != original
        folder = args.output / name
        folder.mkdir()
        cpp = folder / 'test.cpp'
        write_text(cpp, PRE + functions['Ap6256NvramStrip'] + function + TEST, encoding='utf-8')
        command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(VC / 'include')]
        command += ['/I' + str(INC / item) for item in ('ucrt', 'shared', 'um')]
        command += [str(cpp), '/Fe:' + str(folder / 'test.exe'), '/Fo:' + str(folder / 'test.obj'), '/link',
                    '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
        compiled = subprocess.run(command, capture_output=True)
        write_bytes(folder / 'compile.log', compiled.stdout + compiled.stderr)
        if compiled.returncode:
            print((compiled.stdout + compiled.stderr).decode(errors='replace'))
            compiled.check_returncode()
        run = subprocess.run([str(folder / 'test.exe')], capture_output=True)
        output = run.stdout + run.stderr
        write_bytes(folder / 'run.log', output)
        if name == 'current':
            print(output.decode(errors='replace'), end='')
            run.check_returncode()
        else:
            assert run.returncode != 0 and b'Assertion failed' in output, output
            witness = b'readBeforeStart==0' if name == 'readback-control' else b'flags[i]'
            assert witness in output, output
        results.append(dict(name=name, exit_code=run.returncode, passed=True))
    report = dict(passed=True, board_verified=False, cases=results,
                  source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  boundary='Download ordering, NVRAM conversion, flag publication and failure recovery.')
    write_text(args.output / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
