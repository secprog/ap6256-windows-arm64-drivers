# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise production BCDC negotiation through SDPCM with injected bus CRCs.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
from pathlib import Path
import argparse
import json
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
PRE = r'''
#define Ap6256TraceInformationEnabled(Category) TRUE
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <vector>
#include <string>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define MAXULONG 0xffffffffUL
#define POOL_FLAG_NON_PAGED 0
#define AP6256_POOL_TAG 0
#define KernelMode 0
#define Executive 0
#define IO_NO_INCREMENT 0
typedef int KIRQL;
static void KeAcquireSpinLock(int* l, KIRQL* i) { assert(!*l); *l=1; *i=0; }
static void KeReleaseSpinLock(int* l, KIRQL) { assert(*l); *l=0; }
static void Ap6256LockAcquire(int* l) { assert(!*l); *l=1; }
static void Ap6256LockRelease(int* l) { assert(*l); *l=0; }
static void KeSetEvent(int* e, int, BOOLEAN) { *e=1; }
static void KeClearEvent(int* e) { *e=0; }
static unsigned waits, delays, allocations;
static NTSTATUS KeWaitForSingleObject(int* e, int, int, BOOLEAN, LARGE_INTEGER* t) {
    assert(t->QuadPart == -50000000); ++waits;
    return *e ? STATUS_SUCCESS : STATUS_TIMEOUT;
}
static PVOID ExAllocatePool2(int, size_t n, int) { ++allocations; return calloc(1,n); }
static void ExFreePoolWithTag(PVOID p, int) { assert(allocations); --allocations; free(p); }
static NTSTATUS RtlStringCbLengthA(PCSTR p, size_t n, size_t* out) {
    *out=strnlen(p,n); return *out<n ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}
static std::vector<std::string> logs;
static void trace(const char* f, ...) {
    char b[512]; va_list a; va_start(a,f); vsnprintf(b,sizeof(b),f,a); va_end(a); logs.emplace_back(b);
}
#define TraceDiag(...) trace("DIAG " __VA_ARGS__)
#define TraceError(t,...) trace("ERR " __VA_ARGS__)
#define TraceWarn(t,...) trace("WARN " __VA_ARGS__)
#define TraceVerbose(t,...) trace("VERBOSE " __VA_ARGS__)
#define TraceInfo(t,...) trace("INFO " __VA_ARGS__)
struct Device {
    volatile LONG HostTxQuiesced=0,FirmwareIoQuiesced=0;
    PVOID PowerThread=nullptr;
    struct {
        BOOLEAN Sleeping=FALSE;
        BOOLEAN TxGlom, TxFlowStopped; UCHAR FlowControl; UINT8 MaxTxSeq, TxSeq;
        int TxLock, TxStateLock; LONG64 StatTxFrames;
        ULONG Function2BlockSize, TxGlomBytes, MaxTransferBytes[3], MaxBlocksPerCmd53;
    } Sdio;
    struct {
        int Lock, ResponseLock, ResponseEvent; ULONG RequestId;
        PUCHAR IoctlBuffer, ResponseBuffer; ULONG IoctlBufferSize, ResponseBufferSize, ResponseLength;
        NTSTATUS ResponseStatus; BOOLEAN Pending, Initialized; UINT16 PendingId;
        UINT32 PendingCommand; UCHAR PendingIfIndex; BOOLEAN PendingSet; CHAR PendingIovar[32];
    } Bcdc;
    BOOLEAN DatapathRunning; ULONG TxScratchSize; volatile LONG FirmwareHalted;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static PVOID KeGetCurrentThread(){return (PVOID)1;}
static BOOLEAN configured=TRUE;
static BOOLEAN Ap6256TxGlomConfigured(Device*) { return configured; }
static ULONG Ap6256TxGlomBytesConfigured(Device*) { return 32768; }
'''
MOCKS = r'''
VOID Ap6256BcdcProcessControlFrame(Device*, PUCHAR, ULONG);
static std::vector<NTSTATUS> write_results;
static std::vector<std::vector<UCHAR>> writes;
static std::vector<char> operations;
static unsigned terminations, firmware_commands, grant_at, stop_at;
static bool reply, firmware_error, stop_on_failure;
static Device* waiting_device;
static unsigned rd16(const UCHAR* p) { return p[0] | (unsigned(p[1])<<8); }
static unsigned rd32(const UCHAR* p) { return rd16(p) | (rd16(p+2)<<16); }
static NTSTATUS Ap6256SdioFrameRW(Device* c, BOOLEAN write, PUCHAR p, ULONG n) {
    assert(write && c->Sdio.TxLock && !c->Sdio.TxStateLock && !c->Bcdc.ResponseLock);
    operations.push_back('W'); writes.emplace_back(p,p+n);
    const unsigned hdr=c->Sdio.TxGlom?20:12;
    assert(n>=hdr && (rd16(p)^rd16(p+2))==0xffff);
    const unsigned wire=c->Sdio.TxGlom?(rd32(p+4)&0xffffff)+4:rd16(p);
    assert(p[hdr-8]==c->Sdio.TxSeq && p[hdr-5]==hdr);
    assert(wire<=n);
    if(c->Sdio.TxGlom) {
        assert(rd16(p)==n && rd32(p+4)==((wire-4)|0x1000000));
        assert(rd32(p+8)==((n-wire)<<16));
    }
    for(unsigned i=wire;i<n;++i) assert(p[i]==0);
    NTSTATUS status=writes.size()<=write_results.size()?write_results[writes.size()-1]:STATUS_SUCCESS;
    if(!NT_SUCCESS(status)) {
        if(stop_on_failure) c->DatapathRunning=FALSE;
        return status;
    }
    if(p[hdr-7]==0) {
        assert(c->Bcdc.Lock && c->Bcdc.Pending);
        assert(wire==hdr+16+15 && rd32(p+hdr)==263 && rd32(p+hdr+4)==15);
        assert(rd32(p+hdr+8)==((c->Bcdc.RequestId<<16)|2));
        assert(!memcmp(p+hdr+16,"bus:rxglom\0\1\0\0\0",15));
        ++firmware_commands;
        if(reply) {
            BCDC_DCMD_HEADER answer={263,15,(c->Bcdc.RequestId<<16)|(firmware_error?1u:0u),firmware_error?UINT32(-23):0u};
            Ap6256BcdcProcessControlFrame(c,(PUCHAR)&answer,sizeof(answer));
        }
    }
    return status;
}
static VOID Ap6256SdioTxFail(Device* c) {
    assert(c->Sdio.TxLock && !c->Sdio.TxStateLock);
    operations.push_back('T'); ++terminations;
}
static NTSTATUS KeDelayExecutionThread(int, BOOLEAN, LARGE_INTEGER* t) {
    assert(t->QuadPart==-100000 && waiting_device && !waiting_device->Sdio.TxLock);
    ++delays;
    if(delays==grant_at) waiting_device->Sdio.MaxTxSeq=0;
    if(delays==stop_at) waiting_device->DatapathRunning=FALSE;
    return STATUS_SUCCESS;
}
'''
TEST = r'''
static Device setup(bool glom=false) {
    static UCHAR tx[4096], rx[4096];
    assert(!allocations); memset(tx,0,sizeof(tx)); memset(rx,0,sizeof(rx));
    logs.clear(); writes.clear(); operations.clear(); write_results.clear();
    waits=delays=terminations=firmware_commands=grant_at=stop_at=0;
    configured=TRUE; reply=true; firmware_error=stop_on_failure=false; waiting_device=nullptr;
    Device c={}; c.DatapathRunning=TRUE; c.TxScratchSize=40960;
    c.Sdio.TxGlom=BOOLEAN(glom); c.Sdio.Function2BlockSize=512;
    c.Sdio.TxSeq=255; c.Sdio.MaxTxSeq=0; c.Sdio.MaxTransferBytes[2]=32768;
    c.Bcdc.RequestId=40; c.Bcdc.IoctlBuffer=tx; c.Bcdc.IoctlBufferSize=sizeof(tx);
    c.Bcdc.ResponseBuffer=rx; c.Bcdc.ResponseBufferSize=sizeof(rx);
    return c;
}
static NTSTATUS command(Device* c) {
    UINT32 on=1; return Ap6256BcdcSetIovar(c,"bus:rxglom",&on,sizeof(on));
}
static void unlocked(Device* c) {
    assert(!c->Sdio.TxLock && !c->Sdio.TxStateLock && !c->Bcdc.Lock && !c->Bcdc.ResponseLock && !allocations);
    assert(!c->Bcdc.Pending);
}
static bool logged(const char* part) {
    for(const auto& line:logs) if(line.find(part)!=std::string::npos) return true;
    return false;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);

    auto c=setup(); write_results={STATUS_CRC_ERROR,STATUS_SUCCESS};
    assert(Ap6256DatapathEnableTxGlom(&c)==STATUS_SUCCESS);
    assert(c.Sdio.TxGlom && c.Sdio.TxSeq==0 && c.Bcdc.RequestId==41);
    assert(writes.size()==2 && writes[0].size()==44 && writes[0]==writes[1]);
    assert(terminations==1 && operations==std::vector<char>({'W','T','W'}));
    assert(c.Sdio.StatTxFrames==1 && firmware_commands==1 && waits==1);
    assert(logged("DIAG tx glom: on") && Ap6256TxHdrLen(&c)==20); unlocked(&c);
    puts("PASS: captured startup CRC recovers with identical 44-byte command, one request ID/credit, and glom enabled");

    for(bool glom:{false,true}) for(unsigned errors:{0u,1u,2u,3u}) {
        c=setup(glom); write_results.assign(errors,STATUS_CRC_ERROR);
        const NTSTATUS result=command(&c); const bool success=errors<3;
        assert(result==(success?STATUS_SUCCESS:STATUS_CRC_ERROR));
        assert(writes.size()==(success?errors+1:3) && terminations==errors);
        for(const auto& frame:writes) assert(frame==writes[0]);
        assert(c.Sdio.TxSeq==(success?0:255) && c.Sdio.StatTxFrames==(success?1:0));
        assert(c.Bcdc.RequestId==41 && waits==(success?1u:0u));
        assert(firmware_commands==(success?1u:0u));
        assert(rd16(c.Bcdc.IoctlBuffer)==(glom?51u:43u)); unlocked(&c);
    }
    puts("PASS: three-write bound, abort before retries, normal/extended headers restored, sequence wrap and no double accounting");

    for(unsigned mode:{0u,1u,2u}) {
        c=setup(); firmware_error=mode==0; reply=mode!=1;
        if(mode==2) write_results={STATUS_CRC_ERROR,STATUS_CRC_ERROR,STATUS_CRC_ERROR};
        assert(Ap6256DatapathEnableTxGlom(&c)==STATUS_SUCCESS && !c.Sdio.TxGlom);
        assert(writes.size()==(mode==2?3u:1u));
        assert(waits==(mode==2?0u:1u));
        assert(logged("DIAG tx glom:") && !logged("firmware refused")); unlocked(&c);
    }
    c=setup(); reply=false;
    assert(command(&c)==STATUS_IO_TIMEOUT && writes.size()==1 && terminations==0); unlocked(&c);
    puts("PASS: firmware rejection and reply timeout are not replayed; failure retains 12-byte mode and reports negotiation status");

    for(NTSTATUS s:{STATUS_IO_TIMEOUT,STATUS_CANCELLED,STATUS_DEVICE_REMOVED,STATUS_DEVICE_DATA_ERROR}) {
        c=setup(); write_results={s}; assert(command(&c)==s);
        assert(writes.size()==1 && terminations==1 && c.Sdio.TxSeq==255 && waits==0); unlocked(&c);
    }
    c=setup(); stop_on_failure=true; write_results={STATUS_CRC_ERROR};
    assert(command(&c)==STATUS_CRC_ERROR && writes.size()==1 && terminations==1); unlocked(&c);
    for(bool glom:{false,true}) {
        c=setup(glom); c.Sdio.MaxTxSeq=1; write_results={STATUS_CRC_ERROR};
        UCHAR data[64]={}; const ULONG hdr=glom?20:12, wire=hdr+4+14;
        auto hw=(PSDPCM_HW_HEADER)data; hw->FrameLength=UINT16(wire); hw->FrameLengthInverted=UINT16(~wire);
        data[hdr-7]=2; data[hdr-5]=UCHAR(hdr); data[hdr]=0x20;
        assert(Ap6256DatapathSendSdpcm(&c,data,(wire+3)&~3u)==STATUS_CRC_ERROR);
        assert(writes.size()==1 && terminations==1 && c.Sdio.TxSeq==255); unlocked(&c);
    }
    puts("PASS: data frames, non-CRC transport errors and stopped datapath receive no extra writes");

    c=setup(); c.Sdio.MaxTxSeq=255; waiting_device=&c; grant_at=3;
    write_results={STATUS_CRC_ERROR}; assert(command(&c)==STATUS_SUCCESS);
    assert(delays==3 && writes.size()==2 && terminations==1); unlocked(&c);
    c=setup(); c.Sdio.MaxTxSeq=255; waiting_device=&c;
    assert(command(&c)==STATUS_DEVICE_BUSY && delays==150 && writes.empty() && !terminations); unlocked(&c);
    c=setup(); c.Sdio.MaxTxSeq=255; waiting_device=&c; stop_at=1;
    assert(command(&c)==STATUS_DEVICE_NOT_READY && delays==1 && writes.empty()); unlocked(&c);
    c=setup();c.FirmwareIoQuiesced=1;
    assert(command(&c)==STATUS_DEVICE_NOT_READY&&writes.empty());unlocked(&c);
    c.PowerThread=KeGetCurrentThread();assert(command(&c)==STATUS_SUCCESS&&writes.size()==1);unlocked(&c);
    c=setup();c.Sdio.Sleeping=TRUE;
    assert(command(&c)==STATUS_DEVICE_NOT_READY&&writes.empty());unlocked(&c);
    puts("PASS: sleeping traffic is rejected; only the power transition thread may issue controls while quiesced");
    c=setup(); configured=FALSE;
    assert(Ap6256DatapathEnableTxGlom(&c)==STATUS_SUCCESS && !c.Sdio.TxGlom && writes.empty());
    assert(logged("DIAG tx glom: off by registry")); unlocked(&c);
    puts("PASS: delayed/exhausted credit, stop during credit wait and registry opt-out");
}
'''

def declaration(source, name):
    return re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?^\\}[^;]+;', source, re.M)[0] + '\n'

def function(root, file, name):
    source = read_source_text(root / 'src' / file).replace('static __forceinline', 'static')
    matches = list(re.finditer('^(?:static\\s+)?(?:[A-Z][A-Za-z0-9_]*\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{', source, re.M))
    if not matches:
        raise ValueError(name)
    match = matches[-1]
    signature = match[0][:-1].replace('static ', '')
    chunk = source[match.end() - 1:]
    clean = re.sub('//[^\\n]*|/\\*[\\s\\S]*?\\*/|"(?:\\\\.|[^"\\\\])*"', lambda m: ' ' * len(m[0]), chunk)
    depth = 0
    for (i, ch) in enumerate(clean):
        depth += (ch == '{') - (ch == '}')
        if depth == 0:
            result = signature + chunk[:i + 1] + '\n'
            if name == 'Ap6256BcdcDcmdWithResult' and 'Ap6256BcdcDcmdTransaction' in source:
                result = function(root, file, 'Ap6256BcdcFirmwareErrorName') + function(root, file, 'Ap6256BcdcDcmdTransaction') + result
            if name == 'Ap6256BcdcGetIovarResultIf' and 'Ap6256BcdcGetIovarInternal' in source:
                result = function(root, file, 'Ap6256BcdcGetIovarInternal') + result
            return result
    raise ValueError(name)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, default=output_dir('control-retry'))
    args = parser.parse_args()
    (root, out) = (args.source_root.resolve(), args.output_dir.resolve())
    out.mkdir(parents=True, exist_ok=True)
    text = PRE
    for (file, pattern) in (('sdpcm.h', '^#define (?:SDPCM_|BCDC_|BRCMF_C_(?:SET|GET)_VAR)[^\\n]+'), ('bcdc.h', '^#define AP6256_BCDC_[^\\n]+'), ('bcdc.c', '^#define BCDC_HDR_LEN[^\\n]+'), ('datapath.h', '^#define AP6256_TX_GLOM_MAX_FRAMES[^\\n]+'), ('datapath.c', '^#define AP6256_(?:TX_GLOM_ROOM|CONTROL_TX_RETRIES)[^\\n]+')):
        text += '\n'.join(re.findall(pattern, read_source_text(root / 'src' / file), re.M)) + '\n'
    text += '#define AP6256_SDIO_FUNC_DATA 2\n#pragma pack(push,1)\n'
    sd = read_source_text(root / 'src/common/sdpcm.h')
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'SDPCM_HW_EXT', 'BCDC_DATA_HEADER', 'BCDC_DCMD_HEADER'):
        text += declaration(sd, name)
    text += '#pragma pack(pop)\n' + MOCKS
    if 'Ap6256RawBcdcTxCurrent' in read_source_text(root / 'src/common/datapath.c'):
        text += read_source_text(root / 'src/common/host_fips_wire.h').replace('#pragma once', '')
        text += r'''
static BOOLEAN Ap6256FipsActive(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256RawTxCurrent(Device*,UINT32,const UCHAR*,ULONG) {return FALSE;}
'''
        text += function(root, 'common/host_cipher_transport.c', 'Ap6256RawBcdcTxCurrent')
    has_reply_evidence = 'Ap6256BcdcDcmdWithResult' in read_source_text(root / 'src/common/bcdc.c')
    if has_reply_evidence:
        text += declaration(read_source_text(root / 'src/common/bcdc.h'), 'AP6256_BCDC_QUERY_RESULT')
    for (file, name) in (('datapath.h', 'Ap6256TxHdrLen'), ('datapath.c', 'Ap6256Align4'), ('datapath.c', 'Ap6256AlignTransfer'), ('datapath.c', 'Ap6256DatapathSendSdpcm'), ('bcdc.c', 'Ap6256BcdcProcessControlFrame'), ('bcdc.c', 'Ap6256BcdcDcmdWithResult'), ('bcdc.c', 'Ap6256BcdcDcmd'), ('bcdc.c', 'Ap6256BcdcSetIovarResultIf'), ('bcdc.c', 'Ap6256BcdcSetIovarIf'), ('bcdc.c', 'Ap6256BcdcSetIovar'), ('datapath.c', 'Ap6256DatapathTxGlomBytes'), ('datapath.c', 'Ap6256DatapathEnableTxGlom')):
        if name == 'Ap6256BcdcDcmdWithResult' and (not has_reply_evidence):
            continue
        if name == 'Ap6256BcdcSetIovarResultIf' and name not in read_source_text(root / 'src/common/bcdc.c'):
            continue
        text += function(root, file, name)
    text += TEST
    source = out / 'tests.cpp'
    write_bytes(source, text.encode())
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / f) for f in ('ucrt', 'shared', 'um')]
    command += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
