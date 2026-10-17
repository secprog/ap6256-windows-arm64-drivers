# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Verify read-only feature queries and raw BCDC GET/SET reply evidence.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('test-control-retry.py'))
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
MOCKS = r'''
VOID Ap6256BcdcProcessControlFrame(Device*, PUCHAR, ULONG);
enum Fault { NoFault, FirmwareError, TransportError, NoReply, WrongId, ShortHeader, Oversize };
static Fault fault;
static unsigned expected_interface;
static UINT32 echoed_length, firmware_status;
static std::vector<UCHAR> answer_payload;
static std::vector<std::string> queries;
static std::vector<UCHAR> selector;
static bool fault_later, fail_allocation;
static bool board_reply_model;
static bool expected_set;
static NTSTATUS Ap6256DatapathSendSdpcm(Device* c, PUCHAR frame, ULONG length) {
    assert(c->Bcdc.Lock && c->Bcdc.Pending && !c->Bcdc.ResponseLock);
    unsigned hdr=c->Sdio.TxGlom?20:12;
    auto sw=(PSDPCM_SW_HEADER)(frame+hdr-SDPCM_SWHDR_LEN);
    auto cmd=(PBCDC_DCMD_HEADER)(frame+hdr);
    assert(sw->ChannelAndFlags==SDPCM_CONTROL_CHANNEL && sw->DataOffset==hdr);
    assert(cmd->Cmd==(expected_set?263u:262u));
    assert(!!(cmd->Flags&BCDC_DCMD_SET)==expected_set);
    assert(((cmd->Flags&BCDC_DCMD_IF_MASK)>>BCDC_DCMD_IF_SHIFT)==expected_interface);
    assert(cmd->Len<=AP6256_BCDC_TX_MAXLEN && hdr+16+cmd->Len<=length);
    const char* name=(const char*)(cmd+1);
    const size_t n=strnlen(name,cmd->Len);
    assert(n<cmd->Len);
    queries.emplace_back(name);
    selector.assign((const UCHAR*)name+n+1,(const UCHAR*)name+cmd->Len);
    Fault current=fault_later && queries.size()<3 ? NoFault : fault;
    if(current==TransportError) return STATUS_DEVICE_REMOVED;
    if(current==NoReply) return STATUS_SUCCESS;
    auto payload=answer_payload;
    UINT32 reply_status=firmware_status,reply_length=echoed_length;
    if(board_reply_model) {



        payload.assign((const UCHAR*)name,(const UCHAR*)name+cmd->Len);
        reply_length=cmd->Len;
        if(queries.back()=="wnm_bsstrans_policy" || queries.back()=="ext_cap") {
            current=FirmwareError;reply_status=UINT32(-23);
        } else {
            const UINT32 value=queries.back()=="rrm"?0x00010833u:0u;
            assert(payload.size()>=sizeof(value));
            memcpy(payload.data(),&value,sizeof(value));
        }
    }
    std::vector<UCHAR> bytes(16+payload.size());
    BCDC_DCMD_HEADER header={expected_set?263u:262u,reply_length,
        (c->Bcdc.RequestId<<16)|(current==FirmwareError?BCDC_DCMD_ERROR:0u),reply_status};
    if(current==WrongId) header.Flags+=1u<<BCDC_DCMD_ID_SHIFT;
    memcpy(bytes.data(),&header,16);
    if(!payload.empty()) memcpy(bytes.data()+16,payload.data(),payload.size());
    if(current==ShortHeader) bytes.resize(8);
    if(current==Oversize) bytes.resize(c->Bcdc.ResponseBufferSize+1);
    Ap6256BcdcProcessControlFrame(c,bytes.data(),ULONG(bytes.size()));
    return STATUS_SUCCESS;
}
static NTSTATUS KeDelayExecutionThread(int, BOOLEAN, LARGE_INTEGER*) { assert(false); return 0; }
'''
TEST = r'''
static Device setup(bool glom=false) {
    assert(!allocations);
    static UCHAR tx[4096],rx[4096];
    memset(tx,0,sizeof(tx));memset(rx,0,sizeof(rx));
    logs.clear();queries.clear();selector.clear();answer_payload.clear();
    fault=NoFault;fault_later=fail_allocation=board_reply_model=expected_set=false;expected_interface=0;
    echoed_length=0xffffffff;firmware_status=0;waits=delays=0;
    Device c={};c.DatapathRunning=TRUE;c.Sdio.TxGlom=BOOLEAN(glom);
    c.Sdio.Function2BlockSize=512;c.Sdio.MaxTransferBytes[2]=32768;
    c.Bcdc.IoctlBuffer=tx;c.Bcdc.IoctlBufferSize=sizeof(tx);
    c.Bcdc.ResponseBuffer=rx;c.Bcdc.ResponseBufferSize=sizeof(rx);
    return c;
}
static bool empty_result(const AP6256_BCDC_QUERY_RESULT& r) {
    return !r.FirmwareReply&&!r.FirmwareError&&!r.FirmwareStatus&&!r.PayloadLength;
}
static void unlocked(const Device& c) {
    assert(!c.Bcdc.Lock&&!c.Bcdc.ResponseLock&&!c.Sdio.TxLock&&!allocations);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);


    for(bool glom:{false,true}) for(unsigned count:{0u,3u,4u,5u,9u,16u,40u}) {
        auto c=setup(glom);expected_interface=3;
        for(unsigned i=0;i<count;i++) answer_payload.push_back(UCHAR(i+1));
        UCHAR out[16];memset(out,0xa5,sizeof(out));
        AP6256_BCDC_QUERY_RESULT r;memset(&r,0xff,sizeof(r));
        assert(Ap6256BcdcGetIovarResultIf(&c,3,"probe",out,sizeof(out),&r)==STATUS_SUCCESS);
        assert(r.FirmwareReply&&!r.FirmwareError&&!r.FirmwareStatus&&r.PayloadLength==count);
        assert(queries==std::vector<std::string>({"probe"}));
        assert(selector==std::vector<UCHAR>(16,0xa5));
        for(unsigned i=0;i<16;i++) assert(out[i]==(i<count?i+1:0));
        assert(waits==1&&!c.Bcdc.Pending);unlocked(c);
    }
    puts("PASS: query interface, selectors, both headers, exact reply sizes, truncation and zero padding");

    for(Fault f:{FirmwareError,TransportError,NoReply,WrongId,ShortHeader,Oversize}) {
        auto c=setup();fault=f;firmware_status=UINT32(-23);answer_payload={1,2,3,4};
        UCHAR out[16];memset(out,0xa5,sizeof(out));
        AP6256_BCDC_QUERY_RESULT r;memset(&r,0xff,sizeof(r));
        auto s=Ap6256BcdcGetIovarResultIf(&c,0,"probe",out,sizeof(out),&r);
        assert(!NT_SUCCESS(s));
        if(f==FirmwareError) assert(r.FirmwareReply&&r.FirmwareError&&r.FirmwareStatus==-23&&r.PayloadLength==4);
        else assert(empty_result(r));
        for(UCHAR v:out) assert(v==0xa5);
        unlocked(c);
    }

    auto c=setup();firmware_status=UINT32(-23);answer_payload={42};
    UCHAR out[16]={};AP6256_BCDC_QUERY_RESULT r={};
    assert(Ap6256BcdcGetIovarResultIf(&c,0,"probe",out,sizeof(out),&r)==STATUS_SUCCESS);
    assert(r.FirmwareReply&&!r.FirmwareError&&r.FirmwareStatus==-23&&out[0]==42);
    unlocked(c);
    puts("PASS: explicit firmware rejection distinguished from transport, timeout, malformed and mismatched replies");

    c=setup();memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcGetIovarResultIf(&c,16,"probe",out,16,&r)==STATUS_INVALID_PARAMETER);
    assert(empty_result(r)&&queries.empty());
    memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcGetIovarResultIf(&c,0,"probe",nullptr,16,&r)==STATUS_INVALID_PARAMETER);
    assert(empty_result(r)&&queries.empty());
    memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcGetIovarResultIf(&c,0,"probe",out,MAXULONG,&r)==STATUS_INVALID_BUFFER_SIZE);
    assert(empty_result(r)&&queries.empty());
    c.DatapathRunning=FALSE;memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcGetIovarResultIf(&c,0,"probe",out,16,&r)==STATUS_DEVICE_NOT_READY);
    assert(empty_result(r)&&queries.empty());unlocked(c);
    c=setup();fail_allocation=true;memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcGetIovarResultIf(&c,0,"probe",out,16,&r)==STATUS_INSUFFICIENT_RESOURCES);
    assert(empty_result(r)&&queries.empty());unlocked(c);
    c=setup();answer_payload={9,8,7};
    assert(Ap6256BcdcGetIovarIf(&c,0,"probe",out,16)==STATUS_SUCCESS);
    assert(out[0]==9&&out[1]==8&&out[2]==7&&out[3]==0);unlocked(c);
    puts("PASS: invalid interface/buffer/size, stopped device, allocation failure and existing API compatibility");

    for(bool optional:{false,true})for(INT32 fw:{-23,-6,-10,-8,-17}) {
        c=setup();fault=FirmwareError;firmware_status=UINT32(fw);
        AP6256_BCDC_QUERY_RESULT probeResult;UINT32 value=0xa5a5a5a5;
        NTSTATUS status=optional ? Ap6256BcdcProbeIovar(&c,"probe",&value,4,&probeResult)
                                 : Ap6256BcdcGetIovarResultIf(&c,0,"probe",&value,4,&probeResult);
        assert(status==STATUS_UNSUCCESSFUL && probeResult.FirmwareReply && probeResult.FirmwareError && probeResult.FirmwareStatus==fw && value==0xa5a5a5a5);
        bool found=false;
        for(const auto& line:logs)if(line.find("iovar 'probe'")!=std::string::npos) {
            assert(line.find(optional && fw==-23 ? "VERBOSE " : "WARN ")==0);
            if(fw==-10)assert(line.find("NOT_BAND_LOCKED (-10)")!=std::string::npos);
            found=true;
        }
        assert(found);unlocked(c);
    }
    c=setup();expected_set=true;fault=FirmwareError;firmware_status=UINT32(-23);
    assert(Ap6256BcdcSetIovarResultIf(&c,0,"probe",out,4,nullptr)==STATUS_UNSUCCESSFUL);
    bool setterWarning=false;
    for(const auto& line:logs)if(line.find("WARN SET cmd 263 if 0 iovar 'probe': UNSUPPORTED (-23)")==0)setterWarning=true;
    assert(setterWarning);unlocked(c);
    puts("PASS: optional UNSUPPORTED alone is verbose; operational SET/GET and other errors remain named warnings with unchanged results");

    const std::vector<std::string> expected={"wnm","wnm_bsstrans_resp","wnm_bsstrans_policy","rrm","ext_cap"};
    for(Fault f:{NoFault,FirmwareError,TransportError,NoReply}) {
        c=setup();fault=f;firmware_status=f==FirmwareError?UINT32(-23):0;
        answer_payload={1,2,3,4,5};
        Ap6256ProbeRoamingControls(&c);
        assert(queries.size()==((f==NoFault||f==FirmwareError)?5:1));
        for(size_t i=0;i<queries.size();i++) assert(queries[i]==expected[i]);
        assert(selector==std::vector<UCHAR>(16,0));
        unsigned reports=0;
        for(const auto& line:logs) if(line.find("DIAG feature probe:")==0) {
            ++reports;
            if(f==NoFault) assert(line.find("reply 1 error 0 fw 0 length 5 words 04030201 00000005 00000000 00000000")!=std::string::npos);
            if(f==FirmwareError) assert(line.find("reply 1 error 1 fw -23 length 5 words 00000000 00000000 00000000 00000000")!=std::string::npos);
        }
        assert(reports==queries.size());unlocked(c);
    }
    c=setup();fault=NoReply;fault_later=true;Ap6256ProbeRoamingControls(&c);
    assert(queries.size()==3&&waits==3);unlocked(c);
    puts("PASS: five allowlisted GETs only, raw results reported, explicit rejection continues, transport failure stops the probe");




    const std::vector<std::string> board_reports={
        "wnm status 0x00000000 reply 1 error 0 fw 0 length 20 words 00000000 00000000 00000000 00000000",
        "wnm_bsstrans_resp status 0x00000000 reply 1 error 0 fw 0 length 34 words 00000000 74737362 736E6172 7365725F",
        "wnm_bsstrans_policy status 0xC0000001 reply 1 error 1 fw -23 length 36 words 00000000 00000000 00000000 00000000",
        "rrm status 0x00000000 reply 1 error 0 fw 0 length 20 words 00010833 00000000 00000000 00000000",
        "ext_cap status 0xC0000001 reply 1 error 1 fw -23 length 24 words 00000000 00000000 00000000 00000000"
    };
    for(bool glom:{false,true}) {
        c=setup(glom);board_reply_model=true;
        Ap6256ProbeRoamingControls(&c);
        assert(queries==expected && waits==5);
        size_t report=0;
        for(const auto& line:logs) if(line.find("DIAG feature probe:")==0) {
            assert(report<board_reports.size());
            assert(line.find(board_reports[report++])!=std::string::npos);
        }
        assert(report==board_reports.size());unlocked(c);
    }
    puts("PASS: historical mixed replies and echoed request-tail model reproduce all five board diagnostics");




    const UCHAR param[]={0,0,13,0,3,0,5,0,54,3,0x56,0x62,0};
    for(bool glom:{false,true}) for(Fault f:{NoFault,FirmwareError,TransportError,NoReply,WrongId,ShortHeader,Oversize}) {
        c=setup(glom);expected_set=true;expected_interface=3;fault=f;
        firmware_status=UINT32(-23);answer_payload={1,2,3,4};
        memset(&r,0xff,sizeof(r));
        auto s=Ap6256BcdcSetIovarResultIf(&c,3,"fbt_param",param,sizeof(param),&r);
        assert(selector==std::vector<UCHAR>(param,param+sizeof(param)));
        assert(queries==std::vector<std::string>({"fbt_param"}));
        if(f==NoFault) assert(s==STATUS_SUCCESS && r.FirmwareReply && !r.FirmwareError && r.FirmwareStatus==-23);
        else if(f==FirmwareError) assert(s==STATUS_UNSUCCESSFUL && r.FirmwareReply && r.FirmwareError && r.FirmwareStatus==-23);
        else assert(!NT_SUCCESS(s) && empty_result(r));
        unlocked(c);
    }
    c=setup();expected_set=true;memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcSetIovarResultIf(&c,16,"fbt_param",param,sizeof(param),&r)==STATUS_INVALID_PARAMETER);
    assert(empty_result(r) && queries.empty());
    memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcSetIovarResultIf(&c,0,"fbt_param",nullptr,sizeof(param),&r)==STATUS_INVALID_PARAMETER);
    assert(empty_result(r) && queries.empty());
    memset(&r,0xff,sizeof(r));
    assert(Ap6256BcdcSetIovarResultIf(&c,0,"fbt_param",param,MAXULONG,&r)==STATUS_INVALID_BUFFER_SIZE);
    assert(empty_result(r) && queries.empty());unlocked(c);
    puts("PASS: SET exact bytes/interface and matched-reply evidence; raw status requires ERROR flag; timeout/transport/invalid responses cannot trigger a compatibility retry");
#ifdef HAS_P2P_MEMORY_PROBE
    for(Fault f:{NoFault,FirmwareError,TransportError}) {
        c=setup();c.Chip.ChipId=0x4345;c.Chip.ChipRev=9;c.FirmwareFtmPatchVerified=TRUE;
        fault=f;firmware_status=UINT32(-23);
        const char* memory="Heap Free: 26000(26K), Packet pool: 32 of 64 available\n";
        answer_payload.assign(memory,memory+strlen(memory)+1);
        Ap6256P2pTraceMemory(&c,"before p2p_ifadd");
        assert(queries==std::vector<std::string>({"memuse"}) && selector==std::vector<UCHAR>(320,0));
        assert(!expected_set && waits==(f==TransportError?0u:1u));unlocked(c);
        bool found=false;
        for(const auto& line:logs) if(line.find("p2p memory before p2p_ifadd:")!=std::string::npos) {
            found=true;
            assert((line.find("Heap Free:")!=std::string::npos)==(f==NoFault));
        }
        assert(found);
    }
    c=setup();c.Chip.ChipId=0x4345;c.Chip.ChipRev=9;c.FirmwareFtmPatchVerified=TRUE;c.FirmwareHalted=1;
    Ap6256P2pTraceMemory(&c,"after p2p_ifadd refusal");assert(queries.empty());
    c.FirmwareHalted=0;c.FirmwareFtmPatchVerified=FALSE;
    Ap6256P2pTraceMemory(&c,"before p2p_ifadd");assert(queries.empty());
    c.FirmwareFtmPatchVerified=TRUE;c.Chip.ChipRev=6;
    Ap6256P2pTraceMemory(&c,"before p2p_ifadd");assert(queries.empty());
    puts("PASS: P2P heap diagnostics use a 320-byte GET on verified r9 only; failed replies cannot log stale text or query halted firmware");
#endif
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output-dir', type=Path, default=output_dir('firmware-probes'))
    args = parser.parse_args()
    (root, out) = (args.source_root.resolve(), args.output_dir.resolve())
    out.mkdir(parents=True, exist_ok=True)
    text = control.PRE.split('static BOOLEAN configured')[0]
    text = text.replace('struct Device {', 'struct Device {\n struct { UINT32 ChipId,ChipRev; } Chip;BOOLEAN FirmwareFtmPatchVerified;')
    text = text.replace('static PVOID ExAllocatePool2', 'static bool fail_allocation;\nstatic PVOID ExAllocatePool2')
    text = text.replace('{ ++allocations; return calloc(1,n); }', '{ if(fail_allocation)return nullptr; ++allocations; return calloc(1,n); }')
    for (file, pattern) in (('sdpcm.h', '^#define (?:SDPCM_|BCDC_|BRCMF_C_GET_VAR|BRCMF_C_SET_VAR)[^\\n]+'), ('bcdc.h', '^#define AP6256_BCDC_[^\\n]+'), ('bcdc.c', '^#define BCDC_HDR_LEN[^\\n]+')):
        text += '\n'.join(re.findall(pattern, read_source_text(root / 'src' / file), re.M)) + '\n'
    text += '#define AP6256_SDIO_FUNC_DATA 2\n#pragma pack(push,1)\n'
    for name in ('SDPCM_HW_HEADER', 'SDPCM_SW_HEADER', 'BCDC_DCMD_HEADER'):
        text += control.declaration(read_source_text(root / 'src/common/sdpcm.h'), name)
    text += '#pragma pack(pop)\n'
    text += control.declaration(read_source_text(root / 'src/common/bcdc.h'), 'AP6256_BCDC_QUERY_RESULT')
    text += MOCKS.replace('static bool fault_later, fail_allocation;', 'static bool fault_later;')
    for (file, name) in (('datapath.h', 'Ap6256TxHdrLen'), ('datapath.c', 'Ap6256Align4'), ('datapath.c', 'Ap6256AlignTransfer'), ('bcdc.c', 'Ap6256BcdcProcessControlFrame'), ('bcdc.c', 'Ap6256BcdcDcmdWithResult'), ('bcdc.c', 'Ap6256BcdcGetIovarResultIf'), ('bcdc.c', 'Ap6256BcdcGetIovarIf'), ('bcdc.c', 'Ap6256BcdcSetIovarResultIf'), ('bcdc.c', 'Ap6256BcdcProbeIovar'), ('device.c', 'Ap6256ProbeRoamingControls')):
        text += control.function(root, file, name)
    if 'Ap6256P2pTraceMemory' in (root / 'src/common/hotspot.c').read_text(encoding='utf-8-sig'):
        text += control.function(root, 'common/bcdc.c', 'Ap6256BcdcGetIovar')
        text += control.function(root, 'common/hotspot.c', 'Ap6256P2pTraceMemory')
        text += '#define HAS_P2P_MEMORY_PROBE 1\n'
    source = out / 'tests.cpp'
    write_bytes(source, (text + TEST).encode())
    command = [str(control.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(control.VC / 'include')]
    command += ['/I' + str(control.INC / f) for f in ('ucrt', 'shared', 'um')]
    command += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(control.VC / 'lib/x64'), '/LIBPATH:' + str(control.LIB / 'ucrt/x64'), '/LIBPATH:' + str(control.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
