# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute production APS1 decoder, Microsoft codec and both query dispatchers.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse
import hashlib
import json
import runpy
import subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
CAP = runpy.run_path(str(ROOT / 'tests/test-wdi-capabilities.py'))
CONTROL = runpy.run_path(str(ROOT / 'tests/test-control-retry.py'))
PRE = '#define WIN32_NO_STATUS\n' + CAP['PREAMBLE'].split('struct Device {')[0] + r'''
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <vector>
#include <string>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define NDIS_STATUS_SUCCESS STATUS_SUCCESS
#define NDIS_STATUS_PENDING STATUS_PENDING
#define NDIS_STATUS_INDICATION_REQUIRED STATUS_NDIS_INDICATION_REQUIRED
#define NDIS_STATUS_BUFFER_TOO_SHORT STATUS_NDIS_BUFFER_TOO_SHORT
#define AP6256_STATION_PORT 0u
#define AP6256_GROUP_PORT 2u
#define AP6256_WDI_OPMODE_P2P_GO 16u
#define TRACE_NETADAPTER 0
template<class... Args> static void hostTrace(Args...) {(void)sizeof...(Args);}
#define TraceError(t,...) hostTrace(__VA_ARGS__)
'''
MOCKS = r'''
struct Device {
    BOOLEAN FirmwareFtmPatchVerified=TRUE; LONG FirmwareHalted=0;
    struct {BOOLEAN Created=TRUE,FirmwareReady=TRUE,Stopping=FALSE,NativeStateUncertain=FALSE; UINT32 IfIndex=7,Mode=16;} Go;
    AP6256_POWER_SAVE_DX PowerSaveDx[2] = {};
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Role {BOOLEAN Closing=FALSE;};
struct Wifi {
    Device* Ctx;
    BOOLEAN Stopping=FALSE,HardwareAvailable=TRUE,PowerStateDx=FALSE;
    int ConnectLock=0;
    TLV_CONTEXT TlvContext={};
    struct {Role* Roles[2];int GroupLock=0;} Model;
};
typedef Wifi* PAP6256_WIFI;
static std::vector<int*> locks;
static void Ap6256LockAcquire(int* lock) {assert(!*lock);*lock=1;locks.push_back(lock);}
static void Ap6256LockRelease(int* lock) {assert(*lock && locks.back()==lock);*lock=0;locks.pop_back();}
static std::vector<UCHAR> wire;
static ULONG received=80,queries=0;
static UINT32 lastInterface=999;
static NTSTATUS queryStatus=STATUS_SUCCESS;
static bool firmwareReply=true,firmwareError=false;
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 iface,PCSTR name,PVOID out,ULONG size,PAP6256_BCDC_QUERY_RESULT result) {
    assert(!strcmp(name,"wdi_power_stats") && size==80 && (iface==0 || iface==7));
    ++queries;lastInterface=iface;*result={};result->PayloadLength=received;
    result->FirmwareReply=(BOOLEAN)firmwareReply;result->FirmwareError=(BOOLEAN)firmwareError;
    memset(out,0,size);memcpy(out,wire.data(),min((size_t)size,wire.size()));
    return queryStatus;
}
static void put32(size_t o,UINT32 v) {for(unsigned i=0;i<4;++i)wire.at(o+i)=UCHAR(v>>(8*i));}
static void put64(size_t o,ULONGLONG v) {for(unsigned i=0;i<8;++i)wire.at(o+i)=UCHAR(v>>(8*i));}
static void reset() {
    wire.assign(80,0);put32(0,0x31535041);put32(4,80);put32(8,3);put32(12,2);
    put32(16,100);put32(20,2);put32(28,1);
    put64(32,0x100000001ull);put64(40,0x100000000ull);
    put64(48,0x100000002ull);put64(56,0x100000003ull);put64(64,0x100000004ull);put64(72,0x100000005ull);
    received=80;queries=0;lastInterface=999;queryStatus=STATUS_SUCCESS;firmwareReply=true;firmwareError=false;
    assert(locks.empty());
}
struct Request {
    struct {struct {PVOID InformationBuffer;ULONG OutputBufferLength=256,BytesWritten=0,BytesNeeded=0;} METHOD_INFORMATION;} DATA;
    UCHAR Buffer[256];unsigned Completes=0;NTSTATUS Status=STATUS_SUCCESS;ULONG CompletedBytes=0;
    Request(){memset(Buffer,0,sizeof(Buffer));DATA.METHOD_INFORMATION.InformationBuffer=Buffer;}
};
typedef Request* AP6256_REQUEST;
static void Ap6256CompleteRequest(Wifi*,Request* request,NTSTATUS status) {
    assert(++request->Completes==1);request->Status=status;
    ((WDI_MESSAGE_HEADER*)request->Buffer)->Status=Ap6256NtToNdisStatus(status);
}
static PVOID WifiRequestGetInOutBuffer(Request* request,UINT*,UINT* output) {
    *output=request->DATA.METHOD_INFORMATION.OutputBufferLength;return request->Buffer;
}
static void WifiRequestSetBytesNeeded(Request* request,ULONG needed) {request->DATA.METHOD_INFORMATION.BytesNeeded=needed;}
static void WifiRequestComplete(Request* request,NTSTATUS status,ULONG bytes) {
    assert(++request->Completes==1);request->Status=status;request->CompletedBytes=bytes;
}
static WDI_PORT_ID Ap6256WifiCxExternalPort(Device*,UINT32 id) {return id==0?42:68;}
static void Ap6256CxQuiesceRole(Wifi*,UINT32) {assert(false);}
static NTSTATUS Ap6256GeneratePmOffload(Wifi*,const UCHAR*,ULONG,UCHAR**,ULONG*) {assert(false);return STATUS_NOT_SUPPORTED;}
static void Ap6256HandlePowerRequest(Wifi*,Request*,const UCHAR*,ULONG) {assert(false);}
static void Ap6256HandleGetCapabilities(Wifi*,Request*) {assert(false);}
static void Ap6256HandleGetGroupStatistics(Wifi*,Request*) {assert(false);}
static void Ap6256HandleGetStatistics(Wifi*,Request*) {assert(false);}
static void Ap6256HandleGetNextActionFrameDialogToken(Wifi*,Request*) {assert(false);}
static void Ap6256HandleGetPmProtocolOffload(Wifi*,Request*,const UCHAR*,ULONG) {assert(false);}
'''
TEST = r'''
static WDI_GET_AUTO_POWER_SAVE_STRUCT decode(Wifi& wifi,UCHAR* data,ULONG size) {
    assert(data && size==72 && data[0]==0xb3 && data[1]==0 && data[2]==68 && data[3]==0);
    WDI_GET_AUTO_POWER_SAVE_RESULTS result={};
    assert(ParseWdiGetAutoPowerSaveFromIhv(size,data,&wifi.TlvContext,&result)==NDIS_STATUS_SUCCESS);
    assert(!result.AutoPowerSaveParameters.bReserved && !result.AutoPowerSaveParameters.wReserved);
    return result.AutoPowerSaveParameters;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    reset();Device ctx;Role station,group;Wifi wifi;wifi.Ctx=&ctx;wifi.TlvContext.PeerVersion=WDI_VERSION_LATEST;wifi.Model.Roles[0]=&station;wifi.Model.Roles[1]=&group;
    AP6256_POWER_SAVE_STATS stats={};
    assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_SUCCESS);
    assert(stats.BeaconInterval==102 && stats.ListenInterval==2 && stats.Mode==2);
    assert(stats.MillisecondsSinceStart==0x100000001ull && stats.MillisecondsInPowerSave==0x100000000ull);
    assert(stats.ReceivedMulticastPackets==0x100000002ull && stats.SentUnicastPackets==0x100000005ull);
    for(ULONG length=0;length<80;++length) {
        received=length;memset(&stats,0xff,sizeof(stats));
        assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_DEVICE_PROTOCOL_ERROR);
        const UCHAR* bytes=(const UCHAR*)&stats;for(size_t i=0;i<sizeof(stats);++i)assert(!bytes[i]);
    }
    reset();received=96;assert(Ap6256WifiGetPowerSaveStats(&ctx,7,&stats)==STATUS_SUCCESS && lastInterface==7);
    for(auto bad:std::vector<std::pair<size_t,UINT32>>{{0,0},{4,79},{8,1},{12,3},{16,65536},{20,256},{24,256},{28,256}}) {
        reset();put32(bad.first,bad.second);assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_DEVICE_PROTOCOL_ERROR);
    }
    reset();put64(40,0x100000002ull);assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_DEVICE_PROTOCOL_ERROR);
    reset();put32(16,65535);assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_INTEGER_OVERFLOW);
    reset();put32(20,128);put32(28,2);assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_INTEGER_OVERFLOW);
    reset();put32(24,3);put32(28,2);assert(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)==STATUS_NOT_SUPPORTED);
    reset();put32(20,255);assert(!Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)&&stats.ListenInterval==255);
    AP6256_POWER_SAVE_DX pending[2];Ap6256PowerCaptureDx(&ctx,pending);assert(pending[0].Seen&&!pending[0].Valid);
    for(auto fault:{0,1,2,3,4}) {
        reset();ctx.FirmwareFtmPatchVerified=TRUE;ctx.FirmwareHalted=0;
        if(fault==0)queryStatus=STATUS_IO_TIMEOUT;
        if(fault==1)firmwareReply=false;
        if(fault==2)firmwareError=true;
        if(fault==3)ctx.FirmwareFtmPatchVerified=FALSE;
        if(fault==4)ctx.FirmwareHalted=1;
        assert(!NT_SUCCESS(Ap6256WifiGetPowerSaveStats(&ctx,0,&stats)));
        if(fault>=3)assert(!queries);
    }
    ctx.FirmwareFtmPatchVerified=TRUE;ctx.FirmwareHalted=0;reset();
    puts("PASS: received-length admission, exact APS1 scope, u64 values, units, interval bounds and firmware failures");
    for(UINT32 mode=0;mode<3;++mode) {
        reset();put32(12,mode);UCHAR* generated=nullptr;ULONG length=0;
        assert(!Ap6256GeneratePowerSave(&wifi,0,&generated,&length));auto report=decode(wifi,generated,length);
        assert(report.EnableAutoPSM==(mode!=0) && report.BeaconInterval==102);
        assert(report.ListenInterval==(mode?2:1) && report.ListenIntervalInDx==255);
        assert(report.PowerMode==(WDI_POWER_SAVE_LEVEL)(mode==0?0:mode==1?16:8) && report.PowerModeinDx==0 && report.Reason==5);
        assert(report.MillisecondsSinceStart==0x100000001ull && report.MillisecondsInPowerSave==0x100000000ull);
        assert(report.ReceivedMulticastPackets==0x100000002ull && report.SentMulticastPackets==0x100000003ull);
        assert(report.ReceivedUnicastPackets==0x100000004ull && report.SentUnicastPacket==0x100000005ull);
        FreeGenerated(generated);assert(locks.empty());
    }
    reset();ctx.PowerSaveDx[0]={TRUE,TRUE,10,0,1};ctx.PowerSaveDx[1]={TRUE,TRUE,1,0,0};
    for(UINT32 port:{0u,2u}) {
        UCHAR* generated=nullptr;ULONG length=0;assert(!Ap6256GeneratePowerSave(&wifi,port,&generated,&length));
        auto report=decode(wifi,generated,length);assert(lastInterface==(port?7u:0u));
        assert(report.ListenIntervalInDx==(port?1:10) && report.PowerModeinDx==(port?0:16));FreeGenerated(generated);
    }
    for(int fault=0;fault<8;++fault) {
        reset();wifi.Stopping=FALSE;wifi.HardwareAvailable=TRUE;wifi.PowerStateDx=FALSE;
        ctx.Go.Created=TRUE;ctx.Go.FirmwareReady=TRUE;ctx.Go.Stopping=FALSE;ctx.Go.NativeStateUncertain=FALSE;
        ctx.PowerSaveDx[1].Valid=TRUE;
        if(fault==0)wifi.Stopping=TRUE;if(fault==1)wifi.HardwareAvailable=FALSE;if(fault==2)wifi.PowerStateDx=TRUE;
        if(fault==3)ctx.Go.Created=FALSE;if(fault==4)ctx.Go.FirmwareReady=FALSE;
        if(fault==5)ctx.Go.Stopping=TRUE;if(fault==6)ctx.Go.NativeStateUncertain=TRUE;if(fault==7)ctx.PowerSaveDx[1].Valid=FALSE;
        UCHAR* generated=(UCHAR*)1;ULONG length=999;assert(!NT_SUCCESS(Ap6256GeneratePowerSave(&wifi,2,&generated,&length)));
        assert(!generated&&!length&&!queries&&locks.empty());
    }
    wifi.Stopping=FALSE;wifi.HardwareAvailable=TRUE;wifi.PowerStateDx=FALSE;
    ctx.Go.Created=TRUE;ctx.Go.FirmwareReady=TRUE;ctx.Go.Stopping=FALSE;ctx.Go.NativeStateUncertain=FALSE;
    memset(ctx.PowerSaveDx,0,sizeof(ctx.PowerSaveDx));reset();
    UCHAR* generated=(UCHAR*)1;ULONG length=999;
    assert(Ap6256GeneratePowerSave(&wifi,1,&generated,&length)==STATUS_INVALID_PARAMETER&&!generated&&!length&&!queries);
    puts("PASS: real Microsoft TLV roundtrip, three power levels, station/group routing, last Dx and lifecycle locks");
    for(bool cx:{false,true}) for(WDI_PORT_ID port:{(WDI_PORT_ID)0,(WDI_PORT_ID)2}) for(bool small:{false,true}) {
        reset();Request request;auto header=(WDI_MESSAGE_HEADER*)request.Buffer;header->PortId=port;
        request.DATA.METHOD_INFORMATION.OutputBufferLength=small?sizeof(WDI_MESSAGE_HEADER)+71:256;
        bool handled=cx?TestCxDispatch(&wifi,&request,header,nullptr,0,WDI_GET_AUTO_POWER_SAVE):
                        TestWdiDispatch(&wifi,&request,header,nullptr,0,WDI_GET_AUTO_POWER_SAVE);
        assert(handled && request.Completes==1 && queries==1 && lastInterface==(port?7u:0u));
        if(small)assert(!NT_SUCCESS(request.Status)&&request.DATA.METHOD_INFORMATION.BytesNeeded==sizeof(WDI_MESSAGE_HEADER)+72);
        else {
            assert(request.Status==STATUS_SUCCESS && header->Status==NDIS_STATUS_SUCCESS);
            assert(header->PortId==(cx?(port?68u:42u):port));
            assert((cx?request.CompletedBytes:request.DATA.METHOD_INFORMATION.BytesWritten)==sizeof(WDI_MESSAGE_HEADER)+72);
            decode(wifi,request.Buffer+sizeof(WDI_MESSAGE_HEADER),72);
        }
    }
    for(bool cx:{false,true}) {
        reset();queryStatus=STATUS_IO_TIMEOUT;Request request;auto header=(WDI_MESSAGE_HEADER*)request.Buffer;
        assert(cx?TestCxDispatch(&wifi,&request,header,nullptr,0,WDI_GET_AUTO_POWER_SAVE):
                  TestWdiDispatch(&wifi,&request,header,nullptr,0,WDI_GET_AUTO_POWER_SAVE));
        assert(request.Completes==1&&!NT_SUCCESS(request.Status));
    }
    puts("PASS: actual WDI/WiFiCx GET dispatch, opaque port translation, BytesWritten/BytesNeeded and transport failure completion");
}
'''

def read(path):
    return path.read_text(encoding='utf-8-sig')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dispatch-source-root', type=Path, default=ROOT)
    p.add_argument('--frontend', choices=('both', 'wdi', 'wificx'), default='both')
    p.add_argument('--output-dir', type=Path, default=output_dir('power-save-statistics'))
    args = p.parse_args()
    out = args.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)
    common = _functions(read(ROOT / 'src/common/netadapter.c'))
    code = PRE + read(ROOT / 'src/common/power_stats.h').replace('#pragma once', '')
    code += CONTROL['declaration'](read(ROOT / 'src/common/bcdc.h'), 'AP6256_BCDC_QUERY_RESULT')
    code += common['Ap6256NdisToNtStatus'] + common['Ap6256NtToNdisStatus'] + MOCKS
    for file in ('power_stats.inc', 'power_query.inc'):
        code += '\n'.join(_functions(read(ROOT / 'src/common' / file)).values()) + '\n'
    dispatch = []
    for (model, label) in [('wdi', 'Wdi'), ('wificx', 'Cx')]:
        path = args.dispatch_source_root / 'src' / model / 'netadapter.c'
        text = read(path)
        functions = _functions(text)
        if model == 'wdi':
            code += functions['Ap6256CompleteQuery']
        code += functions['Ap6256ModelDispatchCommand'].replace('Ap6256ModelDispatchCommand', 'Test' + label + 'Dispatch')
        dispatch.append(dict(path=str(path), sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    test = TEST
    if args.frontend != 'both':
        test = test.replace('for(bool cx:{false,true})', 'for(bool cx:{' + ('true' if args.frontend == 'wificx' else 'false') + '})')
    cpp = out / 'tests.cpp'
    write_text(cpp, (code + test).replace(' = {0};', ' = {};'), encoding='utf8')
    (vc, inc, lib) = [CONTROL[k] for k in ('VC', 'INC', 'LIB')]
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4505', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WDI' if args.frontend == 'wdi' else '/DAP6256_ENABLE_WIFICX', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / n) for n in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2) + '\n', encoding='utf-8')
    subprocess.run(cmd, check=True)
    run = subprocess.run([str(out / 'tests.exe')], text=True, capture_output=True)
    write_text(out / 'runtime.log', run.stdout + run.stderr, encoding='utf8')
    report = dict(exit_code=run.returncode, expected_failure=False, frontend=args.frontend, dispatch_sources=dispatch, harness_sha256=hashlib.sha256(cpp.read_bytes()).hexdigest(), test_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), boundary=__doc__, board_validated=False)
    write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(run.stdout + run.stderr, end='')
    assert (run.returncode != 0) == False, report
if __name__ == '__main__':
    main()
