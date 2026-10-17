# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise production key authorization, receive filters and bounded diagnostics.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import argparse
import importlib.util
from pathlib import Path
from wdi_test_support import contract_preamble
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
PRE = r'''
#include <vector>
#include <string>
#include <stdarg.h>
#undef TraceDiag
static std::vector<std::string> logs;
static void trace(const char* f,...) {
    char b[512];va_list a;va_start(a,f);vsnprintf(b,sizeof(b),f,a);va_end(a);logs.emplace_back(b);
}
#define TraceDiag(...) trace(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceData(...) trace(__VA_ARGS__)
#define TraceInfo(t,...) trace(__VA_ARGS__)
#define TraceWarn(t,...) trace(__VA_ARGS__)
#define TraceError(t,...) trace(__VA_ARGS__)
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_DEVICE_DATA_ERROR ((NTSTATUS)0xc000009c)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
struct Device {
    BOOLEAN FirmwareWowlAdapter=FALSE,FirmwareGtkOffloadSupported=FALSE;
    struct { BOOLEAN FirmwareReady,Started;UINT32 IfIndex,Mode;
        LONG PacketFilter,DataTrace[Ap6256GoDataStageCount];
        LONG Ipv4Trace[2][Ap6256GoDataStageCount]; } Go;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi { Device* Ctx;TLV_CONTEXT TlvContext; };
typedef Wifi* PAP6256_WIFI;
typedef void* AP6256_REQUEST;
struct Call { UINT32 iface,command;std::vector<UCHAR> bytes; };
static std::vector<Call> calls;
static NTSTATUS keyStatus,fallbackStatus,authStatus,cleanupStatus,readStatus,filterStatus,requestStatus;
static unsigned pmCalls,readCalls,staFilterCalls,fallbackCalls;
static UINT32 queryFlags=0xe03a;
static unsigned badReadback;
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s) {requestStatus=s;}
static NTSTATUS Ap6256BcdcSetDcmdIf(Device*,UINT32 iface,UINT32 command,const VOID* data,ULONG len) {
    auto p=(const UCHAR*)data;calls.push_back({iface,command,{p,p+len}});
    if(command==BRCMF_C_SET_KEY) {
        assert(len==164);UINT32 size;memcpy(&size,p+4,4);
        return size ? keyStatus : cleanupStatus;
    }
    assert((command==BRCMF_C_SCB_AUTHORIZE || command==BRCMF_C_SCB_DEAUTHORIZE) && len==6);
    return command==BRCMF_C_SCB_AUTHORIZE ? authStatus : 0;
}
static NTSTATUS Ap6256BcdcSetIovarIf(Device*,UINT32 iface,const char* name,const VOID* data,ULONG len) {
    auto p=(const UCHAR*)data;
    if(!strcmp(name,"wsec_key")) {
        assert(len==164);fallbackCalls++;calls.push_back({iface,263,{p,p+len}});return fallbackStatus;
    }
    assert(!strcmp(name,"allmulti") && len==4 && *(const UINT32*)data==1);
    calls.push_back({iface,263,{p,p+len}});return filterStatus;
}
static NTSTATUS Ap6256BcdcGetIovarIf(Device*,UINT32 iface,const char* name,VOID* data,ULONG len) {
    assert(iface==7 && !strcmp(name,"sta_info") && len==512);readCalls++;
    UCHAR mac[6];memcpy(mac,data,6);memset(data,0,len);auto p=(UCHAR*)data;
    p[0]=4;p[2]=200;memcpy(p+8,&queryFlags,4);memcpy(p+16,mac,6);
    if(badReadback==1)p[16]^=2;
    if(badReadback==2)p[2]=21;
    if(badReadback==3)p[3]=3;
    return readStatus;
}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN enabled) {assert(enabled);pmCalls++;return 0;}
static ULONGLONG KeQueryInterruptTime(){return 0;}
static NTSTATUS Ap6256WlfcWaitEapol(Device*,UINT32) {return 0;}
static NTSTATUS Ap6256WifiSetPacketFilter(Device*,ULONG,BOOLEAN) {staFilterCalls++;return filterStatus;}


static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR,const VOID*,ULONG) {
    assert(false);return STATUS_NOT_SUPPORTED;
}
'''
TEST = r'''
static void reset() {
    calls.clear();logs.clear();keyStatus=fallbackStatus=authStatus=cleanupStatus=readStatus=filterStatus=0;
    requestStatus=STATUS_IO_TIMEOUT;pmCalls=readCalls=staFilterCalls=fallbackCalls=0;badReadback=0;queryFlags=0xe03a;
}
static bool logged(const char* text) {for(auto& s:logs)if(s.find(text)!=std::string::npos)return true;return false;}
#if AP6256_TRACE_DATAPATH
static void ipChecksum(UCHAR* f) {
    f[24]=f[25]=0;unsigned sum=0;
    for(unsigned i=14;i<34;i+=2)sum+=(unsigned(f[i])<<8)|f[i+1];
    while(sum>>16)sum=(sum&65535)+(sum>>16);
    sum=(~sum)&65535;f[24]=(UCHAR)(sum>>8);f[25]=(UCHAR)sum;
}
#endif
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    Device d={};d.Go.FirmwareReady=d.Go.Started=TRUE;d.Go.IfIndex=7;d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;
    AP6256_CCMP_KEY key={};key.IfIndex=7;key.Pairwise=TRUE;
    UCHAR mac[]={0xa0,0xd3,0x65,0xa0,0x51,0x45};memcpy(key.PeerAddress,mac,6);memset(key.Key,0xa5,16);
    key.ReceiveSequenceValid=TRUE;for(unsigned i=0;i<6;i++)key.ReceiveSequence[i]=(UCHAR)(i+1);
    reset();assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && calls.size()==2 && readCalls==1 && !pmCalls);
    assert(calls[0].iface==7 && calls[0].command==45 && calls[1].iface==7 && calls[1].command==121);
    auto& k=calls[0].bytes;assert(k.size()==164 && k[4]==16 && k[112]==4 && !k[116]);
    assert(!memcmp(k.data()+8,key.Key,16) && !memcmp(k.data()+156,mac,6));
    assert(k[132]==1 && k[140]==3 && k[141]==4 && k[142]==5 && k[143]==6 && k[144]==1 && k[145]==2);
    assert(calls[1].bytes==std::vector<UCHAR>(mac,mac+6) && logged("authorized 1"));
    key.IfIndex=0;reset();assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && pmCalls==1 && !readCalls);
    for(auto& c:calls)assert(c.iface==0);
    key.IfIndex=7;key.Pairwise=FALSE;key.KeyId=2;reset();
    assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && calls.size()==1 && !readCalls && !pmCalls);
    assert(calls[0].bytes[116]==2 && calls[0].bytes[156]==0 && calls[0].bytes[0]==2);
    key.Pairwise=TRUE;key.KeyId=0;
    reset();keyStatus=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && fallbackCalls==1 && calls.size()==3);
    assert(calls[0].bytes==calls[1].bytes && calls[1].iface==7);
    reset();keyStatus=fallbackStatus=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_IO_TIMEOUT && calls.size()==2 && !readCalls);
    for(NTSTATUS cleanup : { (NTSTATUS)0, STATUS_DEVICE_DATA_ERROR }) {
        reset();authStatus=STATUS_IO_TIMEOUT;cleanupStatus=fallbackStatus=cleanup;
        assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_IO_TIMEOUT && !pmCalls && !readCalls);
        assert(calls.size()==(NT_SUCCESS(cleanup)?4u:5u));
        for(auto& c:calls)assert(c.iface==7);
        assert(calls[2].command==122 && calls[2].bytes==std::vector<UCHAR>(mac,mac+6));
        assert(calls[3].command==45 && calls[3].bytes[4]==0 && calls[3].bytes[112]==0);
        assert(!memcmp(calls[3].bytes.data()+156,mac,6));
    }
    key.IfIndex=0;reset();authStatus=STATUS_IO_TIMEOUT;
    assert(Ap6256WifiAddCcmpKey(&d,&key)==STATUS_IO_TIMEOUT && !pmCalls);key.IfIndex=7;
    for(unsigned bad=1;bad<=3;bad++) {
        reset();badReadback=bad;assert(Ap6256WifiAddCcmpKey(&d,&key)==0);
        assert(logged("invalid identity/layout") && !logged("authorized 1"));
    }
    reset();readStatus=STATUS_IO_TIMEOUT;assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && logged("readback if 7 ->"));
    reset();queryFlags=0xe01a;assert(Ap6256WifiAddCcmpKey(&d,&key)==0 && logged("authorized 0"));
    reset();key.KeyId=16;assert(!NT_SUCCESS(Ap6256WifiAddCcmpKey(&d,&key)) && calls.empty());key.KeyId=0;
    key.PeerAddress[0]|=1;assert(!NT_SUCCESS(Ap6256WifiAddCcmpKey(&d,&key)) && calls.empty());memcpy(key.PeerAddress,mac,6);
    puts("PASS: exact per-interface key/authorization bytes, rollback and error propagation, group/STA isolation, optional identity-checked readback");

    Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
    WDI_MESSAGE_HEADER h={};h.PortId=2;WDI_SET_RECEIVE_PACKET_FILTER_PARAMETERS f={};
    f.PacketFilterType=WDI_PACKET_FILTER_DIRECTED|WDI_PACKET_FILTER_BROADCAST;
    UINT8* bytes=NULL;ULONG length=0;
    assert(GenerateWdiSetReceivePacketFilterToIhv(&f,0,&w.TlvContext,&length,&bytes)==0);
    reset();d.Go.PacketFilter=0;Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==0 && d.Go.PacketFilter==(AP6256_RXF_DIRECTED|AP6256_RXF_BROADCAST));
    assert(calls.size()==1 && calls[0].iface==7);
    reset();filterStatus=STATUS_IO_TIMEOUT;d.Go.PacketFilter=AP6256_RXF_DIRECTED;
    Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==STATUS_IO_TIMEOUT && d.Go.PacketFilter==AP6256_RXF_DIRECTED);
    h.PortId=0;Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==STATUS_IO_TIMEOUT && staFilterCalls==1);
    reset();h.PortId=1;Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==0 && calls.empty() && !staFilterCalls);
    h.PortId=9;Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==STATUS_INVALID_DEVICE_STATE && calls.empty());
    h.PortId=2;d.Go.FirmwareReady=FALSE;Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);
    assert(requestStatus==STATUS_INVALID_DEVICE_STATE && calls.empty());d.Go.FirmwareReady=TRUE;
    Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length-1);assert(!NT_SUCCESS(requestStatus) && calls.empty());
    FreeGenerated(bytes);bytes=NULL;
    f.PacketFilterType=0x80000000;
    assert(GenerateWdiSetReceivePacketFilterToIhv(&f,0,&w.TlvContext,&length,&bytes)==0);
    Ap6256HandleReceivePacketFilter(&w,&h,NULL,bytes,length);assert(!NT_SUCCESS(requestStatus) && calls.empty());
    FreeGenerated(bytes);
    puts("PASS: real WDI filter codec, per-port updates and failures, deleted/invalid ports, malformed/unsupported filters");

#if AP6256_TRACE_DATAPATH
    reset();memset(d.Go.DataTrace,0,sizeof(d.Go.DataTrace));
    memset(d.Go.Ipv4Trace,0,sizeof(d.Go.Ipv4Trace));


    UCHAR noise[90]={};noise[12]=0x86;noise[13]=0xdd;
    for(unsigned i=0;i<16;i++)Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,7,noise,sizeof(noise),0);
    assert(logs.size()==16);logs.clear();
    UCHAR frame[54]={};frame[12]=8;frame[14]=0x45;frame[17]=40;frame[18]=0x12;frame[19]=0x34;
    frame[23]=17;frame[26]=192;frame[27]=168;frame[28]=137;frame[29]=102;
    frame[30]=192;frame[31]=168;frame[32]=137;frame[33]=1;
    frame[34]=0xc0;frame[35]=1;frame[37]=53;frame[39]=20;frame[42]=0x37;frame[43]=0x59;
    ipChecksum(frame);
    UCHAR original[sizeof(frame)];memcpy(original,frame,sizeof(frame));
    Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,7,frame,sizeof(frame),0);
    assert(logs.size()==1 && logged("hotspot IPv4 rx-bus") && logged("192.168.137.102>192.168.137.1"));
    assert(logged("valid 1 hdrsum 1") && logged("DNS 1 id 0x3759 reply 0"));
    assert(!memcmp(original,frame,sizeof(frame)));
    Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,0,frame,sizeof(frame),0);
    assert(logs.size()==2 && logged("if 0 192.168.137.102"));
    puts("PASS: IPv4 remains visible after the captured IPv6 startup burst; station and GO paths have independent budgets");

    reset();memset(d.Go.Ipv4Trace,0,sizeof(d.Go.Ipv4Trace));
    for(unsigned i=0;i<1000;i++)Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,7,frame,sizeof(frame),0);
    assert(logs.size()==16 && d.Go.Ipv4Trace[1][Ap6256GoDataRxBus]==16);
    for(unsigned i=0;i<1000;i++)Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,0,frame,sizeof(frame),0);
    assert(logs.size()==32 && d.Go.Ipv4Trace[0][Ap6256GoDataRxBus]==16);
    Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,9,frame,sizeof(frame),0);
    d.Go.Started=FALSE;Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,0,frame,sizeof(frame),0);
    d.Go.Started=TRUE;d.Go.Mode=0;Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,0,frame,sizeof(frame),0);
    d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;assert(logs.size()==32);
    reset();assert(Ap6256WifiAddCcmpKey(&d,&key)==0);
    for(unsigned iface=0;iface<2;iface++)for(unsigned stage=0;stage<Ap6256GoDataStageCount;stage++)
        assert(d.Go.Ipv4Trace[iface][stage]==0);
    logs.clear();frame[44]=0x80;
    Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,7,frame,sizeof(frame),0);
    assert(logged("DNS 1 id 0x3759 reply 1"));
    logs.clear();frame[24]^=1;
    Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,7,frame,sizeof(frame),0);
    assert(logged("valid 1 hdrsum 0"));


    for(unsigned variant=0;variant<3;variant++) {
        memcpy(frame,original,sizeof(frame));
        if(variant==0)frame[21]=1;
        if(variant==1)frame[17]=28;
        if(variant==2)frame[39]=8;
        logs.clear();Ap6256TraceHotspotPacket(&d,Ap6256GoDataTxQueued,7,frame,sizeof(frame),0);
        assert(logged("DNS 0 id 0x0000"));
        if(variant==0)assert(logged("ports 0>0"));
    }
    puts("PASS: bounded output, active-GO gate, authorization reset, IPv4 checksum and DNS identity, fragment and nested-length validation");


    auto guarded=(UCHAR*)VirtualAlloc(NULL,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);assert(guarded);
    DWORD old;assert(VirtualProtect(guarded+4096,4096,PAGE_NOACCESS,&old));
    for(ULONG n=0;n<128;n++)for(unsigned ihl=0;ihl<16;ihl++)for(unsigned ether : {0u,6u}) {
        auto p=guarded+4096-n;memset(p,0,n);memset(d.Go.DataTrace,0,sizeof(d.Go.DataTrace));
        memset(d.Go.Ipv4Trace,0,sizeof(d.Go.Ipv4Trace));logs.clear();
        if(n>=14){p[12]=8;p[13]=(UCHAR)ether;}
        if(n>=15)p[14]=(UCHAR)(0x40|ihl);if(n>=24)p[23]=17;
        if(n>=18)p[17]=(UCHAR)(n-14);
        unsigned udp=14+ihl*4;
        if(udp>=34 && n>=udp+4)p[udp+3]=53;
        if(udp>=34 && n>=udp+6)p[udp+5]=20;
        Ap6256TraceHotspotPacket(&d,Ap6256GoDataRxBus,7,p,n,0);
    }
    VirtualFree(guarded,0,MEM_RELEASE);
    puts("PASS: guard-page checks for every short ARP/IPv4 buffer and IPv4 header length");
#else


    reset();memset(d.Go.DataTrace,0,sizeof(d.Go.DataTrace));
    memset(d.Go.Ipv4Trace,0,sizeof(d.Go.Ipv4Trace));
    Device before=d;
    UCHAR frame[96]={};
    for(unsigned ether : {0x0800u,0x0806u,0x86ddu}) {
        frame[12]=(UCHAR)(ether>>8);frame[13]=(UCHAR)ether;
        UCHAR original[sizeof(frame)];memcpy(original,frame,sizeof(frame));
        for(UINT32 iface : {0u,7u})for(unsigned stage=0;stage<Ap6256GoDataStageCount;stage++)
            for(unsigned packet=0;packet<32;packet++)
                Ap6256TraceHotspotPacket(&d,(AP6256_GO_DATA_STAGE)stage,iface,frame,sizeof(frame),0);
        assert(!memcmp(original,frame,sizeof(frame)));
    }
    assert(logs.empty() && !memcmp(&before,&d,sizeof(d)));
    puts("PASS: production packet tracing emits nothing, leaves frames and device state unchanged");
#endif
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=output_dir('hotspot-data'))
    args = parser.parse_args()
    cap = module('test-wdi-capabilities')
    hot = module('test-hotspot')
    tx = module('test-wdi-transmit')
    hot.ROOT = args.source_root
    src = args.source_root / 'src'
    ctx = read_source_text(src / 'ap6256.h')
    wh = read_source_text(src / 'wifi_ops.h')
    wc = read_source_text(src / 'wifi_ops.c')
    sd = read_source_text(src / 'sdpcm.h')
    na = read_source_text(src / 'netadapter.c')
    text = cap.PREAMBLE.split('struct Device {')[0].replace('assert(context == 0); free(p);', '(void)context; free(p);')
    text += tx.declaration(ctx, 'AP6256_GO_DATA_STAGE')
    for (source, pattern) in ((ctx, '^#define AP6256_(?:RXF_\\w+|STATION_PORT|GROUP_PORT|DISCOVERY_PORT)[^\\n]+'), (wh, '^#define AP6256_(?:WDI_OPMODE_P2P_GO|STATION_PORT|GROUP_PORT|DISCOVERY_PORT)[^\\n]+'), (wc, '^#define BRCMF_(?:CRYPTO_ALGO_AES_CCM|PRIMARY_KEY)[^\\n]+'), (sd, '^#define BRCMF_C_(?:SET_KEY|SCB_AUTHORIZE|SCB_DEAUTHORIZE)\\s+[^\\n]+'), (na, '^#define AP6256_WDI_FILTER_[^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += PRE + tx.declaration(wh, 'AP6256_CCMP_KEY')
    text += read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    text += r'''
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
static BOOLEAN Ap6256FipsActive(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256FipsSnapshot(Device*,UINT32,AP6256_FIPS_SESSION*) {return FALSE;}
static BOOLEAN Ap6256FipsRetired(Device*,UINT32) {return FALSE;}
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) {return FALSE;}
'''
    text += '#pragma pack(push,1)\n' + tx.declaration(wc, 'BRCMF_WSEC_KEY') + '#pragma pack(pop)\n'
    import native_key_fixture
    text = native_key_fixture.context(text)
    text += native_key_fixture.writer()
    functions = [('wifi_ops.c', 'VOID Ap6256WifiSeedGroupKey(Device* Ctx,UINT32 Id,BOOLEAN Management,BOOLEAN Valid,const UCHAR* Key,const UCHAR* Rsc)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiDeleteCcmpKeyIf(Device* Ctx,UINT32 IfIndex,ULONG KeyId,BOOLEAN Pairwise,const UCHAR* PeerAddress)'), ('wifi_ops.c', 'VOID Ap6256WifiTracePeerAuthorization(Device* Ctx,UINT32 IfIndex,const UCHAR* Address)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiAddCcmpKey(Device* Ctx,PAP6256_CCMP_KEY Key)'), ('netadapter.c', 'VOID Ap6256HandleReceivePacketFilter(Wifi* Wifi,PWDI_MESSAGE_HEADER Header,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('datapath.c', 'VOID Ap6256TraceHotspotPacket(Device* Ctx,AP6256_GO_DATA_STAGE Stage,UINT32 IfIndex,const UCHAR* Frame,ULONG Length,NTSTATUS Status)')]
    for (file, signature) in functions:
        name = re.search('(Ap6256\\w+)\\(', signature)[1]
        text += signature + '\n' + hot.body(file, name) + '\n'
    text += TEST
    args.output.mkdir(parents=True, exist_ok=True)
    cpp = args.output / 'tests.cpp'
    write_bytes(cpp, (contract_preamble() + text).encode())
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    for tracing in (0, 1):
        executable = args.output / ('tests-tracing-' + str(tracing) + '.exe')
        build = command + ['/DAP6256_TRACE_DATAPATH=' + str(tracing), str(cpp), '/Fe:' + str(executable), '/Fo:' + str(args.output / ('tests-tracing-' + str(tracing) + '.obj')), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib', str(tx.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
        subprocess.run(build, check=True)
        subprocess.run([str(executable)], check=True)
if __name__ == '__main__':
    main()
