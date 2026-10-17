# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util, json, re, subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('control', Path(__file__).with_name('test-control-retry.py'))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <assert.h>
#include <stdio.h>
#include <vector>
#include <random>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define AP6256_POOL_TAG 0
#define POOL_FLAG_NON_PAGED 0
#define TraceWarn(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define TRACE_NETADAPTER 0
#define AP6256_ENABLE_WDI
#define AP6256_WDI_TLV_IHV_DATA 189u
#define AP6256_STATION_PORT 0u
#define NDIS_STATUS_INVALID_DATA ((LONG)0xc0010015)
#define Ap6256FwRunning 2u
struct _AP6256_PNO_STATE;
struct Device { int PnoLock; BOOLEAN FirmwareEnhancedPnoSupported, FirmwarePnoGscanSupported, FirmwarePnoExtendedEvents; _AP6256_PNO_STATE* PnoState; PVOID Fdo; ULONG FirmwareState; BOOLEAN DatapathRunning; };
typedef Device* PAP6256_DEVICE_CONTEXT;
typedef int KIRQL;
static void KeInitializeSpinLock(KSPIN_LOCK* l) { *l=0; }
static void KeAcquireSpinLock(KSPIN_LOCK* l,KIRQL* old) { assert(!*l);*l=1;*old=0; }
static void KeReleaseSpinLock(KSPIN_LOCK* l,KIRQL) { assert(*l);*l=0; }
static void Ap6256LockAcquire(int* l) { assert(!*l);*l=1; }
static void Ap6256LockRelease(int* l) { assert(*l);*l=0; }
static ULONGLONG clock_now;
static ULONGLONG KeQueryInterruptTime() { return clock_now; }
struct AP6256_WORKITEM { void (*Routine)(void*); void* Context; BOOLEAN Queued; };
static NTSTATUS Ap6256WorkItemCreate(AP6256_WORKITEM* w,PVOID,void (*r)(void*),void* p) { *w={r,p,FALSE};return 0; }
static void Ap6256WorkItemEnqueue(AP6256_WORKITEM* w) { w->Queued=TRUE; }
static void drain(AP6256_WORKITEM* w) { for(int i=0;w->Queued && i<16;++i){w->Queued=FALSE;w->Routine(w->Context);}assert(!w->Queued); }
static void Ap6256WorkItemFlush(AP6256_WORKITEM* w) { drain(w); }
static void Ap6256WorkItemDestroy(AP6256_WORKITEM* w) { drain(w); }
static int live;static bool oom;
static void* ExAllocatePool2(ULONG,SIZE_T n,ULONG) { if(oom)return nullptr;++live;return calloc(1,n); }
static void ExFreePoolWithTag(void* p,ULONG) { assert(p && live);--live;free(p); }
'''
MOCK = r'''
struct Wifi { Device* Ctx; };typedef Wifi* PAP6256_WIFI;
struct Request { struct { struct { ULONG OutputBufferLength,BytesNeeded,BytesWritten;PVOID InformationBuffer; } METHOD_INFORMATION; } DATA; };typedef Request* AP6256_REQUEST;
static NTSTATUS completion;
static void Ap6256CompleteRequest(Wifi*,Request*,NTSTATUS s) { completion=s; }
static NTSTATUS Ap6256NdisToNtStatus(LONG s) { return s; }
static NTSTATUS Ap6256TdlsControl(Device*,const UCHAR*,ULONG,AP6256_TDLS_STATUS*) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256PnoControl(Device*,const UCHAR*,ULONG,AP6256_PNO_STATUS*) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS channel_status;static ULONG invalid_count;static AP6256_PNO_CONFIG factory_config;
static NTSTATUS Ap6256BcdcQueryDcmd(Device* d,UINT32 cmd,PVOID b,ULONG len) {
    assert(d->PnoLock && cmd==BRCMF_C_GET_VALID_CHANNELS && len==260);
    if(channel_status)return channel_status;
    auto* list=(BRCMF_CHANNEL_LIST*)b;list->Count=invalid_count?invalid_count:4;
    list->Channels[0]=1;list->Channels[1]=6;list->Channels[2]=11;list->Channels[3]=36;return 0;
}
static NTSTATUS Ap6256WifiSetNetworkListOffload(Device*,const AP6256_NLO_PARAMS*) { return 0; }
static NTSTATUS Ap6256WifiProgramNetworkListOffload(Device* d,const AP6256_NLO_PARAMS* p,const AP6256_PNO_CONFIG* cfg) {
    assert(d->PnoLock && p->WindowsRequest);factory_config=*cfg;return 0;
}

static ULONG ext_calls,ext_fault;static UCHAR ext_mask[36];
static ULONG delivered;static NTSTATUS delivery_status;static AP6256_BSS delivered_bss;
static NTSTATUS Ap6256NetNloDiscovery(Device* d,AP6256_BSS* b) {
    assert(d->PnoLock && !d->PnoState->Lock);++delivered;delivered_bss=*b;return delivery_status;
}
static std::vector<std::vector<UCHAR>> chunks;static size_t chunk_index;
static NTSTATUS query_status;static bool short_reply,oversize;
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device* d,UINT32 iface,PCSTR name,PVOID b,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    if(!strcmp(name,"event_msgs_ext")) {
        assert(iface==0 && n==36 && ((UCHAR*)b)[0]==1 && ((UCHAR*)b)[2]==18 && ((UCHAR*)b)[3]==18);
        ++ext_calls;memcpy(b,ext_mask,36);*r={TRUE,FALSE,0,22};((UCHAR*)b)[0]=0x65;
        if(ext_fault==1)r->FirmwareReply=FALSE;if(ext_fault==2)r->PayloadLength=21;
        if(ext_fault==3)((UCHAR*)b)[2]=16;if(ext_fault==5 && ext_calls==2)((UCHAR*)b)[20]=0;
        return 0;
    }
    assert(d->PnoLock && !d->PnoState->Lock && iface==0 && !strcmp(name,"pfnlbest") && n==1500);
    if(query_status)return query_status;
    const auto& v=chunks.at(chunk_index++);assert(v.size()<=n);memcpy(b,v.data(),v.size());*r={TRUE,FALSE,0,(ULONG)v.size()};
    if(short_reply)r->PayloadLength=11;if(oversize)r->PayloadLength=1510;return 0;
}
'''
MOCK += r'''
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const void* b,ULONG n) {
    assert(!strcmp(name,"event_msgs_ext") && n==22);auto* p=(const UCHAR*)b;
    assert(p[0]==1 && p[1]==3 && p[2]==18 && p[4]==0x22 && ((p[20]&0xc0)==0xc0 || (p[20]&0xc0)==0));
    if(ext_fault==4)return STATUS_IO_TIMEOUT;memcpy(ext_mask,b,n);return 0;
}
'''
TEST = r'''
static void u16(std::vector<UCHAR>& v,size_t o,UINT16 n) { v[o]=(UCHAR)n;v[o+1]=(UCHAR)(n>>8); }
static void u32(std::vector<UCHAR>& v,size_t o,UINT32 n) { u16(v,o,(UINT16)n);u16(v,o+2,(UINT16)(n>>16)); }
static std::vector<UCHAR> basic(bool batch,UINT32 count=1,UINT32 status=1) {
    ULONG size=batch?52:44;std::vector<UCHAR> v(12+count*size);u32(v,0,1);u32(v,4,status);u32(v,8,count);
    for(ULONG i=0;i<count;++i){ULONG o=12+i*size;v[o]=2;v[o+5]=(UCHAR)(i+1);v[o+6]=36;v[o+7]=4;
        memcpy(v.data()+o+8,"test",4);u16(v,o+(batch?42:40),(UINT16)-55);
        if(batch){u16(v,o+40,0x1234);u32(v,o+44,123456);}else u16(v,o+42,3);}return v;
}
static std::vector<UCHAR> full() {
    std::vector<UCHAR> v(190);u32(v,0,1);u32(v,4,1);u32(v,8,1);v[12]=2;v[17]=1;v[18]=36;v[19]=4;
    memcpy(v.data()+20,"test",4);u16(v,52,(UINT16)-55);size_t o=56;u32(v,o,109);u32(v,o+4,134);
    v[o+8]=2;v[o+13]=1;u16(v,o+14,100);u16(v,o+16,0x431);v[o+18]=4;memcpy(v.data()+o+19,"test",4);
    u16(v,o+72,42);v[o+88]=36;u16(v,o+78,(UINT16)-55);v[o+96]=1;u16(v,o+116,128);u32(v,o+120,6);
    v[o+128]=0;v[o+129]=4;memcpy(v.data()+o+130,"test",4);return v;
}
static std::vector<UCHAR> swc(UINT32 count,UINT32 total,UCHAR first=1) {
    std::vector<UCHAR> v(12+18*count);u32(v,0,1);u32(v,4,count);u32(v,8,total);
    for(ULONG i=0;i<count;++i){ULONG o=12+18*i;u16(v,o,3);u16(v,o+2,36);v[o+4]=2;v[o+9]=(UCHAR)(first+i);
        for(ULONG j=0;j<8;++j)v[o+10+j]=(UCHAR)(-60+(int)j);}return v;
}
static NTSTATUS decode(UINT32 e,std::vector<UCHAR> v,AP6256_PNO_RESULT& r,UINT32 index=0) {
    UINT32 count,status;return Ap6256PnoDecodeResult(e,v.data(),(ULONG)v.size(),index,&r,&count,&status);
}
static void publish(Device& d,UINT32 e,const std::vector<UCHAR>& v) { Ap6256PnoResultEvent(&d,e,v.data(),(ULONG)v.size()); }
static AP6256_PNO_RESULT_REPLY read(Device& d,UINT16 op=6) {
    AP6256_PNO_REQUEST h={AP6256_PNO_MAGIC,1,op};AP6256_PNO_RESULT_REPLY r;
    assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&r)==0);return r;
}
static void reset(Device& d,BOOLEAN windows=TRUE,BOOLEAN batch=TRUE) {
    Ap6256LockAcquire(&d.PnoLock);Ap6256PnoResultsReset(&d);AP6256_NLO_PARAMS p={};p.WindowsRequest=windows;
    p.Enable=TRUE;p.NetworkCount=1;p.Networks[0].SsidLength=4;memcpy(p.Networks[0].Ssid,"test",4);
    Ap6256PnoResultsCommit(&d,&p,batch);Ap6256LockRelease(&d.PnoLock);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    AP6256_PNO_RESULT r;assert(decode(33,basic(false),r)==0 && r.Kind==1 && r.AgeMilliseconds==3000 && r.Rssi==-55);
    assert(decode(PNO_BATCH_WIRE,basic(true),r)==0 && r.Kind==2 && r.Flags==0x1234 && r.AgeMilliseconds==123456);
    assert(decode(33,full(),r)==0 && r.Kind==3 && r.Channel==36 && r.IesLength==6 && r.BeaconPeriod==100);
    assert(decode(134,full(),r)==0 && decode(135,swc(1,2),r)==0 && r.RssiHistory[0]==-60 && r.RssiHistory[7]==-53);
    assert(decode(33,basic(false,2),r,1)==0 && r.Bssid[5]==2);auto f=full();
    for(auto off:{0u,4u,8u,56u,60u,176u}){auto bad=f;u32(bad,off,0xffffffff);assert(decode(33,bad,r)<0);}
    for(auto off:{12u,19u,74u,64u,185u}){auto bad=f;bad[off]=255;assert(decode(33,bad,r)<0);}
    auto bad=f;u16(bad,172,127);assert(decode(33,bad,r)<0);bad=basic(false);bad.push_back(0);assert(decode(33,bad,r)<0);
    assert(decode(135,swc(2,1),r)<0 && decode(135,swc(1,17),r)<0);
    UCHAR* g=(UCHAR*)VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);assert(g);DWORD protect;
    assert(VirtualProtect(g+4096,4096,PAGE_NOACCESS,&protect));
    for(UINT32 e:{33u,PNO_BATCH_WIRE,134u,135u}) {
        auto fixture=e==PNO_BATCH_WIRE?basic(true):e==135?swc(2,2):f;
        for(ULONG n=0;n<fixture.size();++n){UCHAR* p=g+4096-n;memcpy(p,fixture.data(),n);UINT32 count,status;
            NTSTATUS code=Ap6256PnoDecodeResult(e,p,n,0,&r,&count,&status);
            if(e==33 && n==56)assert(code==0 && r.Kind==1);else assert(code<0);}
    }
    assert(VirtualFree(g,0,MEM_RELEASE));std::mt19937 random(206);
    for(int i=0;i<5000;++i){std::vector<UCHAR> v(random()%512);for(auto& b:v)b=(UCHAR)random();(void)decode(i%2?33:135,v,r);}
    Device d={};d.FirmwareEnhancedPnoSupported=TRUE;
    ext_calls=0;Ap6256PnoEnableResultEvents(&d);
    assert(!d.FirmwarePnoExtendedEvents && ext_calls==0);
    d.FirmwarePnoGscanSupported=TRUE;
    for(ULONG fault=0;fault<6;++fault) {
        memset(ext_mask,0,36);ext_mask[0]=1;ext_mask[2]=ext_mask[3]=18;ext_mask[4]=0x22;ext_fault=fault;ext_calls=0;
        Ap6256PnoEnableResultEvents(&d);assert(d.FirmwarePnoExtendedEvents==(fault==0));
    }
    ext_fault=0;assert(Ap6256PnoResultsInitialize(&d)==0);reset(d);
    auto noIes=f;noIes.resize(184);u32(noIes,60,128);u32(noIes,176,0);
    publish(d,33,noIes);assert(!d.PnoState->HaveBss);
    publish(d,33,f);assert(!delivered);drain(&d.PnoState->Work);assert(delivered==1 && delivered_bss.Channel==36 && delivered_bss.IesLength==6);
    publish(d,33,f);drain(&d.PnoState->Work);assert(delivered==1);auto reply=read(d);
    assert(reply.Result.Kind==3 && reply.Result.IesLength==0 && reply.Remaining==2);assert(read(d).Result.Kind==3 && read(d).Result.Kind==3 && read(d).Result.Kind==0);
    reset(d);Ap6256PnoResultsPower(&d,FALSE);publish(d,33,f);drain(&d.PnoState->Work);assert(delivered==1);
    Ap6256PnoResultsPower(&d,TRUE);assert(delivered==1);drain(&d.PnoState->Work);assert(delivered==2);
    reset(d);publish(d,33,f);reset(d);drain(&d.PnoState->Work);assert(delivered==2 && read(d).Result.Kind==0);
    delivery_status=STATUS_UNSUCCESSFUL;publish(d,33,f);drain(&d.PnoState->Work);assert(delivered==3 && !d.PnoState->Indicated);
    delivery_status=0;Ap6256PnoResultsPower(&d,TRUE);drain(&d.PnoState->Work);assert(delivered==4);
    reset(d,FALSE);publish(d,134,f);drain(&d.PnoState->Work);assert(delivered==4 && read(d).Result.Kind==3);
    reset(d);publish(d,135,swc(1,2));assert(read(d).Result.Kind==0);publish(d,135,swc(1,2,2));
    assert(read(d).Result.Kind==4 && read(d).Result.Kind==4 && read(d).Result.Kind==0);
    publish(d,135,swc(1,2));publish(d,135,swc(1,2));assert(read(d).Dropped==1 && d.PnoState->SwcCount==0);
    publish(d,135,swc(1,2));clock_now+=110000000;publish(d,135,swc(1,2,2));assert(read(d).Result.Kind==0);
    reset(d);for(int i=0;i<20;++i)publish(d,33,basic(false));reply=read(d);assert(reply.Dropped==4 && reply.Remaining==15);
    reset(d);chunks={basic(true,2,0),basic(true,1,1)};chunk_index=0;publish(d,57,{});assert(chunk_index==0);
    drain(&d.PnoState->Work);assert(chunk_index==2 && read(d).Remaining==2);
    reset(d);chunk_index=0;Ap6256PnoResultsPower(&d,FALSE);publish(d,57,{});drain(&d.PnoState->Work);assert(chunk_index==0);
    Ap6256PnoResultsPower(&d,TRUE);drain(&d.PnoState->Work);assert(chunk_index==2);
    reset(d);chunks={basic(true,1,1)};chunks[0].resize(1500);chunk_index=0;
    assert(read(d,7).Remaining==1 && read(d).Result.Kind==2);
    reset(d);chunks={basic(true,0,1)};chunk_index=0;assert(read(d,7).Remaining==0);
    chunks={basic(true,1,1)};short_reply=true;chunk_index=0;AP6256_PNO_REQUEST h={AP6256_PNO_MAGIC,1,7};
    assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&reply)<0);short_reply=false;
    oversize=true;chunk_index=0;assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&reply)<0);oversize=false;
    query_status=STATUS_IO_TIMEOUT;assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&reply)==STATUS_IO_TIMEOUT);query_status=0;
    chunks=std::vector<std::vector<UCHAR>>(8,basic(true,1,0));chunk_index=0;
    assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&reply)==STATUS_BUFFER_OVERFLOW && chunk_index==8);
    reset(d);oom=true;assert(Ap6256PnoResultControl(&d,(UCHAR*)&h,8,&reply)==STATUS_INSUFFICIENT_RESOURCES);oom=false;
    reset(d);publish(d,33,f);
    Wifi wifi={&d};Request request={};WDI_MESSAGE_HEADER wh={};UCHAR buffer[sizeof(wh)+4+2144]={};
    UCHAR ihv[]={189,0,8,0,'P','N','O','1',1,0,6,0};
    request.DATA.METHOD_INFORMATION.InformationBuffer=buffer;request.DATA.METHOD_INFORMATION.OutputBufferLength=sizeof(buffer)-1;
    Ap6256HandleIhvRequest(&wifi,&request,&wh,ihv,sizeof(ihv));assert(completion==STATUS_BUFFER_TOO_SMALL && d.PnoState->Count==1);
    request.DATA.METHOD_INFORMATION.OutputBufferLength=sizeof(buffer);Ap6256HandleIhvRequest(&wifi,&request,&wh,ihv,sizeof(ihv));
    assert(completion==0 && !d.PnoState->Count && buffer[sizeof(wh)+2]==0x60 && buffer[sizeof(wh)+3]==8);
    assert(request.DATA.METHOD_INFORMATION.BytesWritten==sizeof(buffer));
    AP6256_NLO_PARAMS native={};native.Enable=native.WindowsRequest=TRUE;native.NetworkCount=1;
    d.FirmwareState=Ap6256FwRunning;d.DatapathRunning=TRUE;UINT16 hints[]={36,6};
    assert(Ap6256WifiSetWindowsNetworkListOffload(&d,&native,hints,2)==0);
    assert(factory_config.ChannelCount==4 && factory_config.Channels[0]==36 && factory_config.Channels[1]==6 && factory_config.Channels[2]==1 && factory_config.Channels[3]==11);
    assert(factory_config.Gscan.Buckets[0].EndIndex==3 && factory_config.Gscan.Buckets[0].FrequencyMultiple==1);
    hints[0]=165;assert(Ap6256WifiSetWindowsNetworkListOffload(&d,&native,hints,2)==STATUS_INVALID_PARAMETER);hints[0]=36;
    invalid_count=65;assert(Ap6256WifiSetWindowsNetworkListOffload(&d,&native,hints,2)==STATUS_DEVICE_PROTOCOL_ERROR);invalid_count=0;
    channel_status=STATUS_IO_TIMEOUT;assert(Ap6256WifiSetWindowsNetworkListOffload(&d,&native,hints,2)==STATUS_IO_TIMEOUT);channel_status=0;
    d.FirmwarePnoExtendedEvents=TRUE;
    Ap6256PnoResultsPower(&d,FALSE);assert((ext_mask[20]&0xc0)==0);
    Ap6256PnoResultsPower(&d,TRUE);assert((ext_mask[20]&0xc0)==0xc0);
    reset(d);publish(d,33,f);Ap6256PnoResultsQuiesce(&d);assert(delivered==4);
    publish(d,33,f);assert(!d.PnoState->Work.Queued);Ap6256PnoResultsDestroy(&d);assert(!live && !d.PnoState);
    puts("PASS: production PFN v1 decoders, 5000 malformed fixtures, guard pages, SWC fragments/duplicates/expiry, bounded queue, once per request, Dx deferral/reset, delivery retry, asynchronous batch query bounds/failures and teardown");
}
'''

def main():
    out = output_dir('pno-results')
    out.mkdir(parents=True, exist_ok=True)
    h = read_source_text(ROOT / 'src/common/pno.h')
    w = read_source_text(ROOT / 'src/common/wifi_ops.h')
    b = read_source_text(ROOT / 'src/common/bcdc.h')
    dec = '\n'.join(re.findall('^#define (?:AP6256_SCAN_IE_MAX|AP6256_NLO_\\w+|BRCMF_E_PFN_\\w+)\\s+[^\\n]+', w + '\n' + read_source_text(ROOT / 'src/common/sdpcm.h'), re.M)) + '\n'
    for name in ('AP6256_NLO_NETWORK', 'AP6256_NLO_PARAMS', 'AP6256_BSS'):
        dec += c.declaration(w, name)
    dec += c.declaration(read_source_text(ROOT / 'src/common/wifi_ops.c'), 'BRCMF_CHANNEL_LIST')
    dec += re.search('^#define BRCMF_C_GET_VALID_CHANNELS.*', read_source_text(ROOT / 'src/common/sdpcm.h'), re.M)[0] + '\n'
    dec += 'typedef UINT16 WDI_PORT_ID;typedef LONG NDIS_STATUS;\n' + c.declaration(read_source_text(c.INC / 'km/dot11wdi.h'), 'WDI_MESSAGE_HEADER')
    tdls = read_source_text(ROOT / 'src/common/tdls.h')
    dec += re.search('^#define AP6256_TDLS_MAGIC.*', tdls, re.M)[0] + '\n' + c.declaration(tdls, 'AP6256_TDLS_STATUS')
    dec += re.sub('^#(?:pragma once|include.*).*\\n', '', h, flags=re.M).split('_IRQL_requires_max_')[0]
    dec += c.declaration(b, 'AP6256_BCDC_QUERY_RESULT')
    source = re.sub('^#include.*\\n|^_Use_decl_annotations_.*\\n', '', read_source_text(ROOT / 'src/common/pno_results.c'), flags=re.M)
    a = source.index('typedef struct _AP6256_PNO_STATE')
    z = source.index('static VOID PnoPush', a)
    state = source[a:z]
    source = source[:a] + source[z:]
    defines = '\n'.join(re.findall('^#define PNO_.*', source, re.M)) + '\n'
    source = re.sub('^#define PNO_.*\\n', '', source, flags=re.M)
    extra = ''.join((c.function(ROOT, 'wifi_ops.c', n) for n in ('Ap6256WifiPnoChannels', 'Ap6256WifiSetWindowsNetworkListOffload')))
    extra += c.function(ROOT, 'netadapter.c', 'Ap6256HandleIhvRequest')
    cpp = out / 'tests.cpp'
    write_text(cpp, PRE + dec + defines + state + MOCK + source + extra + TEST, encoding='utf-8')
    cmd = [str(c.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(c.VC / 'include')]
    cmd += ['/I' + str(c.INC / f) for f in ('ucrt', 'shared', 'um')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(c.VC / 'lib/x64'), '/LIBPATH:' + str(c.LIB / 'ucrt/x64'), '/LIBPATH:' + str(c.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(cmd, indent=2), encoding='utf-8')
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
