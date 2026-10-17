# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise production counter decoding, WDI field mapping and event masks.'
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

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value
control = module('test-control-retry')
cap = module('test-wdi-capabilities')
PRE = '#define WIN32_NO_STATUS\n' + cap.PREAMBLE.split('struct Device {')[0] + r'''
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <vector>
#include <string>
#include <utility>
#include <stdarg.h>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define POOL_FLAG_NON_PAGED 0
#define AP6256_POOL_TAG 0
static ULONG allocations;
static bool fail_allocation;
static void* ExAllocatePool2(int,size_t n,int) {
    if(fail_allocation)return nullptr;
    ++allocations;return calloc(1,n);
}
static void ExFreePoolWithTag(void* p,int) {assert(allocations);--allocations;free(p);}
static ULONGLONG test_time=1;
static ULONGLONG KeQueryInterruptTime() {return test_time;}
static std::vector<std::string> logs;
static void trace(const char* f,...) {
    char b[512];va_list a;va_start(a,f);vsnprintf(b,sizeof(b),f,a);va_end(a);logs.emplace_back(b);
}
#undef TraceDiag
#define TraceDiag(...) trace(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceInfo(t,...) trace(__VA_ARGS__)
struct Device {
    BOOLEAN FirmwareEnhancedPnoSupported=FALSE; ULONGLONG MacCountersTracedAt=0; BOOLEAN FirmwareNativeManagement=FALSE,FirmwareServicePatchVerified=FALSE; };
typedef Device* PAP6256_DEVICE_CONTEXT;

static void Ap6256SaeFirmwarePrepare(Device*) {}
'''
MOCKS = r'''
enum Fault {None,Unsupported,Transport,ShortReply,BadLength,ShortMask,LostBit,SetFailure,
            InputHeaderResidue,HeaderVersionTwo,ReadbackShort};
static Fault event_fault;
static std::vector<UCHAR> legacy(16),extended(128),counter_reply;
static ULONG ext_gets,ext_sets,counter_gets,legacy_gets;
static bool short_legacy_readback;
static NTSTATUS counter_status;
static ULONG counter_received;
static void reset() {
    legacy.assign(16,0);legacy[15]=0x80;
    extended.assign(128,0);extended[21]=0x40;
    ext_gets=ext_sets=counter_gets=legacy_gets=0;event_fault=None;short_legacy_readback=false;
    counter_status=STATUS_SUCCESS;counter_received=0;counter_reply.clear();logs.clear();
    fail_allocation=false;test_time=1;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 iface,PCSTR name,PVOID out,ULONG len,
                                         PAP6256_BCDC_QUERY_RESULT result) {
    assert(iface==0);*result={};std::vector<UCHAR> data;
    if(!strcmp(name,"event_msgs")) {
        assert(len==16);++legacy_gets;data=legacy;
        if(short_legacy_readback && legacy_gets==2)data.resize(3);
        result->PayloadLength=(ULONG)data.size();
    } else if(!strcmp(name,"counters")) {
        ++counter_gets;if(!NT_SUCCESS(counter_status))return counter_status;
        data=counter_reply;result->PayloadLength=counter_received;
    } else {
        assert(!strcmp(name,"event_msgs_ext"));++ext_gets;
        assert(len==132 && ((UCHAR*)out)[0]==1 && ((UCHAR*)out)[2]==128 && ((UCHAR*)out)[3]==128);
        if(event_fault==Transport)return STATUS_DEVICE_REMOVED;
        if(event_fault==Unsupported) {
            result->FirmwareReply=TRUE;result->FirmwareError=TRUE;result->FirmwareStatus=-23;
            return STATUS_UNSUCCESSFUL;
        }
        data={1,0,128,0};data.insert(data.end(),extended.begin(),extended.end());
        if(event_fault==ShortReply)data.resize(3);


        if(event_fault==InputHeaderResidue) {
            data={'e','v',18,'n'};
            data.insert(data.end(),extended.begin(),extended.begin()+18);
            data.resize(147);
        }
        if(event_fault==HeaderVersionTwo)data[0]=2;
        if(event_fault==BadLength)data[2]=129;
        if(event_fault==ShortMask)data.resize(21);
        if(event_fault==LostBit && ext_gets==2)data[4+17]&=~0x20;
        if(event_fault==ReadbackShort && ext_gets==2)data.resize(21);
        result->PayloadLength=(ULONG)data.size();
    }
    result->FirmwareReply=TRUE;
    memset(out,0,len);memcpy(out,data.data(),min(size_t(len),data.size()));
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,PVOID in,ULONG len) {
    auto p=(UCHAR*)in;
    if(!strcmp(name,"event_msgs")) {
        assert(len==16);legacy.assign(p,p+len);return STATUS_SUCCESS;
    }
    assert(!strcmp(name,"event_msgs_ext"));++ext_sets;
    unsigned mask_length=event_fault==InputHeaderResidue?18:128;
    assert(len==4+mask_length && p[0]==1 && p[1]==1 && p[2]==mask_length && p[3]==0);
    for(unsigned i=0;i<mask_length;i++)assert(p[4+i]==(i==17?0x20:0));
    if(event_fault==SetFailure)return STATUS_UNSUCCESSFUL;
    for(unsigned i=0;i<mask_length;i++)extended[i]|=p[4+i];
    return STATUS_SUCCESS;
}
static void put16(std::vector<UCHAR>& v,size_t off,unsigned x) {
    v.at(off)=UCHAR(x);v.at(off+1)=UCHAR(x>>8);
}
static void put32(std::vector<UCHAR>& v,size_t off,UINT32 x) {
    for(unsigned i=0;i<4;i++)v.at(off+i)=UCHAR(x>>(8*i));
}
static std::vector<UCHAR> legacy_fixture() {
    std::vector<UCHAR> v(844);put16(v,0,10);put16(v,2,844);



    for(auto e:std::vector<std::pair<unsigned,UINT32>>{
        {20,17},{76,23},{92,29},{112,31},{444,37},{476,41},{492,43},
        {496,47},{500,3},{508,2},{512,19},{516,53},{520,59},{672,61},
        {660,67},{756,71}})put32(v,e.first,e.second);

    put32(v,196,0xdeadbeef);put32(v,652,0xbadf00d);put32(v,664,0xcafebabe);
    return v;
}
static std::vector<UCHAR> xtlv_fixture() {
    std::vector<UCHAR> v(528);put16(v,0,30);put16(v,2,524);
    put16(v,4,999);put16(v,6,1);v[8]=0xab;
    put16(v,12,256);put16(v,14,512);
    for(unsigned i=0;i<128;i++)put32(v,16+4*i,1000+i);
    return v;
}
'''
TEST = r'''
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    reset();Device c;UINT32 decoded[128];ULONG count;
    auto v=legacy_fixture();
    assert(Ap6256DecodeMacCounters(v.data(),(ULONG)v.size(),decoded,&count)==STATUS_SUCCESS);
    assert(count==128 && decoded[4]==17 && decoded[18]==23 && decoded[22]==29 && decoded[27]==31);
    assert(decoded[53]==37 && decoded[61]==41 && decoded[65]==43 && decoded[66]==47);
    assert(decoded[67]==3 && decoded[69]==2 && decoded[70]==19 && decoded[71]==53 && decoded[72]==59);
    assert(decoded[105]==67 && decoded[106]==61 && decoded[127]==71);
    WDI_MAC_STATISTICS_CONTAINER peer={};WDI_PHY_STATISTICS_CONTAINER phy={};
    apply_statistics(decoded,peer,&phy);
    assert(peer.CCMPDecryptErrors==3 && peer.WEPUndecryptableCount==2 && peer.CCMPFormatErrors==43);
    assert(peer.CCMPReplays==47 && peer.TKIPICVErrorCount==59 && peer.WEPICVErrorCount==19);
    assert(peer.DecryptFailureCount==41 && peer.DecryptSuccessCount==53 && phy.MaxTXLifetimeExceededCount==61);
    puts("PASS: v10 ABI seams and independent cipher counters mapped to genuine WDI containers");

    for(ULONG n=0;n<v.size();n++) {
        memset(decoded,0xff,sizeof(decoded));count=999;
        assert(!NT_SUCCESS(Ap6256DecodeMacCounters(v.data(),n,decoded,&count)));
        assert(count==0);for(auto x:decoded)assert(x==0);
    }
    for(unsigned n:{4u,675u,677u,845u,65535u}) {
        auto b=v;put16(b,2,n);assert(!NT_SUCCESS(Ap6256DecodeMacCounters(b.data(),(ULONG)b.size(),decoded,&count)));
        assert(count==0);
    }
    put16(v,2,676);v.resize(676);
    assert(Ap6256DecodeMacCounters(v.data(),676,decoded,&count)==STATUS_SUCCESS && count==107 && decoded[106]==61);
    auto x=xtlv_fixture();
    assert(Ap6256DecodeMacCounters(x.data(),(ULONG)x.size(),decoded,&count)==STATUS_SUCCESS && count==128);
    for(unsigned i=0;i<128;i++)assert(decoded[i]==1000+i);
    for(ULONG n=0;n<x.size();n++)assert(!NT_SUCCESS(Ap6256DecodeMacCounters(x.data(),n,decoded,&count)) && count==0);
    for(auto b:std::vector<std::vector<UCHAR>>{x,x,x,x}) {
        static unsigned index=0;
        switch(index++) {
        case 0:put16(b,2,12);break;
        case 1:put16(b,14,511);break;
        case 2:b.resize(536);put16(b,2,532);put16(b,528,256);put16(b,530,4);break;
        case 3:b.resize(529);put16(b,2,525);break;
        }
        assert(!NT_SUCCESS(Ap6256DecodeMacCounters(b.data(),(ULONG)b.size(),decoded,&count)) && count==0);
    }
    put16(x,0,29);assert(Ap6256DecodeMacCounters(x.data(),(ULONG)x.size(),decoded,&count)==STATUS_NOT_SUPPORTED);
    puts("PASS: v10/v30 short replies, declared bounds, alignment, duplicate and unsupported layouts");
    reset();counter_reply=legacy_fixture();counter_received=(ULONG)counter_reply.size();
    assert(Ap6256WifiGetMacCounters(&c,decoded,&count)==STATUS_SUCCESS && count==128 && !allocations);
    assert(counter_gets==1 && logs.size()==1);
    assert(Ap6256WifiGetMacCounters(&c,decoded,&count)==STATUS_SUCCESS && logs.size()==1);
    test_time+=50000000;assert(Ap6256WifiGetMacCounters(&c,decoded,&count)==STATUS_SUCCESS && logs.size()==2);
    counter_received=100;assert(!NT_SUCCESS(Ap6256WifiGetMacCounters(&c,decoded,&count)) && count==0 && !allocations);
    counter_status=STATUS_DEVICE_REMOVED;
    assert(Ap6256WifiGetMacCounters(&c,decoded,&count)==STATUS_DEVICE_REMOVED && count==0 && !allocations);
    fail_allocation=true;
    assert(Ap6256WifiGetMacCounters(&c,decoded,&count)==STATUS_INSUFFICIENT_RESOURCES && count==0 && !allocations);
    puts("PASS: query received length, transport/allocation failure, cleanup and trace rate limit");
    reset();assert(Ap6256WifiConfigureEvents(&c)==STATUS_SUCCESS);
    assert((legacy[6]&0x0e)==0x0e);
    assert(legacy[15]==0x80 && (legacy[9]&0x28)==0x28 && ext_sets==1 && ext_gets==2);
    assert((legacy[11]&0x10)==0x10);
    assert(extended[21]==0x40 && extended[17]==0x20);
    for(Fault f:{InputHeaderResidue,HeaderVersionTwo}) {
        reset();event_fault=f;
        assert(Ap6256WifiConfigureEvents(&c)==STATUS_SUCCESS);
        assert(ext_sets==1 && ext_gets==2 && extended[17]==0x20);
        assert(legacy[15]==0x80 && extended[21]==0x40);
        assert(logs.back().find("141=1")!=std::string::npos);
    }
    puts("PASS: successful GET with unreturned header fields, including historical's 101/18/147 reply");
    reset();short_legacy_readback=true;
    assert(Ap6256WifiConfigureEvents(&c)==STATUS_SUCCESS && ext_sets==1 && ext_gets==2);
    assert(logs[0].find("readback unverified")!=std::string::npos);
    for(Fault f:{Unsupported,Transport,ShortReply,BadLength,ShortMask,LostBit,SetFailure,ReadbackShort}) {
        reset();event_fault=f;
        assert(Ap6256WifiConfigureEvents(&c)==STATUS_SUCCESS && (legacy[9]&0x28)==0x28);
        assert(legacy[15]==0x80 && extended[21]==0x40);
        if(f==LostBit)assert(ext_sets==1 && ext_gets==2 && logs.back().find("141=0")!=std::string::npos);
        else if(f==ReadbackShort)assert(ext_sets==1 && ext_gets==2 && logs.back().find("unverified")!=std::string::npos);
        else if(f==SetFailure)assert(ext_sets==1 && ext_gets==1);
        else assert(ext_sets==0 && ext_gets==1);
    }
    puts("PASS: additive event141 subscription/readback, legacy preservation and optional-query failures");
    reset();c.FirmwareNativeManagement=TRUE;
    assert(Ap6256WifiConfigureEvents(&c)==STATUS_SUCCESS);
    reset();short_legacy_readback=true;
    assert(Ap6256WifiConfigureEvents(&c)==STATUS_DEVICE_PROTOCOL_ERROR);
    puts("PASS: patched firmware requires verified event-75 subscription");
}
'''

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--mapping-source', type=Path, help='Substitute a saved netadapter.c for the cipher-mapping negative control')
    parser.add_argument('--events-source-root', type=Path, help='Substitute saved event-mask functions for the firmware-header negative control')
    parser.add_argument('--output-dir', type=Path, default=output_dir('firmware-statistics'))
    args = parser.parse_args()
    (root, out) = (args.source_root.resolve(), args.output_dir.resolve())
    out.mkdir(parents=True, exist_ok=True)
    text = PRE
    for (file, pattern) in [('sdpcm.h', '^#define BRCMF_E_\\w+[^\\n]*'), ('wifi_ops.h', '^#define AP6256_(?:MAC_COUNTER|COUNTERS_)\\w*[^\\n]*'), ('netadapter.c', '^#define AP6256_CNT_\\w+[^\\n]*')]:
        text += '\n'.join(re.findall(pattern, read_source_text(root / 'src' / file, encoding='utf-8'), re.M)) + '\n'
    text += control.declaration(read_source_text(root / 'src/common/bcdc.h', encoding='utf-8'), 'AP6256_BCDC_QUERY_RESULT') + MOCKS
    for name in ('Ap6256EventMaskSet', 'Ap6256WifiConfigureRrmEvents', 'Ap6256WifiConfigureEvents', 'Ap6256DecodeMacCounters', 'Ap6256WifiGetMacCounters'):
        event_root = args.events_source_root or root
        text += control.function(event_root if name in ('Ap6256EventMaskSet', 'Ap6256WifiConfigureRrmEvents', 'Ap6256WifiConfigureEvents') else root, 'wifi_ops.c', name)
    net = read_source_text(args.mapping_source or root / 'src/common/netadapter.c', encoding='utf-8')
    begin = net.index('        if (haveMac) {', net.index('macCounterCount > AP6256_CNT_TX_LIFETIME'))
    end = net.index('\n        if (haveIf)', begin)
    body = net[begin:end].replace('if (haveMac)', 'if (true)')
    text += 'static void apply_statistics(UINT32* macCounters, WDI_MAC_STATISTICS_CONTAINER& peer, WDI_PHY_STATISTICS_CONTAINER* current) {\n' + body + '\n}\n'
    source = out / 'tests.cpp'
    write_text(source, text + TEST, encoding='utf-8')
    command = [str(control.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(control.VC / 'include')]
    command += ['/I' + str(control.INC / f) for f in ('ucrt', 'shared', 'um', 'km', 'km/wlan/1.0')]
    command += [str(source), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(control.VC / 'lib/x64'), '/LIBPATH:' + str(control.LIB / 'ucrt/x64'), '/LIBPATH:' + str(control.LIB / 'um/x64')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
