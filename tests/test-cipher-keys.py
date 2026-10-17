# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise production WDI key requests and the FullMAC IGTK wire contract.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import native_key_fixture
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
#include <array>
#include <map>
#include <string>
#include <stdarg.h>
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xc0010015)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#undef TraceDiag
static void trace(const char*,...) {}
#define TraceDiag(...) trace(__VA_ARGS__)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceInfo(t,...) trace(__VA_ARGS__)
#define TraceWarn(t,...) trace(__VA_ARGS__)
#define TraceError(t,...) trace(__VA_ARGS__)
#undef RtlEqualMemory
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
struct Device {
    int HostFipsLock=0;AP6256_FIPS_SESSION HostFipsSessions[16]={};UINT32 HostFipsBlockedMask=0,HostFipsRetiredMask=0;
    struct { BOOLEAN FirmwareReady,Started;UINT32 IfIndex,Mode;
        LONG DataTrace[Ap6256GoDataStageCount],Ipv4Trace[2][Ap6256GoDataStageCount]; } Go;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static NTSTATUS eapolBarrierStatus;
static unsigned eapolBarrierCalls;
ULONGLONG KeQueryInterruptTime(){return 0;}
NTSTATUS Ap6256WlfcWaitEapol(Device*,UINT32) {++eapolBarrierCalls;return eapolBarrierStatus;}
struct Wifi { Device* Ctx;TLV_CONTEXT TlvContext; };
typedef Wifi* PAP6256_WIFI;
typedef void* AP6256_REQUEST;
struct Call { UINT32 iface,command;std::vector<UCHAR> bytes; };
static std::vector<Call> calls;
static std::map<std::string,std::vector<UCHAR>> installed;
static NTSTATUS request_status;
static LONG fail_id=-1;
static bool fail_delete,fail_command,fail_iovar;
static unsigned authorizations,deauthorizations;
struct SeedCall {UINT32 Id;BOOLEAN Igtk,Valid;std::vector<UCHAR> Key,Sequence;};
static std::vector<SeedCall> seeds;


static VOID Ap6256WifiSeedGroupKey(Device*,UINT32 id,BOOLEAN igtk,BOOLEAN valid,const UCHAR* key,const UCHAR* seq) {
    assert((igtk?(id==4 || id==5):(id<4)) && (valid?key!=nullptr:key==nullptr));
    seeds.push_back({id,igtk,valid,valid?std::vector<UCHAR>(key,key+16):std::vector<UCHAR>{},seq?std::vector<UCHAR>(seq,seq+6):std::vector<UCHAR>{}});
}
static const UCHAR peer[]={0x02,0x17,0x23,0x41,0x53,0x65},zero[6]={};
static UINT32 le32(const UCHAR* p) {return (UINT32)p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24);}
static std::string identity(UINT32 iface,const UCHAR* p) {
    auto key=std::to_string(iface)+":"+std::to_string(le32(p))+":";
    key.append((const char*)p+156,6);return key;
}
static NTSTATUS write_key(UINT32 iface,const UCHAR* p,ULONG n,bool iovar) {
    assert(n==164);bool deleting=le32(p+4)==0;
    if((deleting && fail_delete) || (!deleting && (LONG)le32(p)==fail_id) ||
        (iovar?fail_iovar:fail_command))return STATUS_IO_TIMEOUT;
    auto id=identity(iface,p);
    if(deleting)installed.erase(id);else installed[id]={p,p+n};return 0;
}
static NTSTATUS Ap6256BcdcSetDcmdIf(Device*,UINT32 iface,UINT32 command,const VOID* data,ULONG n) {
    auto p=(const UCHAR*)data;calls.push_back({iface,command,{p,p+n}});
    if(command==45)return write_key(iface,p,n,false);
    assert(n==6);
    if(command==121)authorizations++;else {assert(command==122);deauthorizations++;}
    return 0;
}
static NTSTATUS Ap6256BcdcSetIovarIf(Device*,UINT32 iface,const char* name,const VOID* data,ULONG n) {
    assert(!strcmp(name,"wsec_key"));auto p=(const UCHAR*)data;
    calls.push_back({iface,263,{p,p+n}});return write_key(iface,p,n,true);
}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN enabled) {assert(enabled);return 0;}
static VOID Ap6256WifiTracePeerAuthorization(Device*,UINT32,const UCHAR*) {}
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s) {request_status=s;}
static NTSTATUS Ap6256WifiSetDefaultKeyIdIf(Device*,UINT32,ULONG) {assert(false);return 0;}


static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) {return FALSE;}
static NTSTATUS Ap6256HostCipherAddKeys(Device*,ULONG,const AP6256_HOST_CIPHER_KEY*,ULONG) {
    return STATUS_NOT_SUPPORTED;
}
static NTSTATUS Ap6256HostCipherDeleteKeys(Device*,ULONG,const AP6256_HOST_CIPHER_KEY*,ULONG) {
    return STATUS_NOT_SUPPORTED;
}
#define AP6256_POOL_TAG 0x48434b54u
#define POOL_FLAG_NON_PAGED 1
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
static std::map<void*,SIZE_T> keyCopies;
static BOOLEAN failKeyCopy=FALSE;
static void* ExAllocatePool2(ULONG flag,SIZE_T bytes,ULONG tag) {
    assert(flag==POOL_FLAG_NON_PAGED&&tag==AP6256_POOL_TAG);void* p=calloc(1,bytes);
    if(failKeyCopy){failKeyCopy=FALSE;free(p);return nullptr;}
    if(p)keyCopies[p]=bytes;return p;
}
static VOID ExFreePoolWithTag(void* p,ULONG tag) {
    assert(tag==AP6256_POOL_TAG&&keyCopies.count(p));
    for(SIZE_T i=0;i<keyCopies[p];++i)assert(((UCHAR*)p)[i]==0);
    keyCopies.erase(p);free(p);
}
'''
TEST = r'''
static void reset() {
    calls.clear();installed.clear();seeds.clear();request_status=STATUS_NOT_SUPPORTED;fail_id=-1;
    fail_delete=fail_command=fail_iovar=false;authorizations=deauthorizations=0;
}
static void add(Wifi* w,WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* p,UINT16 port=2) {
    UINT8* b=nullptr;ULONG n=0;WDI_MESSAGE_HEADER h={};h.PortId=port;
    assert(GenerateWdiSetAddCipherKeysToIhv(p,0,&w->TlvContext,&n,&b)==0);
    Ap6256HandleKeyRequest(w,&h,nullptr,WDI_SET_ADD_CIPHER_KEYS,b,n);FreeGenerated(b);
}
static void del(Wifi* w,WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* p,UINT16 port=2) {
    UINT8* b=nullptr;ULONG n=0;WDI_MESSAGE_HEADER h={};h.PortId=port;
    assert(GenerateWdiSetDeleteCipherKeysToIhv(p,0,&w->TlvContext,&n,&b)==0);
    Ap6256HandleKeyRequest(w,&h,nullptr,WDI_SET_DELETE_CIPHER_KEYS,b,n);FreeGenerated(b);
}
static void verify_igtk(const Call& c,UINT32 iface,UINT32 id,const UCHAR* address,const UCHAR* key,const UCHAR* ipn) {
    assert(c.iface==iface && (c.command==45 || c.command==263));auto p=c.bytes.data();
    assert(c.bytes.size()==164 && le32(p)==id && le32(p+4)==16);
    assert(le32(p+112)==4 && le32(p+116)==(!memcmp(address,zero,6)?2u:0u));
    assert(le32(p+132)==1 && !memcmp(p+156,address,6) && !memcmp(p+8,key,16));
    UINT64 actual=((UINT64)le32(p+140)<<16)|p[144]|((UINT64)p[145]<<8),expected=0;
    for(unsigned i=0;i<6;i++)expected|=(UINT64)ipn[i]<<(8*i);
    assert(actual==expected);
    for(unsigned i=24;i<112;i++)assert(!p[i]);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    Device d={};d.Go.FirmwareReady=TRUE;d.Go.IfIndex=7;d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;
    Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
    UCHAR key[32];for(unsigned i=0;i<sizeof(key);i++)key[i]=(UCHAR)(0xa0+i);
    const UCHAR ipn[]={0x13,0x25,0x37,0x49,0x5b,0x6d};
    for(UINT32 iface:{0u,7u})for(NTSTATUS failure:{STATUS_IO_TIMEOUT,STATUS_DEVICE_NOT_READY}) {
        reset();eapolBarrierStatus=failure;eapolBarrierCalls=0;
        AP6256_CCMP_KEY pending={};pending.IfIndex=iface;pending.Pairwise=TRUE;pending.PeerAddress[0]=2;
        assert(Ap6256WifiAddCcmpKey(&d,&pending)==failure && calls.empty() && seeds.empty() && eapolBarrierCalls==1);
        AP6256_BIP_KEY management={};management.IfIndex=iface;management.KeyId=4;management.KeyLength=16;
        eapolBarrierCalls=0;
        assert(Ap6256WifiAddBipKey(&d,&management)==failure && calls.empty() && seeds.empty() && eapolBarrierCalls==1);
    }
    eapolBarrierStatus=0;
    WDI_SET_ADD_CIPHER_KEYS_CONTAINER add_entries[3]={};
    WDI_SET_ADD_CIPHER_KEYS_PARAMETERS a={};a.SetCipherKey.pElements=add_entries;a.SetCipherKey.ElementCount=3;
    auto& ig=a.SetCipherKey.pElements[0];
    ig.Optional.CipherKeyID_IsPresent=TRUE;ig.CipherKeyID.CipherKeyID=4;
    ig.CipherKeyTypeInfo.CipherAlgorithm=WDI_CIPHER_ALGO_BIP;
    ig.CipherKeyTypeInfo.KeyType=WDI_CIPHER_KEY_TYPE_IGTK;
    ig.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_INBOUND;
    ig.Optional.BIPKey_IsPresent=TRUE;ig.BIPKey.pElements=key;ig.BIPKey.ElementCount=16;
    ig.Optional.ReceiveSequenceCount_IsPresent=TRUE;
    memcpy(ig.ReceiveSequenceCount.ReceiveSequenceCount,ipn,6);
    auto& ck=a.SetCipherKey.pElements[1];
    ck.Optional.CipherKeyID_IsPresent=TRUE;ck.CipherKeyID.CipherKeyID=2;
    ck.CipherKeyTypeInfo.CipherAlgorithm=WDI_CIPHER_ALGO_CCMP;
    ck.CipherKeyTypeInfo.KeyType=WDI_CIPHER_KEY_TYPE_GROUP_KEY;
    ck.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_BOTH;
    ck.Optional.CCMPKey_IsPresent=TRUE;ck.CCMPKey.pElements=key;ck.CCMPKey.ElementCount=16;
    ck.Optional.ReceiveSequenceCount_IsPresent=TRUE;memcpy(ck.ReceiveSequenceCount.ReceiveSequenceCount,ipn,6);
    auto& bad=a.SetCipherKey.pElements[2];bad.CipherKeyTypeInfo.CipherAlgorithm=WDI_CIPHER_ALGO_GCMP;
    bad.CipherKeyTypeInfo.KeyType=WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
    bad.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_BOTH;
    bad.Optional.PeerMacAddress_IsPresent=TRUE;memcpy(bad.PeerMacAddress.Address,peer,6);
    WDI_SET_DELETE_CIPHER_KEYS_CONTAINER delete_entry[1]={};
    WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS x={};x.CipherKeyInfo.pElements=delete_entry;x.CipherKeyInfo.ElementCount=1;
    auto& di=x.CipherKeyInfo.pElements[0];di.Optional.CipherKeyID_IsPresent=TRUE;
    di.CipherKeyID.CipherKeyID=4;di.CipherKeyTypeInfo=ig.CipherKeyTypeInfo;
    a.SetCipherKey.ElementCount=1;
    for(UINT16 port: {(UINT16)0,(UINT16)2})for(ULONG id: {4u,5u})for(int addressed=0;addressed<2;addressed++) {
        reset();ig.CipherKeyID.CipherKeyID=id;di.CipherKeyID.CipherKeyID=id;
        ig.Optional.PeerMacAddress_IsPresent=di.Optional.PeerMacAddress_IsPresent=(BOOLEAN)addressed;
        memcpy(ig.PeerMacAddress.Address,peer,6);memcpy(di.PeerMacAddress.Address,peer,6);
        add(&w,&a,port);assert(request_status==0 && calls.size()==1 && installed.size()==1);
        verify_igtk(calls[0],port?7:0,id,addressed?peer:zero,key,ipn);
        assert(seeds.size()==(port?0u:1u));
        if(!port){assert(seeds[0].Id==id && seeds[0].Igtk && seeds[0].Valid && seeds[0].Key==std::vector<UCHAR>(key,key+16) && seeds[0].Sequence==std::vector<UCHAR>(ipn,ipn+6));}
        assert(!authorizations && !deauthorizations);
        del(&w,&x,port);assert(request_status==0 && calls.size()==2 && installed.empty());
        auto p=calls[1].bytes.data();assert(le32(p)==id && !le32(p+4) && !le32(p+112));
        assert(!memcmp(p+156,addressed?peer:zero,6) && calls[1].iface==(port?7u:0u));
        assert(!authorizations && !deauthorizations);
        assert(seeds.size()==(port?0u:2u));if(!port)assert(!seeds[1].Valid && seeds[1].Id==id && seeds[1].Igtk && seeds[1].Key.empty());
    }
    ig.CipherKeyID.CipherKeyID=di.CipherKeyID.CipherKeyID=4;
    ig.Optional.PeerMacAddress_IsPresent=di.Optional.PeerMacAddress_IsPresent=FALSE;


    reset();fail_command=true;add(&w,&a);assert(request_status==0 && calls.size()==2);
    assert(calls[0].bytes==calls[1].bytes);verify_igtk(calls[1],7,4,zero,key,ipn);
    fail_command=false;fail_delete=true;del(&w,&x);
    assert(request_status==STATUS_IO_TIMEOUT && installed.size()==1 && calls.size()==4);
    assert(calls[2].bytes==calls[3].bytes);fail_delete=false;del(&w,&x);assert(installed.empty());
    reset();fail_command=fail_iovar=true;add(&w,&a);
    assert(request_status==STATUS_IO_TIMEOUT && installed.empty() && calls.size()==2);


    for(int cleanup_fails=0;cleanup_fails<2;cleanup_fails++) {
        reset();a.SetCipherKey.ElementCount=2;fail_id=2;fail_delete=!!cleanup_fails;
        add(&w,&a);assert(request_status==STATUS_IO_TIMEOUT);
        if(!cleanup_fails)assert(installed.empty());else assert(installed.size()==1);
        assert(calls.size()==(cleanup_fails?5u:4u) && le32(calls[3].bytes.data())==4 && !le32(calls[3].bytes.data()+4));
        for(auto& c:calls)assert(c.iface==7);
    }
    reset();a.SetCipherKey.ElementCount=3;add(&w,&a);
    assert(request_status==STATUS_NOT_SUPPORTED && installed.empty() && calls.size()==4);
    assert(le32(calls[2].bytes.data())==2 && le32(calls[3].bytes.data())==4);

    reset();a.SetCipherKey.ElementCount=1;add(&w,&a,0);assert(installed.size()==1);
    fail_id=2;a.SetCipherKey.ElementCount=2;add(&w,&a,2);assert(installed.size()==1);
    assert(installed.begin()->first.rfind("0:4:",0)==0);

    a.SetCipherKey.ElementCount=1;
    for(unsigned mode=0;mode<10;mode++) {
        reset();auto oldOptional=ig.Optional;auto oldInfo=ig.CipherKeyTypeInfo;
        if(mode==0)ig.Optional.CipherKeyID_IsPresent=FALSE;
        if(mode==1)ig.CipherKeyID.CipherKeyID=0;
        if(mode==2)ig.CipherKeyID.CipherKeyID=6;
        if(mode==3)ig.CipherKeyTypeInfo.KeyType=WDI_CIPHER_KEY_TYPE_GROUP_KEY;
        if(mode==4)ig.CipherKeyTypeInfo.Direction=(WDI_CIPHER_KEY_DIRECTION)0;
        if(mode==5)ig.Optional.BIPKey_IsPresent=FALSE;
        if(mode==6)ig.BIPKey.ElementCount=15;
        if(mode==7)ig.BIPKey.ElementCount=32;
        if(mode==8)ig.Optional.ReceiveSequenceCount_IsPresent=FALSE;
        if(mode==9)ig.BIPKey.pElements=nullptr;
        assert(!NT_SUCCESS(Ap6256AddKeys(&w,7,&a)) && calls.empty());
        ig.Optional=oldOptional;ig.CipherKeyTypeInfo=oldInfo;ig.CipherKeyID.CipherKeyID=4;
        ig.BIPKey.ElementCount=16;ig.BIPKey.pElements=key;
    }
    reset();di.CipherKeyTypeInfo.KeyType=WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
    del(&w,&x);assert(!NT_SUCCESS(request_status) && calls.empty());di.CipherKeyTypeInfo=ig.CipherKeyTypeInfo;
    di.Optional.CipherKeyID_IsPresent=FALSE;assert(!NT_SUCCESS(Ap6256DeleteKeys(&w,7,&x)) && calls.empty());
    di.Optional.CipherKeyID_IsPresent=TRUE;di.CipherKeyID.CipherKeyID=6;
    del(&w,&x);assert(!NT_SUCCESS(request_status) && calls.empty());di.CipherKeyID.CipherKeyID=4;
    reset();add(&w,&a,1);assert(!NT_SUCCESS(request_status) && calls.empty());
    d.Go.FirmwareReady=FALSE;add(&w,&a,2);assert(!NT_SUCCESS(request_status) && calls.empty());d.Go.FirmwareReady=TRUE;
    WDI_MESSAGE_HEADER header={};header.PortId=2;
    UCHAR malformed[]={0x52,0,0xff,0xff};Ap6256HandleKeyRequest(&w,&header,nullptr,WDI_SET_ADD_CIPHER_KEYS,malformed,sizeof(malformed));
    assert(!NT_SUCCESS(request_status) && calls.empty());


    if(w.TlvContext.PeerVersion>=WDI_VERSION_1_1_9)for(bool management:{false,true}) {
        WDI_SET_ADD_CIPHER_KEYS_CONTAINER unsupported={};
        WDI_SET_ADD_CIPHER_KEYS_PARAMETERS one={};one.SetCipherKey.pElements=&unsupported;one.SetCipherKey.ElementCount=1;
        unsupported.CipherKeyTypeInfo.CipherAlgorithm=management?WDI_CIPHER_ALGO_BIP_GMAC_256:WDI_CIPHER_ALGO_GCMP_256;
        unsupported.CipherKeyTypeInfo.KeyType=management?WDI_CIPHER_KEY_TYPE_IGTK:WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
        unsupported.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_BOTH;
        unsupported.Optional.CipherKeyID_IsPresent=TRUE;unsupported.CipherKeyID.CipherKeyID=management?4:0;
        unsupported.Optional.PeerMacAddress_IsPresent=TRUE;memcpy(unsupported.PeerMacAddress.Address,peer,6);
        unsupported.Optional.ReceiveSequenceCount_IsPresent=TRUE;
        memcpy(unsupported.ReceiveSequenceCount.ReceiveSequenceCount,ipn,6);
        if(management){unsupported.Optional.BIP_GMAC_256Key_IsPresent=TRUE;unsupported.BIP_GMAC_256Key.pElements=key;unsupported.BIP_GMAC_256Key.ElementCount=32;}
        else {unsupported.Optional.GCMP_256Key_IsPresent=TRUE;unsupported.GCMP_256Key.pElements=key;unsupported.GCMP_256Key.ElementCount=32;}
        reset();add(&w,&one);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
    }


    d.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;
    a.SetCipherKey.pElements=&ck;a.SetCipherKey.ElementCount=1;
    for(UINT16 port:{(UINT16)0,(UINT16)2})for(bool pairwise:{false,true})for(ULONG id:{0u,3u}) {
        UINT32 iface=port?7:0;auto& session=d.HostFipsSessions[iface];session.Generation=123;session.IfIndex=(UCHAR)iface;
        memcpy(session.Bssid,peer,6);ck.CipherKeyID.CipherKeyID=id;di.CipherKeyID.CipherKeyID=id;
        ck.CipherKeyTypeInfo.CipherAlgorithm=WDI_CIPHER_ALGO_CCMP;
        ck.CipherKeyTypeInfo.KeyType=pairwise?WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY:WDI_CIPHER_KEY_TYPE_GROUP_KEY;
        ck.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_BOTH;di.CipherKeyTypeInfo=ck.CipherKeyTypeInfo;
        ck.Optional.PeerMacAddress_IsPresent=di.Optional.PeerMacAddress_IsPresent=(BOOLEAN)pairwise;
        memcpy(ck.PeerMacAddress.Address,peer,6);memcpy(di.PeerMacAddress.Address,peer,6);
        reset();add(&w,&a,port);assert(request_status==0&&installed.empty()&&seeds.empty());
        assert(calls.size()==(pairwise?1u:0u)&&authorizations==(pairwise?1u:0u));
        if(pairwise)assert(calls[0].command==121&&calls[0].iface==iface&&calls[0].bytes==std::vector<UCHAR>(peer,peer+6));
        del(&w,&x,port);assert(request_status==0&&installed.empty()&&seeds.empty());
        assert(calls.size()==(pairwise?2u:0u)&&deauthorizations==(pairwise?1u:0u));
        d.HostFipsBlockedMask=1u<<iface;reset();add(&w,&a,port);assert(request_status==STATUS_DEVICE_NOT_READY&&calls.empty());
        del(&w,&x,port);assert(request_status==STATUS_DEVICE_NOT_READY&&calls.empty());
        d.HostFipsRetiredMask=1u<<iface;del(&w,&x,port);assert(request_status==0&&calls.empty());
        add(&w,&a,port);assert(request_status==STATUS_DEVICE_NOT_READY&&calls.empty());
        d.HostFipsBlockedMask=d.HostFipsRetiredMask=0;
    }
    puts("PASS: real Microsoft key codec keeps Host FIPS keys on the host; STA/client controlled-port, ambiguous failure and late retired deletion checks");
    ig.BIPKey.pElements=nullptr;ig.BIPKey.ElementCount=0;ck.CCMPKey.pElements=nullptr;ck.CCMPKey.ElementCount=0;
    a.SetCipherKey.pElements=nullptr;a.SetCipherKey.ElementCount=0;
    x.CipherKeyInfo.pElements=nullptr;x.CipherKeyInfo.ElementCount=0;
    puts("PASS: real WDI IGTK install/delete dispatch, FullMAC cipher/flags/48-bit IPN, ID 4/5 and STA/group isolation, command fallback/failures, mixed-key rollback, malformed descriptors and TLVs");
}
'''

def build_source(source_root=ROOT):
    (cap, hot, tx) = (module(n) for n in ('test-wdi-capabilities', 'test-hotspot', 'test-wdi-transmit'))
    hot.ROOT = source_root
    src = source_root / 'src'
    ctx = read_source_text(src / 'ap6256.h', encoding='utf-8')
    wh = read_source_text(src / 'wifi_ops.h', encoding='utf-8')
    wc = read_source_text(src / 'wifi_ops.c', encoding='utf-8')
    sd = read_source_text(src / 'sdpcm.h', encoding='utf-8')
    text = cap.PREAMBLE.split('struct Device {')[0].replace('assert(context == 0); free(p);', '(void)context; free(p);')
    text += tx.declaration(ctx, 'AP6256_GO_DATA_STAGE')
    for (source, pattern) in ((ctx, '^#define AP6256_(?:STATION_PORT|GROUP_PORT|DISCOVERY_PORT)[^\\n]+'), (wh, '^#define AP6256_(?:WDI_OPMODE_P2P_GO|WDI_OPMODE_P2P_CLIENT|BIP_KEY_MAX)[^\\n]+'), (wc, '^#define BRCMF_(?:CRYPTO_ALGO_AES_CCM|PRIMARY_KEY)[^\\n]+'), (sd, '^#define BRCMF_C_(?:SET_KEY|SCB_AUTHORIZE|SCB_DEAUTHORIZE)\\s+[^\\n]+')):
        text += '\n'.join(re.findall(pattern, source, re.M)) + '\n'
    text += read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    text += '#define AP6256_HC_KEY_BYTES 32u\n'
    text += tx.declaration(read_source_text(ROOT / 'src/common/host_cipher_keys.h'), 'AP6256_HOST_CIPHER_KEY')
    text += PRE + tx.declaration(wh, 'AP6256_CCMP_KEY') + tx.declaration(wh, 'AP6256_BIP_KEY')
    text += r'''
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
typedef int KIRQL;
static void KeAcquireSpinLock(int* lock,KIRQL* irql) {assert(!*lock);*lock=1;*irql=0;}
static void KeReleaseSpinLock(int* lock,KIRQL) {assert(*lock);*lock=0;}
'''
    from driver_sources import _functions
    fips = _functions(read_source_text(ROOT / 'src/common/host_fips.c'))
    for name in ('Ap6256FipsActive', 'Ap6256FipsSnapshot', 'Ap6256FipsRetired'):
        text += fips[name] + '\n'
    text += '#pragma pack(push,1)\n' + tx.declaration(wc, 'BRCMF_WSEC_KEY') + '#pragma pack(pop)\n'
    text = native_key_fixture.context(text)
    text += native_key_fixture.writer()
    functions = [('wifi_ops.c', 'NTSTATUS Ap6256WifiDeleteCcmpKeyIf(Device* Ctx,UINT32 IfIndex,ULONG KeyId,BOOLEAN Pairwise,const UCHAR* PeerAddress)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiAddCcmpKey(Device* Ctx,PAP6256_CCMP_KEY Key)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiAddBipKey(Device* Ctx,PAP6256_BIP_KEY Key)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiDeleteBipKeyIf(Device* Ctx,UINT32 IfIndex,ULONG KeyId,const UCHAR* PeerAddress)'), ('netadapter.c', 'NTSTATUS Ap6256CommandInterface(Wifi* Wifi,const WDI_MESSAGE_HEADER* Header,UINT32* IfIndex)'), ('netadapter.c', 'NTSTATUS Ap6256ParseHostKey(const WDI_SET_ADD_CIPHER_KEYS_CONTAINER* Source,AP6256_HOST_CIPHER_KEY* Key)'), ('netadapter.c', 'NTSTATUS Ap6256ParseHostDelete(const WDI_SET_DELETE_CIPHER_KEYS_CONTAINER* Source,AP6256_HOST_CIPHER_KEY* Key)'), ('netadapter.c', 'NTSTATUS Ap6256HostKeys(Wifi* Wifi,UINT32 IfIndex,const WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* Add,const WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* Delete)'), ('netadapter.c', 'NTSTATUS Ap6256AddKeys(Wifi* Wifi,UINT32 IfIndex,WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* Parameters)'), ('netadapter.c', 'NTSTATUS Ap6256DeleteKeys(Wifi* Wifi,UINT32 IfIndex,WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* Parameters)'), ('netadapter.c', 'VOID Ap6256HandleKeyRequest(Wifi* Wifi,PWDI_MESSAGE_HEADER Header,AP6256_REQUEST Request,UINT16 MessageId,const UCHAR* Tlv,ULONG TlvLength)')]
    for (file, signature) in functions:
        name = re.search('(Ap6256\\w+)\\(', signature)[1]
        text += signature + '\n' + hot.body(file, name) + '\n'
    return text + TEST

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, default=output_dir('cipher-keys'))
    args = parser.parse_args()
    tx = module('test-wdi-transmit')
    text = build_source(args.source_root)
    args.output.mkdir(parents=True, exist_ok=True)
    cpp = args.output / 'tests.cpp'
    write_bytes(cpp, (contract_preamble() + text).encode())
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(args.output / 'tests.exe'), '/Fo:' + str(args.output / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib', str(tx.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    result = subprocess.run([str(args.output / 'tests.exe')], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    print(result.stdout.decode(errors='replace'))
    result.check_returncode()
if __name__ == '__main__':
    main()
