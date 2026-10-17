# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'WDI requests and group-client results through production functions and codec.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
from wdi_test_support import contract_preamble
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
PRE = r'''
#include <vector>
#include <string>
#include <cstdarg>
#include <cstdio>
#define AP6256_ENABLE_WDI
#define POOL_FLAG_NON_PAGED 64
#define AP6256_POOL_TAG 1
#define TraceInfo(...) ((void)0)
#undef TraceVerbose
#define TraceVerbose(...) ((void)0)
#define TRACE_NETADAPTER 0
#define MAXULONG 0xffffffffUL
static std::string adapter_warning;
static void TraceWarn(unsigned,const char* format,...) {
    char message[512];va_list args;va_start(args,format);
    vsnprintf(message,sizeof(message),format,args);va_end(args);adapter_warning=message;
}
#define TraceDiag(...) ((void)0)
#define TraceError(...) ((void)0)
#define NT_SUCCESS(s) ((LONG)(s)>=0)
#define STATUS_SUCCESS ((LONG)0)
#define STATUS_UNSUCCESSFUL ((LONG)0xc0000001)
#define STATUS_NOT_SUPPORTED ((LONG)0xc00000bb)
#define STATUS_INVALID_DEVICE_STATE ((LONG)0xc0000184)
#define STATUS_DEVICE_NOT_READY ((LONG)0xc00000a3)
#define STATUS_INVALID_BUFFER_SIZE ((LONG)0xc0000206)
#define STATUS_DEVICE_BUSY ((LONG)0x80000011)
#define STATUS_IO_TIMEOUT ((LONG)0xc00000b5)
#define STATUS_INSUFFICIENT_RESOURCES ((LONG)0xc000009a)
#define NDIS_STATUS_INVALID_DATA ((LONG)0xc0010015)
typedef LONG NTSTATUS;
struct Device {
    int PnoLock;
    volatile LONG BeaconLossTimeoutSeconds=0, NloScanMode=0;
    BOOLEAN FirmwareArpOffloadSupported, FirmwareNdOffloadSupported;
    BOOLEAN FirmwareGtkOffloadSupported=FALSE,FirmwareWowlAdapter=FALSE;
    UINT32 WowlCapabilities;
    BOOLEAN FirmwareEnhancedPnoSupported, FirmwarePnoDelaySupported, FirmwarePnoGscanSupported, FirmwarePnoExtendedEvents;
    BOOLEAN FirmwareLinkUp, FirmwareMchanSupported, ConfiguredMacAddressValid;
    UCHAR ConfiguredMacAddress[6], MacAddress[6];
    struct {
        BOOLEAN Created, Started, ClientSecure, ClientMfp, FirmwareReady;
        UINT32 Mode, IfIndex, Channel;
        UCHAR ClientBssid[6];
    } Go;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi {
    Device* Ctx; TLV_CONTEXT TlvContext;
    int ConnectLock;
    BOOLEAN ArpOffloadValid[AP6256_ARP_OFFLOAD_SLOTS] = {};
    UINT32 ArpOffloadIds[AP6256_ARP_OFFLOAD_SLOTS];
    WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER ArpOffloads[AP6256_ARP_OFFLOAD_SLOTS];
    BOOLEAN PortCreated, ApStarted, GoNativeAssociation;
    UINT32 PortOperationMode, GtkOffloadId;
    BOOLEAN GtkOffloadValid; AP6256_GTK_OFFLOAD GtkOffload={};
    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER NsOffloads[5]={};ULONG NsOffloadCount=0;
    LONG HardwareAvailable, DisallowedBandMask;
    AP6256_SECURITY ApSecurity;
    AP6256_AP_PARAMS GoApParams;
};
typedef Wifi* PAP6256_WIFI;
NTSTATUS Ap6256BuildGtkOffload(Wifi*,const WDI_PM_RSN_KEY_INFO_CONTAINER*,AP6256_GTK_OFFLOAD*) {return STATUS_NOT_SUPPORTED;}
NTSTATUS Ap6256WifiReadGtkOffload(Device*,AP6256_GTK_STATE*) {return STATUS_NOT_SUPPORTED;}
NTSTATUS Ap6256WifiRemoveGtkOffload(Device*) {return STATUS_NOT_SUPPORTED;}
typedef void* AP6256_REQUEST;
struct Call { std::string name; std::vector<UCHAR> bytes; };
static std::vector<Call> calls;
static std::string fail_iovar;
static NTSTATUS request_status;
static unsigned starts, indications, completions;
static AP6256_AP_PARAMS started;
static bool fail_pool;
static unsigned pool_live;
static void* ExAllocatePool2(ULONG,size_t n,ULONG) {
    void* p=fail_pool ? nullptr : calloc(1,n);if(p)pool_live++;return p;
}
static void ExFreePoolWithTag(void* p,ULONG) { assert(p && pool_live);pool_live--;free(p); }
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) { return (NTSTATUS)s; }
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s) { request_status=s;completions++; }
static UINT32 configured_beacon_timeout=4;
static ULONG beacon_payload_bytes=16;
static unsigned beacon_get_calls=0, beacon_set_calls=0;
static int beacon_fault=0;
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const VOID* p,ULONG n) {
    Call c;c.name=name;if(n)c.bytes.assign((const UCHAR*)p,(const UCHAR*)p+n);calls.push_back(c);
    if(!strcmp(name,"bcn_timeout")) {
        assert(n==4);++beacon_set_calls;memcpy(&configured_beacon_timeout,p,4);
        if(beacon_fault==8 && beacon_set_calls==1)return STATUS_IO_TIMEOUT;
    }
    return fail_iovar==name ? STATUS_IO_TIMEOUT : 0;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 iface,PCSTR name,PVOID out,ULONG n,AP6256_BCDC_QUERY_RESULT* reply) {
    assert(!iface && !strcmp(name,"bcn_timeout") && n==4);++beacon_get_calls;
    *reply={TRUE,FALSE,0,beacon_payload_bytes};memcpy(out,&configured_beacon_timeout,4);
    if(beacon_fault==1 && beacon_get_calls==1)return STATUS_IO_TIMEOUT;
    if(beacon_fault==2 && beacon_get_calls==2)return STATUS_IO_TIMEOUT;
    if(beacon_fault==3 && beacon_get_calls==2){UINT32 v=configured_beacon_timeout+1;memcpy(out,&v,4);}
    if(beacon_fault==4 && beacon_get_calls==2)reply->PayloadLength=3;
    if(beacon_fault==5 && beacon_get_calls==2)reply->FirmwareReply=FALSE;
    if(beacon_fault==6 && beacon_get_calls==2){reply->FirmwareError=TRUE;reply->FirmwareStatus=-23;}
    if(beacon_fault==7 && beacon_get_calls==2)reply->PayloadLength=0;
    return 0;
}


static NTSTATUS Ap6256AddArpOffload(Wifi*,const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER*) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256AddNsOffload(Wifi*,const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER*) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256RemoveArpOffloadId(Wifi*,UINT32) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256MboSetBands(Wifi* w,LONG mask,BOOLEAN) { w->DisallowedBandMask=mask;return 0; }
static NTSTATUS Ap6256WifiSetMacAddress(Device*,const UCHAR*) { return 0; }
static VOID Ap6256NetSetMacAddress(Device*) {}
static NTSTATUS Ap6256WifiGetChannel(Device*,UINT32* channel) { *channel=36;return 0; }
static NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 command,PVOID p,ULONG n) {
    assert(command==BRCMF_C_GET_VALID_CHANNELS && n==65*4);
    const UINT32 channels[]={4,1,6,36,44};memcpy(p,channels,sizeof(channels));return 0;
}
static NTSTATUS Ap6256GoStart(Device*,AP6256_AP_PARAMS* p) { started=*p;starts++;return 0; }
static NTSTATUS Ap6256GoStop(Device*) { return 0; }
static BOOLEAN Ap6256TalGoPeerCreate(Device*,const UCHAR*,ULONG) { return TRUE; }
static PVOID Ap6256RequestGetId(AP6256_REQUEST) { return nullptr; }
static VOID Ap6256IndicateP2pGroupChannel(Wifi*,PWDI_MESSAGE_HEADER,PVOID,UINT32 channel) {
    assert(channel==started.Channel && starts && !completions);indications++;
}
static NTSTATUS Ap6256SendIndication(Wifi*,UINT16,PWDI_MESSAGE_HEADER,ULONG,NTSTATUS s,const UCHAR*,ULONG) {
    assert(s==request_status && completions==1);return 0;
}
'''
CLIENT_MOCKS = r'''
#undef RtlEqualMemory
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)


static const UCHAR client_request[]={0x11,0,10,0,0,4,'t','e','s','t'};
static const UCHAR client_response[]={0x11,0,0,0,1,0xc0,1,2,0x82,0x84};
static const UCHAR client_beacon[]={0,0,0,0,0,0,0,0,100,0,0x11,0,0,4,'t','e','s','t'};
enum ClientFault {
    NoFault, BssidQueryFailure, BssidMismatch, ChannelQueryFailure,
    ChannelMismatch, MissingRequest, MissingResponse, PeerRejected,
    MissingBeacon, InitialFailure, DeliveryFailure, CodecOom, FrameOom,
    ClientFaultCount
};
static ClientFault client_fault;
static unsigned client_sends,client_reads;
static bool client_reassoc,client_wmm;
static std::vector<UCHAR> client_result;
static NTSTATUS Ap6256WifiGetBssidIf(Device* d,UINT32 iface,UCHAR* bssid) {
    assert(iface==1 && iface==d->Go.IfIndex);client_reads++;
    memcpy(bssid,d->Go.ClientBssid,6);
    if(client_fault==BssidMismatch)bssid[5]^=1;
    return client_fault==BssidQueryFailure ? STATUS_IO_TIMEOUT : 0;
}
static NTSTATUS Ap6256WifiGetChannelIf(Device* d,UINT32 iface,UINT32* channel) {
    assert(iface==1 && iface==d->Go.IfIndex);client_reads++;
    *channel=client_fault==ChannelMismatch ? 44 : d->Go.Channel;
    return client_fault==ChannelQueryFailure ? STATUS_IO_TIMEOUT : 0;
}
static UCHAR* frameCopy(const UCHAR* bytes,size_t length) {
    auto p=(UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED,length,AP6256_POOL_TAG);
    if(p)memcpy(p,bytes,length);return p;
}
static VOID Ap6256WifiGetAssocFramesIf(Device* d,UINT32 iface,AP6256_ASSOC_FRAMES* f) {
    assert(iface==1 && iface==d->Go.IfIndex);client_reads++;
    if(client_fault!=MissingRequest){
        f->AssocRequest=frameCopy(client_request,sizeof(client_request));
        f->AssocRequestLength=sizeof(client_request);
    }
    if(client_fault!=MissingResponse){
        f->AssocResponse=frameCopy(client_response,sizeof(client_response));
        f->AssocResponseLength=sizeof(client_response);
    }
    if(client_fault!=MissingBeacon){
        f->Beacon=frameCopy(client_beacon,sizeof(client_beacon));
        f->BeaconLength=sizeof(client_beacon);
    }
    f->ReAssociation=client_reassoc;f->WmmNegotiated=client_wmm;
    f->PeerStatusCode=client_fault==PeerRejected ? 17 : 0;
}
static NTSTATUS Ap6256SendGeneratedIndication(Wifi*,UINT16 id,
    const WDI_MESSAGE_HEADER* header,ULONG transaction,PVOID request,const UCHAR* bytes,ULONG length) {
    if(id==WDI_INDICATION_NLO_DISCOVERY) {
        assert(header->PortId==0 && transaction==WDI_TRANSACTION_ID_UNSOLICIT && request==nullptr);
        assert(bytes && length);client_result.assign(bytes,bytes+length);return client_fault==DeliveryFailure ? STATUS_UNSUCCESSFUL : 0;
    }
    assert(id==WDI_INDICATION_ASSOCIATION_RESULT && header->PortId==2 && header->TransactionId==57);
    assert(transaction==WDI_TRANSACTION_ID_UNSOLICIT && request==(PVOID)(ULONG_PTR)123);
    assert(bytes && length);client_result.assign(bytes,bytes+length);client_sends++;
    return client_fault==DeliveryFailure ? STATUS_UNSUCCESSFUL : 0;
}
'''
CLIENT_MOCKS += r'''
static Wifi* nlo_wifi;
static Wifi* Ap6256WifiFromDevice(Device* d) { assert(nlo_wifi && nlo_wifi->Ctx==d);return nlo_wifi; }
static void KeQuerySystemTimePrecise(LARGE_INTEGER* t) { t->QuadPart=123456789000ll; }
static ULONG Ap6256LinkQualityFromRssi(INT16) { return 70; }
'''
TEST = r'''
static UINT32 le32(const UCHAR* p) { return (UINT32)p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24); }
static const UCHAR* tlv(const UCHAR* p,ULONG n,UINT16 tag,ULONG* len) {
    while(n>=4) { UINT16 id=(UINT16)(p[0]|(p[1]<<8)),size=(UINT16)(p[2]|(p[3]<<8));
        assert(size<=n-4);if(id==tag){*len=size;return p+4;}p+=size+4;n-=size+4; }
    return nullptr;
}
static void checkSaeContract(ULONG version) {


    TLV_CONTEXT context={};context.PeerVersion=version;
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};
    const UCHAR peer[]={2,0,0,0,0,1};memcpy(p.BssId.Address,peer,6);
    p.SAERequestType=WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS;
    p.Optional.SAECommitParams_IsPresent=TRUE;
    auto& commit=p.SAECommitParams;
    commit.FiniteCyclicGroup=19;
    UCHAR scalar[32]={1},element[64]={2},rejected[]={20,0,21,0};
    commit.Optional.Scalar_IsPresent=commit.Optional.Element_IsPresent=TRUE;
    commit.Optional.RejectedGroups_IsPresent=TRUE;
    commit.Scalar.pElements=scalar;commit.Scalar.ElementCount=sizeof(scalar);
    commit.Element.pElements=element;commit.Element.ElementCount=sizeof(element);
    commit.RejectedGroups.pElements=rejected;commit.RejectedGroups.ElementCount=sizeof(rejected);
    UCHAR* wire=nullptr;ULONG bytes=0,len=0;
    assert(GenerateWdiSetSaeAuthParamsToIhv(&p,0,&context,&bytes,&wire)==0);
    const UCHAR* value=tlv(wire,bytes,WDI_TLV_SAE_COMMIT_PARAMS,&len);
    assert(!!value==(version>=WDI_VERSION_1_1_10));
    if(value) {
        ULONG n=0;const UCHAR* groups=tlv(value,len,WDI_TLV_SAE_REJECTED_GROUPS,&n);
        assert(groups && n==sizeof(rejected) && !memcmp(groups,rejected,n));
    }
    WDI_SET_SAE_AUTH_PARAMS_COMMAND parsed={};
    assert(ParseWdiSetSaeAuthParamsToIhv(bytes,wire,&context,&parsed)==0);
    assert(parsed.SAERequestType==WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS);
    assert(!!parsed.Optional.SAECommitParams_IsPresent==(version>=WDI_VERSION_1_1_10));
    if(parsed.Optional.SAECommitParams_IsPresent) {
        auto& q=parsed.SAECommitParams;
        assert(q.FiniteCyclicGroup==19 && q.Optional.RejectedGroups_IsPresent);
        assert(q.Scalar.ElementCount==sizeof(scalar) && !memcmp(q.Scalar.pElements,scalar,sizeof(scalar)));
        assert(q.Element.ElementCount==sizeof(element) && !memcmp(q.Element.pElements,element,sizeof(element)));
        assert(q.RejectedGroups.ElementCount==sizeof(rejected) && !memcmp(q.RejectedGroups.pElements,rejected,sizeof(rejected)));
    }
    CleanupParsedWdiSetSaeAuthParamsToIhv(&parsed);FreeGenerated(wire);
}
static void reset() { assert(!pool_live);calls.clear();fail_iovar.clear();fail_pool=false;starts=indications=completions=0;request_status=STATUS_IO_TIMEOUT; }
static void nlo(Wifi& w,int hidden,bool enable=true,bool invalid=false,ULONG delay=0,ULONG iterations=3) {
    WDI_NETWORK_LIST_OFFLOAD_PARAMETERS p={};WDI_SSID_OFFLOAD_CONTAINER ssid={};WDI_ALGO_PAIRS algo={};
    UCHAR name[]={'h','i','d','d','e','n'};
    p.NetworkListOffload.NetworkListOffloadConfig.ulFlags=enable?2:1;
    p.NetworkListOffload.NetworkListOffloadConfig.FastScanIterations=iterations;
    p.NetworkListOffload.NetworkListOffloadConfig.DelayStartInSeconds=delay;
    p.NetworkListOffload.NetworkListOffloadConfig.FastScanPeriodinSeconds=20;
    p.NetworkListOffload.NetworkListOffloadConfig.SlowScanPeriodinSeconds=120;
    p.NetworkListOffload.Optional.SsidOffload_IsPresent=TRUE;
    p.NetworkListOffload.SsidOffload.ElementCount=1;p.NetworkListOffload.SsidOffload.pElements=&ssid;
    algo.AuthAlgorithm=invalid?WDI_AUTH_ALGO_OWE:WDI_AUTH_ALGO_RSNA_PSK;algo.CipherAlgorithm=WDI_CIPHER_ALGO_CCMP;
    ssid.UnicastAlgorithms.ElementCount=1;ssid.UnicastAlgorithms.pElements=&algo;
    ssid.SsidToScan.ElementCount=sizeof(name);ssid.SsidToScan.pElements=name;
    WDI_BAND_CHANNEL_MAPPING_ENTRY hint={WDI_BAND_ID_5000,36,5180000};
    ssid.BandChannelHintList.pElements=&hint;ssid.BandChannelHintList.ElementCount=1;
    ssid.Optional.IsDirectedProbeForHiddenPermitted_IsPresent=hidden>=0;
    ssid.IsDirectedProbeForHiddenPermitted=hidden==1;
    UCHAR* wire=nullptr;ULONG bytes=0;
    assert(GenerateWdiSetNetworkListOffloadToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
    Ap6256HandleSetNetworkListOffload(&w,nullptr,wire,bytes);FreeGenerated(wire);
}
static void start(Wifi& w,bool legacy,WDI_BAND_ID band=WDI_BAND_ID_ANY) {
    WDI_TASK_START_AP_PARAMETERS p={};WDI_AP_BAND_CHANNEL_LIST_CONTAINER bands={};
    UCHAR ssid[]={'t','e','s','t'};WDI_AUTH_ALGORITHM auth=WDI_AUTH_ALGO_RSNA_PSK;
    WDI_CIPHER_ALGORITHM cipher=WDI_CIPHER_ALGO_CCMP;
    p.DesiredSSID.pElements=ssid;p.DesiredSSID.ElementCount=sizeof(ssid);
    p.AuthenticationAlgorithms.pElements=&auth;p.AuthenticationAlgorithms.ElementCount=1;
    p.UnicastCipherAlgorithms.pElements=p.MulticastCipherAlgorithms.pElements=&cipher;
    p.UnicastCipherAlgorithms.ElementCount=p.MulticastCipherAlgorithms.ElementCount=1;
    p.StaticParameters.BeaconPeriod=100;p.StaticParameters.DTIMPeriod=2;
    p.StaticParameters.AcceptNonP2PClients=legacy;p.StaticParameters.ExcludeUnencrypted=TRUE;
    if(band!=WDI_BAND_ID_ANY) {
        p.StaticParameters.MustUseSpecifiedChannels=TRUE;p.Optional.APBandChannelList_IsPresent=TRUE;
        bands.BandID=band;p.APBandChannelList.pElements=&bands;p.APBandChannelList.ElementCount=1;
    }
    UCHAR* wire=nullptr;ULONG bytes=0,len=0;
    assert(GenerateWdiTaskStartApToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
    const UCHAR* fixed=tlv(wire,bytes,0xab,&len);
    assert(fixed && len==(w.TlvContext.PeerVersion>=WDI_VERSION_1_0_10?12u:10u));
    assert(le32(fixed)==100 && le32(fixed+4)==2 && fixed[8]==1);
    if(len==12)assert(!!fixed[10]==legacy && !!fixed[11]==(band!=WDI_BAND_ID_ANY));
    WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=55;
    Ap6256HandleStartAp(&w,nullptr,&h,wire,bytes);FreeGenerated(wire);
}
static void rekey(Wifi& w,ULONG kckLength,ULONG kekLength,bool truncate=false) {


    UCHAR kck[64],kek[64];
    for(unsigned i=0;i<64;i++){kck[i]=(UCHAR)(0x20+i);kek[i]=(UCHAR)(0xa0+i);}
    assert(kckLength<=sizeof(kck) && kekLength<=sizeof(kek));
    WDI_SET_ADD_PM_PROTOCOL_OFFLOAD_PARAMETERS_PARAMETERS p={};
    p.Optional.DOT11RSNREKeyOffload_IsPresent=TRUE;
    auto& info=p.DOT11RSNREKeyOffload.RsnKeyInfo;
    info.ProtocolOffloadId=0x12345678;info.ReplayCounter=0x0102030405060708ull;
    info.KCK_CONTENT.pElements=kck;info.KCK_CONTENT.ElementCount=kckLength;
    info.KEK_CONTENT.pElements=kek;info.KEK_CONTENT.ElementCount=kekLength;
    UCHAR* wire=nullptr;ULONG bytes=0,len=0;
    assert(GenerateWdiSetAddPmProtocolOffloadToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
    const UCHAR* rsn=tlv(wire,bytes,0x63,&len);assert(rsn);
    if(w.TlvContext.PeerVersion>=WDI_VERSION_1_1_6){rsn=tlv(rsn,len,0x148,&len);assert(rsn);}
    if(w.TlvContext.PeerVersion>=WDI_VERSION_1_1_9){
        ULONG n=0;const UCHAR* key=tlv(rsn,len,0x168,&n);
        assert(key && n==kckLength && !memcmp(key,kck,n));
        key=tlv(rsn,len,0x169,&n);assert(key && n==kekLength && !memcmp(key,kek,n));
    } else {

        assert(len==44 && le32(rsn)==0x12345678);
        for(unsigned i=0;i<8;i++)assert(rsn[4+i]==8-i);
        assert(!memcmp(rsn+12,kck,16) && !memcmp(rsn+28,kek,16));
    }
    Ap6256HandleAddPmProtocolOffload(&w,nullptr,wire,bytes-(truncate?1u:0u));
    FreeGenerated(wire);assert(completions==1);
}
static void checkRekey(Wifi& w) {

    AP6256_GTK_OFFLOAD gtk={};gtk.OffloadId=0x12345678;
    gtk.ReplayCounter=0x0102030405060708ull;
    for(unsigned i=0;i<16;i++){gtk.Kck[i]=(UCHAR)(0x20+i);gtk.Kek[i]=(UCHAR)(0xa0+i);}
    w.Ctx->FirmwareGtkOffloadSupported=TRUE;
    gtk.DescriptorVersion=2;gtk.MicKind=1;
    reset();assert(Ap6256WifiAddGtkOffload(w.Ctx,&gtk)==0 && calls.size()==1);
    const auto& c=calls[0];assert(c.name=="wdi_gtk_config" && c.bytes.size()==56);
    for(unsigned i=0;i<16;i++){assert(c.bytes[i]==0x20+i);assert(c.bytes[16+i]==0xa0+i);}
    for(unsigned i=0;i<8;i++)assert(c.bytes[32+i]==i+1);
    assert(le32(c.bytes.data()+40)==2&&le32(c.bytes.data()+44)==1&&le32(c.bytes.data()+52)==gtk.OffloadId);
    reset();fail_iovar="wdi_gtk_config";
    assert(Ap6256WifiAddGtkOffload(w.Ctx,&gtk)==STATUS_IO_TIMEOUT);
    w.Ctx->FirmwareGtkOffloadSupported=FALSE;

    reset();w.GtkOffloadValid=FALSE;w.GtkOffloadId=0;
    rekey(w,16,16);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
    assert(!w.GtkOffloadValid && !w.GtkOffloadId);
    if(w.TlvContext.PeerVersion>=WDI_VERSION_1_1_9){
        for(ULONG n:{1u,15u,17u,24u,32u,64u})for(bool changeKck:{false,true}){
            reset();rekey(w,changeKck?n:16u,changeKck?16u:n);
            assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
            assert(!w.GtkOffloadValid && !w.GtkOffloadId);
        }
    }
    reset();rekey(w,16,16,true);assert(!NT_SUCCESS(request_status) && calls.empty());
    reset();w.PortOperationMode=AP6256_WDI_OPMODE_P2P_GO;rekey(w,16,16);
    assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
    w.PortOperationMode=AP6256_WDI_OPMODE_STA;
}
static void checkClientAssociation(Wifi& w) {
    for(UINT32 channel:{1u,36u})for(bool secure:{false,true})for(bool reassoc:{false,true}){
        for(unsigned fault=0;fault<ClientFaultCount;fault++){
            reset();client_fault=(ClientFault)fault;client_sends=client_reads=0;client_result.clear();
            client_reassoc=reassoc;client_wmm=!reassoc;
            fail_codec=client_fault==CodecOom;fail_pool=client_fault==FrameOom;
            auto& go=w.Ctx->Go;go.Channel=channel;go.IfIndex=1;
            go.ClientSecure=secure;go.ClientMfp=secure && reassoc;
            const UCHAR bssid[]={2,9,8,7,6,5};memcpy(go.ClientBssid,bssid,6);
            WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=57;
            const bool accepted=!!Ap6256ClientAssociation(&w,&h,(PVOID)(ULONG_PTR)123,client_fault!=InitialFailure);
            fail_codec=fail_pool=false;
            assert(accepted==(client_fault==NoFault || client_fault==MissingBeacon));
            assert(!pool_live && calls.empty() && !completions);
            unsigned expectedReads=3;
            if(client_fault==InitialFailure)expectedReads=0;
            if(client_fault==BssidQueryFailure || client_fault==BssidMismatch)expectedReads=1;
            if(client_fault==ChannelQueryFailure || client_fault==ChannelMismatch)expectedReads=2;
            assert(client_reads==expectedReads);
            if(client_fault==CodecOom){assert(!client_sends && client_result.empty());continue;}
            assert(client_sends==1 && !client_result.empty());
            WDI_INDICATION_ASSOCIATION_RESULT_LIST parsed={};
            assert(ParseWdiIndicationAssociationResultFromIhv((ULONG)client_result.size(),client_result.data(),
                &w.TlvContext,&parsed)==0);
            assert(parsed.AssociationResults.ElementCount==1 && parsed.AssociationResults.pElements);
            const auto& result=parsed.AssociationResults.pElements[0];
            assert(!memcmp(result.BSSID.Address,bssid,6));
            assert(result.ActivePhyTypeList.ElementCount==1 && result.ActivePhyTypeList.pElements);
            assert(result.ActivePhyTypeList.pElements[0]==(channel==1 ? WDI_PHY_TYPE_HT : WDI_PHY_TYPE_VHT));


            const bool associated=client_fault==NoFault || client_fault==MissingBeacon || client_fault==DeliveryFailure;
            const auto& p=result.AssociationResultParameters;
            assert(p.AssociationStatus==(associated ? WDI_ASSOC_STATUS_SUCCESS : WDI_ASSOC_STATUS_FAILURE));
            assert(p.BandID==(channel==1 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000));
            assert(p.AuthAlgorithm==(secure ? WDI_AUTH_ALGO_RSNA_PSK : WDI_AUTH_ALGO_80211_OPEN));
            assert(p.UnicastCipherAlgorithm==(secure ? WDI_CIPHER_ALGO_CCMP : WDI_CIPHER_ALGO_NONE));
            assert(p.MulticastDataCipherAlgorithm==p.UnicastCipherAlgorithm);
            assert(p.MulticastMgmtCipherAlgorithm==(secure && reassoc ? WDI_CIPHER_ALGO_BIP : WDI_CIPHER_ALGO_NONE));
            assert(!!p.PortAuthorized==(associated && !secure));
            assert(p.StatusCode==(client_fault==PeerRejected ? 17u : 0u));
            assert(!!p.ReAssociation==(expectedReads==3 && reassoc));
            assert(!!p.WMMQoSEnabled==(expectedReads==3 && client_wmm));
            assert(!!result.Optional.AssociationRequestFrame_IsPresent==associated);
            assert(!!result.Optional.AssociationResponseFrame_IsPresent==associated);
            assert(!!result.Optional.BeaconProbeResponse_IsPresent==(associated && client_fault!=MissingBeacon));
            if(associated){
                assert(result.AssociationRequestFrame.ElementCount==sizeof(client_request));
                assert(!memcmp(result.AssociationRequestFrame.pElements,client_request,sizeof(client_request)));
                assert(result.AssociationResponseFrame.ElementCount==sizeof(client_response));
                assert(!memcmp(result.AssociationResponseFrame.pElements,client_response,sizeof(client_response)));
                if(client_fault!=MissingBeacon){
                    assert(result.BeaconProbeResponse.ElementCount==sizeof(client_beacon));
                    assert(!memcmp(result.BeaconProbeResponse.pElements,client_beacon,sizeof(client_beacon)));
                }
            }
            CleanupParsedWdiIndicationAssociationResultFromIhv(&parsed);
        }
    }
    reset();
}
static void checkNloDelivery(Wifi& w) {
    AP6256_BSS b={};nlo_wifi=&w;client_fault=NoFault;
    b.Bssid[0]=2;b.Bssid[5]=1;b.Channel=36;b.Rssi=-55;b.BeaconPeriod=100;b.Capability=0x431;
    UCHAR ies[]={0,4,'t','e','s','t'};b.IesLength=sizeof(ies);memcpy(b.Ies,ies,sizeof(ies));
    for(bool beacon:{false,true}) {
        b.FromBeacon=beacon;client_result.clear();assert(Ap6256NetNloDiscovery(w.Ctx,&b)==0);
        WDI_INDICATION_NLO_DISCOVERY_PARAMETERS p={};
        assert(ParseWdiIndicationNloDiscoveryFromIhv((ULONG)client_result.size(),client_result.data(),&w.TlvContext,&p)==0);
        assert(p.DeviceDescriptor.ElementCount==1);auto& e=p.DeviceDescriptor.pElements[0];
        assert(e.ChannelInfo.ChannelNumber==36 && e.SignalInfo.RSSI==-55 && e.BSSID.Address[0]==2);
        const auto& frame=beacon ? e.BeaconFrame : e.ProbeResponseFrame;
        assert(frame.ElementCount==18 && frame.pElements[8]==100 && frame.pElements[10]==0x31 && !memcmp(frame.pElements+12,ies,sizeof(ies)));
        assert(e.Optional.BeaconFrame_IsPresent==(beacon?1u:0u) && e.Optional.ProbeResponseFrame_IsPresent==(beacon?0u:1u));
        CleanupParsedWdiIndicationNloDiscoveryFromIhv(&p);
    }
    fail_codec=true;assert(Ap6256NetNloDiscovery(w.Ctx,&b)<0);fail_codec=false;
    client_fault=DeliveryFailure;assert(Ap6256NetNloDiscovery(w.Ctx,&b)==STATUS_UNSUCCESSFUL);client_fault=NoFault;
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    for(ULONG version:{WDI_VERSION_1_0,WDI_VERSION_1_1_9,AP6256_TEST_WDI_VERSION}) {
        Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=version;
        w.PortOperationMode=AP6256_WDI_OPMODE_STA;checkRekey(w);checkNloDelivery(w);
        checkClientAssociation(w);
        d.Go.Created=TRUE;d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;d.FirmwareLinkUp=d.FirmwareMchanSupported=TRUE;
        for(int hidden:{-1,0,1}) {
            reset();nlo(w,hidden);assert(request_status==0 && calls.size()==5);
            assert(calls[0].name=="pfn" && le32(calls[0].bytes.data())==0 && calls[1].name=="pfnclear");
            const auto& net=calls[2];assert(net.name=="pfn_add" && net.bytes.size()==56);
            assert(le32(net.bytes.data())==6 && !memcmp(net.bytes.data()+4,"hidden",6));
            assert(le32(net.bytes.data()+36)==(hidden==1 && version>=WDI_VERSION_1_1_0?4u:0u));
            assert(le32(net.bytes.data()+40)==1 && le32(net.bytes.data()+48)==128 && le32(net.bytes.data()+52)==4);
            assert(calls[3].name=="pfn_set" && calls[3].bytes.size()==24 && le32(calls[3].bytes.data()+4)==20);
            assert(calls[4].name=="pfn" && le32(calls[4].bytes.data())==1);
        }
        reset();nlo(w,1,false);assert(request_status==0 && calls.size()==2);
        reset();nlo(w,1,true,false,1);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
        reset();nlo(w,1,true,false,20,100);assert(request_status==0 &&
            calls[3].bytes[18]==100 && (calls[3].bytes[12]&8)==0);
        reset();nlo(w,1,true,false,120,0);assert(request_status==0 &&
            le32(calls[3].bytes.data()+4)==120 && (calls[3].bytes[12]&8)==0);
        reset();nlo(w,1,true,false,20,0);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
        d.FirmwarePnoDelaySupported=TRUE;
        for(ULONG delay:{1u,30u,MAXUINT32}) {
            reset();nlo(w,1,true,false,delay,100);assert(request_status==0 && calls.size()==6);
            assert(calls[4].name=="pfn_override" && calls[4].bytes.size()==24 &&
                le32(calls[4].bytes.data())==0x444f4e50 && le32(calls[4].bytes.data()+8)==delay &&
                (calls[3].bytes[12]&8)==0 && calls[5].name=="pfn");
        }
        reset();nlo(w,1,true,false,30,0);assert(request_status==0 &&
            le32(calls[3].bytes.data()+4)==120 && le32(calls[4].bytes.data()+8)==30);
        reset();fail_iovar="pfn_override";nlo(w,1,true,false,30);
        assert(request_status==STATUS_IO_TIMEOUT && calls.size()==7);
        for(const auto& call:calls)if(call.name=="pfn")assert(le32(call.bytes.data())==0);
        d.FirmwarePnoDelaySupported=FALSE;
        reset();nlo(w,1,true,false,0,101);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
        reset();nlo(w,1,true,false,0,0);assert(request_status==0 && le32(calls[3].bytes.data()+4)==120);
        reset();nlo(w,1,true,true);assert(!NT_SUCCESS(request_status) && calls.empty());
        reset();fail_iovar="pfn_add";nlo(w,1);assert(request_status==STATUS_IO_TIMEOUT && calls.size()==5);
        reset();fail_pool=true;nlo(w,1);assert(request_status==STATUS_INSUFFICIENT_RESOURCES && calls.empty());
        for(bool legacy:{false,true}) {
            reset();start(w,legacy);assert(request_status==0 && starts==1 && indications==1);
            assert(started.Channel==36 && started.BeaconPeriod==100 && started.DtimPeriod==2);
            assert(!!w.GoApParams.RejectNonP2pClients==(!legacy && version>=WDI_VERSION_1_0_10));
        }
        if(version>=WDI_VERSION_1_0_10) {
            reset();start(w,true,WDI_BAND_ID_5000);assert(request_status==0 && started.Channel==36);
            reset();start(w,true,WDI_BAND_ID_2400);assert(request_status==0 && started.Channel==1);
            d.FirmwareMchanSupported=FALSE;reset();start(w,true,WDI_BAND_ID_2400);
            assert(!NT_SUCCESS(request_status) && !starts && !indications);d.FirmwareMchanSupported=TRUE;
        }


        WDI_SET_FIRMWARE_CONFIGURATION_PARAMETERS p={};p.PLDRSupport=TRUE;
        WDI_LINK_QUALITY_BAR_MAP_PARAMETERS map[6]={};
        p.LinkQualityBarMap.pElements=map;p.LinkQualityBarMap.ElementCount=6;
        UCHAR* wire=nullptr;ULONG bytes=0,len=0;
        assert(GenerateWdiSetAdapterConfigurationToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
        const UCHAR* support=tlv(wire,bytes,0x11a,&len);
        assert(!!support==(version>=WDI_VERSION_1_0_10));if(support)assert(len==1 && support[0]==1);
        reset();Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
        assert(request_status==0 && calls.empty());FreeGenerated(wire);
        for(unsigned optional=0;optional<3;optional++) {
            p.Optional.UnreachableDetectionThreshold_IsPresent=optional==0;
            p.Optional.GroupOwnerResetPolicy_IsPresent=optional==1;
            p.Optional.AdapterNloScanMode_IsPresent=optional==2;
            p.UnreachableDetectionThreshold=10;
            p.GroupOwnerResetPolicy=WDI_P2P_GO_INTERNAL_RESET_POLICY_USE_LAST_CHANNEL;
            p.AdapterNloScanMode=WDI_SCAN_TYPE_ACTIVE_ONLY;
            assert(GenerateWdiSetAdapterConfigurationToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
            reset();adapter_warning.clear();Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
            const char* expected[]={"unreachable threshold","GO internal reset policy","NLO scan mode"};
            assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
            assert(adapter_warning.find(expected[optional])!=std::string::npos);
            FreeGenerated(wire);
        }
        p.Optional.UnreachableDetectionThreshold_IsPresent=TRUE;
        p.Optional.GroupOwnerResetPolicy_IsPresent=FALSE;
        p.Optional.AdapterNloScanMode_IsPresent=TRUE;
        p.UnreachableDetectionThreshold=3000;
        p.AdapterNloScanMode=WDI_SCAN_TYPE_AUTO;
        p.LinkQualityBarMap.ElementCount=2;
        assert(GenerateWdiSetAdapterConfigurationToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
        assert(bytes==(version>=WDI_VERSION_1_0_10?31u:26u));
        w.HardwareAvailable=TRUE;reset();adapter_warning.clear();
        reset();adapter_warning.clear();configured_beacon_timeout=4;
        beacon_get_calls=beacon_set_calls=0;beacon_fault=0;
        d.BeaconLossTimeoutSeconds=0;d.NloScanMode=0;
        Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
        assert(request_status==0 && d.BeaconLossTimeoutSeconds==3 && d.NloScanMode==3);
        assert(configured_beacon_timeout==3 && beacon_set_calls==1 && beacon_get_calls==2);
        for(int fault=1;fault<=8;fault++) {
            reset();adapter_warning.clear();configured_beacon_timeout=4;
            beacon_get_calls=beacon_set_calls=0;beacon_fault=fault;
            d.BeaconLossTimeoutSeconds=4;d.NloScanMode=0;
            Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
            assert(!NT_SUCCESS(request_status) && d.BeaconLossTimeoutSeconds==4 && d.NloScanMode==0);
            assert(configured_beacon_timeout==4 && beacon_set_calls==(fault==1?0u:2u));
            assert(adapter_warning.find("unreachable threshold programming")!=std::string::npos);
        }
        reset();beacon_fault=0;beacon_get_calls=beacon_set_calls=0;
        w.HardwareAvailable=FALSE;configured_beacon_timeout=10;
        Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
        assert(request_status==0 && d.BeaconLossTimeoutSeconds==3 && d.NloScanMode==3);
        assert(!beacon_set_calls && !beacon_get_calls);
        assert(Ap6256WifiRestoreUnreachableThreshold(&d)==0 && configured_beacon_timeout==3);
        reset();nlo(w,1);assert(request_status==0 && d.NloScanMode==3 && calls.size()==5);
        d.NloScanMode=1;reset();nlo(w,1);assert(request_status==STATUS_NOT_SUPPORTED && calls.empty());
        d.NloScanMode=3;reset();nlo(w,1);assert(request_status==0);
        FreeGenerated(wire);d.BeaconLossTimeoutSeconds=0;d.NloScanMode=0;
        p.LinkQualityBarMap.ElementCount=6;
        p.Optional.UnreachableDetectionThreshold_IsPresent=FALSE;
        p.Optional.GroupOwnerResetPolicy_IsPresent=FALSE;
        p.Optional.AdapterNloScanMode_IsPresent=FALSE;
        assert(GenerateWdiSetAdapterConfigurationToIhv(&p,0,&w.TlvContext,&bytes,&wire)==0);
        reset();w.PortCreated=TRUE;adapter_warning.clear();Ap6256HandleAdapterConfiguration(&w,nullptr,wire,bytes);
        assert(request_status==STATUS_INVALID_DEVICE_STATE && adapter_warning.find("port state")!=std::string::npos);
        w.PortCreated=FALSE;FreeGenerated(wire);
        reset();adapter_warning.clear();UCHAR badConfig[]={0xab,0,0xff,0xff};
        Ap6256HandleAdapterConfiguration(&w,nullptr,badConfig,sizeof(badConfig));
        assert(!NT_SUCCESS(request_status) && adapter_warning.find("parse")!=std::string::npos);
        UCHAR malformed[]={0xab,0,0xff,0xff};reset();WDI_MESSAGE_HEADER h={};h.PortId=2;
        Ap6256HandleStartAp(&w,nullptr,&h,malformed,sizeof(malformed));assert(!NT_SUCCESS(request_status) && !starts);
    }

    Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=WDI_VERSION_1_1_8;
    w.PortOperationMode=AP6256_WDI_OPMODE_STA;checkRekey(w);checkNloDelivery(w);
    assert(!pool_live);
    checkSaeContract(WDI_VERSION_1_1_9);
    checkSaeContract(WDI_VERSION_1_1_10);
    checkSaeContract(WDI_VERSION_1_1_12);
    puts("PASS: real WDI 1.0/1.1.9/shipping START_AP, PLDR, NLO, GTK serialization/refusal and group-client association wire/failure cases; SAE H2E parameter conversion at 1.1.10/1.1.12, including rejected groups, and 1.1.9 negative control");
}
'''

def main():
    (cap, hot, tx) = [module(n) for n in ('test-wdi-capabilities', 'test-hotspot', 'test-wdi-transmit')]
    files = {name: read_source_text(ROOT / 'src' / name) for name in ('ap6256.h', 'wifi_ops.h', 'wifi_ops.c', 'sdpcm.h', 'netadapter.c')}
    text = cap.PREAMBLE.split('struct Device {')[0]
    codec_memory = cap.HOST_CODEC_MEMORY.replace('return malloc(n);', 'return fail_codec ? nullptr : malloc(n);')
    assert codec_memory != cap.HOST_CODEC_MEMORY
    text = text.replace(cap.HOST_CODEC_MEMORY, 'static bool fail_codec;\n' + codec_memory)
    for name in ('AP6256_SECURITY', 'AP6256_AP_PARAMS', 'AP6256_NLO_NETWORK', 'AP6256_NLO_PARAMS', 'AP6256_GTK_OFFLOAD', 'AP6256_ASSOC_FRAMES', 'AP6256_BSS'):
        text += tx.declaration(files['wifi_ops.h'], name)
    constants = '\n'.join(re.findall('^#define (?:AP6256_(?:STATION_PORT|GROUP_PORT|SCAN_IE_MAX|ARP_OFFLOAD_SLOTS|WOWL_\\w+|NLO_\\w+|WDI_OPMODE_(?:P2P_GO|STA)|DISALLOW_\\w+)|BRCMF_(?:PFN_\\w+|C_GET_VALID_CHANNELS))\\s+[^\\n]+', '\n'.join(files.values()), re.M)) + '\n'
    wdi_header = read_source_text(tx.INC / 'km/dot11wdi.h')
    constants += re.search('^#define WDI_VERSION_1_1_12\\s+[^\\n]+', wdi_header, re.M)[0] + '\n'
    state = read_source_text(ROOT / 'src/common/wowl.h')
    state = state[state.index('typedef struct _AP6256_GROUP_KEY_STATE'):state.index('C_ASSERT')]
    text = constants + text + tx.declaration(read_source_text(ROOT / 'src/common/bcdc.h'), 'AP6256_BCDC_QUERY_RESULT') + state + PRE + CLIENT_MOCKS
    text += re.sub('^#(?:pragma once|include.*).*\\n', '', read_source_text(ROOT / 'src/common/pno.h'), flags=re.M).split('_IRQL_requires_max_')[0]
    text += r'''
#define STATUS_DATA_ERROR ((LONG)0xc000003e)
#define STATUS_DEVICE_PROTOCOL_ERROR ((LONG)0xc0000186)
static void Ap6256LockAcquire(int* l) { assert(!*l);*l=1; }
static void Ap6256LockRelease(int* l) { assert(*l);*l=0; }
static NTSTATUS Ap6256PnoValidateConfig(const AP6256_PNO_CONFIG*) { assert(false);return STATUS_NOT_SUPPORTED; }
static BOOLEAN Ap6256PnoConfigNeedsGscan(const AP6256_PNO_CONFIG*) { assert(false);return FALSE; }
static NTSTATUS Ap6256PnoApplyConfig(Device*,const AP6256_PNO_CONFIG*) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256PnoGetEnabledLocked(Device*,UINT32*) { assert(false);return STATUS_NOT_SUPPORTED; }


static void Ap6256PnoResultsReset(Device* d) { assert(d->PnoLock); }
static void Ap6256PnoResultsCommit(Device* d,const AP6256_NLO_PARAMS* p,BOOLEAN batch) {
    assert(d->PnoLock && p && !batch);
}
static NTSTATUS Ap6256WifiPnoChannels(Device*,AP6256_PNO_CONFIG*,BOOLEAN) { assert(false);return STATUS_NOT_SUPPORTED; }
static NTSTATUS Ap6256WifiSetNetworkListOffload(Device*,const AP6256_NLO_PARAMS*);


static BOOLEAN Ap6256FipsActive(Device*,UINT32) { return FALSE; }
static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32) { return FALSE; }
static NTSTATUS Ap6256WifiSetWindowsNetworkListOffload(Device* d,const AP6256_NLO_PARAMS* p,const UINT16* h,ULONG n) {
    assert(p->WindowsRequest && n==1 && h[0]==36);
    return Ap6256WifiSetNetworkListOffload(d,p);
}
'''
    for name in ('WLC_SSID', 'BRCMF_PFN_NET', 'BRCMF_PFN_PARAM', 'BRCMF_PFN_INITIAL_DELAY', 'AP6256_NLO_SECURITY', 'BRCMF_GTK_KEY_INFO'):
        text += tx.declaration(files['wifi_ops.c'], name)
    text += re.search('static const AP6256_NLO_SECURITY Ap6256NloSecurity\\[\\] = \\{[\\s\\S]*?\\};', files['wifi_ops.c'])[0] + '\n'
    funcs = [('wifi_ops.c', 'VOID Ap6256WifiFreeAssocFrames(AP6256_ASSOC_FRAMES* Frames)'), ('netadapter.c', 'BOOLEAN Ap6256ClientAssociation(Wifi* Wifi,const WDI_MESSAGE_HEADER* Header,PVOID RequestId,BOOLEAN Success)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiAddGtkOffload(Device* Ctx,const AP6256_GTK_OFFLOAD* Offload)'), ('netadapter.c', 'VOID Ap6256HandleAddPmProtocolOffload(Wifi* Wifi,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('wifi_ops.c', 'const AP6256_NLO_SECURITY* Ap6256WifiNloSecurityFor(UINT32 AuthAlgorithm,UINT32 CipherAlgorithm)'), ('wifi_ops.c', 'BOOLEAN Ap6256WifiNloSecuritySupported(UINT32 AuthAlgorithm,UINT32 CipherAlgorithm)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiClearNetworkListOffloadLocked(Device* Ctx)'), ('wifi_ops.c', 'VOID Ap6256WifiClearNetworkListOffload(Device* Ctx)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiProgramNetworkListOffload(Device* Ctx,const AP6256_NLO_PARAMS* Params,const AP6256_PNO_CONFIG* Config)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiSetNetworkListOffload(Device* Ctx,const AP6256_NLO_PARAMS* Params)'), ('netadapter.c', 'VOID Ap6256HandleSetNetworkListOffload(Wifi* Wifi,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'BOOLEAN Ap6256MacIsValue(const UCHAR* Address,UCHAR Value)'), ('netadapter.c', 'BOOLEAN Ap6256MacIsValidUnicast(const UCHAR* Address)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiValidateUnreachableThreshold(UINT32 ThresholdMs)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiReadBeaconTimeout(Device* Ctx,UINT32* Timeout)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiApplyUnreachableThreshold(Device* Ctx,UINT32 ThresholdMs)'), ('wifi_ops.c', 'NTSTATUS Ap6256WifiRestoreUnreachableThreshold(Device* Ctx)'), ('netadapter.c', 'VOID Ap6256HandleAdapterConfiguration(Wifi* Wifi,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'BOOLEAN Ap6256BandIsMasked(LONG Mask,WDI_BAND_ID BandId)'), ('netadapter.c', 'BOOLEAN Ap6256BandIsDisallowed(Wifi* Wifi,WDI_BAND_ID BandId)'), ('netadapter.c', 'NTSTATUS Ap6256NetNloDiscovery(Device* Ctx,AP6256_BSS* Bss)'), ('netadapter.c', 'BOOLEAN Ap6256ApChannelRequested(const WDI_TASK_START_AP_PARAMETERS* P,UINT32 Channel)'), ('netadapter.c', 'NTSTATUS Ap6256SelectApChannel(Wifi* Wifi,const WDI_TASK_START_AP_PARAMETERS* P,PULONG Channel)'), ('netadapter.c', 'VOID Ap6256HandleStartAp(Wifi* Wifi,AP6256_REQUEST Request,PWDI_MESSAGE_HEADER Header,const UCHAR* Tlv,ULONG TlvLength)')]
    for (file, signature) in funcs:
        name = re.search('(Ap6256\\w+)\\(', signature)[1]
        if name == 'Ap6256NetNloDiscovery':
            enabled = files[file][files[file].rindex('NTSTATUS Ap6256NetNloDiscovery('):]
            body = enabled[enabled.index('{'):].split('\n}', 1)[0] + '\n}'
        else:
            body = hot.body(file, name)
        body = body.replace('= {0};', '= {};')
        text += signature + '\n' + body + '\n'
    from driver_sources import _functions
    sae_only = sys.argv[1:] == ['--sae-only']
    if sys.argv[1:] and (not sae_only):
        raise ValueError('Usage: test-wdi-contract.py [--sae-only]')
    if sae_only:
        text = cap.PREAMBLE.split('struct Device {')[0]
        text += re.search('^#define WDI_VERSION_1_1_12\\s+[^\\n]+', wdi_header, re.M)[0] + '\n'
        text += TEST[TEST.index('static const UCHAR* tlv('):TEST.index('static void reset()')]
        text += r'''
int main() {
    assert(AP6256_TEST_WDI_VERSION == WDI_VERSION_1_1_10);
    checkSaeContract(WDI_VERSION_1_1_9);
    checkSaeContract(WDI_VERSION_1_1_10);
    checkSaeContract(WDI_VERSION_1_1_12);
    puts("PASS: Microsoft SAE H2E parameter conversion at 1.1.10/1.1.12, exact public parameter bytes and 1.1.9 negative control");
}
'''
    out = output_dir('wdi-contract')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, contract_preamble() + text + ('' if sae_only else TEST), encoding='utf-8')
    command = [str(tx.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(tx.VC / 'include')]
    command += ['/I' + str(tx.INC / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(tx.VC / 'lib/x64'), '/LIBPATH:' + str(tx.LIB / 'ucrt/x64'), '/LIBPATH:' + str(tx.LIB / 'um/x64'), 'advapi32.lib', str(tx.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
