# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Negotiated PMF: production RSNE parser and station indication, real WDI codec.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text, _fixture
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from wdi_test_support import contract_preamble
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cap', Path(__file__).with_name('test-wdi-capabilities.py'))
cap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cap)
PRE = cap.PREAMBLE.split('struct Device {')[0] + r'''
#include <vector>
#include <initializer_list>
#define AP6256_ENABLE_WDI
#define AP6256_OWE_DH_MAX 71u
#define AP6256_OWE_EXTRA_MAX 1024u
#define AP6256_POOL_TAG 0
#define POOL_FLAG_NON_PAGED 0
#define TRACE_NETADAPTER 0
#define TraceInfo(...) ((void)0)
#define TraceWarn(...) ((void)0)
#define TraceError(...) ((void)0)
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define NT_SUCCESS(s) ((LONG)(s)>=0)
#define STATUS_DEVICE_DATA_ERROR ((LONG)0xc000009c)
#define STATUS_NOT_SUPPORTED ((LONG)0xc00000bb)
#define STATUS_SUCCESS ((LONG)0)
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define KeAcquireSpinLock(l,i) (*(i)=0)
#define KeReleaseSpinLock(l,i) ((void)(i))
#define AP6256_TIMER_STOP(t,w) ((void)(t),(void)(w))
#define AP6256_PHY_ID_HT 3
#define AP6256_PHY_ID_VHT 4
typedef LONG NTSTATUS;
typedef int KIRQL;
static int allocations;
static void* ExAllocatePool2(int,ULONG n,int) {++allocations;return calloc(1,n);}
static void ExFreePoolWithTag(void* p,int) {assert(p);--allocations;free(p);}
'''
MOCKS = r'''
struct Wifi;
struct Device { UINT32 FirmwareOweGeneration; UCHAR FirmwareOwePeer[6]; UINT8 LastRssi; CHAR LastRssiDbm; ULONG TalPhyId,TalChannelFreq;
    UCHAR MacAddress[6];UINT32 HostCipherAkm,HostCipherMfp,HostCipherOwnerGeneration;BOOLEAN HostCipherActive; Wifi* Owner;
    BOOLEAN FirmwareSaePatchVerified;LONG HostCipherFirmwareQualified; };
struct Wifi {
    Device* Ctx; TLV_CONTEXT TlvContext; int CommandLock;
    struct { BOOLEAN Active; } ConnectTask;
    ULONG ConnectCandidateIndex,ConnectCandidateCount;
    AP6256_CONNECT_PARAMS ConnectCandidates[16];
    WDI_CHANNEL_NUMBER ConnectChannel;
    WDI_AUTH_ALGORITHM AuthAlgorithm;
    WDI_CIPHER_ALGORITHM UnicastCipher,MulticastCipher,MulticastMgmtCipher;
    BOOLEAN ConnectBssidValid,ConnectionActive;
    UCHAR ConnectBssid[6];
    AP6256_SAE Sae; LONG ConnectGeneration; BOOLEAN SaeFirmwareReleased;
    AP6256_FT_STATE Ft;
    UINT32 SaeFirmwareGeneration;UCHAR SaeFirmwarePeer[6];BOOLEAN SaeNeedsAbort;int SaeTimer;
    LONG SaeGeneration;LONGLONG SaeCachedDeadlineMs;
    UINT32 HostCipherGeneration;
    UINT32 SaeEventGeneration;
    BOOLEAN ConnectDeparting,Stopping;
    AP6256_ASSOC_FAILURE AssocFailure;
    BOOLEAN AssocComebackPending;
};
typedef Wifi* PAP6256_WIFI;
typedef Device* PAP6256_DEVICE_CONTEXT;
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->Owner;}
static unsigned fallback_calls;
static BOOLEAN Ap6256StationSaeFallback(Wifi*) {++fallback_calls;return TRUE;}
static const UCHAR testAp[6]={0x94,0x83,0xc4,0xa2,0x20,0x7b};
static AP6256_ASSOC_FRAMES fixture;
static const UCHAR* expectedFailureResponse;
static ULONG expectedFailureResponseLength;
static int peers,disconnects,indications,peer_deletes,indication_attempts;
static unsigned indication_fault;
static NTSTATUS private_clear_status;
static int private_clears;
static unsigned hc_profile_reads,hc_profile_fault,hc_ends,hc_confirms;
static bool hc_confirm_failure,hc_confirmed;
static bool peer_create_fail;
static NTSTATUS Ap6256HostCipherReadProfile(Device* d,UINT32 i,AP6256_HC_STORE_SESSION* owner,AP6256_HC_PROFILE_CONTROL* p) {
    assert(i==0);++hc_profile_reads;
    if(!d->HostCipherActive||hc_profile_fault==1||(hc_profile_fault==7&&hc_profile_reads==2)||
        (hc_profile_fault==8&&hc_profile_reads==3))return STATUS_NOT_SUPPORTED;
    *owner={};owner->Generation=777;memcpy(owner->Station,d->MacAddress,6);memcpy(owner->Bssid,testAp,6);
    *p={0x31435048,32,777,9,9,d->HostCipherMfp?12u:0u,d->HostCipherAkm,d->HostCipherMfp};
    if(hc_profile_fault==2)++owner->Generation;
    if(hc_profile_fault==3)++owner->Bssid[5];
    if(hc_profile_fault==4)++owner->Station[5];
    if(hc_profile_fault==5)p->Akm^=1;
    if(hc_profile_fault==6)p->Mfp^=1;
    return 0;
}
static NTSTATUS Ap6256HostCipherConfirmAssociation(Device* d,UINT32 i,UINT32 generation,
    const UCHAR* station,const UCHAR* bssid,UINT32 akm,UINT32 mfp) {
    assert(i==0&&generation==777&&d->HostCipherActive&&hc_profile_reads==3&&!hc_confirmed);
    assert(!memcmp(station,d->MacAddress,6)&&!memcmp(bssid,testAp,6)&&akm==d->HostCipherAkm&&mfp==d->HostCipherMfp);
    ++hc_confirms;if(hc_confirm_failure)return STATUS_NOT_SUPPORTED;
    hc_confirmed=true;return 0;
}
static NTSTATUS Ap6256HostCipherEnd(Device* d,UINT32 i,BOOLEAN retiring) {
    assert(i==0&&!retiring);++hc_ends;d->HostCipherActive=FALSE;hc_confirmed=false;return 0;
}
static NTSTATUS Ap6256HostCipherEndGeneration(Device* d,UINT32 i,UINT32 generation,BOOLEAN* matched) {
    assert(i==0&&generation==777);*matched=(BOOLEAN)(d->HostCipherActive&&d->HostCipherOwnerGeneration==generation);
    return *matched?Ap6256HostCipherEnd(d,i,FALSE):STATUS_NOT_SUPPORTED;
}
template<class L,class C> static NDIS_STATUS TestGenerateAssociation(L* list,ULONG prefix,C* ctx,ULONG* size,UCHAR** out) {
    if(indication_fault==1)return (NDIS_STATUS)STATUS_NOT_SUPPORTED;
    if(indication_fault==2){*size=0;*out=nullptr;return NDIS_STATUS_SUCCESS;}
    NDIS_STATUS s=GenerateWdiIndicationAssociationResult(list,prefix,ctx,size,out);
    if(indication_fault==3)*size=0;
    return s;
}
static NTSTATUS Ap6256SaePrivateEnd(Device*,UINT32 gen,const UCHAR* peer,BOOLEAN associated) {
    assert(associated && gen==99 && !memcmp(peer,testAp,6));++private_clears;return private_clear_status;
}

static bool owe_clear_failure;
static unsigned owe_clears;
static NTSTATUS Ap6256OweEnd(Device* d,BOOLEAN) {
    assert(d->FirmwareOweGeneration);++owe_clears;
    if(owe_clear_failure)return STATUS_DEVICE_DATA_ERROR;
    d->FirmwareOweGeneration=0;return 0;
}
static BOOLEAN Ap6256FtAssociationValid(...) {assert(false);return FALSE;}
static NTSTATUS Ap6256FtEnd(...) {assert(false);return STATUS_NOT_SUPPORTED;}
static void Ap6256FtConnectionLost(AP6256_FT_STATE* s) {assert(s->Phase==Ap6256FtIdle);}
static WDI_ASSOCIATION_RESULT_PARAMETERS decoded;
static LONGLONG Ap6256InterruptTimeMs() {return 100;}
static NTSTATUS Ap6256WifiGetBssid(Device*,UCHAR* b) {memcpy(b,testAp,6);return 0;}
static NTSTATUS Ap6256WifiGetChannel(Device*,UINT32* ch) {*ch=36;return 0;}
static NTSTATUS Ap6256WifiGetRssi(Device*,INT32* r) {*r=-46;return 0;}
static NTSTATUS Ap6256WifiDisconnect(Device*) {++disconnects;return 0;}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN) {return 0;}
static PCSTR Ap6256ConnectBssRejection(Wifi*,const UCHAR*,UINT32) {return nullptr;}
static VOID Ap6256MboAssociation(Wifi*,BOOLEAN,const UCHAR*,const AP6256_ASSOC_FRAMES*,BOOLEAN) {}
static void Ap6256WifiTraceAssocList(Device*) {}
static void Ap6256TalSetBssid(Device*,const UCHAR*) {}
static BOOLEAN Ap6256TalPeerCreate(Device*,const UCHAR*) {++peers;return (BOOLEAN)!peer_create_fail;}
static void Ap6256TalPeerDelete(Device*) {++peer_deletes;}
static void Ap6256WifiGetAssocFrames(Device*,AP6256_ASSOC_FRAMES* f) {
    *f=fixture;

    if(f->Beacon) {f->Beacon=(PUCHAR)ExAllocatePool2(0,f->BeaconLength,0);memcpy(f->Beacon,fixture.Beacon,f->BeaconLength);}
    if(f->AssocRequest) {f->AssocRequest=(PUCHAR)ExAllocatePool2(0,f->AssocRequestLength,0);memcpy(f->AssocRequest,fixture.AssocRequest,f->AssocRequestLength);}
    if(f->AssocResponse) {f->AssocResponse=(PUCHAR)ExAllocatePool2(0,f->AssocResponseLength,0);memcpy(f->AssocResponse,fixture.AssocResponse,f->AssocResponseLength);}
}
static NTSTATUS Ap6256SendGeneratedIndication(Wifi* w,UINT16 id,const WDI_MESSAGE_HEADER*,UINT32,PVOID,const UCHAR* b,ULONG n) {
    assert(id==WDI_INDICATION_ASSOCIATION_RESULT);
    ++indication_attempts;
    if(indication_fault>=4) {
        if(indication_fault==5){w->HostCipherGeneration=778;w->Ctx->HostCipherOwnerGeneration=778;}
        return STATUS_NOT_SUPPORTED;
    }
    WDI_INDICATION_ASSOCIATION_RESULT_LIST p={};
    assert(ParseWdiIndicationAssociationResultFromIhv(n,b,&w->TlvContext,&p)==0);
    assert(p.AssociationResults.ElementCount==1);
    const auto& r=p.AssociationResults.pElements[0];
    decoded=r.AssociationResultParameters;
    assert(!memcmp(r.BSSID.Address,testAp,6));
    if(decoded.AssociationStatus==WDI_ASSOC_STATUS_SUCCESS ||
        decoded.AssociationStatus==WDI_ASSOC_STATUS_ASSOC_FAILED_BY_PEER) {
        assert(!!r.Optional.AssociationRequestFrame_IsPresent==!!fixture.AssocRequest);
        if(fixture.AssocRequest) {
            assert(r.AssociationRequestFrame.ElementCount==fixture.AssocRequestLength);
            assert(!memcmp(r.AssociationRequestFrame.pElements,fixture.AssocRequest,fixture.AssocRequestLength));
        }
        assert(!!r.Optional.BeaconProbeResponse_IsPresent==!!fixture.Beacon);
        if(fixture.Beacon) {
            assert(r.BeaconProbeResponse.ElementCount==fixture.BeaconLength);
            assert(!memcmp(r.BeaconProbeResponse.pElements,fixture.Beacon,fixture.BeaconLength));
        }
        assert(r.Optional.AssociationResponseFrame_IsPresent);
        auto response=expectedFailureResponse?expectedFailureResponse:fixture.AssocResponse;
        auto responseLength=expectedFailureResponse?expectedFailureResponseLength:fixture.AssocResponseLength;
        assert(r.AssociationResponseFrame.ElementCount==responseLength);
        assert(!memcmp(r.AssociationResponseFrame.pElements,response,responseLength));
    }
    CleanupParsedWdiIndicationAssociationResultFromIhv(&p);++indications;return 0;
}
'''
TEST = r'''
using Bytes=std::vector<UCHAR>;
static Bytes rsn(UCHAR caps,int cipher=-1,unsigned pmkids=0,unsigned pairs=1,unsigned akms=1) {
    Bytes b={48,0,1,0,0,15,172,4,(UCHAR)pairs,0};
    for(unsigned i=0;i<pairs;++i) b.insert(b.end(),{0,15,172,4});
    b.insert(b.end(),{(UCHAR)akms,0});
    for(unsigned i=0;i<akms;++i) b.insert(b.end(),{0,15,172,(UCHAR)(2+i)});
    b.insert(b.end(),{caps,0});
    if(cipher>=0 || pmkids) {
        b.insert(b.end(),{(UCHAR)pmkids,0});b.insert(b.end(),pmkids*16,0x5a);
        if(cipher>=0) b.insert(b.end(),{0,15,172,(UCHAR)cipher});
    }
    b[1]=(UCHAR)(b.size()-2);return b;
}
static int cases;
static void check(const Bytes& station,const Bytes& access,bool reassoc,bool secure,
                  NTSTATUS expected,bool pmf,int evidence=0,bool wire=false,int saeMode=0,
                  bool h2e=false,bool validH2e=true) {
    Bytes req(reassoc?10:4,0),beacon(12,0),response={0x11,0x10,0,0,1,0xc0};
    req.insert(req.end(),station.begin(),station.end());
    beacon.insert(beacon.end(),access.begin(),access.end());
    fixture={};fixture.AssocRequest=req.data();fixture.AssocRequestLength=(ULONG)req.size();
    fixture.Beacon=beacon.data();fixture.BeaconLength=(ULONG)beacon.size();
    fixture.AssocResponse=response.data();fixture.AssocResponseLength=(ULONG)response.size();
    fixture.ReAssociation=(BOOLEAN)reassoc;fixture.WmmNegotiated=TRUE;memcpy(fixture.BeaconBssid,testAp,6);
    if(evidence==1) fixture.AssocRequest=nullptr;
    if(evidence==2) fixture.Beacon=nullptr;
    if(evidence==3) ++fixture.BeaconBssid[5];
    if(evidence==4) fixture.AssocRequestLength=3;
    if(evidence==5) fixture.BeaconLength=11;
    BOOLEAN result=TRUE;
    NTSTATUS status=Ap6256WifiAssocPmf(&fixture,testAp,&result);
    if(secure) {assert(status==expected);assert(!!result==(expected==0&&pmf));}
    if(wire) {
        Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        w.ConnectChannel=36;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.AuthAlgorithm=secure?WDI_AUTH_ALGO_RSNA_PSK:WDI_AUTH_ALGO_80211_OPEN;
        if(saeMode) {
            w.AuthAlgorithm=WDI_AUTH_ALGO_WPA3_SAE;w.Sae.State=Ap6256SaeAccepted;
            w.Sae.H2e=(BOOLEAN)h2e;
            w.SaeFirmwareReleased=TRUE;w.Sae.Generation=w.ConnectGeneration=9;memcpy(w.Sae.Peer,testAp,6);
            if(saeMode==2)w.Sae.State=Ap6256SaeStatus;
            if(saeMode==3)w.SaeFirmwareReleased=FALSE;
            if(saeMode==4)++w.Sae.Generation;
            if(saeMode==5)++w.Sae.Peer[5];
            if((saeMode>=7 && saeMode<=13) || saeMode>=16) {
                w.Sae.State=Ap6256SaeIdle;w.SaeFirmwareReleased=FALSE;
                w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=1;
                auto& p=w.ConnectCandidates[0];p.PmkidValid=TRUE;p.Security=Ap6256SecuritySaeHost;
                p.SaeCachedH2e=(BOOLEAN)h2e;
                memcpy(p.Bssid,testAp,6);memset(p.Pmkid,0x5a,16);
                w.SaeGeneration=w.ConnectGeneration;w.SaeCachedDeadlineMs=2000;
                if(saeMode==8)++p.Pmkid[15];
                if(saeMode==9)++w.SaeGeneration;
                if(saeMode==10)w.SaeCachedDeadlineMs=100;
                if(saeMode==11)++p.Bssid[5];
                if(saeMode==12)p.PmkidValid=FALSE;
            }
        }
        private_clear_status=(saeMode==15 || saeMode==17)?STATUS_NOT_SUPPORTED:0;
        if(saeMode>=14) {w.SaeFirmwareGeneration=99;memcpy(w.SaeFirmwarePeer,testAp,6);}
        w.UnicastCipher=w.MulticastCipher=secure?WDI_CIPHER_ALGO_CCMP:WDI_CIPHER_ALGO_NONE;


        w.MulticastMgmtCipher=WDI_CIPHER_ALGO_BIP;
        peers=disconnects=indications=private_clears=0;decoded={};WDI_MESSAGE_HEADER h={};
        bool success=Ap6256IndicateAssociation(&w,&h,nullptr,TRUE)!=FALSE;
        assert(success==(!secure||(expected==0&&(!saeMode||((saeMode==1||saeMode==7||saeMode==14||saeMode==16)&&pmf&&validH2e)))));
        assert(indications==1 && allocations==0);
        assert(!!w.ConnectionActive==success && peers==(success?1:0));
        assert(disconnects==(success?0:1));
        assert(decoded.AssociationStatus==(success?WDI_ASSOC_STATUS_SUCCESS:WDI_ASSOC_STATUS_FAILURE));
        assert(decoded.MulticastMgmtCipherAlgorithm==(success&&secure&&pmf?WDI_CIPHER_ALGO_BIP:WDI_CIPHER_ALGO_NONE));
        assert(!!decoded.PortAuthorized==(success&&!secure));
        if(success) assert(!!decoded.ReAssociation==reassoc);
        if(success&&saeMode)assert(w.SaeFirmwareReleased);
        if(saeMode>=14)assert((w.SaeFirmwareGeneration==0)==success && private_clears==1);
    }
    ++cases;
}
static void hostCipherAssociation() {
    unsigned count=0;
    for(UINT32 akm:{1u,2u,5u,8u,12u,18u})for(UINT32 mfp:{0u,1u,2u})for(bool cached:{false,true})
        for(bool reassoc:{false,true}) {
        if((akm==5||akm==8||akm==12||akm==18)&&mfp!=2)continue;
        for(unsigned fault=0;fault<42;++fault) {
            if((fault==4||fault==7)&&!mfp)continue;
            if((fault==29||fault==30)&&akm!=8)continue;
            if(fault==33&&(akm!=18||cached))continue;
            if(fault==34&&akm==18)continue;
            Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
            d.MacAddress[0]=2;d.MacAddress[5]=0x55;d.HostCipherActive=TRUE;d.HostCipherAkm=akm;d.HostCipherMfp=mfp;
            d.HostCipherOwnerGeneration=777;
            w.HostCipherGeneration=777;w.ConnectGeneration=9;w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=1;
            w.ConnectChannel=36;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
            w.UnicastCipher=w.MulticastCipher=WDI_CIPHER_ALGO_GCMP_256;
            w.AuthAlgorithm=akm==1?WDI_AUTH_ALGO_RSNA:akm==2?WDI_AUTH_ALGO_RSNA_PSK:
                akm==5?WDI_AUTH_ALGO_WPA3_ENT:akm==8?WDI_AUTH_ALGO_WPA3_SAE:
                akm==12?WDI_AUTH_ALGO_WPA3_ENT_192:WDI_AUTH_ALGO_OWE;
            auto& p=w.ConnectCandidates[0];p.HostCipher=TRUE;p.HostCipherAkm=akm;p.Mfp=(AP6256_MFP)mfp;
            p.BssidValid=TRUE;memcpy(p.Bssid,testAp,6);p.PmkidValid=(BOOLEAN)cached;memset(p.Pmkid,0x5a,16);
            p.Security=akm==1||akm==5||akm==12?Ap6256SecurityWpa2Enterprise:akm==2?Ap6256SecurityWpa2Host:
                akm==8?Ap6256SecuritySaeHost:Ap6256SecurityOweHost;
            Bytes station=rsn((UCHAR)(mfp==2?0xc0:mfp?0x80:0),mfp?12:-1,cached?1:0);
            Bytes access=rsn((UCHAR)(mfp?0x80:0),mfp?12:-1);
            station[7]=station[13]=access[7]=access[13]=9;station[19]=access[19]=(UCHAR)akm;
            if(fault==1)station[7]=4;if(fault==2)station[13]=4;if(fault==3)station[19]=3;
            if(fault==4)station.back()=6;if(fault==5)access[7]=4;if(fault==6)access[13]=4;
            if(fault==7)access.back()=6;if(fault==8)station[20]=0x40;
            if(fault==17)station[21]|=4;
            if(fault==18){if(cached)station[24]^=1;else{
                station=rsn((UCHAR)(mfp==2?0xc0:mfp?0x80:0),mfp?12:-1,1);
                station[7]=station[13]=9;station[19]=(UCHAR)akm;}}
            Bytes request(reassoc?10:4,0),response={0x11,0x10,0,0,1,0xc0},beacon(12,0);
            request.insert(request.end(),station.begin(),station.end());
            response.insert(response.end(),access.begin(),access.end());beacon.insert(beacon.end(),access.begin(),access.end());
            if(akm==8){
                p.SaeCachedH2e=TRUE;w.Sae.H2e=TRUE;w.Sae.Generation=w.ConnectGeneration;memcpy(w.Sae.Peer,testAp,6);
                w.Sae.State=cached?Ap6256SaeIdle:Ap6256SaeAccepted;w.SaeFirmwareReleased=(BOOLEAN)!cached;
                w.SaeGeneration=w.ConnectGeneration;w.SaeCachedDeadlineMs=1000;
                w.SaeFirmwareGeneration=99;memcpy(w.SaeFirmwarePeer,testAp,6);
                request.insert(request.end(),{244,1,(UCHAR)(fault==30?0:0x20)});
                if(fault==29){w.SaeFirmwareReleased=FALSE;w.SaeCachedDeadlineMs=0;}
            }
            if(akm==18){
                Bytes dh(37,0x5a);dh[0]=255;dh[1]=35;dh[2]=32;dh[3]=19;dh[4]=0;
                assert(Ap6256OweCopyIes(dh.data(),37,nullptr,0,nullptr,0,&p)==0);
                request.insert(request.end(),dh.begin(),dh.end());
                if(cached){response={0x11,0x10,0,0,1,0xc0};Bytes rs=rsn(0x80,12,1);rs[7]=rs[13]=9;rs[19]=18;response.insert(response.end(),rs.begin(),rs.end());}
                else {if(fault==33)dh[3]=22;response.insert(response.end(),dh.begin(),dh.end());}
                d.FirmwareOweGeneration=42;memcpy(d.FirmwareOwePeer,testAp,6);
            }
            if(fault==12)response[2]=1;if(fault==13)response.resize(5);
            if(fault==14)request.resize(reassoc?9:3);
            if(fault==15)request.insert(request.end(),station.begin(),station.end());
            if(fault==16)response.push_back(221);
            if(fault==34)response.resize(6);
            if(fault==35)response[2]=77;
            fixture={};fixture.ReAssociation=(BOOLEAN)reassoc;memcpy(fixture.BeaconBssid,testAp,6);
            fixture.AssocRequest=fault==9?nullptr:request.data();fixture.AssocRequestLength=(ULONG)request.size();
            fixture.Beacon=fault==10?nullptr:beacon.data();fixture.BeaconLength=(ULONG)beacon.size();
            fixture.AssocResponse=response.data();fixture.AssocResponseLength=(ULONG)response.size();
            fixture.PeerStatusValid=TRUE;fixture.PeerStatusCode=(UINT16)(fault==12?1:fault==35?77:0);
            if(fault==11)++fixture.BeaconBssid[5];if(fault==26)w.HostCipherGeneration=0;
            if(fault==27)w.ConnectTask.Active=FALSE;if(fault==28)p.HostCipher=FALSE;
            hc_profile_reads=hc_profile_fault=hc_ends=0;private_clear_status=0;owe_clear_failure=false;
            hc_confirms=0;hc_confirmed=false;hc_confirm_failure=fault==36;
            indication_fault=fault>=37?fault-36:0;peer_deletes=indication_attempts=0;
            if(fault>=19&&fault<=25)hc_profile_fault=fault-18;if(fault==32)hc_profile_fault=8;
            peer_create_fail=fault==31;peers=disconnects=indications=private_clears=0;decoded={};
            WDI_MESSAGE_HEADER h={};bool expected=fault==0||fault==34;
            auto success=Ap6256IndicateAssociation(&w,&h,nullptr,(BOOLEAN)(fault!=35));
            if(!!success!=expected)fprintf(stderr,"HC association akm %u mfp %u cache %u reassoc %u fault %u result %u expected %u\n",akm,mfp,cached,reassoc,fault,success,expected);
            if(fault>=37) {
                assert(!success&&!indications&&allocations==0&&hc_confirms==1&&hc_profile_reads==3);
                assert(indication_attempts==(fault>=40?1:0));
                if(fault==41)assert(d.HostCipherActive&&hc_confirmed&&w.HostCipherGeneration==778&&w.ConnectionActive&&w.ConnectBssidValid&&!hc_ends&&!peer_deletes&&!disconnects);
                else assert(!d.HostCipherActive&&!hc_confirmed&&!w.HostCipherGeneration&&!w.ConnectionActive&&!w.ConnectBssidValid&&hc_ends==1&&peer_deletes==1&&disconnects==1&&w.MulticastMgmtCipher==WDI_CIPHER_ALGO_NONE);
                ++count;continue;
            }
            assert(!!success==expected&&indications==1&&allocations==0);
            assert(!!w.ConnectionActive==expected&&!decoded.PortAuthorized);
            assert(decoded.AuthAlgorithm==w.AuthAlgorithm&&decoded.UnicastCipherAlgorithm==WDI_CIPHER_ALGO_GCMP_256&&decoded.MulticastDataCipherAlgorithm==WDI_CIPHER_ALGO_GCMP_256);
            assert(decoded.MulticastMgmtCipherAlgorithm==(expected&&mfp?WDI_CIPHER_ALGO_BIP_GMAC_256:WDI_CIPHER_ALGO_NONE));
            assert(!!d.HostCipherActive==expected);
            assert(decoded.AssociationStatus==(expected?WDI_ASSOC_STATUS_SUCCESS:
                fault==35&&akm==18?WDI_ASSOC_STATUS_ASSOC_FAILED_BY_PEER:WDI_ASSOC_STATUS_FAILURE));
            if(expected)assert(hc_profile_reads==3&&hc_confirms==1&&hc_confirmed&&!hc_ends&&peers==1&&!disconnects);
            else assert(hc_ends&&disconnects&&w.HostCipherGeneration==0&&!hc_confirmed&&hc_confirms==(fault==36?1u:0u));
            ++count;
        }
    }
    hc_profile_fault=indication_fault=0;peer_create_fail=hc_confirm_failure=hc_confirmed=false;
    printf("PASS: %u public GCMP/GMAC association-result cases\n",count);
}
static void peerRefusals() {
    unsigned count=0;
    for(bool reassoc:{false,true}) for(unsigned status:{1u,30u,77u})
        for(UINT32 value:{1u,0x89abcdefu}) for(unsigned aid:{0u,1u,0xc000u,0xc001u,0xc7d7u,0xffffu})
        for(unsigned fault=0;fault<7;++fault) {
        Device d={};Wifi w={};w.Ctx=&d;d.Owner=&w;
        w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        w.AuthAlgorithm=WDI_AUTH_ALGO_WPA3_SAE;w.UnicastCipher=w.MulticastCipher=WDI_CIPHER_ALGO_CCMP;
        w.ConnectChannel=36;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=1;
        w.ConnectGeneration=w.SaeGeneration=42;w.SaeEventGeneration=19;
        Bytes response={0x11,0x10,(UCHAR)status,0,0,0,56,5,3,
            (UCHAR)value,(UCHAR)(value>>8),(UCHAR)(value>>16),(UCHAR)(value>>24)};
        response[4]=(UCHAR)aid;response[5]=(UCHAR)(aid>>8);
        if(fault==1)response.insert(response.end(),response.begin()+6,response.end());
        if(fault==2)response.pop_back();
        if(fault==3)response.push_back(1);
        if(fault==4)response[8]=2;
        if(fault==5)response.resize(6);
        AP6256_ASSOC_FRAMES parsed={};parsed.PeerStatusValid=TRUE;parsed.PeerStatusCode=(UINT16)status;
        parsed.AssocResponse=response.data();parsed.AssocResponseLength=(ULONG)response.size();
        assert(Ap6256AssociationComebackTime(&parsed)==((status==30&&(fault==0||fault==6))?value:0));
        Bytes stale={0x11,0x10,17,0,0,0};
        fixture={};fixture.AssocResponse=stale.data();fixture.AssocResponseLength=(ULONG)stale.size();
        expectedFailureResponse=response.data();expectedFailureResponseLength=(ULONG)response.size();
        Ap6256NetStationAssocFailure(&d,testAp,19,(BOOLEAN)reassoc,response.data(),(ULONG)response.size());
        assert(w.AssocFailure.Length==response.size());
        if(fault==6) {
            ++w.AssocFailure.ConnectGeneration;
            AP6256_ASSOC_FRAMES rejected={};assert(!Ap6256StationCopyAssocFailure(&w,&rejected));
        }
        WDI_MESSAGE_HEADER h={};decoded={};peers=indications=0;
        assert(!Ap6256IndicateAssociation(&w,&h,nullptr,FALSE));
        assert(decoded.AssociationStatus==(fault==6?WDI_ASSOC_STATUS_FAILURE:WDI_ASSOC_STATUS_ASSOC_FAILED_BY_PEER));
        assert(decoded.StatusCode==(fault==6?0:status));
        assert(decoded.AssociationComebackTime==((!fault&&status==30)?value:0));
        assert(!!w.AssocComebackPending==(fault!=6&&status==30));
        fallback_calls=0;
        assert(!!Ap6256ModelRetryAssociation(&w)==!(fault!=6&&status==30));
        assert(fallback_calls==(fault!=6&&status==30?0u:1u));
        assert(!decoded.PortAuthorized && !w.ConnectionActive && !peers && indications==1 && !allocations);
        assert(!w.AssocFailure.Length);++count;
    }
    expectedFailureResponse=nullptr;expectedFailureResponseLength=0;
    for(unsigned fault=0;fault<15;++fault) {
        Device d={};Wifi w={};w.Ctx=&d;d.Owner=&w;
        w.ConnectTask.Active=TRUE;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.ConnectGeneration=w.SaeGeneration=42;w.SaeEventGeneration=19;
        UCHAR peer[6];memcpy(peer,testAp,6);UINT32 owner=19;
        Bytes response={0x11,0x10,30,0,0,0};
        if(fault==0)w.ConnectTask.Active=FALSE;
        if(fault==1)w.ConnectDeparting=TRUE;
        if(fault==2)w.Stopping=TRUE;
        if(fault==3)++w.SaeGeneration;
        if(fault==4)++owner;
        if(fault==5)peer[5]^=1;
        if(fault==6)owner=0;
        if(fault==7)response.resize(5);
        if(fault==8)response.resize(AP6256_ASSOC_FAILURE_MAX+1);
        if(fault==9)response[2]=0;
        if(fault==10)response[0]=response[1]=0;
        if(fault==11)response[3]=0xff;
        if(fault==12)response[2]=127;
        Ap6256NetStationAssocFailure(&d,fault==14?nullptr:peer,owner,FALSE,
            fault==13?nullptr:response.data(),(ULONG)response.size());
        assert(!w.AssocFailure.Length);++count;
    }
    printf("PASS: %u AP refusal cases; immutable SAE owner, exact response, comeback TU, malformed IE and stale-owner guards, actual Windows indication codec\n",count);
}
static void oweAssociation() {
    for(bool reassoc:{false,true}) for(bool cached:{false,true})
        for(unsigned group:{19u,20u,21u}) for(unsigned fault=0;fault<10;++fault) {
        Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        w.AuthAlgorithm=WDI_AUTH_ALGO_OWE;w.UnicastCipher=w.MulticastCipher=WDI_CIPHER_ALGO_CCMP;
        w.ConnectChannel=36;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=1;d.FirmwareOweGeneration=42;memcpy(d.FirmwareOwePeer,testAp,6);
        auto& p=w.ConnectCandidates[0];p.Security=Ap6256SecurityOweHost;p.Mfp=Ap6256MfpRequired;
        p.BssidValid=TRUE;memcpy(p.Bssid,testAp,6);p.PmkidValid=(BOOLEAN)cached;memset(p.Pmkid,0x5a,16);
        Bytes dh(5+(group==19?32:group==20?48:66),0x5a);
        dh[0]=255;dh[1]=(UCHAR)(dh.size()-2);dh[2]=32;dh[3]=(UCHAR)group;dh[4]=0;
        assert(Ap6256OweCopyIes(dh.data(),(ULONG)dh.size(),nullptr,0,nullptr,0,&p)==0);
        Bytes station=rsn(0xc0,6,cached?1:0),access=rsn(0x80,6,cached?1:0);
        station[19]=access[19]=18;
        Bytes request(reassoc?10:4,0),response={0x11,0x10,0,0,1,0xc0},beacon(12,0);
        request.insert(request.end(),station.begin(),station.end());request.insert(request.end(),dh.begin(),dh.end());
        response.insert(response.end(),access.begin(),access.end());
        if(!cached)response.insert(response.end(),dh.begin(),dh.end());
        beacon.insert(beacon.end(),access.begin(),access.end());
        if(fault==1)response[6+19]=2;
        if(fault==2)beacon[12+20]=response[6+20]=0;
        if(fault==3)response.resize(6);
        if(fault==4 && !cached)response[6+access.size()+3]=22;
        if(fault==4 && cached)response[6+24]^=1;
        if(fault==5)request[reassoc?10+19:4+19]=2;
        if(fault==6)d.FirmwareOwePeer[5]^=1;
        owe_clear_failure=fault==7;owe_clears=0;
        bool inputSuccess=fault!=8 && fault!=9;
        if(fault==8 || fault==9) {response={0x11,0x10,77,0,0,0};}
        fixture={};fixture.ReAssociation=(BOOLEAN)reassoc;fixture.PeerStatusValid=(BOOLEAN)(fault==8);
        fixture.PeerStatusCode=(UINT16)(fault==8?77:0);memcpy(fixture.BeaconBssid,testAp,6);
        fixture.AssocRequest=request.data();fixture.AssocRequestLength=(ULONG)request.size();
        fixture.AssocResponse=response.data();fixture.AssocResponseLength=(ULONG)response.size();
        fixture.Beacon=beacon.data();fixture.BeaconLength=(ULONG)beacon.size();
        peers=disconnects=indications=0;WDI_MESSAGE_HEADER h={};
        assert(!!Ap6256IndicateAssociation(&w,&h,nullptr,(BOOLEAN)inputSuccess)==(fault==0));
        assert(owe_clears==1 && !!d.FirmwareOweGeneration==owe_clear_failure);
        assert(!decoded.PortAuthorized && decoded.AuthAlgorithm==WDI_AUTH_ALGO_OWE);
        assert(decoded.AssociationStatus==(fault==0?WDI_ASSOC_STATUS_SUCCESS:
            fault==8?WDI_ASSOC_STATUS_ASSOC_FAILED_BY_PEER:WDI_ASSOC_STATUS_FAILURE));
        if(fault==0)assert(decoded.MulticastMgmtCipherAlgorithm==WDI_CIPHER_ALGO_BIP && peers==1);
        if(fault==8)assert(decoded.StatusCode==77 && decoded.ReAssociation==(BOOLEAN)reassoc);
        assert(indications==1 && allocations==0);++cases;
    }
    owe_clear_failure=false;
    puts("PASS: 120 enabled OWE association indications, AP DH/cache and raw frames, required PMF, controlled-port ownership, owner/abort guards and AP status-77 forwarding");
}
static void enterpriseAssociation() {
    unsigned count=0;
    for(bool reassoc:{false,true}) for(bool cached:{false,true}) for(unsigned fault=0;fault<20;++fault) {
        Device d={};Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        w.AuthAlgorithm=WDI_AUTH_ALGO_WPA3_ENT;w.UnicastCipher=w.MulticastCipher=WDI_CIPHER_ALGO_CCMP;
        w.ConnectChannel=36;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=1;
        auto& candidate=w.ConnectCandidates[0];candidate.Wpa3Enterprise=TRUE;
        candidate.Security=Ap6256SecurityWpa2Enterprise;candidate.Mfp=Ap6256MfpRequired;
        candidate.PmkidValid=(BOOLEAN)cached;memset(candidate.Pmkid,0x5a,16);
        memcpy(candidate.Bssid,testAp,6);candidate.BssidValid=TRUE;candidate.Channel=36;
        Bytes sta=rsn(0xc0,6,cached?1:0),ap=rsn(0x80,6);sta[19]=ap[19]=5;
        if(fault==1)sta[19]=1;if(fault==2)ap[19]=1;
        if(fault==3)sta[13]=9;if(fault==4)ap[13]=9;
        if(fault==5)sta[7]=9;if(fault==6)ap[7]=9;
        if(fault==7)sta[20]=0x80;if(fault==8)ap[20]=0;
        if(fault==9)sta.back()=12;if(fault==10)ap.back()=12;
        if(fault==11&&cached)sta[24]^=1;
        Bytes req(reassoc?10:4,0),beacon(12,0),response={0x11,0x10,0,0,1,0xc0};
        req.insert(req.end(),sta.begin(),sta.end());beacon.insert(beacon.end(),ap.begin(),ap.end());
        if(fault==12)response[2]=1;
        if(fault==13)response.push_back(221);
        if(fault==14){response.insert(response.end(),ap.begin(),ap.end());response[6+19]=1;}
        if(fault==15){response.insert(response.end(),ap.begin(),ap.end());}
        if(fault==16){beacon.insert(beacon.end(),ap.begin(),ap.end());}
        fixture={};fixture.ReAssociation=(BOOLEAN)reassoc;fixture.WmmNegotiated=TRUE;
        fixture.AssocRequest=req.data();fixture.AssocRequestLength=(ULONG)req.size();
        fixture.Beacon=beacon.data();fixture.BeaconLength=(ULONG)beacon.size();memcpy(fixture.BeaconBssid,testAp,6);
        fixture.AssocResponse=response.data();fixture.AssocResponseLength=(ULONG)response.size();
        if(fault==17)++fixture.BeaconBssid[5];
        if(fault==18)candidate.Wpa3Enterprise=FALSE;
        if(fault==19)fixture.AssocRequest=nullptr;
        peers=disconnects=indications=peer_deletes=indication_attempts=0;
        indication_fault=hc_profile_fault=0;peer_create_fail=false;
        WDI_MESSAGE_HEADER h={};const bool expected=fault==0||fault==15||(fault==11&&!cached);
        bool success=!!Ap6256IndicateAssociation(&w,&h,nullptr,TRUE);
        if(success!=expected)fprintf(stderr,"Enterprise association cache %u reassoc %u fault %u success %u expected %u\n",cached,reassoc,fault,success,expected);
        assert(success==expected&&indications==1&&allocations==0);
        assert(!!w.ConnectionActive==expected&&!decoded.PortAuthorized);
        assert(decoded.AuthAlgorithm==WDI_AUTH_ALGO_WPA3_ENT&&decoded.UnicastCipherAlgorithm==WDI_CIPHER_ALGO_CCMP);
        assert(decoded.MulticastDataCipherAlgorithm==WDI_CIPHER_ALGO_CCMP);
        assert(decoded.MulticastMgmtCipherAlgorithm==(expected?WDI_CIPHER_ALGO_BIP:WDI_CIPHER_ALGO_NONE));
        assert(expected?peers==1&&!disconnects:disconnects>0);++count;
    }
    printf("PASS: %u WPA3-Enterprise/CCMP association-result cases\n",count);
}

int main() {
    enterpriseAssociation();
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    for(bool reassoc:{false,true}) {
        check(rsn(0x80),rsn(0x0c),reassoc,true,0,false,0,true);
        for(UCHAR sta:std::initializer_list<UCHAR>{0,0x80,0xc0}) for(UCHAR apcaps:std::initializer_list<UCHAR>{0,0x80,0xc0}) {
            bool enabled=(sta&apcaps&0x80)!=0;
            bool bad=((sta&0x40)&&!(apcaps&0x80))||((apcaps&0x40)&&!(sta&0x80));
            check(rsn(sta),rsn(apcaps),reassoc,true,bad?STATUS_DEVICE_DATA_ERROR:0,enabled,0,true);
        }
        check(rsn(0x80,6,2,2,3),rsn(0xc0,6,1,3,4),reassoc,true,0,true,0,true);
        check(rsn(0x80),rsn(0x80,6),reassoc,true,0,true);
        check(rsn(0x80,6),rsn(0x80),reassoc,true,0,true);
        check({}, {},reassoc,false,0,false,0,true);
        for(int evidence=1;evidence<=5;++evidence)
            check(rsn(0x80),rsn(0x80),reassoc,true,STATUS_DEVICE_DATA_ERROR,false,evidence,true);
        for(int cipher:{0,4,11,12,13,255}) {
            check(rsn(0x80,cipher),rsn(0x80),reassoc,true,STATUS_NOT_SUPPORTED,false,0,true);
            check(rsn(0x80),rsn(0x80,cipher),reassoc,true,STATUS_NOT_SUPPORTED,false,0,true);
        }
        for(Bytes invalid:{Bytes{},Bytes{48,2,2,0},rsn(0x40),rsn(0x80,6,0,0),rsn(0x80,6,0,1,0)}) {
            check(invalid,rsn(0x80),reassoc,true,STATUS_DEVICE_DATA_ERROR,false,0,true);
            check(rsn(0x80),invalid,reassoc,true,STATUS_DEVICE_DATA_ERROR,false,0,true);
        }
    }


    Bytes full=rsn(0x80,6,1);
    SYSTEM_INFO si;GetSystemInfo(&si);
    auto region=(UCHAR*)VirtualAlloc(nullptr,2*si.dwPageSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    assert(region);DWORD old;
    assert(VirtualProtect(region+si.dwPageSize,si.dwPageSize,PAGE_NOACCESS,&old));
    for(size_t n=0;n<=full.size();++n) {
        UCHAR* p=region+si.dwPageSize-n;
        if(n) memcpy(p,full.data(),n);
        AP6256_RSN_MFP parsed={};
        assert(!!Ap6256WifiReadRsnMfp(p,(ULONG)n,&parsed)==(n==full.size()));++cases;
        if(n>=2) {
            p[1]=(UCHAR)(n-2);
            bool valid=n==4||n==8||n==14||n==20||n==22||n==40||n==44;
            assert(!!Ap6256WifiReadRsnMfp(p,(ULONG)n,&parsed)==valid);++cases;
        }
    }
    VirtualFree(region,0,MEM_RELEASE);
    Bytes dup=rsn(0x80);dup.insert(dup.end(),full.begin(),full.end());
    check(dup,rsn(0x80),false,true,STATUS_DEVICE_DATA_ERROR,false,0,true);
    Bytes overflow=rsn(0x80);overflow[8]=overflow[9]=0xff;
    check(overflow,rsn(0x80),false,true,STATUS_DEVICE_DATA_ERROR,false);
    Bytes wrongOui=rsn(0x80,6);wrongOui[wrongOui.size()-4]=1;
    check(wrongOui,rsn(0x80),false,true,STATUS_NOT_SUPPORTED,false);
    Bytes tail=rsn(0x80);tail.push_back(221);
    check(tail,rsn(0x80),false,true,STATUS_DEVICE_DATA_ERROR,false);
    Bytes ordered={0,3,'f','o','o',221,0};Bytes r=rsn(0x80);
    ordered.insert(ordered.end(),r.begin(),r.end());ordered.insert(ordered.end(),{1,1,0x82});
    check(ordered,rsn(0x80),false,true,0,true,0,true);
    Bytes saeRsn=rsn(0xc0);saeRsn[19]=8;
    for(bool reassoc:{false,true}) {
        check(saeRsn,saeRsn,reassoc,true,0,true,0,true,1);
        for(int mode:{2,3,4,5})check(saeRsn,saeRsn,reassoc,true,0,true,0,true,mode);
        check(rsn(0xc0),saeRsn,reassoc,true,0,true,0,true,6);
        check(saeRsn,rsn(0),reassoc,true,STATUS_DEVICE_DATA_ERROR,false,0,true,1);
        Bytes cached=rsn(0xc0,-1,1);cached[19]=8;
        check(cached,saeRsn,reassoc,true,0,true,0,true,7);
        for(int mode:{8,9,10,11,12})check(cached,saeRsn,reassoc,true,0,true,0,true,mode);
        for(int mode:{14,15})check(saeRsn,saeRsn,reassoc,true,0,true,0,true,mode);
        for(int mode:{16,17})check(cached,saeRsn,reassoc,true,0,true,0,true,mode);
        Bytes fullH2e=saeRsn;fullH2e.insert(fullH2e.end(),{244,1,0x20});
        Bytes cachedH2e=cached;cachedH2e.insert(cachedH2e.end(),{244,1,0x20});
        check(fullH2e,saeRsn,reassoc,true,0,true,0,true,1,true);
        check(cachedH2e,saeRsn,reassoc,true,0,true,0,true,7,true);
        check(saeRsn,saeRsn,reassoc,true,0,true,0,true,1,true,false);
        check(cached,saeRsn,reassoc,true,0,true,0,true,7,true,false);
        check(fullH2e,saeRsn,reassoc,true,0,true,0,true,1,false,false);
        check(cachedH2e,saeRsn,reassoc,true,0,true,0,true,7,false,false);
        cachedH2e.insert(cachedH2e.end(),{244,1,0x20});
        check(cachedH2e,saeRsn,reassoc,true,0,true,0,true,7,true,false);

        check(saeRsn,saeRsn,reassoc,true,0,true,0,true,13);
        check(cached,rsn(0),reassoc,true,STATUS_DEVICE_DATA_ERROR,false,0,true,7);
    }
    peerRefusals();
    oweAssociation();
    hostCipherAssociation();
    assert(allocations==0);
    printf("PASS: %d PMF cases; real station association codec; PMF off/on, reassociation, defaults, unsupported/missing/malformed evidence, guard-page bounds and cleanup\n",cases);
}
'''

def function(source, name):
    found = re.search('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source, re.M)
    if not found:
        raise ValueError(name)
    return found[0] + '\n'

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--association-source', type=Path, default=ROOT / 'src/common/netadapter.c')
    parser.add_argument('--output-dir', type=Path, default=output_dir('association-pmf'))
    args = parser.parse_args()
    wifi = read_source_text(ROOT / 'src/common/wifi_ops.c', encoding='utf-8-sig')
    header = read_source_text(ROOT / 'src/common/wifi_ops.h', encoding='utf-8-sig')
    net = read_source_text(args.association_source, encoding='utf-8-sig')
    text = contract_preamble() + PRE
    text += read_source_text(ROOT / 'src/common/association_failure.h') + '\n'
    sae_header = read_source_text(ROOT / 'src/common/sae.h')
    text += '\n'.join(re.findall('^#define AP6256_SAE_(?:BODY_MAX|FRAME_MAX)\\s+[^\\n]+', sae_header, re.M)) + '\n'
    text += re.search('typedef enum _AP6256_SAE_STATE \\{[\\s\\S]*?\\} AP6256_SAE_STATE;', sae_header)[0] + '\n'
    text += re.search('typedef struct _AP6256_SAE \\{[\\s\\S]*?\\} AP6256_SAE;', sae_header)[0] + '\n'
    text += '\n'.join(re.findall('^#define AP6256_(?:RSN_\\w+|(?:RE)?ASSOC_REQ_FIXED_LEN|BEACON_FIXED_LEN)\\s+[^\\n]+', wifi + '\n' + header, re.M)) + '\n'
    for (name, source) in [('AP6256_ASSOC_FRAMES', header), ('AP6256_RSN_MFP', wifi)]:
        text += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', source)[0] + '\n'
    for name in ('AP6256_SECURITY', 'AP6256_MFP', 'AP6256_CONNECT_PARAMS'):
        text += re.search('typedef (?:enum|struct) _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', header)[0] + '\n'
    for name in ('host_cipher_frame.h', 'host_cipher_rsn.h', 'host_cipher_rsn.c'):
        text += re.sub('^#(?:include|pragma)[^\\n]*\\n', '', read_source_text(ROOT / 'src/common' / name), flags=re.M) + '\n'
    for (name, path) in [('AP6256_HC_STORE_SESSION', 'host_cipher_store.h'), ('AP6256_HC_PROFILE_CONTROL', 'host_cipher_control.h')]:
        text += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', read_source_text(ROOT / 'src/common' / path))[0] + '\n'
    ft_header = read_source_text(ROOT / 'src/common/ft.h')
    text += ft_header[ft_header.index('#define AP6256_FT_MDE_LENGTH'):ft_header.index('_IRQL_requires_max_')] + '\n'
    owe = read_source_text(ROOT / 'src/common/owe.c').split('_Use_decl_annotations_\nNTSTATUS Ap6256OweBuildCommand')[0]
    text += re.search('^static UINT16 Owe16[^\\n]+', owe, re.M)[0] + '\n' + owe[owe.index('_Use_decl_annotations_'):] + '\n'
    text += MOCKS
    text += function(read_source_text(ROOT / 'src/common/sae_station.inc'), 'Ap6256StationSaeComplete')
    for name in ('Ap6256GetLe16', 'Ap6256GetLe32', 'Ap6256WifiReadRsnMfp', 'Ap6256WifiAssocPmf', 'Ap6256WifiFreeAssocFrames'):
        text += function(wifi, name)
    sae_fw = read_source_text(ROOT / 'src/common/sae_fw.c')
    text += function(read_source_text(ROOT / 'src/common/sae.c'), 'Ap6256SaeReadRsnxe') + '\n'
    text += function(sae_fw, 'Ap6256SaeFwLe16') + function(sae_fw, 'Ap6256SaeAssociationRsn') + function(sae_fw, 'Ap6256SaeAssociationPmkid') + function(sae_fw, 'Ap6256SaeAssociationH2e')
    for name in ('Ap6256HostCipherAssociationProfile', 'Ap6256HostCipherAssociationRsn', 'Ap6256Wpa3EnterpriseAssociationRsn', 'Ap6256StationAssociationDisconnect'):
        if name in net:
            text += function(net, name)
    for name in ('Ap6256NetStationAssocFailure', 'Ap6256StationCopyAssocFailure', 'Ap6256AssociationComebackTime'):
        source = _fixture(None.read_text(encoding='utf-8-sig'), ROOT, 'wdi') if None and name == 'Ap6256NetStationAssocFailure' else net
        text += function(source, name)
    text += r'''
struct TestEvent { UCHAR AuthType[4],Flags[2],IfIdx,BssCfgIdx; };
static UINT32 Ap6256ReadBe32(PUCHAR p){return ((UINT32)p[0]<<24)|((UINT32)p[1]<<16)|((UINT32)p[2]<<8)|p[3];}
static UINT16 Ap6256ReadBe16(PUCHAR p){return (UINT16)((p[0]<<8)|p[1]);}
static BOOLEAN Ap6256HostCipherEventRead(const UCHAR*,ULONG,UINT32*,UCHAR*){return FALSE;}
static void Ap6256NetStationHostCipherEvent(Device*,BOOLEAN,BOOLEAN,const UCHAR*,UINT32){}
static void Ap6256NetStationFirmwareEvent(Device*,BOOLEAN,BOOLEAN,const UCHAR*,UINT32){}
'''
    sdpcm = read_source_text(ROOT / 'src/common/sdpcm.h')
    sae_header = read_source_text(ROOT / 'src/common/sae_fw.h')
    for name in ('AP6256_SAE_OWNER_AUTH_FLAG', 'AP6256_SAE_OWNER_MAGIC'):
        text += re.search('^#define ' + name + '[^\\n]+', sae_header, re.M)[0] + '\n'
    text += function(sae_fw, 'Ap6256SaeFwLe32') + function(sae_fw, 'Ap6256SaePrivateOwner')
    for name in ('BRCMF_E_SET_SSID', 'BRCMF_E_AUTH', 'BRCMF_E_ASSOC', 'BRCMF_E_REASSOC', 'BRCMF_E_LINK', 'BRCMF_E_DEAUTH', 'BRCMF_E_DEAUTH_IND', 'BRCMF_E_DISASSOC', 'BRCMF_E_DISASSOC_IND', 'BRCMF_E_STATUS_SUCCESS'):
        text += re.search('^#define ' + name + '\\s+[^\\n]+', sdpcm, re.M)[0] + '\n'
    datapath = read_source_text(ROOT / 'src/common/datapath.c')
    start = datapath.index('    if ((Ap6256ReadBe32((PUCHAR)&evt->AuthType) & AP6256_SAE_OWNER_AUTH_FLAG)')
    end = datapath.index('{', start) + 1
    depth = 1
    while depth:
        depth += (datapath[end] == '{') - (datapath[end] == '}')
        end += 1
    text += 'static void TestOwnedRefusal(Device* Ctx,TestEvent* evt,UINT32 eventType,UINT32 status,UCHAR* eventBody,ULONG eventBodyLen){\n' + datapath[start:end] + '}\n'
    text += r'''
static void refusalEventRouting() {
    unsigned count=0;
    for(UINT32 type:{3u,7u,9u})for(unsigned aid:{0u,0xc000u,0xc001u,0xffffu}) {
        Device d={};Wifi w={};w.Ctx=&d;d.Owner=&w;d.FirmwareSaePatchVerified=TRUE;
        w.ConnectTask.Active=TRUE;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,testAp,6);
        w.ConnectGeneration=w.SaeGeneration=42;w.SaeEventGeneration=19;
        UCHAR body[22]={};UINT32 magic=AP6256_SAE_OWNER_MAGIC,owner=19;
        memcpy(body,&magic,4);memcpy(body+4,&owner,4);memcpy(body+8,testAp,6);body[14]=1;
        body[16]=0x11;body[17]=0x10;body[18]=30;body[20]=(UCHAR)aid;body[21]=(UCHAR)(aid>>8);
        TestEvent event={};event.AuthType[0]=0x80;
        TestOwnedRefusal(&d,&event,type,1,body,sizeof(body));
        assert(w.AssocFailure.Length==(type==3?0u:6u));
        if(type!=3)assert(!memcmp(w.AssocFailure.Response,body+16,6));
        ++count;
    }
    printf("PASS: %u production owned-event routing cases; AUTH excluded, ASSOC/REASSOC retain exact nonzero-AID refusal bytes\n",count);
}
'''
    text += function(read_source_text(ROOT / 'src/common/station_auth.c'), 'Ap6256ModelRetryAssociation')
    indication = net
    text += function(indication, 'Ap6256IndicateAssociation').replace('GenerateWdiIndicationAssociationResult(', 'TestGenerateAssociation(') + TEST.replace('int main() {', 'int main() {\n    refusalEventRouting();')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    cpp = args.output_dir / 'tests.cpp'
    write_bytes(cpp, text.encode())
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    cmd += [str(cpp), '/Fe:' + str(args.output_dir / 'tests.exe'), '/Fo:' + str(args.output_dir / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    compiled = subprocess.run(cmd, capture_output=True, text=True)
    write_text(args.output_dir / 'compile.log', compiled.stdout + compiled.stderr, encoding='utf-8')
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(args.output_dir / 'tests.exe')], capture_output=True, text=True)
    write_text(args.output_dir / 'run.log', executed.stdout + executed.stderr, encoding='utf-8')
    print(executed.stdout + executed.stderr, end='')
    assert executed.returncode == 0, executed.returncode
    if args.association_source.resolve() == (ROOT / 'src/common/netadapter.c').resolve():
        names = [p.relative_to(ROOT).as_posix() for p in (ROOT / 'src').rglob('*') if p.is_file()]
        inputs = [ROOT / name for name in names if Path(name).name != 'buildstamp.h']
        inputs += [ROOT / name for name in ('tests/test-association-pmf.py', 'tests/test-wdi-capabilities.py', 'tests/wdi_test_support.py', 'tests/driver_sources.py', 'tests/source-layout.json')]
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        report = dict(exit_code=0, host_cipher_cases=int(re.search('PASS: (\\d+) public GCMP/GMAC', executed.stdout)[1]), peer_refusal_cases=int(re.search('PASS: (\\d+) AP refusal', executed.stdout)[1]), ordinary_pmf_cases=347, ordinary_owe_cases=120, enterprise_ccmp_cases=int(re.search('PASS: (\\d+) WPA3-Enterprise/CCMP', executed.stdout)[1]), sources={str(path.relative_to(ROOT)): digest(path) for path in inputs}, test_exe_sha256=digest(args.output_dir / 'tests.exe'), generated_cpp_sha256=digest(cpp), compiler_sha256=digest(Path(cmd[0])), codec_sha256=digest(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib'), board_verified=False, association_qualified=False, boundary='RSNE/PMKID/SAE-H2E/OWE-DH validation and station association indications through the Microsoft codec.')
        write_text(args.output_dir / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
