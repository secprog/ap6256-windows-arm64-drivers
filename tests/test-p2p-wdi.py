# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"Exercise production P2P WDI handlers with Microsoft's real TLV codec."
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text, _functions
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
cap = module('test-wdi-capabilities')
hotspot = module('test-hotspot')
PRE = cap.PREAMBLE.split('struct Device {')[0].replace('assert(context == 0); free(p);', '(void)context; free(p);') + r'''
#define AP6256_ENABLE_WDI
typedef LONG NTSTATUS;
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xc0010015)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xc000023c)
#define AP6256_P2P_DISCOVER_FIRST_MS 20u
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define TraceWarn(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define AP6256_DISCOVERY_PORT 1
#define AP6256_STATION_PORT 0
#define AP6256_GROUP_PORT 2
#define AP6256_P2P_DISC_SCAN 0
#define AP6256_P2P_DISC_LISTEN 1
'''
MOCKS = r'''
struct Wifi;
struct Device { BOOLEAN P2pBssValid, DatapathRunning, FirmwareP2pSupported, FirmwareNativeManagement, FirmwareServiceOffload;
    BOOLEAN FirmwareBssTransitionEnabled, FirmwareLinkUp; AP6256_P2P_STATE P2p;
    UINT32 P2pBssIndex; Wifi* WifiContext;
    struct { BOOLEAN Created,FirmwareReady;UINT32 IfIndex,BssIndex;AP6256_P2P_STATE P2p; } Go;
};
struct Task { BOOLEAN Active; };
struct Wifi { struct {ULONG AdvertisementCount;BOOLEAN Active;} Service; Device* Ctx; TLV_CONTEXT TlvContext; BOOLEAN PortCreated, P2pPortCreated, P2pDiscovering, Stopping;
    BOOLEAN ConnectBssidValid;UCHAR ConnectBssid[6];
    LONG HardwareAvailable,DisallowedBandMask,ScanIndicated,ScanDropped;UINT32 PortOperationMode;int P2pLock,P2pListenTimer,P2pDiscoverTimer;
    Task ScanTask,ActionFrameTask,ConnectTask,ClientConnectTask,P2pDiscoverTask;
};
typedef Wifi* PAP6256_WIFI;typedef void* AP6256_REQUEST;
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->WifiContext;}
static NTSTATUS request_status,start_status;static int starts;
static AP6256_P2P_DISCOVER captured_discover;
static int mutations,pulses,rearms,stops,sends,indications,action_indications;
static UINT32 last_if,last_channel,last_delay,rx_channel;
static UINT16 rx_port;
static UCHAR rx_source[6];static WDI_BAND_ID rx_band;
static AP6256_P2P_ACTION_FRAME captured;
static UCHAR stored[512],incoming[512];static ULONG stored_len,incoming_len;
static UCHAR preceding[512];static ULONG preceding_len;
static int channel_indications,group_indications;
static NTSTATUS plan_status;
static NTSTATUS Ap6256P2pGetChannelPlan(Device*,ULONG mask,AP6256_P2P_CHANNEL_PLAN* p) {
    assert(mask==0);*p={};p->Count=4;p->Channels[0]=1;p->Channels[1]=6;p->Channels[2]=36;p->Channels[3]=149;
    p->Classes[0]=p->Classes[1]=81;p->Classes[2]=115;p->Classes[3]=125;
    p->OperatingChannel=36;p->OperatingClass=115;return plan_status;
}
static VOID Ap6256P2pTraceAction(BOOLEAN,UCHAR,UCHAR,UINT32,const UCHAR*,ULONG) {}
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s) {request_status=s;}
static VOID Ap6256LockAcquire(int* held) {assert(!*held);*held=1;}
static VOID Ap6256LockRelease(int* held) {assert(*held);*held=0;}
#define AP6256_TIMER_STOP(t,w) ((void)(t),(void)(w),++stops)
#define AP6256_TIMER_START(t,ms) ((void)(t),last_delay=(ms),++rearms)
static UINT32 discovery_if=3;
static UINT32 Ap6256WifiP2pInterface(Device*) {return discovery_if;}
static NTSTATUS Ap6256P2pBuildIesFor(Device*,AP6256_P2P_STATE*,UINT32 i) {mutations++;last_if=i;return 0;}
static NTSTATUS Ap6256P2pBuildIes(Device* d) {return Ap6256P2pBuildIesFor(d,&d->P2p,3);}
static NTSTATUS Ap6256P2pSetHostIesFor(Device*,AP6256_P2P_STATE*,UINT32 i,AP6256_P2P_FRAME,const UCHAR* b,ULONG n) {
    mutations++;last_if=i;stored_len=n;if(n)memcpy(stored,b,n);return 0;
}
static NTSTATUS Ap6256P2pSetHostIes(Device* d,AP6256_P2P_FRAME f,const UCHAR* b,ULONG n) {
    return Ap6256P2pSetHostIesFor(d,&d->P2p,3,f,b,n);
}
static BOOLEAN Ap6256BandIsDisallowed(Wifi* w,WDI_BAND_ID b) {
    return (BOOLEAN)((w->DisallowedBandMask & (b==WDI_BAND_ID_2400 ? 1 : 2))!=0);
}



static VOID Ap6256MboBtmRequest(Wifi* w,const UCHAR* peer,const UCHAR* body,ULONG n) {
    (void)w;(void)peer;assert(n>=7 && body[0]==10 && body[1]==7);
}
static PVOID Ap6256RequestGetId(AP6256_REQUEST r) {return r;}
static NTSTATUS Ap6256BeginTask(Wifi*,Task* t,PWDI_MESSAGE_HEADER,PVOID) {t->Active=TRUE;return 0;}
static VOID Ap6256FailStartedTask(Wifi*,Task* t,UINT16,NTSTATUS s) {t->Active=FALSE;request_status=s;}
static VOID Ap6256P2pStopDiscovery(Device*) {}
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR,const VOID*,ULONG) {assert(false);return 0;}
static NTSTATUS Ap6256ServiceValidateAdvertisements(Wifi*,const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* s) {return s->ServiceEntry.ElementCount?STATUS_NOT_SUPPORTED:0;}
static unsigned service_advertisement_calls;
static NTSTATUS Ap6256ServiceAdvertise(Wifi*,const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* s) {service_advertisement_calls++;return s->ServiceEntry.ElementCount?STATUS_NOT_SUPPORTED:0;}
static NTSTATUS Ap6256ServiceResumeListen(Wifi*) {return 0;}
static NTSTATUS Ap6256ServiceCapture(Wifi*,const WDI_TASK_P2P_DISCOVER_PARAMETERS* p,BOOLEAN) {
 return p->Optional.ServiceNameHash_IsPresent || p->Optional.ServiceInformationDiscoveryEntry_IsPresent ||
 (p->DiscoverMode.ServiceDiscoveryType && p->DiscoverMode.ServiceDiscoveryType!=WDI_P2P_SERVICE_DISCOVERY_TYPE_NO_SERVICE_DISCOVERY) ? STATUS_NOT_SUPPORTED:0;
}
static NTSTATUS Ap6256ServiceBegin(Wifi*,ULONG) {return 0;}
static VOID Ap6256ServiceStop(Wifi*,BOOLEAN) {}
static ULONG Ap6256ServiceAdvance(Wifi*) {assert(false);return 0;}
static NTSTATUS Ap6256P2pStartDiscovery(Device*,const AP6256_P2P_DISCOVER* d) {starts++;captured_discover=*d;return start_status;}
static NTSTATUS Ap6256WifiSetP2pDiscoveryState(Device*,UINT32,UINT32 ch,UINT32) {pulses++;last_channel=ch;return 0;}
static VOID Ap6256StartP2pActionFrame(Wifi*,AP6256_REQUEST,PWDI_MESSAGE_HEADER,UINT16,
    const AP6256_P2P_ACTION_FRAME* f,UINT32) {
    sends++;captured=*f;stored_len=f->VendorIesLength;
    if(stored_len)memcpy(stored,f->VendorIes,stored_len);
    preceding_len=f->PeerIesLength;assert(preceding_len<=sizeof(preceding));
    if(preceding_len)memcpy(preceding,f->PeerIes,preceding_len);
}
static NTSTATUS Ap6256SendGeneratedIndication(Wifi* w,UINT16 id,const WDI_MESSAGE_HEADER* h,UINT32,PVOID,PUCHAR data,ULONG len) {
    if(id==WDI_INDICATION_ACTION_FRAME_RECEIVED) {
        WDI_INDICATION_ACTION_FRAME_RECEIVED_PARAMETERS p={};
        assert(ParseWdiIndicationActionFrameReceivedFromIhv(len,data,&w->TlvContext,&p)==0);
        action_indications++;rx_port=h->PortId;rx_channel=p.ChannelInfo.ChannelNumber;rx_band=p.ChannelInfo.BandId;
        memcpy(rx_source,p.SourceAddress.Address,6);incoming_len=p.ActionFrameBody.ElementCount;
        assert(incoming_len<=sizeof(incoming));memcpy(incoming,p.ActionFrameBody.pElements,incoming_len);
        CleanupParsedWdiIndicationActionFrameReceivedFromIhv(&p);return 0;
    }
    if(id==WDI_INDICATION_P2P_OPERATING_CHANNEL_ATTRIBUTES) {
        WDI_INDICATION_P2P_OPERATING_CHANNEL_ATTRIBUTES_PARAMETERS p={};
        assert(ParseWdiIndicationP2pOperatingChannelAttributesFromIhv(len,data,&w->TlvContext,&p)==0);
        assert(h->PortId==(w->P2pPortCreated?1:0));
        assert(p.PreferredOperatingChannel.ChannelNumber==36 && p.PreferredOperatingChannel.OperatingClass==115);
        assert(p.PreferredListenChannel.ChannelNumber==w->Ctx->P2p.ListenChannel && p.PreferredListenChannel.OperatingClass==81);
        assert(p.ChannelList.ChannelEntries.ElementCount==3);
        assert(p.ChannelList.ChannelEntries.pElements[0].OperatingClass==81 && p.ChannelList.ChannelEntries.pElements[0].ChannelList.ElementCount==2);
        assert(p.ChannelList.ChannelEntries.pElements[2].OperatingClass==125 && p.ChannelList.ChannelEntries.pElements[2].ChannelList.pElements[0]==149);
        CleanupParsedWdiIndicationP2pOperatingChannelAttributesFromIhv(&p);channel_indications++;return 0;
    }
    if(id==WDI_INDICATION_P2P_GROUP_OPERATING_CHANNEL) {
        WDI_INDICATION_P2P_GROUP_OPERATING_CHANNEL_PARAMETERS p={};
        assert(ParseWdiIndicationP2pGroupOperatingChannelFromIhv(len,data,&w->TlvContext,&p)==0);
        assert(h->PortId==2 && p.Channel.ChannelNumber==36 && p.Channel.OperatingClass==115);
        assert(p.IndicateReason==WDI_P2P_CHANNEL_INDICATE_REASON_NEW_CONNECTION);
        if (w->TlvContext.PeerVersion >= WDI_VERSION_1_1_4) {
            assert(p.APBandInformation.BandID==WDI_BAND_ID_5000);
            assert(!p.APBandInformation.IsPCPinPBSS);
        }
        CleanupParsedWdiIndicationP2pGroupOperatingChannelFromIhv(&p);group_indications++;return 0;
    }
    assert(id==WDI_INDICATION_P2P_ACTION_FRAME_RECEIVED);indications++;rx_port=h->PortId;
    WDI_INDICATION_P2P_ACTION_FRAME_RECEIVED_PARAMETERS p={};
    assert(ParseWdiIndicationP2pActionFrameReceivedFromIhv(len,data,&w->TlvContext,&p)==0);
    assert(p.FrameInfo.Optional.DeviceContext_IsPresent && p.FrameInfo.DeviceContext.ElementCount==4);
    memcpy(&rx_channel,p.FrameInfo.DeviceContext.pElements,4);
    incoming_len=p.FrameInfo.FrameIEs.ElementCount;assert(incoming_len<=sizeof(incoming));
    if(incoming_len)memcpy(incoming,p.FrameInfo.FrameIEs.pElements,incoming_len);
    CleanupParsedWdiIndicationP2pActionFrameReceivedFromIhv(&p);return 0;
}
'''
DISCOVERY_MOCKS = r'''
static ULONG discovery_next;static int discovery_done;
static ULONG Ap6256P2pAdvanceDiscovery(Device*) {return discovery_next;}
static BOOLEAN Ap6256ClaimTask(Wifi* w,Task* task,PWDI_MESSAGE_HEADER h,PVOID* id) {
    assert(w->P2pLock);if(!task->Active)return FALSE;task->Active=FALSE;
    *h={};h->PortId=1;*id=NULL;return TRUE;
}
static NTSTATUS Ap6256SendIndicationRq(Wifi* w,UINT16 id,PWDI_MESSAGE_HEADER,UINT32,PVOID,NTSTATUS s,PUCHAR,ULONG) {
    assert(!w->P2pLock && id==WDI_INDICATION_P2P_DISCOVERY_COMPLETE);discovery_done++;request_status=s;return 0;
}
'''
TEST = r'''
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    Device d={};Wifi w={};w.Ctx=&d;d.WifiContext=&w;w.P2pPortCreated=TRUE;w.HardwareAvailable=1;
    w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;d.P2pBssValid=TRUE;d.DatapathRunning=TRUE;d.P2p.ListenChannel=1;
    d.Go.FirmwareReady=TRUE;d.Go.IfIndex=7;
    WDI_MESSAGE_HEADER h={};h.PortId=AP6256_DISCOVERY_PORT;
    const UCHAR wfd[]={221,4,0x50,0x6f,0x9a,10};
    UINT8* bytes=NULL;ULONG len=0;
    WDI_SET_ADVERTISEMENT_INFORMATION_PARAMETERS ad={};
    ad.Optional.DeviceCapability_IsPresent=TRUE;ad.DeviceCapability.DeviceCapabilityBitmap=0x25;
    ad.Optional.AdditionalIEs_IsPresent=TRUE;ad.AdditionalIEs.Optional.AdditionalProbeResponseIEs_IsPresent=TRUE;
    ad.AdditionalIEs.AdditionalProbeResponseIEs.pElements=(UINT8*)wfd;
    ad.AdditionalIEs.AdditionalProbeResponseIEs.ElementCount=sizeof(wfd);
    assert(GenerateWdiSetAdvertisementInformationToIhv(&ad,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==0 && d.P2p.DeviceCapability==0x25 && last_if==3);
    assert(stored_len==sizeof(wfd) && !memcmp(stored,wfd,sizeof(wfd)));
    h.PortId=AP6256_GROUP_PORT;
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==0 && d.Go.P2p.DeviceCapability==0x25 && last_if==7);
    h.PortId=0;int before=mutations;
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==STATUS_INVALID_DEVICE_STATE && mutations==before);
    FreeGenerated(bytes);bytes=NULL;h.PortId=1;

    WDI_P2P_ADVERTISED_SERVICE_ENTRY_CONTAINER service={};
    service.ServiceName.pElements=(UCHAR*)"org.wi-fi.test";
    service.ServiceName.ElementCount=14;
    service.AdvertisementID=7;service.ServiceStatus=1;
    ad.Optional.AdvertisedServices_IsPresent=TRUE;
    ad.AdvertisedServices.Optional.ServiceEntry_IsPresent=TRUE;
    ad.AdvertisedServices.ServiceEntry.pElements=&service;
    ad.AdvertisedServices.ServiceEntry.ElementCount=1;
    ad.DeviceCapability.DeviceCapabilityBitmap=0x77;
    assert(GenerateWdiSetAdvertisementInformationToIhv(&ad,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==STATUS_NOT_SUPPORTED && mutations==before && d.P2p.DeviceCapability==0x25);
    FreeGenerated(bytes);bytes=NULL;
    ad.AdvertisedServices.ServiceEntry.ElementCount=0;
    ad.AdvertisedServices.Optional.ServiceEntry_IsPresent=FALSE;
    ad.AdvertisedServices.ServiceEntry.pElements=NULL;
    ad.DeviceCapability.DeviceCapabilityBitmap=0x25;
    assert(GenerateWdiSetAdvertisementInformationToIhv(&ad,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==0);
    FreeGenerated(bytes);bytes=NULL;
    ad.Optional.AdvertisedServices_IsPresent=FALSE;
    {
        WDI_SET_ADVERTISEMENT_INFORMATION_PARAMETERS empty={};
        empty.Optional.AdvertisedServices_IsPresent=TRUE;
        UCHAR* emptyBytes=NULL;ULONG emptyLength=0;
        assert(GenerateWdiSetAdvertisementInformationToIhv(&empty,0,&w.TlvContext,&emptyLength,&emptyBytes)==0);
        assert(emptyLength==10);
        assert(!Ap6256EmptyGroupServiceList(NULL,emptyLength));
        SYSTEM_INFO sys={};GetSystemInfo(&sys);
        UCHAR* page=(UCHAR*)VirtualAlloc(NULL,sys.dwPageSize*2,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
        assert(page);DWORD oldProtection;
        assert(VirtualProtect(page+sys.dwPageSize,sys.dwPageSize,PAGE_NOACCESS,&oldProtection));
        for(ULONG cut=0;cut<=emptyLength;cut++) {
            UCHAR* bounded=page+sys.dwPageSize-cut;
            if(cut)memcpy(bounded,emptyBytes,cut);
            assert(!!Ap6256EmptyGroupServiceList(bounded,cut)==(cut==emptyLength));
        }
        assert(VirtualFree(page,0,MEM_RELEASE));
        h.PortId=AP6256_GROUP_PORT;
        w.Service.Active=TRUE;w.Service.AdvertisementCount=3;
        unsigned serviceCalls=service_advertisement_calls;
        int writes=mutations;
        Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,emptyBytes,emptyLength);
        assert(request_status==AP6256_EXPECT_EMPTY_GROUP_STATUS && mutations==writes);
        assert(w.Service.Active && w.Service.AdvertisementCount==3 && service_advertisement_calls==serviceCalls);
        UCHAR unknown[16]={};memcpy(unknown,emptyBytes,10);unknown[2]=12;
        const UCHAR prefix[]={0xf1,0,2,0,0xaa,0xbb};memcpy(unknown+10,prefix,sizeof(prefix));
        assert(!Ap6256EmptyGroupServiceList(unknown,sizeof(unknown)));
        Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,unknown,sizeof(unknown));
        assert(request_status==STATUS_NOT_SUPPORTED && mutations==writes && service_advertisement_calls==serviceCalls);
        UCHAR duplicate[20]={};memcpy(duplicate,emptyBytes,10);memcpy(duplicate+10,emptyBytes,10);
        assert(!Ap6256EmptyGroupServiceList(duplicate,sizeof(duplicate)));
        Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,duplicate,sizeof(duplicate));
        assert(request_status!=0 && service_advertisement_calls==serviceCalls);
        FreeGenerated(emptyBytes);
        empty.Optional.AdvertisedServices_IsPresent=FALSE;
        empty.Optional.AdditionalIEs_IsPresent=TRUE;
        empty.AdditionalIEs.Optional.AdditionalProbeResponseIEs_IsPresent=TRUE;
        empty.AdditionalIEs.AdditionalProbeResponseIEs.pElements=(UINT8*)wfd;
        empty.AdditionalIEs.AdditionalProbeResponseIEs.ElementCount=sizeof(wfd);
        empty.Optional.AdvertisedServices_IsPresent=TRUE;
        assert(GenerateWdiSetAdvertisementInformationToIhv(&empty,0,&w.TlvContext,&emptyLength,&emptyBytes)==0);
        Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,emptyBytes,emptyLength);
        assert(request_status==AP6256_EXPECT_EMPTY_GROUP_STATUS);
        assert(service_advertisement_calls==serviceCalls && w.Service.AdvertisementCount==3);
        if constexpr(AP6256_EXPECT_EMPTY_GROUP_STATUS==0)assert(stored_len==sizeof(wfd));
        FreeGenerated(emptyBytes);
        empty.AdvertisedServices.Optional.ServiceEntry_IsPresent=TRUE;
        empty.AdvertisedServices.ServiceEntry.pElements=&service;
        empty.AdvertisedServices.ServiceEntry.ElementCount=1;
        writes=mutations;
        assert(GenerateWdiSetAdvertisementInformationToIhv(&empty,0,&w.TlvContext,&emptyLength,&emptyBytes)==0);
        Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,emptyBytes,emptyLength);
        assert(request_status==STATUS_NOT_SUPPORTED && mutations==writes && service_advertisement_calls==serviceCalls);
        FreeGenerated(emptyBytes);
        w.Service.Active=FALSE;w.Service.AdvertisementCount=0;
        h.PortId=AP6256_DISCOVERY_PORT;
        printf("PASS: 10-byte empty GO service list status 0x%08X; discovery state isolation, combined IE request and nonempty rejection\n",(unsigned)AP6256_EXPECT_EMPTY_GROUP_STATUS);
    }
    before=mutations;
    UCHAR bad[]={221,8,0};
    ad.DeviceCapability.DeviceCapabilityBitmap=0x77;
    ad.AdditionalIEs.Optional.AdditionalBeaconIEs_IsPresent=TRUE;
    ad.AdditionalIEs.AdditionalBeaconIEs.pElements=(UINT8*)wfd;
    ad.AdditionalIEs.AdditionalBeaconIEs.ElementCount=sizeof(wfd);
    ad.AdditionalIEs.AdditionalProbeResponseIEs.pElements=bad;
    ad.AdditionalIEs.AdditionalProbeResponseIEs.ElementCount=sizeof(bad);
    assert(GenerateWdiSetAdvertisementInformationToIhv(&ad,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleSetAdvertisementInformation(&w,&h,NULL,bytes,len);
    assert(request_status==STATUS_INVALID_PARAMETER && mutations==before && d.P2p.DeviceCapability==0x25);
    FreeGenerated(bytes);bytes=NULL;

    WDI_SET_P2P_LISTEN_STATE_PARAMETERS ls={};ls.ListenState=(WDI_P2P_LISTEN_STATE)AP6256_P2P_LISTEN_HIGH;
    ls.ListenDuration.ListenActiveDuration=80;ls.ListenDuration.CycleDuration=160;
    ls.Optional.ListenChannel_IsPresent=TRUE;ls.ListenChannel.ChannelNumber=6;
    assert(GenerateWdiSetP2pListenStateToIhv(&ls,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleSetP2pListenState(&w,&h,NULL,bytes,len);
    assert(request_status==0 && pulses==1 && last_channel==6 && d.P2p.Listening && rearms==1);
    Task* busy[]={&w.ScanTask,&w.ActionFrameTask,&w.ConnectTask,&w.ClientConnectTask};
    for(auto task:busy) {
        task->Active=TRUE;before=pulses;int oldmut=mutations;
        Ap6256EvtP2pListenTick(&w);assert(pulses==before && last_delay==160);
        Ap6256HandleSetP2pListenState(&w,&h,NULL,bytes,len);
        assert(request_status==STATUS_DEVICE_BUSY && mutations==oldmut && pulses==before);
        task->Active=FALSE;
    }
    w.P2pDiscovering=TRUE;before=pulses;Ap6256EvtP2pListenTick(&w);assert(pulses==before);w.P2pDiscovering=FALSE;
    Ap6256EvtP2pListenTick(&w);assert(pulses==before+1);
    w.HardwareAvailable=0;before=rearms;Ap6256EvtP2pListenTick(&w);assert(rearms==before);w.HardwareAvailable=1;
    h.PortId=0;before=pulses;Ap6256HandleSetP2pListenState(&w,&h,NULL,bytes,len);
    assert(request_status==STATUS_INVALID_DEVICE_STATE && pulses==before);h.PortId=1;
    assert(Ap6256QuiesceP2pListen(&w)==0 && last_channel==0);
    FreeGenerated(bytes);bytes=NULL;

    w.P2pDiscovering=TRUE;w.P2pDiscoverTask.Active=TRUE;discovery_next=100;
    Ap6256EvtP2pDiscoverTick(&w);assert(w.P2pDiscovering && discovery_done==0 && last_delay==100);
    discovery_next=0;d.P2p.DiscoverStatus=STATUS_DEVICE_NOT_READY;
    Ap6256EvtP2pDiscoverTick(&w);assert(!w.P2pDiscovering && discovery_done==1 && request_status==STATUS_DEVICE_NOT_READY);
    Ap6256EvtP2pDiscoverTick(&w);assert(discovery_done==1);
    w.P2pDiscovering=TRUE;w.P2pDiscoverTask.Active=FALSE;
    Ap6256EvtP2pDiscoverTick(&w);assert(discovery_done==1);


    w.P2pDiscovering=FALSE;
    WDI_TASK_P2P_DISCOVER_PARAMETERS disc={};
    disc.DiscoverMode.DiscoveryType=WDI_P2P_DISCOVER_TYPE_SCAN_ONLY;
    disc.DiscoverMode.ScanType=WDI_P2P_SCAN_TYPE_ACTIVE;
    disc.DiscoverMode.ScanRepeatCount=3;disc.DiscoverMode.TimeBetweenScans=80;
    disc.DiscoverMode.ForcedDiscovery=TRUE;
    disc.DwellTime.MaximumScanTime=15000;disc.DwellTime.ActiveChannelDwellTime=30;
    disc.DwellTime.PassiveChannelDwellTime=60;
    WDI_SSID ssids[2];ssids[1].ElementCount=8;ssids[1].pElements=(UCHAR*)"DIRECT-A";
    disc.Optional.SSIDList_IsPresent=TRUE;disc.SSIDList.pElements=ssids;disc.SSIDList.ElementCount=2;
    WDI_CHANNEL_NUMBER ch2[]={1,6,11},ch5[]={36};
    WDI_SCAN_BAND_CHANNEL_LIST_CONTAINER bands[2];
    bands[0].BandID=WDI_BAND_ID_2400;bands[0].ChannelList.pElements=ch2;bands[0].ChannelList.ElementCount=3;
    bands[1].BandID=WDI_BAND_ID_5000;bands[1].ChannelList.pElements=ch5;bands[1].ChannelList.ElementCount=1;
    WDI_P2P_DISCOVERY_CHANNEL_SETTINGS_CONTAINER settings[2];
    settings[0].ListenDuration.CycleDuration=100;settings[0].ListenDuration.ListenActiveDuration=40;
    settings[0].BandChannelList.pElements=&bands[0];settings[0].BandChannelList.ElementCount=1;
    settings[1].ListenDuration.CycleDuration=120;settings[1].ListenDuration.ListenActiveDuration=55;
    settings[1].BandChannelList.pElements=&bands[1];settings[1].BandChannelList.ElementCount=1;
    disc.Optional.DiscoveryChannelSettings_IsPresent=TRUE;
    disc.DiscoveryChannelSettings.pElements=settings;disc.DiscoveryChannelSettings.ElementCount=2;
    disc.Optional.VendorIEs_IsPresent=TRUE;disc.VendorIEs.pElements=(UCHAR*)wfd;disc.VendorIEs.ElementCount=sizeof(wfd);
    disc.Optional.bIncludeListenChannel_IsPresent=TRUE;disc.bIncludeListenChannel=FALSE;
    assert(GenerateWdiTaskP2pDiscoverToIhv(&disc,0,&w.TlvContext,&len,&bytes)==0);
    w.ScanIndicated=5;w.ScanDropped=7;
    Ap6256HandleP2pDiscover(&w,NULL,&h,bytes,len);FreeGenerated(bytes);bytes=NULL;
    assert(request_status==0 && starts==1 && w.P2pDiscovering && w.P2pDiscoverTask.Active && last_delay==20);
    assert(!w.ScanIndicated && !w.ScanDropped);
    assert(captured_discover.ScanRepeatCount==3 && captured_discover.TimeBetweenScans==80);
    assert(captured_discover.MaximumDwellMs==15000 && captured_discover.ForcedDiscovery);
    assert(!!captured_discover.OmitListenChannel==(w.TlvContext.PeerVersion>=WDI_VERSION_1_0_20));
    assert(captured_discover.SsidCount==2 && !captured_discover.Ssids[0].Length);
    assert(captured_discover.Ssids[1].Length==8 && !memcmp(captured_discover.Ssids[1].Data,"DIRECT-A",8));
    assert(captured_discover.ChannelCount==4 && captured_discover.Channels[3].Number==36);
    assert(captured_discover.Channels[0].DwellMs==40 && captured_discover.Channels[0].CycleMs==100);
    assert(captured_discover.Channels[3].DwellMs==55 && captured_discover.Channels[3].CycleMs==120);
    AP6256_P2P_DISCOVER plan;
    disc.bIncludeListenChannel=TRUE;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==0 && !plan.OmitListenChannel);
    disc.Optional.bIncludeListenChannel_IsPresent=FALSE;
    ch5[0]=300;assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_INVALID_PARAMETER);ch5[0]=36;
    ssids[1].ElementCount=33;assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_INVALID_PARAMETER);ssids[1].ElementCount=8;
    settings[0].ListenDuration.ListenActiveDuration=101;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_INVALID_PARAMETER);
    settings[0].ListenDuration.ListenActiveDuration=40;
    disc.DiscoverMode.DiscoveryType=WDI_P2P_DISCOVER_TYPE_SCAN_SOCIAL_CHANNELS;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==0 && plan.ChannelCount==3);
    w.DisallowedBandMask=1;assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_NETWORK_UNREACHABLE);
    w.DisallowedBandMask=0;disc.DiscoverMode.DiscoveryType=WDI_P2P_DISCOVER_TYPE_SCAN_ONLY;
    disc.Optional.DiscoveryChannelSettings_IsPresent=FALSE;disc.Optional.SSIDList_IsPresent=FALSE;
    disc.DiscoverMode.ScanRepeatCount=0;disc.DiscoverMode.TimeBetweenScans=0xffffffffu;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==0 && plan.SsidCount==1 && !plan.ChannelCount);
    assert(plan.ScanRepeatCount==0 && plan.TimeBetweenScans==0xffffffffu && !plan.Ssids[0].Length);
    w.P2pDiscovering=FALSE;w.P2pDiscoverTask.Active=FALSE;
    assert(GenerateWdiTaskP2pDiscoverToIhv(&disc,0,&w.TlvContext,&len,&bytes)==0);
    w.ScanTask.Active=TRUE;before=starts;int before_mutations=mutations;
    Ap6256HandleP2pDiscover(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_INVALID_DEVICE_STATE && starts==before && mutations==before_mutations);
    w.ScanTask.Active=FALSE;start_status=STATUS_DEVICE_NOT_READY;
    Ap6256HandleP2pDiscover(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_DEVICE_NOT_READY && !w.P2pDiscoverTask.Active && !w.P2pDiscovering);
    start_status=0;FreeGenerated(bytes);bytes=NULL;



    before=starts;before_mutations=mutations;
    WDI_P2P_SERVICE_NAME_HASH_CONTAINER hash={};
    disc.DiscoverMode.ServiceDiscoveryType=WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_NAME_ONLY;
    disc.Optional.ServiceNameHash_IsPresent=TRUE;
    disc.ServiceNameHash.pElements=&hash;disc.ServiceNameHash.ElementCount=1;
    assert(GenerateWdiTaskP2pDiscoverToIhv(&disc,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pDiscover(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_NOT_SUPPORTED && starts==before && mutations==before_mutations && !w.P2pDiscoverTask.Active);
    FreeGenerated(bytes);bytes=NULL;
    disc.DiscoverMode.ServiceDiscoveryType=WDI_P2P_SERVICE_DISCOVERY_TYPE_NO_SERVICE_DISCOVERY;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_NOT_SUPPORTED);
    disc.Optional.ServiceNameHash_IsPresent=FALSE;
    WDI_P2P_SERVICE_INFORMATION_DISCOVERY_ENTRY_CONTAINER query={};
    query.ServiceName.pElements=service.ServiceName.pElements;
    query.ServiceName.ElementCount=service.ServiceName.ElementCount;
    query.ServiceTransactionId=19;
    disc.DiscoverMode.ServiceDiscoveryType=WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_INFORMATION;
    disc.Optional.ServiceInformationDiscoveryEntry_IsPresent=TRUE;
    disc.ServiceInformationDiscoveryEntry.pElements=&query;disc.ServiceInformationDiscoveryEntry.ElementCount=1;
    assert(GenerateWdiTaskP2pDiscoverToIhv(&disc,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pDiscover(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_NOT_SUPPORTED && starts==before && mutations==before_mutations && !w.P2pDiscoverTask.Active);
    FreeGenerated(bytes);bytes=NULL;
    disc.Optional.ServiceInformationDiscoveryEntry_IsPresent=FALSE;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==STATUS_NOT_SUPPORTED);
    disc.DiscoverMode.ServiceDiscoveryType=WDI_P2P_SERVICE_DISCOVERY_TYPE_NO_SERVICE_DISCOVERY;
    assert(Ap6256CaptureP2pDiscover(&w,&disc,&plan)==0);

    WDI_TASK_P2P_SEND_REQUEST_ACTION_FRAME_PARAMETERS req={};
    req.RequestParams.RequestFrameType=WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_REQUEST;
    req.RequestParams.DialogToken=9;req.RequestParams.SendTimeout=500;req.RequestParams.PostACKDwellTime=100;
    req.Optional.GONegotiationRequestInfo_IsPresent=TRUE;
    req.GONegotiationRequestInfo.RequestParams.GOIntent=7;req.GONegotiationRequestInfo.RequestParams.TieBreaker=1;
    req.DeviceDescriptor.ChannelInfo.ChannelNumber=36;req.DeviceDescriptor.ChannelInfo.BandId=WDI_BAND_ID_5000;
    req.Optional.VendorIEs_IsPresent=TRUE;req.VendorIEs.pElements=(UINT8*)wfd;req.VendorIEs.ElementCount=sizeof(wfd);
    assert(GenerateWdiTaskP2pSendRequestActionFrameToIhv(&req,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pSendRequestActionFrame(&w,NULL,&h,bytes,len);
    assert(sends==1 && captured.TransmitChannel==36 && captured.GoIntentByte==15 && captured.DialogToken==9);
    assert(stored_len==sizeof(wfd) && !memcmp(stored,wfd,sizeof(wfd)));
    h.PortId=0;Ap6256HandleP2pSendRequestActionFrame(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_INVALID_DEVICE_STATE && sends==1);h.PortId=1;
    FreeGenerated(bytes);bytes=NULL;

    UCHAR body[14]={4,9,0x50,0x6f,0x9a,9,0,9};memcpy(body+8,wfd,sizeof(wfd));
    UCHAR peer[6]={2,1,2,3,4,5};
    Ap6256NetP2pActionFrameReceived(&w,WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_REQUEST,0xd024,peer,body,sizeof(body));
    assert(indications==1 && rx_port==1 && rx_channel==36 && incoming_len==6 && !memcmp(incoming,wfd,6));
    UINT32 channel;WDI_BAND_ID band;
    for(UINT16 sb=0;sb<4;sb++) {Ap6256ChanspecToChannel((UINT16)(0xe02a|(sb<<8)),&channel,&band);assert(channel==36u+4u*sb && band==WDI_BAND_ID_5000);}
    Ap6256ChanspecToChannel(0xd826,&channel,&band);assert(channel==36);
    Ap6256ChanspecToChannel(0xd926,&channel,&band);assert(channel==40);
    Ap6256ChanspecToChannel(0xe72a,&channel,&band);assert(channel==0);
    WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME_PARAMETERS rsp={};
    rsp.ResponseParams.ResponseFrameType=WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_RESPONSE;
    rsp.ResponseParams.DialogToken=9;rsp.Optional.GONegotiationResponseInfo_IsPresent=TRUE;
    rsp.PrecedingFrameInformation.FrameParams.ActionFrameType=WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_REQUEST;
    rsp.PrecedingFrameInformation.FrameParams.DialogToken=9;
    rsp.PrecedingFrameInformation.FrameIEs.pElements=incoming;
    rsp.PrecedingFrameInformation.FrameIEs.ElementCount=incoming_len;
    rsp.PrecedingFrameInformation.Optional.DeviceContext_IsPresent=TRUE;
    rsp.PrecedingFrameInformation.DeviceContext.pElements=(UINT8*)&rx_channel;
    rsp.PrecedingFrameInformation.DeviceContext.ElementCount=4;
    assert(GenerateWdiTaskP2pSendResponseActionFrameToIhv(&rsp,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len);
    assert(sends==2 && captured.TransmitChannel==36 && captured.HaveStatus && captured.DialogToken==9);
    h.PortId=0;Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len);
    assert(request_status==STATUS_INVALID_DEVICE_STATE && sends==2);
    FreeGenerated(bytes);


    d.FirmwareP2pSupported=TRUE;w.PortCreated=TRUE;
    for(ULONG version : {WDI_VERSION_1_0, WDI_VERSION_LATEST}) {
        w.TlvContext.PeerVersion=version;
        for(int port=0;port<2;port++) {w.P2pPortCreated=(BOOLEAN)port;Ap6256IndicateP2pChannels(&w);}
        h.PortId=2;Ap6256IndicateP2pGroupChannel(&w,&h,NULL,36);
    }
    assert(channel_indications==4 && group_indications==2);
    plan_status=STATUS_IO_TIMEOUT;Ap6256IndicateP2pChannels(&w);assert(channel_indications==4);plan_status=0;

    w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;h.PortId=1;
    req.GONegotiationRequestInfo.Optional.RemoteListenChannel_IsPresent=TRUE;
    req.GONegotiationRequestInfo.RemoteListenChannel.ChannelNumber=6;
    req.GONegotiationRequestInfo.RemoteListenChannel.OperatingClass=81;
    bytes=NULL;assert(GenerateWdiTaskP2pSendRequestActionFrameToIhv(&req,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pSendRequestActionFrame(&w,NULL,&h,bytes,len);
    assert(captured.TransmitChannel==6);FreeGenerated(bytes);bytes=NULL;
    rsp.ResponseParams.ResponseFrameType=WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_CONFIRM;
    rsp.Optional.GONegotiationResponseInfo_IsPresent=FALSE;rsp.Optional.GONegotiationConfirmationInfo_IsPresent=TRUE;
    rsp.GONegotiationConfirmationInfo.Optional.RemoteListenChannel_IsPresent=TRUE;
    rsp.GONegotiationConfirmationInfo.RemoteListenChannel.ChannelNumber=11;
    rsp.GONegotiationConfirmationInfo.RemoteListenChannel.OperatingClass=81;
    assert(GenerateWdiTaskP2pSendResponseActionFrameToIhv(&rsp,0,&w.TlvContext,&len,&bytes)==0);
    Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len);
    assert(captured.TransmitChannel==11 && preceding_len==incoming_len && !memcmp(preceding,incoming,incoming_len));
    FreeGenerated(bytes);


    const UCHAR action[]={10,7,23,0,0,0,1};
    w.PortCreated=TRUE;w.P2pPortCreated=TRUE;d.P2pBssIndex=1;
    d.Go.Created=TRUE;d.Go.BssIndex=2;
    struct {UCHAR ifidx,bss;UINT16 port;} routes[]={{0,0,0},{3,1,1},{7,2,2}};
    for(const auto& route:routes) {
        int n=action_indications;
        Ap6256NetActionFrameReceived(&d,route.ifidx,route.bss,peer,0xd024,action,sizeof(action));
        assert(action_indications==n+1 && rx_port==route.port);
        assert(rx_channel==36 && rx_band==WDI_BAND_ID_5000 && !memcmp(rx_source,peer,6));
        assert(incoming_len==sizeof(action) && !memcmp(incoming,action,sizeof(action)));
    }


    const UCHAR beaconRequest[]={5,0,0x79,0,0,38,16,0x37,0,5,115,36,0,0,100,0,0,0x94,0x83,0xc4,0xa2,0x20,0x7a};
    int beaconBefore=action_indications;
    Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,beaconRequest,sizeof(beaconRequest));
    assert(action_indications==beaconBefore+1 && rx_port==0);
    assert(incoming_len==sizeof(beaconRequest) && !memcmp(incoming,beaconRequest,sizeof(beaconRequest)));
    int n=action_indications;
    Ap6256NetActionFrameReceived(&d,0,9,peer,0xd024,action,sizeof(action));
    Ap6256NetActionFrameReceived(&d,7,0,peer,0xd024,action,sizeof(action));
    Ap6256NetActionFrameReceived(&d,0,1,peer,0xd024,action,sizeof(action));
    Ap6256NetActionFrameReceived(&d,0,2,peer,0xd024,action,sizeof(action));
    w.PortCreated=FALSE;Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,action,sizeof(action));w.PortCreated=TRUE;
    w.P2pPortCreated=FALSE;Ap6256NetActionFrameReceived(&d,3,1,peer,0xd024,action,sizeof(action));w.P2pPortCreated=TRUE;
    d.Go.Created=FALSE;Ap6256NetActionFrameReceived(&d,7,2,peer,0xd024,action,sizeof(action));d.Go.Created=TRUE;
    d.Go.FirmwareReady=FALSE;Ap6256NetActionFrameReceived(&d,7,2,peer,0xd024,action,sizeof(action));d.Go.FirmwareReady=TRUE;
    w.Stopping=TRUE;Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,action,sizeof(action));w.Stopping=FALSE;
    d.DatapathRunning=FALSE;Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,action,sizeof(action));d.DatapathRunning=TRUE;
    Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,NULL,0);
    Ap6256NetActionFrameReceived(&d,0,0,peer,0xe72a,action,sizeof(action));
    assert(action_indications==n);


    discovery_if=0;Ap6256NetActionFrameReceived(&d,0,1,peer,0x1006,action,sizeof(action));
    assert(action_indications==n+1 && rx_port==1 && rx_channel==6 && rx_band==WDI_BAND_ID_2400);


    n=indications;Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,body,sizeof(body));
    assert(indications==n+1 && rx_port==1 && incoming_len==6 && !memcmp(incoming,wfd,6));
    w.P2pPortCreated=FALSE;Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,body,sizeof(body));
    assert(indications==n+1);

    const UCHAR gas[]={4,11,19,0,0,0,0,108,2,0,0,0,0};
    n=action_indications;
    Ap6256NetActionFrameReceived(&d,0,0,peer,0xd024,gas,sizeof(gas));
    assert(action_indications==n+1 && rx_port==0 && incoming_len==sizeof(gas) && !memcmp(incoming,gas,sizeof(gas)));
    w.P2pPortCreated=TRUE;
    Ap6256NetActionFrameReceived(&d,0,1,peer,0x1006,gas,sizeof(gas));
    assert(action_indications==n+2 && rx_port==1 && incoming_len==sizeof(gas) && !memcmp(incoming,gas,sizeof(gas)));
    UCHAR provisionIes[129]={}, provisionVendor[42]={221,40,0x50,0x6f,0x9a,0x0a};
    provisionIes[0]=221;provisionIes[1]=127;
    const ULONG provisionVersions[]={WDI_VERSION_1_1_9,WDI_VERSION_1_1_10};
    const UCHAR defaultGroupCapability=d.P2p.GroupCapability=0x25;
    h.PortId=1;w.P2pPortCreated=TRUE;
    unsigned provisionCases=0;
    for(ULONG version:provisionVersions) for(int context=0;context<2;++context) for(int present=0;present<2;++present) {
        WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME_PARAMETERS p={};
        w.TlvContext.PeerVersion=version;
        p.ResponseParams.ResponseFrameType=WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_RESPONSE;
        p.ResponseParams.DialogToken=9;p.ResponseParams.SendTimeout=500;p.ResponseParams.PostACKDwellTime=100;
        memcpy(p.ResponseParams.PeerDeviceAddress.Address,peer,6);
        p.Optional.ProvisionDiscoveryResponseInfo_IsPresent=(BOOLEAN)present;
        p.ProvisionDiscoveryResponseInfo.ResponseParams.GroupCapability=0x17;
        p.Optional.VendorIEs_IsPresent=TRUE;
        p.VendorIEs.pElements=provisionVendor;p.VendorIEs.ElementCount=sizeof(provisionVendor);
        p.PrecedingFrameInformation.FrameParams.ActionFrameType=WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_REQUEST;
        p.PrecedingFrameInformation.FrameParams.DialogToken=9;
        memcpy(p.PrecedingFrameInformation.FrameParams.PeerDeviceAddress.Address,peer,6);
        p.PrecedingFrameInformation.FrameIEs.pElements=provisionIes;
        p.PrecedingFrameInformation.FrameIEs.ElementCount=sizeof(provisionIes);
        p.PrecedingFrameInformation.Optional.DeviceContext_IsPresent=(BOOLEAN)context;
        p.PrecedingFrameInformation.DeviceContext.pElements=(UINT8*)&rx_channel;
        p.PrecedingFrameInformation.DeviceContext.ElementCount=4;
        len=0;bytes=NULL;
        assert(GenerateWdiTaskP2pSendResponseActionFrameToIhv(&p,0,&w.TlvContext,&len,&bytes)==0);
        if(context && !present)assert(len==229);
        int sent=sends;request_status=0x12345678;
        Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len);
        assert(sends==sent+1 && captured.Subtype==AP6256_P2P_AF_PROV_DISC_RSP && !captured.HaveStatus);
        assert(captured.DialogToken==9 && captured.GroupCapability==(present ? 0x17 : defaultGroupCapability));
        assert(captured.TransmitChannel==(context ? rx_channel : 0));
        assert(stored_len==sizeof(provisionVendor) && !memcmp(stored,provisionVendor,stored_len));
        assert(preceding_len==sizeof(provisionIes) && !memcmp(preceding,provisionIes,preceding_len));
        h.PortId=0;sent=sends;
        Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len);
        assert(sends==sent && request_status==STATUS_INVALID_DEVICE_STATE);h.PortId=1;
        sent=sends;
        Ap6256HandleP2pSendResponseActionFrame(&w,NULL,&h,bytes,len-1);
        assert(sends==sent && !NT_SUCCESS(request_status));
        FreeGenerated(bytes);bytes=NULL;++provisionCases;
    }
    printf("PASS: %u Provision Discovery responses with optional info absent/present; captured 229-byte shape, capability/context/vendor preservation and malformed/wrong-port rejection\n",provisionCases);
    puts("PASS: production WDI handlers + Microsoft codec, unsupported service rejection before mutation, empty advertisement clear, ordinary discovery/listen/action policies and unchanged GAS/ANQP receive transport");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action-rx-source', type=Path, default=ROOT / 'src/common/netadapter.c', help='Use a previous production receive body as a negative control')
    parser.add_argument('--output', type=Path, default=output_dir('p2p-wdi'))
    parser.add_argument('--response-source', type=Path, default=ROOT / 'src/common/netadapter.c')
    parser.add_argument('--advertisement-source', type=Path, default=ROOT / 'src/common/netadapter.c')
    args = parser.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=True)
    text = PRE + '\n#include <initializer_list>\n'
    text += '#define AP6256_EXPECT_EMPTY_GROUP_STATUS ' + '0' + '\n'
    headers = {name: read_source_text(ROOT / 'src' / name) for name in ('ap6256.h', 'p2p.h', 'wifi_ops.h', 'p2p.c')}
    for line in '\n'.join(headers.values()).splitlines():
        if re.match('#define AP6256_P2P_(?:DISCOVER_|LISTEN_|IE_|SECONDARY_MAX|DEVICE_NAME_MAX|VENDOR_IE_MAX|AF_|ACTION_HEADER)', line):
            text += line + '\n'
    for (file, name) in [('wifi_ops.h', 'AP6256_SCAN_BAND'), ('ap6256.h', 'AP6256_P2P_FRAME'), ('ap6256.h', 'AP6256_P2P_DEVICE_TYPE'), ('ap6256.h', 'AP6256_P2P_IE_SLOT'), ('ap6256.h', 'AP6256_P2P_DISCOVER_SSID'), ('ap6256.h', 'AP6256_P2P_DISCOVER_CHANNEL'), ('ap6256.h', 'AP6256_P2P_DISCOVER'), ('ap6256.h', 'AP6256_P2P_STATE'), ('p2p.h', 'AP6256_P2P_DISCOVER_PHASE'), ('p2p.h', 'AP6256_P2P_ACTION_FRAME')]:
        text += re.search('typedef (?:struct|enum) _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', headers[file])[0] + '\n'
    text += re.search('typedef struct _AP6256_P2P_CHANNEL_PLAN\\s*\\{[\\s\\S]*?\\}\\s*AP6256_P2P_CHANNEL_PLAN;', headers['p2p.h'])[0] + '\n'
    text += MOCKS
    ownership = read_source_text(ROOT / 'src/common/native_mgmt.h')
    ownership = ownership[ownership.index('static __inline BOOLEAN Ap6256OwnsManagementFrame'):]
    ownership = re.sub('_In_reads_bytes_opt_\\(Length\\)|_In_', '', ownership).replace('PAP6256_DEVICE_CONTEXT', 'Device*')
    text += '\n' + ownership + '\n'
    source = read_source_text(ROOT / 'src/common/netadapter.c')
    text += re.search('static const UINT16 Ap6256Channels5\\[\\] = \\{[\\s\\S]*?\\};', source)[0] + '\n'
    sigs = [('p2p.c', 'BOOLEAN Ap6256P2pVendorIesValid(const UCHAR* Ies,ULONG Length)'), ('p2p.c', 'BOOLEAN Ap6256P2pIsSocialChannel(UINT32 Channel)'), ('p2p.c', 'NTSTATUS Ap6256P2pPulseListen(Device* Ctx)'), ('p2p.c', 'NTSTATUS Ap6256P2pSetListenState(Device* Ctx,UINT32 State,UINT32 ActiveMs,UINT32 CycleMs,UINT32 Channel)'), ('netadapter.c', 'VOID Ap6256FillP2pGroupId(AP6256_P2P_ACTION_FRAME* Frame,const WDI_P2P_GROUP_ID* GroupId)'), ('netadapter.c', 'VOID Ap6256HandleSetAdvertisementInformation(Wifi* Wifi,PWDI_MESSAGE_HEADER Header,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'VOID Ap6256HandleSetP2pListenState(Wifi* Wifi,PWDI_MESSAGE_HEADER Header,AP6256_REQUEST Request,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'NTSTATUS Ap6256QuiesceP2pListen(Wifi* Wifi)'), ('netadapter.c', 'VOID Ap6256HandleP2pSendRequestActionFrame(Wifi* Wifi,AP6256_REQUEST Request,PWDI_MESSAGE_HEADER Header,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'VOID Ap6256HandleP2pSendResponseActionFrame(Wifi* Wifi,AP6256_REQUEST Request,PWDI_MESSAGE_HEADER Header,const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'VOID Ap6256ChanspecToChannel(UINT16 Chanspec,PUINT32 Channel,WDI_BAND_ID* Band)'), ('netadapter.c', 'VOID Ap6256NetP2pActionFrameReceived(Wifi* Wifi,WDI_P2P_ACTION_FRAME_TYPE Type,UINT16 Chanspec,const UCHAR* SourceAddress,const UCHAR* Body,ULONG Length)')]
    sigs += [('netadapter.c', 'BOOLEAN Ap6256ChannelSupported(AP6256_SCAN_BAND Band,WDI_CHANNEL_NUMBER Channel)'), ('netadapter.c', 'NTSTATUS Ap6256AppendP2pDiscoverChannel(AP6256_P2P_DISCOVER* Discover,UINT16 Number,UINT32 DwellMs,UINT32 CycleMs)'), ('netadapter.c', 'NTSTATUS Ap6256CaptureP2pDiscover(Wifi* Wifi,const WDI_TASK_P2P_DISCOVER_PARAMETERS* Params,AP6256_P2P_DISCOVER* Discover)'), ('netadapter.c', 'VOID Ap6256HandleP2pDiscover(Wifi* Wifi,AP6256_REQUEST Request,PWDI_MESSAGE_HEADER Header,const UCHAR* Tlv,ULONG TlvLength)')]
    sigs = [('p2p.c', 'UCHAR Ap6256P2pChannelClass(UINT32 Channel)'), ('netadapter.c', 'BOOLEAN Ap6256ReadTlvHeader(const UCHAR* Tlv,ULONG TlvLength,ULONG Offset,UINT16* Type,UINT16* Length)'), ('netadapter.c', 'BOOLEAN Ap6256EmptyGroupServiceList(const UCHAR* Tlv,ULONG TlvLength)'), ('netadapter.c', 'VOID Ap6256IndicateP2pChannels(Wifi* Wifi)'), ('netadapter.c', 'VOID Ap6256IndicateP2pGroupChannel(Wifi* Wifi,const WDI_MESSAGE_HEADER* Header,PVOID RequestId,UINT32 Channel)')] + sigs
    for (file, sig) in sigs:
        name = re.search('(Ap6256\\w+)\\(', sig)[1]
        selected = args.response_source if name == 'Ap6256HandleP2pSendResponseActionFrame' else args.advertisement_source
        definition = _functions(read_source_text(selected))[name] if name in ('Ap6256HandleP2pSendResponseActionFrame', 'Ap6256HandleSetAdvertisementInformation') else None
        body = definition[definition.index('{'):] if definition else hotspot.body(file, name)
        text += '\n' + sig + '\n' + body + '\n'
    text += '\nBOOLEAN Ap6256P2pActionFrameType(const UCHAR* Body,ULONG Length,WDI_P2P_ACTION_FRAME_TYPE* Type)\n' + hotspot.body('netadapter.c', 'Ap6256P2pActionFrameType') + '\n'
    rx_source = read_source_text(args.action_rx_source, encoding='utf-8-sig')
    start = rx_source.rindex('VOID Ap6256NetActionFrameReceived(')
    start = rx_source.index('{', start)
    end = rx_source.index('\n}\n', start) + 2
    text += r'''
VOID Ap6256NetActionFrameReceived(Device* Ctx,UCHAR IfIndex,UCHAR BssCfgIndex,const UCHAR* SourceAddress,UINT16 Chanspec,const UCHAR* Body,ULONG Length)
'''
    text += '\n{ (void)IfIndex; (void)BssCfgIndex;\n' + rx_source[start + 1:end] + '\n'
    source = read_source_text(ROOT / 'src/common/netadapter.c')
    text += DISCOVERY_MOCKS
    for signature in ('static VOID Ap6256EvtP2pListenTick(PVOID Context)', 'static VOID Ap6256EvtP2pDiscoverTick(_In_ PVOID Context)'):
        start = source.index(signature)
        end = source.index('\n}\n', start) + 2
        text += re.sub('#else[\\s\\S]*?#endif', '', source[start:end], count=1) + '\n'
    text += TEST
    cpp = out / 'tests.cpp'
    write_bytes(cpp, (contract_preamble() + text).encode())
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')] + ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')] + [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
