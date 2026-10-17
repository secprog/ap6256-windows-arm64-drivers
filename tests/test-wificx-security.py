# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'WiFiCx security capabilities and opaque request/indication bindings.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import importlib.util
import re
import subprocess
import sys
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]
OUT = output_dir('wificx-security')

def load(name):
    spec = importlib.util.spec_from_file_location(name, AP / 'tests' / ('test-' + name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def function(source, name):
    return _functions(source)[name] + '\n'
MOCKS = r'''
#include <vector>
#include <stdlib.h>
typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#undef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_CANCELLED ((NTSTATUS)0xc0000120)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define AP6256_GROUP_PORT 2u
#define AP6256_GO_PEERS 9u
#define AP6256_GO_CLIENTS 8u
#define AP6256_POOL_TAG 1u
#define POOL_FLAG_PAGED 1u
#define AP6256_CMDQ_DEPTH 16u
#define MAXULONG 0xffffffffu
struct HardwareDevice;
typedef HardwareDevice Device;
typedef Device* WDFDEVICE;
DECLARE_HANDLE(WIFIREQUEST);
typedef WIFIREQUEST AP6256_REQUEST;
struct RequestData {UINT16 Id;UCHAR* Bytes;UINT Input,Output;ULONG Complete=0,Written=0;NTSTATUS Status=0;};
struct AP6256_FT_EVENT {ULONG Owned;};
struct CxRole {UINT16 PortId=0,LogicalPort=0;LONG Ready=1,Closing=0;};
typedef CxRole* PAP6256_CX_ADAPTER;
struct Wifi {
    struct {int AdapterLock=0,RoleLock=0;CxRole* Roles[2]={};} Model;
    Device* Ctx=nullptr;TLV_CONTEXT TlvContext={};
    int CommandWorkItem=1;LONG Stopping=0,HardwareAvailable=1;
    int CommandLock=0;ULONG CommandHead=0,CommandTail=0;
    AP6256_REQUEST CommandPending[AP6256_CMDQ_DEPTH]={};
    LONG CommandSaeGeneration[AP6256_CMDQ_DEPTH]={};
    struct {
        LONG SaeGeneration=0,SaeLostGeneration=0;
        ULONG SaeHead=0,SaeTail=0,FtHead=0,FtTail=0;
        BOOLEAN FtEventsLost=FALSE;
        AP6256_FT_EVENT* FtEvents[2]={};
    } Auth;
    struct {BOOLEAN Active=TRUE;} ScanTask,ConnectTask,DisconnectTask;
    struct {struct {BOOLEAN Active=TRUE;} Task;} Ftm;
};
typedef Wifi AP6256_WIFI;
typedef Wifi* PAP6256_WIFI;
struct HardwareDevice {
    struct {ULONG ChipId=0x4345,ChipRev=9;} Chip;
    BOOLEAN FirmwareMboTransport=FALSE,FirmwareFtmSupported=FALSE;
    BOOLEAN FirmwareExternalAuth=FALSE,FirmwarePrivateSae=FALSE,FirmwareMfpSupported=FALSE;
    BOOLEAN FirmwareFtPatchVerified=FALSE,FirmwareHostFt=FALSE;
    BOOLEAN FirmwareOwePatchVerified=FALSE,FirmwareHostOwe=FALSE;
    BOOLEAN HostFipsReady=FALSE;
    BOOLEAN WifiCapabilitiesSet=FALSE,FirmwareServiceOffload=FALSE,FirmwareP2pSupported=FALSE;
    UINT16 WifiStationPortId=0,WifiDirectPortId=1,WifiGroupPortId=2;PVOID WifiEngine=nullptr;PVOID WifiDirectDevice=nullptr;
    struct {UCHAR DeviceAddress[6]={};} P2p;
    WDFDEVICE Device=this;Wifi* Adapter=nullptr;PVOID NetAdapter=nullptr;
    @STATION_CIPHER_FIELDS@
    DOT11_AUTH_CIPHER_PAIR WifiGroupCipher[2]={};
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static Device* Ap6256GetDeviceContext(WDFDEVICE d) {return d;}
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->Adapter;}
static ULONG peerVersion=WDI_VERSION_1_1_10;
static ULONG WifiDeviceGetOsWdiVersion(WDFDEVICE) {return peerVersion;}
static ULONG calls,failAt,pools;
static BOOLEAN failAllocation;
static Wifi* ExAllocatePool2(ULONG,SIZE_T n,ULONG) {
    assert(n==sizeof(Wifi));if(failAllocation)return nullptr;++pools;
    return (Wifi*)calloc(1,n);
}
static void ExFreePoolWithTag(Wifi* p,ULONG) {assert(pools);--pools;free(p);}
static ULONG freedFt;
static void ExFreePoolWithTag(AP6256_FT_EVENT* p,ULONG tag) {
    assert(p && p->Owned==99 && tag==AP6256_POOL_TAG);++freedFt;free(p);
}
static NTSTATUS step() {return ++calls==failAt ? STATUS_IO_TIMEOUT : STATUS_SUCCESS;}
static WIFI_DEVICE_CAPABILITIES reportedDevice;
static WIFI_STATION_CAPABILITIES reportedStation;
static NTSTATUS WifiDeviceSetDeviceCapabilities(WDFDEVICE,const WIFI_DEVICE_CAPABILITIES* p) {
    reportedDevice=*p;assert(p->Size==sizeof(*p));return step();
}
static NTSTATUS WifiDeviceSetStationCapabilities(WDFDEVICE d,const WIFI_STATION_CAPABILITIES* p) {
    reportedStation=*p;assert(p->Size==sizeof(*p));
    assert(p->UnicastAlgorithmsList==d->WifiAuthCipher && p->MulticastDataAlgorithmsList==d->WifiAuthCipher);
    assert(p->MulticastMgmtAlgorithmsList==d->WifiMgmtCipher);return step();
}
static NTSTATUS WifiDeviceSetBandCapabilities(WDFDEVICE,const WIFI_BAND_CAPABILITIES* p) {
    assert(p->NumBands==2);return step();
}
static NTSTATUS WifiDeviceSetPhyCapabilities(WDFDEVICE,const WIFI_PHY_CAPABILITIES* p) {
    assert(p->NumPhyTypes==5);return step();
}
static WIFI_WIFIDIRECT_CAPABILITIES reportedWfd;
static NTSTATUS WifiDeviceSetWiFiDirectCapabilities(WDFDEVICE,const WIFI_WIFIDIRECT_CAPABILITIES* p) {reportedWfd=*p;return step();}
static UINT16 WifiRequestGetMessageId(WIFIREQUEST r) {return ((RequestData*)r)->Id;}
static PVOID WifiRequestGetInOutBuffer(WIFIREQUEST r,UINT* inSize,UINT* outSize) {
    auto p=(RequestData*)r;*inSize=p->Input;*outSize=p->Output;return p->Bytes;
}
static void WifiRequestComplete(WIFIREQUEST r,NTSTATUS status,ULONG bytes) {
    auto p=(RequestData*)r;assert(!p->Complete);++p->Complete;p->Status=status;p->Written=bytes;
}
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
typedef int KIRQL;
#undef InterlockedCompareExchange
#define InterlockedCompareExchange(p,a,b) ((void)(a),(void)(b),*(p))
#undef InterlockedExchange
#define InterlockedExchange(p,v) (*(p)=(v))
#undef InterlockedCompareExchangePointer
#define InterlockedCompareExchangePointer(p,v,e) ((*(p)==(e)) ? (*(p)=(v)) : *(p))
#define KeAcquireSpinLock(l,i) (assert(!*(l)),++*(l),*(i)=0)
#define KeReleaseSpinLock(l,i) (assert(*(l)==1),--*(l),(void)(i))
static ULONG kicks;
#define AP6256_CMDQ_KICK(w) ((void)(w),++kicks)
#define AP6256_CMDQ_OK(w) ((w)->CommandWorkItem!=0)
struct Memory {std::vector<UCHAR> Bytes;BOOLEAN Received=FALSE;};
typedef Memory* WDFMEMORY;
struct WDF_OBJECT_ATTRIBUTES {WDFDEVICE ParentObject;};
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset(a,0,sizeof(*(a)))
#define NonPagedPoolNx 0
static BOOLEAN failMemory;
static ULONG memories;
static UINT16 indicatedMessage;
static std::vector<UCHAR> indicatedBytes;
static NTSTATUS WdfMemoryCreate(WDF_OBJECT_ATTRIBUTES* a,int,ULONG,SIZE_T n,WDFMEMORY* m,PVOID* p) {
    assert(a->ParentObject);if(failMemory)return STATUS_INSUFFICIENT_RESOURCES;
    *m=new Memory;(*m)->Bytes.resize(n);*p=(*m)->Bytes.data();++memories;return STATUS_SUCCESS;
}
static void WifiDeviceReceiveIndication(WDFDEVICE,UINT16 id,WDFMEMORY m) {
    assert(!m->Received);m->Received=TRUE;indicatedMessage=id;indicatedBytes=m->Bytes;
}
static void WdfObjectDelete(WDFMEMORY m) {assert(m->Received && memories);--memories;delete m;}
static NDIS_STATUS Ap6256NtToNdisStatus(NTSTATUS status) {return (NDIS_STATUS)status;}
typedef Wifi* WDFTIMER;
typedef Wifi* WDFWORKITEM;
typedef Wifi* WDFOBJECT;
static Wifi* WdfTimerGetParentObject(WDFTIMER t) {return t;}
static Wifi* WdfWorkItemGetParentObject(WDFWORKITEM t) {return t;}
static Wifi* Ap6256GetWifiContext(Wifi* w) {return w;}
static void Ap6256LockAcquire(int* p) {assert(!*p);*p=1;}
static void Ap6256LockRelease(int* p) {assert(*p==1);*p=0;}
static void Ap6256ClearGoEvents(Wifi*) {}
static void Ap6256ForgetGoAutoAssoc(Wifi*,const UCHAR*) {}
static ULONG timerCallbacks,workCallbacks;
static void Ap6256StationSaeTimer(PVOID w) {assert(w);++timerCallbacks;}
static void Ap6256DrainCommandQueue(Wifi* w) {assert(w);++workCallbacks;}
'''
TEST = r'''
static void qualified(Device& d) {
    d.FirmwarePrivateSae=d.FirmwareMfpSupported=TRUE;
    d.FirmwareFtPatchVerified=d.FirmwareHostFt=TRUE;
    d.FirmwareOwePatchVerified=d.FirmwareHostOwe=TRUE;
}
int main() {
    initTables();

    for(unsigned mask=0;mask<512;++mask) {
        Device d;calls=failAt=0;
        d.FirmwareExternalAuth=(BOOLEAN)!!(mask&1);d.FirmwarePrivateSae=(BOOLEAN)!!(mask&2);
        d.FirmwareMfpSupported=(BOOLEAN)!!(mask&4);d.FirmwareFtPatchVerified=(BOOLEAN)!!(mask&8);
        d.FirmwareHostFt=(BOOLEAN)!!(mask&16);d.FirmwareOwePatchVerified=(BOOLEAN)!!(mask&32);
        d.FirmwareHostOwe=(BOOLEAN)!!(mask&64);
        d.HostFipsReady=(BOOLEAN)!!(mask&256);
        peerVersion=mask&128 ? WDI_VERSION_1_1_10 : WDI_VERSION_1_1_9;
        assert(Ap6256ModelHardwareReady(&d)==STATUS_SUCCESS && d.WifiCapabilitiesSet && calls==4 && !pools);
        bool sae=(mask&3)&&(mask&4)&&(mask&128);
        bool owe=(mask&32)&&(mask&64)&&(mask&4)&&(mask&128);
        bool ft=(mask&8)&&(mask&16);
        assert(!!reportedDevice.SAEAuthenticationSupported==sae && !!reportedDevice.FastTransitionSupported==ft);
        assert(reportedStation.MFPCapable==!!(mask&4));
        assert(reportedStation.HostFIPSModeImplemented==(d.HostFipsReady?DOT11_EXTSTA_ATTRIBUTES_SAFEMODE_OID_SUPPORTED:0));
        bool enterprise=(mask&4)!=0;
        assert(reportedStation.NumSupportedUnicastAlgorithms==3u+sae+owe+enterprise);
        assert(reportedStation.NumSupportedMulticastDataAlgorithms==3u+sae+owe+enterprise);
        assert(reportedStation.NumSupportedMulticastMgmtAlgorithms==2u+sae+owe+enterprise);
        ULONG data=3,mgmt=2;
        if(sae) {assert(d.WifiAuthCipher[data++].AuthAlgoId==DOT11_AUTH_ALGO_WPA3_SAE);assert(d.WifiMgmtCipher[mgmt++].AuthAlgoId==DOT11_AUTH_ALGO_WPA3_SAE);}
        if(owe) {assert(d.WifiAuthCipher[data++].AuthAlgoId==DOT11_AUTH_ALGO_OWE);assert(d.WifiMgmtCipher[mgmt++].AuthAlgoId==DOT11_AUTH_ALGO_OWE);}
        if(enterprise) {assert(d.WifiAuthCipher[data++].AuthAlgoId==DOT11_AUTH_ALGO_WPA3_ENT);assert(d.WifiMgmtCipher[mgmt++].AuthAlgoId==DOT11_AUTH_ALGO_WPA3_ENT);}
        for(ULONG i=1;i<data;++i)assert(d.WifiAuthCipher[i].CipherAlgoId==DOT11_CIPHER_ALGO_CCMP);
        for(ULONG i=0;i<mgmt;++i)assert(d.WifiMgmtCipher[i].CipherAlgoId==DOT11_CIPHER_ALGO_BIP);
        assert(Ap6256ModelHardwareReady(&d)==0 && calls==4);
    }
    for(failAt=1;failAt<=4;++failAt) {
        Device d;qualified(d);calls=0;
        assert(Ap6256ModelHardwareReady(&d)==STATUS_IO_TIMEOUT && !d.WifiCapabilitiesSet && calls==failAt && !pools);
    }
    Device d;qualified(d);calls=failAt=0;failAllocation=TRUE;
    assert(Ap6256ModelHardwareReady(&d)==STATUS_INSUFFICIENT_RESOURCES && !d.WifiCapabilitiesSet && !calls && !pools);
    failAllocation=FALSE;

    for(ULONG enabled=0;enabled<2;++enabled) for(ULONG p2p=0;p2p<2;++p2p) {
        Device sd;qualified(sd);calls=failAt=0;
        sd.FirmwareServiceOffload=(BOOLEAN)enabled;sd.FirmwareP2pSupported=(BOOLEAN)p2p;
        assert(Ap6256ModelHardwareReady(&sd)==0 && calls==4u+p2p);
        if(p2p) {
            assert(reportedWfd.ServiceDiscoverySupported==enabled && reportedWfd.ServiceNameDiscoverySupported==enabled && reportedWfd.ServiceInformationDiscoverySupported==enabled);
            assert(reportedWfd.ServiceNameAdvertisementsMaxBytesSupported==(enabled?800u:0u) && reportedWfd.ServiceInformationAdvertisementsMaxBytesSupported==(enabled?3072u:0u));
            assert(reportedWfd.WFDRoleCount==1 && reportedWfd.ConcurrentGOCount==1 && reportedWfd.ConcurrentClientCount==1 && !reportedWfd.BackgroundDiscoverySupported);
            assert(reportedWfd.GOClientTableSize==8 && reportedWfd.NumSupportedUnicastAlgorithms==2 && reportedWfd.UnicastAlgorithms==sd.WifiGroupCipher);
        }
    }

    Wifi w;CxRole sta;w.Model.Roles[0]=&sta;w.Ctx=&d;d.Adapter=&w;w.Auth.SaeGeneration=77;
    WDI_MESSAGE_HEADER header={};header.PortId=0;header.TransactionId=19;header.IhvSpecificId=23;
    RequestData r={WDI_SET_SAE_AUTH_PARAMS,(UCHAR*)&header,sizeof(header),sizeof(header)};
    WIFIREQUEST request=(WIFIREQUEST)&r;
    assert(Ap6256RequestGetMessageId(request)==WDI_SET_SAE_AUTH_PARAMS);
    PWDI_MESSAGE_HEADER view;const UCHAR* tlv;ULONG length;
    assert(Ap6256GetRequestView(request,&view,&tlv,&length)==0 && view==&header && !length);
    r.Input=sizeof(header)-1;assert(Ap6256GetRequestView(request,&view,&tlv,&length)==STATUS_INVALID_PARAMETER);r.Input=sizeof(header);
    Ap6256EvtWifiSendCommand(&d,request);
    assert(!r.Complete && w.CommandHead==1 && w.CommandPending[0]==request && w.CommandSaeGeneration[0]==77 && kicks==1);
    w.Auth.SaeGeneration=88;assert(w.CommandSaeGeneration[0]==77);w.CommandTail=w.CommandHead;
    Ap6256CompleteRequest(&w,request,0);assert(r.Complete==1 && r.Written==sizeof(header));
    RequestData noAdapter={WDI_SET_SAE_AUTH_PARAMS,nullptr,0,0};d.Adapter=nullptr;
    Ap6256EvtWifiSendCommand(&d,(WIFIREQUEST)&noAdapter);assert(noAdapter.Complete==1 && noAdapter.Status==STATUS_DEVICE_NOT_READY && !noAdapter.Written);
    d.Adapter=&w;w.Stopping=1;RequestData stopped={WDI_SET_SAE_AUTH_PARAMS,(UCHAR*)&header,sizeof(header),sizeof(header)};
    Ap6256EvtWifiSendCommand(&d,(WIFIREQUEST)&stopped);assert(stopped.Complete==1 && stopped.Status==STATUS_DEVICE_NOT_READY);w.Stopping=0;
    w.CommandHead=w.CommandTail+AP6256_CMDQ_DEPTH;RequestData full={WDI_SET_SAE_AUTH_PARAMS,(UCHAR*)&header,sizeof(header),sizeof(header)};
    Ap6256EvtWifiSendCommand(&d,(WIFIREQUEST)&full);assert(full.Complete==1 && full.Status==STATUS_INSUFFICIENT_RESOURCES && !w.CommandLock);


    w.CommandHead=w.CommandTail;sta.PortId=7;d.WifiStationPortId=7;d.WifiDirectPortId=19;d.WifiDirectDevice=&w;
    for(UINT16 port: {UINT16(7),UINT16(19)}) {
        WDI_MESSAGE_HEADER h={};h.PortId=port;h.TransactionId=31;
        RequestData q={WDI_TASK_P2P_DISCOVER,(UCHAR*)&h,sizeof(h),sizeof(h)};
        Ap6256EvtWifiSendCommand(&d,(WIFIREQUEST)&q);
        assert(!q.Complete && h.PortId==(port==7?0:1));w.CommandTail=w.CommandHead;
        assert(Ap6256SendIndicationRq(&w,WDI_INDICATION_P2P_DISCOVERY_COMPLETE,&h,31,nullptr,0,nullptr,0)==0);
        assert(((WDI_MESSAGE_HEADER*)indicatedBytes.data())->PortId==port);
        Ap6256CompleteRequest(&w,(WIFIREQUEST)&q,0);assert(q.Complete==1 && h.PortId==port);
    }
    WDI_MESSAGE_HEADER unknown={};unknown.PortId=99;
    RequestData badPort={WDI_TASK_P2P_DISCOVER,(UCHAR*)&unknown,sizeof(unknown),sizeof(unknown)};
    Ap6256EvtWifiSendCommand(&d,(WIFIREQUEST)&badPort);assert(badPort.Complete==1 && badPort.Status==STATUS_INVALID_DEVICE_STATE && unknown.PortId==99);
    sta.PortId=0;d.WifiStationPortId=0;d.WifiDirectPortId=1;d.WifiDirectDevice=nullptr;

    UCHAR payload[3]={1,2,3};
    assert(Ap6256SendIndicationRq(&w,WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED,&header,0,(PVOID)99,0,payload,3)==0 && !memories);
    auto received=(WDI_MESSAGE_HEADER*)indicatedBytes.data();
    assert(indicatedMessage==WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED && received->TransactionId==0 && received->PortId==0 && received->IhvSpecificId==23);
    assert(indicatedBytes.size()==sizeof(header)+3 && !memcmp(indicatedBytes.data()+sizeof(header),payload,3));
    assert(Ap6256SendIndicationRq(&w,WDI_INDICATION_FT_ASSOC_PARAMS_NEEDED,&header,header.TransactionId,nullptr,0,payload,3)==0);
    assert(((WDI_MESSAGE_HEADER*)indicatedBytes.data())->TransactionId==19);
    assert(Ap6256SendIndicationRq(&w,WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED,&header,0,nullptr,0,nullptr,1)==STATUS_INVALID_PARAMETER);
    failMemory=TRUE;assert(Ap6256SendIndicationRq(&w,WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED,&header,0,nullptr,0,payload,3)==STATUS_INSUFFICIENT_RESOURCES && !memories);
    Ap6256EvtSaeTimeout(&w);Ap6256EvtCommandWorkItem(&w);assert(timerCallbacks==1 && workCallbacks==1);


    for(ULONG wrap=0;wrap<2;++wrap)for(ULONG n=0;n<=AP6256_CMDQ_DEPTH;++n) {
        Wifi dead;dead.Ctx=&d;dead.CommandWorkItem=0;d.WifiEngine=&dead;
        dead.CommandTail=wrap ? MAXULONG-3u : 0;dead.CommandHead=dead.CommandTail+n;
        RequestData pending[AP6256_CMDQ_DEPTH]={};
        for(ULONG i=0;i<n;++i) {
            pending[i].Id=WDI_SET_SAE_AUTH_PARAMS;pending[i].Bytes=(UCHAR*)&header;
            pending[i].Input=pending[i].Output=sizeof(header);
            dead.CommandPending[(dead.CommandTail+i)&(AP6256_CMDQ_DEPTH-1)]=(WIFIREQUEST)&pending[i];
        }
        dead.Auth.SaeHead=3;dead.Auth.SaeTail=1;dead.Auth.SaeLostGeneration=6;
        dead.Auth.FtTail=MAXULONG;dead.Auth.FtHead=1;dead.Auth.FtEventsLost=TRUE;
        for(ULONG i=0;i<2;++i) {
            dead.Auth.FtEvents[i]=(AP6256_FT_EVENT*)malloc(sizeof(AP6256_FT_EVENT));
            dead.Auth.FtEvents[i]->Owned=99;
        }
        ULONG oldFreed=freedFt;
        Ap6256EvtEngineCleanup(&dead);
        assert(dead.Stopping && !dead.HardwareAvailable && !d.WifiEngine && !dead.CommandLock);
        assert(dead.CommandTail==dead.CommandHead && freedFt==oldFreed+2);
        assert(dead.Auth.FtTail==dead.Auth.FtHead && !dead.Auth.FtEventsLost);
        assert(dead.Auth.SaeTail==dead.Auth.SaeHead && !dead.Auth.SaeLostGeneration);
        assert(!dead.ScanTask.Active && !dead.ConnectTask.Active && !dead.DisconnectTask.Active);
        for(ULONG i=0;i<n;++i)assert(pending[i].Complete==1 && pending[i].Status==STATUS_CANCELLED);
        Ap6256EvtEngineCleanup(&dead);assert(freedFt==oldFreed+2);
    }
    printf("PASS: WiFiCx 256 firmware/version capability combinations, four registration failures, opaque request queue ownership/completion, stale generation retention, indication framing/allocation, WDF timer/worker bindings and cleanup with disposed children\n");
}
'''

def main():
    cap = load('wdi-capabilities')
    header = (INC / 'km/wificx/1.2/wificx.h').read_text(encoding='utf-8-sig')
    types = re.search('^#define MAX_FIRMWARE_VERSION_LENGTH [^\\n]+', header, re.M)[0] + '\n'
    types += 'typedef void WIFI_STA_BANDS_COMBINATION;\n'
    for name in ('WIFI_DEVICE_CAPABILITIES', 'WIFI_STATION_CAPABILITIES', 'WIFI_BAND_INFO', 'WIFI_BAND_CAPABILITIES', 'WIFI_PHY_INFO', 'WIFI_PHY_CAPABILITIES', 'WIFI_WIFIDIRECT_CAPABILITIES'):
        types += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\} ' + name + ';', header)[0] + '\n'
        if name.endswith('CAPABILITIES'):
            types += 'static void ' + name + '_INIT(' + name + '* p) {memset(p,0,sizeof(*p));p->Size=sizeof(*p);}\n'
    frontend = (AP / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig')
    frontend = frontend.replace('#include "role_adapter.inc"', (AP / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig'))
    common = (AP / 'src/common/netadapter.c').read_text(encoding='utf-8-sig')
    auth = (AP / 'src/common/station_auth.c').read_text(encoding='utf-8-sig')
    text = '#pragma warning(disable:4505)\n' + cap.PREAMBLE.split('struct Device {')[0]
    tables = (AP / 'src/common/capability_tables.h').read_text(encoding='utf-8-sig').replace('#pragma once', '')
    initializers = ''
    for name in ('Ap6256AlgoPairs', 'Ap6256MgmtAlgoPairs'):
        array = re.search('static const WDI_ALGO_PAIRS ' + name + '\\[\\] = \\{[\\s\\S]*?\\};', tables)[0]
        pairs = re.findall('\\{ (WDI_AUTH_ALGO_\\w+),\\s+(WDI_CIPHER_ALGO_\\w+) \\}', array)
        tables = tables.replace(array, 'static WDI_ALGO_PAIRS ' + name + '[' + str(len(pairs)) + '];')
        for (index, (algorithm, cipher)) in enumerate(pairs):
            initializers += f'{name}[{index}].AuthAlgorithm={algorithm};{name}[{index}].CipherAlgorithm={cipher};\n'
    tables += 'static void initTables() {\n' + initializers + '}\n'
    for name in ('Ap6256RatesB', 'Ap6256RatesOfdm'):
        tables += re.search('^const UINT16 ' + name + '\\[\\] = \\{[^;]+;', common, re.M)[0] + '\n'
    fields = '\n'.join((line for line in (AP / 'src/wificx/device_fields.h').read_text(encoding='utf-8-sig').splitlines() if re.match('DOT11_AUTH_CIPHER_PAIR Wifi(?:Auth|Mgmt)Cipher\\[', line)))
    assert len(fields.splitlines()) == 2
    text += types + MOCKS.replace('@STATION_CIPHER_FIELDS@', fields) + tables + '\n#define AP6256_STATION_PORT 0\n#define AP6256_DISCOVERY_PORT 1\n#define AP6256_P2P_VENDOR_IE_MAX 512\n'
    text += '\nstatic BOOLEAN Ap6256HostCipherAvailable(Wifi*) {return FALSE;}\n'
    for name in ('Ap6256HostFbtAvailable', 'Ap6256HostSaeAvailable', 'Ap6256HostOweAvailable'):
        text += function(auth, name)
    for name in ('Ap6256Wpa3EnterpriseAvailable', 'Ap6256CopyAlgoPairs', 'Ap6256QueueCommand'):
        text += function(common, name)
    text += function(auth, 'Ap6256StationAuthFreeEvents')
    for name in ('Ap6256CxInternalPort', 'Ap6256WifiCxExternalPort', 'Ap6256SetPhyInfo', 'Ap6256SetWifiCapabilities', 'Ap6256ModelHardwareReady', 'Ap6256RequestGetMessageId', 'Ap6256GetRequestView', 'Ap6256CompleteRequest', 'Ap6256EvtWifiSendCommand', 'Ap6256SendIndicationRq', 'Ap6256EvtSaeTimeout', 'Ap6256EvtCommandWorkItem', 'Ap6256EvtEngineCleanup'):
        text += function(frontend, name).replace('= {0};', '= {};')
    OUT.mkdir(parents=True, exist_ok=True)
    cpp = OUT / 'tests.cpp'
    write_text(cpp, text + TEST, encoding='utf-8')
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(OUT / 'tests.exe'), '/Fo:' + str(OUT / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    subprocess.run(command, check=True)
    subprocess.run([str(OUT / 'tests.exe')], check=True)
    subprocess.run([sys.executable, str(AP / 'tests/test-sae-station.py'), '--model', 'wificx', '--output', str(OUT / 'sae')], check=True)
if __name__ == '__main__':
    main()
