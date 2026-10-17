# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Run WiFiCx GO/client control engines with real role peers/data and Microsoft TLVs.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m
base = module('group_roles_base', ROOT / 'tests/test-wificx-roles.py')
OUT = output_dir('wificx-group-integration')
STATE = r'''
struct Device {
 Wifi* Engine=nullptr;KSPIN_LOCK TalStateLock;LONG TxFrames=0;
 KSPIN_LOCK HostFipsLock;AP6256_FIPS_SESSION HostFipsSessions[16]={};
 UINT32 HostFipsBlockedMask=0,HostFipsRetiredMask=0;BOOLEAN HostFipsReady=FALSE;
 BOOLEAN FirmwareLinkUp=TRUE,FirmwareMchanSupported=TRUE,FirmwareFtmPatchVerified=TRUE;struct {UINT32 ChipId=0x4345,ChipRev=9;} Chip;UINT32 StationChannel=36;UINT8 D11IoType=2;
 struct {BOOLEAN Created=TRUE,FirmwareReady=TRUE,Started=FALSE,Stopping=FALSE,WpsEnabled=FALSE,NativeStateUncertain=FALSE;
  UINT32 Mode=AP6256_WDI_OPMODE_P2P_CLIENT,IfIndex=7,BssIndex=2,Channel=0;
  UCHAR Address[6]={2,4,5,6,7,8},ClientBssid[6]={};BOOLEAN ClientConnected=FALSE,ClientSecure=FALSE,ClientMfp=FALSE;
  CHAR ClientRssiDbm=-100;AP6256_GO_PEER Peers[AP6256_GO_PEERS]={};struct {UCHAR OperatingChannel=0,OperatingClass=0;UINT32 AssocStatus=0;AP6256_P2P_IE_SLOT DriverIes[Ap6256P2pFrameMax]={},HostIes[Ap6256P2pFrameMax]={};} P2p;
 } Go;
 PVOID WifiDirectDevice=nullptr;UINT16 WifiDirectPortId=19;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi {
 Device* Ctx=nullptr;LONG HardwareAvailable=1,Stopping=0,DisallowedBandMask=0;
 BOOLEAN PowerStateDx=FALSE;AP6256_MODEL_STATE Model={};WDFWORKITEM CommandWorkItem=nullptr;KSPIN_LOCK CommandLock;TLV_CONTEXT TlvContext={};
 BOOLEAN ApStarted=TRUE;AP6256_SECURITY ApSecurity=Ap6256SecurityWpa2Host;AP6256_AP_PARAMS GoApParams={};
 AP6256_WDI_TASK ConnectTask={},ApAssocTask={};WDI_MESSAGE_HEADER IndicationHeader={};UCHAR ApPendingAssocMac[6]={};
};
'''
EXTRA = r'''
#include <type_traits>
#include <memory>
#include <set>
static std::set<PVOID> poolLive;static ULONG poolCount=0,poolFailAt=0;
#include <strsafe.h>
#define RtlStringCbPrintfA StringCbPrintfA
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define STATUS_DEVICE_PROTOCOL_ERROR ((LONG)0xc0000186)
#include <string>
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceInfo(...) ((void)0)
#define RtlCompareMemory(a,b,n) (memcmp(a,b,n)==0 ? (n) : 0u)
#define STATUS_UNSUCCESSFUL ((LONG)0xc0000001)
#undef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((LONG)0xc000000d)
#define STATUS_IO_DEVICE_ERROR ((LONG)0xc0000185)
#define STATUS_IO_TIMEOUT ((LONG)0xc00000b5)
#define STATUS_NETWORK_UNREACHABLE ((LONG)0xc000023c)
struct HostTimer {bool Armed=false;ULONG Delay=0;unsigned Starts=0,Stops=0;};
typedef HostTimer* AP6256_TIMER_OBJ;
typedef PVOID WDFOBJECT;
struct OpaqueRequest {ULONG Magic=0xcafed00d,Completions=0;NTSTATUS Status=STATUS_UNSUCCESSFUL;};
typedef OpaqueRequest* AP6256_REQUEST;
static LONGLONG nowMs=100;
static LONGLONG Ap6256InterruptTimeMs() {return nowMs;}
static VOID timerStart(HostTimer* t,ULONG delay) {assert(t && !spinDepth);t->Armed=true;t->Delay=delay;++t->Starts;}
static VOID timerStop(HostTimer* t,BOOLEAN) {assert(t && !spinDepth);t->Armed=false;++t->Stops;}
#define AP6256_TIMER_START timerStart
#define AP6256_TIMER_STOP timerStop
'''
NATIVE = r'''



static NTSTATUS Ap6256FipsStop(Device* d,UINT32 i) {assert(!d->HostFipsReady && !d->HostFipsBlockedMask && !d->HostFipsSessions[i].Generation);return 0;}
static NTSTATUS Ap6256FipsRetire(Device* d,UINT32 i) {return Ap6256FipsStop(d,i);}
static BOOLEAN Ap6256FipsRetired(Device* d,UINT32 i) {return (d->HostFipsRetiredMask & (1u<<i))!=0;}
static NTSTATUS Ap6256FipsCheckVendorIes(const UCHAR*,ULONG) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256FipsSetQos(Device*,UINT32,BOOLEAN) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256FipsVerifySecurity(Device*,UINT32,UINT32,UINT32) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256FipsBegin(Device*,UINT32,const UCHAR*,const UCHAR*) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256CopyFipsCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER*,AP6256_CONNECT_PARAMS* p) {assert(!p->HostFips);return 0;}
NTSTATUS Ap6256CancelClientLocked(PAP6256_WIFI,NTSTATUS,UINT32);
VOID Ap6256NetFirmwareHalted(Device*);
NTSTATUS Ap6256GoStop(Device*);
VOID Ap6256ModelApStopped(Wifi*,Device*);
static VOID Ap6256NetQueueLinkEvent(Device*,UCHAR) {assert(false);}
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
struct Io {UINT32 IfIndex,Command;std::string Name;std::vector<UCHAR> Bytes;};
static std::vector<Io> io;
static std::vector<UCHAR> hostIes;static std::vector<std::vector<UCHAR>> joinIes;
static ULONG ioStep=0,failStep=0;static bool failAllJoins=false,failAssocDelivery=false,failConnectDelivery=false,failApDelivery=false,failRequestDelivery=false,poisonAtM3=false;
static UCHAR* requestBytes=nullptr;static ULONG requestLength=0;static WDI_MESSAGE_HEADER* requestHeader=nullptr;
static unsigned metadataReads=0;static bool inRx=false;static ULONG commandKicks=0;
#define AP6256_CMDQ_OK(w) ((w)->CommandWorkItem!=nullptr)
#define AP6256_CMDQ_KICK(w) (++commandKicks)
static Device* apDevice=nullptr;static bool apBssUp=false,apFailUp=false,apFailDown=false,apCloseRole=false,failStartDelivery=false;
static UINT32 apAuth=0,apWsec=0,apWpaAuth=0,apRestrict=0;
static NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 cmd,VOID* out,ULONG n) {assert(cmd==BRCMF_C_GET_VALID_CHANNELS && n==65*4);auto p=(UINT32*)out;p[0]=4;p[1]=1;p[2]=36;p[3]=40;p[4]=149;return 0;}
static NTSTATUS Ap6256GoCreate(Device* d) {assert(d->Go.Created && d->Go.FirmwareReady);return d->Go.NativeStateUncertain?STATUS_DEVICE_HARDWARE_ERROR:STATUS_SUCCESS;}
static NTSTATUS Ap6256WifiGetChanspec(Device*,UINT32* ch) {*ch=0xd024;return 0;}
static VOID Ap6256WifiTraceApBss(Device*,UINT32 iface) {assert(iface==7);}
static NTSTATUS nativeIo(UINT32 iface,UINT32 cmd,const char* name,const VOID* data,ULONG len) {
 assert(!spinDepth && !inRx && iface==7);const UCHAR* p=(const UCHAR*)data;std::vector<UCHAR> b;if(len){assert(p);b.assign(p,p+len);}
 io.push_back({iface,cmd,name?name:"",b});++ioStep;if(cmd==BRCMF_C_SET_SSID)joinIes.push_back(hostIes);
 if(apDevice){
  UINT32 value=0;if(len>=4)memcpy(&value,b.data(),4);
  if(name && !strcmp(name,"bss")){assert(len==8 && value==2);memcpy(&value,b.data()+4,4);if(!value && apFailDown)return STATUS_IO_DEVICE_ERROR;apBssUp=value!=0;if(value && apCloseRole)apDevice->Engine->Model.Roles[1]->Closing=1;if(value && apFailUp)return STATUS_IO_DEVICE_ERROR;}
  if(name && len==8 && !strncmp(name,"bsscfg:",7)){assert(value==2);memcpy(&value,b.data()+4,4);if(!strcmp(name,"bsscfg:auth"))apAuth=value;if(!strcmp(name,"bsscfg:wsec"))apWsec=value;if(!strcmp(name,"bsscfg:wpa_auth"))apWpaAuth=value;}
  if(cmd==BRCMF_C_SET_WEP_RESTRICT)apRestrict=value;
 }

 if(ioStep==failStep || (failAllJoins && cmd==BRCMF_C_SET_SSID))return STATUS_IO_DEVICE_ERROR;
 return 0;
}
static NTSTATUS Ap6256BcdcSetDcmdIf(Device*,UINT32 iface,UINT32 cmd,const VOID* p,ULONG n) {return nativeIo(iface,cmd,nullptr,p,n);}
static NTSTATUS Ap6256BcdcSetIovarIf(Device*,UINT32 iface,PCSTR name,const VOID* p,ULONG n) {return nativeIo(iface,0,name,p,n);}
static NTSTATUS Ap6256BcdcQueryDcmdIf(Device* d,UINT32 iface,UINT32 cmd,VOID* p,ULONG n) {
 assert(!spinDepth && !inRx && iface==7);if(cmd==BRCMF_C_GET_RATE){assert(n==4);*(UINT32*)p=108;return 0;}
 if(cmd==BRCMF_C_GET_RSSI){assert(n==4);*(INT32*)p=-55;return 0;}
 ++metadataReads;if(cmd==failMetadataCommand)return STATUS_IO_TIMEOUT;
 if(cmd==BRCMF_C_GET_BSS_INFO){assert(n==AP6256_BSS_INFO_MAX);memcpy((UCHAR*)p+4,&firmwareBss,sizeof(firmwareBss));return 0;}
 assert(n==4);UINT32 value=0;switch(cmd){case BRCMF_C_GET_AUTH:break;case BRCMF_C_GET_WSEC:value=d->Go.WpsEnabled?0x40u:0u;if(d->Engine->ApSecurity==Ap6256SecurityWpa2Host)value|=4;break;case BRCMF_C_GET_WPA_AUTH:value=d->Engine->ApSecurity==Ap6256SecurityWpa2Host?0x80u:0u;break;case BRCMF_C_GET_WEP_RESTRICT:value=d->Engine->ApSecurity==Ap6256SecurityWpa2Host?1u:0u;break;default:assert(false);}
 if(apDevice){switch(cmd){case BRCMF_C_GET_AUTH:value=apAuth;break;case BRCMF_C_GET_WSEC:value=apWsec;break;case BRCMF_C_GET_WPA_AUTH:value=apWpaAuth;break;case BRCMF_C_GET_WEP_RESTRICT:value=apRestrict;break;}}memcpy(p,&value,4);return 0;
}
static NTSTATUS Ap6256BcdcGetIovarIf(Device* d,UINT32 iface,PCSTR name,PVOID out,ULONG n) {
 assert(!spinDepth && !inRx && iface==7);++metadataReads;
 if(!strcmp(name,"wme_bss_disable")){assert(n==4);*(UINT32*)out=0;return 0;}
 assert(!strcmp(name,"sta_info") && n==sizeof(firmwareStation) && !memcmp(out,metadataPeer,6));
 memcpy(out,firmwareStation,n);if(metadataTransition==1)d->Engine->Stopping=1;if(metadataTransition==2)d->Engine->HardwareAvailable=0;return 0;
}
static NTSTATUS Ap6256BcdcGetIovar(Device*,PCSTR name,PVOID out,ULONG n) {
 assert(!spinDepth && !inRx && !strcmp(name,"wme") && n==4);++metadataReads;if(failWme)return STATUS_IO_TIMEOUT;*(UINT32*)out=1;return 0;
}
static NTSTATUS Ap6256WifiGetChannel(Device* d,UINT32* c) {*c=d->StationChannel;return 0;}
static NTSTATUS Ap6256WifiGetBssidIf(Device* d,UINT32 iface,UCHAR* mac) {assert(iface==7);++metadataReads;memcpy(mac,d->Go.ClientBssid,6);return 0;}
static NTSTATUS Ap6256WifiGetChannelIf(Device* d,UINT32 iface,UINT32* c) {assert(iface==7);++metadataReads;*c=d->Go.Channel;return 0;}
static VOID Ap6256WifiGetAssocFramesIf(Device*,UINT32 iface,AP6256_ASSOC_FRAMES* f) {
 assert(iface==7);++metadataReads;const UCHAR request[]={1,0,1,0,221,4,0,0x50,0xf2,4};const UCHAR response[]={1,0,0,0,1,0,221,4,0,0x50,0xf2,4};
 f->AssocRequest=(PUCHAR)malloc(sizeof(request));f->AssocRequestLength=sizeof(request);memcpy(f->AssocRequest,request,sizeof(request));
 f->AssocResponse=(PUCHAR)malloc(sizeof(response));f->AssocResponseLength=sizeof(response);memcpy(f->AssocResponse,response,sizeof(response));
 f->PeerStatusCode=0;f->PeerStatusValid=TRUE;f->WmmNegotiated=TRUE;
}
static VOID Ap6256WifiFreeAssocFrames(AP6256_ASSOC_FRAMES* f) {free(f->AssocRequest);free(f->AssocResponse);free(f->Beacon);memset(f,0,sizeof(*f));}
static NTSTATUS Ap6256P2pSetHostIesFor(Device*,PVOID,UINT32 iface,UINT32 kind,const UCHAR* p,ULONG n) {
 assert(iface==7 && (kind==Ap6256P2pFrameAssocRequest || kind==Ap6256P2pFrameAssocResponse));hostIes.clear();if(n){assert(p);hostIes.assign(p,p+n);}return 0;
}
static NTSTATUS Ap6256P2pBuildIesFor(Device*,PVOID,UINT32 iface) {assert(iface==7);return 0;}
static NTSTATUS Ap6256QuiesceP2pListen(Wifi*) {return 0;}
static PVOID Ap6256RequestGetId(AP6256_REQUEST r) {assert(r && r->Magic==0xcafed00d);return r;}
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST r,NTSTATUS status) {assert(r && !r->Completions && r->Magic==0xcafed00d);++r->Completions;r->Status=status;if(poisonAtM3){poisonAtM3=false;memset(requestBytes,0xef,requestLength);memset(requestHeader,0xef,sizeof(*requestHeader));}}
struct Indication {UINT16 Id;WDI_MESSAGE_HEADER Header;UINT32 Transaction;PVOID Request;NTSTATUS Status;std::vector<UCHAR> Bytes;};
static std::vector<Indication> indications;
static NTSTATUS Ap6256SendIndicationRq(Wifi*,UINT16 id,const WDI_MESSAGE_HEADER* h,UINT32 tx,PVOID request,NTSTATUS status,const UCHAR* bytes,ULONG length) {
 assert(!spinDepth && h->PortId==(id==WDI_INDICATION_FIRMWARE_STALLED?0xffff:2));std::vector<UCHAR> b;if(length){assert(bytes);b.assign(bytes,bytes+length);}
 indications.push_back({id,*h,tx,request,status,b});
 if((id==WDI_INDICATION_ASSOCIATION_RESULT && failAssocDelivery) || (id==WDI_INDICATION_CONNECT_COMPLETE && failConnectDelivery) || (id==WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE && failApDelivery) || (id==WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED && failRequestDelivery) || (id==WDI_INDICATION_START_AP_COMPLETE && failStartDelivery))return STATUS_INSUFFICIENT_RESOURCES;
 return 0;
}
static VOID Ap6256IndicateP2pGroupChannel(Wifi*,const WDI_MESSAGE_HEADER* h,PVOID,UINT32 channel) {assert(h->PortId==2 && channel>0);}
VOID Ap6256ForgetGoAutoAssoc(Wifi*,const UCHAR*);



static VOID Ap6256NetApAssociationRequest(Device*,const UCHAR*,BOOLEAN,const UCHAR*,ULONG) {assert(false);}


static NTSTATUS Ap6256WifiSendAssocDecisionIf(Device*,UINT32 iface,const UCHAR* mac,BOOLEAN accept,UINT16 reason) {
 assert(accept && reason==0);return nativeIo(iface,0,"assoc_decision",mac,6);
}
'''
AUTO_METADATA = r'''
static UCHAR firmwareStation[512]={};static BRCMF_BSS_INFO firmwareBss={};
static UCHAR metadataPeer[6]={};static UINT32 failMetadataCommand=0;static ULONG metadataTransition=0;static bool failWme=false;
'''
TEST = r'''
static unsigned count(UINT16 id) {unsigned n=0;for(auto& i:indications)if(i.Id==id)++n;return n;}
static Indication& lastIndication(UINT16 id) {
 auto it=std::find_if(indications.rbegin(),indications.rend(),[id](const Indication& i){return i.Id==id;});assert(it!=indications.rend());return *it;
}
static void roleInit(PAP6256_CX_ADAPTER r,Wifi* w,UINT16 port,UINT16 external) {
 r->Wifi=w;r->Adapter=r;r->LogicalPort=port;r->PortId=external;r->Ready=1;r->Registered=TRUE;r->Generation=1;
 ExInitializeRundownProtection(&r->Rundown);w->Model.Roles[port==0?0:1]=r;
}
static ULONG peerIndex(Device& d,const UCHAR* mac) {for(ULONG n=1;n<AP6256_GO_PEERS;++n)if(d.Go.Peers[n].Active && !memcmp(d.Go.Peers[n].Address,mac,6))return n;return AP6256_GO_PEERS;}
struct Fixture {
 Device d={};Wifi w={};AP6256_CX_ADAPTER station={},group={};AP6256_QUEUE_CONTEXT tx={},gtx={},rx={};HostTimer timer={},apTimer={};
 Fixture() {
  io.clear();indications.clear();peerCalls.clear();cancels.clear();transmits.clear();hostIes.clear();joinIes.clear();failStep=ioStep=0;failAllJoins=failAssocDelivery=failConnectDelivery=failApDelivery=failRequestDelivery=poisonAtM3=false;metadataReads=0;commandKicks=0;inRx=false;nowMs=100;assert(poolLive.empty());poolCount=poolFailAt=0;failMetadataCommand=metadataTransition=0;failWme=false;
  apDevice=nullptr;apBssUp=apFailUp=apFailDown=apCloseRole=failStartDelivery=false;apAuth=apWsec=apWpaAuth=apRestrict=0;
  w.Ctx=&d;d.Engine=&w;w.CommandWorkItem=&gtx;w.TlvContext.PeerVersion=WDI_VERSION_1_1_10;w.Model.ClientConnectTimer=&timer;w.Model.ApAssocTimer=&apTimer;
  roleInit(&station,&w,0,37);roleInit(&group,&w,2,73);station.DataEnabled=1;group.DataEnabled=0;
  w.Model.StationPeerCreated=TRUE;w.Model.StationPeerGeneration=13;const UCHAR staPeer[6]={2,1,1,1,1,1};memcpy(w.Model.StationPeerAddress,staPeer,6);
  tx.Role=&station;tx.Wifi=&w;tx.Queue=&tx;tx.TxWorkItem=&tx;tx.IsTx=TRUE;tx.Started=tx.TxEnabled=1;memcpy(tx.PeerAddress,staPeer,6);station.TxQueues[0]=&tx;
  gtx.Role=&group;gtx.Wifi=&w;gtx.Queue=&gtx;gtx.TxWorkItem=&gtx;gtx.IsTx=TRUE;gtx.Started=gtx.TxEnabled=1;group.TxQueues[0]=&gtx;
  rx.Role=&group;rx.Wifi=&w;rx.Queue=&rx;rx.Started=1;group.RxQueue=&rx;
 }
 ~Fixture(){Ap6256ForgetGoAutoAssoc(&w,nullptr);assert(poolLive.empty());}
 void stationTraffic() {
  AP6256_FRAME f={};f.Length=64;memcpy(f.Data,w.Model.StationPeerAddress,6);f.Data[6]=2;f.Data[12]=8;
  NET_PACKET_WIFI_EXEMPTION_ACTION exemption={};
  assert(Ap6256CxPrepareTx(&tx,&exemption,&f)==0 && Ap6256CxTransmit(&tx,&f)==0);
  assert(transmits.back().IfIndex==0 && transmits.back().Port==0 && w.Model.StationPeerGeneration==13 && station.Ready && station.DataEnabled);
 }
 void connect(OpaqueRequest& request,BOOLEAN secure,ULONG candidates=2,BOOLEAN fips=FALSE,ULONG ieMode=0) {
  WDI_TASK_CONNECT_PARAMETERS p={};std::remove_pointer_t<decltype(p.ConnectParameters.SSIDList.pElements)> ssid={};
  UCHAR name[]={'T','E','S','T'};ssid.pElements=name;ssid.ElementCount=sizeof(name);p.ConnectParameters.SSIDList.pElements=&ssid;p.ConnectParameters.SSIDList.ElementCount=1;
  auto auth=secure?WDI_AUTH_ALGO_RSNA_PSK:WDI_AUTH_ALGO_80211_OPEN;auto cipher=secure?WDI_CIPHER_ALGO_CCMP:WDI_CIPHER_ALGO_NONE;
  p.ConnectParameters.AuthenticationAlgorithms.pElements=&auth;p.ConnectParameters.AuthenticationAlgorithms.ElementCount=1;
  p.ConnectParameters.UnicastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.UnicastCipherAlgorithms.ElementCount=1;
  p.ConnectParameters.MulticastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.MulticastCipherAlgorithms.ElementCount=1;
  p.ConnectParameters.ConnectionSettings.MFPEnabled=secure;p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled=fips;
  WDI_CONNECT_BSS_ENTRY_CONTAINER entries[2]={};for(ULONG n=0;n<2;++n){entries[n].BSSID.Address[0]=2;entries[n].BSSID.Address[5]=(UCHAR)(10+n);entries[n].ChannelInfo.ChannelNumber=36+n*4;entries[n].ChannelInfo.BandId=WDI_BAND_ID_5000;}
  p.PreferredBSSEntryList.pElements=entries;p.PreferredBSSEntryList.ElementCount=candidates;
  UCHAR ies[]={221,4,0,0x50,0xf2,4};p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent=TRUE;p.ConnectParameters.AssociationRequestVendorIE.pElements=ies;p.ConnectParameters.AssociationRequestVendorIE.ElementCount=sizeof(ies);
  std::vector<UCHAR> per[2];if(ieMode){
   for(ULONG n=0;n<2;++n){per[n]={221,4,0x11,0x22,0x33,(UCHAR)n};entries[n].Optional.AssociationRequestVendorIE_IsPresent=TRUE;}
   if(ieMode==2)per[1][1]=7;
   if(ieMode==3 || ieMode==4){ULONG length=ieMode==3?512:506;for(auto& data:per){data.assign(length,0x42);ULONG offset=0;while(offset<length){ULONG bytes=min((ULONG)257,length-offset);data[offset]=221;data[offset+1]=(UCHAR)(bytes-2);offset+=bytes;}}}
   if(ieMode==5){p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent=FALSE;for(ULONG n=0;n<2;++n){per[n].clear();entries[n].Optional.AssociationRequestVendorIE_IsPresent=FALSE;}}
   if(ieMode==6)p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent=FALSE;
   if(ieMode==7)ies[1]=7;
   if(ieMode==8){per[1].clear();entries[1].Optional.AssociationRequestVendorIE_IsPresent=FALSE;}
   for(ULONG n=0;n<2;++n){entries[n].AssociationRequestVendorIE.pElements=per[n].empty()?nullptr:per[n].data();entries[n].AssociationRequestVendorIE.ElementCount=(ULONG)per[n].size();}
  }
  PUCHAR bytes=nullptr;ULONG length=0;NDIS_STATUS generated=GenerateWdiTaskConnectToIhv(&p,0,&w.TlvContext,&length,&bytes);if(generated)fprintf(stderr,"CONNECT generator IE mode %lu status %08lx\n",ieMode,generated);assert(generated==0 && bytes);
  WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=777;
  Ap6256HandleClientConnect(&w,&request,&h,bytes,length);memset(bytes,0xee,length);FreeGenerated(bytes);memset(ies,0,sizeof(ies));for(auto& data:per)std::fill(data.begin(),data.end(),(UCHAR)0xee);
 }
};
static void checkAssociation(Fixture& f,BOOLEAN secure) {
 auto it=std::find_if(indications.rbegin(),indications.rend(),[](const Indication& i){return i.Id==WDI_INDICATION_ASSOCIATION_RESULT;});assert(it!=indications.rend());
 WDI_INDICATION_ASSOCIATION_RESULT_LIST p={};assert(ParseWdiIndicationAssociationResultFromIhv((ULONG)it->Bytes.size(),it->Bytes.data(),&f.w.TlvContext,&p)==0);
 assert(p.AssociationResults.ElementCount==1);auto& a=p.AssociationResults.pElements[0];assert(a.AssociationResultParameters.AssociationStatus==WDI_ASSOC_STATUS_SUCCESS && !memcmp(a.BSSID.Address,f.d.Go.ClientBssid,6));
 assert(a.AssociationResultParameters.AuthAlgorithm==(secure?WDI_AUTH_ALGO_RSNA_PSK:WDI_AUTH_ALGO_80211_OPEN));
 assert(a.AssociationResultParameters.PortAuthorized==!secure && a.Optional.AssociationRequestFrame_IsPresent && a.Optional.AssociationResponseFrame_IsPresent);
 CleanupParsedWdiIndicationAssociationResultFromIhv(&p);
}

static void nativeGoCase(bool deliveryFailure,bool cleanupFailure=false,bool timeout=false) {
 auto owned=std::make_unique<Fixture>();auto& f=*owned;f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.d.Go.Started=TRUE;f.d.Go.Channel=36;
 assert(Ap6256ModelStartApPeer(&f.w,0)==0);Ap6256ModelApStarted(&f.w,0);
 const UCHAR other[6]={2,2,2,2,2,21},target[6]={2,2,2,2,2,20};
 assert(Ap6256CxGroupPeerCreate(&f.d,other,AP6256_PHY_ID_HT));Ap6256CxGroupRxOpen(&f.d,other);const ULONG otherSlot=peerIndex(f.d,other);
 OpaqueRequest request;WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=888;
 WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE_PARAMETERS p={};memcpy(p.IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address,target,6);
 UCHAR req[]={1,0,1,0};p.IncomingRequestInfo.AssocRequestFrame.pElements=req;p.IncomingRequestInfo.AssocRequestFrame.ElementCount=sizeof(req);p.AssocResponseParameters.AcceptRequest=TRUE;
 PUCHAR bytes=nullptr;ULONG length=0;assert(GenerateWdiTaskSendApAssociationResponseToIhv(&p,0,&f.w.TlvContext,&length,&bytes)==0);
 Ap6256HandleSendApAssociationResponse(&f.w,&request,&h,bytes,length);FreeGenerated(bytes);
 assert(request.Completions==1 && request.Status==0 && f.w.ApAssocTask.Active && f.apTimer.Armed);
 if(timeout){
  nowMs=f.w.ApAssocTask.DeadlineMs-1;Ap6256OnApAssocTimeout(&f.w);assert(f.w.ApAssocTask.Active);++nowMs;if(cleanupFailure)failStep=ioStep+1;Ap6256OnApAssocTimeout(&f.w);
  assert(!f.w.ApAssocTask.Active && peerIndex(f.d,target)==AP6256_GO_PEERS && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1 && lastIndication(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE).Status==STATUS_IO_TIMEOUT && lastIndication(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE).Bytes.empty());
  assert(f.d.Go.Peers[otherSlot].Active && f.d.Go.Peers[otherSlot].RxOpen);
  Ap6256OnApAssocTimeout(&f.w);assert(count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1);
  if(cleanupFailure)assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);else f.stationTraffic();return;
 }
 const ULONG eventLength=34+6+12;auto event=(AP6256_GO_EVENT*)calloc(1,offsetof(AP6256_GO_EVENT,Data)+eventLength);
 event->Type=BRCMF_E_ASSOC_IND_NDIS;event->Generation=f.w.Model.GoEventGeneration;event->Length=eventLength;memcpy(event->Address,target,6);
 UINT32 fields[8]={0,0,34,6,40,12,0,0};memcpy(event->Data,fields,sizeof(fields));event->Data[34]=1;event->Data[38]=1;event->Data[48]=100;
 failApDelivery=deliveryFailure;if(cleanupFailure)failStep=ioStep+1;Ap6256ProcessGoEvent(&f.w,event);free(event);
 assert(!f.w.ApAssocTask.Active && !f.apTimer.Armed && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1);
 assert(f.d.Go.Peers[otherSlot].Active && f.d.Go.Peers[otherSlot].RxOpen && f.group.DataEnabled && f.d.Go.Started);
 if(cleanupFailure){assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);AP6256_FRAME blocked={};blocked.Length=64;NET_PACKET_WIFI_EXEMPTION_ACTION ex={};assert(!NT_SUCCESS(Ap6256CxPrepareTx(&f.tx,&ex,&blocked)));}else f.stationTraffic();
 ULONG slot=peerIndex(f.d,target);
 if(deliveryFailure) {
  assert(slot==AP6256_GO_PEERS);
  memcpy(f.gtx.PeerAddress,target,6);AP6256_FRAME packet={};packet.Length=64;NET_PACKET_WIFI_EXEMPTION_ACTION exemption={};assert(!NT_SUCCESS(Ap6256CxPrepareTx(&f.gtx,&exemption,&packet)));
 } else {
  assert(slot<AP6256_GO_PEERS && f.d.Go.Peers[slot].RxOpen);
  auto& completion=indications.back();assert(completion.Transaction==888 && completion.Request==&request && completion.Status==0);
  WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE_PARAMETERS parsed={};assert(ParseWdiIndicationSendApAssociationResponseCompleteFromIhv((ULONG)completion.Bytes.size(),completion.Bytes.data(),&f.w.TlvContext,&parsed)==0);
  assert(!memcmp(parsed.AssocResponseResult.PeerMACAddress.Address,target,6) && parsed.AssocResponseResult.UnicastCipherAlgorithm==WDI_CIPHER_ALGO_CCMP);
  CleanupParsedWdiIndicationSendApAssociationResponseCompleteFromIhv(&parsed);
 }
}

static const UCHAR autoPeer[6]={2,2,3,4,5,26},otherPeer[6]={2,2,3,4,5,27};
static const UCHAR autoIes[]={0,4,'t','e','s','t',1,2,0x82,0x84,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
static void seedAutonomous(Fixture& f,bool secure=true){
 f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.d.Go.Started=TRUE;f.d.Go.Channel=36;f.w.ApSecurity=secure?Ap6256SecurityWpa2Host:Ap6256SecurityOpen;
 f.w.GoApParams.Security=f.w.ApSecurity;f.w.GoApParams.Channel=36;f.w.GoApParams.SsidLength=4;memcpy(f.w.GoApParams.Ssid,"test",4);
 memset(firmwareStation,0,sizeof(firmwareStation));UINT16 word=4;memcpy(firmwareStation,&word,2);word=200;memcpy(firmwareStation+2,&word,2);word=0x431;memcpy(firmwareStation+4,&word,2);
 UINT32 flags=0xe01a;memcpy(firmwareStation+8,&flags,4);memcpy(firmwareStation+16,autoPeer,6);memcpy(metadataPeer,autoPeer,6);flags=1000;memcpy(firmwareStation+48,&flags,4);word=7;memcpy(firmwareStation+152,&word,2);
 firmwareBss={};firmwareBss.Version=109;firmwareBss.Length=128;memcpy(firmwareBss.Bssid,f.d.Go.Address,6);firmwareBss.BeaconPeriod=100;firmwareBss.Capability=0x421;firmwareBss.SsidLen=4;memcpy(firmwareBss.Ssid,"test",4);firmwareBss.Rateset.Count=12;
 for(ULONG n=0;n<12;++n)firmwareBss.Rateset.Rates[n]=(UCHAR)(n+1);
 assert(sizeof(firmwareBss)==128 && offsetof(BRCMF_BSS_INFO,IeOffset)==116);
 assert(Ap6256ModelStartApPeer(&f.w,0)==0);Ap6256ModelApStarted(&f.w,0);assert(Ap6256CxGroupPeerCreate(&f.d,otherPeer,AP6256_PHY_ID_HT));Ap6256CxGroupRxOpen(&f.d,otherPeer);
}
static void drainGo(Fixture& f){
 for(;;){PVOID event=nullptr;BOOLEAN lost=FALSE;KIRQL irql;KeAcquireSpinLock(&f.w.CommandLock,&irql);BOOLEAN ready=Ap6256ModelTakeCommandEvent(&f.w,&event,&lost);KeReleaseSpinLock(&f.w.CommandLock,irql);if(!ready)break;Ap6256ModelProcessCommandEvent(&f.w,event,lost);}
}
static void autoEvent(Fixture& f,bool malformed=false){
 std::vector<UCHAR> input(autoIes,autoIes+sizeof(autoIes));if(malformed)input[1]=255;ULONG reads=metadataReads,requests=count(WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED),kicks=commandKicks;
 inRx=true;Ap6256NetGoEvent(&f.d,BRCMF_E_ASSOC_IND,0,0,0,autoPeer,input.data(),(ULONG)input.size());inRx=false;
 assert(metadataReads==reads && count(WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED)==requests && commandKicks==kicks+1);
 std::fill(input.begin(),input.end(),(UCHAR)0xeb);drainGo(f);
}
static void autoResponse(Fixture& f,OpaqueRequest& r,bool accept=true,ULONG indicationIndex=0){
 std::vector<UCHAR> incoming;ULONG index=0;for(auto& i:indications)if(i.Id==WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED){if(index++==indicationIndex)incoming=i.Bytes;}
 assert(!incoming.empty());WDI_INDICATION_AP_ASSOCIATION_REQUEST_PARAMETERS ip={};assert(ParseWdiIndicationApAssociationRequestReceivedFromIhv((ULONG)incoming.size(),incoming.data(),&f.w.TlvContext,&ip)==0);
 assert(ip.IncomingRequestInfo.Optional.AssocRequestDeviceContext_IsPresent && ip.IncomingRequestInfo.AssocRequestDeviceContext.ElementCount==8 && ip.IncomingRequestInfo.AssocRequestFrame.ElementCount==4+sizeof(autoIes));
 assert(!memcmp(ip.IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address,autoPeer,6) && !memcmp(ip.IncomingRequestInfo.AssocRequestFrame.pElements+4,autoIes,sizeof(autoIes)));
 UINT16 listen=0;memcpy(&listen,ip.IncomingRequestInfo.AssocRequestFrame.pElements+2,2);assert(listen==10);
 WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE_PARAMETERS p={};p.IncomingRequestInfo.Optional=ip.IncomingRequestInfo.Optional;p.IncomingRequestInfo.AssocRequestParams=ip.IncomingRequestInfo.AssocRequestParams;
 p.IncomingRequestInfo.AssocRequestFrame.pElements=ip.IncomingRequestInfo.AssocRequestFrame.pElements;p.IncomingRequestInfo.AssocRequestFrame.ElementCount=ip.IncomingRequestInfo.AssocRequestFrame.ElementCount;
 p.IncomingRequestInfo.AssocRequestDeviceContext.pElements=ip.IncomingRequestInfo.AssocRequestDeviceContext.pElements;p.IncomingRequestInfo.AssocRequestDeviceContext.ElementCount=ip.IncomingRequestInfo.AssocRequestDeviceContext.ElementCount;
 p.AssocResponseParameters.AcceptRequest=accept;p.AssocResponseParameters.ReasonCode=accept?0:17;
 UCHAR* bytes=nullptr;ULONG length=0;assert(GenerateWdiTaskSendApAssociationResponseToIhv(&p,0,&f.w.TlvContext,&length,&bytes)==0);CleanupParsedWdiIndicationApAssociationRequestReceivedFromIhv(&ip);
 WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=888;requestBytes=bytes;requestLength=length;requestHeader=&h;poisonAtM3=true;
 Ap6256HandleSendApAssociationResponse(&f.w,&r,&h,bytes,length);assert(!poisonAtM3);FreeGenerated(bytes);assert(r.Completions==1);
}
static void autonomousCase(ULONG mode){
 auto owned=std::make_unique<Fixture>();auto& f=*owned;seedAutonomous(f,mode!=1);const ULONG other=peerIndex(f.d,otherPeer);const bool cleanFailure=mode>=5;
 if(mode==5 || mode==9)failRequestDelivery=true;if(mode==5 || mode==6 || mode==7)failStep=ioStep+1;
 if(mode==7 || mode==8)firmwareStation[16]^=1;
 if(mode==10)f.w.GoApParams.RejectNonP2pClients=TRUE;
 if(mode>=11 && mode<=13)poolFailAt=mode-9;
 if(mode==14)failWme=true;if(mode>=15)metadataTransition=mode-14;
 autoEvent(f,mode==6);
 if(!cleanFailure){
  assert(count(WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED)==1 && peerIndex(f.d,autoPeer)==AP6256_GO_PEERS && f.w.Model.GoAutoAssoc[0]);
  failApDelivery=mode==2 || mode==4;if(mode==4)failStep=ioStep+1;OpaqueRequest r;autoResponse(f,r,mode!=3);assert(r.Status==0 && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1 && !f.w.Model.GoAutoAssoc[0]);
  auto& last=lastIndication(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE);assert(last.Transaction==888 && last.Request==&r && last.Header.TransactionId==888);
  if(mode<=1){
   ULONG slot=peerIndex(f.d,autoPeer);assert(slot<AP6256_GO_PEERS && f.d.Go.Peers[slot].RxOpen && last.Status==0);
   WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE_PARAMETERS p={};assert(ParseWdiIndicationSendApAssociationResponseCompleteFromIhv((ULONG)last.Bytes.size(),last.Bytes.data(),&f.w.TlvContext,&p)==0);
   assert(!memcmp(p.AssocResponseResult.PeerMACAddress.Address,autoPeer,6) && p.AssocResponseResult.AuthAlgorithm==(mode==1?WDI_AUTH_ALGO_80211_OPEN:WDI_AUTH_ALGO_RSNA_PSK));
   assert(p.AssocResponseFrame.ElementCount>=6 && p.AssocResponseFrame.pElements[4]==7 && p.AssocResponseFrame.pElements[5]==0xc0 && p.ActivePhyList.ElementCount==1);
   assert(p.BeaconIEs.ElementCount>=12 && p.BeaconIEs.pElements[8]==100 && p.BeaconIEs.pElements[9]==0 && p.BeaconIEs.pElements[10]==(mode==1?0x21:0x31));
   ULONG ssids=0,rsns=0;for(ULONG off=12;off<p.BeaconIEs.ElementCount;){assert(off+2<=p.BeaconIEs.ElementCount);ULONG size=p.BeaconIEs.pElements[off+1]+2u;assert(size<=p.BeaconIEs.ElementCount-off);if(p.BeaconIEs.pElements[off]==0){++ssids;assert(size==6 && !memcmp(p.BeaconIEs.pElements+off+2,"test",4));}if(p.BeaconIEs.pElements[off]==48){++rsns;assert(size==22 && p.BeaconIEs.pElements[off+20]==0x0c);}off+=size;}assert(ssids==1 && rsns==(mode==1?0u:1u));CleanupParsedWdiIndicationSendApAssociationResponseCompleteFromIhv(&p);
   memcpy(f.gtx.PeerAddress,autoPeer,6);AP6256_FRAME tx={};tx.Length=64;memcpy(tx.Data,autoPeer,6);NET_PACKET_WIFI_EXEMPTION_ACTION ex={};assert(Ap6256CxPrepareTx(&f.gtx,&ex,&tx)==0 && Ap6256CxTransmit(&f.gtx,&tx)==0 && transmits.back().IfIndex==7);
   UCHAR eth[64]={};memcpy(eth,f.d.Go.Address,6);memcpy(eth+6,autoPeer,6);eth[12]=8;Ap6256NetRxIndicate(&f.d,eth,sizeof(eth),0,7);assert(f.group.RxHead==1 && f.station.RxHead==0);
  }else{assert(peerIndex(f.d,autoPeer)==AP6256_GO_PEERS);if(mode==3){assert(last.Status==STATUS_CONNECTION_REFUSED && last.Bytes.empty() && !io.empty());UINT32 reason=0;memcpy(&reason,io.back().Bytes.data(),4);assert(reason==17);}}
 }else{
  assert(!f.w.Model.GoAutoAssoc[0] && peerIndex(f.d,autoPeer)==AP6256_GO_PEERS && !count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE));
  assert(count(WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED)==(mode==5 || mode==9?1u:0u));
 }
 assert(f.d.Go.Peers[other].Active && f.d.Go.Peers[other].RxOpen);
 if(mode==4 || mode==5 || mode==6 || mode==7){assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);}else if(mode<15){assert(!f.d.Go.NativeStateUncertain);f.stationTraffic();}
 if(mode>=15){assert(io.empty() && metadataReads==2);}
 Ap6256ForgetGoAutoAssoc(&f.w,nullptr);assert(poolLive.empty());
}
static void lostGoCase(bool cleanupFailure,bool allocatorFailure=false){
 auto owned=std::make_unique<Fixture>();auto& f=*owned;seedAutonomous(f);autoEvent(f);assert(f.w.Model.GoAutoAssoc[0]);
 OpaqueRequest request;WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=888;assert(Ap6256BeginTask(&f.w,&f.w.ApAssocTask,&h,&request)==0);Ap6256SetTaskDeadline(&f.w,&f.w.ApAssocTask,1500);timerStart(&f.apTimer,1500);
 UCHAR unknown[6]={2,3,4,5,6,55};if(allocatorFailure)poolFailAt=poolCount+1;
 ULONG total=allocatorFailure?1u:AP6256_GO_EVENT_DEPTH+1u;for(ULONG n=0;n<total;++n){inRx=true;Ap6256NetGoEvent(&f.d,BRCMF_E_DEAUTH_IND,0,3,0,unknown,nullptr,0);inRx=false;}
 assert(f.w.Model.GoEventsLost);if(cleanupFailure)failStep=ioStep+1;drainGo(f);
 assert(!f.w.Model.GoEventsLost && f.w.Model.GoEventHead==f.w.Model.GoEventTail && !f.w.Model.GoAutoAssoc[0] && poolLive.empty() && !f.w.ApAssocTask.Active && !f.apTimer.Armed && !f.group.DataEnabled && !f.w.ApStarted && !f.d.Go.Started);
 for(ULONG n=0;n<AP6256_GO_PEERS;++n)assert(!f.d.Go.Peers[n].Active);
 assert(count(WDI_INDICATION_STOP_AP)==1 && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1 && indications.back().Id==WDI_INDICATION_STOP_AP);
 if(cleanupFailure){assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);}else{assert(!f.d.Go.NativeStateUncertain && f.w.HardwareAvailable);f.stationTraffic();}
}

static void autonomousTokens(){
 auto owned=std::make_unique<Fixture>();auto& f=*owned;seedAutonomous(f);autoEvent(f);autoEvent(f);assert(count(WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED)==2 && f.w.Model.GoAutoAssoc[0]);ULONGLONG latest=f.w.Model.GoAutoAssoc[0]->Token;
 OpaqueRequest stale;autoResponse(f,stale,true,0);assert(stale.Status==STATUS_CONNECTION_DISCONNECTED && f.w.Model.GoAutoAssoc[0]->Token==latest && !count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE) && peerIndex(f.d,autoPeer)==AP6256_GO_PEERS);
 OpaqueRequest current;autoResponse(f,current,true,1);assert(current.Status==0 && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1 && peerIndex(f.d,autoPeer)<AP6256_GO_PEERS);OpaqueRequest duplicate;autoResponse(f,duplicate,true,1);assert(duplicate.Status==STATUS_CONNECTION_DISCONNECTED && count(WDI_INDICATION_SEND_AP_ASSOCIATION_RESPONSE_COMPLETE)==1);f.stationTraffic();
}

static void clientCleanupCase(ULONG mode,bool failCleanup) {
 fprintf(stderr,"client cleanup case %lu failure %u\n",mode,failCleanup?1u:0u);
 auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE);
 assert(r.Completions==1 && r.Status==0 && f.w.Model.ClientConnectTask.Active && f.d.Go.Started);
 if(mode==1){Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected && count(WDI_INDICATION_CONNECT_COMPLETE)==1);}
 f.stationTraffic();AP6256_FRAME frame={};frame.Length=64;memcpy(f.gtx.PeerAddress,f.d.Go.ClientBssid,6);memcpy(frame.Data,f.d.Go.ClientBssid,6);NET_PACKET_WIFI_EXEMPTION_ACTION ex={};assert(Ap6256CxPrepareTx(&f.gtx,&ex,&frame)==0);
 LONG old=f.w.Model.GroupGeneration;ULONG joins=(ULONG)joinIes.size();if(failCleanup)failStep=ioStep+1;
 if(mode==0){nowMs=f.w.Model.ClientConnectTask.DeadlineMs;Ap6256OnClientConnectTimeout(&f.w);}
 else if(mode==1 || mode==3)Ap6256ClientLinkWork(&f.w,FALSE,old);
 else assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==(failCleanup?STATUS_IO_DEVICE_ERROR:STATUS_SUCCESS));
 if(mode==3 && !failCleanup){
  assert(f.w.Model.ClientConnectTask.Active && f.timer.Armed && joinIes.size()==joins+1 && f.w.Model.ClientCandidateIndex==1);
  Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected && count(WDI_INDICATION_CONNECT_COMPLETE)==1);assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0);
 }else{
  assert(!f.w.Model.ClientConnectTask.Active && !f.timer.Armed && joinIes.size()==joins);
  assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1);if(mode!=1)assert(!NT_SUCCESS(lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status));
  if(mode==0)assert(lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status==STATUS_IO_TIMEOUT);
  if(mode==2)assert(lastIndication(WDI_INDICATION_CONNECT_COMPLETE).Status==STATUS_CANCELLED);
 }
 assert(!f.d.Go.ClientConnected && !f.group.DataEnabled && !Ap6256CxFrameCurrent(&f.group,&frame));for(ULONG n=0;n<AP6256_GO_PEERS;++n)assert(!f.d.Go.Peers[n].Active);
 ULONG reads=metadataReads;Ap6256ClientLinkWork(&f.w,TRUE,old);assert(metadataReads==reads && count(WDI_INDICATION_CONNECT_COMPLETE)==1);
 if(failCleanup){
  assert(f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && count(WDI_INDICATION_FIRMWARE_STALLED)==1);
  auto& stalled=lastIndication(WDI_INDICATION_FIRMWARE_STALLED);assert(stalled.Header.PortId==0xffff && !stalled.Request && stalled.Transaction==0);
  AP6256_FRAME blocked={};blocked.Length=64;memcpy(blocked.Data,f.w.Model.StationPeerAddress,6);assert(!NT_SUCCESS(Ap6256CxPrepareTx(&f.tx,&ex,&blocked)));
 }else{assert(!f.d.Go.NativeStateUncertain && f.w.HardwareAvailable && !count(WDI_INDICATION_FIRMWARE_STALLED));f.stationTraffic();}
}

static void apLifecycleCase(ULONG mode) {
 fprintf(stderr,"AP lifecycle case %lu\n",mode);
 auto owned=std::make_unique<Fixture>();auto& f=*owned;f.d.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;f.w.ApStarted=FALSE;apDevice=&f.d;
 bool secure=mode!=0;WDI_TASK_START_AP_PARAMETERS p={};UCHAR ssid[]={'t','e','s','t'};p.DesiredSSID.pElements=ssid;p.DesiredSSID.ElementCount=4;
 auto auth=secure?WDI_AUTH_ALGO_RSNA_PSK:WDI_AUTH_ALGO_80211_OPEN;auto cipher=secure?WDI_CIPHER_ALGO_CCMP:WDI_CIPHER_ALGO_NONE;
 p.AuthenticationAlgorithms.pElements=&auth;p.AuthenticationAlgorithms.ElementCount=1;p.UnicastCipherAlgorithms.pElements=&cipher;p.UnicastCipherAlgorithms.ElementCount=1;p.MulticastCipherAlgorithms.pElements=&cipher;p.MulticastCipherAlgorithms.ElementCount=1;
 p.StaticParameters.BeaconPeriod=100;p.StaticParameters.DTIMPeriod=2;p.StaticParameters.ExcludeUnencrypted=secure;p.StaticParameters.AcceptNonP2PClients=TRUE;p.StaticParameters.MustUseSpecifiedChannels=TRUE;
 p.Optional.AdvertisedOperatingChannel_IsPresent=TRUE;p.AdvertisedOperatingChannel.ChannelNumber=36;p.AdvertisedOperatingChannel.OperatingClass=115;
 apFailUp=mode==2 || mode==4;apFailDown=mode==4 || mode==5 || mode==7 || mode==9;apCloseRole=mode==6 || mode==7;failStartDelivery=mode==8 || mode==9;if(mode==3 || mode==5)failMetadataCommand=BRCMF_C_GET_WSEC;
 UCHAR* bytes=nullptr;ULONG length=0;assert(GenerateWdiTaskStartApToIhv(&p,0,&f.w.TlvContext,&length,&bytes)==0 && bytes);
 OpaqueRequest r;WDI_MESSAGE_HEADER h={};h.PortId=2;h.TransactionId=901;requestBytes=bytes;requestLength=length;requestHeader=&h;poisonAtM3=true;
 Ap6256HandleStartAp(&f.w,&r,&h,bytes,length);FreeGenerated(bytes);assert(r.Completions==1 && !poisonAtM3 && count(WDI_INDICATION_START_AP_COMPLETE)==1);
 auto& completed=lastIndication(WDI_INDICATION_START_AP_COMPLETE);assert(completed.Header.PortId==2 && completed.Header.TransactionId==901 && completed.Transaction==901 && completed.Status==r.Status);
 if(mode<=1){
  assert(r.Status==0 && f.w.ApStarted && f.d.Go.Started && apBssUp && f.group.DataEnabled && f.d.Go.Peers[0].Active && f.w.GoApParams.Security==(secure?Ap6256SecurityWpa2Host:Ap6256SecurityOpen));f.stationTraffic();
  AP6256_FRAME frame={};frame.Length=64;memset(frame.Data,0xff,6);memset(f.gtx.PeerAddress,0xff,6);NET_PACKET_WIFI_EXEMPTION_ACTION ex={};assert(Ap6256CxPrepareTx(&f.gtx,&ex,&frame)==0 && Ap6256CxTransmit(&f.gtx,&frame)==0 && transmits.back().IfIndex==7);
  OpaqueRequest stop;WDI_MESSAGE_HEADER stopHeader={};stopHeader.PortId=2;stopHeader.TransactionId=902;Ap6256HandleStopAp(&f.w,&stop,&stopHeader);assert(stop.Completions==1 && stop.Status==0 && !f.w.ApStarted && !f.d.Go.Started && !apBssUp && !f.group.DataEnabled && !f.d.Go.Peers[0].Active && count(WDI_INDICATION_STOP_AP_COMPLETE)==1);f.stationTraffic();
 }else{
  assert((mode>=8?NT_SUCCESS(r.Status):!NT_SUCCESS(r.Status)) && !f.w.ApStarted && !f.group.DataEnabled);
  for(ULONG n=0;n<AP6256_GO_PEERS;++n)assert(!f.d.Go.Peers[n].Active);
  if(apFailDown){assert(apBssUp && f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && count(WDI_INDICATION_FIRMWARE_STALLED)==1);}
  else{assert(!apBssUp && !f.d.Go.Started && !f.d.Go.NativeStateUncertain && f.w.HardwareAvailable);f.stationTraffic();}
 }
 f.group.Closing=0;apDevice=nullptr;
}

int main(int argc,char** argv) {
 if(argc>1){apLifecycleCase((ULONG)std::stoul(argv[1]));return 0;}
 unsigned cases=0;
 for(BOOLEAN secure:{(BOOLEAN)FALSE,(BOOLEAN)TRUE}) {
  auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.stationTraffic();f.connect(r,secure);
  assert(r.Completions==1 && r.Status==0 && f.w.Model.ClientConnectTask.Active && f.timer.Armed && f.group.DataEnabled && f.d.Go.Started && !f.d.Go.ClientConnected);
  assert(hostIes.size()==6 && hostIes[1]==4);LONG generation=f.w.Model.GroupGeneration;
  f.stationTraffic();unsigned reads=metadataReads;Ap6256ClientLinkWork(&f.w,TRUE,generation-1);assert(metadataReads==reads && !count(WDI_INDICATION_CONNECT_COMPLETE));
  Ap6256ClientLinkWork(&f.w,TRUE,generation);assert(!f.w.Model.ClientConnectTask.Active && !f.timer.Armed && f.d.Go.ClientConnected && f.d.Go.Peers[1].RxOpen);checkAssociation(f,secure);
  assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1 && indications[indications.size()-2].Request==&r);
  AP6256_FRAME stale={};stale.Length=64;memcpy(stale.Data,f.d.Go.ClientBssid,6);NET_PACKET_WIFI_EXEMPTION_ACTION exemption={};memcpy(f.gtx.PeerAddress,f.d.Go.ClientBssid,6);assert(Ap6256CxPrepareTx(&f.gtx,&exemption,&stale)==0 && Ap6256CxTransmit(&f.gtx,&stale)==0);assert(transmits.back().IfIndex==7 && transmits.back().Port==2);
  UCHAR eth[64]={};memcpy(eth,f.d.Go.Address,6);memcpy(eth+6,f.d.Go.ClientBssid,6);eth[12]=8;Ap6256NetRxIndicate(&f.d,eth,sizeof(eth),0,7);assert(f.group.RxHead==1 && f.station.RxHead==0);
  assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0 && !f.group.DataEnabled && !f.d.Go.ClientConnected && !f.d.Go.Started && !f.d.Go.Peers[0].Active && !f.d.Go.Peers[1].Active && !Ap6256CxFrameCurrent(&f.group,&stale));
  f.stationTraffic();assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1 && count(WDI_INDICATION_DISASSOCIATION)==1);OpaqueRequest again;f.connect(again,secure);assert(again.Status==0 && f.w.Model.ClientConnectTask.Active);assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0);++cases;
 }
 for(ULONG failure=1;failure<=7;++failure) {
  auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;failStep=failure;f.connect(r,TRUE);assert(r.Status==0 && f.w.Model.ClientConnectTask.Active && f.w.Model.ClientCandidateIndex==1 && f.d.Go.ClientBssid[5]==11);f.stationTraffic();
  Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected && count(WDI_INDICATION_CONNECT_COMPLETE)==1);checkAssociation(f,TRUE);assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0);++cases;
 }
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;failAllJoins=true;f.connect(r,TRUE);assert(r.Status==0 && !f.w.Model.ClientConnectTask.Active && !f.timer.Armed && !f.group.DataEnabled && count(WDI_INDICATION_CONNECT_COMPLETE)==1);assert(indications.back().Status==STATUS_IO_DEVICE_ERROR);f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE);LONG old=f.w.Model.GroupGeneration;nowMs=f.w.Model.ClientConnectTask.DeadlineMs-1;Ap6256OnClientConnectTimeout(&f.w);assert(f.w.Model.ClientConnectTask.Active);++nowMs;Ap6256OnClientConnectTimeout(&f.w);assert(!f.w.Model.ClientConnectTask.Active && !f.group.DataEnabled && indications.back().Status==STATUS_IO_TIMEOUT);Ap6256ClientLinkWork(&f.w,TRUE,old);assert(count(WDI_INDICATION_CONNECT_COMPLETE)==1);f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,1,TRUE);assert(!NT_SUCCESS(r.Status) && !f.w.Model.ClientConnectTask.Active && io.empty() && peerCalls.empty());f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.d.FirmwareMchanSupported=FALSE;f.d.StationChannel=44;f.connect(r,TRUE);assert(!f.w.Model.ClientConnectTask.Active && indications.back().Status==STATUS_DEVICE_BUSY && !f.group.DataEnabled);f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,1);failAssocDelivery=true;Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(!f.d.Go.ClientConnected && !f.group.DataEnabled && count(WDI_INDICATION_CONNECT_COMPLETE)==1 && !NT_SUCCESS(indications.back().Status));f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,1);failConnectDelivery=true;Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(!f.d.Go.ClientConnected && !f.group.DataEnabled && !f.d.Go.Peers[1].Active && !f.d.Go.Started && !f.w.Model.ClientConnectTask.Active && !f.timer.Armed);f.stationTraffic();++cases;}
 {auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,1);failConnectDelivery=true;failStep=ioStep+1;Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(!f.d.Go.ClientConnected && !f.group.DataEnabled && !f.d.Go.Peers[1].Active && !f.w.Model.ClientConnectTask.Active && !f.timer.Armed && f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable);++cases;}


 for(ULONG mode:{1u,4u,5u,6u,8u}){
  auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,2,FALSE,mode);assert(r.Status==0 && f.w.Model.ClientConnectTask.Active && joinIes.size()==1);f.stationTraffic();
  ULONG common=mode==5 || mode==6?0u:6u,extra=mode==4?506u:mode==5?0u:6u;
  assert(joinIes[0].size()==common+extra);if(extra==6){assert(joinIes[0][common]==221 && joinIes[0].back()==0);}
  Ap6256ClientLinkWork(&f.w,FALSE,f.w.Model.GroupGeneration);assert(f.w.Model.ClientConnectTask.Active && f.w.Model.ClientCandidateIndex==1 && joinIes.size()==2);
  if(mode==8)extra=0;assert(joinIes[1].size()==common+extra);if(extra==6){assert(joinIes[1][common]==221 && joinIes[1].back()==1);}
  Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected && count(WDI_INDICATION_CONNECT_COMPLETE)==1);checkAssociation(f,TRUE);assert(Ap6256CancelClient(&f.w,STATUS_CANCELLED,3)==0);f.stationTraffic();++cases;
 }
 for(ULONG mode:{2u,3u,7u}){auto owned=std::make_unique<Fixture>();auto& f=*owned;OpaqueRequest r;f.connect(r,TRUE,2,FALSE,mode);assert(r.Status==STATUS_INVALID_PARAMETER && r.Completions==1 && !f.w.Model.ClientConnectTask.Active && !f.d.Go.Started && io.empty() && peerCalls.empty());f.stationTraffic();++cases;}
 for(ULONG mode=0;mode<4;++mode)for(bool failed:{false,true}){clientCleanupCase(mode,failed);++cases;}
 nativeGoCase(false);nativeGoCase(true);nativeGoCase(true,true);nativeGoCase(false,false,true);nativeGoCase(false,true,true);cases+=5;
 for(ULONG mode=0;mode<=16;++mode){fprintf(stderr,"autonomous case %lu\n",mode);autonomousCase(mode);++cases;}autonomousTokens();++cases;lostGoCase(false);lostGoCase(true);lostGoCase(false,true);cases+=3;
 for(ULONG mode=0;mode<10;++mode){apLifecycleCase(mode);++cases;}
 printf("PASS: %u real-codec GO/client connect/fallback/cancel/timeout/IE/security/autonomous admission cases with actual role peers/data and surviving station traffic\n",cases);
 return 0;
}
'''

def typed_enum(text, name):
    return re.search('typedef enum _' + name + '\\s*\\{[\\s\\S]*?\\} ' + name + ';', text)[0] + '\n'

def build_source():
    (raw, names) = base.build_source()
    all_functions = _functions((ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/wificx/role_adapter.inc').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/common/datapath.c').read_text(encoding='utf-8-sig'))
    text = raw[:raw.index(all_functions['Ap6256DatapathTransmitEx'])]
    start = text.index('struct Device {')
    end = text.index('static Wifi* Ap6256WifiFromDevice', start)
    ops = (ROOT / 'src/common/wifi_ops.h').read_text(encoding='utf-8-sig')
    internal = (ROOT / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig')
    hotspot = (ROOT / 'src/common/hotspot.h').read_text(encoding='utf-8-sig')
    types = EXTRA
    for name in ('AP6256_SECURITY', 'AP6256_MFP', 'AP6256_SCAN_BAND'):
        types += typed_enum(ops, name)
    for name in ('AP6256_CONNECT_PARAMS', 'AP6256_SCAN_CHANNEL', 'AP6256_ASSOC_FRAMES'):
        types += base.typed(ops, name)
    types += base.typed(ops, 'AP6256_AP_PARAMS') + base.typed(ops, 'AP6256_AP_PEER_INFO') + base.typed(hotspot, 'AP6256_GO_ASSOC_RESULT')
    types += base.typed((ROOT / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig'), 'BRCMF_BSS_INFO')
    p2p = (ROOT / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    types += typed_enum(p2p, 'AP6256_P2P_FRAME') + base.typed(p2p, 'AP6256_P2P_IE_SLOT')
    types += base.typed(internal, 'AP6256_WDI_TASK') + base.typed(hotspot, 'AP6256_GO_AUTO_ASSOC')
    types += base.typed((ROOT / 'src/wificx/netmodel_state.h').read_text(encoding='utf-8-sig'), 'AP6256_MODEL_STATE')
    for source in (ops, internal, hotspot):
        for line in source.splitlines():
            if re.match('^#define AP6256_(?:OWE_|GO_ASSOC_|LINK_CLIENT_|CONNECT_BSSID_LIMIT|CONNECT_TIMEOUT_MS|DISALLOW_BAND_|PHY_ID_|BEACON_FIXED_LEN)', line):
                types = line + '\n' + types
    for line in ops.splitlines():
        if line.startswith('#define AP6256_WDI_OPMODE_P2P_'):
            text = re.sub('^#define ' + line.split()[1] + '[^\\n]*', line, text, flags=re.M)
    start = text.index('struct Device {')
    end = text.index('static Wifi* Ap6256WifiFromDevice', start)
    text = text[:start] + types + STATE + text[end:]
    text += r'''
template<class A,class B> std::common_type_t<A,B> min(A a,B b){return a<b?a:b;}
template<class A,class B> std::common_type_t<A,B> max(A a,B b){return a>b?a:b;}
'''
    sdpcm = (ROOT / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    for name in ('BRCMF_C_GET_RATE', 'BRCMF_C_GET_RSSI', 'BRCMF_C_SET_INFRA', 'BRCMF_C_SET_SSID', 'BRCMF_C_DISASSOC', 'BRCMF_C_SET_KEY_PRIMARY', 'BRCMF_C_GET_AUTH', 'BRCMF_C_GET_WSEC', 'BRCMF_C_GET_WPA_AUTH', 'BRCMF_C_GET_WEP_RESTRICT', 'BRCMF_C_GET_BSS_INFO', 'BRCMF_C_GET_VALID_CHANNELS', 'BRCMF_C_SET_WEP_RESTRICT', 'BRCMF_C_SET_BCNPRD', 'BRCMF_C_SET_DTIMPRD'):
        text += re.search('^#define\\s+' + name + '[^\\n]*', sdpcm, re.M)[0] + '\n'
    text += '\n'.join(re.findall('^#define BRCMU_[^\\n]*', (ROOT / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig'), re.M)) + '\n'
    text += re.search('^#define\\s+AP6256_BCDC_TX_MAXLEN[^\\n]*', (ROOT / 'src/common/bcdc.h').read_text(encoding='utf-8-sig'), re.M)[0] + '\n'
    for line in sdpcm.splitlines():
        if re.match('^#define (?:BRCMF_E_|BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON)', line):
            text += line + '\n'
    for line in (ROOT / 'src/common/netadapter.h').read_text(encoding='utf-8-sig').splitlines():
        if re.match('^#define AP6256_(?:AP_(?:CAN_SUSTAIN|STOP_)|LINK_CLIENT_)', line):
            text += line + '\n'
    for name in ('STATUS_CONNECTION_REFUSED', 'STATUS_DEVICE_DATA_ERROR', 'STATUS_DEVICE_HARDWARE_ERROR'):
        text += re.search('^#define ' + name + '[^\\n]*', (base.INC / 'shared/ntstatus.h').read_text(encoding='utf-8-sig'), re.M)[0] + '\n'
    text += re.search('^#define AP6256_P2P_VENDOR_IE_MAX[^\\n]*', (ROOT / 'src/common/p2p.h').read_text(encoding='utf-8-sig'), re.M)[0] + '\n'
    text += _functions((ROOT / 'src/common/p2p.c').read_text(encoding='utf-8-sig'))['Ap6256P2pVendorIesValid'] + '\n'
    text += re.search('^#define AP6256_BSS_INFO_MAX[^\\n]*', (ROOT / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig'), re.M)[0] + '\n'
    text += AUTO_METADATA + NATIVE
    text = text.replace('static PUCHAR ExAllocatePool2(ULONG,SIZE_T n,ULONG) {return (PUCHAR)calloc(1,n);}', 'static PUCHAR ExAllocatePool2(ULONG,SIZE_T n,ULONG) {assert(!spinDepth);++poolCount;if(poolCount==poolFailAt)return nullptr;PUCHAR p=(PUCHAR)calloc(1,n);assert(p);assert(poolLive.insert(p).second);return p;}')
    text = text.replace('static void ExFreePoolWithTag(PVOID p,ULONG) {free(p);}', 'static void ExFreePoolWithTag(PVOID p,ULONG) {assert(poolLive.erase(p)==1);free(p);}')
    common = _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))
    native = _functions((ROOT / 'src/common/hotspot.c').read_text(encoding='utf-8-sig') + '\n' + (ROOT / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig'))
    group = _functions((ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig'))
    signatures = ['Ap6256P2pVendorIesValid']
    selected = [(common, ('Ap6256SendGeneratedIndication', 'Ap6256SendIndication', 'Ap6256ClaimTask', 'Ap6256SetTaskDeadline', 'Ap6256BeginTask', 'Ap6256FailStartedTask', 'Ap6256MacIsValue', 'Ap6256MacIsValidUnicast', 'Ap6256AddressInList', 'Ap6256AddressListIsUnrestricted', 'Ap6256BandIsMasked', 'Ap6256ChannelSupported', 'Ap6256AlgorithmPresent', 'Ap6256CipherPresent', 'Ap6256LinkQualityFromRssi', 'Ap6256NetApStopped', 'Ap6256NetApCanSustain')), (native, ('Ap6256EncodeChanspec', 'Ap6256GoSetBsscfg', 'Ap6256ClientConnect', 'Ap6256ClientDisconnect', 'Ap6256GoParseAssocResult', 'Ap6256GoDisconnectPeer', 'Ap6256GoStop', 'Ap6256WifiQueryBssInfo', 'Ap6256WifiGetApPeerInfo', 'Ap6256WifiGetApWmmEnabled', 'Ap6256GoVerifySecurity', 'Ap6256GoWideChanspecMatches', 'Ap6256GoSharedChanspec', 'Ap6256GoStart', 'Ap6256GoIesValid', 'Ap6256GoAssociationAllowed', 'Ap6256GoAppendIeBytes', 'Ap6256GoBuildAutoAssoc'))]
    text += re.search('static const UINT16 Ap6256Channels5\\[\\] = \\{[\\s\\S]*?\\};', internal)[0] + '\n'
    for (table, chosen) in selected:
        for name in chosen:
            signatures.append(name)
            text += table[name].replace('= {0};', '= {};') + '\n'
    for name in names:
        signatures.append(name)
        text += all_functions[name].replace('static VOID Ap6256ModelDeleteStationPeer', 'VOID Ap6256ModelDeleteStationPeer') + '\n'
    signatures.append('Ap6256NetFirmwareHalted')
    text += all_functions['Ap6256NetFirmwareHalted'] + '\n'
    chosen = ('Ap6256ClearGoEvents', 'Ap6256ForgetGoAutoAssoc', 'Ap6256CancelGoAssociation', 'Ap6256ModelApStopped', 'Ap6256GoRejectPeer', 'Ap6256GoAutoAssociation', 'Ap6256CxApAssocTimeout', 'Ap6256OnApAssocTimeout', 'Ap6256GoIndicateDisassociation', 'Ap6256ClientAssociation', 'Ap6256ClientLinkState', 'Ap6256ClientAppendVendorIes', 'Ap6256ClientStartAttempt', 'Ap6256CxDisconnectClient', 'Ap6256ClientAttemptResult', 'Ap6256CancelClientLocked', 'Ap6256CancelClient', 'Ap6256CxClientLinkWork', 'Ap6256ClientLinkWork', 'Ap6256CxClientConnectTimeout', 'Ap6256OnClientConnectTimeout', 'Ap6256HandleClientConnect', 'Ap6256GoAutoVendorIesMatch', 'Ap6256HandleGoAutoResponse', 'Ap6256HandleSendApAssociationResponse', 'Ap6256ProcessGoEvent', 'Ap6256CxStopGoChecked', 'Ap6256ModelStartApBegin', 'Ap6256ModelStartApEnd', 'Ap6256ModelStartApHardware', 'Ap6256ModelStartApCompleted', 'Ap6256ModelStartApPeer', 'Ap6256ModelApStarted', 'Ap6256ModelStopApPeers', 'Ap6256CxQueueGoEvent', 'Ap6256NetGoEvent', 'Ap6256ModelTakeCommandEvent', 'Ap6256ModelProcessCommandEvent')
    for name in chosen:
        signatures.append(name)
        body = group[name].replace('= {0};', '= {};')
        if name == 'Ap6256ModelProcessCommandEvent':
            body = body.replace('Ap6256ProcessGoEvent(wifi, Event);', 'Ap6256ProcessGoEvent(wifi, static_cast<const AP6256_GO_EVENT*>(Event));')
        text += body + '\n'
    for name in ('Ap6256BandIsDisallowed', 'Ap6256ApChannelRequested', 'Ap6256SelectApChannel', 'Ap6256HandleStartAp', 'Ap6256HandleStopAp'):
        signatures.append(name)
        text += common[name].replace('= {0};', '= {};') + '\n'
    return (text + TEST, signatures)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ap-case', type=int, choices=range(10))
    args = parser.parse_args()
    (text, names) = build_source()
    out = OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64'), 'advapi32.lib', str(base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(args.ap_case)] if args.ap_case is not None else []), capture_output=True, text=True, timeout=40)
    print(run.stdout, end='')
    print(run.stderr, end='')
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in ('src/wificx/group_engine.inc', 'src/wificx/role_adapter.inc', 'src/wificx/netadapter.c', 'src/wificx/netmodel_state.h', 'src/common/netadapter.c', 'src/common/hotspot.c', 'src/common/wifi_ops.h', 'src/common/netadapter_internal.h', 'src/common/native_frame.inc', 'src/common/ap6256.h', 'src/common/netadapter.h', 'src/common/hotspot.h', 'src/common/sdpcm.h', 'src/common/bcdc.h', 'src/common/wifi_ops.c', 'src/common/datapath.c', 'src/common/p2p.c', 'src/common/p2p.h', 'tests/driver_sources.py', 'tests/test-wificx-roles.py', 'tests/test-wificx-group-integration.py')}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'sdk_header_sha256': {p: hashlib.sha256((base.INC / p).read_bytes()).hexdigest() for p in ('km/netcx/kmdf/adapter/2.5/netadaptercxtypes.h', 'shared/netcx/shared/1.0/net/wifi/exemptionactiontypes.h', 'um/wlan/2.0/TlvGenerated_.hpp')}, 'board_verified': False, 'boundary': 'Microsoft TLV codec and GO/client control, task, role and data paths.', 'negative_control': None, 'expect_regression': False, 'ap_case': args.ap_case, 'negative_source_sha256': None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
