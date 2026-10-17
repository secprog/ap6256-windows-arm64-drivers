# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute WiFiCx group key requests across native role, cleanup and power lifetimes.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess
from driver_sources import _functions
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('key_cold', ROOT / 'tests/test-wificx-factory-cold.py')
cold = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cold)
base = cold.group.base
OUT = output_dir('wificx-group-key-lifecycle')
GLOBALS = r'''
#include <map>
struct KeyCall {UINT32 IfIndex,Command;std::vector<UCHAR> Bytes;};
static std::vector<KeyCall> keyCalls;
static std::map<std::string,std::vector<UCHAR>> keyTable;
static std::set<std::string> keyAuthorized;
static UINT16 keyMessageId=WDI_TASK_CHANGE_OPERATION_MODE;
static bool keyWakeAfterSet=false,keyFailAuthorize=false,keyFailDelete=false;
static LONG keyFailId=-1;static UINT32 keyWakeCommand=BRCMF_C_SET_KEY;static unsigned keyAdmissionFailures=0;
static unsigned keyNativeAttempts=0,keyDefault=0,keySeeds=0;
static ULONGLONG KeQueryInterruptTime(){return 0;}
static NTSTATUS Ap6256WlfcWaitEapol(Device*,UINT32) {return 0;}
static NTSTATUS modeControlAdmission(Device*);
static VOID factoryScheduleWake(Device*);
static UINT32 keyLe32(const UCHAR* p){return (UINT32)p[0]|((UINT32)p[1]<<8)|((UINT32)p[2]<<16)|((UINT32)p[3]<<24);}
static std::string keyPeer(UINT32 iface,const UCHAR* p){return std::to_string(iface)+":"+std::string((const char*)p,6);}
static std::string keyIdentity(UINT32 iface,const UCHAR* p){return keyPeer(iface,p+156)+":"+std::to_string(keyLe32(p));}
static void keyRetire(UINT32 iface){
 const auto prefix=std::to_string(iface)+":";
 for(auto it=keyTable.begin();it!=keyTable.end();)if(it->first.rfind(prefix,0)==0)it=keyTable.erase(it);else ++it;
 for(auto it=keyAuthorized.begin();it!=keyAuthorized.end();)if(it->rfind(prefix,0)==0)it=keyAuthorized.erase(it);else ++it;
}
static NTSTATUS keyEndpoint(Device* d,UINT32 iface,UINT32 command,const VOID* p,ULONG n){
 ++keyNativeAttempts;NTSTATUS status=modeControlAdmission(d);if(!NT_SUCCESS(status)){++keyAdmissionFailures;return status;}
 assert(!spinDepth && (iface==0 || (iface==7 && nativePresent)));
 const auto bytes=(const UCHAR*)p;keyCalls.push_back({iface,command,std::vector<UCHAR>(bytes,bytes+n)});
 if(command==BRCMF_C_SET_KEY){
  assert(n==164);const bool removing=keyLe32(bytes+4)==0;
  if((removing && keyFailDelete) || (!removing && (LONG)keyLe32(bytes)==keyFailId))return STATUS_IO_TIMEOUT;
  if(removing)keyTable.erase(keyIdentity(iface,bytes));else keyTable[keyIdentity(iface,bytes)]={bytes,bytes+n};
 }else if(command==BRCMF_C_SCB_AUTHORIZE){assert(n==6);if(keyFailAuthorize)return STATUS_IO_DEVICE_ERROR;keyAuthorized.insert(keyPeer(iface,bytes));}
 else if(command==BRCMF_C_SCB_DEAUTHORIZE){assert(n==6);keyAuthorized.erase(keyPeer(iface,bytes));}
 else {assert(command==BRCMF_C_SET_KEY_PRIMARY && n==4);keyDefault=keyLe32(bytes);}
 if(keyWakeAfterSet && command==keyWakeCommand){keyWakeAfterSet=false;factoryScheduleWake(d);}
 return 0;
}
static VOID Ap6256WifiSeedGroupKey(Device*,UINT32,BOOLEAN,BOOLEAN,const UCHAR*,const UCHAR*){++keySeeds;}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN on){assert(on);return 0;}
static VOID Ap6256WifiTracePeerAuthorization(Device*,UINT32,const UCHAR*){}
'''
KEYIO = r'''
static NTSTATUS Ap6256BcdcSetDcmdIf(Device* d,UINT32 iface,UINT32 command,const VOID* p,ULONG n){
 if(command==BRCMF_C_SET_KEY || command==BRCMF_C_SCB_AUTHORIZE || command==BRCMF_C_SCB_DEAUTHORIZE || (command==BRCMF_C_SET_KEY_PRIMARY && n==4 && *(const UINT32*)p!=0))return keyEndpoint(d,iface,command,p,n);
 return keyOriginalDcmd(d,iface,command,p,n);
}
static NTSTATUS Ap6256BcdcSetIovarIf(Device* d,UINT32 iface,PCSTR name,const VOID* p,ULONG n){
 if(!strcmp(name,"wsec_key"))return keyEndpoint(d,iface,BRCMF_C_SET_KEY,p,n);
 NTSTATUS status=keyOriginalIovar(d,iface,name,p,n);
 if(NT_SUCCESS(status) && (!strcmp(name,"key_remove_all") || (!strcmp(name,"bss") && n==8 && ((const UINT32*)p)[1]==0)))keyRetire(iface);
 return status;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device* d,UINT32 iface,UINT32 command,PVOID p,ULONG n,AP6256_BCDC_QUERY_RESULT* result){
 if(command!=BRCMF_C_GET_KEY_PRIMARY)return keyOriginalQuery(d,iface,command,p,n,result);
 ++keyNativeAttempts;NTSTATUS status=modeControlAdmission(d);if(!NT_SUCCESS(status)){++keyAdmissionFailures;return status;}
 assert(n==4 && *(const UINT32*)p==keyDefault);*(UINT32*)p=1;memset(result,0,sizeof(*result));result->FirmwareReply=TRUE;result->PayloadLength=4;return 0;
}
'''
TEST = r'''
struct KeyPayload {
 UCHAR Material[16]={},Sequence[6]={1,2,3,4,5,6};WDI_SET_ADD_CIPHER_KEYS_CONTAINER Entries[3]={};WDI_SET_ADD_CIPHER_KEYS_PARAMETERS Add={};WDI_SET_DELETE_CIPHER_KEYS_CONTAINER Removal[3]={};WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS Delete={};
 KeyPayload(const UCHAR* peer){
  for(ULONG n=0;n<16;++n)Material[n]=(UCHAR)(0xa0+n);
  Add.SetCipherKey.pElements=Entries;Add.SetCipherKey.ElementCount=3;Delete.CipherKeyInfo.pElements=Removal;Delete.CipherKeyInfo.ElementCount=3;
  for(ULONG n=0;n<3;++n){auto& e=Entries[n];e.Optional.CipherKeyID_IsPresent=TRUE;e.CipherKeyID.CipherKeyID=n==0?0:(n==1?2:4);e.CipherKeyTypeInfo.CipherAlgorithm=n==2?WDI_CIPHER_ALGO_BIP:WDI_CIPHER_ALGO_CCMP;e.CipherKeyTypeInfo.KeyType=n==0?WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY:(n==1?WDI_CIPHER_KEY_TYPE_GROUP_KEY:WDI_CIPHER_KEY_TYPE_IGTK);e.CipherKeyTypeInfo.Direction=WDI_CIPHER_KEY_DIRECTION_BOTH;
   e.Optional.ReceiveSequenceCount_IsPresent=TRUE;memcpy(e.ReceiveSequenceCount.ReceiveSequenceCount,Sequence,6);
   if(n==0){e.Optional.PeerMacAddress_IsPresent=TRUE;memcpy(e.PeerMacAddress.Address,peer,6);}
   if(n==2){e.Optional.BIPKey_IsPresent=TRUE;e.BIPKey.pElements=Material;e.BIPKey.ElementCount=16;}else{e.Optional.CCMPKey_IsPresent=TRUE;e.CCMPKey.pElements=Material;e.CCMPKey.ElementCount=16;}
   Removal[n].Optional.CipherKeyID_IsPresent=TRUE;Removal[n].CipherKeyID=e.CipherKeyID;Removal[n].CipherKeyTypeInfo=e.CipherKeyTypeInfo;Removal[n].Optional.PeerMacAddress_IsPresent=e.Optional.PeerMacAddress_IsPresent;Removal[n].PeerMacAddress=e.PeerMacAddress;
  }
 }
};
static void keyRequest(Fixture& f,OpaqueRequest& request,UINT16 message,KeyPayload& payload,UINT16 port=2){
 PUCHAR bytes=nullptr;ULONG n=0;
 if(message==WDI_SET_ADD_CIPHER_KEYS)assert(GenerateWdiSetAddCipherKeysToIhv(&payload.Add,sizeof(WDI_MESSAGE_HEADER),&f.w.TlvContext,&n,&bytes)==0);
 else if(message==WDI_SET_DELETE_CIPHER_KEYS)assert(GenerateWdiSetDeleteCipherKeysToIhv(&payload.Delete,sizeof(WDI_MESSAGE_HEADER),&f.w.TlvContext,&n,&bytes)==0);
 else {WDI_SET_DEFAULT_KEY_ID_PARAMETERS p={};p.DefaultKeyIdParameters.KeyID=2;assert(GenerateWdiSetDefaultKeyIdToIhv(&p,sizeof(WDI_MESSAGE_HEADER),&f.w.TlvContext,&n,&bytes)==0);}
 WDI_MESSAGE_HEADER header={};header.PortId=port;header.TransactionId=988;requestHeader=&header;requestBytes=bytes;requestLength=n;keyMessageId=message;


 Ap6256LockAcquire(&f.w.Model.AdapterLock);Ap6256ProcessCommand(&f.w,&request,0);Ap6256LockRelease(&f.w.Model.AdapterLock);
 assert(request.Completions==1);FreeGenerated(bytes);requestHeader=nullptr;requestBytes=nullptr;keyMessageId=WDI_TASK_CHANGE_OPERATION_MODE;
 if(factoryWakeActor.joinable()){factoryWakeActor.join();beforeLock=nullptr;assert(factoryWakeStatus==0);}
}
static void keyCase(ULONG n){
 fprintf(stderr,"group key lifecycle case %lu\n",n);auto owned=keyFixture();auto& f=*owned;auto role=f.w.Model.Roles[1];
 const UCHAR peer[6]={2,9,8,7,6,5};KeyPayload payload(peer),station(f.w.Model.StationPeerAddress);OpaqueRequest request,connect,change,ap,stationRequest;
 keyRequest(f,stationRequest,WDI_SET_ADD_CIPHER_KEYS,station,0);assert(stationRequest.Status==0 && keyTable.size()==3 && keySeeds==2);
 const auto stationKeys=keyTable;keySeeds=0;keyCalls.clear();keyNativeAttempts=0;
 if(n==1 || n==3 || n==7){modeTask(f,change,AP6256_WDI_OPMODE_P2P_CLIENT);assert(change.Status==0);if(n!=7){f.connect(connect,TRUE,1);Ap6256ClientLinkWork(&f.w,TRUE,f.w.Model.GroupGeneration);assert(f.d.Go.ClientConnected);memcpy(payload.Entries[0].PeerMacAddress.Address,f.d.Go.ClientBssid,6);payload.Removal[0].PeerMacAddress=payload.Entries[0].PeerMacAddress;}}
 AP6256_FRAME oldGroup={};
 if(n==0 || n==4 || n==5 || n==6 || n==9 || n==18 || n==19){
  startAp(f,ap);assert(ap.Status==0);assert(Ap6256CxGroupPeerCreate(&f.d,peer,0));Ap6256CxGroupRxOpen(&f.d,peer);memcpy(f.gtx.PeerAddress,peer,6);
  oldGroup.Length=64;memcpy(oldGroup.Data,peer,6);oldGroup.Data[6]=2;oldGroup.Data[12]=8;NET_PACKET_WIFI_EXEMPTION_ACTION exempt={};assert(Ap6256CxPrepareTx(&f.gtx,&exempt,&oldGroup)==0 && Ap6256CxFrameCurrent(role,&oldGroup));
 }
 if(n==2 || n==17)keyWakeAfterSet=true;
 if(n==8)keyFailAuthorize=true;
 if(n==10 || n==11 || n==17){keyFailId=2;keyFailDelete=n==11;}
 if(n==12){role->Closing=1;}
 if(n==13){f.d.Go.NativeStateUncertain=TRUE;}
 if(n==14){assert(Ap6256WifiCxArmWake(&f.d)==0);}
 keyRequest(f,request,WDI_SET_ADD_CIPHER_KEYS,payload);
 if(n==12 || n==13 || n==14){assert(!NT_SUCCESS(request.Status) && keyCalls.empty() && !keyNativeAttempts && keyTable==stationKeys);if(n==12){role->Closing=0;WdfObjectDelete(role);assert(engineRefs==1 && keyTable==stationKeys);}else{WdfObjectDelete(role);assert(engineRefs==1);if(n==14){assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && keyTable.empty());assert(Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0);}else assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD3)==0 && keyTable.empty());}return;}
 if(n==8 || n==10 || n==11 || n==17){
  assert(!NT_SUCCESS(request.Status));assert(keyTable.size()==(n==11?4u:3u));for(const auto& p:stationKeys)assert(keyTable.at(p.first)==p.second);
  keyFailAuthorize=keyFailDelete=false;keyFailId=-1;
  if(n==17)assert(f.w.PowerStateDx && !keyAdmissionFailures && request.Status==STATUS_IO_TIMEOUT);
  WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && keyTable==stationKeys && engineRefs==1);
  if(n==17){assert(f.d.Go.NativeStateUncertain);assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && keyTable.empty());assert(Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0);}
  return;
 }
 fprintf(stderr,"key result %08lx entries %zu attempts %u native-calls %zu dx %u quiesced %ld authorized %zu\n",request.Status,keyTable.size(),keyNativeAttempts,keyCalls.size(),(unsigned)f.w.PowerStateDx,f.d.FirmwareIoQuiesced,keyAuthorized.size());
 assert(request.Status==0 && keyTable.size()==6 && !keySeeds);
 auto it=std::find_if(keyCalls.begin(),keyCalls.end(),[](const KeyCall& c){return c.Command==BRCMF_C_SCB_AUTHORIZE;});assert(it!=keyCalls.end() && it->IfIndex==7 && it->Bytes.size()==6 && !memcmp(it->Bytes.data(),payload.Entries[0].PeerMacAddress.Address,6));
 for(const auto& c:keyCalls)assert(c.IfIndex==7);for(const auto& p:stationKeys)assert(keyTable.at(p.first)==p.second);
 if(n==2){assert(f.w.PowerStateDx && f.d.FirmwareIoQuiesced && f.d.LowPowerArmed && factoryActorAtGroup);assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD2)==0 && !coldStops);assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0 && keyTable.size()==6);}
 if(n==3){AP6256_FRAME old={};old.Length=64;memcpy(old.Data,f.d.Go.ClientBssid,6);old.Data[6]=2;old.Data[12]=8;memcpy(f.gtx.PeerAddress,f.d.Go.ClientBssid,6);NET_PACKET_WIFI_EXEMPTION_ACTION exempt={};assert(Ap6256CxPrepareTx(&f.gtx,&exempt,&old)==0);LONG generation=f.w.Model.GroupGeneration;
  assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD3)==0 && keyTable.empty() && !role->DataEnabled && !Ap6256CxFrameCurrent(role,&old));assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD3)==0 && Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD3)==0 && f.d.Go.FirmwareReady && !role->DataEnabled);
  Ap6256ClientLinkWork(&f.w,TRUE,generation);assert(!f.d.Go.ClientConnected && !role->DataEnabled && keyTable.empty());WdfObjectDelete(role);assert(engineRefs==1);return;}
 if(n==4){assert(Ap6256ModelResetGroup(&f.w)==0);Ap6256ModelResetGroupPeers(&f.w);f.w.ApStarted=FALSE;assert(!f.d.Go.Started && !role->DataEnabled && !Ap6256CxFrameCurrent(role,&oldGroup) && keyTable==stationKeys);OpaqueRequest restart;startAp(f,restart);assert(Ap6256CxGroupPeerCreate(&f.d,peer,0));Ap6256CxGroupRxOpen(&f.d,peer);assert(!Ap6256CxFrameCurrent(role,&oldGroup));WdfObjectDelete(role);assert(engineRefs==1 && keyTable==stationKeys);return;}
 if(n==5){assert(Ap6256WifiCxArmWake(&f.d)==STATUS_NOT_SUPPORTED && !f.w.PowerStateDx && !f.d.LowPowerArmed && keyTable.size()==6);}
 if(n==6){WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && !Ap6256CxFrameCurrent(role,&oldGroup) && keyTable==stationKeys && engineRefs==1);NETADAPTER_INIT init={WIFI_ADAPTER_WIFI_DIRECT_ROLE,74};assert(Ap6256EvtWifiCreateAdapter(&f.d,&init)==0 && keyTable==stationKeys && lastAdapter!=role && !lastAdapter->DataEnabled);WdfObjectDelete(lastAdapter);assert(engineRefs==1);return;}
 if(n==7){assert(Ap6256WifiCxArmWake(&f.d)==0);WdfObjectDelete(role);assert(f.d.Go.NativeStateUncertain && keyTable.size()==6);assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && !resumes && coldStarts==1 && keyTable.empty());assert(Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0 && !f.w.Model.Roles[1]);return;}
 if(n==9 || n==16){OpaqueRequest select;if(n==16){keyWakeAfterSet=true;keyWakeCommand=BRCMF_C_SET_KEY_PRIMARY;}keyRequest(f,select,WDI_SET_DEFAULT_KEY_ID,payload);assert(select.Status==0 && keyDefault==2);if(n==16){assert(f.w.PowerStateDx && !keyAdmissionFailures);assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0);}}
 if(n==18 || n==19){
  if(n==18){deleteFail=true;deleteEffect=false;}else apFailDown=true;
  WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && engineRefs==1 && f.d.Go.NativeStateUncertain && !f.w.HardwareAvailable && !Ap6256CxFrameCurrent(role,&oldGroup));
  assert(keyTable.size()==(n==18?3u:6u));deleteFail=false;apFailDown=false;
  assert(Ap6256EvtD0Exit(&f.d,WdfPowerDeviceD3)==0 && keyTable.empty());assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD3)==0 && Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD3)==0 && !f.w.Model.Roles[1] && !f.d.Go.Created);return;
 }
 if(n==15){keyWakeAfterSet=true;keyWakeCommand=BRCMF_C_SCB_DEAUTHORIZE;}
 OpaqueRequest remove;keyRequest(f,remove,WDI_SET_DELETE_CIPHER_KEYS,payload);assert(remove.Status==0 && keyTable==stationKeys && !keyAuthorized.count(keyPeer(7,payload.Entries[0].PeerMacAddress.Address)));
 if(n==15){assert(f.w.PowerStateDx && !keyAdmissionFailures);assert(Ap6256EvtD0Entry(&f.d,WdfPowerDeviceD2)==0 && Ap6256EvtD0EntryPostInterruptsEnabled(&f.d,WdfPowerDeviceD2)==0);}
 WdfObjectDelete(role);assert(!f.w.Model.Roles[1] && engineRefs==1 && keyTable==stationKeys && heldLocks.empty());
}
int main(int argc,char** argv){if(argc>1){keyCase((ULONG)std::stoul(argv[1]));return 0;}for(ULONG n=0;n<20;++n)keyCase(n);puts("PASS: 20 real-codec group key/authorization/native-role/power lifetime cases");return 0;}
'''

def build_source():
    (text, names) = cold.build_source()
    text = text.replace('int main(int argc,char** argv)', 'int factoryColdMain(int argc,char** argv)')
    text = 'static void keyTrace(const char*,...){}\n' + text.replace('#define TraceDiag(...) ((void)0)', '#define TraceDiag(...) keyTrace(__VA_ARGS__)')
    text = text.replace('static void startAp(Fixture& f,OpaqueRequest& request){', 'static void startAp(Fixture& f,OpaqueRequest& request){ULONG apCompletions=count(WDI_INDICATION_START_AP_COMPLETE);').replace('count(WDI_INDICATION_START_AP_COMPLETE)==1 && lastIndication(WDI_INDICATION_START_AP_COMPLETE).Status==request.Status', 'count(WDI_INDICATION_START_AP_COMPLETE)==apCompletions+1 && lastIndication(WDI_INDICATION_START_AP_COMPLETE).Status==request.Status')

    def change(old, new):
        nonlocal text
        assert text.count(old) == 1, (old[:100], text.count(old))
        text = text.replace(old, new)
    change('static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32 i){assert(i==0);return hostCipherPowerMode!=0;}', 'static BOOLEAN Ap6256HostCipherPacketActive(Device*,UINT32 i){assert(i==0 || i==7);return i==0 && hostCipherPowerMode!=0;}')
    ctx = (ROOT / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    ops = (ROOT / 'src/common/wifi_ops.h').read_text(encoding='utf-8-sig')
    wc = (ROOT / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig')
    sd = (ROOT / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    enum = cold.group.typed_enum(ctx, 'AP6256_GO_DATA_STAGE')
    change('struct GroupPowerDevice {', enum + '\nstruct GroupPowerDevice {')
    change('AP6256_GO_PEER Peers[AP6256_GO_PEERS]={};', 'AP6256_GO_PEER Peers[AP6256_GO_PEERS]={};LONG DataTrace[Ap6256GoDataStageCount]={},Ipv4Trace[2][Ap6256GoDataStageCount]={};')
    definitions = ''
    for (source, pattern) in ((ops, '^#define AP6256_BIP_KEY_MAX[^\\n]*'), (wc, '^#define BRCMF_(?:CRYPTO_ALGO_AES_CCM|PRIMARY_KEY)\\s+[^\\n]*'), (sd, '^#define BRCMF_C_(?:SET_KEY|SCB_AUTHORIZE|SCB_DEAUTHORIZE|GET_KEY_PRIMARY)\\s+[^\\n]*')):
        for d in re.findall(pattern, source, re.M):
            name = d.split()[1]
            if not re.search('^#define\\s+' + name + '\\s', text, re.M):
                definitions += d + '\n'
    declarations = base.typed(ops, 'AP6256_CCMP_KEY') + base.typed(ops, 'AP6256_BIP_KEY') + '#pragma pack(push,1)\n' + base.typed(wc, 'BRCMF_WSEC_KEY') + '#pragma pack(pop)\n'
    before = _functions(text)['Ap6256BcdcSetDcmdIf']
    change(before, definitions + GLOBALS + before.replace('Ap6256BcdcSetDcmdIf', 'keyOriginalDcmd'))
    before = _functions(text)['Ap6256BcdcSetIovarIf']
    change(before, before.replace('Ap6256BcdcSetIovarIf', 'keyOriginalIovar') + KEYIO[:KEYIO.index('static NTSTATUS Ap6256BcdcQueryDcmdResultIf')])
    text += KEYIO[KEYIO.index('static NTSTATUS Ap6256BcdcQueryDcmdResultIf'):].replace('if(command!=BRCMF_C_GET_KEY_PRIMARY)return keyOriginalQuery(d,iface,command,p,n,result);', 'assert(iface==7 && command==BRCMF_C_GET_KEY_PRIMARY);')
    before = _functions(text)['Ap6256RequestGetMessageId']
    change(before, 'static UINT16 Ap6256RequestGetMessageId(AP6256_REQUEST r){assert(r && r->Magic==0xcafed00d);return keyMessageId;}')
    change('template<class... T> static NTSTATUS Ap6256HandleKeyRequest(T...){assert(false);return STATUS_NOT_SUPPORTED;}', 'static VOID Ap6256HandleKeyRequest(Wifi*,PWDI_MESSAGE_HEADER,AP6256_REQUEST,UINT16,const UCHAR*,ULONG);')
    statusHeader = (base.INC / 'shared/ndis/status.h').read_text(encoding='utf-8-sig')
    text += '\n' + re.search('^#define NDIS_STATUS_INVALID_DATA[^\\n]*', statusHeader, re.M)[0] + '\n' + declarations
    text += 'static NTSTATUS Ap6256HostCipherSetDefault(Device*,ULONG,ULONG){assert(false);return STATUS_NOT_SUPPORTED;}\n'
    table = _functions(wc)
    import native_key_fixture
    text = native_key_fixture.context(text)
    text += native_key_fixture.writer()
    for name in ('Ap6256WifiDeleteCcmpKeyIf', 'Ap6256WifiAddCcmpKey', 'Ap6256WifiAddBipKey', 'Ap6256WifiDeleteBipKeyIf', 'Ap6256WifiSetDefaultKeyIdIf'):
        text += table[name].replace('= {0};', '= {};') + '\n'
        names.append(name)
    text += '#define AP6256_HC_KEY_BYTES 32u\n' + base.typed((ROOT / 'src/common/host_cipher_keys.h').read_text(encoding='utf-8-sig'), 'AP6256_HOST_CIPHER_KEY') + '\n'
    text += 'static NTSTATUS Ap6256HostCipherAddKeys(Device*,ULONG,const AP6256_HOST_CIPHER_KEY*,ULONG){return STATUS_NOT_SUPPORTED;}\n'
    text += 'static NTSTATUS Ap6256HostCipherDeleteKeys(Device*,ULONG,const AP6256_HOST_CIPHER_KEY*,ULONG){return STATUS_NOT_SUPPORTED;}\n'
    for name in ('Ap6256CommandInterface', 'Ap6256ParseHostKey', 'Ap6256ParseHostDelete', 'Ap6256HostKeys', 'Ap6256AddKeys', 'Ap6256DeleteKeys', 'Ap6256HandleKeyRequest'):
        text += _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))[name] + '\n'
        names.append(name)
    for name in ('Ap6256ModelResetGroup', 'Ap6256ModelResetGroupPeers', 'Ap6256CxStopGoChecked'):
        body = _functions((ROOT / 'src/wificx/group_engine.inc').read_text(encoding='utf-8-sig'))[name]
        if name == 'Ap6256ModelResetGroup':
            text += 'static NTSTATUS Ap6256CxStopGoChecked(Wifi*);\n'
        existing = _functions(text)
        if name in existing:
            text = text.replace(existing[name], body)
        else:
            text += body + '\n'
        if name not in names:
            names.append(name)
    before = _functions(text)['Ap6256BcdcSetIovar']
    change(before, before.replace('Ap6256BcdcSetIovar', 'keyOriginalPrimary') + r'''
static NTSTATUS Ap6256BcdcSetIovar(Device* d,PCSTR name,const VOID* p,ULONG n){NTSTATUS s=keyOriginalPrimary(d,name,p,n);if(!nativePresent && !strcmp(name,"p2p_ifdel"))keyRetire(7);return s;}
''')
    for name in ('Ap6256TearDownChip', 'Ap6256BringUpChip'):
        before = _functions(text)[name]
        change(before, before.replace('nativePresent=false;', 'nativePresent=false;keyTable.clear();keyAuthorized.clear();'))
    setup = cold.TEST[cold.TEST.index(' allocations.clear();'):cold.TEST.index(' OpaqueRequest connect,change,ap;')]
    setup = setup.replace('auto owned=std::make_unique<Fixture>();', r'''keyTable.clear();keyAuthorized.clear();keyCalls.clear();keyMessageId=WDI_TASK_CHANGE_OPERATION_MODE;keyWakeAfterSet=keyFailAuthorize=keyFailDelete=false;keyFailId=-1;keyNativeAttempts=keyDefault=keySeeds=keyAdmissionFailures=0;keyWakeCommand=BRCMF_C_SET_KEY;
 auto owned=std::make_unique<Fixture>();''')
    setup = setup.replace('auto role=lastAdapter;', 'auto role=lastAdapter;')
    text += '\nstatic std::unique_ptr<Fixture> keyFixture(){\n' + setup + 'return owned;\n}\n'
    return (text + TEST, names)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--case', type=int, choices=range(20))
    parser.add_argument('--output-dir', type=Path)
    args = parser.parse_args()
    (text, names) = build_source()
    text = text.replace('#define TraceVerbose(...) ((void)0)', '#undef TraceVerbose\n#define TraceVerbose(...) ((void)0)')
    old_hashes = {}
    case = args.case if args.case is not None else {'key-wake': 2, 'delete-wake': 15, 'default-wake': 16, 'rollback-wake': 17, 'closing': 12, 'uncertain': 13}.get(None)
    out = args.output_dir or OUT / (None or 'current')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, text, encoding='utf-8')
    command = [str(base.VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/wd4100', '/Od', '/MT', '/DWDI_IS_DRIVER', '/DAP6256_ENABLE_WIFICX', '/I' + str(base.VC / 'include')]
    command += ['/I' + str(base.INC / p) for p in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/STACK:16777216', '/LIBPATH:' + str(base.VC / 'lib/x64'), '/LIBPATH:' + str(base.LIB / 'ucrt/x64'), '/LIBPATH:' + str(base.LIB / 'um/x64'), 'advapi32.lib', str(base.LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    write_text(out / 'compile-command.json', json.dumps(command, indent=2), encoding='utf-8')
    subprocess.run(command, check=True)
    run = subprocess.run([str(out / 'tests.exe')] + ([str(case)] if case is not None else []), capture_output=True, text=True, timeout=45)
    print(run.stdout, end='')
    print(run.stderr, end='')
    paths = ('src/common/kmdf_device.c', 'src/common/device.c', 'src/common/firmware.c', 'src/common/bcdc.c', 'src/common/netadapter.c', 'src/common/wifi_ops.c', 'src/common/wifi_ops.h', 'src/common/sdpcm.h', 'src/common/ap6256.h', 'src/common/hotspot.c', 'src/common/netadapter_internal.h', 'src/wificx/netadapter.c', 'src/wificx/role_adapter.inc', 'src/wificx/group_engine.inc', 'src/wificx/wowl_power.inc', 'src/wificx/netmodel_state.h', 'tests/driver_sources.py', 'tests/test-wificx-group-key-lifecycle.py', 'tests/test-wificx-factory-cold.py', 'tests/test-wificx-factory-power.py', 'tests/test-wificx-hardware-stop.py', 'tests/test-wificx-group-mode.py', 'tests/test-wificx-group-power.py', 'tests/test-wificx-group-integration.py', 'tests/test-wificx-roles.py')
    headers = dict(cold.factory.mode.power.HEADERS)
    for header in (base.INC / 'shared/ndis/status.h', base.INC / 'km/netcx/kmdf/adapter/2.5/netadapter.h', base.SDK / 'Include/wdf/kmdf/1.33/wdfdevice.h'):
        headers[str(header)] = hashlib.sha256(header.read_bytes()).hexdigest()
    receipt = {'functions': names, 'source_sha256': {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in paths}, 'cpp_sha256': hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compiler_sha256': hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(), 'codec_sha256': hashlib.sha256(Path(command[-1]).read_bytes()).hexdigest(), 'exe_sha256': hashlib.sha256((out / 'tests.exe').read_bytes()).hexdigest(), 'sdk_header_sha256': headers, 'boundary': __doc__, 'board_verified': False, 'case': case, 'negative_control': None, 'negative_source_sha256': old_hashes or None, 'returncode': run.returncode, 'stdout': run.stdout, 'stderr': run.stderr}
    write_text(out / 'receipt.json', json.dumps(receipt, indent=2), encoding='utf-8')
    assert run.returncode != 0 if False or None else run.returncode == 0, run.returncode
if __name__ == '__main__':
    main()
