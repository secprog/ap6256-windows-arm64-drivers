# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute production host-cipher control/broker/store/CNG with reply faults.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import ctypes as c
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
AP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('control_transport', AP / 'tests/test-host-cipher-transport.py')
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)
(U8, U32, P8) = (T.U8, T.U32, T.P8)

class Key(c.Structure):
    _fields_ = [('cipher', U32), ('keyid', U32), ('pairwise', U8), ('tx', U8), ('rx', U8), ('peer_present', U8), ('peer', U8 * 6), ('material', U8 * 32), ('rsc', U8 * 6)]

class Query(c.Structure):
    _fields_ = [('reply', U8), ('error', U8), ('status', c.c_int), ('length', U32)]

class Session(c.Structure):
    _fields_ = [('generation', U32), ('station', U8 * 6), ('bssid', U8 * 6)]

class Profile(c.Structure):
    _fields_ = [(name, U32) for name in ('abi', 'bytes', 'generation', 'pairwise', 'group', 'management', 'akm', 'mfp')]
IO = c.CFUNCTYPE(c.c_long, c.c_void_p, U8, U32, c.c_char_p, c.c_void_p, U32, c.POINTER(Query))
FIXTURE = r'''
#undef C_ASSERT
#define TEST_CONCAT_(a,b) a##b
#define TEST_CONCAT(a,b) TEST_CONCAT_(a,b)
#define C_ASSERT(x) typedef char TEST_CONCAT(test_assert_,__LINE__)[(x)?1:-1]
#define MAXUSHORT 0xffffu
#define AP6256_GROUP_PORT 2
typedef struct {BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;} AP6256_BCDC_QUERY_RESULT,*PAP6256_BCDC_QUERY_RESULT;
typedef NTSTATUS (*ControlIo)(void*,BOOLEAN,UINT32,PCSTR,void*,ULONG,PAP6256_BCDC_QUERY_RESULT);
static ControlIo testIo;static void* testIoContext;
static ULONG capsBits=0x1f,fault,faultSkips,faultOnly,ioCalls,cancels;
static AP6256_HC_MODE nativeModes[16];
static AP6256_HC_AUTH_CONTROL nativeAuthorization[16];
static AP6256_HC_PROFILE_CONTROL nativeProfiles[16];
static AP6256_HC_DISCONNECT_CONTROL nativeDisconnect[16];
static UCHAR nativeDisconnectWire[AP6256_HC_DISCONNECT_WIRE_BYTES];
static ULONG nativePtkSeen[16],disconnectMode,disconnectStatus,disconnectSets;
static ULONG nativeEpochs[16][8],nativeDefaults[16][2];
static VOID Ap6256WlfcCancel(Device* d,UINT16 port,UINT16 peer,void* cookie) {
 assert(port==0||port==2);assert(peer==0xffff&&!cookie);assert(d->HostCipherBlockedMask);++cancels;
}
static NTSTATUS FixtureIo(Device* d,BOOLEAN set,UINT32 iface,PCSTR name,void* data,ULONG n,PAP6256_BCDC_QUERY_RESULT result) {
 ULONG thisFault=0;assert(iface<16&&TestIrql==0);
 assert(n==32||(set&&!strcmp(name,"wdi_hc_disconnect")&&n==32+AP6256_HC_DISCONNECT_WIRE_BYTES));++ioCalls;
 if(result){memset(result,0,sizeof(*result));result->FirmwareReply=TRUE;result->PayloadLength=n;}
 if(testIo)return testIo(testIoContext,set,iface,name,data,n,result);
 if((!faultOnly || !strcmp(name,faultOnly==1?"wdi_hc_key":faultOnly==2?"wdi_hc_auth":faultOnly==3?"wdi_hc_profile":faultOnly==4?"wdi_hc_disconnect":"wdi_hc_mode")) &&
    ((set&&(fault==1||fault==2))||(!set&&fault>=3))){
  if(faultSkips)--faultSkips;else {thisFault=fault;fault=0;}
 }
 if(thisFault==1)return STATUS_IO_TIMEOUT;
 if(!strcmp(name,"wdi_hc_caps")) {
  assert(d->HostCipherFirmwareQualified==-1&&!Ap6256RawGenerationCurrent(d,iface,1,TRUE));
  ULONG values[8]={0x31435048,32,capsBits,1,8192,1760,2244,16};assert(!set);memcpy(data,values,32);
 } else {
  assert(Ap6256HostCipherPacketActive(d,iface));
   if(set||strcmp(name,"wdi_hc_profile"))assert(!Ap6256RawGenerationCurrent(d,iface,1,TRUE));
  if(!strcmp(name,"wdi_hc_disconnect")) {
   AP6256_HC_DISCONNECT_CONTROL* a=data;
   assert(a->Abi==0x31435048&&a->Bytes==32&&a->Generation&&!a->NativeStatus&&!a->Completed);
   assert(!Ap6256HostCipherStoreActive(&d->HostCipherStore,iface)&&TestKeyCount(&d->HostCipherStore)==0);
   if(set){
    AP6256_HC_WIRE_VIEW view;AP6256_HC_WIRE_SESSION session;
    assert(nativeModes[iface].Enabled&&a->Generation==nativeModes[iface].Session.Generation&&a->IfIndex==iface);
    ++disconnectSets;nativeDisconnect[iface]=*a;nativeDisconnect[iface].Mode=0;
    if(a->Mode==1){
     assert(n==32+AP6256_HC_DISCONNECT_WIRE_BYTES);
     memcpy(&session,&nativeModes[iface].Session,sizeof(session));
     assert(Ap6256HostCipherWireRead(&session,AP6256_HC_MGMT_TX_DIRECT,(UCHAR*)data+32,n-32,&view));
     assert(view.Length==50&&view.Frame[0]==0xc0&&(view.FrameControl&0x4000)&&view.KeyId<2);
     assert(view.Epoch==nativeEpochs[iface][view.KeyId]&&nativeDefaults[iface][0]==view.KeyId);
     memcpy(nativeDisconnectWire,(UCHAR*)data+32,sizeof(nativeDisconnectWire));
     if(disconnectMode)nativeDisconnect[iface].Mode=1;
    }else if(a->Mode==2&&(!nativeProfiles[iface].Mfp||!nativePtkSeen[iface])&&disconnectMode)nativeDisconnect[iface].Mode=2;
    nativeDisconnect[iface].NativeStatus=disconnectStatus;nativeDisconnect[iface].Completed=1;
    memset(&nativeModes[iface],0,32);nativeModes[iface].Abi=0x31435048;nativeModes[iface].Bytes=32;
    memset(&nativeProfiles[iface],0,32);memset(&nativeAuthorization[iface],0,32);
    memset(nativeEpochs[iface],0,32);nativePtkSeen[iface]=0;
   }else{
    assert(!a->Reason&&!a->Mode);
    if(a->Generation!=nativeDisconnect[iface].Generation||a->IfIndex!=nativeDisconnect[iface].IfIndex)return STATUS_INVALID_DEVICE_STATE;
    *a=nativeDisconnect[iface];
   }
  } else if(!strcmp(name,"wdi_hc_mode")) {
   AP6256_HC_MODE* m=data;
   if(set){nativeModes[iface]=*m;memset(&nativeAuthorization[iface],0,32);memset(&nativeProfiles[iface],0,32);nativePtkSeen[iface]=0;if(!m->Enabled){memset(&nativeModes[iface].Session,0,20);memset(nativeEpochs[iface],0,32);} }
   else *m=nativeModes[iface];
  } else if(!strcmp(name,"wdi_hc_profile")) {
   AP6256_HC_PROFILE_CONTROL* p=data;
   assert(p->Abi==0x31435048&&p->Bytes==32&&nativeModes[iface].Enabled&&p->Generation==nativeModes[iface].Session.Generation);
   if(set){
    assert(p->Pairwise==9&&p->Group==9&&p->Mfp<=2&&p->Management==(p->Mfp?12u:0u));
    assert(p->Akm==1||p->Akm==2||p->Akm==5||p->Akm==8||p->Akm==12||p->Akm==18);
    for(ULONG s=0;s<8;++s)assert(!nativeEpochs[iface][s]);
    nativeProfiles[iface]=*p;
   }else{
    assert(!p->Pairwise&&!p->Group&&!p->Management&&!p->Akm&&!p->Mfp);*p=nativeProfiles[iface];
   }
  } else if(!strcmp(name,"wdi_hc_auth")) {
   AP6256_HC_AUTH_CONTROL* a=data;
   assert(a->Abi==0x31435048&&a->Bytes==32);
   assert(nativeModes[iface].Enabled&&a->Generation==nativeModes[iface].Session.Generation);
   if(set){
    assert(a->Authorized<=1);
    if(a->Authorized){
     assert(a->Slot<2&&a->Epoch&&nativeDefaults[iface][0]==a->Slot&&nativeEpochs[iface][a->Slot]==a->Epoch);
     if(nativeProfiles[iface].Mfp)assert(a->ManagementEpoch&&a->ManagementSlot>=6&&a->ManagementSlot<8&&nativeEpochs[iface][a->ManagementSlot]==a->ManagementEpoch);
     else assert(!a->ManagementEpoch&&!a->ManagementSlot);
    }else assert(!a->Epoch&&!a->Slot&&!a->ManagementEpoch&&!a->ManagementSlot);
    nativeAuthorization[iface]=*a;
   }else{
    assert(!a->Authorized&&!a->Epoch&&!a->Slot&&!a->ManagementEpoch&&!a->ManagementSlot);*a=nativeAuthorization[iface];
   }
  } else {
   AP6256_HC_KEY_CONTROL* k=data;ULONG group;
   assert(!strcmp(name,"wdi_hc_key")&&k->Slot<8&&k->Abi==0x31435048&&k->Bytes==32&&!k->Reserved);
   assert(nativeModes[iface].Enabled&&k->Generation==nativeModes[iface].Session.Generation);
   group=k->Slot>=6;
   if(set){nativeEpochs[iface][k->Slot]=k->Epoch;if(k->Slot<2&&k->Epoch)nativePtkSeen[iface]=1;if(k->SetDefault)nativeDefaults[iface][group]=k->Slot;
    AP6256_HC_AUTH_CONTROL* a=&nativeAuthorization[iface];
    if(a->Authorized&&(a->Epoch!=nativeEpochs[iface][nativeDefaults[iface][0]]||a->Slot!=nativeDefaults[iface][0]||
       (nativeProfiles[iface].Mfp&&nativeEpochs[iface][a->ManagementSlot]!=a->ManagementEpoch))){
     a->Authorized=a->Epoch=a->Slot=a->ManagementEpoch=a->ManagementSlot=0;
    }
   }
   else {
    assert(!k->Epoch&&!k->SetDefault&&!k->DefaultSlot);
    k->Epoch=nativeEpochs[iface][k->Slot];
    k->SetDefault=k->Epoch&&(k->Slot<=1||k->Slot>=6)&&nativeDefaults[iface][group]==k->Slot;
    k->DefaultSlot=k->SetDefault?k->Slot:0;
   }
  }
 }
 if(thisFault==2||thisFault==3)return STATUS_IO_TIMEOUT;
 if(thisFault==4)result->PayloadLength=31;
 if(thisFault==5)result->FirmwareReply=FALSE;
 if(thisFault==6){result->FirmwareError=TRUE;result->FirmwareStatus=-2;}
 if(thisFault==7)((ULONG*)data)[0]^=1;
 if(thisFault==8)((ULONG*)data)[4]^=1;
 if(thisFault==9)Ap6256HostCipherStoreInvalidate(&d->HostCipherStore,iface);
 if(thisFault==10)((ULONG*)data)[2]^=1;
 if(thisFault==11)((ULONG*)data)[5]^=1;
 if(thisFault==12){InterlockedExchange(&d->HostCipherFirmwareQualified,0);Ap6256HostCipherStoreInvalidateAll(&d->HostCipherStore);}
 if(thisFault==13)InterlockedExchange(&d->FirmwareHalted,1);
 if(thisFault==14)((ULONG*)data)[6]^=1;
 if(thisFault==15)((ULONG*)data)[7]^=1;
 return 0;
}
static NTSTATUS Ap6256BcdcSetIovarIf(Device* d,UINT32 i,PCSTR name,const VOID* data,ULONG n) {
 UCHAR copy[32];assert(n==32);memcpy(copy,data,n);return FixtureIo(d,TRUE,i,name,copy,n,NULL);
}
static NTSTATUS Ap6256BcdcSetIovarResultIf(Device* d,UINT32 i,PCSTR name,const VOID* data,ULONG n,PAP6256_BCDC_QUERY_RESULT result) {
 UCHAR copy[32+AP6256_HC_DISCONNECT_WIRE_BYTES];assert(n<=sizeof(copy));memcpy(copy,data,n);
 return FixtureIo(d,TRUE,i,name,copy,n,result);
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device* d,UINT32 i,PCSTR name,void* data,ULONG n,PAP6256_BCDC_QUERY_RESULT result) {
 return FixtureIo(d,FALSE,i,name,data,n,result);
}
'''
TAIL = r'''
void TestControlReset(void) {
 memset(nativeModes,0,sizeof(nativeModes));memset(nativeEpochs,0,sizeof(nativeEpochs));memset(nativeDefaults,0,sizeof(nativeDefaults));
 memset(nativeAuthorization,0,sizeof(nativeAuthorization));
 memset(nativeProfiles,0,sizeof(nativeProfiles));
 memset(nativeDisconnect,0,sizeof(nativeDisconnect));memset(nativeDisconnectWire,0,sizeof(nativeDisconnectWire));
 memset(nativePtkSeen,0,sizeof(nativePtkSeen));disconnectMode=1;disconnectStatus=disconnectSets=0;
 capsBits=0x1f;fault=faultSkips=faultOnly=ioCalls=cancels=0;testIo=NULL;testIoContext=NULL;
}
void TestCaps(ULONG bits) {capsBits=bits;}
void TestFault(ULONG value) {fault=value;faultSkips=faultOnly=0;}
void TestFaultAfter(ULONG value,ULONG skip) {fault=value;faultSkips=skip;faultOnly=1;}
void TestAuthFault(ULONG value) {fault=value;faultSkips=0;faultOnly=2;}
void TestProfileFault(ULONG value) {fault=value;faultSkips=0;faultOnly=3;}
void TestDisconnectFault(ULONG value,ULONG stage) {fault=value;faultSkips=0;faultOnly=stage?5:4;}
void TestDisconnectOutcome(ULONG accepted,ULONG status) {disconnectMode=accepted;disconnectStatus=status;}
ULONG TestDisconnectSets(void) {return disconnectSets;}
const UCHAR* TestDisconnectWire(void) {return nativeDisconnectWire;}
void TestControlIo(ControlIo callback,void* context) {testIo=callback;testIoContext=context;}
ULONG TestIoCalls(void) {return ioCalls;}
ULONG TestBlocked(Device* d) {return d->HostCipherBlockedMask;}
ULONG TestNextGeneration(Device* d) {return d->HostCipherNextGeneration;}
void TestGenerationFrontier(Device* d,ULONG value) {assert(value>=d->HostCipherNextGeneration);d->HostCipherNextGeneration=value;}
void* TestStore(Device* d) {return &d->HostCipherStore;}
ULONG TestNativeEpoch(ULONG i,ULONG slot) {return nativeEpochs[i][slot];}
ULONG TestNativeDefault(ULONG i,ULONG group) {return nativeDefaults[i][group];}
ULONG TestNativeAuthorized(ULONG i) {return nativeAuthorization[i].Authorized;}
ULONG TestNativeManagement(ULONG i,ULONG field) {assert(field<2);return field?nativeAuthorization[i].ManagementSlot:nativeAuthorization[i].ManagementEpoch;}
ULONG TestNativeProfile(ULONG i,ULONG field) {assert(i<16&&field<8);return ((ULONG*)&nativeProfiles[i])[field];}
void TestChangeProfile(ULONG i,ULONG field,ULONG value) {assert(i<16&&field<8);((ULONG*)&nativeProfiles[i])[field]=value;}
void TestIrqlControl(UCHAR value) {TestIrql=value;}
void TestHalted(Device* d,LONG value) {InterlockedExchange(&d->FirmwareHalted,value);}
void TestFirmwareState(Device* d,LONG value) {d->FirmwareState=value;}
ULONGLONG TestPnFrontier(Device* d) {return d->HostCipherStore.NextTransmitPn;}
void* TestProvider(Device* d) {return d->HostCipherStore.Provider;}
'''

def build(out, transform=None, additional_exports=()):

    def plain(name):
        return re.sub('^#(?:include|pragma)[^\\n]*\\n', '', (AP / ('src/common/' + name)).read_text(encoding='utf-8-sig'), flags=re.M)
    text = T.build_fixture_text()
    text += plain('host_cipher_disconnect.h') + plain('host_cipher_control.h') + plain('host_cipher_keys.h') + FIXTURE
    text += plain('host_cipher_control.c') + plain('host_cipher_keys.c') + TAIL
    if transform is not None:
        text = transform(text)
    fixture = out / 'control-fixture.c'
    write_bytes(fixture, text.encode())
    exports = ['TestDeviceCreate', 'TestDeviceDestroy', 'TestControlReset', 'TestCaps', 'TestFault', 'TestFaultAfter', 'TestAuthFault', 'TestProfileFault', 'TestNativeProfile', 'TestControlIo', 'TestConfigure', 'TestDispatch', 'TestCaptures', 'TestCaptured', 'TestCapturedBytes', 'TestIoCalls', 'TestBlocked', 'TestNextGeneration', 'TestGenerationFrontier', 'TestStore', 'TestNativeEpoch', 'TestNativeDefault', 'TestNativeAuthorized', 'TestNativeManagement', 'TestChangeProfile', 'TestKeyCount', 'TestPoolCount', 'TestIrqlControl', 'TestHalted', 'TestSetClock', 'TestFragmentCount', 'TestFailAlloc', 'TestPause', 'TestWaitEntered', 'TestUnpause', 'Ap6256HostCipherQualify', 'Ap6256HostCipherFirmwareRetire', 'Ap6256HostCipherFirmwareStarted', 'TestFirmwareState', 'TestPnFrontier', 'TestProvider', 'Ap6256HostCipherBegin', 'Ap6256HostCipherBeginProfile', 'Ap6256HostCipherReadProfile', 'Ap6256HostCipherConfirmAssociation', 'Ap6256HostCipherEnd', 'Ap6256HostCipherEndGeneration', 'Ap6256HostCipherAddKey', 'Ap6256HostCipherDisconnect', 'TestDisconnectFault', 'TestDisconnectOutcome', 'TestDisconnectSets', 'TestDisconnectWire', 'Ap6256HostCipherDeleteKey', 'Ap6256HostCipherAddKeys', 'Ap6256HostCipherDeleteKeys', 'Ap6256HostCipherSetDefault', 'Ap6256HostCipherPacketActive', 'Ap6256HostCipherBeginProfileRx', 'Ap6256HostCipherSetRxExemptions', 'Ap6256HostCipherStoreSetRxExemptions', 'Ap6256HostCipherStoreSetExcludeUnencrypted', 'Ap6256HostCipherStoreRxAllowed', 'Ap6256RawPrepareTx', 'Ap6256RawTxCurrent', 'Ap6256RawBcdcTxCurrent', 'Ap6256RawGenerationCurrent', 'Ap6256RawRxRead', 'Ap6256HostCipherStoreFrame', 'Ap6256HostCipherStoreSnapshot', 'Ap6256HostCipherStoreAuthorize', 'Ap6256HostCipherStoreDefault', 'Ap6256HostCipherStoreKeyOwner', 'Ap6256HostCipherStoreInvalidate', 'Ap6256HostCipherStoreInstall', 'Ap6256HostCipherStoreSetDefault', 'Ap6256HostCipherStoreAuthorized', 'Ap6256HostCipherStoreInvalidateAll']
    exports += ['Ap6256HostCipherDataRx', 'Ap6256RawRxFrame', 'Ap6256HostCipherDataRxAmsduBegin', 'Ap6256HostCipherDataRxAmsduNext']
    exports += list(additional_exports)
    definition = out / 'control.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(exports) + '\n', encoding='utf-8')
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in [T.VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    command = [str(T.VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/wd4005', '/O2', '/GS', '/MT', '/LD', '/DAP6256_HOST_CRYPTO_USER_TEST']
    command += ['/I' + str(p) for p in [T.VC / 'include', INC / 'um', INC / 'shared', INC / 'ucrt']]
    command += [str(AP / ('src/common/' + p)) for p in ('host_cipher_frame.c', 'host_crypto_cng.c', 'host_cipher_wire.c', 'host_fips_wire.c')]
    command += [str(fixture), '/Fo' + str(out) + '\\', '/Fe' + str(out / 'control.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'control.lib'), 'bcrypt.lib']
    result = subprocess.run(command, cwd=out, env=env, capture_output=True, text=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    assert result.returncode == 0, result.stdout + result.stderr

def load_dll(path):
    dll = c.CDLL(str(path))
    ptr = c.c_void_p
    dll.TestDeviceCreate.restype = ptr
    dll.TestDeviceDestroy.argtypes = [ptr]
    dll.TestStore.argtypes = [ptr]
    dll.TestStore.restype = ptr
    dll.TestKeyCount.argtypes = [ptr]
    dll.TestBlocked.argtypes = [ptr]
    dll.TestBlocked.restype = U32
    dll.TestNextGeneration.argtypes = [ptr]
    dll.TestGenerationFrontier.argtypes = [ptr, U32]
    dll.TestHalted.argtypes = [ptr, c.c_long]
    dll.TestFirmwareState.argtypes = [ptr, c.c_long]
    dll.TestPnFrontier.argtypes = [ptr]
    dll.TestPnFrontier.restype = c.c_uint64
    dll.TestProvider.argtypes = [ptr]
    dll.TestProvider.restype = ptr
    dll.Ap6256HostCipherFirmwareStarted.argtypes = [ptr]
    dll.Ap6256HostCipherFirmwareRetire.argtypes = [ptr]
    dll.TestAuthFault.argtypes = [U32]
    dll.TestNativeAuthorized.argtypes = [U32]
    dll.TestControlIo.argtypes = [IO, ptr]
    dll.Ap6256HostCipherQualify.argtypes = [ptr, U8]
    dll.Ap6256HostCipherBegin.argtypes = [ptr, U32, P8, P8]
    dll.Ap6256HostCipherBeginProfile.argtypes = [ptr, U32, P8, P8, U32, U32]
    dll.Ap6256HostCipherReadProfile.argtypes = [ptr, U32, c.POINTER(Session), c.POINTER(Profile)]
    dll.Ap6256HostCipherConfirmAssociation.argtypes = [ptr, U32, U32, P8, P8, U32, U32]
    dll.TestNativeManagement.argtypes = [U32, U32]
    dll.TestChangeProfile.argtypes = [U32, U32, U32]
    dll.TestProfileFault.argtypes = [U32]
    dll.TestNativeProfile.argtypes = [U32, U32]
    dll.Ap6256HostCipherEnd.argtypes = [ptr, U32, U8]
    dll.Ap6256HostCipherEndGeneration.argtypes = [ptr, U32, U32, c.POINTER(U8)]
    dll.Ap6256HostCipherDisconnect.argtypes = [ptr, U32, P8, U32, c.POINTER(U8)]
    dll.TestDisconnectFault.argtypes = [U32, U32]
    dll.TestDisconnectOutcome.argtypes = [U32, U32]
    dll.TestDisconnectWire.restype = ptr
    dll.Ap6256HostCipherAddKey.argtypes = [ptr, U32, c.POINTER(Key)]
    dll.Ap6256HostCipherAddKeys.argtypes = [ptr, U32, c.POINTER(Key), U32]
    dll.Ap6256HostCipherDeleteKeys.argtypes = [ptr, U32, c.POINTER(Key), U32]
    dll.Ap6256HostCipherDeleteKey.argtypes = [ptr, U32, U32, U32, U8, P8]
    dll.Ap6256HostCipherSetDefault.argtypes = [ptr, U32, U32]
    dll.Ap6256HostCipherPacketActive.argtypes = [ptr, U32]
    dll.Ap6256HostCipherPacketActive.restype = U8
    dll.Ap6256RawTxCurrent.argtypes = [ptr, U32, P8, U32]
    dll.Ap6256RawTxCurrent.restype = U8
    dll.Ap6256RawBcdcTxCurrent.argtypes = [ptr, P8, U32]
    dll.Ap6256RawBcdcTxCurrent.restype = U8
    dll.Ap6256RawGenerationCurrent.argtypes = [ptr, U32, U32, U8]
    dll.Ap6256RawGenerationCurrent.restype = U8
    dll.Ap6256RawPrepareTx.argtypes = [ptr, U32, P8, U32, c.POINTER(U32), c.POINTER(U8), c.POINTER(U8)]
    dll.Ap6256HostCipherStoreAuthorize.argtypes = [ptr, U32, U32, U8]
    dll.Ap6256HostCipherStoreAuthorized.argtypes = [ptr, U32, U32]
    dll.Ap6256HostCipherStoreAuthorized.restype = U8
    dll.Ap6256HostCipherStoreDefault.argtypes = [ptr, U32, U32, U8, c.POINTER(T.Owner)]
    dll.Ap6256HostCipherStoreDefault.restype = U8
    return dll

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('host-cipher-control'))
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    build(out)
    dll = load_dll(out / 'control.dll')
    checks = 0

    def check(value):
        nonlocal checks
        checks += 1
        assert value, checks

    def start(mfp=0):
        dll.TestControlReset()
        d = dll.TestDeviceCreate()
        dll.TestCaps(287)
        check(dll.Ap6256HostCipherQualify(d, 1) == 0)
        check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, mfp) == 0)
        check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 1, T.buf(T.STATION), T.buf(T.APMAC), 2, mfp) == 0)
        return d

    def key(cipher=9, keyid=0, pair=True, tx=True, rx=True, material=bytes(range(32))):
        k = Key()
        k.cipher = cipher
        k.keyid = keyid
        k.pairwise = pair
        k.tx = tx
        k.rx = rx
        k.peer_present = pair
        k.peer[:] = T.APMAC
        k.material[:] = material
        return k

    def transmit(d):
        plain = T.frame(True, b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload')
        output = (U8 * 8352)()
        output[:len(plain)] = plain
        (n, p, e) = (U32(len(plain)), U8(0), U8(0))
        status = dll.Ap6256RawPrepareTx(d, 0, output, len(output), c.byref(n), c.byref(p), c.byref(e))
        return (status, bytes(output[:n.value]))

    def retired(d):
        check(dll.TestBlocked(d) & 1)
        check(dll.TestKeyCount(dll.TestStore(d)) == 0)
        check(dll.Ap6256HostCipherPacketActive(d, 0))
        check(not dll.Ap6256RawGenerationCurrent(d, 0, 1, 1))
        check(transmit(d)[0] < 0)
        ordinary = b' \x00\x00\x00' + bytes(30)
        check(not dll.Ap6256RawBcdcTxCurrent(d, T.buf(ordinary), len(ordinary)))
    fresh_start_cases = 0
    for sticky in (False, True):
        d = start()
        try:
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            (status, old_wire) = transmit(d)
            check(status == 0)
            (provider, pn) = (dll.TestProvider(d), dll.TestPnFrontier(d))
            check(provider and pn == 1)
            if sticky:
                dll.TestFault(4)
                check(dll.Ap6256HostCipherEnd(d, 0, 0) < 0)
                retired(d)
            dll.TestFirmwareState(d, 1)
            calls = dll.TestIoCalls()
            check(dll.Ap6256HostCipherFirmwareStarted(d) == 0)
            check(dll.TestIoCalls() == calls and dll.TestKeyCount(dll.TestStore(d)) == 0)
            check(not dll.TestBlocked(d) and (not dll.Ap6256HostCipherPacketActive(d, 0)))
            check(dll.TestProvider(d) == provider and dll.TestPnFrontier(d) == pn and (dll.TestNextGeneration(d) == 1))
            check(not dll.Ap6256RawTxCurrent(d, 0, T.buf(old_wire), len(old_wire)))
            check(dll.Ap6256RawGenerationCurrent(d, 0, 0, 0))
            check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
            dll.TestControlReset()
            check(dll.Ap6256HostCipherQualify(d, 1) < 0)
            dll.TestFirmwareState(d, 2)
            check(dll.Ap6256HostCipherQualify(d, 1) < 0)
            check(dll.Ap6256RawGenerationCurrent(d, 0, 0, 0))
            dll.TestCaps(287)
            check(dll.Ap6256HostCipherQualify(d, 1) == 0)
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0)
            check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 2, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0)
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            check(dll.TestNativeEpoch(0, 0) == 2 and dll.TestNextGeneration(d) == 2)
            (status, new_wire) = transmit(d)
            check(status == 0 and dll.TestPnFrontier(d) == pn + 1)
            check(dll.TestProvider(d) == provider and (not dll.Ap6256RawTxCurrent(d, 0, T.buf(old_wire), len(old_wire))))
            check(dll.Ap6256RawTxCurrent(d, 0, T.buf(new_wire), len(new_wire)))
            fresh_start_cases += 1
        finally:
            dll.TestDeviceDestroy(d)
    for (state, halted, irql) in ((0, 0, 0), (2, 0, 0), (1, 1, 0), (1, 0, 2)):
        d = start()
        try:
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            dll.TestFirmwareState(d, state)
            dll.TestHalted(d, halted)
            dll.TestIrqlControl(irql)
            calls = dll.TestIoCalls()
            check(dll.Ap6256HostCipherFirmwareStarted(d) < 0)
            dll.TestIrqlControl(0)
            check(dll.TestIoCalls() == calls and dll.TestKeyCount(dll.TestStore(d)) == 1)
            check(dll.Ap6256HostCipherPacketActive(d, 0) and dll.TestNextGeneration(d) == 1)
            fresh_start_cases += 1
        finally:
            dll.TestIrqlControl(0)
            dll.TestDeviceDestroy(d)
    disconnect_cases = 0
    for (mfp, phase) in ((0, 'key'), (2, 'initial'), (2, 'key'), (2, 'ready'), (2, 'deleted')):
        d = start(mfp)
        try:
            if phase in ('key', 'ready', 'deleted'):
                check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            if phase == 'ready':
                check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key(12, 4, False, False))) == 0)
            if phase == 'deleted':
                check(dll.Ap6256HostCipherDeleteKey(d, 0, 9, 0, 1, T.buf(T.APMAC)) == 0)
            handled = U8(0)
            reason = 4660
            status = dll.Ap6256HostCipherDisconnect(d, 0, T.buf(T.APMAC), reason, c.byref(handled))
            check((status < 0) == (phase == 'deleted') and handled.value == 1)
            check(dll.TestDisconnectSets() == 1 and dll.TestKeyCount(dll.TestStore(d)) == 0 and (not dll.TestBlocked(d)))
            check(not dll.Ap6256HostCipherPacketActive(d, 0) and (not dll.TestNativeAuthorized(0)))
            if mfp and phase in ('key', 'ready'):
                plain = bytearray(26)
                plain[0] = 192
                plain[4:10] = T.APMAC
                plain[10:16] = T.STATION
                plain[16:22] = T.APMAC
                plain[24:26] = reason.to_bytes(2, 'little')
                observed = c.string_at(dll.TestDisconnectWire(), 210)
                check(observed == T.wire(8, T.oracle_gcmp(bytes(range(32)), bytes(plain), 1), token=0, epoch=1, generation=1))
            disconnect_cases += 1
        finally:
            dll.TestDeviceDestroy(d)
    for (fault, stage, blocked) in [(1, 0, True), (2, 0, False)] + [(f, s, True) for s in (0, 1) for f in (3, 4, 5, 6, 7, 8, 10, 12, 13, 14, 15)] + [(11, 0, False)]:
        d = start(2)
        try:
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            dll.TestDisconnectFault(fault, stage)
            handled = U8(0)
            status = dll.Ap6256HostCipherDisconnect(d, 0, None, 0, c.byref(handled))
            check((status == 0) == (fault == 2 and stage == 0) and handled.value == 1)
            check(dll.TestKeyCount(dll.TestStore(d)) == 0 and bool(dll.TestBlocked(d) & 1) == blocked)
            check(dll.TestDisconnectSets() == (0 if fault == 1 else 1))
            check(transmit(d)[0] < 0)
            disconnect_cases += 1
        finally:
            dll.TestDeviceDestroy(d)
    for (accepted, native_status) in ((0, 0), (1, 4294967280)):
        d = start(2)
        try:
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            dll.TestDisconnectOutcome(accepted, native_status)
            handled = U8(0)
            check(dll.Ap6256HostCipherDisconnect(d, 0, None, 3, c.byref(handled)) < 0 and handled.value)
            check(dll.TestKeyCount(dll.TestStore(d)) == 0 and bool(dll.TestBlocked(d) & 1) == bool(native_status))
            check(dll.TestDisconnectSets() == 1)
            disconnect_cases += 1
        finally:
            dll.TestDeviceDestroy(d)
    for invalid in ('peer', 'reason', 'interface', 'irql', 'handled'):
        d = start(2)
        try:
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
            peer = bytearray(T.APMAC)
            if invalid == 'peer':
                peer[5] ^= 1
            if invalid == 'irql':
                dll.TestIrqlControl(2)
            handled = U8(0)
            before = dll.TestIoCalls()
            check(dll.Ap6256HostCipherDisconnect(d, 16 if invalid == 'interface' else 0, T.buf(bytes(peer)), 65536 if invalid == 'reason' else 3, None if invalid == 'handled' else c.byref(handled)) < 0)
            dll.TestIrqlControl(0)
            check(dll.TestIoCalls() == before and (not dll.TestBlocked(d)) and (dll.TestKeyCount(dll.TestStore(d)) == 1))
            check(handled.value == int(invalid in ('peer', 'reason')))
            disconnect_cases += 1
        finally:
            dll.TestDeviceDestroy(d)
    dll.TestControlReset()
    d = dll.TestDeviceCreate()
    try:
        handled = U8(99)
        check(dll.Ap6256HostCipherDisconnect(d, 0, None, 3, c.byref(handled)) == 0 and (not handled.value))
        check(dll.TestIoCalls() == 0)
        disconnect_cases += 1
    finally:
        dll.TestDeviceDestroy(d)
    d = start()
    try:
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
        for generation in (0, 2):
            matched = U8(99)
            calls = dll.TestIoCalls()
            check(dll.Ap6256HostCipherEndGeneration(d, 0, generation, c.byref(matched)) < 0 and (not matched.value))
            check(dll.TestIoCalls() == calls and dll.TestKeyCount(dll.TestStore(d)) == 1)
            check(dll.TestNativeAuthorized(0) and transmit(d)[0] == 0)
        check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0)
        check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 2, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0)
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
        matched = U8(99)
        calls = dll.TestIoCalls()
        check(dll.Ap6256HostCipherEndGeneration(d, 0, 1, c.byref(matched)) < 0 and (not matched.value))
        check(dll.TestIoCalls() == calls and dll.TestNativeAuthorized(0) and (transmit(d)[0] == 0))
        check(dll.Ap6256HostCipherEndGeneration(d, 0, 2, c.byref(matched)) == 0 and matched.value)
        check(dll.TestKeyCount(dll.TestStore(d)) == 0 and (not dll.TestNativeAuthorized(0)))
    finally:
        dll.TestDeviceDestroy(d)
    d = start()
    try:
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(key())) == 0)
        dll.TestFault(4)
        matched = U8(0)
        check(dll.Ap6256HostCipherEndGeneration(d, 0, 1, c.byref(matched)) < 0 and matched.value)
        retired(d)
    finally:
        dll.TestDeviceDestroy(d)
    dll.TestControlReset()
    d = dll.TestDeviceCreate()
    try:
        check(dll.Ap6256HostCipherQualify(d, 0) == 0 and dll.TestIoCalls() == 0)
        check(dll.Ap6256HostCipherQualify(d, 1) < 0)
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
    finally:
        dll.TestDeviceDestroy(d)
    for retirement in (12, 13):
        dll.TestControlReset()
        d = dll.TestDeviceCreate()
        try:
            dll.TestCaps(287)
            dll.TestFault(retirement)
            check(dll.Ap6256HostCipherQualify(d, 1) < 0)
            check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
            check(not dll.Ap6256RawGenerationCurrent(d, 0, 1, 1))
        finally:
            dll.TestDeviceDestroy(d)
    for firmware_state in (0, 1):
        dll.TestControlReset()
        d = dll.TestDeviceCreate()
        try:
            dll.TestCaps(287)
            dll.TestFirmwareState(d, firmware_state)
            check(dll.Ap6256HostCipherQualify(d, 1) < 0 and dll.TestIoCalls() == 0)
            check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
        finally:
            dll.TestDeviceDestroy(d)
    dll.TestControlReset()
    d = dll.TestDeviceCreate()
    try:
        dll.TestCaps(287)
        dll.TestHalted(d, 1)
        check(dll.Ap6256HostCipherQualify(d, 1) < 0 and dll.TestIoCalls() == 0)
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
    finally:
        dll.TestDeviceDestroy(d)
    d = start()
    try:
        store = dll.TestStore(d)
        check(not dll.TestBlocked(d))
        check(dll.TestNextGeneration(d) == 1)
        k = key()
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) == 0)
        owner = T.Owner()
        check(dll.Ap6256HostCipherStoreDefault(store, 0, 1, 0, c.byref(owner)))
        check((owner.generation, owner.slot, owner.epoch) == (1, 0, 1))
        check(dll.TestNativeEpoch(0, 0) == 1 and dll.TestNativeDefault(0, 0) == 0)
        check(dll.Ap6256HostCipherStoreAuthorized(store, 0, 1) and dll.TestNativeAuthorized(0))
        (status, wire) = transmit(d)
        check(status == 0 and wire[19] == 1)
        check(dll.Ap6256RawTxCurrent(d, 0, T.buf(wire), len(wire)))
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) == 0 and dll.TestNativeEpoch(0, 0) == 1)
        (status, second) = transmit(d)
        check(status == 0 and second != wire)
        for (cipher, keyid, pair, tx, rx, slot) in ((9, 3, False, True, True, 5), (9, 2, False, False, True, 4)):
            group = key(cipher, keyid, pair, tx, rx)
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(group)) == 0)
            check(dll.TestNativeEpoch(0, slot) != 0)
        alternate = key(keyid=1, material=bytes(range(32, 64)))
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(alternate)) == 0 and dll.TestNativeDefault(0, 0) == 1)
        check(not dll.Ap6256RawTxCurrent(d, 0, T.buf(wire), len(wire)))
        check(dll.Ap6256HostCipherSetDefault(d, 0, 0) == 0 and dll.TestNativeDefault(0, 0) == 0)
        check(dll.Ap6256RawTxCurrent(d, 0, T.buf(wire), len(wire)))
        bad = key()
        bad.peer[5] ^= 1
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(bad)) < 0 and (not dll.TestBlocked(d)))
        check(dll.Ap6256HostCipherSetDefault(d, 0, 2) < 0 and (not dll.TestBlocked(d)))
        check(dll.Ap6256HostCipherDeleteKey(d, 0, 9, 0, 1, T.buf(T.APMAC)) == 0)
        check(dll.TestNativeEpoch(0, 0) == 0 and (not dll.Ap6256RawTxCurrent(d, 0, T.buf(wire), len(wire))))
        check(dll.Ap6256HostCipherEnd(d, 0, 1) == 0)
        retired(d)
        check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestBlocked(d)))
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) == 0 and dll.TestNextGeneration(d) == 2)
        check(dll.Ap6256HostCipherBegin(d, 16, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
        dll.TestIrqlControl(2)
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
        dll.TestIrqlControl(0)
        dll.TestGenerationFrontier(d, 4294967295)
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0)
        retired(d)
    finally:
        dll.TestDeviceDestroy(d)
    d = start(mfp=2)
    try:
        store = dll.TestStore(d)
        k = key()
        initial = (Key * 2)(k, key(cipher=12, keyid=4, pair=False, tx=False))
        check(dll.Ap6256HostCipherAddKeys(d, 0, initial, 2) == 0)
        check(dll.Ap6256HostCipherStoreAuthorize(store, 0, 1, 1) == 0)
        (status, old) = transmit(d)
        check(status == 0)
        batch = (Key * 3)(key(material=bytes(range(32, 64))), key(keyid=3, pair=False), key(cipher=12, keyid=4, pair=False, tx=False))
        invalid = (Key * 2)(batch[0], key(keyid=3, pair=False, tx=True, rx=False))
        before = dll.TestIoCalls()
        check(dll.Ap6256HostCipherAddKeys(d, 0, invalid, 2) < 0)
        check(dll.TestIoCalls() == before and (not dll.TestBlocked(d)) and (dll.TestKeyCount(store) == 2))
        check(dll.Ap6256RawTxCurrent(d, 0, T.buf(old), len(old)))
        check(dll.Ap6256HostCipherAddKeys(d, 0, batch, 0) < 0 and dll.TestIoCalls() == before)
        check(dll.Ap6256HostCipherAddKeys(d, 0, batch, 3) == 0)
        check(dll.TestKeyCount(store) == 3 and (not dll.TestBlocked(d)))
        check(not dll.Ap6256RawTxCurrent(d, 0, T.buf(old), len(old)))
        check(dll.Ap6256HostCipherDeleteKeys(d, 0, batch, 3) == 0 and dll.TestKeyCount(store) == 0)
        check(not dll.Ap6256HostCipherStoreAuthorized(store, 0, 1))
    finally:
        dll.TestDeviceDestroy(d)
    for deleting in (False, True):
        d = start(mfp=2)
        try:
            batch = (Key * 3)(key(), key(keyid=3, pair=False), key(cipher=12, keyid=4, pair=False, tx=False))
            check(dll.Ap6256HostCipherAddKeys(d, 0, batch, 3) == 0)
            check(dll.Ap6256HostCipherStoreAuthorize(dll.TestStore(d), 0, 1, 1) == 0)
            dll.TestFaultAfter(3, 1)
            operation = dll.Ap6256HostCipherDeleteKeys if deleting else dll.Ap6256HostCipherAddKeys
            check(operation(d, 0, batch, 3) < 0)
            retired(d)
            check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestBlocked(d)))
        finally:
            dll.TestDeviceDestroy(d)
    d = start()
    try:
        store = dll.TestStore(d)
        inbound = key(tx=False)
        outbound = key(keyid=1, rx=False)
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(inbound)) == 0)
        check(not dll.TestNativeAuthorized(0) and (not dll.Ap6256HostCipherStoreAuthorized(store, 0, 1)))
        check(transmit(d)[0] < 0)
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(outbound)) == 0)
        check(dll.TestNativeAuthorized(0) and dll.Ap6256HostCipherStoreAuthorized(store, 0, 1))
        check(transmit(d)[0] == 0)
        check(dll.Ap6256HostCipherDeleteKey(d, 0, 9, 0, 1, T.buf(T.APMAC)) == 0)
        check(not dll.TestNativeAuthorized(0) and (not dll.Ap6256HostCipherStoreAuthorized(store, 0, 1)))
        group = key(keyid=3, pair=False)
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(group)) == 0 and (not dll.TestNativeAuthorized(0)))
        check(transmit(d)[0] < 0)
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(inbound)) == 0 and dll.TestNativeAuthorized(0))
        (status, old) = transmit(d)
        check(status == 0)
        outbound.material[0] ^= 1
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(outbound)) == 0 and dll.TestNativeAuthorized(0))
        check(not dll.Ap6256RawTxCurrent(d, 0, T.buf(old), len(old)))
        check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestNativeAuthorized(0)))
    finally:
        dll.TestDeviceDestroy(d)
    for fault in range(1, 14):
        d = start()
        try:
            k = key()
            dll.TestAuthFault(fault)
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) < 0)
            retired(d)
            if fault >= 12:
                before = dll.TestIoCalls()
                check(dll.Ap6256HostCipherEnd(d, 0, 0) < 0 and dll.TestIoCalls() == before and dll.TestBlocked(d))
            else:
                check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestNativeAuthorized(0)))
        finally:
            dll.TestDeviceDestroy(d)
    for akm in (1, 2, 5, 8, 12, 18):
        for mfp in (0, 1, 2):
            d = start()
            try:
                before = dll.TestIoCalls()
                supported = akm in (1, 2) or mfp == 2
                status = dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), akm, mfp)
                if not supported:
                    check(status < 0 and dll.TestIoCalls() == before and (not dll.TestBlocked(d)))
                    continue
                check(status == 0 and (not dll.TestBlocked(d)) and (dll.TestNextGeneration(d) == 2))
                expected = (826495048, 32, 2, 9, 9, 12 if mfp else 0, akm, mfp)
                check(tuple((dll.TestNativeProfile(0, i) for i in range(8))) == expected)
                (owner, profile) = (Session(), Profile())
                check(dll.Ap6256HostCipherReadProfile(d, 0, c.byref(owner), c.byref(profile)) == 0)
                check(owner.generation == 2 and bytes(owner.station) == T.STATION and (bytes(owner.bssid) == T.APMAC))
                check(tuple((getattr(profile, name) for (name, _) in Profile._fields_)) == expected)
                check(not dll.Ap6256HostCipherStoreAuthorized(dll.TestStore(d), 0, 2) and transmit(d)[0] < 0)
                k = key()
                before = dll.TestIoCalls()
                check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) < 0)
                check(dll.TestIoCalls() == before and dll.TestKeyCount(dll.TestStore(d)) == 0 and (not dll.TestBlocked(d)))
                check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 2, T.buf(T.STATION), T.buf(T.APMAC), akm, mfp) == 0)
                check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 2, T.buf(T.STATION), T.buf(T.APMAC), akm, mfp) < 0)
                check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) == 0)
                management = key(cipher=12, keyid=4, pair=False, tx=False)
                if mfp:
                    check(transmit(d)[0] < 0 and (not dll.TestNativeAuthorized(0)))
                    check(dll.Ap6256HostCipherStoreAuthorize(dll.TestStore(d), 0, 2, 1) < 0)
                    management.tx = True
                    management.rx = False
                    check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(management)) == 0 and (not dll.TestNativeAuthorized(0)))
                    management.tx = False
                    management.rx = True
                    check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(management)) == 0)
                    check(dll.TestNativeManagement(0, 1) == 6 and dll.TestNativeManagement(0, 0) == dll.TestNativeEpoch(0, 6))
                else:
                    before = dll.TestIoCalls()
                    check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(management)) < 0 and dll.TestIoCalls() == before)
                check(transmit(d)[0] == 0)
                if mfp:
                    check(dll.Ap6256HostCipherDeleteKey(d, 0, 12, 4, 0, None) == 0)
                    check(transmit(d)[0] < 0 and (not dll.TestNativeAuthorized(0)))
                check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestNativeProfile(0, 6)))
            finally:
                dll.TestDeviceDestroy(d)
    for (akm, mfp) in ((0, 0), (3, 2), (4, 2), (9, 2), (11, 2), (256, 2), (2, 3), (2, 4294967295)):
        d = start()
        try:
            before = dll.TestIoCalls()
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), akm, mfp) < 0)
            check(dll.TestIoCalls() == before and dll.TestNextGeneration(d) == 1 and (not dll.TestBlocked(d)))
        finally:
            dll.TestDeviceDestroy(d)
    for fault in range(1, 16):
        d = start()
        try:
            check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0)
            dll.TestProfileFault(fault)
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 2) < 0)
            retired(d)
            if fault in (12, 13):
                before = dll.TestIoCalls()
                check(dll.Ap6256HostCipherEnd(d, 0, 0) < 0 and dll.TestIoCalls() == before and dll.TestBlocked(d))
            else:
                check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestBlocked(d)))
        finally:
            dll.TestDeviceDestroy(d)
    for fault in range(3, 16):
        d = start()
        try:
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 2) == 0)
            (owner, profile) = (Session(), Profile())
            c.memset(c.byref(owner), 165, c.sizeof(owner))
            c.memset(c.byref(profile), 165, c.sizeof(profile))
            dll.TestProfileFault(fault)
            check(dll.Ap6256HostCipherReadProfile(d, 0, c.byref(owner), c.byref(profile)) < 0)
            check(bytes(owner) == bytes(c.sizeof(owner)) and bytes(profile) == bytes(c.sizeof(profile)))
        finally:
            dll.TestDeviceDestroy(d)
    dll.TestControlReset()
    d = dll.TestDeviceCreate()
    try:
        dll.TestCaps(287)
        check(dll.Ap6256HostCipherQualify(d, 1) == 0)
        check(dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) == 0)
        k = key()
        before = dll.TestIoCalls()
        check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) < 0 and dll.TestIoCalls() == before)
    finally:
        dll.TestDeviceDestroy(d)
    for bad in range(6):
        d = start()
        try:
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 2) == 0)
            (station, peer) = (bytearray(T.STATION), bytearray(T.APMAC))
            if bad == 0:
                station[5] ^= 1
            if bad == 1:
                peer[5] ^= 1
            (generation, akm, mfp) = (1 if bad == 2 else 2, 1 if bad == 3 else 2, 1 if bad == 4 else 2)
            if bad == 5:
                dll.TestChangeProfile(0, 6, 1)
            check(dll.Ap6256HostCipherConfirmAssociation(d, 0, generation, T.buf(bytes(station)), T.buf(bytes(peer)), akm, mfp) < 0)
            k = key()
            before = dll.TestIoCalls()
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) < 0 and dll.TestIoCalls() == before)
            check(dll.TestKeyCount(dll.TestStore(d)) == 0)
        finally:
            dll.TestDeviceDestroy(d)
    for fault in range(3, 16):
        d = start()
        try:
            check(dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 2) == 0)
            dll.TestProfileFault(fault)
            check(dll.Ap6256HostCipherConfirmAssociation(d, 0, 2, T.buf(T.STATION), T.buf(T.APMAC), 2, 2) < 0)
            k = key()
            before = dll.TestIoCalls()
            check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) < 0 and dll.TestIoCalls() == before)
        finally:
            dll.TestDeviceDestroy(d)
    for operation in ('add', 'delete', 'default', 'begin', 'end'):
        for fault in range(1, 13):
            if operation == 'end' and fault in (9, 12):
                continue
            d = start()
            try:
                k = key()
                check(dll.Ap6256HostCipherAddKey(d, 0, c.byref(k)) == 0)
                if operation == 'begin':
                    check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0)
                dll.TestFault(fault)
                if operation == 'add':
                    k.material[0] ^= 1
                    status = dll.Ap6256HostCipherAddKey(d, 0, c.byref(k))
                elif operation == 'delete':
                    status = dll.Ap6256HostCipherDeleteKey(d, 0, 9, 0, 1, T.buf(T.APMAC))
                elif operation == 'default':
                    status = dll.Ap6256HostCipherSetDefault(d, 0, 0)
                elif operation == 'begin':
                    status = dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC))
                else:
                    status = dll.Ap6256HostCipherEnd(d, 0, 0)
                assert status < 0, (operation, fault, status, checks)
                check(status < 0)
                retired(d)
                if fault == 12:
                    before = dll.TestIoCalls()
                    check(dll.Ap6256HostCipherEnd(d, 0, 0) < 0 and dll.TestIoCalls() == before and dll.TestBlocked(d))
                else:
                    check(dll.Ap6256HostCipherEnd(d, 0, 0) == 0 and (not dll.TestBlocked(d)))
            finally:
                dll.TestDeviceDestroy(d)
    check(dll.TestPoolCount() == 0)
    names = ['src/common/host_cipher_control.c', 'src/common/host_cipher_control.h', 'src/common/host_cipher_disconnect.h', 'src/common/host_cipher_keys.c', 'src/common/host_cipher_keys.h', 'src/common/host_cipher_store.c', 'src/common/host_cipher_store.h', 'src/common/host_cipher_transport.c', 'src/common/host_cipher_path.c', 'src/common/host_cipher_wire.c', 'src/common/host_cipher_frame.c', 'src/common/host_crypto_cng.c', 'src/common/host_fips.c', 'src/common/host_fips_wire.c', 'src/common/datapath.c', 'src/common/ap6256.h', 'tests/host-cipher-store-fixture.c', 'tests/test-host-cipher-control.py', 'tests/test-host-cipher-transport.py']
    report = dict(checks=checks, disconnect_cases=disconnect_cases, fresh_start_cases=fresh_start_cases, sources={n: hashlib.sha256((AP / n).read_bytes()).hexdigest() for n in names}, dll_sha256=hashlib.sha256((out / 'control.dll').read_bytes()).hexdigest(), board_verified=False, association_qualified=False, boundary=__doc__)
    write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS: %d production host control/key/CNG/admission checks with declared native reply fixtures' % checks)
if __name__ == '__main__':
    main()
