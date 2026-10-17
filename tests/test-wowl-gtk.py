# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"""Production negotiated RSN ADD/REMOVE/GET with Microsoft's actual TLV codec."""
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import runpy, subprocess
from driver_sources import _functions, read_source_text
ROOT = Path(__file__).resolve().parents[1]
BASE = runpy.run_path(str(ROOT / 'tests/test-wowl-add-gate.py'))
MOCK = r'''
#include <vector>
#define AP6256_WOWL_KEY_ROTATION 0x4000u
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003e)
struct Wifi {
 Device* Ctx; int ConnectLock=0; TLV_CONTEXT TlvContext={};
 UINT32 PortOperationMode=AP6256_WDI_OPMODE_STA;
 BOOLEAN ArpOffloadValid[8]={};UINT32 ArpOffloadIds[8]={};
 WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER ArpOffloads[8]={};
 WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER NsOffloads[5]={};ULONG NsOffloadCount=0;
 BOOLEAN GtkOffloadValid=FALSE;UINT32 GtkOffloadId=0;AP6256_GTK_OFFLOAD GtkOffload={};
 WDI_CIPHER_ALGORITHM MulticastCipher=WDI_CIPHER_ALGO_CCMP,MulticastMgmtCipher=WDI_CIPHER_ALGO_BIP;
 WDI_AUTH_ALGORITHM AuthAlgorithm=WDI_AUTH_ALGO_RSNA_PSK;
 struct {BOOLEAN MobilityDomainValid=FALSE;} Ft;
};
typedef Wifi* PAP6256_WIFI;typedef void* AP6256_REQUEST;
static void Ap6256LockAcquire(int*){}static void Ap6256LockRelease(int*){}
static NTSTATUS completion;static AP6256_GTK_STATE state={};
static unsigned sets,removes,reads,arpCalls;static unsigned failSet;static bool failNs,failRead;
static AP6256_GTK_OFFLOAD configured={};
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s){return (NTSTATUS)s;}
static VOID Ap6256CompleteRequest(Wifi*,AP6256_REQUEST,NTSTATUS s){completion=s;}
static NTSTATUS Ap6256WifiAddGtkOffload(Device*,const AP6256_GTK_OFFLOAD* c){
 ++sets;configured=*c;state.OffloadId=c->OffloadId;state.DescriptorVersion=c->DescriptorVersion;
 state.MicKind=c->MicKind;state.Pmf=c->Pmf;memcpy(state.Kck,c->Kck,16);memcpy(state.Kek,c->Kek,16);
 for(unsigned i=0;i<8;i++)state.Replay[i]=(UCHAR)(c->ReplayCounter>>(56-i*8));
 return sets==failSet?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;
}
static NTSTATUS Ap6256WifiRemoveGtkOffload(Device*){++removes;return STATUS_SUCCESS;}
static NTSTATUS Ap6256WifiReadGtkOffload(Device*,AP6256_GTK_STATE* s){++reads;*s=state;return failRead?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;}
static NTSTATUS Ap6256AddArpOffload(Wifi* w,const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* r){
 ++arpCalls;w->ArpOffloadValid[0]=TRUE;w->ArpOffloadIds[0]=r->ProtocolOffloadId;w->ArpOffloads[0]=*r;return STATUS_SUCCESS;}
static NTSTATUS Ap6256AddNsOffload(Wifi*,const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER*){return failNs?STATUS_UNSUCCESSFUL:STATUS_SUCCESS;}
static NTSTATUS Ap6256RemoveArpOffloadId(Wifi* w,UINT32){w->ArpOffloadValid[0]=FALSE;return STATUS_SUCCESS;}
static NTSTATUS Ap6256RemoveNsOffloadId(Wifi*,UINT32){return STATUS_SUCCESS;}
static NTSTATUS Ap6256BcdcSetIovar(Device*,const char*,const void*,ULONG){return STATUS_SUCCESS;}
'''
TEST = r'''
static UCHAR kck[16],kek[16];
static void add(Wifi& w, bool mixed=false,ULONG keylen=16,UINT32 id=0) {
 WDI_SET_ADD_PM_PROTOCOL_OFFLOAD_PARAMETERS_PARAMETERS req={};
 req.Optional.DOT11RSNREKeyOffload_IsPresent=TRUE;
 auto& key=req.DOT11RSNREKeyOffload.RsnKeyInfo;key.ProtocolOffloadId=id;key.ReplayCounter=1;
 key.KCK_CONTENT.pElements=kck;key.KCK_CONTENT.ElementCount=keylen;
 key.KEK_CONTENT.pElements=kek;key.KEK_CONTENT.ElementCount=16;
 if(mixed){req.Optional.ipv4ARPOffload_IsPresent=TRUE;req.ipv4ARPOffload.ProtocolOffloadId=17;
 req.Optional.ipv6ARPOffload_IsPresent=TRUE;req.ipv6ARPOffload.ProtocolOffloadId=18;}
 UCHAR* bytes=nullptr;ULONG n=0;assert(!GenerateWdiSetAddPmProtocolOffloadToIhv(&req,0,&w.TlvContext,&n,&bytes));
 Ap6256HandleAddPmProtocolOffload(&w,nullptr,bytes,n);FreeGenerated(bytes);
}
static void remove(Wifi& w,UINT32 id){
 WDI_SET_REMOVE_PM_PROTOCOL_OFFLOAD_PARAMETERS req={};req.RemovePMOffload=id;
 UCHAR* b=nullptr;ULONG n=0;assert(!GenerateWdiSetRemovePmProtocolOffloadToIhv(&req,0,&w.TlvContext,&n,&b));
 Ap6256HandleRemovePmProtocolOffload(&w,nullptr,b,n);FreeGenerated(b);
}
static NTSTATUS get(Wifi& w,UINT32 id,bool verify=true,unsigned count=2){
 WDI_GET_PM_PROTOCOL_OFFLOAD_PARAMETERS req={};req.GetPMOffload=id;
 UCHAR *b=nullptr,*out=nullptr;ULONG n=0,size=0;
 assert(!GenerateWdiGetPmProtocolOffloadToIhv(&req,0,&w.TlvContext,&n,&b));
 NTSTATUS s=Ap6256GeneratePmOffload(&w,b,n,&out,&size);FreeGenerated(b);
 if(NT_SUCCESS(s)&&verify){
  WDI_GET_PM_PROTOCOL_OFFLOAD_RESULTS decoded={};assert(!ParseWdiGetPmProtocolOffloadFromIhv(size,out,&w.TlvContext,&decoded));
  assert(decoded.Optional.DOT11RSNREKeyOffload_IsPresent);
  auto& keys=decoded.DOT11RSNREKeyOffload;
  assert(keys.RsnKeyInfo.ProtocolOffloadId==id && keys.RsnKeyInfo.ReplayCounter==0x102030405060708ULL);
  assert(!memcmp(keys.RsnKeyInfo.KCK_CONTENT.pElements,kck,16)&&!memcmp(keys.RsnKeyInfo.KEK_CONTENT.pElements,kek,16));
  assert(keys.Optional.CipherKey_IsPresent&&keys.CipherKey.ElementCount==count);
  if(count==2){
  assert(keys.CipherKey.pElements[0].CipherKeyType==WDI_CIPHER_KEY_TYPE_GROUP_KEY&&keys.CipherKey.pElements[0].CCMPKey.pElements[0]==0x71);
  assert(keys.CipherKey.pElements[1].CipherKeyType==WDI_CIPHER_KEY_TYPE_IGTK&&keys.CipherKey.pElements[1].BIPKey.pElements[0]==0x72);
  assert(keys.CipherKey.pElements[0].ReceiveSequenceCount.ReceiveSequenceCount[5]==0x73);
  } else for(unsigned i=0;i<count;i++)assert(keys.CipherKey.pElements[i].CipherKeyType==(i<4?WDI_CIPHER_KEY_TYPE_GROUP_KEY:WDI_CIPHER_KEY_TYPE_IGTK));
  CleanupParsedWdiGetPmProtocolOffloadFromIhv(&decoded);
 }
 if(out)FreeGenerated(out);return s;
}
int main(){
 Device d;d.FirmwareGtkOffloadSupported=TRUE;d.FirmwareNdOffloadSupported=TRUE;
 d.WowlCapabilities=AP6256_WOWL_ARP_OFFLOAD|AP6256_WOWL_KEY_ROTATION;
 Wifi w;w.Ctx=&d;w.TlvContext.PeerVersion=WDI_VERSION_LATEST;
 for(unsigned i=0;i<16;i++){kck[i]=(UCHAR)(i+1);kek[i]=(UCHAR)(i+33);}
 add(w);assert(!completion&&w.GtkOffloadValid&&w.GtkOffloadId==0&&configured.DescriptorVersion==2&&configured.MicKind==1&&configured.Pmf==1);
 unsigned firstSets=sets;add(w,false,16,99);assert(completion==STATUS_INSUFFICIENT_RESOURCES&&sets==firstSets);
 state.GtkId=1;state.GtkValid=1;state.Gtk[0]=0x71;state.GtkRsc[5]=0x73;
 state.Keys[1].Id=1;state.Keys[1].Valid=1;state.Keys[1].Key[0]=0x71;state.Keys[1].Rsc[5]=0x73;
 state.Keys[5].Id=5;state.Keys[5].Valid=1;state.Keys[5].Key[0]=0x72;
 state.IgtkId=5;state.IgtkValid=1;state.Igtk[0]=0x72;
 for(unsigned i=0;i<8;i++)state.Replay[i]=(UCHAR)(i+1);
 assert(get(w,0)==STATUS_SUCCESS);assert(reads==1);
 for(unsigned i=0;i<6;i++){state.Keys[i].Id=i;state.Keys[i].Valid=1;}
 assert(get(w,0,true,6)==STATUS_SUCCESS);
 for(unsigned i=0;i<6;i++)state.Keys[i].Valid=i==1||i==5;
 failRead=true;assert(get(w,0,false)==STATUS_UNSUCCESSFUL);failRead=false;
 state.OffloadId=99;assert(get(w,0,false)==STATUS_DATA_ERROR);state.OffloadId=0;
 remove(w,0);assert(!completion&&!w.GtkOffloadValid&&removes==1);
 for(auto auth:{WDI_AUTH_ALGO_WPA3_SAE,WDI_AUTH_ALGO_OWE,WDI_AUTH_ALGO_RSNA,WDI_AUTH_ALGO_WPA3_ENT}){
  w.AuthAlgorithm=auth;w.Ft.MobilityDomainValid=auth==WDI_AUTH_ALGO_RSNA;
  add(w);assert(!completion);
  assert(configured.DescriptorVersion==((auth==WDI_AUTH_ALGO_RSNA||auth==WDI_AUTH_ALGO_WPA3_ENT)?3u:0u));
  assert(configured.MicKind==(auth==WDI_AUTH_ALGO_OWE?2u:3u));remove(w,0);
 }
 unsigned calls=sets;add(w,false,15);assert(completion==STATUS_INVALID_PARAMETER&&sets==calls);
 w.MulticastMgmtCipher=WDI_CIPHER_ALGO_NONE;add(w);assert(completion==STATUS_NOT_SUPPORTED&&sets==calls);
 w.MulticastMgmtCipher=WDI_CIPHER_ALGO_BIP;
 w.AuthAlgorithm=WDI_AUTH_ALGO_80211_OPEN;add(w);assert(completion==STATUS_NOT_SUPPORTED&&sets==calls);
 w.AuthAlgorithm=WDI_AUTH_ALGO_RSNA_PSK;w.Ft.MobilityDomainValid=FALSE;
 failNs=true;add(w,true);assert(completion==STATUS_UNSUCCESSFUL&&!w.GtkOffloadValid&&!w.ArpOffloadValid[0]);
 failNs=false;add(w);assert(!completion);state.Replay[7]=9;
 unsigned before=sets;failSet=sets+1;add(w);
 assert(completion==STATUS_UNSUCCESSFUL&&sets==before+2&&configured.ReplayCounter==9&&w.GtkOffloadValid);
 failSet=0;remove(w,0);assert(!completion);assert(get(w,0,false)==STATUS_INVALID_PARAMETER);
 puts("PASS: production RSN negotiated profiles, opaque ID zero, live GET codec, failure rollback and removal");
}
'''

def main():
    source = read_source_text(ROOT / 'src/common/netadapter.c')
    f = _functions(source)
    h = read_source_text(ROOT / 'src/common/wifi_ops.h')
    a = h.index('typedef struct _AP6256_GTK_OFFLOAD')
    b = h.index('} AP6256_GTK_OFFLOAD, *PAP6256_GTK_OFFLOAD;', a) + len('} AP6256_GTK_OFFLOAD, *PAP6256_GTK_OFFLOAD;')
    sh = read_source_text(ROOT / 'src/common/wowl.h')
    sh = sh[sh.index('typedef struct _AP6256_GROUP_KEY_STATE'):sh.index('C_ASSERT')]
    code = BASE['PRE'] + h[a:b] + sh + MOCK + '\n' + ''.join((f[n] for n in ['Ap6256BuildGtkOffload', 'Ap6256HandleAddPmProtocolOffload', 'Ap6256HandleRemovePmProtocolOffload']))
    code += _functions(read_source_text(ROOT / 'src/common/pm_query.inc'))['Ap6256GeneratePmOffload'] + TEST
    out = output_dir('wowl-gtk')
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, code, encoding='utf-8')
    (VC, INC, LIB) = (BASE['VC'], BASE['INC'], BASE['LIB'])
    cmd = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(VC / 'include')]
    cmd += ['/I' + str(INC / n) for n in ['ucrt', 'shared', 'um', 'um/wlan/2.0']]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64'), 'advapi32.lib', str(LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
