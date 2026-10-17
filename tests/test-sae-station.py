# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Exercise the production station SAE binding with real WDI TLVs.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sae_test', ROOT / 'tests/test-sae.py')
sae = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sae)
BINDING = r'''
#define AP6256_ENABLE_WDI
#define AP6256_SAE_QUEUE_DEPTH 8u
#define AP6256_CMDQ_DEPTH 16u
#define STATUS_CANCELLED ((NTSTATUS)0xc0000120)
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xc000023c)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define AP6256_STATION_PORT 0
#define AP6256_GROUP_PORT 2
#define AP6256_DISCOVERY_PORT 1
typedef int KIRQL;
struct Request {
    UCHAR MiniportReserved[16];
    struct { struct { ULONG Oid; } METHOD_INFORMATION; } DATA;
    NTSTATUS Status;ULONG Completed;
};
typedef Request* AP6256_REQUEST;
struct Task { BOOLEAN Active;WDI_MESSAGE_HEADER Header;PVOID RequestId;LONGLONG DeadlineMs; };
struct Wifi {
    Device* Ctx;TLV_CONTEXT TlvContext;Task ConnectTask;
    AP6256_SAE Sae;AP6256_SAE_EVENT SaeQueue[AP6256_SAE_QUEUE_DEPTH];
    AP6256_FT_STATE Ft;AP6256_FT_EVENT* FtEvents[2];ULONG FtHead,FtTail;BOOLEAN FtEventsLost;AP6256_FT_OWNER FtLostOwner;
    ULONG SaeHead,SaeTail;LONG SaeGeneration,SaeLostGeneration;UINT32 HostCipherGeneration;
    UCHAR SaeSsid[32];ULONG SaeSsidLength;BOOLEAN SaeFirmwareReleased;
    UINT32 SaeFirmwareGeneration,SaeFirmwareCounter,SaeEventGeneration;UCHAR SaeFirmwarePeer[6];BOOLEAN SaeNeedsAbort;
    struct {ULONG Length;} AssocFailure;
    BOOLEAN AssocComebackPending;
    LONGLONG SaeCachedDeadlineMs;
    LONG ConnectGeneration,Stopping,HardwareAvailable;BOOLEAN ConnectDeparting;
    ULONG ConnectCandidateIndex,ConnectCandidateCount;AP6256_CONNECT_PARAMS ConnectCandidates[2];
    UCHAR ConnectBssid[6];BOOLEAN ConnectBssidValid,ConnectionActive;UINT32 ConnectChannel;
    int CommandLock,ConnectLock,SaeTimer,CommandWorkItem;
    ULONG CommandHead,CommandTail;AP6256_REQUEST CommandPending[AP6256_CMDQ_DEPTH];LONG CommandSaeGeneration[AP6256_CMDQ_DEPTH];
    int CommandDraining;
};
typedef Wifi* PAP6256_WIFI;
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->NetAdapter;}
static ULONG kicks,timer_delay,failed_joins,joins,disconnects;
static NTSTATUS delivery_status;
static LONGLONG now_ms;
static LONGLONG Ap6256InterruptTimeMs() {return now_ms;}
#define KeAcquireSpinLock(l,i) (assert(!*(l)),++*(l),*(i)=0)
#define KeReleaseSpinLock(l,i) (assert(*(l)==1),--*(l),(void)(i))
#define Ap6256LockAcquire(l) (assert(!*(l)),++*(l))
#define Ap6256LockRelease(l) (assert(*(l)==1),--*(l))
#define AP6256_TIMER_STOP(t,w) ((void)(t),(void)(w),timer_delay=0)
#define AP6256_TIMER_START(t,ms) ((void)(t),timer_delay=(ms),assert(timer_delay<=30000))
#define AP6256_CMDQ_KICK(w) ((void)(w),++kicks)
#define AP6256_CMDQ_OK(w) ((w)->CommandWorkItem!=0)
#undef InterlockedCompareExchange
#undef InterlockedIncrement
#define InterlockedCompareExchange(p,a,b) ((void)(a),(void)(b),*(p))
#define InterlockedIncrement(p) (++*(p))
static bool spin_held;
struct Notice {ULONG type;UINT32 transaction;PVOID request;std::vector<UCHAR> frame;};
static std::vector<Notice> notices;
static NTSTATUS Ap6256SendGeneratedIndication(Wifi* w,UINT16 id,const WDI_MESSAGE_HEADER* h,
    UINT32 transaction,PVOID request,const UCHAR* bytes,ULONG length) {
    assert(id==WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED && h->TransactionId==77);
    assert(w->ConnectLock==1 && !w->CommandLock && !spin_held);
    if(delivery_status)return delivery_status;
    WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED_PARAMETERS p={};
    assert(ParseWdiIndicationSaeAuthParamsNeededFromIhv(length,bytes,&w->TlvContext,&p)==0);
    assert(memcmp(p.BssId.Address,peer,6)==0);
    Notice v={(ULONG)p.SAEIndicationType,transaction,request,{}};
    if(p.Optional.SAECommitFrame_IsPresent)v.frame.assign(p.SAECommitFrame.pElements,p.SAECommitFrame.pElements+p.SAECommitFrame.ElementCount);
    if(p.Optional.SAEConfirmFrame_IsPresent)v.frame.assign(p.SAEConfirmFrame.pElements,p.SAEConfirmFrame.pElements+p.SAEConfirmFrame.ElementCount);
    notices.push_back(v);CleanupParsedWdiIndicationSaeAuthParamsNeededFromIhv(&p);return 0;
}
static void Ap6256CompleteRequest(Wifi* w,Request* r,NTSTATUS status) {
    assert(!w->ConnectLock && !w->CommandLock && !r->Completed);r->Status=status;++r->Completed;
}
static void Ap6256NetStationLinkEvent(Device* d,BOOLEAN up,BOOLEAN terminal,const UCHAR* p) {
    assert(!up&&terminal&&d->NetAdapter->ConnectLock==1&&memcmp(p,peer,6)==0);++failed_joins;
}
static NTSTATUS Ap6256WifiConnect(Device* d,AP6256_CONNECT_PARAMS* p) {
    assert(d->NetAdapter->ConnectLock==1 && p->Security==Ap6256SecuritySaeHost);
    assert(d->NetAdapter->SaeGeneration==d->NetAdapter->ConnectGeneration);++joins;
    if(d->FirmwarePrivateSae)return Ap6256SaePrivateArm(d,p->SaeFirmwareGeneration,
        p->Bssid,p->SaeTimeoutMs,p->PmkidValid?p->Pmkid:nullptr,p->SaeCachedH2e);
    return 0;
}


static NTSTATUS Ap6256FtEnd(Device*,AP6256_FT_STATE* state,BOOLEAN associated) {
    assert(!associated && state->Phase==Ap6256FtIdle);return 0;
}
static NTSTATUS Ap6256OweEnd(Device* d,BOOLEAN) {
    assert(!d->FirmwareOweGeneration);return 0;
}
static NTSTATUS Ap6256WifiConnectFt(Device*,AP6256_CONNECT_PARAMS*,AP6256_CONNECT_FT_SETUP*) {
    assert(false);return STATUS_DEVICE_BUSY;
}
static NTSTATUS Ap6256MboPrepareJoin(Wifi*,const AP6256_CONNECT_PARAMS*) {return 0;}
static BOOLEAN Ap6256IndicateAssociation(Wifi*,const WDI_MESSAGE_HEADER*,PVOID,BOOLEAN) {return FALSE;}
static NTSTATUS Ap6256WifiDisconnect(Device* d) {assert(d->NetAdapter->ConnectLock==1);++disconnects;return 0;}


static NTSTATUS Ap6256HostCipherReadProfile(Device*,UINT32,AP6256_HC_STORE_SESSION*,AP6256_HC_PROFILE_CONTROL*) {
    assert(false);return STATUS_DEVICE_NOT_READY;
}
static NTSTATUS Ap6256HostCipherEnd(Device*,UINT32,BOOLEAN) {assert(false);return STATUS_DEVICE_NOT_READY;}
'''
TEST = r'''
static Wifi w;static Device d;
static void setup(bool private_transport=false) {
    memset(&w,0,sizeof(w));memset(&d,0,sizeof(d));w.Ctx=&d;d.NetAdapter=&w;
    memcpy(d.MacAddress,local,6);d.FirmwareExternalAuth=d.FirmwareMfpSupported=TRUE;
    w.HardwareAvailable=TRUE;w.CommandWorkItem=1;w.TlvContext.PeerVersion=WDI_VERSION_1_1_10;
    w.ConnectTask.Active=TRUE;w.ConnectTask.Header.TransactionId=77;w.ConnectTask.RequestId=(void*)88;
    w.ConnectTask.DeadlineMs=30000;w.ConnectCandidateCount=1;
    auto& p=w.ConnectCandidates[0];memcpy(p.Bssid,peer,6);p.BssidValid=TRUE;p.Channel=36;
    memcpy(p.Ssid,"net",3);p.SsidLength=3;p.Security=Ap6256SecuritySaeHost;p.Mfp=Ap6256MfpRequired;
    now_ms=0;firmware_status=delivery_status=0;failed_joins=joins=kicks=timer_delay=disconnects=0;notices.clear();writes.clear();
    if(private_transport) {
        d=private_device();d.NetAdapter=&w;memcpy(d.MacAddress,local,6);
    }
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(joins==1 && w.SaeGeneration==w.ConnectGeneration && w.Sae.State==Ap6256SaeIdle);
}
static void pump() {
    drain_sae(&w);
}
static void start() {
    UCHAR b[60]={1};memcpy(b+2,peer,6);b[8]=3;memcpy(b+12,"net",3);
    Ap6256NetSaeEvent(&d,AP6256_CYW_EXT_AUTH_REQ,0,peer,b,60);
    memset(b,0,sizeof(b));CHECK(w.SaeHead-w.SaeTail==1);pump();
    CHECK(w.Sae.State==Ap6256SaeCommitParameters && notices.size()==1);
    CHECK(notices.back().type==0 && notices.back().transaction==0 && notices.back().request==(void*)88);
}
static void issue(WDI_SET_SAE_AUTH_PARAMS_COMMAND* p,LONG stamped=0,BOOLEAN success=TRUE,USHORT port=0) {
    UCHAR* bytes=nullptr;ULONG n=0;
    CHECK(GenerateWdiSetSaeAuthParamsToIhv(p,0,&w.TlvContext,&n,&bytes)==0);
    Request r={};r.DATA.METHOD_INFORMATION.Oid=WDI_SET_SAE_AUTH_PARAMS;
    CHECK(Ap6256QueueCommand(&w,&r)==0 && w.CommandPending[w.CommandTail%AP6256_CMDQ_DEPTH]==&r);
    LONG SaeGeneration=w.CommandSaeGeneration[w.CommandTail++%AP6256_CMDQ_DEPTH];if(stamped)SaeGeneration=stamped;
    WDI_MESSAGE_HEADER header={};header.PortId=port;
    dispatch(&w,&r,&header,bytes,n,WDI_SET_SAE_AUTH_PARAMS,SaeGeneration);
    FreeGenerated(bytes);CHECK(r.Completed==1);CHECK(success ? r.Status==0 : r.Status<0);
}
static void commit_request(WDI_SET_SAE_AUTH_PARAMS_COMMAND* parameters) {
    auto& p=*parameters;memcpy(p.BssId.Address,peer,6);
    p.SAERequestType=WDI_SAE_REQUEST_TYPE_COMMIT_PARAMS;p.Optional.SAECommitParams_IsPresent=TRUE;
    p.SAECommitParams.FiniteCyclicGroup=19;
    p.SAECommitParams.Optional.Scalar_IsPresent=TRUE;p.SAECommitParams.Scalar.pElements=scalar;p.SAECommitParams.Scalar.ElementCount=32;
    p.SAECommitParams.Optional.Element_IsPresent=TRUE;p.SAECommitParams.Element.pElements=element;p.SAECommitParams.Element.ElementCount=64;
}
static void rx(USHORT seq,ULONG payload) {
    auto f=frame(seq,0,payload);std::vector<UCHAR> b(16+f.size());memcpy(b.data()+16,f.data(),f.size());
    Ap6256NetSaeEvent(&d,AP6256_CYW_EXT_AUTH_RX,0,peer,b.data(),(ULONG)b.size());pump();
}
static void cached() {
    setup();w.ConnectCandidates[0].PmkidValid=TRUE;memset(w.ConnectCandidates[0].Pmkid,0x5a,16);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(w.Sae.State==Ap6256SaeIdle && w.SaeCachedDeadlineMs==2000 && timer_delay==2000 && notices.empty());
}
static void private_start() {
    CHECK(w.SaeFirmwareGeneration==42 && w.SaeFirmwareGeneration!=(UINT32)w.SaeGeneration);
    CHECK(w.SaeEventGeneration==42);
    CHECK(fw_word(20)==1 && timer_delay==50 && notices.empty());
    Ap6256StationSaeTimer(&w);pump();CHECK(notices.empty() && w.Sae.State==Ap6256SaeIdle);
    fw_put32(20,2);now_ms=50;Ap6256StationSaeTimer(&w);pump();
    CHECK(w.Sae.State==Ap6256SaeCommitParameters && notices.size()==1);
}
static void private_rx(USHORT seq,ULONG payload,UINT32 generation=0) {
    auto f=frame(seq,0,payload);std::vector<UCHAR> b(12+f.size(),0);
    UINT32 magic=0x31415341,gen=generation?generation:w.SaeFirmwareGeneration;UINT16 n=(UINT16)f.size();
    memcpy(b.data(),&magic,4);memcpy(b.data()+4,&gen,4);memcpy(b.data()+8,&n,2);
    memcpy(b.data()+12,f.data(),f.size());
    if(gen==w.SaeFirmwareGeneration) {fw_put32(28,fw_word(28)+1);if(seq==2)fw_private[34]|=2;}
    Ap6256NetSaePrivateEvent(&d,peer,b.data(),(ULONG)b.size());
    memset(b.data(),0,b.size());pump();
}
static void private_station() {
    setup(true);CHECK(Ap6256HostSaeAvailable(&w) && !d.FirmwareExternalAuth);private_start();
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};commit_request(&p);issue(&p);
    CHECK(writes.back().name=="ap_sae" && writes.back().bytes[6]==2 && w.Sae.State==Ap6256SaeCommitResponse);
    private_rx(1,98,41);CHECK(w.Sae.State==Ap6256SaeCommitResponse && fw_word(28)==0);
    private_rx(1,98);CHECK(w.Sae.State==Ap6256SaeCommitDecision && notices.back().type==1);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND c={};memcpy(c.BssId.Address,peer,6);c.SAERequestType=WDI_SAE_REQUEST_TYPE_CONFIRM_PARAMS;
    c.Optional.SAEConfirmParams_IsPresent=TRUE;c.SAEConfirmParams.SendConfirm=1;
    c.SAEConfirmParams.Confirm.pElements=confirm;c.SAEConfirmParams.Confirm.ElementCount=32;
    issue(&c);private_rx(2,34);CHECK(w.Sae.State==Ap6256SaeStatus && notices.back().type==2);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND ok={};memcpy(ok.BssId.Address,peer,6);ok.SAERequestType=WDI_SAE_REQUEST_TYPE_SUCCESS;
    ok.Optional.SAEStatus_IsPresent=TRUE;ok.SAEStatus=WDI_SAE_STATUS_SUCCESS;issue(&ok);
    CHECK(w.Sae.State==Ap6256SaeAccepted && w.SaeFirmwareReleased && fw_word(20)==3);
    CHECK(writes.back().bytes[6]==3 && !timer_delay);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationSaeComplete(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(!w.SaeFirmwareGeneration && fw_word(20)==0 && fw_word(16)==42 && writes.back().bytes[6]==5);
    CHECK(w.SaeEventGeneration==42);
    auto count=writes.size();Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);Ap6256LockRelease(&w.ConnectLock);
    CHECK(writes.size()==count && !disconnects);
    CHECK(w.SaeEventGeneration==42);

    setup(true);private_start();issue(&p);now_ms=1050;Ap6256StationSaeTimer(&w);pump();
    CHECK(w.Sae.Transmits==2 && writes.back().name=="ap_sae");
    private_rx(1,98);issue(&c);now_ms=2050;Ap6256StationSaeTimer(&w);pump();
    CHECK(w.Sae.State==Ap6256SaeConfirmParameters && notices.back().type==4);
    issue(&c);private_rx(2,34);firmware_status=STATUS_UNSUCCESSFUL;issue(&ok,0,FALSE);
    CHECK(!w.SaeFirmwareReleased && w.SaeNeedsAbort && w.SaeFirmwareGeneration==42 && !w.SaeGeneration);
    CHECK(!w.SaeEventGeneration);
    count=joins;Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==STATUS_DEVICE_BUSY);Ap6256LockRelease(&w.ConnectLock);
    CHECK(joins==count && w.SaeNeedsAbort);
    firmware_status=0;Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(!w.SaeNeedsAbort && w.SaeFirmwareGeneration==43 && joins==count+1);
    fw_put32(20,2);now_ms=2100;Ap6256StationSaeTimer(&w);pump();issue(&p);
    auto before=w.SaeHead;private_rx(1,98,42);CHECK(w.SaeHead==before && w.Sae.State==Ap6256SaeCommitResponse);
    AP6256_SAE_EVENT stale={};stale.Generation=w.SaeGeneration;stale.FirmwareGeneration=42;
    count=notices.size();Ap6256StationSaeEvent(&w,&stale);CHECK(notices.size()==count && !w.SaeNeedsAbort);

    setup(true);w.ConnectCandidates[0].PmkidValid=TRUE;memset(w.ConnectCandidates[0].Pmkid,0x5a,16);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(fw_word(20)==4 && w.SaeFirmwareGeneration==43 && timer_delay==2000);
    now_ms=2000;Ap6256StationSaeTimer(&w);pump();CHECK(failed_joins==1 && !w.SaeFirmwareGeneration && fw_word(20)==0);
    CHECK(Ap6256StationSaeFallback(&w));
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(w.SaeFirmwareGeneration==44 && !w.SaeCachedDeadlineMs && fw_word(20)==1);
    CHECK(w.SaeEventGeneration==44);

    setup(true);auto& cachedCandidate=w.ConnectCandidates[0];
    cachedCandidate.PmkidValid=TRUE;cachedCandidate.SaeCachedH2e=TRUE;
    memset(cachedCandidate.Pmkid,0x5a,16);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(fw_word(20)==4 && fw_word(36)==3 && writes.back().bytes[22]==2);
    now_ms=2000;Ap6256StationSaeTimer(&w);pump();CHECK(failed_joins==1 && !w.SaeFirmwareGeneration);
    CHECK(Ap6256StationSaeFallback(&w) && !cachedCandidate.SaeCachedH2e);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(fw_word(20)==1 && fw_word(36)==0 && writes.back().bytes[22]==0);

    setup(true);private_start();issue(&p);count=notices.size();
    UCHAR native[60]={1};memcpy(native+2,peer,6);native[8]=3;memcpy(native+12,"net",3);
    before=w.SaeHead;Ap6256NetSaeEvent(&d,187,0,peer,native,60);CHECK(w.SaeHead==before && notices.size()==count);
    setup(true);firmware_status=STATUS_UNSUCCESSFUL;
    Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);Ap6256LockRelease(&w.ConnectLock);
    CHECK(w.SaeNeedsAbort && w.SaeFirmwareGeneration==42 && fw_word(20)==1 && w.Sae.State==Ap6256SaeIdle);
    firmware_status=0;Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);Ap6256LockRelease(&w.ConnectLock);
    CHECK(!w.SaeNeedsAbort && !w.SaeFirmwareGeneration && fw_word(20)==0);
    fw_put32(16,MAXULONG);
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationStartNext(&w)==STATUS_INTEGER_OVERFLOW);Ap6256LockRelease(&w.ConnectLock);
}
int main() {
    setup();CHECK(Ap6256HostSaeAvailable(&w));w.TlvContext.PeerVersion=WDI_VERSION_1_1_9;
    CHECK(!Ap6256HostSaeAvailable(&w));w.TlvContext.PeerVersion=WDI_VERSION_1_1_10;
    d.FirmwareExternalAuth=FALSE;CHECK(!Ap6256HostSaeAvailable(&w));d.FirmwareExternalAuth=TRUE;
    d.FirmwareMfpSupported=FALSE;CHECK(!Ap6256HostSaeAvailable(&w));d.FirmwareMfpSupported=TRUE;
    start();WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};commit_request(&p);
    issue(&p,w.SaeGeneration+1,FALSE);issue(&p,0,FALSE,1);
    CHECK(w.Sae.State==Ap6256SaeCommitParameters && writes.empty());
    issue(&p);
    CHECK(w.Sae.State==Ap6256SaeCommitResponse && writes.back().name=="mgmt_frame");
    rx(1,98);CHECK(w.Sae.State==Ap6256SaeCommitDecision && notices.back().type==1);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND c={};memcpy(c.BssId.Address,peer,6);c.SAERequestType=WDI_SAE_REQUEST_TYPE_CONFIRM_PARAMS;
    c.Optional.SAEConfirmParams_IsPresent=TRUE;c.SAEConfirmParams.SendConfirm=1;c.SAEConfirmParams.Confirm.pElements=confirm;c.SAEConfirmParams.Confirm.ElementCount=32;
    issue(&c);CHECK(w.Sae.State==Ap6256SaeConfirmResponse);
    rx(2,34);CHECK(w.Sae.State==Ap6256SaeStatus && notices.back().type==2);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND ok={};memcpy(ok.BssId.Address,peer,6);ok.SAERequestType=WDI_SAE_REQUEST_TYPE_SUCCESS;
    ok.Optional.SAEStatus_IsPresent=TRUE;ok.SAEStatus=WDI_SAE_STATUS_SUCCESS;issue(&ok);
    CHECK(w.Sae.State==Ap6256SaeAccepted && w.SaeFirmwareReleased && writes.back().name=="auth_status");
    auto released_writes=writes.size();
    Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);Ap6256LockRelease(&w.ConnectLock);
    CHECK(writes.size()==released_writes && !w.SaeGeneration);
    CHECK(writes.back().bytes[0]==4 && !failed_joins && !timer_delay && !w.ConnectionActive);
    setup();start();commit_request(&p);issue(&p);now_ms=1000;Ap6256StationSaeTimer(&w);pump();
    CHECK(w.Sae.Transmits==2 && writes.back().name=="mgmt_frame");
    rx(1,98);issue(&c);now_ms=2000;Ap6256StationSaeTimer(&w);pump();
    CHECK(w.Sae.State==Ap6256SaeConfirmParameters && notices.back().type==4);
    issue(&c);rx(2,34);firmware_status=STATUS_UNSUCCESSFUL;

    UCHAR* bytes=nullptr;ULONG n=0;CHECK(GenerateWdiSetSaeAuthParamsToIhv(&ok,0,&w.TlvContext,&n,&bytes)==0);
    Request r={};WDI_MESSAGE_HEADER h={};
    dispatch(&w,&r,&h,bytes,n,WDI_SET_SAE_AUTH_PARAMS,w.SaeGeneration);FreeGenerated(bytes);
    CHECK(r.Completed==1 && r.Status<0 && !w.SaeFirmwareReleased && w.SaeGeneration==0 && failed_joins==1);
    CHECK(writes.back().name=="auth_status" && writes.back().bytes[0]==3);
    setup();start();commit_request(&p);issue(&p);auto stale=w.SaeQueue[0];
    Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);++w.ConnectGeneration;
    Ap6256StationSaeArm(&w,&w.ConnectCandidates[0]);Ap6256LockRelease(&w.ConnectLock);
    auto count=writes.size();Ap6256StationSaeEvent(&w,&stale);CHECK(writes.size()==count && w.Sae.State==Ap6256SaeIdle);
    now_ms=30001;UCHAR expired[60]={1};memcpy(expired+2,peer,6);expired[8]=3;memcpy(expired+12,"net",3);
    Ap6256NetSaeEvent(&d,AP6256_CYW_EXT_AUTH_REQ,0,peer,expired,60);pump();
    CHECK(failed_joins==1 && !w.SaeGeneration);
    setup();start();delivery_status=STATUS_UNSUCCESSFUL;commit_request(&p);

    issue(&p);rx(1,98);CHECK(failed_joins==1 && !w.SaeGeneration);
    setup();for(ULONG i=0;i<AP6256_SAE_QUEUE_DEPTH+1;++i) {
        UCHAR b[60]={1};Ap6256NetSaeEvent(&d,AP6256_CYW_EXT_AUTH_REQ,0,peer,b,60);
    }
    CHECK(w.SaeHead-w.SaeTail==AP6256_SAE_QUEUE_DEPTH && w.SaeLostGeneration==w.SaeGeneration);
    pump();CHECK(failed_joins==1 && !w.SaeGeneration && w.SaeTail==w.SaeHead);
    setup();w.SaeLostGeneration=w.SaeGeneration+1;pump();CHECK(!failed_joins && w.SaeGeneration);
    w.Stopping=TRUE;auto head=w.SaeHead;Ap6256StationSaeTimer(&w);CHECK(w.SaeHead==head);
    cached();auto cached_generation=w.ConnectGeneration;
    now_ms=1999;Ap6256StationSaeTimer(&w);pump();CHECK(!failed_joins && timer_delay==1);
    now_ms=2000;Ap6256StationSaeTimer(&w);pump();
    CHECK(failed_joins==1 && disconnects==1 && !w.SaeGeneration && notices.empty());
    Ap6256LockAcquire(&w.ConnectLock);CHECK(Ap6256StationSaeFallback(&w));
    CHECK(!Ap6256StationSaeFallback(&w) && !w.ConnectCandidates[0].PmkidValid);
    CHECK(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    CHECK(w.ConnectCandidateIndex==0 && w.ConnectGeneration!=cached_generation && !w.SaeCachedDeadlineMs && !timer_delay);
    start();CHECK(w.Sae.State==Ap6256SaeCommitParameters);
    cached();w.SaeFirmwareReleased=TRUE;
    Ap6256LockAcquire(&w.ConnectLock);Ap6256StationSaeCancel(&w);Ap6256LockRelease(&w.ConnectLock);
    CHECK(!disconnects && !w.SaeCachedDeadlineMs && !timer_delay);
    cached();UCHAR req[60]={1};memcpy(req+2,peer,6);req[8]=3;memcpy(req+12,"net",3);
    Ap6256NetSaeEvent(&d,AP6256_CYW_EXT_AUTH_REQ,0,other,req,60);pump();
    CHECK(failed_joins==1 && notices.empty());
    private_station();
    printf("PASS: %u station SAE assertions\n",assertions);
}
'''

def function(source, name):
    matches = list(re.finditer('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source, re.M))
    if not matches:
        raise ValueError(name)
    return matches[-1][0]

def main():
    global ROOT
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--model', choices=('wdi', 'wificx'), default='wdi')
    args = parser.parse_args()
    ROOT = args.source_root.resolve()
    sae.ROOT = ROOT
    net = read_source_text(ROOT / 'src/common/netadapter.c')
    frontend = (ROOT / 'src' / args.model / 'netadapter.c').read_text(encoding='utf-8-sig')
    binding = BINDING
    test = TEST
    if args.model == 'wificx':
        binding = binding.replace('#define AP6256_ENABLE_WDI', '#define AP6256_ENABLE_WIFICX')
        binding = binding.replace('    UCHAR MiniportReserved[16];\n    struct { struct { ULONG Oid; } METHOD_INFORMATION; } DATA;', '    UINT16 MessageId;PUCHAR Buffer;UINT InputLength,OutputLength;ULONG BytesWritten;')
        first = binding.index('static void Ap6256CompleteRequest(')
        last = binding.index('static void Ap6256NetStationLinkEvent(', first)
        binding = binding[:first] + r'''
typedef Request* WIFIREQUEST;
typedef Device* WDFDEVICE;
static UINT16 WifiRequestGetMessageId(WIFIREQUEST r) {return r->MessageId;}
static PVOID WifiRequestGetInOutBuffer(WIFIREQUEST r,UINT* inputSize,UINT* outputSize) {
    *inputSize=r->InputLength;*outputSize=r->OutputLength;return r->Buffer;
}
static void WifiRequestComplete(WIFIREQUEST r,NTSTATUS status,ULONG bytes) {
    assert(!r->Completed);r->Status=status;++r->Completed;r->BytesWritten=bytes;
    assert(bytes==(NT_SUCCESS(status)?sizeof(WDI_MESSAGE_HEADER):0));
}
''' + function(frontend, 'Ap6256WifiCxExternalPort') + function(frontend, 'Ap6256CompleteRequest') + binding[last:]
        test = test.replace('r.DATA.METHOD_INFORMATION.Oid=WDI_SET_SAE_AUTH_PARAMS;', 'r.MessageId=WDI_SET_SAE_AUTH_PARAMS;')
        test = test.replace('real WDI SET dispatcher', 'WiFiCx opaque request completion and shared SET dispatcher')
    pre = re.sub('struct Device \\{[\\s\\S]*?\\};', lambda m: 'struct Wifi;' + m[0][:-2] + 'Wifi* NetAdapter;UCHAR MacAddress[6]; UINT32 FirmwareOweGeneration; };', sae.PRE, count=1)
    commands = ''.join((line + '\n' for line in read_source_text(ROOT / 'src/common/sdpcm.h').splitlines() if re.match('#define BRCMF_C_', line)))
    source = sae.contract_preamble() + commands + pre
    if args.model == 'wificx':
        source = source.replace('struct Device {', 'struct Device { UINT16 WifiStationPortId=0,WifiDirectPortId=1,WifiGroupPortId=2;')
    for file in ('sae.h', 'sae.c', 'sae_fw.h', 'sae_fw.c', 'sae_wdi.h', 'sae_wdi.c'):
        text = read_source_text(ROOT / 'src' / file)
        text = re.sub('^#(?:pragma once|include).*\\n', '', text, flags=re.M)
        text = re.sub('typedef struct _MLO_LINK_INFO \\{[\\s\\S]*?\\} MLO_LINK_INFO, \\*PMLO_LINK_INFO;', '', text)
        source += text.replace('= {0};', '= {};') + '\n'
    source += sae.TEST[:sae.TEST.index('int main()')]
    source += '#define AP6256_POOL_TAG 1u\n#define ExFreePoolWithTag(p,t) (assert(false), (void)(p), (void)(t))\n'
    for name in ('AP6256_SECURITY', 'AP6256_MFP', 'AP6256_CONNECT_PARAMS'):
        source += re.search('typedef (?:enum|struct) _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', read_source_text(ROOT / 'src/common/wifi_ops.h'))[0] + '\n'
    ft_header = read_source_text(ROOT / 'src/common/ft.h')
    source += ft_header[ft_header.index('#define AP6256_FT_MDE_LENGTH'):ft_header.index('_IRQL_requires_max_')] + '\n'
    ft_fw_header = read_source_text(ROOT / 'src/common/ft_fw.h')
    source += re.search('^#define AP6256_FT_FW_AUTH_MAX [^\\n]+', ft_fw_header, re.M)[0] + '\n'
    source += re.search('typedef struct _AP6256_FT_EVENT \\{[\\s\\S]*?\\} AP6256_FT_EVENT;', ft_fw_header)[0] + '\n'
    for (file, name) in (('host_cipher_store.h', 'AP6256_HC_STORE_SESSION'), ('host_cipher_control.h', 'AP6256_HC_PROFILE_CONTROL')):
        header = read_source_text(ROOT / 'src/common' / file)
        source += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + ';', header)[0] + '\n'
    source += re.search('typedef struct _AP6256_SAE_EVENT \\{[\\s\\S]*?\\} AP6256_SAE_EVENT;', net)[0] + '\n' + binding
    source += read_source_text(ROOT / 'src/common/sae_station.inc') + '\n'
    for name in ('Ap6256RequestGetMessageId', 'Ap6256QueueCommand', 'Ap6256HostSaeAvailable', 'Ap6256StationStartNext'):
        source += function(frontend if name == 'Ap6256RequestGetMessageId' else net, name) + '\n'
    worker = function(read_source_text(ROOT / 'src/common/station_auth.c'), 'Ap6256DrainCommandQueue')
    worker = worker.replace('->Auth.', '->')
    source += r'''
static BOOLEAN Ap6256ModelTakeCommandEvent(Wifi*,PVOID*,BOOLEAN*) {return FALSE;}
static void Ap6256ModelProcessCommandEvent(Wifi*,PVOID,BOOLEAN) {assert(false);}
static void Ap6256StationFtEvent(Wifi*,const AP6256_FT_EVENT*,const AP6256_FT_OWNER*) {assert(false);}
static void Ap6256ProcessCommand(Wifi*,Request*,LONG) {assert(false);}
#undef InterlockedExchange
#define InterlockedExchange(p,v) ((*(p))=(v))
''' + worker + '\nstatic void drain_sae(Wifi* wifi) {Ap6256DrainCommandQueue(wifi); }\n'
    dispatch = re.search('    case WDI_SET_SAE_AUTH_PARAMS:[\\s\\S]*?        break;', net)[0]
    source += r'''static void dispatch(Wifi* Wifi,Request* Request,PWDI_MESSAGE_HEADER header,const UCHAR* tlv,ULONG tlvLength,UINT16 id,LONG SaeGeneration) {switch(id) {
''' + dispatch + '\ndefault:assert(false);}}\n' + test
    source = '#pragma warning(disable:4505)\n' + source
    out = (args.output or output_dir('sae-station')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    write_text(cpp, source, encoding='utf-8')
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    cmd = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    cmd += ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    cmd += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(cmd, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
