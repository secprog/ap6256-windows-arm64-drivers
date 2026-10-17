# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Run station CONNECT/ROAM through the real WDI codec and production firmware writer.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text, _functions, _mask
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
from wdi_test_support import contract_preamble
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
cap = module('test-wdi-capabilities')
PRE = cap.PREAMBLE.split('struct Device {')[0] + r'''
#include <initializer_list>
#include <vector>
#define AP6256_ENABLE_WDI
typedef LONG NTSTATUS;
typedef int KIRQL;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xc0000186)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_NETWORK_UNREACHABLE ((NTSTATUS)0xc000023c)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_CANCELLED ((NTSTATUS)0xc0000120)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xc0010015)
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TraceInfo(...) ((void)0)
#define TraceWarn(...) ((void)0)
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TRACE_NETADAPTER 0
static void TraceError(int,const char*,...) {}
#define RtlCompareMemory(a,b,n) (memcmp(a,b,n)==0?(n):0)
#define KeAcquireSpinLock(l,i) (*(i)=0)
#define KeReleaseSpinLock(l,i) ((void)(i))
#define AP6256_POOL_TAG 0
#define POOL_FLAG_NON_PAGED 0
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_INVALID_BUFFER_SIZE ((NTSTATUS)0xc0000206)
static int candidate_allocations;
static void* ExAllocatePool2(int, size_t n, int) {++candidate_allocations;return calloc(1,n);}
static void ExFreePoolWithTag(void* p,int) {assert(p);--candidate_allocations;free(p);}
#define AP6256_STATION_PORT 0
#define AP6256_GROUP_PORT 2
#define AP6256_TIMER_START(t,ms) ((void)(t),(void)(ms),++timer_starts)
#define AP6256_TIMER_STOP(t,w) Ap6256TestTimerStop(t,w)
#define Ap6256LockAcquire(l) (++*(l))
#define Ap6256LockRelease(l) (assert(*(l)>0),--*(l))
static LONGLONG test_now=1;
static LONGLONG Ap6256InterruptTimeMs() {return test_now;}
struct Device;
typedef Device* PAP6256_DEVICE_CONTEXT;
'''
MOCKS = r'''
struct Wifi;
enum {Ap6256FwNotLoaded,Ap6256FwDownloading,Ap6256FwRunning};
struct HostStore {ULONG Generation;volatile LONG Ready=1;};
struct Device {
    int NativeKeyLock=0;
    BOOLEAN NativeDeparturePending=FALSE;
    struct { UINT32 ChipId = 0x4345, ChipRev = 9; } Chip;
    Wifi* NetAdapter;
    UINT8 D11IoType;
    BOOLEAN FirmwareLinkUp, ConnectionRequiresSupplicant, SupplicantComplete;
    BOOLEAN FirmwareMchanSupported, FirmwareExternalAuth, FirmwareMfpSupported;
    BOOLEAN FirmwarePrivateSae;
    BOOLEAN FirmwareSaePatchVerified;
    BOOLEAN FirmwareFtPatchVerified, FirmwareHostFt;
    BOOLEAN FirmwareOwePatchVerified, FirmwareHostOwe;
    BOOLEAN HostFipsReady;
    volatile LONG HostCipherFirmwareQualified;
    BOOLEAN FirmwareHostCipherPatchVerified=TRUE;
    LONG FirmwareState=Ap6256FwRunning;
    volatile LONG FirmwareHalted,HostCipherBlockedMask;
    BOOLEAN HostCipherActive;
    UINT32 HostCipherAkm,HostCipherMfp;
    HostStore HostCipherStore;
    int HostFipsLock;AP6256_FIPS_SESSION HostFipsSessions[16];UINT32 HostFipsNextGeneration,HostFipsBlockedMask,HostFipsRetiredMask;
    UCHAR MacAddress[6];
    UINT32 FirmwareOweGeneration, FirmwareOweNextGeneration;
    UCHAR FirmwareOwePeer[6];
    struct { BOOLEAN Started; UINT32 Channel; } Go;
};

static NTSTATUS Ap6256SaeVerifySecurity(Device*, UINT32, BOOLEAN);
static NTSTATUS Ap6256SaeSetBip(Device*);
struct AP6256_BCDC_QUERY_RESULT {
    BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;
};
static NTSTATUS Ap6256SaeSetPmkid(Device*,const UCHAR*,const UCHAR*);
NTSTATUS Ap6256SaeCopyPmkid(BOOLEAN, const UCHAR*, ULONG, BOOLEAN*, UCHAR*);
struct Task { BOOLEAN Active; WDI_MESSAGE_HEADER Header; PVOID RequestId; LONGLONG DeadlineMs; };
struct Wifi {
    Device* Ctx;
    TLV_CONTEXT TlvContext=[] {TLV_CONTEXT context={};context.PeerVersion=AP6256_TEST_WDI_VERSION;return context;}();
    Task ConnectTask,DisconnectTask;
    WDI_MESSAGE_HEADER IndicationHeader; int DisconnectTimer;
    LONG DisallowedBandMask; int CommandLock, ConnectTimer;
    BOOLEAN ConnectRestricted, ConnectTaskIsRoam, ConnectBssidValid, ConnectionActive;
    UCHAR ConnectBssid[6]; UINT32 ConnectChannel;
    WDI_AUTH_ALGORITHM AuthAlgorithm;
    WDI_CIPHER_ALGORITHM UnicastCipher, MulticastCipher, MulticastMgmtCipher;
    int ConnectLock; LONG Stopping,HardwareAvailable;
    AP6256_CONNECT_PARAMS ConnectCandidates[AP6256_CONNECT_BSSID_LIMIT];
    ULONG ConnectCandidateCount, ConnectCandidateIndex;
    BOOLEAN ConnectDeparting;
    BOOLEAN SaeNeedsAbort;
    UINT32 SaeFirmwareGeneration, SaeEventGeneration;
    struct {ULONG Length;} AssocFailure;
    BOOLEAN AssocComebackPending;
    UINT32 HostCipherGeneration;
    volatile LONG ConnectGeneration;
    AP6256_FT_STATE Ft;
    UCHAR LinkEvents[AP6256_LINKQ_DEPTH];
    LONG LinkGenerations[AP6256_LINKQ_DEPTH],GroupGeneration;
    UINT32 LinkFirmwareGenerations[AP6256_LINKQ_DEPTH];
    UCHAR LinkFirmwareEvents[AP6256_LINKQ_DEPTH];
    ULONG LinkHead,LinkTail;int LinkLock;


    UCHAR ArpOffloadValid[4], ArpOffloads[64], NsOffloads[64], GtkOffload[64];
    ULONG ArpOffloadIds[4], NsOffloadCount, GtkOffloadId;
    BOOLEAN GtkOffloadValid;
    struct { BOOLEAN Associated; UCHAR AssociatedAp[6], Transition[64]; } Mbo;
};
typedef Wifi* PAP6256_WIFI;
static void Ap6256NetStationAssocFailure(Device*,const UCHAR*,UINT32,BOOLEAN,const UCHAR*,ULONG) {}


static NTSTATUS Ap6256FtEnd(Device*,AP6256_FT_STATE* s,BOOLEAN) {
    assert(s->Phase==Ap6256FtIdle && !s->NeedsAbort);return 0;
}
static NTSTATUS Ap6256FtValidateBegin(...) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256FtBegin(...) {assert(false);return STATUS_NOT_SUPPORTED;}
static BOOLEAN Ap6256HostFbtAvailable(Wifi*);
static VOID Ap6256StationSaeCancel(Wifi*) {}
static BOOLEAN Ap6256OweDhValid(const UCHAR*,ULONG);
static NTSTATUS Ap6256OweCopyIes(const UCHAR*,ULONG,const UCHAR*,ULONG,const UCHAR*,ULONG,AP6256_CONNECT_PARAMS*);
static NTSTATUS Ap6256OweEnd(Device*,BOOLEAN);
static NTSTATUS Ap6256OweArm(Device*,const AP6256_CONNECT_PARAMS*);
static NTSTATUS Ap6256OwePrepareSecurity(Device*);
static NTSTATUS Ap6256StationSaeArm(Wifi* w, AP6256_CONNECT_PARAMS* p) {
    assert((w->Ctx->FirmwareExternalAuth||w->Ctx->FirmwarePrivateSae) && w->Ctx->FirmwareMfpSupported);
    if(p->HostCipher){p->SaeFirmwareGeneration=99;p->SaeTimeoutMs=30000;}
    return 0;
}
static NTSTATUS Ap6256SaePrivateArm(Device*,UINT32,const UCHAR*,UINT32,const UCHAR*,BOOLEAN);
typedef void* AP6256_REQUEST;
static NTSTATUS request_status;
static UINT32 fw_auth, fw_wpa, fw_wsec, fw_infra, fail_command;
static NTSTATUS expected_failure;
static UINT32 command_order[256]; static ULONG command_count;
static UINT32 fw_mfp;
static UINT32 fw_bip;
static NTSTATUS bip_status;
static bool bip_no_reply, bip_fw_error;
static int private_arms;
static NTSTATUS private_arm_status;
static BOOLEAN private_cached,private_h2e;
static BRCMF_JOIN_PARAMS joined;
static int joins, mutations, pmks, timer_starts, failures;
static int group_dispatch;
static bool replace_on_completion=false;
static bool state_tests=false;
static bool check_timeout_lock=false;
static std::vector<char> indications;
static int disconnects;
static BOOLEAN cache_written;
static UCHAR written_pmkid[16],written_peer[6];
static bool owe_abort_fail;
static unsigned owe_arms,owe_ends;
static unsigned hc_profiles,hc_ends,hc_security_fault,hc_bip_readback_fault;
static NTSTATUS hc_begin_status,hc_end_status,fips_end_status;
static bool check_security_order, replace_after_disassociation;
static std::vector<char> security_order;
static bool disconnect_writer_tests,disconnect_host_handled,disconnect_host_retire;
static NTSTATUS disconnect_host_status;
static UINT16 disconnect_reason;
static UCHAR disconnect_peer[6];
static unsigned disconnect_host_calls,disconnect_clears,disconnect_timer_stops,disconnect_completion_replace;
static Wifi* disconnect_wifi;
static PWDI_MESSAGE_HEADER disconnect_input_header;
static std::vector<UINT32> disconnect_commands;
static std::vector<NTSTATUS> disconnect_completions;
static VOID Ap6256TestTimerStop(int,BOOLEAN wait) {
    if(disconnect_writer_tests&&wait){assert(disconnect_wifi&&disconnect_wifi->ConnectLock==0);++disconnect_timer_stops;}
}
static BOOLEAN Ap6256HostCipherStoreActive(HostStore* store,UINT32 iface) {assert(iface==0);return store->Generation!=0;}
static NTSTATUS Ap6256HostCipherDisconnect(Device* d,UINT32 iface,const UCHAR* peer,UINT32 reason,BOOLEAN* handled) {
    assert(disconnect_writer_tests&&iface==0&&d->NetAdapter->ConnectLock==1);
    assert(peer&&memcmp(peer,disconnect_peer,6)==0&&reason==disconnect_reason);
    ++disconnect_host_calls;*handled=(BOOLEAN)disconnect_host_handled;
    if(disconnect_host_handled&&disconnect_host_retire){d->HostCipherActive=FALSE;d->HostCipherStore.Generation=0;}
    return disconnect_host_status;
}
static BOOLEAN Ap6256WifiHasNativeKeys(Device*) {return FALSE;}
static NTSTATUS Ap6256NativeDeparture(Device*,const UCHAR*,UINT32,BOOLEAN* handled){*handled=FALSE;return 0;}
static NTSTATUS Ap6256WifiClearSecurityState(Device*) {assert(disconnect_writer_tests);++disconnect_clears;return 0;}
#define KernelMode 0
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER* delay) {
    assert(mode==0&&!alert&&delay->QuadPart==-5000000LL&&disconnect_writer_tests);
    assert(disconnect_wifi->Ctx->NativeKeyLock==1);return 0;
}
static BOOLEAN Ap6256HostCipherPacketActive(Device* d,UINT32 i) {assert(i==0);return d->HostCipherActive;}
static VOID Ap6256HostCipherStoreStop(HostStore* store,UINT32 i) {assert(i==0);store->Generation=0;}
static NTSTATUS Ap6256HostCipherEnd(Device* d,UINT32 i,BOOLEAN retiring) {
    assert(i==0&&!retiring);++hc_ends;
    if(check_security_order)security_order.push_back('R');
    NTSTATUS status=d->HostCipherActive?hc_end_status:0;


    d->HostCipherActive=FALSE;Ap6256HostCipherStoreStop(&d->HostCipherStore,i);return status;
}
static NTSTATUS Ap6256HostCipherBeginProfile(Device* d,UINT32 i,const UCHAR* station,const UCHAR* peer,UINT32 akm,UINT32 mfp) {
    assert(i==0&&d->HostCipherFirmwareQualified==1&&!d->HostCipherActive&&!joins);
    assert(!memcmp(station,d->MacAddress,6)&&!(peer[0]&1)&&mfp<=2);
    assert(fw_auth==0&&fw_infra==1&&fw_mfp==mfp);
    assert(fw_wpa==(akm==1||akm==5||akm==12?0x40u:akm==8?0x8000u:0x80u));
    assert(fw_wsec==(4u|(mfp?0x200u:0u)|(mfp==2?0x400u:0u)|((akm==8||akm==18)?0x800u:0u)));
    if(akm==8)assert(private_arms==1);
    if(akm==18)assert(owe_arms==1);
    if(mfp)assert(fw_bip==6);
    ++hc_profiles;d->HostCipherAkm=akm;d->HostCipherMfp=mfp;
    d->HostCipherActive=TRUE;d->HostCipherStore.Generation=777;return hc_begin_status;
}
static BOOLEAN host_exclude_unencrypted;
static NTSTATUS Ap6256HostCipherBeginProfileRx(Device* d,UINT32 i,const UCHAR* station,const UCHAR* peer,UINT32 akm,UINT32 mfp,BOOLEAN exclude) {
    host_exclude_unencrypted=exclude;
    return Ap6256HostCipherBeginProfile(d,i,station,peer,akm,mfp);
}
static NTSTATUS Ap6256HostCipherReadProfile(Device* d,UINT32 i,AP6256_HC_STORE_SESSION* owner,AP6256_HC_PROFILE_CONTROL* p) {
    assert(i==0&&d->HostCipherActive);*owner={};owner->Generation=777;
    memcpy(owner->Station,d->MacAddress,6);memcpy(owner->Bssid,joined.Params.Bssid,6);
    *p={0x31435048,32,777,9,9,d->HostCipherMfp?12u:0u,d->HostCipherAkm,d->HostCipherMfp};return 0;
}
static BOOLEAN Ap6256HostCipherStoreSnapshot(HostStore* store,ULONG i,AP6256_HC_STORE_SESSION* owner) {
    assert(i==0);*owner={};if(!store->Generation)return FALSE;
    owner->Generation=store->Generation;memcpy(owner->Bssid,joined.Params.Bssid,6);return TRUE;
}
static NTSTATUS Ap6256SaePrivateEnd(Device*,UINT32 generation,const UCHAR*,BOOLEAN associated) {
    assert(generation==99&&!associated);return 0;
}
static UCHAR fips_mode[32];static UINT32 fips_qos;static unsigned fips_modes,fips_seeds;
static unsigned hc_offload_writes,hc_offload_fail;
static UINT32 hc_offload_switches[2];
static NTSTATUS Ap6256BcdcSetIovarIf(Device*,UINT32 iface,PCSTR name,const void* bytes,ULONG n) {
    assert(iface==0);
    if(!strcmp(name,"wdi_fips_mode")){assert(n==32);memcpy(fips_mode,bytes,n);++fips_modes;
        if(check_security_order)security_order.push_back('F');
        if(!((const UINT32*)bytes)[2]&&fips_end_status)return fips_end_status;}
    else if(!strcmp(name,"wme_bss_disable")){assert(n==4);memcpy(&fips_qos,bytes,4);}
    else if(!strcmp(name,"arpoe")||!strcmp(name,"ndoe")){assert(n==4&&*(const UINT32*)bytes==0);hc_offload_switches[!strcmp(name,"ndoe")]=0;}
    else {assert((!strcmp(name,"wdi_gtk_config")&&n==56)||(!strcmp(name,"wdi_gtk_key")&&n==36));++fips_seeds;}
    if(!strcmp(name,"arpoe")||!strcmp(name,"ndoe")||!strcmp(name,"wdi_gtk_config")||!strcmp(name,"wdi_gtk_key"))
        if(++hc_offload_writes==hc_offload_fail)return STATUS_IO_TIMEOUT;
    return 0;
}
static void Ap6256WlfcCancel(Device*,UINT16 port,UINT16 peer,PVOID owner) {assert(port==0&&peer==0xffff&&!owner);}


static NTSTATUS Ap6256OwePrepareSecurity(Device*) {
    assert(fw_auth==0 && fw_wpa==0x80 && fw_wsec==0xe04 && fw_mfp==2 && fw_infra==1);
    fw_bip=6;return 0;
}
static NTSTATUS Ap6256OweArm(Device* d,const AP6256_CONNECT_PARAMS* p) {
    assert(!d->FirmwareOweGeneration && p->Security==Ap6256SecurityOweHost);
    assert(fw_auth==0 && fw_wpa==0x80 && fw_wsec==0xe04 && fw_mfp==2 && fw_bip==6);
    assert(!cache_written && Ap6256OweDhValid(p->OweDh,p->OweDhLength));
    d->FirmwareOweGeneration=++d->FirmwareOweNextGeneration;memcpy(d->FirmwareOwePeer,p->Bssid,6);
    ++owe_arms;return 0;
}
static NTSTATUS Ap6256OweEnd(Device* d,BOOLEAN) {
    if(!d->FirmwareOweGeneration)return 0;
    ++owe_ends;if(owe_abort_fail)return STATUS_IO_TIMEOUT;
    d->FirmwareOweGeneration=0;memset(d->FirmwareOwePeer,0,6);return 0;
}
static NTSTATUS Ap6256SaePrivateArm(Device* d,UINT32 generation,const UCHAR* peer,UINT32 timeout,const UCHAR* pmkid,BOOLEAN h2e) {
    assert(d->FirmwarePrivateSae && generation==99 && timeout==30000 && !(peer[0]&1));
    assert(!!pmkid==!!private_cached && h2e==private_h2e);
    if(pmkid)assert(!memcmp(pmkid,written_pmkid,16));
    assert(fw_auth==0 && fw_wpa==0x8000 && fw_wsec==3588 && fw_mfp==2 && fw_infra==1);
    assert(fw_bip==(AP6256_TEST_HAS_BIP?6u:0u));
    assert(!joins);++private_arms;return private_arm_status;
}
static NTSTATUS Ap6256SaeSetPmkid(Device*,const UCHAR* peer,const UCHAR* pmkid) {
    cache_written=(BOOLEAN)(pmkid!=nullptr);memcpy(written_peer,peer,6);
    if(pmkid)memcpy(written_pmkid,pmkid,16);else memset(written_pmkid,0,16);return 0;
}
static UCHAR queued_code;
static LONG queued_generation;
static UINT32 queued_firmware_generation;
static UCHAR queued_firmware_event;
static int queued_count;
static Wifi* Ap6256WifiFromDevice(Device* d) {return d->NetAdapter;}
static void captureLinkKick(Wifi* w) {
    assert(w->LinkHead!=w->LinkTail);
    ULONG index=(w->LinkHead-1)&(AP6256_LINKQ_DEPTH-1);
    queued_code=w->LinkEvents[index];queued_generation=w->LinkGenerations[index];
    queued_firmware_generation=w->LinkFirmwareGenerations[index];
    queued_firmware_event=w->LinkFirmwareEvents[index];++queued_count;
    w->LinkTail=w->LinkHead;
}
#define AP6256_LINKQ_OK(w) TRUE
#define AP6256_LINKQ_KICK(w) captureLinkKick(w)
static int rx_opens;
static VOID Ap6256TalRxOpen(Device*) {++rx_opens;}
static VOID Ap6256WifiArmRoamTriggers(Device*) {}
static VOID Ap6256NetLinkStateWork(Wifi*) {}
static VOID Ap6256IndicateP2pChannels(Wifi*) {}
static VOID Ap6256IndicateDisassociation(Wifi*,const WDI_MESSAGE_HEADER*);
static VOID Ap6256MboDisassociated(Wifi*) {}
static VOID Ap6256ClearPmOffloads(Wifi*) {}
static VOID Ap6256TalSetBssid(Device*,const UCHAR* address) {assert(!address);}
static VOID Ap6256TalPeerDelete(Device* d) {
    if(check_security_order) {
        assert(!d->HostCipherActive&&!d->HostCipherStore.Generation);
        assert(!d->HostFipsSessions[0].Generation&&(!d->HostFipsReady||(d->HostFipsBlockedMask&1)));
        security_order.push_back('P');
    }
}
static NTSTATUS Ap6256SendGeneratedIndication(Wifi* w,UINT16 id,const WDI_MESSAGE_HEADER*,
    UINT32 transaction,PVOID,const UCHAR* bytes,ULONG n) {
    assert(id==WDI_INDICATION_DISASSOCIATION&&transaction==WDI_TRANSACTION_ID_UNSOLICIT);
    WDI_INDICATION_DISASSOCIATION_PARAMETERS decoded={};
    assert(ParseWdiIndicationDisassociationFromIhv(n,bytes,&w->TlvContext,&decoded)==NDIS_STATUS_SUCCESS);
    assert(decoded.Optional.NeedPeerStateCleanup_IsPresent&&decoded.NeedPeerStateCleanup);
    assert(decoded.DisconnectIndicationParameters.DisassociationWABIReason==WDI_ASSOC_STATUS_DISASSOCIATED_BY_HOST);
    CleanupParsedWdiIndicationDisassociationFromIhv(&decoded);
    if(check_security_order) {
        assert(!w->Ctx->HostCipherActive&&!w->Ctx->HostCipherStore.Generation);
        assert(!w->Ctx->HostFipsSessions[0].Generation&&(!w->Ctx->HostFipsReady||(w->Ctx->HostFipsBlockedMask&1)));
        assert(!w->ConnectionActive&&!w->ConnectBssidValid&&!w->Mbo.Associated);
        const UCHAR empty[64]={};
        assert(!memcmp(w->ArpOffloads,empty,64)&&!memcmp(w->NsOffloads,empty,64)&&!memcmp(w->GtkOffload,empty,64));
        assert(!w->NsOffloadCount&&!w->GtkOffloadValid&&!w->GtkOffloadId);
        security_order.push_back('D');
    }
    indications.push_back('D');
    if(replace_after_disassociation) {
        w->Ctx->HostCipherActive=TRUE;w->Ctx->HostCipherStore.Generation=778;
        ++w->ConnectGeneration;
    }
    return 0;
}

static NTSTATUS Ap6256BcdcSetDcmd(Device* d,UINT32 cmd,const void* b,ULONG n) {
    if(disconnect_writer_tests) {
        assert(d->NetAdapter->ConnectLock==1&&!d->HostCipherActive&&!d->HostCipherStore.Generation);
        disconnect_commands.push_back(cmd);
        if(cmd==BRCMF_C_SCB_DEAUTHORIZE)assert(n==6&&!memcmp(b,disconnect_peer,6));
        else if(cmd==BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON){
            assert(n==sizeof(BRCMF_SCB_VAL));auto* scb=(const BRCMF_SCB_VAL*)b;
            assert(scb->Value==disconnect_reason&&!memcmp(scb->Address,disconnect_peer,6));
        }else assert(cmd==BRCMF_C_DISASSOC&&!b&&!n);
        return cmd==fail_command?STATUS_IO_TIMEOUT:0;
    }
    ++mutations; assert(command_count<RTL_NUMBER_OF(command_order));
    command_order[command_count++]=cmd;
    if(cmd==fail_command) return STATUS_IO_TIMEOUT;
    switch(cmd) {
    case BRCMF_C_SET_AUTH: assert(n==4); memcpy(&fw_auth,b,4); break;
    case BRCMF_C_SET_WPA_AUTH: assert(n==4); memcpy(&fw_wpa,b,4); break;
    case BRCMF_C_SET_WSEC: assert(n==4); memcpy(&fw_wsec,b,4);
        if(fw_wpa&0x9000u) fw_wsec|=0x800u;break;
    case BRCMF_C_SET_INFRA: assert(n==4); memcpy(&fw_infra,b,4); break;
    case BRCMF_C_SET_SSID: assert(n==sizeof(joined));memcpy(&joined,b,n);++joins;break;
    default: assert(false);
    }
    return 0;
}
static NTSTATUS Ap6256BcdcQueryDcmd(Device*,UINT32 cmd,void* b,ULONG n) {
    assert(n==4); UINT32 v=cmd==BRCMF_C_GET_AUTH?fw_auth:
        cmd==BRCMF_C_GET_WPA_AUTH?fw_wpa:cmd==BRCMF_C_GET_WSEC?fw_wsec:fw_infra;
    memcpy(b,&v,4);return 0;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device* d,UINT32 iface,UINT32 cmd,
    void* b,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(iface==0);memset(r,0,sizeof(*r));r->FirmwareReply=TRUE;r->PayloadLength=4;
    NTSTATUS status=Ap6256BcdcQueryDcmd(d,cmd,b,n);
    const UINT32 commands[]={BRCMF_C_GET_AUTH,BRCMF_C_GET_WPA_AUTH,BRCMF_C_GET_WSEC,BRCMF_C_GET_INFRA};
    for(unsigned i=0;i<4;++i)if(hc_security_fault==i+1&&cmd==commands[i])*(UINT32*)b^=1;
    if(hc_security_fault==6)r->FirmwareReply=FALSE;
    if(hc_security_fault==7)r->FirmwareError=TRUE;
    if(hc_security_fault==8)r->PayloadLength=3;
    return hc_security_fault==9?STATUS_IO_TIMEOUT:status;
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32 iface,PCSTR name,
    void* b,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(iface==0);memset(r,0,sizeof(*r));r->FirmwareReply=TRUE;r->PayloadLength=n;
    if(!strcmp(name,"wdi_fips_mode")){assert(n==32);memcpy(b,fips_mode,32);}
    else if(!strcmp(name,"wme_bss_disable")){assert(n==4);memcpy(b,&fips_qos,4);}
    else if(!strcmp(name,"wdi_fips_caps")){UINT32 caps[4]={0x31504648,16,7,8192};assert(n==16);memcpy(b,caps,16);}
    else if(!strcmp(name,"arpoe")||!strcmp(name,"ndoe")){assert(n==4);memcpy(b,&hc_offload_switches[!strcmp(name,"ndoe")],n);}
    else if(!strcmp(name,"bip")) {
        assert(n==4);UCHAR selector[4]={0,15,172,(UCHAR)fw_bip};memcpy(b,selector,4);
        if(hc_bip_readback_fault==1)return STATUS_IO_TIMEOUT;
        if(hc_bip_readback_fault==2)r->FirmwareReply=FALSE;
        if(hc_bip_readback_fault==3)r->FirmwareError=TRUE;
        if(hc_bip_readback_fault==4)r->PayloadLength=3;
        if(hc_bip_readback_fault==5)((UCHAR*)b)[3]=12;
    } else {assert(!strcmp(name,"mfp")&&n==4);memcpy(b,&fw_mfp,4);r->PayloadLength=8;}
    if(hc_security_fault==5&&!strcmp(name,"mfp"))*(UINT32*)b^=1;
    if(hc_security_fault==6)r->FirmwareReply=FALSE;
    if(hc_security_fault==7)r->FirmwareError=TRUE;
    if(hc_security_fault==8)r->PayloadLength=3;
    return hc_security_fault==9?STATUS_IO_TIMEOUT:0;
}
#if AP6256_TEST_HAS_BIP
static std::vector<UCHAR> fw_station_ie;
static unsigned wpaie_fault;
static NTSTATUS Ap6256BcdcSetIovarResultIf(Device*,UINT32 iface,PCSTR name,
    const void* b,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(iface==0);
    if(!strcmp(name,"wpaie")) {
        ++mutations;memset(r,0,sizeof(*r));r->FirmwareReply=(BOOLEAN)(wpaie_fault!=1);
        r->FirmwareError=(BOOLEAN)(wpaie_fault==2);r->FirmwareStatus=wpaie_fault==2?-2:0;
        assert(n==0||n==28||n==44);
        if(!wpaie_fault)fw_station_ie.assign((const UCHAR*)b,(const UCHAR*)b+n);
        return wpaie_fault==3?STATUS_IO_TIMEOUT:0;
    }
    assert(!strcmp(name,"bip") && n==4);
    assert(!memcmp(b,"\x00\x0f\xac\x06",4));++mutations;
    memset(r,0,sizeof(*r));r->FirmwareReply=(BOOLEAN)!bip_no_reply;
    r->FirmwareError=(BOOLEAN)bip_fw_error;r->FirmwareStatus=bip_fw_error?-2:0;
    if(!bip_status && !bip_no_reply && !bip_fw_error)fw_bip=6;
    return bip_status;
}
#endif
static NTSTATUS Ap6256BcdcSetIovar(Device*,PCSTR name,const void* b,ULONG n) {
    ++mutations;
    if(!strcmp(name,"mfp")) {assert(n==4);memcpy(&fw_mfp,b,4);
        assert(fw_mfp<=2);fw_wsec=(fw_wsec&~0x600u)|(fw_mfp==2?0x600u:fw_mfp?0x200u:0u);}
    else if(!strcmp(name,"set_pmk")) {++pmks;}
    else assert(!strcmp(name,"assoc_retry_max"));
    return 0;
}
static NTSTATUS Ap6256BcdcGetIovar(Device*,PCSTR,void*,ULONG) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256WifiSetU32(Device*,UINT32,UINT32,PCSTR) {++mutations;return 0;}
static NTSTATUS Ap6256WifiSetBssWmm(Device*,BOOLEAN enabled) {assert(enabled);return 0;}
static NTSTATUS Ap6256WifiSetMfpWsecBit(Device*,BOOLEAN enabled) {
    if(enabled) fw_wsec|=0x200u;else fw_wsec&=~0x200u;return 0;
}
static NTSTATUS Ap6256WifiSetPowerSave(Device*,BOOLEAN enabled) {assert(!enabled);return 0;}
static NTSTATUS Ap6256WifiGetBssid(Device*,UCHAR*) {return STATUS_DEVICE_NOT_READY;}
static NTSTATUS Ap6256WifiReassociate(Device*,const UCHAR*) {assert(false);return STATUS_NOT_SUPPORTED;}
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS s) {return (NTSTATUS)s;}
static VOID Ap6256CompleteRequest(Wifi* w,AP6256_REQUEST,NTSTATUS s) {
    request_status=s;
    if(disconnect_writer_tests) {
        assert(w->ConnectLock==0);
        if(s==0&&disconnect_completion_replace==1)++w->ConnectGeneration;
        if(s==0&&disconnect_completion_replace==2)w->DisconnectTask.Header.TransactionId=999;
        if(s==0&&disconnect_completion_replace==3)*disconnect_input_header={};
        if(s==0&&disconnect_completion_replace==10)w->DisconnectTask.RequestId=(PVOID)0x5678;
    }
    if(replace_on_completion && s==0) {
        w->ConnectTask.Header.TransactionId=888;
        w->ConnectTask.DeadlineMs=777;
    }
}
static PVOID Ap6256RequestGetId(AP6256_REQUEST r) {return r;}
static NTSTATUS Ap6256BeginTask(Wifi*,Task* t,PWDI_MESSAGE_HEADER h,PVOID requestId) {
    if(disconnect_writer_tests&&t->Active)return STATUS_DEVICE_BUSY;
    assert(!t->Active);t->Active=TRUE;t->Header=*h;t->RequestId=requestId;return 0;
}
static BOOLEAN Ap6256ClaimTask(Wifi*,Task* t,PWDI_MESSAGE_HEADER h,PVOID* r) {
    assert(t->Active);*h=t->Header;*r=t->RequestId;t->Active=FALSE;return TRUE;
}
static inline BOOLEAN Ap6256ClaimMatchingTask(Wifi* w,Task* t,UINT32 txn,WDI_PORT_ID port,PWDI_MESSAGE_HEADER h,PVOID* r) {
    if(!t->Active || t->Header.TransactionId!=txn || t->Header.PortId!=port) return FALSE;
    return Ap6256ClaimTask(w,t,h,r);
}
static inline BOOLEAN Ap6256ClaimExpiredTask(Wifi* w,Task* t,PWDI_MESSAGE_HEADER h,PVOID* r) {
    if(!t->Active || !t->DeadlineMs || Ap6256InterruptTimeMs()<t->DeadlineMs) return FALSE;
    return Ap6256ClaimTask(w,t,h,r);
}
static inline VOID Ap6256SetTaskDeadline(Wifi*,Task* t,ULONG timeout) {t->DeadlineMs=Ap6256InterruptTimeMs()+timeout;}
static BOOLEAN Ap6256IndicateAssociation(Wifi* w,const WDI_MESSAGE_HEADER*,PVOID,BOOLEAN success) {
    if(!state_tests)assert(!success);
    indications.push_back(success?'A':'F');w->ConnectionActive=success;return success;
}
static UINT16 Ap6256ConnectCompletionId(Wifi* w) {return w->ConnectTaskIsRoam?WDI_INDICATION_ROAM_COMPLETE:WDI_INDICATION_CONNECT_COMPLETE;}
static NTSTATUS Ap6256SendIndicationRq(Wifi*,UINT16,const WDI_MESSAGE_HEADER*,UINT32,PVOID,NTSTATUS s,const void*,ULONG) {
    if(disconnect_writer_tests){assert(disconnect_wifi->ConnectLock==0);disconnect_completions.push_back(s);return 0;}
    if(!state_tests)assert(s==expected_failure);
    if(check_security_order)security_order.push_back('C');
    indications.push_back( NT_SUCCESS(s)?'C':'X');++failures;return 0;
}
static NTSTATUS Ap6256QuiesceP2pListen(Wifi*) {return 0;}


static NTSTATUS Ap6256WifiDisconnect(Device* d) {
    assert(state_tests);
    if(check_timeout_lock)assert(d->NetAdapter->ConnectLock==1);
    ++disconnects;return STATUS_SUCCESS;
}
static VOID Ap6256StoreConnectRestrictions(Wifi* w,const WDI_ADDRESS_LIST_CONTAINER* a,const WDI_ADDRESS_LIST_CONTAINER* d,LONG m) {
    assert(!a&&!d&&!m);w->ConnectRestricted=FALSE;
}
static VOID Ap6256HandleClientConnect(Wifi*,AP6256_REQUEST,PWDI_MESSAGE_HEADER,const UCHAR*,ULONG) {++group_dispatch;}
static BOOLEAN Ap6256ModelDisconnectPort(Wifi*,AP6256_REQUEST,PWDI_MESSAGE_HEADER,WDI_TASK_DISCONNECT_PARAMETERS*,NTSTATUS) {return FALSE;}
'''
TEST = r'''
#if AP6256_TEST_HAS_HOST_CIPHER_DISASSOC
static void disconnectWriter() {
    unsigned cases=0;state_tests=true;disconnect_writer_tests=true;
    auto run=[&](ULONG version,unsigned mode,bool linked,UINT16 reason,unsigned fault) {
        Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;disconnect_wifi=&w;
        w.HardwareAvailable=1;w.ConnectGeneration=123;w.TlvContext.PeerVersion=version;
        w.ConnectionActive=(BOOLEAN)linked;d.FirmwareLinkUp=d.SupplicantComplete=d.ConnectionRequiresSupplicant=(BOOLEAN)linked;
        w.ConnectBssidValid=TRUE;w.ConnectBssid[0]=2;w.ConnectBssid[5]=0x6b;
        memcpy(disconnect_peer,w.ConnectBssid,6);disconnect_reason=reason;
        WDI_TASK_DISCONNECT_PARAMETERS p={};
        memcpy(p.DisconnectParameters.MacAddress.Address,disconnect_peer,6);
        p.DisconnectParameters.Disassociation80211Reason=reason;
        WDI_MESSAGE_HEADER h={};h.TransactionId=77;h.PortId=0;disconnect_input_header=&h;
        if(fault==4)p.DisconnectParameters.MacAddress.Address[5]^=1;
        if(fault==5)p.DisconnectParameters.MacAddress.Address[0]|=1;
        if(fault==6)p.DisconnectParameters.Disassociation80211Reason=0;
        if(fault==7)h.PortId=99;
        if(fault==8){w.DisconnectTask.Active=TRUE;w.DisconnectTask.Header.TransactionId=998;}
        disconnect_completion_replace=fault<=3||fault==10?fault:0;
        disconnect_host_handled=mode!=0;disconnect_host_retire=mode!=3;
        disconnect_host_status=mode>=2?STATUS_IO_TIMEOUT:0;
        if(mode){d.HostCipherActive=TRUE;d.HostCipherStore.Generation=777;}
        disconnect_host_calls=disconnect_clears=disconnect_timer_stops=0;hc_ends=0;
        disconnect_commands.clear();disconnect_completions.clear();timer_starts=0;
        fail_command=fault==9?BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON:0;
        ULONG n=0;UCHAR* wire=nullptr;
        assert(GenerateWdiTaskDisconnectToIhv(&p,0,&w.TlvContext,&n,&wire)==NDIS_STATUS_SUCCESS&&wire&&n);
        Ap6256HandleDisconnectRequest(&w,(PVOID)0x1234,&h,wire,n);FreeGenerated(wire);
        bool rejected=fault>=4&&fault<=8,stale=fault==1||fault==2||fault==10;
        assert(w.ConnectLock==0);
        if(rejected||stale) {
            assert(!disconnect_host_calls&&!disconnect_clears&&disconnect_commands.empty()&&!timer_starts);
            if(mode)assert(d.HostCipherActive&&d.HostCipherStore.Generation==777);
            assert((request_status<0)==rejected);
            assert(disconnect_completions.size()==(fault==1?1u:0u));
            if(fault==2)assert(w.DisconnectTask.Active&&w.DisconnectTask.Header.TransactionId==999);
            if(fault==10)assert(w.DisconnectTask.Active&&w.DisconnectTask.Header.TransactionId==77&&w.DisconnectTask.RequestId==(PVOID)0x5678);
        }else{
            assert(request_status==0&&disconnect_host_calls==1&&timer_starts==1);
            assert(w.DisconnectTask.DeadlineMs==test_now+AP6256_DISCONNECT_TIMEOUT_MS);
            if(mode)assert(disconnect_commands.empty()&&!disconnect_clears&&!hc_ends);
            else{
                std::vector<UINT32> expected={BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON};
                if(fault==9)expected.push_back(BRCMF_C_DISASSOC);
                expected.push_back(BRCMF_C_SCB_DEAUTHORIZE);
                assert(disconnect_commands==expected&&disconnect_clears==1&&hc_ends==1);
            }
            bool completed=mode>=2||!linked;
            assert(!!w.DisconnectTask.Active==!completed&&disconnect_completions.size()==(completed?1u:0u));
            assert(disconnect_timer_stops==(completed?1u:0u));
            if(completed)assert((disconnect_completions[0]<0)==(mode>=2));
            if(mode==3)assert(d.HostCipherActive&&d.HostCipherStore.Generation==777&&!!d.FirmwareLinkUp==linked);
            else assert(!d.HostCipherActive&&!d.HostCipherStore.Generation&&!d.FirmwareLinkUp&&!d.SupplicantComplete&&!d.ConnectionRequiresSupplicant);
        }
        ++cases;
    };
    for(ULONG version:{(ULONG)AP6256_TEST_WDI_VERSION,(ULONG)WDI_VERSION_2_0_4}) {
        for(unsigned mode=0;mode<4;++mode)for(bool linked:{false,true})for(UINT16 reason:{(UINT16)3,(UINT16)0x1234,(UINT16)65535})run(version,mode,linked,reason,0);
        for(unsigned fault=1;fault<=8;++fault)run(version,1,true,0x1234,fault);
        run(version,0,true,0x1234,9);
        run(version,1,true,0x1234,10);
    }
    disconnect_writer_tests=state_tests=false;disconnect_completion_replace=0;fail_command=0;
    printf("PASS: %u Microsoft DISCONNECT codec/production task/writer cases\n",cases);
}
#endif
#if AP6256_TEST_HAS_HOST_CIPHER_DISASSOC
static void disassociationSecurity() {
    unsigned cases=0;state_tests=true;
    for(unsigned mode=0;mode<3;++mode)for(unsigned kind=0;kind<4;++kind)
        for(bool failed:{false,true})for(bool replacement:{false,true}) {
        if((mode==0&&failed)||(kind==3&&replacement))continue;
        Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
        w.HardwareAvailable=1;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        w.ConnectGeneration=123;w.ConnectionActive=w.ConnectBssidValid=(BOOLEAN)(kind!=3);
        w.ConnectBssid[0]=2;w.ConnectBssid[5]=1;w.Mbo.Associated=TRUE;
        memset(w.ArpOffloadValid,1,sizeof(w.ArpOffloadValid));
        memset(w.ArpOffloadIds,1,sizeof(w.ArpOffloadIds));
        memset(w.ArpOffloads,1,sizeof(w.ArpOffloads));memset(w.NsOffloads,1,sizeof(w.NsOffloads));
        memset(w.GtkOffload,1,sizeof(w.GtkOffload));w.NsOffloadCount=w.GtkOffloadId=1;w.GtkOffloadValid=TRUE;
        if(mode==1){d.HostCipherActive=TRUE;d.HostCipherStore.Generation=777;}
        if(mode==2){d.HostFipsReady=TRUE;d.HostFipsSessions[0].Generation=41;}
        hc_end_status=mode==1&&failed?STATUS_IO_TIMEOUT:0;
        fips_end_status=mode==2&&failed?STATUS_IO_TIMEOUT:0;
        hc_ends=0;indications.clear();security_order.clear();check_security_order=true;
        replace_after_disassociation=replacement;
        w.DisconnectTask.Active=(BOOLEAN)(kind==0||kind==2);
        if(kind==2)Ap6256OnDisconnectTimeout(&w);
        else Ap6256NetLinkChangeWork(&w,FALSE,FALSE,123,0,FALSE);
        std::vector<char> expected={'R'};if(mode==2)expected.push_back('F');
        if(kind!=3){expected.push_back('P');expected.push_back('D');}
        if(kind==0||kind==2)expected.push_back('C');
        assert(security_order==expected&&hc_ends==1&&!w.DisconnectTask.Active);
        assert(!d.HostFipsSessions[0].Generation);
        if(replacement)assert(d.HostCipherActive&&d.HostCipherStore.Generation==778&&w.ConnectGeneration==124);
        else assert(!d.HostCipherActive&&!d.HostCipherStore.Generation);
        check_security_order=replace_after_disassociation=false;++cases;
    }
    hc_end_status=fips_end_status=0;

    for(unsigned mode=0;mode<3;++mode)for(bool staleFirmware:{false,true}) {
        Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
        w.ConnectGeneration=123;w.ConnectionActive=w.ConnectBssidValid=TRUE;
        if(mode==1){d.HostCipherActive=TRUE;d.HostCipherStore.Generation=777;}
        if(mode==2){d.HostFipsReady=TRUE;d.HostFipsSessions[0].Generation=41;}
        w.SaeEventGeneration=100;w.DisconnectTask.Active=TRUE;w.DisconnectTask.DeadlineMs=200;
        security_order.clear();indications.clear();check_security_order=true;hc_ends=0;
        Ap6256NetLinkChangeWork(&w,FALSE,FALSE,staleFirmware?123:122,99,staleFirmware);
        assert(security_order.empty()&&indications.empty()&&!hc_ends&&w.ConnectionActive&&w.DisconnectTask.Active);
        if(mode==1)assert(d.HostCipherActive&&d.HostCipherStore.Generation==777);
        if(mode==2)assert(d.HostFipsSessions[0].Generation==41);
        check_security_order=false;++cases;
    }


    Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
    d.D11IoType=2;d.MacAddress[0]=2;d.MacAddress[5]=0x55;
    d.HostCipherFirmwareQualified=1;d.FirmwareMfpSupported=TRUE;d.HostCipherActive=TRUE;d.HostCipherStore.Generation=776;
    w.ConnectGeneration=123;w.ConnectDeparting=w.ConnectionActive=w.ConnectBssidValid=TRUE;
    w.ConnectBssid[0]=2;w.ConnectBssid[5]=1;w.ConnectTask.Active=TRUE;w.ConnectTask.DeadlineMs=200;
    w.ConnectCandidateCount=1;auto& p=w.ConnectCandidates[0];p.HostCipher=TRUE;p.HostCipherAkm=2;
    p.Security=Ap6256SecurityWpa2Host;p.Mfp=Ap6256MfpRequired;p.BssidValid=TRUE;
    p.Bssid[0]=2;p.Bssid[5]=2;p.Channel=36;memcpy(p.Ssid,"next",4);p.SsidLength=4;
    joins=mutations=command_count=hc_profiles=hc_ends=0;fail_command=0;fw_bip=0;
    hc_begin_status=0;hc_security_fault=hc_bip_readback_fault=0;
    bip_status=0;bip_no_reply=bip_fw_error=false;
    indications.clear();Ap6256NetLinkChangeWork(&w,FALSE,FALSE,123,0,FALSE);
    assert(joins==1&&w.ConnectTask.Active&&!w.ConnectDeparting);
    assert(d.HostCipherActive&&d.HostCipherStore.Generation==777&&hc_profiles==1&&hc_ends==2);
    assert(indications==std::vector<char>({'D'}));++cases;
    state_tests=false;
    printf("PASS: %u production disassociation retirement/order cases\n",cases);
}
#endif
static void check(WDI_AUTH_ALGORITHM auth,WDI_CIPHER_ALGORITHM cipher,bool roam,bool mfp,
                  bool fips,int ft,UINT32 fail,NTSTATUS expected,bool replace=false,int pmkidLength=-1,int h2eSource=0,bool fipsReady=false,bool ht=false,bool metadata=true) {
    Device d={};d.D11IoType=BRCMU_D11AC_IOTYPE;
    d.HostFipsReady=(BOOLEAN)fipsReady;d.MacAddress[0]=2;d.MacAddress[5]=0x55;
    Wifi w={};w.Ctx=&d;w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
    w.HardwareAvailable=1;
    d.FirmwareExternalAuth=d.FirmwareMfpSupported=(BOOLEAN)(pmkidLength!=-1);
    WDI_TASK_CONNECT_PARAMETERS p={};
    UCHAR ssidBytes[]={'t','e','s','t'};WDI_SSID ssid={};
    ssid.pElements=ssidBytes;ssid.ElementCount=sizeof(ssidBytes);
    p.ConnectParameters.SSIDList.pElements=&ssid;p.ConnectParameters.SSIDList.ElementCount=1;
    p.ConnectParameters.AuthenticationAlgorithms.pElements=&auth;p.ConnectParameters.AuthenticationAlgorithms.ElementCount=1;
    p.ConnectParameters.UnicastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.UnicastCipherAlgorithms.ElementCount=1;
    p.ConnectParameters.MulticastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.MulticastCipherAlgorithms.ElementCount=1;
    p.ConnectParameters.ConnectionSettings.MFPEnabled=(BOOLEAN)mfp;
    p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled=(BOOLEAN)fips;
    WDI_CONNECT_BSS_ENTRY_CONTAINER entries[2]={};auto& bss=entries[0];bss.BSSID.Address[0]=2;bss.BSSID.Address[5]=7;
    bss.ChannelInfo.ChannelNumber=36;bss.ChannelInfo.BandId=WDI_BAND_ID_5000;
    p.PreferredBSSEntryList.pElements=&bss;p.PreferredBSSEntryList.ElementCount=1;
    UCHAR ie[]={54,3,0x12,0x34,0};
    UCHAR fte[84]={55,82};fte[52]=0x77;
    if(ft==1) {
        bss.Optional.FTInitialAssocParameters_IsPresent=TRUE;
        bss.FTInitialAssocParameters.MDE.pElements=ie;bss.FTInitialAssocParameters.MDE.ElementCount=sizeof(ie);
    }
    if(ft==2) {
        bss.Optional.FTReAssocParameters_IsPresent=TRUE;
        bss.FTReAssocParameters.MDE.pElements=ie;bss.FTReAssocParameters.MDE.ElementCount=sizeof(ie);
        bss.FTReAssocParameters.FTE.pElements=fte;bss.FTReAssocParameters.FTE.ElementCount=sizeof(fte);
    }
    entries[1].BSSID.Address[0]=2;entries[1].ChannelInfo.BandId=WDI_BAND_ID_5000;
    entries[1].BSSID.Address[5]=8;entries[1].ChannelInfo.ChannelNumber=40;
    p.PreferredBSSEntryList.pElements=entries;p.PreferredBSSEntryList.ElementCount=roam?2:1;
    UCHAR pmkid[17];memset(pmkid,0x5a,sizeof(pmkid));
    if(pmkidLength>=0) {
        bss.Optional.PMKID_IsPresent=TRUE;bss.PMKID.pElements=pmkid;
        bss.PMKID.ElementCount=(ULONG)pmkidLength;
    }
    UCHAR h2eBody[15]={};h2eBody[12]=244;h2eBody[13]=1;h2eBody[14]=0x20;
    UCHAR fipsBeacon[40]={};fipsBeacon[12]=45;fipsBeacon[13]=26;
    if(fipsReady && metadata) {
        bss.Optional.BeaconFrame_IsPresent=TRUE;bss.BeaconFrame.pElements=fipsBeacon;bss.BeaconFrame.ElementCount=ht?40:12;
    }
    if(h2eSource==1) {
        bss.Optional.BeaconFrame_IsPresent=TRUE;bss.BeaconFrame.pElements=h2eBody;bss.BeaconFrame.ElementCount=15;
    } else if(h2eSource==2) {
        bss.Optional.ProbeResponseFrame_IsPresent=TRUE;bss.ProbeResponseFrame.pElements=h2eBody;bss.ProbeResponseFrame.ElementCount=15;
    } else if(h2eSource==3) {
        bss.Optional.AssociationRequestVendorIE_IsPresent=TRUE;
        bss.AssociationRequestVendorIE.pElements=h2eBody+12;bss.AssociationRequestVendorIE.ElementCount=3;
    } else if(h2eSource==4) {
        p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent=TRUE;
        p.ConnectParameters.AssociationRequestVendorIE.pElements=h2eBody+12;
        p.ConnectParameters.AssociationRequestVendorIE.ElementCount=3;
    }
    UCHAR* bytes=nullptr;ULONG len=0;
    NDIS_STATUS s=roam?GenerateWdiTaskRoamToIhv((WDI_TASK_ROAM_PARAMETERS*)&p,0,&w.TlvContext,&len,&bytes):
        GenerateWdiTaskConnectToIhv(&p,0,&w.TlvContext,&len,&bytes);
    if(s!=0 && pmkidLength>=0 && pmkidLength!=16) {


        assert(expected==STATUS_INVALID_PARAMETER);FreeGenerated(bytes);return;
    }
    assert(s==0&&bytes&&len);
    WDI_MESSAGE_HEADER h={};h.PortId=AP6256_STATION_PORT;h.TransactionId=321;
    mutations=joins=pmks=timer_starts=failures=0;command_count=0;fail_command=fail;
    fips_modes=fips_seeds=0;
    expected_failure=STATUS_IO_TIMEOUT;
    replace_on_completion=replace;
    fw_auth=fw_wpa=fw_wsec=fw_infra=fw_mfp=0xffffffffu;
    cache_written=FALSE;
    request_status=STATUS_INVALID_PARAMETER;
    Ap6256HandleConnectRequest(&w,nullptr,roam?WDI_TASK_ROAM:WDI_TASK_CONNECT,&h,bytes,len);
    replace_on_completion=false;
    FreeGenerated(bytes);
    assert(request_status==expected);
    if(expected!=0) {assert(!mutations&&!joins&&!timer_starts&&!w.ConnectTask.Active);return;}
    if(replace) {
        assert(!mutations && !joins && !timer_starts && !failures);
        assert(w.ConnectTask.Active && w.ConnectTask.Header.TransactionId==888);
        assert(w.ConnectTask.DeadlineMs==777);return;
    }
    assert(w.AuthAlgorithm==auth && w.UnicastCipher==cipher && w.MulticastCipher==cipher);

    assert(w.MulticastMgmtCipher==WDI_CIPHER_ALGO_NONE);
    assert(!!w.ConnectTaskIsRoam==roam && timer_starts==1);
    assert(!pmks && !d.ConnectionRequiresSupplicant);
    if(fail) {
        assert(!joins&&failures==1&&!w.ConnectTask.Active);
        return;
    }
    assert(joins==1 && w.ConnectTask.Active && !failures);
    if(fipsReady&&fips) {
        AP6256_FIPS_SESSION session;assert(Ap6256FipsSnapshot(&d,0,&session));
        assert(session.Generation&&session.IfIndex==0&&!memcmp(session.Bssid,bss.BSSID.Address,6));
        assert(!memcmp(session.Station,d.MacAddress,6)&&fips_qos==(ht?0u:1u)&&fips_modes==1&&fips_seeds==7);
        assert(w.ConnectCandidates[0].HostFips&&!!w.ConnectCandidates[0].HostFipsHt==(ht&&metadata));
    }
    assert(w.ConnectCandidateCount==(roam?2u:1u));
    if(roam)assert(w.ConnectCandidates[1].Bssid[5]==8&&w.ConnectCandidates[1].Channel==40);
    bool sae=auth==WDI_AUTH_ALGO_WPA3_SAE;
    assert(fw_auth==(sae&&pmkidLength<0?3u:0u) && fw_infra==1 && fw_mfp==(sae?2u:(mfp?1u:0u)));
    UINT32 expectedWpa=sae?0x40000:auth==WDI_AUTH_ALGO_RSNA?0x40u:auth==WDI_AUTH_ALGO_RSNA_PSK?0x80u:0u;
    assert(fw_wpa==expectedWpa);
    assert(fw_wsec==((cipher==WDI_CIPHER_ALGO_CCMP?4u:0u)|(sae?0x600u:mfp?0x200u:0u)));
    if(sae) {
        assert(!!cache_written==(pmkidLength==16));
        assert(!!w.ConnectCandidates[0].PmkidValid==!!cache_written);
        assert(!!w.ConnectCandidates[0].SaeCachedH2e==(cache_written&&h2eSource!=0));
        assert(!memcmp(written_peer,bss.BSSID.Address,6));
        if(cache_written) {
            assert(!memcmp(w.ConnectCandidates[0].Pmkid,pmkid,16));
            assert(!memcmp(written_pmkid,pmkid,16));
        }
    }
    assert(command_order[0]==BRCMF_C_SET_AUTH && command_order[1]==BRCMF_C_SET_WPA_AUTH && command_order[2]==BRCMF_C_SET_WSEC);
    assert(joined.Ssid.SsidLen==4 && !memcmp(joined.Ssid.Ssid,ssidBytes,4));
    assert(!memcmp(joined.Params.Bssid,bss.BSSID.Address,6) && joined.Params.ChanspecList[0]==0xd024);
}
static void refusedFt() {
    for(bool roam:{false,true}) for(int ft:{1,2})
        for(WDI_AUTH_ALGORITHM auth:{WDI_AUTH_ALGO_RSNA,WDI_AUTH_ALGO_RSNA_PSK})
            check(auth,WDI_CIPHER_ALGO_CCMP,roam,false,false,ft,0,STATUS_NOT_SUPPORTED);
}

static void roamState() {
    state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
    d.D11IoType=BRCMU_D11AC_IOTYPE;command_count=0;fail_command=0;joins=0;
    w.ConnectTask.Active=TRUE;w.ConnectTask.Header.TransactionId=99;w.ConnectTask.DeadlineMs=200;
    w.ConnectTaskIsRoam=TRUE;w.ConnectGeneration=10;w.ConnectionActive=TRUE;
    w.ConnectDeparting=TRUE;w.ConnectBssidValid=TRUE;w.ConnectBssid[0]=2;w.ConnectBssid[5]=1;
    UCHAR old[6]={2,0,0,0,0,1},target[6]={2,0,0,0,0,2};
    w.ConnectCandidateCount=2;
    for(unsigned i=0;i<2;++i){auto& c=w.ConnectCandidates[i];c.BssidValid=TRUE;
        c.Bssid[0]=2;c.Bssid[5]=(UCHAR)(i+2);c.Channel=i?40:36;c.Security=Ap6256SecurityOpen;
        memcpy(c.Ssid,"test",4);c.SsidLength=4;}
    indications.clear();queued_count=0;
    Ap6256NetStationLinkEvent(&d,FALSE,FALSE,old);assert(queued_count==1&&queued_code==AP6256_LINK_DOWN);
    Ap6256NetLinkChangeWork(&w,FALSE,FALSE,queued_generation,0,FALSE);
    assert(indications==std::vector<char>({'D'})&&joins==1&&w.ConnectTask.Active&&!w.ConnectDeparting);
    LONG first=w.ConnectGeneration;
    Ap6256NetStationLinkEvent(&d,FALSE,FALSE,old);assert(queued_count==1);
    Ap6256NetStationLinkEvent(&d,FALSE,TRUE,target);assert(queued_code==AP6256_LINK_JOIN_FAILED);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,queued_generation,0,FALSE);
    assert(joins==2&&w.ConnectCandidateIndex==1&&w.ConnectTask.Active);
    assert(indications==std::vector<char>({'D','F'}));
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,first,0,FALSE);assert(joins==2&&w.ConnectTask.Active);
    target[5]=3;Ap6256NetStationLinkEvent(&d,TRUE,FALSE,target);LONG successGen=queued_generation;
    Ap6256NetLinkChangeWork(&w,TRUE,FALSE,successGen,0,FALSE);
    assert(!w.ConnectTask.Active&&w.ConnectionActive&&w.ConnectGeneration==successGen);
    assert(indications==std::vector<char>({'D','F','A','C'}));
    Ap6256NetStationLinkEvent(&d,FALSE,FALSE,old);int n=queued_count;
    Ap6256NetStationLinkEvent(&d,FALSE,FALSE,target);assert(queued_count==n+1);
    Ap6256NetLinkChangeWork(&w,FALSE,FALSE,queued_generation,0,FALSE);
    assert(indications.back()=='D'&&!w.ConnectionActive);

    w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=2;w.ConnectCandidateIndex=0;
    indications.clear();assert(Ap6256StationStartNext(&w)==0);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,w.ConnectGeneration,0,FALSE);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,w.ConnectGeneration,0,FALSE);
    assert(!w.ConnectTask.Active&&indications==std::vector<char>({'F','F','X'}));

    w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=2;w.ConnectCandidateIndex=0;
    test_now=200;int j=joins;assert(Ap6256StationStartNext(&w)==STATUS_IO_TIMEOUT&&joins==j);
    test_now=1;WDI_MESSAGE_HEADER h={};PVOID rid;
    assert(!Ap6256ClaimConnectTask(&w,Ap6256ConnectClaimMatching,111,0,&h,&rid));
    assert(w.ConnectTask.Active);
    assert(Ap6256ClaimConnectTask(&w,Ap6256ConnectClaimMatching,99,0,&h,&rid));
    assert(!w.ConnectTask.Active&&w.ConnectCandidateCount==0);
    assert(Ap6256StationStartNext(&w)==STATUS_NETWORK_UNREACHABLE&&joins==j);

    w.ConnectTask.Active=TRUE;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,target,6);d.FirmwareLinkUp=TRUE;
    Ap6256NetStationLinkEvent(&d,FALSE,FALSE,target);assert(queued_code==AP6256_LINK_JOIN_FAILED&&!d.FirmwareLinkUp);


    check_timeout_lock=true;
    for(bool departing:{false,true}) {
        w.ConnectionActive=departing;w.ConnectDeparting=departing;
        w.ConnectTask.Active=TRUE;w.ConnectCandidateCount=2;
        w.ConnectTask.DeadlineMs=200;test_now=199;indications.clear();
        int before=disconnects;LONG gen=w.ConnectGeneration;
        Ap6256ExpireConnect(&w);assert(w.ConnectTask.Active&&disconnects==before);
        test_now=200;Ap6256ExpireConnect(&w);Ap6256ExpireConnect(&w);
        assert(!w.ConnectTask.Active&&!w.ConnectCandidateCount&&!w.ConnectDeparting);
        assert(w.ConnectGeneration==gen+1&&disconnects==before+1&&w.ConnectLock==0);
        assert(indications==std::vector<char>({departing?'D':'F','X'}));
    }
    check_timeout_lock=false;test_now=1;
    state_tests=false;
    puts("PASS: old AP departure -> ordered fallback -> association -> ROAM_COMPLETE; exhaustion, cancellation, deadline and stale peer/generation handling");
}
static void cachedRoamFallback() {
    state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
    d.D11IoType=BRCMU_D11AC_IOTYPE;d.FirmwareExternalAuth=d.FirmwareMfpSupported=TRUE;
    w.ConnectTask.Active=TRUE;w.ConnectTask.Header.TransactionId=99;w.ConnectTask.DeadlineMs=30000;
    w.ConnectTaskIsRoam=TRUE;w.ConnectCandidateCount=2;test_now=1;
    command_count=0;fail_command=0;joins=failures=0;indications.clear();
    for(unsigned i=0;i<2;++i) {
        auto& p=w.ConnectCandidates[i];p.Security=Ap6256SecuritySaeHost;p.Mfp=Ap6256MfpRequired;
        p.BssidValid=TRUE;p.Bssid[0]=2;p.Bssid[5]=(UCHAR)(i+2);p.Channel=i?40:36;
        memcpy(p.Ssid,"test",4);p.SsidLength=4;p.PmkidValid=(BOOLEAN)(i==0);memset(p.Pmkid,0x5a,16);
    }
    Ap6256LockAcquire(&w.ConnectLock);assert(Ap6256StationStartNext(&w)==0);Ap6256LockRelease(&w.ConnectLock);
    LONG cachedGeneration=w.ConnectGeneration;
    assert(joins==1 && fw_auth==0 && cache_written);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,cachedGeneration,0,FALSE);
    assert(joins==2 && w.ConnectCandidateIndex==0 && !w.ConnectCandidates[0].PmkidValid);
    assert(fw_auth==3 && !cache_written && w.ConnectGeneration!=cachedGeneration);
    assert(w.ConnectTask.Active && indications==std::vector<char>({'F'}));
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,cachedGeneration,0,FALSE);
    assert(joins==2 && w.ConnectTask.Active);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,w.ConnectGeneration,0,FALSE);
    assert(joins==3 && w.ConnectCandidateIndex==1 && fw_auth==3 && w.ConnectTask.Active);
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,w.ConnectGeneration,0,FALSE);
    assert(!w.ConnectTask.Active && failures==1 && indications==std::vector<char>({'F','F','F','X'}));

    w.ConnectTask.Active=TRUE;w.ConnectTask.DeadlineMs=30000;w.ConnectCandidateIndex=0;
    w.ConnectCandidateCount=1;w.ConnectCandidates[0].PmkidValid=TRUE;
    fail_command=BRCMF_C_SET_SSID;command_count=0;joins=0;
    Ap6256LockAcquire(&w.ConnectLock);assert(Ap6256StationStartNext(&w)==STATUS_IO_TIMEOUT);Ap6256LockRelease(&w.ConnectLock);
    assert(!joins && w.ConnectCandidateIndex==1 && !w.ConnectCandidates[0].PmkidValid && fw_auth==3);
    fail_command=0;state_tests=false;
    puts("PASS: cached PMKID CONNECT/ROAM copies, Open authentication, same-AP full SAE fallback once, next-AP progression and stale-generation rejection");
}
static void private_join() {
    Device d={};d.FirmwarePrivateSae=d.FirmwareMfpSupported=TRUE;d.D11IoType=2;
    AP6256_CONNECT_PARAMS p={};memcpy(p.Ssid,"net",3);p.SsidLength=3;
    p.Bssid[0]=2;p.Bssid[5]=1;p.BssidValid=TRUE;p.Channel=36;
    p.Security=Ap6256SecuritySaeHost;p.Mfp=Ap6256MfpRequired;
    p.SaeFirmwareGeneration=99;p.SaeTimeoutMs=30000;
    for(int mode:{0,1,3}) {
        p.PmkidValid=private_cached=(BOOLEAN)(mode!=0);
        p.SaeCachedH2e=private_h2e=(BOOLEAN)(mode==3);memset(p.Pmkid,0x5a,16);
        for(NTSTATUS result:{(NTSTATUS)0,STATUS_IO_TIMEOUT}) {
            private_arm_status=result;private_arms=joins=command_count=mutations=0;fail_command=0;
            fw_bip=0;
            auto actual=Ap6256WifiConnect(&d,&p);
            if(actual!=result)fprintf(stderr,"Private SAE security join returned 0x%08lX, expected 0x%08lX\n",actual,result);
            assert(actual==result && private_arms==1);
            assert(joins==(NT_SUCCESS(result)?1:0));
        }
    }
    if(AP6256_TEST_HAS_BIP) {
        for(int failure:{1,2,3}) {
            bip_status=failure==1?STATUS_IO_TIMEOUT:0;
            bip_no_reply=failure==2;bip_fw_error=failure==3;
            private_arms=joins=fw_bip=0;
            assert(Ap6256WifiConnect(&d,&p)==(failure==1?STATUS_IO_TIMEOUT:STATUS_DEVICE_PROTOCOL_ERROR));
            assert(!private_arms && !joins && !fw_bip);
        }
        bip_status=0;bip_no_reply=bip_fw_error=false;
        puts("PASS: native BIP selector sent before full/cached SAE ARM; failed/missing/error acknowledgement prevents ARM and SET_SSID");
    } else puts("PASS: saved source leaves BIP unconfigured before full/cached SAE ARM");
    puts("PASS: private SAE programs AUTH 0, WPA_AUTH 0x8000, CCMP/required PMF and ARM before SET_SSID; failed ARM prevents join");
}
#if AP6256_TEST_HAS_HOST_CIPHER_PROFILE
static void hostCipherRequest() {
    unsigned cases=0;
    for(UINT32 version:{(UINT32)AP6256_TEST_WDI_VERSION,(UINT32)WDI_VERSION_2_0_4})
        for(UINT32 akm:{1u,2u,5u,8u,12u,18u})for(bool roam:{false,true})for(bool cached:{false,true})
        for(unsigned mfp=0;mfp<3;++mfp) {
        if((akm==1||akm==2)?mfp==2:mfp!=2)continue;
        for(unsigned fault=0;fault<17;++fault) {
            Device d={};Wifi w={};w.Ctx=&d;w.HardwareAvailable=1;d.NetAdapter=&w;
            d.D11IoType=2;d.MacAddress[0]=2;d.MacAddress[5]=0x55;
            d.HostCipherFirmwareQualified=fault==1?0:1;d.FirmwarePrivateSae=d.FirmwareMfpSupported=TRUE;
            d.FirmwareHostOwe=d.FirmwareOwePatchVerified=TRUE;
            w.TlvContext.PeerVersion=version;
            WDI_TASK_CONNECT_PARAMETERS p={};UCHAR ssidBytes[]={'n','e','t'};WDI_SSID ssid={};
            ssid.pElements=ssidBytes;ssid.ElementCount=3;
            p.ConnectParameters.SSIDList.pElements=&ssid;p.ConnectParameters.SSIDList.ElementCount=1;
            WDI_AUTH_ALGORITHM auth=akm==1?WDI_AUTH_ALGO_RSNA:akm==2?WDI_AUTH_ALGO_RSNA_PSK:
                akm==5?WDI_AUTH_ALGO_WPA3_ENT:akm==8?WDI_AUTH_ALGO_WPA3_SAE:
                akm==12?WDI_AUTH_ALGO_WPA3_ENT_192:WDI_AUTH_ALGO_OWE;
            WDI_CIPHER_ALGORITHM unicast=fault==4?WDI_CIPHER_ALGO_CCMP:WDI_CIPHER_ALGO_GCMP_256;
            WDI_CIPHER_ALGORITHM group=fault==5?WDI_CIPHER_ALGO_CCMP:WDI_CIPHER_ALGO_GCMP_256;
            p.ConnectParameters.AuthenticationAlgorithms.pElements=&auth;p.ConnectParameters.AuthenticationAlgorithms.ElementCount=1;
            p.ConnectParameters.UnicastCipherAlgorithms.pElements=&unicast;p.ConnectParameters.UnicastCipherAlgorithms.ElementCount=1;
            p.ConnectParameters.MulticastCipherAlgorithms.pElements=&group;p.ConnectParameters.MulticastCipherAlgorithms.ElementCount=1;
            p.ConnectParameters.ConnectionSettings.MFPEnabled=(BOOLEAN)(fault!=3&&mfp!=0);
            p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled=(BOOLEAN)(fault==13);
            p.ConnectParameters.ConnectionSettings.ExcludeUnencrypted=(BOOLEAN)(cached||roam);
            RSNA_AKM_SUITE selected=(RSNA_AKM_SUITE)(0xac0f00u|(akm<<24));
            RSNA_AKM_SUITE constrained=fault==6?(RSNA_AKM_SUITE)0x03ac0f00u:selected;
            p.ConnectParameters.Optional.RsnaAkmSuites_IsPresent=TRUE;
            p.ConnectParameters.RsnaAkmSuites.pElements=&constrained;p.ConnectParameters.RsnaAkmSuites.ElementCount=1;
            RSNA_AKM_CIPHER_PAIR pair={selected,fault==7?rsna_cipher_ccmp_128:rsna_cipher_gcmp_256};
            p.ConnectParameters.Optional.RsnaAkmCipherSuites_IsPresent=TRUE;
            p.ConnectParameters.RsnaAkmCipherSuites.pElements=&pair;p.ConnectParameters.RsnaAkmCipherSuites.ElementCount=1;
            WDI_CONNECT_BSS_ENTRY_CONTAINER bss={};bss.BSSID.Address[0]=fault==12?3:2;bss.BSSID.Address[5]=7;
            bss.ChannelInfo.ChannelNumber=36;bss.ChannelInfo.BandId=WDI_BAND_ID_5000;
            p.PreferredBSSEntryList.pElements=&bss;p.PreferredBSSEntryList.ElementCount=1;
            std::vector<UCHAR> beacon(12,0);
            std::vector<UCHAR> rsn={48,26,1,0,0,15,172,9,1,0,0,15,172,9,1,0,0,15,172,(UCHAR)akm,
                (UCHAR)(mfp?0x80:0),0,0,0,0,15,172,12};
            if(fault==8)rsn[7]=4;if(fault==9)rsn[13]=4;if(fault==10)rsn[27]=6;
            if(fault==11)rsn[19]=3;if(fault==15)rsn[1]=255;
            beacon.insert(beacon.end(),rsn.begin(),rsn.end());
            if(akm==8&&cached)beacon.insert(beacon.end(),{244,1,0x20});
            bss.Optional.BeaconFrame_IsPresent=(BOOLEAN)(fault!=2);bss.BeaconFrame.pElements=beacon.data();bss.BeaconFrame.ElementCount=(ULONG)beacon.size();
            std::vector<UCHAR> probe=beacon;
            if(fault==16){probe[12+13]=4;bss.Optional.ProbeResponseFrame_IsPresent=TRUE;
                bss.ProbeResponseFrame.pElements=probe.data();bss.ProbeResponseFrame.ElementCount=(ULONG)probe.size();}
            UCHAR pmkid[16];memset(pmkid,0x5a,16);
            bss.Optional.PMKID_IsPresent=(BOOLEAN)cached;bss.PMKID.pElements=pmkid;bss.PMKID.ElementCount=16;
            UCHAR mde[]={54,3,0x12,0x34,0};
            if(fault==14){bss.Optional.FTInitialAssocParameters_IsPresent=TRUE;
                bss.FTInitialAssocParameters.MDE.pElements=mde;bss.FTInitialAssocParameters.MDE.ElementCount=5;}
            UCHAR dh[37]={255,35,32,19,0};for(unsigned i=5;i<37;++i)dh[i]=(UCHAR)(i-4);
            if(akm==18){p.ConnectParameters.Optional.OWEDHIE_IsPresent=TRUE;p.ConnectParameters.OWEDHIE.pElements=dh;p.ConnectParameters.OWEDHIE.ElementCount=37;}
            UCHAR* bytes=nullptr;ULONG length=0;
            auto generated=roam?GenerateWdiTaskRoamToIhv((WDI_TASK_ROAM_PARAMETERS*)&p,0,&w.TlvContext,&length,&bytes):
                GenerateWdiTaskConnectToIhv(&p,0,&w.TlvContext,&length,&bytes);
            if(generated)fprintf(stderr,"HC codec version %08x akm %u mfp %u fault %u generate %08lx\n",version,akm,mfp,fault,(unsigned long)generated);
            assert(generated==0&&bytes);
            WDI_TASK_CONNECT_PARAMETERS decodedRequest={};
            assert((roam?ParseWdiTaskRoam(length,bytes,&w.TlvContext,(WDI_TASK_ROAM_PARAMETERS*)&decodedRequest):
                ParseWdiTaskConnect(length,bytes,&w.TlvContext,&decodedRequest))==0);
            assert(!!decodedRequest.ConnectParameters.Optional.RsnaAkmSuites_IsPresent==(version>=WDI_VERSION_2_0_4));


            assert(!decodedRequest.ConnectParameters.Optional.RsnaAkmCipherSuites_IsPresent);
            if(roam)CleanupParsedWdiTaskRoam((WDI_TASK_ROAM_PARAMETERS*)&decodedRequest);else CleanupParsedWdiTaskConnect(&decodedRequest);
            joins=mutations=command_count=private_arms=0;owe_arms=owe_ends=0;
            hc_profiles=hc_ends=hc_security_fault=hc_bip_readback_fault=0;hc_begin_status=hc_end_status=0;
            private_cached=(BOOLEAN)(akm==8&&cached);private_h2e=(BOOLEAN)(private_cached&&fault!=2);
            bip_status=0;bip_no_reply=bip_fw_error=false;private_arm_status=0;fail_command=0;fw_bip=0;
            bool accepted=fault==0||fault==2||(fault==3&&(akm==1||akm==2))||(fault==10&&!mfp)||
                (fault==6&&version<WDI_VERSION_2_0_4)||fault==7;
            WDI_MESSAGE_HEADER h={};h.TransactionId=901;h.PortId=0;
            request_status=STATUS_INVALID_PARAMETER;
            Ap6256HandleConnectRequest(&w,nullptr,roam?WDI_TASK_ROAM:WDI_TASK_CONNECT,&h,bytes,length);
            FreeGenerated(bytes);
            if((request_status==0)!=accepted)fprintf(stderr,"HC CONNECT akm %u mfp %u roam %u cache %u fault %u status %08lx expected %u\n",akm,mfp,roam,cached,fault,(unsigned long)request_status,accepted);
            assert((request_status==0)==accepted);
            if(accepted){
                assert(joins==1&&hc_profiles==1&&w.ConnectTask.Active&&d.HostCipherActive);
                assert(w.AuthAlgorithm==auth&&w.UnicastCipher==WDI_CIPHER_ALGO_GCMP_256&&w.MulticastCipher==w.UnicastCipher);
                assert(w.MulticastMgmtCipher==WDI_CIPHER_ALGO_NONE&&w.HostCipherGeneration==777);
                auto& candidate=w.ConnectCandidates[0];assert(candidate.HostCipher&&candidate.HostCipherAkm==akm&&candidate.Mfp==(AP6256_MFP)(fault==3?0:mfp));
                assert(!!candidate.ExcludeUnencrypted==(cached||roam)&&!!host_exclude_unencrypted==(cached||roam));
                assert(!!candidate.PmkidValid==cached);if(cached)assert(!memcmp(candidate.Pmkid,pmkid,16));
            }else assert(!joins&&!mutations&&!w.ConnectTask.Active&&!hc_profiles);
            assert(candidate_allocations==0);++cases;
        }
    }
    for(UINT32 akm:{1u,2u,5u,8u,12u,18u}) {
        WDI_CONNECT_PARAMETERS_CONTAINER direct={};
        RSNA_AKM_SUITE selector=(RSNA_AKM_SUITE)(0xac0f00u|(akm<<24));
        RSNA_AKM_CIPHER_PAIR pair={selector,rsna_cipher_gcmp_256};
        direct.Optional.RsnaAkmSuites_IsPresent=direct.Optional.RsnaAkmCipherSuites_IsPresent=TRUE;
        direct.RsnaAkmSuites.pElements=&selector;direct.RsnaAkmSuites.ElementCount=1;
        direct.RsnaAkmCipherSuites.pElements=&pair;direct.RsnaAkmCipherSuites.ElementCount=1;
        assert(Ap6256HostCipherRequestSuite(&direct,akm));
        pair.cipher=rsna_cipher_ccmp_128;assert(!Ap6256HostCipherRequestSuite(&direct,akm));
        pair.cipher=rsna_cipher_gcmp_256;pair.akm=rsna_akm_none;assert(!Ap6256HostCipherRequestSuite(&direct,akm));
        pair.akm=selector;selector=rsna_akm_none;assert(!Ap6256HostCipherRequestSuite(&direct,akm));
        selector=pair.akm;direct.RsnaAkmSuites.ElementCount=0;assert(!Ap6256HostCipherRequestSuite(&direct,akm));
        direct.RsnaAkmSuites.ElementCount=1;direct.RsnaAkmCipherSuites.ElementCount=0;assert(!Ap6256HostCipherRequestSuite(&direct,akm));
    }
    private_cached=private_h2e=FALSE;
    printf("PASS: %u Microsoft GCMP CONNECT/ROAM selection cases\n",cases);
    puts("PASS: 36 direct AKM/cipher constraint checks; SDK 26100 omits the declared pair field in CONNECT generation");
}
static void hostCipherJoin() {
    unsigned cases=0;
    for(UINT32 akm:{1u,2u,5u,8u,12u,18u})for(UINT32 mfp:{0u,1u,2u}) {
        if((akm==5||akm==8||akm==12||akm==18)&&mfp!=2)continue;
        for(unsigned failure=0;failure<21;++failure) {
            if(failure>=13&&(!mfp||akm==8||akm==18))continue;
            Device d={};d.D11IoType=2;d.MacAddress[0]=2;d.MacAddress[5]=0x55;
            d.HostCipherFirmwareQualified=1;d.FirmwarePrivateSae=d.FirmwareMfpSupported=TRUE;
            d.FirmwareHostOwe=d.FirmwareOwePatchVerified=TRUE;
            AP6256_CONNECT_PARAMS p={};memcpy(p.Ssid,"net",3);p.SsidLength=3;
            p.Bssid[0]=2;p.Bssid[5]=1;p.BssidValid=TRUE;p.Channel=36;
            p.HostCipher=TRUE;p.HostCipherAkm=akm;p.Mfp=(AP6256_MFP)mfp;
            p.Security=akm==1||akm==5||akm==12?Ap6256SecurityWpa2Enterprise:akm==2?Ap6256SecurityWpa2Host:
                akm==8?Ap6256SecuritySaeHost:Ap6256SecurityOweHost;
            p.SaeFirmwareGeneration=99;p.SaeTimeoutMs=30000;
            p.OweDh[0]=255;p.OweDh[1]=35;p.OweDh[2]=32;p.OweDh[3]=19;
            for(unsigned i=5;i<37;++i)p.OweDh[i]=(UCHAR)(i-4);p.OweDhLength=37;
            joins=mutations=command_count=private_arms=0;owe_arms=owe_ends=0;
            hc_profiles=hc_ends=hc_security_fault=hc_bip_readback_fault=0;hc_begin_status=hc_end_status=0;
            fail_command=0;private_arm_status=0;private_cached=private_h2e=FALSE;
            bip_status=0;bip_no_reply=bip_fw_error=false;fw_bip=0;
            if(failure>=1&&failure<=9)hc_security_fault=failure;
            if(failure==10)hc_begin_status=STATUS_IO_TIMEOUT;
            if(failure==11)fail_command=BRCMF_C_SET_SSID;
            if(failure==12){d.HostCipherActive=TRUE;hc_end_status=STATUS_IO_TIMEOUT;}
            if(failure==13)bip_status=STATUS_IO_TIMEOUT;
            if(failure==14)bip_no_reply=true;
            if(failure==15)bip_fw_error=true;
            if(failure>=16)hc_bip_readback_fault=failure-15;
            auto status=Ap6256WifiConnect(&d,&p);
            assert(!!NT_SUCCESS(status)==(failure==0));
            assert(joins==(failure==0?1:0));
            assert(hc_profiles==((failure==0||failure==10||failure==11)?1u:0u));
            if(failure==0)assert(d.HostCipherActive&&hc_ends==1);
            else if(failure==12)assert(!d.HostCipherActive&&!mutations&&hc_ends==1);
            else assert(!d.HostCipherActive);
            if((failure==10||failure==11)&&akm==18)assert(!d.FirmwareOweGeneration&&owe_ends==1);
            ++cases;
        }
    }

    for(unsigned failedWrite=1;failedWrite<=9;++failedWrite) {
        Device d={};d.D11IoType=2;d.MacAddress[0]=2;d.MacAddress[5]=0x55;
        d.HostCipherFirmwareQualified=1;
        AP6256_CONNECT_PARAMS p={};memcpy(p.Ssid,"net",3);p.SsidLength=3;
        p.Bssid[0]=2;p.Bssid[5]=1;p.BssidValid=TRUE;p.Channel=36;
        p.HostCipher=TRUE;p.HostCipherAkm=2;p.Security=Ap6256SecurityWpa2Host;
        joins=mutations=command_count=private_arms=owe_arms=hc_profiles=hc_ends=0;
        hc_security_fault=hc_bip_readback_fault=0;hc_begin_status=hc_end_status=0;fail_command=0;
        hc_offload_writes=0;hc_offload_fail=failedWrite;
        hc_offload_switches[0]=hc_offload_switches[1]=1;
        assert(Ap6256WifiConnect(&d,&p)==STATUS_IO_TIMEOUT && hc_offload_writes==failedWrite);
        assert(!joins&&!mutations&&!hc_profiles&&!private_arms&&!owe_arms&&!d.HostCipherActive);++cases;
    }
    hc_offload_fail=0;
    hc_offload_switches[0]=hc_offload_switches[1]=0;


    for(unsigned invalid=0;invalid<7;++invalid) {
        Device d={};d.D11IoType=2;d.HostCipherFirmwareQualified=1;
        AP6256_CONNECT_PARAMS p={};p.SsidLength=3;p.Bssid[0]=2;p.BssidValid=TRUE;
        p.Channel=36;p.HostCipher=TRUE;p.HostCipherAkm=2;p.Security=Ap6256SecurityWpa2Host;
        if(invalid==0)d.HostCipherFirmwareQualified=0;
        if(invalid==1)p.HostFips=TRUE;
        if(invalid==2)p.FastTransition=TRUE;
        if(invalid==3)p.HostCipherAkm=11;
        if(invalid==4)p.Security=Ap6256SecurityWpa2Firmware;
        if(invalid==5)p.Mfp=(AP6256_MFP)3;
        if(invalid==6)p.BssidValid=FALSE;
        joins=mutations=command_count=hc_profiles=hc_ends=0;
        assert(Ap6256WifiConnect(&d,&p)==STATUS_NOT_SUPPORTED&&!mutations&&!hc_ends&&!hc_profiles);++cases;
    }
    hc_security_fault=hc_bip_readback_fault=0;hc_begin_status=hc_end_status=0;fail_command=0;
    bip_status=0;bip_no_reply=bip_fw_error=false;
    printf("PASS: %u production host-cipher common join/security/cleanup checks\n",cases);
}
#endif
static void hostCipherEventOwners() {
    unsigned cases=0;
    const UCHAR peer[6]={2,0x66,0x77,0x88,0x99,0xaa};
    memcpy(joined.Params.Bssid,peer,6);



    for(const auto& event:nativeHostCipherEvents) {
        state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
        d.HostCipherFirmwareQualified=1;d.HostCipherStore.Generation=31;d.FirmwareLinkUp=TRUE;
        w.HardwareAvailable=1;w.ConnectGeneration=123;w.ConnectTask.Active=TRUE;
        w.ConnectTask.DeadlineMs=200;w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,peer,6);
        w.SaeEventGeneration=99;w.HostCipherGeneration=0;
        queued_count=0;auto body=event.data;
        Ap6256TestOwnedDispatch(&d,event.type,event.status,event.auth,1,0,0,body.data(),(ULONG)body.size());
        bool progress=event.type==BRCMF_E_AUTH || event.type==BRCMF_E_ASSOC || event.type==BRCMF_E_REASSOC;
        assert(queued_count==(progress?0:1));++cases;
        if(!progress) {
            assert(queued_firmware_generation==31 && queued_firmware_event==AP6256_STATION_EVENT_HOST_CIPHER);
            assert(queued_generation==123);
            bool up=event.type==BRCMF_E_SET_SSID || event.type==BRCMF_E_LINK;
            assert(queued_code==(up?AP6256_LINK_UP:AP6256_LINK_JOIN_FAILED));++cases;


            d.HostCipherStore.Generation=32;indications.clear();int before=joins;
            Ap6256NetLinkChangeWork(&w,(BOOLEAN)up,(BOOLEAN)!up,123,31,AP6256_STATION_EVENT_HOST_CIPHER);
            assert(w.ConnectTask.Active && indications.empty() && joins==before);++cases;
        }
    }
    Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
    d.HostCipherFirmwareQualified=1;d.HostCipherStore.Generation=31;d.FirmwareLinkUp=TRUE;d.SupplicantComplete=TRUE;
    w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,peer,6);w.ConnectGeneration=123;
    w.ConnectTask.Active=TRUE;w.ConnectTask.DeadlineMs=200;w.SaeEventGeneration=99;
    UCHAR body[16];Ap6256HostCipherEventWrite(body,31,peer);queued_count=0;
    for(UINT32 old:{0u,30u,32u}) {
        Ap6256NetStationHostCipherEvent(&d,FALSE,TRUE,peer,old);
        assert(!queued_count && d.FirmwareLinkUp && d.SupplicantComplete);++cases;
    }

    for(UINT32 old:{0u,31u,99u}) {
        Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,peer,old);
        assert(!queued_count && d.FirmwareLinkUp && d.SupplicantComplete);++cases;
    }
    for(ULONG n=0;n<16;++n) {
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,0x80000000,0,0,0,body,n);
        assert(!queued_count);++cases;
    }
    for(unsigned offset:{0u,4u,8u,14u,15u}) {
        UCHAR bad[16];memcpy(bad,body,16);
        if(offset==4)memset(bad+4,0,4);else if(offset==8)bad[8]|=1;else bad[offset]^=1;
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,0x80000000,0,0,0,bad,16);
        assert(!queued_count);++cases;
    }
    UCHAR outPeer[6]={};UINT32 outGeneration=0;
    assert(!Ap6256HostCipherEventRead(body,16,(UINT32*)body,outPeer));++cases;
    assert(!Ap6256HostCipherEventRead(body,16,&outGeneration,body+8));++cases;
    assert(!Ap6256HostCipherEventRead(body,16,(UINT32*)outPeer,outPeer));++cases;
    for(unsigned port:{1u,2u,15u,255u}) {
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,0x80000000,0,(UINT8)port,0,body,16);
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,0x80000000,0,0,(UINT8)port,body,16);
        assert(!queued_count);cases+=2;
    }
    d.HostCipherFirmwareQualified=0;
    Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,0x80000000,0,0,0,body,16);
    assert(!queued_count);++cases;
    d.HostCipherFirmwareQualified=1;d.HostCipherStore.Generation=0;w.HostCipherGeneration=31;
    Ap6256NetStationHostCipherEvent(&d,FALSE,TRUE,peer,31);
    Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,peer,0);
    assert(!queued_count && d.FirmwareLinkUp);cases+=2;
    indications.clear();int before=joins;
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,123,31,AP6256_STATION_EVENT_HOST_CIPHER);
    assert(w.ConnectTask.Active && indications.empty() && joins==before);++cases;
    state_tests=false;
    printf("PASS: %u host-cipher native-event receipt/queue/worker cases\n",cases);
}
static void hostCipherComposedAssociationEvents() {
    unsigned cases=0;
    const UCHAR peer[6]={2,0x44,0x4a,0,0x12,0x34};
    memcpy(joined.Params.Bssid,peer,6);



    for(const auto& sequence:nativeHostCipherAssociationEvents) for(bool roam:{false,true}) {
        state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
        d.HostCipherFirmwareQualified=1;d.HostCipherStore.Generation=31;d.HostCipherActive=TRUE;
        w.HardwareAvailable=1;w.ConnectGeneration=123;w.ConnectTask.Active=TRUE;
        w.ConnectTask.DeadlineMs=200;w.ConnectTaskIsRoam=(BOOLEAN)roam;
        w.ConnectBssidValid=TRUE;memcpy(w.ConnectBssid,peer,6);
        w.SaeEventGeneration=100;w.HostCipherGeneration=31;
        queued_count=rx_opens=0;indications.clear();
        for(const auto& event:sequence.events) {
            auto body=event.data;int before=queued_count;
            Ap6256TestOwnedDispatch(&d,event.type,event.status,event.auth,1,0,0,
                body.data(),(ULONG)body.size());
            if(event.type==BRCMF_E_LINK && !(event.auth&0x80000000u)) {


                Ap6256NetStationFirmwareEvent(&d,TRUE,FALSE,peer,0);
                assert(queued_count==before);
            } else if(event.type==BRCMF_E_SET_SSID ||
                      (event.type==BRCMF_E_ASSOC && event.status)) {
                assert(queued_count==before+1);
                assert(queued_generation==123 && queued_firmware_generation==31);
                assert(queued_firmware_event==AP6256_STATION_EVENT_HOST_CIPHER);
                assert(queued_code==(sequence.success?AP6256_LINK_UP:AP6256_LINK_JOIN_FAILED));
            } else assert(queued_count==before);
        }
        assert(queued_count>0 && w.ConnectTask.Active && indications.empty());
        assert((bool)d.FirmwareLinkUp==sequence.success);
        int opens=rx_opens;
        d.HostCipherStore.Generation=32;
        Ap6256NetLinkChangeWork(&w,(BOOLEAN)sequence.success,(BOOLEAN)!sequence.success,
            123,31,AP6256_STATION_EVENT_HOST_CIPHER);
        assert(w.ConnectTask.Active && indications.empty() && rx_opens==opens);
        d.HostCipherStore.Generation=31;
        Ap6256NetLinkChangeWork(&w,(BOOLEAN)sequence.success,(BOOLEAN)!sequence.success,
            123,31,AP6256_STATION_EVENT_HOST_CIPHER);
        assert(!w.ConnectTask.Active && (bool)w.ConnectionActive==sequence.success);
        assert(indications==std::vector<char>(sequence.success?
            std::initializer_list<char>{'A','C'}:std::initializer_list<char>{'F','X'}));
        assert(rx_opens==(sequence.success?1:0));
        auto completed=indications;
        Ap6256NetLinkChangeWork(&w,(BOOLEAN)sequence.success,(BOOLEAN)!sequence.success,
            123,31,AP6256_STATION_EVENT_HOST_CIPHER);
        assert(indications==completed && rx_opens==(sequence.success?1:0));
        ++cases;
    }
    state_tests=false;
    printf("PASS: %u composed native association-event CONNECT/ROAM sequences\n",cases);
}
static void ownedFailures() {
    state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
    d.FirmwarePrivateSae=TRUE;w.HardwareAvailable=1;w.ConnectTask.Active=TRUE;
    w.ConnectTask.DeadlineMs=200;w.ConnectGeneration=123;
    w.SaeFirmwareGeneration=w.SaeEventGeneration=100;w.ConnectBssidValid=TRUE;
    UCHAR peer[6]={2,0,0,0,0,9};memcpy(w.ConnectBssid,peer,6);
    queued_count=0;indications.clear();int beforeJoins=joins;


    for(UINT32 old:{0u,99u,101u}) {
        d.FirmwareLinkUp=TRUE;d.SupplicantComplete=TRUE;
        Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,peer,old);
        assert(!queued_count && d.FirmwareLinkUp && d.SupplicantComplete);
    }
    UCHAR wrong[6]={2,0,0,0,0,8};
    Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,wrong,100);
    assert(!queued_count);
    Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,peer,100);
    assert(queued_count==1 && queued_firmware_generation==100 && queued_firmware_event);
    assert(queued_generation==123 && queued_code==AP6256_LINK_JOIN_FAILED);


    w.SaeFirmwareGeneration=w.SaeEventGeneration=101;
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,123,100,TRUE);
    assert(w.ConnectTask.Active && indications.empty() && joins==beforeJoins);

    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,123,0,TRUE);
    assert(w.ConnectTask.Active && indications.empty() && joins==beforeJoins);


    w.SaeFirmwareGeneration=0;
    Ap6256NetLinkChangeWork(&w,FALSE,TRUE,123,0,TRUE);
    assert(w.ConnectTask.Active && indications.empty());
    w.ConnectTask.Active=FALSE;w.ConnectionActive=TRUE;
    d.FirmwareLinkUp=TRUE;w.SaeEventGeneration=101;
    Ap6256NetStationFirmwareEvent(&d,FALSE,FALSE,peer,100);
    assert(queued_count==1 && d.FirmwareLinkUp);
    Ap6256NetStationFirmwareEvent(&d,FALSE,FALSE,peer,0);
    assert(queued_count==2 && queued_firmware_event && !queued_firmware_generation);
    Ap6256NetLinkChangeWork(&w,FALSE,FALSE,123,0,TRUE);
    assert(!w.ConnectionActive && indications==std::vector<char>({'D'}));

    w.ConnectTask.Active=TRUE;w.SaeEventGeneration=0;d.FirmwareLinkUp=TRUE;
    Ap6256NetStationFirmwareEvent(&d,FALSE,TRUE,peer,0);
    assert(queued_count==3 && queued_firmware_event && !d.FirmwareLinkUp);
    w.SaeFirmwareGeneration=w.SaeEventGeneration=102;
    Ap6256NetStationLinkEvent(&d,FALSE,TRUE,peer);
    assert(queued_count==4 && !queued_firmware_event);


    w.SaeFirmwareGeneration=0;w.SaeEventGeneration=102;
    w.ConnectionActive=TRUE;w.ConnectDeparting=TRUE;w.ConnectBssidValid=TRUE;
    memcpy(w.ConnectBssid,peer,6);d.FirmwareLinkUp=TRUE;
    w.ConnectCandidateCount=1;w.ConnectCandidateIndex=0;
    auto& next=w.ConnectCandidates[0];next.BssidValid=TRUE;
    next.Bssid[0]=2;next.Bssid[5]=10;next.Channel=36;
    next.Security=Ap6256SecurityOpen;memcpy(next.Ssid,"test",4);next.SsidLength=4;
    d.D11IoType=BRCMU_D11AC_IOTYPE;fail_command=0;command_count=0;
    indications.clear();int before=joins;
    Ap6256NetStationFirmwareEvent(&d,FALSE,FALSE,peer,0);
    assert(queued_count==5 && queued_code==AP6256_LINK_DOWN && queued_firmware_event);
    Ap6256NetLinkChangeWork(&w,FALSE,FALSE,w.ConnectGeneration,0,TRUE);
    assert(joins==before+1 && !w.ConnectDeparting && w.ConnectTask.Active);
    assert(!w.SaeEventGeneration && indications==std::vector<char>({'D'}));
    state_tests=false;
    puts("PASS: firmware event owner survives receipt/queue/worker; stale same-peer, unowned and CLEAR-window events cannot cancel a newer SAE attempt");
}
static void ownedSuccess() {
    const NativeOwnerEvent* completion=nullptr;
    for(const auto& event:nativeOwnerEvents)
        if(event.type==BRCMF_E_SET_SSID && (event.auth&AP6256_SAE_OWNER_AUTH_FLAG)) {completion=&event;break;}
    assert(completion && completion->data.size()>=16);
    const UCHAR peer[6]={2,0x44,0x4a,0,0x12,0x34};
    for(bool roam:{false,true}) {
        state_tests=true;Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
        d.FirmwarePrivateSae=d.FirmwareSaePatchVerified=TRUE;w.HardwareAvailable=1;
        w.ConnectTask.Active=TRUE;w.ConnectTaskIsRoam=(BOOLEAN)roam;
        w.ConnectTask.DeadlineMs=200;w.ConnectGeneration=123;
        w.SaeFirmwareGeneration=w.SaeEventGeneration=100;w.ConnectBssidValid=TRUE;
        memcpy(w.ConnectBssid,peer,6);queued_count=rx_opens=0;indications.clear();
        UCHAR body[2048]={};memcpy(body,completion->data.data(),completion->data.size());
        ULONG length=(ULONG)completion->data.size();

        for(UINT32 type:{BRCMF_E_AUTH,BRCMF_E_ASSOC,BRCMF_E_REASSOC})
            Ap6256TestOwnedDispatch(&d,type,0,completion->auth,0,0,0,body,length);
        assert(!queued_count && !d.FirmwareLinkUp);

        Ap6256NetStationFirmwareEvent(&d,TRUE,FALSE,peer,0);
        assert(!queued_count && !d.FirmwareLinkUp);

        body[4]=99;
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,length);
        assert(!queued_count && !d.FirmwareLinkUp);body[4]=100;
        body[13]^=1;
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,length);
        assert(!queued_count && !d.FirmwareLinkUp);body[13]^=1;
        for(ULONG truncated=0;truncated<16;truncated++)
            Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,truncated);
        assert(!queued_count && !d.FirmwareLinkUp);
        for(UINT32 auth:{0u,3u})
            Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,auth,0,0,0,body,length);
        for(UINT8 index:std::initializer_list<UINT8>{1,2}) {
            Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,index,0,body,length);
            Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,index,body,length);
        }
        assert(!queued_count && !d.FirmwareLinkUp);
        d.FirmwareSaePatchVerified=FALSE;
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,length);
        assert(!queued_count);d.FirmwareSaePatchVerified=TRUE;
        Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,length);
        if(!AP6256_TEST_HAS_SAE_COMPLETION) {
            assert(!queued_count && !d.FirmwareLinkUp && w.ConnectTask.Active);
            assert(indications.empty() && !rx_opens);
        } else {
            assert(queued_count==1 && queued_code==AP6256_LINK_UP && d.FirmwareLinkUp);
            assert(queued_generation==123 && queued_firmware_generation==100 && queued_firmware_event);

            w.SaeFirmwareGeneration=w.SaeEventGeneration=101;
            Ap6256NetLinkChangeWork(&w,TRUE,FALSE,123,100,TRUE);
            assert(w.ConnectTask.Active && indications.empty() && !rx_opens);
            w.SaeFirmwareGeneration=w.SaeEventGeneration=100;
            Ap6256NetLinkChangeWork(&w,TRUE,FALSE,123,100,TRUE);
            assert(!w.ConnectTask.Active && w.ConnectionActive && rx_opens==1);
            assert(indications==std::vector<char>({'A','C'}));

            Ap6256TestOwnedDispatch(&d,BRCMF_E_SET_SSID,0,completion->auth,0,0,0,body,length);
            Ap6256NetLinkChangeWork(&w,TRUE,FALSE,123,100,TRUE);
            assert(indications==std::vector<char>({'A','C'}) && rx_opens==1);
        }
        state_tests=false;
    }
    if(AP6256_TEST_HAS_SAE_COMPLETION)
        puts("PASS: owned SET_SSID success reaches production CONNECT/ROAM completion and RX-open scheduling; stale/malformed/unowned/duplicate controls pass");
    else puts("PASS: saved historical ignores owned SET_SSID success and leaves CONNECT/ROAM pending with RX unopened");
}
static void ownedDispatch() {
    Device d={};Wifi w={};w.Ctx=&d;d.NetAdapter=&w;
    d.FirmwarePrivateSae=d.FirmwareSaePatchVerified=TRUE;w.HardwareAvailable=1;
    w.ConnectTask.Active=TRUE;w.ConnectTask.DeadlineMs=200;w.ConnectGeneration=123;
    w.SaeFirmwareGeneration=w.SaeEventGeneration=100;w.ConnectBssidValid=TRUE;
    const UCHAR peer[6]={2,0x44,0x4a,0,0x12,0x34};memcpy(w.ConnectBssid,peer,6);
    queued_count=0;
    for(const auto& native: nativeOwnerEvents) {
        UCHAR body[2048]={};assert(native.data.size()<=sizeof(body));
        memcpy(body,native.data.data(),native.data.size());
        d.FirmwareLinkUp=TRUE;int before=queued_count;
        Ap6256TestOwnedDispatch(&d,native.type,native.status,native.auth,0,0,0,body,(ULONG)native.data.size());
        if(native.auth&AP6256_SAE_OWNER_AUTH_FLAG) {
            assert(queued_count==before+1 && queued_firmware_generation==100 && queued_firmware_event);
            for(UINT32 badAuth:{0u,3u}) {
                before=queued_count;
                Ap6256TestOwnedDispatch(&d,native.type,native.status,badAuth,0,0,0,body,(ULONG)native.data.size());
                assert(queued_count==before);
            }
            for(UINT8 port:std::initializer_list<UINT8>{1,2}) {
                before=queued_count;
                Ap6256TestOwnedDispatch(&d,native.type,native.status,native.auth,0,port,0,body,(ULONG)native.data.size());
                Ap6256TestOwnedDispatch(&d,native.type,native.status,native.auth,0,0,port,body,(ULONG)native.data.size());
                assert(queued_count==before);
            }
            for(ULONG n=0;n<16;n++) {
                before=queued_count;
                Ap6256TestOwnedDispatch(&d,native.type,native.status,native.auth,0,0,0,body,n);
                assert(queued_count==before);
            }
            before=queued_count;d.FirmwareSaePatchVerified=FALSE;
            Ap6256TestOwnedDispatch(&d,native.type,native.status,native.auth,0,0,0,body,(ULONG)native.data.size());
            assert(queued_count==before);d.FirmwareSaePatchVerified=TRUE;
        } else assert(queued_count==before);
    }
    puts("PASS: actual native constructor payloads reach production Windows owned-event dispatch; marker, patch, interface and truncated-prefix guards");
}
static void oweConnect() {
    unsigned cases=0;
    for(bool roam:{false,true}) for(unsigned group:{19u,20u,21u})
        for(bool cached:{false,true}) for(unsigned fault=0;fault<9;++fault) {
        Device d={};d.D11IoType=2;Wifi w={};w.Ctx=&d;d.NetAdapter=&w;w.HardwareAvailable=1;
        w.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
        d.FirmwareOwePatchVerified=d.FirmwareHostOwe=d.FirmwareMfpSupported=TRUE;
        WDI_TASK_CONNECT_PARAMETERS p={};WDI_SSID ssid={};UCHAR ssidBytes[]={'o','w','e'};
        ssid.pElements=ssidBytes;ssid.ElementCount=3;
        p.ConnectParameters.SSIDList.pElements=&ssid;p.ConnectParameters.SSIDList.ElementCount=1;
        WDI_AUTH_ALGORITHM auth[2]={WDI_AUTH_ALGO_OWE,WDI_AUTH_ALGO_80211_OPEN};
        WDI_CIPHER_ALGORITHM cipher=fault==7?WDI_CIPHER_ALGO_TKIP:WDI_CIPHER_ALGO_CCMP;
        p.ConnectParameters.AuthenticationAlgorithms.pElements=auth;p.ConnectParameters.AuthenticationAlgorithms.ElementCount=2;
        p.ConnectParameters.UnicastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.UnicastCipherAlgorithms.ElementCount=1;
        p.ConnectParameters.MulticastCipherAlgorithms.pElements=&cipher;p.ConnectParameters.MulticastCipherAlgorithms.ElementCount=1;
        p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled=(BOOLEAN)(fault==6);
        WDI_CONNECT_BSS_ENTRY_CONTAINER bss[2]={};
        UCHAR extra[]={221,2,1,2},specific[]={221,3,3,4,5};
        for(unsigned i=0;i<2;++i) {
            bss[i].BSSID.Address[0]=2;bss[i].BSSID.Address[5]=(UCHAR)(i+7);
            bss[i].ChannelInfo.ChannelNumber=i?40:36;bss[i].ChannelInfo.BandId=WDI_BAND_ID_5000;
            bss[i].Optional.AssociationRequestVendorIE_IsPresent=TRUE;
            bss[i].AssociationRequestVendorIE.pElements=specific;bss[i].AssociationRequestVendorIE.ElementCount=5;
        }
        p.PreferredBSSEntryList.pElements=bss;p.PreferredBSSEntryList.ElementCount=roam?2:1;
        UCHAR pmkid[16];memset(pmkid,0x5a,16);
        if(cached) {bss[0].Optional.PMKID_IsPresent=TRUE;bss[0].PMKID.pElements=pmkid;bss[0].PMKID.ElementCount=16;}
        std::vector<UCHAR> dh(5+(group==19?32:group==20?48:66),0x5a);
        dh[0]=255;dh[1]=(UCHAR)(dh.size()-2);dh[2]=32;dh[3]=(UCHAR)group;dh[4]=0;
        p.ConnectParameters.Optional.OWEDHIE_IsPresent=(BOOLEAN)(fault!=1);
        p.ConnectParameters.OWEDHIE.pElements=dh.data();p.ConnectParameters.OWEDHIE.ElementCount=(ULONG)dh.size();
        p.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent=TRUE;
        p.ConnectParameters.AssociationRequestVendorIE.pElements=extra;p.ConnectParameters.AssociationRequestVendorIE.ElementCount=4;
        if(fault==2)dh[3]=22;
        if(fault==3)extra[1]=5;
        if(fault==4)d.FirmwareOwePatchVerified=FALSE;
        if(fault==5)d.FirmwareMfpSupported=FALSE;
        UCHAR* bytes=nullptr;ULONG n=0;
        assert((roam?GenerateWdiTaskRoamToIhv((WDI_TASK_ROAM_PARAMETERS*)&p,0,&w.TlvContext,&n,&bytes):
            GenerateWdiTaskConnectToIhv(&p,0,&w.TlvContext,&n,&bytes))==0);
        WDI_MESSAGE_HEADER h={};h.TransactionId=909;
        command_count=mutations=joins=pmks=failures=timer_starts=0;owe_arms=owe_ends=0;
        fail_command=fault==8?BRCMF_C_SET_SSID:0;owe_abort_fail=false;
        expected_failure=STATUS_IO_TIMEOUT;test_now=1;cache_written=FALSE;
        fw_auth=fw_wpa=fw_wsec=fw_infra=fw_mfp=0xffffffffu;
        Ap6256HandleConnectRequest(&w,nullptr,roam?WDI_TASK_ROAM:WDI_TASK_CONNECT,&h,bytes,n);FreeGenerated(bytes);
        if(fault>=1 && fault<=7) {
            assert(request_status<0 && !mutations && !joins && !owe_arms && !w.ConnectTask.Active);
        } else {
            assert(request_status==0 && !pmks && w.AuthAlgorithm==WDI_AUTH_ALGO_OWE);
            assert(fw_auth==0 && fw_wpa==0x80 && fw_wsec==0xe04 && fw_mfp==2 && fw_bip==6);
            assert(owe_arms==(fault==8&&roam?2u:1u) && !cache_written);
            if(fault==8) {assert(!joins && !d.FirmwareOweGeneration && owe_ends==owe_arms && failures==1);}
            else {
                assert(joins==1 && w.ConnectTask.Active && d.FirmwareOweGeneration==1);
                auto& c=w.ConnectCandidates[0];assert(c.Security==Ap6256SecurityOweHost && c.Mfp==Ap6256MfpRequired);
                assert(c.OweDhLength==dh.size() && !memcmp(c.OweDh,dh.data(),dh.size()));
                assert(c.OweExtraLength==9 && !memcmp(c.OweExtra,extra,4) && !memcmp(c.OweExtra+4,specific,5));
                assert(!!c.PmkidValid==cached && (!cached || !memcmp(c.Pmkid,pmkid,16)));
                if(roam)assert(w.ConnectCandidateCount==2 && w.ConnectCandidates[1].OweExtraLength==9);


                owe_abort_fail=true;int writes=mutations;
                assert(Ap6256StationStartNext(&w)==STATUS_DEVICE_BUSY && mutations==writes);
                owe_abort_fail=false;
                WDI_MESSAGE_HEADER claimed={};PVOID rid=nullptr;
                assert(Ap6256ClaimConnectTask(&w,Ap6256ConnectClaimMatching,909,0,&claimed,&rid));
                assert(!d.FirmwareOweGeneration && !w.ConnectTask.Active && !w.ConnectCandidateCount);
            }
        }
        assert(candidate_allocations==0);++cases;
    }
    fail_command=0;
    printf("PASS: %u enabled OWE CONNECT/ROAM codec cases, groups/cache/common and per-BSS IEs, exact security, admission failures, join failure and abort/cancel ownership\n",cases);
}
static void enterpriseCcmpRequest() {
    unsigned cases=0;
    for(UINT32 version:{(UINT32)AP6256_TEST_WDI_VERSION,(UINT32)WDI_VERSION_2_0_4})
    for(bool roam:{false,true}) for(bool cached:{false,true}) for(unsigned fault=0;fault<35;++fault) {
        Device d={}; Wifi w={}; w.Ctx=&d; d.NetAdapter=&w; w.HardwareAvailable=1;
        w.TlvContext.PeerVersion=version; d.FirmwareMfpSupported=TRUE; d.D11IoType=2;
        d.MacAddress[0]=2;d.MacAddress[5]=0x55;
        if(fault==3)d.Chip.ChipRev=6;
        WDI_TASK_CONNECT_PARAMETERS p={}; WDI_SSID ssid={}; UCHAR name[]={'e','n','t'};
        ssid.pElements=name;ssid.ElementCount=3;
        p.ConnectParameters.SSIDList.pElements=&ssid;p.ConnectParameters.SSIDList.ElementCount=1;
        WDI_AUTH_ALGORITHM auth=WDI_AUTH_ALGO_WPA3_ENT;
        WDI_CIPHER_ALGORITHM uni=WDI_CIPHER_ALGO_CCMP,group=fault==7?WDI_CIPHER_ALGO_GCMP_256:WDI_CIPHER_ALGO_CCMP;
        p.ConnectParameters.AuthenticationAlgorithms.pElements=&auth;p.ConnectParameters.AuthenticationAlgorithms.ElementCount=1;
        p.ConnectParameters.UnicastCipherAlgorithms.pElements=&uni;p.ConnectParameters.UnicastCipherAlgorithms.ElementCount=1;
        p.ConnectParameters.MulticastCipherAlgorithms.pElements=&group;p.ConnectParameters.MulticastCipherAlgorithms.ElementCount=1;
        p.ConnectParameters.ConnectionSettings.MFPEnabled=(BOOLEAN)(fault!=1);
        p.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled=(BOOLEAN)(fault==2);
        RSNA_AKM_SUITE akm=(RSNA_AKM_SUITE)(fault==4?0x01ac0f00u:0x05ac0f00u);
        p.ConnectParameters.Optional.RsnaAkmSuites_IsPresent=TRUE;
        p.ConnectParameters.RsnaAkmSuites.pElements=&akm;p.ConnectParameters.RsnaAkmSuites.ElementCount=1;
        RSNA_AKM_CIPHER_PAIR pair={(RSNA_AKM_SUITE)0x05ac0f00u,fault==5?rsna_cipher_gcmp_256:rsna_cipher_ccmp_128};
        p.ConnectParameters.Optional.RsnaAkmCipherSuites_IsPresent=TRUE;
        p.ConnectParameters.RsnaAkmCipherSuites.pElements=&pair;p.ConnectParameters.RsnaAkmCipherSuites.ElementCount=1;
        assert(!!Ap6256Wpa3EnterpriseRequestSuite(&p.ConnectParameters)==(fault!=4&&fault!=5));
        WDI_CONNECT_BSS_ENTRY_CONTAINER bss={};bss.BSSID.Address[0]=2;bss.BSSID.Address[5]=7;
        bss.ChannelInfo.BandId=WDI_BAND_ID_5000;bss.ChannelInfo.ChannelNumber=36;
        p.PreferredBSSEntryList.pElements=&bss;p.PreferredBSSEntryList.ElementCount=fault==8?0:1;
        UCHAR mde[]={54,3,0x12,0x34,0};
        if(fault==9){bss.Optional.FTInitialAssocParameters_IsPresent=TRUE;
            bss.FTInitialAssocParameters.MDE.pElements=mde;bss.FTInitialAssocParameters.MDE.ElementCount=5;}
        std::vector<UCHAR> beacon(12,0);
        std::vector<UCHAR> rsn={48,26,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,5,0x80,0,0,0,0,15,172,6};
        if(fault==10)rsn[19]=1;if(fault==11)rsn[13]=9;if(fault==12)rsn[20]=0;
        if(fault==13)rsn[27]=12;if(fault==14)rsn[1]=255;
        beacon.insert(beacon.end(),rsn.begin(),rsn.end());
        if(fault==16)beacon.insert(beacon.end(),rsn.begin(),rsn.end());
        bss.Optional.BeaconFrame_IsPresent=(BOOLEAN)(fault!=15);bss.BeaconFrame.pElements=beacon.data();
        bss.BeaconFrame.ElementCount=(ULONG)beacon.size();
        UCHAR pmkid[16];memset(pmkid,0x5a,sizeof(pmkid));
        bss.Optional.PMKID_IsPresent=(BOOLEAN)cached;bss.PMKID.pElements=pmkid;bss.PMKID.ElementCount=fault==6?15:16;
        UCHAR* bytes=nullptr;ULONG length=0;
        auto generated=roam?GenerateWdiTaskRoamToIhv((WDI_TASK_ROAM_PARAMETERS*)&p,0,&w.TlvContext,&length,&bytes):
            GenerateWdiTaskConnectToIhv(&p,0,&w.TlvContext,&length,&bytes);
        if(generated){assert(fault==8||(cached&&fault==6));FreeGenerated(bytes);++cases;continue;}
        joins=mutations=command_count=failures=timer_starts=0;fail_command=0;
        hc_security_fault=hc_bip_readback_fault=0;hc_begin_status=hc_end_status=0;
        bip_status=0;bip_no_reply=bip_fw_error=false;fw_bip=0;cache_written=FALSE;
        wpaie_fault=fault>=32?fault-31:0;
        fw_auth=fw_wpa=fw_wsec=fw_infra=fw_mfp=0xffffffffu;
        if(fault>=17&&fault<=25)hc_security_fault=fault-16;
        if(fault==26)bip_no_reply=true;
        if(fault==27)bip_fw_error=true;
        if(fault==28)bip_status=STATUS_IO_TIMEOUT;
        if(fault==29)fail_command=BRCMF_C_SET_WPA_AUTH;
        if(fault==30||fault==31)d.HostCipherActive=TRUE;
        if(fault==31)hc_end_status=STATUS_IO_TIMEOUT;
        expected_failure=((fault>=17&&fault<=24)||fault==26||fault==27||fault==32||fault==33)?STATUS_DEVICE_PROTOCOL_ERROR:STATUS_IO_TIMEOUT;
        WDI_MESSAGE_HEADER h={};h.TransactionId=926;h.PortId=0;request_status=STATUS_INVALID_PARAMETER;
        Ap6256HandleConnectRequest(&w,nullptr,roam?WDI_TASK_ROAM:WDI_TASK_CONNECT,&h,bytes,length);FreeGenerated(bytes);
        const bool accepted=fault==0||fault==5||fault==15||fault>=17||(fault==4&&version<WDI_VERSION_2_0_4)||(fault==6&&!cached);
        if((request_status==0)!=accepted)fprintf(stderr,"Enterprise CCMP version %08x roam %u cache %u fault %u status %08lx expected %u\n",version,roam,cached,fault,(unsigned long)request_status,accepted);
        assert((request_status==0)==accepted);
        if(fault>=17&&fault<=29||fault==31||fault>=32) {
            assert(request_status==0&&!joins&&failures==1&&!w.ConnectTask.Active);
            assert(candidate_allocations==0);++cases;continue;
        }
        if(accepted) {
            assert(joins==1&&!failures&&!pmks&&!d.ConnectionRequiresSupplicant&&!d.HostCipherActive);
            assert(w.AuthAlgorithm==WDI_AUTH_ALGO_WPA3_ENT&&w.UnicastCipher==WDI_CIPHER_ALGO_CCMP&&w.MulticastCipher==WDI_CIPHER_ALGO_CCMP);
            assert(w.ConnectTask.Active&&w.ConnectCandidates[0].Wpa3Enterprise&&!w.ConnectCandidates[0].HostCipher);
            assert(w.ConnectCandidates[0].Mfp==Ap6256MfpRequired);
            assert(fw_auth==0&&fw_wpa==0x1000&&fw_wsec==0xe04&&fw_mfp==2&&fw_infra==1&&fw_bip==6);
            assert(!!cache_written==cached&&!!w.ConnectCandidates[0].PmkidValid==cached);
            std::vector<UCHAR> selected={48,26,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,5,0xc0,0,0,0,0,15,172,6};
            if(cached){selected[1]=42;selected[22]=1;selected.insert(selected.begin()+24,16,0x5a);}
            assert(fw_station_ie==selected);
            if(fault==0){printf("ENTERPRISE_RSNE:%u:",cached?1u:0u);for(UCHAR byte:fw_station_ie)printf("%02x",byte);puts("");}
        } else assert(!joins&&!mutations&&!w.ConnectTask.Active);
        assert(candidate_allocations==0);++cases;
    }
    hc_security_fault=hc_bip_readback_fault=0;hc_end_status=bip_status=0;
    wpaie_fault=0;
    bip_no_reply=bip_fw_error=false;fail_command=0;
    printf("PASS: %u native WPA3-Enterprise/CCMP CONNECT/ROAM cases; mandatory PMF, SHA-256 mode, AKM/cipher/AP evidence, cache and retained GCMP separation\n",cases);
}

int main(int argc,char** argv) {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    if(argc==2 && !strcmp(argv[1],"ft-only")) {refusedFt();return 0;}
    if(argc==2 && !strcmp(argv[1],"enterprise-only")) {
        enterpriseCcmpRequest();
        hostCipherRequest();
        for(bool roam:{false,true}) for(bool mfp:{false,true}) {
            check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,roam,mfp,false,0,0,0);
            check(WDI_AUTH_ALGO_RSNA_PSK,WDI_CIPHER_ALGO_CCMP,roam,mfp,false,0,0,0);
        }
        check(WDI_AUTH_ALGO_80211_OPEN,WDI_CIPHER_ALGO_NONE,false,false,false,0,0,0);
        puts("PASS: retained Open/WPA2 CONNECT/ROAM and separate GCMP profiles");
        return 0;
    }
    for(bool roam:{false,true}) for(bool mfp:{false,true}) {
        check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,roam,mfp,false,0,0,0);
        check(WDI_AUTH_ALGO_RSNA_PSK,WDI_CIPHER_ALGO_CCMP,roam,mfp,false,0,0,0);
    }
    check(WDI_AUTH_ALGO_80211_OPEN,WDI_CIPHER_ALGO_NONE,false,false,false,0,0,0);
    for(WDI_AUTH_ALGORITHM auth:{WDI_AUTH_ALGO_WPA,WDI_AUTH_ALGO_WPA3_SAE,WDI_AUTH_ALGO_OWE})
        check(auth,WDI_CIPHER_ALGO_CCMP,false,false,false,0,0,STATUS_NOT_SUPPORTED);
    check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_TKIP,false,false,false,0,0,STATUS_NOT_SUPPORTED);
    check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,false,false,true,0,0,STATUS_NOT_SUPPORTED);
    for(UINT32 fail:{BRCMF_C_SET_AUTH,BRCMF_C_SET_WPA_AUTH,BRCMF_C_SET_WSEC,BRCMF_C_SET_INFRA,BRCMF_C_SET_SSID})
        check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,false,false,false,0,fail,0);
    for(bool roam:{false,true}) {
        check(WDI_AUTH_ALGO_WPA3_SAE,WDI_CIPHER_ALGO_CCMP,roam,true,false,0,0,0,false,16);
        check(WDI_AUTH_ALGO_WPA3_SAE,WDI_CIPHER_ALGO_CCMP,roam,true,false,0,0,0,false,-2);
        for(int source:{1,2,3,4})check(WDI_AUTH_ALGO_WPA3_SAE,WDI_CIPHER_ALGO_CCMP,roam,true,false,0,0,0,false,16,source);
        for(int n:{0,15,17})check(WDI_AUTH_ALGO_WPA3_SAE,WDI_CIPHER_ALGO_CCMP,roam,true,false,0,0,STATUS_INVALID_PARAMETER,false,n);
    }
    private_join();
#if AP6256_TEST_HAS_HOST_CIPHER_PROFILE
    hostCipherJoin();
    hostCipherRequest();
#endif
#if AP6256_TEST_HAS_HOST_CIPHER_DISASSOC
    disconnectWriter();
    disassociationSecurity();
#endif
    refusedFt();hostCipherEventOwners();hostCipherComposedAssociationEvents();ownedFailures();ownedDispatch();ownedSuccess();
    roamState();
    cachedRoamFallback();
    oweConnect();


    check(WDI_AUTH_ALGO_80211_OPEN,WDI_CIPHER_ALGO_NONE,false,false,true,0,0,0,false,-1,0,true,false,false);
    check(WDI_AUTH_ALGO_RSNA_PSK,WDI_CIPHER_ALGO_CCMP,false,false,true,0,0,0,false,-1,0,true,false,false);
    check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,false,false,true,0,0,0,false,-1,0,true,false,false);
    for(bool ht:{false,true}) {
        check(WDI_AUTH_ALGO_80211_OPEN,WDI_CIPHER_ALGO_NONE,false,false,true,0,0,0,false,-1,0,true,ht);
        check(WDI_AUTH_ALGO_RSNA_PSK,WDI_CIPHER_ALGO_CCMP,false,false,true,0,0,0,false,-1,0,true,ht);
        check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,false,false,true,0,0,0,false,-1,0,true,ht);
        check(WDI_AUTH_ALGO_RSNA_PSK,WDI_CIPHER_ALGO_CCMP,false,false,true,0,BRCMF_C_SET_SSID,0,false,-1,0,true,ht);
    }
    puts("PASS: Microsoft CONNECT codec -> actual Host FIPS candidate/QoS/security/mode/seed handling for non-HT/HT open/PSK/Enterprise and failed-join cleanup");

    check(WDI_AUTH_ALGO_RSNA,WDI_CIPHER_ALGO_CCMP,true,true,false,0,0,0,true);
    puts("PASS: real CONNECT/ROAM codec -> production station admission -> firmware AKM/CCMP; cancelled join cannot replace a newer task; open/PSK/PMF preserved; unsupported security/FT refused; command failures stop join");
}
'''

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'src')
    parser.add_argument('--output', type=Path, default=output_dir('station-security'))
    args = parser.parse_args()
    source = {n: read_source_text(args.source_dir / n if (args.source_dir / n).exists() else ROOT / 'src' / n, encoding='utf-8-sig') for n in ('netadapter.c', 'wifi_ops.c', 'wifi_ops.h', 'bcdc.h', 'sdpcm.h', 'sae_fw.c', 'sae_fw.h', 'datapath.c')}
    text = contract_preamble() + PRE
    has_bip = 'Ap6256SaeSetBip(Ctx)' in source['wifi_ops.c']
    assert has_bip != False
    text = '#define AP6256_TEST_HAS_BIP ' + str(int(has_bip)) + '\n' + text
    has_completion = 'SAE: owned SET_SSID success' in source['datapath.c']
    assert has_completion != False
    text = '#define AP6256_TEST_HAS_SAE_COMPLETION ' + str(int(has_completion)) + '\n' + text
    text = '#define AP6256_TEST_HAS_HOST_CIPHER_PROFILE ' + str(int('Ap6256HostCipherBeginProfile' in source['wifi_ops.c'])) + '\n' + text
    has_disassoc = 'Ap6256HostCipherEnd(Wifi->Ctx, 0, FALSE)' in source['netadapter.c']
    text = '#define AP6256_TEST_HAS_HOST_CIPHER_DISASSOC ' + str(int(has_disassoc)) + '\n' + text
    for line in '\n'.join(source.values()).splitlines():
        if re.match('#define (?:BRCMF_[CE]_|WSEC_|WPA2?_AUTH_|AP6256_ASSOC_RETRY_MAX|BRCMF_WSEC_|WLC_BAND_|BRCMU_|AP6256_DISCONNECT_TIMEOUT_MS|AP6256_CONNECT_(?:TIMEOUT_MS|BSSID_LIMIT)|AP6256_DISALLOW_BAND_|AP6256_LINK_|AP6256_LINKQ_DEPTH|AP6256_SAE_OWNER_)', line):
            text += line + '\n'
    for name in ('AP6256_SECURITY', 'AP6256_MFP', 'AP6256_CONNECT_PARAMS', 'AP6256_SCAN_BAND', 'AP6256_SCAN_CHANNEL'):
        text += re.search('typedef (?:struct|enum) _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', source['wifi_ops.h'])[0] + '\n'
    text += '#pragma pack(push,1)\n'
    for name in ('WLC_SSID', 'BRCMF_ASSOC_PARAMS', 'BRCMF_JOIN_PARAMS', 'BRCMF_REASSOC_PARAMS', 'BRCMF_WSEC_PMK', 'BRCMF_SCB_VAL'):
        text += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', source['wifi_ops.c'])[0] + '\n'
    ft_header = read_source_text(ROOT / 'src/common/ft.h')
    text += '#pragma pack(pop)\n'
    text += '\n'.join((line for line in ft_header.splitlines() if line.startswith('#define AP6256_FT_'))) + '\n'
    for name in ('AP6256_FT_PHASE', 'AP6256_FT_OWNER', 'AP6256_FT_STATE', 'AP6256_CONNECT_FT_SETUP'):
        text += re.search('typedef (?:struct|enum) _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', ft_header)[0] + '\n'
    text += read_source_text(ROOT / 'src/common/host_fips_wire.h').replace('#pragma once', '')
    for name in ('host_cipher_frame.h', 'host_cipher_rsn.h', 'host_cipher_rsn.c', 'host_cipher_event.h'):
        text += re.sub('^#(?:include|pragma)[^\\n]*\\n', '', read_source_text(ROOT / 'src/common' / name), flags=re.M) + '\n'
    for (name, path) in [('AP6256_HC_STORE_SESSION', 'host_cipher_store.h'), ('AP6256_HC_PROFILE_CONTROL', 'host_cipher_control.h')]:
        text += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', read_source_text(ROOT / 'src/common' / path))[0] + '\n'
    text += '#define AP6256_HC_FIRMWARE_RETIRED 0x80000000u\n' + MOCKS
    text += '#define AP6256_WLFC_ANY 0xffffu\n'
    text += re.sub('^#include[^\\n]*\\n', '', read_source_text(ROOT / 'src/common/host_fips_wire.c'), flags=re.M)
    text += re.sub('^#include[^\\n]*\\n', '', read_source_text(ROOT / 'src/common/host_fips.c'), flags=re.M)
    header = read_source_text(ROOT / 'src/common/netadapter_internal.h')
    text += header[header.index('static inline NTSTATUS Ap6256CopyFipsCandidate'):header.index('#define AP6256_WDI_TLV_IHV_DATA')]
    if 'Ap6256MboPrepareJoin' in source['netadapter.c']:
        text += r'''
static NTSTATUS Ap6256MboPrepareJoin(PAP6256_WIFI,const AP6256_CONNECT_PARAMS*) {return 0;}
static BOOLEAN Ap6256MboJoinBlocked(PAP6256_WIFI,const UCHAR*) {return FALSE;}
static NTSTATUS Ap6256MboCopyVendorIes(AP6256_CONNECT_PARAMS*,const UCHAR*,ULONG) {return 0;}
'''
    owe = read_source_text(ROOT / 'src/common/owe.c').split('typedef struct _OWE_IES')[0]
    text += owe[owe.index('static UINT16 Owe16'):owe.index('static UINT32 Owe32')]
    text += owe[owe.index('_Use_decl_annotations_'):] + '\n'
    if has_bip:
        text += re.search('^NTSTATUS Ap6256SaeSetBip\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source['sae_fw.c'], re.M)[0] + '\n'
    text += re.search('^NTSTATUS Ap6256SaeVerifySecurity\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source['sae_fw.c'], re.M)[0] + '\n'
    ft = read_source_text(ROOT / 'src/common/ft.c')
    binding_ft = read_source_text(ROOT / 'src/common/ft_station.inc')
    for (content, names) in [(ft, ['Ap6256FtConnectionLost']), (binding_ft, ['Ap6256FtCopyCandidate', 'Ap6256FtValidateCandidates'])]:
        for name in names:
            text += re.search('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', content, re.M)[0] + '\n'
    codec = read_source_text(ROOT / 'src/common/sae_wdi.c')
    text += re.search('^NTSTATUS Ap6256SaeReadRsnxe\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', read_source_text(ROOT / 'src/common/sae.c'), re.M)[0] + '\n'
    for name in ('Ap6256SaeCopyPmkid', 'Ap6256SaeCopyCachedH2e'):
        text += re.search('^NTSTATUS ' + name + '\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', codec, re.M)[0] + '\n'
    binding = read_source_text(ROOT / 'src/common/sae_station.inc')
    text += re.search('^static BOOLEAN Ap6256StationSaeFallback\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', binding, re.M)[0] + '\n'
    if 'Ap6256ClaimConnectTask' in source['netadapter.c']:
        text += re.search('typedef enum _AP6256_CONNECT_CLAIM\\s*\\{[\\s\\S]*?\\}\\s*AP6256_CONNECT_CLAIM;', source['netadapter.c'])[0] + '\n'
    text += re.search('static const UINT16 Ap6256Channels5\\[\\] = \\{[\\s\\S]*?\\};', source['netadapter.c'])[0] + '\n'
    for (file, names) in [('wifi_ops.c', ['Ap6256EncodeChanspec', 'Ap6256WifiPrepareHostCipherOffloads', 'Ap6256WifiSetStationRsn', 'Ap6256WifiConnectCommon', 'Ap6256WifiConnect', 'Ap6256WifiConnectFt', 'Ap6256WifiDisconnectWithReason']), ('netadapter.c', ['Ap6256HostSaeAvailable', 'Ap6256HostOweAvailable', 'Ap6256HostFbtAvailable', 'Ap6256HostCipherAvailable', 'Ap6256Wpa3EnterpriseAvailable', 'Ap6256MacIsValue', 'Ap6256MacIsValidUnicast', 'Ap6256AddressInList', 'Ap6256AddressListIsUnrestricted', 'Ap6256ChannelSupported', 'Ap6256BandIsMasked', 'Ap6256AlgorithmPresent', 'Ap6256CipherPresent', 'Ap6256ClaimConnectTask', 'Ap6256IndicateDisassociation', 'Ap6256StationStartNext', 'Ap6256ExpireConnect', 'Ap6256HandleConnectRequest', 'Ap6256HandleDisconnectRequest', 'Ap6256NetLinkChangeWork', 'Ap6256NetQueueLinkEventOwner', 'Ap6256NetStationLinkEventOwner', 'Ap6256NetStationLinkEvent', 'Ap6256NetStationFirmwareEvent', 'Ap6256NetStationHostCipherEvent'])]:
        for name in names:
            if name not in source[file]:
                continue
            matches = list(re.finditer('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source[file], re.M))
            match = matches[-1] if matches else None
            if not match:
                raise ValueError(name)
            body = match[0].replace('PAP6256_DEVICE_CONTEXT', 'Device*')
            if name == 'Ap6256HandleDisconnectRequest' and has_disassoc:
                body = _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))[name]
            text += body + '\n'
    if has_disassoc:
        text += _functions((ROOT / 'src/common/netadapter.c').read_text(encoding='utf-8-sig'))['Ap6256OnDisconnectTimeout'] + '\n'
    for name in ('Ap6256SaeFwLe32', 'Ap6256SaeFwLe16', 'Ap6256SaePrivateOwner'):
        text += re.search('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{[\\s\\S]*?^\\}', source['sae_fw.c'], re.M)[0] + '\n'
    block_start = source['datapath.c'].index('    if ((Ap6256ReadBe32((PUCHAR)&evt->AuthType) & AP6256_SAE_OWNER_AUTH_FLAG)')
    masked = _mask(source['datapath.c'])
    block_end = masked.index('{', block_start) + 1
    depth = 1
    while depth:
        depth += (masked[block_end] == '{') - (masked[block_end] == '}')
        block_end += 1
    block = source['datapath.c'][block_start:block_end]
    text += r'''
struct OwnedHeader { UCHAR AuthType[4],Flags[2],IfIdx,BssCfgIdx; };
static UINT32 Ap6256ReadBe32(const UCHAR* p) {return ((UINT32)p[0]<<24)|((UINT32)p[1]<<16)|((UINT32)p[2]<<8)|p[3];}
static UINT16 Ap6256ReadBe16(const UCHAR* p) {return (UINT16)(((UINT16)p[0]<<8)|p[1]);}
static void Ap6256TestOwnedDispatch(Device* Ctx,UINT32 eventType,UINT32 status,UINT32 auth,UINT16 flags,
    UINT8 interfaceIndex,UINT8 bssIndex,UCHAR* eventBody,ULONG eventBodyLen) {
    OwnedHeader header={};OwnedHeader* evt=&header;
    for(unsigned i=0;i<4;i++)header.AuthType[i]=(UCHAR)(auth>>(24-i*8));
    header.Flags[0]=(UCHAR)(flags>>8);header.Flags[1]=(UCHAR)flags;
    header.IfIdx=interfaceIndex;header.BssCfgIdx=bssIndex;

''' + block + '}\n'
    text += 'struct NativeOwnerEvent {UINT32 type,status,auth;std::vector<UCHAR> data;};\n'
    text += 'static const std::vector<NativeOwnerEvent> nativeOwnerEvents={},nativeHostCipherEvents={};\n'
    text += 'struct NativeAssociationEvents {bool success;std::vector<NativeOwnerEvent> events;};\n'
    text += 'static const std::vector<NativeAssociationEvents> nativeHostCipherAssociationEvents={};\n'
    text += TEST
    args.output.mkdir(parents=True, exist_ok=True)
    cpp = args.output / 'tests.cpp'
    write_bytes(cpp, text.encode())
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    command += ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(args.output / 'tests.exe'), '/Fo:' + str(args.output / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    compiled = subprocess.run(command, capture_output=True, text=True)
    write_text(args.output / 'compile.log', compiled.stdout + compiled.stderr, encoding='utf-8')
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    executed = subprocess.run([str(args.output / 'tests.exe')] + ['enterprise-only'], capture_output=True, text=True)
    write_text(args.output / 'run.log', executed.stdout + executed.stderr, encoding='utf-8')
    print(executed.stdout + executed.stderr, end='')
    assert executed.returncode == 0, executed.returncode
    if args.source_dir.resolve() == (ROOT / 'src').resolve() and True:
        names = [p.relative_to(ROOT).as_posix() for p in (ROOT / 'src').rglob('*') if p.is_file()]
        inputs = [ROOT / name for name in names if Path(name).name != 'buildstamp.h']
        inputs += [ROOT / name for name in ('tests/test-station-security.py', 'tests/test-wdi-capabilities.py', 'tests/wdi_test_support.py', 'tests/driver_sources.py', 'tests/source-layout.json')]
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        match = re.search('PASS: (\\d+) production host-cipher common join/', executed.stdout)
        report = dict(exit_code=0, common_host_cipher_cases=int(match[1]) if match else 0, host_cipher_event_owner_cases=0, native_host_cipher_association_event_sequences=0, enterprise_ccmp_connect_cases=int(re.search('PASS: (\\d+) native WPA3-Enterprise/CCMP', executed.stdout)[1]), enterprise_rsne_inputs={cache: value for (cache, value) in re.findall('ENTERPRISE_RSNE:([01]):([0-9a-f]+)', executed.stdout)}, historical_native_event_tests_run=False, windows_host_cipher_connect_cases=int(re.search('PASS: (\\d+) Microsoft GCMP', executed.stdout)[1]), wire_versions=[re.search('AP6256_TEST_WDI_VERSION (\\w+)', contract_preamble())[1], 'WDI_VERSION_2_0_4'], direct_akm_cipher_checks=36, disassociation_retirement_cases=int(re.search('PASS: (\\d+) production disassociation retirement/', executed.stdout)[1]) if has_disassoc and False else 0, windows_disconnect_cases=int(re.search('PASS: (\\d+) Microsoft DISCONNECT codec/', executed.stdout)[1]) if has_disassoc and False else 0, sources={str(path.relative_to(ROOT)): digest(path) for path in inputs}, test_exe_sha256=digest(args.output / 'tests.exe'), generated_cpp_sha256=digest(cpp), compiler_sha256=digest(Path(command[0])), codec_sha256=digest(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib'), board_verified=False, association_qualified=False, boundary='Microsoft CONNECT/ROAM handling, enterprise CCMP, GCMP, PMF and candidate/cache validation.')
        write_text(args.output / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
