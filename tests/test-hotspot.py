# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Compile and execute the production C hotspot/routing functions with host mocks.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import argparse
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
START_SOURCE = None
CREATE_SOURCE = None
STOP_SOURCE = None

def body(file, name):
    override = START_SOURCE if name == 'Ap6256GoStart' else CREATE_SOURCE if name == 'Ap6256GoCreate' else STOP_SOURCE if name == 'Ap6256GoStop' else None
    path = override if override is not None else ROOT / 'src' / file
    text = read_source_text(path, encoding='utf-8-sig')
    match = re.search('^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{', text, re.M)
    if not match:
        raise ValueError(name)
    start = match.end() - 1
    clean = re.sub('//[^\\n]*|/\\*[\\s\\S]*?\\*/|"(?:\\\\.|[^"\\\\])*"', lambda m: ' ' * len(m[0]), text[start:])
    depth = 0
    for (i, char) in enumerate(clean):
        depth += (char == '{') - (char == '}')
        if depth == 0:
            return text[start:start + i + 1]
    raise ValueError('Unclosed function: ' + name)
PREAMBLE = r'''

#define AP6256_ENABLE_WDI 1
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
typedef uint8_t UCHAR, BOOLEAN;
typedef uint16_t UINT16, WDI_PEER_ID, WDI_PORT_ID;
typedef uint32_t UINT32, ULONG, WDI_EXTENDED_TID;
typedef int32_t LONG, INT32, NTSTATUS, NDIS_STATUS;
typedef uint64_t ULONG_PTR;
typedef uint64_t ULONGLONG;
typedef size_t SIZE_T;
typedef unsigned char* PUCHAR;
typedef ULONG* PULONG;
typedef UINT32* PUINT32;
typedef void VOID, *PVOID, *TAL_TXRX_HANDLE;
typedef char CHAR;
typedef const char* PCSTR;
typedef int KIRQL;
typedef struct {int64_t QuadPart;} LARGE_INTEGER;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS 0
#define NDIS_STATUS_SUCCESS 0
#define NDIS_STATUS_PENDING 1
#define STATUS_INVALID_PARAMETER -1
#define STATUS_INVALID_BUFFER_SIZE -2
#define STATUS_BUFFER_TOO_SMALL -3
#define STATUS_NOT_SUPPORTED -4
#define STATUS_INSUFFICIENT_RESOURCES -5
#define STATUS_DEVICE_NOT_READY -6
#define STATUS_IO_TIMEOUT -7
#define STATUS_DEVICE_BUSY -8
#define NT_SUCCESS(s) ((s)>=0)
#define KernelMode 0
#define POOL_FLAG_NON_PAGED 0
#define AP6256_POOL_TAG 0
#define AP6256_P2P_IF_GO 1
#define AP6256_WDI_OPMODE_P2P_GO 0x20
#define AP6256_WDI_OPMODE_P2P_CLIENT 0x10
#define STATUS_INVALID_DEVICE_STATE -9
#define STATUS_DEVICE_PROTOCOL_ERROR -10
#define STATUS_DEVICE_HARDWARE_ERROR -11
#define AP6256_STATION_PORT 0
#define AP6256_GROUP_PORT 2
#define AP6256_GO_PEERS 9
#define AP6256_TAL_PEER_ID 0
#define WDI_PORT_ANY 65535
#define WDI_PEER_ANY 65535
#define UNREFERENCED_PARAMETER(x) (void)(x)
#define RtlZeroMemory(p,n) memset(p,0,n)
#define RtlSecureZeroMemory(p,n) memset(p,0,n)
#define RtlCopyMemory memcpy
#define RtlMoveMemory memmove
#define RtlEqualMemory(a,b,n) (memcmp(a,b,n)==0)
#define RTL_NUMBER_OF(a) (sizeof(a)/sizeof((a)[0]))
#define KeAcquireSpinLock(l,i) (*(i)=0)
#define KeReleaseSpinLock(l,i) ((void)(i))
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
#define TraceError(...) ((void)0)
#define TraceInfo(...) ((void)0)
#define Ap6256TalCount(...) ((void)0)
#define _IRQL_requires_max_(...)
static LONG InterlockedIncrement(volatile LONG* p) {return ++*p;}
static LONG InterlockedExchange(volatile LONG* p,LONG v) {LONG old=*p;*p=v;return old;}
static LONG InterlockedCompareExchange(volatile LONG* p,LONG v,LONG old) {LONG r=*p; if(r==old)*p=v;return r;}
static void* ExAllocatePool2(int flag,size_t n,int tag) {return calloc(1,n);}
static void ExFreePoolWithTag(void* p,int tag) {free(p);}
static NTSTATUS RtlStringCbPrintfA(char* out,size_t n,const char* fmt,...) {
    va_list args; int count; va_start(args,fmt);count=vsnprintf(out,n,fmt,args);va_end(args);
    return count<0 || (size_t)count>=n ? -1 : 0;
}
static void KeDelayExecutionThread(int mode,int alert,LARGE_INTEGER* delay) {}
typedef struct NBL {struct NBL* next;void* MiniportReserved[2];int freed;} NBL,*PNET_BUFFER_LIST;
#define NET_BUFFER_LIST_NEXT_NBL(n) ((n)->next)
#define RX_PORT(n) ((UINT16)((ULONG_PTR)(n)->MiniportReserved[1] & 0xffffu))
#define RX_PEER(n) ((UINT16)((ULONG_PTR)(n)->MiniportReserved[1] >> 16))
typedef struct {UCHAR Address[6];BOOLEAN Active,DeletePending,RxOpen;UINT32 PhyId;ULONGLONG RxGeneration;} PEER;
typedef struct {UCHAR OperatingChannel,OperatingClass;} P2P;
typedef struct {
    BOOLEAN Created,FirmwareReady,NativeStateUncertain,Started,TalAdded,RxStopped,Stopping,WpsEnabled;
    UINT32 Mode,BssIndex,IfIndex,Channel; UCHAR Address[6],ClientBssid[6]; LONG PacketFilter;
    LONG DataTrace[Ap6256GoDataStageCount];
    BOOLEAN ClientConnected,ClientSecure,ClientMfp;
    PEER Peers[9]; P2P P2p;
} GO;
typedef struct {UCHAR Address[6];} WDI_MAC_ADDRESS;
typedef struct {union {struct {UINT16 PortID,PeerID;} txMetaData;} u;} META,*PWDI_FRAME_METADATA;
typedef struct CTX {
    struct {UINT32 ChipId,ChipRev;} Chip;
    BOOLEAN FirmwareFtmPatchVerified,FirmwareHalted;
    GO Go; BOOLEAN FirmwareP2pSupported,FirmwareLinkUp,FirmwareMchanSupported; UCHAR D11IoType; UINT32 TalPhyId;
    LONG FirmwareIfMap[16]; KIRQL TalStateLock,RxQueueLock;
    UCHAR TalBssid[6]; LONG TalRxSequence; BOOLEAN TalPeerCreated,TalRxOpen,StationRxStopped,RxStopped;
    PNET_BUFFER_LIST RxQueueHead,RxQueueTail; ULONG RxQueueCount;
    ULONGLONG StationRxGeneration,GroupRxGeneration;
    BOOLEAN TxAborting; UINT16 TxAbortPort,TxAbortPeer;
    void* WdiDataPathHandle;
    struct {
        void (*PeerCreateIndication)(void*,UINT16,UINT16,WDI_MAC_ADDRESS);
        void (*PeerDeleteIndication)(void*,UINT16,UINT16,NDIS_STATUS*);
    } WdiDataApi;
} CTX,*PAP6256_DEVICE_CONTEXT;
typedef enum {Ap6256SecurityOpen,Ap6256SecurityWpa2Host,Ap6256SecurityWpa2Firmware} SECURITY;
typedef struct {UCHAR Ssid[32]; ULONG SsidLength; SECURITY Security; BOOLEAN ExcludeUnencrypted;
    ULONG Channel,BeaconPeriod,DtimPeriod;} AP,*PAP6256_AP_PARAMS;
typedef enum {Ap6256MfpNone,Ap6256MfpCapable,Ap6256MfpRequired} MFP;
typedef struct {UCHAR Ssid[32];ULONG SsidLength;SECURITY Security;MFP Mfp;BOOLEAN BssidValid;UCHAR Bssid[6];UINT32 Channel;} AP6256_CONNECT_PARAMS;
typedef enum {Ap6256ScanBand2G,Ap6256ScanBand5G} BAND;
typedef struct {UINT16 Number;BAND Band;} AP6256_SCAN_CHANNEL;
typedef UINT16* PUINT16;
typedef UCHAR UINT8;
static NTSTATUS Ap6256ClientDisconnect(CTX* Ctx,UINT32 Reason);
static VOID Ap6256P2pReleaseIesFor(CTX* c,P2P* p,UINT32 i) {}
static VOID Ap6256P2pForgetIesFor(P2P* p) {}
typedef struct {const UCHAR* Response;ULONG ResponseLength;const UCHAR* Beacon;ULONG BeaconLength;UINT16 StatusCode;} AP6256_GO_ASSOC_RESULT;
static BOOLEAN Ap6256TalUpcallClaim(CTX* c) {return TRUE;}
static VOID Ap6256TalUpcallRelease(CTX* c) {}


static unsigned wlfc_cancels;
static UINT16 cancelled_peer;
static VOID Ap6256WlfcCancel(CTX* c,UINT16 port,UINT16 peer,PVOID cookie) {
    assert(port==AP6256_GROUP_PORT && peer>0 && peer<=AP6256_GO_PEERS && !cookie);
    wlfc_cancels++;cancelled_peer=peer;
}
static VOID Ap6256TalFreeRxNbl(CTX* c,PNET_BUFFER_LIST n) {assert(!n->freed);n->freed=1;}
static unsigned calls,fail_at,station_channel=6,radio_down;
static UINT32 station_chanspec=0x1006,chanspec_list[380];
static NTSTATUS chanspec_status;
static unsigned chanspec_queries;
static BOOLEAN reject_wide,reject_narrow;
static BOOLEAN tdls_blocked;
static NTSTATUS tdls_block_status;
static NTSTATUS Ap6256TdlsSetBlocked(CTX* c,BOOLEAN blocked) {
    (void)c;
    tdls_blocked=blocked;return tdls_block_status;
}
static UINT32 group_auth,group_wsec,group_wpa,group_restrict;
static BOOLEAN advertised_privacy;
static int security_wrong;
static struct {UINT32 iface,cmd;char name[64];UCHAR data[256];ULONG len;} ops[128];
static NTSTATUS record(UINT32 iface,const char* name,const void* data,ULONG len) {
    unsigned n=calls++; assert(n<128);ops[n].iface=iface;ops[n].cmd=0;strcpy_s(ops[n].name,64,name);
    ops[n].len=len;assert(len<=256);if(len)memcpy(ops[n].data,data,len);
    return calls==fail_at ? -99 : 0;
}
static NTSTATUS Ap6256BcdcSetIovarIf(CTX*c,UINT32 i,PCSTR n,const void*d,ULONG l) {
    if(!strcmp(n,"chanspec")) {
        UINT32 v;assert(l==4);memcpy(&v,d,4);
        NTSTATUS status=record(i,n,d,l);
        if((reject_wide && (v & 0x3800u)!=0x1000u) ||
           (reject_narrow && (v & 0x3800u)==0x1000u))return -99;
        return status;
    }
    if(l==8) {
        UINT32 v;memcpy(&v,(const UCHAR*)d+4,4);
        if(!strcmp(n,"bsscfg:auth"))group_auth=v;
        if(!strcmp(n,"bsscfg:wsec"))group_wsec=v;
        if(!strcmp(n,"bsscfg:wpa_auth"))group_wpa=v;


        if(!strcmp(n,"bss") && v==1)advertised_privacy=(group_wsec & 0x137u)!=0 && group_restrict!=0;
    }


    if(!strcmp(n,"bsscfg:rx_unencrypted_eapol")) {record(i,n,d,l);return STATUS_NOT_SUPPORTED;}
    return record(i,n,d,l);
}
static NTSTATUS Ap6256BcdcQueryDcmdIf(CTX*c,UINT32 i,UINT32 cmd,void*d,ULONG l) {
    UINT32 v=cmd==21 ? group_auth : cmd==133 ? group_wsec : cmd==164 ? group_wpa : group_restrict;
    assert(cmd==21 || cmd==133 || cmd==164 || cmd==81);assert(l==4 && i==1);
    if(security_wrong==1 && cmd==133)v=0;
    if(security_wrong==2 && cmd==164)v=0;
    if(security_wrong==3 && cmd==21)v=1;
    if(security_wrong==4 && cmd==81)v=!group_restrict;
    memcpy(d,&v,4);return record(i,"get-security",&cmd,4);
}
NTSTATUS Ap6256BcdcGetIovarIf(CTX*c,UINT32 i,PCSTR n,void*d,ULONG l) {
    (void)c;record(i,n,d,l);return STATUS_NOT_SUPPORTED;
}

static VOID Ap6256WifiTraceApBss(CTX*c,UINT32 i) {assert(i==1);}

static NTSTATUS delete_status;
static INT32 delete_firmware_status;
static BOOLEAN delete_firmware_reply=TRUE,delete_firmware_error=TRUE;
static NTSTATUS Ap6256BcdcSetIovar(CTX*c,PCSTR n,const void*d,ULONG l) {
    NTSTATUS status=record(0,n,d,l);
    if(!strcmp(n,"p2p_ifdel") && delete_status)status=delete_status;
    if(status==0 && !strcmp(n,"p2p_ifdel"))c->FirmwareIfMap[2]=0;
    if(status==0 && !strcmp(n,"p2p_ifadd"))c->FirmwareIfMap[2]=2;
    return status;
}
typedef struct {BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;} AP6256_BCDC_QUERY_RESULT;
static NTSTATUS Ap6256BcdcSetIovarResultIf(CTX*c,UINT32 i,PCSTR n,const void*d,ULONG l,AP6256_BCDC_QUERY_RESULT*r) {
    assert(i==0 && !strcmp(n,"p2p_ifdel") && l==6);
    NTSTATUS status=Ap6256BcdcSetIovar(c,n,d,l);
    r->FirmwareReply=delete_firmware_reply;r->FirmwareError=delete_firmware_error;
    r->FirmwareStatus=delete_firmware_status;
    return delete_status?delete_status:status;
}
static NTSTATUS Ap6256BcdcSetDcmdIf(CTX*c,UINT32 i,UINT32 cmd,const void*d,ULONG l) {
    if(cmd==82){assert(i==1 && l==4);group_restrict=*(const UINT32*)d;}
    NTSTATUS status=record(i,"dcmd",d,l);ops[calls-1].cmd=cmd;return status;
}
static unsigned memuse_queries,memuse_positions[2];
static NTSTATUS memuse_status;
static NTSTATUS Ap6256BcdcGetIovar(CTX*c,PCSTR n,void*d,ULONG l) {
    if(!strcmp(n,"memuse")) {
        assert(l==320 && memuse_queries<2);
        memuse_positions[memuse_queries++]=calls;
        if(memuse_status<0)return memuse_status;
        const char* value="Heap Free: 26000(26K), Packet pool: 32 of 64 available\n";
        memcpy(d,value,strlen(value)+1);return STATUS_SUCCESS;
    }
    if(!strcmp(n,"chanspecs")) {
        assert(l==sizeof(chanspec_list));chanspec_queries++;
        memcpy(d,chanspec_list,l);return chanspec_status;
    }
    UINT32 bss=2;memcpy(d,&bss,4);return 0;
}
static NTSTATUS Ap6256WifiGetChanspec(CTX*c,UINT32*p) {*p=station_chanspec;return 0;}
static NTSTATUS Ap6256WifiGetChannel(CTX*c,UINT32*p) {*p=station_channel;return 0;}
static NTSTATUS Ap6256WifiRadioUpDown(CTX*c,BOOLEAN up) {if(!up)radio_down++;return 0;}
static NTSTATUS Ap6256P2pBuildIesFor(CTX*c,P2P*p,UINT32 i) {return record(i,"ies",NULL,0);}
#define PASSIVE_LEVEL 0
#define WDI_RX_INDICATION_DISPATCH_GENERAL 1
#define WDI_RX_INDICATION_PASSIVE 0
static int KeGetCurrentIrql(void) {return 0;}
static void Ap6256TalRxIndicateQueued(CTX*c,int level,const char* reason) {}
typedef enum {WDI_BAND_ID_2400=1,WDI_BAND_ID_5000=2} WDI_BAND_ID;
#define AP6256_DISALLOW_BAND_2G 1
#define AP6256_DISALLOW_BAND_5G 2
typedef struct {UINT32 TransactionId;UINT16 PortId;} WDI_MESSAGE_HEADER;
typedef struct {BOOLEAN Active;WDI_MESSAGE_HEADER Header;PVOID RequestId;int64_t DeadlineMs;} TASK;
typedef struct {CTX* Ctx;LONG DisallowedBandMask;int GroupLock,ClientConnectTimer;
    TASK ClientConnectTask;volatile LONG GroupGeneration;AP6256_CONNECT_PARAMS ClientCandidates[16];
    ULONG ClientCandidateCount,ClientCandidateIndex;BOOLEAN HardwareAvailable;} WIFI,*PAP6256_WIFI;
#define STATUS_UNSUCCESSFUL -11
#define STATUS_CANCELLED -12
#define STATUS_IO_DEVICE_ERROR -13
#define AP6256_PHY_ID_HT 3
#define AP6256_PHY_ID_VHT 4
#define WDI_INDICATION_CONNECT_COMPLETE 200
#define AP6256_TIMER_STOP(t,w) ((void)((t)=0))
#define Ap6256LockAcquire(l) ((void)0)
#define Ap6256LockRelease(l) ((void)0)
static int64_t now_ms;
static int64_t Ap6256InterruptTimeMs(void) {return now_ms;}
static unsigned assoc_ok,assoc_fail,m4,disassoc,link_state;
static NTSTATUS Ap6256QuiesceP2pListen(WIFI*w) {(void)w;return STATUS_SUCCESS;}
static BOOLEAN assoc_answer=TRUE;
static NTSTATUS last_completion;
static BOOLEAN Ap6256ClaimTask(WIFI*w,TASK*t,WDI_MESSAGE_HEADER*h,PVOID*id) {
    if(!t->Active)return FALSE;*h=t->Header;*id=t->RequestId;t->Active=FALSE;return TRUE;
}
static BOOLEAN Ap6256ClientAssociation(WIFI*w,const WDI_MESSAGE_HEADER*h,PVOID id,BOOLEAN success) {
    assert(h->PortId==2 && id==(void*)0xabc);if(success && assoc_answer){assoc_ok++;return TRUE;}
    assoc_fail++;return FALSE;
}
static NTSTATUS Ap6256SendIndicationRq(WIFI*w,UINT16 msg,const WDI_MESSAGE_HEADER*h,UINT32 txn,
    PVOID id,NTSTATUS status,const void*p,ULONG n) {
    assert(msg==WDI_INDICATION_CONNECT_COMPLETE && h->PortId==2 && txn==71 && id==(void*)0xabc);
    m4++;last_completion=status;return 0;
}
static VOID Ap6256ClientLinkState(WIFI*w) {link_state++;}
static VOID Ap6256IndicateP2pGroupChannel(WIFI*w,const WDI_MESSAGE_HEADER*h,PVOID id,UINT32 channel) {
    assert(w->ClientConnectTask.Active && h->PortId==AP6256_GROUP_PORT && channel==w->Ctx->Go.Channel);
    (void)id;
}
static VOID Ap6256GoIndicateDisassociation(WIFI*w,const UCHAR*addr,UINT16 reason) {disassoc++;}
static VOID Ap6256TalGoRxOpen(CTX*c,const UCHAR*addr) {
    for(unsigned i=1;i<9;i++)if(c->Go.Peers[i].Active && !memcmp(addr,c->Go.Peers[i].Address,6))c->Go.Peers[i].RxOpen=1;
}
typedef struct {
    WDI_BAND_ID BandID;
    struct {BOOLEAN ChannelList_IsPresent;} Optional;
    struct {ULONG ElementCount;UINT32* pElements;} ChannelList;
} WDI_AP_BAND_CHANNEL_LIST_CONTAINER;
typedef struct {
    struct {BOOLEAN APBandChannelList_IsPresent,AdvertisedOperatingChannel_IsPresent;} Optional;
    struct {ULONG ElementCount;WDI_AP_BAND_CHANNEL_LIST_CONTAINER* pElements;} APBandChannelList;
    struct {UINT32 ChannelNumber;} AdvertisedOperatingChannel;
    struct {BOOLEAN MustUseSpecifiedChannels;} StaticParameters;
} WDI_TASK_START_AP_PARAMETERS;
static UINT32 valid_channels[65]={5,1,6,11,36,52};
static NTSTATUS Ap6256BcdcQueryDcmd(CTX*c,UINT32 cmd,void*d,ULONG len) {
    assert(len==sizeof(valid_channels));memcpy(d,valid_channels,len);return 0;
}
'''
TESTS = r'''
static void reset(CTX* c) {
    memset(c,0,sizeof(*c));calls=fail_at=radio_down=0;
    station_channel=6;station_chanspec=0x1006;chanspec_queries=0;
    chanspec_status=STATUS_NOT_SUPPORTED;memset(chanspec_list,0,sizeof(chanspec_list));
    reject_wide=reject_narrow=FALSE;
    group_auth=group_wsec=group_wpa=group_restrict=0;
    advertised_privacy=FALSE;security_wrong=0;
    delete_status=delete_firmware_status=0;delete_firmware_reply=delete_firmware_error=TRUE;
    c->Go.Created=c->Go.FirmwareReady=c->FirmwareP2pSupported=1;
    c->Go.Mode=AP6256_WDI_OPMODE_P2P_GO;c->D11IoType=2;memcpy(c->Go.ClientBssid,"remote",6);
    c->Go.IfIndex=1;c->Go.BssIndex=2;c->FirmwareLinkUp=1;
    memcpy(c->TalBssid,"ABCDEF",6);memcpy(c->Go.Address,"UVWXYZ",6);
}
static void parser_tests(void) {
    UCHAR buf[80]={0};UINT32 fields[8]={34,4,38,6,44,3,0,0};AP6256_GO_ASSOC_RESULT r;
    memcpy(buf,fields,32);buf[46]=0;
    assert(Ap6256GoParseAssocResult(buf,47,&r));assert(r.Response==buf+38 && r.ResponseLength==6);
    assert(r.Beacon==buf+44 && r.BeaconLength==3 && r.StatusCode==0);
    buf[40]=17;assert(Ap6256GoParseAssocResult(buf,47,&r)&&r.StatusCode==17);
    assert(!Ap6256GoParseAssocResult(buf,46,&r));assert(!Ap6256GoParseAssocResult(NULL,80,&r));
    fields[2]=0xfffffff0;fields[3]=32;memcpy(buf,fields,32);
    assert(!Ap6256GoParseAssocResult(buf,80,&r));
    fields[2]=4;fields[3]=6;memcpy(buf,fields,32);assert(!Ap6256GoParseAssocResult(buf,80,&r));
    for(unsigned n=0;n<10000;n++) {unsigned k=n%32;buf[k]=(UCHAR)rand();
        if(Ap6256GoParseAssocResult(buf,80,&r)) {
            assert(r.Response>=buf+34 && r.Response+r.ResponseLength<=buf+80);
            assert(!r.BeaconLength || (r.Beacon>=buf+34 && r.Beacon+r.BeaconLength<=buf+80));
        }
    }
}
static void firmware_tests(void) {
    CTX c; AP p={{0}};unsigned steps;
    p.SsidLength=4;memcpy(p.Ssid,"test",4);p.Security=Ap6256SecurityWpa2Host;
    p.Channel=6;p.BeaconPeriod=100;p.DtimPeriod=2;p.ExcludeUnencrypted=1;



    p.ExcludeUnencrypted=0;
    reset(&c);assert(Ap6256GoStart(&c,&p)==0);
    assert(advertised_privacy && group_restrict==1);
    p.ExcludeUnencrypted=1;
    reset(&c);assert(Ap6256GoStart(&c,&p)==0);assert(c.Go.Started && c.FirmwareLinkUp && radio_down==0);
    assert(advertised_privacy && group_restrict==1);
    steps=calls;assert(!strcmp(ops[calls-5].name,"bss") && ((UINT32*)ops[calls-5].data)[1]==1);
    for(unsigned i=0;i<calls;i++) {assert(ops[i].iface==1);
        if(!strncmp(ops[i].name,"bsscfg:",7)) assert(*(UINT32*)ops[i].data==2);
    }
    for(unsigned i=1;i<=steps;i++) {reset(&c);fail_at=i;
        assert(Ap6256GoStart(&c,&p)<0 && c.FirmwareLinkUp && !radio_down);
        fail_at=0;assert(Ap6256GoStop(&c)==0 && !c.Go.Started);
    }
    for(int bad=1;bad<=4;bad++) {
        reset(&c);security_wrong=bad;
        assert(Ap6256GoStart(&c,&p)==STATUS_DEVICE_PROTOCOL_ERROR);
        assert(Ap6256GoStop(&c)==0 && !c.Go.Started && c.FirmwareLinkUp && !radio_down);
    }
    reset(&c);c.Go.WpsEnabled=TRUE;assert(Ap6256GoStart(&c,&p)==0 && group_wsec==0x44);
    reset(&c);p.Security=Ap6256SecurityOpen;assert(Ap6256GoStart(&c,&p)==0 && !group_wsec && !group_wpa);
    assert(!advertised_privacy && group_restrict==1);
    p.ExcludeUnencrypted=0;
    reset(&c);assert(Ap6256GoStart(&c,&p)==0 && !advertised_privacy && group_restrict==0);
    c.Go.WpsEnabled=1;
    assert(Ap6256GoStart(&c,&p)==0 && group_wsec==0x40 && !advertised_privacy);
    p.Security=Ap6256SecurityWpa2Host;
    reset(&c);p.Channel=11;assert(Ap6256GoStart(&c,&p)==STATUS_DEVICE_BUSY && calls==0);
    reset(&c);c.FirmwareMchanSupported=TRUE;p.Channel=36;
    assert(Ap6256GoStart(&c,&p)==0 && c.Go.Channel==36 && c.FirmwareLinkUp && !radio_down);
    p.Channel=6;
    reset(&c);c.Go.Started=1;assert(Ap6256GoStop(&c)==0 && !c.Go.Started && c.FirmwareLinkUp);
    for(unsigned i=0;i<calls;i++) assert(ops[i].iface==1);


    for(unsigned condition=0;condition<5;++condition) {
        reset(&c);c.Go.Started=TRUE;c.FirmwareFtmPatchVerified=TRUE;
        c.Chip.ChipId=0x4345;c.Chip.ChipRev=9;
        if(condition==1)c.FirmwareFtmPatchVerified=FALSE;
        if(condition==2)c.Chip.ChipRev=6;
        if(condition==3)c.Chip.ChipId=0x4346;
        if(condition==4)fail_at=1;
        NTSTATUS result=Ap6256GoStop(&c);
        assert(calls==((condition==0 || condition==4)?1u:3u));
        assert(ops[0].iface==1 && !strcmp(ops[0].name,"bss") && ops[0].len==8);
        assert(((UINT32*)ops[0].data)[0]==2 && ((UINT32*)ops[0].data)[1]==0);
        assert((condition==4)==(result<0));
        assert(c.Go.Started==(condition==4) && c.Go.Stopping==(condition!=4));
        assert(c.FirmwareLinkUp && !radio_down);
        if(condition>0 && condition<4) {
            assert(!strcmp(ops[1].name,"key_remove_all") && ops[1].iface==1);
            assert(ops[2].cmd==BRCMF_C_SET_KEY_PRIMARY && ops[2].iface==1 && ops[2].len==4);
        }
    }
    reset(&c);c.Go.FirmwareReady=0;assert(Ap6256GoStop(&c)==0 && calls==0);
    reset(&c);c.Go.FirmwareReady=0;c.FirmwareIfMap[2]=2;
    assert(Ap6256GoCreate(&c)==0 && c.Go.IfIndex==1 && c.Go.BssIndex==2 && c.Go.FirmwareReady);
    assert(tdls_blocked);
    assert(!strcmp(ops[0].name,"p2p_ifadd"));assert(!strcmp(ops[1].name,"bsscfg:ap_isolate"));
    assert(Ap6256GoDelete(&c)==0 && !tdls_blocked);
    reset(&c);c.Go.FirmwareReady=0;fail_at=1;assert(Ap6256GoCreate(&c)<0);
    assert(!c.Go.FirmwareReady);
    assert(calls==2 && !strcmp(ops[1].name,"p2p_ifdel") && !tdls_blocked);
    for(unsigned condition=0;condition<5;++condition) {
        reset(&c);c.Go.FirmwareReady=0;fail_at=1;
        delete_status=STATUS_DEVICE_PROTOCOL_ERROR;delete_firmware_status=-30;
        if(condition==1)delete_firmware_reply=FALSE;
        if(condition==2)delete_firmware_error=FALSE;
        if(condition==3)delete_firmware_status=-1;
        if(condition==4)delete_firmware_status=-2;
        assert(Ap6256GoCreate(&c)==-99 && !c.Go.FirmwareReady);
        assert(tdls_blocked==(condition!=0));
        assert(calls==2 && !strcmp(ops[1].name,"p2p_ifdel"));
        assert(c.Go.NativeStateUncertain==(condition!=0));
        if(condition!=0) {
            unsigned savedCalls=calls;
            assert(Ap6256GoCreate(&c)==STATUS_DEVICE_HARDWARE_ERROR && calls==savedCalls);
            assert(Ap6256GoDelete(&c)==STATUS_DEVICE_HARDWARE_ERROR && calls==savedCalls);
        }
    }
    for(unsigned fault=0;fault<3;++fault) {
        reset(&c);c.Go.FirmwareReady=0;c.FirmwareFtmPatchVerified=TRUE;
        c.Chip.ChipId=0x4345;c.Chip.ChipRev=9;memuse_queries=0;
        memuse_status=fault==1?STATUS_NOT_SUPPORTED:STATUS_SUCCESS;
        fail_at=fault==2?1u:0u;
        NTSTATUS result=Ap6256GoCreate(&c);
        assert((fault==2)==(result<0));
        assert(memuse_queries==(fault==2?2u:1u) && memuse_positions[0]==0);
        if(fault==2)assert(memuse_positions[1]==1 && !c.Go.FirmwareReady);
    }
    memuse_queries=0;memuse_status=STATUS_SUCCESS;
    reset(&c);c.Go.FirmwareReady=0;tdls_block_status=STATUS_DEVICE_PROTOCOL_ERROR;
    assert(Ap6256GoCreate(&c)==STATUS_DEVICE_PROTOCOL_ERROR && calls==0);
    tdls_block_status=STATUS_SUCCESS;
    assert(Ap6256GoDelete(&c)==0);
    assert(tdls_blocked);
    assert(Ap6256GoPrepare(&c)==0 && radio_down==1);
    assert(Ap6256GoDisconnectPeer(&c,(const UCHAR*)"client",3)==STATUS_DEVICE_NOT_READY);
}
static void client_firmware_tests(void) {
    CTX c;AP6256_CONNECT_PARAMS p={0};unsigned steps;
    reset(&c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;c.Go.FirmwareReady=0;
    assert(Ap6256GoCreate(&c)==0 && calls==1);
    assert(*(UINT16*)(ops[0].data+6)==0);
    p.SsidLength=6;memcpy(p.Ssid,"DIRECT",6);p.BssidValid=TRUE;
    memcpy(p.Bssid,"remote",6);p.Channel=6;p.Security=Ap6256SecurityWpa2Host;p.Mfp=Ap6256MfpCapable;
    calls=0;assert(Ap6256ClientConnect(&c,&p)==0);steps=calls;
    assert(ops[calls-1].len==50 && *(UINT32*)(ops[calls-1].data+44)==1);
    assert(!memcmp(ops[calls-1].data+36,p.Bssid,6));
    assert(*(UINT16*)(ops[calls-1].data+48)==0x1006);
    for(unsigned i=0;i<calls;i++)assert(ops[i].iface==1);
    assert(c.FirmwareLinkUp && !radio_down);
    for(unsigned fail=1;fail<=steps;fail++) {
        reset(&c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;fail_at=fail;
        assert(Ap6256ClientConnect(&c,&p)<0);
        assert(c.FirmwareLinkUp && !radio_down);
    }
    reset(&c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;c.Go.WpsEnabled=1;
    p.Security=Ap6256SecurityOpen;p.Mfp=Ap6256MfpNone;
    assert(Ap6256ClientConnect(&c,&p)==0);
    assert(!strcmp(ops[1].name,"bsscfg:wpa_auth") && *(UINT32*)(ops[1].data+4)==0);
    assert(!strcmp(ops[2].name,"bsscfg:wsec") && *(UINT32*)(ops[2].data+4)==0x40);
    reset(&c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;
    assert(Ap6256ClientDisconnect(&c,3)==0 && calls==2);
    reset(&c);c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;c.Go.Started=1;
    assert(Ap6256GoStop(&c)==0 && !c.Go.Started && c.Go.Stopping);
    assert(*(UINT32*)ops[0].data==3 && !memcmp(ops[0].data+4,c.Go.ClientBssid,6));
    for(unsigned i=0;i<calls;i++)assert(ops[i].iface==1);
    reset(&c);assert(Ap6256GroupChangeMode(&c,AP6256_WDI_OPMODE_P2P_CLIENT)==0);
    assert(c.Go.Mode==AP6256_WDI_OPMODE_P2P_CLIENT && c.Go.FirmwareReady);
    assert(Ap6256GroupChangeMode(&c,AP6256_WDI_OPMODE_P2P_GO)==0);
    assert(c.Go.Mode==AP6256_WDI_OPMODE_P2P_GO && c.Go.FirmwareReady);
    c.Go.Started=1;assert(Ap6256GroupChangeMode(&c,AP6256_WDI_OPMODE_P2P_CLIENT)<0);
    reset(&c);fail_at=5;
    assert(Ap6256GroupChangeMode(&c,AP6256_WDI_OPMODE_P2P_CLIENT)<0);
    assert(c.Go.Mode==AP6256_WDI_OPMODE_P2P_GO && c.Go.FirmwareReady);
}
static void bandwidth_tests(void) {
    CTX c;AP p={0};
    p.SsidLength=4;memcpy(p.Ssid,"test",4);p.Security=Ap6256SecurityWpa2Host;p.Channel=36;



    reset(&c);station_channel=36;station_chanspec=0xe02a;
    chanspec_status=0;chanspec_list[0]=2;chanspec_list[1]=0xd024;chanspec_list[2]=0xe02a;
    assert(Ap6256GoStart(&c,&p)==0);
    assert(!strcmp(ops[0].name,"chanspec") && *(UINT32*)ops[0].data==0xe02a);
    assert(chanspec_queries==1 && c.Go.Channel==36 && c.Go.P2p.OperatingChannel==36);
    assert(c.Go.P2p.OperatingClass==115 && c.FirmwareLinkUp && !radio_down);

    for(unsigned center=42;center<=155;center+=113) for(unsigned sb=0;sb<4;sb++) {
        reset(&c);p.Channel=center-6+4*sb;station_channel=p.Channel;
        station_chanspec=0xe000u+(sb<<8)+center;chanspec_status=0;
        chanspec_list[0]=1;chanspec_list[1]=station_chanspec;
        assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==station_chanspec);
        assert(c.Go.Channel==p.Channel && c.Go.P2p.OperatingChannel==p.Channel);
    }
    const UINT32 centers[]={38,46,151,159};
    for(unsigned k=0;k<4;k++)for(unsigned sb=0;sb<2;sb++) {
        reset(&c);p.Channel=centers[k]-2+4*sb;station_channel=p.Channel;
        station_chanspec=0xd800u+(sb<<8)+centers[k];chanspec_status=0;
        chanspec_list[0]=1;chanspec_list[1]=station_chanspec;
        assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==station_chanspec);
        assert(c.Go.Channel==p.Channel && c.Go.P2p.OperatingChannel==p.Channel);
    }
    p.Channel=36;


    for(unsigned k=0;k<5;k++) {
        reset(&c);station_channel=36;station_chanspec=0xe02a;
        chanspec_status=k==0 ? STATUS_NOT_SUPPORTED : 0;
        chanspec_list[0]=k==1 ? 0 : k==2 ? 380 : k==3 ? UINT32_MAX : 1;
        chanspec_list[1]=0xe12a;
        assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0xd024 && c.Go.Channel==36);
    }


    const UINT32 invalid[]={0xe12a,0xe42a,0xe03a,0xe832,0x202a,0x1e02a,0xda26,0xe09b};
    for(unsigned k=0;k<sizeof(invalid)/sizeof(invalid[0]);k++) {
        reset(&c);station_channel=36;station_chanspec=invalid[k];chanspec_status=0;
        chanspec_list[0]=1;chanspec_list[1]=station_chanspec;
        assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0xd024 && !chanspec_queries);
    }
    reset(&c);station_channel=36;station_chanspec=0xe02a;reject_wide=TRUE;
    chanspec_status=0;chanspec_list[0]=1;chanspec_list[1]=station_chanspec;
    assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0xe02a && *(UINT32*)ops[1].data==0xd024);
    assert(c.Go.Channel==36 && c.Go.P2p.OperatingChannel==36 && !radio_down);
    reject_narrow=TRUE;calls=0;c.Go.Started=FALSE;
    assert(Ap6256GoStart(&c,&p)<0 && calls==2 && !c.Go.Started);


    reset(&c);c.FirmwareLinkUp=FALSE;station_chanspec=0xe02a;
    assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0xd024 && !chanspec_queries);
    reset(&c);p.Channel=6;station_chanspec=0x1808;
    assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0x1006 && !chanspec_queries);
    reset(&c);c.D11IoType=1;
    assert(Ap6256GoStart(&c,&p)==0 && *(UINT32*)ops[0].data==0x2b06 && !chanspec_queries);
    reset(&c);c.D11IoType=0;
    assert(Ap6256GoStart(&c,&p)==STATUS_DEVICE_PROTOCOL_ERROR && !calls);
}
static void frame_tests(void) {
    CTX c;UCHAR eth[1500],dot11[1600];ULONG n,out;
    reset(&c);
    for(unsigned i=0;i<sizeof(eth);i++)eth[i]=(UCHAR)i;
    for(unsigned role=0;role<2;role++) for(unsigned iface=0;iface<2;iface++) for(unsigned cast=0;cast<3;cast++) {
        c.Go.Mode=role?AP6256_WDI_OPMODE_P2P_CLIENT:AP6256_WDI_OPMODE_P2P_GO;
        unsigned go=iface && !role;
        const UCHAR* bssid=iface?(role?c.Go.ClientBssid:c.Go.Address):c.TalBssid;
        eth[0]=cast==0?2:cast==1?1:255;eth[12]=0x88;eth[13]=0x8e;
        assert(Ap6256TalEthernetTo80211(&c,eth,sizeof(eth),iface,dot11,sizeof(dot11),&n)==0);
        assert(dot11[1]==(go?1:2));
        assert(!memcmp(dot11+(go?4:10),bssid,6));
        assert(Ap6256Tal80211ToEthernet(dot11,n,&out)==0 && out==sizeof(eth));
        assert(!memcmp(eth,dot11,out));
    }
    {AP6256_RX_ROUTE route;
     c.Go.TalAdded=c.Go.Started=1;c.Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;
     c.Go.Peers[1].Active=c.Go.Peers[1].RxOpen=1;c.Go.Peers[1].PhyId=4;
     memcpy(c.Go.Peers[1].Address,c.Go.ClientBssid,6);
     assert(memcmp(eth+6,c.Go.ClientBssid,6)!=0);
     assert(Ap6256TalResolveRxPeer(&c,1,eth+6,&route) && route.PeerId==2 && route.PhyId==4 && route.Ready);
     c.Go.Peers[1].RxOpen=0;
     assert(Ap6256TalResolveRxPeer(&c,1,eth+6,&route) && !route.Ready);
     c.Go.Mode=AP6256_WDI_OPMODE_P2P_GO;
     assert(!Ap6256TalResolveRxPeer(&c,1,eth+6,&route));
     assert(Ap6256TalResolveRxPeer(&c,1,c.Go.ClientBssid,&route));
     assert(!Ap6256TalResolveRxPeer(&c,3,eth+6,&route));
    }
    assert(Ap6256TalEthernetTo80211(&c,eth,13,1,dot11,1600,&n)<0);
    assert(Ap6256TalEthernetTo80211(&c,eth,1500,1,dot11,10,&n)<0);
    dot11[0]=0;assert(Ap6256Tal80211ToEthernet(dot11,64,&out)<0);
}
static void put(CTX*c,NBL*n,UINT16 port,UINT16 peer) {
    memset(n,0,sizeof(*n));n->MiniportReserved[1]=(void*)((ULONG_PTR)port|((ULONG_PTR)peer<<16));
    if(c->RxQueueTail)c->RxQueueTail->next=n;else c->RxQueueHead=n;c->RxQueueTail=n;c->RxQueueCount++;
}
static void queue_tests(void) {
    CTX c;NBL n[5],*got;NDIS_STATUS status;reset(&c);c.TalPeerCreated=c.TalRxOpen=c.Go.Started=1;
    Ap6256TalRxStop(&c,WDI_PORT_ANY,&status);
    assert(status==0 && c.StationRxStopped && c.Go.RxStopped && !c.RxStopped);
    Ap6256TalRxRestart(&c,AP6256_STATION_PORT);
    assert(!c.StationRxStopped && c.Go.RxStopped);
    Ap6256TalRxRestart(&c,AP6256_GROUP_PORT);
    assert(!c.StationRxStopped && !c.Go.RxStopped);
    c.Go.Peers[1].Active=c.Go.Peers[1].RxOpen=c.Go.Peers[2].Active=1;
    put(&c,&n[0],0,0);put(&c,&n[1],2,2);put(&c,&n[2],2,3);put(&c,&n[3],0,0);put(&c,&n[4],2,2);
    c.Go.RxStopped=1;Ap6256TalRxGetMpdus(&c,WDI_PEER_ANY,0,&got);
    assert(got==&n[0] && got->next==&n[3] && !n[3].next && c.RxQueueCount==3);
    c.Go.RxStopped=0;Ap6256TalRxGetMpdus(&c,2,0,&got);
    assert(got==&n[1]&&got->next==&n[4]&&!n[4].next && c.RxQueueHead==&n[2]&&c.RxQueueTail==&n[2]);
    Ap6256TalRxGetMpdus(&c,WDI_PEER_ANY,0,&got);assert(!got && c.RxQueueCount==1);
    c.Go.Peers[2].RxOpen=1;Ap6256TalRxGetMpdus(&c,3,0,&got);assert(got==&n[2] && !c.RxQueueHead && !c.RxQueueTail);
    put(&c,&n[0],0,0);put(&c,&n[1],2,2);put(&c,&n[2],0,0);put(&c,&n[3],2,3);
    Ap6256TalFlushPortRx(&c,2,2);assert(n[1].freed&&!n[0].freed&&!n[2].freed&&!n[3].freed);
    Ap6256TalFlushPortRx(&c,2,WDI_PEER_ANY);assert(c.RxQueueCount==2 && c.RxQueueTail==&n[2]);
    Ap6256TalFlushPortRx(&c,WDI_PORT_ANY,WDI_PEER_ANY);assert(!c.RxQueueHead&&!c.RxQueueTail&&!c.RxQueueCount);
}
static unsigned creates,deletes;static int pending;
static void created(void*h,UINT16 port,UINT16 peer,WDI_MAC_ADDRESS mac) {assert(port==2&&peer>0&&peer<=9);creates++;}
static void deleted(void*h,UINT16 port,UINT16 peer,NDIS_STATUS*s) {assert(port==2&&peer>0&&peer<=9);
    assert(wlfc_cancels && cancelled_peer==peer);deletes++;*s=pending?NDIS_STATUS_PENDING:0;}
static void peer_tests(void) {
    CTX c;UCHAR addr[6]={2,0,0,0,0,0};reset(&c);c.Go.TalAdded=1;
    wlfc_cancels=0;
    c.WdiDataApi.PeerCreateIndication=created;c.WdiDataApi.PeerDeleteIndication=deleted;
    for(unsigned i=0;i<8;i++){addr[5]=(UCHAR)i;assert(Ap6256TalGoPeerCreate(&c,addr,3));}
    addr[5]=8;assert(!Ap6256TalGoPeerCreate(&c,addr,3));assert(creates==8);
    addr[5]=0;assert(Ap6256TalGoPeerCreate(&c,addr,3) && creates==8);
    pending=1;Ap6256TalGoPeerDelete(&c,addr);assert(c.Go.Peers[1].DeletePending && !c.Go.Peers[1].Active);
    addr[5]=8;assert(!Ap6256TalGoPeerCreate(&c,addr,3));
    c.Go.Peers[1].DeletePending=0;assert(Ap6256TalGoPeerCreate(&c,addr,3));
    pending=0;Ap6256TalGoPeerDelete(&c,NULL);assert(deletes==9 && wlfc_cancels==9);
    for(unsigned i=1;i<9;i++)assert(!c.Go.Peers[i].Active&&!c.Go.Peers[i].DeletePending);
}
static void client_task_init(WIFI*w,CTX*c) {
    reset(c);memset(w,0,sizeof(*w));w->Ctx=c;w->HardwareAvailable=TRUE;
    c->Go.Mode=AP6256_WDI_OPMODE_P2P_CLIENT;c->FirmwareLinkUp=FALSE;c->Go.TalAdded=TRUE;
    c->WdiDataApi.PeerCreateIndication=created;c->WdiDataApi.PeerDeleteIndication=deleted;
    w->ClientConnectTask.Active=TRUE;w->ClientConnectTask.Header.PortId=2;
    w->ClientConnectTask.Header.TransactionId=71;w->ClientConnectTask.RequestId=(void*)0xabc;
    w->ClientConnectTask.DeadlineMs=30000;w->ClientCandidateCount=1;
    AP6256_CONNECT_PARAMS*p=&w->ClientCandidates[0];p->SsidLength=4;memcpy(p->Ssid,"test",4);
    p->BssidValid=TRUE;memcpy(p->Bssid,"remote",6);p->Channel=6;p->Security=Ap6256SecurityWpa2Host;
    assoc_ok=assoc_fail=m4=disassoc=link_state=0;assoc_answer=TRUE;now_ms=0;pending=0;
    assert(Ap6256ClientStartAttempt(w)==0);
}
static void client_task_tests(void) {
    CTX c;WIFI w;LONG old;
    client_task_init(&w,&c);old=w.GroupGeneration;
    assert(c.Go.Started && !c.Go.Peers[1].RxOpen);
    Ap6256ClientLinkWork(&w,TRUE,old-1);assert(!m4 && w.ClientConnectTask.Active);
    Ap6256ClientLinkWork(&w,TRUE,old);
    assert(m4==1 && last_completion==0 && assoc_ok==1 && c.Go.ClientConnected && c.Go.Peers[1].RxOpen);
    Ap6256ClientLinkWork(&w,TRUE,old);assert(m4==1);
    Ap6256ClientLinkWork(&w,FALSE,old);assert(disassoc==1 && !c.Go.ClientConnected && !c.Go.Started);
    assert(c.TalPeerCreated==FALSE);
    client_task_init(&w,&c);old=w.GroupGeneration;
    assert(Ap6256CancelClientLocked(&w,STATUS_CANCELLED,3)==0);
    assert(m4==1 && last_completion==STATUS_CANCELLED && assoc_fail==1 && !w.ClientConnectTask.Active);
    Ap6256ClientLinkWork(&w,TRUE,old);assert(m4==1 && !c.Go.ClientConnected);
    client_task_init(&w,&c);Ap6256EvtClientConnectTimeout(&w);assert(!m4);
    now_ms=30000;Ap6256EvtClientConnectTimeout(&w);assert(m4==1 && last_completion==STATUS_IO_TIMEOUT);
    Ap6256EvtClientConnectTimeout(&w);assert(m4==1);
    client_task_init(&w,&c);w.ClientCandidateCount=2;w.ClientCandidates[1]=w.ClientCandidates[0];
    w.ClientCandidates[1].Bssid[5]++;old=w.GroupGeneration;
    Ap6256ClientLinkWork(&w,FALSE,old);assert(!m4 && assoc_fail==1 && w.ClientCandidateIndex==1);
    Ap6256ClientLinkWork(&w,TRUE,old);assert(!m4);
    Ap6256ClientLinkWork(&w,TRUE,w.GroupGeneration);assert(m4==1 && assoc_ok==1 && c.Go.ClientConnected);
    client_task_init(&w,&c);assoc_answer=FALSE;
    Ap6256ClientLinkWork(&w,TRUE,w.GroupGeneration);assert(m4==1 && last_completion<0 && !c.Go.ClientConnected);
    client_task_init(&w,&c);c.FirmwareLinkUp=TRUE;c.FirmwareMchanSupported=TRUE;
    w.ClientCandidates[0].Channel=36;station_channel=6;
    assert(Ap6256ClientStartAttempt(&w)==0 && c.Go.Channel==36 && c.FirmwareLinkUp);
    c.FirmwareMchanSupported=FALSE;
    assert(Ap6256ClientStartAttempt(&w)==STATUS_DEVICE_BUSY && c.FirmwareLinkUp);
    w.ClientCandidates[0].Channel=6;
    assert(Ap6256ClientStartAttempt(&w)==0 && c.FirmwareLinkUp);
    client_task_init(&w,&c);w.HardwareAvailable=FALSE;
    Ap6256ClientLinkWork(&w,TRUE,w.GroupGeneration);assert(!m4 && !c.Go.ClientConnected);
}
static void abort_tests(void) {
    CTX c;NBL a={0},b={0};META ma={0},mb={0};reset(&c);
    ma.u.txMetaData.PortID=0;ma.u.txMetaData.PeerID=0;mb.u.txMetaData.PortID=2;mb.u.txMetaData.PeerID=2;
    a.MiniportReserved[0]=&ma;b.MiniportReserved[0]=&mb;c.TxAborting=1;c.TxAbortPort=2;c.TxAbortPeer=2;
    assert(!Ap6256TalTxNblAborting(&c,&a)&&Ap6256TalTxNblAborting(&c,&b));assert(!Ap6256TalTxSamePeer(&a,&b));
    c.TxAbortPort=WDI_PORT_ANY;c.TxAbortPeer=WDI_PEER_ANY;assert(Ap6256TalTxNblAborting(&c,&a));
    b.MiniportReserved[0]=NULL;assert(!Ap6256TalTxNblAborting(&c,&b));
}
static void channel_tests(void) {
    CTX c;WIFI wifi={&c,0};WDI_TASK_START_AP_PARAMETERS p={0};UINT32 channel=0,list[]={11,36};
    WDI_AP_BAND_CHANNEL_LIST_CONTAINER bands[2]={0};
    reset(&c);assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==6);
    c.FirmwareMchanSupported=TRUE;


    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==6);
    station_channel=36;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==36);
    wifi.DisallowedBandMask=AP6256_DISALLOW_BAND_5G;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==1);
    wifi.DisallowedBandMask=0;station_channel=6;
    p.Optional.AdvertisedOperatingChannel_IsPresent=1;
    p.AdvertisedOperatingChannel.ChannelNumber=36;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==36);
    p.Optional.AdvertisedOperatingChannel_IsPresent=0;
    c.FirmwareMchanSupported=FALSE;
    p.StaticParameters.MustUseSpecifiedChannels=1;p.Optional.APBandChannelList_IsPresent=1;
    p.APBandChannelList.ElementCount=2;p.APBandChannelList.pElements=bands;
    bands[0].BandID=WDI_BAND_ID_2400;bands[1].BandID=WDI_BAND_ID_5000;
    for(unsigned i=0;i<2;i++){bands[i].Optional.ChannelList_IsPresent=1;bands[i].ChannelList.ElementCount=1;bands[i].ChannelList.pElements=&list[i];}
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==STATUS_DEVICE_BUSY);
    c.FirmwareMchanSupported=TRUE;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==11);
    c.FirmwareMchanSupported=FALSE;
    c.FirmwareLinkUp=0;p.Optional.AdvertisedOperatingChannel_IsPresent=1;p.AdvertisedOperatingChannel.ChannelNumber=36;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==36);
    wifi.DisallowedBandMask=AP6256_DISALLOW_BAND_5G;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==11);
    wifi.DisallowedBandMask=0;list[0]=13;list[1]=52;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==STATUS_DEVICE_BUSY);
    p.StaticParameters.MustUseSpecifiedChannels=0;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==0 && channel==36);
    bands[0].ChannelList.pElements=NULL;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==STATUS_INVALID_PARAMETER);
    p.Optional.APBandChannelList_IsPresent=0;valid_channels[0]=65;
    assert(Ap6256SelectApChannel(&wifi,&p,&channel)==STATUS_INVALID_BUFFER_SIZE);
}
int main(void) {parser_tests();firmware_tests();client_firmware_tests();bandwidth_tests();frame_tests();queue_tests();peer_tests();client_task_tests();abort_tests();channel_tests();
    puts("PASS: WPA2 privacy with either OS exclude policy, unsupported EAPOL iovar, interface-scoped restriction readback, P2P client lifecycle/cancel/timeout/retry/stale events, firmware routing/failure rollback, frame round-trips, per-port RX/stop/restart, peer exhaustion/churn, scoped TX abort, channel constraints, malformed association events (10,000 cases)");return 0;}
'''

def main():
    global START_SOURCE, CREATE_SOURCE, STOP_SOURCE
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, default=ROOT / 'build' / 'x64' / 'hotspot-tests')
    ap.add_argument('--start-source', type=Path, help='Use an older GoStart body as a negative control')
    ap.add_argument('--create-source', type=Path, help='Use an older GoCreate body as a negative control')
    ap.add_argument('--stop-source', type=Path, help='Use an older GoStop body as a negative control')
    args = ap.parse_args()
    START_SOURCE = args.start_source
    CREATE_SOURCE = args.create_source
    STOP_SOURCE = args.stop_source
    args.output.mkdir(parents=True, exist_ok=True)
    ctx = read_source_text(ROOT / 'src/common/ap6256.h')
    text = re.search('typedef enum _AP6256_GO_DATA_STAGE \\{[\\s\\S]*?\\} AP6256_GO_DATA_STAGE;', ctx)[0] + '\n' + PREAMBLE
    bcdc_limits = read_source_text(ROOT / 'src/common/bcdc.h')
    text += re.search('^#define\\s+AP6256_BCDC_TX_MAXLEN\\s+[^\\n]+', bcdc_limits, re.M)[0] + '\n'
    tal = read_source_text(ROOT / 'src/wdi/wdi_tal.c')
    text += re.search('typedef struct _AP6256_RX_ROUTE \\{[\\s\\S]*?\\} AP6256_RX_ROUTE;', tal)[0] + '\n'
    text += '\n'.join(re.findall('^#define AP6256_(?:FC|ETH|80211|LLC)[^\\n]+', tal, re.M))
    text += '\nstatic const UCHAR Ap6256OuiBridgeTunnel[3]={0,0,0xf8},Ap6256OuiRfc1042[3]={0,0,0};\n'
    bcdc = read_source_text(ROOT / 'src/common/sdpcm.h')
    for const in ['BRCMF_C_DISASSOC', 'BRCMF_C_SET_INFRA', 'BRCMF_C_SET_SSID', 'BRCMF_C_SET_WEP_RESTRICT', 'BRCMF_C_SET_BCNPRD', 'BRCMF_C_SET_DTIMPRD', 'BRCMF_C_SET_KEY_PRIMARY', 'BRCMF_C_GET_VALID_CHANNELS', 'BRCMF_C_GET_AUTH', 'BRCMF_C_GET_WEP_RESTRICT', 'BRCMF_C_GET_WSEC', 'BRCMF_C_GET_WPA_AUTH']:
        text += re.search('^#define\\s+' + const + '\\s+[^\\n]+', bcdc, re.M)[0] + '\n'
    wifi_ops = read_source_text(ROOT / 'src/common/wifi_ops.c')
    text += '\n'.join(re.findall('^#define BRCMU_[^\\n]+', wifi_ops, re.M)) + '\n'
    signatures = [('wifi_ops.c', 'NTSTATUS Ap6256EncodeChanspec(UINT8 IoType,const AP6256_SCAN_CHANNEL* Channel,PUINT16 Chanspec)'), ('hotspot.c', 'NTSTATUS Ap6256ClientDisconnect(CTX* Ctx,UINT32 Reason)'), ('hotspot.c', 'BOOLEAN Ap6256GoParseAssocResult(const UCHAR* Data,ULONG Length,AP6256_GO_ASSOC_RESULT* Result)'), ('hotspot.c', 'NTSTATUS Ap6256WaitFirmwareInterface(CTX* Ctx,UINT32 BssIndex,PUINT32 IfIndex)'), ('hotspot.c', 'NTSTATUS Ap6256GoPrepare(CTX* Ctx)'), ('hotspot.c', 'NTSTATUS Ap6256GoSetBsscfg(CTX* Ctx,PCSTR Name,const VOID* Data,ULONG Length)'), ('hotspot.c', 'VOID Ap6256P2pTraceMemory(CTX* Ctx,const CHAR* Stage)'), ('hotspot.c', 'NTSTATUS Ap6256GoCreate(CTX* Ctx)'), ('hotspot.c', 'NTSTATUS Ap6256GoVerifySecurity(CTX* Ctx,PAP6256_AP_PARAMS Params)'), ('hotspot.c', 'BOOLEAN Ap6256GoWideChanspecMatches(UINT8 IoType,UINT32 Chanspec,UINT32 Primary)'), ('hotspot.c', 'UINT32 Ap6256GoSharedChanspec(CTX* Ctx,UINT32 Primary,UINT32 Fallback)'), ('hotspot.c', 'NTSTATUS Ap6256GoStart(CTX* Ctx,PAP6256_AP_PARAMS Params)'), ('hotspot.c', 'NTSTATUS Ap6256GoStop(CTX* Ctx)'), ('hotspot.c', 'NTSTATUS Ap6256GoDelete(CTX* Ctx)'), ('hotspot.c', 'NTSTATUS Ap6256GroupChangeMode(CTX* Ctx,UINT32 Mode)'), ('hotspot.c', 'NTSTATUS Ap6256ClientConnect(CTX* Ctx,const AP6256_CONNECT_PARAMS* Params)'), ('hotspot.c', 'NTSTATUS Ap6256GoDisconnectPeer(CTX* Ctx,const UCHAR* Address,UINT16 Reason)'), ('wdi_tal.c', 'NTSTATUS Ap6256TalEthernetTo80211(CTX* Ctx,const UCHAR* Eth,ULONG EthLength,UINT32 IfIndex,PUCHAR Out,ULONG Capacity,PULONG OutLength)'), ('wdi_tal.c', 'BOOLEAN Ap6256TalResolveRxPeer(CTX* Ctx,UINT32 IfIndex,const UCHAR* Source,AP6256_RX_ROUTE* Route)'), ('wdi_tal.c', 'NTSTATUS Ap6256Tal80211ToEthernet(PUCHAR Buffer,ULONG Length,PULONG EthLength)'), ('wdi_tal.c', 'VOID Ap6256TalFlushPortRx(CTX* Ctx,UINT16 Port,UINT16 Peer)'), ('wdi_tal.c', 'VOID Ap6256TalRxGetMpdus(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PEER_ID PeerId,WDI_EXTENDED_TID ExTid,PNET_BUFFER_LIST* ppNBL)'), ('wdi_tal.c', 'VOID Ap6256TalRxStop(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId,NDIS_STATUS* pWifiStatus)'), ('wdi_tal.c', 'VOID Ap6256TalRxRestart(TAL_TXRX_HANDLE MiniportTalTxRxContext,WDI_PORT_ID PortId)'), ('wdi_tal.c', 'BOOLEAN Ap6256TalGoPeerCreate(CTX* Ctx,const UCHAR* Address,UINT32 PhyId)'), ('wdi_tal.c', 'VOID Ap6256TalGoPeerDelete(CTX* Ctx,const UCHAR* Address)'), ('wdi_tal.c', 'BOOLEAN Ap6256TalTxNblAborting(CTX* Ctx,PNET_BUFFER_LIST Nbl)'), ('wdi_tal.c', 'BOOLEAN Ap6256TalTxSamePeer(PNET_BUFFER_LIST A,PNET_BUFFER_LIST B)'), ('netadapter.c', 'NTSTATUS Ap6256ClientStartAttempt(PAP6256_WIFI Wifi)'), ('netadapter.c', 'VOID Ap6256ClientAttemptResult(PAP6256_WIFI Wifi,BOOLEAN Up,NTSTATUS FailureStatus)'), ('netadapter.c', 'NTSTATUS Ap6256CancelClientLocked(PAP6256_WIFI Wifi,NTSTATUS CompletionStatus,UINT32 Reason)'), ('netadapter.c', 'VOID Ap6256ClientLinkWork(PAP6256_WIFI Wifi,BOOLEAN Up,LONG Generation)'), ('netadapter.c', 'VOID Ap6256EvtClientConnectTimeout(PVOID Context)'), ('netadapter.c', 'BOOLEAN Ap6256BandIsMasked(LONG Mask,WDI_BAND_ID BandId)'), ('netadapter.c', 'BOOLEAN Ap6256BandIsDisallowed(PAP6256_WIFI Wifi,WDI_BAND_ID BandId)'), ('netadapter.c', 'BOOLEAN Ap6256ApChannelRequested(const WDI_TASK_START_AP_PARAMETERS* P,UINT32 Channel)'), ('netadapter.c', 'NTSTATUS Ap6256SelectApChannel(PAP6256_WIFI Wifi,const WDI_TASK_START_AP_PARAMETERS* P,PULONG Channel)')]
    for (file, sig) in signatures:
        name = re.search('(Ap6256\\w+)\\(', sig)[1]
        text += '\n' + sig + '\n' + body(file, name) + '\n'
    text += TESTS
    source = args.output / 'hotspot-tests.c'
    write_text(source, text, encoding='utf-8')
    vc = VC
    sdk = SDK
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c11', '/W4', '/WX', '/wd4100', '/Od', '/I' + str(vc / 'include'), '/I' + str(INC / 'ucrt'), str(source), '/Fe:' + str(args.output / 'hotspot-tests.exe'), '/Fo:' + str(args.output / 'hotspot-tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt' / 'x64'), '/LIBPATH:' + str(LIB / 'um' / 'x64')]
    subprocess.run(command, check=True)
    subprocess.run([str(args.output / 'hotspot-tests.exe')], check=True)
if __name__ == '__main__':
    main()
