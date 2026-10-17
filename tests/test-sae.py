# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute the production SAE exchange and CYW wire writers on the host.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util
import argparse
from pathlib import Path
import re
import subprocess
from wdi_test_support import contract_preamble
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('cap', ROOT / 'tests/test-wdi-capabilities.py')
cap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cap)
PRE = cap.PREAMBLE.split('struct Device {')[0] + r'''
#include <vector>
#include <string>
#include <initializer_list>
typedef LONG NTSTATUS;
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xc0000184)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225)
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xc0000186)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xc00000a3)
#define MAXULONG 0xffffffffu
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif
struct Device { BOOLEAN FirmwareExternalAuth; BOOLEAN FirmwareMfpSupported;
    BOOLEAN FirmwareSaePatchVerified, FirmwarePrivateSaeAbi, FirmwarePrivateSae; };
typedef Device* PAP6256_DEVICE_CONTEXT;
struct AP6256_BCDC_QUERY_RESULT {
    BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;
};
static std::string fw_caps;
static std::vector<UCHAR> fw_mask;
static UCHAR fw_pmkid[28];
static UINT32 fw_auth=3;
static UINT32 fw_wsec=1540;
static UINT32 fw_wpa_auth=0x40000;
static UCHAR fw_private[40],fw_private_peer[6];
static ULONG fw_private_length=47;
static bool fw_no_reply,fw_private_drop,fw_private_mode_drop;
static void fw_put32(ULONG offset,UINT32 value) {memcpy(fw_private+offset,&value,4);}
static UINT32 fw_word(ULONG offset) {UINT32 v;memcpy(&v,fw_private+offset,4);return v;}
static bool fw_short,fw_drop,fw_error,fw_clamp;
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*,UINT32,const char* name,void* p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    memset(r,0,sizeof(*r));r->FirmwareReply=(BOOLEAN)!fw_no_reply;r->FirmwareError=fw_error;
    if(fw_error)return STATUS_UNSUCCESSFUL;
    if(!strcmp(name,"cap")) {
        r->PayloadLength=(ULONG)fw_caps.size()+1;
        memset(p,0,n);memcpy(p,fw_caps.c_str(),min(n,r->PayloadLength));
    } else if(!strcmp(name,"event_msgs_ext")) {
        r->PayloadLength=4+(ULONG)fw_mask.size();
        memset(p,0,n);auto b=(UCHAR*)p;b[2]=(UCHAR)fw_mask.size();
        memcpy(b+4,fw_mask.data(),min(n-4,(ULONG)fw_mask.size()));
        if(fw_drop)b[4+189/8]&=~(1<<(189&7));
    } else if(!strcmp(name,"ap_sae")) {
        assert(n==40);memcpy(p,fw_private,n);r->PayloadLength=fw_private_length;
    } else if(!strcmp(name,"event_msgs")) {
        memset(p,0,n);((UCHAR*)p)[0]=fw_drop?0:8;r->PayloadLength=18;
    } else if(!strcmp(name,"pmkid_info")) {
        assert(n==sizeof(fw_pmkid));memcpy(p,fw_pmkid,n);
        r->PayloadLength=fw_short?(fw_pmkid[0]?25:3):n;
        if(fw_drop)((UCHAR*)p)[0]^=1;
        if(fw_clamp)((UCHAR*)p)[25]^=1;
    } else {assert(!strcmp(name,"mfp"));UINT32 v=fw_clamp?1:
        (fw_wsec&0x400)?2:(fw_wsec>>9)&1;memcpy(p,&v,4);r->PayloadLength=fw_short?3:4;}
    return 0;
}
static NTSTATUS Ap6256BcdcQueryDcmdResultIf(Device*,UINT32,UINT32 cmd,void* p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(n==4);memset(r,0,sizeof(*r));r->FirmwareReply=TRUE;
    r->PayloadLength=fw_short?3:4;UINT32 v=cmd==BRCMF_C_GET_AUTH?fw_auth:
        cmd==BRCMF_C_GET_WPA_AUTH?fw_wpa_auth:cmd==BRCMF_C_GET_WSEC?fw_wsec:1;
    if(fw_clamp&&cmd==BRCMF_C_GET_AUTH)v=2;
    memcpy(p,&v,4);return fw_error?STATUS_UNSUCCESSFUL:0;
}
struct Write { std::string name; std::vector<UCHAR> bytes; };
static std::vector<Write> writes;
static NTSTATUS firmware_status;
static NTSTATUS Ap6256BcdcSetIovar(Device*,const char* name,const VOID* p,ULONG n) {
    writes.push_back({name,std::vector<UCHAR>((const UCHAR*)p,(const UCHAR*)p+n)});
    if(!strcmp(name,"event_msgs_ext")) {
        auto b=(const UCHAR*)p;assert(n>=4 && b[0]==1 && b[1]==3 && b[2]==n-4);
        fw_mask.assign(b+4,b+n);
    } else if(!strcmp(name,"pmkid_info") && !firmware_status) {
        assert(n==sizeof(fw_pmkid));memcpy(fw_pmkid,p,n);
    }
    return firmware_status;
}
static NTSTATUS Ap6256BcdcSetIovarResultIf(Device*,UINT32 iface,const char* name,
    const VOID* p,ULONG n,AP6256_BCDC_QUERY_RESULT* r) {
    assert(iface==0 && !strcmp(name,"ap_sae") && n>=32 && n<=1056);
    memset(r,0,sizeof(*r));r->FirmwareReply=(BOOLEAN)!fw_no_reply;r->FirmwareError=fw_error;
    writes.push_back({name,std::vector<UCHAR>((const UCHAR*)p,(const UCHAR*)p+n)});
    if(firmware_status)return firmware_status;
    if(fw_error)return STATUS_UNSUCCESSFUL;
    const UCHAR* b=(const UCHAR*)p;UINT16 op,version,len,flags,reserved;UINT32 magic,total,gen,timeout;
    memcpy(&magic,b,4);memcpy(&version,b+4,2);memcpy(&op,b+6,2);memcpy(&total,b+8,4);
    memcpy(&gen,b+12,4);memcpy(&flags,b+22,2);memcpy(&len,b+24,2);
    memcpy(&reserved,b+26,2);memcpy(&timeout,b+28,4);
    assert(magic==0x31415341 && version==1 && total==n && gen && len==n-32 && (op==6 ? !(flags&~2u) : !flags) && !reserved);
    if(fw_private_drop)return 0;
    if(op==1 || op==6) {
        assert(fw_word(20)==0 && gen>fw_word(16) && timeout>=1000 && timeout<=30000);
        assert(len==(op==6?16u:0u));memcpy(fw_private_peer,b+16,6);
        fw_put32(16,gen);fw_put32(20,op==6?4:1);fw_put32(36,op==6?(fw_private_mode_drop?1u:1u|flags):0);
    } else {
        assert(gen==fw_word(16) && !memcmp(b+16,fw_private_peer,6) && !timeout);
        if(op==2) {
            assert(len>=8 && fw_word(20)==2);fw_put32(24,fw_word(24)+1);
            if(b[34]==1) {memcpy(fw_private+32,b+38,2);if(b[36]==126)fw_put32(36,2);}
            else fw_private[34]|=1;
        } else if(op==3) {
            assert(!len && fw_word(20)==2);
            if(fw_word(24)<2 || fw_word(28)<2 || fw_private[34]!=3) {
                r->FirmwareError=TRUE;r->FirmwareStatus=-2;return STATUS_UNSUCCESSFUL;
            }
            fw_put32(20,3);
        } else {
            assert((op==4 || op==5) && !len);
            fw_put32(20,0);memset(fw_private+24,0,16);
        }
    }
    return 0;
}


struct CywMgmtHeader {
    UINT32 version,dwell_time;UINT16 len,frame_control,channel;
    UCHAR da[6],bssid[6];UINT32 packet_id;
};
struct CywAuthStatus {
    UINT16 flags;UCHAR peer_mac[6];UINT32 ssid_len;UCHAR ssid[32],pmkid[16];
};
static_assert(sizeof(CywMgmtHeader)==32 && offsetof(CywMgmtHeader,packet_id)==28,"CYW management ABI");
static_assert(sizeof(CywAuthStatus)==60 && offsetof(CywAuthStatus,ssid_len)==8,"CYW external-auth ABI");
'''
TEST = r'''
static const UCHAR local[6]={2,1,2,3,4,5},peer[6]={2,6,7,8,9,10},other[6]={2,9,9,9,9,9};
static UCHAR scalar[66],element[132],confirm[64],token[254],groups[254];
static AP6256_SAE s;
static AP6256_SAE_OUTPUT out;
static unsigned assertions;
#define CHECK(x) do {++assertions;assert(x);} while(0)
static void begin(LONG generation=1) {
    CHECK(Ap6256SaeBegin(&s,local,peer,generation,0,30000,&out)==0);
    CHECK(out.Notice==Ap6256SaeNeedCommit && !out.TxLength);
}
static AP6256_SAE_COMMIT commit(bool h2e=false,USHORT group=19,ULONG tokens=0,ULONG rejected=0) {
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};
    memcpy(p.BssId.Address,peer,6);
    p.SAERequestType=h2e?WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS:WDI_SAE_REQUEST_TYPE_COMMIT_PARAMS;
    p.Optional.SAECommitParams_IsPresent=TRUE;
    auto& q=p.SAECommitParams;
    q.FiniteCyclicGroup=group;
    ULONG n=group==19?32:(group==20?48:66);
    q.Optional.Scalar_IsPresent=TRUE;q.Scalar.pElements=scalar;q.Scalar.ElementCount=n;
    q.Optional.Element_IsPresent=TRUE;q.Element.pElements=element;q.Element.ElementCount=2*n;
    if(tokens){q.Optional.AntiCloggingToken_IsPresent=TRUE;q.AntiCloggingToken.pElements=token;q.AntiCloggingToken.ElementCount=tokens;}
    if(rejected){q.Optional.RejectedGroups_IsPresent=TRUE;q.RejectedGroups.pElements=groups;q.RejectedGroups.ElementCount=rejected;}
    TLV_CONTEXT context={};context.PeerVersion=AP6256_TEST_WDI_VERSION;
    UCHAR* bytes=nullptr;ULONG length=0;
    CHECK(GenerateWdiSetSaeAuthParamsToIhv(&p,0,&context,&length,&bytes)==0);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND parsed={};
    CHECK(ParseWdiSetSaeAuthParamsToIhv(length,bytes,&context,&parsed)==0);
    CHECK(parsed.Optional.SAECommitParams_IsPresent);
    auto& v=parsed.SAECommitParams;
    CHECK(v.FiniteCyclicGroup==group && v.Scalar.ElementCount==n &&
          v.Element.ElementCount==2*n && memcmp(v.Scalar.pElements,scalar,n)==0);
    CHECK(v.AntiCloggingToken.ElementCount==tokens && v.RejectedGroups.ElementCount==rejected);
    CleanupParsedWdiSetSaeAuthParamsToIhv(&parsed);FreeGenerated(bytes);
    return {group,(BOOLEAN)h2e,{scalar,n},{element,2*n},{token,tokens},{groups,rejected}};
}
static std::vector<UCHAR> frame(USHORT transaction=1,USHORT status=0,ULONG payload=100) {
    std::vector<UCHAR> f(30+payload);
    f[0]=0xb0;memcpy(f.data()+4,local,6);memcpy(f.data()+10,peer,6);memcpy(f.data()+16,peer,6);
    f[24]=3;f[26]=(UCHAR)transaction;f[28]=(UCHAR)status;f[29]=(UCHAR)(status>>8);
    for(ULONG i=30;i<f.size();++i)f[i]=(UCHAR)i;
    return f;
}
static void received_commit() {
    auto f=frame();CHECK(Ap6256SaeReceive(&s,s.Generation,1,f.data(),(ULONG)f.size(),&out)==0);
    CHECK(out.Notice==Ap6256SaePeerCommit && out.RxLength==f.size() &&
          memcmp(out.RxFrame,f.data(),f.size())==0 && s.State==Ap6256SaeCommitDecision);
}
static void supplied_commit(bool h2e=false,USHORT group=19,ULONG tokens=0,ULONG rejected=0) {
    auto p=commit(h2e,group,tokens,rejected);
    CHECK(Ap6256SaeCommit(&s,s.Generation,peer,0,&p,&out)==0);
    CHECK(out.TxLength>=104 && out.PacketId && s.State==Ap6256SaeCommitResponse);
}
static void supplied_confirm() {
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};
    memcpy(p.BssId.Address,peer,6);p.SAERequestType=WDI_SAE_REQUEST_TYPE_CONFIRM_PARAMS;
    p.Optional.SAEConfirmParams_IsPresent=TRUE;
    p.SAEConfirmParams.SendConfirm=0x1234;
    p.SAEConfirmParams.Confirm.pElements=confirm;p.SAEConfirmParams.Confirm.ElementCount=s.ConfirmLength;
    TLV_CONTEXT c={};c.PeerVersion=AP6256_TEST_WDI_VERSION;
    UCHAR* bytes=nullptr;ULONG length=0;
    CHECK(GenerateWdiSetSaeAuthParamsToIhv(&p,0,&c,&length,&bytes)==0);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND q={};
    CHECK(ParseWdiSetSaeAuthParamsToIhv(length,bytes,&c,&q)==0);
    CHECK(Ap6256SaeConfirm(&s,s.Generation,peer,2,q.SAEConfirmParams.SendConfirm,
          q.SAEConfirmParams.Confirm.pElements,q.SAEConfirmParams.Confirm.ElementCount,&out)==0);
    CHECK(out.TxLength==8+s.ConfirmLength && out.TxBody[0]==3 && out.TxBody[2]==2 &&
          out.TxBody[4]==0 && out.TxBody[5]==0 && out.TxBody[6]==0x34 && out.TxBody[7]==0x12 &&
          memcmp(out.TxBody+8,confirm,s.ConfirmLength)==0);
    CleanupParsedWdiSetSaeAuthParamsToIhv(&q);FreeGenerated(bytes);
}
static void invalid_inputs() {
    begin();AP6256_SAE old=s;
    CHECK(Ap6256SaeBegin(&s,local,local,1,0,30000,&out)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeBegin(&s,local,peer,0,0,30000,&out)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeBegin(&s,local,peer,1,0,30001,&out)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeBegin(&s,local,peer,1,-1,30000,&out)==STATUS_INVALID_PARAMETER);
    CHECK(memcmp(&old,&s,sizeof(s))==0);
    CHECK(Ap6256SaeBegin(&s,local,peer,1,0x7ffffffffffffffeLL,0x7fffffffffffffffLL,&out)==0);
    CHECK(s.RetryAtMs==0x7fffffffffffffffLL);
    begin();old=s;
    auto p=commit();
    CHECK(Ap6256SaeCommit(&s,2,peer,0,&p,&out)==STATUS_INVALID_DEVICE_STATE);
    CHECK(Ap6256SaeCommit(&s,1,other,0,&p,&out)==STATUS_INVALID_DEVICE_STATE);
    CHECK(Ap6256SaeConfirm(&s,1,peer,0,1,confirm,32,&out)==STATUS_INVALID_DEVICE_STATE);
    for(ULONG k=0;k<8;++k) {
        auto q=p;
        switch(k) {
        case 0:q.Group=22;break;case 1:q.Scalar.Length=31;break;
        case 2:q.Element.Length=65;break;case 3:q.Scalar.Data=nullptr;break;
        case 4:q.Token.Length=255;break;case 5:q.Token={nullptr,1};break;
        case 6:q.RejectedGroups={groups,2};break;case 7:q.H2e=TRUE;q.RejectedGroups.Length=3;break;
        }
        CHECK(Ap6256SaeCommit(&s,1,peer,0,&q,&out)==STATUS_INVALID_PARAMETER);
        CHECK(!out.TxLength && !out.PacketId && memcmp(&old,&s,sizeof(s))==0);
    }
}
static void wire_layout() {
    for(USHORT group:{(USHORT)19,(USHORT)20,(USHORT)21})for(bool h2e:{false,true}) {
        begin();supplied_commit(h2e,group,7,h2e?4:0);
        ULONG n=group==19?32:(group==20?48:66),offset=8;
        CHECK(out.TxBody[0]==3 && out.TxBody[1]==0 && out.TxBody[2]==1 && out.TxBody[3]==0);
        CHECK(Ap6256SaeRead16(out.TxBody+4)==(h2e?126:0) && Ap6256SaeRead16(out.TxBody+6)==group);
        if(!h2e){CHECK(memcmp(out.TxBody+offset,token,7)==0);offset+=7;}
        CHECK(memcmp(out.TxBody+offset,scalar,n)==0);offset+=n;
        CHECK(memcmp(out.TxBody+offset,element,2*n)==0);offset+=2*n;
        if(h2e) {
            CHECK(out.TxBody[offset]==255 && out.TxBody[offset+1]==5 && out.TxBody[offset+2]==92);
            CHECK(memcmp(out.TxBody+offset+3,groups,4)==0);offset+=7;
            CHECK(out.TxBody[offset]==255 && out.TxBody[offset+1]==8 && out.TxBody[offset+2]==93);
            CHECK(memcmp(out.TxBody+offset+3,token,7)==0);offset+=10;
        }
        CHECK(out.TxLength==offset);
        received_commit();supplied_confirm();
    }
    begin();supplied_commit(true,21,254,254);CHECK(out.TxLength==8+198+257+257);
}
static void exchange() {
    for(bool early:{false,true}) {
        begin();supplied_commit();UINT32 first=out.PacketId;
        CHECK(Ap6256SaeTxStatus(&s,1,first,false,&out)==0);
        CHECK(Ap6256SaeTxStatus(&s,1,first,true,&out)==STATUS_NOT_FOUND);
        received_commit();
        CHECK(Ap6256SaeFinish(&s,1,peer,2,TRUE,0,&out)==STATUS_INVALID_DEVICE_STATE);
        auto f=frame(2,0,34);
        if(early) {
            CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==0);
            CHECK(!out.RxLength && out.Notice==Ap6256SaeNoNotice);
            CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==STATUS_NOT_FOUND);
        }
        supplied_confirm();
        if(!early)CHECK(Ap6256SaeReceive(&s,1,3,f.data(),(ULONG)f.size(),&out)==0);
        CHECK(out.Notice==Ap6256SaePeerConfirm && s.State==Ap6256SaeStatus);
        CHECK(Ap6256SaeFinish(&s,2,peer,3,TRUE,0,&out)==STATUS_INVALID_DEVICE_STATE);
        CHECK(Ap6256SaeFinish(&s,1,other,3,TRUE,0,&out)==STATUS_INVALID_DEVICE_STATE);
        CHECK(Ap6256SaeFinish(&s,1,peer,3,TRUE,0,&out)==0);
        CHECK(s.State==Ap6256SaeAccepted && !s.CommitLength);
        CHECK(Ap6256SaeFinish(&s,1,peer,3,TRUE,0,&out)==STATUS_INVALID_DEVICE_STATE);
        begin(2);supplied_commit();CHECK(out.PacketId!=first);
        CHECK(Ap6256SaeTxStatus(&s,2,first,true,&out)==STATUS_NOT_FOUND);
    }

    for(USHORT status:{(USHORT)0,(USHORT)76,(USHORT)77,(USHORT)126}) {
        begin();supplied_commit();auto f=frame(1,status);
        CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==0);
        CHECK(out.Notice==Ap6256SaePeerCommit && Ap6256SaeRead16(out.RxFrame+28)==status);
        auto p=commit(true,20,8,2);CHECK(Ap6256SaeCommit(&s,1,peer,2,&p,&out)==0);
    }
}
static void bounded_retries() {
    begin();supplied_commit();auto original=std::vector<UCHAR>(out.TxBody,out.TxBody+out.TxLength);
    UINT32 packet=out.PacketId;
    CHECK(Ap6256SaeTimeout(&s,2,1000,&out)==STATUS_INVALID_DEVICE_STATE);
    CHECK(Ap6256SaeTimeout(&s,1,999,&out)==STATUS_NOT_FOUND);
    for(ULONG i=1;i<AP6256_SAE_TX_LIMIT;++i) {
        CHECK(Ap6256SaeTimeout(&s,1,1000*i,&out)==0);
        CHECK(out.PacketId!=packet && out.TxLength==original.size() &&
              memcmp(out.TxBody,original.data(),original.size())==0);
        packet=out.PacketId;
    }
    CHECK(Ap6256SaeTimeout(&s,1,8000,&out)<0 && out.Notice==Ap6256SaeError && !out.TxLength);
    begin();supplied_commit();received_commit();supplied_confirm();
    CHECK(Ap6256SaeTimeout(&s,1,1002,&out)==0);
    CHECK(out.Notice==Ap6256SaeNeedNewConfirm && !out.TxLength && s.State==Ap6256SaeConfirmParameters);
    CHECK(Ap6256SaeTimeout(&s,1,2002,&out)<0 && out.Status==52);
    begin();CHECK(Ap6256SaeTimeout(&s,1,1000,&out)<0 && out.Status==51);
    begin();supplied_commit();CHECK(Ap6256SaeFinish(&s,1,peer,1,FALSE,35,&out)<0 && out.Status==35);
    CHECK(s.State==Ap6256SaeFailed);
    begin();auto p=commit();CHECK(Ap6256SaeCommit(&s,1,peer,30000,&p,&out)<0 && !out.TxLength);
}
static void rx_bounds() {
    begin();supplied_commit();auto good=frame();AP6256_SAE original=s;
    for(ULONG n=0;n<30;++n) {
        CHECK(Ap6256SaeReceive(&s,1,1,good.data(),n,&out)==STATUS_INVALID_PARAMETER);
        CHECK(memcmp(&s,&original,sizeof(s))==0);
    }
    for(ULONG pos:{0u,1u,4u,10u,16u,22u,24u,25u}) {
        auto f=good;f[pos]^=1;
        CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==STATUS_INVALID_PARAMETER);
        CHECK(!out.RxLength && memcmp(&s,&original,sizeof(s))==0);
    }
    auto f=good;f[26]=2;CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==STATUS_NOT_FOUND);
    f=good;f[1]|=0x40;CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==STATUS_INVALID_PARAMETER);
    f.resize(AP6256_SAE_FRAME_MAX+1);CHECK(Ap6256SaeReceive(&s,1,1,f.data(),(ULONG)f.size(),&out)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeReceive(&s,2,1,good.data(),(ULONG)good.size(),&out)==STATUS_INVALID_DEVICE_STATE);
}
static void firmware_writers() {
    Device d={};begin();supplied_commit(true,19,5,4);
    auto body=std::vector<UCHAR>(out.TxBody,out.TxBody+out.TxLength);
    UINT32 packet=out.PacketId;writes.clear();firmware_status=0;
    CHECK(Ap6256SaeSendAuth(&d,36,peer,packet,body.data(),(ULONG)body.size())==0);
    CHECK(writes.size()==1 && writes[0].name=="mgmt_frame");
    auto& bytes=writes[0].bytes;
    CywMgmtHeader mh={};memcpy(&mh,bytes.data(),sizeof(mh));
    CHECK(mh.version==0 && mh.dwell_time==4000 && mh.packet_id==packet && mh.len==body.size());
    CHECK(bytes.size()==32+body.size() && bytes[0]==0 && bytes[1]==0 && bytes[2]==0 && bytes[3]==0);
    CHECK(bytes[4]==0xa0 && bytes[5]==0x0f && bytes[6]==0 && bytes[7]==0);
    CHECK(Ap6256SaeRead16(bytes.data()+8)==body.size() && Ap6256SaeRead16(bytes.data()+10)==0xb0);
    CHECK(Ap6256SaeRead16(bytes.data()+12)==36 && memcmp(bytes.data()+14,peer,6)==0 &&
          memcmp(bytes.data()+20,peer,6)==0 && bytes[26]==0 && bytes[27]==0);
    CHECK(memcmp(bytes.data()+32,body.data(),body.size())==0);
    const UCHAR ssid[3]={'x',0,'y'};
    for(bool success:{false,true}) {
        CHECK(Ap6256SaeAuthStatus(&d,peer,ssid,3,(BOOLEAN)success)==0);
        auto& w=writes.back();CHECK(w.name=="auth_status" && w.bytes.size()==60);
        CywAuthStatus auth={};memcpy(&auth,w.bytes.data(),sizeof(auth));
        CHECK(auth.ssid_len==3 && auth.flags==(success?4:3) && memcmp(auth.peer_mac,peer,6)==0);
        CHECK(Ap6256SaeRead16(w.bytes.data())==(success?4:3) && memcmp(w.bytes.data()+2,peer,6)==0);
        CHECK(w.bytes[8]==3 && w.bytes[9]==0 && memcmp(w.bytes.data()+12,ssid,3)==0);
        for(size_t i=15;i<60;++i)CHECK(w.bytes[i]==0);
    }
    firmware_status=STATUS_NOT_SUPPORTED;
    CHECK(Ap6256SaeSendAuth(&d,36,peer,packet,body.data(),(ULONG)body.size())==STATUS_NOT_SUPPORTED);
    CHECK(Ap6256SaeAuthStatus(&d,peer,ssid,3,TRUE)==STATUS_NOT_SUPPORTED);
    auto count=writes.size();
    for(USHORT channel:{(USHORT)0,(USHORT)197})
        CHECK(Ap6256SaeSendAuth(&d,channel,peer,packet,body.data(),(ULONG)body.size())==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeSendAuth(&d,36,peer,0,body.data(),(ULONG)body.size())==STATUS_INVALID_PARAMETER);
    for(ULONG n=0;n<6;++n)CHECK(Ap6256SaeSendAuth(&d,36,peer,packet,body.data(),n)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaeAuthStatus(&d,peer,ssid,0,TRUE)==STATUS_INVALID_PARAMETER);
    CHECK(writes.size()==count);
}
static NTSTATUS apply(WDI_SET_SAE_AUTH_PARAMS_COMMAND* p,LONG generation=1) {
    TLV_CONTEXT c={};c.PeerVersion=AP6256_TEST_WDI_VERSION;
    UCHAR* wire=nullptr;ULONG n=0;
    CHECK(GenerateWdiSetSaeAuthParamsToIhv(p,0,&c,&n,&wire)==0);
    NTSTATUS result=Ap6256SaeApplyWdi(&s,generation,2,wire,n,&c,&out);
    FreeGenerated(wire);return result;
}
static void indication(TLV_CONTEXT* c) {
    auto expected=out;UCHAR* wire=nullptr;ULONG n=0;
    CHECK(Ap6256SaeEncodeWdi(&s,&out,c,&wire,&n)==0);
    WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED_PARAMETERS p={};
    CHECK(ParseWdiIndicationSaeAuthParamsNeededFromIhv(n,wire,c,&p)==0);
    CHECK((ULONG)p.SAEIndicationType==(ULONG)expected.Notice && memcmp(p.BssId.Address,peer,6)==0);
    if(expected.Notice==Ap6256SaePeerCommit) {
        CHECK(p.Optional.SAECommitFrame_IsPresent && p.SAECommitFrame.ElementCount==expected.RxLength-24);
        CHECK(memcmp(p.SAECommitFrame.pElements,expected.RxFrame+24,expected.RxLength-24)==0);
    } else if(expected.Notice==Ap6256SaePeerConfirm) {
        CHECK(p.Optional.SAEConfirmFrame_IsPresent && p.SAEConfirmFrame.ElementCount==expected.RxLength-24);
        CHECK(memcmp(p.SAEConfirmFrame.pElements,expected.RxFrame+24,expected.RxLength-24)==0);
    } else if(expected.Notice==Ap6256SaeError) {
        CHECK(p.Optional.SAEStatus_IsPresent && (ULONG)p.SAEStatus==expected.Status);
    }
    CleanupParsedWdiIndicationSaeAuthParamsNeededFromIhv(&p);FreeGenerated(wire);
}
static void wdi_adapter() {
    begin();TLV_CONTEXT c={};c.PeerVersion=AP6256_TEST_WDI_VERSION;indication(&c);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p={};memcpy(p.BssId.Address,peer,6);
    p.SAERequestType=WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS;
    p.Optional.SAECommitParams_IsPresent=TRUE;auto& q=p.SAECommitParams;
    q.FiniteCyclicGroup=19;q.Optional.Scalar_IsPresent=TRUE;q.Scalar.pElements=scalar;q.Scalar.ElementCount=32;
    q.Optional.Element_IsPresent=TRUE;q.Element.pElements=element;q.Element.ElementCount=64;
    CHECK(apply(&p,2)==STATUS_INVALID_DEVICE_STATE && !out.TxLength);
    CHECK(apply(&p)==0 && out.TxLength==104 && out.TxBody[4]==126);
    received_commit();indication(&c);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND cp={};memcpy(cp.BssId.Address,peer,6);
    cp.SAERequestType=WDI_SAE_REQUEST_TYPE_CONFIRM_PARAMS;
    cp.Optional.SAEConfirmParams_IsPresent=TRUE;cp.SAEConfirmParams.SendConfirm=1;
    cp.SAEConfirmParams.Confirm.pElements=confirm;cp.SAEConfirmParams.Confirm.ElementCount=32;
    CHECK(apply(&cp)==0 && out.TxLength==40);
    auto f=frame(2,0,34);CHECK(Ap6256SaeReceive(&s,1,3,f.data(),(ULONG)f.size(),&out)==0);indication(&c);
    WDI_SET_SAE_AUTH_PARAMS_COMMAND verdict={};memcpy(verdict.BssId.Address,peer,6);
    verdict.SAERequestType=WDI_SAE_REQUEST_TYPE_SUCCESS;
    CHECK(apply(&verdict)==STATUS_INVALID_PARAMETER && s.State==Ap6256SaeStatus);
    verdict.Optional.SAEStatus_IsPresent=TRUE;verdict.SAEStatus=WDI_SAE_STATUS_SUCCESS;
    CHECK(apply(&verdict)==0 && s.State==Ap6256SaeAccepted);
    begin();verdict.SAERequestType=WDI_SAE_REQUEST_TYPE_FAILURE;verdict.SAEStatus=WDI_SAE_STATUS_INITIALIZATION_NO_KEY;
    CHECK(apply(&verdict)<0 && out.Notice==Ap6256SaeError);indication(&c);
    begin();AP6256_SAE saved=s;
    for(ULONG i=0;i<8;++i) {
        UCHAR malformed[8]={0};
        CHECK(Ap6256SaeApplyWdi(&s,1,2,malformed,i,&c,&out)<0);
        CHECK(!out.TxLength && memcmp(&saved,&s,sizeof(s))==0);
    }
    c.PeerVersion=WDI_VERSION_1_1_9;
    UCHAR malformed[1]={0};
    CHECK(Ap6256SaeApplyWdi(&s,1,2,malformed,1,&c,&out)==STATUS_NOT_SUPPORTED);
    UCHAR* wire=(UCHAR*)1;ULONG n=1;
    CHECK(Ap6256SaeEncodeWdi(&s,&out,&c,&wire,&n)==STATUS_NOT_SUPPORTED && !wire && !n);
}
static void backend() {
    Device d={};fw_caps="ap sta sae_ext mfp";fw_mask.assign(25,0xa5);auto original=fw_mask;
    firmware_status=0;fw_short=fw_drop=fw_error=fw_clamp=false;
    Ap6256SaeFirmwarePrepare(&d);CHECK(d.FirmwareExternalAuth);
    for(ULONG i=0;i<25;++i)CHECK((fw_mask[i]&original[i])==original[i]);
    for(const char* c:{"sae mfp","sae_external mfp","xsae_ext mfp","sae_ext"}) {
        fw_caps=c;auto n=writes.size();Ap6256SaeFirmwarePrepare(&d);
        CHECK(d.FirmwareExternalAuth && writes.size()==n+1);
    }
    fw_caps="ap sta mfp";fw_mask.assign(25,0);Ap6256SaeFirmwarePrepare(&d);
    CHECK(d.FirmwareExternalAuth);
    fw_caps="";fw_mask.assign(25,0);Ap6256SaeFirmwarePrepare(&d);
    CHECK(d.FirmwareExternalAuth);
    fw_caps="sae_ext mfp";fw_mask.assign(18,0);auto n=writes.size();
    Ap6256SaeFirmwarePrepare(&d);CHECK(!d.FirmwareExternalAuth && writes.size()==n);
    fw_mask.assign(25,0);fw_drop=true;Ap6256SaeFirmwarePrepare(&d);CHECK(!d.FirmwareExternalAuth);
    fw_drop=false;fw_error=true;Ap6256SaeFirmwarePrepare(&d);CHECK(!d.FirmwareExternalAuth);
    fw_error=false;CHECK(Ap6256SaeVerifySecurity(&d,1540,FALSE)==0);
    CHECK(Ap6256SaeVerifySecurity(&d,516,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);
    fw_wsec=516;CHECK(Ap6256SaeVerifySecurity(&d,516,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);
    CHECK(Ap6256SaeVerifySecurity(&d,1540,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);fw_wsec=1540;
    fw_short=true;CHECK(Ap6256SaeVerifySecurity(&d,1540,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);
    fw_short=false;fw_clamp=true;CHECK(Ap6256SaeVerifySecurity(&d,1540,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);fw_clamp=false;
    fw_auth=0;CHECK(Ap6256SaeVerifySecurity(&d,1540,TRUE)==0);
    CHECK(Ap6256SaeVerifySecurity(&d,1540,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);fw_auth=3;
    CHECK(Ap6256SaeVerifySecurity(&d,1540,TRUE)==STATUS_DEVICE_PROTOCOL_ERROR);
    UCHAR req[60]={1};memcpy(req+2,peer,6);req[8]=3;memcpy(req+12,"net",3);BOOLEAN abort=TRUE;
    CHECK(Ap6256SaeAuthRequest(req,60,peer,(const UCHAR*)"net",3,&abort)==0 && !abort);
    req[0]=2;CHECK(Ap6256SaeAuthRequest(req,60,peer,(const UCHAR*)"net",3,&abort)==0 && abort);
    CHECK(Ap6256SaeAuthRequest(req,59,peer,(const UCHAR*)"net",3,&abort)<0);
    CHECK(Ap6256SaeAuthRequest(req,60,other,(const UCHAR*)"net",3,&abort)==STATUS_NOT_FOUND);
    req[0]=3;CHECK(Ap6256SaeAuthRequest(req,60,peer,(const UCHAR*)"net",3,&abort)<0);
    begin();auto c=commit();CHECK(Ap6256SaeCommit(&s,1,peer,0,&c,&out)==0);
    auto f=frame(1,0,98);std::vector<UCHAR> event(16+f.size());memcpy(event.data()+16,f.data(),f.size());
    memset(event.data()+16,0xff,24);
    CHECK(Ap6256SaeReceiveEvent(&s,1,3,other,event.data(),(ULONG)event.size(),&out)==STATUS_NOT_FOUND);
    CHECK(Ap6256SaeReceiveEvent(&s,1,3,peer,event.data(),45,&out)<0);
    CHECK(Ap6256SaeReceiveEvent(&s,1,3,peer,event.data(),(ULONG)event.size(),&out)==0 && out.Notice==Ap6256SaePeerCommit);
    UCHAR assoc[]={0,0,0,0,48,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,192,0};
    CHECK(Ap6256SaeAssociationRsn(assoc,sizeof(assoc),FALSE));
    for(ULONG k=0;k<sizeof(assoc);++k)CHECK(!Ap6256SaeAssociationRsn(assoc,k,FALSE));
    assoc[23]=2;CHECK(!Ap6256SaeAssociationRsn(assoc,sizeof(assoc),FALSE));assoc[23]=8;
    assoc[24]=128;CHECK(!Ap6256SaeAssociationRsn(assoc,sizeof(assoc),FALSE));assoc[24]=192;
    assoc[11]=2;CHECK(!Ap6256SaeAssociationRsn(assoc,sizeof(assoc),FALSE));
}

static Device private_device(UINT32 features=1) {
    memset(fw_private,0,sizeof(fw_private));fw_put32(0,0x31415341);
    fw_private[4]=1;fw_private[6]=40;fw_put32(8,1024);fw_put32(12,features);fw_put32(16,41);
    fw_private_length=47;fw_no_reply=fw_private_drop=fw_private_mode_drop=false;
    firmware_status=0;fw_error=fw_drop=fw_short=fw_clamp=false;
    fw_mask.assign(18,0);fw_caps="sta mfp";fw_wsec=3588;fw_auth=0;fw_wpa_auth=0x8000;
    Device d={};d.FirmwareSaePatchVerified=d.FirmwareMfpSupported=TRUE;
    Ap6256SaeFirmwarePrepare(&d);return d;
}

static void private_backend() {
    Device d=private_device();CHECK(d.FirmwarePrivateSaeAbi && d.FirmwarePrivateSae && !d.FirmwareExternalAuth);
    AP6256_SAE_PRIVATE_STATE state={};CHECK(Ap6256SaePrivateQuery(&d,&state)==0);
    CHECK(state.Generation==41 && state.Phase==0 && state.Features==1);
    CHECK(Ap6256SaeVerifySecurity(&d,3588,FALSE)==0);
    fw_wsec=1540;CHECK(Ap6256SaeVerifySecurity(&d,3588,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);fw_wsec=3588;
    CHECK(Ap6256SaePrivateArm(&d,100,peer,30000,nullptr,FALSE)==0);
    const auto& arm=writes.back();CHECK(arm.name=="ap_sae" && arm.bytes.size()==32);
    CHECK(!memcmp(arm.bytes.data()+16,peer,6) && arm.bytes[6]==1 && !arm.bytes[22]);
    CHECK(fw_word(16)==100 && fw_word(20)==1);
    fw_put32(20,2);begin();supplied_commit();
    CHECK(Ap6256SaePrivateCommand(&d,2,100,peer,out.TxBody,out.TxLength)==0);
    CHECK(writes.back().bytes.size()==32+out.TxLength && !memcmp(writes.back().bytes.data()+32,out.TxBody,out.TxLength));
    CHECK(fw_word(24)==1 && fw_private[32]==19);
    CHECK(Ap6256SaePrivateCommand(&d,3,100,peer,nullptr,0)==STATUS_UNSUCCESSFUL && fw_word(20)==2);
    received_commit();supplied_confirm();
    CHECK(Ap6256SaePrivateCommand(&d,2,100,peer,out.TxBody,out.TxLength)==0);
    fw_put32(28,2);fw_private[34]|=2;
    CHECK(Ap6256SaePrivateCommand(&d,3,100,peer,nullptr,0)==0 && fw_word(20)==3);
    CHECK(Ap6256SaePrivateEnd(&d,100,peer,TRUE)==0 && fw_word(20)==0 && fw_word(16)==100);
    CHECK(writes.back().bytes[6]==5);
    CHECK(Ap6256SaePrivateArm(&d,101,peer,1000,token,FALSE)==0 && fw_word(20)==4);
    CHECK(writes.back().bytes.size()==48 && !memcmp(writes.back().bytes.data()+32,token,16));
    CHECK(Ap6256SaePrivateEnd(&d,100,peer,FALSE)==STATUS_DEVICE_BUSY && fw_word(20)==4);
    CHECK(Ap6256SaePrivateEnd(&d,101,peer,FALSE)==0 && writes.back().bytes[6]==4);
    for(BOOLEAN h2e:{(BOOLEAN)FALSE,(BOOLEAN)TRUE}) {
        d=private_device();
        CHECK(Ap6256SaePrivateArm(&d,101,peer,1000,token,h2e)==0);
        CHECK(writes.back().bytes[22]==(h2e?2:0) && fw_word(36)==(h2e?3u:1u));
        CHECK(Ap6256SaePrivateEnd(&d,101,peer,FALSE)==0 && fw_word(36)==0);
    }
    auto beforeInvalid=writes.size();
    CHECK(Ap6256SaePrivateArm(&d,102,peer,1000,nullptr,TRUE)==STATUS_INVALID_PARAMETER);
    CHECK(writes.size()==beforeInvalid);
    fw_private_mode_drop=true;
    CHECK(Ap6256SaePrivateArm(&d,102,peer,1000,token,TRUE)==STATUS_DEVICE_PROTOCOL_ERROR);
    CHECK(Ap6256SaePrivateEnd(&d,102,peer,FALSE)==0);
    fw_private_mode_drop=false;
    d=private_device();
    for(UINT32 duration:{999u,30001u})CHECK(Ap6256SaePrivateArm(&d,102,peer,duration,nullptr,FALSE)==STATUS_INVALID_PARAMETER);
    auto count=writes.size();CHECK(Ap6256SaePrivateCommand(&d,2,0,peer,out.TxBody,out.TxLength)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaePrivateCommand(&d,2,102,peer,out.TxBody,7)==STATUS_INVALID_PARAMETER);
    CHECK(Ap6256SaePrivateCommand(&d,7,102,peer,nullptr,0)==STATUS_INVALID_PARAMETER && writes.size()==count);
    auto valid=std::vector<UCHAR>(fw_private,fw_private+40);
    for(ULONG pos:{0u,4u,6u,8u,12u,20u,24u,28u,32u,34u,36u}) {
        memcpy(fw_private,valid.data(),40);fw_private[pos]=0xff;
        memset(&state,0xa5,sizeof(state));CHECK(Ap6256SaePrivateQuery(&d,&state)==STATUS_DEVICE_PROTOCOL_ERROR);
        AP6256_SAE_PRIVATE_STATE zero={};CHECK(!memcmp(&state,&zero,sizeof(state)));
    }
    memcpy(fw_private,valid.data(),40);
    for(ULONG n=0;n<40;++n) {fw_private_length=n;CHECK(Ap6256SaePrivateQuery(&d,&state)==STATUS_DEVICE_PROTOCOL_ERROR);}
    for(ULONG n:{40u,41u,47u}) {fw_private_length=n;CHECK(Ap6256SaePrivateQuery(&d,&state)==0);}
    fw_private_length=40;fw_no_reply=true;CHECK(Ap6256SaePrivateArm(&d,102,peer,1000,nullptr,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);
    fw_no_reply=false;CHECK(fw_word(20)==1 && Ap6256SaePrivateEnd(&d,102,peer,FALSE)==0);
    fw_private_drop=true;CHECK(Ap6256SaePrivateArm(&d,103,peer,1000,nullptr,FALSE)==STATUS_DEVICE_PROTOCOL_ERROR);
    fw_private_drop=false;firmware_status=STATUS_UNSUCCESSFUL;
    CHECK(Ap6256SaePrivateArm(&d,103,peer,1000,nullptr,FALSE)==STATUS_UNSUCCESSFUL);firmware_status=0;
    d=private_device(0);CHECK(d.FirmwarePrivateSaeAbi && !d.FirmwarePrivateSae);
    CHECK(Ap6256SaePrivateArm(&d,100,peer,1000,nullptr,FALSE)==STATUS_NOT_SUPPORTED);
    d=private_device(2);CHECK(!d.FirmwarePrivateSaeAbi && !d.FirmwarePrivateSae);
    d=private_device();fw_drop=true;Ap6256SaeFirmwarePrepare(&d);CHECK(d.FirmwarePrivateSaeAbi && !d.FirmwarePrivateSae);
    fw_drop=false;d.FirmwareMfpSupported=FALSE;Ap6256SaeFirmwarePrepare(&d);CHECK(!d.FirmwarePrivateSae);
    d.FirmwareSaePatchVerified=FALSE;Ap6256SaeFirmwarePrepare(&d);CHECK(!d.FirmwarePrivateSaeAbi);
    fw_auth=3;fw_wpa_auth=0x40000;

    auto f=frame(1,0,98);std::vector<UCHAR> event(12+f.size(),0);
    UINT32 magic=0x31415341,gen=100;UINT16 n=(UINT16)f.size();
    memcpy(event.data(),&magic,4);memcpy(event.data()+4,&gen,4);memcpy(event.data()+8,&n,2);
    memcpy(event.data()+12,f.data(),f.size());UINT32 owner;ULONG size;
    CHECK(Ap6256SaePrivateFrame(event.data(),(ULONG)event.size(),local,peer,&owner,&size));
    CHECK(owner==100 && size==f.size());
    for(ULONG pos:{0u,4u,8u,10u,12u,13u,16u,22u,28u,34u,36u}) {
        auto bad=event;bad[pos]^=1;
        if(pos==4) {memset(bad.data()+4,0,4);}
        CHECK(!Ap6256SaePrivateFrame(bad.data(),(ULONG)bad.size(),local,peer,&owner,&size));
        CHECK(!owner && !size);
    }
    CHECK(!Ap6256SaePrivateFrame(event.data(),41,local,peer,&owner,&size));
}
static void cached_h2e() {
    BOOLEAN present=TRUE,h2e=TRUE;
    CHECK(Ap6256SaeReadRsnxe(nullptr,0,&present,&h2e)==0 && !present && !h2e);
    CHECK(Ap6256SaeReadRsnxe(nullptr,1,&present,&h2e)==STATUS_INVALID_PARAMETER && !present && !h2e);
    for(std::vector<UCHAR> ie: {std::vector<UCHAR>{244,1,0x20},
        std::vector<UCHAR>{244,2,0x21,0}, std::vector<UCHAR>{244,1,0}}) {
        CHECK(Ap6256SaeReadRsnxe(ie.data(),(ULONG)ie.size(),&present,&h2e)==0 && present);
        CHECK(!!h2e==!!(ie[2]&0x20));
        auto duplicate=ie;duplicate.insert(duplicate.end(),ie.begin(),ie.end());
        CHECK(Ap6256SaeReadRsnxe(duplicate.data(),(ULONG)duplicate.size(),&present,&h2e)<0 && !present && !h2e);
        for(bool reassoc:{false,true}) {
            std::vector<UCHAR> request(reassoc?10:4,0);request.insert(request.end(),ie.begin(),ie.end());
            CHECK(Ap6256SaeAssociationH2e(request.data(),(ULONG)request.size(),reassoc,(BOOLEAN)!!(ie[2]&0x20)));
            CHECK(!Ap6256SaeAssociationH2e(request.data(),(ULONG)request.size(),reassoc,(BOOLEAN)!(ie[2]&0x20)));
        }
    }
    for(std::vector<UCHAR> bad: {std::vector<UCHAR>{244}, std::vector<UCHAR>{244,0},
        std::vector<UCHAR>{244,2,0x20,0}, std::vector<UCHAR>{244,1,0x21},
        std::vector<UCHAR>{244,1,0x20,221}}) {
        CHECK(Ap6256SaeReadRsnxe(bad.data(),(ULONG)bad.size(),&present,&h2e)<0 && !present && !h2e);
    }
    SYSTEM_INFO si;GetSystemInfo(&si);
    auto region=(UCHAR*)VirtualAlloc(nullptr,2*si.dwPageSize,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    CHECK(region!=nullptr);DWORD old;
    CHECK(VirtualProtect(region+si.dwPageSize,si.dwPageSize,PAGE_NOACCESS,&old));
    UCHAR full[]={244,2,0x21,0};
    for(ULONG n=0;n<=sizeof(full);++n) {
        UCHAR* p=region+si.dwPageSize-n;if(n)memcpy(p,full,n);
        CHECK((Ap6256SaeReadRsnxe(p,n,&present,&h2e)==0)==(n==0||n==sizeof(full)));
    }
    VirtualFree(region,0,MEM_RELEASE);

    WDI_CONNECT_BSS_ENTRY_CONTAINER candidate={};
    UCHAR ap[15]={};ap[12]=244;ap[13]=1;ap[14]=0x20;
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)==0 && !h2e);
    candidate.Optional.BeaconFrame_IsPresent=TRUE;
    candidate.BeaconFrame.pElements=ap;candidate.BeaconFrame.ElementCount=sizeof(ap);
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)==0 && h2e);
    UCHAR explicitClassic[]={244,1,0}, explicitH2e[]={244,1,0x20};
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,explicitClassic,3,&h2e)==0 && !h2e);
    candidate.Optional.AssociationRequestVendorIE_IsPresent=TRUE;
    candidate.AssociationRequestVendorIE.pElements=explicitH2e;
    candidate.AssociationRequestVendorIE.ElementCount=3;
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)==0 && h2e);
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,explicitClassic,3,&h2e)<0 && !h2e);
    candidate.Optional.AssociationRequestVendorIE_IsPresent=FALSE;
    UCHAR probe[15]={};probe[12]=244;probe[13]=1;
    candidate.Optional.ProbeResponseFrame_IsPresent=TRUE;
    candidate.ProbeResponseFrame.pElements=probe;candidate.ProbeResponseFrame.ElementCount=15;
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)<0 && !h2e);
    probe[14]=0x20;
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)==0 && h2e);
    for(ULONG n=1;n<15;++n) {
        candidate.BeaconFrame.ElementCount=n;
        CHECK((Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)==0)==(n==12));
    }
    candidate.BeaconFrame.ElementCount=15;candidate.BeaconFrame.pElements=nullptr;
    CHECK(Ap6256SaeCopyCachedH2e(&candidate,nullptr,0,&h2e)<0 && !h2e);
}

static void private_event_owner() {
    UCHAR body[48]={};UINT32 magic=0x314f5341,gen=123,owner=0;
    UCHAR address[6]={};memcpy(body,&magic,4);memcpy(body+4,&gen,4);
    memcpy(body+8,peer,6);body[14]=1;
    for(ULONG length:{16u,17u,48u}) {
        CHECK(Ap6256SaePrivateOwner(body,length,&owner,address));
        CHECK(owner==123 && !memcmp(address,peer,6));
    }
    for(ULONG length=0;length<16;length++) {
        owner=123;memset(address,0xff,6);
        CHECK(!Ap6256SaePrivateOwner(body,length,&owner,address));
        CHECK(!owner && !memcmp(address,"\0\0\0\0\0\0",6));
    }
    for(ULONG offset:{0u,4u,8u,14u,15u}) {
        UCHAR bad[48];memcpy(bad,body,48);bad[offset]^=1;
        if(offset==4)memset(bad+4,0,4);
        CHECK(!Ap6256SaePrivateOwner(bad,48,&owner,address));
        CHECK(!owner && !memcmp(address,"\0\0\0\0\0\0",6));
    }
    memset(body+8,0,6);
    CHECK(!Ap6256SaePrivateOwner(body,48,&owner,address) && !owner);
}

static void cached_pmkid() {
    Device d={};UCHAR pmkid[16],copied[16];BOOLEAN valid=FALSE;
    for(ULONG i=0;i<16;++i)pmkid[i]=(UCHAR)(20+i);
    CHECK(Ap6256SaeCopyPmkid(TRUE,pmkid,16,copied,&valid)==0 && valid && !memcmp(copied,pmkid,16));
    for(ULONG n:{0u,15u,17u})CHECK(Ap6256SaeCopyPmkid(TRUE,pmkid,n,copied,&valid)<0 && !valid);
    CHECK(Ap6256SaeCopyPmkid(TRUE,nullptr,16,copied,&valid)<0 && !valid);
    CHECK(Ap6256SaeCopyPmkid(FALSE,nullptr,0,copied,&valid)==0 && !valid);
    for(UCHAR b:copied)CHECK(b==0);
    firmware_status=0;fw_short=fw_drop=fw_error=fw_clamp=false;
    CHECK(Ap6256SaeSetPmkid(&d,peer,pmkid)==0);
    CHECK(writes.back().name=="pmkid_info" && writes.back().bytes.size()==28);
    CHECK(fw_pmkid[0]==1 && !memcmp(fw_pmkid+4,peer,6) && !memcmp(fw_pmkid+10,pmkid,16));
    fw_short=true;CHECK(Ap6256SaeSetPmkid(&d,peer,pmkid)==STATUS_DEVICE_PROTOCOL_ERROR);fw_short=false;
    fw_drop=true;CHECK(Ap6256SaeSetPmkid(&d,peer,pmkid)==STATUS_DEVICE_PROTOCOL_ERROR);fw_drop=false;
    fw_clamp=true;CHECK(Ap6256SaeSetPmkid(&d,peer,pmkid)==STATUS_DEVICE_PROTOCOL_ERROR);fw_clamp=false;
    firmware_status=STATUS_UNSUCCESSFUL;CHECK(Ap6256SaeSetPmkid(&d,peer,pmkid)<0);firmware_status=0;
    CHECK(Ap6256SaeSetPmkid(&d,peer,nullptr)==0 && fw_pmkid[0]==0);
    for(UCHAR b:fw_pmkid)CHECK(b==0);
    fw_short=true;CHECK(Ap6256SaeSetPmkid(&d,peer,nullptr)==STATUS_DEVICE_PROTOCOL_ERROR);fw_short=false;
    std::vector<UCHAR> rsn={48,38,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,8,192,0,1,0};
    rsn.insert(rsn.end(),pmkid,pmkid+16);
    for(bool reassoc:{false,true}) {
        std::vector<UCHAR> request(reassoc?10:4,0);request.insert(request.end(),rsn.begin(),rsn.end());
        CHECK(Ap6256SaeAssociationPmkid(request.data(),(ULONG)request.size(),reassoc,pmkid));
        for(ULONG n=0;n<request.size();++n)CHECK(!Ap6256SaeAssociationPmkid(request.data(),n,reassoc,pmkid));
        request.back()^=1;CHECK(!Ap6256SaeAssociationPmkid(request.data(),(ULONG)request.size(),reassoc,pmkid));
    }
}
int main() {
    for(ULONG i=0;i<66;++i)scalar[i]=(UCHAR)i;
    for(ULONG i=0;i<132;++i)element[i]=(UCHAR)(200-i);
    for(ULONG i=0;i<64;++i)confirm[i]=(UCHAR)(100+i);
    for(ULONG i=0;i<254;++i){token[i]=(UCHAR)(i+1);groups[i]=(UCHAR)i;}
    invalid_inputs();wire_layout();exchange();bounded_retries();rx_bounds();firmware_writers();wdi_adapter();backend();cached_pmkid();private_backend();cached_h2e();private_event_owner();
    printf("PASS: %u SAE assertions\n",assertions);
}
'''

def main():
    global ROOT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    ROOT = args.source_root.resolve()
    header = read_source_text(ROOT / 'src/common/sae.h')
    source = read_source_text(ROOT / 'src/common/sae.c')
    fw_header = read_source_text(ROOT / 'src/common/sae_fw.h')
    fw_source = read_source_text(ROOT / 'src/common/sae_fw.c')
    fw_header = re.sub('^#(?:pragma once|include).*\\n', '', fw_header, flags=re.M)
    fw_source = re.sub('^#include.*\\n', '', fw_source, flags=re.M).replace('= {0};', '= {};')
    codec_header = read_source_text(ROOT / 'src/common/sae_wdi.h')
    codec_source = read_source_text(ROOT / 'src/common/sae_wdi.c')
    header = re.sub('^#(?:pragma once|include).*\\n', '', header, flags=re.M)
    source = re.sub('^#include.*\\n', '', source, flags=re.M)
    codec_header = re.sub('^#(?:pragma once|include).*\\n', '', codec_header, flags=re.M)
    codec_source = re.sub('^#include.*\\n', '', codec_source, flags=re.M)
    codec_source = re.sub('typedef struct _MLO_LINK_INFO \\{[\\s\\S]*?\\} MLO_LINK_INFO, \\*PMLO_LINK_INFO;', '', codec_source)
    codec_source = codec_source.replace('= {0};', '= {};')
    out = (args.output or output_dir('sae')).resolve()
    out.mkdir(parents=True, exist_ok=True)
    cpp = out / 'tests.cpp'
    commands = ''.join((line + '\n' for line in read_source_text(ROOT / 'src/common/sdpcm.h').splitlines() if re.match('#define BRCMF_C_', line)))
    write_text(cpp, contract_preamble() + commands + PRE + header + source + fw_header + fw_source + codec_header + codec_source + TEST, encoding='utf-8')
    vc = VC
    sdk = SDK
    (inc, lib) = (INC, LIB)
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')]
    command += ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
