/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"
static UINT16 F16(const UCHAR* p) { return (UINT16)(p[0]|((UINT16)p[1]<<8)); }
static VOID P16(UCHAR* p,UINT16 n) { p[0]=(UCHAR)n;p[1]=(UCHAR)(n>>8); }
static WDI_FTM_RESPONSE_STATUS FtmStatus(INT32 Firmware,NTSTATUS Status) {
    switch(Firmware) {
    case -1039:case -1035:case -23:return WDI_FTM_RESPONSE_STATUS_INCAPABLE;
    case -1030:return WDI_FTM_RESPONSE_STATUS_UNREACHABLE;
    case -1031:case -1032:return WDI_FTM_RESPONSE_STATUS_TIMEOUT;
    case -1026:return WDI_FTM_RESPONSE_STATUS_ABORTED;
    case -1027:case -1036:case -1045:return WDI_FTM_RESPONSE_STATUS_REJECTED;
    default:return Status==STATUS_IO_TIMEOUT?WDI_FTM_RESPONSE_STATUS_TIMEOUT:WDI_FTM_RESPONSE_STATUS_FAILED;
    }
}
static NTSTATUS FtmLciSet(PAP6256_WIFI Wifi,const AP6256_FTM_TARGET* Target) {
    UCHAR bytes[16]={0};AP6256_BCDC_QUERY_RESULT r={0};NTSTATUS status;
    P16(bytes,0x300);P16(bytes+2,16);P16(bytes+4,Wifi->Ftm.Session);
    if(Target && Target->RequestLci) {
        bytes[6]=Target->Token;bytes[7]=1;RtlCopyMemory(bytes+8,Target->Peer,6);
    }
    status=Ap6256BcdcSetIovarResultIf(Wifi->Ctx,0,"ftm_wdi_lci",bytes,sizeof(bytes),&r);
    if(NT_SUCCESS(status) && (!r.FirmwareReply || r.FirmwareError)) status=STATUS_DEVICE_PROTOCOL_ERROR;
    return status;
}
static NTSTATUS FtmLciGet(PAP6256_WIFI Wifi,AP6256_FTM_TARGET* Target,BOOLEAN* Pending) {
    UCHAR bytes[16+AP6256_FTM_LCI_MAX]={0};AP6256_BCDC_QUERY_RESULT r={0};ULONG n;
    NTSTATUS status=Ap6256BcdcGetIovarResultIf(Wifi->Ctx,0,"ftm_wdi_lci",bytes,sizeof(bytes),&r);
    *Pending=FALSE;
    if(!NT_SUCCESS(status)) return status;
    n=F16(bytes+14);
    if(!r.FirmwareReply || r.FirmwareError || r.PayloadLength<16 || F16(bytes)!=0x300 ||
        F16(bytes+2)!=16+n || n>AP6256_FTM_LCI_MAX || 16+n>r.PayloadLength ||
        F16(bytes+4)!=Wifi->Ftm.Session || bytes[6]!=Target->Token ||
        !RtlEqualMemory(bytes+8,Target->Peer,6) || bytes[7]>5) return STATUS_DEVICE_PROTOCOL_ERROR;
    Target->LciStatus=WDI_LCI_REPORT_STATUS_FAILURE;
    if(bytes[7]==1) *Pending=TRUE;
    else if(bytes[7]==2) {
        ULONG pos=0;
        if(n<18 || bytes[16]!=0 || bytes[17]!=16) return STATUS_DEVICE_PROTOCOL_ERROR;
        while(pos<n) {
            ULONG len;
            if(n-pos<2 || (len=bytes[16+pos+1])>n-pos-2) return STATUS_DEVICE_PROTOCOL_ERROR;
            pos+=len+2;
        }
        Target->LciStatus=WDI_LCI_REPORT_STATUS_SUCCESS;Target->LciLength=(UINT16)n;
        RtlCopyMemory(Target->Lci,bytes+16,n);
    } else if(bytes[7]==3) Target->LciStatus=WDI_LCI_REPORT_STATUS_INCAPABLE;
    else if(bytes[7]==4) Target->LciStatus=WDI_LCI_REPORT_STATUS_REFUSED;
    return STATUS_SUCCESS;
}
static VOID FtmRetireSession(PAP6256_WIFI Wifi) {
    AP6256_FTM_STATE* f=&Wifi->Ftm;UCHAR reply[AP6256_FTM_REPLY_MAX];ULONG n;
    INT32 firmware=0;NTSTATUS status,deleted;
    if(!f->Session) return;
    if(Wifi->Ctx->DatapathRunning && Wifi->Ctx->FirmwareState==Ap6256FwRunning &&
        Wifi->Ctx->FirmwareFtmSupported) {
        status=Ap6256FtmCommand(Wifi->Ctx,7,f->Session,0,NULL,0,TRUE,reply,sizeof(reply),&n,&firmware);

        if(!NT_SUCCESS(status) && (firmware==-1024 || firmware==-1025 || firmware==-30)) status=STATUS_SUCCESS;
        deleted=Ap6256FtmCommand(Wifi->Ctx,8,f->Session,0,NULL,0,TRUE,reply,sizeof(reply),&n,&firmware);
        if(!NT_SUCCESS(deleted) && (firmware==-1025 || firmware==-30)) deleted=STATUS_SUCCESS;
        if(NT_SUCCESS(status)) status=deleted;
        deleted=FtmLciSet(Wifi,NULL);if(NT_SUCCESS(status)) status=deleted;
        if(!NT_SUCCESS(status)) {
            Wifi->Ctx->FirmwareFtmSupported=FALSE;
            TraceDiag("FTM: session %u cleanup failed 0x%08X; firmware restart required\n",f->Session,status);
        }
    }
    f->Session=0;
}
static VOID FtmFinish(PAP6256_WIFI Wifi,NTSTATUS CompletionStatus) {
    AP6256_FTM_STATE* f=&Wifi->Ftm;WDI_MESSAGE_HEADER header;PVOID request;
    WDI_INDICATION_REQUEST_FTM_COMPLETE_PARAMETERS p={0};
    WDI_FTM_RESPONSE_CONTAINER responses[AP6256_FTM_TARGET_MAX]={0};
    UCHAR reply[AP6256_FTM_REPLY_MAX],*generated=NULL;ULONG n=0,length=0,i;NTSTATUS status;
    FtmRetireSession(Wifi);
    if(f->Enabled && Wifi->Ctx->DatapathRunning && Wifi->Ctx->FirmwareState==Ap6256FwRunning) {
        status=Ap6256FtmCommand(Wifi->Ctx,3,0,0,NULL,0,TRUE,reply,sizeof(reply),&n,NULL);
        if(!NT_SUCCESS(status)) { Wifi->Ctx->FirmwareFtmSupported=FALSE;
            TraceDiag("FTM: disable cleanup failed 0x%08X\n",status); }
    }
    f->Enabled=FALSE;AP6256_TIMER_STOP(f->Timer,FALSE);
    if(!Ap6256ClaimTask(Wifi,&f->Task,&header,&request)) return;
    for(i=0;i<f->Count;i++) {
        AP6256_FTM_TARGET* t=&f->Targets[i];WDI_FTM_RESPONSE_CONTAINER* r=&responses[i];
        RtlCopyMemory(r->BSSID.Address,t->Peer,6);r->Status=t->Status;
        if(t->Status==WDI_FTM_RESPONSE_STATUS_SUCCESS) {
            r->Optional.NumberOfMeasurements_IsPresent=TRUE;r->NumberOfMeasurements=t->Measurement.Measurements;
            r->Optional.SignalInfo_IsPresent=TRUE;r->SignalInfo.RSSI=t->Measurement.Rssi;
            r->SignalInfo.LinkQuality=Ap6256LinkQualityFromRssi(t->Measurement.Rssi);
            r->Optional.RTT_IsPresent=TRUE;r->RTT=t->Measurement.RttPs;
            r->Optional.BandwidthUsed_IsPresent=TRUE;r->BandwidthUsed=WDI_FTM_BANDWIDTH_20;
            if(t->Measurement.VariancePresent) {
                r->Optional.RTTVariance_IsPresent=TRUE;r->RTTVariance=t->Measurement.VariancePs;
            }
        }
        if(t->RequestLci) {
            r->Optional.LCIStatus_IsPresent=TRUE;r->LCIStatus=t->LciStatus;
            if(t->LciStatus==WDI_LCI_REPORT_STATUS_SUCCESS && t->LciLength) {
                r->Optional.LCIReport_IsPresent=TRUE;r->LCIReport.ElementCount=t->LciLength;
                r->LCIReport.pElements=t->Lci;
            }
        }
    }
    p.FTMResponseList.ElementCount=f->Count;p.FTMResponseList.pElements=responses;
    status=Ap6256NdisToNtStatus(GenerateWdiIndicationRequestFtmCompleteFromIhv(&p,0,&Wifi->TlvContext,&length,&generated));
    (VOID)Ap6256SendIndicationRq(Wifi,WDI_INDICATION_REQUEST_FTM_COMPLETE,&header,
        header.TransactionId,request,NT_SUCCESS(status)?CompletionStatus:status,generated,length);
    if(generated) FreeGenerated(generated);
}
static VOID FtmAdvance(PAP6256_WIFI Wifi) {
    AP6256_FTM_STATE* f=&Wifi->Ftm;UCHAR reply[AP6256_FTM_REPLY_MAX];ULONG n=0;
    NTSTATUS status;INT32 firmware=0,native=0;UINT16 state=0;LONGLONG now;
    while(f->Index<f->Count && f->Task.Active) {
        AP6256_FTM_TARGET* t=&f->Targets[f->Index];BOOLEAN pending=FALSE;
        now=Ap6256InterruptTimeMs();
        if(now>=f->Task.DeadlineMs || !Wifi->Ctx->FirmwareFtmSupported) break;
        if(!t->Valid) { t->Status=WDI_FTM_RESPONSE_STATUS_INCAPABLE;t->Complete=TRUE;f->Index++;continue; }
        if(!f->Session) {
            ULONG timeout=(ULONG)min(150ll,f->Task.DeadlineMs-now);
            f->NextSession=(UINT16)((f->NextSession%32767u)+1u);f->Session=f->NextSession;
            t->Token=(UCHAR)f->Session;if(!t->Token) t->Token=1;
            f->TargetDeadline=min(now+timeout,f->Task.DeadlineMs);
            status=Ap6256FtmCommand(Wifi->Ctx,4,f->Session,t->Chanspec,t->Peer,timeout,TRUE,reply,sizeof(reply),&n,&firmware);
            if(NT_SUCCESS(status)) status=FtmLciSet(Wifi,t);
            if(NT_SUCCESS(status)) status=Ap6256FtmCommand(Wifi->Ctx,5,f->Session,0,NULL,0,TRUE,reply,sizeof(reply),&n,&firmware);
            if(!NT_SUCCESS(status)) {
                t->Status=FtmStatus(firmware,status);t->Complete=TRUE;FtmRetireSession(Wifi);f->Index++;continue;
            }
        }
        status=Ap6256FtmCommand(Wifi->Ctx,11,f->Session,0,NULL,0,FALSE,reply,sizeof(reply),&n,&firmware);
        if(NT_SUCCESS(status)) status=Ap6256FtmDecodeStatus(reply,n,f->Session,&state,&native);
        now=Ap6256InterruptTimeMs();
        if(!NT_SUCCESS(status)) { t->Status=FtmStatus(firmware,status);t->Complete=TRUE; }
        else if(state==9) {
            if(native) { t->Status=FtmStatus(native,STATUS_SUCCESS);t->Complete=TRUE; }
            else {
                status=Ap6256FtmCommand(Wifi->Ctx,9,f->Session,0,NULL,0,FALSE,reply,sizeof(reply),&n,&firmware);
                if(NT_SUCCESS(status)) status=Ap6256FtmDecodeResult(reply,n,f->Session,t->Peer,&t->Measurement);
                t->Status=NT_SUCCESS(status) && !t->Measurement.Status && t->Measurement.Measurements?
                    WDI_FTM_RESPONSE_STATUS_SUCCESS:FtmStatus(t->Measurement.Status,status);
                if(t->RequestLci) {
                    status=FtmLciGet(Wifi,t,&pending);
                    if(!NT_SUCCESS(status)) t->LciStatus=WDI_LCI_REPORT_STATUS_FAILURE;
                }
                t->Complete=!pending || now>=f->TargetDeadline;
            }
        } else if(now>=f->TargetDeadline) { t->Status=WDI_FTM_RESPONSE_STATUS_TIMEOUT;t->Complete=TRUE; }
        if(!t->Complete) { AP6256_TIMER_START(f->Timer,5);return; }
        TraceDiag("FTM: target %u/%u sid %u native state %u status %ld -> result %u, %u measurement(s)\n",
            f->Index+1,f->Count,f->Session,state,native,(UINT32)t->Status,t->Measurement.Measurements);
        FtmRetireSession(Wifi);f->Index++;
    }
    if(f->Index<f->Count && f->Session) {

        if(f->Targets[f->Index].Status!=WDI_FTM_RESPONSE_STATUS_SUCCESS)
            f->Targets[f->Index].Status=WDI_FTM_RESPONSE_STATUS_TIMEOUT;
        f->Targets[f->Index].Complete=TRUE;
    }
    FtmFinish(Wifi,STATUS_SUCCESS);
}
VOID Ap6256HandleFtmRequest(PAP6256_WIFI Wifi,AP6256_REQUEST Request,const WDI_MESSAGE_HEADER* Header,
    const UCHAR* Tlv,ULONG TlvLength) {
    WDI_TASK_REQUEST_FTM_PARAMETERS p={0};AP6256_FTM_STATE* f=&Wifi->Ftm;ULONG i,timeout=0;
    NTSTATUS status=Ap6256NdisToNtStatus(ParseWdiTaskRequestFtmToIhv(TlvLength,Tlv,&Wifi->TlvContext,&p));
    if(!NT_SUCCESS(status)) { CleanupParsedWdiTaskRequestFtmToIhv(&p);Ap6256CompleteRequest(Wifi,Request,status);return; }
    Ap6256LockAcquire(&f->Lock);
    if(!Wifi->Ctx->FirmwareFtmSupported || Header->PortId!=AP6256_STATION_PORT ||
        !Wifi->HardwareAvailable || !Wifi->Ctx->DatapathRunning) status=STATUS_NOT_SUPPORTED;
    else if(f->Task.Active || Wifi->ScanTask.Active || Wifi->ConnectTask.Active || Wifi->DisconnectTask.Active ||
        Wifi->ActionFrameTask.Active || Wifi->P2pDiscoverTask.Active || Wifi->Ctx->P2p.Listening || Wifi->ApStarted ||
        Ap6256ModelGroupConnecting(Wifi)) status=STATUS_DEVICE_BUSY;
    else if(!p.FTMRequestTimeout || p.FTMRequestTimeout>150u*AP6256_FTM_TARGET_MAX ||
        !p.FTMTargetList.ElementCount || p.FTMTargetList.ElementCount>AP6256_FTM_TARGET_MAX ||
        !p.FTMTargetList.pElements) status=STATUS_INVALID_PARAMETER;
    if(NT_SUCCESS(status)) {
        f->Count=p.FTMTargetList.ElementCount;f->Index=0;f->Session=0;f->Enabled=FALSE;
        timeout=p.FTMRequestTimeout;
        RtlZeroMemory(f->Targets,sizeof(f->Targets));
        for(i=0;i<f->Count;i++) {
            const WDI_FTM_TARGET_BSS_ENTRY_CONTAINER* in=&p.FTMTargetList.pElements[i];
            AP6256_FTM_TARGET* t=&f->Targets[i];AP6256_SCAN_CHANNEL channel={0};NTSTATUS valid;
            RtlCopyMemory(t->Peer,in->BSSID.Address,6);t->RequestLci=(BOOLEAN)!!in->RequestLCIReport;
            t->Status=WDI_FTM_RESPONSE_STATUS_NOT_ATTEMPTED;t->LciStatus=WDI_LCI_REPORT_STATUS_FAILURE;
            channel.Number=(UINT16)in->ChannelInfo.ChannelNumber;
            channel.Band=in->ChannelInfo.BandId==WDI_BAND_ID_2400?Ap6256ScanBand2G:Ap6256ScanBand5G;
            valid=Ap6256EncodeChanspec(Wifi->Ctx->D11IoType,&channel,&t->Chanspec);
            if(NT_SUCCESS(valid) && in->Optional.BeaconFrame_IsPresent) valid=Ap6256FtmValidateBeacon(in->BeaconFrame.pElements,in->BeaconFrame.ElementCount);
            if(NT_SUCCESS(valid) && in->Optional.ProbeResponseFrame_IsPresent) valid=Ap6256FtmValidateBeacon(in->ProbeResponseFrame.pElements,in->ProbeResponseFrame.ElementCount);
            t->Valid=NT_SUCCESS(valid) && Ap6256MacIsValidUnicast(t->Peer) &&
                in->ChannelInfo.ChannelNumber<=MAXUSHORT &&
                (in->ChannelInfo.BandId==WDI_BAND_ID_2400 || in->ChannelInfo.BandId==WDI_BAND_ID_5000) &&
                !Ap6256BandIsMasked(Wifi->DisallowedBandMask,in->ChannelInfo.BandId);
        }
        status=Ap6256BeginTask(Wifi,&f->Task,Header,Ap6256RequestGetId(Request));
    }
    CleanupParsedWdiTaskRequestFtmToIhv(&p);
    Ap6256CompleteRequest(Wifi,Request,status);
    if(NT_SUCCESS(status)) {
        UCHAR reply[AP6256_FTM_REPLY_MAX];ULONG n;

        Ap6256SetTaskDeadline(Wifi,&f->Task,timeout);
        status=Ap6256FtmCommand(Wifi->Ctx,2,0,0,NULL,0,TRUE,reply,sizeof(reply),&n,NULL);
        f->Enabled=NT_SUCCESS(status);
        if(NT_SUCCESS(status)) FtmAdvance(Wifi);else FtmFinish(Wifi,status);
    }
    Ap6256LockRelease(&f->Lock);
}
VOID Ap6256OnFtmTick(PVOID Context) {
    PAP6256_WIFI w=(PAP6256_WIFI)Context;
    if(!w) return;
    Ap6256LockAcquire(&w->Ftm.Lock);
    if(w->Ftm.Task.Active && !w->Stopping && w->HardwareAvailable) FtmAdvance(w);
    Ap6256LockRelease(&w->Ftm.Lock);
}
BOOLEAN Ap6256FtmCancel(PAP6256_WIFI Wifi,BOOLEAN Match,UINT32 TransactionId,
    WDI_PORT_ID Port,NTSTATUS CompletionStatus) {
    AP6256_FTM_STATE* f=&Wifi->Ftm;BOOLEAN claimed=FALSE;ULONG i;
    AP6256_TIMER_STOP(f->Timer,TRUE);
    Ap6256LockAcquire(&f->Lock);
    if(f->Task.Active && (!Match || (f->Task.Header.TransactionId==TransactionId && f->Task.Header.PortId==Port))) {
        claimed=TRUE;
        for(i=f->Index;i<f->Count;i++) {
            if(!f->Targets[i].Complete) f->Targets[i].Status=WDI_FTM_RESPONSE_STATUS_ABORTED;
            f->Targets[i].Complete=TRUE;
        }
        FtmFinish(Wifi,CompletionStatus);
    } else if(f->Task.Active && !Wifi->Stopping && Wifi->HardwareAvailable) AP6256_TIMER_START(f->Timer,5);
    Ap6256LockRelease(&f->Lock);return claimed;
}
