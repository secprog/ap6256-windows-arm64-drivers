/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"
#include <bcrypt.h>
typedef struct _AP6256_SERVICE_REPORT {
    AP6256_BSS Bss;
    AP6256_SERVICE_ENTRY Entries[AP6256_SERVICE_MAX], Queries[AP6256_SERVICE_MAX];
    WDI_P2P_DISCOVERED_SERVICE_ENTRY_CONTAINER WdiEntries[AP6256_SERVICE_MAX];
    UCHAR Frame[12+AP6256_SCAN_IE_MAX], Attributes[AP6256_SCAN_IE_MAX];
} AP6256_SERVICE_REPORT;
static NTSTATUS Ap6256ServiceSet(PAP6256_WIFI Wifi, PCSTR Name, const VOID* Data, ULONG Length)
{
    AP6256_BCDC_QUERY_RESULT r={0};
    NTSTATUS status=Ap6256BcdcSetIovarResultIf(Wifi->Ctx,0,Name,Data,Length,&r);
    if (NT_SUCCESS(status) && (!r.FirmwareReply || r.FirmwareError))
        status=STATUS_DEVICE_PROTOCOL_ERROR;
    if (!NT_SUCCESS(status)) TraceDiag("service command %s: reply %u firmware %ld -> 0x%08X\n",
        Name,r.FirmwareReply,r.FirmwareStatus,status);
    return status;
}
static VOID Ap6256ServicePut16(UCHAR* p, UINT16 n) { p[0]=(UCHAR)n;p[1]=(UCHAR)(n>>8); }
static NTSTATUS Ap6256ServiceHashIe(PAP6256_WIFI Wifi, BOOLEAN Add)
{
    UCHAR bytes[12+2+4+3+6*AP6256_SERVICE_MAX]={0}; ULONG i,n=Wifi->Service.QueryCount;
    UINT32 one=1, flags=0x10;
    if (!n) return STATUS_SUCCESS;
    RtlCopyMemory(bytes,Add?"add":"del",3); RtlCopyMemory(bytes+4,&one,4);
    RtlCopyMemory(bytes+8,&flags,4);
    bytes[12]=221;bytes[13]=(UCHAR)(7+6*n);
    bytes[14]=0x50;bytes[15]=0x6f;bytes[16]=0x9a;bytes[17]=9;
    bytes[18]=21;Ap6256ServicePut16(bytes+19,(UINT16)(6*n));
    for (i=0;i<n;i++) RtlCopyMemory(bytes+21+6*i,Wifi->Service.Queries[i].Hash,6);
    return Ap6256ServiceSet(Wifi,"vndr_ie",bytes,21+6*n);
}
_Use_decl_annotations_
NTSTATUS Ap6256ServiceCapture(PAP6256_WIFI Wifi, const WDI_TASK_P2P_DISCOVER_PARAMETERS* Params,
    BOOLEAN Store)
{
    ULONG type=Params->DiscoverMode.ServiceDiscoveryType, i,n=0;
    AP6256_SERVICE_ENTRY* entries; NTSTATUS status=STATUS_SUCCESS;
    if (type==0 || type==WDI_P2P_SERVICE_DISCOVERY_TYPE_NO_SERVICE_DISCOVERY) {
        if (Params->Optional.ServiceNameHash_IsPresent ||
            Params->Optional.ServiceInformationDiscoveryEntry_IsPresent) return STATUS_INVALID_PARAMETER;
        if (Store) Wifi->Service.QueryCount=0;
        return STATUS_SUCCESS;
    }
    if (!Wifi->Ctx->FirmwareServiceOffload) return STATUS_NOT_SUPPORTED;
    if (type!=WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_NAME_ONLY &&
        type!=WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_INFORMATION) return STATUS_NOT_SUPPORTED;
    if (type==WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_NAME_ONLY) {
        n=Params->ServiceNameHash.ElementCount;
        if (!Params->Optional.ServiceNameHash_IsPresent || !n || n>AP6256_SERVICE_MAX ||
            !Params->ServiceNameHash.pElements) return STATUS_INVALID_PARAMETER;
    } else {
        n=Params->ServiceInformationDiscoveryEntry.ElementCount;
        if (!Params->Optional.ServiceInformationDiscoveryEntry_IsPresent || !n ||
            n>AP6256_SERVICE_MAX || !Params->ServiceInformationDiscoveryEntry.pElements)
            return STATUS_INVALID_PARAMETER;
    }
    entries=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*entries)*n,AP6256_POOL_TAG);
    if (!entries) return STATUS_INSUFFICIENT_RESOURCES;
    for (i=0;i<n;i++) {
        AP6256_SERVICE_ENTRY* e=&entries[i];
        if (type==WDI_P2P_SERVICE_DISCOVERY_TYPE_SERVICE_NAME_ONLY) {
            RtlCopyMemory(e->Hash,&Params->ServiceNameHash.pElements[i],6);
        } else {
            const WDI_P2P_SERVICE_INFORMATION_DISCOVERY_ENTRY_CONTAINER* s=
                &Params->ServiceInformationDiscoveryEntry.pElements[i];
            if (!s->ServiceName.ElementCount || s->ServiceName.ElementCount>AP6256_SERVICE_NAME_MAX ||
                !s->ServiceName.pElements || (s->Optional.ServiceInformation_IsPresent &&
                (s->ServiceInformation.ElementCount>AP6256_SERVICE_REQUEST_MAX ||
                (s->ServiceInformation.ElementCount && !s->ServiceInformation.pElements)))) {
                status=STATUS_INVALID_PARAMETER;break;
            }
            e->NameLength=s->ServiceName.ElementCount;
            RtlCopyMemory(e->Name,s->ServiceName.pElements,e->NameLength);
            RtlCopyMemory(e->Hash,&s->ServiceNameHash,6);
            e->QueryInformation=(BOOLEAN)s->Optional.ServiceInformation_IsPresent;
            e->InfoLength=e->QueryInformation?s->ServiceInformation.ElementCount:0;
            RtlCopyMemory(e->Info,s->ServiceInformation.pElements,e->InfoLength);
            e->Transaction=s->ServiceTransactionId;e->Update=s->ServiceUpdateIndicator;
        }
    }
    if (NT_SUCCESS(status) && Store) {
        RtlCopyMemory(Wifi->Service.Queries,entries,sizeof(*entries)*n);
        Wifi->Service.QueryCount=n;
    }
    ExFreePoolWithTag(entries,AP6256_POOL_TAG);return status;
}
_Use_decl_annotations_
NTSTATUS Ap6256ServiceBegin(PAP6256_WIFI Wifi, ULONG ScanDurationMs)
{
    AP6256_SERVICE_STATE* s=&Wifi->Service; NTSTATUS status; KIRQL irql;
    if (!Wifi->Ctx->FirmwareServiceOffload) return s->QueryCount?STATUS_NOT_SUPPORTED:STATUS_SUCCESS;
    status=Ap6256ServiceSet(Wifi,"p2po_stop",NULL,0);
    if (!NT_SUCCESS(status)) return status;
    if (!s->QueryCount) return STATUS_SUCCESS;
    status=Ap6256ServiceHashIe(Wifi,TRUE);
    if (!NT_SUCCESS(status)) { Ap6256ServiceResumeListen(Wifi);return status; }
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    s->HashIeInstalled=TRUE;s->PeerCount=0;s->PeerIndex=0;s->QueryIndex=0;
    s->QueryPending=s->QueryDone=s->QueryFailed=s->ScanFinished=FALSE;
    s->ResponseLength=0;s->Active=TRUE;
    s->Deadline=KeQueryInterruptTime()+((ULONGLONG)max(1000u,ScanDurationMs)+5000ull)*10000ull;
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256ServiceIndicate(PAP6256_WIFI Wifi, AP6256_SERVICE_REPORT* Report, ULONG Count)
{
    WDI_BSS_ENTRY_CONTAINER entry={0}; WDI_INDICATION_BSS_ENTRY_LIST_PARAMETERS p={0};
    WDI_MESSAGE_HEADER header; PVOID request; KIRQL irql;
    ULONG i,length=0; PUCHAR generated=NULL; NTSTATUS status;
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    if (!Wifi->Service.Active || !Wifi->P2pDiscoverTask.Active) {
        KeReleaseSpinLock(&Wifi->CommandLock,irql);return STATUS_CANCELLED;
    }
    header=Wifi->P2pDiscoverTask.Header;request=Wifi->P2pDiscoverTask.RequestId;
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    for (i=0;i<Count;i++) {
        AP6256_SERVICE_ENTRY* s=&Report->Entries[i];
        WDI_P2P_DISCOVERED_SERVICE_ENTRY_CONTAINER* w=&Report->WdiEntries[i];
        w->ServiceName.pElements=s->Name;w->ServiceName.ElementCount=s->NameLength;
        w->AdvertisementID=s->AdvertisementId;w->ConfigurationMethods=s->ConfigurationMethods;
        w->ServiceStatus=s->Status;
        w->Optional.ServiceInformation_IsPresent=s->HaveInformation;
        w->ServiceInformation.pElements=s->Info;w->ServiceInformation.ElementCount=s->InfoLength;
    }
    RtlCopyMemory(entry.BSSID.Address,Report->Bss.Bssid,6);
    Ap6256ServicePut16(Report->Frame+8,Report->Bss.BeaconPeriod);
    Ap6256ServicePut16(Report->Frame+10,Report->Bss.Capability);
    RtlCopyMemory(Report->Frame+12,Report->Bss.Ies,Report->Bss.IesLength);
    entry.Optional.ProbeResponseFrame_IsPresent=!Report->Bss.FromBeacon;
    entry.Optional.BeaconFrame_IsPresent=Report->Bss.FromBeacon;
    if (Report->Bss.FromBeacon) {
        entry.BeaconFrame.pElements=Report->Frame;entry.BeaconFrame.ElementCount=12+Report->Bss.IesLength;
    } else {
        entry.ProbeResponseFrame.pElements=Report->Frame;
        entry.ProbeResponseFrame.ElementCount=12+Report->Bss.IesLength;
    }
    entry.SignalInfo.RSSI=Report->Bss.Rssi;
    entry.SignalInfo.LinkQuality=Ap6256LinkQualityFromRssi(Report->Bss.Rssi);
    entry.ChannelInfo.ChannelNumber=Report->Bss.Channel;
    entry.ChannelInfo.BandId=Report->Bss.Channel<=14?WDI_BAND_ID_2400:WDI_BAND_ID_5000;
    entry.Optional.P2PDiscoveredServiceEntry_IsPresent=TRUE;
    entry.P2PDiscoveredServiceEntry.pElements=Report->WdiEntries;
    entry.P2PDiscoveredServiceEntry.ElementCount=Count;
    p.Optional.DeviceDescriptor_IsPresent=TRUE;p.DeviceDescriptor.ElementCount=1;
    p.DeviceDescriptor.pElements=&entry;
    status=Ap6256NdisToNtStatus(GenerateWdiIndicationBssEntryList(&p,0,&Wifi->TlvContext,&length,&generated));
    if (NT_SUCCESS(status) && generated) status=Ap6256SendGeneratedIndication(Wifi,
        WDI_INDICATION_BSS_ENTRY_LIST,&header,WDI_TRANSACTION_ID_UNSOLICIT,request,generated,length);
    else if (NT_SUCCESS(status)) status=STATUS_INSUFFICIENT_RESOURCES;
    FreeGenerated(generated);
    if (NT_SUCCESS(status)) InterlockedIncrement(&Wifi->ScanIndicated);
    TraceDiag("service result: txn %u peer %02X:%02X:%02X:%02X:%02X:%02X entries %u -> 0x%08X\n",
        header.TransactionId,Report->Bss.Bssid[0],Report->Bss.Bssid[1],Report->Bss.Bssid[2],
        Report->Bss.Bssid[3],Report->Bss.Bssid[4],Report->Bss.Bssid[5],Count,status);
    return status;
}
static BOOLEAN Ap6256ServiceHashMatches(const AP6256_SERVICE_ENTRY* Entry,const UCHAR* Hash)
{
    UCHAR name[AP6256_SERVICE_NAME_MAX], digest[32]; ULONG i;
    for (i=0;i<Entry->NameLength;i++) name[i]=Entry->Name[i]>='A' && Entry->Name[i]<='Z'?
        (UCHAR)(Entry->Name[i]-'A'+'a'):Entry->Name[i];
    return (BOOLEAN)(NT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE,NULL,0,name,Entry->NameLength,
        digest,sizeof(digest))) && RtlEqualMemory(digest,Hash,6));
}
_Use_decl_annotations_
BOOLEAN Ap6256ServiceScanResult(PAP6256_WIFI Wifi,const AP6256_BSS* Bss)
{
    AP6256_SERVICE_REPORT* r; ULONG pos=0,used=0,n=0,i,j,matched=0; KIRQL irql;
    ULONG count;
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    if (!Wifi->Service.Active) { KeReleaseSpinLock(&Wifi->CommandLock,irql);return FALSE; }
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    if (Bss->IesLength>AP6256_SCAN_IE_MAX) return TRUE;
    r=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*r),AP6256_POOL_TAG);
    if (!r) return TRUE;
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    count=Wifi->Service.QueryCount;RtlCopyMemory(r->Queries,Wifi->Service.Queries,sizeof(r->Queries));
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    while (pos<Bss->IesLength) {
        ULONG len;
        if (pos>sizeof(Bss->Ies)-2 || Bss->IesLength-pos<2 || (len=Bss->Ies[pos+1])>Bss->IesLength-pos-2) goto done;
        if (Bss->Ies[pos]==221 && len>=4 && pos<=sizeof(Bss->Ies)-6 && Bss->Ies[pos+2]==0x50 &&
            Bss->Ies[pos+3]==0x6f && Bss->Ies[pos+4]==0x9a && Bss->Ies[pos+5]==9) {
            if (len-4>sizeof(r->Attributes)-used) goto done;
            RtlCopyMemory(r->Attributes+used,Bss->Ies+pos+6,len-4);used+=len-4;
        }
        pos+=2+len;
    }
    if (!NT_SUCCESS(Ap6256ServiceDecodeAdvertisements(r->Attributes,used,r->Entries,&n))) goto done;
    for (i=0;i<n;i++) for (j=0;j<count;j++) {
        if (r->Queries[j].NameLength ? Ap6256ServiceNameMatches(r->Entries[i].Name,r->Entries[i].NameLength,
            r->Queries[j].Name,r->Queries[j].NameLength) : Ap6256ServiceHashMatches(&r->Entries[i],r->Queries[j].Hash)) {
            r->Entries[matched++]=r->Entries[i];break;
        }
    }
    if (!matched) goto done;
    r->Bss=*Bss;
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    if (Wifi->Service.Active) {
        for (i=0;i<Wifi->Service.PeerCount;i++)
            if (RtlEqualMemory(Wifi->Service.Peers[i].Bssid,Bss->Bssid,6)) break;
        if (i<AP6256_SERVICE_PEER_MAX) {
            Wifi->Service.Peers[i]=*Bss;
            if (i==Wifi->Service.PeerCount) Wifi->Service.PeerCount++;
        }
    }
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    (VOID)Ap6256ServiceIndicate(Wifi,r,matched);
done:
    ExFreePoolWithTag(r,AP6256_POOL_TAG);return TRUE;
}
_Use_decl_annotations_
VOID Ap6256NetServiceEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Type, UINT32 Status,
    UINT32 Generation,const UCHAR* Peer,const UCHAR* Body,ULONG Length)
{
    PAP6256_WIFI w=Ap6256WifiFromDevice(Ctx); AP6256_SERVICE_STATE* s; KIRQL irql;
    if (!w || !Ctx->FirmwareServiceOffload) return;
    s=&w->Service;
    KeAcquireSpinLock(&w->CommandLock,&irql);
    if (!s->Active || !s->QueryPending || Generation!=s->Generation ||
        s->PeerIndex>=s->PeerCount || !RtlEqualMemory(Peer,s->Peers[s->PeerIndex].Bssid,6)) goto done;
    if (Type==BRCMF_E_GAS_COMPLETE) { s->QueryDone=TRUE;if (Status) s->QueryFailed=TRUE;goto done; }
    if (Type==BRCMF_E_GAS_FRAGMENT_RX) {
        ULONG n; UCHAR frag;
        if (!Body || Length<8 || (n=(ULONG)Body[6]+((ULONG)Body[7]<<8))!=Length-8 ||
            Body[4] || Body[5] || n>sizeof(s->Response)) { s->QueryFailed=TRUE;goto done; }
        frag=(UCHAR)(Body[3]&0x7f);
        if (!s->ResponseLength) { s->Dialog=Body[2];s->Fragment=0; }
        if (s->Dialog!=Body[2] || frag!=s->Fragment || n>sizeof(s->Response)-s->ResponseLength) {
            s->QueryFailed=TRUE;goto done;
        }
        RtlCopyMemory(s->Response+s->ResponseLength,Body+8,n);s->ResponseLength+=n;s->Fragment++;
        if (Status && Status!=8) s->QueryFailed=TRUE;
    }
done:
    KeReleaseSpinLock(&w->CommandLock,irql);
}
_Use_decl_annotations_
NTSTATUS Ap6256ServiceResumeListen(PAP6256_WIFI Wifi)
{
    UCHAR config[12]={0};UINT32 channel=Wifi->Ctx->P2p.ListenChannel;NTSTATUS status;
    if (!Wifi->Ctx->FirmwareServiceOffload || !Wifi->Service.AdvertisementCount ||
        !Wifi->HardwareAvailable || Wifi->P2pDiscovering || Wifi->Service.Active) return STATUS_SUCCESS;
    status=Ap6256ServiceSet(Wifi,"p2po_stop",NULL,0);
    if (!NT_SUCCESS(status) || !Wifi->Ctx->P2p.Listening) return status;
    AP6256_TIMER_STOP(Wifi->P2pListenTimer,FALSE);
    status=Ap6256WifiSetP2pDiscoveryState(Wifi->Ctx,AP6256_P2P_DISC_SCAN,0,0);
    Ap6256ServicePut16(config,2);Ap6256ServicePut16(config+2,12);
    RtlCopyMemory(config+4,&channel,4);config[8]=1;config[9]=1;
    Ap6256ServicePut16(config+10,(UINT16)channel);
    if (NT_SUCCESS(status)) status=Ap6256ServiceSet(Wifi,"p2po_find_config",config,sizeof(config));
    if (NT_SUCCESS(status)) status=Ap6256ServiceSet(Wifi,"p2po_listen",NULL,0);
    if (!NT_SUCCESS(status)) TraceDiag("service listen restore failed 0x%08X\n",status);
    return status;
}
_Use_decl_annotations_
VOID Ap6256ServiceStop(PAP6256_WIFI Wifi, BOOLEAN ClearAdvertisements)
{
    AP6256_SERVICE_STATE* s=&Wifi->Service; BOOLEAN active,ie; ULONG i; KIRQL irql;
    NTSTATUS status=STATUS_SUCCESS,t;
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    active=s->Active;ie=s->HashIeInstalled;s->Active=FALSE;s->QueryPending=FALSE;
    s->QueryDone=FALSE;s->HashIeInstalled=FALSE;s->ResponseLength=0;
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    if (!Wifi->HardwareAvailable || !Wifi->Ctx->FirmwareServiceOffload) {
        if (ClearAdvertisements) { s->AdvertisementCount=0;s->AdvertisementUpdate=0;RtlZeroMemory(s->Advertisements,sizeof(s->Advertisements)); }
        s->QueryCount=0;s->PeerCount=0;return;
    }
    if (active) { t=Ap6256ServiceSet(Wifi,"anqpo_stop_query",NULL,0);if (!NT_SUCCESS(t)) status=t; }
    if (ie) { t=Ap6256ServiceHashIe(Wifi,FALSE);if (!NT_SUCCESS(t)) status=t; }
    if (ClearAdvertisements) {
        t=Ap6256ServiceSet(Wifi,"p2po_stop",NULL,0);if (!NT_SUCCESS(t)) status=t;
        for (i=0;i<s->AdvertisementCount;i++) {
            UINT32 handle=i+1;
            t=Ap6256ServiceSet(Wifi,"p2po_wfds_advertise_del",&handle,4);if (!NT_SUCCESS(t)) status=t;
        }
        s->AdvertisementCount=0;s->AdvertisementUpdate=0;RtlZeroMemory(s->Advertisements,sizeof(s->Advertisements));
    } else { t=Ap6256ServiceResumeListen(Wifi);if (!NT_SUCCESS(t)) status=t; }
    if (!NT_SUCCESS(status)) {
        Wifi->Ctx->FirmwareServiceOffload=FALSE;Wifi->Ctx->P2p.DiscoverStatus=status;
        TraceDiag("service cleanup failed 0x%08X; firmware restart required\n",status);
    }
}
_Use_decl_annotations_
ULONG Ap6256ServiceAdvance(PAP6256_WIFI Wifi)
{
    AP6256_SERVICE_STATE* s=&Wifi->Service; ULONG next, qlen=0; UCHAR config[266]={0},peer[10]={0};
    KIRQL irql; NTSTATUS status; ULONGLONG now=KeQueryInterruptTime();
    BOOLEAN pending,done,failed; AP6256_SERVICE_REPORT* r;
    if (!s->Active) return 0;
    if (now>=s->Deadline) { Ap6256ServiceStop(Wifi,FALSE);return 0; }
    if (!s->ScanFinished) {
        next=Ap6256P2pAdvanceDiscovery(Wifi->Ctx);
        if (next) return next;
        s->ScanFinished=TRUE;
        if (!NT_SUCCESS(Wifi->Ctx->P2p.DiscoverStatus)) { Ap6256ServiceStop(Wifi,FALSE);return 0; }
    }
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    pending=s->QueryPending;done=s->QueryDone;failed=s->QueryFailed;
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    if (pending) {
        if (!done && !failed && now<s->QueryDeadline) return 50;

        KeAcquireSpinLock(&Wifi->CommandLock,&irql);s->QueryPending=FALSE;
        KeReleaseSpinLock(&Wifi->CommandLock,irql);
        if (done && !failed && s->ResponseLength) {
            r=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*r),AP6256_POOL_TAG);
            if (r) {
                ULONG count=0;
                r->Bss=s->Peers[s->PeerIndex];
                status=Ap6256ServiceDecodeResponse(s->Response,s->ResponseLength,
                    &s->Queries[s->QueryIndex],r->Entries,&count);
                if (NT_SUCCESS(status) && count) (VOID)Ap6256ServiceIndicate(Wifi,r,count);
                else TraceDiag("service ANQP response: gen %u bytes %u -> 0x%08X entries %u\n",
                    s->Generation,s->ResponseLength,status,count);
                ExFreePoolWithTag(r,AP6256_POOL_TAG);
            }
        }
        (VOID)Ap6256ServiceSet(Wifi,"anqpo_stop_query",NULL,0);s->QueryIndex++;
    }
    while (s->PeerIndex<s->PeerCount) {
        while (s->QueryIndex<s->QueryCount && !s->Queries[s->QueryIndex].QueryInformation) s->QueryIndex++;
        if (s->QueryIndex<s->QueryCount) break;
        s->PeerIndex++;s->QueryIndex=0;
    }
    if (s->PeerIndex==s->PeerCount) { Ap6256ServiceStop(Wifi,FALSE);return 0; }
    status=Ap6256ServiceEncodeQuery(&s->Queries[s->QueryIndex],config+10,256,&qlen);
    if (!NT_SUCCESS(status)) { Wifi->Ctx->P2p.DiscoverStatus=status;Ap6256ServiceStop(Wifi,FALSE);return 0; }
    if (++s->NextGeneration==0 || s->NextGeneration>=0x80000000u) s->NextGeneration=1;
    s->Generation=s->NextGeneration;
    status=Ap6256ServiceSet(Wifi,"svc_wdi_generation",&s->Generation,4);
    Ap6256ServicePut16(config,0);Ap6256ServicePut16(config+2,500);
    Ap6256ServicePut16(config+4,100);Ap6256ServicePut16(config+6,1);
    Ap6256ServicePut16(config+8,(UINT16)qlen);
    if (NT_SUCCESS(status)) status=Ap6256ServiceSet(Wifi,"anqpo_set",config,10+qlen);
    Ap6256ServicePut16(peer,1);Ap6256ServicePut16(peer+2,s->Peers[s->PeerIndex].Channel);
    RtlCopyMemory(peer+4,s->Peers[s->PeerIndex].Bssid,6);
    KeAcquireSpinLock(&Wifi->CommandLock,&irql);
    s->ResponseLength=0;s->QueryDone=s->QueryFailed=FALSE;s->QueryPending=NT_SUCCESS(status);
    s->QueryDeadline=now+30000000ull;
    KeReleaseSpinLock(&Wifi->CommandLock,irql);
    if (NT_SUCCESS(status)) status=Ap6256ServiceSet(Wifi,"anqpo_start_query",peer,sizeof(peer));
    if (!NT_SUCCESS(status)) {
        TraceDiag("service ANQP start failed 0x%08X\n",status);
        Wifi->Ctx->P2p.DiscoverStatus=status;Ap6256ServiceStop(Wifi,FALSE);return 0;
    }
    TraceDiag("service ANQP start: gen %u peer %u/%u query %u/%u bytes %u\n",s->Generation,
        s->PeerIndex+1,s->PeerCount,s->QueryIndex+1,s->QueryCount,qlen);
    return 50;
}
static NTSTATUS Ap6256ServiceAddAdvertisement(PAP6256_WIFI Wifi,const AP6256_SERVICE_ENTRY* s,ULONG index)
{
    UCHAR record[220+AP6256_SERVICE_INFO_MAX]={0};UINT32 handle=index+1;
    RtlCopyMemory(record,&handle,4);RtlCopyMemory(record+4,s->Hash,6);
    RtlCopyMemory(record+10,&s->AdvertisementId,4);Ap6256ServicePut16(record+14,s->ConfigurationMethods);
    record[16]=(UCHAR)s->NameLength;RtlCopyMemory(record+17,s->Name,s->NameLength);
    record[217]=s->Status;Ap6256ServicePut16(record+218,(UINT16)s->InfoLength);
    RtlCopyMemory(record+220,s->Info,s->InfoLength);
    return Ap6256ServiceSet(Wifi,"p2po_wfds_advertise_add",record,220+s->InfoLength);
}
_Use_decl_annotations_
NTSTATUS Ap6256ServiceValidateAdvertisements(PAP6256_WIFI Wifi,const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* Services)
{
    ULONG i,n=Services->ServiceEntry.ElementCount;
    if (!Wifi->Ctx->FirmwareServiceOffload) return n?STATUS_NOT_SUPPORTED:STATUS_SUCCESS;
    if (n>AP6256_SERVICE_MAX || (n && !Services->ServiceEntry.pElements)) return STATUS_INVALID_PARAMETER;
    for (i=0;i<n;i++) {
        const WDI_P2P_ADVERTISED_SERVICE_ENTRY_CONTAINER* s=&Services->ServiceEntry.pElements[i];
        if (!s->ServiceName.ElementCount || s->ServiceName.ElementCount>AP6256_SERVICE_NAME_MAX ||
            !s->ServiceName.pElements || (s->Optional.ServiceInformation_IsPresent &&
            (s->ServiceInformation.ElementCount>AP6256_SERVICE_INFO_MAX ||
            (s->ServiceInformation.ElementCount && !s->ServiceInformation.pElements)))) return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}
_Use_decl_annotations_
NTSTATUS Ap6256ServiceAdvertise(PAP6256_WIFI Wifi,const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* Services)
{
    AP6256_SERVICE_ENTRY* entries;ULONG i,n=Services->ServiceEntry.ElementCount;
    NTSTATUS status=Ap6256ServiceValidateAdvertisements(Wifi,Services); UINT32 update=Services->ServiceUpdateIndicator;
    if (!NT_SUCCESS(status)) return status;
    if (!Wifi->Ctx->FirmwareServiceOffload) return n?STATUS_NOT_SUPPORTED:STATUS_SUCCESS;
    if (Wifi->Service.Active || Wifi->P2pDiscovering) return STATUS_DEVICE_BUSY;
    if (n>AP6256_SERVICE_MAX || (n && !Services->ServiceEntry.pElements)) return STATUS_INVALID_PARAMETER;
    entries=ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*entries)*AP6256_SERVICE_MAX,AP6256_POOL_TAG);
    if (!entries) return STATUS_INSUFFICIENT_RESOURCES;
    for (i=0;i<n;i++) {
        const WDI_P2P_ADVERTISED_SERVICE_ENTRY_CONTAINER* s=&Services->ServiceEntry.pElements[i];
        AP6256_SERVICE_ENTRY* e=&entries[i];
        if (!s->ServiceName.ElementCount || s->ServiceName.ElementCount>AP6256_SERVICE_NAME_MAX ||
            !s->ServiceName.pElements || (s->Optional.ServiceInformation_IsPresent &&
            (s->ServiceInformation.ElementCount>AP6256_SERVICE_INFO_MAX ||
            (s->ServiceInformation.ElementCount && !s->ServiceInformation.pElements)))) {
            status=STATUS_INVALID_PARAMETER;goto cleanup;
        }
        e->NameLength=s->ServiceName.ElementCount;RtlCopyMemory(e->Name,s->ServiceName.pElements,e->NameLength);
        RtlCopyMemory(e->Hash,&s->ServiceNameHash,6);e->AdvertisementId=s->AdvertisementID;
        e->ConfigurationMethods=s->ConfigurationMethods;e->Status=s->ServiceStatus;e->Update=(UINT16)update;
        e->InfoLength=s->Optional.ServiceInformation_IsPresent?s->ServiceInformation.ElementCount:0;
        RtlCopyMemory(e->Info,s->ServiceInformation.pElements,e->InfoLength);
    }
    status=Ap6256ServiceSet(Wifi,"p2po_stop",NULL,0);
    if (!NT_SUCCESS(status)) goto cleanup;
    {
        ULONG removed=0,added=0,j;NTSTATUS restore=STATUS_SUCCESS;
        for (i=0;i<Wifi->Service.AdvertisementCount;i++) {
            UINT32 handle=i+1;status=Ap6256ServiceSet(Wifi,"p2po_wfds_advertise_del",&handle,4);
            if (!NT_SUCCESS(status)) break;
            removed++;
        }
        if (NT_SUCCESS(status)) for (i=0;i<n;i++) {
            status=Ap6256ServiceAddAdvertisement(Wifi,&entries[i],i);
            if (!NT_SUCCESS(status)) break;
            added++;
        }
        if (NT_SUCCESS(status)) status=Ap6256ServiceSet(Wifi,"svc_wdi_update",&update,4);
        if (!NT_SUCCESS(status)) {

            for (j=0;j<added;j++) {
                UINT32 handle=j+1;NTSTATUS t=Ap6256ServiceSet(Wifi,"p2po_wfds_advertise_del",&handle,4);
                if (!NT_SUCCESS(t)) restore=t;
            }
            for (j=0;j<removed;j++) {
                NTSTATUS t=Ap6256ServiceAddAdvertisement(Wifi,&Wifi->Service.Advertisements[j],j);
                if (!NT_SUCCESS(t)) restore=t;
            }
            { NTSTATUS t=Ap6256ServiceSet(Wifi,"svc_wdi_update",&Wifi->Service.AdvertisementUpdate,4);
              if (!NT_SUCCESS(t)) restore=t; }
            if (NT_SUCCESS(restore)) restore=Ap6256ServiceResumeListen(Wifi);
            if (!NT_SUCCESS(restore)) {
                Wifi->Ctx->FirmwareServiceOffload=FALSE;
                TraceDiag("service advertisement rollback failed 0x%08X; firmware restart required\n",restore);
            }
            goto cleanup;
        }
    }
    RtlCopyMemory(Wifi->Service.Advertisements,entries,sizeof(*entries)*AP6256_SERVICE_MAX);
    Wifi->Service.AdvertisementCount=n;Wifi->Service.AdvertisementUpdate=update;
    status=Ap6256ServiceResumeListen(Wifi);
    if (!n && Wifi->Ctx->P2p.Listening && NT_SUCCESS(status)) {
        status=Ap6256P2pPulseListen(Wifi->Ctx);
        if (NT_SUCCESS(status)) AP6256_TIMER_START(Wifi->P2pListenTimer,Wifi->Ctx->P2p.ListenCycleMs);
    }
    TraceDiag("native WFDS advertisement: %u service(s), update %u\n",n,update);
cleanup:
    ExFreePoolWithTag(entries,AP6256_POOL_TAG);return status;
}
