/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ftm.h"
#include "wifi_ops.h"
static UINT16 F16(const UCHAR* p) { return (UINT16)(p[0]|((UINT16)p[1]<<8)); }
static UINT32 F32(const UCHAR* p) { return (UINT32)F16(p)|((UINT32)F16(p+2)<<16); }
static VOID P16(UCHAR* p,UINT16 v) { p[0]=(UCHAR)v;p[1]=(UCHAR)(v>>8); }
static VOID P32(UCHAR* p,UINT32 v) { P16(p,(UINT16)v);P16(p+2,(UINT16)(v>>16)); }
static VOID Tlv(UCHAR* p,UINT16 id,const UCHAR* v,UINT16 n) {
    P16(p,id);P16(p+2,n);RtlCopyMemory(p+4,v,n);
}
NTSTATUS Ap6256FtmBuildCommand(UINT16 Command,UINT16 Session,UINT16 Chanspec,
    const UCHAR* Peer,ULONG TimeoutMs,UCHAR* Buffer,ULONG Capacity,PULONG Length) {
    ULONG n=12;UCHAR v[8]={0};
    *Length=0;
    if(!Buffer || Capacity<12 || (Command==4 && (!Peer || !Session || !Chanspec ||
        !TimeoutMs || TimeoutMs>600 || Capacity<84))) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Buffer,Capacity);P16(Buffer,0x300);P16(Buffer+4,Command);
    P16(Buffer+6,4);P16(Buffer+8,Session);
    if(Command==4) {

        P32(v,0x80001);Tlv(Buffer+n,25,v,4);n+=8;
        P32(v,0xffffffff);Tlv(Buffer+n,26,v,4);n+=8;
        P32(v,Chanspec);Tlv(Buffer+n,3,v,4);n+=8;
        P32(v,12);Tlv(Buffer+n,5,v,4);n+=8;
        Tlv(Buffer+n,18,Peer,6);n+=12;
        P16(v,4);Tlv(Buffer+n,9,v,2);n+=8;
        P16(v,1);Tlv(Buffer+n,10,v,2);n+=8;
        P32(v,TimeoutMs);P16(v+4,2);P16(v+6,0);Tlv(Buffer+n,15,v,8);n+=12;
    }
    P16(Buffer+2,(UINT16)n);*Length=n;return STATUS_SUCCESS;
}
static NTSTATUS Find(const UCHAR* Buffer,ULONG Length,UINT16 Command,UINT16 Session,
    UINT16 Type,const UCHAR** Value,PULONG Size) {
    ULONG pos=12,end;BOOLEAN found=FALSE;
    *Value=NULL;*Size=0;
    if(!Buffer || Length<12 || F16(Buffer)!=0x300 || F16(Buffer+4)!=Command ||
        F16(Buffer+6)!=4 || F16(Buffer+8)!=Session || F16(Buffer+10) ||
        (end=F16(Buffer+2))<12 || end>Length) return STATUS_DEVICE_PROTOCOL_ERROR;
    while(pos<end) {
        ULONG n,padded;
        if(end-pos<4) return STATUS_DEVICE_PROTOCOL_ERROR;
        n=F16(Buffer+pos+2);padded=(n+3u)&~3u;
        if(padded>end-pos-4) return STATUS_DEVICE_PROTOCOL_ERROR;
        if(F16(Buffer+pos)==Type) {
            if(found) return STATUS_DEVICE_PROTOCOL_ERROR;
            found=TRUE;*Value=Buffer+pos+4;*Size=n;
        }
        pos+=4+padded;
    }
    return found?STATUS_SUCCESS:STATUS_NOT_FOUND;
}
NTSTATUS Ap6256FtmDecodeStatus(const UCHAR* Buffer,ULONG Length,UINT16 Session,
    UINT16* State,INT32* Status) {
    const UCHAR* v;ULONG n;NTSTATUS s=Find(Buffer,Length,11,Session,0x206,&v,&n);
    if(!NT_SUCCESS(s)) return s;
    if(n!=12 || F16(v)!=Session || F16(v+2)>10) return STATUS_DEVICE_PROTOCOL_ERROR;
    *State=F16(v+2);*Status=(INT32)F32(v+4);return STATUS_SUCCESS;
}
static NTSTATUS Interval(const UCHAR* p,INT64* Value) {
    UINT32 raw=F32(p);UINT16 unit=F16(p+4);INT64 scale;
    if(F16(p+6)) return STATUS_DEVICE_PROTOCOL_ERROR;
    switch(unit) {
    case 0:scale=1024000000ll;break;
    case 1:scale=1000000000000ll;break;
    case 2:scale=1000000000ll;break;
    case 3:scale=1000000ll;break;
    case 4:scale=1000ll;break;
    case 5:scale=1;break;
    default:return STATUS_DEVICE_PROTOCOL_ERROR;
    }

    { INT64 value=(INT32)raw;
      if(value>((INT64)MAXINT64)/scale || value<(-((INT64)MAXINT64))/scale) return STATUS_DEVICE_PROTOCOL_ERROR;
      *Value=value*scale; }
    return STATUS_SUCCESS;
}
NTSTATUS Ap6256FtmDecodeResult(const UCHAR* Buffer,ULONG Length,UINT16 Session,
    const UCHAR* Peer,AP6256_FTM_RESULT* Result) {
    const UCHAR* v;ULONG n,i,count;INT64 ps;UINT64 sum=0;NTSTATUS s;
    RtlZeroMemory(Result,sizeof(*Result));
    s=Find(Buffer,Length,9,Session,0x203,&v,&n);if(!NT_SUCCESS(s)) return s;
    if(!Peer || n<52 || F16(v)!=Session || !RtlEqualMemory(v+8,Peer,6) ||
        F16(v+14)>10 || (count=F16(v+50))>(n-52)/16 || n!=52+16*count)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    Result->Session=Session;Result->State=F16(v+14);Result->Status=(INT32)F32(v+4);
    Result->Measurements=v[46];Result->Rssi=(INT16)F16(v+26);Result->RateSpec=F32(v+36);
    if(Result->Status || !Result->Measurements) return STATUS_SUCCESS;
    if(Result->Measurements>v[47] || Result->Rssi>0 || Result->Rssi<-127)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    s=Interval(v+28,&ps);if(!NT_SUCCESS(s) || ps<(INT32)MINLONG || ps>(INT32)MAXLONG)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    Result->RttPs=(INT32)ps;

    if(count>1 && count==Result->Measurements) {
        for(i=0;i<count;i++) {
            INT64 sample,delta;UINT64 square;
            s=Interval(v+52+16*i+4,&sample);if(!NT_SUCCESS(s)) return s;
            if(sample<(INT32)MINLONG || sample>(INT32)MAXLONG) return STATUS_DEVICE_PROTOCOL_ERROR;
            delta=sample-ps;
            if(delta<(INT32)MINLONG || delta>(INT32)MAXLONG) return STATUS_DEVICE_PROTOCOL_ERROR;
            square=(UINT64)(delta*delta);
            if(square>MAXUINT64-sum) return STATUS_DEVICE_PROTOCOL_ERROR;
            sum+=square;
        }
        Result->VariancePs=sum/count;Result->VariancePresent=TRUE;
    }
    return STATUS_SUCCESS;
}
NTSTATUS Ap6256FtmValidateBeacon(const UCHAR* Frame,ULONG Length) {
    ULONG pos=12;
    if(!Frame || Length<12 || Length>12+AP6256_SCAN_IE_MAX) return STATUS_INVALID_PARAMETER;
    while(pos<Length) {
        ULONG n;
        if(Length-pos<2 || (n=Frame[pos+1])>Length-pos-2) return STATUS_INVALID_PARAMETER;
        pos+=n+2;
    }
    return STATUS_SUCCESS;
}
