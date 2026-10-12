/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "service_wire.h"
static UINT16 Ap6256ServiceLe16(const UCHAR* p) { return (UINT16)(p[0] | ((UINT16)p[1] << 8)); }
static UINT32 Ap6256ServiceLe32(const UCHAR* p)
{ return p[0] | ((UINT32)p[1] << 8) | ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24); }
static VOID Ap6256ServiceWirePut16(UCHAR* p, ULONG v) { p[0]=(UCHAR)v; p[1]=(UCHAR)(v >> 8); }
BOOLEAN Ap6256ServiceNameMatches(const UCHAR* Name, ULONG Length,
    const UCHAR* Pattern, ULONG PatternLength)
{
    BOOLEAN prefix;
    if (!PatternLength || !Pattern || (Length && !Name)) return FALSE;
    prefix = Pattern[PatternLength - 1] == '*';
    if (prefix) PatternLength--;
    return (BOOLEAN)((prefix ? Length >= PatternLength : Length == PatternLength) &&
        RtlEqualMemory(Name, Pattern, PatternLength));
}
NTSTATUS Ap6256ServiceEncodeQuery(const AP6256_SERVICE_ENTRY* Entry,
    UCHAR* Buffer, ULONG Capacity, ULONG* Length)
{
    ULONG n;
    *Length=0;
    if (!Entry->NameLength || Entry->NameLength > AP6256_SERVICE_NAME_MAX ||
        Entry->InfoLength > AP6256_SERVICE_REQUEST_MAX) return STATUS_INVALID_PARAMETER;
    n=16+Entry->NameLength+Entry->InfoLength;
    if (n>256 || Capacity<n) return STATUS_BUFFER_TOO_SMALL;
    Ap6256ServiceWirePut16(Buffer,0xdddd); Ap6256ServiceWirePut16(Buffer+2,n-4);
    Buffer[4]=0x50; Buffer[5]=0x6f; Buffer[6]=0x9a; Buffer[7]=9;
    Ap6256ServiceWirePut16(Buffer+8,Entry->Update); Ap6256ServiceWirePut16(Buffer+10,n-12);
    Buffer[12]=11; Buffer[13]=Entry->Transaction; Buffer[14]=(UCHAR)Entry->NameLength;
    RtlCopyMemory(Buffer+15,Entry->Name,Entry->NameLength);
    Buffer[15+Entry->NameLength]=(UCHAR)Entry->InfoLength;
    RtlCopyMemory(Buffer+16+Entry->NameLength,Entry->Info,Entry->InfoLength);
    *Length=n; return STATUS_SUCCESS;
}
NTSTATUS Ap6256ServiceDecodeResponse(const UCHAR* Buffer, ULONG Length,
    const AP6256_SERVICE_ENTRY* Query, AP6256_SERVICE_ENTRY* Entries, ULONG* Count)
{
    ULONG pos=10, n=0;
    *Count=0;
    if (!Buffer || Length<10 || Length>AP6256_SERVICE_RESPONSE_MAX ||
        Ap6256ServiceLe16(Buffer)!=0xdddd || Ap6256ServiceLe16(Buffer+2)!=Length-4 ||
        Buffer[4]!=0x50 || Buffer[5]!=0x6f || Buffer[6]!=0x9a || Buffer[7]!=9)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    while (pos<Length) {
        ULONG end, num, i;
        if (Length-pos<5 || Ap6256ServiceLe16(Buffer+pos)<3 ||
            Ap6256ServiceLe16(Buffer+pos)>Length-pos-2) return STATUS_DEVICE_PROTOCOL_ERROR;
        end=pos+2+Ap6256ServiceLe16(Buffer+pos);
        if (Buffer[pos+2]!=11 || Buffer[pos+3]!=Query->Transaction) { pos=end; continue; }
        if (Buffer[pos+4]!=0) { pos=end; continue; }
        pos+=5;
        if (pos==end) return STATUS_DEVICE_PROTOCOL_ERROR;
        num=Buffer[pos++];
        for (i=0;i<num;i++) {
            AP6256_SERVICE_ENTRY entry={0}; ULONG name, info;
            if (end-pos<7) return STATUS_DEVICE_PROTOCOL_ERROR;
            entry.AdvertisementId=Ap6256ServiceLe32(Buffer+pos);
            entry.ConfigurationMethods=Ap6256ServiceLe16(Buffer+pos+4); name=Buffer[pos+6]; pos+=7;
            if (!name || name>AP6256_SERVICE_NAME_MAX || name>end-pos || end-pos-name<3)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            entry.NameLength=name; RtlCopyMemory(entry.Name,Buffer+pos,name); pos+=name;
            entry.Status=Buffer[pos++]; info=Ap6256ServiceLe16(Buffer+pos); pos+=2;
            if (info>end-pos || info>AP6256_SERVICE_INFO_MAX) return STATUS_DEVICE_PROTOCOL_ERROR;
            entry.InfoLength=info; entry.HaveInformation=TRUE; entry.Update=Ap6256ServiceLe16(Buffer+8);
            RtlCopyMemory(entry.Info,Buffer+pos,info); pos+=info;
            if (Ap6256ServiceNameMatches(entry.Name,name,Query->Name,Query->NameLength)) {
                if (n==AP6256_SERVICE_MAX) return STATUS_BUFFER_OVERFLOW;
                Entries[n++]=entry;
            }
        }
        if (pos!=end) return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    *Count=n; return STATUS_SUCCESS;
}
NTSTATUS Ap6256ServiceDecodeAdvertisements(const UCHAR* Attributes, ULONG Length,
    AP6256_SERVICE_ENTRY* Entries, ULONG* Count)
{
    ULONG pos=0,n=0; *Count=0;
    while (pos<Length) {
        ULONG end;
        if (Length-pos<3 || Ap6256ServiceLe16(Attributes+pos+1)>Length-pos-3)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        end=pos+3+Ap6256ServiceLe16(Attributes+pos+1);
        if (Attributes[pos]!=25) { pos=end; continue; }
        pos+=3;
        while (pos<end) {
            ULONG name;
            if (end-pos<7 || n==AP6256_SERVICE_MAX) return STATUS_DEVICE_PROTOCOL_ERROR;
            name=Attributes[pos+6];
            if (!name || name>AP6256_SERVICE_NAME_MAX || name>end-pos-7)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            RtlZeroMemory(&Entries[n],sizeof(Entries[n]));
            Entries[n].AdvertisementId=Ap6256ServiceLe32(Attributes+pos);
            Entries[n].ConfigurationMethods=Ap6256ServiceLe16(Attributes+pos+4);
            Entries[n].NameLength=name; RtlCopyMemory(Entries[n].Name,Attributes+pos+7,name);
            pos+=7+name; n++;
        }
    }
    *Count=n; return STATUS_SUCCESS;
}
