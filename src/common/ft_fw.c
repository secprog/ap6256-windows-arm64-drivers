/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ft_fw.h"
#include "bcdc.h"

_Use_decl_annotations_
NTSTATUS Ap6256FtFirmwareQualify(PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 reply[5] = { 0 };
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    Ctx->FirmwareHostFt = FALSE;
    if (!Ctx->FirmwareFtPatchVerified) return STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&result, sizeof(result));
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "hostft", reply, sizeof(reply), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(reply) ||
        reply[0] != AP6256_FT_EVENT_MAGIC ||
        reply[1] != (AP6256_FT_FW_VERSION | (AP6256_FT_FW_HEADER << 16)) ||
        reply[2] != AP6256_FT_FW_AUTH_MAX || reply[3] != 7 || reply[4] != 0)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    Ctx->FirmwareHostFt = TRUE;
    TraceDiag("FT bridge: ABI verified; native Windows FT over 802.1X available\n");
    return STATUS_SUCCESS;
}

static ULONG Ap6256FtRead16(const UCHAR* Data)
{
    return (ULONG)Data[0] | ((ULONG)Data[1] << 8);
}

static ULONG Ap6256FtRead32(const UCHAR* Data)
{
    return Ap6256FtRead16(Data) | (Ap6256FtRead16(Data + 2) << 16);
}

BOOLEAN Ap6256FtDecodeEvent(const UCHAR* Data, ULONG Length, AP6256_FT_EVENT* Event)
{
    ULONG request, response, index;
    UCHAR any = 0;
    if (Data == NULL || Event == NULL || Length < AP6256_FT_FW_HEADER ||
        Ap6256FtRead32(Data) != AP6256_FT_EVENT_MAGIC ||
        Ap6256FtRead16(Data + 4) != AP6256_FT_FW_VERSION ||
        Ap6256FtRead16(Data + 6) != AP6256_FT_FW_HEADER ||
        Ap6256FtRead16(Data + 20) != 0 || Ap6256FtRead16(Data + 22) != 0 ||
        Ap6256FtRead16(Data + 34) != 0 || Ap6256FtRead32(Data + 36) != 0 ||
        (Data[24] & 1)) return FALSE;
    request = Ap6256FtRead16(Data + 30);
    response = Ap6256FtRead16(Data + 32);
    for (index = 0; index < 6; ++index) any |= Data[24 + index];
    if (!any || request < 6 || response < 6 || request > AP6256_FT_FW_AUTH_MAX ||
        response > AP6256_FT_FW_AUTH_MAX || Length != AP6256_FT_FW_HEADER + request + response ||
        !(Ap6256FtRead32(Data + 8) | Ap6256FtRead32(Data + 12))) return FALSE;
    RtlZeroMemory(Event, sizeof(*Event));
    Event->Owner.Generation = Ap6256FtRead32(Data + 8) |
        ((ULONGLONG)Ap6256FtRead32(Data + 12) << 32);
    Event->Owner.TransactionId = Ap6256FtRead32(Data + 16);
    RtlCopyMemory(Event->Owner.Bssid, Data + 24, 6);
    Event->RequestLength = request;
    Event->ResponseLength = response;
    RtlCopyMemory(Event->Bodies, Data + AP6256_FT_FW_HEADER, request + response);
    return TRUE;
}

static VOID Ap6256FtPut16(UCHAR* Output, ULONG Value)
{
    Output[0] = (UCHAR)Value;
    Output[1] = (UCHAR)(Value >> 8);
}

static VOID Ap6256FtPut32(UCHAR* Output, ULONG Value)
{
    Ap6256FtPut16(Output, Value);
    Ap6256FtPut16(Output + 2, Value >> 16);
}

static BOOLEAN Ap6256FtFirmwareIe(const UCHAR* Data, ULONG Length,
    UCHAR Id, ULONG Minimum)
{
    return Data != NULL && Length >= Minimum && Length <= 257 &&
        Data[0] == Id && (ULONG)Data[1] + 2 == Length;
}

static NTSTATUS Ap6256FtFirmwareSend(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner, ULONG Operation,
    const UCHAR* Rsn, ULONG RsnLength, const UCHAR* Mde, ULONG MdeLength,
    const UCHAR* Fte, ULONG FteLength, const UCHAR* PmkR0Name, ULONG PmkLength)
{
    UCHAR packet[AP6256_FT_FW_HEADER + 257 + 5 + 257 + 16];
    ULONG length = AP6256_FT_FW_HEADER, index;
    UCHAR any = 0;
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    if (!Ctx->FirmwareHostFt) return STATUS_NOT_SUPPORTED;
    if (Owner == NULL || Owner->Generation == 0 || Owner->PortId != 0 ||
        (Owner->Bssid[0] & 1) != 0) return STATUS_INVALID_PARAMETER;
    for (index = 0; index < 6; ++index) any |= Owner->Bssid[index];
    if (!any || RsnLength > 257 || MdeLength > 5 || FteLength > 257 || PmkLength > 16 ||
        (RsnLength && Rsn == NULL) || (MdeLength && Mde == NULL) ||
        (FteLength && Fte == NULL) || (PmkLength && PmkR0Name == NULL))
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(packet, sizeof(packet));
    Ap6256FtPut16(packet, AP6256_FT_FW_VERSION);
    Ap6256FtPut16(packet + 2, Operation);
    Ap6256FtPut32(packet + 8, (ULONG)Owner->Generation);
    Ap6256FtPut32(packet + 12, (ULONG)(Owner->Generation >> 32));
    Ap6256FtPut32(packet + 16, Owner->TransactionId);
    Ap6256FtPut16(packet + 20, Owner->PortId);
    RtlCopyMemory(packet + 24, Owner->Bssid, 6);
    Ap6256FtPut16(packet + 30, RsnLength);
    Ap6256FtPut16(packet + 32, MdeLength);
    Ap6256FtPut16(packet + 34, FteLength);
    Ap6256FtPut16(packet + 36, PmkLength);
    if (RsnLength) { RtlCopyMemory(packet + length, Rsn, RsnLength); length += RsnLength; }
    if (MdeLength) { RtlCopyMemory(packet + length, Mde, MdeLength); length += MdeLength; }
    if (FteLength) { RtlCopyMemory(packet + length, Fte, FteLength); length += FteLength; }
    if (PmkLength) { RtlCopyMemory(packet + length, PmkR0Name, PmkLength); length += PmkLength; }
    Ap6256FtPut32(packet + 4, length);
    RtlZeroMemory(&result, sizeof(result));
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "hostft", packet, length, &result);
    if (!NT_SUCCESS(status)) return status;
    return result.FirmwareReply && !result.FirmwareError ? STATUS_SUCCESS :
        STATUS_DEVICE_PROTOCOL_ERROR;
}

_Use_decl_annotations_
NTSTATUS Ap6256FtFirmwareBegin(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner, BOOLEAN Reassociation,
    const UCHAR* Mde, ULONG MdeLength, const UCHAR* Fte, ULONG FteLength,
    const UCHAR* PmkR0Name, ULONG PmkLength)
{
    if (MdeLength != 5 || !Ap6256FtFirmwareIe(Mde, MdeLength, 54, 5) ||
        (Reassociation && (!Ap6256FtFirmwareIe(Fte, FteLength, 55, 84) ||
                          PmkLength != 16 || PmkR0Name == NULL)) ||
        (!Reassociation && (FteLength || PmkLength))) return STATUS_INVALID_PARAMETER;
    return Ap6256FtFirmwareSend(Ctx, Owner, Reassociation ?
        AP6256_FT_FW_AUTHENTICATE : AP6256_FT_FW_INITIAL,
        NULL, 0, Mde, MdeLength, Fte, FteLength, PmkR0Name, PmkLength);
}

_Use_decl_annotations_
NTSTATUS Ap6256FtFirmwareResume(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner, const UCHAR* Rsn, ULONG RsnLength,
    const UCHAR* Mde, ULONG MdeLength, const UCHAR* Fte, ULONG FteLength)
{
    if (!Ap6256FtFirmwareIe(Rsn, RsnLength, 48, 4) || Rsn[2] != 1 || Rsn[3] != 0 ||
        MdeLength != 5 || !Ap6256FtFirmwareIe(Mde, MdeLength, 54, 5) ||
        !Ap6256FtFirmwareIe(Fte, FteLength, 55, 84)) return STATUS_INVALID_PARAMETER;
    return Ap6256FtFirmwareSend(Ctx, Owner, AP6256_FT_FW_RESUME,
        Rsn, RsnLength, Mde, MdeLength, Fte, FteLength, NULL, 0);
}

_Use_decl_annotations_
NTSTATUS Ap6256FtFirmwareCancel(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner)
{
    return Ap6256FtFirmwareSend(Ctx, Owner, AP6256_FT_FW_CANCEL,
        NULL, 0, NULL, 0, NULL, 0, NULL, 0);
}

_Use_decl_annotations_
NTSTATUS Ap6256FtFirmwareComplete(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner)
{
    return Ap6256FtFirmwareSend(Ctx, Owner, AP6256_FT_FW_COMPLETE,
        NULL, 0, NULL, 0, NULL, 0, NULL, 0);
}
