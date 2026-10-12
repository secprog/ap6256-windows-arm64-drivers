/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sae.h"
#include "bcdc.h"

_Use_decl_annotations_
NTSTATUS Ap6256SaeReadRsnxe(const UCHAR* Ies, ULONG Length,
    BOOLEAN* Present, BOOLEAN* H2e)
{
    BOOLEAN found = FALSE, h2e = FALSE;
    *Present = FALSE; *H2e = FALSE;
    if (Length && Ies == NULL) return STATUS_INVALID_PARAMETER;
    while (Length) {
        ULONG size;
        if (Length < 2) return STATUS_INVALID_PARAMETER;
        size = Ies[1];
        if (size > Length - 2) return STATUS_INVALID_PARAMETER;
        if (Ies[0] == 244) {

            if (Length < 3 || found || size == 0 || size > 16)
                return STATUS_INVALID_PARAMETER;
            if (((ULONG)Ies[2] & 15u) != size - 1u)
                return STATUS_INVALID_PARAMETER;
            found = TRUE;
            h2e = (BOOLEAN)((Ies[2] & 0x20) != 0);
        }
        Ies += size + 2;
        Length -= size + 2;
    }
    *Present = found; *H2e = h2e;
    return STATUS_SUCCESS;
}

static UINT16 Ap6256SaeRead16(const UCHAR* Bytes)
{
    return (UINT16)(Bytes[0] | ((UINT16)Bytes[1] << 8));
}

static VOID Ap6256SaeWrite16(UCHAR* Bytes, UINT16 Value)
{
    Bytes[0] = (UCHAR)Value;
    Bytes[1] = (UCHAR)(Value >> 8);
}

static VOID Ap6256SaeWrite32(UCHAR* Bytes, UINT32 Value)
{
    ULONG i;
    for (i = 0; i != 4; ++i) Bytes[i] = (UCHAR)(Value >> (8 * i));
}

static VOID Ap6256SaeClearOutput(AP6256_SAE_OUTPUT* Output)
{
    RtlZeroMemory(Output, sizeof(*Output));
    Output->Notice = Ap6256SaeNoNotice;
}

static LONGLONG Ap6256SaeNextDeadline(LONGLONG DeadlineMs, LONGLONG NowMs)
{

    return NowMs + min(DeadlineMs - NowMs, AP6256_SAE_RETRY_MS);
}

static BOOLEAN Ap6256SaeUnicast(const UCHAR* Address)
{
    ULONG i;
    UCHAR any = 0;
    for (i = 0; i < 6; ++i) any |= Address[i];
    return (BOOLEAN)(any != 0 && (Address[0] & 1) == 0);
}

static BOOLEAN Ap6256SaeLive(const AP6256_SAE* Sae, LONG Generation,
    const UCHAR* Peer)
{
    return (BOOLEAN)(Sae->Generation == Generation &&
        Sae->State != Ap6256SaeIdle && Sae->State != Ap6256SaeAccepted &&
        Sae->State != Ap6256SaeFailed &&
        (Peer == NULL || RtlEqualMemory(Peer, Sae->Peer, 6)));
}

static NTSTATUS Ap6256SaeFail(AP6256_SAE* Sae, UINT32 Status,
    AP6256_SAE_OUTPUT* Output)
{
    Sae->State = Ap6256SaeFailed;
    Sae->PendingPacketId = 0;
    Sae->CommitLength = 0;
    Sae->EarlyConfirmLength = 0;
    RtlZeroMemory(Sae->Commit, sizeof(Sae->Commit));
    RtlZeroMemory(Sae->EarlyConfirm, sizeof(Sae->EarlyConfirm));
    Output->Notice = Ap6256SaeError;
    Output->Status = Status;
    return STATUS_UNSUCCESSFUL;
}

_Use_decl_annotations_
VOID Ap6256SaeReset(AP6256_SAE* Sae)
{
    UINT32 next = Sae->NextPacketId;
    RtlZeroMemory(Sae, sizeof(*Sae));
    Sae->NextPacketId = next;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeBegin(AP6256_SAE* Sae, const UCHAR* Local,
    const UCHAR* Peer, LONG Generation, LONGLONG NowMs, LONGLONG DeadlineMs,
    AP6256_SAE_OUTPUT* Output)
{
    Ap6256SaeClearOutput(Output);
    if (!Ap6256SaeUnicast(Local) || !Ap6256SaeUnicast(Peer) ||
        RtlEqualMemory(Local, Peer, 6) || Generation == 0 ||
        NowMs < 0 || DeadlineMs <= NowMs ||
        DeadlineMs - NowMs > 30000) return STATUS_INVALID_PARAMETER;
    Ap6256SaeReset(Sae);
    Sae->State = Ap6256SaeCommitParameters;
    Sae->Generation = Generation;
    Sae->DeadlineMs = DeadlineMs;
    Sae->RetryAtMs = Ap6256SaeNextDeadline(DeadlineMs, NowMs);
    RtlCopyMemory(Sae->Local, Local, 6);
    RtlCopyMemory(Sae->Peer, Peer, 6);
    Output->Notice = Ap6256SaeNeedCommit;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256SaeTransmit(AP6256_SAE* Sae, LONGLONG NowMs,
    AP6256_SAE_OUTPUT* Output)
{
    if (Sae->Transmits == AP6256_SAE_TX_LIMIT)
        return Ap6256SaeFail(Sae, 1, Output);
    ++Sae->Transmits;
    if (++Sae->NextPacketId == 0) ++Sae->NextPacketId;
    Sae->PendingPacketId = Sae->NextPacketId;
    Output->PacketId = Sae->PendingPacketId;
    Sae->RetryAtMs = Ap6256SaeNextDeadline(Sae->DeadlineMs, NowMs);
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256SaeBytesValid(const AP6256_SAE_BYTES* Bytes)
{
    return (BOOLEAN)(Bytes->Length == 0 || Bytes->Data != NULL);
}

static ULONG Ap6256SaePrimeLength(UINT16 Group)
{

    switch (Group) {
    case 19: return 32;
    case 20: return 48;
    case 21: return 66;
    default: return 0;
    }
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeCommit(AP6256_SAE* Sae, LONG Generation,
    const UCHAR* Peer, LONGLONG NowMs, const AP6256_SAE_COMMIT* Commit,
    AP6256_SAE_OUTPUT* Output)
{
    ULONG prime = Ap6256SaePrimeLength(Commit->Group);
    ULONG offset = 8;
    NTSTATUS status;
    Ap6256SaeClearOutput(Output);
    if (NowMs < 0) return STATUS_INVALID_PARAMETER;
    if (!Ap6256SaeLive(Sae, Generation, Peer) ||
        (Sae->State != Ap6256SaeCommitParameters &&
         Sae->State != Ap6256SaeCommitDecision)) return STATUS_INVALID_DEVICE_STATE;
    if (NowMs >= Sae->DeadlineMs) return Ap6256SaeFail(Sae, 51, Output);
    if (prime == 0 || Commit->Scalar.Length != prime ||
        Commit->Element.Length != 2 * prime ||
        !Ap6256SaeBytesValid(&Commit->Scalar) ||
        !Ap6256SaeBytesValid(&Commit->Element) ||
        !Ap6256SaeBytesValid(&Commit->Token) ||
        !Ap6256SaeBytesValid(&Commit->RejectedGroups) ||
        Commit->Token.Length > 254 || Commit->RejectedGroups.Length > 254 ||
        (Commit->RejectedGroups.Length & 1) != 0 ||
        (!Commit->H2e && Commit->RejectedGroups.Length != 0))
        return STATUS_INVALID_PARAMETER;
    Ap6256SaeWrite16(Output->TxBody, 3);
    Ap6256SaeWrite16(Output->TxBody + 2, 1);
    Ap6256SaeWrite16(Output->TxBody + 4, Commit->H2e ? 126 : 0);
    Ap6256SaeWrite16(Output->TxBody + 6, Commit->Group);

    if (!Commit->H2e && Commit->Token.Length) {
        RtlCopyMemory(Output->TxBody + offset, Commit->Token.Data, Commit->Token.Length);
        offset += Commit->Token.Length;
    }
    RtlCopyMemory(Output->TxBody + offset, Commit->Scalar.Data, prime);
    offset += prime;
    RtlCopyMemory(Output->TxBody + offset, Commit->Element.Data, 2 * prime);
    offset += 2 * prime;

    if (Commit->H2e && Commit->RejectedGroups.Length) {
        Output->TxBody[offset++] = 255;
        Output->TxBody[offset++] = (UCHAR)(1 + Commit->RejectedGroups.Length);
        Output->TxBody[offset++] = 92;
        RtlCopyMemory(Output->TxBody + offset, Commit->RejectedGroups.Data,
                      Commit->RejectedGroups.Length);
        offset += Commit->RejectedGroups.Length;
    }
    if (Commit->H2e && Commit->Token.Length) {
        Output->TxBody[offset++] = 255;
        Output->TxBody[offset++] = (UCHAR)(1 + Commit->Token.Length);
        Output->TxBody[offset++] = 93;
        RtlCopyMemory(Output->TxBody + offset, Commit->Token.Data, Commit->Token.Length);
        offset += Commit->Token.Length;
    }
    Output->TxLength = offset;
    status = Ap6256SaeTransmit(Sae, NowMs, Output);
    if (!NT_SUCCESS(status)) {
        Output->TxLength = 0;
        return status;
    }
    Sae->H2e = Commit->H2e;
    Sae->ConfirmLength = Commit->H2e ? (prime <= 32 ? 32 : (prime <= 48 ? 48 : 64)) : 32;
    Sae->EarlyConfirmLength = 0;
    Sae->CommitLength = offset;
    RtlCopyMemory(Sae->Commit, Output->TxBody, offset);
    Sae->State = Ap6256SaeCommitResponse;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeConfirm(AP6256_SAE* Sae, LONG Generation,
    const UCHAR* Peer, LONGLONG NowMs, UINT16 SendConfirm,
    const UCHAR* Confirm, ULONG Length, AP6256_SAE_OUTPUT* Output)
{
    NTSTATUS status;
    Ap6256SaeClearOutput(Output);
    if (NowMs < 0) return STATUS_INVALID_PARAMETER;
    if (!Ap6256SaeLive(Sae, Generation, Peer) ||
        (Sae->State != Ap6256SaeConfirmParameters &&
         Sae->State != Ap6256SaeCommitDecision)) return STATUS_INVALID_DEVICE_STATE;
    if (NowMs >= Sae->DeadlineMs) return Ap6256SaeFail(Sae, 52, Output);
    if (Confirm == NULL || Length != Sae->ConfirmLength)
        return STATUS_INVALID_PARAMETER;
    Ap6256SaeWrite16(Output->TxBody, 3);
    Ap6256SaeWrite16(Output->TxBody + 2, 2);
    Ap6256SaeWrite16(Output->TxBody + 6, SendConfirm);
    RtlCopyMemory(Output->TxBody + 8, Confirm, Length);
    Output->TxLength = 8 + Length;
    status = Ap6256SaeTransmit(Sae, NowMs, Output);
    if (!NT_SUCCESS(status)) {
        Output->TxLength = 0;
        return status;
    }
    Sae->State = Ap6256SaeConfirmResponse;
    if (Sae->EarlyConfirmLength) {
        RtlCopyMemory(Output->RxFrame, Sae->EarlyConfirm, Sae->EarlyConfirmLength);
        Output->RxLength = Sae->EarlyConfirmLength;
        Sae->EarlyConfirmLength = 0;
        Sae->State = Ap6256SaeStatus;
        Output->Notice = Ap6256SaePeerConfirm;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeReceive(AP6256_SAE* Sae, LONG Generation, LONGLONG NowMs,
    const UCHAR* Frame, ULONG Length, AP6256_SAE_OUTPUT* Output)
{
    UINT16 sequence;
    Ap6256SaeClearOutput(Output);
    if (NowMs < 0) return STATUS_INVALID_PARAMETER;
    if (!Ap6256SaeLive(Sae, Generation, NULL)) return STATUS_INVALID_DEVICE_STATE;
    if (NowMs >= Sae->DeadlineMs) return Ap6256SaeFail(Sae, 1, Output);
    if (Length < 30 || Length > AP6256_SAE_FRAME_MAX ||
        (Ap6256SaeRead16(Frame) & 0xc7ff) != 0x00b0 ||
        (Ap6256SaeRead16(Frame + 22) & 15) != 0 ||
        !RtlEqualMemory(Frame + 4, Sae->Local, 6) ||
        !RtlEqualMemory(Frame + 10, Sae->Peer, 6) ||
        !RtlEqualMemory(Frame + 16, Sae->Peer, 6) ||
        Ap6256SaeRead16(Frame + 24) != 3) return STATUS_INVALID_PARAMETER;
    sequence = Ap6256SaeRead16(Frame + 26);
    if (sequence == 1 && Sae->State == Ap6256SaeCommitResponse) {
        Sae->PendingPacketId = 0;

        Sae->State = Ap6256SaeCommitDecision;
        Output->Notice = Ap6256SaePeerCommit;
    } else if (sequence == 2 && (Sae->State == Ap6256SaeCommitDecision ||
                               Sae->State == Ap6256SaeConfirmParameters)) {
        if (Sae->EarlyConfirmLength != 0) return STATUS_NOT_FOUND;
        RtlCopyMemory(Sae->EarlyConfirm, Frame, Length);
        Sae->EarlyConfirmLength = Length;
        return STATUS_SUCCESS;
    } else if (sequence == 2 && Sae->State == Ap6256SaeConfirmResponse) {
        Sae->PendingPacketId = 0;
        Sae->State = Ap6256SaeStatus;
        Output->Notice = Ap6256SaePeerConfirm;
    } else {
        return STATUS_NOT_FOUND;
    }
    Sae->RetryAtMs = Ap6256SaeNextDeadline(Sae->DeadlineMs, NowMs);
    Output->RxLength = Length;
    RtlCopyMemory(Output->RxFrame, Frame, Length);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeFinish(AP6256_SAE* Sae, LONG Generation, const UCHAR* Peer,
    LONGLONG NowMs, BOOLEAN Success, UINT32 Status, AP6256_SAE_OUTPUT* Output)
{
    Ap6256SaeClearOutput(Output);
    if (NowMs < 0) return STATUS_INVALID_PARAMETER;
    if (!Ap6256SaeLive(Sae, Generation, Peer)) return STATUS_INVALID_DEVICE_STATE;
    if (NowMs >= Sae->DeadlineMs) return Ap6256SaeFail(Sae, 53, Output);
    if (!Success) return Ap6256SaeFail(Sae, Status ? Status : 1, Output);
    if (Sae->State != Ap6256SaeStatus || Status != 0) return STATUS_INVALID_DEVICE_STATE;
    Sae->State = Ap6256SaeAccepted;
    Sae->PendingPacketId = 0;
    Sae->CommitLength = 0;
    RtlZeroMemory(Sae->Commit, sizeof(Sae->Commit));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeTimeout(AP6256_SAE* Sae, LONG Generation, LONGLONG NowMs,
    AP6256_SAE_OUTPUT* Output)
{
    Ap6256SaeClearOutput(Output);
    if (NowMs < 0) return STATUS_INVALID_PARAMETER;
    if (!Ap6256SaeLive(Sae, Generation, NULL)) return STATUS_INVALID_DEVICE_STATE;
    if (NowMs < Sae->RetryAtMs) return STATUS_NOT_FOUND;
    if (NowMs >= Sae->DeadlineMs || Sae->Transmits == AP6256_SAE_TX_LIMIT)
        return Ap6256SaeFail(Sae, 1, Output);
    if (Sae->State == Ap6256SaeCommitResponse) {
        NTSTATUS status = Ap6256SaeTransmit(Sae, NowMs, Output);
        if (!NT_SUCCESS(status)) return status;
        Output->TxLength = Sae->CommitLength;
        RtlCopyMemory(Output->TxBody, Sae->Commit, Sae->CommitLength);
    } else if (Sae->State == Ap6256SaeConfirmResponse) {

        Sae->State = Ap6256SaeConfirmParameters;
        Sae->PendingPacketId = 0;
        Output->Notice = Ap6256SaeNeedNewConfirm;
        Sae->RetryAtMs = Ap6256SaeNextDeadline(Sae->DeadlineMs, NowMs);
    } else {
        return Ap6256SaeFail(Sae,
            Sae->State == Ap6256SaeCommitParameters ? 51 :
            (Sae->State == Ap6256SaeConfirmParameters ||
             Sae->State == Ap6256SaeCommitDecision ? 52 : 53), Output);
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeTxStatus(AP6256_SAE* Sae, LONG Generation,
    UINT32 PacketId, BOOLEAN Acknowledged, AP6256_SAE_OUTPUT* Output)
{
    Ap6256SaeClearOutput(Output);
    if (!Ap6256SaeLive(Sae, Generation, NULL) || PacketId == 0 ||
        PacketId != Sae->PendingPacketId) return STATUS_NOT_FOUND;
    Sae->PendingPacketId = 0;

    UNREFERENCED_PARAMETER(Acknowledged);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeSendAuth(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Channel,
    const UCHAR* Peer, UINT32 PacketId, const UCHAR* Body, ULONG Length)
{
    UCHAR request[32 + AP6256_SAE_BODY_MAX];
    if (!Ap6256SaeUnicast(Peer) || Channel == 0 || Channel > 196 ||
        PacketId == 0 || Length < 6 || Length > AP6256_SAE_BODY_MAX ||
        Ap6256SaeRead16(Body) != 3 ||
        (Ap6256SaeRead16(Body + 2) != 1 && Ap6256SaeRead16(Body + 2) != 2))
        return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(request, sizeof(request));
    Ap6256SaeWrite32(request + 4, 4000);
    Ap6256SaeWrite16(request + 8, (UINT16)Length);
    Ap6256SaeWrite16(request + 10, 0x00b0);
    Ap6256SaeWrite16(request + 12, Channel);
    RtlCopyMemory(request + 14, Peer, 6);
    RtlCopyMemory(request + 20, Peer, 6);
    Ap6256SaeWrite32(request + 28, PacketId);
    RtlCopyMemory(request + 32, Body, Length);
    return Ap6256BcdcSetIovar(Ctx, "mgmt_frame", request, 32 + Length);
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeAuthStatus(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Peer,
    const UCHAR* Ssid, ULONG SsidLength, BOOLEAN Success)
{
    UCHAR request[60];
    if (!Ap6256SaeUnicast(Peer) || SsidLength == 0 || SsidLength > 32)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(request, sizeof(request));
    Ap6256SaeWrite16(request, Success ? 4 : 3);
    RtlCopyMemory(request + 2, Peer, 6);
    Ap6256SaeWrite32(request + 8, SsidLength);
    RtlCopyMemory(request + 12, Ssid, SsidLength);

    return Ap6256BcdcSetIovar(Ctx, "auth_status", request, sizeof(request));
}
