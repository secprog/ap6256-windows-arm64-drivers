/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ft.h"
#include "ft_fw.h"

static BOOLEAN Ap6256FtIe(_In_reads_bytes_opt_(Length) const UCHAR* Data,
    _In_ ULONG Length, _In_ UCHAR Id, _In_ ULONG Minimum)
{
    return Data != NULL && Length >= Minimum && Length <= 257u &&
        Data[0] == Id && (ULONG)Data[1] + 2u == Length;
}

static BOOLEAN Ap6256FtMde(_In_reads_bytes_opt_(Length) const UCHAR* Data,
    _In_ ULONG Length)
{
    return Length == AP6256_FT_MDE_LENGTH && Ap6256FtIe(Data, Length, 54, 5);
}

static VOID Ap6256FtClear(_Inout_ AP6256_FT_STATE* State)
{
    ULONGLONG generation = State->NextGeneration;
    BOOLEAN domainValid = State->MobilityDomainValid;
    UCHAR domain[2];
    RtlCopyMemory(domain, State->MobilityDomain, sizeof(domain));
    RtlZeroMemory(State, sizeof(*State));
    State->NextGeneration = generation;
    State->MobilityDomainValid = domainValid;
    RtlCopyMemory(State->MobilityDomain, domain, sizeof(domain));
}

VOID Ap6256FtConnectionLost(_Inout_ AP6256_FT_STATE* State)
{
    State->MobilityDomainValid = FALSE;
    RtlZeroMemory(State->MobilityDomain, sizeof(State->MobilityDomain));
}

BOOLEAN Ap6256FtOwnerMatches(_In_ const AP6256_FT_STATE* State,
    _In_ const AP6256_FT_OWNER* Owner)
{
    return State->Phase != Ap6256FtIdle && Owner->Generation != 0 &&
        State->Owner.Generation == Owner->Generation &&
        State->Owner.TransactionId == Owner->TransactionId &&
        State->Owner.PortId == Owner->PortId &&
        RtlCompareMemory(State->Owner.Bssid, Owner->Bssid, 6) == 6;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtEnd(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_ AP6256_FT_STATE* State, _In_ BOOLEAN Associated)
{
    NTSTATUS status;
    if (State->Phase == Ap6256FtIdle || State->Phase == Ap6256FtDrainingHost)
        return STATUS_SUCCESS;
    if (Associated && (State->Phase == Ap6256FtInitial ||
                       State->Phase == Ap6256FtResumed)) {
        status = Ap6256FtFirmwareComplete(Ctx, &State->Owner);
        if (!NT_SUCCESS(status)) {
            State->Phase = Ap6256FtAbortRequired;
            return status;
        }
        State->MobilityDomainValid = TRUE;
        RtlCopyMemory(State->MobilityDomain, State->Mde + 2, 2);
        Ap6256FtClear(State);
        return STATUS_SUCCESS;
    }
    if (State->NeedsAbort) {
        status = Ap6256FtFirmwareCancel(Ctx, &State->Owner);
        if (!NT_SUCCESS(status)) {
            State->Phase = Ap6256FtAbortRequired;
            return status;
        }
        State->NeedsAbort = FALSE;
    }
    if (State->HostReplyOutstanding) {

        State->Phase = Ap6256FtDrainingHost;
    } else {
        Ap6256FtClear(State);
    }
    return Associated ? STATUS_DEVICE_PROTOCOL_ERROR : STATUS_SUCCESS;
}

NTSTATUS Ap6256FtValidateBegin(
    _In_ const AP6256_FT_STATE* State,
    _In_reads_(6) const UCHAR* Bssid, _In_ BOOLEAN Reassociation,
    _In_reads_bytes_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength,
    _In_reads_bytes_opt_(PmkLength) const UCHAR* PmkR0Name, _In_ ULONG PmkLength)
{
    UCHAR any = 0;
    ULONG index;
    if (State->Phase != Ap6256FtIdle) return STATUS_DEVICE_BUSY;
    if (Bssid == NULL || (Bssid[0] & 1u) != 0 ||
        !Ap6256FtMde(Mde, MdeLength)) return STATUS_INVALID_PARAMETER;
    for (index = 0; index < 6; ++index) any |= Bssid[index];
    if (any == 0 || State->NextGeneration == (ULONGLONG)-1)
        return STATUS_INVALID_PARAMETER;
    if (Reassociation && (!State->MobilityDomainValid ||
        RtlCompareMemory(State->MobilityDomain, Mde + 2, 2) != 2))
        return STATUS_INVALID_PARAMETER;
    if (Reassociation && (Fte == NULL || !Ap6256FtIe(Fte, FteLength, 55,
            AP6256_FT_FTE_MIN_LENGTH) || PmkR0Name == NULL || PmkLength != 16))
        return STATUS_INVALID_PARAMETER;
    if (!Reassociation && (FteLength != 0 || PmkLength != 0))
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtBegin(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ AP6256_FT_STATE* State,
    _In_ UINT16 PortId, _In_ UINT32 TransactionId,
    _In_reads_(6) const UCHAR* Bssid, _In_ BOOLEAN Reassociation,
    _In_reads_bytes_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength,
    _In_reads_bytes_opt_(PmkLength) const UCHAR* PmkR0Name, _In_ ULONG PmkLength)
{
    NTSTATUS status = Ap6256FtValidateBegin(State, Bssid, Reassociation,
        Mde, MdeLength, Fte, FteLength, PmkR0Name, PmkLength);
    if (!NT_SUCCESS(status)) return status;
    if (!Ctx->FirmwareHostFt) return STATUS_NOT_SUPPORTED;
    if (PortId != 0) return STATUS_INVALID_PARAMETER;
    if (Reassociation && (PmkR0Name == NULL || Fte == NULL))
        return STATUS_INVALID_PARAMETER;

    State->Owner.Generation = ++State->NextGeneration;
    State->Owner.PortId = PortId;
    State->Owner.TransactionId = TransactionId;
    RtlCopyMemory(State->Owner.Bssid, Bssid, 6);
    RtlCopyMemory(State->Mde, Mde, sizeof(State->Mde));
    State->Phase = Reassociation ? Ap6256FtAuthenticating : Ap6256FtInitial;
    if (Reassociation && Fte != NULL) RtlCopyMemory(State->SNonce, Fte + 52, 32);

    State->NeedsAbort = TRUE;
    status = Ap6256FtFirmwareBegin(Ctx, &State->Owner, Reassociation,
        Mde, MdeLength, Fte, FteLength, PmkR0Name, PmkLength);
    if (!NT_SUCCESS(status)) (VOID)Ap6256FtEnd(Ctx, State, FALSE);
    return status;
}

_Success_(return != FALSE)
static BOOLEAN Ap6256FtAuthBody(_In_reads_bytes_opt_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_ UCHAR Sequence, _Outptr_ const UCHAR** Mde,
    _Outptr_ const UCHAR** Fte)
{
    ULONG offset = 6;
    BOOLEAN rsn = FALSE;
    *Mde = NULL;
    *Fte = NULL;
    if (Body == NULL || Length < 6 || Length > AP6256_FT_AUTH_MAX_LENGTH ||
        Body[0] != 2 || Body[1] != 0 || Body[2] != Sequence || Body[3] != 0 ||
        Body[4] != 0 || Body[5] != 0) return FALSE;
    while (offset < Length) {
        ULONG size;
        const UCHAR* ie;
        if (Length - offset < 2) return FALSE;
        ie = Body + offset;
        size = (ULONG)ie[1] + 2u;
        if (size > Length - offset) return FALSE;
        if (ie[0] == 48) {
            if (rsn || size < 4 || ie[2] != 1 || ie[3] != 0) return FALSE;
            rsn = TRUE;
        } else if (ie[0] == 54) {
            if (*Mde != NULL || !Ap6256FtMde(ie, size)) return FALSE;
            *Mde = ie;
        } else if (ie[0] == 55) {
            if (*Fte != NULL || size < AP6256_FT_FTE_MIN_LENGTH) return FALSE;
            *Fte = ie;
        }
        offset += size;
    }
    return rsn && *Mde != NULL && *Fte != NULL;
}

_Success_(return != FALSE)
BOOLEAN Ap6256FtReadAuthenticationIdentity(
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length,
    _In_ UCHAR Sequence, _Out_writes_(AP6256_FT_MDE_LENGTH) UCHAR* Mde,
    _Out_writes_(32) UCHAR* SNonce)
{
    const UCHAR *mde, *fte;
    if ((Sequence != 1 && Sequence != 2) ||
        !Ap6256FtAuthBody(Body, Length, Sequence, &mde, &fte)) return FALSE;
    RtlCopyMemory(Mde, mde, AP6256_FT_MDE_LENGTH);
    RtlCopyMemory(SNonce, fte + 52, 32);
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtAcceptAuthentication(
    _Inout_ AP6256_FT_STATE* State, _In_ const AP6256_FT_OWNER* Owner,
    _In_reads_bytes_(RequestLength) const UCHAR* Request, _In_ ULONG RequestLength,
    _In_reads_bytes_(ResponseLength) const UCHAR* Response, _In_ ULONG ResponseLength)
{
    const UCHAR *requestMde, *requestFte, *responseMde, *responseFte;
    if (!Ap6256FtOwnerMatches(State, Owner) ||
        State->Phase != Ap6256FtAuthenticating) return STATUS_INVALID_DEVICE_STATE;
    if (!Ap6256FtAuthBody(Request, RequestLength, 1, &requestMde, &requestFte) ||
        !Ap6256FtAuthBody(Response, ResponseLength, 2, &responseMde, &responseFte) ||
        RtlCompareMemory(requestMde, State->Mde, 5) != 5 ||
        RtlCompareMemory(responseMde, State->Mde, 5) != 5 ||
        RtlCompareMemory(requestFte + 52, State->SNonce, 32) != 32 ||
        RtlCompareMemory(responseFte + 52, State->SNonce, 32) != 32)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    RtlCopyMemory(State->ANonce, responseFte + 20, 32);
    State->Phase = Ap6256FtWaitingHost;

    State->HostReplyOutstanding = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFinish(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ AP6256_FT_STATE* State,
    _In_ const AP6256_FT_OWNER* Owner, _In_ UINT32 HostStatus,
    _In_reads_bytes_opt_(RsnLength) const UCHAR* Rsn, _In_ ULONG RsnLength,
    _In_reads_bytes_opt_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength)
{
    NTSTATUS status;
    if (!Ap6256FtOwnerMatches(State, Owner)) return STATUS_INVALID_DEVICE_STATE;
    if (State->Phase == Ap6256FtAbortRequired && State->HostReplyOutstanding) {

        State->HostReplyOutstanding = FALSE;
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (State->Phase == Ap6256FtDrainingHost) {
        Ap6256FtClear(State);
        return STATUS_SUCCESS;
    }
    if (State->Phase != Ap6256FtWaitingHost) return STATUS_INVALID_DEVICE_STATE;
    if (HostStatus != 0) {
        State->HostReplyOutstanding = FALSE;
        return Ap6256FtEnd(Ctx, State, FALSE);
    }
    if (Rsn == NULL || Mde == NULL || Fte == NULL ||
        !Ap6256FtIe(Rsn, RsnLength, 48, 4) || Rsn[2] != 1 || Rsn[3] != 0 ||
        !Ap6256FtMde(Mde, MdeLength) ||
        !Ap6256FtIe(Fte, FteLength, 55, AP6256_FT_FTE_MIN_LENGTH)) {
        State->HostReplyOutstanding = FALSE;
        (VOID)Ap6256FtEnd(Ctx, State, FALSE);
        return STATUS_INVALID_PARAMETER;
    }
    if (RtlCompareMemory(Mde, State->Mde, 5) != 5 ||
        RtlCompareMemory(Fte + 20, State->ANonce, 32) != 32 ||
        RtlCompareMemory(Fte + 52, State->SNonce, 32) != 32) {

        return STATUS_INVALID_DEVICE_STATE;
    }
    State->HostReplyOutstanding = FALSE;

    status = Ap6256FtFirmwareResume(Ctx, &State->Owner,
        Rsn, RsnLength, Mde, MdeLength, Fte, FteLength);
    if (!NT_SUCCESS(status)) {
        (VOID)Ap6256FtEnd(Ctx, State, FALSE);
    } else {
        State->NeedsAbort = TRUE;
        State->FinalRsnLength = RsnLength;
        State->FinalFteLength = FteLength;
        RtlCopyMemory(State->FinalRsn, Rsn, RsnLength);
        RtlCopyMemory(State->FinalFte, Fte, FteLength);
        State->Phase = Ap6256FtResumed;
    }
    return status;
}

BOOLEAN Ap6256FtAssociationValid(const AP6256_FT_STATE* State,
    const AP6256_ASSOC_FRAMES* Frames)
{
    ULONG offset = Frames->ReAssociation ? 10u : 4u;
    const UCHAR *rsn = NULL, *mde = NULL, *fte = NULL;
    ULONG rsnLength = 0, fteLength = 0;
    if ((State->Phase != Ap6256FtInitial && State->Phase != Ap6256FtResumed) ||
        Frames->AssocRequest == NULL || Frames->AssocRequestLength < offset ||
        (State->Phase == Ap6256FtResumed && !Frames->ReAssociation)) return FALSE;
    while (offset < Frames->AssocRequestLength) {
        const UCHAR* e = Frames->AssocRequest + offset;
        ULONG length;
        if (Frames->AssocRequestLength - offset < 2 ||
            (length = (ULONG)e[1] + 2) > Frames->AssocRequestLength - offset) return FALSE;
        if (e[0] == 48) { if (rsn) return FALSE; rsn = e; rsnLength = length; }
        if (e[0] == 54) { if (mde || length != 5) return FALSE; mde = e; }
        if (e[0] == 55) { if (fte) return FALSE; fte = e; fteLength = length; }
        offset += length;
    }
    if (rsn == NULL || mde == NULL || RtlCompareMemory(mde, State->Mde, 5) != 5)
        return FALSE;
    if (State->Phase == Ap6256FtResumed)
        return rsnLength == State->FinalRsnLength && fte != NULL &&
            fteLength == State->FinalFteLength &&
            RtlCompareMemory(rsn, State->FinalRsn, rsnLength) == rsnLength &&
            RtlCompareMemory(fte, State->FinalFte, fteLength) == fteLength;

    return rsnLength >= 20 && rsn[2] == 1 && rsn[3] == 0 &&
        RtlCompareMemory(rsn + 4, "\x00\x0f\xac\x04", 4) == 4 &&
        rsn[8] == 1 && rsn[9] == 0 &&
        RtlCompareMemory(rsn + 10, "\x00\x0f\xac\x04", 4) == 4 &&
        rsn[14] == 1 && rsn[15] == 0 &&
        RtlCompareMemory(rsn + 16, "\x00\x0f\xac\x03", 4) == 4;
}
