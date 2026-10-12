/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "owe.h"
#include "host_cipher_rsn.h"
#include "bcdc.h"

static UINT16 Owe16(const UCHAR* p) { return (UINT16)(p[0] | ((UINT16)p[1] << 8)); }
static UINT32 Owe32(const UCHAR* p) { return Owe16(p) | ((UINT32)Owe16(p + 2) << 16); }
static VOID OwePut16(UCHAR* p, UINT16 n) { p[0] = (UCHAR)n; p[1] = (UCHAR)(n >> 8); }
static VOID OwePut32(UCHAR* p, UINT32 n) { OwePut16(p, (UINT16)n); OwePut16(p + 2, (UINT16)(n >> 16)); }
static BOOLEAN OwePeer(const UCHAR* p) {
    static const UCHAR zero[6] = {0};
    return (BOOLEAN)(p != NULL && !(p[0] & 1) && !RtlEqualMemory(p, zero, 6));
}

_Use_decl_annotations_
BOOLEAN Ap6256OweDhValid(const UCHAR* Ie, ULONG Length)
{
    ULONG group, size;
    if (Ie == NULL || Length < 5 || Length > AP6256_OWE_DH_MAX ||
        Ie[0] != 255 || Ie[1] + 2u != Length || Ie[2] != 32) return FALSE;
    group = Owe16(Ie + 3);
    size = group == 19 ? 32u : (group == 20 ? 48u : (group == 21 ? 66u : 0u));
    return (BOOLEAN)(size && Length == 5u + size);
}

static BOOLEAN OweExtraValid(const UCHAR* p, ULONG n)
{
    if (n > AP6256_OWE_EXTRA_MAX || (n && p == NULL)) return FALSE;
    while (n) {
        ULONG size;
        if (n < 2 || (size = p[1] + 2u) > n || p[0] == 48 ||
            (p[0] == 255 && size >= 3 && p[2] == 32)) return FALSE;
        p += size; n -= size;
    }
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS Ap6256OweCopyIes(const UCHAR* Dh, ULONG DhLength,
    const UCHAR* Common, ULONG CommonLength, const UCHAR* Bss, ULONG BssLength,
    AP6256_CONNECT_PARAMS* Params)
{
    if (!Ap6256OweDhValid(Dh, DhLength) || !OweExtraValid(Common, CommonLength) ||
        !OweExtraValid(Bss, BssLength) || BssLength > AP6256_OWE_EXTRA_MAX - CommonLength)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Params->OweDh, sizeof(Params->OweDh));
    RtlZeroMemory(Params->OweExtra, sizeof(Params->OweExtra));
    RtlCopyMemory(Params->OweDh, Dh, DhLength);
    if (CommonLength && Common != NULL) RtlCopyMemory(Params->OweExtra, Common, CommonLength);
    if (BssLength && Bss != NULL) RtlCopyMemory(Params->OweExtra + CommonLength, Bss, BssLength);
    Params->OweDhLength = DhLength;
    Params->OweExtraLength = CommonLength + BssLength;
    return STATUS_SUCCESS;
}

typedef struct _OWE_IES {
    const UCHAR* Rsn;
    const UCHAR* Dh;
    ULONG RsnLength, DhLength, DhRemaining;
} OWE_IES;

static BOOLEAN OweFind(const UCHAR* p, ULONG n, OWE_IES* found)
{
    RtlZeroMemory(found, sizeof(*found));
    if (n && p == NULL) return FALSE;
    while (n) {
        ULONG size;
        if (n < 2 || (size = p[1] + 2u) > n) return FALSE;
        if (p[0] == 48) {
            if (found->Rsn != NULL) return FALSE;
            found->Rsn = p; found->RsnLength = size;
        }
        if (p[0] == 255 && size >= 3 && p[2] == 32) {
            if (found->Dh != NULL) return FALSE;
            found->Dh = p; found->DhLength = size; found->DhRemaining = n;
        }
        p += size; n -= size;
    }
    return TRUE;
}

static BOOLEAN OweRsn(const OWE_IES* ies, BOOLEAN Request, BOOLEAN HostCipher,
    const UCHAR* Pmkid, BOOLEAN* Matched)
{
    const UCHAR* p = ies->Rsn;
    ULONG n = ies->RsnLength, off = 10, count, i;
    BOOLEAN ccmp = FALSE, owe = FALSE;
    *Matched = FALSE;
    if (HostCipher) {
        AP6256_HC_RSN rsn;
        if (!Ap6256HostCipherRsnRead(p, n, &rsn) || !Ap6256HostCipherRsnMatch(&rsn, 18, 2, Request ? 1 : 0))
            return FALSE;
        if (Pmkid) *Matched = (BOOLEAN)Ap6256HostCipherRsnPmkid(&rsn, Pmkid, Request ? 1 : 0);
        return (BOOLEAN)(!Request || (Pmkid ? *Matched : rsn.PmkidCount == 0));
    }
    if (p == NULL || n < 22 || Owe16(p + 2) != 1 ||
        !RtlEqualMemory(p + 4, "\x00\x0f\xac\x04", 4)) return FALSE;
    count = Owe16(p + 8);
    if (!count || count > (n - off) / 4 || (Request && count != 1)) return FALSE;
    for (i = 0; i < count; ++i, off += 4)
        if (RtlEqualMemory(p + off, "\x00\x0f\xac\x04", 4)) ccmp = TRUE;
    if (off + 2 > n) return FALSE;
    count = Owe16(p + off); off += 2;
    if (!count || count > (n - off) / 4 || (Request && count != 1)) return FALSE;
    for (i = 0; i < count; ++i, off += 4)
        if (RtlEqualMemory(p + off, "\x00\x0f\xac\x12", 4)) owe = TRUE;
    if (!ccmp || !owe || off + 2 > n || !(Owe16(p + off) & 0x80) ||
        (Request && (Owe16(p + off) & 0xc0) != 0xc0)) return FALSE;
    off += 2;
    count = 0;
    if (off != n) {
        if (off + 2 > n) return FALSE;
        count = Owe16(p + off); off += 2;
        if (count > (n - off) / 16 || (Request && count != (Pmkid != NULL ? 1u : 0u)))
            return FALSE;
        for (i = 0; i < count; ++i, off += 16)
            if (Pmkid != NULL && RtlEqualMemory(p + off, Pmkid, 16)) *Matched = TRUE;
        if (off != n && (n - off != 4 ||
            !RtlEqualMemory(p + off, "\x00\x0f\xac\x06", 4))) return FALSE;
    }
    return (BOOLEAN)(!Request || Pmkid == NULL || *Matched);
}

_Use_decl_annotations_
BOOLEAN Ap6256OweRequestValid(const AP6256_CONNECT_PARAMS* Params,
    const AP6256_ASSOC_FRAMES* Frames)
{
    OWE_IES req;
    ULONG fixed = Frames->ReAssociation ? 10u : 4u;
    BOOLEAN matched;
    if (Params->Security != Ap6256SecurityOweHost ||
        !Ap6256OweDhValid(Params->OweDh, Params->OweDhLength) ||
        !OweExtraValid(Params->OweExtra, Params->OweExtraLength) ||
        Frames->AssocRequest == NULL || Frames->AssocRequestLength < fixed ||
        !OweFind(Frames->AssocRequest + fixed, Frames->AssocRequestLength - fixed, &req) ||
        !OweRsn(&req, TRUE, Params->HostCipher, Params->PmkidValid ? Params->Pmkid : NULL, &matched) ||
        req.Dh == NULL || req.DhLength != Params->OweDhLength ||
        !RtlEqualMemory(req.Dh, Params->OweDh, Params->OweDhLength) ||
        Params->OweExtraLength > req.DhRemaining - req.DhLength ||
        !RtlEqualMemory(req.Dh + req.DhLength, Params->OweExtra, Params->OweExtraLength))
        return FALSE;
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN Ap6256OweAssociationValid(const AP6256_CONNECT_PARAMS* Params,
    const AP6256_ASSOC_FRAMES* Frames)
{
    OWE_IES resp;
    BOOLEAN responseMatch;
    if (!Ap6256OweRequestValid(Params, Frames) ||
        Frames->AssocResponse == NULL || Frames->AssocResponseLength < 6 ||
        Owe16(Frames->AssocResponse + 2) != 0 ||
        !OweFind(Frames->AssocResponse + 6, Frames->AssocResponseLength - 6, &resp) ||
        !OweRsn(&resp, FALSE, Params->HostCipher, Params->PmkidValid ? Params->Pmkid : NULL, &responseMatch)) return FALSE;

    return (BOOLEAN)(responseMatch || (Ap6256OweDhValid(resp.Dh, resp.DhLength) &&
        Owe16(resp.Dh + 3) == Owe16(Params->OweDh + 3)));
}

_Use_decl_annotations_
NTSTATUS Ap6256OweBuildCommand(UINT16 Operation, UINT32 Generation,
    const AP6256_CONNECT_PARAMS* Params, UCHAR* Bytes, ULONG Capacity, ULONG* Length)
{
    ULONG dh = Operation == 1 ? Params->OweDhLength : 0;
    ULONG extra = Operation == 1 ? Params->OweExtraLength : 0;
    ULONG pmkid = Operation == 1 && Params->PmkidValid ? 16u : 0u;
    *Length = 0;
    if (Operation < 1 || Operation > 3 || !Generation || !Params->BssidValid ||
        !OwePeer(Params->Bssid) || (Operation == 1 &&
        (!Ap6256OweDhValid(Params->OweDh, dh) || !OweExtraValid(Params->OweExtra, extra))))
        return STATUS_INVALID_PARAMETER;
    if (Capacity < 40 + dh + extra + pmkid) return STATUS_BUFFER_TOO_SMALL;
    RtlZeroMemory(Bytes, 40 + dh + extra + pmkid);
    OwePut16(Bytes, 1); OwePut16(Bytes + 2, Operation);
    OwePut32(Bytes + 4, 40 + dh + extra + pmkid); OwePut32(Bytes + 8, Generation);
    RtlCopyMemory(Bytes + 16, Params->Bssid, 6);
    OwePut16(Bytes + 22, (UINT16)dh); OwePut16(Bytes + 24, (UINT16)extra);
    OwePut16(Bytes + 26, (UINT16)pmkid);
    if (dh) RtlCopyMemory(Bytes + 40, Params->OweDh, dh);
    if (extra) RtlCopyMemory(Bytes + 40 + dh, Params->OweExtra, extra);
    if (pmkid) RtlCopyMemory(Bytes + 40 + dh + extra, Params->Pmkid, pmkid);
    *Length = 40 + dh + extra + pmkid;
    return STATUS_SUCCESS;
}

typedef struct _OWE_STATE { UINT32 Phase, Generation, Last; UCHAR Peer[6]; } OWE_STATE;
static BOOLEAN OweReply(const AP6256_BCDC_QUERY_RESULT* r, ULONG length)
{
    return (BOOLEAN)(r->FirmwareReply && !r->FirmwareError && r->FirmwareStatus == 0 &&
        r->PayloadLength >= length);
}

static NTSTATUS OweQuery(PAP6256_DEVICE_CONTEXT Ctx, OWE_STATE* State)
{
    UCHAR bytes[36] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    RtlZeroMemory(State, sizeof(*State));
    if (!Ctx->FirmwareOwePatchVerified) return STATUS_NOT_SUPPORTED;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "hostowe", bytes, sizeof(bytes), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!OweReply(&result, sizeof(bytes)) || Owe32(bytes) != 0x3145574fu ||
        Owe16(bytes + 4) != 1 || Owe16(bytes + 6) != 40 ||
        Owe32(bytes + 8) != AP6256_OWE_DH_MAX || Owe32(bytes + 12) != AP6256_OWE_EXTRA_MAX ||
        Owe32(bytes + 16) > 2 || Owe16(bytes + 34)) return STATUS_DEVICE_PROTOCOL_ERROR;
    State->Phase = Owe32(bytes + 16); State->Generation = Owe32(bytes + 20);
    State->Last = Owe32(bytes + 24); RtlCopyMemory(State->Peer, bytes + 28, 6);
    if (State->Phase ? (!State->Generation || State->Generation != State->Last || !OwePeer(State->Peer)) :
        (State->Generation || !RtlEqualMemory(State->Peer, "\0\0\0\0\0\0", 6)))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256OweFirmwareQualify(PAP6256_DEVICE_CONTEXT Ctx)
{
    OWE_STATE state;
    NTSTATUS status = OweQuery(Ctx, &state);
    Ctx->FirmwareHostOwe = FALSE;
    if (!NT_SUCCESS(status)) return status;
    if (state.Phase || state.Last) return STATUS_DEVICE_PROTOCOL_ERROR;
    Ctx->FirmwareHostOwe = Ctx->FirmwareMfpSupported;
    TraceDiag("OWE: exact-image public-IE ABI verified; Windows DH, board CCMP/PMF\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256OweVerifySecurity(PAP6256_DEVICE_CONTEXT Ctx)
{
    const UINT32 commands[] = {BRCMF_C_GET_AUTH, BRCMF_C_GET_WPA_AUTH,
        BRCMF_C_GET_WSEC, BRCMF_C_GET_INFRA};
    const UINT32 wanted[] = {0, 0x80, 0xe04, 1};
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(commands); ++i) {
        UINT32 value = 0;
        AP6256_BCDC_QUERY_RESULT result = {0};
        NTSTATUS status = Ap6256BcdcQueryDcmdResultIf(Ctx, 0, commands[i], &value, sizeof(value), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!OweReply(&result, sizeof(value)) || value != wanted[i]) return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    for (i = 0; i < 2; ++i) {
        UINT32 value = MAXUINT32;
        AP6256_BCDC_QUERY_RESULT result = {0};
        NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, i ? "supp_wpa" : "mfp",
            &value, sizeof(value), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!OweReply(&result, sizeof(value)) || value != (i ? 0u : 2u))
            return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    {
        UCHAR cipher[4] = {0};
        AP6256_BCDC_QUERY_RESULT result = {0};
        NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "bip", cipher, sizeof(cipher), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!OweReply(&result, sizeof(cipher)) || !RtlEqualMemory(cipher, "\x00\x0f\xac\x06", 4))
            return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256OwePrepareSecurity(PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 supplicant = 0;
    const UCHAR cipher[] = {0, 0x0f, 0xac, 6};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "supp_wpa", &supplicant,
        sizeof(supplicant), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!OweReply(&result, 0)) return STATUS_DEVICE_PROTOCOL_ERROR;
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "bip", cipher, sizeof(cipher), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!OweReply(&result, 0)) return STATUS_DEVICE_PROTOCOL_ERROR;
    return Ap6256OweVerifySecurity(Ctx);
}

static NTSTATUS OweWrite(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Operation,
    UINT32 Generation, const AP6256_CONNECT_PARAMS* Params)
{
    UCHAR bytes[40 + AP6256_OWE_DH_MAX + AP6256_OWE_EXTRA_MAX + 16];
    ULONG length;
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256OweBuildCommand(Operation, Generation, Params, bytes, sizeof(bytes), &length);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "hostowe", bytes, length, &result);
    if (!NT_SUCCESS(status)) return status;
    return OweReply(&result, 0) ? STATUS_SUCCESS : STATUS_DEVICE_PROTOCOL_ERROR;
}

_Use_decl_annotations_
NTSTATUS Ap6256OweArm(PAP6256_DEVICE_CONTEXT Ctx, const AP6256_CONNECT_PARAMS* Params)
{
    OWE_STATE state;
    NTSTATUS status;
    if (!Ctx->FirmwareHostOwe || Ctx->FirmwareOweGeneration ||
        Params->Security != Ap6256SecurityOweHost || Params->Mfp != Ap6256MfpRequired)
        return STATUS_INVALID_DEVICE_STATE;
    status = OweQuery(Ctx, &state);
    if (!NT_SUCCESS(status)) return status;
    if (state.Phase || state.Last > Ctx->FirmwareOweNextGeneration ||
        Ctx->FirmwareOweNextGeneration == MAXUINT32) return STATUS_DEVICE_BUSY;

    Ctx->FirmwareOweGeneration = ++Ctx->FirmwareOweNextGeneration;
    RtlCopyMemory(Ctx->FirmwareOwePeer, Params->Bssid, 6);
    status = OweWrite(Ctx, 1, Ctx->FirmwareOweGeneration, Params);
    if (NT_SUCCESS(status)) status = OweQuery(Ctx, &state);
    if (NT_SUCCESS(status) && (state.Phase != 1 || state.Generation != Ctx->FirmwareOweGeneration ||
        !RtlEqualMemory(state.Peer, Params->Bssid, 6))) status = STATUS_DEVICE_PROTOCOL_ERROR;
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256OweEnd(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Associated)
{
    OWE_STATE state;
    NTSTATUS status;
    AP6256_CONNECT_PARAMS params = {0};
    if (!Ctx->FirmwareOweGeneration) return STATUS_SUCCESS;
    status = OweQuery(Ctx, &state);
    if (!NT_SUCCESS(status)) return status;
    if (state.Phase) {
        if (state.Generation != Ctx->FirmwareOweGeneration ||
            !RtlEqualMemory(state.Peer, Ctx->FirmwareOwePeer, 6)) return STATUS_DEVICE_BUSY;
        params.BssidValid = TRUE; RtlCopyMemory(params.Bssid, state.Peer, 6);
        status = OweWrite(Ctx, Associated ? 3u : 2u, state.Generation, &params);
        if (NT_SUCCESS(status)) status = OweQuery(Ctx, &state);
        if (!NT_SUCCESS(status)) return status;
        if (state.Phase) return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    Ctx->FirmwareOweGeneration = 0;
    RtlZeroMemory(Ctx->FirmwareOwePeer, sizeof(Ctx->FirmwareOwePeer));
    return STATUS_SUCCESS;
}
