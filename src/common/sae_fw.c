/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sae_fw.h"
#include "bcdc.h"

static UINT32 Ap6256SaeFwLe32(const UCHAR* p)
{
    return (UINT32)p[0] | ((UINT32)p[1] << 8) |
        ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static UINT16 Ap6256SaeFwLe16(const UCHAR* p)
{
    return (UINT16)((UINT16)p[0] | ((UINT16)p[1] << 8));
}

static VOID Ap6256SaeFwPut16(UCHAR* p, UINT16 Value)
{
    p[0] = (UCHAR)Value; p[1] = (UCHAR)(Value >> 8);
}

static VOID Ap6256SaeFwPut32(UCHAR* p, UINT32 Value)
{
    Ap6256SaeFwPut16(p, (UINT16)Value);
    Ap6256SaeFwPut16(p + 2, (UINT16)(Value >> 16));
}

_Use_decl_annotations_
BOOLEAN Ap6256SaePrivateOwner(const UCHAR* Body, ULONG Length,
    UINT32* Generation, UCHAR* Peer)
{
    *Generation = 0;
    RtlZeroMemory(Peer, 6);
    if (Length < 16 || Ap6256SaeFwLe32(Body) != AP6256_SAE_OWNER_MAGIC ||
        !Ap6256SaeFwLe32(Body + 4) || Ap6256SaeFwLe16(Body + 14) != 1 ||
        (Body[8] & 1) || RtlEqualMemory(Body + 8, "\0\0\0\0\0\0", 6))
        return FALSE;
    *Generation = Ap6256SaeFwLe32(Body + 4);
    RtlCopyMemory(Peer, Body + 8, 6);
    return TRUE;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaePrivateQuery(PAP6256_DEVICE_CONTEXT Ctx,
    AP6256_SAE_PRIVATE_STATE* State)
{
    UCHAR bytes[40] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    AP6256_SAE_PRIVATE_STATE state = {0};
    NTSTATUS status;
    RtlZeroMemory(State, sizeof(*State));
    if (!Ctx->FirmwareSaePatchVerified) return STATUS_NOT_SUPPORTED;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "ap_sae", bytes, sizeof(bytes), &result);
    if (!NT_SUCCESS(status)) return status;

    if (!result.FirmwareReply || result.FirmwareError || result.FirmwareStatus != 0 ||
        result.PayloadLength < sizeof(bytes) ||
        Ap6256SaeFwLe32(bytes) != AP6256_SAE_PRIVATE_MAGIC ||
        Ap6256SaeFwLe16(bytes + 4) != 1 || Ap6256SaeFwLe16(bytes + 6) != 40 ||
        Ap6256SaeFwLe32(bytes + 8) != AP6256_SAE_BODY_MAX) {
        TraceDiag("SAE: private GET invalid reply; reply %u error %u firmware %d "
            "bytes %u magic 0x%08X version %u size %u max-body %u\n",
            result.FirmwareReply, result.FirmwareError, result.FirmwareStatus,
            result.PayloadLength, Ap6256SaeFwLe32(bytes), Ap6256SaeFwLe16(bytes + 4),
            Ap6256SaeFwLe16(bytes + 6), Ap6256SaeFwLe32(bytes + 8));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    state.Features = Ap6256SaeFwLe32(bytes + 12);
    state.Generation = Ap6256SaeFwLe32(bytes + 16);
    state.Phase = Ap6256SaeFwLe32(bytes + 20);
    state.Transmits = Ap6256SaeFwLe32(bytes + 24);
    state.Receives = Ap6256SaeFwLe32(bytes + 28);
    state.Group = Ap6256SaeFwLe16(bytes + 32);
    state.Observations = Ap6256SaeFwLe16(bytes + 34);
    state.Mode = Ap6256SaeFwLe32(bytes + 36);
    if ((state.Features & ~AP6256_SAE_PRIVATE_FEATURE) != 0 ||
        (state.Phase > AP6256_SAE_PRIVATE_CACHED && state.Phase != AP6256_SAE_PRIVATE_FAILED) ||
        (state.Phase != AP6256_SAE_PRIVATE_IDLE && !state.Generation) ||
        state.Transmits > AP6256_SAE_TX_LIMIT || state.Receives > 16 ||
        (state.Group && (state.Group < 19 || state.Group > 21)) ||
        state.Observations > 3 || state.Mode > 3 ||
        (state.Phase == AP6256_SAE_PRIVATE_IDLE &&
            (state.Transmits || state.Receives || state.Group || state.Observations || state.Mode)))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    *State = state;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256SaePrivateWrite(PAP6256_DEVICE_CONTEXT Ctx,
    UINT16 Operation, UINT32 Generation, const UCHAR* Peer, UINT32 TimeoutMs,
    UINT16 Flags, const UCHAR* Body, ULONG Length)
{
    UCHAR bytes[32 + AP6256_SAE_BODY_MAX] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    if (!Ctx->FirmwareSaePatchVerified || !Ctx->FirmwarePrivateSaeAbi)
        return STATUS_NOT_SUPPORTED;
    if (!Generation || Peer == NULL || (Peer[0] & 1) || Length > AP6256_SAE_BODY_MAX ||
        (Length && Body == NULL) || RtlEqualMemory(Peer, "\0\0\0\0\0\0", 6))
        return STATUS_INVALID_PARAMETER;
    Ap6256SaeFwPut32(bytes, AP6256_SAE_PRIVATE_MAGIC);
    Ap6256SaeFwPut16(bytes + 4, 1);
    Ap6256SaeFwPut16(bytes + 6, Operation);
    Ap6256SaeFwPut32(bytes + 8, 32 + Length);
    Ap6256SaeFwPut32(bytes + 12, Generation);
    RtlCopyMemory(bytes + 16, Peer, 6);
    Ap6256SaeFwPut16(bytes + 22, Flags);
    Ap6256SaeFwPut16(bytes + 24, (UINT16)Length);
    Ap6256SaeFwPut32(bytes + 28, TimeoutMs);
    if (Length) RtlCopyMemory(bytes + 32, Body, Length);
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "ap_sae", bytes, 32 + Length, &result);
    if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError || result.FirmwareStatus != 0) {
        TraceDiag("SAE: private SET op %u generation %u status 0x%08X reply %u "
            "error %u firmware %d\n", Operation, Generation, status,
            result.FirmwareReply, result.FirmwareError, result.FirmwareStatus);
        if (!NT_SUCCESS(status)) return status;
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaePrivateArm(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Generation,
    const UCHAR* Peer, UINT32 TimeoutMs, const UCHAR* Pmkid, BOOLEAN CachedH2e)
{
    AP6256_SAE_PRIVATE_STATE state;
    NTSTATUS status;
    if (!Ctx->FirmwarePrivateSae) return STATUS_NOT_SUPPORTED;
    if (TimeoutMs < 1000 || TimeoutMs > 30000 || (CachedH2e && Pmkid == NULL))
        return STATUS_INVALID_PARAMETER;
    status = Ap6256SaePrivateWrite(Ctx, Pmkid != NULL ? 6 : 1, Generation,
        Peer, TimeoutMs, CachedH2e ? 2u : 0u, Pmkid, Pmkid != NULL ? 16 : 0);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SaePrivateQuery(Ctx, &state);
    if (!NT_SUCCESS(status)) return status;
    if (!(state.Features & AP6256_SAE_PRIVATE_FEATURE) || state.Generation != Generation ||
        state.Phase != (Pmkid != NULL ? AP6256_SAE_PRIVATE_CACHED : AP6256_SAE_PRIVATE_ARMED) ||
        state.Mode != (Pmkid != NULL ? (CachedH2e ? 3u : 1u) : 0u) ||
        state.Transmits || state.Receives || state.Group || state.Observations)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaePrivateCommand(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Operation,
    UINT32 Generation, const UCHAR* Peer, const UCHAR* Body, ULONG Length)
{
    if (Operation < AP6256_SAE_PRIVATE_TX || Operation > AP6256_SAE_PRIVATE_CLEAR ||
        (Operation == AP6256_SAE_PRIVATE_TX ? Length < 8 : Length != 0))
        return STATUS_INVALID_PARAMETER;
    if ((Operation == AP6256_SAE_PRIVATE_TX || Operation == AP6256_SAE_PRIVATE_ACCEPT) &&
        !Ctx->FirmwarePrivateSae) return STATUS_NOT_SUPPORTED;
    return Ap6256SaePrivateWrite(Ctx, Operation, Generation, Peer, 0, 0, Body, Length);
}

_Use_decl_annotations_
NTSTATUS Ap6256SaePrivateEnd(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Generation,
    const UCHAR* Peer, BOOLEAN Associated)
{
    AP6256_SAE_PRIVATE_STATE state;
    NTSTATUS status;
    if (!Generation || Peer == NULL) return STATUS_INVALID_PARAMETER;
    status = Ap6256SaePrivateQuery(Ctx, &state);
    if (!NT_SUCCESS(status)) return status;
    if (state.Phase == AP6256_SAE_PRIVATE_IDLE) return STATUS_SUCCESS;
    if (state.Generation != Generation) return STATUS_DEVICE_BUSY;
    status = Ap6256SaePrivateCommand(Ctx, Associated ? AP6256_SAE_PRIVATE_CLEAR :
        AP6256_SAE_PRIVATE_ABORT, Generation, Peer, NULL, 0);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SaePrivateQuery(Ctx, &state);
    if (!NT_SUCCESS(status)) return status;
    if (state.Generation != Generation || state.Phase != AP6256_SAE_PRIVATE_IDLE)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN Ap6256SaePrivateFrame(const UCHAR* Body, ULONG Length,
    const UCHAR* Local, const UCHAR* Peer, UINT32* Generation, ULONG* FrameLength)
{
    const UCHAR* frame;
    ULONG size;
    *Generation = 0; *FrameLength = 0;
    if (Length < 12 + 30 || Length > 12 + AP6256_SAE_FRAME_MAX ||
        Ap6256SaeFwLe32(Body) != AP6256_SAE_PRIVATE_MAGIC ||
        Ap6256SaeFwLe16(Body + 10) != 0 || !Ap6256SaeFwLe32(Body + 4)) return FALSE;
    size = Ap6256SaeFwLe16(Body + 8);
    frame = Body + 12;
    if (size != Length - 12 || (Ap6256SaeFwLe16(frame) & 0xc7ff) != 0x00b0 ||
        (Ap6256SaeFwLe16(frame + 22) & 15) != 0 ||
        Ap6256SaeFwLe16(frame + 24) != 3 ||
        (Ap6256SaeFwLe16(frame + 26) != 1 && Ap6256SaeFwLe16(frame + 26) != 2) ||
        !RtlEqualMemory(frame + 4, Local, 6) ||
        !RtlEqualMemory(frame + 10, Peer, 6) || !RtlEqualMemory(frame + 16, Peer, 6))
        return FALSE;
    *Generation = Ap6256SaeFwLe32(Body + 4); *FrameLength = size;
    return TRUE;
}

static BOOLEAN Ap6256SaeFwToken(const CHAR* Caps, ULONG Length,
    const CHAR* Token, ULONG TokenLength)
{
    ULONG i;
    for (i = 0; i < Length && Caps[i] != '\0'; ++i) {
        if (TokenLength < Length - i && (i == 0 || Caps[i - 1] == ' ') &&
            RtlEqualMemory(Caps + i, Token, TokenLength) &&
            (Caps[i + TokenLength] == ' ' || Caps[i + TokenLength] == '\0'))
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN Ap6256SaeFwMaskValid(const UCHAR* Mask,
    const AP6256_BCDC_QUERY_RESULT* Result, NTSTATUS Status)
{
    return NT_SUCCESS(Status) && Result->FirmwareReply && !Result->FirmwareError &&
        Result->PayloadLength >= 4 && Mask[2] >= 24 && Mask[2] <= 128 &&
        Mask[2] <= Result->PayloadLength - 4;
}

_Use_decl_annotations_
VOID Ap6256SaeFirmwarePrepare(PAP6256_DEVICE_CONTEXT Ctx)
{
    CHAR caps[512] = {0};
    UCHAR mask[132] = {1, 0, 128, 128}, wanted[128];
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    ULONG length, i;
    Ctx->FirmwareExternalAuth = FALSE;
    Ctx->FirmwarePrivateSaeAbi = FALSE;
    Ctx->FirmwarePrivateSae = FALSE;
    if (Ctx->FirmwareSaePatchVerified) {
        AP6256_SAE_PRIVATE_STATE state;
        UCHAR authMask[128] = {0};
        status = Ap6256SaePrivateQuery(Ctx, &state);
        if (NT_SUCCESS(status)) {
            Ctx->FirmwarePrivateSaeAbi = TRUE;
            status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs", authMask,
                sizeof(authMask), &result);
            if ((state.Features & AP6256_SAE_PRIVATE_FEATURE) &&
                Ctx->FirmwareMfpSupported && NT_SUCCESS(status) && result.FirmwareReply &&
                !result.FirmwareError && result.FirmwareStatus == 0 &&
                result.PayloadLength >= 1 && (authMask[0] & (1u << 3)))
                Ctx->FirmwarePrivateSae = TRUE;
            TraceDiag("SAE: exact-image private ABI verified; transport feature %u\n",
                Ctx->FirmwarePrivateSae ? 1u : 0u);
        } else {
            TraceDiag("SAE: exact-image private ABI query failed 0x%08X\n", status);
        }
    }
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "cap", caps, sizeof(caps), &result);
    if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError ||
        !Ap6256SaeFwToken(caps, min(result.PayloadLength, sizeof(caps)), "sae_ext", 7) ||
        !Ap6256SaeFwToken(caps, min(result.PayloadLength, sizeof(caps)), "mfp", 3)) {

        TraceDiag("SAE: capability tokens absent; probing native external authentication events\n");
    }
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs_ext", mask, sizeof(mask), &result);
    if (!Ap6256SaeFwMaskValid(mask, &result, status)) return;
    length = mask[2];
    for (i = AP6256_CYW_EXT_AUTH_REQ; i <= AP6256_CYW_MGMT_OFFCHAN_DONE; ++i)
        mask[4 + i / 8] |= (UCHAR)(1u << (i & 7));
    RtlCopyMemory(wanted, mask + 4, length);

    mask[0] = 1; mask[1] = 3; mask[3] = 0;
    status = Ap6256BcdcSetIovar(Ctx, "event_msgs_ext", mask, 4 + length);
    if (!NT_SUCCESS(status)) return;
    RtlZeroMemory(mask, sizeof(mask));
    mask[0] = 1; mask[2] = 128; mask[3] = 128;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs_ext", mask, sizeof(mask), &result);
    if (!Ap6256SaeFwMaskValid(mask, &result, status) || mask[2] < length) return;
    for (i = 0; i < length; ++i) {
        if ((mask[4 + i] & wanted[i]) != wanted[i]) return;
    }
    Ctx->FirmwareExternalAuth = TRUE;
    TraceDiag("SAE: CYW external authentication events verified\n");
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeSetBip(PAP6256_DEVICE_CONTEXT Ctx)
{

    const UCHAR selector[] = {0x00, 0x0f, 0xac, 0x06};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    if (!Ctx->FirmwarePrivateSae || !Ctx->FirmwareMfpSupported)
        return STATUS_NOT_SUPPORTED;
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "bip", selector, sizeof(selector), &result);
    if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError || result.FirmwareStatus != 0) {
        TraceDiag("SAE: BIP configuration status 0x%08X reply %u error %u firmware %d\n",
            status, result.FirmwareReply, result.FirmwareError, result.FirmwareStatus);
        if (!NT_SUCCESS(status)) return status;
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    TraceDiag("SAE: native BIP-CMAC-128 configured before authentication\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeVerifySecurity(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Wsec,
    BOOLEAN CachedPmkid)
{
    const UINT32 commands[] = {BRCMF_C_GET_AUTH, BRCMF_C_GET_WPA_AUTH,
        BRCMF_C_GET_WSEC, BRCMF_C_GET_INFRA};
    const UINT32 expected[] = {
        Ctx->FirmwarePrivateSae || CachedPmkid ? 0u : 3u,
        Ctx->FirmwarePrivateSae ? 0x00008000u : 0x00040000u, Wsec, 1};
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(commands); ++i) {
        UINT32 value = 0;
        AP6256_BCDC_QUERY_RESULT result = {0};
        NTSTATUS status = Ap6256BcdcQueryDcmdResultIf(Ctx, 0, commands[i],
            &value, sizeof(value), &result);
        if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError ||
            result.FirmwareStatus != 0 || result.PayloadLength < sizeof(value) ||
            value != expected[i]) {
            TraceDiag("SAE: security GET cmd %u status 0x%08X reply %u error %u "
                "firmware %d bytes %u expected 0x%08X got 0x%08X\n",
                commands[i], status, result.FirmwareReply, result.FirmwareError,
                result.FirmwareStatus, result.PayloadLength, expected[i], value);
            if (!NT_SUCCESS(status)) return status;
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }
    {
        UINT32 mfp = 0;
        AP6256_BCDC_QUERY_RESULT result = {0};
        NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "mfp", &mfp, sizeof(mfp), &result);
        if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError ||
            result.FirmwareStatus != 0 || result.PayloadLength < sizeof(mfp) || mfp != 2) {
            TraceDiag("SAE: security GET mfp status 0x%08X reply %u error %u "
                "firmware %d bytes %u expected 2 got %u\n",
                status, result.FirmwareReply, result.FirmwareError,
                result.FirmwareStatus, result.PayloadLength, mfp);
            if (!NT_SUCCESS(status)) return status;
            return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }
    TraceDiag("SAE: security readback verified; wsec 0x%08X, required PMF\n", Wsec);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeSetPmkid(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Peer, const UCHAR* Pmkid)
{

    UCHAR wanted[28] = {0}, got[28] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    if (Pmkid != NULL) {
        wanted[0] = 1;
        RtlCopyMemory(wanted + 4, Peer, 6);
        RtlCopyMemory(wanted + 10, Pmkid, 16);
    }
    status = Ap6256BcdcSetIovar(Ctx, "pmkid_info", wanted, sizeof(wanted));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "pmkid_info", got, sizeof(got), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < (Pmkid != NULL ? 26u : 4u) ||
        Ap6256SaeFwLe32(got) != (Pmkid != NULL ? 1u : 0u) ||
        (Pmkid != NULL && !RtlEqualMemory(got + 4, wanted + 4, 22)))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeAuthRequest(const UCHAR* Body, ULONG Length,
    const UCHAR* Peer, const UCHAR* Ssid, ULONG SsidLength, BOOLEAN* Abort)
{
    UINT16 flags;
    *Abort = FALSE;
    if (Length < 60 || SsidLength == 0 || SsidLength > 32) return STATUS_INVALID_PARAMETER;
    if (Ap6256SaeFwLe32(Body + 8) != SsidLength ||
        !RtlEqualMemory(Body + 2, Peer, 6) || !RtlEqualMemory(Body + 12, Ssid, SsidLength))
        return STATUS_NOT_FOUND;
    flags = Ap6256SaeFwLe16(Body);
    if (flags != 1 && flags != 2) return STATUS_INVALID_PARAMETER;
    *Abort = (BOOLEAN)(flags == 2);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeReceiveEvent(AP6256_SAE* Sae, LONG Generation, LONGLONG NowMs,
    const UCHAR* Peer, const UCHAR* Body, ULONG Length, AP6256_SAE_OUTPUT* Output)
{
    UCHAR frame[AP6256_SAE_FRAME_MAX];
    RtlZeroMemory(Output, sizeof(*Output));
    Output->Notice = Ap6256SaeNoNotice;

    if (Length < 16 + 30 || Length > 16 + sizeof(frame)) return STATUS_INVALID_PARAMETER;
    if (!RtlEqualMemory(Peer, Sae->Peer, 6)) return STATUS_NOT_FOUND;
    RtlZeroMemory(frame, sizeof(frame));
    frame[0] = 0xb0;
    RtlCopyMemory(frame + 4, Sae->Local, 6);
    RtlCopyMemory(frame + 10, Peer, 6);
    RtlCopyMemory(frame + 16, Sae->Peer, 6);
    RtlCopyMemory(frame + 24, Body + 16 + 24, Length - 16 - 24);
    return Ap6256SaeReceive(Sae, Generation, NowMs, frame, Length - 16, Output);
}

_Use_decl_annotations_
BOOLEAN Ap6256SaeAssociationRsn(const UCHAR* Body, ULONG Length, BOOLEAN Reassociation)
{
    ULONG offset = Reassociation ? 10u : 4u;
    BOOLEAN found = FALSE;
    while (offset + 2 <= Length) {
        const UCHAR* ie = Body + offset;
        ULONG size = ie[1], pos, count;
        if (size > Length - offset - 2) return FALSE;
        if (ie[0] == 48) {
            const UCHAR* rsn = ie + 2;
            if (found || size < 8 || Ap6256SaeFwLe16(rsn) != 1) return FALSE;
            found = TRUE;

            if (!RtlEqualMemory(rsn + 2, "\x00\x0f\xac\x04", 4)) return FALSE;
            count = Ap6256SaeFwLe16(rsn + 6);
            if (count != 1 || size < 12 ||
                !RtlEqualMemory(rsn + 8, "\x00\x0f\xac\x04", 4)) return FALSE;
            pos = 12;
            if (size - pos < 2) return FALSE;
            count = Ap6256SaeFwLe16(rsn + pos); pos += 2;
            if (count != 1 || size - pos < 6 ||
                !RtlEqualMemory(rsn + pos, "\x00\x0f\xac\x08", 4)) return FALSE;
            pos += 4;
            if ((Ap6256SaeFwLe16(rsn + pos) & 0x00c0) != 0x00c0) return FALSE;
        }
        offset += 2 + size;
    }
    return found && offset == Length;
}

_Use_decl_annotations_
BOOLEAN Ap6256SaeAssociationPmkid(const UCHAR* Body, ULONG Length,
    BOOLEAN Reassociation, const UCHAR* Pmkid)
{
    ULONG offset = Reassociation ? 10u : 4u;
    if (!Ap6256SaeAssociationRsn(Body, Length, Reassociation)) return FALSE;
    while (offset + 2 <= Length) {
        const UCHAR* ie = Body + offset;
        ULONG size = ie[1];

        if (ie[0] == 48) return size >= 38 &&
            Ap6256SaeFwLe16(ie + 22) == 1 &&
            RtlEqualMemory(ie + 24, Pmkid, 16);
        offset += 2 + size;
    }
    return FALSE;
}

_Use_decl_annotations_
BOOLEAN Ap6256SaeAssociationH2e(const UCHAR* Body, ULONG Length,
    BOOLEAN Reassociation, BOOLEAN H2e)
{
    ULONG offset = Reassociation ? 10u : 4u;
    BOOLEAN present, actualH2e;
    if (Length < offset) return FALSE;
    return (BOOLEAN)(NT_SUCCESS(Ap6256SaeReadRsnxe(Body + offset, Length - offset,
        &present, &actualH2e)) && actualH2e == H2e && (!H2e || present));
}
