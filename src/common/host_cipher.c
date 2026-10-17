/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher.h"
#include "sdio.h"
#include <bcrypt.h>

#ifndef AP6256_HOST_CIPHER_CANDIDATE
#define AP6256_HOST_CIPHER_CANDIDATE 0
#endif

#if AP6256_HOST_CIPHER_CANDIDATE
#include "host_cipher_patch.h"
#include "native_departure_patch.h"

typedef struct _AP6256_HC_PATCH {
    ULONG Offset, Length, DataOffset;
} AP6256_HC_PATCH;
static const AP6256_HC_PATCH Ap6256HcPatches[] = {
    AP6256_HC_PATCH_ENTRIES
};

static const AP6256_HC_PATCH Ap6256NdPatches[] = {
    AP6256_ND_PATCH_ENTRIES
};

static NTSTATUS Ap6256HcHash(_In_reads_bytes_(Length) const UCHAR* Image,
    _In_ ULONG Length, _In_reads_(32) const UCHAR Expected[32])
{
    UCHAR digest[32];
    NTSTATUS status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0,
        (PUCHAR)Image, Length, digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    return RtlEqualMemory(digest, Expected, sizeof(digest)) ?
        STATUS_SUCCESS : STATUS_REVISION_MISMATCH;
}

static BOOLEAN Ap6256HcExactChip(PAP6256_DEVICE_CONTEXT Ctx, ULONG Length)
{
    return Ctx->Chip.ChipId == 0x4345 && Ctx->Chip.ChipRev == 9 &&
        Ctx->Chip.RamBase == 0x198000 && Ctx->Chip.RamSize == 0xc8000 &&
        Length == AP6256_HC_IMAGE_SIZE;
}
#endif

_Use_decl_annotations_
NTSTATUS Ap6256PrepareHostCiphers(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR* Image, PULONG Length, BOOLEAN* Applied)
{
    if (Ctx == NULL || Image == NULL || Length == NULL || Applied == NULL)
        return STATUS_INVALID_PARAMETER;
    *Applied = FALSE;
#if AP6256_HOST_CIPHER_CANDIDATE
    UCHAR digest[32];
    PUCHAR copy;
    ULONG i;
    NTSTATUS status;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9)
        return STATUS_SUCCESS;
    if (*Image == NULL || !Ap6256HcExactChip(Ctx, *Length))
        return STATUS_REVISION_MISMATCH;
    status = Ap6256HcHash(*Image, *Length, Ap6256HcInputSha256);
    if (!NT_SUCCESS(status)) return status;
    for (i = 0; i < RTL_NUMBER_OF(Ap6256HcPatches); ++i) {
        const AP6256_HC_PATCH* patch = &Ap6256HcPatches[i];
        if (patch->Offset > *Length || patch->Length > *Length - patch->Offset ||
            patch->DataOffset > sizeof(Ap6256HcPatchBytes) ||
            patch->Length > sizeof(Ap6256HcPatchBytes) - patch->DataOffset)
            return STATUS_REVISION_MISMATCH;
    }
    copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, *Length, AP6256_POOL_TAG);
    if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(copy, *Image, *Length);
    for (i = 0; i < RTL_NUMBER_OF(Ap6256HcPatches); ++i) {
        const AP6256_HC_PATCH* patch = &Ap6256HcPatches[i];
        RtlCopyMemory(copy + patch->Offset,
            Ap6256HcPatchBytes + patch->DataOffset, patch->Length);
    }
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, copy, *Length,
        digest, sizeof(digest));
    if (NT_SUCCESS(status) && (!RtlEqualMemory(digest, Ap6256HcOutputSha256,
        sizeof(digest)) || !RtlEqualMemory(digest, Ap6256NdInputSha256,
        sizeof(digest)))) status = STATUS_DATA_ERROR;
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(copy, AP6256_POOL_TAG);
        return status;
    }
    for (i = 0; i < RTL_NUMBER_OF(Ap6256NdPatches); ++i) {
        const AP6256_HC_PATCH* patch = &Ap6256NdPatches[i];
        if (patch->Offset > *Length || patch->Length > *Length - patch->Offset ||
            patch->DataOffset > sizeof(Ap6256NdPatchBytes) ||
            patch->Length > sizeof(Ap6256NdPatchBytes) - patch->DataOffset) {
            ExFreePoolWithTag(copy, AP6256_POOL_TAG);
            return STATUS_REVISION_MISMATCH;
        }
        RtlCopyMemory(copy + patch->Offset,
            Ap6256NdPatchBytes + patch->DataOffset, patch->Length);
    }
    status = Ap6256HcHash(copy, *Length, Ap6256NdOutputSha256);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(copy, AP6256_POOL_TAG);
        return status;
    }
    ExFreePoolWithTag(*Image, AP6256_POOL_TAG);
    *Image = copy;
    *Applied = TRUE;
    TraceDiag("host-cipher board-test relay: exact image composed; runtime ABI check pending\n");
#else
    UNREFERENCED_PARAMETER(Image);
    UNREFERENCED_PARAMETER(Length);
#endif
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256VerifyHostCiphers(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Image, ULONG Length)
{
#if AP6256_HOST_CIPHER_CANDIDATE
    ULONG pass;
    NTSTATUS status;
    if (Ctx == NULL || Image == NULL || !Ap6256HcExactChip(Ctx, Length))
        return STATUS_REVISION_MISMATCH;
    status = Ap6256HcHash(Image, Length, Ap6256NdOutputSha256);
    if (!NT_SUCCESS(status)) return status;
    for (pass = 0; pass < RTL_NUMBER_OF(Ap6256HcPatches) + RTL_NUMBER_OF(Ap6256NdPatches); ++pass) {
        const AP6256_HC_PATCH* patch = pass < RTL_NUMBER_OF(Ap6256HcPatches) ?
            &Ap6256HcPatches[pass] : &Ap6256NdPatches[pass - RTL_NUMBER_OF(Ap6256HcPatches)];
        ULONG start = patch->Offset & ~3u;
        ULONG end = (patch->Offset + patch->Length + 3u) & ~3u;
        ULONG offset;
        if (patch->Offset > Length || patch->Length > Length - patch->Offset ||
            end > Length) return STATUS_REVISION_MISMATCH;
        for (offset = start; offset < end; offset += sizeof(UINT32)) {
            UINT32 value = 0;
            status = Ap6256SdioReadBackplane32(Ctx, Ctx->Chip.RamBase + offset, &value);
            if (!NT_SUCCESS(status)) return status;
            if (!RtlEqualMemory(&value, Image + offset, sizeof(value))) {
                TraceDiag("host-cipher relay: TCM mismatch at 0x%08X\n",
                    Ctx->Chip.RamBase + offset);
                return STATUS_DEVICE_DATA_ERROR;
            }
        }
    }
    TraceDiag("host-cipher experimental relay: all patch spans read back before CPU start\n");
    return STATUS_SUCCESS;
#else
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Image);
    UNREFERENCED_PARAMETER(Length);
    return STATUS_NOT_SUPPORTED;
#endif
}
