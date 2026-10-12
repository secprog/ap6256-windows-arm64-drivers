/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sae_firmware.h"
#include "sdio.h"
#include <bcrypt.h>
#include "sae_patch.h"
#include <firmware_image.h>

typedef struct _AP6256_SAE_PATCH {
    ULONG Offset, Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_SAE_PATCH;

static const AP6256_SAE_PATCH Ap6256SaePatches[] = {
    AP6256_SAE_PATCH_ENTRIES
};

C_ASSERT(sizeof(Ap6256SaePool) == AP6256_SAE_POOL_SIZE);
C_ASSERT(AP6256_SAE_POOL_OFFSET >= AP6256_SAE_INPUT_SIZE);
C_ASSERT(AP6256_SAE_POOL_OFFSET + AP6256_SAE_POOL_SIZE == AP6256_SAE_OUTPUT_SIZE);
C_ASSERT((AP6256_SAE_OUTPUT_SIZE & 3u) == 0);

_Use_decl_annotations_
NTSTATUS Ap6256PrepareSae(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR* Image, PULONG Length, BOOLEAN* Applied)
{
    UCHAR digest[32];
    PUCHAR copy;
    ULONG i;
    NTSTATUS status;
    *Applied = FALSE;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9)
        return STATUS_SUCCESS;
    if (*Image == NULL || Ctx->Chip.RamBase != AP6256_SAE_RAM_BASE ||
        Ctx->Chip.RamSize != AP6256_SAE_RAM_SIZE ||
        *Length != AP6256_SAE_INPUT_SIZE ||
        AP6256_SAE_OUTPUT_SIZE > Ctx->Chip.RamSize)
        return STATUS_REVISION_MISMATCH;
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, *Image, *Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, Ap6256SaeInputSha256, sizeof(digest)))
        return STATUS_REVISION_MISMATCH;
    for (i = 0; i < RTL_NUMBER_OF(Ap6256SaePatches); ++i) {
        const AP6256_SAE_PATCH* p = &Ap6256SaePatches[i];
        if (p->Offset > *Length || p->Length > *Length - p->Offset ||
            !RtlEqualMemory(*Image + p->Offset, p->Original, p->Length))
            return STATUS_REVISION_MISMATCH;
    }

    copy = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                 AP6256_SAE_OUTPUT_SIZE, AP6256_POOL_TAG);
    if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    RtlZeroMemory(copy, AP6256_SAE_OUTPUT_SIZE);
    RtlCopyMemory(copy, *Image, *Length);
    for (i = 0; i < RTL_NUMBER_OF(Ap6256SaePatches); ++i) {
        const AP6256_SAE_PATCH* p = &Ap6256SaePatches[i];
        RtlCopyMemory(copy + p->Offset, p->Replacement, p->Length);
    }
    RtlCopyMemory(copy + AP6256_SAE_POOL_OFFSET,
                  Ap6256SaePool, sizeof(Ap6256SaePool));
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, copy,
                        AP6256_SAE_OUTPUT_SIZE, digest, sizeof(digest));
    if (NT_SUCCESS(status) &&
        !RtlEqualMemory(digest, Ap6256SaeOutputSha256, sizeof(digest)))
        status = STATUS_DATA_ERROR;
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(copy, AP6256_POOL_TAG);
        return status;
    }
    ExFreePoolWithTag(*Image, AP6256_POOL_TAG);
    *Image = copy;
    *Length = AP6256_SAE_OUTPUT_SIZE;
    *Applied = TRUE;
    TraceDiag("SAE: exact transport candidate composed; host crypto, chip CCMP/PMF\n");
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256VerifySae(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Image, ULONG Length)
{
    UCHAR digest[32];
    ULONG i;
    NTSTATUS status;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9 ||
        Ctx->Chip.RamBase != AP6256_SAE_RAM_BASE ||
        Ctx->Chip.RamSize != AP6256_SAE_RAM_SIZE ||
        Length != SAE_VERIFY_SIZE)
        return STATUS_REVISION_MISMATCH;
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)Image,
                        Length, digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, SAE_VERIFY_SHA, sizeof(digest)))
        return STATUS_DATA_ERROR;
    for (i = 0; i <= RTL_NUMBER_OF(Ap6256SaePatches); ++i) {
        ULONG start, end, offset;
        if (i == RTL_NUMBER_OF(Ap6256SaePatches)) {

            start = AP6256_SAE_INPUT_SIZE & ~3u;
            end = AP6256_SAE_OUTPUT_SIZE;
        } else {
            const AP6256_SAE_PATCH* p = &Ap6256SaePatches[i];
            if (p->Offset > Length || p->Length > Length - p->Offset)
                return STATUS_INVALID_IMAGE_FORMAT;
            start = p->Offset & ~3u;
            end = (p->Offset + p->Length + 3u) & ~3u;
        }
        for (offset = start; offset < end; offset += sizeof(UINT32)) {
            UINT32 value = 0;
            status = Ap6256SdioReadBackplane32(Ctx,
                AP6256_SAE_RAM_BASE + offset, &value);
            if (!NT_SUCCESS(status)) {
                TraceError(TRACE_FIRMWARE,
                    "SAE: TCM word read failed at 0x%08X: 0x%08X\n",
                    AP6256_SAE_RAM_BASE + offset, status);
                return status;
            }
            if (!RtlEqualMemory(&value, Image + offset, sizeof(value))) {
                TraceError(TRACE_FIRMWARE,
                    "SAE: TCM mismatch at 0x%08X before CPU start\n",
                    AP6256_SAE_RAM_BASE + offset);
                return STATUS_DEVICE_DATA_ERROR;
            }
        }
    }
    TraceDiag("SAE: all hooks, CRC, heap reservation and appended pool verified\n");
    return STATUS_SUCCESS;
}
