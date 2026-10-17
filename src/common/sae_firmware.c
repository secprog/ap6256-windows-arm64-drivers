/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sae_firmware.h"
#include <bcrypt.h>
#include "sae_patch.h"

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
