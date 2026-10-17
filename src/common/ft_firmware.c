/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ft_firmware.h"
#include <bcrypt.h>
#include "ft_patch.h"
typedef struct _AP6256_FT_PATCH {
    ULONG Offset, Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_FT_PATCH;
static const AP6256_FT_PATCH Ap6256FtPatches[] = { AP6256_FT_PATCH_ENTRIES };

_Use_decl_annotations_
NTSTATUS Ap6256PrepareFt(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR* Image, PULONG Length, BOOLEAN* Applied)
{
    *Applied = FALSE;
    {
        NTSTATUS status;
        UCHAR digest[32];
        PUCHAR copy;
        ULONG i;
        if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9)
            return STATUS_SUCCESS;
        if (*Image == NULL || Ctx->Chip.RamBase != 0x198000 ||
            Ctx->Chip.RamSize != 0xc8000 || *Length != AP6256_FT_INPUT_SIZE ||
            AP6256_FT_OUTPUT_SIZE > Ctx->Chip.RamSize)
            return STATUS_REVISION_MISMATCH;
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, *Image, *Length,
                            digest, sizeof(digest));
        if (!NT_SUCCESS(status)) return status;
        if (!RtlEqualMemory(digest, Ap6256FtInputSha256, sizeof(digest)))
            return STATUS_REVISION_MISMATCH;
        for (i = 0; i < RTL_NUMBER_OF(Ap6256FtPatches); ++i) {
            const AP6256_FT_PATCH* p = &Ap6256FtPatches[i];
            if (p->Offset > *Length || p->Length > *Length - p->Offset ||
                !RtlEqualMemory(*Image + p->Offset, p->Original, p->Length))
                return STATUS_REVISION_MISMATCH;
        }
        copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_FT_OUTPUT_SIZE, AP6256_POOL_TAG);
        if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(copy, AP6256_FT_OUTPUT_SIZE);
        RtlCopyMemory(copy, *Image, *Length);
        RtlCopyMemory(copy + AP6256_FT_CODE_OFFSET, Ap6256FtCode, sizeof(Ap6256FtCode));
        for (i = 0; i < RTL_NUMBER_OF(Ap6256FtPatches); ++i) {
            const AP6256_FT_PATCH* p = &Ap6256FtPatches[i];
            RtlCopyMemory(copy + p->Offset, p->Replacement, p->Length);
        }
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, copy,
                            AP6256_FT_OUTPUT_SIZE, digest, sizeof(digest));
        if (NT_SUCCESS(status) && !RtlEqualMemory(digest, Ap6256FtOutputSha256, sizeof(digest)))
            status = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(status)) { ExFreePoolWithTag(copy, AP6256_POOL_TAG); return status; }
        ExFreePoolWithTag(*Image, AP6256_POOL_TAG);
        *Image = copy;
        *Length = AP6256_FT_OUTPUT_SIZE;
        *Applied = TRUE;
        TraceDiag("FT bridge: exact download copy patched; Windows owns FT validation\n");
    }
    return STATUS_SUCCESS;
}
