/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ft_firmware.h"
#include "sdio.h"
#include <bcrypt.h>
#include <firmware_image.h>
#include "ft_patch.h"
#include "owe_patch.h"
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

_Use_decl_annotations_
NTSTATUS Ap6256VerifyFt(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Image, ULONG Length)
{
    ULONG i, pass;
    UCHAR digest[32];
    NTSTATUS status;
    if (Image == NULL || Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9 ||
        Ctx->Chip.RamBase != 0x198000 || Ctx->Chip.RamSize != 0xc8000 ||
        Length != SAE_VERIFY_SIZE) return STATUS_REVISION_MISMATCH;
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, (PUCHAR)Image, Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, SAE_VERIFY_SHA, sizeof(digest)))
        return STATUS_DATA_ERROR;

    for (pass = 0; pass <= RTL_NUMBER_OF(Ap6256FtPatches); ++pass) {
        ULONG start, end;
        if (pass == RTL_NUMBER_OF(Ap6256FtPatches)) {
            start = AP6256_FT_EXTENSION_OFFSET & ~3u;
            end = Length;
        } else {
            start = Ap6256FtPatches[pass].Offset & ~3u;
            end = (Ap6256FtPatches[pass].Offset + Ap6256FtPatches[pass].Length + 3u) & ~3u;
        }
        for (i = start; i < end; i += sizeof(UINT32)) {
            UINT32 value = 0;
            NTSTATUS readStatus = Ap6256SdioReadBackplane32(Ctx, Ctx->Chip.RamBase + i, &value);
            if (!NT_SUCCESS(readStatus)) return readStatus;
            if (!RtlEqualMemory(&value, Image + i, sizeof(value))) {
                TraceDiag("FT bridge: TCM verification failed at 0x%08X\n", Ctx->Chip.RamBase + i);
                return STATUS_DEVICE_DATA_ERROR;
            }
        }
    }
    TraceDiag("FT bridge: shared SAE/FT hooks and complete reservation verified before CPU start\n");
    return STATUS_SUCCESS;
}
