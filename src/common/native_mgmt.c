/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "native_mgmt.h"
#include <bcrypt.h>
#include "native_mgmt_patch.h"

typedef struct _AP6256_PATCH {
    ULONG Offset;
    ULONG Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_PATCH;

static const AP6256_PATCH Ap6256Patches[] = {
    AP6256_NATIVE_PATCH_ENTRIES
};
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PrepareNativeManagement(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_updates_bytes_(Length) PUCHAR Image, _In_ ULONG Length,
    _Out_ BOOLEAN* Applied)
{
    UCHAR digest[32];
    ULONG i;
    NTSTATUS status;
    *Applied = FALSE;

    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9)
        return STATUS_SUCCESS;
    if (Ctx->Chip.RamBase != AP6256_RAM_BASE ||
        Length != AP6256_IMAGE_SIZE || Length > Ctx->Chip.RamSize) {
        return STATUS_REVISION_MISMATCH;
    }
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, Image, Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, Ap6256OriginalSha256, sizeof(digest))) {
        return STATUS_REVISION_MISMATCH;
    }

    for (i = 0; i < RTL_NUMBER_OF(Ap6256Patches); ++i) {
        const AP6256_PATCH* p = &Ap6256Patches[i];
        if (p->Offset > Length || p->Length > Length - p->Offset ||
            !RtlEqualMemory(Image + p->Offset, p->Original, p->Length)) {
            return STATUS_REVISION_MISMATCH;
        }
    }
    for (i = 0; i < RTL_NUMBER_OF(Ap6256Patches); ++i) {
        const AP6256_PATCH* p = &Ap6256Patches[i];
        RtlCopyMemory(Image + p->Offset, p->Replacement, p->Length);
    }
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, Image, Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, Ap6256PatchedSha256, sizeof(digest))) {
        return STATUS_DATA_ERROR;
    }
    *Applied = TRUE;
    TraceDiag("native management: exact image repaired; native RRM/Neighbor, Windows BTM verdict via firmware TX\n");
    return STATUS_SUCCESS;
}
