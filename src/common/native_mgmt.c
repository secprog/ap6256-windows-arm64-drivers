/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "native_mgmt.h"
#include "sdio.h"
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

_Use_decl_annotations_
NTSTATUS Ap6256VerifyNativeManagementImage(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Image, ULONG Length)
{

    UCHAR readback[(AP6256_VERIFY_MAX_BYTES + 6u) & ~3u] = { 0 };
    ULONG i;
    for (i = 0; i < RTL_NUMBER_OF(Ap6256Patches); ++i) {
        const AP6256_PATCH* p = &Ap6256Patches[i];
        const ULONG address = AP6256_RAM_BASE + p->Offset;
        const ULONG leading = address & 3u;
        const ULONG readAddress = address & ~3u;
        const ULONG readLength = (leading + p->Length + 3u) & ~3u;
        ULONG j;
        NTSTATUS status;
        if (readLength > sizeof(readback)) return STATUS_BUFFER_TOO_SMALL;

        for (j = 0; j < readLength; j += sizeof(UINT32)) {
            UINT32 value = 0;
            status = Ap6256SdioReadBackplane32(Ctx, readAddress + j, &value);
            if (!NT_SUCCESS(status)) {
                TraceError(TRACE_FIRMWARE,
                           "native management: TCM word read failed at 0x%08X: 0x%08X\n",
                           readAddress + j, status);
                return status;
            }
            RtlCopyMemory(readback + j, &value, sizeof(value));
        }
        if (Image != NULL && (p->Offset > Length || p->Length > Length - p->Offset))
            return STATUS_INVALID_IMAGE_FORMAT;
        for (j = 0; j < p->Length; ++j) {
            if (readback[leading + j] != (Image != NULL ? Image[p->Offset + j] : p->Replacement[j])) {
                TraceError(TRACE_FIRMWARE,
                           "native management: TCM readback mismatch at 0x%08X: "
                           "expected %02X got %02X (read 0x%08X, %u bytes)\n",
                           address + j, (Image != NULL ? Image[p->Offset + j] : p->Replacement[j]), readback[leading + j],
                           readAddress, readLength);
                return STATUS_DEVICE_DATA_ERROR;
            }
        }
        TraceDiag("native management: TCM span 0x%08X +%u verified "
                  "(read 0x%08X, %u word(s))\n",
                  address, p->Length, readAddress, readLength / (ULONG)sizeof(UINT32));
    }
    TraceDiag("management: all %u TCM spans verified before CPU start\n",
              (ULONG)RTL_NUMBER_OF(Ap6256Patches));
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256VerifyNativeManagement(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{ return Ap6256VerifyNativeManagementImage(Ctx, NULL, 0); }
