/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "pno_delay.h"
#include <bcrypt.h>
#include "pno_delay_patch.h"
#include "native_mgmt_patch.h"
typedef struct _AP6256_PNO_DELAY_PATCH {
    ULONG Offset;
    ULONG Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_PNO_DELAY_PATCH;

#define PNO_DELAY_PATCH(Name, Offset) { Offset, sizeof(Ap6256PnoDelay##Name##Original), \
    Ap6256PnoDelay##Name##Original, Ap6256PnoDelay##Name##Replacement }
static const AP6256_PNO_DELAY_PATCH Ap6256PnoDelayPatches[] = {
    PNO_DELAY_PATCH(Control, AP6256_PNO_DELAY_CONTROL_OFFSET),
    PNO_DELAY_PATCH(Guard, AP6256_PNO_DELAY_GUARD_OFFSET),
    PNO_DELAY_PATCH(Allocate, AP6256_PNO_DELAY_ALLOCATE_OFFSET),
    PNO_DELAY_PATCH(OverrideCall, AP6256_PNO_DELAY_OVERRIDECALL_OFFSET),
    PNO_DELAY_PATCH(ImmediateCall, AP6256_PNO_DELAY_IMMEDIATECALL_OFFSET),
    PNO_DELAY_PATCH(ScheduledCall, AP6256_PNO_DELAY_SCHEDULEDCALL_OFFSET),
    PNO_DELAY_PATCH(FireEntry, AP6256_PNO_DELAY_FIREENTRY_OFFSET),
    PNO_DELAY_PATCH(ClearEntry, AP6256_PNO_DELAY_CLEARENTRY_OFFSET),
    PNO_DELAY_PATCH(ScanEntry, AP6256_PNO_DELAY_SCANENTRY_OFFSET)
};
#undef PNO_DELAY_PATCH
C_ASSERT(sizeof(Ap6256PnoDelayControlOriginal) == sizeof(Ap6256PnoDelayControlReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayGuardOriginal) == sizeof(Ap6256PnoDelayGuardReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayAllocateOriginal) == sizeof(Ap6256PnoDelayAllocateReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayOverrideCallOriginal) == sizeof(Ap6256PnoDelayOverrideCallReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayImmediateCallOriginal) == sizeof(Ap6256PnoDelayImmediateCallReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayScheduledCallOriginal) == sizeof(Ap6256PnoDelayScheduledCallReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayFireEntryOriginal) == sizeof(Ap6256PnoDelayFireEntryReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayClearEntryOriginal) == sizeof(Ap6256PnoDelayClearEntryReplacement));
C_ASSERT(sizeof(Ap6256PnoDelayScanEntryOriginal) == sizeof(Ap6256PnoDelayScanEntryReplacement));

_Use_decl_annotations_
NTSTATUS Ap6256PnoPrepareInitialDelay(PAP6256_DEVICE_CONTEXT Ctx,
    PUCHAR Image, ULONG Length, BOOLEAN* Applied)
{
    UCHAR digest[32];
    const UCHAR* outputDigest;
    NTSTATUS status;
    ULONG i;
    *Applied = FALSE;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9 ||
        Ctx->Chip.RamBase != AP6256_PNO_DELAY_RAM_BASE ||
        Length != AP6256_PNO_DELAY_IMAGE_SIZE || Length > Ctx->Chip.RamSize)
        return STATUS_SUCCESS;
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, Image, Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (RtlEqualMemory(digest, Ap6256PnoDelayOriginalSha256, sizeof(digest)))
        outputDigest = Ap6256PnoDelayOutput0Sha256;
    else if (RtlEqualMemory(digest, Ap6256PnoDelayManagementInputSha256, sizeof(digest)))
        outputDigest = Ap6256PnoDelayOutput1Sha256;
    else if (RtlEqualMemory(digest, Ap6256PatchedSha256, sizeof(digest)))
        outputDigest = Ap6256NativePnoSha256;
    else return STATUS_SUCCESS;

    for (i = 0; i < RTL_NUMBER_OF(Ap6256PnoDelayPatches); ++i) {
        const AP6256_PNO_DELAY_PATCH* p = &Ap6256PnoDelayPatches[i];
        if (p->Offset > Length || p->Length > Length - p->Offset ||
            !RtlEqualMemory(Image + p->Offset, p->Original, p->Length))
            return STATUS_REVISION_MISMATCH;
    }
    for (i = 0; i < RTL_NUMBER_OF(Ap6256PnoDelayPatches); ++i) {
        const AP6256_PNO_DELAY_PATCH* p = &Ap6256PnoDelayPatches[i];
        RtlCopyMemory(Image + p->Offset, p->Replacement, p->Length);
    }
    status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, Image, Length,
                        digest, sizeof(digest));
    if (!NT_SUCCESS(status)) return status;
    if (!RtlEqualMemory(digest, outputDigest, sizeof(digest))) return STATUS_DATA_ERROR;
    *Applied = TRUE;
    return STATUS_SUCCESS;
}
