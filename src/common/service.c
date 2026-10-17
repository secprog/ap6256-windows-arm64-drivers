/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "service.h"
#include "sdio.h"
#include <bcrypt.h>
#include "bcdc.h"
#include "service_patch.h"
typedef struct _AP6256_SERVICE_PATCH {
    ULONG Offset, Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_SERVICE_PATCH;
static const AP6256_SERVICE_PATCH Ap6256ServicePatches[] = { AP6256_SERVICE_PATCH_ENTRIES };

_Use_decl_annotations_
NTSTATUS Ap6256PrepareService(PAP6256_DEVICE_CONTEXT Ctx,
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
            Ctx->Chip.RamSize != 0xc8000 || *Length != AP6256_SERVICE_INPUT_SIZE ||
            AP6256_SERVICE_OUTPUT_SIZE > Ctx->Chip.RamSize)
            return STATUS_REVISION_MISMATCH;
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, *Image, *Length,
                            digest, sizeof(digest));
        if (!NT_SUCCESS(status)) return status;
        if (!RtlEqualMemory(digest, Ap6256ServiceInputSha256, sizeof(digest)))
            return STATUS_REVISION_MISMATCH;
        for (i = 0; i < RTL_NUMBER_OF(Ap6256ServicePatches); ++i) {
            const AP6256_SERVICE_PATCH* p = &Ap6256ServicePatches[i];
            if (p->Offset > *Length || p->Length > *Length - p->Offset ||
                !RtlEqualMemory(*Image + p->Offset, p->Original, p->Length))
                return STATUS_REVISION_MISMATCH;
        }
        copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_SERVICE_OUTPUT_SIZE, AP6256_POOL_TAG);
        if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(copy, AP6256_SERVICE_OUTPUT_SIZE);
        RtlCopyMemory(copy, *Image, *Length);
        RtlCopyMemory(copy + AP6256_SERVICE_CODE_OFFSET, Ap6256ServiceExtension, sizeof(Ap6256ServiceExtension));
        for (i = 0; i < RTL_NUMBER_OF(Ap6256ServicePatches); ++i) {
            const AP6256_SERVICE_PATCH* p = &Ap6256ServicePatches[i];
            RtlCopyMemory(copy + p->Offset, p->Replacement, p->Length);
        }
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, copy,
                            AP6256_SERVICE_OUTPUT_SIZE, digest, sizeof(digest));
        if (NT_SUCCESS(status) && !RtlEqualMemory(digest, Ap6256ServiceOutputSha256, sizeof(digest)))
            status = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(status)) { ExFreePoolWithTag(copy, AP6256_POOL_TAG); return status; }
        ExFreePoolWithTag(*Image, AP6256_POOL_TAG);
        *Image = copy;
        *Length = AP6256_SERVICE_OUTPUT_SIZE;
        *Applied = TRUE;
        TraceDiag("SERVICE adapter: exact download copy patched; native ANQP/P2PO attachment and service engines restored\n");
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256QualifyService(PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 words[4] = {0}, value = 0; ULONG i;
    AP6256_BCDC_QUERY_RESULT result = {0}; NTSTATUS status;
    Ctx->FirmwareServiceOffload = FALSE;
    if (!Ctx->FirmwareServicePatchVerified) return STATUS_SUCCESS;
    for (i = 0; i < RTL_NUMBER_OF(words); i++) {
        status = Ap6256SdioReadBackplane32(Ctx, 0x226000u + 4u * i, &words[i]);
        if (!NT_SUCCESS(status)) return status;
    }
    if (words[0] != 0x31564f53u || words[1] < 0x198000u || words[1] >= 0x260000u ||
        words[2] != 1 || words[3] != 1) return STATUS_DEVICE_PROTOCOL_ERROR;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "p2po_state", &value, sizeof(value), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < 4 || value != 0)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    value = 0;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "anqpo_auto_hotspot", &value, sizeof(value), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < 4 || value != 0)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    for (i=0;i<2;i++) {
        value=0;
        status=Ap6256BcdcGetIovarResultIf(Ctx,0,i?"svc_wdi_update":"svc_wdi_generation",&value,4,&result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength<4 || value!=0)
            return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    Ctx->FirmwareServiceOffload = TRUE;
    TraceDiag("service offload: exact patch, native attachment, timers and ANQPO/P2PO getters qualified; test candidate\n");
    return STATUS_SUCCESS;
}
