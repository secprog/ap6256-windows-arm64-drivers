/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "ftm_firmware.h"
#include <bcrypt.h>
#include "bcdc.h"
#include "ftm_patch.h"
#include "ftm.h"
typedef struct _AP6256_FTM_PATCH {
    ULONG Offset, Length;
    const UCHAR* Original;
    const UCHAR* Replacement;
} AP6256_FTM_PATCH;
static const AP6256_FTM_PATCH Ap6256FtmPatches[] = { AP6256_FTM_PATCH_ENTRIES };

_Use_decl_annotations_
NTSTATUS Ap6256PrepareFtm(PAP6256_DEVICE_CONTEXT Ctx,
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
            Ctx->Chip.RamSize != 0xc8000 || *Length != AP6256_FTM_INPUT_SIZE ||
            AP6256_FTM_OUTPUT_SIZE > Ctx->Chip.RamSize)
            return STATUS_REVISION_MISMATCH;
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, *Image, *Length,
                            digest, sizeof(digest));
        if (!NT_SUCCESS(status)) return status;
        if (!RtlEqualMemory(digest, Ap6256FtmInputSha256, sizeof(digest)))
            return STATUS_REVISION_MISMATCH;
        for (i = 0; i < RTL_NUMBER_OF(Ap6256FtmPatches); ++i) {
            const AP6256_FTM_PATCH* p = &Ap6256FtmPatches[i];
            if (p->Offset > *Length || p->Length > *Length - p->Offset ||
                !RtlEqualMemory(*Image + p->Offset, p->Original, p->Length))
                return STATUS_REVISION_MISMATCH;
        }
        copy = ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_FTM_OUTPUT_SIZE, AP6256_POOL_TAG);
        if (copy == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(copy, AP6256_FTM_OUTPUT_SIZE);
        RtlCopyMemory(copy, *Image, *Length);
        RtlCopyMemory(copy + AP6256_FTM_CODE_OFFSET, Ap6256FtmExtension, sizeof(Ap6256FtmExtension));
        for (i = 0; i < RTL_NUMBER_OF(Ap6256FtmPatches); ++i) {
            const AP6256_FTM_PATCH* p = &Ap6256FtmPatches[i];
            RtlCopyMemory(copy + p->Offset, p->Replacement, p->Length);
        }
        status = BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, copy,
                            AP6256_FTM_OUTPUT_SIZE, digest, sizeof(digest));
        if (NT_SUCCESS(status) && !RtlEqualMemory(digest, Ap6256FtmOutputSha256, sizeof(digest)))
            status = STATUS_DATA_ERROR;
        if (!NT_SUCCESS(status)) { ExFreePoolWithTag(copy, AP6256_POOL_TAG); return status; }
        ExFreePoolWithTag(*Image, AP6256_POOL_TAG);
        *Image = copy;
        *Length = AP6256_FTM_OUTPUT_SIZE;
        *Applied = TRUE;
        TraceDiag("FTM adapter: exact download copy patched; native ranging engine, receive path and LCI adapter restored\n");
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256FtmCommand(PAP6256_DEVICE_CONTEXT Ctx,UINT16 Command,UINT16 Session,
    UINT16 Chanspec,const UCHAR* Peer,ULONG TimeoutMs,BOOLEAN Setter,UCHAR* Reply,
    ULONG Capacity,PULONG Length,INT32* FirmwareStatus)
{
    AP6256_BCDC_QUERY_RESULT result={0};ULONG n=0;NTSTATUS status;
    *Length=0;if(FirmwareStatus) *FirmwareStatus=0;
    status=Ap6256FtmBuildCommand(Command,Session,Chanspec,Peer,TimeoutMs,Reply,Capacity,&n);
    if(!NT_SUCCESS(status)) return status;
    status=Setter?Ap6256BcdcSetIovarResultIf(Ctx,0,"proxd",Reply,n,&result):
        Ap6256BcdcGetIovarResultIf(Ctx,0,"proxd",Reply,Capacity,&result);
    if(result.FirmwareReply && FirmwareStatus) *FirmwareStatus=result.FirmwareStatus;
    if(!NT_SUCCESS(status)) return status;
    if(!result.FirmwareReply || result.FirmwareError) return STATUS_DEVICE_PROTOCOL_ERROR;
    if(!Setter) {
        n=(ULONG)Reply[2]+((ULONG)Reply[3]<<8);
        if(result.PayloadLength<12 || n<12 || n>Capacity || n>result.PayloadLength ||
            Reply[0]!=0 || Reply[1]!=3 || Reply[4]!=(UCHAR)Command || Reply[5] ||
            Reply[6]!=4 || Reply[7] || Reply[8]!=(UCHAR)Session ||
            Reply[9]!=(UCHAR)(Session>>8) || Reply[10] || Reply[11])
            return STATUS_DEVICE_PROTOCOL_ERROR;
        *Length=n;
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256QualifyFtm(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_BCDC_QUERY_RESULT r={0};UINT32 abi=0;UCHAR reply[AP6256_FTM_REPLY_MAX];
    ULONG n=0;NTSTATUS status;
    Ctx->FirmwareFtmSupported=FALSE;
    if(!Ctx->FirmwareFtmPatchVerified) return STATUS_SUCCESS;
    status=Ap6256BcdcGetIovarResultIf(Ctx,0,"ftm_wdi_ready",&abi,sizeof(abi),&r);
    if(!NT_SUCCESS(status)) goto unavailable;

    if(!r.FirmwareReply || r.FirmwareError || r.PayloadLength<sizeof(abi) ||
        abi!=AP6256_FTM_ABI) {
        status=STATUS_DEVICE_PROTOCOL_ERROR;
        goto unavailable;
    }
    status=Ap6256FtmCommand(Ctx,2,0,0,NULL,0,TRUE,reply,sizeof(reply),&n,NULL);
    if(!NT_SUCCESS(status)) goto unavailable;
    status=Ap6256FtmCommand(Ctx,10,0,0,NULL,0,FALSE,reply,sizeof(reply),&n,NULL);
    if(NT_SUCCESS(status) && n<16) status=STATUS_DEVICE_PROTOCOL_ERROR;
    { NTSTATUS cleanup=Ap6256FtmCommand(Ctx,3,0,0,NULL,0,TRUE,reply,sizeof(reply),&n,NULL);
      if(NT_SUCCESS(status)) status=cleanup; }
    if(!NT_SUCCESS(status)) goto unavailable;
    Ctx->FirmwareFtmSupported=TRUE;
    TraceDiag("FTM: exact image, native attachment, ABI 0x%08X and control/cleanup qualified; ranging awaits board test\n",abi);
    return STATUS_SUCCESS;
unavailable:
    TraceDiag("FTM: native backend unavailable (ABI 0x%08X status 0x%08X; ready length %u reply %u error %u firmware %d); capability disabled\n",
        abi,status,r.PayloadLength,r.FirmwareReply,r.FirmwareError,r.FirmwareStatus);
    return STATUS_SUCCESS;
}
