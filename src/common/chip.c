/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "chip.h"
#include "sdio.h"

#define CORE_CC_REG(base, off)  ((base) + (off))
#define CHIP_READ_FAILED        0xFFFFFFFFUL

static UINT32 ChipRead32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address)
{
    UINT32 value = CHIP_READ_FAILED;
    NTSTATUS status = Ap6256SdioReadBackplane32(Ctx, Address, &value);
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_CHIP, "read32 0x%08X failed 0x%08X\n", Address, status);
        return CHIP_READ_FAILED;
    }
    return value;
}

static VOID ChipWrite32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address, _In_ UINT32 Value)
{
    NTSTATUS status = Ap6256SdioWriteBackplane32(Ctx, Address, Value);
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_CHIP, "write32 0x%08X=0x%08X failed 0x%08X\n", Address, Value, status);
    }
}

static VOID ChipStallUs(_In_ ULONG Us) { KeStallExecutionProcessor(Us); }

static BOOLEAN ChipSpinWaitEq(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address,
                              _In_ UINT32 Mask, _In_ UINT32 Expected, _In_ ULONG TimeoutUs)
{
    ULONG waited = 0;
    while (waited <= TimeoutUs) {
        if ((ChipRead32(Ctx, Address) & Mask) == Expected) {
            return TRUE;
        }
        ChipStallUs(10);
        waited += 10;
    }
    return FALSE;
}

_Must_inspect_result_
PAP6256_CORE Ap6256ChipGetCore(_In_ PAP6256_CHIP Chip, _In_ UINT16 CoreId)
{
    for (ULONG i = 0; i < Chip->CoreCount; i++) {
        if (Chip->Cores[i].Id == CoreId) {
            return &Chip->Cores[i];
        }
    }
    return NULL;
}

static PAP6256_CORE ChipAddCore(_In_ PAP6256_CHIP Chip, _In_ UINT16 Id,
                                _In_ UINT32 Base, _In_ UINT32 WrapBase, _In_ UINT16 Rev)
{
    PAP6256_CORE core;
    if (Chip->CoreCount >= AP6256_MAX_CORES) {
        TraceWarn(TRACE_CHIP, "core table full, dropping core 0x%03X\n", Id);
        return NULL;
    }
    core = &Chip->Cores[Chip->CoreCount++];
    core->Id = Id;
    core->Base = Base;
    core->WrapBase = WrapBase;
    core->Rev = Rev;
    TraceVerbose(TRACE_CHIP, "core 0x%03X rev %u base 0x%08X wrap 0x%08X\n",
                 Id, Rev, Base, WrapBase);
    return core;
}

static UINT32 DmpGetDesc(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ PUINT32 EromAddr, _Out_opt_ PUINT8 Type)
{
    UINT32 val = ChipRead32(Ctx, *EromAddr);
    *EromAddr += 4;
    if (Type != NULL) {
        *Type = (UINT8)(val & DMP_DESC_TYPE_MSK);
        if ((UINT8)(*Type & ~DMP_DESC_ADDRSIZE_GT32) == DMP_DESC_ADDRESS) {
            *Type = DMP_DESC_ADDRESS;
        }
    }
    return val;
}

static NTSTATUS DmpGetRegAddr(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ PUINT32 EromAddr,
                              _Out_ PUINT32 RegBase, _Out_ PUINT32 WrapBase)
{
    UINT8 desc, stype, sztype, wraptype;
    UINT32 val, szdesc;

    *RegBase = 0;
    *WrapBase = 0;

    val = DmpGetDesc(Ctx, EromAddr, &desc);
    if (desc == DMP_DESC_MASTER_PORT) {
        wraptype = DMP_SLAVE_TYPE_MWRAP;
    } else if (desc == DMP_DESC_ADDRESS) {
        *EromAddr -= 4;
        wraptype = DMP_SLAVE_TYPE_SWRAP;
    } else {
        *EromAddr -= 4;
        return STATUS_UNSUCCESSFUL;
    }

    do {

        do {
            val = DmpGetDesc(Ctx, EromAddr, &desc);
            if (desc == DMP_DESC_EOT) {
                *EromAddr -= 4;
                return STATUS_UNSUCCESSFUL;
            }
        } while (desc != DMP_DESC_ADDRESS && desc != DMP_DESC_COMPONENT);

        if (desc == DMP_DESC_COMPONENT) {
            *EromAddr -= 4;
            return STATUS_SUCCESS;
        }

        if (val & DMP_DESC_ADDRSIZE_GT32) {
            (VOID)DmpGetDesc(Ctx, EromAddr, NULL);
        }

        sztype = (UINT8)((val & DMP_SLAVE_SIZE_TYPE) >> DMP_SLAVE_SIZE_TYPE_S);
        if (sztype == DMP_SLAVE_SIZE_DESC) {
            szdesc = DmpGetDesc(Ctx, EromAddr, NULL);
            if (szdesc & DMP_DESC_ADDRSIZE_GT32) {
                (VOID)DmpGetDesc(Ctx, EromAddr, NULL);
            }
        }

        if (sztype != DMP_SLAVE_SIZE_4K && sztype != DMP_SLAVE_SIZE_8K) {
            continue;
        }

        stype = (UINT8)((val & DMP_SLAVE_TYPE) >> DMP_SLAVE_TYPE_S);
        if (*RegBase == 0 && stype == DMP_SLAVE_TYPE_SLAVE) {
            *RegBase = val & DMP_SLAVE_ADDR_BASE;
        }
        if (*WrapBase == 0 && stype == wraptype) {
            *WrapBase = val & DMP_SLAVE_ADDR_BASE;
        }
    } while (*RegBase == 0 || *WrapBase == 0);

    return STATUS_SUCCESS;
}

static NTSTATUS ChipEromScan(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_CHIP chip = &Ctx->Chip;
    UINT32 eromAddr;
    UINT8 descType = 0;
    UINT32 val;

    eromAddr = ChipRead32(Ctx, CORE_CC_REG(chip->EnumBase, CC_EROMPTR));
    if (eromAddr == CHIP_READ_FAILED) {
        return STATUS_DEVICE_NOT_READY;
    }

    while (descType != DMP_DESC_EOT) {
        UINT16 id;
        UINT8 nmw, nsw, rev;
        UINT32 base, wrap;
        NTSTATUS status;

        val = DmpGetDesc(Ctx, &eromAddr, &descType);
        if (!(val & DMP_DESC_VALID)) continue;
        if (descType == DMP_DESC_EMPTY) continue;
        if (descType != DMP_DESC_COMPONENT) continue;

        id = (UINT16)((val & DMP_COMP_PARTNUM) >> DMP_COMP_PARTNUM_S);

        val = DmpGetDesc(Ctx, &eromAddr, &descType);
        if ((val & DMP_DESC_TYPE_MSK) != DMP_DESC_COMPONENT) {
            return STATUS_UNSUCCESSFUL;
        }

        nmw = (UINT8)((val & DMP_COMP_NUM_MWRAP) >> DMP_COMP_NUM_MWRAP_S);
        nsw = (UINT8)((val & DMP_COMP_NUM_SWRAP) >> DMP_COMP_NUM_SWRAP_S);
        rev = (UINT8)((val & DMP_COMP_REVISION) >> DMP_COMP_REVISION_S);

        if ((nmw + nsw) == 0 && id != BCMA_CORE_PMU && id != BCMA_CORE_GCI) {
            continue;
        }

        status = DmpGetRegAddr(Ctx, &eromAddr, &base, &wrap);
        if (!NT_SUCCESS(status)) {
            continue;
        }

        (VOID)ChipAddCore(chip, id, base, wrap, rev);
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256ChipCoreIsUp(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core)
{
    UINT32 io = ChipRead32(Ctx, Core->WrapBase + BCMA_IOCTL);
    UINT32 rst = ChipRead32(Ctx, Core->WrapBase + BCMA_RESET_CTL);
    BOOLEAN clkOk = (io & (BCMA_IOCTL_FGC | BCMA_IOCTL_CLK)) == BCMA_IOCTL_CLK;
    return clkOk && ((rst & BCMA_RESET_CTL_RESET) == 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipCoreDisable(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core,
                               _In_ UINT32 PreReset, _In_ UINT32 Reset)
{
    UINT32 rst = ChipRead32(Ctx, Core->WrapBase + BCMA_RESET_CTL);
    if ((rst & BCMA_RESET_CTL_RESET) == 0) {

        ChipWrite32(Ctx, Core->WrapBase + BCMA_IOCTL, PreReset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
        (VOID)ChipRead32(Ctx, Core->WrapBase + BCMA_IOCTL);

        ChipWrite32(Ctx, Core->WrapBase + BCMA_RESET_CTL, BCMA_RESET_CTL_RESET);
        ChipStallUs(20);
        (VOID)ChipSpinWaitEq(Ctx, Core->WrapBase + BCMA_RESET_CTL,
                             BCMA_RESET_CTL_RESET, BCMA_RESET_CTL_RESET, 300);
    }

    ChipWrite32(Ctx, Core->WrapBase + BCMA_IOCTL, Reset | BCMA_IOCTL_FGC | BCMA_IOCTL_CLK);
    (VOID)ChipRead32(Ctx, Core->WrapBase + BCMA_IOCTL);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipResetCore(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core,
                             _In_ UINT32 PreReset, _In_ UINT32 Reset, _In_ UINT32 PostReset)
{
    int count;

    Ap6256ChipCoreDisable(Ctx, Core, PreReset, Reset);

    count = 0;
    while (ChipRead32(Ctx, Core->WrapBase + BCMA_RESET_CTL) & BCMA_RESET_CTL_RESET) {
        ChipWrite32(Ctx, Core->WrapBase + BCMA_RESET_CTL, 0);
        if (++count > 50) break;
        ChipStallUs(60);
    }

    ChipWrite32(Ctx, Core->WrapBase + BCMA_IOCTL, PostReset | BCMA_IOCTL_CLK);
    (VOID)ChipRead32(Ctx, Core->WrapBase + BCMA_IOCTL);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipSetPassive(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_CORE arm = Ctx->Chip.ArmCore;
    PAP6256_CORE d11 = Ctx->Chip.D11Core;

    if (arm != NULL) {

        UINT32 io = ChipRead32(Ctx, arm->WrapBase + BCMA_IOCTL) & ARMCR4_BCMA_IOCTL_CPUHALT;
        Ap6256ChipResetCore(Ctx, arm, io, ARMCR4_BCMA_IOCTL_CPUHALT, ARMCR4_BCMA_IOCTL_CPUHALT);
    } else {
        TraceError(TRACE_CHIP, "no ARM CR4 core; cannot set passive\n");
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (d11 != NULL) {
        Ap6256ChipCoreDisable(Ctx, d11,
                              D11_BCMA_IOCTL_PHYRESET | D11_BCMA_IOCTL_PHYCLOCKEN,
                              D11_BCMA_IOCTL_PHYCLOCKEN);
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipSetActive(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 ResetVector)
{
    PAP6256_CORE arm = Ctx->Chip.ArmCore;
    PAP6256_CORE sdiod = Ctx->Chip.SdiodCore;
    NTSTATUS status;

    if (arm == NULL) {
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (sdiod != NULL) {
        ChipWrite32(Ctx, sdiod->Base + SD_REG_INTSTATUS, 0xFFFFFFFF);
    }

    if (ResetVector != 0) {
        status = Ap6256SdioRamRW(Ctx, TRUE, 0, (PUCHAR)&ResetVector,
                                 sizeof(ResetVector));
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_CHIP, "reset vector write failed 0x%08X\n", status);
            return status;
        }
    }

    Ap6256ChipResetCore(Ctx, arm, ARMCR4_BCMA_IOCTL_CPUHALT, 0, 0);

    if (!Ap6256ChipCoreIsUp(Ctx, arm)) {
        TraceError(TRACE_CHIP, "ARM CR4 did not come up after activate\n");
        return STATUS_DEVICE_NOT_READY;
    }
    TraceInfo(TRACE_CHIP, "ARM CR4 running\n");
    return STATUS_SUCCESS;
}

static UINT32 ChipTcmRamSize(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Arm)
{
    UINT32 cap = ChipRead32(Ctx, Arm->Base + ARMCR4_CAP);
    UINT32 nab = (cap & ARMCR4_TCBANB_MASK) >> ARMCR4_TCBANB_SHIFT;
    UINT32 nbb = (cap & ARMCR4_TCBBNB_MASK) >> ARMCR4_TCBBNB_SHIFT;
    UINT32 totb = nab + nbb;
    UINT32 memsize = 0;

    for (UINT32 idx = 0; idx < totb; idx++) {
        UINT32 bxinfo, blksize;
        ChipWrite32(Ctx, Arm->Base + ARMCR4_BANKIDX, idx);
        bxinfo = ChipRead32(Ctx, Arm->Base + ARMCR4_BANKINFO);
        blksize = ARMCR4_BSZ_MULT;
        if (bxinfo & ARMCR4_BLK_1K_MASK) {
            blksize >>= 3;
        }
        memsize += ((bxinfo & ARMCR4_BSZ_MASK) + 1) * blksize;
    }
    return memsize;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipAttach(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_CHIP chip = &Ctx->Chip;
    NTSTATUS status;
    UINT32 chipidReg, socitype;

    RtlZeroMemory(chip, sizeof(*chip));
    chip->EnumBase = SI_ENUM_BASE_DEFAULT;

    status = Ap6256SdioEnableBackplaneClock(Ctx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR,
                               SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_FORCE_ALP);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ChipStallUs(65);
    (VOID)Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SDIOPULLUP, 0);

    chipidReg = ChipRead32(Ctx, CORE_CC_REG(chip->EnumBase, CC_CHIPID));
    if (chipidReg == CHIP_READ_FAILED || chipidReg == 0) {
        TraceError(TRACE_CHIP, "failed to read chipid (0x%08X)\n", chipidReg);

        status = Ap6256SdioBusFallback(Ctx);
        if (!NT_SUCCESS(status)) {
            return STATUS_DEVICE_NOT_READY;
        }
        chipidReg = ChipRead32(Ctx, CORE_CC_REG(chip->EnumBase, CC_CHIPID));
        if (chipidReg == CHIP_READ_FAILED || chipidReg == 0) {
            TraceError(TRACE_CHIP, "chipid still unreadable after bus test (0x%08X)\n", chipidReg);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    chip->ChipId  = chipidReg & CID_ID_MASK;
    chip->ChipRev = (chipidReg & CID_REV_MASK) >> CID_REV_SHIFT;
    socitype      = (chipidReg & CID_TYPE_MASK) >> CID_TYPE_SHIFT;

    RtlStringCbPrintfA(chip->Name, sizeof(chip->Name), "BCM%X/%u",
                       chip->ChipId, chip->ChipRev);
    TraceInfo(TRACE_CHIP, "chip %s (chipid=0x%08X socitype=%u)\n",
              chip->Name, chipidReg, socitype);

    if (chip->ChipId != BRCM_CC_4345_CHIP_ID && chip->ChipId != BRCM_CC_43454_CHIP_ID) {
        TraceWarn(TRACE_CHIP, "unexpected chip id 0x%X (expected 0x4345 family)\n",
                  chip->ChipId);

    }
    if (socitype != SOCI_AI) {
        TraceWarn(TRACE_CHIP, "unexpected SOC interconnect type %u (expected AI)\n", socitype);
    }

    status = ChipEromScan(Ctx);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_CHIP, "EROM scan failed 0x%08X\n", status);
        return status;
    }

    chip->ChipCommon = Ap6256ChipGetCore(chip, BCMA_CORE_CHIPCOMMON);
    chip->ArmCore    = Ap6256ChipGetCore(chip, BCMA_CORE_ARM_CR4);
    chip->SdiodCore  = Ap6256ChipGetCore(chip, BCMA_CORE_SDIO_DEV);
    chip->D11Core    = Ap6256ChipGetCore(chip, BCMA_CORE_80211);

    if (chip->ChipCommon == NULL || chip->ArmCore == NULL || chip->SdiodCore == NULL) {
        TraceError(TRACE_CHIP, "required cores missing (cc=%p arm=%p sdiod=%p)\n",
                   chip->ChipCommon, chip->ArmCore, chip->SdiodCore);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    chip->RamBase = 0x198000;
    chip->RamSize = ChipTcmRamSize(Ctx, chip->ArmCore);
    TraceInfo(TRACE_CHIP, "TCM rambase=0x%06X ramsize=%u (%u KB)\n",
              chip->RamBase, chip->RamSize, chip->RamSize / 1024);

    if (chip->RamSize == 0 || chip->RamSize > (4u * 1024 * 1024)) {
        TraceError(TRACE_CHIP, "implausible ramsize %u\n", chip->RamSize);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    status = Ap6256ChipSetPassive(Ctx);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    TraceInfo(TRACE_CHIP, "chip attach complete, %u cores\n", chip->CoreCount);
    return STATUS_SUCCESS;
}
