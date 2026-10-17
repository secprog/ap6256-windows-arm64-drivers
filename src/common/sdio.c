/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sdio.h"
#include "chip.h"

static VOID Ap6256StallUs(_In_ ULONG Microseconds)
{
    KeStallExecutionProcessor(Microseconds);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256SleepMs(_In_ ULONG Milliseconds)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -((LONGLONG)Milliseconds * 10 * 1000);
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioReadF0(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _Out_ PUCHAR Value)
{
    *Value = 0;
    return Ap6256SdBusCmd52(Ctx, FALSE, 0, Address, Value);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioWriteF0(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _In_ UCHAR Value)
{
    UCHAR v = Value;
    return Ap6256SdBusCmd52(Ctx, TRUE, 0, Address, &v);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioReadF1(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _Out_ PUCHAR Value)
{
    *Value = 0;
    return Ap6256SdBusCmd52(Ctx, FALSE, 1, Address, Value);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdioWriteF1(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Address, _In_ UCHAR Value)
{
    UCHAR v = Value;
    return Ap6256SdBusCmd52(Ctx, TRUE, 1, Address, &v);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256SetWindowLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address)
{
    NTSTATUS status;
    UINT32 window = Address & SBSDIO_SBWINDOW_MASK;
    UINT32 v;

    if (window == Ctx->Sdio.BackplaneWindow) {
        return STATUS_SUCCESS;
    }

    v = window >> 8;
    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SBADDRLOW, (UCHAR)(v & 0xff));
    if (!NT_SUCCESS(status)) return status;
    v >>= 8;
    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SBADDRMID, (UCHAR)(v & 0xff));
    if (!NT_SUCCESS(status)) return status;
    v >>= 8;
    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SBADDRHIGH, (UCHAR)(v & 0xff));
    if (!NT_SUCCESS(status)) return status;

    Ctx->Sdio.BackplaneWindow = window;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetBackplaneWindow(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Ctx->Sdio.Lock);
    status = Ap6256SetWindowLocked(Ctx, Address);
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256Backplane32Locked(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Write,
                                        _In_ UINT32 Address, _Inout_ PUINT32 Value)
{
    NTSTATUS status;
    ULONG offset;
    UCHAR buf[4] = { 0 };

    status = Ap6256SetWindowLocked(Ctx, Address);
    if (!NT_SUCCESS(status)) return status;

    offset = (Address & SBSDIO_SB_OFT_ADDR_MASK) | SBSDIO_SB_ACCESS_2_4B_FLAG;

    if (Write) {
        RtlCopyMemory(buf, Value, sizeof(buf));
    }
    status = Ap6256SdBusCmd53(Ctx, Write, 1, offset, TRUE, buf, sizeof(buf));
    if (NT_SUCCESS(status) && !Write) {
        RtlCopyMemory(Value, buf, sizeof(buf));
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioReadBackplane32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address, _Out_ PUINT32 Value)
{
    NTSTATUS status;
    *Value = 0;
    Ap6256LockAcquire(&Ctx->Sdio.Lock);
    status = Ap6256Backplane32Locked(Ctx, FALSE, Address, Value);
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioWriteBackplane32(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Address, _In_ UINT32 Value)
{
    NTSTATUS status;
    UINT32 v = Value;
    Ap6256LockAcquire(&Ctx->Sdio.Lock);
    status = Ap6256Backplane32Locked(Ctx, TRUE, Address, &v);
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioRamRW(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Write,
                         _In_ UINT32 Address,
                         _Inout_updates_bytes_(Length) PUCHAR Buffer,
                         _In_ ULONG Length)
{
    NTSTATUS status = STATUS_SUCCESS;
    ULONG remaining = Length;
    PUCHAR p = Buffer;
    UINT32 addr = Address;

    Ap6256LockAcquire(&Ctx->Sdio.Lock);

    while (remaining != 0) {
        ULONG winOffset;
        ULONG spaceInWindow;
        ULONG chunk;
        ULONG ocpOffset;

        status = Ap6256SetWindowLocked(Ctx, addr);
        if (!NT_SUCCESS(status)) break;

        winOffset = addr & SBSDIO_SB_OFT_ADDR_MASK;
        spaceInWindow = SBSDIO_SB_OFT_ADDR_LIMIT - winOffset;
        chunk = (remaining < spaceInWindow) ? remaining : spaceInWindow;

        ocpOffset = winOffset | SBSDIO_SB_ACCESS_2_4B_FLAG;

        status = Ap6256SdBusCmd53(Ctx, Write, 1, ocpOffset, TRUE, p, chunk);
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_SDIO, "RamRW %s addr=0x%08X chunk=%u failed 0x%08X\n",
                       Write ? "wr" : "rd", addr, chunk, status);
            break;
        }

        addr += chunk;
        p += chunk;
        remaining -= chunk;
    }

    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioFrameRW(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Write,
                           _Inout_updates_bytes_(Length) PUCHAR Buffer,
                           _In_ ULONG Length)
{
    NTSTATUS status;
    UINT32 address;

    if (Ctx->Chip.ChipCommon == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    Ap6256LockAcquire(&Ctx->Sdio.Lock);
    address = Ctx->Chip.ChipCommon->Base;
    status = Ap6256SetWindowLocked(Ctx, address);
    if (NT_SUCCESS(status)) {
        address = (address & SBSDIO_SB_OFT_ADDR_MASK) | SBSDIO_SB_ACCESS_2_4B_FLAG;

        status = Ap6256SdBusCmd53(Ctx, Write, 2, address, Write, Buffer, Length);
    }
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioFrameReadHeader(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _Out_writes_bytes_(Length) PUCHAR Buffer,
                                   _In_ ULONG Length)
{
    NTSTATUS status;
    UINT32 address;

    if (Ctx->Chip.ChipCommon == NULL) {
        return STATUS_DEVICE_NOT_READY;
    }

    Ap6256LockAcquire(&Ctx->Sdio.Lock);
    address = Ctx->Chip.ChipCommon->Base;
    status = Ap6256SetWindowLocked(Ctx, address);
    if (NT_SUCCESS(status)) {
        address = (address & SBSDIO_SB_OFT_ADDR_MASK) | SBSDIO_SB_ACCESS_2_4B_FLAG;
        status = Ap6256SdBusCmd53Mode(Ctx, FALSE, 2, address, FALSE, Buffer,
                                      Length, TRUE);
    }
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    return status;
}

#define AP6256_SDHC_PHYS_BASE   0x8804000ULL
#define AP6256_SDHC_SPAN        0x1000

#define SDHC_BLOCK          0x004
#define SDHC_ARGUMENT       0x008
#define SDHC_XFER_CMD       0x00C
#define SDHC_PRESENT_STATE  0x024
#define SDHC_HOST_CTL       0x028
#define SDHC_CLOCK_CTL      0x02C
#define SDHC_INT_STATUS     0x030
#define SDHC_INT_ENABLE     0x034
#define SDHC_SIGNAL_ENABLE  0x038
#define SDHC_HOST_CTL2      0x03C
#define SDHC_CAPS_LO        0x040
#define SDHC_CAPS_HI        0x044
#define SDHC_ADMA_ERROR     0x054
#define SDHC_ADMA_ADDR_LO   0x058
#define SDHC_ADMA_ADDR_HI   0x05C
#define SDHC_V5_DLL_CONFIG  0x200
#define SDHC_V5_DLL_STATUS  0x208
#define SDHC_V5_VENDOR_SPEC 0x20C
#define SDHC_V5_VENDOR_CAPS 0x21C
#define SDHC_V5_DLL_CONFIG2 0x254
#define SDHC_V5_DLL_CONFIG3 0x258
#define SDHC_V5_DDR_CONFIG  0x25C
#define SDHC_V5_MCI_VERSION 0x318
#define SDHC_V5_DLL_USR_CTL 0x388

_IRQL_requires_max_(PASSIVE_LEVEL)
PUCHAR Ap6256SdioMapHostRegisters(VOID)
{
    PHYSICAL_ADDRESS pa;
    pa.QuadPart = AP6256_SDHC_PHYS_BASE;
    return (PUCHAR)MmMapIoSpaceEx(pa, AP6256_SDHC_SPAN, PAGE_READWRITE | PAGE_NOCACHE);
}

static ULONG Ap6256Reg(_In_ PUCHAR Regs, _In_ ULONG Offset)
{
    return READ_REGISTER_ULONG((volatile ULONG *)(Regs + Offset));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioUnmapHostRegisters(_In_opt_ PUCHAR Regs)
{
    if (Regs != NULL) {
        MmUnmapIoSpace(Regs, AP6256_SDHC_SPAN);
    }
}

_IRQL_requires_max_(APC_LEVEL)
VOID Ap6256SdioDumpTransferFailure(_In_opt_ PUCHAR Regs, _In_ PCSTR Label)
{
    ULONG block, intStatus;

    if (Regs == NULL) {
        return;
    }
    TraceDiag("failure interrupt enables: inten=%08X sigen=%08X autocmd_err=%04X\n",
              Ap6256Reg(Regs, SDHC_INT_ENABLE), Ap6256Reg(Regs, SDHC_SIGNAL_ENABLE),
              Ap6256Reg(Regs, SDHC_HOST_CTL2) & 0xFFFF);
    block = Ap6256Reg(Regs, SDHC_BLOCK);
    intStatus = Ap6256Reg(Regs, SDHC_INT_STATUS);
    TraceDiag("%s: blksz=%u blkcnt=%u int=%08X%s%s%s%s%s%s xfer/cmd=%08X present=%08X "
              "ctl2=%08X adma_err=%08X adma=%08X%08X\n",
              Label, block & 0xFFF, block >> 16, intStatus,
              (intStatus & 0x00010000) ? " cmd-timeout" : "",
              (intStatus & 0x00020000) ? " cmd-crc" : "",
              (intStatus & 0x00100000) ? " data-timeout" : "",
              (intStatus & 0x00200000) ? " data-crc" : "",
              (intStatus & 0x00400000) ? " data-endbit" : "",
              (intStatus & 0x04000000) ? " adma" : "",
              Ap6256Reg(Regs, SDHC_XFER_CMD), Ap6256Reg(Regs, SDHC_PRESENT_STATE),
              Ap6256Reg(Regs, SDHC_HOST_CTL2), Ap6256Reg(Regs, SDHC_ADMA_ERROR),
              Ap6256Reg(Regs, SDHC_ADMA_ADDR_HI), Ap6256Reg(Regs, SDHC_ADMA_ADDR_LO));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256DumpHostRegisters(_In_opt_ PUCHAR Regs, _In_ PCSTR Label)
{
    if (Regs == NULL) {
        return;
    }
    TraceDiag("regs %-14s blk=%08X arg=%08X xfer/cmd=%08X present=%08X hostctl=%08X clk=%08X\n",
              Label,
              Ap6256Reg(Regs, SDHC_BLOCK), Ap6256Reg(Regs, SDHC_ARGUMENT),
              Ap6256Reg(Regs, SDHC_XFER_CMD), Ap6256Reg(Regs, SDHC_PRESENT_STATE),
              Ap6256Reg(Regs, SDHC_HOST_CTL), Ap6256Reg(Regs, SDHC_CLOCK_CTL));
    TraceDiag("regs %-14s int=%08X inten=%08X sigen=%08X ctl2=%08X adma_err=%08X adma=%08X%08X\n",
              Label,
              Ap6256Reg(Regs, SDHC_INT_STATUS), Ap6256Reg(Regs, SDHC_INT_ENABLE),
              Ap6256Reg(Regs, SDHC_SIGNAL_ENABLE), Ap6256Reg(Regs, SDHC_HOST_CTL2),
              Ap6256Reg(Regs, SDHC_ADMA_ERROR),
              Ap6256Reg(Regs, SDHC_ADMA_ADDR_HI), Ap6256Reg(Regs, SDHC_ADMA_ADDR_LO));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256DumpHostIdentity(_In_opt_ PUCHAR Regs)
{
    ULONG version;

    if (Regs == NULL) {
        TraceDiag("regs: SD host register block could not be mapped\n");
        return;
    }
    version = Ap6256Reg(Regs, SDHC_V5_MCI_VERSION);
    TraceDiag("regs identity:  mci_version=%08X (major %u minor 0x%02X) caps=%08X %08X vendor_caps=%08X\n",
              version, (version >> 28) & 0xF, version & 0xFF,
              Ap6256Reg(Regs, SDHC_CAPS_LO), Ap6256Reg(Regs, SDHC_CAPS_HI),
              Ap6256Reg(Regs, SDHC_V5_VENDOR_CAPS));
    TraceDiag("regs identity:  dll_cfg=%08X dll_status=%08X dll_cfg2=%08X dll_cfg3=%08X "
              "dll_usr_ctl=%08X vendor_spec=%08X ddr_cfg=%08X\n",
              Ap6256Reg(Regs, SDHC_V5_DLL_CONFIG), Ap6256Reg(Regs, SDHC_V5_DLL_STATUS),
              Ap6256Reg(Regs, SDHC_V5_DLL_CONFIG2), Ap6256Reg(Regs, SDHC_V5_DLL_CONFIG3),
              Ap6256Reg(Regs, SDHC_V5_DLL_USR_CTL), Ap6256Reg(Regs, SDHC_V5_VENDOR_SPEC),
              Ap6256Reg(Regs, SDHC_V5_DDR_CONFIG));
}

#define AP6256_BUSTEST_4B      0x01u
#define AP6256_BUSTEST_1BLK    0x02u
#define AP6256_BUSTEST_2BLK    0x04u
#define AP6256_BUSTEST_8BLK    0x08u
#define AP6256_BUSTEST_96BYTE  0x10u
#define AP6256_BUSTEST_128BYTE 0x20u
#define AP6256_BUSTEST_512BYTE 0x40u
#define AP6256_BUSTEST_ALL     0x0Fu
#define AP6256_BUSTEST_ALL_SHAPES 0x7Fu
#define AP6256_BUSTEST_MIN     (AP6256_BUSTEST_4B | AP6256_BUSTEST_1BLK)

static BOOLEAN Ap6256BufLooksValid(_In_reads_bytes_(Length) const UCHAR *Buf, _In_ ULONG Length)
{
    BOOLEAN anyZero = FALSE, anyOnes = FALSE;
    ULONG i;
    for (i = 0; i < Length; i++) {
        if (Buf[i] != 0x00) anyZero = TRUE;
        if (Buf[i] != 0xFF) anyOnes = TRUE;
    }
    return anyZero && anyOnes;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static ULONG Ap6256BusTestLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Label,
                                 _Inout_updates_bytes_(512) PUCHAR Buf,
                                 _In_opt_ PUCHAR Regs)
{
    static const struct {
        ULONG Offset;
        ULONG Length;
        ULONG Bit;
        BOOLEAN ByteMode;
        PCSTR What;
    } shapes[] = {

        { 0x0000, 4,   AP6256_BUSTEST_4B,      FALSE, "4 B byte" },
        { 0x0000, 64,  AP6256_BUSTEST_1BLK,    FALSE, "64 B 1 block" },
        { 0x0000, 128, AP6256_BUSTEST_2BLK,    FALSE, "128 B 2 blocks" },
        { 0x0000, 512, AP6256_BUSTEST_8BLK,    FALSE, "512 B 8 blocks" },
        { 0x0000, 96,  AP6256_BUSTEST_96BYTE,  TRUE,  "96 B byte" },
        { 0x0000, 128, AP6256_BUSTEST_128BYTE, TRUE,  "128 B byte" },
        { 0x0000, 512, AP6256_BUSTEST_512BYTE, TRUE,  "512 B byte" },
    };
    ULONG passed = 0;
    ULONG i;
    NTSTATUS status;

    status = Ap6256SetWindowLocked(Ctx, 0x18000000);
    if (!NT_SUCCESS(status)) {
        TraceDiag("bus test %s: window set failed 0x%08X\n", Label, status);
        return 0;
    }
    for (i = 0; i < RTL_NUMBER_OF(shapes); i++) {
        BOOLEAN valid = FALSE;
        if (shapes[i].Length > 512) {
            continue;
        }
        RtlZeroMemory(Buf, 512);
        Ctx->Sdio.ForceByteMode = shapes[i].ByteMode;
        status = Ap6256SdBusCmd53(Ctx, FALSE, 1,
                                  shapes[i].Offset | SBSDIO_SB_ACCESS_2_4B_FLAG,
                                  TRUE, Buf, shapes[i].Length);
        Ctx->Sdio.ForceByteMode = FALSE;
        if (NT_SUCCESS(status)) {
            valid = Ap6256BufLooksValid(Buf, shapes[i].Length);
        }
        TraceDiag("bus test %s: %-14s -> 0x%08X  %02X %02X %02X %02X %s\n",
                  Label, shapes[i].What, status, Buf[0], Buf[1], Buf[2], Buf[3],
                  NT_SUCCESS(status) ? (valid ? "ok" : "NO DATA") : "");
        Ap6256DumpHostRegisters(Regs, shapes[i].What);
        if (valid) {
            passed |= shapes[i].Bit;
        } else {

            TraceDiag("bus test %s: stopping after the first failure\n", Label);
            break;
        }
    }
    return passed;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioBusFallback(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    NTSTATUS result = STATUS_DEVICE_NOT_READY;
    PUCHAR buf;
    ULONG clock = 0;
    UCHAR width = 0;
    ULONG first, second, passed;
    PUCHAR regs;

    buf = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, 512, AP6256_POOL_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Ap6256LockAcquire(&Ctx->Sdio.Lock);

    status = Ap6256SdBusGetBusClock(Ctx, &clock);
    TraceDiag("bus test: SDP_BUS_CLOCK get -> 0x%08X value %u (kHz)\n", status, clock);
    status = Ap6256SdBusGetBusWidth(Ctx, &width);
    TraceDiag("bus test: SDP_BUS_WIDTH get -> 0x%08X value %u\n", status, width);

    regs = Ap6256SdioMapHostRegisters();
    Ap6256DumpHostIdentity(regs);
    Ap6256DumpHostRegisters(regs, "before");

    first = Ap6256BusTestLocked(Ctx, "pass 1", buf, regs);

    second = (first == AP6256_BUSTEST_ALL_SHAPES)
           ? Ap6256BusTestLocked(Ctx, "pass 2", buf, regs)
           : first;
    passed = first & second;

    if (passed == AP6256_BUSTEST_ALL) {
        result = STATUS_SUCCESS;
    } else if ((passed & AP6256_BUSTEST_MIN) == AP6256_BUSTEST_MIN) {

        Ctx->Sdio.MaxBlocksPerCmd53 = (passed & AP6256_BUSTEST_2BLK) ? 2u : 1u;
        result = STATUS_SUCCESS;
    }
    TraceDiag("bus test: result 0x%08X (passed 0x%X/0x%X, clock %u kHz, width %u, max blocks %u)\n",
              result, first, second, clock, width, Ctx->Sdio.MaxBlocksPerCmd53);
    if (!NT_SUCCESS(result)) {
        TraceDiag("bus test: no usable data phase at %u kHz. A read that SUCCEEDS with an"
                  " all-zero buffer means the DMA landed outside the CPU's view (ACPI _CCA"
                  " vs IORT coherency for SDC2); a read that TIMES OUT means the host could"
                  " not clock the data phase (PEP gcc_sdcc2_apps_clk rate).\n", clock);
    }

    Ap6256SdioUnmapHostRegisters(regs);
    Ap6256LockRelease(&Ctx->Sdio.Lock);
    ExFreePoolWithTag(buf, AP6256_POOL_TAG);
    return result;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioEnableBackplaneClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN WantHt)
{
    NTSTATUS status;
    UCHAR clkctl;
    UCHAR want = SBSDIO_ALP_AVAIL_REQ;
    UCHAR avail = SBSDIO_ALP_AVAIL;
    int retries;

    if (WantHt) {
        want = SBSDIO_HT_AVAIL_REQ;
        avail = SBSDIO_HT_AVAIL;
    }

    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR,
                               (UCHAR)(SBSDIO_FORCE_HW_CLKREQ_OFF | want));
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (retries = 0; retries < 500; retries++) {
        status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, &clkctl);
        if (NT_SUCCESS(status) && (clkctl & avail)) {
            Ctx->Sdio.ClockOn = TRUE;
            TraceVerbose(TRACE_SDIO, "backplane clock ready (csr=0x%02X)\n", clkctl);
            return STATUS_SUCCESS;
        }
        Ap6256StallUs(100);
    }

    TraceError(TRACE_SDIO, "timed out waiting for %s clock (csr=0x%02X)\n",
               WantHt ? "HT" : "ALP", clkctl);
    return STATUS_DEVICE_NOT_READY;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioDisableBackplaneClock(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;

    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, 0);
    if (NT_SUCCESS(status)) {
        Ctx->Sdio.ClockOn = FALSE;
    }
    return status;
}

#define AP6256_RXFAIL_FLUSH_LOOKS   2048u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioRxFail(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                      _In_ BOOLEAN Abort,
                      _In_ BOOLEAN RequestRetransmit)
{
    UCHAR frameCtrl = SFC_RF_TERM;
    ULONG attempt;
    ULONG count = 0;
    ULONG firstCount = 0;
    ULONG lastCount = 0xffffu;
    BOOLEAN zeroed = FALSE;
    BOOLEAN unreadable = FALSE;
    BOOLEAN nakSent = FALSE;

    Ap6256LockAcquire(&Ctx->Sdio.Lock);

    if (Abort) {
        (VOID)Ap6256SdBusAbortFunction(Ctx, (UCHAR)AP6256_SDIO_FUNC_DATA);
    }

    (VOID)Ap6256SdBusCmd52(Ctx, TRUE, (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                           SBSDIO_FUNC1_FRAMECTRL, &frameCtrl);

    for (attempt = 0; attempt < AP6256_RXFAIL_FLUSH_LOOKS; attempt++) {
        UCHAR hi = 0, lo = 0;

        if (!NT_SUCCESS(Ap6256SdBusCmd52(Ctx, FALSE,
                                         (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                                         SBSDIO_FUNC1_RFRAMEBCHI, &hi)) ||
            !NT_SUCCESS(Ap6256SdBusCmd52(Ctx, FALSE,
                                         (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                                         SBSDIO_FUNC1_RFRAMEBCLO, &lo))) {
            unreadable = TRUE;
            break;
        }
        count = ((ULONG)hi << 8) | lo;
        if (attempt == 0) {
            firstCount = count;
        }
        if (count == 0) {
            zeroed = TRUE;
            break;
        }
        if (count > lastCount) {
            TraceWarn(TRACE_SDIO,
                      "receive frame byte count growing: last %u now %u\n",
                      lastCount, count);
        }
        lastCount = count;
    }
    if (unreadable) {
        TraceError(TRACE_SDIO, "receive frame byte count unreadable after "
                   "terminate (look %u)\n", attempt);
    } else if (!zeroed) {
        TraceError(TRACE_SDIO, "receive frame terminate left %u byte(s) in "
                   "the FIFO after %u look(s)\n", count, attempt);
    } else if (attempt != 0) {
        TraceVerbose(TRACE_SDIO, "receive frame flush took %u look(s)\n",
                     attempt);
    }

    if (RequestRetransmit && Ctx->Chip.SdiodCore != NULL &&
        NT_SUCCESS(Ap6256SdioWriteBackplane32(
            Ctx, Ctx->Chip.SdiodCore->Base + SD_REG_TOSBMAILBOX, SMB_NAK))) {
        nakSent = TRUE;
        Ctx->RxSkip = TRUE;
        Ctx->RxSkipSince = KeQueryInterruptTime();
    }

    Ap6256LockRelease(&Ctx->Sdio.Lock);

    TraceWarn(TRACE_SDIO, "receive frame terminated (%u byte(s) pending, "
              "%u look(s))%s\n", firstCount, attempt,
              nakSent ? "; retransmission requested" : "");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioTxFail(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR frameCtrl = SFC_WF_TERM;
    ULONG attempt;

    Ap6256LockAcquire(&Ctx->Sdio.Lock);

    (VOID)Ap6256SdBusAbortFunction(Ctx, (UCHAR)AP6256_SDIO_FUNC_DATA);
    (VOID)Ap6256SdBusCmd52(Ctx, TRUE, (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                           SBSDIO_FUNC1_FRAMECTRL, &frameCtrl);

    for (attempt = 0; attempt < 3; attempt++) {
        UCHAR hi = 0, lo = 0;

        if (!NT_SUCCESS(Ap6256SdBusCmd52(Ctx, FALSE,
                                         (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                                         SBSDIO_FUNC1_WFRAMEBCHI, &hi)) ||
            !NT_SUCCESS(Ap6256SdBusCmd52(Ctx, FALSE,
                                         (UCHAR)AP6256_SDIO_FUNC_BACKPLANE,
                                         SBSDIO_FUNC1_WFRAMEBCLO, &lo))) {
            break;
        }
        if (hi == 0 && lo == 0) break;
        if (attempt == 2) {
            TraceWarn(TRACE_SDIO,
                      "transmit frame terminate left %u byte(s) unwritten\n",
                      ((ULONG)hi << 8) | lo);
        }
    }

    Ap6256LockRelease(&Ctx->Sdio.Lock);
    TraceWarn(TRACE_SDIO, "transmit frame terminated\n");
}

#define AP6256_BUS_STATS_PERIOD_MS  5000u

static LONGLONG Ap6256StatTake(_Inout_ volatile LONGLONG* Counter)
{
    return InterlockedExchange64(Counter, 0);
}

static LONGLONG Ap6256StatAverage(_In_ LONGLONG Total, _In_ LONGLONG Count)
{
    return (Count != 0) ? Total / Count : 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdioTraceBusStats(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONGLONG now = KeQueryInterruptTime();
    ULONGLONG elapsedMs;
    LONGLONG hdrReads, hdrUs, bodyReads, bodyBytes, bodyUs;
    LONGLONG writes, writeBytes, writeUs, other, otherUs, rxFrames, txFrames;
    LONGLONG passes, emptyPolls;
    LONG isrNow, isrDelta;

    if (Ctx->Sdio.StatPrintedAt == 0) {
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatHdrReads);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatHdrReadUs);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatBodyReads);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatBodyReadBytes);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatBodyReadUs);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatWrites);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatWriteBytes);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatWriteUs);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatOtherCmd53);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatOtherUs);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatRxFrames);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatTxFrames);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatPasses);
        (VOID)Ap6256StatTake(&Ctx->Sdio.StatEmptyPolls);
        Ctx->Sdio.StatIsrSnapshot = InterlockedCompareExchange(&Ctx->Sdio.IsrCount, 0, 0);
        Ctx->Sdio.StatPrintedAt = now;
        return;
    }
    elapsedMs = (now - Ctx->Sdio.StatPrintedAt) / 10000u;
    if (elapsedMs < AP6256_BUS_STATS_PERIOD_MS) {
        return;
    }
    Ctx->Sdio.StatPrintedAt = now;

    hdrReads   = Ap6256StatTake(&Ctx->Sdio.StatHdrReads);
    hdrUs      = Ap6256StatTake(&Ctx->Sdio.StatHdrReadUs);
    bodyReads  = Ap6256StatTake(&Ctx->Sdio.StatBodyReads);
    bodyBytes  = Ap6256StatTake(&Ctx->Sdio.StatBodyReadBytes);
    bodyUs     = Ap6256StatTake(&Ctx->Sdio.StatBodyReadUs);
    writes     = Ap6256StatTake(&Ctx->Sdio.StatWrites);
    writeBytes = Ap6256StatTake(&Ctx->Sdio.StatWriteBytes);
    writeUs    = Ap6256StatTake(&Ctx->Sdio.StatWriteUs);
    other      = Ap6256StatTake(&Ctx->Sdio.StatOtherCmd53);
    otherUs    = Ap6256StatTake(&Ctx->Sdio.StatOtherUs);
    rxFrames   = Ap6256StatTake(&Ctx->Sdio.StatRxFrames);
    txFrames   = Ap6256StatTake(&Ctx->Sdio.StatTxFrames);
    passes     = Ap6256StatTake(&Ctx->Sdio.StatPasses);
    emptyPolls = Ap6256StatTake(&Ctx->Sdio.StatEmptyPolls);
    isrNow     = InterlockedCompareExchange(&Ctx->Sdio.IsrCount, 0, 0);
    isrDelta   = isrNow - Ctx->Sdio.StatIsrSnapshot;
    Ctx->Sdio.StatIsrSnapshot = isrNow;

    if (rxFrames == 0 && txFrames == 0 && bodyReads == 0 && writes == 0) {
        return;
    }
    TraceInfo(TRACE_SDIO,
              "bus %I64u ms: rx %I64d frame(s) in %I64d header read(s) "
              "(%I64d us avg) + %I64d frame read(s) %I64d KB (%I64d us avg); "
              "tx %I64d frame(s) in %I64d write(s) %I64d KB (%I64d us avg); "
              "%I64d other CMD53 (%I64d us avg); bus busy %I64d ms; "
              "%d interrupt(s), %I64d pass(es), %I64d empty poll(s)\n",
              elapsedMs, rxFrames, hdrReads, Ap6256StatAverage(hdrUs, hdrReads),
              bodyReads, bodyBytes / 1024, Ap6256StatAverage(bodyUs, bodyReads),
              txFrames, writes, writeBytes / 1024,
              Ap6256StatAverage(writeUs, writes),
              other, Ap6256StatAverage(otherUs, other),
              (hdrUs + bodyUs + writeUs + otherUs) / 1000,
              isrDelta, passes, emptyPolls);
}

_IRQL_requires_max_(APC_LEVEL)
static UCHAR Ap6256SdioPeek(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function,
                            _In_ ULONG Address, _Inout_ PULONG Failed)
{
    UCHAR value = 0;

    if (!NT_SUCCESS(Ap6256SdBusCmd52(Ctx, FALSE, Function, Address, &value))) {
        (*Failed)++;
        return 0xFF;
    }
    return value;
}

_IRQL_requires_max_(APC_LEVEL)
VOID Ap6256SdioDumpCardState(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Label)
{
    ULONG failed = 0;
    UCHAR ioEnable, ioReady, intEnable, intPending, busSpeed;
    UCHAR fn1Low, fn1High, fn2Low, fn2High;
    UCHAR clockCsr, deviceControl, watermark, mesBusy, sleepCsr;
    UCHAR frameControl, readCountLow, readCountHigh;
    UINT8 txSeq, maxTxSeq, flowControl;
    BOOLEAN flowStopped;
    KIRQL irql;

    ioEnable      = Ap6256SdioPeek(Ctx, 0, 0x02, &failed);
    ioReady       = Ap6256SdioPeek(Ctx, 0, 0x03, &failed);
    intEnable     = Ap6256SdioPeek(Ctx, 0, 0x04, &failed);
    intPending    = Ap6256SdioPeek(Ctx, 0, 0x05, &failed);
    busSpeed      = Ap6256SdioPeek(Ctx, 0, 0x13, &failed);
    fn1Low        = Ap6256SdioPeek(Ctx, 0, 0x110, &failed);
    fn1High       = Ap6256SdioPeek(Ctx, 0, 0x111, &failed);
    fn2Low        = Ap6256SdioPeek(Ctx, 0, 0x210, &failed);
    fn2High       = Ap6256SdioPeek(Ctx, 0, 0x211, &failed);
    clockCsr      = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_CHIPCLKCSR, &failed);
    deviceControl = Ap6256SdioPeek(Ctx, 1, SBSDIO_DEVICE_CTL, &failed);
    watermark     = Ap6256SdioPeek(Ctx, 1, SBSDIO_WATERMARK, &failed);
    mesBusy       = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_MESBUSYCTRL, &failed);
    sleepCsr      = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_SLEEPCSR, &failed);
    frameControl  = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_FRAMECTRL, &failed);
    readCountLow  = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_RFRAMEBCLO, &failed);
    readCountHigh = Ap6256SdioPeek(Ctx, 1, SBSDIO_FUNC1_RFRAMEBCHI, &failed);

    KeAcquireSpinLock(&Ctx->Sdio.TxStateLock, &irql);
    txSeq = Ctx->Sdio.TxSeq;
    maxTxSeq = Ctx->Sdio.MaxTxSeq;
    flowControl = Ctx->Sdio.FlowControl;
    flowStopped = Ctx->Sdio.TxFlowStopped;
    KeReleaseSpinLock(&Ctx->Sdio.TxStateLock, irql);

    TraceDiag("%s card: CCCR IOE 0x%02X IOR 0x%02X IEN 0x%02X INTPEND 0x%02X "
              "SPEED 0x%02X; FBR block fn1 %u fn2 %u; host block %u; isr %d; "
              "%u register read(s) failed\n",
              Label, (ULONG)ioEnable, (ULONG)ioReady, (ULONG)intEnable,
              (ULONG)intPending, (ULONG)busSpeed,
              (ULONG)fn1Low | ((ULONG)fn1High << 8),
              (ULONG)fn2Low | ((ULONG)fn2High << 8),
              Ctx->Sdio.HostBlockLength, Ctx->Sdio.IsrCount, failed);
    TraceDiag("%s dongle: CHIPCLKCSR 0x%02X DEVCTL 0x%02X WATERMARK 0x%02X "
              "MESBUSYCTRL 0x%02X SLEEPCSR 0x%02X FRAMECTRL 0x%02X read frame "
              "%u byte(s) left; tx seq %u ceiling %u flow 0x%02X stopped %u\n",
              Label, (ULONG)clockCsr, (ULONG)deviceControl, (ULONG)watermark,
              (ULONG)mesBusy, (ULONG)sleepCsr, (ULONG)frameControl,
              (ULONG)readCountLow | ((ULONG)readCountHigh << 8),
              (ULONG)txSeq, (ULONG)maxTxSeq, (ULONG)flowControl,
              (ULONG)flowStopped);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioInitializeRetention(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_CORE cc = Ctx->Chip.ChipCommon, pmu;
    UINT32 caps, ext, pmucaps, selector, control = 0;
    UCHAR wake, card, clock, sleep;
    NTSTATUS status, restore;
    if (Ctx->Sdio.RetentionInitialized) return STATUS_SUCCESS;
    Ctx->Sdio.SaveRestoreEnabled = FALSE;
    if (cc == NULL) return STATUS_DEVICE_NOT_READY;
    status = Ap6256SdioReadBackplane32(Ctx, cc->Base + CC_CAPABILITIES, &caps);
    if (!NT_SUCCESS(status)) return status;
    if ((caps & CC_CAP_PMU) == 0) goto no_sr;
    status = Ap6256SdioReadBackplane32(Ctx, cc->Base + CC_CAPABILITIES_EXT, &ext);
    if (!NT_SUCCESS(status)) return status;
    pmu = cc;
    if (cc->Rev >= 35 && (ext & 0x40u) != 0) {
        pmu = Ap6256ChipGetCore(&Ctx->Chip, 0x827u);
        if (pmu == NULL) return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    status = Ap6256SdioReadBackplane32(Ctx, pmu->Base + CC_PMU_CAPABILITIES, &pmucaps);
    if (!NT_SUCCESS(status)) return status;
    Ctx->Chip.CcCaps = caps;
    Ctx->Chip.PmuCaps = pmucaps;
    Ctx->Chip.PmuRev = pmucaps & 0xffu;
    if (Ctx->Chip.PmuRev < 17 ||
        (Ctx->Chip.ChipId != BRCM_CC_4345_CHIP_ID &&
         Ctx->Chip.ChipId != BRCM_CC_43454_CHIP_ID)) goto no_sr;
    status = Ap6256SdioReadBackplane32(Ctx, pmu->Base + CC_CHIPCONTROL_ADDR, &selector);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioWriteBackplane32(Ctx, pmu->Base + CC_CHIPCONTROL_ADDR, 3);
    if (NT_SUCCESS(status))
        status = Ap6256SdioReadBackplane32(Ctx, pmu->Base + CC_CHIPCONTROL_DATA, &control);
    restore = Ap6256SdioWriteBackplane32(Ctx, pmu->Base + CC_CHIPCONTROL_ADDR, selector);
    if (!NT_SUCCESS(status)) return status;
    if (!NT_SUCCESS(restore)) return restore;
    if ((control & 4u) == 0) goto no_sr;
    status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_WAKEUPCTRL, &wake);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioReadF0(Ctx, SDIO_CCCR_BRCM_CARDCAP, &card);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, &clock);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_SLEEPCSR, &sleep);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SLEEPCSR,
                              (UCHAR)(sleep | SBSDIO_FUNC1_SLEEPCSR_KSO_EN));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_WAKEUPCTRL, (UCHAR)(wake | 2u));
    if (NT_SUCCESS(status))
        status = Ap6256SdioWriteF0(Ctx, SDIO_CCCR_BRCM_CARDCAP,
            SDIO_CCCR_BRCM_CARDCAP_CMD14_SUPPORT | SDIO_CCCR_BRCM_CARDCAP_CMD14_EXT);
    if (NT_SUCCESS(status))
        status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, SBSDIO_FORCE_HT);
    if (!NT_SUCCESS(status)) {
        (VOID)Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_WAKEUPCTRL, wake);
        (VOID)Ap6256SdioWriteF0(Ctx, SDIO_CCCR_BRCM_CARDCAP, card);
        (VOID)Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, clock);
        return status;
    }
    Ctx->Sdio.SaveRestoreEnabled = TRUE;
no_sr:
    Ctx->Sdio.RetentionInitialized = TRUE;
    TraceInfo(TRACE_POWER, "SDIO retention: save/restore %u, PMU rev %u\n",
              (ULONG)Ctx->Sdio.SaveRestoreEnabled, Ctx->Chip.PmuRev);
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256SdioSetKso(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN On)
{
    UCHAR request = On ? SBSDIO_FUNC1_SLEEPCSR_KSO_EN : 0;
    UCHAR mask = On ? (SBSDIO_FUNC1_SLEEPCSR_KSO_MASK |
                      SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK) : SBSDIO_FUNC1_SLEEPCSR_KSO_MASK;
    UCHAR expected = On ? mask : 0, value = 0;
    ULONG attempt;
    NTSTATUS status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SLEEPCSR, request);
    if (!NT_SUCCESS(status)) return status;
    if (On) Ap6256StallUs(2000);
    for (attempt = 0; attempt < 20000; ++attempt) {
        status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_SLEEPCSR, &value);
        if (!NT_SUCCESS(status)) return status;
        if ((value & mask) == expected) return STATUS_SUCCESS;
        Ap6256StallUs(50);
        status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_SLEEPCSR, request);
        if (!NT_SUCCESS(status)) return status;
    }
    TraceError(TRACE_POWER, "SDIO KSO %u timed out, sleepcsr 0x%02X\n", (ULONG)On, value);
    return STATUS_IO_TIMEOUT;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetSleep(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Sleep)
{
    NTSTATUS status;
    UCHAR clock;
    if (Sleep == Ctx->Sdio.Sleeping) return STATUS_SUCCESS;
    if (Sleep) {
        status = Ap6256SdioInitializeRetention(Ctx);
        if (!NT_SUCCESS(status)) return status;
        status = Ap6256SdioReadF0(Ctx, SDIO_CCCR_BRCM_SEPINT, &Ctx->Sdio.AwakeSepInt);
        if (!NT_SUCCESS(status)) return status;
        Ctx->Sdio.SepIntSaved = TRUE;
        Ctx->Sdio.Sleeping = TRUE;

        status = Ap6256SdioWriteF0(Ctx, SDIO_CCCR_BRCM_SEPINT,
            SDIO_CCCR_BRCM_SEPINT_MASK | SDIO_CCCR_BRCM_SEPINT_OE | SDIO_CCCR_BRCM_SEPINT_ACT_HI);
        if (!NT_SUCCESS(status)) return status;

        Ctx->Sdio.Sleeping = TRUE;
        if (Ctx->Sdio.SaveRestoreEnabled) {
            status = Ap6256SdioReadF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, &clock);
            if (NT_SUCCESS(status) && (clock & 0x3fu) == 0)
                status = Ap6256SdioWriteF1(Ctx, SBSDIO_FUNC1_CHIPCLKCSR, SBSDIO_ALP_AVAIL_REQ);
            if (NT_SUCCESS(status)) status = Ap6256SdioSetKso(Ctx, FALSE);
        } else status = Ap6256SdioDisableBackplaneClock(Ctx);
        if (NT_SUCCESS(status)) Ctx->Sdio.ClockOn = FALSE;
    } else {
        status = Ctx->Sdio.SaveRestoreEnabled ? Ap6256SdioSetKso(Ctx, TRUE) : STATUS_SUCCESS;
        Ctx->Sdio.ClockOn = FALSE;
        if (NT_SUCCESS(status)) status = Ap6256SdioEnableBackplaneClock(Ctx, TRUE);
        if (NT_SUCCESS(status) && Ctx->Sdio.SepIntSaved)
            status = Ap6256SdioWriteF0(Ctx, SDIO_CCCR_BRCM_SEPINT, Ctx->Sdio.AwakeSepInt);
        if (NT_SUCCESS(status)) {
            Ctx->Sdio.BackplaneWindow = MAXULONG;
            Ctx->Sdio.Sleeping = FALSE;
            Ctx->Sdio.SepIntSaved = FALSE;
        }
    }
    return status;
}
