/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sdio.h"
#include "datapath.h"

#include <initguid.h>
#include <ntddsd.h>

#define SDIFACE(Ctx)  ((PSDBUS_INTERFACE_STANDARD)(Ctx)->Sdio.BusInterface)

#define AP6256_CMD53_MAX_TRANSFER   (32u * 1024u)
#define AP6256_CMD53_START_TRANSFER (8u * 1024u)

#define AP6256_CMD53_START_TRANSFER_DATA AP6256_CMD53_MAX_TRANSFER

_Function_class_(SDBUS_CALLBACK_ROUTINE)
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID Ap6256SdBusIsrCallback(_In_ PVOID Context, _In_ ULONG InterruptType)
{
    PAP6256_DEVICE_CONTEXT ctx = (PAP6256_DEVICE_CONTEXT)Context;

    UNREFERENCED_PARAMETER(InterruptType);

    InterlockedIncrement(&ctx->Sdio.IsrCount);
    Ap6256DatapathOnInterrupt(ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusAcquireInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    PSDBUS_INTERFACE_STANDARD iface;
    SDBUS_INTERFACE_PARAMETERS params;
    PDEVICE_OBJECT pdo;

    if (Ctx->Sdio.BusInterface != NULL) {
        return STATUS_DEVICE_BUSY;
    }

    iface = (PSDBUS_INTERFACE_STANDARD)ExAllocatePool2(
                POOL_FLAG_NON_PAGED, sizeof(SDBUS_INTERFACE_STANDARD), AP6256_POOL_TAG);
    if (iface == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    pdo = Ctx->Pdo;
    status = SdBusOpenInterface(pdo, iface, sizeof(SDBUS_INTERFACE_STANDARD),
                                SDBUS_INTERFACE_VERSION);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_SDIO, "SdBusOpenInterface failed 0x%08X\n", status);
        ExFreePoolWithTag(iface, AP6256_POOL_TAG);
        return status;
    }

    Ctx->Sdio.BusInterface = iface;
    Ctx->Sdio.BusInterfaceContext = iface->Context;

    RtlZeroMemory(&params, sizeof(params));
    params.Size = sizeof(params);
    params.SdioFlags = 0;
    params.TargetObject = Ctx->NextDevice;
    params.DeviceGeneratesInterrupts = TRUE;
    params.CallbackAtDpcLevel = TRUE;
    params.CallbackRoutine = Ap6256SdBusIsrCallback;
    params.CallbackRoutineContext = Ctx;

    status = iface->InitializeInterface(iface->Context, &params);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_SDIO, "InitializeInterface failed 0x%08X\n", status);
        iface->InterfaceDereference(iface->Context);
        ExFreePoolWithTag(iface, AP6256_POOL_TAG);
        Ctx->Sdio.BusInterface = NULL;
        Ctx->Sdio.BusInterfaceContext = NULL;
        return status;
    }

    TraceInfo(TRACE_SDIO, "SD bus interface ready (ver 0x%X)\n", iface->Version);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SdBusReleaseInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    if (iface != NULL) {
        if (iface->InterfaceDereference != NULL) {
            iface->InterfaceDereference(iface->Context);
        }
        ExFreePoolWithTag(iface, AP6256_POOL_TAG);
        Ctx->Sdio.BusInterface = NULL;
        Ctx->Sdio.BusInterfaceContext = NULL;
    }

    if (Ctx->Sdio.Bounce != NULL) {
        ExFreePoolWithTag(Ctx->Sdio.Bounce, AP6256_POOL_TAG);
        Ctx->Sdio.Bounce = NULL;
        Ctx->Sdio.BounceSize = 0;
    }
    InterlockedExchange(&Ctx->Sdio.BounceBusy, 0);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd52(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN Write, _In_ UCHAR Function,
                          _In_ ULONG Address, _Inout_ PUCHAR Data)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    SDBUS_REQUEST_PACKET packet;
    SD_RW_DIRECT_ARGUMENT arg;
    NTSTATUS status;
    const SDCMD_DESCRIPTOR desc = {
        SDCMD_IO_RW_DIRECT, SDCC_STANDARD,
        Write ? SDTD_WRITE : SDTD_READ, SDTT_CMD_ONLY, SDRT_5
    };

    if (iface == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    arg.u.AsULONG = 0;
    arg.u.bits.Function = Function & 0x7;
    arg.u.bits.Address = Address & 0x1FFFF;
    arg.u.bits.WriteToDevice = Write ? 1 : 0;
    if (Write) {
        arg.u.bits.Data = *Data;
    }

    RtlZeroMemory(&packet, sizeof(packet));
    packet.RequestFunction = SDRF_DEVICE_COMMAND;
    packet.Parameters.DeviceCommand.CmdDesc = desc;
    packet.Parameters.DeviceCommand.Argument = arg.u.AsULONG;

    status = SdBusSubmitRequest(iface->Context, &packet);
    if (NT_SUCCESS(status) && !Write) {

        *Data = (UCHAR)(packet.ResponseData.AsULONG[0] & 0xFF);
    }
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS Ap6256SdBusEnsureHostBlockLength(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                 _In_ ULONG Length);
_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusAbortFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256SdBusProperty(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Set,
                                    _In_ SDBUS_PROPERTY Property,
                                    _Inout_updates_bytes_(Length) PVOID Buffer,
                                    _In_ ULONG Length);

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd53Mode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ BOOLEAN Write, _In_ UCHAR Function,
                              _In_ ULONG Address, _In_ BOOLEAN Incrementing,
                              _Inout_updates_bytes_(Length) PUCHAR Buffer,
                              _In_ ULONG Length,
                              _In_ BOOLEAN ByteMode)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG blockSize = (Function == 2) ? Ctx->Sdio.Function2BlockSize
                                       : Ctx->Sdio.Function1BlockSize;
    ULONG remaining = Length;
    ULONG address = Address;
    PUCHAR cursor = Buffer;

    if (iface == NULL || Function > 7 || Address > 0x1FFFF) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    if (Length == 0) {
        return STATUS_SUCCESS;
    }

    while (remaining != 0) {
        SDBUS_REQUEST_PACKET packet;
        SD_RW_EXTENDED_ARGUMENT arg;
        SDCMD_DESCRIPTOR desc;
        BOOLEAN blockMode = FALSE;
        ULONG count;
        ULONG chunk;
        ULONG maxBlockBytes;
        ULONG maxBlocks;
        PUCHAR bounce;
        BOOLEAN bounceCached = FALSE;
        PMDL mdl;
        SIZE_T bounceSize;
        LARGE_INTEGER submitStart = {0}, submitEnd = {0}, submitFrequency = {0};
        BOOLEAN traceStats = Ap6256TraceInformationEnabled(TRACE_SDIO | TRACE_DRIVER);
        LONGLONG submitUs = 0;
        ULONG cacheAlign;
        ULONG mdlLength;

        if (Ctx->Sdio.MaxTransferBytes[Function] == 0) {
            Ctx->Sdio.MaxTransferBytes[Function] =
                (Function == AP6256_SDIO_FUNC_DATA) ? AP6256_CMD53_START_TRANSFER_DATA
                                                    : AP6256_CMD53_START_TRANSFER;
        }
        maxBlocks = (Ctx->Sdio.MaxBlocksPerCmd53 != 0 && Ctx->Sdio.MaxBlocksPerCmd53 <= 511u)
                  ? Ctx->Sdio.MaxBlocksPerCmd53 : 511u;
        maxBlockBytes = (blockSize != 0 && blockSize <= 512)
                      ? min(maxBlocks * blockSize, AP6256_CMD53_MAX_TRANSFER)
                      : 0;
        if (maxBlockBytes > Ctx->Sdio.MaxTransferBytes[Function]) {

            maxBlockBytes = Ctx->Sdio.MaxTransferBytes[Function]
                          - (Ctx->Sdio.MaxTransferBytes[Function] % blockSize);
            if (maxBlockBytes == 0) {
                maxBlockBytes = blockSize;
            }
        }

        if (!ByteMode && !Ctx->Sdio.ForceByteMode && maxBlockBytes != 0 &&
            remaining >= 2u * blockSize) {
            chunk = min((remaining / blockSize) * blockSize, maxBlockBytes);
            blockMode = TRUE;
            count = chunk / blockSize;
        } else {
            chunk = min(remaining, 512u);
            count = chunk;
        }
        if (chunk == 0 || chunk > remaining) {
            return STATUS_INTEGER_OVERFLOW;
        }
        __analysis_assume(chunk <= remaining);

        status = Ap6256SdBusEnsureHostBlockLength(Ctx, blockMode ? blockSize : chunk);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        bounceSize = ROUND_TO_PAGES(chunk);
        bounce = NULL;
        if (InterlockedCompareExchange(&Ctx->Sdio.BounceBusy, 1, 0) == 0) {
            if (Ctx->Sdio.Bounce == NULL) {
                Ctx->Sdio.BounceSize = ROUND_TO_PAGES(AP6256_CMD53_MAX_TRANSFER);
                Ctx->Sdio.Bounce = (PUCHAR)ExAllocatePool2(
                    POOL_FLAG_NON_PAGED, Ctx->Sdio.BounceSize, AP6256_POOL_TAG);
            }
            if (Ctx->Sdio.Bounce != NULL && Ctx->Sdio.BounceSize >= bounceSize) {
                bounce = Ctx->Sdio.Bounce;
                bounceSize = Ctx->Sdio.BounceSize;
                bounceCached = TRUE;
            } else {
                InterlockedExchange(&Ctx->Sdio.BounceBusy, 0);
            }
        }
        if (bounce == NULL) {
            bounce = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, bounceSize,
                                             AP6256_POOL_TAG);
            if (bounce == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        __analysis_assume(bounceSize >= chunk);

        cacheAlign = KeGetRecommendedSharedDataAlignment();
        if (cacheAlign == 0) {
            cacheAlign = 64;
        }
        mdlLength = (ULONG)((chunk + cacheAlign - 1) & ~((SIZE_T)cacheAlign - 1));
        if ((SIZE_T)mdlLength > bounceSize) {
            mdlLength = (ULONG)bounceSize;
        }
        __analysis_assume(mdlLength >= chunk);

        if (Write) {
            RtlCopyMemory(bounce, cursor, chunk);
            RtlZeroMemory(bounce + chunk, mdlLength - chunk);
        } else {
            RtlZeroMemory(bounce, mdlLength);
        }

        mdl = IoAllocateMdl(bounce, mdlLength, FALSE, FALSE, NULL);
        if (mdl == NULL) {
            if (bounceCached) {
                InterlockedExchange(&Ctx->Sdio.BounceBusy, 0);
            } else {
                ExFreePoolWithTag(bounce, AP6256_POOL_TAG);
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        MmBuildMdlForNonPagedPool(mdl);

        if (Write) {
            KeFlushIoBuffers(mdl, FALSE, TRUE);
        }

        desc.Cmd = SDCMD_IO_RW_EXTENDED;
        desc.CmdClass = SDCC_STANDARD;
        desc.TransferDirection = Write ? SDTD_WRITE : SDTD_READ;

        desc.TransferType = (blockMode && count > 1) ? SDTT_MULTI_BLOCK_NO_CMD12 : SDTT_SINGLE_BLOCK;
        desc.ResponseType = SDRT_5;

        arg.u.AsULONG = 0;
        arg.u.bits.Function = Function;
        arg.u.bits.Address = address;
        arg.u.bits.OpCode = Incrementing ? 1 : 0;
        arg.u.bits.BlockMode = blockMode ? 1 : 0;
        arg.u.bits.Count = (!blockMode && count == 512) ? 0 : count;
        arg.u.bits.WriteToDevice = Write ? 1 : 0;

        RtlZeroMemory(&packet, sizeof(packet));
        packet.RequestFunction = SDRF_DEVICE_COMMAND;
        packet.Parameters.DeviceCommand.CmdDesc = desc;
        packet.Parameters.DeviceCommand.Argument = arg.u.AsULONG;
        packet.Parameters.DeviceCommand.Mdl = mdl;
        packet.Parameters.DeviceCommand.Length = chunk;

        if (traceStats) submitStart = KeQueryPerformanceCounter(&submitFrequency);
        status = SdBusSubmitRequest(iface->Context, &packet);
        if (traceStats) submitEnd = KeQueryPerformanceCounter(NULL);

        if (traceStats) {
            submitUs = (submitFrequency.QuadPart != 0)
                ? (LONGLONG)((submitEnd.QuadPart - submitStart.QuadPart) * 1000000
                             / submitFrequency.QuadPart)
                : 0;

            if (Function == AP6256_SDIO_FUNC_DATA && Write) {
                InterlockedIncrement64(&Ctx->Sdio.StatWrites);
                InterlockedAdd64(&Ctx->Sdio.StatWriteBytes, (LONGLONG)chunk);
                InterlockedAdd64(&Ctx->Sdio.StatWriteUs, submitUs);
            } else if (Function == AP6256_SDIO_FUNC_DATA && ByteMode) {
                InterlockedIncrement64(&Ctx->Sdio.StatHdrReads);
                InterlockedAdd64(&Ctx->Sdio.StatHdrReadUs, submitUs);
            } else if (Function == AP6256_SDIO_FUNC_DATA) {
                InterlockedIncrement64(&Ctx->Sdio.StatBodyReads);
                InterlockedAdd64(&Ctx->Sdio.StatBodyReadBytes, (LONGLONG)chunk);
                InterlockedAdd64(&Ctx->Sdio.StatBodyReadUs, submitUs);
            } else {
                InterlockedIncrement64(&Ctx->Sdio.StatOtherCmd53);
                InterlockedAdd64(&Ctx->Sdio.StatOtherUs, submitUs);
            }
        }
        if (!NT_SUCCESS(status) && traceStats) {
            TraceDiag("CMD53 timing fn%u len=%u %s elapsed_us=%I64u isr_count=%d information=%Iu response_len=%u\n",
                      Function, chunk, blockMode ? "block" : "byte",
                      (ULONGLONG)submitUs,
                      Ctx->Sdio.IsrCount,
                      packet.Information, (ULONG)packet.ResponseLength);
        }
        if (!Write) {
            KeFlushIoBuffers(mdl, TRUE, TRUE);
        }
        if (NT_SUCCESS(status) && !Write) {

            __analysis_assume(chunk <= mdlLength);
            RtlCopyMemory(cursor, bounce, chunk);
        }
        if (!NT_SUCCESS(status)) {

            TraceError(TRACE_SDIO,
                       "CMD53 %s fn%u addr 0x%05X %s count %u len %u failed 0x%08X (R5 0x%08X)\n",
                       Write ? "write" : "read", Function, address,
                       blockMode ? "block" : "byte", count, chunk, status,
                       packet.ResponseData.AsULONG[0]);
            Ap6256SdioDumpTransferFailure(Ctx->Sdio.HostRegs, "CMD53 fail");

            {
                static LONG cardStateDumps;

                if (InterlockedIncrement(&cardStateDumps) <= 4) {
                    Ap6256SdioDumpCardState(Ctx, "CMD53 fail");
                }
            }

            (VOID)Ap6256SdBusAbortFunction(Ctx, Function);
        }

        IoFreeMdl(mdl);
        if (bounceCached) {
            InterlockedExchange(&Ctx->Sdio.BounceBusy, 0);
        } else {
            ExFreePoolWithTag(bounce, AP6256_POOL_TAG);
        }
        if (!NT_SUCCESS(status)) {

            if (blockMode && chunk > blockSize) {
                ULONG reduced = chunk / 2;
                reduced -= (reduced % blockSize);
                if (reduced < blockSize) {
                    reduced = blockSize;
                }
                Ctx->Sdio.MaxTransferBytes[Function] = reduced;

                if (Function != AP6256_SDIO_FUNC_DATA &&
                    packet.Information == 0) {
                    TraceDiag("CMD53 fn%u %u-byte block transfer refused with "
                              "no data moved; cap now %u bytes, reissuing\n",
                              Function, chunk, reduced);
                    status = STATUS_SUCCESS;
                    continue;
                }

                TraceWarn(TRACE_SDIO,
                          "CMD53 fn%u %u-byte block transfer failed after %Iu "
                          "byte(s); cap now %u bytes, NOT reissued\n",
                          Function, chunk, packet.Information, reduced);
            }
            break;
        }

        cursor += chunk;
        remaining -= chunk;
        if (Incrementing) {
            address += chunk;
            if (address > 0x1FFFF && remaining != 0) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
        }
    }
    return status;
}

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS Ap6256SdBusEnsureHostBlockLength(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                 _In_ ULONG Length)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    SDBUS_REQUEST_PACKET packet;
    NTSTATUS status;
    USHORT len = (USHORT)Length;

    if (iface == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    if (Length == 0 || Length > 512) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ctx->Sdio.HostBlockLength == Length) {
        return STATUS_SUCCESS;
    }

    RtlZeroMemory(&packet, sizeof(packet));
    packet.RequestFunction = SDRF_SET_PROPERTY;
    packet.Parameters.GetSetProperty.Property = SDP_FUNCTION_BLOCK_LENGTH;
    packet.Parameters.GetSetProperty.Buffer = &len;
    packet.Parameters.GetSetProperty.Length = sizeof(len);

    status = SdBusSubmitRequest(iface->Context, &packet);
    if (NT_SUCCESS(status)) {
        Ctx->Sdio.HostBlockLength = Length;

        TraceData("host block length -> %u\n", Length);
    } else {
        Ctx->Sdio.HostBlockLength = 0;
        TraceError(TRACE_SDIO, "set host block length %u failed 0x%08X\n", Length, status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UCHAR Function, _In_ ULONG BlockSize)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);

    if (iface == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    if (Function != 1 || BlockSize == 0 || BlockSize > 512) {
        return STATUS_INVALID_PARAMETER;
    }

    Ctx->Sdio.HostBlockLength = 0;
    return Ap6256SdBusEnsureHostBlockLength(Ctx, BlockSize);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdioSetCardBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UCHAR Function, _In_ ULONG BlockSize)
{
    ULONG address;
    ULONG readback;
    UCHAR low = 0;
    UCHAR high = 0;
    NTSTATUS status;

    if (Function == 0 || Function > 7 || BlockSize > 2048) {
        return STATUS_INVALID_PARAMETER;
    }

    address = SDIO_FBR_BASE(Function) + SDIO_FBR_BLKSIZE;

    if (BlockSize != 0) {
        status = Ap6256SdioWriteF0(Ctx, address, (UCHAR)(BlockSize & 0xFF));
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_SDIO, "fn%u card block size low byte failed 0x%08X\n",
                       Function, status);
            return status;
        }
        status = Ap6256SdioWriteF0(Ctx, address + 1,
                                   (UCHAR)((BlockSize >> 8) & 0xFF));
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_SDIO, "fn%u card block size high byte failed 0x%08X\n",
                       Function, status);
            return status;
        }
    }

    status = Ap6256SdioReadF0(Ctx, address, &low);
    if (NT_SUCCESS(status)) {
        status = Ap6256SdioReadF0(Ctx, address + 1, &high);
    }
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_SDIO, "fn%u card block size readback failed 0x%08X\n",
                   Function, status);
        return status;
    }

    readback = (ULONG)low | ((ULONG)high << 8);
    TraceDiag("fn%u card block size: wrote %u, FBR 0x%03X reads %u\n",
              Function, BlockSize, address, readback);

    if (BlockSize != 0 && readback != BlockSize) {
        TraceError(TRACE_SDIO,
                   "fn%u card block size did not take (wanted %u, card says %u)\n",
                   Function, BlockSize, readback);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetHostBlockSize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                     _Out_ PUSHORT BlockSize)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    SDBUS_REQUEST_PACKET packet;

    if (iface == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    *BlockSize = 0;
    RtlZeroMemory(&packet, sizeof(packet));
    packet.RequestFunction = SDRF_GET_PROPERTY;
    packet.Parameters.GetSetProperty.Property = SDP_HOST_BLOCK_LENGTH;
    packet.Parameters.GetSetProperty.Buffer = BlockSize;
    packet.Parameters.GetSetProperty.Length = sizeof(*BlockSize);
    return SdBusSubmitRequest(iface->Context, &packet);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256SdBusProperty(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Set,
                                    _In_ SDBUS_PROPERTY Property,
                                    _Inout_updates_bytes_(Length) PVOID Buffer,
                                    _In_ ULONG Length)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    SDBUS_REQUEST_PACKET packet;

    if (iface == NULL) {
        return STATUS_DEVICE_NOT_CONNECTED;
    }
    RtlZeroMemory(&packet, sizeof(packet));
    packet.RequestFunction = Set ? SDRF_SET_PROPERTY : SDRF_GET_PROPERTY;
    packet.Parameters.GetSetProperty.Property = Property;
    packet.Parameters.GetSetProperty.Buffer = Buffer;
    packet.Parameters.GetSetProperty.Length = Length;
    return SdBusSubmitRequest(iface->Context, &packet);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetBusClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PULONG Clock)
{
    *Clock = 0;
    return Ap6256SdBusProperty(Ctx, FALSE, SDP_BUS_CLOCK, Clock, sizeof(*Clock));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBusClock(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Clock)
{
    ULONG value = Clock;
    return Ap6256SdBusProperty(Ctx, TRUE, SDP_BUS_CLOCK, &value, sizeof(value));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusGetBusWidth(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PUCHAR Width)
{
    *Width = 0;
    return Ap6256SdBusProperty(Ctx, FALSE, SDP_BUS_WIDTH, Width, sizeof(*Width));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusSetBusWidth(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Width)
{
    UCHAR value = Width;
    return Ap6256SdBusProperty(Ctx, TRUE, SDP_BUS_WIDTH, &value, sizeof(value));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusEnableFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function)
{
    NTSTATUS status;
    UCHAR ioEnable = 0;

    if (Function == 0 || Function > 7) {
        return STATUS_INVALID_PARAMETER;
    }
    status = Ap6256SdBusCmd52(Ctx, FALSE, 0, 0x02  , &ioEnable);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ioEnable |= (UCHAR)(1u << Function);
    return Ap6256SdBusCmd52(Ctx, TRUE, 0, 0x02, &ioEnable);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusAbortFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function)
{
    UCHAR abort = (UCHAR)(Function & 0x7);
    NTSTATUS status;

    if (Function > 7) {
        return STATUS_INVALID_PARAMETER;
    }
    status = Ap6256SdBusCmd52(Ctx, TRUE, 0, 0x06  , &abort);
    TraceVerbose(TRACE_SDIO, "abort fn%u -> 0x%08X\n", Function, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusDisableFunction(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Function)
{
    NTSTATUS status;
    UCHAR ioEnable = 0;

    if (Function == 0 || Function > 7) {
        return STATUS_INVALID_PARAMETER;
    }
    status = Ap6256SdBusCmd52(Ctx, FALSE, 0, 0x02  ,
                              &ioEnable);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    ioEnable &= (UCHAR)~(1u << Function);
    return Ap6256SdBusCmd52(Ctx, TRUE, 0, 0x02, &ioEnable);
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS Ap6256SdBusCmd53(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN Write, _In_ UCHAR Function,
                          _In_ ULONG Address, _In_ BOOLEAN Incrementing,
                          _Inout_updates_bytes_(Length) PUCHAR Buffer,
                          _In_ ULONG Length)
{
    return Ap6256SdBusCmd53Mode(Ctx, Write, Function, Address, Incrementing,
                                Buffer, Length, FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SdBusRegisterInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    BOOLEAN enable = TRUE;
    UCHAR interruptEnable = 0;

    status = Ap6256SdBusProperty(Ctx, TRUE, SDP_FUNCTION_INT_ENABLE,
                                 &enable, sizeof(enable));
    TraceDiag("card interrupt: SDP_FUNCTION_INT_ENABLE -> 0x%08X\n", status);

    status = Ap6256SdioReadF0(Ctx, 0x04  , &interruptEnable);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_SDIO, "read CCCR interrupt enable failed 0x%08X\n", status);
        interruptEnable = 0;
    }

    interruptEnable |= (UCHAR)(SDIO_CCCR_IEN_FUNC0 |
                               SDIO_CCCR_IEN_FUNC1 |
                               SDIO_CCCR_IEN_FUNC2);
    status = Ap6256SdioWriteF0(Ctx, 0x04, interruptEnable);
    TraceDiag("card interrupt: CCCR 0x04 -> 0x%02X status 0x%08X\n",
              interruptEnable, status);
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_SDIO, "card interrupt not enabled; the data path will "
                               "not receive frames\n");
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256SdBusAckInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PSDBUS_INTERFACE_STANDARD iface = SDIFACE(Ctx);
    if (iface != NULL && iface->AcknowledgeInterrupt != NULL) {
        (VOID)iface->AcknowledgeInterrupt(iface->Context);
    }
}
