/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "bcdc.h"
#include "sdio.h"
#include "datapath.h"

#define BCDC_HDR_LEN        ((ULONG)sizeof(BCDC_DCMD_HEADER))

#define BCDC_FRAME_OVERHEAD (SDPCM_GLOM_HDRLEN + BCDC_HDR_LEN)

static __forceinline ULONG Ap6256Align4(_In_ ULONG v) { return (v + 3u) & ~3u; }

static ULONG Ap6256AlignTransfer(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONG Value)
{
    ULONG blockSize = Ctx->Sdio.Function2BlockSize;
    ULONG alignment = sizeof(UINT32);

    if (blockSize != 0 && blockSize <= 512 && Value > blockSize) {
        alignment = blockSize;
    }
    if (Value > MAXULONG - (alignment - 1)) return 0;
    return ((Value + alignment - 1) / alignment) * alignment;
}

_Use_decl_annotations_
VOID Ap6256BcdcFirmwareHalted(PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL irql;
    if (!Ctx->Bcdc.Initialized) return;
    KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &irql);
    Ctx->Bcdc.Pending = FALSE;
    Ctx->Bcdc.ResponseStatus = STATUS_DEVICE_HARDWARE_ERROR;
    Ctx->Bcdc.ResponseLength = 0;
    KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, irql);
    KeSetEvent(&Ctx->Bcdc.ResponseEvent, IO_NO_INCREMENT, FALSE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcInit(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG bufSize = BCDC_FRAME_OVERHEAD + AP6256_BCDC_MAXBUF + Ctx->Sdio.Function2BlockSize;

    if (Ctx->Bcdc.IoctlBuffer == NULL) {
        Ctx->Bcdc.IoctlBuffer = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, bufSize, AP6256_POOL_TAG);
        if (Ctx->Bcdc.IoctlBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Ctx->Bcdc.IoctlBufferSize = bufSize;
    }
    if (Ctx->Bcdc.ResponseBuffer == NULL) {
        Ctx->Bcdc.ResponseBuffer = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, BCDC_HDR_LEN + AP6256_BCDC_MAXBUF,
            AP6256_POOL_TAG);
        if (Ctx->Bcdc.ResponseBuffer == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Ctx->Bcdc.ResponseBufferSize = BCDC_HDR_LEN + AP6256_BCDC_MAXBUF;
    }

    Ctx->Bcdc.RequestId = 0;
    Ctx->Bcdc.Pending = FALSE;
    Ctx->Bcdc.ResponseLength = 0;
    Ctx->Bcdc.ResponseStatus = STATUS_DEVICE_NOT_READY;
    KeInitializeEvent(&Ctx->Bcdc.ResponseEvent, NotificationEvent, FALSE);
    KeInitializeSpinLock(&Ctx->Bcdc.ResponseLock);
    Ctx->Bcdc.Initialized = TRUE;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256BcdcCleanup(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    KIRQL oldIrql;

    if (!Ctx->Bcdc.Initialized) return;
    KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
    Ctx->Bcdc.Pending = FALSE;
    Ctx->Bcdc.ResponseStatus = STATUS_CANCELLED;
    Ctx->Bcdc.ResponseLength = 0;
    KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);
    KeSetEvent(&Ctx->Bcdc.ResponseEvent, IO_NO_INCREMENT, FALSE);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256BcdcDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    if (Ctx->Bcdc.IoctlBuffer != NULL) {
        ExFreePoolWithTag(Ctx->Bcdc.IoctlBuffer, AP6256_POOL_TAG);
        Ctx->Bcdc.IoctlBuffer = NULL;
        Ctx->Bcdc.IoctlBufferSize = 0;
    }
    if (Ctx->Bcdc.ResponseBuffer != NULL) {
        ExFreePoolWithTag(Ctx->Bcdc.ResponseBuffer, AP6256_POOL_TAG);
        Ctx->Bcdc.ResponseBuffer = NULL;
        Ctx->Bcdc.ResponseBufferSize = 0;
    }
    Ctx->Bcdc.Initialized = FALSE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256BcdcProcessControlFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_reads_bytes_(Length) PUCHAR Payload,
                                   _In_ ULONG Length)
{
    PBCDC_DCMD_HEADER header;
    KIRQL oldIrql;
    NTSTATUS responseStatus = STATUS_SUCCESS;
    BOOLEAN signal = FALSE;
    UINT16 id = 0;

    if (Length < BCDC_HDR_LEN) {
        responseStatus = STATUS_DEVICE_PROTOCOL_ERROR;
    } else {

        header = (PBCDC_DCMD_HEADER)Payload;
        id = (UINT16)BCDC_DCMD_ID(header->Flags);
    }

    KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
    if (Ctx->Bcdc.Pending &&
        (!NT_SUCCESS(responseStatus) || id == Ctx->Bcdc.PendingId)) {
        if (NT_SUCCESS(responseStatus) && Length <= Ctx->Bcdc.ResponseBufferSize) {
            RtlCopyMemory(Ctx->Bcdc.ResponseBuffer, Payload, Length);
            Ctx->Bcdc.ResponseLength = Length;
        } else {
            Ctx->Bcdc.ResponseLength = 0;
            if (NT_SUCCESS(responseStatus)) {
                responseStatus = STATUS_BUFFER_OVERFLOW;
            }
        }
        Ctx->Bcdc.ResponseStatus = responseStatus;
        Ctx->Bcdc.Pending = FALSE;
        signal = TRUE;
    }
    KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);

    if (signal) {
        KeSetEvent(&Ctx->Bcdc.ResponseEvent, IO_NO_INCREMENT, FALSE);
    } else if (NT_SUCCESS(responseStatus)) {
        TraceWarn(TRACE_BCDC, "unexpected control response id %u\n", id);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256BcdcDcmdWithResult(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Cmd, _In_ BOOLEAN Set,
                               _In_ UINT32 IfIndex,
                               _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
                               _Out_opt_ PAP6256_BCDC_QUERY_RESULT Result)
{
    NTSTATUS status;
    PUCHAR frame;
    PSDPCM_HW_HEADER hw;
    PSDPCM_SW_HEADER sw;
    PBCDC_DCMD_HEADER bcdc;
    PUCHAR payload;
    ULONG txLength, wireLength, transferLength, rxLen, id, hdrLen;
    LARGE_INTEGER timeout;
    KIRQL oldIrql;

    if (Result != NULL) RtlZeroMemory(Result, sizeof(*Result));
    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0)
        return STATUS_DEVICE_HARDWARE_ERROR;
    if (Ctx->FirmwareIoQuiesced != 0 && Ctx->PowerThread != KeGetCurrentThread())
        return STATUS_DEVICE_NOT_READY;
    if (Length > AP6256_BCDC_MAXBUF) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    if (Length != 0 && Buffer == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    txLength = Length;
    if (txLength > AP6256_BCDC_TX_MAXLEN) {
        if (Set) {
            TraceError(TRACE_BCDC,
                       "cmd %u set payload %u exceeds the %u-byte control "
                       "message limit\n", Cmd, Length, AP6256_BCDC_TX_MAXLEN);
            return STATUS_INVALID_BUFFER_SIZE;
        }
        txLength = AP6256_BCDC_TX_MAXLEN;
    }

    if (Ctx->Bcdc.IoctlBuffer == NULL ||
        Ctx->Bcdc.ResponseBuffer == NULL || !Ctx->DatapathRunning) {
        return STATUS_DEVICE_NOT_READY;
    }

    Ap6256LockAcquire(&Ctx->Bcdc.Lock);

    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0) {
        status = STATUS_DEVICE_HARDWARE_ERROR;
        goto done;
    }

    if ((Ctx->FirmwareIoQuiesced != 0 && Ctx->PowerThread != KeGetCurrentThread()) ||
        !Ctx->DatapathRunning || Ctx->Sdio.Sleeping) {
        status = STATUS_DEVICE_NOT_READY;
        goto done;
    }
    frame   = Ctx->Bcdc.IoctlBuffer;

    hdrLen = Ap6256TxHdrLen(Ctx);
    wireLength = hdrLen + BCDC_HDR_LEN + txLength;
    transferLength = Ap6256AlignTransfer(Ctx, wireLength);
    if (transferLength == 0 || transferLength > Ctx->Bcdc.IoctlBufferSize ||
        wireLength > MAXUINT16 || Ap6256Align4(wireLength) > transferLength) {
        status = STATUS_BUFFER_OVERFLOW;
        goto done;
    }
    RtlZeroMemory(frame, transferLength);

    hw      = (PSDPCM_HW_HEADER)frame;
    sw      = (PSDPCM_SW_HEADER)(frame + hdrLen - SDPCM_SWHDR_LEN);
    bcdc    = (PBCDC_DCMD_HEADER)(frame + hdrLen);
    payload = frame + hdrLen + BCDC_HDR_LEN;

    id = (++Ctx->Bcdc.RequestId) & 0xFFFF;

    hw->FrameLength = (UINT16)wireLength;
    hw->FrameLengthInverted = (UINT16)~wireLength;

    sw->ChannelAndFlags = SDPCM_CONTROL_CHANNEL;
    sw->DataOffset = (UINT8)hdrLen;

    bcdc->Cmd = Cmd;

    bcdc->Len = txLength;
    bcdc->Flags = (id << BCDC_DCMD_ID_SHIFT) | (Set ? BCDC_DCMD_SET : 0) |
                  ((IfIndex << BCDC_DCMD_IF_SHIFT) & BCDC_DCMD_IF_MASK);
    bcdc->Status = 0;

    if (txLength != 0) {
        RtlCopyMemory(payload, Buffer, txLength);
    }

    KeClearEvent(&Ctx->Bcdc.ResponseEvent);
    KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
    Ctx->Bcdc.PendingId = (UINT16)id;
    Ctx->Bcdc.PendingCommand = Cmd;
    Ctx->Bcdc.PendingIfIndex = (UCHAR)IfIndex;
    Ctx->Bcdc.PendingSet = Set;
    RtlZeroMemory(Ctx->Bcdc.PendingIovar, sizeof(Ctx->Bcdc.PendingIovar));
    if ((Cmd == BRCMF_C_GET_VAR || Cmd == BRCMF_C_SET_VAR) && txLength != 0) {
        ULONG n = 0;
        while (n < txLength && n < sizeof(Ctx->Bcdc.PendingIovar) - 1 && payload[n] != 0) {
            Ctx->Bcdc.PendingIovar[n] = (CHAR)payload[n];
            ++n;
        }
    }
    Ctx->Bcdc.Pending = TRUE;
    Ctx->Bcdc.ResponseLength = 0;
    Ctx->Bcdc.ResponseStatus = STATUS_IO_TIMEOUT;
    KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);

    status = Ap6256DatapathSendSdpcm(Ctx, frame, transferLength);

    if (status == STATUS_DEVICE_BUSY) {
        const ULONG creditWaitMs = 1500;
        LARGE_INTEGER interval;
        ULONG waitedMs = 0;

        interval.QuadPart = -(10ll * 1000 * 10);
        while (status == STATUS_DEVICE_BUSY && Ctx->DatapathRunning &&
               waitedMs < creditWaitMs) {
            (VOID)KeDelayExecutionThread(KernelMode, FALSE, &interval);
            waitedMs += 10;
            status = Ap6256DatapathSendSdpcm(Ctx, frame, transferLength);
        }
        if (status == STATUS_DEVICE_BUSY) {
            TraceError(TRACE_BCDC, "cmd %u: no bus credit after %u ms\n",
                       Cmd, waitedMs);
        }
    }
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_BCDC, "cmd %u send failed 0x%08X\n", Cmd, status);
        KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
        Ctx->Bcdc.Pending = FALSE;
        KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);
        goto done;
    }

    timeout.QuadPart = -(5ll * 10 * 1000 * 1000);
    status = KeWaitForSingleObject(&Ctx->Bcdc.ResponseEvent, Executive,
                                   KernelMode, FALSE, &timeout);
    if (status == STATUS_TIMEOUT) {
        BOOLEAN halted;
        KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
        halted = InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0;
        if (!halted) Ctx->Bcdc.Pending = FALSE;
        KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);
        if (!halted) {
            status = STATUS_IO_TIMEOUT;
            TraceError(TRACE_BCDC, "cmd %u response timed out\n", Cmd);
            goto done;
        }

        status = KeWaitForSingleObject(&Ctx->Bcdc.ResponseEvent, Executive,
                                       KernelMode, FALSE, NULL);
    }
    if (!NT_SUCCESS(status)) goto done;

    KeAcquireSpinLock(&Ctx->Bcdc.ResponseLock, &oldIrql);
    status = InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0 ?
        STATUS_DEVICE_HARDWARE_ERROR : Ctx->Bcdc.ResponseStatus;
    rxLen = Ctx->Bcdc.ResponseLength;
    KeReleaseSpinLock(&Ctx->Bcdc.ResponseLock, oldIrql);
    if (!NT_SUCCESS(status)) goto done;
    if (rxLen < BCDC_HDR_LEN) {
        status = STATUS_DEVICE_PROTOCOL_ERROR;
        goto done;
    }

    bcdc = (PBCDC_DCMD_HEADER)Ctx->Bcdc.ResponseBuffer;
    payload = (PUCHAR)bcdc + BCDC_HDR_LEN;

    if (BCDC_DCMD_ID(bcdc->Flags) != id) {
        TraceError(TRACE_BCDC, "reply id mismatch (got %u want %u)\n",
                   BCDC_DCMD_ID(bcdc->Flags), id);
        status = STATUS_DEVICE_PROTOCOL_ERROR;
        goto done;
    }
    if (Result != NULL) {
        Result->FirmwareReply = TRUE;
        Result->FirmwareError = (BOOLEAN)((bcdc->Flags & BCDC_DCMD_ERROR) != 0);
        Result->FirmwareStatus = (INT32)bcdc->Status;
        Result->PayloadLength = rxLen - BCDC_HDR_LEN;
    }

    if (bcdc->Flags & BCDC_DCMD_ERROR) {
        TraceWarn(TRACE_BCDC, "cmd %u firmware status %d\n", Cmd, (INT32)bcdc->Status);
        status = STATUS_UNSUCCESSFUL;
        goto done;
    }

    if (!Set && Length != 0) {

        ULONG copy = min(Length, rxLen - BCDC_HDR_LEN);
        RtlZeroMemory(Buffer, Length);
        RtlCopyMemory(Buffer, payload, copy);
    }
    status = STATUS_SUCCESS;

done:
    Ap6256LockRelease(&Ctx->Bcdc.Lock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256BcdcDcmd(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Cmd, _In_ BOOLEAN Set, _In_ UINT32 IfIndex,
    _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length)
{
    return Ap6256BcdcDcmdWithResult(Ctx, Cmd, Set, IfIndex, Buffer, Length, NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcQueryDcmdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ UINT32 IfIndex, _In_ UINT32 Cmd,
                              _Inout_updates_bytes_(Length) PVOID Buffer,
                              _In_ ULONG Length)
{
    if (IfIndex > 15) return STATUS_INVALID_PARAMETER;
    return Ap6256BcdcDcmd(Ctx, Cmd, FALSE, IfIndex, Buffer, Length);
}

_Use_decl_annotations_
NTSTATUS Ap6256BcdcQueryDcmdResultIf(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 IfIndex, UINT32 Cmd, PVOID Buffer, ULONG Length,
    PAP6256_BCDC_QUERY_RESULT Result)
{
    RtlZeroMemory(Result, sizeof(*Result));
    if (IfIndex > 15) return STATUS_INVALID_PARAMETER;
    return Ap6256BcdcDcmdWithResult(Ctx, Cmd, FALSE, IfIndex, Buffer, Length, Result);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetDcmdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ UINT32 IfIndex, _In_ UINT32 Cmd,
                            _In_reads_bytes_(Length) PVOID Buffer,
                            _In_ ULONG Length)
{
    if (IfIndex > 15) return STATUS_INVALID_PARAMETER;
    return Ap6256BcdcDcmd(Ctx, Cmd, TRUE, IfIndex, Buffer, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcQueryDcmd(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Cmd,
                             _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length)
{
    return Ap6256BcdcDcmd(Ctx, Cmd, FALSE, 0, Buffer, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetDcmd(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Cmd,
                           _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length)
{
    return Ap6256BcdcDcmd(Ctx, Cmd, TRUE, 0, Buffer, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)

NTSTATUS Ap6256BcdcGetIovarIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ UINT32 IfIndex, _In_ PCSTR Name,
                              _Inout_updates_bytes_(Length) PVOID Out,
                              _In_ ULONG Length)
{
    return Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, Name, Out, Length, NULL);
}

_Use_decl_annotations_
NTSTATUS Ap6256BcdcGetIovarResultIf(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 IfIndex, PCSTR Name, PVOID Out, ULONG Length,
    PAP6256_BCDC_QUERY_RESULT Result)
{
    NTSTATUS status;
    size_t nameLen;
    PUCHAR scratch;
    ULONG total;

    if (Result != NULL) RtlZeroMemory(Result, sizeof(*Result));
    if (IfIndex > 15 || (Length != 0 && Out == NULL)) return STATUS_INVALID_PARAMETER;
    status = RtlStringCbLengthA(Name, AP6256_BCDC_MAXBUF, &nameLen);
    if (!NT_SUCCESS(status)) return status;
    nameLen += 1;

    if (Length > AP6256_BCDC_MAXBUF - nameLen) return STATUS_INVALID_BUFFER_SIZE;
    total = (ULONG)nameLen + Length;

    scratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, AP6256_POOL_TAG);
    if (scratch == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(scratch, total);
    RtlCopyMemory(scratch, Name, nameLen);
    if (Length != 0) RtlCopyMemory(scratch + nameLen, Out, Length);

    status = Ap6256BcdcDcmdWithResult(Ctx, BRCMF_C_GET_VAR, FALSE, IfIndex,
                                     scratch, total, Result);
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(Out, scratch, Length);
    }
    ExFreePoolWithTag(scratch, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcGetIovar(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
                            _Inout_updates_bytes_(Length) PVOID Out,
                            _In_ ULONG Length)
{
    return Ap6256BcdcGetIovarIf(Ctx, 0, Name, Out, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetIovarIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ UINT32 IfIndex, _In_ PCSTR Name,
                              _In_reads_bytes_(Length) const VOID* Data,
                              _In_ ULONG Length)
{
    return Ap6256BcdcSetIovarResultIf(Ctx, IfIndex, Name, Data, Length, NULL);
}

_Use_decl_annotations_
NTSTATUS Ap6256BcdcSetIovarResultIf(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 IfIndex, PCSTR Name, const VOID* Data, ULONG Length,
    PAP6256_BCDC_QUERY_RESULT Result)
{
    NTSTATUS status;
    size_t nameLen;
    PUCHAR scratch;
    ULONG total;

    if (Result != NULL) RtlZeroMemory(Result, sizeof(*Result));
    if (IfIndex > 15 || (Length != 0 && Data == NULL)) return STATUS_INVALID_PARAMETER;
    status = RtlStringCbLengthA(Name, AP6256_BCDC_MAXBUF, &nameLen);
    if (!NT_SUCCESS(status)) return status;
    nameLen += 1;

    if (Length > AP6256_BCDC_MAXBUF - nameLen) return STATUS_INVALID_BUFFER_SIZE;
    total = (ULONG)nameLen + Length;

    scratch = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, total, AP6256_POOL_TAG);
    if (scratch == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(scratch, Name, nameLen);
    if (Length != 0) {
        RtlCopyMemory(scratch + nameLen, Data, Length);
    }

    status = Ap6256BcdcDcmdWithResult(Ctx, BRCMF_C_SET_VAR, TRUE, IfIndex,
                                     scratch, total, Result);
    ExFreePoolWithTag(scratch, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetIovar(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
                            _In_reads_bytes_(Length) const VOID* Data,
                            _In_ ULONG Length)
{
    return Ap6256BcdcSetIovarIf(Ctx, 0, Name, Data, Length);
}
