/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "wifi_ops.h"
#include "native_departure.h"
#include "bcdc.h"
#include "host_cipher_control.h"
#include "host_fips.h"

C_ASSERT(sizeof(AP6256_NATIVE_DEPARTURE_CONTROL) == AP6256_ND_BYTES);

static NTSTATUS Ap6256NativeDepartureRead(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Token,
    AP6256_NATIVE_DEPARTURE_CONTROL* Control)
{
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    RtlZeroMemory(Control, sizeof(*Control));
    Control->Abi = AP6256_ND_ABI;
    Control->Bytes = sizeof(*Control);
    Control->Token = Token;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wdi_native_departure",
        Control, sizeof(*Control), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(*Control) ||
        Control->Abi != AP6256_ND_ABI || Control->Bytes != sizeof(*Control) ||
        Control->Token != Token || Control->Reserved[0] || Control->Reserved[1] ||
        (Control->Flags & ~(AP6256_ND_PMF | AP6256_ND_ELIGIBLE)) ||
        Control->Flags == AP6256_ND_ELIGIBLE)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    if (Token) {
        if (Control->Reason != Ctx->NativeDepartureReason ||
            !RtlEqualMemory(Control->Peer, Ctx->NativeDeparturePeer, 6) ||
            Control->Attempts != 1 || Control->State < AP6256_ND_PENDING ||
            Control->State > AP6256_ND_COMMITTING ||
            (Control->Operation != AP6256_ND_START && Control->Operation != AP6256_ND_COMMIT) ||
            ((Control->State == AP6256_ND_PENDING || Control->State == AP6256_ND_ACKED) &&
                Control->Operation != AP6256_ND_START) ||
            ((Control->State == AP6256_ND_COMMITTING || Control->State == AP6256_ND_COMMITTED) &&
                Control->Operation != AP6256_ND_COMMIT))
            return STATUS_DEVICE_PROTOCOL_ERROR;
    } else if (Control->Operation || Control->Reason || Control->State ||
        Control->NativeStatus || Control->TxStatus || Control->Attempts)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256NativeDepartureLocked(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Bssid, UINT32 Reason, BOOLEAN* Handled)
{
    AP6256_NATIVE_DEPARTURE_CONTROL request, receipt;
    BOOLEAN tracked = FALSE;
    ULONG slot, attempt, poll;
    NTSTATUS status;
    LARGE_INTEGER delay;
    *Handled = Ctx->NativeDepartureToken != 0;
    if (!Ctx->FirmwareHostCipherPatchVerified || Ctx->Chip.ChipId != 0x4345 ||
        Ctx->Chip.ChipRev != 9)
        return *Handled ? STATUS_DEVICE_NOT_READY : STATUS_SUCCESS;
    if (Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, 0) || Ap6256FipsActive(Ctx, 0))
        return *Handled ? STATUS_DEVICE_BUSY : STATUS_SUCCESS;
    if (Bssid != NULL && (Bssid[0] & 1)) return STATUS_INVALID_PARAMETER;
    if (Reason > 65535) return STATUS_INVALID_PARAMETER;
    if (!*Handled) {
        for (slot = 0; slot < AP6256_NATIVE_KEY_SLOTS; ++slot) {
            AP6256_NATIVE_KEY_REF* key = &Ctx->NativeKeys[slot];
            if (key->Valid && key->Pairwise && !key->Management &&
                (Bssid == NULL || RtlEqualMemory(key->PeerAddress, Bssid, 6))) tracked = TRUE;
        }
        if (!tracked) return STATUS_SUCCESS;
    } else if ((Bssid != NULL && !RtlEqualMemory(Bssid, Ctx->NativeDeparturePeer, 6)) ||
        (Reason != 0 && Reason != Ctx->NativeDepartureReason)) return STATUS_DEVICE_BUSY;
    for (attempt = 0; attempt < 3; ++attempt) {
        if (!Ctx->NativeDepartureToken) {
            status = Ap6256NativeDepartureRead(Ctx, 0, &receipt);
            if (!NT_SUCCESS(status)) { *Handled = TRUE; return status; }
            if (!(receipt.Flags & AP6256_ND_PMF))
                return *Handled ? STATUS_DEVICE_PROTOCOL_ERROR : STATUS_SUCCESS;
            *Handled = TRUE;
            if (!(receipt.Flags & AP6256_ND_ELIGIBLE) || (receipt.Peer[0] & 1) ||
                (Bssid != NULL && !RtlEqualMemory(receipt.Peer, Bssid, 6)))
                return STATUS_DEVICE_PROTOCOL_ERROR;
            if (Ctx->NativeDepartureNext == MAXULONG) return STATUS_INTEGER_OVERFLOW;
            Ctx->NativeDepartureToken = ++Ctx->NativeDepartureNext;
            Ctx->NativeDepartureReason = Reason ? Reason : 8u;
            RtlCopyMemory(Ctx->NativeDeparturePeer, receipt.Peer, 6);
        }
        *Handled = TRUE;
        Ctx->NativeDeparturePending = TRUE;
        RtlZeroMemory(&request, sizeof(request));
        request.Abi = AP6256_ND_ABI;
        request.Bytes = sizeof(request);
        request.Token = Ctx->NativeDepartureToken;
        request.Operation = AP6256_ND_START;
        request.Reason = Ctx->NativeDepartureReason;
        RtlCopyMemory(request.Peer, Ctx->NativeDeparturePeer, 6);
        if (!Ctx->NativeDepartureCommitted)
            (VOID)Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_native_departure", &request, sizeof(request));
        for (poll = 0; poll < 51; ++poll) {
            status = Ap6256NativeDepartureRead(Ctx, request.Token, &receipt);
            if (!NT_SUCCESS(status)) return status;
            if (receipt.State != AP6256_ND_PENDING && receipt.State != AP6256_ND_COMMITTING) break;
            if (poll == 50) return STATUS_IO_TIMEOUT;
            delay.QuadPart = -100000LL;
            status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
            if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_IO_TIMEOUT : status;
        }
        TraceVerbose(TRACE_DRIVER, "native protected departure: token %u state %u TX 0x%08X native %d attempt %u\n",
            request.Token, receipt.State, receipt.TxStatus, receipt.NativeStatus, attempt + 1);
        if (receipt.State == AP6256_ND_FAILED) {
            if (receipt.NativeStatus == -12 && attempt < 2) {
                Ctx->NativeDepartureToken = 0;
                continue;
            }
            return receipt.NativeStatus == -1 ? STATUS_INSUFFICIENT_RESOURCES : STATUS_DEVICE_PROTOCOL_ERROR;
        }
        if ((receipt.State != AP6256_ND_ACKED && receipt.State != AP6256_ND_COMMITTED) ||
            receipt.NativeStatus != 0 || !(receipt.TxStatus & 2u) || receipt.Attempts != 1)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        if (receipt.State == AP6256_ND_ACKED) {
            request.Operation = AP6256_ND_COMMIT;
            for (poll = 0; poll < 51; ++poll) {
                if (receipt.State == AP6256_ND_ACKED)
                    (VOID)Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_native_departure", &request, sizeof(request));
                status = Ap6256NativeDepartureRead(Ctx, request.Token, &receipt);
                if (!NT_SUCCESS(status)) return status;
                if (receipt.State != AP6256_ND_ACKED && receipt.State != AP6256_ND_COMMITTING) break;
                if (poll == 50) return STATUS_IO_TIMEOUT;
                delay.QuadPart = -100000LL;
                status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
                if (status != STATUS_SUCCESS) return NT_SUCCESS(status) ? STATUS_IO_TIMEOUT : status;
            }
            TraceVerbose(TRACE_DRIVER, "native protected departure commit receipt: token %u state %u native %d TX 0x%08X\n",
                request.Token, receipt.State, receipt.NativeStatus, receipt.TxStatus);
            if (receipt.State != AP6256_ND_COMMITTED || receipt.Operation != AP6256_ND_COMMIT ||
                receipt.NativeStatus || !(receipt.TxStatus & 2u) || receipt.Attempts != 1)
                return STATUS_DEVICE_PROTOCOL_ERROR;
        }
        TraceInfo(TRACE_NETADAPTER, "native protected departure committed: token %u reason %u TX 0x%08X\n",
            request.Token, request.Reason, receipt.TxStatus);
        Ctx->NativeDepartureCommitted = TRUE;
        return STATUS_SUCCESS;
    }
    return STATUS_IO_TIMEOUT;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NativeDeparture(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_opt_(6) const UCHAR* Bssid, _In_ UINT32 Reason, _Out_ BOOLEAN* Handled)
{
    NTSTATUS status;
    if (Ctx == NULL || Handled == NULL || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    status = Ap6256NativeDepartureLocked(Ctx, Bssid, Reason, Handled);
    if (!NT_SUCCESS(status))
        TraceWarn(TRACE_NETADAPTER, "native protected departure incomplete: token %u pending %u committed %u status 0x%08X\n",
            Ctx->NativeDepartureToken, Ctx->NativeDeparturePending, Ctx->NativeDepartureCommitted, status);
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    return status;
}
