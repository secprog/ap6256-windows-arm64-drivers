/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

#define AP6256_WLFC_CAPACITY 128u
#define AP6256_WLFC_ANY 0xffffu
typedef enum _AP6256_WLFC_COMPLETION {
    Ap6256WlfcTransfer,
    Ap6256WlfcSend
} AP6256_WLFC_COMPLETION;
typedef enum _AP6256_WLFC_RESULT {
    Ap6256WlfcOk, Ap6256WlfcNoAck, Ap6256WlfcDiscard,
    Ap6256WlfcCancelled, Ap6256WlfcTransferFailed, Ap6256WlfcTimeout
} AP6256_WLFC_RESULT;
typedef VOID (*AP6256_WLFC_CALLBACK)(PVOID Cookie,
    AP6256_WLFC_COMPLETION Completion, AP6256_WLFC_RESULT Result);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WlfcCreate(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WlfcConfigure(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcDrain(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcStop(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcDestroy(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256WlfcEnabled(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16 Ap6256WlfcRoom(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256WlfcKick(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS Ap6256WlfcEnqueue(PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Ethernet, ULONG Length,
    UCHAR Priority, UCHAR Exemption, UCHAR IfIndex, UINT16 Port, UINT16 Peer,
    AP6256_WLFC_CALLBACK Callback, PVOID Cookie);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256WlfcCancel(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer,
    PVOID Cookie);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcCancelAndWait(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer,
    PVOID Cookie);
_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG Ap6256WlfcPending(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256WlfcAbortBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT16 Port, UINT16 Peer);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256WlfcAbortEnd(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256WlfcSignals(PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Signals, ULONG Length);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256WlfcEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Event,
    _In_reads_bytes_(Length) const UCHAR* Body, ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WlfcResumeRetained(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ ULONGLONG Slept);
