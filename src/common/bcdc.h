/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetDcmdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ UINT32 Cmd,
    _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcQueryDcmdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ UINT32 Cmd,
    _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length);

#define AP6256_BCDC_MAXBUF      2048

VOID Ap6256BcdcFirmwareHalted(_In_ PAP6256_DEVICE_CONTEXT Ctx);

typedef struct _AP6256_BCDC_QUERY_RESULT {
    BOOLEAN FirmwareReply;
    BOOLEAN FirmwareError;
    INT32 FirmwareStatus;
    ULONG PayloadLength;
} AP6256_BCDC_QUERY_RESULT, *PAP6256_BCDC_QUERY_RESULT;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcQueryDcmdResultIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ UINT32 Cmd,
    _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length,
    _Out_ PAP6256_BCDC_QUERY_RESULT Result);

#define AP6256_BCDC_TX_MAXLEN   1536

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcInit(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256BcdcCleanup(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256BcdcDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256BcdcProcessControlFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_reads_bytes_(Length) PUCHAR Payload,
                                   _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcQueryDcmd(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Cmd,
                             _Inout_updates_bytes_(Length) PVOID Buffer, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetDcmd(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Cmd,
                           _In_reads_bytes_(Length) PVOID Buffer, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcGetIovar(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
                            _Inout_updates_bytes_(Length) PVOID Out,
                            _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetIovar(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
                            _In_reads_bytes_(Length) const VOID* Data,
                            _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcGetIovarIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ UINT32 IfIndex, _In_ PCSTR Name,
                              _Inout_updates_bytes_(Length) PVOID Out,
                              _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcGetIovarResultIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ PCSTR Name,
    _Inout_updates_bytes_(Length) PVOID Out, _In_ ULONG Length,
    _Out_opt_ PAP6256_BCDC_QUERY_RESULT Result);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcProbeIovar(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
    _Inout_updates_bytes_(Length) PVOID Out, _In_ ULONG Length,
    _Out_opt_ PAP6256_BCDC_QUERY_RESULT Result);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetIovarIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ UINT32 IfIndex, _In_ PCSTR Name,
                              _In_reads_bytes_(Length) const VOID* Data,
                              _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BcdcSetIovarResultIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ PCSTR Name,
    _In_reads_bytes_(Length) const VOID* Data, _In_ ULONG Length,
    _Out_opt_ PAP6256_BCDC_QUERY_RESULT Result);
