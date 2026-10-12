/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "wifi_ops.h"

_Must_inspect_result_
BOOLEAN Ap6256OweDhValid(_In_reads_bytes_(Length) const UCHAR* Ie, _In_ ULONG Length);
_Must_inspect_result_
NTSTATUS Ap6256OweCopyIes(_In_reads_bytes_(DhLength) const UCHAR* Dh, _In_ ULONG DhLength,
    _In_reads_bytes_opt_(CommonLength) const UCHAR* Common, _In_ ULONG CommonLength,
    _In_reads_bytes_opt_(BssLength) const UCHAR* Bss, _In_ ULONG BssLength,
    _Inout_ AP6256_CONNECT_PARAMS* Params);
_Must_inspect_result_
BOOLEAN Ap6256OweRequestValid(_In_ const AP6256_CONNECT_PARAMS* Params,
    _In_ const AP6256_ASSOC_FRAMES* Frames);
_Must_inspect_result_
BOOLEAN Ap6256OweAssociationValid(_In_ const AP6256_CONNECT_PARAMS* Params,
    _In_ const AP6256_ASSOC_FRAMES* Frames);
_Must_inspect_result_
NTSTATUS Ap6256OweBuildCommand(_In_ UINT16 Operation, _In_ UINT32 Generation,
    _In_ const AP6256_CONNECT_PARAMS* Params,
    _Out_writes_bytes_to_(Capacity, *Length) UCHAR* Bytes, _In_ ULONG Capacity,
    _Out_ ULONG* Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256OweFirmwareQualify(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256OweVerifySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256OwePrepareSecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256OweArm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_CONNECT_PARAMS* Params);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256OweEnd(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Associated);
