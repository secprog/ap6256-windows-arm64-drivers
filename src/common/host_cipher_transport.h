/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"
#include "host_cipher_path.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherSetRxExemptions(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const AP6256_HC_RX_EXEMPT* Entries, ULONG Count);
#include "host_fips_wire.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawTxCurrent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Wire, _In_ ULONG Length);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawDestination(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Wire, _In_ ULONG Length, _Out_writes_(6) UCHAR* Destination);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawBcdcTxCurrent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Bcdc, _In_ ULONG Length);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256HostCipherPacketActive(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS Ap6256RawPrepareTx(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _Inout_updates_bytes_(Capacity) UCHAR* Buffer, _In_ ULONG Capacity,
    _Inout_ ULONG* Length, _Out_ UCHAR* Priority, _Inout_ UCHAR* Exemption);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawRxRead(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Wire, _In_ ULONG Length,
    _Out_ AP6256_FIPS_FRAME_VIEW* View, _Out_ ULONG* Generation, _Out_ BOOLEAN* HostCipher);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawGenerationCurrent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_ ULONG Generation, _In_ BOOLEAN HostCipher);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256RawRxFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_ ULONG Generation, _In_ BOOLEAN HostCipher, _In_reads_bytes_(Length) const UCHAR* Frame,
    _In_ ULONG Length, _Out_ AP6256_FIPS_FRAME_VIEW* View);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HostCipherReceiveManagement(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Wire, _In_ ULONG Length);
