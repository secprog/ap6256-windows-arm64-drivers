/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256FipsSnapshot(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _Out_ AP6256_FIPS_SESSION* Session);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256FipsActive(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256FipsRetired(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256FipsReset(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsQualify(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN PatchVerified);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsStop(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsRetire(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsBegin(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_(6) const UCHAR* Station, _In_reads_(6) const UCHAR* Bssid);
NTSTATUS Ap6256FipsCandidateHt(_In_reads_bytes_opt_(BeaconLength) const UCHAR* Beacon,
    _In_ ULONG BeaconLength, _In_reads_bytes_opt_(ProbeLength) const UCHAR* Probe,
    _In_ ULONG ProbeLength, _In_reads_(6) const UCHAR* Bssid, _Out_ BOOLEAN* Ht);
NTSTATUS Ap6256FipsCheckVendorIes(_In_reads_bytes_opt_(Length) const UCHAR* Ies, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsSetQos(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ BOOLEAN Ht);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FipsVerifySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_ UINT32 Wsec, _In_ UINT32 WpaAuth);

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS Ap6256FipsPrepareTx(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _Inout_updates_bytes_(Capacity) UCHAR* Buffer, _In_ ULONG Capacity,
    _Inout_ ULONG* Length, _Out_ UCHAR* Priority, _Out_ UCHAR* Exemption);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256FipsTxCurrent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Wire, _In_ ULONG Length);
_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256FipsBcdcTxCurrent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Bcdc, _In_ ULONG Length);
