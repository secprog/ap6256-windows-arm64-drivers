/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetWdiCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetWdiDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
NDIS_STATUS
Ap6256NetWdiOidRequest(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PNDIS_OID_REQUEST OidRequest);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256NetGoEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 EventType, _In_ UINT32 Status,
                 _In_ UINT32 Reason, _In_ UINT16 Flags, _In_reads_(6) const UCHAR* Address,
                 _In_reads_bytes_opt_(Length) const UCHAR* Data, _In_ ULONG Length);
