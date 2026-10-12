/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256TalGoPeerCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* Address, _In_ UINT32 PhyId);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TalGoPeerDelete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_opt_(6) const UCHAR* Address);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TalGoRxOpen(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_reads_(6) const UCHAR* Address);

_IRQL_requires_max_(PASSIVE_LEVEL)
NDIS_STATUS
Ap6256WdiTalInitialize(_In_ NDIS_HANDLE MiniportAdapterContext,
                       _In_ NDIS_HANDLE NdisMiniportDataPathHandle,
                       _In_ PNDIS_WDI_DATA_API NdisWdiDataPathApi,
                       _Out_ PTAL_TXRX_HANDLE pMiniportTalTxRxContext,
                       _Inout_ PNDIS_MINIPORT_WDI_DATA_HANDLERS pMiniportDataHandlers,
                       _Out_ UINT32 *pMiniportWdiFrameMetadataExtraSpace);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiTalDeinitialize(_In_ TAL_TXRX_HANDLE MiniportTalTxRxContext);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                    _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
                    _In_ UCHAR Priority, _In_ UINT32 IfIndex);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256WdiRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256WdiTxResume(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256TalSetBssid(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                  _In_reads_bytes_opt_(6) const UCHAR *Bssid);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN
Ap6256TalPeerCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                    _In_reads_(6) const UCHAR* Bssid);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256TalPeerDelete(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256TalRxOpen(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID
Ap6256TalRxFlushQueue(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TalWlfcAbortProgress(_In_ PAP6256_DEVICE_CONTEXT Ctx);
