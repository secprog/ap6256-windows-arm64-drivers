/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathInit(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathStart(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathStop(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256DatapathOnInterrupt(_In_ PAP6256_DEVICE_CONTEXT Ctx);

static __forceinline ULONG Ap6256TxHdrLen(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    return Ctx->Sdio.TxGlom ? SDPCM_GLOM_HDRLEN : SDPCM_HDRLEN;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathEnableTxGlom(_In_ PAP6256_DEVICE_CONTEXT Ctx);

typedef struct _AP6256_TX_GLOM_FRAME {
    ULONG Offset;
    ULONG WireLength;
} AP6256_TX_GLOM_FRAME, *PAP6256_TX_GLOM_FRAME;

#define AP6256_TX_GLOM_MAX_FRAMES   32u

_IRQL_requires_max_(DISPATCH_LEVEL)
ULONG Ap6256DatapathTxGlomBytes(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathSendGlom(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _Inout_updates_bytes_(BufferSize) PUCHAR Buffer,
                                _In_ ULONG BufferSize,
                                _In_reads_(Count) const AP6256_TX_GLOM_FRAME* Frames,
                                _In_ ULONG Count,
                                _Out_ PULONG Sent);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256TraceHotspotPacket(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ AP6256_GO_DATA_STAGE Stage, _In_ UINT32 IfIndex,
    _In_reads_bytes_(Length) const UCHAR* Frame, _In_ ULONG Length,
    _In_ NTSTATUS Status);

_IRQL_requires_max_(PASSIVE_LEVEL)

#define AP6256_TX_PRIORITY  0

NTSTATUS Ap6256DatapathTransmit(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathSendSdpcm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Inout_updates_bytes_(TransferLength) PUCHAR Frame,
                                 _In_ ULONG TransferLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathSuspend(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256DatapathResume(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256DatapathTransmitEx(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length, UCHAR Priority,
    UCHAR Exemption, UCHAR IfIndex, UINT16 Port, UINT16 Peer, PVOID Cookie);
