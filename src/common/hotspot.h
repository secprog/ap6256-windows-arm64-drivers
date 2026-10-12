/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "wifi_ops.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoPrepare(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoStart(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_AP_PARAMS Params);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoVerifySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_AP_PARAMS* Params);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoStop(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoDelete(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GroupChangeMode(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Mode);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ClientConnect(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_CONNECT_PARAMS* Params);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ClientDisconnect(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Reason);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WaitFirmwareInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 BssIndex, _Out_ PUINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoSetBsscfg(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name,
    _In_reads_bytes_(Length) const VOID* Data, _In_ ULONG Length);

typedef struct _AP6256_GO_ASSOC_RESULT {
    const UCHAR* Response;
    ULONG ResponseLength;
    const UCHAR* Beacon;
    ULONG BeaconLength;
    UINT16 StatusCode;
} AP6256_GO_ASSOC_RESULT;

BOOLEAN Ap6256GoParseAssocResult(_In_reads_bytes_opt_(Length) const UCHAR* Data,
    _In_ ULONG Length, _Out_ AP6256_GO_ASSOC_RESULT* Result);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoDisconnectPeer(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* Address, _In_ UINT16 Reason);

typedef struct _AP6256_GO_AUTO_ASSOC {
    ULONGLONG Token;
    UCHAR Address[6];
    ULONG RequestLength;
    UCHAR Request[4 + AP6256_GO_ASSOC_IE_MAX];
    ULONG ResponseLength;
    UCHAR Response[6 + AP6256_GO_ASSOC_IE_MAX];
    ULONG BeaconLength;

    UCHAR Beacon[AP6256_BEACON_FIXED_LEN + AP6256_GO_ASSOC_IE_MAX];
} AP6256_GO_AUTO_ASSOC;

BOOLEAN Ap6256GoIesValid(_In_reads_bytes_opt_(Length) const UCHAR* Ies, _In_ ULONG Length);
BOOLEAN Ap6256GoAssociationAllowed(_In_ const AP6256_AP_PARAMS* Params,
    _In_reads_bytes_opt_(Length) const UCHAR* Ies, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GoBuildAutoAssoc(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_AP_PARAMS* Params, _In_ const AP6256_AP_PEER_INFO* Info,
    _In_reads_bytes_(Length) const UCHAR* Ies, _In_ ULONG Length,
    _Out_ AP6256_GO_AUTO_ASSOC* Assoc);
