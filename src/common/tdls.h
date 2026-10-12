/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

#define AP6256_TDLS_MAGIC       0x534c4454u
#define AP6256_TDLS_VERSION     1u
#define AP6256_TDLS_DISABLED    0u
#define AP6256_TDLS_MANUAL      1u
#define AP6256_TDLS_AUTO        2u
#define AP6256_TDLS_UNKNOWN     0xffffffffu

#define AP6256_TDLS_QUERY       0u
#define AP6256_TDLS_OFF         1u
#define AP6256_TDLS_ON_MANUAL   2u
#define AP6256_TDLS_ON_AUTO     3u
#define AP6256_TDLS_DISCOVER    4u
#define AP6256_TDLS_SETUP       5u
#define AP6256_TDLS_TEARDOWN    6u

typedef struct _AP6256_TDLS_REQUEST {
    UINT32 Magic;
    UINT16 Version;
    UINT16 Operation;
    UCHAR Peer[6];
    UINT16 Reserved;
} AP6256_TDLS_REQUEST;

typedef struct _AP6256_TDLS_STATUS {
    UINT32 Version;
    UINT32 Supported;
    UINT32 RequestedMode;
    UINT32 ActiveMode;
    UINT32 Blocked;
    UINT32 DiscoveredEvents;
    UINT32 ConnectedEvents;
    UINT32 DisconnectedEvents;
} AP6256_TDLS_STATUS;

C_ASSERT(sizeof(AP6256_TDLS_REQUEST) == 16);
C_ASSERT(sizeof(AP6256_TDLS_STATUS) == 32);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TdlsInitialize(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_opt_(Length) const CHAR* Capabilities, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256TdlsControl(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Request, _In_ ULONG Length,
    _Out_ AP6256_TDLS_STATUS* Status);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256TdlsSetBlocked(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Blocked);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TdlsPeerEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_ UINT32 Status, _In_ UINT32 Reason, _In_reads_(6) const UCHAR* Peer);
