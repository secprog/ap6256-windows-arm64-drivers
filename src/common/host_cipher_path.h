/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "host_cipher_store.h"
#include "host_cipher_wire.h"

#define AP6256_HC_MAX_MANAGEMENT 1760u

NTSTATUS Ap6256HostCipherManagementReply(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Request, ULONG Length, UCHAR* Reply, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written);

NTSTATUS Ap6256HostCipherManagementTx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Frame, ULONG Length, UCHAR* Wire, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written);

NTSTATUS Ap6256HostCipherDataTx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Frame, ULONG Length, UCHAR Exemption, UCHAR* Wire, ULONG Capacity,
    ULONG* Written, UCHAR* Priority);
NTSTATUS Ap6256HostCipherDataRx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length, UCHAR* PlainWire, ULONG Capacity, ULONG* Written);
BOOLEAN Ap6256HostCipherDataRxRead(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* PlainWire, ULONG Length, AP6256_HC_WIRE_VIEW* View);

typedef struct _AP6256_HC_AMSDU_CURSOR {
    const UCHAR* Frame;
    AP6256_HC_WIRE_SESSION Session;
    ULONG Header, Length, Offset, Epoch;
    BOOLEAN Group, HasData;
} AP6256_HC_AMSDU_CURSOR;
BOOLEAN Ap6256HostCipherDataRxAmsduBegin(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* PlainWire, ULONG Length, AP6256_HC_AMSDU_CURSOR* Cursor);
BOOLEAN Ap6256HostCipherDataRxAmsduNext(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_AMSDU_CURSOR* Cursor, UCHAR* PlainWire, ULONG Capacity, ULONG* Written);

BOOLEAN Ap6256HostCipherPathTxCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length);
BOOLEAN Ap6256HostCipherPathDestination(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length, UCHAR Destination[6]);
