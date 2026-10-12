/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

typedef struct _AP6256_HOST_CIPHER_KEY {
    ULONG Cipher, KeyId;
    BOOLEAN Pairwise, TxAllowed, RxAllowed, PeerPresent;
    UCHAR Peer[6], Key[32], ReceiveSequence[6];
} AP6256_HOST_CIPHER_KEY;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherAddKeys(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Keys, ULONG Count);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherDeleteKeys(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Keys, ULONG Count);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherAddKey(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Key);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherDeleteKey(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    ULONG Cipher, ULONG KeyId, BOOLEAN Pairwise, const UCHAR* Peer);
