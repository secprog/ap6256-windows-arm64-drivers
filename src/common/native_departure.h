/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#define AP6256_ND_ABI 0x3150444eu
#define AP6256_ND_BYTES 48u
#define AP6256_ND_START 1u
#define AP6256_ND_COMMIT 2u
#define AP6256_ND_PENDING 1u
#define AP6256_ND_ACKED 2u
#define AP6256_ND_FAILED 3u
#define AP6256_ND_COMMITTED 4u
#define AP6256_ND_COMMITTING 5u
#define AP6256_ND_ELIGIBLE 1u
#define AP6256_ND_PMF 2u

typedef struct _AP6256_NATIVE_DEPARTURE_CONTROL {
    unsigned int Abi, Bytes, Token, Operation, Reason;
    unsigned char Peer[6], Reserved[2];
    unsigned int State;
    int NativeStatus;
    unsigned int TxStatus, Attempts, Flags;
} AP6256_NATIVE_DEPARTURE_CONTROL;
