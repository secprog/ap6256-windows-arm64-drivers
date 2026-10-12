/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "host_cipher_wire.h"

#define AP6256_HC_DISCONNECT_CLEANUP 0u
#define AP6256_HC_DISCONNECT_PROTECTED 1u
#define AP6256_HC_DISCONNECT_NATIVE_CLEAR 2u
#define AP6256_HC_DISCONNECT_FRAME_BYTES 50u
#define AP6256_HC_DISCONNECT_WIRE_BYTES (160u + AP6256_HC_DISCONNECT_FRAME_BYTES)

typedef struct _AP6256_HC_DISCONNECT_CONTROL {
    AP6256_HC_U32 Abi, Bytes, Generation, IfIndex, Reason, Mode, NativeStatus, Completed;
} AP6256_HC_DISCONNECT_CONTROL;
