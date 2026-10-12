/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "host_cipher_frame.h"

#define AP6256_HC_EVENT_MAGIC 0x314f4348u
#define AP6256_HC_EVENT_PREFIX 16u
#define AP6256_HC_EVENT_AUTH_FLAG 0x80000000u
#define AP6256_STATION_EVENT_HOST_CIPHER 2u

static inline int Ap6256HostCipherEventSeparate(const void* A, AP6256_HC_U32 An,
    const void* B, AP6256_HC_U32 Bn)
{
    AP6256_HC_U64 a = (AP6256_HC_U64)A, b = (AP6256_HC_U64)B;
    return a + An >= a && b + Bn >= b && (a + An <= b || b + Bn <= a);
}

static inline int Ap6256HostCipherEventRead(const AP6256_HC_U8* Body,
    AP6256_HC_U32 Length, AP6256_HC_U32* Generation, AP6256_HC_U8 Peer[6])
{
    AP6256_HC_U32 i, generation, any = 0;
    if (!Body || Length < AP6256_HC_EVENT_PREFIX || !Generation || !Peer ||
        !Ap6256HostCipherEventSeparate(Body, 16, Generation, 4) ||
        !Ap6256HostCipherEventSeparate(Body, 16, Peer, 6) ||
        !Ap6256HostCipherEventSeparate(Generation, 4, Peer, 6)) return 0;
    if (Body[0] != 'H' || Body[1] != 'C' || Body[2] != 'O' || Body[3] != '1' ||
        Body[14] != 1 || Body[15] || (Body[8] & 1u)) return 0;
    generation = Body[4] | ((AP6256_HC_U32)Body[5] << 8) |
        ((AP6256_HC_U32)Body[6] << 16) | ((AP6256_HC_U32)Body[7] << 24);
    for (i = 0; i < 6; ++i) any |= Body[8 + i];
    if (!generation || !any) return 0;
    *Generation = generation;
    for (i = 0; i < 6; ++i) Peer[i] = Body[8 + i];
    return 1;
}

static inline void Ap6256HostCipherEventWrite(AP6256_HC_U8 Header[16],
    AP6256_HC_U32 Generation, const AP6256_HC_U8 Peer[6])
{
    AP6256_HC_U32 i;
    Header[0] = 'H'; Header[1] = 'C'; Header[2] = 'O'; Header[3] = '1';
    for (i = 0; i < 4; ++i) Header[4 + i] = (AP6256_HC_U8)(Generation >> (i * 8));
    for (i = 0; i < 6; ++i) Header[8 + i] = Peer[i];
    Header[14] = 1; Header[15] = 0;
}
