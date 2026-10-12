/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

typedef unsigned char AP6256_HC_U8;
typedef unsigned short AP6256_HC_U16;
typedef unsigned int AP6256_HC_U32;
typedef unsigned long long AP6256_HC_U64;
typedef char AP6256_HC_WIDTHS[(sizeof(AP6256_HC_U8) == 1 &&
    sizeof(AP6256_HC_U16) == 2 && sizeof(AP6256_HC_U32) == 4 &&
    sizeof(AP6256_HC_U64) == 8) ? 1 : -1];

#define AP6256_HC_GCMP256       9u
#define AP6256_HC_BIPGMAC256    12u
#define AP6256_HC_KEY_BYTES     32u
#define AP6256_HC_TAG_BYTES     16u
#define AP6256_HC_MAX_FRAME     8192u
#define AP6256_HC_MAX_PN        0x0000ffffffffffffull
#define AP6256_HC_RX_QUEUES     18u

typedef int (*AP6256_HC_AEAD)(void* Context, int Encrypt,
    const AP6256_HC_U8 Nonce[12], const AP6256_HC_U8* Aad,
    AP6256_HC_U32 AadLength, const AP6256_HC_U8* Input,
    AP6256_HC_U32 InputLength, AP6256_HC_U8* Output,
    AP6256_HC_U8 Tag[AP6256_HC_TAG_BYTES]);

typedef struct _AP6256_HC_KEY_STATE {
    AP6256_HC_U32 Cipher;
    AP6256_HC_U16 KeyId;
    AP6256_HC_U8 Pairwise;
    AP6256_HC_U8 TxAllowed;
    AP6256_HC_U8 Station[6];
    AP6256_HC_U8 Bssid[6];
    AP6256_HC_U8 RxAllowed;
    AP6256_HC_U64 TxPn;
    AP6256_HC_U64 RxPn[AP6256_HC_RX_QUEUES];
} AP6256_HC_KEY_STATE;

int Ap6256HostCipherInit(AP6256_HC_KEY_STATE* State,
    AP6256_HC_U32 Cipher, AP6256_HC_U16 KeyId, int Pairwise, int TxAllowed, int RxAllowed,
    const AP6256_HC_U8 Station[6], const AP6256_HC_U8 Bssid[6],
    AP6256_HC_U64 ReceivePn);

int Ap6256HostCipherRaiseReceivePn(AP6256_HC_KEY_STATE* State, AP6256_HC_U64 ReceivePn);

int Ap6256HostCipherEncrypt(AP6256_HC_KEY_STATE* State,
    AP6256_HC_AEAD Aead, void* Context,
    const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Output, AP6256_HC_U32 Capacity,
    AP6256_HC_U8* Scratch, AP6256_HC_U32 ScratchCapacity, AP6256_HC_U32* Written);
int Ap6256HostCipherDecrypt(AP6256_HC_KEY_STATE* State,
    AP6256_HC_AEAD Aead, void* Context,
    const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Output, AP6256_HC_U32 Capacity,
    AP6256_HC_U8* Scratch, AP6256_HC_U32 ScratchCapacity, AP6256_HC_U32* Written);
