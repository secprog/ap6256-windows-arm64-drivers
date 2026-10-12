/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "host_cipher_frame.h"

#define AP6256_HC_WIRE_MAGIC 0x31574348u
#define AP6256_HC_WIRE_VERSION 1u

#define AP6256_HC_RELAY_FEATURES 0x11fu
#define AP6256_HC_WIRE_HEADER 24u
#define AP6256_HC_WIRE_TX_HEADER 160u
#define AP6256_HC_DATA_RX_PREFIX 38u

#define AP6256_HC_DATA_TX 1u
#define AP6256_HC_DATA_RX 2u
#define AP6256_HC_MGMT_RX 3u
#define AP6256_HC_MGMT_RX_VERIFIED 4u
#define AP6256_HC_MGMT_TX_REQUEST 5u
#define AP6256_HC_MGMT_TX_REPLY 6u
#define AP6256_HC_MGMT_DROP 7u
#define AP6256_HC_MGMT_TX_DIRECT 8u

#define AP6256_HC_DATA_RX_VERIFIED 9u

#define AP6256_HC_DATA_TX_HANDSHAKE 10u
#define AP6256_HC_DATA_TX_NO_KEY 11u

#define AP6256_HC_DATA_RX_MSDU_VERIFIED 12u

typedef struct _AP6256_HC_WIRE_SESSION {
    AP6256_HC_U32 Generation;
    AP6256_HC_U8 IfIndex, Station[6], Bssid[6], Reserved[3];
} AP6256_HC_WIRE_SESSION;

typedef struct _AP6256_HC_WIRE_VIEW {
    const AP6256_HC_U8* Frame;
    AP6256_HC_U32 Length, HeaderBytes, Token, Epoch;
    AP6256_HC_U16 FrameControl, SequenceControl;
    AP6256_HC_U8 Type, Tid, Fragmented, KeyId;
} AP6256_HC_WIRE_VIEW;

int Ap6256HostCipherWireRead(const AP6256_HC_WIRE_SESSION* Session,
    AP6256_HC_U32 Type, const AP6256_HC_U8* Wire, AP6256_HC_U32 Length,
    AP6256_HC_WIRE_VIEW* View);
int Ap6256HostCipherWireWrite(const AP6256_HC_WIRE_SESSION* Session,
    AP6256_HC_U32 Type, AP6256_HC_U32 Token, AP6256_HC_U32 Epoch,
    const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Header, AP6256_HC_U32 Capacity);

int Ap6256HostCipherWireWriteDataRxPrefix(const AP6256_HC_WIRE_SESSION* Session,
    const AP6256_HC_U8* Prefix, AP6256_HC_U32 PrefixBytes, AP6256_HC_U32 FrameBytes,
    AP6256_HC_U8* Header, AP6256_HC_U32 Capacity);
int Ap6256HostCipherWireReadDataRxPrefix(const AP6256_HC_WIRE_SESSION* Session,
    const AP6256_HC_U8* Header, AP6256_HC_U32 HeaderBytes,
    const AP6256_HC_U8* Prefix, AP6256_HC_U32 PrefixBytes, AP6256_HC_U32 FrameBytes);
