/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

typedef unsigned char AP6256_FIPS_U8;
typedef unsigned short AP6256_FIPS_U16;
typedef unsigned int AP6256_FIPS_U32;
typedef char AP6256_FIPS_TYPE_WIDTHS[(sizeof(AP6256_FIPS_U8) == 1 &&
    sizeof(AP6256_FIPS_U16) == 2 && sizeof(AP6256_FIPS_U32) == 4) ? 1 : -1];

#define AP6256_FIPS_WIRE_MAGIC           0x50494648u
#define AP6256_FIPS_WIRE_VERSION         1u
#define AP6256_FIPS_WIRE_HEADER_BYTES    24u

#define AP6256_FIPS_TX_HEADER_BYTES      160u

#define AP6256_FIPS_MAX_MPDU_BYTES       8192u

#define AP6256_FIPS_BCDC_TX_EXEMPT       3u
#define AP6256_FIPS_BCDC_RX_FLAGS2       0x80u
#define AP6256_FIPS_TX                   1u
#define AP6256_FIPS_RX                   2u
#define AP6256_FIPS_RX_CRC_VERIFIED      0x0001u
#define AP6256_FIPS_RX_UNDECRYPTED       0x0002u

typedef struct _AP6256_FIPS_SESSION {
    AP6256_FIPS_U32 Generation;
    AP6256_FIPS_U8 IfIndex;
    AP6256_FIPS_U8 Station[6];
    AP6256_FIPS_U8 Bssid[6];
} AP6256_FIPS_SESSION;

typedef struct _AP6256_FIPS_FRAME_VIEW {
    const AP6256_FIPS_U8* Frame;
    AP6256_FIPS_U32 Length;
    AP6256_FIPS_U32 HeaderLength;
    AP6256_FIPS_U16 FrameControl;
    AP6256_FIPS_U16 SequenceControl;
    AP6256_FIPS_U8 Tid;
    AP6256_FIPS_U8 Fragmented;
} AP6256_FIPS_FRAME_VIEW;

int Ap6256FipsValidateFrame(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, const AP6256_FIPS_U8* Frame,
    AP6256_FIPS_U32 Length, AP6256_FIPS_FRAME_VIEW* View);

int Ap6256FipsWriteHeader(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, AP6256_FIPS_U16 Flags,
    const AP6256_FIPS_U8* Frame, AP6256_FIPS_U32 FrameLength,
    AP6256_FIPS_U8* Header, AP6256_FIPS_U32 Capacity);

int Ap6256FipsReadEnvelope(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, const AP6256_FIPS_U8* Bytes,
    AP6256_FIPS_U32 Length, AP6256_FIPS_FRAME_VIEW* View);
