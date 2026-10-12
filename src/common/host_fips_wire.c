/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_fips_wire.h"

static AP6256_FIPS_U16 le16(const AP6256_FIPS_U8* p)
{
    return (AP6256_FIPS_U16)((AP6256_FIPS_U16)p[0] | ((AP6256_FIPS_U16)p[1] << 8));
}

static AP6256_FIPS_U32 le32(const AP6256_FIPS_U8* p)
{
    return (AP6256_FIPS_U32)p[0] | ((AP6256_FIPS_U32)p[1] << 8) |
        ((AP6256_FIPS_U32)p[2] << 16) | ((AP6256_FIPS_U32)p[3] << 24);
}

static void put16(AP6256_FIPS_U8* p, AP6256_FIPS_U16 value)
{
    p[0] = (AP6256_FIPS_U8)value;
    p[1] = (AP6256_FIPS_U8)(value >> 8);
}

static void put32(AP6256_FIPS_U8* p, AP6256_FIPS_U32 value)
{
    p[0] = (AP6256_FIPS_U8)value;
    p[1] = (AP6256_FIPS_U8)(value >> 8);
    p[2] = (AP6256_FIPS_U8)(value >> 16);
    p[3] = (AP6256_FIPS_U8)(value >> 24);
}

static int equal6(const AP6256_FIPS_U8* a, const AP6256_FIPS_U8* b)
{
    unsigned int i;
    for (i = 0; i < 6; i++) if (a[i] != b[i]) return 0;
    return 1;
}

static int unicast(const AP6256_FIPS_U8* address)
{
    unsigned int i, nonzero = 0;
    for (i = 0; i < 6; i++) nonzero |= address[i];
    return nonzero != 0 && !(address[0] & 1u);
}

static int session_valid(const AP6256_FIPS_SESSION* s)
{
    return s && s->Generation && s->IfIndex < 16 && unicast(s->Station) &&
        unicast(s->Bssid) && !equal6(s->Station, s->Bssid);
}

static void clear_view(AP6256_FIPS_FRAME_VIEW* view)
{
    if (!view) return;
    view->Frame = 0;
    view->Length = 0;
    view->HeaderLength = 0;
    view->FrameControl = 0;
    view->SequenceControl = 0;
    view->Tid = 0;
    view->Fragmented = 0;
}

static int flags_valid(AP6256_FIPS_U8 direction, AP6256_FIPS_U16 flags)
{
    if (direction == AP6256_FIPS_TX) return flags == 0;
    return direction == AP6256_FIPS_RX &&
        flags == (AP6256_FIPS_RX_CRC_VERIFIED | AP6256_FIPS_RX_UNDECRYPTED);
}

int Ap6256FipsValidateFrame(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, const AP6256_FIPS_U8* Frame,
    AP6256_FIPS_U32 Length, AP6256_FIPS_FRAME_VIEW* View)
{
    AP6256_FIPS_U16 fc, sequence, qos = 0;
    AP6256_FIPS_U32 header = 24;
    clear_view(View);
    if (!View || !session_valid(Session) || !Frame || Length < 24 ||
        Length > AP6256_FIPS_MAX_MPDU_BYTES ||
        (Direction != AP6256_FIPS_TX && Direction != AP6256_FIPS_RX)) return 0;
    fc = le16(Frame);
    sequence = le16(Frame + 22);

    if ((fc & 0x000fu) != 0x0008u || (fc & 0x0040u) ||
        (fc & 0x0300u) != (Direction == AP6256_FIPS_TX ? 0x0100u : 0x0200u)) return 0;
    if (fc & 0x0080u) {
        if (Length < 26) return 0;
        qos = le16(Frame + 24);
        header = 26;
        if (fc & 0x8000u) header += 4;

        if (Direction == AP6256_FIPS_TX && (qos & 0x0080u)) return 0;
    }
    if (Length <= header || ((fc & 0x4000u) && Length - header < 16)) return 0;
    if (Direction == AP6256_FIPS_TX) {
        if (!equal6(Frame + 4, Session->Bssid) || !equal6(Frame + 10, Session->Station)) return 0;
    } else {
        if (!equal6(Frame + 10, Session->Bssid) ||
            (!(Frame[4] & 1u) && !equal6(Frame + 4, Session->Station))) return 0;
    }
    View->Frame = Frame;
    View->Length = Length;
    View->HeaderLength = header;
    View->FrameControl = fc;
    View->SequenceControl = sequence;
    View->Tid = (AP6256_FIPS_U8)(qos & 15u);
    View->Fragmented = (AP6256_FIPS_U8)(((fc & 0x0400u) || (sequence & 15u)) ? 1u : 0u);
    return 1;
}

int Ap6256FipsWriteHeader(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, AP6256_FIPS_U16 Flags,
    const AP6256_FIPS_U8* Frame, AP6256_FIPS_U32 FrameLength,
    AP6256_FIPS_U8* Header, AP6256_FIPS_U32 Capacity)
{
    AP6256_FIPS_FRAME_VIEW view;
    unsigned int i;
    AP6256_FIPS_U32 header = Direction == AP6256_FIPS_TX ?
        AP6256_FIPS_TX_HEADER_BYTES : AP6256_FIPS_WIRE_HEADER_BYTES;
    if (!Header || Capacity < header ||
        !flags_valid(Direction, Flags) ||
        !Ap6256FipsValidateFrame(Session, Direction, Frame, FrameLength, &view)) return 0;
    for (i = 0; i < header; i++) Header[i] = 0;
    put32(Header, AP6256_FIPS_WIRE_MAGIC);
    put16(Header + 4, AP6256_FIPS_WIRE_VERSION);
    put16(Header + 6, (AP6256_FIPS_U16)header);
    put32(Header + 8, Session->Generation);
    put16(Header + 12, (AP6256_FIPS_U16)FrameLength);
    Header[14] = Session->IfIndex;
    Header[15] = Direction;
    put16(Header + 16, Flags);
    return 1;
}

int Ap6256FipsReadEnvelope(const AP6256_FIPS_SESSION* Session,
    AP6256_FIPS_U8 Direction, const AP6256_FIPS_U8* Bytes,
    AP6256_FIPS_U32 Length, AP6256_FIPS_FRAME_VIEW* View)
{
    AP6256_FIPS_U32 frameLength, i;
    AP6256_FIPS_U32 header = Direction == AP6256_FIPS_TX ?
        AP6256_FIPS_TX_HEADER_BYTES : AP6256_FIPS_WIRE_HEADER_BYTES;
    clear_view(View);
    if (!View || !session_valid(Session) || !Bytes ||
        Length < header ||
        le32(Bytes) != AP6256_FIPS_WIRE_MAGIC ||
        le16(Bytes + 4) != AP6256_FIPS_WIRE_VERSION ||
        le16(Bytes + 6) != header ||
        le32(Bytes + 8) != Session->Generation || Bytes[14] != Session->IfIndex ||
        Bytes[15] != Direction || !flags_valid(Direction, le16(Bytes + 16)) ||
        le16(Bytes + 18) || le32(Bytes + 20)) return 0;
    frameLength = le16(Bytes + 12);
    for (i = AP6256_FIPS_WIRE_HEADER_BYTES; i < header; i++)
        if (Bytes[i]) return 0;

    if (frameLength != Length - header) return 0;
    return Ap6256FipsValidateFrame(Session, Direction,
        Bytes + header, frameLength, View);
}
