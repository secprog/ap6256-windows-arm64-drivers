/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_wire.h"

static AP6256_HC_U16 Hw16(const AP6256_HC_U8* p)
{ return (AP6256_HC_U16)(p[0] | ((AP6256_HC_U16)p[1] << 8)); }
static AP6256_HC_U32 Hw32(const AP6256_HC_U8* p)
{ return (AP6256_HC_U32)Hw16(p) | ((AP6256_HC_U32)Hw16(p + 2) << 16); }
static void HwPut16(AP6256_HC_U8* p, AP6256_HC_U32 n)
{ p[0] = (AP6256_HC_U8)n; p[1] = (AP6256_HC_U8)(n >> 8); }
static void HwPut32(AP6256_HC_U8* p, AP6256_HC_U32 n)
{ HwPut16(p, n); HwPut16(p + 2, n >> 16); }
static void HwZero(void* p, AP6256_HC_U32 n)
{ AP6256_HC_U8* b = (AP6256_HC_U8*)p; while (n--) *b++ = 0; }
static void HwCopy(void* To, const void* From, AP6256_HC_U32 n)
{
    AP6256_HC_U8* a = (AP6256_HC_U8*)To;
    const AP6256_HC_U8* b = (const AP6256_HC_U8*)From;
    while (n--) *a++ = *b++;
}
static int HwSeparate(const void* a, AP6256_HC_U32 an, const void* b, AP6256_HC_U32 bn)
{
    AP6256_HC_U64 ap = (AP6256_HC_U64)a, bp = (AP6256_HC_U64)b;
    return ap + an >= ap && bp + bn >= bp && (ap + an <= bp || bp + bn <= ap);
}
static int HwEqual6(const AP6256_HC_U8* a, const AP6256_HC_U8* b)
{
    AP6256_HC_U32 i, different = 0;
    for (i = 0; i < 6; ++i) different |= a[i] ^ b[i];
    return different == 0;
}
static int HwUnicast(const AP6256_HC_U8* p)
{
    AP6256_HC_U32 i, any = 0;
    for (i = 0; i < 6; ++i) any |= p[i];
    return any && !(p[0] & 1u);
}
static int HwSession(const AP6256_HC_WIRE_SESSION* s)
{
    return s && s->Generation && s->IfIndex < 16 &&
        !s->Reserved[0] && !s->Reserved[1] && !s->Reserved[2] &&
        HwUnicast(s->Station) && HwUnicast(s->Bssid) && !HwEqual6(s->Station, s->Bssid);
}
static AP6256_HC_U32 HwHeader(AP6256_HC_U32 Type)
{
    return Type == AP6256_HC_DATA_TX || Type == AP6256_HC_DATA_TX_HANDSHAKE ||
        Type == AP6256_HC_DATA_TX_NO_KEY || Type == AP6256_HC_MGMT_TX_REPLY ||
        Type == AP6256_HC_MGMT_TX_DIRECT ? AP6256_HC_WIRE_TX_HEADER : AP6256_HC_WIRE_HEADER;
}
static int HwRobust(AP6256_HC_U16 Fc, const AP6256_HC_U8* Body, AP6256_HC_U32 Length)
{
    AP6256_HC_U32 subtype = Fc & 0xf0u, category;
    if (subtype == 0xa0u || subtype == 0xc0u) return Length >= 2;
    if (subtype != 0xd0u || Length < 2) return 0;
    category = Body[0];
    return category != 4 && category != 7 && category != 11 && category != 15 &&
        category != 20 && category != 21 && category != 22 && category != 127;
}
static int HwGcmp(AP6256_HC_WIRE_VIEW* v, AP6256_HC_U32 Header, int Pairwise)
{
    const AP6256_HC_U8* iv;
    if (!(v->FrameControl & 0x4000u) || v->Length < Header + 24u) return 0;
    iv = v->Frame + Header;
    if (iv[2] || (iv[3] & 0x3fu) != 0x20u) return 0;
    v->KeyId = (AP6256_HC_U8)(iv[3] >> 6);
    return !Pairwise || v->KeyId <= 1;
}
static int HwBip(AP6256_HC_WIRE_VIEW* v)
{
    const AP6256_HC_U8* mmie;
    AP6256_HC_U16 id;
    if ((v->FrameControl & 0x4000u) || v->Length < 50u) return 0;
    mmie = v->Frame + v->Length - 26;
    id = Hw16(mmie + 2);
    if (mmie[0] != 76 || mmie[1] != 24 || (id != 4 && id != 5)) return 0;
    v->KeyId = (AP6256_HC_U8)id;
    return HwRobust(v->FrameControl, v->Frame + 24, v->Length - 50);
}
static int HwFrame(const AP6256_HC_WIRE_SESSION* s, AP6256_HC_WIRE_VIEW* v)
{
    const AP6256_HC_U8* f = v->Frame;
    AP6256_HC_U32 header = 24, subtype, direction;
    int transmit, group, data;
    if (v->Type < AP6256_HC_DATA_TX || v->Type > AP6256_HC_DATA_RX_MSDU_VERIFIED) return 0;
    if (v->Type == AP6256_HC_MGMT_DROP)
        return v->Token && !v->Epoch && !v->Length;
    if (!f || v->Length < 24 || v->Length > AP6256_HC_MAX_FRAME) return 0;
    transmit = v->Type == AP6256_HC_DATA_TX || v->Type == AP6256_HC_DATA_TX_HANDSHAKE ||
        v->Type == AP6256_HC_DATA_TX_NO_KEY || v->Type == AP6256_HC_MGMT_TX_REQUEST ||
        v->Type == AP6256_HC_MGMT_TX_REPLY || v->Type == AP6256_HC_MGMT_TX_DIRECT;
    data = v->Type == AP6256_HC_DATA_TX || v->Type == AP6256_HC_DATA_TX_HANDSHAKE ||
        v->Type == AP6256_HC_DATA_TX_NO_KEY || v->Type == AP6256_HC_DATA_RX ||
        v->Type == AP6256_HC_DATA_RX_VERIFIED || v->Type == AP6256_HC_DATA_RX_MSDU_VERIFIED;
    if (v->Type == AP6256_HC_DATA_RX_MSDU_VERIFIED) {
        if ((v->Token != 1 && v->Token != 2) || !v->Epoch) return 0;
    } else if (data || v->Type == AP6256_HC_MGMT_TX_DIRECT) { if (v->Token) return 0; }
    else if (!v->Token) return 0;
    if (v->Type == AP6256_HC_DATA_RX || v->Type == AP6256_HC_MGMT_RX ||
        v->Type == AP6256_HC_MGMT_TX_REQUEST) { if (v->Epoch) return 0; }
    else if (!data && !v->Epoch) return 0;
    v->FrameControl = Hw16(f); v->SequenceControl = Hw16(f + 22);
    if ((v->FrameControl & 3u) || (v->FrameControl & 0x0300u) == 0x0300u) return 0;
    group = f[4] & 1u;
    if (transmit) {
        if (!HwEqual6(f + 10, s->Station) || (!group && !HwEqual6(f + 4, s->Bssid))) return 0;
    } else if (!HwEqual6(f + 10, s->Bssid) || (!group && !HwEqual6(f + 4, s->Station))) return 0;
    if (data) {
        subtype = v->FrameControl & 0xfcu;
        direction = v->FrameControl & 0x0300u;
        if ((subtype != 8 && subtype != 0x88u) || direction != (transmit ? 0x0100u : 0x0200u) ||
            (transmit && group)) return 0;
        if (subtype == 0x88u) {
            if (v->Length < 26 || (transmit && (f[24] & 0x80u))) return 0;
            v->Tid = f[24] & 15u; header = (v->FrameControl & 0x8000u) ? 30u : 26u;
        } else if (v->FrameControl & 0x8000u) return 0;
        if (v->Length < header) return 0;
        v->Fragmented = (AP6256_HC_U8)(!!(v->SequenceControl & 15u) || !!(v->FrameControl & 0x0400u));
        if (v->Fragmented && (group || (subtype == 0x88u && (f[24] & 0x80u)))) return 0;
        if (v->Type == AP6256_HC_DATA_TX_HANDSHAKE &&
            (!(v->FrameControl & 0x4000u) || !v->Epoch || v->Fragmented)) return 0;
        if (v->Type == AP6256_HC_DATA_TX_NO_KEY && ((v->FrameControl & 0x4000u) || v->Epoch)) return 0;
        if (v->Type == AP6256_HC_DATA_RX_MSDU_VERIFIED)
            return !(v->FrameControl & 0x4000u) && !v->Fragmented &&
                !(subtype == 0x88u && (f[24] & 0x80u));
        if (v->Type == AP6256_HC_DATA_RX_VERIFIED && v->Epoch)
            return !(v->FrameControl & 0x4000u) && !v->Fragmented;
        if (v->FrameControl & 0x4000u)
            return (!transmit || v->Epoch) && HwGcmp(v, header, !group);

        if (!transmit)
            return !v->Epoch && (!v->Fragmented || v->Type == AP6256_HC_DATA_RX) && v->Length > header &&
                !(subtype == 0x88u && (f[24] & 0x80u));

        return !v->Epoch && !v->Fragmented && !(subtype == 0x88u && (f[24] & 0x80u)) &&
            v->Length >= header + 8u && f[header] == 0xaa && f[header + 1] == 0xaa &&
            f[header + 2] == 3 && !f[header + 3] && !f[header + 4] && !f[header + 5] &&
            f[header + 6] == 0x88 && f[header + 7] == 0x8e;
    }
    if ((v->FrameControl & 0x830cu) || v->Fragmented ||
        (v->SequenceControl & 15u) || (v->FrameControl & 0x0400u) || !HwEqual6(f + 16, s->Bssid)) return 0;
    subtype = v->FrameControl & 0xf0u;
    if (subtype != 0xa0u && subtype != 0xc0u && subtype != 0xd0u) return 0;
    if (v->Type == AP6256_HC_MGMT_RX_VERIFIED || v->Type == AP6256_HC_MGMT_TX_REQUEST)
        return !(v->FrameControl & 0x4000u) && HwRobust(v->FrameControl, f + 24, v->Length - 24);
    if (v->FrameControl & 0x4000u) return !group && v->Length >= 50u && HwGcmp(v, 24, 1);
    if (group && HwBip(v)) return 1;

    return v->Type == AP6256_HC_MGMT_RX && HwRobust(v->FrameControl, f + 24, v->Length - 24);
}

static void HwWriteHeader(const AP6256_HC_WIRE_SESSION* Session,
    AP6256_HC_U32 Type, AP6256_HC_U32 Token, AP6256_HC_U32 Epoch,
    AP6256_HC_U32 Length, AP6256_HC_U8* Header, AP6256_HC_U32 header)
{
    HwZero(Header, header);
    HwPut32(Header, AP6256_HC_WIRE_MAGIC); HwPut16(Header + 4, AP6256_HC_WIRE_VERSION);
    HwPut16(Header + 6, header); HwPut32(Header + 8, Session->Generation);
    HwPut32(Header + 12, Token); HwPut16(Header + 16, Length);
    Header[18] = Session->IfIndex; Header[19] = (AP6256_HC_U8)Type;
    HwPut32(Header + 20, Epoch);
}

int Ap6256HostCipherWireWrite(const AP6256_HC_WIRE_SESSION* Session,
    AP6256_HC_U32 Type, AP6256_HC_U32 Token, AP6256_HC_U32 Epoch,
    const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Header, AP6256_HC_U32 Capacity)
{
    AP6256_HC_WIRE_VIEW view;
    AP6256_HC_U32 header = HwHeader(Type);
    if (!Session || !HwSession(Session) || !Header || Capacity < header ||
        !HwSeparate(Header, header, Session, sizeof(*Session)) ||
        (Length && !HwSeparate(Header, header, Frame, Length))) return 0;
    HwZero(&view, sizeof(view)); view.Type = (AP6256_HC_U8)Type;
    if (Type != view.Type) return 0;
    view.Token = Token; view.Epoch = Epoch; view.Frame = Frame; view.Length = Length;
    if (!HwFrame(Session, &view)) return 0;
    HwWriteHeader(Session, Type, Token, Epoch, Length, Header, header); return 1;
}

int Ap6256HostCipherWireRead(const AP6256_HC_WIRE_SESSION* Session,
    AP6256_HC_U32 Type, const AP6256_HC_U8* Wire, AP6256_HC_U32 Length,
    AP6256_HC_WIRE_VIEW* View)
{
    AP6256_HC_WIRE_VIEW v;
    AP6256_HC_U32 header, i;
    if (!View || (Wire && !HwSeparate(View, sizeof(*View), Wire, Length)) ||
        (Session && !HwSeparate(View, sizeof(*View), Session, sizeof(*Session)))) return 0;
    HwZero(View, sizeof(*View));
    if (!Session || !HwSession(Session) || !Wire || Length < AP6256_HC_WIRE_HEADER ||
        Hw32(Wire) != AP6256_HC_WIRE_MAGIC || Hw16(Wire + 4) != AP6256_HC_WIRE_VERSION ||
        Hw32(Wire + 8) != Session->Generation || Wire[18] != Session->IfIndex || Wire[19] != Type) return 0;
    header = HwHeader(Type);
    if (Hw16(Wire + 6) != header || Length < header || Hw16(Wire + 16) != Length - header) return 0;
    for (i = AP6256_HC_WIRE_HEADER; i < header; ++i) if (Wire[i]) return 0;
    HwZero(&v, sizeof(v)); v.Type = (AP6256_HC_U8)Type;
    v.Frame = Wire + header; v.Length = Length - header; v.HeaderBytes = header;
    v.Token = Hw32(Wire + 12); v.Epoch = Hw32(Wire + 20);
    if (!HwFrame(Session, &v)) return 0;
    HwCopy(View, &v, sizeof(v)); return 1;
}

static int HwDataRxPrefix(const AP6256_HC_WIRE_SESSION* Session,
    const AP6256_HC_U8* Prefix, AP6256_HC_U32 PrefixBytes, AP6256_HC_U32 FrameBytes)
{
    AP6256_HC_WIRE_VIEW v;
    AP6256_HC_U32 needed = FrameBytes < AP6256_HC_DATA_RX_PREFIX ? FrameBytes : AP6256_HC_DATA_RX_PREFIX;
    if (!HwSession(Session) || !Prefix || FrameBytes < 24 || FrameBytes > AP6256_HC_MAX_FRAME ||
        PrefixBytes < needed || PrefixBytes > FrameBytes) return 0;
    HwZero(&v, sizeof(v)); v.Type = AP6256_HC_DATA_RX;
    v.Frame = Prefix; v.Length = FrameBytes;

    return HwFrame(Session, &v);
}

int Ap6256HostCipherWireWriteDataRxPrefix(const AP6256_HC_WIRE_SESSION* Session,
    const AP6256_HC_U8* Prefix, AP6256_HC_U32 PrefixBytes, AP6256_HC_U32 FrameBytes,
    AP6256_HC_U8* Header, AP6256_HC_U32 Capacity)
{
    if (!Header || Capacity < AP6256_HC_WIRE_HEADER || !Session ||
        !HwSeparate(Header, AP6256_HC_WIRE_HEADER, Session, sizeof(*Session)) ||
        !HwSeparate(Header, AP6256_HC_WIRE_HEADER, Prefix, PrefixBytes) ||
        !HwDataRxPrefix(Session, Prefix, PrefixBytes, FrameBytes)) return 0;
    HwWriteHeader(Session, AP6256_HC_DATA_RX, 0, 0, FrameBytes, Header, AP6256_HC_WIRE_HEADER);
    return 1;
}

int Ap6256HostCipherWireReadDataRxPrefix(const AP6256_HC_WIRE_SESSION* Session,
    const AP6256_HC_U8* Header, AP6256_HC_U32 HeaderBytes,
    const AP6256_HC_U8* Prefix, AP6256_HC_U32 PrefixBytes, AP6256_HC_U32 FrameBytes)
{
    return Header && HeaderBytes == AP6256_HC_WIRE_HEADER && HwSession(Session) &&
        Hw32(Header) == AP6256_HC_WIRE_MAGIC && Hw16(Header + 4) == AP6256_HC_WIRE_VERSION &&
        Hw16(Header + 6) == AP6256_HC_WIRE_HEADER && Hw32(Header + 8) == Session->Generation &&
        !Hw32(Header + 12) && Hw16(Header + 16) == FrameBytes &&
        Header[18] == Session->IfIndex && Header[19] == AP6256_HC_DATA_RX && !Hw32(Header + 20) &&
        HwDataRxPrefix(Session, Prefix, PrefixBytes, FrameBytes);
}
