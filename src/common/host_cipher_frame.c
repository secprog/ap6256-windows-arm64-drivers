/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_frame.h"

typedef struct _HC_FRAME {
    AP6256_HC_U16 Fc;
    AP6256_HC_U32 Header;
    AP6256_HC_U32 Queue;
    int Management;
    int Qos;
} HC_FRAME;

static void HcCopy(AP6256_HC_U8* To, const AP6256_HC_U8* From, AP6256_HC_U32 Bytes)
{
    AP6256_HC_U32 i;
    for (i = 0; i < Bytes; ++i) To[i] = From[i];
}

static void HcErase(void* Buffer, AP6256_HC_U32 Bytes)
{
    volatile AP6256_HC_U8* p = (volatile AP6256_HC_U8*)Buffer;
    while (Bytes--) *p++ = 0;
}

static AP6256_HC_U16 HcLe16(const AP6256_HC_U8* p)
{
    return (AP6256_HC_U16)(p[0] | ((AP6256_HC_U16)p[1] << 8));
}

static void HcPut16(AP6256_HC_U8* p, AP6256_HC_U16 Value)
{
    p[0] = (AP6256_HC_U8)Value; p[1] = (AP6256_HC_U8)(Value >> 8);
}

static int HcSame(const AP6256_HC_U8* A, const AP6256_HC_U8* B)
{
    AP6256_HC_U32 i, difference = 0;
    for (i = 0; i < 6; ++i) difference |= A[i] ^ B[i];
    return difference == 0;
}

static int HcUnicast(const AP6256_HC_U8* Address)
{
    AP6256_HC_U32 i, any = 0;
    for (i = 0; i < 6; ++i) any |= Address[i];
    return any && !(Address[0] & 1);
}

static int HcStateValid(const AP6256_HC_KEY_STATE* State)
{
    if (!State || !HcUnicast(State->Station) || !HcUnicast(State->Bssid) ||
        HcSame(State->Station, State->Bssid) || State->TxPn > AP6256_HC_MAX_PN ||
        State->Pairwise > 1 || State->TxAllowed > 1 || State->RxAllowed > 1 ||
        (!State->TxAllowed && !State->RxAllowed)) return 0;
    if (State->Cipher == AP6256_HC_GCMP256)
        return State->KeyId <= (State->Pairwise ? 1u : 3u) &&
            (State->Pairwise || !State->TxAllowed);
    return State->Cipher == AP6256_HC_BIPGMAC256 && !State->Pairwise &&
        (State->KeyId == 4 || State->KeyId == 5);
}

int Ap6256HostCipherInit(AP6256_HC_KEY_STATE* State,
    AP6256_HC_U32 Cipher, AP6256_HC_U16 KeyId, int Pairwise, int TxAllowed, int RxAllowed,
    const AP6256_HC_U8 Station[6], const AP6256_HC_U8 Bssid[6], AP6256_HC_U64 ReceivePn)
{
    AP6256_HC_U32 i;
    if (!State) return 0;
    HcErase(State, sizeof(*State));
    if (!Station || !Bssid || ReceivePn > AP6256_HC_MAX_PN ||
        (Pairwise != 0 && Pairwise != 1) || (TxAllowed != 0 && TxAllowed != 1) ||
        (RxAllowed != 0 && RxAllowed != 1)) return 0;
    State->Cipher = Cipher; State->KeyId = KeyId;
    State->Pairwise = (AP6256_HC_U8)Pairwise;
    State->TxAllowed = (AP6256_HC_U8)TxAllowed;
    State->RxAllowed = (AP6256_HC_U8)RxAllowed;
    HcCopy(State->Station, Station, 6); HcCopy(State->Bssid, Bssid, 6);
    if (!HcStateValid(State)) { HcErase(State, sizeof(*State)); return 0; }
    for (i = 0; i < AP6256_HC_RX_QUEUES; ++i) State->RxPn[i] = ReceivePn;
    return 1;
}

int Ap6256HostCipherRaiseReceivePn(AP6256_HC_KEY_STATE* State, AP6256_HC_U64 ReceivePn)
{
    AP6256_HC_U32 i;
    if (!HcStateValid(State) || ReceivePn > AP6256_HC_MAX_PN) return 0;
    for (i = 0; i < AP6256_HC_RX_QUEUES; ++i)
        if (State->RxPn[i] > AP6256_HC_MAX_PN) return 0;
    for (i = 0; i < AP6256_HC_RX_QUEUES; ++i)
        if (State->RxPn[i] < ReceivePn) State->RxPn[i] = ReceivePn;
    return 1;
}

static int HcDescribe(const AP6256_HC_KEY_STATE* State, int Tx,
    const AP6256_HC_U8* Frame, AP6256_HC_U32 Length, HC_FRAME* Info)
{
    AP6256_HC_U16 kind, ds;
    if (!HcStateValid(State) || !Frame || Length < 24 || Length > AP6256_HC_MAX_FRAME)
        return 0;
    Info->Fc = HcLe16(Frame); kind = Info->Fc & 0x00ffu;
    Info->Header = 24; Info->Queue = 16; Info->Qos = 0; Info->Management = 0;
    ds = Info->Fc & 0x0300u;
    if (kind == 8 || kind == 0x88) {
        if (ds != (Tx ? 0x0100u : 0x0200u) || State->Cipher != AP6256_HC_GCMP256)
            return 0;
        if (kind == 0x88) {
            Info->Qos = 1; Info->Header += 2;
            if (Info->Fc & 0x8000u) Info->Header += 4;
            if (Length < Info->Header) return 0;
            Info->Queue = Frame[24] & 15u;

            if (Tx && (Frame[24] & 0x80u)) return 0;
        }
    } else if (kind == 0xa0 || kind == 0xc0 || kind == 0xd0) {
        if (ds || (Info->Fc & 0x8000u) || (Info->Fc & 0x0400u) ||
            (HcLe16(Frame + 22) & 15u)) return 0;
        Info->Management = 1; Info->Queue = 17;
        if (State->Cipher == AP6256_HC_GCMP256 && !State->Pairwise) return 0;
    } else return 0;
    if (Tx) {
        if (!State->TxAllowed || !HcSame(Frame + 10, State->Station)) return 0;
        if (Info->Management) {
            if (!HcSame(Frame + 16, State->Bssid)) return 0;
            if (State->Cipher == AP6256_HC_BIPGMAC256) {
                if (!(Frame[4] & 1u)) return 0;
            } else if (!State->Pairwise || !HcSame(Frame + 4, State->Bssid)) return 0;
        } else if (!HcSame(Frame + 4, State->Bssid)) return 0;
    } else {
        if (!State->RxAllowed) return 0;
        if (!HcSame(Frame + 10, State->Bssid)) return 0;
        if (Info->Management && !HcSame(Frame + 16, State->Bssid)) return 0;
        if (State->Pairwise) {
            if (!HcSame(Frame + 4, State->Station)) return 0;
        } else if (!(Frame[4] & 1u)) return 0;
    }
    return Length >= Info->Header;
}

static int HcRobust(const HC_FRAME* Info, const AP6256_HC_U8* Body, AP6256_HC_U32 Length)
{
    AP6256_HC_U8 category;
    if (!Info->Management) return 1;
    if ((Info->Fc & 0x00f0u) != 0xd0u) return Length >= 2;
    if (Length < 2) return 0;
    category = Body[0];

    return category != 4 && category != 7 && category != 11 && category != 15 &&
        category != 20 && category != 21 && category != 22 && category != 127;
}

static AP6256_HC_U32 HcGcmpAad(const HC_FRAME* Info, const AP6256_HC_U8* Frame,
    AP6256_HC_U8 Aad[24])
{
    AP6256_HC_U16 fc = (AP6256_HC_U16)((Info->Fc & ~0x3800u) | 0x4000u);
    if (!Info->Management) fc &= 0xff8fu;
    if (Info->Qos) fc &= 0x7fffu;
    HcPut16(Aad, fc); HcCopy(Aad + 2, Frame + 4, 18);
    Aad[20] = Frame[22] & 15u; Aad[21] = 0;
    if (Info->Qos) { Aad[22] = Frame[24] & 15u; Aad[23] = 0; }
    return Info->Qos ? 24u : 22u;
}

static void HcNonce(const AP6256_HC_U8* Frame, AP6256_HC_U64 Pn, AP6256_HC_U8 Nonce[12])
{
    AP6256_HC_U32 i;
    HcCopy(Nonce, Frame + 10, 6);
    for (i = 0; i < 6; ++i) Nonce[11 - i] = (AP6256_HC_U8)(Pn >> (i * 8));
}

static AP6256_HC_U64 HcReadPn(const AP6256_HC_U8* Bytes)
{
    AP6256_HC_U32 i;
    AP6256_HC_U64 pn = 0;
    for (i = 0; i < 6; ++i) pn |= (AP6256_HC_U64)Bytes[i] << (i * 8);
    return pn;
}

static void HcWritePn(AP6256_HC_U8* Bytes, AP6256_HC_U64 Pn)
{
    AP6256_HC_U32 i;
    for (i = 0; i < 6; ++i) Bytes[i] = (AP6256_HC_U8)(Pn >> (i * 8));
}

static int HcSeparate(const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Output, AP6256_HC_U32 OutputLength)
{

    AP6256_HC_U64 input = (AP6256_HC_U64)Frame, output = (AP6256_HC_U64)Output;
    if (!Output) return 0;
    return output >= input ? output - input >= Length : input - output >= OutputLength;
}

int Ap6256HostCipherEncrypt(AP6256_HC_KEY_STATE* State, AP6256_HC_AEAD Aead,
    void* Context, const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Output, AP6256_HC_U32 Capacity,
    AP6256_HC_U8* Scratch, AP6256_HC_U32 ScratchCapacity, AP6256_HC_U32* Written)
{
    HC_FRAME info;
    AP6256_HC_U8 nonce[12], aad[24], pn[6];
    AP6256_HC_U32 body, needed, aadLength;
    AP6256_HC_U64 next;
    if (Written) *Written = 0;
    if (!Written || !Aead || !HcDescribe(State, 1, Frame, Length, &info) ||
        !HcRobust(&info, Frame + info.Header, Length - info.Header)) return 0;
    body = Length - info.Header;
    needed = Length + (State->Cipher == AP6256_HC_GCMP256 ? 24u : 26u);
    if (needed > AP6256_HC_MAX_FRAME || Capacity < needed ||
        !HcSeparate(Frame, Length, Output, needed) || State->TxPn == AP6256_HC_MAX_PN)
        return 0;
    if (State->Cipher == AP6256_HC_BIPGMAC256 && ((info.Fc & 0x4000u) ||
        ScratchCapacity < needed - 4 || !HcSeparate(Frame, Length, Scratch, needed - 4) ||
        !HcSeparate(Output, needed, Scratch, needed - 4))) return 0;
    next = ++State->TxPn;
    HcNonce(Frame, next, nonce); HcCopy(Output, Frame, info.Header);
    if (State->Cipher == AP6256_HC_GCMP256) {
        AP6256_HC_U8* iv = Output + info.Header;
        HcPut16(Output, (AP6256_HC_U16)(info.Fc | 0x4000u));
        HcWritePn(pn, next);
        iv[0] = pn[0]; iv[1] = pn[1]; iv[2] = 0;
        iv[3] = (AP6256_HC_U8)(0x20u | (State->KeyId << 6));
        HcCopy(iv + 4, pn + 2, 4);
        aadLength = HcGcmpAad(&info, Output, aad);
        if (!Aead(Context, 1, nonce, aad, aadLength, Frame + info.Header, body,
                iv + 8, Output + needed - 16)) goto fail;
    } else {
        AP6256_HC_U8* mmie = Output + Length;
        HcCopy(Output + info.Header, Frame + info.Header, body);
        mmie[0] = 76; mmie[1] = 24; HcPut16(mmie + 2, State->KeyId);
        HcWritePn(mmie + 4, next); HcErase(mmie + 10, 16);
        HcPut16(Scratch, (AP6256_HC_U16)(info.Fc & ~0x3800u));
        HcCopy(Scratch + 2, Frame + 4, 18);
        HcCopy(Scratch + 20, Output + 24, needed - 24);
        if (!Aead(Context, 1, nonce, Scratch, needed - 4, 0, 0, 0, mmie + 10)) {
            HcErase(Scratch, needed - 4); goto fail;
        }
        HcErase(Scratch, needed - 4);
    }
    *Written = needed; return 1;
fail:
    HcErase(Output, needed); return 0;
}

int Ap6256HostCipherDecrypt(AP6256_HC_KEY_STATE* State, AP6256_HC_AEAD Aead,
    void* Context, const AP6256_HC_U8* Frame, AP6256_HC_U32 Length,
    AP6256_HC_U8* Output, AP6256_HC_U32 Capacity,
    AP6256_HC_U8* Scratch, AP6256_HC_U32 ScratchCapacity, AP6256_HC_U32* Written)
{
    HC_FRAME info;
    AP6256_HC_U8 nonce[12], aad[24], pn[6], tag[16];
    AP6256_HC_U32 body, needed, aadLength;
    AP6256_HC_U64 received;
    if (Written) *Written = 0;
    if (!Written || !Aead || !HcDescribe(State, 0, Frame, Length, &info)) return 0;
    if (State->Cipher == AP6256_HC_GCMP256) {
        const AP6256_HC_U8* iv = Frame + info.Header;
        if (!(info.Fc & 0x4000u) || Length < info.Header + 24u ||
            iv[2] || iv[3] != (AP6256_HC_U8)(0x20u | (State->KeyId << 6))) return 0;
        pn[0] = iv[0]; pn[1] = iv[1]; HcCopy(pn + 2, iv + 4, 4);
        received = HcReadPn(pn); needed = Length - 24;
    } else {
        const AP6256_HC_U8* mmie;
        if ((info.Fc & 0x4000u) || Length < 24u + 26u) return 0;
        mmie = Frame + Length - 26;
        if (mmie[0] != 76 || mmie[1] != 24 || HcLe16(mmie + 2) != State->KeyId)
            return 0;
        received = HcReadPn(mmie + 4); needed = Length - 26;
        if (!HcRobust(&info, Frame + 24, needed - 24)) return 0;
        if (ScratchCapacity < Length - 4 || !HcSeparate(Frame, Length, Scratch, Length - 4) ||
            !HcSeparate(Output, needed, Scratch, Length - 4)) return 0;
    }
    if (State->RxPn[info.Queue] > AP6256_HC_MAX_PN ||
        received <= State->RxPn[info.Queue] || Capacity < needed ||
        !HcSeparate(Frame, Length, Output, needed)) return 0;
    body = needed - info.Header;
    HcNonce(Frame, received, nonce); HcCopy(tag, Frame + Length - 16, 16);
    HcCopy(Output, Frame, info.Header);
    if (State->Cipher == AP6256_HC_GCMP256) {
        aadLength = HcGcmpAad(&info, Frame, aad);
        if (!Aead(Context, 0, nonce, aad, aadLength, Frame + info.Header + 8, body,
                Output + info.Header, tag)) goto fail;
        if (!HcRobust(&info, Output + info.Header, body)) goto fail;
        HcPut16(Output, (AP6256_HC_U16)(info.Fc & ~0x4000u));
    } else {
        HcPut16(Scratch, (AP6256_HC_U16)(info.Fc & ~0x3800u));
        HcCopy(Scratch + 2, Frame + 4, 18);
        HcCopy(Scratch + 20, Frame + 24, Length - 24);
        HcErase(Scratch + Length - 20, 16);
        if (!Aead(Context, 0, nonce, Scratch, Length - 4, 0, 0, 0, tag)) {
            HcErase(Scratch, Length - 4); goto fail;
        }
        HcErase(Scratch, Length - 4);
        HcCopy(Output + 24, Frame + 24, body);
    }
    State->RxPn[info.Queue] = received; HcErase(tag, sizeof(tag));
    *Written = needed; return 1;
fail:
    HcErase(Output, needed); HcErase(tag, sizeof(tag)); return 0;
}
