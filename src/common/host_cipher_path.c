/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_path.h"

static BOOLEAN HcPathSeparate(const void* A, ULONG An, const void* B, ULONG Bn)
{
    ULONGLONG a = (ULONGLONG)A, b = (ULONGLONG)B;
    return a + An >= a && b + Bn >= b && (a + An <= b || b + Bn <= a);
}

static BOOLEAN HcPathSession(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_WIRE_SESSION* Session)
{
    AP6256_HC_STORE_SESSION stored;
    RtlZeroMemory(Session, sizeof(*Session));
    if (!Ap6256HostCipherStoreSnapshot(Store, IfIndex, &stored)) return FALSE;
    Session->Generation = stored.Generation; Session->IfIndex = (UCHAR)IfIndex;
    RtlCopyMemory(Session->Station, stored.Station, 6);
    RtlCopyMemory(Session->Bssid, stored.Bssid, 6); return TRUE;
}

static BOOLEAN HcPathSameDefault(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner)
{
    AP6256_HC_TX_OWNER current;
    return Ap6256HostCipherStoreDefault(Store, IfIndex, Owner->Generation,
        Owner->Slot >= 6, &current) && current.Epoch == Owner->Epoch && current.Slot == Owner->Slot;
}

static ULONG HcPathDataHeader(const UCHAR* Frame, ULONG Length, BOOLEAN Transmit,
    BOOLEAN Aggregate, BOOLEAN Fragments)
{
    ULONG header, fc;
    if (!Frame || Length < 24 || Length > AP6256_HC_MAX_FRAME) return 0;
    fc = Frame[0] | ((ULONG)Frame[1] << 8);
    if ((fc & 0xfcu) != 8 && (fc & 0xfcu) != 0x88u) return 0;
    if ((fc & 0x0303u) != (Transmit ? 0x0100u : 0x0200u) ||
        (!Fragments && ((fc & 0x0400u) || (Frame[22] & 15u)))) return 0;
    if ((fc & 0xfcu) == 8) { if (fc & 0x8000u) return 0; header = 24; }
    else {
        if (Length < 26 || ((Frame[24] & 0x80u) && (Transmit || !Aggregate))) return 0;
        header = (fc & 0x8000u) ? 30u : 26u;
    }
    return Length >= header ? header : 0;
}

static BOOLEAN HcPathEapolBody(const UCHAR* Body, ULONG Length)
{
    return Length >= 8 && RtlEqualMemory(Body, "\xaa\xaa\x03\x00\x00\x00\x88\x8e", 8);
}

static BOOLEAN HcPathEapol(const UCHAR* Frame, ULONG Length, ULONG Header)
{
    return Header && Length >= Header && HcPathEapolBody(Frame + Header, Length - Header);
}

static BOOLEAN HcPathUnicast(const UCHAR* Address)
{
    ULONG i, any = 0;
    for (i = 0; i < 6; ++i) any |= Address[i];
    return any && !(Address[0] & 1u);
}

static BOOLEAN HcPathAmsduSubframe(const AP6256_HC_WIRE_SESSION* Session,
    const UCHAR* Frame, ULONG Length, ULONG Offset, ULONG* Payload, ULONG* Next)
{
    const UCHAR* sub;
    ULONG bytes, end, padding;
    if (Offset > Length || Length - Offset < 15u) return FALSE;
    sub = Frame + Offset; bytes = ((ULONG)sub[12] << 8) | sub[13];
    if (!bytes || bytes > Length - Offset - 14u || !HcPathUnicast(sub + 6) ||
        (!(sub[0] & 1u) && !RtlEqualMemory(sub, Session->Station, 6))) return FALSE;
    end = Offset + 14u + bytes;
    if (end == Length) *Next = end;
    else {
        padding = (4u - ((14u + bytes) & 3u)) & 3u;

        if (Length - end < padding + 15u) return FALSE;
        *Next = end + padding;
    }
    *Payload = bytes; return TRUE;
}

static BOOLEAN HcPathAmsduLayout(const AP6256_HC_WIRE_SESSION* Session,
    const UCHAR* Frame, ULONG Length, ULONG Header, BOOLEAN* HasData)
{
    ULONG offset = Header, bytes, next;
    *HasData = FALSE;
    if (Header < 26 || Length <= Header || (Frame[0] & 0xfcu) != 0x88u ||
        !(Frame[24] & 0x80u) || (Frame[1] & 0x40u) ||
        Length - Header < 15u) return FALSE;

    if (RtlEqualMemory(Frame + Header, "\xaa\xaa\x03\x00\x00\x00", 6)) return FALSE;
    while (offset < Length) {
        if (!HcPathAmsduSubframe(Session, Frame, Length, offset, &bytes, &next)) return FALSE;
        if (!HcPathEapolBody(Frame + offset + 14u, bytes)) *HasData = TRUE;
        offset = next;
    }
    return offset == Length;
}

static BOOLEAN HcPathMapped(AP6256_HC_STORE* Store, ULONG IfIndex, ULONG Generation)
{
    AP6256_HC_TX_OWNER owner;
    return Ap6256HostCipherStoreKeyOwner(Store, IfIndex, Generation, 0, TRUE, &owner) ||
        Ap6256HostCipherStoreKeyOwner(Store, IfIndex, Generation, 0, FALSE, &owner) ||
        Ap6256HostCipherStoreKeyOwner(Store, IfIndex, Generation, 1, TRUE, &owner) ||
        Ap6256HostCipherStoreKeyOwner(Store, IfIndex, Generation, 1, FALSE, &owner);
}

NTSTATUS Ap6256HostCipherDataTx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Frame, ULONG Length, UCHAR Exemption, UCHAR* Wire, ULONG Capacity,
    ULONG* Written, UCHAR* Priority)
{
    AP6256_HC_WIRE_SESSION session, current;
    AP6256_HC_TX_OWNER selected, owner;
    ULONG header, encrypted = 0, kind;
    BOOLEAN eapol, clear;
    NTSTATUS status;
    if (Written) *Written = 0;
    if (!Written || !Priority || !Wire || !Frame || Exemption > 2 ||
        !HcPathSeparate(Frame, Length, Wire, Capacity)) return STATUS_INVALID_PARAMETER;
    if (!HcPathSession(Store, IfIndex, &session)) return STATUS_DEVICE_NOT_READY;
    header = HcPathDataHeader(Frame, Length, TRUE, FALSE, FALSE);
    if (!header || !RtlEqualMemory(Frame + 4, session.Bssid, 6) ||
        !RtlEqualMemory(Frame + 10, session.Station, 6)) return STATUS_DATA_ERROR;
    eapol = HcPathEapol(Frame, Length, header);
    clear = Exemption == 1 || (Exemption == 2 && !HcPathMapped(Store, IfIndex, session.Generation));
    if (clear) {

        if (!eapol || (Frame[1] & 0x40u)) return STATUS_DATA_ERROR;
        if (Capacity < AP6256_HC_WIRE_TX_HEADER + Length) return STATUS_BUFFER_TOO_SMALL;
        RtlCopyMemory(Wire + AP6256_HC_WIRE_TX_HEADER, Frame, Length);
        encrypted = Length; RtlZeroMemory(&owner, sizeof(owner));
        kind = Exemption == 2 ? AP6256_HC_DATA_TX_NO_KEY : AP6256_HC_DATA_TX;
    } else {
        if (!eapol && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation)) return STATUS_INVALID_DEVICE_STATE;
        if (!Ap6256HostCipherStoreDefault(Store, IfIndex, session.Generation, FALSE, &selected)) return STATUS_DEVICE_NOT_READY;
        if (Capacity < AP6256_HC_WIRE_TX_HEADER + Length + 24u) return STATUS_BUFFER_TOO_SMALL;
        status = Ap6256HostCipherStoreFrame(Store, IfIndex, session.Generation, AP6256_HC_GCMP256,
            (USHORT)selected.Slot, TRUE, TRUE, Frame, Length, Wire + AP6256_HC_WIRE_TX_HEADER,
            Capacity - AP6256_HC_WIRE_TX_HEADER, NULL, 0, &encrypted, &owner);
        if (!NT_SUCCESS(status)) return status;
        kind = eapol ? AP6256_HC_DATA_TX_HANDSHAKE : AP6256_HC_DATA_TX;
        if (owner.Epoch != selected.Epoch || !HcPathSameDefault(Store, IfIndex, &owner) ||
            !Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, &owner, TRUE) ||
            (!eapol && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation))) goto retired;
    }
    if (!HcPathSession(Store, IfIndex, &current) || !RtlEqualMemory(&current, &session, sizeof(session)) ||
        !Ap6256HostCipherWireWrite(&session, kind, 0, owner.Epoch, Wire + AP6256_HC_WIRE_TX_HEADER,
            encrypted, Wire, Capacity)) goto retired;
    *Priority = header > 24 ? Frame[24] & 7u : 0;
    *Written = AP6256_HC_WIRE_TX_HEADER + encrypted; return STATUS_SUCCESS;
retired:
    RtlSecureZeroMemory(Wire, AP6256_HC_WIRE_TX_HEADER + encrypted); return STATUS_DEVICE_NOT_READY;
}

static BOOLEAN HcPathDataRxRead(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* PlainWire, ULONG Length, AP6256_HC_WIRE_VIEW* View, BOOLEAN CheckPrivacy)
{
    AP6256_HC_WIRE_SESSION session;
    AP6256_HC_TX_OWNER owner;
    ULONG header, type;
    if (!View) return FALSE;
    RtlZeroMemory(View, sizeof(*View));
    if (!PlainWire || Length < AP6256_HC_WIRE_HEADER) return FALSE;
    type = PlainWire[19];
    if ((type != AP6256_HC_DATA_RX_VERIFIED && type != AP6256_HC_DATA_RX_MSDU_VERIFIED) ||
        !HcPathSession(Store, IfIndex, &session) ||
        !Ap6256HostCipherWireRead(&session, type, PlainWire, Length, View)) return FALSE;
    header = HcPathDataHeader(View->Frame, View->Length, FALSE, FALSE, FALSE);
    if (header && (!View->Epoch || (Ap6256HostCipherStoreEpochOwner(Store, IfIndex, session.Generation,
        View->Epoch, FALSE, &owner) && owner.Slot < 6 &&
        ((type == AP6256_HC_DATA_RX_MSDU_VERIFIED ? View->Token == 2 : !!(View->Frame[4] & 1u)) ?
            owner.Slot >= 2 : owner.Slot < 2))) &&
        (HcPathEapol(View->Frame, View->Length, header) || Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation)) &&
        (!CheckPrivacy || Ap6256HostCipherStoreRxAllowed(Store, IfIndex, session.Generation,
            (View->Frame[4] & 1u) != 0, View->Epoch != 0,
            View->Frame + header, View->Length - header))) return TRUE;
    RtlZeroMemory(View, sizeof(*View)); return FALSE;
}

BOOLEAN Ap6256HostCipherDataRxRead(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* PlainWire, ULONG Length, AP6256_HC_WIRE_VIEW* View)
{
    return HcPathDataRxRead(Store, IfIndex, PlainWire, Length, View, TRUE);
}

NTSTATUS Ap6256HostCipherDataRx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length, UCHAR* PlainWire, ULONG Capacity, ULONG* Written)
{
    AP6256_HC_WIRE_SESSION session, current;
    AP6256_HC_WIRE_VIEW view;
    AP6256_HC_TX_OWNER owner;
    ULONG plain = 0, header;
    ULONGLONG pn = 0;
    BOOLEAN group, aggregate, hasData;
    NTSTATUS status;
    if (Written) *Written = 0;
    if (!Written || !Wire || !PlainWire || Capacity < AP6256_HC_WIRE_HEADER ||
        !HcPathSeparate(Wire, Length, PlainWire, Capacity)) return STATUS_INVALID_PARAMETER;
    if (!HcPathSession(Store, IfIndex, &session)) return STATUS_DEVICE_NOT_READY;
    if (!Ap6256HostCipherWireRead(&session, AP6256_HC_DATA_RX, Wire, Length, &view) ||
        !(header = HcPathDataHeader(view.Frame, view.Length, FALSE, TRUE, TRUE))) return STATUS_DATA_ERROR;
    aggregate = header >= 26 && (view.Frame[24] & 0x80u) != 0;
    RtlZeroMemory(&owner, sizeof(owner)); group = (view.Frame[4] & 1u) != 0;
    if (view.FrameControl & 0x4000u) {
        const UCHAR* iv = view.Frame + header;
        pn = (ULONGLONG)iv[0] | ((ULONGLONG)iv[1] << 8) |
            ((ULONGLONG)iv[4] << 16) | ((ULONGLONG)iv[5] << 24) |
            ((ULONGLONG)iv[6] << 32) | ((ULONGLONG)iv[7] << 40);
        status = Ap6256HostCipherStoreFrame(Store, IfIndex, session.Generation, AP6256_HC_GCMP256,
            view.KeyId, !group, FALSE, view.Frame, view.Length, PlainWire + AP6256_HC_WIRE_HEADER,
            Capacity - AP6256_HC_WIRE_HEADER, NULL, 0, &plain, &owner);
        if (!NT_SUCCESS(status)) return status;
        if (!Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, &owner, FALSE)) goto retired;
    } else {
        owner.Generation = session.Generation;
        if (Capacity - AP6256_HC_WIRE_HEADER < view.Length) return STATUS_BUFFER_TOO_SMALL;
        plain = view.Length; RtlCopyMemory(PlainWire + AP6256_HC_WIRE_HEADER, view.Frame, plain);
    }
    if (view.Fragmented) {
        ULONG bytes = plain;
        status = Ap6256HostCipherStoreFragment(Store, IfIndex, &owner, pn,
            PlainWire + AP6256_HC_WIRE_HEADER, Capacity - AP6256_HC_WIRE_HEADER, &plain);
        if (status != STATUS_SUCCESS) {
            RtlSecureZeroMemory(PlainWire, AP6256_HC_WIRE_HEADER + bytes); return status;
        }
        if (owner.Epoch && !Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, &owner, FALSE)) goto retired;
    }
    hasData = !HcPathEapol(PlainWire + AP6256_HC_WIRE_HEADER, plain, header);
    if (aggregate && !HcPathAmsduLayout(&session, PlainWire + AP6256_HC_WIRE_HEADER, plain, header, &hasData)) {
        RtlSecureZeroMemory(PlainWire, AP6256_HC_WIRE_HEADER + plain); return STATUS_DATA_ERROR;
    }
    if (!aggregate && !Ap6256HostCipherStoreRxAllowed(Store, IfIndex, session.Generation,
        group, owner.Epoch != 0, PlainWire + AP6256_HC_WIRE_HEADER + header, plain - header)) goto retired;
    if (!HcPathSession(Store, IfIndex, &current) || !RtlEqualMemory(&current, &session, sizeof(session)) ||
        (hasData &&
            !Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation)) ||
        !Ap6256HostCipherWireWrite(&session, AP6256_HC_DATA_RX_VERIFIED, 0, owner.Epoch,
            PlainWire + AP6256_HC_WIRE_HEADER, plain, PlainWire, Capacity)) goto retired;
    *Written = AP6256_HC_WIRE_HEADER + plain; return STATUS_SUCCESS;
retired:
    RtlSecureZeroMemory(PlainWire, AP6256_HC_WIRE_HEADER + plain); return STATUS_DEVICE_NOT_READY;
}

BOOLEAN Ap6256HostCipherDataRxAmsduBegin(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* PlainWire, ULONG Length, AP6256_HC_AMSDU_CURSOR* Cursor)
{
    AP6256_HC_WIRE_SESSION session;
    AP6256_HC_WIRE_VIEW view;
    AP6256_HC_TX_OWNER owner;
    ULONG header;
    BOOLEAN group, hasData;
    if (!Cursor || !HcPathSeparate(PlainWire, Length, Cursor, sizeof(*Cursor))) return FALSE;
    RtlZeroMemory(Cursor, sizeof(*Cursor));
    if (!HcPathSession(Store, IfIndex, &session) ||
        !Ap6256HostCipherWireRead(&session, AP6256_HC_DATA_RX_VERIFIED, PlainWire, Length, &view) ||
        !view.Epoch || !(header = HcPathDataHeader(view.Frame, view.Length, FALSE, TRUE, FALSE)) ||
        !HcPathAmsduLayout(&session, view.Frame, view.Length, header, &hasData)) return FALSE;
    group = (view.Frame[4] & 1u) != 0;
    if (!Ap6256HostCipherStoreEpochOwner(Store, IfIndex, session.Generation, view.Epoch, FALSE, &owner) ||
        owner.Slot >= 6 || (group ? owner.Slot < 2 : owner.Slot >= 2) ||
        (hasData && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation))) return FALSE;
    Cursor->Frame = view.Frame; Cursor->Session = session;
    Cursor->Header = header; Cursor->Length = view.Length; Cursor->Offset = header;
    Cursor->Epoch = view.Epoch; Cursor->Group = group; Cursor->HasData = hasData; return TRUE;
}

BOOLEAN Ap6256HostCipherDataRxAmsduNext(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_AMSDU_CURSOR* Cursor, UCHAR* PlainWire, ULONG Capacity, ULONG* Written)
{
    AP6256_HC_WIRE_SESSION current;
    AP6256_HC_TX_OWNER owner;
    AP6256_HC_WIRE_VIEW verified;
    const UCHAR* sub;
    UCHAR* frame;
    ULONG bytes, next, needed;
    if (Written) *Written = 0;
    if (!Written || !Cursor || !PlainWire || Cursor->Session.IfIndex != IfIndex || !Cursor->Frame ||
        (Cursor->Header != 26 && Cursor->Header != 30) || Cursor->Length > AP6256_HC_MAX_FRAME ||
        Cursor->Offset < Cursor->Header || !Cursor->Epoch ||
        !HcPathSeparate(Cursor->Frame, Cursor->Length, PlainWire, Capacity) ||
        !HcPathSeparate(Cursor, sizeof(*Cursor), PlainWire, Capacity) ||
        !HcPathSession(Store, IfIndex, &current) || !RtlEqualMemory(&current, &Cursor->Session, sizeof(current)) ||
        !Ap6256HostCipherStoreEpochOwner(Store, IfIndex, current.Generation, Cursor->Epoch, FALSE, &owner) ||
        owner.Slot >= 6 || (Cursor->Group ? owner.Slot < 2 : owner.Slot >= 2) ||
        (Cursor->HasData && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, current.Generation)) ||
        !HcPathAmsduSubframe(&current, Cursor->Frame, Cursor->Length, Cursor->Offset, &bytes, &next)) return FALSE;
    needed = AP6256_HC_WIRE_HEADER + Cursor->Header + bytes;
    if (Capacity < needed) return FALSE;
    sub = Cursor->Frame + Cursor->Offset; frame = PlainWire + AP6256_HC_WIRE_HEADER;
    RtlCopyMemory(frame, Cursor->Frame, Cursor->Header);
    RtlCopyMemory(frame + 4, sub, 6); RtlCopyMemory(frame + 16, sub + 6, 6);
    frame[24] &= 0x7fu;
    RtlCopyMemory(frame + Cursor->Header, sub + 14, bytes);
    if (!Ap6256HostCipherWireWrite(&current, AP6256_HC_DATA_RX_MSDU_VERIFIED,
        Cursor->Group ? 2u : 1u, Cursor->Epoch, frame, Cursor->Header + bytes, PlainWire, Capacity) ||

        !HcPathDataRxRead(Store, IfIndex, PlainWire, needed, &verified, FALSE) ||
        (Cursor->HasData && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, current.Generation))) {
        RtlSecureZeroMemory(PlainWire, needed); return FALSE;
    }
    Cursor->Offset = next; *Written = needed; return TRUE;
}

NTSTATUS Ap6256HostCipherManagementReply(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Request, ULONG Length, UCHAR* Reply, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written)
{
    AP6256_HC_WIRE_SESSION session, current;
    AP6256_HC_WIRE_VIEW view;
    AP6256_HC_TX_OWNER selected, owner;
    ULONG type, response, header, slot = AP6256_HC_SLOTS, cipher, id, plainLength = 0;
    BOOLEAN encrypt, group;
    NTSTATUS status = STATUS_DATA_ERROR;
    if (Written) *Written = 0;
    if (!Written || !Request || !Reply || Length < AP6256_HC_WIRE_HEADER ||
        Capacity < AP6256_HC_WIRE_HEADER ||
        !HcPathSeparate(Request, Length, Reply, Capacity) ||
        (ScratchCapacity && (!Scratch || !HcPathSeparate(Request, Length, Scratch, ScratchCapacity) ||
            !HcPathSeparate(Reply, Capacity, Scratch, ScratchCapacity)))) return STATUS_INVALID_PARAMETER;
    if (!HcPathSession(Store, IfIndex, &session)) return STATUS_DEVICE_NOT_READY;
    type = Request[19];
    if ((type != AP6256_HC_MGMT_RX && type != AP6256_HC_MGMT_TX_REQUEST) ||
        !Ap6256HostCipherWireRead(&session, type, Request, Length, &view) ||
        view.Length > AP6256_HC_MAX_MANAGEMENT) return STATUS_DATA_ERROR;
    encrypt = type == AP6256_HC_MGMT_TX_REQUEST; group = (view.Frame[4] & 1u) != 0;
    response = encrypt ? AP6256_HC_MGMT_TX_REPLY : AP6256_HC_MGMT_RX_VERIFIED;
    header = encrypt ? AP6256_HC_WIRE_TX_HEADER : AP6256_HC_WIRE_HEADER;
    RtlZeroMemory(&selected, sizeof(selected));
    if (encrypt) {
        if (Ap6256HostCipherStoreDefault(Store, IfIndex, session.Generation, group, &selected)) slot = selected.Slot;
    } else if (view.FrameControl & 0x4000u) slot = view.KeyId;
    else if (group && view.KeyId >= 4 && view.KeyId <= 5) slot = view.KeyId + 2u;

    if (slot < 2 || slot == 6 || slot == 7) {
        cipher = slot < 2 ? AP6256_HC_GCMP256 : AP6256_HC_BIPGMAC256;
        id = slot < 2 ? slot : slot - 2u;
        if (Capacity > header) status = Ap6256HostCipherStoreFrame(Store, IfIndex,
            session.Generation, cipher, (USHORT)id, slot < 2, encrypt,
            view.Frame, view.Length, Reply + header, Capacity - header, Scratch,
            ScratchCapacity, &plainLength, &owner);
        if (NT_SUCCESS(status) && plainLength <= AP6256_HC_MAX_MANAGEMENT &&
            Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, &owner, encrypt) &&
            (!encrypt || (owner.Epoch == selected.Epoch && HcPathSameDefault(Store, IfIndex, &owner))) &&
            Ap6256HostCipherWireWrite(&session, response, view.Token, owner.Epoch,
                Reply + header, plainLength, Reply, Capacity)) {
            *Written = header + plainLength; return STATUS_SUCCESS;
        }
        if (plainLength) RtlSecureZeroMemory(Reply + header, plainLength);
    }

    if (!HcPathSession(Store, IfIndex, &current) || !RtlEqualMemory(&session, &current, sizeof(session)))
        return STATUS_DEVICE_NOT_READY;
    if (!Ap6256HostCipherWireWrite(&session, AP6256_HC_MGMT_DROP, view.Token, 0,
        NULL, 0, Reply, Capacity)) return STATUS_DATA_ERROR;
    *Written = AP6256_HC_WIRE_HEADER; return STATUS_SUCCESS;
}

NTSTATUS Ap6256HostCipherManagementTx(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Frame, ULONG Length, UCHAR* Wire, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written)
{
    AP6256_HC_WIRE_SESSION session, current;
    AP6256_HC_TX_OWNER selected, owner;
    UCHAR probe[AP6256_HC_WIRE_HEADER];
    ULONG encrypted = 0, overhead, cipher, id;
    BOOLEAN group;
    NTSTATUS status;
    if (Written) *Written = 0;
    if (!Written || !Frame || !Wire || Length < 26 ||
        !HcPathSeparate(Frame, Length, Wire, Capacity) ||
        (ScratchCapacity && (!Scratch || !HcPathSeparate(Frame, Length, Scratch, ScratchCapacity) ||
            !HcPathSeparate(Wire, Capacity, Scratch, ScratchCapacity)))) return STATUS_INVALID_PARAMETER;
    if (!HcPathSession(Store, IfIndex, &session)) return STATUS_DEVICE_NOT_READY;

    if (!Ap6256HostCipherWireWrite(&session, AP6256_HC_MGMT_TX_REQUEST, 1, 0,
        Frame, Length, probe, sizeof(probe))) return STATUS_DATA_ERROR;
    group = (Frame[4] & 1u) != 0; overhead = group ? 26u : 24u;
    if (Length > AP6256_HC_MAX_MANAGEMENT - overhead) return STATUS_DATA_ERROR;
    if (Capacity < AP6256_HC_WIRE_TX_HEADER + Length + overhead) return STATUS_BUFFER_TOO_SMALL;
    if (group && ScratchCapacity < Length + overhead - 4u) return STATUS_BUFFER_TOO_SMALL;
    if (!Ap6256HostCipherStoreDefault(Store, IfIndex, session.Generation, group, &selected))
        return STATUS_DEVICE_NOT_READY;
    cipher = group ? AP6256_HC_BIPGMAC256 : AP6256_HC_GCMP256;
    id = group ? selected.Slot - 2u : selected.Slot;
    status = Ap6256HostCipherStoreFrame(Store, IfIndex, session.Generation, cipher,
        (USHORT)id, !group, TRUE, Frame, Length, Wire + AP6256_HC_WIRE_TX_HEADER,
        Capacity - AP6256_HC_WIRE_TX_HEADER, Scratch, ScratchCapacity, &encrypted, &owner);
    if (!NT_SUCCESS(status)) {
        RtlSecureZeroMemory(Wire, AP6256_HC_WIRE_TX_HEADER + Length + overhead);
        return status;
    }
    if (encrypted > AP6256_HC_MAX_MANAGEMENT || owner.Epoch != selected.Epoch ||
        !HcPathSameDefault(Store, IfIndex, &owner) ||
        !Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, &owner, TRUE) ||
        !HcPathSession(Store, IfIndex, &current) || !RtlEqualMemory(&session, &current, sizeof(session)) ||
        !Ap6256HostCipherWireWrite(&session, AP6256_HC_MGMT_TX_DIRECT, 0, owner.Epoch,
            Wire + AP6256_HC_WIRE_TX_HEADER, encrypted, Wire, Capacity)) {
        RtlSecureZeroMemory(Wire, AP6256_HC_WIRE_TX_HEADER + encrypted);
        return STATUS_DEVICE_NOT_READY;
    }
    *Written = AP6256_HC_WIRE_TX_HEADER + encrypted;
    return STATUS_SUCCESS;
}

BOOLEAN Ap6256HostCipherPathTxCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length)
{
    AP6256_HC_WIRE_SESSION session;
    AP6256_HC_WIRE_VIEW view;
    AP6256_HC_TX_OWNER owner;
    ULONG type, slot;
    if (!Wire || Length < AP6256_HC_WIRE_HEADER || !HcPathSession(Store, IfIndex, &session)) return FALSE;
    type = Wire[19];
    if ((type != AP6256_HC_DATA_TX && type != AP6256_HC_DATA_TX_HANDSHAKE &&
        type != AP6256_HC_DATA_TX_NO_KEY && type != AP6256_HC_MGMT_RX_VERIFIED &&
        type != AP6256_HC_MGMT_TX_REPLY && type != AP6256_HC_MGMT_DROP &&
        type != AP6256_HC_MGMT_TX_DIRECT) ||
        !Ap6256HostCipherWireRead(&session, type, Wire, Length, &view)) return FALSE;
    if (type == AP6256_HC_MGMT_DROP) return TRUE;
    if (type != AP6256_HC_DATA_TX && type != AP6256_HC_DATA_TX_HANDSHAKE &&
        type != AP6256_HC_DATA_TX_NO_KEY && view.Length > AP6256_HC_MAX_MANAGEMENT) return FALSE;
    if (type == AP6256_HC_MGMT_RX_VERIFIED) {
        if (!Ap6256HostCipherStoreEpochOwner(Store, IfIndex, session.Generation, view.Epoch, FALSE, &owner)) return FALSE;
        return (view.Frame[4] & 1u) ? owner.Slot >= 6 : owner.Slot < 2;
    }

    if (type == AP6256_HC_DATA_TX && !view.Epoch) return TRUE;
    if (type == AP6256_HC_DATA_TX_NO_KEY) return !HcPathMapped(Store, IfIndex, session.Generation);
    if (type == AP6256_HC_DATA_TX && !Ap6256HostCipherStoreAuthorized(Store, IfIndex, session.Generation)) return FALSE;
    slot = (view.FrameControl & 0x4000u) ? view.KeyId : view.KeyId + 2u;
    return Ap6256HostCipherStoreKeyOwner(Store, IfIndex, session.Generation, slot, TRUE, &owner) &&
        owner.Epoch == view.Epoch &&
        ((type != AP6256_HC_DATA_TX && type != AP6256_HC_DATA_TX_HANDSHAKE &&
            type != AP6256_HC_MGMT_TX_DIRECT) || HcPathSameDefault(Store, IfIndex, &owner));
}

BOOLEAN Ap6256HostCipherPathDestination(AP6256_HC_STORE* Store, ULONG IfIndex,
    const UCHAR* Wire, ULONG Length, UCHAR Destination[6])
{
    AP6256_HC_WIRE_SESSION session;
    if (!Destination) return FALSE;
    RtlZeroMemory(Destination, 6);
    if (!Ap6256HostCipherPathTxCurrent(Store, IfIndex, Wire, Length) || !HcPathSession(Store, IfIndex, &session)) return FALSE;

    RtlCopyMemory(Destination, session.Bssid, 6); return TRUE;
}
