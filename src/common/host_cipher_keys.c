/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_keys.h"
#include "host_cipher_control.h"

static NTSTATUS HcKeySpec(ULONG IfIndex, const AP6256_HC_STORE_SESSION* Session,
    const AP6256_HOST_CIPHER_KEY* Key, AP6256_HC_KEY_SPEC* Spec, BOOLEAN Delete)
{
    AP6256_HC_KEY_STATE shape;
    ULONG i;
    int valid;
    RtlZeroMemory(Spec, sizeof(*Spec));
    if (!Key || Key->KeyId > MAXUSHORT || Key->Pairwise > 1 ||
        Key->PeerPresent > 1 || Key->TxAllowed > 1 || Key->RxAllowed > 1)
        return STATUS_INVALID_PARAMETER;
    if (Key->Pairwise && (!Key->PeerPresent || !RtlEqualMemory(Key->Peer, Session->Bssid, 6)))
        return STATUS_INVALID_PARAMETER;
    if (!Key->Pairwise && Key->PeerPresent && !RtlEqualMemory(Key->Peer, Session->Bssid, 6)) {
        static const UCHAR zeroPeer[6] = {0};

        if (!(Key->Peer[0] & 1) && !RtlEqualMemory(Key->Peer, zeroPeer, 6))
            return STATUS_INVALID_PARAMETER;
    }
    Spec->IfIndex = IfIndex; Spec->Generation = Session->Generation;
    Spec->Cipher = Key->Cipher; Spec->KeyId = (USHORT)Key->KeyId;
    Spec->Pairwise = Key->Pairwise;
    Spec->TxAllowed = Delete ? FALSE : Key->TxAllowed;
    Spec->RxAllowed = Delete ? TRUE : Key->RxAllowed;

    if (Spec->Cipher == AP6256_HC_GCMP256 && !Spec->Pairwise) Spec->TxAllowed = FALSE;
    RtlCopyMemory(Spec->Bssid, Session->Bssid, 6);
    if (!Delete) {
        RtlCopyMemory(Spec->Key, Key->Key, sizeof(Spec->Key));
        for (i = 0; i < 6; ++i) Spec->ReceivePn |= (ULONGLONG)Key->ReceiveSequence[i] << (i * 8u);
    }
    valid = Ap6256HostCipherInit(&shape, Spec->Cipher, Spec->KeyId, Spec->Pairwise,
        Spec->TxAllowed, Spec->RxAllowed, Session->Station, Session->Bssid, Spec->ReceivePn);
    RtlSecureZeroMemory(&shape, sizeof(shape));
    return valid ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

static NTSTATUS HcKeys(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Keys, ULONG Count, BOOLEAN Delete)
{
    AP6256_HC_STORE_SESSION session;
    AP6256_HC_KEY_SPEC spec;
    AP6256_HC_TX_OWNER owner;
    AP6256_HC_ASSOCIATION_PROFILE profile;
    BOOLEAN changed = FALSE, selectDefault;
    ULONG i;
    NTSTATUS status;
    if (!Ctx || !Keys || !Count) return STATUS_INVALID_PARAMETER;
    status = Ap6256HostCipherControlStart(Ctx, IfIndex, &session);
    if (!NT_SUCCESS(status)) return status;
    if (!Ap6256HostCipherStoreProfile(&Ctx->HostCipherStore, IfIndex, session.Generation, TRUE, &profile)) {
        status = STATUS_INVALID_DEVICE_STATE; goto complete;
    }
    for (i = 0; i < Count; ++i) {
        status = HcKeySpec(IfIndex, &session, &Keys[i], &spec, Delete);
        if (NT_SUCCESS(status) && spec.Cipher != (spec.Pairwise ? profile.Pairwise :
            spec.Cipher == AP6256_HC_BIPGMAC256 ? profile.Management : profile.Group))
            status = STATUS_INVALID_PARAMETER;
        RtlSecureZeroMemory(&spec, sizeof(spec));
        if (!NT_SUCCESS(status)) goto complete;
    }
    for (i = 0; i < Count; ++i) {
        status = HcKeySpec(IfIndex, &session, &Keys[i], &spec, Delete);
        if (!NT_SUCCESS(status)) goto wipe;
        status = Delete ? Ap6256HostCipherStoreDelete(&Ctx->HostCipherStore, IfIndex,
            session.Generation, spec.Cipher, spec.KeyId, spec.Pairwise) :
            Ap6256HostCipherStoreInstall(&Ctx->HostCipherStore, &spec);
        if (!NT_SUCCESS(status)) goto wipe;
        changed = TRUE;
        if (Delete && (spec.Pairwise || spec.Cipher == AP6256_HC_BIPGMAC256))
            status = Ap6256HostCipherKeyReady(Ctx, IfIndex, session.Generation, TRUE);
        RtlZeroMemory(&owner, sizeof(owner));
        owner.Generation = session.Generation;
        owner.Slot = spec.Pairwise ? spec.KeyId : 2 + spec.KeyId;
        if (!Delete && !Ap6256HostCipherStoreKeyOwner(&Ctx->HostCipherStore, IfIndex,
            session.Generation, owner.Slot, spec.TxAllowed, &owner)) status = STATUS_DEVICE_NOT_READY;
        selectDefault = !Delete && spec.TxAllowed &&
            (spec.Pairwise || spec.Cipher == AP6256_HC_BIPGMAC256);
        if (NT_SUCCESS(status)) status = Ap6256HostCipherKeyAcknowledge(Ctx, IfIndex, &owner, selectDefault);
        if (NT_SUCCESS(status) && selectDefault)
            status = Ap6256HostCipherStoreSetDefault(&Ctx->HostCipherStore, IfIndex, &owner);
wipe:
        RtlSecureZeroMemory(&spec, sizeof(spec));
        if (!NT_SUCCESS(status)) break;
    }
    if (NT_SUCCESS(status))
        status = Ap6256HostCipherKeyReady(Ctx, IfIndex, session.Generation, FALSE);
complete:
    return Ap6256HostCipherControlFinish(Ctx, IfIndex, session.Generation, status, changed);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherAddKeys(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Keys, ULONG Count)
{
    return HcKeys(Ctx, IfIndex, Keys, Count, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherDeleteKeys(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Keys, ULONG Count)
{
    return HcKeys(Ctx, IfIndex, Keys, Count, TRUE);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherAddKey(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    const AP6256_HOST_CIPHER_KEY* Key)
{
    return Ap6256HostCipherAddKeys(Ctx, IfIndex, Key, 1);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherDeleteKey(PAP6256_DEVICE_CONTEXT Ctx, ULONG IfIndex,
    ULONG Cipher, ULONG KeyId, BOOLEAN Pairwise, const UCHAR* Peer)
{
    AP6256_HOST_CIPHER_KEY key = {0};
    key.Cipher = Cipher; key.KeyId = KeyId; key.Pairwise = Pairwise;
    key.PeerPresent = Peer != NULL;
    if (Peer) RtlCopyMemory(key.Peer, Peer, sizeof(key.Peer));
    return Ap6256HostCipherDeleteKeys(Ctx, IfIndex, &key, 1);
}
