/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_store.h"
#include "host_crypto_cng.h"

#define HC_STORE_TAG 'cHPA'
#define HC_FRAGMENT_TAG 'fHPA'

typedef struct _HC_RX_FRAGMENT {
    ULONGLONG Started, LastPn;
    ULONG Generation, Epoch, Slot, Header, Length, Fragment, Sequence, Tid;
    UCHAR Frame[AP6256_HC_MAX_FRAME];
} HC_RX_FRAGMENT;
struct _AP6256_HC_RX_FRAGMENTS {
    HC_RX_FRAGMENT Entries[AP6256_HC_RX_FRAGMENT_CACHE];
};

static VOID HcClearFragmentsLocked(AP6256_HC_STORE* Store, ULONG IfIndex)
{
    if (Store->RxFragments[IfIndex])
        RtlSecureZeroMemory(Store->RxFragments[IfIndex], sizeof(AP6256_HC_RX_FRAGMENTS));
}

struct _AP6256_HC_COUNTERS {
    AP6256_HC_COUNTERS* Next;
    KSPIN_LOCK Lock;
    UCHAR Digest[32];
    ULONGLONG RxPn[AP6256_HC_RX_QUEUES];
};

struct _AP6256_HC_STORED_KEY {
    EX_RUNDOWN_REF Rundown;
    KSPIN_LOCK Lock;
    ULONG Epoch, ObjectBytes;
    void* Handle;
    AP6256_HC_KEY_STATE State;
    AP6256_HC_COUNTERS* Counters;
    UCHAR Material[32];

};

static BOOLEAN HcStoreEnter(AP6256_HC_STORE* Store)
{
    return KeGetCurrentIrql() <= DISPATCH_LEVEL && Store &&
        InterlockedCompareExchange(&Store->Ready, 0, 0) &&
        ExAcquireRundownProtection(&Store->Rundown);
}

static ULONG HcSlot(ULONG Cipher, USHORT Id, BOOLEAN Pairwise)
{
    if (Cipher == AP6256_HC_GCMP256) {
        if (Pairwise && Id <= 1) return Id;
        if (!Pairwise && Id <= 3) return 2u + Id;
    } else if (Cipher == AP6256_HC_BIPGMAC256 && !Pairwise && (Id == 4 || Id == 5))
        return 6u + Id - 4u;
    return AP6256_HC_SLOTS;
}

static VOID HcDestroy(AP6256_HC_STORED_KEY* Key)
{
    if (!Key) return;
    ExWaitForRundownProtectionRelease(&Key->Rundown);
    if (Key->Handle)
        (VOID)Ap6256HostCryptoDestroyKey(Key->Handle, (UCHAR*)(Key + 1), Key->ObjectBytes);
    RtlSecureZeroMemory(Key, sizeof(*Key) + Key->ObjectBytes);
    ExFreePoolWithTag(Key, HC_STORE_TAG);
}

static BOOLEAN HcMaterialEqual(const UCHAR A[32], const UCHAR B[32])
{
    ULONG i, difference = 0;
    for (i = 0; i < 32; ++i) difference |= A[i] ^ B[i];
    return difference == 0;
}

static VOID HcDestroyCounters(AP6256_HC_COUNTERS* Counters)
{
    while (Counters) {
        AP6256_HC_COUNTERS* next = Counters->Next;
        RtlSecureZeroMemory(Counters, sizeof(*Counters));
        ExFreePoolWithTag(Counters, HC_STORE_TAG);
        Counters = next;
    }
}

static VOID HcRaiseCounters(AP6256_HC_COUNTERS* Counters, ULONGLONG Pn)
{
    ULONG i;
    for (i = 0; i < AP6256_HC_RX_QUEUES; ++i)
        if (Counters->RxPn[i] < Pn) Counters->RxPn[i] = Pn;
}

static ULONGLONG HcReservePn(AP6256_HC_STORE* Store)
{
    ULONGLONG pn = 0;
    KeAcquireSpinLockAtDpcLevel(&Store->PnLock);
    if (Store->NextTransmitPn < AP6256_HC_MAX_PN) pn = ++Store->NextTransmitPn;
    KeReleaseSpinLockFromDpcLevel(&Store->PnLock);
    return pn;
}

static ULONG HcDetachPortLocked(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_STORED_KEY* Keys[AP6256_HC_SLOTS], AP6256_HC_COUNTERS** Counters)
{
    ULONG i, revision, generation;
    HcClearFragmentsLocked(Store, IfIndex);
    for (i = 0; i < AP6256_HC_SLOTS; ++i) Keys[i] = Store->Ports[IfIndex].Keys[i];
    *Counters = Store->Ports[IfIndex].Counters;
    Store->CounterCount -= Store->Ports[IfIndex].CounterCount;
    revision = Store->Ports[IfIndex].Revision;
    if (revision != MAXULONG) ++revision;
    generation = Store->Ports[IfIndex].LastGeneration;
    RtlZeroMemory(&Store->Ports[IfIndex], sizeof(Store->Ports[IfIndex]));
    Store->Ports[IfIndex].Revision = revision;
    Store->Ports[IfIndex].LastGeneration = generation;
    return revision;
}

static ULONG HcDetachPort(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_STORED_KEY* Keys[AP6256_HC_SLOTS], AP6256_HC_COUNTERS** Counters)
{
    KIRQL irql;
    ULONG revision;
    KeAcquireSpinLock(&Store->Lock, &irql);
    revision = HcDetachPortLocked(Store, IfIndex, Keys, Counters);
    KeReleaseSpinLock(&Store->Lock, irql);
    return revision;
}

NTSTATUS Ap6256HostCipherStoreInit(AP6256_HC_STORE* Store)
{
    AP6256_HC_U32 bytes = 0;
    NTSTATUS status;
    if (!Store || KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Store, sizeof(*Store));
    KeInitializeSpinLock(&Store->Lock); KeInitializeSpinLock(&Store->PnLock);
    KeInitializeMutex(&Store->Mutation, 0);
    ExInitializeRundownProtection(&Store->Rundown);
    status = Ap6256HostCryptoOpen(&Store->Provider, &bytes);
    if (!NT_SUCCESS(status)) return status;
    Store->ObjectBytes = bytes;
    InterlockedExchange(&Store->Ready, 1);
    return STATUS_SUCCESS;
}

VOID Ap6256HostCipherStoreClose(AP6256_HC_STORE* Store)
{
    ULONG i, slot;
    if (!Store || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        !InterlockedExchange(&Store->Ready, 0)) return;
    ExWaitForRundownProtectionRelease(&Store->Rundown);

    for (i = 0; i < AP6256_HC_INTERFACES; ++i) {
        for (slot = 0; slot < AP6256_HC_SLOTS; ++slot)
            HcDestroy(Store->Ports[i].Keys[slot]);
        HcDestroyCounters(Store->Ports[i].Counters);
        if (Store->RxFragments[i]) {
            HcClearFragmentsLocked(Store, i);
            ExFreePoolWithTag(Store->RxFragments[i], HC_FRAGMENT_TAG);
            Store->RxFragments[i] = NULL;
        }
    }
    (VOID)Ap6256HostCryptoClose(Store->Provider);
    Store->Provider = NULL;
    RtlSecureZeroMemory(Store->Ports, sizeof(Store->Ports));
    RtlSecureZeroMemory(Store->RxExemptions, sizeof(Store->RxExemptions));
    Store->CounterCount = 0;
}

NTSTATUS Ap6256HostCipherStoreBegin(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, const UCHAR Station[6], const UCHAR Bssid[6])
{
    AP6256_HC_KEY_STATE check;
    AP6256_HC_STORED_KEY* old[AP6256_HC_SLOTS];
    AP6256_HC_COUNTERS* counters;
    KIRQL irql;
    ULONG i, revision;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !Generation || !Ap6256HostCipherInit(&check, 9, 0, 1, 1, 1, Station, Bssid, 0))
        return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Generation <= Store->Ports[IfIndex].LastGeneration || Store->Ports[IfIndex].Revision == MAXULONG) {
        KeReleaseSpinLock(&Store->Lock, irql);
        (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
        ExReleaseRundownProtection(&Store->Rundown); return status;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    revision = HcDetachPort(Store, IfIndex, old, &counters);
    for (i = 0; i < AP6256_HC_SLOTS; ++i) HcDestroy(old[i]);
    HcDestroyCounters(counters);
    KeAcquireSpinLock(&Store->Lock, &irql);

    if (Store->Ports[IfIndex].Revision == revision) {
        Store->Ports[IfIndex].Generation = Generation;
        Store->Ports[IfIndex].Configured = 1;
        Store->Ports[IfIndex].LastGeneration = Generation;
        RtlCopyMemory(Store->Ports[IfIndex].Station, Station, 6);
        RtlCopyMemory(Store->Ports[IfIndex].Bssid, Bssid, 6);
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown);
    return status;
}

NTSTATUS Ap6256HostCipherStoreInstall(AP6256_HC_STORE* Store, const AP6256_HC_KEY_SPEC* Spec)
{
    AP6256_HC_STORED_KEY *key = NULL, *old = NULL;
    AP6256_HC_COUNTERS *counters = NULL, *newCounters = NULL;
    UCHAR digest[32] = {0};
    AP6256_HC_STORE_PORT snapshot;
    ULONG slot;
    KIRQL irql;
    NTSTATUS status = STATUS_INVALID_PARAMETER;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !Spec ||
        Spec->IfIndex >= AP6256_HC_INTERFACES || !Spec->Generation ||
        (slot = HcSlot(Spec->Cipher, Spec->KeyId, Spec->Pairwise)) >= AP6256_HC_SLOTS)
        return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    snapshot = Store->Ports[Spec->IfIndex];
    KeReleaseSpinLock(&Store->Lock, irql);
    if (snapshot.Generation != Spec->Generation ||
        (snapshot.ProfileBound && (!snapshot.AssociationConfirmed ||
            Spec->Cipher != (Spec->Pairwise ? snapshot.Profile.Pairwise :
                Spec->Cipher == AP6256_HC_BIPGMAC256 ? snapshot.Profile.Management : snapshot.Profile.Group))) ||
        !RtlEqualMemory(snapshot.Bssid, Spec->Bssid, 6)) {
        status = STATUS_INVALID_DEVICE_STATE; goto done;
    }
    key = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*key) + Store->ObjectBytes, HC_STORE_TAG);
    if (!key) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
    key->ObjectBytes = Store->ObjectBytes;
    KeInitializeSpinLock(&key->Lock); ExInitializeRundownProtection(&key->Rundown);
    if (!Ap6256HostCipherInit(&key->State, Spec->Cipher, Spec->KeyId, Spec->Pairwise,
        Spec->TxAllowed, Spec->RxAllowed, snapshot.Station, snapshot.Bssid, Spec->ReceivePn))
        goto done;
    status = Ap6256HostCryptoCreateKey(Store->Provider, Spec->Key,
        (UCHAR*)(key + 1), key->ObjectBytes, &key->Handle);
    if (!NT_SUCCESS(status)) goto done;
    RtlCopyMemory(key->Material, Spec->Key, 32);
    status = Ap6256HostCryptoFingerprint(Spec->Key, digest);
    if (!NT_SUCCESS(status)) goto done;
    for (counters = snapshot.Counters; counters; counters = counters->Next)
        if (HcMaterialEqual(counters->Digest, digest)) break;
    if (!counters) {
        if (Store->CounterCount >= AP6256_HC_COUNTER_LIMIT) {
            status = STATUS_INSUFFICIENT_RESOURCES; goto done;
        }
        newCounters = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*newCounters), HC_STORE_TAG);
        if (!newCounters) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
        KeInitializeSpinLock(&newCounters->Lock);
        RtlCopyMemory(newCounters->Digest, digest, sizeof(digest));
        counters = newCounters;
    }
    key->Counters = counters;
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[Spec->IfIndex].Generation != Spec->Generation) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        old = Store->Ports[Spec->IfIndex].Keys[slot];
        if (old && HcMaterialEqual(old->Material, key->Material)) {

            KeAcquireSpinLockAtDpcLevel(&old->Lock);
            if (Ap6256HostCipherRaiseReceivePn(&old->State, Spec->ReceivePn)) {
                KeAcquireSpinLockAtDpcLevel(&old->Counters->Lock);
                HcRaiseCounters(old->Counters, Spec->ReceivePn);
                KeReleaseSpinLockFromDpcLevel(&old->Counters->Lock);
                old->State.TxAllowed = Spec->TxAllowed;
                old->State.RxAllowed = Spec->RxAllowed;
                if (!Spec->RxAllowed) HcClearFragmentsLocked(Store, Spec->IfIndex);
                status = STATUS_SUCCESS;
            } else status = STATUS_INVALID_PARAMETER;
            KeReleaseSpinLockFromDpcLevel(&old->Lock);
            old = NULL;
        } else if (Store->NextEpoch == MAXULONG) {
            old = NULL; status = STATUS_INTEGER_OVERFLOW;
        } else {

            if (newCounters) {
                newCounters->Next = Store->Ports[Spec->IfIndex].Counters;
                Store->Ports[Spec->IfIndex].Counters = newCounters;
                ++Store->Ports[Spec->IfIndex].CounterCount; ++Store->CounterCount;
                newCounters = NULL;
            }
            KeAcquireSpinLockAtDpcLevel(&counters->Lock);
            HcRaiseCounters(counters, Spec->ReceivePn);
            RtlCopyMemory(key->State.RxPn, counters->RxPn, sizeof(key->State.RxPn));
            KeReleaseSpinLockFromDpcLevel(&counters->Lock);
            key->Epoch = ++Store->NextEpoch;
            Store->Ports[Spec->IfIndex].Keys[slot] = key;
            key = NULL; status = STATUS_SUCCESS;
            HcClearFragmentsLocked(Store, Spec->IfIndex);
        }
    }
    KeReleaseSpinLock(&Store->Lock, irql);
done:
    HcDestroy(old); HcDestroy(key);
    HcDestroyCounters(newCounters);
    RtlSecureZeroMemory(digest, sizeof(digest));
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown);
    return status;
}

NTSTATUS Ap6256HostCipherStoreDelete(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Cipher, USHORT KeyId, BOOLEAN Pairwise)
{
    AP6256_HC_STORED_KEY* old = NULL;
    ULONG slot = HcSlot(Cipher, KeyId, Pairwise);
    KIRQL irql;
    NTSTATUS status = STATUS_SUCCESS;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !Generation || slot >= AP6256_HC_SLOTS) return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[IfIndex].Generation != Generation) status = STATUS_INVALID_DEVICE_STATE;
    else {
        old = Store->Ports[IfIndex].Keys[slot]; Store->Ports[IfIndex].Keys[slot] = NULL;
        HcClearFragmentsLocked(Store, IfIndex);
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    HcDestroy(old);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE); ExReleaseRundownProtection(&Store->Rundown);
    return status;
}

VOID Ap6256HostCipherStoreStop(AP6256_HC_STORE* Store, ULONG IfIndex)
{
    AP6256_HC_STORED_KEY* old[AP6256_HC_SLOTS];
    AP6256_HC_COUNTERS* counters;
    ULONG i;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !HcStoreEnter(Store)) return;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    (VOID)HcDetachPort(Store, IfIndex, old, &counters);
    for (i = 0; i < AP6256_HC_SLOTS; ++i) HcDestroy(old[i]);
    HcDestroyCounters(counters);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE); ExReleaseRundownProtection(&Store->Rundown);
}

VOID Ap6256HostCipherStoreInvalidate(AP6256_HC_STORE* Store, ULONG IfIndex)
{
    KIRQL irql;
    if (IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return;
    KeAcquireSpinLock(&Store->Lock, &irql);
    Store->Ports[IfIndex].Generation = 0;
    HcClearFragmentsLocked(Store, IfIndex);
    if (Store->Ports[IfIndex].Revision != MAXULONG) ++Store->Ports[IfIndex].Revision;
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown);
}

VOID Ap6256HostCipherStoreInvalidateAll(AP6256_HC_STORE* Store)
{
    KIRQL irql;
    ULONG i;
    if (!HcStoreEnter(Store)) return;
    KeAcquireSpinLock(&Store->Lock, &irql);
    for (i = 0; i < AP6256_HC_INTERFACES; ++i) {
        Store->Ports[i].Generation = 0;
        HcClearFragmentsLocked(Store, i);
        if (Store->Ports[i].Revision != MAXULONG) ++Store->Ports[i].Revision;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown);
}

VOID Ap6256HostCipherStoreStopAll(AP6256_HC_STORE* Store)
{
    AP6256_HC_STORED_KEY* old[AP6256_HC_INTERFACES][AP6256_HC_SLOTS];
    AP6256_HC_COUNTERS* counters[AP6256_HC_INTERFACES];
    KIRQL irql;
    ULONG i, slot;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !HcStoreEnter(Store)) return;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    for (i = 0; i < AP6256_HC_INTERFACES; ++i) (VOID)HcDetachPortLocked(Store, i, old[i], &counters[i]);
    KeReleaseSpinLock(&Store->Lock, irql);
    for (i = 0; i < AP6256_HC_INTERFACES; ++i) {
        for (slot = 0; slot < AP6256_HC_SLOTS; ++slot) HcDestroy(old[i][slot]);
        HcDestroyCounters(counters[i]);
    }
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown);
}

BOOLEAN Ap6256HostCipherStoreTxCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner)
{
    return Ap6256HostCipherStoreOwnerCurrent(Store, IfIndex, Owner, TRUE);
}

BOOLEAN Ap6256HostCipherStoreOwnerCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner, BOOLEAN Encrypt)
{
    KIRQL irql;
    BOOLEAN current = FALSE;
    AP6256_HC_STORED_KEY* key;
    if (Encrypt > 1 || IfIndex >= AP6256_HC_INTERFACES || !Owner || !Owner->Generation ||
        !Owner->Epoch || Owner->Slot >= AP6256_HC_SLOTS || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    key = Store->Ports[IfIndex].Keys[Owner->Slot];
    if (Store->Ports[IfIndex].Generation == Owner->Generation && key && key->Epoch == Owner->Epoch &&
        (Encrypt ? key->State.TxAllowed : key->State.RxAllowed))
        current = TRUE;
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return current;
}

NTSTATUS Ap6256HostCipherStoreSetDefault(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner)
{
    KIRQL irql;
    AP6256_HC_STORED_KEY* key;
    AP6256_HC_STORE_PORT* port;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !Owner || !Owner->Generation || !Owner->Epoch ||
        (Owner->Slot >= 2 && Owner->Slot != 6 && Owner->Slot != 7))
        return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex]; key = port->Keys[Owner->Slot];
    if (port->Generation == Owner->Generation && key && key->Epoch == Owner->Epoch && key->State.TxAllowed) {
        if (Owner->Slot < 2) { port->TxSlot = Owner->Slot; port->TxEpoch = Owner->Epoch; }
        else { port->ManagementSlot = Owner->Slot; port->ManagementEpoch = Owner->Epoch; }
        status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

BOOLEAN Ap6256HostCipherStoreDefault(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Management, AP6256_HC_TX_OWNER* Owner)
{
    KIRQL irql;
    AP6256_HC_STORE_PORT* port;
    AP6256_HC_STORED_KEY* key;
    ULONG slot, epoch;
    BOOLEAN current = FALSE;
    if (!Owner) return FALSE;
    RtlZeroMemory(Owner, sizeof(*Owner));
    if (!Generation || Management > 1 || IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    slot = Management ? port->ManagementSlot : port->TxSlot;
    epoch = Management ? port->ManagementEpoch : port->TxEpoch;
    key = slot < AP6256_HC_SLOTS ? port->Keys[slot] : NULL;
    if (port->Generation == Generation && epoch && key && key->Epoch == epoch && key->State.TxAllowed) {
        Owner->Generation = Generation; Owner->Epoch = epoch; Owner->Slot = slot; current = TRUE;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return current;
}

BOOLEAN Ap6256HostCipherStoreKeyOwner(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Slot, BOOLEAN Encrypt, AP6256_HC_TX_OWNER* Owner)
{
    KIRQL irql;
    AP6256_HC_STORED_KEY* key;
    BOOLEAN current = FALSE;
    if (!Owner) return FALSE;
    RtlZeroMemory(Owner, sizeof(*Owner));
    if (!Generation || Slot >= AP6256_HC_SLOTS || Encrypt > 1 ||
        IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    key = Store->Ports[IfIndex].Keys[Slot];
    if (Store->Ports[IfIndex].Generation == Generation && key &&
        (Encrypt ? key->State.TxAllowed : key->State.RxAllowed)) {
        Owner->Generation = Generation; Owner->Epoch = key->Epoch; Owner->Slot = Slot; current = TRUE;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return current;
}

BOOLEAN Ap6256HostCipherStoreEpochOwner(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Epoch, BOOLEAN Encrypt, AP6256_HC_TX_OWNER* Owner)
{
    KIRQL irql;
    ULONG slot;
    BOOLEAN current = FALSE;
    if (!Owner) return FALSE;
    RtlZeroMemory(Owner, sizeof(*Owner));
    if (!Generation || !Epoch || Encrypt > 1 || IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[IfIndex].Generation == Generation) for (slot = 0; slot < AP6256_HC_SLOTS; ++slot) {
        AP6256_HC_STORED_KEY* key = Store->Ports[IfIndex].Keys[slot];
        if (key && key->Epoch == Epoch && (Encrypt ? key->State.TxAllowed : key->State.RxAllowed)) {
            Owner->Generation = Generation; Owner->Epoch = Epoch; Owner->Slot = slot; current = TRUE; break;
        }
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return current;
}

BOOLEAN Ap6256HostCipherStoreSnapshot(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_STORE_SESSION* Session)
{
    KIRQL irql;
    BOOLEAN current = FALSE;
    if (!Session) return FALSE;
    RtlZeroMemory(Session, sizeof(*Session));
    if (IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[IfIndex].Generation) {
        Session->Generation = Store->Ports[IfIndex].Generation;
        RtlCopyMemory(Session->Station, Store->Ports[IfIndex].Station, 6);
        RtlCopyMemory(Session->Bssid, Store->Ports[IfIndex].Bssid, 6);
        current = TRUE;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown);
    return current;
}

BOOLEAN Ap6256HostCipherStoreActive(AP6256_HC_STORE* Store, ULONG IfIndex)
{
    KIRQL irql;
    BOOLEAN active;
    if (IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    active = Store->Ports[IfIndex].Configured != 0;
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return active;
}

NTSTATUS Ap6256HostCipherStoreSetRxExemptions(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_RX_EXEMPT* Entries, ULONG Count)
{
    AP6256_HC_RX_EXEMPT_LIST list = {0};
    KIRQL irql;
    ULONG i;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        Count > AP6256_HC_RX_EXEMPT_MAX || (Count && !Entries)) return STATUS_INVALID_PARAMETER;

    for (i = 0; i < Count; ++i) {
        if (Entries[i].Action > 2 || Entries[i].PacketType < 1 || Entries[i].PacketType > 3)
            return STATUS_INVALID_PARAMETER;
        list.Entries[i] = Entries[i];
    }
    list.Count = Count;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    KeAcquireSpinLock(&Store->Lock, &irql);
    Store->RxExemptions[IfIndex] = list;
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return STATUS_SUCCESS;
}

NTSTATUS Ap6256HostCipherStoreSetExcludeUnencrypted(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN ExcludeUnencrypted)
{
    KIRQL irql;
    AP6256_HC_STORE_PORT* port;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    ULONG slot;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !Generation || ExcludeUnencrypted > 1) return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    if (port->Generation == Generation && !port->AssociationConfirmed) {
        for (slot = 0; slot < AP6256_HC_SLOTS && !port->Keys[slot]; ++slot) {}
        if (slot == AP6256_HC_SLOTS) {
            port->ExcludeUnencrypted = ExcludeUnencrypted; status = STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

BOOLEAN Ap6256HostCipherStoreRxAllowed(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Group, BOOLEAN Protected, const UCHAR* Body, ULONG Length)
{
    KIRQL irql;
    USHORT etherType = 0;
    ULONG i;
    BOOLEAN hasType, allowed = FALSE, exempt = FALSE, mapped;
    AP6256_HC_STORE_PORT* port;
    const AP6256_HC_RX_EXEMPT_LIST* list;
    if (!Generation || Group > 1 || Protected > 1 || !Body || !Length ||
        IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    hasType = Length >= 8 && Body[0] == 0xaa && Body[1] == 0xaa && Body[2] == 3 &&
        !Body[3] && !Body[4] && (!Body[5] || Body[5] == 0xf8);
    if (hasType) RtlCopyMemory(&etherType, Body + 6, sizeof(etherType));
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex]; list = &Store->RxExemptions[IfIndex];
    if (port->Generation == Generation) {

        mapped = port->Keys[0] != NULL || port->Keys[1] != NULL;
        allowed = Protected || !port->ExcludeUnencrypted;
        for (i = 0; hasType && i < list->Count; ++i) {
            const AP6256_HC_RX_EXEMPT* entry = &list->Entries[i];
            if (entry->EtherType != etherType ||
                !(entry->PacketType & (Group ? 2u : 1u))) continue;
            if (entry->Action == 1) { if (Protected) {allowed = FALSE; break;} exempt = TRUE; }
            else if (entry->Action == 2 && !Protected) {
                if (mapped) {allowed = FALSE; break;} exempt = TRUE;
            }
        }
        if (i == list->Count || !hasType) allowed = allowed || exempt;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return allowed;
}

NTSTATUS Ap6256HostCipherStoreFragment(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner, ULONGLONG Pn, UCHAR* Frame, ULONG Capacity,
    ULONG* Length)
{
    AP6256_HC_RX_FRAGMENTS *cache, *fresh = NULL;
    HC_RX_FRAGMENT *entry = NULL, *oldest = NULL;
    AP6256_HC_STORE_PORT* port;
    AP6256_HC_STORED_KEY* key;
    ULONG bytes, header, fc, fragment, sequence, tid, i, body;
    ULONGLONG now;
    KIRQL irql;
    NTSTATUS status = STATUS_DATA_ERROR;
    if (!Length) return STATUS_INVALID_PARAMETER;
    bytes = *Length; *Length = 0;
    if (!Frame || !Owner || !Owner->Generation || IfIndex >= AP6256_HC_INTERFACES ||
        bytes < 24 || bytes > Capacity || bytes > AP6256_HC_MAX_FRAME ||
        (Owner->Epoch ? (!Pn || Pn > AP6256_HC_MAX_PN || Owner->Slot >= 2) : Pn != 0))
        return STATUS_INVALID_PARAMETER;
    fc = Frame[0] | ((ULONG)Frame[1] << 8);
    if ((fc & 0x4303u) != 0x0200u || (Frame[4] & 1u)) return STATUS_DATA_ERROR;
    if ((fc & 0xfcu) == 8 && !(fc & 0x8000u)) header = 24;
    else if ((fc & 0xfcu) == 0x88u && bytes >= 26 && !(Frame[24] & 0x80u))
        header = fc & 0x8000u ? 30u : 26u;
    else return STATUS_DATA_ERROR;
    if (bytes <= header) return STATUS_DATA_ERROR;
    fragment = Frame[22] & 15u;
    sequence = (Frame[22] | ((ULONG)Frame[23] << 8)) & 0xfff0u;
    tid = header == 24 ? 16u : Frame[24] & 15u;
    if ((!fragment && !(fc & 0x0400u)) || (fragment == 15 && (fc & 0x0400u)))
        return STATUS_DATA_ERROR;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    KeAcquireSpinLock(&Store->Lock, &irql);
    cache = Store->RxFragments[IfIndex];
    KeReleaseSpinLock(&Store->Lock, irql);
    if (!cache && !fragment) {
        fresh = ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*fresh), HC_FRAGMENT_TAG);
        if (!fresh) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
    }
    now = KeQueryInterruptTime();
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    if (port->Generation != Owner->Generation ||
        !RtlEqualMemory(Frame + 4, port->Station, 6) ||
        !RtlEqualMemory(Frame + 10, port->Bssid, 6)) {
        status = STATUS_DEVICE_NOT_READY; goto unlock;
    }
    if (Owner->Epoch) {
        key = port->Keys[Owner->Slot];
        if (!key || key->Epoch != Owner->Epoch || !key->State.RxAllowed) {
            status = STATUS_DEVICE_NOT_READY; goto unlock;
        }
    }
    cache = Store->RxFragments[IfIndex];
    if (!cache && fresh) {cache = fresh; Store->RxFragments[IfIndex] = fresh; fresh = NULL;}
    if (!cache) goto unlock;
    for (i = 0; i < AP6256_HC_RX_FRAGMENT_CACHE; ++i) {
        HC_RX_FRAGMENT* candidate = &cache->Entries[i];
        if (candidate->Length && (candidate->Generation != Owner->Generation ||
            now - candidate->Started >= AP6256_HC_RX_FRAGMENT_LIFETIME))
            RtlSecureZeroMemory(candidate, sizeof(*candidate));
        if (candidate->Length && candidate->Sequence == sequence && candidate->Tid == tid)
            entry = candidate;
        if (!oldest || candidate->Started < oldest->Started) oldest = candidate;
    }
    if (!fragment) {

        if (entry && !Owner->Epoch && !entry->Epoch) goto unlock;
        if (!entry) {
            for (i = 0; i < AP6256_HC_RX_FRAGMENT_CACHE; ++i)
                if (!cache->Entries[i].Length) {entry = &cache->Entries[i]; break;}
        }
        if (!entry) entry = oldest;
        RtlSecureZeroMemory(entry, sizeof(*entry));
        entry->Started = now; entry->LastPn = Pn;
        entry->Generation = Owner->Generation; entry->Epoch = Owner->Epoch; entry->Slot = Owner->Slot;
        entry->Header = header; entry->Length = bytes; entry->Sequence = sequence; entry->Tid = tid;
        RtlCopyMemory(entry->Frame, Frame, bytes);
        status = STATUS_PENDING; goto unlock;
    }
    if (!entry || fragment <= entry->Fragment) goto unlock;

    if (fragment != entry->Fragment + 1u || header != entry->Header ||
        Owner->Epoch != entry->Epoch || (Owner->Epoch &&
            (Owner->Slot != entry->Slot || entry->LastPn == AP6256_HC_MAX_PN || Pn != entry->LastPn + 1u)) ||
        ((fc ^ (entry->Frame[0] | ((ULONG)entry->Frame[1] << 8))) & 0xc3ffu) ||
        !RtlEqualMemory(Frame + 4, entry->Frame + 4, 18)) goto discard;
    body = bytes - header;
    if (body > AP6256_HC_MAX_FRAME - entry->Length || entry->Length + body > Capacity) {
        status = STATUS_BUFFER_TOO_SMALL; goto discard;
    }
    RtlCopyMemory(entry->Frame + entry->Length, Frame + header, body);
    entry->Length += body; entry->Fragment = fragment; entry->LastPn = Pn;
    if (fc & 0x0400u) {status = STATUS_PENDING; goto unlock;}
    RtlCopyMemory(Frame, entry->Frame, entry->Length);
    Frame[1] &= 0xfbu; Frame[22] &= 0xf0u;
    *Length = entry->Length; status = STATUS_SUCCESS;
discard:
    RtlSecureZeroMemory(entry, sizeof(*entry));
unlock:
    KeReleaseSpinLock(&Store->Lock, irql);
done:
    if (fresh) {RtlSecureZeroMemory(fresh, sizeof(*fresh)); ExFreePoolWithTag(fresh, HC_FRAGMENT_TAG);}
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

NTSTATUS Ap6256HostCipherStoreBindProfile(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, const AP6256_HC_ASSOCIATION_PROFILE* Profile)
{
    KIRQL irql;
    ULONG slot;
    AP6256_HC_STORE_PORT* port;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES || !Generation || !Profile ||
        Profile->Pairwise != AP6256_HC_GCMP256 || Profile->Group != AP6256_HC_GCMP256 || Profile->Mfp > 2 ||
        Profile->Management != (Profile->Mfp ? AP6256_HC_BIPGMAC256 : 0) ||
        (Profile->Akm != 1 && Profile->Akm != 2 && Profile->Akm != 5 && Profile->Akm != 8 && Profile->Akm != 12 && Profile->Akm != 18) ||
        ((Profile->Akm == 5 || Profile->Akm == 8 || Profile->Akm == 12 || Profile->Akm == 18) && Profile->Mfp != 2))
        return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    if (port->Generation == Generation && !port->ProfileBound) {
        for (slot = 0; slot < AP6256_HC_SLOTS && !port->Keys[slot]; ++slot) {}
        if (slot == AP6256_HC_SLOTS) {
            port->Profile = *Profile; port->ProfileBound = 1;
            port->AssociationConfirmed = port->Authorized = 0; status = STATUS_SUCCESS;
        }
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

NTSTATUS Ap6256HostCipherStoreConfirmAssociation(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_STORE_SESSION* Session, const AP6256_HC_ASSOCIATION_PROFILE* Profile)
{
    KIRQL irql;
    AP6256_HC_STORE_PORT* port;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || IfIndex >= AP6256_HC_INTERFACES ||
        !Session || !Session->Generation || !Profile) return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    if (port->Generation == Session->Generation && port->ProfileBound && !port->AssociationConfirmed &&
        RtlEqualMemory(port->Station, Session->Station, 6) && RtlEqualMemory(port->Bssid, Session->Bssid, 6) &&
        RtlEqualMemory(&port->Profile, Profile, sizeof(*Profile))) {
        port->AssociationConfirmed = 1; status = STATUS_SUCCESS;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

BOOLEAN Ap6256HostCipherStoreProfile(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN RequireConfirmed, AP6256_HC_ASSOCIATION_PROFILE* Profile)
{
    KIRQL irql;
    AP6256_HC_STORE_PORT* port;
    BOOLEAN current = FALSE;
    if (!Profile) return FALSE;
    RtlZeroMemory(Profile, sizeof(*Profile));
    if (!Generation || RequireConfirmed > 1 || IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    port = &Store->Ports[IfIndex];
    if (port->Generation == Generation && port->ProfileBound && (!RequireConfirmed || port->AssociationConfirmed)) {
        *Profile = port->Profile; current = TRUE;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return current;
}

static BOOLEAN HcStoreProfileKeysReady(const AP6256_HC_STORE_PORT* Port)
{
    AP6256_HC_STORED_KEY* tx;
    ULONG slot;
    if (!Port->ProfileBound) return TRUE;
    if (!Port->AssociationConfirmed || Port->TxSlot >= 2 || !Port->TxEpoch) return FALSE;
    tx = Port->Keys[Port->TxSlot];
    if (!tx || tx->Epoch != Port->TxEpoch || !tx->State.TxAllowed) return FALSE;
    for (slot = 0; slot < 2; ++slot)
        if (Port->Keys[slot] && Port->Keys[slot]->State.RxAllowed) break;
    if (slot == 2) return FALSE;
    if (Port->Profile.Management) {
        for (slot = 6; slot < 8; ++slot)
            if (Port->Keys[slot] && Port->Keys[slot]->State.RxAllowed) break;
        if (slot == 8) return FALSE;
    }
    return TRUE;
}

NTSTATUS Ap6256HostCipherStoreAuthorize(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Authorized)
{
    KIRQL irql;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL || !Generation || Authorized > 1 ||
        IfIndex >= AP6256_HC_INTERFACES) return STATUS_INVALID_PARAMETER;
    if (!HcStoreEnter(Store)) return STATUS_DEVICE_NOT_READY;
    (VOID)KeWaitForSingleObject(&Store->Mutation, Executive, KernelMode, FALSE, NULL);
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[IfIndex].Generation == Generation && InterlockedCompareExchange(&Store->Ready, 0, 0) &&
        (!Authorized || HcStoreProfileKeysReady(&Store->Ports[IfIndex]))) {
        Store->Ports[IfIndex].Authorized = Authorized; status = STATUS_SUCCESS;
        if (!Authorized) HcClearFragmentsLocked(Store, IfIndex);
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    (VOID)KeReleaseMutex(&Store->Mutation, FALSE);
    ExReleaseRundownProtection(&Store->Rundown); return status;
}

BOOLEAN Ap6256HostCipherStoreAuthorized(AP6256_HC_STORE* Store, ULONG IfIndex, ULONG Generation)
{
    KIRQL irql;
    BOOLEAN authorized = FALSE;
    if (!Generation || IfIndex >= AP6256_HC_INTERFACES || !HcStoreEnter(Store)) return FALSE;
    KeAcquireSpinLock(&Store->Lock, &irql);
    authorized = Store->Ports[IfIndex].Generation == Generation && Store->Ports[IfIndex].Authorized &&
        HcStoreProfileKeysReady(&Store->Ports[IfIndex]) &&
        InterlockedCompareExchange(&Store->Ready, 0, 0);
    KeReleaseSpinLock(&Store->Lock, irql);
    ExReleaseRundownProtection(&Store->Rundown); return authorized;
}

NTSTATUS Ap6256HostCipherStoreFrame(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Cipher, USHORT KeyId, BOOLEAN Pairwise, BOOLEAN Encrypt,
    const UCHAR* Frame, ULONG Length, UCHAR* Output, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written, AP6256_HC_TX_OWNER* Owner)
{
    AP6256_HC_STORED_KEY* key = NULL;
    ULONG slot = HcSlot(Cipher, KeyId, Pairwise);
    KIRQL irql;
    AP6256_HC_U32 written = 0;
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    if (Written) *Written = 0;
    if (Owner) RtlZeroMemory(Owner, sizeof(*Owner));
    if (!Written || !Owner || !Generation || Encrypt > 1 || Pairwise > 1 || IfIndex >= AP6256_HC_INTERFACES ||
        slot >= AP6256_HC_SLOTS || !HcStoreEnter(Store)) return status;
    KeAcquireSpinLock(&Store->Lock, &irql);
    if (Store->Ports[IfIndex].Generation == Generation) {
        key = Store->Ports[IfIndex].Keys[slot];
        if (key && !ExAcquireRundownProtection(&key->Rundown)) key = NULL;
    }
    KeReleaseSpinLock(&Store->Lock, irql);
    if (key) {
        int ok;
        KeAcquireSpinLock(&key->Lock, &irql);
        if (Encrypt) {
            ULONGLONG pn = key->State.TxAllowed ? HcReservePn(Store) : 0;
            ok = 0;
            if (pn) {
                key->State.TxPn = pn - 1;
                ok = Ap6256HostCipherEncrypt(&key->State, Ap6256HostCryptoCrypt, key->Handle,
                    Frame, Length, Output, Capacity, Scratch, ScratchCapacity, &written);
            }
        } else {
            KeAcquireSpinLockAtDpcLevel(&key->Counters->Lock);
            RtlCopyMemory(key->State.RxPn, key->Counters->RxPn, sizeof(key->State.RxPn));
            ok = Ap6256HostCipherDecrypt(&key->State, Ap6256HostCryptoCrypt, key->Handle,
                Frame, Length, Output, Capacity, Scratch, ScratchCapacity, &written);
            if (ok) RtlCopyMemory(key->Counters->RxPn, key->State.RxPn, sizeof(key->State.RxPn));
            KeReleaseSpinLockFromDpcLevel(&key->Counters->Lock);
        }
        if (ok) {
            *Written = written; Owner->Generation = Generation;
            Owner->Epoch = key->Epoch; Owner->Slot = slot; status = STATUS_SUCCESS;
        } else status = STATUS_DATA_ERROR;
        KeReleaseSpinLock(&key->Lock, irql);
        if (NT_SUCCESS(status)) {
            KeAcquireSpinLock(&Store->Lock, &irql);
            if (!InterlockedCompareExchange(&Store->Ready, 0, 0) ||
                Store->Ports[IfIndex].Generation != Generation ||
                Store->Ports[IfIndex].Keys[slot] != key) {
                RtlSecureZeroMemory(Output, *Written); *Written = 0;
                RtlZeroMemory(Owner, sizeof(*Owner)); status = STATUS_DEVICE_NOT_READY;
            }
            KeReleaseSpinLock(&Store->Lock, irql);
        }
        ExReleaseRundownProtection(&key->Rundown);
    }
    ExReleaseRundownProtection(&Store->Rundown); return status;
}
