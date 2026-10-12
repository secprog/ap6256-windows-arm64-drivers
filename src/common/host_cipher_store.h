/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#ifndef AP6256_HOST_CIPHER_STORE_USER_TEST
#include <ntddk.h>
#endif
#include "host_cipher_frame.h"

#define AP6256_HC_INTERFACES 16u
#define AP6256_HC_SLOTS 8u
#define AP6256_HC_COUNTER_LIMIT 4096u
#define AP6256_HC_RX_EXEMPT_MAX 16u
#define AP6256_HC_RX_FRAGMENT_CACHE 4u
#define AP6256_HC_RX_FRAGMENT_LIFETIME 20000000ull

typedef struct _AP6256_HC_RX_EXEMPT {
    USHORT EtherType;
    UCHAR Action, PacketType;
} AP6256_HC_RX_EXEMPT;
typedef struct _AP6256_HC_RX_EXEMPT_LIST {
    ULONG Count;
    AP6256_HC_RX_EXEMPT Entries[AP6256_HC_RX_EXEMPT_MAX];
} AP6256_HC_RX_EXEMPT_LIST;

typedef struct _AP6256_HC_STORED_KEY AP6256_HC_STORED_KEY;
typedef struct _AP6256_HC_COUNTERS AP6256_HC_COUNTERS;
typedef struct _AP6256_HC_RX_FRAGMENTS AP6256_HC_RX_FRAGMENTS;
typedef struct _AP6256_HC_ASSOCIATION_PROFILE {
    ULONG Pairwise, Group, Management, Akm, Mfp;
} AP6256_HC_ASSOCIATION_PROFILE;
typedef struct _AP6256_HC_STORE_PORT {
    ULONG Generation, LastGeneration, Revision;
    ULONG Configured, Authorized;
    ULONG ProfileBound, AssociationConfirmed;
    ULONG ExcludeUnencrypted;
    AP6256_HC_ASSOCIATION_PROFILE Profile;
    ULONG TxSlot, TxEpoch, ManagementSlot, ManagementEpoch;
    UCHAR Station[6], Bssid[6];
    AP6256_HC_STORED_KEY* Keys[AP6256_HC_SLOTS];
    AP6256_HC_COUNTERS* Counters;
    ULONG CounterCount;
} AP6256_HC_STORE_PORT;

typedef struct _AP6256_HC_STORE {
    KSPIN_LOCK Lock;
    KSPIN_LOCK PnLock;
    KMUTEX Mutation;
    EX_RUNDOWN_REF Rundown;
    volatile LONG Ready;
    void* Provider;
    ULONG ObjectBytes, NextEpoch;
    ULONG CounterCount;
    ULONGLONG NextTransmitPn;
    AP6256_HC_STORE_PORT Ports[AP6256_HC_INTERFACES];

    AP6256_HC_RX_EXEMPT_LIST RxExemptions[AP6256_HC_INTERFACES];

    AP6256_HC_RX_FRAGMENTS* RxFragments[AP6256_HC_INTERFACES];
} AP6256_HC_STORE;

typedef struct _AP6256_HC_KEY_SPEC {
    ULONG IfIndex, Generation, Cipher;
    USHORT KeyId;
    BOOLEAN Pairwise, TxAllowed, RxAllowed;
    UCHAR Bssid[6];
    UCHAR Key[32];
    ULONGLONG ReceivePn;
} AP6256_HC_KEY_SPEC;

typedef struct _AP6256_HC_TX_OWNER {
    ULONG Generation, Epoch, Slot;
} AP6256_HC_TX_OWNER;

typedef struct _AP6256_HC_STORE_SESSION {
    ULONG Generation;
    UCHAR Station[6], Bssid[6];
} AP6256_HC_STORE_SESSION;

NTSTATUS Ap6256HostCipherStoreInit(AP6256_HC_STORE* Store);
VOID Ap6256HostCipherStoreClose(AP6256_HC_STORE* Store);
NTSTATUS Ap6256HostCipherStoreBegin(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, const UCHAR Station[6], const UCHAR Bssid[6]);

NTSTATUS Ap6256HostCipherStoreBindProfile(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, const AP6256_HC_ASSOCIATION_PROFILE* Profile);
NTSTATUS Ap6256HostCipherStoreConfirmAssociation(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_STORE_SESSION* Session, const AP6256_HC_ASSOCIATION_PROFILE* Profile);
BOOLEAN Ap6256HostCipherStoreProfile(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN RequireConfirmed, AP6256_HC_ASSOCIATION_PROFILE* Profile);
NTSTATUS Ap6256HostCipherStoreInstall(AP6256_HC_STORE* Store, const AP6256_HC_KEY_SPEC* Spec);
NTSTATUS Ap6256HostCipherStoreDelete(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Cipher, USHORT KeyId, BOOLEAN Pairwise);
VOID Ap6256HostCipherStoreStop(AP6256_HC_STORE* Store, ULONG IfIndex);
VOID Ap6256HostCipherStoreStopAll(AP6256_HC_STORE* Store);

VOID Ap6256HostCipherStoreInvalidate(AP6256_HC_STORE* Store, ULONG IfIndex);
VOID Ap6256HostCipherStoreInvalidateAll(AP6256_HC_STORE* Store);
BOOLEAN Ap6256HostCipherStoreSnapshot(AP6256_HC_STORE* Store, ULONG IfIndex,
    AP6256_HC_STORE_SESSION* Session);
BOOLEAN Ap6256HostCipherStoreActive(AP6256_HC_STORE* Store, ULONG IfIndex);
NTSTATUS Ap6256HostCipherStoreSetRxExemptions(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_RX_EXEMPT* Entries, ULONG Count);

NTSTATUS Ap6256HostCipherStoreSetExcludeUnencrypted(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN ExcludeUnencrypted);

BOOLEAN Ap6256HostCipherStoreRxAllowed(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Group, BOOLEAN Protected, const UCHAR* Body, ULONG Length);

NTSTATUS Ap6256HostCipherStoreFragment(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner, ULONGLONG Pn, UCHAR* Frame, ULONG Capacity,
    ULONG* Length);
NTSTATUS Ap6256HostCipherStoreAuthorize(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Authorized);
BOOLEAN Ap6256HostCipherStoreAuthorized(AP6256_HC_STORE* Store, ULONG IfIndex, ULONG Generation);
BOOLEAN Ap6256HostCipherStoreTxCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner);

NTSTATUS Ap6256HostCipherStoreSetDefault(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner);
BOOLEAN Ap6256HostCipherStoreDefault(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, BOOLEAN Management, AP6256_HC_TX_OWNER* Owner);
BOOLEAN Ap6256HostCipherStoreKeyOwner(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Slot, BOOLEAN Encrypt, AP6256_HC_TX_OWNER* Owner);
BOOLEAN Ap6256HostCipherStoreEpochOwner(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Epoch, BOOLEAN Encrypt, AP6256_HC_TX_OWNER* Owner);
BOOLEAN Ap6256HostCipherStoreOwnerCurrent(AP6256_HC_STORE* Store, ULONG IfIndex,
    const AP6256_HC_TX_OWNER* Owner, BOOLEAN Encrypt);

NTSTATUS Ap6256HostCipherStoreFrame(AP6256_HC_STORE* Store, ULONG IfIndex,
    ULONG Generation, ULONG Cipher, USHORT KeyId, BOOLEAN Pairwise, BOOLEAN Encrypt,
    const UCHAR* Frame, ULONG Length, UCHAR* Output, ULONG Capacity,
    UCHAR* Scratch, ULONG ScratchCapacity, ULONG* Written, AP6256_HC_TX_OWNER* Owner);
