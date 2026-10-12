/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"
#include "host_cipher_wire.h"
#include "host_cipher_disconnect.h"

#define AP6256_HC_CONTROL_ABI 0x31435048u
typedef struct _AP6256_HC_MODE {
    UINT32 Abi, Bytes, Enabled;
    AP6256_HC_WIRE_SESSION Session;
} AP6256_HC_MODE;
typedef struct _AP6256_HC_KEY_CONTROL {
    UINT32 Abi, Bytes, Generation, Slot, Epoch, SetDefault, DefaultSlot, Reserved;
} AP6256_HC_KEY_CONTROL;
typedef struct _AP6256_HC_AUTH_CONTROL {
    UINT32 Abi, Bytes, Generation, Authorized, Epoch, Slot, ManagementEpoch, ManagementSlot;
} AP6256_HC_AUTH_CONTROL;
typedef struct _AP6256_HC_PROFILE_CONTROL {
    UINT32 Abi, Bytes, Generation, Pairwise, Group, Management, Akm, Mfp;
} AP6256_HC_PROFILE_CONTROL;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherQualify(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN PatchVerified);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HostCipherFirmwareRetire(PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherFirmwareStarted(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6]);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherBeginProfile(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherBeginProfileRx(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp,
    BOOLEAN ExcludeUnencrypted);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherReadProfile(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_HC_STORE_SESSION* Session, AP6256_HC_PROFILE_CONTROL* Profile);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherConfirmAssociation(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherEnd(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, BOOLEAN Retiring);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherEndGeneration(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, BOOLEAN* Matched);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherDisconnect(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Bssid, UINT32 Reason, BOOLEAN* Handled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherControlStart(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_HC_STORE_SESSION* Session);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherControlFinish(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, NTSTATUS Status, BOOLEAN Changed);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherKeyAcknowledge(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const AP6256_HC_TX_OWNER* Owner, BOOLEAN SelectDefault);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherKeyReady(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, BOOLEAN ClosePort);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256HostCipherSetDefault(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, ULONG KeyId);
