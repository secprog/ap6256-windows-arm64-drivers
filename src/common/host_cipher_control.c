/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_control.h"
#include "host_fips.h"
#include "bcdc.h"
#include "wlfc.h"
#include "host_cipher_path.h"

C_ASSERT(sizeof(AP6256_HC_MODE) == 32);
C_ASSERT(sizeof(AP6256_HC_KEY_CONTROL) == 32);
C_ASSERT(sizeof(AP6256_HC_AUTH_CONTROL) == 32);
C_ASSERT(sizeof(AP6256_HC_PROFILE_CONTROL) == 32);
C_ASSERT(sizeof(AP6256_HC_DISCONNECT_CONTROL) == 32);

static AP6256_HC_ASSOCIATION_PROFILE HcControlProfile(const AP6256_HC_PROFILE_CONTROL* Profile)
{
    AP6256_HC_ASSOCIATION_PROFILE bound = {Profile->Pairwise, Profile->Group,
        Profile->Management, Profile->Akm, Profile->Mfp};
    return bound;
}

static BOOLEAN HcControlCurrent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, UINT32 Generation)
{
    AP6256_HC_STORE_SESSION current;
    return InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) == 1 &&
        !(InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) & AP6256_HC_FIRMWARE_RETIRED) &&
        !InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) &&
        !Ap6256FipsActive(Ctx, IfIndex) &&
        Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, &current) &&
        current.Generation == Generation;
}

static VOID HcControlBlock(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    InterlockedOr(&Ctx->HostCipherBlockedMask, (LONG)(1u << IfIndex));
    Ap6256WlfcCancel(Ctx, IfIndex ? AP6256_GROUP_PORT : AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
}

static NTSTATUS HcControlMode(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, const AP6256_HC_MODE* Mode)
{
    AP6256_HC_MODE readback = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wdi_hc_mode", Mode, sizeof(*Mode));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_mode", &readback, sizeof(readback), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(readback) ||
        !RtlEqualMemory(Mode, &readback, sizeof(readback))) return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

static NTSTATUS HcControlEnd(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, BOOLEAN Retiring)
{
    AP6256_HC_MODE mode = {AP6256_HC_CONTROL_ABI, sizeof(mode), 0, {0}};
    NTSTATUS status;
    if (!Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, IfIndex) &&
        !(InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
          (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex))))
        return STATUS_SUCCESS;
    HcControlBlock(Ctx, IfIndex);
    Ap6256HostCipherStoreInvalidate(&Ctx->HostCipherStore, IfIndex);
    if (InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
        Ctx->FirmwareState != Ap6256FwRunning ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) {

        Ap6256HostCipherStoreStop(&Ctx->HostCipherStore, IfIndex);
        return STATUS_DEVICE_NOT_READY;
    }
    status = HcControlMode(Ctx, IfIndex, &mode);
    Ap6256HostCipherStoreStop(&Ctx->HostCipherStore, IfIndex);
    if (NT_SUCCESS(status) && !Retiring &&
        InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) == 1 &&
        Ctx->FirmwareState == Ap6256FwRunning &&
        !InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0))
        InterlockedAnd(&Ctx->HostCipherBlockedMask, (LONG)~(1u << IfIndex));
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherEnd(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, BOOLEAN Retiring)
{
    NTSTATUS status;
    if (!Ctx || IfIndex >= AP6256_HC_INTERFACES || Retiring > 1 || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    status = HcControlEnd(Ctx, IfIndex, Retiring);
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherEndGeneration(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, BOOLEAN* Matched)
{
    AP6256_HC_STORE_SESSION session;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    if (Matched) *Matched = FALSE;
    if (!Ctx || !Matched || !Generation || IfIndex >= AP6256_HC_INTERFACES ||
        KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    if (Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, &session) &&
        session.Generation == Generation) {
        *Matched = TRUE;
        status = HcControlEnd(Ctx, IfIndex, FALSE);
    }
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherDisconnect(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Bssid, UINT32 Reason, BOOLEAN* Handled)
{
    struct {
        AP6256_HC_DISCONNECT_CONTROL Header;
        UCHAR Wire[AP6256_HC_DISCONNECT_WIRE_BYTES];
    } request = {0};
    AP6256_HC_DISCONNECT_CONTROL receipt = {0};
    AP6256_HC_STORE_SESSION session;
    AP6256_HC_ASSOCIATION_PROFILE profile;
    AP6256_HC_MODE mode = {AP6256_HC_CONTROL_ABI, sizeof(mode), 0, {0}}, readback = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    UCHAR frame[26] = {0xc0};
    ULONG written = 0;
    NTSTATUS status = STATUS_SUCCESS, cryptoStatus;
    if (Handled) *Handled = FALSE;
    if (!Ctx || !Handled || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    if (!Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, &session)) {
        if (InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
            (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex))) {
            *Handled = TRUE; status = STATUS_DEVICE_NOT_READY;
        }
        goto complete;
    }
    *Handled = TRUE;
    if ((Bssid && !RtlEqualMemory(Bssid, session.Bssid, 6)) || Reason > 65535u) {
        status = STATUS_INVALID_PARAMETER; goto complete;
    }
    if (!HcControlCurrent(Ctx, IfIndex, session.Generation)) {
        status = STATUS_DEVICE_NOT_READY; goto complete;
    }
    if (!Ap6256HostCipherStoreProfile(&Ctx->HostCipherStore, IfIndex, session.Generation, FALSE, &profile)) {
        status = STATUS_INVALID_DEVICE_STATE; goto complete;
    }
    if (!Reason) Reason = 3;
    HcControlBlock(Ctx, IfIndex);
    RtlCopyMemory(frame + 4, session.Bssid, 6);
    RtlCopyMemory(frame + 10, session.Station, 6);
    RtlCopyMemory(frame + 16, session.Bssid, 6);
    frame[24] = (UCHAR)Reason; frame[25] = (UCHAR)(Reason >> 8);
    request.Header.Abi = AP6256_HC_CONTROL_ABI; request.Header.Bytes = sizeof(request.Header);
    request.Header.Generation = session.Generation; request.Header.IfIndex = IfIndex;
    request.Header.Reason = Reason; request.Header.Mode = AP6256_HC_DISCONNECT_NATIVE_CLEAR;
    cryptoStatus = profile.Mfp ? Ap6256HostCipherManagementTx(&Ctx->HostCipherStore, IfIndex,
        frame, sizeof(frame), request.Wire, sizeof(request.Wire), NULL, 0, &written) : STATUS_SUCCESS;
    if (profile.Mfp && NT_SUCCESS(cryptoStatus)) {
        request.Header.Mode = AP6256_HC_DISCONNECT_PROTECTED;
        if (written != sizeof(request.Wire)) {status = STATUS_DEVICE_PROTOCOL_ERROR; goto complete;}
    } else written = 0;

    if (!HcControlCurrent(Ctx, IfIndex, session.Generation)) {
        status = STATUS_DEVICE_NOT_READY; goto complete;
    }
    Ap6256HostCipherStoreInvalidate(&Ctx->HostCipherStore, IfIndex);
    Ap6256HostCipherStoreStop(&Ctx->HostCipherStore, IfIndex);

    (VOID)Ap6256BcdcSetIovarResultIf(Ctx, IfIndex, "wdi_hc_disconnect", &request,
        sizeof(request.Header) + written, &result);
    receipt.Abi = request.Header.Abi; receipt.Bytes = sizeof(receipt);
    receipt.Generation = session.Generation; receipt.IfIndex = IfIndex;
    RtlZeroMemory(&result, sizeof(result));

    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_disconnect",
        &receipt, sizeof(receipt), &result);
    if (!NT_SUCCESS(status)) goto complete;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(receipt) ||
        receipt.Abi != request.Header.Abi || receipt.Bytes != sizeof(receipt) ||
        receipt.Generation != session.Generation || receipt.IfIndex != IfIndex ||
        receipt.Reason != Reason || receipt.Mode > AP6256_HC_DISCONNECT_NATIVE_CLEAR ||
        receipt.NativeStatus || receipt.Completed != 1) {
        status = STATUS_DEVICE_PROTOCOL_ERROR; goto complete;
    }
    RtlZeroMemory(&result, sizeof(result));
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_mode", &readback, sizeof(readback), &result);
    if (!NT_SUCCESS(status)) goto complete;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(readback) ||
        !RtlEqualMemory(&mode, &readback, sizeof(mode)) ||
        Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, IfIndex) ||
        InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) {
        status = STATUS_DEVICE_PROTOCOL_ERROR; goto complete;
    }

    InterlockedAnd(&Ctx->HostCipherBlockedMask, (LONG)~(1u << IfIndex));
    if (receipt.Mode != request.Header.Mode)
        status = NT_SUCCESS(cryptoStatus) ? STATUS_UNSUCCESSFUL : cryptoStatus;
complete:
    RtlSecureZeroMemory(frame, sizeof(frame));
    RtlSecureZeroMemory(&request, sizeof(request));
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
VOID Ap6256HostCipherFirmwareRetire(PAP6256_DEVICE_CONTEXT Ctx)
{
    if (!Ctx) return;

    InterlockedOr(&Ctx->HostCipherBlockedMask, (LONG)AP6256_HC_FIRMWARE_RETIRED);
    InterlockedExchange(&Ctx->HostCipherFirmwareQualified, 0);
    Ap6256HostCipherStoreInvalidateAll(&Ctx->HostCipherStore);
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    InterlockedOr(&Ctx->HostCipherBlockedMask, (LONG)AP6256_HC_FIRMWARE_RETIRED);
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherFirmwareStarted(PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    if (!Ctx || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        Ctx->FirmwareState != Ap6256FwDownloading ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0))
        return STATUS_INVALID_DEVICE_STATE;

    InterlockedExchange(&Ctx->HostCipherFirmwareQualified, 0);
    Ap6256HostCipherStoreInvalidateAll(&Ctx->HostCipherStore);
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    InterlockedExchange(&Ctx->HostCipherFirmwareQualified, 0);
    if (Ctx->FirmwareState != Ap6256FwDownloading ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) goto complete;
    Ap6256HostCipherStoreStopAll(&Ctx->HostCipherStore);
    if (Ctx->FirmwareState != Ap6256FwDownloading ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) goto complete;

    InterlockedExchange(&Ctx->HostCipherBlockedMask, 0);
    status = STATUS_SUCCESS;
complete:
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherQualify(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN PatchVerified)
{
    UINT32 caps[8] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status = STATUS_SUCCESS;
    if (!Ctx || PatchVerified > 1 || KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);

    InterlockedExchange(&Ctx->HostCipherFirmwareQualified, -1);
    Ap6256HostCipherStoreInvalidateAll(&Ctx->HostCipherStore);
    if (!PatchVerified) goto complete;
    if (Ctx->FirmwareState != Ap6256FwRunning ||
        (InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) & AP6256_HC_FIRMWARE_RETIRED) ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) {
        status = STATUS_DEVICE_NOT_READY; goto complete;
    }
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wdi_hc_caps", caps, sizeof(caps), &result);
    if (!NT_SUCCESS(status)) goto complete;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(caps) ||
        caps[0] != AP6256_HC_CONTROL_ABI || caps[1] != sizeof(caps) || caps[2] != AP6256_HC_RELAY_FEATURES || caps[3] != 1 ||
        caps[4] != AP6256_HC_MAX_FRAME || caps[5] != 1760 || caps[6] != 2244 || caps[7] != 16 ||
        !InterlockedCompareExchange(&Ctx->HostCipherStore.Ready, 0, 0) ||
        Ctx->FirmwareState != Ap6256FwRunning ||
        (InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) & AP6256_HC_FIRMWARE_RETIRED) ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0)) {
        status = STATUS_DEVICE_PROTOCOL_ERROR; goto complete;
    }

    Ap6256HostCipherStoreStopAll(&Ctx->HostCipherStore);
    if (InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 1, -1) != -1) {
        status = STATUS_DEVICE_NOT_READY; goto complete;
    }

    InterlockedAnd(&Ctx->HostCipherBlockedMask, (LONG)~((1u << AP6256_HC_INTERFACES) - 1u));
complete:
    (VOID)InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, -1);
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

static NTSTATUS HcControlBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6], const AP6256_HC_PROFILE_CONTROL* Profile,
    BOOLEAN ExcludeUnencrypted)
{
    AP6256_HC_MODE mode = {AP6256_HC_CONTROL_ABI, sizeof(mode), 1, {0}};
    UCHAR header[24];
    NTSTATUS status;
    if (!Ctx || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL || ExcludeUnencrypted > 1)
        return STATUS_INVALID_PARAMETER;
    mode.Session.Generation = 1; mode.Session.IfIndex = (UCHAR)IfIndex;
    if (!Station || !Bssid) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(mode.Session.Station, Station, 6); RtlCopyMemory(mode.Session.Bssid, Bssid, 6);
    if (!Ap6256HostCipherWireWrite(&mode.Session, AP6256_HC_MGMT_DROP, 1, 0, NULL, 0, header, sizeof(header)))
        return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    if (InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) || Ap6256FipsActive(Ctx, IfIndex)) {
        status = STATUS_NOT_SUPPORTED; goto complete;
    }
    status = HcControlEnd(Ctx, IfIndex, TRUE);
    if (!NT_SUCCESS(status)) goto complete;
    HcControlBlock(Ctx, IfIndex);
    if (Ctx->HostCipherNextGeneration == MAXULONG) {status = STATUS_INTEGER_OVERFLOW; goto complete;}
    mode.Session.Generation = ++Ctx->HostCipherNextGeneration;
    status = Ap6256HostCipherStoreBegin(&Ctx->HostCipherStore, IfIndex, mode.Session.Generation, Station, Bssid);
    if (NT_SUCCESS(status)) status = Ap6256HostCipherStoreSetExcludeUnencrypted(&Ctx->HostCipherStore,
        IfIndex, mode.Session.Generation, ExcludeUnencrypted);
    if (NT_SUCCESS(status)) status = HcControlMode(Ctx, IfIndex, &mode);
    if (NT_SUCCESS(status) && Profile) {
        AP6256_HC_PROFILE_CONTROL expected = *Profile, query = {0};
        AP6256_BCDC_QUERY_RESULT result = {0};
        expected.Generation = mode.Session.Generation;

        if (!HcControlCurrent(Ctx, IfIndex, expected.Generation)) status = STATUS_DEVICE_NOT_READY;
        else status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wdi_hc_profile", &expected, sizeof(expected));
        if (NT_SUCCESS(status)) {
            query.Abi = expected.Abi; query.Bytes = expected.Bytes; query.Generation = expected.Generation;
            status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_profile", &query, sizeof(query), &result);
            if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
                result.PayloadLength < sizeof(query) || !RtlEqualMemory(&expected, &query, sizeof(expected))))
                status = STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }
    if (NT_SUCCESS(status) && !HcControlCurrent(Ctx, IfIndex, mode.Session.Generation)) status = STATUS_DEVICE_NOT_READY;
    if (NT_SUCCESS(status) && Profile) {
        AP6256_HC_ASSOCIATION_PROFILE bound = HcControlProfile(Profile);
        status = Ap6256HostCipherStoreBindProfile(&Ctx->HostCipherStore, IfIndex, mode.Session.Generation, &bound);
    }
    if (NT_SUCCESS(status)) InterlockedAnd(&Ctx->HostCipherBlockedMask, (LONG)~(1u << IfIndex));
    else {Ap6256HostCipherStoreInvalidate(&Ctx->HostCipherStore, IfIndex); Ap6256HostCipherStoreStop(&Ctx->HostCipherStore, IfIndex);}
complete:
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherBegin(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6])
{
    return HcControlBegin(Ctx, IfIndex, Station, Bssid, NULL, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherBeginProfile(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp)
{
    return Ap6256HostCipherBeginProfileRx(Ctx, IfIndex, Station, Bssid, Akm, Mfp, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherBeginProfileRx(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp, BOOLEAN ExcludeUnencrypted)
{
    AP6256_HC_PROFILE_CONTROL profile = {AP6256_HC_CONTROL_ABI, sizeof(profile), 0,
        AP6256_HC_GCMP256, AP6256_HC_GCMP256,
        Mfp ? AP6256_HC_BIPGMAC256 : 0, Akm, Mfp};
    if (Mfp > 2 || (Akm != 1 && Akm != 2 && Akm != 5 && Akm != 8 && Akm != 12 && Akm != 18) ||
        ((Akm == 5 || Akm == 8 || Akm == 12 || Akm == 18) && Mfp != 2)) return STATUS_NOT_SUPPORTED;
    return HcControlBegin(Ctx, IfIndex, Station, Bssid, &profile, ExcludeUnencrypted);
}

static NTSTATUS HcControlReadProfile(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_HC_STORE_SESSION* Session, AP6256_HC_PROFILE_CONTROL* Profile)
{
    AP6256_HC_STORE_SESSION owner = {0};
    AP6256_HC_PROFILE_CONTROL query = {AP6256_HC_CONTROL_ABI, sizeof(query), 0, 0, 0, 0, 0, 0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    AP6256_HC_ASSOCIATION_PROFILE bound, readback;
    NTSTATUS status;
    if (!Session || !Profile) return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Session, sizeof(*Session)); RtlZeroMemory(Profile, sizeof(*Profile));
    if (!Ctx || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    if ((InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
         (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex))) ||
        !Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, &owner) ||
        !HcControlCurrent(Ctx, IfIndex, owner.Generation) ||
        !Ap6256HostCipherStoreProfile(&Ctx->HostCipherStore, IfIndex, owner.Generation, FALSE, &bound)) {
        status = STATUS_DEVICE_NOT_READY; goto complete;
    }
    query.Generation = owner.Generation;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_profile", &query, sizeof(query), &result);
    if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(query) || query.Abi != AP6256_HC_CONTROL_ABI ||
        query.Bytes != sizeof(query) || query.Generation != owner.Generation ||
        query.Pairwise != AP6256_HC_GCMP256 || query.Group != AP6256_HC_GCMP256 ||
        query.Mfp > 2 || query.Management != (query.Mfp ? AP6256_HC_BIPGMAC256 : 0) ||
        (query.Akm != 1 && query.Akm != 2 && query.Akm != 5 && query.Akm != 8 && query.Akm != 12 && query.Akm != 18) ||
        ((query.Akm == 5 || query.Akm == 8 || query.Akm == 12 || query.Akm == 18) && query.Mfp != 2)))
        status = STATUS_DEVICE_PROTOCOL_ERROR;
    if (NT_SUCCESS(status) && !HcControlCurrent(Ctx, IfIndex, owner.Generation)) status = STATUS_DEVICE_NOT_READY;
    readback = HcControlProfile(&query);
    if (NT_SUCCESS(status) && !RtlEqualMemory(&bound, &readback, sizeof(bound))) status = STATUS_DEVICE_PROTOCOL_ERROR;
    if (NT_SUCCESS(status)) {*Session = owner; *Profile = query;}
complete:
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherReadProfile(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_HC_STORE_SESSION* Session, AP6256_HC_PROFILE_CONTROL* Profile)
{
    NTSTATUS status;
    if (Session) RtlZeroMemory(Session, sizeof(*Session));
    if (Profile) RtlZeroMemory(Profile, sizeof(*Profile));
    if (!Ctx || !Session || !Profile || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    status = HcControlReadProfile(Ctx, IfIndex, Session, Profile);
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherConfirmAssociation(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, const UCHAR Station[6], const UCHAR Bssid[6], UINT32 Akm, UINT32 Mfp)
{
    AP6256_HC_STORE_SESSION session;
    AP6256_HC_PROFILE_CONTROL profile;
    AP6256_HC_ASSOCIATION_PROFILE bound;
    NTSTATUS status;
    if (!Ctx || !Station || !Bssid || !Generation || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    status = HcControlReadProfile(Ctx, IfIndex, &session, &profile);
    if (NT_SUCCESS(status) && (session.Generation != Generation || profile.Akm != Akm || profile.Mfp != Mfp ||
        !RtlEqualMemory(session.Station, Station, 6) || !RtlEqualMemory(session.Bssid, Bssid, 6)))
        status = STATUS_INVALID_DEVICE_STATE;
    if (NT_SUCCESS(status)) {
        bound = HcControlProfile(&profile);
        status = Ap6256HostCipherStoreConfirmAssociation(&Ctx->HostCipherStore, IfIndex, &session, &bound);
    }
    if (NT_SUCCESS(status) && !HcControlCurrent(Ctx, IfIndex, Generation)) status = STATUS_DEVICE_NOT_READY;
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherControlStart(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    AP6256_HC_STORE_SESSION* Session)
{
    AP6256_HC_ASSOCIATION_PROFILE profile;
    if (!Ctx || !Session || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Session, sizeof(*Session));
    (VOID)KeWaitForSingleObject(&Ctx->HostCipherControlLock, Executive, KernelMode, FALSE, NULL);
    if (InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) || Ap6256FipsActive(Ctx, IfIndex) ||
        (InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
         (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex))) ||
        !Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, Session) ||
        !Ap6256HostCipherStoreProfile(&Ctx->HostCipherStore, IfIndex, Session->Generation, TRUE, &profile)) {
        (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE); return STATUS_NOT_SUPPORTED;
    }
    HcControlBlock(Ctx, IfIndex);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherControlFinish(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, NTSTATUS Status, BOOLEAN Changed)
{
    BOOLEAN current = HcControlCurrent(Ctx, IfIndex, Generation);
    if (NT_SUCCESS(Status) && !current) Status = STATUS_DEVICE_NOT_READY;
    if ((!NT_SUCCESS(Status) && Changed) || !current) {
        Ap6256HostCipherStoreInvalidate(&Ctx->HostCipherStore, IfIndex);
        Ap6256HostCipherStoreStop(&Ctx->HostCipherStore, IfIndex);
    } else InterlockedAnd(&Ctx->HostCipherBlockedMask, (LONG)~(1u << IfIndex));
    (VOID)KeReleaseMutex(&Ctx->HostCipherControlLock, FALSE);
    return Status;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherKeyAcknowledge(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const AP6256_HC_TX_OWNER* Owner, BOOLEAN SelectDefault)
{
    AP6256_HC_KEY_CONTROL key = {0}, readback = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    if (!Owner || Owner->Slot >= AP6256_HC_SLOTS || SelectDefault > 1 ||
        (SelectDefault && (!Owner->Epoch || (Owner->Slot > 1 && Owner->Slot < 6))) ||
        !HcControlCurrent(Ctx, IfIndex, Owner->Generation)) return STATUS_INVALID_DEVICE_STATE;
    key.Abi = AP6256_HC_CONTROL_ABI; key.Bytes = sizeof(key);
    key.Generation = Owner->Generation; key.Slot = Owner->Slot; key.Epoch = Owner->Epoch;
    key.SetDefault = SelectDefault; key.DefaultSlot = SelectDefault ? Owner->Slot : 0;
    status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wdi_hc_key", &key, sizeof(key));
    if (!NT_SUCCESS(status)) return status;
    readback.Abi = key.Abi; readback.Bytes = key.Bytes; readback.Generation = key.Generation; readback.Slot = key.Slot;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_key", &readback, sizeof(readback), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(readback) ||
        readback.Abi != key.Abi || readback.Bytes != key.Bytes || readback.Generation != key.Generation ||
        readback.Slot != key.Slot || readback.Epoch != key.Epoch || readback.Reserved || readback.SetDefault > 1 ||
        (readback.SetDefault && (!readback.Epoch || (key.Slot > 1 && key.Slot < 6))) ||
        readback.DefaultSlot != (readback.SetDefault ? key.Slot : 0) ||
        (SelectDefault && !readback.SetDefault) || !HcControlCurrent(Ctx, IfIndex, key.Generation))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherKeyReady(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Generation, BOOLEAN ClosePort)
{
    AP6256_HC_AUTH_CONTROL expected = {0}, query = {0};
    AP6256_HC_TX_OWNER tx = {0}, rx = {0}, management = {0}, current = {0};
    AP6256_HC_ASSOCIATION_PROFILE profile;
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    ULONG slot;
    if (!Ctx || IfIndex >= AP6256_HC_INTERFACES || KeGetCurrentIrql() != PASSIVE_LEVEL ||
        ClosePort > 1 || !HcControlCurrent(Ctx, IfIndex, Generation) ||
        !Ap6256HostCipherStoreProfile(&Ctx->HostCipherStore, IfIndex, Generation, TRUE, &profile))
        return STATUS_INVALID_DEVICE_STATE;
    expected.Abi = AP6256_HC_CONTROL_ABI; expected.Bytes = sizeof(expected);
    expected.Generation = Generation;
    if (!ClosePort && Ap6256HostCipherStoreDefault(&Ctx->HostCipherStore,
        IfIndex, Generation, FALSE, &tx)) {
        for (slot = 0; slot < 2; ++slot) {
            if (Ap6256HostCipherStoreKeyOwner(&Ctx->HostCipherStore, IfIndex,
                Generation, slot, FALSE, &rx)) {
                if (profile.Management) {
                    ULONG managementSlot;
                    for (managementSlot = 6; managementSlot < 8; ++managementSlot)
                        if (Ap6256HostCipherStoreKeyOwner(&Ctx->HostCipherStore, IfIndex,
                            Generation, managementSlot, FALSE, &management)) break;
                    if (managementSlot == 8) break;
                }
                expected.Authorized = 1; expected.Epoch = tx.Epoch; expected.Slot = tx.Slot;
                expected.ManagementEpoch = management.Epoch; expected.ManagementSlot = management.Slot; break;
            }
        }
    }

    status = Ap6256HostCipherStoreAuthorize(&Ctx->HostCipherStore, IfIndex, Generation, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wdi_hc_auth", &expected, sizeof(expected));
    if (!NT_SUCCESS(status)) return status;
    query.Abi = expected.Abi; query.Bytes = expected.Bytes; query.Generation = Generation;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_hc_auth", &query, sizeof(query), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(query) ||
        !RtlEqualMemory(&expected, &query, sizeof(expected)) || !HcControlCurrent(Ctx, IfIndex, Generation) ||
        (expected.Authorized && (!Ap6256HostCipherStoreDefault(&Ctx->HostCipherStore, IfIndex, Generation, FALSE, &current) ||
            !RtlEqualMemory(&tx, &current, sizeof(tx)) ||
            !Ap6256HostCipherStoreTxCurrent(&Ctx->HostCipherStore, IfIndex, &tx) ||
            !Ap6256HostCipherStoreOwnerCurrent(&Ctx->HostCipherStore, IfIndex, &rx, FALSE) ||
            (profile.Management && !Ap6256HostCipherStoreOwnerCurrent(&Ctx->HostCipherStore, IfIndex, &management, FALSE)))))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return Ap6256HostCipherStoreAuthorize(&Ctx->HostCipherStore, IfIndex, Generation,
        (BOOLEAN)expected.Authorized);
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherSetDefault(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, ULONG KeyId)
{
    AP6256_HC_STORE_SESSION session;
    AP6256_HC_TX_OWNER owner;
    NTSTATUS status;
    ULONG slot = KeyId <= 1 ? KeyId : (KeyId == 4 || KeyId == 5) ? KeyId + 2 : AP6256_HC_SLOTS;
    if (slot >= AP6256_HC_SLOTS) return STATUS_NOT_SUPPORTED;
    status = Ap6256HostCipherControlStart(Ctx, IfIndex, &session);
    if (!NT_SUCCESS(status)) return status;
    if (!Ap6256HostCipherStoreKeyOwner(&Ctx->HostCipherStore, IfIndex, session.Generation, slot, TRUE, &owner))
        return Ap6256HostCipherControlFinish(Ctx, IfIndex, session.Generation, STATUS_INVALID_DEVICE_STATE, FALSE);
    status = Ap6256HostCipherKeyAcknowledge(Ctx, IfIndex, &owner, TRUE);
    if (NT_SUCCESS(status)) status = Ap6256HostCipherStoreSetDefault(&Ctx->HostCipherStore, IfIndex, &owner);
    if (NT_SUCCESS(status) && slot < 2)
        status = Ap6256HostCipherKeyReady(Ctx, IfIndex, session.Generation, FALSE);
    return Ap6256HostCipherControlFinish(Ctx, IfIndex, session.Generation, status, TRUE);
}
