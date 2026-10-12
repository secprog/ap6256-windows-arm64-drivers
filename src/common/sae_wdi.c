/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "sae_wdi.h"
#include <netmodel.h>
#include <TlvGeneratorParser.hpp>

C_ASSERT((UINT32)Ap6256SaeNeedCommit == (UINT32)WDI_SAE_INDICATION_TYPE_COMMIT_REQUEST_PARAMS_NEEDED);
C_ASSERT((UINT32)Ap6256SaePeerCommit == (UINT32)WDI_SAE_INDICATION_TYPE_COMMIT_FRAME);
C_ASSERT((UINT32)Ap6256SaePeerConfirm == (UINT32)WDI_SAE_INDICATION_TYPE_CONFIRM_FRAME);
C_ASSERT((UINT32)Ap6256SaeError == (UINT32)WDI_SAE_INDICATION_TYPE_ERROR);
C_ASSERT((UINT32)Ap6256SaeNeedNewConfirm == (UINT32)WDI_SAE_INDICATION_TYPE_CONFIRM_REQUEST_RESEND_REQUEST);

_Use_decl_annotations_
NTSTATUS Ap6256SaeCopyPmkid(BOOLEAN Present, const UCHAR* Bytes, ULONG Length,
    UCHAR* Pmkid, BOOLEAN* Valid)
{
    RtlZeroMemory(Pmkid, 16);
    *Valid = FALSE;
    if (!Present) return STATUS_SUCCESS;
    if (Bytes == NULL || Length != 16) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(Pmkid, Bytes, 16);
    *Valid = TRUE;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeCopyCachedH2e(const struct _WDI_CONNECT_BSS_ENTRY_CONTAINER* Candidate,
    const UCHAR* CommonIes, ULONG CommonLength, BOOLEAN* H2e)
{
    BOOLEAN commonPresent, commonH2e, extraPresent = FALSE, extraH2e = FALSE;
    BOOLEAN beaconPresent = FALSE, beaconH2e = FALSE;
    BOOLEAN probePresent = FALSE, probeH2e = FALSE;
    NTSTATUS status;
    *H2e = FALSE;
    status = Ap6256SaeReadRsnxe(CommonIes, CommonLength, &commonPresent, &commonH2e);
    if (!NT_SUCCESS(status)) return status;
    if (Candidate->Optional.AssociationRequestVendorIE_IsPresent) {
        status = Ap6256SaeReadRsnxe(Candidate->AssociationRequestVendorIE.pElements,
            Candidate->AssociationRequestVendorIE.ElementCount, &extraPresent, &extraH2e);
        if (!NT_SUCCESS(status)) return status;
    }
    if (commonPresent && extraPresent && commonH2e != extraH2e)
        return STATUS_INVALID_PARAMETER;
    if (Candidate->Optional.BeaconFrame_IsPresent && Candidate->BeaconFrame.ElementCount) {
        if (Candidate->BeaconFrame.pElements == NULL || Candidate->BeaconFrame.ElementCount < 12)
            return STATUS_INVALID_PARAMETER;
        status = Ap6256SaeReadRsnxe(Candidate->BeaconFrame.pElements + 12,
            Candidate->BeaconFrame.ElementCount - 12, &beaconPresent, &beaconH2e);
        if (!NT_SUCCESS(status)) return status;
    }
    if (Candidate->Optional.ProbeResponseFrame_IsPresent && Candidate->ProbeResponseFrame.ElementCount) {
        if (Candidate->ProbeResponseFrame.pElements == NULL || Candidate->ProbeResponseFrame.ElementCount < 12)
            return STATUS_INVALID_PARAMETER;
        status = Ap6256SaeReadRsnxe(Candidate->ProbeResponseFrame.pElements + 12,
            Candidate->ProbeResponseFrame.ElementCount - 12, &probePresent, &probeH2e);
        if (!NT_SUCCESS(status)) return status;
    }
    if (beaconPresent && probePresent && beaconH2e != probeH2e)
        return STATUS_INVALID_PARAMETER;

    *H2e = extraPresent ? extraH2e : commonPresent ? commonH2e :
        (BOOLEAN)(beaconH2e || probeH2e);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeApplyWdi(AP6256_SAE* Sae, LONG Generation, LONGLONG NowMs,
    const UCHAR* Tlv, ULONG Length, const struct _TLV_CONTEXT* Codec,
    AP6256_SAE_OUTPUT* Output)
{
    WDI_SET_SAE_AUTH_PARAMS_COMMAND p = {0};
    AP6256_SAE_COMMIT commit = {0};
    NTSTATUS status;
    RtlZeroMemory(Output, sizeof(*Output));
    Output->Notice = Ap6256SaeNoNotice;
    if (Codec->PeerVersion < WDI_VERSION_1_1_10) return STATUS_NOT_SUPPORTED;
    status = (NTSTATUS)ParseWdiSetSaeAuthParamsToIhv(Length, Tlv, Codec, &p);
    if (!NT_SUCCESS(status)) goto Done;
    switch (p.SAERequestType) {
    case WDI_SAE_REQUEST_TYPE_COMMIT_PARAMS:
    case WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS:
        if (!p.Optional.SAECommitParams_IsPresent ||
            !p.SAECommitParams.Optional.Scalar_IsPresent ||
            !p.SAECommitParams.Optional.Element_IsPresent ||
            p.Optional.SAEConfirmParams_IsPresent || p.Optional.SAEStatus_IsPresent) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        commit.Group = p.SAECommitParams.FiniteCyclicGroup;
        commit.H2e = (BOOLEAN)(p.SAERequestType == WDI_SAE_REQUEST_TYPE_COMMIT_H2E_PARAMS);
        commit.Scalar.Data = p.SAECommitParams.Scalar.pElements;
        commit.Scalar.Length = p.SAECommitParams.Scalar.ElementCount;
        commit.Element.Data = p.SAECommitParams.Element.pElements;
        commit.Element.Length = p.SAECommitParams.Element.ElementCount;
        if (p.SAECommitParams.Optional.AntiCloggingToken_IsPresent) {
            commit.Token.Data = p.SAECommitParams.AntiCloggingToken.pElements;
            commit.Token.Length = p.SAECommitParams.AntiCloggingToken.ElementCount;
        }
        if (p.SAECommitParams.Optional.RejectedGroups_IsPresent) {
            commit.RejectedGroups.Data = p.SAECommitParams.RejectedGroups.pElements;
            commit.RejectedGroups.Length = p.SAECommitParams.RejectedGroups.ElementCount;
        }
        status = Ap6256SaeCommit(Sae, Generation, p.BssId.Address, NowMs, &commit, Output);
        break;
    case WDI_SAE_REQUEST_TYPE_CONFIRM_PARAMS:
        if (!p.Optional.SAEConfirmParams_IsPresent ||
            p.Optional.SAECommitParams_IsPresent || p.Optional.SAEStatus_IsPresent) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = Ap6256SaeConfirm(Sae, Generation, p.BssId.Address, NowMs,
            p.SAEConfirmParams.SendConfirm, p.SAEConfirmParams.Confirm.pElements,
            p.SAEConfirmParams.Confirm.ElementCount, Output);
        break;
    case WDI_SAE_REQUEST_TYPE_SUCCESS:
    case WDI_SAE_REQUEST_TYPE_FAILURE:
        TraceDiag("SAE: Windows verdict request %s; status present %u value %u\n",
            p.SAERequestType == WDI_SAE_REQUEST_TYPE_SUCCESS ? "SUCCESS" : "FAILURE",
            p.Optional.SAEStatus_IsPresent,
            p.Optional.SAEStatus_IsPresent ? (UINT32)p.SAEStatus : MAXULONG);
        if (p.Optional.SAECommitParams_IsPresent || p.Optional.SAEConfirmParams_IsPresent ||
            (p.SAERequestType == WDI_SAE_REQUEST_TYPE_SUCCESS &&
             (!p.Optional.SAEStatus_IsPresent || p.SAEStatus != WDI_SAE_STATUS_SUCCESS))) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        status = Ap6256SaeFinish(Sae, Generation, p.BssId.Address, NowMs,
            (BOOLEAN)(p.SAERequestType == WDI_SAE_REQUEST_TYPE_SUCCESS),
            p.Optional.SAEStatus_IsPresent ? p.SAEStatus : WDI_SAE_STATUS_FAILURE, Output);
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        break;
    }
Done:
    CleanupParsedWdiSetSaeAuthParamsToIhv(&p);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256SaeEncodeWdi(const AP6256_SAE* Sae, const AP6256_SAE_OUTPUT* Output,
    const struct _TLV_CONTEXT* Codec, UCHAR** Bytes, ULONG* Length)
{
    WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED_PARAMETERS p = {0};
    NTSTATUS status;
    *Bytes = NULL;
    *Length = 0;
    if (Codec->PeerVersion < WDI_VERSION_1_1_10) return STATUS_NOT_SUPPORTED;
    if (Output->Notice > Ap6256SaeNeedNewConfirm) return STATUS_NOT_FOUND;
    RtlCopyMemory(p.BssId.Address, Sae->Peer, 6);
    p.SAEIndicationType = (WDI_SAE_INDICATION_TYPE)Output->Notice;
    if (Output->Notice == Ap6256SaePeerCommit || Output->Notice == Ap6256SaePeerConfirm) {
        if (Output->RxLength < 30 || Output->RxLength > sizeof(Output->RxFrame))
            return STATUS_INVALID_PARAMETER;
        if (Output->Notice == Ap6256SaePeerCommit) {
            p.Optional.SAECommitFrame_IsPresent = TRUE;

            p.SAECommitFrame.pElements = (UCHAR*)Output->RxFrame + 24;
            p.SAECommitFrame.ElementCount = Output->RxLength - 24;
        } else {
            p.Optional.SAEConfirmFrame_IsPresent = TRUE;
            p.SAEConfirmFrame.pElements = (UCHAR*)Output->RxFrame + 24;
            p.SAEConfirmFrame.ElementCount = Output->RxLength - 24;
        }
    } else if (Output->Notice == Ap6256SaeError) {
        p.Optional.SAEStatus_IsPresent = TRUE;
        p.SAEStatus = (WDI_SAE_STATUS)Output->Status;
    }
    status = (NTSTATUS)GenerateWdiIndicationSaeAuthParamsNeededFromIhv(
        &p, 0, Codec, Length, Bytes);
    if (!NT_SUCCESS(status)) {
        FreeGenerated(*Bytes);
        *Bytes = NULL;
        *Length = 0;
    }
    return status;
}
