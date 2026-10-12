/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

VOID Ap6256StationSaeCancel(PAP6256_WIFI Wifi)
{
    KIRQL irql;
    NTSTATUS privateStatus = STATUS_SUCCESS;
    BOOLEAN privateOwner = (BOOLEAN)(Wifi->Auth.SaeFirmwareGeneration != 0);
    AP6256_TIMER_STOP(Wifi->Auth.SaeTimer, FALSE);
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    Wifi->Auth.SaeGeneration = 0;
    if (!Wifi->Auth.SaeFirmwareReleased) Wifi->Auth.SaeEventGeneration = 0;
    Wifi->Auth.SaeTail = Wifi->Auth.SaeHead;
    Wifi->Auth.SaeLostGeneration = 0;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);
    if (privateOwner) {
        privateStatus = Wifi->HardwareAvailable && !Wifi->Stopping
            ? Ap6256SaePrivateEnd(Wifi->Ctx, Wifi->Auth.SaeFirmwareGeneration,
                Wifi->Auth.SaeFirmwarePeer, FALSE) : STATUS_DEVICE_NOT_READY;
        KeAcquireSpinLock(&Wifi->CommandLock, &irql);
        Wifi->Auth.SaeNeedsAbort = (BOOLEAN)!NT_SUCCESS(privateStatus);
        if (NT_SUCCESS(privateStatus)) {
            Wifi->Auth.SaeFirmwareGeneration = 0;
            RtlZeroMemory(Wifi->Auth.SaeFirmwarePeer, sizeof(Wifi->Auth.SaeFirmwarePeer));
        }
        KeReleaseSpinLock(&Wifi->CommandLock, irql);
    } else if (!Wifi->Auth.SaeFirmwareReleased && Wifi->HardwareAvailable && !Wifi->Stopping) {
        if (Wifi->Auth.SaeCachedDeadlineMs)
            (VOID)Ap6256WifiDisconnect(Wifi->Ctx);
        else if (Wifi->Auth.Sae.State != Ap6256SaeIdle)
            (VOID)Ap6256SaeAuthStatus(Wifi->Ctx, Wifi->Auth.Sae.Peer,
                Wifi->Auth.SaeSsid, Wifi->Auth.SaeSsidLength, FALSE);
    }
    Ap6256SaeReset(&Wifi->Auth.Sae);
    Wifi->Auth.SaeFirmwareReleased = FALSE;
    Wifi->Auth.SaeCachedDeadlineMs = 0;
}

NTSTATUS Ap6256StationSaeComplete(PAP6256_WIFI Wifi)
{
    NTSTATUS status = STATUS_SUCCESS;
    KIRQL irql;
    if (Wifi->Auth.SaeFirmwareGeneration) {
        status = Ap6256SaePrivateEnd(Wifi->Ctx, Wifi->Auth.SaeFirmwareGeneration,
            Wifi->Auth.SaeFirmwarePeer, TRUE);
        if (!NT_SUCCESS(status)) return status;
        KeAcquireSpinLock(&Wifi->CommandLock, &irql);
        Wifi->Auth.SaeFirmwareGeneration = 0;
        Wifi->Auth.SaeNeedsAbort = FALSE;
        RtlZeroMemory(Wifi->Auth.SaeFirmwarePeer, sizeof(Wifi->Auth.SaeFirmwarePeer));
        KeReleaseSpinLock(&Wifi->CommandLock, irql);
    }
    Wifi->Auth.SaeFirmwareReleased = TRUE;
    AP6256_TIMER_STOP(Wifi->Auth.SaeTimer, FALSE);
    return status;
}

static BOOLEAN Ap6256StationSaeFallback(PAP6256_WIFI Wifi)
{
    AP6256_CONNECT_PARAMS* candidate;
    if (Wifi->ConnectCandidateIndex >= Wifi->ConnectCandidateCount) return FALSE;
    candidate = &Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex];
    if (candidate->Security != Ap6256SecuritySaeHost || !candidate->PmkidValid)
        return FALSE;
    candidate->PmkidValid = FALSE;
    candidate->SaeCachedH2e = FALSE;
    RtlZeroMemory(candidate->Pmkid, sizeof(candidate->Pmkid));
    TraceDiag("SAE: cached PMKID failed; retrying the same BSS with full SAE\n");
    return TRUE;
}

static BOOLEAN Ap6256StationSaeLive(PAP6256_WIFI Wifi, LONG Generation)
{
    return Generation != 0 && Generation == Wifi->ConnectGeneration &&
        Generation == Wifi->Auth.SaeGeneration && Wifi->ConnectTask.Active &&
        !Wifi->ConnectDeparting && !Wifi->Stopping && Wifi->HardwareAvailable &&
        Wifi->ConnectCandidateIndex < Wifi->ConnectCandidateCount &&
        Wifi->ConnectCandidates[Wifi->ConnectCandidateIndex].Security == Ap6256SecuritySaeHost;
}

static NTSTATUS Ap6256StationSaeNotice(PAP6256_WIFI Wifi, const AP6256_SAE_OUTPUT* Output)
{
    UCHAR* bytes = NULL;
    ULONG length = 0;
    NTSTATUS status;
    if (Output->Notice == Ap6256SaeNoNotice) return STATUS_SUCCESS;
    status = Ap6256SaeEncodeWdi(&Wifi->Auth.Sae, Output, &Wifi->TlvContext, &bytes, &length);
    if (NT_SUCCESS(status) && (Output->Notice == Ap6256SaePeerCommit ||
                              Output->Notice == Ap6256SaePeerConfirm)) {
        UINT16 auth[3];
        RtlCopyMemory(auth, Output->RxFrame + 24, sizeof(auth));
        TraceDiag("SAE: peer %s to Windows; frame %u body %u bytes, "
            "algorithm %u transaction %u status %u\n",
            Output->Notice == Ap6256SaePeerCommit ? "Commit" : "Confirm",
            Output->RxLength, Output->RxLength - 24, auth[0], auth[1], auth[2]);
    }
    if (NT_SUCCESS(status)) status = Ap6256SendGeneratedIndication(Wifi,
        WDI_INDICATION_SAE_AUTH_PARAMS_NEEDED, &Wifi->ConnectTask.Header,
        WDI_TRANSACTION_ID_UNSOLICIT, Wifi->ConnectTask.RequestId, bytes, length);
    FreeGenerated(bytes);
    return status;
}

static VOID Ap6256StationSaeFailed(PAP6256_WIFI Wifi, UINT32 Reason)
{
    AP6256_SAE_OUTPUT output;
    LONG generation = Wifi->Auth.SaeGeneration;
    if (!Ap6256StationSaeLive(Wifi, generation)) return;
    if (Wifi->Auth.Sae.State != Ap6256SaeIdle) {
        RtlZeroMemory(&output, sizeof(output));
        output.Notice = Ap6256SaeError;
        output.Status = Reason;
        (VOID)Ap6256StationSaeNotice(Wifi, &output);
    }
    TraceDiag("SAE: authentication failed, reason %u generation %ld\n", Reason, generation);
    Ap6256StationSaeCancel(Wifi);

    Ap6256NetStationLinkEvent(Wifi->Ctx, FALSE, TRUE, Wifi->ConnectBssid);
}

static NTSTATUS Ap6256StationSaeOutput(PAP6256_WIFI Wifi, const AP6256_SAE_OUTPUT* Output)
{
    NTSTATUS status = STATUS_SUCCESS;
    if (Output->TxLength) {
        if (Wifi->Auth.SaeFirmwareGeneration)
            status = Ap6256SaePrivateCommand(Wifi->Ctx, AP6256_SAE_PRIVATE_TX,
                Wifi->Auth.SaeFirmwareGeneration, Wifi->Auth.SaeFirmwarePeer,
                Output->TxBody, Output->TxLength);
        else status = Ap6256SaeSendAuth(Wifi->Ctx,
            (UINT16)Wifi->ConnectChannel, Wifi->Auth.Sae.Peer, Output->PacketId,
            Output->TxBody, Output->TxLength);
    }

    if (NT_SUCCESS(status)) status = Ap6256StationSaeNotice(Wifi, Output);
    if (NT_SUCCESS(status) && Wifi->Auth.Sae.State != Ap6256SaeAccepted &&
        Wifi->Auth.Sae.State != Ap6256SaeFailed && Wifi->Auth.Sae.State != Ap6256SaeIdle)
        AP6256_TIMER_START(Wifi->Auth.SaeTimer, (ULONG)max(1ll,
            Wifi->Auth.Sae.RetryAtMs - Ap6256InterruptTimeMs()));
    return status;
}

static NTSTATUS Ap6256StationSaeArm(PAP6256_WIFI Wifi, AP6256_CONNECT_PARAMS* Parameters)
{
    KIRQL irql;
    UINT32 firmwareGeneration = 0;
    Parameters->SaeFirmwareGeneration = 0;
    Parameters->SaeTimeoutMs = 0;
    if (Wifi->Ctx->FirmwarePrivateSae) {
        AP6256_SAE_PRIVATE_STATE state;
        NTSTATUS status = Ap6256SaePrivateQuery(Wifi->Ctx, &state);
        LONGLONG remaining = Wifi->ConnectTask.DeadlineMs - Ap6256InterruptTimeMs();
        if (!NT_SUCCESS(status)) return status;
        if (state.Phase != AP6256_SAE_PRIVATE_IDLE || Wifi->Auth.SaeNeedsAbort)
            return STATUS_DEVICE_BUSY;
        if (!(state.Features & AP6256_SAE_PRIVATE_FEATURE)) return STATUS_NOT_SUPPORTED;
        Wifi->Auth.SaeFirmwareCounter = max(Wifi->Auth.SaeFirmwareCounter, state.Generation);
        if (Wifi->Auth.SaeFirmwareCounter == MAXULONG) return STATUS_INTEGER_OVERFLOW;
        if (remaining <= 0) return STATUS_IO_TIMEOUT;
        firmwareGeneration = ++Wifi->Auth.SaeFirmwareCounter;
        Parameters->SaeFirmwareGeneration = firmwareGeneration;
        Parameters->SaeTimeoutMs = (UINT32)min(30000ll, max(1000ll, remaining));
    }
    RtlCopyMemory(Wifi->Auth.SaeSsid, Parameters->Ssid, Parameters->SsidLength);
    Wifi->Auth.SaeSsidLength = Parameters->SsidLength;
    Wifi->Auth.SaeFirmwareReleased = FALSE;
    KeAcquireSpinLock(&Wifi->CommandLock, &irql);
    Wifi->Auth.SaeFirmwareGeneration = firmwareGeneration;
    Wifi->Auth.SaeEventGeneration = firmwareGeneration;
    if (firmwareGeneration) RtlCopyMemory(Wifi->Auth.SaeFirmwarePeer, Parameters->Bssid, 6);
    Wifi->Auth.SaeGeneration = Wifi->ConnectGeneration;
    KeReleaseSpinLock(&Wifi->CommandLock, irql);

    if (Parameters->PmkidValid) {

        Wifi->Auth.SaeCachedDeadlineMs = min(Wifi->ConnectTask.DeadlineMs,
            Ap6256InterruptTimeMs() + 2000ll);
        AP6256_TIMER_START(Wifi->Auth.SaeTimer, (ULONG)max(1ll,
            Wifi->Auth.SaeCachedDeadlineMs - Ap6256InterruptTimeMs()));
    } else if (firmwareGeneration) AP6256_TIMER_START(Wifi->Auth.SaeTimer, 50);
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID Ap6256NetSaePrivateEvent(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Peer,
    const UCHAR* Body, ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    UINT32 generation;
    ULONG frameLength;
    KIRQL irql;
    BOOLEAN queued = FALSE;
    if (wifi == NULL || !Ctx->FirmwarePrivateSae ||
        !Ap6256SaePrivateFrame(Body, Length, Ctx->MacAddress, Peer, &generation, &frameLength))
        return;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (generation == wifi->Auth.SaeFirmwareGeneration && wifi->Auth.SaeGeneration &&
        !wifi->Stopping && wifi->HardwareAvailable &&
        RtlEqualMemory(Peer, wifi->Auth.SaeFirmwarePeer, 6)) {
        if ((ULONG)(wifi->Auth.SaeHead - wifi->Auth.SaeTail) < AP6256_SAE_QUEUE_DEPTH) {
            AP6256_SAE_EVENT* event = &wifi->Auth.SaeQueue[wifi->Auth.SaeHead++ % AP6256_SAE_QUEUE_DEPTH];
            event->Generation = wifi->Auth.SaeGeneration;
            event->FirmwareGeneration = generation;
            event->Type = AP6256_SAE_PRIVATE_MAGIC; event->Status = 0;
            event->Length = frameLength;
            RtlCopyMemory(event->Peer, Peer, 6);
            RtlCopyMemory(event->Body, Body + 12, frameLength);
        } else wifi->Auth.SaeLostGeneration = wifi->Auth.SaeGeneration;
        queued = TRUE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (queued) AP6256_CMDQ_KICK(wifi);
}

_Use_decl_annotations_
VOID Ap6256NetSaeEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
    UINT32 Status, const UCHAR* Peer, const UCHAR* Body, ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    KIRQL irql;
    BOOLEAN queued = FALSE;
    if (wifi == NULL || Length > AP6256_SAE_FRAME_MAX + 16 ||
        EventType < AP6256_CYW_EXT_AUTH_REQ || EventType > AP6256_CYW_MGMT_OFFCHAN_DONE)
        return;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (wifi->Auth.SaeGeneration && !wifi->Auth.SaeFirmwareGeneration &&
        !wifi->Stopping && wifi->HardwareAvailable) {
        if ((ULONG)(wifi->Auth.SaeHead - wifi->Auth.SaeTail) < AP6256_SAE_QUEUE_DEPTH) {
            AP6256_SAE_EVENT* event = &wifi->Auth.SaeQueue[wifi->Auth.SaeHead++ % AP6256_SAE_QUEUE_DEPTH];
            event->Generation = wifi->Auth.SaeGeneration;
            event->FirmwareGeneration = 0;
            event->Type = EventType; event->Status = Status; event->Length = Length;
            RtlCopyMemory(event->Peer, Peer, 6);
            if (Length) RtlCopyMemory(event->Body, Body, Length);
        } else wifi->Auth.SaeLostGeneration = wifi->Auth.SaeGeneration;
        queued = TRUE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (queued) AP6256_CMDQ_KICK(wifi);
}

VOID Ap6256StationSaeTimer(PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    KIRQL irql;
    BOOLEAN queued = FALSE;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (wifi->Auth.SaeGeneration && !wifi->Stopping && wifi->HardwareAvailable) {
        if ((ULONG)(wifi->Auth.SaeHead - wifi->Auth.SaeTail) < AP6256_SAE_QUEUE_DEPTH) {
            AP6256_SAE_EVENT* event = &wifi->Auth.SaeQueue[wifi->Auth.SaeHead++ % AP6256_SAE_QUEUE_DEPTH];
            event->Generation = wifi->Auth.SaeGeneration;
            event->FirmwareGeneration = wifi->Auth.SaeFirmwareGeneration;
            event->Type = 0; event->Status = 0; event->Length = 0;
        } else wifi->Auth.SaeLostGeneration = wifi->Auth.SaeGeneration;
        queued = TRUE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (queued) AP6256_CMDQ_KICK(wifi);
}

static VOID Ap6256StationSaeEvent(PAP6256_WIFI Wifi, const AP6256_SAE_EVENT* Event)
{
    AP6256_SAE_OUTPUT output = {0};
    NTSTATUS status = STATUS_NOT_FOUND;
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (!Ap6256StationSaeLive(Wifi, Event->Generation)) goto Done;
    if (Event->FirmwareGeneration != Wifi->Auth.SaeFirmwareGeneration) goto Done;
    if (Ap6256InterruptTimeMs() >= Wifi->ConnectTask.DeadlineMs) {
        Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
        goto Done;
    }
    if (Wifi->Auth.SaeCachedDeadlineMs) {
        if (Event->Type == 0) {
            if (Ap6256InterruptTimeMs() >= Wifi->Auth.SaeCachedDeadlineMs)
                Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
            else AP6256_TIMER_START(Wifi->Auth.SaeTimer, (ULONG)max(1ll,
                Wifi->Auth.SaeCachedDeadlineMs - Ap6256InterruptTimeMs()));
        } else if (Event->Type == AP6256_CYW_EXT_AUTH_REQ) {
            BOOLEAN abort;
            status = Ap6256SaeAuthRequest(Event->Body, Event->Length,
                Wifi->ConnectBssid, Wifi->Auth.SaeSsid, Wifi->Auth.SaeSsidLength, &abort);
            if (NT_SUCCESS(status)) Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
        }
        goto Done;
    }
    if (Wifi->Auth.SaeFirmwareGeneration) {
        if (Event->Type != 0 && Event->Type != AP6256_SAE_PRIVATE_MAGIC) goto Done;
        if (Wifi->Auth.Sae.State == Ap6256SaeIdle) {
            AP6256_SAE_PRIVATE_STATE state;
            status = Ap6256SaePrivateQuery(Wifi->Ctx, &state);
            if (!NT_SUCCESS(status) || state.Generation != Wifi->Auth.SaeFirmwareGeneration ||
                (state.Phase != AP6256_SAE_PRIVATE_ARMED && state.Phase != AP6256_SAE_PRIVATE_HELD)) {
                Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
                goto Done;
            }
            if (state.Phase == AP6256_SAE_PRIVATE_ARMED) {
                AP6256_TIMER_START(Wifi->Auth.SaeTimer, 50);
                goto Done;
            }
            status = Ap6256SaeBegin(&Wifi->Auth.Sae, Wifi->Ctx->MacAddress,
                Wifi->ConnectBssid, Event->Generation, Ap6256InterruptTimeMs(),
                Wifi->ConnectTask.DeadlineMs, &output);
            if (!NT_SUCCESS(status) || !NT_SUCCESS(Ap6256StationSaeOutput(Wifi, &output))) {
                Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
                goto Done;
            }
            if (Event->Type == 0) goto Done;
        }
        if (Event->Type == AP6256_SAE_PRIVATE_MAGIC)
            status = Ap6256SaeReceive(&Wifi->Auth.Sae, Event->Generation,
                Ap6256InterruptTimeMs(), Event->Body, Event->Length, &output);
        else status = Ap6256SaeTimeout(&Wifi->Auth.Sae, Event->Generation,
            Ap6256InterruptTimeMs(), &output);
    } else
    if (Event->Type == AP6256_CYW_EXT_AUTH_REQ) {
        BOOLEAN abort;
        status = Ap6256SaeAuthRequest(Event->Body, Event->Length,
            Wifi->ConnectBssid, Wifi->Auth.SaeSsid, Wifi->Auth.SaeSsidLength, &abort);
        if (!NT_SUCCESS(status)) goto Done;
        if (abort || Event->Status != 0) {
            Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
            goto Done;
        }
        if (Wifi->Auth.Sae.State != Ap6256SaeIdle) goto Done;
        status = Ap6256SaeBegin(&Wifi->Auth.Sae, Wifi->Ctx->MacAddress,
            Wifi->ConnectBssid, Event->Generation, Ap6256InterruptTimeMs(),
            Wifi->ConnectTask.DeadlineMs, &output);
    } else if (Event->Type == AP6256_CYW_EXT_AUTH_RX && Event->Status == 0) {
        status = Ap6256SaeReceiveEvent(&Wifi->Auth.Sae, Event->Generation,
            Ap6256InterruptTimeMs(), Event->Peer, Event->Body, Event->Length, &output);
    } else if (Event->Type == AP6256_CYW_MGMT_TX_STATUS && Event->Length >= 4) {
        UINT32 packetId;
        RtlCopyMemory(&packetId, Event->Body, sizeof(packetId));
        status = Ap6256SaeTxStatus(&Wifi->Auth.Sae, Event->Generation,
            packetId, (BOOLEAN)(Event->Status == 0), &output);
    } else if (Event->Type == 0) {
        status = Ap6256SaeTimeout(&Wifi->Auth.Sae, Event->Generation,
            Ap6256InterruptTimeMs(), &output);
    } else goto Done;
    if (output.Notice == Ap6256SaeError) {
        Ap6256StationSaeFailed(Wifi, output.Status);
    } else if (NT_SUCCESS(status) && !NT_SUCCESS(Ap6256StationSaeOutput(Wifi, &output))) {
        Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
    }
Done:
    Ap6256LockRelease(&Wifi->ConnectLock);
}

VOID Ap6256HandleSaeParameters(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
    PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength, LONG generation)
{
    AP6256_SAE_OUTPUT output;
    NTSTATUS status = STATUS_INVALID_DEVICE_STATE;
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (Header->PortId != AP6256_STATION_PORT ||
        !Ap6256StationSaeLive(Wifi, generation) || Wifi->Auth.Sae.State == Ap6256SaeIdle)
        goto Done;
    status = Ap6256SaeApplyWdi(&Wifi->Auth.Sae, generation, Ap6256InterruptTimeMs(),
        Tlv, TlvLength, &Wifi->TlvContext, &output);
    if (output.Notice == Ap6256SaeError) {
        Ap6256StationSaeFailed(Wifi, output.Status);

        status = STATUS_SUCCESS;
    } else if (NT_SUCCESS(status)) {
        status = Ap6256StationSaeOutput(Wifi, &output);
        if (NT_SUCCESS(status) && Wifi->Auth.Sae.State == Ap6256SaeAccepted) {
            TraceDiag("SAE: Windows verdict SUCCESS; releasing firmware session %u\n",
                Wifi->Auth.SaeFirmwareGeneration);
            AP6256_TIMER_STOP(Wifi->Auth.SaeTimer, FALSE);
            if (Wifi->Auth.SaeFirmwareGeneration)
                status = Ap6256SaePrivateCommand(Wifi->Ctx, AP6256_SAE_PRIVATE_ACCEPT,
                    Wifi->Auth.SaeFirmwareGeneration, Wifi->Auth.SaeFirmwarePeer, NULL, 0);
            else status = Ap6256SaeAuthStatus(Wifi->Ctx, Wifi->Auth.Sae.Peer,
                Wifi->Auth.SaeSsid, Wifi->Auth.SaeSsidLength, TRUE);
            if (NT_SUCCESS(status)) {
                Wifi->Auth.SaeFirmwareReleased = TRUE;
                TraceDiag("SAE: Windows accepted Confirm; firmware association resumed\n");
            }
        }
        if (!NT_SUCCESS(status)) Ap6256StationSaeFailed(Wifi, WDI_SAE_STATUS_FAILURE);
    }
Done:
    Ap6256LockRelease(&Wifi->ConnectLock);
    Ap6256CompleteRequest(Wifi, Request, status);
}
