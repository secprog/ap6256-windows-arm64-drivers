/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "tdls.h"
#include "bcdc.h"
#include "wifi_ops.h"

typedef struct _AP6256_TDLS_ENDPOINT {
    UCHAR Peer[6];
    UCHAR Mode;
    UCHAR Reserved0;
    UINT16 Chanspec;
    UINT16 Reserved1;
    UINT32 Reserved2;
} AP6256_TDLS_ENDPOINT;
C_ASSERT(sizeof(AP6256_TDLS_ENDPOINT) == 16);
C_ASSERT(FIELD_OFFSET(AP6256_TDLS_ENDPOINT, Chanspec) == 8);
C_ASSERT(FIELD_OFFSET(AP6256_TDLS_ENDPOINT, Reserved2) == 12);

static BOOLEAN Ap6256TdlsHasToken(const CHAR* Caps, ULONG Length)
{
    ULONG i;
    if (Caps == NULL) return FALSE;
    for (i = 0; i + 4 < Length && Caps[i] != '\0'; ++i) {
        if ((i == 0 || Caps[i - 1] == ' ') &&
            RtlEqualMemory(Caps + i, "tdls", 4) &&
            (Caps[i + 4] == ' ' || Caps[i + 4] == '\0')) return TRUE;
    }
    return FALSE;
}

static BOOLEAN Ap6256TdlsUnicast(const UCHAR* Peer)
{
    static const UCHAR zero[6] = {0};
    return (BOOLEAN)((Peer[0] & 1u) == 0 && !RtlEqualMemory(Peer, zero, 6));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256TdlsReadBool(PAP6256_DEVICE_CONTEXT Ctx, PCSTR Name, UINT32* Value)
{
    AP6256_BCDC_QUERY_RESULT reply = {0};
    UINT32 value = AP6256_TDLS_UNKNOWN;
    NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, Name, &value, sizeof(value), &reply);
    if (!NT_SUCCESS(status)) return status;
    if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength < sizeof(value) ||
        value > 1) return STATUS_DEVICE_PROTOCOL_ERROR;
    *Value = value;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256TdlsWriteBool(PAP6256_DEVICE_CONTEXT Ctx, PCSTR Name, UINT32 Value)
{
    UINT32 actual = AP6256_TDLS_UNKNOWN;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, Name, &Value, sizeof(Value));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256TdlsReadBool(Ctx, Name, &actual);
    if (NT_SUCCESS(status) && actual != Value) status = STATUS_DEVICE_PROTOCOL_ERROR;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256TdlsEventsReady(PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR mask[16] = {0};
    AP6256_BCDC_QUERY_RESULT reply = {0};
    NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs", mask, sizeof(mask), &reply);
    if (!NT_SUCCESS(status)) return status;
    if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength < sizeof(mask) ||
        (mask[BRCMF_E_TDLS_PEER_EVENT / 8] & (1u << (BRCMF_E_TDLS_PEER_EVENT & 7))) == 0)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256TdlsApply(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Mode)
{
    NTSTATUS status;
    InterlockedExchange(&Ctx->TdlsActiveMode, (LONG)AP6256_TDLS_UNKNOWN);
    status = Ap6256TdlsWriteBool(Ctx, "tdls_enable", 0);
    if (!NT_SUCCESS(status)) return status;
    InterlockedExchange(&Ctx->TdlsActiveMode, AP6256_TDLS_DISABLED);
    if (Mode == AP6256_TDLS_DISABLED) return STATUS_SUCCESS;

    status = Ap6256TdlsEventsReady(Ctx);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256TdlsWriteBool(Ctx, "tdls_auto_op", Mode == AP6256_TDLS_AUTO ? 1u : 0u);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256TdlsWriteBool(Ctx, "tdls_enable", 1);
    if (NT_SUCCESS(status)) {
        UINT32 modeReadback = AP6256_TDLS_UNKNOWN;

        status = Ap6256TdlsReadBool(Ctx, "tdls_auto_op", &modeReadback);
        if (NT_SUCCESS(status) && modeReadback != (Mode == AP6256_TDLS_AUTO ? 1u : 0u))
            status = STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&Ctx->TdlsActiveMode, (LONG)Mode);
    } else {

        InterlockedExchange(&Ctx->TdlsActiveMode, (LONG)AP6256_TDLS_UNKNOWN);
        if (NT_SUCCESS(Ap6256TdlsWriteBool(Ctx, "tdls_enable", 0)))
            InterlockedExchange(&Ctx->TdlsActiveMode, AP6256_TDLS_DISABLED);
    }
    TraceDiag("TDLS: apply mode %u -> 0x%08X, active %u\n", Mode, status,
        (UINT32)InterlockedCompareExchange(&Ctx->TdlsActiveMode, 0, 0));
    return status;
}

_Use_decl_annotations_
VOID Ap6256TdlsInitialize(PAP6256_DEVICE_CONTEXT Ctx, const CHAR* Capabilities, ULONG Length)
{
    UINT32 value;
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    Ap6256LockAcquire(&Ctx->TdlsLock);
    Ctx->FirmwareTdlsSupported = FALSE;
    Ctx->TdlsRequestedMode = AP6256_TDLS_DISABLED;
    Ctx->TdlsBlocked = FALSE;
    InterlockedExchange(&Ctx->TdlsActiveMode, AP6256_TDLS_DISABLED);
    InterlockedExchange(&Ctx->TdlsDiscoveredEvents, 0);
    InterlockedExchange(&Ctx->TdlsConnectedEvents, 0);
    InterlockedExchange(&Ctx->TdlsDisconnectedEvents, 0);
    if (Ap6256TdlsHasToken(Capabilities, Length)) {
        InterlockedExchange(&Ctx->TdlsActiveMode, (LONG)AP6256_TDLS_UNKNOWN);
        status = Ap6256TdlsReadBool(Ctx, "tdls_enable", &value);
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&Ctx->TdlsActiveMode,
                value ? (LONG)AP6256_TDLS_UNKNOWN : AP6256_TDLS_DISABLED);
            Ctx->FirmwareTdlsSupported = TRUE;
            Ctx->TdlsRequestedMode = AP6256_TDLS_AUTO;
            status = Ap6256TdlsApply(Ctx, AP6256_TDLS_AUTO);
        }
    }
    Ap6256LockRelease(&Ctx->TdlsLock);
    TraceDiag("TDLS: firmware control %u, automatic startup 0x%08X; "
        "direct-link operation requires peer/air validation\n", Ctx->FirmwareTdlsSupported, status);
}

_Use_decl_annotations_
NTSTATUS Ap6256TdlsSetBlocked(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Blocked)
{
    NTSTATUS status = STATUS_SUCCESS;
    Ap6256LockAcquire(&Ctx->TdlsLock);
    Ctx->TdlsBlocked = Blocked;
    if (Ctx->FirmwareTdlsSupported) {
        UINT32 mode = Blocked ? AP6256_TDLS_DISABLED : Ctx->TdlsRequestedMode;
        if ((UINT32)InterlockedCompareExchange(&Ctx->TdlsActiveMode, 0, 0) != mode)
            status = Ap6256TdlsApply(Ctx, mode);
    }
    Ap6256LockRelease(&Ctx->TdlsLock);
    TraceDiag("TDLS: secondary-interface exclusion %u -> 0x%08X\n", Blocked, status);
    return status;
}

static VOID Ap6256TdlsSnapshot(PAP6256_DEVICE_CONTEXT Ctx, AP6256_TDLS_STATUS* Status)
{
    Status->Version = AP6256_TDLS_VERSION;
    Status->Supported = Ctx->FirmwareTdlsSupported;
    Status->RequestedMode = Ctx->TdlsRequestedMode;
    Status->ActiveMode = (UINT32)InterlockedCompareExchange(&Ctx->TdlsActiveMode, 0, 0);
    Status->Blocked = Ctx->TdlsBlocked;
    Status->DiscoveredEvents = (UINT32)InterlockedCompareExchange(&Ctx->TdlsDiscoveredEvents, 0, 0);
    Status->ConnectedEvents = (UINT32)InterlockedCompareExchange(&Ctx->TdlsConnectedEvents, 0, 0);
    Status->DisconnectedEvents = (UINT32)InterlockedCompareExchange(&Ctx->TdlsDisconnectedEvents, 0, 0);
}

_Use_decl_annotations_
NTSTATUS Ap6256TdlsControl(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Request,
    ULONG Length, AP6256_TDLS_STATUS* Status)
{
    AP6256_TDLS_REQUEST request;
    UINT32 activeMode;
    NTSTATUS status = STATUS_SUCCESS;
    static const UCHAR zero[6] = {0};
    RtlZeroMemory(Status, sizeof(*Status));
    if (Length != sizeof(request)) return STATUS_INVALID_BUFFER_SIZE;
    RtlCopyMemory(&request, Request, sizeof(request));
    if (request.Magic != AP6256_TDLS_MAGIC) return STATUS_NOT_SUPPORTED;
    if (request.Version != AP6256_TDLS_VERSION || request.Reserved != 0 ||
        request.Operation > AP6256_TDLS_TEARDOWN) return STATUS_INVALID_PARAMETER;
    if (request.Operation <= AP6256_TDLS_ON_AUTO) {
        if (!RtlEqualMemory(request.Peer, zero, 6)) return STATUS_INVALID_PARAMETER;
    } else if (!Ap6256TdlsUnicast(request.Peer) ||
        RtlEqualMemory(request.Peer, Ctx->MacAddress, 6)) return STATUS_INVALID_PARAMETER;

    Ap6256LockAcquire(&Ctx->TdlsLock);
    activeMode = (UINT32)InterlockedCompareExchange(&Ctx->TdlsActiveMode, 0, 0);
    if (request.Operation != AP6256_TDLS_QUERY) {
        if (!Ctx->FirmwareTdlsSupported) status = STATUS_NOT_SUPPORTED;
        else if (Ctx->FirmwareState != Ap6256FwRunning || !Ctx->DatapathRunning)
            status = STATUS_DEVICE_NOT_READY;
        else if (request.Operation <= AP6256_TDLS_ON_AUTO) {
            UINT32 mode = request.Operation - AP6256_TDLS_OFF;
            if ((Ctx->TdlsBlocked || Ctx->Go.FirmwareReady) && mode != AP6256_TDLS_DISABLED)
                status = STATUS_DEVICE_BUSY;
            else {
                status = Ap6256TdlsApply(Ctx, mode);
                if (NT_SUCCESS(status)) Ctx->TdlsRequestedMode = mode;
            }
        } else if (Ctx->TdlsBlocked || Ctx->Go.FirmwareReady) status = STATUS_DEVICE_BUSY;
        else if (!Ctx->FirmwareLinkUp ||
            (activeMode != AP6256_TDLS_MANUAL && activeMode != AP6256_TDLS_AUTO))
            status = STATUS_DEVICE_NOT_READY;
        else {
            UCHAR bssid[6];
            AP6256_TDLS_ENDPOINT endpoint = {0};
            status = Ap6256WifiGetBssid(Ctx, bssid);
            if (NT_SUCCESS(status) && RtlEqualMemory(bssid, request.Peer, 6))
                status = STATUS_INVALID_PARAMETER;
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(endpoint.Peer, request.Peer, 6);
                endpoint.Mode = request.Operation == AP6256_TDLS_DISCOVER ? 6u :
                    request.Operation == AP6256_TDLS_SETUP ? 1u : 3u;
                status = Ap6256BcdcSetIovar(Ctx, "tdls_endpoint", &endpoint, sizeof(endpoint));

                TraceDiag("TDLS: endpoint mode %u -> 0x%08X\n", (ULONG)endpoint.Mode, status);
            }
        }
    }
    Ap6256TdlsSnapshot(Ctx, Status);
    Ap6256LockRelease(&Ctx->TdlsLock);
    return status;
}

_Use_decl_annotations_
VOID Ap6256TdlsPeerEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 Status, UINT32 Reason, const UCHAR* Peer)
{
    if (IfIndex != 0 || Status != BRCMF_E_STATUS_SUCCESS || Reason > 2 ||
        !Ctx->FirmwareTdlsSupported || !Ap6256TdlsUnicast(Peer) ||
        RtlEqualMemory(Peer, Ctx->MacAddress, 6)) return;
    if (Reason == 0) InterlockedIncrement(&Ctx->TdlsDiscoveredEvents);
    else if (Reason == 1) InterlockedIncrement(&Ctx->TdlsConnectedEvents);
    else InterlockedIncrement(&Ctx->TdlsDisconnectedEvents);
    TraceDiag("TDLS: peer %02X:%02X:%02X:%02X:%02X:%02X %s\n",
        Peer[0], Peer[1], Peer[2], Peer[3], Peer[4], Peer[5],
        Reason == 0 ? "discovered" : Reason == 1 ? "connected" : "disconnected");
}
