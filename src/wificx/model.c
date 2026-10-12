/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "model.h"
#include "../common/netadapter.h"
#include "wifi_ops.h"
#include "hotspot.h"
#include "sae_fw.h"
#include "ft_fw.h"

NTSTATUS Ap6256ModelPrepareConcurrent(PAP6256_DEVICE_CONTEXT Ctx)
{

    NTSTATUS status = STATUS_SUCCESS;
    if (Ctx->FirmwareP2pSupported) {
        NTSTATUS goStatus = Ap6256GoPrepare(Ctx);
        if (!NT_SUCCESS(goStatus)) {
            Ctx->FirmwareP2pSupported = FALSE;

            status = Ap6256WifiRadioUpDown(Ctx, TRUE);
            if (!NT_SUCCESS(status))
                return status;
        }
        TraceDiag("hotspot: concurrent firmware mode %s (0x%08X)\n",
                  Ctx->FirmwareP2pSupported ? "ready" : "unavailable", goStatus);
    }
    return status;
}

BOOLEAN Ap6256ModelRouteGroupEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                                   UINT32 eventType, UINT32 status, const UCHAR* eventBody,
                                   ULONG eventBodyLen)
{

    if (eventType != BRCMF_E_IF && eventType != BRCMF_E_ESCAN_RESULT &&
        eventType != BRCMF_E_ACTION_FRAME_RX && eventType != BRCMF_E_ACTION_FRAME_COMPLETE &&
        eventType != BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE &&
        eventType != BRCMF_E_P2P_DISC_LISTEN_COMPLETE && (evt->IfIdx != 0 || evt->BssCfgIdx != 0)) {
        if (Ctx->Go.FirmwareReady && evt->BssCfgIdx == Ctx->Go.BssIndex) {
            Ap6256NetGoEvent(Ctx, eventType, status, RtlUlongByteSwap(evt->Reason),
                             RtlUshortByteSwap(evt->Flags), evt->Address, eventBody, eventBodyLen);
        }
        return TRUE;
    }
    return FALSE;
}

VOID Ap6256ModelAssociationEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                                 UINT32 eventType, const UCHAR* eventBody, ULONG eventBodyLen)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(evt);
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(eventBody);
    UNREFERENCED_PARAMETER(eventBodyLen);
}

VOID Ap6256ModelDfsStopEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                             UINT32 eventType, UINT32 status, const UCHAR* eventBody,
                             ULONG eventBodyLen)
{

    Ap6256NetGoEvent(Ctx, eventType, status, RtlUlongByteSwap(evt->Reason),
                     RtlUshortByteSwap(evt->Flags), evt->Address, eventBody, eventBodyLen);
}

VOID Ap6256ModelWlfcAbortProgress(PAP6256_DEVICE_CONTEXT Ctx) { UNREFERENCED_PARAMETER(Ctx); }

VOID Ap6256ModelRecordFirmwareCrash(PAP6256_DEVICE_CONTEXT Ctx) { UNREFERENCED_PARAMETER(Ctx); }
