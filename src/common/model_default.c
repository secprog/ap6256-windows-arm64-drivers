/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "model.h"
#include "netadapter.h"
#include "wifi_ops.h"
#include "hotspot.h"
#include "sae_fw.h"
#include "ft_fw.h"

VOID Ap6256ModelRecordFirmwareCrash(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

NTSTATUS Ap6256ModelPrepareConcurrent(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    NTSTATUS status = STATUS_SUCCESS;

    return status;
}

BOOLEAN Ap6256ModelRouteGroupEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                                   UINT32 eventType, UINT32 status, const UCHAR* eventBody,
                                   ULONG eventBodyLen)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(evt);
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(eventBody);
    UNREFERENCED_PARAMETER(eventBodyLen);

    return FALSE;
}

VOID Ap6256ModelAssociationEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                                 UINT32 eventType, const UCHAR* eventBody, ULONG eventBodyLen)
{

    Ap6256NetApAssociationRequest(
        Ctx, evt->Address,
        (BOOLEAN)(eventType == BRCMF_E_REASSOC_IND || eventType == BRCMF_E_PRE_REASSOC_IND),
        eventBody, eventBodyLen);
}

VOID Ap6256ModelDfsStopEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                             UINT32 eventType, UINT32 status, const UCHAR* eventBody,
                             ULONG eventBodyLen)
{
    UNREFERENCED_PARAMETER(evt);
    UNREFERENCED_PARAMETER(eventType);
    UNREFERENCED_PARAMETER(status);
    UNREFERENCED_PARAMETER(eventBody);
    UNREFERENCED_PARAMETER(eventBodyLen);
    Ap6256NetApStopped(Ctx, AP6256_AP_STOP_FREQUENCY_NOT_AVAILABLE);
}

VOID Ap6256ModelWlfcAbortProgress(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}
