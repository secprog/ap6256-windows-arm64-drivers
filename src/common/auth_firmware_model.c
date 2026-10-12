/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "model.h"
#include "netadapter.h"
#include "sae_fw.h"
#include "ft_fw.h"

BOOLEAN Ap6256ModelRouteAuthEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
                                  UINT32 eventType, UINT32 status, const UCHAR* eventBody,
                                  ULONG eventBodyLen)
{

    if (eventType == BRCMF_E_AUTH && RtlUlongByteSwap(evt->Reason) == AP6256_SAE_PRIVATE_MAGIC) {
        if (status == 0 && Ctx->FirmwarePrivateSae && evt->IfIdx == 0 && evt->BssCfgIdx == 0 &&
            RtlUlongByteSwap(evt->AuthType) == 3)
            Ap6256NetSaePrivateEvent(Ctx, evt->Address, eventBody, eventBodyLen);
        return TRUE;
    }
    if (eventType == BRCMF_E_AUTH && RtlUlongByteSwap(evt->Reason) == AP6256_FT_EVENT_MAGIC) {
        if (status == 0 && Ctx->FirmwareHostFt && evt->IfIdx == 0 && evt->BssCfgIdx == 0 &&
            RtlUlongByteSwap(evt->AuthType) == 2)
            Ap6256NetFtEvent(Ctx, evt->Address, eventBody, eventBodyLen);
        return TRUE;
    }
    return FALSE;
}
