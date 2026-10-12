/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "model.h"

BOOLEAN Ap6256ModelRouteAuthEvent(PAP6256_DEVICE_CONTEXT Ctx, const BRCMF_EVENT_MSG* evt,
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
