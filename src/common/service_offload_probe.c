/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "p2p.h"
#include "bcdc.h"
#include "trace.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256P2pProbeOffloadGetter(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PCSTR Name, _In_ UINT32 Maximum)
{
    AP6256_BCDC_QUERY_RESULT result = {0};

    UINT32 value = 0;
    NTSTATUS status;
    BOOLEAN verified;

    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, Name, &value, sizeof(value), &result);
    verified = (BOOLEAN)(NT_SUCCESS(status) && result.FirmwareReply &&
        !result.FirmwareError && result.FirmwareStatus == 0 &&
        result.PayloadLength == sizeof(value) && value <= Maximum);
    TraceDiag("offload interface GET %s: status 0x%08X reply %u error %u "
        "fw-status %ld bytes %u value %u verified %u; capabilities disabled\n",
        Name, status, (ULONG)result.FirmwareReply, (ULONG)result.FirmwareError,
        result.FirmwareStatus, result.PayloadLength, value, (ULONG)verified);
    return verified;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pProbeOffloadInterfaces(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    (VOID)Ap6256P2pProbeOffloadGetter(Ctx, "p2po_state", 2u);
    (VOID)Ap6256P2pProbeOffloadGetter(Ctx, "anqpo_auto_hotspot", MAXUSHORT);
}
