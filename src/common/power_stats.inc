/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

static UINT32 Ap6256PowerRead32(const UCHAR* p)
{
    return (UINT32)p[0] | ((UINT32)p[1] << 8) |
           ((UINT32)p[2] << 16) | ((UINT32)p[3] << 24);
}

static ULONGLONG Ap6256PowerRead64(const UCHAR* p)
{
    return Ap6256PowerRead32(p) | ((ULONGLONG)Ap6256PowerRead32(p + 4) << 32);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPowerSaveStats(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
                                    PAP6256_POWER_SAVE_STATS Stats)
{
    UCHAR reply[AP6256_POWER_STATS_BYTES] = {0};
    AP6256_BCDC_QUERY_RESULT result = {0};
    UINT32 mode, beacon, dtim, bcnListen, dtimListen, listen, beaconMs;
    NTSTATUS status;

    RtlZeroMemory(Stats, sizeof(*Stats));
    if (!Ctx->FirmwareFtmPatchVerified) return STATUS_NOT_SUPPORTED;
    if (Ctx->FirmwareHalted) return STATUS_DEVICE_HARDWARE_ERROR;
    status = Ap6256BcdcGetIovarResultIf(Ctx, IfIndex, "wdi_power_stats",
                                      reply, sizeof(reply), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(reply) ||
        Ap6256PowerRead32(reply) != AP6256_POWER_STATS_ABI ||
        Ap6256PowerRead32(reply + 4) != sizeof(reply) ||
        Ap6256PowerRead32(reply + 8) != AP6256_POWER_STATS_SHARED_TIME_SCOPED_TRAFFIC)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    mode = Ap6256PowerRead32(reply + 12);
    beacon = Ap6256PowerRead32(reply + 16);
    dtim = Ap6256PowerRead32(reply + 20);
    bcnListen = Ap6256PowerRead32(reply + 24);
    dtimListen = Ap6256PowerRead32(reply + 28);
    if (mode > 2 || beacon > 65535 || dtim > 255 ||
        bcnListen > 255 || dtimListen > 255) return STATUS_DEVICE_PROTOCOL_ERROR;
    beaconMs = (beacon * 1024u) / 1000u;

    if (mode == 0) listen = 1;
    else if (dtimListen == 1 || (!bcnListen && !dtimListen)) listen = dtim;
    else if (!bcnListen) listen = dtim * dtimListen;
    else if (!dtimListen) listen = bcnListen;
    else return STATUS_NOT_SUPPORTED;

    if (beaconMs > 65535 || listen > 255) return STATUS_INTEGER_OVERFLOW;
    if (Ap6256PowerRead64(reply + 40) > Ap6256PowerRead64(reply + 32))
        return STATUS_DEVICE_PROTOCOL_ERROR;
    Stats->Mode = mode;
    Stats->BeaconInterval = (UINT16)beaconMs;
    Stats->ListenInterval = (UCHAR)listen;
    Stats->MillisecondsSinceStart = Ap6256PowerRead64(reply + 32);
    Stats->MillisecondsInPowerSave = Ap6256PowerRead64(reply + 40);
    Stats->ReceivedMulticastPackets = Ap6256PowerRead64(reply + 48);
    Stats->SentMulticastPackets = Ap6256PowerRead64(reply + 56);
    Stats->ReceivedUnicastPackets = Ap6256PowerRead64(reply + 64);
    Stats->SentUnicastPackets = Ap6256PowerRead64(reply + 72);
    return STATUS_SUCCESS;
}

static VOID Ap6256PowerCaptureDx(PAP6256_DEVICE_CONTEXT Ctx, AP6256_POWER_SAVE_DX* Pending)
{
    AP6256_POWER_SAVE_STATS stats;
    UINT32 slot;
    RtlZeroMemory(Pending, sizeof(*Pending) * 2);
    for (slot = 0; slot < 2; ++slot) {
        if (slot && (!Ctx->Go.FirmwareReady || Ctx->Go.NativeStateUncertain)) continue;
        Pending[slot].Seen = TRUE;
        Pending[slot].Valid = (BOOLEAN)NT_SUCCESS(Ap6256WifiGetPowerSaveStats(
            Ctx, slot ? Ctx->Go.IfIndex : 0, &stats));

        if (Pending[slot].Valid && stats.ListenInterval == 255) Pending[slot].Valid = FALSE;
        if (Pending[slot].Valid) {
            Pending[slot].Mode = stats.Mode;
            Pending[slot].ListenInterval = stats.ListenInterval;
        }
    }
}
