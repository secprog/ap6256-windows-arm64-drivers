/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

static WDI_POWER_SAVE_LEVEL Ap6256PowerSaveLevel(UINT32 Mode)
{
    if (Mode == 1) return WDI_POWER_SAVE_LEVEL_MAX_PSP;
    if (Mode == 2) return WDI_POWER_SAVE_LEVEL_FAST_PSP;
    return WDI_POWER_SAVE_LEVEL_NO_POWER_SAVE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GeneratePowerSave(PAP6256_WIFI Wifi, UINT32 PortId,
                                UCHAR** Generated, ULONG* GeneratedLength)
{
    WDI_GET_AUTO_POWER_SAVE_RESULTS results = {0};
    AP6256_POWER_SAVE_STATS stats = {0};
    AP6256_POWER_SAVE_DX dx = {0};
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    UINT32 slot, ifIndex;
    NTSTATUS status;
    NDIS_STATUS generatedStatus;

    *Generated = NULL; *GeneratedLength = 0;
    if (PortId != AP6256_STATION_PORT && PortId != AP6256_GROUP_PORT)
        return STATUS_INVALID_PARAMETER;
    slot = PortId == AP6256_GROUP_PORT ? 1u : 0u;
    Ap6256LockAcquire(&Wifi->ConnectLock);
#ifdef AP6256_ENABLE_WIFICX
    Ap6256LockAcquire(&Wifi->Model.GroupLock);
#endif
    if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx ||
        (slot && (!ctx->Go.Created || !ctx->Go.FirmwareReady ||
                  ctx->Go.Stopping || ctx->Go.NativeStateUncertain))) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        ifIndex = slot ? ctx->Go.IfIndex : 0;
        dx = ctx->PowerSaveDx[slot];
        status = dx.Seen && !dx.Valid ? STATUS_DEVICE_PROTOCOL_ERROR :
            Ap6256WifiGetPowerSaveStats(ctx, ifIndex, &stats);
    }
#ifdef AP6256_ENABLE_WIFICX
    Ap6256LockRelease(&Wifi->Model.GroupLock);
#endif
    Ap6256LockRelease(&Wifi->ConnectLock);
    if (!NT_SUCCESS(status)) return status;

    results.AutoPowerSaveParameters.EnableAutoPSM = (UINT8)(stats.Mode != 0);
    results.AutoPowerSaveParameters.BeaconInterval = stats.BeaconInterval;
    results.AutoPowerSaveParameters.ListenInterval = stats.ListenInterval;
    results.AutoPowerSaveParameters.ListenIntervalInDx = dx.Seen ? dx.ListenInterval : 255;
    results.AutoPowerSaveParameters.PowerMode = Ap6256PowerSaveLevel(stats.Mode);
    results.AutoPowerSaveParameters.PowerModeinDx = Ap6256PowerSaveLevel(dx.Seen ? dx.Mode : 0);

    results.AutoPowerSaveParameters.Reason = WDI_POWER_MODE_REASON_CODE_OTHERS;
    results.AutoPowerSaveParameters.MillisecondsSinceStart = stats.MillisecondsSinceStart;
    results.AutoPowerSaveParameters.MillisecondsInPowerSave = stats.MillisecondsInPowerSave;
    results.AutoPowerSaveParameters.ReceivedMulticastPackets = stats.ReceivedMulticastPackets;
    results.AutoPowerSaveParameters.SentMulticastPackets = stats.SentMulticastPackets;
    results.AutoPowerSaveParameters.ReceivedUnicastPackets = stats.ReceivedUnicastPackets;
    results.AutoPowerSaveParameters.SentUnicastPacket = stats.SentUnicastPackets;
    generatedStatus = GenerateWdiGetAutoPowerSave(&results, 0, &Wifi->TlvContext,
                                                GeneratedLength, Generated);
    return Ap6256NdisToNtStatus(generatedStatus);
}
