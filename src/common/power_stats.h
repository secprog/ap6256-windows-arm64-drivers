/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#define AP6256_POWER_STATS_ABI 0x31535041u
#define AP6256_POWER_STATS_BYTES 80u
#define AP6256_POWER_STATS_SHARED_TIME_SCOPED_TRAFFIC 3u

typedef struct _AP6256_POWER_SAVE_STATS {
    UINT32 Mode;
    UINT16 BeaconInterval;
    UCHAR ListenInterval;
    UCHAR Reserved;
    ULONGLONG MillisecondsSinceStart;
    ULONGLONG MillisecondsInPowerSave;
    ULONGLONG ReceivedMulticastPackets;
    ULONGLONG SentMulticastPackets;
    ULONGLONG ReceivedUnicastPackets;
    ULONGLONG SentUnicastPackets;
} AP6256_POWER_SAVE_STATS, *PAP6256_POWER_SAVE_STATS;

typedef struct _AP6256_POWER_SAVE_DX {
    BOOLEAN Seen;
    BOOLEAN Valid;
    UCHAR ListenInterval;
    UCHAR Reserved;
    UINT32 Mode;
} AP6256_POWER_SAVE_DX;
