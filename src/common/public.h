/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include <initguid.h>

DEFINE_GUID(GUID_DEVINTERFACE_AP6256,
    0x7b9a6e2c, 0x43ac, 0x4d56, 0x9f, 0x1b, 0xa9, 0xbf, 0x02, 0xd0, 0x62, 0x56);

#define AP6256_IOCTL_BASE   0x8000

#define IOCTL_AP6256_GET_CHIP_INFO \
    CTL_CODE(FILE_DEVICE_NETWORK, AP6256_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AP6256_GET_MAC \
    CTL_CODE(FILE_DEVICE_NETWORK, AP6256_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_READ_ACCESS)
#define IOCTL_AP6256_GET_FW_STATE \
    CTL_CODE(FILE_DEVICE_NETWORK, AP6256_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_READ_ACCESS)

#pragma pack(push, 1)
typedef struct _AP6256_CHIP_INFO {
    UINT32 ChipId;
    UINT32 ChipRev;
    UINT32 RamBase;
    UINT32 RamSize;
    UINT32 CoreCount;
    UINT32 FirmwareState;
    CHAR   Name[12];
} AP6256_CHIP_INFO, *PAP6256_CHIP_INFO;
#pragma pack(pop)
