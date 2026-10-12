/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ft.h"

#define AP6256_FT_FW_VERSION 1u
#define AP6256_FT_FW_HEADER 40u
#define AP6256_FT_FW_INITIAL 1u
#define AP6256_FT_FW_AUTHENTICATE 2u
#define AP6256_FT_FW_RESUME 3u
#define AP6256_FT_FW_CANCEL 4u
#define AP6256_FT_FW_COMPLETE 5u
#define AP6256_FT_EVENT_MAGIC 0x31544648u
#define AP6256_FT_FW_AUTH_MAX 768u

typedef struct _AP6256_FT_EVENT {
    AP6256_FT_OWNER Owner;
    ULONG RequestLength, ResponseLength;
    UCHAR Bodies[2 * AP6256_FT_FW_AUTH_MAX];
} AP6256_FT_EVENT;

BOOLEAN Ap6256FtDecodeEvent(const UCHAR* Data, ULONG Length,
    AP6256_FT_EVENT* Event);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFirmwareQualify(PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFirmwareBegin(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner, BOOLEAN Reassociation,
    const UCHAR* Mde, ULONG MdeLength, const UCHAR* Fte, ULONG FteLength,
    const UCHAR* PmkR0Name, ULONG PmkLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFirmwareResume(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner, const UCHAR* Rsn, ULONG RsnLength,
    const UCHAR* Mde, ULONG MdeLength, const UCHAR* Fte, ULONG FteLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFirmwareCancel(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFirmwareComplete(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_FT_OWNER* Owner);
