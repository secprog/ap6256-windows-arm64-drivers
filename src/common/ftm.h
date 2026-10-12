/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"
#define AP6256_FTM_TARGET_MAX 4u
#define AP6256_FTM_REPLY_MAX 1024u
#define AP6256_FTM_LCI_MAX 252u
#define AP6256_FTM_ABI 0x00010301u
typedef struct _AP6256_FTM_RESULT {
    UINT16 Session, State, Measurements;
    INT32 Status, Rssi, RttPs;
    UINT32 RateSpec;
    UINT64 VariancePs;
    BOOLEAN VariancePresent;
} AP6256_FTM_RESULT;
NTSTATUS Ap6256FtmBuildCommand(UINT16 Command, UINT16 Session, UINT16 Chanspec,
    const UCHAR* Peer, ULONG TimeoutMs, UCHAR* Buffer, ULONG Capacity, PULONG Length);
NTSTATUS Ap6256FtmDecodeStatus(const UCHAR* Buffer, ULONG Length, UINT16 Session,
    UINT16* State, INT32* Status);
NTSTATUS Ap6256FtmDecodeResult(const UCHAR* Buffer, ULONG Length, UINT16 Session,
    const UCHAR* Peer, AP6256_FTM_RESULT* Result);
NTSTATUS Ap6256FtmValidateBeacon(const UCHAR* Frame, ULONG Length);
