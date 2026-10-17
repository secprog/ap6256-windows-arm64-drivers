/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "association_failure.h"

#define AP6256_SAE_QUEUE_DEPTH 8u
typedef struct _AP6256_SAE_EVENT {
    LONG Generation;
    UINT32 FirmwareGeneration;
    UINT32 Type, Status;
    UCHAR Peer[6];
    ULONG Length;
    UCHAR Body[AP6256_SAE_FRAME_MAX + 16];
} AP6256_SAE_EVENT;

typedef struct _AP6256_AUTH_STATE {
    AP6256_FT_STATE Ft;
    AP6256_FT_EVENT* FtEvents[2];
    ULONG FtHead, FtTail;
    BOOLEAN FtEventsLost;
    AP6256_FT_OWNER FtLostOwner;
    AP6256_TIMER_OBJ SaeTimer;
    AP6256_SAE Sae;
    AP6256_SAE_EVENT SaeQueue[AP6256_SAE_QUEUE_DEPTH];
    ULONG SaeHead, SaeTail;
    LONG SaeGeneration, SaeLostGeneration;
    UCHAR SaeSsid[32];
    ULONG SaeSsidLength;
    BOOLEAN SaeFirmwareReleased;
    UINT32 SaeFirmwareGeneration, SaeFirmwareCounter;
    UINT32 SaeEventGeneration;
    UINT32 HostCipherGeneration;
    UCHAR SaeFirmwarePeer[6];
    BOOLEAN SaeNeedsAbort;
    LONGLONG SaeCachedDeadlineMs;
    AP6256_ASSOC_FAILURE AssocFailure;
    BOOLEAN AssocComebackPending;
} AP6256_AUTH_STATE;
