/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#define AP6256_GO_EVENT_DEPTH 32u
#define AP6256_GO_EVENT_MAX 4096u
typedef struct _AP6256_GO_EVENT {
    UINT32 Type, Status, Reason;
    UINT16 Flags;
    UCHAR Address[6];
    ULONG Generation, Length;
    UCHAR Data[1];
} AP6256_GO_EVENT;
typedef struct _AP6256_MODEL_STATE {

    AP6256_LOCK GroupLock;
    AP6256_TIMER_OBJ ClientConnectTimer;
    AP6256_WDI_TASK ClientConnectTask;
    volatile LONG GroupGeneration;
    AP6256_CONNECT_PARAMS ClientCandidates[AP6256_CONNECT_BSSID_LIMIT];
    ULONG ClientCandidateCount;
    ULONG ClientCandidateIndex;
    AP6256_TIMER_OBJ ApAssocTimer;
    WDI_PHY_TYPE ApAssocPhy;
    BOOLEAN ApAssocAccept;
    AP6256_GO_EVENT* GoEvents[AP6256_GO_EVENT_DEPTH];
    ULONG GoEventHead, GoEventTail, GoEventGeneration;
    BOOLEAN GoEventsLost, GoNativeAssociation;
    ULONGLONG GoAssocToken;
    AP6256_GO_AUTO_ASSOC* GoAutoAssoc[AP6256_GO_PEERS - 1];
} AP6256_MODEL_STATE;
