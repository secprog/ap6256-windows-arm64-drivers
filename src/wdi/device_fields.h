/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

NDIS_HANDLE MiniportHandle;

ULONG WdiOsVersion;
NDIS_WDI_OPEN_ADAPTER_COMPLETE_HANDLER WdiOpenAdapterComplete;
NDIS_WDI_CLOSE_ADAPTER_COMPLETE_HANDLER WdiCloseAdapterComplete;

NDIS_WDI_DATA_API WdiDataApi;
NDIS_HANDLE WdiDataPathHandle;
NDIS_HANDLE RxNblPool;

WDI_PORT_ID TalPortId;
BOOLEAN TalPortValid;
BOOLEAN TalPeerCreated;
BOOLEAN TalRxOpen;
BOOLEAN TalPeerDeletePending;

UCHAR TalPeerAddress[6];

BOOLEAN RxPaused;
LONG TalTxRequests;
LONG TalTxPasses;

LONG TalTrace[Ap6256TraceSlotCount];

LONG TalCalls[Ap6256CallCount];

LONG TalRxFrames;
LONG TalRxPulls;
LONG TalTxFrames;
LONG TalRxEapol;
LONG TalTxEapol;

KSPIN_LOCK RxQueueLock;
PNET_BUFFER_LIST RxQueueHead;
PNET_BUFFER_LIST RxQueueTail;
ULONG RxQueueCount;

ULONGLONG StationRxGeneration;
ULONGLONG GroupRxGeneration;
BOOLEAN RxStopped;
BOOLEAN StationRxStopped;
BOOLEAN TalStarted;
UINT8 LastRssi;

CHAR LastRssiDbm;
ULONG TalPhyId;
ULONG TalChannelFreq;

KSPIN_LOCK TalStateLock;
ULONG RxIndicationsActive;
ULONG TxPassesActive;
BOOLEAN TxAborting;
BOOLEAN TxAbortConfirmNeeded;
WDI_PORT_ID TxAbortPort;
WDI_PEER_ID TxAbortPeer;

ULONG TalUpcallsActive;
BOOLEAN TalApiOpen;
KEVENT TalIdle;

UINT8 TalBssid[6];
LONG TalRxSequence;

AP6256_WORKITEM TxWorker;

volatile LONG TxPassScheduled;
volatile LONG TxPassRerun;

AP6256_TIMER RxOpenTimer;

AP6256_LOCK TxPassLock;
volatile LONG TxKeyFenceRequested;
volatile LONG TxKeyFenceCompleted;

LONG TxPaused;

volatile LONG TxEmptyDequeueCredit;
