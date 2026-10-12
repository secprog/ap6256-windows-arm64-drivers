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

#define AP6256_CX_TX_QUEUES ((AP6256_GO_PEERS * 8u) + 1u)
#define AP6256_CX_STA_TX_QUEUES ((2u * 8u) + 1u)

#define AP6256_CX_NATIVE_FRAME_MAX (AP6256_FIPS_MAX_MPDU_BYTES + AP6256_FIPS_TX_HEADER_BYTES)
typedef struct _AP6256_CX_ADAPTER AP6256_CX_ADAPTER, *PAP6256_CX_ADAPTER;
typedef struct _AP6256_FRAME {
    ULONG Length;
    UCHAR Priority, Exemption, HostCipher;
    UINT16 Peer;
    LONG Generation;
    ULONGLONG PeerGeneration;
    UINT32 FipsGeneration;
    UCHAR Data[AP6256_CX_NATIVE_FRAME_MAX];
} AP6256_FRAME, *PAP6256_FRAME;

typedef struct _AP6256_QUEUE_CONTEXT {
    PAP6256_WIFI Wifi;
    PAP6256_CX_ADAPTER Role;
    NETPACKETQUEUE Queue;
    NET_EXTENSION VirtualAddress, ExemptionAction;
    BOOLEAN IsTx;
    UCHAR Priority;
    UCHAR PeerAddress[6];
    EX_RUNDOWN_REF Rundown;
    volatile LONG Closing, NotificationEnabled, TxRunning, TxEnabled, TxWakePending, Started;
    BOOLEAN RundownClosed;
    WDFWORKITEM TxWorkItem;
    KSPIN_LOCK TxLock;
    AP6256_FRAME TxPending[AP6256_TXQ_DEPTH];
    ULONG TxHead, TxTail;
} AP6256_QUEUE_CONTEXT, *PAP6256_QUEUE_CONTEXT;

struct _AP6256_CX_ADAPTER {
    PAP6256_WIFI Wifi;
    NETADAPTER Adapter;
    UINT16 PortId, LogicalPort;
    EX_RUNDOWN_REF Rundown;
    volatile LONG Closing, Ready, Generation, DataEnabled;
    KSPIN_LOCK QueueLock;
    PAP6256_QUEUE_CONTEXT TxQueues[AP6256_CX_TX_QUEUES];
    PAP6256_QUEUE_CONTEXT RxQueue;
    KSPIN_LOCK RxLock;
    AP6256_FRAME RxPending[AP6256_RXQ_DEPTH];
    ULONG RxHead, RxTail;
    volatile LONG RxSequence;
    BOOLEAN FirmwareCreated, Registered;
};

typedef struct _AP6256_MODEL_STATE {
    NETADAPTER Adapter;
    WDFOBJECT Object;
    AP6256_LOCK AdapterLock;
    KSPIN_LOCK RoleLock;
    PAP6256_CX_ADAPTER Roles[2];
    BOOLEAN StationPeerCreated;
    UCHAR StationPeerAddress[6];
    ULONG StationPeerPhy;
    ULONGLONG StationPeerGeneration;
    AP6256_LOCK GroupLock, PeerLock;
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
