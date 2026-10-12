/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

#define AP6256_P2P_VENDOR_IE_MAX 512u

BOOLEAN Ap6256P2pVendorIesValid(const UCHAR* Ies, ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pProbeOffloadInterfaces(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pPulseListen(PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_P2P_DISCOVER_SCAN_ONLY    1u
#define AP6256_P2P_DISCOVER_FIND_ONLY    2u
#define AP6256_P2P_DISCOVER_AUTO         3u
#define AP6256_P2P_DISCOVER_SOCIAL_ONLY  4u

typedef enum _AP6256_P2P_DISCOVER_PHASE {
    Ap6256P2pDiscoverIdle = 0,
    Ap6256P2pDiscoverScan,
    Ap6256P2pDiscoverListen,
    Ap6256P2pDiscoverSearch,
    Ap6256P2pDiscoverNextChannel,
    Ap6256P2pDiscoverRepeat
} AP6256_P2P_DISCOVER_PHASE;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pStartDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_P2P_DISCOVER* Discover);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pStopDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pResetDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ BOOLEAN SetDefaultMib);

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG Ap6256P2pAdvanceDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_P2P_ACTION_HEADER     8u

#define AP6256_P2P_AF_GO_NEG_REQ     0u
#define AP6256_P2P_AF_GO_NEG_RSP     1u
#define AP6256_P2P_AF_GO_NEG_CONF    2u
#define AP6256_P2P_AF_INVITE_REQ     3u
#define AP6256_P2P_AF_INVITE_RSP     4u
#define AP6256_P2P_AF_DEV_DISC_REQ   5u
#define AP6256_P2P_AF_DEV_DISC_RSP   6u
#define AP6256_P2P_AF_PROV_DISC_REQ  7u
#define AP6256_P2P_AF_PROV_DISC_RSP  8u

typedef struct _AP6256_P2P_ACTION_FRAME {
    UCHAR   Subtype;
    UCHAR   DialogToken;
    UCHAR   PeerAddress[6];
    UINT32  DwellMs;
    UINT32  TransmitChannel;

    UCHAR   GoIntentByte;
    UINT16  GoConfigTimeoutMs;
    UINT16  ClientConfigTimeoutMs;
    UCHAR   IntendedInterface[6];
    UCHAR   GroupCapability;
    BOOLEAN HaveIntendedInterface;

    UCHAR   Status;
    BOOLEAN HaveStatus;

    UCHAR   InvitationFlags;
    BOOLEAN HaveInvitationFlags;
    BOOLEAN HaveGroupBssid;
    UCHAR   GroupBssid[6];

    BOOLEAN HaveGroupId;
    UCHAR   GroupDeviceAddress[6];
    UCHAR   GroupSsid[32];
    ULONG   GroupSsidLength;

    BOOLEAN HaveOperatingChannel;
    UCHAR   OperatingClass;
    UCHAR   OperatingChannel;

    const UCHAR* PeerIes;
    ULONG   PeerIesLength;
    ULONG   DisallowedBands;

    const UCHAR* VendorIes;
    ULONG   VendorIesLength;
} AP6256_P2P_ACTION_FRAME, *PAP6256_P2P_ACTION_FRAME;

typedef struct _AP6256_P2P_CHANNEL_PLAN {
    ULONG Count;
    UCHAR Channels[64];
    UCHAR Classes[64];
    UCHAR OperatingClass;
    UCHAR OperatingChannel;
} AP6256_P2P_CHANNEL_PLAN;

typedef struct _AP6256_P2P_PEER_INFO {
    BOOLEAN HaveStatus;
    BOOLEAN HaveIntent;
    BOOLEAN HaveChannelList;
    BOOLEAN HaveOperatingChannel;
    UCHAR Status;
    UCHAR Intent;
    UCHAR OperatingClass;
    UCHAR OperatingChannel;
    UCHAR ListenChannel;
    UCHAR GroupSsidLength;
    UCHAR ChannelClasses[166];
} AP6256_P2P_PEER_INFO;

BOOLEAN Ap6256P2pParsePeerIes(_In_reads_bytes_opt_(Length) const UCHAR* Ies,
    _In_ ULONG Length, _Out_ AP6256_P2P_PEER_INFO* Peer);

UCHAR Ap6256P2pChannelClass(_In_ UINT32 Channel);

VOID Ap6256P2pTraceAction(_In_ BOOLEAN Transmit, _In_ UCHAR Subtype,
    _In_ UCHAR Token, _In_ UINT32 Channel,
    _In_reads_bytes_opt_(Length) const UCHAR* Ies, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pGetChannelPlan(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ ULONG DisallowedBands, _Out_ AP6256_P2P_CHANNEL_PLAN* Plan);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildActionFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ const AP6256_P2P_ACTION_FRAME* Frame,
                                   _Outptr_result_bytebuffer_(*Length)
                                       PUCHAR* Body,
                                   _Out_ PULONG Length,
                                   _Out_writes_(6) PUCHAR Bssid,
                                   _Out_ PUINT32 Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pInitialize(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pSetCountry(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_reads_(2) const CHAR* Code);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256P2pIsSocialChannel(_In_ UINT32 Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pReleaseIes(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetHostIes(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ AP6256_P2P_FRAME Frame,
                             _In_reads_bytes_opt_(Length) const UCHAR* Ies,
                             _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildIes(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetListenState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 State,
                                 _In_ UINT32 ActiveMs,
                                 _In_ UINT32 CycleMs,
                                 _In_ UINT32 Channel);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pReleaseIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pForgetIesFor(AP6256_P2P_STATE* p2p);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetHostIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex, AP6256_P2P_FRAME Frame, const UCHAR* Ies, ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex);
