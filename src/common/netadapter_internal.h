/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "netadapter.h"
#include "datapath.h"
#include "firmware.h"
#include "wifi_ops.h"
#include "hotspot.h"
#include "bcdc.h"
#include "tdls.h"
#include "pno.h"
#include "native_mgmt.h"
#include "sae_fw.h"
#include "sae_wdi.h"
#include "ft_fw.h"
#include "owe.h"
#include "wlfc.h"
#include "p2p.h"
#include "service_offload.h"
#include "mbo.h"
#include "ftm.h"
#include "ftm_firmware.h"
#include "host_fips.h"
#include "host_cipher_keys.h"
#include "host_cipher_control.h"
#include "host_cipher_rsn.h"
#include "host_cipher_event.h"
#include <netmodel.h>
#include <TlvGeneratorParser.hpp>

static inline NTSTATUS Ap6256CopyFipsCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* Bss,
    AP6256_CONNECT_PARAMS* Params)
{
    NTSTATUS status;
    if (!Params->HostFips) return STATUS_SUCCESS;
    if (Params->FastTransition || Params->Mfp != Ap6256MfpNone) return STATUS_NOT_SUPPORTED;
    status = Ap6256FipsCheckVendorIes(Params->AssociationVendorIes, Params->AssociationVendorIesLength);
    if (!NT_SUCCESS(status)) return status;
    if (Bss->Optional.AssociationRequestVendorIE_IsPresent) {
        status = Ap6256FipsCheckVendorIes(Bss->AssociationRequestVendorIE.pElements,
            Bss->AssociationRequestVendorIE.ElementCount);
        if (!NT_SUCCESS(status)) return status;
    }
    return Ap6256FipsCandidateHt(
        Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.pElements : NULL,
        Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.ElementCount : 0,
        Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.pElements : NULL,
        Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.ElementCount : 0,
        Bss->BSSID.Address, &Params->HostFipsHt);
}

static inline BOOLEAN Ap6256HostCipherRequestSuite(const WDI_CONNECT_PARAMETERS_CONTAINER* Params,
    UINT32 Akm)
{
    const UINT32 selector = 0x00ac0f00u | (Akm << 24);
    ULONG i;
    BOOLEAN present;
    if (Params->Optional.RsnaAkmSuites_IsPresent) {
        present = FALSE;
        if (!Params->RsnaAkmSuites.pElements) return FALSE;
        for (i = 0; i < Params->RsnaAkmSuites.ElementCount; ++i)
            if ((UINT32)Params->RsnaAkmSuites.pElements[i] == selector) present = TRUE;
        if (!present) return FALSE;
    }
    if (Params->Optional.RsnaAkmCipherSuites_IsPresent) {
        present = FALSE;
        if (!Params->RsnaAkmCipherSuites.pElements) return FALSE;
        for (i = 0; i < Params->RsnaAkmCipherSuites.ElementCount; ++i)
            if ((UINT32)Params->RsnaAkmCipherSuites.pElements[i].akm == selector &&
                (UINT32)Params->RsnaAkmCipherSuites.pElements[i].cipher == 0x09ac0f00u) present = TRUE;
        if (!present) return FALSE;
    }
    return TRUE;
}

static inline NTSTATUS Ap6256CopyHostCipherCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* Bss,
    AP6256_CONNECT_PARAMS* Params)
{
    const UCHAR* frames[2];
    ULONG lengths[2], i;
    AP6256_HC_RSN rsn;
    if (!Params->HostCipher) return STATUS_SUCCESS;
    if (Params->FastTransition || Params->HostFips) return STATUS_NOT_SUPPORTED;
    frames[0] = Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.pElements : NULL;
    frames[1] = Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.pElements : NULL;
    lengths[0] = Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.ElementCount : 0;
    lengths[1] = Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.ElementCount : 0;
    for (i = 0; i < 2; ++i) {
        if ((i ? Bss->Optional.ProbeResponseFrame_IsPresent : Bss->Optional.BeaconFrame_IsPresent) &&
            (!frames[i] || lengths[i] < 12 ||
             !Ap6256HostCipherRsnRead(frames[i] + 12, lengths[i] - 12, &rsn) ||
             !Ap6256HostCipherRsnMatch(&rsn, Params->HostCipherAkm, (UINT32)Params->Mfp, 0)))
            return STATUS_NOT_SUPPORTED;
    }

    return STATUS_SUCCESS;
}

static inline BOOLEAN Ap6256Wpa3EnterpriseRequestSuite(const WDI_CONNECT_PARAMETERS_CONTAINER* Params)
{
    ULONG i;
    BOOLEAN present;
    if (Params->Optional.RsnaAkmSuites_IsPresent) {
        present = FALSE;
        if (!Params->RsnaAkmSuites.pElements) return FALSE;
        for (i = 0; i < Params->RsnaAkmSuites.ElementCount; ++i)
            if ((UINT32)Params->RsnaAkmSuites.pElements[i] == 0x05ac0f00u) present = TRUE;
        if (!present) return FALSE;
    }
    if (Params->Optional.RsnaAkmCipherSuites_IsPresent) {
        present = FALSE;
        if (!Params->RsnaAkmCipherSuites.pElements) return FALSE;
        for (i = 0; i < Params->RsnaAkmCipherSuites.ElementCount; ++i)
            if ((UINT32)Params->RsnaAkmCipherSuites.pElements[i].akm == 0x05ac0f00u &&
                (UINT32)Params->RsnaAkmCipherSuites.pElements[i].cipher == 0x04ac0f00u) present = TRUE;
        if (!present) return FALSE;
    }
    return TRUE;
}

static inline NTSTATUS Ap6256CopyWpa3EnterpriseCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* Bss,
    AP6256_CONNECT_PARAMS* Params)
{
    const UCHAR* frames[2];
    ULONG lengths[2], i;
    AP6256_HC_RSN rsn;
    if (!Params->Wpa3Enterprise) return STATUS_SUCCESS;
    if (Params->FastTransition || Params->HostFips || Params->HostCipher) return STATUS_NOT_SUPPORTED;
    frames[0] = Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.pElements : NULL;
    frames[1] = Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.pElements : NULL;
    lengths[0] = Bss->Optional.BeaconFrame_IsPresent ? Bss->BeaconFrame.ElementCount : 0;
    lengths[1] = Bss->Optional.ProbeResponseFrame_IsPresent ? Bss->ProbeResponseFrame.ElementCount : 0;
    for (i = 0; i < 2; ++i)
        if ((i ? Bss->Optional.ProbeResponseFrame_IsPresent : Bss->Optional.BeaconFrame_IsPresent) &&
            (!frames[i] || lengths[i] < 12 ||
             !Ap6256HostCipherRsnRead(frames[i] + 12, lengths[i] - 12, &rsn) ||
             !Ap6256Wpa3EnterpriseRsnMatch(&rsn, 0))) return STATUS_NOT_SUPPORTED;
    return Ap6256SaeCopyPmkid((BOOLEAN)(Bss->Optional.PMKID_IsPresent != 0),
        Bss->Optional.PMKID_IsPresent ? Bss->PMKID.pElements : NULL,
        Bss->Optional.PMKID_IsPresent ? Bss->PMKID.ElementCount : 0,
        Params->Pmkid, &Params->PmkidValid);
}

#define AP6256_WDI_TLV_IHV_DATA 189u

#define AP6256_WDI_FILTER_SUPPORTED 0x03FF002Fu
#define AP6256_WDI_FILTER_MGMT_CLASSES 0x03FE0000u

#define AP6256_CNT_TX_MULTICAST 49u
#define AP6256_CNT_RX_DUP 53u
#define AP6256_CNT_RTS_OK 54u
#define AP6256_CNT_RTS_FAIL 55u
#define AP6256_CNT_ACK_FAIL 56u
#define AP6256_CNT_RX_FRAG 57u
#define AP6256_CNT_RX_MULTICAST 58u
#define AP6256_CNT_FCS_ERROR 59u
#define AP6256_CNT_DECRYPT_FAIL 61u
#define AP6256_CNT_TKIP_MIC 62u
#define AP6256_CNT_TKIP_REPLAY 64u
#define AP6256_CNT_CCMP_FORMAT 65u
#define AP6256_CNT_CCMP_REPLAY 66u
#define AP6256_CNT_DECRYPT_ERR 67u
#define AP6256_CNT_WEP_UNDECRYPTABLE 69u
#define AP6256_CNT_WEP_ICV 70u
#define AP6256_CNT_DECRYPT_OK 71u
#define AP6256_CNT_TKIP_ICV 72u
#define AP6256_CNT_WEP_EXCLUDED 73u
#define AP6256_CNT_TX_LIFETIME 106u

#define AP6256_IF_PHY_TX_FRAME 8u
#define AP6256_IF_TX_FAIL 48u
#define AP6256_IF_TX_RETRY 56u
#define AP6256_IF_TX_RETRIES 64u
#define AP6256_IF_TX_FRAME 72u
#define AP6256_IF_TX_MULTI 80u
#define AP6256_IF_TX_FRAG 88u
#define AP6256_IF_RX_FRAME 96u
#define AP6256_IF_RX_MULTI 144u

#define AP6256_IF_U64(off) (*(const UINT64 UNALIGNED*)(ifCounters + (off)))

#define AP6256_PHY_ID_HRDSSS 0u
#define AP6256_PHY_ID_ERP 1u
#define AP6256_PHY_ID_OFDM 2u
#define AP6256_PHY_ID_HT 3u
#define AP6256_PHY_ID_VHT 4u
#define AP6256_PHY_COUNT 5u

#define AP6256_FRAME_MAX 1600u
#define AP6256_RXQ_DEPTH 32u
#define AP6256_TXQ_DEPTH 64u
#define AP6256_MAX_TX_FRAGMENTS 16u

#define AP6256_LINKQ_DEPTH 16u

#define AP6256_LINK_DOWN 0u
#define AP6256_LINK_UP 1u
#define AP6256_LINK_REFRESH 2u
#define AP6256_LINK_RADIO 3u
#define AP6256_LINK_CLIENT_DOWN 4u
#define AP6256_LINK_CLIENT_UP 5u
#define AP6256_LINK_JOIN_FAILED 6u

#define AP6256_CMDQ_DEPTH 16u
#define AP6256_LINK_SPEED 433000000ull
#define AP6256_SCAN_TIMEOUT_MS 20000u
#define AP6256_CONNECT_TIMEOUT_MS 30000u
#define AP6256_DISCONNECT_TIMEOUT_MS 5000u

#define AP6256_ACTION_FRAME_DEFAULT_DWELL_MS 50u
#define AP6256_ACTION_FRAME_DEFAULT_TIMEOUT_MS 500u
#define AP6256_ACTION_FRAME_POST_ACK_MIN_MS 100u
#define AP6256_ACTION_EVENT_COUNT 16u

#define AP6256_P2P_DISCOVER_FIRST_MS 20u

#define AP6256_EVENT_STATUS_SUCCESS 0u
#define AP6256_EVENT_STATUS_TIMEOUT 2u
#define AP6256_EVENT_STATUS_NO_ACK 5u

#define AP6256_DISALLOW_BAND_2G 0x00000001L
#define AP6256_DISALLOW_BAND_5G 0x00000002L

C_ASSERT((AP6256_RXQ_DEPTH & (AP6256_RXQ_DEPTH - 1)) == 0);
C_ASSERT((AP6256_TXQ_DEPTH & (AP6256_TXQ_DEPTH - 1)) == 0);
C_ASSERT((AP6256_CMDQ_DEPTH & (AP6256_CMDQ_DEPTH - 1)) == 0);

static const UINT16 Ap6256Channels5[] = {36,  40,  44,  48,  52,  56,  60,  64,  100,
                                         104, 108, 112, 116, 120, 124, 128, 132, 136,
                                         140, 144, 149, 153, 157, 161, 165};

typedef struct _AP6256_WDI_TASK {
    BOOLEAN Active;
    WDI_MESSAGE_HEADER Header;

    PVOID RequestId;

    LONGLONG DeadlineMs;
} AP6256_WDI_TASK, *PAP6256_WDI_TASK;

typedef struct _AP6256_FTM_TARGET {
    UCHAR Peer[6],Token;
    UINT16 Chanspec,LciLength;
    BOOLEAN RequestLci,Valid,Complete;
    WDI_FTM_RESPONSE_STATUS Status;
    WDI_LCI_REPORT_STATUS LciStatus;
    AP6256_FTM_RESULT Measurement;
    UCHAR Lci[AP6256_FTM_LCI_MAX];
} AP6256_FTM_TARGET;
typedef struct _AP6256_FTM_STATE {
    AP6256_WDI_TASK Task;
    AP6256_TIMER_OBJ Timer;
    AP6256_LOCK Lock;
    ULONG Count,Index;
    UINT16 Session,NextSession;
    BOOLEAN Enabled;
    LONGLONG TargetDeadline;
    AP6256_FTM_TARGET Targets[AP6256_FTM_TARGET_MAX];
} AP6256_FTM_STATE;

typedef struct _AP6256_ACTION_FRAME_COMPLETION {
    WDI_MESSAGE_HEADER Header;
    PVOID RequestId;
    UINT16 CompletionId;
    UINT32 PacketId;
    UCHAR Destination[6];
    PUCHAR Body;
    ULONG BodyLength;
} AP6256_ACTION_FRAME_COMPLETION, *PAP6256_ACTION_FRAME_COMPLETION;

typedef struct _AP6256_ACTION_TX_EVENT {
    UINT32 PacketId;
    UINT32 Status;
} AP6256_ACTION_TX_EVENT;

#define AP6256_CONNECT_BSSID_LIMIT 16

#define AP6256_WOWL_MAGIC 0x00000001u
#define AP6256_WOWL_NET 0x00000002u
#define AP6256_WOWL_DISCONNECT 0x00000004u
#define AP6256_WOWL_BEACON 0x00000010u
#define AP6256_WOWL_M1 0x00000040u
#define AP6256_WOWL_EAPID 0x00000080u
#define AP6256_WOWL_GTK_FAILURE 0x00000400u
#define AP6256_WOWL_ARP_OFFLOAD 0x00001000u
#define AP6256_WOWL_KEY_ROTATION 0x00004000u

#define AP6256_WOL_PATTERN_BYTES 128u
#define AP6256_NS_OFFLOAD_ADDRESSES 5u

#define AP6256_RX_COALESCE_FILTERS 8u

#define AP6256_P2P_PORT_NUMBER 1u

typedef struct _AP6256_RX_COALESCE_FILTER {
    UINT32 FilterId;
    ULONG FieldCount;
    WDI_RECEIVE_COALESCING_FIELD* Fields;
} AP6256_RX_COALESCE_FILTER;

typedef struct _AP6256_WIFI AP6256_WIFI, *PAP6256_WIFI;

#include <netmodel_state.h>
#include "station_auth_state.h"

typedef struct _AP6256_WIFI {
    PAP6256_DEVICE_CONTEXT Ctx;
    AP6256_MODEL_STATE Model;
    AP6256_AUTH_STATE Auth;

    AP6256_WORKITEM_OBJ CommandWorkItem;

    AP6256_WORKITEM_OBJ LinkWorkItem;

    UCHAR LinkEvents[AP6256_LINKQ_DEPTH];
    LONG LinkGenerations[AP6256_LINKQ_DEPTH];
    UINT32 LinkFirmwareGenerations[AP6256_LINKQ_DEPTH];
    UCHAR LinkFirmwareEvents[AP6256_LINKQ_DEPTH];
    ULONG LinkHead;
    ULONG LinkTail;
    KSPIN_LOCK LinkLock;

    volatile LONG LinkDraining;
    AP6256_TIMER_OBJ ScanTimer;
    AP6256_TIMER_OBJ ConnectTimer;
    AP6256_TIMER_OBJ DisconnectTimer;

    AP6256_REQUEST CommandPending[AP6256_CMDQ_DEPTH];
    LONG CommandSaeGeneration[AP6256_CMDQ_DEPTH];
    volatile LONG CommandDraining;
    ULONG CommandHead;
    ULONG CommandTail;
    KSPIN_LOCK CommandLock;
    TLV_CONTEXT TlvContext;

    AP6256_WDI_TASK ScanTask;
    AP6256_WDI_TASK ConnectTask;
    AP6256_WDI_TASK DisconnectTask;

    BOOLEAN ConnectTaskIsRoam;
    AP6256_CONNECT_PARAMS ConnectCandidates[AP6256_CONNECT_BSSID_LIMIT];
    ULONG ConnectCandidateCount;
    ULONG ConnectCandidateIndex;
    BOOLEAN ConnectDeparting;
    volatile LONG ConnectGeneration;

    AP6256_LOCK ConnectLock;

    BOOLEAN ApStarted;
    AP6256_WDI_TASK ApAssocTask;
    AP6256_AP_PARAMS GoApParams;
    AP6256_SECURITY ApSecurity;

    UCHAR ApPendingAssocMac[6];

    UCHAR RoamLinkQualityThreshold;
    BOOLEAN RoamLinkQualityThresholdValid;

    AP6256_WDI_TASK ActionFrameTask;
    AP6256_TIMER_OBJ ActionFrameTimer;

    AP6256_WORKITEM_OBJ ActionFrameCompleteWorker;

    AP6256_ACTION_TX_EVENT ActionFrameEvents[AP6256_ACTION_EVENT_COUNT];
    ULONG ActionFrameEventHead;
    ULONG ActionFrameEventCount;
    BOOLEAN ActionFrameEventDraining;
    BOOLEAN ActionFrameEventOverflow;
    UINT32 ActionFrameOverflowPacketId;
    UINT16 ActionFrameCompleteId;
    UINT32 ActionFramePendingId;
    LONGLONG ActionFrameDeadline;
    LONGLONG ActionFrameDwellDeadline;
    BOOLEAN ActionFrameAcked;
    ULONG ActionFrameRetryMs;
    UINT32 ActionFrameChannel;
    UINT32 ActionFrameIfIndex;
    UINT32 ActionFrameDwellMs;
    UCHAR ActionFrameBssid[6];
    UCHAR ActionFrameDest[6];
    PUCHAR ActionFrameBody;
    ULONG ActionFrameBodyLength;

    AP6256_LOCK ActionFrameLock;

    AP6256_RX_COALESCE_FILTER RxCoalesceFilters[AP6256_RX_COALESCE_FILTERS];
    UINT32 RxCoalesceMaxDelay;

    BOOLEAN ArpOffloadValid[AP6256_ARP_OFFLOAD_SLOTS];
    UINT32 ArpOffloadIds[AP6256_ARP_OFFLOAD_SLOTS];
    WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER ArpOffloads[AP6256_ARP_OFFLOAD_SLOTS];

    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER NsOffloads[AP6256_NS_OFFLOAD_ADDRESSES];
    ULONG NsOffloadCount;
    UINT32 GtkOffloadId;
    BOOLEAN GtkOffloadValid;
    AP6256_GTK_OFFLOAD GtkOffload;
    BOOLEAN RetainedResume;

    UINT32 WolPatternIds[AP6256_WOL_PATTERN_MAX];
    ULONG WolPatternCount;

    BOOLEAN P2pDiscovering;
    AP6256_SERVICE_STATE Service;
    AP6256_FTM_STATE Ftm;

    AP6256_WDI_TASK P2pDiscoverTask;
    AP6256_TIMER_OBJ P2pDiscoverTimer;
    AP6256_TIMER_OBJ P2pListenTimer;
    AP6256_LOCK P2pLock;

    WDI_MESSAGE_HEADER IndicationHeader;
    WDI_AUTH_ALGORITHM AuthAlgorithm;
    WDI_CIPHER_ALGORITHM UnicastCipher;
    WDI_CIPHER_ALGORITHM MulticastCipher;

    WDI_CIPHER_ALGORITHM MulticastMgmtCipher;
    UCHAR ConnectBssid[6];
    WDI_CHANNEL_NUMBER ConnectChannel;
    BOOLEAN ConnectBssidValid;
    BOOLEAN ConnectionActive;

    UCHAR ConnectAllowed[AP6256_CONNECT_BSSID_LIMIT][6];
    UCHAR ConnectDisallowed[AP6256_CONNECT_BSSID_LIMIT][6];
    ULONG ConnectAllowedCount;
    ULONG ConnectDisallowedCount;
    LONG ConnectDisallowedBands;
    BOOLEAN ConnectRestricted;

    BOOLEAN PowerStateDx;
    BOOLEAN PortCreated;
    UINT16 PortNumber;
    UINT32 StationPortMode;

    BOOLEAN P2pPortCreated;
    UINT16 P2pPortNumber;
    UINT32 P2pPortMode;
    UCHAR P2pPortAddress[6];

    UINT32 PortOperationMode;

    LONG NextActionFrameDialogToken;

    LONG ActionFramePacketId;

    BOOLEAN SoftwareRadioState;

    BOOLEAN HardwareRadioState;
    volatile LONG DisallowedBandMask;
    AP6256_MBO_STATE Mbo;

    volatile LONG ScanIndicated;
    volatile LONG ScanDropped;
    volatile LONG HardwareAvailable;
    volatile LONG Stopping;
} AP6256_WIFI, *PAP6256_WIFI;
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BuildGtkOffload(PAP6256_WIFI Wifi,
    const WDI_PM_RSN_KEY_INFO_CONTAINER* Source, AP6256_GTK_OFFLOAD* Offload);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GeneratePmOffload(_In_ PAP6256_WIFI Wifi,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength,
    UCHAR** Generated, ULONG* GeneratedLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256GeneratePowerSave(PAP6256_WIFI Wifi, UINT32 PortId,
                                UCHAR** Generated, ULONG* GeneratedLength);

typedef enum _AP6256_CONNECT_CLAIM {
    Ap6256ConnectClaimAny,
    Ap6256ConnectClaimMatching,
    Ap6256ConnectClaimExpired
} AP6256_CONNECT_CLAIM;

extern const UINT16 Ap6256RatesB[4];

NTSTATUS Ap6256MboInitialize(PAP6256_WIFI Wifi);
VOID Ap6256MboReset(PAP6256_WIFI Wifi);
VOID Ap6256MboDisassociated(PAP6256_WIFI Wifi);
VOID Ap6256MboScanResult(PAP6256_WIFI Wifi, const AP6256_BSS* Bss);
BOOLEAN Ap6256MboJoinBlocked(PAP6256_WIFI Wifi, const UCHAR* Bssid);
NTSTATUS Ap6256MboPrepareJoin(PAP6256_WIFI Wifi, const AP6256_CONNECT_PARAMS* Params);
NTSTATUS Ap6256MboCopyVendorIes(AP6256_CONNECT_PARAMS* Params, const UCHAR* Ies, ULONG Length);
VOID Ap6256MboAssociation(PAP6256_WIFI Wifi, BOOLEAN Success, const UCHAR* Bssid,
    const AP6256_ASSOC_FRAMES* Frames, BOOLEAN Pmf);
VOID Ap6256MboBtmRequest(PAP6256_WIFI Wifi, const UCHAR* Peer, const UCHAR* Body, ULONG Length);
NTSTATUS Ap6256MboExtendResponse(PAP6256_WIFI Wifi, const UCHAR* Peer, UCHAR* Body,
    ULONG Capacity, ULONG* Length);
NTSTATUS Ap6256MboSetBands(PAP6256_WIFI Wifi, LONG Bands, BOOLEAN Notify);
VOID Ap6256HandleFtmRequest(PAP6256_WIFI Wifi,AP6256_REQUEST Request,
    const WDI_MESSAGE_HEADER* Header,const UCHAR* Tlv,ULONG TlvLength);
VOID Ap6256OnFtmTick(PVOID Context);
BOOLEAN Ap6256FtmCancel(PAP6256_WIFI Wifi,BOOLEAN Match,UINT32 TransactionId,
    WDI_PORT_ID Port,NTSTATUS CompletionStatus);
extern const UINT16 Ap6256RatesOfdm[8];

BOOLEAN Ap6256AddressInList(_In_reads_(6) const UCHAR* Address,
                            _In_ const WDI_ADDRESS_LIST_CONTAINER* List);
BOOLEAN Ap6256AddressListIsUnrestricted(_In_ const WDI_ADDRESS_LIST_CONTAINER* List);
BOOLEAN Ap6256AlgorithmPresent(_In_ const WDI_AUTH_ALGORITHM_LIST_CONTAINER* List,
                               _In_ WDI_AUTH_ALGORITHM Algorithm);
BOOLEAN Ap6256BandIsMasked(_In_ LONG Mask, _In_ WDI_BAND_ID BandId);
NTSTATUS Ap6256BeginTask(_In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task,
                         _In_ const WDI_MESSAGE_HEADER* Header, _In_opt_ PVOID RequestId);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256CancelActionFrame(_In_ PAP6256_WIFI Wifi,
                                                                _In_ NTSTATUS Status);
NTSTATUS Ap6256CancelClient(PAP6256_WIFI Wifi, NTSTATUS CompletionStatus, UINT32 Reason);
NTSTATUS Ap6256CancelClientLocked(PAP6256_WIFI Wifi, NTSTATUS CompletionStatus, UINT32 Reason);
VOID Ap6256CancelGoAssociation(PAP6256_WIFI Wifi, NTSTATUS Status);
BOOLEAN Ap6256ChannelSupported(_In_ AP6256_SCAN_BAND Band, _In_ WDI_CHANNEL_NUMBER Channel);
BOOLEAN Ap6256CipherPresent(_In_ const WDI_CIPHER_ALGORITHM_LIST_CONTAINER* List,
                            _In_ WDI_CIPHER_ALGORITHM Algorithm);
_IRQL_requires_max_(PASSIVE_LEVEL) _Success_(return != FALSE)
BOOLEAN Ap6256ClaimConnectTask(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_CONNECT_CLAIM Claim, _In_ UINT32 TransactionId,
    _In_ WDI_PORT_ID PortId, _Out_ PWDI_MESSAGE_HEADER Header, _Out_ PVOID* RequestId);
_Success_(return != FALSE)
BOOLEAN Ap6256ClaimMatchingTask(
    _In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task, _In_ UINT32 TransactionId,
    _In_ WDI_PORT_ID PortId, _Out_ PWDI_MESSAGE_HEADER Header, _Out_ PVOID* RequestId);
_Success_(return != FALSE)
BOOLEAN Ap6256ClaimTask(_In_ PAP6256_WIFI Wifi,
                                                   _Inout_ PAP6256_WDI_TASK Task,
                                                   _Out_ PWDI_MESSAGE_HEADER Header,
                                                   _Out_ PVOID* RequestId);
VOID Ap6256ClearGoEvents(PAP6256_WIFI Wifi);
VOID Ap6256ClientLinkWork(PAP6256_WIFI Wifi, BOOLEAN Up, LONG Generation);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256CompleteRequest(_In_opt_ PAP6256_WIFI Wifi,
                                                               _In_ AP6256_REQUEST Request,
                                                               _In_ NTSTATUS Status);
_IRQL_requires_max_(DISPATCH_LEVEL)
PCSTR Ap6256ConnectBssRejection(_In_ PAP6256_WIFI Wifi,
                                                                    _In_reads_(6)
                                                                        const UCHAR* Bssid,
                                                                    _In_ ULONG Channel);
UINT16 Ap6256ConnectCompletionId(_In_ PAP6256_WIFI Wifi);
BOOLEAN Ap6256HostCipherAvailable(_In_ PAP6256_WIFI Wifi);
BOOLEAN Ap6256Wpa3EnterpriseAvailable(_In_ PAP6256_WIFI Wifi);
ULONG Ap6256CopyAlgoPairs(_In_ PAP6256_WIFI Wifi, _In_reads_(Total) const WDI_ALGO_PAIRS* Source,
                          _In_ ULONG Total, _Out_writes_(Total) WDI_ALGO_PAIRS* Destination);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256FailStartedTask(_In_ PAP6256_WIFI Wifi,
                                                              _Inout_ PAP6256_WDI_TASK Task,
                                                              _In_ UINT16 CompletionId,
                                                              _In_ NTSTATUS Status);
VOID Ap6256FlushSoftwareQueues(_In_ PAP6256_WIFI Wifi);
VOID Ap6256ForgetGoAutoAssoc(PAP6256_WIFI Wifi, const UCHAR* Address);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256FreeActionFrame(_In_ PAP6256_WIFI Wifi);
NTSTATUS Ap6256GetRequestView(_In_ AP6256_REQUEST Request, _Out_ PWDI_MESSAGE_HEADER* Header,
                              _Outptr_result_bytebuffer_(*TlvLength) const UCHAR** Tlv,
                              _Out_ PULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleAbortRequest(_In_ PAP6256_WIFI Wifi,
                                                                 _In_ AP6256_REQUEST Request,
                                                                 _In_reads_bytes_(TlvLength)
                                                                     const UCHAR* Tlv,
                                                                 _In_ ULONG TlvLength);
VOID Ap6256HandleClientConnect(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                               PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleGetCapabilities(_In_ PAP6256_WIFI Wifi,
                                                                    _In_ AP6256_REQUEST Request);
_IRQL_requires_max_(PASSIVE_LEVEL)

VOID Ap6256HandleGetGroupStatistics(PAP6256_WIFI Wifi, AP6256_REQUEST Request);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256HandleGetNextActionFrameDialogToken(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256HandleGetPmProtocolOffload(_In_ PAP6256_WIFI Wifi,
                                  _In_ AP6256_REQUEST Request,
                                  _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                  _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleGetStatistics(_In_ PAP6256_WIFI Wifi,
                                                                  _In_ AP6256_REQUEST Request);
VOID Ap6256HandleGoAutoResponse(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                const WDI_MESSAGE_HEADER* Header,
                                WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE_PARAMETERS* P,
                                WDI_PHY_TYPE Phy, NTSTATUS ParseStatus);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleIhvRequest(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ const WDI_MESSAGE_HEADER* Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandlePowerRequest(_In_ PAP6256_WIFI Wifi,
                                                                 _In_ AP6256_REQUEST Request,
                                                                 _In_reads_bytes_(TlvLength)
                                                                     const UCHAR* Tlv,
                                                                 _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256HandleSendApAssociationResponse(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
BOOLEAN Ap6256HostFbtAvailable(_In_ PAP6256_WIFI Wifi);
BOOLEAN Ap6256HostOweAvailable(_In_ PAP6256_WIFI Wifi);
BOOLEAN Ap6256HostSaeAvailable(_In_ PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)

BOOLEAN
Ap6256IndicateAssociation(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header,
                          _In_opt_ PVOID RequestId, _In_ BOOLEAN Success);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256IndicateDisassociation(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header);
VOID Ap6256IndicateP2pGroupChannel(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header,
                                   _In_opt_ PVOID RequestId, _In_ UINT32 Channel);
_IRQL_requires_max_(DISPATCH_LEVEL)

PCSTR Ap6256IndicationName(UINT16 MessageId);
_IRQL_requires_max_(DISPATCH_LEVEL)
LONGLONG Ap6256InterruptTimeMs(VOID);
UINT32 Ap6256LinkQualityFromRssi(_In_ INT32 Rssi);
VOID Ap6256LinkWork(_In_ PAP6256_WIFI wifi);
BOOLEAN Ap6256MacIsValidUnicast(_In_reads_(6) const UCHAR* Address);
BOOLEAN Ap6256MacIsValue(_In_reads_(6) const UCHAR* Address, _In_ UCHAR Value);
VOID Ap6256ModelApStarted(PAP6256_WIFI Wifi, NTSTATUS status);
VOID Ap6256ModelApStopped(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx);
VOID Ap6256ModelCancelAuthentication(PAP6256_WIFI Wifi);
NTSTATUS Ap6256ModelChangeGroupMode(PAP6256_WIFI Wifi, UINT32 wdiMode);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256ModelChangeGroupModeCompleted(_In_ PAP6256_WIFI Wifi, _In_ UINT32 PreviousMode,
                                       _In_ NTSTATUS CompletionStatus);
BOOLEAN Ap6256ModelClientLinkEvent(PAP6256_WIFI Wifi, UCHAR code, LONG generation);
VOID Ap6256ModelCompleteAuthentication(PAP6256_WIFI Wifi);
BOOLEAN Ap6256ModelConnectPort(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                               PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength,
                               BOOLEAN isRoam);
VOID Ap6256ModelConnectionLost(PAP6256_WIFI Wifi);
NTSTATUS Ap6256ModelCopyAuthenticationCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate,
                                                const WDI_TASK_CONNECT_PARAMETERS* parameters,
                                                BOOLEAN sae, BOOLEAN owe,
                                                AP6256_CONNECT_PARAMS* output);
NTSTATUS Ap6256ModelCopyFtCandidate(const WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate,
                                    BOOLEAN isRoam, AP6256_CONNECT_PARAMS* output);
VOID Ap6256ModelDeleteGroup(PAP6256_WIFI Wifi);
VOID Ap6256ModelDeleteStationPeer(PAP6256_WIFI Wifi);
BOOLEAN Ap6256ModelDisconnectPort(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                  PWDI_MESSAGE_HEADER Header,
                                  WDI_TASK_DISCONNECT_PARAMETERS* parameters, NTSTATUS status);
BOOLEAN Ap6256ModelDispatchCommand(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
                                   PWDI_MESSAGE_HEADER header, const UCHAR* tlv, ULONG tlvLength,
                                   UINT16 messageId);
BOOLEAN Ap6256ModelGroupConnecting(PAP6256_WIFI Wifi);
BOOLEAN Ap6256ModelLinkUsable(PAP6256_WIFI Wifi);
VOID Ap6256ModelOpenStationReceive(PAP6256_WIFI Wifi, BOOLEAN associated);
BOOLEAN Ap6256ModelRejectStationEvent(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx,
                                      UCHAR FirmwareEvent, UINT32 FirmwareGeneration,
                                      const UCHAR* Peer);
NTSTATUS Ap6256ModelResetGroup(PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ModelResetGroupAddress(_In_ PAP6256_WIFI Wifi,
                                     _In_reads_(6) const UCHAR* Address);
VOID Ap6256ModelResetGroupPeers(PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256ModelGroupAddressChanged(_In_ PAP6256_WIFI Wifi);
BOOLEAN Ap6256ModelRetryAssociation(PAP6256_WIFI Wifi);
VOID Ap6256ModelSetLinkState(PAP6256_WIFI Wifi, BOOLEAN LinkUp);
BOOLEAN Ap6256ModelStaleLinkEvent(PAP6256_WIFI Wifi, UCHAR FirmwareEvent,
                                  UINT32 FirmwareGeneration);

VOID Ap6256ModelStampLinkEvent(PAP6256_WIFI Wifi, UCHAR Code);

NTSTATUS Ap6256ModelStartApBegin(PAP6256_WIFI Wifi);
VOID Ap6256ModelStartApEnd(PAP6256_WIFI Wifi);
NTSTATUS Ap6256ModelStartApHardware(PAP6256_WIFI Wifi, PAP6256_AP_PARAMS Params);
VOID Ap6256ModelStartApCompleted(PAP6256_WIFI Wifi, NTSTATUS StartStatus, NTSTATUS CompletionStatus);
NTSTATUS Ap6256ModelStartApPeer(PAP6256_WIFI Wifi, NTSTATUS status);
NTSTATUS Ap6256ModelStartInterfaces(PAP6256_WIFI Wifi, PAP6256_DEVICE_CONTEXT Ctx);
VOID Ap6256ModelStopApPeers(PAP6256_WIFI Wifi, NTSTATUS status);
NTSTATUS Ap6256ModelValidateCandidates(PAP6256_WIFI Wifi, const AP6256_CONNECT_PARAMS* candidates,
                                       ULONG candidateCount, BOOLEAN isRoam);
NTSTATUS Ap6256NdisToNtStatus(_In_ NDIS_STATUS Status);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetQueueLinkEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                                _In_ UCHAR Code);
VOID Ap6256NotifyRxQueue(_In_ PAP6256_WIFI Wifi);
NDIS_STATUS Ap6256NtToNdisStatus(_In_ NTSTATUS Status);
VOID Ap6256OnActionFrameTimeout(_In_ PVOID Context);
VOID Ap6256OnConnectTimeout(_In_ PVOID Context);
VOID Ap6256OnDisconnectTimeout(_In_ PVOID Context);
VOID Ap6256OnP2pDiscoverTick(_In_ PVOID Context);
VOID Ap6256OnP2pListenTick(PVOID Context);
VOID Ap6256OnScanTimeout(_In_ PVOID Context);
VOID Ap6256ProcessCommand(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, LONG SaeGeneration);
_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS Ap6256QueueCommand(_In_opt_ PAP6256_WIFI Wifi,
                                                                _In_ AP6256_REQUEST Request);
NTSTATUS Ap6256QuiesceP2pListen(PAP6256_WIFI Wifi);
PVOID Ap6256RequestGetId(_In_ AP6256_REQUEST Request);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SendGeneratedIndication(
    _In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId, _In_ const WDI_MESSAGE_HEADER* OriginalHeader,
    _In_ UINT32 TransactionId, _In_opt_ PVOID RequestId,
    _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
NTSTATUS Ap6256SendIndicationRq(_In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId,
                                _In_ const WDI_MESSAGE_HEADER* OriginalHeader,
                                _In_ UINT32 TransactionId, _In_opt_ PVOID RequestId,
                                _In_ NTSTATUS CompletionStatus,
                                _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv,
                                _In_ ULONG TlvLength);
VOID Ap6256SetTaskDeadline(_In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task,
                           _In_ ULONG TimeoutMs);
NTSTATUS Ap6256StationStartNext(_In_ PAP6256_WIFI Wifi);
PAP6256_WIFI Ap6256WifiFromDevice(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG Ap6256WolPatternCeiling(_In_ PAP6256_WIFI Wifi);

VOID Ap6256StationSaeCancel(PAP6256_WIFI Wifi);
NTSTATUS Ap6256StationSaeComplete(PAP6256_WIFI Wifi);
VOID Ap6256StationSaeTimer(PVOID Context);
VOID Ap6256HandleSaeParameters(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
    PWDI_MESSAGE_HEADER Header, const UCHAR* Tlv, ULONG TlvLength, LONG Generation);
VOID Ap6256HandleSetFastBssTransition(PAP6256_WIFI Wifi, AP6256_REQUEST Request,
    const WDI_MESSAGE_HEADER* Header, const UCHAR* Tlv, ULONG TlvLength);
VOID Ap6256DrainCommandQueue(PAP6256_WIFI Wifi);
VOID Ap6256StationAuthStop(PAP6256_WIFI Wifi);
VOID Ap6256StationAuthFreeEvents(PAP6256_WIFI Wifi);
VOID Ap6256ModelSetStationBssid(PAP6256_WIFI Wifi, const UCHAR* Bssid);
BOOLEAN Ap6256ModelCreateStationPeer(PAP6256_WIFI Wifi, const UCHAR* Bssid);
BOOLEAN Ap6256ModelTakeCommandEvent(PAP6256_WIFI Wifi, PVOID* Event, BOOLEAN* Lost);
VOID Ap6256ModelProcessCommandEvent(PAP6256_WIFI Wifi, PVOID Event, BOOLEAN Lost);

VOID Ap6256ModelUpdateReceiveContext(PAP6256_WIFI Wifi);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ServiceCapture(PAP6256_WIFI Wifi, const WDI_TASK_P2P_DISCOVER_PARAMETERS* Params, BOOLEAN Store);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ServiceBegin(PAP6256_WIFI Wifi, ULONG ScanDurationMs);
_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG Ap6256ServiceAdvance(PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256ServiceStop(PAP6256_WIFI Wifi, BOOLEAN ClearAdvertisements);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ServiceAdvertise(PAP6256_WIFI Wifi, const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* Services);
_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256ServiceScanResult(PAP6256_WIFI Wifi, const AP6256_BSS* Bss);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ServiceResumeListen(PAP6256_WIFI Wifi);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ServiceValidateAdvertisements(PAP6256_WIFI Wifi, const WDI_P2P_ADVERTISED_SERVICES_CONTAINER* Services);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256RecomputePortModes(_In_ PAP6256_WIFI Wifi);
