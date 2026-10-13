/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"
#include "wowl.h"
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPowerSaveStats(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
                                    PAP6256_POWER_SAVE_STATS Stats);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiQualifyMbo(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_WDI_OPMODE_STA          0x01u
#define AP6256_WDI_OPMODE_P2P_DEVICE   0x08u
#define AP6256_WDI_OPMODE_P2P_CLIENT   0x10u
#define AP6256_WDI_OPMODE_P2P_GO       0x20u

typedef enum _AP6256_SECURITY {
    Ap6256SecurityOpen = 0,
    Ap6256SecurityWpa2Host,
    Ap6256SecurityWpa2Firmware,
    Ap6256SecurityWpa2Enterprise,
    Ap6256SecuritySaeHost,
    Ap6256SecurityOweHost,
} AP6256_SECURITY;

typedef enum _AP6256_MFP {
    Ap6256MfpNone = 0,
    Ap6256MfpCapable = 1,
    Ap6256MfpRequired = 2,
} AP6256_MFP;

typedef struct _AP6256_AP_PARAMS {
    UCHAR   Ssid[32];
    ULONG   SsidLength;
    ULONG   Channel;
    UINT32  BeaconPeriod;
    UINT32  DtimPeriod;
    BOOLEAN ExcludeUnencrypted;
    BOOLEAN RejectNonP2pClients;

    AP6256_SECURITY Security;
} AP6256_AP_PARAMS, *PAP6256_AP_PARAMS;

#define AP6256_OWE_DH_MAX 71u
#define AP6256_OWE_EXTRA_MAX 1024u

typedef struct _AP6256_CONNECT_PARAMS {
    UCHAR           Ssid[32];
    ULONG           SsidLength;
    UCHAR           Bssid[6];
    BOOLEAN         BssidValid;
    AP6256_SECURITY Security;
    BOOLEAN         HostFips, HostFipsHt;

    BOOLEAN         HostCipher;

    BOOLEAN         Wpa3Enterprise;
    BOOLEAN         ExcludeUnencrypted;
    UINT32          HostCipherAkm;

    BOOLEAN         PmkidValid;
    UCHAR           Pmkid[16];
    BOOLEAN         SaeCachedH2e;

    UINT32          SaeFirmwareGeneration, SaeTimeoutMs;

    UCHAR           OweDh[AP6256_OWE_DH_MAX], OweExtra[AP6256_OWE_EXTRA_MAX];
    ULONG           OweDhLength, OweExtraLength;

    UCHAR           AssociationVendorIes[1024];
    ULONG           AssociationVendorIesLength;

    BOOLEAN         FastTransition, FtReassociation;
    UCHAR           FtMde[5], FtFte[257], FtPmkR0Name[16];
    ULONG           FtFteLength;
    CHAR            Passphrase[64];
    ULONG           PassphraseLength;

    AP6256_MFP      Mfp;

    UINT32          Channel;
} AP6256_CONNECT_PARAMS, *PAP6256_CONNECT_PARAMS;

#define AP6256_REASON_LEAVING   3u

#define AP6256_SCAN_SSID_MAX       16u
#define AP6256_SCAN_CHANNEL_MAX    128u

typedef enum _AP6256_SCAN_TYPE {
    Ap6256ScanTypeActive = 0,
    Ap6256ScanTypePassive,
    Ap6256ScanTypeAuto,
} AP6256_SCAN_TYPE;

typedef enum _AP6256_SCAN_BAND {
    Ap6256ScanBand2G = 0,
    Ap6256ScanBand5G,
} AP6256_SCAN_BAND;

typedef struct _AP6256_SCAN_SSID {
    ULONG Length;
    UCHAR Data[32];
} AP6256_SCAN_SSID, *PAP6256_SCAN_SSID;

typedef struct _AP6256_SCAN_CHANNEL {
    UINT16 Number;
    AP6256_SCAN_BAND Band;
} AP6256_SCAN_CHANNEL, *PAP6256_SCAN_CHANNEL;

typedef struct _AP6256_SCAN_PARAMS {
    UCHAR Bssid[6];
    AP6256_SCAN_TYPE ScanType;
    ULONG ActiveChannelDwellTime;
    ULONG PassiveChannelDwellTime;
    ULONG MaximumScanTime;
    ULONG SsidCount;
    AP6256_SCAN_SSID Ssids[AP6256_SCAN_SSID_MAX];
    ULONG ChannelCount;
    AP6256_SCAN_CHANNEL Channels[AP6256_SCAN_CHANNEL_MAX];
} AP6256_SCAN_PARAMS, *PAP6256_SCAN_PARAMS;

#define AP6256_SCAN_IE_MAX 2048u

typedef struct _AP6256_BSS {
    UINT16  SyncId;
    UCHAR   Bssid[6];
    UCHAR   Ssid[32];
    ULONG   SsidLength;
    INT16   Rssi;
    UINT16  Channel;
    UINT16  BeaconPeriod;
    UINT16  Capability;
    BOOLEAN FromBeacon;
    BOOLEAN FromCache;
    UCHAR   Ies[AP6256_SCAN_IE_MAX];
    ULONG   IesLength;
} AP6256_BSS, *PAP6256_BSS;

typedef struct _AP6256_CCMP_KEY {
    UINT32  IfIndex;
    ULONG   KeyId;
    BOOLEAN Pairwise;
    UCHAR   PeerAddress[6];
    UCHAR   Key[16];
    BOOLEAN ReceiveSequenceValid;
    UCHAR   ReceiveSequence[6];
} AP6256_CCMP_KEY, *PAP6256_CCMP_KEY;

#define AP6256_BIP_KEY_MAX   16u

typedef struct _AP6256_BIP_KEY {
    UINT32  IfIndex;
    ULONG   KeyId;
    UCHAR   PeerAddress[6];
    ULONG   KeyLength;
    UCHAR   Key[AP6256_BIP_KEY_MAX];
    UCHAR   Ipn[6];
} AP6256_BIP_KEY, *PAP6256_BIP_KEY;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiUp(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetRadioState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_reads_(6) const UCHAR* Address);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiResetMib(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiScanStart(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ const AP6256_SCAN_PARAMS* Params);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiScanAbort(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiLegacyScanAbort(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAbortOffChannel(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiOnEscanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_reads_bytes_(Length) PUCHAR EventData, _In_ ULONG Length,
                                 _Out_ PAP6256_BSS Bss);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiConnect(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CONNECT_PARAMS Params);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDisconnect(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiClearSecurityState(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiResetFirmwareCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMfpWsecBit(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enable);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetBssWmm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ BOOLEAN Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPermanentMacAddress(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_writes_(6) PUCHAR Address);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMulticastList(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_reads_opt_(Count) const VOID* Addresses,
                                    _In_ ULONG Count);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ ULONG Filter,
                                   _In_ BOOLEAN SendUpMgmt);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddCcmpKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ PAP6256_CCMP_KEY Key);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddBipKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ PAP6256_BIP_KEY Key);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDeleteBipKeyIf(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex, _In_ ULONG KeyId, _In_reads_(6) const UCHAR* PeerAddress);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDeleteCcmpKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ ULONG KeyId,
                                 _In_ BOOLEAN Pairwise,
                                 _In_reads_(6) const UCHAR* PeerAddress);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetWpsEnabled(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendAssocDecision(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                     _In_reads_(6) const UCHAR* PeerAddress,
                                     _In_ BOOLEAN Accept,
                                     _In_ UINT16 StatusCode);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiStartAp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ PAP6256_AP_PARAMS Params);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiStopAp(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendActionFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ UINT32 IfIndex,
                                   _In_ UINT32 Channel,
                                   _In_ UINT32 DwellTimeMs,
                                   _In_reads_(6) const UCHAR* Bssid,
                                   _In_reads_(6) const UCHAR* Destination,
                                   _In_ UINT32 PacketId,
                                   _In_reads_bytes_(BodyLength) const UCHAR* Body,
                                   _In_ ULONG BodyLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetOperationMode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UINT32 WdiMode,
                                    _In_ UINT32 PreviousWdiMode);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetDefaultKeyId(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ ULONG KeyId);

#define AP6256_NLO_NETWORK_MAX      16u
#define AP6256_NLO_CHANNEL_HINTS     4u

typedef struct _AP6256_NLO_NETWORK {
    UCHAR  Ssid[32];
    ULONG  SsidLength;
    UINT32 AuthAlgorithm;
    UINT32 CipherAlgorithm;
    BOOLEAN DirectedProbePermitted;
} AP6256_NLO_NETWORK, *PAP6256_NLO_NETWORK;

typedef struct _AP6256_NLO_PARAMS {
    UINT32 ScanPeriodSeconds;
    BOOLEAN Enable;
    BOOLEAN WindowsRequest;
    UINT32 FastIterations;
    UINT32 SlowPeriodSeconds;
    UINT32 DelayStartSeconds;
    ULONG  NetworkCount;
    AP6256_NLO_NETWORK Networks[AP6256_NLO_NETWORK_MAX];
} AP6256_NLO_PARAMS, *PAP6256_NLO_PARAMS;

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiClearNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256WifiNloSecuritySupported(_In_ UINT32 AuthAlgorithm,
                                       _In_ UINT32 CipherAlgorithm);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiChannelIsValid(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UINT32 Channel,
                                  _Out_ PBOOLEAN Valid);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                         _In_ const AP6256_NLO_PARAMS* Params);

#define AP6256_WOL_PATTERN_MAX   22u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolBitmapPattern(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 PatternId,
    _In_reads_bytes_(PatternLength) const UCHAR* Pattern,
    _In_ ULONG PatternLength,
    _In_reads_bytes_(MaskLength) const UCHAR* Mask,
    _In_ ULONG MaskLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolMagicPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolEapolPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveWolPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UINT32 PatternId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRadioUpDown(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _In_ BOOLEAN Up);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChanspec(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PUINT32 Chanspec);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRadioDisabled(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _Out_ PBOOLEAN HardwareOff,
                                    _Out_ PBOOLEAN SoftwareOff);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRoamTrigger(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PINT32 TriggerDbm);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiArmRssiEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ INT32 TriggerDbm);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiArmRoamTriggers(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_P2P_IF_CLIENT      0u
#define AP6256_P2P_IF_GO          1u
#define AP6256_P2P_IF_DYNBCN_GO   2u
#define AP6256_P2P_IF_DEV         3u

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 Ap6256WifiP2pInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_GO_ASSOC_IE_MAX 1024u
#define AP6256_BEACON_FIXED_LEN 12u
typedef struct _AP6256_AP_PEER_INFO {
    UINT16 Capability;
    UINT16 Aid;
    UINT16 ListenInterval;
    UINT16 ApCapability;
    UINT16 BeaconPeriod;
    UCHAR Ssid[32];
    ULONG SsidLength;
    UCHAR Rates[16];
    ULONG RateCount;
    ULONG BeaconLength;

    UCHAR Beacon[AP6256_GO_ASSOC_IE_MAX];
} AP6256_AP_PEER_INFO;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetApPeerInfo(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* Address, _Out_ AP6256_AP_PEER_INFO* Info);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetApWmmEnabled(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Out_ BOOLEAN* Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceApBss(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pSetDiscoverySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                           _In_ BOOLEAN WpsEnabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pSetDiscoveryInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                            _In_ BOOLEAN Enable,
                                            _Out_opt_ PUINT32 BssIndex);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pAddInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_reads_(6) const UCHAR* Address,
                                   _In_ UINT16 Role,
                                   _In_ UINT16 Chanspec);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pDeleteInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_reads_(6) const UCHAR* Address);

#define AP6256_WAKE_ON_NLO_DISCOVERY          0x00000001u
#define AP6256_WAKE_ON_AP_ASSOCIATION_LOST    0x00000002u
#define AP6256_WAKE_ON_GTK_HANDSHAKE_ERROR    0x00000004u
#define AP6256_WAKE_ON_4WAY_HANDSHAKE_REQUEST 0x00000008u

#define AP6256_WAKE_PACKET_BYTES    128u
#define AP6256_WAKE_PACKET_NET        1u

#pragma pack(push, 1)
typedef struct _AP6256_WAKE_PACKET {
    UINT32 Type;
    UINT32 PatternId;
    UINT32 OriginalLength;
    UINT32 SavedLength;
    UCHAR  Packet[AP6256_WAKE_PACKET_BYTES];
} AP6256_WAKE_PACKET;
#pragma pack(pop)

C_ASSERT(sizeof(AP6256_WAKE_PACKET) == 144);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilterMax(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _Out_ PUINT32 Max);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiEnablePacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId,
                                      _In_ BOOLEAN Enable);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilterMode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ UINT32 Mode);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMasterPacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                         _In_ UINT32 Mask);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiArmWakeEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 MediaSpecific);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadWakeEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PUINT32 Status);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadWakePacket(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ AP6256_WAKE_PACKET* Packet);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSuspendForWake(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UINT32 MediaSpecific,
                                  _In_ BOOLEAN ArpOffload,
                                  _In_ BOOLEAN NsOffload);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiResumeFromWake(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _Out_ PUINT32 WakeStatus,
                              _Out_ AP6256_WAKE_PACKET* Packet,
                              _Out_ PBOOLEAN PacketValid);

#define AP6256_ARP_OFFLOAD_SLOTS   8u

typedef struct _AP6256_ARP_OFFLOAD {
    UINT32 OffloadId;
    UCHAR  RemoteIpv4[4];
    UCHAR  HostIpv4[4];
    UCHAR  MacAddress[6];
} AP6256_ARP_OFFLOAD, *PAP6256_ARP_OFFLOAD;

typedef struct _AP6256_NS_OFFLOAD {
    UINT32 OffloadId;
    UCHAR  RemoteIpv6[16];
    UCHAR  SolicitedNodeIpv6[16];
    UCHAR  TargetIpv6A[16];
    UCHAR  TargetIpv6B[16];
    UCHAR  MacAddress[6];
} AP6256_NS_OFFLOAD, *PAP6256_NS_OFFLOAD;

typedef struct _AP6256_GTK_OFFLOAD {
    UINT32 OffloadId;
    UINT64 ReplayCounter;
    UCHAR  Kck[16];
    UCHAR  Kek[16];
    UINT32 DescriptorVersion, MicKind, Pmf;
} AP6256_GTK_OFFLOAD, *PAP6256_GTK_OFFLOAD;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddArpOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_ARP_OFFLOAD* Offload,
                                 _In_ ULONG Slot);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveArpOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ ULONG Slot);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddNsOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ const AP6256_NS_OFFLOAD* Offload);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveNsOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ UINT32 OffloadId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddGtkOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_GTK_OFFLOAD* Offload);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiEnableProtocolOffloads(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                          _In_ BOOLEAN Arp,
                                          _In_ BOOLEAN NeighborDiscovery);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterMaxDelay(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ UINT32 DelayMs);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterArp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ BOOLEAN Add,
                                  _In_reads_(4) const UCHAR* Ipv4Address);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterProtocol(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ BOOLEAN Add,
                                       _In_ UINT32 Mask);

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 Ap6256WifiD0FilterMaskForPort(_In_ UINT32 Port, _In_ BOOLEAN Ipv6);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMaxKeys(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _Out_ PUINT32 MaxKeys);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256WifiWmmEnabled(_In_ PAP6256_DEVICE_CONTEXT Ctx);

#define AP6256_MAC_COUNTER_DWORDS  128u
#define AP6256_IF_COUNTER_BYTES    184u
#define AP6256_IF_COUNTER_MIN_BYTES 152u

#define AP6256_COUNTERS_XTLV_VERSION  30u
#define AP6256_COUNTERS_LEGACY_VERSION 10u
#define AP6256_COUNTERS_MACSTAT_ID   256u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMacCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Out_writes_(AP6256_MAC_COUNTER_DWORDS)
                                     PUINT32 Counters,
                                 _Out_ PULONG CounterCount);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetIfCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Out_writes_bytes_(AP6256_IF_COUNTER_BYTES)
                                     PUCHAR Counters);

#define AP6256_P2P_DISC_SCAN     0u
#define AP6256_P2P_DISC_LISTEN   1u
#define AP6256_P2P_DISC_SEARCH   2u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetVendorIes(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ UINT32 PktFlag,
                                _In_ BOOLEAN Add,
                                _In_reads_bytes_(IesLength) const UCHAR* Ies,
                                _In_ ULONG IesLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetP2pDiscoveryState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                        _In_ UINT32 State,
                                        _In_ UINT32 Channel,
                                        _In_ UINT32 DwellMs);

#define AP6256_P2P_SCAN_CHANNEL_MAX  16u

typedef struct _AP6256_P2P_SCAN {
    UCHAR  Ssid[32];
    ULONG  SsidLength;
    BOOLEAN Passive;
    INT32  NProbes;
    INT32  ActiveTimeMs;
    INT32  PassiveTimeMs;
    ULONG  ChannelCount;
    UINT16 Channels[AP6256_P2P_SCAN_CHANNEL_MAX];
} AP6256_P2P_SCAN, *PAP6256_P2P_SCAN;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pScan(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ const AP6256_P2P_SCAN* Scan);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetBssid(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_writes_(6) PUCHAR Bssid);

typedef struct _AP6256_ASSOC_FRAMES {
    PUCHAR Beacon;
    ULONG  BeaconLength;
    PUCHAR AssocRequest;
    ULONG  AssocRequestLength;
    PUCHAR AssocResponse;
    ULONG  AssocResponseLength;
    BOOLEAN ReAssociation;
    UINT16  PeerStatusCode;
    BOOLEAN PeerStatusValid;

    BOOLEAN WmmNegotiated;

    UCHAR BeaconBssid[6];
} AP6256_ASSOC_FRAMES, *PAP6256_ASSOC_FRAMES;

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiGetAssocFrames(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _Out_ PAP6256_ASSOC_FRAMES Frames);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiFreeAssocFrames(_Inout_ PAP6256_ASSOC_FRAMES Frames);

NTSTATUS Ap6256WifiAssocPmf(_In_ const AP6256_ASSOC_FRAMES* Frames,
                          _In_reads_(6) const UCHAR* Bssid,
                          _Out_ BOOLEAN* Enabled);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChannel(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PUINT32 Channel);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRssi(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PINT32 Rssi);

#include <pshpack1.h>
typedef struct _AP6256_PKT_COUNTS {
    UINT32 RxGood;
    UINT32 RxBad;
    UINT32 TxGood;
    UINT32 TxBad;
    UINT32 RxOtherCastGood;
} AP6256_PKT_COUNTS, *PAP6256_PKT_COUNTS;
#include <poppack.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPacketCounts(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _Out_ PAP6256_PKT_COUNTS Counts);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMaxLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PUINT32 RateHalfMbps);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PUINT32 RateHalfMbps);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPhyNoise(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PINT32 NoiseDbm);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPowerSave(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ BOOLEAN Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetCountry(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_reads_(2) const CHAR* Code);

#define AP6256_EXEMPT_ACTION_ALWAYS      0u
#define AP6256_EXEMPT_ACTION_ON_NO_KEY   1u
#define AP6256_EXEMPT_PACKET_UNICAST     0u
#define AP6256_EXEMPT_PACKET_MULTICAST   1u
#define AP6256_EXEMPT_PACKET_BOTH        2u

#define AP6256_EXEMPT_MAX                16u

#include <pshpack1.h>
typedef struct _AP6256_EXEMPT_ENTRY {
    UINT16 EtherType;
    UINT16 Action;
    UINT16 PacketType;
} AP6256_EXEMPT_ENTRY;
#include <poppack.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPrivacyExemptionsIf(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex,
    _In_reads_(Count) const AP6256_EXEMPT_ENTRY* Entries,
    _In_ ULONG Count);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPrivacyExemptions(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(Count) const AP6256_EXEMPT_ENTRY* Entries,
    _In_ ULONG Count);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReassociate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _In_reads_(6) const UCHAR* Bssid);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDisconnectWithReason(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                        _In_reads_opt_(6) const UCHAR* Bssid,
                                        _In_ UINT32 ReasonCode);

_IRQL_requires_max_(DISPATCH_LEVEL)
BOOLEAN Ap6256WifiEscanEventIsCurrent(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_opt_(Length) const UCHAR* EventData,
    _In_ ULONG Length,
    _Out_ PUINT16 SyncId);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceAssocList(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDeleteCcmpKeyIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ ULONG KeyId, _In_ BOOLEAN Pairwise, _In_reads_(6) const UCHAR* PeerAddress);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetDefaultKeyIdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ ULONG KeyId);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetWpsEnabledIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ BOOLEAN Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendAssocDecisionIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_reads_(6) const UCHAR* PeerAddress, _In_ BOOLEAN Accept, _In_ UINT16 StatusCode);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetVendorIesIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _In_ UINT32 PktFlag, _In_ BOOLEAN Add, _In_reads_bytes_(IesLength) const UCHAR* Ies,
    _In_ ULONG IesLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetStationVendorIes(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 PktFlag, _In_ BOOLEAN Add, _In_reads_bytes_(IesLength) const UCHAR* Ies,
    _In_ ULONG IesLength);

BOOLEAN Ap6256WifiIesPmfCapable(_In_reads_bytes_(Length) const UCHAR* Ies, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetBssidIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _Out_writes_(6) PUCHAR Bssid);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiGetAssocFramesIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _Out_ PAP6256_ASSOC_FRAMES Frames);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChannelIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _Out_ PUINT32 Channel);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256EncodeChanspec(_In_ UINT8 IoType, _In_ const AP6256_SCAN_CHANNEL* Channel, _Out_ PUINT16 Chanspec);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetIfCountersIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
                                  _Out_writes_bytes_(AP6256_IF_COUNTER_BYTES) PUCHAR Counters);
