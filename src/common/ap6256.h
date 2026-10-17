/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include <ntddk.h>

#include <device_framework.h>

#include <ntstrsafe.h>

#include "osal.h"
#include "watchdog.h"
#include "trace.h"
#include "hwids.h"
#include "chipregs.h"
#include "sdpcm.h"
#include "firmware_crash.h"
#include "power_stats.h"
#include "host_fips_wire.h"
#include "host_cipher_store.h"

#define AP6256_PMKID_LIST_BYTES     0x168u
#define AP6256_PMKID_CLEAR_BYTES    0x1cu

#define AP6256_POOL_TAG  '6256'

#define AP6256_HC_FIRMWARE_RETIRED 0x80000000u

#ifndef min
#define min(a, b) (((a) < (b)) ? (a) : (b))
#endif
#ifndef max
#define max(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define AP6256_MAX_CORES        24
#define AP6256_CORENAME_LEN     12

typedef struct _AP6256_CORE {
    UINT16 Id;
    UINT16 Rev;
    UINT32 Base;
    UINT32 WrapBase;
} AP6256_CORE, *PAP6256_CORE;

typedef struct _AP6256_CHIP {
    UINT32      ChipId;
    UINT32      ChipRev;
    UINT32      EnumBase;
    UINT32      RamBase;
    UINT32      RamSize;
    UINT32      PmuRev;
    UINT32      PmuCaps;
    UINT32      CcCaps;
    UINT32      SharedAddress;
    CHAR        Name[AP6256_CORENAME_LEN];

    AP6256_CORE Cores[AP6256_MAX_CORES];
    ULONG       CoreCount;

    PAP6256_CORE ChipCommon;
    PAP6256_CORE ArmCore;
    PAP6256_CORE SdiodCore;
    PAP6256_CORE D11Core;
} AP6256_CHIP, *PAP6256_CHIP;

typedef struct _AP6256_SDIO {

    PVOID       BusInterface;
    PVOID       BusInterfaceContext;

    ULONG       Function1BlockSize;
    ULONG       Function2BlockSize;
    ULONG       HostBlockLength;
    ULONG       MaxBlocksPerCmd53;
    ULONG       MaxTransferBytes[8];
    PUCHAR      HostRegs;
    volatile LONG IsrCount;
    BOOLEAN     ForceByteMode;

    volatile LONGLONG StatHdrReads;
    volatile LONGLONG StatHdrReadUs;
    volatile LONGLONG StatBodyReads;
    volatile LONGLONG StatBodyReadBytes;
    volatile LONGLONG StatBodyReadUs;
    volatile LONGLONG StatWrites;
    volatile LONGLONG StatWriteBytes;
    volatile LONGLONG StatWriteUs;
    volatile LONGLONG StatOtherCmd53;
    volatile LONGLONG StatOtherUs;
    volatile LONGLONG StatRxFrames;
    volatile LONGLONG StatTxFrames;
    volatile LONGLONG StatPasses;
    volatile LONGLONG StatEmptyPolls;
    LONG        StatIsrSnapshot;
    ULONGLONG   StatPrintedAt;

    PUCHAR      Bounce;
    SIZE_T      BounceSize;
    volatile LONG BounceBusy;

    UINT32      BackplaneWindow;
    UINT8       TxSeq;
    UINT8       RxSeq;
    UINT8       MaxTxSeq;
    UINT8       FlowControl;
    BOOLEAN     TxFlowStopped;

    BOOLEAN     TxGlom;
    ULONG       TxGlomBytes;

    BOOLEAN     RetentionInitialized;
    BOOLEAN     SaveRestoreEnabled;
    BOOLEAN     Sleeping;
    UCHAR       AwakeSepInt;
    BOOLEAN     SepIntSaved;
    BOOLEAN     ClockOn;
    AP6256_LOCK Lock;
    AP6256_LOCK TxLock;
    KSPIN_LOCK  TxStateLock;
} AP6256_SDIO, *PAP6256_SDIO;

typedef struct _AP6256_BCDC {
    UINT32      RequestId;
    AP6256_LOCK Lock;
    UINT8*      IoctlBuffer;
    ULONG       IoctlBufferSize;
    UINT8*      ResponseBuffer;
    ULONG       ResponseBufferSize;
    ULONG       ResponseLength;
    UINT16      PendingId;
    UINT32      PendingCommand;
    UCHAR       PendingIfIndex;
    BOOLEAN     PendingSet;
    CHAR        PendingIovar[32];
    BOOLEAN     Pending;
    BOOLEAN     Initialized;
    NTSTATUS    ResponseStatus;
    KEVENT      ResponseEvent;
    KSPIN_LOCK  ResponseLock;
} AP6256_BCDC, *PAP6256_BCDC;

typedef enum _AP6256_FW_STATE {
    Ap6256FwNotLoaded = 0,
    Ap6256FwDownloading,
    Ap6256FwRunning,
    Ap6256FwError
} AP6256_FW_STATE;

#define AP6256_RXF_DIRECTED      0x0001
#define AP6256_RXF_MULTICAST     0x0002
#define AP6256_RXF_ALL_MULTICAST 0x0004
#define AP6256_RXF_BROADCAST     0x0008
#define AP6256_RXF_PROMISCUOUS   0x0020

typedef enum _AP6256_TRACE_SLOT {
    Ap6256TraceTxTalSend = 0,
    Ap6256TraceTxSendComplete,
    Ap6256TraceTxDescInit,
    Ap6256TraceTxDescDeInit,
    Ap6256TraceTxQueueInOrder,
    Ap6256TraceTxPeerBacklog,
    Ap6256TraceTxComplete,
    Ap6256TraceTxBuildFail,
    Ap6256TraceRxReturn,
    Ap6256TraceRxPpduRssi,
    Ap6256TraceRxClaimDenied,
    Ap6256TraceRxPullStopped,
    Ap6256TraceRxNotifyPaused,
    Ap6256TraceRxIndicate,
    Ap6256TraceRxIndicateDone,
    Ap6256TraceRxFrameDump,
    Ap6256TraceRxNblBuilt,
    Ap6256TraceRxBuildFail,
    Ap6256TraceRxFiltered,
    Ap6256TraceRxRefused,
    Ap6256TraceRxResumed,
    Ap6256TraceRxQueueFull,
    Ap6256TraceRxStale,
    Ap6256TraceSlotCount
} AP6256_TRACE_SLOT;

typedef enum _AP6256_TAL_CALL {

    Ap6256CallTxAbort = 0,
    Ap6256CallRxStop,
    Ap6256CallRxFlush,
    Ap6256CallRxRestart,
    Ap6256CallRxResume,
    Ap6256CallRxThrottle,
    Ap6256CallTalStart,
    Ap6256CallTalStop,
    Ap6256CallAddPort,
    Ap6256CallDeletePort,
    Ap6256CallSetPortOpMode,
    Ap6256CallResetPort,
    Ap6256CallPeerConfig,
    Ap6256CallPeerDeleteConfirm,

    Ap6256CallUpRxInorderData,
    Ap6256CallUpPeerCreate,
    Ap6256CallUpPeerDelete,
    Ap6256CallUpTxDequeue,
    Ap6256CallUpTxTransferComplete,
    Ap6256CallUpTxSendComplete,
    Ap6256CallUpTxSendPause,
    Ap6256CallUpTxSendRestart,
    Ap6256CallUpTxAbortConfirm,
    Ap6256CallUpRxFlushConfirm,
    Ap6256CallUpAllocMetadata,
    Ap6256CallUpFreeMetadata,
    Ap6256CallCount
} AP6256_TAL_CALL;

#define AP6256_P2P_SECONDARY_MAX    5u
#define AP6256_P2P_DEVICE_NAME_MAX  32u

#define AP6256_P2P_IE_BEACON        0x0001u
#define AP6256_P2P_IE_PROBE_RESP    0x0002u
#define AP6256_P2P_IE_ASSOC_RESP    0x0004u
#define AP6256_P2P_IE_PROBE_REQ     0x0010u
#define AP6256_P2P_IE_ASSOC_REQ     0x0020u
#define AP6256_P2P_IE_CUSTOM        0x0100u

typedef enum _AP6256_P2P_FRAME {
    Ap6256P2pFrameProbeRequest = 0,
    Ap6256P2pFrameProbeResponse,
    Ap6256P2pFrameBeacon,
    Ap6256P2pFrameAssocResponse,
    Ap6256P2pFrameAssocRequest,
    Ap6256P2pFrameMax
} AP6256_P2P_FRAME;

typedef struct _AP6256_P2P_DEVICE_TYPE {
    UINT16 Category;
    UCHAR  Oui[4];
    UINT16 Subcategory;
} AP6256_P2P_DEVICE_TYPE;

typedef struct _AP6256_P2P_IE_SLOT {
    PUCHAR Bytes;
    ULONG  Length;
} AP6256_P2P_IE_SLOT;

#define AP6256_P2P_DISCOVER_SSID_MAX     16u
#define AP6256_P2P_DISCOVER_CHANNEL_MAX 64u

typedef struct _AP6256_P2P_DISCOVER_SSID {
    UCHAR Data[32];
    ULONG Length;
} AP6256_P2P_DISCOVER_SSID;

typedef struct _AP6256_P2P_DISCOVER_CHANNEL {
    UINT16 Number;
    UINT32 DwellMs;
    UINT32 CycleMs;
} AP6256_P2P_DISCOVER_CHANNEL;

typedef struct _AP6256_P2P_DISCOVER {
    UINT32 DiscoveryType;
    BOOLEAN ForcedDiscovery;
    BOOLEAN ActiveScan;
    BOOLEAN OmitListenChannel;
    UINT32 MaximumDwellMs;
    UINT32 ScanRepeatCount;
    UINT32 TimeBetweenScans;
    UINT32 ActiveDwellMs;
    UINT32 PassiveDwellMs;
    ULONG SsidCount;
    AP6256_P2P_DISCOVER_SSID Ssids[AP6256_P2P_DISCOVER_SSID_MAX];
    ULONG ChannelCount;
    AP6256_P2P_DISCOVER_CHANNEL Channels[AP6256_P2P_DISCOVER_CHANNEL_MAX];
} AP6256_P2P_DISCOVER, *PAP6256_P2P_DISCOVER;

typedef struct _AP6256_P2P_STATE {

    UCHAR  DeviceCapability;
    UCHAR  GroupCapability;
    UCHAR  AssocStatus;
    UCHAR  DeviceAddress[6];
    UINT16 ConfigMethods;
    AP6256_P2P_DEVICE_TYPE PrimaryType;
    ULONG  SecondaryCount;
    AP6256_P2P_DEVICE_TYPE Secondary[AP6256_P2P_SECONDARY_MAX];
    ULONG  DeviceNameLength;
    UCHAR  DeviceName[AP6256_P2P_DEVICE_NAME_MAX];

    UCHAR  ListenChannel;
    UINT16 ListenActiveMs;
    UINT16 ListenCycleMs;
    UINT32 ListenState;
    BOOLEAN Listening;
    BOOLEAN OmitProbeRequestListenChannel;
    NTSTATUS DiscoverStatus;
    volatile LONG DiscoverScanPending;

    UCHAR  CountryString[3];

    UCHAR  OperatingClass;
    UCHAR  OperatingChannel;

    AP6256_P2P_IE_SLOT HostIes[Ap6256P2pFrameMax];
    AP6256_P2P_IE_SLOT DriverIes[Ap6256P2pFrameMax];

    AP6256_P2P_DISCOVER Discover;
    ULONG   DiscoverPhase;
    ULONG   DiscoverSsidIndex;
    ULONG   DiscoverChannelIndex;
    ULONG   DiscoverScansCompleted;
    BOOLEAN DiscoverSearch;
    BOOLEAN DiscoverPassComplete;
    LONGLONG DiscoverDeadline;
    LONGLONG DiscoverNextScan;
    LONGLONG DiscoverChannelDeadline;
} AP6256_P2P_STATE, *PAP6256_P2P_STATE;

#define AP6256_STATION_PORT 0u
#define AP6256_DISCOVERY_PORT 1u
#define AP6256_GROUP_PORT 2u
#define AP6256_P2P_CLIENT_ROLES 1u
#define AP6256_GO_CLIENTS 8u
#define AP6256_GO_PEERS (AP6256_GO_CLIENTS + 1u)

typedef struct _AP6256_GO_PEER {
    UCHAR Address[6];
    BOOLEAN Active;
    BOOLEAN DeletePending;
    BOOLEAN RxOpen;
    UINT32 PhyId;
    ULONGLONG RxGeneration;
} AP6256_GO_PEER;

typedef enum _AP6256_GO_DATA_STAGE {
    Ap6256GoDataRxBus,
    Ap6256GoDataRxFiltered,
    Ap6256GoDataRxQueued,
    Ap6256GoDataTxQueued,
    Ap6256GoDataTxTransfer,
    Ap6256GoDataRxWdi,
    Ap6256GoDataStageCount
} AP6256_GO_DATA_STAGE;

typedef struct _AP6256_GO_STATE {
    BOOLEAN Created;
    BOOLEAN FirmwareReady;
    BOOLEAN NativeStateUncertain;
    BOOLEAN Started;
    BOOLEAN TalAdded;
    BOOLEAN Stopping;
    BOOLEAN WpsEnabled;
    BOOLEAN RxStopped;
    UINT32 Mode;
    UINT32 BssIndex;
    UINT32 IfIndex;
    UINT32 Channel;
    UCHAR Address[6];
    volatile LONG PacketFilter;

    volatile LONG DataTrace[Ap6256GoDataStageCount];

    volatile LONG Ipv4Trace[2][Ap6256GoDataStageCount];
    UCHAR ClientBssid[6];
    BOOLEAN ClientConnected;
    BOOLEAN ClientSecure;
    BOOLEAN ClientMfp;
    CHAR ClientRssiDbm;
    AP6256_GO_PEER Peers[AP6256_GO_PEERS];
    AP6256_P2P_STATE P2p;
} AP6256_GO_STATE;

typedef struct _AP6256_CONNECTION_QUALITY {
    KMUTEX Lock;
    BOOLEAN Initialized;
    BOOLEAN PowerSaveRequested;
    BOOLEAN MchanSaved;
    UINT32 SavedMchanAlgorithm;
    UINT32 SavedMchanBandwidth;
    BOOLEAN GroupPmSaved;
    UINT32 SavedGroupPm;
    UINT32 GroupPmIfIndex;
    UINT32 Hints[AP6256_GROUP_PORT + 1];
} AP6256_CONNECTION_QUALITY;

#define AP6256_NATIVE_KEY_SLOTS 32u

typedef struct _AP6256_NATIVE_KEY_REF {
    ULONG KeyId;
    UCHAR PeerAddress[6];
    BOOLEAN Pairwise;
    BOOLEAN Management;
    BOOLEAN Valid;
} AP6256_NATIVE_KEY_REF;

typedef struct _AP6256_DEVICE_CONTEXT {
    AP6256_GO_STATE Go;
    AP6256_CONNECTION_QUALITY ConnectionQuality;

    volatile LONG FirmwareIfMap[16];
#include <device_fields.h>

    PDEVICE_OBJECT  Fdo;
    PDEVICE_OBJECT  Pdo;
    PDEVICE_OBJECT  NextDevice;

    AP6256_SDIO     Sdio;
    AP6256_CHIP     Chip;
    AP6256_BCDC     Bcdc;

    AP6256_FW_STATE FirmwareState;
    KSPIN_LOCK HostFipsLock;
    AP6256_FIPS_SESSION HostFipsSessions[16];
    UINT32 HostFipsNextGeneration, HostFipsBlockedMask, HostFipsRetiredMask;
    BOOLEAN HostFipsReady;
    AP6256_HC_STORE HostCipherStore;

    volatile LONG HostCipherFirmwareQualified;
    KMUTEX HostCipherControlLock;

    volatile LONG HostCipherBlockedMask;
    UINT32 HostCipherNextGeneration;
    volatile LONG  FirmwareIoQuiesced;
    ULONGLONG      RetainedSleepStarted;
    AP6256_POWER_SAVE_DX PowerSaveDx[2];
    PKTHREAD       PowerThread;
    volatile LONG  HostTxQuiesced;
    volatile LONG  FirmwareHalted;
    AP6256_FW_CRASH FirmwareCrash;
    UINT8           MacAddress[6];

    UINT8           PermanentMacAddress[6];
    BOOLEAN         PermanentMacAddressValid;
    UINT8           ConfiguredMacAddress[6];
    BOOLEAN         ConfiguredMacAddressValid;
    UINT8           D11IoType;

    AP6256_WORKITEM FrameWorker;
    AP6256_WATCHDOG Watchdog;
    struct _AP6256_WLFC* Wlfc;

    AP6256_LOCK     WlfcLifetimeLock;
    UINT8*          RxScratch;
    ULONG           RxScratchSize;
    UINT8*          TxScratch;
    ULONG           TxScratchSize;
    UINT16          GlomLengths[64];
    ULONG           GlomCount;
    ULONG           GlomTotalLength;

    ULONG           GlomErrors;

    ULONG           RxNextLength;

    BOOLEAN         RxSkip;
    ULONGLONG       RxSkipSince;

    BOOLEAN         RxBatching;
    ULONG           RxBatched;

    volatile LONG   IsrHeldOff;

    volatile LONG   FrameDraining;
    volatile LONG   FrameRerun;

    volatile LONG   PacketFilter;

    BOOLEAN FirmwareSaeSupported;
    BOOLEAN FirmwareExternalAuth;
    BOOLEAN FirmwareMfpSupported;

    BOOLEAN FirmwareNativeManagement;
    BOOLEAN FirmwareMboTransport;

    BOOLEAN FirmwareSaePatchVerified;
    BOOLEAN FirmwarePrivateSaeAbi;
    BOOLEAN FirmwarePrivateSae;

    BOOLEAN FirmwareHostFt;
    BOOLEAN FirmwareFtPatchVerified;
    BOOLEAN FirmwareOwePatchVerified, FirmwareHostOwe;
    BOOLEAN FirmwareServicePatchVerified, FirmwareServiceOffload;
    BOOLEAN FirmwareFtmPatchVerified, FirmwareFtmSupported;
    BOOLEAN FirmwareHostCipherPatchVerified;

    UINT32 FirmwareOweGeneration, FirmwareOweNextGeneration;
    UCHAR FirmwareOwePeer[6];

    BOOLEAN FirmwareBssTransitionEnabled;

    BOOLEAN FirmwareArpOffloadSupported;
    BOOLEAN FirmwareNdOffloadSupported;
    BOOLEAN FirmwareWowlAdapter;
    BOOLEAN FirmwareGtkOffloadSupported;

    BOOLEAN FirmwareP2pSupported;
    BOOLEAN FirmwareMchanSupported;

    AP6256_LOCK TdlsLock;
    AP6256_LOCK PnoLock;
    BOOLEAN FirmwareEnhancedPnoSupported;
    BOOLEAN FirmwarePnoDelaySupported;

    BOOLEAN FirmwarePnoGscanSupported;
    BOOLEAN FirmwarePnoExtendedEvents;
    struct _AP6256_PNO_STATE* PnoState;
    BOOLEAN FirmwareTdlsSupported;
    BOOLEAN TdlsBlocked;
    UINT32 TdlsRequestedMode;
    volatile LONG TdlsActiveMode;
    volatile LONG TdlsDiscoveredEvents;
    volatile LONG TdlsConnectedEvents;
    volatile LONG TdlsDisconnectedEvents;

    UINT32  BtCoexMode;

    UINT32  SavedBeaconListenDtim;
    UINT32  SavedRoamOff;
    UINT32  SavedPowerSaveMode;
    UINT32  SavedD0FilterEnable;
    BOOLEAN SavedD0FilterValid;
    BOOLEAN SavedLowPowerStateValid;
    BOOLEAN SavedBeaconListenValid;
    BOOLEAN SavedRoamOffValid;
    BOOLEAN SavedPowerSaveValid;

    ULONGLONG LinkRateTracedAt;
    ULONGLONG MacCountersTracedAt;

    UINT32  PacketFilterMask;

    UINT32  WakeEnabledPatterns;
    UINT32  WakeEnabledOffloads;
    UINT32  WakeUpFlags;
    UINT32  WakeMediaSpecificEvents;

    BOOLEAN LowPowerArmed;

    UINT32  P2pBssIndex;
    UINT32  P2pInterfaceIndex;
    BOOLEAN P2pBssValid;
    BOOLEAN P2pInterfaceValid;

    INT32   RoamRssiTriggerDbm;
    volatile LONG BeaconLossTimeoutSeconds;
    volatile LONG NloScanMode;

    UINT32  PacketFilterMax;

    UINT32  WowlCapabilities;

    AP6256_P2P_STATE P2p;

    volatile LONG   RxFrames;

    volatile LONG   RxFiltered;
    volatile LONG   TxFrames;
    volatile LONG   ScanSyncId;

    BOOLEAN         AllMulticastRequested;
    BOOLEAN         PromiscuousRequested;

    BOOLEAN         DatapathRunning;
    BOOLEAN         ConnectionRequiresSupplicant;
    BOOLEAN         FirmwareLinkUp;
    BOOLEAN         SupplicantComplete;
    AP6256_LOCK     NativeKeyLock;
    AP6256_NATIVE_KEY_REF NativeKeys[AP6256_NATIVE_KEY_SLOTS];
    BOOLEAN         NativeDeparturePending;
    BOOLEAN         NativeDepartureCommitted;
    UINT32          NativeDepartureToken;
    UINT32          NativeDepartureNext;
    UINT32          NativeDepartureReason;
    UCHAR           NativeDeparturePeer[6];

    PVOID           NetAdapter;

    UINT16          SdioVendorId;
    UINT16          SdioDeviceId;
} AP6256_DEVICE_CONTEXT, *PAP6256_DEVICE_CONTEXT;
#include <device_context.h>

DRIVER_INITIALIZE             DriverEntry;
#include <device_callbacks.h>

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BringUpChip(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ BOOLEAN OnCommandWorker);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256TearDownChip(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_ BOOLEAN OnCommandWorker);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WdiChipUp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                          _In_ BOOLEAN OnCommandWorker);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WdiChipDown(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                        _In_ BOOLEAN OnCommandWorker);
