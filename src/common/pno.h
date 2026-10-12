/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "wifi_ops.h"

#define AP6256_PNO_MAGIC       0x314f4e50u
#define AP6256_PNO_VERSION     1u
#define AP6256_PNO_QUERY       0u
#define AP6256_PNO_STOP        1u
#define AP6256_PNO_START       2u
#define AP6256_PNO_OVERRIDE    3u
#define AP6256_PNO_MAC         4u
#define AP6256_PNO_FLAGS       5u
#define AP6256_PNO_READ_RESULT 6u
#define AP6256_PNO_FETCH_BATCH 7u
#define AP6256_PNO_CHANNEL_MAX 64u
#define AP6256_PNO_BUCKET_MAX  16u
#define AP6256_PNO_SWC_MAX     16u
#define AP6256_PNO_USE_MAC      1u
#define AP6256_PNO_USE_OVERRIDE 2u
#define AP6256_PNO_USE_SWC      4u
#define AP6256_PNO_USE_BATCH    8u
#define AP6256_PNO_STATUS_GSCAN 1u
#define AP6256_PNO_STATUS_DELAY 2u

#pragma pack(push, 1)

typedef struct _AP6256_PNO_BUCKET {
    UINT16 EndIndex;
    UCHAR FrequencyMultiple;
    UCHAR Flags;
} AP6256_PNO_BUCKET;

typedef struct _AP6256_PNO_GSCAN {
    UINT16 Version;
    UCHAR Flags;
    UCHAR BufferThreshold;
    UCHAR SwcThreshold;
    UCHAR RssiWindow;
    UCHAR BucketCount;
    UCHAR RetryThreshold;
    UINT16 LostApWindow;
    AP6256_PNO_BUCKET Buckets[AP6256_PNO_BUCKET_MAX];
} AP6256_PNO_GSCAN;

typedef struct _AP6256_PNO_SWC_ENTRY {
    UCHAR Bssid[6];
    CHAR RssiLow;
    CHAR RssiHigh;
} AP6256_PNO_SWC_ENTRY;

typedef struct _AP6256_PNO_OVERRIDE_PARAMS {
    UINT16 Version;
    UINT16 StartOffsetSeconds;
    UINT16 DurationSeconds;
    UINT16 Reserved;
    INT32 ScanSeconds;
    INT32 LostSeconds;
    UINT16 Flags;
    UCHAR Exponent;
    UCHAR Repeat;
    INT32 SlowSeconds;
} AP6256_PNO_OVERRIDE_PARAMS;

typedef struct _AP6256_PNO_MAC_PARAMS {
    UCHAR Version;
    UCHAR Flags;
    UCHAR Address[6];
} AP6256_PNO_MAC_PARAMS;

typedef struct _AP6256_PNO_CONFIG {
    UINT32 ChannelCount;
    UINT16 Channels[AP6256_PNO_CHANNEL_MAX];
    AP6256_PNO_GSCAN Gscan;
    UINT32 Options;
    UINT32 SwcCount;
    AP6256_PNO_SWC_ENTRY Swc[AP6256_PNO_SWC_MAX];
    AP6256_PNO_OVERRIDE_PARAMS Override;
    AP6256_PNO_MAC_PARAMS Mac;
} AP6256_PNO_CONFIG;

typedef struct _AP6256_PNO_REQUEST {
    UINT32 Magic;
    UINT16 Version;
    UINT16 Operation;
} AP6256_PNO_REQUEST;
typedef struct _AP6256_PNO_NETWORK {
    UINT32 SsidLength;
    UINT32 AuthAlgorithm;
    UINT32 CipherAlgorithm;
    UINT32 DirectedProbePermitted;
    UCHAR Ssid[32];
} AP6256_PNO_NETWORK;
typedef struct _AP6256_PNO_START_PARAMS {
    UINT32 ScanPeriodSeconds;
    UINT32 NetworkCount;
    AP6256_PNO_NETWORK Networks[AP6256_NLO_NETWORK_MAX];
    AP6256_PNO_CONFIG Config;
} AP6256_PNO_START_PARAMS;
typedef struct _AP6256_PNO_STATUS {
    UINT32 Version;
    UINT32 Supported;
    UINT32 Enabled;
    UINT32 Reserved;
} AP6256_PNO_STATUS;

typedef struct _AP6256_PNO_RESULT {
    UINT32 Kind, Sequence, AgeMilliseconds, Flags, SsidLength;
    UCHAR Bssid[6];
    UINT16 Channel;
    INT16 Rssi;
    UINT16 BeaconPeriod, Capability;
    UCHAR RssiCount, Reserved;
    UCHAR Ssid[32];
    CHAR RssiHistory[8];
    UINT32 IesLength;
    UCHAR Ies[AP6256_SCAN_IE_MAX];
} AP6256_PNO_RESULT;
typedef struct _AP6256_PNO_RESULT_REPLY {
    UINT32 Version, Remaining, Dropped, Generation;
    AP6256_PNO_RESULT Result;
} AP6256_PNO_RESULT_REPLY;
#pragma pack(pop)

C_ASSERT(sizeof(AP6256_PNO_BUCKET) == 4);
C_ASSERT(FIELD_OFFSET(AP6256_PNO_GSCAN, Buckets) == 10);
C_ASSERT(sizeof(AP6256_PNO_SWC_ENTRY) == 8);
C_ASSERT(sizeof(AP6256_PNO_OVERRIDE_PARAMS) == 24);
C_ASSERT(sizeof(AP6256_PNO_MAC_PARAMS) == 8);
C_ASSERT(sizeof(AP6256_PNO_CONFIG) == 374);
C_ASSERT(sizeof(AP6256_PNO_REQUEST) == 8);
C_ASSERT(sizeof(AP6256_PNO_NETWORK) == 48);
C_ASSERT(sizeof(AP6256_PNO_START_PARAMS) == 1150);
C_ASSERT(sizeof(AP6256_PNO_STATUS) == 16);
C_ASSERT(sizeof(AP6256_PNO_RESULT) == 2128);
C_ASSERT(sizeof(AP6256_PNO_RESULT_REPLY) == 2144);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256PnoIdentify(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) PUCHAR Image, _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoValidateConfig(_In_ const AP6256_PNO_CONFIG* Config);

BOOLEAN Ap6256PnoConfigNeedsGscan(_In_ const AP6256_PNO_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoApplyChannelsLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_PNO_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoApplyConfig(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_PNO_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoGetEnabledLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ UINT32* Enabled);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetEnhancedNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_NLO_PARAMS* Params, _In_ const AP6256_PNO_CONFIG* Config);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoControl(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Request, _In_ ULONG Length,
    _Out_ AP6256_PNO_STATUS* Status);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoResultsInitialize(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256PnoEnableResultEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256PnoResultsQuiesce(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256PnoResultsDestroy(_In_ PAP6256_DEVICE_CONTEXT Ctx);

VOID Ap6256PnoResultsReset(_In_ PAP6256_DEVICE_CONTEXT Ctx);
VOID Ap6256PnoResultsCommit(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_NLO_PARAMS* Params, _In_ BOOLEAN Batch);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256PnoResultsPower(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN D0);
BOOLEAN Ap6256PnoWindowsActive(_In_ PAP6256_DEVICE_CONTEXT Ctx);
NTSTATUS Ap6256PnoDecodeResult(_In_ UINT32 Event,
    _In_reads_bytes_(Length) const UCHAR* Data, _In_ ULONG Length, _In_ ULONG Index,
    _Out_ AP6256_PNO_RESULT* Result, _Out_ UINT32* Count, _Out_ UINT32* Status);
VOID Ap6256PnoResultEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Event,
    _In_reads_bytes_(Length) const UCHAR* Data, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoResultControl(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_bytes_(Length) const UCHAR* Data, _In_ ULONG Length,
    _Out_ AP6256_PNO_RESULT_REPLY* Reply);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiPnoChannels(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_ AP6256_PNO_CONFIG* Config, _In_ BOOLEAN Fill);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetWindowsNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_NLO_PARAMS* Params,
    _In_reads_(HintCount) const UINT16* Hints, _In_ ULONG HintCount);
