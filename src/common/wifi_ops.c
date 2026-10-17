/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "wifi_ops.h"
#include "quality.h"
#include "host_fips.h"
#include "host_cipher_control.h"
#include "host_cipher_transport.h"
#include "sdio.h"
#include "datapath.h"
#include "netadapter.h"
#include "wlfc.h"
#include "pno.h"
#include "bcdc.h"
#include "p2p.h"
#include "service.h"
#include "ftm_firmware.h"
#include "mbo.h"
#include "hotspot.h"
#include "sae_fw.h"
#include "owe.h"
#include "ft.h"
#include "wlfc.h"
#include "power_stats.inc"

#define WSEC_WEP_ENABLED            0x0001
#define WSEC_TKIP_ENABLED           0x0002
#define WSEC_AES_ENABLED            0x0004
#define SES_OW_ENABLED              0x0040
#define WSEC_MFP_CAPABLE            0x0200
#define WSEC_MFP_REQUIRED           0x0400
#define WSEC_SHA256_KDF             0x0800

#define WPA_AUTH_DISABLED           0x0000
#define WPA2_AUTH_UNSPECIFIED       0x0040
#define WPA2_AUTH_PSK               0x0080
#define WPA2_AUTH_1X_SHA256         0x1000

#define AP6256_BTCOEX_DISABLED       0u
#define AP6256_BTCOEX_ENABLED        1u
#define AP6256_BTCOEX_AUTO           3u
#define AP6256_BTC_MODE_AUTO         8u

#define WLC_BAND_AUTO               0u
#define WLC_BAND_5G                 1u
#define WLC_BAND_2G                 2u
#define WLC_BAND_ALL                3u

#define AP6256_PM_OFF               0u
#define AP6256_PM_MAX               1u
#define AP6256_PM_FAST              2u

#define AP6256_BANDLIST_MAX         3u

#define AP6256_VALID_CHANNELS_MAX   65u

#include <pshpack1.h>
typedef struct _BRCMF_REV_INFO {
    UINT32 VendorId;
    UINT32 DeviceId;
    UINT32 RadioRev;
    UINT32 ChipRev;
    UINT32 CoreRev;
    UINT32 BoardId;
    UINT32 BoardVendor;
    UINT32 BoardRev;
    UINT32 DriverRev;
    UINT32 UcodeRev;
    UINT32 Bus;
    UINT32 ChipNum;
    UINT32 PhyType;
    UINT32 PhyRev;
    UINT32 AnaRev;
    UINT32 ChipPkg;
    UINT32 NvramRev;

    UINT32 Reserved;
} BRCMF_REV_INFO, *PBRCMF_REV_INFO;
#include <poppack.h>
C_ASSERT(sizeof(BRCMF_REV_INFO) == 72);

C_ASSERT(sizeof(AP6256_PKT_COUNTS) == 20);

#define AP6256_RADIO_UPDOWN_ARG   1u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRadioUpDown(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _In_ BOOLEAN Up)
{
    UINT32 arg = AP6256_RADIO_UPDOWN_ARG;

    return Ap6256BcdcSetDcmd(Ctx, Up ? BRCMF_C_UP : BRCMF_C_DOWN,
                             &arg, sizeof(arg));
}

#include <pshpack1.h>

typedef struct _BRCMF_SCB_VAL {
    UINT32 Value;
    UCHAR  Address[6];
    UCHAR  Pad[2];
} BRCMF_SCB_VAL;

C_ASSERT(sizeof(BRCMF_SCB_VAL) == 12);

#define AP6256_ASSOCLIST_MAX 122u
typedef struct _BRCMF_ASSOCLIST {
    UINT32 Count;
    UCHAR  Addresses[AP6256_ASSOCLIST_MAX][6];
} BRCMF_ASSOCLIST;

typedef struct _BRCMF_RATESET {
    UINT32 Count;
    UCHAR  Rates[16];
} BRCMF_RATESET;

typedef struct _BRCMF_COUNTRY {
    CHAR   Abbrev[4];
    INT32  Revision;
    CHAR   Ccode[4];
} BRCMF_COUNTRY;

typedef struct _BRCMF_REASSOC_PARAMS {
    UCHAR  Bssid[6];
    UCHAR  Reserved[2];
    INT32  ChanspecNum;
    UINT16 ChanspecList[1];
} BRCMF_REASSOC_PARAMS;

#include <poppack.h>

#define AP6256_BEACON_LOSS_TIMEOUT_SECONDS 4u

#define WL_RADIO_SW_DISABLE         (1u << 0)
#define WL_RADIO_HW_DISABLE         (1u << 1)

#define AP6256_SHORT_RETRY_LIMIT    7u
#define AP6256_LONG_RETRY_LIMIT     4u

#define BRCMF_WSEC_PASSPHRASE       0x0001
#define BRCMF_WSEC_MAX_PSK_LEN      64

#define BRCMF_CRYPTO_ALGO_AES_CCM   4
#define BRCMF_PRIMARY_KEY           (1u << 1)

#define AP6256_ROLE_STA                0x04u
#define AP6256_ROLE_P2P_DEVICE         0x10u
#define AP6256_ROLE_P2P_GO             0x20u
#define AP6256_ROLE_P2P_CLIENT         0x40u

#define BRCMF_ARP_OL_AGENT            0x00000001u
#define BRCMF_ARP_OL_SNOOP            0x00000008u

#define AP6256_D0_FILTER_NETBIOS_NS   0x0002u
#define AP6256_D0_FILTER_LLMNR        0x0004u
#define AP6256_D0_FILTER_SSDP         0x0008u
#define AP6256_D0_FILTER_WSD          0x0010u
#define AP6256_D0_FILTER_LLMNR_V6     0x0400u
#define AP6256_D0_FILTER_SSDP_V6      0x0800u
#define AP6256_D0_FILTER_WSD_V6       0x1000u

#define AP6256_UDP_PORT_NETBIOS_NS    137u
#define AP6256_UDP_PORT_SSDP          1900u
#define AP6256_UDP_PORT_WSD           3702u
#define AP6256_UDP_PORT_LLMNR         5355u

#define BRCMF_VNDR_IE_BEACON_FLAG    0x0001u
#define BRCMF_VNDR_IE_PRBRSP_FLAG    0x0002u
#define BRCMF_VNDR_IE_ASSOCRSP_FLAG  0x0004u
#define BRCMF_VNDR_IE_AUTHRSP_FLAG   0x0008u
#define BRCMF_VNDR_IE_PRBREQ_FLAG    0x0010u
#define BRCMF_VNDR_IE_ASSOCREQ_FLAG  0x0020u
#define BRCMF_VNDR_IE_CUSTOM_FLAG    0x0100u

#define BRCMF_P2P_DISC_ST_SCAN       0u
#define BRCMF_P2P_DISC_ST_LISTEN     1u
#define BRCMF_P2P_DISC_ST_SEARCH     2u

#define AP6256_P2P_LISTEN_ACTIVE_DEFAULT   20u
#define AP6256_P2P_LISTEN_CYCLE_DEFAULT    130u
#define AP6256_P2P_LISTEN_ACTIVE_HIGH      300u
#define AP6256_P2P_LISTEN_CYCLE_HIGH       400u

#define AP6256_P2P_SOCIAL_CHANNEL_COUNT    3u

#define BRCMF_ESCAN_REQ_VERSION     1
#define WL_ESCAN_ACTION_START       1
#define WL_ESCAN_ACTION_ABORT       3
#define DOT11_BSSTYPE_ANY           2
#define BRCMF_SCANTYPE_DEFAULT      ((INT8)-1)
#define BRCMF_SCANTYPE_ACTIVE       0
#define BRCMF_SCANTYPE_PASSIVE      1

#define BRCMU_D11N_IOTYPE           1
#define BRCMU_D11AC_IOTYPE          2
#define BRCMU_CHSPEC_D11N_SB_NONE   0x0300u
#define BRCMU_CHSPEC_D11N_BW_20     0x0800u
#define BRCMU_CHSPEC_D11N_BAND_5G   0x1000u
#define BRCMU_CHSPEC_D11N_BAND_2G   0x2000u
#define BRCMU_CHSPEC_D11AC_BW_20    0x1000u
#define BRCMU_CHSPEC_D11AC_BAND_5G  0xC000u
#define BRCMU_CHSPEC_D11AC_BAND_2G  0x0000u

#pragma pack(push, 1)

typedef struct _WLC_SSID {
    UINT32 SsidLen;
    UCHAR  Ssid[32];
} WLC_SSID;

typedef struct _BRCMF_SCAN_PARAMS {
    WLC_SSID Ssid;
    UCHAR    Bssid[6];
    INT8     BssType;
    INT8     ScanType;
    INT32    NProbes;
    INT32    ActiveTime;
    INT32    PassiveTime;
    INT32    HomeTime;
    INT32    ChannelNum;
    UINT16   ChannelList[1];
} BRCMF_SCAN_PARAMS;

typedef struct _BRCMF_ESCAN_PARAMS {
    UINT32 Version;
    UINT16 Action;
    UINT16 SyncId;
    BRCMF_SCAN_PARAMS Params;
} BRCMF_ESCAN_PARAMS;

typedef struct _BRCMF_VNDR_IE_BUF {
    CHAR   Command[4];
    UINT32 Count;

} BRCMF_VNDR_IE_BUF;

typedef struct _BRCMF_P2P_DISC_STATE {
    UCHAR  State;
    UCHAR  Pad;
    UINT16 Chanspec;
    UINT16 DwellMs;
} BRCMF_P2P_DISC_STATE;

C_ASSERT(sizeof(BRCMF_P2P_DISC_STATE) == 6);

typedef struct _BRCMF_P2P_DISC_BSSCFG {
    UINT32 BssIndex;
    BRCMF_P2P_DISC_STATE State;
} BRCMF_P2P_DISC_BSSCFG;

C_ASSERT(sizeof(BRCMF_P2P_DISC_BSSCFG) == 10);

typedef struct _BRCMF_P2P_SCAN_PARAMS {
    UCHAR  Type;
    UCHAR  Pad[3];
    BRCMF_ESCAN_PARAMS Escan;
} BRCMF_P2P_SCAN_PARAMS;

typedef struct _BRCMF_ASSOC_PARAMS {
    UCHAR  Bssid[6];
    UCHAR  Reserved[2];
    INT32  ChanspecNum;
    UINT16 ChanspecList[1];
} BRCMF_ASSOC_PARAMS;

typedef struct _BRCMF_JOIN_PARAMS {
    WLC_SSID Ssid;
    BRCMF_ASSOC_PARAMS Params;
} BRCMF_JOIN_PARAMS;

typedef struct _BRCMF_WSEC_PMK {
    UINT16 KeyLen;
    UINT16 Flags;
    UCHAR  Key[BRCMF_WSEC_MAX_PSK_LEN];
} BRCMF_WSEC_PMK;

typedef struct _BRCMF_CHANNEL_INFO {
    UINT32 HardwareChannel;
    UINT32 TargetChannel;
    UINT32 ScanChannel;
} BRCMF_CHANNEL_INFO;

#define BRCMF_BSS_FLAGS_FROM_BEACON 0x01u
#define BRCMF_BSS_FLAGS_FROM_CACHE  0x02u

typedef struct _BRCMF_BSS_INFO {
    UINT32 Version;
    UINT32 Length;
    UCHAR  Bssid[6];
    UINT16 BeaconPeriod;
    UINT16 Capability;
    UCHAR  SsidLen;
    UCHAR  Ssid[32];
    UCHAR  ReservedAfterSsid;
    struct { UINT32 Count; UCHAR Rates[16]; } Rateset;
    UINT16 Chanspec;
    UINT16 AtimWindow;
    UCHAR  DtimPeriod;
    UCHAR  ReservedAfterDtim;
    INT16  Rssi;
    INT8   PhyNoise;
    UCHAR  NCap;
    UCHAR  ReservedBeforeNbss[2];
    UINT32 NbssCap;
    UCHAR  ControlChannel;
    UCHAR  ReservedBeforeReserved32[3];
    UINT32 Reserved32;
    UCHAR  Flags;
    UCHAR  Reserved[3];
    UCHAR  BasicMcs[16];
    UINT16 IeOffset;
    UCHAR  ReservedBeforeIeLength[2];
    UINT32 IeLength;
    UINT16 Snr;
    UCHAR  ReservedTail[2];
} BRCMF_BSS_INFO;

typedef struct _BRCMF_ESCAN_RESULT {
    UINT32 BufLen;
    UINT32 Version;
    UINT16 SyncId;
    UINT16 BssCount;
    BRCMF_BSS_INFO BssInfo;
} BRCMF_ESCAN_RESULT;

#pragma pack(pop)

C_ASSERT(sizeof(WLC_SSID) == 36);
C_ASSERT(sizeof(BRCMF_CHANNEL_INFO) == 12);
C_ASSERT(FIELD_OFFSET(BRCMF_SCAN_PARAMS, ChannelList) == 64);
C_ASSERT(FIELD_OFFSET(BRCMF_ASSOC_PARAMS, ChanspecNum) == 8);
C_ASSERT(FIELD_OFFSET(BRCMF_ASSOC_PARAMS, ChanspecList) == 12);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, Chanspec) == 72);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, Rssi) == 78);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, NbssCap) == 84);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, Flags) == 96);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, IeOffset) == 116);
C_ASSERT(FIELD_OFFSET(BRCMF_BSS_INFO, IeLength) == 120);
C_ASSERT(sizeof(BRCMF_BSS_INFO) == 128);

#pragma pack(push, 1)
typedef struct _BRCMF_WSEC_KEY {
    UINT32 Index;
    UINT32 Length;
    UCHAR  Data[32];
    UINT32 Pad1[18];
    UINT32 Algorithm;
    UINT32 Flags;
    UINT32 Pad2[3];
    UINT32 IvInitialized;
    UINT32 Pad3;
    UINT32 RxIvHigh;
    UINT16 RxIvLow;
    UCHAR  ReservedAfterRxIv[2];
    UINT32 Pad4[2];
    UCHAR  PeerAddress[6];
    UCHAR  ReservedTail[2];
} BRCMF_WSEC_KEY;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(BRCMF_WSEC_KEY, Algorithm) == 112);
C_ASSERT(FIELD_OFFSET(BRCMF_WSEC_KEY, RxIvHigh) == 140);
C_ASSERT(FIELD_OFFSET(BRCMF_WSEC_KEY, PeerAddress) == 156);
C_ASSERT(sizeof(BRCMF_WSEC_KEY) == 164);

static VOID Ap6256EventMaskSet(_Inout_updates_bytes_(Length) PUCHAR Mask,
                               _In_ ULONG Length, _In_ ULONG Event)
{
    ULONG byte = Event / 8;
    if (byte < Length) Mask[byte] |= (UCHAR)(1u << (Event & 7));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiConfigureRrmEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    UCHAR ext[4 + 128] = {1, 0, 128, 128};
    AP6256_BCDC_QUERY_RESULT result = {0};
    ULONG maskLength;
    NTSTATUS status;

    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs_ext",
        ext, sizeof(ext), &result);
    if (!NT_SUCCESS(status) || !result.FirmwareReply ||
        result.FirmwareError || result.PayloadLength < 4 ||
        ext[2] < 18 || ext[2] > sizeof(ext) - 4 ||
        ext[2] > result.PayloadLength - 4) {
        TraceDiag("RRM event mask: query 0x%08X reply %u error %u fw %d "
            "bytes %u ver %u len %u; extended subscription unavailable\n",
            status, result.FirmwareReply, result.FirmwareError,
            result.FirmwareStatus, result.PayloadLength, ext[0], ext[2]);
        return;
    }
    maskLength = ext[2];
    RtlZeroMemory(ext, sizeof(ext));
    ext[0] = 1;
    ext[1] = 1;
    ext[2] = (UCHAR)maskLength;
    Ap6256EventMaskSet(ext + 4, maskLength, BRCMF_E_RRM);
    status = Ap6256BcdcSetIovar(Ctx, "event_msgs_ext", ext, 4 + maskLength);
    if (!NT_SUCCESS(status)) {
        TraceDiag("RRM event mask: additive enable 141 -> 0x%08X\n", status);
        return;
    }

    RtlZeroMemory(ext, sizeof(ext));
    ext[0] = 1; ext[2] = 128; ext[3] = 128;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs_ext",
        ext, sizeof(ext), &result);
    if (NT_SUCCESS(status) && result.FirmwareReply && !result.FirmwareError &&
        result.PayloadLength >= 22 && ext[2] >= 18 &&
        ext[2] <= sizeof(ext) - 4 && ext[2] <= result.PayloadLength - 4) {
        TraceDiag("RRM event mask: readback 141=%u, %u mask byte(s)\n",
            (ext[4 + BRCMF_E_RRM / 8] >> (BRCMF_E_RRM & 7)) & 1, ext[2]);
    } else {
        TraceDiag("RRM event mask: readback unverified 0x%08X, bytes %u\n",
            status, result.PayloadLength);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiConfigureEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR mask[16];
    AP6256_BCDC_QUERY_RESULT result = {0};

    static const UCHAR requiredEvents[] = {

        BRCMF_E_SET_SSID, BRCMF_E_JOIN, BRCMF_E_START, BRCMF_E_AUTH,
        BRCMF_E_AUTH_IND, BRCMF_E_DEAUTH, BRCMF_E_DEAUTH_IND,
        BRCMF_E_ASSOC, BRCMF_E_ASSOC_IND, BRCMF_E_REASSOC,
        BRCMF_E_REASSOC_IND, BRCMF_E_DISASSOC, BRCMF_E_DISASSOC_IND,
        BRCMF_E_LINK, BRCMF_E_ROAM, BRCMF_E_JOIN_START,
        BRCMF_E_PRE_ASSOC_IND, BRCMF_E_PRE_REASSOC_IND,

        BRCMF_E_PRUNE, BRCMF_E_MIC_ERROR, BRCMF_E_TXFAIL,
        BRCMF_E_ICV_ERROR, BRCMF_E_UNICAST_DECODE_ERROR, BRCMF_E_MULTICAST_DECODE_ERROR,

        BRCMF_E_PSK_SUP, BRCMF_E_EAPOL_MSG, BRCMF_E_PMKID_CACHE,

        BRCMF_E_ESCAN_RESULT, BRCMF_E_SCAN_COMPLETE,
        BRCMF_E_PFN_NET_FOUND, BRCMF_E_PFN_SCAN_ALLGONE,

        BRCMF_E_ACTION_FRAME, BRCMF_E_ACTION_FRAME_COMPLETE,
        BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE, BRCMF_E_ACTION_FRAME_RX,
        BRCMF_E_ACTION_FRAME_RX_NDIS, BRCMF_E_RM_COMPLETE,
        BRCMF_E_TDLS_PEER_EVENT, BRCMF_E_FIFO_CREDIT_MAP, BRCMF_E_BCMC_CREDIT_SUPPORT,

        BRCMF_E_IF, BRCMF_E_AP_STARTED, BRCMF_E_RSSI, BRCMF_E_NATIVE,
        BRCMF_E_NDIS_LINK, BRCMF_E_CSA_COMPLETE_IND,
        BRCMF_E_DFS_AP_STOP, BRCMF_E_DFS_AP_RESUME,
        BRCMF_E_ASSOC_IND_NDIS, BRCMF_E_REASSOC_IND_NDIS,
        BRCMF_E_BCNLOST_MSG, BRCMF_E_RADIO, BRCMF_E_SCAN_CONFIRM_IND
    };
    NTSTATUS status;
    ULONG index;

    RtlZeroMemory(mask, sizeof(mask));
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs", mask, sizeof(mask), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(mask))
        return STATUS_DEVICE_PROTOCOL_ERROR;

    for (index = 0; index < RTL_NUMBER_OF(requiredEvents); index++) {
        Ap6256EventMaskSet(mask, sizeof(mask), requiredEvents[index]);
    }
    if (Ctx->FirmwareServicePatchVerified) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_GAS_FRAGMENT_RX);
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_GAS_COMPLETE);
    }
    if (Ctx->FirmwareEnhancedPnoSupported) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_PFN_BEST_BATCHING);
    }
    status = Ap6256BcdcSetIovar(Ctx, "event_msgs", mask, sizeof(mask));
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(mask, sizeof(mask));
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "event_msgs", mask, sizeof(mask), &result);
    if (NT_SUCCESS(status) && result.FirmwareReply && !result.FirmwareError &&
        result.PayloadLength >= sizeof(mask)) {
        TraceDiag("action event mask: readback 59=%u 60=%u 70=%u "
            "75=%u 77=%u 90=%u\n",
            (mask[7] >> 3) & 1, (mask[7] >> 4) & 1, (mask[8] >> 6) & 1,
            (mask[9] >> 3) & 1, (mask[9] >> 5) & 1, (mask[11] >> 2) & 1);
    } else {
        TraceDiag("action event mask: readback unverified 0x%08X, bytes %u\n",
            status, result.PayloadLength);
    }

    if (Ctx->FirmwareNativeManagement &&
        (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError ||
         result.PayloadLength < sizeof(mask) || (mask[9] & 0x08u) == 0)) {
        TraceDiag("native management: required event 75 readback failed\n");
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (Ctx->FirmwareServicePatchVerified) {
        if (!NT_SUCCESS(status) || !result.FirmwareReply || result.FirmwareError ||
            result.PayloadLength<sizeof(mask) || !(mask[12]&0x80u) || !(mask[13]&0x01u))
            return STATUS_DEVICE_PROTOCOL_ERROR;
        TraceDiag("service event mask: readback 103=1 104=1\n");
    }
    Ap6256WifiConfigureRrmEvents(Ctx);
    Ap6256SaeFirmwarePrepare(Ctx);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiQueryBtCoexist(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                         _Out_ PULONG BtCoexist)
{
    union {
        ULONG Dword;
        WCHAR String[16];
    } value = { 0 };
    UNICODE_STRING stringValue;
    NTSTATUS status;
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    ULONG mode = AP6256_BTCOEX_AUTO;
    USHORT stringLength;

    *BtCoexist = AP6256_BTCOEX_AUTO;
    status = Ap6256RegQueryValue(Ctx->Pdo, L"BTCoexist", sizeof(value), &value,
                                 &valueLength, &valueType);
    if (status == STATUS_OBJECT_NAME_NOT_FOUND) {
        TraceInfo(TRACE_NETADAPTER,
                  "BTCoexist absent; using Broadcom default Auto (3)\n");
        return STATUS_SUCCESS;
    }
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER,
                   "BTCoexist registry query failed 0x%08X\n", status);
        return status;
    }

    if (valueType == REG_DWORD && valueLength == sizeof(value.Dword)) {
        mode = value.Dword;
    } else if ((valueType == REG_SZ || valueType == REG_EXPAND_SZ) &&
               valueLength >= sizeof(WCHAR) &&
               valueLength <= sizeof(value.String) &&
               (valueLength % sizeof(WCHAR)) == 0) {
        stringLength = (USHORT)valueLength;
        if (value.String[(valueLength / sizeof(WCHAR)) - 1] == L'\0') {
            stringLength -= sizeof(WCHAR);
        }
        if (stringLength == 0) {
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
        stringValue.Buffer = value.String;
        stringValue.Length = stringLength;
        stringValue.MaximumLength = (USHORT)valueLength;
        status = RtlUnicodeStringToInteger(&stringValue, 10, &mode);
        if (!NT_SUCCESS(status)) {
            TraceError(TRACE_NETADAPTER,
                       "BTCoexist is not a valid integer (0x%08X)\n", status);
            return STATUS_DEVICE_CONFIGURATION_ERROR;
        }
    } else {
        TraceError(TRACE_NETADAPTER,
                   "BTCoexist has invalid registry type %u/length %u\n",
                   valueType, valueLength);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    if (mode != AP6256_BTCOEX_DISABLED &&
        mode != AP6256_BTCOEX_ENABLED &&
        mode != AP6256_BTCOEX_AUTO) {
        TraceError(TRACE_NETADAPTER, "BTCoexist value %u is unsupported\n", mode);
        return STATUS_DEVICE_CONFIGURATION_ERROR;
    }

    *BtCoexist = mode;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiConfigureBluetoothCoexistence(
    _In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    ULONG configuredMode;
    UINT32 firmwareMode;

    status = Ap6256WifiQueryBtCoexist(Ctx, &configuredMode);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    firmwareMode = (configuredMode == AP6256_BTCOEX_AUTO) ?
        AP6256_BTC_MODE_AUTO : configuredMode;
    status = Ap6256BcdcSetIovar(Ctx, "btc_mode",
                                &firmwareMode, sizeof(firmwareMode));
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER,
                   "btc_mode=%u (BTCoexist=%u) failed 0x%08X\n",
                   firmwareMode, configuredMode, status);
        return status;
    }

    Ctx->BtCoexMode = firmwareMode;

    TraceInfo(TRACE_NETADAPTER, "BT coexistence configured: UI=%u firmware=%u\n",
              configuredMode, firmwareMode);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static UINT32 Ap6256WifiQueryU32(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 Cmd, _In_ PCSTR Name,
                                 _Out_opt_ PNTSTATUS Status)
{
    UINT32 value = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, Cmd, &value, sizeof(value));

    if (Status != NULL) *Status = status;
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "  %-22s query failed (0x%08X)\n",
                  Name, status);
        return 0;
    }
    TraceInfo(TRACE_NETADAPTER, "  %-22s %u (0x%08X)\n", Name, value, value);
    return value;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiSetU32(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 Cmd, _In_ UINT32 Value,
                                 _In_ PCSTR Name)
{
    UINT32 value = Value;
    NTSTATUS status = Ap6256BcdcSetDcmd(Ctx, Cmd, &value, sizeof(value));

    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "  %s := %u REFUSED (0x%08X)\n",
                  Name, Value, status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiAssertStationRole(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const struct { UINT32 Cmd; UINT32 Value; PCSTR Name; } asserts[] = {
        { BRCMF_C_SET_INFRA,        1u,                         "infra"        },
        { BRCMF_C_SET_AP,           0u,                         "ap"           },
        { BRCMF_C_SET_MONITOR,      0u,                         "monitor"      },
        { BRCMF_C_SET_PROMISC,      0u,                         "promisc"      },
        { BRCMF_C_SET_PASSIVE_SCAN, 0u,                         "passive scan" },
        { BRCMF_C_SET_FAKEFRAG,     0u,                         "fakefrag"     },
        { BRCMF_C_SET_SRL,          AP6256_SHORT_RETRY_LIMIT,   "short retry"  },
        { BRCMF_C_SET_LRL,          AP6256_LONG_RETRY_LIMIT,    "long retry"   },
    };
    ULONG i;

    TraceInfo(TRACE_NETADAPTER, "asserting station role\n");
    for (i = 0; i < RTL_NUMBER_OF(asserts); i++) {
        (VOID)Ap6256WifiSetU32(Ctx, asserts[i].Cmd, asserts[i].Value,
                               asserts[i].Name);
    }

    {
        static const struct { UINT32 Get; UINT32 Set; PCSTR Name; } echo[] = {
            { BRCMF_C_GET_BCNPRD,     BRCMF_C_SET_BCNPRD,     "beacon period" },
            { BRCMF_C_GET_DTIMPRD,    BRCMF_C_SET_DTIMPRD,    "dtim period"   },
            { BRCMF_C_GET_REGULATORY, BRCMF_C_SET_REGULATORY, "regulatory"    },
        };

        for (i = 0; i < RTL_NUMBER_OF(echo); i++) {
            UINT32 current = 0;
            if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, echo[i].Get,
                                               &current, sizeof(current)))) {
                (VOID)Ap6256WifiSetU32(Ctx, echo[i].Set, current,
                                       echo[i].Name);
            }
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiInventory(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const struct { UINT32 Cmd; PCSTR Name; } queries[] = {
        { BRCMF_C_GET_INFRA,       "infra"            },
        { BRCMF_C_GET_AP,          "ap"               },
        { BRCMF_C_GET_MONITOR,     "monitor"          },
        { BRCMF_C_GET_AUTH,        "auth"             },
        { BRCMF_C_GET_WSEC,        "wsec"             },
        { BRCMF_C_GET_WPA_AUTH,    "wpa_auth"         },
        { BRCMF_C_GET_PM,          "power save"       },
        { BRCMF_C_GET_RADIO,       "radio bits"       },
        { BRCMF_C_GET_PHYTYPE,     "phy type"         },
        { BRCMF_C_GET_REGULATORY,  "regulatory"       },
        { BRCMF_C_GET_SRL,         "short retry"      },
        { BRCMF_C_GET_LRL,         "long retry"       },
        { BRCMF_C_GET_BCNPRD,      "beacon period"    },
        { BRCMF_C_GET_DTIMPRD,     "dtim period"      },
        { BRCMF_C_GET_RATE,        "rate (x500kbps)"  },
        { BRCMF_C_GET_RSSI,        "rssi dBm"         },
        { BRCMF_C_GET_PHY_NOISE,   "noise dBm"        },
    };
    ULONG i;

    TraceInfo(TRACE_NETADAPTER, "firmware inventory:\n");
    for (i = 0; i < RTL_NUMBER_OF(queries); i++) {
        (VOID)Ap6256WifiQueryU32(Ctx, queries[i].Cmd, queries[i].Name, NULL);
    }

    {
        WLC_SSID ssid;
        BRCMF_RATESET rates;
        BRCMF_ASSOCLIST assoc;
        CHAR phyList[8];
        UCHAR bssid[6];

        RtlZeroMemory(&ssid, sizeof(ssid));
        if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_SSID,
                                           &ssid, sizeof(ssid)))) {
            TraceInfo(TRACE_NETADAPTER, "  %-22s '%.*s'\n", "ssid",
                      (int)(ssid.SsidLen > 32u ? 32u : ssid.SsidLen),
                      ssid.Ssid);
        }

        RtlZeroMemory(bssid, sizeof(bssid));
        if (Ctx->FirmwareLinkUp && NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_BSSID,
                                           bssid, sizeof(bssid)))) {
            TraceInfo(TRACE_NETADAPTER,
                      "  %-22s %02X:%02X:%02X:%02X:%02X:%02X\n", "bssid",
                      bssid[0], bssid[1], bssid[2], bssid[3], bssid[4],
                      bssid[5]);
        } else if (!Ctx->FirmwareLinkUp) {
            TraceInfo(TRACE_NETADAPTER, "  %-22s not associated\n", "bssid");
        }

        RtlZeroMemory(&rates, sizeof(rates));
        if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_CURR_RATESET,
                                           &rates, sizeof(rates))) &&
            rates.Count != 0 && rates.Count <= RTL_NUMBER_OF(rates.Rates)) {
            TraceInfo(TRACE_NETADAPTER,
                      "  %-22s %u rate(s), %u.%u to %u.%u Mbps\n", "rateset",
                      rates.Count,
                      (rates.Rates[0] & 0x7Fu) / 2u,
                      ((rates.Rates[0] & 0x7Fu) % 2u) * 5u,
                      (rates.Rates[rates.Count - 1] & 0x7Fu) / 2u,
                      ((rates.Rates[rates.Count - 1] & 0x7Fu) % 2u) * 5u);
        }

        RtlZeroMemory(phyList, sizeof(phyList));
        if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_PHYLIST,
                                           phyList, sizeof(phyList) - 1))) {
            phyList[RTL_NUMBER_OF(phyList) - 1] = '\0';
            TraceInfo(TRACE_NETADAPTER, "  %-22s '%s'\n", "phy list",
                      phyList);
        }

        RtlZeroMemory(&assoc, sizeof(assoc));
        assoc.Count = AP6256_ASSOCLIST_MAX;
        if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_ASSOCLIST,
                                           &assoc, sizeof(assoc)))) {
            TraceInfo(TRACE_NETADAPTER, "  %-22s %u peer(s)\n", "assoclist",
                      assoc.Count);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceAssocList(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    BRCMF_ASSOCLIST assoc;

    RtlZeroMemory(&assoc, sizeof(assoc));
    assoc.Count = AP6256_ASSOCLIST_MAX;
    if (!NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_ASSOCLIST,
                                        &assoc, sizeof(assoc)))) {
        return;
    }
    if (assoc.Count == 0) {
        TraceWarn(TRACE_NETADAPTER,
                  "firmware assoclist is EMPTY after association\n");
        return;
    }
    TraceDiag("firmware assoclist: %u peer(s), first "
              "%02X:%02X:%02X:%02X:%02X:%02X\n", assoc.Count,
              assoc.Addresses[0][0], assoc.Addresses[0][1],
              assoc.Addresses[0][2], assoc.Addresses[0][3],
              assoc.Addresses[0][4], assoc.Addresses[0][5]);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetCountry(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_reads_(2) const CHAR* Code)
{
    BRCMF_COUNTRY country;
    NTSTATUS status;

    if (Code == NULL || Code[0] == '\0' || Code[1] == '\0') {
        return STATUS_INVALID_PARAMETER;
    }

    RtlZeroMemory(&country, sizeof(country));
    country.Abbrev[0] = Code[0];
    country.Abbrev[1] = Code[1];
    country.Ccode[0]  = Code[0];
    country.Ccode[1]  = Code[1];

    status = Ap6256BcdcSetIovar(Ctx, "country", &country, sizeof(country));
    if (NT_SUCCESS(status)) {

        Ap6256P2pSetCountry(Ctx, Code);
        TraceInfo(TRACE_NETADAPTER, "regulatory domain %c%c\n",
                  Code[0], Code[1]);
        return status;
    }

    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_COUNTRY,
                               country.Abbrev, sizeof(country.Abbrev));
    if (NT_SUCCESS(status)) Ap6256P2pSetCountry(Ctx, Code);
    TraceInfo(TRACE_NETADAPTER,
              "regulatory domain %c%c via the legacy command -> 0x%08X\n",
              Code[0], Code[1], status);
    return status;
}

_Use_decl_annotations_
BOOLEAN Ap6256WifiEscanEventIsCurrent(PAP6256_DEVICE_CONTEXT Ctx,
                                      const UCHAR* EventData, ULONG Length,
                                      PUINT16 SyncId)
{
    UINT16 eventSync;

    *SyncId = 0;
    if (EventData == NULL ||
        Length < (ULONG)FIELD_OFFSET(BRCMF_ESCAN_RESULT, BssInfo)) {
        return FALSE;
    }

    eventSync = ((const BRCMF_ESCAN_RESULT*)EventData)->SyncId;
    *SyncId = eventSync;
    return (BOOLEAN)(eventSync != 0 && eventSync == (UINT16)Ctx->ScanSyncId);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPrivacyExemptions(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(Count) const AP6256_EXEMPT_ENTRY* Entries,
    _In_ ULONG Count)
{
    return Ap6256WifiSetPrivacyExemptionsIf(Ctx, 0, Entries, Count);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPrivacyExemptionsIf(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 IfIndex,
    _In_reads_(Count) const AP6256_EXEMPT_ENTRY* Entries,
    _In_ ULONG Count)
{
    struct {
        UINT32 Count;
        AP6256_EXEMPT_ENTRY Entries[AP6256_EXEMPT_MAX];
    } list;
    ULONG length;

    if (Count > AP6256_EXEMPT_MAX) return STATUS_INVALID_PARAMETER;

    RtlZeroMemory(&list, sizeof(list));
    list.Count = Count;
    if (Count != 0) {
        RtlCopyMemory(list.Entries, Entries,
                      Count * sizeof(AP6256_EXEMPT_ENTRY));
    }

    length = sizeof(UINT32) + Count * sizeof(AP6256_EXEMPT_ENTRY);
    return Ap6256BcdcSetIovarIf(Ctx, IfIndex, "exempt_list", &list, length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReassociate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _In_reads_(6) const UCHAR* Bssid)
{
    BRCMF_REASSOC_PARAMS reassoc;
    NTSTATUS status;

    RtlZeroMemory(&reassoc, sizeof(reassoc));
    RtlCopyMemory(reassoc.Bssid, Bssid, sizeof(reassoc.Bssid));
    reassoc.ChanspecNum = 0;

    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_REASSOC, &reassoc,
                               FIELD_OFFSET(BRCMF_REASSOC_PARAMS,
                                            ChanspecList));
    TraceInfo(TRACE_NETADAPTER,
              "reassociating to %02X:%02X:%02X:%02X:%02X:%02X -> 0x%08X\n",
              Bssid[0], Bssid[1], Bssid[2], Bssid[3], Bssid[4], Bssid[5],
              status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256WifiHasNativeKeys(PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG slot;
    BOOLEAN found;
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    found = Ctx->NativeDeparturePending;
    for (slot = 0; slot < AP6256_NATIVE_KEY_SLOTS; ++slot) {
        if (Ctx->NativeKeys[slot].Valid) {
            found = TRUE;
            break;
        }
    }
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    return found;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiForgetNativeKeys(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    RtlZeroMemory(Ctx->NativeKeys, sizeof(Ctx->NativeKeys));
    Ctx->NativeDeparturePending = FALSE;
    Ctx->NativeDepartureToken = 0;
    Ctx->NativeDepartureCommitted = FALSE;
    Ctx->NativeDepartureReason = 0;
    RtlZeroMemory(Ctx->NativeDeparturePeer, sizeof(Ctx->NativeDeparturePeer));
    Ap6256LockRelease(&Ctx->NativeKeyLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiWriteNativeKey(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 IfIndex, BRCMF_WSEC_KEY* Key, BOOLEAN Pairwise, BOOLEAN Management)
{
    ULONG index;
    LONG slot = -1, available = -1;
    NTSTATUS status;
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    if (IfIndex == 0 && Ctx->NativeDeparturePending) {
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return STATUS_DEVICE_BUSY;
    }
    if (IfIndex == 0) {
        for (index = 0; index < AP6256_NATIVE_KEY_SLOTS; ++index) {
            AP6256_NATIVE_KEY_REF* ref = &Ctx->NativeKeys[index];
            if (!ref->Valid) {
                if (available < 0) available = (LONG)index;
            } else if (ref->KeyId == Key->Index && ref->Pairwise == Pairwise &&
                ref->Management == Management &&
                RtlEqualMemory(ref->PeerAddress, Key->PeerAddress, sizeof(ref->PeerAddress))) {
                slot = (LONG)index;
                break;
            }
        }
        if (Key->Length && slot < 0) slot = available;
        if (Key->Length && slot < 0) {
            Ap6256LockRelease(&Ctx->NativeKeyLock);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    status = Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SET_KEY, Key, sizeof(*Key));
    if (!NT_SUCCESS(status)) {
        status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "wsec_key", Key, sizeof(*Key));
    }
    if (NT_SUCCESS(status) && IfIndex == 0 && slot >= 0) {
        AP6256_NATIVE_KEY_REF* ref = &Ctx->NativeKeys[slot];
        RtlZeroMemory(ref, sizeof(*ref));
        if (Key->Length) {
            ref->KeyId = Key->Index;
            ref->Pairwise = Pairwise;
            ref->Management = Management;
            RtlCopyMemory(ref->PeerAddress, Key->PeerAddress, sizeof(ref->PeerAddress));
            ref->Valid = TRUE;
        }
    }
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDisconnectWithReason(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                        _In_reads_opt_(6) const UCHAR* Bssid,
                                        _In_ UINT32 ReasonCode)
{
    NTSTATUS status = STATUS_NOT_SUPPORTED;
    LARGE_INTEGER delay;
    BOOLEAN hostHandled = FALSE;
    BOOLEAN nativeHandled = FALSE;
    BOOLEAN wasFips = Ap6256FipsActive(Ctx, 0);

    Ap6256WlfcCancel(Ctx, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
    status = Ap6256HostCipherDisconnect(Ctx, 0, Bssid, ReasonCode, &hostHandled);
    if (hostHandled) {

        if (!Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, 0)) {
            Ctx->FirmwareLinkUp = FALSE;
            Ctx->SupplicantComplete = FALSE;
            Ctx->ConnectionRequiresSupplicant = FALSE;
        }
        return status;
    }
    status = STATUS_NOT_SUPPORTED;
    (VOID)Ap6256HostCipherEnd(Ctx, 0, FALSE);

    (VOID)Ap6256FipsRetire(Ctx, 0);
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    if (!wasFips) {
        status = Ap6256NativeDeparture(Ctx, Bssid, ReasonCode, &nativeHandled);
        if (!NT_SUCCESS(status)) {
            Ap6256LockRelease(&Ctx->NativeKeyLock);
            return status;
        }
        if (nativeHandled) goto cleanup;
    }
    status = STATUS_NOT_SUPPORTED;

    if (Bssid != NULL && ReasonCode != 0) {
        BRCMF_SCB_VAL scb;

        RtlZeroMemory(&scb, sizeof(scb));
        scb.Value = ReasonCode;
        RtlCopyMemory(scb.Address, Bssid, sizeof(scb.Address));

        status = Ap6256BcdcSetDcmd(Ctx,
                                   BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON,
                                   &scb, sizeof(scb));
        TraceInfo(TRACE_NETADAPTER,
                  "disconnecting from %02X:%02X:%02X:%02X:%02X:%02X, "
                  "reason %u -> 0x%08X\n",
                  Bssid[0], Bssid[1], Bssid[2], Bssid[3], Bssid[4], Bssid[5],
                  ReasonCode, status);
    }

    if (!NT_SUCCESS(status)) {
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_DISASSOC, NULL, 0);
    }
    if (!NT_SUCCESS(status)) {
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return status;
    }
    Ctx->NativeDeparturePending = TRUE;
    delay.QuadPart = -5000000LL;
    status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
    TraceVerbose(TRACE_DRIVER, "station disconnect departure drain: reason %u, 500 ms -> 0x%08X\n",
        ReasonCode, status);
    if (status != STATUS_SUCCESS) {
        if (NT_SUCCESS(status)) status = STATUS_IO_TIMEOUT;
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return status;
    }
    Ctx->NativeDeparturePending = FALSE;
cleanup:
    if (Bssid != NULL && ReasonCode != 0) {
        (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SCB_DEAUTHORIZE,
            (PVOID)(ULONG_PTR)Bssid, 6);
    }
    status = Ap6256WifiClearSecurityState(Ctx);

    Ctx->FirmwareLinkUp = FALSE;
    Ctx->SupplicantComplete = FALSE;
    Ctx->ConnectionRequiresSupplicant = FALSE;
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    return status;
}

#define AP6256_SCAN_CHANNEL_TIME_MS  40u
#define AP6256_SCAN_UNASSOC_TIME_MS  40u
#define AP6256_SCAN_PASSIVE_TIME_MS  120u

#define AP6256_ASSOC_RETRY_MAX        3u

#define AP6256_SCAN_NPROBES           2u
#define AP6256_SCAN_HOME_TIME_MS    120u

#define AP6256_ROAM_TRIGGER_DBM      (-75)

#define AP6256_ROAM_DELTA_DB         15

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiTraceRevInfo(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    BRCMF_REV_INFO rev;
    NTSTATUS status;

    RtlZeroMemory(&rev, sizeof(rev));
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_REVINFO, &rev, sizeof(rev));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "revinfo unavailable 0x%08X\n", status);
        return;
    }
    TraceInfo(TRACE_NETADAPTER,
              "chip %u rev %u pkg %u, radio rev %u, phy type %u rev %u, "
              "board %04X:%04X rev %u, ucode %u, nvram rev %u\n",
              rev.ChipNum, rev.ChipRev, rev.ChipPkg, rev.RadioRev,
              rev.PhyType, rev.PhyRev, rev.BoardVendor, rev.BoardId,
              rev.BoardRev, rev.UcodeRev, rev.NvramRev);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiTraceBandsAndChannels(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 bands[AP6256_BANDLIST_MAX];
    UINT32 channels[AP6256_VALID_CHANNELS_MAX];
    NTSTATUS status;

    RtlZeroMemory(bands, sizeof(bands));
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_BANDLIST,
                                 bands, sizeof(bands));

    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "band list unavailable 0x%08X\n", status);
    } else if (bands[0] == 0 || bands[0] >= AP6256_BANDLIST_MAX) {
        TraceWarn(TRACE_NETADAPTER, "band list count %u is not usable\n",
                  bands[0]);
    } else {
        TraceInfo(TRACE_NETADAPTER,
                  "firmware bands (1=5GHz 2=2.4GHz): %u supported, %u%s%u\n",
                  bands[0], bands[1], bands[0] > 1 ? " and " : "",
                  bands[0] > 1 ? bands[2] : bands[1]);
    }

    RtlZeroMemory(channels, sizeof(channels));
    channels[0] = AP6256_VALID_CHANNELS_MAX - 1;
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_VALID_CHANNELS,
                                 channels, sizeof(channels));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "valid channel list unavailable 0x%08X\n", status);
    } else if (channels[0] == 0 || channels[0] >= AP6256_VALID_CHANNELS_MAX) {
        TraceWarn(TRACE_NETADAPTER, "valid channel count %u is not usable\n",
                  channels[0]);
    } else {
        TraceInfo(TRACE_NETADAPTER,
                  "firmware allows %u channel(s), %u through %u\n",
                  channels[0], channels[1], channels[channels[0]]);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiDisableFirmwareRoaming(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 roamOff = 1;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "roam_off", &roamOff,
                                         sizeof(roamOff));

    if (NT_SUCCESS(status)) {
        TraceInfo(TRACE_NETADAPTER, "firmware roaming disabled\n");
        return;
    }

    TraceWarn(TRACE_NETADAPTER,
              "roam_off rejected 0x%08X; falling back to a reluctant "
              "trigger\n", status);
    {
        INT32 trigger[2] = { AP6256_ROAM_TRIGGER_DBM, (INT32)WLC_BAND_ALL };
        INT32 delta[2]   = { AP6256_ROAM_DELTA_DB,    (INT32)WLC_BAND_ALL };

        (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_ROAM_TRIGGER,
                                trigger, sizeof(trigger));
        (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_ROAM_DELTA,
                                delta, sizeof(delta));
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiConfigureScanTimes(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const struct {
        UINT32 Cmd;
        UINT32 Value;
        PCSTR  Name;
    } times[] = {
        { BRCMF_C_SET_SCAN_CHANNEL_TIME, AP6256_SCAN_CHANNEL_TIME_MS, "channel" },
        { BRCMF_C_SET_SCAN_UNASSOC_TIME, AP6256_SCAN_UNASSOC_TIME_MS, "unassoc" },
        { BRCMF_C_SET_SCAN_PASSIVE_TIME, AP6256_SCAN_PASSIVE_TIME_MS, "passive" },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(times); i++) {
        UINT32 value = times[i].Value;
        NTSTATUS status = Ap6256BcdcSetDcmd(Ctx, times[i].Cmd,
                                            &value, sizeof(value));
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER, "scan %s time not set 0x%08X\n",
                      times[i].Name, status);
        }
    }

    {
        static const struct { PCSTR Name; UINT32 Value; } iovars[] = {
            { "scan_nprobes",              AP6256_SCAN_NPROBES },
            { "scan_home_time",            AP6256_SCAN_HOME_TIME_MS },
        };

        for (i = 0; i < RTL_NUMBER_OF(iovars); i++) {
            UINT32 value = iovars[i].Value;
            NTSTATUS status = Ap6256BcdcSetIovar(Ctx, iovars[i].Name, &value,
                                                 sizeof(value));
            if (!NT_SUCCESS(status)) {
                TraceWarn(TRACE_NETADAPTER, "%s not set 0x%08X\n",
                          iovars[i].Name, status);
            }
        }
    }

    TraceInfo(TRACE_NETADAPTER,
              "scan dwell: %u ms per channel associated, %u ms unassociated, "
              "%u ms passive, %u ms at home, %u probe(s)\n",
              AP6256_SCAN_CHANNEL_TIME_MS, AP6256_SCAN_UNASSOC_TIME_MS,
              AP6256_SCAN_PASSIVE_TIME_MS, AP6256_SCAN_HOME_TIME_MS,
              AP6256_SCAN_NPROBES);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static UINT32 Ap6256WifiConfiguredPowerSave(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    union {
        ULONG Dword;
        WCHAR Text[2];
    } value = {0};
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    NTSTATUS status;

    status = Ap6256RegQueryValue(Ctx->Pdo, L"PowerSaveMode", sizeof(value),
                                 &value, &valueLength, &valueType);
    if (NT_SUCCESS(status) && valueLength == sizeof(value)) {
        if (valueType == REG_DWORD && value.Dword <= AP6256_PM_FAST) {
            return value.Dword;
        }

        if (valueType == REG_SZ && value.Text[0] >= L'0' &&
            value.Text[0] <= L'2' && value.Text[1] == L'\0') {
            return (UINT32)(value.Text[0] - L'0');
        }
    }
    return AP6256_PM_FAST;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiProgramPowerSave(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ BOOLEAN Enabled, _In_ BOOLEAN ForceOff)
{
    UINT32 pm = Enabled && !ForceOff ? Ap6256WifiConfiguredPowerSave(Ctx) : AP6256_PM_OFF;
    NTSTATUS status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_PM, &pm, sizeof(pm));

    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "power save %u not set 0x%08X\n",
                  pm, status);
    } else {
        UINT32 readBack = 0;
        AP6256_BCDC_QUERY_RESULT result;

        status = Ap6256BcdcQueryDcmdResultIf(Ctx, 0, BRCMF_C_GET_PM,
                                  &readBack, sizeof(readBack), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError ||
            result.PayloadLength < sizeof(readBack) || readBack != pm)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        TraceInfo(TRACE_NETADAPTER, "power save %s (firmware reports %u)\n",
                  pm == AP6256_PM_FAST ? "FAST (doze between beacons)"
                  : pm == AP6256_PM_OFF && ForceOff ? "OFF by connection quality"
                  : pm == AP6256_PM_OFF && Enabled ? "OFF by registry PowerSaveMode"
                  : pm == AP6256_PM_OFF ? "OFF" : "MAX by registry PowerSaveMode",
                  readBack);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPacketCounts(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _Out_ PAP6256_PKT_COUNTS Counts)
{
    RtlZeroMemory(Counts, sizeof(*Counts));
    return Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_PKTCNTS,
                               Counts, sizeof(*Counts));
}

#define AP6256_LINK_RATE_PERIOD_MS  5000u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONGLONG now = KeQueryInterruptTime();
    UINT32 rate = 0;
    UINT32 nrate = 0;
    UINT32 pm = 0;
    INT32 rssi = 0;
    NTSTATUS rateStatus, nrateStatus;
    PCSTR encoding;
    ULONG bandwidth;

    if ((now - Ctx->LinkRateTracedAt) / 10000u < AP6256_LINK_RATE_PERIOD_MS) {
        return;
    }
    Ctx->LinkRateTracedAt = now;

    rateStatus = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_RATE, &rate, sizeof(rate));
    nrateStatus = Ap6256BcdcGetIovar(Ctx, "nrate", &nrate, sizeof(nrate));
    (VOID)Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_PM, &pm, sizeof(pm));
    (VOID)Ap6256WifiGetRssi(Ctx, &rssi);

    switch ((nrate >> 24) & 0x3u) {
    case 0:  encoding = "legacy"; break;
    case 1:  encoding = "HT"; break;
    case 2:  encoding = "VHT"; break;
    default: encoding = "?"; break;
    }
    switch ((nrate >> 16) & 0x7u) {
    case 1:  bandwidth = 20; break;
    case 2:  bandwidth = 40; break;
    case 3:  bandwidth = 80; break;
    case 4:  bandwidth = 160; break;
    default: bandwidth = 0; break;
    }

    if (!NT_SUCCESS(nrateStatus)) {
        TraceInfo(TRACE_NETADAPTER,
                  "link rate now: %u kbps (rate 0x%08X), nrate unreadable "
                  "0x%08X, pm %u, RSSI %d dBm\n",
                  NT_SUCCESS(rateStatus) ? rate * 500u : 0u, rateStatus,
                  nrateStatus, pm, rssi);
        return;
    }
    TraceInfo(TRACE_NETADAPTER,
              "link rate now: %u kbps, nrate 0x%08X = %s rate/mcs %u nss %u "
              "%u MHz%s, pm %u, RSSI %d dBm\n",
              NT_SUCCESS(rateStatus) ? rate * 500u : 0u, nrate, encoding,
              ((nrate >> 24) & 0x3u) == 2 ? (nrate & 0xFu) : (nrate & 0xFFu),
              ((nrate >> 24) & 0x3u) == 2 ? ((nrate >> 4) & 0x7u) : 1u,
              bandwidth, (nrate & 0x00800000u) != 0 ? " SGI" : "",
              pm, rssi);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PUINT32 RateHalfMbps)
{
    UINT32 rate = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_RATE,
                                          &rate, sizeof(rate));

    *RateHalfMbps = NT_SUCCESS(status) ? rate : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMaxLinkRate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PUINT32 RateHalfMbps)
{
    UINT32 rate = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_MAX_RATE,
                                          &rate, sizeof(rate));

    *RateHalfMbps = NT_SUCCESS(status) ? rate : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRadioDisabled(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _Out_ PBOOLEAN HardwareOff,
                                    _Out_ PBOOLEAN SoftwareOff)
{
    UINT32 bits = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_RADIO,
                                          &bits, sizeof(bits));

    *HardwareOff = FALSE;
    *SoftwareOff = FALSE;
    if (!NT_SUCCESS(status)) return status;

    *HardwareOff = (BOOLEAN)((bits & WL_RADIO_HW_DISABLE) != 0);
    *SoftwareOff = (BOOLEAN)((bits & WL_RADIO_SW_DISABLE) != 0);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPhyNoise(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PINT32 NoiseDbm)
{
    INT32 noise = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_PHY_NOISE,
                                          &noise, sizeof(noise));

    *NoiseDbm = NT_SUCCESS(status) ? noise : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiApplyConfiguredCountry(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    WCHAR value[8] = { 0 };
    CHAR code[2];
    ULONG valueLength = 0;
    ULONG valueType = REG_NONE;
    NTSTATUS status;

    status = Ap6256RegQueryValue(Ctx->Pdo, L"Country", sizeof(value), value,
                                 &valueLength, &valueType);
    if (!NT_SUCCESS(status)) return;
    if ((valueType != REG_SZ && valueType != REG_EXPAND_SZ) ||
        valueLength < 2 * sizeof(WCHAR)) {
        TraceWarn(TRACE_NETADAPTER,
                  "Country has invalid registry type %u/length %u\n",
                  valueType, valueLength);
        return;
    }
    if (value[0] > 0x7F || value[1] > 0x7F) {
        TraceWarn(TRACE_NETADAPTER, "Country is not a two-letter code\n");
        return;
    }
    code[0] = (CHAR)value[0];
    code[1] = (CHAR)value[1];
    (VOID)Ap6256WifiSetCountry(Ctx, code);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiConfigureHandshake(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    static const struct { PCSTR Name; UINT32 Value; PCSTR Why; } settings[] = {
        { "exempt_m4",     1u, "message 4 may go out unencrypted" },
        { "buf_key_b4_m4", 1u, "the pairwise key waits for message 4" },

        { "wnm",           0u, "802.11v BSS transition off" },

        { "assoc_recreate", 0u, "no firmware-initiated re-association" },
    };
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(settings); i++) {
        UINT32 value = settings[i].Value;
        NTSTATUS status = Ap6256BcdcSetIovar(Ctx, settings[i].Name,
                                             &value, sizeof(value));
        if (NT_SUCCESS(status)) {
            TraceInfo(TRACE_NETADAPTER, "%s = %u: %s\n",
                      settings[i].Name, settings[i].Value, settings[i].Why);
        } else {
            TraceWarn(TRACE_NETADAPTER,
                      "%s not accepted 0x%08X (%s)\n",
                      settings[i].Name, status, settings[i].Why);
        }
    }
}

#define AP6256_NATIVE_RRM_CAPABILITIES { 0x32u, 0u, 0u, 0u, 0u }

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiConfigureNativeRrmBeforeUp(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    const UCHAR capabilities[5] =
        AP6256_NATIVE_RRM_CAPABILITIES;
    NTSTATUS status;
    if (!Ctx->FirmwareNativeManagement) return STATUS_SUCCESS;

    status = Ap6256WifiRadioUpDown(Ctx, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovar(Ctx, "rrm", capabilities, sizeof(capabilities));
    if (!NT_SUCCESS(status)) {
        TraceDiag("native management: rrm capabilities SET failed 0x%08X\n", status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiConfigureNativeManagement(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    const UCHAR expectedRrm[5] =
        AP6256_NATIVE_RRM_CAPABILITIES;
    UCHAR rrm[5] = { 0 };
    UINT32 value = 1u;
    AP6256_BCDC_QUERY_RESULT result = { 0 };
    NTSTATUS status;
    Ctx->FirmwareBssTransitionEnabled = FALSE;
    if (!Ctx->FirmwareNativeManagement) return STATUS_SUCCESS;

    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "rrm", rrm, sizeof(rrm), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(rrm) ||
        !RtlEqualMemory(rrm, expectedRrm, sizeof(rrm))) {
        TraceDiag("native management: rrm readback failed %02X %02X %02X %02X %02X\n",
                  rrm[0], rrm[1], rrm[2], rrm[3], rrm[4]);
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    TraceDiag("native management: rrm 32 00 00 00 00 verified; firmware reports/neighbor cache\n");

    status = Ap6256BcdcSetIovar(Ctx, "wnm", &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = 0;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wnm", &value, sizeof(value), &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(value) || value != 1u) {
        TraceDiag("native management: wnm BTM readback failed (0x%08X)\n", value);
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    Ctx->FirmwareBssTransitionEnabled = TRUE;
    TraceDiag("native management: wnm 0x%08X verified; Windows BTM policy, native protected replies and Windows station moves\n", value);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiConfigureDongle(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256WifiAssertStationRole(Ctx);
    Ap6256WifiApplyConfiguredCountry(Ctx);
    Ap6256WifiTraceRevInfo(Ctx);
    Ap6256WifiTraceBandsAndChannels(Ctx);
    Ap6256WifiDisableFirmwareRoaming(Ctx);
    Ap6256WifiConfigureHandshake(Ctx);
    Ap6256WifiConfigureScanTimes(Ctx);

    (VOID)Ap6256WifiSetPowerSave(Ctx, FALSE);

    Ap6256WifiInventory(Ctx);
}

#define AP6256_KEEP_ALIVE_PERIOD_MS  55000u

#pragma pack(push, 1)
typedef struct _BRCMF_MKEEP_ALIVE_PKT {
    UINT16 Version;
    UINT16 Length;
    UINT32 PeriodMs;
    UINT16 DataLength;
    UCHAR  KeepAliveId;
    UCHAR  Data[1];
} BRCMF_MKEEP_ALIVE_PKT;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(BRCMF_MKEEP_ALIVE_PKT, Data) == 11);

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiConfigureKeepAlive(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    BRCMF_MKEEP_ALIVE_PKT request;
    NTSTATUS status;

    RtlZeroMemory(&request, sizeof(request));
    request.Version = 1;
    request.Length = (UINT16)FIELD_OFFSET(BRCMF_MKEEP_ALIVE_PKT, Data);
    request.PeriodMs = AP6256_KEEP_ALIVE_PERIOD_MS;

    status = Ap6256BcdcSetIovar(Ctx, "mkeep_alive", &request,
                                (ULONG)FIELD_OFFSET(BRCMF_MKEEP_ALIVE_PKT, Data));
    TraceDiag("keep-alive: null frame every %u ms -> 0x%08X\n",
              AP6256_KEEP_ALIVE_PERIOD_MS, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiUp(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    UINT32 infra = 1;
    UINT32 ioType = 0;

    status = Ap6256WifiConfigureNativeRrmBeforeUp(Ctx);
    if (!NT_SUCCESS(status)) return status;

    status = Ap6256WlfcConfigure(Ctx);
    if (!NT_SUCCESS(status)) {
        TraceDiag("WLFC: startup negotiation failed 0x%08X\n", status);
        return status;
    }
    status = Ap6256WifiRadioUpDown(Ctx, TRUE);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &infra, sizeof(infra));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_VERSION,
                                 &ioType, sizeof(ioType));
    if (!NT_SUCCESS(status)) return status;
    if (ioType != BRCMU_D11N_IOTYPE && ioType != BRCMU_D11AC_IOTYPE) {
        TraceError(TRACE_NETADAPTER, "unsupported D11 I/O type %u\n", ioType);
        return STATUS_NOT_SUPPORTED;
    }
    Ctx->D11IoType = (UINT8)ioType;
    status = Ap6256WifiConfigureBluetoothCoexistence(Ctx);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256WifiConfigureEvents(Ctx);
    if (!NT_SUCCESS(status)) return status;

    Ap6256WifiConfigureKeepAlive(Ctx);

    Ap6256WifiConfigureDongle(Ctx);
    status = Ap6256WifiConfigureNativeManagement(Ctx);
    if (NT_SUCCESS(status)) status = Ap6256QualityReapply(Ctx);
    if (NT_SUCCESS(status)) status = Ap6256QualifyService(Ctx);
    if (NT_SUCCESS(status)) status = Ap6256QualifyFtm(Ctx);
    if (NT_SUCCESS(status)) status = Ap6256FipsQualify(Ctx, Ctx->FirmwareFtmPatchVerified);
    if (NT_SUCCESS(status) && !Ctx->FirmwareServicePatchVerified) Ap6256P2pProbeOffloadInterfaces(Ctx);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiLeaveForPowerDown(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    LARGE_INTEGER delay;
    BOOLEAN nativeHandled = FALSE;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL ||
        Ctx->FirmwareState != Ap6256FwRunning || !Ctx->DatapathRunning ||
        Ctx->Sdio.BusInterface == NULL || Ctx->Sdio.Sleeping ||
        InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0)
        return STATUS_DEVICE_NOT_READY;
    if (Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, 0) ||
        Ap6256FipsActive(Ctx, 0))
        return STATUS_NOT_SUPPORTED;
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    if (!Ctx->FirmwareLinkUp && !Ctx->NativeDeparturePending) {
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return STATUS_SUCCESS;
    }

    Ap6256WlfcCancel(Ctx, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
    status = Ap6256NativeDeparture(Ctx, NULL, 0, &nativeHandled);
    if (nativeHandled || !NT_SUCCESS(status)) {
        if (nativeHandled && NT_SUCCESS(status)) status = Ap6256WifiClearSecurityState(Ctx);
        TraceVerbose(TRACE_DRIVER, "native protected departure before power down: 0x%08X\n", status);
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return status;
    }
    status = Ctx->NativeDeparturePending ? STATUS_SUCCESS :
        Ap6256BcdcSetDcmd(Ctx, BRCMF_C_DISASSOC, NULL, 0);
    if (NT_SUCCESS(status)) {
        Ctx->NativeDeparturePending = TRUE;
        delay.QuadPart = -5000000LL;
        status = KeDelayExecutionThread(KernelMode, FALSE, &delay);
        if (status == STATUS_SUCCESS) Ctx->NativeDeparturePending = FALSE;
        else if (NT_SUCCESS(status)) status = STATUS_IO_TIMEOUT;
    }
    TraceVerbose(TRACE_DRIVER, "station departure before power down: 0x%08X, transmit grace %u ms\n",
        status, NT_SUCCESS(status) ? 500u : 0u);
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetRadioState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enabled)
{
    NTSTATUS status;
    UINT32 radio;

    if (!Enabled)
        (VOID)Ap6256WifiLeaveForPowerDown(Ctx);

    radio = (WL_RADIO_SW_DISABLE << 16) | (Enabled ? 0u : WL_RADIO_SW_DISABLE);
    (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_RADIO, &radio, sizeof(radio));

    radio = 0;
    if (NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_RADIO,
                                       &radio, sizeof(radio)))) {
        TraceInfo(TRACE_NETADAPTER, "radio %s, state bits 0x%08X\n",
                  Enabled ? "ON" : "OFF", radio);
    }

    if (Enabled) return Ap6256WifiUp(Ctx);
    status = Ap6256WifiRadioUpDown(Ctx, FALSE);
    Ctx->FirmwareLinkUp = FALSE;
    Ctx->SupplicantComplete = FALSE;
    Ctx->ConnectionRequiresSupplicant = FALSE;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256EncodeChanspec(_In_ UINT8 IoType,
                                     _In_ const AP6256_SCAN_CHANNEL* Channel,
                                     _Out_ PUINT16 Chanspec)
{
    UINT16 encoded;

    if ((Channel->Band != Ap6256ScanBand2G &&
         Channel->Band != Ap6256ScanBand5G) ||
        (Channel->Band == Ap6256ScanBand2G &&
         (Channel->Number < 1 || Channel->Number > 14)) ||
        (Channel->Band == Ap6256ScanBand5G &&
         (Channel->Number < 34 || Channel->Number > 223))) {
        return STATUS_INVALID_PARAMETER;
    }

    encoded = Channel->Number;
    if (IoType == BRCMU_D11N_IOTYPE) {
        encoded |= BRCMU_CHSPEC_D11N_SB_NONE | BRCMU_CHSPEC_D11N_BW_20;
        encoded |= Channel->Band == Ap6256ScanBand2G ?
            BRCMU_CHSPEC_D11N_BAND_2G : BRCMU_CHSPEC_D11N_BAND_5G;
    } else if (IoType == BRCMU_D11AC_IOTYPE) {
        encoded |= BRCMU_CHSPEC_D11AC_BW_20;
        encoded |= Channel->Band == Ap6256ScanBand2G ?
            BRCMU_CHSPEC_D11AC_BAND_2G : BRCMU_CHSPEC_D11AC_BAND_5G;
    } else {
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    *Chanspec = encoded;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiScanStartInternal(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_SCAN_PARAMS* Params,
                                           _In_ UINT16 SyncId)
{
    BRCMF_ESCAN_PARAMS* escan;
    PUCHAR ssidCursor;
    ULONG fixedLength = FIELD_OFFSET(BRCMF_ESCAN_PARAMS, Params.ChannelList);
    ULONG channelBytes;
    ULONG ssidOffset;
    ULONG len;
    ULONG index;
    ULONG trailingSsidCount;
    NTSTATUS status;

    if (Params == NULL || Params->SsidCount > AP6256_SCAN_SSID_MAX ||
        Params->ChannelCount > AP6256_SCAN_CHANNEL_MAX ||
        (Ctx->D11IoType != BRCMU_D11N_IOTYPE &&
         Ctx->D11IoType != BRCMU_D11AC_IOTYPE)) {
        return STATUS_INVALID_PARAMETER;
    }
    for (index = 0; index < Params->SsidCount; index++)
        if (Params->Ssids[index].Length > sizeof(Params->Ssids[index].Data))
            return STATUS_INVALID_PARAMETER;
    channelBytes = Params->ChannelCount * sizeof(UINT16);
    trailingSsidCount = Params->SsidCount > 1 ? Params->SsidCount : 0;
    ssidOffset = (fixedLength + channelBytes + 3u) & ~3u;
    if (ssidOffset < fixedLength || ssidOffset > AP6256_BCDC_MAXBUF ||
        trailingSsidCount > (AP6256_BCDC_MAXBUF - ssidOffset) / sizeof(WLC_SSID)) {
        return STATUS_INVALID_BUFFER_SIZE;
    }
    len = ssidOffset + trailingSsidCount * sizeof(WLC_SSID);
    escan = (BRCMF_ESCAN_PARAMS*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, len, AP6256_POOL_TAG);
    if (escan == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(escan, len);
    escan->Version = BRCMF_ESCAN_REQ_VERSION;
    escan->Action = WL_ESCAN_ACTION_START;
    if (!SyncId || SyncId != (UINT16)Ctx->ScanSyncId) {
        ExFreePoolWithTag(escan, AP6256_POOL_TAG);
        return STATUS_CANCELLED;
    }
    escan->SyncId = SyncId;

    RtlCopyMemory(escan->Params.Bssid, Params->Bssid, sizeof(escan->Params.Bssid));
    escan->Params.BssType = DOT11_BSSTYPE_ANY;
    switch (Params->ScanType) {
    case Ap6256ScanTypeActive:
        escan->Params.ScanType = BRCMF_SCANTYPE_ACTIVE;
        break;
    case Ap6256ScanTypePassive:
        escan->Params.ScanType = BRCMF_SCANTYPE_PASSIVE;
        break;
    case Ap6256ScanTypeAuto:
        escan->Params.ScanType = BRCMF_SCANTYPE_DEFAULT;
        break;
    default:
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }
    escan->Params.NProbes = -1;
    escan->Params.ActiveTime = Params->ActiveChannelDwellTime == 0 ?
        -1 : (INT32)Params->ActiveChannelDwellTime;
    escan->Params.PassiveTime = Params->PassiveChannelDwellTime == 0 ?
        -1 : (INT32)Params->PassiveChannelDwellTime;
    escan->Params.HomeTime = -1;
    escan->Params.ChannelNum = (INT32)(Params->ChannelCount |
        (trailingSsidCount << 16));

    if (Params->SsidCount == 1) {
        escan->Params.Ssid.SsidLen = Params->Ssids[0].Length;
        RtlCopyMemory(escan->Params.Ssid.Ssid, Params->Ssids[0].Data,
                      Params->Ssids[0].Length);
    }
    for (index = 0; index < Params->ChannelCount; index++) {
        UINT16 chanspec;
        status = Ap6256EncodeChanspec(Ctx->D11IoType, &Params->Channels[index],
                                      &chanspec);
        if (!NT_SUCCESS(status)) goto done;
        RtlCopyMemory((PUCHAR)escan + fixedLength + index * sizeof(chanspec),
                      &chanspec, sizeof(chanspec));
    }
    ssidCursor = (PUCHAR)escan + ssidOffset;
    for (index = 0; index < trailingSsidCount; index++) {
        WLC_SSID* ssid = (WLC_SSID*)ssidCursor;
        ssid->SsidLen = Params->Ssids[index].Length;
        RtlCopyMemory(ssid->Ssid, Params->Ssids[index].Data,
                      Params->Ssids[index].Length);
        ssidCursor += sizeof(*ssid);
    }

    TraceInfo(TRACE_NETADAPTER,
              "starting %s (sync_id %u, %u SSIDs, %u channels, dwell "
              "active %u passive %u ms, max scan time %u ms) "
              "ssid[0] '%.*s' bssid %02X:%02X:%02X:%02X:%02X:%02X\n",
              "escan",
              escan->SyncId, Params->SsidCount, Params->ChannelCount,
              Params->ActiveChannelDwellTime, Params->PassiveChannelDwellTime,
              Params->MaximumScanTime,
              Params->SsidCount != 0 ? (int)Params->Ssids[0].Length : 0,
              Params->SsidCount != 0 ? Params->Ssids[0].Data : (const UCHAR*)"",
              Params->Bssid[0], Params->Bssid[1], Params->Bssid[2],
              Params->Bssid[3], Params->Bssid[4], Params->Bssid[5]);

    status = Ap6256BcdcSetIovar(Ctx, "escan", escan, len);

done:
    ExFreePoolWithTag(escan, AP6256_POOL_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiScanStart(PAP6256_DEVICE_CONTEXT Ctx, const AP6256_SCAN_PARAMS* Params,
                            UINT16 SyncId)
{
    return Ap6256WifiScanStartInternal(Ctx, Params, SyncId);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAbortOffChannel(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    return Ap6256BcdcSetIovar(Ctx, "scanabort", NULL, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiScanAbort(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    BRCMF_ESCAN_PARAMS abort;
    NTSTATUS status;

    RtlZeroMemory(&abort, sizeof(abort));
    abort.Version = BRCMF_ESCAN_REQ_VERSION;
    abort.Action = WL_ESCAN_ACTION_ABORT;
    abort.SyncId = (UINT16)Ctx->ScanSyncId;
    RtlFillMemory(abort.Params.Bssid, sizeof(abort.Params.Bssid), 0xFF);
    abort.Params.BssType = DOT11_BSSTYPE_ANY;
    abort.Params.ScanType = 0;
    abort.Params.NProbes = -1;
    abort.Params.ActiveTime = -1;
    abort.Params.PassiveTime = -1;
    abort.Params.HomeTime = -1;
    abort.Params.ChannelNum = 0;

    status = Ap6256BcdcSetIovar(Ctx, "escan", &abort,
                                FIELD_OFFSET(BRCMF_ESCAN_PARAMS,
                                             Params.ChannelList));
    if (NT_SUCCESS(status)) return status;

    TraceDiag("escan abort not accepted 0x%08X; using the sentinel scan\n",
              status);

    return Ap6256WifiLegacyScanAbort(Ctx);
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiLegacyScanAbort(PAP6256_DEVICE_CONTEXT Ctx)
{
    BRCMF_SCAN_PARAMS params;

    RtlZeroMemory(&params, sizeof(params));
    RtlFillMemory(params.Bssid, sizeof(params.Bssid), 0xFF);
    params.BssType = DOT11_BSSTYPE_ANY;
    params.ScanType = BRCMF_SCANTYPE_ACTIVE;
    params.NProbes = 1;
    params.ActiveTime = -1;
    params.PassiveTime = -1;
    params.HomeTime = -1;
    params.ChannelNum = 1;
    params.ChannelList[0] = MAXUINT16;
    return Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SCAN, &params, sizeof(params));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiOnEscanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_reads_bytes_(Length) PUCHAR EventData, _In_ ULONG Length,
                                 _Out_ PAP6256_BSS Bss)
{
    BRCMF_ESCAN_RESULT* result = (BRCMF_ESCAN_RESULT*)EventData;
    BRCMF_BSS_INFO* info;
    ULONG fixedLength = FIELD_OFFSET(BRCMF_ESCAN_RESULT, BssInfo);
    ULONG available;

    RtlZeroMemory(Bss, sizeof(*Bss));

    if (Length < fixedLength) return STATUS_BUFFER_TOO_SMALL;
    if (result->SyncId != (UINT16)Ctx->ScanSyncId) return STATUS_NOT_FOUND;
    if (result->BufLen < fixedLength || result->BufLen > Length) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    if (result->BssCount == 0) return STATUS_NO_MORE_ENTRIES;
    if (result->BssCount != 1 || result->BufLen < sizeof(BRCMF_ESCAN_RESULT)) {
        return STATUS_DEVICE_DATA_ERROR;
    }

    info = &result->BssInfo;
    available = result->BufLen - fixedLength;
    if (info->Length < sizeof(BRCMF_BSS_INFO) ||
        info->Length > available) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    if (info->IeOffset < sizeof(BRCMF_BSS_INFO) ||
        info->IeOffset > info->Length ||
        info->IeLength > info->Length - info->IeOffset ||
        info->IeLength > sizeof(Bss->Ies)) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    Bss->SyncId = result->SyncId;
    RtlCopyMemory(Bss->Bssid, info->Bssid, 6);
    Bss->SsidLength = min((ULONG)info->SsidLen, (ULONG)sizeof(Bss->Ssid));
    RtlCopyMemory(Bss->Ssid, info->Ssid, Bss->SsidLength);
    Bss->Rssi = info->Rssi;

    Bss->Channel = (info->ControlChannel != 0)
        ? (UINT16)info->ControlChannel
        : (UINT16)(info->Chanspec & 0x00FF);
    Bss->BeaconPeriod = info->BeaconPeriod;
    Bss->Capability = info->Capability;
    Bss->FromBeacon = (BOOLEAN)((info->Flags & BRCMF_BSS_FLAGS_FROM_BEACON) != 0);
    Bss->FromCache = (BOOLEAN)((info->Flags & BRCMF_BSS_FLAGS_FROM_CACHE) != 0);
    Bss->IesLength = info->IeLength;
    if (Bss->IesLength != 0) {
        RtlCopyMemory(Bss->Ies, (PUCHAR)info + info->IeOffset, Bss->IesLength);
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiPrepareHostCipherOffloads(PAP6256_DEVICE_CONTEXT Ctx)
{
    const PCSTR switches[] = {"arpoe", "ndoe"};
    UCHAR config[56] = {0}, key[36] = {0};
    UINT32 zero = 0, value, slot;
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    for (slot = 0; slot < RTL_NUMBER_OF(switches); ++slot) {

        value = 1; RtlZeroMemory(&result, sizeof(result));
        status = Ap6256BcdcGetIovarResultIf(Ctx, 0, switches[slot], &value, sizeof(value), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(value))
            return STATUS_DEVICE_PROTOCOL_ERROR;
        if (!value) continue;
        status = Ap6256BcdcSetIovarIf(Ctx, 0, switches[slot], &zero, sizeof(zero));
        if (!NT_SUCCESS(status)) return status;
        value = 1; RtlZeroMemory(&result, sizeof(result));
        status = Ap6256BcdcGetIovarResultIf(Ctx, 0, switches[slot], &value, sizeof(value), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(value) || value)
            return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    status = Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_gtk_config", config, sizeof(config));
    if (!NT_SUCCESS(status)) return status;
    for (slot = 0; slot < 6; ++slot) {
        UINT32 management = slot >= 4;
        RtlCopyMemory(key, &slot, sizeof(slot));
        RtlCopyMemory(key + 4, &management, sizeof(management));
        status = Ap6256BcdcSetIovarIf(Ctx, 0, "wdi_gtk_key", key, sizeof(key));
        if (!NT_SUCCESS(status)) return status;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiSetStationRsn(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ PAP6256_CONNECT_PARAMS Params)
{

    UCHAR ie[44] = {48, 26, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4,
        1, 0, 0, 15, 172, 5, 0xc0, 0, 0, 0, 0, 15, 172, 6};
    ULONG length = Params->Wpa3Enterprise ? 28u : 0u;
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9) return STATUS_SUCCESS;
    if (Params->Wpa3Enterprise && Params->PmkidValid) {
        ie[1] = 42; ie[22] = 1;
        RtlCopyMemory(ie + 24, Params->Pmkid, 16);
        ie[40] = 0; ie[41] = 15; ie[42] = 172; ie[43] = 6;
        length = sizeof(ie);
    }
    status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "wpaie", ie, length, &result);
    if (!NT_SUCCESS(status)) return status;
    if (!result.FirmwareReply || result.FirmwareError || result.FirmwareStatus)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiConnectCommon(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ PAP6256_CONNECT_PARAMS Params, _In_opt_ AP6256_CONNECT_FT_SETUP* Ft)
{
    NTSTATUS status;
    UINT32 infra = 1;
    BOOLEAN sae = Params->Security == Ap6256SecuritySaeHost;
    BOOLEAN owe = Params->Security == Ap6256SecurityOweHost;
    BOOLEAN privateSae = sae && Ctx->FirmwarePrivateSae;
    BOOLEAN ftRoam = Ft != NULL && Ft->Reassociation;
    BOOLEAN wpa2 = Params->Security != Ap6256SecurityOpen;
    BOOLEAN hadFips = Ap6256FipsActive(Ctx, 0);
    BOOLEAN hostCipher = Params->HostCipher;
    BOOLEAN hadHostCipher = Ap6256HostCipherPacketActive(Ctx, 0);
    UINT32 wsec = (wpa2 ? WSEC_AES_ENABLED : 0) | ((owe || Params->Wpa3Enterprise) ? WSEC_SHA256_KDF : 0);
    UINT32 wpaAuth = sae ? (privateSae ? 0x00008000u : 0x00040000u) :
        (Params->Security == Ap6256SecurityWpa2Enterprise
        ? (Params->Wpa3Enterprise ? WPA2_AUTH_1X_SHA256 : WPA2_AUTH_UNSPECIFIED)
        : (wpa2 ? WPA2_AUTH_PSK : WPA_AUTH_DISABLED));
    UINT32 auth = sae && !privateSae && !Params->PmkidValid ? 3u : 0u;
    BRCMF_JOIN_PARAMS join;
    ULONG joinLen;

    if (Params->SsidLength == 0 || Params->SsidLength > 32) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Params->Security != Ap6256SecurityOpen &&
        Params->Security != Ap6256SecurityWpa2Host &&
        Params->Security != Ap6256SecurityWpa2Firmware &&
        Params->Security != Ap6256SecurityWpa2Enterprise && !sae && !owe) {
        return STATUS_NOT_SUPPORTED;
    }
    if (Params->Wpa3Enterprise &&
        (Params->Wpa3Enterprise != TRUE || Params->Security != Ap6256SecurityWpa2Enterprise ||
         Params->HostCipher || Params->HostFips || Ft || Params->FastTransition ||
         Params->Mfp != Ap6256MfpRequired || !Params->BssidValid || !Params->Channel || Params->Channel > 196 ||
         !Ctx->FirmwareMfpSupported || Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9))
        return STATUS_NOT_SUPPORTED;
    if (hostCipher && (hostCipher != TRUE || Params->HostFips || Ft ||
        Params->FastTransition || !Params->BssidValid || !Params->Channel || Params->Channel > 196 ||
        (UINT32)Params->Mfp > 2 ||
        InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) != 1 ||
        ((Params->HostCipherAkm == 1 || Params->HostCipherAkm == 5 || Params->HostCipherAkm == 12)
            ? (Params->Security != Ap6256SecurityWpa2Enterprise ||
               (Params->HostCipherAkm != 1 && Params->Mfp != Ap6256MfpRequired)) :
         Params->HostCipherAkm == 2 ? Params->Security != Ap6256SecurityWpa2Host :
         Params->HostCipherAkm == 8 ? (!sae || !privateSae) :
         Params->HostCipherAkm == 18 ? !owe : TRUE))) return STATUS_NOT_SUPPORTED;
    if (Params->HostFips && (!Ctx->HostFipsReady || Params->Mfp != Ap6256MfpNone ||
        !Params->BssidValid || !Params->Channel || sae || owe || Ft ||
        Params->Security == Ap6256SecurityWpa2Firmware)) return STATUS_NOT_SUPPORTED;
    if (Params->HostFips) {
        status = Ap6256FipsCheckVendorIes(Params->AssociationVendorIes, Params->AssociationVendorIesLength);
        if (!NT_SUCCESS(status)) return status;
    }
    if (sae && ((!Ctx->FirmwareExternalAuth && !privateSae) || Params->Mfp != Ap6256MfpRequired ||
                !Params->BssidValid || Params->Channel == 0 || Params->Channel > 196))
        return STATUS_NOT_SUPPORTED;
    if (owe && (!Ctx->FirmwareHostOwe || !Ctx->FirmwareOwePatchVerified ||
        Params->Mfp != Ap6256MfpRequired || !Params->BssidValid || !Params->Channel ||
        Params->Channel > 196 || !Ap6256OweDhValid(Params->OweDh, Params->OweDhLength)))
        return STATUS_NOT_SUPPORTED;

    if (Ctx->FirmwareOweGeneration) return STATUS_DEVICE_BUSY;
    if (Params->FastTransition != (Ft != NULL) ||
        (Ft && (!Ctx->FirmwareHostFt || Params->Security != Ap6256SecurityWpa2Enterprise ||
                !Params->BssidValid || !Params->Channel))) return STATUS_NOT_SUPPORTED;
    if (ftRoam) {
        UCHAR current[6];
        WLC_SSID currentSsid = {0};
        if (!Ctx->FirmwareLinkUp ||
            !NT_SUCCESS(Ap6256WifiGetBssid(Ctx, current)) ||
            RtlEqualMemory(current, Params->Bssid, 6) ||
            !NT_SUCCESS(Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_SSID,
                &currentSsid, sizeof(currentSsid))) || currentSsid.SsidLen != Params->SsidLength ||
            !RtlEqualMemory(currentSsid.Ssid, Params->Ssid, Params->SsidLength))
            return STATUS_INVALID_DEVICE_STATE;
    }

    status = Ap6256HostCipherEnd(Ctx, 0, FALSE);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256FipsStop(Ctx, 0);
    if (!NT_SUCCESS(status)) return status;
    if (!Ctx->FirmwareLinkUp && Ap6256WifiHasNativeKeys(Ctx)) {
        status = Ap6256WifiClearSecurityState(Ctx);
        if (!NT_SUCCESS(status)) return status;
    }
    status = Ap6256WifiSetStationRsn(Ctx, Params);
    if (!NT_SUCCESS(status)) return status;
    if (hostCipher) {
        status = Ap6256WifiPrepareHostCipherOffloads(Ctx);
        if (!NT_SUCCESS(status)) return status;
    }

    {
        UINT32 retries = AP6256_ASSOC_RETRY_MAX;
        (VOID)Ap6256BcdcSetIovar(Ctx, "assoc_retry_max", &retries,
                                 sizeof(retries));
    }

    if (!ftRoam) {
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AUTH, &auth, sizeof(auth));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WPA_AUTH, &wpaAuth, sizeof(wpaAuth));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WSEC, &wsec, sizeof(wsec));
    if (!NT_SUCCESS(status)) return status;

    if (Params->HostFips) {
        status = Ap6256FipsSetQos(Ctx, 0, Params->HostFipsHt);
        if (!NT_SUCCESS(status)) return status;
    } else (VOID)Ap6256WifiSetBssWmm(Ctx, TRUE);

    {
        UINT32 mfp = (UINT32)Params->Mfp;
        NTSTATUS mfpStatus = Ap6256BcdcSetIovar(Ctx, "mfp", &mfp, sizeof(mfp));
        if ((sae || owe || Ft || Params->HostFips || hostCipher || Params->Wpa3Enterprise) && !NT_SUCCESS(mfpStatus)) return mfpStatus;

        if (NT_SUCCESS(Ap6256WifiSetMfpWsecBit(Ctx,
                                               (BOOLEAN)(mfp != 0))) &&
            mfp != 0) {

            wsec |= WSEC_MFP_CAPABLE;
        }

        if (!NT_SUCCESS(mfpStatus)) {
            TraceWarn(TRACE_NETADAPTER, "mfp %u not programmed 0x%08X; association "
                      "will be unprotected\n", mfp, mfpStatus);
        } else if (mfp != 0) {
            TraceInfo(TRACE_NETADAPTER, "mfp %u\n", mfp);
        }
        if (hostCipher && mfp == 2) wsec |= WSEC_MFP_REQUIRED;
    }

    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &infra, sizeof(infra));
    if (!NT_SUCCESS(status)) return status;
    } else if (Params->Mfp != Ap6256MfpNone) wsec |= WSEC_MFP_CAPABLE;
    if (Params->Wpa3Enterprise) wsec |= WSEC_MFP_REQUIRED;
    if (sae) {
        if (privateSae) {
            status = Ap6256SaeSetBip(Ctx);
            if (!NT_SUCCESS(status)) return status;
        }

        wsec |= WSEC_MFP_CAPABLE | WSEC_MFP_REQUIRED;

        if (privateSae) wsec |= WSEC_SHA256_KDF;
        status = Ap6256SaeVerifySecurity(Ctx, wsec, Params->PmkidValid);
        if (!NT_SUCCESS(status)) {
            TraceDiag("SAE: security readback refused join (0x%08X)\n", status);
            return status;
        }
        status = Ap6256SaeSetPmkid(Ctx, Params->Bssid,
            Params->PmkidValid ? Params->Pmkid : NULL);
        if (!NT_SUCCESS(status)) return status;
    }

    if (owe) {
        wsec |= WSEC_MFP_CAPABLE | WSEC_MFP_REQUIRED;
        status = Ap6256OwePrepareSecurity(Ctx);
        if (!NT_SUCCESS(status)) return status;

        status = Ap6256SaeSetPmkid(Ctx, Params->Bssid, NULL);
        if (!NT_SUCCESS(status)) return status;
    }

    if ((hostCipher && !sae && !owe) || Params->Wpa3Enterprise) {
        if (Params->Mfp != Ap6256MfpNone) {

            const UCHAR selector[] = {0, 15, 172, 6};
            UCHAR got[sizeof(selector)] = {0};
            AP6256_BCDC_QUERY_RESULT result = {0};
            if (!Ctx->FirmwareMfpSupported) return STATUS_NOT_SUPPORTED;
            status = Ap6256BcdcSetIovarResultIf(Ctx, 0, "bip", selector, sizeof(selector), &result);
            if (!NT_SUCCESS(status)) return status;
            if (!result.FirmwareReply || result.FirmwareError || result.FirmwareStatus)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "bip", got, sizeof(got), &result);
            if (!NT_SUCCESS(status)) return status;
            if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(got) ||
                !RtlEqualMemory(got, selector, sizeof(selector))) return STATUS_DEVICE_PROTOCOL_ERROR;
        }

        status = Ap6256SaeSetPmkid(Ctx, Params->Bssid,
            Params->PmkidValid ? Params->Pmkid : NULL);
        if (!NT_SUCCESS(status)) return status;
    }

    if (Params->HostFips) {
        status = Ap6256FipsVerifySecurity(Ctx, 0, wsec, wpaAuth);
        if (!NT_SUCCESS(status)) return status;
    } else if (hostCipher || Params->Wpa3Enterprise) {
        const UINT32 commands[] = {BRCMF_C_GET_AUTH, BRCMF_C_GET_WPA_AUTH,
            BRCMF_C_GET_WSEC, BRCMF_C_GET_INFRA};
        const UINT32 expected[] = {auth, wpaAuth, wsec, infra};
        AP6256_BCDC_QUERY_RESULT result = {0};
        UINT32 got, index;
        for (index = 0; index < RTL_NUMBER_OF(commands); ++index) {
            got = 0;
            status = Ap6256BcdcQueryDcmdResultIf(Ctx, 0, commands[index], &got, sizeof(got), &result);
            if (!NT_SUCCESS(status)) return status;
            if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(got) ||
                got != expected[index]) return STATUS_DEVICE_PROTOCOL_ERROR;
        }
        got = 0;
        status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "mfp", &got, sizeof(got), &result);
        if (!NT_SUCCESS(status)) return status;
        if (!result.FirmwareReply || result.FirmwareError || result.PayloadLength < sizeof(got) ||
            got != (UINT32)Params->Mfp) return STATUS_DEVICE_PROTOCOL_ERROR;
    } else {
        UINT32 gotWsec = 0, gotWpaAuth = 0, gotAuth = 0, gotInfra = 0;

        status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_WSEC,
                                  &gotWsec, sizeof(gotWsec));
        if ((Ft || Params->HostFips) && !NT_SUCCESS(status)) return status;
        status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_WPA_AUTH,
                                  &gotWpaAuth, sizeof(gotWpaAuth));
        if ((Ft || Params->HostFips) && !NT_SUCCESS(status)) return status;
        status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_AUTH,
                                  &gotAuth, sizeof(gotAuth));
        if ((Ft || Params->HostFips) && !NT_SUCCESS(status)) return status;
        status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_INFRA,
                                  &gotInfra, sizeof(gotInfra));
        if ((Ft || Params->HostFips) && !NT_SUCCESS(status)) return status;

        TraceDiag("security readback: wsec %u/%u wpa_auth %u/%u auth %u/%u "
                  "infra %u/%u (set/got)%s\n",
                  wsec, gotWsec, wpaAuth, gotWpaAuth, auth, gotAuth,
                  infra, gotInfra,
                  (gotWsec == wsec && gotWpaAuth == wpaAuth &&
                   gotAuth == auth && gotInfra == infra)
                      ? "" : "  <- MISMATCH");
        if (Ft || Params->HostFips) {
            UINT32 gotMfp = 0;
            if (gotWsec != wsec || gotWpaAuth != wpaAuth || gotAuth != auth || gotInfra != infra)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            status = Ap6256BcdcGetIovar(Ctx, "mfp", &gotMfp, sizeof(gotMfp));
            if (!NT_SUCCESS(status)) return status;
            if (gotMfp != (UINT32)Params->Mfp) return STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }

    (VOID)Ap6256WifiSetPowerSave(Ctx, FALSE);

    if (Params->Security == Ap6256SecurityWpa2Firmware) {
        BRCMF_WSEC_PMK pmk;
        if (Params->PassphraseLength < 8 || Params->PassphraseLength > 63) {
            return STATUS_INVALID_PARAMETER;
        }
        RtlZeroMemory(&pmk, sizeof(pmk));
        pmk.KeyLen = (UINT16)Params->PassphraseLength;
        pmk.Flags = BRCMF_WSEC_PASSPHRASE;
        RtlCopyMemory(pmk.Key, Params->Passphrase, Params->PassphraseLength);
        status = Ap6256BcdcSetIovar(Ctx, "set_pmk", &pmk, sizeof(pmk));
        if (!NT_SUCCESS(status)) {

            TraceWarn(TRACE_NETADAPTER,
                      "set_pmk iovar refused 0x%08X; trying the legacy "
                      "command\n", status);
            status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WSEC_PMK,
                                       &pmk, sizeof(pmk));
            if (!NT_SUCCESS(status)) return status;
        }
    }

    if (!sae && !owe && !Ft && !Params->HostFips && !hadFips && !hostCipher && !hadHostCipher &&
        Params->BssidValid && Ctx->FirmwareLinkUp) {
        UCHAR current[6];

        if (NT_SUCCESS(Ap6256WifiGetBssid(Ctx, current)) &&
            RtlCompareMemory(current, Params->Bssid, 6) == 6 &&
            NT_SUCCESS(Ap6256WifiReassociate(Ctx, Params->Bssid))) {
            Ctx->ConnectionRequiresSupplicant =
                (Params->Security == Ap6256SecurityWpa2Firmware);
            Ctx->SupplicantComplete = !Ctx->ConnectionRequiresSupplicant;
            return STATUS_SUCCESS;
        }
    }

    Ctx->ConnectionRequiresSupplicant =
        (Params->Security == Ap6256SecurityWpa2Firmware);
    Ctx->FirmwareLinkUp = FALSE;
    Ctx->SupplicantComplete = !Ctx->ConnectionRequiresSupplicant;

    (VOID)Ap6256WifiSetU32(Ctx, BRCMF_C_SET_ASSOC_PREFER,
                           Params->Channel == 0 ? WLC_BAND_AUTO :
                           (Params->Channel <= 14 ? WLC_BAND_2G : WLC_BAND_5G),
                           "assoc band preference");

    RtlZeroMemory(&join, sizeof(join));
    join.Ssid.SsidLen = Params->SsidLength;
    RtlCopyMemory(join.Ssid.Ssid, Params->Ssid, Params->SsidLength);
    if (Params->BssidValid) {
        RtlCopyMemory(join.Params.Bssid, Params->Bssid, 6);
    } else {
        RtlFillMemory(join.Params.Bssid, 6, 0xFF);
    }

    joinLen = FIELD_OFFSET(BRCMF_JOIN_PARAMS, Params.ChanspecList);
    join.Params.ChanspecNum = 0;

    if (Params->Channel != 0) {
        AP6256_SCAN_CHANNEL channel;
        UINT16 chanspec = 0;

        channel.Number = (UINT16)Params->Channel;
        channel.Band = Params->Channel <= 14 ? Ap6256ScanBand2G
                                             : Ap6256ScanBand5G;

        if (!Ctx->Go.Started && !ftRoam)
            (VOID)Ap6256WifiSetU32(Ctx, BRCMF_C_SET_CHANNEL, Params->Channel,
                                   "target channel");

        if (NT_SUCCESS(Ap6256EncodeChanspec(Ctx->D11IoType, &channel,
                                            &chanspec))) {
            join.Params.ChanspecNum = 1;
            join.Params.ChanspecList[0] = chanspec;
            joinLen = sizeof(BRCMF_JOIN_PARAMS);
        } else {
            TraceWarn(TRACE_NETADAPTER,
                      "channel %u has no chanspec; letting the firmware "
                      "find the BSS\n", Params->Channel);
        }
    }

    TraceInfo(TRACE_NETADAPTER, "connecting to '%.*s' (%s) on %s\n",
              (int)Params->SsidLength, Params->Ssid,
              Params->Security == Ap6256SecurityOpen ? "open" :
              (Params->Security == Ap6256SecurityWpa2Enterprise ? "WPA2 Enterprise host" :
              (Params->Security == Ap6256SecurityWpa2Host ? "WPA2 host" :
              (Params->Security == Ap6256SecuritySaeHost ? "WPA3 SAE host" :
              (owe ? "OWE host" : "WPA2 firmware")))),
              join.Params.ChanspecNum != 0 ? "the requested channel"
                                           : "any channel");

    if (Ft) {
        if (join.Params.ChanspecNum != 1) return STATUS_INVALID_PARAMETER;
        status = Ap6256FtBegin(Ctx, Ft->State, Ft->PortId, Ft->TransactionId,
            Params->Bssid, Ft->Reassociation, Ft->Mde, sizeof(Ft->Mde),
            Ft->Reassociation ? Ft->Fte : NULL, Ft->FteLength,
            Ft->Reassociation ? Ft->PmkR0Name : NULL, Ft->Reassociation ? 16u : 0u);
        if (!NT_SUCCESS(status)) return status;
    }
    if (privateSae) {
        if (join.Params.ChanspecNum != 1) return STATUS_INVALID_PARAMETER;
        status = Ap6256SaePrivateArm(Ctx, Params->SaeFirmwareGeneration,
            Params->Bssid, Params->SaeTimeoutMs, Params->PmkidValid ? Params->Pmkid : NULL,
            Params->SaeCachedH2e);
        if (!NT_SUCCESS(status)) return status;
    }
    if (owe) {
        if (join.Params.ChanspecNum != 1) return STATUS_INVALID_PARAMETER;
        status = Ap6256OweArm(Ctx, Params);
        if (!NT_SUCCESS(status)) {
            (VOID)Ap6256OweEnd(Ctx, FALSE);
            return status;
        }
    }
    if (Params->HostFips) {
        status = Ap6256FipsBegin(Ctx, 0, Ctx->MacAddress, Params->Bssid);
        if (!NT_SUCCESS(status)) return status;
    }
    if (hostCipher) {
        if (join.Params.ChanspecNum != 1) {status = STATUS_INVALID_PARAMETER; goto joinFailure;}
        status = Ap6256HostCipherBeginProfileRx(Ctx, 0, Ctx->MacAddress, Params->Bssid,
            Params->HostCipherAkm, (UINT32)Params->Mfp, Params->ExcludeUnencrypted);
        if (!NT_SUCCESS(status)) goto joinFailure;
    }
    if (ftRoam) {
        BRCMF_REASSOC_PARAMS reassoc = {0};
        RtlCopyMemory(reassoc.Bssid, Params->Bssid, 6);
        reassoc.ChanspecNum = 1;
        reassoc.ChanspecList[0] = join.Params.ChanspecList[0];
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_REASSOC, &reassoc, sizeof(reassoc));
    } else status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_SSID, &join, joinLen);
joinFailure:
    if (hostCipher && !NT_SUCCESS(status)) {
        (VOID)Ap6256HostCipherEnd(Ctx, 0, FALSE);
        if (privateSae) (VOID)Ap6256SaePrivateEnd(Ctx, Params->SaeFirmwareGeneration, Params->Bssid, FALSE);
    }
    if (Ft && !NT_SUCCESS(status)) (VOID)Ap6256FtEnd(Ctx, Ft->State, FALSE);
    if (owe && !NT_SUCCESS(status)) (VOID)Ap6256OweEnd(Ctx, FALSE);
    if (Params->HostFips && !NT_SUCCESS(status)) (VOID)Ap6256FipsStop(Ctx, 0);

    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiConnect(PAP6256_DEVICE_CONTEXT Ctx, PAP6256_CONNECT_PARAMS Params)
{
    return Ap6256WifiConnectCommon(Ctx, Params, NULL);
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiConnectFt(PAP6256_DEVICE_CONTEXT Ctx,
    PAP6256_CONNECT_PARAMS Params, AP6256_CONNECT_FT_SETUP* Setup)
{
    if (Setup == NULL || Setup->State == NULL) return STATUS_INVALID_PARAMETER;
    return Ap6256WifiConnectCommon(Ctx, Params, Setup);
}

#define AP6256_MCAST_MAX 64

typedef struct _AP6256_MCAST_LIST {
    UINT32 Count;
    UCHAR  Addresses[AP6256_MCAST_MAX][6];
} AP6256_MCAST_LIST;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMulticastList(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_reads_opt_(Count) const VOID* Addresses,
                                    _In_ ULONG Count)
{
    AP6256_MCAST_LIST list;
    UINT32 allMulti;
    NTSTATUS status;

    if (Count != 0 && Addresses == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    allMulti = (Count > AP6256_MCAST_MAX || Ctx->AllMulticastRequested) ? 1 : 0;

    RtlZeroMemory(&list, sizeof(list));
    if (Count != 0 && Count <= AP6256_MCAST_MAX) {
        RtlCopyMemory(list.Addresses, Addresses, Count * 6);
        list.Count = Count;
    }

    status = Ap6256BcdcSetIovar(
        Ctx, "mcast_list", &list,
        FIELD_OFFSET(AP6256_MCAST_LIST, Addresses) + (list.Count * 6));
    if (!NT_SUCCESS(status)) {

        allMulti = 1;
        (VOID)Ap6256BcdcSetIovar(Ctx, "allmulti", &allMulti, sizeof(allMulti));
        return status;
    }

    return Ap6256BcdcSetIovar(Ctx, "allmulti", &allMulti, sizeof(allMulti));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ ULONG Filter, _In_ BOOLEAN SendUpMgmt)
{
    BOOLEAN promiscuous =
        (BOOLEAN)((Filter & AP6256_RXF_PROMISCUOUS) != 0);
    BOOLEAN allMulticast =
        (BOOLEAN)(promiscuous || (Filter & AP6256_RXF_ALL_MULTICAST) != 0);
    UINT32 allMulti = allMulticast ? 1 : 0;
    UINT32 promisc = promiscuous ? 1 : 0;
    UINT32 sendUp = SendUpMgmt ? 1 : 0;
    NTSTATUS status;

    InterlockedExchange(&Ctx->PacketFilter, (LONG)Filter);
    Ctx->AllMulticastRequested = allMulticast;
    Ctx->PromiscuousRequested = promiscuous;

    status = Ap6256BcdcSetIovar(Ctx, "sendup_mgmt", &sendUp, sizeof(sendUp));
    if (!NT_SUCCESS(status) && SendUpMgmt) {
        TraceWarn(TRACE_NETADAPTER,
                  "sendup_mgmt = 1 refused 0x%08X; 802.11 management classes "
                  "will not be delivered\n", status);
    }

    Ctx->PacketFilterMask = Filter;
    status = Ap6256WifiSetMasterPacketFilter(Ctx, Filter);
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "packet_filter 0x%08X refused 0x%08X\n", Filter, status);
    }

    status = Ap6256BcdcSetIovar(Ctx, "allmulti", &allMulti, sizeof(allMulti));
    if (!NT_SUCCESS(status)) return status;

    return Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_PROMISC, &promisc,
                             sizeof(promisc));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDisconnect(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR bssid[6];

    if (NT_SUCCESS(Ap6256WifiGetBssid(Ctx, bssid))) {
        return Ap6256WifiDisconnectWithReason(Ctx, bssid,
                                              AP6256_REASON_LEAVING);
    }
    return Ap6256WifiDisconnectWithReason(Ctx, NULL, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_reads_(6) const UCHAR* Address)
{
    if (Address == NULL) return STATUS_INVALID_PARAMETER;
    return Ap6256BcdcSetIovar(Ctx, "cur_etheraddr", Address, 6);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetPermanentMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                          _Out_writes_(6) PUCHAR Address)
{

    RtlZeroMemory(Address, 6);
    return Ap6256BcdcGetIovar(Ctx, "perm_etheraddr", Address, 6);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMfpWsecBit(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enable)
{
    UINT32 wsec = 0;
    UINT32 wanted;
    NTSTATUS status = Ap6256BcdcGetIovar(Ctx, "wsec", &wsec, sizeof(wsec));

    if (!NT_SUCCESS(status)) return status;

    wanted = Enable ? (wsec | WSEC_MFP_CAPABLE) :
        (wsec & ~(WSEC_MFP_CAPABLE | WSEC_MFP_REQUIRED));
    if (wanted == wsec) return STATUS_SUCCESS;

    status = Ap6256BcdcSetIovar(Ctx, "wsec", &wanted, sizeof(wanted));
    TraceDiag("wsec 0x%08X -> 0x%08X (MFP %s) 0x%08X\n",
              wsec, wanted, Enable ? "on" : "off", status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiResetFirmwareCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    (VOID)Ap6256BcdcSetIovar(Ctx, "wme_clear_counters", NULL, 0);
    (VOID)Ap6256BcdcSetIovar(Ctx, "reset_d11cnts", NULL, 0);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiClearSecurityState(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    ULONG slot;
    NTSTATUS status = STATUS_SUCCESS, step;
    UCHAR pmkids[AP6256_PMKID_CLEAR_BYTES];

    if (Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, 0) || Ap6256FipsActive(Ctx, 0))
        return STATUS_NOT_SUPPORTED;
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    if (Ctx->NativeDeparturePending && !Ctx->NativeDepartureCommitted) {
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return STATUS_DEVICE_BUSY;
    }
    Ctx->NativeDeparturePending = FALSE;
    for (slot = 0; slot < AP6256_NATIVE_KEY_SLOTS; ++slot) {
        AP6256_NATIVE_KEY_REF ref = Ctx->NativeKeys[slot];
        if (!ref.Valid) continue;
        step = ref.Management ? Ap6256WifiDeleteBipKeyIf(Ctx, 0, ref.KeyId, ref.PeerAddress) :
            Ap6256WifiDeleteCcmpKeyIf(Ctx, 0, ref.KeyId, ref.Pairwise, ref.PeerAddress);
        if (!NT_SUCCESS(step) && NT_SUCCESS(status)) status = step;
    }
    if (NT_SUCCESS(status)) status = Ap6256WifiSetMfpWsecBit(Ctx, FALSE);
    step = Ap6256WifiSetBssWmm(Ctx, TRUE);
    if (!NT_SUCCESS(step) && NT_SUCCESS(status)) status = step;
    RtlZeroMemory(pmkids, sizeof(pmkids));
    step = Ap6256BcdcSetIovar(Ctx, "pmkid_info", pmkids, sizeof(pmkids));
    if (!NT_SUCCESS(step) && NT_SUCCESS(status)) status = step;
    if (Ctx->NativeDepartureCommitted) {
        if (NT_SUCCESS(status)) {
            Ctx->NativeDepartureToken = 0;
            Ctx->NativeDepartureCommitted = FALSE;
            Ctx->NativeDepartureReason = 0;
            RtlZeroMemory(Ctx->NativeDeparturePeer, sizeof(Ctx->NativeDeparturePeer));
        } else Ctx->NativeDeparturePending = TRUE;
    }
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    TraceVerbose(TRACE_DRIVER, "station security cleanup: tracked keys and PMF -> 0x%08X\n", status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiResetMib(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 infra = 1;
    UINT32 disabled = 0;
    NTSTATUS status;

    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &infra, sizeof(infra));
    if (!NT_SUCCESS(status)) return status;
    (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_DISASSOC, NULL, 0);
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AUTH, &disabled, sizeof(disabled));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WPA_AUTH,
                               &disabled, sizeof(disabled));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WSEC, &disabled, sizeof(disabled));
    if (!NT_SUCCESS(status)) return status;
    (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WEP_RESTRICT,
                            &disabled, sizeof(disabled));

    Ap6256WifiResetFirmwareCounters(Ctx);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddBipKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ PAP6256_BIP_KEY Key)
{
    BRCMF_WSEC_KEY firmwareKey;
    NTSTATUS status;

    static const UCHAR zeroAddress[6] = {0};

    if ((Key->KeyId != 4 && Key->KeyId != 5) ||
        Key->KeyLength != AP6256_BIP_KEY_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ap6256FipsActive(Ctx, Key->IfIndex)) return STATUS_NOT_SUPPORTED;

    status = Ap6256WlfcWaitEapol(Ctx, Key->IfIndex);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&firmwareKey, sizeof(firmwareKey));
    firmwareKey.Index = Key->KeyId;
    firmwareKey.Length = Key->KeyLength;
    RtlCopyMemory(firmwareKey.Data, Key->Key, Key->KeyLength);
    RtlCopyMemory(firmwareKey.PeerAddress, Key->PeerAddress,
                  sizeof(firmwareKey.PeerAddress));
    firmwareKey.Algorithm = BRCMF_CRYPTO_ALGO_AES_CCM;
    if (RtlEqualMemory(Key->PeerAddress, zeroAddress, sizeof(zeroAddress)))
        firmwareKey.Flags = BRCMF_PRIMARY_KEY;
    firmwareKey.IvInitialized = 1;
    firmwareKey.RxIvHigh = ((UINT32)Key->Ipn[5] << 24) | ((UINT32)Key->Ipn[4] << 16) |
        ((UINT32)Key->Ipn[3] << 8) | Key->Ipn[2];
    firmwareKey.RxIvLow = (UINT16)(((UINT16)Key->Ipn[1] << 8) | Key->Ipn[0]);

    status = Ap6256WifiWriteNativeKey(Ctx, Key->IfIndex, &firmwareKey, FALSE, TRUE);

    TraceVerbose(TRACE_DRIVER, "IGTK command t100ns %llu if %u id %u -> 0x%08X\n",
        KeQueryInterruptTime(), Key->IfIndex, Key->KeyId, status);
    if (NT_SUCCESS(status) && Key->IfIndex == 0)
        Ap6256WifiSeedGroupKey(Ctx, Key->KeyId, TRUE, TRUE, Key->Key, Key->Ipn);
    RtlSecureZeroMemory(&firmwareKey, sizeof(firmwareKey));
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiDeleteBipKeyIf(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    ULONG KeyId, const UCHAR* PeerAddress)
{
    static const UCHAR zeroAddress[6] = {0};
    BRCMF_WSEC_KEY firmwareKey;
    NTSTATUS status;
    if (KeyId != 4 && KeyId != 5) return STATUS_INVALID_PARAMETER;
    if (Ap6256FipsActive(Ctx, IfIndex)) return STATUS_NOT_SUPPORTED;
    RtlZeroMemory(&firmwareKey, sizeof(firmwareKey));
    firmwareKey.Index = KeyId;
    RtlCopyMemory(firmwareKey.PeerAddress, PeerAddress, sizeof(firmwareKey.PeerAddress));
    if (RtlEqualMemory(PeerAddress, zeroAddress, sizeof(zeroAddress)))
        firmwareKey.Flags = BRCMF_PRIMARY_KEY;

    status = Ap6256WifiWriteNativeKey(Ctx, IfIndex, &firmwareKey, FALSE, TRUE);
    if (NT_SUCCESS(status) && IfIndex == 0)
        Ap6256WifiSeedGroupKey(Ctx, (UINT32)KeyId, TRUE, FALSE, NULL, NULL);
    TraceDiag("IGTK delete if %u id %u -> 0x%08X\n", IfIndex, KeyId, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256WifiTracePeerAuthorization(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 IfIndex, const UCHAR* Address)
{
    UCHAR sta[512] = {0};
    UINT16 version, length;
    UINT32 flags;
    NTSTATUS status;
    RtlCopyMemory(sta, Address, 6);
    status = Ap6256BcdcGetIovarIf(Ctx, IfIndex, "sta_info", sta, sizeof(sta));
    if (!NT_SUCCESS(status)) {
        TraceDiag("hotspot: authorized peer readback if %u -> 0x%08X\n", IfIndex, status);
        return;
    }
    RtlCopyMemory(&version, sta, 2);
    RtlCopyMemory(&length, sta + 2, 2);
    if (version < 4 || length < 22 || length > sizeof(sta) ||
        !RtlEqualMemory(sta + 16, Address, 6)) {
        TraceDiag("hotspot: authorized peer readback if %u invalid identity/layout v%u len %u\n",
            IfIndex, (ULONG)version, (ULONG)length);
        return;
    }
    RtlCopyMemory(&flags, sta + 8, 4);
    TraceDiag("hotspot: authorized peer readback if %u flags 0x%X authorized %u\n",
        IfIndex, flags, (ULONG)((flags & 0x20u) != 0));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddCcmpKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _In_ PAP6256_CCMP_KEY Key)
{
    BRCMF_WSEC_KEY firmwareKey;
    NTSTATUS status;

    if (Key->KeyId >= 16 || (Key->Pairwise &&
        (Key->PeerAddress[0] & 1) != 0)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ap6256FipsActive(Ctx, Key->IfIndex)) {
        AP6256_FIPS_SESSION session;
        if (!Ap6256FipsSnapshot(Ctx, Key->IfIndex, &session)) return STATUS_DEVICE_NOT_READY;
        if (Key->KeyId >= 4 || (Key->Pairwise && !RtlEqualMemory(Key->PeerAddress, session.Bssid, 6)))
            return STATUS_INVALID_PARAMETER;

        return Key->Pairwise ? Ap6256BcdcSetDcmdIf(Ctx, Key->IfIndex, BRCMF_C_SCB_AUTHORIZE,
            Key->PeerAddress, sizeof(Key->PeerAddress)) : STATUS_SUCCESS;
    }

    status = Ap6256WlfcWaitEapol(Ctx, Key->IfIndex);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&firmwareKey, sizeof(firmwareKey));
    firmwareKey.Index = Key->KeyId;
    firmwareKey.Length = sizeof(Key->Key);
    RtlCopyMemory(firmwareKey.Data, Key->Key, sizeof(Key->Key));
    firmwareKey.Algorithm = BRCMF_CRYPTO_ALGO_AES_CCM;
    if (Key->Pairwise) {
        RtlCopyMemory(firmwareKey.PeerAddress, Key->PeerAddress,
                      sizeof(firmwareKey.PeerAddress));
    } else {
        firmwareKey.Flags = BRCMF_PRIMARY_KEY;
    }
    if (Key->ReceiveSequenceValid) {
        firmwareKey.RxIvHigh = ((UINT32)Key->ReceiveSequence[5] << 24) |
                               ((UINT32)Key->ReceiveSequence[4] << 16) |
                               ((UINT32)Key->ReceiveSequence[3] << 8) |
                               Key->ReceiveSequence[2];
        firmwareKey.RxIvLow = (UINT16)(((UINT16)Key->ReceiveSequence[1] << 8) |
                                       Key->ReceiveSequence[0]);
        firmwareKey.IvInitialized = 1;
    }

    status = Ap6256WifiWriteNativeKey(Ctx, Key->IfIndex, &firmwareKey, Key->Pairwise, FALSE);

    TraceVerbose(TRACE_DRIVER, "CCMP key command t100ns %llu if %u id %u pairwise %u rxiv %u -> 0x%08X\n",
        KeQueryInterruptTime(), Key->IfIndex, Key->KeyId, (ULONG)Key->Pairwise,
        (ULONG)Key->ReceiveSequenceValid, status);
    if (NT_SUCCESS(status) && Key->Pairwise) {
        status = Ap6256BcdcSetDcmdIf(Ctx, Key->IfIndex, BRCMF_C_SCB_AUTHORIZE,
                                    firmwareKey.PeerAddress,
                                    sizeof(firmwareKey.PeerAddress));
        TraceDiag("controlled port authorize if %u peer "
                  "%02X:%02X:%02X:%02X:%02X:%02X -> 0x%08X\n", Key->IfIndex,
                  firmwareKey.PeerAddress[0], firmwareKey.PeerAddress[1],
                  firmwareKey.PeerAddress[2], firmwareKey.PeerAddress[3],
                  firmwareKey.PeerAddress[4], firmwareKey.PeerAddress[5], status);
        if (!NT_SUCCESS(status)) {

            NTSTATUS cleanup = Ap6256WifiDeleteCcmpKeyIf(Ctx, Key->IfIndex,
                Key->KeyId, TRUE, Key->PeerAddress);
            TraceDiag("controlled port authorization failed; key rollback if %u -> 0x%08X\n",
                Key->IfIndex, cleanup);
        } else if (Ctx->Go.FirmwareReady && Ctx->Go.Started &&
                   Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO &&
                   Key->IfIndex == Ctx->Go.IfIndex) {
            ULONG stage;
            for (stage = 0; stage < Ap6256GoDataStageCount; stage++) {
                InterlockedExchange(&Ctx->Go.DataTrace[stage], 0);
                InterlockedExchange(&Ctx->Go.Ipv4Trace[0][stage], 0);
                InterlockedExchange(&Ctx->Go.Ipv4Trace[1][stage], 0);
            }
            Ap6256WifiTracePeerAuthorization(Ctx, Key->IfIndex, Key->PeerAddress);
        }
    }

    if (NT_SUCCESS(status) && !Key->Pairwise && Key->IfIndex == 0)
        Ap6256WifiSeedGroupKey(Ctx, Key->KeyId, FALSE, TRUE, Key->Key,
            Key->ReceiveSequenceValid ? Key->ReceiveSequence : NULL);
    if (NT_SUCCESS(status) && Key->Pairwise && Key->IfIndex == 0) {
        (VOID)Ap6256WifiSetPowerSave(Ctx, TRUE);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDeleteCcmpKey(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ ULONG KeyId,
                                 _In_ BOOLEAN Pairwise,
                                 _In_reads_(6) const UCHAR* PeerAddress)
{
    return Ap6256WifiDeleteCcmpKeyIf(Ctx, 0, KeyId, Pairwise, PeerAddress);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiDeleteCcmpKeyIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ ULONG KeyId, _In_ BOOLEAN Pairwise, _In_reads_(6) const UCHAR* PeerAddress)
{
    BRCMF_WSEC_KEY firmwareKey;
    NTSTATUS status;

    if (KeyId >= 16 || (Pairwise && ((PeerAddress[0] & 1) != 0))) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ap6256FipsActive(Ctx, IfIndex)) {
        AP6256_FIPS_SESSION session;
        if (!Ap6256FipsSnapshot(Ctx, IfIndex, &session)) {

            if (Ap6256FipsRetired(Ctx, IfIndex))
                return KeyId < 4 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
            return STATUS_DEVICE_NOT_READY;
        }
        if (KeyId >= 4 || (Pairwise && !RtlEqualMemory(PeerAddress, session.Bssid, 6)))
            return STATUS_INVALID_PARAMETER;
        return Pairwise ? Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SCB_DEAUTHORIZE,
            (PVOID)(ULONG_PTR)PeerAddress, 6) : STATUS_SUCCESS;
    }
    Ap6256LockAcquire(&Ctx->NativeKeyLock);
    if (IfIndex == 0 && Ctx->NativeDeparturePending) {
        Ap6256LockRelease(&Ctx->NativeKeyLock);
        return STATUS_DEVICE_BUSY;
    }
    RtlZeroMemory(&firmwareKey, sizeof(firmwareKey));
    firmwareKey.Index = KeyId;
    if (Pairwise) {
        RtlCopyMemory(firmwareKey.PeerAddress, PeerAddress,
                      sizeof(firmwareKey.PeerAddress));
    } else {
        firmwareKey.Flags = BRCMF_PRIMARY_KEY;
    }
    if (Pairwise) {
        (VOID)Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SCB_DEAUTHORIZE,
                                (PVOID)(ULONG_PTR)PeerAddress, 6);
    }

    status = Ap6256WifiWriteNativeKey(Ctx, IfIndex, &firmwareKey, Pairwise, FALSE);
    Ap6256LockRelease(&Ctx->NativeKeyLock);
    if (NT_SUCCESS(status) && !Pairwise && IfIndex == 0)
        Ap6256WifiSeedGroupKey(Ctx, (UINT32)KeyId, FALSE, FALSE, NULL, NULL);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetWpsEnabled(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ BOOLEAN Enabled)
{
    return Ap6256WifiSetWpsEnabledIf(Ctx, 0, Enabled);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetWpsEnabledIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ BOOLEAN Enabled)
{
    UINT32 wsec = 0;
    NTSTATUS status;

    status = Ap6256BcdcQueryDcmdIf(Ctx, IfIndex, BRCMF_C_GET_WSEC, &wsec, sizeof(wsec));
    if (!NT_SUCCESS(status)) return status;

    if (Enabled) {
        wsec |= SES_OW_ENABLED;
    } else {
        wsec &= ~(UINT32)SES_OW_ENABLED;
    }

    status = Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SET_WSEC, &wsec, sizeof(wsec));
    TraceInfo(TRACE_NETADAPTER, "WPS %s: wsec 0x%X -> 0x%08X\n",
              Enabled ? "enabled" : "disabled", wsec, status);
    return status;
}

#pragma pack(push, 1)
typedef struct _BRCMF_ASSOC_DECISION {
    UCHAR  Accept;
    UCHAR  Pad;
    UINT16 StatusCode;
    UCHAR  PeerAddress[6];
    UCHAR  Reserved[6];
    UINT64 Timestamp;
} BRCMF_ASSOC_DECISION;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(BRCMF_ASSOC_DECISION, StatusCode) == 2);
C_ASSERT(FIELD_OFFSET(BRCMF_ASSOC_DECISION, PeerAddress) == 4);
C_ASSERT(FIELD_OFFSET(BRCMF_ASSOC_DECISION, Timestamp) == 16);
C_ASSERT(sizeof(BRCMF_ASSOC_DECISION) == 24);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendAssocDecision(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                     _In_reads_(6) const UCHAR* PeerAddress,
                                     _In_ BOOLEAN Accept,
                                     _In_ UINT16 StatusCode)
{
    return Ap6256WifiSendAssocDecisionIf(Ctx, 0, PeerAddress, Accept, StatusCode);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendAssocDecisionIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_reads_(6) const UCHAR* PeerAddress, _In_ BOOLEAN Accept, _In_ UINT16 StatusCode)
{
    BRCMF_ASSOC_DECISION decision;
    LARGE_INTEGER now;
    NTSTATUS status;

    RtlZeroMemory(&decision, sizeof(decision));
    decision.Accept = Accept ? 1 : 0;
    decision.StatusCode = StatusCode;
    RtlCopyMemory(decision.PeerAddress, PeerAddress, 6);
    if (Accept) {
        KeQuerySystemTime(&now);
        decision.Timestamp = (UINT64)now.QuadPart;
    }

    status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "assoc_decision", &decision,
                                sizeof(decision));
    TraceInfo(TRACE_NETADAPTER,
              "association %s for %02X:%02X:%02X:%02X:%02X:%02X "
              "(status %u) -> 0x%08X\n",
              Accept ? "ACCEPTED" : "REFUSED",
              PeerAddress[0], PeerAddress[1], PeerAddress[2],
              PeerAddress[3], PeerAddress[4], PeerAddress[5],
              (ULONG)StatusCode, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiStartAp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ PAP6256_AP_PARAMS Params)
{
    UINT32 value;
    UINT32 wsec;
    UINT32 wpaAuth;
    NTSTATUS status;
    WLC_SSID ssid;

    if (Params->SsidLength == 0 || Params->SsidLength > sizeof(ssid.Ssid)) {
        return STATUS_INVALID_PARAMETER;
    }

    (VOID)Ap6256WifiRadioUpDown(Ctx, FALSE);

    value = 0;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;

    value = 1;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AP, &value, sizeof(value));
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER,
                   "start AP: the firmware refused the AP role 0x%08X\n",
                   status);
        return status;
    }

    if (Params->BeaconPeriod != 0) {
        value = Params->BeaconPeriod;
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_BCNPRD, &value,
                                   sizeof(value));
        if (!NT_SUCCESS(status)) return status;
    }
    if (Params->DtimPeriod != 0) {
        value = Params->DtimPeriod;
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_DTIMPRD, &value,
                                   sizeof(value));
        if (!NT_SUCCESS(status)) return status;
    }

    value = Params->ExcludeUnencrypted ? 1u : 0u;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WEP_RESTRICT, &value,
                               sizeof(value));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "start AP: EAP restrict %u refused 0x%08X\n",
                  value, status);
    }

    switch (Params->Security) {
    case Ap6256SecurityOpen:
        wsec = 0;
        wpaAuth = WPA_AUTH_DISABLED;
        break;
    case Ap6256SecurityWpa2Host:
    case Ap6256SecurityWpa2Firmware:
        wsec = WSEC_AES_ENABLED;
        wpaAuth = WPA2_AUTH_PSK;
        break;
    default:
        return STATUS_NOT_SUPPORTED;
    }

    value = wsec;

    value = 0;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AUTH, &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = wpaAuth;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WPA_AUTH, &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;
    value = wsec;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_WSEC, &value, sizeof(value));
    if (!NT_SUCCESS(status)) return status;

    if (Params->Channel != 0) {
        value = Params->Channel;
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_CHANNEL, &value,
                                   sizeof(value));
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER,
                      "start AP: channel %u refused 0x%08X\n",
                      Params->Channel, status);
        }
    }

    status = Ap6256WifiRadioUpDown(Ctx, TRUE);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&ssid, sizeof(ssid));
    ssid.SsidLen = Params->SsidLength;
    RtlCopyMemory(ssid.Ssid, Params->Ssid, Params->SsidLength);
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_SSID, &ssid, sizeof(ssid));

    if (NT_SUCCESS(status) && Params->Channel != 0) {
        value = Params->Channel;
        (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_CHANNEL, &value,
                                sizeof(value));
    }

    TraceInfo(TRACE_NETADAPTER,
              "AP started: %u byte SSID, channel %u, beacon %u, DTIM %u, "
              "wsec 0x%X wpa_auth 0x%X -> 0x%08X\n",
              Params->SsidLength, Params->Channel, Params->BeaconPeriod,
              Params->DtimPeriod, wsec, wpaAuth, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiStopAp(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 value;
    NTSTATUS status;

    Ap6256WlfcCancel(Ctx, AP6256_GROUP_PORT, AP6256_WLFC_ANY, NULL);

    (VOID)Ap6256WifiScanAbort(Ctx);

    (VOID)Ap6256WifiClearSecurityState(Ctx);

    status = Ap6256WifiRadioUpDown(Ctx, FALSE);

    value = 0;
    (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AP, &value, sizeof(value));
    value = 1;
    (VOID)Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &value, sizeof(value));
    (VOID)Ap6256WifiRadioUpDown(Ctx, TRUE);

    TraceInfo(TRACE_NETADAPTER, "AP stopped -> 0x%08X\n", status);
    return status;
}

#pragma pack(push, 1)
typedef struct _BRCMF_ACTION_FRAME {
    UCHAR  DestinationAddress[6];
    UINT16 Length;
    UINT32 PacketId;
    UCHAR  Data[1];
} BRCMF_ACTION_FRAME;

typedef struct _BRCMF_AF_PARAMS {
    UINT32 Channel;
    UINT32 DwellTime;
    UCHAR  Bssid[6];
    UCHAR  Pad[2];
    BRCMF_ACTION_FRAME ActionFrame;
} BRCMF_AF_PARAMS;
#pragma pack(pop)

C_ASSERT(FIELD_OFFSET(BRCMF_AF_PARAMS, Bssid) == 8);
C_ASSERT(FIELD_OFFSET(BRCMF_AF_PARAMS, ActionFrame) == 16);
C_ASSERT(FIELD_OFFSET(BRCMF_ACTION_FRAME, PacketId) == 8);

#define AP6256_ACTFRAME_IOVAR_NAME  "actframe"
#define AP6256_ACTFRAME_FIRMWARE_MAX  1800u
#define AP6256_ACTION_FRAME_MAX                                             \
    (AP6256_BCDC_TX_MAXLEN - (ULONG)sizeof(AP6256_ACTFRAME_IOVAR_NAME) -     \
     (ULONG)FIELD_OFFSET(BRCMF_AF_PARAMS, ActionFrame.Data))

C_ASSERT(AP6256_ACTION_FRAME_MAX <= AP6256_ACTFRAME_FIRMWARE_MAX);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSendActionFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ UINT32 IfIndex,
                                   _In_ UINT32 Channel,
                                   _In_ UINT32 DwellTimeMs,
                                   _In_reads_(6) const UCHAR* Bssid,
                                   _In_reads_(6) const UCHAR* Destination,
                                   _In_ UINT32 PacketId,
                                   _In_reads_bytes_(BodyLength) const UCHAR* Body,
                                   _In_ ULONG BodyLength)
{
    BRCMF_AF_PARAMS* params;
    ULONG total;
    NTSTATUS status;

    if (BodyLength == 0 || BodyLength > AP6256_ACTION_FRAME_MAX) {
        TraceWarn(TRACE_NETADAPTER,
                  "action frame of %u byte(s) refused: the body must be 1 to "
                  "%u bytes to cross BCDC\n",
                  BodyLength, (ULONG)AP6256_ACTION_FRAME_MAX);
        return STATUS_INVALID_PARAMETER;
    }

    total = (ULONG)FIELD_OFFSET(BRCMF_AF_PARAMS, ActionFrame.Data) + BodyLength;
    params = (BRCMF_AF_PARAMS*)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
                                               AP6256_POOL_TAG);
    if (params == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    params->Channel = Channel;
    params->DwellTime = DwellTimeMs;
    RtlCopyMemory(params->Bssid, Bssid, 6);
    RtlCopyMemory(params->ActionFrame.DestinationAddress, Destination, 6);
    params->ActionFrame.Length = (UINT16)BodyLength;
    params->ActionFrame.PacketId = PacketId;
    RtlCopyMemory(params->ActionFrame.Data, Body, BodyLength);

    status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, AP6256_ACTFRAME_IOVAR_NAME,
                                params, total);

    TraceDiag("action frame if %u -> %02X:%02X:%02X:%02X:%02X:%02X channel %u "
              "dwell %u ms, %u byte(s), id %u -> 0x%08X\n",
              IfIndex, Destination[0], Destination[1], Destination[2],
              Destination[3], Destination[4], Destination[5],
              Channel, DwellTimeMs, BodyLength, PacketId, status);
    if (BodyLength >= 2) {
        TraceDiag("action TX id %u: category %u action %u\n",
            PacketId, Body[0], Body[1]);
    }

    ExFreePoolWithTag(params, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetOperationMode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UINT32 WdiMode,
                                    _In_ UINT32 PreviousWdiMode)
{
    UINT32 role = 0;
    UINT32 infra;
    UINT32 ap;
    NTSTATUS status;

    if (WdiMode & AP6256_WDI_OPMODE_STA)        role |= AP6256_ROLE_STA;
    if (WdiMode & AP6256_WDI_OPMODE_P2P_DEVICE) role |= AP6256_ROLE_P2P_DEVICE;
    if (WdiMode & AP6256_WDI_OPMODE_P2P_CLIENT) role |= AP6256_ROLE_P2P_CLIENT;
    if (WdiMode & AP6256_WDI_OPMODE_P2P_GO)     role |= AP6256_ROLE_P2P_GO;

    TraceInfo(TRACE_NETADAPTER,
              "operation mode: WDI 0x%02X -> role 0x%02X (was WDI 0x%02X)\n",
              WdiMode, role, PreviousWdiMode);

    if (role == 0) return STATUS_INVALID_PARAMETER;

    if ((role & (AP6256_ROLE_P2P_GO | AP6256_ROLE_P2P_DEVICE)) != 0) {
        TraceWarn(TRACE_NETADAPTER,
                  "operation mode 0x%02X needs the P2P group-owner or device "
                  "role, which this driver does not program\n", WdiMode);
        return STATUS_NOT_SUPPORTED;
    }

    infra = 1;
    ap = 0;
    status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_INFRA, &infra, sizeof(infra));
    if (!NT_SUCCESS(status)) return status;
    return Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_AP, &ap, sizeof(ap));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetDefaultKeyId(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ ULONG KeyId)
{
    return Ap6256WifiSetDefaultKeyIdIf(Ctx, 0, KeyId);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetDefaultKeyIdIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _In_ ULONG KeyId)
{
    NTSTATUS status;
    UINT32 isPrimary = KeyId;
    AP6256_BCDC_QUERY_RESULT result = {0};

    if (Ap6256HostCipherPacketActive(Ctx, IfIndex)) return Ap6256HostCipherSetDefault(Ctx, IfIndex, KeyId);
    if (KeyId >= 4) return STATUS_INVALID_PARAMETER;
    if (Ap6256FipsActive(Ctx, IfIndex)) {
        AP6256_FIPS_SESSION session;
        return Ap6256FipsSnapshot(Ctx, IfIndex, &session) ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
    }
    status = Ap6256BcdcSetDcmdIf(Ctx, IfIndex, BRCMF_C_SET_KEY_PRIMARY,
                               &KeyId, sizeof(KeyId));
    if (NT_SUCCESS(status)) {

        NTSTATUS queryStatus = Ap6256BcdcQueryDcmdResultIf(
            Ctx, IfIndex, BRCMF_C_GET_KEY_PRIMARY,
            &isPrimary, sizeof(isPrimary), &result);
        if (NT_SUCCESS(queryStatus) && result.FirmwareReply &&
            !result.FirmwareError && result.PayloadLength >= sizeof(isPrimary)) {
            if (isPrimary != 1) {
                TraceWarn(TRACE_NETADAPTER,
                          "primary key %u not confirmed on if %u (predicate %u)\n",
                          KeyId, IfIndex, isPrimary);
            }
        } else {

            TraceDiag("primary key %u readback unavailable on if %u: 0x%08X, %u byte(s)\n",
                      KeyId, IfIndex, queryStatus, result.PayloadLength);
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetBssid(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_writes_(6) PUCHAR Bssid)
{
    return Ap6256WifiGetBssidIf(Ctx, 0, Bssid);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetBssidIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
                             _Out_writes_(6) PUCHAR Bssid)
{
    UCHAR buf[6] = { 0 };
    NTSTATUS status = Ap6256BcdcQueryDcmdIf(Ctx, IfIndex, BRCMF_C_GET_BSSID, buf, sizeof(buf));
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(Bssid, buf, 6);
    }
    return status;
}

#define AP6256_BSS_INFO_MAX     AP6256_BCDC_TX_MAXLEN

#define AP6256_ASSOC_INFO_MAX    2048
#define AP6256_ASSOC_IE_MAX      AP6256_ASSOC_INFO_MAX

#define AP6256_ASSOC_INFO_LEN             28
#define AP6256_ASSOC_INFO_REQ_FIXED_OFF   12
#define AP6256_ASSOC_INFO_RESP_FIXED_OFF  22
#define AP6256_ASSOC_INFO_FLAGS_OFF        8
#define AP6256_ASSOC_INFO_FLAG_REASSOC     1u

#define AP6256_ASSOC_REQ_FIXED_LEN 4
#define AP6256_REASSOC_REQ_FIXED_LEN 10
#define AP6256_ASSOC_RSP_FIXED_LEN 6

typedef struct _AP6256_ASSOC_ELEMENTS {
    ULONG   MaxLegacyHalfMbps;
    ULONG   HtMcsMax;
    UINT16  VhtRxMcsMap;
    BOOLEAN HtCap, HtOp, VhtCap, VhtOp, Wmm, Rsn, ExtCap;
} AP6256_ASSOC_ELEMENTS, *PAP6256_ASSOC_ELEMENTS;

static VOID Ap6256NoteAssocElement(_Inout_ PAP6256_ASSOC_ELEMENTS Found,
                                   _In_ UCHAR Id,
                                   _In_reads_bytes_(Len) const UCHAR* Body,
                                   _In_ UCHAR Len)
{
    ULONG index;

    switch (Id) {
    case 1:
    case 50:
        for (index = 0; index < Len; index++) {
            ULONG r = Body[index] & 0x7Fu;
            if (r > Found->MaxLegacyHalfMbps) Found->MaxLegacyHalfMbps = r;
        }
        break;
    case 45:
        Found->HtCap = TRUE;
        if (Len >= 19) {
            for (index = 0; index < 32; index++) {
                if ((Body[3 + index / 8] & (1u << (index % 8))) != 0) {
                    Found->HtMcsMax = index;
                }
            }
        }
        break;
    case 61:  Found->HtOp = TRUE; break;
    case 191:
        Found->VhtCap = TRUE;
        if (Len >= 6) {
            Found->VhtRxMcsMap = (UINT16)(Body[4] | ((UINT16)Body[5] << 8));
        }
        break;
    case 192: Found->VhtOp = TRUE; break;
    case 48:  Found->Rsn = TRUE; break;
    case 127: Found->ExtCap = TRUE; break;
    case 221:
        if (Len >= 4 && Body[0] == 0x00 && Body[1] == 0x50 &&
            Body[2] == 0xF2 && Body[3] == 0x02) {
            Found->Wmm = TRUE;
        }
        break;
    default:
        break;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256TraceAssocElements(_In_ PCSTR Label,
                                     _In_reads_bytes_(Length) const UCHAR* Ies,
                                     _In_ ULONG Length)
{
    AP6256_ASSOC_ELEMENTS found;
    const UCHAR* cursor = Ies;
    ULONG remaining = Length;
    CHAR ids[160];
    size_t idsUsed = 0;

    RtlZeroMemory(&found, sizeof(found));
    found.VhtRxMcsMap = 0xFFFF;
    ids[0] = '\0';

    while (remaining >= 2u) {
        UCHAR id = cursor[0];
        UCHAR len = cursor[1];

        if ((ULONG)len > remaining - 2u) break;
        Ap6256NoteAssocElement(&found, id, cursor + 2, len);

        if (idsUsed < sizeof(ids) - 8) {
            (VOID)RtlStringCbPrintfA(ids + idsUsed, sizeof(ids) - idsUsed,
                                     "%s%u", idsUsed != 0 ? "," : "", (ULONG)id);
            (VOID)RtlStringCbLengthA(ids, sizeof(ids), &idsUsed);
        }
        cursor += 2u + len;
        remaining -= 2u + len;
    }

    TraceDiag("%s: legacy up to %u Mbps; HT cap %s (mcs 0-%u) HT op %s; "
              "VHT cap %s (rx mcs map 0x%04X) VHT op %s; WMM %s; RSN %s; "
              "ext cap %s; element ids %s\n",
              Label, found.MaxLegacyHalfMbps / 2u,
              found.HtCap ? "yes" : "NO", found.HtMcsMax,
              found.HtOp ? "yes" : "no",
              found.VhtCap ? "yes" : "NO", (ULONG)found.VhtRxMcsMap,
              found.VhtOp ? "yes" : "no",
              found.Wmm ? "yes" : "NO", found.Rsn ? "yes" : "no",
              found.ExtCap ? "yes" : "no", ids);
    return found.Wmm;
}

static VOID Ap6256PutLe16(_Out_writes_bytes_(2) PUCHAR Out, _In_ UINT16 Value)
{
    Out[0] = (UCHAR)(Value & 0xFF);
    Out[1] = (UCHAR)(Value >> 8);
}

static UINT16 Ap6256GetLe16(_In_reads_bytes_(2) const UCHAR* In)
{
    return (UINT16)(In[0] | ((UINT16)In[1] << 8));
}

static UINT32 Ap6256GetLe32(_In_reads_bytes_(4) const UCHAR* In)
{
    return (UINT32)In[0] | ((UINT32)In[1] << 8) |
           ((UINT32)In[2] << 16) | ((UINT32)In[3] << 24);
}

typedef struct _AP6256_RSN_MFP {
    UINT16 Capabilities;
    UINT32 GroupManagementCipher;
} AP6256_RSN_MFP;

#define AP6256_RSN_MFPR 0x0040u
#define AP6256_RSN_MFPC 0x0080u
#define AP6256_RSN_BIP_CMAC_128 0x06ac0f00u

static BOOLEAN Ap6256WifiReadRsnMfp(_In_reads_bytes_(Length) const UCHAR* Ies,
                                  _In_ ULONG Length,
                                  _Out_ AP6256_RSN_MFP* Mfp)
{
    const UCHAR* rsn = NULL;
    ULONG left = 0, count, i;

    RtlZeroMemory(Mfp, sizeof(*Mfp));
    Mfp->GroupManagementCipher = AP6256_RSN_BIP_CMAC_128;
    if (Ies == NULL) return FALSE;
    while (Length >= 2) {
        ULONG size = (ULONG)Ies[1] + 2;
        if (size > Length) return FALSE;
        if (Ies[0] == 48) {
            if (rsn != NULL) return FALSE;
            rsn = Ies + 2;
            left = size - 2;
        }
        Ies += size;
        Length -= size;
    }
    if (Length != 0 || rsn == NULL || left < 2 || Ap6256GetLe16(rsn) != 1) return FALSE;
    rsn += 2; left -= 2;
    if (left == 0) return TRUE;
    if (left < 4) return FALSE;
    rsn += 4; left -= 4;
    for (i = 0; i < 2; ++i) {
        if (left == 0) return TRUE;
        if (left < 2) return FALSE;
        count = Ap6256GetLe16(rsn);
        rsn += 2; left -= 2;
        if (count == 0 || count > left / 4) return FALSE;
        rsn += count * 4; left -= count * 4;
    }
    if (left == 0) return TRUE;
    if (left < 2) return FALSE;
    Mfp->Capabilities = Ap6256GetLe16(rsn);
    rsn += 2; left -= 2;
    if ((Mfp->Capabilities & (AP6256_RSN_MFPR | AP6256_RSN_MFPC)) ==
        AP6256_RSN_MFPR) return FALSE;
    if (left == 0) return TRUE;
    if (left < 2) return FALSE;
    count = Ap6256GetLe16(rsn);
    rsn += 2; left -= 2;
    if (count > left / 16) return FALSE;
    rsn += count * 16; left -= count * 16;
    if (left == 0) return TRUE;
    if (left < 4) return FALSE;
    Mfp->GroupManagementCipher = Ap6256GetLe32(rsn);
    return TRUE;
}

_Use_decl_annotations_
BOOLEAN Ap6256WifiIesPmfCapable(const UCHAR* Ies, ULONG Length)
{
    AP6256_RSN_MFP mfp;
    return Ap6256WifiReadRsnMfp(Ies, Length, &mfp) &&
           (mfp.Capabilities & AP6256_RSN_MFPC) != 0;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiAssocPmf(const AP6256_ASSOC_FRAMES* Frames,
                          const UCHAR* Bssid, BOOLEAN* Enabled)
{
    AP6256_RSN_MFP station, ap;
    ULONG requestFixed = Frames->ReAssociation ? AP6256_REASSOC_REQ_FIXED_LEN :
                                               AP6256_ASSOC_REQ_FIXED_LEN;
    *Enabled = FALSE;
    if (Frames->AssocRequest == NULL || Frames->AssocRequestLength < requestFixed ||
        Frames->Beacon == NULL || Frames->BeaconLength < AP6256_BEACON_FIXED_LEN ||
        !RtlEqualMemory(Frames->BeaconBssid, Bssid, 6) ||
        !Ap6256WifiReadRsnMfp(Frames->AssocRequest + requestFixed,
                             Frames->AssocRequestLength - requestFixed, &station) ||
        !Ap6256WifiReadRsnMfp(Frames->Beacon + AP6256_BEACON_FIXED_LEN,
                             Frames->BeaconLength - AP6256_BEACON_FIXED_LEN, &ap)) {
        return STATUS_DEVICE_DATA_ERROR;
    }

    if (((station.Capabilities & AP6256_RSN_MFPR) &&
         !(ap.Capabilities & AP6256_RSN_MFPC)) ||
        ((ap.Capabilities & AP6256_RSN_MFPR) &&
         !(station.Capabilities & AP6256_RSN_MFPC))) {
        return STATUS_DEVICE_DATA_ERROR;
    }
    if ((station.Capabilities & ap.Capabilities & AP6256_RSN_MFPC) != 0) {

        if (station.GroupManagementCipher != AP6256_RSN_BIP_CMAC_128 ||
            ap.GroupManagementCipher != AP6256_RSN_BIP_CMAC_128) {
            return STATUS_NOT_SUPPORTED;
        }
        *Enabled = TRUE;
    }
    TraceDiag("association PMF: request RSN caps 0x%04X, AP 0x%04X -> %s\n",
              (ULONG)station.Capabilities, (ULONG)ap.Capabilities,
              *Enabled ? "BIP-CMAC-128" : "none");
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
_Success_(return >= 0)
static NTSTATUS Ap6256WifiQueryBssInfo(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
    _Out_writes_bytes_(BufferSize) PUCHAR Buffer,
    _In_ ULONG BufferSize,
    _Outptr_result_nullonfailure_ BRCMF_BSS_INFO** Info)
{
    BRCMF_BSS_INFO* info;
    NTSTATUS status;

    *Info = NULL;
    if (BufferSize <= sizeof(UINT32) + sizeof(BRCMF_BSS_INFO)) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    *(UINT32*)Buffer = BufferSize;
    status = Ap6256BcdcQueryDcmdIf(Ctx, IfIndex, BRCMF_C_GET_BSS_INFO, Buffer, BufferSize);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    info = (BRCMF_BSS_INFO*)(Buffer + sizeof(UINT32));
    if (info->Length < sizeof(BRCMF_BSS_INFO) ||
        info->Length > BufferSize - sizeof(UINT32) ||
        (info->IeLength != 0 &&
         (info->IeOffset < sizeof(BRCMF_BSS_INFO) ||
          info->IeOffset > info->Length ||
          info->IeLength > info->Length - info->IeOffset))) {
        TraceDiag("BSS query if %u rejected: version %u length %u IE offset %u bytes %u capacity %u\n",
                  IfIndex, info->Version, info->Length, (ULONG)info->IeOffset,
                  info->IeLength, BufferSize - (ULONG)sizeof(UINT32));
        return STATUS_DEVICE_DATA_ERROR;
    }

    *Info = info;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiGetApPeerInfo(PAP6256_DEVICE_CONTEXT Ctx,
    const UCHAR* Address, AP6256_AP_PEER_INFO* Info)
{
    UCHAR sta[512] = {0};
    PUCHAR buffer;
    BRCMF_BSS_INFO* bss;
    UINT16 version, length, aid;
    UINT32 flags, listenMs;
    ULONGLONG interval;
    NTSTATUS status;
    RtlZeroMemory(Info, sizeof(*Info));
    RtlCopyMemory(sta, Address, 6);
    status = Ap6256BcdcGetIovarIf(Ctx, Ctx->Go.IfIndex, "sta_info", sta, sizeof(sta));
    if (!NT_SUCCESS(status)) {
        TraceDiag("hotspot: sta_info if %u failed 0x%08X\n", Ctx->Go.IfIndex, status);
        return status;
    }
    RtlCopyMemory(&version, sta, 2);
    RtlCopyMemory(&length, sta + 2, 2);
    RtlCopyMemory(&flags, sta + 8, 4);
    RtlCopyMemory(&aid, sta + 152, 2);
    aid &= 0x3fff;
    TraceDiag("hotspot: sta_info if %u version %u length %u flags 0x%X AID %u\n",
        Ctx->Go.IfIndex, (ULONG)version, (ULONG)length, flags, (ULONG)aid);
    if (version < 4 || length < 154 || length > sizeof(sta) ||
        (flags & 0x10u) == 0 || !RtlEqualMemory(sta + 16, Address, 6) ||
        aid == 0 || aid > 2007) {
        TraceDiag("hotspot: sta_info identity/layout rejected (MAC match %u)\n",
            (ULONG)RtlEqualMemory(sta + 16, Address, 6));
        return STATUS_DEVICE_DATA_ERROR;
    }
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_BSS_INFO_MAX, AP6256_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;
    status = Ap6256WifiQueryBssInfo(Ctx, Ctx->Go.IfIndex, buffer, AP6256_BSS_INFO_MAX, &bss);
    if (NT_SUCCESS(status)) {
        if (bss->Version != 109 || !RtlEqualMemory(bss->Bssid, Ctx->Go.Address, 6) ||
            bss->SsidLen == 0 || bss->SsidLen > sizeof(Info->Ssid) ||
            bss->Rateset.Count == 0 || bss->Rateset.Count > sizeof(Info->Rates) ||
            bss->BeaconPeriod == 0 || bss->IeLength > sizeof(Info->Beacon)) {
            TraceDiag("hotspot: AP BSS metadata rejected: version %u MAC match %u SSID %u rates %u beacon %u IE bytes %u\n",
                bss->Version, (ULONG)RtlEqualMemory(bss->Bssid, Ctx->Go.Address, 6),
                (ULONG)bss->SsidLen, bss->Rateset.Count, (ULONG)bss->BeaconPeriod, bss->IeLength);
            status = STATUS_DEVICE_DATA_ERROR;
        } else {
            RtlCopyMemory(&Info->Capability, sta + 4, 2);
            RtlCopyMemory(&listenMs, sta + 48, 4);

            interval = ((ULONGLONG)listenMs * 1000 + (ULONG)bss->BeaconPeriod * 1024 - 1) /
                ((ULONG)bss->BeaconPeriod * 1024);
            Info->ListenInterval = (UINT16)min(max(interval, 1), 65535);
            Info->Aid = aid;
            Info->ApCapability = bss->Capability;
            Info->BeaconPeriod = bss->BeaconPeriod;
            Info->SsidLength = bss->SsidLen;
            RtlCopyMemory(Info->Ssid, bss->Ssid, Info->SsidLength);
            Info->RateCount = bss->Rateset.Count;
            RtlCopyMemory(Info->Rates, bss->Rateset.Rates, Info->RateCount);
            Info->BeaconLength = bss->IeLength;
            if (Info->BeaconLength) RtlCopyMemory(Info->Beacon,
                (PUCHAR)bss + bss->IeOffset, Info->BeaconLength);
        }
    }
    ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiGetApWmmEnabled(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN* Enabled)
{
    UINT32 wme = 0, disabled = 0;
    NTSTATUS status;
    *Enabled = FALSE;
    status = Ap6256BcdcGetIovar(Ctx, "wme", &wme, sizeof(wme));
    if (NT_SUCCESS(status))
        status = Ap6256BcdcGetIovarIf(Ctx, Ctx->Go.IfIndex,
            "wme_bss_disable", &disabled, sizeof(disabled));
    if (NT_SUCCESS(status)) *Enabled = (BOOLEAN)((wme & 0xffu) != 0 && disabled == 0);
    TraceDiag("hotspot: GO WMM if %u wme %u disabled %u -> 0x%08X\n",
        Ctx->Go.IfIndex, wme, disabled, status);
    return status;
}

static UINT16 Ap6256WifiBssControlChannel(_In_ const BRCMF_BSS_INFO* Info)
{
    return (Info->ControlChannel != 0) ? (UINT16)Info->ControlChannel
                                       : (UINT16)(Info->Chanspec & 0x00FF);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiTraceApBss(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex)
{
    PUCHAR buffer;
    BRCMF_BSS_INFO* info;
    NTSTATUS status;
    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_BSS_INFO_MAX, AP6256_POOL_TAG);
    if (buffer == NULL) return;
    status = Ap6256WifiQueryBssInfo(Ctx, IfIndex, buffer, AP6256_BSS_INFO_MAX, &info);
    if (NT_SUCCESS(status)) {
        TraceVerbose(TRACE_DRIVER, "hotspot: cached BSS if %u BSSID %02X:%02X:%02X:%02X:%02X:%02X base capability 0x%04X base privacy %u SSID bytes %u; transmitted capability is finalized separately\n",
                  IfIndex, info->Bssid[0], info->Bssid[1], info->Bssid[2],
                  info->Bssid[3], info->Bssid[4], info->Bssid[5],
                  (ULONG)info->Capability, (ULONG)((info->Capability & 0x10u) != 0),
                  (ULONG)info->SsidLen);
        TraceDiag("hotspot: BSS bandwidth readback if %u chanspec 0x%04X primary %u HT %u\n",
            IfIndex, (ULONG)info->Chanspec, (ULONG)info->ControlChannel, (ULONG)info->NCap);
    } else TraceDiag("hotspot: BSS readback if %u unavailable 0x%08X\n", IfIndex, status);
    ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiFreeAssocFrames(_Inout_ PAP6256_ASSOC_FRAMES Frames)
{
    if (Frames->Beacon != NULL) {
        ExFreePoolWithTag(Frames->Beacon, AP6256_POOL_TAG);
    }
    if (Frames->AssocRequest != NULL) {
        ExFreePoolWithTag(Frames->AssocRequest, AP6256_POOL_TAG);
    }
    if (Frames->AssocResponse != NULL) {
        ExFreePoolWithTag(Frames->AssocResponse, AP6256_POOL_TAG);
    }
    RtlZeroMemory(Frames, sizeof(*Frames));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiGetAssocFrames(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PAP6256_ASSOC_FRAMES Frames)
{
    Ap6256WifiGetAssocFramesIf(Ctx, 0, Frames);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiGetAssocFramesIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
                              _Out_ PAP6256_ASSOC_FRAMES Frames)
{
    struct { UINT32 ReqLength; UINT32 RespLength; } lengths;
    UCHAR assocInfo[AP6256_ASSOC_INFO_LEN];
    ULONG reqFixed = AP6256_ASSOC_REQ_FIXED_LEN;
    PUCHAR bssBuffer = NULL;
    BRCMF_BSS_INFO* info;
    UINT16 capability = 0;
    UINT16 beaconPeriod = 100;
    UINT16 reqCapability = 0;
    UINT16 reqListen = 0;
    UINT16 respCapability = 0;
    UINT16 respStatus = 0xFFFF;
    UINT16 respAid = 0;
    BOOLEAN fixedFieldsValid = FALSE;
    NTSTATUS status;

    RtlZeroMemory(Frames, sizeof(*Frames));
    RtlZeroMemory(&lengths, sizeof(lengths));

    bssBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                        AP6256_BSS_INFO_MAX, AP6256_POOL_TAG);
    if (bssBuffer != NULL) {
        status = Ap6256WifiQueryBssInfo(Ctx, IfIndex, bssBuffer, AP6256_BSS_INFO_MAX,
                                        &info);
        if (NT_SUCCESS(status)) {
            ULONG total = AP6256_BEACON_FIXED_LEN + info->IeLength;

            capability = info->Capability;
            beaconPeriod = info->BeaconPeriod;
            Frames->Beacon = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
                                                     AP6256_POOL_TAG);
            if (Frames->Beacon != NULL) {

                Ap6256PutLe16(Frames->Beacon + 8, beaconPeriod);
                Ap6256PutLe16(Frames->Beacon + 10, capability);
                RtlCopyMemory(Frames->Beacon + AP6256_BEACON_FIXED_LEN,
                              (PUCHAR)info + info->IeOffset, info->IeLength);
                Frames->BeaconLength = total;
                RtlCopyMemory(Frames->BeaconBssid, info->Bssid, 6);
            }
        } else {
            TraceWarn(TRACE_NETADAPTER,
                      "bss info for the joined BSS unavailable (0x%08X)\n",
                      status);
        }
        ExFreePoolWithTag(bssBuffer, AP6256_POOL_TAG);
    }

    RtlZeroMemory(assocInfo, sizeof(assocInfo));
    status = Ap6256BcdcGetIovarIf(Ctx, IfIndex, "assoc_info", assocInfo,
                                sizeof(assocInfo));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "assoc_info unavailable (0x%08X)\n",
                  status);
        return;
    }

    RtlCopyMemory(&lengths, assocInfo, sizeof(lengths));
    if ((Ap6256GetLe32(assocInfo + AP6256_ASSOC_INFO_FLAGS_OFF) &
         AP6256_ASSOC_INFO_FLAG_REASSOC) != 0) {
        reqFixed = AP6256_REASSOC_REQ_FIXED_LEN;
    }

    reqCapability = Ap6256GetLe16(assocInfo + AP6256_ASSOC_INFO_REQ_FIXED_OFF);
    reqListen = Ap6256GetLe16(assocInfo + AP6256_ASSOC_INFO_REQ_FIXED_OFF + 2);
    respCapability = Ap6256GetLe16(assocInfo + AP6256_ASSOC_INFO_RESP_FIXED_OFF);
    respStatus = Ap6256GetLe16(assocInfo + AP6256_ASSOC_INFO_RESP_FIXED_OFF + 2);
    respAid = Ap6256GetLe16(assocInfo + AP6256_ASSOC_INFO_RESP_FIXED_OFF + 4);

    fixedFieldsValid = (BOOLEAN)(
        respStatus == 0 &&
        (respAid & 0x3FFF) != 0 && (respAid & 0x3FFF) <= 2007 &&
        reqListen != 0 && reqListen <= 1000 &&
        reqCapability != 0 && reqCapability != 0xFFFF &&
        respCapability != 0 && respCapability != 0xFFFF);

    Frames->ReAssociation =
        (BOOLEAN)(reqFixed == AP6256_REASSOC_REQ_FIXED_LEN);
    Frames->PeerStatusValid = fixedFieldsValid || (respStatus > 0 && respStatus < 127 &&
        respAid == 0 && reqListen != 0 && reqListen <= 1000 &&
        reqCapability != 0 && reqCapability != 0xffff &&
        respCapability != 0 && respCapability != 0xffff &&
        lengths.ReqLength >= reqFixed && lengths.ReqLength <= AP6256_ASSOC_IE_MAX &&
        lengths.RespLength >= AP6256_ASSOC_RSP_FIXED_LEN && lengths.RespLength <= AP6256_ASSOC_IE_MAX);
    Frames->PeerStatusCode = Frames->PeerStatusValid ? respStatus : (UINT16)0;

    TraceDiag("assoc_info: req %u resp %u bytes (%s, %u fixed); request cap "
              "0x%04X listen %u; response cap 0x%04X status %u aid %u -> fixed "
              "fields %s\n",
              lengths.ReqLength, lengths.RespLength,
              reqFixed == AP6256_REASSOC_REQ_FIXED_LEN ? "reassoc" : "assoc",
              reqFixed, reqCapability, reqListen, respCapability, respStatus,
              respAid, fixedFieldsValid ? "used" : "IGNORED (implausible)");

    if (lengths.ReqLength > reqFixed &&
        lengths.ReqLength <= AP6256_ASSOC_IE_MAX) {
        ULONG ieLength = lengths.ReqLength - reqFixed;

        Frames->AssocRequest = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, lengths.ReqLength, AP6256_POOL_TAG);
        if (Frames->AssocRequest != NULL) {

            if (fixedFieldsValid) {
                RtlCopyMemory(Frames->AssocRequest,
                              assocInfo + AP6256_ASSOC_INFO_REQ_FIXED_OFF,
                              reqFixed);
            } else {
                RtlZeroMemory(Frames->AssocRequest, reqFixed);
                Ap6256PutLe16(Frames->AssocRequest, capability);
                Ap6256PutLe16(Frames->AssocRequest + 2, 10);
            }
            status = Ap6256BcdcGetIovarIf(Ctx, IfIndex, "assoc_req_ies",
                                        Frames->AssocRequest + reqFixed,
                                        ieLength);
            if (NT_SUCCESS(status)) {
                Frames->AssocRequestLength = lengths.ReqLength;
            } else {
                ExFreePoolWithTag(Frames->AssocRequest, AP6256_POOL_TAG);
                Frames->AssocRequest = NULL;
            }
        }
    }

    if (lengths.RespLength >= AP6256_ASSOC_RSP_FIXED_LEN &&
        lengths.RespLength <= AP6256_ASSOC_IE_MAX) {
        ULONG ieLength = lengths.RespLength - AP6256_ASSOC_RSP_FIXED_LEN;

        Frames->AssocResponse = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, lengths.RespLength, AP6256_POOL_TAG);
        if (Frames->AssocResponse != NULL) {
            if (Frames->PeerStatusValid) {
                RtlCopyMemory(Frames->AssocResponse,
                              assocInfo + AP6256_ASSOC_INFO_RESP_FIXED_OFF,
                              AP6256_ASSOC_RSP_FIXED_LEN);
            } else {
                Ap6256PutLe16(Frames->AssocResponse, capability);
                Ap6256PutLe16(Frames->AssocResponse + 2, 0);
                Ap6256PutLe16(Frames->AssocResponse + 4, 1);
            }
            status = STATUS_SUCCESS;
            if (ieLength != 0) {
                status = Ap6256BcdcGetIovarIf(
                    Ctx, IfIndex, "assoc_resp_ies",
                    Frames->AssocResponse + AP6256_ASSOC_RSP_FIXED_LEN,
                    ieLength);
            }
            if (NT_SUCCESS(status)) {
                Frames->AssocResponseLength = lengths.RespLength;
            } else {
                ExFreePoolWithTag(Frames->AssocResponse, AP6256_POOL_TAG);
                Frames->AssocResponse = NULL;
            }
        }
    }

    TraceDiag("association frames: beacon %u, request %u (%u IE bytes), "
              "response %u (%u IE bytes)\n",
              Frames->BeaconLength, Frames->AssocRequestLength,
              lengths.ReqLength, Frames->AssocResponseLength,
              lengths.RespLength);

    if (Frames->AssocRequest != NULL && Frames->AssocRequestLength > reqFixed) {
        (VOID)Ap6256TraceAssocElements("assoc request",
                                       Frames->AssocRequest + reqFixed,
                                       Frames->AssocRequestLength - reqFixed);
    }
    if (Frames->AssocResponse != NULL &&
        Frames->AssocResponseLength > AP6256_ASSOC_RSP_FIXED_LEN) {

        Frames->WmmNegotiated = Ap6256TraceAssocElements(
            "assoc response", Frames->AssocResponse + AP6256_ASSOC_RSP_FIXED_LEN,
            Frames->AssocResponseLength - AP6256_ASSOC_RSP_FIXED_LEN);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChanspec(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                               _Out_ PUINT32 Chanspec)
{
    UINT32 value = 0;
    NTSTATUS status = Ap6256BcdcGetIovar(Ctx, "chanspec", &value,
                                         sizeof(value));

    *Chanspec = NT_SUCCESS(status) ? value : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChannel(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PUINT32 Channel)
{
    return Ap6256WifiGetChannelIf(Ctx, 0, Channel);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetChannelIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex, _Out_ PUINT32 Channel)
{
    BRCMF_CHANNEL_INFO channelInfo = { 0 };
    BRCMF_BSS_INFO* info = NULL;
    PUCHAR buffer;
    NTSTATUS status;

    *Channel = 0;

    buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_BSS_INFO_MAX,
                                     AP6256_POOL_TAG);
    if (buffer != NULL) {
        status = Ap6256WifiQueryBssInfo(Ctx, IfIndex, buffer, AP6256_BSS_INFO_MAX, &info);
        if (NT_SUCCESS(status)) {
            UINT16 control = Ap6256WifiBssControlChannel(info);
            UINT16 centre = (UINT16)(info->Chanspec & 0x00FF);

            if (control != 0) {
                *Channel = control;
                if (control != centre) {
                    TraceVerbose(TRACE_NETADAPTER,
                                 "channel: control %u (chanspec 0x%04X centre "
                                 "%u)\n", control, info->Chanspec, centre);
                }
            }
        }
        ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
    }
    if (*Channel != 0) {
        return STATUS_SUCCESS;
    }

    status = Ap6256BcdcQueryDcmdIf(Ctx, IfIndex, BRCMF_C_GET_CHANNEL,
                                 &channelInfo, sizeof(channelInfo));
    if (NT_SUCCESS(status)) {
        *Channel = channelInfo.HardwareChannel;
        TraceVerbose(TRACE_NETADAPTER,
                     "channel: no BSS record, using hardware channel %u\n",
                     *Channel);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetBssWmm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ BOOLEAN Enabled)
{
    UINT32 value = 0;
    NTSTATUS status = Ap6256BcdcGetIovar(Ctx, "wme_bss_disable", &value,
                                         sizeof(value));

    if (!NT_SUCCESS(status)) return status;

    value = Enabled ? 0u : 1u;
    return Ap6256BcdcSetIovar(Ctx, "wme_bss_disable", &value, sizeof(value));
}

#pragma pack(push, 1)

typedef struct _BRCMF_PFN_NET {
    WLC_SSID Ssid;
    INT32  Flags;
    INT32  Infra;
    INT32  Auth;
    UINT32 WpaAuth;
    UINT32 Wsec;
} BRCMF_PFN_NET;

typedef struct _BRCMF_PFN_PARAM {
    UINT32 Version;
    UINT32 ScanFrequency;
    UINT32 LostNetworkTimeout;
    UINT16 Flags;
    UINT16 RssiMargin;
    UCHAR  BestN;
    UCHAR  MScan;
    UCHAR  Repeat;
    UCHAR  Exp;
    UINT32 SlowFrequency;
} BRCMF_PFN_PARAM;

typedef struct _BRCMF_PFN_INITIAL_DELAY {
    UINT32 Magic;
    UINT32 Version;
    UINT32 DelaySeconds;
    UINT32 Reserved[3];
} BRCMF_PFN_INITIAL_DELAY;

typedef struct _BRCMF_CHANNEL_LIST {
    UINT32 Count;
    UINT32 Channels[64];
} BRCMF_CHANNEL_LIST;

#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_PFN_NET) == 56);
C_ASSERT(sizeof(BRCMF_PFN_PARAM) == 24);
C_ASSERT(sizeof(BRCMF_PFN_INITIAL_DELAY) == 24);
C_ASSERT(sizeof(BRCMF_CHANNEL_LIST) == 260);

#define BRCMF_PFN_VERSION            2u

#define BRCMF_PFN_FLAG_IMMEDIATE     0x0008u
#define BRCMF_PFN_FLAG_ALWAYS_0100   0x0100u
#define BRCMF_PFN_FLAG_ALWAYS_0200   0x0200u
#define BRCMF_PFN_FLAG_ALWAYS_0400   0x0400u

typedef struct _AP6256_NLO_SECURITY {
    UINT32 AuthAlgorithm;
    UINT32 CipherAlgorithm;
    UINT32 WpaAuth;
    UINT32 Wsec;
} AP6256_NLO_SECURITY;

static const AP6256_NLO_SECURITY Ap6256NloSecurity[] = {
    { 1, 0x000,   0,    0 },
    { 1, 0x101,   0,    1 },
    { 2, 0x000,   0,    0 },
    { 2, 0x101,   0,    1 },
    { 6, 0x002,  64,    2 },
    { 7, 0x002, 128,    2 },
    { 6, 0x004,  64,    4 },
    { 7, 0x004, 128,    4 },
    { 3, 0x002,   2,    2 },
    { 4, 0x002,   4,    2 },
    { 3, 0x004,   2,    4 },
    { 4, 0x004,   4,    4 }
};

_IRQL_requires_max_(PASSIVE_LEVEL)
static const AP6256_NLO_SECURITY* Ap6256WifiNloSecurityFor(
    _In_ UINT32 AuthAlgorithm, _In_ UINT32 CipherAlgorithm)
{
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(Ap6256NloSecurity); i++) {
        if (Ap6256NloSecurity[i].AuthAlgorithm == AuthAlgorithm &&
            Ap6256NloSecurity[i].CipherAlgorithm == CipherAlgorithm) {
            return &Ap6256NloSecurity[i];
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256WifiNloSecuritySupported(_In_ UINT32 AuthAlgorithm,
                                       _In_ UINT32 CipherAlgorithm)
{
    return (BOOLEAN)(Ap6256WifiNloSecurityFor(AuthAlgorithm,
                                              CipherAlgorithm) != NULL);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiChannelIsValid(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UINT32 Channel,
                                  _Out_ PBOOLEAN Valid)
{
    BRCMF_CHANNEL_LIST* list;
    NTSTATUS status;
    ULONG i;

    *Valid = TRUE;

    list = (BRCMF_CHANNEL_LIST*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                sizeof(*list),
                                                AP6256_POOL_TAG);
    if (list == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    list->Count = RTL_NUMBER_OF(list->Channels);
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_VALID_CHANNELS, list,
                                 sizeof(*list));
    if (NT_SUCCESS(status)) {
        ULONG count = min(list->Count, RTL_NUMBER_OF(list->Channels));

        *Valid = FALSE;
        for (i = 0; i < count; i++) {
            if (list->Channels[i] == Channel) {
                *Valid = TRUE;
                break;
            }
        }
    }

    ExFreePoolWithTag(list, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiClearNetworkListOffloadLocked(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 off = 0;
    NTSTATUS status;

    Ap6256PnoResultsReset(Ctx);
    status = Ap6256BcdcSetIovar(Ctx, "pfn", &off, sizeof(off));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovar(Ctx, "pfnclear", NULL, 0);
    TraceInfo(TRACE_NETADAPTER, "network list offload cleared\n");
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiClearNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Ctx->PnoLock);
    status = Ap6256WifiClearNetworkListOffloadLocked(Ctx);
    Ap6256LockRelease(&Ctx->PnoLock);
    if (!NT_SUCCESS(status)) TraceWarn(TRACE_NETADAPTER, "PNO clear failed 0x%08X\n", status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiProgramNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_NLO_PARAMS* Params, _In_opt_ const AP6256_PNO_CONFIG* Config)
{
    BRCMF_PFN_PARAM param;
    UINT32 on = 1;
    ULONG i;
    NTSTATUS status;

    if (Params->NetworkCount > AP6256_NLO_NETWORK_MAX) return STATUS_INVALID_PARAMETER;
    if (Params->WindowsRequest) {
        LONG mode = InterlockedCompareExchange(&Ctx->NloScanMode, 0, 0);
        if (mode != 0 && (UINT32)mode != AP6256_NLO_SCAN_AUTO) return STATUS_NOT_SUPPORTED;
    }
    if (Params->Enable && Params->NetworkCount != 0) {
        if (Params->ScanPeriodSeconds == 0 || Params->ScanPeriodSeconds > MAXLONG / 1000)
            return STATUS_INVALID_PARAMETER;
        if (Params->WindowsRequest && (Params->FastIterations > 100 ||
            (!Ctx->FirmwarePnoDelaySupported && Params->DelayStartSeconds != 0 &&
             Params->DelayStartSeconds != Params->ScanPeriodSeconds) ||
            Params->SlowPeriodSeconds == 0 || Params->SlowPeriodSeconds > MAXLONG / 1000))
            return STATUS_NOT_SUPPORTED;
        for (i = 0; i < Params->NetworkCount; ++i) {
            const AP6256_NLO_NETWORK* net = &Params->Networks[i];
            if (net->SsidLength == 0 || net->SsidLength > sizeof(net->Ssid) ||
                !Ap6256WifiNloSecuritySupported(net->AuthAlgorithm, net->CipherAlgorithm))
                return STATUS_INVALID_PARAMETER;
        }
    }
    if (Config != NULL) {
        if (!Params->Enable || Params->NetworkCount == 0) return STATUS_INVALID_PARAMETER;
        if (!Ctx->FirmwareEnhancedPnoSupported) return STATUS_NOT_SUPPORTED;
        if (Ctx->Go.FirmwareReady) return STATUS_DEVICE_BUSY;
        status = Ap6256PnoValidateConfig(Config);
        if (!NT_SUCCESS(status)) return status;
        if (Ap6256PnoConfigNeedsGscan(Config) && !Ctx->FirmwarePnoGscanSupported)
            return STATUS_NOT_SUPPORTED;
        if (!Ctx->FirmwarePnoExtendedEvents) {
            if ((Config->Options & AP6256_PNO_USE_SWC) != 0) return STATUS_NOT_SUPPORTED;
            for (i = 0; i < Config->Gscan.BucketCount; ++i)
                if (Config->Gscan.Buckets[i].Flags == 2) return STATUS_NOT_SUPPORTED;
        }
        status = Ap6256WifiPnoChannels(Ctx, (AP6256_PNO_CONFIG*)Config, FALSE);
        if (!NT_SUCCESS(status)) return status;
        for (i = 0; i < Config->Gscan.BucketCount; ++i)
            if (Params->ScanPeriodSeconds > (ULONG)(MAXLONG / 1000) / Config->Gscan.Buckets[i].FrequencyMultiple)
                return STATUS_INVALID_PARAMETER;
    }
    status = Ap6256WifiClearNetworkListOffloadLocked(Ctx);
    if (!NT_SUCCESS(status)) return status;

    if (!Params->Enable || Params->NetworkCount == 0) return STATUS_SUCCESS;

    for (i = 0; i < Params->NetworkCount; i++) {
        const AP6256_NLO_NETWORK* net = &Params->Networks[i];
        const AP6256_NLO_SECURITY* security =
            Ap6256WifiNloSecurityFor(net->AuthAlgorithm, net->CipherAlgorithm);
        BRCMF_PFN_NET entry;

        if (security == NULL) return STATUS_INVALID_PARAMETER;

        RtlZeroMemory(&entry, sizeof(entry));
        entry.Ssid.SsidLen = net->SsidLength;
        RtlCopyMemory(entry.Ssid.Ssid, net->Ssid,
                      min(net->SsidLength, sizeof(entry.Ssid.Ssid)));

        entry.Flags = net->DirectedProbePermitted ? (1u << 2) : 0;
        entry.Infra = 1;
        entry.Auth = (net->AuthAlgorithm == 2) ? 1 : 0;
        entry.WpaAuth = security->WpaAuth;
        entry.Wsec = security->Wsec;

        status = Ap6256BcdcSetIovar(Ctx, "pfn_add", &entry, sizeof(entry));
        if (!NT_SUCCESS(status)) {
            TraceWarn(TRACE_NETADAPTER,
                      "pfn_add %u of %u refused 0x%08X\n",
                      i + 1, Params->NetworkCount, status);
            goto rollback;
        }
    }

    RtlZeroMemory(&param, sizeof(param));
    param.Version = BRCMF_PFN_VERSION;
    param.ScanFrequency = Params->ScanPeriodSeconds;
    param.LostNetworkTimeout = Params->ScanPeriodSeconds;
    param.Flags = (UINT16)(BRCMF_PFN_FLAG_ALWAYS_0100 |
                           BRCMF_PFN_FLAG_ALWAYS_0200 |
                           BRCMF_PFN_FLAG_ALWAYS_0400 |
                           BRCMF_PFN_FLAG_IMMEDIATE);

    if (Params->WindowsRequest && Params->DelayStartSeconds != 0)
        param.Flags = (UINT16)(param.Flags & ~BRCMF_PFN_FLAG_IMMEDIATE);
    if (Params->WindowsRequest && Params->FastIterations != 0) {
        param.Flags |= 0x00c0;
        param.Repeat = (UCHAR)Params->FastIterations;
        param.SlowFrequency = Params->SlowPeriodSeconds;
    }
    if (Config != NULL && (Config->Options & AP6256_PNO_USE_BATCH) != 0) {
        param.Flags |= 0x0020;
        param.BestN = 2;
        param.MScan = 4;
    }

    status = Ap6256BcdcSetIovar(Ctx, "pfn_set", &param, sizeof(param));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "pfn_set refused 0x%08X\n", status);
        goto rollback;
    }

    if (Config != NULL) {
        status = Ap6256PnoApplyConfig(Ctx, Config);
        if (!NT_SUCCESS(status)) goto rollback;
    }
    if (Ctx->FirmwarePnoDelaySupported) {
        BRCMF_PFN_INITIAL_DELAY delay = {0};
        delay.Magic = 0x444f4e50u;
        delay.Version = 1;
        delay.DelaySeconds = Params->WindowsRequest ? Params->DelayStartSeconds : 0;
        status = Ap6256BcdcSetIovar(Ctx, "pfn_override", &delay, sizeof(delay));
        if (!NT_SUCCESS(status)) goto rollback;
    }
    Ap6256PnoResultsCommit(Ctx, Params, (BOOLEAN)(Config != NULL &&
        (Config->Options & AP6256_PNO_USE_BATCH) != 0));
    status = Ap6256BcdcSetIovar(Ctx, "pfn", &on, sizeof(on));
    if (NT_SUCCESS(status) && Config != NULL) {
        UINT32 enabled = MAXUINT32;
        status = Ap6256PnoGetEnabledLocked(Ctx, &enabled);
        if (NT_SUCCESS(status) && enabled != 1) status = STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (NT_SUCCESS(status) && Config != NULL && (Config->Options & AP6256_PNO_USE_OVERRIDE) != 0)
        status = Ap6256BcdcSetIovar(Ctx, "pfn_override", (PVOID)&Config->Override, sizeof(Config->Override));
    TraceInfo(TRACE_NETADAPTER,
              "network list offload: %u network(s), every %u s -> 0x%08X\n",
              Params->NetworkCount, Params->ScanPeriodSeconds, status);
    if (NT_SUCCESS(status)) return status;
rollback:

    {
        NTSTATUS cleanup = Ap6256WifiClearNetworkListOffloadLocked(Ctx);
        if (!NT_SUCCESS(cleanup)) TraceWarn(TRACE_NETADAPTER, "PNO rollback unverified 0x%08X\n", cleanup);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetNetworkListOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ const AP6256_NLO_PARAMS* Params)
{
    NTSTATUS status;
    Ap6256LockAcquire(&Ctx->PnoLock);
    status = Ap6256WifiProgramNetworkListOffload(Ctx, Params, NULL);
    Ap6256LockRelease(&Ctx->PnoLock);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiSetEnhancedNetworkListOffload(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_NLO_PARAMS* Params, const AP6256_PNO_CONFIG* Config)
{
    NTSTATUS status;
    if (Ctx->FirmwareState != Ap6256FwRunning || !Ctx->DatapathRunning) return STATUS_DEVICE_NOT_READY;
    Ap6256LockAcquire(&Ctx->PnoLock);
    status = Ap6256WifiProgramNetworkListOffload(Ctx, Params, Config);
    Ap6256LockRelease(&Ctx->PnoLock);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiPnoChannels(PAP6256_DEVICE_CONTEXT Ctx, AP6256_PNO_CONFIG* Config, BOOLEAN Fill)
{
    BRCMF_CHANNEL_LIST list = {0};
    NTSTATUS status;
    ULONG i, j;
    list.Count=RTL_NUMBER_OF(list.Channels);
    status=Ap6256BcdcQueryDcmd(Ctx,BRCMF_C_GET_VALID_CHANNELS,&list,sizeof(list));
    if (!NT_SUCCESS(status)) return status;
    if (list.Count==0 || list.Count>RTL_NUMBER_OF(list.Channels) || Config->ChannelCount>64)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    for (i=0; i<Config->ChannelCount; ++i) {
        for (j=0; j<list.Count; ++j) if (Config->Channels[i]==list.Channels[j]) break;
        if (j==list.Count) return STATUS_INVALID_PARAMETER;
    }
    for (i=0; i<list.Count; ++i) {
        if (list.Channels[i]==0 || list.Channels[i]>255) return STATUS_DEVICE_PROTOCOL_ERROR;
        if (Fill) {
            for (j=0; j<Config->ChannelCount; ++j) if (Config->Channels[j]==list.Channels[i]) break;
            if (j==Config->ChannelCount) {
                if (j==64) return STATUS_BUFFER_OVERFLOW;
                Config->Channels[Config->ChannelCount++]=(UINT16)list.Channels[i];
            }
        }
    }
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiSetWindowsNetworkListOffload(PAP6256_DEVICE_CONTEXT Ctx,
    const AP6256_NLO_PARAMS* Params, const UINT16* Hints, ULONG HintCount)
{
    AP6256_PNO_CONFIG config = {0};
    NTSTATUS status;
    if (HintCount>64 || !Params->WindowsRequest) return STATUS_INVALID_PARAMETER;
    if (!Params->Enable || Params->NetworkCount==0)
        return Ap6256WifiSetNetworkListOffload(Ctx,Params);
    if (!Ctx->FirmwareEnhancedPnoSupported) return STATUS_NOT_SUPPORTED;
    if (Ctx->FirmwareState!=Ap6256FwRunning || !Ctx->DatapathRunning) return STATUS_DEVICE_NOT_READY;
    config.ChannelCount=HintCount;
    if (HintCount!=0) RtlCopyMemory(config.Channels,Hints,2*HintCount);
    config.Gscan.Version=1; config.Gscan.RssiWindow=4; config.Gscan.BucketCount=1;
    config.Gscan.Buckets[0].FrequencyMultiple=1;
    Ap6256LockAcquire(&Ctx->PnoLock);
    status=Ap6256WifiPnoChannels(Ctx,&config,TRUE);
    if (NT_SUCCESS(status)) {
        config.Gscan.Buckets[0].EndIndex=(UINT16)(config.ChannelCount-1);
        status=Ap6256WifiProgramNetworkListOffload(Ctx,Params,&config);
    }
    Ap6256LockRelease(&Ctx->PnoLock);
    return status;
}

#define AP6256_WOL_ADDR_OFFSET      4u
#define AP6256_WOL_ADDR_BYTES      12u
#define AP6256_WOL_PAYLOAD_OFFSET  30u
#define AP6256_WOL_PATTERN_GROWTH  18u

#define BRCMF_PKT_FILTER_PATTERN    0u
#define BRCMF_PKT_FILTER_MAGIC      1u

#define AP6256_MAGIC_SYNC_BYTES     6u
#define AP6256_MAGIC_REPEATS       16u
#define AP6256_MAGIC_SIZE  (AP6256_MAGIC_SYNC_BYTES + AP6256_MAGIC_REPEATS * 6u)

static const UCHAR Ap6256EapolFilterMask[9] = {
    0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFF
};
static const UCHAR Ap6256EapolFilterPattern[9] = {
    0x88, 0x8E, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
};

#pragma pack(push, 1)
typedef struct _BRCMF_PKT_FILTER {
    UINT32 Id;
    UINT32 Type;
    UINT32 NegateMatch;
    UINT32 Offset;
    UINT32 Size;

} BRCMF_PKT_FILTER;
#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_PKT_FILTER) == 20);

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiBuildPacketFilter(_In_ UINT32 Id,
                                            _In_ UINT32 Type,
                                            _In_ UINT32 Offset,
                                            _In_ ULONG Size,
                                            _Outptr_ BRCMF_PKT_FILTER** Filter,
                                            _Out_ UCHAR** Mask,
                                            _Out_ UCHAR** Pattern,
                                            _Out_ PULONG Total)
{
    BRCMF_PKT_FILTER* filter;
    ULONG total = (ULONG)sizeof(BRCMF_PKT_FILTER) + 2u * Size;

    *Filter = NULL;
    *Mask = NULL;
    *Pattern = NULL;
    *Total = 0;

    filter = (BRCMF_PKT_FILTER*)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
                                                AP6256_POOL_TAG);
    if (filter == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    filter->Id = Id;
    filter->Type = Type;
    filter->NegateMatch = 0;
    filter->Offset = Offset;
    filter->Size = Size;

    *Filter = filter;
    *Mask = (UCHAR*)(filter + 1);
    *Pattern = *Mask + Size;
    *Total = total;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolBitmapPattern(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 PatternId,
    _In_reads_bytes_(PatternLength) const UCHAR* Pattern,
    _In_ ULONG PatternLength,
    _In_reads_bytes_(MaskLength) const UCHAR* Mask,
    _In_ ULONG MaskLength)
{
    BRCMF_PKT_FILTER* filter;
    UCHAR* mask;
    UCHAR* pattern;
    ULONG total;
    ULONG size;
    ULONG i;
    NTSTATUS status;

    if (PatternLength < 14u || PatternLength > AP6256_ACTFRAME_FIRMWARE_MAX ||
        MaskLength * 8u < PatternLength) {
        return STATUS_INVALID_PARAMETER;
    }

    size = PatternLength + AP6256_WOL_PATTERN_GROWTH;
    status = Ap6256WifiBuildPacketFilter(PatternId,
                                         BRCMF_PKT_FILTER_PATTERN, 0, size,
                                         &filter, &mask, &pattern, &total);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(mask, 2u * size);

    for (i = 0; i < PatternLength; i++) {
        ULONG target = (i < AP6256_WOL_ADDR_BYTES)
            ? (AP6256_WOL_ADDR_OFFSET + i)
            : (AP6256_WOL_PAYLOAD_OFFSET + (i - AP6256_WOL_ADDR_BYTES));
        BOOLEAN wanted = (BOOLEAN)((Mask[i / 8u] >> (i % 8u)) & 1u);

        mask[target] = wanted ? 0xFFu : 0x00u;
        pattern[target] = Pattern[i];
    }

    status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_add", filter, total);
    TraceInfo(TRACE_NETADAPTER,
              "wake pattern %u: %u byte(s) of Ethernet as a %u-byte 802.11 "
              "filter -> 0x%08X\n",
              PatternId, PatternLength, size, status);

    ExFreePoolWithTag(filter, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolMagicPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId)
{
    BRCMF_PKT_FILTER* filter;
    UCHAR* mask;
    UCHAR* pattern;
    ULONG total;
    ULONG i;
    NTSTATUS status;

    status = Ap6256WifiBuildPacketFilter(PatternId, BRCMF_PKT_FILTER_MAGIC,
                                         AP6256_WOL_PAYLOAD_OFFSET,
                                         AP6256_MAGIC_SIZE,
                                         &filter, &mask, &pattern, &total);
    if (!NT_SUCCESS(status)) return status;

    RtlFillMemory(mask, AP6256_MAGIC_SIZE, 0xFF);
    RtlFillMemory(pattern, AP6256_MAGIC_SYNC_BYTES, 0xFF);
    for (i = 0; i < AP6256_MAGIC_REPEATS; i++) {
        RtlCopyMemory(pattern + AP6256_MAGIC_SYNC_BYTES + i * 6u,
                      Ctx->MacAddress, 6u);
    }

    status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_add", filter, total);
    TraceInfo(TRACE_NETADAPTER, "wake pattern %u: magic packet -> 0x%08X\n",
              PatternId, status);

    ExFreePoolWithTag(filter, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddWolEapolPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId)
{
    BRCMF_PKT_FILTER* filter;
    UCHAR* mask;
    UCHAR* pattern;
    ULONG total;
    NTSTATUS status;

    status = Ap6256WifiBuildPacketFilter(
        PatternId, BRCMF_PKT_FILTER_PATTERN,
        AP6256_WOL_PAYLOAD_OFFSET, (ULONG)sizeof(Ap6256EapolFilterMask),
        &filter, &mask, &pattern, &total);
    if (!NT_SUCCESS(status)) return status;

    RtlCopyMemory(mask, Ap6256EapolFilterMask, sizeof(Ap6256EapolFilterMask));
    RtlCopyMemory(pattern, Ap6256EapolFilterPattern,
                  sizeof(Ap6256EapolFilterPattern));

    status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_add", filter, total);
    TraceInfo(TRACE_NETADAPTER,
              "wake pattern %u: EAPOL request -> 0x%08X\n",
              PatternId, status);

    ExFreePoolWithTag(filter, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveWolPattern(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ UINT32 PatternId)
{
    UINT32 id = PatternId;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_delete", &id,
                                         sizeof(id));

    TraceInfo(TRACE_NETADAPTER, "wake pattern %u removed -> 0x%08X\n",
              PatternId, status);
    return status;
}

#define AP6256_PACKET_FILTER_SLEEP  0x00000008u

#define AP6256_PKT_FILTER_USABLE      22u

#define AP6256_PKT_FILTER_MODE_SLEEP  13u
#define AP6256_PKT_FILTER_MODE_AWAKE  15u

#define AP6256_SLEEP_LISTEN_MS      1000u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilterMax(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _Out_ PUINT32 Usable)
{
    UINT32 want = AP6256_PKT_FILTER_USABLE + 1;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_max", &want,
                                         sizeof(want));

    *Usable = AP6256_PKT_FILTER_USABLE;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiEnablePacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_ UINT32 PatternId,
                                      _In_ BOOLEAN Enable)
{
    struct { UINT32 Id; UINT32 Enable; } request;
    NTSTATUS status;

    request.Id = PatternId;
    request.Enable = Enable ? 1u : 0u;
    status = Ap6256BcdcSetIovar(Ctx, "pkt_filter_enable", &request,
                                sizeof(request));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "wake pattern %u could not be %s 0x%08X\n",
                  PatternId, Enable ? "enabled" : "disabled", status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetPacketFilterMode(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ UINT32 Mode)
{
    UINT32 mode = Mode;
    return Ap6256BcdcSetIovar(Ctx, "pkt_filter_mode", &mode, sizeof(mode));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetMasterPacketFilter(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                         _In_ UINT32 Mask)
{
    UINT32 mask = Mask;
    return Ap6256BcdcSetIovar(Ctx, "packet_filter", &mask, sizeof(mask));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiSetWakeEventMask(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                           _In_ UINT32 MediaSpecific)
{
    UCHAR mask[16];

    RtlZeroMemory(mask, sizeof(mask));
    if ((MediaSpecific & AP6256_WAKE_ON_AP_ASSOCIATION_LOST) != 0) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_DISASSOC);
    }
    if ((MediaSpecific & AP6256_WAKE_ON_NLO_DISCOVERY) != 0) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_PFN_NET_FOUND);
    }
    if ((MediaSpecific & AP6256_WAKE_ON_GTK_HANDSHAKE_ERROR) != 0) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_PSK_SUP);
    }
    if ((MediaSpecific & AP6256_WAKE_ON_4WAY_HANDSHAKE_REQUEST) != 0) {
        Ap6256EventMaskSet(mask, sizeof(mask), BRCMF_E_EAPOL_MSG);
    }
    return Ap6256BcdcSetIovar(Ctx, "event_msgs", mask, sizeof(mask));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiStretchBeaconListen(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 current = 0;
    UINT32 beacon = 0;
    UINT32 dtimPeriod = 0;
    UINT32 interval;
    UINT32 window = AP6256_SLEEP_LISTEN_MS;
    UINT32 dtim = 1;

    NTSTATUS status;
    Ctx->SavedBeaconListenValid = FALSE;
    status = Ap6256BcdcGetIovar(Ctx, "bcn_li_dtim", &current, sizeof(current));
    if (!NT_SUCCESS(status)) return status;
    Ctx->SavedBeaconListenDtim = current;
    Ctx->SavedBeaconListenValid = TRUE;

    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_BCNPRD, &beacon, sizeof(beacon));
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_DTIMPRD, &dtimPeriod, sizeof(dtimPeriod));
    if (!NT_SUCCESS(status)) return status;
    if (beacon > 65535 || dtimPeriod > 255) return STATUS_DEVICE_PROTOCOL_ERROR;

    interval = beacon * dtimPeriod;
    if (interval != 0) {
        if (window < interval) window = interval;
        dtim = (window + interval / 2u) / interval;
    }

    TraceInfo(TRACE_NETADAPTER,
              "sleep listen: beacon %u x DTIM %u = %u ms, listening every %u "
              "DTIM (was %u)\n", beacon, dtimPeriod, interval, dtim, current);

    if (dtim != current) {
        return Ap6256BcdcSetIovar(Ctx, "bcn_li_dtim", &dtim, sizeof(dtim));
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiArmWakeEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 MediaSpecific)
{
    AP6256_WAKE_PACKET empty;
    UINT32 mask = MediaSpecific;
    NTSTATUS status;
    if (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0)) return STATUS_NOT_SUPPORTED;

    status = Ap6256BcdcSetIovar(Ctx, "wake_event_enable", &mask, sizeof(mask));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "wake_event_enable 0x%08X not accepted 0x%08X\n",
                  MediaSpecific, status);
        return status;
    }

    status = Ap6256WifiSetWakeEventMask(Ctx, MediaSpecific);
    if (!NT_SUCCESS(status)) return status;

    RtlZeroMemory(&empty, sizeof(empty));
    status = Ap6256BcdcSetIovar(Ctx, "wake_packet", &empty, sizeof(empty));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "wake packet not cleared 0x%08X\n",
                  status);
        return status;
    }

    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadWakeEvents(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PUINT32 Status)
{
    UINT32 value = 0;
    NTSTATUS status = Ap6256BcdcGetIovar(Ctx, "wake_event_status", &value,
                                         sizeof(value));

    *Status = NT_SUCCESS(status) ? value : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadWakePacket(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ AP6256_WAKE_PACKET* Packet)
{
    NTSTATUS status;

    AP6256_BCDC_QUERY_RESULT result;
    RtlZeroMemory(Packet, sizeof(*Packet));
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wake_packet", Packet, sizeof(*Packet), &result);
    if (!NT_SUCCESS(status)) return status;

    if (result.PayloadLength != sizeof(*Packet) ||
        Packet->SavedLength > sizeof(Packet->Packet) ||
        Packet->SavedLength > Packet->OriginalLength) {
        RtlZeroMemory(Packet, sizeof(*Packet));
        return STATUS_DEVICE_PROTOCOL_ERROR;
    }
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSuspendForWake(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UINT32 MediaSpecific,
                                  _In_ BOOLEAN ArpOffload,
                                  _In_ BOOLEAN NsOffload)
{
    UINT32 roamOff = 0;
    UINT32 one = 1;
    NTSTATUS status;
    NTSTATUS firstFailure = STATUS_SUCCESS;
    AP6256_POWER_SAVE_DX pendingPower[2];
    if (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0)) return STATUS_NOT_SUPPORTED;

    Ctx->PowerThread = KeGetCurrentThread();
    InterlockedExchange(&Ctx->HostTxQuiesced, 1);
    InterlockedExchange(&Ctx->FirmwareIoQuiesced, 1);

    Ap6256LockAcquire(&Ctx->Bcdc.Lock);
    Ap6256LockRelease(&Ctx->Bcdc.Lock);
    Ctx->SavedPowerSaveValid = FALSE;
    Ctx->SavedRoamOffValid = FALSE;
    Ctx->SavedBeaconListenValid = FALSE;
    Ctx->SavedD0FilterValid = FALSE;
    Ctx->LowPowerArmed = TRUE;
    Ctx->SavedLowPowerStateValid = TRUE;
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_PM, &Ctx->SavedPowerSaveMode,
                               sizeof(Ctx->SavedPowerSaveMode));
    Ctx->SavedPowerSaveValid = (BOOLEAN)NT_SUCCESS(status);
    if (!NT_SUCCESS(status)) firstFailure = status;
    if (Ctx->SavedPowerSaveValid) {
        status = Ap6256WifiSetPowerSave(Ctx, TRUE);
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }
    status = Ap6256WifiStretchBeaconListen(Ctx);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    status = Ap6256BcdcGetIovar(Ctx, "roam_off", &roamOff, sizeof(roamOff));
    Ctx->SavedRoamOffValid = (BOOLEAN)NT_SUCCESS(status);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    if (Ctx->SavedRoamOffValid) {
        Ctx->SavedRoamOff = roamOff;
        status = Ap6256BcdcSetIovar(Ctx, "roam_off", &one, sizeof(one));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }

    status = Ap6256BcdcGetIovar(Ctx, "d0_filter_enable",
        &Ctx->SavedD0FilterEnable, sizeof(Ctx->SavedD0FilterEnable));
    if (NT_SUCCESS(status)) {
        UINT32 disable = 0;
        Ctx->SavedD0FilterValid = TRUE;
        status = Ap6256BcdcSetIovar(Ctx, "d0_filter_enable", &disable, sizeof(disable));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }
    status = Ap6256WifiEnableProtocolOffloads(Ctx, ArpOffload, NsOffload);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    status = Ap6256WifiArmWakeEvents(Ctx, MediaSpecific);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    status = Ap6256WifiSetMasterPacketFilter(
        Ctx, Ctx->PacketFilterMask | AP6256_PACKET_FILTER_SLEEP);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    status = Ap6256WifiSetPacketFilterMode(Ctx, AP6256_PKT_FILTER_MODE_SLEEP);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    if (Ctx->FirmwareWowlAdapter) {
        UINT32 sleep = 1u | ((Ctx->WakeEnabledOffloads &
            AP6256_PM_RSN_REKEY) != 0 &&
            Ctx->FirmwareGtkOffloadSupported ? 2u : 0u);
        status = Ap6256BcdcSetIovar(Ctx, "wdi_wowl_sleep", &sleep, sizeof(sleep));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }

    Ap6256PowerCaptureDx(Ctx, pendingPower);
    Ctx->RetainedSleepStarted = KeQueryInterruptTime();
    Ap6256DatapathSuspend(Ctx);
    status = Ap6256SdioSetSleep(Ctx, TRUE);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    Ctx->PowerThread = NULL;
    if (NT_SUCCESS(firstFailure)) {
        RtlCopyMemory(Ctx->PowerSaveDx, pendingPower, sizeof(pendingPower));
        TraceInfo(TRACE_NETADAPTER,
                  "armed for wake: media events 0x%08X, filter mask 0x%08X, "
                  "ARP %u, NS %u\n",
                  MediaSpecific, Ctx->PacketFilterMask | AP6256_PACKET_FILTER_SLEEP,
                  (ULONG)ArpOffload, (ULONG)NsOffload);
    } else {
        TraceError(TRACE_NETADAPTER,
                   "Dx hot setup incomplete 0x%08X; chip stays up for D0 restore\n",
                   firstFailure);
    }
    return firstFailure;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiResumeFromWake(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _Out_ PUINT32 WakeStatus,
                              _Out_ AP6256_WAKE_PACKET* Packet,
                              _Out_ PBOOLEAN PacketValid)
{
    UINT32 zero = 0;
    NTSTATUS status, firstFailure = STATUS_SUCCESS;
    Ctx->PowerThread = KeGetCurrentThread();

    *WakeStatus = 0;
    *PacketValid = FALSE;
    RtlZeroMemory(Packet, sizeof(*Packet));

    status = Ap6256SdioSetSleep(Ctx, FALSE);
    if (!NT_SUCCESS(status)) { Ctx->PowerThread = NULL; return status; }
    Ap6256DatapathResume(Ctx);
    if (Ctx->FirmwareWowlAdapter) {
        status = Ap6256BcdcSetIovar(Ctx, "wdi_wowl_sleep", &zero, sizeof(zero));
        if (!NT_SUCCESS(status)) { Ctx->PowerThread = NULL; return status; }
    }
    status = Ap6256WifiSetPacketFilterMode(Ctx, AP6256_PKT_FILTER_MODE_AWAKE);
    if (!NT_SUCCESS(status)) firstFailure = status;

    status = Ap6256WifiConfigureEvents(Ctx);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    status = Ap6256WifiReadWakeEvents(Ctx, WakeStatus);
    if (Ctx->FirmwareWowlAdapter && !NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    if (NT_SUCCESS(Ap6256WifiReadWakePacket(Ctx, Packet)) &&
        Packet->Type == AP6256_WAKE_PACKET_NET && Packet->SavedLength != 0) {
        *PacketValid = TRUE;
    }

    if (Ctx->SavedBeaconListenValid) {
        status = Ap6256BcdcSetIovar(Ctx, "bcn_li_dtim", &Ctx->SavedBeaconListenDtim,
            sizeof(Ctx->SavedBeaconListenDtim));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }
    if (Ctx->SavedRoamOffValid) {
        status = Ap6256BcdcSetIovar(Ctx, "roam_off", &Ctx->SavedRoamOff, sizeof(Ctx->SavedRoamOff));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }

    {
        NTSTATUS arpStatus = Ctx->FirmwareArpOffloadSupported
            ? Ap6256BcdcSetIovar(Ctx, "arpoe", &zero, sizeof(zero)) : STATUS_SUCCESS;
        NTSTATUS ndStatus = Ctx->FirmwareNdOffloadSupported
            ? Ap6256BcdcSetIovar(Ctx, "ndoe", &zero, sizeof(zero)) : STATUS_SUCCESS;
        if (!NT_SUCCESS(arpStatus) && NT_SUCCESS(firstFailure)) firstFailure = arpStatus;
        if (!NT_SUCCESS(ndStatus) && NT_SUCCESS(firstFailure)) firstFailure = ndStatus;
        if (!NT_SUCCESS(arpStatus) || !NT_SUCCESS(ndStatus))
            TraceError(TRACE_NETADAPTER,
                       "D0 protocol offload disable failed: ARP 0x%08X, ND 0x%08X\n",
                       arpStatus, ndStatus);
    }

    status = Ap6256WifiSetMasterPacketFilter(Ctx, Ctx->PacketFilterMask);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    if (Ctx->SavedD0FilterValid) {
        status = Ap6256BcdcSetIovar(Ctx, "d0_filter_enable",
            &Ctx->SavedD0FilterEnable, sizeof(Ctx->SavedD0FilterEnable));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
        Ctx->SavedD0FilterValid = FALSE;
    }
    if (Ctx->SavedPowerSaveValid) {
        UINT32 pm = Ctx->SavedPowerSaveMode;
        status = Ap6256BcdcSetDcmd(Ctx, BRCMF_C_SET_PM, &pm, sizeof(pm));
        if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    }

    Ctx->SavedLowPowerStateValid = FALSE;
    Ctx->SavedBeaconListenValid = Ctx->SavedRoamOffValid = Ctx->SavedPowerSaveValid = FALSE;
    Ctx->LowPowerArmed = FALSE;
    Ap6256WlfcResumeRetained(Ctx, KeQueryInterruptTime() - Ctx->RetainedSleepStarted);
    InterlockedExchange(&Ctx->FirmwareIoQuiesced, 0);
    Ctx->PowerThread = NULL;
    status = Ap6256QualityReapply(Ctx);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    InterlockedExchange(&Ctx->HostTxQuiesced, 0);
    Ap6256NetTxKick(Ctx);
    TraceInfo(TRACE_NETADAPTER,
              "woke: status 0x%08X, wake packet %s\n",
              *WakeStatus, *PacketValid ? "present" : "none");
    return firstFailure;
}

#define AP6256_ROAM_RSSI_DEFAULT_DBM   (-80)
#define AP6256_RSSI_EVENT_RATE_MS      2000u
#define AP6256_RSSI_EVENT_FLOOR        (-128)

#pragma pack(push, 1)
typedef struct _BRCMF_RSSI_EVENT {
    UINT32 RateLimitMs;
    UCHAR  LevelCount;
    CHAR   Levels[8];
    UCHAR  Reserved[3];
} BRCMF_RSSI_EVENT;
#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_RSSI_EVENT) == 16);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRoamTrigger(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _Out_ PINT32 TriggerDbm)
{
    INT32 request[2] = {0};
    NTSTATUS status;

    *TriggerDbm = AP6256_ROAM_RSSI_DEFAULT_DBM;

    {
        UINT32 chanspec = 0, band;
        AP6256_BCDC_QUERY_RESULT result;
        status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "chanspec", &chanspec,
            sizeof(chanspec), &result);
        if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
            result.PayloadLength < sizeof(chanspec) || chanspec > MAXUINT16 ||
            (chanspec & 0xffu) == 0)) status = STATUS_DEVICE_PROTOCOL_ERROR;
        band = Ctx->D11IoType == BRCMU_D11AC_IOTYPE ? chanspec & 0xc000u : chanspec & 0xf000u;
        if (NT_SUCCESS(status)) {
            if ((Ctx->D11IoType == BRCMU_D11AC_IOTYPE && band == BRCMU_CHSPEC_D11AC_BAND_5G) ||
                (Ctx->D11IoType == BRCMU_D11N_IOTYPE && band == BRCMU_CHSPEC_D11N_BAND_5G))
                request[1] = 1;
            else if ((Ctx->D11IoType == BRCMU_D11AC_IOTYPE && band == BRCMU_CHSPEC_D11AC_BAND_2G) ||
                     (Ctx->D11IoType == BRCMU_D11N_IOTYPE && band == BRCMU_CHSPEC_D11N_BAND_2G))
                request[1] = 2;
            else status = STATUS_DEVICE_PROTOCOL_ERROR;
        }
        if (NT_SUCCESS(status)) {
            request[0] = 0;
            status = Ap6256BcdcQueryDcmdResultIf(Ctx, 0, BRCMF_C_GET_ROAM_TRIGGER, request,
                                 sizeof(request), &result);
            if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
                result.PayloadLength < sizeof(request[0]) ||
                request[0] <= AP6256_RSSI_EVENT_FLOOR || request[0] >= 0))
                status = STATUS_DEVICE_PROTOCOL_ERROR;
        }
    }
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "roam trigger query failed 0x%08X; using %d dBm\n",
                  status, AP6256_ROAM_RSSI_DEFAULT_DBM);
        return status;
    }

    *TriggerDbm = request[0];
    TraceInfo(TRACE_NETADAPTER,
              "roam trigger is %d dBm on the current band\n", request[0]);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiArmRssiEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ INT32 TriggerDbm)
{
    BRCMF_RSSI_EVENT request;
    NTSTATUS status;

    RtlZeroMemory(&request, sizeof(request));
    request.RateLimitMs = AP6256_RSSI_EVENT_RATE_MS;
    request.LevelCount = 2;
    request.Levels[0] = (CHAR)AP6256_RSSI_EVENT_FLOOR;
    request.Levels[1] = (CHAR)TriggerDbm;

    status = Ap6256BcdcSetIovar(Ctx, "rssi_event", &request, sizeof(request));
    TraceInfo(TRACE_NETADAPTER,
              "rssi event armed at %d dBm, at most one every %u ms -> "
              "0x%08X\n", TriggerDbm, AP6256_RSSI_EVENT_RATE_MS, status);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiValidateUnreachableThreshold(UINT32 ThresholdMs)
{
    if (ThresholdMs < 1000u || ThresholdMs % 1000u != 0)
        return STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiReadBeaconTimeout(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                          _Out_ UINT32* Timeout)
{
    AP6256_BCDC_QUERY_RESULT result = {0};
    *Timeout = 0;
    NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "bcn_timeout",
        Timeout, sizeof(*Timeout), &result);
    if (NT_SUCCESS(status) && (!result.FirmwareReply || result.FirmwareError ||
        result.PayloadLength < sizeof(*Timeout))) status = STATUS_DEVICE_PROTOCOL_ERROR;
    if (!NT_SUCCESS(status))
        TraceWarn(TRACE_NETADAPTER,
            "beacon timeout GET not verified: status 0x%08X reply %u error %u firmware %d payload %u byte(s)\n",
            status, (UINT32)result.FirmwareReply, (UINT32)result.FirmwareError,
            result.FirmwareStatus, result.PayloadLength);
    else
        TraceVerbose(TRACE_NETADAPTER, "beacon timeout readback: %u seconds, payload %u byte(s)\n",
            *Timeout, result.PayloadLength);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiApplyUnreachableThreshold(PAP6256_DEVICE_CONTEXT Ctx, UINT32 ThresholdMs)
{
    UINT32 timeout = ThresholdMs / 1000u, previous = 0, actual = 0;
    NTSTATUS status = Ap6256WifiValidateUnreachableThreshold(ThresholdMs);
    NTSTATUS cleanup;
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256WifiReadBeaconTimeout(Ctx, &previous);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovar(Ctx, "bcn_timeout", &timeout, sizeof(timeout));
    if (NT_SUCCESS(status)) {
        status = Ap6256WifiReadBeaconTimeout(Ctx, &actual);
        if (NT_SUCCESS(status) && actual != timeout) status = STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (NT_SUCCESS(status)) return status;
    cleanup = Ap6256BcdcSetIovar(Ctx, "bcn_timeout", &previous, sizeof(previous));
    if (NT_SUCCESS(cleanup)) {
        cleanup = Ap6256WifiReadBeaconTimeout(Ctx, &actual);
        if (NT_SUCCESS(cleanup) && actual != previous) cleanup = STATUS_DEVICE_PROTOCOL_ERROR;
    }
    if (!NT_SUCCESS(cleanup))
        TraceWarn(TRACE_NETADAPTER, "beacon timeout rollback not confirmed 0x%08X\n", cleanup);
    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiRestoreUnreachableThreshold(PAP6256_DEVICE_CONTEXT Ctx)
{
    LONG timeout = InterlockedCompareExchange(&Ctx->BeaconLossTimeoutSeconds, 0, 0);
    if (timeout == 0) return STATUS_SUCCESS;
    if (timeout < 0 || (UINT32)timeout > MAXULONG / 1000u) return STATUS_INVALID_DEVICE_STATE;
    return Ap6256WifiApplyUnreachableThreshold(Ctx, (UINT32)timeout * 1000u);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiArmRoamTriggers(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    INT32 trigger = AP6256_ROAM_RSSI_DEFAULT_DBM;
    LONG configured = InterlockedCompareExchange(&Ctx->BeaconLossTimeoutSeconds, 0, 0);
    UINT32 timeout = configured > 0 ? (UINT32)configured : AP6256_BEACON_LOSS_TIMEOUT_SECONDS;
    NTSTATUS status = configured != 0 ? Ap6256WifiRestoreUnreachableThreshold(Ctx) :
        Ap6256WifiApplyUnreachableThreshold(Ctx, timeout * 1000u);
    if (!NT_SUCCESS(status))
        TraceWarn(TRACE_NETADAPTER, "beacon loss timeout %u seconds not confirmed 0x%08X\n",
            timeout, status);

    (VOID)Ap6256WifiGetRoamTrigger(Ctx, &trigger);
    Ctx->RoamRssiTriggerDbm = trigger;
    (VOID)Ap6256WifiArmRssiEvent(Ctx, trigger);
}

#pragma pack(push, 1)
typedef struct _BRCMF_P2P_IF {
    UCHAR  Address[6];
    UINT16 Role;
    UINT16 Chanspec;
} BRCMF_P2P_IF;
#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_P2P_IF) == 10);

#define AP6256_P2P_IF_REPLY_BYTES  20u

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 Ap6256WifiP2pInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    return Ctx->P2pInterfaceValid ? Ctx->P2pInterfaceIndex : 0u;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256WifiAllowConcurrency(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 one = 1;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "apsta", &one, sizeof(one));

    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "apsta not accepted 0x%08X; a second interface may not "
                  "come up\n", status);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pSetDiscoverySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                           _In_ BOOLEAN WpsEnabled)
{
    UINT32 request[2], got;
    UINT32 ifIndex;
    NTSTATUS status;
    if (!Ctx->P2pBssValid || Ctx->P2pBssIndex == 0)
        return STATUS_DEVICE_NOT_READY;
    ifIndex = Ap6256WifiP2pInterface(Ctx);
    request[0] = Ctx->P2pBssIndex;
    request[1] = WSEC_AES_ENABLED | (WpsEnabled ? SES_OW_ENABLED : 0u);
    status = Ap6256BcdcSetIovarIf(Ctx, ifIndex, "bsscfg:wsec", request, sizeof(request));
    if (!NT_SUCCESS(status)) return status;
    got = request[0];
    status = Ap6256BcdcGetIovarIf(Ctx, ifIndex, "bsscfg:wsec", &got, sizeof(got));
    TraceDiag("P2P: discovery security if %u bsscfg %u wsec 0x%X/0x%X -> 0x%08X\n",
              ifIndex, request[0], request[1], got, status);
    if (NT_SUCCESS(status) && (got & (WSEC_AES_ENABLED | SES_OW_ENABLED)) != request[1])
        status = STATUS_DEVICE_PROTOCOL_ERROR;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pSetDiscoveryInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                            _In_ BOOLEAN Enable,
                                            _Out_opt_ PUINT32 BssIndex)
{
    UINT32 enable = Enable ? 1u : 0u;
    UINT32 index = 0;
    NTSTATUS status;

    if (BssIndex != NULL) *BssIndex = 0;

    status = Ap6256BcdcSetIovar(Ctx, "p2p_disc", &enable, sizeof(enable));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "p2p_disc %u refused 0x%08X\n",
                  enable, status);
        return status;
    }
    if (!Enable) {
        Ctx->P2pBssValid = FALSE;
        Ctx->P2pInterfaceValid = FALSE;
        Ap6256P2pForgetIesFor(&Ctx->P2p);
        return STATUS_SUCCESS;
    }

    status = Ap6256BcdcGetIovar(Ctx, "p2p_dev", &index, sizeof(index));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "p2p discovery enabled but p2p_dev did not answer 0x%08X\n",
                  status);
        return status;
    }
    if (BssIndex != NULL) *BssIndex = index;

    Ctx->P2pBssIndex = index;
    Ctx->P2pBssValid = TRUE;
    if (index < RTL_NUMBER_OF(Ctx->FirmwareIfMap)) {
        LONG mapping = InterlockedCompareExchange(&Ctx->FirmwareIfMap[index], 0, 0);
        if (mapping > 0 && mapping <= 16) {
            Ctx->P2pInterfaceIndex = (UINT32)(mapping - 1);
            Ctx->P2pInterfaceValid = TRUE;
        }
    }

    status = Ap6256WifiP2pSetDiscoverySecurity(Ctx, FALSE);
    if (!NT_SUCCESS(status)) {
        UINT32 zero = 0;
        (VOID)Ap6256BcdcSetIovar(Ctx, "p2p_disc", &zero, sizeof(zero));
        Ctx->P2pBssValid = FALSE;
        Ctx->P2pInterfaceValid = FALSE;
        if (BssIndex != NULL) *BssIndex = 0;
        return status;
    }
    TraceInfo(TRACE_NETADAPTER, "p2p discovery interface is bsscfg %u\n",
              index);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pAddInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_reads_(6) const UCHAR* Address,
                                   _In_ UINT16 Role,
                                   _In_ UINT16 Chanspec)
{
    BRCMF_P2P_IF request;
    UCHAR reply[AP6256_P2P_IF_REPLY_BYTES];
    UINT32 one = 1;
    NTSTATUS status;

    (VOID)Ap6256WifiAllowConcurrency(Ctx);

    RtlZeroMemory(&request, sizeof(request));
    RtlCopyMemory(request.Address, Address, sizeof(request.Address));
    request.Role = Role;
    request.Chanspec = Chanspec;

    status = Ap6256BcdcSetIovar(Ctx, "p2p_ifadd", &request, sizeof(request));
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "p2p_ifadd %02X:%02X:%02X:%02X:%02X:%02X role %u refused "
                  "0x%08X\n", Address[0], Address[1], Address[2], Address[3],
                  Address[4], Address[5], (ULONG)Role, status);
        return status;
    }

    RtlZeroMemory(reply, sizeof(reply));
    RtlCopyMemory(reply, Address, 6);
    status = Ap6256BcdcGetIovar(Ctx, "p2p_if", reply, sizeof(reply));

    if (NT_SUCCESS(status)) {
        UINT32 bss = 0;
        RtlCopyMemory(&bss, reply, sizeof(bss));
        Ctx->P2pBssIndex = bss;
        Ctx->P2pBssValid = TRUE;
    }
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER,
                  "p2p interface added but p2p_if did not answer 0x%08X\n",
                  status);
        (VOID)Ap6256BcdcSetIovar(Ctx, "p2p_ifdel", (PVOID)(ULONG_PTR)Address, 6);
        return status;
    }

    if (Role == AP6256_P2P_IF_CLIENT) {
        (VOID)Ap6256BcdcSetIovar(Ctx, "buf_key_b4_m4", &one, sizeof(one));
    } else {
        (VOID)Ap6256BcdcSetIovar(Ctx, "ap_isolate", &one, sizeof(one));
    }

    TraceInfo(TRACE_NETADAPTER,
              "p2p %s interface %02X:%02X:%02X:%02X:%02X:%02X on chanspec "
              "0x%04X\n",
              Role == AP6256_P2P_IF_CLIENT ? "client" : "group owner",
              Address[0], Address[1], Address[2], Address[3], Address[4],
              Address[5], (ULONG)Chanspec);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pDeleteInterface(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                      _In_reads_(6) const UCHAR* Address)
{
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "p2p_ifdel",
                                         (PVOID)(ULONG_PTR)Address, 6);

    Ctx->P2pBssValid = FALSE;
    Ctx->P2pInterfaceValid = FALSE;

    TraceInfo(TRACE_NETADAPTER,
              "p2p interface %02X:%02X:%02X:%02X:%02X:%02X removed -> "
              "0x%08X\n",
              Address[0], Address[1], Address[2], Address[3], Address[4],
              Address[5], status);
    return status;
}

#pragma pack(push, 1)
typedef struct _BRCMF_WSEC_INFO {
    UCHAR  Version;
    UCHAR  Pad[2];
    UCHAR  TlvCount;
    UINT16 Type;
    UINT16 Length;

} BRCMF_WSEC_INFO;
#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_WSEC_INFO) == 8);

#define BRCMF_WSEC_INFO_VERSION   1u
#define BRCMF_WSEC_INFO_MAX_KEYS  1u

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMaxKeys(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                              _Out_ PUINT32 MaxKeys)
{
    struct {
        BRCMF_WSEC_INFO Header;
        UINT32 Value;
    } query;
    NTSTATUS status;

    *MaxKeys = 0;

    RtlZeroMemory(&query, sizeof(query));
    query.Header.Version = BRCMF_WSEC_INFO_VERSION;
    query.Header.TlvCount = 1;
    query.Header.Type = BRCMF_WSEC_INFO_MAX_KEYS;
    query.Header.Length = sizeof(query.Value);

    status = Ap6256BcdcProbeIovar(Ctx, "wsec_info", &query, sizeof(query), NULL);
    if (!NT_SUCCESS(status)) return status;

    if (query.Header.Length != sizeof(query.Value) || query.Value == 0) {
        return STATUS_NOT_SUPPORTED;
    }

    *MaxKeys = query.Value;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256WifiWmmEnabled(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UINT32 wme = 0;

    if (!NT_SUCCESS(Ap6256BcdcGetIovar(Ctx, "wme", &wme, sizeof(wme)))) {
        return FALSE;
    }
    return (BOOLEAN)((wme & 0xFFu) != 0);
}

static NTSTATUS Ap6256DecodeMacCounters(_In_reads_bytes_(ReplyLength) const UCHAR* Reply,
    _In_ ULONG ReplyLength, _Out_writes_(AP6256_MAC_COUNTER_DWORDS) PUINT32 Counters,
    _Out_ PULONG CounterCount)
{
    UINT16 version, length;
    ULONG end, offset, found = 0, count = 0;
    RtlZeroMemory(Counters, AP6256_MAC_COUNTER_DWORDS * sizeof(UINT32));
    *CounterCount = 0;
    if (ReplyLength < 4) return STATUS_DEVICE_PROTOCOL_ERROR;
    version = (UINT16)(Reply[0] | ((UINT16)Reply[1] << 8));
    length = (UINT16)(Reply[2] | ((UINT16)Reply[3] << 8));

    if (version == AP6256_COUNTERS_LEGACY_VERSION) {

        if (length < 676 || length > ReplyLength || (length & 3) != 0)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        RtlCopyMemory(Counters, Reply + 4, 48 * sizeof(UINT32));
        RtlCopyMemory(Counters + 48, Reply + 424, 57 * sizeof(UINT32));
        RtlCopyMemory(Counters + 105, Reply + 660, sizeof(UINT32));
        count = min(AP6256_MAC_COUNTER_DWORDS - 106, ((ULONG)length - 672) / 4);
        RtlCopyMemory(Counters + 106, Reply + 672, count * sizeof(UINT32));
        *CounterCount = 106 + count;
        return STATUS_SUCCESS;
    }
    if (version != AP6256_COUNTERS_XTLV_VERSION) return STATUS_NOT_SUPPORTED;
    if (length > ReplyLength - 4) return STATUS_DEVICE_PROTOCOL_ERROR;
    end = 4 + (ULONG)length;
    offset = 4;
    while (offset < end) {
        UINT16 id, size;
        ULONG step;

        if (offset + 4 > ReplyLength || end - offset < 4)
            return STATUS_DEVICE_PROTOCOL_ERROR;
        id = (UINT16)(Reply[offset] | ((UINT16)Reply[offset + 1] << 8));
        size = (UINT16)(Reply[offset + 2] | ((UINT16)Reply[offset + 3] << 8));
        step = ((ULONG)size + 7) & ~3u;
        if (step > end - offset) return STATUS_DEVICE_PROTOCOL_ERROR;
        if (id == AP6256_COUNTERS_MACSTAT_ID) {
            if (found != 0 || size == 0 || (size & 3) != 0)
                return STATUS_DEVICE_PROTOCOL_ERROR;
            found = offset + 4;
            count = min((ULONG)size / 4, AP6256_MAC_COUNTER_DWORDS);
        }
        offset += step;
    }
    if (found == 0) return STATUS_NOT_FOUND;
    RtlCopyMemory(Counters, Reply + found, count * sizeof(UINT32));
    *CounterCount = count;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetMacCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Out_writes_(AP6256_MAC_COUNTER_DWORDS)
                                     PUINT32 Counters,
                                 _Out_ PULONG CounterCount)
{
    UCHAR* reply;
    ULONG replySize = 0x3F8u;
    AP6256_BCDC_QUERY_RESULT result = {0};
    NTSTATUS status;

    RtlZeroMemory(Counters, AP6256_MAC_COUNTER_DWORDS * sizeof(UINT32));
    *CounterCount = 0;

    reply = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, replySize,
                                    AP6256_POOL_TAG);
    if (reply == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    RtlZeroMemory(reply, replySize);
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "counters", reply, replySize, &result);
    if (NT_SUCCESS(status)) {
        status = result.FirmwareReply && !result.FirmwareError
            ? Ap6256DecodeMacCounters(reply, min(replySize, result.PayloadLength),
                Counters, CounterCount)
            : STATUS_DEVICE_PROTOCOL_ERROR;
    }

    if (NT_SUCCESS(status) && *CounterCount > 106) {
        ULONGLONG now = KeQueryInterruptTime();
        if (Ctx->MacCountersTracedAt == 0 ||
            now - Ctx->MacCountersTracedAt >= 50000000u) {
            Ctx->MacCountersTracedAt = now;
            TraceDiag("MAC counters v%u: rxctl %u badcm %u badproto %u "
                "rxundec %u ccmpformat %u ccmpreplay %u ccmpundec %u "
                "decsuccess %u txctl %u\n",
                (ULONG)(reply[0] | ((UINT16)reply[1] << 8)), Counters[18],
                Counters[22], Counters[27], Counters[61], Counters[65],
                Counters[66], Counters[67], Counters[71], Counters[4]);
        }
    }
    ExFreePoolWithTag(reply, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetIfCounters(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _Out_writes_bytes_(AP6256_IF_COUNTER_BYTES)
                                     PUCHAR Counters)
{
    return Ap6256WifiGetIfCountersIf(Ctx, 0, Counters);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetIfCountersIf(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
                                  _Out_writes_bytes_(AP6256_IF_COUNTER_BYTES) PUCHAR Counters)
{
    NTSTATUS status;
    UINT16 length;

    RtlZeroMemory(Counters, AP6256_IF_COUNTER_BYTES);
    status = Ap6256BcdcGetIovarIf(Ctx, IfIndex, "if_counters", Counters,
                                AP6256_IF_COUNTER_BYTES);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    length = (UINT16)(Counters[2] | ((UINT16)Counters[3] << 8));
    if (length < AP6256_IF_COUNTER_MIN_BYTES) {
        return STATUS_NOT_SUPPORTED;
    }
    return STATUS_SUCCESS;
}

#pragma pack(push, 1)

typedef struct _BRCMF_ARP_HOSTIP_ID {
    UCHAR  HostIpv4[4];
    UCHAR  Slot;
} BRCMF_ARP_HOSTIP_ID;

typedef struct _BRCMF_ND_PARAM {
    UCHAR  TargetIpv6A[16];
    UCHAR  TargetIpv6B[16];
    UCHAR  SolicitedNodeIpv6[16];
    UCHAR  RemoteIpv6[16];
    UCHAR  MacAddress[6];
    UINT32 OffloadId;
} BRCMF_ND_PARAM;

typedef struct _BRCMF_GTK_KEY_INFO {
    UCHAR Kck[16];
    UCHAR Kek[16];
    UCHAR ReplayCounter[8];
} BRCMF_GTK_KEY_INFO;

#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_ARP_HOSTIP_ID) == 5);
C_ASSERT(sizeof(BRCMF_ND_PARAM) == 74);
C_ASSERT(sizeof(BRCMF_GTK_KEY_INFO) == 40);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddArpOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_ARP_OFFLOAD* Offload,
                                 _In_ ULONG Slot)
{
    BRCMF_ARP_HOSTIP_ID hostIp;
    UINT32 value;
    UINT32 slotId = (UINT32)Slot;
    NTSTATUS status;
    NTSTATUS cleanupStatus;
    BOOLEAN hostIpAttempted = FALSE;
    PCSTR failedStep = "arpoe";
    if (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0)) return STATUS_NOT_SUPPORTED;

    if (Slot >= AP6256_ARP_OFFLOAD_SLOTS) return STATUS_INVALID_PARAMETER;

    value = 1;
    status = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (!NT_SUCCESS(status)) goto fail;
    value = BRCMF_ARP_OL_AGENT | BRCMF_ARP_OL_SNOOP;
    failedStep = "arp_ol";
    status = Ap6256BcdcSetIovar(Ctx, "arp_ol", &value, sizeof(value));
    if (!NT_SUCCESS(status)) goto fail;
    value = 1;
    failedStep = "arp_peerage";
    status = Ap6256BcdcSetIovar(Ctx, "arp_peerage", &value, sizeof(value));
    if (!NT_SUCCESS(status)) goto fail;

    RtlZeroMemory(&hostIp, sizeof(hostIp));
    RtlCopyMemory(hostIp.HostIpv4, Offload->HostIpv4, 4);
    hostIp.Slot = (UCHAR)Slot;
    failedStep = "arp_hostip_id";

    hostIpAttempted = TRUE;
    status = Ap6256BcdcSetIovar(Ctx, "arp_hostip_id", &hostIp, sizeof(hostIp));
    if (!NT_SUCCESS(status)) goto fail;

    failedStep = "arp_remoteip";
    status = Ap6256BcdcSetIovar(Ctx, "arp_remoteip", Offload->RemoteIpv4, 4);
    if (!NT_SUCCESS(status)) goto fail;
    failedStep = "arp_macaddr";
    status = Ap6256BcdcSetIovar(Ctx, "arp_macaddr", Offload->MacAddress, 6);
    if (!NT_SUCCESS(status)) goto fail;

    value = 0;
    failedStep = "arpoe disable";
    status = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (!NT_SUCCESS(status)) goto fail;

    TraceInfo(TRACE_NETADAPTER,
              "ARP offload %u in slot %u: host %u.%u.%u.%u, remote "
              "%u.%u.%u.%u, %02X:%02X:%02X:%02X:%02X:%02X\n",
              Offload->OffloadId, Slot,
              Offload->HostIpv4[0], Offload->HostIpv4[1],
              Offload->HostIpv4[2], Offload->HostIpv4[3],
              Offload->RemoteIpv4[0], Offload->RemoteIpv4[1],
              Offload->RemoteIpv4[2], Offload->RemoteIpv4[3],
              Offload->MacAddress[0], Offload->MacAddress[1],
              Offload->MacAddress[2], Offload->MacAddress[3],
              Offload->MacAddress[4], Offload->MacAddress[5]);
    return STATUS_SUCCESS;

fail:
    TraceWarn(TRACE_NETADAPTER, "ARP offload slot %u: %s failed 0x%08X\n",
              Slot, failedStep, status);
    if (hostIpAttempted) {
        cleanupStatus = Ap6256BcdcSetIovar(
            Ctx, "arp_hostip_clear_id", &slotId, sizeof(slotId));
        if (!NT_SUCCESS(cleanupStatus)) {
            Ctx->FirmwareArpOffloadSupported = FALSE;
            TraceError(TRACE_NETADAPTER,
                       "ARP offload slot %u rollback failed 0x%08X\n",
                       Slot, cleanupStatus);
        }
    }
    value = 0;
    cleanupStatus = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (!NT_SUCCESS(cleanupStatus)) {
        Ctx->FirmwareArpOffloadSupported = FALSE;
        TraceError(TRACE_NETADAPTER,
                   "ARP offload disable after failure returned 0x%08X\n",
                   cleanupStatus);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveArpOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                    _In_ ULONG Slot)
{
    UINT32 value = 1;
    UINT32 slot = (UINT32)Slot;
    NTSTATUS status;
    NTSTATUS firstFailure = STATUS_SUCCESS;

    if (Slot >= AP6256_ARP_OFFLOAD_SLOTS) return STATUS_INVALID_PARAMETER;

    status = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (!NT_SUCCESS(status)) firstFailure = status;
    status = Ap6256BcdcSetIovar(Ctx, "arp_table_clear", NULL, 0);
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    status = Ap6256BcdcSetIovar(Ctx, "arp_hostip_clear_id", &slot, sizeof(slot));
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;
    status = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (!NT_SUCCESS(status) && NT_SUCCESS(firstFailure)) firstFailure = status;

    if (NT_SUCCESS(firstFailure))
        TraceInfo(TRACE_NETADAPTER, "ARP offload slot %u cleared\n", Slot);
    else
        TraceWarn(TRACE_NETADAPTER,
                  "ARP offload slot %u removal incomplete 0x%08X\n",
                  Slot, firstFailure);
    return firstFailure;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddNsOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ const AP6256_NS_OFFLOAD* Offload)
{
    BRCMF_ND_PARAM param;
    NTSTATUS status;
    if (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0)) return STATUS_NOT_SUPPORTED;

    RtlZeroMemory(&param, sizeof(param));
    RtlCopyMemory(param.TargetIpv6A, Offload->TargetIpv6A, 16);
    RtlCopyMemory(param.TargetIpv6B, Offload->TargetIpv6B, 16);
    RtlCopyMemory(param.SolicitedNodeIpv6, Offload->SolicitedNodeIpv6, 16);
    RtlCopyMemory(param.RemoteIpv6, Offload->RemoteIpv6, 16);
    RtlCopyMemory(param.MacAddress, Offload->MacAddress, 6);
    param.OffloadId = Offload->OffloadId;

    status = Ap6256BcdcSetIovar(Ctx, Ctx->FirmwareWowlAdapter ? "wdi_nd_set" : "nd_set_param", &param, sizeof(param));
    TraceInfo(TRACE_NETADAPTER, "IPv6 NS offload %u -> 0x%08X\n",
              Offload->OffloadId, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveNsOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ UINT32 OffloadId)
{
    UINT32 id = OffloadId;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, Ctx->FirmwareWowlAdapter ? "wdi_nd_clear" : "nd_clear_param", &id,
                                         sizeof(id));

    TraceInfo(TRACE_NETADAPTER, "IPv6 NS offload %u cleared -> 0x%08X\n",
              OffloadId, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiAddGtkOffload(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_GTK_OFFLOAD* Offload)
{
    UCHAR wire[56];
    ULONG i;
    NTSTATUS status;
    if (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0)) return STATUS_NOT_SUPPORTED;
    if (!Ctx->FirmwareGtkOffloadSupported) return STATUS_NOT_SUPPORTED;
    RtlZeroMemory(wire, sizeof(wire));
    RtlCopyMemory(wire, Offload->Kck, 16);
    RtlCopyMemory(wire + 16, Offload->Kek, 16);
    for (i = 0; i < 8; ++i) wire[32 + i] = (UCHAR)(Offload->ReplayCounter >> (56 - i * 8));
    RtlCopyMemory(wire + 40, &Offload->DescriptorVersion, 4);
    RtlCopyMemory(wire + 44, &Offload->MicKind, 4);
    RtlCopyMemory(wire + 48, &Offload->Pmf, 4);
    RtlCopyMemory(wire + 52, &Offload->OffloadId, 4);
    status = Ap6256BcdcSetIovar(Ctx, "wdi_gtk_config", wire, sizeof(wire));
    RtlSecureZeroMemory(wire, sizeof(wire));
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiEnableProtocolOffloads(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                          _In_ BOOLEAN Arp,
                                          _In_ BOOLEAN NeighborDiscovery)
{
    UINT32 value = 1;
    NTSTATUS status;
    if ((Arp || NeighborDiscovery) &&
        (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0))) return STATUS_NOT_SUPPORTED;

    if ((Arp && !Ctx->FirmwareArpOffloadSupported) ||
        (NeighborDiscovery && !Ctx->FirmwareNdOffloadSupported))
        return STATUS_NOT_SUPPORTED;
    if (Arp) {
        status = Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
        if (!NT_SUCCESS(status)) goto fail;
    }
    if (NeighborDiscovery) {
        status = Ap6256BcdcSetIovar(Ctx, "ndoe", &value, sizeof(value));
        if (!NT_SUCCESS(status)) goto fail;
    }
    TraceInfo(TRACE_NETADAPTER, "protocol offloads enabled: arp %u, nd %u\n",
              (ULONG)Arp, (ULONG)NeighborDiscovery);
    return STATUS_SUCCESS;

fail:
    TraceError(TRACE_NETADAPTER, "protocol offload enable failed 0x%08X\n", status);
    value = 0;
    if (Arp)
        (VOID)Ap6256BcdcSetIovar(Ctx, "arpoe", &value, sizeof(value));
    if (NeighborDiscovery)
        (VOID)Ap6256BcdcSetIovar(Ctx, "ndoe", &value, sizeof(value));
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterMaxDelay(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ UINT32 DelayMs)
{
    UINT32 value = DelayMs;
    NTSTATUS status = Ap6256BcdcSetIovar(Ctx, "d0_filter_max_delay", &value,
                                         sizeof(value));

    TraceInfo(TRACE_NETADAPTER, "d0_filter_max_delay %u ms -> 0x%08X\n",
              DelayMs, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterArp(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ BOOLEAN Add,
                                  _In_reads_(4) const UCHAR* Ipv4Address)
{
    NTSTATUS status;

    status = Ap6256BcdcSetIovar(Ctx,
                                Add ? "d0_filter_arp" : "d0_filter_arp_clear",
                                Ipv4Address, 4u);
    if (NT_SUCCESS(status) && Add) {
        UINT32 enable = 1;
        status = Ap6256BcdcSetIovar(Ctx, "d0_filter_enable", &enable,
                                    sizeof(enable));
    }

    TraceInfo(TRACE_NETADAPTER, "d0 ARP filter %s %u.%u.%u.%u -> 0x%08X\n",
              Add ? "add" : "clear", Ipv4Address[0], Ipv4Address[1],
              Ipv4Address[2], Ipv4Address[3], status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetD0FilterProtocol(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ BOOLEAN Add,
                                       _In_ UINT32 Mask)
{
    UINT32 value = Mask;
    NTSTATUS status;

    status = Ap6256BcdcSetIovar(Ctx,
                                Add ? "d0_filter_ipv4" : "d0_filter_ipv4_clear",
                                &value, sizeof(value));
    if (NT_SUCCESS(status) && Add) {
        UINT32 enable = 1;
        status = Ap6256BcdcSetIovar(Ctx, "d0_filter_enable", &enable,
                                    sizeof(enable));
    }

    TraceInfo(TRACE_NETADAPTER, "d0 protocol filter %s mask 0x%04X -> 0x%08X\n",
              Add ? "add" : "clear", Mask, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT32 Ap6256WifiD0FilterMaskForPort(_In_ UINT32 Port, _In_ BOOLEAN Ipv6)
{
    if (Ipv6) {
        switch (Port) {
        case AP6256_UDP_PORT_SSDP:  return AP6256_D0_FILTER_SSDP_V6;
        case AP6256_UDP_PORT_WSD:   return AP6256_D0_FILTER_WSD_V6;
        case AP6256_UDP_PORT_LLMNR: return AP6256_D0_FILTER_LLMNR_V6;
        default: return 0;
        }
    }
    switch (Port) {
    case AP6256_UDP_PORT_NETBIOS_NS: return AP6256_D0_FILTER_NETBIOS_NS;
    case AP6256_UDP_PORT_SSDP:       return AP6256_D0_FILTER_SSDP;
    case AP6256_UDP_PORT_WSD:        return AP6256_D0_FILTER_WSD;
    case AP6256_UDP_PORT_LLMNR:      return AP6256_D0_FILTER_LLMNR;
    default: return 0;
    }
}

static UINT16 Ap6256P2pChanspec(_In_ UINT32 Channel)
{
    UINT16 channel = (UINT16)(Channel & 0xFFu);
    UINT16 chanspec = (UINT16)(BRCMU_CHSPEC_D11AC_BW_20 | channel);

    if (channel > 14u) chanspec |= BRCMU_CHSPEC_D11AC_BAND_5G;
    return chanspec;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetVendorIes(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                _In_ UINT32 PktFlag,
                                _In_ BOOLEAN Add,
                                _In_reads_bytes_(IesLength) const UCHAR* Ies,
                                _In_ ULONG IesLength)
{
    return Ap6256WifiSetVendorIesIf(Ctx, Ap6256WifiP2pInterface(Ctx), PktFlag, Add, Ies, IesLength);
}

static NTSTATUS Ap6256WifiSetVendorIesForContext(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 PktFlag, BOOLEAN Add, const UCHAR* Ies, ULONG IesLength, BOOLEAN Station);

_Use_decl_annotations_
NTSTATUS Ap6256WifiSetVendorIesIf(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 PktFlag, BOOLEAN Add, const UCHAR* Ies, ULONG IesLength)
{
    return Ap6256WifiSetVendorIesForContext(Ctx, IfIndex, PktFlag, Add, Ies, IesLength, FALSE);
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiSetStationVendorIes(PAP6256_DEVICE_CONTEXT Ctx,
    UINT32 PktFlag, BOOLEAN Add, const UCHAR* Ies, ULONG IesLength)
{
    return Ap6256WifiSetVendorIesForContext(Ctx, 0, PktFlag, Add, Ies, IesLength, TRUE);
}

_Use_decl_annotations_
NTSTATUS Ap6256WifiQualifyMbo(PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_MBO_PREFERENCES preferences={0};
    UCHAR ie[AP6256_MBO_IE_MAX];ULONG length=0;NTSTATUS status,cleanup;
    Ctx->FirmwareMboTransport=FALSE;
    if(!Ctx->FirmwareNativeManagement || !Ctx->FirmwareBssTransitionEnabled ||
        !Ctx->FirmwareMfpSupported) return STATUS_SUCCESS;
    status=Ap6256MboSetPreferences(&preferences,3,NULL,0);
    if(NT_SUCCESS(status)) status=Ap6256MboBuildIe(&preferences,ie,sizeof(ie),&length);
    if(!NT_SUCCESS(status)) return status;
    status=Ap6256WifiSetStationVendorIes(Ctx,AP6256_P2P_IE_PROBE_REQ,TRUE,ie,length);

    cleanup=Ap6256WifiSetStationVendorIes(Ctx,AP6256_P2P_IE_PROBE_REQ,FALSE,ie,length);
    if(!NT_SUCCESS(status)) return status;
    if(!NT_SUCCESS(cleanup)) return cleanup;
    Ctx->FirmwareMboTransport=TRUE;
    TraceDiag("MBO: native station vendor-IE add/delete and retained WNM/MFP qualified\n");
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256WifiSetVendorIesForContext(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    UINT32 PktFlag, BOOLEAN Add, const UCHAR* Ies, ULONG IesLength, BOOLEAN Station)
{
    BRCMF_VNDR_IE_BUF* buffer;
    ULONG total = (ULONG)sizeof(BRCMF_VNDR_IE_BUF);
    ULONG count = 0;
    ULONG offset;
    UCHAR* out;
    NTSTATUS status;

    if (!Ies || IesLength > AP6256_SCAN_IE_MAX) return STATUS_INVALID_PARAMETER;
    for (offset = 0; offset + 2u <= IesLength; ) {
        ULONG length = (ULONG)Ies[offset + 1] + 2u;
        if (length > IesLength - offset) return STATUS_INVALID_PARAMETER;
        count++;
        total += length + (ULONG)sizeof(UINT32);
        offset += length;
    }
    if (count == 0 || offset != IesLength || total < sizeof(BRCMF_VNDR_IE_BUF) ||
        total > sizeof(BRCMF_VNDR_IE_BUF) + 3u * AP6256_SCAN_IE_MAX)
        return STATUS_INVALID_PARAMETER;

    buffer = (BRCMF_VNDR_IE_BUF*)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
                                                 AP6256_POOL_TAG);
    if (buffer == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    RtlCopyMemory(buffer->Command, Add ? "add" : "del", 3);
    buffer->Count = count;

    out = (UCHAR*)(buffer + 1);
    for (offset = 0; offset + 2u <= IesLength; ) {
        ULONG length = (ULONG)Ies[offset + 1] + 2u;
        if (length > IesLength - offset) break;
        RtlCopyMemory(out, &PktFlag, sizeof(PktFlag));
        RtlCopyMemory(out + sizeof(PktFlag), Ies + offset, length);
        out += sizeof(PktFlag) + length;
        offset += length;
    }

    if (Station) {
        status = Ap6256BcdcSetIovar(Ctx, "vndr_ie", buffer, total);
    } else if (Ctx->Go.FirmwareReady && IfIndex == Ctx->Go.IfIndex) {
        status = Ap6256GoSetBsscfg(Ctx, "vndr_ie", buffer, total);
    } else if (Ctx->P2pBssValid && IfIndex == Ap6256WifiP2pInterface(Ctx)) {
        SIZE_T dataSize = (SIZE_T)total + sizeof(UINT32);
        if (dataSize < sizeof(UINT32) || dataSize > 3u * AP6256_SCAN_IE_MAX + 12u) {
            ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
            return STATUS_INVALID_PARAMETER;
        }

        PUCHAR data = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            3u * AP6256_SCAN_IE_MAX + 12u, AP6256_POOL_TAG);
        if (data == NULL) status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            RtlCopyMemory(data, &Ctx->P2pBssIndex, sizeof(UINT32));
            RtlCopyMemory(data + sizeof(UINT32), buffer, total);
            status = Ap6256BcdcSetIovarIf(Ctx, IfIndex, "bsscfg:vndr_ie", data, (ULONG)dataSize);
            ExFreePoolWithTag(data, AP6256_POOL_TAG);
        }
    } else status = STATUS_DEVICE_NOT_READY;
    TraceInfo(TRACE_NETADAPTER,
              "vndr_ie %s mask 0x%03X: %u element(s), %u byte(s) -> 0x%08X\n",
              Add ? "add" : "del", PktFlag, count, IesLength, status);

    ExFreePoolWithTag(buffer, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiSetP2pDiscoveryState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                        _In_ UINT32 State,
                                        _In_ UINT32 Channel,
                                        _In_ UINT32 DwellMs)
{
    BRCMF_P2P_DISC_BSSCFG request;
    NTSTATUS status;

    if (!Ctx->P2pBssValid) return STATUS_DEVICE_NOT_READY;

    RtlZeroMemory(&request, sizeof(request));
    request.BssIndex = Ctx->P2pBssIndex;
    request.State.State = (UCHAR)State;
    request.State.Chanspec = Channel != 0 ? Ap6256P2pChanspec(Channel) : 0;
    request.State.DwellMs = (UINT16)DwellMs;
    status = Ap6256BcdcSetIovarIf(Ctx, Ap6256WifiP2pInterface(Ctx),
        "bsscfg:p2p_state", &request, sizeof(request));
    TraceVerbose(TRACE_NETADAPTER,
                 "p2p_state %u channel %u (chanspec 0x%04X) dwell %u ms "
                 "-> 0x%08X\n",
                 State, Channel, request.State.Chanspec, DwellMs, status);
    return status;
}

#define BRCMF_P2P_SCAN_TYPE_ESCAN    'E'

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiP2pScan(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ const AP6256_P2P_SCAN* Scan)
{
    BRCMF_P2P_SCAN_PARAMS* params;
    ULONG total;
    ULONG i;
    NTSTATUS status;

    if (!Ctx->P2pBssValid || Ctx->P2pBssIndex == 0) return STATUS_DEVICE_NOT_READY;
    if (Scan->SsidLength > sizeof(Scan->Ssid) ||
        Scan->ChannelCount > AP6256_P2P_SCAN_CHANNEL_MAX) {
        return STATUS_INVALID_PARAMETER;
    }

    total = (ULONG)FIELD_OFFSET(BRCMF_P2P_SCAN_PARAMS,
                                Escan.Params.ChannelList) +
            (Scan->ChannelCount != 0 ? Scan->ChannelCount * sizeof(UINT16)
                                     : sizeof(UINT16));
    params = (BRCMF_P2P_SCAN_PARAMS*)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                                     total, AP6256_POOL_TAG);
    if (params == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    params->Type = BRCMF_P2P_SCAN_TYPE_ESCAN;
    params->Escan.Version = BRCMF_ESCAN_REQ_VERSION;
    params->Escan.Action = WL_ESCAN_ACTION_START;
    params->Escan.SyncId = (UINT16)InterlockedIncrement(&Ctx->ScanSyncId);
    if (params->Escan.SyncId == 0)
        params->Escan.SyncId = (UINT16)InterlockedIncrement(&Ctx->ScanSyncId);

    params->Escan.Params.Ssid.SsidLen = Scan->SsidLength;
    RtlCopyMemory(params->Escan.Params.Ssid.Ssid, Scan->Ssid,
                  min(Scan->SsidLength,
                      sizeof(params->Escan.Params.Ssid.Ssid)));
    RtlFillMemory(params->Escan.Params.Bssid,
                  sizeof(params->Escan.Params.Bssid), 0xFF);
    params->Escan.Params.BssType = DOT11_BSSTYPE_ANY;
    params->Escan.Params.ScanType = Scan->Passive ? BRCMF_SCANTYPE_PASSIVE
                                                  : BRCMF_SCANTYPE_ACTIVE;
    params->Escan.Params.NProbes = Scan->NProbes;
    params->Escan.Params.ActiveTime = Scan->ActiveTimeMs;
    params->Escan.Params.PassiveTime = Scan->PassiveTimeMs;
    params->Escan.Params.HomeTime = -1;
    params->Escan.Params.ChannelNum = (INT32)Scan->ChannelCount;

    for (i = 0; i < Scan->ChannelCount; i++) {
        UINT16 chanspec = Ap6256P2pChanspec(Scan->Channels[i]);
        params->Escan.Params.ChannelList[i] = chanspec;
    }

    {
        PUCHAR request = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            sizeof(UINT32) + total, AP6256_POOL_TAG);
        if (request == NULL) status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            RtlCopyMemory(request, &Ctx->P2pBssIndex, sizeof(UINT32));
            RtlCopyMemory(request + sizeof(UINT32), params, total);
            status = Ap6256BcdcSetIovarIf(Ctx, Ap6256WifiP2pInterface(Ctx),
                "bsscfg:p2p_scan", request, sizeof(UINT32) + total);
            ExFreePoolWithTag(request, AP6256_POOL_TAG);
        }
    }
    TraceDiag("p2p_scan: sync %u bsscfg %u, %u channel(s) first %u, %s, "
              "dwell %ld ms, SSID %u byte(s) -> 0x%08X\n",
              params->Escan.SyncId, Ctx->P2pBssIndex, Scan->ChannelCount,
              Scan->ChannelCount != 0 ? (ULONG)Scan->Channels[0] : 0,
              Scan->Passive ? "passive" : "active",
              Scan->Passive ? Scan->PassiveTimeMs : Scan->ActiveTimeMs,
              Scan->SsidLength, status);

    ExFreePoolWithTag(params, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiGetRssi(_In_ PAP6256_DEVICE_CONTEXT Ctx, _Out_ PINT32 Rssi)
{
    INT32 v = 0;
    NTSTATUS status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_RSSI, &v, sizeof(v));
    *Rssi = NT_SUCCESS(status) ? v : 0;
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveGtkOffload(PAP6256_DEVICE_CONTEXT Ctx)
{
    UCHAR wire[56] = {0};
    if (!Ctx->FirmwareWowlAdapter) return STATUS_NOT_SUPPORTED;
    return Ap6256BcdcSetIovar(Ctx, "wdi_gtk_config", wire, sizeof(wire));
}
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadGtkOffload(PAP6256_DEVICE_CONTEXT Ctx, AP6256_GTK_STATE* State)
{
    AP6256_BCDC_QUERY_RESULT result;
    NTSTATUS status;
    RtlZeroMemory(State, sizeof(*State));
    if (!Ctx->FirmwareGtkOffloadSupported) return STATUS_NOT_SUPPORTED;
    status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "wdi_gtk_state", State, sizeof(*State), &result);
    if (NT_SUCCESS(status) && (result.PayloadLength != sizeof(*State) ||
        State->Abi != AP6256_WOWL_ABI || State->GtkId > 3 || State->GtkValid > 1 ||
        State->IgtkValid > 1 || (State->IgtkValid && (State->IgtkId < 4 || State->IgtkId > 5))))
        status = STATUS_DATA_ERROR;
    if (NT_SUCCESS(status)) {
        ULONG slot;
        for (slot = 0; slot < RTL_NUMBER_OF(State->Keys); ++slot)
            if (State->Keys[slot].Valid > 1 ||
                (State->Keys[slot].Valid && State->Keys[slot].Id != slot)) status = STATUS_DATA_ERROR;
    }
    if (!NT_SUCCESS(status)) RtlSecureZeroMemory(State, sizeof(*State));
    return status;
}
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiSeedGroupKey(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Id,
    BOOLEAN Management, BOOLEAN Valid, const UCHAR* Key, const UCHAR* Rsc)
{
    UCHAR wire[36] = {0};
    UINT32 management = Management, valid = Valid;
    NTSTATUS status;
    if (Valid && (Ap6256FipsActive(Ctx, 0) || Ap6256HostCipherPacketActive(Ctx, 0))) return;
    if (!Ctx->FirmwareWowlAdapter || (Management ? (Id < 4 || Id > 5) : Id > 3)) return;
    RtlCopyMemory(wire, &Id, 4);
    RtlCopyMemory(wire + 4, &management, 4);
    RtlCopyMemory(wire + 8, &valid, 4);
    if (Valid) {
        RtlCopyMemory(wire + 12, Key, 16);
        if (Rsc) RtlCopyMemory(wire + 28, Rsc, 6);
    }
    status = Ap6256BcdcSetIovar(Ctx, "wdi_gtk_key", wire, sizeof(wire));
    RtlSecureZeroMemory(wire, sizeof(wire));
    if (!NT_SUCCESS(status)) {
        Ctx->FirmwareGtkOffloadSupported = FALSE;
        TraceError(TRACE_NETADAPTER, "group key seed failed 0x%08X; rekey offload withdrawn\n", status);
    }
}
