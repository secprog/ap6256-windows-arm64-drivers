/*
 * SPDX-License-Identifier: GPL-3.0-only AND ISC
 * Project-authored portions are licensed under the GNU General Public License,
 * version 3 only. Provided without warranty. See LICENSE for the GPL text.
 *
 * Firmware command definitions are derived from
 * drivers/net/wireless/broadcom/brcm80211/brcmfmac/fwil.h in Linux:
 * https://github.com/torvalds/linux
 * Upstream commit: 24a19b953e2a3d0ea5a8c4951a0ab8f32720c907
 * Copyright (c) 2012 Broadcom Corporation
 *
 * The following ISC notice applies to those Linux-derived definitions only.
 * See LICENSE-ISC.txt and NOTICE.txt for the license text and provenance.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <ntddk.h>

#pragma pack(push, 1)

typedef struct _SDPCM_HW_HEADER {
    UINT16 FrameLength;
    UINT16 FrameLengthInverted;
} SDPCM_HW_HEADER, *PSDPCM_HW_HEADER;

typedef struct _SDPCM_SW_HEADER {
    UINT8  Sequence;
    UINT8  ChannelAndFlags;
    UINT8  NextLength;
    UINT8  DataOffset;
    UINT8  FlowControl;
    UINT8  BusDataCredit;
    UINT8  Reserved[2];
} SDPCM_SW_HEADER, *PSDPCM_SW_HEADER;

#define SDPCM_HWHDR_LEN             4
#define SDPCM_SWHDR_LEN             8
#define SDPCM_HDRLEN               (SDPCM_HWHDR_LEN + SDPCM_SWHDR_LEN)

typedef struct _SDPCM_HW_EXT {
    UINT32 LengthAndLast;
    UINT32 TailPad;
} SDPCM_HW_EXT, *PSDPCM_HW_EXT;

#define SDPCM_HWEXT_LEN             8
#define SDPCM_HWEXT_LASTFRM         (1u << 24)
#define SDPCM_HWEXT_TAILPAD_SHIFT   16
#define SDPCM_GLOM_HDRLEN          (SDPCM_HWHDR_LEN + SDPCM_HWEXT_LEN + SDPCM_SWHDR_LEN)

#define SDPCM_CONTROL_CHANNEL      0
#define SDPCM_EVENT_CHANNEL        1
#define SDPCM_DATA_CHANNEL         2
#define SDPCM_GLOM_CHANNEL         3
#define SDPCM_TEST_CHANNEL         15

#define SDPCM_CHANNEL_MASK         0x0f
#define SDPCM_SEQ_WRAP             256

#define SDPCM_PROT_VERSION         4
#define SDPCM_SHARED_VERSION       3
#define SDPCM_SHARED_VERSION_MASK  0x000000ffu
#define SDPCM_SHARED_ASSERT_BUILT  0x00000100u
#define SDPCM_SHARED_ASSERT        0x00000200u
#define SDPCM_SHARED_TRAP          0x00000400u

typedef struct _SDPCM_SHARED {
    UINT32 Flags;
    UINT32 TrapAddress;
    UINT32 AssertExpressionAddress;
    UINT32 AssertFileAddress;
    UINT32 AssertLine;
    UINT32 ConsoleAddress;
    UINT32 MessageTraceAddress;
    UINT8  Tag[32];
    UINT32 BreakpointAddress;
} SDPCM_SHARED, *PSDPCM_SHARED;

C_ASSERT(sizeof(SDPCM_SHARED) == 64);

#define BCDC_DCMD_PROTO_VERSION    2

typedef struct _BCDC_DCMD_HEADER {
    UINT32 Cmd;
    UINT32 Len;
    UINT32 Flags;
    UINT32 Status;
} BCDC_DCMD_HEADER, *PBCDC_DCMD_HEADER;

#define BCDC_DCMD_ERROR            0x00000001
#define BCDC_DCMD_SET              0x00000002
#define BCDC_DCMD_IF_MASK          0x0000F000
#define BCDC_DCMD_IF_SHIFT         12
#define BCDC_DCMD_ID_MASK          0xFFFF0000
#define BCDC_DCMD_ID_SHIFT         16

#define BCDC_DCMD_ID(flags)        (((flags) & BCDC_DCMD_ID_MASK) >> BCDC_DCMD_ID_SHIFT)

typedef struct _BCDC_DATA_HEADER {
    UINT8 Flags;
    UINT8 Priority;
    UINT8 Flags2;
    UINT8 DataOffset;
} BCDC_DATA_HEADER, *PBCDC_DATA_HEADER;

#define BCDC_DATA_FLAG_PROTO_SHIFT 4

#define BCDC_DATA_EXEMPT_NONE       0u
#define BCDC_DATA_EXEMPT_ALWAYS     1u
#define BCDC_DATA_EXEMPT_ON_NO_KEY  2u

#pragma pack(pop)

#define BRCMF_C_GET_VERSION                     1
#define BRCMF_C_UP                              2
#define BRCMF_C_DOWN                            3
#define BRCMF_C_SET_PROMISC                     10
#define BRCMF_C_GET_RATE                        12

#define BRCMF_C_GET_MAX_RATE                    13
#define BRCMF_C_GET_INFRA                       19
#define BRCMF_C_SET_INFRA                       20
#define BRCMF_C_GET_AUTH                        21
#define BRCMF_C_SET_AUTH                        22
#define BRCMF_C_GET_BSSID                       23
#define BRCMF_C_GET_SSID                        25
#define BRCMF_C_SET_SSID                        26
#define BRCMF_C_TERMINATED                      28
#define BRCMF_C_GET_CHANNEL                     29
#define BRCMF_C_SET_CHANNEL                     30
#define BRCMF_C_GET_SRL                         31
#define BRCMF_C_SET_SRL                         32
#define BRCMF_C_GET_LRL                         33
#define BRCMF_C_SET_LRL                         34
#define BRCMF_C_GET_RADIO                       37
#define BRCMF_C_SET_RADIO                       38
#define BRCMF_C_GET_PHYTYPE                     39
#define BRCMF_C_SET_KEY                         45
#define BRCMF_C_GET_REGULATORY                  46
#define BRCMF_C_SET_REGULATORY                  47
#define BRCMF_C_SET_PASSIVE_SCAN                49
#define BRCMF_C_SCAN                            50
#define BRCMF_C_SCAN_RESULTS                    51
#define BRCMF_C_DISASSOC                        52
#define BRCMF_C_REASSOC                         53
#define BRCMF_C_GET_ROAM_TRIGGER                54
#define BRCMF_C_SET_ROAM_TRIGGER                55
#define BRCMF_C_SET_ROAM_DELTA                  57
#define BRCMF_C_GET_BCNPRD                      75
#define BRCMF_C_SET_BCNPRD                      76
#define BRCMF_C_GET_DTIMPRD                     77
#define BRCMF_C_SET_DTIMPRD                     78
#define BRCMF_C_SET_COUNTRY                     84
#define BRCMF_C_GET_PM                          85
#define BRCMF_C_SET_PM                          86
#define BRCMF_C_GET_REVINFO                     98
#define BRCMF_C_GET_MONITOR                     107
#define BRCMF_C_SET_MONITOR                     108
#define BRCMF_C_GET_CURR_RATESET                114
#define BRCMF_C_GET_AP                          117
#define BRCMF_C_SET_AP                          118

#define BRCMF_C_GET_WEP_RESTRICT                81
#define BRCMF_C_SET_WEP_RESTRICT                82
#define BRCMF_C_SCB_AUTHORIZE               121
#define BRCMF_C_SCB_DEAUTHORIZE             122
#define BRCMF_C_GET_RSSI                        127
#define BRCMF_C_GET_WSEC                        133
#define BRCMF_C_SET_WSEC                        134
#define BRCMF_C_GET_PHY_NOISE                   135
#define BRCMF_C_GET_BSS_INFO                    136
#define BRCMF_C_GET_PKTCNTS                     137
#define BRCMF_C_GET_BANDLIST                    140
#define BRCMF_C_GET_BAND                        141
#define BRCMF_C_SET_SCB_TIMEOUT                 158
#define BRCMF_C_GET_ASSOCLIST                   159
#define BRCMF_C_GET_WPA_AUTH                    164
#define BRCMF_C_SET_WPA_AUTH                    165
#define BRCMF_C_GET_PHYLIST                     180
#define BRCMF_C_SET_SCAN_CHANNEL_TIME           185
#define BRCMF_C_SET_SCAN_UNASSOC_TIME           187
#define BRCMF_C_SCB_DEAUTHENTICATE_FOR_REASON   201
#define BRCMF_C_SET_ASSOC_PREFER                205
#define BRCMF_C_GET_VALID_CHANNELS              217
#define BRCMF_C_SET_FAKEFRAG                    219
#define BRCMF_C_GET_KEY_PRIMARY                 235
#define BRCMF_C_SET_KEY_PRIMARY                 236
#define BRCMF_C_SET_SCAN_PASSIVE_TIME           258
#define BRCMF_C_GET_VAR                         262
#define BRCMF_C_SET_VAR                         263
#define BRCMF_C_SET_WSEC_PMK                    268

#define BCMILCP_BCM_SUBTYPE_EVENT   1
#define BCMILCP_SUBTYPE_VENDOR_LONG 0x8001
#define ETHER_TYPE_BRCM             0x886C

#pragma pack(push, 1)
typedef struct _BRCMF_EVENT_MSG {
    UINT16 Version;
    UINT16 Flags;
    UINT32 EventType;
    UINT32 Status;
    UINT32 Reason;
    UINT32 AuthType;
    UINT32 DataLen;
    UINT8  Address[6];
    UINT8  IfName[16];
    UINT8  IfIdx;
    UINT8  BssCfgIdx;
} BRCMF_EVENT_MSG, *PBRCMF_EVENT_MSG;
#pragma pack(pop)

#define BRCMF_E_SET_SSID            0
#define BRCMF_E_JOIN                1
#define BRCMF_E_AUTH                3
#define BRCMF_E_ASSOC               7
#define BRCMF_E_DEAUTH              5
#define BRCMF_E_DEAUTH_IND          6
#define BRCMF_E_REASSOC             9
#define BRCMF_E_DISASSOC            11
#define BRCMF_E_DISASSOC_IND        12
#define BRCMF_E_LINK                16
#define BRCMF_E_ROAM                19
#define BRCMF_E_START               2
#define BRCMF_E_AUTH_IND            4
#define BRCMF_E_MIC_ERROR           17
#define BRCMF_E_ICV_ERROR           49
#define BRCMF_E_UNICAST_DECODE_ERROR 50
#define BRCMF_E_MULTICAST_DECODE_ERROR 51
#define BRCMF_E_TXFAIL              20
#define BRCMF_E_PMKID_CACHE         21
#define BRCMF_E_PRUNE               23
#define BRCMF_E_EAPOL_MSG           25
#define BRCMF_E_SCAN_COMPLETE       26
#define BRCMF_E_JOIN_START          36
#define BRCMF_E_PRE_ASSOC_IND       61
#define BRCMF_E_PRE_REASSOC_IND     62
#define BRCMF_E_AP_STARTED          64
#define BRCMF_E_PFN_SCAN_ALLGONE    83
#define BRCMF_E_NATIVE              94
#define BRCMF_E_PFN_NET_FOUND       33
#define BRCMF_E_PFN_BEST_BATCHING   57
#define BRCMF_E_PFN_GSCAN_FULL_RESULT 134
#define BRCMF_E_PFN_SWC             135
#define BRCMF_E_PSK_SUP             46
#define BRCMF_E_RSSI                56
#define BRCMF_E_ESCAN_RESULT        69

#define BRCMF_E_NDIS_LINK           18
#define BRCMF_E_BCNLOST_MSG         31
#define BRCMF_E_RADIO               40
#define BRCMF_E_SCAN_CONFIRM_IND    45
#define BRCMF_E_PROBERESP_MSG       71
#define BRCMF_E_DFS_AP_STOP         65
#define BRCMF_E_DFS_AP_RESUME       66
#define BRCMF_E_CSA_COMPLETE_IND    80
#define BRCMF_E_ASSOC_IND_NDIS      85
#define BRCMF_E_REASSOC_IND_NDIS    86

#define BRCMF_EVENT_MSG_LINK        0x0001
#define BRCMF_EVENT_MSG_FLUSHTXQ    0x0002
#define BRCMF_EVENT_MSG_GROUP       0x0004

#pragma pack(push, 1)
typedef struct _BRCMF_RX_MGMT_DATA {
    UINT16 Version;
    UINT16 Chanspec;
    UINT32 Rssi;
    UINT32 MacTime;
    UINT32 Rate;
} BRCMF_RX_MGMT_DATA;
#pragma pack(pop)

C_ASSERT(sizeof(BRCMF_RX_MGMT_DATA) == 16);

#define BRCMF_DOT11_MGMT_HDR_LEN   24u
#define BRCMF_ACTION_FRAME_RX_MIN  (sizeof(BRCMF_RX_MGMT_DATA) + \
                                    BRCMF_DOT11_MGMT_HDR_LEN + 1u)

#define BRCMF_E_ASSOC_IND                         8
#define BRCMF_E_REASSOC_IND                      10
#define BRCMF_E_P2P_DISC_LISTEN_COMPLETE         55
#define BRCMF_E_ACTION_FRAME                     59
#define BRCMF_E_ACTION_FRAME_COMPLETE            60
#define BRCMF_E_ACTION_FRAME_OFF_CHAN_COMPLETE   70
#define BRCMF_E_P2P_PROBREQ_MSG                  72
#define BRCMF_E_ACTION_FRAME_RX                  75
#define BRCMF_E_RM_COMPLETE                      77
#define BRCMF_E_ACTION_FRAME_RX_NDIS             90
#define BRCMF_E_TDLS_PEER_EVENT                  92
#define BRCMF_E_FIFO_CREDIT_MAP                  74
#define BRCMF_E_BCMC_CREDIT_SUPPORT             127
#define BRCMF_E_RRM                             141
#define BRCMF_E_GAS_FRAGMENT_RX                 103
#define BRCMF_E_GAS_COMPLETE                    104
#define BRCMF_E_P2PO_ADD_DEVICE                 105
#define BRCMF_E_P2PO_DEL_DEVICE                 106
#define BRCMF_E_IF                  54

#pragma pack(push, 1)
typedef struct _BRCMF_IF_EVENT {
    UINT8 IfIndex;
    UINT8 Action;
    UINT8 Flags;
    UINT8 BssCfgIndex;
    UINT8 Role;
} BRCMF_IF_EVENT;
#pragma pack(pop)

#define BRCMF_E_IF_ADD              1
#define BRCMF_E_IF_DEL              2
#define BRCMF_E_IF_CHANGE           3

#define BRCMF_E_STATUS_SUCCESS      0
#define BRCMF_E_STATUS_FAIL         1
#define BRCMF_E_STATUS_TIMEOUT      2
#define BRCMF_E_STATUS_NO_NETWORKS  3
#define BRCMF_E_STATUS_ABORT        4
#define BRCMF_E_STATUS_PARTIAL      8
#define BRCMF_E_STATUS_FWSUP_COMPLETED 6

#define SD_REG_CORECONTROL          0x00
#define SD_REG_INTSTATUS            0x20
#define SD_REG_HOSTINTMASK          0x24
#define SD_REG_INTMASK              0x28
#define SD_REG_TOSBMAILBOX          0x40
#define SD_REG_TOHOSTMAILBOX        0x44
#define SD_REG_TOSBMAILBOXDATA      0x48
#define SD_REG_TOHOSTMAILBOXDATA    0x4C

#define I_HMB_SW0                   (1u << 4)
#define I_HMB_SW1                   (1u << 5)
#define I_HMB_SW2                   (1u << 6)
#define I_HMB_SW3                   (1u << 7)
#define I_HMB_SW_MASK               0x000000F0
#define I_HMB_FC_STATE              I_HMB_SW0
#define I_HMB_FC_CHANGE             I_HMB_SW1
#define I_HMB_FRAME_IND             I_HMB_SW2
#define I_HMB_HOST_INT              I_HMB_SW3
#define I_CHIPACTIVE                (1u << 31)

#define SMB_NAK                     (1u << 0)
#define SMB_INT_ACK                 (1u << 1)
#define SMB_USE_OOB                 (1u << 2)
#define SMB_DEV_INT                 (1u << 3)

#define SMB_DATA_VERSION_SHIFT      16

#define HMB_DATA_NAKHANDLED         0x00000001u
#define HMB_DATA_DEVREADY           0x00000002u
#define HMB_DATA_FC                 0x00000004u
#define HMB_DATA_FWREADY            0x00000008u
#define HMB_DATA_FWHALT             0x00000010u
#define HMB_DATA_FCDATA_MASK        0xff000000u
#define HMB_DATA_FCDATA_SHIFT       24
#define HMB_DATA_VERSION_MASK       0x00ff0000u
#define HMB_DATA_VERSION_SHIFT      16

#define SDPCM_HOSTINTMASK           (I_HMB_SW_MASK | I_CHIPACTIVE)
