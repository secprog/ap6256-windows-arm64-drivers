/*
 * SPDX-License-Identifier: GPL-3.0-only AND ISC
 * Project-authored portions are licensed under the GNU General Public License,
 * version 3 only. Provided without warranty. See LICENSE for the GPL text.
 *
 * Register and bit definitions are derived from Linux brcm80211 files
 * drivers/net/wireless/broadcom/brcm80211/brcmfmac/sdio.h,
 * drivers/net/wireless/broadcom/brcm80211/brcmfmac/sdio.c and
 * drivers/net/wireless/broadcom/brcm80211/include/soc.h:
 * https://github.com/torvalds/linux
 * Upstream commit: 24a19b953e2a3d0ea5a8c4951a0ab8f32720c907
 * Copyright (c) 2010 Broadcom Corporation
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

#define SI_ENUM_BASE_DEFAULT        0x18000000

#define SICF_BIST_EN                0x8000
#define SICF_PME_EN                 0x4000
#define SICF_CORE_BITS              0x3ffc
#define SICF_FGC                    0x0002
#define SICF_CLOCK_EN               0x0001

#define SISF_BIST_DONE              0x8000
#define SISF_BIST_ERROR             0x4000
#define SISF_GATED_CLK              0x2000
#define SISF_DMA64                  0x1000
#define SISF_CORE_BITS              0x0fff

#define BCMA_CORE_CHIPCOMMON        0x800
#define BCMA_CORE_SDIO_DEV          0x829
#define BCMA_CORE_ARM_CR4           0x83e
#define BCMA_CORE_80211             0x812
#define BCMA_CORE_INTERNAL_MEM      0x80e

#define CC_CHIPID                   0x00
#define CC_CAPABILITIES             0x04
#define CC_CORECONTROL              0x08
#define CC_CHIPSTATUS               0x2c
#define CC_INTSTATUS                0x20
#define CC_WATCHDOG                 0x80
#define CC_CLKDIV                   0x94
#define CC_CAPABILITIES_EXT         0xac
#define CC_CLK_CTL_ST               0x1e0
#define CC_PMU_CONTROL              0x600
#define CC_PMU_CAPABILITIES         0x604
#define CC_PMU_STATUS               0x608
#define CC_PMU_WATCHDOG             0x634
#define CC_CHIPCONTROL_ADDR         0x650
#define CC_CHIPCONTROL_DATA         0x654
#define CC_PMU_XTALFREQ             0x66c

#define CID_ID_MASK                 0x0000ffff
#define CID_REV_MASK                0x000f0000
#define CID_REV_SHIFT               16
#define CID_PKG_MASK                0x00f00000
#define CID_PKG_SHIFT               20
#define CID_TYPE_MASK               0xf0000000
#define CID_TYPE_SHIFT              28

#define SOCI_AI                     1

#define CC_CAP_PMU                  0x10000000

#define SDIO_FUNC_ENABLE_1          0x02
#define SDIO_FUNC_ENABLE_2          0x04
#define SDIO_FUNC_READY_1           0x02
#define SDIO_FUNC_READY_2           0x04
#define INTR_STATUS_FUNC1           0x02
#define INTR_STATUS_FUNC2           0x04

#define SDIO_CCCR_BRCM_CARDCAP              0xf0
#define SDIO_CCCR_BRCM_CARDCAP_CMD14_SUPPORT 0x02
#define SDIO_CCCR_BRCM_CARDCAP_CMD14_EXT     0x04
#define SDIO_CCCR_BRCM_CARDCAP_CMD_NODEC     0x08

#define SDIO_CCCR_IEN_FUNC0         0x01
#define SDIO_CCCR_IEN_FUNC1         0x02
#define SDIO_CCCR_IEN_FUNC2         0x04

#define SDIO_CCCR_BRCM_CARDCTRL             0xf1
#define SDIO_CCCR_BRCM_CARDCTRL_WLANRESET   0x02

#define SDIO_CCCR_BRCM_SEPINT               0xf2
#define SDIO_CCCR_BRCM_SEPINT_MASK          0x01
#define SDIO_CCCR_BRCM_SEPINT_OE            0x02
#define SDIO_CCCR_BRCM_SEPINT_ACT_HI        0x04

#define SDIO_FBR_BASE(f)            ((ULONG)(f) * 0x100u)
#define SDIO_FBR_BLKSIZE            0x10u

#define AP6256_F1_BLOCKSIZE         64

#define AP6256_F2_BLOCKSIZE         512

#define SBSDIO_SPROM_CS             0x10000
#define SBSDIO_GPIO_SELECT          0x10005
#define SBSDIO_GPIO_OUT             0x10006
#define SBSDIO_GPIO_EN              0x10007
#define SBSDIO_WATERMARK            0x10008
#define SBSDIO_DEVICE_CTL           0x10009

#define SBSDIO_FUNC1_SBADDRLOW      0x1000A
#define SBSDIO_FUNC1_SBADDRMID      0x1000B
#define SBSDIO_FUNC1_SBADDRHIGH     0x1000C
#define SBSDIO_FUNC1_FRAMECTRL      0x1000D
#define SBSDIO_FUNC1_CHIPCLKCSR     0x1000E
#define SBSDIO_FUNC1_SDIOPULLUP     0x1000F
#define SBSDIO_FUNC1_WFRAMEBCLO     0x10019
#define SBSDIO_FUNC1_WFRAMEBCHI     0x1001A
#define SBSDIO_FUNC1_RFRAMEBCLO     0x1001B
#define SBSDIO_FUNC1_RFRAMEBCHI     0x1001C
#define SBSDIO_FUNC1_MESBUSYCTRL    0x1001D
#define SBSDIO_FUNC1_WAKEUPCTRL     0x1001E
#define SBSDIO_FUNC1_SLEEPCSR       0x1001F

#define SBSDIO_FUNC1_MISC_REG_START 0x10000
#define SBSDIO_FUNC1_MISC_REG_LIMIT 0x1001F

#define SBSDIO_DEVCTL_SETBUSY       0x01
#define SBSDIO_DEVCTL_SPI_INTR_SYNC 0x02
#define SBSDIO_DEVCTL_CA_INT_ONLY   0x04
#define SBSDIO_DEVCTL_PADS_ISO      0x08
#define SBSDIO_DEVCTL_F2WM_ENAB     0x10
#define SBSDIO_DEVCTL_SB_RST_CTL    0x30
#define SBSDIO_DEVCTL_RST_CORECTL   0x00
#define SBSDIO_DEVCTL_RST_BPRESET   0x10
#define SBSDIO_DEVCTL_RST_NOBPRESET 0x20

#define SFC_RF_TERM                 0x01
#define SFC_WF_TERM                 0x02
#define SFC_CRC4WOOS                0x04
#define SFC_ABORTALL                0x08

#define SBSDIO_FORCE_ALP            0x01
#define SBSDIO_FORCE_HT             0x02
#define SBSDIO_FORCE_ILP            0x04
#define SBSDIO_ALP_AVAIL_REQ        0x08
#define SBSDIO_HT_AVAIL_REQ         0x10
#define SBSDIO_FORCE_HW_CLKREQ_OFF  0x20
#define SBSDIO_ALP_AVAIL            0x40
#define SBSDIO_HT_AVAIL             0x80
#define SBSDIO_CSR_MASK             0x1F
#define SBSDIO_AVBITS               (SBSDIO_HT_AVAIL | SBSDIO_ALP_AVAIL)
#define SBSDIO_ALPAV(x)             ((x) & SBSDIO_AVBITS)
#define SBSDIO_HTAV(x)              (((x) & SBSDIO_AVBITS) == SBSDIO_AVBITS)

#define BRCMF_INIT_CLKCTL1          (SBSDIO_FORCE_HW_CLKREQ_OFF | SBSDIO_ALP_AVAIL_REQ)

#define SBSDIO_MESBUSYCTRL_ENAB         0x80
#define SBSDIO_WATERMARK_MASK           0x7Fu
#define SBSDIO_FIFOTUNE_MIN_COREREV     15u
#define SBSDIO_OVERFLOW_BLKSZ512_WM     96
#define SBSDIO_OVERFLOW_BLKSZ512_MES    80
#define SBSDIO_DEFAULT_WATERMARK        8

#define SBSDIO_FUNC1_SLEEPCSR_KSO_MASK   0x01
#define SBSDIO_FUNC1_SLEEPCSR_KSO_EN     0x01
#define SBSDIO_FUNC1_SLEEPCSR_DEVON_MASK 0x02

#define SBSDIO_SB_OFT_ADDR_MASK     0x07FFF
#define SBSDIO_SB_OFT_ADDR_LIMIT    0x08000
#define SBSDIO_SB_ACCESS_2_4B_FLAG  0x08000

#define SBSDIO_SBWINDOW_MASK        0xffff8000

#define SDIO_REQ_4BYTE              0x1
#define SDIO_REQ_FIXED             0x2
