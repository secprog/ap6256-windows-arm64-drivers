/*
 * SPDX-License-Identifier: GPL-3.0-only AND ISC
 * Project-authored portions are licensed under the GNU General Public License,
 * version 3 only. Provided without warranty. See LICENSE for the GPL text.
 *
 * DMP descriptor and wrapper definitions are derived from
 * drivers/net/wireless/broadcom/brcm80211/brcmfmac/chip.c in Linux:
 * https://github.com/torvalds/linux
 * Upstream commit: 24a19b953e2a3d0ea5a8c4951a0ab8f32720c907
 * Copyright (c) 2014 Broadcom Corporation
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

#include "ap6256.h"

#define CC_EROMPTR                  0xfc

#define BCMA_IOCTL                  0x0408
#define BCMA_RESET_CTL              0x0800

#define BCMA_IOCTL_CLK              0x0001
#define BCMA_IOCTL_FGC              0x0002
#define BCMA_RESET_CTL_RESET        0x0001

#define ARMCR4_BCMA_IOCTL_CPUHALT   0x0020

#define D11_BCMA_IOCTL_PHYCLOCKEN   0x0004
#define D11_BCMA_IOCTL_PHYRESET     0x0008

#define ARMCR4_CAP                  0x04
#define ARMCR4_BANKIDX              0x40
#define ARMCR4_BANKINFO             0x44
#define ARMCR4_TCBBNB_MASK          0xf0
#define ARMCR4_TCBBNB_SHIFT         4
#define ARMCR4_TCBANB_MASK          0x0f
#define ARMCR4_TCBANB_SHIFT         0
#define ARMCR4_BSZ_MASK             0x7f
#define ARMCR4_BSZ_MULT             8192
#define ARMCR4_BLK_1K_MASK          0x200

#define DMP_DESC_TYPE_MSK           0x0000000F
#define DMP_DESC_EMPTY              0x00000000
#define DMP_DESC_VALID              0x00000001
#define DMP_DESC_COMPONENT          0x00000001
#define DMP_DESC_MASTER_PORT        0x00000003
#define DMP_DESC_ADDRESS            0x00000005
#define DMP_DESC_ADDRSIZE_GT32      0x00000008
#define DMP_DESC_EOT                0x0000000F

#define DMP_COMP_DESIGNER           0xFFF00000
#define DMP_COMP_DESIGNER_S         20
#define DMP_COMP_PARTNUM            0x000FFF00
#define DMP_COMP_PARTNUM_S          8
#define DMP_COMP_REVISION           0xFF000000
#define DMP_COMP_REVISION_S         24
#define DMP_COMP_NUM_SWRAP          0x00F80000
#define DMP_COMP_NUM_SWRAP_S        19
#define DMP_COMP_NUM_MWRAP          0x0007C000
#define DMP_COMP_NUM_MWRAP_S        14

#define DMP_SLAVE_ADDR_BASE         0xFFFFF000
#define DMP_SLAVE_TYPE              0x000000C0
#define DMP_SLAVE_TYPE_S            6
#define  DMP_SLAVE_TYPE_SLAVE       0
#define  DMP_SLAVE_TYPE_BRIDGE      1
#define  DMP_SLAVE_TYPE_SWRAP       2
#define  DMP_SLAVE_TYPE_MWRAP       3
#define DMP_SLAVE_SIZE_TYPE         0x00000030
#define DMP_SLAVE_SIZE_TYPE_S       4
#define  DMP_SLAVE_SIZE_4K          0
#define  DMP_SLAVE_SIZE_8K          1
#define  DMP_SLAVE_SIZE_16K         2
#define  DMP_SLAVE_SIZE_DESC        3

#define BCMA_CORE_PMU               0x827
#define BCMA_CORE_GCI               0x840

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipAttach(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_Must_inspect_result_
PAP6256_CORE Ap6256ChipGetCore(_In_ PAP6256_CHIP Chip, _In_ UINT16 CoreId);

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256ChipCoreIsUp(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipCoreDisable(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core,
                               _In_ UINT32 PreReset, _In_ UINT32 Reset);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipResetCore(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_CORE Core,
                             _In_ UINT32 PreReset, _In_ UINT32 Reset, _In_ UINT32 PostReset);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipSetPassive(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256ChipSetActive(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 ResetVector);
