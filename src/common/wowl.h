/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#define AP6256_PM_RSN_REKEY 0x00000080u
#define AP6256_WOWL_ABI 0x314c4f57u

typedef struct _AP6256_GROUP_KEY_STATE {
    UINT32 Id, Valid;
    UCHAR Key[16], Rsc[8];
} AP6256_GROUP_KEY_STATE;
typedef struct _AP6256_GTK_STATE {
    UINT32 Abi, OffloadId, DescriptorVersion, MicKind, Pmf;
    UINT32 GtkId, GtkValid, IgtkId, IgtkValid, Changed;
    UCHAR Kck[16], Kek[16], Replay[8], Station[6], Peer[6];
    UCHAR Gtk[16], GtkRsc[8], Igtk[16], IgtkRsc[8];
    AP6256_GROUP_KEY_STATE Keys[6];
} AP6256_GTK_STATE;
C_ASSERT(sizeof(AP6256_GROUP_KEY_STATE) == 32);
C_ASSERT(sizeof(AP6256_GTK_STATE) == 332);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiRemoveGtkOffload(PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiReadGtkOffload(PAP6256_DEVICE_CONTEXT Ctx, AP6256_GTK_STATE* State);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256WifiSeedGroupKey(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Id,
    BOOLEAN Management, BOOLEAN Valid, const UCHAR* Key, const UCHAR* Rsc);
