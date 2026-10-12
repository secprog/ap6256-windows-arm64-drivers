/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#if !defined(AP6256_ENABLE_WDI) || defined(AP6256_ENABLE_WIFICX)
#error "Select exactly the WDI frontend in the build."
#endif
#include <ndis.h>
#include <dot11wdi.h>

#include <dot11wificxtypes.hpp>

typedef struct _MLO_LINK_INFO {
    UINT32 LinkID;
    WDI_MAC_ADDRESS StaLinkAddress;
    WDI_MAC_ADDRESS APLinkAddress;
} MLO_LINK_INFO, *PMLO_LINK_INFO;

C_ASSERT(sizeof(MLO_LINK_INFO) == sizeof(UINT32) + 2 * sizeof(WDI_MAC_ADDRESS));
#include "wdi_tal.h"

#include "sae_wdi.h"

typedef PNDIS_OID_REQUEST AP6256_REQUEST;

_IRQL_requires_max_(DISPATCH_LEVEL)
UINT16 Ap6256RequestGetMessageId(_In_ AP6256_REQUEST Request);

typedef AP6256_TIMER AP6256_TIMER_OBJ;
typedef AP6256_WORKITEM AP6256_WORKITEM_OBJ;

#define AP6256_TIMER_OK(t) Ap6256TimerValid(&(t))
#define AP6256_TIMER_START(t, ms) Ap6256TimerStart(&(t), (ms))
#define AP6256_TIMER_STOP(t, wait) Ap6256TimerStop(&(t), (wait))
#define AP6256_CMDQ_KICK(w) Ap6256WorkItemEnqueue(&(w)->CommandWorkItem)
#define AP6256_CMDQ_OK(w) Ap6256WorkItemValid(&(w)->CommandWorkItem)
#define AP6256_LINKQ_KICK(w) Ap6256WorkItemEnqueue(&(w)->LinkWorkItem)
#define AP6256_LINKQ_OK(w) Ap6256WorkItemValid(&(w)->LinkWorkItem)
#define AP6256_ACTIONFRAME_COMPLETE_KICK(w) Ap6256WorkItemEnqueue(&(w)->ActionFrameCompleteWorker)

#ifndef AP6256_WDI_VERSION
#define AP6256_WDI_VERSION WDI_VERSION_LATEST
#endif
