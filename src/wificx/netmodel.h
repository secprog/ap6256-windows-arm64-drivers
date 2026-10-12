/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#if !defined(AP6256_ENABLE_WIFICX) || defined(AP6256_ENABLE_WDI)
#error "Select exactly the WIFICX frontend in the build."
#endif
#include <netadaptercx.h>
#include <net/virtualaddress.h>
#include <wificx.h>
#include <net/wifi/exemptionaction.h>

typedef WIFIREQUEST AP6256_REQUEST;

_IRQL_requires_max_(PASSIVE_LEVEL)
UINT16 Ap6256RequestGetMessageId(_In_ AP6256_REQUEST Request);

typedef WDFTIMER AP6256_TIMER_OBJ;
typedef WDFWORKITEM AP6256_WORKITEM_OBJ;

#define AP6256_TIMER_OK(t) ((t) != NULL)
#define AP6256_TIMER_START(t, ms) ((VOID)WdfTimerStart((t), WDF_REL_TIMEOUT_IN_MS(ms)))
#define AP6256_TIMER_STOP(t, wait) ((VOID)WdfTimerStop((t), (wait)))
#define AP6256_CMDQ_KICK(w) WdfWorkItemEnqueue((w)->CommandWorkItem)
#define AP6256_CMDQ_OK(w) ((w)->CommandWorkItem != NULL)
#define AP6256_LINKQ_KICK(w) WdfWorkItemEnqueue((w)->LinkWorkItem)
#define AP6256_LINKQ_OK(w) ((w)->LinkWorkItem != NULL)
#define AP6256_ACTIONFRAME_COMPLETE_KICK(w) WdfWorkItemEnqueue((w)->ActionFrameCompleteWorker)

#ifndef AP6256_WDI_VERSION
#define AP6256_WDI_VERSION WDI_VERSION_LATEST
#endif
