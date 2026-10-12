/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoPrepareInitialDelay(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_updates_bytes_(Length) PUCHAR Image, _In_ ULONG Length,
    _Out_ BOOLEAN* Applied);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PnoVerifyInitialDelay(_In_ PAP6256_DEVICE_CONTEXT Ctx);
