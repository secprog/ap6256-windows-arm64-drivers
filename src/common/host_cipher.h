/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PrepareHostCiphers(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_ PUCHAR* Image, _Inout_ PULONG Length, _Out_ BOOLEAN* Applied);
