/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareDownload(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256FirmwareHalt(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                       _In_ UINT32 Mailbox, _In_ UINT32 InterruptStatus);

BOOLEAN Ap6256FirmwareVolumeGone(VOID);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareQueryMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _Out_writes_(6) PUCHAR MacAddress);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FirmwareLoadClm(_In_ PAP6256_DEVICE_CONTEXT Ctx);
