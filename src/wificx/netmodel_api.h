/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS
Ap6256NetDeviceInitConfig(_In_ PWDFDEVICE_INIT DeviceInit);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetAdapterCreate(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetGoEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
    UINT32 Status, UINT32 Reason, UINT16 Flags,
    _In_reads_(6) const UCHAR* Address,
    _In_reads_bytes_opt_(Length) const UCHAR* Data, ULONG Length);
