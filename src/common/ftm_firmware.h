/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256PrepareFtm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_ PUCHAR* Image,_Inout_ PULONG Length,_Out_ BOOLEAN* Applied);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtmCommand(_In_ PAP6256_DEVICE_CONTEXT Ctx,_In_ UINT16 Command,
    _In_ UINT16 Session,_In_ UINT16 Chanspec,_In_opt_ const UCHAR* Peer,_In_ ULONG TimeoutMs,
    _In_ BOOLEAN Setter,_Out_writes_bytes_(Capacity) UCHAR* Reply,_In_ ULONG Capacity,
    _Out_ PULONG Length,_Out_opt_ INT32* FirmwareStatus);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256QualifyFtm(_In_ PAP6256_DEVICE_CONTEXT Ctx);
