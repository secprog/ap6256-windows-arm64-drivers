/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "sae.h"

struct _TLV_CONTEXT;
struct _WDI_CONNECT_BSS_ENTRY_CONTAINER;

NTSTATUS Ap6256SaeCopyPmkid(_In_ BOOLEAN Present,
    _In_reads_bytes_opt_(Length) const UCHAR* Bytes, _In_ ULONG Length,
    _Out_writes_(16) UCHAR* Pmkid, _Out_ BOOLEAN* Valid);

NTSTATUS Ap6256SaeCopyCachedH2e(
    _In_ const struct _WDI_CONNECT_BSS_ENTRY_CONTAINER* Candidate,
    _In_reads_bytes_opt_(CommonLength) const UCHAR* CommonIes,
    _In_ ULONG CommonLength, _Out_ BOOLEAN* H2e);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeApplyWdi(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_ LONGLONG NowMs,
    _In_reads_bytes_(Length) const UCHAR* Tlv, _In_ ULONG Length,
    _In_ const struct _TLV_CONTEXT* Codec,
    _Out_ AP6256_SAE_OUTPUT* Output);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeEncodeWdi(_In_ const AP6256_SAE* Sae,
    _In_ const AP6256_SAE_OUTPUT* Output,
    _In_ const struct _TLV_CONTEXT* Codec,
    _Outptr_result_buffer_(*Length) UCHAR** Bytes, _Out_ ULONG* Length);
