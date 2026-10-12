/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "sae.h"

#define AP6256_CYW_EXT_AUTH_REQ       187u
#define AP6256_CYW_EXT_AUTH_RX        188u
#define AP6256_CYW_MGMT_TX_STATUS     189u
#define AP6256_CYW_MGMT_OFFCHAN_DONE  190u

#define AP6256_SAE_PRIVATE_MAGIC     0x31415341u
#define AP6256_SAE_OWNER_MAGIC       0x314f5341u
#define AP6256_SAE_OWNER_AUTH_FLAG   0x80000000u
#define AP6256_SAE_PRIVATE_FEATURE   1u
#define AP6256_SAE_PRIVATE_IDLE      0u
#define AP6256_SAE_PRIVATE_ARMED     1u
#define AP6256_SAE_PRIVATE_HELD      2u
#define AP6256_SAE_PRIVATE_ACCEPTED  3u
#define AP6256_SAE_PRIVATE_CACHED    4u
#define AP6256_SAE_PRIVATE_FAILED    6u
#define AP6256_SAE_PRIVATE_TX        2u
#define AP6256_SAE_PRIVATE_ACCEPT    3u
#define AP6256_SAE_PRIVATE_ABORT     4u
#define AP6256_SAE_PRIVATE_CLEAR     5u

typedef struct _AP6256_SAE_PRIVATE_STATE {
    UINT32 Features, Generation, Phase, Transmits, Receives, Mode;
    UINT16 Group, Observations;
} AP6256_SAE_PRIVATE_STATE;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaePrivateQuery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Out_ AP6256_SAE_PRIVATE_STATE* State);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaePrivateArm(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Generation, _In_reads_(6) const UCHAR* Peer,
    _In_ UINT32 TimeoutMs, _In_reads_opt_(16) const UCHAR* Pmkid,
    _In_ BOOLEAN CachedH2e);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaePrivateCommand(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT16 Operation, _In_ UINT32 Generation,
    _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_opt_(Length) const UCHAR* Body, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaePrivateEnd(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Generation, _In_reads_(6) const UCHAR* Peer,
    _In_ BOOLEAN Associated);
BOOLEAN Ap6256SaePrivateFrame(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_reads_(6) const UCHAR* Local,
    _In_reads_(6) const UCHAR* Peer, _Out_ UINT32* Generation,
    _Out_ ULONG* FrameLength);
BOOLEAN Ap6256SaePrivateOwner(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _Out_ UINT32* Generation,
    _Out_writes_(6) UCHAR* Peer);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256SaeFirmwarePrepare(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeSetBip(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeVerifySecurity(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 Wsec, _In_ BOOLEAN CachedPmkid);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeSetPmkid(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* Peer, _In_reads_opt_(16) const UCHAR* Pmkid);

NTSTATUS Ap6256SaeAuthRequest(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_(SsidLength) const UCHAR* Ssid, _In_ ULONG SsidLength,
    _Out_ BOOLEAN* Abort);
NTSTATUS Ap6256SaeReceiveEvent(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_ LONGLONG NowMs,
    _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length,
    _Out_ AP6256_SAE_OUTPUT* Output);

BOOLEAN Ap6256SaeAssociationRsn(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_ BOOLEAN Reassociation);
BOOLEAN Ap6256SaeAssociationPmkid(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_ BOOLEAN Reassociation,
    _In_reads_(16) const UCHAR* Pmkid);
BOOLEAN Ap6256SaeAssociationH2e(_In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length, _In_ BOOLEAN Reassociation, _In_ BOOLEAN H2e);
