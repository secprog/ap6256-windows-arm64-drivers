/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "wifi_ops.h"

#define AP6256_FT_MDE_LENGTH 5u
#define AP6256_FT_FTE_MIN_LENGTH 84u
#define AP6256_FT_AUTH_MAX_LENGTH 768u

typedef enum _AP6256_FT_PHASE {
    Ap6256FtIdle,
    Ap6256FtInitial,
    Ap6256FtAuthenticating,
    Ap6256FtWaitingHost,
    Ap6256FtResumed,
    Ap6256FtAbortRequired,
    Ap6256FtDrainingHost
} AP6256_FT_PHASE;

typedef struct _AP6256_FT_OWNER {
    ULONGLONG Generation;
    UINT32 TransactionId;
    UINT16 PortId;
    UCHAR Bssid[6];
} AP6256_FT_OWNER;

typedef struct _AP6256_FT_STATE {
    AP6256_FT_PHASE Phase;
    AP6256_FT_OWNER Owner;

    ULONGLONG NextGeneration;

    BOOLEAN MobilityDomainValid;
    UCHAR MobilityDomain[2];
    BOOLEAN NeedsAbort;
    BOOLEAN HostReplyOutstanding;
    UCHAR Mde[AP6256_FT_MDE_LENGTH];
    UCHAR SNonce[32];
    UCHAR ANonce[32];
    ULONG FinalRsnLength, FinalFteLength;
    UCHAR FinalRsn[257], FinalFte[257];
} AP6256_FT_STATE;

typedef struct _AP6256_CONNECT_FT_SETUP {
    AP6256_FT_STATE* State;
    UINT16 PortId;
    UINT32 TransactionId;
    BOOLEAN Reassociation;
    UCHAR Mde[AP6256_FT_MDE_LENGTH];
    UCHAR Fte[257];
    ULONG FteLength;
    UCHAR PmkR0Name[16];
} AP6256_CONNECT_FT_SETUP;

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiConnectFt(PAP6256_DEVICE_CONTEXT Ctx,
    PAP6256_CONNECT_PARAMS Params, AP6256_CONNECT_FT_SETUP* Setup);

NTSTATUS Ap6256FtValidateBegin(
    _In_ const AP6256_FT_STATE* State, _In_reads_(6) const UCHAR* Bssid,
    _In_ BOOLEAN Reassociation,
    _In_reads_bytes_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength,
    _In_reads_bytes_opt_(PmkLength) const UCHAR* PmkR0Name, _In_ ULONG PmkLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtBegin(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ AP6256_FT_STATE* State,
    _In_ UINT16 PortId, _In_ UINT32 TransactionId,
    _In_reads_(6) const UCHAR* Bssid, _In_ BOOLEAN Reassociation,
    _In_reads_bytes_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength,
    _In_reads_bytes_opt_(PmkLength) const UCHAR* PmkR0Name, _In_ ULONG PmkLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtAcceptAuthentication(
    _Inout_ AP6256_FT_STATE* State, _In_ const AP6256_FT_OWNER* Owner,
    _In_reads_bytes_(RequestLength) const UCHAR* Request, _In_ ULONG RequestLength,
    _In_reads_bytes_(ResponseLength) const UCHAR* Response, _In_ ULONG ResponseLength);

_Success_(return != FALSE)
BOOLEAN Ap6256FtReadAuthenticationIdentity(
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length,
    _In_ UCHAR Sequence, _Out_writes_(AP6256_FT_MDE_LENGTH) UCHAR* Mde,
    _Out_writes_(32) UCHAR* SNonce);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtFinish(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _Inout_ AP6256_FT_STATE* State,
    _In_ const AP6256_FT_OWNER* Owner, _In_ UINT32 HostStatus,
    _In_reads_bytes_opt_(RsnLength) const UCHAR* Rsn, _In_ ULONG RsnLength,
    _In_reads_bytes_opt_(MdeLength) const UCHAR* Mde, _In_ ULONG MdeLength,
    _In_reads_bytes_opt_(FteLength) const UCHAR* Fte, _In_ ULONG FteLength);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256FtEnd(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _Inout_ AP6256_FT_STATE* State, _In_ BOOLEAN Associated);

VOID Ap6256FtConnectionLost(_Inout_ AP6256_FT_STATE* State);

BOOLEAN Ap6256FtAssociationValid(const AP6256_FT_STATE* State,
    const AP6256_ASSOC_FRAMES* Frames);

BOOLEAN Ap6256FtOwnerMatches(_In_ const AP6256_FT_STATE* State,
    _In_ const AP6256_FT_OWNER* Owner);
