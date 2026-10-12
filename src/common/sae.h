/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once
#include "ap6256.h"

#define AP6256_SAE_BODY_MAX       1024u
#define AP6256_SAE_FRAME_MAX      (24u + AP6256_SAE_BODY_MAX)
#define AP6256_SAE_RETRY_MS       1000u
#define AP6256_SAE_TX_LIMIT       8u

NTSTATUS Ap6256SaeReadRsnxe(_In_reads_bytes_opt_(Length) const UCHAR* Ies,
    _In_ ULONG Length, _Out_ BOOLEAN* Present, _Out_ BOOLEAN* H2e);

typedef enum _AP6256_SAE_STATE {
    Ap6256SaeIdle,
    Ap6256SaeCommitParameters,
    Ap6256SaeCommitResponse,
    Ap6256SaeCommitDecision,
    Ap6256SaeConfirmParameters,
    Ap6256SaeConfirmResponse,
    Ap6256SaeStatus,
    Ap6256SaeAccepted,
    Ap6256SaeFailed
} AP6256_SAE_STATE;

typedef enum _AP6256_SAE_NOTICE {
    Ap6256SaeNeedCommit = 0,
    Ap6256SaePeerCommit = 1,
    Ap6256SaePeerConfirm = 2,
    Ap6256SaeError = 3,
    Ap6256SaeNeedNewConfirm = 4,
    Ap6256SaeNoNotice = 0xff
} AP6256_SAE_NOTICE;

typedef struct _AP6256_SAE_BYTES {
    const UCHAR* Data;
    ULONG Length;
} AP6256_SAE_BYTES;

typedef struct _AP6256_SAE_COMMIT {
    UINT16 Group;
    BOOLEAN H2e;
    AP6256_SAE_BYTES Scalar;
    AP6256_SAE_BYTES Element;
    AP6256_SAE_BYTES Token;
    AP6256_SAE_BYTES RejectedGroups;
} AP6256_SAE_COMMIT;

typedef struct _AP6256_SAE_OUTPUT {
    AP6256_SAE_NOTICE Notice;
    UINT32 Status;
    UINT32 PacketId;
    ULONG TxLength;
    UCHAR TxBody[AP6256_SAE_BODY_MAX];
    ULONG RxLength;
    UCHAR RxFrame[AP6256_SAE_FRAME_MAX];
} AP6256_SAE_OUTPUT;

typedef struct _AP6256_SAE {
    AP6256_SAE_STATE State;
    LONG Generation;
    UCHAR Peer[6];
    UCHAR Local[6];
    LONGLONG DeadlineMs;
    LONGLONG RetryAtMs;
    UINT32 NextPacketId;
    UINT32 PendingPacketId;
    ULONG Transmits;
    BOOLEAN H2e;
    ULONG ConfirmLength;
    ULONG CommitLength;
    UCHAR Commit[AP6256_SAE_BODY_MAX];
    ULONG EarlyConfirmLength;
    UCHAR EarlyConfirm[AP6256_SAE_FRAME_MAX];
} AP6256_SAE;

NTSTATUS Ap6256SaeBegin(_Inout_ AP6256_SAE* Sae,
    _In_reads_(6) const UCHAR* Local, _In_reads_(6) const UCHAR* Peer,
    _In_ LONG Generation, _In_ LONGLONG NowMs, _In_ LONGLONG DeadlineMs,
    _Out_ AP6256_SAE_OUTPUT* Output);
VOID Ap6256SaeReset(_Inout_ AP6256_SAE* Sae);
NTSTATUS Ap6256SaeCommit(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_reads_(6) const UCHAR* Peer,
    _In_ LONGLONG NowMs, _In_ const AP6256_SAE_COMMIT* Commit,
    _Out_ AP6256_SAE_OUTPUT* Output);
NTSTATUS Ap6256SaeConfirm(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_reads_(6) const UCHAR* Peer,
    _In_ LONGLONG NowMs, _In_ UINT16 SendConfirm,
    _In_reads_bytes_(Length) const UCHAR* Confirm, _In_ ULONG Length,
    _Out_ AP6256_SAE_OUTPUT* Output);
NTSTATUS Ap6256SaeReceive(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_ LONGLONG NowMs,
    _In_reads_bytes_(Length) const UCHAR* Frame, _In_ ULONG Length,
    _Out_ AP6256_SAE_OUTPUT* Output);
NTSTATUS Ap6256SaeFinish(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_reads_(6) const UCHAR* Peer,
    _In_ LONGLONG NowMs, _In_ BOOLEAN Success, _In_ UINT32 Status,
    _Out_ AP6256_SAE_OUTPUT* Output);
NTSTATUS Ap6256SaeTimeout(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_ LONGLONG NowMs,
    _Out_ AP6256_SAE_OUTPUT* Output);
NTSTATUS Ap6256SaeTxStatus(_Inout_ AP6256_SAE* Sae,
    _In_ LONG Generation, _In_ UINT32 PacketId, _In_ BOOLEAN Acknowledged,
    _Out_ AP6256_SAE_OUTPUT* Output);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeSendAuth(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT16 Channel, _In_reads_(6) const UCHAR* Peer, _In_ UINT32 PacketId,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SaeAuthStatus(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_(SsidLength) const UCHAR* Ssid, _In_ ULONG SsidLength,
    _In_ BOOLEAN Success);
