/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#pragma once

#include "ap6256.h"
#include "wifi_ops.h"

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetFirmwareHalted(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
                         _In_ UCHAR Priority, _In_ UINT32 IfIndex);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApAssociationRequest(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_reads_(6) const UCHAR* PeerAddress,
    _In_ BOOLEAN Reassociation,
    _In_reads_bytes_opt_(Length) const UCHAR* Frame,
    _In_ ULONG Length);

#define AP6256_ROAM_LOW_LINK_QUALITY   15u
#define AP6256_ROAM_ASSOCIATION_LOST   11u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRoamingNeeded(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ UINT32 Reason);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRadioChanged(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetTkipMicFailure(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_reads_(6) const UCHAR* PeerAddress,
                             _In_ UINT32 KeyIndex,
                             _In_ BOOLEAN GroupKey);

#define AP6256_AP_STOP_FREQUENCY_NOT_AVAILABLE  1u
#define AP6256_AP_CAN_SUSTAIN_IHV               0xFF000000u

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApStopped(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Reason);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApCanSustain(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                           _In_ UINT32 Reason);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkStateRefresh(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameReceived(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UCHAR IfIndex,
    _In_ UCHAR BssCfgIndex,
    _In_reads_(6) const UCHAR* SourceAddress,
    _In_ UINT16 Chanspec,
    _In_reads_bytes_(Length) const UCHAR* Body,
    _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameComplete(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 PacketId,
    _In_ UINT32 FirmwareStatus);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameCompleteQueue(
    _In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ UINT32 PacketId,
    _In_ UINT32 FirmwareStatus);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_BSS Bss);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetNloDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_BSS Bss);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanComplete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ NTSTATUS CompletionStatus);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkChange(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN LinkUp);

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetTxKick(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetHardwareStart(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)

VOID Ap6256NetHardwareStop(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ NTSTATUS CompletionStatus,
                            _In_ BOOLEAN OnCommandWorker);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetStationLinkEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Up,
    _In_ BOOLEAN TerminalFailure, _In_reads_opt_(6) const UCHAR* Peer);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetStationFirmwareEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Up,
    _In_ BOOLEAN TerminalFailure, _In_reads_opt_(6) const UCHAR* Peer,
    _In_ UINT32 FirmwareGeneration);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetStationHostCipherEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN Up,
    _In_ BOOLEAN TerminalFailure, _In_reads_(6) const UCHAR* Peer,
    _In_ UINT32 FirmwareGeneration);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetSaeEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 EventType,
    _In_ UINT32 Status, _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length);

#include <netmodel_api.h>

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetSaePrivateEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_reads_(6) const UCHAR* Peer,
                             _In_reads_bytes_(Length) const UCHAR* Body,
                             _In_ ULONG Length);
_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetFtEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                     _In_reads_(6) const UCHAR* Peer,
                     _In_reads_bytes_(Length) const UCHAR* Body,
                     _In_ ULONG Length);

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetServiceEvent(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Type,
    _In_ UINT32 Status, _In_ UINT32 Generation, _In_reads_(6) const UCHAR* Peer,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length);
