/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#ifndef AP6256_ALLOW_STUB_NETADAPTER
#error "The diagnostic adapter requires explicit build acknowledgement."
#endif

#include "netadapter.h"
#include "datapath.h"
#include "firmware.h"
#include "wifi_ops.h"
#include "hotspot.h"
#include "bcdc.h"
#include "tdls.h"
#include "pno.h"
#include "native_mgmt.h"
#include "sae_fw.h"
#include "ft_fw.h"
#include "owe.h"
#include "wlfc.h"

_Use_decl_annotations_
VOID Ap6256NetFirmwareHalted(PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_Use_decl_annotations_
VOID Ap6256NetSaeEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 EventType,
    UINT32 Status, const UCHAR* Peer, const UCHAR* Body, ULONG Length)
{
    UNREFERENCED_PARAMETER(Ctx); UNREFERENCED_PARAMETER(EventType);
    UNREFERENCED_PARAMETER(Status); UNREFERENCED_PARAMETER(Peer);
    UNREFERENCED_PARAMETER(Body); UNREFERENCED_PARAMETER(Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApAssociationRequest(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_reads_(6) const UCHAR* PeerAddress,
                                   _In_ BOOLEAN Reassociation,
                                   _In_reads_bytes_opt_(Length) const UCHAR* Frame,
                                   _In_ ULONG Length)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(PeerAddress);
    UNREFERENCED_PARAMETER(Reassociation);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRoamingNeeded(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ UINT32 Reason)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Reason);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRadioChanged(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetTkipMicFailure(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_reads_(6) const UCHAR* PeerAddress,
                             _In_ UINT32 KeyIndex,
                             _In_ BOOLEAN GroupKey)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(PeerAddress);
    UNREFERENCED_PARAMETER(KeyIndex);
    UNREFERENCED_PARAMETER(GroupKey);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApStopped(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Reason)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Reason);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApCanSustain(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 Reason)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Reason);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkStateRefresh(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameReceived(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UCHAR IfIndex,
                                  _In_ UCHAR BssCfgIndex,
                                  _In_reads_(6) const UCHAR* SourceAddress,
                                  _In_ UINT16 Chanspec,
                                  _In_reads_bytes_(Length) const UCHAR* Body,
                                  _In_ ULONG Length)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(IfIndex);
    UNREFERENCED_PARAMETER(BssCfgIndex);
    UNREFERENCED_PARAMETER(SourceAddress);
    UNREFERENCED_PARAMETER(Chanspec);
    UNREFERENCED_PARAMETER(Body);
    TraceVerbose(TRACE_NETADAPTER,
                 "action frame %u bytes (no adapter; dropped)\n", Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameComplete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ UINT32 PacketId,
                                  _In_ UINT32 FirmwareStatus)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(PacketId);
    UNREFERENCED_PARAMETER(FirmwareStatus);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameCompleteQueue(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                       _In_ UINT32 PacketId,
                                       _In_ UINT32 FirmwareStatus)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(PacketId);
    UNREFERENCED_PARAMETER(FirmwareStatus);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxFlush(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{

    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRxIndicate(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_reads_bytes_(Length) PUCHAR Frame, _In_ ULONG Length,
                         _In_ UCHAR Priority, _In_ UINT32 IfIndex)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Frame);
    UNREFERENCED_PARAMETER(Priority);
    UNREFERENCED_PARAMETER(IfIndex);
    TraceVerbose(TRACE_NETADAPTER, "rx %u bytes (no adapter; dropped)\n", Length);
}

_Use_decl_annotations_
NTSTATUS Ap6256NetNloDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_BSS Bss)
{
    UNREFERENCED_PARAMETER(Ctx); UNREFERENCED_PARAMETER(Bss);
    return STATUS_NOT_SUPPORTED;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ PAP6256_BSS Bss)
{
    UNREFERENCED_PARAMETER(Ctx);
    TraceInfo(TRACE_NETADAPTER, "scan BSS '%.*s' %02X:%02X:%02X:%02X:%02X:%02X rssi=%d ch=%u\n",
              (int)Bss->SsidLength, Bss->Ssid,
              Bss->Bssid[0], Bss->Bssid[1], Bss->Bssid[2],
              Bss->Bssid[3], Bss->Bssid[4], Bss->Bssid[5], Bss->Rssi, Bss->Channel);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanComplete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ NTSTATUS CompletionStatus)
{
    UNREFERENCED_PARAMETER(Ctx);
    TraceInfo(TRACE_NETADAPTER, "scan complete 0x%08X\n", CompletionStatus);
}

_Use_decl_annotations_
VOID Ap6256NetStationLinkEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
    BOOLEAN TerminalFailure, const UCHAR* Peer)
{
    UNREFERENCED_PARAMETER(TerminalFailure);
    UNREFERENCED_PARAMETER(Peer);
    Ctx->FirmwareLinkUp = Up;
    if (!Up) Ctx->SupplicantComplete = FALSE;
    Ap6256NetLinkChange(Ctx, Up);
}

_Use_decl_annotations_
VOID Ap6256NetStationFirmwareEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
    BOOLEAN TerminalFailure, const UCHAR* Peer, UINT32 FirmwareGeneration)
{
    if (FirmwareGeneration) return;
    Ap6256NetStationLinkEvent(Ctx, Up, TerminalFailure, Peer);
}

_Use_decl_annotations_
VOID Ap6256NetStationHostCipherEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                    BOOLEAN TerminalFailure, const UCHAR* Peer,
                                    UINT32 FirmwareGeneration)
{

    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(Up);
    UNREFERENCED_PARAMETER(TerminalFailure);
    UNREFERENCED_PARAMETER(Peer);
    UNREFERENCED_PARAMETER(FirmwareGeneration);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkChange(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ BOOLEAN LinkUp)
{
    UNREFERENCED_PARAMETER(Ctx);
    TraceInfo(TRACE_NETADAPTER, "link %s\n", LinkUp ? "up" : "down");
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256NetTxKick(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetSetMacAddress(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetHardwareStart(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    UNREFERENCED_PARAMETER(Ctx);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetHardwareStop(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                            _In_ NTSTATUS CompletionStatus,
                            _In_ BOOLEAN OnCommandWorker)
{
    UNREFERENCED_PARAMETER(Ctx);
    UNREFERENCED_PARAMETER(CompletionStatus);
    UNREFERENCED_PARAMETER(OnCommandWorker);
}

_Use_decl_annotations_
VOID Ap6256NetServiceEvent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 Type, UINT32 Status,
    UINT32 Generation,const UCHAR* Peer,const UCHAR* Body,ULONG Length)
{
    UNREFERENCED_PARAMETER(Ctx);UNREFERENCED_PARAMETER(Type);UNREFERENCED_PARAMETER(Status);
    UNREFERENCED_PARAMETER(Generation);UNREFERENCED_PARAMETER(Peer);
    UNREFERENCED_PARAMETER(Body);UNREFERENCED_PARAMETER(Length);
}
