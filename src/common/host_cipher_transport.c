/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "host_cipher_transport.h"
#include "host_fips.h"
#include "datapath.h"
#include "bcdc.h"
#include "wlfc.h"
#include "netadapter.h"

_Use_decl_annotations_
BOOLEAN Ap6256HostCipherPacketActive(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    return IfIndex < AP6256_HC_INTERFACES &&
        ((InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
          (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex))) ||
        Ap6256HostCipherStoreActive(&Ctx->HostCipherStore, IfIndex));
}

_Use_decl_annotations_
NTSTATUS Ap6256HostCipherSetRxExemptions(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const AP6256_HC_RX_EXEMPT* Entries, ULONG Count)
{

    if (!InterlockedCompareExchange(&Ctx->HostCipherStore.Ready, 0, 0))
        return Ap6256HostCipherPacketActive(Ctx, IfIndex) ? STATUS_DEVICE_NOT_READY : STATUS_SUCCESS;
    return Ap6256HostCipherStoreSetRxExemptions(&Ctx->HostCipherStore, IfIndex, Entries, Count);
}

static BOOLEAN HcPacketReady(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex)
{
    return IfIndex < AP6256_HC_INTERFACES &&
        InterlockedCompareExchange(&Ctx->HostCipherFirmwareQualified, 0, 0) == 1 &&
        !InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) &&
        !(InterlockedCompareExchange(&Ctx->HostCipherBlockedMask, 0, 0) &
          (AP6256_HC_FIRMWARE_RETIRED | (1u << IfIndex)));
}

_Use_decl_annotations_
NTSTATUS Ap6256RawPrepareTx(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, UCHAR* Buffer,
    ULONG Capacity, ULONG* Length, UCHAR* Priority, UCHAR* Exemption)
{
    UCHAR* wire;
    ULONG written = 0;
    NTSTATUS status;
    if (!Buffer || !Length || !Priority || !Exemption || *Length > Capacity) return STATUS_INVALID_PARAMETER;
    if (!Ap6256HostCipherPacketActive(Ctx, IfIndex))
        return Ap6256FipsPrepareTx(Ctx, IfIndex, Buffer, Capacity, Length, Priority, Exemption);
    if (!HcPacketReady(Ctx, IfIndex) || Ap6256FipsActive(Ctx, IfIndex)) {
        *Length = 0; return STATUS_DEVICE_NOT_READY;
    }
    wire = ExAllocatePool2(POOL_FLAG_NON_PAGED, AP6256_HC_MAX_FRAME + AP6256_HC_WIRE_TX_HEADER, AP6256_POOL_TAG);
    if (!wire) { *Length = 0; return STATUS_INSUFFICIENT_RESOURCES; }
    status = Ap6256HostCipherDataTx(&Ctx->HostCipherStore, IfIndex, Buffer, *Length, *Exemption,
        wire, min(Capacity, AP6256_HC_MAX_FRAME + AP6256_HC_WIRE_TX_HEADER), &written, Priority);
    if (NT_SUCCESS(status) && Ap6256RawTxCurrent(Ctx, IfIndex, wire, written)) {
        RtlCopyMemory(Buffer, wire, written); *Length = written; *Exemption = AP6256_FIPS_BCDC_TX_EXEMPT;
    } else { if (NT_SUCCESS(status)) status = STATUS_DEVICE_NOT_READY; *Length = 0; }
    RtlSecureZeroMemory(wire, AP6256_HC_MAX_FRAME + AP6256_HC_WIRE_TX_HEADER);
    ExFreePoolWithTag(wire, AP6256_POOL_TAG); return status;
}

_Use_decl_annotations_
BOOLEAN Ap6256RawGenerationCurrent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    ULONG Generation, BOOLEAN HostCipher)
{
    AP6256_HC_STORE_SESSION hc;
    AP6256_FIPS_SESSION fips;
    if (!Generation) return !HostCipher && !Ap6256HostCipherPacketActive(Ctx, IfIndex) && !Ap6256FipsActive(Ctx, IfIndex);
    if (HostCipher) return HcPacketReady(Ctx, IfIndex) &&
        !Ap6256FipsActive(Ctx, IfIndex) && Ap6256HostCipherStoreSnapshot(&Ctx->HostCipherStore, IfIndex, &hc) && hc.Generation == Generation;
    return !Ap6256HostCipherPacketActive(Ctx, IfIndex) && Ap6256FipsSnapshot(Ctx, IfIndex, &fips) && fips.Generation == Generation;
}

_Use_decl_annotations_
BOOLEAN Ap6256RawRxRead(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, const UCHAR* Wire,
    ULONG Length, AP6256_FIPS_FRAME_VIEW* View, ULONG* Generation, BOOLEAN* HostCipher)
{
    AP6256_HC_WIRE_VIEW hc;
    AP6256_FIPS_SESSION fips;
    RtlZeroMemory(View, sizeof(*View)); *Generation = 0; *HostCipher = FALSE;
    if (!Wire || Length < 4) return FALSE;
    if (RtlEqualMemory(Wire, "HCW1", 4)) {
        if (Length < AP6256_HC_WIRE_HEADER || !Ap6256RawGenerationCurrent(Ctx, IfIndex,
            Wire[8] | ((ULONG)Wire[9] << 8) | ((ULONG)Wire[10] << 16) | ((ULONG)Wire[11] << 24), TRUE) ||
            !Ap6256HostCipherDataRxRead(&Ctx->HostCipherStore, IfIndex, Wire, Length, &hc)) return FALSE;
        View->Frame = hc.Frame; View->Length = hc.Length; View->FrameControl = hc.FrameControl;
        View->SequenceControl = hc.SequenceControl; View->Tid = hc.Tid;
        View->HeaderLength = (hc.FrameControl & 0xfcu) == 0x88u ? ((hc.FrameControl & 0x8000u) ? 30u : 26u) : 24u;
        RtlCopyMemory(Generation, Wire + 8, sizeof(*Generation)); *HostCipher = TRUE; return TRUE;
    }
    if (Ap6256HostCipherPacketActive(Ctx, IfIndex) || !Ap6256FipsSnapshot(Ctx, IfIndex, &fips) ||
        !Ap6256FipsReadEnvelope(&fips, AP6256_FIPS_RX, Wire, Length, View)) return FALSE;
    *Generation = fips.Generation; return TRUE;
}

_Use_decl_annotations_
BOOLEAN Ap6256RawRxFrame(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, ULONG Generation,
    BOOLEAN HostCipher, const UCHAR* Frame, ULONG Length, AP6256_FIPS_FRAME_VIEW* View)
{
    AP6256_FIPS_SESSION fips;
    RtlZeroMemory(View, sizeof(*View));

    if (HostCipher || !Ap6256RawGenerationCurrent(Ctx, IfIndex, Generation, FALSE)) return FALSE;
    return Ap6256FipsSnapshot(Ctx, IfIndex, &fips) &&
        fips.Generation == Generation && Ap6256FipsValidateFrame(&fips, AP6256_FIPS_RX, Frame, Length, View);
}

static VOID HcIndicateData(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, UCHAR* Plain, ULONG Length)
{
    AP6256_FIPS_FRAME_VIEW view;
    ULONG generation = 0, filter, needed;
    BOOLEAN hostCipher;
    const UCHAR* address;
    if (Ap6256RawRxRead(Ctx, IfIndex, Plain, Length, &view, &generation, &hostCipher)) {
        address = view.Frame + 4;
        filter = (ULONG)InterlockedCompareExchange(IfIndex == 0 ? &Ctx->PacketFilter : &Ctx->Go.PacketFilter, 0, 0);
        needed = RtlEqualMemory(address, "\xff\xff\xff\xff\xff\xff", 6) ? AP6256_RXF_BROADCAST :
            (address[0] & 1u) ? AP6256_RXF_MULTICAST | AP6256_RXF_ALL_MULTICAST : AP6256_RXF_DIRECTED;
        if ((filter & AP6256_RXF_PROMISCUOUS) || (filter & needed)) {
            InterlockedIncrement(&Ctx->RxFrames); Ap6256NetRxIndicate(Ctx, Plain, Length, view.Tid & 7u, IfIndex);
        } else InterlockedIncrement(&Ctx->RxFiltered);
    }
}

static VOID HcReceiveData(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex, const UCHAR* Wire, ULONG Length)
{
    const ULONG capacity = AP6256_HC_MAX_FRAME + AP6256_HC_WIRE_HEADER;
    UCHAR* plain;
    UCHAR* single = NULL;
    AP6256_HC_AMSDU_CURSOR cursor;
    ULONG written = 0, subframeBytes;
    plain = ExAllocatePool2(POOL_FLAG_NON_PAGED, capacity, AP6256_POOL_TAG);
    if (!plain) return;
    if (NT_SUCCESS(Ap6256HostCipherDataRx(&Ctx->HostCipherStore, IfIndex, Wire, Length, plain, capacity, &written)) && written) {
        if (Ap6256HostCipherDataRxAmsduBegin(&Ctx->HostCipherStore, IfIndex, plain, written, &cursor)) {
            single = ExAllocatePool2(POOL_FLAG_NON_PAGED, capacity, AP6256_POOL_TAG);
            if (single) {
                while (Ap6256HostCipherDataRxAmsduNext(&Ctx->HostCipherStore, IfIndex, &cursor,
                    single, capacity, &subframeBytes)) HcIndicateData(Ctx, IfIndex, single, subframeBytes);
            }
        } else HcIndicateData(Ctx, IfIndex, plain, written);
    }
    if (single) { RtlSecureZeroMemory(single, capacity); ExFreePoolWithTag(single, AP6256_POOL_TAG); }
    RtlSecureZeroMemory(plain, AP6256_HC_MAX_FRAME + AP6256_HC_WIRE_HEADER);
    ExFreePoolWithTag(plain, AP6256_POOL_TAG);
}

_Use_decl_annotations_
BOOLEAN Ap6256RawTxCurrent(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Wire, ULONG Length)
{
    if (Wire && Length >= 4 && RtlEqualMemory(Wire, "HCW1", 4))
        return HcPacketReady(Ctx, IfIndex) &&
            !Ap6256FipsActive(Ctx, IfIndex) && Ap6256HostCipherPathTxCurrent(&Ctx->HostCipherStore, IfIndex, Wire, Length);
    return !Ap6256HostCipherPacketActive(Ctx, IfIndex) && Ap6256FipsTxCurrent(Ctx, IfIndex, Wire, Length);
}

_Use_decl_annotations_
BOOLEAN Ap6256RawDestination(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Wire, ULONG Length, UCHAR* Destination)
{
    AP6256_FIPS_SESSION session;
    AP6256_FIPS_FRAME_VIEW view;
    RtlZeroMemory(Destination, 6);
    if (!Ap6256RawTxCurrent(Ctx, IfIndex, Wire, Length)) return FALSE;
    if (RtlEqualMemory(Wire, "HCW1", 4))
        return Ap6256HostCipherPathDestination(&Ctx->HostCipherStore, IfIndex, Wire, Length, Destination);
    if (!Ap6256FipsSnapshot(Ctx, IfIndex, &session) ||
        !Ap6256FipsReadEnvelope(&session, AP6256_FIPS_TX, Wire, Length, &view)) return FALSE;
    RtlCopyMemory(Destination, view.Frame + 4, 6); return TRUE;
}

_Use_decl_annotations_
BOOLEAN Ap6256RawBcdcTxCurrent(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Bcdc, ULONG Length)
{
    ULONG skip;
    UINT32 ifIndex;
    if (!Bcdc || Length < 4) return FALSE;
    skip = 4u + 4u * Bcdc[3]; if (skip > Length) return FALSE;
    ifIndex = Bcdc[2] & 15u;
    return (Bcdc[0] & 3u) == AP6256_FIPS_BCDC_TX_EXEMPT ?
        Ap6256RawTxCurrent(Ctx, ifIndex, Bcdc + skip, Length - skip) :
        !Ap6256FipsActive(Ctx, ifIndex) && !Ap6256HostCipherPacketActive(Ctx, ifIndex);
}

_Use_decl_annotations_
VOID Ap6256HostCipherReceiveManagement(PAP6256_DEVICE_CONTEXT Ctx, UINT32 IfIndex,
    const UCHAR* Wire, ULONG Length)
{
    const ULONG replyBytes = AP6256_HC_WIRE_TX_HEADER + AP6256_HC_MAX_MANAGEMENT;
    UCHAR* reply;
    ULONG written = 0;
    NTSTATUS status;
    if (!HcPacketReady(Ctx, IfIndex) ||
        Ap6256FipsActive(Ctx, IfIndex) || !Wire || Length < AP6256_HC_WIRE_HEADER) return;
    if (Wire[19] == AP6256_HC_DATA_RX) { HcReceiveData(Ctx, IfIndex, Wire, Length); return; }
    if (Wire[19] != AP6256_HC_MGMT_RX && Wire[19] != AP6256_HC_MGMT_TX_REQUEST) return;
    reply = ExAllocatePool2(POOL_FLAG_NON_PAGED, replyBytes + AP6256_HC_MAX_FRAME, AP6256_POOL_TAG);
    if (!reply) return;
    status = Ap6256HostCipherManagementReply(&Ctx->HostCipherStore, IfIndex, Wire, Length,
        reply, replyBytes, reply + replyBytes, AP6256_HC_MAX_FRAME, &written);
    if (NT_SUCCESS(status) && Ap6256RawTxCurrent(Ctx, IfIndex, reply, written)) {
        if (Ap6256WlfcEnabled(Ctx))
            (VOID)Ap6256WlfcEnqueue(Ctx, reply, written, 0, AP6256_FIPS_BCDC_TX_EXEMPT,
                (UCHAR)IfIndex, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL, NULL);
        else (VOID)Ap6256DatapathTransmitEx(Ctx, reply, written, 0, AP6256_FIPS_BCDC_TX_EXEMPT,
            (UCHAR)IfIndex, AP6256_STATION_PORT, AP6256_WLFC_ANY, NULL);
    }
    RtlSecureZeroMemory(reply, replyBytes + AP6256_HC_MAX_FRAME);
    ExFreePoolWithTag(reply, AP6256_POOL_TAG);
}
