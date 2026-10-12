/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "p2p.h"
#include "bcdc.h"
#include "sdpcm.h"
#include "wifi_ops.h"
#include "trace.h"

static const UCHAR Ap6256P2pOui[4] = { 0x50, 0x6F, 0x9A, 0x09 };

static const UCHAR Ap6256WpsOui[3] = { 0x00, 0x50, 0xF2 };
#define AP6256_WPS_DEVICE_TYPE_OUI4  0x04u

#define AP6256_WPS_ATTR_DEVICE_NAME  0x1011u

#define AP6256_P2P_ATTR_STATUS            0u
#define AP6256_P2P_ATTR_CAPABILITY        2u
#define AP6256_P2P_ATTR_DEVICE_ID         3u
#define AP6256_P2P_ATTR_LISTEN_CHANNEL    6u
#define AP6256_P2P_ATTR_EXT_LISTEN_TIMING 8u
#define AP6256_P2P_ATTR_DEVICE_INFO      13u
#define AP6256_P2P_ATTR_INTERFACE        16u
#define AP6256_P2P_ATTR_OPERATING_CHANNEL 17u

#define AP6256_P2P_LISTEN_OPERATING_CLASS 81u

#define AP6256_P2P_LISTEN_ACTIVE_DEFAULT   20u
#define AP6256_P2P_LISTEN_CYCLE_DEFAULT   130u
#define AP6256_P2P_LISTEN_ACTIVE_HIGH     300u
#define AP6256_P2P_LISTEN_CYCLE_HIGH      400u

#define AP6256_P2P_LISTEN_OFF          0u
#define AP6256_P2P_LISTEN_AUTOMATIC   16u
#define AP6256_P2P_LISTEN_HIGH        24u
#define AP6256_P2P_LISTEN_ANY       0x18u

#define AP6256_P2P_IE_MAX  256u

static PUCHAR Ap6256P2pWriteHeader(_Inout_opt_ PUCHAR At, _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 6u);
    if (At == NULL) return NULL;

    At[0] = 0xDDu;
    At[1] = 0;
    RtlCopyMemory(At + 2, Ap6256P2pOui, sizeof(Ap6256P2pOui));
    return At + 6;
}

static PUCHAR Ap6256P2pWriteAttrHeader(_In_ PUCHAR At, _In_ UCHAR Id,
                                       _In_ USHORT Length)
{
    At[0] = Id;
    At[1] = (UCHAR)(Length & 0xFFu);
    At[2] = (UCHAR)(Length >> 8);
    return At + 3;
}

static PUCHAR Ap6256P2pWriteStatus(_Inout_opt_ PUCHAR At, _In_ UCHAR Status,
                                   _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 4u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_STATUS, 1);
    *At++ = Status;
    return At;
}

static PUCHAR Ap6256P2pWriteCapability(_Inout_opt_ PUCHAR At,
                                       _In_ UCHAR DeviceCapability,
                                       _In_ UCHAR GroupCapability,
                                       _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 5u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_CAPABILITY, 2);
    *At++ = DeviceCapability;
    *At++ = GroupCapability;
    return At;
}

static PUCHAR Ap6256P2pWriteDeviceId(_Inout_opt_ PUCHAR At,
                                     _In_reads_(6) const UCHAR* Address,
                                     _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 9u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_DEVICE_ID, 6);
    RtlCopyMemory(At, Address, 6);
    return At + 6;
}

static PUCHAR Ap6256P2pWriteListenChannel(_Inout_opt_ PUCHAR At,
                                          _In_reads_(3) const UCHAR* Country,
                                          _In_ UCHAR Channel,
                                          _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 8u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_LISTEN_CHANNEL, 5);
    RtlCopyMemory(At, Country, 3);
    At += 3;
    *At++ = AP6256_P2P_LISTEN_OPERATING_CLASS;
    *At++ = Channel;
    return At;
}

static PUCHAR Ap6256P2pWriteOperatingChannel(_Inout_opt_ PUCHAR At,
                                             _In_reads_(3) const UCHAR* Country,
                                             _In_ UCHAR OperatingClass,
                                             _In_ UCHAR Channel,
                                             _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 8u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_OPERATING_CHANNEL, 5);
    RtlCopyMemory(At, Country, 3);
    At += 3;
    *At++ = OperatingClass;
    *At++ = Channel;
    return At;
}

static PUCHAR Ap6256P2pWriteExtListenTiming(_Inout_opt_ PUCHAR At,
                                            _In_ UINT16 AvailabilityPeriod,
                                            _In_ UINT16 AvailabilityInterval,
                                            _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 7u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_EXT_LISTEN_TIMING, 4);
    *At++ = (UCHAR)(AvailabilityPeriod & 0xFFu);
    *At++ = (UCHAR)(AvailabilityPeriod >> 8);
    *At++ = (UCHAR)(AvailabilityInterval & 0xFFu);
    *At++ = (UCHAR)(AvailabilityInterval >> 8);
    return At;
}

static PUCHAR Ap6256P2pWriteInterface(_Inout_opt_ PUCHAR At,
                                      _In_reads_(6) const UCHAR* DeviceAddress,
                                      _In_reads_(6) const UCHAR* InterfaceAddress,
                                      _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 16u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_INTERFACE, 13);
    RtlCopyMemory(At, DeviceAddress, 6);
    At += 6;
    *At++ = 1;
    RtlCopyMemory(At, InterfaceAddress, 6);
    return At + 6;
}

static BOOLEAN Ap6256P2pDeviceTypeKnown(_In_ UINT16 Category,
                                        _In_ UINT16 Subcategory)
{
    static const UCHAR maxSubcategory[] = {
        0,
        8,
        9,
        5,
        4,
        1,
        4,
        4,
        6,
        5,
        5,
        6
    };

    if (Subcategory == 0) return FALSE;
    if (Category == 0 || Category >= RTL_NUMBER_OF(maxSubcategory)) {
        return FALSE;
    }
    return (BOOLEAN)(Subcategory <= maxSubcategory[Category]);
}

static VOID Ap6256P2pWriteBe16(_In_ PUCHAR At, _In_ UINT16 Value)
{
    At[0] = (UCHAR)(Value >> 8);
    At[1] = (UCHAR)(Value & 0xFFu);
}

static PUCHAR Ap6256P2pWriteDeviceInfo(_Inout_opt_ PUCHAR At,
                                       _In_ const AP6256_P2P_STATE* P2p,
                                       _Inout_ PUSHORT Length)
{
    USHORT body = (USHORT)(P2p->DeviceNameLength + 4u +
                           8u * P2p->SecondaryCount + 17u);
    ULONG i;

    *Length = (USHORT)(*Length + body + 3u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_DEVICE_INFO, body);

    RtlCopyMemory(At, P2p->DeviceAddress, 6);
    At += 6;
    Ap6256P2pWriteBe16(At, P2p->ConfigMethods);
    At += 2;

    Ap6256P2pWriteBe16(At, P2p->PrimaryType.Category);
    At += 2;
    RtlCopyMemory(At, Ap6256WpsOui, sizeof(Ap6256WpsOui));
    At += 3;
    *At++ = Ap6256P2pDeviceTypeKnown(P2p->PrimaryType.Category,
                                     P2p->PrimaryType.Subcategory)
                ? AP6256_WPS_DEVICE_TYPE_OUI4 : 0u;
    Ap6256P2pWriteBe16(At, P2p->PrimaryType.Subcategory);
    At += 2;

    *At++ = (UCHAR)P2p->SecondaryCount;
    for (i = 0; i < P2p->SecondaryCount; i++) {
        Ap6256P2pWriteBe16(At, P2p->Secondary[i].Category);
        At += 2;
        RtlCopyMemory(At, P2p->Secondary[i].Oui, 4);
        At += 4;
        Ap6256P2pWriteBe16(At, P2p->Secondary[i].Subcategory);
        At += 2;
    }

    Ap6256P2pWriteBe16(At, AP6256_WPS_ATTR_DEVICE_NAME);
    At += 2;
    Ap6256P2pWriteBe16(At, (UINT16)P2p->DeviceNameLength);
    At += 2;
    RtlCopyMemory(At, P2p->DeviceName, P2p->DeviceNameLength);
    return At + P2p->DeviceNameLength;
}

static VOID Ap6256P2pBuildProbeRequest(_In_ const AP6256_P2P_STATE* P2p,
                                       _Inout_opt_ PUCHAR At,
                                       _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);
    cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                      P2p->GroupCapability, Length);
    if (!P2p->OmitProbeRequestListenChannel) {
        cursor = Ap6256P2pWriteListenChannel(cursor, P2p->CountryString,
                                             P2p->ListenChannel, Length);
    }
    if (P2p->Listening) {
        cursor = Ap6256P2pWriteExtListenTiming(cursor, P2p->ListenActiveMs,
                                               P2p->ListenCycleMs, Length);
    }
    cursor = Ap6256P2pWriteOperatingChannel(cursor, P2p->CountryString,
                                            P2p->OperatingClass,
                                            P2p->OperatingChannel, Length);
    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

static VOID Ap6256P2pBuildProbeResponse(_In_ const AP6256_P2P_STATE* P2p,
                                        _Inout_opt_ PUCHAR At,
                                        _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);
    cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                      P2p->GroupCapability, Length);
    if (P2p->Listening) {
        cursor = Ap6256P2pWriteExtListenTiming(cursor, P2p->ListenActiveMs,
                                               P2p->ListenCycleMs, Length);
    }
    cursor = Ap6256P2pWriteDeviceInfo(cursor, P2p, Length);
    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

static VOID Ap6256P2pBuildBeacon(_In_ const AP6256_P2P_STATE* P2p,
                                 _Inout_opt_ PUCHAR At,
                                 _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);
    cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                      P2p->GroupCapability, Length);
    cursor = Ap6256P2pWriteDeviceId(cursor, P2p->DeviceAddress, Length);
    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

static VOID Ap6256P2pBuildAssocResponse(_In_ const AP6256_P2P_STATE* P2p,
                                        _Inout_opt_ PUCHAR At,
                                        _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);
    cursor = Ap6256P2pWriteStatus(cursor, P2p->AssocStatus, Length);
    if (P2p->Listening) {
        cursor = Ap6256P2pWriteExtListenTiming(cursor, P2p->ListenActiveMs,
                                               P2p->ListenCycleMs, Length);
    }
    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

static VOID Ap6256P2pBuildAssocRequest(_In_ const AP6256_P2P_STATE* P2p,
                                       _In_reads_(6) const UCHAR* Interface,
                                       _Inout_opt_ PUCHAR At,
                                       _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);
    cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability, 0,
                                      Length);
    cursor = Ap6256P2pWriteExtListenTiming(cursor, P2p->ListenActiveMs,
                                           P2p->ListenCycleMs, Length);
    cursor = Ap6256P2pWriteDeviceInfo(cursor, P2p, Length);
    cursor = Ap6256P2pWriteInterface(cursor, P2p->DeviceAddress, Interface,
                                     Length);
    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

#define AP6256_P2P_ATTR_GO_INTENT          4u
#define AP6256_P2P_ATTR_CONFIG_TIMEOUT     5u
#define AP6256_P2P_ATTR_GROUP_BSSID        7u
#define AP6256_P2P_ATTR_INTENDED_INTERFACE 9u
#define AP6256_P2P_ATTR_CHANNEL_LIST      11u
#define AP6256_P2P_ATTR_GROUP_ID          15u
#define AP6256_P2P_ATTR_INVITATION_FLAGS  18u

static PUCHAR Ap6256P2pWriteGoIntent(_Inout_opt_ PUCHAR At, _In_ UCHAR Intent,
                                     _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 4u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_GO_INTENT, 1);
    *At++ = Intent;
    return At;
}

static PUCHAR Ap6256P2pWriteConfigTimeout(_Inout_opt_ PUCHAR At,
                                          _In_ UINT16 GoTimeoutMs,
                                          _In_ UINT16 ClientTimeoutMs,
                                          _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 5u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_CONFIG_TIMEOUT, 2);
    *At++ = (UCHAR)(GoTimeoutMs / 10u);
    *At++ = (UCHAR)(ClientTimeoutMs / 10u);
    return At;
}

static PUCHAR Ap6256P2pWriteAddressAttr(_Inout_opt_ PUCHAR At, _In_ UCHAR Id,
                                        _In_reads_(6) const UCHAR* Address,
                                        _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 9u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, Id, 6);
    RtlCopyMemory(At, Address, 6);
    return At + 6;
}

static PUCHAR Ap6256P2pWriteInvitationFlags(_Inout_opt_ PUCHAR At,
                                            _In_ UCHAR Flags,
                                            _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + 4u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_INVITATION_FLAGS, 1);
    *At++ = Flags;
    return At;
}

static PUCHAR Ap6256P2pWriteGroupId(_Inout_opt_ PUCHAR At,
                                    _In_reads_(6) const UCHAR* DeviceAddress,
                                    _In_reads_bytes_(SsidLength) const UCHAR* Ssid,
                                    _In_ ULONG SsidLength,
                                    _Inout_ PUSHORT Length)
{
    *Length = (USHORT)(*Length + SsidLength + 9u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_GROUP_ID,
                                  (USHORT)(SsidLength + 6u));
    RtlCopyMemory(At, DeviceAddress, 6);
    At += 6;
    RtlCopyMemory(At, Ssid, SsidLength);
    return At + SsidLength;
}

UCHAR Ap6256P2pChannelClass(_In_ UINT32 Channel)
{
    if (Channel >= 1 && Channel <= 13) return 81;
    if (Channel >= 36 && Channel <= 48 && (Channel % 4u) == 0) return 115;
    if (Channel >= 52 && Channel <= 64 && (Channel % 4u) == 0) return 118;
    if (Channel >= 100 && Channel <= 144 && (Channel % 4u) == 0) return 121;
    if (Channel >= 149 && Channel <= 165 && ((Channel - 149u) % 4u) == 0) return 125;
    return 0;
}

static BOOLEAN Ap6256P2pChannelInClass(_In_ UCHAR Class, _In_ UINT32 Channel)
{
    UCHAR canonical = Ap6256P2pChannelClass(Channel);
    return (BOOLEAN)(canonical != 0 && (Class == canonical ||
        (Class == 124 && canonical == 125 && Channel <= 161)));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pGetChannelPlan(_In_ PAP6256_DEVICE_CONTEXT Ctx,
    _In_ ULONG DisallowedBands, _Out_ AP6256_P2P_CHANNEL_PLAN* Plan)
{
    UINT32 valid[65] = {64};
    UINT32 station = 0, channel;
    ULONG index;
    NTSTATUS status;
    RtlZeroMemory(Plan, sizeof(*Plan));
    if (Ctx->FirmwareLinkUp) {
        status = Ap6256WifiGetChannel(Ctx, &station);
        if (!NT_SUCCESS(status)) return status;
        if (station == 0) return STATUS_DEVICE_NOT_READY;
    }
    status = Ap6256BcdcQueryDcmd(Ctx, BRCMF_C_GET_VALID_CHANNELS, valid, sizeof(valid));
    if (!NT_SUCCESS(status)) return status;
    if (valid[0] == 0 || valid[0] > 64) return STATUS_DEVICE_PROTOCOL_ERROR;

    for (channel = 1; channel <= 165; channel++) {
        UCHAR opClass = Ap6256P2pChannelClass(channel);
        if (opClass == 0 || opClass == 118 || opClass == 121 ||
            (DisallowedBands & (channel <= 13 ? 1u : 2u)) ||
            (station && !Ctx->FirmwareMchanSupported && channel != station)) continue;
        for (index = 1; index <= valid[0]; index++) {
            if (valid[index] == channel) {
                Plan->Channels[Plan->Count] = (UCHAR)channel;
                Plan->Classes[Plan->Count++] = opClass;
                break;
            }
        }
    }
    if (Plan->Count == 0) return STATUS_DEVICE_NOT_READY;
    Plan->OperatingChannel = Plan->Channels[0];
    Plan->OperatingClass = Plan->Classes[0];
    for (index = 0; index < Plan->Count; index++) {
        if (Plan->Channels[index] == (station ? station : Ctx->P2p.OperatingChannel)) {
            Plan->OperatingChannel = Plan->Channels[index];
            Plan->OperatingClass = Plan->Classes[index];
            break;
        }
    }
    return STATUS_SUCCESS;
}

static BOOLEAN Ap6256P2pParseAttributes(
    _In_reads_bytes_(Length) const UCHAR* cursor, _In_ ULONG Length,
    _Inout_ AP6256_P2P_PEER_INFO* Peer)
{
    while (Length >= 3) {
        ULONG size, pos;
        UCHAR id;
        const UCHAR* value;
        id = cursor[0];
        size = cursor[1] | ((ULONG)cursor[2] << 8);
        if (size > Length - 3u) return FALSE;
        value = cursor + 3;
        switch (id) {
        case AP6256_P2P_ATTR_STATUS:
            if (size != 1 || Peer->HaveStatus) return FALSE;
            Peer->HaveStatus = TRUE; Peer->Status = value[0];
            break;
        case AP6256_P2P_ATTR_GO_INTENT:
            if (size != 1 || Peer->HaveIntent || value[0] > 31) return FALSE;
            Peer->HaveIntent = TRUE; Peer->Intent = value[0];
            break;
        case AP6256_P2P_ATTR_LISTEN_CHANNEL:
            if (size != 5) return FALSE;
            if (value[2] == 4 && Ap6256P2pChannelInClass(value[3], value[4]))
                Peer->ListenChannel = value[4];
            break;
        case AP6256_P2P_ATTR_OPERATING_CHANNEL:
            if (size != 5 || Peer->HaveOperatingChannel) return FALSE;
            Peer->HaveOperatingChannel = TRUE;
            Peer->OperatingClass = value[2] == 4 ? value[3] : 0;
            Peer->OperatingChannel = value[4];
            break;
        case AP6256_P2P_ATTR_GROUP_ID:
            if (size < 6 || size > 38) return FALSE;
            Peer->GroupSsidLength = (UCHAR)(size - 6);
            break;
        case AP6256_P2P_ATTR_CHANNEL_LIST:
            if (size < 3 || Peer->HaveChannelList) return FALSE;
            Peer->HaveChannelList = TRUE;
            for (pos = 3; pos < size;) {
                ULONG count, i;
                UCHAR opClass;
                if (size - pos < 2) return FALSE;
                opClass = value[pos++]; count = value[pos++];
                if (count == 0 || count > size - pos) return FALSE;
                for (i = 0; i < count; i++) {
                    UCHAR ch = value[pos + i];
                    if (value[2] == 4 && Ap6256P2pChannelInClass(opClass, ch))
                        Peer->ChannelClasses[ch] = opClass;
                }
                pos += count;
            }
            break;
        default:
            break;
        }
        cursor += size + 3u;
        Length -= size + 3u;
    }
    return (BOOLEAN)(Length == 0);
}

BOOLEAN Ap6256P2pParsePeerIes(_In_reads_bytes_opt_(Length) const UCHAR* Ies,
    _In_ ULONG Length, _Out_ AP6256_P2P_PEER_INFO* Peer)
{
    UCHAR attributes[1024] = {0};
    ULONG used = 0;
    RtlZeroMemory(Peer, sizeof(*Peer));
    if (Ies == NULL) return (BOOLEAN)(Length == 0);
    while (Length >= 2) {
        ULONG size = (ULONG)Ies[1] + 2u;
        if (size > Length) return FALSE;
        if (Ies[0] == 221 && size >= 6 &&
            RtlEqualMemory(Ies + 2, Ap6256P2pOui, 4)) {
            ULONG bytes = size - 6u;
            if (bytes > sizeof(attributes) - used) return FALSE;
            RtlCopyMemory(attributes + used, Ies + 6, bytes);
            used += bytes;
        }
        Ies += size;
        Length -= size;
    }
    if (Length != 0) return FALSE;
    return Ap6256P2pParseAttributes(attributes, used, Peer);
}

VOID Ap6256P2pTraceAction(_In_ BOOLEAN Transmit, _In_ UCHAR Subtype,
    _In_ UCHAR Token, _In_ UINT32 Channel,
    _In_reads_bytes_opt_(Length) const UCHAR* Ies, _In_ ULONG Length)
{
    AP6256_P2P_PEER_INFO peer;
    BOOLEAN valid = Ap6256P2pParsePeerIes(Ies, Length, &peer);
    ULONG index, count = 0;
    for (index = 1; index < RTL_NUMBER_OF(peer.ChannelClasses); index++)
        if (peer.ChannelClasses[index] != 0) count++;
    TraceDiag("P2P negotiation %s: subtype %u token %u tx/rx-channel %u "
              "valid %u status %u intent-byte %u op %u/%u listen %u "
              "channel-list %u usable %u group-ssid %u\n",
              Transmit ? "TX" : "RX", (ULONG)Subtype, (ULONG)Token, Channel,
              (ULONG)valid, peer.HaveStatus ? (ULONG)peer.Status : 255u,
              peer.HaveIntent ? (ULONG)peer.Intent : 255u,
              (ULONG)peer.OperatingClass, (ULONG)peer.OperatingChannel,
              (ULONG)peer.ListenChannel, (ULONG)peer.HaveChannelList,
              count, (ULONG)peer.GroupSsidLength);
}

static NTSTATUS Ap6256P2pNegotiateChannels(
    _In_ const AP6256_P2P_ACTION_FRAME* Frame,
    _Inout_ AP6256_P2P_CHANNEL_PLAN* Plan)
{
    AP6256_P2P_PEER_INFO peer;
    ULONG read, write = 0;
    UCHAR preferred = Plan->OperatingChannel;
    UCHAR preferredClass = 0;
    if (!Ap6256P2pParsePeerIes(Frame->PeerIes, Frame->PeerIesLength, &peer))
        return STATUS_INVALID_PARAMETER;

    if (Frame->HaveStatus && Frame->Status != 0) return STATUS_SUCCESS;
    if (Frame->Subtype == AP6256_P2P_AF_GO_NEG_CONF && !Frame->HaveGroupId &&
        (!peer.HaveOperatingChannel ||
         !Ap6256P2pChannelInClass(peer.OperatingClass, peer.OperatingChannel)))
        return STATUS_INVALID_PARAMETER;
    if (peer.HaveChannelList) {
        for (read = 0; read < Plan->Count; read++) {
            UCHAR ch = Plan->Channels[read];
            if (peer.ChannelClasses[ch] == 0) continue;
            Plan->Channels[write] = ch;
            Plan->Classes[write++] = peer.ChannelClasses[ch];
        }
        Plan->Count = write;
        if (write == 0) return STATUS_NOT_SUPPORTED;
    }

    if (peer.HaveOperatingChannel &&
        Ap6256P2pChannelInClass(peer.OperatingClass, peer.OperatingChannel)) {
        preferred = peer.OperatingChannel;
        preferredClass = peer.OperatingClass;
    }
    if (Frame->HaveOperatingChannel) {
        if (!Ap6256P2pChannelInClass(Frame->OperatingClass, Frame->OperatingChannel))
            return STATUS_INVALID_PARAMETER;
        preferred = Frame->OperatingChannel;
        preferredClass = Frame->OperatingClass;
    }
    Plan->OperatingChannel = Plan->Channels[0];
    Plan->OperatingClass = Plan->Classes[0];
    for (read = 0; read < Plan->Count; read++) {
        if (Plan->Channels[read] == preferred) {
            Plan->OperatingChannel = preferred;
            Plan->OperatingClass = preferredClass ? preferredClass : Plan->Classes[read];
            Plan->Classes[read] = Plan->OperatingClass;
            return STATUS_SUCCESS;
        }
    }
    if (Frame->HaveOperatingChannel ||
        (Frame->Subtype == AP6256_P2P_AF_GO_NEG_CONF && !Frame->HaveGroupId))
        return STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

static PUCHAR Ap6256P2pWriteChannelList(_Inout_opt_ PUCHAR At,
                                        _In_reads_(3) const UCHAR* Country,
                                        _In_ const AP6256_P2P_CHANNEL_PLAN* Plan,
                                        _Inout_ PUSHORT Length)
{
    ULONG index, end;
    USHORT body = (USHORT)(3u + Plan->Count);
    for (index = 0; index < Plan->Count; index++)
        if (index == 0 || Plan->Classes[index] != Plan->Classes[index - 1]) body += 2;

    *Length = (USHORT)(*Length + body + 3u);
    if (At == NULL) return NULL;

    At = Ap6256P2pWriteAttrHeader(At, AP6256_P2P_ATTR_CHANNEL_LIST, body);
    RtlCopyMemory(At, Country, 3);
    At += 3;
    for (index = 0; index < Plan->Count; index = end) {
        for (end = index + 1; end < Plan->Count &&
             Plan->Classes[end] == Plan->Classes[index]; end++) { }
        *At++ = Plan->Classes[index];
        *At++ = (UCHAR)(end - index);
        RtlCopyMemory(At, Plan->Channels + index, end - index);
        At += end - index;
    }
    return At;
}

static VOID Ap6256P2pBuildActionIe(_In_ const AP6256_P2P_STATE* P2p,
                                   _In_ const AP6256_P2P_ACTION_FRAME* Frame,
                                   _In_ const AP6256_P2P_CHANNEL_PLAN* Plan,
                                   _Inout_opt_ PUCHAR At,
                                   _Out_ PUSHORT Length)
{
    PUCHAR head = At;
    PUCHAR cursor;

    *Length = 0;
    cursor = Ap6256P2pWriteHeader(At, Length);

    switch (Frame->Subtype) {
    case AP6256_P2P_AF_GO_NEG_REQ:
    case AP6256_P2P_AF_GO_NEG_RSP:
        if (Frame->HaveStatus) {
            cursor = Ap6256P2pWriteStatus(cursor, Frame->Status, Length);
        }
        cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                          Frame->GroupCapability, Length);
        cursor = Ap6256P2pWriteGoIntent(cursor, Frame->GoIntentByte, Length);
        cursor = Ap6256P2pWriteConfigTimeout(cursor, Frame->GoConfigTimeoutMs,
                                             Frame->ClientConfigTimeoutMs,
                                             Length);
        if (Frame->Subtype == AP6256_P2P_AF_GO_NEG_REQ) {
            cursor = Ap6256P2pWriteListenChannel(cursor, P2p->CountryString,
                                                 P2p->ListenChannel, Length);
        }
        cursor = Ap6256P2pWriteOperatingChannel(
            cursor, P2p->CountryString, Plan->OperatingClass,
            Plan->OperatingChannel, Length);
        if (P2p->Listening) {
            cursor = Ap6256P2pWriteExtListenTiming(cursor, P2p->ListenActiveMs,
                                                   P2p->ListenCycleMs, Length);
        }
        if (Frame->HaveIntendedInterface) {
            cursor = Ap6256P2pWriteAddressAttr(
                cursor, AP6256_P2P_ATTR_INTENDED_INTERFACE,
                Frame->IntendedInterface, Length);
        }
        cursor = Ap6256P2pWriteChannelList(cursor, P2p->CountryString, Plan, Length);
        cursor = Ap6256P2pWriteDeviceInfo(cursor, P2p, Length);
        if (Frame->Subtype == AP6256_P2P_AF_GO_NEG_RSP && Frame->HaveGroupId) {
            cursor = Ap6256P2pWriteGroupId(cursor, Frame->GroupDeviceAddress,
                Frame->GroupSsid, Frame->GroupSsidLength, Length);
        }
        break;

    case AP6256_P2P_AF_GO_NEG_CONF:
        cursor = Ap6256P2pWriteStatus(cursor, Frame->Status, Length);
        cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                          Frame->GroupCapability, Length);
        cursor = Ap6256P2pWriteOperatingChannel(
            cursor, P2p->CountryString, Plan->OperatingClass,
            Plan->OperatingChannel, Length);
        cursor = Ap6256P2pWriteChannelList(cursor, P2p->CountryString, Plan, Length);
        if (Frame->HaveGroupId) {
            cursor = Ap6256P2pWriteGroupId(cursor, Frame->GroupDeviceAddress,
                                           Frame->GroupSsid,
                                           Frame->GroupSsidLength, Length);
        }
        break;

    case AP6256_P2P_AF_INVITE_REQ:
    case AP6256_P2P_AF_INVITE_RSP:
        if (Frame->HaveStatus) {
            cursor = Ap6256P2pWriteStatus(cursor, Frame->Status, Length);
        }
        cursor = Ap6256P2pWriteConfigTimeout(cursor, Frame->GoConfigTimeoutMs,
                                             Frame->ClientConfigTimeoutMs,
                                             Length);
        if (Frame->HaveOperatingChannel) {
            cursor = Ap6256P2pWriteOperatingChannel(
                cursor, P2p->CountryString, Plan->OperatingClass,
                Plan->OperatingChannel, Length);
        }
        if (Frame->HaveGroupBssid) {
            cursor = Ap6256P2pWriteAddressAttr(
                cursor, AP6256_P2P_ATTR_GROUP_BSSID, Frame->GroupBssid,
                Length);
        }
        cursor = Ap6256P2pWriteChannelList(cursor, P2p->CountryString, Plan, Length);
        cursor = Ap6256P2pWriteDeviceInfo(cursor, P2p, Length);
        if (Frame->HaveGroupId) {
            cursor = Ap6256P2pWriteGroupId(cursor, Frame->GroupDeviceAddress,
                                           Frame->GroupSsid,
                                           Frame->GroupSsidLength, Length);
        }
        if (Frame->HaveInvitationFlags) {
            cursor = Ap6256P2pWriteInvitationFlags(cursor,
                                                   Frame->InvitationFlags,
                                                   Length);
        }
        break;

    case AP6256_P2P_AF_PROV_DISC_REQ:
    case AP6256_P2P_AF_PROV_DISC_RSP:
    default:
        cursor = Ap6256P2pWriteCapability(cursor, P2p->DeviceCapability,
                                          Frame->GroupCapability, Length);
        cursor = Ap6256P2pWriteDeviceInfo(cursor, P2p, Length);
        if (Frame->HaveGroupId) {
            cursor = Ap6256P2pWriteGroupId(cursor, Frame->GroupDeviceAddress,
                                           Frame->GroupSsid,
                                           Frame->GroupSsidLength, Length);
        }
        break;
    }

    UNREFERENCED_PARAMETER(cursor);
    if (head != NULL) head[1] = (UCHAR)(*Length - 2u);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildActionFrame(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                   _In_ const AP6256_P2P_ACTION_FRAME* Frame,
                                   _Outptr_result_bytebuffer_(*Length)
                                       PUCHAR* Body,
                                   _Out_ PULONG Length,
                                   _Out_writes_(6) PUCHAR Bssid,
                                   _Out_ PUINT32 Channel)
{
    const AP6256_P2P_STATE* p2p = &Ctx->P2p;
    PUCHAR body;
    USHORT ieLength = 0;
    ULONG total;
    AP6256_P2P_CHANNEL_PLAN plan;
    NTSTATUS status;

    *Body = NULL;
    *Length = 0;
    *Channel = Frame->TransmitChannel;
    if (*Channel == 0 || *Channel > 165) return STATUS_INVALID_PARAMETER;
    if (Frame->GroupSsidLength > sizeof(Frame->GroupSsid)) return STATUS_INVALID_PARAMETER;

    if (!Ap6256P2pVendorIesValid(Frame->VendorIes, Frame->VendorIesLength))
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(&plan, sizeof(plan));
    if (Frame->Subtype <= AP6256_P2P_AF_INVITE_RSP) {
        status = Ap6256P2pGetChannelPlan(Ctx, Frame->DisallowedBands, &plan);
        if (NT_SUCCESS(status)) status = Ap6256P2pNegotiateChannels(Frame, &plan);
        if (!NT_SUCCESS(status)) {
            TraceDiag("P2P channel negotiation: subtype %u -> 0x%08X\n",
                      (ULONG)Frame->Subtype, status);
            return status;
        }
    }
    Ap6256P2pBuildActionIe(p2p, Frame, &plan, NULL, &ieLength);
    if (ieLength > AP6256_P2P_IE_MAX ||
        Frame->VendorIesLength > AP6256_P2P_VENDOR_IE_MAX) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    total = AP6256_P2P_ACTION_HEADER + ieLength + Frame->VendorIesLength;

    body = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, total,
                                   AP6256_POOL_TAG);
    if (body == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    if (total < AP6256_P2P_ACTION_HEADER) {
        ExFreePoolWithTag(body, AP6256_POOL_TAG);
        return STATUS_INTERNAL_ERROR;
    }

    body[0] = 4;
    body[1] = 9;
    body[2] = Ap6256P2pOui[0];
    body[3] = Ap6256P2pOui[1];
    body[4] = Ap6256P2pOui[2];
    body[5] = Ap6256P2pOui[3];
    body[6] = Frame->Subtype;
    body[7] = Frame->DialogToken;

    Ap6256P2pBuildActionIe(p2p, Frame, &plan, body + AP6256_P2P_ACTION_HEADER,
                           &ieLength);
    if (Frame->VendorIesLength != 0 && Frame->VendorIes != NULL) {
        RtlCopyMemory(body + AP6256_P2P_ACTION_HEADER + ieLength,
                      Frame->VendorIes, Frame->VendorIesLength);
    }

    switch (Frame->Subtype) {
    case AP6256_P2P_AF_GO_NEG_RSP:
    case AP6256_P2P_AF_INVITE_RSP:
    case AP6256_P2P_AF_PROV_DISC_RSP:
    case AP6256_P2P_AF_DEV_DISC_RSP:
        RtlCopyMemory(Bssid, p2p->DeviceAddress, 6);
        break;
    default:
        RtlCopyMemory(Bssid, Frame->PeerAddress, 6);
        break;
    }

    *Body = body;
    *Length = total;
    Ap6256P2pTraceAction(TRUE, Frame->Subtype, Frame->DialogToken, *Channel,
        body + AP6256_P2P_ACTION_HEADER, total - AP6256_P2P_ACTION_HEADER);

    TraceInfo(TRACE_NETADAPTER,
              "P2P action frame subtype %u, token %u: %u byte(s) on "
              "channel %u\n",
              (ULONG)Frame->Subtype, (ULONG)Frame->DialogToken, total,
              *Channel);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pInitialize(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;

    RtlZeroMemory(p2p, sizeof(*p2p));
    p2p->ListenChannel = 1;
    p2p->OperatingClass = AP6256_P2P_LISTEN_OPERATING_CLASS;
    p2p->OperatingChannel = 1;
    p2p->ListenActiveMs = AP6256_P2P_LISTEN_ACTIVE_DEFAULT;
    p2p->ListenCycleMs = AP6256_P2P_LISTEN_CYCLE_DEFAULT;
    p2p->CountryString[0] = 'X';
    p2p->CountryString[1] = 'X';
    p2p->CountryString[2] = 0x04;
    RtlCopyMemory(p2p->DeviceAddress, Ctx->MacAddress,
                  sizeof(p2p->DeviceAddress));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pSetCountry(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                         _In_reads_(2) const CHAR* Code)
{
    Ctx->P2p.CountryString[0] = (UCHAR)Code[0];
    Ctx->P2p.CountryString[1] = (UCHAR)Code[1];
    Ctx->P2p.CountryString[2] = 0x04;
}

static const UCHAR Ap6256P2pWildcardSsid[7] = { 'D', 'I', 'R', 'E', 'C', 'T', '-' };

#define AP6256_P2P_SEARCH_DWELL_MS    30u
#define AP6256_P2P_LISTEN_QUANTUM_MS 100u
#define AP6256_P2P_LISTEN_QUANTA      10u
#define AP6256_P2P_SCAN_POLL_MS       20u

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256P2pSubmitDiscoveryScan(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    const AP6256_P2P_DISCOVER* discover = &p2p->Discover;
    const AP6256_P2P_DISCOVER_SSID* ssid = &discover->Ssids[p2p->DiscoverSsidIndex];
    AP6256_P2P_SCAN scan;
    NTSTATUS status;
    UINT32 state;

    RtlZeroMemory(&scan, sizeof(scan));
    scan.SsidLength = ssid->Length;
    if (scan.SsidLength != 0) RtlCopyMemory(scan.Ssid, ssid->Data, scan.SsidLength);
    else {
        scan.SsidLength = sizeof(Ap6256P2pWildcardSsid);
        RtlCopyMemory(scan.Ssid, Ap6256P2pWildcardSsid, scan.SsidLength);
    }
    scan.Passive = (BOOLEAN)!discover->ActiveScan;
    scan.NProbes = 1;
    scan.ActiveTimeMs = discover->ActiveDwellMs != 0
        ? (INT32)discover->ActiveDwellMs : AP6256_P2P_SEARCH_DWELL_MS;
    scan.PassiveTimeMs = discover->PassiveDwellMs != 0
        ? (INT32)discover->PassiveDwellMs : AP6256_P2P_SEARCH_DWELL_MS;
    if (discover->ChannelCount != 0) {
        const AP6256_P2P_DISCOVER_CHANNEL* channel = &discover->Channels[p2p->DiscoverChannelIndex];
        scan.ChannelCount = 1;
        scan.Channels[0] = channel->Number;
        if (channel->DwellMs != 0) {
            scan.ActiveTimeMs = (INT32)channel->DwellMs;
            scan.PassiveTimeMs = (INT32)channel->DwellMs;
        }
        if (p2p->DiscoverSsidIndex == 0)
            p2p->DiscoverChannelDeadline = (LONGLONG)(KeQueryInterruptTime() / 10000ull) + channel->CycleMs;
    } else if (p2p->DiscoverSearch) {
        scan.ChannelCount = 3;
        scan.Channels[0] = 1;
        scan.Channels[1] = 6;
        scan.Channels[2] = 11;
    }

    p2p->DiscoverPhase = p2p->DiscoverSearch ? Ap6256P2pDiscoverSearch : Ap6256P2pDiscoverScan;
    state = p2p->DiscoverSearch && discover->DiscoveryType != AP6256_P2P_DISCOVER_SOCIAL_ONLY
        ? AP6256_P2P_DISC_SEARCH : AP6256_P2P_DISC_SCAN;
    status = Ap6256WifiSetP2pDiscoveryState(Ctx, state, 0, 0);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&p2p->DiscoverScanPending, 1);
        status = Ap6256WifiP2pScan(Ctx, &scan);
        if (!NT_SUCCESS(status)) InterlockedExchange(&p2p->DiscoverScanPending, 0);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256P2pStartDiscoveryPass(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    p2p->DiscoverSsidIndex = 0;
    p2p->DiscoverChannelIndex = 0;
    p2p->DiscoverPassComplete = FALSE;
    p2p->DiscoverSearch = (BOOLEAN)(
        p2p->Discover.DiscoveryType == AP6256_P2P_DISCOVER_FIND_ONLY ||
        p2p->Discover.DiscoveryType == AP6256_P2P_DISCOVER_SOCIAL_ONLY);
    p2p->DiscoverDeadline = (LONGLONG)(KeQueryInterruptTime() / 10000ull) + p2p->Discover.MaximumDwellMs;
    return Ap6256P2pSubmitDiscoveryScan(Ctx);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pStartDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ const AP6256_P2P_DISCOVER* Discover)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    NTSTATUS status;
    ULONG index;

    if (p2p->DiscoverPhase != Ap6256P2pDiscoverIdle) return STATUS_INVALID_DEVICE_STATE;
    if (Discover->SsidCount > AP6256_P2P_DISCOVER_SSID_MAX ||
        Discover->ChannelCount > AP6256_P2P_DISCOVER_CHANNEL_MAX ||
        Discover->MaximumDwellMs == 0) return STATUS_INVALID_PARAMETER;
    for (index = 0; index < Discover->SsidCount; index++)
        if (Discover->Ssids[index].Length > sizeof(Discover->Ssids[index].Data))
            return STATUS_INVALID_PARAMETER;

    p2p->Discover = *Discover;
    p2p->OmitProbeRequestListenChannel = Discover->OmitListenChannel;
    if (p2p->Discover.SsidCount == 0) {
        p2p->Discover.SsidCount = 1;
        p2p->Discover.Ssids[0].Length = 0;
    }
    p2p->DiscoverStatus = STATUS_SUCCESS;
    p2p->DiscoverScansCompleted = 0;

    status = Ap6256P2pBuildIes(Ctx);
    if (NT_SUCCESS(status)) status = Ap6256P2pStartDiscoveryPass(Ctx);
    if (!NT_SUCCESS(status)) {
        p2p->DiscoverStatus = status;
        Ap6256P2pStopDiscovery(Ctx);
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pStopDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;

    p2p->OmitProbeRequestListenChannel = FALSE;
    if (p2p->DiscoverPhase == Ap6256P2pDiscoverIdle) return;

    p2p->DiscoverPhase = Ap6256P2pDiscoverIdle;
    if (InterlockedExchange(&p2p->DiscoverScanPending, 0) != 0) {
        NTSTATUS status = Ap6256WifiScanAbort(Ctx);
        if (!NT_SUCCESS(status)) p2p->DiscoverStatus = status;
    }

    {
        NTSTATUS status = Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_SCAN, 0, 0);
        if (!NT_SUCCESS(status) && NT_SUCCESS(p2p->DiscoverStatus)) p2p->DiscoverStatus = status;
        status = Ap6256P2pBuildIes(Ctx);
        if (!NT_SUCCESS(status) && NT_SUCCESS(p2p->DiscoverStatus)) p2p->DiscoverStatus = status;
    }

    TraceInfo(TRACE_NETADAPTER, "P2P discovery stopped\n");
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pResetDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                  _In_ BOOLEAN SetDefaultMib)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    NTSTATUS status;

    status = Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_SCAN, 0, 0);
    if (!NT_SUCCESS(status)) return status;

    p2p->DiscoverPhase = Ap6256P2pDiscoverIdle;
    InterlockedExchange(&p2p->DiscoverScanPending, 0);
    p2p->DiscoverDeadline = 0;
    RtlZeroMemory(&p2p->Discover, sizeof(p2p->Discover));
    p2p->DiscoverSsidIndex = 0;
    p2p->DiscoverChannelIndex = 0;
    p2p->DiscoverScansCompleted = 0;
    p2p->DiscoverNextScan = 0;
    p2p->DiscoverChannelDeadline = 0;
    p2p->DiscoverPassComplete = FALSE;
    p2p->Listening = FALSE;
    p2p->ListenState = AP6256_P2P_LISTEN_OFF;

    if (SetDefaultMib) {
        static const UINT32 flags[Ap6256P2pFrameMax] = {
            AP6256_P2P_IE_PROBE_REQ, AP6256_P2P_IE_PROBE_RESP,
            AP6256_P2P_IE_BEACON, AP6256_P2P_IE_ASSOC_RESP,
            AP6256_P2P_IE_ASSOC_REQ
        };
        UCHAR address[6];
        UCHAR country[3];
        ULONG frame, host;

        status = Ap6256WifiP2pSetDiscoverySecurity(Ctx, FALSE);
        if (!NT_SUCCESS(status)) return status;

        for (frame = 0; frame < Ap6256P2pFrameMax; frame++) {
            for (host = 0; host < 2; host++) {
                AP6256_P2P_IE_SLOT* slot = host
                    ? &p2p->HostIes[frame] : &p2p->DriverIes[frame];
                if (slot->Bytes == NULL) continue;
                status = Ap6256WifiSetVendorIesIf(Ctx,
                    Ap6256WifiP2pInterface(Ctx), flags[frame] |
                        (host ? AP6256_P2P_IE_CUSTOM : 0),
                    FALSE, slot->Bytes, slot->Length);
                if (!NT_SUCCESS(status)) return status;
                ExFreePoolWithTag(slot->Bytes, AP6256_POOL_TAG);
                slot->Bytes = NULL;
                slot->Length = 0;
            }
        }
        RtlCopyMemory(address, p2p->DeviceAddress, sizeof(address));
        RtlCopyMemory(country, p2p->CountryString, sizeof(country));
        Ap6256P2pInitialize(Ctx);
        RtlCopyMemory(p2p->DeviceAddress, address, sizeof(address));
        RtlCopyMemory(p2p->CountryString, country, sizeof(country));
    }
    TraceDiag("P2P: discovery reset bsscfg %u default MIB %u -> 0x%08X\n",
              Ctx->P2pBssIndex, (ULONG)SetDefaultMib, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static ULONG Ap6256P2pFinishDiscoveryPass(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    NTSTATUS status;
    if (InterlockedExchange(&p2p->DiscoverScanPending, 0) != 0) {
        status = Ap6256WifiScanAbort(Ctx);
        if (!NT_SUCCESS(status)) p2p->DiscoverStatus = status;
    }
    if (p2p->Discover.ScanRepeatCount != 0) p2p->DiscoverScansCompleted++;
    if (!NT_SUCCESS(p2p->DiscoverStatus) ||
        (p2p->Discover.ScanRepeatCount != 0 &&
         p2p->DiscoverScansCompleted >= p2p->Discover.ScanRepeatCount)) {
        Ap6256P2pStopDiscovery(Ctx);
        return 0;
    }
    status = Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_SCAN, 0, 0);
    if (!NT_SUCCESS(status)) {
        p2p->DiscoverStatus = status;
        Ap6256P2pStopDiscovery(Ctx);
        return 0;
    }
    p2p->DiscoverPhase = Ap6256P2pDiscoverRepeat;
    p2p->DiscoverNextScan = (LONGLONG)(KeQueryInterruptTime() / 10000ull) + p2p->Discover.TimeBetweenScans;
    return max(1u, min(p2p->Discover.TimeBetweenScans, 1000u));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static ULONG Ap6256P2pFinishDiscoverySweep(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    LONGLONG now = (LONGLONG)(KeQueryInterruptTime() / 10000ull);
    ULONG listenMs;
    NTSTATUS status;

    p2p->DiscoverPassComplete = TRUE;
    if (p2p->Discover.ChannelCount != 0 ||
        p2p->Discover.DiscoveryType == AP6256_P2P_DISCOVER_SCAN_ONLY ||
        p2p->Discover.DiscoveryType == AP6256_P2P_DISCOVER_SOCIAL_ONLY ||
        now >= p2p->DiscoverDeadline)
        return Ap6256P2pFinishDiscoveryPass(Ctx);

    listenMs = ((ULONG)((KeQueryInterruptTime() >> 10) % AP6256_P2P_LISTEN_QUANTA) + 1u)
        * AP6256_P2P_LISTEN_QUANTUM_MS;
    listenMs = (ULONG)min((LONGLONG)listenMs, p2p->DiscoverDeadline - now);
    p2p->DiscoverPhase = Ap6256P2pDiscoverListen;
    p2p->DiscoverNextScan = now + listenMs;
    status = Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_LISTEN, p2p->ListenChannel, listenMs);
    if (NT_SUCCESS(status)) return listenMs;
    p2p->DiscoverStatus = status;
    Ap6256P2pStopDiscovery(Ctx);
    return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG Ap6256P2pAdvanceDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    LONGLONG now = (LONGLONG)(KeQueryInterruptTime() / 10000ull);
    NTSTATUS status;

    if (p2p->DiscoverPhase == Ap6256P2pDiscoverIdle) return 0;
    if (!NT_SUCCESS(p2p->DiscoverStatus)) {
        Ap6256P2pStopDiscovery(Ctx);
        return 0;
    }
    if (p2p->DiscoverPhase == Ap6256P2pDiscoverRepeat) {
        if (now < p2p->DiscoverNextScan)
            return (ULONG)min(p2p->DiscoverNextScan - now, 1000);
        status = Ap6256P2pStartDiscoveryPass(Ctx);
    } else {
        if (InterlockedCompareExchange(&p2p->DiscoverScanPending, 0, 0) != 0) {
            if (now < p2p->DiscoverDeadline)
                return (ULONG)min(p2p->DiscoverDeadline - now, AP6256_P2P_SCAN_POLL_MS);

            if (p2p->Discover.ForcedDiscovery && !p2p->DiscoverPassComplete)
                p2p->DiscoverStatus = STATUS_IO_TIMEOUT;
            return Ap6256P2pFinishDiscoveryPass(Ctx);
        }

        if (!NT_SUCCESS(p2p->DiscoverStatus)) {
            Ap6256P2pStopDiscovery(Ctx);
            return 0;
        }
        if (p2p->DiscoverPhase == Ap6256P2pDiscoverListen ||
            p2p->DiscoverPhase == Ap6256P2pDiscoverNextChannel) {
            if (now >= p2p->DiscoverDeadline) {
                if (p2p->Discover.ForcedDiscovery && !p2p->DiscoverPassComplete)
                    p2p->DiscoverStatus = STATUS_IO_TIMEOUT;
                return Ap6256P2pFinishDiscoveryPass(Ctx);
            }
            if (now < p2p->DiscoverNextScan)
                return (ULONG)min(min(p2p->DiscoverNextScan, p2p->DiscoverDeadline) - now, 1000);
            if (p2p->DiscoverPhase == Ap6256P2pDiscoverListen) {
                p2p->DiscoverSsidIndex = 0;
                p2p->DiscoverChannelIndex = 0;
                p2p->DiscoverSearch = TRUE;
            } else if (p2p->DiscoverChannelIndex >= p2p->Discover.ChannelCount) {
                return Ap6256P2pFinishDiscoverySweep(Ctx);
            }
            status = Ap6256P2pSubmitDiscoveryScan(Ctx);
        } else {

            p2p->DiscoverSsidIndex++;
            if (p2p->DiscoverSsidIndex == p2p->Discover.SsidCount) {
                p2p->DiscoverSsidIndex = 0;
                p2p->DiscoverChannelIndex++;
                if (p2p->Discover.ChannelCount == 0)
                    return Ap6256P2pFinishDiscoverySweep(Ctx);
                if (p2p->DiscoverChannelIndex == p2p->Discover.ChannelCount)
                    p2p->DiscoverPassComplete = TRUE;
                p2p->DiscoverPhase = Ap6256P2pDiscoverNextChannel;
                p2p->DiscoverNextScan = p2p->DiscoverChannelDeadline;
                if (now < p2p->DiscoverNextScan && now < p2p->DiscoverDeadline)
                    return (ULONG)min(min(p2p->DiscoverNextScan, p2p->DiscoverDeadline) - now, 1000);
                if (p2p->DiscoverChannelIndex == p2p->Discover.ChannelCount)
                    return Ap6256P2pFinishDiscoverySweep(Ctx);
            }
            if (now >= p2p->DiscoverDeadline) {
                if (p2p->Discover.ForcedDiscovery && !p2p->DiscoverPassComplete)
                    p2p->DiscoverStatus = STATUS_IO_TIMEOUT;
                return Ap6256P2pFinishDiscoveryPass(Ctx);
            }
            status = Ap6256P2pSubmitDiscoveryScan(Ctx);
        }
    }
    if (NT_SUCCESS(status)) return AP6256_P2P_SCAN_POLL_MS;
    p2p->DiscoverStatus = status;
    Ap6256P2pStopDiscovery(Ctx);
    return 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
BOOLEAN Ap6256P2pIsSocialChannel(_In_ UINT32 Channel)
{
    return (BOOLEAN)(Channel == 1u || Channel == 6u || Channel == 11u);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256P2pProgramSlot(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 IfIndex,
                                     _Inout_ AP6256_P2P_IE_SLOT* Slot,
                                     _In_ UINT32 PktFlag,
                                     _In_reads_bytes_opt_(Length) const UCHAR* Ies,
                                     _In_ ULONG Length)
{
    PUCHAR replacement = NULL;
    NTSTATUS status;
    if (Length != 0 && Ies == NULL) return STATUS_INVALID_PARAMETER;
    if (Length == Slot->Length && (Length == 0 ||
        (Slot->Bytes != NULL && RtlEqualMemory(Slot->Bytes, Ies, Length))))
        return STATUS_SUCCESS;

    if (Length != 0) {
        replacement = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED, Length, AP6256_POOL_TAG);
        if (replacement == NULL) return STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(replacement, Ies, Length);
    }
    if (Slot->Bytes != NULL) {
        status = Ap6256WifiSetVendorIesIf(Ctx, IfIndex, PktFlag, FALSE, Slot->Bytes, Slot->Length);
        if (!NT_SUCCESS(status)) {
            if (replacement != NULL) ExFreePoolWithTag(replacement, AP6256_POOL_TAG);
            return status;
        }
    }
    status = Length == 0 ? STATUS_SUCCESS :
        Ap6256WifiSetVendorIesIf(Ctx, IfIndex, PktFlag, TRUE, replacement, Length);
    if (!NT_SUCCESS(status)) {
        NTSTATUS restore = Slot->Bytes == NULL ? STATUS_SUCCESS :
            Ap6256WifiSetVendorIesIf(Ctx, IfIndex, PktFlag, TRUE, Slot->Bytes, Slot->Length);
        if (!NT_SUCCESS(restore)) {
            TraceWarn(TRACE_NETADAPTER, "P2P IE restore failed 0x%08X\n", restore);
            ExFreePoolWithTag(Slot->Bytes, AP6256_POOL_TAG);
            Slot->Bytes = NULL;
            Slot->Length = 0;
        }
        ExFreePoolWithTag(replacement, AP6256_POOL_TAG);
        return status;
    }
    if (Slot->Bytes != NULL) ExFreePoolWithTag(Slot->Bytes, AP6256_POOL_TAG);
    Slot->Bytes = replacement;
    Slot->Length = Length;
    return STATUS_SUCCESS;
}

BOOLEAN Ap6256P2pVendorIesValid(const UCHAR* Ies, ULONG Length)
{
    ULONG offset = 0;
    if (Length > AP6256_P2P_VENDOR_IE_MAX || (Length != 0 && Ies == NULL)) return FALSE;
    while (offset < Length) {
        ULONG size;
        if (Length - offset < 2 || Ies[offset] != 221 || Ies[offset + 1] < 3) return FALSE;
        size = (ULONG)Ies[offset + 1] + 2u;
        if (size > Length - offset) return FALSE;
        offset += size;
    }
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pReleaseIes(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256P2pReleaseIesFor(Ctx, &Ctx->P2p, Ap6256WifiP2pInterface(Ctx));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256P2pReleaseIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex)
{
    static const UINT32 flags[Ap6256P2pFrameMax] = {
        AP6256_P2P_IE_PROBE_REQ,  AP6256_P2P_IE_PROBE_RESP,
        AP6256_P2P_IE_BEACON,     AP6256_P2P_IE_ASSOC_RESP,
        AP6256_P2P_IE_ASSOC_REQ
    };
    ULONG i;

    for (i = 0; i < Ap6256P2pFrameMax; i++) {
        (VOID)Ap6256P2pProgramSlot(Ctx, IfIndex, &p2p->DriverIes[i], flags[i],
                                   NULL, 0);
        (VOID)Ap6256P2pProgramSlot(Ctx, IfIndex, &p2p->HostIes[i],
                                   flags[i] | AP6256_P2P_IE_CUSTOM, NULL, 0);
    }
}

_Use_decl_annotations_
VOID Ap6256P2pForgetIesFor(AP6256_P2P_STATE* p2p)
{
    ULONG frame, host;
    for (frame = 0; frame < Ap6256P2pFrameMax; frame++) {
        for (host = 0; host < 2; host++) {
            AP6256_P2P_IE_SLOT* slot = host ? &p2p->HostIes[frame] : &p2p->DriverIes[frame];
            if (slot->Bytes != NULL) ExFreePoolWithTag(slot->Bytes, AP6256_POOL_TAG);
            slot->Bytes = NULL;
            slot->Length = 0;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetHostIes(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                             _In_ AP6256_P2P_FRAME Frame,
                             _In_reads_bytes_opt_(Length) const UCHAR* Ies,
                             _In_ ULONG Length)
{
    return Ap6256P2pSetHostIesFor(Ctx, &Ctx->P2p, Ap6256WifiP2pInterface(Ctx), Frame, Ies, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetHostIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex, AP6256_P2P_FRAME Frame, const UCHAR* Ies, ULONG Length)
{
    static const UINT32 flags[Ap6256P2pFrameMax] = {
        AP6256_P2P_IE_PROBE_REQ,  AP6256_P2P_IE_PROBE_RESP,
        AP6256_P2P_IE_BEACON,     AP6256_P2P_IE_ASSOC_RESP,
        AP6256_P2P_IE_ASSOC_REQ
    };

    if ((ULONG)Frame >= Ap6256P2pFrameMax || !Ap6256P2pVendorIesValid(Ies, Length))
        return STATUS_INVALID_PARAMETER;

    return Ap6256P2pProgramSlot(Ctx, IfIndex, &p2p->HostIes[Frame],
                                flags[Frame] | AP6256_P2P_IE_CUSTOM,
                                Ies, Length);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildIes(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    return Ap6256P2pBuildIesFor(Ctx, &Ctx->P2p, Ap6256WifiP2pInterface(Ctx));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pBuildIesFor(PAP6256_DEVICE_CONTEXT Ctx, AP6256_P2P_STATE* p2p, UINT32 IfIndex)
{
    UCHAR buffer[AP6256_P2P_IE_MAX];
    USHORT length;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG frame;

    for (frame = 0; frame < Ap6256P2pFrameMax && NT_SUCCESS(status); frame++) {
        UINT32 flag;

        RtlZeroMemory(buffer, sizeof(buffer));
        length = 0;
        switch ((AP6256_P2P_FRAME)frame) {
        case Ap6256P2pFrameProbeRequest:
            flag = AP6256_P2P_IE_PROBE_REQ;
            Ap6256P2pBuildProbeRequest(p2p, NULL, &length);
            if (length > sizeof(buffer)) return STATUS_BUFFER_TOO_SMALL;
            Ap6256P2pBuildProbeRequest(p2p, buffer, &length);
            break;
        case Ap6256P2pFrameProbeResponse:
            flag = AP6256_P2P_IE_PROBE_RESP;
            Ap6256P2pBuildProbeResponse(p2p, NULL, &length);
            if (length > sizeof(buffer)) return STATUS_BUFFER_TOO_SMALL;
            Ap6256P2pBuildProbeResponse(p2p, buffer, &length);
            break;
        case Ap6256P2pFrameBeacon:
            flag = AP6256_P2P_IE_BEACON;
            Ap6256P2pBuildBeacon(p2p, NULL, &length);
            if (length > sizeof(buffer)) return STATUS_BUFFER_TOO_SMALL;
            Ap6256P2pBuildBeacon(p2p, buffer, &length);
            break;
        case Ap6256P2pFrameAssocResponse:
            flag = AP6256_P2P_IE_ASSOC_RESP;
            Ap6256P2pBuildAssocResponse(p2p, NULL, &length);
            if (length > sizeof(buffer)) return STATUS_BUFFER_TOO_SMALL;
            Ap6256P2pBuildAssocResponse(p2p, buffer, &length);
            break;
        default:
            flag = AP6256_P2P_IE_ASSOC_REQ;
            Ap6256P2pBuildAssocRequest(p2p, p2p == &Ctx->Go.P2p ? Ctx->Go.Address : Ctx->MacAddress, NULL, &length);
            if (length > sizeof(buffer)) return STATUS_BUFFER_TOO_SMALL;
            Ap6256P2pBuildAssocRequest(p2p, p2p == &Ctx->Go.P2p ? Ctx->Go.Address : Ctx->MacAddress, buffer, &length);
            break;
        }

        status = Ap6256P2pProgramSlot(Ctx, IfIndex, &p2p->DriverIes[frame], flag,
                                      buffer, length);
    }

    TraceInfo(TRACE_NETADAPTER, "P2P information elements rebuilt -> 0x%08X\n",
              status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pSetListenState(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                 _In_ UINT32 State,
                                 _In_ UINT32 ActiveMs,
                                 _In_ UINT32 CycleMs,
                                 _In_ UINT32 Channel)
{
    AP6256_P2P_STATE* p2p = &Ctx->P2p;
    UINT16 oldActive = p2p->ListenActiveMs, oldCycle = p2p->ListenCycleMs;
    UINT32 oldState = p2p->ListenState;
    BOOLEAN oldListening = p2p->Listening;
    UCHAR oldChannel = p2p->ListenChannel;
    NTSTATUS status;

    if (State != AP6256_P2P_LISTEN_OFF && State != AP6256_P2P_LISTEN_AUTOMATIC &&
        State != AP6256_P2P_LISTEN_HIGH) return STATUS_NOT_SUPPORTED;
    if (State == AP6256_P2P_LISTEN_OFF) {
        ActiveMs = AP6256_P2P_LISTEN_ACTIVE_DEFAULT;
        CycleMs = AP6256_P2P_LISTEN_CYCLE_DEFAULT;
    } else {
        if (ActiveMs == 0) ActiveMs = State == AP6256_P2P_LISTEN_AUTOMATIC
            ? AP6256_P2P_LISTEN_ACTIVE_DEFAULT : AP6256_P2P_LISTEN_ACTIVE_HIGH;
        if (CycleMs == 0) CycleMs = State == AP6256_P2P_LISTEN_AUTOMATIC
            ? AP6256_P2P_LISTEN_CYCLE_DEFAULT : AP6256_P2P_LISTEN_CYCLE_HIGH;
    }
    if (!Ap6256P2pIsSocialChannel(Channel) ||
        ActiveMs > 65535u || CycleMs > 65535u || CycleMs <= ActiveMs)
        return STATUS_INVALID_PARAMETER;
    if (!Ctx->P2pBssValid) return STATUS_DEVICE_NOT_READY;
    if (p2p->DiscoverPhase != Ap6256P2pDiscoverIdle) return STATUS_DEVICE_BUSY;

    p2p->ListenChannel = (UCHAR)Channel;
    p2p->ListenActiveMs = (UINT16)ActiveMs;
    p2p->ListenCycleMs = (UINT16)CycleMs;
    p2p->ListenState = State;
    p2p->Listening = State != AP6256_P2P_LISTEN_OFF;
    status = Ap6256P2pBuildIes(Ctx);
    if (NT_SUCCESS(status)) status = p2p->Listening
        ? Ap6256P2pPulseListen(Ctx)
        : Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_SCAN, 0, 0);
    if (!NT_SUCCESS(status)) {
        p2p->ListenChannel = oldChannel;
        p2p->ListenActiveMs = oldActive;
        p2p->ListenCycleMs = oldCycle;
        p2p->ListenState = oldState;
        p2p->Listening = oldListening;
        (VOID)Ap6256P2pBuildIes(Ctx);
    }
    TraceDiag("P2P listen state %u channel %u active %u cycle %u -> 0x%08X\n",
        State, p2p->ListenChannel, ActiveMs, CycleMs, status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256P2pPulseListen(PAP6256_DEVICE_CONTEXT Ctx)
{
    if (!Ctx->P2p.Listening || Ctx->P2p.DiscoverPhase != Ap6256P2pDiscoverIdle)
        return STATUS_INVALID_DEVICE_STATE;
    return Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_LISTEN,
        Ctx->P2p.ListenChannel, Ctx->P2p.ListenActiveMs);
}
