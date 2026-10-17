/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#define AP6256_FC_TYPE_MASK        0x000Cu
#define AP6256_FC_TYPE_DATA        0x0008u
#define AP6256_FC_SUBTYPE_NODATA   0x0040u
#define AP6256_FC_SUBTYPE_QOS      0x0080u
#define AP6256_FC_TODS             0x0100u
#define AP6256_FC_FROMDS           0x0200u
#define AP6256_FC_ORDER            0x8000u

#define AP6256_80211_HDR_MIN       24u
#define AP6256_LLC_SNAP_LEN        8u
#define AP6256_ETH_HDR_LEN         14u
#define AP6256_ETH_TYPE_MIN        0x0600u
#define AP6256_ETH_LEN_MAX         1500u
#define AP6256_ETH_TYPE_AARP       0x80F3u
#define AP6256_ETH_TYPE_IPX        0x8137u

#define AP6256_RX_ENCAP_GROWTH \
    (AP6256_80211_HDR_MIN + AP6256_LLC_SNAP_LEN - AP6256_ETH_HDR_LEN)

static const UCHAR Ap6256OuiRfc1042[3]      = { 0x00, 0x00, 0x00 };
static const UCHAR Ap6256OuiBridgeTunnel[3] = { 0x00, 0x00, 0xF8 };

_IRQL_requires_max_(DISPATCH_LEVEL)
static NTSTATUS
Ap6256Tal80211ToEthernet(_Inout_updates_bytes_(Length) PUCHAR Buffer,
                         _In_ ULONG Length,
                         _Out_ PULONG EthLength)
{
    UINT16 fc;
    ULONG hdrLength = AP6256_80211_HDR_MIN;
    ULONG payloadOffset;
    ULONG payloadLength;
    UINT16 etherType = 0;
    BOOLEAN stripSnap = FALSE;
    UCHAR da[6];
    UCHAR sa[6];

    *EthLength = 0;

    if (Length < AP6256_80211_HDR_MIN) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    fc = (UINT16)(Buffer[0] | ((UINT16)Buffer[1] << 8));

    if ((fc & AP6256_FC_TYPE_MASK) != AP6256_FC_TYPE_DATA ||
        (fc & AP6256_FC_SUBTYPE_NODATA) != 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if ((fc & (AP6256_FC_TODS | AP6256_FC_FROMDS)) ==
        (AP6256_FC_TODS | AP6256_FC_FROMDS)) {
        hdrLength += 6;
    }
    if ((fc & AP6256_FC_SUBTYPE_QOS) != 0) {
        hdrLength += 2;
        if ((fc & AP6256_FC_ORDER) != 0) {
            hdrLength += 4;
        }
    }
    if (Length < hdrLength) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    switch (fc & (AP6256_FC_TODS | AP6256_FC_FROMDS)) {
    case 0:
        RtlCopyMemory(da, Buffer + 4, 6);
        RtlCopyMemory(sa, Buffer + 10, 6);
        break;
    case AP6256_FC_TODS:
        RtlCopyMemory(da, Buffer + 16, 6);
        RtlCopyMemory(sa, Buffer + 10, 6);
        break;
    case AP6256_FC_FROMDS:
        RtlCopyMemory(da, Buffer + 4, 6);
        RtlCopyMemory(sa, Buffer + 16, 6);
        break;
    default:

        if (Length < AP6256_80211_HDR_MIN + 6) {
            return STATUS_INVALID_BUFFER_SIZE;
        }
        RtlCopyMemory(da, Buffer + 16, 6);
        RtlCopyMemory(sa, Buffer + 24, 6);
        break;
    }

    payloadOffset = hdrLength;
    payloadLength = Length - hdrLength;

    if (payloadLength == 6 && (da[0] & 1u) != 0) {
        static const UCHAR iapp[6] = {0, 1, 0xaf, 0x81, 1, 0};
        if (RtlEqualMemory(Buffer + payloadOffset, iapp, sizeof(iapp)))
            return STATUS_NOT_SUPPORTED;
    }

    if (payloadLength >= AP6256_LLC_SNAP_LEN &&
        payloadOffset + AP6256_LLC_SNAP_LEN <= Length &&
        Buffer[payloadOffset] == 0xAA &&
        Buffer[payloadOffset + 1] == 0xAA &&
        Buffer[payloadOffset + 2] == 0x03) {
        const UCHAR *oui = Buffer + payloadOffset + 3;
        UINT16 snapType = (UINT16)(((UINT16)Buffer[payloadOffset + 6] << 8) |
                                    Buffer[payloadOffset + 7]);

        if (RtlEqualMemory(oui, Ap6256OuiBridgeTunnel, 3) ||
            (RtlEqualMemory(oui, Ap6256OuiRfc1042, 3) &&
             snapType != AP6256_ETH_TYPE_AARP &&
             snapType != AP6256_ETH_TYPE_IPX)) {
            stripSnap = TRUE;
            etherType = snapType;
        }
    }

    if (stripSnap) {
        payloadOffset += AP6256_LLC_SNAP_LEN;
        payloadLength -= AP6256_LLC_SNAP_LEN;
    } else {

        if (payloadLength > AP6256_ETH_LEN_MAX) {
            return STATUS_INVALID_PARAMETER;
        }
        etherType = (UINT16)payloadLength;
    }

    if (AP6256_ETH_HDR_LEN + payloadLength > Length) {
        return STATUS_INVALID_BUFFER_SIZE;
    }

    RtlMoveMemory(Buffer + AP6256_ETH_HDR_LEN, Buffer + payloadOffset,
                  payloadLength);
    RtlCopyMemory(Buffer, da, 6);
    RtlCopyMemory(Buffer + 6, sa, 6);
    Buffer[12] = (UCHAR)(etherType >> 8);
    Buffer[13] = (UCHAR)(etherType & 0xFF);

    *EthLength = AP6256_ETH_HDR_LEN + payloadLength;
    return STATUS_SUCCESS;
}
