/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "netadapter_internal.h"
#include "host_cipher_transport.h"
#include "pm_query.inc"
#include "power_query.inc"

const UINT16 Ap6256RatesB[] = {2, 4, 11, 22};
const UINT16 Ap6256RatesOfdm[] = {12, 18, 24, 36, 48, 72, 96, 108};
#define AP6256_ACK_CASE(id)                                                                        \
    case id:                                                                                       \
        Ap6256AcknowledgeCommand(Wifi, Request, #id);                                              \
        break
#define AP6256_DECLINE_CASE(id)                                                                    \
    case id:                                                                                       \
        Ap6256DeclineCommand(Wifi, Request, #id);                                                  \
        break
static BOOLEAN Ap6256BandIsDisallowed(_In_ PAP6256_WIFI Wifi, _In_ WDI_BAND_ID BandId);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256SendIndication(_In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId,
                     _In_ const WDI_MESSAGE_HEADER* OriginalHeader, _In_ UINT32 TransactionId,
                     _In_ NTSTATUS CompletionStatus,
                     _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_Success_(return != FALSE)
static BOOLEAN Ap6256ClaimExpiredTask(_In_ PAP6256_WIFI Wifi,
                                                                 _Inout_ PAP6256_WDI_TASK Task,
                                                                 _Out_ PWDI_MESSAGE_HEADER Header,
                                                                 _Out_ PVOID* RequestId);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRoamingNeeded(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                               _In_ UINT32 Reason);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetTkipMicFailure(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                                _In_reads_(6)
                                                                    const UCHAR* PeerAddress,
                                                                _In_ UINT32 KeyIndex,
                                                                _In_ BOOLEAN GroupKey);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameCompleteQueue(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 PacketId, _In_ UINT32 FirmwareStatus);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256ChanspecToChannel(_In_ UINT16 Chanspec, _Out_ PUINT32 Channel, _Out_ WDI_BAND_ID* Band);
static BOOLEAN Ap6256P2pActionFrameType(_In_reads_bytes_(Length) const UCHAR* Body,
                                        _In_ ULONG Length, _Out_ WDI_P2P_ACTION_FRAME_TYPE* Type);
static VOID Ap6256IndicateP2pChannels(_In_ PAP6256_WIFI Wifi);
static VOID
Ap6256NetP2pActionFrameReceived(_In_ PAP6256_WIFI Wifi, _In_ WDI_P2P_ACTION_FRAME_TYPE Type,
                                _In_ UINT16 Chanspec, _In_reads_(6) const UCHAR* SourceAddress,
                                _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameReceived(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR IfIndex, _In_ UCHAR BssCfgIndex,
    _In_reads_(6) const UCHAR* SourceAddress, _In_ UINT16 Chanspec,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length);
_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetNloDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                                  _In_ PAP6256_BSS Bss);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_ PAP6256_BSS Bss);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanComplete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ NTSTATUS CompletionStatus);
_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID Ap6256StoreConnectRestrictions(
    _In_ PAP6256_WIFI Wifi, _In_opt_ const WDI_ADDRESS_LIST_CONTAINER* Allowed,
    _In_opt_ const WDI_ADDRESS_LIST_CONTAINER* Disallowed, _In_ LONG DisallowedBands);
static VOID Ap6256ExpireConnect(_In_ PAP6256_WIFI wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)

static VOID
Ap6256NetLinkStateWork(_In_ PAP6256_WIFI Wifi);
static VOID Ap6256NetLinkChangeWork(_In_ PAP6256_WIFI wifi, _In_ BOOLEAN LinkUp,
                                    _In_ BOOLEAN JoinFailed, _In_ LONG Generation,
                                    _In_ UINT32 FirmwareGeneration, _In_ UCHAR FirmwareEvent);
static VOID Ap6256NetRadioStateWork(_In_ PAP6256_WIFI Wifi);
static VOID Ap6256NetQueueLinkEventOwner(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Code,
                                         _In_ LONG Generation, _In_ UINT32 FirmwareGeneration,
                                         _In_ UCHAR FirmwareEvent);
static VOID Ap6256NetQueueLinkEventGeneration(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Code,
                                              _In_ LONG Generation);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkChange(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_ BOOLEAN LinkUp);
static VOID Ap6256NetStationLinkEventOwner(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                           BOOLEAN TerminalFailure, const UCHAR* Peer,
                                           UINT32 FirmwareGeneration, UCHAR FirmwareEvent);
_Use_decl_annotations_
VOID Ap6256NetStationFirmwareEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                                          BOOLEAN TerminalFailure,
                                                          const UCHAR* Peer,
                                                          UINT32 FirmwareGeneration);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkStateRefresh(_In_ PAP6256_DEVICE_CONTEXT Ctx);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRadioChanged(_In_ PAP6256_DEVICE_CONTEXT Ctx);
static ULONG Ap6256FirstAuthAlgo(_In_ const WDI_AUTH_ALGORITHM_LIST_CONTAINER* List);
static ULONG Ap6256FirstCipherAlgo(_In_ const WDI_CIPHER_ALGORITHM_LIST_CONTAINER* List);
static BOOLEAN Ap6256ScanTriggerValid(_In_ WDI_SCAN_TRIGGER Trigger);
static NTSTATUS Ap6256AppendScanChannel(_Inout_ PAP6256_SCAN_PARAMS Params,
                                        _In_ AP6256_SCAN_BAND Band, _In_ UINT16 Channel);
static NTSTATUS Ap6256AppendBandChannels(_Inout_ PAP6256_SCAN_PARAMS Params,
                                         _In_ AP6256_SCAN_BAND Band);
static NTSTATUS Ap6256PopulateAllowedScanChannels(_In_ PAP6256_WIFI Wifi,
                                                  _Inout_ PAP6256_SCAN_PARAMS Params);
static NTSTATUS Ap6256CaptureScanParameters(_In_ PAP6256_WIFI Wifi,
                                            _In_ const WDI_SCAN_PARAMETERS* Wdi,
                                            _Out_ AP6256_SCAN_PARAMS* Params);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleScanRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                        _In_ PWDI_MESSAGE_HEADER Header,
                        _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
static VOID Ap6256HandleConnectRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                       _In_ UINT16 MessageId, _In_ PWDI_MESSAGE_HEADER Header,
                                       _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                       _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleDisconnectRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                              _In_ PWDI_MESSAGE_HEADER Header,
                              _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
static NTSTATUS Ap6256CommandInterface(PAP6256_WIFI Wifi, PWDI_MESSAGE_HEADER Header,
                                       PUINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256ParseHostKey(_In_ const WDI_SET_ADD_CIPHER_KEYS_CONTAINER* Source,
                   _Out_ AP6256_HOST_CIPHER_KEY* Key)
{
    const UCHAR* material;
    ULONG length;
    BOOLEAN gcmp = Source->CipherKeyTypeInfo.CipherAlgorithm == WDI_CIPHER_ALGO_GCMP_256;
    BOOLEAN pairwise = Source->CipherKeyTypeInfo.KeyType == WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
    ULONG id = Source->Optional.CipherKeyID_IsPresent ? Source->CipherKeyID.CipherKeyID : 0;
    RtlZeroMemory(Key, sizeof(*Key));
    if (Source->CipherKeyTypeInfo.Static > 1) return STATUS_INVALID_PARAMETER;

    if (Source->CipherKeyTypeInfo.Static) return STATUS_NOT_SUPPORTED;
    if (Source->Optional.LinkId_IsPresent || !Source->Optional.ReceiveSequenceCount_IsPresent ||
        (Source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_BOTH &&
         Source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_INBOUND &&
         Source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_OUTBOUND))
        return STATUS_INVALID_PARAMETER;
    if (gcmp) {
        if ((pairwise && (!Source->Optional.PeerMacAddress_IsPresent || id > 1)) ||
            (!pairwise && (Source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_GROUP_KEY ||
                           !Source->Optional.CipherKeyID_IsPresent || id > 3)) ||
            !Source->Optional.GCMP_256Key_IsPresent || Source->Optional.BIP_GMAC_256Key_IsPresent)
            return STATUS_INVALID_PARAMETER;
        material = Source->GCMP_256Key.pElements; length = Source->GCMP_256Key.ElementCount;
    } else {
        if (Source->CipherKeyTypeInfo.CipherAlgorithm != WDI_CIPHER_ALGO_BIP_GMAC_256 ||
            Source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_IGTK ||
            !Source->Optional.CipherKeyID_IsPresent || (id != 4 && id != 5) ||
            !Source->Optional.BIP_GMAC_256Key_IsPresent || Source->Optional.GCMP_256Key_IsPresent)
            return STATUS_INVALID_PARAMETER;
        material = Source->BIP_GMAC_256Key.pElements; length = Source->BIP_GMAC_256Key.ElementCount;
    }
    if (!material || length != AP6256_HC_KEY_BYTES || Source->Optional.CCMPKey_IsPresent ||
        Source->Optional.GCMPKey_IsPresent || Source->Optional.TKIPInfo_IsPresent ||
        Source->Optional.BIPKey_IsPresent || Source->Optional.WEPKey_IsPresent ||
        Source->Optional.IHVKey_IsPresent) return STATUS_INVALID_PARAMETER;
    Key->Cipher = (ULONG)Source->CipherKeyTypeInfo.CipherAlgorithm; Key->KeyId = id;
    Key->Pairwise = pairwise; Key->PeerPresent = Source->Optional.PeerMacAddress_IsPresent != 0;
    Key->TxAllowed = Source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_INBOUND;
    Key->RxAllowed = Source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_OUTBOUND;
    if (Key->PeerPresent) RtlCopyMemory(Key->Peer, Source->PeerMacAddress.Address, sizeof(Key->Peer));
    RtlCopyMemory(Key->Key, material, sizeof(Key->Key));
    RtlCopyMemory(Key->ReceiveSequence, Source->ReceiveSequenceCount.ReceiveSequenceCount,
        sizeof(Key->ReceiveSequence));
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256ParseHostDelete(const WDI_SET_DELETE_CIPHER_KEYS_CONTAINER* Source,
    AP6256_HOST_CIPHER_KEY* Key)
{
    BOOLEAN pairwise = Source->CipherKeyTypeInfo.KeyType == WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
    BOOLEAN gcmp = Source->CipherKeyTypeInfo.CipherAlgorithm == WDI_CIPHER_ALGO_GCMP_256;
    ULONG id = Source->Optional.CipherKeyID_IsPresent ? Source->CipherKeyID.CipherKeyID : 0;
    RtlZeroMemory(Key, sizeof(*Key));
    if (Source->Optional.LinkId_IsPresent ||
        (gcmp && ((pairwise && (!Source->Optional.PeerMacAddress_IsPresent || id > 1)) ||
            (!pairwise && (Source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_GROUP_KEY ||
                          !Source->Optional.CipherKeyID_IsPresent || id > 3)))) ||
        (!gcmp && (Source->CipherKeyTypeInfo.CipherAlgorithm != WDI_CIPHER_ALGO_BIP_GMAC_256 ||
            Source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_IGTK ||
            !Source->Optional.CipherKeyID_IsPresent || (id != 4 && id != 5))))
        return STATUS_INVALID_PARAMETER;
    Key->Cipher = (ULONG)Source->CipherKeyTypeInfo.CipherAlgorithm; Key->KeyId = id;
    Key->Pairwise = pairwise; Key->PeerPresent = Source->Optional.PeerMacAddress_IsPresent != 0;
    if (Key->PeerPresent) RtlCopyMemory(Key->Peer, Source->PeerMacAddress.Address, sizeof(Key->Peer));
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256HostKeys(PAP6256_WIFI Wifi, UINT32 IfIndex,
    const WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* Add, const WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* Delete)
{
    AP6256_HOST_CIPHER_KEY* keys;
    ULONG count = Add ? Add->SetCipherKey.ElementCount : Delete->CipherKeyInfo.ElementCount;
    SIZE_T bytes = (SIZE_T)count * sizeof(*keys);
    ULONG i, cipher;
    NTSTATUS status = STATUS_SUCCESS;

    keys = (AP6256_HOST_CIPHER_KEY*)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, AP6256_POOL_TAG);
    if (!keys) return STATUS_INSUFFICIENT_RESOURCES;
    for (i = 0; i < count; ++i) {
        cipher = (ULONG)(Add ? Add->SetCipherKey.pElements[i].CipherKeyTypeInfo.CipherAlgorithm :
            Delete->CipherKeyInfo.pElements[i].CipherKeyTypeInfo.CipherAlgorithm);
        if (cipher != WDI_CIPHER_ALGO_GCMP_256 && cipher != WDI_CIPHER_ALGO_BIP_GMAC_256) {
            status = STATUS_NOT_SUPPORTED; break;
        }
        status = Add ? Ap6256ParseHostKey(&Add->SetCipherKey.pElements[i], &keys[i]) :
            Ap6256ParseHostDelete(&Delete->CipherKeyInfo.pElements[i], &keys[i]);
        if (!NT_SUCCESS(status)) break;
    }
    if (NT_SUCCESS(status)) status = Add ? Ap6256HostCipherAddKeys(Wifi->Ctx, IfIndex, keys, count) :
        Ap6256HostCipherDeleteKeys(Wifi->Ctx, IfIndex, keys, count);
    RtlSecureZeroMemory(keys, bytes);
    ExFreePoolWithTag(keys, AP6256_POOL_TAG);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddKeys(_In_ PAP6256_WIFI Wifi, _In_ UINT32 IfIndex,
              _In_ WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* Parameters);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256DeleteKeys(_In_ PAP6256_WIFI Wifi, _In_ UINT32 IfIndex,
                 _In_ WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* Parameters);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleKeyRequest(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                       _In_ AP6256_REQUEST Request, _In_ UINT16 MessageId,
                       _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAdapterConfiguration(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                 _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256IndicateRadioStatus(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRadioRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                         _In_ PWDI_MESSAGE_HEADER Header,
                         _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256FillP2pGroupId(_Out_ PAP6256_P2P_ACTION_FRAME Frame, _In_ const WDI_P2P_GROUP_ID* GroupId);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256ActionFrameInterface(_In_ PAP6256_WIFI Wifi, _In_ UINT16 Port, _Out_ PUINT32 IfIndex);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256StartP2pActionFrame(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                          _In_ PWDI_MESSAGE_HEADER Header, _In_ UINT16 CompletionId,
                          _In_ const AP6256_P2P_ACTION_FRAME* Frame, _In_ UINT32 SendTimeoutMs);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleP2pSendRequestActionFrame(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
static NTSTATUS Ap6256AppendP2pDiscoverChannel(_Inout_ PAP6256_P2P_DISCOVER Discover,
                                               _In_ UINT16 Number, _In_ UINT32 DwellMs,
                                               _In_ UINT32 CycleMs);
static NTSTATUS Ap6256CaptureP2pDiscover(_In_ PAP6256_WIFI Wifi,
                                         _In_ const WDI_TASK_P2P_DISCOVER_PARAMETERS* Params,
                                         _Out_ PAP6256_P2P_DISCOVER Discover);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleP2pDiscover(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                        _In_ PWDI_MESSAGE_HEADER Header,
                        _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleP2pSendResponseActionFrame(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleSetAdvertisementInformation(
    _In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header, _In_ AP6256_REQUEST Request,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetP2pListenState(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                              _In_ AP6256_REQUEST Request,
                              _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetNetworkListOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                  _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                  _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256RecomputePortModes(_In_ PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256RememberWolPattern(_In_ PAP6256_WIFI Wifi,
                                                                        _In_ UINT32 PatternId);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256ForgetWolPattern(_In_ PAP6256_WIFI Wifi,
                                                                      _In_ UINT32 PatternId);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAddWolPattern(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                          _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRemoveWolPattern(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                             _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddArpOffload(_In_ PAP6256_WIFI Wifi,
                    _In_ const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* Source);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddNsOffload(_In_ PAP6256_WIFI Wifi,
                   _In_ const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER* Source);

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256BuildGtkOffload(PAP6256_WIFI Wifi,
    const WDI_PM_RSN_KEY_INFO_CONTAINER* Source, AP6256_GTK_OFFLOAD* Offload)
{
    if (!Wifi->Ctx->FirmwareGtkOffloadSupported ||
        (Wifi->Ctx->WowlCapabilities & AP6256_WOWL_KEY_ROTATION) == 0 ||
        Wifi->MulticastCipher != WDI_CIPHER_ALGO_CCMP) return STATUS_NOT_SUPPORTED;
    if (Source->KCK_CONTENT.ElementCount != 16 || Source->KEK_CONTENT.ElementCount != 16 ||
        !Source->KCK_CONTENT.pElements || !Source->KEK_CONTENT.pElements)
        return STATUS_INVALID_PARAMETER;
    RtlZeroMemory(Offload, sizeof(*Offload));
    Offload->OffloadId = Source->ProtocolOffloadId;
    Offload->ReplayCounter = Source->ReplayCounter;
    RtlCopyMemory(Offload->Kck, Source->KCK_CONTENT.pElements, 16);
    RtlCopyMemory(Offload->Kek, Source->KEK_CONTENT.pElements, 16);
    Offload->Pmf = Wifi->MulticastMgmtCipher == WDI_CIPHER_ALGO_BIP;
    if (Wifi->AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE) {
        Offload->DescriptorVersion = 0; Offload->MicKind = 3;
    } else if (Wifi->AuthAlgorithm == WDI_AUTH_ALGO_OWE) {
        Offload->DescriptorVersion = 0; Offload->MicKind = 2;
    } else if (Wifi->AuthAlgorithm == WDI_AUTH_ALGO_RSNA && Wifi->Auth.Ft.MobilityDomainValid) {
        Offload->DescriptorVersion = 3; Offload->MicKind = 3;
    } else if (Wifi->AuthAlgorithm == WDI_AUTH_ALGO_RSNA || Wifi->AuthAlgorithm == WDI_AUTH_ALGO_RSNA_PSK) {
        Offload->DescriptorVersion = 2; Offload->MicKind = 1;
    } else return STATUS_NOT_SUPPORTED;
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256ClearPmOffloads(_In_ PAP6256_WIFI Wifi);

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAddPmProtocolOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                 _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRemovePmProtocolOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                    _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                    _In_ ULONG TlvLength);
_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS Ap6256SendPendingActionFrame(_In_ PAP6256_WIFI Wifi);
_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN Ap6256ClaimActionFrameLocked(
    _In_ PAP6256_WIFI Wifi, _In_ BOOLEAN AbortOffChannel,
    _Out_ PAP6256_ACTION_FRAME_COMPLETION Done);
_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256IndicateActionFrameDone(
    _In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_ACTION_FRAME_COMPLETION Done,
    _In_ NTSTATUS Status);

BOOLEAN Ap6256BandIsMasked(_In_ LONG Mask, _In_ WDI_BAND_ID BandId)
{

    if (Mask == 0) return FALSE;
    if (BandId == WDI_BAND_ID_2400)
        return (BOOLEAN)((Mask & AP6256_DISALLOW_BAND_2G) != 0);
    if (BandId == WDI_BAND_ID_5000)
        return (BOOLEAN)((Mask & AP6256_DISALLOW_BAND_5G) != 0);

    return TRUE;
}

static BOOLEAN Ap6256BandIsDisallowed(_In_ PAP6256_WIFI Wifi, _In_ WDI_BAND_ID BandId)
{
    LONG mask = InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0);
    return Ap6256BandIsMasked(mask, BandId);
}

NTSTATUS Ap6256NdisToNtStatus(_In_ NDIS_STATUS Status)
{
    if (NT_SUCCESS(Status) && Status != NDIS_STATUS_SUCCESS && Status != NDIS_STATUS_PENDING &&
        Status != NDIS_STATUS_INDICATION_REQUIRED) {
        return STATUS_UNSUCCESSFUL;
    }
    if (Status == NDIS_STATUS_BUFFER_TOO_SHORT)
        return STATUS_BUFFER_TOO_SMALL;
    return (NTSTATUS)Status;
}

NDIS_STATUS Ap6256NtToNdisStatus(_In_ NTSTATUS Status)
{
    if (NT_SUCCESS(Status) && Status != STATUS_PENDING &&
        Status != STATUS_NDIS_INDICATION_REQUIRED) {
        return NDIS_STATUS_SUCCESS;
    }
    if (Status == STATUS_BUFFER_TOO_SMALL)
        return NDIS_STATUS_BUFFER_TOO_SHORT;
    return (NDIS_STATUS)Status;
}

_IRQL_requires_max_(DISPATCH_LEVEL)

PCSTR Ap6256IndicationName(UINT16 MessageId)
{
    switch (MessageId) {
    case WDI_INDICATION_OPEN_COMPLETE:
        return "OPEN_COMPLETE";
    case WDI_INDICATION_CLOSE_COMPLETE:
        return "CLOSE_COMPLETE";
    case WDI_INDICATION_CREATE_PORT_COMPLETE:
        return "CREATE_PORT_COMPLETE";
    case WDI_INDICATION_DELETE_PORT_COMPLETE:
        return "DELETE_PORT_COMPLETE";
    case WDI_INDICATION_DOT11_RESET_COMPLETE:
        return "DOT11_RESET_COMPLETE";
    case WDI_INDICATION_SCAN_COMPLETE:
        return "SCAN_COMPLETE";
    case WDI_INDICATION_BSS_ENTRY_LIST:
        return "BSS_ENTRY_LIST";
    case WDI_INDICATION_ASSOCIATION_RESULT:
        return "ASSOCIATION_RESULT";
    case WDI_INDICATION_CONNECT_COMPLETE:
        return "CONNECT_COMPLETE";
    case WDI_INDICATION_DISCONNECT_COMPLETE:
        return "DISCONNECT_COMPLETE";
    case WDI_INDICATION_DISASSOCIATION:
        return "DISASSOCIATION";
    case WDI_INDICATION_ROAM_COMPLETE:
        return "ROAM_COMPLETE";
    case WDI_INDICATION_ROAMING_NEEDED:
        return "ROAMING_NEEDED";
    case WDI_INDICATION_LINK_STATE_CHANGE:
        return "LINK_STATE_CHANGE";
    case WDI_INDICATION_TKIP_MIC_FAILURE:
        return "TKIP_MIC_FAILURE";
    case WDI_INDICATION_PMKID_CANDIDATE_LIST_UPDATE:
        return "PMKID_CANDIDATE_LIST";
    case WDI_INDICATION_RADIO_STATUS:
        return "RADIO_STATUS";
    case WDI_INDICATION_STOP_AP:
        return "STOP_AP";
    case WDI_INDICATION_START_AP_COMPLETE:
        return "START_AP_COMPLETE";
    case WDI_INDICATION_SET_RADIO_STATE_COMPLETE:
        return "SET_RADIO_STATE_COMPLETE";
    case WDI_INDICATION_CHANGE_OPERATION_MODE_COMPLETE:
        return "CHANGE_OPMODE_COMPLETE";
    default:
        return "indication";
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256SendIndication(_In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId,
                     _In_ const WDI_MESSAGE_HEADER* OriginalHeader, _In_ UINT32 TransactionId,
                     _In_ NTSTATUS CompletionStatus,
                     _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    return Ap6256SendIndicationRq(Wifi, MessageId, OriginalHeader, TransactionId, NULL,
                                  CompletionStatus, Tlv, TlvLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256SendGeneratedIndication(
    _In_ PAP6256_WIFI Wifi, _In_ UINT16 MessageId, _In_ const WDI_MESSAGE_HEADER* OriginalHeader,
    _In_ UINT32 TransactionId, _In_opt_ PVOID RequestId,
    _In_reads_bytes_opt_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    return Ap6256SendIndicationRq(Wifi, MessageId, OriginalHeader, TransactionId, RequestId,
                                  STATUS_SUCCESS, Tlv, TlvLength);
}

_Success_(return != FALSE)
BOOLEAN Ap6256ClaimTask(_In_ PAP6256_WIFI Wifi,
                                                   _Inout_ PAP6256_WDI_TASK Task,
                                                   _Out_ PWDI_MESSAGE_HEADER Header,
                                                   _Out_ PVOID* RequestId)
{
    KIRQL oldIrql;
    BOOLEAN active;

    *RequestId = NULL;
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    active = Task->Active;
    if (active) {
        *Header = Task->Header;
        *RequestId = Task->RequestId;
        Task->Active = FALSE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    return active;
}

_Success_(return != FALSE)
BOOLEAN Ap6256ClaimMatchingTask(
    _In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task, _In_ UINT32 TransactionId,
    _In_ WDI_PORT_ID PortId, _Out_ PWDI_MESSAGE_HEADER Header, _Out_ PVOID* RequestId)
{
    KIRQL oldIrql;
    BOOLEAN matched;

    *RequestId = NULL;
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    matched = Task->Active && Task->Header.TransactionId == TransactionId &&
              Task->Header.PortId == PortId;
    if (matched) {
        *Header = Task->Header;
        *RequestId = Task->RequestId;
        Task->Active = FALSE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    return matched;
}

VOID Ap6256SetTaskDeadline(_In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task,
                           _In_ ULONG TimeoutMs)
{
    KIRQL oldIrql;

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (Task->Active) {
        Task->DeadlineMs = Ap6256InterruptTimeMs() + (LONGLONG)TimeoutMs;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
}

_Success_(return != FALSE)
static BOOLEAN Ap6256ClaimExpiredTask(_In_ PAP6256_WIFI Wifi,
                                                                 _Inout_ PAP6256_WDI_TASK Task,
                                                                 _Out_ PWDI_MESSAGE_HEADER Header,
                                                                 _Out_ PVOID* RequestId)
{
    KIRQL oldIrql;
    BOOLEAN expired;

    *RequestId = NULL;
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    expired = Task->Active && Task->DeadlineMs != 0 && Ap6256InterruptTimeMs() >= Task->DeadlineMs;
    if (expired) {
        *Header = Task->Header;
        *RequestId = Task->RequestId;
        Task->Active = FALSE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    return expired;
}

UINT16 Ap6256ConnectCompletionId(_In_ PAP6256_WIFI Wifi)
{
    return Wifi->ConnectTaskIsRoam ? WDI_INDICATION_ROAM_COMPLETE : WDI_INDICATION_CONNECT_COMPLETE;
}

_IRQL_requires_max_(PASSIVE_LEVEL) _Success_(return != FALSE)
BOOLEAN Ap6256ClaimConnectTask(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_CONNECT_CLAIM Claim, _In_ UINT32 TransactionId,
    _In_ WDI_PORT_ID PortId, _Out_ PWDI_MESSAGE_HEADER Header, _Out_ PVOID* RequestId)
{
    BOOLEAN claimed;
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (Claim == Ap6256ConnectClaimMatching) {
        claimed = Ap6256ClaimMatchingTask(Wifi, &Wifi->ConnectTask, TransactionId, PortId, Header,
                                          RequestId);
    } else if (Claim == Ap6256ConnectClaimExpired) {
        claimed = Ap6256ClaimExpiredTask(Wifi, &Wifi->ConnectTask, Header, RequestId);
    } else {
        claimed = Ap6256ClaimTask(Wifi, &Wifi->ConnectTask, Header, RequestId);
    }
    if (claimed) {

        Ap6256ModelCancelAuthentication(Wifi);
        Wifi->ConnectCandidateCount = 0;
        Wifi->ConnectDeparting = FALSE;
        InterlockedIncrement(&Wifi->ConnectGeneration);
    }
    Ap6256LockRelease(&Wifi->ConnectLock);
    return claimed;
}

UINT32 Ap6256LinkQualityFromRssi(_In_ INT32 Rssi)
{

    if (Rssi == 0)
        return 0;

    if (Rssi < -90)
        return 0;
    if (Rssi < -70)
        return (UINT32)((Rssi + 90) * 2);
    if (Rssi < -68)
        return (UINT32)((Rssi + 70) * 10 + 40);
    if (Rssi < -58)
        return (UINT32)((Rssi + 68) * 2 + 60);
    if (Rssi < -30)
        return (UINT32)(((Rssi + 58) * 5) / 7 + 80);
    return 100;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRoamingNeeded(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                               _In_ UINT32 Reason)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_INDICATION_ROAMING_NEEDED_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;

    if (wifi == NULL || !wifi->PortCreated)
        return;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));
    parameters.RoamingReason = (WDI_ASSOC_STATUS)Reason;

    TraceDiag("asking Windows for a roam (reason %u)\n", Reason);

    if (GenerateWdiIndicationRoamingNeeded(&parameters, 0, &wifi->TlvContext, &generatedLength,
                                           &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = wifi->PortNumber;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_ROAMING_NEEDED, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetTkipMicFailure(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                                _In_reads_(6)
                                                                    const UCHAR* PeerAddress,
                                                                _In_ UINT32 KeyIndex,
                                                                _In_ BOOLEAN GroupKey)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_INDICATION_TKIP_MIC_FAILURE_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;

    if (wifi == NULL || !wifi->PortCreated)
        return;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));
    parameters.FailureInfo.DefaultKeyFailure = GroupKey ? TRUE : FALSE;
    parameters.FailureInfo.KeyIndex = GroupKey ? KeyIndex : 0;
    RtlCopyMemory(parameters.FailureInfo.PeerMacAddress.Address, PeerAddress, 6);

    TraceWarn(TRACE_NETADAPTER,
              "TKIP MIC failure from %02X:%02X:%02X:%02X:%02X:%02X "
              "(%s key, index %u)\n",
              PeerAddress[0], PeerAddress[1], PeerAddress[2], PeerAddress[3], PeerAddress[4],
              PeerAddress[5], GroupKey ? "group" : "pairwise", GroupKey ? KeyIndex : 0);

    if (GenerateWdiIndicationTkipMicFailure(&parameters, 0, &wifi->TlvContext, &generatedLength,
                                            &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = wifi->PortNumber;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_TKIP_MIC_FAILURE, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApStopped(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                           _In_ UINT32 Reason)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_INDICATION_STOP_AP_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;

    if (wifi == NULL || !Ctx->Go.Created)
        return;

    Ctx->Go.Started = FALSE;
    wifi->ApStarted = FALSE;

    Ap6256ModelApStopped(wifi, Ctx);
    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));
    parameters.Reason = Reason;

    TraceWarn(TRACE_NETADAPTER, "the AP stopped without being asked (reason %u)\n", Reason);

    if (GenerateWdiIndicationStopAp(&parameters, 0, &wifi->TlvContext, &generatedLength,
                                    &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = AP6256_GROUP_PORT;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_STOP_AP, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApCanSustain(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ UINT32 Reason)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_INDICATION_CAN_SUSTAIN_AP_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;

    if (wifi == NULL || !Ctx->Go.Created)
        return;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));
    parameters.Reason = Reason;

    TraceInfo(TRACE_NETADAPTER, "the AP can run again (reason 0x%08X)\n", Reason);

    if (GenerateWdiIndicationCanSustainAp(&parameters, 0, &wifi->TlvContext, &generatedLength,
                                          &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = AP6256_GROUP_PORT;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_CAN_SUSTAIN_AP, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetApAssociationRequest(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_reads_(6) const UCHAR* PeerAddress,
    _In_ BOOLEAN Reassociation, _In_reads_bytes_opt_(Length) const UCHAR* Frame, _In_ ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_INDICATION_AP_ASSOCIATION_REQUEST_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;

    if (wifi == NULL || !wifi->ApStarted || Frame == NULL || Length < (Reassociation ? 10u : 4u))
        return;

    if (!Ap6256GoAssociationAllowed(&wifi->GoApParams, Frame + (Reassociation ? 10u : 4u),
                                    Length - (Reassociation ? 10u : 4u))) {

        (VOID) Ap6256WifiSendAssocDecisionIf(Ctx, Ctx->Go.IfIndex, PeerAddress, FALSE,
                                             12);
        return;
    }

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));

    RtlCopyMemory(parameters.IncomingRequestInfo.AssocRequestParams.PeerMacAddress.Address,
                  PeerAddress, 6);
    parameters.IncomingRequestInfo.AssocRequestParams.IsReassociationRequest =
        Reassociation ? 1 : 0;
    if (Frame != NULL && Length != 0) {
        parameters.IncomingRequestInfo.AssocRequestFrame.ElementCount = Length;
        parameters.IncomingRequestInfo.AssocRequestFrame.pElements = (UINT8*)Frame;
        parameters.IncomingRequestInfo.AssocRequestFrame.MemoryInternallyAllocated = FALSE;
    }

    TraceInfo(TRACE_NETADAPTER,
              "AP %sassociation request from "
              "%02X:%02X:%02X:%02X:%02X:%02X, %u IE byte(s)\n",
              Reassociation ? "re" : "", PeerAddress[0], PeerAddress[1], PeerAddress[2],
              PeerAddress[3], PeerAddress[4], PeerAddress[5], Length);

    if (GenerateWdiIndicationApAssociationRequestReceived(&parameters, 0, &wifi->TlvContext,
                                                          &generatedLength,
                                                          &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = AP6256_GROUP_PORT;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_AP_ASSOCIATION_REQUEST_RECEIVED,
                                             &header, WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameComplete(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 PacketId, _In_ UINT32 FirmwareStatus)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    AP6256_ACTION_FRAME_COMPLETION done;
    LONGLONG remaining;
    NTSTATUS finishStatus;
    BOOLEAN claimed;

    if (wifi == NULL || wifi->Stopping || !wifi->HardwareAvailable || !wifi->ActionFrameTask.Active)
        return;
    if (PacketId != wifi->ActionFramePendingId) {
        TraceWarn(TRACE_NETADAPTER,
                  "action frame status for packet %u, but %u is the one in "
                  "flight\n",
                  PacketId, wifi->ActionFramePendingId);
        return;
    }

    AP6256_TIMER_STOP(wifi->ActionFrameTimer, TRUE);

    Ap6256LockAcquire(&wifi->ActionFrameLock);

    if (wifi->Stopping || !wifi->HardwareAvailable || !wifi->ActionFrameTask.Active ||
        wifi->ActionFrameBody == NULL) {
        Ap6256LockRelease(&wifi->ActionFrameLock);
        return;
    }
    if (PacketId != wifi->ActionFramePendingId) {

        LONGLONG delay = wifi->ActionFrameAcked
                             ? wifi->ActionFrameDwellDeadline - Ap6256InterruptTimeMs()
                             : (LONGLONG)wifi->ActionFrameRetryMs;
        AP6256_TIMER_START(wifi->ActionFrameTimer, (ULONG)max(1ll, delay));
        Ap6256LockRelease(&wifi->ActionFrameLock);
        return;
    }

    if (wifi->ActionFrameAcked) {
        LONGLONG delay = wifi->ActionFrameDwellDeadline - Ap6256InterruptTimeMs();
        AP6256_TIMER_START(wifi->ActionFrameTimer, (ULONG)max(1ll, delay));
        Ap6256LockRelease(&wifi->ActionFrameLock);
        return;
    }

    remaining = wifi->ActionFrameDeadline - Ap6256InterruptTimeMs();
    TraceDiag("action frame TX status: id %u firmware %u remaining %I64d ms\n", PacketId,
              FirmwareStatus, remaining);

    if (remaining >= (LONGLONG)wifi->ActionFrameRetryMs &&
        (FirmwareStatus == AP6256_EVENT_STATUS_NO_ACK ||
         FirmwareStatus == AP6256_EVENT_STATUS_TIMEOUT)) {
        TraceInfo(TRACE_NETADAPTER,
                  "action frame %u not acknowledged; resending, %I64d ms "
                  "left\n",
                  PacketId, remaining);
        finishStatus = Ap6256SendPendingActionFrame(wifi);
        if (NT_SUCCESS(finishStatus)) {
            AP6256_TIMER_START(wifi->ActionFrameTimer, wifi->ActionFrameRetryMs);
            Ap6256LockRelease(&wifi->ActionFrameLock);
            return;
        }
    } else if (FirmwareStatus == AP6256_EVENT_STATUS_SUCCESS) {
        TraceInfo(TRACE_NETADAPTER, "action frame %u acknowledged\n", PacketId);
        finishStatus = STATUS_SUCCESS;
        if (wifi->ActionFrameCompleteId == WDI_INDICATION_P2P_SEND_REQUEST_ACTION_FRAME_COMPLETE ||
            wifi->ActionFrameCompleteId == WDI_INDICATION_P2P_SEND_RESPONSE_ACTION_FRAME_COMPLETE) {

            Ap6256LockAcquire(&wifi->P2pLock);

            finishStatus = Ap6256WifiAbortOffChannel(Ctx);
            if (NT_SUCCESS(finishStatus)) {
                finishStatus = Ap6256WifiSetP2pDiscoveryState(Ctx, AP6256_P2P_DISC_LISTEN,
                                                              wifi->ActionFrameChannel,
                                                              wifi->ActionFrameDwellMs);
            } else {
                TraceDiag("P2P post-ACK release failed: id %u -> 0x%08X\n", PacketId, finishStatus);
            }
            Ap6256LockRelease(&wifi->P2pLock);
            TraceDiag("P2P post-ACK dwell: id %u channel %u %u ms -> 0x%08X\n", PacketId,
                      wifi->ActionFrameChannel, wifi->ActionFrameDwellMs, finishStatus);
            if (NT_SUCCESS(finishStatus)) {
                wifi->ActionFrameAcked = TRUE;
                wifi->ActionFrameDwellDeadline = Ap6256InterruptTimeMs() + wifi->ActionFrameDwellMs;
                AP6256_TIMER_START(wifi->ActionFrameTimer, wifi->ActionFrameDwellMs);
                Ap6256LockRelease(&wifi->ActionFrameLock);
                return;
            }
        }
    } else {
        TraceWarn(TRACE_NETADAPTER,
                  "action frame %u failed: firmware status %u, %I64d ms "
                  "left\n",
                  PacketId, FirmwareStatus, remaining);
        finishStatus = STATUS_UNSUCCESSFUL;
    }

    claimed = Ap6256ClaimActionFrameLocked(wifi, (BOOLEAN)!NT_SUCCESS(finishStatus), &done);
    Ap6256LockRelease(&wifi->ActionFrameLock);
    if (claimed) {
        Ap6256IndicateActionFrameDone(wifi, &done, finishStatus);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameCompleteQueue(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UINT32 PacketId, _In_ UINT32 FirmwareStatus)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    KIRQL irql;
    BOOLEAN overflow = FALSE;

    if (wifi == NULL)
        return;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);
    if (wifi->ActionFrameEventCount == AP6256_ACTION_EVENT_COUNT) {
        overflow = TRUE;

        if (PacketId == wifi->ActionFramePendingId) {
            wifi->ActionFrameEventOverflow = TRUE;
            wifi->ActionFrameOverflowPacketId = PacketId;
        }
    } else {
        ULONG tail =
            (wifi->ActionFrameEventHead + wifi->ActionFrameEventCount) % AP6256_ACTION_EVENT_COUNT;
        wifi->ActionFrameEvents[tail].PacketId = PacketId;
        wifi->ActionFrameEvents[tail].Status = FirmwareStatus;
        wifi->ActionFrameEventCount++;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (overflow)
        TraceDiag("action TX status queue overflow: id %u status %u\n", PacketId, FirmwareStatus);
    AP6256_ACTIONFRAME_COMPLETE_KICK(wifi);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256ChanspecToChannel(_In_ UINT16 Chanspec, _Out_ PUINT32 Channel, _Out_ WDI_BAND_ID* Band)
{
    UINT32 width = (Chanspec & 0x3800u), sideband = (Chanspec >> 8) & 7u;
    INT32 control = Chanspec & 0x00FFu;
    *Band = (Chanspec & 0xC000u) == 0xC000u ? WDI_BAND_ID_5000 : WDI_BAND_ID_2400;

    if (width == 0x1800u && sideband < 2u)
        control += (INT32)sideband * 4 - 2;
    else if (width == 0x2000u && sideband < 4u)
        control += (INT32)sideband * 4 - 6;
    else if (width != 0x1000u || sideband != 0u)
        control = 0;
    *Channel = control > 0 && control <= 165 ? (UINT32)control : 0;
}

static BOOLEAN Ap6256P2pActionFrameType(_In_reads_bytes_(Length) const UCHAR* Body,
                                        _In_ ULONG Length, _Out_ WDI_P2P_ACTION_FRAME_TYPE* Type)
{
    *Type = (WDI_P2P_ACTION_FRAME_TYPE)0;

    if (Length < AP6256_P2P_ACTION_HEADER)
        return FALSE;
    if (Body[0] != 4 || Body[1] != 9)
        return FALSE;
    if (Body[2] != 0x50 || Body[3] != 0x6F || Body[4] != 0x9A || Body[5] != 0x09) {
        return FALSE;
    }

    switch (Body[6]) {
    case AP6256_P2P_AF_GO_NEG_REQ:
        *Type = WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_REQUEST;
        return TRUE;
    case AP6256_P2P_AF_GO_NEG_RSP:
        *Type = WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_RESPONSE;
        return TRUE;
    case AP6256_P2P_AF_GO_NEG_CONF:
        *Type = WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_CONFIRM;
        return TRUE;
    case AP6256_P2P_AF_INVITE_REQ:
        *Type = WDI_P2P_ACTION_FRAME_INVITATION_REQUEST;
        return TRUE;
    case AP6256_P2P_AF_INVITE_RSP:
        *Type = WDI_P2P_ACTION_FRAME_INVITATION_RESPONSE;
        return TRUE;
    case AP6256_P2P_AF_PROV_DISC_REQ:
        *Type = WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_REQUEST;
        return TRUE;
    case AP6256_P2P_AF_PROV_DISC_RSP:
        *Type = WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_RESPONSE;
        return TRUE;
    default:

        return FALSE;
    }
}

static VOID Ap6256IndicateP2pChannels(_In_ PAP6256_WIFI Wifi)
{
    AP6256_P2P_CHANNEL_PLAN plan;
    WDI_INDICATION_P2P_OPERATING_CHANNEL_ATTRIBUTES_PARAMETERS p;
    WDI_P2P_CHANNEL_ENTRIES_CONTAINER entries[3];
    WDI_COUNTRY_REGION_LIST country;
    WDI_CHANNEL_NUMBER channels[64];
    WDI_MESSAGE_HEADER header = {0};
    PUCHAR generated = NULL;
    ULONG length = 0, index, groups = 0;
    NTSTATUS status;
    RtlZeroMemory(&p, sizeof(p));
    RtlZeroMemory(entries, sizeof(entries));
    RtlZeroMemory(&country, sizeof(country));
    if (!Wifi->Ctx->FirmwareP2pSupported || (!Wifi->PortCreated && !Wifi->P2pPortCreated) ||
        !Wifi->HardwareAvailable)
        return;
    status = Ap6256P2pGetChannelPlan(Wifi->Ctx, (ULONG)Wifi->DisallowedBandMask, &plan);
    if (!NT_SUCCESS(status)) {
        TraceDiag("P2P channel attributes: firmware query -> 0x%08X\n", status);
        return;
    }
    for (index = 0; index < plan.Count; index++) {
        channels[index] = plan.Channels[index];
        if (index == 0 || plan.Classes[index] != plan.Classes[index - 1]) {
            if (groups == RTL_NUMBER_OF(entries))
                return;
            entries[groups].OperatingClass = plan.Classes[index];
            entries[groups++].ChannelList.pElements = &channels[index];
        }
        entries[groups - 1].ChannelList.ElementCount++;
    }
    RtlCopyMemory(country.CountryOrRegionString, Wifi->Ctx->P2p.CountryString, 3);
    p.ChannelList.CountryRegionList.pElements = &country;
    p.ChannelList.CountryRegionList.ElementCount = 1;
    p.ChannelList.ChannelEntries.pElements = entries;
    p.ChannelList.ChannelEntries.ElementCount = groups;
    RtlCopyMemory(p.PreferredOperatingChannel.CountryOrRegionString, Wifi->Ctx->P2p.CountryString,
                  3);
    p.PreferredOperatingChannel.OperatingClass = plan.OperatingClass;
    p.PreferredOperatingChannel.ChannelNumber = plan.OperatingChannel;
    RtlCopyMemory(p.PreferredListenChannel.CountryOrRegionString, Wifi->Ctx->P2p.CountryString, 3);
    p.PreferredListenChannel.OperatingClass = 81;
    p.PreferredListenChannel.ChannelNumber = Wifi->Ctx->P2p.ListenChannel;
    header.PortId = Wifi->P2pPortCreated ? AP6256_DISCOVERY_PORT : AP6256_STATION_PORT;
    status = Ap6256NdisToNtStatus(GenerateWdiIndicationP2pOperatingChannelAttributes(
        &p, 0, &Wifi->TlvContext, &length, &generated));
    if (NT_SUCCESS(status) && generated != NULL)
        status = Ap6256SendGeneratedIndication(
            Wifi, WDI_INDICATION_P2P_OPERATING_CHANNEL_ATTRIBUTES, &header,
            WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated, length);
    FreeGenerated(generated);
    TraceDiag("P2P channel attributes: port %u op %u/%u listen %u, %u channel(s) -> 0x%08X\n",
              (ULONG)header.PortId, (ULONG)plan.OperatingClass, (ULONG)plan.OperatingChannel,
              (ULONG)Wifi->Ctx->P2p.ListenChannel, plan.Count, status);
}

VOID Ap6256IndicateP2pGroupChannel(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header,
                                   _In_opt_ PVOID RequestId, _In_ UINT32 Channel)
{
    WDI_INDICATION_P2P_GROUP_OPERATING_CHANNEL_PARAMETERS p;
    PUCHAR generated = NULL;
    ULONG length = 0;
    NTSTATUS status;
    RtlZeroMemory(&p, sizeof(p));
    RtlCopyMemory(p.Channel.CountryOrRegionString, Wifi->Ctx->P2p.CountryString, 3);
    p.Channel.ChannelNumber = Channel;
    p.Channel.OperatingClass = Ap6256P2pChannelClass(Channel);
    p.IndicateReason = WDI_P2P_CHANNEL_INDICATE_REASON_NEW_CONNECTION;

    p.APBandInformation.BandID = Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000;
    p.APBandInformation.IsPCPinPBSS = FALSE;
    status = Ap6256NdisToNtStatus(GenerateWdiIndicationP2pGroupOperatingChannel(
        &p, 0, &Wifi->TlvContext, &length, &generated));
    if (NT_SUCCESS(status) && generated != NULL)
        status = Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_P2P_GROUP_OPERATING_CHANNEL,
                                               Header, WDI_TRANSACTION_ID_UNSOLICIT, RequestId,
                                               generated, length);
    FreeGenerated(generated);
    TraceDiag("P2P group channel: port %u op %u/%u -> 0x%08X\n", (ULONG)Header->PortId,
              (ULONG)p.Channel.OperatingClass, Channel, status);
}

static VOID
Ap6256NetP2pActionFrameReceived(_In_ PAP6256_WIFI Wifi, _In_ WDI_P2P_ACTION_FRAME_TYPE Type,
                                _In_ UINT16 Chanspec, _In_reads_(6) const UCHAR* SourceAddress,
                                _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length)
{
    WDI_INDICATION_P2P_ACTION_FRAME_RECEIVED_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    UINT32 channel = 0;
    WDI_BAND_ID band;
    Ap6256ChanspecToChannel(Chanspec, &channel, &band);

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));

    parameters.FrameInfo.Optional.DeviceContext_IsPresent = TRUE;
    parameters.FrameInfo.DeviceContext.pElements = (UINT8*)&channel;
    parameters.FrameInfo.DeviceContext.ElementCount = sizeof(channel);
    parameters.FrameInfo.FrameParams.ActionFrameType = Type;
    RtlCopyMemory(parameters.FrameInfo.FrameParams.PeerDeviceAddress.Address, SourceAddress, 6);
    parameters.FrameInfo.FrameParams.DialogToken = Body[7];

    parameters.FrameInfo.FrameIEs.ElementCount = Length - AP6256_P2P_ACTION_HEADER;
    parameters.FrameInfo.FrameIEs.pElements = (UINT8*)(Body + AP6256_P2P_ACTION_HEADER);
    parameters.FrameInfo.FrameIEs.MemoryInternallyAllocated = FALSE;

    Ap6256P2pTraceAction(FALSE, Body[6], Body[7], channel, Body + AP6256_P2P_ACTION_HEADER,
                         Length - AP6256_P2P_ACTION_HEADER);

    TraceDiag("P2P action frame type %u token %u from "
              "%02X:%02X:%02X:%02X:%02X:%02X, %u IE byte(s)\n",
              (ULONG)Type, (ULONG)Body[7], SourceAddress[0], SourceAddress[1], SourceAddress[2],
              SourceAddress[3], SourceAddress[4], SourceAddress[5],
              Length - AP6256_P2P_ACTION_HEADER);

    if (GenerateWdiIndicationP2pActionFrameReceived(&parameters, 0, &Wifi->TlvContext,
                                                    &generatedLength,
                                                    &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = AP6256_DISCOVERY_PORT;
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_P2P_ACTION_FRAME_RECEIVED,
                                             &header, WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetActionFrameReceived(
    _In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR IfIndex, _In_ UCHAR BssCfgIndex,
    _In_reads_(6) const UCHAR* SourceAddress, _In_ UINT16 Chanspec,
    _In_reads_bytes_(Length) const UCHAR* Body, _In_ ULONG Length)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_P2P_ACTION_FRAME_TYPE p2pType;
    WDI_INDICATION_ACTION_FRAME_RECEIVED_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    UINT32 channel = 0;
    WDI_BAND_ID band = WDI_BAND_ID_UNKNOWN;
    UINT16 port;

    if (wifi == NULL || wifi->Stopping || !Ctx->DatapathRunning || Body == NULL || Length == 0)
        return;

    if (Ap6256P2pActionFrameType(Body, Length, &p2pType)) {
        if (!wifi->P2pPortCreated)
            return;
        Ap6256NetP2pActionFrameReceived(wifi, p2pType, Chanspec, SourceAddress, Body, Length);
        return;
    }

    if (IfIndex == 0 && BssCfgIndex == 0 && wifi->PortCreated) {
        port = AP6256_STATION_PORT;
    } else if (wifi->P2pPortCreated && Ctx->P2pBssValid && BssCfgIndex == Ctx->P2pBssIndex &&
               IfIndex == Ap6256WifiP2pInterface(Ctx)) {
        port = AP6256_DISCOVERY_PORT;
    } else if (Ctx->Go.Created && Ctx->Go.FirmwareReady && BssCfgIndex == Ctx->Go.BssIndex &&
               IfIndex == Ctx->Go.IfIndex) {
        port = AP6256_GROUP_PORT;
    } else {
        TraceWarn(TRACE_NETADAPTER, "action frame for unavailable interface %u bsscfg %u\n",
                  IfIndex, BssCfgIndex);
        return;
    }
    Ap6256ChanspecToChannel(Chanspec, &channel, &band);
    if (channel == 0 || band == WDI_BAND_ID_UNKNOWN)
        return;

    if (port == AP6256_STATION_PORT && Ap6256OwnsManagementFrame(Ctx, Body, Length, FALSE))
        return;
    if (port == AP6256_STATION_PORT && Ctx->FirmwareNativeManagement && Length >= 2 &&
        Body[0] == 10 && Body[1] == 7 &&
        (Length < 7 || !Ctx->FirmwareBssTransitionEnabled || !Ctx->FirmwareLinkUp ||
         !wifi->ConnectBssidValid || !RtlEqualMemory(SourceAddress, wifi->ConnectBssid, 6))) {
        TraceWarn(TRACE_NETADAPTER, "BTM request outside the current station association\n");
        return;
    }

    if (port == AP6256_STATION_PORT && Length >= 7 && Body[0] == 10 && Body[1] == 7)
        Ap6256MboBtmRequest(wifi, SourceAddress, Body, Length);

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));

    RtlCopyMemory(parameters.SourceAddress.Address, SourceAddress, 6);
    parameters.ChannelInfo.ChannelNumber = (WDI_CHANNEL_NUMBER)channel;
    parameters.ChannelInfo.BandId = band;
    parameters.ActionFrameBody.ElementCount = Length;
    parameters.ActionFrameBody.pElements = (UINT8*)Body;
    parameters.ActionFrameBody.MemoryInternallyAllocated = FALSE;

    TraceDiag("action frame from %02X:%02X:%02X:%02X:%02X:%02X, %u byte(s), "
              "chanspec 0x%04X (channel %u, band %u), category %u action %u\n",
              SourceAddress[0], SourceAddress[1], SourceAddress[2], SourceAddress[3],
              SourceAddress[4], SourceAddress[5], Length, (ULONG)Chanspec, channel, (ULONG)band,
              Body[0], Length >= 2 ? Body[1] : 255u);

    if (GenerateWdiIndicationActionFrameReceived(&parameters, 0, &wifi->TlvContext,
                                                 &generatedLength,
                                                 &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = port;
        (VOID) Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_ACTION_FRAME_RECEIVED, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetNloDiscovery(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                                  _In_ PAP6256_BSS Bss)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER header = {0};
    WDI_INDICATION_NLO_DISCOVERY_PARAMETERS parameters = {0};
    WDI_BSS_ENTRY_CONTAINER entry = {0};
    UCHAR body[12 + AP6256_SCAN_IE_MAX] = {0};
    PUCHAR generated = NULL;
    ULONG length = 0;
    NTSTATUS status;
    LARGE_INTEGER discovered;
    if (wifi == NULL || Bss->IesLength == 0 || Bss->IesLength > AP6256_SCAN_IE_MAX)
        return STATUS_DEVICE_NOT_READY;
    if (Ap6256BandIsDisallowed(wifi, Bss->Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000))
        return STATUS_INVALID_PARAMETER;
    body[8] = (UCHAR)Bss->BeaconPeriod;
    body[9] = (UCHAR)(Bss->BeaconPeriod >> 8);
    body[10] = (UCHAR)Bss->Capability;
    body[11] = (UCHAR)(Bss->Capability >> 8);
    RtlCopyMemory(body + 12, Bss->Ies, Bss->IesLength);
    RtlCopyMemory(entry.BSSID.Address, Bss->Bssid, 6);
    if (Bss->FromBeacon) {
        entry.Optional.BeaconFrame_IsPresent = TRUE;
        entry.BeaconFrame.pElements = body;
        entry.BeaconFrame.ElementCount = 12 + Bss->IesLength;
    } else {
        entry.Optional.ProbeResponseFrame_IsPresent = TRUE;
        entry.ProbeResponseFrame.pElements = body;
        entry.ProbeResponseFrame.ElementCount = 12 + Bss->IesLength;
    }
    entry.SignalInfo.RSSI = Bss->Rssi;
    entry.SignalInfo.LinkQuality = Ap6256LinkQualityFromRssi(Bss->Rssi);
    entry.ChannelInfo.ChannelNumber = Bss->Channel;
    entry.ChannelInfo.BandId = Bss->Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000;
    KeQuerySystemTimePrecise(&discovered);
    entry.Optional.EntryAgeInfo_IsPresent = TRUE;
    entry.EntryAgeInfo.HostTimeStamp = (UINT64)discovered.QuadPart;
    entry.EntryAgeInfo.CachedInformation = Bss->FromCache;
    parameters.DeviceDescriptor.pElements = &entry;
    parameters.DeviceDescriptor.ElementCount = 1;
    header.PortId = AP6256_STATION_PORT;
    status = Ap6256NdisToNtStatus(
        GenerateWdiIndicationNloDiscovery(&parameters, 0, &wifi->TlvContext, &length, &generated));
    if (NT_SUCCESS(status) && generated != NULL)
        status =
            Ap6256SendGeneratedIndication(wifi, WDI_INDICATION_NLO_DISCOVERY, &header,
                                          WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated, length);
    else if (NT_SUCCESS(status))
        status = STATUS_INSUFFICIENT_RESOURCES;
    FreeGenerated(generated);
    TraceInfo(TRACE_NETADAPTER, "NLO discovery delivered 0x%08X ch %u ies %u\n", status,
              Bss->Channel, Bss->IesLength);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanResult(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_ PAP6256_BSS Bss)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER taskHeader;
    WDI_INDICATION_BSS_ENTRY_LIST_PARAMETERS parameters;
    WDI_BSS_ENTRY_CONTAINER entry;
    UCHAR frameBody[12 + AP6256_SCAN_IE_MAX];
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    NDIS_STATUS ndisStatus;
    KIRQL oldIrql;
    LARGE_INTEGER discovered;
    PVOID taskRequestId;

    if (wifi == NULL || Bss->SyncId != (UINT16)Ctx->ScanSyncId)
        return;

    if (Bss->IesLength > AP6256_SCAN_IE_MAX) {
        InterlockedIncrement(&wifi->ScanDropped);
        TraceWarn(TRACE_NETADAPTER, "scan BSS dropped: %u IE bytes exceeds %u\n", Bss->IesLength,
                  AP6256_SCAN_IE_MAX);
        return;
    }
    if (Ap6256BandIsDisallowed(wifi, Bss->Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000)) {
        InterlockedIncrement(&wifi->ScanDropped);
        TraceInfo(TRACE_NETADAPTER, "scan BSS dropped: channel %u band disallowed (mask 0x%X)\n",
                  Bss->Channel, InterlockedCompareExchange(&wifi->DisallowedBandMask, 0, 0));
        return;
    }
    KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
    if (!wifi->ScanTask.Active && !wifi->P2pDiscoverTask.Active) {
        KeReleaseSpinLock(&wifi->CommandLock, oldIrql);
        InterlockedIncrement(&wifi->ScanDropped);
        TraceInfo(TRACE_NETADAPTER, "scan BSS dropped: no scan task active\n");
        return;
    }
    taskHeader = wifi->ScanTask.Active ? wifi->ScanTask.Header : wifi->P2pDiscoverTask.Header;
    taskRequestId =
        wifi->ScanTask.Active ? wifi->ScanTask.RequestId : wifi->P2pDiscoverTask.RequestId;
    KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

    if (Ap6256ServiceScanResult(wifi, Bss)) return;
    Ap6256MboScanResult(wifi, Bss);

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&entry, sizeof(entry));
    RtlZeroMemory(frameBody, sizeof(frameBody));
    frameBody[8] = (UCHAR)Bss->BeaconPeriod;
    frameBody[9] = (UCHAR)(Bss->BeaconPeriod >> 8);
    frameBody[10] = (UCHAR)Bss->Capability;
    frameBody[11] = (UCHAR)(Bss->Capability >> 8);
    if (Bss->IesLength != 0) {
        RtlCopyMemory(frameBody + 12, Bss->Ies, Bss->IesLength);
    }

    RtlCopyMemory(entry.BSSID.Address, Bss->Bssid, sizeof(Bss->Bssid));

    if (Bss->FromBeacon) {
        entry.Optional.BeaconFrame_IsPresent = TRUE;
        entry.BeaconFrame.ElementCount = 12 + Bss->IesLength;
        entry.BeaconFrame.pElements = frameBody;
        entry.BeaconFrame.MemoryInternallyAllocated = FALSE;
    } else {
        entry.Optional.ProbeResponseFrame_IsPresent = TRUE;
        entry.ProbeResponseFrame.ElementCount = 12 + Bss->IesLength;
        entry.ProbeResponseFrame.pElements = frameBody;
        entry.ProbeResponseFrame.MemoryInternallyAllocated = FALSE;
    }
    entry.SignalInfo.RSSI = Bss->Rssi;
    entry.SignalInfo.LinkQuality = Ap6256LinkQualityFromRssi(Bss->Rssi);
    entry.ChannelInfo.ChannelNumber = Bss->Channel;
    entry.ChannelInfo.BandId = Bss->Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000;

    KeQuerySystemTimePrecise(&discovered);
    entry.Optional.EntryAgeInfo_IsPresent = TRUE;
    entry.EntryAgeInfo.HostTimeStamp = (UINT64)discovered.QuadPart;
    entry.EntryAgeInfo.CachedInformation = Bss->FromCache;

    parameters.Optional.DeviceDescriptor_IsPresent = TRUE;
    parameters.DeviceDescriptor.ElementCount = 1;
    parameters.DeviceDescriptor.pElements = &entry;
    parameters.DeviceDescriptor.MemoryInternallyAllocated = FALSE;
    ndisStatus = GenerateWdiIndicationBssEntryList(&parameters, 0, &wifi->TlvContext,
                                                   &generatedLength, &generated);
    if (ndisStatus == NDIS_STATUS_SUCCESS && generated != NULL) {

        NTSTATUS sendStatus = Ap6256SendGeneratedIndication(
            wifi, WDI_INDICATION_BSS_ENTRY_LIST, &taskHeader, WDI_TRANSACTION_ID_UNSOLICIT,
            taskRequestId, generated, generatedLength);
        if (NT_SUCCESS(sendStatus)) {
            InterlockedIncrement(&wifi->ScanIndicated);
            if (taskHeader.PortId == AP6256_DISCOVERY_PORT) {
                TraceDiag("P2P result %02X:%02X:%02X:%02X:%02X:%02X "
                          "ch %u %s ies %u -> indicated\n",
                          Bss->Bssid[0], Bss->Bssid[1], Bss->Bssid[2], Bss->Bssid[3], Bss->Bssid[4],
                          Bss->Bssid[5], Bss->Channel,
                          Bss->FromBeacon ? "beacon" : "probe response", Bss->IesLength);
            }

            TraceVerbose(TRACE_NETADAPTER,
                         "scan BSS '%.*s' %02X:%02X:%02X:%02X:%02X:%02X "
                         "rssi=%d ch=%u ies=%u -> indicated\n",
                         (int)Bss->SsidLength, Bss->Ssid, Bss->Bssid[0], Bss->Bssid[1],
                         Bss->Bssid[2], Bss->Bssid[3], Bss->Bssid[4], Bss->Bssid[5], Bss->Rssi,
                         Bss->Channel, Bss->IesLength);
        } else {

            InterlockedIncrement(&wifi->ScanDropped);
            TraceError(TRACE_NETADAPTER, "scan BSS indication REFUSED 0x%08X (%u bytes)\n",
                       sendStatus, generatedLength);
        }
    } else {
        InterlockedIncrement(&wifi->ScanDropped);
        TraceError(TRACE_NETADAPTER, "BSS indication generation failed 0x%08X\n", ndisStatus);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetScanComplete(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                              _In_ NTSTATUS CompletionStatus)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    WDI_MESSAGE_HEADER header;
    PVOID requestId;

    if (wifi != NULL && wifi->P2pDiscoverTask.Active) {

        if (InterlockedCompareExchange(&wifi->Ctx->P2p.DiscoverScanPending, 0, 0) != 0) {
            TraceDiag("P2P scan complete sync %u status 0x%08X: %ld indicated, %ld dropped\n",
                      (UINT16)Ctx->ScanSyncId, CompletionStatus,
                      InterlockedCompareExchange(&wifi->ScanIndicated, 0, 0),
                      InterlockedCompareExchange(&wifi->ScanDropped, 0, 0));
            wifi->Ctx->P2p.DiscoverStatus = CompletionStatus;
            InterlockedExchange(&wifi->Ctx->P2p.DiscoverScanPending, 0);
        }
        return;
    }
    if (wifi != NULL) {

        AP6256_TIMER_STOP(wifi->ScanTimer, FALSE);
    }
    if (wifi != NULL && Ap6256ClaimTask(wifi, &wifi->ScanTask, &header, &requestId)) {

        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SCAN_COMPLETE, &header,
                                      header.TransactionId, requestId, CompletionStatus, NULL, 0);

        TraceInfo(TRACE_NETADAPTER, "WDI scan complete 0x%08X: %d indicated, %d dropped\n",
                  CompletionStatus, InterlockedCompareExchange(&wifi->ScanIndicated, 0, 0),
                  InterlockedCompareExchange(&wifi->ScanDropped, 0, 0));
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
static VOID Ap6256StoreConnectRestrictions(
    _In_ PAP6256_WIFI Wifi, _In_opt_ const WDI_ADDRESS_LIST_CONTAINER* Allowed,
    _In_opt_ const WDI_ADDRESS_LIST_CONTAINER* Disallowed, _In_ LONG DisallowedBands)
{
    KIRQL oldIrql;
    ULONG index;

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    RtlZeroMemory(Wifi->ConnectAllowed, sizeof(Wifi->ConnectAllowed));
    RtlZeroMemory(Wifi->ConnectDisallowed, sizeof(Wifi->ConnectDisallowed));
    Wifi->ConnectAllowedCount = 0;
    Wifi->ConnectDisallowedCount = 0;
    Wifi->ConnectDisallowedBands = DisallowedBands;

    if (Allowed != NULL && Allowed->pElements != NULL) {
        for (index = 0; index < Allowed->ElementCount && index < AP6256_CONNECT_BSSID_LIMIT;
             index++) {
            RtlCopyMemory(Wifi->ConnectAllowed[index], Allowed->pElements[index].Address, 6);
        }
        Wifi->ConnectAllowedCount = index;
    }
    if (Disallowed != NULL && Disallowed->pElements != NULL) {
        for (index = 0; index < Disallowed->ElementCount && index < AP6256_CONNECT_BSSID_LIMIT;
             index++) {
            RtlCopyMemory(Wifi->ConnectDisallowed[index], Disallowed->pElements[index].Address, 6);
        }
        Wifi->ConnectDisallowedCount = index;
    }
    Wifi->ConnectRestricted = (BOOLEAN)(Wifi->ConnectAllowedCount != 0 ||
                                        Wifi->ConnectDisallowedCount != 0 || DisallowedBands != 0);
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
PCSTR Ap6256ConnectBssRejection(_In_ PAP6256_WIFI Wifi,
                                                                    _In_reads_(6)
                                                                        const UCHAR* Bssid,
                                                                    _In_ ULONG Channel)
{
    PCSTR reason = NULL;
    KIRQL oldIrql;
    ULONG index;

    if (Ap6256MboJoinBlocked(Wifi, Bssid)) return "MBO association restriction or retry delay";
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (Wifi->ConnectRestricted) {
        for (index = 0; index < Wifi->ConnectDisallowedCount; index++) {
            if (RtlCompareMemory(Bssid, Wifi->ConnectDisallowed[index], 6) == 6) {
                reason = "it is on the host's disallowed list";
                break;
            }
        }
        if (reason == NULL && Wifi->ConnectAllowedCount != 0) {
            BOOLEAN found = FALSE;
            for (index = 0; index < Wifi->ConnectAllowedCount; index++) {
                if (RtlCompareMemory(Bssid, Wifi->ConnectAllowed[index], 6) == 6) {
                    found = TRUE;
                    break;
                }
            }
            if (!found)
                reason = "it is not on the host's allowed list";
        }
        if (reason == NULL && Wifi->ConnectDisallowedBands != 0 && Channel != 0 &&
            Ap6256BandIsMasked(Wifi->ConnectDisallowedBands,
                               Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000)) {
            reason = "the host disallowed its band";
        }
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    return reason;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID
Ap6256IndicateDisassociation(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header)
{
    WDI_INDICATION_DISASSOCIATION_PARAMETERS parameters;
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;
    NDIS_STATUS ndisStatus;
    KIRQL oldIrql;

    (VOID)Ap6256HostCipherEnd(Wifi->Ctx, 0, FALSE);
    (VOID)Ap6256FipsRetire(Wifi->Ctx, 0);
    Ap6256ModelConnectionLost(Wifi);
    Ap6256MboDisassociated(Wifi);
    Ap6256ClearPmOffloads(Wifi);
    RtlZeroMemory(Wifi->ArpOffloadValid, sizeof(Wifi->ArpOffloadValid));
    RtlZeroMemory(Wifi->ArpOffloadIds, sizeof(Wifi->ArpOffloadIds));
    RtlZeroMemory(Wifi->ArpOffloads, sizeof(Wifi->ArpOffloads));
    RtlZeroMemory(Wifi->NsOffloads, sizeof(Wifi->NsOffloads));
    Wifi->NsOffloadCount = 0;
    Wifi->GtkOffloadValid = FALSE;
    Wifi->GtkOffloadId = 0;
    RtlSecureZeroMemory(&Wifi->GtkOffload, sizeof(Wifi->GtkOffload));
    RtlZeroMemory(&parameters, sizeof(parameters));
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    Wifi->Mbo.Associated = FALSE;
    RtlZeroMemory(&Wifi->Mbo.AssociatedAp, sizeof(Wifi->Mbo.AssociatedAp));
    RtlZeroMemory(&Wifi->Mbo.Transition, sizeof(Wifi->Mbo.Transition));
    RtlCopyMemory(parameters.DisconnectIndicationParameters.MacAddress.Address, Wifi->ConnectBssid,
                  sizeof(Wifi->ConnectBssid));
    Wifi->ConnectBssidValid = FALSE;
    Wifi->ConnectionActive = FALSE;
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);

    Ap6256ModelDeleteStationPeer(Wifi);

    parameters.DisconnectIndicationParameters.DisassociationWABIReason =
        WDI_ASSOC_STATUS_DISASSOCIATED_BY_HOST;
    parameters.Optional.NeedPeerStateCleanup_IsPresent = TRUE;
    parameters.NeedPeerStateCleanup = TRUE;
    ndisStatus = GenerateWdiIndicationDisassociation(&parameters, 0, &Wifi->TlvContext,
                                                     &generatedLength, &generated);
    if (ndisStatus == NDIS_STATUS_SUCCESS && generated != NULL) {
        (VOID) Ap6256SendGeneratedIndication(
            Wifi, WDI_INDICATION_DISASSOCIATION, Header, WDI_TRANSACTION_ID_UNSOLICIT,
            Wifi->DisconnectTask.RequestId, generated, generatedLength);
    }
    FreeGenerated(generated);
}

static VOID Ap6256ExpireConnect(_In_ PAP6256_WIFI wifi)
{
    WDI_MESSAGE_HEADER header;
    PVOID requestId;
    Ap6256LockAcquire(&wifi->ConnectLock);
    if (Ap6256ClaimExpiredTask(wifi, &wifi->ConnectTask, &header, &requestId)) {

        Ap6256ModelCancelAuthentication(wifi);
        wifi->ConnectCandidateCount = 0;
        wifi->ConnectDeparting = FALSE;
        InterlockedIncrement(&wifi->ConnectGeneration);
        TraceError(TRACE_NETADAPTER, "connect timed out with no association from the firmware\n");
        (VOID) Ap6256WifiDisconnect(wifi->Ctx);
        if (wifi->ConnectionActive)
            Ap6256IndicateDisassociation(wifi, &header);
        else
            Ap6256IndicateAssociation(wifi, &header, requestId, FALSE);
        (VOID) Ap6256SendIndicationRq(wifi, Ap6256ConnectCompletionId(wifi), &header,
                                      header.TransactionId, requestId, STATUS_IO_TIMEOUT, NULL, 0);
    }
    Ap6256LockRelease(&wifi->ConnectLock);
}

_IRQL_requires_max_(PASSIVE_LEVEL)

static VOID
Ap6256NetLinkStateWork(_In_ PAP6256_WIFI Wifi)
{
    WDI_INDICATION_LINK_STATE_CHANGE_PARAMETERS parameters;
    WDI_MESSAGE_HEADER header;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    UCHAR bssid[6] = {0, 0, 0, 0, 0, 0};
    UINT32 rateHalfMbps = 0;
    UINT32 chanspec = 0;
    UINT32 speedKbps;
    INT32 rssi = 0;

    if (!Wifi->PortCreated || !Wifi->ConnectionActive)
        return;

    (VOID) Ap6256WifiGetLinkRate(Wifi->Ctx, &rateHalfMbps);
    if (!NT_SUCCESS(Ap6256WifiGetBssid(Wifi->Ctx, bssid)))
        return;
    (VOID) Ap6256WifiGetRssi(Wifi->Ctx, &rssi);
    (VOID) Ap6256WifiGetChanspec(Wifi->Ctx, &chanspec);

    speedKbps = rateHalfMbps * 500u;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&header, sizeof(header));
    RtlCopyMemory(parameters.LinkStateChangeParameters.PeerMACAddress.Address, bssid, 6);

    parameters.LinkStateChangeParameters.TxLinkSpeed = speedKbps;
    parameters.LinkStateChangeParameters.RxLinkSpeed = speedKbps;
    parameters.LinkStateChangeParameters.LinkQuality = (UINT8)Ap6256LinkQualityFromRssi(rssi);

    TraceInfo(TRACE_NETADAPTER,
              "link state: %02X:%02X:%02X:%02X:%02X:%02X %u kbps, "
              "RSSI %d dBm, quality %u, chanspec 0x%04X\n",
              bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5], speedKbps, rssi,
              (ULONG)parameters.LinkStateChangeParameters.LinkQuality, chanspec);

    if (GenerateWdiIndicationLinkStateChange(&parameters, 0, &Wifi->TlvContext, &generatedLength,
                                             &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        header.PortId = Wifi->PortNumber;
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_LINK_STATE_CHANGE, &header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

static VOID Ap6256NetLinkChangeWork(_In_ PAP6256_WIFI wifi, _In_ BOOLEAN LinkUp,
                                    _In_ BOOLEAN JoinFailed, _In_ LONG Generation,
                                    _In_ UINT32 FirmwareGeneration, _In_ UCHAR FirmwareEvent)
{
    WDI_MESSAGE_HEADER taskHeader;
    WDI_MESSAGE_HEADER indicationHeader;
    PVOID taskRequestId = NULL;
    BOOLEAN connectPending;
    BOOLEAN disconnectPending;
    BOOLEAN hadConnection;
    KIRQL oldIrql;

    if (!Ap6256ModelLinkUsable(wifi))
        return;

    AP6256_TIMER_STOP(wifi->ConnectTimer, TRUE);
    AP6256_TIMER_STOP(wifi->DisconnectTimer, TRUE);

    Ap6256LockAcquire(&wifi->ConnectLock);
    if (Generation != wifi->ConnectGeneration

        || Ap6256ModelStaleLinkEvent(wifi, FirmwareEvent, FirmwareGeneration)) {

        if (wifi->DisconnectTask.Active)
            AP6256_TIMER_START(
                wifi->DisconnectTimer,
                (ULONG)max(1ll, wifi->DisconnectTask.DeadlineMs - Ap6256InterruptTimeMs()));
        if (wifi->ConnectTask.Active)
            goto StillJoining;
        Ap6256LockRelease(&wifi->ConnectLock);
        return;
    }
    KeAcquireSpinLock(&wifi->CommandLock, &oldIrql);
    indicationHeader = wifi->IndicationHeader;
    connectPending = wifi->ConnectTask.Active;
    disconnectPending = wifi->DisconnectTask.Active;
    hadConnection = wifi->ConnectionActive;
    taskHeader = connectPending
                     ? wifi->ConnectTask.Header
                     : (disconnectPending ? wifi->DisconnectTask.Header : indicationHeader);
    taskRequestId = connectPending ? wifi->ConnectTask.RequestId
                                   : (disconnectPending ? wifi->DisconnectTask.RequestId : NULL);
    KeReleaseSpinLock(&wifi->CommandLock, oldIrql);

    if (connectPending) {
        NTSTATUS status = STATUS_UNSUCCESSFUL;
        BOOLEAN associated = FALSE;
        if (wifi->ConnectDeparting) {
            if (LinkUp)
                goto StillJoining;

            Ap6256IndicateDisassociation(wifi, &taskHeader);
            wifi->ConnectDeparting = FALSE;
            status = Ap6256StationStartNext(wifi);
            if (NT_SUCCESS(status))
                goto StillJoining;
        } else if (LinkUp || JoinFailed) {
            associated = Ap6256IndicateAssociation(wifi, &taskHeader, taskRequestId, LinkUp);
            if (!associated) {

                if (!Ap6256ModelRetryAssociation(wifi))
                    ++wifi->ConnectCandidateIndex;
                status = Ap6256StationStartNext(wifi);
                if (NT_SUCCESS(status))
                    goto StillJoining;
            } else
                status = STATUS_SUCCESS;
        } else {

            goto StillJoining;
        }
        (VOID) Ap6256ClaimTask(wifi, &wifi->ConnectTask, &taskHeader, &taskRequestId);

        Ap6256ModelCompleteAuthentication(wifi);
        wifi->ConnectCandidateCount = 0;
        wifi->ConnectDeparting = FALSE;

        if (!associated)
            InterlockedIncrement(&wifi->ConnectGeneration);
        LinkUp = associated;
        (VOID) Ap6256SendIndicationRq(wifi, Ap6256ConnectCompletionId(wifi), &taskHeader,
                                      taskHeader.TransactionId, taskRequestId, status, NULL, 0);

        Ap6256ModelOpenStationReceive(wifi, associated);
    } else if (!LinkUp && disconnectPending) {
        (VOID) Ap6256ClaimTask(wifi, &wifi->DisconnectTask, &taskHeader, &taskRequestId);
        Ap6256IndicateDisassociation(wifi, &taskHeader);
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_DISCONNECT_COMPLETE, &taskHeader,
                                      taskHeader.TransactionId, taskRequestId, STATUS_SUCCESS, NULL,
                                      0);
    } else if (!LinkUp && hadConnection) {
        Ap6256IndicateDisassociation(wifi, &indicationHeader);
    } else if (!LinkUp) {

        (VOID)Ap6256HostCipherEnd(wifi->Ctx, 0, FALSE);
        (VOID)Ap6256FipsRetire(wifi->Ctx, 0);
    }
    Ap6256LockRelease(&wifi->ConnectLock);

    Ap6256ModelSetLinkState(wifi, LinkUp);

    if (LinkUp)
        Ap6256WifiArmRoamTriggers(wifi->Ctx);

    if (LinkUp)
        Ap6256NetLinkStateWork(wifi);

    Ap6256IndicateP2pChannels(wifi);

    TraceInfo(TRACE_NETADAPTER, "link %s -> adapter\n", LinkUp ? "up" : "down");
    return;
StillJoining:
    AP6256_TIMER_START(wifi->ConnectTimer,
                       (ULONG)max(1ll, wifi->ConnectTask.DeadlineMs - Ap6256InterruptTimeMs()));
    Ap6256LockRelease(&wifi->ConnectLock);
}

static VOID Ap6256NetRadioStateWork(_In_ PAP6256_WIFI Wifi)
{
    WDI_MESSAGE_HEADER header;
    BOOLEAN hardwareOff = FALSE;
    BOOLEAN softwareOff = FALSE;
    BOOLEAN wasOn;

    if (!Wifi->PortCreated)
        return;
    if (!NT_SUCCESS(Ap6256WifiGetRadioDisabled(Wifi->Ctx, &hardwareOff, &softwareOff))) {
        return;
    }

    wasOn = Wifi->HardwareRadioState;
    Wifi->HardwareRadioState = (BOOLEAN)!hardwareOff;

    if (wasOn != Wifi->HardwareRadioState) {
        TraceInfo(TRACE_NETADAPTER, "radio: hardware %s, software %s\n", hardwareOff ? "OFF" : "on",
                  softwareOff ? "OFF" : "on");
    } else {
        TraceVerbose(TRACE_NETADAPTER, "radio: hardware %s, software %s\n",
                     hardwareOff ? "OFF" : "on", softwareOff ? "OFF" : "on");
    }

    RtlZeroMemory(&header, sizeof(header));
    header.PortId = Wifi->PortNumber;
    Ap6256IndicateRadioStatus(Wifi, &header);

    if (wasOn && hardwareOff)
        Ap6256NetLinkChangeWork(Wifi, FALSE, TRUE, Wifi->ConnectGeneration, 0, FALSE);
}

VOID Ap6256LinkWork(_In_ PAP6256_WIFI wifi)
{

    if (InterlockedCompareExchange(&wifi->LinkDraining, 1, 0) != 0) {
        return;
    }

    for (;;) {
        UCHAR code = AP6256_LINK_DOWN;
        LONG generation = 0;
        UINT32 firmwareGeneration = 0;
        UCHAR firmwareEvent = 0;
        BOOLEAN have = FALSE;
        KIRQL oldIrql;

        KeAcquireSpinLock(&wifi->LinkLock, &oldIrql);
        if (wifi->LinkTail != wifi->LinkHead) {
            code = wifi->LinkEvents[wifi->LinkTail & (AP6256_LINKQ_DEPTH - 1)];
            generation = wifi->LinkGenerations[wifi->LinkTail & (AP6256_LINKQ_DEPTH - 1)];
            firmwareGeneration =
                wifi->LinkFirmwareGenerations[wifi->LinkTail & (AP6256_LINKQ_DEPTH - 1)];
            firmwareEvent = wifi->LinkFirmwareEvents[wifi->LinkTail & (AP6256_LINKQ_DEPTH - 1)];
            wifi->LinkTail++;
            have = TRUE;
        }
        KeReleaseSpinLock(&wifi->LinkLock, oldIrql);

        if (!have) {

            BOOLEAN empty;

            InterlockedExchange(&wifi->LinkDraining, 0);

            KeAcquireSpinLock(&wifi->LinkLock, &oldIrql);
            empty = (BOOLEAN)(wifi->LinkTail == wifi->LinkHead);
            KeReleaseSpinLock(&wifi->LinkLock, oldIrql);

            if (empty || InterlockedCompareExchange(&wifi->LinkDraining, 1, 0) != 0) {
                return;
            }
            continue;
        }

        if (InterlockedCompareExchange(&wifi->Stopping, 0, 0) != 0) {
            continue;
        }

        if (Ap6256ModelClientLinkEvent(wifi, code, generation))
            continue;
        if (code == AP6256_LINK_REFRESH) {
            Ap6256NetLinkStateWork(wifi);
        } else if (code == AP6256_LINK_RADIO) {
            Ap6256NetRadioStateWork(wifi);
        } else {
            if (generation == InterlockedCompareExchange(&wifi->ConnectGeneration, 0, 0))
                Ap6256NetLinkChangeWork(wifi, (BOOLEAN)(code == AP6256_LINK_UP),
                                        (BOOLEAN)(code == AP6256_LINK_JOIN_FAILED), generation,
                                        firmwareGeneration, firmwareEvent);
        }
    }
}

static VOID Ap6256NetQueueLinkEventOwner(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Code,
                                         _In_ LONG Generation, _In_ UINT32 FirmwareGeneration,
                                         _In_ UCHAR FirmwareEvent)
{
    static const char* const names[] = {"down",  "up",          "refresh",
                                        "radio", "client down", "client up"};
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    BOOLEAN queued = FALSE;
    KIRQL oldIrql;

    if (wifi == NULL || !AP6256_LINKQ_OK(wifi))
        return;

    KeAcquireSpinLock(&wifi->LinkLock, &oldIrql);
    if (wifi->LinkHead - wifi->LinkTail < AP6256_LINKQ_DEPTH) {
        wifi->LinkEvents[wifi->LinkHead & (AP6256_LINKQ_DEPTH - 1)] = Code;
        wifi->LinkGenerations[wifi->LinkHead & (AP6256_LINKQ_DEPTH - 1)] = Generation;
        wifi->LinkFirmwareGenerations[wifi->LinkHead & (AP6256_LINKQ_DEPTH - 1)] =
            FirmwareGeneration;
        wifi->LinkFirmwareEvents[wifi->LinkHead & (AP6256_LINKQ_DEPTH - 1)] = FirmwareEvent;

        Ap6256ModelStampLinkEvent(wifi, Code);
        wifi->LinkHead++;
        queued = TRUE;
    }
    KeReleaseSpinLock(&wifi->LinkLock, oldIrql);

    if (!queued) {
        TraceWarn(TRACE_NETADAPTER, "link event queue full; %s dropped\n",
                  Code < ARRAYSIZE(names) ? names[Code] : "?");
        return;
    }

    AP6256_LINKQ_KICK(wifi);
}

static VOID Ap6256NetQueueLinkEventGeneration(_In_ PAP6256_DEVICE_CONTEXT Ctx, _In_ UCHAR Code,
                                              _In_ LONG Generation)
{
    Ap6256NetQueueLinkEventOwner(Ctx, Code, Generation, 0, FALSE);
}

_Use_decl_annotations_
VOID Ap6256NetQueueLinkEvent(PAP6256_DEVICE_CONTEXT Ctx, UCHAR Code)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    if (wifi != NULL)
        Ap6256NetQueueLinkEventGeneration(
            Ctx, Code, InterlockedCompareExchange(&wifi->ConnectGeneration, 0, 0));
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkChange(_In_ PAP6256_DEVICE_CONTEXT Ctx,
                                                            _In_ BOOLEAN LinkUp)
{
    Ap6256NetQueueLinkEvent(Ctx, LinkUp ? AP6256_LINK_UP : AP6256_LINK_DOWN);
}

static VOID Ap6256NetStationLinkEventOwner(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                           BOOLEAN TerminalFailure, const UCHAR* Peer,
                                           UINT32 FirmwareGeneration, UCHAR FirmwareEvent)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    BOOLEAN accept = TRUE;
    KIRQL irql;
    LONG generation;
    if (wifi == NULL)
        return;
    KeAcquireSpinLock(&wifi->CommandLock, &irql);

    if (Ap6256ModelRejectStationEvent(wifi, Ctx, FirmwareEvent, FirmwareGeneration, Peer)) {
        KeReleaseSpinLock(&wifi->CommandLock, irql);
        return;
    }
    if (wifi->ConnectTask.Active) {
        if (wifi->ConnectDeparting) {
            accept = !Up && !TerminalFailure &&
                     (Peer == NULL || !Ap6256MacIsValidUnicast(Peer) ||
                      RtlEqualMemory(Peer, wifi->ConnectBssid, 6));
        } else if (!Up && !TerminalFailure) {

            accept = Ctx->FirmwareLinkUp && Peer != NULL && wifi->ConnectBssidValid &&
                     RtlEqualMemory(Peer, wifi->ConnectBssid, 6);
            if (accept)
                TerminalFailure = TRUE;
        } else if (Up && wifi->ConnectBssidValid && Peer != NULL &&
                   !RtlEqualMemory(Peer, wifi->ConnectBssid, 6)) {
            accept = FALSE;
        }
    } else if (!Up && !TerminalFailure && wifi->ConnectionActive && Peer != NULL &&
               Ap6256MacIsValidUnicast(Peer) && !RtlEqualMemory(Peer, wifi->ConnectBssid, 6)) {
        accept = FALSE;
    } else if (TerminalFailure)
        accept = FALSE;
    generation = wifi->ConnectGeneration;
    if (accept) {
        Ctx->FirmwareLinkUp = Up;
        if (!Up)
            Ctx->SupplicantComplete = FALSE;
    }
    KeReleaseSpinLock(&wifi->CommandLock, irql);
    if (accept && (!Up || !Ctx->ConnectionRequiresSupplicant || Ctx->SupplicantComplete))
        Ap6256NetQueueLinkEventOwner(
            Ctx,
            Up ? AP6256_LINK_UP : (TerminalFailure ? AP6256_LINK_JOIN_FAILED : AP6256_LINK_DOWN),
            generation, FirmwareGeneration, FirmwareEvent);
}

_Use_decl_annotations_
VOID Ap6256NetStationLinkEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                                      BOOLEAN TerminalFailure, const UCHAR* Peer)
{
    Ap6256NetStationLinkEventOwner(Ctx, Up, TerminalFailure, Peer, 0, FALSE);
}

_Use_decl_annotations_
VOID Ap6256NetStationFirmwareEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                                          BOOLEAN TerminalFailure,
                                                          const UCHAR* Peer,
                                                          UINT32 FirmwareGeneration)
{
    Ap6256NetStationLinkEventOwner(Ctx, Up, TerminalFailure, Peer, FirmwareGeneration, TRUE);
}

_Use_decl_annotations_
VOID Ap6256NetStationHostCipherEvent(PAP6256_DEVICE_CONTEXT Ctx, BOOLEAN Up,
                                    BOOLEAN TerminalFailure, const UCHAR* Peer,
                                    UINT32 FirmwareGeneration)
{
    Ap6256NetStationLinkEventOwner(Ctx, Up, TerminalFailure, Peer, FirmwareGeneration,
        AP6256_STATION_EVENT_HOST_CIPHER);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetLinkStateRefresh(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256NetQueueLinkEvent(Ctx, AP6256_LINK_REFRESH);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256NetRadioChanged(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    Ap6256NetQueueLinkEvent(Ctx, AP6256_LINK_RADIO);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256NetHardwareStart(_In_ PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    NTSTATUS status = STATUS_SUCCESS;

    if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0)
        return STATUS_DEVICE_HARDWARE_ERROR;
    if (wifi != NULL && InterlockedCompareExchange(&wifi->Stopping, 0, 0) == 0) {
        if (!wifi->SoftwareRadioState) {
            status = Ap6256WifiSetRadioState(Ctx, FALSE);
            if (!NT_SUCCESS(status))
                return status;
        }

        status = Ap6256ModelStartInterfaces(wifi, Ctx);
        if (!NT_SUCCESS(status))
            return status;
        Ap6256LockAcquire(&wifi->ConnectLock);
        (VOID)Ap6256MboInitialize(wifi);
        Ap6256LockRelease(&wifi->ConnectLock);
        InterlockedExchange(&wifi->HardwareAvailable, 1);

        if (InterlockedCompareExchange(&Ctx->FirmwareHalted, 0, 0) != 0) {
            InterlockedExchange(&wifi->HardwareAvailable, 0);
            return STATUS_DEVICE_HARDWARE_ERROR;
        }
    }
    return status;
}

BOOLEAN Ap6256HostCipherAvailable(_In_ PAP6256_WIFI Wifi)
{
    PAP6256_DEVICE_CONTEXT ctx = Wifi->Ctx;
    return Wifi->TlvContext.PeerVersion >= WDI_VERSION_1_1_9 &&
        ctx->FirmwareHostCipherPatchVerified && ctx->FirmwareState == Ap6256FwRunning &&
        !InterlockedCompareExchange(&ctx->FirmwareHalted, 0, 0) &&
        !(InterlockedCompareExchange(&ctx->HostCipherBlockedMask, 0, 0) & AP6256_HC_FIRMWARE_RETIRED) &&
        InterlockedCompareExchange(&ctx->HostCipherFirmwareQualified, 0, 0) == 1 &&
        InterlockedCompareExchange(&ctx->HostCipherStore.Ready, 0, 0) == 1;
}

ULONG Ap6256CopyAlgoPairs(_In_ PAP6256_WIFI Wifi, _In_reads_(Total) const WDI_ALGO_PAIRS* Source,
                          _In_ ULONG Total, _Out_writes_(Total) WDI_ALGO_PAIRS* Destination)
{
    ULONG i, count = 0;
    RtlZeroMemory(Destination, Total * sizeof(*Destination));
    for (i = 0; i < Total; ++i) {
        if ((Source[i].CipherAlgorithm == WDI_CIPHER_ALGO_GCMP_256 ||
             Source[i].CipherAlgorithm == WDI_CIPHER_ALGO_BIP_GMAC_256) &&
            !Ap6256HostCipherAvailable(Wifi)) continue;
        if (Source[i].CipherAlgorithm == WDI_CIPHER_ALGO_BIP_GMAC_256 &&
            !Wifi->Ctx->FirmwareMfpSupported) continue;

        if ((Source[i].AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT ||
             Source[i].AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT_192) &&
            !Wifi->Ctx->FirmwareMfpSupported) continue;
        if (Source[i].AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE && !Ap6256HostSaeAvailable(Wifi))
            continue;
        if (Source[i].AuthAlgorithm == WDI_AUTH_ALGO_OWE && !Ap6256HostOweAvailable(Wifi))
            continue;
        Destination[count++] = Source[i];
    }
    return count;
}

NTSTATUS Ap6256BeginTask(_In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_WDI_TASK Task,
                         _In_ const WDI_MESSAGE_HEADER* Header, _In_opt_ PVOID RequestId)
{
    KIRQL oldIrql;
    NTSTATUS status = STATUS_SUCCESS;

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (Task->Active) {
        status = STATUS_DEVICE_BUSY;
    } else {
        Task->Active = TRUE;
        Task->Header = *Header;
        Task->RequestId = RequestId;
        Task->DeadlineMs = 0;

        if (Header->PortId == AP6256_STATION_PORT)
            Wifi->IndicationHeader = *Header;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256FailStartedTask(_In_ PAP6256_WIFI Wifi,
                                                              _Inout_ PAP6256_WDI_TASK Task,
                                                              _In_ UINT16 CompletionId,
                                                              _In_ NTSTATUS Status)
{
    WDI_MESSAGE_HEADER header;
    PVOID requestId;

    if (Ap6256ClaimTask(Wifi, Task, &header, &requestId)) {
        (VOID) Ap6256SendIndicationRq(Wifi, CompletionId, &header, header.TransactionId, requestId,
                                      Status, NULL, 0);
    }
}

BOOLEAN Ap6256MacIsValue(_In_reads_(6) const UCHAR* Address, _In_ UCHAR Value)
{
    ULONG index;
    for (index = 0; index < 6; index++) {
        if (Address[index] != Value)
            return FALSE;
    }
    return TRUE;
}

BOOLEAN Ap6256MacIsValidUnicast(_In_reads_(6) const UCHAR* Address)
{
    return Address != NULL && (Address[0] & 1u) == 0 && !Ap6256MacIsValue(Address, 0x00) &&
           !Ap6256MacIsValue(Address, 0xFF);
}

static ULONG Ap6256FirstAuthAlgo(_In_ const WDI_AUTH_ALGORITHM_LIST_CONTAINER* List)
{
    return (List->ElementCount != 0 && List->pElements != NULL) ? (ULONG)List->pElements[0] : 0;
}

static ULONG Ap6256FirstCipherAlgo(_In_ const WDI_CIPHER_ALGORITHM_LIST_CONTAINER* List)
{
    return (List->ElementCount != 0 && List->pElements != NULL) ? (ULONG)List->pElements[0] : 0;
}

BOOLEAN Ap6256AddressInList(_In_reads_(6) const UCHAR* Address,
                            _In_ const WDI_ADDRESS_LIST_CONTAINER* List)
{
    ULONG index;

    if (List->ElementCount != 0 && List->pElements == NULL)
        return FALSE;
    for (index = 0; index < List->ElementCount; index++) {
        if (RtlCompareMemory(Address, List->pElements[index].Address, 6) == 6) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN Ap6256AddressListIsUnrestricted(_In_ const WDI_ADDRESS_LIST_CONTAINER* List)
{
    ULONG index;

    if (List->ElementCount == 0 || List->pElements == NULL)
        return TRUE;
    for (index = 0; index < List->ElementCount; index++) {
        if (Ap6256MacIsValue(List->pElements[index].Address, 0xFF))
            return TRUE;
    }
    return FALSE;
}

static BOOLEAN Ap6256ScanTriggerValid(_In_ WDI_SCAN_TRIGGER Trigger)
{
    switch (Trigger) {
    case WDI_SCAN_TRIGGER_MANUAL:
    case WDI_SCAN_TRIGGER_BACKGROUND:
    case WDI_SCAN_TRIGGER_ROAM:
    case WDI_SCAN_TRIGGER_CONNECT:
    case WDI_SCAN_TRIGGER_ANQP_QUERY:
    case WDI_SCAN_TRIGGER_FAST_ROAM:
    case WDI_SCAN_TRIGGER_FTM:
    case WDI_SCAN_TRIGGER_BEACON_REQUEST:
        return TRUE;
    default:
        return FALSE;
    }
}

BOOLEAN Ap6256ChannelSupported(_In_ AP6256_SCAN_BAND Band, _In_ WDI_CHANNEL_NUMBER Channel)
{
    ULONG index;

    if (Band == Ap6256ScanBand2G) {
        return Channel >= 1 && Channel <= 14;
    }
    for (index = 0; index < RTL_NUMBER_OF(Ap6256Channels5); index++) {
        if (Channel == Ap6256Channels5[index])
            return TRUE;
    }
    return FALSE;
}

static NTSTATUS Ap6256AppendScanChannel(_Inout_ PAP6256_SCAN_PARAMS Params,
                                        _In_ AP6256_SCAN_BAND Band, _In_ UINT16 Channel)
{
    ULONG index;

    for (index = 0; index < Params->ChannelCount; index++) {
        if (Params->Channels[index].Band == Band && Params->Channels[index].Number == Channel) {
            return STATUS_SUCCESS;
        }
    }
    if (Params->ChannelCount == AP6256_SCAN_CHANNEL_MAX) {
        return STATUS_INVALID_PARAMETER;
    }
    Params->Channels[Params->ChannelCount].Band = Band;
    Params->Channels[Params->ChannelCount].Number = Channel;
    Params->ChannelCount++;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256AppendBandChannels(_Inout_ PAP6256_SCAN_PARAMS Params,
                                         _In_ AP6256_SCAN_BAND Band)
{
    ULONG index;
    NTSTATUS status;

    if (Band == Ap6256ScanBand2G) {
        for (index = 1; index <= 14; index++) {
            status = Ap6256AppendScanChannel(Params, Band, (UINT16)index);
            if (!NT_SUCCESS(status))
                return status;
        }
        return STATUS_SUCCESS;
    }
    for (index = 0; index < RTL_NUMBER_OF(Ap6256Channels5); index++) {
        status = Ap6256AppendScanChannel(Params, Band, Ap6256Channels5[index]);
        if (!NT_SUCCESS(status))
            return status;
    }
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256PopulateAllowedScanChannels(_In_ PAP6256_WIFI Wifi,
                                                  _Inout_ PAP6256_SCAN_PARAMS Params)
{
    LONG mask = InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0);
    NTSTATUS status;

    if (mask == 0)
        return STATUS_SUCCESS;
    if ((mask & AP6256_DISALLOW_BAND_2G) == 0) {
        status = Ap6256AppendBandChannels(Params, Ap6256ScanBand2G);
        if (!NT_SUCCESS(status))
            return status;
    }
    if ((mask & AP6256_DISALLOW_BAND_5G) == 0) {
        status = Ap6256AppendBandChannels(Params, Ap6256ScanBand5G);
        if (!NT_SUCCESS(status))
            return status;
    }
    return Params->ChannelCount != 0 ? STATUS_SUCCESS : STATUS_NETWORK_UNREACHABLE;
}

static NTSTATUS Ap6256CaptureScanParameters(_In_ PAP6256_WIFI Wifi,
                                            _In_ const WDI_SCAN_PARAMETERS* Wdi,
                                            _Out_ AP6256_SCAN_PARAMS* Params)
{
    ULONG index;
    ULONG channelIndex;
    BOOLEAN broadcast;
    BOOLEAN zero;

    RtlZeroMemory(Params, sizeof(*Params));
    RtlCopyMemory(Params->Bssid, Wdi->BSSID.Address, sizeof(Params->Bssid));
    broadcast = Ap6256MacIsValue(Params->Bssid, 0xFF);
    zero = Ap6256MacIsValue(Params->Bssid, 0x00);
    if (!broadcast && (zero || (Params->Bssid[0] & 1u) != 0)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (Wdi->SSIDList.ElementCount > AP6256_SCAN_SSID_MAX ||
        (Wdi->SSIDList.ElementCount != 0 && Wdi->SSIDList.pElements == NULL)) {
        return STATUS_INVALID_PARAMETER;
    }
    Params->SsidCount = Wdi->SSIDList.ElementCount;
    for (index = 0; index < Params->SsidCount; index++) {
        const WDI_SSID* source = &Wdi->SSIDList.pElements[index];
        if (source->ElementCount > sizeof(Params->Ssids[index].Data) ||
            (source->ElementCount != 0 && source->pElements == NULL)) {
            return STATUS_INVALID_PARAMETER;
        }
        Params->Ssids[index].Length = source->ElementCount;
        if (source->ElementCount != 0) {
            RtlCopyMemory(Params->Ssids[index].Data, source->pElements, source->ElementCount);
        }
    }

    if (!Ap6256ScanTriggerValid(Wdi->ScanModeParameters.ScanTrigger)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Wdi->ScanModeParameters.ScanRepeatCount != 1) {
        return STATUS_NOT_SUPPORTED;
    }
    switch (Wdi->ScanModeParameters.AllowedScanType) {
    case WDI_SCAN_TYPE_ACTIVE_ONLY:
        Params->ScanType = Ap6256ScanTypeActive;
        break;
    case WDI_SCAN_TYPE_PASSIVE_ONLY:
        Params->ScanType = Ap6256ScanTypePassive;
        break;
    case WDI_SCAN_TYPE_AUTO:
        Params->ScanType = Ap6256ScanTypeAuto;
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }

    if (Wdi->DwellTime.ActiveChannelDwellTime > MAXLONG ||
        Wdi->DwellTime.PassiveChannelDwellTime > MAXLONG) {
        return STATUS_INVALID_PARAMETER;
    }
    Params->ActiveChannelDwellTime = Wdi->DwellTime.ActiveChannelDwellTime;
    Params->PassiveChannelDwellTime = Wdi->DwellTime.PassiveChannelDwellTime;
    Params->MaximumScanTime = Wdi->DwellTime.MaximumScanTime;

    if (Wdi->Optional.VendorIEs_IsPresent && Wdi->VendorIEs.ElementCount != 0) {
        if (Wdi->VendorIEs.pElements == NULL)
            return STATUS_INVALID_PARAMETER;
        if (Params->ScanType != Ap6256ScanTypePassive)
            return STATUS_NOT_SUPPORTED;
    }
    if (Wdi->Optional.SixGHzBandChannelList_IsPresent &&
        Wdi->SixGHzBandChannelList.ElementCount != 0) {
        return STATUS_NOT_SUPPORTED;
    }
    if (!Wdi->Optional.BandChannelList_IsPresent ||
        Wdi->ScanModeParameters.ScanTrigger == WDI_SCAN_TRIGGER_MANUAL ||
        Wdi->BandChannelList.ElementCount == 0) {
        return Ap6256PopulateAllowedScanChannels(Wifi, Params);
    }
    if (Wdi->BandChannelList.ElementCount != 0 && Wdi->BandChannelList.pElements == NULL) {
        return STATUS_INVALID_PARAMETER;
    }

    for (index = 0; index < Wdi->BandChannelList.ElementCount; index++) {
        const WDI_SCAN_BAND_CHANNEL_LIST_CONTAINER* band = &Wdi->BandChannelList.pElements[index];
        AP6256_SCAN_BAND scanBand;

        if (band->BandID == WDI_BAND_ID_2400) {
            scanBand = Ap6256ScanBand2G;
        } else if (band->BandID == WDI_BAND_ID_5000) {
            scanBand = Ap6256ScanBand5G;
        } else {
            return STATUS_NOT_SUPPORTED;
        }
        if (Ap6256BandIsDisallowed(Wifi, band->BandID))
            continue;
        if (band->ChannelList.ElementCount != 0 && band->ChannelList.pElements == NULL) {
            return STATUS_INVALID_PARAMETER;
        }
        if (band->ChannelList.ElementCount == 0) {
            NTSTATUS status = Ap6256AppendBandChannels(Params, scanBand);
            if (!NT_SUCCESS(status))
                return status;
            continue;
        }
        for (channelIndex = 0; channelIndex < band->ChannelList.ElementCount; channelIndex++) {
            WDI_CHANNEL_NUMBER number = band->ChannelList.pElements[channelIndex];
            NTSTATUS status;
            if (number > MAXUINT16 || !Ap6256ChannelSupported(scanBand, number)) {
                return STATUS_INVALID_PARAMETER;
            }
            status = Ap6256AppendScanChannel(Params, scanBand, (UINT16)number);
            if (!NT_SUCCESS(status))
                return status;
        }
    }
    return Params->ChannelCount != 0 ? STATUS_SUCCESS : STATUS_NETWORK_UNREACHABLE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleScanRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                        _In_ PWDI_MESSAGE_HEADER Header,
                        _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SCAN_PARAMETERS parameters;
    AP6256_SCAN_PARAMS scanParams = {0};
    NTSTATUS status;
    ULONG timeoutMs;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(ParseWdiTaskScan(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        CleanupParsedWdiTaskScan(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }
    status = Wifi->P2pDiscoverTask.Active
                 ? STATUS_DEVICE_BUSY
                 : Ap6256CaptureScanParameters(Wifi, &parameters, &scanParams);
    if (NT_SUCCESS(status) &&
        (!Wifi->Ctx->DatapathRunning || Wifi->Ctx->FirmwareState != Ap6256FwRunning)) {
        status = STATUS_DEVICE_NOT_READY;
    } else if (NT_SUCCESS(status)) {
        status = Ap6256BeginTask(Wifi, &Wifi->ScanTask, Header, Ap6256RequestGetId(Request));
        if (NT_SUCCESS(status)) {
            InterlockedExchange(&Wifi->ScanIndicated, 0);
            InterlockedExchange(&Wifi->ScanDropped, 0);
        }
    }
    CleanupParsedWdiTaskScan(&parameters);
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
    timeoutMs =
        scanParams.MaximumScanTime != 0 ? scanParams.MaximumScanTime : AP6256_SCAN_TIMEOUT_MS;

    Ap6256SetTaskDeadline(Wifi, &Wifi->ScanTask, timeoutMs);
    AP6256_TIMER_START(Wifi->ScanTimer, timeoutMs);
    status = Ap6256QuiesceP2pListen(Wifi);
    if (NT_SUCCESS(status))
        status = Ap6256WifiScanStart(Wifi->Ctx, &scanParams);
    if (!NT_SUCCESS(status)) {
        AP6256_TIMER_STOP(Wifi->ScanTimer, TRUE);
        Ap6256FailStartedTask(Wifi, &Wifi->ScanTask, WDI_INDICATION_SCAN_COMPLETE, status);
    }
}

BOOLEAN Ap6256AlgorithmPresent(_In_ const WDI_AUTH_ALGORITHM_LIST_CONTAINER* List,
                               _In_ WDI_AUTH_ALGORITHM Algorithm)
{
    ULONG index;
    if (List->ElementCount != 0 && List->pElements == NULL)
        return FALSE;
    for (index = 0; index < List->ElementCount; index++) {
        if (List->pElements[index] == Algorithm)
            return TRUE;
    }
    return FALSE;
}

BOOLEAN Ap6256CipherPresent(_In_ const WDI_CIPHER_ALGORITHM_LIST_CONTAINER* List,
                            _In_ WDI_CIPHER_ALGORITHM Algorithm)
{
    ULONG index;
    if (List->ElementCount != 0 && List->pElements == NULL)
        return FALSE;
    for (index = 0; index < List->ElementCount; index++) {
        if (List->pElements[index] == Algorithm)
            return TRUE;
    }
    return FALSE;
}

static VOID Ap6256HandleConnectRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                       _In_ UINT16 MessageId, _In_ PWDI_MESSAGE_HEADER Header,
                                       _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                       _In_ ULONG TlvLength)
{
    const BOOLEAN isRoam = (BOOLEAN)(MessageId == WDI_TASK_ROAM);
    WDI_TASK_CONNECT_PARAMETERS parameters;
    AP6256_CONNECT_PARAMS connect;
    WDI_MESSAGE_HEADER joinOwner;
    WDI_SSID* ssid;
    BOOLEAN open;
    BOOLEAN wpa2;
    BOOLEAN enterprise;
    BOOLEAN sae;
    BOOLEAN owe;
    WDI_AUTH_ALGORITHM hostCipherAuth = WDI_AUTH_ALGO_UNKNOWN;
    BOOLEAN requestedFt = FALSE;
    NTSTATUS status;
    NTSTATUS preparationStatus = STATUS_SUCCESS;
    LONG disallowedBands;
    ULONG index;
    AP6256_CONNECT_PARAMS* candidates = NULL;
    ULONG candidateCount = 0;
    WDI_CHANNEL_NUMBER preferredChannel = 0;
    WDI_CONNECT_BSS_ENTRY_CONTAINER* preferred = NULL;
    KIRQL oldIrql;

    if (Ap6256ModelConnectPort(Wifi, Request, Header, Tlv, TlvLength, isRoam))
        return;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&connect, sizeof(connect));
    status = Ap6256NdisToNtStatus(
        isRoam ? ParseWdiTaskRoam(TlvLength, Tlv, &Wifi->TlvContext,
                                  (WDI_TASK_ROAM_PARAMETERS*)&parameters)
               : ParseWdiTaskConnect(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        TraceError(TRACE_NETADAPTER, "%s REFUSED: TLV parse failed 0x%08X (%u bytes)\n",
                   isRoam ? "roam" : "connect", status, TlvLength);
        goto Complete;
    }

    if (parameters.ConnectParameters.SSIDList.ElementCount == 0 ||
        parameters.ConnectParameters.SSIDList.pElements == NULL) {
        TraceError(TRACE_NETADAPTER, "connect REFUSED: request carries no SSID\n");
        status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }
    if (parameters.ConnectParameters.SSIDList.ElementCount > 1) {

        TraceWarn(TRACE_NETADAPTER, "connect: %u SSIDs requested, joining the first only\n",
                  parameters.ConnectParameters.SSIDList.ElementCount);
    }
    ssid = &parameters.ConnectParameters.SSIDList.pElements[0];
    if (ssid->ElementCount == 0 || ssid->ElementCount > sizeof(connect.Ssid) ||
        ssid->pElements == NULL) {
        TraceError(TRACE_NETADAPTER, "connect REFUSED: SSID of %u byte(s) (max %u), buffer %s\n",
                   ssid->ElementCount, (ULONG)sizeof(connect.Ssid),
                   ssid->pElements != NULL ? "present" : "MISSING");
        status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    TraceDiag("connect '%.*s': auth %u algo(s) first %u, unicast %u first %u, "
              "multicast %u first %u, MFP %u, FIPS %u, %u preferred BSS\n",
              (int)ssid->ElementCount, (const CHAR*)ssid->pElements,
              parameters.ConnectParameters.AuthenticationAlgorithms.ElementCount,
              Ap6256FirstAuthAlgo(&parameters.ConnectParameters.AuthenticationAlgorithms),
              parameters.ConnectParameters.UnicastCipherAlgorithms.ElementCount,
              Ap6256FirstCipherAlgo(&parameters.ConnectParameters.UnicastCipherAlgorithms),
              parameters.ConnectParameters.MulticastCipherAlgorithms.ElementCount,
              Ap6256FirstCipherAlgo(&parameters.ConnectParameters.MulticastCipherAlgorithms),
              parameters.ConnectParameters.ConnectionSettings.MFPEnabled,
              parameters.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled,
              parameters.PreferredBSSEntryList.ElementCount);
    TraceDiag("connect optionals: vendorIE %u, phyList %u, disallowedBSSIDs %u, "
              "allowedBSSIDs %u, oweDHIE %u, unavailableBands %u, "
              "akmCipherSuites %u, akmSuites %u\n",
              parameters.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent,
              parameters.ConnectParameters.Optional.ActivePhyTypeList_IsPresent,
              parameters.ConnectParameters.Optional.DisallowedBSSIDs_IsPresent,
              parameters.ConnectParameters.Optional.AllowedBSSIDs_IsPresent,
              parameters.ConnectParameters.Optional.OWEDHIE_IsPresent,
              parameters.ConnectParameters.Optional.UnavailableBandList_IsPresent,
              parameters.ConnectParameters.Optional.RsnaAkmCipherSuites_IsPresent,
              parameters.ConnectParameters.Optional.RsnaAkmSuites_IsPresent);

    open = Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                                  WDI_AUTH_ALGO_80211_OPEN) &&
           Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms,
                               WDI_CIPHER_ALGO_NONE) &&
           Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms,
                               WDI_CIPHER_ALGO_NONE);
    wpa2 = Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                                  WDI_AUTH_ALGO_RSNA_PSK) &&
           Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms,
                               WDI_CIPHER_ALGO_CCMP) &&
           Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms,
                               WDI_CIPHER_ALGO_CCMP);
    enterprise = !wpa2 &&
                 Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                                        WDI_AUTH_ALGO_RSNA) &&
                 Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms,
                                     WDI_CIPHER_ALGO_CCMP) &&
                 Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms,
                                     WDI_CIPHER_ALGO_CCMP);

    sae = Ap6256HostSaeAvailable(Wifi) &&
          Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                                 WDI_AUTH_ALGO_WPA3_SAE) &&
          Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms,
                              WDI_CIPHER_ALGO_CCMP) &&
          Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms,
                              WDI_CIPHER_ALGO_CCMP);

    owe = Ap6256HostOweAvailable(Wifi) &&
          Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                                 WDI_AUTH_ALGO_OWE) &&
          Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms,
                              WDI_CIPHER_ALGO_CCMP) &&
          Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms,
                              WDI_CIPHER_ALGO_CCMP);
    if (Ap6256HostCipherAvailable(Wifi) &&
        !parameters.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled &&
        parameters.ConnectParameters.AuthenticationAlgorithms.pElements &&
        Ap6256CipherPresent(&parameters.ConnectParameters.UnicastCipherAlgorithms, WDI_CIPHER_ALGO_GCMP_256) &&
        Ap6256CipherPresent(&parameters.ConnectParameters.MulticastCipherAlgorithms, WDI_CIPHER_ALGO_GCMP_256)) {
        const BOOLEAN onlyOwe = Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
            WDI_AUTH_ALGO_OWE);
        for (index = 0; index < parameters.ConnectParameters.AuthenticationAlgorithms.ElementCount; ++index) {
            WDI_AUTH_ALGORITHM algorithm = parameters.ConnectParameters.AuthenticationAlgorithms.pElements[index];
            UINT32 akm = algorithm == WDI_AUTH_ALGO_RSNA ? 1u :
                algorithm == WDI_AUTH_ALGO_RSNA_PSK ? 2u : algorithm == WDI_AUTH_ALGO_WPA3_ENT ? 5u :
                algorithm == WDI_AUTH_ALGO_WPA3_SAE ? 8u : algorithm == WDI_AUTH_ALGO_WPA3_ENT_192 ? 12u :
                algorithm == WDI_AUTH_ALGO_OWE ? 18u : 0u;
            if (!akm || (onlyOwe && akm != 18) ||
                ((akm == 5 || akm == 8 || akm == 12 || akm == 18) &&
                    !parameters.ConnectParameters.ConnectionSettings.MFPEnabled) ||
                (akm == 8 && (!Wifi->Ctx->FirmwarePrivateSae || !Ap6256HostSaeAvailable(Wifi))) ||
                (akm == 18 && !Ap6256HostOweAvailable(Wifi)) ||
                !Ap6256HostCipherRequestSuite(&parameters.ConnectParameters, akm)) continue;
            connect.HostCipher = TRUE; connect.HostCipherAkm = akm; hostCipherAuth = algorithm;
            open = FALSE; wpa2 = akm == 2; enterprise = akm == 1 || akm == 5 || akm == 12;
            sae = akm == 8; owe = akm == 18;
            break;
        }
        if (!connect.HostCipher) {
            status = STATUS_NOT_SUPPORTED;
            goto Complete;
        }
    }

    if (Ap6256AlgorithmPresent(&parameters.ConnectParameters.AuthenticationAlgorithms,
                               WDI_AUTH_ALGO_OWE)) {
        if (!owe) {
            status = STATUS_NOT_SUPPORTED;
            goto Complete;
        }
        open = wpa2 = enterprise = sae = FALSE;
    }

    if (!open && !wpa2 && !enterprise && !sae && !owe) {
        WDI_AUTH_ALGORITHM_LIST_CONTAINER* algos =
            &parameters.ConnectParameters.AuthenticationAlgorithms;
        TraceError(
            TRACE_NETADAPTER,
            "unsupported security: %u auth algorithm(s), first %u; "
            "this driver does OPEN, RSNA_PSK/CCMP, RSNA/CCMP%s\n",
            algos->ElementCount,
            (algos->ElementCount != 0 && algos->pElements != NULL) ? (ULONG)algos->pElements[0] : 0,
            Ap6256HostSaeAvailable(Wifi) ? " and WPA3_SAE/CCMP"
                                         : " (SAE external authentication backend unavailable)");
        status = STATUS_NOT_SUPPORTED;
        goto Complete;
    }

    connect.Mfp = (sae || owe || (connect.HostCipher &&
        (connect.HostCipherAkm == 5 || connect.HostCipherAkm == 12))) ? Ap6256MfpRequired
                               : (parameters.ConnectParameters.ConnectionSettings.MFPEnabled
                                      ? Ap6256MfpCapable
                                      : Ap6256MfpNone);

    connect.HostFips = parameters.ConnectParameters.ConnectionSettings.HostFIPSModeEnabled != 0;
    connect.ExcludeUnencrypted = parameters.ConnectParameters.ConnectionSettings.ExcludeUnencrypted != 0;
    if (connect.HostFips && (!Wifi->Ctx->HostFipsReady || connect.Mfp != Ap6256MfpNone || sae || owe)) {
        status = STATUS_NOT_SUPPORTED;
        goto Complete;
    }
    if (owe) {
        if (!parameters.ConnectParameters.Optional.OWEDHIE_IsPresent) {
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        status = Ap6256OweCopyIes(
            parameters.ConnectParameters.OWEDHIE.pElements,
            parameters.ConnectParameters.OWEDHIE.ElementCount,
            parameters.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent
                ? parameters.ConnectParameters.AssociationRequestVendorIE.pElements
                : NULL,
            parameters.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent
                ? parameters.ConnectParameters.AssociationRequestVendorIE.ElementCount
                : 0,
            NULL, 0, &connect);
        if (!NT_SUCCESS(status))
            goto Complete;
    } else if (parameters.ConnectParameters.Optional.AssociationRequestVendorIE_IsPresent &&
               parameters.ConnectParameters.AssociationRequestVendorIE.ElementCount != 0) {
        status = Ap6256MboCopyVendorIes(&connect,
            parameters.ConnectParameters.AssociationRequestVendorIE.pElements,
            parameters.ConnectParameters.AssociationRequestVendorIE.ElementCount);
        if (!NT_SUCCESS(status)) goto Complete;
    }
    candidates = (AP6256_CONNECT_PARAMS*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, AP6256_CONNECT_BSSID_LIMIT * sizeof(*candidates), AP6256_POOL_TAG);
    if (candidates == NULL) {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Complete;
    }

    disallowedBands = InterlockedCompareExchange(&Wifi->DisallowedBandMask, 0, 0);
    if (parameters.ConnectParameters.Optional.UnavailableBandList_IsPresent) {
        WDI_BAND_ID_LIST_CONTAINER* unavailable = &parameters.ConnectParameters.UnavailableBandList;
        if (unavailable->ElementCount != 0 && unavailable->pElements == NULL) {
            TraceError(TRACE_NETADAPTER,
                       "connect REFUSED: unavailable band list claims %u "
                       "entries but carries none\n",
                       unavailable->ElementCount);
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        for (index = 0; index < unavailable->ElementCount; index++) {
            if (unavailable->pElements[index] == WDI_BAND_ID_2400) {
                disallowedBands |= AP6256_DISALLOW_BAND_2G;
            } else if (unavailable->pElements[index] == WDI_BAND_ID_5000) {
                disallowedBands |= AP6256_DISALLOW_BAND_5G;
            }
        }
    }

    connect.SsidLength = ssid->ElementCount;
    RtlCopyMemory(connect.Ssid, ssid->pElements, connect.SsidLength);

    connect.Security =
        owe ? Ap6256SecurityOweHost
            : (sae ? Ap6256SecuritySaeHost
                   : (enterprise ? Ap6256SecurityWpa2Enterprise
                                 : (wpa2 ? Ap6256SecurityWpa2Host : Ap6256SecurityOpen)));

    if (parameters.PreferredBSSEntryList.pElements != NULL) {
        for (index = 0; index < parameters.PreferredBSSEntryList.ElementCount; ++index) {
            const WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate =
                &parameters.PreferredBSSEntryList.pElements[index];
            if (candidate->Optional.FTInitialAssocParameters_IsPresent ||
                candidate->Optional.FTReAssocParameters_IsPresent) {
                requestedFt = TRUE;
                if (connect.HostCipher || !enterprise || !Ap6256HostFbtAvailable(Wifi)) {
                    status = STATUS_NOT_SUPPORTED;
                    goto Complete;
                }
                if ((candidate->Optional.FTInitialAssocParameters_IsPresent &&
                     candidate->Optional.FTReAssocParameters_IsPresent) ||
                    (isRoam != (BOOLEAN)candidate->Optional.FTReAssocParameters_IsPresent)) {
                    status = STATUS_INVALID_PARAMETER;
                    goto Complete;
                }
            }
        }
    }

    if (parameters.PreferredBSSEntryList.ElementCount != 0 &&
        parameters.PreferredBSSEntryList.pElements != NULL) {
        for (index = 0; index < parameters.PreferredBSSEntryList.ElementCount; index++) {
            WDI_CONNECT_BSS_ENTRY_CONTAINER* candidate =
                &parameters.PreferredBSSEntryList.pElements[index];
            WDI_BAND_ID bandId = candidate->ChannelInfo.BandId;
            if (Wifi->Ctx->Go.Started && !Wifi->Ctx->FirmwareMchanSupported &&
                candidate->ChannelInfo.ChannelNumber != Wifi->Ctx->Go.Channel)
                continue;

            if (bandId == WDI_BAND_ID_UNKNOWN) {
                if (Ap6256ChannelSupported(Ap6256ScanBand2G,
                                           candidate->ChannelInfo.ChannelNumber)) {
                    bandId = WDI_BAND_ID_2400;
                } else if (Ap6256ChannelSupported(Ap6256ScanBand5G,
                                                  candidate->ChannelInfo.ChannelNumber)) {
                    bandId = WDI_BAND_ID_5000;
                }
            }
            if ((bandId != WDI_BAND_ID_2400 && bandId != WDI_BAND_ID_5000) ||
                !Ap6256ChannelSupported(bandId == WDI_BAND_ID_2400 ? Ap6256ScanBand2G
                                                                   : Ap6256ScanBand5G,
                                        candidate->ChannelInfo.ChannelNumber))
                continue;
            if (!Ap6256MacIsValidUnicast(candidate->BSSID.Address)) {
                TraceInfo(TRACE_NETADAPTER,
                          "connect: preferred[%u] skipped, BSSID is not a "
                          "unicast address\n",
                          index);
                continue;
            }
            if (Ap6256MboJoinBlocked(Wifi, candidate->BSSID.Address)) continue;
            if (Ap6256BandIsMasked(disallowedBands, bandId)) {
                TraceInfo(TRACE_NETADAPTER,
                          "connect: preferred[%u] %02X:%02X:%02X:%02X:%02X:%02X "
                          "skipped, band %u channel %u disallowed (mask 0x%X)\n",
                          index, candidate->BSSID.Address[0], candidate->BSSID.Address[1],
                          candidate->BSSID.Address[2], candidate->BSSID.Address[3],
                          candidate->BSSID.Address[4], candidate->BSSID.Address[5], bandId,
                          candidate->ChannelInfo.ChannelNumber, disallowedBands);
                continue;
            }

            if (parameters.ConnectParameters.Optional.DisallowedBSSIDs_IsPresent &&
                parameters.ConnectParameters.DisallowedBSSIDs.ElementCount != 0 &&
                Ap6256AddressInList(candidate->BSSID.Address,
                                    &parameters.ConnectParameters.DisallowedBSSIDs)) {
                TraceInfo(TRACE_NETADAPTER,
                          "connect: preferred[%u] skipped, BSSID is on the "
                          "host's disallowed list\n",
                          index);
                continue;
            }
            if (parameters.ConnectParameters.Optional.AllowedBSSIDs_IsPresent &&
                !Ap6256AddressListIsUnrestricted(&parameters.ConnectParameters.AllowedBSSIDs) &&
                !Ap6256AddressInList(candidate->BSSID.Address,
                                     &parameters.ConnectParameters.AllowedBSSIDs)) {
                TraceInfo(TRACE_NETADAPTER,
                          "connect: preferred[%u] skipped, BSSID is not on the "
                          "host's allowed list\n",
                          index);
                continue;
            }

            if (candidateCount == AP6256_CONNECT_BSSID_LIMIT) {
                status = STATUS_INVALID_PARAMETER;
                goto Complete;
            }
            if (requestedFt && !candidate->Optional.FTInitialAssocParameters_IsPresent &&
                !candidate->Optional.FTReAssocParameters_IsPresent)
                continue;
            candidates[candidateCount] = connect;
            if (!owe && candidate->Optional.AssociationRequestVendorIE_IsPresent) {
                status = Ap6256MboCopyVendorIes(&candidates[candidateCount],
                    candidate->AssociationRequestVendorIE.pElements,
                    candidate->AssociationRequestVendorIE.ElementCount);
                if (!NT_SUCCESS(status)) goto Complete;
            }
            if (owe) {
                status = Ap6256OweCopyIes(connect.OweDh, connect.OweDhLength, connect.OweExtra,
                                          connect.OweExtraLength,
                                          candidate->Optional.AssociationRequestVendorIE_IsPresent
                                              ? candidate->AssociationRequestVendorIE.pElements
                                              : NULL,
                                          candidate->Optional.AssociationRequestVendorIE_IsPresent
                                              ? candidate->AssociationRequestVendorIE.ElementCount
                                              : 0,
                                          &candidates[candidateCount]);
                if (!NT_SUCCESS(status))
                    goto Complete;
            }

            status = Ap6256ModelCopyFtCandidate(candidate, isRoam, &candidates[candidateCount]);
            if (!NT_SUCCESS(status))
                goto Complete;

            status = Ap6256ModelCopyAuthenticationCandidate(candidate, &parameters, sae, owe,
                                                            &candidates[candidateCount]);
            if (!NT_SUCCESS(status))
                goto Complete;
            status = Ap6256CopyFipsCandidate(candidate, &candidates[candidateCount]);
            if (!NT_SUCCESS(status)) goto Complete;
            status = Ap6256CopyHostCipherCandidate(candidate, &candidates[candidateCount]);
            if (!NT_SUCCESS(status)) goto Complete;
            candidates[candidateCount].BssidValid = TRUE;
            RtlCopyMemory(candidates[candidateCount].Bssid, candidate->BSSID.Address, 6);
            candidates[candidateCount++].Channel = candidate->ChannelInfo.ChannelNumber;
            if (preferred == NULL) {
                preferred = candidate;
                preferredChannel = candidate->ChannelInfo.ChannelNumber;
            }
        }
    }

    if ((isRoam || sae || owe || requestedFt || connect.HostFips || connect.HostCipher) && candidateCount == 0) {

        status = STATUS_NETWORK_UNREACHABLE;
        goto Complete;
    }
    if (preferred != NULL) {

        Ap6256StoreConnectRestrictions(Wifi, NULL, NULL, 0);
        RtlCopyMemory(connect.Bssid, preferred->BSSID.Address, sizeof(connect.Bssid));
        connect.BssidValid = TRUE;
        TraceInfo(TRACE_NETADAPTER,
                  "connect: joining %02X:%02X:%02X:%02X:%02X:%02X on channel %u\n",
                  connect.Bssid[0], connect.Bssid[1], connect.Bssid[2], connect.Bssid[3],
                  connect.Bssid[4], connect.Bssid[5], preferredChannel);
    } else {

        const WDI_ADDRESS_LIST_CONTAINER* allowed =
            parameters.ConnectParameters.Optional.AllowedBSSIDs_IsPresent &&
                    !Ap6256AddressListIsUnrestricted(&parameters.ConnectParameters.AllowedBSSIDs)
                ? &parameters.ConnectParameters.AllowedBSSIDs
                : NULL;
        const WDI_ADDRESS_LIST_CONTAINER* disallowed =
            parameters.ConnectParameters.Optional.DisallowedBSSIDs_IsPresent &&
                    parameters.ConnectParameters.DisallowedBSSIDs.ElementCount != 0
                ? &parameters.ConnectParameters.DisallowedBSSIDs
                : NULL;

        if ((allowed != NULL && allowed->ElementCount > AP6256_CONNECT_BSSID_LIMIT) ||
            (disallowed != NULL && disallowed->ElementCount > AP6256_CONNECT_BSSID_LIMIT)) {

            TraceError(TRACE_NETADAPTER,
                       "connect REFUSED: no usable BSS among %u preferred "
                       "entry(s), and the host's BSSID list is longer than the "
                       "%u this driver can enforce on a wildcard join\n",
                       parameters.PreferredBSSEntryList.ElementCount, AP6256_CONNECT_BSSID_LIMIT);
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }

        Ap6256StoreConnectRestrictions(Wifi, allowed, disallowed, disallowedBands);
        TraceWarn(TRACE_NETADAPTER,
                  "connect: no usable BSS among %u preferred entry(s); joining "
                  "by SSID and letting the firmware choose%s\n",
                  parameters.PreferredBSSEntryList.ElementCount,
                  Wifi->ConnectRestricted ? " (the host's restrictions will be checked against the "
                                            "BSS it picks)"
                                          : "");
    }

    Ap6256LockAcquire(&Wifi->ConnectLock);

    status = Ap6256ModelValidateCandidates(Wifi, candidates, candidateCount, isRoam);
    if (!NT_SUCCESS(status)) {
        Ap6256LockRelease(&Wifi->ConnectLock);
        goto Complete;
    }
    status = Ap6256BeginTask(Wifi, &Wifi->ConnectTask, Header, Ap6256RequestGetId(Request));
    if (!NT_SUCCESS(status)) {
        Ap6256LockRelease(&Wifi->ConnectLock);
        TraceError(TRACE_NETADAPTER,
                   "connect REFUSED 0x%08X: a connect task is already in "
                   "flight\n",
                   status);
        goto Complete;
    }

    Wifi->ConnectTaskIsRoam = isRoam;
    joinOwner = *Header;
    Wifi->ConnectCandidateIndex = 0;
    Wifi->ConnectCandidateCount = candidateCount ? candidateCount : 1;
    if (candidateCount)
        RtlCopyMemory(Wifi->ConnectCandidates, candidates, candidateCount * sizeof(candidates[0]));
    else
        Wifi->ConnectCandidates[0] = connect;
    ExFreePoolWithTag(candidates, AP6256_POOL_TAG);
    candidates = NULL;
    InterlockedIncrement(&Wifi->ConnectGeneration);
    Wifi->ConnectDeparting = Wifi->ConnectionActive && !(requestedFt && isRoam);

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    Wifi->AuthAlgorithm =
        connect.HostCipher ? hostCipherAuth : owe ? WDI_AUTH_ALGO_OWE
            : (sae ? WDI_AUTH_ALGO_WPA3_SAE
                   : (enterprise ? WDI_AUTH_ALGO_RSNA
                                 : (wpa2 ? WDI_AUTH_ALGO_RSNA_PSK : WDI_AUTH_ALGO_80211_OPEN)));
    Wifi->UnicastCipher =
        connect.HostCipher ? WDI_CIPHER_ALGO_GCMP_256 :
            (wpa2 || enterprise || sae || owe) ? WDI_CIPHER_ALGO_CCMP : WDI_CIPHER_ALGO_NONE;
    Wifi->MulticastCipher = Wifi->UnicastCipher;

    Wifi->MulticastMgmtCipher = WDI_CIPHER_ALGO_NONE;

    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);

    Ap6256LockRelease(&Wifi->ConnectLock);

    if (isRoam) {

        CleanupParsedWdiTaskRoam((WDI_TASK_ROAM_PARAMETERS*)&parameters);

    } else {

        CleanupParsedWdiTaskConnect(&parameters);
    }
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);

    Ap6256LockAcquire(&Wifi->ConnectLock);
    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (Wifi->ConnectTask.Active &&
        Wifi->ConnectTask.Header.TransactionId == joinOwner.TransactionId &&
        Wifi->ConnectTask.Header.PortId == joinOwner.PortId) {
        Wifi->ConnectTask.DeadlineMs = Ap6256InterruptTimeMs() + AP6256_CONNECT_TIMEOUT_MS;
    } else {
        preparationStatus = STATUS_CANCELLED;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);
    if (preparationStatus != STATUS_CANCELLED)
        AP6256_TIMER_START(Wifi->ConnectTimer, AP6256_CONNECT_TIMEOUT_MS);
    Ap6256LockRelease(&Wifi->ConnectLock);

    status = preparationStatus;
    if (NT_SUCCESS(status))
        status = Ap6256QuiesceP2pListen(Wifi);
    if (NT_SUCCESS(status)) {
        BOOLEAN live;
        Ap6256LockAcquire(&Wifi->ConnectLock);
        KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
        live = Wifi->ConnectTask.Active && !Wifi->Stopping && Wifi->HardwareAvailable &&
               Wifi->ConnectTask.Header.TransactionId == joinOwner.TransactionId &&
               Wifi->ConnectTask.Header.PortId == joinOwner.PortId &&
               Wifi->ConnectTask.DeadlineMs > Ap6256InterruptTimeMs();
        KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);

        if (!live)
            status = STATUS_CANCELLED;
        else if (Wifi->ConnectDeparting) {
            status = Ap6256WifiDisconnect(Wifi->Ctx);
        } else
            status = Ap6256StationStartNext(Wifi);
        Ap6256LockRelease(&Wifi->ConnectLock);
    }
    if (!NT_SUCCESS(status)) {
        WDI_MESSAGE_HEADER taskHeader;
        PVOID taskRequestId;

        if (Ap6256ClaimConnectTask(Wifi, Ap6256ConnectClaimMatching, joinOwner.TransactionId,
                                   joinOwner.PortId, &taskHeader, &taskRequestId)) {
            (VOID) Ap6256SendIndicationRq(Wifi, Ap6256ConnectCompletionId(Wifi), &taskHeader,
                                          taskHeader.TransactionId, taskRequestId, status, NULL, 0);
        }
    }
    return;

Complete:
    if (candidates != NULL)
        ExFreePoolWithTag(candidates, AP6256_POOL_TAG);
    CleanupParsedWdiTaskConnect(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleDisconnectRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                              _In_ PWDI_MESSAGE_HEADER Header,
                              _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_DISCONNECT_PARAMETERS parameters;
    WDI_MESSAGE_HEADER disconnectHeader = *Header, taskHeader = {0};
    PVOID disconnectRequestId = Ap6256RequestGetId(Request);
    PVOID taskRequestId = NULL;
    UCHAR peer[6] = {0};
    UINT16 reason = 0;
    LONG generation;
    NTSTATUS status;
    BOOLEAN wasConnected = TRUE, completed = FALSE;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskDisconnect(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (Ap6256ModelDisconnectPort(Wifi, Request, Header, &parameters, status))
        return;
    if (NT_SUCCESS(status) && Header->PortId != AP6256_STATION_PORT)
        status = STATUS_INVALID_DEVICE_STATE;
    if (NT_SUCCESS(status)) {
        RtlCopyMemory(peer, parameters.DisconnectParameters.MacAddress.Address, sizeof(peer));
        reason = parameters.DisconnectParameters.Disassociation80211Reason;
        if (!Ap6256MacIsValidUnicast(peer) || !reason)
            status = STATUS_INVALID_PARAMETER;
    }
    CleanupParsedWdiTaskDisconnect(&parameters);
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }
    Ap6256LockAcquire(&Wifi->ConnectLock);
    generation = Wifi->ConnectGeneration;
    status = Wifi->ConnectBssidValid && !RtlEqualMemory(peer, Wifi->ConnectBssid, sizeof(peer))
                 ? STATUS_INVALID_DEVICE_STATE
                 : Ap6256BeginTask(Wifi, &Wifi->DisconnectTask, Header, disconnectRequestId);
    Ap6256LockRelease(&Wifi->ConnectLock);
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (generation != Wifi->ConnectGeneration || !Wifi->DisconnectTask.Active ||
        Wifi->DisconnectTask.RequestId != disconnectRequestId ||
        Wifi->DisconnectTask.Header.TransactionId != disconnectHeader.TransactionId ||
        Wifi->DisconnectTask.Header.PortId != disconnectHeader.PortId ||
        (Wifi->ConnectBssidValid && !RtlEqualMemory(peer, Wifi->ConnectBssid, sizeof(peer)))) {
        status = STATUS_INVALID_DEVICE_STATE;
    } else {
        wasConnected = Wifi->Ctx->FirmwareLinkUp;
        TraceDiag("Windows asked to disconnect (firmware link %s)\n", wasConnected ? "up" : "down");
        Ap6256SetTaskDeadline(Wifi, &Wifi->DisconnectTask, AP6256_DISCONNECT_TIMEOUT_MS);
        AP6256_TIMER_START(Wifi->DisconnectTimer, AP6256_DISCONNECT_TIMEOUT_MS);
        status = Ap6256WifiDisconnectWithReason(Wifi->Ctx, peer, reason);
    }
    if ((!NT_SUCCESS(status) || !wasConnected) && Wifi->DisconnectTask.RequestId == disconnectRequestId)
        completed = Ap6256ClaimMatchingTask(Wifi, &Wifi->DisconnectTask,
            disconnectHeader.TransactionId, disconnectHeader.PortId, &taskHeader, &taskRequestId);
    Ap6256LockRelease(&Wifi->ConnectLock);
    if (completed) {

        AP6256_TIMER_STOP(Wifi->DisconnectTimer, TRUE);
        (VOID) Ap6256SendIndicationRq(Wifi, WDI_INDICATION_DISCONNECT_COMPLETE, &taskHeader,
                                      taskHeader.TransactionId, taskRequestId, status, NULL, 0);
    }
}

static NTSTATUS Ap6256CommandInterface(PAP6256_WIFI Wifi, PWDI_MESSAGE_HEADER Header,
                                       PUINT32 IfIndex)
{
    *IfIndex = 0;
    if (Header->PortId == AP6256_STATION_PORT)
        return STATUS_SUCCESS;
    if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.FirmwareReady) {
        *IfIndex = Wifi->Ctx->Go.IfIndex;
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_STATE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddKeys(_In_ PAP6256_WIFI Wifi, _In_ UINT32 IfIndex,
              _In_ WDI_SET_ADD_CIPHER_KEYS_PARAMETERS* Parameters)
{
    static const UCHAR zeroAddress[6] = {0};
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    if (Parameters->SetCipherKey.ElementCount == 0 || Parameters->SetCipherKey.pElements == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ap6256HostCipherPacketActive(Wifi->Ctx, IfIndex))
        return Ap6256HostKeys(Wifi, IfIndex, Parameters, NULL);
    for (index = 0; index < Parameters->SetCipherKey.ElementCount; index++) {
        ULONG cipher = (ULONG)Parameters->SetCipherKey.pElements[index].CipherKeyTypeInfo.CipherAlgorithm;
        if (cipher == WDI_CIPHER_ALGO_GCMP_256 || cipher == WDI_CIPHER_ALGO_BIP_GMAC_256)
            return Ap6256HostKeys(Wifi, IfIndex, Parameters, NULL);
    }
    for (index = 0; index < Parameters->SetCipherKey.ElementCount; index++) {
        WDI_SET_ADD_CIPHER_KEYS_CONTAINER* source = &Parameters->SetCipherKey.pElements[index];
        AP6256_CCMP_KEY key;

        RtlZeroMemory(&key, sizeof(key));
        key.IfIndex = IfIndex;

        if (source->CipherKeyTypeInfo.CipherAlgorithm == WDI_CIPHER_ALGO_BIP) {
            AP6256_BIP_KEY bip;

            if (source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_IGTK ||
                !source->Optional.CipherKeyID_IsPresent ||
                (source->CipherKeyID.CipherKeyID != 4 && source->CipherKeyID.CipherKeyID != 5) ||
                (source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_BOTH &&
                 source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_INBOUND &&
                 source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_OUTBOUND) ||
                !source->Optional.BIPKey_IsPresent || source->BIPKey.pElements == NULL ||
                source->BIPKey.ElementCount != AP6256_BIP_KEY_MAX ||
                !source->Optional.ReceiveSequenceCount_IsPresent) {
                TraceWarn(
                    TRACE_NETADAPTER,
                    "cipher key %u: invalid IGTK type, ID, direction, key or sequence count\n",
                    index);
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }

            RtlZeroMemory(&bip, sizeof(bip));
            bip.IfIndex = IfIndex;
            bip.KeyId = source->CipherKeyID.CipherKeyID;
            if (source->Optional.PeerMacAddress_IsPresent) {
                RtlCopyMemory(bip.PeerAddress, source->PeerMacAddress.Address,
                              sizeof(bip.PeerAddress));
            }
            bip.KeyLength = source->BIPKey.ElementCount;
            RtlCopyMemory(bip.Key, source->BIPKey.pElements, bip.KeyLength);
            RtlCopyMemory(bip.Ipn, source->ReceiveSequenceCount.ReceiveSequenceCount,
                          sizeof(bip.Ipn));

            status = Ap6256WifiAddBipKey(Wifi->Ctx, &bip);
            RtlSecureZeroMemory(&bip, sizeof(bip));
            if (!NT_SUCCESS(status))
                break;
            continue;
        }

        if (source->CipherKeyTypeInfo.CipherAlgorithm != WDI_CIPHER_ALGO_CCMP ||
            !source->Optional.CCMPKey_IsPresent ||
            source->CCMPKey.ElementCount != sizeof(key.Key) || source->CCMPKey.pElements == NULL ||
            (source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_BOTH &&
             source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_INBOUND &&
             source->CipherKeyTypeInfo.Direction != WDI_CIPHER_KEY_DIRECTION_OUTBOUND)) {

            TraceError(TRACE_NETADAPTER,
                       "cipher key %u REFUSED: algo 0x%02X, ccmp present %u "
                       "len %u, direction %u\n",
                       index, (UINT32)source->CipherKeyTypeInfo.CipherAlgorithm,
                       source->Optional.CCMPKey_IsPresent, source->CCMPKey.ElementCount,
                       (UINT32)source->CipherKeyTypeInfo.Direction);
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (source->CipherKeyTypeInfo.KeyType == WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY) {
            if (!source->Optional.PeerMacAddress_IsPresent) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            key.Pairwise = TRUE;
            RtlCopyMemory(key.PeerAddress, source->PeerMacAddress.Address, sizeof(key.PeerAddress));
        } else if (source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_GROUP_KEY) {
            status = STATUS_NOT_SUPPORTED;
            break;
        }
        if (source->Optional.CipherKeyID_IsPresent) {
            key.KeyId = source->CipherKeyID.CipherKeyID;
        } else if (!key.Pairwise) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RtlCopyMemory(key.Key, source->CCMPKey.pElements, sizeof(key.Key));
        if (source->Optional.ReceiveSequenceCount_IsPresent) {
            key.ReceiveSequenceValid = TRUE;
            RtlCopyMemory(key.ReceiveSequence, source->ReceiveSequenceCount.ReceiveSequenceCount,
                          sizeof(key.ReceiveSequence));
        }
        status = Ap6256WifiAddCcmpKey(Wifi->Ctx, &key);
        if (Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO && IfIndex == Wifi->Ctx->Go.IfIndex)
            TraceDiag("hotspot: key install if %u pairwise %u id %u -> 0x%08X\n", IfIndex,
                      (ULONG)key.Pairwise, key.KeyId, status);
        RtlSecureZeroMemory(&key, sizeof(key));
        if (!NT_SUCCESS(status))
            break;
    }

    if (!NT_SUCCESS(status)) {
        while (index != 0) {
            WDI_SET_ADD_CIPHER_KEYS_CONTAINER* source;
            BOOLEAN pairwise;
            ULONG keyId;
            index--;
            source = &Parameters->SetCipherKey.pElements[index];

            if (source->CipherKeyTypeInfo.CipherAlgorithm == WDI_CIPHER_ALGO_BIP) {
                (VOID) Ap6256WifiDeleteBipKeyIf(Wifi->Ctx, IfIndex, source->CipherKeyID.CipherKeyID,
                                                source->Optional.PeerMacAddress_IsPresent
                                                    ? source->PeerMacAddress.Address
                                                    : zeroAddress);
                continue;
            }
            if (source->CipherKeyTypeInfo.CipherAlgorithm != WDI_CIPHER_ALGO_CCMP) {
                continue;
            }
            pairwise = source->CipherKeyTypeInfo.KeyType == WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
            keyId = source->Optional.CipherKeyID_IsPresent ? source->CipherKeyID.CipherKeyID : 0;
            (VOID) Ap6256WifiDeleteCcmpKeyIf(Wifi->Ctx, IfIndex, keyId, pairwise,
                                             source->PeerMacAddress.Address);
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256DeleteKeys(_In_ PAP6256_WIFI Wifi, _In_ UINT32 IfIndex,
                 _In_ WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS* Parameters)
{
    static const UCHAR zeroAddress[6] = {0};
    ULONG index;
    NTSTATUS status = STATUS_SUCCESS;

    if (Parameters->CipherKeyInfo.ElementCount == 0 ||
        Parameters->CipherKeyInfo.pElements == NULL) {
        return STATUS_INVALID_PARAMETER;
    }
    if (Ap6256HostCipherPacketActive(Wifi->Ctx, IfIndex))
        return Ap6256HostKeys(Wifi, IfIndex, NULL, Parameters);
    for (index = 0; index < Parameters->CipherKeyInfo.ElementCount; index++) {
        ULONG cipher = (ULONG)Parameters->CipherKeyInfo.pElements[index].CipherKeyTypeInfo.CipherAlgorithm;
        if (cipher == WDI_CIPHER_ALGO_GCMP_256 || cipher == WDI_CIPHER_ALGO_BIP_GMAC_256)
            return Ap6256HostKeys(Wifi, IfIndex, NULL, Parameters);
    }
    for (index = 0; index < Parameters->CipherKeyInfo.ElementCount; index++) {
        WDI_SET_DELETE_CIPHER_KEYS_CONTAINER* source = &Parameters->CipherKeyInfo.pElements[index];
        BOOLEAN pairwise = source->CipherKeyTypeInfo.KeyType == WDI_CIPHER_KEY_TYPE_PAIRWISE_KEY;
        ULONG keyId = source->Optional.CipherKeyID_IsPresent ? source->CipherKeyID.CipherKeyID : 0;
        if (source->CipherKeyTypeInfo.CipherAlgorithm == WDI_CIPHER_ALGO_BIP) {
            if (source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_IGTK ||
                !source->Optional.CipherKeyID_IsPresent || (keyId != 4 && keyId != 5))
                return STATUS_INVALID_PARAMETER;
            status = Ap6256WifiDeleteBipKeyIf(Wifi->Ctx, IfIndex, keyId,
                                              source->Optional.PeerMacAddress_IsPresent
                                                  ? source->PeerMacAddress.Address
                                                  : zeroAddress);
            if (!NT_SUCCESS(status))
                break;
            continue;
        }
        if (source->CipherKeyTypeInfo.CipherAlgorithm != WDI_CIPHER_ALGO_CCMP ||
            (pairwise && !source->Optional.PeerMacAddress_IsPresent) ||
            (!pairwise && source->CipherKeyTypeInfo.KeyType != WDI_CIPHER_KEY_TYPE_GROUP_KEY) ||
            (!pairwise && !source->Optional.CipherKeyID_IsPresent)) {
            return STATUS_NOT_SUPPORTED;
        }
        status = Ap6256WifiDeleteCcmpKeyIf(Wifi->Ctx, IfIndex, keyId, pairwise,
                                           source->PeerMacAddress.Address);
        if (!NT_SUCCESS(status))
            break;
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleKeyRequest(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                       _In_ AP6256_REQUEST Request, _In_ UINT16 MessageId,
                       _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    UINT32 ifIndex = 0;
    NTSTATUS status;
#if defined(AP6256_ENABLE_WIFICX)
    BOOLEAN group = Header->PortId == AP6256_GROUP_PORT;
    if (group) {
        PAP6256_CX_ADAPTER role;

        Ap6256LockAcquire(&Wifi->Model.GroupLock);
        role = Wifi->Model.Roles[1];
        if (Wifi->Stopping || !Wifi->HardwareAvailable || Wifi->PowerStateDx)
            status = STATUS_DEVICE_NOT_READY;
        else if (Wifi->Ctx->Go.NativeStateUncertain)
            status = STATUS_DEVICE_HARDWARE_ERROR;
        else if (!role || !role->Ready || role->Closing)
            status = STATUS_CANCELLED;
        else
            status = Ap6256CommandInterface(Wifi, Header, &ifIndex);
    } else
#endif
        status = Ap6256CommandInterface(Wifi, Header, &ifIndex);
    if (!NT_SUCCESS(status)) goto Complete;

    if (MessageId == WDI_SET_ADD_CIPHER_KEYS) {
        WDI_SET_ADD_CIPHER_KEYS_PARAMETERS parameters;
        RtlZeroMemory(&parameters, sizeof(parameters));
        status = Ap6256NdisToNtStatus(
            ParseWdiSetAddCipherKeys(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
        if (NT_SUCCESS(status))
            status = Ap6256AddKeys(Wifi, ifIndex, &parameters);
        CleanupParsedWdiSetAddCipherKeys(&parameters);
    } else if (MessageId == WDI_SET_DELETE_CIPHER_KEYS) {
        WDI_SET_DELETE_CIPHER_KEYS_PARAMETERS parameters;
        RtlZeroMemory(&parameters, sizeof(parameters));
        status = Ap6256NdisToNtStatus(
            ParseWdiSetDeleteCipherKeys(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
        if (NT_SUCCESS(status))
            status = Ap6256DeleteKeys(Wifi, ifIndex, &parameters);
        CleanupParsedWdiSetDeleteCipherKeys(&parameters);
    } else {
        WDI_SET_DEFAULT_KEY_ID_PARAMETERS parameters;
        RtlZeroMemory(&parameters, sizeof(parameters));
        status = Ap6256NdisToNtStatus(
            ParseWdiSetDefaultKeyId(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
        if (NT_SUCCESS(status)) {
            status = Ap6256WifiSetDefaultKeyIdIf(Wifi->Ctx, ifIndex,
                                                 parameters.DefaultKeyIdParameters.KeyID);
        }
        CleanupParsedWdiSetDefaultKeyId(&parameters);
    }
Complete:
#if defined(AP6256_ENABLE_WIFICX)
    if (group) Ap6256LockRelease(&Wifi->Model.GroupLock);
#endif
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAdapterConfiguration(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_FIRMWARE_CONFIGURATION_PARAMETERS parameters;
    NTSTATUS status;
    LONG disallowedBands = 0;
    ULONG index;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetAdapterConfiguration(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status))
        goto Complete;
    if (Wifi->PortCreated) {
        status = STATUS_INVALID_DEVICE_STATE;
        goto Complete;
    }
    if (parameters.Optional.UnreachableDetectionThreshold_IsPresent ||
        parameters.Optional.GroupOwnerResetPolicy_IsPresent ||
        parameters.Optional.AdapterNloScanMode_IsPresent) {
        status = STATUS_NOT_SUPPORTED;
        goto Complete;
    }
    if (parameters.Optional.DisallowedBandList_IsPresent) {
        if (parameters.DisallowedBandList.ElementCount != 0 &&
            parameters.DisallowedBandList.pElements == NULL) {
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        for (index = 0; index < parameters.DisallowedBandList.ElementCount; index++) {
            if (parameters.DisallowedBandList.pElements[index] == WDI_BAND_ID_2400) {
                disallowedBands |= AP6256_DISALLOW_BAND_2G;
            } else if (parameters.DisallowedBandList.pElements[index] == WDI_BAND_ID_5000) {
                disallowedBands |= AP6256_DISALLOW_BAND_5G;
            } else if (parameters.DisallowedBandList.pElements[index] == WDI_BAND_ID_ANY) {
                status = STATUS_INVALID_PARAMETER;
                goto Complete;
            }
        }
    }
    if (parameters.Optional.MacAddress_IsPresent) {
        if (!Ap6256MacIsValidUnicast(parameters.MacAddress.Address)) {
            status = STATUS_INVALID_PARAMETER;
            goto Complete;
        }
        if (InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) != 0) {
            status = Ap6256WifiSetMacAddress(Wifi->Ctx, parameters.MacAddress.Address);
            if (!NT_SUCCESS(status))
                goto Complete;
        }
    }

    Ap6256LockAcquire(&Wifi->ConnectLock);
    status = Ap6256MboSetBands(Wifi, disallowedBands, TRUE);
    Ap6256LockRelease(&Wifi->ConnectLock);
    if (!NT_SUCCESS(status)) goto Complete;
    InterlockedExchange(&Wifi->DisallowedBandMask, disallowedBands);
    if (parameters.Optional.MacAddress_IsPresent) {
        RtlCopyMemory(Wifi->Ctx->ConfiguredMacAddress, parameters.MacAddress.Address,
                      sizeof(Wifi->Ctx->ConfiguredMacAddress));
        Wifi->Ctx->ConfiguredMacAddressValid = TRUE;
        RtlCopyMemory(Wifi->Ctx->MacAddress, parameters.MacAddress.Address,
                      sizeof(Wifi->Ctx->MacAddress));
        Ap6256NetSetMacAddress(Wifi->Ctx);
    }

Complete:
    CleanupParsedWdiSetAdapterConfiguration(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256IndicateRadioStatus(_In_ PAP6256_WIFI Wifi, _In_ const WDI_MESSAGE_HEADER* Header)
{
    WDI_INDICATION_RADIO_STATUS_PARAMETERS parameters;
    PUCHAR generated = NULL;
    ULONG generatedLength = 0;

    RtlZeroMemory(&parameters, sizeof(parameters));
    parameters.RadioState.HardwareState = Wifi->HardwareRadioState;
    parameters.RadioState.SoftwareState = Wifi->SoftwareRadioState;
    if (GenerateWdiIndicationRadioStatus(&parameters, 0, &Wifi->TlvContext, &generatedLength,
                                         &generated) == NDIS_STATUS_SUCCESS &&
        generated != NULL) {
        (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_RADIO_STATUS, Header,
                                             WDI_TRANSACTION_ID_UNSOLICIT, NULL, generated,
                                             generatedLength);
    }
    FreeGenerated(generated);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRadioRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                         _In_ PWDI_MESSAGE_HEADER Header,
                         _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_RADIO_STATE_PARAMETERS parameters;
    NTSTATUS status;

    WDI_MESSAGE_HEADER completedHeader = *Header;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskSetRadioState(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (NT_SUCCESS(status)) {
        status = Ap6256WifiSetRadioState(Wifi->Ctx, parameters.SoftwareRadioState != 0);
    }
    if (NT_SUCCESS(status)) {
        Wifi->SoftwareRadioState = parameters.SoftwareRadioState != 0;
    }
    CleanupParsedWdiTaskSetRadioState(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
    if (NT_SUCCESS(status)) {
        if (!Wifi->SoftwareRadioState)
            Ap6256NetLinkChange(Wifi->Ctx, FALSE);
        Ap6256IndicateRadioStatus(Wifi, &completedHeader);
        (VOID) Ap6256SendIndication(Wifi, WDI_INDICATION_SET_RADIO_STATE_COMPLETE, &completedHeader,
                                    completedHeader.TransactionId, STATUS_SUCCESS, NULL, 0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256FillP2pGroupId(_Out_ PAP6256_P2P_ACTION_FRAME Frame, _In_ const WDI_P2P_GROUP_ID* GroupId)
{
    Frame->HaveGroupId = TRUE;
    RtlCopyMemory(Frame->GroupDeviceAddress, GroupId->DeviceAddress.Address, 6);
    Frame->GroupSsidLength = min(GroupId->GroupSSID.ElementCount, (UINT32)sizeof(Frame->GroupSsid));
    if (Frame->GroupSsidLength != 0 && GroupId->GroupSSID.pElements != NULL) {
        RtlCopyMemory(Frame->GroupSsid, GroupId->GroupSSID.pElements, Frame->GroupSsidLength);
    } else {
        Frame->GroupSsidLength = 0;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256ActionFrameInterface(_In_ PAP6256_WIFI Wifi, _In_ UINT16 Port, _Out_ PUINT32 IfIndex)
{
    *IfIndex = 0;
    if (Port == AP6256_STATION_PORT && Wifi->PortCreated) {
        return STATUS_SUCCESS;
    }
    if (Port == AP6256_DISCOVERY_PORT && Wifi->P2pPortCreated && Wifi->Ctx->P2pBssValid) {
        *IfIndex = Ap6256WifiP2pInterface(Wifi->Ctx);
        return STATUS_SUCCESS;
    }
    if (Port == AP6256_GROUP_PORT && Wifi->Ctx->Go.Created && Wifi->Ctx->Go.FirmwareReady &&
        !Wifi->Ctx->Go.Stopping) {
        *IfIndex = Wifi->Ctx->Go.IfIndex;
        return STATUS_SUCCESS;
    }
    return STATUS_INVALID_DEVICE_STATE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256StartP2pActionFrame(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                          _In_ PWDI_MESSAGE_HEADER Header, _In_ UINT16 CompletionId,
                          _In_ const AP6256_P2P_ACTION_FRAME* Frame, _In_ UINT32 SendTimeoutMs)
{
    PUCHAR body = NULL;
    ULONG length = 0;
    UCHAR bssid[6];
    UINT32 channel = 0;
    NTSTATUS status;
    AP6256_ACTION_FRAME_COMPLETION done;
    UINT32 ifIndex = 0;
    BOOLEAN claimed = FALSE;

    if (Frame->DwellMs > 65535u) {
        Ap6256CompleteRequest(Wifi, Request, STATUS_INVALID_PARAMETER);
        return;
    }

    Ap6256LockAcquire(&Wifi->ActionFrameLock);

    if (Wifi->ActionFrameTask.Active) {
        Ap6256LockRelease(&Wifi->ActionFrameLock);
        TraceWarn(TRACE_NETADAPTER, "P2P action frame REFUSED: one is already in flight\n");
        Ap6256CompleteRequest(Wifi, Request, STATUS_DEVICE_BUSY);
        return;
    }

    status = Ap6256ActionFrameInterface(Wifi, Header->PortId, &ifIndex);
    if (NT_SUCCESS(status)) {
        status = Ap6256P2pBuildActionFrame(Wifi->Ctx, Frame, &body, &length, bssid, &channel);
    }
    TraceDiag("P2P action build: txn %u port %u subtype %u token %u channel %u vendor %u bytes -> "
              "0x%08X\n",
              Header->TransactionId, (ULONG)Header->PortId, (ULONG)Frame->Subtype,
              (ULONG)Frame->DialogToken, Frame->TransmitChannel, Frame->VendorIesLength, status);
    if (NT_SUCCESS(status)) {
        status = Ap6256BeginTask(Wifi, &Wifi->ActionFrameTask, Header, Ap6256RequestGetId(Request));
    }
    if (!NT_SUCCESS(status)) {
        Ap6256LockRelease(&Wifi->ActionFrameLock);
        if (body != NULL)
            ExFreePoolWithTag(body, AP6256_POOL_TAG);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    Ap6256FreeActionFrame(Wifi);
    Wifi->ActionFrameBody = body;
    Wifi->ActionFrameBodyLength = length;
    RtlCopyMemory(Wifi->ActionFrameBssid, bssid, sizeof(bssid));
    RtlCopyMemory(Wifi->ActionFrameDest, Frame->PeerAddress, sizeof(Wifi->ActionFrameDest));
    Wifi->ActionFrameChannel = channel;
    Wifi->ActionFrameIfIndex = ifIndex;
    Wifi->ActionFrameDwellMs = max(Frame->DwellMs, AP6256_ACTION_FRAME_POST_ACK_MIN_MS);
    Wifi->ActionFrameCompleteId = CompletionId;
    Wifi->ActionFramePendingId = (UINT32)InterlockedIncrement(&Wifi->ActionFramePacketId);
    Wifi->ActionFrameRetryMs = Wifi->ActionFrameDwellMs;
    Wifi->ActionFrameDeadline =
        Ap6256InterruptTimeMs() +
        (SendTimeoutMs != 0 ? SendTimeoutMs : AP6256_ACTION_FRAME_DEFAULT_TIMEOUT_MS);

    status = Ap6256SendPendingActionFrame(Wifi);
    if (NT_SUCCESS(status)) {
        AP6256_TIMER_START(Wifi->ActionFrameTimer, Wifi->ActionFrameRetryMs);
    } else {
        claimed = Ap6256ClaimActionFrameLocked(Wifi, FALSE, &done);
    }
    Ap6256LockRelease(&Wifi->ActionFrameLock);

    Ap6256CompleteRequest(Wifi, Request, status);
    if (claimed) {
        Ap6256IndicateActionFrameDone(Wifi, &done, status);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleP2pSendRequestActionFrame(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_P2P_SEND_REQUEST_ACTION_FRAME_PARAMETERS parameters;
    AP6256_P2P_ACTION_FRAME frame;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&frame, sizeof(frame));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskP2pSendRequestActionFrame(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && (Header->PortId != AP6256_DISCOVERY_PORT || !Wifi->P2pPortCreated)) {
        TraceWarn(TRACE_NETADAPTER,
                  "P2P request action frame REFUSED: the port is not a P2P "
                  "device (op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_INVALID_DEVICE_STATE;
    }
    if (NT_SUCCESS(status) && Wifi->P2pDiscovering) {
        TraceWarn(TRACE_NETADAPTER, "P2P request action frame REFUSED: discovery is running\n");
        status = STATUS_INVALID_DEVICE_STATE;
    }

    if (NT_SUCCESS(status)) {
        const WDI_P2P_ACTION_FRAME_REQUEST_PARAMETERS* rp = &parameters.RequestParams;

        RtlCopyMemory(frame.PeerAddress, rp->PeerDeviceAddress.Address, 6);
        frame.DialogToken = rp->DialogToken;
        frame.TransmitChannel = parameters.DeviceDescriptor.ChannelInfo.ChannelNumber;
        frame.DisallowedBands = (ULONG)Wifi->DisallowedBandMask;
        frame.DwellMs = rp->PostACKDwellTime;
        frame.GroupCapability = Wifi->Ctx->P2p.GroupCapability;
        if (parameters.Optional.VendorIEs_IsPresent) {
            frame.VendorIes = parameters.VendorIEs.pElements;
            frame.VendorIesLength = parameters.VendorIEs.ElementCount;
        }

        switch (rp->RequestFrameType) {
        case WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_REQUEST: {
            const WDI_P2P_GO_NEGOTIATION_REQUEST_PARAMETERS* go =
                &parameters.GONegotiationRequestInfo.RequestParams;

            if (!parameters.Optional.GONegotiationRequestInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_GO_NEG_REQ;
            if (go->GOIntent > 15 || go->TieBreaker > 1) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (parameters.GONegotiationRequestInfo.Optional.RemoteListenChannel_IsPresent) {
                frame.TransmitChannel =
                    parameters.GONegotiationRequestInfo.RemoteListenChannel.ChannelNumber;
            }

            frame.GoIntentByte =
                (UCHAR)(((go->GOIntent & 0x7Fu) << 1) | (go->TieBreaker == 1 ? 1u : 0u));

            frame.GoConfigTimeoutMs = max(go->GOConfigTimeout, 500u);
            frame.ClientConfigTimeoutMs = max(go->ClientConfigTimeout, 150u);
            RtlCopyMemory(frame.IntendedInterface, go->IntendedInterfaceAddress.Address, 6);
            frame.HaveIntendedInterface = TRUE;
            frame.GroupCapability = go->GroupCapability;
            break;
        }

        case WDI_P2P_ACTION_FRAME_INVITATION_REQUEST: {
            const WDI_P2P_INVITATION_REQUEST_INFO_CONTAINER* info =
                &parameters.InvitationRequestInfo;

            if (!parameters.Optional.InvitationRequestInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_INVITE_REQ;
            frame.GoConfigTimeoutMs = max(info->RequestParams.GOConfigTimeout, 500u);
            frame.ClientConfigTimeoutMs = max(info->RequestParams.ClientConfigTimeout, 150u);
            frame.InvitationFlags = info->RequestParams.InvitationFlags;
            frame.HaveInvitationFlags = TRUE;
            if (info->Optional.GroupBSSID_IsPresent) {
                frame.HaveGroupBssid = TRUE;
                RtlCopyMemory(frame.GroupBssid, info->GroupBSSID.Address, 6);
            }
            if (info->Optional.OperatingChannel_IsPresent) {
                frame.HaveOperatingChannel = TRUE;
                frame.OperatingClass = info->OperatingChannel.OperatingClass;
                if (info->OperatingChannel.ChannelNumber > 165) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                frame.OperatingChannel = (UCHAR)info->OperatingChannel.ChannelNumber;
            }
            Ap6256FillP2pGroupId(&frame, &info->GroupID);
            break;
        }

        case WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_REQUEST: {
            const WDI_P2P_PROVISION_DISCOVERY_REQUEST_INFO_CONTAINER* info =
                &parameters.ProvisionDiscoveryRequestInfo;

            if (!parameters.Optional.ProvisionDiscoveryRequestInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_PROV_DISC_REQ;
            frame.GroupCapability = info->RequestParams.GroupCapability;
            if (info->Optional.GroupID_IsPresent) {
                Ap6256FillP2pGroupId(&frame, &info->GroupID);
            }
            break;
        }

        default:
            TraceWarn(TRACE_NETADAPTER,
                      "P2P request action frame type %u is not one this "
                      "driver sends\n",
                      (ULONG)rp->RequestFrameType);
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        if (NT_SUCCESS(status)) {
            Ap6256StartP2pActionFrame(Wifi, Request, Header,
                                      WDI_INDICATION_P2P_SEND_REQUEST_ACTION_FRAME_COMPLETE, &frame,
                                      rp->SendTimeout);
            CleanupParsedWdiTaskP2pSendRequestActionFrame(&parameters);
            return;
        }
    }

    TraceDiag("P2P request rejected: txn %u port %u discovering %u status 0x%08X\n",
              Header->TransactionId, (ULONG)Header->PortId, (ULONG)Wifi->P2pDiscovering, status);
    CleanupParsedWdiTaskP2pSendRequestActionFrame(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

static NTSTATUS Ap6256AppendP2pDiscoverChannel(_Inout_ PAP6256_P2P_DISCOVER Discover,
                                               _In_ UINT16 Number, _In_ UINT32 DwellMs,
                                               _In_ UINT32 CycleMs)
{
    AP6256_P2P_DISCOVER_CHANNEL* channel;
    ULONG index;

    if (Discover->DiscoveryType == AP6256_P2P_DISCOVER_SOCIAL_ONLY &&
        !Ap6256P2pIsSocialChannel(Number))
        return STATUS_SUCCESS;
    for (index = 0; index < Discover->ChannelCount; index++) {
        channel = &Discover->Channels[index];
        if (channel->Number == Number && channel->DwellMs == DwellMs && channel->CycleMs == CycleMs)
            return STATUS_SUCCESS;
    }
    if (Discover->ChannelCount == AP6256_P2P_DISCOVER_CHANNEL_MAX)
        return STATUS_INVALID_PARAMETER;
    channel = &Discover->Channels[Discover->ChannelCount++];
    channel->Number = Number;
    channel->DwellMs = DwellMs;
    channel->CycleMs = CycleMs;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256CaptureP2pDiscover(_In_ PAP6256_WIFI Wifi,
                                         _In_ const WDI_TASK_P2P_DISCOVER_PARAMETERS* Params,
                                         _Out_ PAP6256_P2P_DISCOVER Discover)
{
    const WDI_P2P_DISCOVER_MODE* mode = &Params->DiscoverMode;
    ULONG index, bandIndex, channelIndex;
    NTSTATUS status;

    RtlZeroMemory(Discover, sizeof(*Discover));
    if (mode->DiscoveryType < AP6256_P2P_DISCOVER_SCAN_ONLY ||
        mode->DiscoveryType > AP6256_P2P_DISCOVER_SOCIAL_ONLY || mode->ScanType < 1u ||
        mode->ScanType > 3u || Params->DwellTime.MaximumScanTime == 0 ||
        Params->DwellTime.ActiveChannelDwellTime > MAXLONG ||
        Params->DwellTime.PassiveChannelDwellTime > MAXLONG)
        return STATUS_INVALID_PARAMETER;

    status = Ap6256ServiceCapture(Wifi, Params, FALSE);
    if (!NT_SUCCESS(status)) return status;

    Discover->DiscoveryType = mode->DiscoveryType;
    Discover->ForcedDiscovery = mode->ForcedDiscovery;
    Discover->ActiveScan = (BOOLEAN)(mode->ScanType != 2u);
    Discover->OmitListenChannel = (BOOLEAN)(Params->Optional.bIncludeListenChannel_IsPresent &&
                                            !Params->bIncludeListenChannel);
    Discover->MaximumDwellMs = Params->DwellTime.MaximumScanTime;

    Discover->ScanRepeatCount = mode->ScanRepeatCount;
    Discover->TimeBetweenScans = mode->TimeBetweenScans;
    Discover->ActiveDwellMs = Params->DwellTime.ActiveChannelDwellTime;
    Discover->PassiveDwellMs = Params->DwellTime.PassiveChannelDwellTime;

    if (Params->Optional.SSIDList_IsPresent) {
        if (Params->SSIDList.ElementCount > AP6256_P2P_DISCOVER_SSID_MAX ||
            (Params->SSIDList.ElementCount != 0 && Params->SSIDList.pElements == NULL))
            return STATUS_INVALID_PARAMETER;
        Discover->SsidCount = Params->SSIDList.ElementCount;
        for (index = 0; index < Discover->SsidCount; index++) {
            const WDI_SSID* ssid = &Params->SSIDList.pElements[index];
            if (ssid->ElementCount > sizeof(Discover->Ssids[index].Data) ||
                (ssid->ElementCount != 0 && ssid->pElements == NULL))
                return STATUS_INVALID_PARAMETER;
            Discover->Ssids[index].Length = ssid->ElementCount;
            if (ssid->ElementCount != 0)
                RtlCopyMemory(Discover->Ssids[index].Data, ssid->pElements, ssid->ElementCount);
        }
    }

    if (Discover->SsidCount == 0)
        Discover->SsidCount = 1;

    if (!Params->Optional.DiscoveryChannelSettings_IsPresent ||
        Params->DiscoveryChannelSettings.ElementCount == 0) {

        if (!Ap6256BandIsDisallowed(Wifi, WDI_BAND_ID_2400) &&
            !Ap6256BandIsDisallowed(Wifi, WDI_BAND_ID_5000))
            return STATUS_SUCCESS;
        if (!Ap6256BandIsDisallowed(Wifi, WDI_BAND_ID_2400)) {
            for (index = 1; index <= 14; index++) {
                status = Ap6256AppendP2pDiscoverChannel(Discover, (UINT16)index, 0, 0);
                if (!NT_SUCCESS(status))
                    return status;
            }
        }
        if (!Ap6256BandIsDisallowed(Wifi, WDI_BAND_ID_5000)) {
            for (index = 0; index < RTL_NUMBER_OF(Ap6256Channels5); index++) {
                status = Ap6256AppendP2pDiscoverChannel(Discover, Ap6256Channels5[index], 0, 0);
                if (!NT_SUCCESS(status))
                    return status;
            }
        }
    } else {
        if (Params->DiscoveryChannelSettings.pElements == NULL)
            return STATUS_INVALID_PARAMETER;
        for (index = 0; index < Params->DiscoveryChannelSettings.ElementCount; index++) {
            const WDI_P2P_DISCOVERY_CHANNEL_SETTINGS_CONTAINER* settings =
                &Params->DiscoveryChannelSettings.pElements[index];
            UINT32 dwell = settings->ListenDuration.ListenActiveDuration;
            UINT32 cycle = settings->ListenDuration.CycleDuration;
            if (dwell > MAXLONG || dwell > cycle ||
                (settings->BandChannelList.ElementCount != 0 &&
                 settings->BandChannelList.pElements == NULL))
                return STATUS_INVALID_PARAMETER;
            for (bandIndex = 0; bandIndex < settings->BandChannelList.ElementCount; bandIndex++) {
                const WDI_SCAN_BAND_CHANNEL_LIST_CONTAINER* band =
                    &settings->BandChannelList.pElements[bandIndex];
                AP6256_SCAN_BAND scanBand;
                ULONG count;
                if (band->BandID == WDI_BAND_ID_2400)
                    scanBand = Ap6256ScanBand2G;
                else if (band->BandID == WDI_BAND_ID_5000)
                    scanBand = Ap6256ScanBand5G;
                else
                    return STATUS_NOT_SUPPORTED;
                if (band->ChannelList.ElementCount != 0 && band->ChannelList.pElements == NULL)
                    return STATUS_INVALID_PARAMETER;
                if (Ap6256BandIsDisallowed(Wifi, band->BandID))
                    continue;
                count = band->ChannelList.ElementCount;
                if (count == 0)
                    count = scanBand == Ap6256ScanBand2G ? 14u : RTL_NUMBER_OF(Ap6256Channels5);
                for (channelIndex = 0; channelIndex < count; channelIndex++) {
                    UINT32 number =
                        band->ChannelList.ElementCount != 0
                            ? band->ChannelList.pElements[channelIndex]
                            : (scanBand == Ap6256ScanBand2G ? channelIndex + 1
                                                            : Ap6256Channels5[channelIndex]);
                    if (!Ap6256ChannelSupported(scanBand, number))
                        return STATUS_INVALID_PARAMETER;
                    status = Ap6256AppendP2pDiscoverChannel(Discover, (UINT16)number, dwell, cycle);
                    if (!NT_SUCCESS(status))
                        return status;
                }
            }
        }
    }

    return Discover->ChannelCount != 0 ? STATUS_SUCCESS : STATUS_NETWORK_UNREACHABLE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleP2pDiscover(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                        _In_ PWDI_MESSAGE_HEADER Header,
                        _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_P2P_DISCOVER_PARAMETERS parameters;
    AP6256_P2P_DISCOVER discover;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&discover, sizeof(discover));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskP2pDiscover(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && (Header->PortId != AP6256_DISCOVERY_PORT || !Wifi->P2pPortCreated)) {
        TraceWarn(TRACE_NETADAPTER,
                  "P2P discovery REFUSED: the port is not a P2P device "
                  "(op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_INVALID_DEVICE_STATE;
    }
    if (NT_SUCCESS(status) &&
        (Wifi->P2pDiscovering || Wifi->ScanTask.Active || Wifi->ActionFrameTask.Active)) {
        TraceWarn(TRACE_NETADAPTER, "P2P discovery REFUSED: a radio task is already running\n");
        status = STATUS_INVALID_DEVICE_STATE;
    }

    if (NT_SUCCESS(status))
        status = Ap6256CaptureP2pDiscover(Wifi, &parameters, &discover);
    if (NT_SUCCESS(status) && parameters.Optional.VendorIEs_IsPresent) {
        Ap6256LockAcquire(&Wifi->P2pLock);
        status =
            Ap6256P2pSetHostIes(Wifi->Ctx, Ap6256P2pFrameProbeRequest,
                                parameters.VendorIEs.pElements, parameters.VendorIEs.ElementCount);
        Ap6256LockRelease(&Wifi->P2pLock);
    }

    if (NT_SUCCESS(status)) {
        status = Ap6256BeginTask(Wifi, &Wifi->P2pDiscoverTask, Header, Ap6256RequestGetId(Request));
    }

    if (!NT_SUCCESS(status)) {
        TraceDiag("P2P discovery rejected: txn %u port %u status 0x%08X\n", Header->TransactionId,
                  Header->PortId, status);
        CleanupParsedWdiTaskP2pDiscover(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    InterlockedExchange(&Wifi->ScanIndicated, 0);
    InterlockedExchange(&Wifi->ScanDropped, 0);
    Ap6256LockAcquire(&Wifi->P2pLock);
    status = Ap6256ServiceCapture(Wifi, &parameters, TRUE);
    if (NT_SUCCESS(status)) status = Ap6256ServiceBegin(Wifi, discover.MaximumDwellMs);
    if (NT_SUCCESS(status)) status = Ap6256P2pStartDiscovery(Wifi->Ctx, &discover);
    if (!NT_SUCCESS(status)) {
        Ap6256P2pStopDiscovery(Wifi->Ctx);
        Ap6256ServiceStop(Wifi, FALSE);
    }
    Wifi->P2pDiscovering = NT_SUCCESS(status);
    Ap6256LockRelease(&Wifi->P2pLock);
    TraceDiag("P2P discovery start: txn %u port %u bsscfg %u type %u "
              "active %u dwell %u ms, %u SSID(s), %u channel(s), repeat %u "
              "interval %u ms, vendor %u bytes -> 0x%08X\n",
              Header->TransactionId, Header->PortId, Wifi->Ctx->P2pBssIndex, discover.DiscoveryType,
              (ULONG)discover.ActiveScan, discover.MaximumDwellMs, discover.SsidCount,
              discover.ChannelCount, discover.ScanRepeatCount, discover.TimeBetweenScans,
              parameters.Optional.VendorIEs_IsPresent ? parameters.VendorIEs.ElementCount : 0,
              status);
    CleanupParsedWdiTaskP2pDiscover(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);

    if (!NT_SUCCESS(status)) {
        Ap6256FailStartedTask(Wifi, &Wifi->P2pDiscoverTask, WDI_INDICATION_P2P_DISCOVERY_COMPLETE,
                              status);
        return;
    }

    Wifi->P2pDiscovering = TRUE;
    AP6256_TIMER_START(Wifi->P2pDiscoverTimer, AP6256_P2P_DISCOVER_FIRST_MS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleP2pSendResponseActionFrame(
    _In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PWDI_MESSAGE_HEADER Header,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME_PARAMETERS parameters;
    AP6256_P2P_ACTION_FRAME frame;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&frame, sizeof(frame));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskP2pSendResponseActionFrame(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && (Header->PortId != AP6256_DISCOVERY_PORT || !Wifi->P2pPortCreated)) {
        TraceWarn(TRACE_NETADAPTER,
                  "P2P response action frame REFUSED: the port is not a P2P "
                  "device (op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_INVALID_DEVICE_STATE;
    }

    if (NT_SUCCESS(status)) {
        const WDI_P2P_SEND_ACTION_FRAME_RESPONSE_PARAMETERS* rp = &parameters.ResponseParams;

        RtlCopyMemory(frame.PeerAddress, rp->PeerDeviceAddress.Address, 6);
        frame.DialogToken = rp->DialogToken;

        if (parameters.PrecedingFrameInformation.Optional.DeviceContext_IsPresent &&
            parameters.PrecedingFrameInformation.DeviceContext.ElementCount == sizeof(UINT32) &&
            parameters.PrecedingFrameInformation.DeviceContext.pElements != NULL)
            RtlCopyMemory(&frame.TransmitChannel,
                          parameters.PrecedingFrameInformation.DeviceContext.pElements,
                          sizeof(UINT32));
        frame.DwellMs = rp->PostACKDwellTime;
        frame.GroupCapability = Wifi->Ctx->P2p.GroupCapability;
        frame.HaveStatus = TRUE;
        frame.DisallowedBands = (ULONG)Wifi->DisallowedBandMask;
        frame.PeerIes = parameters.PrecedingFrameInformation.FrameIEs.pElements;
        frame.PeerIesLength = parameters.PrecedingFrameInformation.FrameIEs.ElementCount;
        if (parameters.Optional.VendorIEs_IsPresent) {
            frame.VendorIes = parameters.VendorIEs.pElements;
            frame.VendorIesLength = parameters.VendorIEs.ElementCount;
        }

        switch (rp->ResponseFrameType) {
        case WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_RESPONSE: {
            const WDI_P2P_GO_NEGOTIATION_RESPONSE_INFO_CONTAINER* info =
                &parameters.GONegotiationResponseInfo;

            if (!parameters.Optional.GONegotiationResponseInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_GO_NEG_RSP;
            frame.Status = info->ResponseParams.StatusCode;
            if (info->ResponseParams.GOIntent > 15 || info->ResponseParams.TieBreaker > 1) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            frame.GoIntentByte = (UCHAR)(((info->ResponseParams.GOIntent & 0x7Fu) << 1) |
                                         (info->ResponseParams.TieBreaker == 1 ? 1u : 0u));
            frame.GoConfigTimeoutMs = max(info->ResponseParams.GOConfigTimeout, 500u);
            frame.ClientConfigTimeoutMs = max(info->ResponseParams.ClientConfigTimeout, 150u);
            RtlCopyMemory(frame.IntendedInterface,
                          info->ResponseParams.IntendedInterfaceAddress.Address, 6);
            frame.HaveIntendedInterface = TRUE;
            frame.GroupCapability = info->ResponseParams.GroupCapability;
            if (info->Optional.GroupID_IsPresent) {
                Ap6256FillP2pGroupId(&frame, &info->GroupID);
            }
            break;
        }

        case WDI_P2P_ACTION_FRAME_GO_NEGOTIATION_CONFIRM: {
            const WDI_P2P_GO_NEGOTIATION_CONFIRMATION_INFO_CONTAINER* info =
                &parameters.GONegotiationConfirmationInfo;

            if (!parameters.Optional.GONegotiationConfirmationInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_GO_NEG_CONF;
            if (info->Optional.RemoteListenChannel_IsPresent)
                frame.TransmitChannel = info->RemoteListenChannel.ChannelNumber;
            frame.Status = info->ConfirmationParams.StatusCode;
            frame.GroupCapability = info->ConfirmationParams.GroupCapability;
            if (info->Optional.GroupID_IsPresent) {
                Ap6256FillP2pGroupId(&frame, &info->GroupID);
            }
            break;
        }

        case WDI_P2P_ACTION_FRAME_INVITATION_RESPONSE: {
            const WDI_P2P_INVITATION_RESPONSE_INFO_CONTAINER* info =
                &parameters.InvitationResponseInfo;

            if (!parameters.Optional.InvitationResponseInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_INVITE_RSP;
            frame.Status = info->ResponseParams.StatusCode;
            frame.GoConfigTimeoutMs = max(info->ResponseParams.GOConfigTimeout, 500u);
            frame.ClientConfigTimeoutMs = max(info->ResponseParams.ClientConfigTimeout, 150u);
            if (info->Optional.GroupBSSID_IsPresent) {
                frame.HaveGroupBssid = TRUE;
                RtlCopyMemory(frame.GroupBssid, info->GroupBSSID.Address, 6);
            }
            if (info->Optional.OperatingChannel_IsPresent) {
                frame.HaveOperatingChannel = TRUE;
                frame.OperatingClass = info->OperatingChannel.OperatingClass;
                if (info->OperatingChannel.ChannelNumber > 165) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                frame.OperatingChannel = (UCHAR)info->OperatingChannel.ChannelNumber;
            }
            break;
        }

        case WDI_P2P_ACTION_FRAME_PROVISION_DISCOVERY_RESPONSE: {
            const WDI_P2P_PROVISION_DISCOVERY_RESPONSE_INFO_CONTAINER* info =
                &parameters.ProvisionDiscoveryResponseInfo;

            if (!parameters.Optional.ProvisionDiscoveryResponseInfo_IsPresent) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            frame.Subtype = AP6256_P2P_AF_PROV_DISC_RSP;

            frame.HaveStatus = FALSE;
            frame.GroupCapability = info->ResponseParams.GroupCapability;
            if (info->Optional.GroupID_IsPresent) {
                Ap6256FillP2pGroupId(&frame, &info->GroupID);
            }
            break;
        }

        default:
            TraceWarn(TRACE_NETADAPTER,
                      "P2P response action frame type %u is not one this "
                      "driver sends\n",
                      (ULONG)rp->ResponseFrameType);
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        if (NT_SUCCESS(status)) {
            Ap6256StartP2pActionFrame(Wifi, Request, Header,
                                      WDI_INDICATION_P2P_SEND_RESPONSE_ACTION_FRAME_COMPLETE,
                                      &frame, rp->SendTimeout);
            CleanupParsedWdiTaskP2pSendResponseActionFrame(&parameters);
            return;
        }
    }

    TraceDiag("P2P response rejected: txn %u port %u discovering %u status 0x%08X\n",
              Header->TransactionId, (ULONG)Header->PortId, (ULONG)Wifi->P2pDiscovering, status);
    CleanupParsedWdiTaskP2pSendResponseActionFrame(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleSetAdvertisementInformation(
    _In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header, _In_ AP6256_REQUEST Request,
    _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_ADVERTISEMENT_INFORMATION_PARAMETERS parameters;
    BOOLEAN group = Header->PortId == AP6256_GROUP_PORT;
    AP6256_P2P_STATE* p2p = group ? &Wifi->Ctx->Go.P2p : &Wifi->Ctx->P2p;
    UINT32 ifIndex = group ? Wifi->Ctx->Go.IfIndex : Ap6256WifiP2pInterface(Wifi->Ctx);
    NTSTATUS status;
    BOOLEAN rebuild = FALSE;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetAdvertisementInformation(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) &&
        ((group && !Wifi->Ctx->Go.FirmwareReady) ||
         (!group && (Header->PortId != AP6256_DISCOVERY_PORT || !Wifi->P2pPortCreated)))) {
        TraceWarn(TRACE_NETADAPTER,
                  "advertisement information REFUSED: the port is not a P2P "
                  "one (op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_INVALID_DEVICE_STATE;
    }

    if (NT_SUCCESS(status) && parameters.Optional.AdvertisedServices_IsPresent && group)
        status = STATUS_NOT_SUPPORTED;
    if (NT_SUCCESS(status) && parameters.Optional.AdvertisedServices_IsPresent)
        status=Ap6256ServiceValidateAdvertisements(Wifi,&parameters.AdvertisedServices);

    if (NT_SUCCESS(status) && parameters.Optional.AdditionalIEs_IsPresent) {
        const WDI_ADDITIONAL_IES_CONTAINER* ies = &parameters.AdditionalIEs;
        if ((ies->Optional.AdditionalBeaconIEs_IsPresent &&
             !Ap6256P2pVendorIesValid(ies->AdditionalBeaconIEs.pElements,
                                      ies->AdditionalBeaconIEs.ElementCount)) ||
            (ies->Optional.AdditionalProbeResponseIEs_IsPresent &&
             !Ap6256P2pVendorIesValid(ies->AdditionalProbeResponseIEs.pElements,
                                      ies->AdditionalProbeResponseIEs.ElementCount)) ||
            (ies->Optional.AdditionalProbeRequestDefaultIEs_IsPresent &&
             !Ap6256P2pVendorIesValid(ies->AdditionalProbeRequestDefaultIEs.pElements,
                                      ies->AdditionalProbeRequestDefaultIEs.ElementCount)))
            status = STATUS_INVALID_PARAMETER;
    }

    Ap6256LockAcquire(&Wifi->P2pLock);
    if (NT_SUCCESS(status) && parameters.Optional.DeviceCapability_IsPresent) {
        p2p->DeviceCapability = parameters.DeviceCapability.DeviceCapabilityBitmap;
        rebuild = TRUE;
    }

    if (NT_SUCCESS(status) && parameters.Optional.DeviceInformation_IsPresent) {
        const WDI_P2P_DEVICE_INFO_PARAMETERS* info =
            &parameters.DeviceInformation.DeviceInfoParameters;
        const WDI_BYTE_BLOB* name = &parameters.DeviceInformation.DeviceName;

        RtlCopyMemory(p2p->DeviceAddress, info->DeviceAddress, 6);
        p2p->ConfigMethods = info->ConfigurationMethods;
        p2p->PrimaryType.Category = info->DeviceType.CategoryID;
        p2p->PrimaryType.Subcategory = info->DeviceType.SubcategoryID;
        RtlCopyMemory(p2p->PrimaryType.Oui, info->DeviceType.OUI, 4);

        p2p->DeviceNameLength = 0;
        if (name->pElements != NULL) {
            p2p->DeviceNameLength = min(name->ElementCount, AP6256_P2P_DEVICE_NAME_MAX);
            RtlCopyMemory(p2p->DeviceName, name->pElements, p2p->DeviceNameLength);
        }
        rebuild = TRUE;
    }

    if (NT_SUCCESS(status) && parameters.Optional.GroupOwnerCapability_IsPresent) {
        p2p->GroupCapability = parameters.GroupOwnerCapability.GroupCapabilityBitmap;
        rebuild = TRUE;
    }

    if (NT_SUCCESS(status) && parameters.Optional.SecondaryDeviceTypeList_IsPresent) {
        ULONG count =
            min(parameters.SecondaryDeviceTypeList.ElementCount, AP6256_P2P_SECONDARY_MAX);
        ULONG i;

        p2p->SecondaryCount = 0;
        for (i = 0; i < count && parameters.SecondaryDeviceTypeList.pElements != NULL; i++) {
            const WDI_P2P_DEVICE_TYPE* type = &parameters.SecondaryDeviceTypeList.pElements[i];

            p2p->Secondary[i].Category = type->CategoryID;
            p2p->Secondary[i].Subcategory = type->SubcategoryID;
            RtlCopyMemory(p2p->Secondary[i].Oui, type->OUI, 4);
            p2p->SecondaryCount = i + 1;
        }
        rebuild = TRUE;
    }

    if (NT_SUCCESS(status) && parameters.Optional.AdditionalIEs_IsPresent) {
        const WDI_ADDITIONAL_IES_CONTAINER* ies = &parameters.AdditionalIEs;

        if (ies->Optional.AdditionalBeaconIEs_IsPresent) {
            status = Ap6256P2pSetHostIesFor(Wifi->Ctx, p2p, ifIndex, Ap6256P2pFrameBeacon,
                                            ies->AdditionalBeaconIEs.pElements,
                                            ies->AdditionalBeaconIEs.ElementCount);
        }
        if (NT_SUCCESS(status) && ies->Optional.AdditionalProbeResponseIEs_IsPresent) {
            status = Ap6256P2pSetHostIesFor(Wifi->Ctx, p2p, ifIndex, Ap6256P2pFrameProbeResponse,
                                            ies->AdditionalProbeResponseIEs.pElements,
                                            ies->AdditionalProbeResponseIEs.ElementCount);
        }
        if (NT_SUCCESS(status) && ies->Optional.AdditionalProbeRequestDefaultIEs_IsPresent) {
            status = Ap6256P2pSetHostIesFor(Wifi->Ctx, p2p, ifIndex, Ap6256P2pFrameProbeRequest,
                                            ies->AdditionalProbeRequestDefaultIEs.pElements,
                                            ies->AdditionalProbeRequestDefaultIEs.ElementCount);
        }
    }

    if (NT_SUCCESS(status) && rebuild) {
        status = Ap6256P2pBuildIesFor(Wifi->Ctx, p2p, ifIndex);
    }

    if (NT_SUCCESS(status) && parameters.Optional.AdvertisedServices_IsPresent)
        status = Ap6256ServiceAdvertise(Wifi, &parameters.AdvertisedServices);
    Ap6256LockRelease(&Wifi->P2pLock);
    CleanupParsedWdiSetAdvertisementInformation(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

NTSTATUS Ap6256QuiesceP2pListen(PAP6256_WIFI Wifi)
{
    NTSTATUS status = STATUS_SUCCESS;
    Ap6256LockAcquire(&Wifi->P2pLock);
    if (Wifi->Service.AdvertisementCount && Wifi->Ctx->FirmwareServiceOffload)
        status = Ap6256BcdcSetIovar(Wifi->Ctx, "p2po_stop", NULL, 0);
    if (NT_SUCCESS(status) && Wifi->Ctx->P2p.Listening && !Wifi->P2pDiscovering)
        status = Ap6256WifiSetP2pDiscoveryState(Wifi->Ctx, AP6256_P2P_DISC_SCAN, 0, 0);
    Ap6256LockRelease(&Wifi->P2pLock);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetP2pListenState(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                              _In_ AP6256_REQUEST Request,
                              _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_P2P_LISTEN_STATE_PARAMETERS parameters;
    NTSTATUS status;
    UCHAR previousChannel = Wifi->Ctx->P2p.ListenChannel;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetP2pListenState(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && (Header->PortId != AP6256_DISCOVERY_PORT || !Wifi->P2pPortCreated)) {
        TraceWarn(TRACE_NETADAPTER,
                  "P2P listen state REFUSED: the port is not a P2P device "
                  "(op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_INVALID_DEVICE_STATE;
    }

    Ap6256LockAcquire(&Wifi->P2pLock);
    if (NT_SUCCESS(status) && (Wifi->P2pDiscovering || Wifi->ScanTask.Active ||
                               Wifi->ActionFrameTask.Active || Wifi->ConnectTask.Active

                               || Ap6256ModelGroupConnecting(Wifi)))
        status = STATUS_DEVICE_BUSY;
    if (NT_SUCCESS(status)) {
        UINT32 channel = parameters.Optional.ListenChannel_IsPresent
                             ? parameters.ListenChannel.ChannelNumber
                             : Wifi->Ctx->P2p.ListenChannel;
        AP6256_TIMER_STOP(Wifi->P2pListenTimer, FALSE);
        status = Ap6256P2pSetListenState(Wifi->Ctx, parameters.ListenState,
                                         parameters.ListenDuration.ListenActiveDuration,
                                         parameters.ListenDuration.CycleDuration, channel);
        if (NT_SUCCESS(status)) status = Ap6256ServiceResumeListen(Wifi);
        if (Wifi->Ctx->P2p.Listening && !Wifi->Service.AdvertisementCount)
            AP6256_TIMER_START(Wifi->P2pListenTimer, Wifi->Ctx->P2p.ListenCycleMs);
    }
    Ap6256LockRelease(&Wifi->P2pLock);
    CleanupParsedWdiSetP2pListenState(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
    if (NT_SUCCESS(status) && previousChannel != Wifi->Ctx->P2p.ListenChannel)
        Ap6256IndicateP2pChannels(Wifi);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetNetworkListOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                  _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                  _In_ ULONG TlvLength)
{
    WDI_NETWORK_LIST_OFFLOAD_PARAMETERS parameters;
    AP6256_NLO_PARAMS* nlo = NULL;
    UINT16 hints[AP6256_PNO_CHANNEL_MAX] = {0};
    ULONG hintCount = 0;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetNetworkListOffload(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status)) {
        const WDI_NETWORK_LIST_OFFLOAD_INFO* info = &parameters.NetworkListOffload;
        const WDI_NETWORK_LIST_OFFLOAD_CONFIG* config = &info->NetworkListOffloadConfig;
        ULONG count = info->Optional.SsidOffload_IsPresent ? info->SsidOffload.ElementCount : 0;
        ULONG index;

        nlo =
            (AP6256_NLO_PARAMS*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*nlo), AP6256_POOL_TAG);
        if (nlo == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            count = 0;
        }

        if (NT_SUCCESS(status) && count > AP6256_NLO_NETWORK_MAX) {
            TraceWarn(TRACE_NETADAPTER,
                      "network list offload: %u networks is more than the %u "
                      "this firmware holds\n",
                      count, AP6256_NLO_NETWORK_MAX);
            status = STATUS_INVALID_PARAMETER;
        }

        for (index = 0; NT_SUCCESS(status) && index < count; index++) {
            const WDI_SSID_OFFLOAD_CONTAINER* source = &info->SsidOffload.pElements[index];
            AP6256_NLO_NETWORK* net = &nlo->Networks[index];
            ULONG hint, previous;
            UINT32 auth = 1;
            UINT32 cipher = 0;

            if (source->UnicastAlgorithms.ElementCount != 0 &&
                source->UnicastAlgorithms.pElements != NULL) {
                auth = source->UnicastAlgorithms.pElements[0].AuthAlgorithm;
                cipher = source->UnicastAlgorithms.pElements[0].CipherAlgorithm;
            }

            if (!Ap6256WifiNloSecuritySupported(auth, cipher)) {
                TraceWarn(TRACE_NETADAPTER,
                          "network list offload: auth %u with cipher 0x%03X "
                          "is not a pair this firmware scans for\n",
                          auth, cipher);
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }

            if (source->SsidToScan.ElementCount > sizeof(net->Ssid) ||
                (source->SsidToScan.ElementCount != 0 && source->SsidToScan.pElements == NULL)) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            net->SsidLength = source->SsidToScan.ElementCount;
            if (net->SsidLength != 0) {
                RtlCopyMemory(net->Ssid, source->SsidToScan.pElements, net->SsidLength);
            }
            net->AuthAlgorithm = auth;
            net->DirectedProbePermitted =
                (BOOLEAN)(source->Optional.IsDirectedProbeForHiddenPermitted_IsPresent &&
                          source->IsDirectedProbeForHiddenPermitted);
            net->CipherAlgorithm = cipher;
            nlo->NetworkCount = index + 1;
            if (source->BandChannelHintList.ElementCount > AP6256_NLO_CHANNEL_HINTS ||
                (source->BandChannelHintList.ElementCount != 0 &&
                 source->BandChannelHintList.pElements == NULL)) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }
            for (hint = 0; hint < source->BandChannelHintList.ElementCount; ++hint) {
                const WDI_BAND_CHANNEL_MAPPING_ENTRY* channel =
                    &source->BandChannelHintList.pElements[hint];
                if (channel->ChannelNumber == 0 || channel->ChannelNumber > 255 ||
                    (Wifi->TlvContext.PeerVersion > WDI_VERSION_1_1_9 &&
                     channel->BandId != WDI_BAND_ID_ANY &&
                     channel->BandId !=
                         (channel->ChannelNumber <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000))) {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }
                for (previous = 0; previous < hintCount; ++previous)
                    if (hints[previous] == channel->ChannelNumber)
                        break;
                if (previous == hintCount) {
                    if (hintCount == AP6256_PNO_CHANNEL_MAX) {
                        status = STATUS_INVALID_PARAMETER;
                        break;
                    }
                    hints[hintCount++] = (UINT16)channel->ChannelNumber;
                }
            }
        }

        if (NT_SUCCESS(status)) {

            nlo->Enable = (BOOLEAN)((config->ulFlags & 0x2u) != 0 && (config->ulFlags & 0x1u) == 0);
            nlo->ScanPeriodSeconds = config->FastScanIterations != 0
                                         ? config->FastScanPeriodinSeconds
                                         : config->SlowScanPeriodinSeconds;
            nlo->WindowsRequest = TRUE;
            nlo->FastIterations = config->FastScanIterations;
            nlo->SlowPeriodSeconds = config->SlowScanPeriodinSeconds;
            nlo->DelayStartSeconds = config->DelayStartInSeconds;
            status = Ap6256WifiSetWindowsNetworkListOffload(Wifi->Ctx, nlo, hints, hintCount);
        }
    }

    if (nlo != NULL)
        ExFreePoolWithTag(nlo, AP6256_POOL_TAG);
    CleanupParsedWdiSetNetworkListOffload(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256RecomputePortModes(_In_ PAP6256_WIFI Wifi)
{
    Wifi->PortOperationMode = (Wifi->PortCreated ? Wifi->StationPortMode : 0u) |
                              (Wifi->P2pPortCreated ? Wifi->P2pPortMode : 0u) |
                              (Wifi->Ctx->Go.Created ? Wifi->Ctx->Go.Mode : 0u);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
ULONG Ap6256WolPatternCeiling(_In_ PAP6256_WIFI Wifi)
{
    ULONG firmware = (ULONG)Wifi->Ctx->PacketFilterMax;

    if (firmware == 0 || firmware > AP6256_WOL_PATTERN_MAX) {
        return AP6256_WOL_PATTERN_MAX;
    }
    return firmware;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256RememberWolPattern(_In_ PAP6256_WIFI Wifi,
                                                                        _In_ UINT32 PatternId)
{
    if (Wifi->WolPatternCount < RTL_NUMBER_OF(Wifi->WolPatternIds)) {
        Wifi->WolPatternIds[Wifi->WolPatternCount] = PatternId;
        Wifi->WolPatternCount++;
    }
    (VOID) Ap6256WifiEnablePacketFilter(Wifi->Ctx, PatternId, TRUE);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256ForgetWolPattern(_In_ PAP6256_WIFI Wifi,
                                                                      _In_ UINT32 PatternId)
{
    ULONG index;

    for (index = 0; index < Wifi->WolPatternCount; index++) {
        if (Wifi->WolPatternIds[index] != PatternId)
            continue;
        for (; index + 1 < Wifi->WolPatternCount; index++) {
            Wifi->WolPatternIds[index] = Wifi->WolPatternIds[index + 1];
        }
        Wifi->WolPatternCount--;
        Wifi->WolPatternIds[Wifi->WolPatternCount] = 0;
        return;
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAddWolPattern(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                          _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_ADD_WOL_PATTERN_PARAMETERS parameters;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetAddWolPattern(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && !Wifi->Ctx->FirmwareArpOffloadSupported) {
        status = STATUS_NOT_SUPPORTED;
    }

    if (NT_SUCCESS(status) && (Wifi->PortOperationMode & AP6256_WDI_OPMODE_STA) == 0 &&
        Wifi->PortOperationMode != 0) {
        TraceWarn(TRACE_NETADAPTER,
                  "wake pattern REFUSED: the port is not a station "
                  "(op mode 0x%02X)\n",
                  Wifi->PortOperationMode);
        status = STATUS_UNSUCCESSFUL;
    }

    if (NT_SUCCESS(status)) {
        if (parameters.Optional.WakePacketEapolRequestIdPatternId_IsPresent) {
            if (Wifi->WolPatternCount >= Ap6256WolPatternCeiling(Wifi)) {
                status = Ap6256NdisToNtStatus(NDIS_STATUS_RESOURCES);
            } else {
                status = Ap6256WifiAddWolEapolPattern(Wifi->Ctx,
                                                      parameters.WakePacketEapolRequestIdPatternId);
                if (NT_SUCCESS(status)) {
                    Ap6256RememberWolPattern(Wifi, parameters.WakePacketEapolRequestIdPatternId);
                }
            }
        } else if (parameters.Optional.WakePacketIpv4TcpSync_IsPresent ||
                   parameters.Optional.WakePacketIpv6TcpSync_IsPresent) {
            TraceWarn(TRACE_NETADAPTER, "wake on TCP SYN is not something this firmware "
                                        "matches\n");
            status = STATUS_NOT_SUPPORTED;
        } else if (parameters.Optional.WakePacketMagicPacketPatternId_IsPresent) {

            status =
                Ap6256WifiAddWolMagicPattern(Wifi->Ctx, parameters.WakePacketMagicPacketPatternId);
        } else if (parameters.Optional.WakePacketPattern_IsPresent) {
            ULONG index;

            status = STATUS_SUCCESS;
            for (index = 0; index < parameters.WakePacketPattern.ElementCount && NT_SUCCESS(status);
                 index++) {
                const WDI_PACKET_PATTERN_CONTAINER* source =
                    &parameters.WakePacketPattern.pElements[index];

                if (source->PacketPattern.pElements == NULL ||
                    source->PacketPatternMask.pElements == NULL) {
                    status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                    break;
                }
                if (Wifi->WolPatternCount >= Ap6256WolPatternCeiling(Wifi)) {
                    TraceWarn(TRACE_NETADAPTER,
                              "wake pattern %u refused: %u are already "
                              "programmed\n",
                              source->WakePacketPatternId, Wifi->WolPatternCount);
                    status = Ap6256NdisToNtStatus(NDIS_STATUS_RESOURCES);
                    break;
                }
                status = Ap6256WifiAddWolBitmapPattern(
                    Wifi->Ctx, source->WakePacketPatternId, source->PacketPattern.pElements,
                    source->PacketPattern.ElementCount, source->PacketPatternMask.pElements,
                    source->PacketPatternMask.ElementCount);
                if (NT_SUCCESS(status)) {
                    Ap6256RememberWolPattern(Wifi, source->WakePacketPatternId);
                }
            }
        } else {

            TraceWarn(TRACE_NETADAPTER, "wake pattern command named no pattern\n");
        }
    }

    CleanupParsedWdiSetAddWolPattern(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRemoveWolPattern(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                             _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_REMOVE_WOL_PATTERN_PARAMETERS parameters;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetRemoveWolPattern(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status) && !Wifi->Ctx->FirmwareArpOffloadSupported) {
        status = STATUS_NOT_SUPPORTED;
    }

    if (NT_SUCCESS(status)) {
        status = Ap6256WifiRemoveWolPattern(Wifi->Ctx, parameters.PatternId);
        if (NT_SUCCESS(status)) {
            Ap6256ForgetWolPattern(Wifi, parameters.PatternId);
        }
    }

    CleanupParsedWdiSetRemoveWolPattern(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddArpOffload(_In_ PAP6256_WIFI Wifi,
                    _In_ const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* Source)
{
    AP6256_ARP_OFFLOAD offload;
    AP6256_ARP_OFFLOAD previous;
    const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* old;
    BOOLEAN replacing;
    ULONG slot;
    NTSTATUS status;

    if (!Wifi->Ctx->FirmwareArpOffloadSupported ||
        (Wifi->Ctx->WowlCapabilities & AP6256_WOWL_ARP_OFFLOAD) == 0)
        return STATUS_NOT_SUPPORTED;
    for (slot = 0; slot < Wifi->NsOffloadCount; ++slot)
        if (Wifi->NsOffloads[slot].ProtocolOffloadId == Source->ProtocolOffloadId)
            return STATUS_INVALID_PARAMETER;

    for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; slot++) {
        if (Wifi->ArpOffloadValid[slot] &&
            Wifi->ArpOffloadIds[slot] == Source->ProtocolOffloadId)
            break;
    }
    if (slot == AP6256_ARP_OFFLOAD_SLOTS) {
        for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; slot++) {
            if (!Wifi->ArpOffloadValid[slot])
                break;
        }
    }
    if (slot == AP6256_ARP_OFFLOAD_SLOTS) {
        TraceWarn(TRACE_NETADAPTER, "ARP offload %u refused: all %u slots are in use\n",
                  Source->ProtocolOffloadId, AP6256_ARP_OFFLOAD_SLOTS);
        return Ap6256NdisToNtStatus(NDIS_STATUS_RESOURCES);
    }

    if (Wifi->GtkOffloadValid && Wifi->GtkOffloadId == Source->ProtocolOffloadId)
        return STATUS_INVALID_PARAMETER;
    replacing = Wifi->ArpOffloadValid[slot];
    if (replacing) {

        old = &Wifi->ArpOffloads[slot];
        RtlZeroMemory(&previous, sizeof(previous));
        previous.OffloadId = old->ProtocolOffloadId;
        RtlCopyMemory(previous.RemoteIpv4, old->RemoteIPV4Address, 4);
        RtlCopyMemory(previous.HostIpv4, old->HostIPV4Address, 4);
        RtlCopyMemory(previous.MacAddress, old->MacAddress.Address, 6);
    }

    RtlZeroMemory(&offload, sizeof(offload));
    offload.OffloadId = Source->ProtocolOffloadId;
    RtlCopyMemory(offload.RemoteIpv4, Source->RemoteIPV4Address, 4);
    RtlCopyMemory(offload.HostIpv4, Source->HostIPV4Address, 4);
    RtlCopyMemory(offload.MacAddress, Source->MacAddress.Address, 6);

    status = Ap6256WifiAddArpOffload(Wifi->Ctx, &offload, slot);
    if (NT_SUCCESS(status)) {
        Wifi->ArpOffloadValid[slot] = TRUE;
        Wifi->ArpOffloadIds[slot] = offload.OffloadId;
        Wifi->ArpOffloads[slot] = *Source;
    } else if (replacing) {
        NTSTATUS restoreStatus = Ap6256WifiAddArpOffload(Wifi->Ctx, &previous, slot);
        if (!NT_SUCCESS(restoreStatus)) {

            Wifi->ArpOffloadValid[slot] = FALSE;
            Wifi->ArpOffloadIds[slot] = 0;
            RtlZeroMemory(&Wifi->ArpOffloads[slot],
                          sizeof(Wifi->ArpOffloads[slot]));
            TraceError(TRACE_NETADAPTER,
                       "ARP offload %u restore failed 0x%08X after update failure 0x%08X\n",
                       Source->ProtocolOffloadId, restoreStatus, status);
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256RemoveArpOffloadId(_In_ PAP6256_WIFI Wifi, _In_ UINT32 id)
{
    ULONG slot;
    NTSTATUS status;
    UINT32 disable = 0;
    for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; ++slot)
        if (Wifi->ArpOffloadValid[slot] && Wifi->ArpOffloadIds[slot] == id) break;
    if (slot == AP6256_ARP_OFFLOAD_SLOTS) return STATUS_INVALID_PARAMETER;
    status = Ap6256WifiRemoveArpOffload(Wifi->Ctx, slot);
    if (NT_SUCCESS(status)) {
        Wifi->ArpOffloadValid[slot] = FALSE;
        Wifi->ArpOffloadIds[slot] = 0;
        RtlZeroMemory(&Wifi->ArpOffloads[slot],
                      sizeof(Wifi->ArpOffloads[slot]));

        status = Ap6256BcdcSetIovar(Wifi->Ctx, "arpoe", &disable, sizeof(disable));
        if (!NT_SUCCESS(status)) {
            Wifi->Ctx->FirmwareArpOffloadSupported = FALSE;
            TraceError(TRACE_NETADAPTER, "D0 ARP disable after removal failed 0x%08X\n", status);
        }
    } else {

        AP6256_ARP_OFFLOAD previous;
        const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* old =
            &Wifi->ArpOffloads[slot];
        NTSTATUS restoreStatus;
        RtlZeroMemory(&previous, sizeof(previous));
        previous.OffloadId = old->ProtocolOffloadId;
        RtlCopyMemory(previous.RemoteIpv4, old->RemoteIPV4Address, 4);
        RtlCopyMemory(previous.HostIpv4, old->HostIPV4Address, 4);
        RtlCopyMemory(previous.MacAddress, old->MacAddress.Address, 6);
        restoreStatus = Ap6256WifiAddArpOffload(Wifi->Ctx, &previous, slot);
        if (!NT_SUCCESS(restoreStatus)) {
            Wifi->ArpOffloadValid[slot] = FALSE;
            Wifi->ArpOffloadIds[slot] = 0;
            RtlZeroMemory(&Wifi->ArpOffloads[slot],
                          sizeof(Wifi->ArpOffloads[slot]));
            TraceError(TRACE_NETADAPTER,
                       "ARP offload %u restore failed 0x%08X after removal failure 0x%08X\n",
                       id, restoreStatus, status);
        }
    }
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256ProgramNsOffload(_In_ PAP6256_WIFI Wifi,
                        _In_ const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER* Source)
{
    AP6256_NS_OFFLOAD offload;
    RtlZeroMemory(&offload, sizeof(offload));
    offload.OffloadId = Source->ProtocolOffloadId;
    RtlCopyMemory(offload.RemoteIpv6, Source->RemoteIPV6Address, 16);
    RtlCopyMemory(offload.SolicitedNodeIpv6, Source->SolicitdNodeIPv6Address, 16);
    RtlCopyMemory(offload.TargetIpv6A, Source->TargetIPV6Address1, 16);
    RtlCopyMemory(offload.TargetIpv6B, Source->TargetIPV6Address2, 16);
    RtlCopyMemory(offload.MacAddress, Source->MacAddress.Address, 6);
    return Ap6256WifiAddNsOffload(Wifi->Ctx, &offload);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256ApplyNsTable(_In_ PAP6256_WIFI Wifi,
                    _In_reads_(AP6256_NS_OFFLOAD_ADDRESSES)
                    const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER* Desired,
                    _In_ ULONG DesiredCount)
{
    UINT32 disable = 0;
    ULONG oldCount = Wifi->NsOffloadCount, i, attempted;
    NTSTATUS status, restoreStatus;
    if (DesiredCount > AP6256_NS_OFFLOAD_ADDRESSES) return STATUS_INVALID_PARAMETER;
    status = Ap6256BcdcSetIovar(Wifi->Ctx, "ndoe", &disable, sizeof(disable));
    if (!NT_SUCCESS(status)) return status;

    for (i = oldCount; i != 0; --i) {
        status = Ap6256WifiRemoveNsOffload(
            Wifi->Ctx, Wifi->NsOffloads[i - 1].ProtocolOffloadId);
        if (!NT_SUCCESS(status)) goto uncertain;
    }
    for (i = 0; i < DesiredCount; ++i) {
        status = Ap6256ProgramNsOffload(Wifi, &Desired[i]);
        if (!NT_SUCCESS(status)) {

            attempted = i + 1;
            while (attempted != 0) {
                --attempted;
                restoreStatus = Ap6256WifiRemoveNsOffload(
                    Wifi->Ctx, Desired[attempted].ProtocolOffloadId);
                if (!NT_SUCCESS(restoreStatus)) goto uncertain;
            }
            for (attempted = 0; attempted < oldCount; ++attempted) {
                restoreStatus = Ap6256ProgramNsOffload(
                    Wifi, &Wifi->NsOffloads[attempted]);
                if (!NT_SUCCESS(restoreStatus)) goto uncertain;
            }
            return status;
        }
    }
    RtlCopyMemory(Wifi->NsOffloads, Desired, sizeof(Wifi->NsOffloads));
    Wifi->NsOffloadCount = DesiredCount;
    return STATUS_SUCCESS;
uncertain:

    Wifi->Ctx->FirmwareNdOffloadSupported = FALSE;
    RtlZeroMemory(Wifi->NsOffloads, sizeof(Wifi->NsOffloads));
    Wifi->NsOffloadCount = 0;
    (VOID)Ap6256BcdcSetIovar(Wifi->Ctx, "ndoe", &disable, sizeof(disable));
    TraceError(TRACE_NETADAPTER,
               "NS table rebuild failed 0x%08X; ND disabled until firmware reinitialization\n",
               status);
    return status;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256AddNsOffload(_In_ PAP6256_WIFI Wifi,
                   _In_ const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER* Source)
{
    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER desired[AP6256_NS_OFFLOAD_ADDRESSES];
    ULONG i, slot, desiredCount = Wifi->NsOffloadCount;
    BOOLEAN haveTarget = FALSE;
    if (!Wifi->Ctx->FirmwareNdOffloadSupported ||
        (Wifi->Ctx->WowlCapabilities & AP6256_WOWL_ARP_OFFLOAD) == 0)
        return STATUS_NOT_SUPPORTED;
    for (i = 0; i < AP6256_ARP_OFFLOAD_SLOTS; ++i)
        if (Wifi->ArpOffloadValid[i] &&
            Wifi->ArpOffloadIds[i] == Source->ProtocolOffloadId)
            return STATUS_INVALID_PARAMETER;
    if (Wifi->GtkOffloadValid && Wifi->GtkOffloadId == Source->ProtocolOffloadId)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < 16; ++i)
        if (Source->TargetIPV6Address1[i] || Source->TargetIPV6Address2[i])
            haveTarget = TRUE;
    if (!haveTarget) return STATUS_INVALID_PARAMETER;
    RtlCopyMemory(desired, Wifi->NsOffloads, sizeof(desired));
    for (slot = 0; slot < desiredCount; ++slot)
        if (desired[slot].ProtocolOffloadId == Source->ProtocolOffloadId) break;
    if (slot == AP6256_NS_OFFLOAD_ADDRESSES)
        return Ap6256NdisToNtStatus(NDIS_STATUS_RESOURCES);
    desired[slot] = *Source;
    if (slot == desiredCount) ++desiredCount;
    return Ap6256ApplyNsTable(Wifi, desired, desiredCount);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256RemoveNsOffloadId(_In_ PAP6256_WIFI Wifi, _In_ UINT32 Id)
{
    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER desired[AP6256_NS_OFFLOAD_ADDRESSES];
    ULONG slot, i;
    for (slot = 0; slot < Wifi->NsOffloadCount; ++slot)
        if (Wifi->NsOffloads[slot].ProtocolOffloadId == Id) break;
    if (slot == Wifi->NsOffloadCount) return STATUS_INVALID_PARAMETER;
    if (!Wifi->Ctx->FirmwareNdOffloadSupported) return STATUS_NOT_SUPPORTED;
    RtlZeroMemory(desired, sizeof(desired));
    for (i = 0; i < slot; ++i) desired[i] = Wifi->NsOffloads[i];
    for (i = slot + 1; i < Wifi->NsOffloadCount; ++i)
        desired[i - 1] = Wifi->NsOffloads[i];
    return Ap6256ApplyNsTable(Wifi, desired, Wifi->NsOffloadCount - 1);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256ClearPmOffloads(_In_ PAP6256_WIFI Wifi)
{
    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER empty[AP6256_NS_OFFLOAD_ADDRESSES];
    ULONG slot;
    BOOLEAN hadArp = FALSE;
    UINT32 disable = 0;
    NTSTATUS status;
    if (Wifi->Ctx->FirmwareWowlAdapter) {
        (VOID)Ap6256WifiRemoveGtkOffload(Wifi->Ctx);
        for (slot = 0; slot < 6; ++slot)
            Ap6256WifiSeedGroupKey(Wifi->Ctx, slot, slot >= 4, FALSE, NULL, NULL);
    }
    Wifi->GtkOffloadValid = FALSE;
    Wifi->GtkOffloadId = 0;
    RtlSecureZeroMemory(&Wifi->GtkOffload, sizeof(Wifi->GtkOffload));

    if (Wifi->NsOffloadCount != 0) {
        RtlZeroMemory(empty, sizeof(empty));
        (VOID)Ap6256ApplyNsTable(Wifi, empty, 0);
    }
    for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; ++slot) {
        if (!Wifi->ArpOffloadValid[slot]) continue;
        hadArp = TRUE;
        status = Ap6256WifiRemoveArpOffload(Wifi->Ctx, slot);
        if (!NT_SUCCESS(status)) {
            Wifi->Ctx->FirmwareArpOffloadSupported = FALSE;
            TraceError(TRACE_NETADAPTER,
                       "disconnect ARP clear slot %u failed 0x%08X\n", slot, status);
        }
    }
    if (hadArp) {
        status = Ap6256BcdcSetIovar(Wifi->Ctx, "arpoe", &disable, sizeof(disable));
        if (!NT_SUCCESS(status)) {
            Wifi->Ctx->FirmwareArpOffloadSupported = FALSE;
            TraceError(TRACE_NETADAPTER, "disconnect ARP disable failed 0x%08X\n", status);
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleAddPmProtocolOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_ADD_PM_PROTOCOL_OFFLOAD_PARAMETERS_PARAMETERS parameters;
    WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER previousArp;
    NTSTATUS status, rollbackStatus;
    AP6256_GTK_OFFLOAD gtk, previousGtk;
    BOOLEAN gtkApplied = FALSE, previousGtkValid;
    BOOLEAN arpApplied = FALSE, previousArpValid = FALSE;
    UINT32 disable = 0;
    ULONG slot;
    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&previousArp, sizeof(previousArp));
    RtlZeroMemory(&gtk, sizeof(gtk));
    RtlZeroMemory(&previousGtk, sizeof(previousGtk));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetAddPmProtocolOffload(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (NT_SUCCESS(status) && (Wifi->PortOperationMode & AP6256_WDI_OPMODE_STA) == 0 &&
        Wifi->PortOperationMode != 0) status = STATUS_NOT_SUPPORTED;

    if (NT_SUCCESS(status) &&
        (Ap6256FipsActive(Wifi->Ctx, 0) || Ap6256HostCipherPacketActive(Wifi->Ctx, 0)))
        status = STATUS_NOT_SUPPORTED;
    previousGtkValid = Wifi->GtkOffloadValid;
    previousGtk = Wifi->GtkOffload;

    if (NT_SUCCESS(status) &&
        ((parameters.Optional.DOT11RSNREKeyOffload_IsPresent &&
          !Wifi->Ctx->FirmwareGtkOffloadSupported) ||
         (parameters.Optional.ipv4ARPOffload_IsPresent &&
          !Wifi->Ctx->FirmwareArpOffloadSupported) ||
         (parameters.Optional.ipv6ARPOffload_IsPresent &&
          !Wifi->Ctx->FirmwareNdOffloadSupported) ||
         ((parameters.Optional.ipv4ARPOffload_IsPresent || parameters.Optional.ipv6ARPOffload_IsPresent) &&
          (Wifi->Ctx->WowlCapabilities & AP6256_WOWL_ARP_OFFLOAD) == 0)))
        status = STATUS_NOT_SUPPORTED;
    if (NT_SUCCESS(status) &&
        ((!parameters.Optional.ipv4ARPOffload_IsPresent &&
          !parameters.Optional.ipv6ARPOffload_IsPresent && !parameters.Optional.DOT11RSNREKeyOffload_IsPresent) ||
         (parameters.Optional.ipv4ARPOffload_IsPresent &&
          parameters.Optional.ipv6ARPOffload_IsPresent &&
          parameters.ipv4ARPOffload.ProtocolOffloadId ==
          parameters.ipv6ARPOffload.ProtocolOffloadId)))
        status = STATUS_INVALID_PARAMETER;
    if (NT_SUCCESS(status) && parameters.Optional.DOT11RSNREKeyOffload_IsPresent) {
        UINT32 id = parameters.DOT11RSNREKeyOffload.RsnKeyInfo.ProtocolOffloadId;
        status = previousGtkValid && previousGtk.OffloadId != id
            ? STATUS_INSUFFICIENT_RESOURCES
            : Ap6256BuildGtkOffload(Wifi, &parameters.DOT11RSNREKeyOffload.RsnKeyInfo, &gtk);
        if ((parameters.Optional.ipv4ARPOffload_IsPresent && id == parameters.ipv4ARPOffload.ProtocolOffloadId) ||
            (parameters.Optional.ipv6ARPOffload_IsPresent && id == parameters.ipv6ARPOffload.ProtocolOffloadId))
            status = STATUS_INVALID_PARAMETER;
        for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; ++slot)
            if (Wifi->ArpOffloadValid[slot] && Wifi->ArpOffloadIds[slot] == id) status = STATUS_INVALID_PARAMETER;
        for (slot = 0; slot < Wifi->NsOffloadCount; ++slot)
            if (Wifi->NsOffloads[slot].ProtocolOffloadId == id) status = STATUS_INVALID_PARAMETER;
        if (NT_SUCCESS(status) && previousGtkValid) {
            AP6256_GTK_STATE current;
            status = Ap6256WifiReadGtkOffload(Wifi->Ctx, &current);
            if (NT_SUCCESS(status) && current.OffloadId != previousGtk.OffloadId)
                status = STATUS_DATA_ERROR;
            if (NT_SUCCESS(status)) {
                ULONG byte;
                previousGtk.ReplayCounter = 0;
                for (byte = 0; byte < 8; ++byte)
                    previousGtk.ReplayCounter = (previousGtk.ReplayCounter << 8) | current.Replay[byte];
            }
            RtlSecureZeroMemory(&current, sizeof(current));
        }
        if (NT_SUCCESS(status)) {
            gtkApplied = TRUE;
            status = Ap6256WifiAddGtkOffload(Wifi->Ctx, &gtk);
        }
    }
    if (NT_SUCCESS(status) && parameters.Optional.ipv4ARPOffload_IsPresent) {
        for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; ++slot)
            if (Wifi->ArpOffloadValid[slot] &&
                Wifi->ArpOffloadIds[slot] == parameters.ipv4ARPOffload.ProtocolOffloadId) {
                previousArpValid = TRUE;
                previousArp = Wifi->ArpOffloads[slot];
                break;
            }
        status = Ap6256AddArpOffload(Wifi, &parameters.ipv4ARPOffload);
        arpApplied = (BOOLEAN)NT_SUCCESS(status);
    }
    if (NT_SUCCESS(status) && parameters.Optional.ipv6ARPOffload_IsPresent) {
        status = Ap6256AddNsOffload(Wifi, &parameters.ipv6ARPOffload);
        if (!NT_SUCCESS(status) && arpApplied) {

            rollbackStatus = previousArpValid
                ? Ap6256AddArpOffload(Wifi, &previousArp)
                : Ap6256RemoveArpOffloadId(Wifi, parameters.ipv4ARPOffload.ProtocolOffloadId);
            if (!NT_SUCCESS(rollbackStatus)) {
                Wifi->Ctx->FirmwareArpOffloadSupported = FALSE;
                RtlZeroMemory(Wifi->ArpOffloadValid, sizeof(Wifi->ArpOffloadValid));
                RtlZeroMemory(Wifi->ArpOffloadIds, sizeof(Wifi->ArpOffloadIds));
                RtlZeroMemory(Wifi->ArpOffloads, sizeof(Wifi->ArpOffloads));
                (VOID)Ap6256BcdcSetIovar(Wifi->Ctx, "arpoe", &disable, sizeof(disable));
                TraceError(TRACE_NETADAPTER,
                           "mixed PM ADD rollback failed 0x%08X after NS failure 0x%08X\n",
                           rollbackStatus, status);
            }
        }
    }
    if (gtkApplied) {
        if (NT_SUCCESS(status)) {
            Wifi->GtkOffload = gtk; Wifi->GtkOffloadId = gtk.OffloadId; Wifi->GtkOffloadValid = TRUE;
        } else {
            rollbackStatus = previousGtkValid ? Ap6256WifiAddGtkOffload(Wifi->Ctx, &previousGtk)
                : Ap6256WifiRemoveGtkOffload(Wifi->Ctx);
            if (!NT_SUCCESS(rollbackStatus)) {
                Wifi->Ctx->FirmwareGtkOffloadSupported = FALSE;
                Wifi->GtkOffloadValid = FALSE; Wifi->GtkOffloadId = 0;
                RtlSecureZeroMemory(&Wifi->GtkOffload, sizeof(Wifi->GtkOffload));
                TraceError(TRACE_NETADAPTER, "GTK ADD rollback failed 0x%08X\n", rollbackStatus);
            }
        }
    }
    RtlSecureZeroMemory(&gtk, sizeof(gtk));
    RtlSecureZeroMemory(&previousGtk, sizeof(previousGtk));
    Ap6256LockRelease(&Wifi->ConnectLock);
    CleanupParsedWdiSetAddPmProtocolOffload(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleRemovePmProtocolOffload(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                    _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                    _In_ ULONG TlvLength)
{
    WDI_SET_REMOVE_PM_PROTOCOL_OFFLOAD_PARAMETERS parameters;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetRemovePmProtocolOffload(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    Ap6256LockAcquire(&Wifi->ConnectLock);
    if (NT_SUCCESS(status)) {
        UINT32 id = parameters.RemovePMOffload;
        ULONG slot;

        if (Wifi->GtkOffloadValid && Wifi->GtkOffloadId == id) {
            status = Ap6256WifiRemoveGtkOffload(Wifi->Ctx);
            if (NT_SUCCESS(status)) {
                Wifi->GtkOffloadValid = FALSE;
                Wifi->GtkOffloadId = 0;
                RtlSecureZeroMemory(&Wifi->GtkOffload, sizeof(Wifi->GtkOffload));
            }
        } else {
            for (slot = 0; slot < AP6256_ARP_OFFLOAD_SLOTS; slot++) {
                if (Wifi->ArpOffloadValid[slot] && Wifi->ArpOffloadIds[slot] == id)
                    break;
            }
            if (slot != AP6256_ARP_OFFLOAD_SLOTS) {
                status = Ap6256RemoveArpOffloadId(Wifi, id);
            } else {
                status = Ap6256RemoveNsOffloadId(Wifi, id);
            }
        }
    }

    Ap6256LockRelease(&Wifi->ConnectLock);
    CleanupParsedWdiSetRemovePmProtocolOffload(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static AP6256_RX_COALESCE_FILTER*
Ap6256FindCoalesceFilter(_In_ PAP6256_WIFI Wifi, _In_ UINT32 FilterId, _In_ BOOLEAN InUse)
{
    ULONG i;

    for (i = 0; i < AP6256_RX_COALESCE_FILTERS; i++) {
        AP6256_RX_COALESCE_FILTER* slot = &Wifi->RxCoalesceFilters[i];
        if (InUse) {
            if (slot->Fields != NULL && slot->FilterId == FilterId)
                return slot;
        } else if (slot->Fields == NULL) {
            return slot;
        }
    }
    return NULL;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256ApplyCoalesceFilter(_In_ PAP6256_WIFI Wifi, _In_ const AP6256_RX_COALESCE_FILTER* Filter,
                          _In_ BOOLEAN Add)
{
    BOOLEAN ipv6 = FALSE;
    ULONG i;

    for (i = 0; i < Filter->FieldCount; i++) {
        const WDI_RECEIVE_COALESCING_FIELD* field = &Filter->Fields[i];

        switch (field->FrameHeader) {
        case NdisFrameHeaderArp:
            if (field->HeaderField == NdisARPHeaderFieldTPA) {
                (VOID) Ap6256WifiSetD0FilterArp(Wifi->Ctx, Add, field->FieldValue.Byte);
            }
            break;

        case NdisFrameHeaderIPv6:
            ipv6 = TRUE;
            break;

        case NdisFrameHeaderUdp:
            if (field->HeaderField == NdisUdpHeaderFieldDestinationPort) {
                UINT32 port = ((UINT32)field->FieldValue.Byte[0] << 8) | field->FieldValue.Byte[1];
                UINT32 mask = Ap6256WifiD0FilterMaskForPort(port, ipv6);

                if (mask != 0) {
                    (VOID) Ap6256WifiSetD0FilterProtocol(Wifi->Ctx, Add, mask);
                } else {
                    TraceInfo(TRACE_NETADAPTER,
                              "receive coalescing: UDP port %u has no filter "
                              "in this firmware\n",
                              port);
                }
            }
            break;

        default:

            break;
        }
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetReceiveCoalescing(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_RECEIVE_COALESCING_PARAMETERS parameters;
    AP6256_RX_COALESCE_FILTER* slot;
    const ADD_RECEIVE_COALESCING_INFO* info;
    ULONG count;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetReceiveCoalescing(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    info = &parameters.AddReceiveCoalescing;
    count = info->Optional.ReceiveCoalescingField_IsPresent
                ? info->ReceiveCoalescingField.ElementCount
                : 0;

    if (count == 0 || info->ReceiveCoalescingField.pElements == NULL) {
        TraceWarn(TRACE_NETADAPTER, "receive coalescing filter %u has no field tests\n",
                  info->ReceivingCoalesingConfig.FilterId);
        CleanupParsedWdiSetReceiveCoalescing(&parameters);
        Ap6256CompleteRequest(Wifi, Request, STATUS_UNSUCCESSFUL);
        return;
    }

    slot = Ap6256FindCoalesceFilter(Wifi, 0, FALSE);
    if (slot == NULL) {
        TraceWarn(TRACE_NETADAPTER, "receive coalescing: all %u filter slots are in use\n",
                  AP6256_RX_COALESCE_FILTERS);
        CleanupParsedWdiSetReceiveCoalescing(&parameters);
        Ap6256CompleteRequest(Wifi, Request, STATUS_UNSUCCESSFUL);
        return;
    }

    slot->Fields = (WDI_RECEIVE_COALESCING_FIELD*)ExAllocatePool2(
        POOL_FLAG_NON_PAGED, count * sizeof(WDI_RECEIVE_COALESCING_FIELD), AP6256_POOL_TAG);
    if (slot->Fields == NULL) {
        CleanupParsedWdiSetReceiveCoalescing(&parameters);
        Ap6256CompleteRequest(Wifi, Request, STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    RtlCopyMemory(slot->Fields, info->ReceiveCoalescingField.pElements,
                  count * sizeof(WDI_RECEIVE_COALESCING_FIELD));
    slot->FieldCount = count;
    slot->FilterId = info->ReceivingCoalesingConfig.FilterId;

    if (info->ReceivingCoalesingConfig.MaxCoalescingDelay < Wifi->RxCoalesceMaxDelay) {
        Wifi->RxCoalesceMaxDelay = info->ReceivingCoalesingConfig.MaxCoalescingDelay;
        (VOID) Ap6256WifiSetD0FilterMaxDelay(Wifi->Ctx, Wifi->RxCoalesceMaxDelay);
    }

    TraceInfo(TRACE_NETADAPTER,
              "receive coalescing filter %u: %u field test(s), "
              "max delay %u ms\n",
              slot->FilterId, count, info->ReceivingCoalesingConfig.MaxCoalescingDelay);

    Ap6256ApplyCoalesceFilter(Wifi, slot, TRUE);

    CleanupParsedWdiSetReceiveCoalescing(&parameters);
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleClearReceiveCoalescing(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                   _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                                   _In_ ULONG TlvLength)
{
    WDI_SET_CLEAR_RECEIVE_COALESCING_PARAMETERS parameters;
    AP6256_RX_COALESCE_FILTER* slot;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetClearReceiveCoalescing(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status)) {
        slot = Ap6256FindCoalesceFilter(Wifi, parameters.FilterId, TRUE);
        if (slot == NULL) {
            TraceWarn(TRACE_NETADAPTER, "receive coalescing filter %u is not programmed\n",
                      parameters.FilterId);
            status = STATUS_UNSUCCESSFUL;
        } else {
            Ap6256ApplyCoalesceFilter(Wifi, slot, FALSE);
            ExFreePoolWithTag(slot->Fields, AP6256_POOL_TAG);
            RtlZeroMemory(slot, sizeof(*slot));
            TraceInfo(TRACE_NETADAPTER, "receive coalescing filter %u cleared\n",
                      parameters.FilterId);
        }
    }

    CleanupParsedWdiSetClearReceiveCoalescing(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetConnectionQuality(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_CONNECTION_QUALITY_PARAMETERS parameters;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetConnectionQuality(TlvLength, Tlv, &Wifi->TlvContext, &parameters));

    if (NT_SUCCESS(status)) {
        switch (parameters.Quality) {
        case WDI_CONNECTION_QUALITY_AUTO_POWER_SAVE:
            status = Ap6256WifiSetPowerSave(Wifi->Ctx, TRUE);
            break;

        case WDI_CONNECTION_QUALITY_NO_POWER_SAVE:
            status = Ap6256WifiSetPowerSave(Wifi->Ctx, FALSE);
            break;

        case WDI_CONNECTION_QUALITY_LOW_LATENCY:
            Wifi->RoamLinkQualityThresholdValid = FALSE;
            if (!parameters.Optional.LowLatencyParameters_IsPresent) {
                TraceWarn(TRACE_NETADAPTER, "connection quality LOW_LATENCY without the "
                                            "low-latency parameters\n");
                status = Ap6256NdisToNtStatus(NDIS_STATUS_INVALID_DATA);
                break;
            }
            Wifi->RoamLinkQualityThreshold =
                parameters.LowLatencyParameters.RoamingNeededLinkQualityThreshold;
            Wifi->RoamLinkQualityThresholdValid = TRUE;
            TraceInfo(TRACE_NETADAPTER,
                      "connection quality LOW_LATENCY: roam below link "
                      "quality %u, off-channel at most %u ms\n",
                      (ULONG)Wifi->RoamLinkQualityThreshold,
                      (ULONG)parameters.LowLatencyParameters.MaximumOffChannelOperationTime);
            break;

        default:
            TraceWarn(TRACE_NETADAPTER,
                      "connection quality hint %u is not one this radio "
                      "implements\n",
                      (ULONG)parameters.Quality);
            status = STATUS_NOT_SUPPORTED;
            break;
        }
    }

    CleanupParsedWdiSetConnectionQuality(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSetP2pWpsEnabled(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                             _In_ AP6256_REQUEST Request,
                             _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_P2P_WPS_ENABLED_PARAMETERS parameters;
    NTSTATUS status;
    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetP2pWpsEnabled(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (NT_SUCCESS(status)) {
        if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.FirmwareReady) {
            status = Ap6256WifiSetWpsEnabledIf(Wifi->Ctx, Wifi->Ctx->Go.IfIndex,
                                               (BOOLEAN)(parameters.WPSEnabled != 0));
            if (NT_SUCCESS(status))
                Wifi->Ctx->Go.WpsEnabled = (BOOLEAN)(parameters.WPSEnabled != 0);
        } else if (Header->PortId == AP6256_DISCOVERY_PORT && Wifi->Ctx->P2pBssValid) {
            status =
                Ap6256WifiP2pSetDiscoverySecurity(Wifi->Ctx, (BOOLEAN)(parameters.WPSEnabled != 0));
        } else
            status = STATUS_INVALID_DEVICE_STATE;
    }
    CleanupParsedWdiSetP2pWpsEnabled(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

static BOOLEAN Ap6256ApChannelRequested(const WDI_TASK_START_AP_PARAMETERS* P, UINT32 Channel)
{
    ULONG i, j;
    if (P->Optional.APBandChannelList_IsPresent) {
        for (i = 0; i < P->APBandChannelList.ElementCount; ++i) {
            const WDI_AP_BAND_CHANNEL_LIST_CONTAINER* band = &P->APBandChannelList.pElements[i];
            if (band->BandID != (Channel <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000))
                continue;
            if (!band->Optional.ChannelList_IsPresent)
                return TRUE;
            for (j = 0; j < band->ChannelList.ElementCount; ++j)
                if (band->ChannelList.pElements[j] == Channel)
                    return TRUE;
        }
        return FALSE;
    }
    return P->Optional.AdvertisedOperatingChannel_IsPresent &&
           P->AdvertisedOperatingChannel.ChannelNumber == Channel;
}

static NTSTATUS Ap6256SelectApChannel(PAP6256_WIFI Wifi, const WDI_TASK_START_AP_PARAMETERS* P,
                                      PULONG Channel)
{
    UINT32 valid[65] = {64}, station = 0, preferred = 0, candidate = 0;
    ULONG i;
    NTSTATUS status;
    if (P->Optional.APBandChannelList_IsPresent) {
        if (P->APBandChannelList.ElementCount == 0 || P->APBandChannelList.pElements == NULL)
            return STATUS_INVALID_PARAMETER;
        for (i = 0; i < P->APBandChannelList.ElementCount; ++i)
            if (P->APBandChannelList.pElements[i].Optional.ChannelList_IsPresent &&
                P->APBandChannelList.pElements[i].ChannelList.ElementCount != 0 &&
                P->APBandChannelList.pElements[i].ChannelList.pElements == NULL)
                return STATUS_INVALID_PARAMETER;
    }
    if (Wifi->Ctx->FirmwareLinkUp) {
        status = Ap6256WifiGetChannel(Wifi->Ctx, &station);
        if (!NT_SUCCESS(status))
            return status;
        if (station == 0)
            return STATUS_DEVICE_NOT_READY;
    }
    status = Ap6256BcdcQueryDcmd(Wifi->Ctx, BRCMF_C_GET_VALID_CHANNELS, valid, sizeof(valid));
    if (!NT_SUCCESS(status))
        return status;
    if (valid[0] > 64)
        return STATUS_INVALID_BUFFER_SIZE;
    if (P->Optional.AdvertisedOperatingChannel_IsPresent)
        preferred = P->AdvertisedOperatingChannel.ChannelNumber;
    for (i = 1; i <= valid[0]; ++i) {
        UINT32 ch = valid[i];
        BOOLEAN requested, candidateRequested;

        if (ch == 0 || ch > 165 || (ch >= 52 && ch <= 144) ||
            (station != 0 && station != ch && !Wifi->Ctx->FirmwareMchanSupported) ||
            Ap6256BandIsDisallowed(Wifi, ch <= 14 ? WDI_BAND_ID_2400 : WDI_BAND_ID_5000))
            continue;
        requested = Ap6256ApChannelRequested(P, ch);
        if (P->StaticParameters.MustUseSpecifiedChannels && !requested)
            continue;
        if (ch == preferred) {
            candidate = ch;
            break;
        }
        candidateRequested = Ap6256ApChannelRequested(P, candidate);
        if (candidate == 0 || (requested && !candidateRequested) ||
            (requested == candidateRequested && ch == station))
            candidate = ch;
    }
    if (candidate == 0)
        return STATUS_DEVICE_BUSY;
    *Channel = candidate;
    TraceDiag("hotspot: channel selection station %u advertised %u must-use %u bands %u -> %u\n",
              station, preferred, (ULONG)P->StaticParameters.MustUseSpecifiedChannels,
              P->Optional.APBandChannelList_IsPresent ? P->APBandChannelList.ElementCount : 0u,
              candidate);
    return STATUS_SUCCESS;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleStartAp(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                    _In_ PWDI_MESSAGE_HEADER Header, _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                    _In_ ULONG TlvLength)
{
    WDI_TASK_START_AP_PARAMETERS parameters;
    WDI_MESSAGE_HEADER completedHeader = *Header;
    AP6256_AP_PARAMS ap;
    NTSTATUS status;
    BOOLEAN modelEntered = FALSE;

    RtlZeroMemory(&parameters, sizeof(parameters));
    RtlZeroMemory(&ap, sizeof(ap));

    status = Ap6256ModelStartApBegin(Wifi);
    if (NT_SUCCESS(status)) {
        modelEntered = TRUE;
        status = Ap6256NdisToNtStatus(
            ParseWdiTaskStartAp(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    }

    if (NT_SUCCESS(status)) {
        if (parameters.DesiredSSID.ElementCount == 0 ||
            parameters.DesiredSSID.ElementCount > sizeof(ap.Ssid) ||
            parameters.DesiredSSID.pElements == NULL) {
            TraceError(TRACE_NETADAPTER, "start AP REFUSED: SSID of %u byte(s)\n",
                       parameters.DesiredSSID.ElementCount);
            status = STATUS_INVALID_PARAMETER;
        }
    }

    if (NT_SUCCESS(status)) {
        ap.SsidLength = parameters.DesiredSSID.ElementCount;
        RtlCopyMemory(ap.Ssid, parameters.DesiredSSID.pElements, ap.SsidLength);
        ap.BeaconPeriod = parameters.StaticParameters.BeaconPeriod;
        ap.DtimPeriod = parameters.StaticParameters.DTIMPeriod;
        ap.ExcludeUnencrypted = (BOOLEAN)(parameters.StaticParameters.ExcludeUnencrypted != 0);
        ap.RejectNonP2pClients = (BOOLEAN)(Wifi->TlvContext.PeerVersion >= WDI_VERSION_1_0_10 &&
                                           !parameters.StaticParameters.AcceptNonP2PClients);
        if (parameters.Optional.AdvertisedOperatingChannel_IsPresent) {
            ap.Channel = parameters.AdvertisedOperatingChannel.ChannelNumber;
        }

        if (parameters.AuthenticationAlgorithms.ElementCount != 1 ||
            parameters.UnicastCipherAlgorithms.ElementCount != 1 ||
            parameters.MulticastCipherAlgorithms.ElementCount != 1 ||
            parameters.AuthenticationAlgorithms.pElements == NULL ||
            parameters.UnicastCipherAlgorithms.pElements == NULL ||
            parameters.MulticastCipherAlgorithms.pElements == NULL) {
            status = STATUS_NOT_SUPPORTED;
        } else if (parameters.AuthenticationAlgorithms.pElements[0] == WDI_AUTH_ALGO_RSNA_PSK &&
                   parameters.UnicastCipherAlgorithms.pElements[0] == WDI_CIPHER_ALGO_CCMP &&
                   parameters.MulticastCipherAlgorithms.pElements[0] == WDI_CIPHER_ALGO_CCMP) {
            ap.Security = Ap6256SecurityWpa2Host;
        } else if (parameters.AuthenticationAlgorithms.pElements[0] == WDI_AUTH_ALGO_80211_OPEN &&
                   parameters.UnicastCipherAlgorithms.pElements[0] == WDI_CIPHER_ALGO_NONE &&
                   parameters.MulticastCipherAlgorithms.pElements[0] == WDI_CIPHER_ALGO_NONE) {
            ap.Security = Ap6256SecurityOpen;
        } else
            status = STATUS_NOT_SUPPORTED;

        if (NT_SUCCESS(status)) {
            if (Header->PortId != AP6256_GROUP_PORT || !Wifi->Ctx->Go.Created ||
                Wifi->Ctx->Go.Started || Wifi->Ctx->Go.Mode != AP6256_WDI_OPMODE_P2P_GO)
                status = STATUS_INVALID_DEVICE_STATE;
            else {
                status = Ap6256SelectApChannel(Wifi, &parameters, &ap.Channel);
                if (NT_SUCCESS(status)) {
                    status = Ap6256ModelStartApHardware(Wifi, &ap);
                }
            }

            status = Ap6256ModelStartApPeer(Wifi, status);
            if (NT_SUCCESS(status)) {
                Wifi->ApSecurity = ap.Security;
                Wifi->GoApParams = ap;
            }

            Ap6256ModelApStarted(Wifi, status);
            if (NT_SUCCESS(status)) {
                Ap6256IndicateP2pGroupChannel(Wifi, Header, Ap6256RequestGetId(Request),
                                              ap.Channel);
                Wifi->ApStarted = TRUE;
            }
        }
    }

    TraceDiag("hotspot: START_AP port %u channel %u -> 0x%08X\n", (ULONG)completedHeader.PortId,
              ap.Channel, status);
    CleanupParsedWdiTaskStartAp(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
    {
        NTSTATUS completionStatus =
            Ap6256SendIndication(Wifi, WDI_INDICATION_START_AP_COMPLETE, &completedHeader,
                                completedHeader.TransactionId, status, NULL, 0);
        Ap6256ModelStartApCompleted(Wifi, status, completionStatus);
    }
    if (modelEntered) Ap6256ModelStartApEnd(Wifi);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID Ap6256HandleStopAp(_In_ PAP6256_WIFI Wifi,
                                                                  _In_ AP6256_REQUEST Request,
                                                                  _In_ PWDI_MESSAGE_HEADER Header)
{
    WDI_MESSAGE_HEADER completedHeader = *Header;
    NTSTATUS status =
        Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO
            ? Ap6256GoStop(Wifi->Ctx)
            : STATUS_INVALID_DEVICE_STATE;

    Ap6256ModelStopApPeers(Wifi, status);
    if (NT_SUCCESS(status))
        Wifi->ApStarted = FALSE;
    Ap6256CompleteRequest(Wifi, Request, status);
    (VOID) Ap6256SendIndication(Wifi, WDI_INDICATION_STOP_AP_COMPLETE, &completedHeader,
                                completedHeader.TransactionId, status, NULL, 0);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
LONGLONG Ap6256InterruptTimeMs(VOID)
{
    return (LONGLONG)(KeQueryInterruptTime() / 10000ull);
}

_IRQL_requires_max_(DISPATCH_LEVEL)
VOID Ap6256FreeActionFrame(_In_ PAP6256_WIFI Wifi)
{
    if (Wifi->ActionFrameBody != NULL) {
        ExFreePoolWithTag(Wifi->ActionFrameBody, AP6256_POOL_TAG);
        Wifi->ActionFrameBody = NULL;
    }
    Wifi->ActionFrameBodyLength = 0;
    Wifi->ActionFrameAcked = FALSE;
    Wifi->ActionFrameDwellDeadline = 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static NTSTATUS
Ap6256SendPendingActionFrame(_In_ PAP6256_WIFI Wifi)
{
    NTSTATUS status;
    UINT32 ifIndex;
    if (Wifi->ActionFrameBody == NULL)
        return STATUS_INVALID_DEVICE_STATE;
    status = Ap6256ActionFrameInterface(Wifi, Wifi->ActionFrameTask.Header.PortId, &ifIndex);
    if (!NT_SUCCESS(status) || ifIndex != Wifi->ActionFrameIfIndex)
        return STATUS_INVALID_DEVICE_STATE;
    status = Ap6256QuiesceP2pListen(Wifi);
    if (!NT_SUCCESS(status))
        return status;

    return Ap6256WifiSendActionFrame(Wifi->Ctx, Wifi->ActionFrameIfIndex, Wifi->ActionFrameChannel,
                                     Wifi->ActionFrameDwellMs, Wifi->ActionFrameBssid,
                                     Wifi->ActionFrameDest, Wifi->ActionFramePendingId,
                                     Wifi->ActionFrameBody, Wifi->ActionFrameBodyLength);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static BOOLEAN
Ap6256ClaimActionFrameLocked(_In_ PAP6256_WIFI Wifi, _In_ BOOLEAN AbortOffChannel,
                             _Out_ PAP6256_ACTION_FRAME_COMPLETION Done)
{
    RtlZeroMemory(Done, sizeof(*Done));
    if (!Ap6256ClaimTask(Wifi, &Wifi->ActionFrameTask, &Done->Header, &Done->RequestId)) {
        return FALSE;
    }

    Done->CompletionId = Wifi->ActionFrameCompleteId;
    Done->PacketId = Wifi->ActionFramePendingId;
    RtlCopyMemory(Done->Destination, Wifi->ActionFrameDest, 6);
    AP6256_TIMER_STOP(Wifi->ActionFrameTimer, FALSE);
    if (AbortOffChannel && Wifi->ActionFrameBody != NULL) {
        (VOID) Ap6256WifiAbortOffChannel(Wifi->Ctx);
    }
    Done->Body = Wifi->ActionFrameBody;
    Done->BodyLength = Wifi->ActionFrameBodyLength;
    Wifi->ActionFrameBody = NULL;
    Wifi->ActionFrameBodyLength = 0;
    Wifi->ActionFrameAcked = FALSE;
    Wifi->ActionFrameDwellDeadline = 0;
    return TRUE;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
VOID Ap6256CancelActionFrame(_In_ PAP6256_WIFI Wifi,
                                                                _In_ NTSTATUS Status)
{
    AP6256_ACTION_FRAME_COMPLETION done;
    BOOLEAN claimed;
    AP6256_TIMER_STOP(Wifi->ActionFrameTimer, TRUE);
    Ap6256LockAcquire(&Wifi->ActionFrameLock);
    claimed = Ap6256ClaimActionFrameLocked(Wifi, TRUE, &done);
    Ap6256LockRelease(&Wifi->ActionFrameLock);
    if (claimed)
        Ap6256IndicateActionFrameDone(Wifi, &done, Status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256IndicateActionFrameDone(_In_ PAP6256_WIFI Wifi, _Inout_ PAP6256_ACTION_FRAME_COMPLETION Done,
                              _In_ NTSTATUS Status)
{
    WDI_INDICATION_P2P_SEND_REQUEST_ACTION_FRAME_COMPLETE_PARAMETERS request;
    WDI_INDICATION_P2P_SEND_RESPONSE_ACTION_FRAME_COMPLETE_PARAMETERS response;
    WDI_P2P_SEND_ACTION_FRAME_RESULT_CONTAINER* result;
    WDI_P2P_ACTION_FRAME_TYPE type;
    UINT8* generated = NULL;
    ULONG generatedLength = 0;
    NTSTATUS deliveryStatus;
    BOOLEAN isRequest =
        (BOOLEAN)(Done->CompletionId == WDI_INDICATION_P2P_SEND_REQUEST_ACTION_FRAME_COMPLETE);
    BOOLEAN isResponse =
        (BOOLEAN)(Done->CompletionId == WDI_INDICATION_P2P_SEND_RESPONSE_ACTION_FRAME_COMPLETE);

    if (NT_SUCCESS(Status) && (isRequest || isResponse)) {
        if (Done->Body == NULL || !Ap6256P2pActionFrameType(Done->Body, Done->BodyLength, &type)) {
            Status = STATUS_INVALID_DEVICE_STATE;
        } else {
            RtlZeroMemory(&request, sizeof(request));
            RtlZeroMemory(&response, sizeof(response));
            result = isRequest ? &request.SendActionFrameResult : &response.SendActionFrameResult;
            RtlCopyMemory(result->FrameParameters.PeerDeviceAddress.Address, Done->Destination, 6);
            result->FrameParameters.DialogToken = Done->Body[7];
            result->FrameIEs.pElements = Done->Body + AP6256_P2P_ACTION_HEADER;
            result->FrameIEs.ElementCount = Done->BodyLength - AP6256_P2P_ACTION_HEADER;
            Status = Ap6256NdisToNtStatus(
                isRequest ? GenerateWdiIndicationP2pSendRequestActionFrameComplete(
                                &request, 0, &Wifi->TlvContext, &generatedLength, &generated)
                          : GenerateWdiIndicationP2pSendResponseActionFrameComplete(
                                &response, 0, &Wifi->TlvContext, &generatedLength, &generated));
            if (NT_SUCCESS(Status) && (generated == NULL || generatedLength == 0))
                Status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    deliveryStatus = Ap6256SendIndicationRq(
        Wifi, Done->CompletionId, &Done->Header, Done->Header.TransactionId, Done->RequestId,
        Status, NT_SUCCESS(Status) ? generated : NULL, NT_SUCCESS(Status) ? generatedLength : 0);
    TraceDiag("action frame complete: id %u txn %u port %u indication %u status 0x%08X, %u TLV "
              "bytes -> 0x%08X\n",
              Done->PacketId, Done->Header.TransactionId, (ULONG)Done->Header.PortId,
              (ULONG)Done->CompletionId, Status, NT_SUCCESS(Status) ? generatedLength : 0,
              deliveryStatus);
    FreeGenerated(generated);
    if (Done->Body != NULL)
        ExFreePoolWithTag(Done->Body, AP6256_POOL_TAG);
    Done->Body = NULL;
    Done->BodyLength = 0;
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleSendActionFrame(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                            _In_ UINT16 MessageId, _In_ PWDI_MESSAGE_HEADER Header,
                            _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_SEND_REQUEST_ACTION_FRAME_PARAMETERS parameters;
    NTSTATUS status;
    UCHAR bssid[6];
    UINT32 ifIndex = 0;
    BOOLEAN isRequest = (BOOLEAN)(MessageId == WDI_TASK_SEND_REQUEST_ACTION_FRAME);
    BOOLEAN taskBegun = FALSE;
    BOOLEAN claimed = FALSE;
    ULONG frameCapacity = 0;
    AP6256_ACTION_FRAME_COMPLETION done;
    UINT16 completionId = isRequest ? WDI_INDICATION_SEND_REQUEST_ACTION_FRAME_COMPLETE
                                    : WDI_INDICATION_SEND_RESPONSE_ACTION_FRAME_COMPLETE;

    RtlZeroMemory(&parameters, sizeof(parameters));

    status = Ap6256NdisToNtStatus(
        isRequest
            ? ParseWdiTaskSendRequestActionFrame(TlvLength, Tlv, &Wifi->TlvContext, &parameters)
            : ParseWdiTaskSendResponseActionFrame(
                  TlvLength, Tlv, &Wifi->TlvContext,
                  (WDI_TASK_SEND_RESPONSE_ACTION_FRAME_PARAMETERS*)&parameters));

    if (NT_SUCCESS(status) && (parameters.ActionFrameBody.pElements == NULL ||
                               parameters.ActionFrameBody.ElementCount == 0 ||
                               parameters.ActionFrameBody.ElementCount > MAXULONG - 9u)) {
        status = STATUS_INVALID_PARAMETER;
    }

    Ap6256LockAcquire(&Wifi->ActionFrameLock);

    if (NT_SUCCESS(status) && Header->PortId == AP6256_STATION_PORT &&
        Ap6256OwnsManagementFrame(Wifi->Ctx, parameters.ActionFrameBody.pElements,
                                    parameters.ActionFrameBody.ElementCount, TRUE)) {
        status = STATUS_NOT_SUPPORTED;
    }
    if (NT_SUCCESS(status) && Wifi->ActionFrameTask.Active) {

        TraceWarn(TRACE_NETADAPTER, "action frame REFUSED: one is already in flight\n");
        status = STATUS_DEVICE_BUSY;
    }

    if (NT_SUCCESS(status)) {
        status = Ap6256ActionFrameInterface(Wifi, Header->PortId, &ifIndex);
    }

    if (NT_SUCCESS(status)) {
        status = Ap6256BeginTask(Wifi, &Wifi->ActionFrameTask, Header, Ap6256RequestGetId(Request));
        taskBegun = (BOOLEAN)NT_SUCCESS(status);
    }

    if (NT_SUCCESS(status)) {

        if (Header->PortId == AP6256_STATION_PORT && Wifi->ConnectBssidValid) {
            RtlCopyMemory(bssid, Wifi->ConnectBssid, sizeof(bssid));
        } else if (Header->PortId == AP6256_GROUP_PORT &&
                   Wifi->Ctx->Go.Mode == AP6256_WDI_OPMODE_P2P_GO) {
            RtlCopyMemory(bssid, Wifi->Ctx->Go.Address, sizeof(bssid));
        } else if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.ClientConnected) {
            RtlCopyMemory(bssid, Wifi->Ctx->Go.ClientBssid, sizeof(bssid));
        } else {
            RtlCopyMemory(bssid, parameters.RequestParams.DestinationAddress.Address,
                          sizeof(bssid));
        }

        Ap6256FreeActionFrame(Wifi);
        frameCapacity = parameters.ActionFrameBody.ElementCount + 9u;
        Wifi->ActionFrameBody = (PUCHAR)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, frameCapacity, AP6256_POOL_TAG);
        if (Wifi->ActionFrameBody == NULL) {
            status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            RtlCopyMemory(Wifi->ActionFrameBody, parameters.ActionFrameBody.pElements,
                          parameters.ActionFrameBody.ElementCount);
            Wifi->ActionFrameBodyLength = parameters.ActionFrameBody.ElementCount;
            if (Header->PortId == AP6256_STATION_PORT)
                status = Ap6256MboExtendResponse(Wifi,
                    parameters.RequestParams.DestinationAddress.Address, Wifi->ActionFrameBody,
                    frameCapacity, &Wifi->ActionFrameBodyLength);
            RtlCopyMemory(Wifi->ActionFrameBssid, bssid, sizeof(bssid));
            RtlCopyMemory(Wifi->ActionFrameDest,
                          parameters.RequestParams.DestinationAddress.Address,
                          sizeof(Wifi->ActionFrameDest));
            Wifi->ActionFrameChannel = (UINT32)parameters.RequestParams.ChannelNumber;
            Wifi->ActionFrameIfIndex = ifIndex;
            Wifi->ActionFrameDwellMs = parameters.RequestParams.PostACKDwellTime;
            Wifi->ActionFrameCompleteId = completionId;
            Wifi->ActionFramePendingId = (UINT32)InterlockedIncrement(&Wifi->ActionFramePacketId);

            Wifi->ActionFrameRetryMs = parameters.RequestParams.PostACKDwellTime != 0
                                           ? parameters.RequestParams.PostACKDwellTime
                                           : AP6256_ACTION_FRAME_DEFAULT_DWELL_MS;
            Wifi->ActionFrameDeadline =
                Ap6256InterruptTimeMs() + (parameters.RequestParams.SendTimeout != 0
                                               ? parameters.RequestParams.SendTimeout
                                               : AP6256_ACTION_FRAME_DEFAULT_TIMEOUT_MS);

            if (NT_SUCCESS(status)) status = Ap6256SendPendingActionFrame(Wifi);
        }
    }

    if (NT_SUCCESS(status)) {

        AP6256_TIMER_START(Wifi->ActionFrameTimer, Wifi->ActionFrameRetryMs);
    } else if (taskBegun) {

        claimed = Ap6256ClaimActionFrameLocked(Wifi, FALSE, &done);
    }

    Ap6256LockRelease(&Wifi->ActionFrameLock);

    if (isRequest) {
        CleanupParsedWdiTaskSendRequestActionFrame(&parameters);
    } else {
        CleanupParsedWdiTaskSendResponseActionFrame(
            (WDI_TASK_SEND_RESPONSE_ACTION_FRAME_PARAMETERS*)&parameters);
    }

    Ap6256CompleteRequest(Wifi, Request, status);

    if (claimed) {
        done.CompletionId = completionId;
        Ap6256IndicateActionFrameDone(Wifi, &done, status);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleChangeOperationMode(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                                _In_ PWDI_MESSAGE_HEADER Header,
                                _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_CHANGE_OPERATION_MODE_PARAMETERS parameters;
    WDI_MESSAGE_HEADER completedHeader = *Header;
    NTSTATUS status;
    UINT32 wdiMode = 0;
    UINT32 previousGroupMode = Wifi->Ctx->Go.Mode;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskChangeOperationMode(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (NT_SUCCESS(status)) {
        wdiMode = (UINT32)parameters.OperationMode;
        if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.Created) {
            status = Ap6256ModelChangeGroupMode(Wifi, wdiMode);
        } else if (Header->PortId == AP6256_DISCOVERY_PORT && Wifi->P2pPortCreated) {
            status =
                wdiMode == AP6256_WDI_OPMODE_P2P_DEVICE ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
        } else if (Header->PortId == AP6256_STATION_PORT && wdiMode == AP6256_WDI_OPMODE_STA) {
            status = STATUS_SUCCESS;
        } else
            status = STATUS_NOT_SUPPORTED;
    }
    if (NT_SUCCESS(status)) {

        TraceInfo(TRACE_NETADAPTER, "port %u operation mode 0x%02X -> 0x%02X\n",
                  (ULONG)completedHeader.PortId, Wifi->PortOperationMode, wdiMode);
        if (completedHeader.PortId == AP6256_GROUP_PORT) {
            Wifi->Ctx->Go.Mode = wdiMode;
        } else if (Wifi->P2pPortCreated && completedHeader.PortId == Wifi->P2pPortNumber) {
            Wifi->P2pPortMode = wdiMode;
        } else {
            Wifi->StationPortMode = wdiMode;
        }
        Ap6256RecomputePortModes(Wifi);
    } else {
        TraceWarn(TRACE_NETADAPTER, "operation mode 0x%02X REFUSED 0x%08X\n", wdiMode, status);
    }
    CleanupParsedWdiTaskChangeOperationMode(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
    if (NT_SUCCESS(status)) {

        NTSTATUS deliveryStatus = Ap6256SendIndication(
            Wifi, WDI_INDICATION_CHANGE_OPERATION_MODE_COMPLETE,
            &completedHeader, completedHeader.TransactionId, STATUS_SUCCESS, NULL, 0);
        if (completedHeader.PortId == AP6256_GROUP_PORT)
            Ap6256ModelChangeGroupModeCompleted(Wifi, previousGroupMode, deliveryStatus);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleResetRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request,
                         _In_ PWDI_MESSAGE_HEADER Header,
                         _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_TASK_DOT11_RESET_PARAMETERS parameters;
    NTSTATUS status;

    WDI_MESSAGE_HEADER completedHeader = *Header;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiTaskDot11Reset(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (NT_SUCCESS(status) && parameters.Optional.ResetMloLinkMACAddresses_IsPresent) {
        status = STATUS_NOT_SUPPORTED;
    }
    if (NT_SUCCESS(status) && Header->PortId != AP6256_STATION_PORT) {
        if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.Created) {
            UINT32 ifIndex = Wifi->Ctx->Go.IfIndex;

            status = Ap6256ModelResetGroup(Wifi);

            Ap6256ModelResetGroupPeers(Wifi);
            Wifi->ApStarted = FALSE;
            if (NT_SUCCESS(status)) {
                InterlockedExchange(&Wifi->Ctx->Go.PacketFilter, 0);
                Ap6256P2pReleaseIesFor(Wifi->Ctx, &Wifi->Ctx->Go.P2p, Wifi->Ctx->Go.IfIndex);
                if (parameters.Dot11ResetParameters.SetDefaultMIB) {
                    Wifi->Ctx->Go.WpsEnabled = FALSE;
                    Wifi->Ctx->Go.P2p.AssocStatus = 0;
                    if (ifIndex && ifIndex < AP6256_HC_INTERFACES)
                        status = Ap6256HostCipherSetRxExemptions(Wifi->Ctx, ifIndex, NULL, 0);
                }
            }
            if (NT_SUCCESS(status) && parameters.Optional.ResetMACAddress_IsPresent) {
                if (!Ap6256MacIsValidUnicast(parameters.ResetMACAddress.Address) ||
                    RtlEqualMemory(parameters.ResetMACAddress.Address, Wifi->Ctx->MacAddress, 6) ||
                    RtlEqualMemory(parameters.ResetMACAddress.Address, Wifi->Ctx->P2p.DeviceAddress,
                                   6))
                    status = STATUS_INVALID_PARAMETER;
                else {
                    status = Ap6256ModelResetGroupAddress(Wifi,
                                                          parameters.ResetMACAddress.Address);
                }
            }
        } else if (Header->PortId == AP6256_DISCOVERY_PORT && Wifi->P2pPortCreated) {

            if (parameters.Optional.ResetMACAddress_IsPresent &&
                !RtlEqualMemory(parameters.ResetMACAddress.Address, Wifi->Ctx->P2p.DeviceAddress,
                                6)) {
                status = STATUS_NOT_SUPPORTED;
            } else {
                Wifi->P2pDiscovering = FALSE;
                AP6256_TIMER_STOP(Wifi->P2pDiscoverTimer, TRUE);
                AP6256_TIMER_STOP(Wifi->P2pListenTimer, TRUE);
                Ap6256LockAcquire(&Wifi->P2pLock);
                AP6256_TIMER_STOP(Wifi->P2pListenTimer, FALSE);
                Ap6256P2pStopDiscovery(Wifi->Ctx);
                Ap6256ServiceStop(Wifi, TRUE);
                Ap6256FailStartedTask(Wifi, &Wifi->P2pDiscoverTask,
                                      WDI_INDICATION_P2P_DISCOVERY_COMPLETE, STATUS_CANCELLED);
                status = Ap6256P2pResetDiscovery(Wifi->Ctx,
                                                 parameters.Dot11ResetParameters.SetDefaultMIB);
                Ap6256LockRelease(&Wifi->P2pLock);
            }
        } else
            status = STATUS_NOT_FOUND;
        CleanupParsedWdiTaskDot11Reset(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        if (NT_SUCCESS(status))
            (VOID) Ap6256SendIndication(Wifi, WDI_INDICATION_DOT11_RESET_COMPLETE, &completedHeader,
                                        completedHeader.TransactionId, status, NULL, 0);
        return;
    }
    if (NT_SUCCESS(status) && Wifi->Ctx->FirmwareLinkUp) {
        TraceDiag("Windows reset the port while connected; disconnecting\n");
        status = Ap6256WifiDisconnect(Wifi->Ctx);
    }
    if (NT_SUCCESS(status)) {

        status = Ap6256WifiSetMulticastList(Wifi->Ctx, NULL, 0);
    }
    if (NT_SUCCESS(status) && parameters.Dot11ResetParameters.SetDefaultMIB) {
        status = Ap6256WifiResetMib(Wifi->Ctx);
        if (NT_SUCCESS(status)) status = Ap6256HostCipherSetRxExemptions(Wifi->Ctx, 0, NULL, 0);
    }
    if (NT_SUCCESS(status) && parameters.Optional.ResetMACAddress_IsPresent) {
        if (!Ap6256MacIsValidUnicast(parameters.ResetMACAddress.Address)) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            status = Ap6256WifiSetMacAddress(Wifi->Ctx, parameters.ResetMACAddress.Address);
            if (NT_SUCCESS(status)) {
                RtlCopyMemory(Wifi->Ctx->ConfiguredMacAddress, parameters.ResetMACAddress.Address,
                              sizeof(Wifi->Ctx->ConfiguredMacAddress));
                Wifi->Ctx->ConfiguredMacAddressValid = TRUE;
                RtlCopyMemory(Wifi->Ctx->MacAddress, parameters.ResetMACAddress.Address,
                              sizeof(Wifi->Ctx->MacAddress));
                Ap6256NetSetMacAddress(Wifi->Ctx);
            }
        }
    }
    if (NT_SUCCESS(status)) {
        Ap6256FlushSoftwareQueues(Wifi);
    }
    CleanupParsedWdiTaskDot11Reset(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
    if (NT_SUCCESS(status)) {
        Ap6256NetLinkChange(Wifi->Ctx, FALSE);
        (VOID) Ap6256SendIndication(Wifi, WDI_INDICATION_DOT11_RESET_COMPLETE, &completedHeader,
                                    completedHeader.TransactionId, STATUS_SUCCESS, NULL, 0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandlePortRequest(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ UINT16 MessageId,
                        _In_ PWDI_MESSAGE_HEADER Header,
                        _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    NTSTATUS status;
    WDI_MESSAGE_HEADER completedHeader = *Header;
    if (MessageId == WDI_TASK_CREATE_PORT) {
        WDI_TASK_CREATE_PORT_PARAMETERS parameters;
        WDI_INDICATION_CREATE_PORT_COMPLETE_PARAMETERS completion;
        PUCHAR generated = NULL;
        ULONG generatedLength = 0;
        UINT32 mode;
        BOOLEAN made = FALSE;
        RtlZeroMemory(&parameters, sizeof(parameters));
        RtlZeroMemory(&completion, sizeof(completion));
        status = Ap6256NdisToNtStatus(
            ParseWdiTaskCreatePort(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
        mode = (UINT32)parameters.CreatePortParameters.OpModeMask;
        if (NT_SUCCESS(status) && parameters.Optional.MacAddress_IsPresent &&
            (mode == AP6256_WDI_OPMODE_STA || mode == AP6256_WDI_OPMODE_P2P_DEVICE) &&
            !RtlEqualMemory(parameters.MacAddress.Address,
                            mode == AP6256_WDI_OPMODE_STA ? Wifi->Ctx->MacAddress
                                                          : Wifi->Ctx->P2p.DeviceAddress,
                            6))
            status = STATUS_NOT_SUPPORTED;
        if (NT_SUCCESS(status)) {
            if (mode == AP6256_WDI_OPMODE_STA) {
                if (Wifi->PortCreated)
                    status = STATUS_OBJECT_NAME_COLLISION;
                else {
                    Wifi->PortCreated = TRUE;
                    Wifi->PortNumber = AP6256_STATION_PORT;
                    Wifi->StationPortMode = mode;
                    completion.PortAttributes.PortNumber = AP6256_STATION_PORT;
                    RtlCopyMemory(completion.PortAttributes.MacAddress.Address,
                                  Wifi->Ctx->MacAddress, 6);
                    made = TRUE;
                }
            } else if (!Wifi->Ctx->FirmwareP2pSupported)
                status = STATUS_NOT_SUPPORTED;
            else if (mode == AP6256_WDI_OPMODE_P2P_DEVICE) {
                if (Wifi->P2pPortCreated)
                    status = STATUS_OBJECT_NAME_COLLISION;
                else {
                    status = Ap6256WifiP2pSetDiscoveryInterface(Wifi->Ctx, TRUE, NULL);
                    if (NT_SUCCESS(status)) {
                        Wifi->P2pPortCreated = TRUE;
                        Wifi->P2pPortNumber = AP6256_DISCOVERY_PORT;
                        Wifi->P2pPortMode = mode;
                        RtlCopyMemory(Wifi->P2pPortAddress, Wifi->Ctx->P2p.DeviceAddress, 6);
                        completion.PortAttributes.PortNumber = AP6256_DISCOVERY_PORT;
                        RtlCopyMemory(completion.PortAttributes.MacAddress.Address,
                                      Wifi->P2pPortAddress, 6);
                        made = TRUE;
                    }
                }
            } else if ((mode & (AP6256_WDI_OPMODE_P2P_GO | AP6256_WDI_OPMODE_P2P_CLIENT)) &&
                       !(mode & ~(AP6256_WDI_OPMODE_P2P_GO | AP6256_WDI_OPMODE_P2P_CLIENT))) {
                if (Wifi->Ctx->Go.Created)
                    status = STATUS_OBJECT_NAME_COLLISION;
                else {
                    RtlCopyMemory(Wifi->Ctx->Go.Address, Wifi->Ctx->P2p.DeviceAddress, 6);
                    Wifi->Ctx->Go.Address[0] |= 2;
                    Wifi->Ctx->Go.Address[5] ^=
                        0x80;
                    if (parameters.Optional.MacAddress_IsPresent) {
                        if (!Ap6256MacIsValidUnicast(parameters.MacAddress.Address) ||
                            RtlEqualMemory(parameters.MacAddress.Address, Wifi->Ctx->MacAddress,
                                           6) ||
                            RtlEqualMemory(parameters.MacAddress.Address,
                                           Wifi->Ctx->P2p.DeviceAddress, 6))
                            status = STATUS_INVALID_PARAMETER;
                        else
                            RtlCopyMemory(Wifi->Ctx->Go.Address, parameters.MacAddress.Address, 6);
                    }
                    if (NT_SUCCESS(status)) {
                        Wifi->Ctx->Go.P2p = Wifi->Ctx->P2p;
                        RtlZeroMemory(Wifi->Ctx->Go.P2p.DriverIes,
                                      sizeof(Wifi->Ctx->Go.P2p.DriverIes));
                        RtlZeroMemory(Wifi->Ctx->Go.P2p.HostIes, sizeof(Wifi->Ctx->Go.P2p.HostIes));
                        Wifi->Ctx->Go.Mode = (mode & AP6256_WDI_OPMODE_P2P_GO)
                                                 ? AP6256_WDI_OPMODE_P2P_GO
                                                 : AP6256_WDI_OPMODE_P2P_CLIENT;
                        status = Ap6256GoCreate(Wifi->Ctx);
                    }
                    if (NT_SUCCESS(status)) {
                        Wifi->Ctx->Go.Created = TRUE;
                        completion.PortAttributes.PortNumber = AP6256_GROUP_PORT;
                        RtlCopyMemory(completion.PortAttributes.MacAddress.Address,
                                      Wifi->Ctx->Go.Address, 6);
                        made = TRUE;
                    }
                }
            } else
                status = STATUS_NOT_SUPPORTED;
        }
        if (NT_SUCCESS(status)) {
            status = Ap6256NdisToNtStatus(GenerateWdiIndicationCreatePortComplete(
                &completion, 0, &Wifi->TlvContext, &generatedLength, &generated));
            if (NT_SUCCESS(status) && generated == NULL)
                status = STATUS_INSUFFICIENT_RESOURCES;
        }
        if (!NT_SUCCESS(status) && made) {
            switch (completion.PortAttributes.PortNumber) {
            case AP6256_GROUP_PORT:
                (VOID) Ap6256GoDelete(Wifi->Ctx);
                Wifi->Ctx->Go.Created = FALSE;
                break;
            case AP6256_DISCOVERY_PORT:
                (VOID) Ap6256WifiP2pSetDiscoveryInterface(Wifi->Ctx, FALSE, NULL);
                Wifi->P2pPortCreated = FALSE;
                break;
            default:
                Wifi->PortCreated = FALSE;
                break;
            }
        }
        Ap6256RecomputePortModes(Wifi);
        TraceDiag("hotspot: create port mode 0x%X port %u -> 0x%08X\n", mode,
                  completion.PortAttributes.PortNumber, status);
        CleanupParsedWdiTaskCreatePort(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        if (NT_SUCCESS(status))
            (VOID) Ap6256SendGeneratedIndication(Wifi, WDI_INDICATION_CREATE_PORT_COMPLETE,
                                                 &completedHeader, completedHeader.TransactionId,
                                                 NULL, generated, generatedLength);
        FreeGenerated(generated);
        if (NT_SUCCESS(status) &&
            (mode == AP6256_WDI_OPMODE_STA || mode == AP6256_WDI_OPMODE_P2P_DEVICE))
            Ap6256IndicateP2pChannels(Wifi);
    } else {
        WDI_TASK_DELETE_PORT_PARAMETERS parameters;
        UINT16 port;
        RtlZeroMemory(&parameters, sizeof(parameters));
        status = Ap6256NdisToNtStatus(
            ParseWdiTaskDeletePort(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
        port = (UINT16)parameters.DeletePortParameters.PortNumber;
        if (NT_SUCCESS(status)) {
            if (port == AP6256_GROUP_PORT && Wifi->Ctx->Go.Created) {

                Ap6256ModelDeleteGroup(Wifi);
                Ap6256P2pReleaseIesFor(Wifi->Ctx, &Wifi->Ctx->Go.P2p, Wifi->Ctx->Go.IfIndex);
                status = Ap6256GoDelete(Wifi->Ctx);
                if (NT_SUCCESS(status)) {
                    Wifi->Ctx->Go.Created = FALSE;
                    Wifi->ApStarted = FALSE;
                }
            } else if (port == AP6256_DISCOVERY_PORT && Wifi->P2pPortCreated) {
                AP6256_TIMER_STOP(Wifi->P2pListenTimer, TRUE);
                AP6256_TIMER_STOP(Wifi->P2pDiscoverTimer, TRUE);
                Ap6256LockAcquire(&Wifi->P2pLock);
                Wifi->Ctx->P2p.Listening = FALSE;
                Wifi->P2pDiscovering = FALSE;
                AP6256_TIMER_STOP(Wifi->P2pListenTimer, FALSE);
                Ap6256P2pStopDiscovery(Wifi->Ctx);
                Ap6256ServiceStop(Wifi, TRUE);
                Ap6256FailStartedTask(Wifi, &Wifi->P2pDiscoverTask,
                                      WDI_INDICATION_P2P_DISCOVERY_COMPLETE, STATUS_CANCELLED);
                status = Ap6256WifiP2pSetDiscoveryInterface(Wifi->Ctx, FALSE, NULL);
                Ap6256LockRelease(&Wifi->P2pLock);
                if (NT_SUCCESS(status)) {
                    Wifi->P2pPortCreated = FALSE;
                    Wifi->P2pPortMode = 0;
                }
            } else if (port == AP6256_STATION_PORT && Wifi->PortCreated) {
                Wifi->PortCreated = FALSE;
                Wifi->StationPortMode = 0;
            } else
                status = STATUS_NOT_FOUND;
        }
        Ap6256RecomputePortModes(Wifi);
        CleanupParsedWdiTaskDeletePort(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        if (NT_SUCCESS(status))
            (VOID) Ap6256SendIndication(Wifi, WDI_INDICATION_DELETE_PORT_COMPLETE, &completedHeader,
                                        completedHeader.TransactionId, status, NULL, 0);
    }
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandlePrivacyExemptionList(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                                 _In_ AP6256_REQUEST Request,
                                 _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_PRIVACY_EXEMPTION_LIST_PARAMETERS parameters;
    UINT32 ifIndex;
    NTSTATUS status;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetPrivacyExemptionList(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    status = Ap6256CommandInterface(Wifi, Header, &ifIndex);
    if (!NT_SUCCESS(status)) {
        CleanupParsedWdiSetPrivacyExemptionList(&parameters);
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    {
        AP6256_EXEMPT_ENTRY entries[AP6256_EXEMPT_MAX];
        AP6256_HC_RX_EXEMPT hostEntries[AP6256_HC_RX_EXEMPT_MAX];
        ULONG count = 0;
        ULONG skipped = 0;
        ULONG index;
        ULONG supplied = parameters.Optional.PrivacyExemptionEntry_IsPresent
                             ? parameters.PrivacyExemptionEntry.ElementCount
                             : 0;

        if (supplied > AP6256_HC_RX_EXEMPT_MAX ||
            (supplied && !parameters.PrivacyExemptionEntry.pElements)) {
            status = STATUS_INVALID_PARAMETER;
            goto PrivacyComplete;
        }
        for (index = 0; index < supplied; ++index) {
            const WDI_PRIVACY_EXEMPTION_LIST_CONTAINER* entry =
                &parameters.PrivacyExemptionEntry.pElements[index];
            if (entry->ExemptionActionType < WDI_EXEMPT_NO_EXEMPTION ||
                entry->ExemptionActionType > WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE ||
                entry->ExemptionPacketType < WDI_EXEMPT_PACKET_TYPE_UNICAST ||
                entry->ExemptionPacketType > WDI_EXEMPT_PACKET_TYPE_BOTH) {
                status = STATUS_INVALID_PARAMETER;
                goto PrivacyComplete;
            }
            hostEntries[index].EtherType = entry->EtherType;
            hostEntries[index].Action = (UCHAR)entry->ExemptionActionType;
            hostEntries[index].PacketType = (UCHAR)entry->ExemptionPacketType;
        }

        for (index = 0; index < supplied && count < AP6256_EXEMPT_MAX; index++) {
            const WDI_PRIVACY_EXEMPTION_LIST_CONTAINER* entry =
                &parameters.PrivacyExemptionEntry.pElements[index];
            UINT16 action;
            UINT16 packet;

            switch (entry->ExemptionActionType) {
            case WDI_EXEMPT_ALWAYS:
                action = (UINT16)AP6256_EXEMPT_ACTION_ALWAYS;
                break;
            case WDI_EXEMPT_ON_KEY_MAPPING_KEY_UNAVAILABLE:
                action = (UINT16)AP6256_EXEMPT_ACTION_ON_NO_KEY;
                break;
            default:

                skipped++;
                continue;
            }

            switch (entry->ExemptionPacketType) {
            case WDI_EXEMPT_PACKET_TYPE_UNICAST:
                packet = (UINT16)AP6256_EXEMPT_PACKET_UNICAST;
                break;
            case WDI_EXEMPT_PACKET_TYPE_MULTICAST:
                packet = (UINT16)AP6256_EXEMPT_PACKET_MULTICAST;
                break;
            case WDI_EXEMPT_PACKET_TYPE_BOTH:
                packet = (UINT16)AP6256_EXEMPT_PACKET_BOTH;
                break;
            default:
                skipped++;
                continue;
            }

            entries[count].EtherType = entry->EtherType;
            entries[count].Action = action;
            entries[count].PacketType = packet;
            count++;
        }

        if (InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) != 0) {
            NTSTATUS programmed =
                Ap6256WifiSetPrivacyExemptionsIf(Wifi->Ctx, ifIndex, entries, count);

            TraceDiag("privacy exemption list: port %u if %u, %u supplied, %u programmed, "
                      "%u skipped -> 0x%08X\n",
                      (ULONG)Header->PortId, ifIndex, supplied, count, skipped, programmed);
            if (Header->PortId == AP6256_GROUP_PORT) {

                status = programmed;
            } else if (count != 0 && !NT_SUCCESS(programmed)) {

                TraceWarn(TRACE_NETADAPTER, "exempt_list not accepted; relying on the firmware's "
                                            "own EAPOL exemption\n");
            }
        } else {
            TraceInfo(TRACE_NETADAPTER,
                      "privacy exemption list: %u entry(s) held, the radio is "
                      "not up\n",
                      supplied);
        }
        if (NT_SUCCESS(status))
            status = Ap6256HostCipherSetRxExemptions(Wifi->Ctx, ifIndex, hostEntries, supplied);
    }

PrivacyComplete:
    CleanupParsedWdiSetPrivacyExemptionList(&parameters);
    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleMulticastList(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                          _In_ AP6256_REQUEST Request, _In_reads_bytes_(TlvLength) const UCHAR* Tlv,
                          _In_ ULONG TlvLength)
{
    WDI_SET_MULTICAST_LIST_PARAMETERS parameters;
    NTSTATUS status;
    ULONG count;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetMulticastList(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    count = parameters.MulticastList.ElementCount;
    if (Header->PortId == AP6256_DISCOVERY_PORT && Wifi->P2pPortCreated) {

        TraceVerbose(TRACE_NETADAPTER,
                     "P2P discovery multicast list: %u address(es), no data peers\n", count);
        CleanupParsedWdiSetMulticastList(&parameters);
        Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
        return;
    }
    status = Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.Created ? STATUS_SUCCESS
             : Header->PortId != AP6256_STATION_PORT
                 ? STATUS_INVALID_DEVICE_STATE
                 : Ap6256WifiSetMulticastList(
                       Wifi->Ctx, (count != 0) ? parameters.MulticastList.pElements : NULL, count);
    if (!NT_SUCCESS(status)) {

        TraceWarn(TRACE_NETADAPTER,
                  "multicast list (%u address(es)) not programmed 0x%08X; "
                  "receiving all multicast\n",
                  count, status);
    } else {
        TraceInfo(TRACE_NETADAPTER, "multicast list: %u address(es)\n", count);
    }

    CleanupParsedWdiSetMulticastList(&parameters);
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256HandleReceivePacketFilter(_In_ PAP6256_WIFI Wifi, _In_ PWDI_MESSAGE_HEADER Header,
                                _In_ AP6256_REQUEST Request,
                                _In_reads_bytes_(TlvLength) const UCHAR* Tlv, _In_ ULONG TlvLength)
{
    WDI_SET_RECEIVE_PACKET_FILTER_PARAMETERS parameters;
    NTSTATUS status;
    UINT32 wdiFilter;
    ULONG filter;
    BOOLEAN sendUpMgmt;

    RtlZeroMemory(&parameters, sizeof(parameters));
    status = Ap6256NdisToNtStatus(
        ParseWdiSetReceivePacketFilter(TlvLength, Tlv, &Wifi->TlvContext, &parameters));
    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    wdiFilter = (UINT32)parameters.PacketFilterType;

    if ((wdiFilter & ~AP6256_WDI_FILTER_SUPPORTED) != 0) {
        TraceWarn(TRACE_NETADAPTER,
                  "receive filter 0x%08X REFUSED: 0x%08X is outside the "
                  "supported classes\n",
                  wdiFilter, wdiFilter & ~AP6256_WDI_FILTER_SUPPORTED);
        Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
        CleanupParsedWdiSetReceivePacketFilter(&parameters);
        return;
    }

    filter = 0;
    if ((wdiFilter & WDI_PACKET_FILTER_DIRECTED) != 0)
        filter |= AP6256_RXF_DIRECTED;
    if ((wdiFilter & WDI_PACKET_FILTER_MULTICAST) != 0)
        filter |= AP6256_RXF_MULTICAST;
    if ((wdiFilter & WDI_PACKET_FILTER_ALL_MULTICAST) != 0)
        filter |= AP6256_RXF_ALL_MULTICAST;
    if ((wdiFilter & WDI_PACKET_FILTER_BROADCAST) != 0)
        filter |= AP6256_RXF_BROADCAST;
    if ((wdiFilter & WDI_PACKET_FILTER_PROMISCUOUS) != 0)
        filter |= AP6256_RXF_PROMISCUOUS;

    sendUpMgmt = (BOOLEAN)((wdiFilter & AP6256_WDI_FILTER_MGMT_CLASSES) != 0);

    if (Header->PortId == AP6256_GROUP_PORT && Wifi->Ctx->Go.FirmwareReady) {
        UINT32 allmulti = 1;
        status = Ap6256BcdcSetIovarIf(Wifi->Ctx, Wifi->Ctx->Go.IfIndex, "allmulti", &allmulti,
                                      sizeof(allmulti));
        if (NT_SUCCESS(status))
            InterlockedExchange(&Wifi->Ctx->Go.PacketFilter, (LONG)filter);
    } else if (Header->PortId == AP6256_DISCOVERY_PORT) {
        status = STATUS_SUCCESS;
    } else if (Header->PortId == AP6256_STATION_PORT) {
        status = Ap6256WifiSetPacketFilter(Wifi->Ctx, filter, sendUpMgmt);
    } else
        status = STATUS_INVALID_DEVICE_STATE;
    if (!NT_SUCCESS(status)) {
        TraceWarn(TRACE_NETADAPTER, "receive filter 0x%08X not programmed 0x%08X\n", wdiFilter,
                  status);
    } else {
        TraceInfo(TRACE_NETADAPTER, "receive filter: WDI 0x%08X -> 0x%03X, sendup_mgmt %u\n",
                  wdiFilter, filter, (ULONG)sendUpMgmt);
    }

    CleanupParsedWdiSetReceivePacketFilter(&parameters);

    if (Header->PortId == AP6256_GROUP_PORT)
        TraceDiag("hotspot: receive filter WDI 0x%08X software 0x%03X -> 0x%08X\n", wdiFilter,
                  (ULONG)InterlockedCompareExchange(&Wifi->Ctx->Go.PacketFilter, 0, 0), status);

    Ap6256CompleteRequest(Wifi, Request, status);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256AcknowledgeCommand(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PCSTR Name)
{
    TraceInfo(TRACE_NETADAPTER, "%s: accepted\n", Name);
    Ap6256CompleteRequest(Wifi, Request, STATUS_SUCCESS);
}

_IRQL_requires_max_(PASSIVE_LEVEL)
static VOID
Ap6256DeclineCommand(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, _In_ PCSTR Name)
{
    TraceDiag("%s: declined (capability not advertised)\n", Name);
    Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
}

VOID Ap6256ProcessCommand(_In_ PAP6256_WIFI Wifi, _In_ AP6256_REQUEST Request, LONG SaeGeneration)
{
    PWDI_MESSAGE_HEADER header;
    const UCHAR* tlv;
    ULONG tlvLength;
    UINT16 messageId = Ap6256RequestGetMessageId(Request);
    NTSTATUS status = Ap6256GetRequestView(Request, &header, &tlv, &tlvLength);

    if (!NT_SUCCESS(status)) {
        Ap6256CompleteRequest(Wifi, Request, status);
        return;
    }

    if (messageId == WDI_TASK_START_AP || messageId == WDI_TASK_STOP_AP ||
        messageId == WDI_TASK_CHANGE_OPERATION_MODE || messageId == WDI_TASK_CREATE_PORT)
        TraceDiag("hotspot: cmd %u port %u txn %u\n", messageId, (ULONG)header->PortId,
                  header->TransactionId);
    TraceVerbose(TRACE_NETADAPTER, "cmd %u (port %u, txn %u, %u TLV bytes)\n", messageId,
                 header != NULL ? (ULONG)header->PortId : 0u,
                 header != NULL ? header->TransactionId : 0u, tlvLength);

    if (Wifi->PowerStateDx && messageId != WDI_SET_POWER_STATE) {
        Ap6256CompleteRequest(Wifi, Request, STATUS_POWER_STATE_INVALID); return;
    }
    if (InterlockedCompareExchange(&Wifi->HardwareAvailable, 0, 0) == 0 &&
        messageId != WDI_SET_ADAPTER_CONFIGURATION && messageId != WDI_TASK_CREATE_PORT &&
        messageId != WDI_TASK_DELETE_PORT && messageId != WDI_GET_ADAPTER_CAPABILITIES &&
        messageId != WDI_SET_POWER_STATE && messageId != WDI_ABORT_TASK) {

        TraceError(TRACE_NETADAPTER, "cmd %u REFUSED: hardware not available\n", messageId);
        Ap6256CompleteRequest(Wifi, Request, STATUS_DEVICE_NOT_READY);
        return;
    }

    if (Wifi->Ftm.Task.Active && (messageId==WDI_TASK_SCAN || messageId==WDI_TASK_CONNECT ||
        messageId==WDI_TASK_ROAM || messageId==WDI_TASK_START_AP || messageId==WDI_TASK_P2P_DISCOVER ||
        messageId==WDI_TASK_CHANGE_OPERATION_MODE || messageId==WDI_TASK_DELETE_PORT ||
        messageId==WDI_TASK_SEND_REQUEST_ACTION_FRAME || messageId==WDI_TASK_SEND_RESPONSE_ACTION_FRAME ||
        messageId==WDI_TASK_P2P_SEND_REQUEST_ACTION_FRAME || messageId==WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME))
        (VOID)Ap6256FtmCancel(Wifi,FALSE,0,0,STATUS_CANCELLED);
    switch (messageId) {
    case WDI_SET_SAE_AUTH_PARAMS:
        Ap6256HandleSaeParameters(Wifi, Request, header, tlv, tlvLength, SaeGeneration);
        break;
    case WDI_SET_FAST_BSS_TRANSITION_PARAMETERS:
        Ap6256HandleSetFastBssTransition(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_SET_ADAPTER_CONFIGURATION:
        Ap6256HandleAdapterConfiguration(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_TASK_SCAN:
        Ap6256HandleScanRequest(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_CONNECT:
    case WDI_TASK_ROAM:
        Ap6256HandleConnectRequest(Wifi, Request, messageId, header, tlv, tlvLength);
        break;
    case WDI_TASK_DISCONNECT:
        Ap6256HandleDisconnectRequest(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_DOT11_RESET:
        Ap6256HandleResetRequest(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_SET_RADIO_STATE:
        Ap6256HandleRadioRequest(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_CHANGE_OPERATION_MODE:
        Ap6256HandleChangeOperationMode(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_START_AP:
        Ap6256HandleStartAp(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_STOP_AP:
        Ap6256HandleStopAp(Wifi, Request, header);
        break;
    case WDI_TASK_SEND_AP_ASSOCIATION_RESPONSE:
        Ap6256HandleSendApAssociationResponse(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_IHV_REQUEST:
        Ap6256HandleIhvRequest(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_SET_P2P_WPS_ENABLED:
        Ap6256HandleSetP2pWpsEnabled(Wifi, header, Request, tlv, tlvLength);
        break;
    case WDI_SET_CONNECTION_QUALITY:
        Ap6256HandleSetConnectionQuality(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_RECEIVE_COALESCING:
        Ap6256HandleSetReceiveCoalescing(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_CLEAR_RECEIVE_COALESCING:
        Ap6256HandleClearReceiveCoalescing(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_ADD_PM_PROTOCOL_OFFLOAD:
        Ap6256HandleAddPmProtocolOffload(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_REMOVE_PM_PROTOCOL_OFFLOAD:
        Ap6256HandleRemovePmProtocolOffload(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_ADD_WOL_PATTERN:
        Ap6256HandleAddWolPattern(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_REMOVE_WOL_PATTERN:
        Ap6256HandleRemoveWolPattern(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_NETWORK_LIST_OFFLOAD:
        if (header->PortId != AP6256_STATION_PORT)
            Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
        else
            Ap6256HandleSetNetworkListOffload(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_ADVERTISEMENT_INFORMATION:
        Ap6256HandleSetAdvertisementInformation(Wifi, header, Request, tlv, tlvLength);
        break;
    case WDI_SET_P2P_LISTEN_STATE:
        Ap6256HandleSetP2pListenState(Wifi, header, Request, tlv, tlvLength);
        break;
    case WDI_TASK_P2P_SEND_REQUEST_ACTION_FRAME:
        Ap6256HandleP2pSendRequestActionFrame(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_P2P_SEND_RESPONSE_ACTION_FRAME:
        Ap6256HandleP2pSendResponseActionFrame(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_P2P_DISCOVER:
        Ap6256HandleP2pDiscover(Wifi, Request, header, tlv, tlvLength);
        break;
    case WDI_TASK_SEND_REQUEST_ACTION_FRAME:
    case WDI_TASK_SEND_RESPONSE_ACTION_FRAME:
        Ap6256HandleSendActionFrame(Wifi, Request, messageId, header, tlv, tlvLength);
        break;
    case WDI_SET_ADD_CIPHER_KEYS:
    case WDI_SET_DELETE_CIPHER_KEYS:
    case WDI_SET_DEFAULT_KEY_ID:
        Ap6256HandleKeyRequest(Wifi, header, Request, messageId, tlv, tlvLength);
        break;
    case WDI_TASK_CREATE_PORT:
    case WDI_TASK_DELETE_PORT:
        Ap6256HandlePortRequest(Wifi, Request, messageId, header, tlv, tlvLength);
        break;
    case WDI_ABORT_TASK:
        Ap6256HandleAbortRequest(Wifi, Request, tlv, tlvLength);
        break;
    case WDI_SET_PRIVACY_EXEMPTION_LIST:
        Ap6256HandlePrivacyExemptionList(Wifi, header, Request, tlv, tlvLength);
        break;
    case WDI_SET_MULTICAST_LIST:
        Ap6256HandleMulticastList(Wifi, header, Request, tlv, tlvLength);
        break;
    case WDI_SET_RECEIVE_PACKET_FILTER:
        Ap6256HandleReceivePacketFilter(Wifi, header, Request, tlv, tlvLength);
        break;

        AP6256_ACK_CASE(WDI_SET_HOST_DETECT_ERROR);
        AP6256_ACK_CASE(WDI_SET_OPERATION_MODE);
        AP6256_ACK_CASE(WDI_SET_AUTO_POWER_SAVE);
        AP6256_ACK_CASE(WDI_SET_FLUSH_BSS_ENTRY);
        AP6256_ACK_CASE(WDI_SET_ASSOCIATION_PARAMETERS);
        AP6256_ACK_CASE(WDI_SET_TCP_OFFLOAD_PARAMETERS);
        AP6256_ACK_CASE(WDI_SET_ENCAPSULATION_OFFLOAD);
        AP6256_ACK_CASE(WDI_SET_END_DWELL_TIME);
        AP6256_ACK_CASE(WDI_SET_NEIGHBOR_REPORT_ENTRIES);
        AP6256_ACK_CASE(WDI_SET_LOCATION_PRIVACY);

        AP6256_DECLINE_CASE(WDI_TASK_OPEN);
        AP6256_DECLINE_CASE(WDI_TASK_CLOSE);
        AP6256_DECLINE_CASE(WDI_TASK_SET_READY_TO_RECEIVE_INDICATIONS);
        AP6256_DECLINE_CASE(WDI_TASK_DELETE_PEER_STATE);

        AP6256_DECLINE_CASE(WDI_GET_BSS_ENTRY_LIST);
        AP6256_DECLINE_CASE(WDI_GET_RECEIVE_COALESCING_MATCH_COUNT);

        AP6256_DECLINE_CASE(WDI_TCP_RSC_STATISTICS);
        AP6256_DECLINE_CASE(WDI_GET_SUPPORTED_DEVICE_SERVICES);
        AP6256_DECLINE_CASE(WDI_DEVICE_SERVICE_COMMAND);

        AP6256_DECLINE_CASE(WDI_TASK_IHV);

        AP6256_DECLINE_CASE(WDI_SET_P2P_ADDITIONAL_IE);
        AP6256_DECLINE_CASE(WDI_SET_P2P_START_BACKGROUND_DISCOVERY);
        AP6256_DECLINE_CASE(WDI_SET_P2P_STOP_BACKGROUND_DISCOVERY);

    case WDI_TASK_REQUEST_FTM:
        Ap6256HandleFtmRequest(Wifi,Request,header,tlv,tlvLength);
        break;

    default:

        if (!Ap6256ModelDispatchCommand(Wifi, Request, header, tlv, tlvLength, messageId)) {
            TraceError(TRACE_NETADAPTER,
                       "REFUSED WiFi command 0x%X - no handler; a connection may "
                       "fail with no other symptom\n",
                       messageId);
            Ap6256CompleteRequest(Wifi, Request, STATUS_NOT_SUPPORTED);
        }
        break;
    }
}

_IRQL_requires_max_(DISPATCH_LEVEL)
NTSTATUS Ap6256QueueCommand(_In_opt_ PAP6256_WIFI Wifi,
                                                                _In_ AP6256_REQUEST Request)
{
    KIRQL oldIrql;
    BOOLEAN queued = FALSE;

    if (Wifi == NULL || !AP6256_CMDQ_OK(Wifi) ||
        InterlockedCompareExchange(&Wifi->Stopping, 0, 0) != 0) {
        return STATUS_DEVICE_NOT_READY;
    }

    KeAcquireSpinLock(&Wifi->CommandLock, &oldIrql);
    if (InterlockedCompareExchange(&Wifi->Stopping, 0, 0) == 0 &&
        (ULONG)(Wifi->CommandHead - Wifi->CommandTail) < AP6256_CMDQ_DEPTH) {
        Wifi->CommandPending[Wifi->CommandHead & (AP6256_CMDQ_DEPTH - 1)] = Request;

        Wifi->CommandSaeGeneration[Wifi->CommandHead & (AP6256_CMDQ_DEPTH - 1)] =
            Wifi->Auth.SaeGeneration;
        Wifi->CommandHead++;
        queued = TRUE;
    }
    KeReleaseSpinLock(&Wifi->CommandLock, oldIrql);

    if (!queued) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    AP6256_CMDQ_KICK(Wifi);
    return STATUS_SUCCESS;
}

VOID Ap6256OnScanTimeout(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    WDI_MESSAGE_HEADER header;
    PVOID requestId;

    if (Ap6256ClaimExpiredTask(wifi, &wifi->ScanTask, &header, &requestId)) {
        NTSTATUS abortStatus = Ap6256WifiScanAbort(wifi->Ctx);
        if (!NT_SUCCESS(abortStatus)) {
            TraceWarn(TRACE_NETADAPTER, "firmware scan abort failed 0x%08X\n", abortStatus);
        }
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_SCAN_COMPLETE, &header,
                                      header.TransactionId, requestId, STATUS_SUCCESS, NULL, 0);
        TraceInfo(TRACE_NETADAPTER,
                  "scan ran out of time and was aborted; WDI scan complete "
                  "0x%08X: %d indicated, %d dropped\n",
                  STATUS_SUCCESS, InterlockedCompareExchange(&wifi->ScanIndicated, 0, 0),
                  InterlockedCompareExchange(&wifi->ScanDropped, 0, 0));
    }
}

VOID Ap6256OnConnectTimeout(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    Ap6256ExpireConnect(wifi);
}

VOID Ap6256OnP2pDiscoverTick(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    WDI_MESSAGE_HEADER header = {0};
    PVOID requestId = NULL;
    ULONG next;
    BOOLEAN claimed = FALSE;
    NTSTATUS completion = STATUS_SUCCESS;

    if (wifi == NULL)
        return;
    Ap6256LockAcquire(&wifi->P2pLock);
    if (!wifi->Stopping && wifi->HardwareAvailable && wifi->P2pDiscovering) {
        next = wifi->Service.Active ? Ap6256ServiceAdvance(wifi) : Ap6256P2pAdvanceDiscovery(wifi->Ctx);
        if (next != 0) {
            AP6256_TIMER_START(wifi->P2pDiscoverTimer, next);
        } else {
            wifi->P2pDiscovering = FALSE;
            completion = wifi->Ctx->P2p.DiscoverStatus;
            { NTSTATUS listenStatus=Ap6256ServiceResumeListen(wifi);
              if (NT_SUCCESS(completion) && !NT_SUCCESS(listenStatus)) completion=listenStatus; }
            claimed = Ap6256ClaimTask(wifi, &wifi->P2pDiscoverTask, &header, &requestId);
        }
    }
    Ap6256LockRelease(&wifi->P2pLock);
    if (claimed) {
        TraceDiag(
            "P2P discovery complete: txn %u port %u status 0x%08X, %ld indicated, %ld dropped\n",
            header.TransactionId, header.PortId, completion,
            InterlockedCompareExchange(&wifi->ScanIndicated, 0, 0),
            InterlockedCompareExchange(&wifi->ScanDropped, 0, 0));
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_P2P_DISCOVERY_COMPLETE, &header,
                                      header.TransactionId, requestId, completion, NULL, 0);
    }
}

VOID Ap6256OnP2pListenTick(PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    NTSTATUS status = STATUS_SUCCESS;
    if (wifi == NULL)
        return;
    Ap6256LockAcquire(&wifi->P2pLock);
    if (!wifi->Stopping && wifi->HardwareAvailable && wifi->P2pPortCreated &&
        wifi->Ctx->P2p.Listening) {
        BOOLEAN busy = wifi->P2pDiscovering || wifi->ScanTask.Active ||
                       wifi->ActionFrameTask.Active || wifi->ConnectTask.Active;
        busy = busy || Ap6256ModelGroupConnecting(wifi);
        if (!busy && wifi->Ctx->DatapathRunning)
            status = Ap6256P2pPulseListen(wifi->Ctx);
        if (!NT_SUCCESS(status))
            TraceWarn(TRACE_NETADAPTER, "P2P periodic listen failed 0x%08X\n", status);
        AP6256_TIMER_START(wifi->P2pListenTimer, wifi->Ctx->P2p.ListenCycleMs);
    }
    Ap6256LockRelease(&wifi->P2pLock);
}

VOID Ap6256OnActionFrameTimeout(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    AP6256_ACTION_FRAME_COMPLETION done;
    BOOLEAN claimed;

    if (wifi == NULL || wifi->Stopping || !wifi->HardwareAvailable || !wifi->ActionFrameTask.Active)
        return;

    Ap6256LockAcquire(&wifi->ActionFrameLock);
    if (wifi->Stopping || !wifi->HardwareAvailable || !wifi->ActionFrameTask.Active ||
        wifi->ActionFrameBody == NULL) {
        Ap6256LockRelease(&wifi->ActionFrameLock);
        return;
    }

    if (wifi->ActionFrameAcked) {
        LONGLONG delay = wifi->ActionFrameDwellDeadline - Ap6256InterruptTimeMs();
        if (delay > 0) {
            AP6256_TIMER_START(wifi->ActionFrameTimer, (ULONG)delay);
            Ap6256LockRelease(&wifi->ActionFrameLock);
            return;
        }
        claimed = Ap6256ClaimActionFrameLocked(wifi, FALSE, &done);
        Ap6256LockRelease(&wifi->ActionFrameLock);
        if (claimed)
            Ap6256IndicateActionFrameDone(wifi, &done, STATUS_SUCCESS);
        return;
    }

    if (wifi->ActionFrameDeadline - Ap6256InterruptTimeMs() >= (LONGLONG)wifi->ActionFrameRetryMs) {
        TraceWarn(TRACE_NETADAPTER,
                  "action frame %u: no transmit status after %u ms; "
                  "resending\n",
                  wifi->ActionFramePendingId, wifi->ActionFrameRetryMs);
        if (NT_SUCCESS(Ap6256SendPendingActionFrame(wifi))) {
            AP6256_TIMER_START(wifi->ActionFrameTimer, wifi->ActionFrameRetryMs);
            Ap6256LockRelease(&wifi->ActionFrameLock);
            return;
        }
    }

    TraceWarn(TRACE_NETADAPTER, "action frame %u timed out with no transmit status\n",
              wifi->ActionFramePendingId);
    claimed = Ap6256ClaimActionFrameLocked(wifi, TRUE, &done);
    Ap6256LockRelease(&wifi->ActionFrameLock);
    if (claimed) {
        Ap6256IndicateActionFrameDone(wifi, &done, STATUS_IO_TIMEOUT);
    }
}

VOID Ap6256OnDisconnectTimeout(_In_ PVOID Context)
{
    PAP6256_WIFI wifi = (PAP6256_WIFI)Context;
    WDI_MESSAGE_HEADER header;
    PVOID requestId;

    Ap6256LockAcquire(&wifi->ConnectLock);
    if (Ap6256ClaimTask(wifi, &wifi->DisconnectTask, &header, &requestId)) {
        Ap6256IndicateDisassociation(wifi, &header);
        (VOID) Ap6256SendIndicationRq(wifi, WDI_INDICATION_DISCONNECT_COMPLETE, &header,
                                      header.TransactionId, requestId, STATUS_IO_TIMEOUT, NULL, 0);
    }
    Ap6256LockRelease(&wifi->ConnectLock);
}
