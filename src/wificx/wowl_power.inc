/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include <netpoweroffload.h>
#include <netpoweroffloadlist.h>
#include <netwakesource.h>
#include <netwakesourcelist.h>
#include <wificxpoweroffload.h>
#include <wificxpoweroffloadlist.h>
#include <wificxwakesource.h>
#include <wificxwakesourcelist.h>

static VOID Ap6256WifiCxSetPowerCapabilities(NETADAPTER Adapter, PAP6256_DEVICE_CONTEXT Ctx)
{
    NET_ADAPTER_POWER_OFFLOAD_ARP_CAPABILITIES arp;
    NET_ADAPTER_POWER_OFFLOAD_NS_CAPABILITIES ns;
    NET_ADAPTER_WAKE_BITMAP_CAPABILITIES bitmap;
    NET_ADAPTER_WAKE_MAGIC_PACKET_CAPABILITIES magic;
    NET_ADAPTER_WAKE_EAPOL_PACKET_CAPABILITIES eapol;
    WIFI_ADAPTER_POWER_OFFLOAD_RSN_REKEY_CAPABILITIES gtk;
    WIFI_ADAPTER_WAKE_CAPABILITIES wake;
    UINT32 caps = Ctx->WowlCapabilities;
    ULONG slots = Ctx->PacketFilterMax;
    if (slots == 0 || slots > AP6256_WOL_PATTERN_MAX) slots = AP6256_WOL_PATTERN_MAX;
    if (!Ctx->FirmwareWowlAdapter) return;
    if (Ctx->FirmwareArpOffloadSupported && (caps & AP6256_WOWL_ARP_OFFLOAD)) {
        NET_ADAPTER_POWER_OFFLOAD_ARP_CAPABILITIES_INIT(&arp, AP6256_ARP_OFFLOAD_SLOTS);
        NetAdapterPowerOffloadSetArpCapabilities(Adapter, &arp);
    }
    if (Ctx->FirmwareNdOffloadSupported && (caps & AP6256_WOWL_ARP_OFFLOAD)) {
        NET_ADAPTER_POWER_OFFLOAD_NS_CAPABILITIES_INIT(&ns, AP6256_NS_OFFLOAD_ADDRESSES);
        NetAdapterPowerOffloadSetNSCapabilities(Adapter, &ns);
    }
    if (Ctx->FirmwareGtkOffloadSupported && (caps & AP6256_WOWL_KEY_ROTATION)) {
        WIFI_ADAPTER_POWER_OFFLOAD_RSN_REKEY_CAPABILITIES_INIT(&gtk);
        WifiAdapterPowerOffloadSetRsnRekeyCapabilities(Adapter, &gtk);
    }
    if ((caps & AP6256_WOWL_NET) && slots > 2) {
        NET_ADAPTER_WAKE_BITMAP_CAPABILITIES_INIT(&bitmap);
        bitmap.BitmapPattern = TRUE; bitmap.MaximumPatternCount = slots - 2;
        bitmap.MaximumPatternSize = AP6256_WOL_PATTERN_BYTES;
        NetAdapterWakeSetBitmapCapabilities(Adapter, &bitmap);
    }
    if (caps & AP6256_WOWL_MAGIC) {
        NET_ADAPTER_WAKE_MAGIC_PACKET_CAPABILITIES_INIT(&magic); magic.MagicPacket = TRUE;
        NetAdapterWakeSetMagicPacketCapabilities(Adapter, &magic);
    }
    if (caps & AP6256_WOWL_EAPID) {
        NET_ADAPTER_WAKE_EAPOL_PACKET_CAPABILITIES_INIT(&eapol); eapol.EapolPacket = TRUE;
        NetAdapterWakeSetEapolPacketCapabilities(Adapter, &eapol);
    }
    WIFI_ADAPTER_WAKE_CAPABILITIES_INIT(&wake);
    wake.NloDiscovery = (caps & AP6256_WOWL_M1) != 0;
    wake.ApAssociationLost = (caps & (AP6256_WOWL_BEACON | AP6256_WOWL_DISCONNECT)) ==
        (AP6256_WOWL_BEACON | AP6256_WOWL_DISCONNECT);
    wake.GtkHandshakeError = (caps & AP6256_WOWL_GTK_FAILURE) != 0;
    wake.FourWayHandshakeRequest = (caps & AP6256_WOWL_M1) != 0;
    WifiAdapterSetWakeCapabilities(Adapter, &wake);
}

static NTSTATUS Ap6256WifiCxForgetSleepRecords(PAP6256_WIFI Wifi)
{
    ULONG i;
    NTSTATUS status;
    while (Wifi->WolPatternCount != 0) {
        status = Ap6256WifiRemoveWolPattern(Wifi->Ctx, Wifi->WolPatternIds[Wifi->WolPatternCount - 1]);
        if (!NT_SUCCESS(status)) return status;
        --Wifi->WolPatternCount;
    }
    for (i = Wifi->NsOffloadCount; i != 0; --i) {
        status = Ap6256WifiRemoveNsOffload(Wifi->Ctx, Wifi->NsOffloads[i - 1].ProtocolOffloadId);
        if (!NT_SUCCESS(status)) return status;
        Wifi->NsOffloadCount = i - 1;
    }
    for (i = 0; i < AP6256_ARP_OFFLOAD_SLOTS; ++i) if (Wifi->ArpOffloadValid[i]) {
        status = Ap6256WifiRemoveArpOffload(Wifi->Ctx, i);
        if (!NT_SUCCESS(status)) return status;
        Wifi->ArpOffloadValid[i] = FALSE;
    }
    status = Ap6256WifiRemoveGtkOffload(Wifi->Ctx);
    if (!NT_SUCCESS(status)) return status;
    Wifi->GtkOffloadValid = FALSE; Wifi->GtkOffloadId = 0;
    RtlSecureZeroMemory(&Wifi->GtkOffload, sizeof(Wifi->GtkOffload));
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256WifiCxArmWake(WDFDEVICE Device)
{
    PAP6256_DEVICE_CONTEXT ctx = Ap6256GetDeviceContext(Device);
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(ctx);
    NET_POWER_OFFLOAD_LIST netOffloads;
    NET_WAKE_SOURCE_LIST netWake;
    WIFI_POWER_OFFLOAD_LIST wifiOffloads;
    WIFI_WAKE_SOURCE_LIST wifiWake;
    NTSTATUS status;
    SIZE_T i;
    ULONG arpCount = 0, nsCount = 0;
    UINT32 zero = 0;
    BOOLEAN recover = FALSE;
    if (!wifi) return STATUS_NOT_SUPPORTED;

    Ap6256LockAcquire(&wifi->ConnectLock);
    Ap6256LockAcquire(&wifi->Model.GroupLock);
    if (!wifi->HardwareAvailable || wifi->Stopping || !ctx->FirmwareWowlAdapter ||
        ctx->Go.Started || ctx->Go.NativeStateUncertain || Ap6256FipsActive(ctx, 0) ||
        Ap6256HostCipherPacketActive(ctx, 0)) {
        status = STATUS_NOT_SUPPORTED;
        goto unlock;
    }
    if (ctx->LowPowerArmed) {
        status = STATUS_SUCCESS;
        goto unlock;
    }
    wifi->PowerStateDx = TRUE;
    status = Ap6256WifiCxForgetSleepRecords(wifi);
    if (!NT_SUCCESS(status)) goto done;
    ctx->WakeEnabledPatterns = ctx->WakeEnabledOffloads = ctx->WakeMediaSpecificEvents = 0;
    NET_POWER_OFFLOAD_LIST_INIT(&netOffloads); NetDeviceGetPowerOffloadList(Device, &netOffloads);
    for (i = 0; i < NetPowerOffloadListGetCount(&netOffloads); ++i) {
        NETPOWEROFFLOAD item = NetPowerOffloadListGetElement(&netOffloads, i);
        if (NetPowerOffloadGetAdapter(item) != wifi->Model.Adapter) continue;
        if (NetPowerOffloadGetType(item) == NetPowerOffloadTypeArp) {
            NET_POWER_OFFLOAD_ARP_PARAMETERS source;
            AP6256_ARP_OFFLOAD target = {0};
            WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* record;
            if (arpCount == AP6256_ARP_OFFLOAD_SLOTS) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
            NET_POWER_OFFLOAD_ARP_PARAMETERS_INIT(&source); NetPowerOffloadGetArpParameters(item, &source);
            if (source.LinkLayerAddress.Length != 6) {status = STATUS_INVALID_PARAMETER; goto done;}
            target.OffloadId = source.Id;
            RtlCopyMemory(target.RemoteIpv4, &source.RemoteIPv4Address, 4);
            RtlCopyMemory(target.HostIpv4, &source.HostIPv4Address, 4);
            RtlCopyMemory(target.MacAddress, source.LinkLayerAddress.Address, 6);

            record = &wifi->ArpOffloads[arpCount]; RtlZeroMemory(record, sizeof(*record));
            record->ProtocolOffloadId = source.Id;
            RtlCopyMemory(record->RemoteIPV4Address, target.RemoteIpv4, 4);
            RtlCopyMemory(record->HostIPV4Address, target.HostIpv4, 4);
            RtlCopyMemory(record->MacAddress.Address, target.MacAddress, 6);
            wifi->ArpOffloadValid[arpCount] = TRUE; wifi->ArpOffloadIds[arpCount++] = source.Id;
            status = Ap6256WifiAddArpOffload(ctx, &target, arpCount - 1);
            if (!NT_SUCCESS(status)) goto done;
            ctx->WakeEnabledOffloads |= NDIS_PM_PROTOCOL_OFFLOAD_ARP_SUPPORTED;
        } else if (NetPowerOffloadGetType(item) == NetPowerOffloadTypeNS) {
            NET_POWER_OFFLOAD_NS_PARAMETERS source;
            AP6256_NS_OFFLOAD target = {0};
            WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER* record;
            if (nsCount == AP6256_NS_OFFLOAD_ADDRESSES) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
            NET_POWER_OFFLOAD_NS_PARAMETERS_INIT(&source); NetPowerOffloadGetNSParameters(item, &source);
            if (source.LinkLayerAddress.Length != 6) {status = STATUS_INVALID_PARAMETER; goto done;}
            target.OffloadId = source.Id;
            RtlCopyMemory(target.RemoteIpv6, &source.RemoteIPv6Address, 16);
            RtlCopyMemory(target.SolicitedNodeIpv6, &source.SolicitedNodeIPv6Address, 16);
            RtlCopyMemory(target.TargetIpv6A, &source.TargetIPv6Addresses[0], 16);
            RtlCopyMemory(target.TargetIpv6B, &source.TargetIPv6Addresses[1], 16);
            RtlCopyMemory(target.MacAddress, source.LinkLayerAddress.Address, 6);

            record = &wifi->NsOffloads[nsCount++]; RtlZeroMemory(record, sizeof(*record));
            record->ProtocolOffloadId = source.Id;
            RtlCopyMemory(record->RemoteIPV6Address, target.RemoteIpv6, 16);
            RtlCopyMemory(record->SolicitdNodeIPv6Address, target.SolicitedNodeIpv6, 16);
            RtlCopyMemory(record->TargetIPV6Address1, target.TargetIpv6A, 16);
            RtlCopyMemory(record->TargetIPV6Address2, target.TargetIpv6B, 16);
            RtlCopyMemory(record->MacAddress.Address, target.MacAddress, 6);
            wifi->NsOffloadCount = nsCount;
            status = Ap6256WifiAddNsOffload(ctx, &target); if (!NT_SUCCESS(status)) goto done;
            ctx->WakeEnabledOffloads |= NDIS_PM_PROTOCOL_OFFLOAD_NS_SUPPORTED;
        }
    }
    WIFI_POWER_OFFLOAD_LIST_INIT(&wifiOffloads); WifiDeviceGetPowerOffloadList(Device, &wifiOffloads);
    for (i = 0; i < WifiPowerOffloadListGetCount(&wifiOffloads); ++i) {
        WIFIPOWEROFFLOAD item = WifiPowerOffloadListGetElement(&wifiOffloads, i);
        WIFI_POWER_OFFLOAD_80211RSNREKEY_PARAMETERS source;
        WDI_PM_RSN_KEY_INFO_CONTAINER info = {0};
        AP6256_GTK_OFFLOAD target;
        if (WifiPowerOffloadGetAdapter(item) != wifi->Model.Adapter) continue;
        if (WifiPowerOffloadGetType(item) != WifiPowerOffloadType80211RsnRekey || wifi->GtkOffloadValid) {
            status = STATUS_NOT_SUPPORTED; goto done;
        }
        WIFI_POWER_OFFLOAD_80211RSNREKEY_PARAMETERS_INIT(&source);
        WifiPowerOffloadGet80211RSNRekeyParameters(item, &source);
        info.ProtocolOffloadId = source.ProtocolOffloadId; info.ReplayCounter = source.ReplayCounter;
        info.KCK_CONTENT.ElementCount = source.KCKLength; info.KCK_CONTENT.pElements = source.KCK;
        info.KEK_CONTENT.ElementCount = source.KEKLength; info.KEK_CONTENT.pElements = source.KEK;
        status = Ap6256BuildGtkOffload(wifi, &info, &target);
        if (NT_SUCCESS(status)) {
            wifi->GtkOffload = target; wifi->GtkOffloadId = target.OffloadId; wifi->GtkOffloadValid = TRUE;
            status = Ap6256WifiAddGtkOffload(ctx, &target);
            if (NT_SUCCESS(status)) ctx->WakeEnabledOffloads |= NDIS_PM_PROTOCOL_OFFLOAD_80211_RSN_REKEY_SUPPORTED;
        }
        RtlSecureZeroMemory(&target, sizeof(target)); RtlSecureZeroMemory(&source, sizeof(source));
        if (!NT_SUCCESS(status)) goto done;
    }
    NET_WAKE_SOURCE_LIST_INIT(&netWake); NetDeviceGetWakeSourceList(Device, &netWake);
    for (i = 0; i < NetWakeSourceListGetCount(&netWake); ++i) {
        NETWAKESOURCE item = NetWakeSourceListGetElement(&netWake, i);
        NET_WAKE_SOURCE_TYPE type = NetWakeSourceGetType(item);
        UINT32 id;
        if (NetWakeSourceGetAdapter(item) != wifi->Model.Adapter) continue;
        if (wifi->WolPatternCount >= Ap6256WolPatternCeiling(wifi)) {status = STATUS_INSUFFICIENT_RESOURCES; goto done;}
        if (type == NetWakeSourceTypeBitmapPattern) {
            NET_WAKE_SOURCE_BITMAP_PARAMETERS pattern;
            NET_WAKE_SOURCE_BITMAP_PARAMETERS_INIT(&pattern); NetWakeSourceGetBitmapParameters(item, &pattern);
            if (pattern.PatternSize > AP6256_WOL_PATTERN_BYTES || pattern.MaskSize > AP6256_WOL_PATTERN_BYTES) {
                status = STATUS_INVALID_PARAMETER; goto done;
            }
            id = pattern.Id;
            status = Ap6256WifiAddWolBitmapPattern(ctx, id, pattern.Pattern, (ULONG)pattern.PatternSize,
                pattern.Mask, (ULONG)pattern.MaskSize);
        } else if (type == NetWakeSourceTypeMagicPacket) {
            id = NetAdapterWakeMagicPatternId; status = Ap6256WifiAddWolMagicPattern(ctx, id);
        } else if (type == NetWakeSourceTypeEapolPacket) {
            id = NetAdapterWakeEapolPatternId; status = Ap6256WifiAddWolEapolPattern(ctx, id);
        } else {status = STATUS_NOT_SUPPORTED; goto done;}
        wifi->WolPatternIds[wifi->WolPatternCount++] = id;
        if (!NT_SUCCESS(status)) goto done;
        status = Ap6256WifiEnablePacketFilter(ctx, id, TRUE); if (!NT_SUCCESS(status)) goto done;
        ctx->WakeEnabledPatterns = 1;
    }
    WIFI_WAKE_SOURCE_LIST_INIT(&wifiWake); WifiDeviceGetWakeSourceList(Device, &wifiWake);
    for (i = 0; i < WifiWakeSourceListGetCount(&wifiWake); ++i) {
        WIFIWAKESOURCE item = WifiWakeSourceListGetElement(&wifiWake, i);
        if (WifiWakeSourceGetAdapter(item) != wifi->Model.Adapter) continue;
        switch (WifiWakeSourceGetType(item)) {
        case WifiWakeSourceTypeNloDiscovery: ctx->WakeMediaSpecificEvents |= AP6256_WAKE_ON_NLO_DISCOVERY; break;
        case WifiWakeSourceTypeApAssociationLost: ctx->WakeMediaSpecificEvents |= AP6256_WAKE_ON_AP_ASSOCIATION_LOST; break;
        case WifiWakeSourceTypeGtkHandshakeError: ctx->WakeMediaSpecificEvents |= AP6256_WAKE_ON_GTK_HANDSHAKE_ERROR; break;
        case WifiWakeSourceTypeFourWayHandshakeRequest: ctx->WakeMediaSpecificEvents |= AP6256_WAKE_ON_4WAY_HANDSHAKE_REQUEST; break;
        default: status = STATUS_NOT_SUPPORTED; goto done;
        }
    }
    status = Ap6256WifiSuspendForWake(ctx, ctx->WakeMediaSpecificEvents, arpCount != 0, nsCount != 0);
    if (!NT_SUCCESS(status)) {
        AP6256_WAKE_PACKET packet; BOOLEAN valid; UINT32 reason;
        recover = !NT_SUCCESS(Ap6256WifiResumeFromWake(ctx, &reason, &packet, &valid));
    }
done:
    if (!NT_SUCCESS(status)) {
        if (!recover) {
            NTSTATUS cleanup = Ap6256WifiCxForgetSleepRecords(wifi);
            if (!NT_SUCCESS(cleanup)) recover = TRUE;
            cleanup = Ap6256BcdcSetIovar(ctx, "arpoe", &zero, sizeof(zero));
            if (!NT_SUCCESS(cleanup)) recover = TRUE;
            cleanup = Ap6256BcdcSetIovar(ctx, "ndoe", &zero, sizeof(zero));
            if (!NT_SUCCESS(cleanup)) recover = TRUE;
        }
        ctx->WakeEnabledPatterns = ctx->WakeEnabledOffloads = ctx->WakeMediaSpecificEvents = 0;
        wifi->PowerStateDx = FALSE;
    }
unlock:
    Ap6256LockRelease(&wifi->Model.GroupLock);
    Ap6256LockRelease(&wifi->ConnectLock);
    if (recover) {

        NTSTATUS reset;
        Ap6256TearDownChip(ctx, FALSE);
        reset = Ap6256BringUpChip(ctx, FALSE);
        if (NT_SUCCESS(reset)) reset = Ap6256ModelHardwareReady(ctx);
        TraceError(TRACE_POWER, "wake-arm recovery 0x%08X after failure 0x%08X\n", reset, status);
    }
    return status;
}
static EVT_WDF_DEVICE_ARM_WAKE_FROM_S0 Ap6256WifiCxArmS0;
static EVT_WDF_DEVICE_ARM_WAKE_FROM_SX Ap6256WifiCxArmSx;
static EVT_WDF_DEVICE_DISARM_WAKE_FROM_S0 Ap6256WifiCxDisarmS0;
static EVT_WDF_DEVICE_DISARM_WAKE_FROM_SX Ap6256WifiCxDisarmSx;
_Use_decl_annotations_
static NTSTATUS Ap6256WifiCxArmS0(WDFDEVICE Device) {return Ap6256WifiCxArmWake(Device);}
_Use_decl_annotations_
static NTSTATUS Ap6256WifiCxArmSx(WDFDEVICE Device) {return Ap6256WifiCxArmWake(Device);}

_Use_decl_annotations_
static VOID Ap6256WifiCxDisarmS0(WDFDEVICE Device) {UNREFERENCED_PARAMETER(Device);}
_Use_decl_annotations_
static VOID Ap6256WifiCxDisarmSx(WDFDEVICE Device) {UNREFERENCED_PARAMETER(Device);}

_IRQL_requires_max_(PASSIVE_LEVEL)
NTSTATUS Ap6256WifiCxResumePower(PAP6256_DEVICE_CONTEXT Ctx)
{
    PAP6256_WIFI wifi = Ap6256WifiFromDevice(Ctx);
    UINT32 reason;
    AP6256_WAKE_PACKET packet;
    BOOLEAN valid;
    NTSTATUS status = Ap6256WifiResumeFromWake(Ctx, &reason, &packet, &valid);
    if (!NT_SUCCESS(status)) return status;
    if (!wifi) return STATUS_DEVICE_NOT_READY;
    wifi->PowerStateDx = FALSE;
    if (reason & AP6256_WAKE_ON_NLO_DISCOVERY) WifiAdapterReportWakeReason(wifi->Model.Adapter, WifiWakeReasonTypeNloDiscovery);
    if (reason & AP6256_WAKE_ON_AP_ASSOCIATION_LOST) WifiAdapterReportWakeReason(wifi->Model.Adapter, WifiWakeReasonTypeApAssociationlost);
    if (reason & AP6256_WAKE_ON_GTK_HANDSHAKE_ERROR) WifiAdapterReportWakeReason(wifi->Model.Adapter, WifiWakeReasonTypeGtkHandshakeError);
    if (reason & AP6256_WAKE_ON_4WAY_HANDSHAKE_REQUEST) WifiAdapterReportWakeReason(wifi->Model.Adapter, WifiWakeReasonTypeFourWayHandshakeRequest);
    if (valid) {
        NET_ADAPTER_WAKE_REASON_PACKET wake;
        WDF_OBJECT_ATTRIBUTES attributes;
        PVOID data;
        NET_ADAPTER_WAKE_REASON_PACKET_INIT(&wake);
        wake.PatternId = packet.PatternId; wake.OriginalPacketSize = packet.OriginalLength;
        WDF_OBJECT_ATTRIBUTES_INIT(&attributes); attributes.ParentObject = Ctx->Device;
        status = WdfMemoryCreate(&attributes, NonPagedPoolNx, AP6256_POOL_TAG,
            packet.SavedLength, &wake.WakePacket, &data);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(data, packet.Packet, packet.SavedLength);
            NetAdapterReportWakeReasonPacket(wifi->Model.Adapter, &wake);
            WdfObjectDelete(wake.WakePacket);
        } else return status;
    }
    wifi->RetainedResume = TRUE;
    Ap6256PnoResultsPower(Ctx, TRUE);
    return STATUS_SUCCESS;
}
