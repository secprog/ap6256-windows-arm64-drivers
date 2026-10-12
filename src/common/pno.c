/*
 * SPDX-License-Identifier: GPL-3.0-only
 * Licensed under the GNU General Public License, version 3 only.
 * Provided without warranty. See LICENSE for the license text.
 */

#include "pno.h"
#include "bcdc.h"
#include <bcrypt.h>

static const UCHAR Ap6256PnoSha256[32] = {
    0xdd,0xf8,0x3f,0x21,0x00,0x88,0x5b,0x16,0x6b,0xe5,0x2d,0x21,0xc8,0x96,0x6d,0xb1,
    0x64,0xfd,0xd4,0xe1,0xd8,0x16,0xac,0xa2,0xac,0xc6,0x7e,0xe9,0xcc,0x28,0xd7,0x26
};

_Use_decl_annotations_
VOID Ap6256PnoIdentify(PAP6256_DEVICE_CONTEXT Ctx, PUCHAR Image, ULONG Length)
{
    UCHAR digest[32];
    Ctx->FirmwareEnhancedPnoSupported = FALSE;
    Ctx->FirmwarePnoDelaySupported = FALSE;

    Ctx->FirmwarePnoGscanSupported = FALSE;
    if (Ctx->Chip.ChipId != 0x4345 || Ctx->Chip.ChipRev != 9 ||
        Ctx->Chip.RamBase != 0x198000 || Length != 495898 || Length > Ctx->Chip.RamSize)
        return;
    if (NT_SUCCESS(BCryptHash(BCRYPT_SHA256_ALG_HANDLE, NULL, 0, Image, Length,
        digest, sizeof(digest))) && RtlEqualMemory(digest, Ap6256PnoSha256, sizeof(digest)))
        Ctx->FirmwareEnhancedPnoSupported = TRUE;
}

static BOOLEAN Ap6256PnoUnicast(const UCHAR* Address)
{
    static const UCHAR zero[6] = {0};
    return (BOOLEAN)((Address[0] & 1u) == 0 && !RtlEqualMemory(Address, zero, 6));
}

static BOOLEAN Ap6256PnoSeconds(INT32 Seconds, BOOLEAN AllowZero)
{
    return (BOOLEAN)(Seconds >= (AllowZero ? 0 : 1) && Seconds <= MAXLONG / 1000);
}

static NTSTATUS Ap6256PnoValidateOverride(const AP6256_PNO_OVERRIDE_PARAMS* Params)
{
    UINT16 mode = (Params->Flags & 6u) >> 1;
    if (Params->Version != 1 || Params->Reserved != 0 || (Params->Flags & ~7u) != 0 ||
        Params->Exponent > 5 || Params->Repeat > 100) return STATUS_INVALID_PARAMETER;

    if (Params->DurationSeconds == 0)
        return Params->StartOffsetSeconds == 0 ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
    if (!Ap6256PnoSeconds(Params->ScanSeconds, FALSE) ||
        !Ap6256PnoSeconds(Params->LostSeconds, TRUE) ||
        !Ap6256PnoSeconds(Params->SlowSeconds, TRUE)) return STATUS_INVALID_PARAMETER;
    if ((Params->Flags & 1u) != 0 && mode != 0 &&
        (Params->Repeat == 0 || (mode == 3 ? Params->SlowSeconds == 0 : Params->Exponent == 0)))
        return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

static NTSTATUS Ap6256PnoValidateMac(const AP6256_PNO_MAC_PARAMS* Params)
{
    static const UCHAR zero[6] = {0};
    if (Params->Version != 1 || (Params->Flags & ~7u) != 0) return STATUS_INVALID_PARAMETER;

    if (RtlEqualMemory(Params->Address, zero, 6)) return STATUS_SUCCESS;
    return Ap6256PnoUnicast(Params->Address) && (Params->Address[0] & 2u) != 0
        ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER;
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoValidateConfig(const AP6256_PNO_CONFIG* Config)
{
    ULONG i, j;
    const ULONG bucketCount = Config->Gscan.BucketCount;
    if (bucketCount == 0 || bucketCount > AP6256_PNO_BUCKET_MAX) return STATUS_INVALID_PARAMETER;
    if (Config->ChannelCount == 0 || Config->ChannelCount > AP6256_PNO_CHANNEL_MAX ||
        Config->Gscan.Version != 1 || (Config->Gscan.Flags & ~1u) != 0 ||
        Config->Gscan.BucketCount == 0 || Config->Gscan.BucketCount > AP6256_PNO_BUCKET_MAX ||
        Config->Gscan.BufferThreshold > 101 || Config->Gscan.RssiWindow < 4 ||
        Config->Gscan.RssiWindow > 8 || Config->Gscan.LostApWindow > 255 ||
        (Config->Options & ~15u) != 0 || Config->SwcCount > AP6256_PNO_SWC_MAX)
        return STATUS_INVALID_PARAMETER;
    for (i = 0; i < Config->ChannelCount; ++i) {
        if (Config->Channels[i] == 0 || Config->Channels[i] > 255) return STATUS_INVALID_PARAMETER;
        for (j = 0; j < i; ++j)
            if (Config->Channels[i] == Config->Channels[j]) return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < bucketCount; ++i) {
        const AP6256_PNO_BUCKET* bucket = &Config->Gscan.Buckets[i];
        if (bucket->EndIndex >= Config->ChannelCount || bucket->FrequencyMultiple == 0 ||
            (bucket->Flags != 0 && bucket->Flags != 2) ||
            (i != 0 && bucket->EndIndex <= Config->Gscan.Buckets[i - 1].EndIndex))
            return STATUS_INVALID_PARAMETER;
    }
    if (Config->Gscan.Buckets[bucketCount - 1].EndIndex != Config->ChannelCount - 1)
        return STATUS_INVALID_PARAMETER;
    if ((Config->Options & AP6256_PNO_USE_SWC) != 0) {
        if (Config->SwcCount == 0 || Config->Gscan.SwcThreshold == 0 ||
            Config->Gscan.SwcThreshold > Config->SwcCount) return STATUS_INVALID_PARAMETER;
        for (i = 0; i < Config->SwcCount; ++i) {
            const AP6256_PNO_SWC_ENTRY* entry = &Config->Swc[i];
            if (!Ap6256PnoUnicast(entry->Bssid) || entry->RssiLow >= entry->RssiHigh ||
                entry->RssiHigh > 0) return STATUS_INVALID_PARAMETER;
            for (j = 0; j < i; ++j)
                if (RtlEqualMemory(entry->Bssid, Config->Swc[j].Bssid, 6)) return STATUS_INVALID_PARAMETER;
        }
    } else if (Config->SwcCount != 0 || Config->Gscan.SwcThreshold != 0) return STATUS_INVALID_PARAMETER;
    if ((Config->Options & AP6256_PNO_USE_MAC) != 0 &&
        !NT_SUCCESS(Ap6256PnoValidateMac(&Config->Mac))) return STATUS_INVALID_PARAMETER;
    if ((Config->Options & AP6256_PNO_USE_OVERRIDE) != 0 &&
        !NT_SUCCESS(Ap6256PnoValidateOverride(&Config->Override))) return STATUS_INVALID_PARAMETER;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
BOOLEAN Ap6256PnoConfigNeedsGscan(const AP6256_PNO_CONFIG* Config)
{

    return (BOOLEAN)(Config->Gscan.BucketCount != 1 ||
        Config->Gscan.Buckets[0].FrequencyMultiple != 1 || Config->Gscan.Buckets[0].Flags != 0 ||
        Config->Gscan.Flags != 0 || Config->Gscan.BufferThreshold != 0 ||
        Config->Gscan.SwcThreshold != 0 || Config->Gscan.RssiWindow != 4 ||
        Config->Gscan.LostApWindow != 0 ||
        (Config->Gscan.RetryThreshold != 0 && Config->Gscan.RetryThreshold != 3) ||
        (Config->Options & AP6256_PNO_USE_SWC) != 0);
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoGetEnabledLocked(PAP6256_DEVICE_CONTEXT Ctx, UINT32* Enabled)
{
    AP6256_BCDC_QUERY_RESULT reply = {0};
    UINT32 value = MAXUINT32;
    NTSTATUS status = Ap6256BcdcGetIovarResultIf(Ctx, 0, "pfn", &value, sizeof(value), &reply);
    if (!NT_SUCCESS(status)) return status;
    if (!reply.FirmwareReply || reply.FirmwareError || reply.PayloadLength < sizeof(value) || value > 1)
        return STATUS_DEVICE_PROTOCOL_ERROR;
    *Enabled = value;
    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoApplyChannelsLocked(PAP6256_DEVICE_CONTEXT Ctx, const AP6256_PNO_CONFIG* Config)
{
    struct { UINT32 ReportType, Count; UINT16 Channels[64]; UINT32 Flags; } channels = {0};
    UINT32 enabled;
    NTSTATUS status = Ap6256PnoValidateConfig(Config);
    C_ASSERT(sizeof(channels) == 140);
    if (!NT_SUCCESS(status)) return status;
    if (!Ctx->FirmwareEnhancedPnoSupported) return STATUS_NOT_SUPPORTED;
    status = Ap6256PnoGetEnabledLocked(Ctx, &enabled);
    if (!NT_SUCCESS(status)) return status;
    if (enabled != 0) return STATUS_DEVICE_BUSY;

    status = Ap6256WifiPnoChannels(Ctx, (AP6256_PNO_CONFIG*)Config, FALSE);
    if (!NT_SUCCESS(status)) return status;
    channels.Count = Config->ChannelCount;
    RtlCopyMemory(channels.Channels, Config->Channels, Config->ChannelCount * sizeof(UINT16));
    return Ap6256BcdcSetIovar(Ctx, "pfn_cfg", &channels, sizeof(channels));
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoApplyConfig(PAP6256_DEVICE_CONTEXT Ctx, const AP6256_PNO_CONFIG* Config)
{
    NTSTATUS status;
    ULONG bucket;

    status = Ap6256PnoValidateConfig(Config);
    if (!NT_SUCCESS(status)) return status;
    if (!Ap6256PnoConfigNeedsGscan(Config)) {
        status = Ap6256PnoApplyChannelsLocked(Ctx, Config);
        if (NT_SUCCESS(status) && (Config->Options & AP6256_PNO_USE_MAC) != 0)
            status = Ap6256BcdcSetIovar(Ctx, "pfn_macaddr", (PVOID)&Config->Mac, sizeof(Config->Mac));
        return status;
    }
    if (!Ctx->FirmwarePnoGscanSupported) return STATUS_NOT_SUPPORTED;
    if (!Ctx->FirmwarePnoExtendedEvents) {
        if ((Config->Options & AP6256_PNO_USE_SWC) != 0) return STATUS_NOT_SUPPORTED;
        for (bucket = 0; bucket < Config->Gscan.BucketCount; ++bucket)
            if (Config->Gscan.Buckets[bucket].Flags == 2) return STATUS_NOT_SUPPORTED;
    }
    status = Ap6256PnoApplyChannelsLocked(Ctx, Config);
    if (!NT_SUCCESS(status)) return status;
    status = Ap6256BcdcSetIovar(Ctx, "pfn_gscan_cfg", (PVOID)&Config->Gscan,
        10u + 4u * Config->Gscan.BucketCount);
    if (!NT_SUCCESS(status)) return status;
    if ((Config->Options & AP6256_PNO_USE_SWC) != 0) {
        status = Ap6256BcdcSetIovar(Ctx, "pfn_add_swc_bssid", (PVOID)Config->Swc,
            Config->SwcCount * sizeof(AP6256_PNO_SWC_ENTRY));
        if (!NT_SUCCESS(status)) return status;
    }
    if ((Config->Options & AP6256_PNO_USE_MAC) != 0) {
        status = Ap6256BcdcSetIovar(Ctx, "pfn_macaddr", (PVOID)&Config->Mac, sizeof(Config->Mac));
        if (!NT_SUCCESS(status)) return status;
    }

    return status;
}

_Use_decl_annotations_
NTSTATUS Ap6256PnoControl(PAP6256_DEVICE_CONTEXT Ctx, const UCHAR* Request,
    ULONG Length, AP6256_PNO_STATUS* Status)
{
    AP6256_PNO_REQUEST header;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG payload;
    RtlZeroMemory(Status, sizeof(*Status));
    Status->Version = AP6256_PNO_VERSION;
    Status->Supported = Ctx->FirmwareEnhancedPnoSupported;
    Status->Reserved = Ctx->FirmwarePnoGscanSupported ? AP6256_PNO_STATUS_GSCAN : 0;
    if (Ctx->FirmwarePnoDelaySupported) Status->Reserved |= AP6256_PNO_STATUS_DELAY;
    Status->Enabled = MAXUINT32;
    if (Length < sizeof(header)) return STATUS_INVALID_BUFFER_SIZE;
    RtlCopyMemory(&header, Request, sizeof(header));
    if (header.Magic != AP6256_PNO_MAGIC) return STATUS_NOT_SUPPORTED;
    if (header.Version != AP6256_PNO_VERSION || header.Operation > AP6256_PNO_FLAGS)
        return STATUS_INVALID_PARAMETER;
    payload = Length - sizeof(header);
    if ((header.Operation <= AP6256_PNO_STOP && payload != 0) ||
        (header.Operation == AP6256_PNO_START && payload != sizeof(AP6256_PNO_START_PARAMS)) ||
        (header.Operation == AP6256_PNO_OVERRIDE && payload != sizeof(AP6256_PNO_OVERRIDE_PARAMS)) ||
        (header.Operation == AP6256_PNO_MAC && payload != sizeof(AP6256_PNO_MAC_PARAMS)) ||
        (header.Operation == AP6256_PNO_FLAGS && payload != 1)) return STATUS_INVALID_BUFFER_SIZE;
    if (!Ctx->FirmwareEnhancedPnoSupported)
        return header.Operation == AP6256_PNO_QUERY ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
    if (Ctx->FirmwareState != Ap6256FwRunning || !Ctx->DatapathRunning) return STATUS_DEVICE_NOT_READY;
    if (header.Operation == AP6256_PNO_START) {
        AP6256_PNO_START_PARAMS* start;
        AP6256_NLO_PARAMS* nlo;
        ULONG i;
        start = (AP6256_PNO_START_PARAMS*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*start), AP6256_POOL_TAG);
        nlo = (AP6256_NLO_PARAMS*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*nlo), AP6256_POOL_TAG);
        if (start == NULL || nlo == NULL) status = STATUS_INSUFFICIENT_RESOURCES;
        else {
            RtlCopyMemory(start, Request + sizeof(header), sizeof(*start));
            if (start->NetworkCount == 0 || start->NetworkCount > AP6256_NLO_NETWORK_MAX)
                status = STATUS_INVALID_PARAMETER;
            nlo->Enable = TRUE;
            nlo->ScanPeriodSeconds = start->ScanPeriodSeconds;
            nlo->NetworkCount = start->NetworkCount;
            for (i = 0; NT_SUCCESS(status) && i < start->NetworkCount; ++i) {
                const AP6256_PNO_NETWORK* source = &start->Networks[i];
                AP6256_NLO_NETWORK* net = &nlo->Networks[i];
                if (source->DirectedProbePermitted > 1) { status = STATUS_INVALID_PARAMETER; break; }
                net->SsidLength = source->SsidLength;
                net->AuthAlgorithm = source->AuthAlgorithm;
                net->CipherAlgorithm = source->CipherAlgorithm;
                net->DirectedProbePermitted = (BOOLEAN)source->DirectedProbePermitted;
                RtlCopyMemory(net->Ssid, source->Ssid, sizeof(net->Ssid));
            }
            if (NT_SUCCESS(status)) status = Ap6256WifiSetEnhancedNetworkListOffload(Ctx, nlo, &start->Config);
        }
        if (start != NULL) ExFreePoolWithTag(start, AP6256_POOL_TAG);
        if (nlo != NULL) ExFreePoolWithTag(nlo, AP6256_POOL_TAG);
        if (NT_SUCCESS(status)) Status->Enabled = 1;
        return status;
    }
    if (header.Operation == AP6256_PNO_FLAGS && !Ctx->FirmwarePnoGscanSupported)
        return STATUS_NOT_SUPPORTED;
    Ap6256LockAcquire(&Ctx->PnoLock);
    if (header.Operation == AP6256_PNO_STOP) {
        UINT32 off = 0;
        Ap6256PnoResultsReset(Ctx);
        status = Ap6256BcdcSetIovar(Ctx, "pfn", &off, sizeof(off));
        if (NT_SUCCESS(status)) status = Ap6256PnoGetEnabledLocked(Ctx, &Status->Enabled);
        if (NT_SUCCESS(status) && Status->Enabled != 0) status = STATUS_DEVICE_PROTOCOL_ERROR;
        if (NT_SUCCESS(status)) status = Ap6256BcdcSetIovar(Ctx, "pfnclear", NULL, 0);
    } else if (header.Operation == AP6256_PNO_OVERRIDE) {
        AP6256_PNO_OVERRIDE_PARAMS params;
        RtlCopyMemory(&params, Request + sizeof(header), sizeof(params));
        status = Ap6256PnoValidateOverride(&params);
        if (NT_SUCCESS(status)) status = Ap6256BcdcSetIovar(Ctx, "pfn_override", &params, sizeof(params));
    } else if (header.Operation == AP6256_PNO_MAC) {
        AP6256_PNO_MAC_PARAMS params;
        RtlCopyMemory(&params, Request + sizeof(header), sizeof(params));
        status = Ap6256PnoValidateMac(&params);
        if (NT_SUCCESS(status)) status = Ap6256BcdcSetIovar(Ctx, "pfn_macaddr", &params, sizeof(params));
    } else if (header.Operation == AP6256_PNO_FLAGS) {
        UCHAR flags[14] = {1, 0, 0x80};
        if (Length != sizeof(header) + 1) { Ap6256LockRelease(&Ctx->PnoLock); return STATUS_INVALID_BUFFER_SIZE; }
        if ((Request[sizeof(header)] & ~1u) != 0) status = STATUS_INVALID_PARAMETER;
        else {
            flags[2] |= Request[sizeof(header)];
            status = Ap6256BcdcSetIovar(Ctx, "pfn_gscan_cfg", flags, sizeof(flags));
        }
    }
    if (NT_SUCCESS(status)) status = Ap6256PnoGetEnabledLocked(Ctx, &Status->Enabled);
    Ap6256LockRelease(&Ctx->PnoLock);
    return status;
}
