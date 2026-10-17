# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"Check the production secondary-role capabilities with Microsoft's TLV codec."
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text, _functions
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]
HOST_CODEC_MEMORY = r'''
void* __cdecl operator new(size_t n, ULONG_PTR context) noexcept {
    assert(context == 0); return malloc(n);
}
void __cdecl operator delete(void* p, size_t size) noexcept {
    (void)size; free(p);
}
void __cdecl operator delete[](void* p, size_t size) noexcept {
    (void)size; free(p);
}
'''
PREAMBLE = r'''
#define AP6256_SERVICE_MAX 4u
#define AP6256_FTM_TARGET_MAX 4u
#define AP6256_SERVICE_NAME_MAX 200u
#define AP6256_SERVICE_INFO_MAX 768u
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define NDIS_SUPPORT_NDIS620 1
#define NDIS_SUPPORT_NDIS630 1
#include <ntddndis.h>
#define WIFICX_TEMPORARY_REMOVED_FOR_USERMODE
#include <dot11wificxintf.h>
#include <dot11wificxtypes.hpp>
#include <TlvGeneratorParser.hpp>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <new>
#define TraceDiag(...) ((void)0)
#ifndef TraceVerbose
#define TraceVerbose(t,...) TraceDiag(__VA_ARGS__)
#endif

size_t testPoolAllocations = 0, testPoolFrees = 0;
''' + HOST_CODEC_MEMORY + r'''
struct Device {
    struct { ULONG ChipId = 0x4345, ChipRev = 9; } Chip;
    BOOLEAN FirmwareP2pSupported, FirmwareMchanSupported, FirmwareServiceOffload;
    BOOLEAN FirmwareMfpSupported, FirmwareSaeSupported;
    BOOLEAN FirmwarePrivateSae, FirmwareExternalAuth;
    BOOLEAN FirmwareNativeManagement, FirmwareBssTransitionEnabled;
    BOOLEAN FirmwareFtmSupported;
    BOOLEAN HostFipsReady;
    BOOLEAN FirmwareFtPatchVerified, FirmwareHostFt;
    BOOLEAN FirmwareOwePatchVerified, FirmwareHostOwe;
    ULONG CapabilityHead=0x12345678u;
    @WIFICX_CAPABILITY_FIELDS@
    ULONG CapabilityTail=0x87654321u;
    BOOLEAN FirmwareHostCipherPatchVerified;
    volatile LONG HostCipherFirmwareQualified, HostCipherBlockedMask, FirmwareHalted;
    LONG FirmwareState;
    struct { volatile LONG Ready; } HostCipherStore;
    struct { UCHAR DeviceAddress[6]; } P2p;
};
enum {Ap6256FwNotLoaded, Ap6256FwDownloading, Ap6256FwRunning};
struct WifiState { Device* Ctx; TLV_CONTEXT TlvContext; struct { BOOLEAN Enabled; } Mbo; };
static unsigned capabilityCases = 0;
static void check(bool enabled, bool localAddress, bool mchan, bool handoff, bool wnm,
                  bool ftPatch=false, bool ftAbi=false, bool privateSae=false,
                  bool externalAuth=false, ULONG peerVersion=AP6256_WDI_VERSION,
                  bool owePatch=false, bool oweAbi=false, bool service=false, bool mbo=false, bool ftm=false, bool fips=false,
                  bool hcPatch=false, LONG hcQualified=0, bool hcProvider=false,
                  bool hcHalt=false, bool hcRetired=false, LONG hcState=Ap6256FwRunning,
                  ULONG chipId=0x4345, ULONG chipRev=9) {
    Device device = {};
    device.Chip.ChipId=chipId;device.Chip.ChipRev=chipRev;
    device.FirmwareP2pSupported = enabled;
    device.FirmwareMchanSupported = mchan;
    device.FirmwareServiceOffload = service;
    device.FirmwareMfpSupported = enabled;
    device.FirmwareSaeSupported = enabled;
    device.FirmwarePrivateSae = privateSae;
    device.FirmwareExternalAuth = externalAuth;
    device.FirmwareNativeManagement = handoff;
    device.FirmwareBssTransitionEnabled = wnm;
    device.FirmwareFtmSupported=ftm;
    device.HostFipsReady=fips;
    device.FirmwareFtPatchVerified = ftPatch;
    device.FirmwareHostFt = ftAbi;
    device.FirmwareOwePatchVerified = owePatch; device.FirmwareHostOwe = oweAbi;
    device.FirmwareHostCipherPatchVerified = hcPatch;
    device.HostCipherFirmwareQualified = hcQualified;
    device.HostCipherStore.Ready = hcProvider;
    device.FirmwareHalted = hcHalt;
    device.HostCipherBlockedMask = hcRetired ? (LONG)AP6256_HC_FIRMWARE_RETIRED : 0;
    device.FirmwareState = hcState;
    const UCHAR mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(device.P2p.DeviceAddress, mac, sizeof(mac));
    if (localAddress) device.P2p.DeviceAddress[0] |= 2;
    WifiState wifi = {};
    wifi.Ctx = &device;
    wifi.Mbo.Enabled = mbo;
    wifi.TlvContext.PeerVersion = peerVersion;
    WifiState* Wifi = &wifi;
    WDI_GET_ADAPTER_CAPABILITIES_PARAMETERS caps = {};
    CHAR firmware[] = "test";
    caps.InterfaceAttributes.FirmwareVersion.ElementCount = sizeof(firmware);
    caps.InterfaceAttributes.FirmwareVersion.pElements = firmware;
    caps.StationAttributes.StationCapabilities.KeyMappingTableSize = 16;
    caps.StationAttributes.StationCapabilities.ScanSSIDListSize = 4;
'''
CHECKS = r'''
    TLV_CONTEXT context = {};
    context.PeerVersion = peerVersion;
    UCHAR* bytes = NULL;
    ULONG length = 0;
    NDIS_STATUS status = GenerateWdiGetAdapterCapabilitiesFromIhv(
        &caps, 0, &context, &length, &bytes);
    if (status != 0) fprintf(stderr, "Generate failed: 0x%08lx (enabled %d)\n", status, enabled);
    assert(status == 0 && bytes != NULL && length > 0);
    WDI_GET_ADAPTER_CAPABILITIES_PARAMETERS parsed = {};
    status = ParseWdiGetAdapterCapabilitiesFromIhv(length, bytes, &context, &parsed);
    assert(status == 0);
    if (TEST_NATIVE_WIFI_REPLAY) {




        bool unicastAuth[12] = {}, multicastAuth[12] = {};
        const auto& uni = parsed.StationAttributes.UnicastAlgorithms;
        const auto& multi = parsed.StationAttributes.MulticastDataAlgorithms;
        for (ULONG i = 0; i < uni.ElementCount; ++i) {
            const auto& pair = uni.pElements[i];
            assert((ULONG)pair.AuthAlgorithm < RTL_NUMBER_OF(unicastAuth));
            if (pair.CipherAlgorithm == WDI_CIPHER_ALGO_GCMP_256 &&
                (pair.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT ||
                 pair.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE ||
                 pair.AuthAlgorithm == WDI_AUTH_ALGO_OWE)) continue;
            unicastAuth[(ULONG)pair.AuthAlgorithm] = true;
        }
        for (ULONG i = 0; i < multi.ElementCount; ++i) {
            assert((ULONG)multi.pElements[i].AuthAlgorithm < RTL_NUMBER_OF(multicastAuth));
            multicastAuth[(ULONG)multi.pElements[i].AuthAlgorithm] = true;
        }
        for (ULONG auth = 0; auth < RTL_NUMBER_OF(unicastAuth); ++auth) {
            if (unicastAuth[auth] != multicastAuth[auth])
                fprintf(stderr, "Native Wi-Fi authentication set mismatch: auth %lu, unicast %u, multicast %u\n",
                    auth, unsigned(unicastAuth[auth]), unsigned(multicastAuth[auth]));
            assert(unicastAuth[auth] == multicastAuth[auth]);
        }
    }
    assert(!!parsed.InterfaceAttributes.InterfaceCapabilities.CannotSupportMiracastSink == !enabled);
    assert(parsed.InterfaceAttributes.InterfaceCapabilities.NumChannels == (mchan ? 2 : 1));
    assert(parsed.InterfaceAttributes.InterfaceCapabilities.Support_eCSA);
    assert(parsed.InterfaceAttributes.InterfaceCapabilities.ActionFramesSupported);
    const auto& iface = parsed.InterfaceAttributes.InterfaceCapabilities;
    const auto& sta = parsed.StationAttributes.StationCapabilities;
    assert(!!iface.FastTransitionSupported == (ftPatch && ftAbi));
    assert(!!sta.MFPCapable == enabled);
    const bool expectedSae = enabled &&
        (privateSae || externalAuth) && peerVersion >= WDI_VERSION_1_1_10;
    assert(!!iface.SAEAuthenticationSupported == expectedSae);
    const bool expectedOwe = enabled && owePatch && oweAbi && peerVersion >= WDI_VERSION_1_1_10;
    assert(!!iface.MBOSupported == (mbo && enabled && handoff && wnm));
    assert(!!iface.BeaconReportsImplemented == handoff);
    assert(!!iface.BSSTransitionSupported == (handoff && wnm));
    assert(!iface.IPDockingSupported && !sta.HostWPA3FIPSModeEnabled);
    assert(sta.HostFIPSModeImplemented==(fips?DOT11_EXTSTA_ATTRIBUTES_SAFEMODE_OID_SUPPORTED:0));
    assert(!!sta.FTMAsInitiatorSupport==ftm && sta.FTMNumberOfSupportedTargets==(ftm?4u:0u));
    const bool expectedHc = TEST_HC_WIRING && peerVersion >= WDI_VERSION_1_1_9 && hcPatch &&
        hcQualified == 1 && hcProvider && !hcHalt && !hcRetired && hcState == Ap6256FwRunning;
    const ULONG enterpriseCcmp = TEST_ENTERPRISE_CCMP && enabled && peerVersion >= WDI_VERSION_1_1_9 &&
        chipId == 0x4345 && chipRev == 9;
    const ULONG expectedGcmp = expectedHc ? 2u + (enabled ? 2u : 0u) + expectedSae + expectedOwe : 0u;
    const ULONG expectedGmac = expectedHc && enabled ? 4u + expectedSae + expectedOwe : 0u;
    if(parsed.StationAttributes.UnicastAlgorithms.ElementCount != 3u + expectedSae + expectedOwe + expectedGcmp + enterpriseCcmp)
        fprintf(stderr,"Host capability mismatch: MFP %d, patch %d, ABI %ld, CNG %d, halt %d, retired %d, state %ld, Windows 0x%08lx: data pairs %lu expected %lu\n",
            enabled,hcPatch,hcQualified,hcProvider,hcHalt,hcRetired,hcState,peerVersion,
            parsed.StationAttributes.UnicastAlgorithms.ElementCount,3u+expectedSae+expectedOwe+expectedGcmp+enterpriseCcmp);
    assert(parsed.StationAttributes.UnicastAlgorithms.ElementCount == 3u + expectedSae + expectedOwe + expectedGcmp + enterpriseCcmp);
    assert(parsed.StationAttributes.MulticastDataAlgorithms.ElementCount == 3u + expectedSae + expectedOwe + expectedGcmp + enterpriseCcmp);
    assert(parsed.StationAttributes.MulticastManagementAlgorithms.ElementCount == 2u + expectedSae + expectedOwe + expectedGmac + enterpriseCcmp);
    unsigned enterpriseUni = 0, enterpriseMulti = 0, enterpriseManagement = 0;
    for (ULONG i = 0; i < parsed.StationAttributes.UnicastAlgorithms.ElementCount; ++i) {
        const auto& pair = parsed.StationAttributes.UnicastAlgorithms.pElements[i];
        enterpriseUni += pair.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT && pair.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP;
    }
    for (ULONG i = 0; i < parsed.StationAttributes.MulticastDataAlgorithms.ElementCount; ++i) {
        const auto& pair = parsed.StationAttributes.MulticastDataAlgorithms.pElements[i];
        enterpriseMulti += pair.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT && pair.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP;
    }
    for (ULONG i = 0; i < parsed.StationAttributes.MulticastManagementAlgorithms.ElementCount; ++i) {
        const auto& pair = parsed.StationAttributes.MulticastManagementAlgorithms.pElements[i];
        enterpriseManagement += pair.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_ENT && pair.CipherAlgorithm == WDI_CIPHER_ALGO_BIP;
    }
    assert(enterpriseUni == enterpriseCcmp && enterpriseMulti == enterpriseCcmp && enterpriseManagement == enterpriseCcmp);
    const WDI_AUTH_ALGORITHM hostAuths[] = {WDI_AUTH_ALGO_RSNA_PSK,WDI_AUTH_ALGO_RSNA,
        WDI_AUTH_ALGO_WPA3_ENT,WDI_AUTH_ALGO_WPA3_ENT_192,WDI_AUTH_ALGO_WPA3_SAE,WDI_AUTH_ALGO_OWE};
    for (auto algorithm : hostAuths) {
        const bool authAvailable = algorithm == WDI_AUTH_ALGO_WPA3_SAE ? expectedSae :
            algorithm == WDI_AUTH_ALGO_OWE ? expectedOwe :
            (algorithm == WDI_AUTH_ALGO_WPA3_ENT || algorithm == WDI_AUTH_ALGO_WPA3_ENT_192) ? enabled : true;
        unsigned unicast=0,multicast=0,management=0;
        const auto& uni=parsed.StationAttributes.UnicastAlgorithms;
        const auto& multi=parsed.StationAttributes.MulticastDataAlgorithms;
        const auto& mgmt=parsed.StationAttributes.MulticastManagementAlgorithms;
        for(ULONG i=0;i<uni.ElementCount;i++)
            unicast += uni.pElements[i].AuthAlgorithm==algorithm && uni.pElements[i].CipherAlgorithm==WDI_CIPHER_ALGO_GCMP_256;
        for(ULONG i=0;i<multi.ElementCount;i++)
            multicast += multi.pElements[i].AuthAlgorithm==algorithm && multi.pElements[i].CipherAlgorithm==WDI_CIPHER_ALGO_GCMP_256;
        for(ULONG i=0;i<mgmt.ElementCount;i++)
            management += mgmt.pElements[i].AuthAlgorithm==algorithm && mgmt.pElements[i].CipherAlgorithm==WDI_CIPHER_ALGO_BIP_GMAC_256;
        assert(unicast==unsigned(expectedHc && authAvailable) && multicast==unicast);
        assert(management==unsigned(expectedHc && enabled && authAvailable));
    }
    assert(parsed.StationAttributes.UnicastAlgorithms.pElements[1].AuthAlgorithm == WDI_AUTH_ALGO_RSNA_PSK);
    assert(parsed.StationAttributes.UnicastAlgorithms.pElements[1].CipherAlgorithm == WDI_CIPHER_ALGO_CCMP);
    assert(parsed.StationAttributes.UnicastAlgorithms.pElements[2].AuthAlgorithm == WDI_AUTH_ALGO_RSNA);
    assert(parsed.StationAttributes.UnicastAlgorithms.pElements[2].CipherAlgorithm == WDI_CIPHER_ALGO_CCMP);
    assert(parsed.StationAttributes.MulticastManagementAlgorithms.pElements[1].AuthAlgorithm == WDI_AUTH_ALGO_RSNA);
    assert(parsed.StationAttributes.MulticastManagementAlgorithms.pElements[1].CipherAlgorithm == WDI_CIPHER_ALGO_BIP);
    if (expectedSae) {
        const auto& unicast = parsed.StationAttributes.UnicastAlgorithms.pElements[3];
        const auto& multicast = parsed.StationAttributes.MulticastDataAlgorithms.pElements[3];
        const auto& management = parsed.StationAttributes.MulticastManagementAlgorithms.pElements[2];
        assert(unicast.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE);
        assert(unicast.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP);
        assert(multicast.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE);
        assert(multicast.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP);
        assert(management.AuthAlgorithm == WDI_AUTH_ALGO_WPA3_SAE);
        assert(management.CipherAlgorithm == WDI_CIPHER_ALGO_BIP);
    }
    if (expectedOwe) {
        const auto& pair = parsed.StationAttributes.UnicastAlgorithms.pElements[3 + expectedSae];
        const auto& mgmt = parsed.StationAttributes.MulticastManagementAlgorithms.pElements[2 + expectedSae];
        assert(pair.AuthAlgorithm == WDI_AUTH_ALGO_OWE && pair.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP);
        assert(mgmt.AuthAlgorithm == WDI_AUTH_ALGO_OWE && mgmt.CipherAlgorithm == WDI_CIPHER_ALGO_BIP);
    }


    if (fips) {
        assert(sta.HostFIPSModeImplemented == DOT11_EXTSTA_ATTRIBUTES_SAFEMODE_OID_SUPPORTED);
        assert(!sta.HostWPA3FIPSModeEnabled);
        for (unsigned which = 0; which < 2; ++which) {
            const auto& list = which == 0 ? parsed.StationAttributes.UnicastAlgorithms :
                                           parsed.StationAttributes.MulticastDataAlgorithms;
            bool openPair = false, personalPair = false, enterprisePair = false;
            for (ULONG i = 0; i < list.ElementCount; ++i) {
                const auto& pair = list.pElements[i];
                openPair |= pair.AuthAlgorithm == WDI_AUTH_ALGO_80211_OPEN && pair.CipherAlgorithm == WDI_CIPHER_ALGO_NONE;
                personalPair |= pair.AuthAlgorithm == WDI_AUTH_ALGO_RSNA_PSK && pair.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP;
                enterprisePair |= pair.AuthAlgorithm == WDI_AUTH_ALGO_RSNA && pair.CipherAlgorithm == WDI_CIPHER_ALGO_CCMP;
            }
            assert(openPair && personalPair && enterprisePair);
        }
    }
    if (parsed.Optional.P2PAttributes_IsPresent) {
        assert(parsed.Optional.VirtualizationAttributes_IsPresent);
        assert(parsed.Optional.APAttributes_IsPresent);

        assert(parsed.APAttributes.UnicastAlgorithms.ElementCount == 2);
        assert(parsed.APAttributes.MulticastDataAlgorithms.ElementCount == 2);
        assert(parsed.APAttributes.UnicastAlgorithms.pElements[0].AuthAlgorithm == WDI_AUTH_ALGO_80211_OPEN);
        assert(parsed.APAttributes.UnicastAlgorithms.pElements[1].AuthAlgorithm == WDI_AUTH_ALGO_RSNA_PSK);
        const auto& virt = parsed.VirtualizationAttributes.VirtualizationCapabilities;
        const auto& p2p = parsed.P2PAttributes;


        assert(p2p.InterfaceAddressList.ElementCount > 0);
        assert(p2p.InterfaceAddressList.ElementCount <= virt.WiFiDirectGroupCount);
        assert(p2p.P2PCapabilities.ConcurrentGOCount <= virt.WiFiDirectGroupCount);
        assert(p2p.P2PCapabilities.ConcurrentClientCount <= virt.WiFiDirectGroupCount);
        assert(virt.ExtSTACount == 1 && virt.WiFiDirectGroupCount == 1);
        assert(virt.SimultaneousSTAWFDClientCount == 2);
        assert(virt.SimultaneousMultiChannelOperationLimit == (mchan ? 2 : 1));
        assert(p2p.P2PCapabilities.MaxVendorSpecificExtensionIESize == 512);
        assert(!!p2p.P2PCapabilities.ServiceDiscoverySupported==service);
        assert(!!p2p.P2PCapabilities.ServiceNameDiscoverySupported==service);
        assert(!!p2p.P2PCapabilities.ServiceInformationDiscoverySupported==service);
        assert(p2p.P2PCapabilities.ServiceNameAdvertisementsMaxBytesSupported==(service?800u:0u));
        assert(p2p.P2PCapabilities.ServiceInformationAdvertisementsMaxBytesSupported==(service?3072u:0u));
        assert(p2p.P2PCapabilities.ConcurrentGOCount == 1);


        assert(p2p.P2PCapabilities.GOon5GHzBandSupported);


        assert(p2p.P2PCapabilities.ConcurrentClientCount >= 1);

        assert(parsed.APAttributes.APCapabilities.ScanSSIDListSize >= 4);
        assert(parsed.APAttributes.APCapabilities.DesiredSSIDListSize >= 1);
        assert(parsed.APAttributes.APCapabilities.PrivacyExemptionListSize >= 1);
        assert(parsed.APAttributes.APCapabilities.AssociationTableSize >= 1);
        assert(parsed.APAttributes.APCapabilities.AssociationTableSize <= 2007);
        assert(parsed.APAttributes.APCapabilities.DefaultKeyTableSize >= 4);
        assert(p2p.P2PCapabilities.DiscoveryFilterListSize >= 2);
        assert(p2p.P2PCapabilities.GOClientTableSize <=
               parsed.APAttributes.APCapabilities.KeyMappingTableSize);
        assert(memcmp(p2p.P2PCapabilities.DeviceAddress,
                      device.P2p.DeviceAddress, 6) == 0);
        const UCHAR* group = p2p.InterfaceAddressList.pElements[0].Address;
        assert((group[0] & 3) == 2);
        assert(memcmp(group, device.P2p.DeviceAddress, 6) != 0);
        UCHAR expected[6];
        memcpy(expected, device.P2p.DeviceAddress, 6);
        expected[0] |= 2;
        expected[5] ^= 0x80;
        assert(memcmp(group, expected, 6) == 0);
    }

    const bool expectedRoles = enabled;
    assert(!!parsed.Optional.VirtualizationAttributes_IsPresent == expectedRoles);
    assert(!!parsed.Optional.APAttributes_IsPresent == expectedRoles);
    assert(!!parsed.Optional.P2PAttributes_IsPresent == expectedRoles);
    CleanupParsedWdiGetAdapterCapabilitiesFromIhv(&parsed);
    FreeGenerated(bytes);
    ++capabilityCases;
}
static void checkApBandRequest() {
    TLV_CONTEXT os = {}, driver = {};
    os.PeerVersion = AP6256_WDI_VERSION;
    driver.PeerVersion = AP6256_WDI_VERSION;
    WDI_TASK_START_AP_PARAMETERS p = {}, decoded = {};
    UINT8 ssid[] = {'t','e','s','t'};
    WDI_AUTH_ALGORITHM auth = WDI_AUTH_ALGO_RSNA_PSK;
    WDI_CIPHER_ALGORITHM cipher = WDI_CIPHER_ALGO_CCMP;
    WDI_CHANNEL_NUMBER channels[] = {36, 44};
    WDI_AP_BAND_CHANNEL_LIST_CONTAINER band = {};
    p.DesiredSSID.pElements = ssid;
    p.DesiredSSID.ElementCount = sizeof(ssid);
    p.AuthenticationAlgorithms.pElements = &auth;
    p.AuthenticationAlgorithms.ElementCount = 1;
    p.UnicastCipherAlgorithms.pElements = &cipher;
    p.UnicastCipherAlgorithms.ElementCount = 1;
    p.MulticastCipherAlgorithms.pElements = &cipher;
    p.MulticastCipherAlgorithms.ElementCount = 1;
    p.StaticParameters.BeaconPeriod = 100;
    p.StaticParameters.DTIMPeriod = 1;
    p.StaticParameters.ExcludeUnencrypted = TRUE;
    p.StaticParameters.MustUseSpecifiedChannels = TRUE;
    p.Optional.APBandChannelList_IsPresent = TRUE;
    p.APBandChannelList.ElementCount = 1;
    p.APBandChannelList.pElements = &band;
    band.BandID = WDI_BAND_ID_5000;
    band.Optional.ChannelList_IsPresent = TRUE;
    band.ChannelList.ElementCount = 2;
    band.ChannelList.pElements = channels;
    UINT8* bytes = nullptr;
    ULONG length = 0;
    assert(GenerateWdiTaskStartApToIhv(&p, 0, &os, &length, &bytes) == 0);
    assert(ParseWdiTaskStartApToIhv(length, bytes, &driver, &decoded) == 0);
    assert(decoded.StaticParameters.MustUseSpecifiedChannels);
    assert(decoded.StaticParameters.BeaconPeriod == 100);
    assert(decoded.Optional.APBandChannelList_IsPresent);
    assert(decoded.APBandChannelList.ElementCount == 1);
    const auto& parsedBand = decoded.APBandChannelList.pElements[0];
    assert(parsedBand.BandID == WDI_BAND_ID_5000);
    assert(parsedBand.Optional.ChannelList_IsPresent);
    assert(parsedBand.ChannelList.ElementCount == 2);
    assert(parsedBand.ChannelList.pElements[0] == 36);
    assert(parsedBand.ChannelList.pElements[1] == 44);
    CleanupParsedWdiTaskStartApToIhv(&decoded);
    FreeGenerated(bytes);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    for (int enabled = 0; enabled < 2; ++enabled)
        for (int local = 0; local < 2; ++local)
            for (int mchan = 0; mchan < 2; ++mchan)
                for (int handoff = 0; handoff < 2; ++handoff)
                    for (int wnm = 0; wnm < 2; ++wnm)
                        check(enabled != 0, local != 0, mchan != 0, handoff != 0, wnm != 0);
    check(true,false,true,true,true,false,false,false,false,AP6256_WDI_VERSION,false,false,true);
    check(true,false,true,true,true,false,false,false,false,AP6256_WDI_VERSION,false,false,true,true,true);
    check(true,false,true,true,true,false,false,false,false,AP6256_WDI_VERSION,false,false,true,true,true,true);
    checkApBandRequest();
    if(TEST_HC_WIRING) {
        const ULONG hostCipherVersions[] = {WDI_VERSION_1_1_8,WDI_VERSION_1_1_9,WDI_VERSION_1_1_10};
        for(int mfp=0;mfp<2;mfp++) for(int sae=0;sae<2;sae++) for(int owe=0;owe<2;owe++)
        for(ULONG version:hostCipherVersions) for(int patch=0;patch<2;patch++) for(LONG qualified=-1;qualified<=1;qualified++)
        for(int provider=0;provider<2;provider++) for(int halt=0;halt<2;halt++)
        for(int retired=0;retired<2;retired++) for(LONG state=0;state<3;state++)
            check(mfp!=0,false,true,true,true,false,false,sae!=0,false,version,owe!=0,owe!=0,
                false,false,false,false,patch!=0,qualified,provider!=0,halt!=0,retired!=0,state);
        for (int ready = 0; ready < 2; ++ready)
            check(true,false,true,true,true,false,false,true,false,AP6256_WDI_VERSION,true,true,
                false,false,false,true,ready!=0,ready,ready!=0);
    }
    assert(testPoolAllocations != 0 && testPoolAllocations == testPoolFrees);
    printf("PASS: %u capability cases; real Microsoft TLV codec, SAE backend/MFP/peer-version gates and consistent CCMP/BIP lists; 5 GHz GO, AP bands/channels and shared group port\n", capabilityCases);
}
'''

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source', type=Path, default=ROOT / 'src/common/netadapter.c')
    ap.add_argument('--contract', type=Path, default=ROOT / 'src/common/ap6256.h')
    ap.add_argument('--memory-source', type=Path, default=ROOT / 'src/common/tlv_memory.cpp')
    ap.add_argument('--output', type=Path, default=output_dir('wdi-capabilities'))
    ap.add_argument('--firmware-reports', action='store_true')
    ap.add_argument('--wdi-ft', action='store_true')
    ap.add_argument('--wdi-sae', action='store_true')
    ap.add_argument('--wdi-owe', action='store_true')
    ap.add_argument('--algo-model', choices=('wdi', 'wificx'), default='wdi', help='Compile the production algorithm policy for this frontend')
    ap.add_argument('--native-wifi-replay', action='store_true', help='Require matching authentication sets after the captured WDI unicast filtering')
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    production = read_source_text(args.source, encoding='utf-8-sig')
    start = production.index('    const BOOLEAN advertiseSecondaryRoles =')
    end = production.rfind('\n    {', start, production.index('        UINT32 patterns =', start))
    assignments = production[start:end]
    for field in ('NumChannels', 'CannotSupportMiracastSink', 'Support_eCSA', 'ActionFramesSupported', 'FastTransitionSupported'):
        assignments += re.search('caps\\.InterfaceAttributes\\.InterfaceCapabilities\\.' + field + '\\s*=[^;]+;', production)[0] + '\n'
    security_start = production.index('    caps.StationAttributes.StationCapabilities.MFPCapable =')
    security_end = production.index('    TraceDiag("capabilities: MFP', security_start)
    assignments += production[security_start:security_end]
    helpers = ''
    pair_initializers = ''
    for name in ('Ap6256AlgoPairs', 'Ap6256MgmtAlgoPairs'):
        array = re.search('static const WDI_ALGO_PAIRS ' + name + '\\[\\] = \\{[\\s\\S]*?\\};', production)[0]
        pairs = re.findall('\\{\\s*(WDI_AUTH_\\w+)\\s*,\\s*(WDI_CIPHER_\\w+)\\s*\\}', array)
        helpers += f'static WDI_ALGO_PAIRS {name}[{len(pairs)}];\n'
        for (i, (auth, cipher)) in enumerate(pairs):
            pair_initializers += f'{name}[{i}].AuthAlgorithm = {auth};\n{name}[{i}].CipherAlgorithm = {cipher};\n'
    for name in ('Ap6256HostSaeAvailable', 'Ap6256HostOweAvailable', 'Ap6256HostCipherAvailable', 'Ap6256Wpa3EnterpriseAvailable', 'Ap6256CopyAlgoPairs', 'Ap6256AlgoPairCount', 'Ap6256HostFbtAvailable'):
        if name not in production:
            continue
        helper = _functions(production)[name].replace('PAP6256_WIFI', 'WifiState*').replace('PAP6256_DEVICE_CONTEXT', 'Device*') + '\n'
        if name == 'Ap6256HostFbtAvailable' and args.wdi_ft or (name == 'Ap6256HostSaeAvailable' and args.wdi_sae) or (name == 'Ap6256HostOweAvailable' and args.wdi_owe) or (name == 'Ap6256CopyAlgoPairs' and args.algo_model == 'wdi'):
            helper = '#define AP6256_ENABLE_WDI\n' + helper + '#undef AP6256_ENABLE_WDI\n'
        helpers += helper
    declaration = re.search('WDI_MAC_ADDRESS p2pInterfaces\\[[^\\]]+\\];', production)[0]
    constants = re.search('^#define\\s+AP6256_WDI_VERSION\\s+[^\\n]+', read_source_text(args.contract, encoding='utf-8-sig'), re.M)[0] + '\n'
    constants += '#define TEST_WDI_FT ' + str(int(args.wdi_ft)) + '\n'
    constants += '#define TEST_WDI_SAE ' + str(int(args.wdi_sae)) + '\n'
    constants += '#define TEST_WDI_OWE ' + str(int(args.wdi_owe)) + '\n'
    constants += '#define TEST_HC_WIRING ' + str(int('Ap6256HostCipherAvailable' in production)) + '\n'
    constants += '#define TEST_ENTERPRISE_CCMP ' + str(int(bool(re.search('\\{\\s*WDI_AUTH_ALGO_WPA3_ENT\\s*,\\s*WDI_CIPHER_ALGO_CCMP\\s*\\}', production)))) + '\n'
    constants += '#define TEST_NATIVE_WIFI_REPLAY ' + str(int(args.native_wifi_replay)) + '\n'
    constants += '#define AP6256_HC_FIRMWARE_RETIRED 0x80000000u\n'
    headers = '\n'.join((read_source_text(ROOT / 'src' / f) for f in ('ap6256.h', 'p2p.h', 'hotspot.h')))
    for name in ('AP6256_GO_CLIENTS', 'AP6256_P2P_SECONDARY_MAX', 'AP6256_P2P_CLIENT_ROLES', 'AP6256_P2P_VENDOR_IE_MAX'):
        constants += re.search('^#define\\s+' + name + '\\s+[^\\n]+', headers, re.M)[0] + '\n'
    source = args.output / 'capability-tests.cpp'
    preamble = PREAMBLE.replace(HOST_CODEC_MEMORY, '').replace('static void check(', helpers + 'static void check(', 1)
    checks = CHECKS.replace('    checkApBandRequest();', r'''    for(bool verified:{false,true}) for(bool abi:{false,true})
        check(true,false,true,true,true,verified,abi);
    checkApBandRequest();''')
    checks = checks.replace('    checkApBandRequest();', r'''    for(int mfp=0;mfp<2;++mfp) for(int sae=0;sae<2;++sae)
        for(int op=0;op<2;++op) for(int oa=0;oa<2;++oa)
            check(mfp!=0,false,true,true,true,true,true,sae!=0,false,AP6256_WDI_VERSION,op!=0,oa!=0);
    checkApBandRequest();''')
    checks = checks.replace('for(bool verified:{false,true}) for(bool abi:{false,true})', 'for(int verified=0;verified<2;++verified) for(int abi=0;abi<2;++abi)')
    checks = checks.replace('    checkApBandRequest();', r'''    for(int mfp=0;mfp<2;++mfp) for(int native=0;native<2;++native)
        for(int btm=0;btm<2;++btm) for(int qualified=0;qualified<2;++qualified)
            check(mfp!=0,false,true,native!=0,btm!=0,false,false,false,false,AP6256_WDI_VERSION,false,false,false,qualified!=0);
    checkApBandRequest();''')
    checks = checks.replace('    checkApBandRequest();', r'''    for(ULONG chip=0;chip<2;++chip) for(ULONG revision=0;revision<2;++revision) for(int mfp=0;mfp<2;++mfp)
        check(mfp!=0,false,true,true,true,false,false,false,false,WDI_VERSION_1_1_10,false,false,false,false,false,false,false,0,false,false,false,Ap6256FwRunning,0x4345+chip,revision?9:6);
    checkApBandRequest();''')
    checks = checks.replace('    checkApBandRequest();', r'''    const ULONG versions[] = {WDI_VERSION_1_1_8, WDI_VERSION_1_1_9, WDI_VERSION_1_1_10};
    for(int mfp=0;mfp<2;++mfp) for(int priv=0;priv<2;++priv)
        for(int ext=0;ext<2;++ext) for(ULONG version:versions)
            check(mfp!=0,false,true,true,true,false,false,priv!=0,ext!=0,version);
    checkApBandRequest();''')
    cx = (ROOT / 'src/wificx/netadapter.c').read_text(encoding='utf-8-sig')
    fields = '\n'.join((line for line in (ROOT / 'src/wificx/device_fields.h').read_text(encoding='utf-8-sig').splitlines() if re.match('DOT11_AUTH_CIPHER_PAIR Wifi(?:Auth|Mgmt)Cipher\\[', line)))
    assert len(fields.splitlines()) == 2
    preamble = preamble.replace('@WIFICX_CAPABILITY_FIELDS@', fields)
    cx_copy = cx[cx.index('    for (index = 0; index < count; ++index) {'):cx.index('\n    WIFI_DEVICE_CAPABILITIES deviceCaps;')]
    copy_check = r'''
    {
        Device* ctx = &device;
        ULONG count=stationCount,index;
        WDI_ALGO_PAIRS* pairs=stationPairs;
        WDI_ALGO_PAIRS* management=managementPairs;
        @COPY@
        assert(ctx->CapabilityHead==0x12345678u&&ctx->CapabilityTail==0x87654321u);
        for(ULONG i=0;i<count;i++)
            assert((ULONG)ctx->WifiAuthCipher[i].AuthAlgoId==(ULONG)pairs[i].AuthAlgorithm&&
                   (ULONG)ctx->WifiAuthCipher[i].CipherAlgoId==(ULONG)pairs[i].CipherAlgorithm);
        for(ULONG i=0;i<managementCount;i++)
            assert((ULONG)ctx->WifiMgmtCipher[i].AuthAlgoId==(ULONG)management[i].AuthAlgorithm&&
                   (ULONG)ctx->WifiMgmtCipher[i].CipherAlgoId==(ULONG)management[i].CipherAlgorithm);
    }
'''.replace('@COPY@', cx_copy)
    write_text(source, ('#define AP6256_NATIVE_RRM\n' if args.firmware_reports else '') + constants + preamble + declaration + '\n' + pair_initializers + assignments + copy_check + checks, encoding='utf-8')
    write_text(args.output / 'ntddk.h', r'''
#pragma once

#pragma warning(disable: 5043)
#include <windows.h>
#include <stdlib.h>
#include <assert.h>
#define POOL_FLAG_NON_PAGED 64
extern size_t testPoolAllocations, testPoolFrees;
inline void* ExAllocatePool2(ULONG flags, size_t size, ULONG tag) {
    assert(flags == POOL_FLAG_NON_PAGED && tag == 0x74353641u);
    void* p = calloc(1, size);
    if (p) ++testPoolAllocations;
    return p;
}
inline void ExFreePoolWithTag(void* p, ULONG tag) {
    assert(p && tag == 0x74353641u);
    ++testPoolFrees;
    free(p);
}
''', encoding='utf-8')
    vc = VC
    sdk = SDK
    include = INC
    lib = LIB
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include'), '/I' + str(args.output.resolve())]
    command += ['/I' + str(include / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(source), str(args.memory_source.resolve()), '/Fe:' + str(args.output / 'capability-tests.exe'), '/Fo:' + str(args.output.resolve()) + '/', '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    result = subprocess.run([str(args.output / 'capability-tests.exe')], capture_output=True, text=True)
    write_text(args.output / 'run.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        print(result.stdout + result.stderr, end='')
        result.check_returncode()
    print(result.stdout, end='')
    cases = int(re.search('PASS: (\\d+) capability cases', result.stdout)[1])
    sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    paths = [p for p in (ROOT / 'src').rglob('*') if p.is_file() and p.suffix in ('.c', '.h', '.cpp', '.inc') and (p.name != 'buildstamp.h')]
    paths += [Path(__file__), ROOT / 'tests/driver_sources.py', ROOT / 'tests/source-layout.json']
    receipt = dict(checks=cases, sources={p.relative_to(ROOT).as_posix(): sha(p) for p in paths}, generated_sha256=sha(source), executable_sha256=sha(args.output / 'capability-tests.exe'), compiler_sha256=sha(Path(command[0])), codec_sha256=sha(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib'), runtime_gates_executed=True, mandatory_pmf_pairs_refused=True, actual_microsoft_codec=True, wificx_array_copy_executed=True, algorithm_model=args.algo_model, captured_native_wifi_auth_set_replay=args.native_wifi_replay, host_fips_capabilities_preserved=True, wificx_registration_is_fixture=True, association_qualified=False, board_verified=False)
    write_text(args.output / 'result.json', json.dumps(receipt, indent=2) + '\n', encoding='utf-8')
if __name__ == '__main__':
    main()
