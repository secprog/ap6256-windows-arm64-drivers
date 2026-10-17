# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"""Verify unsupported NS/GTK WDI add requests cannot program partial ARP state."""
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import subprocess
from driver_sources import _functions, read_source_text
ROOT = Path(__file__).resolve().parents[1]
PRE = r'''
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
void* __cdecl operator new(size_t n, ULONG_PTR context) noexcept {
    assert(context == 0); return malloc(n);
}
void __cdecl operator delete(void* p, size_t) noexcept { free(p); }
void __cdecl operator delete[](void* p, size_t) noexcept { free(p); }
typedef LONG NTSTATUS;
#undef STATUS_INVALID_PARAMETER
#undef STATUS_NOT_SUPPORTED
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xc0000001)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_DATA_ERROR ((NTSTATUS)0xc000003e)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xc000009a)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define NDIS_STATUS_INVALID_DATA ((NDIS_STATUS)0xc0010015)
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define AP6256_WDI_OPMODE_STA 0x01u
#define TRACE_NETADAPTER 0
#define TraceWarn(...) ((void)0)
#define AP6256_ARP_OFFLOAD_SLOTS 8u
#define AP6256_WOWL_ARP_OFFLOAD 0x1000u
#define TraceError(...) ((void)0)
struct Device {
    BOOLEAN HostFips = FALSE;
    UINT32 HostCipherMode = 0;
    BOOLEAN FirmwareArpOffloadSupported = TRUE;
    BOOLEAN FirmwareNdOffloadSupported = FALSE;
    BOOLEAN FirmwareGtkOffloadSupported = FALSE;
    UINT32 WowlCapabilities = AP6256_WOWL_ARP_OFFLOAD;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
static BOOLEAN Ap6256FipsActive(Device* d, UINT32 i) {assert(i == 0);return d->HostFips;}
static BOOLEAN Ap6256HostCipherPacketActive(Device* d, UINT32 i) {assert(i == 0);return d->HostCipherMode != 0;}
'''
MOCK = r'''
struct Wifi {
    int ConnectLock = 0;
    Device* Ctx;
    TLV_CONTEXT TlvContext = {};
    UINT32 PortOperationMode = AP6256_WDI_OPMODE_STA;
    BOOLEAN ArpOffloadValid[AP6256_ARP_OFFLOAD_SLOTS] = {};
    UINT32 ArpOffloadIds[AP6256_ARP_OFFLOAD_SLOTS] = {};
    WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER ArpOffloads[AP6256_ARP_OFFLOAD_SLOTS] = {};
    BOOLEAN GtkOffloadValid = FALSE;
    UINT32 GtkOffloadId = 0;
    AP6256_GTK_OFFLOAD GtkOffload = {};
    WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER NsOffloads[5] = {};
    ULONG NsOffloadCount = 0;
    WDI_CIPHER_ALGORITHM MulticastCipher = WDI_CIPHER_ALGO_CCMP;
    WDI_CIPHER_ALGORITHM MulticastMgmtCipher = WDI_CIPHER_ALGO_NONE;
    WDI_AUTH_ALGORITHM AuthAlgorithm = WDI_AUTH_ALGO_RSNA_PSK;
    struct { BOOLEAN MobilityDomainValid = FALSE; } Ft;
};
typedef Wifi* PAP6256_WIFI;
static void Ap6256LockAcquire(int*) {}
static void Ap6256LockRelease(int*) {}

typedef void* AP6256_REQUEST;
static NTSTATUS completion = STATUS_UNSUCCESSFUL;
static unsigned arpCalls = 0, nsCalls = 0, gtkCalls = 0, arpRemoves = 0;
static bool failNs = false;
static NTSTATUS Ap6256NdisToNtStatus(NDIS_STATUS status) {
    return (NTSTATUS)status;
}
static VOID Ap6256CompleteRequest(Wifi*, AP6256_REQUEST, NTSTATUS status) {
    completion = status;
}
static NTSTATUS Ap6256AddArpOffload(Wifi* wifi,
    const WDI_PM_PROTOCOL_OFFLOAD_IPv4ARP_CONTAINER* record) {
    ++arpCalls; wifi->ArpOffloadValid[0] = TRUE; wifi->ArpOffloadIds[0] = record->ProtocolOffloadId;
    wifi->ArpOffloads[0] = *record; return STATUS_SUCCESS;
}
static NTSTATUS Ap6256AddNsOffload(Wifi*,
    const WDI_PM_PROTOCOL_OFFLOAD_IPv6NS_CONTAINER*) {
    ++nsCalls; return failNs ? STATUS_UNSUCCESSFUL : STATUS_SUCCESS;
}
static NTSTATUS Ap6256RemoveArpOffloadId(Wifi* wifi, UINT32) {
    ++arpRemoves; wifi->ArpOffloadValid[0] = FALSE; wifi->ArpOffloadIds[0] = 0; wifi->ArpOffloads[0] = {};
    return STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetIovar(Device*, const char*, const void*, ULONG) {
    return STATUS_SUCCESS;
}
'''
TEST = r'''
static void add(Wifi& wifi, bool arp, bool ns, bool gtk, UINT32 arpId = 17, UINT32 nsId = 18) {
    WDI_SET_ADD_PM_PROTOCOL_OFFLOAD_PARAMETERS_PARAMETERS request = {};
    request.Optional.ipv4ARPOffload_IsPresent = arp;
    request.Optional.ipv6ARPOffload_IsPresent = ns;
    request.Optional.DOT11RSNREKeyOffload_IsPresent = gtk;
    request.ipv4ARPOffload.ProtocolOffloadId = arpId;
    request.ipv6ARPOffload.ProtocolOffloadId = nsId;
    UCHAR kck[16] = {}, kek[16] = {};
    auto& info = request.DOT11RSNREKeyOffload.RsnKeyInfo;
    info.ProtocolOffloadId = 19;
    info.KCK_CONTENT.pElements = kck;
    info.KCK_CONTENT.ElementCount = 16;
    info.KEK_CONTENT.pElements = kek;
    info.KEK_CONTENT.ElementCount = 16;
    UINT8* bytes = nullptr;
    ULONG length = 0;
    assert(GenerateWdiSetAddPmProtocolOffloadToIhv(
        &request, 0, &wifi.TlvContext, &length, &bytes) == 0);
    completion = STATUS_UNSUCCESSFUL;
    Ap6256HandleAddPmProtocolOffload(&wifi, nullptr, bytes, length);
    FreeGenerated(bytes);
}
int main() {
    Device device;
    Wifi wifi;
    wifi.Ctx = &device;
    wifi.TlvContext.PeerVersion = WDI_VERSION_LATEST;
    add(wifi, true, false, false);
    assert(completion == STATUS_SUCCESS && arpCalls == 1 &&
           nsCalls == 0 && gtkCalls == 0);
    arpCalls = 0;
    add(wifi, false, true, false);
    assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls);
    add(wifi, false, false, true);
    assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls);
    add(wifi, true, false, true);
    assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls);
    add(wifi, true, true, false);
    assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls);
    device.FirmwareNdOffloadSupported = TRUE;
    device.WowlCapabilities = 0;
    add(wifi, true, true, false);
    assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls);
    device.WowlCapabilities = AP6256_WOWL_ARP_OFFLOAD;
    add(wifi, false, true, false);
    assert(completion == STATUS_SUCCESS && nsCalls == 1 && !arpCalls && !gtkCalls);
    wifi.ArpOffloadValid[0] = FALSE; wifi.ArpOffloadIds[0] = 0; wifi.ArpOffloads[0] = {};
    failNs = true;
    add(wifi, true, true, false);
    assert(completion == STATUS_UNSUCCESSFUL && arpRemoves == 1 &&
           wifi.ArpOffloadIds[0] == 0);
    wifi.ArpOffloadValid[0] = TRUE; wifi.ArpOffloadIds[0] = 17;
    wifi.ArpOffloads[0].ProtocolOffloadId = 17;
    wifi.ArpOffloads[0].HostIPV4Address[3] = 9;
    add(wifi, true, true, false);
    assert(completion == STATUS_UNSUCCESSFUL && arpRemoves == 1 &&
           wifi.ArpOffloads[0].HostIPV4Address[3] == 9);

    wifi.ArpOffloadIds[0] = 0; wifi.ArpOffloads[0].ProtocolOffloadId = 0;
    wifi.ArpOffloads[0].HostIPV4Address[3] = 7;
    add(wifi, true, true, false, 0);
    assert(completion == STATUS_UNSUCCESSFUL && arpRemoves == 1 &&
           wifi.ArpOffloadValid[0] && wifi.ArpOffloads[0].HostIPV4Address[3] == 7);
    auto calls = arpCalls;
    add(wifi, true, true, false, 0, 0);
    assert(completion == STATUS_INVALID_PARAMETER && arpCalls == calls);
    wifi.ArpOffloadValid[0] = FALSE; wifi.ArpOffloads[0] = {};
    add(wifi, true, true, false, 0);
    assert(completion == STATUS_UNSUCCESSFUL && arpRemoves == 2 && !wifi.ArpOffloadValid[0]);
    wifi.ArpOffloadValid[0] = TRUE;wifi.ArpOffloadIds[0] = 0;
    wifi.ArpOffloads[0].ProtocolOffloadId = 0;wifi.ArpOffloads[0].HostIPV4Address[3] = 7;
    auto oldRecord = wifi.ArpOffloads[0];
    for (unsigned mode = 1; mode <= 3; ++mode) {
        device.HostFips = mode == 1;device.HostCipherMode = mode == 1 ? 0 : mode - 1;
        device.FirmwareNdOffloadSupported = device.FirmwareGtkOffloadSupported = TRUE;
        for (unsigned mask = 1; mask <= 7; ++mask) {
            arpCalls = nsCalls = gtkCalls = arpRemoves = 0;
            add(wifi, !!(mask & 1), !!(mask & 2), !!(mask & 4));
            assert(completion == STATUS_NOT_SUPPORTED && !arpCalls && !nsCalls && !gtkCalls && !arpRemoves);
            assert(wifi.ArpOffloadValid[0] && wifi.ArpOffloadIds[0] == 0 &&
                   !memcmp(&oldRecord, &wifi.ArpOffloads[0], sizeof(oldRecord)));
        }
    }
    puts("PASS: 21 host-crypto actual-codec mixed-offload preflight cases; ordinary rejection/rollback including ID zero passes");
}
'''

def main() -> None:
    source = read_source_text(ROOT / 'src/common/netadapter.c')
    header = read_source_text(ROOT / 'src/common/wifi_ops.h')
    function = _functions(source)['Ap6256HandleAddPmProtocolOffload']
    start = header.index('typedef struct _AP6256_GTK_OFFLOAD')
    end = header.index('} AP6256_GTK_OFFLOAD, *PAP6256_GTK_OFFLOAD;', start)
    end += len('} AP6256_GTK_OFFLOAD, *PAP6256_GTK_OFFLOAD;')
    output = output_dir('wowl-add-gate')
    output.mkdir(parents=True, exist_ok=True)
    cpp = output / 'tests.cpp'
    stateHeader = read_source_text(ROOT / 'src/common/wowl.h')
    state = stateHeader[stateHeader.index('typedef struct _AP6256_GROUP_KEY_STATE'):stateHeader.index('C_ASSERT')]
    newMock = '\n' + state + '\n#define AP6256_WOWL_KEY_ROTATION 0x4000u\n'
    newMock += 'static NTSTATUS Ap6256WifiAddGtkOffload(Device*, const AP6256_GTK_OFFLOAD*) {++gtkCalls;return STATUS_SUCCESS;}\n'
    newMock += 'static NTSTATUS Ap6256WifiRemoveGtkOffload(Device*) {return STATUS_SUCCESS;}\n'
    newMock += 'static NTSTATUS Ap6256WifiReadGtkOffload(Device*, AP6256_GTK_STATE*) {return STATUS_NOT_SUPPORTED;}\n'
    newMock += _functions(source)['Ap6256BuildGtkOffload']
    write_text(cpp, PRE + header[start:end] + '\n' + MOCK + newMock + function + TEST, encoding='utf-8')
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / folder) for folder in ('ucrt', 'shared', 'um', 'um/wlan/2.0')]
    command += [str(cpp), '/Fe:' + str(output / 'tests.exe'), '/Fo:' + str(output / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64'), 'advapi32.lib', str(LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    subprocess.run([str(output / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
