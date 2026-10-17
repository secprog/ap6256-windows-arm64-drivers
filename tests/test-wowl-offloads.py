# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute production WoWLAN ARP and offload-enable paths against firmware failures.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from pathlib import Path
import re
import subprocess
from driver_sources import _functions, read_source_text
ROOT = Path(__file__).resolve().parents[1]
PRE = r'''
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <vector>
#include <string>
#include <map>
typedef LONG NTSTATUS;
#undef STATUS_INVALID_PARAMETER
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xc000000d)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xc00000b5)
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define AP6256_ARP_OFFLOAD_SLOTS 8u
#define BRCMF_ARP_OL_AGENT 1u
#define BRCMF_ARP_OL_SNOOP 8u
#define TRACE_NETADAPTER 0
#define TraceInfo trace
#define TraceWarn trace
#define TraceError trace
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xc00000bb)
#define STATUS_DEVICE_PROTOCOL_ERROR ((NTSTATUS)0xc0000186)
typedef struct {BOOLEAN FirmwareReply,FirmwareError;INT32 FirmwareStatus;ULONG PayloadLength;} AP6256_BCDC_QUERY_RESULT;
struct Device {
    BOOLEAN HostFips = FALSE;
    UINT32 HostCipherMode = 0;
    BOOLEAN FirmwareWowlAdapter = FALSE;
    BOOLEAN FirmwareArpOffloadSupported = TRUE;
    BOOLEAN FirmwareNdOffloadSupported = TRUE;
    BOOLEAN FirmwareGtkOffloadSupported = TRUE;
    BOOLEAN FirmwareLinkUp = TRUE, PnoActive = FALSE;
    UINT32 WakeEnabledPatterns = 0, WakeEnabledOffloads = 0;
    UINT32 WakeUpFlags = 0, WakeMediaSpecificEvents = 0;
};
typedef Device* PAP6256_DEVICE_CONTEXT;
struct Wifi {Device* Ctx;};
typedef Wifi* PAP6256_WIFI;
#define AP6256_WAKE_ON_NLO_DISCOVERY 1u
static void trace(int, const char*, ...) {}
'''
MOCK = r'''


static BOOLEAN Ap6256FipsActive(Device* d, UINT32 i) {assert(i == 0);return d->HostFips;}
static BOOLEAN Ap6256HostCipherPacketActive(Device* d, UINT32 i) {assert(i == 0);return d->HostCipherMode != 0;}
static BOOLEAN Ap6256PnoWindowsActive(Device* d) {return d->PnoActive;}
static NTSTATUS Ap6256WifiSetWakeEventMask(Device*, UINT32) {return STATUS_SUCCESS;}
struct Command {
    std::string name;
    std::vector<UCHAR> bytes;
};
static std::vector<Command> commands;
static size_t failCall = 0;
static unsigned queryFault = 0, queryFaultAt = 0, queries = 0;
static std::map<std::string,UINT32> settings;
static NTSTATUS Ap6256BcdcSetIovar(Device*, const char* name,
                                    const void* bytes, ULONG length) {
    Command command;
    command.name = name;
    if (length) {
        assert(bytes != nullptr);
        const UCHAR* first = (const UCHAR*)bytes;
        command.bytes.assign(first, first + length);
    }
    commands.push_back(command);
    if (length == 4) {UINT32 value;memcpy(&value, bytes, 4);settings[name] = value;}
    return commands.size() == failCall ? STATUS_IO_TIMEOUT : STATUS_SUCCESS;
}
static NTSTATUS Ap6256BcdcSetIovarIf(Device* d, UINT32 iface, const char* name, const void* bytes, ULONG length) {
    assert(iface == 0);return Ap6256BcdcSetIovar(d,name,bytes,length);
}
static NTSTATUS Ap6256BcdcGetIovarResultIf(Device*, UINT32 iface, const char* name, void* bytes, ULONG length, AP6256_BCDC_QUERY_RESULT* result) {
    assert(iface == 0 && length == 4);++queries;
    memset(result,0,sizeof(*result));result->FirmwareReply = TRUE;result->PayloadLength = 4;
    *(UINT32*)bytes = settings[name];
    if (queries == queryFaultAt) {
        if (queryFault == 1) result->FirmwareReply = FALSE;
        if (queryFault == 2) result->FirmwareError = TRUE;
        if (queryFault == 3) result->PayloadLength = 3;
        if (queryFault == 4) *(UINT32*)bytes = 1;
        if (queryFault == 5) return STATUS_IO_TIMEOUT;
    }
    return STATUS_SUCCESS;
}
static void reset(size_t fail = 0) {
    commands.clear();
    failCall = fail;
    queryFault = queryFaultAt = queries = 0;settings.clear();
}
static UINT32 word(const Command& command) {
    assert(command.bytes.size() == 4);
    UINT32 value;
    memcpy(&value, command.bytes.data(), sizeof(value));
    return value;
}
'''
TEST = r'''
int main() {
    Device device;
    AP6256_ARP_OFFLOAD arp = {};
    arp.OffloadId = 17;
    arp.HostIpv4[0] = 192;
    arp.HostIpv4[1] = 0;
    arp.HostIpv4[2] = 2;
    arp.HostIpv4[3] = 3;
    arp.RemoteIpv4[0] = 192;
    arp.RemoteIpv4[1] = 0;
    arp.RemoteIpv4[2] = 2;
    arp.RemoteIpv4[3] = 1;
    for (unsigned i = 0; i < 6; ++i) arp.MacAddress[i] = (UCHAR)(0x20 + i);

    reset();
    assert(Ap6256WifiAddArpOffload(&device, &arp, 2) == STATUS_SUCCESS);
    assert(commands.size() == 7);
    const char* expected[] = {"arpoe", "arp_ol", "arp_peerage",
                              "arp_hostip_id", "arp_remoteip", "arp_macaddr",
                              "arpoe"};
    for (unsigned i = 0; i < 7; ++i) assert(commands[i].name == expected[i]);
    assert(word(commands.front()) == 1 && word(commands.back()) == 0);
    assert(commands[3].bytes.size() == 5 &&
           commands[3].bytes[0] == 192 && commands[3].bytes[4] == 2);

    for (size_t fail = 1; fail <= 7; ++fail) {
        reset(fail);
        assert(Ap6256WifiAddArpOffload(&device, &arp, 2) == STATUS_IO_TIMEOUT);
        assert(commands.back().name == "arpoe" && word(commands.back()) == 0);
        bool cleared = false;
        for (const auto& command : commands)
            if (command.name == "arp_hostip_clear_id")
                cleared = true;
        assert(cleared == (fail >= 4));
    }
    reset();
    assert(Ap6256WifiAddArpOffload(&device, &arp, 8) ==
           STATUS_INVALID_PARAMETER && commands.empty());

    reset();
    assert(Ap6256WifiRemoveArpOffload(&device, 2) == STATUS_SUCCESS);
    assert(commands.size() == 4);
    assert(commands[0].name == "arpoe" &&
           commands[1].name == "arp_table_clear" &&
           commands[2].name == "arp_hostip_clear_id" &&
           commands[3].name == "arpoe");
    for (size_t fail = 1; fail <= 4; ++fail) {
        reset(fail);
        assert(Ap6256WifiRemoveArpOffload(&device, 2) == STATUS_IO_TIMEOUT);
        assert(commands.size() == 4);
    }

    device.FirmwareNdOffloadSupported = FALSE;
    reset();
    assert(Ap6256WifiEnableProtocolOffloads(&device, TRUE, TRUE) ==
           STATUS_NOT_SUPPORTED && commands.empty());
    device.FirmwareNdOffloadSupported = TRUE;
    reset();
    assert(Ap6256WifiEnableProtocolOffloads(&device, FALSE, FALSE) ==
           STATUS_SUCCESS && commands.empty());
    reset();
    assert(Ap6256WifiEnableProtocolOffloads(&device, TRUE, FALSE) ==
           STATUS_SUCCESS);
    assert(commands.size() == 1 && commands[0].name == "arpoe" &&
           word(commands[0]) == 1);
    reset();
    assert(Ap6256WifiEnableProtocolOffloads(&device, FALSE, TRUE) ==
           STATUS_SUCCESS);
    assert(commands.size() == 1 && commands[0].name == "ndoe" &&
           word(commands[0]) == 1);
    reset();
    assert(Ap6256WifiEnableProtocolOffloads(&device, TRUE, TRUE) ==
           STATUS_SUCCESS);
    assert(commands.size() == 2 && commands[0].name == "arpoe" &&
           commands[1].name == "ndoe");
    for (size_t fail = 1; fail <= 2; ++fail) {
        reset(fail);
        assert(Ap6256WifiEnableProtocolOffloads(&device, TRUE, TRUE) ==
               STATUS_IO_TIMEOUT);
        assert(commands.size() >= 3);
        assert(commands[commands.size()-2].name == "arpoe" &&
               word(commands[commands.size()-2]) == 0);
        assert(commands.back().name == "ndoe" &&
               word(commands.back()) == 0);
    }

    AP6256_NS_OFFLOAD ns = {};
    AP6256_GTK_OFFLOAD gtk = {};
    UCHAR key[16] = {}, rsc[6] = {};
    Wifi wifi = {&device};
    unsigned hostPowerChecks = 0;
    auto verify = [&](bool condition) {assert(condition);++hostPowerChecks;};
    for (unsigned mode = 1; mode <= 3; ++mode) {
        device.HostFips = mode == 1;
        device.HostCipherMode = mode == 1 ? 0 : mode - 1;
        device.FirmwareWowlAdapter = TRUE;
        reset();
        verify(Ap6256WifiAddArpOffload(&device, &arp, 2) == STATUS_NOT_SUPPORTED && commands.empty());
        verify(Ap6256WifiAddNsOffload(&device, &ns) == STATUS_NOT_SUPPORTED && commands.empty());
        verify(Ap6256WifiAddGtkOffload(&device, &gtk) == STATUS_NOT_SUPPORTED && commands.empty());
        verify(Ap6256WifiArmWakeEvents(&device, 0) == STATUS_NOT_SUPPORTED && commands.empty());
        for (unsigned mask = 1; mask <= 3; ++mask)
            verify(Ap6256WifiEnableProtocolOffloads(&device, (BOOLEAN)(mask & 1), (BOOLEAN)(mask >> 1)) == STATUS_NOT_SUPPORTED && commands.empty());
        verify(Ap6256WifiEnableProtocolOffloads(&device, FALSE, FALSE) == STATUS_SUCCESS && commands.empty());
        Ap6256WifiSeedGroupKey(&device, 1, FALSE, TRUE, key, rsc);
        Ap6256WifiSeedGroupKey(&device, 4, TRUE, TRUE, key, rsc);
        verify(commands.empty());

        Ap6256WifiSeedGroupKey(&device, 4, TRUE, FALSE, nullptr, nullptr);
        verify(commands.size() == 1 && commands[0].name == "wdi_gtk_key");
        reset();
        verify(Ap6256WifiRemoveArpOffload(&device, 2) == STATUS_SUCCESS && commands.size() == 4);
        device.FirmwareLinkUp = TRUE;device.WakeEnabledPatterns = 1;
        device.WakeEnabledOffloads = 1;device.WakeUpFlags = 1;device.WakeMediaSpecificEvents = 1;
        verify(!Ap6256PowerSleepIsHot(&wifi));
        device.FirmwareLinkUp = FALSE;device.PnoActive = TRUE;
        verify(!Ap6256PowerSleepIsHot(&wifi));
    }
    device.HostFips = FALSE;device.HostCipherMode = 0;
    verify(Ap6256PowerSleepIsHot(&wifi));
    device.FirmwareLinkUp = TRUE;
    verify(Ap6256PowerSleepIsHot(&wifi));
    reset();
    verify(Ap6256WifiAddNsOffload(&device, &ns) == STATUS_SUCCESS && commands.size() == 1);
    reset();
    verify(Ap6256WifiAddGtkOffload(&device, &gtk) == STATUS_SUCCESS && commands.size() == 1);
    reset();
    verify(Ap6256WifiArmWakeEvents(&device, 0) == STATUS_SUCCESS && commands.size() == 2);
    reset();settings["arpoe"] = settings["ndoe"] = 1;
    verify(Ap6256WifiPrepareHostCipherOffloads(&device) == STATUS_SUCCESS && commands.size() == 9 && queries == 4);
    assert(commands[0].name == "arpoe" && !word(commands[0]) && commands[1].name == "ndoe" && !word(commands[1]));
    assert(commands[2].name == "wdi_gtk_config" && commands[2].bytes == std::vector<UCHAR>(56,0));
    for (unsigned slot = 0; slot < 6; ++slot) {
        UCHAR expectedKey[36] = {};UINT32 management = slot >= 4;
        memcpy(expectedKey,&slot,4);memcpy(expectedKey+4,&management,4);
        assert(commands[slot+3].name == "wdi_gtk_key" && commands[slot+3].bytes == std::vector<UCHAR>(expectedKey,expectedKey+36));
    }
    for (unsigned active = 0; active < 3; ++active) {
        reset();settings["arpoe"] = active & 1;settings["ndoe"] = (active >> 1) & 1;
        unsigned count = (active & 1) + ((active >> 1) & 1);
        verify(Ap6256WifiPrepareHostCipherOffloads(&device) == STATUS_SUCCESS && commands.size() == 7 + count && queries == 2 + count);
        assert(!settings["arpoe"] && !settings["ndoe"]);


        for (unsigned i = count; i < commands.size(); ++i)
            assert(commands[i].name == (i == count ? "wdi_gtk_config" : "wdi_gtk_key"));
    }
    for (unsigned fail = 1; fail <= 9; ++fail) {
        reset(fail);settings["arpoe"] = settings["ndoe"] = 1;
        verify(Ap6256WifiPrepareHostCipherOffloads(&device) == STATUS_IO_TIMEOUT && commands.size() == fail);
    }
    for (unsigned failAt = 1; failAt <= 4; ++failAt) for (unsigned kind = 1; kind <= 5; ++kind) {
        if (kind == 4 && (failAt & 1)) continue;
        reset();settings["arpoe"] = settings["ndoe"] = 1;queryFault = kind;queryFaultAt = failAt;
        verify(Ap6256WifiPrepareHostCipherOffloads(&device) == (kind == 5 ? STATUS_IO_TIMEOUT : STATUS_DEVICE_PROTOCOL_ERROR) && commands.size() == failAt / 2);
    }
    printf("PASS: %u host-crypto power/offload checks; ordinary ARP/NS/GTK/wake/NLO regressions pass\n", hostPowerChecks);
}
'''

def declaration(source: str, name: str) -> str:
    match = re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?^\\}\\s*' + name + '[^;]*;', source, re.M)
    if not match:
        raise ValueError(name)
    return match.group(0) + '\n'

def main() -> None:
    source = read_source_text(ROOT / 'src/common/wifi_ops.c')
    header = read_source_text(ROOT / 'src/common/wifi_ops.h')
    functions = _functions(source)
    text = PRE + re.search('^#define AP6256_WAKE_PACKET_BYTES[^\\n]*', header, re.M)[0] + '\n'
    text += declaration(header, 'AP6256_ARP_OFFLOAD')
    for name in ('AP6256_NS_OFFLOAD', 'AP6256_GTK_OFFLOAD', 'AP6256_WAKE_PACKET'):
        text += declaration(header, name)
    text += '#pragma pack(push, 1)\n'
    text += declaration(source, 'BRCMF_ARP_HOSTIP_ID')
    text += declaration(source, 'BRCMF_ND_PARAM')
    text += '#pragma pack(pop)\n' + MOCK
    for name in ('Ap6256WifiAddArpOffload', 'Ap6256WifiRemoveArpOffload', 'Ap6256WifiEnableProtocolOffloads', 'Ap6256WifiAddNsOffload', 'Ap6256WifiAddGtkOffload', 'Ap6256WifiSeedGroupKey', 'Ap6256WifiArmWakeEvents'):
        text += functions[name] + '\n'
    text += functions['Ap6256WifiPrepareHostCipherOffloads'] + '\n'
    text += _functions(read_source_text(ROOT / 'src/wdi/netadapter.c'))['Ap6256PowerSleepIsHot'] + '\n'
    text += TEST
    output = output_dir('wowl-offloads')
    output.mkdir(parents=True, exist_ok=True)
    program = output / 'tests.cpp'
    write_text(program, text, encoding='utf-8')
    command = [str(VC / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/I' + str(VC / 'include')]
    command += ['/I' + str(INC / folder) for folder in ('ucrt', 'shared', 'um')]
    command += [str(program), '/Fe:' + str(output / 'tests.exe'), '/Fo:' + str(output / 'tests.obj'), '/link', '/LIBPATH:' + str(VC / 'lib/x64'), '/LIBPATH:' + str(LIB / 'ucrt/x64'), '/LIBPATH:' + str(LIB / 'um/x64')]
    subprocess.run(command, check=True)
    subprocess.run([str(output / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
