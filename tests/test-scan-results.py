# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"Firmware escan -> production WDI BSS indication, using Microsoft's TLV codec."
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
from driver_sources import read_source_text
import importlib.util
from pathlib import Path
from wdi_test_support import contract_preamble
import re
import subprocess
ROOT = Path(__file__).resolve().parents[1]

def module(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result
cap = module('test-wdi-capabilities')
hotspot = module('test-hotspot')
PRE = cap.PREAMBLE.split('struct Device {')[0].replace('assert(context == 0); free(p);', '(void)context; free(p);') + r'''
#include <stddef.h>
#include <initializer_list>
typedef LONG NTSTATUS;
typedef UCHAR KIRQL;
#define NDIS_STATUS_SUCCESS ((NDIS_STATUS)0)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xc0000023)
#define STATUS_NOT_FOUND ((NTSTATUS)0xc0000225)
#define STATUS_DEVICE_DATA_ERROR ((NTSTATUS)0xc000009c)
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001a)
#define TraceWarn(...) ((void)0)
#define TraceInfo(...) ((void)0)
#undef TraceVerbose
#define TraceVerbose(...) ((void)0)
#define TraceError(...) ((void)0)
#define AP6256_DISCOVERY_PORT 1u
'''
MOCKS = r'''
struct Device { LONG ScanSyncId; };
struct Task { BOOLEAN Active; WDI_MESSAGE_HEADER Header; PVOID RequestId; };
struct Wifi { TLV_CONTEXT TlvContext; Task ScanTask,P2pDiscoverTask;
    LONG ScanIndicated,ScanDropped,DisallowedBandMask;KIRQL CommandLock;UINT16 ScanTaskSyncId;
};
typedef Wifi* PAP6256_WIFI;
static BOOLEAN Ap6256ServiceScanResult(Wifi*,const AP6256_BSS*) {return FALSE;}
static void Ap6256MboScanResult(Wifi*,const AP6256_BSS*) {}
static Wifi testWifi;
static UINT8* captured;
static ULONG captured_length,indications;
static WDI_MESSAGE_HEADER captured_header;
static PVOID captured_request;
static UINT32 captured_txn;
static const UINT64 host_timestamp=0x0123456789abcdefULL;
static Wifi* Ap6256WifiFromDevice(Device*) { return &testWifi; }
static BOOLEAN Ap6256BandIsDisallowed(Wifi* w,WDI_BAND_ID band) {return w->DisallowedBandMask && band==WDI_BAND_ID_5000;}
static VOID KeAcquireSpinLock(KIRQL* lock,KIRQL* old) {assert(!*lock);*old=0;*lock=1;}
static VOID KeReleaseSpinLock(KIRQL* lock,KIRQL old) {assert(*lock && old==0);*lock=0;}
static VOID KeQuerySystemTimePrecise(LARGE_INTEGER* value) {value->QuadPart=host_timestamp;}
static NTSTATUS Ap6256SendGeneratedIndication(Wifi*,UINT16 id,PWDI_MESSAGE_HEADER h,UINT32 txn,PVOID request,PUCHAR bytes,ULONG len) {
    assert(id==WDI_INDICATION_BSS_ENTRY_LIST && !testWifi.CommandLock);
    if(captured)free(captured);captured=(UINT8*)malloc(len);assert(captured);
    memcpy(captured,bytes,len);captured_length=len;captured_header=*h;
    captured_txn=txn;captured_request=request;indications++;return 0;
}
'''
TEST = r'''

static const UCHAR ies[]={
    0,7,'D','I','R','E','C','T','-',
    221,9,0x50,0x6f,0x9a,9,2,2,0,0x25,0,
    221,13,0x50,0x6f,0x9a,10,0,0,6,0,0x11,0x1c,0x44,0,50
};
struct WireFixture {
    UCHAR bytes[sizeof(BRCMF_ESCAN_RESULT)+sizeof(ies)];
    UCHAR* data() { return bytes; }
    size_t size() const { return sizeof(bytes); }
};
static WireFixture fixture(UINT8 flags) {
    WireFixture bytes={};
    auto* e=(BRCMF_ESCAN_RESULT*)bytes.data();e->BufLen=(ULONG)bytes.size();
    e->Version=1;e->SyncId=43;e->BssCount=1;
    auto* b=&e->BssInfo;b->Version=109;b->Length=sizeof(*b)+sizeof(ies);
    b->Bssid[0]=0x46;b->Bssid[5]=0x9a;b->BeaconPeriod=100;b->Capability=0x10;
    b->SsidLen=7;memcpy(b->Ssid,"DIRECT-",7);b->Chanspec=0xd024;b->ControlChannel=36;
    b->Rssi=-47;b->Flags=flags;b->IeOffset=sizeof(*b);b->IeLength=sizeof(ies);
    memcpy((UCHAR*)b+b->IeOffset,ies,sizeof(ies));return bytes;
}
static void check(Device* d,UINT8 flags,bool p2p) {
    auto bytes=fixture(flags);AP6256_BSS b={};
    assert(Ap6256WifiOnEscanResult(d,bytes.data(),(ULONG)bytes.size(),&b)==0);
    assert(b.SyncId==43);
    testWifi.ScanTask.Active=!p2p;testWifi.P2pDiscoverTask.Active=p2p;
    testWifi.ScanTaskSyncId=43;
    auto* task=p2p?&testWifi.P2pDiscoverTask:&testWifi.ScanTask;
    task->Header.PortId=p2p?1:0;task->Header.TransactionId=73;
    task->RequestId=(PVOID)(ULONG_PTR)(p2p?0xabcdef:0x123456);
    ULONG before=indications;Ap6256NetScanResult(d,&b);assert(indications==before+1);
    assert(captured_header.PortId==task->Header.PortId && captured_txn==0 && captured_request==task->RequestId);
    WDI_INDICATION_BSS_ENTRY_LIST_PARAMETERS parsed={};
    assert(ParseWdiIndicationBssEntryListFromIhv(captured_length,captured,&testWifi.TlvContext,&parsed)==0);
    assert(parsed.Optional.DeviceDescriptor_IsPresent && parsed.DeviceDescriptor.ElementCount==1);
    auto& entry=parsed.DeviceDescriptor.pElements[0];bool beacon=(flags&1)!=0;
    assert(bool(entry.Optional.BeaconFrame_IsPresent)==beacon);
    assert(bool(entry.Optional.ProbeResponseFrame_IsPresent)==!beacon);
    auto& frame=beacon?entry.BeaconFrame:entry.ProbeResponseFrame;
    assert(frame.ElementCount==12+sizeof(ies) && !memcmp(frame.pElements+12,ies,sizeof(ies)));
    assert(frame.pElements[8]==100 && frame.pElements[9]==0 && frame.pElements[10]==0x10);
    assert(entry.BSSID.Address[0]==0x46 && entry.BSSID.Address[5]==0x9a);
    assert(entry.SignalInfo.RSSI==-47 && entry.ChannelInfo.ChannelNumber==36 && entry.ChannelInfo.BandId==WDI_BAND_ID_5000);
    assert(entry.Optional.EntryAgeInfo_IsPresent && entry.EntryAgeInfo.HostTimeStamp==host_timestamp);
    assert(entry.EntryAgeInfo.CachedInformation==((flags&2)!=0));
    CleanupParsedWdiIndicationBssEntryListFromIhv(&parsed);
}
int main() {
    SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX);
    static_assert(offsetof(BRCMF_BSS_INFO,Flags)==96);
    static_assert(sizeof(BRCMF_BSS_INFO)==128);
    Device d={};d.ScanSyncId=43;testWifi.TlvContext.PeerVersion=AP6256_TEST_WDI_VERSION;
    for(bool p2p:{true,false})for(UINT8 flags:std::initializer_list<UINT8>{0,1,2,3,4,5})check(&d,flags,p2p);
    assert(testWifi.ScanIndicated==12 && testWifi.ScanDropped==0);
    auto bytes=fixture(0);AP6256_BSS b={};auto* e=(BRCMF_ESCAN_RESULT*)bytes.data();
    e->SyncId=42;assert(Ap6256WifiOnEscanResult(&d,bytes.data(),(ULONG)bytes.size(),&b)==STATUS_NOT_FOUND);
    e->SyncId=43;e->BssInfo.IeLength+=1;
    assert(Ap6256WifiOnEscanResult(&d,bytes.data(),(ULONG)bytes.size(),&b)==STATUS_DEVICE_DATA_ERROR);
    e->BssInfo.IeLength-=1;
    for(ULONG length=0;length<bytes.size();length++)assert(!NT_SUCCESS(Ap6256WifiOnEscanResult(&d,bytes.data(),length,&b)));
    assert(Ap6256WifiOnEscanResult(&d,bytes.data(),(ULONG)bytes.size(),&b)==0);

    ULONG oldIndications=indications;++d.ScanSyncId;
    Ap6256NetScanResult(&d,&b);assert(indications==oldIndications);--d.ScanSyncId;
    ULONG before=indications;testWifi.ScanTask.Active=FALSE;testWifi.P2pDiscoverTask.Active=FALSE;
    Ap6256NetScanResult(&d,&b);assert(indications==before && testWifi.ScanDropped==1);
    testWifi.P2pDiscoverTask.Active=TRUE;testWifi.DisallowedBandMask=1;
    Ap6256NetScanResult(&d,&b);assert(indications==before && testWifi.ScanDropped==2);
    testWifi.DisallowedBandMask=0;b.IesLength=AP6256_SCAN_IE_MAX+1;
    Ap6256NetScanResult(&d,&b);assert(indications==before && testWifi.ScanDropped==3);
    free(captured);
    puts("PASS: firmware escan frame/cache flags -> actual WDI probe/beacon TLVs; P2P and STA ports, WFD bytes, request identity, stale/truncated results and drop guards");
}
'''

def definition(source, name):
    candidates = list(re.finditer('^(?:static\\s+)?(?:[A-Z][A-Za-z0-9_]*\\s+)+' + name + '\\s*\\([^;]*?\\)\\s*\\{', source, re.M))
    start = candidates[-1].end() - 1
    clean = re.sub('//[^\\n]*|/\\*[\\s\\S]*?\\*/|"(?:\\\\.|[^"\\\\])*"', lambda m: ' ' * len(m[0]), source[start:])
    depth = 0
    for (i, c) in enumerate(clean):
        depth += (c == '{') - (c == '}')
        if not depth:
            return source[start:start + i + 1]
    raise ValueError(name)

def main():
    out = output_dir('scan-results')
    out.mkdir(parents=True, exist_ok=True)
    ops = read_source_text(ROOT / 'src/common/wifi_ops.c')
    hdr = read_source_text(ROOT / 'src/common/wifi_ops.h')
    net = read_source_text(ROOT / 'src/common/netadapter.c')
    text = PRE + '\n' + re.search('^#define AP6256_SCAN_IE_MAX[^\\n]+', hdr, re.M)[0] + '\n'
    text += '\n'.join(re.findall('^#define BRCMF_BSS_FLAGS_[^\\n]+', ops, re.M)) + '\n'
    for (source, name) in [(hdr, 'AP6256_BSS'), (ops, 'BRCMF_BSS_INFO'), (ops, 'BRCMF_ESCAN_RESULT')]:
        text += '#pragma pack(push, 1)\n' if name == 'BRCMF_BSS_INFO' else ''
        text += re.search('typedef struct _' + name + '\\s*\\{[\\s\\S]*?\\}\\s*' + name + '[^;]*;', source)[0] + '\n'
        text += '#pragma pack(pop)\n' if name == 'BRCMF_ESCAN_RESULT' else ''
    text += MOCKS
    for (source, sig) in [(ops, 'NTSTATUS Ap6256WifiOnEscanResult(Device* Ctx,PUCHAR EventData,ULONG Length,PAP6256_BSS Bss)'), (net, 'UINT32 Ap6256LinkQualityFromRssi(INT32 Rssi)'), (net, 'VOID Ap6256NetScanResult(Device* Ctx,PAP6256_BSS Bss)')]:
        name = re.search('(Ap6256\\w+)\\(', sig)[1]
        text += '\n' + sig + '\n' + definition(source, name) + '\n'
    cpp = out / 'tests.cpp'
    write_bytes(cpp, (contract_preamble() + text + TEST).encode())
    vc = VC
    sdk = SDK
    inc = INC
    lib = LIB
    command = [str(vc / 'bin/HostX64/x64/cl.exe'), '/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/Od', '/MT', '/DWDI_IS_DRIVER', '/I' + str(vc / 'include')] + ['/I' + str(inc / f) for f in ('ucrt', 'shared', 'um', 'um/wlan/2.0')] + [str(cpp), '/Fe:' + str(out / 'tests.exe'), '/Fo:' + str(out / 'tests.obj'), '/link', '/LIBPATH:' + str(vc / 'lib/x64'), '/LIBPATH:' + str(lib / 'ucrt/x64'), '/LIBPATH:' + str(lib / 'um/x64'), 'advapi32.lib', str(lib / 'um/x64/wlan/2.0/WificxTLVGenParse.lib')]
    subprocess.run(command, check=True)
    subprocess.run([str(out / 'tests.exe')], check=True)
if __name__ == '__main__':
    main()
