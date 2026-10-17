# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Run marked BCDC receive, CNG replies and final raw admission from actual C.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import subprocess
from driver_sources import _functions
P = runpy.run_path(str(Path(__file__).with_name('test-host-cipher-path.py')))
(AP, VC, SDK, Spec, Owner) = (P[s] for s in ('AP', 'VC', 'SDK', 'Spec', 'Owner'))
(U8, U32, P8) = (P[s] for s in ('U8', 'U32', 'P8'))
(buf, frame, wire, oracle_gcmp, oracle_bip) = (P[s] for s in ('buf', 'frame', 'wire', 'oracle_gcmp', 'oracle_bip'))
(STATION, APMAC) = (P['STATION'], P['APMAC'])
FIXTURE = r'''
#define _Use_decl_annotations_
#define _IRQL_requires_max_(x)
#define AP6256_POOL_TAG 0
#define AP6256_STATION_PORT 0
#define AP6256_WLFC_ANY 0xffff
#define SDPCM_DATA_CHANNEL 2
#define SDPCM_EVENT_CHANNEL 1
#define BCDC_DATA_FLAG_PROTO_SHIFT 4
#define BCDC_DCMD_PROTO_VERSION 2
#define TraceWarn(...) ((void)0)
typedef struct {UCHAR Flags,Priority,Flags2,DataOffset;} BCDC_DATA_HEADER,*PBCDC_DATA_HEADER;
enum {Ap6256FwNotLoaded=0,Ap6256FwDownloading=1,Ap6256FwRunning=2};
typedef struct {
 AP6256_HC_STORE HostCipherStore;
 volatile LONG HostCipherFirmwareQualified,FirmwareHalted;
 volatile LONG HostCipherBlockedMask;
 LONG FirmwareState;
 KMUTEX HostCipherControlLock;UINT32 HostCipherNextGeneration;
 KSPIN_LOCK HostFipsLock;
 AP6256_FIPS_SESSION HostFipsSessions[16];
 ULONG HostFipsBlockedMask;
 LONG PacketFilter,RxFiltered,RxFrames;
 struct {LONG PacketFilter;} Go;
 BOOLEAN WlfcOn;
} Device,*PAP6256_DEVICE_CONTEXT;
static UCHAR captured[8352],destination[6];
static ULONG captures,capturedBytes,queueKind,indications;
static UCHAR received[8216];static ULONG receivedBytes;
static UCHAR receivedHistory[512][8216];static ULONG receivedSizes[512],receivedCount,retireAfter,revokeAfter;
BOOLEAN Ap6256RawTxCurrent(Device*,UINT32,const UCHAR*,ULONG);
BOOLEAN Ap6256RawDestination(Device*,UINT32,const UCHAR*,ULONG,UCHAR*);
BOOLEAN Ap6256RawBcdcTxCurrent(Device*,const UCHAR*,ULONG);
BOOLEAN Ap6256RawRxRead(Device*,UINT32,const UCHAR*,ULONG,AP6256_FIPS_FRAME_VIEW*,ULONG*,BOOLEAN*);
static BOOLEAN Ap6256WlfcEnabled(Device* d) {return d->WlfcOn;}
static NTSTATUS Record(Device* d,const UCHAR* p,ULONG n,UCHAR exempt,UCHAR iface) {
 UCHAR bcdc[8356]={0x23,0,iface,0};
 assert(exempt==3 && n<=sizeof(captured));memcpy(bcdc+4,p,n);
 assert(Ap6256RawBcdcTxCurrent(d,bcdc,n+4));
 assert(Ap6256RawDestination(d,iface,p,n,destination));
 memcpy(captured,p,n);capturedBytes=n;++captures;return 0;
}
static NTSTATUS Ap6256WlfcEnqueue(Device* d,const UCHAR* p,ULONG n,UCHAR priority,
 UCHAR exempt,UCHAR iface,UINT16 port,UINT16 peer,void* cb,void* cookie) {
 assert(!priority && !port && peer==0xffff && !cb && !cookie);queueKind=1;
 return Record(d,p,n,exempt,iface);
}
static NTSTATUS Ap6256DatapathTransmitEx(Device* d,PUCHAR p,ULONG n,UCHAR priority,
 UCHAR exempt,UCHAR iface,UINT16 port,UINT16 peer,void* cookie) {
 assert(!priority && !port && peer==0xffff && !cookie);queueKind=2;
 return Record(d,p,n,exempt,iface);
}
static BOOLEAN Ap6256WlfcSignals(Device* d,const UCHAR* p,ULONG n) {(void)d;(void)p;(void)n;return TRUE;}
static VOID Ap6256NetRxIndicate(Device* d,PUCHAR p,ULONG n,UCHAR priority,UINT32 i) {
 ULONG indicatedGeneration=0;
 if(n>=4&&!memcmp(p,"HCW1",4)) {
  AP6256_FIPS_FRAME_VIEW v;ULONG g;BOOLEAN hc;
  assert(Ap6256RawRxRead(d,i,p,n,&v,&g,&hc)&&hc&&priority==(v.Tid&7));
  indicatedGeneration=g;
  assert(n<=sizeof(received));memcpy(received,p,n);receivedBytes=n;
  assert(receivedCount<512);memcpy(receivedHistory[receivedCount],p,n);receivedSizes[receivedCount++]=n;
 }
 ++indications;
 if(retireAfter&&indications==retireAfter)Ap6256HostCipherStoreInvalidate(&d->HostCipherStore,i);
 if(revokeAfter&&indications==revokeAfter)assert(!Ap6256HostCipherStoreAuthorize(&d->HostCipherStore,i,indicatedGeneration,0));
}
static VOID Ap6256IndicateRx(Device* d,PUCHAR p,ULONG n,UCHAR priority,UINT32 i) {Ap6256NetRxIndicate(d,p,n,priority,i);}
static VOID Ap6256HandleEvent(Device* d,PUCHAR p,ULONG n) {(void)d;(void)p;(void)n;}
'''
TAIL = r'''
Device* TestDeviceCreate(void) {
 AP6256_HC_STORE* temporary=TestCreate();assert(temporary);TestDestroy(temporary);
 Device* d=calloc(1,sizeof(*d));assert(d);
 assert(!Ap6256HostCipherStoreInit(&d->HostCipherStore));KeInitializeSpinLock(&d->HostFipsLock);
 d->FirmwareState=Ap6256FwRunning;
 KeInitializeMutex(&d->HostCipherControlLock,0);
 return d;
}
void TestConfigure(Device* d,LONG qualified,LONG wlfc) {
 d->HostCipherFirmwareQualified=qualified;d->WlfcOn=wlfc!=0;
 captures=capturedBytes=queueKind=indications=receivedBytes=0;
 receivedCount=retireAfter=revokeAfter=0;
}
void TestDeviceDestroy(Device* d) {Ap6256HostCipherStoreClose(&d->HostCipherStore);DeleteCriticalSection(&d->HostCipherStore.Mutation);DeleteCriticalSection(&d->HostCipherControlLock);free(d);}
void TestDispatch(Device* d,PUCHAR p,ULONG n,UCHAR channel) {Ap6256DispatchBcdcFrame(d,channel,p,n);}
ULONG TestCaptures(void) {return captures;}
ULONG TestCapturedBytes(void) {return capturedBytes;}
ULONG TestQueueKind(void) {return queueKind;}
ULONG TestIndications(void) {return indications;}
const UCHAR* TestCaptured(void) {return captured;}
const UCHAR* TestDestination(void) {return destination;}
const UCHAR* TestReceived(void) {return received;}
ULONG TestReceivedBytes(void) {return receivedBytes;}
const UCHAR* TestReceivedAt(ULONG i) {assert(i<receivedCount);return receivedHistory[i];}
ULONG TestReceivedAtBytes(ULONG i) {assert(i<receivedCount);return receivedSizes[i];}
void TestRetireAfter(ULONG i) {retireAfter=i;}
void TestRevokeAfter(ULONG i) {revokeAfter=i;}
void TestFilter(Device* d,LONG filter) {d->PacketFilter=filter;}
void TestFips(Device* d,LONG on) {
 AP6256_FIPS_SESSION* s=&d->HostFipsSessions[0];RtlZeroMemory(s,sizeof(*s));
 if(on){s->Generation=777;memcpy(s->Station,"\x02\x11\x22\x33\x44\x55",6);memcpy(s->Bssid,"\x02\x66\x77\x88\x99\xaa",6);}
}
'''

def build_fixture_text():
    text = '#include "' + str(AP / 'tests/host-cipher-store-fixture.c').replace('\\', '/') + '"\n'
    text += '#include "' + str(AP / 'src/common/host_cipher_path.c').replace('\\', '/') + '"\n'
    text += '#include "' + str(AP / 'src/common/host_fips_wire.h').replace('\\', '/') + '"\n' + FIXTURE
    fips = _functions((AP / 'src/common/host_fips.c').read_text(encoding='utf-8-sig'))
    for name in ('Ap6256FipsSnapshot', 'Ap6256FipsActive', 'Ap6256FipsTxCurrent', 'Ap6256FipsPrepareTx'):
        text += fips[name] + '\n'
    header = (AP / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    text += '\n'.join(re.findall('^#define AP6256_(?:RXF_|HC_FIRMWARE_RETIRED)[^\\n]*', header, re.M)) + '\n'
    text += re.sub('^#include[^\\n]*\\n', '', (AP / 'src/common/host_cipher_transport.c').read_text(encoding='utf-8-sig'), flags=re.M)
    datapath = _functions((AP / 'src/common/datapath.c').read_text(encoding='utf-8-sig'))
    text += datapath['Ap6256PullBcdcData'] + '\n' + datapath['Ap6256DispatchBcdcFrame'] + '\n' + TAIL
    return text

def main():
    a = argparse.ArgumentParser(description=__doc__)
    a.add_argument('--output', type=Path, default=output_dir('host-cipher-transport'))
    out = a.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    text = build_fixture_text()
    fixture = out / 'transport-fixture.c'
    write_bytes(fixture, text.encode())
    exports = ['TestDeviceCreate', 'TestConfigure', 'TestDeviceDestroy', 'TestDispatch', 'TestCaptures', 'TestCaptured', 'TestCapturedBytes', 'TestQueueKind', 'TestIndications', 'TestDestination', 'TestFips', 'TestPoolCount', 'TestReceived', 'TestReceivedBytes', 'TestFilter', 'TestReceivedAt', 'TestReceivedAtBytes', 'TestRetireAfter', 'TestRevokeAfter', 'TestSetClock', 'TestFragmentCount']
    exports += ['Ap6256HostCipherStore' + s for s in ('Begin', 'Install', 'KeyOwner', 'SetDefault', 'Delete', 'Invalidate', 'Active', 'Stop', 'Authorize', 'SetRxExemptions', 'SetExcludeUnencrypted')]
    exports += ['Ap6256HostCipherManagementTx', 'Ap6256RawTxCurrent', 'Ap6256RawDestination', 'Ap6256RawBcdcTxCurrent', 'Ap6256RawPrepareTx', 'Ap6256RawGenerationCurrent', 'Ap6256RawRxFrame', 'Ap6256RawRxRead']
    definition = out / 'transport.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(exports) + '\n', encoding='utf-8')
    sources = [AP / ('src/common/' + s) for s in ('host_cipher_frame.c', 'host_crypto_cng.c', 'host_cipher_wire.c', 'host_fips_wire.c')]
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in [VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    cmd = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/wd4005', '/O2', '/GS', '/MT', '/LD', '/DAP6256_HOST_CRYPTO_USER_TEST']
    cmd += ['/I' + str(p) for p in [VC / 'include', INC / 'um', INC / 'shared', INC / 'ucrt']]
    cmd += [str(p) for p in sources] + [str(fixture), '/Fo' + str(out) + '\\', '/Fe' + str(out / 'transport.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'transport.lib'), 'bcrypt.lib']
    build = subprocess.run(cmd, cwd=out, env=env, text=True, capture_output=True)
    write_text(out / 'compile.log', build.stdout + build.stderr, encoding='utf-8')
    assert build.returncode == 0, build.stdout + build.stderr
    dll = c.CDLL(str(out / 'transport.dll'))
    dll.TestDeviceCreate.restype = c.c_void_p
    for n in ('TestCaptured', 'TestDestination', 'TestReceived', 'TestReceivedAt'):
        getattr(dll, n).restype = c.c_void_p
    for n in ('TestReceivedAt', 'TestReceivedAtBytes', 'TestRetireAfter', 'TestRevokeAfter'):
        getattr(dll, n).argtypes = [U32]
    dll.TestDeviceDestroy.argtypes = [c.c_void_p]
    dll.TestConfigure.argtypes = [c.c_void_p, c.c_long, c.c_long]
    dll.TestFips.argtypes = [c.c_void_p, c.c_long]
    dll.TestDispatch.argtypes = [c.c_void_p, P8, U32, U8]
    dll.TestFilter.argtypes = [c.c_void_p, c.c_long]
    dll.Ap6256HostCipherStoreBegin.argtypes = [c.c_void_p, U32, U32, P8, P8]
    dll.Ap6256HostCipherStoreInstall.argtypes = [c.c_void_p, c.POINTER(Spec)]
    dll.Ap6256HostCipherStoreKeyOwner.argtypes = [c.c_void_p, U32, U32, U32, U8, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreSetDefault.argtypes = [c.c_void_p, U32, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreAuthorize.argtypes = [c.c_void_p, U32, U32, U8]
    dll.Ap6256RawPrepareTx.argtypes = [c.c_void_p, U32, P8, U32, c.POINTER(U32), P8, P8]
    dll.Ap6256RawGenerationCurrent.argtypes = [c.c_void_p, U32, U32, U8]
    dll.Ap6256RawRxFrame.argtypes = [c.c_void_p, U32, U32, U8, P8, U32, P8]
    dll.Ap6256RawRxRead.argtypes = [c.c_void_p, U32, P8, U32, P8, c.POINTER(U32), c.POINTER(U8)]
    for n in ('Ap6256RawTxCurrent', 'Ap6256RawBcdcTxCurrent'):
        getattr(dll, n).argtypes = [c.c_void_p] + ([U32] if n.endswith('RawTxCurrent') else []) + [P8, U32]
    for n in ('Ap6256HostCipherStoreActive', 'Ap6256HostCipherStoreInvalidate', 'Ap6256HostCipherStoreStop'):
        getattr(dll, n).argtypes = [c.c_void_p, U32]
    for n in ('Ap6256HostCipherStoreActive', 'Ap6256HostCipherStoreKeyOwner', 'Ap6256RawTxCurrent', 'Ap6256RawBcdcTxCurrent', 'Ap6256RawGenerationCurrent', 'Ap6256RawRxFrame', 'Ap6256RawRxRead'):
        getattr(dll, n).restype = U8
    d = dll.TestDeviceCreate()
    checks = 0

    def check(v):
        nonlocal checks
        checks += 1
        assert v

    def dispatch(data, marked=True, interface=0, padding=0):
        bcdc = bytes([32, 0, interface | (128 if marked else 0), padding]) + bytes(padding * 4) + data
        dll.TestDispatch(d, buf(bcdc), len(bcdc), 2)
        return c.string_at(dll.TestCaptured(), dll.TestCapturedBytes())
    try:
        check(dll.Ap6256HostCipherStoreBegin(d, 0, 10, buf(STATION), buf(APMAC)) == 0)
        key = bytes(range(32))
        groupkey = bytes((x ^ 165 for x in key))
        for (cipher, keyid, tx, material) in ((9, 0, True, key), (12, 4, False, groupkey)):
            s = Spec(0, 10, cipher, keyid, cipher == 9, tx, True, buf(APMAC), buf(material), 0)
            check(dll.Ap6256HostCipherStoreInstall(d, c.byref(s)) == 0)
        owner = Owner()
        check(dll.Ap6256HostCipherStoreKeyOwner(d, 0, 10, 0, True, c.byref(owner)))
        check(dll.Ap6256HostCipherStoreSetDefault(d, 0, c.byref(owner)) == 0)
        plain = frame(True, b'\x08\x00', management=192)
        dll.TestConfigure(d, 0, 1)
        check(not dispatch(wire(5, plain)) and dll.TestCaptures() == 0)
        check(not dll.Ap6256RawTxCurrent(d, 0, buf(wire(7)), 24))
        txpn = 0
        rxpn = 10
        for queued in (True, False):
            for padding in (0, 2):
                dll.TestConfigure(d, 1, queued)
                txpn += 1
                expected = wire(6, oracle_gcmp(key, plain, txpn), epoch=owner.epoch)
                check(dispatch(wire(5, plain), padding=padding) == expected)
                check(dll.TestCaptures() == 1 and dll.TestQueueKind() == (1 if queued else 2))
                check(c.string_at(dll.TestDestination(), 6) == APMAC and dll.TestIndications() == 0)
                check(dll.Ap6256RawTxCurrent(d, 0, buf(expected), len(expected)))
                dll.TestConfigure(d, 1, queued)
                rxpn += 1
                received = frame(False, b'\x08\x00', management=192)
                expected = wire(4, received, token=55, epoch=owner.epoch)
                check(dispatch(wire(3, oracle_gcmp(key, received, rxpn), token=55), padding=padding) == expected)
                check(dll.TestCaptures() == 1 and dll.TestIndications() == 0)
                dll.TestConfigure(d, 1, queued)
                check(dispatch(wire(3, received, token=99)) == wire(7, token=99))
                check(dll.TestCaptures() == 1 and c.string_at(dll.TestDestination(), 6) == APMAC)
        groupowner = Owner()
        check(dll.Ap6256HostCipherStoreKeyOwner(d, 0, 10, 6, False, c.byref(groupowner)))
        group = frame(False, b'\x08\x00', management=192, group=True)
        dll.TestConfigure(d, 1, True)
        check(dispatch(wire(3, oracle_bip(groupkey, group, 50), token=100)) == wire(4, group, token=100, epoch=groupowner.epoch))
        dll.Ap6256HostCipherStoreStop(d, 0)
        dll.TestFips(d, 1)
        fipsdata = frame(True, b'\xaa\xaa\x03\x00\x00\x00\x88\x8ehello')
        import struct
        legacy = struct.pack('<IHHIHBBHHI', 1346979400, 1, 160, 777, len(fipsdata), 0, 1, 0, 0, 0) + bytes(136) + fipsdata
        check(dll.Ap6256RawTxCurrent(d, 0, buf(legacy), len(legacy)))
        check(not dll.Ap6256RawTxCurrent(d, 0, buf(wire(7)), 24))
        dll.TestFips(d, 0)
        check(dll.Ap6256HostCipherStoreBegin(d, 0, 11, buf(STATION), buf(APMAC)) == 0)
        for (data, marked, iface) in ((wire(5, plain), True, 0), (wire(5, plain, generation=11), False, 0), (wire(5, plain, generation=11), True, 1), (b'HCW1', True, 0), (wire(7, generation=11), True, 0)):
            dll.TestConfigure(d, 1, True)
            check(not dispatch(data, marked, iface) and (not dll.TestCaptures()) and (not dll.TestIndications()))
        check(dll.Ap6256HostCipherStoreActive(d, 0))
        dll.Ap6256HostCipherStoreInvalidate(d, 0)
        check(dll.Ap6256HostCipherStoreActive(d, 0))
        bcdc = bytes([32, 0, 0, 0]) + bytes(14)
        check(not dll.Ap6256RawBcdcTxCurrent(d, buf(bcdc), len(bcdc)))
        check(not dll.Ap6256RawBcdcTxCurrent(d, buf(bytes([35, 0, 0, 255])), 4))
        dll.Ap6256HostCipherStoreStop(d, 0)
        check(not dll.Ap6256HostCipherStoreActive(d, 0))
        check(dll.Ap6256RawBcdcTxCurrent(d, buf(bcdc), len(bcdc)))
        check(dll.Ap6256HostCipherStoreBegin(d, 0, 12, buf(STATION), buf(APMAC)) == 0)
        s = Spec(0, 12, 9, 0, True, True, True, buf(APMAC), buf(key), 0)
        check(dll.Ap6256HostCipherStoreInstall(d, c.byref(s)) == 0)
        owner = Owner()
        check(dll.Ap6256HostCipherStoreKeyOwner(d, 0, 12, 0, True, c.byref(owner)))
        check(dll.Ap6256HostCipherStoreSetDefault(d, 0, c.byref(owner)) == 0)
        check(dll.Ap6256HostCipherStoreAuthorize(d, 0, 12, True) == 0)
        data = b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload'
        plain = frame(False, data, tid=5)
        request = wire(2, oracle_gcmp(key, plain, 50), token=0, generation=12)
        dll.TestConfigure(d, 1, True)
        dll.TestFilter(d, 32)
        check(not dispatch(request) and (not dll.TestCaptures()) and (dll.TestIndications() == 1))
        accepted = c.string_at(dll.TestReceived(), dll.TestReceivedBytes())
        check(accepted == wire(9, plain, token=0, epoch=owner.epoch, generation=12))
        dll.TestConfigure(d, 1, True)
        dispatch(accepted)
        check(dll.TestIndications() == 0)
        dispatch(request)
        check(dll.TestIndications() == 0)
        view = (U8 * 64)()
        check(not dll.Ap6256RawRxFrame(d, 0, 12, True, buf(plain), len(plain), view))
        (generation, mode) = (U32(), U8())
        check(dll.Ap6256RawRxRead(d, 0, buf(accepted), len(accepted), view, c.byref(generation), c.byref(mode)))
        check(generation.value == 12 and mode.value == 1)
        check(not dll.Ap6256RawRxFrame(d, 0, 12, False, buf(plain), len(plain), view))
        check(dll.Ap6256RawGenerationCurrent(d, 0, 12, True))
        check(not dll.Ap6256RawGenerationCurrent(d, 0, 12, False))
        check(not dll.Ap6256RawGenerationCurrent(d, 0, 0, False))
        groupSpec = Spec(0, 12, 9, 2, False, False, True, buf(APMAC), buf(groupkey), 0)
        check(dll.Ap6256HostCipherStoreInstall(d, c.byref(groupSpec)) == 0)
        gtk = Owner()
        check(dll.Ap6256HostCipherStoreKeyOwner(d, 0, 12, 4, False, c.byref(gtk)))
        source = bytes.fromhex('02aabbccddee')
        multicast = bytes.fromhex('01005e000001')
        eapol = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e\x02\x01\x00\x00'
        amsduCases = 0
        amsduChildren = 0
        amsduPn = 100

        def aggregate_body(msdus):
            result = bytearray()
            for (index, (da, sa, payload)) in enumerate(msdus):
                sub = da + sa + len(payload).to_bytes(2, 'big') + payload
                result += sub
                if index + 1 < len(msdus):
                    result += b'\xa5' * (-len(sub) & 3)
            return bytes(result)

        def child(parent, da, sa, payload):
            n = 30 if parent[1] & 128 else 26
            mac = bytearray(parent[:n])
            mac[4:10] = da
            mac[16:22] = sa
            mac[24] &= 127
            return bytes(mac) + payload

        def amsdu_dispatch(body, tid=5, htc=False, group=False, filter_value=32, retire=0, revoke=0):
            nonlocal amsduCases, amsduPn
            amsduPn += 1
            amsduCases += 1
            parent = frame(False, body, tid=tid | 128, htc=htc, group=group)
            encrypted = wire(2, oracle_gcmp(groupkey if group else key, parent, amsduPn, keyid=2 if group else 0), token=0, generation=12)
            dll.TestConfigure(d, 1, True)
            dll.TestFilter(d, filter_value)
            dll.TestRetireAfter(retire)
            dll.TestRevokeAfter(revoke)
            check(not dispatch(encrypted) and (not dll.TestCaptures()))
            packets = [c.string_at(dll.TestReceivedAt(i), dll.TestReceivedAtBytes(i)) for i in range(dll.TestIndications())]
            return (parent, encrypted, packets)
        for group_rx in (False, True):
            for (tid, htc) in ((0, False), (5, False), (15, True)):
                msdus = [(STATION, source, data), (b'\xff' * 6, APMAC, data + b'1'), (multicast, source, data + b'22'), (STATION, APMAC, eapol)]
                (parent, encrypted, packets) = amsdu_dispatch(aggregate_body(msdus), tid, htc, group_rx)
                expected = [wire(12, child(parent, *msdu), token=2 if group_rx else 1, epoch=gtk.epoch if group_rx else owner.epoch, generation=12) for msdu in msdus]
                check(packets == expected)
                amsduChildren += len(packets)
                check(not dll.Ap6256RawRxRead(d, 0, buf(wire(9, parent, token=0, epoch=gtk.epoch if group_rx else owner.epoch, generation=12)), 24 + len(parent), view, c.byref(generation), c.byref(mode)))
                for packet in packets:
                    check(dll.Ap6256RawRxRead(d, 0, buf(packet), len(packet), view, c.byref(generation), c.byref(mode)))
                    wrong = bytearray(packet)
                    wrong[12:16] = (1 if group_rx else 2).to_bytes(4, 'little')
                    check(not dll.Ap6256RawRxRead(d, 0, buf(wrong), len(wrong), view, c.byref(generation), c.byref(mode)))
                    check(not dll.Ap6256RawTxCurrent(d, 0, buf(packet), len(packet)))
                dll.TestConfigure(d, 1, True)
                dispatch(encrypted)
                check(dll.TestIndications() == 0)
                dispatch(packets[0])
                check(dll.TestIndications() == 0)
        msdus = [(STATION, source, data), (b'\xff' * 6, source, data), (multicast, source, data)]
        (parent, _, packets) = amsdu_dispatch(aggregate_body(msdus), filter_value=1)
        check(packets == [wire(12, child(parent, *msdus[0]), token=1, epoch=owner.epoch, generation=12)])
        amsduChildren += len(packets)
        msdus = [(STATION, source, b'x' * n) for n in (1, 2, 3, 4, 7900)]
        (parent, _, packets) = amsdu_dispatch(aggregate_body(msdus), tid=9)
        check(packets == [wire(12, child(parent, *m), token=1, epoch=owner.epoch, generation=12) for m in msdus])
        amsduChildren += len(packets)
        msdus = [(STATION, source, bytes([i & 255])) for i in range(300)]
        (parent, _, packets) = amsdu_dispatch(aggregate_body(msdus), tid=10)
        check(packets == [wire(12, child(parent, *m), token=1, epoch=owner.epoch, generation=12) for m in msdus])
        amsduChildren += len(packets)
        sub = STATION + source + len(data).to_bytes(2, 'big') + data
        broken = [b'', sub + b'\x00', sub[:-1], STATION + source + b'\xff\xff' + data, STATION + source + b'\x00\x00', source + source + len(data).to_bytes(2, 'big') + data, STATION + bytes(6) + len(data).to_bytes(2, 'big') + data, STATION + multicast + len(data).to_bytes(2, 'big') + data, b'\xaa\xaa\x03\x00\x00\x00' + source + len(data).to_bytes(2, 'big') + data, aggregate_body([(STATION, source, data), (STATION, source, data)])[:-1]]
        for body in broken:
            (_, _, packets) = amsdu_dispatch(body)
            check(not packets)
        msdus = [(STATION, source, data)] * 3
        (_, _, packets) = amsdu_dispatch(aggregate_body(msdus), revoke=1)
        check(len(packets) == 1)
        check(not dll.Ap6256RawRxRead(d, 0, buf(packets[0]), len(packets[0]), view, c.byref(generation), c.byref(mode)))
        (_, _, packets) = amsdu_dispatch(aggregate_body(msdus))
        check(not packets)
        handshakeMsdus = [(STATION, source, eapol)] * 3
        (parent, _, packets) = amsdu_dispatch(aggregate_body(handshakeMsdus))
        check(packets == [wire(12, child(parent, *m), token=1, epoch=owner.epoch, generation=12) for m in handshakeMsdus])
        amsduChildren += len(packets)
        check(dll.Ap6256HostCipherStoreAuthorize(d, 0, 12, True) == 0)
        tx = frame(True, data, tid=5)
        output = (U8 * 8352)()
        output[:len(tx)] = tx
        n = U32(len(tx))
        priority = U8(99)
        exempt = U8(0)
        check(dll.Ap6256RawPrepareTx(d, 0, output, len(output), c.byref(n), c.byref(priority), c.byref(exempt)) == 0)
        sent = bytes(output[:n.value])
        check(sent == wire(1, oracle_gcmp(key, tx, txpn + 1), token=0, epoch=owner.epoch, generation=12))
        check(priority.value == 5 and exempt.value == 3 and dll.Ap6256RawTxCurrent(d, 0, buf(sent), len(sent)))
        check(dll.Ap6256HostCipherStoreAuthorize(d, 0, 12, False) == 0)
        check(not dll.Ap6256RawTxCurrent(d, 0, buf(sent), len(sent)))
        check(not dll.Ap6256RawRxFrame(d, 0, 12, True, buf(plain), len(plain), view))
        check(not dll.Ap6256RawRxRead(d, 0, buf(accepted), len(accepted), view, c.byref(generation), c.byref(mode)))
        check(dll.Ap6256HostCipherStoreAuthorize(d, 0, 12, True) == 0)
        (_, _, packets) = amsdu_dispatch(aggregate_body([(STATION, source, data)] * 3), retire=1)
        check(len(packets) == 1)
        check(not dll.Ap6256RawRxRead(d, 0, buf(packets[0]), len(packets[0]), view, c.byref(generation), c.byref(mode)))
        dll.Ap6256HostCipherStoreInvalidate(d, 0)
        check(not dll.Ap6256RawGenerationCurrent(d, 0, 12, True))
        output[:len(tx)] = tx
        n.value = len(tx)
        exempt.value = 0
        check(dll.Ap6256RawPrepareTx(d, 0, output, len(output), c.byref(n), c.byref(priority), c.byref(exempt)) < 0 and (not n.value))
        names = ('src/common/host_cipher_transport.c', 'src/common/host_cipher_transport.h', 'src/common/datapath.c', 'src/common/host_cipher_path.c', 'src/common/host_cipher_path.h', 'src/common/host_cipher_store.c', 'src/common/host_cipher_store.h', 'src/common/host_cipher_frame.c', 'src/common/host_cipher_frame.h', 'src/common/host_cipher_wire.c', 'src/common/host_cipher_wire.h', 'src/common/host_crypto_cng.c', 'src/common/host_crypto_cng.h', 'src/common/host_fips.c', 'src/common/host_fips_wire.c', 'src/common/host_fips_wire.h', 'src/common/ap6256.h', 'tests/host-cipher-store-fixture.c', 'tests/test-host-cipher-crypto.py', 'tests/test-host-cipher-store.py', 'tests/test-host-cipher-path.py', 'tests/test-host-cipher-transport.py', 'tests/driver_sources.py')
        report = dict(checks=checks, sources={n: hashlib.sha256((AP / n).read_bytes()).hexdigest() for n in names}, amsdu_cases=amsduCases, amsdu_verified_children=amsduChildren, amsdu_whole_validation=True, amsdu_parent_key_class=True, amsdu_delivery_retirement=True, dll_sha256=hashlib.sha256((out / 'transport.dll').read_bytes()).hexdigest(), fixture_sha256=hashlib.sha256(fixture.read_bytes()).hexdigest(), boundary=__doc__, board_verified=False)
        write_bytes(out / 'result.json', (json.dumps(report, indent=2) + '\n').encode())
        print('PASS: %d marked BCDC/management/data/CNG/raw admission checks, queue and direct bus fixtures' % checks)
    finally:
        dll.TestDeviceDestroy(d)
        assert dll.TestPoolCount() == 0
if __name__ == '__main__':
    main()
