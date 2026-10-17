# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute fresh firmware readiness and host-cipher retirement with real CNG.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes as c
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import threading
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('recovery_control', AP / 'tests/test-host-cipher-control.py')
control = importlib.util.module_from_spec(spec)
spec.loader.exec_module(control)
(T, U8, U32) = (control.T, control.U8, control.U32)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()
MOCK = r'''
static SDPCM_SHARED sharedFixture;
static UINT32 pointerFixture,reads,delays;
static NTSTATUS readStatus;
static NTSTATUS Ap6256SdioRamRW(Device* d,BOOLEAN write,UINT32 at,PUCHAR p,ULONG n) {
    assert(!write);++reads;
    if(readStatus)return (NTSTATUS)readStatus;
    if(at==d->Chip.RamBase+d->Chip.RamSize-4){assert(n==4);memcpy(p,&pointerFixture,4);}
    else {assert(at==pointerFixture&&n==sizeof(sharedFixture));memcpy(p,&sharedFixture,n);}
    return 0;
}
static NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alert,LARGE_INTEGER* interval) {
    assert(mode==KernelMode&&!alert&&interval->QuadPart==-10000);++delays;return 0;
}
void TestStartupFixture(Device* d,ULONG kind) {
    d->FirmwareState=Ap6256FwDownloading;d->Chip.RamBase=0x198000;d->Chip.RamSize=0xa4000;
    d->Go.NativeStateUncertain=TRUE;memset(d->PowerSaveDx,0x55,sizeof(d->PowerSaveDx));
    d->Chip.SharedAddress=0;sharedFixture=(SDPCM_SHARED){0};sharedFixture.Flags=3;
    pointerFixture=0x19a000;readStatus=STATUS_SUCCESS;reads=delays=0;

    Ap6256HostCipherFirmwareRetire(d);
    InterlockedExchange(&d->FirmwareHalted,1);
    switch(kind){
    case 0:break;
    case 1:sharedFixture.Flags=4;break;
    case 2:sharedFixture.Flags=3|SDPCM_SHARED_TRAP;break;
    case 3:sharedFixture.Flags=3|SDPCM_SHARED_ASSERT;break;
    case 4:readStatus=STATUS_CRC_ERROR;break;
    case 5:pointerFixture=0;break;
    case 6:pointerFixture=0xffff0000;break;
    case 7:pointerFixture=d->Chip.RamBase+d->Chip.RamSize;break;
    case 8:d->Chip.RamBase=0xfffff000;d->Chip.RamSize=0x2000;break;
    case 9:d->Chip.RamSize=sizeof(sharedFixture);break;
    case 10:d->FirmwareState=Ap6256FwRunning;break;
    default:assert(0);
    }
}
ULONG TestReadCount(void){return reads;}
ULONG TestDelayCount(void){return delays;}
ULONG TestBootFlags(Device* d){return (d->FirmwareHalted?1u:0u)|(d->Go.NativeStateUncertain?2u:0u);}
ULONG TestDxEmpty(Device* d){return !d->PowerSaveDx[0].Seen&&!d->PowerSaveDx[1].Seen;}


void TestCompleteInterfaceBlocks(Device* d){InterlockedAnd(&d->HostCipherBlockedMask,(LONG)~0xffffu);}
'''

def transform(text):
    sd = (AP / 'src/common/sdpcm.h').read_text(encoding='utf-8-sig')
    shared = re.search('typedef struct _SDPCM_SHARED \\{.*?\\} SDPCM_SHARED, \\*PSDPCM_SHARED;', sd, re.S)[0]
    shared = shared.replace('UINT8 ', 'UCHAR ')
    power = (AP / 'src/common/power_stats.h').read_text(encoding='utf-8-sig')
    dx = re.search('typedef struct _AP6256_POWER_SAVE_DX \\{.*?\\} AP6256_POWER_SAVE_DX;', power, re.S)[0]
    defines = '\n'.join(re.findall('^#define SDPCM_SHARED_[^\\n]+', sd, re.M))
    firmware = (AP / 'src/common/firmware.c').read_text(encoding='utf-8-sig')
    defines += '\n' + re.search('^#define AP6256_FW_READY_RETRIES[^\\n]+', firmware, re.M)[0]
    prefix = shared + '\n' + dx + '\n' + defines + '\n#define MAXUINT32 0xffffffffu\n#define TraceInfo(...) ((void)0)\n#define TraceError(...) ((void)0)\n'
    assert text.count('typedef struct {\n AP6256_HC_STORE HostCipherStore;') == 1
    text = text.replace('typedef struct {\n AP6256_HC_STORE HostCipherStore;', prefix + 'typedef struct {\n AP6256_HC_STORE HostCipherStore;')
    assert text.count(' LONG FirmwareState;') == 1
    text = text.replace(' LONG FirmwareState;', ' LONG FirmwareState;\n struct {UINT32 RamBase,RamSize,SharedAddress;} Chip;\n AP6256_POWER_SAVE_DX PowerSaveDx[2];')
    assert text.count('struct {LONG PacketFilter;} Go;') == 1
    text = text.replace('struct {LONG PacketFilter;} Go;', 'struct {LONG PacketFilter;BOOLEAN NativeStateUncertain;} Go;')
    functions = _functions(firmware)
    return text + MOCK + functions['Ap6256IsNvramLengthToken'] + '\n' + functions['Ap6256WaitForShared'] + '\nNTSTATUS TestWaitForShared(Device* d){return Ap6256WaitForShared(d);}\n'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('host-cipher-recovery'))
    out = parser.parse_args().output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / 'result.json').unlink(missing_ok=True)
    control.build(out, transform, ('TestStartupFixture', 'TestWaitForShared', 'TestReadCount', 'TestDelayCount', 'TestBootFlags', 'TestDxEmpty', 'TestWaitRundown', 'TestCompleteInterfaceBlocks'))
    dll = control.load_dll(out / 'control.dll')
    dll.TestStartupFixture.argtypes = [c.c_void_p, U32]
    dll.TestWaitForShared.argtypes = [c.c_void_p]
    dll.TestBootFlags.argtypes = [c.c_void_p]
    dll.TestDxEmpty.argtypes = [c.c_void_p]
    dll.TestCompleteInterfaceBlocks.argtypes = [c.c_void_p]
    cases = []
    for sticky in (False, True):
        for kind in range(11):
            dll.TestControlReset()
            d = dll.TestDeviceCreate()
            try:
                dll.TestCaps(287)
                assert dll.Ap6256HostCipherQualify(d, 1) == 0
                assert dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0
                assert dll.Ap6256HostCipherConfirmAssociation(d, 0, 1, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0
                key = control.Key()
                key.cipher = 9
                key.pairwise = key.tx = key.rx = key.peer_present = 1
                key.peer[:] = T.APMAC
                key.material[:] = bytes(range(32))
                assert dll.Ap6256HostCipherAddKey(d, 0, c.byref(key)) == 0
                plain = T.frame(True, b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload')
                output = (U8 * 8352)()
                output[:len(plain)] = plain
                (n, priority, exempt) = (U32(len(plain)), U8(), U8())
                assert dll.Ap6256RawPrepareTx(d, 0, output, len(output), c.byref(n), c.byref(priority), c.byref(exempt)) == 0
                old_wire = bytes(output[:n.value])
                (provider, pn) = (dll.TestProvider(d), dll.TestPnFrontier(d))
                if sticky:
                    dll.TestFault(4)
                    assert dll.Ap6256HostCipherEnd(d, 0, 0) < 0
                    assert dll.TestBlocked(d) & 1
                dll.TestStartupFixture(d, kind)
                calls = dll.TestIoCalls()
                status = dll.TestWaitForShared(d)
                assert (status == 0) == (kind == 0), (sticky, kind, status)
                assert dll.TestIoCalls() == calls and dll.TestProvider(d) == provider
                assert dll.TestPnFrontier(d) == pn == 1 and dll.TestNextGeneration(d) == 1
                assert not dll.Ap6256RawTxCurrent(d, 0, T.buf(old_wire), len(old_wire))
                if kind == 0:
                    assert not dll.TestBootFlags(d) and dll.TestDxEmpty(d)
                    assert not dll.TestKeyCount(dll.TestStore(d)) and (not dll.TestBlocked(d))
                    assert dll.Ap6256RawGenerationCurrent(d, 0, 0, 0)
                    assert dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0
                else:
                    assert dll.TestBootFlags(d) & 2 and (not dll.TestDxEmpty(d))
                    assert dll.TestBlocked(d) & 2147483648
                    assert dll.Ap6256HostCipherPacketActive(d, 0)
                    assert not dll.Ap6256RawGenerationCurrent(d, 0, 0, 0)
                    assert dll.TestKeyCount(dll.TestStore(d)) == (0 if sticky else 1)
                if kind in (5, 6, 7):
                    assert dll.TestDelayCount() == dll.TestReadCount() == 2000
                    assert status == c.c_int32(3221225635).value
                if kind in (8, 9):
                    assert not dll.TestReadCount()
                cases.append(dict(sticky=sticky, input_case=kind, status=status, reads=dll.TestReadCount(), delays=dll.TestDelayCount()))
            finally:
                dll.TestDeviceDestroy(d)
    races = []
    for halt_during_drain in (False, True):
        dll.TestControlReset()
        d = dll.TestDeviceCreate()
        try:
            dll.TestCaps(287)
            assert dll.Ap6256HostCipherQualify(d, 1) == 0
            assert dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0
            assert dll.Ap6256HostCipherConfirmAssociation(d, 0, 1, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0
            key = control.Key()
            key.cipher = 9
            key.pairwise = key.tx = key.rx = key.peer_present = 1
            key.peer[:] = T.APMAC
            key.material[:] = bytes(range(32))
            assert dll.Ap6256HostCipherAddKey(d, 0, c.byref(key)) == 0
            provider = dll.TestProvider(d)

            def queued_encrypt():
                plain = T.frame(True, b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload')
                output = (U8 * 8352)()
                output[:len(plain)] = plain
                (n, priority, exempt) = (U32(len(plain)), U8(), U8())
                status = dll.Ap6256RawPrepareTx(d, 0, output, len(output), c.byref(n), c.byref(priority), c.byref(exempt))
                return (status, n.value)
            with ThreadPoolExecutor(max_workers=2) as pool:
                dll.TestPause()
                encrypt = pool.submit(queued_encrypt)
                try:
                    assert dll.TestWaitEntered()
                    dll.TestStartupFixture(d, 0)
                    recovery = pool.submit(dll.TestWaitForShared, d)
                    assert dll.TestWaitRundown() and (not recovery.done())
                    assert dll.TestProvider(d) == provider
                    assert not dll.Ap6256RawGenerationCurrent(d, 0, 1, 1)
                    if halt_during_drain:
                        dll.TestHalted(d, 1)
                finally:
                    dll.TestUnpause()
                (encrypted_status, written) = encrypt.result(timeout=5)
                status = recovery.result(timeout=5)
                assert encrypted_status < 0 and (not written)
                assert (status == 0) == (not halt_during_drain)
                assert not dll.TestKeyCount(dll.TestStore(d))
                assert dll.TestProvider(d) == provider and dll.TestPnFrontier(d) == 1
                assert dll.TestNextGeneration(d) == 1
                if halt_during_drain:
                    assert dll.TestBootFlags(d) == 3 and (not dll.TestDxEmpty(d))
                    assert dll.Ap6256HostCipherBegin(d, 0, T.buf(T.STATION), T.buf(T.APMAC)) < 0
                else:
                    assert not dll.TestBootFlags(d) and dll.TestDxEmpty(d)
                races.append(dict(halt_during_drain=halt_during_drain, status=status, old_encrypt_status=encrypted_status, emitted_bytes=written))
        finally:
            dll.TestUnpause()
            dll.TestDeviceDestroy(d)
    dll.TestControlReset()
    d = dll.TestDeviceCreate()
    try:
        dll.TestCaps(287)
        assert dll.Ap6256HostCipherQualify(d, 1) == 0
        assert dll.Ap6256HostCipherBeginProfile(d, 0, T.buf(T.STATION), T.buf(T.APMAC), 2, 0) == 0
        (entered, release) = (threading.Event(), threading.Event())
        calls = []

        @control.IO
        def pending_mode(_context, set_op, iface, name, data, length, result):
            assert iface == 0 and name == b'wdi_hc_mode' and (length == 32)
            calls.append(bool(set_op))
            if set_op:
                entered.set()
                assert release.wait(10), 'control reply fixture timed out'
            else:
                c.memmove(data, (U32 * 8)(826495048, 32, 0, 0, 0, 0, 0, 0), 32)
            if result:
                result.contents.reply = 1
                result.contents.length = 32
            return 0
        dll.TestControlIo(pending_mode, None)
        with ThreadPoolExecutor(max_workers=2) as pool:
            old_end = pool.submit(dll.Ap6256HostCipherEnd, d, 0, 0)
            try:
                assert entered.wait(5)
                dll.TestFirmwareState(d, 1)
                barrier = pool.submit(dll.Ap6256HostCipherFirmwareRetire, d)
                assert not barrier.done()
                assert not dll.Ap6256RawGenerationCurrent(d, 0, 1, 1)
            finally:
                release.set()
            assert old_end.result(timeout=5) == 0
            barrier.result(timeout=5)
        assert calls == [True, False]
        assert dll.TestBlocked(d) == 2147483649
        assert not dll.Ap6256RawGenerationCurrent(d, 0, 0, 0)
        before = dll.TestIoCalls()
        assert dll.Ap6256HostCipherEnd(d, 0, 0) < 0
        assert dll.TestIoCalls() == before and calls == [True, False]
        assert dll.TestBlocked(d) == 2147483649
        dll.TestCompleteInterfaceBlocks(d)
        assert dll.TestBlocked(d) == 2147483648
        for iface in (0, 15):
            assert not dll.Ap6256RawGenerationCurrent(d, iface, 0, 0)
            bcdc = T.buf(bytes([32, 0, iface, 0]))
            assert not dll.Ap6256RawBcdcTxCurrent(d, bcdc, 4)
            handled = U8()
            assert dll.Ap6256HostCipherDisconnect(d, iface, None, 3, c.byref(handled)) < 0
            assert handled.value == 1
        dll.TestFirmwareState(d, 2)
        assert dll.Ap6256HostCipherQualify(d, 1) < 0
        assert dll.TestIoCalls() == before and dll.TestBlocked(d) == 2147483648
        races.append(dict(kind='control_reply_drain', native_calls=len(calls), blocked_mask=dll.TestBlocked(d), per_port_clear_stays_retired=True, stale_qualification_refused=True, all_interfaces_blocked=True))
        dll.TestControlIo(control.IO(), None)
        dll.TestStartupFixture(d, 0)
        assert dll.TestWaitForShared(d) == 0 and (not dll.TestBlocked(d))
        dll.TestFirmwareState(d, 2)
        assert dll.Ap6256HostCipherQualify(d, 1) == 0
        assert dll.Ap6256RawGenerationCurrent(d, 0, 0, 0)
    finally:
        dll.TestControlIo(control.IO(), None)
        dll.TestDeviceDestroy(d)
    assert not dll.TestPoolCount()
    names = ['tests/test-host-cipher-recovery.py', 'tests/test-host-cipher-control.py', 'tests/test-host-cipher-transport.py', 'tests/host-cipher-store-fixture.c', 'tests/driver_sources.py', 'src/common/firmware.c', 'src/common/sdpcm.h', 'src/common/power_stats.h']
    names += ['src/common/' + name for name in ('host_cipher_control.c', 'host_cipher_control.h', 'host_cipher_disconnect.h', 'host_cipher_keys.c', 'host_cipher_keys.h', 'host_cipher_store.c', 'host_cipher_store.h', 'host_cipher_transport.c', 'host_cipher_path.c', 'host_cipher_wire.c', 'host_cipher_frame.c', 'host_crypto_cng.c', 'host_fips.c', 'host_fips_wire.c', 'datapath.c', 'ap6256.h')]
    result = dict(sources={name: sha(AP / name) for name in names}, cases=cases, races=races, checks=len(cases) + len(races), dll_sha256=sha(out / 'control.dll'), generated_c_sha256=sha(out / 'control-fixture.c'), real_cng=True, validated_start_retires_host_ownership=True, failed_readiness_stays_retired=True, invalid_pointer_polling_times_out=True, provider_and_nonce_generation_frontiers_preserved=True, board_verified=False, association_qualified=False, scope=__doc__)
    write_bytes(out / 'result.json', (json.dumps(result, indent=2) + '\n').encode())
    print('PASS: 25 actual readiness/store/CNG recovery cases; lease and control-drain races, invalid-pointer deadlines refuse startup')
if __name__ == '__main__':
    main()
