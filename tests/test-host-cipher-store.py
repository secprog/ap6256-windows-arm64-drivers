# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute production key-store C with Microsoft CNG.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import threading
HELPERS = runpy.run_path(str(Path(__file__).with_name('test-host-cipher-crypto.py')))
(AP, VC, SDK) = (HELPERS[s] for s in ('AP', 'VC', 'SDK'))
(frame, oracle_gcmp, oracle_bip, buf) = (HELPERS[s] for s in ('frame', 'oracle_gcmp', 'oracle_bip', 'buf'))
(STATION, APMAC) = (HELPERS[s] for s in ('STATION', 'APMAC'))
(U8, U16, U32, U64) = (c.c_ubyte, c.c_ushort, c.c_uint, c.c_ulonglong)
P8 = c.POINTER(U8)

class Spec(c.Structure):
    _fields_ = [('ifindex', U32), ('generation', U32), ('cipher', U32), ('keyid', U16), ('pairwise', U8), ('tx', U8), ('rx', U8), ('bssid', U8 * 6), ('key', U8 * 32), ('receive', U64)]

class Owner(c.Structure):
    _fields_ = [('generation', U32), ('epoch', U32), ('slot', U32)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('host-cipher-store'))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    control = ['Ap6256HostCipherStore' + s for s in ('Begin', 'Install', 'Delete', 'Stop', 'Invalidate', 'TxCurrent', 'Frame', 'Close')]
    all_control = ['Ap6256HostCipherStoreInvalidateAll', 'Ap6256HostCipherStoreStopAll']
    exports = control + all_control + ['Ap6256HostCipherStoreSnapshot', 'Ap6256HostCipherStoreKeyOwner', 'Ap6256HostCipherStoreSetDefault', 'TestCreate', 'TestDestroy', 'TestPoolCount', 'TestKeyCount', 'TestSetPn', 'TestFailAlloc', 'TestPause', 'TestWaitEntered', 'TestWaitRundown', 'TestUnpause']
    definition = out / 'store.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(exports) + '\n', encoding='ascii')
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in [VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    sources = [AP / 'src/common/host_cipher_frame.c', AP / 'src/common/host_crypto_cng.c', AP / 'tests/host-cipher-store-fixture.c']
    command = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/O2', '/GS', '/MT', '/LD', '/DAP6256_HOST_CRYPTO_USER_TEST']
    command += ['/I' + str(p) for p in [VC / 'include', INC / 'um', INC / 'shared', INC / 'ucrt']]
    command += [str(s) for s in sources] + ['/Fo' + str(out) + '\\', '/Fe' + str(out / 'store.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'store.lib'), 'bcrypt.lib']
    result = subprocess.run(command, cwd=out, env=env, text=True, capture_output=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    dll = c.CDLL(str(out / 'store.dll'))
    dll.TestCreate.restype = c.c_void_p
    dll.TestDestroy.argtypes = [c.c_void_p]
    dll.TestKeyCount.argtypes = [c.c_void_p]
    dll.TestSetPn.argtypes = [c.c_void_p, U64]
    dll.Ap6256HostCipherStoreBegin.argtypes = [c.c_void_p, U32, U32, P8, P8]
    dll.Ap6256HostCipherStoreInstall.argtypes = [c.c_void_p, c.POINTER(Spec)]
    dll.Ap6256HostCipherStoreDelete.argtypes = [c.c_void_p, U32, U32, U32, U16, U8]
    for name in all_control:
        getattr(dll, name).argtypes = [c.c_void_p]
        getattr(dll, name).restype = None
    for name in control[3:5] + [control[7]]:
        getattr(dll, name).argtypes = [c.c_void_p] + ([] if name == control[7] else [U32])
    dll.Ap6256HostCipherStoreTxCurrent.argtypes = [c.c_void_p, U32, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreFrame.argtypes = [c.c_void_p, U32, U32, U32, U16, U8, U8, P8, U32, P8, U32, P8, U32, c.POINTER(U32), c.POINTER(Owner)]
    for name in control[:3] + [control[6]]:
        getattr(dll, name).restype = c.c_long
    checks = 0
    store = dll.TestCreate()
    assert store
    key = bytes(range(32))
    newer = bytes((x ^ 165 for x in key))

    def begin(ifindex, generation):
        nonlocal checks
        checks += 1
        return dll.Ap6256HostCipherStoreBegin(store, ifindex, generation, buf(STATION), buf(APMAC))

    def spec(ifindex=0, generation=100, cipher=9, keyid=0, pair=True, tx=True, rx=True, material=key, receive=0):
        return Spec(ifindex, generation, cipher, keyid, pair, tx, rx, buf(APMAC), buf(material), receive)

    def install(s):
        nonlocal checks
        checks += 1
        return dll.Ap6256HostCipherStoreInstall(store, c.byref(s))

    def invoke(s, encrypt, data):
        nonlocal checks
        output = (U8 * 8192)(*[165] * 8192)
        scratch = (U8 * 8192)()
        written = U32(123)
        owner = Owner(1, 2, 3)
        status = dll.Ap6256HostCipherStoreFrame(store, s.ifindex, s.generation, s.cipher, s.keyid, s.pairwise, encrypt, buf(data), len(data), output, len(output), scratch, len(scratch), c.byref(written), c.byref(owner))
        checks += 1
        if status < 0:
            assert written.value == 0 and (not any(bytes(owner)))
        return (status, bytes(output[:written.value]), owner, bytes(output))

    def current(ifindex, owner):
        nonlocal checks
        checks += 1
        return bool(dll.Ap6256HostCipherStoreTxCurrent(store, ifindex, c.byref(owner)))
    plain = frame(True, b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload', tid=5)
    incoming_plain = frame(False, b'authenticated plaintext', tid=5)
    try:
        assert begin(0, 100) == 0 and begin(1, 200) == 0
        s = spec(receive=10)
        other = spec(ifindex=1, generation=200)
        assert install(s) == 0 and install(other) == 0
        (status, encrypted, owner, _) = invoke(s, True, plain)
        assert status == 0 and encrypted == oracle_gcmp(key, plain, 1) and current(0, owner)
        assert not current(1, owner)
        assert invoke(s, False, oracle_gcmp(key, incoming_plain, 10))[0] < 0
        assert invoke(s, False, oracle_gcmp(key, incoming_plain, 11))[1] == incoming_plain
        assert install(spec(receive=0)) == 0
        assert current(0, owner) and invoke(s, True, plain)[1] == oracle_gcmp(key, plain, 2)
        assert invoke(s, False, oracle_gcmp(key, incoming_plain, 11))[0] < 0
        assert invoke(s, False, oracle_gcmp(key, incoming_plain, 12))[1] == incoming_plain
        dll.TestFailAlloc()
        assert install(spec(material=newer)) < 0 and current(0, owner)
        assert install(spec(receive=1 << 48)) < 0 and current(0, owner)
        bad = spec()
        bad.bssid[5] ^= 1
        assert install(bad) < 0 and current(0, owner)
        assert install(spec(material=newer)) == 0 and (not current(0, owner))
        s = spec(material=newer)
        assert invoke(s, True, plain)[1] == oracle_gcmp(newer, plain, 3)
        assert invoke(other, True, plain)[1] == oracle_gcmp(key, plain, 4)
        assert invoke(s, False, oracle_gcmp(key, incoming_plain, 1))[0] < 0
        assert invoke(s, False, oracle_gcmp(newer, incoming_plain, 1))[1] == incoming_plain
        assert begin(0, 100) < 0
        assert begin(0, 99) < 0
        for keyid in range(4):
            group_material = bytes((x ^ 80 + keyid for x in key))
            group = spec(keyid=keyid, pair=False, tx=False, material=group_material)
            assert install(group) == 0
            for tid in range(16):
                multicast = frame(False, bytes(range(32)), tid=tid, group=True)
                assert invoke(group, False, oracle_gcmp(group_material, multicast, 1, keyid))[1] == multicast
                assert invoke(group, False, oracle_gcmp(group_material, multicast, 1, keyid))[0] < 0
        bip = spec(cipher=12, keyid=4, pair=False)
        assert install(bip) == 0
        group_mgmt = frame(True, b'\x03\x00', management=192, group=True)
        (status, protected, bipowner, _) = invoke(bip, True, group_mgmt)
        assert status == 0 and protected == oracle_bip(key, group_mgmt, 5)
        assert install(spec(cipher=12, keyid=4, pair=False, tx=False)) == 0
        assert not current(0, bipowner)
        assert install(bip) == 0 and invoke(bip, True, group_mgmt)[1] == oracle_bip(key, group_mgmt, 6)
        assert dll.Ap6256HostCipherStoreDelete(store, 0, 100, 12, 4, False) == 0
        assert not current(0, bipowner) and invoke(bip, True, group_mgmt)[0] < 0
        assert invoke(s, False, oracle_gcmp(newer, incoming_plain, 2))[1] == incoming_plain
        assert dll.Ap6256HostCipherStoreDelete(store, 0, 100, 9, 0, True) == 0
        assert install(s) == 0
        assert invoke(s, False, oracle_gcmp(newer, incoming_plain, 2))[0] < 0
        assert invoke(s, False, oracle_gcmp(newer, incoming_plain, 3))[1] == incoming_plain
        assert invoke(s, True, plain)[1] == oracle_gcmp(newer, plain, 7)
        alias = spec(keyid=1, material=newer)
        assert install(alias) == 0
        assert invoke(alias, True, plain)[1] == oracle_gcmp(newer, plain, 8, 1)
        assert invoke(alias, False, oracle_gcmp(newer, incoming_plain, 3, 1))[0] < 0
        assert invoke(alias, False, oracle_gcmp(newer, incoming_plain, 4, 1))[1] == incoming_plain
        assert invoke(s, False, oracle_gcmp(newer, incoming_plain, 4))[0] < 0
        assert dll.Ap6256HostCipherStoreDelete(store, 0, 100, 9, 1, True) == 0

        def paused_frame():
            return invoke(s, True, plain)

        def race(control, wait_rundown=False, invalidate=False):
            results = {}
            dll.TestPause()
            worker = threading.Thread(target=lambda : results.update(frame=paused_frame()))
            worker.start()
            assert dll.TestWaitEntered()
            modifier = threading.Thread(target=lambda : results.update(control=control()))
            modifier.start()
            if wait_rundown:
                assert dll.TestWaitRundown()
                assert modifier.is_alive()
            else:
                modifier.join(5)
                assert not modifier.is_alive()
            if invalidate:
                dll.Ap6256HostCipherStoreInvalidate(store, 0)
            dll.TestUnpause()
            worker.join(5)
            modifier.join(5)
            assert not worker.is_alive() and (not modifier.is_alive())
            assert results['frame'][0] < 0 and (not any(results['frame'][3][:len(plain) + 24]))
            return results
        result = race(lambda : dll.Ap6256HostCipherStoreDelete(store, 0, 100, 9, 0, True), True)
        assert result['control'] == 0
        assert install(s) == 0
        race(lambda : dll.Ap6256HostCipherStoreInvalidate(store, 0))
        assert install(s) < 0 and begin(0, 101) == 0
        s = spec(generation=101, material=newer)
        assert install(s) == 0
        result = race(lambda : begin(0, 102), True, True)
        assert result['control'] < 0 and install(spec(generation=102)) < 0
        assert begin(0, 103) == 0
        s = spec(generation=103, material=newer)
        assert install(s) == 0
        other_owner = invoke(other, True, plain)[2]
        race(lambda : dll.Ap6256HostCipherStoreInvalidateAll(store))
        assert not current(1, other_owner) and invoke(other, True, plain)[0] < 0
        assert begin(0, 104) == 0 and begin(1, 201) == 0
        s = spec(generation=104, material=newer)
        other = spec(ifindex=1, generation=201)
        assert install(s) == 0 and install(other) == 0
        other_owner = invoke(other, True, plain)[2]

        def stop_all():
            dll.Ap6256HostCipherStoreStopAll(store)
        dll.TestPause()
        results = {}
        worker = threading.Thread(target=lambda : results.update(frame=invoke(s, True, plain)))
        worker.start()
        assert dll.TestWaitEntered()
        modifier = threading.Thread(target=stop_all)
        modifier.start()
        assert dll.TestWaitRundown() and modifier.is_alive()
        assert not current(1, other_owner) and invoke(other, True, plain)[0] < 0
        dll.TestUnpause()
        worker.join(5)
        modifier.join(5)
        assert not worker.is_alive() and (not modifier.is_alive())
        assert results['frame'][0] < 0 and (not any(results['frame'][3][:len(plain) + 24]))
        assert dll.TestPoolCount() == 0
        assert begin(0, 104) < 0 and begin(1, 201) < 0
        assert begin(0, 105) == 0
        s = spec(generation=105, material=newer)
        assert install(s) == 0
        race(lambda : dll.Ap6256HostCipherStoreClose(store), True)
        assert install(s) < 0 and invoke(s, True, plain)[0] < 0
        assert dll.TestPoolCount() == 0
        original_store = store
        limits = dll.TestCreate()
        assert limits
        store = limits
        try:
            assert begin(0, 1) == 0
            for sequence in range(4096):
                material = sequence.to_bytes(4, 'little') + bytes(range(4, 32))
                limit_spec = spec(generation=1, material=material)
                assert install(limit_spec) == 0
            assert install(spec(generation=1, material=b'\xff' * 32)) < 0
            assert dll.TestKeyCount(store) == 1
            dll.TestSetPn(store, (1 << 48) - 2)
            assert invoke(limit_spec, True, plain)[1] == oracle_gcmp(material, plain, (1 << 48) - 1)
            assert invoke(limit_spec, True, plain)[0] < 0
            dll.Ap6256HostCipherStoreStopAll(store)
            assert dll.TestPoolCount() == 0
            assert begin(0, 2) == 0 and install(spec(generation=2)) == 0
            assert invoke(spec(generation=2), True, plain)[0] < 0
        finally:
            dll.TestDestroy(limits)
            store = original_store
        assert dll.TestPoolCount() == 0
        inputs = sources + [AP / 'src/common/host_cipher_store.c', AP / 'src/common/host_cipher_store.h', AP / 'src/common/host_cipher_frame.h', AP / 'src/common/host_crypto_cng.h', Path(__file__), Path(__file__).with_name('test-host-cipher-crypto.py')]
        report = {'checks': checks, 'concurrent_races': 6, 'outstanding_key_allocations': dll.TestPoolCount(), 'sources': {str(p.relative_to(AP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}, 'history_capacity': 4096, 'boundary': 'Key-store lifecycle, frame codec, CNG and packet-number history pressure.'}
        write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report))
    finally:
        dll.TestUnpause()
        dll.TestDestroy(store)
        assert dll.TestPoolCount() == 0
if __name__ == '__main__':
    main()
