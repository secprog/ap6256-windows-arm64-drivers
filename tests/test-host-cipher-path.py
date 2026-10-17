# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute management relay replies with the production store/codec and real CNG.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import subprocess
import threading
STORE = runpy.run_path(str(Path(__file__).with_name('test-host-cipher-store.py')))
H = STORE['HELPERS']
(AP, VC, SDK) = (H[s] for s in ('AP', 'VC', 'SDK'))
(frame, oracle_gcmp, oracle_bip, buf) = (H[s] for s in ('frame', 'oracle_gcmp', 'oracle_bip', 'buf'))
(STATION, APMAC) = (H['STATION'], H['APMAC'])
(Spec, Owner) = (STORE['Spec'], STORE['Owner'])
(U8, U16, U32, U64, P8) = (STORE[s] for s in ('U8', 'U16', 'U32', 'U64', 'P8'))

def wire(kind, body=b'', token=1, epoch=0, generation=10, ifindex=0):
    header = 160 if kind in (1, 6, 8, 10, 11) else 24
    return struct.pack('<IHHIIHBBI', 827802440, 1, header, generation, token, len(body), ifindex, kind, epoch) + bytes(header - 24) + body

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=output_dir('host-cipher-path'))
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    fixture = out / 'path-fixture.c'
    write_bytes(fixture, ('#include "' + str(AP / 'tests/host-cipher-store-fixture.c').replace('\\', '/') + '"\n#include "' + str(AP / 'src/common/host_cipher_path.c').replace('\\', '/') + '"\n').encode())
    exports = ['Ap6256HostCipherStore' + s for s in ('Begin', 'Install', 'Delete', 'Invalidate', 'SetDefault', 'Default', 'KeyOwner', 'EpochOwner', 'OwnerCurrent', 'Authorize', 'Authorized')]
    exports += ['Ap6256HostCipherManagementReply', 'Ap6256HostCipherManagementTx', 'Ap6256HostCipherPathTxCurrent', 'Ap6256HostCipherPathDestination', 'TestCreate', 'TestDestroy', 'TestPoolCount', 'TestPause', 'TestWaitEntered', 'TestUnpause', 'Ap6256HostCipherDataTx', 'Ap6256HostCipherDataRx', 'Ap6256HostCipherDataRxRead']
    definition = out / 'path.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(exports) + '\n', encoding='utf-8')
    sources = [AP / 'src/common/host_cipher_frame.c', AP / 'src/common/host_crypto_cng.c', AP / 'src/common/host_cipher_wire.c', fixture]
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in [VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    cmd = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/O2', '/GS', '/MT', '/LD', '/DAP6256_HOST_CRYPTO_USER_TEST']
    cmd += ['/I' + str(p) for p in [VC / 'include', INC / 'um', INC / 'shared', INC / 'ucrt']]
    cmd += [str(p) for p in sources] + ['/Fo' + str(out) + '\\', '/Fe' + str(out / 'path.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'path.lib'), 'bcrypt.lib']
    build = subprocess.run(cmd, cwd=out, env=env, text=True, capture_output=True)
    write_text(out / 'compile.log', build.stdout + build.stderr, encoding='utf-8')
    assert build.returncode == 0, build.stdout + build.stderr
    dll = c.CDLL(str(out / 'path.dll'))
    dll.TestCreate.restype = c.c_void_p
    dll.TestDestroy.argtypes = [c.c_void_p]
    dll.Ap6256HostCipherStoreBegin.argtypes = [c.c_void_p, U32, U32, P8, P8]
    dll.Ap6256HostCipherStoreInstall.argtypes = [c.c_void_p, c.POINTER(Spec)]
    dll.Ap6256HostCipherStoreDelete.argtypes = [c.c_void_p, U32, U32, U32, U16, U8]
    dll.Ap6256HostCipherStoreInvalidate.argtypes = [c.c_void_p, U32]
    dll.Ap6256HostCipherStoreSetDefault.argtypes = [c.c_void_p, U32, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreKeyOwner.argtypes = [c.c_void_p, U32, U32, U32, U8, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreDefault.argtypes = [c.c_void_p, U32, U32, U8, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreEpochOwner.argtypes = [c.c_void_p, U32, U32, U32, U8, c.POINTER(Owner)]
    dll.Ap6256HostCipherStoreOwnerCurrent.argtypes = [c.c_void_p, U32, c.POINTER(Owner), U8]
    dll.Ap6256HostCipherManagementReply.argtypes = [c.c_void_p, U32, P8, U32, P8, U32, P8, U32, c.POINTER(U32)]
    dll.Ap6256HostCipherManagementTx.argtypes = [c.c_void_p, U32, P8, U32, P8, U32, P8, U32, c.POINTER(U32)]
    dll.Ap6256HostCipherPathTxCurrent.argtypes = [c.c_void_p, U32, P8, U32]
    dll.Ap6256HostCipherPathDestination.argtypes = [c.c_void_p, U32, P8, U32, P8]
    dll.Ap6256HostCipherStoreAuthorize.argtypes = [c.c_void_p, U32, U32, U8]
    dll.Ap6256HostCipherStoreAuthorized.argtypes = [c.c_void_p, U32, U32]
    dll.Ap6256HostCipherDataTx.argtypes = [c.c_void_p, U32, P8, U32, U8, P8, U32, c.POINTER(U32), P8]
    dll.Ap6256HostCipherDataRx.argtypes = [c.c_void_p, U32, P8, U32, P8, U32, c.POINTER(U32)]
    dll.Ap6256HostCipherDataRxRead.argtypes = [c.c_void_p, U32, P8, U32, P8]
    for name in ('Ap6256HostCipherPathTxCurrent', 'Ap6256HostCipherPathDestination', 'Ap6256HostCipherStoreDefault', 'Ap6256HostCipherStoreKeyOwner', 'Ap6256HostCipherStoreEpochOwner', 'Ap6256HostCipherStoreOwnerCurrent', 'Ap6256HostCipherStoreAuthorized', 'Ap6256HostCipherDataRxRead'):
        getattr(dll, name).restype = U8
    for name in ('Ap6256HostCipherStoreBegin', 'Ap6256HostCipherStoreInstall', 'Ap6256HostCipherStoreDelete', 'Ap6256HostCipherStoreSetDefault', 'Ap6256HostCipherManagementReply', 'Ap6256HostCipherManagementTx', 'Ap6256HostCipherDataTx', 'Ap6256HostCipherDataRx', 'Ap6256HostCipherStoreAuthorize'):
        getattr(dll, name).restype = c.c_long
    store = dll.TestCreate()
    assert store
    checks = 0
    txpn = 0
    rxpn = 10
    key = bytes(range(32))
    second = bytes((x ^ 165 for x in key))

    def check(value):
        nonlocal checks
        checks += 1
        assert value

    def install(cipher=9, keyid=0, tx=True, rx=True, material=key, generation=10):
        check(dll.Ap6256HostCipherStoreInstall(store, c.byref(Spec(0, generation, cipher, keyid, cipher == 9 and keyid < 2, tx, rx, buf(APMAC), buf(material), 0))) == 0)
        owner = Owner()
        slot = keyid if cipher == 9 else keyid + 2
        check(bool(dll.Ap6256HostCipherStoreKeyOwner(store, 0, generation, slot, not rx, c.byref(owner))))
        return owner

    def reply(request, ifindex=0, capacity=1950):
        output = (U8 * capacity)(*[165] * capacity)
        scratch = (U8 * 8192)()
        written = U32(123)
        status = dll.Ap6256HostCipherManagementReply(store, ifindex, buf(request), len(request), output, capacity, scratch, len(scratch), c.byref(written))
        check(not any(scratch))
        check(status >= 0 or written.value == 0)
        return (status, bytes(output[:written.value]), bytes(output))

    def current(data, ifindex=0):
        return bool(dll.Ap6256HostCipherPathTxCurrent(store, ifindex, buf(data), len(data)))
    try:
        check(dll.Ap6256HostCipherStoreBegin(store, 0, 10, buf(STATION), buf(APMAC)) == 0)
        zero = install()
        one = install(keyid=1, material=second)
        igtk = install(cipher=12, keyid=4, tx=False, material=second)
        plain = frame(True, b'\x08\x00', management=192)
        check(reply(wire(5, plain))[1] == wire(7))
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(zero)) == 0)
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(igtk)) < 0)
        for (subtype, body) in ((160, b'\x08\x00'), (192, b'\x03\x00'), (208, b'\x08\x01abcdefgh')):
            plain = frame(True, body, management=subtype)
            txpn += 1
            (status, answer, _) = reply(wire(5, plain, token=20 + subtype))
            check(status == 0 and answer == wire(6, oracle_gcmp(key, plain, txpn), token=20 + subtype, epoch=zero.epoch))
            check(current(answer) and (not current(answer, 1)))
            dest = (U8 * 6)()
            check(dll.Ap6256HostCipherPathDestination(store, 0, buf(answer), len(answer), dest) and bytes(dest) == APMAC)
            plain = frame(False, body, management=subtype)
            rxpn += 1
            request = wire(3, oracle_gcmp(key, plain, rxpn), token=30 + subtype)
            check(reply(request)[1] == wire(4, plain, token=30 + subtype, epoch=zero.epoch))
            check(current(wire(4, plain, token=30 + subtype, epoch=zero.epoch)))
            check(reply(request)[1] == wire(7, token=30 + subtype))
            check(reply(wire(3, plain))[1] == wire(7))
        for (subtype, body) in ((160, b'\x08\x00'), (192, b'\x03\x00'), (208, b'\x08\x00abcdefgh')):
            plain = frame(False, body, management=subtype, group=True)
            rxpn += 1
            request = wire(3, oracle_bip(second, plain, rxpn), token=40 + subtype)
            verified = wire(4, plain, token=40 + subtype, epoch=igtk.epoch)
            check(reply(request)[1] == verified and current(verified))
            check(not dll.Ap6256HostCipherStoreOwnerCurrent(store, 0, c.byref(igtk), True))
            plain = frame(True, body, management=subtype, group=True)
            check(reply(wire(5, plain))[1] == wire(7))
        plain = frame(False, b'\x08\x00', management=192)
        rxpn += 1
        good = wire(3, oracle_gcmp(key, plain, rxpn), token=201)
        bad = good[:-1] + bytes([good[-1] ^ 1])
        check(reply(bad)[1] == wire(7, token=201))
        check(reply(good)[1] == wire(4, plain, token=201, epoch=zero.epoch))
        plain = frame(True, b'\x08\x00', management=192)
        for (pos, value) in ((0, 1), (4, 2), (6, 25), (8, 11), (18, 1), (19, 4)):
            malformed = bytearray(wire(5, plain))
            malformed[pos] = value
            check(reply(bytes(malformed))[0] < 0)
        check(reply(wire(5, plain, token=0))[0] < 0)
        check(reply(wire(5, frame(True, b'\x04\x00', management=208)))[0] < 0)
        check(reply(wire(5, plain, ifindex=1))[0] < 0)
        check(reply(wire(5, plain), capacity=24)[1] == wire(7))
        alias = buf(wire(5, plain))
        written = U32(55)
        check(dll.Ap6256HostCipherManagementReply(store, 0, alias, len(alias), alias, len(alias), None, 0, c.byref(written)) < 0 and written.value == 0)
        old = zero
        zero = install(material=second)
        check(reply(wire(5, plain))[1] == wire(7))
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(old)) < 0)
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(zero)) == 0)
        check(not current(wire(6, oracle_gcmp(key, plain, 100), epoch=old.epoch)))
        check(not dll.Ap6256HostCipherStoreEpochOwner(store, 0, 10, igtk.epoch, True, c.byref(Owner())))
        check(dll.Ap6256HostCipherStoreEpochOwner(store, 0, 10, igtk.epoch, False, c.byref(Owner())))
        results = {}
        dll.TestPause()
        worker = threading.Thread(target=lambda : results.update(answer=reply(wire(5, plain, token=400))))
        worker.start()
        check(dll.TestWaitEntered())
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(one)) == 0)
        dll.TestUnpause()
        worker.join(5)
        check(not worker.is_alive())
        check(results['answer'][1] == wire(7, token=400) and (not any(results['answer'][2][160:160 + len(plain) + 24])))
        results = {}
        dll.TestPause()
        rxpn += 1
        request = wire(3, oracle_gcmp(second, frame(False, b'\x08\x00', management=192), rxpn), token=401)
        worker = threading.Thread(target=lambda : results.update(answer=reply(request)))
        worker.start()
        check(dll.TestWaitEntered())
        dll.Ap6256HostCipherStoreInvalidate(store, 0)
        dll.TestUnpause()
        worker.join(5)
        check(not worker.is_alive())
        check(results['answer'][0] < 0 and (not results['answer'][1]) and (not any(results['answer'][2][24:50])))
        check(not current(wire(7)) and reply(wire(5, plain))[0] < 0)
        check(dll.Ap6256HostCipherStoreBegin(store, 0, 11, buf(STATION), buf(APMAC)) == 0)
        check(reply(wire(5, plain))[0] < 0)
        five = install(cipher=12, keyid=5, material=key, generation=11)
        check(dll.Ap6256HostCipherStoreSetDefault(store, 0, c.byref(five)) == 0)
        group = frame(True, b'\x08\x00', management=192, group=True)
        txpn += 2
        answer = reply(wire(5, group, generation=11))[1]
        check(answer == wire(6, oracle_bip(key, group, txpn, keyid=5), epoch=five.epoch, generation=11) and current(answer))
        check(dll.Ap6256HostCipherStoreDelete(store, 0, 11, 12, 5, False) == 0)
        check(not current(answer) and reply(wire(5, group, generation=11))[1] == wire(7, generation=11))
        data_store = dll.TestCreate()
        check(bool(data_store))

        def data_tx(f, exemption=0):
            output = (U8 * 8352)(*[165] * 8352)
            n = U32(123)
            priority = U8(99)
            status = dll.Ap6256HostCipherDataTx(data_store, 0, buf(f), len(f), exemption, output, len(output), c.byref(n), c.byref(priority))
            check(status >= 0 or n.value == 0)
            return (status, bytes(output[:n.value]), priority.value, bytes(output))

        def data_rx(w):
            output = (U8 * 8216)(*[165] * 8216)
            n = U32(123)
            status = dll.Ap6256HostCipherDataRx(data_store, 0, buf(w), len(w), output, len(output), c.byref(n))
            check(status >= 0 or n.value == 0)
            return (status, bytes(output[:n.value]), bytes(output))

        def data_current(w):
            return bool(dll.Ap6256HostCipherPathTxCurrent(data_store, 0, buf(w), len(w)))
        try:
            check(dll.Ap6256HostCipherStoreBegin(data_store, 0, 10, buf(STATION), buf(APMAC)) == 0)
            check(not dll.Ap6256HostCipherStoreAuthorized(data_store, 0, 10))
            eapol = b'\xaa\xaa\x03\x00\x00\x00\x88\x8e\x02\x01\x00\x00'
            ordinary = b'\xaa\xaa\x03\x00\x00\x00\x08\x00payload'
            handshake = frame(True, eapol)
            check(data_tx(handshake, 1)[1] == wire(1, handshake, token=0))
            conditional = data_tx(handshake, 2)[1]
            check(conditional == wire(11, handshake, token=0) and data_current(conditional))
            check(data_tx(frame(True, ordinary), 1)[0] < 0)
            check(data_tx(handshake, 0)[0] < 0)
            for (kid, pairwise, material) in ((0, True, key), (2, False, second)):
                spec = Spec(0, 10, 9, kid, pairwise, pairwise, True, buf(APMAC), buf(material), 0)
                check(dll.Ap6256HostCipherStoreInstall(data_store, c.byref(spec)) == 0)
            ptk = Owner()
            check(dll.Ap6256HostCipherStoreKeyOwner(data_store, 0, 10, 0, True, c.byref(ptk)))
            check(dll.Ap6256HostCipherStoreSetDefault(data_store, 0, c.byref(ptk)) == 0)
            check(not data_current(conditional))
            check(data_tx(handshake, 2)[1] == wire(10, oracle_gcmp(key, handshake, 1), token=0, epoch=ptk.epoch))
            check(data_tx(frame(True, ordinary))[0] < 0)
            check(dll.Ap6256HostCipherStoreAuthorize(data_store, 0, 9, True) < 0)
            check(dll.Ap6256HostCipherStoreAuthorize(data_store, 0, 10, True) == 0)
            pn = 1
            for (tid, htc) in ((None, False), (0, False), (7, False), (15, True)):
                tx = frame(True, ordinary, tid=tid, htc=htc)
                pn += 1
                (status, sent, priority, _) = data_tx(tx)
                check(status == 0 and sent == wire(1, oracle_gcmp(key, tx, pn), token=0, epoch=ptk.epoch))
                check(priority == (0 if tid is None else tid & 7) and data_current(sent))
                received = frame(False, ordinary, tid=tid, htc=htc)
                request = wire(2, oracle_gcmp(key, received, 10), token=0)
                (status, plain_wire, _) = data_rx(request)
                check(status == 0 and plain_wire == wire(9, received, token=0, epoch=ptk.epoch))
                view = (U8 * 64)()
                check(dll.Ap6256HostCipherDataRxRead(data_store, 0, buf(plain_wire), len(plain_wire), view))
                replay = data_rx(request)[0]
                assert not data_current(plain_wire) and replay < 0, (tid, htc, replay, plain_wire[19])
                check(True)
            group = frame(False, ordinary, group=True)
            gtk = Owner()
            check(dll.Ap6256HostCipherStoreKeyOwner(data_store, 0, 10, 4, False, c.byref(gtk)))
            request = wire(2, oracle_gcmp(second, group, 11, keyid=2), token=0)
            corrupt = request[:-1] + bytes([request[-1] ^ 1])
            check(data_rx(corrupt)[0] < 0)
            check(data_rx(request)[1] == wire(9, group, token=0, epoch=gtk.epoch))
            check(data_rx(wire(9, group, token=0, epoch=gtk.epoch))[0] < 0)
            (status, clear, _) = data_rx(wire(2, frame(False, ordinary), token=0))
            check(status == 0 and clear == wire(9, frame(False, ordinary), token=0, epoch=0))
            for f in (frame(False, ordinary, fragment=1), frame(False, ordinary, tid=129)):
                check(data_rx(wire(2, oracle_gcmp(key, f, 30), token=0))[0] < 0)
            check(dll.Ap6256HostCipherStoreAuthorize(data_store, 0, 10, False) == 0)
            check(not data_current(sent))
            check(data_tx(handshake, 0)[1][19] == 10)
            check(data_rx(wire(2, frame(False, eapol), token=0))[1] == wire(9, frame(False, eapol), token=0))
            check(dll.Ap6256HostCipherStoreAuthorize(data_store, 0, 10, True) == 0)
            results = {}
            dll.TestPause()
            worker = threading.Thread(target=lambda : results.update(answer=data_tx(frame(True, ordinary))))
            worker.start()
            check(dll.TestWaitEntered())
            check(dll.Ap6256HostCipherStoreAuthorize(data_store, 0, 10, False) == 0)
            dll.TestUnpause()
            worker.join(5)
            check(not worker.is_alive())
            check(results['answer'][0] < 0 and (not results['answer'][1]) and (not any(results['answer'][3][:160 + len(frame(True, ordinary)) + 24])))
            dll.Ap6256HostCipherStoreInvalidate(data_store, 0)
            check(data_tx(handshake, 1)[0] < 0 and (not data_current(wire(1, handshake, token=0))))
        finally:
            dll.TestUnpause()
            dll.TestDestroy(data_store)
        direct_store = dll.TestCreate()
        check(bool(direct_store))

        def direct_tx(plain, capacity=1950, scratch_capacity=1760):
            output = (U8 * capacity)(*[165] * capacity)
            scratch = (U8 * 1760)()
            n = U32(123)
            status = dll.Ap6256HostCipherManagementTx(direct_store, 0, buf(plain), len(plain), output, capacity, scratch if scratch_capacity else None, scratch_capacity, c.byref(n))
            check(not any(scratch))
            check(status >= 0 or n.value == 0)
            return (status, bytes(output[:n.value]), bytes(output))

        def direct_key(slot, material=key):
            (cipher, keyid) = (12, slot - 2) if slot >= 6 else (9, slot)
            check(dll.Ap6256HostCipherStoreInstall(direct_store, c.byref(Spec(0, 10, cipher, keyid, cipher == 9, True, True, buf(APMAC), buf(material), 0))) == 0)
            owner = Owner()
            check(dll.Ap6256HostCipherStoreKeyOwner(direct_store, 0, 10, slot, True, c.byref(owner)))
            check(dll.Ap6256HostCipherStoreSetDefault(direct_store, 0, c.byref(owner)) == 0)
            return owner
        try:
            check(dll.Ap6256HostCipherStoreBegin(direct_store, 0, 10, buf(STATION), buf(APMAC)) == 0)
            check(not dll.Ap6256HostCipherStoreAuthorized(direct_store, 0, 10))
            pt = direct_key(0)
            mg = direct_key(6, second)
            direct_pn = 0
            for group in (False, True):
                (owner, material, oracle) = (mg, second, oracle_bip) if group else (pt, key, oracle_gcmp)
                for subtype in (160, 192, 208):
                    direct_pn += 1
                    plain = frame(True, b'\x08\x00abcd', management=subtype, group=group)
                    (status, answer, _) = direct_tx(plain)
                    check(status == 0 and answer == wire(8, oracle(material, plain, direct_pn), token=0, epoch=owner.epoch))
                    check(dll.Ap6256HostCipherPathTxCurrent(direct_store, 0, buf(answer), len(answer)))
                    check(not dll.Ap6256HostCipherPathTxCurrent(direct_store, 1, buf(answer), len(answer)))
                maximum = 1760 - (26 if group else 24)
                plain = frame(True, bytes(maximum - 24), management=192, group=group)
                answer = direct_tx(plain)[1]
                direct_pn += 1
                check(len(answer) == 160 + 1760)
                check(direct_tx(plain + b'\x00')[0] < 0)
                check(direct_tx(frame(True, b'\x03\x00', management=192, group=group), capacity=209)[0] < 0)
            for plain in (frame(True, b'\x04\x00', management=208), frame(True, b'data'), frame(False, b'\x03\x00', management=192), frame(True, b'\x03\x00', management=192, fragment=1)):
                check(direct_tx(plain)[0] < 0)
            plain = frame(True, b'\x03\x00', management=192)
            check(direct_tx(plain, scratch_capacity=0)[0] == 0)
            check(direct_tx(frame(True, b'\x03\x00', management=192, group=True), scratch_capacity=0)[0] < 0)
            check(direct_tx(frame(True, b'\x03\x00', management=192, group=True), scratch_capacity=47)[0] < 0)
            alias = buf(plain)
            n = U32(77)
            check(dll.Ap6256HostCipherManagementTx(direct_store, 0, alias, len(alias), alias, len(alias), None, 0, c.byref(n)) < 0 and n.value == 0)
            output = (U8 * 1950)()
            n = U32(77)
            check(dll.Ap6256HostCipherManagementTx(direct_store, 0, buf(plain), len(plain), output, len(output), output, len(output), c.byref(n)) < 0 and n.value == 0)
            before = direct_tx(plain)[1]
            alternate = direct_key(1, second)
            check(not dll.Ap6256HostCipherPathTxCurrent(direct_store, 0, buf(before), len(before)))
            results = {}
            dll.TestPause()
            worker = threading.Thread(target=lambda : results.update(answer=direct_tx(plain)))
            worker.start()
            check(dll.TestWaitEntered())
            check(dll.Ap6256HostCipherStoreSetDefault(direct_store, 0, c.byref(pt)) == 0)
            dll.TestUnpause()
            worker.join(5)
            check(not worker.is_alive())
            check(results['answer'][0] < 0 and (not results['answer'][1]) and (not any(results['answer'][2][:210])))
            results = {}
            dll.TestPause()
            worker = threading.Thread(target=lambda : results.update(answer=direct_tx(plain)))
            worker.start()
            check(dll.TestWaitEntered())
            dll.Ap6256HostCipherStoreInvalidate(direct_store, 0)
            dll.TestUnpause()
            worker.join(5)
            check(not worker.is_alive())
            check(results['answer'][0] < 0 and (not results['answer'][1]) and (not any(results['answer'][2][:210])))
            check(direct_tx(plain)[0] < 0)
        finally:
            dll.TestUnpause()
            dll.TestDestroy(direct_store)
        names = ('src/common/host_cipher_path.c', 'src/common/host_cipher_path.h', 'src/common/host_cipher_store.c', 'src/common/host_cipher_store.h', 'src/common/host_cipher_frame.c', 'src/common/host_cipher_frame.h', 'src/common/host_cipher_wire.c', 'src/common/host_cipher_wire.h', 'src/common/host_crypto_cng.c', 'src/common/host_crypto_cng.h', 'tests/host-cipher-store-fixture.c', 'tests/test-host-cipher-crypto.py', 'tests/test-host-cipher-store.py', 'tests/test-host-cipher-path.py')
        report = dict(checks=checks, concurrent_races=5, direct_management_executed=True, sources={n: hashlib.sha256((AP / n).read_bytes()).hexdigest() for n in names}, dll_sha256=hashlib.sha256((out / 'path.dll').read_bytes()).hexdigest(), boundary='Management reply, key-store, wire/frame codec and CNG paths.', board_verified=False)
        write_bytes(out / 'result.json', (json.dumps(report, indent=2) + '\n').encode())
        print('PASS: %d management/data-path checks, real CNG, five authorization/retirement/default races' % checks)
    finally:
        dll.TestUnpause()
        dll.TestDestroy(store)
        assert dll.TestPoolCount() == 0
if __name__ == '__main__':
    main()
