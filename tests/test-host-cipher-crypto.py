# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute the production host codec with real Microsoft AES-GCM/GMAC CNG.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir, write_text, write_bytes
import argparse
import ctypes as c
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
AP = Path(__file__).resolve().parents[1]
(U8, U16, U32, U64) = (c.c_ubyte, c.c_ushort, c.c_uint, c.c_ulonglong)
P8 = c.POINTER(U8)
AEAD = c.CFUNCTYPE(c.c_int, c.c_void_p, c.c_int, P8, P8, U32, P8, U32, P8, P8)
STATION = bytes.fromhex('021122334455')
APMAC = bytes.fromhex('0266778899aa')
OTHER = bytes.fromhex('02aabbccddee')
GROUP = bytes.fromhex('ffffffffffff')

class State(c.Structure):
    _fields_ = [('cipher', U32), ('keyid', U16), ('pairwise', U8), ('tx', U8), ('station', U8 * 6), ('bssid', U8 * 6), ('rx', U8), ('txpn', U64), ('rxpn', U64 * 18)]

def buf(data):
    return (U8 * len(data)).from_buffer_copy(data)

def frame(tx, body, tid=None, htc=False, management=None, group=False, flags=0, fragment=0):
    fc = (8 if tid is None else 136) | (256 if tx else 512)
    (a1, a2, a3) = (APMAC, STATION, OTHER) if tx else (STATION, APMAC, OTHER)
    if management is not None:
        fc = management
        (a1, a2, a3) = (APMAC, STATION, APMAC) if tx else (STATION, APMAC, APMAC)
    if group:
        a1 = GROUP
    fc |= flags | (32768 if htc else 0)
    header = struct.pack('<HH', fc, 22136) + a1 + a2 + a3 + struct.pack('<H', 43968 | fragment)
    if tid is not None:
        header += struct.pack('<H', tid)
        if htc:
            header += bytes.fromhex('12345678')
    return header + body

def header_len(plain):
    return 24 + (2 + (4 if plain[1] & 128 else 0) if plain[0] == 136 else 0)

def oracle_gcmp(key, plain, pn, keyid=0):
    header = bytearray(plain[:header_len(plain)])
    fc = struct.unpack_from('<H', header)[0] | 16384
    struct.pack_into('<H', header, 0, fc)
    authenticated_fc = fc & ~14336
    if fc & 12 == 8:
        authenticated_fc &= ~112
    if fc & 128:
        authenticated_fc &= ~32768
    aad = struct.pack('<H', authenticated_fc) + header[4:22] + bytes([header[22] & 15, 0])
    if fc & 128 and fc & 12 == 8:
        aad += bytes([header[24] & 15, 0])
    iv = pn.to_bytes(6, 'little')
    wire_iv = iv[:2] + bytes([0, 32 | keyid << 6]) + iv[2:]
    encrypted = AESGCM(key).encrypt(bytes(header[10:16]) + pn.to_bytes(6, 'big'), plain[len(header):], bytes(aad))
    return bytes(header) + wire_iv + encrypted

def oracle_bip(key, plain, pn, keyid=4):
    fc = struct.unpack_from('<H', plain)[0]
    mmie = bytes([76, 24]) + struct.pack('<H', keyid) + pn.to_bytes(6, 'little') + bytes(16)
    aad = struct.pack('<H', fc & ~14336) + plain[4:22] + plain[24:] + mmie
    tag = AESGCM(key).encrypt(plain[10:16] + pn.to_bytes(6, 'big'), b'', aad)
    return plain + mmie[:-16] + tag

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('host-cipher-crypto'))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    exports = ['Ap6256HostCipherInit', 'Ap6256HostCipherEncrypt', 'Ap6256HostCipherDecrypt', 'Ap6256HostCryptoOpen', 'Ap6256HostCryptoClose', 'Ap6256HostCryptoCreateKey', 'Ap6256HostCryptoDestroyKey', 'Ap6256HostCryptoCrypt', 'Ap6256HostCipherRaiseReceivePn']
    definition = out / 'crypto.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(exports) + '\n', encoding='ascii')
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in [VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    sources = [AP / 'src/common/host_cipher_frame.c', AP / 'src/common/host_crypto_cng.c']
    command = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/O2', '/GS', '/MT', '/LD', '/DAP6256_HOST_CRYPTO_USER_TEST']
    command += ['/I' + str(p) for p in [VC / 'include', INC / 'um', INC / 'shared', INC / 'ucrt']]
    command += [str(s) for s in sources] + ['/Fo' + str(out) + '\\', '/Fe' + str(out / 'crypto.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'crypto.lib'), 'bcrypt.lib']
    result = subprocess.run(command, cwd=out, env=env, text=True, capture_output=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    dll = c.CDLL(str(out / 'crypto.dll'))
    dll.Ap6256HostCryptoOpen.argtypes = [c.POINTER(c.c_void_p), c.POINTER(U32)]
    dll.Ap6256HostCryptoCreateKey.argtypes = [c.c_void_p, P8, P8, U32, c.POINTER(c.c_void_p)]
    dll.Ap6256HostCryptoDestroyKey.argtypes = [c.c_void_p, P8, U32]
    dll.Ap6256HostCryptoClose.argtypes = [c.c_void_p]
    for name in exports[3:7]:
        getattr(dll, name).restype = c.c_long
    crypt = AEAD(('Ap6256HostCryptoCrypt', dll))
    init = dll.Ap6256HostCipherInit
    init.argtypes = [c.POINTER(State), U32, U16, c.c_int, c.c_int, c.c_int, P8, P8, U64]
    dll.Ap6256HostCipherRaiseReceivePn.argtypes = [c.POINTER(State), U64]
    for name in exports[1:3]:
        getattr(dll, name).argtypes = [c.POINTER(State), AEAD, c.c_void_p, P8, U32, P8, U32, P8, U32, c.POINTER(U32)]
    provider = c.c_void_p()
    object_bytes = U32()
    assert dll.Ap6256HostCryptoOpen(c.byref(provider), c.byref(object_bytes)) == 0
    assert provider and 0 < object_bytes.value <= 8192
    checks = 0
    handles = []

    def key_handle(key):
        obj = (U8 * object_bytes.value)()
        handle = c.c_void_p()
        assert dll.Ap6256HostCryptoCreateKey(provider, buf(key), obj, len(obj), c.byref(handle)) == 0
        handles.append((handle, obj))
        return handle

    def state(cipher=9, keyid=0, pair=True, tx=True, receive=0, rx=True):
        s = State()
        assert init(c.byref(s), cipher, keyid, int(pair), int(tx), int(rx), buf(STATION), buf(APMAC), receive)
        return s

    def invoke(encrypt, s, handle, data, capacity=8192, scratchcap=8192, crypto=crypt):
        nonlocal checks
        output = (U8 * 8192)(*[165] * 8192)
        scratch = (U8 * 8192)(*[90] * 8192)
        written = U32(3735928559)
        fn = dll.Ap6256HostCipherEncrypt if encrypt else dll.Ap6256HostCipherDecrypt
        ok = fn(c.byref(s), crypto, handle, buf(data), len(data), output, capacity, scratch, scratchcap, c.byref(written))
        checks += 1
        if not ok:
            assert written.value == 0
        else:
            assert 0 < written.value <= capacity
        return (ok, bytes(output[:written.value]), bytes(output), bytes(scratch))
    try:
        zero = key_handle(bytes(32))
        tag = (U8 * 16)()
        ciphertext = (U8 * 16)()
        assert crypt(zero, 1, buf(bytes(12)), None, 0, buf(bytes(16)), 16, ciphertext, tag)
        assert bytes(ciphertext).hex() == 'cea7403d4d606b6e074ec5d3baf39d18'
        assert bytes(tag).hex() == 'd0d1c8a799996bf0265b98b5d48ab919'
        assert crypt(zero, 1, buf(bytes(12)), None, 0, None, 0, None, tag)
        assert bytes(tag).hex() == '530f8afbc74536b9a963b4f1c4cb738b'
        assert crypt(zero, 0, buf(bytes(12)), None, 0, None, 0, None, tag)
        tag[0] ^= 1
        assert not crypt(zero, 0, buf(bytes(12)), None, 0, None, 0, None, tag)
        checks += 6
        rng = random.Random(269)
        key = bytes((rng.randrange(256) for _ in range(32)))
        handle = key_handle(key)
        tx = state()
        for tid in [None] + list(range(16)):
            for htc in [False] if tid is None else [False, True]:
                for length in (0, 1, 31, 128, 1500, 8100):
                    body = bytes((rng.randrange(256) for _ in range(length)))
                    for fragment in (0, 3):
                        plain = frame(True, body, tid, htc, flags=1024 if fragment else 0, fragment=fragment)
                        (ok, encoded, _, _) = invoke(True, tx, handle, plain)
                        assert ok and encoded == oracle_gcmp(key, plain, tx.txpn)
                        received = frame(False, body, tid, htc, flags=1024 if fragment else 0, fragment=fragment)
                        incoming = oracle_gcmp(key, received, 1108152157446)
                        rx = state()
                        (ok, decoded, _, _) = invoke(False, rx, handle, incoming)
                        assert ok and decoded == received
                        assert rx.rxpn[16 if tid is None else tid] == 1108152157446
                        before = bytes(rx)
                        assert not invoke(False, rx, handle, incoming)[0] and bytes(rx) == before
        for (kind, body) in ((160, b'\x08\x00'), (192, b'\x03\x00'), (208, b'\x08\x00Q')):
            plain = frame(True, body, management=kind)
            assert invoke(True, tx, handle, plain)[1] == oracle_gcmp(key, plain, tx.txpn)
            received = frame(False, body, management=kind)
            incoming = oracle_gcmp(key, received, 33)
            rx = state()
            assert invoke(False, rx, handle, incoming)[1] == received and rx.rxpn[17] == 33
        for groupid in range(4):
            for tid in (None, 0, 7, 15):
                received = frame(False, b'group data', tid, group=True)
                rx = state(keyid=groupid, pair=False, tx=False)
                assert invoke(False, rx, handle, oracle_gcmp(key, received, 5, groupid))[1] == received
        plain = frame(False, b'\xaa\xaa\x03\x00\x00\x00\x08\x00' + bytes(range(47)), tid=5)
        incoming = oracle_gcmp(key, plain, 100)
        for offset in list(range(4, 22)) + [22, 24] + list(range(26, len(incoming))):
            broken = bytearray(incoming)
            broken[offset] ^= 1
            rx = state()
            before = bytes(rx)
            (ok, _, _, _) = invoke(False, rx, handle, bytes(broken))
            assert not ok and bytes(rx) == before, offset
        for (offset, mask) in ((1, 8), (1, 16), (1, 32), (2, 255), (3, 255), (22, 240), (23, 255), (24, 32)):
            changed = bytearray(incoming)
            changed[offset] ^= mask
            expected = bytearray(plain)
            expected[offset] ^= mask
            assert invoke(False, state(), handle, bytes(changed))[1] == bytes(expected)
        rx = state()
        assert invoke(False, rx, handle, incoming)[0]
        changed = bytearray(incoming)
        changed[24] = 6
        assert not invoke(False, rx, handle, bytes(changed))[0] and rx.rxpn[6] == 0
        nextq = frame(False, b'new TID', tid=6)
        assert invoke(False, rx, handle, oracle_gcmp(key, nextq, 99))[0]
        for keyid in (4, 5):
            for (kind, body) in ((160, b'\x08\x00'), (192, b'\x03\x00'), (208, b'\n\x01\x04' + bytes(500))):
                txb = state(12, keyid, False, True)
                plain = frame(True, body, management=kind, group=True)
                (ok, encoded, _, scratch) = invoke(True, txb, handle, plain)
                assert ok and encoded == oracle_bip(key, plain, 1, keyid)
                assert not any(scratch[:len(encoded) - 4])
                received = frame(False, body, management=kind, group=True)
                incoming_bip = oracle_bip(key, received, 1108152157446, keyid)
                rxb = state(12, keyid, False, False)
                (ok, decoded, _, scratch) = invoke(False, rxb, handle, incoming_bip)
                assert ok and decoded == received and (rxb.rxpn[17] == 1108152157446)
                assert not any(scratch[:len(incoming_bip) - 4])
                assert not invoke(False, rxb, handle, incoming_bip)[0]
                for offset in [0] + list(range(4, 22)) + list(range(24, len(incoming_bip))):
                    broken = bytearray(incoming_bip)
                    broken[offset] ^= 1
                    fresh = state(12, keyid, False, False)
                    before = bytes(fresh)
                    assert not invoke(False, fresh, handle, bytes(broken))[0] and bytes(fresh) == before
                for (offset, mask) in ((1, 8), (1, 16), (1, 32), (2, 255), (22, 255), (23, 255)):
                    changed = bytearray(incoming_bip)
                    changed[offset] ^= mask
                    expected = bytearray(received)
                    expected[offset] ^= mask
                    if offset == 22:
                        assert not invoke(False, state(12, keyid, False, False), handle, bytes(changed))[0]
                    else:
                        assert invoke(False, state(12, keyid, False, False), handle, bytes(changed))[1] == bytes(expected)
        for (cipher, keyid, pair, txok) in ((0, 0, True, True), (9, 4, True, True), (9, 0, False, True), (12, 4, True, True), (12, 6, False, False)):
            bad = State()
            c.memset(c.byref(bad), 165, c.sizeof(bad))
            assert not init(c.byref(bad), cipher, keyid, int(pair), int(txok), 1, buf(STATION), buf(APMAC), 0)
            assert bytes(bad) == bytes(c.sizeof(bad))
            checks += 1
        for category in (4, 7, 11, 15, 20, 21, 22, 127):
            assert not invoke(True, state(), handle, frame(True, bytes([category, 0]), management=208))[0]
            assert not invoke(False, state(), handle, oracle_gcmp(key, frame(False, bytes([category, 0]), management=208), 1))[0]
            assert not invoke(True, state(12, 4, False, True), handle, frame(True, bytes([category, 0]), management=208, group=True))[0]
        for size in range(24):
            assert not invoke(True, state(), handle, bytes(size))[0]
        assert not invoke(True, state(), handle, frame(True, b'data', tid=128))[0]
        assert not invoke(True, state(), handle, frame(True, b'\x03\x00', management=192, fragment=1))[0]
        assert not invoke(True, state(), handle, frame(True, b'x'), capacity=24)[0]
        assert not invoke(True, state(12, 4, False, True), handle, frame(True, b'\x03\x00', management=192, group=True), scratchcap=1)[0]
        exhausted = state()
        exhausted.txpn = (1 << 48) - 1
        before = bytes(exhausted)
        assert not invoke(True, exhausted, handle, frame(True, b'x'))[0] and bytes(exhausted) == before
        assert not invoke(False, state(receive=100), handle, incoming)[0]
        assert not invoke(False, state(rx=False), handle, incoming)[0]
        assert not invoke(True, state(tx=False), handle, frame(True, b'x'))[0]
        reinstall = state(receive=50)
        reinstall.txpn = 1000
        reinstall.rxpn[5] = 2000
        assert dll.Ap6256HostCipherRaiseReceivePn(c.byref(reinstall), 10)
        assert reinstall.txpn == 1000 and reinstall.rxpn[5] == 2000 and (reinstall.rxpn[0] == 50)
        assert dll.Ap6256HostCipherRaiseReceivePn(c.byref(reinstall), 100)
        assert reinstall.txpn == 1000 and reinstall.rxpn[5] == 2000 and (reinstall.rxpn[0] == 100)
        before = bytes(reinstall)
        assert not dll.Ap6256HostCipherRaiseReceivePn(c.byref(reinstall), 1 << 48)
        assert bytes(reinstall) == before
        checks += 3

        @AEAD
        def fail(context, encrypt, nonce, aad, aadlen, input_data, inputlen, output, tag):
            if output and inputlen:
                c.memset(output, 204, inputlen)
            c.memset(tag, 221, 16)
            return 0
        failure = state()
        failed_plain = frame(True, b'secret')
        (ok, _, tentative, _) = invoke(True, failure, handle, failed_plain, crypto=fail)
        assert not ok and failure.txpn == 1 and (not any(tentative[:len(failed_plain) + 24]))
        failure = state()
        failed_incoming = oracle_gcmp(key, frame(False, b'secret'), 55)
        (ok, _, tentative, _) = invoke(False, failure, handle, failed_incoming, crypto=fail)
        assert not ok and (not any(failure.rxpn)) and (not any(tentative[:len(failed_incoming) - 24]))
        failure = state(12, 4, False, True)
        plain = frame(True, b'\x03\x00', management=192, group=True)
        (ok, _, tentative, scratch) = invoke(True, failure, handle, plain, crypto=fail)
        assert not ok and failure.txpn == 1 and (not any(tentative[:len(plain) + 26]))
        assert not any(scratch[:len(plain) + 22])
        report = {'checks': checks, 'provider': 'Microsoft Primitive Provider / Windows CNG, user mode', 'independent_oracle': 'Python cryptography AESGCM', 'key_object_bytes': object_bytes.value, 'state_bytes': c.sizeof(State), 'sources': {str(p.relative_to(AP)): hashlib.sha256(p.read_bytes()).hexdigest() for p in sources + [AP / 'src/common/host_cipher_frame.h', AP / 'src/common/host_crypto_cng.h', Path(__file__)]}, 'boundary': 'Host frame codec and Microsoft AES-GCM/GMAC CNG.'}
        write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report))
    finally:
        for (handle, obj) in handles:
            assert dll.Ap6256HostCryptoDestroyKey(handle, obj, len(obj)) == 0
            assert not any(obj)
        assert dll.Ap6256HostCryptoClose(provider) == 0
if __name__ == '__main__':
    main()
