# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Execute public RSNE validation against read-only, page-bounded inputs.'
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
AP = Path(__file__).resolve().parents[1]
(U8, U32, P8) = (c.c_ubyte, c.c_uint, c.POINTER(c.c_ubyte))

class Rsn(c.Structure):
    _fields_ = [('pairwise', P8), ('akms', P8), ('pmkids', P8), ('pairwise_count', U32), ('akm_count', U32), ('pmkid_count', U32), ('group', U32), ('management', U32), ('caps', c.c_ushort)]

def suite(n):
    return bytes((0, 15, 172, n))

def ie(akm=2, mfp=2, pairs=(9,), akms=None, group=9, management=12, pmkids=(), capabilities=None, include_caps=True, include_tail=True):
    akms = (akm,) if akms is None else akms
    body = struct.pack('<H', 1) + suite(group)
    for values in (pairs, akms):
        body += struct.pack('<H', len(values)) + b''.join((suite(v) for v in values))
    if include_caps:
        body += struct.pack('<H', (192 if mfp == 2 else 128 if mfp else 0) if capabilities is None else capabilities)
    if include_tail:
        body += struct.pack('<H', len(pmkids)) + b''.join(pmkids)
        if management is not None:
            body += suite(management)
    assert len(body) <= 255
    return bytes((48, len(body))) + body

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=output_dir('host-cipher-rsn'))
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    names = ['Ap6256HostCipherRsn' + suffix for suffix in ('Read', 'Match', 'Pmkid')]
    names.append('Ap6256Wpa3EnterpriseRsnMatch')
    definition = out / 'rsn.def'
    write_text(definition, 'EXPORTS\n' + '\n'.join(names) + '\n', encoding='utf-8')
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(p) for p in (VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64')))
    command = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/O2', '/GS', '/MT', '/LD', str(AP / 'src/common/host_cipher_rsn.c'), '/Fo' + str(out) + '\\', '/Fe' + str(out / 'rsn.dll'), '/link', '/DEF:' + str(definition), '/IMPLIB:' + str(out / 'rsn.lib')]
    compiled = subprocess.run(command, cwd=out, env=env, capture_output=True, text=True)
    write_text(out / 'compile.log', compiled.stdout + compiled.stderr, encoding='utf-8')
    assert not compiled.returncode, compiled.stdout + compiled.stderr
    dll = c.CDLL(str(out / 'rsn.dll'))
    dll.Ap6256HostCipherRsnRead.argtypes = [P8, U32, c.POINTER(Rsn)]
    dll.Ap6256HostCipherRsnMatch.argtypes = [c.POINTER(Rsn), U32, U32, c.c_int]
    dll.Ap6256HostCipherRsnPmkid.argtypes = [c.POINTER(Rsn), P8, c.c_int]
    dll.Ap6256Wpa3EnterpriseRsnMatch.argtypes = [c.POINTER(Rsn), c.c_int]
    kernel = c.WinDLL('kernel32', use_last_error=True)
    kernel.VirtualAlloc.argtypes = [c.c_void_p, c.c_size_t, U32, U32]
    kernel.VirtualAlloc.restype = c.c_void_p
    kernel.VirtualProtect.argtypes = [c.c_void_p, c.c_size_t, U32, c.POINTER(U32)]
    kernel.VirtualFree.argtypes = [c.c_void_p, c.c_size_t, U32]
    address = kernel.VirtualAlloc(None, 16384, 12288, 4)
    assert address
    old = U32()
    assert kernel.VirtualProtect(address + 12288, 4096, 1, c.byref(old))
    checks = 0

    def check(value):
        nonlocal checks
        assert value, checks
        checks += 1

    def read(data):
        assert len(data) <= 8192
        assert kernel.VirtualProtect(address, 12288, 4, c.byref(old))
        ptr = address + 12288 - len(data)
        if data:
            c.memmove(ptr, data, len(data))
        assert kernel.VirtualProtect(address, 12288, 2, c.byref(old))
        result = Rsn()
        c.memset(c.byref(result), 165, c.sizeof(result))
        accepted = dll.Ap6256HostCipherRsnRead(c.cast(ptr, P8), len(data), c.byref(result))
        check(c.string_at(ptr, len(data)) == data)
        if not accepted:
            check(bytes(result) == bytes(c.sizeof(result)))
        return (accepted, result)

    def match(data, akm=2, mfp=2, station=1):
        (accepted, result) = read(data)
        return bool(accepted and dll.Ap6256HostCipherRsnMatch(c.byref(result), akm, mfp, station))

    def enterprise(data, station=1):
        (accepted, result) = read(data)
        return bool(accepted and dll.Ap6256Wpa3EnterpriseRsnMatch(c.byref(result), station))
    try:
        for akm in (1, 2, 5, 8, 12, 18):
            for cipher in (4, 9):
                for mfp in range(3):
                    data = ie(akm, mfp, pairs=(cipher,), group=cipher, management=6)
                    check(enterprise(data) == (akm == 5 and cipher == 4 and (mfp == 2)))
                    check(enterprise(data, 0) == (akm == 5 and cipher == 4 and (mfp != 0)))
        selected = ie(5, pairs=(4,), group=4, management=6)
        for n in range(len(selected)):
            check(not enterprise(selected[:n]))
        for changed in (ie(5, pairs=(4, 9), group=4, management=6), ie(5, pairs=(4,), akms=(1, 5), group=4, management=6), ie(5, pairs=(4,), group=4, management=12), ie(5, pairs=(4,), group=4, management=6, capabilities=1216)):
            check(not enterprise(changed))
        check(enterprise(ie(5, pairs=(9, 4), akms=(1, 5), group=4, management=6), 0))
        check(enterprise(ie(5, pairs=(4,), group=4, management=None, include_tail=False)))
        check(not enterprise(selected, -1))
        check(not enterprise(selected, 2))
        check(not dll.Ap6256Wpa3EnterpriseRsnMatch(None, 1))
        for akm in (1, 2, 5, 8, 12, 18):
            for mfp in range(3):
                data = ie(akm, mfp, management=12 if mfp else None)
                supported = akm in (1, 2) or mfp == 2
                check(match(data, akm, mfp) == supported)
                check(match(data, akm, mfp, 0) == supported)
                if supported:
                    for other in (0, 3, 4, 6, 7, 9, 11, 13, 256, 4294967295):
                        check(not match(data, other, mfp))
        for data in (ie(group=4), ie(pairs=(4,)), ie(akms=(1,)), ie(management=6), ie(capabilities=128), ie(capabilities=64), ie(capabilities=1216), ie(capabilities=0), ie(pairs=(9, 4)), ie(akms=(2, 1))):
            check(not match(data))
        check(match(ie(pairs=(4, 9), akms=(1, 2), capabilities=128), station=0))
        check(not match(ie(capabilities=192), mfp=0, station=0))
        check(match(ie(mfp=0, management=None, include_caps=False, include_tail=False), mfp=0))
        check(not match(ie(mfp=0, include_tail=False), mfp=2))
        for mfp in (3, 4294967295):
            check(not match(ie(), mfp=mfp))
        check(not match(ie(), station=-1))
        check(not match(ie(), station=2))
        for data in (ie(), ie(pmkids=(bytes(range(16)), bytes(range(16, 32)))), ie(pairs=(4, 9), akms=(1, 2, 8)), ie(management=None)):
            for n in range(len(data)):
                check(not read(data[:n])[0])
        for offset in (8, 14, 22):
            for count in (0, 65535):
                data = bytearray(ie())
                struct.pack_into('<H', data, offset, count)
                if offset == 22 and (not count):
                    check(read(bytes(data))[0])
                else:
                    check(not read(bytes(data))[0])
        for data in (b'', b'0', b'0\xff', ie() + ie(), ie() + b'\x01', ie() + b'\x01\x02\x00', bytes((48, 0)), b'\x00\x00', ie()[:-1] + b'\x00\x00', ie(include_caps=False, include_tail=True)):
            check(not read(data)[0])
        for tail in (b'\x00', b'\x00\x00\x00', b'\x00' * 5):
            data = bytearray(ie())
            data[1] += len(tail)
            data += tail
            check(not read(bytes(data))[0])
        data = bytearray(ie())
        data[2] = 2
        check(not read(bytes(data))[0])
        ident = bytes(range(16))
        buf = (U8 * 16).from_buffer_copy(ident)
        for (pmkids, station, expected) in (((), 1, False), ((ident,), 1, True), ((ident, bytes(16)), 1, False), ((bytes(16), ident), 0, True), ((bytes(16),), 0, False)):
            (accepted, result) = read(ie(pmkids=pmkids))
            check(accepted)
            check(bool(dll.Ap6256HostCipherRsnPmkid(c.byref(result), buf, station)) == expected)
        check(not dll.Ap6256HostCipherRsnRead(None, 0, None))
        check(not dll.Ap6256HostCipherRsnMatch(None, 2, 2, 1))
        check(not dll.Ap6256HostCipherRsnPmkid(None, buf, 1))
        rng = random.Random(25174)
        for _ in range(2000):
            length = rng.randrange(0, 258)
            data = bytes((rng.randrange(256) for _ in range(length)))
            read(data)
        (accepted, result) = read(b'\x00\x00' * 4082 + ie())
        check(accepted)
        result = Rsn()
        check(not dll.Ap6256HostCipherRsnRead(c.cast(address, P8), 8193, c.byref(result)))
    finally:
        assert kernel.VirtualFree(address, 0, 32768)
    sources = ['src/common/host_cipher_rsn.c', 'src/common/host_cipher_rsn.h', 'src/common/host_cipher_frame.h', 'tests/test-host-cipher-rsn.py']
    digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = dict(checks=checks, read_only_guard_pages=True, randomized_cases=2000, sources={name: digest(AP / name) for name in sources}, dll_sha256=digest(out / 'rsn.dll'), compiler_sha256=digest(Path(command[0])))
    write_text(out / 'result.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(f'PASS: {checks} public RSNE checks; read-only guard pages, strict suites and PMKID lists')
if __name__ == '__main__':
    main()
