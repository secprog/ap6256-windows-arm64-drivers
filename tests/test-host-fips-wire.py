# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Run the actual shared C transport against independently packed MPDU vectors.'
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
(U8, U16, U32) = (c.c_ubyte, c.c_ushort, c.c_uint)

class Session(c.Structure):
    _fields_ = [('generation', U32), ('ifindex', U8), ('station', U8 * 6), ('bssid', U8 * 6)]

class View(c.Structure):
    _fields_ = [('frame', c.POINTER(U8)), ('length', U32), ('header', U32), ('fc', U16), ('sequence', U16), ('tid', U8), ('fragmented', U8)]

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, default=output_dir('host-fips-wire'))
    a = p.parse_args()
    out = a.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    definitions = out / 'wire.def'
    write_text(definitions, 'EXPORTS\nAp6256FipsValidateFrame\nAp6256FipsWriteHeader\nAp6256FipsReadEnvelope\n', encoding='ascii')
    env = dict(os.environ)
    env['LIB'] = ';'.join((str(path) for path in [VC / 'lib/x64', LIB / 'um' / 'x64', LIB / 'ucrt' / 'x64']))
    command = [str(VC / 'bin/Hostx64/x64/cl.exe'), '/nologo', '/TC', '/W4', '/WX', '/O2', '/GS', '/MT', '/LD', str(AP / 'src/common/host_fips_wire.c'), '/Fo' + str(out / 'wire.obj'), '/Fe' + str(out / 'wire.dll'), '/link', '/DEF:' + str(definitions), '/IMPLIB:' + str(out / 'wire.lib')]
    result = subprocess.run(command, env=env, cwd=out, text=True, capture_output=True)
    write_text(out / 'compile.log', result.stdout + result.stderr, encoding='utf-8')
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    dll = c.CDLL(str(out / 'wire.dll'))
    validate = dll.Ap6256FipsValidateFrame
    validate.argtypes = [c.POINTER(Session), U8, c.POINTER(U8), U32, c.POINTER(View)]
    write = dll.Ap6256FipsWriteHeader
    write.argtypes = [c.POINTER(Session), U8, U16, c.POINTER(U8), U32, c.POINTER(U8), U32]
    read = dll.Ap6256FipsReadEnvelope
    read.argtypes = [c.POINTER(Session), U8, c.POINTER(U8), U32, c.POINTER(View)]
    for function in (validate, write, read):
        function.restype = c.c_int
    station = bytes.fromhex('021122334455')
    peer = bytes.fromhex('0266778899aa')
    other = bytes.fromhex('02bbccddee00')
    session = Session(305440103, 3, (U8 * 6).from_buffer_copy(station), (U8 * 6).from_buffer_copy(peer))
    rng = random.Random(268)
    checks = 0

    def buffer(data):
        return (U8 * len(data)).from_buffer_copy(data)

    def mpdu(direction, qos=False, htc=False, protected=True, fragment=0, more=False, amsdu=False, multicast=False, length=None, tid=5):
        fc = 8 | (256 if direction == 1 else 512)
        fc |= (128 if qos else 0) | (32768 if htc else 0)
        fc |= (16384 if protected else 0) | (1024 if more else 0)
        (a1, a2, a3) = (peer, station, other) if direction == 1 else (station, peer, other)
        if multicast and direction == 2:
            a1 = bytes.fromhex('01005e000001')
        header = struct.pack('<HH', fc, 4919) + a1 + a2 + a3 + struct.pack('<H', 22128 | fragment)
        if qos:
            header += struct.pack('<H', tid | (128 if amsdu else 0))
            if htc:
                header += bytes.fromhex('11223344')
        body_length = 77 if length is None else length - len(header)
        assert body_length >= 0
        return header + bytes((rng.randrange(256) for _ in range(body_length)))

    def envelope(frame, direction, generation=None, ifindex=None, flags=None):
        header = 160 if direction == 1 else 24
        return struct.pack('<IHHIHBBHHI', 1346979400, 1, header, session.generation if generation is None else generation, len(frame), session.ifindex if ifindex is None else ifindex, direction, (0 if direction == 1 else 3) if flags is None else flags, 0, 0) + bytes(header - 24) + frame

    def is_cleared(view):
        return not view.frame and (not any([view.length, view.header, view.fc, view.sequence, view.tid, view.fragmented]))

    def rejected(data, direction=1, raw=False, active=session):
        nonlocal checks
        b = buffer(data)
        view = View()
        c.memset(c.byref(view), 165, c.sizeof(view))
        assert not (validate if raw else read)(c.byref(active), direction, b, len(b), c.byref(view))
        assert is_cleared(view) and bytes(b) == data
        checks += 1
    for direction in (1, 2):
        for (qos, htc) in ((False, False), (True, False), (True, True)):
            for protected in (False, True):
                for (frag, more) in ((0, False), (0, True), (3, True), (15, False)):
                    for multicast in (False,) if direction == 1 else (False, True):
                        for length in (None, 2048, 4096, 8192):
                            frame = mpdu(direction, qos, htc, protected, frag, more, multicast=multicast, length=length)
                            (b, view) = (buffer(frame), View())
                            assert validate(c.byref(session), direction, b, len(b), c.byref(view))
                            assert view.header == (30 if htc else 26 if qos else 24)
                            assert view.tid == (5 if qos else 0) and view.fragmented == bool(frag or more)
                            assert c.string_at(view.frame, view.length) == frame and bytes(b) == frame
                            header_size = 160 if direction == 1 else 24
                            storage = (U8 * (header_size + 16))(*[90] * (header_size + 16))
                            header_pointer = c.cast(c.byref(storage, 8), c.POINTER(U8))
                            assert write(c.byref(session), direction, 0 if direction == 1 else 3, b, len(b), header_pointer, header_size)
                            expected = envelope(frame, direction)
                            assert bytes(storage)[8:8 + header_size] == expected[:header_size]
                            assert bytes(storage)[:8] == b'Z' * 8 and bytes(storage)[8 + header_size:] == b'Z' * 8
                            wire = buffer(expected)
                            assert read(c.byref(session), direction, wire, len(wire), c.byref(view))
                            assert c.string_at(view.frame, view.length) == frame and bytes(wire) == expected
                            checks += 3
    valid = envelope(mpdu(1, qos=True, htc=True), 1)
    for index in range(160):
        for bit in range(8):
            bad = bytearray(valid)
            bad[index] ^= 1 << bit
            rejected(bad)
    for n in range(len(valid)):
        rejected(valid[:n])
    rejected(valid + b'\x00')
    rejected(valid + valid)
    for direction in (1, 2):
        frame = mpdu(direction)
        for n in range(24 + 16):
            rejected(frame[:n], direction, raw=True)
        rejected(mpdu(direction, length=8193), direction, raw=True)
        for idx in [4, 10] if direction == 1 else [10]:
            bad = bytearray(frame)
            bad[idx] ^= 2
            rejected(bad, direction, raw=True)
        if direction == 2:
            bad = bytearray(frame)
            bad[4] ^= 2
            rejected(bad, direction, raw=True)
        for fc in (0, 4, 8, 776, 328, 584, 265, 521, 264 if direction == 2 else 520):
            bad = bytearray(frame)
            struct.pack_into('<H', bad, 0, fc)
            rejected(bad, direction, raw=True)
        for flags in range(16):
            if flags != (0 if direction == 1 else 3):
                rejected(envelope(frame, direction, flags=flags), direction)
        rejected(envelope(frame, direction, generation=0), direction)
        rejected(envelope(frame, direction, generation=session.generation + 1), direction)
        rejected(envelope(frame, direction, ifindex=2), direction)
    rejected(mpdu(1, qos=True, amsdu=True), raw=True)
    rx_amsdu = buffer(mpdu(2, qos=True, amsdu=True))
    view = View()
    assert validate(c.byref(session), 2, rx_amsdu, len(rx_amsdu), c.byref(view))
    checks += 1
    for (field, value) in [('generation', 0), ('ifindex', 16)]:
        broken = Session.from_buffer_copy(session)
        setattr(broken, field, value)
        rejected(valid, active=broken)
    for field in ('station', 'bssid'):
        for value in (bytes(6), b'\xff' * 6, station if field == 'bssid' else peer):
            broken = Session.from_buffer_copy(session)
            getattr(broken, field)[:] = value
            rejected(valid, active=broken)
    view = View()
    assert not validate(None, 1, None, 0, c.byref(view)) and is_cleared(view)
    assert not read(None, 1, None, 0, c.byref(view)) and is_cleared(view)
    assert not validate(c.byref(session), 1, None, 0, None)
    assert not read(c.byref(session), 1, None, 0, None)
    assert not write(c.byref(session), 1, 0, None, 0, None, 0)
    untouched = (U8 * 160)(*[90] * 160)
    frame = buffer(mpdu(1))
    for capacity in range(160):
        assert not write(c.byref(session), 1, 0, frame, len(frame), untouched, capacity)
        assert bytes(untouched) == b'Z' * 160
        checks += 1
    assert not write(c.byref(session), 1, 3, frame, len(frame), untouched, 160)
    assert bytes(untouched) == b'Z' * 160
    checks += 6
    sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
    report = dict(checks=checks, production_sha256={name: sha(AP / name) for name in ('src/common/host_fips_wire.c', 'src/common/host_fips_wire.h')}, test_sha256=sha(Path(__file__)), dll_sha256=sha(out / 'wire.dll'), compiler=str(VC / 'bin/Hostx64/x64/cl.exe'), firmware_verified=False, windows_crypto_verified=False, board_verified=False)
    write_text(out / 'results.json', json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print('PASS:', checks, 'production wire bounds, connection binding and byte-preservation checks')
if __name__ == '__main__':
    main()
