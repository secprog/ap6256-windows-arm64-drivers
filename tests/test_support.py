# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import os
import tempfile


def output_dir(name):
    base = Path(os.environ.get('AP6256_TEST_OUTPUT', Path(tempfile.gettempdir()) / 'ap6256-host-tests')).resolve()
    checkout = Path(__file__).resolve().parents[1]
    if base == checkout or checkout in base.parents:
        raise ValueError('Test outputs must be outside the source checkout.')
    return base / name


def generated_text(path, text, bluetooth=False):
    if Path(path).suffix.lower() not in ('.c', '.cpp', '.h', '.inc'):
        return text
    root = Path(__file__).resolve().parents[1]
    notice = (root / 'NOTICE.txt').read_text(encoding='utf-8-sig')
    isc = (root / 'LICENSE-ISC.txt').read_text(encoding='utf-8-sig')
    header = ('Project-authored test harness portions: GPL-3.0-only.\n'
              'Driver fragment licenses and notices follow.\n'
              'Microsoft SDK/WDK material retains Microsoft SDK license terms.\n\n'
              + notice + '\n' + isc)
    if bluetooth:
        permission = (root / 'BLUETOOTH-LINKING-EXCEPTION.txt').read_text(encoding='utf-8-sig')
        mspl = (root / 'bt/LICENSE-MS-PL.txt').read_text(encoding='utf-8-sig')
        header += ('\nProject-authored Bluetooth test portions carry the additional permission below.\n'
                   'Extracted bt/src/io.c and bt/src/io.h portions: MS-PL.\n'
                   'Copyright (c) Microsoft Corporation All Rights Reserved\n\n'
                   + permission + '\n' + mspl)
    return '/*\n' + header.replace('*/', '* /') + '\n*/\n' + text


def write_text(path, text, encoding='utf-8', errors=None):
    return Path(path).write_text(generated_text(path, text), encoding=encoding, errors=errors)


def write_bytes(path, data):
    if Path(path).suffix.lower() in ('.c', '.cpp', '.h', '.inc'):
        data = generated_text(path, data.decode('utf-8-sig')).encode('utf-8')
    return Path(path).write_bytes(data)


def write_bluetooth_text(path, text, encoding='utf-8'):
    return Path(path).write_text(generated_text(path, text, bluetooth=True), encoding=encoding)
