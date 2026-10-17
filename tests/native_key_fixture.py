# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from toolchain import VC, SDK, INC, LIB
from test_support import output_dir
from pathlib import Path
import re
from driver_sources import _functions
AP = Path(__file__).resolve().parents[1]

def context(text, locks=True):
    source = (AP / 'src/common/ap6256.h').read_text(encoding='utf-8-sig')
    definition = re.search('typedef struct _AP6256_NATIVE_KEY_REF \\{.*?\\} AP6256_NATIVE_KEY_REF;', source, re.S)[0]
    constant = re.search('^#define AP6256_NATIVE_KEY_SLOTS[^\\n]+', source, re.M)[0]
    before = constant + '\n' + definition + '\n'
    if locks and (not re.search('Ap6256LockAcquire\\s*\\(\\s*int\\s*\\*', text)):
        before += 'static void Ap6256LockAcquire(int* p){++*p;}\nstatic void Ap6256LockRelease(int* p){assert(*p>0);--*p;}\n'
    members = r'''int NativeKeyLock=0;AP6256_NATIVE_KEY_REF NativeKeys[AP6256_NATIVE_KEY_SLOTS]={};BOOLEAN NativeDeparturePending=FALSE,NativeDepartureCommitted=FALSE;
'''
    members += 'UINT32 NativeDepartureToken=0,NativeDepartureNext=0,NativeDepartureReason=0;UCHAR NativeDeparturePeer[6]={};\n'
    matches = list(re.finditer('struct (?:Device|GroupPowerDevice|ColdDevice|FactoryDevice) \\{', text))
    assert len(matches) == 1, re.findall('struct (\\w*Device) \\{', text)
    match = matches[0]
    text = text[:match.start()] + before + match[0] + '\n' + members + text[match.end():]
    text += '\n#ifndef STATUS_DEVICE_BUSY\n#define STATUS_DEVICE_BUSY ((LONG)0x80000011)\n#endif\n'
    text += '#ifndef STATUS_INSUFFICIENT_RESOURCES\n#define STATUS_INSUFFICIENT_RESOURCES ((LONG)0xc000009a)\n#endif\n'
    return text

def writer():
    source = (AP / 'src/common/wifi_ops.c').read_text(encoding='utf-8-sig')
    return _functions(source)['Ap6256WifiWriteNativeKey'] + '\n'
