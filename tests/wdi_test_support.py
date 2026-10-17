# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

"""Use the shipping WDI contract in host tests; allow an older-wire matrix."""
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir
from driver_sources import read_source_text
from pathlib import Path
import os
import re

def contract_preamble():
    header = read_source_text(Path(__file__).resolve().parents[1] / 'src/common/ap6256.h')
    version = os.environ.get('AP6256_TEST_WDI_VERSION') or re.search('^#define\\s+AP6256_WDI_VERSION\\s+(WDI_VERSION_\\d+_\\d+(?:_\\d+)?)', header, re.M)[1]
    if not re.fullmatch('WDI_VERSION_\\d+_\\d+(?:_\\d+)?', version):
        raise ValueError('Invalid AP6256_TEST_WDI_VERSION')
    owe = read_source_text(Path(__file__).resolve().parents[1] / 'src/common/wifi_ops.h')
    return '#define AP6256_TEST_WDI_VERSION ' + version + '\n' + '\n'.join((line for line in owe.splitlines() if line.startswith('#define AP6256_OWE_'))) + '\n'
