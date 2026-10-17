# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import json
import os
import runpy
import sys


def main():
    script = Path(sys.argv[1]).resolve()
    root = Path(__file__).resolve().parents[1]
    output = Path(os.environ['AP6256_TEST_OUTPUT']).resolve()
    allowed = [root, output, Path(sys.base_prefix).resolve(), Path(sys.prefix).resolve()]
    for key in ('AP6256_TEST_VC', 'VCToolsInstallDir', 'AP6256_TEST_SDK', 'WindowsSdkDir', 'AP6256_TEST_EWDK'):
        if os.environ.get(key):
            allowed.append(Path(os.environ[key]).resolve())
    for key in ('AP6256_TEST_EXTRA_INCLUDE', 'AP6256_TEST_EXTRA_LIB', 'AP6256_TEST_EXTRA_KIT'):
        allowed += [Path(value).resolve() for value in os.environ.get(key, '').split(os.pathsep) if value]
    windows = Path(os.environ.get('SystemRoot', 'C:/Windows')).resolve()
    allowed.append(windows)
    import toolchain
    allowed += [toolchain.VC.resolve(), toolchain.SDK.resolve()]
    files = set()

    def audit(event, args):
        if event == 'socket.connect':
            raise PermissionError('Host tests must not access the network.')
        if event != 'open' or not isinstance(args[0], (str, bytes, os.PathLike)):
            return
        candidate = Path(os.fsdecode(args[0])).resolve()
        if str(candidate).lower() in ('nul', '\\\\.\\nul') or candidate.name.lower() == 'nul':
            return
        if not any(candidate == base or base in candidate.parents for base in allowed):
            raise PermissionError('Test attempted to access an undeclared file: ' + str(candidate))
        files.add(str(candidate))

    sys.addaudithook(audit)
    sys.argv = [str(script)] + sys.argv[2:]
    try:
        runpy.run_path(str(script), run_name='__main__')
    finally:
        receipt = output / 'file-access.json'
        receipt.parent.mkdir(parents=True, exist_ok=True)
        receipt.write_text(json.dumps(dict(python_file_access=sorted(files), network_allowed=False,
                                          boundary='Python file-access audit.'), indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
