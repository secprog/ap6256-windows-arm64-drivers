# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import ast
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]
CI_FILES = {
    '.github/scripts/run-host-tests.ps1',
    '.github/scripts/host-tests/packages.config',
    '.github/workflows/host-tests.yml',
}
LICENSE_NOTICES = {
    'LICENSE': 'cb8313a59fc95703d2df63a084a1e370d73e08c4fe4862bcf229c11e041541d0',
    'LICENSE-ISC.txt': '89e40d08461fabc87df98cc577f47f274532f2fe35fe1777c90854ba464895e7',
    'NOTICE.txt': '5a857fdc7933e2ed7f2c6663908cbf31fd309015e5fe2ea54fb2e72837a4c73a',
    'BLUETOOTH-LINKING-EXCEPTION.txt': 'c3c1b151f703225eb2990478dc06485213780c8af83bfe2ff5502a14c465a974',
    'bt/LICENSE-MS-PL.txt': '32a3c0e99823f2605f51b527460b715f07be519703cfb602a3fc2cd00af68b6b',
}


def main():
    files = {path.relative_to(ROOT).as_posix() for path in (ROOT / 'tests').rglob('*') if path.is_file()} | CI_FILES
    failures = []
    forbidden = re.compile(r'(?i)(?:[A-Z]:[/\\]+Users[/\\]|woa-port|docs[/\\]reference|before-stage|\b[Vv]2[0-9]{2}\b)')
    allowed_extensions = {'.py', '.c', '.json', '.md', '.txt', '.config', '.ps1', '.yml'}
    for name in sorted(files):
        path = ROOT / name
        if not path.is_file():
            failures.append(dict(missing=name))
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            failures.append(dict(escaped_path=name))
            continue
        if path.name.startswith('r9_') or path.suffix.lower() not in allowed_extensions:
            failures.append(dict(unexpected_asset=name))
            continue
        text = path.read_text(encoding='utf-8-sig')
        if name != 'tests/audit.py' and forbidden.search(text):
            failures.append(dict(private_reference=name))
        license_id = 'GPL-3.0-only AND MS-PL' if name == 'tests/test-bt-acl-read-bounds.py' else 'GPL-3.0-only'
        if (path.suffix.lower() in ('.py', '.c', '.ps1', '.yml', '.config')
                and 'SPDX-License-Identifier: ' + license_id not in text[:450]):
            failures.append(dict(missing_license_notice=name))
        if path.suffix == '.py':
            tree = ast.parse(text, filename=name)
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(item.name.split('.')[0] for item in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split('.')[0])
            if imported & {'unicorn', 'keystone', 'pefile', 'Crypto'}:
                failures.append(dict(unexpected_dependency=name, imports=sorted(imported)))
    for name, digest in LICENSE_NOTICES.items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            failures.append(dict(changed_license_notice=name))
    for name in ('bt/src/io.c', 'bt/src/io.h'):
        header = (ROOT / name).read_text(encoding='utf-8-sig')[:450]
        if ('SPDX-License-Identifier: MS-PL' not in header
                or 'Copyright (c) Microsoft Corporation All Rights Reserved' not in header):
            failures.append(dict(missing_bluetooth_source_notice=name))
    catalog = json.loads((ROOT / 'tests/suites.json').read_text(encoding='utf-8'))
    names = set()
    for suite in catalog['suites']:
        if suite['name'] in names or not re.fullmatch('[a-z0-9-]+', suite['name']):
            failures.append(dict(invalid_suite_name=suite['name']))
        names.add(suite['name'])
        if suite['name'] == 'tracing-live' and suite['optional']:
            failures.append(dict(default_suite_disabled=suite['name']))
        if suite['name'].startswith('bt-') and 'tests/' + suite['file'] in files:
            header = (ROOT / 'tests' / suite['file']).read_text(encoding='utf-8-sig')[:450]
            if 'Additional permission: BLUETOOTH-LINKING-EXCEPTION.txt' not in header:
                failures.append(dict(missing_bluetooth_permission=suite['file']))
        if 'tests/' + suite['file'] not in files:
            failures.append(dict(unlisted_suite=suite['file']))
        if any(Path(flag).is_absolute() for flag in suite['flags']):
            failures.append(dict(nonportable_suite=suite['name']))
    result = dict(passed=not failures, project_files=len(files), suites=len(names),
                  vendor_binary_assets=0 if not failures else None, failures=failures,
                  license_scope='Project test material GPL-3.0-only; Bluetooth combinations carry the additional permission and retained MS-PL notices.')
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
