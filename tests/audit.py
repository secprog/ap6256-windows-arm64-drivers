# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import ast
import hashlib
import json
import re

ROOT = Path(__file__).resolve().parents[1]


def main():
    metadata = json.loads((ROOT / 'tests/provenance.json').read_text(encoding='utf-8'))
    expected = set(metadata['project_files'])
    actual = {path.relative_to(ROOT).as_posix() for path in (ROOT / 'tests').rglob('*') if path.is_file()}
    expected_tests = {name for name in expected if name.startswith('tests/')}
    failures = []
    if actual != expected_tests:
        failures.append(dict(inventory_missing=sorted(expected_tests - actual), inventory_unlisted=sorted(actual - expected_tests)))
    forbidden = re.compile(r'(?i)(?:[A-Z]:[/\\]+Users[/\\]|woa-port|docs[/\\]reference|before-stage|\b[Vv]2[0-9]{2}\b)')
    allowed_extensions = {'.py', '.c', '.json', '.md', '.txt', '.config', '.ps1', '.yml'}
    for name in sorted(expected):
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
        if (path.suffix.lower() in ('.py', '.c', '.ps1', '.yml', '.config')
                and 'SPDX-License-Identifier: ' + metadata['project_files'][name]['license'] not in text[:450]):
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
    for name, digest in metadata['retained_notices_sha256'].items():
        if hashlib.sha256((ROOT / name).read_bytes()).hexdigest() != digest:
            failures.append(dict(changed_license_notice=name))
    bluetooth = metadata['bluetooth_tests']
    for name in bluetooth['extracted_sources']:
        header = (ROOT / name).read_text(encoding='utf-8-sig')[:450]
        if ('SPDX-License-Identifier: ' + bluetooth['extracted_source_license'] not in header
                or 'Copyright (c) Microsoft Corporation All Rights Reserved' not in header):
            failures.append(dict(missing_bluetooth_source_notice=name))
    for name in bluetooth['generated_source_notices']:
        if name not in metadata['retained_notices_sha256']:
            failures.append(dict(unverified_bluetooth_notice=name))
    catalog = json.loads((ROOT / 'tests/suites.json').read_text(encoding='utf-8'))
    names = set()
    for suite in catalog['suites']:
        if suite['name'] in names or not re.fullmatch('[a-z0-9-]+', suite['name']):
            failures.append(dict(invalid_suite_name=suite['name']))
        names.add(suite['name'])
        if suite['name'] == 'tracing-live' and suite['optional']:
            failures.append(dict(default_suite_disabled=suite['name']))
        if suite['name'].startswith('bt-'):
            entry = metadata['project_files'].get('tests/' + suite['file'], {})
            if entry.get('additional_permission') != bluetooth['additional_permission']:
                failures.append(dict(missing_bluetooth_permission=suite['file']))
        if 'tests/' + suite['file'] not in expected:
            failures.append(dict(unlisted_suite=suite['file']))
        if any(Path(flag).is_absolute() for flag in suite['flags']):
            failures.append(dict(nonportable_suite=suite['name']))
    result = dict(passed=not failures, project_files=len(expected), suites=len(names),
                  vendor_binary_assets=0 if not failures else None, failures=failures,
                  license_scope='Project test material GPL-3.0-only; Bluetooth combinations carry the additional permission and retained MS-PL notices.')
    print(json.dumps(result, indent=2))
    raise SystemExit(bool(failures))


if __name__ == '__main__':
    main()
