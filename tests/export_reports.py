# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import argparse
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    source, destination = args.input.resolve(), args.output.resolve()
    if destination == source or source in destination.parents or destination in source.parents:
        parser.error('Input and output directories must be separate.')
    if destination == ROOT or ROOT in destination.parents:
        parser.error('Reports must be outside the checkout.')
    if destination.exists() and any(destination.iterdir()):
        parser.error('The report directory must be empty.')
    if not (source / 'results.json').is_file():
        parser.error('Input has no results.json.')
    paths = []
    for path in sorted(source.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in ('.json', '.log'):
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(source):
            raise ValueError('Report path escapes input: ' + str(path))
        target = destination / path.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        paths.append(target)
    for name in ('LICENSE', 'LICENSE-ISC.txt', 'NOTICE.txt', 'BLUETOOTH-LINKING-EXCEPTION.txt', 'bt/LICENSE-MS-PL.txt'):
        target = destination / 'licenses' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        paths.append(target)
    manifest = {path.relative_to(destination).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}
    (destination / 'report-files.json').write_text(json.dumps(manifest, indent=2) + '\n', encoding='utf-8')
    print(f'Exported {len(paths)} reports/notices.')


if __name__ == '__main__':
    main()
