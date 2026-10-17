# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

from pathlib import Path
import json
import os
import subprocess


def version_key(path):
    return tuple(int(part) if part.isdigit() else 0 for part in path.name.split('.'))


def environment_path(*names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return Path(value).resolve()
    return None


def newest(paths, description):
    paths = [path for path in paths if path.is_dir()]
    if not paths:
        raise RuntimeError('Missing ' + description + '. See tests/README.md for toolchain settings.')
    return max(paths, key=version_key)


def vc_directory():
    explicit = environment_path('AP6256_TEST_VC', 'VCToolsInstallDir')
    if explicit:
        return explicit
    ewdk = environment_path('AP6256_TEST_EWDK')
    if ewdk:
        return newest(ewdk.glob('Program Files/Microsoft Visual Studio/*/BuildTools/VC/Tools/MSVC/*'), 'MSVC in the EWDK')
    program = Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)'))
    vswhere = program / 'Microsoft Visual Studio/Installer/vswhere.exe'
    if not vswhere.is_file():
        raise RuntimeError('Set AP6256_TEST_EWDK or run in a Visual Studio developer shell.')
    result = subprocess.run([str(vswhere), '-latest', '-products', '*', '-requires',
                             'Microsoft.VisualStudio.Component.VC.Tools.x86.x64',
                             '-property', 'installationPath'], check=True, capture_output=True, text=True)
    installation = result.stdout.strip()
    if not installation:
        raise RuntimeError('Visual Studio C++ x64 tools are not installed.')
    return newest((Path(installation) / 'VC/Tools/MSVC').glob('*'), 'MSVC')


def kit_directory():
    explicit = environment_path('AP6256_TEST_SDK', 'WindowsSdkDir')
    if explicit:
        return explicit
    ewdk = environment_path('AP6256_TEST_EWDK')
    if ewdk:
        return ewdk / 'Program Files/Windows Kits/10'
    return Path(os.environ.get('ProgramFiles(x86)', 'C:/Program Files (x86)')) / 'Windows Kits/10'


def kit_version(sdk):
    explicit = os.environ.get('AP6256_TEST_SDK_VERSION') or os.environ.get('WindowsSDKVersion')
    if explicit:
        return explicit.strip('/\\')
    return newest((sdk / 'Include').glob('10.*'), 'Windows SDK headers').name


class KitPaths:
    def __init__(self, primary, supplements=()):
        self.primary = Path(primary)
        self.supplements = tuple(Path(path) for path in supplements)

    def __truediv__(self, name):
        primary = self.primary / name
        if primary.exists():
            return primary
        for parent in self.supplements:
            candidate = parent / name
            if candidate.exists():
                return candidate
        return primary

    def __str__(self):
        return str(self.primary)

    def __fspath__(self):
        return str(self.primary)

    def resolve(self):
        return self.primary.resolve()


def extra_paths(name):
    return [Path(value).resolve() for value in os.environ.get(name, '').split(os.pathsep) if value]


VC = vc_directory()
sdk_root = kit_directory()
VERSION = kit_version(sdk_root)
SDK = KitPaths(sdk_root, extra_paths('AP6256_TEST_EXTRA_KIT'))
INC = KitPaths(sdk_root / 'Include' / VERSION, extra_paths('AP6256_TEST_EXTRA_INCLUDE'))
LIB = KitPaths(sdk_root / 'Lib' / VERSION, extra_paths('AP6256_TEST_EXTRA_LIB'))
COMPILER_INCLUDES = [root / part for root in (INC.primary,) + INC.supplements
                     for part in ('ucrt', 'shared', 'um', 'km') if (root / part).is_dir()]
os.environ['INCLUDE'] = os.pathsep.join(str(path) for path in COMPILER_INCLUDES)


def describe():
    required = [VC / 'bin/HostX64/x64/cl.exe', VC / 'include/vector', VC / 'lib/x64/libcmt.lib',
                INC / 'um/windows.h', INC / 'shared/ntstatus.h', INC / 'km/dot11wdi.h',
                INC / 'km/wificx/1.2/wificx.h', LIB / 'ucrt/x64/libucrt.lib',
                LIB / 'um/x64/kernel32.lib', LIB / 'um/x64/wlan/2.0/WificxTLVGenParse.lib']
    missing = [str(path) for path in required if not path.is_file()]
    if missing:
        raise RuntimeError('Missing test prerequisites:\n' + '\n'.join(missing))
    return dict(compiler=str(required[0]), vc=str(VC), sdk=str(SDK), sdk_version=VERSION,
                include_roots=[str(INC.primary)] + [str(path) for path in INC.supplements],
                library_roots=[str(LIB.primary)] + [str(path) for path in LIB.supplements],
                compiler_include_fallback=[str(path) for path in COMPILER_INCLUDES])


if __name__ == '__main__':
    print(json.dumps(describe(), indent=2))
