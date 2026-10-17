# SPDX-License-Identifier: GPL-3.0-only
# Licensed under the GNU General Public License, version 3 only.
# Provided without warranty. See LICENSE for the license text.

'Locate moved production sources for the existing function extraction suites.'
from toolchain import VC, SDK, INC, LIB
from test_support import output_dir
from functools import lru_cache
from pathlib import Path
import json
import re

def _mask(text):
    return re.sub('//[^\\n]*|/\\*[\\s\\S]*?\\*/|"(?:\\\\.|[^"\\\\])*"|\\x27(?:\\\\.|[^\\x27\\\\])*\\x27', lambda m: ''.join(('\n' if c == '\n' else ' ' for c in m[0])), text)

def _functions(text):
    text = re.sub('\\b(?:_IRQL_requires_max_|_Success_)\\([^\\n]*?\\)\\s*', '\n', text)
    text = re.sub('\\b_Use_decl_annotations_\\s*', '\n', text)
    clean = _mask(text)
    result = {}
    pattern = '^(?:(?:static|const|[A-Z][A-Za-z0-9_]*)\\s*\\**\\s+)+(Ap6256\\w+)\\s*\\([^;]*?\\)\\s*\\{'
    for match in re.finditer(pattern, clean, re.M):
        depth = 1
        end = match.end()
        while depth and end < len(clean):
            depth += (clean[end] == '{') - (clean[end] == '}')
            end += 1
        if depth:
            raise ValueError('Unbalanced production function: ' + match[1])
        result[match[1]] = text[match.start():end]
    return result

def _arguments(text):
    clean = _mask(text)
    (result, start, depth) = ([], 0, 0)
    for (index, char) in enumerate(clean):
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif char == ',' and (not depth):
            result.append(text[start:index].strip())
            start = index + 1
    result.append(text[start:].strip())
    return result

def _inline(text, hooks, stack=()):
    clean = _mask(text)
    edits = []
    for match in re.finditer('\\b(Ap6256(?:Model\\w+|On\\w+))\\s*\\(', clean):
        name = match[1]
        if name not in hooks:
            raise ValueError('Missing production hook: ' + name)
        if name in stack:
            raise ValueError('Recursive source extraction hook: ' + name)
        (depth, end) = (1, match.end())
        while depth:
            depth += (clean[end] == '(') - (clean[end] == ')')
            end += 1
        definition = hooks[name]
        opening = definition.index('{')
        (signature, body) = (definition[:opening], definition[opening + 1:-1])
        signature = re.sub('^_\\w+_\\([^\\n]*\\)\\s*', '', signature)
        result_type = re.search('\\b([A-Z][A-Za-z0-9_]*)\\s+' + name, signature)[1]
        formals = signature[signature.index('(') + 1:signature.rindex(')')]
        names = [re.search('(\\w+)\\s*(?:\\[[^]]*\\])?$', arg)[1] for arg in _arguments(formals) if arg != 'VOID']
        actual = text[match.end():end - 1]
        body = _inline(body, hooks, stack + (name,))
        replacement = '([&](' + ', '.join(('auto ' + n for n in names)) + ') -> ' + result_type
        replacement += ' {' + body + '    }(' + actual + '))'
        edits.append((match.start(), end, replacement))
    for (start, end, replacement) in reversed(edits):
        text = text[:start] + replacement + text[end:]
    return text

@lru_cache(maxsize=None)
def _model_hooks(root, model):
    text = _model_network(root, model)
    hooks = root / 'src' / model / 'model.c'
    if model == 'wificx':
        hooks = root / 'src/wificx/model.c'
    text += hooks.read_text(encoding='utf-8-sig')
    text += (root / 'src/common/netadapter.c').read_text(encoding='utf-8-sig')
    text += (root / 'src/common/ftm_station.c').read_text(encoding='utf-8-sig')
    text += _auth_network(root)
    text += (root / 'src/common/auth_firmware_model.c').read_text(encoding='utf-8-sig')
    return {name: body for (name, body) in _functions(text).items() if name.startswith(('Ap6256Model', 'Ap6256On'))}

def _auth_network(root):
    text = (root / 'src/common/station_auth.c').read_text(encoding='utf-8-sig')
    for name in ('sae_station.inc', 'ft_station.inc'):
        text = text.replace('#include "' + name + '"', (root / 'src/common' / name).read_text(encoding='utf-8-sig'))
    return text

def _model_network(root, model):
    text = (root / 'src' / model / 'netadapter.c').read_text(encoding='utf-8-sig')
    for name in ('sae_station.inc', 'ft_station.inc', 'role_adapter.inc', 'group_engine.inc'):
        directive = '#include "' + name + '"'
        if directive in text:
            text = text.replace(directive, (root / 'src' / model / name).read_text(encoding='utf-8-sig'))
    return text

def _fixture(text, root, model):
    text = _inline(text, _model_hooks(root, model))
    return text.replace('->Model.', '->').replace('->Auth.', '->')

@lru_cache(maxsize=None)
def _network(root):
    common = (root / 'src/common/netadapter.c').read_text(encoding='utf-8-sig')
    shared = _functions(common + _auth_network(root))
    model_text = {model: _model_network(root, model) for model in ('wdi', 'wificx')}
    per_model = {model: {**shared, **_functions(text)} for (model, text) in model_text.items()}
    prefix = (root / 'src/common/netadapter_internal.h').read_text(encoding='utf-8-sig')
    prefix += (root / 'src/common/capability_tables.h').read_text(encoding='utf-8-sig')
    prefix += (root / 'src/common/station_auth_state.h').read_text(encoding='utf-8-sig')
    lines = iter(common.splitlines())
    for line in lines:
        if line.startswith('#define '):
            prefix += line + '\n'
            while line.endswith('\\'):
                line = next(lines)
                prefix += line + '\n'
    for model in ('wdi', 'wificx'):
        guard = '#ifdef AP6256_ENABLE_WDI' if model == 'wdi' else '#ifndef AP6256_ENABLE_WDI'
        prefix += guard + '\n' + (root / 'src' / model / 'netmodel_state.h').read_text(encoding='utf-8-sig') + '\n#endif\n'
    for text in (common, model_text['wdi']):
        prefix += '\n'.join(re.findall('^(?:static )?const [^=]+\\bAp6256\\w+\\[\\][^=]*=\\s*\\{.*?\\};', text, re.M | re.S)) + '\n'
    rendered = []
    for name in dict.fromkeys([*per_model['wdi'], *per_model['wificx']]):
        if name.startswith(('Ap6256Model', 'Ap6256On')):
            continue
        bodies = {model: _fixture(functions[name], root, model) for (model, functions) in per_model.items() if name in functions}
        if not name.startswith('Ap6256Net'):
            bodies = {model: body if body.startswith('static ') else 'static ' + body for (model, body) in bodies.items()}
        if len(bodies) == 2:
            (wdi, wifi) = (bodies['wdi'], bodies['wificx'])
            (wdi_sig, wifi_sig) = (wdi[:wdi.index('{')], wifi[:wifi.index('{')])
            if re.sub('\\s+', ' ', wdi_sig).strip() == re.sub('\\s+', ' ', wifi_sig).strip():
                if wdi == wifi:
                    rendered.append(wdi)
                else:
                    rendered.append(wdi_sig + '{\n#ifdef AP6256_ENABLE_WDI\n' + wdi[wdi.index('{') + 1:-1] + '\n#else\n' + wifi[wifi.index('{') + 1:-1] + '\n#endif\n}')
            else:
                rendered.append('#ifdef AP6256_ENABLE_WDI\n' + wdi + '\n#else\n' + wifi + '\n#endif')
        elif 'wdi' in bodies:
            rendered.append('#ifdef AP6256_ENABLE_WDI\n' + bodies['wdi'] + '\n#endif')
        else:
            rendered.append('#ifndef AP6256_ENABLE_WDI\n' + bodies['wificx'] + '\n#endif')
    return prefix + '\n' + '\n\n'.join(rendered) + '\n'

def source_path(path):
    """Resolve a current flat source reference while retaining saved trees."""
    path = Path(path)
    for parent in path.parents:
        manifest = parent.parent / 'tests/source-layout.json'
        if parent.name == 'src' and manifest.is_file():
            mapping = json.loads(manifest.read_text(encoding='utf-8'))
            if path.parent == parent and path.name in mapping:
                return (parent / mapping[path.name] / path.name, parent.parent)
            return (path, parent.parent)
        if parent.name == 'src' and (not path.is_file()) and (parent / path.name).is_file():
            return (parent / path.name, None)
    return (path, None)

def read_source_text(path, *args, **kwargs):
    (actual, root) = source_path(path)
    if root is None:
        return actual.read_text(*args, **kwargs)
    if actual.name == 'netadapter.c':
        return _network(root)
    text = actual.read_text(*args, **kwargs)
    if actual.name == 'wdi_tal.c':
        text = text.replace('#include "../common/native_frame.inc"', (root / 'src/common/native_frame.inc').read_text(encoding='utf-8-sig'))
    if actual.name in ('ap6256.h', 'sae_firmware.c'):
        for header in ('device_framework.h', 'device_fields.h', 'device_context.h', 'device_callbacks.h', 'firmware_image.h'):
            if '#include <' + header + '>' in text:
                wdi = (root / 'src/wdi' / header).read_text(encoding='utf-8-sig')
                wifi = (root / 'src/wificx' / header).read_text(encoding='utf-8-sig')
                text = text.replace('#include <' + header + '>', '#ifdef AP6256_ENABLE_WDI\n' + wdi + '\n#else\n' + wifi + '\n#endif')
    if actual.name in ('device.c', 'datapath.c', 'wlfc.c'):
        text = _fixture(text, root, 'wdi')
    return text.replace('->Model.', '->').replace('->Auth.', '->')

def read_source_bytes(path):
    """Read actual moved file bytes for source fingerprints and binary fixtures."""
    (actual, _) = source_path(path)
    return actual.read_bytes()
