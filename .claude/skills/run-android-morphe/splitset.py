"""Pure bounded aapt2 XML-tree parsing and selected base/config topology checks.

No file/tool/device access. Callers translate SplitSetError into their own error.
Raw attributes retain presence and type; effective manifests never erase absence.
"""
from __future__ import annotations

import json
import re

ANDROID = 'http://schemas.android.com/apk/res/android'
MAX_TREE_BYTES = 8 * 1024**2
MAX_NODES = 20000
MAX_DEPTH = 64
IDS = {'versionCode': '0101021b', 'versionName': '0101021c',
       'versionCodeMajor': '01010576', 'minSdkVersion': '0101020c',
       'hasCode': '0101000c', 'extractNativeLibs': '010104ea',
       'isFeatureSplit': '0101055b',
       'isSplitRequired': '01010591', 'splitTypes': '0101064f',
       'requiredSplitTypes': '0101064e', 'name': '01010003',
       'value': '01010024', 'resource': '01010025'}
ID_NAMES = {value: name for name, value in IDS.items()}
SUPPORTED_TYPES = {'base__abi', 'base__density'}
A = '{' + ANDROID + '}'


class SplitSetError(ValueError):
    pass


def _fail(message):
    raise SplitSetError(message)


def _value(text):
    # Modern aapt2 prints decoded primitives; older builds print typed hex.
    raw = None
    if ' (Raw: ' in text:
        text, raw_text = text.rsplit(' (Raw: ', 1)
        if not raw_text.endswith(')'):
            _fail('malformed raw XML-tree value')
        try:
            raw = json.loads(raw_text[:-1])
        except (ValueError, TypeError):
            _fail('malformed raw XML-tree string')
        if not isinstance(raw, str):
            _fail('raw XML-tree value must be a string')
    if text.startswith('"'):
        try:
            value = json.loads(text)
        except ValueError:
            _fail('malformed XML-tree string')
        kind = 'string'
        if not isinstance(value, str) or (raw is not None and raw != value):
            _fail('conflicting XML-tree raw string')
    elif text in ('true', 'false'):
        kind, value = 'boolean', text == 'true'
    elif re.fullmatch(r'[0-9]+', text):
        kind, value = 'integer', int(text)
    elif re.fullmatch(r'-[1-9][0-9]{0,9}', text):
        # SDK36 decodes signed TYPE_INT_DEC values (e.g. priority=-500).
        # Preserve the integer, not an unresolved string or truthy boolean.
        kind, value = 'integer', int(text)
        if value < -2147483648:
            _fail('signed XML-tree integer outside int32 range')
    elif re.fullmatch(r'0x[0-9a-fA-F]+', text):
        kind, value = 'integer', int(text, 16)
    elif re.fullmatch(r'\(type 0x[0-9a-fA-F]{2}\)0x[0-9a-fA-F]+', text):
        tag, number = re.fullmatch(r'\(type 0x([0-9a-fA-F]{2})\)0x([0-9a-fA-F]+)', text).groups()
        number, tag = int(number, 16), int(tag, 16)
        if tag in (0x10, 0x11):
            kind, value = 'integer', number
        elif tag == 0x12 and number in (0, 1, 0xffffffff):
            kind, value = 'boolean', bool(number)
        else:
            kind, value = 'unresolved', text
    elif re.fullmatch(r'[@?].+', text):
        kind, value = 'unresolved', text
    else:
        _fail('unsupported XML-tree attribute encoding')
    # Raw textual spellings do not override typed primitives.
    return {'type': kind, 'value': value, 'raw': raw}


def parse_xmltree(output: str) -> dict:
    """Parse trusted aapt2 dump xmltree stdout; reject ambiguous/unsupported grammar.

    Returns {source, root}; root/children are {tag, attributes, children}.
    Attribute keys are local or {URI}local, values {type, value, raw, resource_id}.
    Presence is dictionary membership (explicit empty string remains present).
    """
    if (not isinstance(output, str) or len(output.encode('utf-8')) > MAX_TREE_BYTES
            or '\x00' in output or '�' in output):
        _fail('invalid or oversized XML-tree output')
    namespaces, stack, root = {}, [], None
    nodes = attributes = 0
    for line in output.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r'( *)(N|E|A): (.+)', line)
        if not match:
            _fail('unsupported XML-tree row')
        spaces, kind, body = match.groups()
        indent = len(spaces)
        if indent % 2 or indent > MAX_DEPTH * 4 + 4:
            _fail('invalid XML-tree indentation')
        if kind == 'N':
            ns = re.fullmatch(r'([A-Za-z_][\w.-]*)=(\S+) \(line=[0-9]+\)', body)
            if root is not None or indent != 0 or not ns or ns[1] in namespaces:
                _fail('unsupported or duplicate XML-tree namespace')
            namespaces[ns[1]] = ns[2]
            continue
        if kind == 'E':
            element = re.fullmatch(r'([A-Za-z_][\w.-]*) \(line=[0-9]+\)', body)
            if not element:
                _fail('invalid XML-tree element')
            while stack and stack[-1][0] >= indent:
                stack.pop()
            node = {'tag': element[1], 'attributes': {}, 'children': []}
            if not stack:
                if root is not None or indent != (2 if namespaces else 0) or element[1] != 'manifest':
                    _fail('XML-tree must have exactly one manifest root')
                root = node
            else:
                if indent != stack[-1][0] + 4:
                    _fail('invalid XML-tree element hierarchy')
                stack[-1][1]['children'].append(node)
            stack.append((indent, node))
            nodes += 1
            if nodes > MAX_NODES or len(stack) > MAX_DEPTH:
                _fail('XML-tree node/depth bound exceeded')
        else:
            if not stack or indent != stack[-1][0] + 2 or stack[-1][1]['children']:
                _fail('XML-tree attribute outside element header')
            attr = re.fullmatch(r'(.+?)(?:\(0x([0-9a-fA-F]{8})\))?=(.*)', body)
            if not attr:
                _fail('malformed XML-tree attribute')
            name, resource_id, value = attr.groups()
            if ':' in name:
                ns, name = name.rsplit(':', 1)
                uri = namespaces.get(ns, ns if '://' in ns else None)
                if uri is None or uri not in namespaces.values():
                    _fail('undeclared XML-tree attribute namespace')
                key = '{' + uri + '}' + name
            else:
                uri, key = None, name
            if not re.fullmatch(r'[A-Za-z_][\w.-]*', name):
                _fail('invalid XML-tree attribute name')
            # Android reads framework attributes by resource ID, not just by
            # spelling. Reject both a missing/wrong ID and a known ID hidden
            # behind a different name/namespace (which would falsify absence).
            if name in IDS and (uri != ANDROID or resource_id is None
                                or resource_id.lower() != IDS[name]):
                _fail('incorrect namespace/resource ID for Android attribute')
            if (resource_id and resource_id.lower() in ID_NAMES
                    and (uri != ANDROID or name != ID_NAMES[resource_id.lower()])):
                _fail('framework resource ID aliases another attribute')
            if name in ('package', 'split', 'configForSplit') and uri is not None:
                _fail('incorrect namespace for manifest identity')
            attrs = stack[-1][1]['attributes']
            resource_id = resource_id.lower() if resource_id else None
            if (key in attrs or (resource_id and any(
                    item['resource_id'] == resource_id for item in attrs.values()))):
                _fail('duplicate XML-tree attribute or resource ID')
            if len(attrs) >= 256:
                _fail('XML-tree per-element attribute bound exceeded')
            attrs[key] = {**_value(value), 'resource_id': resource_id}
            attributes += 1
            if attributes > MAX_NODES * 32:
                _fail('XML-tree attribute bound exceeded')
    if root is None:
        _fail('missing XML-tree manifest')
    return {'source': 'aapt2_xmltree', 'root': root}


def manifest_fields(raw: dict) -> dict:
    """Return typed manifest declarations, retaining None for absent attributes."""
    root = raw['root']

    def get(node, name, kind, android=True):
        item = node['attributes'].get(('{' + ANDROID + '}' if android else '') + name)
        if item is None:
            return None
        if item['type'] != kind:
            _fail('unresolved or incorrect manifest attribute type: ' + name)
        return item['value']

    def string(node, name, android=True):
        return get(node, name, 'string', android)

    def integer(node, name):
        value = get(node, name, 'integer')
        if value is not None and not 1 <= value <= 2147483647:
            _fail('unsupported manifest integer: ' + name)
        return value

    def types(name):
        value = string(root, name)
        if value is None or value == '':
            return []
        values = value.split(',')
        if len(set(values)) != len(values) or any(v not in SUPPORTED_TYPES for v in values):
            _fail('unsupported or duplicate split type declaration')
        return values

    if '{' + ANDROID + '}versionCodeMajor' in root['attributes']:
        _fail('versionCodeMajor semantics are unsupported')
    applications = [n for n in root['children'] if n['tag'] == 'application']
    sdks = [n for n in root['children'] if n['tag'] == 'uses-sdk']
    if len(applications) != 1 or len(sdks) > 1:
        _fail('exactly one application and at most one uses-sdk required')
    app = applications[0]
    # Security-relevant declarations are accepted only in their defined location.
    locations = {A + name: root for name in (
        'versionCode', 'versionName', 'isFeatureSplit', 'isSplitRequired',
        'splitTypes', 'requiredSplitTypes', 'versionCodeMajor')}
    locations.update({name: root for name in ('package', 'split', 'configForSplit')})
    locations.update({A + name: app for name in ('hasCode', 'extractNativeLibs')})
    locations[A + 'minSdkVersion'] = sdks[0] if sdks else None

    def walk(node, parent=None):
        for key in node['attributes']:
            if key in locations and node is not locations[key]:
                _fail('misplaced manifest declaration: ' + key)
            if key.rsplit('}', 1)[-1] in ('isolatedSplits', 'featureSplit', 'usesSplitName', 'splitName'):
                _fail('unsupported split declaration: ' + key)
        if node['tag'] == 'manifest' and node is not root:
            _fail('nested manifest is unsupported')
        if node['tag'] in ('application', 'uses-sdk', 'uses-split') and parent is not root:
            _fail('misplaced manifest element')
        for child in node['children']:
            walk(child, node)
    walk(root)

    if 'split' in root['attributes']:
        # A deliberately narrow companion grammar: do not silently ignore a
        # feature component/dependency nested under an otherwise allowed tag.
        root_keys = {'package', 'split', 'configForSplit',
                     'platformBuildVersionCode', 'platformBuildVersionName'} | {
            A + name for name in ('versionCode', 'versionName', 'isFeatureSplit',
                'isSplitRequired', 'splitTypes', 'requiredSplitTypes',
                'compileSdkVersion', 'compileSdkVersionCodename', 'revisionCode')}
        if set(root['attributes']) - root_keys:
            _fail('unsupported companion manifest attributes')
        if set(app['attributes']) - {A + 'hasCode', A + 'extractNativeLibs'}:
            _fail('unsupported companion application attributes')
        for node in root['children']:
            if node['tag'] not in ('application', 'uses-sdk'):
                _fail('unsupported companion manifest element')
            if node['tag'] == 'uses-sdk' and (node['children'] or set(node['attributes']) - {
                    A + 'minSdkVersion', A + 'targetSdkVersion'}):
                _fail('unsupported companion SDK declaration')
        for node in app['children']:
            if (node['tag'] != 'meta-data' or node['children']
                    or set(node['attributes']) - {A + 'name', A + 'value', A + 'resource'}
                    or not string(node, 'name')
                    or sum(A + key in node['attributes'] for key in ('value', 'resource')) != 1):
                _fail('unsupported companion metadata or component')
    dependencies = []
    for child in root['children']:
        if child['tag'] == 'uses-split':
            name = string(child, 'name')
            if not name:
                _fail('uses-split requires a literal name')
            dependencies.append(name)
    split_required = get(root, 'isSplitRequired', 'boolean')
    metadata_required = None
    for node in app['children']:
        if node['tag'] == 'meta-data':
            name = string(node, 'name')
            if name == 'com.android.vending.splits.required':
                if metadata_required is not None or '{' + ANDROID + '}resource' in node['attributes']:
                    _fail('duplicate or unresolved required-splits metadata')
                metadata_required = get(node, 'value', 'boolean')
                if metadata_required is None:
                    _fail('required-splits metadata requires a boolean value')
    return {'package': string(root, 'package', False),
            'version_code': (str(get(root, 'versionCode', 'integer'))
                             if '{' + ANDROID + '}versionCode' in root['attributes'] else None),
            'version_name': string(root, 'versionName'), 'split': string(root, 'split', False),
            'config_for_split': string(root, 'configForSplit', False),
            'is_feature_split': get(root, 'isFeatureSplit', 'boolean'),
            'uses_splits': dependencies, 'has_code': get(app, 'hasCode', 'boolean'),
            'min_sdk': integer(sdks[0], 'minSdkVersion') if sdks else None,
            'extract_native_libs': get(app, 'extractNativeLibs', 'boolean'),
            'is_split_required': split_required, 'metadata_splits_required': metadata_required,
            'split_types': types('splitTypes'), 'required_split_types': types('requiredSplitTypes'),
            'application_children': [n['tag'] for n in app['children']],
            'manifest_children': [n['tag'] for n in root['children']],
            'application_attributes': list(app['attributes'])}


def canonical_dex(names: list[str]) -> list[str]:
    indices = []
    for name in names:
        match = re.fullmatch(r'classes(?:([2-9]|[1-9][0-9]+))?\.dex', name)
        if not match:
            _fail('noncanonical or nested DEX payload')
        indices.append(int(match[1]) if match[1] else 1)
    if not indices or sorted(indices) != list(range(1, len(indices) + 1)):
        _fail('base requires a complete canonical contiguous DEX set')
    return sorted(names, key=lambda n: 1 if n == 'classes.dex' else int(n[7:-4]))


def validate_topology(records: list[dict], *, abi: str, density: str) -> dict:
    """Validate verifier member records; return selected topology, not completeness.

    Each record needs path, sha256, manifest_declarations, dex_payloads,
    native_abis, native_libraries. Identity/signature pins belong to the caller.
    Does not mutate records. A singleton retains standalone native support.
    """
    if not records or len(records) > 256:
        _fail('selected-set member bound exceeded')
    bases = [r for r in records if r['manifest_declarations']['split'] is None]
    splits = [r['manifest_declarations']['split'] for r in records]
    if len(bases) != 1 or len(set(splits)) != len(splits):
        _fail('selected set requires one base and unique split identities')
    base = bases[0]
    b = base['manifest_declarations']
    mode = 'standalone' if len(records) == 1 else 'base_config_set'
    provided, required = set(), set()
    members = []
    if b['has_code'] is False:
        _fail('base must be code-bearing')
    dex = canonical_dex(base['dex_payloads'])
    if mode == 'base_config_set' and base['native_abis']:
        _fail('base_config_set requires a non-native code base')
    for record in records:
        m = record['manifest_declarations']
        is_base = record is base
        if m['is_feature_split'] is True or m['uses_splits']:
            _fail('feature splits and uses-split dependencies are unsupported')
        if m['config_for_split'] not in (None, ''):
            _fail('configuration splits must target base')
        if is_base and m['config_for_split'] is not None:
            _fail('base cannot declare configForSplit')
        if not is_base:
            if m['has_code'] is not False or record['dex_payloads']:
                _fail('configuration companions require explicit hasCode=false and no DEX')
            if (any(t != 'meta-data' for t in m['application_children'])
                    or any(t not in ('application', 'uses-sdk') for t in m['manifest_children'])):
                _fail('unsupported companion components or declarations')
            if any(k not in ('{' + ANDROID + '}hasCode', '{' + ANDROID + '}extractNativeLibs')
                   for k in m['application_attributes']):
                _fail('unsupported companion application attributes')
            if m['extract_native_libs'] is not None and m['extract_native_libs'] != (b['extract_native_libs'] is not False):
                _fail('companion native extraction policy conflicts with base')
            if 'base__abi' in m['split_types'] and not record['native_abis']:
                _fail('base__abi provider must contain selected native payload')
            if m['is_split_required'] or m['metadata_splits_required'] or m['required_split_types']:
                _fail('companion required-split declarations are unsupported')
        elif m['split_types']:
            _fail('base cannot provide configuration split types')
        provided.update(m['split_types'])
        required.update(m['required_split_types'])
        members.append({'path': record['path'], 'sha256': record['sha256'],
                        'split': m['split'], 'role': 'base' if is_base else 'base_config',
                        'target': None if is_base else 'base', 'split_types': m['split_types']})
    if not required <= provided:
        _fail('selected set is missing required split types')
    if (b['is_split_required'] or b['metadata_splits_required']) and len(records) == 1:
        _fail('base requires selected configuration splits')
    native = {a for r in records for a in r['native_abis']}
    if ((abi == 'none' and native) or (native and abi not in native)
            or (mode == 'base_config_set' and native and native != {abi})):
        _fail('selected native ABI differs from explicit ABI selection')
    if 'base__abi' in provided and (not native or abi == 'none'):
        _fail('base__abi coverage requires selected native payload')
    if 'base__density' in provided and density == 'nodpi':
        _fail('base__density requires explicit density selection')
    return {'mode': mode, 'base': base['path'], 'base_sha256': base['sha256'],
            'members': members, 'base_dex': dex, 'required_split_types': sorted(required),
            'provided_split_types': sorted(provided),
            'min_sdk': max(r['manifest_declarations']['min_sdk'] or b['min_sdk'] or 1 for r in records),
            'extract_native_libs': b['extract_native_libs'] is not False,
            'coverage': 'declared_types_only_not_resource_or_language_completeness'}
