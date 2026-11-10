"""Bounded bytecode-only standalone or explicit base/config-set assembly; outputs stay external.

Only a caller-reviewed execution report may be supplied. A JSON file, its digest,
and the reviewed_apply acknowledgement are NOT authenticated approval or a sandbox.
Split mode patches only a non-native base and preserves DEX-free companions.
No resource/native edits, v1 signing, key creation or installation.
The explicit keystore is passed to apksigner without reading it in Python; password
arguments are environment variable NAMES only. Tool output is never logged here.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
from pathlib import Path
import re
import struct
import sys
import zipfile

_HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location('_android_assembly_driver', _HERE / 'driver.py')
driver = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = driver
_SPEC.loader.exec_module(driver)


class AssemblyError(Exception):
    """A sanitized assembly failure; partial external outputs are not verified."""


_DEX = re.compile(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex\Z')
_SHA = re.compile(r'[0-9a-fA-F]{64}\Z')
_ENV = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')


def _require(condition, message):
    if not condition:
        raise AssemblyError(message)


def _sha(value):
    _require(isinstance(value, str) and _SHA.fullmatch(value), 'explicit SHA-256 required')
    return value.lower()


def _file(value):
    path = Path(value)
    _require(path.is_absolute(), 'explicit absolute input/tool paths required')
    path = path.resolve(strict=True)
    _require(path.is_file(), 'regular input/tool file required')
    _require(path.stat().st_size <= driver.MAX_ARCHIVE_BYTES, 'input/tool file exceeds byte limit')
    return path


def _stale_signature(name):
    parts = name.upper().split('/')
    return (len(parts) == 2 and parts[0] == 'META-INF' and
            (parts[1] == 'MANIFEST.MF' or parts[1].startswith('SIG-') or
             re.fullmatch(r'.+\.(?:SF|RSA|DSA|EC)', parts[1]) is not None))


def _extras(data):
    """Drop old Android alignment padding; retain unrelated ZIP extra fields."""
    result = bytearray()
    seen = set()
    while data:
        # Older zipalign versions append raw zero padding, not a TLV field.
        if not any(data):
            break
        _require(len(data) >= 4, 'malformed ZIP extra field')
        kind, size = struct.unpack_from('<HH', data)
        _require(len(data) >= size + 4 and kind not in seen and kind != 1,
                 'unsupported ZIP extra field')
        seen.add(kind)
        if kind != 0xd935:
            result.extend(data[:size + 4])
        data = data[size + 4:]
    return bytes(result)


def _packaging(archive):
    """Reject prefixes, hidden gaps and nonstandard packaging; allow APK sig block.

    driver already bounds ZIP metadata, payloads, aliases, compression and paths.
    Here the supported local records must be contiguous, except for a well-framed
    APK Signing Block immediately preceding the central directory.
    """
    stream = archive._driver_stream
    central, _ = driver._zip_directory_bounds(stream, driver.Budget())
    cursor = 0
    for member in sorted(archive.infolist(), key=lambda entry: entry.header_offset):
        _require(member.header_offset == cursor, 'unsupported APK packaging gaps or prefix')
        _require(not member.flag_bits & ~(0x800 | 8), 'unsupported APK ZIP flags')
        _require(member.extract_version <= 20, 'ZIP64 APK packaging is unsupported')
        _extras(member.extra)
        stream.seek(cursor)
        header = stream.read(30)
        values = struct.unpack('<4s5H3L2H', header)
        local_crc, local_compressed, local_size = values[6:9]
        name_len, extra_len = values[-2:]
        stream.seek(cursor + 30 + name_len)
        _extras(stream.read(extra_len))
        cursor += 30 + name_len + extra_len + member.compress_size
        if member.flag_bits & 8:
            stream.seek(cursor)
            first = stream.read(4)
            has_marker = first == b'PK\x07\x08'
            descriptor = stream.read(12) if has_marker else first + stream.read(8)
            _require(len(descriptor) == 12 and struct.unpack('<3L', descriptor) ==
                     (member.CRC, member.compress_size, member.file_size),
                     'unsupported APK data descriptor')
            cursor += 16 if has_marker else 12
        else:
            _require((local_crc, local_compressed, local_size) ==
                     (member.CRC, member.compress_size, member.file_size),
                     'inconsistent APK local size or CRC')
    if cursor != central:
        _require(central - cursor >= 32, 'unsupported APK trailing data')
        stream.seek(central - 24)
        footer = stream.read(24)
        size = struct.unpack_from('<Q', footer)[0]
        _require(footer[8:] == b'APK Sig Block 42' and 24 <= size <= central - cursor - 8,
                 'unsupported APK signing block framing')
        block_start = central - size - 8
        padding = block_start - cursor
        _require(0 <= padding < 16384, 'unsupported APK signing alignment padding')
        stream.seek(cursor)
        _require(stream.read(padding) == bytes(padding), 'nonzero APK signing alignment padding')
        stream.seek(block_start)
        _require(struct.unpack('<Q', stream.read(8))[0] == size,
                 'inconsistent APK signing block sizes')


def _inventory(path, *, companion=False):
    budget = driver.Budget()
    archive = driver._validated_zip(path, budget)
    try:
        _packaging(archive)
        records = {}
        for member in archive.infolist():
            size, digest, _ = driver._read_member(archive, member, budget)
            name = member.filename
            if name.lower().endswith('.dex'):
                _require(_DEX.fullmatch(name), 'unsupported DEX archive name')
            records[name] = dict(sha256=digest, bytes=size,
                                 compression=member.compress_type, directory=member.is_dir())
        _require('AndroidManifest.xml' in records, 'manifest payload required')
        dex = [name for name in records if _DEX.fullmatch(name)]
        if companion:
            _require(not dex, 'configuration companion must contain no DEX')
        else:
            _dex_layout(dex)
        return records
    finally:
        driver._close_zip(archive)


def _dex_file(path):
    _require(112 <= path.stat().st_size <= driver.MAX_FILE_BYTES, 'invalid emitted DEX size')
    with path.open('rb') as source:
        header = source.read(112)
    _require(re.fullmatch(rb'dex\n0(?:35|37|38|39|40)\x00', header[:8]) is not None,
             'unsupported emitted DEX format')
    size, header_size, endian = struct.unpack_from('<III', header, 32)
    _require(size == path.stat().st_size and header_size == 112 and endian == 0x12345678,
             'invalid emitted DEX header')


def _json_unique(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'duplicate report JSON field')
        result[key] = value
    return result


def _report(path, expected_sha, original, protected):
    _require(not path.samefile(protected), 'signing material cannot alias apply evidence')
    _require(path.stat().st_size <= driver.MAX_METADATA_BYTES, 'apply report exceeds size limit')
    _require(driver._hash_file(path) == _sha(expected_sha), 'apply report SHA-256 mismatch')
    report = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=_json_unique)
    _require(isinstance(report, dict) and report.get('status') == 'applied_structurally_verified',
             'successful apply execution evidence required')
    assertions = report.get('structural_assertions')
    _require(isinstance(assertions, dict) and assertions.get('status') == 'passed',
             'passed structural assertions required')
    files = {path: _sha(expected_sha)}
    for field in ('input', 'bundle'):
        record = report.get(field)
        _require(isinstance(record, dict) and isinstance(record.get('path'), str),
                 'apply input/bundle evidence required')
        target = _file(record['path'])
        _require(not target.samefile(protected), 'signing material cannot alias apply evidence')
        digest = _sha(record.get('sha256'))
        _require(driver._hash_file(target) == digest, 'apply input/bundle SHA-256 mismatch')
        if field == 'input':
            _require(target == original, 'apply input is not the selected original APK')
        _require(target not in files and not any(target.samefile(existing) for existing in files),
                 'aliased apply input/bundle evidence')
        files[target] = digest
    records = report.get('dex')
    _require(isinstance(records, list) and 0 < len(records) <= driver.MAX_ENTRIES,
             'explicit emitted DEX evidence required')
    dex = {}
    for record in records:
        _require(isinstance(record, dict) and isinstance(record.get('name'), str) and
                 _DEX.fullmatch(record['name']) and isinstance(record.get('path'), str),
                 'unsupported emitted DEX evidence')
        name = record['name']
        _require(name not in dex, 'duplicate emitted DEX name')
        target = _file(record['path'])
        _require(not target.samefile(protected), 'signing material cannot alias apply evidence')
        _require(target.name == name and target not in files and
                 not any(target.samefile(existing) for existing in files),
                 'aliased or renamed emitted DEX file')
        digest = _sha(record.get('sha256'))
        _dex_file(target)
        _require(driver._hash_file(target) == digest, 'emitted DEX SHA-256 mismatch')
        files[target] = digest
        dex[name] = target
    # The emission directory is data-only, not a resource/native/packaging tree.
    # Keep apply.json and tool logs in its parent, not among the emitted DEX files.
    expected_paths = set(dex.values())
    for parent in {item.parent for item in expected_paths}:
        seen = 0
        for child in parent.iterdir():
            seen += 1
            _require(seen <= driver.MAX_ENTRIES and not child.is_symlink() and
                     child.resolve() in expected_paths and child.is_file(),
                     'unexpected emitted output; only declared DEX files are supported')
    _dex_layout(dex)
    return dex, files


def _dex_layout(names):
    """Return canonical numeric order, rejecting empty or gapped DEX sets."""
    ordered = sorted(names, key=lambda name: 1 if name == 'classes.dex' else int(name[7:-4]))
    expected = ['classes.dex' if index == 1 else f'classes{index}.dex'
                for index in range(1, len(ordered) + 1)]
    _require(ordered and ordered == expected, 'nonempty contiguous canonical DEX layout required')
    return ordered


def _write_unsigned(original, destination, replacements):
    budget = driver.Budget()
    archive = driver._validated_zip(original, budget)
    try:
        _packaging(archive)
        with destination.open('xb') as sink, zipfile.ZipFile(sink, 'w', allowZip64=False) as output:
            output.comment = archive.comment
            members = list(archive.infolist())
            original_names = {member.filename for member in members}
            # Added DEX inherit primary DEX storage/compression and ZIP metadata.
            # Existing names retain their own metadata; no old DEX survives removal.
            primary = archive.getinfo('classes.dex') if replacements else None
            additions = set(replacements) - original_names
            for name in sorted(additions, key=lambda name: int(name[7:-4])):
                info = copy.copy(primary)
                info.filename = info.orig_filename = name
                members.append(info)
            for member in members:
                if _stale_signature(member.filename) or (
                        _DEX.fullmatch(member.filename) and member.filename not in replacements):
                    continue
                info = copy.copy(member)
                info.extra = _extras(info.extra)
                with output.open(info, 'w') as target:
                    if member.filename in replacements:
                        with replacements[member.filename].open('rb') as source:
                            size = 0
                            while True:
                                block = source.read(driver.CHUNK)
                                if not block:
                                    break
                                size += len(block)
                                _require(size <= driver.MAX_FILE_BYTES, 'emitted DEX grew during assembly')
                                target.write(block)
                    else:
                        driver._read_member(archive, member, budget, sink=target)
    finally:
        driver._close_zip(archive)


def _unchanged(files):
    for path, digest in files.items():
        _require(path.is_file() and path.stat().st_size <= driver.MAX_ARCHIVE_BYTES,
                 'an assembly input changed during execution')
        _require(driver._hash_file(path) == digest, 'an assembly input changed during execution')


def _sign_member(tools, store, args, aligned, signed):
    """Shared v2-only command; never read the key or expand password values."""
    command = [str(tools['java']), '-jar', str(tools['signer_jar']), 'sign',
               '--ks', str(store), '--ks-key-alias', args['key_alias'],
               '--ks-pass', 'env:' + args['ks_pass_env']]
    if args['key_pass_env'] is not None:
        command += ['--key-pass', 'env:' + args['key_pass_env']]
    command += ['--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
                '--v3-signing-enabled', 'false', '--v4-signing-enabled', 'false',
                '--out', str(signed), str(aligned)]
    driver.run_tool(command, timeout=args['timeout'])


def _verify_record(result, path, digest, identity, signer):
    _require(isinstance(result, dict) and result.get('status') == 'selected_split_set_verified',
             'APK verification evidence missing')
    records = result.get('apks')
    _require(isinstance(records, list) and len(records) == 1 and isinstance(records[0], dict),
             'single verified APK evidence required')
    record = records[0]
    _require(record.get('path') == str(path) and record.get('sha256') == digest and
             record.get('manifest') == identity and
             record.get('signers_sha256') == sorted(signer), 'APK verification metadata mismatch')


def assemble(*, apks, apply_report, expect_apply_sha256, reviewed_apply, out,
             aapt2, java, signer_jar, zipalign, expect_package, expect_version_code,
             expect_version_name, expect_signer, abi, density, language,
             final_signer_sha256, keystore, ks_pass_env, key_alias,
             key_pass_env=None, timeout=120, allow_dex_layout_change=False,
             input_mode='standalone'):
    """Publish assembly.json only after every selected member passes all checks.

    input_mode: omitted/standalone retains schema-1 singleton outputs. Explicit
    base_config_set requires schema-2 apply evidence and emits schema-2 members.
    apks: original paths in exact apply-set order; base is manifest-selected.
    Split mode revalidates APKM provenance, source/request pins and whole topology,
    replaces only base DEX, and repacks/aligns/v2-verifies every companion.
    apply_report: reviewed successful patchdev apply.json; every path is absolute.
    expect_apply_sha256: independently supplied digest binding that exact execution.
    reviewed_apply: True acknowledges reviewed trusted execution, NOT JSON approval.
    out: NEW external directory with an existing parent. Failed runs remain there.
    Verification pins/selection match driver.verify_apks; final_signer_sha256 is
    separate from original expect_signer. Explicit tool paths must already exist.
    keystore is NEVER opened here. Only env names reach apksigner argv; no logs.
    timeout bounds alignment/signing tools (1..600s); verifier uses driver bounds.
    Singleton outputs unsigned.apk/aligned.apk/signed.apk use v2-only signing
    (API24+). Split outputs use members/NNN/{unsigned,aligned,signed}.apk and
    require affirmative v2 evidence and the identical pinned final signer each.
    allow_dex_layout_change: explicit bool, default False (exact name-set required).
    True permits complete contiguous canonical DEX replacement, including additions
    and removals. Added DEX inherit classes.dex compression; retained names keep
    their original compression. All non-signature non-DEX payloads are preserved.
    Layout changes are supported ONLY within the existing API24+ runtime scope:
    declared/effective minSDK evidence does not prove layout/runtime compatibility.
    Schema 1 adds dex_layout evidence; changed_dex includes added/removed names.
    """
    try:
        return _assemble(apks=apks, apply_report=apply_report,
                         expect_apply_sha256=expect_apply_sha256, reviewed_apply=reviewed_apply,
                         out=out, aapt2=aapt2, java=java, signer_jar=signer_jar,
                         zipalign=zipalign, expect_package=expect_package,
                         expect_version_code=expect_version_code, expect_version_name=expect_version_name,
                         expect_signer=expect_signer, abi=abi, density=density, language=language,
                         final_signer_sha256=final_signer_sha256, keystore=keystore,
                         ks_pass_env=ks_pass_env, key_alias=key_alias,
                         key_pass_env=key_pass_env, timeout=timeout,
                         allow_dex_layout_change=allow_dex_layout_change, input_mode=input_mode)
    except AssemblyError:
        raise
    except Exception:
        # Never render tool stdout/stderr, passwords, argv, untrusted JSON or paths.
        raise AssemblyError('assembly failed; partial outputs are unverified') from None


def _assemble(**args):
    _require(args['reviewed_apply'] is True, 'reviewed trusted apply execution required; JSON is not approval')
    _require(type(args['allow_dex_layout_change']) is bool, 'DEX layout opt-in must be an explicit bool')
    _require(args['input_mode'] in ('standalone', 'base_config_set'), 'unsupported input mode')
    split = args['input_mode'] == 'base_config_set'
    _require(isinstance(args['apks'], (list, tuple)) and
             (2 <= len(args['apks']) <= 256 if split else len(args['apks']) == 1),
             'split sets require explicit base_config_set input mode and 2..256 members')
    _require(type(args['timeout']) is int and 1 <= args['timeout'] <= 600, 'invalid tool timeout')
    original = _file(args['apks'][0])
    _require(original.suffix.lower() == '.apk', 'explicit single APK input required')
    report = _file(args['apply_report'])
    final_signer = _sha(args['final_signer_sha256'])
    signers = args['expect_signer']
    _require(isinstance(signers, (list, tuple)) and signers, 'original signer pins required')
    signers = [_sha(value) for value in signers]
    identity = dict(package=args['expect_package'], version_code=args['expect_version_code'],
                    version_name=args['expect_version_name'], split=None)
    driver._valid_identity(identity)
    tools = {key: _file(args[key]) for key in ('aapt2', 'java', 'signer_jar', 'zipalign')}
    _require(tools['signer_jar'].suffix.lower() == '.jar', 'explicit apksigner JAR required')
    for key in ('aapt2', 'java', 'zipalign'):
        _require(tools[key].suffix.lower() not in ('.bat', '.cmd'), 'tool wrappers are unsupported')
        _require(Path(driver._executable(str(tools[key]))) == tools[key], 'explicit tool resolution mismatch')
    store = _file(args['keystore'])  # existence only: do not read/hash signing material
    for name in (args['ks_pass_env'], args['key_pass_env']):
        _require(name is None or isinstance(name, str) and _ENV.fullmatch(name) and name in os.environ,
                 'existing password environment variable NAME required')
    _require(args['ks_pass_env'] is not None, 'keystore password environment variable NAME required')
    _require(isinstance(args['key_alias'], str) and
             re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', args['key_alias']) is not None and
             not args['key_alias'].startswith('-'), 'explicit simple signing alias required')
    _require(isinstance(args['out'], (str, Path)) and Path(args['out']).is_absolute(),
             'absolute NEW external output directory required')
    _require(not Path(args['out']).is_symlink(), 'output directory cannot be a symlink')
    out = driver.external_output(Path(args['out']))
    _require(not out.exists() and not out.is_symlink() and out.parent.is_dir(),
             'output directory must be NEW with an existing parent')
    _require(not original.samefile(store), 'signing material cannot alias inputs/tools')
    if split:
        return _assemble_split(args, tools, store, out, report, signers, final_signer)
    _require(not report.samefile(store), 'signing material cannot alias apply evidence')
    _require(report.stat().st_size <= driver.MAX_METADATA_BYTES, 'apply report exceeds size limit')
    legacy = json.loads(report.read_text(encoding='utf-8'), object_pairs_hook=_json_unique)
    _require(legacy.get('input_mode', 'standalone') == 'standalone' and legacy.get('schema', 1) == 1,
             'split apply report requires explicit split assembly mode')
    dex, inputs = _report(report, args['expect_apply_sha256'], original, store)
    for tool in tools.values():
        _require(not tool.samefile(store), 'signing material cannot alias inputs/tools')
        inputs[tool] = driver._hash_file(tool)
    _require(not any(path.is_relative_to(out) for path in [*inputs, store]) and
             not any(out.is_relative_to(path.parent) for path in dex.values()),
             'outputs cannot overlap assembly inputs or emitted DEX directories')
    before = _inventory(original)
    original_dex = {name for name in before if _DEX.fullmatch(name)}
    layout_changed = set(dex) != original_dex
    if args['allow_dex_layout_change']:
        _dex_layout(original_dex)
        _dex_layout(dex)
    else:
        _require(not layout_changed, 'emitted DEX names must exactly match original DEX names')
    expected = {name: dict(record) for name, record in before.items()
                if not _stale_signature(name) and not _DEX.fullmatch(name)}
    changed = list(original_dex - set(dex))
    for name, path in dex.items():
        digest = inputs[path]
        if name not in before or digest != before[name]['sha256']:
            changed.append(name)
        expected[name] = dict(before.get(name, before['classes.dex']))
        expected[name].update(sha256=digest, bytes=path.stat().st_size)
    _require(changed, 'apply evidence contains no changed DEX payload')
    _unchanged(inputs)
    out.mkdir(exist_ok=False)
    options = {key: args[key] for key in ('expect_package', 'expect_version_code', 'expect_version_name',
                                         'abi', 'density', 'language')}
    options.update(aapt2=str(tools['aapt2']), java=str(tools['java']), signer_jar=tools['signer_jar'])
    verified = driver.verify_apks([original], out=out / 'original-verification.json',
                                  expect_signer=signers, **options)
    _verify_record(verified, original, inputs[original], identity, signers)
    _unchanged(inputs)
    unsigned, aligned, signed = (out / name for name in ('unsigned.apk', 'aligned.apk', 'signed.apk'))
    _write_unsigned(original, unsigned, dex)
    _require(_inventory(unsigned) == expected, 'unsigned payload/compression preservation mismatch')
    unsigned_hash = driver._hash_file(unsigned)
    align = str(tools['zipalign'])
    driver.run_tool([align, '-P', '16', '4', str(unsigned), str(aligned)], timeout=args['timeout'])
    _require(_inventory(aligned) == expected, 'aligned payload/compression preservation mismatch')
    aligned_hash = driver._hash_file(aligned)
    _sign_member(tools, store, args, aligned, signed)
    _require(_inventory(signed) == expected, 'signed payload/compression preservation mismatch')
    signed_hash = driver._hash_file(signed)
    driver.run_tool([align, '-c', '-P', '16', '4', str(signed)], timeout=args['timeout'])
    final = driver.verify_apks([signed], out=out / 'final-verification.json',
                              expect_signer=[final_signer], **options)
    _verify_record(final, signed, signed_hash, identity, [final_signer])
    _unchanged(inputs)
    _unchanged({unsigned: unsigned_hash, aligned: aligned_hash, signed: signed_hash})
    _require({item.name for item in out.iterdir()} ==
             {'original-verification.json', 'unsigned.apk', 'aligned.apk', 'signed.apk',
              'final-verification.json'}, 'unexpected assembly tool output')
    manifest = {
        'schema': 1, 'status': 'assembled_verified', 'scope': 'bytecode_only_single_apk_v2',
        'apply_report': {'path': str(report), 'sha256': inputs[report]},
        'input': {'path': str(original), 'sha256': inputs[original]},
        'inputs': [{'path': str(path), 'sha256': digest} for path, digest in sorted(inputs.items())],
        'outputs': {label: {'path': str(path), 'sha256': digest} for label, path, digest in
                    (('unsigned', unsigned, unsigned_hash), ('aligned', aligned, aligned_hash),
                     ('signed', signed, signed_hash))},
        'identity': identity, 'final_signer_sha256': final_signer,
        'selection': {'abi': args['abi'], 'density': args['density'], 'languages': list(args['language'])},
        'tools': {role: {'path': str(path), 'sha256': inputs[path]} for role, path in tools.items()},
        'signing': {'scheme': 'v2_only', 'password_transport': 'environment_variable_names'},
        'tool_timeout_seconds': args['timeout'],
        'changed_dex': sorted(changed),
        'dex_layout': {
            'allow_dex_layout_change': args['allow_dex_layout_change'],
            'changed': layout_changed,
            'original': sorted(original_dex, key=lambda name: (len(name), name)),
            'emitted': sorted(dex, key=lambda name: (len(name), name)),
            'added': sorted(set(dex) - original_dex),
            'removed': sorted(original_dex - set(dex)),
            'added_dex_compression': 'inherit_classes.dex',
            'runtime_scope': 'API24+ only (existing v2-only assembly scope)',
            'min_sdk_verification': 'declared/effective minSDK is in verification; layout-specific runtime compatibility not asserted',
        },
        'removed_stale_signatures': sorted(name for name in before if _stale_signature(name)),
        'payloads': expected,
        'original_verification': str(out / 'original-verification.json'),
        'final_verification': str(out / 'final-verification.json'),
        'alignment': {'status': 'passed', 'alignment': 4, 'native_page_kib': 16},
        'note': 'Local evidence only, not authenticated approval. No split, resource/native edit, '
                'legacy v1 signing, install or app-behavior verification.',
    }
    with (out / 'assembly.json').open('x', encoding='utf-8') as sink:
        json.dump(manifest, sink, indent=2)
        sink.write('\n')
    return manifest


def _assemble_split(args, tools, store, out, report_path, signers, final_signer):
    """Schema-2 set orchestration; reuse the singleton ZIP/pin/DEX guards."""
    spec = importlib.util.spec_from_file_location('_assembly_patchdev', _HERE / 'patchdev.py')
    patchdev = importlib.util.module_from_spec(spec); spec.loader.exec_module(patchdev)
    _require(not report_path.samefile(store), 'signing material cannot alias apply evidence')
    _require(driver._hash_file(report_path) == _sha(args['expect_apply_sha256']), 'apply report SHA-256 mismatch')
    report = patchdev.read_json(report_path)
    binding = report.get('split_binding')
    _require(report.get('schema') == 2 and report.get('input_mode') == 'base_config_set' and
             report.get('compatibility_mode') == 'APKM' and isinstance(binding, dict) and
             binding.get('input_mode') == 'base_config_set', 'schema-2 APKM whole-set apply evidence required')
    selected = binding.get('apks')
    _require(isinstance(selected, list) and 2 <= len(selected) <= 256, 'bounded whole-set evidence required')
    originals = [_file(path) for path in args['apks']]
    _require([str(path) for path in originals] == [r.get('path') for r in selected],
             'selected set dropped, added, reordered or substituted')
    container = binding.get('logical_container')
    _require(isinstance(container, dict), 'APKM provenance required')
    # Protect the existence-only signing input before any provenance/hash reads.
    for value in [*selected, container, binding.get('base', {})]:
        _require(not _file(value['path']).samefile(store), 'signing material cannot alias apply evidence')
    _require(patchdev.split_provenance(selected, container) == selected, 'APKM provenance changed')
    base_record = binding.get('base')
    _require(isinstance(base_record, dict), 'pinned manifest-selected base required')
    base = _file(base_record['path'])
    _require(base in originals, 'base is not in selected set')
    dex, inputs = _report(report_path, args['expect_apply_sha256'], base, store)

    def add_record(record):
        _require(isinstance(record, dict), 'pinned apply source evidence required')
        path = _file(record['path'])
        _require(not path.samefile(store), 'signing material cannot alias apply evidence')
        digest = _sha(record.get('sha256'))
        _require(driver._hash_file(path) == digest and inputs.get(path, digest) == digest,
                 'apply set/source SHA-256 mismatch')
        inputs[path] = digest

    for item in [*selected, container, report.get('request'), report.get('verification'), report.get('staged_verification')]:
        add_record(item)
    for field in ('source_hashes', 'tool_hashes'):
        _require(isinstance(report.get(field), list) and report[field], 'reviewed source/tool hashes required')
        for item in report[field]:
            add_record(item)
    mapping = binding.get('staged_apks')
    _require(isinstance(mapping, list) and len(mapping) == len(selected) and
             [r.get('original') for r in mapping] == selected, 'staged member mapping mismatch')
    for pair in mapping:
        add_record(pair.get('staged'))
        _require(pair['staged']['sha256'] == pair['original']['sha256'], 'staged member SHA-256 mismatch')
    request = patchdev.read_json(_file(report['request']['path']))
    _require(request.get('split_binding') == binding and request.get('input_mode') == 'base_config_set' and
             request.get('bundle') == report['bundle']['path'] and
             request.get('bundle_sha256') == report['bundle']['sha256'] and
             request.get('source_hashes') == report.get('source_hashes') and
             request.get('patches') == report.get('patches') and request.get('options') == report.get('options') == {} and
             request.get('patcher_version') == report.get('patcher_version') == '2.3.0',
             'runner request/apply binding mismatch')
    _require(type(binding.get('allow_dex_layout_change')) is bool, 'explicit apply DEX layout policy required')
    for tool in tools.values():
        _require(not tool.samefile(store), 'signing material cannot alias inputs/tools')
        if tool not in inputs:
            inputs[tool] = driver._hash_file(tool)
    _require(not any(path.is_relative_to(out) for path in [*inputs, store]) and
             not any(out.is_relative_to(path.parent) for path in dex.values()), 'outputs overlap assembly inputs')
    before = {path: _inventory(path, companion=path != base) for path in originals}
    original_dex = _dex_layout(name for name in before[base] if _DEX.fullmatch(name))
    emitted = _dex_layout(dex)
    layout_changed = set(original_dex) != set(emitted)
    _require(not layout_changed or (args['allow_dex_layout_change'] and binding['allow_dex_layout_change']),
             'DEX layout change requires explicit apply and assembly opt-in')
    changed = sorted(set(original_dex) - set(dex))
    expected = {}
    for path in originals:
        expected[path] = {name: dict(value) for name, value in before[path].items()
                          if not _stale_signature(name) and not (path == base and _DEX.fullmatch(name))}
    for name, path in dex.items():
        value = dict(before[base].get(name, before[base]['classes.dex']))
        value.update(sha256=inputs[path], bytes=path.stat().st_size)
        expected[base][name] = value
        if name not in before[base] or inputs[path] != before[base][name]['sha256']:
            changed.append(name)
    _require(changed, 'apply evidence contains no changed DEX payload')
    _unchanged(inputs)
    out.mkdir()
    options = {key: args[key] for key in ('expect_package', 'expect_version_code', 'expect_version_name', 'abi', 'density', 'language')}
    options.update(aapt2=str(tools['aapt2']), java=str(tools['java']), signer_jar=tools['signer_jar'])
    verified = driver.verify_apks(originals, out=out / 'original-verification.json', expect_signer=signers, **options)
    topology = patchdev.verified_split_binding(verified, selected, base_record, abi=args['abi'], density=args['density'])
    _require(request.get('identity') == verified['expected'], 'runner identity differs from freshly verified original set')
    _require(topology == binding.get('topology') and verified['selection'] == binding.get('selection'),
             'fresh whole-set topology/selection differs from apply evidence')
    staged_topology = json.loads(json.dumps(topology))
    staged_by_original = {pair['original']['path']: pair['staged'] for pair in mapping}
    staged_topology.update(base=staged_by_original[str(base)]['path'])
    for member in staged_topology['members']:
        member.update(staged_by_original[member['path']])
    _require(staged_topology == binding.get('staged_topology') and
             request.get('input') == staged_topology['base'] and request.get('input_sha256') == base_record['sha256'],
             'staged topology/base execution binding mismatch')
    _unchanged(inputs)
    members_dir = out / 'members'; members_dir.mkdir()
    mappings, output_hashes, signed_paths = [], {}, []
    for index, original in enumerate(originals):
        directory = members_dir / f'{index:03d}'; directory.mkdir()
        unsigned, aligned, signed = [directory / name for name in ('unsigned.apk', 'aligned.apk', 'signed.apk')]
        companion = original != base
        _unchanged(inputs)
        _write_unsigned(original, unsigned, {} if companion else dex)
        _require(_inventory(unsigned, companion=companion) == expected[original], 'unsigned payload/compression preservation mismatch')
        output_hashes[unsigned] = driver._hash_file(unsigned)
        driver.run_tool([str(tools['zipalign']), '-P', '16', '4', str(unsigned), str(aligned)], timeout=args['timeout'])
        _require(_inventory(aligned, companion=companion) == expected[original], 'aligned payload/compression preservation mismatch')
        output_hashes[aligned] = driver._hash_file(aligned)
        _sign_member(tools, store, args, aligned, signed)
        _require(_inventory(signed, companion=companion) == expected[original], 'signed payload/compression preservation mismatch')
        output_hashes[signed] = driver._hash_file(signed)
        driver.run_tool([str(tools['zipalign']), '-c', '-P', '16', '4', str(signed)], timeout=args['timeout'])
        stdout, _ = driver.run_tool([str(tools['java']), '-jar', str(tools['signer_jar']), 'verify',
                                     '--verbose', '--print-certs', str(signed)], timeout=args['timeout'])
        v2 = re.findall(r'(?m)^Verified using v2 scheme \(APK Signature Scheme v2\): (true|false)[ \t]*\r?$', stdout)
        certs = re.findall(r'(?m)^Signer #([1-9][0-9]*) certificate SHA-256 digest: ([0-9a-fA-F]{64})[ \t]*\r?$', stdout)
        _require(v2 == ['true'] and [(n, s.lower()) for n, s in certs] == [('1', final_signer)],
                 'affirmative v2 and exact final signer required per APK')
        _unchanged(inputs); _unchanged(output_hashes)
        _require({path.name for path in directory.iterdir()} == {'unsigned.apk', 'aligned.apk', 'signed.apk'},
                 'unexpected assembly tool output')
        mappings.append({'original': selected[index], 'split': topology['members'][index]['split'],
                         'role': 'base_config' if companion else 'base',
                         'outputs': {label: {'path': str(path), 'sha256': output_hashes[path]}
                                     for label, path in (('unsigned', unsigned), ('aligned', aligned), ('signed', signed))},
                         'payloads': expected[original], 'removed_stale_signatures': sorted(name for name in before[original] if _stale_signature(name)),
                         'alignment': {'status': 'passed', 'alignment': 4, 'native_page_kib': 16},
                         'signing': {'scheme': 'v2_only', 'v2_verified': True, 'signer_sha256': final_signer}})
        signed_paths.append(signed)
    final = driver.verify_apks(signed_paths, out=out / 'final-verification.json', expect_signer=[final_signer], **options)
    _require(len(final.get('apks', [])) == len(originals), 'final whole-set verification missing members')
    for original_record, final_record, path in zip(verified['apks'], final['apks'], signed_paths):
        _verify_record({'status': final.get('status'), 'apks': [final_record]}, path, output_hashes[path],
                       original_record['manifest'], [final_signer])
        for lib in final_record.get('native_libraries', []):
            if lib['compression'] == zipfile.ZIP_STORED:
                _require(lib['data_offset'] % 16384 == 0, 'stored native ZIP data must be 16-KiB aligned')
    final_base = signed_paths[originals.index(base)]
    final_selected = [{'path': str(path), 'sha256': output_hashes[path]} for path in signed_paths]
    final_topology = patchdev.verified_split_binding(final, final_selected,
        {'path': str(final_base), 'sha256': output_hashes[final_base]}, abi=args['abi'], density=args['density'])
    normalized_final = json.loads(json.dumps(final_topology))
    normalized_final.update(base=topology['base'], base_sha256=topology['base_sha256'], base_dex=topology['base_dex'])
    for member, old in zip(normalized_final['members'], topology['members']):
        member.update(path=old['path'], sha256=old['sha256'])
    _require(normalized_final == topology and final_topology['base_dex'] == emitted,
             'final selected-set topology drift')
    _unchanged(inputs); _unchanged(output_hashes)
    _require({p.name for p in out.iterdir()} == {'original-verification.json', 'final-verification.json', 'members'} and
             {p.name for p in members_dir.iterdir()} == {f'{i:03d}' for i in range(len(originals))},
             'unexpected assembly tool output')
    result = {'schema': 2, 'status': 'assembled_verified', 'scope': 'bytecode_only_base_config_set_v2',
              'input_mode': 'base_config_set', 'compatibility_mode': 'APKM', 'split_binding': binding,
              'apply_report': {'path': str(report_path), 'sha256': inputs[report_path]},
              'members': mappings, 'topology': topology, 'final_topology': final_topology,
              'selection': binding['selection'], 'final_signer_sha256': final_signer,
              'inputs': [{'path': str(path), 'sha256': digest} for path, digest in sorted(inputs.items())],
              'changed_dex': sorted(changed), 'dex_layout': {'original': original_dex, 'emitted': emitted,
                  'changed': layout_changed, 'allow_dex_layout_change': args['allow_dex_layout_change']},
              'original_verification': str(out / 'original-verification.json'),
              'final_verification': str(out / 'final-verification.json'),
              'note': 'Local whole-set evidence, not authenticated approval. No JNI, resource completeness, install or runtime proof; pathname races remain possible.'}
    with (out / 'assembly.json').open('x', encoding='utf-8') as sink:
        json.dump(result, sink, indent=2)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apk', type=Path, action='append', required=True, dest='apks')
    parser.add_argument('--input-mode', choices=['standalone', 'base_config_set'], default='standalone',
                        help='Opt-in APKM base-only patching with a whole-set schema-2 apply report')
    parser.add_argument('--apply-report', type=Path, required=True)
    parser.add_argument('--expect-apply-sha256', required=True)
    parser.add_argument('--reviewed-apply', action='store_true', required=True,
                        help='Acknowledge reviewed trusted execution, not approval from arbitrary JSON')
    parser.add_argument('--allow-dex-layout-change', action='store_true',
                        help='Explicitly allow complete contiguous DEX replacement (API24+ only); '
                             'recorded minSDK is not layout/runtime proof; reviewed/pinned apply evidence is still required')
    parser.add_argument('--out', type=Path, required=True)
    driver.verification_arguments(parser)
    parser.add_argument('--zipalign', required=True)
    parser.add_argument('--final-signer-sha256', required=True)
    parser.add_argument('--keystore', type=Path, required=True)
    parser.add_argument('--ks-pass-env', required=True, help='Environment variable NAME, not a password')
    parser.add_argument('--key-alias', required=True)
    parser.add_argument('--key-pass-env', help='Environment variable NAME, not a password')
    parser.add_argument('--timeout', type=int, default=120)
    args = parser.parse_args(argv)
    try:
        result = assemble(**vars(args))
    except AssemblyError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps({'status': result['status'], 'manifest': str(Path(args.out) / 'assembly.json')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
