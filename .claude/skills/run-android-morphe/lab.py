"""Private, offline lab intake, explicit tool preflight and JADX navigation.

Run with Python -I -B. No generated source is a working semantic patch. All
archives/decompiler output remain untrusted data; original DEX is authoritative.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
_SPEC = importlib.util.spec_from_file_location('_android_lab_driver', HERE / 'driver.py')
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError('sibling driver unavailable')
driver = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = driver
_SPEC.loader.exec_module(driver)
LabError = driver.DriverError

TOOLS = ('java', 'javac', 'jar', 'aapt2', 'zipalign', 'apksigner_jar',
         'd8_jar', 'android_jar', 'jadx_jar')
OPTIONAL_FILES = ('build_tools_properties', 'platform_properties')
OPTIONAL_LISTS = ('compiler_classpath', 'runtime_classpath')
MAX_CONFIG_BYTES = 1024 * 1024
MAX_PROBE_OUTPUT = 128 * 1024
MAX_DISCOVERY_BYTES = 256 * 1024 * 1024
MAX_DISCOVERY_FILES = 20000
MAX_MATCHES = 1000


def _sha(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', value):
        raise LabError('explicit SHA-256 must contain 64 hexadecimal characters')
    return value.lower()


def _regular(path):
    """Never accept an explicit link, device or shell wrapper as a tool/input."""
    path = Path(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or path.is_symlink()
            or getattr(info, 'st_file_attributes', 0) & 0x400):
        raise LabError('explicit regular file required')
    return path.resolve(strict=True)


def _new_output(path):
    path = Path(path)
    if path.exists() or path.is_symlink():
        raise LabError('output must be a NEW external directory')
    out = driver.external_output(path)
    if not out.parent.is_dir():
        raise LabError('output parent must already exist')
    return out


def _write_json(path, value):
    with path.open('x', encoding='utf-8') as sink:
        json.dump(value, sink, indent=2, ensure_ascii=True, allow_nan=False)
        sink.write('\n')


def _check_hash(path, expected):
    if driver._hash_file(_regular(path)) != expected:
        raise LabError('input changed or SHA-256 mismatch')


def _input_file(path):
    source = _regular(path)
    if source.stat().st_size > driver.MAX_ARCHIVE_BYTES:
        raise LabError('input archive byte limit exceeded')
    return source


def _copy_input(source, expected, destination):
    """Copy only bytes, with a size bound and checks before/during/after intake."""
    source = _input_file(source)
    _check_hash(source, expected)
    digest, total = hashlib.sha256(), 0
    with source.open('rb') as stream, destination.open('xb') as sink:
        while block := stream.read(driver.CHUNK):
            total += len(block)
            if total > driver.MAX_ARCHIVE_BYTES:
                raise LabError('input archive byte limit exceeded')
            digest.update(block)
            sink.write(block)
    if digest.hexdigest() != expected:
        raise LabError('input changed during copy')
    _check_hash(source, expected)
    _check_hash(destination, expected)
    return {'path': str(destination), 'sha256': expected, 'bytes': total}


def init_lab(archive, expected_sha256, desired_change, out):
    """Inventory a pinned APK/APKM/ZIP in a NEW lab; never infer trusted pins."""
    expected = _sha(expected_sha256)
    source = _input_file(archive)
    if source.suffix.lower() not in ('.apk', '.apkm', '.zip'):
        raise LabError('input must be an explicit APK, APKM or ZIP')
    if (not isinstance(desired_change, str) or not desired_change.strip()
            or len(desired_change) > 8192
            or any(ord(c) < 32 and c not in '\n\t' for c in desired_change)):
        raise LabError('explicit bounded desired change required')
    out = _new_output(out)
    _check_hash(source, expected)
    out.mkdir()
    untrusted = out / 'untrusted'
    untrusted.mkdir()
    (untrusted / 'input').mkdir()
    for name in ('source', 'tests', 'stages'):
        (out / name).mkdir()
    copied = _copy_input(source, expected, untrusted / 'input' / ('input' + source.suffix.lower()))
    inventory = driver.inspect_archive(Path(copied['path']), untrusted / 'inventory')
    if not inventory['apks']:
        raise LabError('input inventory contains no APKs')
    _check_hash(source, expected)
    _check_hash(Path(copied['path']), expected)
    result = {
        'schema': 1, 'status': 'lab_initialized_unverified', 'lab': str(out),
        'input': {'original_path': str(source), **copied},
        'desired_change': desired_change,
        'inventory': 'untrusted/inventory/inventory.json',
        'inventory_sha256': driver._hash_file(untrusted / 'inventory/inventory.json'),
        'invocation': {'operation': 'init', 'cwd': str(HERE)},
        'apk_count': len(inventory['apks']),
        'directories': {'untrusted': 'untrusted', 'source': 'source',
                        'tests': 'tests', 'stages': 'stages'},
        'selected_apks': [], 'trusted_identity': None,
        'patch_status': 'not_authored',
        'requirements': ['independently reviewed package/version/signer pins',
                         'explicit selected APK set and caller-reviewed split completeness',
                         'app-specific source, exact DEX targets and assertions'],
        'note': 'Inventory is untrusted navigation, not verification or authenticated attestation.'}
    _write_json(out / 'lab.json', result)
    return result


def _read_config(path):
    path = _regular(path)
    with path.open('rb') as stream:
        data = stream.read(MAX_CONFIG_BYTES + 1)
    if len(data) > MAX_CONFIG_BYTES:
        raise LabError('tools configuration byte limit exceeded')
    config = driver._metadata_json(data)
    allowed = {'schema', *TOOLS, 'dex_classpath', *OPTIONAL_FILES, *OPTIONAL_LISTS}
    if set(config) - allowed or set(TOOLS + ('dex_classpath', 'schema')) - set(config):
        raise LabError('tools configuration has missing or unknown fields')
    if type(config['schema']) is not int or config['schema'] != 1:
        raise LabError('unsupported tools configuration schema')
    for key in TOOLS + OPTIONAL_FILES:
        if key in config:
            _config_record(config[key])
    for key in ('dex_classpath',) + OPTIONAL_LISTS:
        if key not in config:
            continue
        records = config[key]
        if not isinstance(records, list) or not 1 <= len(records) <= 128:
            raise LabError('explicit nonempty bounded dependency list required')
        for record in records:
            _config_record(record)
        paths = [os.path.normcase(str(Path(r['path']).resolve())) for r in records]
        if len(set(paths)) != len(paths):
            raise LabError('duplicate dependency paths')
    return config, hashlib.sha256(data).hexdigest()


def _config_record(record):
    if not isinstance(record, dict) or set(record) != {'path', 'sha256'}:
        raise LabError('tool/dependency record requires only path and sha256')
    value = record['path']
    if (not isinstance(value, str) or not value or '\x00' in value
            or not Path(value).is_absolute() or '*' in value or '?' in value):
        raise LabError('explicit absolute tool/dependency path required; no wildcards')
    _sha(record['sha256'])


def _tree_budget(root, max_files, max_bytes):
    root = Path(root)
    info = root.lstat()
    if (not stat.S_ISDIR(info.st_mode) or root.is_symlink()
            or getattr(info, 'st_file_attributes', 0) & 0x400):
        raise LabError('discovery output must be a regular directory')
    count, total, entries = 0, 0, 0
    # No followlinks, and fail closed for reparse points and special files.
    def walk_error(_):
        raise LabError('discovery output could not be enumerated')
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        for name in dirs + files:
            entries += 1
            if entries > max_files * 2:
                raise LabError('discovery output entry limit exceeded')
            path = Path(parent) / name
            info = path.lstat()
            if path.is_symlink() or getattr(info, 'st_file_attributes', 0) & 0x400:
                raise LabError('discovery output links are forbidden')
            if stat.S_ISREG(info.st_mode):
                count += 1
                total += info.st_size
                if count > max_files or total > max_bytes:
                    raise LabError('discovery output file/byte limit exceeded')
            elif not stat.S_ISDIR(info.st_mode):
                raise LabError('discovery special output file forbidden')
    return {'files': count, 'bytes': total}


def _run_bounded(args, *, timeout=15, output_limit=MAX_PROBE_OUTPUT,
                 tree=None, max_files=MAX_DISCOVERY_FILES,
                 max_bytes=MAX_DISCOVERY_BYTES, allow_nonzero=False, env_overrides=None):
    """Monitor child stdout/stderr plus generated files; never use untrusted cwd.

    Bounds are polled, so a single write can transiently exceed a disk budget.
    Only this directly launched child is stopped on failure; no process cleanup.
    """
    env = driver.tool_environment()
    for name in ('JADX_DISABLE_XML_SECURITY', 'JADX_DISABLE_ZIP_SECURITY'):
        env.pop(name, None)
    env.update(env_overrides or {})
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen([str(a) for a in args], cwd=str(HERE),
                                       env=env,
                                       shell=False, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr)
        except OSError:
            raise LabError('explicit tool could not be started') from None
        deadline = time.monotonic() + timeout
        try:
            while True:
                status = process.poll()
                if sum(os.fstat(s.fileno()).st_size for s in (stdout, stderr)) > output_limit:
                    raise LabError('tool output limit exceeded')
                if tree is not None:
                    _tree_budget(tree, max_files, max_bytes)
                if status is not None:
                    break
                if time.monotonic() >= deadline:
                    raise LabError('tool time limit exceeded')
                time.sleep(0.05)
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                raise LabError('tool termination unconfirmed') from None
        if process.returncode and not allow_nonzero:
            raise LabError('tool exited unsuccessfully')
        outputs = []
        for stream in (stdout, stderr):
            stream.seek(0)
            outputs.append(stream.read(output_limit).decode('utf-8', errors='replace'))
        return process.returncode, '\n'.join(outputs)


def _present(record, *, executable=False):
    result = {'path': record['path'], 'expected_sha256': _sha(record['sha256']),
              'present': False, 'hash_verified': False}
    try:
        path = _regular(record['path'])
        if executable and path.suffix.lower() in ('.bat', '.cmd', '.ps1', '.py', '.sh'):
            raise LabError('shell-wrapper tools forbidden')
        result['present'] = True
        result['sha256'] = driver._hash_file(path)
        result['hash_verified'] = result['sha256'] == result['expected_sha256']
        if not result['hash_verified']:
            result['error'] = 'hash_mismatch'
    except (OSError, ValueError, LabError):
        result['error'] = 'missing_or_invalid_regular_file'
    return result


def _jar_contains(path, name):
    """Bounded, case-sensitive membership of an already pinned trusted tool JAR.

    Never extract or decompress: valid Java classes may differ only in case even
    on Windows. APK extraction keeps the stricter filesystem-alias rejection.
    """
    with Path(path).open('rb') as stream:
        _, count = driver._zip_directory_bounds(stream, driver.Budget())
        with zipfile.ZipFile(stream) as archive:
            entries = archive.infolist()
            names = [entry.filename for entry in entries]
            if len(entries) != count or len(set(names)) != len(names):
                raise LabError('ambiguous tool JAR entries')
            matches = [entry for entry in entries if entry.filename == name]
            return bool(matches and not matches[0].is_dir() and not matches[0].flag_bits & 1
                        and matches[0].compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED))


def preflight(tools_config, out, *, probe=True):
    """Check ONLY an explicit hash-pinned manifest; no PATH/cache discovery.

    File presence, successful probes, SDK identity, and build closure are distinct.
    This command does not prove an app/patch build or dependency ABI compatibility.
    """
    if type(probe) is not bool:
        raise LabError('probe must be boolean')
    config, config_sha = _read_config(tools_config)
    out = _new_output(out)
    out.mkdir()
    records = {key: _present(config[key], executable=key in TOOLS[:5]) for key in TOOLS}
    for key in OPTIONAL_FILES:
        if key in config:
            records[key] = _present(config[key])
    dependencies = {key: [_present(r) for r in config[key]]
                    for key in ('dex_classpath',) + OPTIONAL_LISTS if key in config}
    blockers, probes = [], {}
    if not all(r['hash_verified'] for r in records.values()):
        blockers.append('missing_invalid_or_changed_tools')
    if not all(r['hash_verified'] for rs in dependencies.values() for r in rs):
        blockers.append('missing_invalid_or_changed_dependencies')

    def ready(*keys):
        return all(records[k]['hash_verified'] for k in keys)

    commands = {
        'java': ('java', ['-version']), 'javac': ('javac', ['-version']),
        'jar': ('jar', ['--version']), 'aapt2': ('aapt2', ['version']),
        'zipalign': ('zipalign', ['-h']),
        'apksigner_jar': ('java', ['-Xmx256m', '-jar', config['apksigner_jar']['path'], 'version']),
        'd8_jar': ('java', ['-Xmx256m', '-cp', config['d8_jar']['path'], 'com.android.tools.r8.D8', '--version']),
        'jadx_jar': ('java', ['-Xmx256m', '-Djava.awt.headless=true', '-cp', config['jadx_jar']['path'], 'jadx.cli.JadxCLI', '--version'])}
    for key, (executable, arguments) in commands.items():
        prerequisites = (key, executable)
        if not probe:
            probes[key] = {'status': 'not_requested'}
            continue
        if not ready(*prerequisites):
            probes[key] = {'status': 'blocked'}
            continue
        try:
            for prerequisite in set(prerequisites):
                _check_hash(Path(config[prerequisite]['path']), _sha(config[prerequisite]['sha256']))
            code, output = _run_bounded([config[executable]['path'], *arguments], allow_nonzero=key == 'zipalign')
            # Never emit raw process output (may contain local environment or paths).
            if key in ('java', 'javac', 'jar'):
                prefix = r'(?:openjdk|java) (?:version )?"?' if key == 'java' else key + r' '
                match = re.search(r'(?m)^' + prefix + r'(21(?:[.][0-9]+)*(?:[-+][A-Za-z0-9.]+)?)(?=[\s"\r\n]|$)', output)
                if not match:
                    raise LabError('JDK 21 required')
                version = match.group(1)
            elif key == 'zipalign':
                if not re.search(r'zip\s*align|zipalign|zip alignment', output, re.I):
                    raise LabError('zipalign help evidence missing')
                version = None
            else:
                match = re.search(r'(?<![A-Za-z0-9])\d+(?:\.\d+){0,4}(?![A-Za-z0-9])', output)
                if not match:
                    raise LabError('version evidence missing')
                version = match.group(0)
            probes[key] = {'status': 'executed', 'exit_code': code, 'version': version}
        except (LabError, OSError):
            probes[key] = {'status': 'failed'}
    if not probe or any(p['status'] != 'executed' for p in probes.values()):
        blockers.append('tool_execution_unverified')

    sdk = {}
    for key, pattern in (
        ('build_tools_properties', r'(?m)^Pkg\.Revision\s*=\s*36\.0\.[0-9]+\s*$'),
        ('platform_properties', r'(?m)^AndroidVersion\.ApiLevel\s*=\s*36\s*$')):
        valid = False
        if key in records and ready(key):
            path = Path(config[key]['path'])
            if path.stat().st_size <= 65536:
                text = path.read_text(encoding='utf-8')
                valid = bool(re.search(pattern, text))
                # SDK identity is bound to the supplied file locations, not a label.
                expected_parent = path.parent
                tool_keys = ('aapt2', 'zipalign') if key == 'build_tools_properties' else ('android_jar',)
                valid = valid and all(Path(config[k]['path']).resolve().parent == expected_parent for k in tool_keys)
        sdk[key] = valid
    if not all(sdk.values()):
        blockers.append('sdk36_identity_unverified')
    jar_checks = {}
    for key, entry in (('android_jar', 'android/app/Activity.class'),
                       ('d8_jar', 'com/android/tools/r8/D8.class')):
        try:
            jar_checks[key] = ready(key) and _jar_contains(config[key]['path'], entry)
        except (LabError, OSError, ValueError, zipfile.BadZipFile):
            jar_checks[key] = False
    try:
        jar_checks['dex_classpath'] = all(r['hash_verified'] for r in dependencies['dex_classpath']) and any(
            _jar_contains(r['path'], 'com/android/tools/smali/dexlib2/DexFileFactory.class')
            for r in dependencies['dex_classpath'])
    except (LabError, OSError, ValueError, zipfile.BadZipFile):
        jar_checks['dex_classpath'] = False
    if not all(jar_checks.values()):
        blockers.append('required_java_classes_missing')
    # Optional patch compiler/runtime manifests can be checked for exact bytes, but
    # only a real offline build/application proves their transitive compatibility.
    closure = {key: ('hashes_verified_not_executed' if key in dependencies and
                      all(r['hash_verified'] for r in dependencies[key]) else 'not_supplied_or_invalid')
               for key in OPTIONAL_LISTS}
    if any(value == 'not_supplied_or_invalid' for value in closure.values()):
        blockers.append('patch_compiler_runtime_closure_not_supplied')
    for key, record in records.items():
        if record['hash_verified']:
            try:
                _check_hash(Path(record['path']), record['expected_sha256'])
            except (LabError, OSError):
                blockers.append('tool_changed_during_preflight')
    for group in dependencies.values():
        for record in group:
            if record['hash_verified']:
                try:
                    _check_hash(Path(record['path']), record['expected_sha256'])
                except (LabError, OSError):
                    blockers.append('dependency_changed_during_preflight')
    result = {'schema': 1, 'status': 'preflight_blocked' if blockers else 'preflight_checks_passed',
              'config_sha256': config_sha,
              'invocation': {'operation': 'preflight', 'cwd': str(HERE), 'probe': probe},
              'tools': records, 'dependencies': dependencies,
              'probes': probes, 'sdk36': sdk, 'required_classes': jar_checks,
              'patch_dependency_closure': closure, 'blockers': sorted(set(blockers)),
              'note': 'Exact manifest only. Presence/probes are not an offline build, signature verification, or dependency ABI proof.'}
    _write_json(out / 'preflight.json', result)
    return result


def search_sources(root, search, *, max_matches=MAX_MATCHES,
                   max_files=MAX_DISCOVERY_FILES, max_bytes=MAX_DISCOVERY_BYTES):
    """Literal class-path and string navigation, not inferred DEX selectors."""
    if (not isinstance(search, str) or not 1 <= len(search) <= 1024
            or any(ord(c) < 32 for c in search)):
        raise LabError('bounded nonempty literal search text required')
    if type(max_matches) is not int or not 1 <= max_matches <= MAX_MATCHES:
        raise LabError('invalid navigation match limit')
    _tree_budget(root, max_files, max_bytes)
    matches, truncated = [], False
    needle = search.casefold()
    for parent, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(parent) / name
            if path.suffix.lower() not in ('.java', '.kt', '.xml', '.txt', '.json'):
                continue
            relative = path.relative_to(root).as_posix()
            if needle in relative.casefold():
                if len(matches) >= max_matches:
                    truncated = True
                    break
                matches.append({'kind': 'class_path', 'path': relative})
            # Bounded chunks/lines: an attacker-controlled single line must not
            # become an unbounded Python allocation. Preserve cross-chunk matches.
            tail, line = '', 1
            with path.open('r', encoding='utf-8', errors='replace') as stream:
                while chunk := stream.read(65536):
                    text = tail + chunk
                    offset = 0
                    while (position := text.find(search, offset)) >= 0:
                        if len(matches) >= max_matches:
                            truncated = True
                            break
                        matches.append({'kind': 'string', 'path': relative,
                                        'line': line + text[:position].count('\n')})
                        offset = position + len(search)
                    if truncated:
                        break
                    keep = min(len(search) - 1, len(text))
                    boundary = len(text) - keep
                    line += text[:boundary].count('\n')
                    tail = text[boundary:]
            if truncated:
                break
        if truncated:
            break
    return {'query': search, 'matches': matches, 'truncated': truncated,
            'note': 'Decompiled names/strings only. Confirm full descriptors and exactly-one targets with original DEX inspection.'}


def discover(apk, expected_sha256, jadx_jar, java, out, search, *, jadx_sha256,
             timeout=120, heap_mb=1024, max_files=MAX_DISCOVERY_FILES,
             max_bytes=MAX_DISCOVERY_BYTES):
    """Decompile a copied pinned APK with explicitly trusted JADX, no resources."""
    expected, jadx_expected = _sha(expected_sha256), _sha(jadx_sha256)
    for value, low, high in ((timeout, 1, 300), (heap_mb, 128, 2048),
                             (max_files, 1, MAX_DISCOVERY_FILES),
                             (max_bytes, 1, MAX_DISCOVERY_BYTES)):
        if type(value) is not int or not low <= value <= high:
            raise LabError('discovery limit outside allowed range')
    if not isinstance(search, str) or not 1 <= len(search) <= 1024 or any(ord(c) < 32 for c in search):
        raise LabError('bounded nonempty literal search text required')
    source, jadx, java = _input_file(apk), _regular(jadx_jar), _regular(java)
    if source.suffix.lower() != '.apk' or jadx.suffix.lower() != '.jar':
        raise LabError('explicit APK and trusted JADX JAR required')
    if java.suffix.lower() in ('.bat', '.cmd', '.ps1', '.py', '.sh'):
        raise LabError('shell-wrapper tools forbidden')
    _check_hash(source, expected)
    _check_hash(jadx, jadx_expected)
    java_sha = driver._hash_file(java)
    out = _new_output(out)
    # Never run decompilation with a tool living in or beside the APK directory.
    if java.is_relative_to(source.parent) or jadx.is_relative_to(source.parent):
        raise LabError('tools must be separate from untrusted input directory')
    out.mkdir()
    untrusted = out / 'untrusted'
    untrusted.mkdir()
    (untrusted / 'input').mkdir()
    copied = _copy_input(source, expected, untrusted / 'input' / 'input.apk')
    inventory = driver.inspect_archive(Path(copied['path']), untrusted / 'inventory')
    if len(inventory['apks']) != 1 or not inventory['apks'][0]['dex']:
        raise LabError('discovery requires one code-bearing APK')
    decompiled = untrusted / 'jadx'
    decompiled.mkdir()
    state = decompiled / '.tool-state'
    state.mkdir()
    env = {}
    for variable, directory in (('JADX_CONFIG_DIR', 'config'), ('JADX_CACHE_DIR', 'cache'),
                                ('JADX_TMP_DIR', 'tmp')):
        location = state / directory
        location.mkdir()
        env[variable] = str(location)
    argv = [str(java), f'-Xmx{heap_mb}m', '-Djava.awt.headless=true', '-cp', str(jadx),
            'jadx.cli.JadxCLI', '--config', 'none', '--no-res', '--mappings-mode', 'ignore',
            '--deobf-cfg-file-mode', 'ignore', '--threads-count', '1',
            '--output-dir', str(decompiled), copied['path']]
    _run_bounded(argv, timeout=timeout, output_limit=MAX_PROBE_OUTPUT,
                 tree=decompiled, max_files=max_files, max_bytes=max_bytes, env_overrides=env)
    totals = _tree_budget(decompiled, max_files, max_bytes)
    if not totals['files']:
        raise LabError('JADX produced no navigation files')
    navigation = search_sources(decompiled, search, max_files=max_files, max_bytes=max_bytes)
    output_files = []
    for parent, dirs, files in os.walk(decompiled, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = _regular(Path(parent) / name)
            output_files.append({'path': path.relative_to(decompiled).as_posix(),
                                 'bytes': path.stat().st_size, 'sha256': driver._hash_file(path)})
    _check_hash(source, expected)
    _check_hash(Path(copied['path']), expected)
    _check_hash(jadx, jadx_expected)
    _check_hash(java, java_sha)
    result = {'schema': 1, 'status': 'navigation_only', 'input': copied,
              'original_path': str(source), 'tools': {'java': {'path': str(java), 'sha256': java_sha},
                                                     'jadx_jar': {'path': str(jadx), 'sha256': jadx_expected}},
              'invocation': {'argv': argv, 'cwd': str(HERE), 'timeout_seconds': timeout,
                             'heap_mb': heap_mb, 'max_files': max_files, 'max_bytes': max_bytes,
                             'environment_overrides': env,
                             'max_console_bytes': MAX_PROBE_OUTPUT},
              'output': {'path': str(decompiled), **totals, 'entries': output_files},
              'navigation': navigation,
              'dex': inventory['apks'][0]['dex'],
              'note': 'Original DEX remains authoritative. No semantic patch or target uniqueness is inferred. Inspect other selected code-bearing splits separately.'}
    _write_json(out / 'discovery.json', result)
    return result


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse normally echoes invalid values, which may be untrusted text.
        self.print_usage(sys.stderr)
        self.exit(2, 'invalid arguments; use --help\n')


def main(argv=None) -> int:
    parser = _ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    init = commands.add_parser('init', help='Initialize an unverified NEW external lab')
    init.add_argument('archive', type=Path)
    init.add_argument('--expect-sha256', required=True)
    init.add_argument('--desired-change', required=True)
    init.add_argument('--out', type=Path, required=True)
    check = commands.add_parser('preflight', help='Explicit hash-pinned JSON manifest only')
    check.add_argument('--tools', type=Path, required=True)
    check.add_argument('--out', type=Path, required=True)
    check.add_argument('--presence-only', action='store_true')
    find = commands.add_parser('discover', help='Bounded JADX class/string navigation only')
    find.add_argument('apk', type=Path)
    find.add_argument('--expect-sha256', required=True)
    find.add_argument('--jadx-jar', type=Path, required=True)
    find.add_argument('--jadx-sha256', required=True)
    find.add_argument('--java', type=Path, required=True)
    find.add_argument('--out', type=Path, required=True)
    find.add_argument('--search', required=True)
    find.add_argument('--timeout', type=int, default=120)
    find.add_argument('--heap-mb', type=int, default=1024)
    find.add_argument('--max-files', type=int, default=MAX_DISCOVERY_FILES)
    find.add_argument('--max-bytes', type=int, default=MAX_DISCOVERY_BYTES)
    args = parser.parse_args(argv)
    try:
        if args.command == 'init':
            result = init_lab(args.archive, args.expect_sha256, args.desired_change, args.out)
            evidence = args.out / 'lab.json'
        elif args.command == 'preflight':
            result = preflight(args.tools, args.out, probe=not args.presence_only)
            evidence = args.out / 'preflight.json'
        else:
            result = discover(args.apk, args.expect_sha256, args.jadx_jar, args.java,
                              args.out, args.search, jadx_sha256=args.jadx_sha256,
                              timeout=args.timeout, heap_mb=args.heap_mb,
                              max_files=args.max_files, max_bytes=args.max_bytes)
            evidence = args.out / 'discovery.json'
        print(json.dumps({'status': result['status'], 'evidence': str(evidence.resolve())}))
        return 1 if result['status'] == 'preflight_blocked' else 0
    except (LabError, OSError, ValueError, TypeError, RuntimeError, RecursionError,
            zipfile.BadZipFile, ET.ParseError):
        # Never echo config paths, archive names, subprocess output or exception text.
        print(json.dumps({'status': 'failed', 'error': 'lab operation failed; no verification implied'}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
