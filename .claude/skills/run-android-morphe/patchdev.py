"""Offline trusted-code development bundles, not Android MPP/Manager artifacts.

CLI: py -I -B patchdev.py {fixture-build,patch-build,apply} --config FILE
All paths in configuration are explicit absolute paths. Hashes are local evidence,
not attestations or a sandbox for the trusted patch/assertion/test code executed.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import zipfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location('_morphe_patchdev_driver', HERE / 'driver.py')
driver = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = driver
_spec.loader.exec_module(driver)
DriverError = driver.DriverError
HASH = re.compile(r'[0-9a-f]{64}')
DEX = re.compile(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex')
CLASS = re.compile(r'[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)*')


def read_json(path: Path) -> dict:
    if path.stat().st_size > 1024 * 1024:
        raise DriverError('configuration exceeds limit')
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result:
                raise DriverError('duplicate JSON key')
            result[k] = v
        return result
    value = json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique)
    if not isinstance(value, dict):
        raise DriverError('JSON object required')
    return value


def absolute(value) -> Path:
    if not isinstance(value, (str, Path)) or not Path(value).is_absolute():
        raise DriverError('explicit absolute path required')
    path = Path(value).resolve()
    if any(c in str(path) for c in ('\n', '\r', os.pathsep, '*', '?')):
        raise DriverError('unsafe path syntax')
    return path


def file_path(value) -> Path:
    path = absolute(value)
    if not path.is_file():
        raise DriverError('required file missing')
    return path


def fresh(value) -> Path:
    path = driver.external_output(absolute(value))
    if path.exists() or path.is_symlink() or not path.parent.is_dir():
        raise DriverError('output must be a NEW external directory with existing parent')
    path.mkdir()
    return path


def digest(path: Path) -> str:
    return driver._hash_file(path)


def pinned(value, expected) -> Path:
    path = file_path(value)
    if not isinstance(expected, str) or not HASH.fullmatch(expected) or digest(path) != expected:
        raise DriverError('file SHA-256 pin mismatch')
    return path


def record(path: Path) -> dict:
    return {'path': str(path), 'sha256': digest(path)}


def write_json(path: Path, value: dict):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)


def run(args: list, cwd: Path, *, timeout=180, limit=8 * 1024 * 1024) -> str:
    """Bound own child only; no shell, inherited JVM injection, raw diagnostics or daemon."""
    env = driver.tool_environment()
    # No inherited credential is intentionally passed as an argument or recorded.
    import tempfile
    with tempfile.TemporaryFile(dir=cwd) as stdout, tempfile.TemporaryFile(dir=cwd) as stderr:
        with subprocess.Popen([str(a) for a in args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                              stdout=stdout, stderr=stderr, shell=False) as child:
            start = time.monotonic()
            while child.poll() is None:
                if time.monotonic() - start > timeout or any(os.fstat(f.fileno()).st_size > limit for f in (stdout, stderr)):
                    child.kill(); child.wait(timeout=10)
                    raise DriverError('tool exceeded time/output bound')
                time.sleep(0.05)
            if any(os.fstat(f.fileno()).st_size > limit for f in (stdout, stderr)):
                raise DriverError('tool exceeded output bound')
            if child.returncode:
                raise DriverError('offline tool failed (diagnostics withheld)')
        stdout.seek(0); stderr.seek(0)
        return (stdout.read(limit) + stderr.read(limit)).decode('utf-8', errors='replace')


def jdk(config: dict, out: Path) -> dict:
    root = absolute(config['jdk'])
    suffix = '.exe' if os.name == 'nt' else ''
    java = file_path(root / 'bin' / ('java' + suffix))
    javac = file_path(root / 'bin' / ('javac' + suffix))
    version = run([java, '-version'], out)
    if not re.search(r'version "21(?:\.[^"]*)?"', version):
        raise DriverError('explicit installed JDK 21 required')
    run([javac, '-version'], out)
    return {'java': java, 'javac': javac}


def closure(cache_root) -> dict:
    """Resolve only reviewed coordinates and exact hashes, never wildcard a cache classpath."""
    root = absolute(cache_root)
    manifest = read_json(HERE / 'templates' / 'cache-closure.json')
    result = {}
    for role in ('runtime', 'compiler'):
        paths = []
        for coordinate, expected in manifest[role]:
            group, artifact, version = coordinate.split(':')
            matches = list((root / group / artifact / version).glob(f'*/{artifact}-{version}.jar'))
            if len(matches) != 1:
                raise DriverError('reviewed compiler/runtime dependency missing or ambiguous')
            paths.append(pinned(matches[0], expected))
        result[role] = paths
    return result


def classpath(paths) -> str:
    return os.pathsep.join(str(p) for p in paths)


def compile_kotlin(java: Path, deps: dict, sources: list[Path], target: Path, cwd: Path, extra=()):
    run([java, '-Xmx2g', '-cp', classpath(deps['compiler']), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
         '-no-stdlib', '-no-reflect', '-jvm-target', '17', '-classpath', classpath([*deps['runtime'], *extra]),
         '-d', target, *sources], cwd, timeout=240)


def unchanged(records: list[dict]):
    if any(digest(Path(r['path'])) != r['sha256'] for r in records):
        raise DriverError('source/tool/input changed during stage')


def sources(values) -> list[Path]:
    if not isinstance(values, list) or not values or len(values) > 100:
        raise DriverError('explicit trusted external Kotlin source list required')
    paths = [file_path(p) for p in values]
    if len(set(paths)) != len(paths) or any(p.suffix != '.kt' or p.is_relative_to(driver.REPO_DIR) for p in paths):
        raise DriverError('Kotlin sources must be unique, reviewed and external')
    return paths


def patch_build(config: dict) -> dict:
    if config.get('trusted_code') is not True:
        raise DriverError('explicit trusted_code=true required; hashes do not sandbox code')
    assertion = config['assertion_class']; test_class = config['test_class']
    if not all(isinstance(x, str) and CLASS.fullmatch(x) for x in (assertion, test_class)):
        raise DriverError('explicit assertion/test JVM classes required')
    patch_sources = sources(config['sources']); tests = sources(config['tests'])
    out = fresh(config['out']); tools = jdk(config, out); deps = closure(config['cache_root'])
    source_hashes = [record(p) for p in [HERE / 'GenericPatchRunner.kt', *patch_sources, *tests]]
    tool_hashes = [record(p) for p in [*tools.values(), *deps['runtime'], *deps['compiler'], HERE / 'templates/cache-closure.json']]
    # Compile runner independently FIRST, then the app-specific bundle and tests.
    runner = out / 'runner.jar'
    compile_kotlin(tools['java'], deps, [HERE / 'GenericPatchRunner.kt'], runner, out)
    classes = out / 'classes'; classes.mkdir()
    compile_kotlin(tools['java'], deps, patch_sources, classes, out)
    bundle = out / 'development.jar'
    with zipfile.ZipFile(bundle, 'x', compression=zipfile.ZIP_DEFLATED) as jar:
        jar.writestr('META-INF/MANIFEST.MF', 'Manifest-Version: 1.0\r\nPatcher-Version: 2.3.0\r\nBundle-Type: JVM-Development-Only\r\n\r\n')
        for p in sorted(classes.rglob('*')):
            if p.is_file():
                jar.write(p, p.relative_to(classes).as_posix())
    assertion_file = classes / (assertion.replace('.', '/') + '.class')
    if not assertion_file.is_file():
        raise DriverError('assertion entry class not compiled into bundle')
    test_jar = out / 'tests.jar'
    compile_kotlin(tools['java'], deps, tests, test_jar, out, [bundle])
    run([tools['java'], '-Xmx2g', '-cp', classpath([test_jar, bundle, *deps['runtime']]), test_class], out)
    unchanged([*source_hashes, *tool_hashes])
    result = {'schema': 1, 'status': 'jvm_development_bundle_built_tests_passed',
              'patcher_version': '2.3.0', 'bundle': record(bundle), 'runner': record(runner),
              'assertion_class': assertion, 'assertion_sha256': digest(assertion_file),
              'source_hashes': source_hashes, 'tool_hashes': tool_hashes,
              'note': 'Trusted JVM development bundle; NOT Android MPP or Manager-ready.'}
    write_json(out / 'build.json', result)
    return result


def fixture_build(config: dict) -> dict:
    """Build self-authored, unsigned local APK; no signing or SDK provisioning."""
    out = fresh(config['out']); tools = jdk(config, out)
    sdk = absolute(config['sdk']); build = sdk / 'build-tools/36.0.0'
    aapt = file_path(build / ('aapt2.exe' if os.name == 'nt' else 'aapt2'))
    d8 = file_path(build / 'lib/d8.jar'); android = file_path(sdk / 'platforms/android-36/android.jar')
    source = out / 'trusted-source'
    originals = [p for p in (HERE / 'fixture').rglob('*') if p.is_file()]
    src_hashes = [record(p) for p in originals]
    tool_hashes = [record(p) for p in [*tools.values(), aapt, d8, android]]
    shutil.copytree(HERE / 'fixture', source)
    for original, entry in zip(originals, src_hashes):
        pinned(source / original.relative_to(HERE / 'fixture'), entry['sha256'])
    classes = out / 'classes'; classes.mkdir(); dex = out / 'dex'; dex.mkdir()
    run([tools['javac'], '-g:none', '-source', '8', '-target', '8', '-bootclasspath', android,
         '-d', classes, source / 'MainActivity.java'], out)
    class_jar = out / 'fixture-classes.jar'
    with zipfile.ZipFile(class_jar, 'x') as jar:
        for p in sorted(classes.rglob('*.class')):
            jar.write(p, p.relative_to(classes).as_posix())
    run([tools['java'], '-Xmx1g', '-cp', d8, 'com.android.tools.r8.D8', '--release', '--min-api', '24',
         '--lib', android, '--output', dex, class_jar], out)
    apk = out / 'fixture-unsigned.apk'
    run([aapt, 'link', '-o', apk, '-I', android, '--manifest', source / 'AndroidManifest.xml',
         '--min-sdk-version', '24', '--target-sdk-version', '30'], out)
    with zipfile.ZipFile(apk, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
        for p in sorted(dex.glob('*.dex')):
            archive.write(p, p.name)
    unchanged([*src_hashes, *tool_hashes])
    result = {'schema': 1, 'status': 'unsigned_fixture_built', 'apk': record(apk), 'trusted_source': str(source),
              'expected': {'package': 'dev.morphe.fixture', 'version_name': '1.0', 'version_code': '1'},
              'source_hashes': src_hashes, 'tool_hashes': tool_hashes,
              'note': 'Unsigned self-authored local test app; baseline button displays BASELINE.'}
    write_json(out / 'fixture.json', result)
    return result


def check_code_apk(path: Path):
    budget = driver.Budget()
    archive = driver._validated_zip(path, budget)
    try:
        names = archive.namelist()
        if any(n.startswith('lib/') or (n.lower().endswith('.dex') and not DEX.fullmatch(n)) for n in names):
            raise DriverError('native or noncanonical code packaging unsupported')
        dex_names = [n for n in names if DEX.fullmatch(n)]
        canonical_dex(dex_names)
    finally:
        driver._close_zip(archive)


def canonical_dex(names):
    try:
        return driver.SPLITSET.canonical_dex(list(names))
    except driver.SPLITSET.SplitSetError as exc:
        raise DriverError(str(exc)) from exc


def split_provenance(selected, container):
    """Authenticate selected physical bytes against a pinned logical APKM ZIP.

    Container metadata is not trusted identity. Only explicitly selected member
    hashes are used; driver.verify_apks must still freshly verify the full set.
    """
    if not isinstance(selected, list) or not 2 <= len(selected) <= 256:
        raise DriverError('base_config_set requires 2..256 selected APK members')
    if not isinstance(container, dict) or set(container) != {'type', 'path', 'sha256'} or container['type'] != 'APKM':
        raise DriverError('explicit APKM logical_container provenance required')
    archive_path = pinned(container['path'], container['sha256'])
    if archive_path.suffix.lower() != '.apkm':
        raise DriverError('explicit APKM container required')
    paths, members, result = [], set(), []
    budget = driver.Budget(); archive = driver._validated_zip(archive_path, budget)
    try:
        for item in selected:
            if not isinstance(item, dict) or set(item) != {'path', 'sha256', 'archive_member'}:
                raise DriverError('selected member path/hash/archive_member required')
            path = pinned(item['path'], item['sha256']); member = item['archive_member']
            if (path.suffix.lower() != '.apk' or path.samefile(archive_path)
                    or any(path.samefile(other) for other in paths)
                    or not isinstance(member, str) or not member.endswith('.apk') or member in members):
                raise DriverError('duplicate, aliased or invalid selected APK member')
            info = archive.getinfo(member)
            if info.is_dir() or driver._read_member(archive, info, budget)[1] != item['sha256']:
                raise DriverError('APKM selected archive-member SHA-256 mismatch')
            paths.append(path); members.add(member)
            result.append({'path': str(path), 'sha256': item['sha256'], 'archive_member': member})
    finally:
        driver._close_zip(archive)
    unchanged([record_ for record_ in result] + [container])
    return result


def verified_split_binding(verified, selected, base, *, abi, density):
    """Bind freshly authenticated records to the exact ordered caller set/base."""
    expected = [{'path': r['path'], 'sha256': r['sha256']} for r in selected]
    records = verified.get('apks', [])
    if (verified.get('schema') != 2 or verified.get('status') != 'selected_split_set_verified'
            or [{'path': r.get('path'), 'sha256': r.get('sha256')} for r in records] != expected):
        raise DriverError('whole-set verification binding mismatch')
    topology = driver.validate_split_set(records, abi=abi, density=density)
    if (topology['mode'] != 'base_config_set' or verified.get('topology') != topology
            or base != {'path': topology['base'], 'sha256': topology['base_sha256']}):
        raise DriverError('manifest-selected physical base/topology mismatch')
    check_code_apk(Path(topology['base']))
    return topology


def apply(config: dict) -> dict:
    if config.get('trusted_code') is not True or config.get('patcher_version') != '2.3.0':
        raise DriverError('trusted code and exact expected patcher 2.3.0 required')
    names = config['patches']
    if not isinstance(names, list) or not names or any(not isinstance(n, str) or not n.strip() or len(n) > 200 for n in names) or len(set(names)) != len(names):
        raise DriverError('explicit unique patch selections required')
    if config.get('options') != {}:
        raise DriverError('only explicit empty options currently supported')
    mode = config.get('input_mode', 'standalone')
    if mode not in ('standalone', 'base_config_set'):
        raise DriverError('unsupported input_mode')
    split = mode == 'base_config_set'
    selected = config['apks']
    if split:
        selected = split_provenance(selected, config.get('logical_container'))
        base = config.get('base')
        if not isinstance(base, dict) or set(base) != {'path', 'sha256'}:
            raise DriverError('explicit pinned physical base reference required')
        apk = pinned(base['path'], base['sha256'])
        base = {'path': str(apk), 'sha256': base['sha256']}
        if type(config.get('allow_dex_layout_change', False)) is not bool:
            raise DriverError('DEX layout opt-in must be an explicit bool')
    else:
        if not isinstance(selected, list) or len(selected) != 1:
            raise DriverError('exactly one standalone code APK supported without explicit split mode')
        if any(key in config for key in ('logical_container', 'base')):
            raise DriverError('split provenance requires explicit base_config_set mode')
        apk = pinned(selected[0]['path'], selected[0]['sha256'])
    bundle = pinned(config['bundle']['path'], config['bundle']['sha256'])
    runner = pinned(config['runner']['path'], config['runner']['sha256'])
    assertion = config['assertion_class']; assertion_hash = config['assertion_sha256']
    if not isinstance(assertion, str) or not CLASS.fullmatch(assertion) or not isinstance(assertion_hash, str) or not HASH.fullmatch(assertion_hash):
        raise DriverError('explicit pinned assertion class required')
    # Inspect only bounded JAR structure and assertion bytes; loading is trusted execution.
    budget = driver.Budget(); jar = driver._validated_zip(bundle, budget)
    try:
        entry = jar.getinfo(assertion.replace('.', '/') + '.class')
        if entry.file_size > 1024 * 1024:
            raise DriverError('assertion class exceeds bound')
        if hashlib.sha256(jar.read(entry)).hexdigest() != assertion_hash:
            raise DriverError('assertion class SHA-256 mismatch')
    finally:
        driver._close_zip(jar)
    check_code_apk(apk)
    inputs = [{'path': str(apk), 'sha256': base['sha256'] if split else selected[0]['sha256']},
              {'path': str(bundle), 'sha256': config['bundle']['sha256']}]
    set_inputs = ([{'path': r['path'], 'sha256': r['sha256']} for r in selected]
                  + [config['logical_container']]) if split else []
    out = fresh(config['out']); tools = jdk(config, out); deps = closure(config['cache_root'])
    # Fresh mandatory verification: never accept a stale supplied verification JSON.
    verification = dict(config['verification'])
    verification['aapt2'] = str(file_path(verification['aapt2']))
    verification['signer_jar'] = file_path(verification['signer_jar'])
    verification['java'] = str(tools['java'])
    tool_hashes = [record(p) for p in [*tools.values(), *deps['runtime'], runner,
                                     Path(verification['aapt2']), verification['signer_jar'],
                                     HERE / 'templates/cache-closure.json', HERE / 'patchdev.py', HERE / 'driver.py']]
    tool_hashes += [record(HERE / 'splitset.py')]
    verified = driver.verify_apks([Path(r['path']) for r in selected] if split else [apk],
                                  out=out / 'verified-input.json', **verification)
    unchanged([*inputs, *set_inputs, *tool_hashes])
    binding = None
    execution_apk = apk
    staged = []
    if split:
        topology = verified_split_binding(verified, selected, base, abi=verification['abi'], density=verification['density'])
        stage = out / 'selected-inputs'; stage.mkdir()
        for index, item in enumerate(selected):
            target = stage / f'member-{index:03d}.apk'
            with Path(item['path']).open('rb') as source, target.open('xb') as sink:
                size = 0
                while True:
                    block = source.read(driver.CHUNK)
                    if not block:
                        break
                    size += len(block)
                    if size > driver.MAX_ARCHIVE_BYTES:
                        raise DriverError('selected APK grew beyond staging bound')
                    sink.write(block)
            pinned(target, item['sha256'])
            staged.append({'path': str(target), 'sha256': item['sha256']})
            if item['path'] == str(apk):
                execution_apk = target
        unchanged([*inputs, *set_inputs, *staged, *tool_hashes])
        staged_verified = driver.verify_apks([Path(r['path']) for r in staged],
                                            out=out / 'verified-staged.json', **verification)
        staged_base = {'path': str(execution_apk), 'sha256': base['sha256']}
        staged_topology = verified_split_binding(staged_verified, staged, staged_base,
                                                abi=verification['abi'], density=verification['density'])
        binding = {'input_mode': mode, 'logical_container': config['logical_container'],
                   'apks': selected, 'base': base, 'topology': topology,
                   'selection': verified['selection'], 'staged_topology': staged_topology,
                   'staged_apks': [{'original': original, 'staged': target}
                                   for original, target in zip(selected, staged)],
                   'allow_dex_layout_change': config.get('allow_dex_layout_change', False)}
    if digest(runner) != config['runner']['sha256']:
        raise DriverError('runner changed before invocation')
    # Source hashes are caller-pinned build metadata, rechecked, not blindly copied.
    source_hashes = config.get('source_hashes', [])
    if not isinstance(source_hashes, list) or not source_hashes:
        raise DriverError('reviewed source hashes required')
    for item in source_hashes:
        pinned(item['path'], item['sha256'])
    request = {'input': str(execution_apk), 'input_sha256': inputs[0]['sha256'],
               'bundle': str(bundle), 'bundle_sha256': inputs[1]['sha256'], 'patcher_version': '2.3.0',
               'patches': names, 'options': {}, 'assertion_class': assertion, 'assertion_sha256': assertion_hash,
               'identity': verified['expected'], 'output': str(out / 'runner-output')}
    if split:
        request.update(input_mode=mode, split_binding=binding, source_hashes=source_hashes)
    request_path = out / 'request.json'; write_json(request_path, request)
    request_record = record(request_path)
    unchanged([*inputs, *set_inputs, *staged, *tool_hashes, *source_hashes])
    run([tools['java'], '-Xmx2g', '-cp', classpath([runner, *deps['runtime']]), 'GenericPatchRunnerKt', request_path], out, timeout=300)
    report = read_json(out / 'runner-output/runner.json')
    if report.get('status') != 'applied_structurally_verified' or report.get('structural_assertions') != {'status': 'passed'}:
        raise DriverError('structural assertion success required')
    emitted = report.get('dex'); seen = set()
    if not isinstance(emitted, list) or not emitted:
        raise DriverError('complete emitted DEX list required')
    for item in emitted:
        name = item['name']; path = pinned(item['path'], item['sha256'])
        if not isinstance(name, str) or not DEX.fullmatch(name) or name in seen or path != out / 'runner-output/dex' / name:
            raise DriverError('unexpected emitted DEX')
        seen.add(name)
    canonical_dex(seen)
    dex_dir = out / 'runner-output/dex'
    if any(child.is_symlink() or not child.is_file() or child.name not in seen for child in dex_dir.iterdir()):
        raise DriverError('unexpected emitted output; only complete declared DEX files supported')
    if split:
        if (report.get('input_mode') != mode or report.get('split_binding') != binding
                or report.get('compatibility_mode') != 'APKM'
                or report.get('request_sha256') != request_record['sha256']):
            raise DriverError('runner whole-set/mode/request binding mismatch')
        if not binding['allow_dex_layout_change'] and set(topology['base_dex']) != seen:
            raise DriverError('emitted DEX layout change requires explicit opt-in')
    unchanged([*inputs, *set_inputs, *staged, *tool_hashes, *source_hashes, request_record])
    result = {'schema': 1, 'status': 'applied_structurally_verified', 'input': inputs[0], 'bundle': inputs[1],
              'patcher_version': '2.3.0', 'patches': names, 'options': {}, 'dex': emitted,
              'structural_assertions': {'status': 'passed', 'class': assertion, 'sha256': assertion_hash},
              'source_hashes': source_hashes, 'tool_hashes': tool_hashes,
              'verification': record(out / 'verified-input.json'),
              'note': 'Non-installable DEX output; JVM bundle is not an Android MPP/Manager artifact.'}
    if split:
        result.update(schema=2, input_mode=mode, split_binding=binding,
                      compatibility_mode='APKM', request=request_record,
                      staged_verification=record(out / 'verified-staged.json'),
                      note='Base-only DEX output; full selected APKM set bound. Pathname races and JNI/resource runtime compatibility are not proven.')
    write_json(out / 'apply.json', result)
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['fixture-build', 'patch-build', 'apply'])
    parser.add_argument('--config', type=Path, required=True, help='Reviewed JSON configuration; no secrets')
    args = parser.parse_args(argv)
    try:
        config = read_json(file_path(args.config))
        functions = {'fixture-build': fixture_build, 'patch-build': patch_build, 'apply': apply}
        result = functions[args.command](config)
        print(json.dumps(result, indent=2))
        return 0
    except (DriverError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.SubprocessError):
        print('patchdev: stage failed; check explicit prerequisites, pins, scope and trusted sources', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
