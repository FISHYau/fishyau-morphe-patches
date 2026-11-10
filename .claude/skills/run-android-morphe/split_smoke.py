"""Self-authored real configuration-split recipe; never a vendor APK converter.

build: unsigned binary-manifest/resource/JNI fixture only (no keys/devices).
assemble: build, actual patch-build/apply, APK-only negative, all-member signing.
devices: separate fresh owned baseline/patched runs from a pinned smoke report.
All outputs are NEW/external. Supply installed JDK21/SDK36/NDK r27d/cache paths.
No downloads, licenses, existing keys, global ADB or cleanup. Screenshot review
is ALWAYS pending a separate explicit Read inspection. JVM bundle is not MPP.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import sys
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
SOURCE = HERE / 'fixture/split'
PACKAGE = 'dev.morphe.splitfixture'
SELECTOR = 'Ldev/morphe/splitfixture/MainActivity;->label()Ljava/lang/String;'
ABIS = {'x86_64': 'x86_64-linux-android27', 'arm64-v8a': 'aarch64-linux-android27'}
IMAGE = 'system-images;android-30;google_apis;x86_64'
CONFIRMED = 'process_exited_and_both_owned_ports_released'


def sibling(stem):
    name = '_split_smoke_' + stem
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, HERE / (stem + '.py'))
    if spec is None or spec.loader is None:
        raise RuntimeError('required trusted sibling missing')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


@contextmanager
def stage(out, name):
    """Append-only progress; failure never creates an aggregate success record."""
    save(out / (name + '-entered.json'), {'stage': name, 'status': 'entered'})
    try:
        yield
    except BaseException:
        save(out / (name + '-failed.json'), {'stage': name, 'status': 'failed',
             'note': 'Partial outputs are not success; do not reuse this output.'})
        raise
    else:
        save(out / (name + '-completed.json'), {'stage': name, 'status': 'completed'})


def chosen_abis(values):
    values = values or list(ABIS)
    require(values and len(values) == len(set(values)) and all(v in ABIS for v in values),
            'unique supported explicit ABIs required')
    return values


def installed(p, args, work):
    """Explicit paths only; no search, provisioning or environment inspection."""
    jdk, sdk, ndk, cache = [p.absolute(value).resolve(strict=True) for value in
                           (args.jdk, args.sdk, args.ndk, args.cache_root)]
    tools = p.jdk({'jdk': str(jdk)}, work)
    build = sdk / 'build-tools/36.0.0'
    suffix = '.exe' if os.name == 'nt' else ''
    tools.update(aapt2=p.file_path(build / ('aapt2' + suffix)),
                 zipalign=p.file_path(build / ('zipalign' + suffix)),
                 signer_jar=p.file_path(build / 'lib/apksigner.jar'),
                 d8_jar=p.file_path(build / 'lib/d8.jar'),
                 android_jar=p.file_path(sdk / 'platforms/android-36/android.jar'))
    # The authorized tool distribution is the installed Windows NDK r27d.
    llvm = ndk / 'toolchains/llvm/prebuilt/windows-x86_64'
    tools.update(clang=p.file_path(llvm / 'bin/clang.exe'),
                 lld=p.file_path(llvm / 'bin/ld.lld.exe'),
                 jni_header=p.file_path(llvm / 'sysroot/usr/include/jni.h'))
    props = [(build / 'source.properties', r'Pkg.Revision\s*=\s*36\.0\.0'),
             (sdk / 'platforms/android-36/source.properties', r'AndroidVersion.ApiLevel\s*=\s*36'),
             (ndk / 'source.properties', r'Pkg.Revision\s*=\s*27\.3\.13750724')]
    for index, (path, expected) in enumerate(props):
        require(path.stat().st_size <= 65536 and re.search(r'(?m)^' + expected + r'\s*$',
                path.read_text(encoding='utf-8')), 'installed SDK36/NDK r27d identity mismatch')
        tools['properties_' + str(index)] = path
    deps = p.closure(str(cache))
    pins = [p.record(path) for path in [*tools.values(), *deps['runtime'], *deps['compiler']]]
    save(work.parent / 'tools.json', {'schema': 1, 'tools': {k: p.record(v) for k, v in tools.items()},
         'pins': pins, 'ndk_revision': '27.3.13750724', 'sysroot': str(llvm / 'sysroot')})
    version = p.run([tools['clang'], '--version'], work)
    require('clang version' in version.lower(), 'NDK Clang version probe failed')
    (work.parent / 'clang-version.txt').write_text(version, encoding='utf-8')
    return tools, deps, pins, llvm / 'sysroot'


def check_unsigned(d, path, aapt2, *, role, abi=None):
    """Inspect actual compiled binary XML/table/ELF and policy, not source XML."""
    inventory = d._apk_inventory(path, d.Budget(), str(aapt2))
    raw, m = d._authoritative_manifest(path, str(aapt2))
    with zipfile.ZipFile(path) as apk:
        require(apk.read('AndroidManifest.xml')[:4] == b'\x03\x00\x08\x00', 'binary XML manifest required')
        if role in ('base', 'resource'):
            require(apk.read('resources.arsc')[:2] == b'\x02\x00', 'binary resource table required')
    require(m['package'] == PACKAGE and m['version_code'] == '1' and m['min_sdk'] == 27 and
            m['extract_native_libs'] is False, 'compiled fixture identity/SDK/native policy mismatch')
    if role == 'base':
        require(m['version_name'] == '1.0' and m['split'] is None and m['has_code'] is True and
                set(m['required_split_types']) == {'base__abi', 'base__density'} and m['is_split_required'] is True,
                'compiled base declarations mismatch')
        require(inventory['dex'] == ['classes.dex'] and not inventory['native_libraries'], 'base payload mismatch')
    else:
        require(m['version_name'] is None and m['has_code'] is False and not inventory['dex_payloads'] and
                m['config_for_split'] is None and m['is_feature_split'] is False, 'compiled companion declarations mismatch')
        kind = 'base__abi' if role == 'native' else 'base__density'
        require(m['split_types'] == [kind] and m['split'] == ('config.' + abi.replace('-', '_') if abi else 'config.xhdpi'),
                'compiled companion split/type mismatch')
        if role == 'native':
            require(len(inventory['native_libraries']) == 1 and inventory['native_abis'] == [abi], 'native payload mismatch')
            inventory['native_libraries'] = d._verify_native_libraries(
                inventory['native_libraries'], abi=abi, extract_native_libs=False)
            require(all(lib['data_offset'] % 16384 == 0 for lib in inventory['native_libraries']), '16-KiB ZIP alignment required')
        else:
            require(not inventory['native_libraries'], 'resource split must not contain native code')
    return {'manifest_declarations': m, 'raw_manifest': raw, 'inventory': inventory}


def build_fixture(args, out):
    p, d = sibling('patchdev'), sibling('driver')
    work = out / 'tool-state'; work.mkdir()
    data = out / 'data'; data.mkdir()
    with stage(out, '01-prerequisites'):
        tools, deps, tool_pins, sysroot = installed(p, args, work)
        originals = sorted(path for path in SOURCE.rglob('*') if path.is_file())
        require(originals and not any(path.is_symlink() for path in SOURCE.rglob('*')), 'regular reviewed fixture sources required')
        source_pins = [p.record(path) for path in originals]
        source = out / 'source'
        shutil.copytree(SOURCE, source)
        copied_pins = [p.record(source / path.relative_to(SOURCE)) for path in originals]
        require([v['sha256'] for v in source_pins] == [v['sha256'] for v in copied_pins], 'source copy mismatch')
        save(out / 'sources.json', {'originals': source_pins, 'staged': copied_pins})
    with stage(out, '02-code-resources'):
        classes, dex = data / 'classes', data / 'dex'
        classes.mkdir(); dex.mkdir()
        p.run([tools['javac'], '-g:none', '-source', '8', '-target', '8', '-bootclasspath', tools['android_jar'],
               '-d', classes, source / 'base/MainActivity.java'], work)
        jar = data / 'app-classes.jar'
        with zipfile.ZipFile(jar, 'x') as archive:
            for path in sorted(classes.rglob('*.class')):
                archive.write(path, path.relative_to(classes).as_posix())
        p.run([tools['java'], '-Xmx1g', '-cp', tools['d8_jar'], 'com.android.tools.r8.D8', '--release',
               '--min-api', '27', '--lib', tools['android_jar'], '--output', dex, jar], work)
        require([v.name for v in dex.iterdir()] == ['classes.dex'], 'fixture must start with one canonical DEX')
        for role in ('base', 'resource'):
            p.run([tools['aapt2'], 'compile', '--dir', source / role / 'res', '-o', data / (role + '-res.zip')], work)
        base_raw, resource_raw = data / 'base-raw.apk', data / 'resource-raw.apk'
        ids = data / 'stable-ids.txt'
        link = [tools['aapt2'], 'link', '-I', tools['android_jar'], '--min-sdk-version', '27',
                '--target-sdk-version', '30', '--no-auto-version']
        p.run([*link, '--manifest', source / 'base/AndroidManifest.xml', '--emit-ids', ids,
               '-o', base_raw, data / 'base-res.zip'], work)
        with zipfile.ZipFile(base_raw, 'a', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.write(dex / 'classes.dex', 'classes.dex')
        # Independent binary-manifest config link; stable IDs preserve base package
        # resource IDs. No resource rewriting, XML-in-ZIP or fake ELF placeholders.
        p.run([*link, '--manifest', source / 'resource/AndroidManifest.xml', '--stable-ids', ids,
               '-o', resource_raw, data / 'resource-res.zip'], work)
        probe_ids = []
        for role, apk, marker in [('base', base_raw, 'SPLIT_RESOURCE_MISSING'),
                                  ('resource', resource_raw, 'SPLIT_RESOURCE_OK')]:
            dump = p.run([tools['aapt2'], 'dump', 'resources', apk], work)
            (data / (role + '-resources.txt')).write_text(dump, encoding='utf-8')
            matches = re.findall(r'(?m)^\s*resource (0x[0-9a-fA-F]+) (?:[^\s:]+:)?string/split_probe\b', dump)
            require(len(matches) == 1 and marker in dump, 'compiled resource probe missing or ambiguous')
            require(('SPLIT_RESOURCE_OK' not in dump) if role == 'base' else ('SPLIT_RESOURCE_MISSING' not in dump),
                    'success resource value must live only in companion')
            probe_ids.append(matches[0].lower())
        require(probe_ids[0] == probe_ids[1], 'base and config resource IDs differ')
    variants = []
    with stage(out, '03-native-packaging'):
        base, resource = data / 'base.apk', data / 'config.xhdpi.apk'
        for raw, aligned in ((base_raw, base), (resource_raw, resource)):
            p.run([tools['zipalign'], '-P', '16', '4', raw, aligned], work)
        base_check = check_unsigned(d, base, tools['aapt2'], role='base')
        res_check = check_unsigned(d, resource, tools['aapt2'], role='resource')
        for abi in chosen_abis(args.abi):
            target = data / abi; target.mkdir()
            manifest = target / 'AndroidManifest.xml'
            manifest.write_text((source / 'native/AndroidManifest.xml.in').read_text(encoding='utf-8').replace(
                '@SPLIT_ABI@', abi.replace('-', '_')), encoding='utf-8')
            library = target / 'libsplitprobe.so'
            p.run([tools['clang'], '--target=' + ABIS[abi], '--sysroot=' + str(sysroot), '-shared', '-fPIC',
                   '-O2', '-Wall', '-Wextra', '-Werror', '-Wl,--no-undefined', '-Wl,-z,max-page-size=16384',
                   '-Wl,-z,common-page-size=16384', '-Wl,-soname,libsplitprobe.so',
                   source / 'native/splitprobe.c', '-o', library], work)
            raw, native = target / 'native-raw.apk', target / 'config.native.apk'
            p.run([*link, '--manifest', manifest, '-o', raw], work)
            with zipfile.ZipFile(raw, 'a') as archive:
                archive.write(library, 'lib/' + abi + '/libsplitprobe.so', compress_type=zipfile.ZIP_STORED)
            p.run([tools['zipalign'], '-P', '16', '4', raw, native], work)
            native_check = check_unsigned(d, native, tools['aapt2'], role='native', abi=abi)
            variants.append({'abi': abi, 'apks': [p.record(v) for v in (base, resource, native)],
                             'compiled_checks': [base_check, res_check, native_check]})
            save(out / ('unsigned-' + abi + '.json'), variants[-1])
    p.unchanged([*source_pins, *copied_pins, *tool_pins])
    result = {'schema': 1, 'status': 'unsigned_real_split_fixture_built', 'variants': variants,
              'trusted_source': str(source), 'source_hashes': copied_pins, 'tool_hashes': tool_pins,
              'resource_id': probe_ids[0], 'note': 'Unsigned build only; no loader/signing/device/runtime proof.'}
    save(out / 'fixture.json', result)
    return result, tools, deps


def build_patch(p, args, source, out, negative=False):
    config = dict(trusted_code=True, jdk=args.jdk, cache_root=args.cache_root, out=str(out),
                  assertion_class='SplitAssertions', test_class='SplitTests',
                  sources=[str(source / 'patch' / ('ApkOnlyPatch.kt' if negative else 'SplitPatch.kt')),
                           str(source / 'patch/SplitAssertions.kt')], tests=[str(source / 'patch/SplitTests.kt')])
    save(out.parent / (out.name + '-config.json'), config)
    return p.patch_build(config)


def inspect_label(d, p, apk, tools, deps, out, expected):
    d.dex(apk, SELECTOR, str(tools['java']), p.classpath(deps['runtime']), out)
    text = out.read_text(encoding='utf-8')
    require(text.count('TARGET_COUNT 1 ' + SELECTOR) == 1 and 'registers=1 tries=0' in text,
            'final exact method count/body metadata mismatch')
    rows = [line.strip() for line in text.splitlines() if re.match(r'^[0-9a-f]{4} ', line)]
    require(len(rows) == 2 and re.fullmatch(r'0000\s+CONST_STRING\s+v0 ' + expected, rows[0]) and
            re.fullmatch(r'0002\s+RETURN_OBJECT\s+v0', rows[1]), 'exact DEX label delta mismatch')
    return p.record(out)


def apply_config(p, args, built, selected, container, verification, out):
    return dict(trusted_code=True, input_mode='base_config_set', logical_container={**p.record(container), 'type': 'APKM'},
                base={k: selected[0][k] for k in ('path', 'sha256')}, apks=selected,
                allow_dex_layout_change=args.allow_dex_layout_change, jdk=args.jdk, cache_root=args.cache_root,
                out=str(out), patcher_version='2.3.0', patches=['Split fixture label'], options={},
                bundle=built['bundle'], runner=built['runner'], assertion_class=built['assertion_class'],
                assertion_sha256=built['assertion_sha256'], source_hashes=built['source_hashes'],
                verification={k: str(v) if isinstance(v, Path) else v for k, v in verification.items() if k != 'java'})


def negative_definition(p, d, args, config, tools, deps, out):
    """A generic failure is not proof: require actual runner definition-phase text."""
    config = dict(config, patches=['APK-only negative'])
    save(out.parent / (out.name + '-config.json'), config)
    try:
        p.apply(config)
    except p.DriverError:
        pass
    else:
        raise RuntimeError('APK-only definition was accepted in split mode')
    request = out / 'request.json'
    require(request.is_file() and (out / 'verified-staged.json').is_file() and
            not (out / 'apply.json').exists() and not (out / 'runner-output/runner.json').exists(),
            'negative failed before actual-loader evidence was available')
    proof = out.parent / (out.name + '-definition-proof'); proof.mkdir()
    # The failed runner already created its output directory. Preserve it and
    # replay into a NEW output, changing ONLY that path in the generated request.
    # Binding, selected bytes, source hashes and negative bundle remain unchanged.
    replay = p.read_json(request)
    replay['output'] = str(proof / 'runner-output')
    replay_path = proof / 'request.json'
    save(replay_path, replay)
    try:
        d.run_tool([str(tools['java']), '-Xmx2g', '-cp', p.classpath([Path(config['runner']['path']), *deps['runtime']]),
                    'GenericPatchRunnerKt', str(replay_path)], timeout=300, log_dir=proof)
    except d.DriverError:
        pass
    else:
        raise RuntimeError('negative runner unexpectedly succeeded')
    stderr = (proof / 'build.stderr.log').read_text(encoding='utf-8').strip()
    require(stderr == 'patch application or structural verification failed at definition preflight' and
            not (out / 'runner-output/dex').exists() and not (out / 'apply.json').exists() and
            not (proof / 'runner-output/dex').exists() and not (proof / 'runner-output/runner.json').exists(),
            'APK-only negative did not fail specifically at definition preflight')
    result = {'status': 'actual_loader_rejected_apk_only_at_definition_preflight',
              'request': p.record(request), 'replay_request': p.record(replay_path),
              'stderr': p.record(proof / 'build.stderr.log'),
              'note': 'A failed or missing tool is NOT a passing compatibility negative.'}
    save(proof / 'negative.json', result)
    return result


def assemble_fixture(args, out):
    require(args.allow_fixture_key is True, 'runtime fresh fixture signing opt-in required')
    p, d, assembly, signing = [sibling(v) for v in ('patchdev', 'driver', 'assembly', 'fixture_signing')]
    build_out = out / 'build'; build_out.mkdir()
    fixture, tools, deps = build_fixture(args, build_out)
    with stage(out, '04-patch-build'):
        source = Path(fixture['trusted_source'])
        positive = build_patch(p, args, source, out / 'patch')
        negative = build_patch(p, args, source, out / 'apk-only-patch', negative=True)
    variants = []
    with stage(out, '05-sign-apply-assemble'):
        with signing.fixture_key(Path(args.jdk), out / 'fixture-signing') as key:
            for variant in fixture['variants']:
                abi = variant['abi']; directory = out / abi; directory.mkdir()
                original_dir = directory / 'original'; original_dir.mkdir()
                originals = []
                for index, record in enumerate(variant['apks']):
                    unsigned = p.pinned(record['path'], record['sha256'])
                    signed = original_dir / ('member-' + str(index) + '.apk')
                    d.run_tool([str(tools['java']), '-jar', str(tools['signer_jar']), 'sign', '--ks', key['keystore'],
                                '--ks-key-alias', key['key_alias'], '--ks-pass', 'env:' + key['ks_pass_env'],
                                '--v1-signing-enabled', 'false', '--v2-signing-enabled', 'true',
                                '--v3-signing-enabled', 'false', '--v4-signing-enabled', 'false',
                                '--out', str(signed), str(unsigned)])
                    d.run_tool([str(tools['zipalign']), '-c', '-P', '16', '4', str(signed)])
                    originals.append(signed)
                    save(directory / ('signed-original-' + str(index) + '.json'), p.record(signed))
                verification = dict(aapt2=str(tools['aapt2']), java=str(tools['java']), signer_jar=str(tools['signer_jar']),
                                    expect_package=PACKAGE, expect_version_code='1', expect_version_name='1.0',
                                    expect_signer=[key['certificate_sha256']], abi=abi, density='xhdpi', language=['none'])
                d.verify_apks(originals, out=directory / 'original-verification.json', **verification)
                container = directory / 'original.apkm'
                names = ['base.apk', 'splits/config.xhdpi.apk', 'splits/config.' + abi + '.apk']
                with zipfile.ZipFile(container, 'x', compression=zipfile.ZIP_STORED) as archive:
                    for path, name in zip(originals, names):
                        archive.write(path, name)
                selected = [{**p.record(path), 'archive_member': name} for path, name in zip(originals, names)]
                baseline_dex = inspect_label(d, p, originals[0], tools, deps, directory / 'baseline-method.txt', 'BASELINE')
                bad_config = apply_config(p, args, negative, selected, container, verification, directory / 'negative-apply')
                negative_result = negative_definition(p, d, args, bad_config, tools, deps, directory / 'negative-apply')
                config = apply_config(p, args, positive, selected, container, verification, directory / 'apply')
                save(directory / 'apply-config.json', config)
                p.apply(config)
                apply_path = directory / 'apply/apply.json'
                assembled = assembly.assemble(input_mode='base_config_set', apks=originals, apply_report=apply_path,
                    expect_apply_sha256=d._hash_file(apply_path), reviewed_apply=True,
                    allow_dex_layout_change=args.allow_dex_layout_change, out=directory / 'assembly',
                    zipalign=str(tools['zipalign']), final_signer_sha256=key['certificate_sha256'],
                    keystore=Path(key['keystore']), key_alias=key['key_alias'], ks_pass_env=key['ks_pass_env'], **verification)
                patched = [item['outputs']['signed'] for item in assembled['members']]
                require(len(patched) == 3 and [m['role'] for m in assembled['members']] == ['base', 'base_config', 'base_config'],
                        'all three ordered members must be assembled')
                final_dex = inspect_label(d, p, Path(patched[0]['path']), tools, deps, directory / 'patched-method.txt', 'PATCHED')
                item = {'abi': abi, 'verification': verification, 'originals': [p.record(v) for v in originals],
                        'patched': patched, 'container': p.record(container), 'negative': negative_result,
                        'baseline_dex': baseline_dex, 'patched_dex': final_dex,
                        'apply': p.record(apply_path), 'assembly': p.record(directory / 'assembly/assembly.json')}
                variants.append(item)
                save(directory / 'variant.json', item)
    # No signing context/password is retained or recreated for device operations.
    result = {'schema': 1, 'status': 'real_split_fixture_assembled_verified', 'variants': variants,
              'fixture': p.record(build_out / 'fixture.json'), 'visual_review': 'not_run',
              'limits': 'Self-authored base-only bytecode fixture, not vendor/MPP/universal support. '
                        'No resource/JNI/installation/ARM-translation runtime claim without separate device evidence.'}
    save(out / 'smoke.json', result)
    return result


def hierarchy(path):
    path = Path(path)
    require(path.stat().st_size <= 4 * 1024 * 1024, 'hierarchy byte limit exceeded')
    data = path.read_bytes()
    require(b'<!' not in data, 'hierarchy declarations forbidden')
    return ET.fromstring(data)


def assert_ui(tree, expected, abi):
    texts = [node.get('text', '') for node in tree.iter('node')]
    require(expected in ('BASELINE', 'PATCHED') and abi in ABIS, 'invalid UI expectation')
    required = [expected, 'SPLIT_RESOURCE_OK', 'JNI_OK_' + abi]
    require(all(texts.count(value) == 1 for value in required), 'exact label/resource/ABI JNI UI evidence missing')
    wrong = 'PATCHED' if expected == 'BASELINE' else 'BASELINE'
    require(wrong not in texts and not any(value in texts for value in
            ('SPLIT_RESOURCE_MISSING', 'RESOURCE_ID_MISSING', 'RESOURCE_ERROR', 'JNI_ERROR',
             'NOT_RUN', 'RESOURCE_NOT_RUN', 'JNI_NOT_RUN')) and
            not any(value.startswith('JNI_OK_') and value != 'JNI_OK_' + abi for value in texts),
            'fallback, error, wrong label or wrong JNI ABI observed')


@contextmanager
def device_stage(evidence, name):
    """Bounded private device diagnostics, never environment/argv/traceback dumps.

    Keep the first failure AND later stop failure: cleanup must not erase the
    original stage/error. Tool details here are private device diagnostics only;
    build/signing stages deliberately keep their existing generic failure record.
    """
    item = {'stage': name, 'status': 'entered'}
    evidence.setdefault('stages', []).append(item)
    try:
        yield
    except BaseException as exc:
        item.update(status='failed', error={'type': type(exc).__name__[:128],
                                           'detail': str(exc)[-4096:]})
        evidence.setdefault('failure', item.copy())
        raise
    else:
        item['status'] = 'completed'


def device_flow(emulator, sdk, jdk, run, apks, verification, expected, abi):
    """Only the existing guarded owned API; persist failures and stop in finally."""
    instance = emulator.Emulator(str(sdk), str(run))
    instance.env['JAVA_HOME'] = str(jdk)
    evidence = {'status': 'incomplete', 'expected': expected, 'abi': abi, 'run': str(run),
                'apks': [str(v) for v in apks], 'visual_review': 'pending_explicit_image_inspection'}
    try:
        with device_stage(evidence, 'create'):
            instance.create(IMAGE)
        with device_stage(evidence, 'owned-session'), emulator.locked(instance.run):
            with device_stage(evidence, 'boot'):
                instance.load()
                evidence['boot'] = instance.start(180, 'swiftshader_indirect')
            # The resource is deliberately density-qualified. Establish xhdpi on
            # this NEW owned disposable device rather than depending on its skin
            # or claiming that a verifier selection changes Android configuration.
            with device_stage(evidence, 'density'):
                instance.adb(['shell', 'wm', 'density', '320'])
                density = instance.adb(['shell', 'wm', 'density'])
                physical = re.findall(r'(?m)^Physical density: ([0-9]+)[ \t]*\r?$', density)
                override = re.findall(r'(?m)^Override density: ([0-9]+)[ \t]*\r?$', density)
                require(len(physical) == 1 and len(override) <= 1 and (override or physical) == ['320'],
                        'owned fixture device did not establish xhdpi density')
                evidence['density'] = {'requested_dpi': 320, 'wm_output': density, 'effective_dpi': 320}
            with device_stage(evidence, 'install'):
                evidence['install'] = instance.install([str(v) for v in apks], verification)
            with device_stage(evidence, 'launch'):
                evidence['launch'] = instance.launch(PACKAGE, None)
            with device_stage(evidence, 'dump-before'):
                evidence['before'] = instance.capture('dump', label='before')
            with device_stage(evidence, 'button'):
                tree = hierarchy(evidence['before']['path'])
                buttons = [node for node in tree.iter('node') if node.get('text') in ('SHOW LABEL', 'Show label')]
                require(len(buttons) == 1, 'exact fixture button missing')
                match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', buttons[0].get('bounds', ''))
                require(match is not None, 'invalid button bounds')
                x1, y1, x2, y2 = map(int, match.groups())
                require(0 <= x1 < x2 <= 32767 and 0 <= y1 < y2 <= 32767, 'invalid button bounds')
            with device_stage(evidence, 'tap'):
                instance.adb(['shell', 'input', 'tap', str((x1 + x2) // 2), str((y1 + y2) // 2)])
            with device_stage(evidence, 'dump-after'):
                evidence['after'] = instance.capture('dump', label='after')
            # Capture private failure evidence too, before the UI assertion.
            with device_stage(evidence, 'screenshot'):
                evidence['screenshot'] = instance.capture('screenshot', label='feature')
            with device_stage(evidence, 'logcat'):
                evidence['logcat'] = instance.capture('logcat', 300, 'feature')
            with device_stage(evidence, 'assert-ui'):
                assert_ui(hierarchy(evidence['after']['path']), expected, abi)
                evidence['ui_assertion'] = 'label_resource_and_real_jni_abi_observed'
    finally:
        try:
            if instance.state and instance.state.get('status') in ('starting', 'running', 'stopping'):
                with device_stage(evidence, 'stop'):
                    with emulator.locked(instance.run):
                        instance.load()
                        evidence['stop'] = instance.stop(60)
                    require(evidence['stop'].get('status') == 'stopped' and
                            evidence['stop'].get('confirmation') == CONFIRMED, 'owned stop unconfirmed')
                if evidence.get('ui_assertion') and not evidence.get('failure'):
                    evidence['status'] = 'ui_asserted_owned_stop_confirmed'
        finally:
            # create may fail before creating its run; never invent ownership.
            if run.is_dir():
                save(run / 'split-fixture-flow.json', evidence)
    require(evidence.get('ui_assertion') and evidence.get('stop', {}).get('confirmation') == CONFIRMED,
            'UI plus owned stop evidence required')
    return evidence


def run_devices(args, out):
    p, d, emulator = [sibling(v) for v in ('patchdev', 'driver', 'emulator')]
    report_path = p.pinned(args.report, args.expect_report_sha256)
    report = p.read_json(report_path)
    require(report.get('schema') == 1 and report.get('status') == 'real_split_fixture_assembled_verified',
            'pinned complete split smoke report required')
    sdk, jdk = p.absolute(args.sdk).resolve(strict=True), p.absolute(args.jdk).resolve(strict=True)
    suffix = '.exe' if os.name == 'nt' else ''
    # Bound the public tool/identity fields rather than accepting arbitrary package
    # or a signer/key override from a hand-edited report.
    expected_tools = {'java': str(jdk / 'bin' / ('java' + suffix)),
                      'aapt2': str(sdk / 'build-tools/36.0.0' / ('aapt2' + suffix)),
                      'signer_jar': str(sdk / 'build-tools/36.0.0/lib/apksigner.jar')}
    results = []
    variants = report.get('variants', [])
    require(isinstance(variants, list) and 1 <= len(variants) <= 2 and
            len({v['abi'] for v in variants}) == len(variants), 'invalid fixture variant list')
    requested = chosen_abis(args.abi) if args.abi else [v['abi'] for v in variants]
    for abi in requested:
        matches = [v for v in variants if v['abi'] == abi]
        require(len(matches) == 1, 'requested ABI not assembled')
        item = matches[0]; verification = item['verification']
        require(set(verification) == set(expected_tools) | {'expect_package', 'expect_version_code', 'expect_version_name',
                'expect_signer', 'abi', 'density', 'language'} and all(verification[k] == v for k, v in expected_tools.items()) and
                verification['expect_package'] == PACKAGE and verification['expect_version_code'] == '1' and
                verification['expect_version_name'] == '1.0' and verification['abi'] == abi and
                verification['density'] == 'xhdpi' and verification['language'] == ['none'], 'fixture verification contract mismatch')
        for role, expected in [('originals', 'BASELINE'), ('patched', 'PATCHED')]:
            records = item[role]
            require(len(records) == 3, 'complete selected fixture set required')
            paths = [p.pinned(v['path'], v['sha256']) for v in records]
            # Fresh owned runs SEQUENTIALLY. A failed/unconfirmed stop aborts the
            # recipe; never start the next session or perform global cleanup.
            flow = device_flow(emulator, sdk, jdk, out / (abi + '-' + expected.lower()), paths,
                               verification, expected, abi)
            results.append(flow)
            save(out / (abi + '-' + expected.lower() + '.json'), flow)
    p.pinned(report_path, args.expect_report_sha256)
    result = {'schema': 1, 'status': 'split_fixture_ui_asserted_owned_stops_confirmed', 'flows': results,
              'source_report': p.record(report_path), 'visual_review': 'pending_explicit_image_inspection',
              'limits': 'JNI_OK_arm64-v8a on this run proves only this fixture execution, not general ARM compatibility.'}
    save(out / 'devices.json', result)
    return result


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest='command', required=True)
    for command in ('build', 'assemble', 'devices'):
        cmd = sub.add_parser(command)
        for flag in ('jdk', 'sdk', 'out'):
            cmd.add_argument('--' + flag, required=True)
        cmd.add_argument('--abi', choices=tuple(ABIS), action='append', help='Repeat; default both for builds, report ABIs for devices')
        if command != 'devices':
            cmd.add_argument('--ndk', required=True, help='Explicit already installed Windows NDK r27d directory')
            cmd.add_argument('--cache-root', required=True, help='Existing pinned Kotlin2.4.21/Morphe2.3.0 closure')
            cmd.add_argument('--trusted-fixture-code', required=True, action='store_true', help='Reviewed self-authored source execution')
        else:
            cmd.add_argument('--report', required=True, help='Absolute completed smoke.json')
            cmd.add_argument('--expect-report-sha256', required=True)
        if command == 'assemble':
            cmd.add_argument('--allow-fixture-key', required=True, action='store_true', help='Runtime opt-in to NEW disposable fixture-only key')
            cmd.add_argument('--allow-dex-layout-change', action='store_true', help='Explicit complete canonical DEX redistribution opt-in for STRIP_SAFE')
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    out = None
    try:
        chosen_abis(args.abi)
        p = sibling('patchdev')
        out = p.fresh(args.out)
        save(out / 'recipe.json', {'schema': 1, 'operation': args.command, 'status': 'started',
                                 'recipe': p.record(Path(__file__)), 'runtime_proof': 'not_yet_established'})
        if args.command == 'build':
            result, _, _ = build_fixture(args, out)
        elif args.command == 'assemble':
            result = assemble_fixture(args, out)
        else:
            result = run_devices(args, out)
        print(json.dumps({'status': result['status'], 'evidence_directory': str(out)}))
        return 0
    except Exception:
        if out is not None:
            save(out / 'failure.json', {'status': 'failed', 'operation': args.command,
                 'note': 'Partial evidence only. Check per-stage records; no aggregate runtime/support claim.'})
        print('Split fixture recipe failed; partial outputs are not success. No raw tool/environment diagnostics emitted.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
