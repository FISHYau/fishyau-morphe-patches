"""Repeatable self-authored fixture smoke; no vendor apps, downloads or Git.

Explicit --allow-fixture-key permits a NEW disposable local signing identity.
--devices additionally creates/stops TWO NEW owned AVDs, never existing runs.
Generated keys, APKs, private screenshots and other evidence stay external.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent


def sibling(stem):
    name = '_fixture_smoke_' + stem
    spec = importlib.util.spec_from_file_location(name, HERE / (stem + '.py'))
    if spec is None or spec.loader is None:
        raise RuntimeError('required sibling missing')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def save(path, value):
    with Path(path).open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def device_flow(emulator, sdk, jdk, run, apk, verification, expected):
    """Use existing ownership guards, not another ADB/server implementation."""
    instance = emulator.Emulator(str(sdk), str(run))
    instance.env['JAVA_HOME'] = str(jdk)
    instance.create('system-images;android-30;google_apis;x86_64')
    evidence = {'apk': str(apk), 'expected_label': expected, 'run': str(run)}
    try:
        with emulator.locked(instance.run):
            instance.load()
            evidence['boot'] = instance.start(180, 'swiftshader_indirect')
            evidence['install'] = instance.install([str(apk)], verification)
            evidence['launch'] = instance.launch('dev.morphe.fixture', None)
            initial = instance.capture('dump', label='before')
            content = Path(initial['path']).read_bytes()
            if len(content) > 4 * 1024 * 1024 or b'<!' in content:
                raise RuntimeError('unexpected fixture hierarchy')
            tree = ET.fromstring(content)
            buttons = [node for node in tree.iter('node') if node.get('text') == 'SHOW LABEL'
                       or node.get('text') == 'Show label']
            if len(buttons) != 1:
                raise RuntimeError('fixture button did not resolve exactly once')
            match = re.fullmatch(r'\[(\d+),(\d+)\]\[(\d+),(\d+)\]', buttons[0].get('bounds', ''))
            if not match:
                raise RuntimeError('invalid fixture button bounds')
            x1, y1, x2, y2 = map(int, match.groups())
            if not (0 <= x1 < x2 <= 32767 and 0 <= y1 < y2 <= 32767):
                raise RuntimeError('invalid fixture button bounds')
            instance.adb(['shell', 'input', 'tap', str((x1 + x2) // 2), str((y1 + y2) // 2)])
            final = instance.capture('dump', label='after')
            content = Path(final['path']).read_bytes()
            if len(content) > 4 * 1024 * 1024 or b'<!' in content:
                raise RuntimeError('unexpected fixture hierarchy')
            texts = [node.get('text') for node in ET.fromstring(content).iter('node')]
            if expected not in texts:
                raise RuntimeError('intended fixture UI label not observed')
            wrong = 'PATCHED' if expected == 'BASELINE' else 'BASELINE'
            if wrong in texts:
                raise RuntimeError('unexpected baseline/patched label observed')
            evidence.update(before=initial, after=final,
                            screenshot=instance.capture('screenshot', label='feature'),
                            logcat=instance.capture('logcat', 200, 'feature'),
                            ui_assertion='passed', visual_review='pending_explicit_image_inspection')
    finally:
        if instance.state and instance.state.get('status') in ('starting', 'running', 'stopping'):
            with emulator.locked(instance.run):
                instance.load()
                evidence['stop'] = instance.stop(60)
    save(run / 'fixture-flow.json', evidence)
    return evidence


def run_smoke(args):
    driver, patchdev, lab, assembly, signing = [sibling(name) for name in
                                              ('driver', 'patchdev', 'lab', 'assembly', 'fixture_signing')]
    out = driver.external_output(Path(args.out))
    if not Path(args.out).is_absolute():
        raise RuntimeError('absolute NEW external output required')
    out.mkdir(parents=True, exist_ok=False)
    jdk, sdk, cache, jadx = [Path(value).resolve(strict=True) for value in
                            (args.jdk, args.sdk, args.cache_root, args.jadx_jar)]
    tools = sdk / 'build-tools/36.0.0'
    suffix = '.exe' if os.name == 'nt' else ''
    deps = patchdev.closure(str(cache))
    paths = {name: jdk / 'bin' / (name + suffix) for name in ('java', 'javac', 'jar')}
    paths.update(aapt2=tools / ('aapt2' + suffix), zipalign=tools / ('zipalign' + suffix),
                 apksigner_jar=tools / 'lib/apksigner.jar', d8_jar=tools / 'lib/d8.jar',
                 android_jar=sdk / 'platforms/android-36/android.jar', jadx_jar=jadx,
                 build_tools_properties=tools / 'source.properties',
                 platform_properties=sdk / 'platforms/android-36/source.properties')
    tool_config = {'schema': 1, **{name: patchdev.record(path) for name, path in paths.items()},
                   'dex_classpath': [patchdev.record(p) for p in deps['runtime']],
                   'runtime_classpath': [patchdev.record(p) for p in deps['runtime']],
                   'compiler_classpath': [patchdev.record(p) for p in deps['compiler']]}
    save(out / 'tools.json', tool_config)
    preflight = lab.preflight(out / 'tools.json', out / 'preflight')
    if preflight['status'] != 'preflight_checks_passed':
        raise RuntimeError('explicit installed prerequisite preflight blocked')
    fixture = patchdev.fixture_build({'jdk': str(jdk), 'sdk': str(sdk), 'out': str(out / 'fixture')})
    unsigned = Path(fixture['apk']['path'])
    source = Path(fixture['trusted_source'])
    java = jdk / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
    aapt = tools / ('aapt2.exe' if os.name == 'nt' else 'aapt2')
    zipalign = tools / ('zipalign.exe' if os.name == 'nt' else 'zipalign')
    signer = tools / 'lib/apksigner.jar'
    original_dir = out / 'original'; original_dir.mkdir()
    aligned, original = original_dir / 'aligned.apk', original_dir / 'signed.apk'
    driver.run_tool([str(zipalign), '-P', '16', '4', str(unsigned), str(aligned)])
    with signing.fixture_key(jdk, out / 'fixture-signing') as key:
        driver.run_tool([str(java), '-jar', str(signer), 'sign', '--ks', key['keystore'],
                         '--ks-key-alias', key['key_alias'], '--ks-pass', 'env:' + key['ks_pass_env'],
                         '--v1-signing-enabled', 'true', '--v2-signing-enabled', 'true',
                         '--v3-signing-enabled', 'false', '--v4-signing-enabled', 'false',
                         '--out', str(original), str(aligned)])
        driver.run_tool([str(zipalign), '-c', '-P', '16', '4', str(original)])
        verification = dict(aapt2=str(aapt), java=str(java), signer_jar=signer,
                            expect_package='dev.morphe.fixture', expect_version_code='1',
                            expect_version_name='1.0', expect_signer=[key['certificate_sha256']],
                            abi='none', density='nodpi', language=['none'])
        baseline = driver.verify_apks([original], out=out / 'original-verification.json', **verification)
        lab.init_lab(original, driver._hash_file(original), 'Change fixture label BASELINE to PATCHED', out / 'lab')
        lab.discover(original, driver._hash_file(original), jadx, str(java), out / 'discovery', 'BASELINE',
                     jadx_sha256=driver._hash_file(jadx))
        deps = patchdev.closure(str(cache))
        driver.dex(original, 'Ldev/morphe/fixture/MainActivity;->label()Ljava/lang/String;', str(java),
                   patchdev.classpath(deps['runtime']), out / 'original-method.txt')
        built = patchdev.patch_build(dict(jdk=str(jdk), cache_root=str(cache), out=str(out / 'patch'),
                                         trusted_code=True, assertion_class='FixtureAssertions',
                                         test_class='FixtureTests',
                                         sources=[str(source / 'FixturePatch.kt'), str(source / 'FixtureAssertions.kt')],
                                         tests=[str(source / 'FixtureTests.kt')]))
        applied = patchdev.apply(dict(jdk=str(jdk), cache_root=str(cache), out=str(out / 'apply'),
                                      trusted_code=True, patcher_version='2.3.0', patches=['Fixture label'], options={},
                                      apks=[{'path': str(original), 'sha256': driver._hash_file(original)}],
                                      bundle=built['bundle'], runner=built['runner'],
                                      assertion_class=built['assertion_class'], assertion_sha256=built['assertion_sha256'],
                                      source_hashes=built['source_hashes'], verification=verification))
        apply_report = out / 'apply/apply.json'
        assembled = assembly.assemble(apks=[original], apply_report=apply_report,
                                      expect_apply_sha256=driver._hash_file(apply_report), reviewed_apply=True,
                                      allow_dex_layout_change=True, out=out / 'assembly', zipalign=str(zipalign),
                                      final_signer_sha256=key['certificate_sha256'], keystore=Path(key['keystore']),
                                      ks_pass_env=key['ks_pass_env'], key_alias=key['key_alias'], **verification)
        patched = Path(assembled['outputs']['signed']['path'])
        driver.dex(patched, 'Ldev/morphe/fixture/MainActivity;->label()Ljava/lang/String;', str(java),
                   patchdev.classpath(deps['runtime']), out / 'patched-method.txt')
    # Signing password has left the environment before any emulator is constructed.
    result = {'schema': 1, 'status': 'fixture_patch_assembled_verified',
              'original': {'path': str(original), 'sha256': driver._hash_file(original)},
              'patched': {'path': str(patched), 'sha256': driver._hash_file(patched)},
              'signer_sha256': verification['expect_signer'][0],
              'build': str(out / 'patch/build.json'), 'apply': str(apply_report),
              'assembly': str(out / 'assembly/assembly.json'),
              'fixture': str(out / 'fixture/fixture.json'),
              'note': 'Development JVM bundle; no Android MPP, Manager import or vendor-app verification.'}
    if args.devices:
        emulator = sibling('emulator')
        result['baseline_device'] = device_flow(emulator, sdk, jdk, out / 'baseline-emulator', original, verification, 'BASELINE')
        result['patched_device'] = device_flow(emulator, sdk, jdk, out / 'patched-emulator', patched, verification, 'PATCHED')
        result['status'] = 'fixture_patch_ui_asserted_both_owned_stops_confirmed'
        result['visual_review'] = 'pending_explicit_image_inspection'
    save(out / 'smoke.json', result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for flag in ('jdk', 'sdk', 'cache-root', 'jadx-jar', 'out'):
        parser.add_argument('--' + flag, required=True)
    parser.add_argument('--allow-fixture-key', required=True, action='store_true',
                        help='Authorize NEW disposable fixture-only signing material')
    parser.add_argument('--devices', action='store_true', help='Authorize TWO NEW owned fixture AVD runs and stops')
    args = parser.parse_args(argv)
    try:
        result = run_smoke(args)
        print(json.dumps({'status': result['status'], 'evidence': str(Path(args.out) / 'smoke.json')}))
        return 0
    except Exception:
        # No environment, signing passwords, private key bytes, or tool streams.
        print('Fixture smoke failed; partial evidence is not success. Check the bounded stage prerequisites.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
