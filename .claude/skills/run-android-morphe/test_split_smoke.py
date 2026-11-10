"""Offline recipe/source regressions, NOT binary packaging/JNI/device evidence.

Run with py -I -B. Every subprocess entry is blocked. Tool/device flows below
use explicit synthetic files and mocks; signing helpers never run or see keys.
"""
from __future__ import annotations

from contextlib import contextmanager
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_test_split_smoke_module', HERE / 'split_smoke.py')
s = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = s
spec.loader.exec_module(s)
p, d = s.sibling('patchdev'), s.sibling('driver')


class Offline(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='morphe-split-smoke-offline-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        for name in ('Popen', 'run', 'call', 'check_call', 'check_output'):
            guard = mock.patch.object(subprocess, name, side_effect=AssertionError('Real subprocess forbidden'))
            guard.start(); self.addCleanup(guard.stop)

    def file(self, name, content=b'public synthetic test bytes'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def args(self, **kwargs):
        return SimpleNamespace(jdk=str(self.root / 'jdk'), sdk=str(self.root / 'sdk'), ndk=str(self.root / 'ndk'),
            cache_root=str(self.root / 'cache'), abi=kwargs.get('abi'), allow_fixture_key=True,
            allow_dex_layout_change=kwargs.get('allow_dex_layout_change', False))


class ContractTests(Offline):
    def cli(self, command, *extra):
        common = [command, '--jdk', str(self.root / 'jdk'), '--sdk', str(self.root / 'sdk'), '--out', str(self.root / 'out')]
        if command != 'devices':
            common += ['--ndk', str(self.root / 'ndk'), '--cache-root', str(self.root / 'cache'), '--trusted-fixture-code']
        return s.parser().parse_args([*common, *extra])

    def test_build_has_no_key_or_device_flag(self):
        args = self.cli('build')
        self.assertFalse(hasattr(args, 'allow_fixture_key'))
        self.assertFalse(hasattr(args, 'devices'))

    def test_assemble_requires_runtime_key_opt_in(self):
        with mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            self.cli('assemble')
        self.assertTrue(self.cli('assemble', '--allow-fixture-key').allow_fixture_key)

    def test_dex_redistribution_is_explicit(self):
        self.assertFalse(self.cli('assemble', '--allow-fixture-key').allow_dex_layout_change)
        self.assertTrue(self.cli('assemble', '--allow-fixture-key', '--allow-dex-layout-change').allow_dex_layout_change)

    def test_devices_requires_hash_and_report(self):
        with mock.patch('sys.stderr', new=io.StringIO()), self.assertRaises(SystemExit):
            self.cli('devices')
        args = self.cli('devices', '--report', str(self.root / 'smoke.json'), '--expect-report-sha256', 'a' * 64)
        self.assertFalse(hasattr(args, 'allow_fixture_key'))
        self.assertFalse(hasattr(args, 'ndk'))

    def test_abis_are_bounded_unique_and_explicit(self):
        self.assertEqual(s.chosen_abis(None), ['x86_64', 'arm64-v8a'])
        for value in (['x86_64', 'x86_64'], ['armeabi-v7a'], ['none']):
            with self.assertRaises(RuntimeError):
                s.chosen_abis(value)

    def test_all_manifests_declare_sdk27_nonextracting_and_no_companion_version(self):
        ns = '{http://schemas.android.com/apk/res/android}'
        for relative in ('base/AndroidManifest.xml', 'resource/AndroidManifest.xml', 'native/AndroidManifest.xml.in'):
            tree = ET.fromstring((s.SOURCE / relative).read_text(encoding='utf-8'))
            self.assertEqual(tree.find('uses-sdk').get(ns + 'minSdkVersion'), '27')
            self.assertEqual(tree.find('application').get(ns + 'extractNativeLibs'), 'false')
            if relative.startswith('base/'):
                self.assertEqual(tree.get(ns + 'requiredSplitTypes'), 'base__abi,base__density')
                self.assertEqual(tree.get(ns + 'versionName'), '1.0')
            else:
                self.assertNotIn(ns + 'versionName', tree.attrib)
                self.assertEqual(tree.find('application').get(ns + 'hasCode'), 'false')
                self.assertIsNone(tree.get('configForSplit'))

    def test_resource_success_is_not_a_base_code_or_fallback_constant(self):
        base = (s.SOURCE / 'base/MainActivity.java').read_text(encoding='utf-8')
        self.assertNotIn('SPLIT_RESOURCE_OK', base)
        self.assertNotIn('JNI_OK_', base)
        self.assertIn('getString(id)', base)
        self.assertIn('System.loadLibrary("splitprobe")', base)
        self.assertIn('nativeView.setText(nativeValue())', base)
        self.assertIn('SPLIT_RESOURCE_MISSING', (s.SOURCE / 'base/res/values/strings.xml').read_text())
        self.assertIn('SPLIT_RESOURCE_OK', (s.SOURCE / 'resource/res/values-xhdpi/strings.xml').read_text())

    def test_listener_avoids_android_bootclasspath_lambda_metafactory(self):
        # SDK36 android.jar lacks the JVM LambdaMetafactory.metafactory method;
        # real javac21 -source/-target 8 failed before emitting any class files.
        base = (s.SOURCE / 'base/MainActivity.java').read_text(encoding='utf-8')
        self.assertNotIn('->', base)
        self.assertIn('import android.view.View;', base)
        self.assertIn('new View.OnClickListener()', base)
        self.assertIn('@Override public void onClick(View view)', base)
        self.assertIn('public static String label() { return "BASELINE"; }', base)
        self.assertIn('labelView.setText(label())', base)

    def test_native_source_and_compatibility_definitions_are_separate(self):
        c = (s.SOURCE / 'native/splitprobe.c').read_text()
        self.assertIn('Java_dev_morphe_splitfixture_MainActivity_nativeValue', c)
        self.assertIn('__aarch64__', c); self.assertIn('__x86_64__', c)
        self.assertIn('NewStringUTF', c)
        positive = (s.SOURCE / 'patch/SplitPatch.kt').read_text()
        negative = (s.SOURCE / 'patch/ApkOnlyPatch.kt').read_text()
        self.assertIn('ApkFileType.APKM_REQUIRED', positive)
        self.assertIn('ApkFileType.APK,', negative)
        self.assertIn('APK_ONLY_EXECUTE_MUST_NOT_BE_REACHED', negative)
        self.assertIn('orEmpty().single()', positive)
        self.assertIn('instructions.size == 2', positive)

    def test_stage_failure_is_append_only_and_not_success(self):
        with self.assertRaises(RuntimeError):
            with s.stage(self.root, 'test'):
                raise RuntimeError('private diagnostics must not be copied')
        self.assertTrue((self.root / 'test-entered.json').exists())
        self.assertFalse((self.root / 'test-completed.json').exists())
        failure = (self.root / 'test-failed.json').read_text()
        self.assertNotIn('private diagnostics', failure)
        with self.assertRaises(FileExistsError):
            with s.stage(self.root, 'test'):
                pass

    def test_new_external_output_rejects_repo_or_reused(self):
        args = self.cli('build')
        out = self.root / 'existing'; out.mkdir()
        with mock.patch('sys.stderr', new=io.StringIO()), mock.patch.object(s, 'build_fixture') as build:
            self.assertEqual(s.main(['build', '--jdk', args.jdk, '--sdk', args.sdk, '--ndk', args.ndk,
                '--cache-root', args.cache_root, '--trusted-fixture-code', '--out', str(out)]), 1)
            build.assert_not_called()
        with self.assertRaises(p.DriverError):
            p.fresh(HERE / 'forbidden-generated-output')


class BuildTests(Offline):
    def build(self, abi=None, fail=None):
        out = self.root / 'build'; out.mkdir()
        tools = {k: self.file('tools/' + k) for k in ('java', 'javac', 'aapt2', 'zipalign', 'signer_jar', 'd8_jar', 'android_jar', 'clang')}
        calls = []

        def run(argv, cwd, **kwargs):
            argv = list(map(str, argv)); calls.append(argv)
            self.assertEqual(cwd, out / 'tool-state')
            if fail and fail in argv:
                raise p.DriverError('synthetic failure')
            if argv[0] == str(tools['javac']):
                target = Path(argv[argv.index('-d') + 1]) / 'dev/morphe/splitfixture'
                target.mkdir(parents=True)
                for name in ('MainActivity.class', 'MainActivity$1.class'):
                    (target / name).write_bytes(b'not actual bytecode')
            elif 'com.android.tools.r8.D8' in argv:
                (Path(argv[argv.index('--output') + 1]) / 'classes.dex').write_bytes(b'not actual dex')
            elif argv[0] == str(tools['clang']):
                Path(argv[argv.index('-o') + 1]).write_bytes(b'not actual ELF; mock only')
            elif 'link' in argv:
                target = Path(argv[argv.index('-o') + 1])
                with zipfile.ZipFile(target, 'x') as apk:
                    apk.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00mock-binary')
                    apk.writestr('resources.arsc', b'\x02\x00mock-table')
                if '--emit-ids' in argv:
                    Path(argv[argv.index('--emit-ids') + 1]).write_text('synthetic stable ids')
            elif 'compile' in argv:
                Path(argv[argv.index('-o') + 1]).write_bytes(b'mocked compiled resources')
            elif 'dump' in argv:
                marker = 'SPLIT_RESOURCE_MISSING' if Path(argv[-1]).name.startswith('base') else 'SPLIT_RESOURCE_OK'
                return 'resource 0x7f010000 string/split_probe\n  ' + marker
            elif argv[0] == str(tools['zipalign']):
                shutil.copyfile(argv[-2], argv[-1])
            return ''

        with (mock.patch.object(s, 'installed', return_value=(tools, {'runtime': [], 'compiler': []}, [], self.root / 'sysroot')),
              mock.patch.object(p, 'run', side_effect=run), mock.patch.object(s, 'check_unsigned', return_value={'mock_only': True})):
            result = s.build_fixture(self.args(abi=abi), out)
        return out, calls, result

    def test_builds_real_tool_commands_both_abis_but_no_signing(self):
        out, calls, (report, _, _) = self.build()
        self.assertEqual(report['status'], 'unsigned_real_split_fixture_built')
        clang = [v for v in calls if Path(v[0]).name == 'clang']
        self.assertEqual(len(clang), 2)
        self.assertEqual({v[1] for v in clang}, {'--target=x86_64-linux-android27', '--target=aarch64-linux-android27'})
        for argv in clang:
            self.assertIn('-shared', argv)
            self.assertIn('-Wl,-z,max-page-size=16384', argv)
            self.assertIn('-Wl,--no-undefined', argv)
        self.assertFalse(any('sign' in argv or 'keytool' in argv for argv in calls))
        for variant in report['variants']:
            with zipfile.ZipFile(variant['apks'][2]['path']) as apk:
                member = apk.getinfo('lib/' + variant['abi'] + '/libsplitprobe.so')
                self.assertEqual(member.compress_type, zipfile.ZIP_STORED)
            self.assertTrue((out / 'source/patch/SplitPatch.kt').is_file())
        self.assertTrue((out / 'fixture.json').exists())

    def test_android_bootclasspath_and_complete_nested_class_packaging(self):
        out, calls, _ = self.build(['x86_64'])
        javac = next(v for v in calls if Path(v[0]).name == 'javac')
        self.assertEqual(javac[javac.index('-source') + 1], '8')
        self.assertEqual(javac[javac.index('-target') + 1], '8')
        self.assertEqual(javac[javac.index('-bootclasspath') + 1], str(self.root / 'tools/android_jar'))
        self.assertNotIn('--release', javac)
        self.assertEqual(javac[-1], str(out / 'source/base/MainActivity.java'))
        self.assertNotEqual(javac[-1], str(s.SOURCE / 'base/MainActivity.java'))
        with zipfile.ZipFile(out / 'data/app-classes.jar') as archive:
            self.assertEqual(set(archive.namelist()), {
                'dev/morphe/splitfixture/MainActivity.class',
                'dev/morphe/splitfixture/MainActivity$1.class'})
        d8 = next(v for v in calls if 'com.android.tools.r8.D8' in v)
        self.assertEqual(d8[-1], str(out / 'data/app-classes.jar'))
        self.assertEqual(d8[d8.index('--min-api') + 1], '27')
        self.assertEqual(d8[d8.index('--lib') + 1], javac[javac.index('-bootclasspath') + 1])

    def test_resource_link_uses_shared_stable_ids_and_no_version_override(self):
        _, calls, _ = self.build(['x86_64'])
        links = [v for v in calls if 'link' in v]
        self.assertIn('--emit-ids', links[0])
        self.assertIn('--stable-ids', links[1])
        self.assertEqual(links[0][links[0].index('--emit-ids') + 1], links[1][links[1].index('--stable-ids') + 1])
        self.assertFalse(any('--version-name' in argv for argv in links))

    def test_tool_failure_has_no_fixture_success(self):
        with self.assertRaises(p.DriverError):
            self.build(fail='compile')
        self.assertFalse((self.root / 'build/fixture.json').exists())
        self.assertTrue((self.root / 'build/02-code-resources-failed.json').exists())

    def test_explicit_ndk_revision_mismatch_rejected_before_clang(self):
        args = self.args()
        for name in ('jdk', 'sdk', 'ndk', 'cache'):
            (self.root / name).mkdir()
        for name in ('aapt2', 'zipalign'):
            self.file('sdk/build-tools/36.0.0/' + name + ('.exe' if os.name == 'nt' else ''))
        for name in ('apksigner.jar', 'd8.jar'):
            self.file('sdk/build-tools/36.0.0/lib/' + name)
        self.file('sdk/platforms/android-36/android.jar')
        for name in ('bin/clang.exe', 'bin/ld.lld.exe', 'sysroot/usr/include/jni.h'):
            self.file('ndk/toolchains/llvm/prebuilt/windows-x86_64/' + name)
        self.file('sdk/build-tools/36.0.0/source.properties', b'Pkg.Revision = 36.0.0\n')
        self.file('sdk/platforms/android-36/source.properties', b'AndroidVersion.ApiLevel=36\n')
        self.file('ndk/source.properties', b'Pkg.Revision = 28.0.0\n')
        with mock.patch.object(p, 'jdk', return_value={}), mock.patch.object(p, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'identity mismatch'):
                s.installed(p, args, self.root)
            run.assert_not_called()


class ExactDexAndNegativeTests(Offline):
    def test_exact_final_dex_assertion_and_wrong_extra_instructions(self):
        tools = {'java': self.file('java')}; apk = self.file('base.apk')
        for expected in ('BASELINE', 'PATCHED'):
            with self.subTest(expected=expected):
                text = ('\nDEX classes.dex METHOD ' + s.SELECTOR + '\nflags=0x9\nregisters=1 tries=0\n'
                        '0000 CONST_STRING v0 ' + expected + '\n0002 RETURN_OBJECT v0\nTARGET_COUNT 1 ' + s.SELECTOR + '\n')
                for drift in ('', 'extra', 'register', 'value', 'count'):
                    target = self.root / (expected + drift + '.txt')
                    actual = text
                    if drift == 'extra': actual = text.replace('0002 RETURN', '0001 NOP\n0002 RETURN')
                    if drift == 'register': actual = text.replace('v0', 'v1')
                    if drift == 'value': actual = text.replace('v0 ' + expected, 'v0 WRONG')
                    if drift == 'count': actual = text.replace('TARGET_COUNT 1', 'TARGET_COUNT 2')
                    with mock.patch.object(d, 'dex', side_effect=lambda *args: target.write_text(actual)):
                        if drift:
                            with self.assertRaises(RuntimeError): s.inspect_label(d, p, apk, tools, {'runtime': []}, target, expected)
                        else:
                            self.assertEqual(s.inspect_label(d, p, apk, tools, {'runtime': []}, target, expected), p.record(target))

    def negative(self, phase='definition preflight', success=False, preflight_fail=False):
        out = self.root / 'negative'
        tools = {'java': self.file('java')}; runner = self.file('runner.jar')
        config = {'out': str(out), 'runner': p.record(runner)}
        original_request = {'output': str(out / 'runner-output'), 'sentinel_binding': {'exact': True}}
        def apply(c):
            self.assertEqual(c['patches'], ['APK-only negative'])
            out.mkdir()
            if not preflight_fail:
                s.save(out / 'request.json', original_request)
                s.save(out / 'verified-staged.json', {'synthetic': True})
                (out / 'runner-output').mkdir()
            if not success: raise p.DriverError('generic failure is not proof')
        def run(argv, **kwargs):
            proof = kwargs['log_dir']
            replay = json.loads(Path(argv[-1]).read_text())
            self.assertNotEqual(replay['output'], original_request['output'])
            self.assertEqual(replay['sentinel_binding'], original_request['sentinel_binding'])
            (proof / 'build.stderr.log').write_text('patch application or structural verification failed at ' + phase + '\n')
            (proof / 'build.stdout.log').write_text('')
            raise d.DriverError('nonzero exit')
        with mock.patch.object(p, 'apply', side_effect=apply), mock.patch.object(d, 'run_tool', side_effect=run):
            return s.negative_definition(p, d, self.args(), config, tools, {'runtime': []}, out)

    def test_negative_requires_actual_definition_phase_and_new_replay_output(self):
        self.assertEqual(self.negative()['status'], 'actual_loader_rejected_apk_only_at_definition_preflight')

    def test_unrelated_runner_failure_is_not_compatibility_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'specifically'):
            self.negative(phase='input snapshot')

    def test_preflight_failure_is_not_compatibility_evidence(self):
        with self.assertRaisesRegex(RuntimeError, 'before actual-loader'):
            self.negative(preflight_fail=True)

    def test_accepted_apk_only_definition_fails_recipe(self):
        with self.assertRaisesRegex(RuntimeError, 'was accepted'):
            self.negative(success=True)

    def test_apply_config_binds_logical_and_physical_set_no_java_in_verification(self):
        paths = [self.file(v) for v in ('base.apk', 'res.apk', 'native.apk')]
        selected = [{**p.record(v), 'archive_member': v.name} for v in paths]
        container = self.file('logical.apkm')
        built = dict(bundle=p.record(self.file('bundle.jar')), runner=p.record(self.file('runner.jar')),
            assertion_class='SplitAssertions', assertion_sha256='a' * 64, source_hashes=[p.record(self.file('source.kt'))])
        cfg = s.apply_config(p, self.args(), built, selected, container, {'java': 'omit', 'abi': 'x86_64'}, self.root / 'apply')
        self.assertEqual(cfg['input_mode'], 'base_config_set')
        self.assertEqual(cfg['apks'], selected)
        self.assertEqual(cfg['base'], p.record(paths[0]))
        self.assertEqual(cfg['logical_container'], {**p.record(container), 'type': 'APKM'})
        self.assertEqual(cfg['verification'], {'abi': 'x86_64'})
        self.assertFalse(cfg['allow_dex_layout_change'])


class CompiledPolicyTests(Offline):
    def check(self, *, role='resource', mutation=None, binary=True):
        path = self.root / 'synthetic.apk'
        with zipfile.ZipFile(path, 'x') as apk:
            apk.writestr('AndroidManifest.xml', b'\x03\x00\x08\x00mock' if binary else b'<manifest/>')
            apk.writestr('resources.arsc', b'\x02\x00mock')
        m = dict(package=s.PACKAGE, version_code='1', min_sdk=27, extract_native_libs=False,
            version_name=None, has_code=False, config_for_split=None, is_feature_split=False,
            split_types=['base__density'], split='config.xhdpi')
        inventory = dict(dex_payloads=[], dex=[], native_libraries=[], native_abis=[])
        if role == 'native':
            m.update(split_types=['base__abi'], split='config.x86_64')
            inventory.update(native_libraries=[{'data_offset': 16384}], native_abis=['x86_64'])
        if mutation: mutation(m, inventory)
        with (mock.patch.object(d, '_apk_inventory', return_value=inventory),
              mock.patch.object(d, '_authoritative_manifest', return_value=({'mock_raw': True}, m)),
              mock.patch.object(d, '_verify_native_libraries', side_effect=lambda v, **kwargs: v)):
            return s.check_unsigned(d, path, self.root / 'aapt2', role=role, abi='x86_64' if role == 'native' else None)

    def test_binary_companion_and_actual_absence_required(self):
        result = self.check()
        self.assertIsNone(result['manifest_declarations']['version_name'])
        self.assertEqual(result['raw_manifest'], {'mock_raw': True})

    def test_text_xml_placeholder_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'binary XML'): self.check(binary=False)

    def test_companion_version_code_or_feature_dex_drift_rejected(self):
        mutations = [lambda m, i: m.update(version_name=''), lambda m, i: m.update(version_name='1.0'),
                     lambda m, i: m.update(min_sdk=24), lambda m, i: m.update(is_feature_split=True),
                     lambda m, i: m.update(has_code=True), lambda m, i: i.update(dex_payloads=['classes.dex']),
                     lambda m, i: m.update(split_types=[]), lambda m, i: m.update(config_for_split='feature')]
        for index, mutation in enumerate(mutations):
            with self.subTest(index=index):
                old = self.root; self.root = old / str(index); self.root.mkdir()
                try:
                    with self.assertRaises(RuntimeError): self.check(mutation=mutation)
                finally: self.root = old

    def test_stored_native_offset_requires_16k_not_just_4k(self):
        with self.assertRaisesRegex(RuntimeError, '16-KiB'):
            self.check(role='native', mutation=lambda m, i: i['native_libraries'][0].update(data_offset=4096))


class AssemblyRecipeTests(Offline):
    def assemble(self, failure=None, allow_layout=False):
        out = self.root / 'assemble'; out.mkdir()
        args = self.args(allow_dex_layout_change=allow_layout)
        tools = {k: self.file('tools/' + k) for k in ('java', 'aapt2', 'zipalign', 'signer_jar')}
        deps = {'runtime': [], 'compiler': []}
        fixture = {'trusted_source': str(self.root / 'staged-source'), 'variants': [
            {'abi': abi, 'apks': [p.record(self.file(abi + '/' + str(i) + '.apk')) for i in range(3)]}
            for abi in ('x86_64', 'arm64-v8a')]}
        events, active = [], []
        signing, assembly = s.sibling('fixture_signing'), s.sibling('assembly')
        @contextmanager
        def fixture_key(jdk, path):
            events.append('key-enter'); active.append(True)
            try:
                yield {'keystore': 'PUBLIC_MOCK_NOT_A_KEY', 'key_alias': 'fixture',
                       'ks_pass_env': 'PUBLIC_TEST_VARIABLE_NAME', 'certificate_sha256': 'a' * 64}
            finally:
                active.pop(); events.append('key-exit')
        def build(args, directory):
            s.save(directory / 'fixture.json', {'mock_build': True})
            return fixture, tools, deps
        def patch_build(*args, **kwargs):
            return dict(bundle=p.record(self.file('development.jar')), runner=p.record(self.file('runner.jar')),
                        assertion_class='SplitAssertions', assertion_sha256='a' * 64,
                        source_hashes=[p.record(self.file('staged-source/patch.kt'))])
        def tool(argv, **kwargs):
            self.assertTrue(active)
            if 'sign' in argv:
                self.assertIn('env:PUBLIC_TEST_VARIABLE_NAME', argv)
                shutil.copyfile(argv[-1], argv[argv.index('--out') + 1])
                events.append('sign')
            return ('', '')
        def apply(config):
            self.assertEqual(config['input_mode'], 'base_config_set')
            self.assertEqual(config['allow_dex_layout_change'], allow_layout)
            self.assertNotIn('java', config['verification'])
            directory = Path(config['out']); directory.mkdir()
            s.save(directory / 'apply.json', {'mock_apply': True})
            events.append('apply')
        def assemble(**kwargs):
            self.assertTrue(active)
            self.assertEqual(kwargs['input_mode'], 'base_config_set')
            self.assertEqual(kwargs['allow_dex_layout_change'], allow_layout)
            self.assertTrue(kwargs['reviewed_apply'])
            self.assertEqual(len(kwargs['apks']), 3)
            directory = kwargs['out']; directory.mkdir()
            events.append('assemble')
            if failure == 'assembly': raise RuntimeError('late mocked signing failure')
            members = []
            for i in range(3):
                path = directory / ('signed-' + str(i) + '.apk'); path.write_bytes(b'mocked final APK')
                members.append({'outputs': {'signed': p.record(path)}, 'role': 'base' if i == 0 else 'base_config'})
            s.save(directory / 'assembly.json', {'mock_assembly': True})
            return {'members': members}
        def inspect(*args):
            if failure == 'final-dex' and args[-1] == 'PATCHED': raise RuntimeError('incorrect final dex')
            target = args[-2]; target.write_text('mock exact inspection')
            return p.record(target)
        with (mock.patch.object(s, 'build_fixture', side_effect=build), mock.patch.object(s, 'build_patch', side_effect=patch_build),
              mock.patch.object(signing, 'fixture_key', side_effect=fixture_key), mock.patch.object(d, 'run_tool', side_effect=tool),
              mock.patch.object(d, 'verify_apks', return_value={}), mock.patch.object(s, 'inspect_label', side_effect=inspect),
              mock.patch.object(s, 'negative_definition', return_value={'mock_negative': True}),
              mock.patch.object(p, 'apply', side_effect=apply), mock.patch.object(assembly, 'assemble', side_effect=assemble)):
            try: result = s.assemble_fixture(args, out)
            except RuntimeError:
                if failure is None: raise
                result = None
        return out, events, result

    def test_all_members_each_abi_and_context_exit_before_any_devices(self):
        out, events, result = self.assemble()
        self.assertEqual(events.count('sign'), 6)
        self.assertEqual(events.count('apply'), 2)
        self.assertEqual(events.count('assemble'), 2)
        self.assertEqual(events[-1], 'key-exit')
        self.assertEqual(len(result['variants']), 2)
        self.assertTrue((out / 'smoke.json').exists())
        for item in result['variants']:
            with zipfile.ZipFile(item['container']['path']) as archive:
                self.assertEqual(len(archive.namelist()), 3)
                self.assertEqual(archive.read('base.apk'), Path(item['originals'][0]['path']).read_bytes())

    def test_explicit_layout_change_opt_in_forwarded_to_apply_and_assembly(self):
        self.assertIsNotNone(self.assemble(allow_layout=True)[2])

    def test_late_assembly_or_final_dex_failure_never_emits_smoke_success(self):
        for failure in ('assembly', 'final-dex'):
            with self.subTest(failure=failure):
                old = self.root; self.root = old / failure; self.root.mkdir()
                try: out, events, result = self.assemble(failure)
                finally: self.root = old
                self.assertIsNone(result)
                self.assertFalse((out / 'smoke.json').exists())
                self.assertTrue((out / '05-sign-apply-assemble-failed.json').exists())
                self.assertEqual(events[-1], 'key-exit')


class UiTests(Offline):
    def tree(self, values):
        tree = ET.Element('hierarchy')
        for value in values: ET.SubElement(tree, 'node', text=value)
        return tree

    def test_exact_label_resource_and_matching_native_abi(self):
        for abi in s.ABIS:
            for expected in ('BASELINE', 'PATCHED'):
                s.assert_ui(self.tree([expected, 'SPLIT_RESOURCE_OK', 'JNI_OK_' + abi]), expected, abi)

    def test_fallback_errors_wrong_abi_duplicate_or_substrings_never_pass(self):
        valid = ['BASELINE', 'SPLIT_RESOURCE_OK', 'JNI_OK_x86_64']
        bad = [valid[:-1], [*valid, 'JNI_ERROR'], [*valid, 'PATCHED'], [*valid, 'SPLIT_RESOURCE_MISSING'],
               ['BASELINE', 'SPLIT_RESOURCE_OK', 'JNI_OK_arm64-v8a'], [*valid, 'JNI_OK_arm64-v8a'],
               [*valid, 'BASELINE'], ['BASELINE extra', *valid[1:]], ['BASELINE', 'SPLIT_RESOURCE_OK extra', valid[-1]]]
        for values in bad:
            with self.subTest(values=values), self.assertRaises(RuntimeError):
                s.assert_ui(self.tree(values), 'BASELINE', 'x86_64')

    def test_hierarchy_rejects_dtd_and_oversized(self):
        for name, content in [('dtd', b'<!DOCTYPE x><hierarchy/>'), ('large', b'x' * (4 * 1024 * 1024 + 1))]:
            with self.assertRaises(RuntimeError): s.hierarchy(self.file(name, content))

    def flow(self, failure=None):
        failures = set(failure if isinstance(failure, tuple) else [failure])
        run = self.root / 'new-owned'
        instance = SimpleNamespace(run=run, env={}, state=None)
        events, locks = [], []
        @contextmanager
        def locked(path):
            self.assertEqual(path, run); self.assertFalse(locks)
            locks.append(path)
            try: yield
            finally: locks.pop()
        def create(image):
            self.assertFalse(locks); self.assertEqual(image, s.IMAGE)
            run.mkdir(); instance.state = {'status': 'created'}; events.append('create')
        def action(name, result=None):
            def invoke(*args):
                self.assertEqual(locks, [run]); events.append(name)
                if name == 'start': instance.state['status'] = 'starting'
                if name in failures: raise RuntimeError('synthetic ' + name + ' failure')
                if name == 'start': instance.state['status'] = 'running'
                if name == 'stop': instance.state['status'] = 'stopped'
                if name == 'adb' and args[0][:3] == ['shell', 'input', 'tap'] and 'tap' in failures:
                    raise RuntimeError('synthetic tap failure')
                if name == 'adb' and args[0] == ['shell', 'wm', 'density']:
                    return 'Physical density: 160\nOverride density: ' + ('240' if 'density' in failures else '320') + '\n'
                return result or {}
            return invoke
        def capture(kind, *args, **kwargs):
            self.assertEqual(locks, [run]); events.append(kind)
            label = kwargs.get('label')
            if kind in failures or kind + '-' + str(label) in failures:
                raise RuntimeError('synthetic ' + kind + '-' + str(label) + ' failure')
            path = run / (str(label) + '-' + kind)
            if kind == 'dump' and label == 'before':
                path.write_text('<hierarchy><node text="Show label" bounds="[10,20][100,80]"/></hierarchy>')
            elif kind == 'dump':
                tree = self.tree(['BASELINE', 'SPLIT_RESOURCE_OK', 'JNI_OK_x86_64' if failure != 'ui' else 'JNI_ERROR'])
                ET.ElementTree(tree).write(path)
            else: path.write_bytes(b'private synthetic capture')
            return {'path': str(path)}
        instance.create = create
        instance.load = lambda: None
        for name in ('start', 'install', 'launch', 'adb'):
            setattr(instance, name, action(name))
        instance.capture = capture
        stop = {'status': 'stopped', 'confirmation': s.CONFIRMED if failure != 'unconfirmed' else 'ack_only'}
        instance.stop = action('stop', stop)
        emulator = SimpleNamespace(Emulator=lambda *args: instance, locked=locked)
        try:
            result = s.device_flow(emulator, self.root / 'sdk', self.root / 'jdk', run,
                                   [self.root / n for n in ('base.apk', 'res.apk', 'native.apk')], {}, 'BASELINE', 'x86_64')
        except RuntimeError:
            if failure is None: raise
            result = None
        else:
            self.assertIsNone(failure, 'Failure case incorrectly passed')
        return result, events, json.loads((run / 'split-fixture-flow.json').read_text())

    def test_owned_flow_captures_pending_visual_review_and_confirms_stop(self):
        result, events, saved = self.flow()
        self.assertEqual(result['status'], 'ui_asserted_owned_stop_confirmed')
        self.assertEqual(saved['visual_review'], 'pending_explicit_image_inspection')
        self.assertEqual(saved['density']['effective_dpi'], 320)
        self.assertEqual(events[-1], 'stop')
        self.assertIn('screenshot', events); self.assertIn('logcat', events)

    def test_stop_finally_and_failure_evidence_survive_boot_install_launch_ui_failures(self):
        for failure in ('start', 'density', 'install', 'launch', 'ui'):
            with self.subTest(failure=failure):
                # Use a separate test directory for every genuinely NEW mocked run.
                old = self.root; self.root = old / failure; self.root.mkdir()
                try: _, events, saved = self.flow(failure)
                finally: self.root = old
                self.assertEqual(events[-1], 'stop')
                self.assertEqual(saved['status'], 'incomplete')
                self.assertNotIn('ui_assertion', saved)
                if failure == 'ui': self.assertIn('screenshot', saved)

    def test_device_failure_identifies_exact_stage_even_before_after_capture(self):
        for failure, stage in [('start', 'boot'), ('density', 'density'), ('install', 'install'),
                               ('launch', 'launch'), ('dump-before', 'dump-before'), ('tap', 'tap'),
                               ('dump-after', 'dump-after'), ('screenshot', 'screenshot'),
                               ('logcat', 'logcat'), ('ui', 'assert-ui')]:
            with self.subTest(failure=failure):
                old = self.root; self.root = old / failure; self.root.mkdir()
                try: _, events, saved = self.flow(failure)
                finally: self.root = old
                self.assertEqual(saved['failure']['stage'], stage)
                self.assertEqual(saved['failure']['status'], 'failed')
                self.assertEqual(saved['failure']['error']['type'], 'RuntimeError')
                self.assertEqual(saved['stages'][-1], {'stage': 'stop', 'status': 'completed'})
                self.assertEqual(events[-1], 'stop')
                self.assertEqual(saved['status'], 'incomplete')
                self.assertNotIn('ui_assertion', saved)

    def test_stop_failure_does_not_erase_primary_stage_diagnostic(self):
        _, events, saved = self.flow(('tap', 'stop'))
        self.assertEqual(saved['failure']['stage'], 'tap')
        self.assertEqual(saved['failure']['error']['detail'], 'synthetic tap failure')
        self.assertEqual(saved['stages'][-1]['stage'], 'stop')
        self.assertEqual(saved['stages'][-1]['status'], 'failed')
        self.assertEqual(saved['stages'][-1]['error']['detail'], 'synthetic stop failure')
        self.assertEqual(saved['status'], 'incomplete')
        self.assertNotIn('stop', saved)
        self.assertEqual(events[-1], 'stop')

    def test_private_device_error_is_bounded_without_environment_or_traceback(self):
        evidence = {}
        with mock.patch.dict(os.environ, {'MORPHE_TEST_SECRET': 'never-copy-environment'}):
            with self.assertRaises(RuntimeError):
                with s.device_stage(evidence, 'tap'):
                    raise RuntimeError('x' * 10000)
        self.assertEqual(len(evidence['failure']['error']['detail']), 4096)
        self.assertEqual(set(evidence['failure']['error']), {'type', 'detail'})
        self.assertNotIn('never-copy-environment', json.dumps(evidence))

    def test_unconfirmed_or_failed_stop_is_not_success(self):
        for failure in ('stop', 'unconfirmed'):
            with self.subTest(failure=failure):
                old = self.root; self.root = old / failure; self.root.mkdir()
                try: result, events, saved = self.flow(failure)
                finally: self.root = old
                self.assertIsNone(result)
                self.assertEqual(saved['status'], 'incomplete')
                self.assertEqual(events[-1], 'stop')

    def test_tap_and_capture_failures_identify_exact_stage_without_retry(self):
        for failure, expected_stage in [('tap', 'tap'), ('dump-before', 'dump-before'),
                ('dump-after', 'dump-after'), ('screenshot', 'screenshot'), ('logcat', 'logcat')]:
            with self.subTest(failure=failure):
                old = self.root; self.root = old / failure; self.root.mkdir()
                try: _, events, saved = self.flow(failure)
                finally: self.root = old
                self.assertEqual(saved['status'], 'incomplete')
                self.assertEqual(saved['failure']['stage'], expected_stage)
                self.assertEqual(saved['failure']['error']['type'], 'RuntimeError')
                self.assertEqual(events[-1], 'stop')
                self.assertNotIn('ui_assertion', saved)
                self.assertEqual([v['stage'] for v in saved['stages']].count(expected_stage), 1)

    def test_stop_failure_does_not_erase_primary_failure(self):
        _, events, saved = self.flow(('tap', 'stop'))
        self.assertEqual(saved['failure']['stage'], 'tap')
        self.assertEqual(saved['failure']['error']['detail'], 'synthetic tap failure')
        self.assertEqual(saved['stages'][-1]['stage'], 'stop')
        self.assertEqual(saved['stages'][-1]['status'], 'failed')
        self.assertEqual(saved['stages'][-1]['error']['detail'], 'synthetic stop failure')
        self.assertEqual(saved['status'], 'incomplete')
        self.assertEqual(events[-1], 'stop')

    def test_device_diagnostics_are_bounded_and_do_not_serialize_environment(self):
        evidence = {'env': 'sentinel-existing-not-a-real-environment'}
        with self.assertRaises(RuntimeError):
            with s.device_stage(evidence, 'tap'):
                raise RuntimeError('x' * 10000)
        detail = evidence['failure']['error']['detail']
        self.assertEqual(len(detail), 4096)
        self.assertNotIn('env', evidence['failure'])
        self.assertNotIn('traceback', evidence['failure'])
        self.assertEqual(evidence['stages'][0]['status'], 'failed')


class SeparateDeviceRecipeTests(Offline):
    def report(self, abis=('x86_64', 'arm64-v8a')):
        sdk, jdk = self.root / 'sdk', self.root / 'jdk'
        sdk.mkdir(); jdk.mkdir()
        suffix = '.exe' if os.name == 'nt' else ''
        variants = []
        for abi in abis:
            verification = dict(java=str(jdk / 'bin' / ('java' + suffix)),
                aapt2=str(sdk / 'build-tools/36.0.0' / ('aapt2' + suffix)),
                signer_jar=str(sdk / 'build-tools/36.0.0/lib/apksigner.jar'),
                expect_package=s.PACKAGE, expect_version_code='1', expect_version_name='1.0',
                expect_signer=['a' * 64], abi=abi, density='xhdpi', language=['none'])
            variants.append({'abi': abi, 'verification': verification,
                'originals': [p.record(self.file(abi + '/original-' + str(i) + '.apk')) for i in range(3)],
                'patched': [p.record(self.file(abi + '/patched-' + str(i) + '.apk')) for i in range(3)]})
        path = self.root / 'smoke.json'
        s.save(path, {'schema': 1, 'status': 'real_split_fixture_assembled_verified', 'variants': variants})
        args = SimpleNamespace(sdk=str(sdk), jdk=str(jdk), report=str(path), expect_report_sha256=p.digest(path), abi=None)
        out = self.root / 'devices'; out.mkdir()
        return args, out, variants

    def test_sequential_baseline_patched_runs_for_each_abi_no_signing_context(self):
        args, out, _ = self.report()
        events = []
        def flow(emulator, sdk, jdk, run, paths, verification, expected, abi):
            events.append((abi, expected, run))
            return {'stop': {'confirmation': s.CONFIRMED}, 'ui_assertion': 'mock only'}
        signing = s.sibling('fixture_signing')
        with mock.patch.object(s, 'device_flow', side_effect=flow), mock.patch.object(signing, 'fixture_key', side_effect=AssertionError('No key operations')):
            result = s.run_devices(args, out)
        self.assertEqual([(a, b) for a, b, _ in events], [('x86_64', 'BASELINE'), ('x86_64', 'PATCHED'),
                                                                     ('arm64-v8a', 'BASELINE'), ('arm64-v8a', 'PATCHED')])
        self.assertEqual(len({path for _, _, path in events}), 4)
        self.assertEqual(result['visual_review'], 'pending_explicit_image_inspection')

    def test_failed_stop_aborts_before_next_run_and_no_aggregate(self):
        args, out, _ = self.report()
        with mock.patch.object(s, 'device_flow', side_effect=RuntimeError('unconfirmed stop')) as flow:
            with self.assertRaises(RuntimeError): s.run_devices(args, out)
            self.assertEqual(flow.call_count, 1)
        self.assertFalse((out / 'devices.json').exists())

    def test_mutated_apk_rejected_before_device_constructor(self):
        args, out, variants = self.report()
        Path(variants[0]['originals'][1]['path']).write_bytes(b'changed')
        with mock.patch.object(s, 'device_flow') as flow:
            with self.assertRaises(p.DriverError): s.run_devices(args, out)
            flow.assert_not_called()

    def test_unknown_package_or_tool_override_rejected(self):
        args, out, variants = self.report()
        report = json.loads(Path(args.report).read_text())
        report['variants'][0]['verification']['expect_package'] = 'other.package'
        Path(args.report).write_text(json.dumps(report)); args.expect_report_sha256 = p.digest(Path(args.report))
        with mock.patch.object(s, 'device_flow') as flow:
            with self.assertRaisesRegex(RuntimeError, 'contract mismatch'): s.run_devices(args, out)
            flow.assert_not_called()


if __name__ == '__main__':
    unittest.main()
