"""Offline smoke regressions. Run: py -I -B test_smoke.py.

No Android tools, real keys, credentials, devices, downloads, or Git. Synthetic
files live only in TemporaryDirectory; subprocess entry points fail closed.
These tests do NOT replace an authorized full smoke and screenshot inspection.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

HERE = Path(__file__).resolve().parent


def load(stem):
    spec = importlib.util.spec_from_file_location('_smoke_test_' + stem, HERE / (stem + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


smoke = load('smoke')
signing = load('fixture_signing')
emulator = load('emulator')
driver = load('driver')
patchdev = load('patchdev')
lab = load('lab')
assembly = load('assembly')
CONFIRMED = 'process_exited_and_both_owned_ports_released'
# Deliberately public test sentinel, not a generated or actual credential.
SENTINEL = 'PUBLIC_SYNTHETIC_TEST_VALUE_NOT_A_CREDENTIAL'
VARIABLE = 'FISHY_FIXTURE_KS_' + 'A' * 24
BEFORE = b'<hierarchy><node text="SHOW LABEL" bounds="[10,20][110,80]"/></hierarchy>'


class OfflineTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='morphe-smoke-test-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        # Even an accidentally unmocked module helper must never run a tool.
        for name in ('Popen', 'run'):
            patcher = mock.patch.object(subprocess, name, side_effect=AssertionError('Real process forbidden'))
            patcher.start()
            self.addCleanup(patcher.stop)

    def file(self, name, content=b'synthetic test bytes'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path


class DeviceFlowTests(OfflineTests):
    def flow(self, *, before=BEFORE, after=None, expected='PATCHED', fail=None):
        run = self.root / 'new-owned-run'
        before_path = self.file('new-owned-run/before.xml', before)
        after_path = self.file('new-owned-run/after.xml', after or
                               ('<hierarchy><node text="' + expected + '"/></hierarchy>').encode())
        instance = mock.create_autospec(emulator.Emulator, instance=True)
        instance.run, instance.env, instance.state = run, {}, None
        active_locks = []
        events = []

        @contextlib.contextmanager
        def locked(path):
            self.assertEqual(path, run)
            self.assertFalse(active_locks, 'No nested lock or retained lock during stop')
            active_locks.append(path)
            try:
                yield
            finally:
                active_locks.pop()

        def create(image):
            self.assertFalse(active_locks)
            self.assertEqual(image, 'system-images;android-30;google_apis;x86_64')
            self.assertEqual(instance.env['JAVA_HOME'], str(self.root / 'jdk'))
            instance.state = {'status': 'created'}
            events.append('create')
            if fail == 'create':
                raise RuntimeError('create failure')

        def action(name, value):
            def invoke(*args, **kwargs):
                self.assertEqual(active_locks, [run], 'Device operation must be locked')
                events.append(name)
                if name == 'start':
                    instance.state['status'] = 'starting'
                if fail == name:
                    raise RuntimeError(name + ' failure')
                if name == 'start':
                    instance.state['status'] = 'running'
                if name == 'stop':
                    instance.state['status'] = 'stopped'
                return value
            return invoke

        def capture(command, lines=200, label=None):
            self.assertEqual(active_locks, [run])
            name = 'dump-' + str(label) if command == 'dump' else command
            events.append(name)
            if fail == name:
                raise RuntimeError(name + ' failure')
            if command == 'dump':
                return {'path': str(before_path if label == 'before' else after_path)}
            return {'path': str(run / ('feature.' + ('png' if command == 'screenshot' else 'txt')))}

        instance.create.side_effect = create
        instance.load.side_effect = action('load', None)
        instance.start.side_effect = action('start', {'serial': 'emulator-5556'})
        instance.install.side_effect = action('install', {'verification': 'synthetic-verification.json'})
        instance.launch.side_effect = action('launch', {'component': 'dev.morphe.fixture/.MainActivity'})
        instance.adb.side_effect = action('tap', '')
        instance.capture.side_effect = capture
        instance.stop.side_effect = action('stop', {'status': 'stopped', 'confirmation': CONFIRMED})
        module = SimpleNamespace(Emulator=mock.Mock(return_value=instance), locked=locked)
        pins = {'expect_package': 'dev.morphe.fixture', 'expect_signer': ['a' * 64]}
        call = lambda: smoke.device_flow(module, self.root / 'sdk', self.root / 'jdk', run,
                                         self.root / 'fixture.apk', pins, expected)
        return call, instance, module, pins, events, run

    def test_success_uses_owned_api_signatures_and_records_pending_visual_review(self):
        call, instance, module, pins, events, run = self.flow()
        evidence = call()
        module.Emulator.assert_called_once_with(str(self.root / 'sdk'), str(run))
        instance.start.assert_called_once_with(180, 'swiftshader_indirect')
        instance.install.assert_called_once_with([str(self.root / 'fixture.apk')], pins)
        instance.launch.assert_called_once_with('dev.morphe.fixture', None)
        instance.adb.assert_called_once_with(['shell', 'input', 'tap', '60', '50'])
        self.assertEqual(instance.capture.call_args_list, [mock.call('dump', label='before'),
                         mock.call('dump', label='after'), mock.call('screenshot', label='feature'),
                         mock.call('logcat', 200, 'feature')])
        instance.stop.assert_called_once_with(60)
        self.assertEqual(events, ['create', 'load', 'start', 'install', 'launch', 'dump-before',
                                 'tap', 'dump-after', 'screenshot', 'logcat', 'load', 'stop'])
        self.assertEqual(evidence['ui_assertion'], 'passed')
        self.assertEqual(evidence['stop']['confirmation'], CONFIRMED)
        self.assertEqual(evidence['visual_review'], 'pending_explicit_image_inspection')
        self.assertEqual(json.loads((run / 'fixture-flow.json').read_text()), evidence)

    def test_title_case_button_and_baseline_label_are_supported(self):
        call, instance, *_ = self.flow(before=BEFORE.replace(b'SHOW LABEL', b'Show label'), expected='BASELINE')
        self.assertEqual(call()['expected_label'], 'BASELINE')
        instance.stop.assert_called_once_with(60)

    def test_invalid_before_hierarchies_never_tap_but_stop_once(self):
        cases = [b'not XML', b'<!DOCTYPE hierarchy><hierarchy/>', b'<hierarchy/>',
                 BEFORE.replace(b'[10,20][110,80]', b'[1,2][1,3]'),
                 BEFORE.replace(b'[10,20][110,80]', b'[0,0][32768,3]'),
                 BEFORE.replace(b'[10,20][110,80]', b'[-1,0][10,20]'),
                 BEFORE.replace(b'[10,20][110,80]', b'broken'),
                 BEFORE.replace(b'</hierarchy>', b'<node text="Show label" bounds="[0,0][2,2]"/></hierarchy>'),
                 b'x' * (4 * 1024 * 1024 + 1)]
        for before in cases:
            with self.subTest(prefix=before[:65]):
                call, instance, _, _, _, run = self.flow(before=before)
                with self.assertRaises((RuntimeError, ET.ParseError)):
                    call()
                instance.adb.assert_not_called()
                instance.stop.assert_called_once_with(60)
                self.assertFalse((run / 'fixture-flow.json').exists())

    def test_wrong_missing_mixed_and_malformed_final_labels_fail_closed(self):
        cases = [b'<hierarchy><node text="BASELINE"/></hierarchy>',
                 b'<hierarchy><node text="PATCHED suffix"/></hierarchy>',
                 b'<hierarchy><node text="PATCHED"/><node text="BASELINE"/></hierarchy>',
                 b'<hierarchy/>', b'<broken', b'<!DOCTYPE hierarchy><hierarchy/>',
                 b'x' * (4 * 1024 * 1024 + 1)]
        for after in cases:
            with self.subTest(prefix=after[:65]):
                call, instance, _, _, _, run = self.flow(after=after)
                with self.assertRaises((RuntimeError, ET.ParseError)):
                    call()
                instance.adb.assert_called_once()
                instance.stop.assert_called_once_with(60)
                self.assertNotIn(mock.call('screenshot', label='feature'), instance.capture.call_args_list)
                self.assertFalse((run / 'fixture-flow.json').exists())

    def test_failed_device_stages_never_return_success_and_attempt_only_one_stop(self):
        for stage in ('start', 'install', 'launch', 'dump-before', 'tap', 'dump-after', 'screenshot', 'logcat', 'stop'):
            with self.subTest(stage=stage):
                call, instance, _, _, _, run = self.flow(fail=stage)
                with self.assertRaisesRegex(RuntimeError, stage + ' failure'):
                    call()
                instance.stop.assert_called_once_with(60)
                self.assertFalse((run / 'fixture-flow.json').exists())

    def test_failed_creation_never_targets_or_stops_a_device(self):
        call, instance, *_ = self.flow(fail='create')
        with self.assertRaisesRegex(RuntimeError, 'create failure'):
            call()
        for method in (instance.start, instance.install, instance.launch, instance.adb, instance.capture, instance.stop):
            method.assert_not_called()

    def test_denied_stop_is_not_retried_even_after_ui_failure(self):
        call, instance, _, _, _, run = self.flow(after=b'<hierarchy/>')
        instance.stop.side_effect = emulator.Failure('stop denied')
        with self.assertRaisesRegex(emulator.Failure, 'stop denied'):
            call()
        instance.stop.assert_called_once_with(60)
        self.assertFalse((run / 'fixture-flow.json').exists())


class StopContractTests(OfflineTests):
    def active(self, status='running'):
        # Real stop implementation, but every process/endpoint/ADB boundary is mocked.
        instance = emulator.Emulator(self.root / 'sdk', self.root / 'run')
        instance.state = {'status': status, 'pid': 12345, 'console_port': 5556,
                          'serial': 'emulator-5556', 'server_port': 40402}
        for name in ('adb', 'bind_server', 'save'):
            patcher = mock.patch.object(instance, name)
            patcher.start()
            self.addCleanup(patcher.stop)
        return instance

    def test_stop_returns_only_after_exit_and_both_ports_are_released(self):
        instance = self.active()
        with mock.patch.object(emulator, 'process_exited', return_value=True) as exited, \
             mock.patch.object(emulator, 'endpoints_released', return_value=True) as released:
            result = instance.stop(60)
        instance.adb.assert_called_once_with(['emu', 'kill'], timeout=10)
        exited.assert_called_once_with(12345)
        released.assert_called_once_with(5556)
        self.assertEqual(result['confirmation'], CONFIRMED)
        self.assertEqual(instance.state['status'], 'stopped')

    def test_exit_or_port_failure_cannot_be_reported_as_stopped(self):
        for process, ports in ((False, True), (True, False)):
            with self.subTest(process=process, ports=ports):
                instance = self.active()
                with mock.patch.object(emulator, 'process_exited', return_value=process), \
                     mock.patch.object(emulator, 'endpoints_released', return_value=ports), \
                     mock.patch.object(emulator.time, 'monotonic', side_effect=[0, 0, 61, 61]):
                    with self.assertRaisesRegex(emulator.Failure, 'unconfirmed'):
                        instance.stop(60)
                self.assertEqual(instance.state['status'], 'stopping')
                self.assertNotIn('stop_confirmation', instance.state)
                instance.adb.assert_called_once()

    def test_stopping_retry_only_confirms_and_never_kills_again(self):
        instance = self.active('stopping')
        with mock.patch.object(emulator, 'process_exited', return_value=True), \
             mock.patch.object(emulator, 'endpoints_released', return_value=True):
            self.assertEqual(instance.stop(60)['status'], 'stopped')
        instance.adb.assert_not_called()

    def test_rejected_owned_kill_leaves_running_and_does_not_fallback(self):
        instance = self.active()
        instance.adb.side_effect = emulator.Failure('AVD not owned')
        with mock.patch.object(emulator, 'process_exited') as exited:
            with self.assertRaisesRegex(emulator.Failure, 'not owned'):
                instance.stop(60)
        instance.adb.assert_called_once()
        exited.assert_not_called()
        self.assertEqual(instance.state['status'], 'running')


class SigningTests(OfflineTests):
    def setup_signing(self, fail=None):
        jdk = self.root / 'jdk'
        self.file('jdk/bin/' + ('keytool.exe' if os.name == 'nt' else 'keytool'))
        fake = mock.create_autospec(driver)
        fake.external_output.side_effect = driver.external_output

        def run(args, **kwargs):
            self.assertEqual(os.environ[VARIABLE], SENTINEL)
            self.assertNotIn(SENTINEL, args)
            self.assertIn('-storepass:env', args)
            self.assertEqual(args[args.index('-storepass:env') + 1], VARIABLE)
            if args[1] == fail:
                raise RuntimeError('synthetic tool failure')
            if args[1] == '-genkeypair':
                Path(args[args.index('-keystore') + 1]).write_bytes(b'NOT_A_REAL_KEYSTORE')
                self.assertIn('-keypass:env', args)
                self.assertEqual(args[args.index('-keypass:env') + 1], VARIABLE)
            else:
                Path(args[args.index('-file') + 1]).write_bytes(b'NOT_A_REAL_CERTIFICATE')
            return '', ''

        fake.run_tool.side_effect = run
        for patcher in (mock.patch.object(signing, '_driver', return_value=fake),
                        mock.patch.object(signing.secrets, 'token_hex', return_value='a' * 24),
                        mock.patch.object(signing.secrets, 'token_urlsafe', return_value=SENTINEL),
                        mock.patch.dict(os.environ)):
            patcher.start()
            self.addCleanup(patcher.stop)
        os.environ.pop(VARIABLE, None)
        return fake, jdk

    def test_only_env_variable_name_and_public_certificate_are_persisted(self):
        fake, jdk = self.setup_signing()
        out = self.root / 'fixture-signing'
        with signing.fixture_key(jdk, out) as public:
            self.assertEqual(os.environ[VARIABLE], SENTINEL)
            self.assertEqual(public['ks_pass_env'], VARIABLE)
            self.assertEqual(public['certificate_sha256'], hashlib.sha256(b'NOT_A_REAL_CERTIFICATE').hexdigest())
            self.assertIs(public['fixture_only'], True)
            self.assertEqual(json.loads((out / 'public-signing.json').read_text()), public)
            self.assertNotIn(SENTINEL, json.dumps(public))
            for path in out.iterdir():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes())
        self.assertNotIn(VARIABLE, os.environ)
        self.assertEqual(fake.run_tool.call_count, 2)

    def test_environment_is_cleared_on_tool_failure_or_context_exception(self):
        for stage in ('-genkeypair', '-exportcert', 'body'):
            with self.subTest(stage=stage):
                fake, jdk = self.setup_signing(fail=stage)
                with self.assertRaisesRegex(RuntimeError, 'synthetic'):
                    with signing.fixture_key(jdk, self.root / stage) as public:
                        self.assertEqual(public['ks_pass_env'], VARIABLE)
                        raise RuntimeError('synthetic body failure')
                self.assertNotIn(VARIABLE, os.environ)

    def test_existing_key_directory_is_never_reused(self):
        fake, jdk = self.setup_signing()
        marker = self.file('existing/fixture-only.p12', b'PREEXISTING_DO_NOT_READ_OR_CHANGE')
        with self.assertRaises(FileExistsError):
            with signing.fixture_key(jdk, marker.parent):
                self.fail('must refuse existing directory')
        fake.run_tool.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'PREEXISTING_DO_NOT_READ_OR_CHANGE')
        self.assertNotIn(VARIABLE, os.environ)


class SmokePipelineTests(OfflineTests):
    setup_signing = SigningTests.setup_signing

    def pipeline(self, devices=False):
        fake_driver, jdk = self.setup_signing()
        sdk, cache = self.root / 'sdk', self.root / 'cache'
        sdk.mkdir(exist_ok=True)
        cache.mkdir(exist_ok=True)
        jadx = self.file('jadx.jar')
        args = SimpleNamespace(jdk=str(jdk), sdk=str(sdk), cache_root=str(cache), jadx_jar=str(jadx),
                               out=str(self.root / 'smoke'), allow_fixture_key=True, devices=devices)
        fake_driver._hash_file.return_value = 'a' * 64
        # Signing fake is also used for alignment/signing, so handle those inertly.
        keytool_run = fake_driver.run_tool.side_effect
        fake_driver.run_tool.side_effect = lambda argv, **kw: keytool_run(argv, **kw) if '-genkeypair' in argv or '-exportcert' in argv else ('', '')
        p, l, a = (mock.create_autospec(module) for module in (patchdev, lab, assembly))
        p.record.side_effect = lambda path: {'path': str(path), 'sha256': 'a' * 64}
        p.closure.return_value = {'runtime': [self.root / 'runtime.jar'], 'compiler': [self.root / 'compiler.jar']}
        p.classpath.return_value = 'synthetic-runtime-classpath'
        p.fixture_build.return_value = {'apk': {'path': str(self.root / 'unsigned.apk')},
                                        'trusted_source': str(self.root / 'trusted-source')}
        p.patch_build.return_value = {'bundle': {}, 'runner': {}, 'assertion_class': 'FixtureAssertions',
                                      'assertion_sha256': 'b' * 64, 'source_hashes': []}
        l.preflight.return_value = {'status': 'preflight_checks_passed'}
        a.assemble.return_value = {'outputs': {'signed': {'path': str(self.root / 'patched.apk')}}}
        modules = dict(driver=fake_driver, patchdev=p, lab=l, assembly=a, fixture_signing=signing,
                       emulator=SimpleNamespace())
        patcher = mock.patch.object(smoke, 'sibling', side_effect=modules.__getitem__)
        patcher.start()
        self.addCleanup(patcher.stop)
        return args, fake_driver, p, l, a

    def test_preflight_blocks_before_fixture_keys_or_device_work(self):
        args, d, p, l, a = self.pipeline(devices=True)
        l.preflight.return_value = {'status': 'blocked'}
        with mock.patch.object(smoke, 'device_flow') as flow:
            with self.assertRaisesRegex(RuntimeError, 'preflight blocked'):
                smoke.run_smoke(args)
        p.fixture_build.assert_not_called()
        d.run_tool.assert_not_called()
        a.assemble.assert_not_called()
        flow.assert_not_called()
        self.assertNotIn(VARIABLE, os.environ)
        self.assertFalse((Path(args.out) / 'smoke.json').exists())
        config = json.loads((Path(args.out) / 'tools.json').read_text())
        self.assertEqual(config['schema'], 1)
        self.assertEqual(config['java']['path'], str(Path(args.jdk) / 'bin' / ('java.exe' if os.name == 'nt' else 'java')))
        self.assertEqual(config['aapt2']['path'], str(Path(args.sdk) / 'build-tools/36.0.0' / ('aapt2.exe' if os.name == 'nt' else 'aapt2')))
        for name in ('build_tools_properties', 'platform_properties', 'dex_classpath', 'runtime_classpath', 'compiler_classpath'):
            self.assertIn(name, config)

    def test_build_only_does_not_construct_emulator_and_drops_signing_environment(self):
        args, d, p, l, a = self.pipeline()
        with mock.patch.object(smoke, 'device_flow') as flow:
            result = smoke.run_smoke(args)
        flow.assert_not_called()
        self.assertNotIn(VARIABLE, os.environ)
        self.assertEqual(result['status'], 'fixture_patch_assembled_verified')
        self.assertNotIn('baseline_device', result)
        self.assertEqual(json.loads((Path(args.out) / 'smoke.json').read_text()), result)
        l.preflight.assert_called_once_with(Path(args.out) / 'tools.json', Path(args.out) / 'preflight')
        a.assemble.assert_called_once()  # Autospec validates current real API signature.
        self.assertEqual(a.assemble.call_args.kwargs['ks_pass_env'], VARIABLE)
        self.assertEqual(a.assemble.call_args.kwargs['final_signer_sha256'],
                         hashlib.sha256(b'NOT_A_REAL_CERTIFICATE').hexdigest())
        argv = [c.args[0] for c in d.run_tool.call_args_list]
        sign = next(command for command in argv if '--ks-pass' in command)
        self.assertEqual(sign[sign.index('--ks-pass') + 1], 'env:' + VARIABLE)
        self.assertNotIn(SENTINEL, json.dumps(argv))
        self.assertNotIn(SENTINEL, (Path(args.out) / 'smoke.json').read_text())

    def test_both_new_flows_begin_after_password_removal_and_final_status_stays_visual_pending(self):
        args, *_ = self.pipeline(devices=True)
        flows = []

        def device_flow(module, sdk, jdk, run, apk, verification, expected):
            self.assertNotIn(VARIABLE, os.environ)
            self.assertEqual(verification['expect_package'], 'dev.morphe.fixture')
            self.assertFalse(run.exists(), 'No existing device run can be selected')
            flows.append((run, expected))
            return {'expected_label': expected, 'ui_assertion': 'passed',
                    'stop': {'status': 'stopped', 'confirmation': CONFIRMED}}

        with mock.patch.object(smoke, 'device_flow', side_effect=device_flow):
            result = smoke.run_smoke(args)
        self.assertEqual(flows, [(Path(args.out) / 'baseline-emulator', 'BASELINE'),
                                 (Path(args.out) / 'patched-emulator', 'PATCHED')])
        self.assertEqual(result['status'], 'fixture_patch_ui_asserted_both_owned_stops_confirmed')
        self.assertEqual(result['visual_review'], 'pending_explicit_image_inspection')
        self.assertEqual(json.loads((Path(args.out) / 'smoke.json').read_text()), result)

    def test_either_device_failure_prevents_final_success_evidence(self):
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call):
                args, *_ = self.pipeline(devices=True)
                args.out += '-' + str(failing_call)
                successes = [{'ui_assertion': 'passed', 'stop': {'status': 'stopped', 'confirmation': CONFIRMED}}] * (failing_call - 1)
                with mock.patch.object(smoke, 'device_flow', side_effect=[*successes, emulator.Failure('unconfirmed stop')]) as flow:
                    with self.assertRaisesRegex(emulator.Failure, 'unconfirmed stop'):
                        smoke.run_smoke(args)
                self.assertEqual(flow.call_count, failing_call)
                self.assertNotIn(VARIABLE, os.environ)
                self.assertFalse((Path(args.out) / 'smoke.json').exists())

    def test_assembly_failure_clears_password_and_never_starts_devices(self):
        args, d, p, l, a = self.pipeline(devices=True)
        a.assemble.side_effect = RuntimeError('synthetic assembly failure')
        with mock.patch.object(smoke, 'device_flow') as flow:
            with self.assertRaisesRegex(RuntimeError, 'assembly failure'):
                smoke.run_smoke(args)
        self.assertNotIn(VARIABLE, os.environ)
        flow.assert_not_called()
        self.assertFalse((Path(args.out) / 'smoke.json').exists())

    def test_existing_output_is_not_reused(self):
        args, d, p, l, a = self.pipeline()
        marker = self.file('smoke/marker', b'KEEP_EXISTING')
        with self.assertRaises(FileExistsError):
            smoke.run_smoke(args)
        p.closure.assert_not_called()
        l.preflight.assert_not_called()
        d.run_tool.assert_not_called()
        self.assertEqual(marker.read_bytes(), b'KEEP_EXISTING')


class FixtureAndCliTests(OfflineTests):
    def test_fixture_manifest_and_compiler_packaging_both_use_minimum_24(self):
        manifest = ET.parse(HERE / 'fixture/AndroidManifest.xml')
        self.assertEqual(manifest.find('uses-sdk').get('{http://schemas.android.com/apk/res/android}minSdkVersion'), '24')
        java, javac, aapt, d8, android = [self.file(name) for name in ('java', 'javac', 'aapt2', 'd8.jar', 'android.jar')]
        calls = []

        def run(argv, cwd, **kwargs):
            calls.append([str(arg) for arg in argv])
            if 'com.android.tools.r8.D8' in argv:
                (Path(argv[argv.index('--output') + 1]) / 'classes.dex').write_bytes(b'synthetic dex')
            elif 'link' in argv:
                with zipfile.ZipFile(Path(argv[argv.index('-o') + 1]), 'x') as archive:
                    archive.writestr('AndroidManifest.xml', b'synthetic binary manifest')
            return ''

        original_file_path = patchdev.file_path

        def file_path(path):
            tools = {'aapt2': aapt, 'aapt2.exe': aapt, 'd8.jar': d8, 'android.jar': android}
            return tools[Path(path).name] if Path(path).name in tools else original_file_path(path)

        with mock.patch.object(patchdev, 'jdk', return_value={'java': java, 'javac': javac}), \
             mock.patch.object(patchdev, 'file_path', side_effect=file_path), \
             mock.patch.object(patchdev, 'run', side_effect=run):
            result = patchdev.fixture_build({'out': str(self.root / 'fixture'), 'jdk': str(self.root), 'sdk': str(self.root)})
        dex_call = next(c for c in calls if 'com.android.tools.r8.D8' in c)
        aapt_call = next(c for c in calls if 'link' in c)
        self.assertEqual(dex_call[dex_call.index('--min-api') + 1], '24')
        self.assertEqual(aapt_call[aapt_call.index('--min-sdk-version') + 1], '24')
        self.assertEqual(result['status'], 'unsigned_fixture_built')

    def test_cli_requires_explicit_key_opt_in_before_running(self):
        argv = [part for flag in ('jdk', 'sdk', 'cache-root', 'jadx-jar', 'out') for part in ('--' + flag, str(self.root))]
        with mock.patch.object(smoke, 'run_smoke') as run, contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_info:
                smoke.main(argv)
        self.assertEqual(exit_info.exception.code, 2)
        run.assert_not_called()

    def test_cli_failure_is_nonzero_and_never_echoes_exception_or_secret(self):
        argv = [part for flag in ('jdk', 'sdk', 'cache-root', 'jadx-jar', 'out') for part in ('--' + flag, str(self.root))]
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(smoke, 'run_smoke', side_effect=RuntimeError(SENTINEL)), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = smoke.main([*argv, '--allow-fixture-key'])
        self.assertEqual(code, 1)
        self.assertEqual(stdout.getvalue(), '')
        self.assertNotIn(SENTINEL, stderr.getvalue())
        self.assertIn('partial evidence is not success', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
