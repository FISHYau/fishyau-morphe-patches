"""Synthetic offline lab regressions. Run Python -I -B with this absolute file."""
from __future__ import annotations

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
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('_tested_android_lab', HERE / 'lab.py')
lab = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = lab
SPEC.loader.exec_module(lab)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_zip(path, entries):
    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as stream:
        for name, data in entries:
            stream.writestr(name, data)
    return path


def apk(path):
    return write_zip(path, [('AndroidManifest.xml',
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        'package="example.fixture" android:versionCode="1" android:versionName="1"/>'),
        ('classes.dex', b'dex\n035\0synthetic'), ('classes2.dex', b'synthetic2')])


class LabTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='android-lab-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / 'inputs'
        self.inputs.mkdir()
        self.input = apk(self.inputs / 'fixture.apk')
        self.expected = digest(self.input)
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        self.java = self.tools / 'java.exe'
        self.java.write_bytes(b'synthetic-java-never-executed')
        self.jadx = self.tools / 'jadx.jar'
        self.jadx.write_bytes(b'synthetic-jadx-never-executed')

    def init(self, **kwargs):
        values = dict(archive=self.input, expected_sha256=self.expected,
                      desired_change='Change self-authored label', out=self.root / 'lab')
        values.update(kwargs)
        return lab.init_lab(**values)

    def discover(self, **kwargs):
        values = dict(apk=self.input, expected_sha256=self.expected, java=self.java,
                      jadx_jar=self.jadx, jadx_sha256=digest(self.jadx),
                      out=self.root / 'discover', search='target')
        values.update(kwargs)
        return lab.discover(**values)

    def mock_decompile(self, args, **kwargs):
        destination = Path(args[args.index('--output-dir') + 1])
        sources = destination / 'sources/example'
        sources.mkdir(parents=True)
        (sources / 'Target.java').write_text('class Target {\nString x = "target";\n}', encoding='utf-8')
        return 0, 'not recorded'

    def config(self):
        build = self.tools / 'build-tools-36'
        build.mkdir()
        platform = self.tools / 'android-36'
        platform.mkdir()
        config = {'schema': 1}
        for name in lab.TOOLS:
            folder = build if name in ('aapt2', 'zipalign') else platform if name == 'android_jar' else self.tools
            suffix = '.jar' if name.endswith('_jar') else '.exe'
            path = folder / (name + suffix)
            if name == 'android_jar':
                write_zip(path, [('android/app/Activity.class', b'fixture')])
            elif name == 'd8_jar':
                write_zip(path, [('com/android/tools/r8/D8.class', b'fixture')])
            else:
                path.write_bytes(('synthetic-' + name).encode())
            config[name] = {'path': str(path), 'sha256': digest(path)}
        dex = write_zip(self.tools / 'dex.jar', [('com/android/tools/smali/dexlib2/DexFileFactory.class', b'fixture')])
        dependency = {'path': str(dex), 'sha256': digest(dex)}
        for name in ('dex_classpath',) + lab.OPTIONAL_LISTS:
            config[name] = [dict(dependency)]
        for key, path, content in (
            ('build_tools_properties', build / 'source.properties', 'Pkg.Revision=36.0.0\n'),
            ('platform_properties', platform / 'source.properties', 'AndroidVersion.ApiLevel=36\n')):
            path.write_text(content, encoding='utf-8')
            config[key] = {'path': str(path), 'sha256': digest(path)}
        path = self.root / 'tools.json'
        path.write_text(json.dumps(config), encoding='utf-8')
        return path, config

    def probe(self, args, **kwargs):
        executable = Path(args[0]).stem
        if executable in ('javac', 'jar'):
            return 0, executable + ' 21.0.5'
        if executable == 'zipalign':
            return 2, 'Zip alignment utility\nUsage: zipalign'
        if '-version' in args:
            return 0, 'openjdk version "21.0.5" 2024-10-15'
        return 0, 'tool 2.3.0'

    def test_tool_jar_membership_is_case_sensitive_without_extraction(self):
        path = write_zip(self.tools / 'case.jar', [('pkg/a.class', b'a'), ('pkg/A.class', b'A')])
        with mock.patch.object(zipfile.ZipFile, 'read', side_effect=AssertionError('no decompression')):
            self.assertTrue(lab._jar_contains(path, 'pkg/A.class'))
            self.assertTrue(lab._jar_contains(path, 'pkg/a.class'))
            self.assertFalse(lab._jar_contains(path, 'PKG/A.class'))
        with self.assertRaises(lab.LabError):
            lab.driver._validated_zip(path, lab.driver.Budget())

    def test_tool_jar_exact_duplicate_rejected(self):
        with self.assertWarns(UserWarning):
            path = write_zip(self.tools / 'duplicate.jar', [('A.class', b'a'), ('A.class', b'b')])
        with self.assertRaises(lab.LabError):
            lab._jar_contains(path, 'A.class')

    def test_tool_jar_metadata_budget_still_applies(self):
        path = write_zip(self.tools / 'bounded.jar', [('A.class', b'a')])
        with mock.patch.object(lab.driver, 'MAX_CENTRAL_BYTES', 1):
            with self.assertRaises(lab.LabError):
                lab._jar_contains(path, 'A.class')

    def test_init_separates_untrusted_and_empty_authoring(self):
        result = self.init()
        out = self.root / 'lab'
        self.assertEqual(result['status'], 'lab_initialized_unverified')
        self.assertEqual(result['selected_apks'], [])
        self.assertIsNone(result['trusted_identity'])
        self.assertEqual(result['patch_status'], 'not_authored')
        self.assertEqual(digest(Path(result['input']['path'])), self.expected)
        self.assertTrue((out / 'untrusted/inventory/extracted/classes.dex').is_file())
        for name in ('source', 'tests', 'stages'):
            self.assertEqual(list((out / name).iterdir()), [])
        self.assertEqual(json.loads((out / 'lab.json').read_text())['input']['sha256'], self.expected)
        self.assertEqual(digest(self.input), self.expected)

    def test_init_apkm(self):
        source = write_zip(self.inputs / 'bundle.apkm', [('base.apk', self.input.read_bytes())])
        result = self.init(archive=source, expected_sha256=digest(source))
        self.assertEqual(result['apk_count'], 1)

    def test_init_rejects_plain_zip_without_apks(self):
        source = write_zip(self.inputs / 'no-apks.zip', [('notes.txt', 'data')])
        with self.assertRaises(lab.LabError):
            self.init(archive=source, expected_sha256=digest(source))
        self.assertFalse((self.root / 'lab/lab.json').exists())

    def test_init_reused_output_preserves_files(self):
        self.init()
        before = (self.root / 'lab/lab.json').read_bytes()
        with self.assertRaises(lab.LabError):
            self.init()
        self.assertEqual((self.root / 'lab/lab.json').read_bytes(), before)

    def test_init_rejects_repository_output(self):
        with self.assertRaises(lab.LabError):
            self.init(out=HERE / 'never-create-generated-lab')
        self.assertFalse((HERE / 'never-create-generated-lab').exists())

    def test_init_requires_existing_parent(self):
        with self.assertRaises(lab.LabError):
            self.init(out=self.root / 'absent/lab')

    def test_init_hash_failure_before_output_creation(self):
        with self.assertRaises(lab.LabError):
            self.init(expected_sha256='0' * 64)
        self.assertFalse((self.root / 'lab').exists())

    def test_init_input_mutated_during_inventory(self):
        inspect = lab.driver.inspect_archive
        def mutate(*args, **kwargs):
            result = inspect(*args, **kwargs)
            self.input.write_bytes(b'mutated')
            return result
        with mock.patch.object(lab.driver, 'inspect_archive', side_effect=mutate):
            with self.assertRaises(lab.LabError):
                self.init()
        self.assertFalse((self.root / 'lab/lab.json').exists())

    def test_init_copied_input_mutated_during_inventory(self):
        inspect = lab.driver.inspect_archive
        def mutate(*args, **kwargs):
            result = inspect(*args, **kwargs)
            Path(args[0]).write_bytes(b'mutated copy')
            return result
        with mock.patch.object(lab.driver, 'inspect_archive', side_effect=mutate):
            with self.assertRaises(lab.LabError):
                self.init()
        self.assertEqual(digest(self.input), self.expected)
        self.assertFalse((self.root / 'lab/lab.json').exists())

    def test_copy_mutation_detected(self):
        destination = self.root / 'copy.apk'
        original_hash = lab.driver._hash_file
        def mutate(path):
            value = original_hash(path)
            if Path(path) == self.input:
                self.input.write_bytes(b'mutated before copy')
            return value
        with mock.patch.object(lab.driver, '_hash_file', side_effect=mutate):
            with self.assertRaisesRegex(lab.LabError, 'changed during copy'):
                lab._copy_input(self.input, self.expected, destination)

    def test_oversize_input_is_rejected_before_hash(self):
        with mock.patch.object(lab.driver, 'MAX_ARCHIVE_BYTES', 2), mock.patch.object(lab.driver, '_hash_file') as hashed:
            with self.assertRaises(lab.LabError):
                self.init()
            hashed.assert_not_called()

    def test_init_traversal_archive_rejected(self):
        bad = write_zip(self.inputs / 'bad.apkm', [('../escape', b'bad')])
        with self.assertRaises(lab.LabError):
            self.init(archive=bad, expected_sha256=digest(bad))
        self.assertFalse((self.root / 'escape').exists())

    def test_invalid_hash_and_desired_change(self):
        for bad in ('', 'z' * 64, 'a' * 63, None):
            with self.subTest(bad=bad), self.assertRaises(lab.LabError):
                self.init(expected_sha256=bad)
        for bad in ('', ' ', '\0hidden', 'x' * 8193, None):
            with self.subTest(bad=bad), self.assertRaises(lab.LabError):
                self.init(desired_change=bad)

    def test_preflight_checks_and_probes_are_separate(self):
        path, config = self.config()
        with mock.patch.object(lab, '_run_bounded', side_effect=self.probe) as run:
            result = lab.preflight(path, self.root / 'preflight')
        self.assertEqual(result['status'], 'preflight_checks_passed')
        self.assertEqual(run.call_count, 8)
        self.assertTrue(all(r['hash_verified'] for r in result['tools'].values()))
        self.assertTrue(all(p['status'] == 'executed' for p in result['probes'].values()))
        self.assertEqual(result['probes']['zipalign']['exit_code'], 2)
        self.assertEqual(result['patch_dependency_closure']['compiler_classpath'], 'hashes_verified_not_executed')
        for call in run.call_args_list:
            self.assertTrue(Path(call.args[0][0]).is_absolute())
        self.assertNotIn('2024-10-15', json.dumps(result))

    def test_preflight_presence_only_stays_blocked(self):
        path, _ = self.config()
        with mock.patch.object(lab, '_run_bounded') as run:
            result = lab.preflight(path, self.root / 'preflight', probe=False)
        run.assert_not_called()
        self.assertEqual(result['status'], 'preflight_blocked')
        self.assertIn('tool_execution_unverified', result['blockers'])

    def test_preflight_missing_or_hash_mismatched_tools_not_executed(self):
        path, config = self.config()
        Path(config['java']['path']).write_bytes(b'changed')
        Path(config['aapt2']['path']).unlink()
        with mock.patch.object(lab, '_run_bounded', side_effect=self.probe) as run:
            result = lab.preflight(path, self.root / 'preflight')
        self.assertIn('missing_invalid_or_changed_tools', result['blockers'])
        self.assertEqual(result['probes']['java']['status'], 'blocked')
        self.assertEqual(result['probes']['d8_jar']['status'], 'blocked')
        self.assertFalse(result['tools']['aapt2']['present'])
        for call in run.call_args_list:
            self.assertNotEqual(call.args[0][0], config['java']['path'])

    def test_preflight_missing_dependency_closure(self):
        path, config = self.config()
        del config['compiler_classpath']
        del config['runtime_classpath']
        path.write_text(json.dumps(config), encoding='utf-8')
        result = lab.preflight(path, self.root / 'preflight', probe=False)
        self.assertIn('patch_compiler_runtime_closure_not_supplied', result['blockers'])

    def test_preflight_mutated_dependency(self):
        path, config = self.config()
        Path(config['dex_classpath'][0]['path']).write_bytes(b'mutated')
        result = lab.preflight(path, self.root / 'preflight', probe=False)
        self.assertIn('missing_invalid_or_changed_dependencies', result['blockers'])
        self.assertFalse(result['required_classes']['dex_classpath'])

    def test_preflight_invalid_config_fields_and_paths(self):
        path, config = self.config()
        for change in (
            lambda c: c.update(schema=2),
            lambda c: c.update(dex_classpath=[]),
            lambda c: c.update(unexpected='not printed'),
            lambda c: c['java'].update(path='java'),
            lambda c: c['java'].update(path=str(self.tools / '*.exe')),
            lambda c: c['java'].update(sha256='wrong'),
            lambda c: c['dex_classpath'].append(c['dex_classpath'][0]),
        ):
            fresh = json.loads(json.dumps(config))
            change(fresh)
            path.write_text(json.dumps(fresh), encoding='utf-8')
            with self.subTest(config=fresh), self.assertRaises(lab.LabError):
                lab.preflight(path, self.root / 'not-created', probe=False)
        self.assertFalse((self.root / 'not-created').exists())

    def test_preflight_duplicate_json_key(self):
        path = self.root / 'duplicate.json'
        path.write_text('{"schema":1,"schema":1}', encoding='utf-8')
        with self.assertRaises(lab.LabError):
            lab.preflight(path, self.root / 'not-created')

    def test_preflight_wrong_jdk_and_probe_failure(self):
        path, _ = self.config()
        def probe(args, **kwargs):
            if Path(args[0]).stem == 'javac':
                raise lab.LabError('untrusted process output must not be printed')
            return 0, 'openjdk version "17.0.8"'
        with mock.patch.object(lab, '_run_bounded', side_effect=probe):
            result = lab.preflight(path, self.root / 'preflight')
        self.assertEqual(result['probes']['java']['status'], 'failed')
        self.assertEqual(result['probes']['javac']['status'], 'failed')
        self.assertNotIn('untrusted process', json.dumps(result))

    def test_preflight_sdk_properties_must_bind_to_tool_locations(self):
        path, config = self.config()
        unrelated = self.tools / 'unrelated.properties'
        unrelated.write_text('Pkg.Revision=36.0.0\n', encoding='utf-8')
        config['build_tools_properties'] = {'path': str(unrelated), 'sha256': digest(unrelated)}
        path.write_text(json.dumps(config), encoding='utf-8')
        result = lab.preflight(path, self.root / 'preflight', probe=False)
        self.assertFalse(result['sdk36']['build_tools_properties'])
        self.assertIn('sdk36_identity_unverified', result['blockers'])

    def test_preflight_detects_mid_probe_tool_mutation(self):
        path, config = self.config()
        def mutate(args, **kwargs):
            Path(config['java']['path']).write_bytes(b'mutated during probe')
            return self.probe(args, **kwargs)
        with mock.patch.object(lab, '_run_bounded', side_effect=mutate):
            result = lab.preflight(path, self.root / 'preflight')
        self.assertIn('tool_changed_during_preflight', result['blockers'])

    def test_preflight_reused_output(self):
        path, _ = self.config()
        lab.preflight(path, self.root / 'preflight', probe=False)
        with self.assertRaises(lab.LabError):
            lab.preflight(path, self.root / 'preflight', probe=False)

    def test_discover_navigation_without_semantic_patch(self):
        with mock.patch.object(lab, '_run_bounded', side_effect=self.mock_decompile) as run:
            result = self.discover()
        self.assertEqual(result['status'], 'navigation_only')
        self.assertEqual(result['dex'], ['classes.dex', 'classes2.dex'])
        self.assertEqual(result['output']['files'], 1)
        matches = result['navigation']['matches']
        self.assertTrue(any(m['kind'] == 'class_path' for m in matches))
        self.assertTrue(any(m['kind'] == 'string' and m['line'] == 2 for m in matches))
        args = run.call_args.args[0]
        self.assertIn('-Xmx1024m', args)
        self.assertIn('--no-res', args)
        self.assertIn('jadx.cli.JadxCLI', args)
        self.assertNotIn('-jar', args)
        self.assertIn('-Djava.awt.headless=true', args)
        self.assertEqual(args[args.index('--config') + 1], 'none')
        overrides = run.call_args.kwargs['env_overrides']
        self.assertEqual(set(overrides), {'JADX_CONFIG_DIR', 'JADX_CACHE_DIR', 'JADX_TMP_DIR'})
        self.assertTrue(all(Path(value).is_relative_to(self.root / 'discover/untrusted/jadx')
                            for value in overrides.values()))
        self.assertEqual(args[args.index('--threads-count') + 1], '1')
        self.assertNotIn(str(self.input), args)
        self.assertEqual(result['invocation']['cwd'], str(HERE))
        self.assertEqual(digest(self.input), self.expected)

    def test_discover_hash_mismatch_before_launch(self):
        with mock.patch.object(lab, '_run_bounded') as run:
            for kwargs in ({'expected_sha256': '0' * 64}, {'jadx_sha256': '0' * 64}):
                with self.subTest(kwargs=kwargs), self.assertRaises(lab.LabError):
                    self.discover(**kwargs)
        run.assert_not_called()
        self.assertFalse((self.root / 'discover').exists())

    def test_discover_rejects_bad_limits_and_search(self):
        cases = ({'timeout': 0}, {'timeout': 301}, {'heap_mb': 2049}, {'heap_mb': True},
                 {'max_files': 20001}, {'max_bytes': 0}, {'search': ''}, {'search': '\n'}, {'search': 'x' * 1025})
        with mock.patch.object(lab, '_run_bounded') as run:
            for kwargs in cases:
                with self.subTest(kwargs=kwargs), self.assertRaises(lab.LabError):
                    self.discover(**kwargs)
        run.assert_not_called()

    def test_discover_rejects_tool_in_input_directory(self):
        untrusted_tool = self.inputs / 'jadx.jar'
        untrusted_tool.write_bytes(b'not trusted')
        with self.assertRaises(lab.LabError):
            self.discover(jadx_jar=untrusted_tool, jadx_sha256=digest(untrusted_tool))

    def test_discover_detects_mutated_input(self):
        def decompile(args, **kwargs):
            self.mock_decompile(args, **kwargs)
            self.input.write_bytes(b'changed')
            return 0, ''
        with mock.patch.object(lab, '_run_bounded', side_effect=decompile):
            with self.assertRaises(lab.LabError):
                self.discover()
        self.assertFalse((self.root / 'discover/discovery.json').exists())

    def test_discover_reused_output_rejected(self):
        with mock.patch.object(lab, '_run_bounded', side_effect=self.mock_decompile) as run:
            self.discover()
            with self.assertRaises(lab.LabError):
                self.discover()
        self.assertEqual(run.call_count, 1)

    def test_discover_no_outputs_is_failure(self):
        with mock.patch.object(lab, '_run_bounded', return_value=(0, '')):
            with self.assertRaises(lab.LabError):
                self.discover()
        self.assertFalse((self.root / 'discover/discovery.json').exists())

    def test_discover_rejects_excess_files_or_bytes(self):
        for index, kwargs in enumerate(({'max_files': 1}, {'max_bytes': 5})):
            def decompile(args, **ignored):
                self.mock_decompile(args, **ignored)
                destination = Path(args[args.index('--output-dir') + 1])
                (destination / 'second.txt').write_text('second', encoding='utf-8')
                return 0, ''
            with mock.patch.object(lab, '_run_bounded', side_effect=decompile):
                with self.subTest(kwargs=kwargs), self.assertRaises(lab.LabError):
                    self.discover(out=self.root / f'discover-{index}', **kwargs)
            self.assertFalse((self.root / f'discover-{index}/discovery.json').exists())

    def test_discover_tool_failure_has_no_success_evidence(self):
        with mock.patch.object(lab, '_run_bounded', side_effect=lab.LabError('arbitrary stdout')):
            with self.assertRaises(lab.LabError):
                self.discover()
        self.assertFalse((self.root / 'discover/discovery.json').exists())

    def test_discover_no_dex_rejected(self):
        path = write_zip(self.inputs / 'resource.apk', [('AndroidManifest.xml', '<manifest package="example.fixture"/>')])
        with mock.patch.object(lab, '_run_bounded') as run, self.assertRaises(lab.LabError):
            self.discover(apk=path, expected_sha256=digest(path))
        run.assert_not_called()

    def test_search_literal_not_regex_and_match_cap(self):
        source = self.root / 'sources'
        source.mkdir()
        (source / 'Test.java').write_text('a.*b\na.*b\na.*b\n', encoding='utf-8')
        result = lab.search_sources(source, 'a.*b', max_matches=2)
        self.assertEqual([r['line'] for r in result['matches']], [1, 2])
        self.assertTrue(result['truncated'])
        self.assertEqual(lab.search_sources(source, 'a.+b')['matches'], [])

    def test_search_long_line_chunk_boundary_and_unicode_line(self):
        source = self.root / 'sources'
        source.mkdir()
        (source / 'Test.java').write_text('ß\n' + 'a' * 65532 + 'target\n', encoding='utf-8')
        result = lab.search_sources(source, 'target')
        self.assertEqual(len(result['matches']), 1)
        self.assertEqual(result['matches'][0]['line'], 2)

    def test_tree_limits_include_directories(self):
        source = self.root / 'outputs'
        source.mkdir()
        (source / 'one').mkdir()
        (source / 'one/two').mkdir()
        (source / 'one/two/three').mkdir()
        with self.assertRaises(lab.LabError):
            lab._tree_budget(source, 1, 1024)

    def test_main_failure_sanitized(self):
        missing = self.inputs / 'private-arbitrary-input.apk'
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = lab.main(['init', str(missing), '--expect-sha256', self.expected,
                             '--desired-change', 'test', '--out', str(self.root / 'out')])
        self.assertEqual(code, 1)
        self.assertNotIn(str(missing), stderr.getvalue())
        self.assertEqual(json.loads(stderr.getvalue())['status'], 'failed')

    def test_cli_parse_errors_do_not_echo_untrusted_values(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            lab.main(['untrusted-control-value'])
        self.assertEqual(raised.exception.code, 2)
        self.assertNotIn('untrusted-control-value', stderr.getvalue())

    def test_main_preflight_blocked_exit(self):
        path, _ = self.config()
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = lab.main(['preflight', '--tools', str(path), '--out', str(self.root / 'check'), '--presence-only'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'preflight_blocked')

    def test_cli_help_isolated_from_untrusted_cwd(self):
        # Plant a module name only in synthetic data; -I prevents its import.
        (self.inputs / 'json.py').write_text('raise RuntimeError("planted module executed")', encoding='utf-8')
        for command in ([], ['init'], ['preflight'], ['discover']):
            result = subprocess.run([sys.executable, '-I', '-B', str(HERE / 'lab.py'), *command, '--help'],
                                    cwd=str(self.inputs), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertIn(b'usage:', result.stdout)
            self.assertNotIn(b'planted', result.stderr)

    def test_real_bounded_runner_uses_trusted_cwd_and_captures_output(self):
        status, output = lab._run_bounded([sys.executable, '-I', '-B', '-c',
            'import os; print(os.getcwd())'], timeout=5)
        self.assertEqual(status, 0)
        self.assertEqual(Path(output.strip()).resolve(), HERE)

    def test_real_bounded_runner_launch_failure_sanitized(self):
        with self.assertRaisesRegex(lab.LabError, '^explicit tool could not be started$'):
            lab._run_bounded([str(self.tools / 'not-a-real-executable')], timeout=1)

    def test_tree_missing_root_and_mocked_link_rejected(self):
        with self.assertRaises(OSError):
            lab._tree_budget(self.root / 'missing-root', 10, 1000)
        with mock.patch.object(Path, 'is_symlink', return_value=True):
            with self.assertRaises(lab.LabError):
                lab._tree_budget(self.inputs, 10, 1000)

    def test_real_bounded_runner_output_limit(self):
        with self.assertRaisesRegex(lab.LabError, 'output limit'):
            lab._run_bounded([sys.executable, '-I', '-B', '-c', 'print("x" * 100000)'],
                             timeout=5, output_limit=1000)

    def test_real_bounded_runner_failure(self):
        with self.assertRaisesRegex(lab.LabError, 'unsuccessfully'):
            lab._run_bounded([sys.executable, '-I', '-B', '-c', 'raise SystemExit(7)'], timeout=5)

    def test_real_bounded_runner_timeout(self):
        with self.assertRaisesRegex(lab.LabError, 'time limit'):
            lab._run_bounded([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(10)'], timeout=1)

    def test_real_bounded_runner_generated_file_limit(self):
        source = self.root / 'runner-output'
        source.mkdir()
        with self.assertRaisesRegex(lab.LabError, 'file/byte limit'):
            lab._run_bounded([sys.executable, '-I', '-B', '-c',
                'from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b"x" * 4096)',
                str(source / 'large.txt')], timeout=5, tree=source, max_bytes=100)


if __name__ == '__main__':
    unittest.main()
