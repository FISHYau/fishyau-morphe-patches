"""Synthetic offline patchdev tests. No SDK, cache, signing material or device access."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('patchdev_test_subject', HERE / 'patchdev.py')
p = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = p
spec.loader.exec_module(p)


class PatchdevTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='morphe-patchdev-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def file(self, name, data=b'fixture'):
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return target

    def apk(self, name='input.apk', entries=None):
        target = self.root / name
        with zipfile.ZipFile(target, 'x') as z:
            for n, value in (entries or {'classes.dex': b'dex data'}).items():
                z.writestr(n, value)
        return target

    def config(self):
        apk = self.apk()
        bundle = self.root / 'development.jar'
        with zipfile.ZipFile(bundle, 'x') as jar:
            jar.writestr('Assertions.class', b'authored assertion')
        runner = self.file('runner.jar')
        source = self.file('source.kt', b'authored')
        return dict(trusted_code=True, patcher_version='2.3.0', patches=['Fixture'], options={},
                    apks=[p.record(apk)], bundle=p.record(bundle), runner=p.record(runner),
                    assertion_class='Assertions', assertion_sha256=p.hashlib.sha256(b'authored assertion').hexdigest(),
                    out=str(self.root / 'apply'), jdk=str(self.root), cache_root=str(self.root),
                    verification={'aapt2': str(self.file('aapt2')), 'signer_jar': str(self.file('apksigner.jar'))},
                    source_hashes=[p.record(source)])

    def test_jdk21_ga_and_maintenance_versions_accepted_not_other_major(self):
        suffix = '.exe' if os.name == 'nt' else ''
        root = self.root / 'jdk'
        self.file('jdk/bin/java' + suffix)
        self.file('jdk/bin/javac' + suffix)
        for version in ('21', '21.0.13'):
            with self.subTest(version=version), patch.object(p, 'run', return_value='openjdk version "' + version + '"'):
                self.assertIn('java', p.jdk({'jdk': str(root)}, self.root))
        with patch.object(p, 'run', return_value='openjdk version "22"'):
            with self.assertRaises(p.DriverError):
                p.jdk({'jdk': str(root)}, self.root)

    def test_relative_path_rejected(self):
        with self.assertRaises(p.DriverError): p.absolute('relative')

    def test_unsafe_classpath_path_rejected(self):
        with self.assertRaises(p.DriverError): p.absolute(self.root / ('bad' + os.pathsep + 'path'))

    def test_fresh_directory(self):
        self.assertEqual(p.fresh(self.root / 'new'), self.root / 'new')

    def test_reused_output_rejected(self):
        with self.assertRaises(p.DriverError): p.fresh(self.root)

    def test_missing_parent_rejected(self):
        with self.assertRaises(p.DriverError): p.fresh(self.root / 'missing/new')

    def test_repository_output_rejected(self):
        with self.assertRaises(p.DriverError): p.fresh(HERE / 'never-created-test-dir')

    def test_hash_pin(self):
        f = self.file('pinned')
        self.assertEqual(p.pinned(f, p.digest(f)), f)
        with self.assertRaises(p.DriverError): p.pinned(f, '0' * 64)

    def test_hash_format(self):
        with self.assertRaises(p.DriverError): p.pinned(self.file('pin'), 'BAD')

    def test_input_mutation_detected(self):
        f = self.file('input'); records = [p.record(f)]; f.write_bytes(b'changed')
        with self.assertRaises(p.DriverError): p.unchanged(records)

    def test_json_duplicate_rejected(self):
        f = self.file('duplicate.json', b'{"a":1,"a":2}')
        with self.assertRaises(p.DriverError): p.read_json(f)

    def test_json_array_rejected(self):
        with self.assertRaises(p.DriverError): p.read_json(self.file('array.json', b'[]'))

    def test_json_bounded(self):
        with self.assertRaises(p.DriverError): p.read_json(self.file('large.json', b' ' * (1024 * 1024 + 1)))

    def test_missing_closure_rejected(self):
        with self.assertRaises(p.DriverError): p.closure(self.root)

    def test_sources_must_be_external(self):
        with self.assertRaises(p.DriverError): p.sources([str(HERE / 'GenericPatchRunner.kt')])

    def test_sources_must_be_unique(self):
        f = str(self.file('a.kt'))
        with self.assertRaises(p.DriverError): p.sources([f, f])

    def test_explicit_sources_required(self):
        for values in ([], 'wildcard.kt', ['missing.kt']):
            with self.assertRaises((p.DriverError, OSError)): p.sources(values)

    def test_canonical_code_apk_accepted(self):
        p.check_code_apk(self.apk(entries={'classes.dex': b'dex', 'classes2.dex': b'dex2'}))

    def test_native_rejected(self):
        with self.assertRaises(p.DriverError):
            p.check_code_apk(self.apk(entries={'classes.dex': b'dex', 'lib/x86/a.so': b'no'}))

    def test_nested_dex_rejected(self):
        with self.assertRaises(p.DriverError):
            p.check_code_apk(self.apk(entries={'classes.dex': b'dex', 'assets/hidden.dex': b'no'}))

    def test_invalid_dex_names(self):
        for i, name in enumerate(('classes1.dex', 'classes02.dex', 'classes0.dex')):
            with self.assertRaises(p.DriverError):
                p.check_code_apk(self.apk(name=f'bad{i}.apk', entries={'classes.dex': b'dex', name: b'no'}))

    def test_complete_contiguous_original_dex_required(self):
        with self.assertRaises(p.DriverError):
            p.check_code_apk(self.apk(entries={'classes.dex': b'dex', 'classes3.dex': b'gap'}))

    def test_case_variant_dex_rejected(self):
        with self.assertRaises(p.DriverError):
            p.check_code_apk(self.apk(entries={'classes.dex': b'dex', 'assets/hidden.DEX': b'hidden'}))

    def test_no_primary_dex_rejected(self):
        with self.assertRaises(p.DriverError): p.check_code_apk(self.apk(entries={'classes2.dex': b'only'}))

    def test_trust_required(self):
        with self.assertRaises(p.DriverError): p.patch_build({'trusted_code': False})
        with self.assertRaises(p.DriverError): p.apply({'trusted_code': False})

    def test_version_pin_required(self):
        with self.assertRaises(p.DriverError): p.apply({'trusted_code': True, 'patcher_version': '1.8.0'})

    def test_selection_failures_before_tool_execution(self):
        c = self.config()
        with patch.object(p, 'run', side_effect=AssertionError('must not execute')):
            for names in ([], ['Fixture', 'Fixture'], [''], 'Fixture'):
                with self.assertRaises(p.DriverError): p.apply({**c, 'patches': names})

    def test_options_rejected(self):
        with self.assertRaises(p.DriverError): p.apply({**self.config(), 'options': {'anything': True}})

    def test_multiple_apks_rejected(self):
        c = self.config()
        with self.assertRaises(p.DriverError): p.apply({**c, 'apks': c['apks'] * 2})

    def test_assertion_pin_checked_before_jvm(self):
        with self.assertRaises(p.DriverError): p.apply({**self.config(), 'assertion_sha256': '0' * 64})

    def test_fresh_verifier_required_and_changed_pin_rejected(self):
        c = self.config()
        def verify(*args, **kwargs):
            Path(c['apks'][0]['path']).write_bytes(b'mutated during fresh verification')
            return {'expected': {}}
        with patch.object(p, 'jdk', return_value={'java': self.file('java'), 'javac': self.file('javac')}), \
             patch.object(p, 'closure', return_value={'runtime': [], 'compiler': []}), \
             patch.object(p.driver, 'verify_apks', side_effect=verify) as v, \
             patch.object(p, 'run', side_effect=AssertionError('must not invoke runner')):
            with self.assertRaises(p.DriverError): p.apply(c)
            v.assert_called_once()
        self.assertFalse((self.root / 'apply/apply.json').exists())

    def test_verification_failure_blocks_runner(self):
        c = self.config()
        with patch.object(p, 'jdk', return_value={'java': self.file('java'), 'javac': self.file('javac')}), \
             patch.object(p, 'closure', return_value={'runtime': [], 'compiler': []}), \
             patch.object(p.driver, 'verify_apks', side_effect=p.DriverError('verification rejected')), \
             patch.object(p, 'run', side_effect=AssertionError('must not invoke runner')):
            with self.assertRaises(p.DriverError): p.apply(c)
        self.assertFalse((self.root / 'apply/apply.json').exists())

    def test_jdk_version_checked(self):
        root = self.root / 'jdk'; suffix = '.exe' if os.name == 'nt' else ''
        self.file(f'jdk/bin/java{suffix}'); self.file(f'jdk/bin/javac{suffix}')
        with patch.object(p, 'run', return_value='openjdk version "17.0.1"'):
            with self.assertRaises(p.DriverError): p.jdk({'jdk': str(root)}, self.root)

    def test_tool_failure_sanitized(self):
        fake = self.file('not-executable')
        with patch.object(p.subprocess, 'Popen', side_effect=OSError('secret-detail')):
            with patch.object(p.sys, 'stderr') as stderr:
                status = p.main(['fixture-build', '--config', str(self.file('c.json', json.dumps({'out': str(self.root / 'newout'), 'jdk': str(fake)}).encode()))])
                self.assertEqual(status, 2)
                self.assertNotIn('secret-detail', str(stderr.write.call_args_list))

    def test_subprocess_timeout_is_bounded(self):
        with self.assertRaises(p.DriverError):
            p.run([sys.executable, '-I', '-B', '-c', 'import time; time.sleep(2)'], self.root, timeout=0.1)

    def test_subprocess_output_is_bounded(self):
        with self.assertRaises(p.DriverError):
            p.run([sys.executable, '-I', '-B', '-c', 'print("x" * 2048)'], self.root, limit=1024)

    def test_subprocess_failure_hides_diagnostics(self):
        with self.assertRaises(p.DriverError) as error:
            p.run([sys.executable, '-I', '-B', '-c', 'import sys; print("private diagnostic"); sys.exit(2)'], self.root)
        self.assertNotIn('private diagnostic', str(error.exception))

    def test_subprocess_uses_trusted_cwd(self):
        result = p.run([sys.executable, '-I', '-B', '-c', 'from pathlib import Path; print(Path.cwd())'], self.root)
        self.assertEqual(Path(result.strip()), self.root)

    def test_file_write_is_exclusive(self):
        target = self.root / 'evidence.json'; p.write_json(target, {'schema': 1})
        with self.assertRaises(FileExistsError): p.write_json(target, {'schema': 2})


if __name__ == '__main__':
    unittest.main()
