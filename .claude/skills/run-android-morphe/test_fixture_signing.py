"""Offline tests of disposable fixture-only signing lifecycle; no real keys."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_test_fixture_signing', HERE / 'fixture_signing.py')
signing = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = signing
spec.loader.exec_module(signing)


class FixtureSigningTests(unittest.TestCase):
    def test_password_never_in_argv_or_public_evidence_and_context_clears_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            home = root / 'jdk'
            (home / 'bin').mkdir(parents=True)
            (home / 'bin' / ('keytool.exe' if os.name == 'nt' else 'keytool')).touch()
            output = root / 'signing'
            driver = mock.Mock()
            driver.external_output.side_effect = lambda path: path
            def run(argv, **kwargs):
                variable = argv[argv.index('-storepass:env') + 1]
                self.assertNotIn(os.environ[variable], argv)
                if '-genkeypair' in argv:
                    (output / 'fixture-only.p12').write_bytes(b'synthetic')
                else:
                    (output / 'fixture-certificate.der').write_bytes(b'public certificate fixture')
                return '', ''
            driver.run_tool.side_effect = run
            with mock.patch.object(signing, '_driver', return_value=driver):
                with signing.fixture_key(home, output) as public:
                    name = public['ks_pass_env']
                    self.assertIn(name, os.environ)
                    self.assertNotIn(os.environ[name], (output / 'public-signing.json').read_text())
                    self.assertTrue(public['fixture_only'])
                self.assertNotIn(name, os.environ)
            self.assertEqual(driver.run_tool.call_count, 2)
            self.assertEqual(json.loads((output / 'public-signing.json').read_text()), public)

    def test_failure_clears_temporary_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'jdk' / 'bin').mkdir(parents=True)
            (root / 'jdk' / 'bin' / ('keytool.exe' if os.name == 'nt' else 'keytool')).touch()
            driver = mock.Mock()
            driver.external_output.side_effect = lambda path: path
            driver.run_tool.side_effect = RuntimeError('synthetic failure')
            previous = set(os.environ)
            with mock.patch.object(signing, '_driver', return_value=driver):
                with self.assertRaises(RuntimeError):
                    with signing.fixture_key(root / 'jdk', root / 'signing'):
                        self.fail('must not yield after generation failure')
            self.assertEqual(set(os.environ), previous)
            self.assertFalse((root / 'signing' / 'public-signing.json').exists())


if __name__ == '__main__':
    unittest.main()
