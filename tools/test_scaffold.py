"""Offline file-policy regressions; no Gradle or Android code is executed."""
import importlib.util
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('check_scaffold', Path(__file__).with_name('check_scaffold.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ScaffoldTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        source = Path(__file__).resolve().parents[1]
        for name in ('gradle/wrapper/gradle-wrapper.jar', 'gradle/wrapper/gradle-wrapper.properties', 'patches/build.gradle.kts', 'LICENSE', 'NOTICE', 'README.md', 'CONTRIBUTING.md'):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, target)

    def test_reviewed_scaffold_passes(self):
        self.assertEqual(module.check(self.root)['status'], 'scaffold_file_policy_passed')

    def test_app_and_cache_payloads_rejected(self):
        for name in ('input.apkm', 'code.dex', 'helper.jar', '.env', 'local.properties'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text('fixture')
                with self.assertRaises(ValueError):
                    module.check(self.root)
                path.unlink()

    def test_nested_git_and_generated_directories_rejected(self):
        for name in ('build', 'extracted', 'inputs', 'evidence', '.gradle', 'child/.git'):
            with self.subTest(name=name):
                path = self.root / name
                path.mkdir(parents=True)
                with self.assertRaises(ValueError):
                    module.check(self.root)
                path.rmdir()

    def test_case_variants_of_private_names_rejected(self):
        for name in ('BUILD', 'Evidence', '.ENV', 'LOCAL.PROPERTIES', '.GIT'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_text('fixture')
                with self.assertRaises(ValueError):
                    module.check(self.root)
                path.unlink()

    def test_enumeration_errors_fail_closed(self):
        def inaccessible(root, **kwargs):
            kwargs['onerror'](PermissionError('synthetic inaccessible directory'))
            return iter(())
        with mock.patch.object(module.os, 'walk', side_effect=inaccessible):
            with self.assertRaisesRegex(ValueError, 'fully enumerated'):
                module.check(self.root)

    def test_duplicate_or_commented_distribution_pins_rejected(self):
        path = self.root / 'gradle/wrapper/gradle-wrapper.properties'
        original = path.read_text(encoding='utf-8')
        for changed in (
            original + '\ndistributionUrl=https://example.invalid/gradle-9.8.2-bin.zip\n',
            original.replace('distributionSha256Sum=', '# distributionSha256Sum='),
            original.replace('services.gradle.org', 'example.invalid'),
        ):
            with self.subTest(changed=changed):
                path.write_text(changed, encoding='utf-8')
                with self.assertRaisesRegex(ValueError, 'distribution pin'):
                    module.check(self.root)

    def test_wrapper_corruption_rejected(self):
        (self.root / 'gradle/wrapper/gradle-wrapper.jar').write_bytes(b'not a wrapper')
        with self.assertRaisesRegex(ValueError, 'wrapper JAR'):
            module.check(self.root)

    def test_wrong_distribution_rejected(self):
        (self.root / 'gradle/wrapper/gradle-wrapper.properties').write_text('distributionUrl=wrong')
        with self.assertRaisesRegex(ValueError, 'distribution pin'):
            module.check(self.root)

    def test_wrong_branding_rejected(self):
        (self.root / 'patches/build.gradle.kts').write_text('name = "Other name"')
        with self.assertRaisesRegex(ValueError, 'identity'):
            module.check(self.root)


if __name__ == '__main__':
    unittest.main()
