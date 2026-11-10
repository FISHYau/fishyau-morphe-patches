"""Offline selected-set regressions. Run py -I -B with this absolute script path."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('_split_test_fixtures', HERE / 'test_driver.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
driver = fixtures.driver
splitset = driver.SPLITSET


def tree(**kwargs):
    with zipfile.ZipFile(io.BytesIO(fixtures.verification_apk_bytes(**kwargs))) as apk:
        return fixtures.xmltree(apk.read('AndroidManifest.xml'))


def declarations(output):
    return splitset.manifest_fields(splitset.parse_xmltree(output))


class ParserTests(unittest.TestCase):
    def test_observed_uri_ids_raw_empty_and_absence(self):
        output = tree(split='arbitrary.identity', version_name=None)
        fields = declarations(output)
        self.assertIsNone(fields['version_name'])
        fields = declarations(tree(split='arbitrary.identity', version_name=''))
        self.assertEqual(fields['version_name'], '')
        self.assertFalse(fields['has_code'])
        self.assertEqual(fields['min_sdk'], 24)
        self.assertEqual(declarations(tree())['version_name'], '1.2')

    def test_real_sdk36_split_required_id(self):
        # Literal from real SDK36 aapt2 output, independently cross-checked
        # against android.R$attr; do not synthesize this ID from IDS.
        output = tree().replace(
            '    A: package=',
            '    A: http://schemas.android.com/apk/res/android:isSplitRequired(0x01010591)=true\n    A: package=')
        self.assertTrue(declarations(output)['is_split_required'])
        for incorrect in ('0101055e', '01010590'):
            with self.subTest(incorrect=incorrect), self.assertRaises(splitset.SplitSetError):
                declarations(output.replace('isSplitRequired(0x01010591)',
                                            'isSplitRequired(0x' + incorrect + ')'))

    def test_old_typed_hex_primitives_and_prefix_namespace(self):
        output = tree().replace(splitset.ANDROID + ':', 'android:')
        output = output.replace('=7', '=(type 0x10)0x7').replace('=24', '=(type 0x10)0x18')
        self.assertEqual(declarations(output)['min_sdk'], 24)
        output = tree(split='cfg').replace('=false', '=(type 0x12)0x0')
        self.assertIs(declarations(output)['has_code'], False)

    def test_observed_sdk36_negative_priority_is_integer(self):
        # Exact offending attribute row from hash-pinned SDK36 aapt2 on the
        # selected Termius base (diagnostic row 475); surrounding tree is synthetic.
        row = ('                A: http://schemas.android.com/apk/res/android:'
               'priority(0x0101001c)=-500\n')
        output = (tree() + '          E: activity (line=0)\n'
                  + '              E: intent-filter (line=0)\n' + row)
        raw = splitset.parse_xmltree(output)
        priority = raw['root']['children'][-1]['children'][0]['children'][0][
            'attributes'][splitset.A + 'priority']
        self.assertEqual(priority, {'type': 'integer', 'value': -500,
                                    'raw': None, 'resource_id': '0101001c'})
        expected = declarations(tree())
        expected['application_children'] = ['activity']
        self.assertEqual(splitset.manifest_fields(raw), expected)

    def test_negative_decimal_bounds_raw_and_malformed_encodings(self):
        for value in (-1, -500, -2147483648):
            with self.subTest(value=value):
                self.assertEqual(splitset._value(str(value)),
                                 {'type': 'integer', 'value': value, 'raw': None})
        self.assertEqual(splitset._value('-500 (Raw: "-500")'),
                         {'type': 'integer', 'value': -500, 'raw': '-500'})
        for text in ('-2147483649', '-99999999999', '-0', '-00', '-0500',
                     '--500', '+500', '-0x1f4', '-500.0', '-5e2', ' -500', '-500 ',
                     '-500garbage', '-500 (Raw: -500)'):
            with self.subTest(text=text), self.assertRaises(splitset.SplitSetError):
                splitset._value(text)

    def test_signed_integer_does_not_weaken_required_types_or_sdk_range(self):
        output = tree()
        for value in (output.replace('=24', '=-500'),
                      output.replace('=24', '="-500"'),
                      output.replace('=24', '=@0x7f010001'),
                      output.replace('="1.2"', '=-500'),
                      tree(split='cfg').replace('=false', '=-500'),
                      tree(root_attrs='android:isSplitRequired="true"').replace('=true', '=-500')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)

    def test_matching_raw_string_is_preserved(self):
        output = tree().replace('="1.2"', '="1.2" (Raw: "1.2")')
        raw = splitset.parse_xmltree(output)
        self.assertEqual(raw['root']['attributes']['{' + splitset.ANDROID + '}versionName']['raw'], '1.2')

    def test_duplicate_or_wrong_namespace_and_id(self):
        output = tree()
        attr = next(line for line in output.splitlines() if 'versionName' in line)
        for value in (output.replace(attr, attr + '\n' + attr),
                      output.replace('versionName(0x0101021c)', 'versionName(0x0101021b)'),
                      output.replace(splitset.ANDROID + ':versionName', 'evil:versionName'),
                      output.replace(splitset.ANDROID + ':versionName', 'versionName'),
                      output.replace('N: android=', 'N: android=wrong/'),
                      output.replace('="1.2"', '="1.2" (Raw: "other")')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)

    def test_framework_ids_cannot_hide_presence_or_alias_other_attributes(self):
        output = tree()
        attr = next(line for line in output.splitlines() if 'versionName' in line)
        for value in (output.replace('versionName(0x0101021c)', 'versionName'),
                      output.replace('versionName(0x0101021c)', 'innocent(0x0101021c)'),
                      output.replace(attr, attr + '\n    A: innocent(0x0101021c)="hidden"'),
                      output.replace(attr, attr + '\n    A: x(0x7f010001)=1\n    A: y(0x7f010001)=2')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)
        raw = splitset.parse_xmltree(output)
        self.assertEqual(raw['root']['attributes'][splitset.A + 'versionName']['resource_id'], '0101021c')

    def test_nested_manifest_and_misplaced_unnamespaced_target_fail(self):
        for suffix in ('      E: manifest (line=0)\n',
                       '        A: configForSplit="feature"\n'):
            with self.subTest(suffix=suffix), self.assertRaises(splitset.SplitSetError):
                declarations(tree() + suffix)

    def test_hierarchy_failures(self):
        output = tree()
        app = next(line for line in output.splitlines() if 'E: application ' in line)
        for value in ('', output + '  E: manifest (line=0)\n',
                      output.replace(app, '    E: application (line=0)'),
                      output.replace(app, app + '\n' + app),
                      output + '    A: package="late"\n',
                      output.replace('    A: package', '\tA: package'),
                      output.replace(app, '      C: "unexpected"'),
                      output.replace(app, '      N: custom=other (line=0)')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)

    def test_bounds_and_corrupt_text(self):
        for value in (tree() + '\x00', tree() + '�'):
            with self.assertRaises(splitset.SplitSetError):
                splitset.parse_xmltree(value)
        with mock.patch.object(splitset, 'MAX_TREE_BYTES', 20), self.assertRaises(splitset.SplitSetError):
            splitset.parse_xmltree(tree())
        with mock.patch.object(splitset, 'MAX_NODES', 1), self.assertRaises(splitset.SplitSetError):
            splitset.parse_xmltree(tree())
        with mock.patch.object(splitset, 'MAX_DEPTH', 1), self.assertRaises(splitset.SplitSetError):
            splitset.parse_xmltree(tree())

    def test_unresolved_wrong_types_misplaced_or_major_fail(self):
        output = tree()
        for value in (output.replace('="1.2"', '=@0x7f010001'),
                      output.replace('="1.2"', '=17'),
                      output.replace('=24', '="VanillaIceCream"'),
                      tree(root_attrs='android:versionCodeMajor="0"'),
                      tree(app_attrs='android:isFeatureSplit="true"'),
                      tree(app_attrs='android:minSdkVersion="27"')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)

    def test_required_metadata_types(self):
        original = tree()
        metadata = ('          E: meta-data (line=0)\n'
                    '            A: android:name(0x01010003)="com.android.vending.splits.required"\n'
                    '            A: android:value(0x01010024)=true\n')
        self.assertTrue(declarations(original + metadata)['metadata_splits_required'])
        for value in (original + metadata + metadata,
                      original + metadata.replace('=true', '=@0x7f010001'),
                      original + metadata.replace('android:value(0x01010024)=true', 'android:resource(0x01010025)=@0x7f010001')):
            with self.assertRaises(splitset.SplitSetError):
                declarations(value)

    def test_unknown_or_duplicate_types_fail_explicitly(self):
        for value in ('feature__abi', 'base__abi,base__abi', 'base__abi, base__density', ',base__abi'):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(tree(root_attrs='android:requiredSplitTypes="' + value + '"'))


class SelectedSetTests(unittest.TestCase):
    setUp = fixtures.VerificationTests.setUp
    apk = fixtures.VerificationTests.apk
    respond = fixtures.VerificationTests.respond
    verify = fixtures.VerificationTests.verify

    def test_negative_version_code_cannot_pass_identity_verification(self):
        self.base.write_bytes(fixtures.verification_apk_bytes(version='-500'))
        with self.assertRaisesRegex(driver.DriverError, 'explicit valid package/version/split identity'):
            self.verify([self.base], abi='none')
        self.assertFalse(self.out.exists())
        self.assertFalse(any(call.args[0][0] == 'JAVA' for call in self.run.call_args_list))

    def test_absent_companion_version_inherits_only_pinned_base(self):
        self.split.write_bytes(fixtures.verification_apk_bytes(split='unrelated.filename', version_name=None))
        result = self.verify([self.split, self.base])
        companion = result['apks'][0]
        self.assertEqual(result['split_set'], 'base_config_set')
        self.assertIsNone(companion['manifest_declarations']['version_name'])
        self.assertNotIn('{' + splitset.ANDROID + '}versionName', companion['raw_manifest']['root']['attributes'])
        self.assertEqual(companion['manifest']['version_name'], '1.2')
        self.assertEqual(companion['effective_manifest']['version_name'], '1.2')
        self.assertEqual(result['topology']['base'], str(self.base))
        self.assertEqual(driver.validate_split_set(result['apks'], abi='arm64-v8a', density='nodpi'), result['topology'])

    def test_empty_or_conflicting_companion_version_and_absent_base_fail(self):
        for name in ('', 'other'):
            self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', version_name=name))
            with self.subTest(name=name), self.assertRaises(driver.DriverError):
                self.verify()
            self.assertFalse(self.out.exists())
        self.base.write_bytes(fixtures.verification_apk_bytes(version_name=None))
        self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', version_name=None))
        with self.assertRaises(driver.DriverError):
            self.verify()

    def test_declared_abi_density_required_coverage(self):
        self.base.write_bytes(fixtures.verification_apk_bytes(
            root_attrs='android:requiredSplitTypes="base__abi,base__density"'))
        self.split.write_bytes(fixtures.verification_apk_bytes(
            split='a', root_attrs='android:splitTypes="base__abi"'))
        with self.assertRaisesRegex(driver.DriverError, 'required split types'):
            self.verify(density='xhdpi')
        density = self.apk('not-a-density-filename.apk', split='b', native=False,
                           root_attrs='android:splitTypes="base__density"')
        result = self.verify([self.base, density, self.split], density='xhdpi')
        self.assertEqual(result['topology']['provided_split_types'], ['base__abi', 'base__density'])
        self.assertIn('not_resource', result['topology']['coverage'])

    def test_abi_type_provider_must_own_native_payload(self):
        companion = self.apk('empty.apk', split='empty', native=False,
                             root_attrs='android:splitTypes="base__abi"')
        with self.assertRaisesRegex(driver.DriverError, 'provider'):
            self.verify([self.base, self.split, companion])

    def test_feature_dependencies_and_companion_components_fail(self):
        for extra in ('android:isFeatureSplit="true"', 'android:configForSplit="feature"'):
            self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', root_attrs=extra))
            with self.subTest(extra=extra), self.assertRaises(driver.DriverError):
                self.verify()
        for element in ('activity', 'service', 'provider', 'receiver', 'uses-library'):
            data = fixtures.verification_apk_bytes(split='cfg')
            with zipfile.ZipFile(io.BytesIO(data)) as apk:
                manifest = apk.read('AndroidManifest.xml').replace(b'/></manifest>',
                    ('><' + element + '/></application></manifest>').encode())
            self.split.write_bytes(fixtures.zip_bytes([('AndroidManifest.xml', manifest)]))
            with self.subTest(element=element), self.assertRaises(driver.DriverError):
                self.verify(abi='none')
        self.base.write_bytes(fixtures.verification_apk_bytes())
        with zipfile.ZipFile(self.base) as apk:
            manifest = apk.read('AndroidManifest.xml').replace(b'</manifest>',
                b'<uses-split android:name="feature"/></manifest>')
        self.base.write_bytes(fixtures.zip_bytes([('AndroidManifest.xml', manifest), ('classes.dex', b'dex')]))
        with self.assertRaisesRegex(driver.DriverError, 'dependencies'):
            self.verify([self.base], abi='none')

    def test_nested_companion_components_and_unknown_declarations_fail(self):
        original = tree(split='cfg')
        nested = ('          E: meta-data (line=0)\n'
                  '            A: android:name(0x01010003)="ordinary.metadata"\n'
                  '            A: android:value(0x01010024)=3\n')
        for value in (original + nested + '              E: activity (line=0)\n',
                      original + nested + '              E: uses-library (line=0)\n',
                      tree(split='cfg', root_attrs='android:unknownSplitBehavior="true"'),
                      tree(root_attrs='android:isolatedSplits="true"'),
                      tree(app_attrs='android:splitName="feature"')):
            with self.subTest(value=value), self.assertRaises(splitset.SplitSetError):
                declarations(value)
        # Standard inert leaf metadata (including integer values) stays valid.
        self.assertEqual(declarations(original + nested)['application_children'], ['meta-data'])

    def test_required_singleton_missing_hascode_and_explicit_base_target(self):
        self.base.write_bytes(fixtures.verification_apk_bytes(root_attrs='android:isSplitRequired="true"'))
        with self.assertRaisesRegex(driver.DriverError, 'requires selected'):
            self.verify([self.base], abi='none')
        with zipfile.ZipFile(io.BytesIO(fixtures.verification_apk_bytes(split='cfg'))) as apk:
            manifest = apk.read('AndroidManifest.xml').replace(b'android:hasCode="false" ', b'')
        self.split.write_bytes(fixtures.zip_bytes([('AndroidManifest.xml', manifest)]))
        with self.assertRaisesRegex(driver.DriverError, 'hasCode=false'):
            self.verify(abi='none')
        self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', root_attrs='configForSplit="feature"'))
        with self.assertRaisesRegex(driver.DriverError, 'target base'):
            self.verify()
        self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', root_attrs='configForSplit=""'))
        self.assertEqual(self.verify()['topology']['members'][1]['target'], 'base')

    def test_companion_application_class_and_policy_override_fail(self):
        for attrs in ('android:name="org.example.app.Hook"', 'android:extractNativeLibs="false"'):
            self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', app_attrs=attrs))
            with self.subTest(attrs=attrs), self.assertRaises(driver.DriverError):
                self.verify()

    def test_companion_code_nested_case_variant_and_noncanonical_base_dex_fail(self):
        for name in ('classes.dex', 'nested/CLASSES.DEX', 'anything.dex'):
            self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg', extra=[(name, b'dex')]))
            with self.subTest(name=name), self.assertRaises(driver.DriverError):
                self.verify()
        self.split.write_bytes(fixtures.verification_apk_bytes(split='cfg'))
        for name in ('classes3.dex', 'nested/classes2.dex', 'Classes2.dex', 'classes1.dex'):
            self.base.write_bytes(fixtures.verification_apk_bytes(extra=[(name, b'dex')]))
            with self.subTest(name=name), self.assertRaises(driver.DriverError):
                self.verify()

    def test_native_base_fails_split_mode_but_valid_standalone_survives(self):
        self.base.write_bytes(fixtures.verification_apk_bytes(native=True))
        with self.assertRaisesRegex(driver.DriverError, 'non-native'):
            self.verify()
        result = self.verify([self.base])
        self.assertEqual(result['split_set'], 'standalone')
        native = result['apks'][0]['native_libraries'][0]
        self.assertEqual(native['elf_machine'], 183)
        self.assertIsNone(native['zip_alignment_bytes'])
        self.assertFalse(native['direct_load_policy_checked'])

    def test_last_signer_cannot_mutate_earlier_member(self):
        original = self.respond
        def mutate(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == 'JAVA' and args[-1] == str(self.split):
                self.base.write_bytes(self.base.read_bytes() + b'changed')
            return result
        self.run.side_effect = mutate
        with self.assertRaisesRegex(driver.DriverError, 'changed'):
            self.verify()
        self.assertFalse(self.out.exists())

    def native_zip(self, *, stored=True, aligned=True, corrupt=False):
        with zipfile.ZipFile(self.split) as apk:
            manifest = apk.read('AndroidManifest.xml')
            header = apk.read('lib/arm64-v8a/arbitrary-name.so')
        if corrupt:
            header = header[:18] + b'\x3e\x00' + header[20:]
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as apk:
            apk.writestr('AndroidManifest.xml', manifest)
            info = zipfile.ZipInfo('lib/arm64-v8a/never-infer-split-role.so')
            info.compress_type = zipfile.ZIP_STORED if stored else zipfile.ZIP_DEFLATED
            if aligned:
                padding = (-(stream.tell() + 30 + len(info.filename))) % 4096
                if padding < 4:
                    padding += 4096
                info.extra = struct.pack('<HH', 0xcafe, padding - 4) + bytes(padding - 4)
            apk.writestr(info, header)
        self.split.write_bytes(stream.getvalue())

    def test_direct_load_native_storage_alignment_and_elf(self):
        self.base.write_bytes(fixtures.verification_apk_bytes(app_attrs='android:extractNativeLibs="false"'))
        original = self.split.read_bytes()
        for stored, aligned, corrupt in ((False, True, False), (True, False, False), (True, True, True)):
            self.split.write_bytes(original)
            self.native_zip(stored=stored, aligned=aligned, corrupt=corrupt)
            with self.subTest(stored=stored, aligned=aligned, corrupt=corrupt), self.assertRaises(driver.DriverError):
                self.verify()
            self.assertFalse(self.out.exists())
        self.split.write_bytes(original)
        self.native_zip()
        result = self.verify()
        native = result['apks'][1]['native_libraries'][0]
        self.assertEqual(native['data_offset'] % 4096, 0)
        self.assertTrue(native['direct_load_policy_checked'])
        self.assertEqual(native['zip_alignment_bytes'], 4096)
        self.assertTrue(native['zip_data_aligned_4096'])
        self.assertEqual(native['runtime_compatibility'], 'not_proven')

    def test_badging_cannot_prove_absence_and_xmltree_disagreement_fails(self):
        original = self.respond
        def drift(args, **kwargs):
            stdout, stderr = original(args, **kwargs)
            if args[0] == 'AAPT2' and args[2] == 'xmltree':
                stdout = stdout.replace('="1.2"', '="2.0"')
            return stdout, stderr
        self.run.side_effect = drift
        with self.assertRaisesRegex(driver.DriverError, 'disagree'):
            self.verify()
        self.assertFalse(self.out.exists())

    def test_standalone_without_native_retains_identity_and_no_abi_assumption(self):
        result = self.verify([self.base], abi='none')
        self.assertEqual(result['topology']['min_sdk'], 24)
        self.assertEqual(result['apks'][0]['manifest']['version_name'], '1.2')
        self.assertEqual(result['apks'][0]['native_libraries'], [])


if __name__ == '__main__':
    unittest.main(verbosity=2)
