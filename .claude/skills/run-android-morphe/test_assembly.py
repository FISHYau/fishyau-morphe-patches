"""Synthetic offline assembly tests; no real signing material or tools are used.

Run with Python -I -B from a trusted working directory. Temporary fixtures live
outside the publication repository and use NEW output directories per test.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('_tested_android_assembly', HERE / 'assembly.py')
assembly = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = assembly
SPEC.loader.exec_module(assembly)
driver = assembly.driver


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dex_bytes(label):
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<III', data, 32, 112 + len(label), 112, 0x12345678)
    return bytes(data) + label


def write_apk(path, entries):
    with zipfile.ZipFile(path, 'w') as archive:
        archive.comment = b'fixture comment'
        for name, content, method in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = method
            archive.writestr(info, content)


def with_signing_block(path, padding=b''):
    data = path.read_bytes()
    end = len(data) - 22 - len(b'fixture comment')
    central = struct.unpack_from('<L', data, end + 16)[0]
    # A framed synthetic signing block: assembly only handles/removes framing;
    # real certificate verification is delegated to the mandatory verifier.
    body = b'fixture block'
    size = len(body) + 24
    block = struct.pack('<Q', size) + body + struct.pack('<Q', size) + b'APK Sig Block 42'
    block = padding + block
    data = bytearray(data[:central] + block + data[central:])
    struct.pack_into('<L', data, end + len(block) + 16, central + len(block))
    path.write_bytes(data)


class AssemblyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='android-assembly-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.original = self.root / 'original.apk'
        self.entries = [
            ('AndroidManifest.xml', b'\x03\x00\x08\x00synthetic binary manifest', zipfile.ZIP_DEFLATED),
            ('classes.dex', dex_bytes(b'original'), zipfile.ZIP_STORED),
            ('classes2.dex', dex_bytes(b'unchanged'), zipfile.ZIP_DEFLATED),
            ('resources.arsc', b'unchanged resources', zipfile.ZIP_STORED),
            ('lib/arm64-v8a/libfixture.so', b'unchanged native', zipfile.ZIP_STORED),
            ('assets/data.txt', b'data', zipfile.ZIP_DEFLATED),
            ('META-INF/', b'', zipfile.ZIP_STORED),
            ('META-INF/MANIFEST.MF', b'old manifest', zipfile.ZIP_DEFLATED),
            ('META-INF/OLD.SF', b'old signature', zipfile.ZIP_DEFLATED),
            ('META-INF/OLD.RSA', b'old cert', zipfile.ZIP_DEFLATED),
            ('META-INF/old.dsa', b'old cert', zipfile.ZIP_DEFLATED),
            ('META-INF/OLD.EC', b'old cert', zipfile.ZIP_DEFLATED),
            ('META-INF/SIG-FIXTURE', b'old signature', zipfile.ZIP_DEFLATED),
            ('META-INF/services/fixture.Service', b'provider', zipfile.ZIP_DEFLATED),
            ('META-INF/LICENSE', b'license retained', zipfile.ZIP_STORED),
            ('META-INF/subdir/file.SF', b'unrelated nested entry', zipfile.ZIP_DEFLATED),
        ]
        write_apk(self.original, self.entries)
        self.dexdir = self.root / 'emitted'
        self.dexdir.mkdir()
        (self.dexdir / 'classes.dex').write_bytes(dex_bytes(b'patched'))
        (self.dexdir / 'classes2.dex').write_bytes(dex_bytes(b'unchanged'))
        self.bundle = self.root / 'bundle.jar'
        self.bundle.write_bytes(b'non-executable synthetic bundle')
        self.report = self.root / 'apply.json'
        self.report_data = {
            'status': 'applied_structurally_verified',
            'input': {'path': str(self.original), 'sha256': digest(self.original)},
            'bundle': {'path': str(self.bundle), 'sha256': digest(self.bundle)},
            'dex': [{'name': path.name, 'path': str(path), 'sha256': digest(path)}
                    for path in sorted(self.dexdir.iterdir())],
            'structural_assertions': {'status': 'passed'},
            'extra_context': {'ignored': 'not approval'},
        }
        self.tools = {}
        for name in ('java', 'aapt2', 'zipalign', 'signer.jar'):
            path = self.root / name
            path.write_bytes(b'synthetic tool placeholder')
            self.tools[name] = path
        # Existence-only placeholder. Tests prohibit Python reads/hashes of it.
        self.keystore = self.root / 'not-a-keystore.fixture'
        self.keystore.touch()
        self.out = self.root / 'new-output'
        self.old_signer = 'a' * 64
        self.new_signer = 'b' * 64
        self.identity = dict(package='org.example.fixture', version_code='1',
                             version_name='1.0', split=None)
        self.opts = dict(
            apks=[self.original], apply_report=self.report, expect_apply_sha256='',
            reviewed_apply=True, out=self.out,
            aapt2=str(self.tools['aapt2']), java=str(self.tools['java']),
            signer_jar=self.tools['signer.jar'], zipalign=str(self.tools['zipalign']),
            expect_package=self.identity['package'], expect_version_code='1', expect_version_name='1.0',
            expect_signer=[self.old_signer], abi='arm64-v8a', density='nodpi', language=['none'],
            final_signer_sha256=self.new_signer, keystore=self.keystore,
            ks_pass_env='ASSEMBLY_TEST_STORE_REF', key_pass_env='ASSEMBLY_TEST_KEY_REF',
            key_alias='fixture', timeout=45,
        )
        self.save_report()
        self.env = mock.patch.dict(os.environ, {'ASSEMBLY_TEST_STORE_REF': 'synthetic-env-only',
                                                'ASSEMBLY_TEST_KEY_REF': 'synthetic-env-only'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.calls = []
        self.verify_count = 0
        self.fail_stage = None
        self.mutate_stage = None
        self.mutate_target = None
        self.mutate_payload = False
        self.bad_metadata = False
        self.extra_output = False
        self.original_verify = driver.verify_apks
        self.patches = [
            mock.patch.object(driver, '_executable', side_effect=lambda value: value),
            mock.patch.object(driver, 'run_tool', side_effect=self.fake_tool),
            mock.patch.object(driver, 'verify_apks', side_effect=self.fake_verify),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        real_hash = driver._hash_file
        def guarded_hash(path):
            if Path(path).samefile(self.keystore):
                self.fail('assembly attempted to read/hash signing material')
            return real_hash(path)
        patch = mock.patch.object(driver, '_hash_file', side_effect=guarded_hash)
        patch.start()
        self.addCleanup(patch.stop)

    def save_report(self):
        self.report.write_text(json.dumps(self.report_data), encoding='utf-8')
        if hasattr(self, 'opts'):
            self.opts['expect_apply_sha256'] = digest(self.report)

    def fake_verify(self, apks, out, expect_signer, **kwargs):
        self.verify_count += 1
        stage = 'verify-original' if self.verify_count == 1 else 'verify-final'
        self.calls.append(stage)
        if self.fail_stage == stage:
            raise driver.DriverError('synthetic failure with sensitive tool output')
        self.assertEqual(expect_signer, [self.old_signer if self.verify_count == 1 else self.new_signer])
        self.assertEqual(kwargs['aapt2'], str(self.tools['aapt2']))
        self.assertEqual(kwargs['java'], str(self.tools['java']))
        self.assertEqual(kwargs['signer_jar'], self.tools['signer.jar'])
        self.assertEqual(kwargs['expect_package'], self.identity['package'])
        self.assertEqual(kwargs['expect_version_code'], self.identity['version_code'])
        self.assertEqual(kwargs['expect_version_name'], self.identity['version_name'])
        self.assertEqual(kwargs['abi'], 'arm64-v8a')
        self.assertEqual(kwargs['density'], 'nodpi')
        self.assertEqual(kwargs['language'], ['none'])
        result = {'status': 'selected_split_set_verified', 'apks': [
            {'path': str(apks[0]), 'sha256': digest(apks[0]), 'manifest': self.identity.copy(),
             'signers_sha256': list(expect_signer)}]}
        if self.bad_metadata and stage == 'verify-final':
            result['apks'][0]['signers_sha256'] = [self.old_signer]
        with Path(out).open('x', encoding='utf-8') as sink:
            json.dump(result, sink)
        if self.mutate_stage == stage:
            self.mutate_target.write_bytes(b'changed input')
        return result

    def fake_tool(self, args, timeout, **kwargs):
        self.assertFalse(kwargs, 'no tool logs or secret-bearing environment snapshots')
        self.assertEqual(timeout, 45)
        if args[0] == str(self.tools['zipalign']):
            stage = 'alignment-check' if args[1] == '-c' else 'align'
        else:
            stage = 'sign'
        self.calls.append((stage, list(args)))
        if self.fail_stage == stage:
            raise driver.DriverError('sensitive diagnostic synthetic-env-only')
        if stage == 'align':
            self.assertEqual(args[1:4], ['-P', '16', '4'])
            shutil.copyfile(args[-2], args[-1])
        elif stage == 'sign':
            self.assertEqual(args[:4], [str(self.tools['java']), '-jar', str(self.tools['signer.jar']), 'sign'])
            self.assertEqual(args[args.index('--ks-pass') + 1], 'env:ASSEMBLY_TEST_STORE_REF')
            self.assertEqual(args[args.index('--key-pass') + 1], 'env:ASSEMBLY_TEST_KEY_REF')
            self.assertEqual(args[args.index('--ks-key-alias') + 1], 'fixture')
            self.assertNotIn('synthetic-env-only', args)
            for flag, value in [('--v1-signing-enabled', 'false'), ('--v2-signing-enabled', 'true'),
                                ('--v3-signing-enabled', 'false'), ('--v4-signing-enabled', 'false')]:
                self.assertEqual(args[args.index(flag) + 1], value)
            signed = Path(args[args.index('--out') + 1])
            shutil.copyfile(args[-1], signed)
            with_signing_block(signed)
            if self.mutate_payload:
                entries = [(name, b'changed resources' if name == 'resources.arsc' else content, method)
                           for name, content, method in self.entries if not assembly._stale_signature(name)]
                entries = [(name, (self.dexdir / name).read_bytes() if name.endswith('.dex') else content, method)
                           for name, content, method in entries]
                write_apk(signed, entries)
            if self.extra_output:
                (signed.parent / 'signed.apk.idsig').touch()
        else:
            self.assertEqual(args[1:5], ['-c', '-P', '16', '4'])
        if self.mutate_stage == stage:
            self.mutate_target.write_bytes(b'changed input')
        return 'not persisted', 'not persisted'

    def run_assembly(self, **updates):
        return assembly.assemble(**{**self.opts, **updates})

    def rejects(self, pattern=None, **updates):
        with self.assertRaisesRegex(assembly.AssemblyError, pattern or '.') as error:
            self.run_assembly(**updates)
        self.assertNotIn('synthetic-env-only', str(error.exception))
        self.assertNotIn('sensitive diagnostic', str(error.exception))
        self.assertFalse((self.out / 'assembly.json').exists())

    def refresh_original(self):
        self.report_data['input']['sha256'] = digest(self.original)
        self.save_report()

    def test_success_preserves_payloads_compression_and_removes_only_stale_signatures(self):
        with_signing_block(self.original)
        self.refresh_original()
        original_hash = digest(self.original)
        result = self.run_assembly()
        self.assertEqual(result['schema'], 1)
        self.assertEqual(result['status'], 'assembled_verified')
        self.assertEqual(result['changed_dex'], ['classes.dex'])
        self.assertFalse(result['dex_layout']['allow_dex_layout_change'])
        self.assertFalse(result['dex_layout']['changed'])
        self.assertEqual(result['dex_layout']['original'], ['classes.dex', 'classes2.dex'])
        self.assertEqual(result['dex_layout']['emitted'], ['classes.dex', 'classes2.dex'])
        self.assertEqual(digest(self.original), original_hash)
        self.assertEqual(result, json.loads((self.out / 'assembly.json').read_text()))
        self.assertEqual(self.calls[0], 'verify-original')
        self.assertEqual([item[0] for item in self.calls if isinstance(item, tuple)],
                         ['align', 'sign', 'alignment-check'])
        self.assertEqual(self.calls[-1], 'verify-final')
        for label in ('unsigned', 'aligned', 'signed'):
            path = Path(result['outputs'][label]['path'])
            self.assertEqual(result['outputs'][label]['sha256'], digest(path))
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.comment, b'fixture comment')
                for name, content, method in self.entries:
                    if assembly._stale_signature(name):
                        self.assertNotIn(name, archive.namelist())
                    else:
                        expected = (self.dexdir / name).read_bytes() if name.endswith('.dex') else content
                        self.assertEqual(archive.read(name), expected)
                        self.assertEqual(archive.getinfo(name).compress_type, method)
        self.assertNotIn(str(self.keystore), json.dumps(result))
        self.assertNotIn('synthetic-env-only', json.dumps(result))
        self.assertEqual(result['alignment']['status'], 'passed')
        self.assertEqual(len(result['removed_stale_signatures']), 6)

    def test_split_set_rejected_before_tools(self):
        self.rejects('split', apks=[self.original, self.original])
        self.assertEqual(self.calls, [])
        self.assertFalse(self.out.exists())

    def test_json_is_not_approval(self):
        self.report_data['approved'] = True
        self.save_report()
        self.rejects('reviewed', reviewed_apply=False)
        self.assertEqual(self.calls, [])

    def test_report_hash_mismatch(self):
        self.rejects('report SHA', expect_apply_sha256='0' * 64)
        self.assertFalse(self.out.exists())

    def test_no_implicit_or_malformed_pins(self):
        for field in ('expect_apply_sha256', 'final_signer_sha256'):
            with self.subTest(field=field):
                self.rejects('SHA', **{field: ''})
        self.rejects('original signer', expect_signer=[])

    def test_bad_status_or_assertions(self):
        self.report_data['status'] = 'applied'
        self.save_report()
        self.rejects('successful')
        self.report_data['status'] = 'applied_structurally_verified'
        self.report_data['structural_assertions']['status'] = 'failed'
        self.save_report()
        self.rejects('assertions')

    def test_missing_evidence_fields(self):
        for field in ('input', 'bundle', 'dex', 'structural_assertions'):
            with self.subTest(field=field):
                value = self.report_data.pop(field)
                self.save_report()
                self.rejects()
                self.report_data[field] = value
        self.assertEqual(self.calls, [])

    def test_report_duplicate_json_fields_rejected(self):
        self.report.write_text('{"status": "x", "status": "applied_structurally_verified"}')
        self.opts['expect_apply_sha256'] = digest(self.report)
        self.rejects('duplicate')

    def test_report_size_limit(self):
        with mock.patch.object(driver, 'MAX_METADATA_BYTES', 8):
            self.rejects('size limit')

    def test_changed_content_input_bundle_dex(self):
        for path in (self.original, self.bundle, self.dexdir / 'classes.dex'):
            with self.subTest(path=path.name):
                old = path.read_bytes()
                path.write_bytes(old + b'changed')
                self.rejects()
                path.write_bytes(old)
        self.assertEqual(self.calls, [])

    def test_report_input_wrong_selected_apk(self):
        other = self.root / 'other.apk'
        shutil.copyfile(self.original, other)
        self.report_data['input']['path'] = str(other)
        self.save_report()
        self.rejects('selected original')

    def test_all_emitted_dex_names_must_match(self):
        self.report_data['dex'].pop()
        (self.dexdir / 'classes2.dex').unlink()
        self.save_report()
        self.rejects('exactly match')

    def test_new_dex_names_rejected(self):
        path = self.dexdir / 'classes3.dex'
        path.write_bytes(dex_bytes(b'new'))
        self.report_data['dex'].append({'name': path.name, 'path': str(path), 'sha256': digest(path)})
        self.save_report()
        self.rejects('exactly match')

    def emitted_layout(self, payloads):
        for path in self.dexdir.iterdir():
            path.unlink()
        for name, payload in payloads.items():
            (self.dexdir / name).write_bytes(payload)
        self.report_data['dex'] = [
            {'name': path.name, 'path': str(path), 'sha256': digest(path)}
            for path in sorted(self.dexdir.iterdir())]
        self.save_report()

    def assert_layout_payloads(self, result, names):
        for label in ('unsigned', 'aligned', 'signed'):
            with zipfile.ZipFile(result['outputs'][label]['path']) as archive:
                self.assertEqual({name for name in archive.namelist() if name.endswith('.dex')}, set(names))
                self.assertEqual(archive.comment, b'fixture comment')
                original_methods = {name: method for name, _, method in self.entries}
                for name, content, method in self.entries:
                    if assembly._stale_signature(name):
                        self.assertNotIn(name, archive.namelist())
                    elif not name.endswith('.dex'):
                        self.assertEqual(archive.read(name), content)
                        self.assertEqual(archive.getinfo(name).compress_type, method)
                for name in names:
                    self.assertEqual(archive.read(name), (self.dexdir / name).read_bytes())
                    self.assertEqual(archive.getinfo(name).compress_type,
                                     original_methods.get(name, original_methods['classes.dex']))
        self.assertEqual(result['dex_layout']['emitted'], names)
        self.assertTrue(result['dex_layout']['allow_dex_layout_change'])
        self.assertEqual(result, json.loads((self.out / 'assembly.json').read_text()))

    def test_opt_in_single_dex_to_multidex_preserves_all_other_payloads(self):
        self.entries = [entry for entry in self.entries if entry[0] != 'classes2.dex']
        write_apk(self.original, self.entries)
        with_signing_block(self.original, b'\0' * 4095)
        self.refresh_original()
        original_hash = digest(self.original)
        result = self.run_assembly(allow_dex_layout_change=True)
        self.assert_layout_payloads(result, ['classes.dex', 'classes2.dex'])
        self.assertEqual(digest(self.original), original_hash)
        self.assertEqual(result['changed_dex'], ['classes.dex', 'classes2.dex'])
        self.assertEqual(result['dex_layout']['original'], ['classes.dex'])
        self.assertEqual(result['dex_layout']['added'], ['classes2.dex'])
        self.assertEqual(result['dex_layout']['removed'], [])
        self.assertTrue(result['dex_layout']['changed'])
        self.assertIn('API24+', result['dex_layout']['runtime_scope'])
        self.assertIn('not asserted', result['dex_layout']['min_sdk_verification'])

    def test_opt_in_removes_stale_dex_even_with_unchanged_retained_payload(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'original')})
        result = self.run_assembly(allow_dex_layout_change=True)
        self.assert_layout_payloads(result, ['classes.dex'])
        self.assertEqual(result['changed_dex'], ['classes2.dex'])
        self.assertEqual(result['dex_layout']['removed'], ['classes2.dex'])
        self.assertEqual(result['dex_layout']['added'], [])
        self.assertNotIn('classes2.dex', result['payloads'])

    def test_opt_in_additions_inherit_compressed_primary_and_keep_retained_methods(self):
        self.entries = [(name, content, zipfile.ZIP_DEFLATED if name == 'classes.dex' else method)
                        for name, content, method in self.entries]
        write_apk(self.original, self.entries)
        self.refresh_original()
        names = ['classes.dex'] + [f'classes{index}.dex' for index in range(2, 11)]
        self.emitted_layout({name: dex_bytes(name.encode()) for name in names})
        # Report ordering is not DEX ordering, and classes10 must follow classes9.
        self.report_data['dex'].reverse()
        self.save_report()
        result = self.run_assembly(allow_dex_layout_change=True)
        self.assert_layout_payloads(result, names)
        self.assertEqual(result['dex_layout']['added_dex_compression'], 'inherit_classes.dex')

    def test_opt_in_still_allows_exact_layout_and_records_acknowledgement(self):
        result = self.run_assembly(allow_dex_layout_change=True)
        self.assert_layout_payloads(result, ['classes.dex', 'classes2.dex'])
        self.assertFalse(result['dex_layout']['changed'])
        self.assertEqual(result['dex_layout']['added'], [])
        self.assertEqual(result['dex_layout']['removed'], [])

    def test_layout_opt_in_requires_actual_bool_before_tools(self):
        for value in (None, 0, 1, 'true', [], {}):
            with self.subTest(value=value):
                self.rejects('explicit bool', allow_dex_layout_change=value)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.out.exists())

    def test_explicit_false_still_rejects_layout_changes_before_tools(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        self.rejects('exactly match', allow_dex_layout_change=False)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.out.exists())

    def test_opt_in_rejects_emitted_gaps_missing_primary_and_empty_set(self):
        for names in (['classes.dex', 'classes3.dex'], ['classes2.dex'], []):
            with self.subTest(names=names):
                self.emitted_layout({name: dex_bytes(b'patched') for name in names})
                self.rejects('contiguous|explicit emitted DEX', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])
        self.assertFalse(self.out.exists())

    def test_opt_in_rejects_gapped_original_layout(self):
        self.entries = [(name.replace('classes2.dex', 'classes3.dex'), content, method)
                        for name, content, method in self.entries]
        write_apk(self.original, self.entries)
        self.refresh_original()
        self.rejects('contiguous', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_opt_in_cannot_bypass_review_pins_or_success_assertions(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        self.rejects('reviewed', allow_dex_layout_change=True, reviewed_apply=False)
        self.rejects('report SHA', allow_dex_layout_change=True, expect_apply_sha256='0' * 64)
        self.report_data['bundle']['sha256'] = '0' * 64
        self.save_report()
        self.rejects('bundle SHA', allow_dex_layout_change=True)
        self.report_data['bundle']['sha256'] = digest(self.bundle)
        self.report_data['structural_assertions']['status'] = 'failed'
        self.save_report()
        self.rejects('assertions', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_opt_in_rejects_undeclared_dex_and_non_dex_output(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        for name in ('classes2.dex', 'resources.arsc', 'nested'):
            with self.subTest(name=name):
                path = self.dexdir / name
                path.mkdir() if name == 'nested' else path.write_bytes(b'unreviewed')
                self.rejects('unexpected emitted', allow_dex_layout_change=True)
                path.rmdir() if path.is_dir() else path.unlink()
        self.assertEqual(self.calls, [])

    def test_opt_in_rejects_declared_noncanonical_names(self):
        for name in ('classes1.dex', 'classes02.dex', 'Classes.dex', 'assets/classes.dex'):
            with self.subTest(name=name):
                self.report_data['dex'][0]['name'] = name
                self.save_report()
                self.rejects('unsupported emitted', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_opt_in_rejects_bad_added_dex_headers(self):
        for offset, value in ((0, b'notdex!!'), (32, struct.pack('<I', 999)),
                              (36, struct.pack('<I', 113)), (40, struct.pack('<I', 0))):
            with self.subTest(offset=offset):
                bad = bytearray(dex_bytes(b'added'))
                bad[offset:offset + len(value)] = value
                self.emitted_layout({'classes.dex': dex_bytes(b'patched'),
                                     'classes2.dex': dex_bytes(b'unchanged'), 'classes3.dex': bytes(bad)})
                self.rejects('DEX format|DEX header', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_opt_in_rejects_unsupported_apk_packaging_before_tools(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        with_signing_block(self.original, b'\0' * 31 + b'X')
        self.refresh_original()
        self.rejects('nonzero', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_opt_in_rejects_stale_dex_reintroduced_by_tool(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        fake = self.fake_tool
        def reintroduce(args, **kwargs):
            result = fake(args, **kwargs)
            if args[0] == str(self.tools['zipalign']) and args[1] != '-c':
                with zipfile.ZipFile(args[-1], 'a') as archive:
                    archive.writestr('classes2.dex', dex_bytes(b'stale'))
            return result
        with mock.patch.object(driver, 'run_tool', side_effect=reintroduce):
            self.rejects('aligned payload/compression', allow_dex_layout_change=True)
        self.assertNotIn('sign', [item[0] for item in self.calls if isinstance(item, tuple)])

    def test_opt_in_detects_non_dex_compression_changes_by_tool(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        fake = self.fake_tool
        def recompress(args, **kwargs):
            result = fake(args, **kwargs)
            if args[0] == str(self.tools['zipalign']) and args[1] != '-c':
                path = Path(args[-1])
                with zipfile.ZipFile(path) as archive:
                    entries = [(info.filename, archive.read(info),
                                zipfile.ZIP_DEFLATED if info.filename == 'lib/arm64-v8a/libfixture.so'
                                else info.compress_type) for info in archive.infolist()]
                write_apk(path, entries)
            return result
        with mock.patch.object(driver, 'run_tool', side_effect=recompress):
            self.rejects('aligned payload/compression', allow_dex_layout_change=True)

    def test_opt_in_does_not_allow_noop(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'original'), 'classes2.dex': dex_bytes(b'unchanged')})
        self.rejects('no changed', allow_dex_layout_change=True)
        self.assertEqual(self.calls, [])

    def test_duplicate_dex_name_rejected(self):
        self.report_data['dex'].append(self.report_data['dex'][0].copy())
        self.save_report()
        self.rejects('duplicate emitted')

    def test_unknown_emitted_resource_native_archive_and_subdirectory_rejected(self):
        for name in ('resources.arsc', 'libfixture.so', 'new.apk', 'classes9.dex', 'nested'):
            with self.subTest(name=name):
                path = self.dexdir / name
                path.mkdir() if name == 'nested' else path.touch()
                self.rejects('unexpected emitted')
                path.rmdir() if path.is_dir() else path.unlink()
        self.assertEqual(self.calls, [])

    def test_nonstandard_dex_names_rejected(self):
        self.report_data['dex'][0]['name'] = 'classes1.dex'
        self.save_report()
        self.rejects('unsupported emitted')

    def test_bad_dex_header_rejected(self):
        path = self.dexdir / 'classes.dex'
        path.write_bytes(b'not a DEX')
        self.report_data['dex'][0]['sha256'] = digest(path)
        self.save_report()
        self.rejects('DEX size')

    def test_noop_rejected(self):
        (self.dexdir / 'classes.dex').write_bytes(dex_bytes(b'original'))
        self.report_data['dex'][0]['sha256'] = digest(self.dexdir / 'classes.dex')
        self.save_report()
        self.rejects('no changed')

    def test_reused_output_rejected_without_overwrite(self):
        self.out.mkdir()
        sentinel = self.out / 'sentinel'
        sentinel.write_bytes(b'retain')
        self.rejects('NEW')
        self.assertEqual(sentinel.read_bytes(), b'retain')

    def test_output_symlink_rejected_before_path_resolution(self):
        real_is_symlink = Path.is_symlink
        def is_symlink(path):
            return path == self.out or real_is_symlink(path)
        with mock.patch.object(Path, 'is_symlink', is_symlink):
            self.rejects('symlink')
        self.assertFalse(self.out.exists())

    def test_repository_output_rejected(self):
        self.rejects(out=HERE / 'not-created-output')
        self.assertFalse((HERE / 'not-created-output').exists())

    def test_emission_directory_output_overlap_rejected(self):
        self.rejects('overlap', out=self.dexdir / 'nested-output')

    def test_missing_or_relative_tools_rejected(self):
        self.rejects(aapt2=str(self.root / 'missing-tool'))
        self.rejects('absolute', zipalign='zipalign')
        self.assertEqual(self.calls, [])

    def test_password_value_is_not_an_environment_variable_name(self):
        self.rejects('variable NAME', ks_pass_env='not a variable name')
        self.rejects('variable NAME', key_pass_env='ABSENT_ASSEMBLY_ENV_001')

    def test_original_verify_failure_blocks_all_assembly_tools(self):
        self.fail_stage = 'verify-original'
        self.rejects()
        self.assertEqual(self.calls, ['verify-original'])
        self.assertFalse((self.out / 'unsigned.apk').exists())

    def test_all_tool_and_final_signer_failures_block_publication(self):
        for stage in ('align', 'sign', 'alignment-check', 'verify-final'):
            with self.subTest(stage=stage):
                self.out = self.root / ('new-' + stage)
                self.opts['out'] = self.out
                self.fail_stage = stage
                self.verify_count = 0
                self.rejects()

    def test_final_signer_metadata_mismatch_rejected(self):
        self.bad_metadata = True
        self.rejects('metadata mismatch')

    def test_signed_payload_changes_rejected(self):
        self.mutate_payload = True
        self.rejects('preservation mismatch')
        self.assertNotIn('verify-final', self.calls)

    def test_inputs_rehashed_after_execution(self):
        for target in (self.original, self.bundle, self.report, self.dexdir / 'classes.dex', self.tools['aapt2']):
            with self.subTest(target=target.name):
                self.out = self.root / ('mutation-' + target.name)
                self.opts['out'] = self.out
                self.verify_count = 0
                old = target.read_bytes()
                self.mutate_stage = 'sign'
                self.mutate_target = target
                self.rejects('input changed')
                target.write_bytes(old)

    def test_unsigned_and_aligned_rehashed_before_publication(self):
        self.mutate_stage = 'verify-final'
        self.mutate_target = self.out / 'unsigned.apk'
        self.rejects('input changed')

    def test_unexpected_signing_sidecar_rejected(self):
        self.extra_output = True
        self.rejects('unexpected assembly tool output')

    def test_archive_prefix_or_gap_rejected(self):
        self.original.write_bytes(b'prefix' + self.original.read_bytes())
        self.refresh_original()
        self.rejects()

    def test_unusual_archive_dex_rejected(self):
        write_apk(self.original, self.entries + [('assets/weird.dex', b'weird', zipfile.ZIP_STORED)])
        self.refresh_original()
        self.rejects('unsupported DEX archive')

    def test_unsafe_archive_entry_rejected(self):
        write_apk(self.original, self.entries + [('../escape', b'bad', zipfile.ZIP_STORED)])
        self.refresh_original()
        self.rejects()
        self.assertEqual(self.calls, [])

    def test_signing_material_alias_evidence_not_read(self):
        self.report_data['bundle']['path'] = str(self.keystore)
        self.save_report()
        self.rejects('signing material')

    def test_timeout_bounds(self):
        for timeout in (0, 601, True, '60'):
            with self.subTest(timeout=timeout):
                self.rejects('timeout', timeout=timeout)

    def test_extra_alignment_padding_is_supported_and_stripped(self):
        self.assertEqual(assembly._extras(b'\0' * 7), b'')
        self.assertEqual(assembly._extras(struct.pack('<HH', 0xd935, 3) + b'xyz'), b'')
        extra = struct.pack('<HH', 0xcafe, 3) + b'xyz'
        self.assertEqual(assembly._extras(extra + b'\0' * 3), extra)

    def test_zero_padding_before_signing_block_is_supported(self):
        before = assembly._inventory(self.original)
        with_signing_block(self.original, b'\0' * 4095)
        self.assertEqual(assembly._inventory(self.original), before)

    def test_nonzero_padding_before_signing_block_is_rejected(self):
        with_signing_block(self.original, b'\0' * 31 + b'X')
        with self.assertRaisesRegex(assembly.AssemblyError, 'nonzero'):
            assembly._inventory(self.original)

    def test_excessive_padding_before_signing_block_is_rejected(self):
        with_signing_block(self.original, b'\0' * 16384)
        with self.assertRaisesRegex(assembly.AssemblyError, 'padding'):
            assembly._inventory(self.original)

    def test_real_driver_verifier_parses_final_signer_evidence_offline(self):
        # Exercise the real verifier grammar, not synthetic native placeholder bytes.
        write_apk(self.original, [entry for entry in self.entries if not entry[0].startswith('lib/')])
        def output(argv, **kwargs):
            if 'xmltree' in argv:
                return ('N: android=http://schemas.android.com/apk/res/android (line=1)\n'
                        '  E: manifest (line=1)\n'
                        '    A: package="org.example.fixture"\n'
                        '    A: android:versionCode(0x0101021b)=1\n'
                        '    A: android:versionName(0x0101021c)="1.0"\n'
                        '      E: application (line=2)\n'), ''
            if 'dump' in argv:
                return "package: name='org.example.fixture' versionCode='1' versionName='1.0'\n", ''
            return 'Signer #1 certificate SHA-256 digest: ' + self.new_signer + '\n', ''
        with mock.patch.object(driver, 'run_tool', side_effect=output):
            result = self.original_verify([self.original], str(self.tools['aapt2']), str(self.tools['java']),
                                          self.tools['signer.jar'], self.root / 'parser-proof.json',
                                          expect_package='org.example.fixture', expect_version_code='1',
                                          expect_version_name='1.0', expect_signer=[self.new_signer],
                                          abi='none', density='nodpi', language=['none'])
        self.assertEqual(result['apks'][0]['signers_sha256'], [self.new_signer])

    def cli_argv(self):
        return ['--apk', str(self.original), '--apply-report', str(self.report),
                '--expect-apply-sha256', self.opts['expect_apply_sha256'], '--reviewed-apply',
                '--out', str(self.out), '--aapt2', str(self.tools['aapt2']),
                '--java', str(self.tools['java']), '--signer-jar', str(self.tools['signer.jar']),
                '--zipalign', str(self.tools['zipalign']), '--expect-package', 'org.example.fixture',
                '--expect-version-code', '1', '--expect-version-name', '1.0',
                '--expect-signer', self.old_signer, '--abi', 'arm64-v8a', '--density', 'nodpi',
                '--language', 'none', '--final-signer-sha256', self.new_signer,
                '--keystore', str(self.keystore), '--ks-pass-env', 'ASSEMBLY_TEST_STORE_REF',
                '--key-pass-env', 'ASSEMBLY_TEST_KEY_REF', '--key-alias', 'fixture', '--timeout', '45']

    def test_main_layout_change_requires_explicit_cli_flag(self):
        self.emitted_layout({'classes.dex': dex_bytes(b'patched')})
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembly.main(self.cli_argv()), 1)
        self.assertIn('exactly match', stderr.getvalue())
        self.assertFalse(self.out.exists())
        self.assertEqual(self.calls, [])
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembly.main(self.cli_argv() + ['--allow-dex-layout-change']), 0)
        result = json.loads((self.out / 'assembly.json').read_text())
        self.assert_layout_payloads(result, ['classes.dex'])

    def test_main_uses_same_library_and_sanitizes_failure(self):
        argv = self.cli_argv()
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembly.main(argv), 0)
        self.assertEqual(json.loads(stdout.getvalue())['status'], 'assembled_verified')
        self.assertEqual(stderr.getvalue(), '')
        self.assertNotIn('synthetic-env-only', stdout.getvalue())
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertEqual(assembly.main(argv), 1)  # never overwrite a completed run
        self.assertNotIn('synthetic-env-only', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
