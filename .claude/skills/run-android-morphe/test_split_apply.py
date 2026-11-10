"""Offline full-set regression tests, not real signing/JNI/Android proof.

Optional --pinned-integration additionally compiles the trusted runner/fixture
with the exact installed closure and executes the actual loader without keys.
"""
from __future__ import annotations
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

HERE = Path(__file__).resolve().parent

def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module

p = load('_split_apply_patchdev', 'patchdev.py')
a = load('_split_apply_assembly', 'assembly.py')
INTEGRATION = '--pinned-integration' in sys.argv
if INTEGRATION:
    sys.argv.remove('--pinned-integration')


def dex(label):
    data = bytearray(112)
    data[:8] = b'dex\n035\0'
    struct.pack_into('<III', data, 32, 112 + len(label), 112, 0x12345678)
    return bytes(data) + label


def apk(path, entries):
    with zipfile.ZipFile(path, 'w') as archive:
        for name, value, method in entries:
            archive.writestr(name, value, compress_type=method)
    return path


class SplitFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='morphe-split-offline-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.old = 'a' * 64; self.final = 'b' * 64
        self.base = apk(self.root / 'not-called-base.apk', [
            ('AndroidManifest.xml', b'base', 0), ('classes.dex', dex(b'original'), 0),
            ('assets/keep', b'keep', 8), ('META-INF/OLD.SF', b'old', 0)])
        self.config = apk(self.root / 'base.apk', [
            ('AndroidManifest.xml', b'config', 0), ('resources.arsc', b'resource', 0),
            ('assets/keep', b'companion', 8), ('META-INF/OLD.RSA', b'old', 8)])
        self.container = self.root / 'logical.apkm'
        self.selected = [{**p.record(self.config), 'archive_member': 'unrelated/resource.apk'},
                         {**p.record(self.base), 'archive_member': 'code.apk'}]
        self.repack_container()
        self.bundle = self.root / 'development.jar'
        with zipfile.ZipFile(self.bundle, 'w') as jar:
            jar.writestr('Assertions.class', b'assertion')
        self.tools = {}
        for name in ('java', 'javac', 'runner.jar', 'aapt2', 'signer.jar', 'zipalign', 'source.kt'):
            path = self.root / name; path.write_bytes(b'placeholder'); self.tools[name] = path
        self.c = dict(trusted_code=True, input_mode='base_config_set', patcher_version='2.3.0',
            patches=['Fixture'], options={}, apks=self.selected, base=p.record(self.base),
            logical_container={**p.record(self.container), 'type': 'APKM'},
            bundle=p.record(self.bundle), runner=p.record(self.tools['runner.jar']),
            assertion_class='Assertions', assertion_sha256=hashlib.sha256(b'assertion').hexdigest(),
            out=str(self.root / 'apply'), jdk=str(self.root), cache_root=str(self.root),
            verification=dict(aapt2=str(self.tools['aapt2']), signer_jar=str(self.tools['signer.jar']),
                expect_package='org.example.fixture', expect_version_code='1', expect_version_name='1.0',
                expect_signer=[self.old], abi='none', density='nodpi', language=['none']),
            source_hashes=[p.record(self.tools['source.kt'])])
        self.companion_version = None
        self.fail_sign = None; self.sign_count = 0
        self.v2 = 'true'; self.final_cert = self.final
        self.drift = None; self.runner_mutation = None; self.report_mutation = None
        self.add_dex = False; self.extra_signed = False
        self.native_alignment = None
        self.calls = []
        for ctx in [patch.object(p, 'jdk', return_value={k: self.tools[k] for k in ('java', 'javac')}),
                    patch.object(p, 'closure', return_value={'runtime': [], 'compiler': []}),
                    patch.object(p, 'run', side_effect=self.runner),
                    patch.object(p.driver, '_executable', side_effect=lambda value: value),
                    patch.object(p.driver, 'run_tool', side_effect=self.tool),
                    patch.object(a.driver, 'run_tool', side_effect=self.tool),
                    patch.object(a.driver, '_executable', side_effect=lambda value: value)]:
            ctx.start(); self.addCleanup(ctx.stop)
        self.store = self.root / 'not-a-key'; self.store.touch()
        env = patch.dict(os.environ, {'SPLIT_TEST_PASS_REF': 'synthetic-only'})
        env.start(); self.addCleanup(env.stop)

    def repack_container(self):
        with zipfile.ZipFile(self.container, 'w') as archive:
            for item in self.selected:
                archive.write(item['path'], item['archive_member'])

    def xml(self, companion):
        rows = ['N: android=http://schemas.android.com/apk/res/android (line=1)',
            '  E: manifest (line=1)', '    A: package="org.example.fixture"',
            '    A: android:versionCode(0x0101021b)=1']
        version = self.companion_version if companion else '1.0'
        if version is not None:
            rows += ['    A: android:versionName(0x0101021c)=' + json.dumps(version)]
        if companion:
            rows += ['    A: split="config.resources"', '    A: configForSplit=""']
        rows += ['      E: uses-sdk (line=2)', '        A: android:minSdkVersion(0x0101020c)=24',
                 '      E: application (line=3)']
        if companion:
            rows += ['        A: android:hasCode(0x0101000c)=false']
        return '\n'.join(rows) + '\n'

    def tool(self, argv, **kwargs):
        args = list(map(str, argv)); self.calls.append(args)
        if 'dump' in args:
            with zipfile.ZipFile(args[-1]) as archive:
                companion = archive.read('AndroidManifest.xml') == b'config'
            if 'xmltree' in args:
                return self.xml(companion), ''
            version = self.companion_version if companion else '1.0'
            return ("package: name='org.example.fixture' versionCode='1' versionName='" +
                    (version or '') + "'" + (" split='config.resources'" if companion else '') + '\n'), ''
        if 'verify' in args:
            signer = self.final_cert if 'members' in Path(args[-1]).parts else self.old
            return ('Verified using v2 scheme (APK Signature Scheme v2): ' + self.v2 + '\n'
                    'Signer #1 certificate SHA-256 digest: ' + signer + '\n'), ''
        if args[0] == str(self.tools['zipalign']):
            if args[1] != '-c':
                shutil.copyfile(args[-2], args[-1])
                if self.native_alignment:
                    target = Path(args[-1])
                    with zipfile.ZipFile(target) as archive:
                        entries = [(i, archive.read(i)) for i in archive.infolist()]
                    with zipfile.ZipFile(target, 'w') as archive:
                        for info, value in entries:
                            if info.filename.startswith('lib/') and info.compress_type == 0:
                                offset = archive.fp.tell() + 30 + len(info.filename.encode('utf-8')) + len(info.extra) + 4
                                size = (-offset) % self.native_alignment
                                info.extra += struct.pack('<HH', 0xd935, size) + bytes(size)
                            archive.writestr(info, value)
                if self.drift and '000' in Path(args[-1]).parts:
                    with zipfile.ZipFile(args[-1]) as archive:
                        entries = [(i.filename, b'drift' if self.drift == 'payload' and i.filename == 'assets/keep' else archive.read(i),
                                    0 if self.drift == 'compression' and i.filename == 'assets/keep' else i.compress_type)
                                   for i in archive.infolist()]
                    apk(Path(args[-1]), entries)
            return '', ''
        if 'sign' in args:
            self.sign_count += 1
            if self.fail_sign == self.sign_count:
                raise a.driver.DriverError('synthetic signing failure')
            target = Path(args[args.index('--out') + 1]); shutil.copyfile(args[-1], target)
            if self.extra_signed:
                target.with_suffix('.apk.idsig').touch()
            return '', ''
        raise AssertionError('unexpected tool action')

    def runner(self, args, cwd, **kwargs):
        request = p.read_json(Path(args[-1]))
        self.request = request
        out = Path(request['output']); out.mkdir(); (out / 'dex').mkdir()
        emitted = []
        for name in ['classes.dex'] + (['classes2.dex'] if self.add_dex else []):
            target = out / 'dex' / name; target.write_bytes(dex(b'patched'))
            emitted.append({'name': name, **p.record(target)})
        report = dict(status='applied_structurally_verified', structural_assertions={'status': 'passed'}, dex=emitted)
        if request.get('input_mode') == 'base_config_set':
            report.update(input_mode='base_config_set', compatibility_mode='APKM', split_binding=request['split_binding'],
                          request_sha256=p.digest(Path(args[-1])))
        if self.report_mutation:
            self.report_mutation(report)
        p.write_json(out / 'runner.json', report)
        if self.runner_mutation:
            self.runner_mutation()
        return ''

    def apply(self, **updates):
        return p.apply({**self.c, **updates})

    def assemble(self, **updates):
        report = self.root / 'apply/apply.json'
        options = dict(input_mode='base_config_set', apks=[Path(i['path']) for i in self.selected],
            apply_report=report, expect_apply_sha256=p.digest(report), reviewed_apply=True,
            out=self.root / 'assembly', aapt2=self.tools['aapt2'], java=self.tools['java'],
            signer_jar=self.tools['signer.jar'], zipalign=self.tools['zipalign'],
            expect_package='org.example.fixture', expect_version_code='1', expect_version_name='1.0',
            expect_signer=[self.old], abi='none', density='nodpi', language=['none'],
            final_signer_sha256=self.final, keystore=self.store, ks_pass_env='SPLIT_TEST_PASS_REF',
            key_alias='fixture')
        return a.assemble(**{**options, **updates})

    def reject_apply(self, **updates):
        with self.assertRaises((p.DriverError, OSError, KeyError)):
            self.apply(**updates)
        self.assertFalse((self.root / 'apply/apply.json').exists())

    def reject_assembly(self, **updates):
        with self.assertRaises(a.AssemblyError):
            self.assemble(**updates)
        self.assertFalse((self.root / 'assembly/assembly.json').exists())

    def test_apply_whole_set_staged_manifest_base_and_absent_version(self):
        result = self.apply()
        self.assertEqual(result['schema'], 2)
        self.assertEqual(result['input'], p.record(self.base))
        self.assertNotEqual(self.request['input'], str(self.base))
        binding = result['split_binding']
        self.assertEqual(binding['apks'], self.selected)
        self.assertEqual(binding['topology']['members'][0]['role'], 'base_config')
        verified = p.read_json(self.root / 'apply/verified-staged.json')
        self.assertIsNone(verified['apks'][0]['manifest_declarations']['version_name'])
        self.assertEqual(verified['apks'][0]['manifest']['version_name'], '1.0')
        self.assertEqual(self.request['source_hashes'], result['source_hashes'])

    def test_omitted_mode_preserves_singleton_schema1(self):
        c = {k: v for k, v in self.c.items() if k not in ('input_mode', 'logical_container', 'base')}
        c['apks'] = [p.record(self.base)]
        result = p.apply(c)
        self.assertEqual(result['schema'], 1)
        self.assertNotIn('input_mode', result)
        self.assertNotIn('split_binding', result)
        self.assertEqual(self.request['input'], str(self.base))

    def test_split_provenance_not_silently_ignored_by_standalone(self):
        self.reject_apply(input_mode='standalone', apks=[p.record(self.base)])

    def alter_member(self, path, extra):
        with zipfile.ZipFile(path, 'a') as archive:
            for name, value in extra:
                archive.writestr(name, value)
        for item in self.selected:
            if item['path'] == str(path):
                item['sha256'] = p.digest(path)
        self.repack_container()
        self.c['logical_container'] = {**p.record(self.container), 'type': 'APKM'}
        self.c['base'] = p.record(self.base)

    def test_code_bearing_companion_rejected(self):
        self.alter_member(self.config, [('classes.dex', dex(b'unsupported'))]); self.reject_apply()

    def test_nested_companion_dex_rejected(self):
        self.alter_member(self.config, [('assets/Hidden.DEX', dex(b'unsupported'))]); self.reject_apply()

    def test_native_base_rejected_before_runner(self):
        self.alter_member(self.base, [('lib/x86/libanything.so', b'unsupported')]); self.reject_apply()

    def test_feature_companion_rejected(self):
        original_xml = self.xml
        self.xml = lambda companion: original_xml(companion).replace(
            '    A: split="config.resources"', '    A: split="config.resources"\n    A: android:isFeatureSplit(0x0101055b)=true')
        self.reject_apply()

    def test_gapped_emitted_dex_rejected(self):
        def gap(report):
            item = report['dex'][0]; path = Path(item['path'])
            target = path.with_name('classes3.dex'); path.rename(target)
            item.update(name=target.name, path=str(target))
        self.report_mutation = gap; self.reject_apply()

    def test_undeclared_emitted_payload_rejected(self):
        self.runner_mutation = lambda: (self.root / 'apply/runner-output/dex/resources.arsc').write_bytes(b'unsupported')
        self.reject_apply()

    def test_apply_matching_explicit_companion_version(self):
        self.companion_version = '1.0'; self.apply()

    def test_empty_version_rejected(self):
        self.companion_version = ''; self.reject_apply()

    def test_conflicting_version_rejected(self):
        self.companion_version = '2.0'; self.reject_apply()

    def test_no_implicit_multi_apk_mode(self):
        self.reject_apply(input_mode='standalone')

    def test_unknown_mode(self):
        self.reject_apply(input_mode='splits')

    def test_missing_provenance(self):
        self.reject_apply(logical_container=None)

    def test_wrong_container_type(self):
        self.reject_apply(logical_container={**self.c['logical_container'], 'type': 'XAPK'})

    def test_wrong_container_hash(self):
        self.reject_apply(logical_container={**self.c['logical_container'], 'sha256': '0' * 64})

    def test_member_hash_not_in_archive(self):
        apk(self.config, [('AndroidManifest.xml', b'config', 0)])
        self.selected[0]['sha256'] = p.digest(self.config)
        self.reject_apply()

    def test_duplicate_archive_member(self):
        self.selected[1]['archive_member'] = self.selected[0]['archive_member']; self.reject_apply()

    def test_duplicate_physical_member(self):
        self.reject_apply(apks=[self.selected[0], self.selected[0]])

    def test_wrong_manifest_base_reference(self):
        self.reject_apply(base=p.record(self.config))

    def test_mutated_companion_during_runner(self):
        self.runner_mutation = lambda: self.config.write_bytes(b'changed')
        self.reject_apply()

    def test_mutated_staged_member_during_runner(self):
        self.runner_mutation = lambda: Path(self.request['split_binding']['staged_apks'][0]['staged']['path']).write_bytes(b'changed')
        self.reject_apply()

    def test_runner_report_dropped_companion(self):
        self.report_mutation = lambda r: r.update(split_binding={**r['split_binding'], 'apks': r['split_binding']['apks'][1:]})
        self.reject_apply()

    def test_runner_report_wrong_mode(self):
        self.report_mutation = lambda r: r.update(compatibility_mode='APK')
        self.reject_apply()

    def test_runner_report_wrong_request_hash(self):
        self.report_mutation = lambda r: r.update(request_sha256='0' * 64)
        self.reject_apply()

    def test_apply_layout_change_requires_opt_in(self):
        self.add_dex = True; self.reject_apply()

    def test_apply_and_assembly_layout_opt_in(self):
        self.add_dex = True
        self.apply(allow_dex_layout_change=True)
        self.reject_assembly()
        # First failure occurs before creating the NEW output.
        result = self.assemble(allow_dex_layout_change=True)
        self.assertTrue(result['dex_layout']['changed'])

    def test_success_all_members_resigned_preserved_and_set_verified(self):
        self.apply(); result = self.assemble()
        self.assertEqual(result['schema'], 2)
        self.assertEqual(self.sign_count, 2)
        self.assertEqual([r['role'] for r in result['members']], ['base_config', 'base'])
        for member in result['members']:
            self.assertTrue(member['signing']['v2_verified'])
            original = Path(member['original']['path'])
            final = Path(member['outputs']['signed']['path'])
            with zipfile.ZipFile(original) as before, zipfile.ZipFile(final) as after:
                for item in before.infolist():
                    if a._stale_signature(item.filename):
                        self.assertNotIn(item.filename, after.namelist())
                    elif not item.filename.endswith('.dex'):
                        self.assertEqual(before.read(item), after.read(item.filename))
                        self.assertEqual(item.compress_type, after.getinfo(item.filename).compress_type)
        self.assertEqual(p.read_json(self.root / 'assembly/assembly.json'), result)
        self.assertNotIn('synthetic-only', json.dumps(result))

    def test_assembly_dropped_companion(self):
        self.apply(); self.reject_assembly(apks=[self.base])

    def test_assembly_reordered_set(self):
        self.apply(); self.reject_assembly(apks=[self.base, self.config])

    def test_assembly_substituted_companion_same_bytes(self):
        self.apply(); substitute = self.root / 'copy.apk'; shutil.copyfile(self.config, substitute)
        self.reject_assembly(apks=[substitute, self.base])

    def test_assembly_mutated_companion(self):
        self.apply(); self.config.write_bytes(b'changed'); self.reject_assembly()

    def test_assembly_mutated_source(self):
        self.apply(); self.tools['source.kt'].write_bytes(b'changed'); self.reject_assembly()

    def rewrite_apply(self, change):
        path = self.root / 'apply/apply.json'
        report = p.read_json(path); change(report)
        path.write_text(json.dumps(report), encoding='utf-8')

    def test_assembly_rejects_non_apkm_compatibility_report(self):
        self.apply(); self.rewrite_apply(lambda r: r.update(compatibility_mode='APK'))
        self.reject_assembly()

    def test_assembly_rejects_schema1_in_split_mode(self):
        self.apply(); self.rewrite_apply(lambda r: r.update(schema=1))
        self.reject_assembly()

    def test_assembly_rejects_changed_topology_binding(self):
        self.apply()
        self.rewrite_apply(lambda r: r['split_binding']['topology']['members'].pop())
        self.reject_assembly()

    def test_assembly_rejects_changed_selection(self):
        self.apply(); self.reject_assembly(density='xhdpi')

    def test_assembly_rejects_changed_container(self):
        self.apply(); self.container.write_bytes(b'changed'); self.reject_assembly()

    def test_assembly_wrong_mode_for_schema2(self):
        self.apply(); self.reject_assembly(input_mode='standalone', apks=[self.base])

    def test_assembly_payload_drift(self):
        self.apply(); self.drift = 'payload'; self.reject_assembly()

    def test_assembly_compression_drift(self):
        self.apply(); self.drift = 'compression'; self.reject_assembly()

    def native_companion(self):
        # Header-only offline ELF identity fixture, NOT a loadable JNI library.
        header = bytearray(64); header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', header, 16, 3, 62, 1)
        struct.pack_into('<H', header, 52, 64)
        self.alter_member(self.config, [('lib/x86_64/libarbitrary.so', bytes(header))])
        self.c['verification']['abi'] = 'x86_64'

    def test_native_companion_16k_zip_alignment_and_preservation(self):
        self.native_companion(); self.apply(); self.native_alignment = 16384
        result = self.assemble(abi='x86_64')
        final = p.read_json(Path(result['final_verification']))
        lib = final['apks'][0]['native_libraries'][0]
        self.assertEqual(lib['data_offset'] % 16384, 0)
        self.assertEqual(lib['runtime_compatibility'], 'not_proven')

    def test_native_4k_alignment_is_not_16k_output_proof(self):
        self.native_companion(); self.apply(); self.native_alignment = 4096
        self.reject_assembly(abi='x86_64')

    def test_late_final_verification_failure_no_aggregate(self):
        self.apply()
        original = a.driver.verify_apks
        def verify(paths, **kwargs):
            result = original(paths, **kwargs)
            if Path(kwargs['out']).name == 'final-verification.json':
                result['apks'][-1]['signers_sha256'] = [self.old]
            return result
        with patch.object(a.driver, 'verify_apks', side_effect=verify):
            self.reject_assembly()
        self.assertEqual(self.sign_count, 2)

    def test_assembly_last_sign_failure_no_aggregate(self):
        self.apply(); self.fail_sign = 2; self.reject_assembly()
        self.assertTrue((self.root / 'assembly/members/000/signed.apk').exists())
        self.assertFalse((self.root / 'assembly/final-verification.json').exists())

    def test_assembly_final_signer_mismatch(self):
        self.apply(); self.final_cert = self.old; self.reject_assembly()

    def test_assembly_missing_affirmative_v2(self):
        self.apply(); self.v2 = 'false'; self.reject_assembly()

    def test_assembly_signing_sidecar(self):
        self.apply(); self.extra_signed = True; self.reject_assembly()

    def test_assembly_reused_output(self):
        self.apply(); self.assemble()
        with self.assertRaises(a.AssemblyError): self.assemble()

    def test_no_dex_companion_inventory_and_writer(self):
        before = a._inventory(self.config, companion=True)
        target = self.root / 'unsigned.apk'; a._write_unsigned(self.config, target, {})
        self.assertEqual(a._inventory(target, companion=True),
                         {k: v for k, v in before.items() if not a._stale_signature(k)})


@unittest.skipUnless(INTEGRATION, 'opt-in pinned compiler/actual-loader integration')
class PinnedRunnerIntegration(unittest.TestCase):
    def test_actual_loader_apkm_and_apkm_required_positive_apk_and_null_negative(self):
        workspace = HERE.parents[3]
        with tempfile.TemporaryDirectory(prefix='morphe-pinned-split-runner-') as temp:
            root = Path(temp).resolve()
            config = {'jdk': str(workspace / 'Termius/tools/temurin21-21.0.13-9/jdk-21.0.13+9'),
                      'cache_root': str(workspace / 'Termius/tools/gradle-home/caches/modules-2/files-2.1')}
            # A previously built unsigned self-authored fixture, not any signing input.
            original = workspace / '.android-morphe/fixture-replay-01/fixture/fixture-unsigned.apk'
            self.assertTrue(original.is_file())
            base = root / 'physical.apk'; shutil.copyfile(original, base)
            companion = apk(root / 'companion.apk', [('AndroidManifest.xml', b'synthetic companion', 0)])
            container = apk(root / 'logical.apkm', [('code.apk', base.read_bytes(), 0), ('resource.apk', companion.read_bytes(), 0)])
            source = (HERE / 'fixture/FixturePatch.kt').read_text(encoding='utf-8')
            imports, body = source.split('// Trusted source example', 1)
            variants = [('M', 'ApkFileType.APKM'), ('Required', 'ApkFileType.APKM_REQUIRED'),
                        ('Apk', 'ApkFileType.APK'), ('Null', 'null')]
            text = imports + '\n'.join(body.replace('fixtureLabelPatch', 'patch' + name)
                .replace('Fixture label', name).replace('ApkFileType.APK,', value + ',') for name, value in variants)
            # Restore the comment prefix stripped above.
            text = text.replace(', not a semantic patch generator or collection plugin.',
                                '// not a semantic patch generator or collection plugin.')
            src = root / 'Patches.kt'; src.write_text(text, encoding='utf-8')
            assertion = root / 'FixtureAssertions.kt'; shutil.copyfile(HERE / 'fixture/FixtureAssertions.kt', assertion)
            tests = root / 'FixtureTests.kt'; shutil.copyfile(HERE / 'fixture/FixtureTests.kt', tests)
            built = p.patch_build({**config, 'trusted_code': True, 'out': str(root / 'build'),
                'sources': [str(src), str(assertion)], 'tests': [str(tests)],
                'assertion_class': 'FixtureAssertions', 'test_class': 'FixtureTests'})
            tools = p.jdk(config, root); deps = p.closure(config['cache_root'])
            originals = [{**p.record(base), 'archive_member': 'code.apk'}, {**p.record(companion), 'archive_member': 'resource.apk'}]
            members = [{'path': x['path'], 'sha256': x['sha256'], 'role': 'base' if i == 0 else 'base_config',
                        'split': None if i == 0 else 'config.resources', 'target': None if i == 0 else 'base', 'split_types': []}
                       for i, x in enumerate(originals)]
            with zipfile.ZipFile(base) as archive:
                original_dex = p.canonical_dex(n for n in archive.namelist() if n.endswith('.dex'))
            topology = dict(mode='base_config_set', base=str(base), base_sha256=p.digest(base), members=members, base_dex=original_dex)
            binding = dict(input_mode='base_config_set', logical_container={**p.record(container), 'type': 'APKM'},
                apks=originals, base=p.record(base), staged_topology=topology, topology=topology,
                staged_apks=[{'original': r, 'staged': {'path': r['path'], 'sha256': r['sha256']}} for r in originals],
                allow_dex_layout_change=True)
            for name, _ in variants:
                request = dict(input_mode='base_config_set', split_binding=binding, input=str(base), input_sha256=p.digest(base),
                    bundle=built['bundle']['path'], bundle_sha256=built['bundle']['sha256'], patcher_version='2.3.0',
                    patches=[name], options={}, assertion_class='FixtureAssertions', assertion_sha256=built['assertion_sha256'],
                    identity={'package': 'dev.morphe.fixture', 'version_code': '1', 'version_name': '1.0', 'signers_sha256': ['a' * 64]},
                    source_hashes=built['source_hashes'], output=str(root / ('run-' + name)))
                path = root / (name + '.json'); p.write_json(path, request)
                args = [tools['java'], '-Xmx2g', '-cp', p.classpath([Path(built['runner']['path']), *deps['runtime']]), 'GenericPatchRunnerKt', path]
                if name in ('Apk', 'Null'):
                    completed = subprocess.run(list(map(str, args)), cwd=root, env=p.driver.tool_environment(),
                                               stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn(b'failed at definition preflight', completed.stderr)
                    self.assertFalse((Path(request['output']) / 'runner.json').exists())
                else:
                    p.run(args, root, timeout=300)
                    report = p.read_json(Path(request['output']) / 'runner.json')
                    self.assertEqual(report['compatibility_mode'], 'APKM')
                    self.assertEqual(report['split_binding'], binding)
                    self.assertEqual(report['request_sha256'], p.digest(path))
                    self.assertEqual(report['changed_methods'], ['Ldev/morphe/fixture/MainActivity;->label()Ljava/lang/String;'])
            # Omitted mode retains the original null/APK singleton compatibility.
            for name in ('Apk', 'Null', 'M'):
                standalone = {k: v for k, v in request.items() if k not in ('input_mode', 'split_binding')}
                standalone.update(patches=[name], output=str(root / ('standalone-' + name)))
                path = root / ('standalone-' + name + '.json'); p.write_json(path, standalone)
                args = [tools['java'], '-Xmx2g', '-cp', p.classpath([Path(built['runner']['path']), *deps['runtime']]), 'GenericPatchRunnerKt', path]
                if name == 'M':
                    completed = subprocess.run(list(map(str, args)), cwd=root, env=p.driver.tool_environment(),
                                               stdin=subprocess.DEVNULL, capture_output=True, timeout=300)
                    self.assertEqual(completed.returncode, 2)
                    self.assertIn(b'failed at definition preflight', completed.stderr)
                else:
                    p.run(args, root, timeout=300)
                    report = p.read_json(Path(standalone['output']) / 'runner.json')
                    self.assertEqual(report['status'], 'applied_structurally_verified')
                    self.assertNotIn('split_binding', report)


if __name__ == '__main__':
    unittest.main()
