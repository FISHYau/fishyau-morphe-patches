"""Offline tests. Run: py -I <absolute path to test_driver.py>."""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('_tested_android_driver', HERE / 'driver.py')
driver = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = driver
SPEC.loader.exec_module(driver)


def zip_bytes(entries):
    stream = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', UserWarning)
        with zipfile.ZipFile(stream, 'w', zipfile.ZIP_DEFLATED) as archive:
            for name, data in entries:
                archive.writestr(name, data)
    return stream.getvalue()


def apk_bytes(package='org.example.app', version='7', split=None, binary=False):
    manifest = (b'\x03\x00\x08\x00binary' if binary else (
        '<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        f'package="{package}" android:versionCode="{version}" '
        'android:versionName="1.2"' + (f' split="{split}"' if split else '') + '/>'
    ).encode())
    return zip_bytes([('AndroidManifest.xml', manifest), ('classes.dex', b'dex\n035\x00'),
                      ('classes10.dex', b'dex-ten'), ('classes21.dex', b'dex-twenty-one'),
                      ('lib/arm64-v8a/libexample.so', b'native')])


def resource_alias_entries():
    """Both reported ASCII families, with deliberately different payloads."""
    return [('res/R5.xml', b'upper R5'), ('res/r5.xml', b'lower r5'),
            ('res/Sc.xml', b'upper Sc'), ('res/sc.xml', b'lower sc')]


def xmltree(data):
    """Synthetic aapt2-shaped output; not binary AXML or real-tool proof."""
    rows = ['N: android=http://schemas.android.com/apk/res/android (line=0)']
    def visit(node, indent):
        rows.append(' ' * indent + 'E: ' + node.tag + ' (line=0)')
        for name, value in node.attrib.items():
            local = name.split('}')[-1]
            if name.startswith('{'):
                name = driver.SPLITSET.ANDROID + ':' + local
                if local in driver.SPLITSET.IDS:
                    name += '(0x' + driver.SPLITSET.IDS[local] + ')'
            encoded = value if value in ('true', 'false') or local in (
                'versionCode', 'minSdkVersion', 'targetSdkVersion') else json.dumps(value)
            rows.append(' ' * (indent + 2) + 'A: ' + name + '=' + encoded)
        for child in node:
            visit(child, indent + 4)
    visit(driver.ET.fromstring(data), 2)
    return '\n'.join(rows) + '\n'


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def archive(self, content, name='input.zip'):
        path = self.root / name
        path.write_bytes(content)
        return path

    def inspect(self, content, name='input.apkm', **kwargs):
        return driver.inspect_archive(self.archive(content, name), self.root / 'out', **kwargs)

    def test_extract_api(self):
        path = self.archive(zip_bytes([('sdk/', b''), ('sdk/system.img', b'123')]))
        records = driver.extract_archive(path, self.root / 'sdk-out')
        self.assertEqual((self.root / 'sdk-out/sdk/system.img').read_bytes(), b'123')
        self.assertEqual(records[0]['sha256'], hashlib.sha256(b'123').hexdigest())
        self.assertGreaterEqual(driver.SDK_MAX_BYTES, 6 * 1024**3)
        self.assertGreaterEqual(driver.SDK_MAX_FILE_BYTES, 6 * 1024**3)

    def test_sdk_limits_separate_from_apk_limits(self):
        path = self.archive(zip_bytes([('system.img', b'x' * 64)]))
        with mock.patch.object(driver, 'MAX_BYTES', 8), mock.patch.object(driver, 'MAX_FILE_BYTES', 8):
            driver.extract_archive(path, self.root / 'sdk')
            with self.assertRaises(driver.DriverError):
                driver._extract(path, self.root / 'apk', driver.Budget())

    def test_zip64_local_header(self):
        path = self.root / 'zip64.zip'
        with zipfile.ZipFile(path, 'w') as archive:
            with archive.open('system.img', 'w', force_zip64=True) as stream:
                stream.write(b'image')
        driver.extract_archive(path, self.root / 'out')
        self.assertEqual((self.root / 'out/system.img').read_bytes(), b'image')

    def test_zip64_end_record(self):
        data = zip_bytes([('system.img', b'image')])
        end = len(data) - 22
        fields = struct.unpack_from('<4s4H2LH', data, end)
        count, size, offset = fields[4], fields[5], fields[6]
        zip64 = struct.pack('<4sQ2H2L4Q', b'PK\x06\x06', 44, 45, 45, 0, 0,
                            count, count, size, offset)
        locator = struct.pack('<4sLQL', b'PK\x06\x07', 0, end, 1)
        eocd = struct.pack('<4s4H2LH', b'PK\x05\x06', 0, 0, 65535, 65535,
                          0xffffffff, 0xffffffff, 0)
        path = self.archive(data[:end] + zip64 + locator + eocd)
        driver.extract_archive(path, self.root / 'out')
        self.assertEqual((self.root / 'out/system.img').read_bytes(), b'image')

    def test_apk_inventory(self):
        result = self.inspect(apk_bytes(), 'app.apk')
        self.assertEqual(result['apks'][0]['manifest']['package'], 'org.example.app')
        self.assertEqual(result['apks'][0]['dex'], ['classes.dex', 'classes10.dex', 'classes21.dex'])
        self.assertEqual(result['apks'][0]['native_abis'], ['arm64-v8a'])
        self.assertEqual(result['manifest_consistency'], 'checked')
        self.assertEqual(json.loads((self.root / 'out/inventory.json').read_text())['apks'], result['apks'])

    def test_apkm_inventory_and_untrusted_metadata(self):
        metadata = {'package_name': 'org.example.app', 'version_code': 7,
                    'instructions': 'DO NOT execute me', 'path': '../../escape'}
        result = self.inspect(zip_bytes([('base.apk', apk_bytes()),
                                       ('splits/arm.apk', apk_bytes(split='config.arm')),
                                       ('info.json', json.dumps(metadata))]))
        self.assertEqual(len(result['apks']), 2)
        self.assertEqual(result['untrusted_info_json'], metadata)
        self.assertFalse((self.root / 'escape').exists())

    def test_binary_manifest_incomplete_without_aapt(self):
        result = self.inspect(apk_bytes(binary=True), 'app.apk')
        self.assertEqual(result['manifest_consistency'], 'incomplete')

    def test_aapt_binary_identity(self):
        with mock.patch.object(driver, '_executable', return_value='trusted-aapt2'), mock.patch.object(
                driver, 'run_tool', return_value=(
                    "package: name='org.example.app' versionCode='7' versionName='1.2'\n", '')) as run:
            result = self.inspect(apk_bytes(binary=True), 'app.apk', aapt2='aapt2')
        self.assertEqual(result['manifest_consistency'], 'checked')
        self.assertEqual(run.call_args.args[0][:3], ['trusted-aapt2', 'dump', 'badging'])

    def test_manifest_aapt_disagreement(self):
        with mock.patch.object(driver, '_executable', return_value='trusted-aapt2'), mock.patch.object(
                driver, 'run_tool', return_value=("package: name='org.other' versionCode='7'\n", '')):
            with self.assertRaisesRegex(driver.DriverError, 'disagree'):
                self.inspect(apk_bytes(), 'app.apk', aapt2='aapt2')

    def test_split_package_and_version_mismatch(self):
        for package, version in [('org.other', '7'), ('org.example.app', '8')]:
            with self.subTest(package=package, version=version):
                path = self.archive(zip_bytes([('base.apk', apk_bytes()),
                    ('split.apk', apk_bytes(package, version, 'config.arm'))]), package + version + '.apkm')
                with self.assertRaisesRegex(driver.DriverError, 'disagree'):
                    driver.inspect_archive(path, self.root / (package + version))

    def test_duplicate_split(self):
        with self.assertRaisesRegex(driver.DriverError, 'duplicate split'):
            self.inspect(zip_bytes([('base.apk', apk_bytes()), ('other.apk', apk_bytes())]))

    def test_metadata_mismatch(self):
        with self.assertRaisesRegex(driver.DriverError, 'info.json disagrees'):
            self.inspect(zip_bytes([('base.apk', apk_bytes()), ('info.json', '{"package_name":"org.other"}')]))

    def test_apkmirror_metadata_aliases(self):
        for field, value in [('pname', 'org.other'), ('versioncode', 8), ('release_version', '9.9')]:
            with self.subTest(field=field):
                path = self.archive(zip_bytes([('base.apk', apk_bytes()),
                    ('info.json', json.dumps({field: value}))]), field + '.apkm')
                with self.assertRaisesRegex(driver.DriverError, 'info.json disagrees'):
                    driver.inspect_archive(path, self.root / field)

    def test_metadata_does_not_reject_unknown_or_absent_companion_version_name(self):
        for index, replacement in enumerate((b'', b'android:versionName=""')):
            with self.subTest(replacement=replacement):
                with zipfile.ZipFile(io.BytesIO(apk_bytes(split='config.arm'))) as apk:
                    companion = zip_bytes([(name, apk.read(name).replace(
                        b'android:versionName="1.2"', replacement)
                        if name == 'AndroidManifest.xml' else apk.read(name)) for name in apk.namelist()])
                path = self.archive(zip_bytes([('base.apk', apk_bytes()), ('config.apk', companion),
                    ('info.json', '{"version_name":"1.2","release_version":"1.2"}')]), f'absent-{index}.apkm')
                result = driver.inspect_archive(path, self.root / f'absent-{index}')
                manifest = next(r['manifest'] for r in result['apks'] if r['manifest']['split'])
                self.assertEqual(manifest['version_name'], None if not replacement else '')

    def test_metadata_still_rejects_explicit_companion_version_conflict(self):
        with zipfile.ZipFile(io.BytesIO(apk_bytes(split='config.arm'))) as apk:
            companion = zip_bytes([(name, apk.read(name).replace(b'versionName="1.2"', b'versionName="2.0"')
                if name == 'AndroidManifest.xml' else apk.read(name)) for name in apk.namelist()])
        with self.assertRaisesRegex(driver.DriverError, 'info.json disagrees'):
            self.inspect(zip_bytes([('base.apk', apk_bytes()), ('config.apk', companion),
                                   ('info.json', '{"version_name":"1.2"}')]))

    def test_metadata_duplicate_json_keys(self):
        with self.assertRaises(driver.DriverError):
            self.inspect(zip_bytes([('base.apk', apk_bytes()), ('info.json', '{"a":1,"a":2}')]))

    def test_dangerous_names(self):
        names = ['../escape', '/absolute', 'C:/escape', 'a\\b', 'a//b', './x', 'a/../b',
                 'CON', 'con.txt', 'aux', 'NUL.apk', 'COM1.txt', 'LPT².txt', 'CONIN$',
                 'file.', 'file ', 'dir./x', 'a:b', 'a?b', 'a\x01b', 'a\x00b',
                 'CON .txt', 'a/' * 65 + 'x']
        for index, name in enumerate(names):
            with self.subTest(name=name):
                if '\x00' in name:
                    # ZipInfo truncates NUL on construction: mutate names after writing.
                    data = zip_bytes([('a_b', b'x')]).replace(b'a_b', b'a\x00b')
                elif '\\' in name:
                    # Windows ZipInfo normalizes backslashes when writing fixtures.
                    data = zip_bytes([('a_b', b'x')]).replace(b'a_b', b'a\\b')
                else:
                    data = zip_bytes([(name, b'x')])
                path = self.archive(data, f'bad-{index}.zip')
                with self.assertRaises(driver.DriverError):
                    driver.extract_archive(path, self.root / f'out-{index}')
        self.assertFalse((self.root / 'escape').exists())

    def test_duplicates_aliases_collisions(self):
        sets = [[('x', b'1'), ('x', b'2')], [('x', b'1'), ('X', b'2')],
                [('x', b'1'), ('x/y', b'2')], [('x/y', b'1'), ('x', b'2')],
                [('x/', b''), ('x', b'2')], [('Dir/a', b'1'), ('dir/b', b'2')],
                [('caf\u00e9/a', b'1'), ('cafe\u0301/b', b'2')]]
        for index, entries in enumerate(sets):
            with self.subTest(entries=entries):
                path = self.archive(zip_bytes(entries), f'bad-{index}.zip')
                with self.assertRaises(driver.DriverError):
                    driver.extract_archive(path, self.root / f'out-{index}')

    def test_links_and_special_files(self):
        for mode in [stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o600, stat.S_IFCHR | 0o600]:
            with self.subTest(mode=mode):
                info = zipfile.ZipInfo('link')
                info.create_system = 3
                info.external_attr = mode << 16
                path = self.archive(zip_bytes([(info, b'target')]), str(mode) + '.zip')
                with self.assertRaises(driver.DriverError):
                    driver.extract_archive(path, self.root / str(mode))

    def test_windows_reparse_attribute(self):
        info = zipfile.ZipInfo('link')
        info.create_system = 0
        info.external_attr = 0x400
        path = self.archive(zip_bytes([(info, b'data')]))
        with self.assertRaises(driver.DriverError):
            driver.extract_archive(path, self.root / 'out')

    def test_new_output_only(self):
        path = self.archive(zip_bytes([('file', b'new')]))
        out = self.root / 'out'
        out.mkdir()
        (out / 'keep').write_bytes(b'original')
        with self.assertRaises(driver.DriverError):
            driver.extract_archive(path, out)
        self.assertEqual((out / 'keep').read_bytes(), b'original')

    def test_entry_and_actual_byte_limits(self):
        path = self.archive(zip_bytes([('a', b'1234'), ('b', b'5678')]))
        with mock.patch.object(driver, 'MAX_ENTRIES', 1):
            with self.assertRaises(driver.DriverError):
                driver.extract_archive(path, self.root / 'count')
        with self.assertRaisesRegex(driver.DriverError, 'actual uncompressed'):
            driver._extract(path, self.root / 'bytes', driver.Budget(max_bytes=7))
        with self.assertRaises(driver.DriverError):
            driver._extract(path, self.root / 'member', driver.Budget(max_file_bytes=3))

    def test_central_size_and_archive_bounds(self):
        data = bytearray(zip_bytes([('x', b'data')]))
        for position, value in [(-10, 0xffffffff), (-6, 0xffffffff)]:
            altered = bytearray(data)
            struct.pack_into('<L', altered, len(altered) + position, value)
            path = self.archive(altered, f'bad-{position}.zip')
            with self.assertRaises(driver.DriverError):
                driver.extract_archive(path, self.root / f'out-{position}')
        path = self.archive(data)
        with mock.patch.object(driver, 'MAX_CENTRAL_BYTES', 1):
            with self.assertRaises(driver.DriverError):
                driver.extract_archive(path, self.root / 'central')
        with self.assertRaises(driver.DriverError):
            driver._extract(path, self.root / 'archive', driver.Budget(max_archive_bytes=10))

    def test_local_header_mismatch(self):
        data = bytearray(zip_bytes([('file', b'data')]))
        data[30] = ord('X')
        with self.assertRaises(driver.DriverError):
            driver.extract_archive(self.archive(data), self.root / 'out')

    def test_crc_corruption(self):
        data = bytearray(zip_bytes([('file', b'payload' * 10)]))
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            item = archive.infolist()[0]
            offset = item.header_offset + 30 + len(item.filename.encode())
        data[offset] ^= 0x40
        with self.assertRaises(driver.DriverError):
            driver.extract_archive(self.archive(data), self.root / 'out')

    def test_overlapping_headers_rejected(self):
        data = bytearray(zip_bytes([('file', b'data'), ('file2', b'data')]))
        first = data.index(b'PK\x01\x02')
        second = data.index(b'PK\x01\x02', first + 4)
        struct.pack_into('<L', data, second + 42, 0)
        with self.assertRaises(driver.DriverError):
            driver.extract_archive(self.archive(data), self.root / 'out')

    def alias_apk(self, extra=(), *, aliases=None):
        return verification_apk_bytes(native=False, extra=(
            resource_alias_entries() if aliases is None else aliases) + list(extra))

    def test_inventory_ascii_resource_aliases_both_pairs_both_orders_exact_hashes(self):
        for index, entries in enumerate((resource_alias_entries(), resource_alias_entries()[::-1])):
            with self.subTest(order=index):
                path = self.archive(self.alias_apk(aliases=entries), f'aliases-{index}.apk')
                result = driver._apk_inventory(path, driver.Budget(), None)
                resources = [row for row in result['entries'] if row['path'].startswith('res/')]
                self.assertEqual([row['path'] for row in resources], [name for name, _ in entries])
                self.assertEqual([(row['bytes'], row['sha256']) for row in resources],
                    [(len(data), hashlib.sha256(data).hexdigest()) for _, data in entries])
                self.assertFalse((self.root / 'extracted').exists())

    def test_inventory_resource_alias_family_with_explicit_parent_and_three_spellings(self):
        family = [('res/Ab.xml', b'first'), ('res/aB.xml', b'second'), ('res/AB.xml', b'third')]
        for reverse in (False, True):
            entries = [('res/', b'')] + family
            if reverse:
                entries.reverse()
            with self.subTest(reverse=reverse):
                result = driver._apk_inventory(self.archive(self.alias_apk(aliases=entries),
                    f'family-{reverse}.apk'), driver.Budget(), None)
                records = {row['path']: row for row in result['entries']}
                for name, payload in family:
                    self.assertEqual(records[name]['sha256'], hashlib.sha256(payload).hexdigest())

    def test_inventory_policy_requires_internal_enum_not_truthy_or_string_switch(self):
        path = self.archive(self.alias_apk(), 'policy.apk')
        for value in (True, False, None, 'apk_inventory_read_only', 'filesystem_strict'):
            with self.subTest(policy=value), self.assertRaisesRegex(driver.DriverError, 'internal ZIP'):
                driver._validated_zip(path, driver.Budget(), policy=value)

    def test_aliases_still_rejected_by_default_validator_and_extraction_before_destination(self):
        path = self.archive(self.alias_apk(), 'aliases.apk')
        with self.assertRaisesRegex(driver.DriverError, 'aliases'):
            driver._validated_zip(path, driver.Budget())
        for index, extract in enumerate((driver.extract_archive,
                lambda p, out: driver._extract(p, out, driver.Budget()))):
            out = self.root / f'strict-{index}'
            with self.subTest(extract=index), self.assertRaisesRegex(driver.DriverError, 'aliases'):
                extract(path, out)
            self.assertFalse(out.exists())

    def test_inventory_rejects_exact_duplicates_before_and_after_admitted_aliases(self):
        a, b = resource_alias_entries()[:2]
        for index, entries in enumerate(([a, a, b], [a, b, a], [a, b, b],
                                         [b, a, b], [b, b, a], [a, b, a, b])):
            with self.subTest(entries=entries), self.assertRaisesRegex(driver.DriverError, 'duplicate'):
                driver._apk_inventory(self.archive(self.alias_apk(aliases=entries),
                                      f'duplicate-{index}.apk'), driver.Budget(), None)

    def test_inventory_excluded_alias_families_and_shapes_both_orders(self):
        families = [('res/a.xml', 'RES/A.xml'), ('res/a.xml', 'res/A.XML'),
                    ('res/raw/a.xml', 'res/raw/A.xml'), ('res/a.txt', 'res/A.txt'),
                    ('res/a-b.xml', 'res/A-b.xml'), ('res/.xml', 'res/.XML'),
                    ('res/caf\u00e9.xml', 'res/cafe\u0301.xml'),
                    ('res/K.xml', 'res/\u212a.xml'), ('res/s.xml', 'res/\u017f.xml'),
                    ('AndroidManifest.xml', 'androidmanifest.xml'),
                    ('classes.dex', 'Classes.dex'), ('lib/x/a.so', 'lib/x/A.so'),
                    ('assets/a.xml', 'assets/A.xml'), ('META-INF/A.SF', 'META-INF/a.SF'),
                    ('res/Mi.xml', 'res/MI.XML')]
        for index, names in enumerate(families):
            with zipfile.ZipFile(io.BytesIO(verification_apk_bytes(native=False))) as base:
                baseline = [(n, base.read(n)) for n in base.namelist() if n not in names]
            for reverse in (False, True):
                with self.subTest(names=names, reverse=reverse):
                    # No exact duplicates obscure the excluded alias being tested.
                    # Binary/unparsed manifest bytes are valid inventory-only input.
                    entries = baseline + resource_alias_entries() + [(n, b'x') for n in names]
                    if reverse:
                        entries.reverse()
                    path = self.archive(zip_bytes(entries), f'shape-{index}-{reverse}.apk')
                    with self.assertRaises(driver.DriverError):
                        driver._apk_inventory(path, driver.Budget(), None)

    def test_inventory_parent_and_leaf_node_collisions_both_orders(self):
        conflicts = [('res', b'x'), ('RES/', b''), ('Res/other.xml', b'x'),
                     ('res/R5.xml/', b''), ('res/r5.xml/child', b'x'),
                     ('res/R5.xml/child', b'x'), ('res/r5.xml/', b'')]
        for index, conflict in enumerate(conflicts):
            for reverse in (False, True):
                entries = resource_alias_entries() + [conflict]
                if reverse:
                    entries.reverse()
                with self.subTest(conflict=conflict, reverse=reverse), self.assertRaises(driver.DriverError):
                    driver._apk_inventory(self.archive(self.alias_apk(aliases=entries),
                        f'node-{index}-{reverse}.apk'), driver.Budget(), None)

    def test_inventory_aliases_do_not_admit_malformed_or_reserved_paths(self):
        names = ['../escape', '/absolute', 'C:/escape', 'res//a.xml', 'res/./a.xml',
                 'res/../a.xml', 'res/CON.xml', 'res/NUL.xml', 'res/COM1.xml',
                 'res/a.xml.', 'res/a.xml ', 'res/a:b.xml', 'res/a?b.xml',
                 'res/a\x01b.xml', 'a/' * 65 + 'x', 'res/' + 'a' * 256 + '.xml']
        for index, name in enumerate(names):
            with self.subTest(name=name), self.assertRaises(driver.DriverError):
                driver._apk_inventory(self.archive(self.alias_apk([(name, b'x')]),
                    f'unsafe-{index}.apk'), driver.Budget(), None)
        for index, bad in enumerate((b'res/a\\b.xml', b'res/a\x00b.xml')):
            data = self.alias_apk([('res/a_b.xml', b'x')]).replace(b'res/a_b.xml', bad)
            with self.subTest(raw=bad), self.assertRaises(driver.DriverError):
                driver._apk_inventory(self.archive(data, f'raw-{index}.apk'), driver.Budget(), None)

    def test_inventory_alias_family_requires_ordinary_files_in_both_orders(self):
        attributes = [(stat.S_IFLNK | 0o777) << 16, (stat.S_IFIFO | 0o600) << 16,
                      (stat.S_IFCHR | 0o600) << 16, (stat.S_IFDIR | 0o700) << 16, 0x400]
        for index, attributes_ in enumerate(attributes):
            special = zipfile.ZipInfo('res/r5.xml')
            special.create_system = 3
            special.external_attr = attributes_
            for reverse in (False, True):
                entries = [('res/R5.xml', b'a'), (special, b'b')]
                if reverse:
                    entries.reverse()
                with self.subTest(attributes=attributes_, reverse=reverse), self.assertRaises(driver.DriverError):
                    driver._apk_inventory(self.archive(self.alias_apk(aliases=entries),
                        f'type-{index}-{reverse}.apk'), driver.Budget(), None)

    def test_inventory_aliases_accept_regular_or_unspecified_unix_file_type(self):
        for index, mode in enumerate((stat.S_IFREG | 0o600, 0o600)):
            entries = []
            for name, payload in resource_alias_entries():
                info = zipfile.ZipInfo(name)
                info.create_system = 3
                info.external_attr = mode << 16
                entries.append((info, payload))
            with self.subTest(mode=mode):
                result = driver._apk_inventory(self.archive(self.alias_apk(aliases=entries),
                    f'ordinary-{index}.apk'), driver.Budget(), None)
                self.assertEqual(len(result['entries']), 6)

    def alias_stored_zip(self):
        # Put the aliases first so full-read failures exercise admitted leaves.
        entries = resource_alias_entries() + [('AndroidManifest.xml', b'<manifest/>')]
        return bytearray(zip_bytes([(zipfile.ZipInfo(name), data) for name, data in entries]))

    def test_inventory_aliases_preserve_local_header_overlap_and_bounds_checks(self):
        for defect in ('name', 'flags', 'method', 'header', 'offset', 'overlap', 'bounds'):
            data = self.alias_stored_zip()
            central = data.index(b'PK\x01\x02')
            if defect == 'name':
                data[30] = ord('X')
            elif defect == 'flags':
                struct.pack_into('<H', data, 6, 8)
            elif defect == 'method':
                struct.pack_into('<H', data, 8, zipfile.ZIP_DEFLATED)
            elif defect == 'header':
                data[0] = 0
            elif defect == 'offset':
                struct.pack_into('<L', data, central + 42, 0xffffffff)
            else:
                size = struct.unpack_from('<L', data, central + 20)[0]
                struct.pack_into('<L', data, central + 20,
                                 size + 1 if defect == 'overlap' else len(data))
            with self.subTest(defect=defect), self.assertRaises(driver.DriverError):
                driver._apk_inventory(self.archive(data, f'local-{defect}.apk'), driver.Budget(), None)

    def test_inventory_aliases_preserve_encryption_and_compression_rejection(self):
        for defect in ('encrypted', 'bzip2', 'lzma', 'unknown'):
            data = self.alias_stored_zip()
            central = data.index(b'PK\x01\x02')
            if defect == 'encrypted':
                struct.pack_into('<H', data, 6, 1)
                struct.pack_into('<H', data, central + 8, 1)
            else:
                method = dict(bzip2=12, lzma=14, unknown=99)[defect]
                struct.pack_into('<H', data, 8, method)
                struct.pack_into('<H', data, central + 10, method)
            with self.subTest(defect=defect), self.assertRaisesRegex(driver.DriverError, 'encrypted or unsupported'):
                driver._apk_inventory(self.archive(data, f'method-{defect}.apk'), driver.Budget(), None)

    def test_inventory_aliases_full_read_crc_each_exact_member(self):
        for index in range(4):
            data = self.alias_stored_zip()
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                member = archive.infolist()[index]
                offset = member.header_offset + 30 + len(member.filename.encode())
            data[offset] ^= 0x40
            with self.subTest(member=index), self.assertRaises(zipfile.BadZipFile):
                driver._apk_inventory(self.archive(data, f'crc-{index}.apk'), driver.Budget(), None)

    def test_inventory_aliases_preserve_all_archive_budgets(self):
        data = self.alias_stored_zip()
        for index, (constant, value, budget, pattern) in enumerate((
                ('MAX_ENTRIES', 1, {}, 'central directory limit'),
                ('MAX_CENTRAL_BYTES', 1, {}, 'central directory limit'),
                ('MAX_ENTRIES', 5, {'entries': 1}, 'entry limit'),
                ('MAX_BYTES', driver.MAX_BYTES, {'max_file_bytes': 1}, 'member byte limit'),
                ('MAX_BYTES', driver.MAX_BYTES, {'max_bytes': 20}, 'actual uncompressed'),
                ('MAX_BYTES', driver.MAX_BYTES, {'max_archive_bytes': len(data) - 1}, 'archive size'))):
            with self.subTest(limit=index), mock.patch.object(driver, constant, value):
                with self.assertRaisesRegex(driver.DriverError, pattern):
                    driver._apk_inventory(self.archive(data, f'budget-{index}.apk'), driver.Budget(**budget), None)

    def test_inventory_aliases_preserve_actual_member_limit(self):
        budget = driver.Budget()
        original = budget.add_bytes
        def lower_member_limit(size):
            original(size)
            budget.max_file_bytes = 1  # Synthetic declared/actual drift after metadata validation.
        with mock.patch.object(budget, 'add_bytes', side_effect=lower_member_limit):
            with self.assertRaisesRegex(driver.DriverError, 'member actual byte limit'):
                driver._apk_inventory(self.archive(self.alias_stored_zip(), 'actual.apk'), budget, None)

    def test_inventory_aliases_preserve_central_directory_bounds(self):
        for index, position in enumerate((-10, -6)):
            data = self.alias_stored_zip()
            struct.pack_into('<L', data, len(data) + position, 0xffffffff)
            with self.subTest(position=position), self.assertRaises(driver.DriverError):
                driver._apk_inventory(self.archive(data, f'central-{index}.apk'), driver.Budget(), None)

    def test_direct_apk_inspect_stays_strict_but_nested_apkm_inventory_accepts_aliases(self):
        payload = self.alias_apk()
        direct = self.archive(payload, 'direct.apk')
        with self.assertRaisesRegex(driver.DriverError, 'aliases'):
            driver.inspect_archive(direct, self.root / 'direct-out')
        self.assertFalse((self.root / 'direct-out/extracted').exists())
        self.assertFalse((self.root / 'direct-out/inventory.json').exists())
        nested = self.archive(zip_bytes([('base.apk', payload)]), 'nested.apkm')
        result = driver.inspect_archive(nested, self.root / 'nested-out')
        self.assertEqual((self.root / 'nested-out/extracted/base.apk').read_bytes(), payload)
        paths = {row['path'] for row in result['apks'][0]['entries']}
        self.assertTrue({name for name, _ in resource_alias_entries()} <= paths)
        outer = self.archive(zip_bytes([('base.apk', payload), ('BASE.apk', payload)]), 'outer.apkm')
        with self.assertRaisesRegex(driver.DriverError, 'aliases'):
            driver.inspect_archive(outer, self.root / 'outer-out')
        self.assertFalse((self.root / 'outer-out/extracted').exists())

    def test_alias_inventory_does_not_enable_patchdev_or_assembly_packaging(self):
        path = self.archive(self.alias_apk(), 'packaging.apk')
        for filename in ('patchdev.py', 'assembly.py'):
            spec = importlib.util.spec_from_file_location('_alias_strict_' + filename[:-3], HERE / filename)
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            self.addCleanup(sys.modules.pop, spec.name, None)
            spec.loader.exec_module(module)
            checks = ([lambda: module.check_code_apk(path)] if filename == 'patchdev.py' else
                      [lambda: module._inventory(path),
                       lambda: module._write_unsigned(path, self.root / 'unsigned.apk', {})])
            for check in checks:
                with self.subTest(module=filename, check=check), self.assertRaisesRegex(
                        module.driver.DriverError, 'aliases'):
                    check()
        self.assertFalse((self.root / 'unsigned.apk').exists())

    def test_utf16_xml_entity_rejected(self):
        xml = '<!DOCTYPE manifest [<!ENTITY x "boom">]><manifest package="&x;"/>'.encode('utf-16-le')
        with self.assertRaises(driver.DriverError):
            self.inspect(zip_bytes([('AndroidManifest.xml', xml)]), 'app.apk')

    def test_xml_entity_rejected(self):
        xml = b'<!DOCTYPE manifest [<!ENTITY x "boom">]><manifest package="&x;"/>'
        with self.assertRaises(driver.DriverError):
            self.inspect(zip_bytes([('AndroidManifest.xml', xml)]), 'app.apk')


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def fake_process(self, status=0, running=False):
        process = mock.Mock()
        process.poll.return_value = None if running else status
        process.returncode = status
        return process

    def test_subprocess_trusted_cwd_no_shell(self):
        with mock.patch.object(driver.subprocess, 'Popen', return_value=self.fake_process()) as popen:
            self.assertEqual(driver.run_tool([sys.executable, '-I', '-c', 'pass']), ('', ''))
        self.assertFalse(popen.call_args.kwargs['shell'])
        self.assertEqual(popen.call_args.kwargs['cwd'], str(driver.SCRIPT_DIR))
        self.assertEqual(popen.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_subprocess_removes_inherited_jvm_injection_not_signing_env(self):
        injected = {name: 'synthetic-injection' for name in
                    ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH', 'KOTLIN_HOME')}
        injected['FISHY_FIXTURE_KS_SYNTHETIC'] = 'synthetic-value'
        with mock.patch.dict(os.environ, injected), mock.patch.object(
                driver.subprocess, 'Popen', return_value=self.fake_process()) as popen:
            driver.run_tool([sys.executable])
            child_env = popen.call_args.kwargs['env']
            for name in injected:
                if name != 'FISHY_FIXTURE_KS_SYNTHETIC':
                    self.assertNotIn(name, child_env)
                    self.assertIn(name, os.environ)
            self.assertEqual(child_env['FISHY_FIXTURE_KS_SYNTHETIC'], 'synthetic-value')

    def test_subprocess_spawn_error_is_sanitized(self):
        with mock.patch.object(driver.subprocess, 'Popen', side_effect=OSError('SECRET')):
            with self.assertRaises(driver.DriverError) as result:
                driver.run_tool([sys.executable])
        self.assertNotIn('SECRET', str(result.exception))

    def test_subprocess_exit_failure(self):
        with mock.patch.object(driver.subprocess, 'Popen', return_value=self.fake_process(17)):
            with self.assertRaisesRegex(driver.DriverError, '17'):
                driver.run_tool([sys.executable])

    def test_subprocess_timeout(self):
        process = self.fake_process(running=True)
        with mock.patch.object(driver.subprocess, 'Popen', return_value=process), mock.patch.object(
                driver.time, 'monotonic', side_effect=[0, 2]):
            with self.assertRaisesRegex(driver.DriverError, 'timeout'):
                driver.run_tool([sys.executable], timeout=1)
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)

    def test_subprocess_output_limit(self):
        process = self.fake_process()
        def start(*args, **kwargs):
            kwargs['stdout'].write(b'x' * 17)
            kwargs['stdout'].flush()
            return process
        with mock.patch.object(driver, 'MAX_TOOL_OUTPUT', 16), mock.patch.object(driver.subprocess, 'Popen', side_effect=start):
            with self.assertRaisesRegex(driver.DriverError, 'output limit'):
                driver.run_tool([sys.executable])

    def test_doctor_never_runs_tools_or_prints_secrets(self):
        with mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'secret-do-not-print'}), mock.patch.object(
                driver, 'run_tool') as run:
            result = driver.doctor()
        run.assert_not_called()
        self.assertNotIn('secret-do-not-print', json.dumps(result))
        self.assertTrue(result['environment_present']['GITHUB_TOKEN'])

    def test_descriptor_validation(self):
        for value in ['La/b/C;->method(I[Ljava/lang/String;)V',
                      'La/b/C;-><init>()V', 'La/b/C;->run()[[I']:
            with self.subTest(value=value):
                driver.validate_selector(value)
        for value in ['La/b/C;', 'C', 'a.b.C', 'run', 'LC;->run', 'LC;->run(V)V',
                      'LC;->run()[V', 'LC;->run()Vjunk', 'L;', 'La//b;', 'LC;->run(II)Vx']:
            with self.subTest(value=value):
                with self.assertRaises(driver.DriverError):
                    driver.validate_selector(value)

    def test_dex_exact_java_source_launch(self):
        apk = self.root / 'app.apk'
        apk.write_bytes(b'APK')
        out = self.root / 'result.json'
        helper = self.root / 'InspectDex.java'
        helper.write_text('// trusted fixture')
        jar = self.root / 'dependency.jar'
        jar.write_bytes(b'fixture')
        selector = 'La/b;->run()V'
        def run(args, **kwargs):
            with out.open('x') as stream:
                stream.write('{"result":true}')
            self.assertEqual(args, ['JAVA', '-cp', str(jar), str(helper), str(apk), str(out), selector])
        with mock.patch.object(driver, 'SCRIPT_DIR', self.root), mock.patch.object(
                driver, '_executable', return_value='JAVA'), mock.patch.object(driver, 'run_tool', side_effect=run):
            driver.dex(apk, selector, 'java', str(jar), out)
        with self.assertRaises(driver.DriverError):
            driver.dex(apk, selector, 'java', str(jar), out)

    def test_lazy_emulator_loader(self):
        helper = self.root / 'emulator.py'
        helper.write_text('def main(args):\n    return 0 if args == ["status", "--flag"] else 7\n')
        with mock.patch.object(driver, 'SCRIPT_DIR', self.root):
            self.assertEqual(driver.main(['emulator', 'status', '--flag']), 0)

    def test_cli_error_does_not_claim_success(self):
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            code = driver.main(['inspect', str(self.root / 'missing.apk'), '--out', str(self.root / 'out')])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue())['status'], 'failed')

    def collection_outputs(self, output):
        artifact = output / 'artifacts/patches/build/libs/example.mpp'
        artifact.parent.mkdir(parents=True)
        artifact.write_bytes(b'synthetic MPP, not Android build proof')
        (output / 'final-mpp.sha256').write_text(driver._hash_file(artifact) + '  /output/work/patches/build/libs/example.mpp\n')
        (output / 'artifacts/patches-list.json').write_text(json.dumps({
            'version': '0.1.0', 'patches': [{'name': 'synthetic'}]}))
        report = output / 'artifacts/patches/build/test-results/test/TEST-example.xml'
        report.parent.mkdir(parents=True)
        report.write_text('<testsuite tests="2" failures="0" errors="0" skipped="0"/>')

    def test_build_source_preserved_and_only_scoped_mounts(self):
        source = self.root / 'source'
        source.mkdir()
        gradlew = source / 'gradlew'
        gradlew.write_bytes(b'original source')
        output = self.root / 'out'
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            if args[1] == 'run':
                self.collection_outputs(output)
            return ('', '')
        with mock.patch.object(driver, '_executable', return_value='DOCKER'), mock.patch.object(
                driver, 'run_tool', side_effect=run), mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'secret-value'}):
            result = driver.build(source, 'trusted-image:1', output)
        self.assertEqual(gradlew.read_bytes(), b'original source')
        self.assertTrue(result['artifacts'])
        command = commands[0]
        self.assertEqual(command.count('--mount'), 3)
        self.assertIn('--rm', command)
        self.assertTrue(any('target=/output' in arg for arg in command))
        self.assertTrue(any('target=/source,readonly' in arg for arg in command))
        self.assertNotIn('secret-value', json.dumps(commands))
        self.assertEqual(result['status'], 'build_command_succeeded')
        self.assertEqual(result['tests']['tests'], 2)
        self.assertEqual(result['bundle']['sha256'], result['sha256'][result['bundle']['path']])
        self.assertEqual(command[command.index('--pull') + 1], 'never')
        self.assertIn('--no-build-cache', command[command.index('-c') + 1])
        self.assertIn('--rerun-tasks', driver.BUILD_SCRIPT)
        self.assertIn('gradle :patches:generatePatchesList', driver.BUILD_SCRIPT)
        self.assertIn('-PcatalogBundle=$bundle', driver.BUILD_SCRIPT)
        self.assertEqual(command[-5:], [driver.DEFAULT_PUBLICATION_REPOSITORY, '', 'false',
                                        ':patches:test', ':patches:buildAndroid'])

    def test_build_source_copy_preserves_entries_without_restoring_existing_directory_metadata(self):
        # GNU tar restores '.' metadata by default. Windows bind-mount directory
        # identities can change as children arrive, making that restoration fail.
        lines = driver.BUILD_SCRIPT.splitlines()
        self.assertEqual(lines[0], 'set -eu')
        copy = [line for line in lines if line.startswith('tar ')]
        self.assertEqual(copy, [
            'tar -C /source --exclude=.git --exclude=.gradle --exclude=build '
            '--exclude=local.properties -cf /output/source.tar .',
            'tar -C /output/work --no-overwrite-dir -xf /output/source.tar'])
        # Standalone commands under -e, not warning suppression, a filtered file
        # list, a pipeline masking tar's status, or an ignored extraction failure.
        self.assertLess(lines.index('mkdir /output/work /output/artifacts'), lines.index(copy[0]))
        self.assertLess(lines.index(copy[0]), lines.index(copy[1]))
        self.assertLess(lines.index(copy[1]), lines.index('cd /output/work'))

    def test_build_tar_failure_retains_partial_copy_and_cannot_reuse_output(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_bytes(b'unchanged source')
        output = self.root / 'out'
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            if args[1] == 'run':
                (output / 'work').mkdir()
                (output / 'work/partial').write_bytes(b'partial copy')
                (output / 'source.tar').write_bytes(b'failed archive fixture')
                (output / 'build.stderr.log').write_text('tar: Unexpected EOF in archive\n')
                raise driver.DriverError('subprocess exited with status 2')
            return '', ''
        with mock.patch.object(driver, '_executable', return_value='DOCKER'), mock.patch.object(
                driver, 'run_tool', side_effect=run):
            with self.assertRaisesRegex(driver.DriverError, 'status 2'):
                driver.build(source, 'image:1', output)
            with self.assertRaises(FileExistsError):
                driver.build(source, 'image:1', output)
        self.assertEqual(len(commands), 2)  # one run, then cleanup; no retry
        self.assertEqual(commands[-1][1:3], ['rm', '--force'])
        self.assertEqual((source / 'gradlew').read_bytes(), b'unchanged source')
        self.assertEqual((output / 'work/partial').read_bytes(), b'partial copy')
        self.assertEqual((output / 'source.tar').read_bytes(), b'failed archive fixture')
        self.assertIn('Unexpected EOF', (output / 'build.stderr.log').read_text())
        report = json.loads((output / 'build.json').read_text())
        self.assertEqual(report['status'], 'failed')
        self.assertNotIn('bundle', report)
        self.assertFalse((output / 'final-mpp.sha256').exists())

    def test_build_typed_inputs_and_offline_credentials(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_text('synthetic')
        output = self.root / 'out'
        def run(args, **kwargs):
            self.collection_outputs(output)
            return '', ''
        with mock.patch.object(driver, '_executable', return_value='DOCKER'), mock.patch.object(
                driver, 'run_tool', side_effect=run) as tool, mock.patch.dict(os.environ, {'GITHUB_TOKEN': 'private'}):
            result = driver.build(source, 'image:1', output, offline=True,
                                  publication_repository='Owner/Repository', version='0.1.0',
                                  tasks=['clean', 'test', 'buildAndroid'])
        args = tool.call_args.args[0]
        self.assertEqual(args.count('--pull'), 1)
        self.assertEqual(args[args.index('--network') + 1], 'none')
        self.assertNotIn('private', json.dumps(args))
        self.assertNotIn('GITHUB_TOKEN', args)  # offline never forwards the host credential
        self.assertEqual(args[-6:], ['Owner/Repository', '0.1.0', 'true', 'clean', 'test', 'buildAndroid'])
        self.assertEqual(result['catalog']['version'], '0.1.0')

    def test_build_validation_fails_before_docker_and_output_creation(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_text('synthetic')
        invalid = [dict(tasks=[]), dict(tasks='test'), dict(tasks=[None]),
                   dict(tasks=[':patches:publish']), dict(tasks=[':patches:test']),
                   dict(tasks=['test', ':patches:test', 'buildAndroid']),
                   dict(tasks=['test', 'buildAndroid', 'clean']),
                   dict(tasks=['buildAndroid', 'test']),
                   dict(tasks=['test', 'buildAndroid', '--init-script=evil']),
                   dict(publication_repository='Owner/Repo -Pfoo=bar'),
                   dict(publication_repository='https://github.com/a/b'),
                   dict(publication_repository=''), dict(version='0.1.0 --debug'),
                   dict(version='01.1.0'), dict(version=1)]
        with mock.patch.object(driver, '_executable') as executable, mock.patch.object(driver, 'run_tool') as tool:
            for index, values in enumerate(invalid):
                out = self.root / f'invalid-{index}'
                with self.subTest(values=values), self.assertRaises(driver.DriverError):
                    driver.build(source, 'image:1', out, **values)
                self.assertFalse(out.exists())
        executable.assert_not_called()
        tool.assert_not_called()

    def test_build_output_failures_record_failed_not_success(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_text('synthetic')
        def absent(out):
            shutil_target = out / 'artifacts/patches/build/libs/example.mpp'
            shutil_target.unlink()
        def duplicate(out):
            (out / 'artifacts/patches/build/libs/extra.mpp').write_bytes(b'extra')
        def no_reports(out):
            (out / 'artifacts/patches/build/test-results/test/TEST-example.xml').unlink()
        def bad_report(out):
            (out / 'artifacts/patches/build/test-results/test/TEST-example.xml').write_text(
                '<testsuite tests="2" failures="1" errors="0"/>')
        def no_tests(out):
            (out / 'artifacts/patches/build/test-results/test/TEST-example.xml').write_text(
                '<testsuite tests="2" failures="0" errors="0" skipped="2"/>')
        def malformed(out):
            (out / 'artifacts/patches-list.json').write_text('{bad')
        def wrong_version(out):
            (out / 'artifacts/patches-list.json').write_text('{"version":"9.0.0","patches":[{}]}')
        def changed(out):
            (out / 'final-mpp.sha256').write_text('0' * 64)
        def empty(out):
            (out / 'artifacts/patches/build/libs/example.mpp').write_bytes(b'')
        for index, mutate in enumerate([absent, duplicate, no_reports, bad_report, no_tests,
                                         malformed, wrong_version, changed, empty]):
            output = self.root / f'failure-{index}'
            def run(args, **kwargs):
                if args[1] == 'run':
                    self.collection_outputs(output)
                    mutate(output)
                return '', ''
            with self.subTest(case=mutate.__name__), mock.patch.object(
                    driver, '_executable', return_value='DOCKER'), mock.patch.object(
                    driver, 'run_tool', side_effect=run) as tool:
                with self.assertRaises(driver.DriverError):
                    driver.build(source, 'image:1', output, version='0.1.0')
                self.assertEqual(json.loads((output / 'build.json').read_text())['status'], 'failed')
                self.assertEqual(tool.call_args.args[0][1:3], ['rm', '--force'])
                self.assertTrue((output / 'artifacts/patches-list.json').exists())

    def test_build_success_without_artifacts_is_failed_and_cannot_be_reused(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_text('synthetic')
        output = self.root / 'out'
        with mock.patch.object(driver, '_executable', return_value='DOCKER'), mock.patch.object(
                driver, 'run_tool', return_value=('', '')):
            with self.assertRaisesRegex(driver.DriverError, 'no collected artifacts'):
                driver.build(source, 'image:1', output)
            with self.assertRaises(FileExistsError):
                driver.build(source, 'image:1', output)
        self.assertEqual(json.loads((output / 'build.json').read_text())['status'], 'failed')

    def test_build_cli_preserves_existing_flags_and_forwards_typed_inputs(self):
        with mock.patch.object(driver, 'build', return_value={'status': 'mocked'}) as build, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(driver.main(['build', '--source', str(self.root), '--image', 'image:1',
                '--out', str(self.root / 'out'), '--publication-repository', 'Owner/Repo',
                '--version', '0.1.0', '--task', 'test', '--task', 'buildAndroid']), 0)
        self.assertEqual(build.call_args.kwargs,
                         dict(publication_repository='Owner/Repo', version='0.1.0'))
        self.assertEqual(build.call_args.args[-1], ['test', 'buildAndroid'])

    def test_build_failure_cleans_container(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_bytes(b'original')
        commands = []
        def run(args, **kwargs):
            commands.append(args)
            if args[1] == 'run':
                raise driver.DriverError('subprocess exited with status 1')
            return ('', '')
        with mock.patch.object(driver, '_executable', return_value='DOCKER'), mock.patch.object(
                driver, 'run_tool', side_effect=run):
            with self.assertRaises(driver.DriverError):
                driver.build(source, 'image:1', self.root / 'out')
        self.assertEqual(commands[-1][1:3], ['rm', '--force'])
        self.assertEqual(json.loads((self.root / 'out/build.json').read_text())['status'], 'failed')

    def test_build_rejects_output_within_source(self):
        source = self.root / 'source'
        source.mkdir()
        (source / 'gradlew').write_bytes(b'original')
        with self.assertRaises(driver.DriverError):
            driver.build(source, 'image:1', source / 'out')


def verification_apk_bytes(package='org.example.app', version='7', split=None,
                           version_name='1.2', native=None, extra=(), root_attrs='', app_attrs=''):
    """Synthetic structural APK only; ELF header is not an executable JNI fixture."""
    manifest = ('<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
                f'package="{package}" android:versionCode="{version}" '
                + (f'android:versionName="{version_name}" ' if version_name is not None else '')
                + (f'split="{split}" ' if split is not None else '') + root_attrs + '>'
                + '<uses-sdk android:minSdkVersion="24"/>'
                + '<application ' + ('android:hasCode="false" ' if split else '')
                + app_attrs + '/></manifest>').encode()
    entries = [('AndroidManifest.xml', manifest)]
    if split is None:
        entries.append(('classes.dex', b'dex\n035\0'))
    if native is None:
        native = split is not None
    if native:
        header = bytearray(64)
        header[:7] = b'\x7fELF\x02\x01\x01'
        struct.pack_into('<HHI', header, 16, 3, 183, 1)
        struct.pack_into('<H', header, 52, 64)
        entries.append(('lib/arm64-v8a/arbitrary-name.so', bytes(header)))
    return zip_bytes(entries + list(extra))


class VerificationTests(unittest.TestCase):
    """Real synthetic APK ZIPs; all aapt2/Java processes are mocked."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.out = self.root / 'verification.json'
        self.jar = self.root / 'apksigner.jar'
        self.jar.write_bytes(b'trusted tool fixture, not executable')
        self.options = dict(aapt2='AAPT2', java='JAVA', signer_jar=self.jar,
                            expect_package='org.example.app', expect_version_code='7',
                            expect_version_name='1.2', expect_signer=['a' * 64],
                            abi='arm64-v8a', density='nodpi', language=['none'])
        self.base = self.apk('base.apk')
        self.split = self.apk('split.apk', split='config.arm64')
        self.signer_output = 'Signer #1 certificate SHA-256 digest: ' + 'A' * 64 + '\n'
        self.exec = mock.patch.object(driver, '_executable', side_effect=lambda value: value).start()
        self.run = mock.patch.object(driver, 'run_tool', side_effect=self.respond).start()
        self.addCleanup(mock.patch.stopall)

    def apk(self, name, **values):
        path = self.root / name
        path.write_bytes(verification_apk_bytes(**values))
        return path

    def respond(self, args, **kwargs):
        if args[0] == 'AAPT2' and args[2] == 'xmltree':
            with zipfile.ZipFile(args[-1]) as apk:
                return xmltree(apk.read('AndroidManifest.xml')), ''
        if args[0] == 'AAPT2':
            with zipfile.ZipFile(args[-1]) as apk:
                identity = driver._manifest(apk.read('AndroidManifest.xml'))
            attrs = [('name', identity['package']), ('versionCode', identity['version_code']),
                     ('versionName', identity['version_name'] if identity['version_name'] is not None else '')]
            if identity['split'] is not None:
                attrs.append(('split', identity['split']))
            return 'package: ' + ' '.join(f"{key}='{value}'" for key, value in attrs) + '\n', ''
        self.assertEqual(args[:6], ['JAVA', '-jar', str(self.jar), 'verify', '--verbose', '--print-certs'])
        return self.signer_output, ''

    def verify(self, paths=None, **options):
        return driver.verify_apks(paths if paths is not None else [self.base, self.split],
                                  out=self.out, **{**self.options, **options})

    def test_verified_bytes_and_explicit_selection_evidence(self):
        result = self.verify()
        self.assertEqual(result['status'], 'selected_split_set_verified')
        self.assertEqual(result['selection'], dict(abi='arm64-v8a', density='nodpi', languages=['none']))
        self.assertEqual(result['apks'][0]['sha256'], hashlib.sha256(self.base.read_bytes()).hexdigest())
        self.assertEqual(result['apks'][0]['signers_sha256'], ['a' * 64])
        self.assertEqual(json.loads(self.out.read_text()), result)

    def test_resource_alias_inventory_still_requires_successful_fresh_verification(self):
        self.base.write_bytes(verification_apk_bytes(extra=resource_alias_entries()))
        result = self.verify()
        self.assertEqual(result['status'], 'selected_split_set_verified')
        self.assertEqual(result['apks'][0]['sha256'], hashlib.sha256(self.base.read_bytes()).hexdigest())
        self.assertEqual(result['apks'][0]['signers_sha256'], ['a' * 64])
        self.assertEqual(json.loads(self.out.read_text()), result)

    def test_alias_bearing_apk_wrong_identity_signer_or_signer_failure_never_reports_success(self):
        cases = [('package', dict(package='org.other.app')), ('code', dict(version='8')),
                 ('name', dict(version_name='1.3')), ('signer', {}), ('missing_signer', {}),
                 ('signer_failure', {})]
        for label, values in cases:
            with self.subTest(case=label):
                self.base.write_bytes(verification_apk_bytes(extra=resource_alias_entries(), **values))
                self.signer_output = ('Signer #1 certificate SHA-256 digest: '
                                      + ('b' if label == 'signer' else 'a') * 64 + '\n')
                if label == 'missing_signer':
                    self.signer_output = ''
                def respond(args, **kwargs):
                    if label == 'signer_failure' and args[0] == 'JAVA':
                        raise driver.DriverError('subprocess exited with status 1')
                    return self.respond(args, **kwargs)
                self.run.side_effect = respond
                with self.assertRaises(driver.DriverError):
                    self.verify()
                self.assertFalse(self.out.exists())

    def test_alias_bearing_apk_mutations_during_inventory_signer_or_later_member_fail(self):
        for phase in ('inventory', 'signer', 'later_member'):
            with self.subTest(phase=phase):
                self.base.write_bytes(verification_apk_bytes(extra=resource_alias_entries()))
                def mutate(args, **kwargs):
                    result = self.respond(args, **kwargs)
                    if ((phase == 'inventory' and args[:3] == ['AAPT2', 'dump', 'badging'])
                            or (phase == 'signer' and args[0] == 'JAVA' and args[-1] == str(self.base))
                            or (phase == 'later_member' and args[0] == 'JAVA' and args[-1] == str(self.split))):
                        self.base.write_bytes(self.base.read_bytes() + b'changed')
                    return result
                self.run.side_effect = mutate
                with self.assertRaisesRegex(driver.DriverError, 'changed'):
                    self.verify()
                self.assertFalse(self.out.exists())

    def test_cli_verify_apks_dispatches_actual_verifier(self):
        args = ['verify-apks', str(self.base), str(self.split), '--out', str(self.out),
                '--aapt2', 'AAPT2', '--java', 'JAVA', '--signer-jar', str(self.jar),
                '--expect-package', 'org.example.app', '--expect-version-code', '7',
                '--expect-version-name', '1.2', '--expect-signer', 'a' * 64,
                '--abi', 'arm64-v8a', '--density', 'nodpi', '--language', 'none']
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            self.assertEqual(driver.main(args), 0)
        self.assertEqual(json.loads(stdout.getvalue())['apk_count'], 2)
        self.assertEqual(len(json.loads(self.out.read_text())['apks']), 2)

    def test_cli_requires_all_verification_pins_and_selection(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            driver.main(['verify-apks', str(self.base), '--out', str(self.out)])
        self.assertEqual(failure.exception.code, 2)
        self.run.assert_not_called()

    def test_unique_existing_apk_files_required_before_tools(self):
        directory = self.root / 'directory.apk'
        directory.mkdir()
        other = self.root / 'not-apk.zip'
        other.write_bytes(self.base.read_bytes())
        for paths in ([], [self.base, self.base], [directory], [other]):
            with self.subTest(paths=paths), self.assertRaises(driver.DriverError):
                self.verify(paths)
        self.run.assert_not_called()
        self.assertFalse(self.out.exists())

    def test_hardlink_duplicate_refused(self):
        alias = self.root / 'hardlink.apk'
        os.link(self.base, alias)
        with self.assertRaisesRegex(driver.DriverError, 'unique'):
            self.verify([self.base, alias])
        self.run.assert_not_called()

    def test_expected_identity_and_signer_must_be_explicit_valid(self):
        for bad in (dict(expect_package=''), dict(expect_package='single'),
                    dict(expect_package='org.bad;echo'), dict(expect_version_code='-1'),
                    dict(expect_version_code='2147483648'), dict(expect_version_code='01'),
                    dict(expect_version_name=' '), dict(expect_version_name='a\nb'),
                    dict(expect_signer=[]), dict(expect_signer=['z' * 64]),
                    dict(expect_signer=['a' * 64, 'A' * 64])):
            with self.subTest(bad=bad), self.assertRaises(driver.DriverError):
                self.verify(**bad)
        self.run.assert_not_called()

    def test_missing_or_invalid_manifest_identity_rejected(self):
        original = driver._apk_inventory
        for bad in (None, {}, {'package': 'single'},
                    {'package': 'org.example.app', 'version_code': '7', 'version_name': None},
                    {'package': 'org.example.app', 'version_code': 'abc', 'version_name': '1.2'},
                    {'package': 'org.example.app', 'version_code': '7', 'version_name': '1.2', 'split': ''}):
            with self.subTest(identity=bad), mock.patch.object(driver, '_apk_inventory',
                    return_value={'manifest': bad, 'native_abis': []}), self.assertRaises(driver.DriverError):
                self.verify()
        self.assertIs(driver._apk_inventory, original)
        self.assertFalse(self.out.exists())

    def test_package_code_and_name_mismatch_fail(self):
        for key, value in [('package', 'org.other.app'), ('version_code', '8'), ('version_name', '1.3')]:
            identity = dict(package='org.example.app', version_code='7', version_name='1.2', split=None)
            identity[key] = value
            with self.subTest(key=key), mock.patch.object(driver, '_apk_inventory',
                    return_value={'manifest': identity, 'native_abis': []}), self.assertRaisesRegex(driver.DriverError, 'expected'):
                self.verify()
        self.assertFalse(self.out.exists())

    def test_missing_base_duplicate_base_and_split_rejected(self):
        sets = [[self.split], [self.base, self.apk('base2.apk')],
                [self.base, self.split, self.apk('duplicate.apk', split='config.arm64')]]
        for paths in sets:
            with self.subTest(paths=paths), self.assertRaises(driver.DriverError):
                self.verify(paths)
        self.assertFalse(self.out.exists())

    def test_signer_mismatch_missing_ambiguous_evidence_rejected(self):
        for output in ('', 'Signer #1 certificate SHA-256 digest: ' + 'b' * 64 + '\n',
                       self.signer_output * 2, self.signer_output.replace('#1', '#2'),
                       self.signer_output + 'Signer #2 certificate SHA-256 digest: garbage\n',
                       'Signer #1 certificate SHA-256 digest: garbage\n'):
            with self.subTest(output=output), self.assertRaises(driver.DriverError):
                self.signer_output = output
                self.verify()
        self.assertFalse(self.out.exists())

    def test_multiple_pinned_signers_normalized_as_set(self):
        self.signer_output += 'Signer #2 certificate SHA-256 digest: ' + 'B' * 64 + '\n'
        result = self.verify(expect_signer=['B' * 64, 'A' * 64])
        self.assertEqual(result['apks'][1]['signers_sha256'], ['a' * 64, 'b' * 64])

    def test_split_signer_drift_rejected(self):
        original = self.respond
        def drift(args, **kwargs):
            if args[0] == 'JAVA' and args[-1] == str(self.split):
                return self.signer_output.replace('A', 'B'), ''
            return original(args, **kwargs)
        self.run.side_effect = drift
        with self.assertRaisesRegex(driver.DriverError, 'signer'):
            self.verify()
        self.assertFalse(self.out.exists())

    def test_apksigner_failure_does_not_write_success(self):
        original = self.respond
        def fail(args, **kwargs):
            if args[0] == 'JAVA':
                raise driver.DriverError('subprocess exited with status 1')
            return original(args, **kwargs)
        self.run.side_effect = fail
        with self.assertRaises(driver.DriverError):
            self.verify()
        self.assertFalse(self.out.exists())

    def test_selection_must_be_explicit_and_native_abi_supported(self):
        for bad in (dict(abi=''), dict(abi='none'), dict(abi='x86_64'), dict(abi='armeabi'), dict(density=''),
                    dict(density='auto'), dict(language=[]), dict(language=['none', 'en']),
                    dict(language=['en', 'en']), dict(language=['en;evil'])):
            with self.subTest(bad=bad), self.assertRaises(driver.DriverError):
                self.verify(**bad)
        self.assertFalse(self.out.exists())

    def test_input_mutation_during_verification_is_rejected(self):
        original = self.respond
        def mutate(args, **kwargs):
            result = original(args, **kwargs)
            if args[0] == 'JAVA':
                self.base.write_bytes(self.base.read_bytes() + b'changed')
            return result
        self.run.side_effect = mutate
        with self.assertRaisesRegex(driver.DriverError, 'changed'):
            self.verify()
        self.assertFalse(self.out.exists())

    def test_existing_report_and_repository_output_refused(self):
        self.out.write_text('keep')
        with self.assertRaises(driver.DriverError):
            self.verify()
        self.assertEqual(self.out.read_text(), 'keep')
        with self.assertRaisesRegex(driver.DriverError, 'outside'):
            driver.external_output(driver.REPO_DIR / 'private-result.json')
        self.run.assert_not_called()


class ExtensionTests(unittest.TestCase):
    def test_dispatch_forwards_original_arguments_under_isolation(self):
        module = mock.Mock()
        module.main.return_value = 7
        spec = mock.Mock()
        spec.name = '_test_extension'
        with mock.patch.object(driver.importlib.util, 'spec_from_file_location', return_value=spec), \
             mock.patch.object(driver.importlib.util, 'module_from_spec', return_value=module), \
             mock.patch.object(Path, 'is_file', return_value=True):
            self.assertEqual(driver.main(['lab-init', '--archive', 'space in name.apkm']), 7)
        module.main.assert_called_once_with(['init', '--archive', 'space in name.apkm'])
        spec.loader.exec_module.assert_called_once_with(module)

    def test_single_command_assembly_helper_receives_no_extra_subcommand(self):
        module = mock.Mock()
        module.main.return_value = 0
        spec = mock.Mock()
        spec.name = '_test_assembly_extension'
        with mock.patch.object(driver.importlib.util, 'spec_from_file_location', return_value=spec), \
             mock.patch.object(driver.importlib.util, 'module_from_spec', return_value=module), \
             mock.patch.object(Path, 'is_file', return_value=True):
            self.assertEqual(driver.main(['assemble', '--help']), 0)
        module.main.assert_called_once_with(['--help'])

    def test_dispatch_uses_only_allowlisted_sibling_files(self):
        for command, (filename, _, _) in driver.EXTENSIONS.items():
            self.assertEqual(Path(filename).name, filename)
            self.assertIn(filename, {'lab.py', 'patchdev.py', 'assembly.py'})
            self.assertNotIn('/', command)

    def test_missing_helper_fails_without_running_other_commands(self):
        with mock.patch.object(Path, 'is_file', return_value=False), \
             contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(driver.main(['apply', '--config', 'missing.json']), 1)
        self.assertIn('required sibling', stderr.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
