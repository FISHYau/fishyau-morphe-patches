"""Bounded Android archive/build utilities. Entry point: py -I driver.py.

Archive contents and info.json are data, never executable instructions. Extraction
always creates a new destination; failed extractions are left for examination.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unicodedata
import uuid
import zipfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from enum import Enum

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_DIR = SCRIPT_DIR.parents[2]


def external_output(path: Path) -> Path:
    path = Path(path).resolve()
    if path.is_relative_to(REPO_DIR):
        raise DriverError('outputs, caches and evidence must stay outside the publication repository')
    return path


MAX_ENTRIES = 20000
MAX_BYTES = 3 * 1024**3
MAX_FILE_BYTES = 3 * 1024**3
SDK_MAX_BYTES = 8 * 1024**3
SDK_MAX_FILE_BYTES = 8 * 1024**3
SDK_MAX_ARCHIVE_BYTES = 8 * 1024**3
MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_CENTRAL_BYTES = 32 * 1024**2
MAX_METADATA_BYTES = 1024**2
MAX_TOOL_OUTPUT = 8 * 1024**2
TOOL_TIMEOUT = 120
BUILD_TIMEOUT = 1800
CHUNK = 64 * 1024
ANDROID_NS = '{http://schemas.android.com/apk/res/android}'


class DriverError(Exception):
    """An operation failed; no success or verification is implied."""


def _splitset_module():
    spec = importlib.util.spec_from_file_location('_morphe_splitset', SCRIPT_DIR / 'splitset.py')
    if spec is None or spec.loader is None:
        raise DriverError('sibling splitset.py is required')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SPLITSET = _splitset_module()


def validate_split_set(records: list[dict], *, abi: str, density: str) -> dict:
    """Shared pure topology API for later apply/assembly; requires verifier records."""
    try:
        return SPLITSET.validate_topology(records, abi=abi, density=density)
    except SPLITSET.SplitSetError as exc:
        raise DriverError(str(exc)) from exc


def _authoritative_manifest(apk: Path, aapt2: str) -> tuple[dict, dict]:
    output, _ = run_tool([aapt2, 'dump', 'xmltree', '--file', 'AndroidManifest.xml', str(apk)])
    try:
        raw = SPLITSET.parse_xmltree(output)
        return raw, SPLITSET.manifest_fields(raw)
    except SPLITSET.SplitSetError as exc:
        raise DriverError(str(exc)) from exc


@dataclass
class Budget:
    entries: int = 0
    bytes: int = 0
    max_bytes: int | None = None
    max_file_bytes: int | None = None
    max_archive_bytes: int | None = None

    def __post_init__(self):
        self.max_bytes = MAX_BYTES if self.max_bytes is None else self.max_bytes
        self.max_file_bytes = MAX_FILE_BYTES if self.max_file_bytes is None else self.max_file_bytes
        self.max_archive_bytes = MAX_ARCHIVE_BYTES if self.max_archive_bytes is None else self.max_archive_bytes

    def add_entry(self) -> None:
        self.entries += 1
        if self.entries > MAX_ENTRIES:
            raise DriverError('archive entry limit exceeded')

    def add_bytes(self, size: int) -> None:
        self.bytes += size
        if self.bytes > self.max_bytes:
            raise DriverError('actual uncompressed byte limit exceeded')


def _path_name(name: str, directory: bool) -> str:
    if not name or '\\' in name or '\x00' in name or name.startswith('/'):
        raise DriverError('unsafe archive path')
    value = name[:-1] if directory and name.endswith('/') else name
    parts = value.split('/')
    if len(value) > 4096 or len(parts) > 64:
        raise DriverError('archive path limit exceeded')
    for part in parts:
        if (not part or part in ('.', '..') or part.endswith(('.', ' '))
                or len(part.encode('utf-8')) > 255
                or any(ord(c) < 32 or ord(c) == 127 or c in '<>:"|?*' for c in part)):
            raise DriverError('unsafe archive path component')
        stem = part.split('.')[0].rstrip(' .').upper()
        if (stem in {'CON', 'PRN', 'AUX', 'NUL', 'CONIN$', 'CONOUT$'}
                or re.fullmatch(r'(?:COM|LPT)[1-9¹²³]', stem)):
            raise DriverError('Windows reserved archive name')
    return '/'.join(parts)


def _zip_directory_bounds(stream, budget: Budget) -> tuple[int, int]:
    stream.seek(0, os.SEEK_END)
    length = stream.tell()
    if length > budget.max_archive_bytes or length < 22:
        raise DriverError('invalid archive size')
    stream.seek(max(0, length - 65557))
    tail = stream.read(65557)
    position = len(tail)
    while True:
        position = tail.rfind(b'PK\x05\x06', 0, position)
        if position < 0:
            raise DriverError('ZIP end record missing')
        if position + 22 <= len(tail):
            values = struct.unpack_from('<4s4H2LH', tail, position)
            if position + 22 + values[-1] == len(tail):
                break
    _, disk, central_disk, disk_count, count, size, offset, _ = values
    absolute_end = length - len(tail) + position
    if disk or central_disk or disk_count != count:
        raise DriverError('multidisk archives are not supported')
    stream.seek(max(0, absolute_end - 20))
    locator = stream.read(20)
    if locator[:4] == b'PK\x06\x07':
        _, zip64_disk, zip64_offset, disks = struct.unpack('<4sLQL', locator)
        if zip64_disk or disks != 1 or zip64_offset + 56 > absolute_end - 20:
            raise DriverError('invalid ZIP64 locator')
        stream.seek(zip64_offset)
        header = stream.read(56)
        if len(header) != 56 or header[:4] != b'PK\x06\x06':
            raise DriverError('invalid ZIP64 end record')
        fields = struct.unpack('<4sQ2H2L4Q', header)
        _, record_size, _, _, disk64, central_disk64, disk_count64, count64, size64, offset64 = fields
        # CPython ZipFile supports the fixed-size ZIP64 end record, not arbitrary
        # extensible sectors. Reject those instead of letting its inferred offsets drift.
        if (record_size != 44 or zip64_offset + 56 != absolute_end - 20
                or disk64 or central_disk64 or disk_count64 != count64
                or (count != 65535 and count != count64)
                or (size != 0xffffffff and size != size64)
                or (offset != 0xffffffff and offset != offset64)):
            raise DriverError('inconsistent ZIP64 end record')
        count, size, offset, absolute_end = count64, size64, offset64, zip64_offset
    elif count == 65535 or size == 0xffffffff or offset == 0xffffffff:
        raise DriverError('ZIP64 locator missing')
    if count > MAX_ENTRIES or size > MAX_CENTRAL_BYTES:
        raise DriverError('ZIP central directory limit exceeded')
    if offset + size != absolute_end:
        raise DriverError('invalid ZIP central directory bounds')
    return offset, count


class _ZipPolicy(Enum):
    FILESYSTEM_STRICT = 'filesystem_strict'
    APK_INVENTORY_READ_ONLY = 'apk_inventory_read_only'


def _validated_zip(path: Path, budget: Budget, *,
                   policy: _ZipPolicy = _ZipPolicy.FILESYSTEM_STRICT) -> zipfile.ZipFile:
    """Validate all metadata; only APK inventory may admit ASCII resource leaves.

    The inventory exception is not safe for extraction or repacking. Folded node
    and prefix checks still apply, including below an admitted resource leaf.
    """
    if not isinstance(policy, _ZipPolicy):
        raise DriverError('invalid internal ZIP validation policy')
    stream = path.open('rb')
    archive = None
    try:
        central, count = _zip_directory_bounds(stream, budget)
        archive = zipfile.ZipFile(stream)
        members = archive.infolist()
        if len(members) != count:
            raise DriverError('inconsistent ZIP entry count')
        explicit = set()
        exact = set()
        resource_leaves = set()
        nodes = {}
        spellings = {}
        spans = []
        for member in members:
            budget.add_entry()
            directory = member.is_dir()
            name = _path_name(member.orig_filename, directory)
            key = unicodedata.normalize('NFC', name).casefold()
            # Eligibility is per ordinary leaf, never a namespace-wide bypass.
            # Keep the normal type/reparse checks below mandatory for every entry.
            mode_type = stat.S_IFMT((member.external_attr >> 16) & 0xffff)
            resource_leaf = (
                policy is _ZipPolicy.APK_INVENTORY_READ_ONLY
                and not directory and mode_type in (0, stat.S_IFREG)
                and not member.external_attr & 0x400
                and re.fullmatch(r'res/[A-Za-z0-9_]+\.xml', name) is not None)
            if name in exact:
                raise DriverError('duplicate archive path')
            exact.add(name)
            alias = resource_leaf and key in resource_leaves
            originals, normalized = name.split('/'), key.split('/')
            for i in range(1, len(originals) + 1):
                prefix = '/'.join(normalized[:i])
                spelling = '/'.join(originals[:i])
                if prefix in spellings and spellings[prefix] != spelling:
                    # Only the complete leaf may differ; parent/prefix aliases
                    # (including descendants of an admitted leaf) remain strict.
                    if not (alias and i == len(originals)):
                        raise DriverError('case or Unicode archive path aliases')
                else:
                    spellings[prefix] = spelling
            if key in explicit and not alias:
                raise DriverError('duplicate archive path')
            explicit.add(key)
            if resource_leaf:
                resource_leaves.add(key)
            mode = (member.external_attr >> 16) & 0xffff
            file_type = stat.S_IFMT(mode)
            if (file_type not in (0, stat.S_IFDIR, stat.S_IFREG)
                    or member.external_attr & 0x400
                    or (file_type == stat.S_IFDIR and not directory)
                    or (file_type == stat.S_IFREG and directory)):
                raise DriverError('links and special archive entries are forbidden')
            if (member.flag_bits & 1 or member.compress_type not in
                    (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise DriverError('encrypted or unsupported ZIP member')
            if member.file_size > budget.max_file_bytes or member.file_size < 0:
                raise DriverError('member byte limit exceeded')
            if directory and member.file_size:
                raise DriverError('directory contains data')
            pieces = key.split('/')
            for i in range(1, len(pieces)):
                parent = '/'.join(pieces[:i])
                if nodes.get(parent) == 'file':
                    raise DriverError('file-directory archive collision')
                nodes[parent] = 'directory'
            kind = 'directory' if directory else 'file'
            if key in nodes and nodes[key] != kind:
                raise DriverError('file-directory archive collision')
            nodes[key] = kind
            if member.header_offset < 0:
                raise DriverError('invalid local ZIP offset')
            stream.seek(member.header_offset)
            header = stream.read(30)
            if len(header) != 30 or header[:4] != b'PK\x03\x04':
                raise DriverError('invalid local ZIP header')
            fields = struct.unpack('<4s5H3L2H', header)
            flags, method, name_len, extra_len = fields[2], fields[3], fields[-2], fields[-1]
            local_name = stream.read(name_len)
            encoding = 'utf-8' if flags & 0x800 else 'cp437'
            if (flags != member.flag_bits or method != member.compress_type
                    or local_name.decode(encoding) != member.orig_filename):
                raise DriverError('inconsistent local ZIP header')
            end = member.header_offset + 30 + name_len + extra_len + member.compress_size
            if end > central or end < member.header_offset:
                raise DriverError('ZIP member outside data bounds')
            spans.append((member.header_offset, end))
        spans.sort()
        if any(a[1] > b[0] for a, b in zip(spans, spans[1:])):
            raise DriverError('overlapping ZIP members')
        # ZipFile does not own a passed stream; give our caller one close point.
        archive._driver_stream = stream
        return archive
    except Exception:
        if archive is not None:
            archive.close()
        stream.close()
        raise


def _close_zip(archive: zipfile.ZipFile) -> None:
    archive.close()
    archive._driver_stream.close()


def _read_member(archive, member, budget: Budget, sink=None, capture=False):
    digest = hashlib.sha256()
    total = 0
    data = bytearray() if capture else None
    with archive.open(member) as source:
        while True:
            block = source.read(CHUNK)
            if not block:
                break
            total += len(block)
            budget.add_bytes(len(block))
            if total > budget.max_file_bytes or (capture and total > MAX_METADATA_BYTES):
                raise DriverError('member actual byte limit exceeded')
            digest.update(block)
            if sink is not None:
                sink.write(block)
            if data is not None:
                data.extend(block)
    if total != member.file_size:
        raise DriverError('inconsistent actual ZIP member size')
    return total, digest.hexdigest(), bytes(data) if data is not None else None


def _extract(archive: Path, destination: Path, budget: Budget) -> list[dict]:
    destination = external_output(destination)
    zip_file = _validated_zip(archive, budget)
    try:
        destination.mkdir(parents=False, exist_ok=False)
        records = []
        for member in zip_file.infolist():
            name = _path_name(member.orig_filename, member.is_dir())
            target = destination.joinpath(*name.split('/'))
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                _read_member(zip_file, member, budget)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open('xb') as sink:
                size, digest, _ = _read_member(zip_file, member, budget, sink)
            records.append({'path': name, 'bytes': size, 'sha256': digest})
        return records
    finally:
        _close_zip(zip_file)


def extract_archive(archive: Path, destination: Path) -> list[dict]:
    """Extract a bounded ZIP to a NEW directory; return path/bytes/sha256 records.

    SDK provisioning uses independent 8 GiB compressed/member/actual limits;
    APK inspection remains capped at 3 GiB actual bytes. The parent must exist.
    ZIP64 is supported with bounded central-directory allocation. No content is
    executed. A failure may leave a partial destination; it is never reused.
    """
    try:
        budget = Budget(max_bytes=SDK_MAX_BYTES, max_file_bytes=SDK_MAX_FILE_BYTES,
                        max_archive_bytes=SDK_MAX_ARCHIVE_BYTES)
        return _extract(Path(archive).resolve(strict=True), Path(destination), budget)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        raise DriverError('archive extraction failed: ' + type(exc).__name__) from exc


def tool_environment() -> dict[str, str]:
    """Keep explicit tool/signing configuration, not inherited JVM injection."""
    env = dict(os.environ)
    for name in ('JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH', 'KOTLIN_HOME'):
        env.pop(name, None)
    return env


def run_tool(args: list[str], *, timeout=TOOL_TIMEOUT, log_dir: Path | None = None):
    """No shell, no untrusted cwd, bounded time and captured output; no echoing."""
    if not args or not all(isinstance(arg, str) and '\x00' not in arg for arg in args):
        raise DriverError('invalid subprocess arguments')
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(args, cwd=str(SCRIPT_DIR), shell=False,
                                       env=tool_environment(),
                                       stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr)
        except OSError as exc:
            raise DriverError('cannot start executable: ' + type(exc).__name__) from exc
        reason = None
        deadline = time.monotonic() + timeout
        try:
            while True:
                status = process.poll()
                if any(os.fstat(f.fileno()).st_size > MAX_TOOL_OUTPUT for f in (stdout, stderr)):
                    reason = 'subprocess output limit exceeded'
                    break
                if status is not None:
                    break
                if time.monotonic() >= deadline:
                    reason = 'subprocess timeout'
                    break
                time.sleep(0.03)
        finally:
            if process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise DriverError('subprocess did not terminate') from exc
        outputs = []
        for label, handle in (('stdout', stdout), ('stderr', stderr)):
            handle.seek(0)
            data = handle.read(MAX_TOOL_OUTPUT)
            if log_dir is not None:
                with (log_dir / ('build.' + label + '.log')).open('xb') as log:
                    log.write(data)
            outputs.append(data.decode('utf-8', errors='replace'))
        if reason:
            raise DriverError(reason)
        if process.returncode:
            raise DriverError('subprocess exited with status ' + str(process.returncode))
        return tuple(outputs)


def _executable(value: str) -> str:
    found = shutil.which(value)
    if found is None:
        raise DriverError('requested executable not found')
    path = Path(found).resolve(strict=True)
    if path.suffix.lower() in {'.bat', '.cmd'}:
        raise DriverError('shell-wrapper executables are not accepted')
    return str(path)


def _metadata_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DriverError('duplicate metadata JSON key')
            result[key] = value
        return result
    value = json.loads(data.decode('utf-8-sig'), object_pairs_hook=pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if not isinstance(value, dict):
        raise DriverError('metadata JSON is not an object')
    return value


def _manifest(data: bytes) -> dict | None:
    if not data.lstrip().startswith(b'<'):
        return None
    # UTF-16 can hide declarations from byte searches while ElementTree expands
    # entities. Text fixtures are strictly UTF-8; real binary AXML uses aapt2.
    text = data.decode('utf-8-sig')
    if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise DriverError('manifest declarations are forbidden')
    root = ET.fromstring(text)
    if root.tag != 'manifest':
        raise DriverError('invalid manifest root')
    return {'package': root.attrib.get('package'),
            'version_code': root.attrib.get(ANDROID_NS + 'versionCode'),
            'version_name': root.attrib.get(ANDROID_NS + 'versionName'),
            'split': root.attrib.get('split')}


def _aapt_manifest(apk: Path, aapt2: str) -> dict:
    output, _ = run_tool([aapt2, 'dump', 'badging', str(apk)])
    lines = [line for line in output.splitlines() if line.startswith('package: ')]
    if len(lines) != 1:
        raise DriverError('aapt2 package identity missing or ambiguous')
    pairs = re.findall(r"(\w+)='([^']*)'", lines[0])
    attrs = dict(pairs)
    if len(attrs) != len(pairs):
        raise DriverError('duplicate aapt2 badging identity attribute')
    package = attrs.get('name')
    if not package or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*', package):
        raise DriverError('aapt2 package identity invalid')
    return {'package': package, 'version_code': attrs.get('versionCode'),
            'version_name': attrs.get('versionName'), 'split': attrs.get('split')}


def _apk_inventory(apk: Path, budget: Budget, aapt2: str | None) -> dict:
    # Exact ZipInfo reads only: this policy must never reach extraction/repacking.
    archive = _validated_zip(apk, budget, policy=_ZipPolicy.APK_INVENTORY_READ_ONLY)
    try:
        entries, dex, abis, dex_payloads, native_libraries = [], [], set(), [], []
        manifest = None
        has_manifest = False
        for member in archive.infolist():
            name = _path_name(member.orig_filename, member.is_dir())
            capture = name == 'AndroidManifest.xml'
            if capture and member.file_size > MAX_METADATA_BYTES:
                raise DriverError('manifest metadata limit exceeded')
            size, digest, data = _read_member(archive, member, budget, capture=capture)
            source = archive._driver_stream
            source.seek(member.header_offset + 26)
            name_len, extra_len = struct.unpack('<2H', source.read(4))
            offset = member.header_offset + 30 + name_len + extra_len
            entries.append({'path': name, 'bytes': size, 'sha256': digest,
                            'compression': member.compress_type, 'data_offset': offset})
            if name.lower().endswith('.dex') and not member.is_dir():
                dex_payloads.append(name)
            if re.fullmatch(r'classes(?:[2-9]|[1-9][0-9]+)?\.dex', name):
                dex.append(name)
            native = re.fullmatch(r'lib/([^/]+)/[^/]+\.so', name)
            if native and not member.is_dir():
                abis.add(native.group(1))
                with archive.open(member) as stream:
                    header = stream.read(64)
                budget.add_bytes(len(header))
                native_libraries.append({'path': name, 'abi': native.group(1),
                                         'elf_header': header.hex(), 'bytes': size,
                                         'compression': member.compress_type, 'data_offset': offset})
            elif name.lower().startswith('lib/') and not member.is_dir():
                # Do not silently hide unsupported native layouts or case variants.
                native_libraries.append({'path': name, 'abi': None})
            if capture:
                has_manifest = True
                manifest = _manifest(data)
        if not has_manifest:
            raise DriverError('APK has no AndroidManifest.xml')
        if aapt2:
            binary_identity = _aapt_manifest(apk, aapt2)
            if manifest is not None and any(
                    value is not None and binary_identity.get(key) != value
                    for key, value in manifest.items()):
                raise DriverError('aapt2 and XML manifest identities disagree')
            manifest = binary_identity
        return {'manifest': manifest, 'manifest_status': 'parsed' if manifest else 'binary_not_parsed',
                'dex': sorted(dex), 'dex_payloads': dex_payloads,
                'native_abis': sorted(abis), 'native_libraries': native_libraries, 'entries': entries}
    finally:
        _close_zip(archive)


def _check_consistency(apks: list[dict], metadata: dict | None) -> None:
    identities = [apk['manifest'] for apk in apks if apk['manifest']]
    for key in ('package', 'version_code'):
        values = {item[key] for item in identities if item.get(key) is not None}
        if len(values) > 1:
            raise DriverError('split APK manifest identities disagree')
    splits = [item.get('split') or '' for item in identities]
    if len(splits) != len(set(splits)):
        raise DriverError('duplicate split APK identity')
    # Metadata never selects commands, paths, or identity. Only compare known fields.
    if metadata is not None and identities:
        for field, key in (('package_name', 'package'), ('pname', 'package'),
                           ('version_code', 'version_code'), ('versioncode', 'version_code'),
                           ('version_name', 'version_name'), ('release_version', 'version_name')):
            value = metadata.get(field)
            # Intake badging cannot distinguish an omitted companion versionName
            # from an explicit empty one. Compare the base and known nonempty
            # companion names only; retain the raw inventory value unchanged.
            # This is NOT inheritance/acceptance: verify_apks proves presence
            # authoritatively and rejects explicit empty values before use.
            compared = [item for item in identities if not (
                key == 'version_name' and item.get('split') and
                item.get(key) in (None, ''))]
            if value is not None and any(str(value) != item.get(key) for item in compared):
                raise DriverError('untrusted info.json disagrees with APK identity')


def inspect_archive(archive: Path, out: Path, aapt2: str | None = None) -> dict:
    out = external_output(out)
    archive = archive.resolve(strict=True)
    aapt2 = _executable(aapt2) if aapt2 else None
    out.mkdir(parents=True, exist_ok=False)
    budget = Budget()
    records = _extract(archive, out / 'extracted', budget)
    metadata = None
    apks = []
    if archive.suffix.lower() == '.apk':
        apk = _apk_inventory(archive, budget, aapt2)
        apk['path'] = archive.name
        apk['sha256'] = _hash_file(archive)
        apks.append(apk)
    else:
        for record in records:
            path = out / 'extracted' / record['path']
            if record['path'] == 'info.json':
                if record['bytes'] > MAX_METADATA_BYTES:
                    raise DriverError('info.json metadata limit exceeded')
                metadata = _metadata_json(path.read_bytes())
            if path.suffix.lower() == '.apk':
                apk = _apk_inventory(path.resolve(), budget, aapt2)
                apk.update({'path': record['path'], 'sha256': record['sha256']})
                apks.append(apk)
    _check_consistency(apks, metadata)
    result = {'archive': {'name': archive.name, 'sha256': _hash_file(archive)},
              'files': records, 'apks': apks, 'untrusted_info_json': metadata,
              'manifest_consistency': 'checked' if apks and all(a['manifest'] for a in apks)
                                      else 'incomplete',
              'limits': {'actual_bytes_read': budget.bytes, 'entries_seen': budget.entries}}
    with (out / 'inventory.json').open('x', encoding='utf-8') as sink:
        json.dump(result, sink, indent=2, ensure_ascii=True)
    return result


def verification_arguments(parser):
    """The same mandatory verification contract is used by verify-apks and install."""
    parser.add_argument('--aapt2', required=True)
    parser.add_argument('--java', required=True)
    parser.add_argument('--signer-jar', type=Path, required=True, help='Trusted apksigner.jar')
    parser.add_argument('--expect-package', required=True)
    parser.add_argument('--expect-version-code', required=True)
    parser.add_argument('--expect-version-name', required=True)
    parser.add_argument('--expect-signer', action='append', required=True, help='Pinned certificate SHA-256; repeat for multiple signers')
    parser.add_argument('--abi', required=True, help='Explicit target ABI, or none for no native code')
    parser.add_argument('--density', required=True, help='Explicit density selection, e.g. xhdpi or nodpi')
    parser.add_argument('--language', action='append', required=True, help='Explicit language selection; none if no language split')


def verification_options(args):
    return dict(aapt2=args.aapt2, java=args.java, signer_jar=args.signer_jar,
                expect_package=args.expect_package, expect_version_code=args.expect_version_code,
                expect_version_name=args.expect_version_name, expect_signer=args.expect_signer,
                abi=args.abi, density=args.density, language=args.language)


def _valid_identity(identity):
    if (not isinstance(identity, dict)
            or not isinstance(identity.get('package'), str)
            or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+', identity['package'])
            or not isinstance(identity.get('version_code'), str)
            or not re.fullmatch(r'(?:0|[1-9][0-9]{0,9})', identity['version_code'])
            or int(identity['version_code']) > 2147483647
            or not isinstance(identity.get('version_name'), str)
            or not identity['version_name'].strip()
            or len(identity['version_name']) > 256
            or any(ord(c) < 32 for c in identity['version_name'])
            or (identity.get('split') is not None and (not isinstance(identity['split'], str)
                or not re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}', identity['split'])))):
        raise DriverError('explicit valid package/version/split identity required')


def verify_apks(apks: list[Path], aapt2: str, java: str, signer_jar: Path, out: Path, *,
                expect_package: str, expect_version_code: str, expect_version_name: str,
                expect_signer: list[str], abi: str, density: str, language: list[str]) -> dict:
    """Check exact selected bytes against pinned identity/signers, not split completeness."""
    out = external_output(out)
    if out.exists() or out.is_symlink() or not out.parent.is_dir():
        raise DriverError('verification output must be a new file')
    expected = dict(package=expect_package, version_code=expect_version_code,
                    version_name=expect_version_name, split=None)
    _valid_identity(expected)
    if (not expect_signer or any(not isinstance(s, str) or not re.fullmatch(r'[0-9a-fA-F]{64}', s)
                                 for s in expect_signer)):
        raise DriverError('explicit valid signer SHA-256 required')
    pinned = sorted(s.lower() for s in expect_signer)
    if len(set(pinned)) != len(pinned):
        raise DriverError('duplicate pinned signer')
    if (abi not in ('none', 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64', 'riscv64')
            or not isinstance(density, str) or not re.fullmatch(r'(?:nodpi|ldpi|mdpi|tvdpi|hdpi|xhdpi|xxhdpi|xxxhdpi|[1-9][0-9]{1,3}dpi)', density)
            or not language or len(set(language)) != len(language)
            or any(not isinstance(item, str) or not re.fullmatch(r'(?:none|[A-Za-z]{2,3}(?:[-+][A-Za-z0-9]{2,8})*)', item) for item in language)
            or ('none' in language and len(language) != 1)):
        raise DriverError('explicit valid ABI/density/language selection required')
    paths = [Path(path).resolve(strict=True) for path in apks]
    if (not paths or len(paths) > 256 or len(paths) != len(set(paths))
            or any(not path.is_file() or path.suffix.lower() != '.apk' for path in paths)
            or any(a.samefile(b) for i, a in enumerate(paths) for b in paths[i + 1:])):
        raise DriverError('explicit unique APK files required')
    aapt2, java = _executable(aapt2), _executable(java)
    signer_jar = Path(signer_jar).resolve(strict=True)
    if not signer_jar.is_file() or signer_jar.suffix.lower() != '.jar':
        raise DriverError('trusted apksigner JAR required')
    records = []
    budget = Budget()
    for path in paths:
        before = _hash_file(path)
        record = _apk_inventory(path, budget, aapt2)
        raw, declarations = _authoritative_manifest(path, aapt2)
        badging = record['manifest']
        if not isinstance(badging, dict):
            raise DriverError('missing badging identity cross-check')
        for key in ('package', 'version_code', 'version_name', 'split'):
            value = declarations[key]
            if key == 'version_name' and value is None and badging.get(key) in (None, ''):
                continue  # Raw XML-tree, not badging, proves absence.
            if badging.get(key) != value:
                raise DriverError('aapt2 badging and XML-tree identities disagree with expected declarations')
        identity = {key: declarations[key] for key in ('package', 'version_code', 'version_name', 'split')}
        # Only a manifest-identified companion may inherit the independently
        # pinned versionName. The mandatory base below must explicitly match it.
        if identity['split'] is not None and identity['version_name'] is None:
            identity['version_name'] = expect_version_name
        _valid_identity(identity)
        if any(identity[key] != expected[key] for key in ('package', 'version_code', 'version_name')):
            raise DriverError('selected APK package/version differs from expected identity')
        stdout, _ = run_tool([java, '-jar', str(signer_jar), 'verify', '--verbose', '--print-certs', str(path)])
        matches = re.findall(r'(?m)^Signer #([1-9][0-9]*) certificate SHA-256 digest: ([0-9a-fA-F]{64})[ \t]*\r?$', stdout)
        numbers = [int(number) for number, _ in matches]
        signers = sorted(digest.lower() for _, digest in matches)
        signer_rows = re.findall(r'(?m)^Signer #[^\r\n]* certificate SHA-256 digest:[^\r\n]*', stdout)
        if (not matches or len(signer_rows) != len(matches)
                or sorted(numbers) != list(range(1, len(matches) + 1))
                or len(set(signers)) != len(signers)):
            raise DriverError('apksigner returned missing or ambiguous signer SHA-256 evidence')
        if signers != pinned:
            raise DriverError('selected split signer certificates differ from pinned signers')
        if before != _hash_file(path):
            raise DriverError('APK changed during verification')
        records.append({'path': str(path), 'sha256': before, 'manifest': identity,
                        'raw_manifest': raw, 'manifest_declarations': declarations,
                        'dex_payloads': record['dex_payloads'], 'dex': record['dex'],
                        'native_libraries': record['native_libraries'],
                        'native_abis': record['native_abis'], 'signers_sha256': signers})
    # Identity/signers were pinned per member above; the shared validator owns
    # base uniqueness, split identities, native selection and topology policy.
    topology = validate_split_set(records, abi=abi, density=density)
    base = next(r for r in records if r['path'] == topology['base'])
    for record in records:
        m = record['manifest_declarations']
        record['effective_manifest'] = {**m, **record['manifest'],
            'has_code': m['has_code'] is not False,
            'min_sdk': m['min_sdk'] or base['manifest_declarations']['min_sdk'] or 1,
            'extract_native_libs': topology['extract_native_libs']}
        record['native_libraries'] = _verify_native_libraries(
            record['native_libraries'], abi=abi, extract_native_libs=topology['extract_native_libs'])
    # Recheck every member after all tools; later members must not mutate earlier ones.
    if any(_hash_file(Path(r['path'])) != r['sha256'] for r in records):
        raise DriverError('APK changed during selected-set verification')
    result = {'schema': 2, 'status': 'selected_split_set_verified', 'apks': records,
              'split_set': topology['mode'], 'topology': topology,
              'expected': {**expected, 'signers_sha256': pinned},
              'selection': {'abi': abi, 'density': density, 'languages': language},
              'note': 'Exact supplied set only; density/language completeness is a caller assertion, not inferred.'}
    with out.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    return result


def _verify_native_libraries(libraries: list[dict], *, abi: str, extract_native_libs: bool) -> list[dict]:
    """Check ABI ELF identity and 4-KiB direct-load ZIP policy, not JNI execution."""
    identities = {'arm64-v8a': (2, 183), 'armeabi-v7a': (1, 40),
                  'x86': (1, 3), 'x86_64': (2, 62), 'riscv64': (2, 243)}
    evidence = []
    for lib in libraries:
        library_abi = lib['abi']
        if library_abi not in identities:
            raise DriverError('unsupported native library layout or ABI')
        header = bytes.fromhex(lib['elf_header'])
        elf_class, machine = identities[library_abi]
        minimum = 64 if elf_class == 2 else 52
        if (len(header) < minimum or header[:4] != b'\x7fELF'
                or header[4:7] != bytes((elf_class, 1, 1)) or header[7] not in (0, 3)
                or struct.unpack_from('<HHI', header, 16) != (3, machine, 1)
                or struct.unpack_from('<H', header, 52 if elf_class == 2 else 40)[0] != minimum):
            raise DriverError('native ELF identity does not match declared ABI')
        if not extract_native_libs and (lib['compression'] != zipfile.ZIP_STORED or lib['data_offset'] % 4096):
            raise DriverError('extractNativeLibs=false requires stored page-aligned native payloads')
        evidence.append({**lib, 'elf_class': elf_class, 'elf_machine': machine,
                         'selected': library_abi == abi,
                         'zip_alignment_bytes': 4096 if not extract_native_libs else None,
                         'zip_data_aligned_4096': lib['data_offset'] % 4096 == 0,
                         'direct_load_policy_checked': not extract_native_libs,
                         'runtime_compatibility': 'not_proven'})
    return evidence


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(CHUNK), b''):
            digest.update(block)
    return digest.hexdigest()


def _type_descriptor(value: str, start: int, allow_void=False) -> int:
    index = start
    while index < len(value) and value[index] == '[':
        index += 1
    if index - start > 255 or index == len(value):
        raise DriverError('invalid full descriptor')
    c = value[index]
    if c in 'BCDFIJSZ' or (c == 'V' and allow_void and index == start):
        return index + 1
    if c == 'L':
        end = value.find(';', index)
        if end != -1 and re.fullmatch(r'[^/.;\[\s()<>]+(?:/[^/.;\[\s()<>]+)*', value[index + 1:end]):
            return end + 1
    raise DriverError('invalid full descriptor')


def validate_selector(selector: str) -> None:
    if not selector.startswith('L'):
        raise DriverError('selector must be a full method descriptor')
    end = _type_descriptor(selector, 0)
    if end == len(selector):
        raise DriverError('selector must include an exact method descriptor')
    match = re.match(r'->(?:[A-Za-z_$][A-Za-z0-9_$]*|<init>|<clinit>)\(', selector[end:])
    if not match:
        raise DriverError('selector must be a full method descriptor')
    index = end + match.end()
    while index < len(selector) and selector[index] != ')':
        index = _type_descriptor(selector, index)
    if index >= len(selector) or _type_descriptor(selector, index + 1, True) != len(selector):
        raise DriverError('invalid full method descriptor')


def dex(apk: Path, selector: str, java: str, classpath: str, out: Path) -> None:
    out = external_output(out)
    validate_selector(selector)
    apk = apk.resolve(strict=True)
    if out.exists() or out.is_symlink() or not out.parent.is_dir():
        raise DriverError('DEX output must be a new file in an existing directory')
    if not classpath or any(not entry for entry in classpath.split(os.pathsep)):
        raise DriverError('explicit classpath required; empty entries are forbidden')
    # Tools execute from the trusted script directory, not the caller directory.
    classpath = os.pathsep.join(str(Path(entry).resolve(strict=True))
                               for entry in classpath.split(os.pathsep))
    helper = SCRIPT_DIR / 'InspectDex.java'
    if not helper.is_file():
        raise DriverError('sibling InspectDex.java is missing')
    # The Java helper atomically reserves the path with CREATE_NEW.
    run_tool([_executable(java), '-cp', classpath, str(helper), str(apk),
              str(out.resolve()), selector])
    if not out.is_file() or out.stat().st_size == 0:
        raise DriverError('DEX helper produced no output')


BUILD_SCRIPT = '''set -eu
repository=$1
version=$2
offline=$3
shift 3
mkdir /output/work /output/artifacts
# A failed copy/build is retained externally, never retried in the same work tree.
tar -C /source --exclude=.git --exclude=.gradle --exclude=build --exclude=local.properties -cf /output/source.tar .
# Windows bind mounts can change directory inode identity while children arrive.
# Keep the fresh work root's metadata instead of restoring the archived '.';
# file contents and newly created directories still extract, and errors stay fatal.
tar -C /output/work --no-overwrite-dir -xf /output/source.tar
cd /output/work
collect() {
  find . -type f -path '*/build/*' \\( -name '*.mpp' -o -name '*.jar' -o -name '*.apk' -o -name '*.aab' -o -path '*/test-results/*/*.xml' \\) -exec sh -c '
  for file do
    relative=${file#./}
    mkdir -p "/output/artifacts/$(dirname "$relative")"
    cp "$file" "/output/artifacts/$relative"
  done' sh {} +
}
trap collect EXIT
gradle() {
  if [ "$offline" = true ]; then set -- --offline "$@"; fi
  if [ -n "$version" ]; then set -- "-Pversion=$version" "$@"; fi
  sh ./gradlew --no-daemon --max-workers=4 --no-build-cache --stacktrace "-PpublicationRepository=$repository" "$@"
}
gradle --rerun-tasks "$@"
# Fresh copy contains no old build outputs. Require exactly one final MPP.
find "$PWD" -type f -path '*/build/*' -name '*.mpp' > /output/mpp-paths.txt
[ "$(wc -l < /output/mpp-paths.txt)" -eq 1 ]
IFS= read -r bundle < /output/mpp-paths.txt
[ -s "$bundle" ]
before=$(sha256sum "$bundle")
# This task consumes compiled outputs and an explicitly selected bundle. It must
# not depend on buildAndroid or compilation; its classpath has no builtBy edges.
gradle :patches:generatePatchesList "-PcatalogBundle=$bundle" -PcatalogOutput=/output/artifacts/patches-list.json
[ "$before" = "$(sha256sum "$bundle")" ]
printf '%s\\n' "$before" > /output/final-mpp.sha256
'''

BUILD_TASKS = {':patches:test', ':patches:buildAndroid', ':patches:clean', 'test', 'buildAndroid', 'clean'}
DEFAULT_PUBLICATION_REPOSITORY = 'FISHYau/fishyau-morphe-patches'


def _collection_tasks(tasks):
    if tasks is None:
        return [':patches:test', ':patches:buildAndroid']
    if (not isinstance(tasks, (list, tuple)) or not tasks
            or any(not isinstance(task, str) or task not in BUILD_TASKS for task in tasks)):
        raise DriverError('only collection clean/test/buildAndroid tasks are allowed')
    normalized = [task if task.startswith(':') else ':patches:' + task for task in tasks]
    if normalized not in ([':patches:test', ':patches:buildAndroid'],
                          [':patches:clean', ':patches:test', ':patches:buildAndroid']):
        raise DriverError('collection tasks must be optional clean then test then buildAndroid exactly once')
    return list(tasks)


def _collection_results(out: Path, artifacts: list[str], version: str | None) -> dict:
    bundles = [path for path in artifacts if path.endswith('.mpp')]
    if len(bundles) != 1 or not (out / bundles[0]).stat().st_size:
        raise DriverError('build must collect exactly one nonempty final MPP')
    bundle = bundles[0]
    digest = _hash_file(out / bundle)
    recorded = (out / 'final-mpp.sha256').read_text(encoding='utf-8').split()
    if not recorded or recorded[0] != digest:
        raise DriverError('final MPP differs from the catalog input hash')
    catalog_path = 'artifacts/patches-list.json'
    catalog = _metadata_json((out / catalog_path).read_bytes())
    if (not isinstance(catalog.get('patches'), list) or not catalog['patches']
            or not isinstance(catalog.get('version'), str)
            or (version is not None and catalog['version'] != version)):
        raise DriverError('missing catalog entries or mismatched requested version')
    reports = sorted(path for path in artifacts if '/test-results/' in path and path.endswith('.xml'))
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    if not reports:
        raise DriverError('build produced no JUnit XML test results')
    for path in reports:
        data = (out / path).read_bytes()
        text = data.decode('utf-8-sig')
        if (len(data) > MAX_TOOL_OUTPUT or '\x00' in text
                or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper()):
            raise DriverError('invalid JUnit XML report')
        root = ET.fromstring(text)
        if root.tag != 'testsuite':
            raise DriverError('expected Gradle JUnit testsuite report')
        for key in counts:
            raw = root.get(key, '0' if key == 'skipped' else '')
            if not re.fullmatch(r'[0-9]+', raw):
                raise DriverError('invalid JUnit test result counts')
            counts[key] += int(raw)
    if counts['tests'] <= counts['skipped'] or counts['failures'] or counts['errors']:
        raise DriverError('collection tests did not execute successfully')
    return {'bundle': {'path': bundle, 'sha256': digest},
            'catalog': {'path': catalog_path, 'sha256': _hash_file(out / catalog_path),
                        'version': catalog['version']},
            'tests': {**counts, 'reports': reports}}


def build(source: Path, image: str, out: Path, offline=False, gradle_volume=None, tasks=None,
          publication_repository=DEFAULT_PUBLICATION_REPOSITORY, version=None) -> dict:
    out = external_output(out)
    source = source.resolve(strict=True)
    if not source.is_dir() or not (source / 'gradlew').is_file():
        raise DriverError('source must be an explicit Gradle project directory')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._/@:+-]*', image):
        raise DriverError('invalid Docker image argument')
    if ',' in str(source) or ',' in str(out.resolve()):
        raise DriverError('Docker bind paths cannot contain commas')
    try:
        out.resolve().relative_to(source)
    except ValueError:
        pass
    else:
        raise DriverError('build output cannot be inside source')
    volume = gradle_volume or ('morphe-gradle-' + uuid.uuid4().hex)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', volume):
        raise DriverError('invalid scoped Gradle volume name')
    tasks = _collection_tasks(tasks)
    if (not isinstance(publication_repository, str) or not re.fullmatch(
            r'[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*', publication_repository)):
        raise DriverError('publicationRepository must be GitHub OWNER/REPO')
    if version is not None and (not isinstance(version, str) or not re.fullmatch(
            r'(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?', version)):
        raise DriverError('version must be an explicit semantic version')
    docker = _executable('docker')
    out.mkdir(parents=True, exist_ok=False)
    name = 'morphe-build-' + uuid.uuid4().hex
    args = [docker, 'run', '--pull', 'never', '--rm', '--name', name, '--cap-drop', 'ALL',
            '--security-opt', 'no-new-privileges', '--mount',
            f'type=bind,source={source},target=/source,readonly', '--mount',
            f'type=volume,source={volume},target=/gradle', '--mount',
            f'type=bind,source={out.resolve()},target=/output',
            '--env', 'GRADLE_USER_HOME=/gradle']
    if offline:
        # Morphe's settings plugin eagerly requires non-null credential providers,
        # even offline. These inert placeholders cannot leave the networkless container.
        args += ['--network', 'none', '--env', 'GITHUB_ACTOR=offline',
                 '--env', 'GITHUB_TOKEN=offline-placeholder-not-a-credential']
    else:
        # Forward by name only. Never retrieve credentials or put values in argv.
        for key in ('GITHUB_TOKEN', 'GITHUB_ACTOR', 'GITHUB_REPOSITORY'):
            if key in os.environ:
                args += ['--env', key]
    args += ['--entrypoint', '/bin/sh', image, '-c', BUILD_SCRIPT, 'build',
             publication_repository, version or '', 'true' if offline else 'false', *tasks]
    metadata = {'out': str(out), 'gradle_volume': volume, 'offline': bool(offline),
                'image': image, 'tasks': tasks, 'publication_repository': publication_repository,
                'requested_version': version}
    try:
        run_tool(args, timeout=BUILD_TIMEOUT, log_dir=out)
        artifacts = sorted(path.relative_to(out).as_posix()
                           for path in (out / 'artifacts').rglob('*') if path.is_file())
        if not artifacts:
            raise DriverError('build exited successfully but produced no collected artifacts')
        evidence = _collection_results(out, artifacts, version)
        result = {**metadata, **evidence, 'status': 'build_command_succeeded',
                  'artifacts': artifacts,
                  'sha256': {path: _hash_file(out / path) for path in artifacts}}
    except (DriverError, OSError, ValueError, ET.ParseError) as exc:
        try:
            run_tool([docker, 'rm', '--force', name], timeout=30)
        except DriverError:
            pass
        # Output validation failures are failures too. Retain the copy, logs and
        # partial artifacts, without reflecting tool output or credential values.
        (out / 'build.json').write_text(json.dumps({**metadata, 'status': 'failed'}), encoding='utf-8')
        if isinstance(exc, DriverError):
            raise
        raise DriverError('collection output validation failed: ' + type(exc).__name__) from exc
    (out / 'build.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    return result


def doctor() -> dict:
    tools = {name: shutil.which(name) is not None for name in
             ('java', 'docker', 'adb', 'aapt2', 'gh')}
    return {'python': {'version': '.'.join(map(str, sys.version_info[:3])),
                       'isolated': bool(sys.flags.isolated)},
            'executables_available': tools,
            'environment_present': {key: bool(os.environ.get(key)) for key in
                                    ('JAVA_HOME', 'ANDROID_HOME', 'ANDROID_SDK_ROOT',
                                     'GITHUB_TOKEN', 'GITHUB_ACTOR')},
            'note': 'Presence only; tools, authentication and runtime are not verified.'}


def _emulator(args: list[str]) -> int:
    path = SCRIPT_DIR / 'emulator.py'
    spec = importlib.util.spec_from_file_location('_morphe_emulator', path)
    if spec is None or spec.loader is None or not path.is_file():
        raise DriverError('sibling emulator.py is missing')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    result = module.main(args)
    return 0 if result is None else int(result)


# Explicit sibling entry points keep the driver usable under Python -I without
# adding an input directory (or any directory) to the Python import path.
EXTENSIONS = {
    'lab-init': ('lab.py', 'init', 'Initialize a new private app-development lab'),
    'preflight': ('lab.py', 'preflight', 'Check explicit installed development tools'),
    'discover': ('lab.py', 'discover', 'Bounded JADX navigation; confirm targets with dex'),
    'fixture-build': ('patchdev.py', 'fixture-build', 'Build the self-authored unsigned Android fixture'),
    'patch-build': ('patchdev.py', 'patch-build', 'Build/test a private JVM development patch bundle'),
    'apply': ('patchdev.py', 'apply', 'Apply an exact trusted bundle with structural assertions'),
    'assemble': ('assembly.py', None, 'Assemble, align, sign and verify a supported APK'),
}


def _extension(command: str, argv: list[str]) -> int:
    filename, subcommand, _ = EXTENSIONS[command]
    path = SCRIPT_DIR / filename
    spec = importlib.util.spec_from_file_location('_morphe_extension_' + path.stem, path)
    if spec is None or spec.loader is None or not path.is_file():
        raise DriverError('required sibling development helper is missing')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    result = module.main(([subcommand] if subcommand is not None else []) + argv)
    return 0 if result is None else int(result)


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == 'emulator':
        return _emulator(argv[1:])
    if argv and argv[0] in EXTENSIONS:
        try:
            return _extension(argv[0], argv[1:])
        except (DriverError, OSError, ValueError, ImportError, AttributeError) as exc:
            print(json.dumps({'status': 'failed', 'error': str(exc) if isinstance(exc, DriverError)
                              else type(exc).__name__}), file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name, (_, _, description) in EXTENSIONS.items():
        commands.add_parser(name, help=description, add_help=False)
    commands.add_parser('doctor')
    inspect = commands.add_parser('inspect')
    inspect.add_argument('archive', type=Path)
    inspect.add_argument('--out', required=True, type=Path)
    inspect.add_argument('--aapt2')
    verify = commands.add_parser('verify-apks', help='Verify an explicitly selected APK set, without any device action')
    verify.add_argument('apks', type=Path, nargs='+')
    verify.add_argument('--out', type=Path, required=True)
    verification_arguments(verify)
    dex_parser = commands.add_parser('dex')
    dex_parser.add_argument('apk', type=Path)
    dex_parser.add_argument('--selector', required=True)
    dex_parser.add_argument('--java', required=True)
    dex_parser.add_argument('--classpath', required=True)
    dex_parser.add_argument('--out', required=True, type=Path)
    build_parser = commands.add_parser('build')
    build_parser.add_argument('--source', required=True, type=Path)
    build_parser.add_argument('--image', required=True)
    build_parser.add_argument('--out', required=True, type=Path)
    build_parser.add_argument('--offline', action='store_true')
    build_parser.add_argument('--gradle-volume')
    build_parser.add_argument('--task', action='append', help='Allowlisted collection task; test and buildAndroid required')
    build_parser.add_argument('--publication-repository', default=DEFAULT_PUBLICATION_REPOSITORY,
                              help='GitHub OWNER/REPO for bundle About metadata, not a publish operation')
    build_parser.add_argument('--version', help='Optional explicit collection semantic version')
    args = parser.parse_args(argv)
    try:
        if args.command == 'doctor':
            result = doctor()
        elif args.command == 'inspect':
            inventory = inspect_archive(args.archive, args.out, args.aapt2)
            identities = [apk['manifest'] for apk in inventory['apks'] if apk['manifest']]
            metadata = inventory['untrusted_info_json'] or {}
            metadata_identity = {key: str(metadata[key])[:128] for key in
                                 ('package_name', 'version_code', 'version_name')
                                 if isinstance(metadata.get(key), (str, int))}
            result = {'status': 'inventory_written',
                      'inventory': str((args.out / 'inventory.json').resolve()),
                      'sha256': inventory['archive']['sha256'],
                      'apk_count': len(inventory['apks']),
                      'file_count': len(inventory['files']),
                      'manifest_consistency': inventory['manifest_consistency'],
                      'manifest_identity': identities[0] if identities else None,
                      'untrusted_metadata_identity': metadata_identity}
        elif args.command == 'verify-apks':
            verified = verify_apks(args.apks, out=args.out, **verification_options(args))
            result = {'status': verified['status'], 'apk_count': len(verified['apks']),
                      'evidence': str(args.out.resolve())}
        elif args.command == 'dex':
            dex(args.apk, args.selector, args.java, args.classpath, args.out)
            result = {'status': 'helper_completed', 'out': str(args.out.resolve())}
        else:
            result = build(args.source, args.image, args.out, args.offline, args.gradle_volume, args.task,
                           publication_repository=args.publication_repository, version=args.version)
        print(json.dumps(result, ensure_ascii=True))
        return 0
    except (DriverError, OSError, ValueError, zipfile.BadZipFile, ET.ParseError,
            RecursionError, RuntimeError) as exc:
        # No subprocess output, filenames, environment values, or untrusted text.
        print(json.dumps({'status': 'failed', 'error': str(exc) if isinstance(exc, DriverError)
                          else type(exc).__name__}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
