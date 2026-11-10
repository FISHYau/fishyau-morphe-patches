#!/usr/bin/env python3
"""Fail-closed release validation/preparation; no network or publishing commands.

Evidence JSON is an authenticated-review INPUT, never cryptographic proof. Hashes
bind bytes, not truth. No APK, screenshot, raw log or private evidence is copied.
See CONTRACT in this module for the intentionally narrow initial policy.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import sys
import zipfile

CONTRACT = """release-v1
Manifest: version/download_url/created_at/description are nonempty strings;
created_at is UTC ISO LocalDateTime without Z/offset. public_key/page_url may be
absent or null; non-null public_key is unsupported by the unsigned-only gate.

The request has exactly: schema, owner, repository, version, created_at,
description, bundle_sha256, catalog_sha256, source_revision, source_tree_sha256,
manager_revision, patcher_version, input_sets, patches. schema is integer 1.
Input sets: id, package_name, version, version_code, abi, density, languages,
signer_sha256, files. files: id, role (base/split), sha256; exactly one base.
Patches: name, source_files (path/sha256 records relative to source root).

Evidence has exactly schema, inspection, patch_evidence. Inspection is a report
(kind=bundle-inspection) with binding, observed_at, tool, status, checks,
artifacts, patches, dependencies, about, signing. patches equals catalog patches
projected to name/compatiblePackages, retaining ALL compatibility fields.
The loader's dependencies object must explicitly map every bundled patch name
to a list of actual loaded dependency identifiers. Initial policy requires every
list empty; missing catalog dependency fields NEVER establish no dependencies.
about has name, author; signing must be unsigned. Inspection checks: android_bundle_load,
actual_definitions, metadata. The actual target patcher loader must produce it;
Python cannot load Android definitions or prove that report truthful.

Each patch_evidence entry has patch, input_set_id, selection, structural,
runtime. Each report has kind, binding, observed_at, tool, status, checks,
artifacts. binding has request_sha256, bundle_sha256, catalog_sha256,
source_revision, source_tree_sha256, manager_revision, patcher_version; per-case
bindings also have patch, input_set_sha256, selection and
patched_application_sha256 (identical structural/runtime output hash). Structural checks:
uncached_tests, patcher_round_trip, dex_control_flow, negative_fixtures.
Runtime checks: patched_feature_interaction, art_verification, manager_import,
visual_inspection. Every status/check is the STRING passed, not a boolean.
Reports require tool name/version/sha256 and artifact kind/sha256 records:
loader-report for inspection, test-report plus dex-report for structural,
runtime-report plus visual-review for runtime. Evidence artifact hashes
reference private reviewed material, never copied.
Reports must be <=7 days old and not in the future. Approval must follow them.

Approval has exactly schema, status=approved, reviewer, reviewed_at,
request_sha256, evidence_sha256, approved_patches. Names must exactly match all
bundled patches. It is a reviewer record, NOT a digital signature. A protected
human must authenticate evidence, review tool provenance, inspect private
runtime material, confirm patch selection/dependencies/options and authorize
public content. A caller-authored approval is not a security boundary.

Catalog version equals request/bundle version. Current generator patch fields
are name, description, default, category, compatiblePackages, options (there is
NO dependencies field). category and compatibility formFactor are nullable
strings. Each patch has a unique name and explicit finite compatiblePackages
targets: packageName, targets containing
version and nonempty versionCodes ABI->integer. All compatibility metadata is
compared with inspection. Wildcard/universal/experimental targets are blocked.
Every advertised package/version/ABI/code needs structural+runtime coverage;
extra/stale/failed/missing evidence and unapproved patches are blocked. Initial
policy also blocks nonempty options/dependencies until an adapter can bind
option values and resolve loader dependency identifiers safely.

Canonical tree digest: SHA256 of b'release-tree-v1\\0' followed by, for every
regular source file sorted by POSIX relative path, UTF8(path), NUL, lowercase
ASCII file SHA256, LF. Only top-level .git is excluded; symlinks, special files,
nonportable paths and case-fold collisions are rejected. Source files are
re-hashed at validation. Build outside the source tree. Preparation additionally
requires source root to be the Git root, exact committed HEAD, no tracked,
untracked or ignored changes/files, and every source file tracked. No Git
initialization or mutation is performed.

prepare writes only a NEW directory external to the source and this repository:
exact approved MPP and generated public catalog bytes, SHA256SUMS, sanitized
verification summary and patches-bundle.candidate.json (NOT a live manifest).
No signed bundle support, publication, release upload or channel advancement.
Future publication must reverify approved bytes, authenticate protected review,
upload and verify immutable assets BEFORE advancing main/patches-bundle.json.
"""

UTC = dt.timezone.utc
MAX_AGE = dt.timedelta(days=7)
MAX_JSON = 8 * 1024 * 1024
MAX_BUNDLE = 128 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
ABI = {"ARM64_V8A", "ARMEABI_V7A", "X86_64", "X86"}
HEX = re.compile(r"[0-9a-f]{64}\Z")
REV = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
DATE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?\Z", re.ASCII)
REPO_ROOT = Path(__file__).resolve().parents[2]


class ReleaseError(ValueError):
    """Unmet release contract; never a publish authorization."""


def require(condition, message):
    if not condition:
        raise ReleaseError(message)


def text(value, label):
    require(isinstance(value, str) and bool(value.strip()), f"{label}: nonempty string required")
    require(not any(ord(c) < 32 or ord(c) == 127 for c in value), f"{label}: control characters")
    return value


def exact(value, keys, label):
    require(isinstance(value, dict) and set(value) == set(keys.split()), f"{label}: unexpected or missing fields")
    return value


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")


def sha(value, label="sha256"):
    require(isinstance(value, str) and HEX.fullmatch(value), f"{label}: lowercase SHA256 required")
    return value


def revision(value):
    require(isinstance(value, str) and REV.fullmatch(value), "full lowercase 40-character revision required")


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def linked(path):
    # Windows junctions/reparse points must not bypass the external-output or
    # canonical-tree policy. is_junction is available on supported Python 3.12+.
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def read_bytes(path, limit):
    path = Path(path)
    require(path.is_file() and not linked(path), f"regular nonsymlink file required: {path}")
    require(path.stat().st_size <= limit, f"file too large: {path.name}")
    data = path.read_bytes()
    require(len(data) <= limit, "file grew beyond limit")
    return data


def read_json(path):
    data = read_bytes(path, MAX_JSON)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ReleaseError("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReleaseError(f"invalid JSON: {Path(path).name}") from exc
    return value, data


def local_time(value):
    require(isinstance(value, str) and DATE.fullmatch(value), "UTC LocalDateTime required, without Z or offset")
    try:
        # Construct explicitly: some Python versions normalize ISO 24:00:00,
        # whereas Java LocalDateTime rejects it. Validate nanoseconds but retain
        # microsecond precision for freshness comparisons.
        fields = [int(value[a:b]) for a, b in ((0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19))]
        micros = int((value[20:] + "000000")[:6]) if len(value) > 19 else 0
        return dt.datetime(*fields, microsecond=micros, tzinfo=UTC)
    except ValueError as exc:
        raise ReleaseError("invalid calendar date") from exc


def fresh(value, now):
    when = local_time(value)
    require(dt.timedelta(0) <= now - when <= MAX_AGE, "stale or future evidence/review")
    return when


def https_url(value, label):
    from urllib.parse import urlsplit
    text(value, label)
    require(not any(c.isspace() for c in value) and "\\" not in value and "%" not in value, f"{label}: ambiguous URL")
    parts = urlsplit(value)
    require(parts.scheme == "https" and parts.hostname and parts.username is None and parts.password is None,
            f"{label}: HTTPS URL without credentials required")
    require(not parts.query and not parts.fragment and parts.netloc == parts.hostname, f"{label}: ports/query/fragment unsupported")
    require(all(p not in {".", ".."} for p in parts.path.split("/")), f"{label}: dot path segments")
    return parts


def normalize_source(value):
    parts = https_url(value, "source")
    if parts.hostname == "github.com":
        fields = parts.path.strip("/").split("/")
        require(len(fields) == 2 and all(NAME.fullmatch(p) and p not in {".", ".."} for p in fields), "GitHub source must be OWNER/REPO")
        return f"https://raw.githubusercontent.com/{fields[0]}/{fields[1]}/main/patches-bundle.json"
    require(parts.path.endswith(".json"), "direct source must have a .json path")
    return value


def asset_url(owner, repository, version):
    for value in (owner, repository):
        require(isinstance(value, str) and NAME.fullmatch(value) and value not in {".", ".."}, "explicit owner/repository required")
    require(isinstance(version, str) and VERSION.fullmatch(version), "semantic version required")
    return f"https://github.com/{owner}/{repository}/releases/download/v{version}/patches-{version}.mpp"


def validate_manifest(value, owner=None, repository=None, version=None):
    require(isinstance(value, dict), "manifest must be object")
    required = {"version", "download_url", "created_at", "description"}
    require(required <= set(value) <= required | {"public_key", "page_url"}, "manifest fields mismatch")
    for key in required:
        text(value[key], key)
    local_time(value["created_at"])
    https_url(value["download_url"], "download_url")
    for key in ("public_key", "page_url"):
        if value.get(key) is not None:
            text(value[key], key)
    if value.get("page_url") is not None:
        https_url(value["page_url"], "page_url")
    if any(v is not None for v in (owner, repository, version)):
        require(all(v is not None for v in (owner, repository, version)), "owner/repository/version must be supplied together")
        require(value["version"] == version, "manifest version mismatch")
        require(value["download_url"] == asset_url(owner, repository, version), "manifest URL/artifact mismatch")
    return value


def make_manifest(request):
    result = {key: request[key] for key in ("version", "created_at", "description")}
    result["download_url"] = asset_url(request["owner"], request["repository"], request["version"])
    result["page_url"] = f"https://github.com/{request['owner']}/{request['repository']}/releases/tag/v{request['version']}"
    return validate_manifest(result, request["owner"], request["repository"], request["version"])


def portable_path(value):
    text(value, "path")
    parts = PurePosixPath(value).parts
    require(parts and not value.startswith("/") and "\\" not in value and ":" not in value,
            "relative POSIX path required")
    require("/".join(parts) == value and all(p not in {".", ".."} and not p.endswith((".", " ")) for p in parts), "noncanonical path")
    require(all(not re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", p) for p in parts), "reserved path")
    return value


def source_tree(root):
    root = Path(root)
    require(root.is_dir() and not linked(root), "source directory required")
    entries = {}
    folded = set()
    def inaccessible(error):
        raise ReleaseError("source directory could not be fully enumerated") from error
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=inaccessible):
        if Path(directory) == root and ".git" in dirs:
            dirs.remove(".git")
        for name in list(dirs) + files:
            path = Path(directory) / name
            require(not linked(path), "source symlinks/junctions are forbidden")
            relative = path.relative_to(root).as_posix()
            if relative == ".git":
                continue
            portable_path(relative)
            require(relative.casefold() not in folded, "case-fold path collision")
            folded.add(relative.casefold())
            mode = path.stat().st_mode
            require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "special source file")
            if stat.S_ISREG(mode):
                entries[relative] = digest(read_bytes(path, MAX_BUNDLE))
    require(entries, "empty source tree")
    data = b"release-tree-v1\0" + b"".join(p.encode("utf-8") + b"\0" + entries[p].encode("ascii") + b"\n" for p in sorted(entries))
    return digest(data), entries


def clean_revision(root, expected, paths):
    def git(*args):
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=False)
        require(proc.returncode == 0, "clean committed Git revision required (Git unavailable or command failed)")
        return proc.stdout
    require(Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() == Path(root).resolve(), "source must be Git root")
    require(git("rev-parse", "HEAD").decode().strip() == expected, "HEAD revision mismatch")
    require(not git("status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"), "source contains changed/untracked/ignored files")
    tracked = set(git("ls-files", "-z").decode("utf-8").rstrip("\0").split("\0"))
    require(tracked == set(paths), "source tree must contain exactly tracked regular files (no submodules)")


def bundle_metadata(data):
    import io
    require(len(data) <= MAX_BUNDLE, "bundle too large")
    # Restrict to a plain single-disk ZIP with no prepended/trailing envelope,
    # archive comment or ZIP64 extension. Never misread appended signatures as
    # unsigned ZIPs merely because zipfile tolerates arbitrary trailing bytes.
    require(len(data) >= 22 and data.startswith(b"PK\x03\x04") and data[-22:-18] == b"PK\x05\x06", "plain unsigned ZIP required; comments/envelopes/trailing signatures unsupported")
    end = struct.unpack("<4s4H2LH", data[-22:])
    require(end[1:3] == (0, 0) and end[3] == end[4] and end[3] < 65535 and end[7] == 0
            and end[5] + end[6] == len(data) - 22, "noncanonical/signed ZIP envelope unsupported")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            names = set()
            total = 0
            for info in bundle.infolist():
                name = info.filename.rstrip("/")
                portable_path(name)
                require(info.filename.casefold() not in names, "duplicate bundle member")
                names.add(info.filename.casefold())
                mode = info.external_attr >> 16
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR} and not info.flag_bits & 1, "special/encrypted bundle member")
                require(not re.search(r"(?i)\.(apk|apkm|apks|aab|png|jpe?g|webp|heic|gif)$", name), "app binaries/raw images must not be distributed inside a bundle")
                require(info.file_size <= MAX_MEMBER, "bundle member too large")
                total += info.file_size
                require(total <= MAX_BUNDLE, "expanded bundle too large")
                require(not re.search(r"(?i)(?:\.(?:sf|rsa|dsa|ec|sig)|(?:^|/)signature(?:\.[^/]*)?)$", name),
                        "signed bundle unsupported: real signature verification is not implemented")
            require("classes.dex" in bundle.namelist(), "Android classes.dex required; renamed JAR is insufficient")
            with bundle.open("classes.dex") as dex:
                magic = dex.read(8)
            require(re.fullmatch(rb"dex\n0(?:3[5-9]|4[01])\x00", magic), "invalid DEX magic")
            manifest = bundle.read("META-INF/MANIFEST.MF").decode("utf-8")
    except (zipfile.BadZipFile, KeyError, UnicodeError, RuntimeError, OSError) as exc:
        raise ReleaseError("invalid Android bundle archive") from exc
    logical = []
    for line in manifest.replace("\r\n", "\n").split("\n"):
        if not line:
            break  # Only main attributes; never accept spoofed named sections.
        if line.startswith(" "):
            require(logical, "orphan manifest continuation")
            logical[-1] += line[1:]
        else:
            logical.append(line)
    result = {}
    for line in logical:
        require(": " in line, "malformed manifest attribute")
        key, value = line.split(": ", 1)
        require(key.lower() not in result, "duplicate manifest attribute")
        result[key.lower()] = value
    return result


def catalog_patches(catalog, version):
    require(isinstance(catalog, dict) and catalog.get("version") == version, "catalog version mismatch")
    require(set(catalog) <= {"NOTE", "version", "patches"}, "unexpected catalog fields")
    if "NOTE" in catalog:
        text(catalog["NOTE"], "catalog note")
    patches = catalog.get("patches")
    require(isinstance(patches, list) and patches, "no patches to promote")
    names = set()
    result = []
    coverage = set()
    for patch in patches:
        exact(patch, "name description default category compatiblePackages options", "catalog patch")
        require(patch["description"] is None or isinstance(patch["description"], str), "invalid patch description")
        require(patch["category"] is None or isinstance(patch["category"], str), "invalid patch category")
        require(type(patch["default"]) is bool, "patch default must be boolean")
        # Options are present in the current generator DTO; dependencies are NOT.
        # Dependency policy is enforced using explicit trusted loader inspection.
        require(patch["options"] == [], "option selection verification unsupported")
        name = text(patch.get("name"), "patch name")
        require(name not in names, "duplicate patch name")
        names.add(name)
        compatible = patch.get("compatiblePackages")
        require(isinstance(compatible, list) and compatible, "universal/wildcard compatibility unsupported")
        package_names = set()
        for app in compatible:
            require(isinstance(app, dict) and {"packageName", "targets"} <= set(app) <= {"packageName", "name", "description", "apkFileType", "appIconColor", "signatures", "formFactor", "targets"}, "compatibility fields mismatch")
            for field in ("name", "description", "apkFileType", "appIconColor", "formFactor"):
                require(app.get(field) is None or isinstance(app[field], str), "invalid compatibility text")
            package = text(app.get("packageName"), "packageName")
            require(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+", package), "invalid package name")
            require(package not in package_names, "duplicate compatible package")
            package_names.add(package)
            signatures = app.get("signatures")
            if signatures is not None:
                require(isinstance(signatures, list) and signatures, "invalid compatibility signatures")
                for signature in signatures:
                    sha(signature, "compatibility signature")
            targets = app.get("targets")
            require(isinstance(targets, list) and targets, "explicit targets required")
            for target in targets:
                require(isinstance(target, dict) and {"version", "versionCodes", "isExperimental"} <= set(target) <= {"version", "versionCodes", "isExperimental", "minSdk", "description"}, "target fields mismatch")
                require(target.get("description") is None or isinstance(target["description"], str), "invalid target description")
                require(target.get("minSdk") is None or type(target["minSdk"]) is int and target["minSdk"] > 0, "invalid minimum SDK")
                v = text(target.get("version"), "explicit target version")
                require(target.get("isExperimental") is False, "experimental/unspecified target unsupported")
                codes = target.get("versionCodes")
                require(isinstance(codes, dict) and codes and set(codes) <= ABI, "explicit ABI versionCodes required")
                for abi, code in codes.items():
                    require(type(code) is int and code > 0, "positive version code required")
                    key = (name, package, v, abi, code)
                    require(key not in coverage, "duplicate compatibility target")
                    coverage.add(key)
        result.append({"name": name, "compatiblePackages": compatible})
    return sorted(result, key=lambda p: p["name"]), coverage


def input_sets(values):
    require(isinstance(values, list) and values, "input sets required")
    result = {}
    for value in values:
        exact(value, "id package_name version version_code abi density languages signer_sha256 files", "input set")
        ident = text(value["id"], "input id")
        require(NAME.fullmatch(ident) and ident not in result, "duplicate/invalid input id")
        for key in ("package_name", "version", "density"):
            text(value[key], key)
        require(value["abi"] in ABI and type(value["version_code"]) is int and value["version_code"] > 0, "invalid input target")
        require(isinstance(value["languages"], list) and value["languages"] and all(isinstance(v, str) and NAME.fullmatch(v) for v in value["languages"]), "explicit languages required (use none if inapplicable)")
        require(len(set(value["languages"])) == len(value["languages"]), "duplicate languages")
        sha(value["signer_sha256"])
        files = value["files"]
        require(isinstance(files, list) and files, "input file hashes required")
        ids, hashes, bases = set(), set(), 0
        for item in files:
            exact(item, "id role sha256", "input file")
            require(isinstance(item["id"], str) and NAME.fullmatch(item["id"]) and item["id"] not in ids, "duplicate/invalid input file id")
            ids.add(item["id"])
            sha(item["sha256"])
            require(item["sha256"] not in hashes, "duplicate input file hash")
            hashes.add(item["sha256"])
            require(item["role"] in {"base", "split"}, "invalid input role")
            bases += item["role"] == "base"
        require(bases == 1, "exactly one base input required")
        result[ident] = value
    return result


def report(value, kind, binding, checks, now, extra=""):
    exact(value, "kind binding observed_at tool status checks artifacts " + extra, kind)
    require(value["kind"] == kind and value["status"] == "passed", "report not passed or wrong kind")
    require(value["binding"] == binding, "report binding mismatch")
    when = fresh(value["observed_at"], now)
    exact(value["tool"], "name version sha256", "report tool")
    text(value["tool"]["name"], "tool name")
    text(value["tool"]["version"], "tool version")
    sha(value["tool"]["sha256"])
    require(value["checks"] == {key: "passed" for key in checks.split()}, "missing/failed report checks")
    require(isinstance(value["artifacts"], list) and value["artifacts"], "reviewable evidence artifact hashes required")
    seen = set()
    for artifact in value["artifacts"]:
        exact(artifact, "kind sha256", "evidence artifact")
        require(artifact["kind"] in {"test-report", "loader-report", "dex-report", "runtime-report", "visual-review"}, "private/raw evidence is not a public asset")
        sha(artifact["sha256"])
        require(artifact["sha256"] not in seen, "duplicate evidence artifact")
        seen.add(artifact["sha256"])
    expected_kinds = {"bundle-inspection": {"loader-report"}, "structural": {"test-report", "dex-report"},
                      "runtime": {"runtime-report", "visual-review"}}[kind]
    require(expected_kinds <= {a["kind"] for a in value["artifacts"]}, "missing kind-specific evidence artifact hashes")
    return when


def validate_release(source_root, bundle_path, catalog_path, request_path, evidence_path, approval_path, *, now=None, committed=False):
    now = now or dt.datetime.now(UTC)
    request, request_bytes = read_json(request_path)
    exact(request, "schema owner repository version created_at description bundle_sha256 catalog_sha256 source_revision source_tree_sha256 manager_revision patcher_version input_sets patches", "request")
    require(type(request["schema"]) is int and request["schema"] == 1, "unsupported request schema")
    manifest = make_manifest(request)
    require(local_time(request["created_at"]) <= now, "future release creation date")
    revision(request["source_revision"])
    revision(request["manager_revision"])
    require(VERSION.fullmatch(text(request["patcher_version"], "patcher version")), "invalid patcher version")
    for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256"):
        sha(request[key], key)
    source_hash, paths = source_tree(Path(source_root))
    require(source_hash == request["source_tree_sha256"], "source tree digest mismatch")
    if committed:
        clean_revision(source_root, request["source_revision"], paths)
    bundle = read_bytes(bundle_path, MAX_BUNDLE)
    require(Path(bundle_path).suffix == ".mpp", "MPP file required")
    require(digest(bundle) == request["bundle_sha256"], "bundle digest mismatch")
    metadata = bundle_metadata(bundle)
    require(metadata.get("version") == request["version"], "bundle Version mismatch")
    require(metadata.get("patcher-version") == request["patcher_version"], "bundle Patcher-Version mismatch")
    require(metadata.get("name") == "FISHYau android patches" and metadata.get("author") == "FISHYau", "bundle About identity mismatch")
    catalog, catalog_bytes = read_json(catalog_path)
    require(digest(catalog_bytes) == request["catalog_sha256"], "catalog digest mismatch")
    patches, needed = catalog_patches(catalog, request["version"])
    names = {p["name"] for p in patches}
    require(isinstance(request["patches"], list), "patch provenance list required")
    provenance = set()
    for patch in request["patches"]:
        exact(patch, "name source_files", "patch provenance")
        require(patch["name"] in names and patch["name"] not in provenance, "extra/duplicate patch provenance")
        provenance.add(patch["name"])
        require(isinstance(patch["source_files"], list) and patch["source_files"], "patch source provenance required")
        sources = set()
        for item in patch["source_files"]:
            exact(item, "path sha256", "source provenance")
            path = portable_path(item["path"])
            sha(item["sha256"])
            require(path not in sources and paths.get(path) == item["sha256"], "source provenance mismatch")
            sources.add(path)
    require(provenance == names, "missing patch source provenance")
    inputs = input_sets(request["input_sets"])
    evidence, evidence_bytes = read_json(evidence_path)
    exact(evidence, "schema inspection patch_evidence", "evidence")
    require(type(evidence["schema"]) is int and evidence["schema"] == 1, "unsupported evidence schema")
    binding = {key: request[key] for key in ("bundle_sha256", "catalog_sha256", "source_revision", "source_tree_sha256", "manager_revision", "patcher_version")}
    binding["request_sha256"] = digest(request_bytes)
    inspection = evidence["inspection"]
    times = [report(inspection, "bundle-inspection", binding, "android_bundle_load actual_definitions metadata", now, "patches dependencies about signing")]
    dependencies = inspection["dependencies"]
    require(isinstance(dependencies, dict) and set(dependencies) == names, "explicit loader dependencies required for every bundled patch")
    require(all(isinstance(value, list) and not value for value in dependencies.values()), "loader dependency selection verification unsupported")
    require(inspection["signing"] == "unsigned", "signed bundles require actual signature verification; unsupported")
    require(inspection["about"] == {"name": metadata["name"], "author": metadata["author"]}, "inspection About mismatch")
    require(canonical(inspection["patches"]) == canonical(patches), "actual loaded catalog/compatibility mismatch")
    cases = evidence["patch_evidence"]
    require(isinstance(cases, list) and cases, "per-patch evidence required")
    covered, used_inputs, seen_cases = set(), set(), set()
    compatibility = {p["name"]: p["compatiblePackages"] for p in patches}
    for case in cases:
        exact(case, "patch input_set_id selection structural runtime", "patch evidence")
        require(case["patch"] in names and case["input_set_id"] in inputs, "unknown patch/input evidence")
        inp = inputs[case["input_set_id"]]
        selection = case["selection"]
        require(isinstance(selection, list) and selection and all(isinstance(n, str) for n in selection), "selection required")
        require(selection == sorted(set(selection)) and set(selection) <= names and case["patch"] in selection, "unknown/duplicate/unsorted patch selection")
        key = (case["patch"], inp["package_name"], inp["version"], inp["abi"], inp["version_code"])
        require(key in needed, "evidence compatibility does not match catalog")
        for selected in selection:
            require((selected, *key[1:]) in needed, "selected patch incompatible with input")
            app = next(a for a in compatibility[selected] if a["packageName"] == inp["package_name"])
            require(app.get("signatures") is None or inp["signer_sha256"] in app["signatures"], "input signer incompatible with catalog")
        identity = (case["patch"], case["input_set_id"], tuple(selection))
        require(identity not in seen_cases, "duplicate patch evidence case")
        seen_cases.add(identity)
        used_inputs.add(case["input_set_id"])
        covered.add(key)
        per_case = dict(binding, patch=case["patch"], input_set_sha256=digest(canonical(inp)), selection=selection)
        structural = case["structural"]
        require(isinstance(structural, dict) and isinstance(structural.get("binding"), dict), "structural binding required")
        patched_hash = sha(structural["binding"].get("patched_application_sha256"), "patched application digest")
        require(patched_hash not in {f["sha256"] for f in inp["files"]}, "runtime must target patched output, not original input")
        per_case["patched_application_sha256"] = patched_hash
        times.append(report(structural, "structural", per_case, "uncached_tests patcher_round_trip dex_control_flow negative_fixtures", now))
        times.append(report(case["runtime"], "runtime", per_case, "patched_feature_interaction art_verification manager_import visual_inspection", now))
    require(covered == needed and used_inputs == set(inputs), "missing compatibility coverage or unused inputs")
    approval, approval_bytes = read_json(approval_path)
    exact(approval, "schema status reviewer reviewed_at request_sha256 evidence_sha256 approved_patches", "approval")
    require(type(approval["schema"]) is int and approval["schema"] == 1 and approval["status"] == "approved", "protected reviewer approval required")
    text(approval["reviewer"], "reviewer")
    require(approval["request_sha256"] == digest(request_bytes) and approval["evidence_sha256"] == digest(evidence_bytes), "approval digest mismatch")
    require(approval["approved_patches"] == sorted(names), "all and only bundled patches must be approved")
    require(fresh(approval["reviewed_at"], now) >= max(times), "approval predates evidence")
    return {"request": request, "manifest": manifest, "bundle": bundle,
            "catalog": {"version": request["version"], "patches": patches}, "catalog_bytes": catalog_bytes,
            "summary": {"schema": 1, "status": "prepared-not-published", "version": request["version"],
                        "binding": binding, "evidence_sha256": digest(evidence_bytes), "approval_sha256": digest(approval_bytes),
                        "approved_patches": sorted(names), "case_count": len(cases),
                        "trust": "Hash binding/completeness only; protected reviewer must authenticate evidence and approval. No cryptographic proof or publication."}}


def new_output(path, source_root):
    path = Path(path).absolute()
    require(not path.exists() and not linked(path), "output must be a new nonexistent directory")
    require(path.parent.is_dir(), "output parent must already exist")
    resolved = path.resolve()
    for root in (Path(source_root).resolve(), REPO_ROOT):
        require(not resolved.is_relative_to(root) and not root.is_relative_to(resolved), "output must be external to source/repository")
    require(all(not linked(p) for p in (path.parent, *path.parent.parents)), "output parents must not be symlinks/junctions")
    path.mkdir()
    return path


def prepare(output, source_root, **paths):
    result = validate_release(source_root, committed=True, **paths)
    # Recheck source immediately before output; no rebuild or post-check artifact read.
    require(source_tree(Path(source_root))[0] == result["request"]["source_tree_sha256"], "source changed during validation")
    clean_revision(source_root, result["request"]["source_revision"], source_tree(Path(source_root))[1])
    files = {f"patches-{result['request']['version']}.mpp": result["bundle"],
             "patches-list.json": result["catalog_bytes"],
             "patches-bundle.candidate.json": canonical(result["manifest"]),
             "verification-summary.json": canonical(result["summary"])}
    files["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items())).encode("ascii")
    directory = new_output(output, source_root)
    for name, data in files.items():
        with (directory / name).open("xb") as handle:
            handle.write(data)
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("contract", help="print release-v1 schema/policy and trust boundaries")
    normalize = commands.add_parser("normalize-source")
    normalize.add_argument("url")
    tree = commands.add_parser("tree-digest")
    tree.add_argument("source_root", type=Path)
    manifest = commands.add_parser("validate-manifest")
    manifest.add_argument("manifest", type=Path)
    manifest.add_argument("--owner")
    manifest.add_argument("--repository")
    manifest.add_argument("--version")
    for name in ("validate", "prepare"):
        command = commands.add_parser(name)
        command.add_argument("--source-root", type=Path, required=True)
        for key in ("bundle", "catalog", "request", "evidence", "approval"):
            command.add_argument("--" + key, dest=key + "_path", type=Path, required=True)
        if name == "prepare":
            command.add_argument("--output", type=Path, required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    try:
        if command == "contract":
            print(CONTRACT)
        elif command == "normalize-source":
            print(normalize_source(args["url"]))
        elif command == "tree-digest":
            print(source_tree(args["source_root"])[0])
        elif command == "validate-manifest":
            validate_manifest(read_json(args.pop("manifest"))[0], **args)
            print("Manifest schema valid; does not establish download, bundle loading or trust.")
        elif command == "validate":
            result = validate_release(**args)
            print(f"Release binding/completeness valid for {len(result['catalog']['patches'])} patch(es); not authenticated proof or publication authorization.")
        else:
            print(f"Prepared only (publication disabled): {prepare(**args)}")
    except (ReleaseError, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile) as exc:
        print(f"Release blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
