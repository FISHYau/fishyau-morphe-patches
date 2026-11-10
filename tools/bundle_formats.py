"""Bounded public MPP/catalog and Morphe Manager source-format helpers.

These checks recognize the current unsigned Android collection's *format*.
They do not execute DEX, compare actual loaded patch definitions to a catalog,
verify signatures, or establish app/runtime behavior. Use the local checkers for
actual loading and patch tests; do not mistake metadata for those checks.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import struct
from urllib.parse import urlsplit
import zipfile
import zlib

UTC = dt.timezone.utc
MAX_JSON = 8 * 1024 * 1024
MAX_BUNDLE = 128 * 1024 * 1024
MAX_MEMBER = 64 * 1024 * 1024
NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*\Z")
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?\Z")
DATE = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?\Z", re.ASCII)
ABI = {"ARM64_V8A", "ARMEABI_V7A", "X86_64", "X86"}
COLLECTION_PATCHES = {"Server Auditor Offline Automation": True,
                      "Server Auditor Premium": True, "Premium unlock": True}


def require(condition, message):
    if not condition:
        raise ValueError(message)


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
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), f"{label}: lowercase SHA256 required")
    return value


def linked(path):
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def read_bytes(path, limit):
    path = Path(path)
    require(path.is_file() and not linked(path), "regular nonsymlink file required")
    require(path.stat().st_size <= limit, "file too large")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "file grew beyond limit")
    return data


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def read_json(path):
    data = read_bytes(path, MAX_JSON)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON number")))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise ValueError("invalid JSON") from None
    return value, data


def local_time(value):
    require(isinstance(value, str) and DATE.fullmatch(value), "UTC LocalDateTime required, without Z or offset")
    try:
        fields = [int(value[a:b]) for a, b in ((0, 4), (5, 7), (8, 10), (11, 13), (14, 16), (17, 19))]
        micros = int((value[20:] + "000000")[:6]) if len(value) > 19 else 0
        return dt.datetime(*fields, microsecond=micros, tzinfo=UTC)
    except ValueError:
        raise ValueError("invalid calendar date") from None


def https_url(value, label):
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


def make_manifest(values):
    require(isinstance(values, dict) and {"owner", "repository", "version", "created_at", "description"} <= set(values), "manifest inputs required")
    result = {key: values[key] for key in ("version", "created_at", "description")}
    result["download_url"] = asset_url(values["owner"], values["repository"], values["version"])
    result["page_url"] = f"https://github.com/{values['owner']}/{values['repository']}/releases/tag/v{values['version']}"
    return validate_manifest(result, values["owner"], values["repository"], values["version"])


def portable_path(value):
    text(value, "path")
    parts = PurePosixPath(value).parts
    require(parts and not value.startswith("/") and "\\" not in value and ":" not in value, "relative POSIX path required")
    require("/".join(parts) == value and all(p not in {".", ".."} and not p.endswith((".", " ")) for p in parts), "noncanonical path")
    require(all(not re.match(r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", p) for p in parts), "reserved path")
    return value


def bundle_metadata(data):
    require(isinstance(data, bytes) and len(data) <= MAX_BUNDLE, "bundle too large or not bytes")
    require(len(data) >= 22 and data.startswith(b"PK\x03\x04") and data[-22:-18] == b"PK\x05\x06",
            "plain unsigned ZIP required; comments/envelopes/trailing signatures unsupported")
    require(data[-42:-38] != b"PK\x06\x07", "ZIP64 locator unsupported")
    end = struct.unpack("<4s4H2LH", data[-22:])
    require(end[1:3] == (0, 0) and end[3] == end[4] and end[3] < 65535 and end[7] == 0
            and end[5] + end[6] == len(data) - 22, "noncanonical/signed ZIP envelope unsupported")
    # ZipFile eagerly allocates every central-directory entry. Bound and
    # reconcile the real header count before giving untrusted bytes to it;
    # forged low EOCD counts do not limit Python's own inventory allocation.
    cursor, central_end, members = end[6], end[6] + end[5], 0
    while cursor < central_end:
        require(members < 4096 and cursor + 46 <= central_end
                and data[cursor:cursor + 4] == b"PK\x01\x02", "invalid/too many central ZIP entries")
        name_size, extra_size, comment_size = struct.unpack_from("<HHH", data, cursor + 28)
        cursor += 46 + name_size + extra_size + comment_size
        require(cursor <= central_end, "truncated central ZIP entry")
        members += 1
    require(members == end[4] and members > 0, "ZIP central count mismatch")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as bundle:
            names, total = set(), 0
            require(len(bundle.infolist()) == end[4] and len(bundle.infolist()) <= 4096, "invalid/too many bundle members")
            require(bundle.infolist() and min(info.header_offset for info in bundle.infolist()) == 0, "prepended ZIP envelope unsupported")
            require(data[end[6] - 16:end[6]] != b"APK Sig Block 42", "signed ZIP block unsupported")
            for info in bundle.infolist():
                name = info.filename.rstrip("/")
                portable_path(name)
                require(info.orig_filename == info.filename and info.filename in {name, name + "/"}
                        and name.casefold() not in names, "duplicate/ambiguous bundle member")
                names.add(name.casefold())
                mode = info.external_attr >> 16
                require(stat.S_IFMT(mode) in {0, stat.S_IFREG, stat.S_IFDIR} and not info.flag_bits & 1, "special/encrypted bundle member")
                require(info.extract_version < 45, "ZIP64 bundle members unsupported")
                extra = info.extra
                while extra:
                    require(len(extra) >= 4, "invalid ZIP extra field")
                    kind, size = struct.unpack("<HH", extra[:4])
                    require(kind != 1 and len(extra) >= 4 + size, "ZIP64/invalid ZIP extra field unsupported")
                    extra = extra[4 + size:]
                require(info.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}, "unsupported ZIP compression")
                require(not re.search(r"(?i)\.(apk|apkm|apks|aab|png|jpe?g|webp|heic|gif)$", name), "app binaries/raw images are not bundle assets")
                require(info.file_size <= MAX_MEMBER, "bundle member too large")
                total += info.file_size
                require(total <= MAX_BUNDLE, "expanded bundle too large")
                require(not re.search(r"(?i)(?:\.(?:sf|rsa|dsa|ec|sig)|(?:^|/)signature(?:\.[^/]*)?)$", name),
                        "signed bundle unsupported: real signature verification is not implemented")
                # Reading also checks CRCs, local/central names and overlapping entries.
                with bundle.open(info) as stream:
                    while stream.read(1024 * 1024):
                        pass
            require("classes.dex" in bundle.namelist(), "Android classes.dex required; renamed JAR is insufficient")
            with bundle.open("classes.dex") as stream:
                require(re.fullmatch(rb"dex\n0(?:3[5-9]|4[01])\x00", stream.read(8)), "invalid DEX magic")
            require(bundle.getinfo("META-INF/MANIFEST.MF").file_size <= MAX_JSON, "bundle manifest too large")
            manifest = bundle.read("META-INF/MANIFEST.MF").decode("utf-8")
    except (zipfile.BadZipFile, KeyError, UnicodeError, RuntimeError, OSError, NotImplementedError, struct.error, zlib.error):
        raise ValueError("invalid Android bundle archive") from None
    logical = []
    for line in manifest.replace("\r\n", "\n").split("\n"):
        if not line:
            break  # Ignore named sections: they cannot override main attributes.
        if line.startswith(" "):
            require(logical, "orphan manifest continuation")
            logical[-1] += line[1:]
        else:
            logical.append(line)
    result = {}
    for line in logical:
        require(": " in line, "malformed manifest attribute")
        key, value = line.split(": ", 1)
        require(key and key.lower() not in result, "duplicate/empty manifest attribute")
        result[key.lower()] = value
    require("signature-version" not in result, "signed bundle unsupported")
    return result


def collection_inventory(catalog, version):
    require(isinstance(catalog, dict) and catalog.get("version") == version and set(catalog) <= {"NOTE", "version", "patches"}, "collection catalog fields/version mismatch")
    if "NOTE" in catalog:
        text(catalog["NOTE"], "catalog note")
    patches = catalog.get("patches")
    require(isinstance(patches, list) and len(patches) == 3, "exact three collection definitions required")
    names = {}
    for patch in patches:
        exact(patch, "name description default category compatiblePackages options", "collection patch")
        name = text(patch["name"], "patch name")
        require(name in COLLECTION_PATCHES and name not in names, "unknown/duplicate collection patch")
        require(type(patch["default"]) is bool and patch["options"] == [], "collection default/options mismatch")
        names[name] = patch["default"]
        for key in ("description", "category"):
            require(patch[key] is None or isinstance(patch[key], str), "invalid collection text")
        apps = patch["compatiblePackages"]
        require(isinstance(apps, list) and len(apps) == 1, "one compatible package required")
        app = apps[0]
        require(isinstance(app, dict) and {"packageName", "targets"} <= set(app) <= {"packageName", "name", "description", "apkFileType", "appIconColor", "signatures", "formFactor", "targets"}, "compatibility fields mismatch")
        for key in ("name", "description", "apkFileType", "appIconColor", "formFactor"):
            require(app.get(key) is None or isinstance(app[key], str), "invalid compatibility text")
        require(app.get("apkFileType") == "APKM", "APKM compatibility required")
        if app.get("signatures") is not None:
            require(isinstance(app["signatures"], list) and app["signatures"], "invalid APK signatures")
            for signature in app["signatures"]:
                sha(signature)
        if name == "Premium unlock":
            # Empty means package-only compatibility, NOT proof of all versions.
            require(app["packageName"] == "com.plexapp.android" and app["targets"] == [], "intentional Plex version-unpinned targets=[] required")
            continue
        require(app["packageName"] == "com.server.auditor.ssh.client", "Termius package mismatch")
        targets = app["targets"]
        require(isinstance(targets, list) and len(targets) == 1, "one finite Termius target required")
        target = targets[0]
        require(isinstance(target, dict) and {"version", "versionCodes", "isExperimental"} <= set(target) <= {"version", "versionCodes", "isExperimental", "minSdk", "description"}, "target fields mismatch")
        require(target.get("description") is None or isinstance(target["description"], str), "invalid target description")
        require(target.get("minSdk") is None or type(target["minSdk"]) is int and target["minSdk"] > 0, "invalid minimum SDK")
        require(target["version"] == "8.0.1" and target["isExperimental"] is False, "finite nonexperimental Termius 8.0.1 required")
        codes = target["versionCodes"]
        require(isinstance(codes, dict) and codes and set(codes) <= ABI and all(type(c) is int and c == 1008 for c in codes.values()), "Termius ABI/code1008 required")
    require(names == COLLECTION_PATCHES, "exact three collection names/defaults required")
    return sorted(patches, key=lambda patch: patch["name"])
