"""Bounded reviewed Termius selection policy; local paths are never trust inputs.

No extraction, signature implementation, execution, or supplied-report mode here.
The parent must freshly run verification_argv and bind both child intervals/closure.
Endpoint hashes detect persistent changes, NOT restored-byte same-user races.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys

REPO = Path(__file__).resolve().parents[2]
POLICY = "termius-8.0.1-selected-identity-v1"
PACKAGE, CODE, VERSION = "com.server.auditor.ssh.client", "1008", "8.0.1"
SIGNER = "73071d4501b19a76b97367b5161f703f1e1d53d76a257a4b3d766d90833978f0"
ARCHIVE = {"size": 46507753, "sha256": "01606bb969574c5140229d0e8b6c1e32cf759543f676e1488d2aa917dea252dc"}
# Independent reviewed policy, not populated from a descriptor, APK or report.
MEMBERS = {
    "base.apk": (56857170, "8d4150b0b97ea4f13820a6b5a36c28b9a2cea7fbe1a542428aaa2cbcdd30a2f7", None),
    "split_config.x86_64.apk": (13636978, "3866f68a693e989779e9a99a46ae138d4611ad5d12325a1c69d53d2b94c26aa8", "config.x86_64"),
    "split_config.mdpi.apk": (107680, "a1edd0ce716c1cdc428b6c22ed3ead697fdf11707c655c2cd9f4b50827f3ada8", "config.mdpi"),
}
PAYLOADS = {
    "java": "f8dc082a7dedbfd2924c3562405a5a1fd12efd2641808c92e2de819c76a58b7e",
    "aapt2": "babf3122e515ddb954c5ac4669e085ce990536c035e3072de30127bddd6e3608",
    "signer_jar": "3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec",
    "provenance": "2ce653b53dfa263a1b45ecf996ab8db03a5bddb5a0147da3050a15db4f88673e",
    "certificate_dialog": "eccf7896ce4678dc4ead1415104d7b70cd4a728b332b87f33e1166f806e19906",
}
SELECTION = {"abi": "x86_64", "density": "mdpi", "languages": ["en"]}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def canonical(path, *, missing=False):
    """Inspect original ancestry BEFORE resolution, including every reparse tag.

    Compare strings, not WindowsPath equality (which ignores case). Directory
    enumeration also rejects short-name and case aliases if resolve preserves them.
    Only a final nonexistent output component is allowed with missing=True.
    """
    require(isinstance(path, (str, Path)), "path string required")
    text = str(path)
    require(text and not any(c in text for c in ("\x00", "*", "?")), "invalid explicit path")
    require(".." not in text.replace("\\", "/").split("/") and "." not in text.replace("\\", "/").split("/"), "dot path aliases forbidden")
    path = Path(text)
    require(path.is_absolute(), "absolute path required")
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            require(missing and item == path, "missing ancestor/input")
            continue
        require(not stat.S_ISLNK(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400), "reparse/link ancestry forbidden")
        if item != Path(item.anchor):
            require(item.name in os.listdir(item.parent), "case/short-name alias forbidden")
    resolved = path.resolve(strict=not missing)
    require(str(resolved) == str(path), "noncanonical path spelling forbidden")
    return path


def record(path):
    path = canonical(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular unaliased input required")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat()
    fields = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    require(fields(before) == fields(after), "input changed while hashing")
    return {"size": after.st_size, "sha256": digest.hexdigest()}


def canonical_driver():
    # Canonical trusted code has definitions only at import; no historical recipe.
    name = "selected_identity_canonical_driver"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, REPO / ".claude/skills/run-android-morphe/driver.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module  # dataclasses resolves its defining module
        spec.loader.exec_module(module)
    return sys.modules[name]


def load_selection(descriptor, java, parse_json):
    descriptor = canonical(descriptor)
    require(not descriptor.is_relative_to(REPO), "selection descriptor must be external")
    require(descriptor.stat().st_size <= 65536, "selection descriptor too large")
    descriptor_record = record(descriptor)
    raw = descriptor.read_bytes()
    require(record(descriptor) == descriptor_record and hashlib.sha256(raw).hexdigest() == descriptor_record["sha256"], "descriptor changed while parsing")
    value = parse_json(raw)
    require(type(value) is dict and set(value) == {"schema", "archive", "members", "aapt2", "signer_jar", "provenance", "certificate_dialog"}
            and value["schema"] == "termius-selected-inputs-v1", "strict selection descriptor required")
    require(type(value["members"]) is list and len(value["members"]) == len(MEMBERS), "exact selected members required")
    members = {}
    for row, name in zip(value["members"], MEMBERS):
        require(type(row) is dict and set(row) == {"name", "apk"} and row["name"] == name and type(row["apk"]) is str,
                "ordered exact archive-member/APK mapping required")
        members[name] = canonical(row["apk"])
        require(members[name].suffix == ".apk", "APK suffix required")
    paths = {"descriptor": descriptor, "java": canonical(java), **{key: canonical(value[key]) for key in
             ("archive", "aapt2", "signer_jar", "provenance", "certificate_dialog")}}
    paths.update({"member:" + name: path for name, path in members.items()})
    identities = set()
    for path in paths.values():
        require(not path.is_relative_to(REPO), "local selection/tool paths must be external")
        record(path)
        info = path.stat()
        ident = info.st_dev, info.st_ino
        require(ident not in identities, "cross-input file alias")
        identities.add(ident)
    require(paths["aapt2"].name == "aapt2.exe" and paths["signer_jar"].name == "apksigner.jar", "explicit reviewed tool payload names required")
    return {"paths": paths, "members": members, "descriptor_record": descriptor_record}


def snapshot_selection(selection):
    paths, members = selection["paths"], selection["members"]
    files = {str(path): record(path) for path in paths.values()}
    require(files[str(paths["descriptor"])] == selection["descriptor_record"], "selection descriptor changed")
    require(files[str(paths["archive"])] == ARCHIVE, "archive policy mismatch")
    for key, digest in PAYLOADS.items():
        require(files[str(paths[key])]["sha256"] == digest, "reviewed payload/provenance policy mismatch: " + key)
    driver = canonical_driver()
    budget = driver.Budget(max_bytes=sum(row[0] for row in MEMBERS.values()),
                           max_file_bytes=128 * 1024**2, max_archive_bytes=ARCHIVE["size"])
    archive = driver._validated_zip(paths["archive"], budget)
    measured = {}
    try:
        for name, (size, digest, _) in MEMBERS.items():
            info = archive.getinfo(name)
            require(info.file_size == size, "selected member declared size mismatch")
            actual_size, actual_hash, _ = driver._read_member(archive, info, budget)
            row = {"size": actual_size, "sha256": actual_hash}
            require(row == {"size": size, "sha256": digest} == files[str(members[name])], "archive/member/APK correspondence mismatch")
            measured[name] = row
    finally:
        driver._close_zip(archive)
    require(files == {str(path): record(path) for path in paths.values()}, "selection changed during snapshot")
    return {"policy": POLICY, "files": files, "archive_members": measured}


def verification_argv(selection, report):
    report = canonical(report, missing=True)
    # Pure deterministic command construction is also used for recheck; the
    # executing parent separately reserves a NEW report, never a supplied one.
    require(report.parent.is_dir(), "verification report parent required")
    paths = selection["paths"]
    return list(map(str, [sys.executable, "-I", "-B", REPO / ".claude/skills/run-android-morphe/driver.py", "verify-apks",
        *selection["members"].values(), "--aapt2", paths["aapt2"], "--java", paths["java"], "--signer-jar", paths["signer_jar"],
        "--expect-package", PACKAGE, "--expect-version-code", CODE, "--expect-version-name", VERSION, "--expect-signer", SIGNER,
        "--abi", "x86_64", "--density", "mdpi", "--language", "en", "--out", report]))


def validate_verification(value, selection):
    require(type(value.get("schema")) is int and value["schema"] == 2 and value.get("status") == "selected_split_set_verified", "fresh canonical verification required")
    require(value["selection"] == SELECTION and value["expected"] == dict(package=PACKAGE, version_code=CODE, version_name=VERSION,
            split=None, signers_sha256=[SIGNER]), "verification selection/independent pins mismatch")
    rows = value["apks"]
    require(type(rows) is list and len(rows) == len(MEMBERS), "exact canonical APK rows required")
    for row, (name, (_, digest, split)) in zip(rows, MEMBERS.items()):
        require(row["path"] == str(selection["members"][name]) and row["sha256"] == digest and row["signers_sha256"] == [SIGNER]
                and row["manifest"] == dict(package=PACKAGE, version_code=CODE, version_name=VERSION, split=split), "verified APK identity/mapping mismatch")
        # Do not duplicate manifest inheritance or topology rules.
        declarations = canonical_driver().SPLITSET.manifest_fields(row["raw_manifest"])
        require(declarations == row["manifest_declarations"], "raw/declaration mismatch")
        require(declarations["package"] == PACKAGE and declarations["version_code"] == CODE and declarations["split"] == split
                and (declarations["version_name"] == VERSION or (split is not None and declarations["version_name"] is None)), "raw identity/inheritance mismatch")
    topology = canonical_driver().validate_split_set(rows, abi="x86_64", density="mdpi")
    require(value["topology"] == topology and value["split_set"] == topology["mode"] == "base_config_set", "canonical topology mismatch")
    require(topology["base"] == str(selection["members"]["base.apk"]) and topology["base_sha256"] == MEMBERS["base.apk"][1]
            and topology["base_dex"] == ["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex", "classes5.dex"]
            and topology["required_split_types"] == topology["provided_split_types"] == ["base__abi", "base__density"]
            and topology["coverage"] == "declared_types_only_not_resource_or_language_completeness", "reviewed bounded topology differs")
    return value
