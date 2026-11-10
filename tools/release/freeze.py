#!/usr/bin/env python3
"""Freeze checked local collection build inputs BEFORE producing observations.

Consumes a successful canonical driver's OUT/build.json, retained source.tar,
final-mpp.sha256 and collected artifacts, plus the exact pristine source root.
Writes four PRIVATE input files to a NEW external directory. No Git, builds,
network, signing, inspection, runtime observations, candidate or approval. XML
and hashes establish local binding/completeness, not authenticated execution.
Failed builds (including unresolved Morphe plugins) cannot be frozen. A copied
work/build directory is not a pristine source. Do not publish this inventory:
it retains exact local paths and the reported build environment identity.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import io
import os
from pathlib import Path
import re
import stat
import sys
import tarfile
import xml.etree.ElementTree as ET

_spec = importlib.util.spec_from_file_location("freeze_staging", Path(__file__).with_name("staging.py"))
s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s)
r = s.r

MAX_SOURCE = 256 * 1024 * 1024
MAX_ENTRIES = 20000
EXCLUDED = {".git", ".gradle", "build", "local.properties"}
TEST_PREFIX = "patches/src/test/kotlin/"
TEST_CLASSES = (
    "io.github.fishyau.androidpatches.collection.CollectionInventoryTest",
    "io.github.fishyau.androidpatches.termius.OfflineAutomationValidationTest",
    "io.github.fishyau.androidpatches.termius.PremiumPatchValidationTest",
    "io.github.fishyau.androidpatches.termius.PatchInventoryTest",
    "io.github.fishyau.androidpatches.plex.HermesBytecodeTest",
    "io.github.fishyau.androidpatches.plex.PremiumUnlockPatchTest",
)
# Reviewed JUnit4 display names, not numeric indices or arbitrary suffixes.
OFFLINE_PARAMETERS = ("snippet widget", "SSH Automation", "terminal Automation")
# Literal reviewed floor: 95 methods / 121 JUnit cases across the six classes.
# Never derive this floor from the supplied source (or its mutable XML/counts).
# Source discovery below remains authoritative for *additional* required cases.
REVIEWED_METHODS = {
    TEST_CLASSES[0]: frozenset("""
        exactThreeRealDefinitionsDefaultsTypesAndDependencies
        actualLoaderFindsExactlyThreeInProductionOutputIncludingHelpers
        missingExtraUnnamedAndEveryDuplicateAreRejected
        everyWrongDefaultDependencyAndOptionIsRejected
        rawDecodedAndBytecodeTypesCannotBeSubstituted
        nullEmptyMultipleWrongPackageAndWrongContainerAreRejectedForEveryPatch
        finiteTermiusAndIntentionallyUnpinnedPlexPoliciesCannotBeExchanged
        actualMorpheDefaultsAndEveryFormFactorMutationAreChecked
        everyUnpinnedPlexSentinelFieldIsConstrained
        everyTermiusAbiCodeIsRequiredAndProjectionRetainsActualMap
        catalogAndInspectionProjectionPreserveEmptyPlexTargetsAndAllThreeEntries
    """.split()),
    TEST_CLASSES[1]: frozenset("""
        originalLayoutIsAccepted
        missingAndAmbiguousTargetsAreRejected
        changedRegisterCountsAreRejected
        changedAccessFlagsAreRejected
        exceptionRegionsAreRejected
        everyOpcodeIsChecked
        everyRegisterOperandIsChecked
        everyReferenceIsChecked
        everyLiteralIsChecked
        everyBranchTargetAndPolarityIsChecked
        missingAndExtraInstructionsAreRejected
        independentlyPatchedTargetIsRejected
        editSitesAndPermissionOrConnectionSemanticsAreExplicit
    """.split()),
    TEST_CLASSES[2]: frozenset("""
        original801LayoutIsAccepted
        highestEncodableParameterRegisterIsAccepted
        insufficientLocalsAreRejected
        unencodableParameterRegisterIsRejected
        staticMapperIsRejected
        missingAndAmbiguousTargetsAreRejected
        alreadyPatchedMapperIsRejected
        unexpectedTryRegionsAreRejected
        constructorWithAdditionalNullCheckIsRejected
        changedConstructorFieldsAreRejected
        changedBaseConstructorIsRejected
        alreadyPatchedExpiryIsRejected
        incorrectExpiryFieldIsRejected
        expiryWithoutScratchLocalIsRejected
        originalStorageProGetterIsAccepted
        missingAndAmbiguousStorageTargetsAreRejected
        staticStorageGetterIsRejected
        changedStorageRegisterCountIsRejected
        storageExceptionHandlersAreRejected
        authenticationFieldIsRejected
        changedStorageFieldOwnerOrTypeIsRejected
        changedStorageMethodReferencesOrCastAreRejected
        changedStorageBranchPolarityOrDestinationIsRejected
        aliasedStorageRegisterOperandsAreRejected
        changedStorageConstantsOrReturnsAreRejected
        missingOrAdditionalStorageInstructionsAreRejected
        alreadyPatchedStorageGetterIsRejectedIndependentlyOfMapper
    """.split()),
    TEST_CLASSES[3]: frozenset("""
        exactInventoryDefaultsDependenciesAndOptions
        termiusSubsetCannotBlessWholeCollectionOrCatalog
        missingExtraUnnamedAndDuplicateEntriesAreRejected
        wrongDefaultIsRejected
        finiteApkmCompatibilityIsExact
        wildcardWrongVersionCodeAndApkOnlyAreRejected
        dependenciesAreRejectedRatherThanInferredFromCatalog
        nonemptyOptionsAreRejected
        narrowerProjectionContainsOnlyTermiusDefinitions
    """.split()),
    TEST_CLASSES[4]: frozenset("""
        readsVersionLengthAndCompactFunctions
        rejectsShortAndWrongMagic
        rejectsUnsupportedVersion
        rejectsInvalidFileLengths
        rejectsNegativeOrOversizedCounts
        rejectsSectionBounds
        readsAsciiUtf16OverflowAndDuplicateStrings
        rejectsStringIdsAndOverflowIndex
        rejectsStringStorageOverrun
        rejectsNegativeOverflowStringFields
        readsLargeFunctionHeader
        rejectsFunctionIdsAndBytecodeBounds
        rejectsBadLargeFunctionHeaderAndSize
        decodesAllOperandWidthsAndSignedAddresses
        stopsBeforeSwitchJumpTable
        rejectsUnknownOpcode
        rejectsTruncatedInstruction
        validatesAndRecomputesExactFooter
    """.split()),
    TEST_CLASSES[5]: frozenset("""
        metadataKeepsExactNameDefaultAndPackageScopedUnpin
        realContextExplicitlyDecodesSyntheticBinaryManifest
        actualProductionExecutionChangesOnlyThreeOpcodesAndFooter
        actualProductionExecutionIsIdempotent
        supportsEveryStrictFlipForm
        mixedAlreadyPatchedAndPendingChangesOnlyPending
        followsShortAndLongMovesAndStringLoads
        duplicateFunctionNamesPatchAllMatchingFunctions
        rejectsMissingOnWithoutWrites
        rejectsMissingRequiredFunctionWithoutPartialWrites
        rejectsNamedFunctionWithoutOnComparisonWithoutPartialWrites
        clearedConstantAndMoveRegistersDoNotMatch
        rejectsWrongMagicVersionAndMalformedInstructionWithoutWrites
        skipsMissingBinaryAndEmptyManifest
        cleansOnlyOptionalDecodedManifestConstraints
        preflightFailureLeavesDecodedManifestAndBundleUnmodified
        documentsPreservedNoOriginalFooterValidation
    """.split()),
}
# Build configuration must equal this checkout's reviewed files. No dependency
# substitution or caller-selected plugin/patcher override is accepted here.
BUILD_CONFIG = (
    "settings.gradle.kts", "build.gradle.kts", "patches/build.gradle.kts",
    "gradle/libs.versions.toml", "gradle.properties",
    "gradle/wrapper/gradle-wrapper.properties", "gradlew", "gradlew.bat",
)
PINS = {"version": "0.1.0", "morphe-patcher": "2.3.0", "morphe-plugin": "2.1.0",
        "smali": "4220ae75f7", "gson": "2.15.0", "junit": "4.13.2"}


def ancestry(path):
    """Check the un-resolved spelling: resolve alone conceals linked ancestors."""
    path = Path(path).absolute()
    r.require(all(not r.linked(p) for p in (path, *path.parents)), "linked input/output ancestry forbidden")
    return path


def disjoint(a, b):
    r.require(not a.is_relative_to(b) and not b.is_relative_to(a), "source/build/output roots must be disjoint")


def regular(path, limit):
    path = ancestry(path)
    r.require(path.stat().st_nlink == 1, "hard-linked input forbidden")
    return r.read_bytes(path, limit)


def walk_files(root):
    result = []
    def failed(exc):
        raise r.ReleaseError("cannot enumerate retained artifacts") from exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in dirs + files:
            path = Path(directory) / name
            ancestry(path)
            mode = path.stat().st_mode
            r.require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "special retained artifact")
        result.extend((Path(directory) / name).relative_to(root).as_posix() for name in files)
        r.require(len(result) <= MAX_ENTRIES, "too many retained artifacts")
    return sorted(result)


def pristine_tree(root):
    ancestry(root)
    tree, paths = r.source_tree(root)
    # GNU tar's driver exclusions apply to basenames anywhere. release.source_tree
    # excludes ONLY top-level .git. Refuse these differences, never silently omit.
    for directory, dirs, files in os.walk(root, followlinks=False):
        if Path(directory) == root and ".git" in dirs:
            dirs.remove(".git")
        for name in dirs + files:
            relative = (Path(directory) / name).relative_to(root).as_posix()
            r.require(name not in EXCLUDED or relative == ".git", "source is not pristine: driver-excluded public path")
            if name in files:
                r.require((Path(directory) / name).stat().st_nlink == 1, "hard-linked input forbidden")
    r.require(len(paths) <= MAX_ENTRIES, "too many source files")
    return tree, paths


def archive_name(data, member):
    # tarfile strips ALL trailing slashes on directory headers. Inspect the
    # original spelling too, otherwise dir// silently aliases dir/. GNU tar uses
    # one LongName header for this collection's long package paths; allow that
    # form, not arbitrary extended-header chains or PAX path overrides.
    offset = member.offset
    header = data[offset:offset + 512]
    if header[156:157] == tarfile.GNUTYPE_LONGNAME:
        size = tarfile.nti(header[124:136])
        r.require(0 < size <= r.MAX_JSON, "invalid GNU source path size")
        raw = data[offset + 512:offset + 512 + size]
        r.require(raw.endswith(b"\x00") and b"\x00" not in raw[:-1], "invalid GNU source path")
        raw = raw[:-1]
        following = offset + 512 + ((size + 511) // 512) * 512
        r.require(data[following + 156:following + 157] in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}, "source archive extended-header chain forbidden")
    else:
        r.require(header[156:157] in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE}, "source archive extended headers forbidden")
        raw = header[:100].split(b"\x00", 1)[0]
        if header[257:263] == b"ustar\x00":
            prefix = header[345:500].split(b"\x00", 1)[0]
            if prefix:
                raw = prefix + b"/" + raw
    name = raw.decode("utf-8")
    if member.isdir() and name.endswith("/"):
        name = name[:-1]  # Exactly ONE canonical directory terminator.
    r.require(name == member.name, "noncanonical source archive path alias")
    return name


def archive_headers(data):
    # Preflight raw headers before tarfile can recursively process extensions or
    # sparse maps. Only regular files, empty directories and a single GNU long
    # name immediately before either are part of this driver's tar contract.
    offset, count, pending = 0, 0, False
    while offset + 512 <= len(data):
        block = data[offset:offset + 512]
        if block == bytes(512):
            r.require(not pending and len(data) - offset >= 1024 and not data[offset:].strip(b"\x00"), "noncanonical/truncated source archive terminator")
            return
        count += 1
        r.require(count <= MAX_ENTRIES * 2, "too many source archive headers")
        info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        r.require(info.type in {tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE, tarfile.GNUTYPE_LONGNAME}, "source archive overrides/links/special headers forbidden")
        r.require(0 <= info.size <= r.MAX_BUNDLE and (not info.isdir() or info.size == 0), "invalid source archive header size")
        if info.type == tarfile.GNUTYPE_LONGNAME:
            r.require(not pending and 0 < info.size <= r.MAX_JSON, "source archive extended-header chain forbidden")
            pending = True
        else:
            pending = False
        offset += 512 + ((info.size + 511) // 512) * 512
        r.require(offset <= len(data), "truncated source archive payload")
    raise r.ReleaseError("missing source archive terminator")


def source_archive(data, expected):
    """Bounded read-only tar inspection. No extraction, imports or execution."""
    r.require(len(data) <= MAX_SOURCE, "source archive too large")
    entries, seen, total = {}, set(), 0
    try:
        archive_headers(data)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:") as archive:
            for count, member in enumerate(archive, 1):
                r.require(count <= MAX_ENTRIES, "too many source archive members")
                r.require(member.isdir() or member.isreg(), "source archive links/special members forbidden")
                r.require(not member.pax_headers and not member.sparse, "source archive overrides/sparse members forbidden")
                name = archive_name(data, member)
                if name == "." and member.isdir():
                    path = "."
                else:
                    path = name[2:] if name.startswith("./") else name
                    r.portable_path(path)
                    r.require(not any(p in EXCLUDED for p in path.split("/")), "excluded source archive member")
                r.require(path.casefold() not in seen, "duplicate/aliased source archive path")
                seen.add(path.casefold())
                r.require(0 <= member.size <= r.MAX_BUNDLE, "source archive member too large")
                total += member.size
                r.require(total <= MAX_SOURCE, "expanded source archive too large")
                if member.isreg():
                    stream = archive.extractfile(member)
                    payload = stream.read(r.MAX_BUNDLE + 1)
                    r.require(len(payload) == member.size, "truncated source archive member")
                    entries[path] = r.digest(payload)
        r.require(entries == expected, "retained source archive differs from pristine source tree")
    except (tarfile.TarError, EOFError) as exc:
        raise r.ReleaseError("invalid retained source archive") from exc
    return entries


def provenance(root, paths):
    """Original/migrated pairs come exclusively from reviewed migration records."""
    termius, _ = r.read_json(root / "docs/termius-migration.json")
    plex, _ = r.read_json(root / "docs/plex-migration.json")
    r.require(termius.get("schema") == 1 and termius.get("kind") == "termius-source-migration", "Termius migration record required")
    tfiles, seen = [], set()
    for entry in termius["entries"]:
        path = r.portable_path(entry["migrated"])
        r.require(path not in seen, "duplicate Termius migration entry")
        seen.add(path)
        if path.startswith(s.MIGRATED):
            tfiles.append(dict(path=path, original_sha256=entry["original_sha256"], migrated_sha256=entry["migrated_sha256"]))
    r.require(plex.get("schema") == 1 and plex.get("source_repository") == "https://github.com/UnkyBadTouch/plex-morphe-patches.git", "Plex migration record required")
    pfiles = [dict(path=e["migrated_path"], original_sha256=e["original_sha256"], migrated_sha256=e["migrated_sha256"]) for e in plex["files"]]
    pfiles += [dict(path=e["retained_path"], original_sha256=e["sha256"], migrated_sha256=e["sha256"]) for e in plex["licenses"]]
    value = {
        "termius": dict(status="accepted-existing-behavior", basis="user-confirmed-tested-working", adaptations=s.TERMIUS_ADAPTATIONS, files=sorted(tfiles, key=lambda e: e["path"])),
        "plex": dict(repository="https://github.com/UnkyBadTouch/plex-morphe-patches", revision=plex["source_revision"], basis="reviewed-source-migration-not-runtime-acceptance", files=sorted(pfiles, key=lambda e: e["path"])),
    }
    s.collection_provenance(value, paths)
    return value


def configuration_paths(paths):
    return {p for p in paths if p.endswith((".gradle", ".gradle.kts", ".versions.toml", ".lockfile"))
            or Path(p).name == "gradle.properties" or p == "gradle/verification-metadata.xml"}


def build_configuration(root, paths):
    for name in BUILD_CONFIG:
        r.require(name in paths and paths[name] == r.digest(regular(r.REPO_ROOT / name, r.MAX_JSON)), "unreviewed build configuration/dependency substitution")
    # Also constrain additional Gradle scripts/catalogs/init scripts: comparison
    # of only libs.versions.toml would leave an obvious substitution path.
    configurations = configuration_paths(paths)
    trusted = configuration_paths(r.source_tree(r.REPO_ROOT)[1])
    r.require(configurations == trusted, "unexpected/missing build configuration")
    for name in configurations:
        r.require(paths[name] == r.digest(regular(r.REPO_ROOT / name, r.MAX_JSON)), "unreviewed build configuration/dependency substitution")
    versions = regular(root / "gradle/libs.versions.toml", r.MAX_JSON).decode("utf-8")
    for name in ("morphe-patcher", "smali", "gson", "junit"):
        r.require(re.search(r'^' + re.escape(name) + r'\s*=\s*"' + re.escape(PINS[name]) + r'"\s*$', versions, re.M), "pinned dependency version required")
    settings = regular(root / "settings.gradle.kts", r.MAX_JSON).decode("utf-8")
    r.require('id("app.morphe.patches") version "2.1.0"' in settings, "pinned Morphe plugin required")
    props = regular(root / "gradle.properties", r.MAX_JSON).decode("utf-8")
    r.require(re.search(r'^version=0\.1\.0\s*$', props, re.M), "pinned collection version required")
    return {name: paths[name] for name in sorted(configurations | set(BUILD_CONFIG))}


def kotlin_code(text):
    # Preserve newlines but mask comments and literals so @Test in a fixture
    # string/comment is not confused with a declaration. No Kotlin is executed.
    token = re.compile(r'/\*.*?\*/|//[^\n]*|""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.S)
    return token.sub(lambda m: re.sub(r'[^\n]', ' ', m.group()), text)


def expected_tests(root, paths):
    expected = {}
    discovered = {p for p in paths if p.startswith(TEST_PREFIX) and p.endswith("Test.kt")}
    required = {TEST_PREFIX + name.replace(".", "/") + ".kt" for name in TEST_CLASSES}
    r.require(discovered == required, "exact six collection test source classes required")
    for name in TEST_CLASSES:
        text = regular(root / (TEST_PREFIX + name.replace(".", "/") + ".kt"), r.MAX_JSON).decode("utf-8")
        code = kotlin_code(text)
        package, short = name.rsplit(".", 1)
        r.require(re.search(r'^package\s+' + re.escape(package) + r'\s*$', code, re.M) and re.search(r'\bclass\s+' + short + r'\b', code), "test class/package mismatch")
        methods = re.findall(r'@Test\s+fun\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*\)', code)
        r.require(methods and len(methods) == len(set(methods)) and len(methods) == len(re.findall(r'@Test\b', code)), "unsupported/duplicate test declaration; review inventory")
        r.require(not re.search(r'@Ignore\b|@Disabled\b', code), "ignored source tests forbidden")
        r.require(REVIEWED_METHODS[name] <= set(methods), "missing reviewed minimum test inventory")
        if name.endswith(".OfflineAutomationValidationTest"):
            declaration = 'fun targets() = listOf("snippet widget", "SSH Automation", "terminal Automation").map { arrayOf(it) }'
            r.require(declaration in text and '@Parameterized.Parameters(name = "{0}")' in text and '@RunWith(Parameterized::class)' in code, "review parameterized test inventory")
            cases = {method + "[" + parameter + "]" for method in methods for parameter in OFFLINE_PARAMETERS}
        else:
            r.require('@RunWith' not in code and '@Parameterized' not in code, "unsupported test runner; review inventory")
            cases = set(methods)
        expected[name] = cases
    return expected


def junit(data, expected):
    text = data.decode("utf-8-sig")
    r.require("\x00" not in text and "<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(), "unsafe JUnit XML")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise r.ReleaseError("invalid JUnit XML") from exc
    name = root.get("name")
    r.require(root.tag == "testsuite" and name in expected, "unexpected JUnit suite/class")
    r.require(all(e.tag in {"properties", "testcase", "system-out", "system-err"} for e in root), "unexpected JUnit suite element")
    r.require(not any(e.tag in {"failure", "error", "skipped"} for e in root.iter()), "failed/errored/skipped JUnit case")
    cases = []
    for case in root.findall("testcase"):
        r.require(case.get("classname") == name and case.get("name") in expected[name], "unexpected JUnit test method/class")
        r.require(not list(case), "unexpected JUnit case contents")
        duration = case.get("time", "")
        r.require(re.fullmatch(r'[0-9]+(?:\.[0-9]+)?', duration), "JUnit execution time required")
        cases.append(case.get("name"))
    r.require(len(cases) == len(set(cases)) and set(cases) == expected[name], "missing/duplicate JUnit method coverage")
    counts = {}
    for key in ("tests", "failures", "errors", "skipped"):
        raw = root.get(key, "0" if key == "skipped" else "")
        r.require(re.fullmatch(r'[0-9]+', raw), "invalid JUnit counts")
        counts[key] = int(raw)
    r.require(counts == dict(tests=len(cases), failures=0, errors=0, skipped=0), "JUnit counts differ from executed cases")
    return name, counts


def snapshot(source_root, build_report, bundle_path, catalog_path):
    root, report_path = ancestry(source_root), ancestry(build_report)
    build = report_path.parent
    r.require(root.is_dir() and build.is_dir() and report_path.name == "build.json", "canonical build.json/source root required")
    root, build = root.resolve(), build.resolve()
    disjoint(root, build)
    disjoint(build, r.REPO_ROOT.resolve())
    report, report_bytes = r.read_json(report_path)
    r.exact(report, "out gradle_volume offline image tasks publication_repository requested_version bundle catalog tests status artifacts sha256", "canonical build report")
    r.require(report["status"] == "build_command_succeeded", "successful canonical build required; failed outputs cannot be frozen")
    r.require(Path(r.text(report["out"], "build out")).is_absolute() and ancestry(report["out"]).resolve() == build, "build output identity mismatch")
    r.text(report["image"], "reported build image")
    r.text(report["gradle_volume"], "reported Gradle volume")
    r.require(type(report["offline"]) is bool and report["publication_repository"] == s.TARGET and report["requested_version"] in (None, "0.1.0"), "build target/version mismatch")
    tasks = report["tasks"]
    allowed = {"clean", "test", "buildAndroid", ":patches:clean", ":patches:test", ":patches:buildAndroid"}
    r.require(isinstance(tasks, list) and all(isinstance(t, str) and t in allowed for t in tasks), "non-allowlisted build tasks")
    normalized = [t if t.startswith(":") else ":patches:" + t for t in tasks]
    r.require(normalized in ([":patches:test", ":patches:buildAndroid"], [":patches:clean", ":patches:test", ":patches:buildAndroid"]), "build tasks must be optional clean/test/buildAndroid in exact order")
    tree, paths = pristine_tree(root)
    config = build_configuration(root, paths)
    prov = provenance(root, paths)
    expected = expected_tests(root, paths)
    inputs = {}
    def read(relative, limit):
        r.portable_path(relative)
        data = regular(build / relative, limit)
        inputs[relative] = r.digest(data)
        return data
    inputs["build.json"] = r.digest(report_bytes)
    # The report itself must also pass hard-link/ancestry checks.
    r.require(regular(report_path, r.MAX_JSON) == report_bytes, "build report changed during read")
    archive = read("source.tar", MAX_SOURCE)
    source_archive(archive, paths)
    final = read("final-mpp.sha256", r.MAX_JSON).decode("utf-8").split()
    r.require(len(final) == 2 and re.fullmatch(r'/output/work/[^\s]+\.mpp', final[1]), "canonical final MPP hash record required")
    r.sha(final[0])
    artifacts = report["artifacts"]
    r.require(isinstance(artifacts, list) and artifacts and all(isinstance(p, str) and p.startswith("artifacts/") for p in artifacts), "collected artifact inventory required")
    for p in artifacts:
        r.portable_path(p)
    r.require(artifacts == sorted(set(artifacts)) and len({p.casefold() for p in artifacts}) == len(artifacts), "duplicate/noncanonical artifact inventory")
    actual = ["artifacts/" + p for p in walk_files(build / "artifacts")]
    r.require(actual == artifacts, "actual retained artifacts differ from build inventory")
    r.require(isinstance(report["sha256"], dict) and set(report["sha256"]) == set(artifacts), "complete artifact hash inventory required")
    for p in artifacts:
        r.sha(report["sha256"][p])
        read(p, r.MAX_BUNDLE)
        r.require(inputs[p] == report["sha256"][p], "retained artifact hash mismatch")
    r.exact(report["bundle"], "path sha256", "build bundle")
    r.exact(report["catalog"], "path sha256 version", "build catalog")
    bp, cp = report["bundle"]["path"], report["catalog"]["path"]
    r.require([p for p in artifacts if p.lower().endswith(".mpp")] == [bp] and bp.endswith(".mpp")
              and cp == "artifacts/patches-list.json" and [p for p in artifacts if Path(p).name.casefold() == "patches-list.json"] == [cp],
              "exact one MPP and canonical catalog required")
    r.require(final[1] == "/output/work/" + bp[len("artifacts/"):], "final MPP path mismatch")
    for supplied, relative in ((bundle_path, bp), (catalog_path, cp)):
        r.require(ancestry(supplied).resolve() == build / relative, "supplied artifact is not exact retained build path")
    bundle = read(bp, r.MAX_BUNDLE)
    catalog, catalog_bytes = r.read_json(build / cp)
    r.require(r.digest(catalog_bytes) == inputs[cp], "catalog changed during read")
    r.require(report["bundle"]["sha256"] == final[0] == inputs[bp] and report["catalog"]["sha256"] == inputs[cp] and report["catalog"]["version"] == "0.1.0", "build bundle/catalog binding mismatch")
    meta = r.bundle_metadata(bundle)
    r.require(all(meta.get(k) == v for k, v in {"name": "FISHYau android patches", "author": "FISHYau", "version": "0.1.0", "patcher-version": "2.3.0"}.items()), "bundle identity/version mismatch")
    s.collection_inventory(catalog, "0.1.0")
    tests = report["tests"]
    r.exact(tests, "tests failures errors skipped reports", "build tests")
    reports = [p for p in artifacts if "/test-results/" in p and p.endswith(".xml")]
    r.require(tests["reports"] == reports and len(reports) == len(expected), "complete six-class JUnit report inventory required")
    totals, seen = dict(tests=0, failures=0, errors=0, skipped=0), set()
    for p in reports:
        name, counts = junit(read(p, r.MAX_JSON), expected)
        r.require(name not in seen, "duplicate JUnit suite")
        seen.add(name)
        for k, v in counts.items():
            totals[k] += v
    r.require(seen == set(expected) and all(type(tests[k]) is int and tests[k] == v for k, v in totals.items()), "build/JUnit aggregate count mismatch")
    # Check a consistent snapshot at the end too: a late change to an otherwise
    # unused public file must not hide behind the tree hash read at entry.
    r.require(pristine_tree(root) == (tree, paths), "source changed during snapshot")
    for relative, digest in inputs.items():
        limit = MAX_SOURCE if relative == "source.tar" else r.MAX_BUNDLE
        r.require(r.digest(regular(build / relative, limit)) == digest, "build input changed during snapshot")
    r.require(["artifacts/" + p for p in walk_files(build / "artifacts")] == artifacts,
              "retained artifacts changed during snapshot")
    return dict(source_root=str(root), build_root=str(build), source_tree_sha256=tree, source_files=paths,
                build_inputs=inputs, build_identity={k: report[k] for k in ("image", "gradle_volume", "offline", "tasks", "publication_repository", "requested_version")},
                build_configuration=config, pinned_versions=PINS, provenance=prov, tests=totals,
                test_cases={name: sorted(cases) for name, cases in sorted(expected.items())},
                bundle=bundle, catalog_bytes=catalog_bytes)


def freeze(output, source_root, build_report, bundle_path, catalog_path, description, *, now=None):
    r.text(description, "description")
    now = now or dt.datetime.now(r.UTC)
    r.require(now.tzinfo is not None and now.utcoffset() == dt.timedelta(0), "UTC freeze clock required")
    created_at = now.replace(tzinfo=None).isoformat(timespec="microseconds")
    args = (source_root, build_report, bundle_path, catalog_path)
    first = snapshot(*args)
    target = ancestry(output).resolve()
    disjoint(target, Path(first["build_root"]))
    request = dict(schema=2, policy=s.COLLECTION_POLICY, owner="FISHYau", repository="fishyau-morphe-patches", version="0.1.0",
                   created_at=created_at, description=description, source_tree_sha256=first["source_tree_sha256"],
                   bundle_sha256=r.digest(first["bundle"]), catalog_sha256=r.digest(first["catalog_bytes"]), provenance=first["provenance"])
    r.make_manifest(request)  # Reuse exact timestamp/metadata contract; do not emit a candidate.
    r.require(snapshot(*args) == first, "inputs changed before freeze")
    directory = r.new_output(output, source_root)
    try:
        files = {"patches-0.1.0.mpp": first["bundle"], "patches-list.json": first["catalog_bytes"], "request.json": r.canonical(request)}
        for name, data in files.items():
            with (directory / name).open("xb") as handle:
                handle.write(data)
        r.require(snapshot(*args) == first, "inputs changed during freeze")
        for name, data in files.items():
            r.require(regular(directory / name, r.MAX_BUNDLE) == data, "frozen output changed")
        inventory = {k: v for k, v in first.items() if k not in {"bundle", "catalog_bytes", "provenance"}}
        inventory.update(schema=1, status="frozen-inputs-not-observations", created_at=created_at,
                         policy=s.COLLECTION_POLICY, request_sha256=r.digest(files["request.json"]),
                         bundle_sha256=request["bundle_sha256"], catalog_sha256=request["catalog_sha256"],
                         frozen_files={name: r.digest(data) for name, data in sorted(files.items())},
                         limitations="Local input binding only; no inspection, structural, Manager, Plex resource/parser/final-bundle/runtime observations, approval, candidate or publication.")
        frozen_bytes = r.canonical(inventory)
        with (directory / "freeze.json").open("xb") as handle:
            handle.write(frozen_bytes)
        r.require(snapshot(*args) == first, "inputs changed after freeze")
        completed = {**files, "freeze.json": frozen_bytes}
        for name, data in completed.items():
            r.require(regular(directory / name, r.MAX_BUNDLE) == data, "frozen output changed after freeze")
        # Hashing expected paths alone misses injected files or empty directories.
        entries = list(directory.iterdir())
        r.require({p.name for p in entries} == set(completed)
                  and all(not r.linked(p) and stat.S_ISREG(p.stat().st_mode) and p.stat().st_nlink == 1 for p in entries),
                  "exact four regular frozen output files required")
    except Exception:
        # Retain failed bytes, but never let an already written freeze marker be
        # mistaken for a completed operation. No details/paths/secrets in marker.
        marker = directory / "freeze.json"
        if marker.exists():
            marker.rename(directory / "freeze-incomplete.json")
        with (directory / "freeze-failed.json").open("xb") as handle:
            handle.write(r.canonical({"status": "failed-do-not-use"}))
        raise
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("source-root", "build-report", "bundle", "catalog", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--description", required=True)
    args = vars(parser.parse_args(argv))
    args["bundle_path"] = args.pop("bundle")
    args["catalog_path"] = args.pop("catalog")
    try:
        directory = freeze(**args)
        inv, _ = r.read_json(directory / "freeze.json")
        print(r.canonical({"status": inv["status"], **{k: inv[k] for k in ("request_sha256", "bundle_sha256", "catalog_sha256", "source_tree_sha256")}}).decode("utf-8"), end="")
    except (r.ReleaseError, OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        # Private paths and any unexpected tool output are deliberately omitted.
        print("Freeze blocked: input validation failed (" + type(exc).__name__ + ").", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
