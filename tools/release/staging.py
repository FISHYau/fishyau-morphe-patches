#!/usr/bin/env python3
"""Versioned accepted-source staging policies; never release approval/publication.

CLI: python -I -B tools/release/staging.py contract
     python -I -B tools/release/staging.py stage --source-root ROOT --bundle X.mpp
       --catalog patches-list.json --request request.json --evidence evidence.json
       --output NEW_EXTERNAL_DIRECTORY

Schemas and trust boundaries are printed by `contract`. No Git requirement, no
rebuild, no private evidence copy, no feature-runtime claim. release-v1 is intact.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
from pathlib import Path
import sys

_spec = importlib.util.spec_from_file_location("release_v1", Path(__file__).with_name("release.py"))
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)

POLICY = "termius-accepted-existing-behavior-v1"
TARGET = "FISHYau/fishyau-morphe-patches"
PATCHES = {"Server Auditor Offline Automation": True, "Server Auditor Premium": False}
MIGRATED = "patches/src/main/kotlin/io/github/fishyau/androidpatches/termius/"
# Exact original local bytes, not a donor commit or an arbitrary caller claim.
# This policy is deliberately non-generic: changing accepted originals needs a
# new reviewed policy, not a re-authored request JSON.
ORIGINALS = {
    "ServerAuditorOfflineAutomationPatch.kt": "72cc4c82755123e2f669be776310c57b665aba14c9a106c4e40fa4fcd66b12f5",
    "ServerAuditorPremiumPatch.kt": "6b200733bc869e88fe959e19c98750bb4a3a3730264f8d6386df3fa30575f736",
    "Fingerprints.kt": "22ed450db3bb8bb242ee6f50025f546675e2d05298f14cab7ecd9d093492cbb4",
    "BytecodeLayout.kt": "be52815c62aba834cfbc78cbb4be4a5037655b63ce850e3c479c5359cb8706df",
    "OfflineAutomationValidation.kt": "67d280d172ac992d0e38d93629da174be873a592e7edc8db046478edce730116",
    "PremiumPatchValidation.kt": "5baed68795dec3aedf95f766f772142ff8acce89fa415e3299982dc56f5aab1b",
}
SOURCES = set(ORIGINALS)
CONTRACT = """termius-accepted-existing-behavior-v1
Request exact fields: schema=1, policy, owner=FISHYau,
repository=fishyau-morphe-patches, version=0.1.0, created_at (offset-free UTC ISO),
description, bundle_sha256, catalog_sha256, source_tree_sha256, provenance.
No source_revision: a pre-Git tree is NOT a committed revision.
provenance exact fields: status=accepted-existing-behavior,
basis=user-confirmed-tested-working, adaptations=mechanical-namespace-import-helper-isolation,
files: [{path, original_sha256, migrated_sha256}]. Paths cover every Kotlin file
in the migrated termius/ directory, including the six named donor files. Those six
original hashes MUST equal the pinned ORIGINALS policy in this module. Original
hashes refer to the original file for whole-file migration and the exact reviewed
extracted fragment for isolated shared helpers. Additional migrated helper files
must be reviewed as part of this complete closure; hashes do NOT prove mechanical
equivalence. This provenance is user-confirmed inherited behavior, NOT fresh
runtime/visual acceptance and NOT a generic policy for unrelated patches.

Evidence exact fields: schema=1, inspection, structural, manager_import.
Every report has kind, platform, binding, observed_at, tool={name,version,sha256},
status=passed, checks={each required check: passed}, artifacts=[{kind,sha256}].
binding exact fields: policy, request_sha256 (exact input bytes), bundle_sha256,
catalog_sha256, source_tree_sha256. Reports <=7 days old, not future.
inspection kind=bundle-inspection, platform=jvm, checks=target_patcher_load,
actual_definitions, metadata, android_dex; extra fields patcher_version=2.3.0,
patches (full catalog patch DTOs, sorted by name), dependencies (every name -> []),
about={name:FISHYau android patches,author:FISHYau}, signing=unsigned;
artifacts must contain loader-report. JVM loading is NOT Android execution.
structural is exactly three reports kind=structural platform=jvm, one for each
singleton and the combined sorted selection. Extra fields selection, input_sha256,
output_sha256 (must differ), scope (explicit nonempty bounded comparison scope).
Checks=uncached_tests, patcher_round_trip, dex_control_flow, negative_fixtures;
artifacts must contain test-report and dex-report. These are structural checks,
not app feature runtime observations or whole-app coverage claims.
manager_import kind=manager-import, platform=android, checks=local_import,
collection_identity, patch_names, defaults, compatibility, visual_inspection;
extra fields manager={version,apk_sha256,certificate_sha256,origin}, where origin
is an official https://github.com/MorpheApp/morphe-manager/releases/... URL;
artifacts must contain manager-report and visual-review. Device ownership and
actual screenshot inspection remain the trusted harness/reviewer's obligation.
No local JSON report authenticates its own observations.

Catalog: exact two names, Offline Automation default true/Premium false, empty
options; one package com.server.auditor.ssh.client, APKM, one finite nonexperimental
8.0.1 target, all advertised ABI codes exactly integer 1008. Loader DTO and explicit
empty dependency map must agree. Bundle name/author/version/patcher are pinned;
plain unsigned Android ZIP required, no signing key advertised.

Output NEW external directory only: exact patches-0.1.0.mpp, patches-list.json,
patches-bundle.candidate.json, verification-summary.json, SHA256SUMS. No live root
manifest. Summary is sanitized, contains inherited provenance separately from
reported new observations, no invented revision/reviewer/runtime success. Its
status is staged-not-published. Hashes establish binding/completeness, not truth.
A protected authenticated human must review originals, migration, exact private
evidence and candidate bytes; later actual clean Git commit/immutable artifact,
configured protected approval and real upload/readback/CAS adapter are REQUIRED.
"""


COLLECTION_POLICY = "initial-three-patch-collection-v2"
# Current defaults are independent of the historical two-Termius policy above.
COLLECTION_PATCHES = {"Server Auditor Offline Automation": True, "Server Auditor Premium": True, "Premium unlock": True}
TERMIUS_ADAPTATIONS = "mechanical-namespace-import-helper-isolation-user-requested-premium-default-on-2026-11-09"
PLEX = "patches/src/main/kotlin/io/github/fishyau/androidpatches/plex/"
PLEX_REVISION = "38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f"
# Reviewed migration record pins, not an invitation to supply arbitrary hashes.
PLEX_FILES = {
    "PremiumUnlockPatch.kt": ("9c266b6d1cad2ad21a20a62a387be37d274b90d01ba7a7479c2984b368f643d5", "90b687f63c4327476a73355de4c0a3fd7f590c161937d0ccd9a1a0086a6f43e3"),
    "shared/HermesBytecode.kt": ("5ba7ec4682cf759c6838ba2c1cb8bf4a1fb1e5b11b80da59d9e7f744a30cf7e0", "4f490a527f26df757214f4dba3c17e3782cedd7498c1a8554db65d1bcdf8a909"),
    "shared/Constants.kt": ("95f4a1c0846d625823cd33022572fc4821f7128d81347d54359c840f4273b763", "8f55471c8c832a49fc0f82bacd22fc008063a7e28b493621315c0c343f4832cc"),
    "LICENSE": ("230184f60bae2feaf244f10a8bac053c8ff33a183bcc365b4d8b876d2b7f4809",) * 2,
    "NOTICE": ("fca3db575c0e22696864f3028fd5f6d5e667bcfada5d85c50d9345597be1ba6a",) * 2,
}
TERMIUS_MIGRATED = dict(zip(
    ("BooleanReturn.kt", "BytecodeLayout.kt", "Compatibility.kt", "Fingerprints.kt", "OfflineAutomationValidation.kt", "PremiumPatchValidation.kt", "ServerAuditorOfflineAutomationPatch.kt", "ServerAuditorPremiumPatch.kt"),
    ("86141faca95ccaf795835c3d771d641f6581f81955d099e6c110a797d20e3c56", "415ded2b5b2dd96d4f4100346e330e39cc3aa85f339337f3f5722392656f9d7c", "4b0cf89d440c9106badb2f895d8480cc6aef792de704081e714d1c51b1a451f0", "6230ace4174c599ea8f3c698d92dedfa51238ee01d23586f4b55c43b53d834b6", "915e0fbf16822e54052decb5efe25c4dbcfaf16f7235eb96e499f442f804f14d", "8e592471f3cddb5182ef4384a5624c6cf901769854e0ac88ca9252df0f7f6a67", "4226b2eef29b4e4cc8eba29f09ff6c6928f87a823d21cfd7bcca158359ad4ba4", "a4c949ceac08afed93d496f92d4c8f7726014854bc1d0366f4b36ba1bc3238fa")))
CONTRACT += """

CURRENT policy=initial-three-patch-collection-v2, request/evidence schema=2.
Same exact request keys. provenance={termius: legacy provenance object shape,
with adaptations=mechanical-namespace-import-helper-isolation-user-requested-premium-default-on-2026-11-09,
plex: {repository: https://github.com/UnkyBadTouch/plex-morphe-patches,
revision: 38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f,
basis: reviewed-source-migration-not-runtime-acceptance,
files: [{path,original_sha256,migrated_sha256}]}}. Plex includes LICENSE/NOTICE;
all migrated paths/hashes and original Plex sources are pinned in this policy.
Termius complete Kotlin closure also equals TERMIUS_MIGRATED, in addition to
legacy original pins. For schema2 only, Compatibility.kt original is the whole
donor shared/Constants.kt (6fd9e5085ad9ae26d968ac8089f0c461c99c4ee2c5450d4a032d5c9e2259ed5f),
and BooleanReturn.kt original is whole donor shared/BytecodeUtils.kt
(0d4f024dbc9416a453ed30423b6c6487397c5d03d0ec0da8e478349b52583a65),
under app/template/patches/. Migrated helper hashes pin the isolated Server
Auditor compatibility and false-only boolean returnEarly implementation, NOT
inheritance of unrelated helpers. Hashes bind reviewed provenance; they do not
prove mechanical equivalence or runtime behavior.
The sole additional Termius production adaptation is the explicit 2026-11-09 user
request: Premium default false -> true. Donor algorithms/guards/compatibility and
original hashes stay unchanged. Earlier namespace-only evidence is historical;
default co-selection does not establish combined Android runtime acceptance.
Exact three names/defaults: Offline Automation=true, Server Auditor Premium=true,
Premium unlock=true. Plex com.plexapp.android/APKM targets=[] is intentional
version-unpinned package compatibility, NOT universal/all-version proof. The
release-v1 finite-target validator and generic bytecode harness stay unchanged.
Legacy structural evidence remains Termius-only (two singletons + combined).
Additional evidence.plex exact keys: resource, parser, final_bundle, runtime.
Reports use the same fresh binding/tool/status/artifacts format as other reports.
resource: kind=plex-resource/platform=jvm; checks=actual_resource_patch hermes_v96
required_named_signatures raw_resource_preservation footer manifest_branches
idempotence negative_fixtures; artifacts=resource-report.
parser: kind=plex-parser/platform=jvm; checks=actual_parser bounds_failures
opcode_layouts negative_fixtures; artifacts=parser-report.
final_bundle: kind=plex-final-bundle/platform=jvm; checks=actual_final_bundle_load
actual_resource_execution exact_three_definitions; artifacts=loader-report resource-report.
Runtime={status:not-observed|blocked|observed, scope, artifacts:[{kind:runtime-report,
sha256}]}; observed requires a fresh standard plex-runtime/android report as
runtime.observation with checks=installation launch client_checks limitations
and artifacts=runtime-report visual-review. Scope always explicit; no inherited
Termius acceptance or historical notes qualify as Plex observations.
Human approval attests review of these private reports under policy, not a
mathematical proof of the claimed observations. Missing evidence blocks staging.
"""


def collection_provenance(value, paths):
    r.exact(value, "termius plex", "collection provenance")
    provenance(value["termius"], paths, adaptations=TERMIUS_ADAPTATIONS)
    # Helpers point to the whole donor source containers; migrated pins isolate
    # only Compatibility and the false boolean returnEarly overload, not the
    # donor's unrelated helpers. This is a policy-specific reviewed extraction.
    originals = {**ORIGINALS, "Compatibility.kt": "6fd9e5085ad9ae26d968ac8089f0c461c99c4ee2c5450d4a032d5c9e2259ed5f", "BooleanReturn.kt": "0d4f024dbc9416a453ed30423b6c6487397c5d03d0ec0da8e478349b52583a65"}
    r.require(all(item["original_sha256"] == originals.get(item["path"][len(MIGRATED):]) for item in value["termius"]["files"]), "complete pinned Termius original provenance required")
    expected = {MIGRATED + name: sha for name, sha in TERMIUS_MIGRATED.items()}
    r.require({p: h for p, h in paths.items() if p.startswith(MIGRATED) and p.endswith('.kt')} == expected, "reviewed Termius closure mismatch")
    plex = value["plex"]
    r.exact(plex, "repository revision basis files", "Plex provenance")
    r.require(plex["repository"] == "https://github.com/UnkyBadTouch/plex-morphe-patches" and plex["revision"] == PLEX_REVISION and plex["basis"] == "reviewed-source-migration-not-runtime-acceptance", "Plex reviewed provenance required; no inherited runtime acceptance")
    required = [{"path": PLEX + name, "original_sha256": hashes[0], "migrated_sha256": hashes[1]} for name, hashes in sorted(PLEX_FILES.items())]
    r.require(plex["files"] == required, "complete pinned Plex migration provenance required")
    r.require({p: h for p, h in paths.items() if p.startswith(PLEX)} == {PLEX + n: h[1] for n, h in PLEX_FILES.items()}, "reviewed Plex source/license closure mismatch")


def collection_inventory(catalog, version):
    # Deliberately independent of catalog_patches: v1 MUST reject targets=[].
    r.require(isinstance(catalog, dict) and catalog.get("version") == version and set(catalog) <= {"NOTE", "version", "patches"}, "collection catalog fields/version mismatch")
    if "NOTE" in catalog:
        r.text(catalog["NOTE"], "catalog note")
    patches = catalog.get("patches")
    r.require(isinstance(patches, list) and len(patches) == 3, "exact three collection definitions required")
    names = {}
    for patch in patches:
        r.exact(patch, "name description default category compatiblePackages options", "collection patch")
        r.require(type(patch["default"]) is bool and patch["options"] == [], "collection default/options mismatch")
        for key in ("description", "category"):
            r.require(patch[key] is None or isinstance(patch[key], str), "invalid collection text")
        name = r.text(patch["name"], "patch name")
        r.require(name not in names, "duplicate collection patch")
        names[name] = patch["default"]
        if name != "Premium unlock":
            # Preserve all finite-target v1 gates for Termius.
            r.catalog_patches({"version": version, "patches": [patch]}, version)
            app = patch["compatiblePackages"][0]
            r.require(len(patch["compatiblePackages"]) == 1 and app["packageName"] == "com.server.auditor.ssh.client" and app.get("apkFileType") == "APKM", "Termius compatibility mismatch")
            r.require(len(app["targets"]) == 1 and app["targets"][0]["version"] == "8.0.1" and all(type(c) is int and c == 1008 for c in app["targets"][0]["versionCodes"].values()), "Termius finite 8.0.1/code1008 required")
        else:
            apps = patch["compatiblePackages"]
            r.require(isinstance(apps, list) and len(apps) == 1, "one Plex package required")
            app = apps[0]
            r.require(isinstance(app, dict) and {"packageName", "targets"} <= set(app) <= {"packageName", "name", "description", "apkFileType", "appIconColor", "signatures", "formFactor", "targets"}, "Plex compatibility fields mismatch")
            r.require(app["packageName"] == "com.plexapp.android" and app.get("apkFileType") == "APKM" and app["targets"] == [], "intentional Plex APKM version-unpinned targets=[] required")
            for key in ("name", "description", "apkFileType", "appIconColor", "formFactor"):
                r.require(app.get(key) is None or isinstance(app[key], str), "invalid Plex compatibility text")
            if app.get("signatures") is not None:
                r.require(isinstance(app["signatures"], list) and app["signatures"], "invalid Plex APK signatures")
                for signature in app["signatures"]:
                    r.sha(signature)
    r.require(names == COLLECTION_PATCHES, "exact three collection names/defaults required")
    return sorted(patches, key=lambda p: p["name"])


def inventory(catalog, version, policy=POLICY):
    if policy == COLLECTION_POLICY:
        return collection_inventory(catalog, version)
    r.require(policy == POLICY, "unsupported inventory policy")
    r.catalog_patches(catalog, version)
    patches = sorted(catalog["patches"], key=lambda p: p["name"])
    r.require({p["name"]: p["default"] for p in patches} == PATCHES, "exact two accepted patch names/defaults required")
    r.require(len(patches) == 2, "exact two definitions required")
    for patch in patches:
        apps = patch["compatiblePackages"]
        r.require(len(apps) == 1, "one accepted package required")
        app = apps[0]
        r.require(app["packageName"] == "com.server.auditor.ssh.client" and app.get("apkFileType") == "APKM", "accepted Termius APKM compatibility required")
        r.require(len(app["targets"]) == 1, "one accepted target required")
        target = app["targets"][0]
        r.require(target["version"] == "8.0.1" and all(type(code) is int and code == 1008 for code in target["versionCodes"].values()), "accepted 8.0.1/code1008 required")
    return patches


def provenance(value, paths, adaptations="mechanical-namespace-import-helper-isolation"):
    r.exact(value, "status basis adaptations files", "accepted provenance")
    r.require(value["status"] == "accepted-existing-behavior" and value["basis"] == "user-confirmed-tested-working", "inherited acceptance required, not a new runtime claim")
    r.require(value["adaptations"] == adaptations, "reviewed migration adaptations required")
    files = value["files"]
    r.require(isinstance(files, list) and files, "source provenance required")
    seen = set()
    for item in files:
        r.exact(item, "path original_sha256 migrated_sha256", "migration source")
        path = r.portable_path(item["path"])
        r.require(path.startswith(MIGRATED) and path.endswith(".kt") and "/" not in path[len(MIGRATED):], "migration closure path required")
        r.sha(item["original_sha256"])
        original = ORIGINALS.get(path[len(MIGRATED):])
        r.require(original is None or item["original_sha256"] == original, "original source is outside accepted existing behavior policy")
        r.sha(item["migrated_sha256"])
        r.require(path not in seen and paths.get(path) == item["migrated_sha256"], "migrated source provenance mismatch")
        seen.add(path)
    expected = {p for p in paths if p.startswith(MIGRATED) and p.endswith(".kt")}
    r.require(seen == expected and {MIGRATED + name for name in SOURCES} <= seen, "complete accepted migration closure required")


def observation(value, kind, platform, binding, checks, artifacts, now, extra=""):
    r.exact(value, "kind platform binding observed_at tool status checks artifacts " + extra, kind)
    r.require(value["kind"] == kind and value["platform"] == platform and value["status"] == "passed", "wrong/failed observation or platform")
    r.require(r.canonical(value["binding"]) == r.canonical(binding), "exact observation binding mismatch")
    r.fresh(value["observed_at"], now)
    r.exact(value["tool"], "name version sha256", "observation tool")
    r.text(value["tool"]["name"], "tool name")
    r.text(value["tool"]["version"], "tool version")
    r.sha(value["tool"]["sha256"])
    r.require(value["checks"] == {k: "passed" for k in checks.split()}, "missing/failed observation checks")
    r.require(isinstance(value["artifacts"], list), "observation artifact list required")
    kinds = set()
    for item in value["artifacts"]:
        r.exact(item, "kind sha256", "private evidence reference")
        r.require(item["kind"] in artifacts and item["kind"] not in kinds, "unexpected/duplicate private evidence kind")
        kinds.add(item["kind"])
        r.sha(item["sha256"])
    r.require(kinds == artifacts, "missing kind-specific private evidence")


PLEX_REPORTS = {
    "resource": ("plex-resource", "actual_resource_patch hermes_v96 required_named_signatures raw_resource_preservation footer manifest_branches idempotence negative_fixtures", {"resource-report"}),
    "parser": ("plex-parser", "actual_parser bounds_failures opcode_layouts negative_fixtures", {"parser-report"}),
    "final_bundle": ("plex-final-bundle", "actual_final_bundle_load actual_resource_execution exact_three_definitions", {"loader-report", "resource-report"}),
}


def validate_plex(value, binding, now):
    r.exact(value, "resource parser final_bundle runtime", "dedicated Plex evidence")
    summary = {}
    for key, (kind, checks, artifacts) in PLEX_REPORTS.items():
        observation(value[key], kind, "jvm", binding, checks, artifacts, now)
        summary[key] = {"platform": "jvm", "status": "passed", "observed_at": value[key]["observed_at"]}
    runtime = value["runtime"]
    r.require(isinstance(runtime, dict) and runtime.get("status") in {"not-observed", "blocked", "observed"}, "explicit honest Plex runtime status required")
    r.exact(runtime, "status scope artifacts" + (" observation" if runtime["status"] == "observed" else ""), "Plex runtime status")
    r.text(runtime["scope"], "Plex runtime scope/limitations")
    r.require(isinstance(runtime["artifacts"], list), "Plex runtime references required")
    for item in runtime["artifacts"]:
        r.exact(item, "kind sha256", "Plex runtime reference")
        r.require(item["kind"] == "runtime-report", "Plex runtime report kind required")
        r.sha(item["sha256"])
    summary["runtime"] = {"status": runtime["status"], "scope_sha256": r.digest(runtime["scope"].encode())}
    if runtime["status"] == "observed":
        observation(runtime["observation"], "plex-runtime", "android", binding, "installation launch client_checks limitations", {"runtime-report", "visual-review"}, now)
        r.require(runtime["artifacts"] and all(item in runtime["observation"]["artifacts"] for item in runtime["artifacts"]), "bound runtime artifact required")
        summary["runtime"]["observed_at"] = runtime["observation"]["observed_at"]
    return summary


def validate(source_root, bundle_path, catalog_path, request_path, evidence_path, *, now=None):
    now = now or dt.datetime.now(r.UTC)
    req, req_bytes = r.read_json(request_path)
    r.exact(req, "schema policy owner repository version created_at description bundle_sha256 catalog_sha256 source_tree_sha256 provenance", "staging request")
    current = req["policy"] == COLLECTION_POLICY
    policy = req["policy"]
    r.require(type(req["schema"]) is int and (req["schema"], policy) in {(1, POLICY), (2, COLLECTION_POLICY)}, "unsupported staging policy")
    r.require(req["owner"] + "/" + req["repository"] == TARGET and req["version"] == "0.1.0", "accepted target/version required")
    manifest = r.make_manifest(req)
    r.require(r.normalize_source("https://github.com/" + TARGET) == "https://raw.githubusercontent.com/" + TARGET + "/main/patches-bundle.json", "source endpoint mismatch")
    r.require(r.local_time(req["created_at"]) <= now, "future creation date")
    for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256"):
        r.sha(req[key])
    tree, paths = r.source_tree(Path(source_root))
    r.require(tree == req["source_tree_sha256"], "source tree digest mismatch")
    (collection_provenance if current else provenance)(req["provenance"], paths)
    bundle = r.read_bytes(bundle_path, r.MAX_BUNDLE)
    r.require(Path(bundle_path).suffix == ".mpp" and r.digest(bundle) == req["bundle_sha256"], "exact MPP bundle digest required")
    meta = r.bundle_metadata(bundle)
    expected = {"name": "FISHYau android patches", "author": "FISHYau", "version": req["version"], "patcher-version": "2.3.0"}
    r.require(all(meta.get(k) == v for k, v in expected.items()), "bundle metadata mismatch")
    catalog, catalog_bytes = r.read_json(catalog_path)
    r.require(r.digest(catalog_bytes) == req["catalog_sha256"], "exact catalog digest mismatch")
    patches = inventory(catalog, req["version"], policy)
    evidence, evidence_bytes = r.read_json(evidence_path)
    r.exact(evidence, "schema inspection structural manager_import" + (" plex" if current else ""), "staging evidence")
    r.require(type(evidence["schema"]) is int and evidence["schema"] == req["schema"], "unsupported evidence schema")
    binding = {k: req[k] for k in ("policy", "bundle_sha256", "catalog_sha256", "source_tree_sha256")}
    binding["request_sha256"] = r.digest(req_bytes)
    inspection = evidence["inspection"]
    observation(inspection, "bundle-inspection", "jvm", binding,
                "target_patcher_load actual_definitions metadata android_dex", {"loader-report"}, now,
                "patcher_version patches dependencies about signing")
    r.require(inspection["patcher_version"] == "2.3.0", "target patcher mismatch")
    r.require(r.canonical(inspection["patches"]) == r.canonical(patches), "loaded definitions/catalog mismatch")
    r.require(inspection["dependencies"] == {name: [] for name in (COLLECTION_PATCHES if current else PATCHES)}, "explicit empty loader dependencies required")
    r.require(inspection["about"] == {k: expected[k] for k in ("name", "author")} and inspection["signing"] == "unsigned", "loaded About/signing mismatch")
    cases = evidence["structural"]
    r.require(isinstance(cases, list) and len(cases) == 3, "two singletons and combined structural coverage required")
    selections = set()
    for case in cases:
        observation(case, "structural", "jvm", binding,
                    "uncached_tests patcher_round_trip dex_control_flow negative_fixtures", {"test-report", "dex-report"}, now,
                    "selection input_sha256 output_sha256 scope")
        selection = case["selection"]
        r.require(isinstance(selection, list) and all(isinstance(n, str) for n in selection), "selection list required")
        r.require(selection == sorted(set(selection)) and set(selection) <= PATCHES.keys(), "invalid structural selection")
        selections.add(tuple(selection))
        r.sha(case["input_sha256"])
        r.sha(case["output_sha256"])
        r.require(case["input_sha256"] != case["output_sha256"], "patched output cannot be original input")
        r.text(case["scope"], "bounded comparison scope")
    r.require(selections == {(name,) for name in PATCHES} | {tuple(sorted(PATCHES))}, "missing/duplicate structural selection coverage")
    manager = evidence["manager_import"]
    observation(manager, "manager-import", "android", binding,
                "local_import collection_identity patch_names defaults compatibility visual_inspection", {"manager-report", "visual-review"}, now, "manager")
    identity = manager["manager"]
    r.exact(identity, "version apk_sha256 certificate_sha256 origin", "official Manager identity")
    r.text(identity["version"], "Manager version")
    r.sha(identity["apk_sha256"])
    r.sha(identity["certificate_sha256"])
    origin = r.https_url(identity["origin"], "Manager origin")
    r.require(origin.hostname == "github.com" and origin.path.startswith("/MorpheApp/morphe-manager/releases/"), "official Manager release provenance required")
    # Do not copy caller-authored tool names, paths, narrative, input/output hashes,
    # reviewer identity or private material into the public summary.
    plex_summary = validate_plex(evidence["plex"], binding, now) if current else None
    summary = {"schema": req["schema"], "policy": policy, "status": "staged-not-published", "target": TARGET,
               "version": req["version"], "binding": binding, "evidence_sha256": r.digest(evidence_bytes),
               "inherited_behavior": req["provenance"],
               "reported_new_observations": {
                   "jvm_inspection": {"platform": "jvm", "status": "passed", "observed_at": inspection["observed_at"]},
                   "jvm_structural": [{"platform": "jvm", "status": "passed", "selection": case["selection"],
                                       "observed_at": case["observed_at"], "scope_sha256": r.digest(case["scope"].encode("utf-8"))}
                                      for case in sorted(cases, key=lambda c: c["selection"])],
                   "android_manager_local_import": {"platform": "android", "status": "passed", "observed_at": manager["observed_at"]},
                   "evidence_authenticated": False},
               "trust": "Hash binding and report completeness only, not authenticated truth. Existing behavior is user-confirmed, not newly measured feature runtime.",
               "remaining": ["actual clean source commit", "immutable approved candidate artifact", "authenticated protected human evidence review",
                             "configured protected release environment", "real upload/download/rehash and manifest-last CAS", "live GitHub source discovery/update not hosted or observed"]}
    if current:
        summary["reported_new_observations"]["plex"] = plex_summary
        summary["trust"] = "Private report completeness and exact hash binding, not authenticated observations. Termius acceptance is not Plex runtime acceptance; unpinned package compatibility is not all-version proof."
    return {"request": req, "bundle": bundle, "catalog_bytes": catalog_bytes, "manifest": manifest, "summary": summary}


def stage(output, source_root, **kwargs):
    result = validate(source_root, **kwargs)
    r.require(r.source_tree(Path(source_root))[0] == result["request"]["source_tree_sha256"], "source changed during staging")
    files = {"patches-0.1.0.mpp": result["bundle"], "patches-list.json": result["catalog_bytes"],
             "patches-bundle.candidate.json": r.canonical(result["manifest"]),
             "verification-summary.json": r.canonical(result["summary"])}
    files["SHA256SUMS"] = "".join(f"{r.digest(data)}  {name}\n" for name, data in sorted(files.items())).encode("ascii")
    directory = r.new_output(output, source_root)
    for name, data in files.items():
        with (directory / name).open("xb") as handle:
            handle.write(data)
    return directory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("contract")
    cmd = sub.add_parser("stage")
    cmd.add_argument("--source-root", type=Path, required=True)
    for name in ("bundle", "catalog", "request", "evidence"):
        cmd.add_argument("--" + name, dest=name + "_path", type=Path, required=True)
    cmd.add_argument("--output", type=Path, required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    try:
        if command == "contract":
            print(CONTRACT)
        else:
            print(stage(**args))
    except (r.ReleaseError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Staging blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
