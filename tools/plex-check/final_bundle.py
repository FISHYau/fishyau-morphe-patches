"""Offline, isolated actual-FINAL-MPP Plex synthetic resource checker.

Run installed Python with -I -B and explicit --jdk/--cache-root/NEW external --out.
`compile-only` establishes only API/adapter compilation; it cannot produce execution
observations. `check` additionally requires exact supplied --bundle/--catalog and a
PREEXISTING frozen --request (never generated after observations). No Gradle, network,
source patch compilation, APKM merging, signing, Android/ART/Manager or app acceptance.
"""
import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
import zipfile

POLICY = "initial-three-patch-collection-v2"
DEFAULTS = {"Server Auditor Offline Automation": True, "Server Auditor Premium": True, "Premium unlock": True}
SCHEMA = 2
REQUEST_FIELDS = "schema policy owner repository version created_at description bundle_sha256 catalog_sha256 source_tree_sha256 provenance"
SUCCESS = "final_bundle_plex_synthetic_resources_verified"
FORBIDDEN = (
    "io/github/fishyau/androidpatches/termius/ServerAuditorOfflineAutomationPatchKt",
    "io/github/fishyau/androidpatches/termius/ServerAuditorPremiumPatchKt",
    "io/github/fishyau/androidpatches/plex/",
)
CASE_NAMES = {
    "flip_JStrictEqual", "flip_JStrictEqualLong", "flip_JStrictNotEqual", "flip_JStrictNotEqualLong",
    "flip_StrictEq", "flip_StrictNeq", "idempotence", "mixed_pending", "duplicate_named_functions",
    "load_move_1", "load_move_2", "manifest_missing", "manifest_binary", "manifest_empty",
    "manifest_decoded_cleanup", "manifest_actual_binary_decode", "missing_on_signature",
    "missing_function_signature", "missing_comparison_signature", "wrong_magic", "wrong_version", "malformed_instruction", "clobbered_on_register",
}
NEGATIVES = {"missing_on_signature", "missing_function_signature", "missing_comparison_signature", "wrong_magic", "wrong_version", "malformed_instruction", "clobbered_on_register"}


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def parse_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))


def release_module(repo):
    spec = importlib.util.spec_from_file_location("plex_trusted_release", repo / "tools/release/release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def staging_module(repo):
    spec = importlib.util.spec_from_file_location("plex_trusted_staging", repo / "tools/release/staging.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_request(data, bundle, catalog, tree_digest, source_entries, staging=None):
    """Consume freeze.py's exact schema2 bytes; never translate or add fields.

    Source entries must come from the caller's actual release.source_tree snapshot,
    not from the request. Provenance pins are the CURRENT staging policy's pins.
    """
    staging = staging or staging_module(Path(__file__).resolve().parents[2])
    release = staging.r
    request = parse_json(data)
    release.exact(request, REQUEST_FIELDS, "frozen request fields")
    require(type(request["schema"]) is int and request["schema"] == SCHEMA
            and request["policy"] == POLICY, "request schema/policy mismatch")
    require((request["owner"], request["repository"], request["version"]) ==
            ("FISHYau", "fishyau-morphe-patches", "0.1.0"), "request target/version mismatch")
    release.make_manifest(request)  # Shared target, offset-free timestamp and description gates.
    require(release.local_time(request["created_at"]) <= dt.datetime.now(release.UTC), "future creation date")
    for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256"):
        release.sha(request[key], "request digest")
    require(request["source_tree_sha256"] == tree_digest, "frozen source tree mismatch")
    staging.collection_provenance(request["provenance"], source_entries)
    require(bundle.suffix == ".mpp" and sha_checked(release, bundle, release.MAX_BUNDLE) == request["bundle_sha256"], "exact final MPP digest required")
    require(sha_checked(release, catalog, release.MAX_JSON) == request["catalog_sha256"], "exact catalog digest required")
    return request


def sha_checked(release, path, limit):
    return hashlib.sha256(release.read_bytes(path, limit)).hexdigest()


def validate_final_inputs(release, request, bundle, catalog, staging=None):
    # Current three-patch inventory intentionally allows Plex targets=[]. Do not
    # weaken or call the historical release-v1 finite-target catalog validator.
    staging = staging or staging_module(Path(__file__).resolve().parents[2])
    metadata = release.bundle_metadata(release.read_bytes(bundle, release.MAX_BUNDLE))
    require(metadata.get("patcher-version") == "2.3.0", "wrong final patcher version")
    require(metadata.get("name") == "FISHYau android patches" and metadata.get("author") == "FISHYau", "wrong final About identity")
    require(metadata.get("version") == request["version"], "final bundle/request version mismatch")
    parsed = parse_json(release.read_bytes(catalog, release.MAX_JSON))
    staging.collection_inventory(parsed, request["version"])


def preflight(request_path, bundle, catalog, tree_digest, source_entries, release, staging):
    """Schema/archive/catalog boundary only; no compiler, loader or observations.

    Returning the original bytes is intentional: staging binds their SHA, not a
    reserialized semantic equivalent. Synthetic archive tests must stop here.
    """
    data = release.read_bytes(request_path, 65536)
    request = validate_request(data, bundle, catalog, tree_digest, source_entries, staging)
    validate_final_inputs(release, request, bundle, catalog, staging)
    return data, request


def resolve(cache, coordinate, digest):
    group, artifact, version = coordinate.split(":")
    candidates = list((cache / group / artifact / version).glob(f"*/{artifact}-{version}.jar"))
    require(len(candidates) == 1 and sha(candidates[0]) == digest, f"missing/ambiguous/hash-mismatched artifact: {coordinate}")
    return candidates[0].resolve(strict=True)


def select_sources(repo):
    root = repo / "tools/plex-check/src/main/kotlin"
    sources = [root / "FinalBundleCheck.kt", root / "FinalBundleFixtures.kt"]
    require(set(root.rglob("*.kt")) == set(sources), "exact tools-only checker source inventory required")
    projection = repo / "patches/src/main/kotlin/io/github/fishyau/androidpatches/tools"
    return sources + [projection / "LoadedBundleMetadata.kt", projection / "PatchListGenerator.kt"]


def isolated_classpath(paths):
    inventories = []
    for path in paths:
        with zipfile.ZipFile(path) as jar:
            names = jar.namelist()
            require(len(names) == len(set(names)), "duplicate parent archive member")
            require(not any(name.startswith(FORBIDDEN) for name in names), f"source definition/production Plex helper on parent: {path}")
        inventories.append({"path": str(path), "sha256": sha(path)})
    return inventories


def utcnow():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def verify_times(record):
    start = dt.datetime.fromisoformat(record["started_at"].replace("Z", "+00:00"))
    end = dt.datetime.fromisoformat(record["finished_at"].replace("Z", "+00:00"))
    require(start.tzinfo is not None and end.tzinfo is not None and end >= start, "invalid observation times")
    require(type(record["elapsed_ns"]) is int and record["elapsed_ns"] > 0, "missing actual duration")


def verify_record(record, root, *, required):
    path = Path(record["path"]).resolve(strict=False)
    require(path.is_relative_to(root) and path != root, "retained evidence escapes run")
    require(record["exists"] is path.is_file(), "retained existence mismatch")
    if required:
        require(path.is_file(), "missing retained evidence")
    if path.is_file():
        require(record["sha256"] == sha(path) and record["bytes"] == path.stat().st_size, "retained evidence digest mismatch")
    else:
        require(record["sha256"] is None and record["bytes"] is None, "invented absent evidence")
    return path


def validate_native(report, out, request_hash, request):
    """No translation of aggregate success or compile-only status into passed flags."""
    require(report.get("schema") == "plex-final-bundle-native-v1" and report.get("status") == SUCCESS, "native execution did not complete")
    require(report.get("request_sha256") == request_hash, "native frozen request mismatch")
    for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256"):
        require(report.get(key) == request[key], "native input binding mismatch")
    require(report.get("actual_definition") == "exact_three_loaded_metadata_catalog_verified", "actual loader not observed")
    require(report.get("resource_execution") == "loaded_plex_raw_resource_patch_all_named_cases_verified", "loaded resource execution not observed")
    require(report.get("loader") == "app.morphe.patcher.patch.loadPatchesFromJar"
            and report.get("executed_patch_names") == ["Premium unlock"], "wrong loader/patch selection")
    require(report.get("classpath_isolation") == "definition_and_production_plex_helper_resources_absent", "native isolation missing")
    verify_times(report)
    cases = report.get("cases")
    require(isinstance(cases, list) and len(cases) == len(CASE_NAMES) and {c.get("name") for c in cases} == CASE_NAMES, "exact named observations required")
    out = out.resolve()
    for case in cases:
        name = case["name"]
        verify_times(case)
        require(case.get("status") == ("rejected_without_writes" if name in NEGATIVES else "resource_bytes_verified"), "named case did not complete")
        require(Path(case["retained_directory"]).resolve() == out / "cases" / name, "case path mismatch")
        require(parse_json((out / "cases" / name / "case.json").read_bytes()) == case, "native case record mismatch")
        paths = {}
        for field in ("fixture_zip", "input_bundle", "expected_bundle", "output_bundle", "input_manifest", "output_manifest", "unrelated_resource"):
            paths[field] = verify_record(case[field], out, required=field not in {"input_manifest", "output_manifest"})
        require(paths["output_bundle"].read_bytes() == paths["expected_bundle"].read_bytes(), "expected whole-resource bytes disagree")
        if name in NEGATIVES:
            require(case["expected_rejection"] and paths["input_bundle"].read_bytes() == paths["output_bundle"].read_bytes(), "negative case mutated bundle")
            require(paths["input_manifest"].read_bytes() == paths["output_manifest"].read_bytes(), "negative case mutated manifest")
        calls = case.get("execute_calls")
        require(isinstance(calls, list) and len(calls) == (2 if name == "idempotence" else 1), "missing actual execute calls")
        for index, call in enumerate(calls, 1):
            verify_times(call)
            require(call["index"] == index, "execute call order mismatch")
            if name in NEGATIVES:
                require(call.get("exception") == "app.morphe.patcher.patch.PatchException" and case["expected_rejection"] in call.get("message", ""), "negative rejection not observed")
            else:
                require(call.get("exception") is None, "positive resource execution rejected")
    return cases


def _execute(args, repo=None):
    repo = (repo or Path(__file__).resolve().parents[2]).resolve()
    out = args.out.resolve()
    require(not out.exists() and out != repo and not out.is_relative_to(repo) and out.parent.is_dir(), "NEW external output with existing parent required")
    validator_paths = [repo / "tools/release/release.py", repo / "tools/release/staging.py"]
    validator_hashes = {str(p): sha(p) for p in validator_paths}
    release = release_module(repo)
    tree_before, source_entries = release.source_tree(repo)
    request_bytes = None
    request = None
    if args.command == "check":
        require(args.request and args.bundle and args.catalog, "check needs preexisting frozen request, final MPP and catalog")
        staging = staging_module(repo)
        request_bytes, request = preflight(args.request, args.bundle, args.catalog, tree_before, source_entries, release, staging)
    else:
        require(not any((args.request, args.bundle, args.catalog)), "compile-only cannot accept observation inputs")
    java = args.jdk.resolve(strict=True) / "bin/java.exe"
    require(java.is_file(), "explicit installed Windows JDK bin/java.exe required")
    jdk_release = args.jdk.resolve() / "release"
    require(re.search(r'^JAVA_VERSION="21(?:\.|\")', jdk_release.read_text(), re.M), "installed JDK21 required")
    closure_path = repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
    closure = parse_json(closure_path.read_bytes())
    require((closure["patcher_version"], closure["compiler_version"]) == ("2.3.0", "2.4.21"), "wrong pinned closure")
    cache = args.cache_root.resolve(strict=True)
    compiler = [resolve(cache, *item) for item in closure["compiler"]]
    runtime = [resolve(cache, *item) for item in closure["runtime"]]
    sources = select_sources(repo)
    inputs = list(dict.fromkeys([Path(__file__).resolve(), *validator_paths, closure_path,
                                java, jdk_release, java.parent / "server/jvm.dll", java.parent.parent / "lib/modules", *compiler, *runtime, *sources]))
    if request is not None:
        inputs += [args.request.resolve(), args.bundle.resolve(), args.catalog.resolve()]
    hashes = {str(p): sha(p) for p in inputs}
    require(all(hashes[p] == digest for p, digest in validator_hashes.items()), "validator changed during preflight")
    if request_bytes is not None:
        require(hashes[str(args.request.resolve())] == hashlib.sha256(request_bytes).hexdigest(), "frozen request changed before copy")
        require(sha(args.bundle) == request["bundle_sha256"] and sha(args.catalog) == request["catalog_sha256"], "final inputs changed before copy")
    out.mkdir()
    (out / "tmp").mkdir()
    if request_bytes is not None:
        (out / "frozen-request.json").write_bytes(request_bytes)
    (out / "source-tree.json").write_text(json.dumps({"sha256": tree_before, "entries": source_entries}, indent=2) + "\n", encoding="utf-8")
    started = time.monotonic_ns()
    report = {"schema": "plex-final-bundle-wrapper-v1", "status": "failed", "mode": args.command,
              "started_at": utcnow(), "source_tree_sha256": tree_before, "source_root": str(repo),
              "request_sha256": hashlib.sha256(request_bytes).hexdigest() if request_bytes is not None else None,
              "input_sha256": hashes, "commands": [], "actual_definition": "not_observed", "resource_execution": "not_observed",
              "scope": "Synthetic noninstallable resource checks, not APKM merge/signing/ART/Manager/Plex app acceptance"}
    env = {k: v for k, v in os.environ.items() if k.upper() not in {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"}}

    def run(label, command):
        row = {"step": label, "argv": list(map(str, command)), "started_at": utcnow()}
        report["commands"].append(row)
        before = time.monotonic_ns()
        log = out / (label + ".log")
        try:
            completed = subprocess.run(row["argv"], cwd=out, env=env, capture_output=True, timeout=300, check=False)
            log.write_bytes(completed.stdout + completed.stderr)
            row["exit_code"] = completed.returncode
            require(completed.returncode == 0, f"{label} exited {completed.returncode}; retained {log}")
        except subprocess.TimeoutExpired as exc:
            log.write_bytes((exc.stdout or b"") + (exc.stderr or b""))
            row["status"] = "timeout"
            raise
        finally:
            row["finished_at"] = utcnow(); row["elapsed_ns"] = time.monotonic_ns() - before
            if log.is_file():
                row["log"] = {"path": str(log), "sha256": sha(log)}
    try:
        run("java-version", [java, "-version"])
        checker = out / "checker-tools-only.jar"
        report["compiled_sources"] = [str(p.relative_to(repo)) for p in sources]
        run("compile", [java, "-Xmx1024m", "-Djava.io.tmpdir=" + str(out / "tmp"), "-cp", os.pathsep.join(map(str, compiler)),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
                        "-classpath", os.pathsep.join(map(str, runtime)), "-d", checker, *sources])
        report["checker_sha256"] = sha(checker)
        report["parent_classpath_inventory"] = isolated_classpath([checker, *runtime])
        report["parent_classpath"] = os.pathsep.join(map(str, [checker, *runtime]))
        if args.command == "check":
            # Preserve this exact request copy before the child can observe anything.
            require((out / "frozen-request.json").read_bytes() == request_bytes
                    and sha(args.request) == report["request_sha256"], "frozen request changed before child")
            require(all(p.is_file() and sha(p) == hashes[str(p)] for p in inputs), "inputs changed before child")
            run("actual-final-bundle", [java, "-Djava.io.tmpdir=" + str(out / "tmp"), "-cp", report["parent_classpath"],
                "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", args.bundle.resolve(), args.catalog.resolve(),
                out / "frozen-request.json", out / "native.json", out / "cases", tree_before, repo])
            native = parse_json((out / "native.json").read_bytes())
            require(native["parent_classpath"] == report["parent_classpath"], "native classpath differs")
            report["cases"] = validate_native(native, out, report["request_sha256"], request)
            report["native_report"] = {"path": str(out / "native.json"), "sha256": sha(out / "native.json")}
            report["actual_definition"] = native["actual_definition"]; report["resource_execution"] = native["resource_execution"]
            report["status"] = SUCCESS
        else:
            report["status"] = "compile_only_no_final_bundle_observation"
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        try:
            after, _ = release.source_tree(repo)
            report["source_tree_sha256_after"] = after
            require(after == tree_before, "source tree changed during check")
            require(all(p.is_file() and sha(p) == hashes[str(p)] for p in inputs), "source/tool/request/final inputs changed during check")
            if request_bytes is not None:
                require((out / "frozen-request.json").read_bytes() == request_bytes, "frozen request changed during execution")
            report["inputs_unchanged"] = True
        except Exception as exc:
            report["status"] = "failed"; report["verification_error"] = str(exc)
        report["finished_at"] = utcnow(); report["elapsed_ns"] = time.monotonic_ns() - started
        with (out / "checker.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2); stream.write("\n")
    return report


def execute(args, repo=None):
    """Even rejected preflights consume their NEW output; never retry that path."""
    source = (repo or Path(__file__).resolve().parents[2]).resolve()
    out = args.out.resolve()
    require(not out.exists() and out != source and not out.is_relative_to(source) and out.parent.is_dir(),
            "NEW external output with existing parent required")
    start = time.monotonic_ns()
    started_at = utcnow()
    try:
        return _execute(args, source)
    except Exception as exc:
        # _execute writes its own report once it starts observations. Never replace
        # such an output (or any concurrently created directory) on an exception.
        if out.exists():
            raise
        out.mkdir()
        report = {"schema": "plex-final-bundle-wrapper-v1", "status": "failed", "phase": "preflight",
                  "mode": args.command, "error": str(exc), "commands": [],
                  "actual_definition": "not_observed", "resource_execution": "not_observed",
                  "started_at": started_at, "finished_at": utcnow(), "elapsed_ns": time.monotonic_ns() - start}
        with (out / "checker.json").open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2); stream.write("\n")
        return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("compile-only", "check"))
    for option in ("jdk", "cache-root", "out"):
        parser.add_argument("--" + option, required=True, type=Path)
    for option in ("request", "bundle", "catalog"):
        parser.add_argument("--" + option, type=Path)
    args = parser.parse_args()
    report = execute(args)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] in {SUCCESS, "compile_only_no_final_bundle_observation"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
