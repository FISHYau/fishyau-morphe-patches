"""Offline, isolated actual-MPP Plex synthetic resource checker.

Run installed Python with -I -B and explicit --jdk/--cache-root/NEW external --out.
`compile-only` checks API/adapter compilation only. `check` additionally requires
explicit --bundle/--catalog. No Gradle, network, source patch compilation, APKM
merging, signing, Android/ART/Manager or app acceptance.
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

SUCCESS = "final_bundle_plex_synthetic_resources_verified"
FORBIDDEN = (
    "io/github/fishyau/androidpatches/termius/ServerAuditorOfflineAutomationPatchKt",
    "io/github/fishyau/androidpatches/termius/ServerAuditorPremiumPatchKt",
    "io/github/fishyau/androidpatches/plex/",
    "io/github/fishyau/androidpatches/spotify/",
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


def formats_module(repo):
    # Explicit trusted source path works under Python -I; never import from inputs.
    spec = importlib.util.spec_from_file_location("plex_trusted_bundle_formats", repo / "tools/bundle_formats.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def preflight(formats, bundle, catalog):
    """Validate artifact bytes/catalog before any compiler or loader execution."""
    require(bundle.suffix == ".mpp", "explicit Android MPP required")
    bundle_bytes = formats.read_bytes(bundle, formats.MAX_BUNDLE)
    catalog_bytes = formats.read_bytes(catalog, formats.MAX_JSON)
    metadata = formats.bundle_metadata(bundle_bytes)
    require(metadata.get("patcher-version") == "2.3.0", "wrong final patcher version")
    require(metadata.get("name") == "FISHYau android patches" and metadata.get("author") == "FISHYau", "wrong final About identity")
    version = metadata.get("version")
    require(isinstance(version, str) and bool(version.strip()), "missing final bundle version")
    # The current inventory intentionally encodes the version-unpinned Plex target
    # as targets=[]. It must still match the actual loader's projection below.
    formats.collection_inventory(parse_json(catalog_bytes), version)
    return {"version": version, "bundle_sha256": hashlib.sha256(bundle_bytes).hexdigest(),
            "catalog_sha256": hashlib.sha256(catalog_bytes).hexdigest()}


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
    for path in paths:
        with zipfile.ZipFile(path) as jar:
            names = jar.namelist()
            require(len(names) == len(set(names)), "duplicate parent archive member")
            require(not any(name.startswith(FORBIDDEN) for name in names), f"source definition/production Plex helper on parent: {path}")


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


def validate_native(report, out, inputs):
    """Compile-only status or aggregate success cannot replace actual case checks."""
    require(report.get("schema") == "plex-final-bundle-native-v1" and report.get("status") == SUCCESS, "native execution did not complete")
    for key in ("version", "bundle_sha256", "catalog_sha256"):
        require(report.get(key) == inputs[key], "native input mismatch")
    require(report.get("actual_definition") == "exact_four_loaded_metadata_catalog_verified", "actual loader not observed")
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
    formats = formats_module(repo)
    selected = None
    if args.command == "check":
        require(args.bundle and args.catalog, "check needs explicit final MPP and catalog")
        selected = preflight(formats, args.bundle, args.catalog)
    else:
        require(not any((args.bundle, args.catalog)), "compile-only cannot accept observation inputs")
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
    # Check the files this invocation actually consumes, not the entire source
    # tree or JDK distribution. These hashes are internal mutation guards only.
    inputs = list(dict.fromkeys([Path(__file__).resolve(), repo / "tools/bundle_formats.py", closure_path,
                                java, jdk_release, *compiler, *runtime, *sources]))
    if selected is not None:
        inputs += [args.bundle.resolve(), args.catalog.resolve()]
    hashes = {p: sha(p) for p in inputs}
    if selected is not None:
        require(hashes[args.bundle.resolve()] == selected["bundle_sha256"]
                and hashes[args.catalog.resolve()] == selected["catalog_sha256"], "final inputs changed during preflight")
    out.mkdir()
    (out / "tmp").mkdir()
    started = time.monotonic_ns()
    report = {"schema": "plex-final-bundle-wrapper-v1", "status": "failed", "mode": args.command,
              "started_at": utcnow(), "commands": [], "actual_definition": "not_observed", "resource_execution": "not_observed",
              "scope": "Synthetic noninstallable resource checks, not APKM merge/signing/ART/Manager/Plex app acceptance"}
    env = {k: v for k, v in os.environ.items() if k.upper() not in {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"}}

    def unchanged():
        return all(p.is_file() and sha(p) == digest for p, digest in hashes.items())

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
            row["log"] = str(log)
    try:
        run("java-version", [java, "-version"])
        checker = out / "checker-tools-only.jar"
        run("compile", [java, "-Xmx1024m", "-Djava.io.tmpdir=" + str(out / "tmp"), "-cp", os.pathsep.join(map(str, compiler)),
                        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
                        "-classpath", os.pathsep.join(map(str, runtime)), "-d", checker, *sources])
        isolated_classpath([checker, *runtime])
        parent_classpath = os.pathsep.join(map(str, [checker, *runtime]))
        if args.command == "check":
            require(unchanged(), "inputs changed before child")
            run("actual-final-bundle", [java, "-Djava.io.tmpdir=" + str(out / "tmp"), "-cp", parent_classpath,
                "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", args.bundle.resolve(), args.catalog.resolve(),
                out / "native.json", out / "cases"])
            native = parse_json((out / "native.json").read_bytes())
            require(native["parent_classpath"] == parent_classpath, "native classpath differs")
            report["cases"] = validate_native(native, out, selected)
            report["native_report"] = str(out / "native.json")
            report["actual_definition"] = native["actual_definition"]; report["resource_execution"] = native["resource_execution"]
            report["status"] = SUCCESS
        else:
            report["status"] = "compile_only_no_final_bundle_observation"
    except Exception as exc:
        report["error"] = str(exc)
    finally:
        try:
            require(unchanged(), "checker inputs changed during check")
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
        # Never replace an output created by this invocation or a concurrent run.
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
    for option in ("bundle", "catalog"):
        parser.add_argument("--" + option, type=Path)
    args = parser.parse_args()
    report = execute(args)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] in {SUCCESS, "compile_only_no_final_bundle_observation"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
