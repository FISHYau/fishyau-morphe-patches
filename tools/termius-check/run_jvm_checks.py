"""Uncached, offline JVM compilation/tests from the reviewed installed cache closure.

Not a Gradle collection build, Android MPP build, Android load, or device test.
Run Python with -I -B. All generated files belong in a NEW external directory.
The reviewed collection compile/test is covered by scoped ongoing workspace approval;
--scope selects sources and is never authorization or a bypass for a new denial.
--scope termius never compiles Plex or collection inventory tests. --scope collection
includes all three definitions and Plex tests. No final-MPP execution is performed.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import time


def digest(path, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def resolve(cache, coordinate, expected=None):
    group, artifact, version = coordinate.split(":")
    matches = list((cache / group / artifact / version).glob(f"*/{artifact}-{version}.jar"))
    if len(matches) != 1:
        raise ValueError(f"Expected exactly one cached artifact: {coordinate}")
    path = matches[0].resolve(strict=True)
    if expected is not None and digest(path) != expected:
        raise ValueError(f"Pinned artifact mismatch: {coordinate}")
    # JUnit/Hamcrest are test-only installed artifacts; authenticate their cache
    # content-addressed directory too, and record SHA-256 in the resulting report.
    if expected is None and digest(path, "sha1") != path.parent.name:
        raise ValueError(f"Test artifact cache digest mismatch: {coordinate}")
    return path


TERMIUS_MAIN = (
    "termius/ServerAuditorOfflineAutomationPatch.kt", "termius/ServerAuditorPremiumPatch.kt",
    "termius/Compatibility.kt", "termius/BooleanReturn.kt", "termius/Fingerprints.kt",
    "termius/BytecodeLayout.kt", "termius/PremiumPatchValidation.kt", "termius/OfflineAutomationValidation.kt",
)
PLEX_MAIN = ("plex/PremiumUnlockPatch.kt", "plex/shared/Constants.kt", "plex/shared/HermesBytecode.kt")
PROJECTION = ("tools/LoadedBundleMetadata.kt", "tools/PatchListGenerator.kt")
TERMIUS_TESTS = ("termius/OfflineAutomationValidationTest.kt", "termius/PremiumPatchValidationTest.kt", "termius/PatchInventoryTest.kt")
PLEX_TESTS = ("plex/SyntheticHermes.kt", "plex/HermesBytecodeTest.kt", "plex/PremiumUnlockPatchTest.kt")
COLLECTION_TESTS = ("collection/CollectionInventoryTest.kt",)


def select_sources(repo, scope):
    """Pure source-policy selection. Never run a compiler/loader or infer scope from globs."""
    if scope not in ("termius", "collection"):
        raise ValueError("Explicit supported scope required")
    package = "io/github/fishyau/androidpatches"
    main_root = repo / "patches/src/main/kotlin" / package
    test_root = repo / "patches/src/test/kotlin" / package
    expected = {main_root / name for name in TERMIUS_MAIN + PLEX_MAIN + PROJECTION}
    actual = set((repo / "patches/src/main/kotlin").rglob("*.kt"))
    if actual != expected:
        raise ValueError("Main source inventory differs from the reviewed exact-three allowlist")
    expected_tests = {test_root / name for name in TERMIUS_TESTS + PLEX_TESTS + COLLECTION_TESTS}
    if set((repo / "patches/src/test/kotlin").rglob("*.kt")) != expected_tests:
        raise ValueError("Test source inventory differs from the reviewed scope allowlist")
    projection = [main_root / name for name in PROJECTION]
    main_sources = [main_root / name for name in TERMIUS_MAIN] + projection
    test_sources = [test_root / name for name in TERMIUS_TESTS]
    test_classes = ["termius.OfflineAutomationValidationTest", "termius.PremiumPatchValidationTest", "termius.PatchInventoryTest"]
    if scope == "collection":
        main_sources += [main_root / name for name in PLEX_MAIN]
        test_sources += [test_root / name for name in PLEX_TESTS + COLLECTION_TESTS]
        test_classes += ["plex.HermesBytecodeTest", "plex.PremiumUnlockPatchTest", "collection.CollectionInventoryTest"]
    tool_root = repo / "tools/termius-check/src/main/kotlin"
    tool_sources = sorted(tool_root.rglob("*.kt"))
    if set(tool_sources) != {tool_root / "InspectBundle.kt", tool_root / "RuntimeCheck.kt"}:
        raise ValueError("Checker source inventory differs from the reviewed adapter allowlist")
    return main_sources, test_sources, projection, tool_sources, ["io.github.fishyau.androidpatches." + name for name in test_classes]


def select_tool_test_sources(repo):
    """Validate both reviewed test inventories without adding native regressions to JUnit."""
    root = repo / "tools/termius-check/src/test"
    reporters = [root / "java/MeasuredJUnit.java"]
    regressions = [root / "kotlin/RuntimeSnapshotRegression.kt"]
    actual = {path for path in root.rglob("*") if not path.is_dir()}
    java = {path for path in actual if path.suffix == ".java"}
    kotlin = {path for path in actual if path.suffix == ".kt"}
    if java != set(reporters):
        raise ValueError("Reporter source differs from exact Java allowlist")
    if kotlin != set(regressions):
        raise ValueError("Native regression source differs from exact Kotlin allowlist")
    if actual != java | kotlin:
        raise ValueError("Unknown source outside reviewed Java/Kotlin test allowlists")
    return reporters, regressions


def inventory(root, paths=None):
    """Content inventory, refusing symlinks/reparse aliases, hardlinks and case aliases."""
    root = root.resolve(strict=True)
    entries = sorted(root.rglob("*") if paths is None else paths)
    result, names, identities = {}, set(), set()
    for path in entries:
        if path.is_symlink() or path.is_junction() or path.resolve(strict=True) != path.absolute():
            raise ValueError(f"Aliased inventory path: {path}")
        if path.is_dir():
            continue
        stat = path.stat()
        name = path.relative_to(root).as_posix()
        identity = (stat.st_dev, stat.st_ino)
        if not path.is_file() or stat.st_nlink != 1 or name.casefold() in names or identity in identities:
            raise ValueError(f"Nonregular/duplicate inventory file: {path}")
        names.add(name.casefold())
        identities.add(identity)
        result[name] = {"size": stat.st_size, "sha256": digest(path)}
    return result


def source_tree(repo):
    roots = (repo / "patches/src", repo / "tools/termius-check/src")
    paths = [p for root in roots for p in root.rglob("*")]
    paths += [repo / "tools/termius-check/run_jvm_checks.py",
              repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"]
    return inventory(repo, paths)


def required_cases(repo, classes):
    """Exact current source @Test methods plus reviewed parameter expansion, not stdout."""
    expected_methods = {"OfflineAutomationValidationTest": 13, "PremiumPatchValidationTest": 27,
                        "PatchInventoryTest": 9, "HermesBytecodeTest": 18,
                        "PremiumUnlockPatchTest": 17, "CollectionInventoryTest": 11}
    rows = []
    for cls in classes:
        path = repo / "patches/src/test/kotlin" / (cls.replace(".", "/") + ".kt")
        methods = re.findall(r"@Test\s+fun\s+([A-Za-z][A-Za-z0-9_]*)\s*\(", path.read_text(encoding="utf-8"))
        if len(methods) != expected_methods[cls.rsplit(".", 1)[-1]] or len(set(methods)) != len(methods):
            raise ValueError(f"Required source-test methods changed: {cls}")
        for method in methods:
            names = ([method + f"[{target}]" for target in ("snippet widget", "SSH Automation", "terminal Automation")]
                     if cls.endswith(".OfflineAutomationValidationTest") else [method])
            rows += [(cls, name, f"{name}({cls})") for name in names]
    return rows


def validate_junit(report, classes, required):
    if (report.get("schema") != "source-junit-measurements-v1" or report.get("status") != "source_tests_passed"
            or report.get("requested_classes") != classes or report.get("unscoped_failures") != []
            or report.get("incomplete_count") != 0):
        raise ValueError("Incomplete/failed source JUnit measurements")
    def identity(row):
        return tuple(row[key] for key in ("class_name", "method_name", "display_name"))
    planned, cases = report["planned_cases"], report["cases"]
    if (Counter(map(identity, planned)) != Counter(required) or Counter(map(identity, cases)) != Counter(required)
            or len(set(required)) != len(required)):
        raise ValueError("Missing/extra/duplicate required JUnit classes or cases")
    def timing(row, key):
        start = datetime.fromisoformat(row["started_at"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(row["ended_at"].replace("Z", "+00:00"))
        if start.tzinfo is None or end.tzinfo is None or end < start or type(row[key]) is not int or row[key] < 0:
            raise ValueError("Invalid measured JUnit timing")
    timing(report, "duration_ns")
    for row in cases:
        timing(row, "duration_ns")
        if row["outcome"] != "passed" or row["failures"] != [] or row["assumptions"] != []:
            raise ValueError("JUnit skip/assumption/failure is not successful execution")
    if report["totals"] != {"run_count": len(required), "failure_count": 0, "ignore_count": 0, "assumption_failure_count": 0}:
        raise ValueError("JUnit totals disagree with complete measured execution")
    return len(cases)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scope", choices=("termius", "collection"), required=True,
                        help="Required; collection includes Plex compilation/initialization/tests; selection is not approval")
    parser.add_argument("--jdk", type=Path, required=True)
    parser.add_argument("--cache-root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    output = args.out.resolve()
    if output == repo or repo in output.parents or output.exists() or not output.parent.is_dir():
        raise ValueError("NEW external output with existing parent required")
    # Reserve once: every later failure retains a failed/partial report in this NEW tree.
    output.mkdir()
    (output / "tmp").mkdir()
    started = time.perf_counter_ns()
    logs = []
    result = {"schema": "scoped-jvm-checks-v3", "status": "failed", "scope": args.scope,
              "source_root": str(repo), "output_root": str(output),
              "inventory_policy": "All regular files; SHA-256 and byte size; aliases/hardlinks rejected; output excludes this report only",
              "started_at": datetime.now(timezone.utc).isoformat(), "steps": logs,
              "limitations": ["Uncached source JVM compilation/tests only; not Gradle, Android MPP, final-MPP parser execution, Manager or ART",
                              "Hash/source/tool consistency is not authentication; protected independent review remains required",
                              "JUnit/Hamcrest use installed content-addressed test jars, not the runtime closure"]}
    env = dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)
    retained = {}

    def retain(paths):
        observed = inventory(output, paths)
        if any(name in retained and retained[name] != row for name, row in observed.items()):
            raise RuntimeError("Previously retained output mutated")
        retained.update(observed)

    def run(name, command, products=()):
        row = {"step": name, "started_at": datetime.now(timezone.utc).isoformat()}
        tick = time.perf_counter_ns()
        logs.append(row)
        path = output / (name + ".log")
        try:
            completed = subprocess.run([str(x) for x in command], cwd=output, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
            path.write_bytes(completed.stdout)
            row["exit_code"] = completed.returncode
            retain([path])
            row["log"] = {"path": str(path), **retained[path.name]}
            if completed.returncode:
                raise RuntimeError(f"{name} failed with exit {completed.returncode}; retained log: {path}")
            retain(list(products) + list((output / "tmp").rglob("*")))
        except subprocess.TimeoutExpired as failure:
            path.write_bytes(failure.stdout or b"")
            row["timed_out"] = True
            retain([path])
            raise
        finally:
            row["ended_at"] = datetime.now(timezone.utc).isoformat()
            row["duration_ns"] = time.perf_counter_ns() - tick

    try:
        jdk = args.jdk.resolve(strict=True)
        java = jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
        javac = jdk / "bin" / ("javac.exe" if os.name == "nt" else "javac")
        if not java.is_file() or not javac.is_file():
            raise ValueError("Explicit installed JDK with javac required")
        closure_path = repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        if (closure["patcher_version"], closure["compiler_version"]) != ("2.3.0", "2.4.21"):
            raise ValueError("Unexpected closure versions")
        cache = args.cache_root.resolve(strict=True)
        compiler = [resolve(cache, *item) for item in closure["compiler"]]
        runtime = [resolve(cache, *item) for item in closure["runtime"]]
        tests = [resolve(cache, item) for item in ("junit:junit:4.13.2", "org.hamcrest:hamcrest-core:1.3")]
        main_sources, test_sources, projection, tool_sources, test_classes = select_sources(repo, args.scope)
        reporters, _ = select_tool_test_sources(repo)
        # Native snapshot regressions are measured by source_tree, not compiled
        # into collection JUnit or the tools-only production checker.
        reporter, = reporters
        excluded = sorted(set((repo / "patches/src/main/kotlin").rglob("*.kt")) - set(main_sources))
        all_sources = list(dict.fromkeys(main_sources + test_sources + tool_sources + [reporter, Path(__file__).resolve()]))
        source_hashes = {p.relative_to(repo).as_posix(): digest(p) for p in all_sources}
        before_source = source_tree(repo)
        if any(before_source[name]["sha256"] != value for name, value in source_hashes.items()):
            raise RuntimeError("Selected source hashes disagree with complete source snapshot")
        before_jdk = inventory(jdk)
        before_deps = inventory(cache, list(dict.fromkeys(compiler + runtime + tests)))
        # Recheck the exact pins against the just-recorded dependency snapshot too.
        for path, (_, expected) in zip(compiler + runtime, closure["compiler"] + closure["runtime"]):
            if before_deps[path.relative_to(cache).as_posix()]["sha256"] != expected:
                raise RuntimeError("Dependency inventory disagrees with pinned closure")
        for path in tests:
            if digest(path, "sha1") != path.parent.name:
                raise RuntimeError("Test dependency changed during inventory")
        required = required_cases(repo, test_classes)
        result.update({"source_hashes": source_hashes, "source_tree_before": before_source,
                       "definition_count": 2 if args.scope == "termius" else 3, "test_classes": test_classes,
                       "source_scope": ("Termius definitions/tests and shared metadata tools only; not whole collection"
                                        if args.scope == "termius" else "Exact three collection definitions; Termius, Plex and collection inventory tests"),
                       "excluded_main_sources": [p.relative_to(repo).as_posix() for p in excluded],
                       "closure_sha256": digest(closure_path), "java_sha256": digest(java),
                       "test_artifacts": {str(p): digest(p) for p in tests},
                       "tool_inventory": {"jdk_root": str(jdk), "jdk_before": before_jdk, "dependency_root": str(cache),
                                          "dependencies_before": before_deps,
                                          "compiler_classpath": list(map(str, compiler)), "runtime_classpath": list(map(str, runtime)),
                                          "test_classpath": list(map(str, tests))}})

        def compile_kotlin(name, sources, target, dependencies, extra=()):
            # No incremental compiler, daemon, Gradle resolution, or compilation cache.
            run(name, [java, "-Xmx2g", "-Djava.io.tmpdir=" + str(output / "tmp"), "-cp", os.pathsep.join(map(str, compiler)),
                       "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
                       "-classpath", os.pathsep.join(map(str, dependencies)), *extra, "-d", target, *sources], [target])

        bundle, test_jar, tool = (output / name for name in ("definitions-JVM-ONLY.jar", "tests.jar", "checker.jar"))
        reporter_classes = output / "junit-reporter"
        reporter_classes.mkdir()
        compile_kotlin("compile-definitions", main_sources, bundle, runtime)
        compile_kotlin("compile-tests", test_sources, test_jar, runtime + tests + [bundle], ["-Xfriend-paths=" + str(bundle)])
        run("compile-junit-reporter", [javac, "-J-Djava.io.tmpdir=" + str(output / "tmp"), "-proc:none", "--release", "17",
                                      "-classpath", os.pathsep.join(map(str, runtime + tests)), "-d", reporter_classes, reporter])
        retain(list(reporter_classes.rglob("*")))
        measured = output / "junit-measurements.json"
        run("junit", [java, "-Djava.io.tmpdir=" + str(output / "tmp"), "-cp",
                      os.pathsep.join(map(str, runtime + tests + [bundle, test_jar, reporter_classes])), "MeasuredJUnit",
                      measured, *test_classes], [measured])
        junit = json.loads(measured.read_text(encoding="utf-8"))
        result["junit"] = junit
        result["executed_cases"] = validate_junit(junit, test_classes, required)
        # Tools contain projection classes ONLY, not source definitions or reporter.
        compile_kotlin("compile-checker", tool_sources + projection, tool, runtime)
        result["source_tree_after"] = source_tree(repo)
        result["tool_inventory"]["jdk_after"] = inventory(jdk)
        result["tool_inventory"]["dependencies_after"] = inventory(cache, list(dict.fromkeys(compiler + runtime + tests)))
        if (before_source != result["source_tree_after"] or before_jdk != result["tool_inventory"]["jdk_after"]
                or before_deps != result["tool_inventory"]["dependencies_after"]):
            raise RuntimeError("Source tree or installed tool/compiler/runtime/test payload changed during execution")
        observed = inventory(output)
        # Source tests intentionally retain private tmp fixtures. Inventory them at
        # their producing step too; late mutations/extra files cannot hide in a final hash.
        if observed != retained:
            raise RuntimeError("Output inventory changed, unretained files or persistent temporary output")
        result["output_inventory"] = observed
        result["outputs"] = {p.name: digest(p) for p in (bundle, test_jar, tool)}
        result["checker_runtime_classpath"] = os.pathsep.join(map(str, [tool] + runtime))
        result["status"] = args.scope + "_uncached_jvm_compilation_tests_passed"
    except BaseException as failure:
        result["error"] = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        result["ended_at"] = datetime.now(timezone.utc).isoformat()
        result["duration_ns"] = time.perf_counter_ns() - started
        if result["status"] == "failed":
            try:
                result["partial_output_inventory_unverified"] = inventory(output)
            except (OSError, ValueError) as failure:
                result["partial_inventory_error"] = str(failure)
        # The report itself is intentionally excluded from its nonrecursive inventory.
        with (output / "jvm-checks.json").open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
