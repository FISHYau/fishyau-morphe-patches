"""Offline JVM compilation and JUnit checks using explicitly selected installed tools.

Not a Gradle collection build, Android MPP build, Android load, or device test.
Run Python with -I -B. All generated files belong in a NEW external directory.
--scope termius compiles Termius definitions/tests and the metadata adapter;
--scope collection includes all three definitions and Plex tests. Source selection
is not execution approval and never overrides a new tool-enforced denial.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


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
    # JUnit/Hamcrest are test-only installed artifacts, not runtime dependencies.
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
    output.mkdir()
    (output / "tmp").mkdir()
    result = {"status": "failed", "scope": args.scope, "steps": [],
              "limitations": "Source JVM checks only; not Android MPP, Manager, ART or device execution"}
    env = dict(os.environ)
    for key in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"):
        env.pop(key, None)

    def run(name, command):
        path = output / (name + ".log")
        row = {"step": name, "log": str(path)}
        result["steps"].append(row)
        try:
            completed = subprocess.run([str(x) for x in command], cwd=output, env=env,
                                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=300, check=False)
            path.write_bytes(completed.stdout)
            row["exit_code"] = completed.returncode
            if completed.returncode:
                raise RuntimeError(f"{name} failed with exit {completed.returncode}; retained log: {path}")
        except subprocess.TimeoutExpired as failure:
            path.write_bytes(failure.stdout or b"")
            row["timed_out"] = True
            raise

    try:
        jdk = args.jdk.resolve(strict=True)
        java = jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
        if not java.is_file():
            raise ValueError("Explicit installed JDK required")
        closure_path = repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
        if (closure["patcher_version"], closure["compiler_version"]) != ("2.3.0", "2.4.21"):
            raise ValueError("Unexpected pinned dependency versions")
        cache = args.cache_root.resolve(strict=True)
        compiler = [resolve(cache, *item) for item in closure["compiler"]]
        runtime = [resolve(cache, *item) for item in closure["runtime"]]
        tests = [resolve(cache, item) for item in ("junit:junit:4.13.2", "org.hamcrest:hamcrest-core:1.3")]
        main_sources, test_sources, projection, tool_sources, test_classes = select_sources(repo, args.scope)
        result["test_classes"] = test_classes

        def compile_kotlin(name, sources, target, dependencies, extra=()):
            # No incremental compiler, daemon, Gradle resolution, or compilation cache.
            run(name, [java, "-Xmx2g", "-Djava.io.tmpdir=" + str(output / "tmp"), "-cp", os.pathsep.join(map(str, compiler)),
                       "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17",
                       "-classpath", os.pathsep.join(map(str, dependencies)), *extra, "-d", target, *sources])
            if not target.is_file():
                raise RuntimeError(f"{name} did not produce its requested JAR: {target}")

        bundle, test_jar, tool = (output / name for name in ("definitions-JVM-ONLY.jar", "tests.jar", "checker.jar"))
        compile_kotlin("compile-definitions", main_sources, bundle, runtime)
        compile_kotlin("compile-tests", test_sources, test_jar, runtime + tests + [bundle], ["-Xfriend-paths=" + str(bundle)])
        run("junit", [java, "-Djava.io.tmpdir=" + str(output / "tmp"), "-cp",
                      os.pathsep.join(map(str, runtime + tests + [bundle, test_jar])), "org.junit.runner.JUnitCore", *test_classes])
        # Keep definitions off the checker parent classpath: actual bundles must load in isolation.
        compile_kotlin("compile-checker", tool_sources + projection, tool, runtime)
        result["outputs"] = {"definitions": str(bundle), "tests": str(test_jar), "checker": str(tool)}
        result["checker_runtime_classpath"] = os.pathsep.join(map(str, [tool] + runtime))
        result["status"] = args.scope + "_uncached_jvm_compilation_tests_passed"
    except BaseException as failure:
        result["error"] = f"{type(failure).__name__}: {failure}"
        raise
    finally:
        # Ordinary diagnostic summary, not a release receipt or an execution-count gate.
        with (output / "jvm-checks.json").open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
