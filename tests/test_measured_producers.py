"""Local JVM runner regressions. Every subprocess is mocked; no build is executed."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tools/termius-check/run_jvm_checks.py"
spec = importlib.util.spec_from_file_location("local_jvm_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class LocalCheckTests(unittest.TestCase):
    def runner_fixture(self, root):
        """Real source paths, but synthetic NONEXECUTABLE dependency/tool bytes."""
        repo = root / "repo"
        for relative in ("patches/src", "tools/termius-check/src"):
            shutil.copytree(REPO / relative, repo / relative)
        shutil.copyfile(RUNNER, repo / "tools/termius-check/run_jvm_checks.py")
        cache = root / "cache"
        pins = {"patcher_version": "2.3.0", "compiler_version": "2.4.21"}
        for kind, coordinate in (("compiler", "synthetic:compiler:1"), ("runtime", "synthetic:runtime:1"),
                                 (None, "junit:junit:4.13.2"), (None, "org.hamcrest:hamcrest-core:1.3")):
            data = ("SYNTHETIC NON-JAR; NEVER EXECUTE " + coordinate).encode()
            group, artifact, version = coordinate.split(":")
            path = cache / group / artifact / version / hashlib.sha1(data).hexdigest() / f"{artifact}-{version}.jar"
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            if kind:
                pins[kind] = [[coordinate, hashlib.sha256(data).hexdigest()]]
        pin_path = repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        pin_path.parent.mkdir(parents=True)
        pin_path.write_text(json.dumps(pins), encoding="utf-8")
        jdk = root / "jdk"
        (jdk / "bin").mkdir(parents=True)
        (jdk / "bin" / ("java.exe" if os.name == "nt" else "java")).write_bytes(b"NOT A JDK; NEVER EXECUTE")
        return repo, jdk, cache

    def invoke_runner(self, repo, jdk, cache, output, scope="collection"):
        argv = [str(repo / "tools/termius-check/run_jvm_checks.py"), "--scope", scope,
                "--jdk", str(jdk), "--cache-root", str(cache), "--out", str(output)]
        with mock.patch.object(runner, "__file__", argv[0]), mock.patch.object(sys, "argv", argv):
            runner.main()

    @staticmethod
    def compiler_boundary(argv, **kwargs):
        # No call escapes this mock, and these bytes cannot be loaded as JVM code.
        if "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler" in argv:
            Path(argv[argv.index("-d") + 1]).write_bytes(b"SYNTHETIC NON-JAR; MOCKED COMPILER")
        return SimpleNamespace(returncode=0, stdout=b"MOCK ONLY; NOT EXECUTION EVIDENCE")

    def test_compilation_junit_and_isolated_checker_in_both_scopes(self):
        for scope in ("termius", "collection"):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()
                repo, jdk, cache = self.runner_fixture(root)
                output = root / "output"
                main, tests, projection, tools, classes = runner.select_sources(repo, scope)
                with mock.patch.object(runner.subprocess, "run", side_effect=self.compiler_boundary) as child, \
                     mock.patch("builtins.print"), \
                     mock.patch.dict(os.environ, {name: "must-not-reach-java" for name in
                                                  ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH")}):
                    self.invoke_runner(repo, jdk, cache, output, scope)
                calls = child.call_args_list
                self.assertEqual(4, len(calls))
                compiled = [call.args[0] for call in calls if "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler" in call.args[0]]
                self.assertEqual([list(map(str, sources)) for sources in (main, tests, tools + projection)],
                                 [argv[argv.index("-d") + 2:] for argv in compiled])
                self.assertIn("-Xfriend-paths=" + str(output / "definitions-JVM-ONLY.jar"), compiled[1])
                junit = calls[2].args[0]
                self.assertEqual(classes, junit[junit.index("org.junit.runner.JUnitCore") + 1:])
                for call in calls:
                    self.assertEqual(output, call.kwargs["cwd"])
                    self.assertEqual(300, call.kwargs["timeout"])
                    for name in ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"):
                        self.assertNotIn(name, call.kwargs["env"])
                report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
                self.assertEqual(scope + "_uncached_jvm_compilation_tests_passed", report["status"])
                self.assertEqual(["compile-definitions", "compile-tests", "junit", "compile-checker"],
                                 [row["step"] for row in report["steps"]])
                classpath = report["checker_runtime_classpath"].split(os.pathsep)
                self.assertEqual(str(output / "checker.jar"), classpath[0])
                self.assertNotIn(str(output / "definitions-JVM-ONLY.jar"), classpath)
                self.assertNotIn(str(output / "tests.jar"), classpath)
                for row in report["steps"]:
                    self.assertEqual(0, row["exit_code"])
                    self.assertTrue(Path(row["log"]).is_file())

    def test_failed_steps_stop_and_retain_diagnostics(self):
        for fail_index, name in enumerate(("compile-definitions", "compile-tests", "junit", "compile-checker")):
            with self.subTest(step=name), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()
                repo, jdk, cache = self.runner_fixture(root)
                output = root / "output"
                calls = []

                def boundary(argv, **kwargs):
                    calls.append(argv)
                    if len(calls) - 1 == fail_index:
                        return SimpleNamespace(returncode=7, stdout=b"synthetic failure diagnostic")
                    return self.compiler_boundary(argv, **kwargs)

                with mock.patch.object(runner.subprocess, "run", side_effect=boundary):
                    with self.assertRaisesRegex(RuntimeError, name + " failed with exit 7"):
                        self.invoke_runner(repo, jdk, cache, output)
                self.assertEqual(fail_index + 1, len(calls))
                report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
                self.assertEqual("failed", report["status"])
                self.assertEqual(7, report["steps"][-1]["exit_code"])
                self.assertEqual(b"synthetic failure diagnostic", (output / (name + ".log")).read_bytes())

    def test_success_exit_without_compiler_output_is_not_success(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            repo, jdk, cache = self.runner_fixture(root)
            output = root / "output"
            with mock.patch.object(runner.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b"no output")) as child:
                with self.assertRaisesRegex(RuntimeError, "did not produce its requested JAR"):
                    self.invoke_runner(repo, jdk, cache, output)
            child.assert_called_once()
            report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", report["status"])

    def test_timeout_retains_partial_log_and_raises(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            repo, jdk, cache = self.runner_fixture(root)
            output = root / "output"
            with mock.patch.object(runner.subprocess, "run", side_effect=subprocess.TimeoutExpired("java", 300, output=b"partial")) as child:
                with self.assertRaises(subprocess.TimeoutExpired):
                    self.invoke_runner(repo, jdk, cache, output)
            child.assert_called_once()
            report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
            self.assertEqual("failed", report["status"])
            self.assertTrue(report["steps"][0]["timed_out"])
            self.assertEqual(b"partial", (output / "compile-definitions.log").read_bytes())

    def test_only_new_external_outputs_with_existing_parent_are_allowed(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            repo, jdk, cache = self.runner_fixture(root)
            existing = root / "existing"
            existing.mkdir()
            (existing / "keep").write_text("preserve", encoding="utf-8")
            with mock.patch.object(runner.subprocess, "run") as child:
                for output in (repo, repo / "new", existing, root / "missing" / "output"):
                    with self.subTest(output=output), self.assertRaisesRegex(ValueError, "NEW external output"):
                        self.invoke_runner(repo, jdk, cache, output)
            child.assert_not_called()
            self.assertEqual("preserve", (existing / "keep").read_text(encoding="utf-8"))
            self.assertFalse((repo / "new").exists())

    def test_pinned_dependency_tampering_stops_before_compilation(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            repo, jdk, cache = self.runner_fixture(root)
            next(cache.rglob("compiler-1.jar")).write_bytes(b"tampered")
            output = root / "output"
            with mock.patch.object(runner.subprocess, "run") as child:
                with self.assertRaisesRegex(ValueError, "Pinned artifact mismatch"):
                    self.invoke_runner(repo, jdk, cache, output)
            child.assert_not_called()
            self.assertEqual("failed", json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))["status"])

    def test_dependency_resolution_rejects_missing_ambiguous_and_bad_test_artifacts(self):
        with tempfile.TemporaryDirectory() as scratch:
            cache = Path(scratch)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                runner.resolve(cache, "test:artifact:1")
            path = cache / "test/artifact/1/not-a-content-digest/artifact-1.jar"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"SYNTHETIC")
            with self.assertRaisesRegex(ValueError, "cache digest mismatch"):
                runner.resolve(cache, "test:artifact:1")
            other = path.parent.parent / "other/artifact-1.jar"
            other.parent.mkdir()
            other.write_bytes(b"OTHER SYNTHETIC")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                runner.resolve(cache, "test:artifact:1")

    def test_structural_checks_keep_selections_negative_shapes_and_reread_assertions(self):
        # Static wiring only: real native execution remains a separate local check.
        text = (REPO / "tools/termius-check/src/main/kotlin/RuntimeCheck.kt").read_text(encoding="utf-8")
        for fragment in ("requireIsolatedDefinitionLoader()", "loadPatchesFromJar(setOf(bundle))",
                         "requireCollectionInventory(loaded)", "verifyOffline(compared)", "verifyPremium(compared)",
                         "check(before == after)", "Files.isSameFile", "StandardOpenOption.CREATE_NEW",
                         "readEmitted(emitDex(combined", "throw failure"):
            self.assertIn(fragment, text)
        for name in ("widget-only", "ssh-only", "terminal-only", "wrong-widget-helper", "wrong-result-register",
                     "wrong-branch-target", "global-pro-override", "premium-repeat"):
            self.assertIn('"' + name + '"', text)
        self.assertIn("assertRejected(repeatedApk", text)
        self.assertIn("assertRejected(repeatedPremium", text)
        self.assertIn("assertRejected(apk, directory, fixture.diagnostic, fixture.already)", text)
        self.assertIn("suffix == before", text)


if __name__ == "__main__":
    unittest.main()
