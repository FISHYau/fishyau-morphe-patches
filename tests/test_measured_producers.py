"""Focused offline producer tests. Synthetic reports/files are NOT execution evidence."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tools/termius-check/run_jvm_checks.py"
spec = importlib.util.spec_from_file_location("measured_runner", RUNNER)
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class MeasuredProducerTests(unittest.TestCase):
    def setUp(self):
        self.classes = runner.select_sources(REPO, "collection")[-1]
        self.required = runner.required_cases(REPO, self.classes)
        identity = lambda row: dict(zip(("class_name", "method_name", "display_name"), row))
        self.report = {
            "schema": "source-junit-measurements-v1", "status": "source_tests_passed",
            "requested_classes": self.classes, "unscoped_failures": [], "incomplete_count": 0,
            "started_at": "2026-11-09T12:00:00Z", "ended_at": "2026-11-09T12:00:01Z", "duration_ns": 1000000000,
            "planned_cases": [identity(row) for row in self.required],
            "cases": [{**identity(row), "started_at": "2026-11-09T12:00:00Z", "ended_at": "2026-11-09T12:00:01Z",
                       "duration_ns": 1, "outcome": "passed", "failures": [], "assumptions": []} for row in self.required],
            "totals": {"run_count": 121, "failure_count": 0, "ignore_count": 0, "assumption_failure_count": 0},
        }

    def reject(self, report):
        with self.assertRaises((ValueError, KeyError, TypeError)):
            runner.validate_junit(report, self.classes, self.required)

    def test_exact_source_cases_and_methods(self):
        self.assertEqual(121, len(self.required))
        methods = {(c, m.split("[")[0]) for c, m, _ in self.required}
        self.assertEqual(95, len(methods))
        offline = [m for c, m, _ in self.required if c.endswith(".OfflineAutomationValidationTest")]
        self.assertEqual({"snippet widget", "SSH Automation", "terminal Automation"}, {m.split("[")[1][:-1] for m in offline})
        self.assertEqual(121, runner.validate_junit(self.report, self.classes, self.required))

    def test_explicit_termius_scope(self):
        classes = runner.select_sources(REPO, "termius")[-1]
        cases = runner.required_cases(REPO, classes)
        self.assertEqual(75, len(cases))
        self.assertTrue(all(".termius." in row[0] for row in cases))

    def test_old_aggregate_not_measured(self):
        self.reject({"status": "collection_uncached_jvm_compilation_tests_passed", "tests": 121})

    def test_missing_extra_or_duplicate_cases(self):
        for field in ("planned_cases", "cases"):
            for operation in ("missing", "extra", "duplicate"):
                with self.subTest(field=field, operation=operation):
                    report = copy.deepcopy(self.report)
                    if operation == "missing": report[field].pop()
                    elif operation == "extra": report[field].append(copy.deepcopy(report[field][0]))
                    else: report[field][-1] = copy.deepcopy(report[field][0])
                    self.reject(report)

    def test_missing_or_substituted_class(self):
        for field in ("requested_classes", "planned_cases", "cases"):
            report = copy.deepcopy(self.report)
            if field == "requested_classes": report[field] = self.classes[:-1]
            else: report[field][0]["class_name"] = "finalMPP.ParserTest"
            self.reject(report)

    def test_ignores_assumptions_failures_incomplete(self):
        for outcome in ("ignored", "assumption_failed", "failed", "incomplete"):
            report = copy.deepcopy(self.report)
            report["cases"][0]["outcome"] = outcome
            self.reject(report)
        for field in ("failures", "assumptions"):
            report = copy.deepcopy(self.report)
            report["cases"][0][field] = [{"message": "synthetic unit-test diagnostic"}]
            self.reject(report)
        for field, value in (("incomplete_count", 1), ("unscoped_failures", [{}]), ("status", "failed")):
            report = copy.deepcopy(self.report)
            report[field] = value
            self.reject(report)

    def test_totals_not_a_substitute_for_execution(self):
        for field in self.report["totals"]:
            report = copy.deepcopy(self.report)
            report["totals"][field] += 1
            self.reject(report)

    def test_invalid_timing(self):
        for field, value in (("duration_ns", -1), ("duration_ns", True),
                             ("ended_at", "2026-11-08T00:00:00Z"), ("started_at", "2026-11-09T00:00:00")):
            for target in ("case", "run"):
                with self.subTest(field=field, target=target):
                    report = copy.deepcopy(self.report)
                    row = report["cases"][0] if target == "case" else report
                    row[field] = value
                    self.reject(report)

    def test_inventory_records_bytes_and_detects_changes(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            target = root / "runtime-payload"
            target.write_bytes(b"first")
            before = runner.inventory(root)
            self.assertEqual(5, before[target.name]["size"])
            self.assertEqual(runner.digest(target), before[target.name]["sha256"])
            target.write_bytes(b"other")
            self.assertNotEqual(before, runner.inventory(root))
            before = runner.inventory(root)
            (root / "unexpected").write_bytes(b"extra")
            self.assertNotEqual(before, runner.inventory(root))

    def test_inventory_refuses_hardlinks(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            (root / "payload").write_bytes(b"x")
            os.link(root / "payload", root / "alias")
            with self.assertRaises(ValueError): runner.inventory(root)

    def test_inventory_refuses_duplicate_paths(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            target = root / "payload"
            target.write_bytes(b"x")
            with self.assertRaises(ValueError): runner.inventory(root, [target, target])

    def test_source_tree_covers_excluded_sources_reporter_and_closure(self):
        measured = runner.source_tree(REPO)
        for name in ("tools/termius-check/src/test/java/MeasuredJUnit.java",
                     "tools/termius-check/src/test/kotlin/RuntimeSnapshotRegression.kt",
                     "tools/termius-check/run_jvm_checks.py",
                     "patches/src/main/kotlin/io/github/fishyau/androidpatches/plex/PremiumUnlockPatch.kt",
                     ".claude/skills/run-android-morphe/templates/cache-closure.json"):
            self.assertIn(name, measured)

    def test_exact_current_tool_test_inventories(self):
        reporters, regressions = runner.select_tool_test_sources(REPO)
        self.assertEqual([REPO / "tools/termius-check/src/test/java/MeasuredJUnit.java"], reporters)
        self.assertEqual([REPO / "tools/termius-check/src/test/kotlin/RuntimeSnapshotRegression.kt"], regressions)
        measured = runner.source_tree(REPO)
        for path in reporters + regressions:
            self.assertEqual(runner.digest(path), measured[path.relative_to(REPO).as_posix()]["sha256"])

    def runner_fixture(self, root):
        """Current reviewed sources, synthetic dependencies/JDK; NEVER executable."""
        repo = root / "repo"
        for relative in ("patches/src", "tools/termius-check/src"):
            shutil.copytree(REPO / relative, repo / relative)
        shutil.copyfile(RUNNER, repo / "tools/termius-check/run_jvm_checks.py")
        cache = root / "cache"
        closure = {"patcher_version": "2.3.0", "compiler_version": "2.4.21"}
        for kind, coordinate in (("compiler", "synthetic:compiler:1"), ("runtime", "synthetic:runtime:1"),
                                 (None, "junit:junit:4.13.2"), (None, "org.hamcrest:hamcrest-core:1.3")):
            data = ("SYNTHETIC NON-JAR; NEVER EXECUTE " + coordinate).encode()
            group, artifact, version = coordinate.split(":")
            path = cache / group / artifact / version / hashlib.sha1(data).hexdigest() / f"{artifact}-{version}.jar"
            path.parent.mkdir(parents=True)
            path.write_bytes(data)
            if kind:
                closure[kind] = [[coordinate, hashlib.sha256(data).hexdigest()]]
        closure_path = repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        closure_path.parent.mkdir(parents=True)
        closure_path.write_text(json.dumps(closure), encoding="utf-8")
        jdk = root / "jdk"
        (jdk / "bin").mkdir(parents=True)
        for name in ("java", "javac"):
            (jdk / "bin" / (name + (".exe" if os.name == "nt" else ""))).write_bytes(b"NOT A JDK; NEVER EXECUTE")
        return repo, jdk, cache

    def invoke_runner(self, repo, jdk, cache, output, scope):
        argv = [str(repo / "tools/termius-check/run_jvm_checks.py"), "--scope", scope,
                "--jdk", str(jdk), "--cache-root", str(cache), "--out", str(output)]
        with mock.patch.object(runner, "__file__", argv[0]), mock.patch.object(sys, "argv", argv):
            runner.main()

    def test_main_accepts_current_sources_with_mocked_compilers_and_separate_native_regression(self):
        for scope, count in (("termius", 75), ("collection", 121)):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as scratch:
                root = Path(scratch).resolve()
                repo, jdk, cache = self.runner_fixture(root)
                output = root / "output"
                main, tests, projection, tools, classes = runner.select_sources(repo, scope)
                junit = copy.deepcopy(self.report)
                junit["requested_classes"] = classes
                for field in ("planned_cases", "cases"):
                    junit[field] = [row for row in junit[field] if row["class_name"] in classes]
                junit["totals"]["run_count"] = count
                commands = []

                def compiler_boundary(argv, **kwargs):
                    # All subprocess calls end here; generated bytes cannot be executed.
                    self.assertEqual(output, kwargs["cwd"])
                    commands.append(argv)
                    if "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler" in argv:
                        index = argv.index("-d")
                        Path(argv[index + 1]).write_bytes(b"SYNTHETIC NON-JAR; MOCKED COMPILER")
                    elif "-proc:none" in argv:
                        (Path(argv[argv.index("-d") + 1]) / "MeasuredJUnit.class").write_bytes(b"SYNTHETIC NON-CLASS")
                    else:
                        self.assertIn("MeasuredJUnit", argv)
                        Path(argv[argv.index("MeasuredJUnit") + 1]).write_text(json.dumps(junit), encoding="utf-8")
                    return SimpleNamespace(returncode=0, stdout=b"MOCK ONLY; NO JVM EXECUTION")

                with mock.patch.object(runner, "select_tool_test_sources", wraps=runner.select_tool_test_sources) as preflight, \
                     mock.patch.object(runner.subprocess, "run", side_effect=compiler_boundary) as child, \
                     mock.patch("builtins.print"):
                    self.invoke_runner(repo, jdk, cache, output, scope)
                preflight.assert_called_once_with(repo)
                self.assertEqual(5, child.call_count)
                self.assertEqual([list(map(str, sources)) for sources in (main, tests, tools + projection)],
                                 [argv[argv.index("-d") + 2:] for argv in commands if "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler" in argv])
                reporter = repo / "tools/termius-check/src/test/java/MeasuredJUnit.java"
                self.assertEqual(str(reporter), commands[2][-1])
                self.assertEqual(classes, commands[3][commands[3].index("MeasuredJUnit") + 2:])
                self.assertFalse(any("RuntimeSnapshotRegression" in arg for argv in commands for arg in argv))
                report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
                self.assertEqual(scope + "_uncached_jvm_compilation_tests_passed", report["status"])
                self.assertEqual(count, report["executed_cases"])
                regression = "tools/termius-check/src/test/kotlin/RuntimeSnapshotRegression.kt"
                for field in ("source_tree_before", "source_tree_after"):
                    self.assertIn(regression, report[field])
                    self.assertIn(reporter.relative_to(repo).as_posix(), report[field])
                # Selected compilation hashes keep their existing contract; the complete
                # source inventory separately covers the native regression.
                self.assertNotIn(regression, report["source_hashes"])
                self.assertEqual(report["source_tree_before"], report["source_tree_after"])

    def test_main_rejects_missing_extra_moved_wrong_language_and_unknown_tool_tests(self):
        java = "java/MeasuredJUnit.java"
        kotlin = "kotlin/RuntimeSnapshotRegression.kt"
        mutations = [
            ("missing-java", java, None), ("missing-kotlin", kotlin, None),
            ("extra-java", None, "java/Extra.java"), ("extra-kotlin", None, "kotlin/Extra.kt"),
            ("nested-extra-java", None, "java/nested/MeasuredJUnit.java"),
            ("nested-extra-kotlin", None, "kotlin/nested/RuntimeSnapshotRegression.kt"),
            ("root-java", java, "MeasuredJUnit.java"), ("root-kotlin", kotlin, "RuntimeSnapshotRegression.kt"),
            ("nested-moved-java", java, "java/nested/MeasuredJUnit.java"),
            ("nested-moved-kotlin", kotlin, "kotlin/nested/RuntimeSnapshotRegression.kt"),
            ("java-in-kotlin", java, "kotlin/MeasuredJUnit.java"),
            ("kotlin-in-java", kotlin, "java/RuntimeSnapshotRegression.kt"),
            ("java-renamed-kotlin", java, "java/MeasuredJUnit.kt"),
            ("kotlin-renamed-java", kotlin, "kotlin/RuntimeSnapshotRegression.java"),
            ("unknown-extension", None, "unknown.py"), ("extensionless", None, "unknown"),
            ("java-backup", None, "java/MeasuredJUnit.java.bak"),
            ("kotlin-script", None, "kotlin/Extra.kts"),
            ("java-at-wrong-root", None, "other/Extra.java"),
            ("kotlin-at-wrong-root", None, "other/Extra.kt"),
        ]
        for label, remove, add in mutations:
            for scope in ("termius", "collection"):
                with self.subTest(mutation=label, scope=scope), tempfile.TemporaryDirectory() as scratch:
                    root = Path(scratch).resolve()
                    repo, jdk, cache = self.runner_fixture(root)
                    test_root = repo / "tools/termius-check/src/test"
                    data = (test_root / remove).read_bytes() if remove else b"SYNTHETIC UNREVIEWED SOURCE"
                    if remove:
                        (test_root / remove).unlink()
                    if add:
                        path = test_root / add
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(data)
                    output = root / "output"
                    with mock.patch.object(runner, "select_tool_test_sources", wraps=runner.select_tool_test_sources) as preflight, \
                         mock.patch.object(runner.subprocess, "run", side_effect=AssertionError("Compiler boundary must not be reached")) as child:
                        with self.assertRaisesRegex(ValueError, "allowlist"):
                            self.invoke_runner(repo, jdk, cache, output, scope)
                    preflight.assert_called_once_with(repo)
                    child.assert_not_called()
                    report = json.loads((output / "jvm-checks.json").read_text(encoding="utf-8"))
                    self.assertEqual("scoped-jvm-checks-v3", report["schema"])
                    self.assertEqual("failed", report["status"])
                    self.assertEqual([], report["steps"])
                    self.assertIn("allowlist", report["error"])

    def test_native_measurement_contract_and_existing_negative_shapes(self):
        text = (REPO / "tools/termius-check/src/main/kotlin/RuntimeCheck.kt").read_text(encoding="utf-8")
        for field in ("termius-structural-check-v3", "structural-check-failed.json", "started_at", "ended_at", "elapsed_ns",
                      "invocation", "parent_classpath", "parent_exact_request2_preflight_only",
                      "patch_results", "changed_method_count", "output_sha256", "manifest_path", "dex_inventory",
                      "before_snapshot_sha256", "after_snapshot_sha256", "snapshots_equal", "diagnostic_matched",
                      "fixture_sha256", "negativeMeasurements.size == 9", "Files.isSameFile", "StandardOpenOption.CREATE_NEW"):
            self.assertIn(field, text)
        for name in ("widget-only", "ssh-only", "terminal-only", "wrong-widget-helper", "wrong-result-register",
                     "wrong-branch-target", "global-pro-override", "premium-repeat"):
            self.assertIn('"' + name + '"', text)
        self.assertIn("check(before == after)", text)
        self.assertIn("verifyOffline(compared)", text)
        self.assertIn("verifyPremium(compared)", text)
        self.assertIn("excludes debug metadata, class metadata and fields", text)

    def test_java_listener_is_authored_and_preserves_summary(self):
        text = (REPO / "tools/termius-check/src/test/java/MeasuredJUnit.java").read_text(encoding="utf-8")
        for value in ("extends RunListener", "testStarted", "testFinished", "testIgnored", "testAssumptionFailure",
                      "testFailure", "new TextListener(System.out)", "CREATE_NEW", "getAssumptionFailureCount"):
            self.assertIn(value, text)


if __name__ == "__main__":
    unittest.main()
