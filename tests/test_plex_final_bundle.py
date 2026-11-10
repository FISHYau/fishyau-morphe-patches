"""Pure wrapper/structural tests; synthetic archives never claim actual-MPP execution."""
import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("plex_final_bundle", ROOT / "tools/plex-check/final_bundle.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def synthetic_catalog(version="9.8.7"):
    """Current metadata shape only, never a loaded patch definition."""
    patches = []
    for name in ("Server Auditor Offline Automation", "Server Auditor Premium", "Premium unlock"):
        plex = name == "Premium unlock"
        app = {"packageName": "com.plexapp.android" if plex else "com.server.auditor.ssh.client",
               "name": "Plex" if plex else "Server Auditor", "description": None,
               "apkFileType": "APKM", "appIconColor": "#282A2D" if plex else "#1A73E8",
               "signatures": None, "formFactor": "MOBILE",
               "targets": [] if plex else [{"version": "8.0.1", "versionCodes": {abi: 1008 for abi in ("ARM64_V8A", "ARMEABI_V7A", "X86_64", "X86")},
                                            "isExperimental": False, "minSdk": None, "description": None}]}
        patches.append({"name": name, "description": "Synthetic metadata only", "default": True,
                        "category": None, "compatiblePackages": [app], "options": []})
    return {"version": version, "patches": patches}


def synthetic_bundle(path, version="9.8.7", patcher="2.3.0", extra=None):
    # Eight magic bytes are sufficient for format inspection, NOT executable DEX.
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("classes.dex", b"dex\n035\x00not executable")
        archive.writestr("META-INF/MANIFEST.MF", f"Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: FISHYau\r\nVersion: {version}\r\nPatcher-Version: {patcher}\r\n\r\n")
        if extra:
            archive.writestr(extra, b"inert fixture")


def arguments(root, **overrides):
    values = dict(command="compile-only", out=root / "new-output", jdk=root / "jdk",
                  cache_root=root / "cache", bundle=None, catalog=None)
    values.update(overrides)
    return argparse.Namespace(**values)


class FinalBundleContractTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="plex-wrapper-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.bundle = self.root / "synthetic-nonexecutable.mpp"
        synthetic_bundle(self.bundle)
        self.catalog = self.root / "catalog.json"
        self.catalog.write_text(json.dumps(synthetic_catalog()), encoding="utf-8")
        self.formats = checker.formats_module(ROOT)

    def test_preflight_inspects_formats_with_artifact_version_not_loader_success(self):
        selected = checker.preflight(self.formats, self.bundle, self.catalog)
        self.assertEqual(selected, {"version": "9.8.7", "bundle_sha256": checker.sha(self.bundle),
                                    "catalog_sha256": checker.sha(self.catalog)})
        self.assertNotIn("actual_definition", selected)

    def test_invalid_mpp_rejected_before_execution(self):
        self.bundle.write_bytes(b"not an Android bundle")
        with self.assertRaises(ValueError):
            checker.preflight(self.formats, self.bundle, self.catalog)

    def test_wrong_extension_rejected(self):
        with self.assertRaisesRegex(ValueError, "MPP"):
            checker.preflight(self.formats, self.bundle.with_suffix(".jar"), self.catalog)

    def test_wrong_patcher_version_rejected(self):
        synthetic_bundle(self.bundle, patcher="0.0.0")
        with self.assertRaisesRegex(ValueError, "patcher version"):
            checker.preflight(self.formats, self.bundle, self.catalog)

    def test_bundle_catalog_version_mismatch_rejected(self):
        self.catalog.write_text(json.dumps(synthetic_catalog("different")), encoding="utf-8")
        with self.assertRaises(ValueError):
            checker.preflight(self.formats, self.bundle, self.catalog)

    def test_signed_archive_rejected(self):
        synthetic_bundle(self.bundle, extra="META-INF/signature.sig")
        with self.assertRaisesRegex(ValueError, "signed bundle"):
            checker.preflight(self.formats, self.bundle, self.catalog)

    def test_wrong_patch_default_and_inventory_rejected(self):
        for change in (lambda p: p[0].update(default=False), lambda p: p.pop(),
                       lambda p: p[0].update(name="Unexpected patch")):
            catalog = synthetic_catalog()
            change(catalog["patches"])
            self.catalog.write_text(json.dumps(catalog), encoding="utf-8")
            with self.assertRaises(ValueError):
                checker.preflight(self.formats, self.bundle, self.catalog)

    def test_duplicate_catalog_json_keys_rejected(self):
        self.catalog.write_text('{"version":"9.8.7",' + json.dumps(synthetic_catalog())[1:], encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "duplicate"):
            checker.preflight(self.formats, self.bundle, self.catalog)

    def test_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            checker.parse_json(b'{"value":NaN}')

    def test_tools_only_projection_has_no_patch_or_hermes_source(self):
        sources = checker.select_sources(ROOT)
        self.assertEqual({p.name for p in sources}, {"FinalBundleCheck.kt", "FinalBundleFixtures.kt", "LoadedBundleMetadata.kt", "PatchListGenerator.kt"})
        self.assertEqual(len(sources), 4)

    def test_extra_checker_source_rejected(self):
        kotlin = self.root / "tools/plex-check/src/main/kotlin"
        kotlin.mkdir(parents=True)
        for name in ("FinalBundleCheck.kt", "FinalBundleFixtures.kt", "Unexpected.kt"):
            (kotlin / name).write_text("// test", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "inventory"):
            checker.select_sources(self.root)

    def test_parent_definitions_and_helper_classes_rejected(self):
        for index, entry in enumerate(("io/github/fishyau/androidpatches/plex/shared/HermesBundle.class",
                                       "io/github/fishyau/androidpatches/plex/shared/Constants.class",
                                       "io/github/fishyau/androidpatches/plex/PremiumUnlockPatchKt.class",
                                       "io/github/fishyau/androidpatches/termius/ServerAuditorPremiumPatchKt.class",
                                       "io/github/fishyau/androidpatches/termius/ServerAuditorOfflineAutomationPatchKt.class")):
            jar = self.root / f"invalid-parent-{index}.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(entry, b"not executable")
            with self.assertRaisesRegex(ValueError, "parent"):
                checker.isolated_classpath([jar])

    def test_tools_only_parent_is_accepted_without_inventory_report(self):
        jar = self.root / "tools-only.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("io/github/fishyau/androidpatches/plexcheck/FinalBundleCheckKt.class", b"fixture only")
        self.assertIsNone(checker.isolated_classpath([jar]))

    def test_all_23_case_names_preserved(self):
        self.assertEqual(len(checker.CASE_NAMES), 23)
        self.assertEqual(len(checker.NEGATIVES), 7)
        self.assertTrue(checker.NEGATIVES < checker.CASE_NAMES)
        self.assertIn("manifest_actual_binary_decode", checker.CASE_NAMES)

    def test_compile_only_never_valid_execution_result(self):
        with self.assertRaisesRegex(ValueError, "did not complete"):
            checker.validate_native({"schema": "plex-final-bundle-native-v1", "status": "compile_only_no_final_bundle_observation"}, self.root, {})

    def test_aggregate_success_without_named_cases_rejected(self):
        selected = checker.preflight(self.formats, self.bundle, self.catalog)
        report = dict(selected, schema="plex-final-bundle-native-v1", status=checker.SUCCESS,
                      actual_definition="exact_three_loaded_metadata_catalog_verified",
                      resource_execution="loaded_plex_raw_resource_patch_all_named_cases_verified",
                      loader="app.morphe.patcher.patch.loadPatchesFromJar", executed_patch_names=["Premium unlock"],
                      classpath_isolation="definition_and_production_plex_helper_resources_absent",
                      started_at="2026-11-09T00:00:00Z", finished_at="2026-11-09T00:00:01Z", elapsed_ns=10)
        with self.assertRaisesRegex(ValueError, "named observations"):
            checker.validate_native(report, self.root, selected)

    def test_native_wrong_artifact_rejected(self):
        selected = checker.preflight(self.formats, self.bundle, self.catalog)
        report = dict(selected, schema="plex-final-bundle-native-v1", status=checker.SUCCESS)
        report["bundle_sha256"] = "wrong"
        with self.assertRaisesRegex(ValueError, "input mismatch"):
            checker.validate_native(report, self.root, selected)

    def test_case_file_tamper_and_escape_rejected(self):
        output = self.root / "output.bundle"
        output.write_bytes(b"observed")
        record = {"path": str(output), "exists": True, "sha256": checker.sha(output), "bytes": 8}
        checker.verify_record(record, self.root, required=True)
        output.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            checker.verify_record(record, self.root, required=True)
        record["path"] = str(self.root.parent / "outside")
        with self.assertRaisesRegex(ValueError, "escapes"):
            checker.verify_record(record, self.root, required=False)

    def test_actual_times_required(self):
        for record in ({"started_at": "2026-11-09T00:00:01Z", "finished_at": "2026-11-09T00:00:00Z", "elapsed_ns": 1},
                       {"started_at": "2026-11-09T00:00:00Z", "finished_at": "2026-11-09T00:00:01Z", "elapsed_ns": 0}):
            with self.assertRaises(ValueError):
                checker.verify_times(record)

    def test_existing_or_internal_output_rejected_without_execution(self):
        for out in (self.root, ROOT / "unused-checker-output"):
            with mock.patch.object(checker.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "NEW external"):
                    checker.execute(arguments(self.root, out=out))
                run.assert_not_called()

    def test_missing_catalog_rejected_before_execution_and_output_consumed(self):
        args = arguments(self.root, command="check", bundle=self.bundle)
        with mock.patch.object(checker.subprocess, "run") as run:
            report = checker.execute(args)
            run.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["phase"], "preflight")
        self.assertIn("explicit final MPP and catalog", report["error"])
        self.assertTrue((args.out / "checker.json").is_file())
        with self.assertRaisesRegex(ValueError, "NEW external"):
            checker.execute(args)

    def test_compile_only_rejects_bundle_observation_inputs(self):
        with mock.patch.object(checker.subprocess, "run") as run:
            report = checker.execute(arguments(self.root, bundle=self.bundle))
            run.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertIn("cannot accept", report["error"])


class MockedCompilationTest(unittest.TestCase):
    """Mock child processes only; never execute synthetic DEX or claim a real load."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="plex-mocked-compile-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "source"
        closure = self.repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        closure.parent.mkdir(parents=True)
        closure.write_text(json.dumps({"patcher_version": "2.3.0", "compiler_version": "2.4.21", "compiler": [], "runtime": []}), encoding="utf-8")
        self.formats_path = self.repo / "tools/bundle_formats.py"
        self.formats_path.parent.mkdir(parents=True)
        self.formats_path.write_text("# inert fixture, never imported", encoding="utf-8")
        self.jdk = self.root / "jdk"
        for file in ("bin/java.exe", "release"):
            path = self.jdk / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'JAVA_VERSION="21.0.13"\n' if file == "release" else b"inert test bytes")
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.source = self.repo / "Tools.kt"
        self.source.write_text("// inert mock source", encoding="utf-8")
        self.args = arguments(self.root, jdk=self.jdk, cache_root=self.cache)
        self.formats = checker.formats_module(ROOT)

    def mock_run(self, argv, **kwargs):
        self.assertEqual(kwargs["cwd"], self.args.out)
        self.assertFalse(any(key.upper() in {"CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"} for key in kwargs["env"]))
        if "-d" in argv:
            with zipfile.ZipFile(argv[argv.index("-d") + 1], "w") as jar:
                jar.writestr("mock/Tool.class", b"inert test data, no bytecode")
        native = "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt" in argv
        return SimpleNamespace(returncode=1 if native else 0, stdout=b"mock-only child output", stderr=b"")

    def run_mocked(self, runner=None):
        with mock.patch.object(checker, "formats_module", return_value=self.formats), \
             mock.patch.object(checker, "select_sources", return_value=[self.source]), \
             mock.patch.object(checker.subprocess, "run", side_effect=runner or self.mock_run):
            return checker.execute(self.args, self.repo)

    def prepare_inputs(self):
        self.args.command = "check"
        self.args.bundle = self.root / "synthetic-nonexecutable.mpp"
        synthetic_bundle(self.args.bundle)
        self.args.catalog = self.root / "catalog.json"
        self.args.catalog.write_text(json.dumps(synthetic_catalog()), encoding="utf-8")

    def test_mocked_compile_only_has_no_execution_flags_or_cases(self):
        report = self.run_mocked()
        self.assertEqual(report["status"], "compile_only_no_final_bundle_observation")
        self.assertEqual(report["actual_definition"], "not_observed")
        self.assertEqual(report["resource_execution"], "not_observed")
        self.assertNotIn("cases", report)
        self.assertEqual([row["step"] for row in report["commands"]], ["java-version", "compile"])
        self.assertTrue(report["inputs_unchanged"])
        for row in report["commands"]:
            checker.verify_times(row)
            self.assertTrue(Path(row["log"]).is_file())
        self.assertEqual(checker.parse_json((self.args.out / "checker.json").read_bytes()), report)

    def test_failed_compile_retained_and_same_output_never_retried(self):
        report = self.run_mocked(lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"mock failure", stderr=b""))
        self.assertEqual(report["status"], "failed")
        self.assertEqual((self.args.out / "java-version.log").read_bytes(), b"mock failure")
        with self.assertRaisesRegex(ValueError, "NEW external"):
            self.run_mocked()

    def test_consumed_source_mutation_overrides_compile_success(self):
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "-d" in argv:
                self.source.write_text("// changed input", encoding="utf-8")
            return result
        report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn("inputs changed", report["verification_error"])

    def test_unrelated_source_changes_do_not_bind_whole_tree(self):
        def change_unrelated(argv, **kwargs):
            (self.repo / "unrelated.txt").write_text("unrelated edit", encoding="utf-8")
            return self.mock_run(argv, **kwargs)
        self.assertEqual(self.run_mocked(change_unrelated)["status"], "compile_only_no_final_bundle_observation")

    def test_native_receives_only_artifact_and_output_paths(self):
        self.prepare_inputs()
        calls = []
        def capture(argv, **kwargs):
            calls.append(argv)
            return self.mock_run(argv, **kwargs)
        report = self.run_mocked(capture)
        self.assertEqual(report["status"], "failed")  # Deliberate mock loader failure.
        main = "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt"
        argv = calls[-1]
        self.assertEqual(argv[argv.index(main) + 1:], [str(self.args.bundle), str(self.args.catalog),
                                                     str(self.args.out / "native.json"), str(self.args.out / "cases")])
        self.assertEqual(report["resource_execution"], "not_observed")

    def test_input_mutation_during_preflight_stops_all_children(self):
        self.prepare_inputs()
        original = checker.preflight
        def mutate(*args):
            selected = original(*args)
            self.args.catalog.write_bytes(self.args.catalog.read_bytes() + b" ")
            return selected
        with mock.patch.object(checker, "preflight", side_effect=mutate):
            report = self.run_mocked(lambda *a, **k: self.fail("child must not start"))
        self.assertEqual(report["status"], "failed")
        self.assertIn("changed during preflight", report["error"])
        self.assertEqual(report["commands"], [])

    def test_artifact_mutation_before_child_is_rejected(self):
        self.prepare_inputs()
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "-d" in argv:
                self.args.bundle.write_bytes(b"mutated after mock compile")
            self.assertNotIn("io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", argv)
            return result
        report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn("before child", report["error"])
        self.assertFalse((self.args.out / "actual-final-bundle.log").exists())

    def test_artifact_mutation_after_child_failure_is_retained(self):
        self.prepare_inputs()
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt" in argv:
                self.args.catalog.write_bytes(b"changed after mock invocation")
            return result
        report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn("inputs changed", report["verification_error"])
        self.assertTrue((self.args.out / "actual-final-bundle.log").is_file())

    def test_format_helper_mutation_is_detected(self):
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "-d" in argv:
                self.formats_path.write_bytes(b"changed helper")
            return result
        report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn("inputs changed", report["verification_error"])


if __name__ == "__main__":
    unittest.main()
