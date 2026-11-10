"""Pure wrapper/negative validation tests; never claims final-MPP execution."""
import argparse
import hashlib
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


def current_provenance():
    spec = importlib.util.spec_from_file_location("plex_test_freeze", ROOT / "tools/release/freeze.py")
    freeze = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(freeze)
    tree, entries = freeze.r.source_tree(ROOT)
    return tree, entries, freeze.provenance(ROOT, entries)


def request_for(bundle, catalog, tree, provenance):
    return dict(schema=2, policy=checker.POLICY, owner="FISHYau", repository="fishyau-morphe-patches", version="0.1.0",
                created_at="2026-11-09T00:00:00", description="Synthetic binding only; not loaded.", provenance=provenance,
                source_tree_sha256=tree, bundle_sha256=checker.sha(bundle), catalog_sha256=checker.sha(catalog))


class FinalBundleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree, cls.entries, cls.provenance = current_provenance()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="plex-wrapper-tests-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        # Deliberately invalid non-ZIP bytes, never loadable Android MPP stand-ins.
        self.bundle = self.root / "invalid-input.mpp"
        self.bundle.write_bytes(b"not an Android bundle")
        self.catalog = self.root / "catalog.json"
        self.catalog.write_bytes(b"{}")
        self.request = request_for(self.bundle, self.catalog, self.tree, self.provenance)

    def validate(self, data=None):
        return checker.validate_request(json.dumps(self.request).encode() if data is None else data,
                                        self.bundle, self.catalog, self.tree, self.entries)

    def test_request_binding_accepts_only_hash_contract_not_bundle_validity(self):
        self.assertEqual(self.validate(), self.request)
        with self.assertRaises(ValueError):
            checker.validate_final_inputs(checker.release_module(ROOT), self.request, self.bundle, self.catalog)

    def test_request_requires_exact_fields(self):
        self.request["passed"] = True
        with self.assertRaisesRegex(ValueError, "fields"):
            self.validate()

    def test_request_requires_current_policy(self):
        self.request["policy"] = "old-two-patch-policy"
        with self.assertRaisesRegex(ValueError, "policy"):
            self.validate()

    def test_request_rejects_redundant_patcher_and_defaults_fields(self):
        for key, value in (("patcher_version", "2.3.0"), ("defaults", checker.DEFAULTS)):
            with self.subTest(key=key):
                self.request[key] = value
                with self.assertRaisesRegex(ValueError, "fields"):
                    self.validate()
                del self.request[key]

    def test_numeric_schema_two_only(self):
        for schema in (True, False, "2", 2.0, 1, "plex-final-bundle-request-v1"):
            self.request["schema"] = schema
            with self.subTest(schema=schema), self.assertRaisesRegex(ValueError, "schema/policy"):
                self.validate()

    def test_hashes_are_exact_lowercase_sha256(self):
        for digest in ("A" * 64, "a" * 63, None, 123):
            self.request["catalog_sha256"] = digest
            with self.assertRaisesRegex(ValueError, "digest"):
                self.validate()

    def test_source_tree_mismatch_rejected(self):
        self.request["source_tree_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "source tree"):
            self.validate()

    def test_bundle_mutation_rejected(self):
        self.bundle.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "MPP digest"):
            self.validate()

    def test_catalog_mutation_rejected(self):
        self.catalog.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "catalog digest"):
            self.validate()

    def test_duplicate_json_keys_rejected_even_equal_values(self):
        raw = json.dumps(self.request).encode().replace(b'{', b'{"policy":"initial-three-patch-collection-v2",', 1)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate(raw)

    def test_nonfinite_json_rejected(self):
        with self.assertRaisesRegex(ValueError, "nonfinite"):
            checker.parse_json(b'{"value":NaN}')

    def test_tools_only_projection_has_no_patch_or_hermes_source(self):
        sources = checker.select_sources(ROOT)
        self.assertEqual(len(sources), 4)
        self.assertEqual({p.name for p in sources}, {"FinalBundleCheck.kt", "FinalBundleFixtures.kt", "LoadedBundleMetadata.kt", "PatchListGenerator.kt"})
        self.assertNotIn("HermesBytecode.kt", {p.name for p in sources})
        self.assertNotIn("PremiumUnlockPatch.kt", {p.name for p in sources})

    def test_extra_checker_source_rejected(self):
        kotlin = self.root / "tools/plex-check/src/main/kotlin"
        kotlin.mkdir(parents=True)
        for name in ("FinalBundleCheck.kt", "FinalBundleFixtures.kt", "Unexpected.kt"):
            (kotlin / name).write_text("// test")
        with self.assertRaisesRegex(ValueError, "inventory"):
            checker.select_sources(self.root)

    def test_parent_definitions_and_helper_classes_rejected(self):
        for index, entry in enumerate(("io/github/fishyau/androidpatches/plex/shared/HermesBundle.class",
                                       "io/github/fishyau/androidpatches/plex/shared/Constants.class",
                                       "io/github/fishyau/androidpatches/plex/PremiumUnlockPatchKt.class",
                                       "io/github/fishyau/androidpatches/termius/ServerAuditorPremiumPatchKt.class")):
            jar = self.root / f"invalid-parent-{index}.jar"
            with zipfile.ZipFile(jar, "w") as archive:
                archive.writestr(entry, b"not executable")
            with self.assertRaisesRegex(ValueError, "parent"):
                checker.isolated_classpath([jar])

    def test_parent_tools_inventory_records_exact_bytes(self):
        jar = self.root / "tools-only.jar"
        with zipfile.ZipFile(jar, "w") as archive:
            archive.writestr("io/github/fishyau/androidpatches/plexcheck/FinalBundleCheckKt.class", b"fixture only")
        self.assertEqual(checker.isolated_classpath([jar]), [{"path": str(jar), "sha256": checker.sha(jar)}])

    def test_compile_only_never_valid_execution_evidence(self):
        with self.assertRaisesRegex(ValueError, "did not complete"):
            checker.validate_native({"schema": "plex-final-bundle-native-v1", "status": "compile_only_no_final_bundle_observation"}, self.root, "c" * 64, self.request)

    def test_aggregate_success_without_named_cases_rejected(self):
        report = {"schema": "plex-final-bundle-native-v1", "status": checker.SUCCESS,
                  "request_sha256": "c" * 64, "source_tree_sha256": self.tree,
                  "bundle_sha256": self.request["bundle_sha256"], "catalog_sha256": self.request["catalog_sha256"],
                  "actual_definition": "exact_three_loaded_metadata_catalog_verified",
                  "resource_execution": "loaded_plex_raw_resource_patch_all_named_cases_verified",
                  "loader": "app.morphe.patcher.patch.loadPatchesFromJar", "executed_patch_names": ["Premium unlock"],
                  "classpath_isolation": "definition_and_production_plex_helper_resources_absent",
                  "started_at": "2026-11-09T00:00:00Z", "finished_at": "2026-11-09T00:00:01Z", "elapsed_ns": 10}
        with self.assertRaisesRegex(ValueError, "named observations"):
            checker.validate_native(report, self.root, "c" * 64, self.request)

    def test_native_wrong_request_rejected(self):
        with self.assertRaisesRegex(ValueError, "request mismatch"):
            checker.validate_native({"schema": "plex-final-bundle-native-v1", "status": checker.SUCCESS,
                                    "request_sha256": "wrong"}, self.root, "c" * 64, self.request)

    def test_evidence_hash_tamper_and_escape_rejected(self):
        evidence = self.root / "evidence"
        evidence.write_bytes(b"observed")
        record = {"path": str(evidence), "exists": True, "sha256": checker.sha(evidence), "bytes": 8}
        checker.verify_record(record, self.root, required=True)
        evidence.write_bytes(b"tampered")
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

    def test_existing_output_rejected_without_execution(self):
        args = argparse.Namespace(command="compile-only", out=self.root, jdk=self.root, cache_root=self.root,
                                  request=None, bundle=None, catalog=None)
        with mock.patch.object(checker.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "NEW external"):
                checker.execute(args)
            run.assert_not_called()

    def test_missing_frozen_request_rejected_before_execution(self):
        args = argparse.Namespace(command="check", out=self.root / "new-output", jdk=self.root, cache_root=self.root,
                                  request=None, bundle=self.bundle, catalog=self.catalog)
        with mock.patch.object(checker.subprocess, "run") as run:
            report = checker.execute(args)
            run.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["phase"], "preflight")
        self.assertIn("preexisting frozen request", report["error"])
        self.assertTrue((args.out / "checker.json").is_file())
        with self.assertRaisesRegex(ValueError, "NEW external"):
            checker.execute(args)

    def test_compile_only_rejects_bundle_observation_inputs(self):
        args = argparse.Namespace(command="compile-only", out=self.root / "new-output", jdk=self.root, cache_root=self.root,
                                  request=None, bundle=self.bundle, catalog=None)
        with mock.patch.object(checker.subprocess, "run") as run:
            report = checker.execute(args)
            run.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertIn("cannot accept", report["error"])


class MockedCompilationTest(unittest.TestCase):
    """Mock child processes only; no generated Android MPP or positive observation."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="plex-mocked-compile-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.repo = self.root / "source"
        closure = self.repo / ".claude/skills/run-android-morphe/templates/cache-closure.json"
        closure.parent.mkdir(parents=True)
        closure.write_text(json.dumps({"patcher_version": "2.3.0", "compiler_version": "2.4.21", "compiler": [], "runtime": []}))
        release = self.repo / "tools/release/release.py"
        release.parent.mkdir(parents=True)
        release.write_text("# fixture, never executed")
        release.with_name("staging.py").write_text("# fixture, never executed")
        self.tree, self.entries, self.provenance = current_provenance()
        self.jdk = self.root / "jdk"
        for file in ("bin/java.exe", "bin/server/jvm.dll", "lib/modules", "release"):
            path = self.jdk / file
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'JAVA_VERSION="21.0.13"\n' if file == "release" else b"inert test bytes")
        self.cache = self.root / "cache"
        self.cache.mkdir()
        self.source = self.repo / "Tools.kt"
        self.source.write_text("// inert mock source")
        self.args = argparse.Namespace(command="compile-only", jdk=self.jdk, cache_root=self.cache,
                                       out=self.root / "new-run", request=None, bundle=None, catalog=None)
        self.fake_release = SimpleNamespace(source_tree=mock.Mock(return_value=(self.tree, self.entries)),
                                            read_bytes=lambda p, limit: p.read_bytes())

    def mock_run(self, argv, **kwargs):
        self.assertEqual(kwargs["cwd"], self.args.out)
        self.assertFalse(any(key.upper() in {"CLASSPATH", "JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS"} for key in kwargs["env"]))
        if self.args.request:
            self.assertEqual((self.args.out / "frozen-request.json").read_bytes(), self.args.request.read_bytes())
        if "-d" in argv:
            with zipfile.ZipFile(argv[argv.index("-d") + 1], "w") as jar:
                jar.writestr("mock/Tool.class", b"inert test data, no bytecode")
        return SimpleNamespace(returncode=1 if "actual-final-bundle" in str(argv) else 0, stdout=b"mock-only child output", stderr=b"")

    def run_mocked(self, runner=None):
        trusted_staging = checker.staging_module(ROOT)
        with mock.patch.object(checker, "release_module", return_value=self.fake_release), \
             mock.patch.object(checker, "staging_module", return_value=trusted_staging), \
             mock.patch.object(checker, "select_sources", return_value=[self.source]), \
             mock.patch.object(checker.subprocess, "run", side_effect=runner or self.mock_run):
            return checker.execute(self.args, self.repo)

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
            self.assertEqual(checker.sha(row["log"]["path"]), row["log"]["sha256"])
        self.assertEqual(checker.parse_json((self.args.out / "checker.json").read_bytes()), report)

    def test_failed_compile_retained_and_same_output_never_retried(self):
        report = self.run_mocked(lambda *a, **k: SimpleNamespace(returncode=1, stdout=b"mock failure", stderr=b""))
        self.assertEqual(report["status"], "failed")
        self.assertEqual((self.args.out / "java-version.log").read_bytes(), b"mock failure")
        with self.assertRaisesRegex(ValueError, "NEW external"):
            self.run_mocked()

    def test_changed_source_tree_overrides_compile_success(self):
        self.fake_release.source_tree.side_effect = [("a" * 64, {}), ("b" * 64, {})]
        report = self.run_mocked()
        self.assertEqual(report["status"], "failed")
        self.assertIn("source tree changed", report["verification_error"])

    def prepare_request(self):
        self.args.command = "check"
        self.args.bundle = self.root / "invalid-input.mpp"
        self.args.bundle.write_bytes(b"explicitly invalid non-ZIP")
        self.args.catalog = self.root / "catalog.json"
        self.args.catalog.write_bytes(b"{}")
        self.args.request = self.root / "request.json"
        request = request_for(self.args.bundle, self.args.catalog, self.tree, self.provenance)
        data = ("  " + json.dumps(request, indent=3) + "\n\n").encode()
        self.args.request.write_bytes(data)
        return data

    def test_frozen_request_exact_bytes_precede_even_java_version(self):
        data = self.prepare_request()
        def fail_actual(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt" in argv:
                return SimpleNamespace(returncode=1, stdout=b"mock-only final run failure", stderr=b"")
            return result
        # Bypass only final archive validation to test sequencing; it is NOT a final-MPP positive test.
        with mock.patch.object(checker, "validate_final_inputs"):
            report = self.run_mocked(fail_actual)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["request_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual((self.args.out / "frozen-request.json").read_bytes(), data)
        self.assertEqual(report["actual_definition"], "not_observed")

    def test_request_mutation_before_copy_stops_all_children(self):
        self.prepare_request()
        def mutate(*args):
            self.args.request.write_bytes(self.args.request.read_bytes() + b" ")
        with mock.patch.object(checker, "validate_final_inputs", side_effect=mutate), \
             mock.patch.object(checker.subprocess, "run") as child:
            report = self.run_mocked()
            child.assert_not_called()
        self.assertEqual(report["status"], "failed")
        self.assertIn("before copy", report["error"])

    def test_original_and_copied_request_mutation_before_child_rejected(self):
        self.prepare_request()
        for target in ("original", "copy"):
            self.args.out = self.root / ("mutation-" + target)
            original = self.args.request.read_bytes()
            def mutate(argv, **kwargs):
                result = self.mock_run(argv, **kwargs)
                if "-d" in argv:
                    path = self.args.request if target == "original" else self.args.out / "frozen-request.json"
                    path.write_bytes(original + b" ")
                self.assertNotIn("io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", argv)
                return result
            with mock.patch.object(checker, "validate_final_inputs"):
                report = self.run_mocked(mutate)
            self.assertEqual(report["status"], "failed")
            self.assertIn("before child", report["error"])
            self.assertEqual(report["resource_execution"], "not_observed")
            self.args.request.write_bytes(original)

    def test_copy_mutation_after_mock_child_failure_retained_as_failure(self):
        self.prepare_request()
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt" in argv:
                (self.args.out / "frozen-request.json").write_bytes(b"changed after mock invocation")
                return SimpleNamespace(returncode=1, stdout=b"mock child failed", stderr=b"")
            return result
        with mock.patch.object(checker, "validate_final_inputs"):
            report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn("frozen request changed during execution", report["verification_error"])
        self.assertEqual(report["resource_execution"], "not_observed")
        self.assertTrue((self.args.out / "actual-final-bundle.log").is_file())

    def test_validator_dependency_is_hashed_and_mutation_overrides_compile_success(self):
        def mutate(argv, **kwargs):
            result = self.mock_run(argv, **kwargs)
            if "-d" in argv:
                (self.repo / "tools/release/staging.py").write_bytes(b"changed validator")
            return result
        report = self.run_mocked(mutate)
        self.assertEqual(report["status"], "failed")
        self.assertIn(str(self.repo / "tools/release/staging.py"), report["input_sha256"])
        self.assertIn("inputs changed", report["verification_error"])


if __name__ == "__main__":
    unittest.main()
