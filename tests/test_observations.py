"""Synthetic contract tests ONLY. Dummy JARs/MPP bytes NEVER go to real children/loaders."""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("test_observations_impl", REPO / "tools/release/observations.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
NOW = dt.datetime(2026, 11, 9, 12, tzinfo=dt.timezone.utc)
START, END = "2026-11-09T10:00:00Z", "2026-11-09T10:00:01Z"
WINDOW = ("2026-11-09T09:59:00.000000", "2026-11-09T10:01:00.000000")


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def jar(path, name="tools/Fixture.class"):
    with zipfile.ZipFile(path, "w") as stream:
        stream.writestr(name, b"CONTRACT ONLY; NOT EXECUTABLE")


def times(native=False):
    return dict(started_at=START, **({"finished_at": END, "elapsed_ns": 1} if native else {"ended_at": END, "duration_ns": 1}))


class SourceFixture:
    """Invented measured report; used solely to test strict validation, never execute."""
    def __init__(self, base):
        self.root = base / "source-jvm"
        self.root.mkdir()
        self.jdk, self.cache = base / "jdk", base / "cache"
        (self.jdk / "bin").mkdir(parents=True)
        self.cache.mkdir()
        (self.jdk / "bin/java.exe").write_bytes(b"not executable")
        self.config = dict(jdk=self.jdk, cache=self.cache, java=self.jdk / "bin/java.exe", compiler=[], runtime=[], tests=[], deps=[], closure_sha256=o.file_record(REPO / ".claude/skills/run-android-morphe/templates/cache-closure.json")["sha256"])
        self.tools = {"jdk": {}, "dependencies": {}}
        main, tests, _, checkers, classes = o.j.select_sources(REPO, "collection")
        required = o.j.required_cases(REPO, classes)
        ident = lambda row: dict(zip(("class_name", "method_name", "display_name"), row))
        self.measured = {"schema": "source-junit-measurements-v1", "status": "source_tests_passed", "requested_classes": classes,
                         "unscoped_failures": [], "incomplete_count": 0, **times(), "planned_cases": [ident(row) for row in required],
                         "cases": [{**ident(row), **times(), "outcome": "passed", "failures": [], "assumptions": []} for row in required],
                         "totals": {"run_count": 121, "failure_count": 0, "ignore_count": 0, "assumption_failure_count": 0}}
        for name in ("definitions-JVM-ONLY.jar", "tests.jar", "checker.jar"):
            jar(self.root / name)
        save(self.root / "junit-measurements.json", self.measured)
        steps = []
        for name in ("compile-definitions", "compile-tests", "compile-junit-reporter", "junit", "compile-checker"):
            log = self.root / (name + ".log")
            log.write_bytes(b"SYNTHETIC CONTRACT LOG")
            steps.append(dict(step=name, exit_code=0, log={"path": str(log), **o.file_record(log)}, **times()))
        sources = list(dict.fromkeys(main + tests + checkers + [REPO / "tools/termius-check/src/test/java/MeasuredJUnit.java", REPO / "tools/termius-check/run_jvm_checks.py"]))
        source_tree = o.j.source_tree(REPO)
        self.report = dict(schema="scoped-jvm-checks-v3", scope="collection", status="collection_uncached_jvm_compilation_tests_passed",
            source_root=str(REPO), output_root=str(self.root), **times(), steps=steps, source_tree_before=source_tree, source_tree_after=source_tree,
            tool_inventory={"jdk_root": str(self.jdk), "dependency_root": str(self.cache), "jdk_before": {}, "jdk_after": {},
                            "dependencies_before": {}, "dependencies_after": {}, "compiler_classpath": [], "runtime_classpath": [], "test_classpath": []},
            closure_sha256=self.config["closure_sha256"], java_sha256=o.file_record(self.config["java"])["sha256"],
            source_hashes={path.relative_to(REPO).as_posix(): o.file_record(path)["sha256"] for path in sources},
            definition_count=3, excluded_main_sources=[], test_classes=classes, test_artifacts={}, junit=self.measured, executed_cases=121,
            outputs={name: o.file_record(self.root / name)["sha256"] for name in ("definitions-JVM-ONLY.jar", "tests.jar", "checker.jar")},
            checker_runtime_classpath=str(self.root / "checker.jar"))
        self.write()

    def write(self, refresh=True):
        if refresh:
            self.report["output_inventory"] = {k: v for k, v in o.inventory(self.root).items() if k != "jvm-checks.json"}
        save(self.root / "jvm-checks.json", self.report)

    def verify(self):
        return o.verify_source_run(self.root, self.config, self.tools, NOW, WINDOW)


class ObservationContracts(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="observations-contract-only-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()

    def test_event_converts_original_not_adaptation_clock(self):
        self.assertEqual(o.utc("2026-11-09T12:00:01+02:00", NOW), "2026-11-09T10:00:01.000000")
        for value in ("2026-11-09T12:00:01Z", "2026-11-01T10:00:01Z", "2026-11-09T10:00:01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                o.utc(value, NOW)
        for changed in ({**times(), "duration_ns": True}, {**times(), "duration_ns": 0}, {**times(), "ended_at": "2026-11-08T00:00:00Z"}):
            with self.assertRaises(ValueError): o.interval(changed, NOW)
        with self.assertRaises(ValueError): o.interval(times(), NOW, within=("2026-11-09T10:00:02", WINDOW[1]))

    def test_binding_preserves_exact_whitespace_and_all_five_fields(self):
        req = dict(policy=o.s.COLLECTION_POLICY, bundle_sha256="a" * 64, catalog_sha256="b" * 64, source_tree_sha256="c" * 64)
        a, b = json.dumps(req).encode(), ("  " + json.dumps(req, indent=3) + "\n\n").encode()
        self.assertNotEqual(o.binding(req, a), o.binding(req, b))
        self.assertEqual(set(o.binding(req, b)), set(req) | {"request_sha256"})
        self.assertEqual(o.binding(req, b)["request_sha256"], o.r.digest(b))

    def test_source_contract_positive_is_only_synthetic_validation(self):
        fixture = SourceFixture(self.base)
        report, _, cp = fixture.verify()
        self.assertEqual(report["executed_cases"], 121)
        self.assertEqual(cp, [fixture.root / "checker.jar"])
        self.assertNotIn("manager_import", report)

    def test_source_old_failed_partial_scope_or_aggregate_rejected(self):
        fixture = SourceFixture(self.base)
        original = copy.deepcopy(fixture.report)
        for field, value in (("schema", "scoped-jvm-checks-v2"), ("status", "failed"), ("scope", "termius"), ("junit", {"tests": 121}),
                             ("checker_runtime_classpath", str(fixture.root / "tests.jar")), ("definition_count", 2), ("source_hashes", {}),
                             ("steps", original["steps"][:-1]), ("executed_cases", 120)):
            fixture.report = {**copy.deepcopy(original), field: value}
            fixture.write()
            with self.subTest(field=field), self.assertRaises((ValueError, KeyError, TypeError)): fixture.verify()

    def test_missing_duplicate_and_skipped_source_cases_fail_closed(self):
        fixture = SourceFixture(self.base)
        original = copy.deepcopy(fixture.measured)
        for mutate in (lambda x: x["cases"].pop(), lambda x: x["cases"].append(x["cases"][0]),
                       lambda x: x["planned_cases"].pop(), lambda x: x["cases"][0].update(outcome="ignored"),
                       lambda x: x["cases"][0].update(assumptions=[{}]), lambda x: x["cases"][0].update(class_name="finalMPP.Parser")):
            measured = copy.deepcopy(original)
            mutate(measured)
            fixture.report["junit"] = measured
            save(fixture.root / "junit-measurements.json", measured)
            fixture.write()
            with self.assertRaises((ValueError, KeyError)): fixture.verify()

    def test_retained_logs_jars_measurements_and_fixtures_cannot_mutate(self):
        fixture = SourceFixture(self.base)
        for name in ("junit.log", "checker.jar", "junit-measurements.json"):
            path = fixture.root / name
            original = path.read_bytes()
            path.write_bytes(original + b"mutation")
            with self.subTest(name=name), self.assertRaises((ValueError, KeyError)): fixture.verify()
            path.write_bytes(original)
        (fixture.root / "unexpected.dex").write_bytes(b"not DEX")
        with self.assertRaises(ValueError): fixture.verify()

    def test_checker_and_native_regression_source_hashes_are_exactly_bound(self):
        fixture = SourceFixture(self.base)
        for name in ("tools/termius-check/src/main/kotlin/RuntimeCheck.kt",
                     "tools/termius-check/src/test/kotlin/RuntimeSnapshotRegression.kt"):
            # The regression entrypoint is covered by the whole source tree, not
            # falsely advertised as part of the 121-case source JUnit inventory.
            self.assertIn(name, fixture.report["source_tree_before"])
        name = "tools/termius-check/src/main/kotlin/RuntimeCheck.kt"
        self.assertEqual(fixture.report["source_hashes"][name], o.file_record(REPO / name)["sha256"])
        fixture.report["source_hashes"][name] = "0" * 64
        fixture.write()
        with self.assertRaises(ValueError): fixture.verify()

    def test_source_tool_and_compilation_snapshots_must_match(self):
        fixture = SourceFixture(self.base)
        for field in ("source_tree_after", "source_tree_before"):
            original = fixture.report[field]
            fixture.report[field] = {}
            fixture.write()
            with self.assertRaises(ValueError): fixture.verify()
            fixture.report[field] = original
        fixture.report["tool_inventory"]["jdk_after"] = {"other": {}}
        fixture.write()
        with self.assertRaises(ValueError): fixture.verify()

    def test_source_case_must_be_inside_measured_junit_not_just_child(self):
        fixture = SourceFixture(self.base)
        fixture.report.update(started_at="2026-11-09T09:59:00Z", ended_at="2026-11-09T10:01:00Z")
        fixture.report["steps"][3].update(started_at="2026-11-09T09:59:30Z", ended_at="2026-11-09T10:00:30Z")
        fixture.measured["cases"][0]["ended_at"] = "2026-11-09T10:00:02Z"
        fixture.report["junit"] = fixture.measured
        save(fixture.root / "junit-measurements.json", fixture.measured)
        fixture.write()
        with self.assertRaises(ValueError): fixture.verify()

    def test_source_step_must_be_inside_producer_not_just_outer_child(self):
        fixture = SourceFixture(self.base)
        fixture.report["steps"][0]["started_at"] = "2026-11-09T09:59:30Z"
        fixture.write()
        with self.assertRaises(ValueError): fixture.verify()

    def test_no_source_production_classes_on_parent_classpath(self):
        for index, entry in enumerate(("io/github/fishyau/androidpatches/termius/BooleanReturnKt.class",
                                        "io/github/fishyau/androidpatches/plex/shared/HermesBundle.class")):
            path = self.base / f"bad-{index}.jar"
            jar(path, entry)
            with self.assertRaises(ValueError): o.isolated([path])

    def test_complete_inventory_and_hardlink_and_escaping_reference_guards(self):
        root = self.base / "retained"
        root.mkdir()
        target = root / "file"
        target.write_bytes(b"first")
        before = o.inventory(root)
        target.write_bytes(b"other")
        self.assertNotEqual(before, o.inventory(root))
        os.link(target, root / "alias")
        with self.assertRaises(ValueError): o.inventory(root)
        with self.assertRaises(ValueError): o.p.verify_record({"path": str(self.base / "outside"), "exists": False, "sha256": None, "bytes": None}, root, required=False)

    def test_session_consumes_new_output_and_retains_child_failure_and_command(self):
        out = self.base / "new"
        session = o.Session(out, [])
        with mock.patch.object(o.subprocess, "run", return_value=SimpleNamespace(returncode=9, stdout=b"failure", stderr=b"diagnostic")) as run:
            with self.assertRaises(ValueError): session.run("mock-child", ["NEVER EXECUTED"])
            self.assertEqual(run.call_count, 1)
        self.assertEqual(session.commands[0]["exit_code"], 9)
        self.assertEqual((out / "mock-child.log").read_bytes(), b"failurediagnostic")
        self.assertEqual(session.commands[0]["argv"], ["NEVER EXECUTED"])
        with self.assertRaises(ValueError): o.Session(out, [])
        (out / "mock-child.log").write_bytes(b"tampered")
        with self.assertRaises(ValueError): session.retain()

    def test_session_timeout_records_failure_and_retains_partial_log(self):
        session = o.Session(self.base / "timeout", [])
        with mock.patch.object(o.subprocess, "run", side_effect=subprocess.TimeoutExpired("MOCK", 1, output=b"partial")):
            with self.assertRaises(subprocess.TimeoutExpired): session.run("child", ["MOCK"])
        self.assertTrue(session.commands[0]["timed_out"])
        self.assertEqual((session.output / "child.log").read_bytes(), b"partial")

    def test_output_must_not_overlap_input_or_source_roots(self):
        with self.assertRaises(ValueError): o.Session(REPO / "unused-output", [])
        inputs = self.base / "inputs"
        inputs.mkdir()
        with self.assertRaises(ValueError): o.Session(inputs / "new", [inputs])
        with self.assertRaises(ValueError): o.Session(self.base / "missing" / "new", [])

    def test_rejected_preflight_snapshot_bytes_failure_consumed_no_children_no_manager(self):
        inputs = self.base / "inputs"
        inputs.mkdir()
        raw = b'  {"schema":1}\n\n'
        request = inputs / "request.json"
        request.write_bytes(raw)
        out = self.base / "output"
        args = dict(request_path=request, bundle=inputs / "absent.mpp", catalog=inputs / "absent.json", jdk=self.base / "jdk", cache_root=self.base / "cache", output=out)
        with mock.patch.object(o.subprocess, "run") as run:
            report = o.execute(**args)
            run.assert_not_called()
        self.assertEqual((out / "frozen-request.json").read_bytes(), raw)
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["complete_evidence"])
        self.assertEqual(report["fragments"], {})
        self.assertEqual(report["components"]["structural"]["status"], "blocked")
        self.assertEqual(report["components"]["manager_import"]["status"], "not-observed")
        self.assertNotIn("schema", report["components"]["manager_import"])
        with self.assertRaises(ValueError): o.execute(**args)
        with self.assertRaises(ValueError): o.recheck(out, now=NOW)

    def test_arbitrary_pass_or_supplied_aggregate_not_cli_options(self):
        with self.assertRaises(SystemExit): o.main(["execute", "--passed"])
        with self.assertRaises(SystemExit): o.main(["adapt", "--report", "fabricated.json"])

    def test_linked_ancestor_and_retained_dex_mutation_rejected(self):
        root = self.base / "run"
        with mock.patch.object(o.r, "linked", side_effect=lambda path: path == self.base):
            with self.assertRaises(ValueError): o.Session(root, [])
        session = o.Session(root, [])
        dex = root / "classes.dex"
        dex.write_bytes(b"INVALID CONTRACT BYTES; NOT LOADED")
        session.retain()
        dex.write_bytes(b"mutated")
        with self.assertRaises(ValueError): session.retain()

    def test_mocked_orchestration_success_is_always_incomplete_and_failure_clears_fragments(self):
        # ALL execution and component-validation seams mocked. No binary is ever loaded.
        inputs = self.base / "inputs"
        inputs.mkdir()
        request_path, bundle, catalog = [inputs / name for name in ("request.json", "invalid.mpp", "catalog.json")]
        raw = b'  {"mocked_contract_only":true}\n\n'
        request_path.write_bytes(raw)
        bundle.write_bytes(b"INVALID; NEVER LOADED")
        catalog.write_bytes(b"{}")
        req = dict(policy=o.s.COLLECTION_POLICY, bundle_sha256=o.p.sha(bundle), catalog_sha256=o.p.sha(catalog), source_tree_sha256=o.r.source_tree(REPO)[0])
        config = dict(java=inputs / "java.exe")
        event = o.p.utcnow()
        def run(session, label, argv):
            directory = session.output / label
            directory.mkdir(exist_ok=label == "inspection")
            if label == "source-jvm":
                for name in ("tests.jar", "checker.jar", "junit-measurements.json"):
                    (directory / name).write_bytes(b"MOCKED CONTRACT ONLY")
            else:
                (directory / "native.json").write_bytes(b"{}")
            if label == "plex":
                (directory / "frozen-request.json").write_bytes(raw)
            session.commands.append(dict(step=label, argv=list(map(str, argv)), exit_code=0,
                started_at=o.p.utcnow(), ended_at=o.p.utcnow(), duration_ns=1))
            session.retain()
        for fails in (False, True):
            out = self.base / ("mock-success" if not fails else "mock-failure")
            with mock.patch.object(o.p, "preflight", return_value=(raw, req)), mock.patch.object(o, "tools", return_value=config), \
                 mock.patch.object(o, "tool_snapshot", return_value={}), mock.patch.object(o.Session, "run", new=run), \
                 mock.patch.object(o, "verify_source_run", return_value=({"executed_cases": 121}, {"ended_at": event}, [])), \
                 mock.patch.object(o, "adapt_inspection", return_value={"mock_contract_only": True}), \
                 mock.patch.object(o, "adapt_plex", side_effect=ValueError("mock failed component") if fails else None, return_value={}), \
                 mock.patch.object(o, "recheck") as recheck, mock.patch.object(o.subprocess, "run") as child:
                result = o.execute(request_path=request_path, bundle=bundle, catalog=catalog, jdk=inputs / "jdk", cache_root=inputs / "cache", output=out)
                child.assert_not_called()
            self.assertFalse(result["complete_evidence"])
            self.assertEqual(result["schema"], "private-jvm-observation-fragments-v1")
            self.assertEqual(result["components"]["manager_import"]["status"], "not-observed")
            self.assertNotIn("manager_import", result["fragments"])
            self.assertNotIn("structural", result["fragments"])
            indexed = o.inventory(out)
            del indexed["partial.json"]
            self.assertEqual(indexed, result["artifact_index"])
            if fails:
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["fragments"], {})
                recheck.assert_not_called()
            else:
                self.assertEqual(result["status"], "incomplete-private-fragments-not-staging-ready", result.get("error"))
                recheck.assert_called_once_with(out)


class InspectionContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inspection-schema-only-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        # Use the trusted synthetic catalog fixture; no MPP or child is involved.
        spec = importlib.util.spec_from_file_location("observation_catalog_fixture", REPO / "tests/test_staging.py")
        ts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ts)
        fixture = ts.CollectionFixture(self.base)
        self.catalog = fixture.catalog
        self.bound = fixture.evidence["inspection"]["binding"]
        self.native = dict(schema="termius-bundle-inspection-v1", status="jvm_actual_loader_metadata_verified", observed_at=END,
            bundle_sha256=self.bound["bundle_sha256"], catalog_sha256=self.bound["catalog_sha256"], patcher_version="2.3.0",
            loader="app.morphe.patcher.patch.loadPatchesFromJar", android_bundle_load="not_observed", dex_check="classes.dex_magic_only_not_ART",
            patches=o.s.collection_inventory(self.catalog, "0.1.0"), dependencies={name: [] for name in sorted(o.s.COLLECTION_PATCHES)},
            about={"name": "FISHYau android patches", "author": "FISHYau"}, signing="unsigned",
            manifest={"name": "FISHYau android patches", "author": "FISHYau", "version": "0.1.0", "patcher-version": "2.3.0"})
        self.path, self.checker = self.base / "native.json", self.base / "checker.jar"
        jar(self.checker)

    def adapt(self):
        save(self.path, self.native)
        return o.adapt_inspection(self.path, self.catalog, self.bound, self.checker, NOW, WINDOW)

    def test_staging_compatible_but_magic_only_and_no_manager(self):
        result = self.adapt()
        self.assertEqual(result["observed_at"], "2026-11-09T10:00:01.000000")
        self.assertEqual(result["patches"], self.native["patches"])
        self.assertEqual(list(result["dependencies"]), sorted(o.s.COLLECTION_PATCHES))
        self.assertNotIn("manager_import", result)
        with self.assertRaises(ValueError): o.s.observation({**result, "binding": {**self.bound, "request_sha256": "0" * 64}}, "bundle-inspection", "jvm", self.bound,
            "target_patcher_load actual_definitions metadata android_dex", {"loader-report"}, NOW, "patcher_version patches dependencies about signing")

    def test_wrong_binding_scope_dtos_and_dates_rejected(self):
        original = copy.deepcopy(self.native)
        for key, value in (("schema", "old"), ("status", "passed"), ("dex_check", "ART passed"), ("android_bundle_load", "passed"),
                           ("bundle_sha256", "0" * 64), ("catalog_sha256", "0" * 64), ("dependencies", {}), ("patches", []),
                           ("about", {}), ("manifest", {}), ("observed_at", "2026-11-08T10:00:01Z")):
            self.native = {**copy.deepcopy(original), key: value}
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)): self.adapt()


class PlexNativeContracts(unittest.TestCase):
    """Invented 23-case retained records, strictly schema tests; no Java is run."""
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="plex-observation-contract-only-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.root = self.base / "plex"
        self.root.mkdir()
        jdk = self.base / "jdk"
        (jdk / "bin/server").mkdir(parents=True)
        (jdk / "lib").mkdir()
        for name in ("release", "bin/java.exe", "bin/server/jvm.dll", "lib/modules"):
            (jdk / name).write_bytes(b"CONTRACT ONLY; NOT EXECUTABLE")
        self.config = dict(jdk=jdk, java=jdk / "bin/java.exe", compiler=[], runtime=[])
        self.bundle, self.catalog = self.base / "invalid.mpp", self.base / "catalog.json"
        self.bundle.write_bytes(b"INVALID SYNTHETIC INPUT; NEVER LOADED")
        spec = importlib.util.spec_from_file_location("plex_observation_catalog_fixture", REPO / "tests/test_staging.py")
        ts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ts)
        catalog_base = self.base / "catalog-fixture"
        catalog_base.mkdir()
        self.catalog_value = ts.CollectionFixture(catalog_base).catalog
        save(self.catalog, self.catalog_value)
        raw = b'  {"contract_only":true}\n\n'
        (self.base / "frozen-request.json").write_bytes(raw)
        (self.root / "frozen-request.json").write_bytes(raw)
        self.bound = dict(policy=o.s.COLLECTION_POLICY, request_sha256=o.r.digest(raw), bundle_sha256=o.p.sha(self.bundle),
                          catalog_sha256=o.p.sha(self.catalog), source_tree_sha256="a" * 64)
        self.request = {key: self.bound[key] for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256")}
        checker = self.root / "checker-tools-only.jar"
        jar(checker)
        cp = str(checker)
        cases = []
        for name in sorted(o.p.CASE_NAMES):
            directory = self.root / "cases" / name
            directory.mkdir(parents=True)
            case = dict(name=name, retained_directory=str(directory), **times(True),
                        status="rejected_without_writes" if name in o.p.NEGATIVES else "resource_bytes_verified",
                        expected_rejection="synthetic rejection" if name in o.p.NEGATIVES else None)
            for key in ("fixture_zip", "input_bundle", "expected_bundle", "output_bundle", "input_manifest", "output_manifest", "unrelated_resource"):
                path = directory / key
                path.write_bytes(b"SYNTHETIC CONTRACT BYTES; NO RESOURCE EXECUTION")
                case[key] = dict(path=str(path), exists=True, bytes=path.stat().st_size, sha256=o.p.sha(path))
            case["working_bundle"] = case["output_bundle"]["path"]
            case["working_manifest"] = case["output_manifest"]["path"]
            if name == "idempotence":
                (directory / "first-output.bundle").write_bytes(Path(case["output_bundle"]["path"]).read_bytes())
            case["execute_calls"] = [dict(index=index, **times(True), exception="app.morphe.patcher.patch.PatchException" if name in o.p.NEGATIVES else None,
                                          message="synthetic rejection") for index in range(1, 3 if name == "idempotence" else 2)]
            cases.append(case)
        self.native = dict(schema="plex-final-bundle-native-v1", status=o.p.SUCCESS, **{key: self.bound[key] for key in ("request_sha256", "bundle_sha256", "catalog_sha256", "source_tree_sha256")},
            actual_definition="exact_three_loaded_metadata_catalog_verified", resource_execution="loaded_plex_raw_resource_patch_all_named_cases_verified",
            loader="app.morphe.patcher.patch.loadPatchesFromJar", executed_patch_names=["Premium unlock"],
            classpath_isolation="definition_and_production_plex_helper_resources_absent", parent_classpath=cp, **times(True), cases=cases,
            patches=o.s.collection_inventory(self.catalog_value, "0.1.0"), dependencies={name: [] for name in sorted(o.s.COLLECTION_PATCHES)})
        expected_inputs = list(dict.fromkeys([REPO / "tools/plex-check/final_bundle.py", REPO / "tools/release/release.py", REPO / "tools/release/staging.py",
            REPO / ".claude/skills/run-android-morphe/templates/cache-closure.json", self.config["java"], jdk / "release", jdk / "bin/server/jvm.dll", jdk / "lib/modules",
            *o.p.select_sources(REPO), self.base / "frozen-request.json", self.bundle, self.catalog]))
        compile_argv = list(map(str, [self.config["java"], "-Xmx1024m", "-Djava.io.tmpdir=" + str(self.root / "tmp"), "-cp", "",
            "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17", "-classpath", "", "-d", checker, *o.p.select_sources(REPO)]))
        native_argv = list(map(str, [self.config["java"], "-Djava.io.tmpdir=" + str(self.root / "tmp"), "-cp", cp,
            "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", self.bundle, self.catalog, self.root / "frozen-request.json", self.root / "native.json",
            self.root / "cases", self.bound["source_tree_sha256"], REPO]))
        commands = []
        for name, argv in (("java-version", [str(self.config["java"]), "-version"]), ("compile", compile_argv), ("actual-final-bundle", native_argv)):
            path = self.root / (name + ".log")
            path.write_bytes(b"SYNTHETIC LOG")
            commands.append(dict(step=name, argv=argv, **times(True), exit_code=0, log={"path": str(path), "sha256": o.p.sha(path)}))
        self.wrapper = dict(schema="plex-final-bundle-wrapper-v1", mode="check", status=o.p.SUCCESS, inputs_unchanged=True,
            request_sha256=self.bound["request_sha256"], source_root=str(REPO), source_tree_sha256=self.bound["source_tree_sha256"],
            source_tree_sha256_after=self.bound["source_tree_sha256"], **times(True), compiled_sources=[str(path.relative_to(REPO)) for path in o.p.select_sources(REPO)],
            checker_sha256=o.p.sha(checker), parent_classpath=cp, parent_classpath_inventory=o.p.isolated_classpath([checker]),
            input_sha256={str(path): o.p.sha(path) for path in expected_inputs}, cases=cases, commands=commands)
        self.write()

    def write(self):
        for case in self.native["cases"]:
            save(Path(case["retained_directory"]) / "case.json", case)
        save(self.root / "native.json", self.native)
        self.wrapper["native_report"] = {"path": str(self.root / "native.json"), "sha256": o.p.sha(self.root / "native.json")}
        save(self.root / "checker.json", self.wrapper)

    def adapt(self):
        return o.adapt_plex(self.root, self.request, self.bound, self.config, NOW, WINDOW, self.bundle, self.catalog)

    def test_exact_native23_contract_retained_files_not_aggregate_only(self):
        result = self.adapt()
        self.assertEqual(set(result), {"resource", "final_bundle"})
        for key, fragment in result.items():
            self.assertEqual(fragment["observed_at"], "2026-11-09T10:00:01.000000")
            kind, checks, kinds = o.s.PLEX_REPORTS[key]
            o.s.observation(fragment, kind, "jvm", self.bound, checks, kinds, NOW)
        self.assertNotIn("parser", result)  # Parser is source-tested separately, not final-MPP execution.

    def test_compile_only_failed_partial_and_old_reports_rejected(self):
        original = copy.deepcopy(self.wrapper)
        for key, value in (("schema", "old"), ("status", "compile_only_no_final_bundle_observation"), ("status", "failed"),
                           ("mode", "compile-only"), ("inputs_unchanged", False), ("cases", []), ("commands", []), ("input_sha256", {}),
                           ("parent_classpath", str(self.base / "tests.jar")), ("request_sha256", "0" * 64)):
            self.wrapper = {**copy.deepcopy(original), key: value}
            self.write()
            with self.subTest(key=key, value=value), self.assertRaises((ValueError, KeyError, TypeError)): self.adapt()

    def test_native_missing_duplicate_selection_or_cases_rejected(self):
        original = copy.deepcopy(self.native)
        for key, value in (("cases", []), ("cases", original["cases"][:-1]), ("cases", original["cases"] + original["cases"][:1]),
                           ("executed_patch_names", ["Premium unlock", "Premium unlock"]), ("executed_patch_names", ["Server Auditor Premium"]),
                           ("bundle_sha256", "0" * 64), ("resource_execution", "passed"), ("finished_at", "2026-11-08T00:00:00Z")):
            self.native = {**copy.deepcopy(original), key: value}
            self.wrapper["cases"] = self.native["cases"]
            self.write()
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)): self.adapt()

    def test_native_case_must_be_inside_native_run_not_just_child(self):
        self.wrapper.update(started_at="2026-11-09T09:59:00Z", finished_at="2026-11-09T10:01:00Z")
        self.wrapper["commands"][-1].update(started_at="2026-11-09T09:59:30Z", finished_at="2026-11-09T10:00:30Z")
        self.native["cases"][0]["finished_at"] = "2026-11-09T10:00:02Z"
        self.write()
        with self.assertRaises(ValueError): self.adapt()

    def test_native_call_must_be_inside_case_not_just_child(self):
        self.native["cases"][0]["execute_calls"][0]["finished_at"] = "2026-11-09T10:00:02Z"
        self.native.update(started_at="2026-11-09T09:59:00Z", finished_at="2026-11-09T10:01:00Z")
        self.wrapper.update(started_at="2026-11-09T09:59:00Z", finished_at="2026-11-09T10:01:00Z")
        self.wrapper["commands"][-1].update(started_at="2026-11-09T09:59:00Z", finished_at="2026-11-09T10:01:00Z")
        self.write()
        with self.assertRaises(ValueError): self.adapt()

    def test_native_command_must_be_inside_wrapper_not_just_outer_child(self):
        self.wrapper["commands"][0]["started_at"] = "2026-11-09T09:59:30Z"
        self.write()
        with self.assertRaises(ValueError): self.adapt()

    def test_native_logs_resources_fixtures_tools_and_inputs_cannot_mutate(self):
        case = self.native["cases"][0]
        paths = [self.root / "actual-final-bundle.log", self.root / "checker-tools-only.jar", self.bundle, self.config["java"],
                 Path(case["fixture_zip"]["path"]), Path(case["output_bundle"]["path"]), Path(case["unrelated_resource"]["path"]),
                 self.root / "frozen-request.json"]
        for path in paths:
            original = path.read_bytes()
            path.write_bytes(original + b"tamper")
            with self.subTest(path=path.name), self.assertRaises((ValueError, KeyError, zipfile.BadZipFile)): self.adapt()
            path.write_bytes(original)

    def test_retained_case_record_mutation_and_escape_rejected(self):
        case = self.native["cases"][0]
        case_json = Path(case["retained_directory"]) / "case.json"
        case_json.write_text("{}")
        with self.assertRaises(ValueError): self.adapt()
        self.write()
        case["fixture_zip"]["path"] = str(self.base / "outside")
        self.write()
        with self.assertRaises(ValueError): self.adapt()


if __name__ == "__main__":
    unittest.main()
