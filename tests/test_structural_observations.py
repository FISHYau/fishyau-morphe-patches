"""Invented native records/mocked children ONLY. Invalid binaries never execute."""
import copy
from contextlib import ExitStack
import datetime as dt
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("structural_identity_fixture", REPO / "tests/test_selected_identity.py")
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
o, si = t.o, t.si
NOW = dt.datetime(2026, 11, 9, 12, tzinfo=dt.timezone.utc)
EVENT = "2026-11-09T10:00:00Z"
WINDOW = ("2026-11-09T09:59:00.000000", "2026-11-09T10:01:00.000000")


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


def jar(path):
    with zipfile.ZipFile(path, "w") as stream: stream.writestr("tools/Synthetic.class", b"NEVER EXECUTABLE")


def timing(event):
    return dict(started_at=event, ended_at=event, elapsed_ns=1)


def synthetic_interpreter(root, stack):
    """Canonical nonexecutable placeholder; callers must mock every subprocess.

    Patching o.sys also changes the process-wide sys module until stack closes.
    """
    path = root / "python-NONEXECUTABLE.fixture"
    path.write_bytes(b"SYNTHETIC INTERPRETER PLACEHOLDER; NEVER EXECUTE")
    path.chmod(0o600)
    path = si.canonical(path)
    stack.enter_context(mock.patch.object(o.sys, "executable", str(path)))
    return path


class StructuralFixture:
    def __init__(self, root, identity, source, catalog, bundle, bound, event=EVENT):
        self.root, self.identity, self.source, self.catalog, self.bundle, self.bound = root, identity, source, catalog, bundle, bound
        root.mkdir()
        self.work = o.structural_work(root)
        self.work.mkdir()
        # Model retained Patcher working DEX, not additional semantic emissions.
        for relative in ("temporary/patched/dex/classes.dex", "temporary/patched/originalDex/classes2.dex",
                         "widget-only/maker-temporary/patched/dex/classes.dex", "combined-temporary/patched/dex/classes.dex"):
            path = self.work / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"SYNTHETIC SCRATCH; NEVER DEX-LOADED")
        cp = [source / "checker.jar"]
        names = [row[2] for row in o.POSITIVES] + [name + "/rejected-dex" for name in o.NEGATIVES]
        names += [name + "/fixture-dex" for name in o.NEGATIVES if name not in ("repeat", "premium-repeat")]
        outputs = {}
        for name in names:
            directory = root / name
            directory.mkdir(parents=True)
            dex = directory / "classes.dex"
            dex.write_bytes(("SYNTHETIC NON-DEX " + name).encode())
            inventory = [dict(name=dex.name, **o.file_record(dex))]
            manifest = directory.parent / (directory.name + "-manifest.tsv")
            data = f"classes.dex\t{dex.stat().st_size}\t{o.p.sha(dex)}\n".encode()
            manifest.write_bytes(data)
            outputs[name] = dict(directory=str(directory), dex_inventory=inventory, manifest_path=str(manifest), output_sha256=o.r.digest(data), manifest_format=o.MANIFEST_FORMAT)
        for name, (_, _, _, maker) in o.NEGATIVES.items():
            fixture = root / name / "fixture-NOT-INSTALLABLE.apk"
            with zipfile.ZipFile(fixture, "w") as archive, zipfile.ZipFile(identity.members["base.apk"]) as original:
                for item in original.infolist():
                    if not (item.filename.startswith("classes") and item.filename.endswith(".dex")):
                        archive.writestr(item.filename, original.read(item))
                for item in outputs[maker]["dex_inventory"]:
                    archive.writestr(item["name"], (Path(outputs[maker]["directory"]) / item["name"]).read_bytes())
        spec = importlib.util.spec_from_file_location("structural_catalog_fixture", REPO / "tests/test_staging.py")
        ts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ts)
        catalog_root = root.parent / (root.name + "-catalog-fixture")
        catalog_root.mkdir()
        self.catalog_value = ts.CollectionFixture(catalog_root).catalog
        # The caller has already fixed the catalog/binding; only standalone fixtures write it.
        if not catalog.exists(): save(catalog, self.catalog_value)
        self.native = dict(schema="termius-structural-check-v3", status="bounded_structural_checks_passed", **timing(event), observed_at=event,
            invocation=list(map(str, [bundle, identity.members["base.apk"], root, catalog, REPO])),
            request_authority="parent_exact_request2_preflight_only", parent_classpath=str(cp[0]), work_directory=str(self.work),
            bundle_sha256=bound["bundle_sha256"], catalog_sha256=o.p.sha(catalog), input_base_sha256=o.p.sha(identity.members["base.apk"]),
            patches=o.s.collection_inventory(o.read(catalog), "0.1.0"), dependencies={name: [] for name in sorted(o.s.COLLECTION_PATCHES)},
            patcher_version="2.3.0", definition_scope="exact_three_collection_definitions", application_scope="Termius_only_singletons_and_combined",
            plex_application="not_supported_not_attempted", snapshot_digest_format=o.DIGEST_FORMAT,
            android_bundle_load="not_observed", manager_import="not_observed", device_behavior="not_observed",
            output_kind="unsigned_incomplete_noninstallable_structural_fixtures", comparison_scope=dict(kind="selected_classes_only_not_whole_app",
                methods=127, explicit_owners=o.OWNERS.copy(), nested_owner_prefixes=[o.LOCAL_EDITOR[:-1] + "$", o.PRESENTER[:-1] + "$"], method_data=o.METHOD_DATA),
            emitted_outputs=list(outputs.values()), checks=["PASS TEXT IS NOT EVIDENCE"], selections=[],
            negative_cases=["repeat", "premium-repeat", *[name for name in o.NEGATIVES if name not in ("repeat", "premium-repeat")]], negative_measurements=[])
        for names, changed, directory in o.POSITIVES:
            self.native["selections"].append(dict(selected=names.copy(), changed_methods=changed.copy(), changed_method_count=len(changed),
                compared_methods=127, status="applied_emitted_reread_verified", reread_verified=True, controlflow_verified=True,
                patch_results=[dict(name=name, error=None) for name in names], emitted=copy.deepcopy(outputs[directory]), **timing(event)))
        for name, (diagnostic, already, selected, _) in o.NEGATIVES.items():
            message = diagnostic + (" already patched" if already else " invalid shape")
            fixture = root / name / "fixture-NOT-INSTALLABLE.apk"
            self.native["negative_measurements"].append(dict(name=name, selected=[selected], expected_diagnostic=diagnostic,
                requires_already_patched=already, diagnostic_matched=True, rejection_diagnostic=message,
                patch_results=[dict(name=selected, error="SyntheticException: " + message)], before_snapshot_sha256="a" * 64,
                after_snapshot_sha256="a" * 64, snapshots_equal=True, compared_methods=127,
                status="expected_rejection_unchanged_bounded_snapshot", fixture_path=str(fixture), fixture_sha256=o.p.sha(fixture),
                emitted=copy.deepcopy(outputs[name + "/rejected-dex"]), **timing(event)))
        self.write()

    def write(self):
        save(self.root / "structural-check.json", self.native)

    def adapt(self, now=NOW, window=WINDOW):
        self.write()
        return o.adapt_structural(self.root, self.catalog, self.bound, self.identity.members["base.apk"], [self.source / "checker.jar"],
            self.source, now, window, self.bundle)


class StructuralContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="structural-contract-ONLY-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        inputs = self.base / "inputs"
        inputs.mkdir()
        self.identity = t.IdentityFixture(inputs, self.stack)
        self.source = self.base / "source-jvm"
        self.source.mkdir()
        jar(self.source / "checker.jar")
        (self.source / "junit-measurements.json").write_bytes(b"SCHEMA TEST ONLY; no JUnit executed")
        self.bundle, catalog = self.base / "invalid.mpp", self.base / "catalog.json"
        self.bundle.write_bytes(b"NOT MPP; NEVER LOADED")
        bound = dict(policy=o.s.COLLECTION_POLICY, request_sha256="1" * 64, bundle_sha256=o.p.sha(self.bundle), catalog_sha256="2" * 64, source_tree_sha256="3" * 64)
        self.fixture = StructuralFixture(self.base / "termius", self.identity, self.source, catalog, self.bundle, bound)
        bound["catalog_sha256"] = o.p.sha(catalog)

    def test_exact_bounded_fragments_are_synthetic_not_actual_verification(self):
        result = self.fixture.adapt()
        self.assertEqual([row["selection"] for row in result], [row[0] for row in o.POSITIVES])
        self.assertEqual(len(result), 3)
        for row in result:
            self.assertIn("shared nine singleton", row["scope"])
            self.assertIn("NOT whole APK", row["scope"])
            self.assertEqual(row["observed_at"], "2026-11-09T10:00:00.000000")
        # Logs/check strings can be entirely absent; actual measurements are authoritative.
        self.fixture.native.pop("checks")
        adapted = self.fixture.adapt()
        self.assertEqual([row["output_sha256"] for row in result], [row["output_sha256"] for row in adapted])
        self.assertEqual([row["checks"] for row in result], [row["checks"] for row in adapted])

    def test_wrong_schema_aggregate_binding_invocation_metadata_scope_and_nonobserved_fields(self):
        original = copy.deepcopy(self.fixture.native)
        mutations = [("schema", "termius-structural-check-v2"), ("status", "PASS"), ("bundle_sha256", "0" * 64),
            ("catalog_sha256", "0" * 64), ("input_base_sha256", "0" * 64), ("invocation", []),
            ("request_authority", "independent request validation"), ("parent_classpath", "definitions.jar"),
            ("work_directory", str(self.base / "arbitrary-sibling")), ("work_directory", str(self.fixture.root)),
            ("patches", []), ("dependencies", {}), ("patcher_version", "2.4.0"), ("application_scope", "all apps"),
            ("definition_scope", "two definitions"), ("plex_application", "passed"), ("android_bundle_load", "passed"),
            ("manager_import", "passed"), ("device_behavior", "passed"), ("output_kind", "installable"),
            ("snapshot_digest_format", "aggregate")]
        for key, value in mutations:
            self.fixture.native = {**copy.deepcopy(original), key: value}
            with self.subTest(key=key), self.assertRaises((ValueError, KeyError)): self.fixture.adapt()

    def test_each_positive_exact_methods_result_multiplicity_and_booleans(self):
        original = copy.deepcopy(self.fixture.native)
        for index in range(3):
            for mutate in (lambda x: x["selected"].append(o.PREMIUM), lambda x: x["changed_methods"].pop(),
                lambda x: x.update(changed_method_count=True), lambda x: x.update(compared_methods=126),
                lambda x: x["patch_results"].append(x["patch_results"][0]), lambda x: x["patch_results"][0].update(error="FAIL"),
                lambda x: x.update(reread_verified=1), lambda x: x.update(controlflow_verified="true"),
                lambda x: x.update(emitted=self.fixture.native["emitted_outputs"][-1])):
                self.fixture.native = copy.deepcopy(original)
                mutate(self.fixture.native["selections"][index])
                with self.subTest(index=index), self.assertRaises((ValueError, KeyError)): self.fixture.adapt()
        for rows in (original["selections"][:-1], original["selections"] + original["selections"][:1], list(reversed(original["selections"]))):
            self.fixture.native = {**copy.deepcopy(original), "selections": rows}
            with self.assertRaises(ValueError): self.fixture.adapt()

    def test_each_negative_exact_selection_result_diagnostic_snapshots_and_fixture(self):
        original = copy.deepcopy(self.fixture.native)
        for index in range(9):
            for mutate in (lambda x: x.update(selected=[o.OFFLINE, o.PREMIUM]), lambda x: x["patch_results"].append(x["patch_results"][0]),
                lambda x: x["patch_results"][0].update(name="unrelated failure"), lambda x: x["patch_results"][0].update(error=None),
                lambda x: x.update(expected_diagnostic="anything"), lambda x: x.update(rejection_diagnostic="wrong rejection"),
                lambda x: x.update(diagnostic_matched=1), lambda x: x.update(requires_already_patched=not x["requires_already_patched"]),
                lambda x: x.update(after_snapshot_sha256="b" * 64), lambda x: x.update(snapshots_equal=1),
                lambda x: x.update(compared_methods=True), lambda x: x.update(fixture_sha256="b" * 64),
                lambda x: x.update(fixture_path=str(self.base / "escape.apk"))):
                self.fixture.native = copy.deepcopy(original)
                mutate(self.fixture.native["negative_measurements"][index])
                with self.subTest(index=index), self.assertRaises((ValueError, KeyError)): self.fixture.adapt()
        for field in ("negative_measurements", "negative_cases"):
            for mutate in (lambda x: x.pop(), lambda x: x.append(x[0]), lambda x: x.reverse()):
                self.fixture.native = copy.deepcopy(original)
                mutate(self.fixture.native[field])
                with self.assertRaises(ValueError): self.fixture.adapt()

    def test_scope_owners_prefixes_counts_and_method_data_exact(self):
        for key, value in (("explicit_owners", o.OWNERS[:-1]), ("nested_owner_prefixes", []), ("methods", True),
                           ("methods", 0), ("method_data", "whole APK"), ("kind", "whole_app")):
            original = copy.deepcopy(self.fixture.native)
            self.fixture.native["comparison_scope"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.fixture.adapt()
            self.fixture.native = original

    def test_native_case_and_producer_timings_are_not_aggregate_dates(self):
        original = copy.deepcopy(self.fixture.native)
        for target in ("run", "selection", "negative"):
            for key, value in (("elapsed_ns", True), ("elapsed_ns", 0), ("started_at", "2026-11-09T09:58:00Z"),
                               ("ended_at", "2026-11-09T10:02:00Z"), ("started_at", "2026-11-09T10:00:00")):
                self.fixture.native = copy.deepcopy(original)
                row = self.fixture.native if target == "run" else self.fixture.native["selections" if target == "selection" else "negative_measurements"][0]
                row[key] = value
                with self.subTest(target=target, key=key), self.assertRaises(ValueError): self.fixture.adapt()

    def test_missing_duplicate_substituted_unreferenced_and_escaped_output_graphs(self):
        original = copy.deepcopy(self.fixture.native)
        mutations = [lambda x: x["emitted_outputs"].pop(), lambda x: x["emitted_outputs"].append(x["emitted_outputs"][0]),
            lambda x: x["emitted_outputs"].__setitem__(1, x["emitted_outputs"][0]),
            lambda x: x["emitted_outputs"][0].update(directory=str(self.base)),
            lambda x: x["emitted_outputs"][0].update(manifest_path=str(self.base / "outside.tsv")),
            lambda x: x["emitted_outputs"][0].update(output_sha256="0" * 64),
            lambda x: x["emitted_outputs"][0]["dex_inventory"][0].update(size=True)]
        for mutate in mutations:
            self.fixture.native = copy.deepcopy(original)
            mutate(self.fixture.native)
            with self.assertRaises((ValueError, KeyError)): self.fixture.adapt()

    def test_retained_dex_manifest_and_noncanonical_file_mutations(self):
        for path in (self.fixture.root / "dex/classes.dex", self.fixture.root / "dex-manifest.tsv",
                     self.fixture.root / "widget-only/fixture-dex/classes.dex", self.fixture.root / "repeat/fixture-NOT-INSTALLABLE.apk"):
            original = path.read_bytes()
            path.write_bytes(original + b"MUTATED")
            with self.subTest(path=path), self.assertRaises((ValueError, si.canonical_driver().DriverError)): self.fixture.adapt()
            path.write_bytes(original)
        for relative in ("dex/classes3.dex", "unreferenced/classes.dex", "unreferenced.tsv", "unreferenced.apk"):
            path = self.fixture.root / relative
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(b"extra")
            with self.subTest(relative=relative), self.assertRaises((ValueError, si.canonical_driver().SPLITSET.SplitSetError)): self.fixture.adapt()
            path.unlink()

    def test_scratch_is_separate_not_an_exclusion_in_semantic_tree(self):
        self.assertEqual(self.base / "termius-work", self.fixture.work)
        fragments = self.fixture.adapt()
        self.assertEqual(3, len(fragments))
        self.assertEqual(19, len(self.fixture.native["emitted_outputs"]))
        # The old scratch spelling INSIDE semantic output must still be rejected.
        unexpected = self.fixture.root / "temporary/patched/dex/classes.dex"
        unexpected.parent.mkdir(parents=True)
        unexpected.write_bytes(b"UNDECLARED SEMANTIC DEX")
        with self.assertRaisesRegex(ValueError, "unreferenced DEX"):
            self.fixture.adapt()

    def test_missing_or_unreported_scratch_root_is_rejected(self):
        self.fixture.native.pop("work_directory")
        with self.assertRaises(KeyError): self.fixture.adapt()
        self.fixture.native["work_directory"] = str(self.fixture.work)
        moved = self.fixture.work.with_name("moved-work")
        self.fixture.work.rename(moved)
        with self.assertRaises(ValueError): self.fixture.adapt()

    def test_empty_reparse_scratch_directory_is_rejected(self):
        empty = self.fixture.work / "empty-reparse"
        empty.mkdir()
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            if path == empty:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "lstat", new=lstat), self.assertRaisesRegex(ValueError, "reparse"):
            self.fixture.adapt()

    def test_exact_structural_invocation_and_source_work_binding(self):
        root = self.fixture.root
        argv = o.structural_argv(dict(java=Path("java")), [self.source / "checker.jar"], self.bundle,
            self.identity.members["base.apk"], root, self.fixture.catalog)
        self.assertEqual(["java", "-Djava.io.tmpdir=" + str(root.parent), "-cp", str(self.source / "checker.jar"),
            "RuntimeCheckKt", str(self.bundle), str(self.identity.members["base.apk"]), str(root), str(self.fixture.catalog), str(REPO)], argv)
        kotlin = (REPO / "tools/termius-check/src/main/kotlin/RuntimeCheck.kt").read_text(encoding="utf-8")
        self.assertIn('val work = parent.resolve(output.name + "-work")', kotlin)
        self.assertIn('"work_directory" to work.absolutePath', kotlin)
        self.assertIn('reserveStructuralDirectories(File(args[2]), source, listOf(bundle, input, catalog))', kotlin)
        for call in ('config(input, work.resolve("temporary"))',
                     'config(fixture, work.resolve(directory.name).resolve("temporary"))',
                     'config(input, work.resolve(directory.name).resolve("maker-temporary"))',
                     'config(input, work.resolve("premium-temporary"))', 'config(input, work.resolve("combined-temporary"))'):
            self.assertEqual(1, kotlin.count(call))
        self.assertNotIn('config(input, output.resolve(', kotlin)
        self.assertNotIn('config(fixture, directory.resolve(', kotlin)

    def test_fixture_maker_payload_cannot_be_substituted_even_with_fresh_hashes(self):
        # Rebind a maker inventory AND its manifest: only the graph edge catches it.
        row = next(row for row in self.fixture.native["emitted_outputs"] if Path(row["directory"]).relative_to(self.fixture.root).as_posix() == "widget-only/fixture-dex")
        path = Path(row["directory"]) / "classes.dex"
        path.write_bytes(b"substituted fixture maker")
        row["dex_inventory"] = [dict(name=path.name, **o.file_record(path))]
        data = f"classes.dex\t{path.stat().st_size}\t{o.p.sha(path)}\n".encode()
        Path(row["manifest_path"]).write_bytes(data)
        row["output_sha256"] = o.r.digest(data)
        with self.assertRaisesRegex(ValueError, "fixture-maker"): self.fixture.adapt()

    def test_empty_nonjunction_reparse_output_is_rejected(self):
        empty = self.fixture.root / "empty-reparse"
        empty.mkdir()
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            if path == empty:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(path, *args, **kwargs)
        with mock.patch.object(Path, "lstat", new=lstat), self.assertRaisesRegex(ValueError, "reparse"):
            self.fixture.adapt()

    def test_contained_but_out_of_execution_order_measurements_rejected(self):
        self.fixture.native.update(ended_at="2026-11-09T10:00:10Z", observed_at="2026-11-09T10:00:10Z")
        self.fixture.native["negative_measurements"][0].update(started_at="2026-11-09T10:00:02Z", ended_at="2026-11-09T10:00:03Z")
        with self.assertRaisesRegex(ValueError, "execution order"):
            self.fixture.adapt()

    def test_failed_terminal_native_is_never_promoted(self):
        (self.fixture.root / "structural-check-failed.json").write_text('{}')
        with self.assertRaises(ValueError): self.fixture.adapt()


class GuardContracts(unittest.TestCase):
    def test_failed_child_postchecks_preserve_both_errors(self):
        session = SimpleNamespace(run=mock.Mock(side_effect=ValueError("original child failure")))
        measure = mock.Mock(side_effect=[dict(errors=[], value=1), dict(errors=["changed tool"], value=2)])
        record = dict(baseline=dict(errors=[], value=1), checks=[])
        with self.assertRaisesRegex(ValueError, "original child failure.*post-use"):
            o.guarded_identity_child(session, "identity", ["NEVER EXECUTE"], measure, record)
        self.assertEqual(measure.call_count, 2)
        self.assertIn("original child failure", record["checks"][0]["primary_error"])
        self.assertIn("closure_error", record["checks"][0])

    def test_timeout_still_attempts_postcheck_and_is_nonquiescent(self):
        session = SimpleNamespace(run=mock.Mock(side_effect=subprocess.TimeoutExpired("MOCK", 1)))
        measure = mock.Mock(return_value=dict(errors=[]))
        record = dict(baseline=dict(errors=[]), checks=[])
        with self.assertRaises(subprocess.TimeoutExpired): o.guarded_identity_child(session, "identity", ["MOCK"], measure, record)
        self.assertEqual(measure.call_count, 2)
        self.assertEqual(record["checks"][0]["quiescence"], "not-established")
        session.run.assert_called_once()

    def test_precheck_failure_prevents_child_and_finally_is_not_skipped(self):
        session = SimpleNamespace(run=mock.Mock())
        record = dict(baseline=dict(errors=[], value=1), checks=[])
        measure = mock.Mock(return_value=dict(errors=[], value=2))
        with self.assertRaises(ValueError): o.guarded_identity_child(session, "identity", ["MOCK"], measure, record)
        self.assertEqual(measure.call_count, 2)
        session.run.assert_not_called()

    def test_session_log_failure_cannot_mask_timeout_or_nonzero_exit(self):
        with tempfile.TemporaryDirectory(prefix="session-failure-contract-ONLY-") as scratch:
            root = Path(scratch).resolve()
            for label in ("timeout", "nonzero"):
                session = o.Session(root / label, [])
                def respond(*args, **kwargs):
                    (session.output / (label + ".log")).write_bytes(b"SYNTHETIC log collision")
                    if label == "timeout":
                        raise subprocess.TimeoutExpired("MOCK", 1, output=b"partial")
                    return SimpleNamespace(returncode=7, stdout=b"mocked", stderr=b"")
                with mock.patch.object(o.subprocess, "run", side_effect=respond):
                    with self.assertRaises(subprocess.TimeoutExpired if label == "timeout" else ValueError):
                        session.run(label, ["NEVER EXECUTE"])
                row = session.commands[0]
                self.assertIn("inventory_error", row)
                self.assertIn("TimeoutExpired" if label == "timeout" else "child failed", row["error"])
                if label == "timeout": self.assertTrue(row["timed_out"])
                else: self.assertEqual(row["exit_code"], 7)

    def test_closure_attempts_all_categories_after_one_probe_fails(self):
        with tempfile.TemporaryDirectory(prefix="closure-interpreter-ONLY-") as scratch, ExitStack() as stack:
            child = stack.enter_context(mock.patch.object(o.subprocess, "run", side_effect=AssertionError("NEVER EXECUTE")))
            interpreter = synthetic_interpreter(Path(scratch).resolve(), stack)
            self.assertTrue(stat.S_ISREG(interpreter.stat().st_mode))
            self.assertFalse(interpreter.stat().st_mode & 0o111)
            selection = stack.enter_context(mock.patch.object(si, "snapshot_selection", side_effect=ValueError("bad member")))
            source = stack.enter_context(mock.patch.object(o.f, "pristine_tree", return_value=("hash", [])))
            stack.enter_context(mock.patch.object(o, "strict_tree_paths"))
            tools = stack.enter_context(mock.patch.object(o, "tool_snapshot", return_value={}))
            files = stack.enter_context(mock.patch.object(si, "record", return_value={}))
            result = o.identity_closure({}, dict(jdk=REPO, runtime=[], compiler=[]), [], Path("request"), Path("bundle"), Path("catalog"), Path("out"), {})
        self.assertEqual(result["errors"], ["selection: ValueError: bad member"])
        selection.assert_called_once_with({})
        source.assert_called_once()
        tools.assert_called_once()
        self.assertEqual(files.call_count, 4)
        child.assert_not_called()

    def test_original_interpreter_symlink_is_rejected_before_tool_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="closure-interpreter-link-ONLY-") as scratch, ExitStack() as stack:
            root = Path(scratch).resolve()
            child = stack.enter_context(mock.patch.object(o.subprocess, "run", side_effect=AssertionError("NEVER EXECUTE")))
            interpreter = synthetic_interpreter(root, stack)
            link = root / "python-link.fixture"
            try:
                link.symlink_to(interpreter)
            except (OSError, NotImplementedError) as exc:
                self.skipTest("symlink creation unavailable: " + str(exc))
            # Keep the original link spelling: resolving here would hide the bug.
            stack.enter_context(mock.patch.object(o.sys, "executable", str(link)))
            selection = stack.enter_context(mock.patch.object(si, "snapshot_selection", return_value={}))
            source = stack.enter_context(mock.patch.object(o.f, "pristine_tree", return_value=("hash", [])))
            stack.enter_context(mock.patch.object(o, "strict_tree_paths"))
            tools = stack.enter_context(mock.patch.object(o, "tool_snapshot", return_value={}))
            files = stack.enter_context(mock.patch.object(si, "record", return_value={}))
            result = o.identity_closure({}, dict(jdk=REPO, runtime=[], compiler=[]), [], Path("request"), Path("bundle"), Path("catalog"), Path("out"), {})
        self.assertEqual(result["errors"], ["tools: ValueError: reparse/link ancestry forbidden"])
        selection.assert_called_once_with({})
        source.assert_called_once()
        tools.assert_not_called()
        self.assertEqual(files.call_count, 4)
        child.assert_not_called()


class SelectedOrchestrationContracts(unittest.TestCase):
    """Synthetic end-to-end parent/recheck, with every subprocess mocked."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="selected-orchestration-ONLY-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        inputs = self.base / "inputs"
        inputs.mkdir()
        self.identity = t.IdentityFixture(inputs, self.stack)
        self.request_path, self.bundle, self.catalog = [inputs / name for name in ("request.json", "invalid.mpp", "catalog.json")]
        self.raw = b'  {"mocked_contract_only":true}\n'
        self.request_path.write_bytes(self.raw)
        self.bundle.write_bytes(b"INVALID SYNTHETIC MPP; NEVER LOADED")
        spec = importlib.util.spec_from_file_location("selected_parent_catalog_fixture", REPO / "tests/test_staging.py")
        ts = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ts)
        catalog_root = self.base / "catalog-fixture"
        catalog_root.mkdir()
        save(self.catalog, ts.CollectionFixture(catalog_root).catalog)
        self.request = dict(policy=o.s.COLLECTION_POLICY, bundle_sha256=o.p.sha(self.bundle), catalog_sha256=o.p.sha(self.catalog),
            source_tree_sha256=o.r.source_tree(REPO)[0], created_at=(dt.datetime.now(o.r.UTC) - dt.timedelta(hours=1)).replace(tzinfo=None).isoformat())
        self.config = dict(java=self.identity.java, jdk=inputs, runtime=[], compiler=[])
        self.cache = inputs / "cache"
        self.cache.mkdir()
        self.events, self.calls = {}, []
        self.mode = "success"
        self.output = self.base / "run"
        self.stack.enter_context(mock.patch.object(o.p, "preflight", return_value=(self.raw, self.request)))
        self.stack.enter_context(mock.patch.object(o, "tools", return_value=self.config))
        self.stack.enter_context(mock.patch.object(o, "tool_snapshot", return_value={}))
        self.stack.enter_context(mock.patch.object(o, "verify_source_run", side_effect=lambda root, *args: ({"executed_cases": 121},
            {"ended_at": self.events["source"]}, [root / "checker.jar", *self.config["runtime"]])))
        self.stack.enter_context(mock.patch.object(o, "adapt_inspection", return_value={"mock_contract": True}))
        self.stack.enter_context(mock.patch.object(o, "adapt_plex", return_value={}))
        self.child = self.stack.enter_context(mock.patch.object(o.subprocess, "run", side_effect=self.respond))
        self.interpreter = synthetic_interpreter(self.base, self.stack)

    def respond(self, argv, **kwargs):
        if "--scope" in argv:
            label = "source"
            root = self.output / "source-jvm"
            root.mkdir()
            jar(root / "checker.jar")
            jar(root / "tests.jar")
            (root / "junit-measurements.json").write_bytes(b"NO TEST EXECUTION")
            self.events[label] = o.p.utcnow()
            if self.mode == "stale": save(self.output / "selected-verification.json", self.identity.verification())
        elif "verify-apks" in argv:
            label = "identity"
            report = self.identity.verification()
            if self.mode == "bad-verifier": report["apks"][0]["manifest"]["package"] = "wrong.package"
            save(self.output / "selected-verification.json", report)
            if self.mode == "stale-work":
                work = o.structural_work(self.output / "termius-structural")
                work.mkdir()
                (work / "retain-existing").write_bytes(b"PREEXISTING; MUST NOT BE REUSED OR CLEANED")
            if self.mode in ("failed-child", "timeout"):
                self.identity.paths["aapt2"].write_bytes(b"changed during mocked child")
                self.calls.append(label)
                if self.mode == "timeout": raise subprocess.TimeoutExpired("MOCK ONLY", 1, output=b"partial synthetic")
                return SimpleNamespace(returncode=7, stdout=b"mock failure", stderr=b"")
        elif "RuntimeCheckKt" in argv:
            label = "structural"
            StructuralFixture(self.output / "termius-structural", self.identity, self.output / "source-jvm", self.catalog, self.bundle,
                o.binding(self.request, self.raw), event=o.p.utcnow())
        elif "--request" in argv:
            label = "plex"
            (self.output / "plex").mkdir()
            (self.output / "plex/frozen-request.json").write_bytes(self.raw)
        else:
            label = "inspection"
            (self.output / "inspection/native.json").write_bytes(b"{}")
        self.calls.append(label)
        return SimpleNamespace(returncode=0, stdout=b"MOCKED CHILD ONLY", stderr=b"")

    def execute(self):
        return o.execute(request_path=self.request_path, bundle=self.bundle, catalog=self.catalog, jdk=self.identity.root,
            cache_root=self.cache, output=self.output, termius_selection=self.identity.descriptor)

    def test_synthetic_success_recheck_reconstructs_and_never_becomes_ready(self):
        report = self.execute()
        self.assertEqual(report["status"], "incomplete-private-fragments-not-staging-ready", report.get("error"))
        self.assertFalse(report["complete_evidence"])
        self.assertEqual(self.calls, ["source", "inspection", "plex", "identity", "structural"])
        self.assertEqual(len(report["fragments"]["structural"]), 3)
        before_calls = self.child.call_count
        self.assertEqual(o.recheck(self.output)["fragments"], report["fragments"])
        self.assertEqual(self.child.call_count, before_calls)  # no re-execution in recheck
        report["fragments"]["structural"][0]["selection"] = [o.PREMIUM]
        save(self.output / "partial.json", report)
        with self.assertRaisesRegex(ValueError, "fragments changed"): o.recheck(self.output)

    def test_persistent_replacement_before_baseline_never_reaches_either_child(self):
        original = o.identity_closure
        for name in ("bundle", "catalog", "request", "request-copy", "checker", "runtime"):
            with self.subTest(name=name):
                self.output = self.base / ("replacement-" + name)
                self.calls.clear()
                runtime = self.cache / "synthetic-runtime.jar"
                jar(runtime)
                self.config["runtime"] = [runtime]
                before_tools = {"dependencies": {runtime.relative_to(self.cache).as_posix(): o.file_record(runtime)}}
                self.config["cache"] = self.cache
                target = {"bundle": self.bundle, "catalog": self.catalog, "request": self.request_path,
                    "request-copy": self.output / "frozen-request.json", "checker": self.output / "source-jvm/checker.jar",
                    "runtime": runtime}[name]
                saved = []
                def replace(*args):
                    if not saved:
                        saved.append(target.read_bytes())
                        target.write_bytes(b"PERSISTENT replacement; all children mocked")
                    return original(*args)
                try:
                    with mock.patch.object(o, "tool_snapshot", return_value=before_tools), \
                         mock.patch.object(o, "identity_closure", side_effect=replace):
                        report = self.execute()
                    self.assertEqual(report["status"], "failed")
                    self.assertEqual(report["fragments"], {})
                    self.assertEqual(self.calls, ["source", "inspection", "plex"])
                    self.assertEqual(report["termius_identity"]["checks"], [])
                finally:
                    if saved: target.write_bytes(saved[0])

    def test_present_invalid_selection_fails_whole_run_not_silent_omission(self):
        self.identity.descriptor.write_text('{"schema":"bad"}')
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.child.assert_not_called()

    def test_canonical_identity_rejection_prevents_runtime(self):
        self.mode = "bad-verifier"
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertNotIn("structural", self.calls)
        self.assertEqual(len(report["termius_identity"]["checks"]), 1)
        self.assertIn("after", report["termius_identity"]["checks"][0])

    def test_stale_report_never_bypasses_fresh_verification(self):
        self.mode = "stale"
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertNotIn("identity", self.calls)
        self.assertNotIn("structural", self.calls)

    def test_failed_child_and_postclosure_failure_are_both_retained(self):
        self.mode = "failed-child"
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        check = report["termius_identity"]["checks"][0]
        self.assertIn("primary_error", check)
        self.assertIn("closure_error", check)
        self.assertTrue(check["after"]["errors"])
        self.assertNotIn("structural", self.calls)
        self.assertTrue((self.output / "identity-closure.json").exists())

    def test_timeout_finally_keeps_failed_nonquiescent_consumed_output(self):
        self.mode = "timeout"
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["complete_evidence"])
        self.assertEqual(report["fragments"], {})
        self.assertEqual(report["termius_identity"]["checks"][0]["quiescence"], "not-established")
        self.assertTrue(report["commands"][-1]["timed_out"])
        self.assertIn("after", report["termius_identity"]["checks"][0])
        with self.assertRaises(ValueError): self.execute()

    def test_late_identity_mutation_clears_all_earlier_fragments(self):
        original = o.adapt_structural
        def adapt(*args):
            result = original(*args)
            self.identity.paths["provenance"].write_bytes(b"late mutation")
            return result
        with mock.patch.object(o, "adapt_structural", side_effect=adapt): report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertIn("structural", self.calls)

    def test_terminal_recheck_failure_clears_component_and_retains_rejected_record(self):
        with mock.patch.object(o, "recheck", side_effect=ValueError("synthetic terminal rejection")):
            report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertEqual(report["components"]["structural"]["status"], "failed")
        self.assertTrue((self.output / "partial-rejected.json").is_file())
        self.assertIn("partial-rejected.json", report["artifact_index"])
        self.assertFalse(report["complete_evidence"])

    def test_final_inventory_failure_clears_component(self):
        original = o.Session.retain
        def retain(session):
            if (session.output / "identity-closure.json").exists():
                raise ValueError("synthetic final inventory failure")
            return original(session)
        with mock.patch.object(o.Session, "retain", new=retain):
            report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertEqual(report["components"]["structural"]["status"], "failed")
        self.assertIn("inventory_error", report)

    def test_recheck_detects_changed_request_closure_and_retained_outputs(self):
        report = self.execute()
        self.assertEqual(report["status"], "incomplete-private-fragments-not-staging-ready", report.get("error"))
        for path in (self.request_path, self.identity.paths["provenance"], self.identity.members["split_config.mdpi.apk"],
                     self.output / "termius-structural/combined-dex/classes.dex"):
            before = path.read_bytes()
            path.write_bytes(before + b"mutation")
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)): o.recheck(self.output)
            path.write_bytes(before)
        self.assertEqual(o.recheck(self.output)["fragments"], report["fragments"])

    def test_preexisting_scratch_prevents_child_and_is_retained_not_cleaned(self):
        self.mode = "stale-work"
        report = self.execute()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["fragments"], {})
        self.assertNotIn("structural", self.calls)
        self.assertFalse((self.output / "termius-structural").exists())
        name = "termius-structural-work/retain-existing"
        self.assertEqual((self.output / name).read_bytes(), b"PREEXISTING; MUST NOT BE REUSED OR CLEANED")
        self.assertIn(name, report["artifact_index"])

    def test_recheck_exactly_indexes_retained_scratch_missing_mutated_and_extra_bytes(self):
        report = self.execute()
        self.assertEqual(report["status"], "incomplete-private-fragments-not-staging-ready", report.get("error"))
        name = "termius-structural-work/temporary/patched/dex/classes.dex"
        path = self.output / name
        self.assertEqual(report["artifact_index"][name], o.file_record(path))
        before = path.read_bytes()
        path.write_bytes(before + b"MUTATED")
        with self.assertRaisesRegex(ValueError, "complete retained artifact inventory changed"):
            o.recheck(self.output)
        path.write_bytes(before)
        path.unlink()
        with self.assertRaisesRegex(ValueError, "complete retained artifact inventory changed"):
            o.recheck(self.output)
        path.write_bytes(before)
        extra = path.with_name("unexpected.dex")
        extra.write_bytes(b"EXTRA RETAINED SCRATCH")
        with self.assertRaisesRegex(ValueError, "complete retained artifact inventory changed"):
            o.recheck(self.output)
        extra.unlink()
        self.assertEqual(o.recheck(self.output)["fragments"], report["fragments"])

    def test_recheck_reconstructs_identity_not_only_retained_index(self):
        report = self.execute()
        self.assertEqual(report["status"], "incomplete-private-fragments-not-staging-ready", report.get("error"))
        report = o.read(self.output / "partial.json")  # independent JSON objects, as a later editor would read
        identity = report["termius_identity"]
        identity["baseline"]["binding"] = {**identity["baseline"]["binding"], "request_sha256": "0" * 64}
        for row in identity["checks"]:
            for key in ("before", "after"): row[key]["binding"]["request_sha256"] = "0" * 64
        save(self.output / "identity-closure.json", identity)
        report["artifact_index"]["identity-closure.json"] = o.file_record(self.output / "identity-closure.json")
        save(self.output / "partial.json", report)
        with self.assertRaisesRegex(ValueError, "identity closure changed"): o.recheck(self.output)


if __name__ == "__main__":
    unittest.main()
