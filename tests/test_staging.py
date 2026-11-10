"""Synthetic schema/attack fixtures ONLY; no MPP/runtime observation is asserted.

All scratch uses new OS temporary directories outside the publication source.
"""
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("staging_under_test", ROOT / "tools/release/staging.py")
s = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(s)
r = s.r
NOW = dt.datetime(2026, 11, 9, 12, tzinfo=r.UTC)
WHEN = "2026-11-09T10:00:00"
H = lambda text: r.digest(text.encode())


class Fixture:
    """Fabricated local schema fixtures, never authenticated evidence."""
    def __init__(self, base):
        self.base = base
        self.source = base / "source"
        self.source.mkdir()
        for name in sorted(s.SOURCES | {"Compatibility.kt", "ReturnEarly.kt"}):
            path = self.source / (s.MIGRATED + name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("// Synthetic source only " + name, encoding="utf-8")
        self.bundle = base / "synthetic.mpp"
        self.write_bundle()
        app = {"packageName": "com.server.auditor.ssh.client", "name": "Server Auditor", "description": None,
               "apkFileType": "APKM", "appIconColor": None, "signatures": None, "formFactor": None,
               "targets": [{"version": "8.0.1", "versionCodes": {"ARM64_V8A": 1008}, "isExperimental": False, "minSdk": None, "description": None}]}
        self.catalog = {"version": "0.1.0", "patches": [{"name": name, "description": "Synthetic only", "default": default,
                        "category": None, "compatiblePackages": [copy.deepcopy(app)], "options": []} for name, default in s.PATCHES.items()]}
        tree, paths = r.source_tree(self.source)
        self.req = {"schema": 1, "policy": s.POLICY, "owner": "FISHYau", "repository": "fishyau-morphe-patches", "version": "0.1.0",
                    "created_at": WHEN, "description": "Synthetic fixture only, not a release.", "bundle_sha256": r.digest(self.bundle.read_bytes()),
                    "catalog_sha256": r.digest(r.canonical(self.catalog)), "source_tree_sha256": tree,
                    "provenance": {"status": "accepted-existing-behavior", "basis": "user-confirmed-tested-working",
                                   "adaptations": "mechanical-namespace-import-helper-isolation",
                                   "files": [{"path": path, "original_sha256": s.ORIGINALS.get(Path(path).name, H("synthetic helper original " + path)), "migrated_sha256": sha} for path, sha in sorted(paths.items())]}}
        self.regenerate()
        self.save()

    def write_bundle(self, version="0.1.0", dex=True, extra=None):
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: FISHYau\r\nVersion: " + version + "\r\nPatcher-Version: 2.3.0\r\n\r\n")
            if dex:
                archive.writestr("classes.dex", b"dex\n039\0SYNTHETIC INVALID DEX BODY")
            for name, data in (extra or {}).items():
                archive.writestr(name, data)

    def regenerate(self):
        binding = {k: self.req[k] for k in ("policy", "bundle_sha256", "catalog_sha256", "source_tree_sha256")}
        binding["request_sha256"] = r.digest(r.canonical(self.req))
        def report(kind, platform, checks, artifacts, **extra):
            return dict(kind=kind, platform=platform, binding=copy.deepcopy(binding), observed_at=WHEN,
                        tool={"name": "SYNTHETIC NOT EXECUTED", "version": "1", "sha256": H("synthetic tool")},
                        status="passed", checks={key: "passed" for key in checks.split()},
                        artifacts=[{"kind": key, "sha256": H("synthetic " + key)} for key in artifacts], **extra)
        inspection = report("bundle-inspection", "jvm", "target_patcher_load actual_definitions metadata android_dex", ["loader-report"],
                            patcher_version="2.3.0", patches=sorted(copy.deepcopy(self.catalog["patches"]), key=lambda p: p["name"]),
                            dependencies={name: [] for name in s.PATCHES}, about={"name": "FISHYau android patches", "author": "FISHYau"}, signing="unsigned")
        selections = [[name] for name in s.PATCHES] + [sorted(s.PATCHES)]
        structural = [report("structural", "jvm", "uncached_tests patcher_round_trip dex_control_flow negative_fixtures", ["test-report", "dex-report"],
                             selection=selection, input_sha256=H("synthetic input"), output_sha256=H("synthetic output " + str(selection)),
                             scope="Synthetic bounded class comparisons, not whole-app/runtime coverage") for selection in selections]
        manager = report("manager-import", "android", "local_import collection_identity patch_names defaults compatibility visual_inspection", ["manager-report", "visual-review"],
                         manager={"version": "synthetic", "apk_sha256": H("synthetic Manager"), "certificate_sha256": H("synthetic certificate"),
                                  "origin": "https://github.com/MorpheApp/morphe-manager/releases/tag/v0.0.0-synthetic"})
        self.evidence = {"schema": 1, "inspection": inspection, "structural": structural, "manager_import": manager}

    def save(self):
        for name, data in (("request", self.req), ("catalog", self.catalog), ("evidence", self.evidence)):
            (self.base / (name + ".json")).write_bytes(r.canonical(data))

    def args(self):
        return dict(source_root=self.source, bundle_path=self.bundle, catalog_path=self.base / "catalog.json",
                    request_path=self.base / "request.json", evidence_path=self.base / "evidence.json")

    def stage(self):
        output = self.base / "staged"
        # Fixed clock only for these synthetic fixtures.
        from unittest import mock
        original = s.validate
        with mock.patch.object(s, "validate", side_effect=lambda source_root, **kwargs: original(source_root, **kwargs, now=NOW)):
            s.stage(output, **self.args())
        return output


class CollectionFixture(Fixture):
    """Actual migrated source bytes, but ALL evidence/bundle bytes fabricated."""
    def __init__(self, base):
        super().__init__(base)
        for file in self.source.rglob('*.kt'):
            file.unlink()
        originals = {**s.ORIGINALS, 'Compatibility.kt': '6fd9e5085ad9ae26d968ac8089f0c461c99c4ee2c5450d4a032d5c9e2259ed5f', 'BooleanReturn.kt': '0d4f024dbc9416a453ed30423b6c6487397c5d03d0ec0da8e478349b52583a65'}
        paths = [s.MIGRATED + n for n in s.TERMIUS_MIGRATED] + [s.PLEX + n for n in s.PLEX_FILES]
        for name in paths:
            out = self.source / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes((ROOT / name).read_bytes())
        self.req.update(schema=2, policy=s.COLLECTION_POLICY, source_tree_sha256=r.source_tree(self.source)[0])
        self.req['provenance'] = {
            'termius': dict(status='accepted-existing-behavior', basis='user-confirmed-tested-working', adaptations=s.TERMIUS_ADAPTATIONS, files=[dict(path=s.MIGRATED + n, original_sha256=originals[n], migrated_sha256=h) for n, h in sorted(s.TERMIUS_MIGRATED.items())]),
            'plex': dict(repository='https://github.com/UnkyBadTouch/plex-morphe-patches', revision=s.PLEX_REVISION, basis='reviewed-source-migration-not-runtime-acceptance', files=[dict(path=s.PLEX + n, original_sha256=h[0], migrated_sha256=h[1]) for n, h in sorted(s.PLEX_FILES.items())])}
        for patch in self.catalog['patches']:
            patch['default'] = s.COLLECTION_PATCHES[patch['name']]
        app = copy.deepcopy(self.catalog['patches'][0]['compatiblePackages'][0])
        app.update(packageName='com.plexapp.android', name='Plex', targets=[])
        self.catalog['patches'].append(dict(name='Premium unlock', description='Synthetic client checks only', default=True, category=None, compatiblePackages=[app], options=[]))
        self.req['catalog_sha256'] = r.digest(r.canonical(self.catalog))
        self.regenerate()
        self.save()

    def regenerate(self):
        super().regenerate()
        if self.req['schema'] != 2:
            return
        self.evidence['schema'] = 2
        self.evidence['inspection']['dependencies']['Premium unlock'] = []
        plex = {}
        for key, (kind, checks, artifacts) in s.PLEX_REPORTS.items():
            report = copy.deepcopy(self.evidence['inspection'])
            report = {k: report[k] for k in 'kind platform binding observed_at tool status checks artifacts'.split()}
            report.update(kind=kind, checks={c: 'passed' for c in checks.split()}, artifacts=[dict(kind=a, sha256=H('synthetic ' + a)) for a in sorted(artifacts)])
            plex[key] = report
        plex['runtime'] = dict(status='not-observed', scope='No Plex device/runtime acceptance observed by this synthetic fixture.', artifacts=[])
        self.evidence['plex'] = plex


class CollectionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix='collection-synthetic-')
        self.addCleanup(temp.cleanup)
        self.f = CollectionFixture(Path(temp.name))

    def validate(self):
        self.f.save()
        return s.validate(**self.f.args(), now=NOW)

    def test_current_three_patch_policy_separates_runtime_and_legacy(self):
        result = self.validate()
        self.assertEqual(result['summary']['schema'], 2)
        self.assertEqual(result['summary']['reported_new_observations']['plex']['runtime']['status'], 'not-observed')
        self.assertEqual({p['name']: p['default'] for p in self.f.catalog['patches']}, s.COLLECTION_PATCHES)
        with self.assertRaisesRegex(r.ReleaseError, 'explicit targets'):
            r.catalog_patches(self.f.catalog, '0.1.0')
        self.f.stage()

    def test_current_defaults_all_true_but_legacy_premium_stays_false(self):
        self.assertEqual(s.COLLECTION_PATCHES, {'Server Auditor Offline Automation': True,
                         'Server Auditor Premium': True, 'Premium unlock': True})
        self.assertEqual(s.PATCHES, {'Server Auditor Offline Automation': True, 'Server Auditor Premium': False})
        for patch in self.f.catalog['patches']:
            patch['default'] = False
            with self.assertRaisesRegex(r.ReleaseError, 'names/defaults'):
                s.collection_inventory(self.f.catalog, '0.1.0')
            patch['default'] = True
        legacy = copy.deepcopy(self.f.catalog)
        legacy['patches'] = legacy['patches'][:2]
        with self.assertRaisesRegex(r.ReleaseError, 'names/defaults'):
            s.inventory(legacy, '0.1.0')
        legacy['patches'][1]['default'] = False
        s.inventory(legacy, '0.1.0')

    def test_default_adaptation_and_reviewed_premium_hash_required(self):
        self.f.req['provenance']['termius']['adaptations'] = 'mechanical-namespace-import-helper-isolation'
        self.f.regenerate()
        with self.assertRaisesRegex(r.ReleaseError, 'adaptations'):
            self.validate()
        self.f.req['provenance']['termius']['adaptations'] = s.TERMIUS_ADAPTATIONS
        path = s.MIGRATED + 'ServerAuditorPremiumPatch.kt'
        source = self.f.source / path
        # Restoring the historical false-default source is not a current-policy source.
        source.write_bytes(source.read_bytes().replace(b'    default = true,', b'    default = false,'))
        self.f.req['source_tree_sha256'], paths = r.source_tree(self.f.source)
        next(e for e in self.f.req['provenance']['termius']['files'] if e['path'] == path)['migrated_sha256'] = paths[path]
        self.f.regenerate()
        with self.assertRaisesRegex(r.ReleaseError, 'reviewed Termius closure'):
            self.validate()

    def test_structural_selections_remain_exact_two_termius_names(self):
        expected = {(name,) for name in s.PATCHES} | {tuple(sorted(s.PATCHES))}
        self.assertEqual(expected, {tuple(e['selection']) for e in self.f.evidence['structural']})
        self.f.evidence['structural'][-1]['selection'] = sorted(s.COLLECTION_PATCHES)
        with self.assertRaisesRegex(r.ReleaseError, 'invalid structural selection'):
            self.validate()

    def test_plex_needs_dedicated_fresh_final_evidence(self):
        for key in s.PLEX_REPORTS:
            report = self.f.evidence['plex'].pop(key)
            with self.assertRaises(r.ReleaseError):
                self.validate()
            self.f.evidence['plex'][key] = report
            report['observed_at'] = '2026-10-01T00:00:00'
            with self.assertRaisesRegex(r.ReleaseError, 'stale'):
                self.validate()
            report['observed_at'] = WHEN

    def test_plex_cannot_inherit_termius_acceptance_or_claim_runtime(self):
        self.f.req['provenance']['plex']['basis'] = 'user-confirmed-tested-working'
        with self.assertRaisesRegex(r.ReleaseError, 'Plex reviewed provenance'):
            self.validate()
        self.f.req['provenance']['plex']['basis'] = 'reviewed-source-migration-not-runtime-acceptance'
        self.f.regenerate()
        self.f.evidence['plex']['runtime']['status'] = 'observed'
        with self.assertRaises(r.ReleaseError):
            self.validate()

    def test_complete_pinned_source_provenance_not_arbitrary_hashes(self):
        for family in ('termius', 'plex'):
            original = copy.deepcopy(self.f.req['provenance'])
            self.f.req['provenance'][family]['files'][0]['original_sha256'] = H('arbitrary')
            with self.assertRaises(r.ReleaseError):
                self.validate()
            self.f.req['provenance'] = original
        path = self.f.source / (s.PLEX + 'extra.kt')
        path.write_text('unreviewed source')
        self.f.req['source_tree_sha256'] = r.source_tree(self.f.source)[0]
        self.f.regenerate()
        with self.assertRaisesRegex(r.ReleaseError, 'closure'):
            self.validate()

    def test_plex_not_universal_or_finite_target_override(self):
        patch = self.f.catalog['patches'][-1]
        for apps in ([], [dict(patch['compatiblePackages'][0], packageName='other.app')], [dict(patch['compatiblePackages'][0], targets=[{'version': '1'}])]):
            original = patch['compatiblePackages']
            patch['compatiblePackages'] = apps
            with self.assertRaises(r.ReleaseError):
                s.collection_inventory(self.f.catalog, '0.1.0')
            patch['compatiblePackages'] = original


class StagingTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="staging-synthetic-")
        self.addCleanup(temp.cleanup)
        self.f = Fixture(Path(temp.name))

    def validate(self):
        self.f.save()
        return s.validate(**self.f.args(), now=NOW)

    def blocked(self, text="."):
        with self.assertRaisesRegex(r.ReleaseError, text):
            self.validate()

    def test_synthetic_complete_binding_not_truth(self):
        result = self.validate()
        summary = result["summary"]
        self.assertEqual(summary["status"], "staged-not-published")
        self.assertFalse(summary["reported_new_observations"]["evidence_authenticated"])
        self.assertEqual(summary["inherited_behavior"]["status"], "accepted-existing-behavior")
        self.assertNotIn("source_revision", summary["binding"])
        self.assertNotIn("runtime", summary["reported_new_observations"])

    def test_stage_exact_bytes_new_external_and_sanitized(self):
        output = self.f.stage()
        self.assertEqual({p.name for p in output.iterdir()}, {"patches-0.1.0.mpp", "patches-list.json", "patches-bundle.candidate.json", "verification-summary.json", "SHA256SUMS"})
        self.assertEqual((output / "patches-0.1.0.mpp").read_bytes(), self.f.bundle.read_bytes())
        self.assertEqual((output / "patches-list.json").read_bytes(), (self.f.base / "catalog.json").read_bytes())
        self.assertFalse((output / "patches-bundle.json").exists())
        summary = (output / "verification-summary.json").read_text()
        for private in (str(self.f.base), "SYNTHETIC NOT EXECUTED", "synthetic input", "reviewer"):
            self.assertNotIn(private, summary)
        for line in (output / "SHA256SUMS").read_text().splitlines():
            sha, name = line.split("  ")
            self.assertEqual(sha, r.digest((output / name).read_bytes()))
        with self.assertRaises(r.ReleaseError):
            self.f.stage()

    def test_exact_catalog_bytes_not_canonical_equivalence(self):
        self.f.save()
        path = self.f.base / "catalog.json"
        path.write_text(json.dumps(self.f.catalog, indent=2))
        with self.assertRaisesRegex(r.ReleaseError, "catalog digest"):
            s.validate(**self.f.args(), now=NOW)

    def test_source_tree_changes_fail(self):
        (self.f.source / "extra.txt").write_text("changed")
        self.blocked("source tree digest")

    def test_provenance_source_and_closure_fail(self):
        for mutation in ("missing", "wrong", "extra", "runtime"):
            original = copy.deepcopy(self.f.req)
            if mutation == "missing":
                self.f.req["provenance"]["files"].pop()
            elif mutation == "wrong":
                self.f.req["provenance"]["files"][0]["migrated_sha256"] = H("wrong")
            elif mutation == "extra":
                self.f.req["provenance"]["files"].append(copy.deepcopy(self.f.req["provenance"]["files"][0]))
            else:
                self.f.req["provenance"]["status"] = "runtime-passed"
            self.f.regenerate()
            self.blocked()
            self.f.req = original

    def test_original_accepted_sources_cannot_be_replaced_by_arbitrary_hashes(self):
        item = next(item for item in self.f.req["provenance"]["files"] if Path(item["path"]).name in s.ORIGINALS)
        item["original_sha256"] = H("unaccepted implementation")
        self.f.regenerate()
        self.blocked("outside accepted existing behavior")

    def test_no_fabricated_revision_or_approval_allowed(self):
        for key in ("source_revision", "approval", "runtime_passed", "public_key"):
            self.f.req[key] = "fabricated"
            self.blocked("unexpected or missing")
            del self.f.req[key]

    def test_missing_each_observation(self):
        for key in ("inspection", "structural", "manager_import"):
            value = self.f.evidence.pop(key)
            self.blocked("unexpected or missing")
            self.f.evidence[key] = value

    def test_platform_not_jvm_as_android(self):
        self.f.evidence["manager_import"]["platform"] = "jvm"
        self.blocked("platform")

    def test_binding_every_report_and_hash(self):
        reports = [self.f.evidence["inspection"], *self.f.evidence["structural"], self.f.evidence["manager_import"]]
        for report in reports:
            for key in report["binding"]:
                value = report["binding"][key]
                report["binding"][key] = H("changed")
                self.blocked("binding mismatch")
                report["binding"][key] = value

    def test_reports_failed_stale_future_or_missing_artifact(self):
        for key in ("inspection", "manager_import"):
            report = self.f.evidence[key]
            original = copy.deepcopy(report)
            for field, value in (("status", True), ("checks", {}), ("artifacts", []), ("observed_at", "2026-10-01T00:00:00"), ("observed_at", "2026-11-10T00:00:00")):
                report[field] = value
                self.blocked()
                report.clear()
                report.update(copy.deepcopy(original))

    def test_loaded_defaults_definitions_dependencies_options(self):
        original = copy.deepcopy(self.f.evidence["inspection"])
        for field, value in (("patches", []), ("dependencies", {}), ("dependencies", {name: ["x"] for name in s.PATCHES}), ("signing", "signed"), ("patcher_version", "2.2.0")):
            self.f.evidence["inspection"][field] = value
            self.blocked()
            self.f.evidence["inspection"] = copy.deepcopy(original)
        self.f.evidence["inspection"]["patches"][0]["default"] = False
        self.blocked("loaded definitions")

    def test_catalog_extra_wrong_default_package_code_or_options(self):
        original = copy.deepcopy(self.f.catalog)
        for mutation in ("extra", "default", "package", "version", "code", "apkm", "options", "experimental", "infinite"):
            self.f.catalog = copy.deepcopy(original)
            p = self.f.catalog["patches"][0]
            app = p["compatiblePackages"][0]
            target = app["targets"][0]
            if mutation == "extra":
                p = copy.deepcopy(p)
                p["name"] = "Unrelated patch"
                self.f.catalog["patches"].append(p)
            elif mutation == "default": p["default"] = False
            elif mutation == "package": app["packageName"] = "invalid.other.app"
            elif mutation == "version": target["version"] = "7.11.2"
            elif mutation == "code": target["versionCodes"] = {"ARM64_V8A": 999}
            elif mutation == "apkm": app["apkFileType"] = "APK"
            elif mutation == "options": p["options"] = [{"key": "other"}]
            elif mutation == "experimental": target["isExperimental"] = True
            else: app["targets"] = []
            self.f.req["catalog_sha256"] = r.digest(r.canonical(self.f.catalog))
            self.f.regenerate()
            self.blocked()

    def test_combined_and_each_singleton_structural_required(self):
        original = copy.deepcopy(self.f.evidence["structural"])
        for cases in (original[:2], [original[0]] * 3, original[1:] + [original[1]]):
            self.f.evidence["structural"] = cases
            self.blocked()
        self.f.evidence["structural"] = original
        original[0]["output_sha256"] = original[0]["input_sha256"]
        self.blocked("original input")

    def test_official_manager_provenance_required(self):
        self.f.evidence["manager_import"]["manager"]["origin"] = "https://example.invalid/fake"
        self.blocked("official Manager")

    def test_bundle_changes_and_wrong_metadata_jar_signature_blocked(self):
        for args in ({"version": "0.2.0"}, {"dex": False}, {"extra": {"META-INF/test.SF": b"synthetic"}}, {"extra": {"private.apk": b"synthetic"}}):
            self.f.write_bundle(**args)
            self.f.req["bundle_sha256"] = r.digest(self.f.bundle.read_bytes())
            self.f.regenerate()
            self.blocked()

    def test_missing_artifact_and_output_under_source_blocked(self):
        self.f.bundle.unlink()
        self.blocked("regular nonsymlink")
        self.assertFalse((self.f.base / "staged").exists())
        with self.assertRaises(r.ReleaseError):
            r.new_output(self.f.source / "bad", self.f.source)

    def test_cli_contract_and_fail_closed(self):
        command = [sys.executable, "-I", "-B", str(ROOT / "tools/release/staging.py")]
        result = subprocess.run(command + ["contract"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn(s.POLICY, result.stdout)
        result = subprocess.run(command + ["stage", "--source-root", str(self.f.source), "--bundle", str(self.f.bundle), "--catalog", str(self.f.base / "missing"), "--request", str(self.f.base / "missing"), "--evidence", str(self.f.base / "missing"), "--output", str(self.f.base / "blocked")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.f.base / "blocked").exists())


if __name__ == "__main__":
    unittest.main()
