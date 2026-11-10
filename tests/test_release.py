"""Synthetic contract fixtures only: never real app inputs, outputs or evidence.

Run from the publication root with: py -I -B -m unittest discover -s tests -p test_release.py -v
"""
import copy
import datetime as dt
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_under_test", ROOT / "tools/release/release.py")
r = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(r)
NOW = dt.datetime(2026, 11, 8, 12, 0, tzinfo=dt.timezone.utc)
WHEN = "2026-11-08T10:00:00"
H = lambda value: hashlib.sha256(value.encode()).hexdigest()

# Matches the current PatchListGenerator.kt Gson serializeNulls DTO shape,
# including category/formFactor and deliberately NO catalog dependencies field.
# It is synthetic data, not output from an actual Android bundle execution.
GENERATOR_CATALOG_FIXTURE = r'''{
  "NOTE": "Generated from an exact MPP. Do not edit by hand; this catalog is not a release approval.",
  "version": "0.1.0",
  "patches": [
    {
      "name": "Synthetic fixture patch",
      "description": "Synthetic only",
      "default": true,
      "category": null,
      "compatiblePackages": [
        {
          "packageName": "invalid.fixture.app",
          "name": "Synthetic fixture",
          "description": null,
          "apkFileType": "APK",
          "appIconColor": null,
          "signatures": null,
          "formFactor": null,
          "targets": [
            {
              "version": "8.0.1",
              "versionCodes": {"ARM64_V8A": 1008},
              "isExperimental": false,
              "minSdk": 26,
              "description": null
            }
          ]
        }
      ],
      "options": []
    }
  ]
}'''


class ManifestTests(unittest.TestCase):
    def manifest(self):
        return {"version": "0.1.0", "download_url": r.asset_url("fixture-owner", "fixture-repo", "0.1.0"),
                "created_at": WHEN, "description": "Synthetic test fixture, not a release."}

    def test_required_strings(self):
        for key in self.manifest():
            for bad in (None, 0, True, "", "   "):
                with self.subTest(key=key, bad=bad):
                    value = self.manifest()
                    value[key] = bad
                    with self.assertRaises(r.ReleaseError):
                        r.validate_manifest(value)
            value = self.manifest()
            del value[key]
            with self.assertRaises(r.ReleaseError):
                r.validate_manifest(value)

    def test_utc_local_datetime(self):
        for date in (WHEN, WHEN + ".123456789", "2024-02-29T00:00:00"):
            value = self.manifest()
            value["created_at"] = date
            r.validate_manifest(value)
        for date in (WHEN + "Z", WHEN + "+00:00", "2026-11-08", "2026-02-30T00:00:00", "2026-11-08 10:00:00", "2026-11-08T24:00:00", WHEN + ".1234567890"):
            value = self.manifest()
            value["created_at"] = date
            with self.subTest(date=date), self.assertRaises(r.ReleaseError):
                r.validate_manifest(value)

    def test_optional_nullable_fields(self):
        for fields in ({}, {"public_key": None, "page_url": None}, {"public_key": "synthetic-schema-only-key", "page_url": "https://example.invalid/release"}):
            r.validate_manifest(dict(self.manifest(), **fields))
        for fields in ({"public_key": False}, {"page_url": 12}, {"unexpected": "field"}):
            with self.assertRaises(r.ReleaseError):
                r.validate_manifest(dict(self.manifest(), **fields))

    def test_synchronized_manifest_identity(self):
        r.validate_manifest(self.manifest(), "fixture-owner", "fixture-repo", "0.1.0")
        for owner, repo, version in (("other", "fixture-repo", "0.1.0"), ("fixture-owner", "other", "0.1.0"), ("fixture-owner", "fixture-repo", "0.2.0"), (None, "fixture-repo", "0.1.0")):
            with self.assertRaises(r.ReleaseError):
                r.validate_manifest(self.manifest(), owner, repo, version)
        value = self.manifest()
        value["download_url"] = value["download_url"].replace("patches-0.1.0.mpp", "other.mpp")
        with self.assertRaises(r.ReleaseError):
            r.validate_manifest(value, "fixture-owner", "fixture-repo", "0.1.0")

    def test_source_normalization_fixture(self):
        # Manager short GitHub source contract inspected at 6bd844d99... .
        fixture = json.loads((ROOT / "tests/fixtures/release/source-normalization.json").read_text(encoding="utf-8"))
        for entry in fixture["valid"]:
            self.assertEqual(r.normalize_source(entry["input"]), entry["expected"])
        for entry in fixture["invalid"]:
            with self.subTest(url=entry), self.assertRaises(r.ReleaseError):
                r.normalize_source(entry)

    def test_unsafe_urls(self):
        for url in ("http://example.invalid/file.mpp", "https://user:password@example.invalid/a", "https://example.invalid:443/a", "https://example.invalid/a?key=x", "https://example.invalid/a#b", "https://example.invalid/a%2fb", "https://example.invalid/a/../b", "https://example.invalid/a\\b"):
            value = self.manifest()
            value["download_url"] = url
            with self.subTest(url=url), self.assertRaises(r.ReleaseError):
                r.validate_manifest(value)


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="release-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        (self.source / "Patch.kt").write_text("// Synthetic source, not a real patch.\n", encoding="utf-8")
        self.bundle = self.base / "fixture.mpp"
        self.write_bundle()
        self.catalog = json.loads(GENERATOR_CATALOG_FIXTURE)
        self.compatibility = self.catalog["patches"][0]["compatiblePackages"]
        self.patches = [{"name": "Synthetic fixture patch", "compatiblePackages": self.compatibility}]
        source_hash, paths = r.source_tree(self.source)
        self.request = {"schema": 1, "owner": "fixture-owner", "repository": "fixture-repo", "version": "0.1.0",
                        "created_at": WHEN, "description": "Synthetic test only, not promoted.",
                        "bundle_sha256": r.digest(self.bundle.read_bytes()), "catalog_sha256": r.digest(r.canonical(self.catalog)),
                        "source_revision": "1" * 40, "source_tree_sha256": source_hash, "manager_revision": "2" * 40,
                        "patcher_version": "2.3.0", "input_sets": [{"id": "synthetic-input", "package_name": "invalid.fixture.app",
                            "version": "8.0.1", "version_code": 1008, "abi": "ARM64_V8A", "density": "none", "languages": ["none"],
                            "signer_sha256": H("synthetic signer"), "files": [{"id": "base", "role": "base", "sha256": H("synthetic input, not APK bytes")}]}],
                        "patches": [{"name": self.patches[0]["name"], "source_files": [{"path": "Patch.kt", "sha256": paths["Patch.kt"]}]}]}
        self.regenerate_evidence()
        self.save()

    def write_bundle(self, extra=None, magic=b"dex\n039\x00", manifest=None):
        with zipfile.ZipFile(self.bundle, "w") as bundle:
            bundle.writestr("META-INF/MANIFEST.MF", manifest or "Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: FISHYau\r\nVersion: 0.1.0\r\nPatcher-Version: 2.3.0\r\n\r\n")
            if magic is not None:
                bundle.writestr("classes.dex", magic + b"synthetic invalid DEX body; fixture only")
            for name, data in (extra or {}).items():
                bundle.writestr(name, data)

    def binding(self):
        value = {key: self.request[key] for key in ("bundle_sha256", "catalog_sha256", "source_revision", "source_tree_sha256", "manager_revision", "patcher_version")}
        value["request_sha256"] = r.digest(r.canonical(self.request))
        return value

    def report(self, kind, binding, checks):
        return {"kind": kind, "binding": copy.deepcopy(binding), "observed_at": WHEN,
                "tool": {"name": "synthetic fixture only", "version": "1.0", "sha256": H("synthetic tool")},
                "status": "passed", "checks": {key: "passed" for key in checks.split()},
                "artifacts": [{"kind": artifact_kind, "sha256": H(kind + artifact_kind + " synthetic report")}
                              for artifact_kind in {"bundle-inspection": ["loader-report"], "structural": ["test-report", "dex-report"],
                                                    "runtime": ["runtime-report", "visual-review"]}[kind]]}

    def regenerate_evidence(self):
        binding = self.binding()
        inspection = self.report("bundle-inspection", binding, "android_bundle_load actual_definitions metadata")
        inspection.update(patches=copy.deepcopy(self.patches), dependencies={patch["name"]: [] for patch in self.patches},
                          about={"name": "FISHYau android patches", "author": "FISHYau"}, signing="unsigned")
        selection = [p["name"] for p in self.patches]
        case_binding = dict(binding, patch=self.patches[0]["name"], input_set_sha256=r.digest(r.canonical(self.request["input_sets"][0])), selection=selection,
                            patched_application_sha256=H("synthetic patched application"))
        self.evidence = {"schema": 1, "inspection": inspection, "patch_evidence": [{"patch": self.patches[0]["name"],
                         "input_set_id": "synthetic-input", "selection": selection,
                         "structural": self.report("structural", case_binding, "uncached_tests patcher_round_trip dex_control_flow negative_fixtures"),
                         "runtime": self.report("runtime", case_binding, "patched_feature_interaction art_verification manager_import visual_inspection")}]}
        self.reapprove()

    def reapprove(self):
        self.approval = {"schema": 1, "status": "approved", "reviewer": "synthetic fixture, not a real reviewer",
                         "reviewed_at": "2026-11-08T11:00:00", "request_sha256": r.digest(r.canonical(self.request)),
                         "evidence_sha256": r.digest(r.canonical(self.evidence)), "approved_patches": sorted(p["name"] for p in self.patches)}

    def save(self):
        for name in ("request", "catalog", "evidence", "approval"):
            (self.base / (name + ".json")).write_bytes(r.canonical(getattr(self, name)))

    def arguments(self):
        return dict(source_root=self.source, bundle_path=self.bundle,
                    **{name + "_path": self.base / (name + ".json") for name in ("request", "catalog", "evidence", "approval")})

    def validate(self):
        return r.validate_release(**self.arguments(), now=NOW)

    def blocked(self, pattern=None):
        self.save()
        with self.assertRaisesRegex(r.ReleaseError, pattern or "."):
            self.validate()

    def test_current_generator_serialize_nulls_fixture(self):
        catalog = json.loads(GENERATOR_CATALOG_FIXTURE)
        patch = catalog["patches"][0]
        self.assertEqual(set(patch), {"name", "description", "default", "category", "compatiblePackages", "options"})
        self.assertNotIn("dependencies", patch)
        self.assertIsNone(patch["category"])
        self.assertIsNone(patch["compatiblePackages"][0]["formFactor"])
        projected, coverage = r.catalog_patches(catalog, "0.1.0")
        self.assertEqual(projected, self.patches)
        self.assertEqual(len(coverage), 1)
        # The precise DTO-shaped fixture passes the complete binding gate too.
        self.assertEqual(self.validate()["catalog"]["patches"], projected)

    def test_nullable_category_and_form_factor_types(self):
        for category in (None, "Synthetic category"):
            for form_factor in (None, "PHONE"):
                catalog = json.loads(GENERATOR_CATALOG_FIXTURE)
                catalog["patches"][0]["category"] = category
                catalog["patches"][0]["compatiblePackages"][0]["formFactor"] = form_factor
                r.catalog_patches(catalog, "0.1.0")
        for field in ("category", "formFactor"):
            for bad in (False, 1, [], {}):
                catalog = json.loads(GENERATOR_CATALOG_FIXTURE)
                target = catalog["patches"][0] if field == "category" else catalog["patches"][0]["compatiblePackages"][0]
                target[field] = bad
                with self.subTest(field=field, value=bad), self.assertRaises(r.ReleaseError):
                    r.catalog_patches(catalog, "0.1.0")

    def test_dependencies_must_be_explicit_in_trusted_loader_inspection(self):
        self.assertNotIn("dependencies", self.catalog["patches"][0])
        original = copy.deepcopy(self.evidence)
        for bad in (None, [], {}, {"unknown patch": []}, {self.patches[0]["name"]: None},
                    {self.patches[0]["name"]: False}, {self.patches[0]["name"]: ["ActualDependencyIdentifier"]}):
            self.evidence = copy.deepcopy(original)
            self.evidence["inspection"]["dependencies"] = bad
            self.reapprove()
            self.blocked("dependenc")
        self.evidence = copy.deepcopy(original)
        del self.evidence["inspection"]["dependencies"]
        self.reapprove()
        self.blocked("missing fields")

    def test_complete_synthetic_fixture_only(self):
        value = self.validate()
        self.assertEqual(value["bundle"], self.bundle.read_bytes())
        self.assertEqual(value["catalog"]["patches"], self.patches)
        self.assertNotIn("public_key", value["manifest"])
        self.assertIn("not-published", value["summary"]["status"])
        self.assertIn("no cryptographic proof", value["summary"]["trust"].lower())

    def test_bundle_changed_bytes(self):
        with self.bundle.open("ab") as handle:
            handle.write(b"changed")
        self.blocked("bundle digest")

    def test_source_changed_bytes(self):
        (self.source / "Patch.kt").write_text("// changed", encoding="utf-8")
        self.blocked("source tree digest")

    def test_new_source_file_is_bound(self):
        (self.source / "untracked.txt").write_text("new", encoding="utf-8")
        self.blocked("source tree digest")

    def test_catalog_changed_bytes(self):
        self.catalog["patches"][0]["name"] = "different"
        self.blocked("catalog digest")

    def test_actual_loaded_patch_names_required(self):
        self.evidence["inspection"]["patches"] = []
        self.reapprove()
        self.blocked("loaded catalog")

    def test_actual_loaded_compatibility_required(self):
        self.evidence["inspection"]["patches"][0]["compatiblePackages"][0]["targets"][0]["version"] = "8.0.2"
        self.reapprove()
        self.blocked("compatibility")

    def test_source_provenance_required(self):
        self.request["patches"][0]["source_files"][0]["sha256"] = H("wrong")
        self.regenerate_evidence()
        self.blocked("provenance")

    def test_empty_patch_set_blocked(self):
        self.catalog["patches"] = []
        self.request["catalog_sha256"] = r.digest(r.canonical(self.catalog))
        self.regenerate_evidence()
        self.blocked("no patches")

    def test_missing_patch_provenance(self):
        self.request["patches"] = []
        self.regenerate_evidence()
        self.blocked("missing patch")

    def test_each_report_binding_is_exact(self):
        for location in ("inspection", "structural", "runtime"):
            for key in ("bundle_sha256", "catalog_sha256", "source_revision", "source_tree_sha256", "manager_revision", "patcher_version", "request_sha256"):
                with self.subTest(location=location, key=key):
                    original = copy.deepcopy(self.evidence)
                    report = self.evidence["inspection"] if location == "inspection" else self.evidence["patch_evidence"][0][location]
                    report["binding"][key] = "wrong"
                    self.reapprove()
                    self.blocked("binding mismatch")
                    self.evidence = original

    def test_input_hash_and_selection_bound(self):
        for key, value in (("input_set_sha256", H("wrong")), ("selection", []), ("patched_application_sha256", H("wrong"))):
            original = copy.deepcopy(self.evidence)
            self.evidence["patch_evidence"][0]["runtime"]["binding"][key] = value
            self.reapprove()
            self.blocked("binding mismatch")
            self.evidence = original

    def test_original_runtime_is_not_patched_runtime(self):
        value = self.request["input_sets"][0]["files"][0]["sha256"]
        for key in ("structural", "runtime"):
            self.evidence["patch_evidence"][0][key]["binding"]["patched_application_sha256"] = value
        self.reapprove()
        self.blocked("original input")

    def test_missing_failed_boolean_reports(self):
        for kind in ("structural", "runtime"):
            for failure in (False, "failed", "missing"):
                original = copy.deepcopy(self.evidence)
                report = self.evidence["patch_evidence"][0][kind]
                if failure == "missing":
                    del report["checks"][next(iter(report["checks"]))]
                else:
                    report["status"] = failure
                self.reapprove()
                self.blocked()
                self.evidence = original
        self.evidence["inspection"]["checks"] = {k: True for k in self.evidence["inspection"]["checks"]}
        self.reapprove()
        self.blocked("checks")

    def test_each_bundled_patch_needs_its_own_bound_reports(self):
        second = copy.deepcopy(self.catalog["patches"][0])
        second["name"] = "Synthetic second patch"
        self.catalog["patches"].append(second)
        self.patches.append({"name": second["name"], "compatiblePackages": copy.deepcopy(second["compatiblePackages"])})
        self.request["patches"].append(dict(copy.deepcopy(self.request["patches"][0]), name=second["name"]))
        self.request["catalog_sha256"] = r.digest(r.canonical(self.catalog))
        self.regenerate_evidence()
        self.blocked("missing compatibility coverage")
        copied = copy.deepcopy(self.evidence["patch_evidence"][0])
        copied["patch"] = second["name"]
        self.evidence["patch_evidence"].append(copied)
        self.reapprove()
        self.blocked("binding mismatch")
        for kind in ("structural", "runtime"):
            copied[kind]["binding"]["patch"] = second["name"]
        self.reapprove()
        self.save()
        self.assertEqual(self.validate()["summary"]["case_count"], 2)

    def test_kind_specific_artifacts_required(self):
        for kind in ("inspection", "structural", "runtime"):
            original = copy.deepcopy(self.evidence)
            report = self.evidence[kind] if kind == "inspection" else self.evidence["patch_evidence"][0][kind]
            report["artifacts"] = [{"kind": "test-report", "sha256": H("generic report")}]
            self.reapprove()
            self.blocked("kind-specific")
            self.evidence = original

    def test_inspection_json_types_must_match_not_python_boolean_equality(self):
        self.evidence["inspection"]["patches"][0]["compatiblePackages"][0]["targets"][0]["isExperimental"] = 0
        self.reapprove()
        self.blocked("compatibility mismatch")

    def test_missing_runtime(self):
        del self.evidence["patch_evidence"][0]["runtime"]
        self.reapprove()
        self.blocked()

    def test_stale_future_and_pre_evidence_approval(self):
        for when in ("2026-10-01T10:00:00", "2026-11-09T10:00:00"):
            self.evidence["patch_evidence"][0]["runtime"]["observed_at"] = when
            self.reapprove()
            self.blocked("stale or future")
        self.evidence["patch_evidence"][0]["runtime"]["observed_at"] = WHEN
        self.reapprove()
        self.approval["reviewed_at"] = "2026-11-08T09:00:00"
        self.blocked("predates")

    def test_all_patches_must_be_approved(self):
        for approved in ([], ["other"], [self.patches[0]["name"], "extra"]):
            self.approval["approved_patches"] = approved
            self.blocked("approved")

    def test_approval_bound_to_report_bytes(self):
        self.evidence["inspection"]["tool"]["version"] = "1.1"
        self.blocked("approval digest")

    def test_unapproved_status(self):
        self.approval["status"] = "pending"
        self.blocked("reviewer approval")

    def test_signed_bundle_report_rejected(self):
        self.evidence["inspection"]["signing"] = "signed"
        self.reapprove()
        self.blocked("signature verification")

    def test_advertised_public_key_not_allowed_in_request(self):
        self.request["public_key"] = "synthetic not a key"
        self.blocked("request")

    def test_signature_members_rejected(self):
        for name in ("META-INF/SIGNER.SF", "META-INF/SIGNER.RSA", "signature", "META-INF/bundle.sig"):
            self.write_bundle(extra={name: b"synthetic signature"})
            self.request["bundle_sha256"] = r.digest(self.bundle.read_bytes())
            self.regenerate_evidence()
            self.blocked("signature verification")

    def test_jar_renamed_to_mpp_rejected(self):
        self.write_bundle(magic=None)
        self.request["bundle_sha256"] = r.digest(self.bundle.read_bytes())
        self.regenerate_evidence()
        self.blocked("classes.dex")

    def test_bad_dex_rejected(self):
        self.write_bundle(magic=b"not-dex!")
        self.request["bundle_sha256"] = r.digest(self.bundle.read_bytes())
        self.regenerate_evidence()
        self.blocked("DEX magic")

    def test_metadata_mismatch(self):
        manifest = "Manifest-Version: 1.0\nName: FISHYau android patches\nAuthor: FISHYau\nVersion: 0.1.0\nPatcher-Version: 2.3.0\n\n"
        for source, target in (("0.1.0", "0.2.0"), ("2.3.0", "2.2.0"), ("FISHYau android patches", "Donor bundle"), ("Author: FISHYau", "Author: Other")):
            self.write_bundle(manifest=manifest.replace(source, target))
            self.request["bundle_sha256"] = r.digest(self.bundle.read_bytes())
            self.regenerate_evidence()
            self.blocked("mismatch")

    def test_manifest_continuations_and_main_section(self):
        manifest = "Manifest-Version: 1.0\r\nName: FISHYau android \r\n patches\r\nAuthor: FISHYau\r\nVersion: 0.1.0\r\nPatcher-Version: 2.3.0\r\n\r\nName: ignored\r\nVersion: bad\r\n"
        self.write_bundle(manifest=manifest)
        self.assertEqual(r.bundle_metadata(self.bundle.read_bytes())["name"], "FISHYau android patches")
        self.write_bundle(manifest=manifest.replace("Author: FISHYau", "Author: FISHYau\r\nauthor: duplicate"))
        with self.assertRaises(r.ReleaseError):
            r.bundle_metadata(self.bundle.read_bytes())

    def test_zip_envelopes_comments_and_trailing_signatures_rejected(self):
        original = self.bundle.read_bytes()
        for data in (b"synthetic envelope" + original, original + b"synthetic detached signature"):
            with self.assertRaisesRegex(r.ReleaseError, "unsigned ZIP"):
                r.bundle_metadata(data)
        with zipfile.ZipFile(self.bundle, "a") as bundle:
            bundle.comment = b"synthetic signature comment"
        with self.assertRaisesRegex(r.ReleaseError, "unsigned ZIP"):
            r.bundle_metadata(self.bundle.read_bytes())

    def test_app_binaries_and_raw_images_cannot_be_nested_assets(self):
        for name in ("private/patched.apk", "screenshots/private.png", "inputs/original.apkm"):
            self.write_bundle(extra={name: b"synthetic private fixture"})
            with self.assertRaisesRegex(r.ReleaseError, "must not be distributed"):
                r.bundle_metadata(self.bundle.read_bytes())

    def test_catalog_options_dependencies_and_unknown_data_blocked(self):
        for key, value in (("options", [{"key": "synthetic-option"}]), ("dependencies", ["OtherPatch"]), ("raw_screenshot", "synthetic")):
            catalog = copy.deepcopy(self.catalog)
            catalog["patches"][0][key] = value
            with self.assertRaises(r.ReleaseError):
                r.catalog_patches(catalog, "0.1.0")

    def test_archive_traversal_rejected_without_extraction(self):
        self.write_bundle(extra={"../escaped.txt": b"bad"})
        with self.assertRaises(r.ReleaseError):
            r.bundle_metadata(self.bundle.read_bytes())
        self.assertFalse((self.base / "escaped.txt").exists())

    def test_compatibility_requires_complete_finite_coverage(self):
        self.catalog["patches"][0]["compatiblePackages"][0]["targets"][0]["versionCodes"]["X86_64"] = 1008
        self.request["catalog_sha256"] = r.digest(r.canonical(self.catalog))
        self.patches[0]["compatiblePackages"] = copy.deepcopy(self.catalog["patches"][0]["compatiblePackages"])
        self.regenerate_evidence()
        self.blocked("missing compatibility coverage")

    def test_universal_and_unbounded_compatibility_blocked(self):
        for bad in (None, []):
            catalog = copy.deepcopy(self.catalog)
            catalog["patches"][0]["compatiblePackages"] = bad
            with self.assertRaises(r.ReleaseError):
                r.catalog_patches(catalog, "0.1.0")
        for key, bad in (("version", None), ("versionCodes", None), ("isExperimental", True)):
            catalog = copy.deepcopy(self.catalog)
            catalog["patches"][0]["compatiblePackages"][0]["targets"][0][key] = bad
            with self.assertRaises(r.ReleaseError):
                r.catalog_patches(catalog, "0.1.0")

    def test_unknown_or_duplicate_selection(self):
        for selection in ([], ["unknown"], [self.patches[0]["name"]] * 2):
            self.evidence["patch_evidence"][0]["selection"] = selection
            self.reapprove()
            self.blocked()

    def test_duplicate_patch_evidence(self):
        self.evidence["patch_evidence"].append(copy.deepcopy(self.evidence["patch_evidence"][0]))
        self.reapprove()
        self.blocked("duplicate")

    def test_input_package_version_code_abi_mismatch(self):
        for key, value in (("package_name", "invalid.other.app"), ("version", "8.0.2"), ("version_code", 1009), ("abi", "X86")):
            original = copy.deepcopy(self.request)
            self.request["input_sets"][0][key] = value
            self.regenerate_evidence()
            self.blocked("compatibility")
            self.request = original

    def test_input_split_hashes_and_base_required(self):
        original = copy.deepcopy(self.request)
        for change in ("duplicate_hash", "no_base", "duplicate_id"):
            self.request = copy.deepcopy(original)
            files = self.request["input_sets"][0]["files"]
            if change == "duplicate_hash":
                files.append(dict(files[0], id="split", role="split"))
            elif change == "no_base":
                files[0]["role"] = "split"
            else:
                files.append(dict(files[0], sha256=H("other"), role="split"))
            self.regenerate_evidence()
            self.blocked()

    def test_signer_matches_catalog(self):
        self.catalog["patches"][0]["compatiblePackages"][0]["signatures"] = [H("other signer")]
        self.request["catalog_sha256"] = r.digest(r.canonical(self.catalog))
        self.patches[0]["compatiblePackages"] = copy.deepcopy(self.catalog["patches"][0]["compatiblePackages"])
        self.regenerate_evidence()
        self.blocked("signer")

    def test_owner_repository_revision_required(self):
        for key, bad in (("owner", ""), ("repository", "../other"), ("source_revision", "main"), ("manager_revision", "HEAD"), ("patcher_version", "latest")):
            original = copy.deepcopy(self.request)
            self.request[key] = bad
            self.blocked()
            self.request = original

    def test_duplicate_json_keys_blocked(self):
        path = self.base / "duplicate.json"
        path.write_text('{"version":"0.1.0","version":"9.9.9"}', encoding="utf-8")
        with self.assertRaises(r.ReleaseError):
            r.read_json(path)

    def test_nonfinite_json_blocked(self):
        path = self.base / "bad.json"
        path.write_text('{"number":NaN}', encoding="utf-8")
        with self.assertRaises(r.ReleaseError):
            r.read_json(path)

    def test_canonical_tree_is_order_independent(self):
        (self.source / "z.txt").write_bytes(b"z")
        (self.source / "a.txt").write_bytes(b"a")
        first, paths = r.source_tree(self.source)
        expected = b"release-tree-v1\0" + b"".join(p.encode() + b"\0" + paths[p].encode() + b"\n" for p in sorted(paths))
        self.assertEqual(first, r.digest(expected))
        git = self.source / ".git"
        git.mkdir()
        (git / "ignored").write_text("not source", encoding="utf-8")
        self.assertEqual(first, r.source_tree(self.source)[0])

    def test_symlink_or_junction_source_blocked(self):
        original = r.linked
        with mock.patch.object(r, "linked", side_effect=lambda path: path.name == "Patch.kt" or original(path)):
            with self.assertRaisesRegex(r.ReleaseError, "symlinks/junctions"):
                r.source_tree(self.source)

    def test_unreadable_source_directory_blocked(self):
        def inaccessible(root, **kwargs):
            kwargs["onerror"](PermissionError("synthetic inaccessible directory"))
            return iter(())
        with mock.patch.object(r.os, "walk", side_effect=inaccessible):
            with self.assertRaisesRegex(r.ReleaseError, "fully enumerated"):
                r.source_tree(self.source)

    def test_nonportable_source_paths(self):
        for path in ("../escape", "/absolute", "C:/absolute", "a\\b", "a//b", "./a", "CON", "a."):
            with self.subTest(path=path), self.assertRaises(r.ReleaseError):
                r.portable_path(path)

    def test_new_output_must_be_external_and_nonexistent(self):
        for path in (self.source / "output", ROOT / "output", self.source, self.base):
            with self.assertRaises(r.ReleaseError):
                r.new_output(path, self.source)
        output = self.base / "fresh-output"
        self.assertEqual(r.new_output(output, self.source), output)
        with self.assertRaises(r.ReleaseError):
            r.new_output(output, self.source)

    def test_prepare_requires_committed_clean_revision(self):
        # Do not initialize a Git repository in tests or mutate source control.
        with mock.patch.object(r.subprocess, "run", return_value=subprocess.CompletedProcess([], 128, b"", b"not a repository")):
            with self.assertRaisesRegex(r.ReleaseError, "committed"):
                r.validate_release(**self.arguments(), now=NOW, committed=True)
        self.assertFalse((self.base / "output").exists())

    def test_clean_revision_rejects_dirty_wrong_head_and_untracked(self):
        source = str(self.source.resolve()).encode() + b"\n"
        rev = (self.request["source_revision"] + "\n").encode()
        for outputs in ((source, b"9" * 40 + b"\n"), (source, rev, b" M Patch.kt\n"), (source, rev, b"", b"Other.kt\0")):
            with mock.patch.object(r.subprocess, "run", side_effect=[subprocess.CompletedProcess([], 0, out, b"") for out in outputs]):
                with self.assertRaises(r.ReleaseError):
                    r.clean_revision(self.source, self.request["source_revision"], {"Patch.kt": H("unused")})

    def test_prepare_exact_bytes_allowlisted_output_only(self):
        result = self.validate()
        output = self.base / "prepared"
        with mock.patch.object(r, "validate_release", return_value=result) as validate, mock.patch.object(r, "clean_revision"):
            r.prepare(output, **self.arguments())
            self.assertTrue(validate.call_args.kwargs["committed"])
        expected = {"patches-0.1.0.mpp", "patches-list.json", "SHA256SUMS", "verification-summary.json", "patches-bundle.candidate.json"}
        self.assertEqual({p.name for p in output.iterdir()}, expected)
        self.assertEqual((output / "patches-0.1.0.mpp").read_bytes(), self.bundle.read_bytes())
        self.assertEqual((output / "patches-list.json").read_bytes(), (self.base / "catalog.json").read_bytes())
        self.assertEqual(r.digest((output / "patches-list.json").read_bytes()), self.request["catalog_sha256"])
        self.assertFalse((output / "patches-bundle.json").exists())
        self.assertNotIn("public_key", json.loads((output / "patches-bundle.candidate.json").read_bytes()))
        for line in (output / "SHA256SUMS").read_text().splitlines():
            sha, name = line.split("  ")
            self.assertEqual(sha, r.digest((output / name).read_bytes()))
        summary = (output / "verification-summary.json").read_text()
        for private in (str(self.base), "synthetic fixture, not a real reviewer", "patched_application_sha256", "signer_sha256"):
            self.assertNotIn(private, summary)
        with mock.patch.object(r, "validate_release", return_value=result), mock.patch.object(r, "clean_revision"):
            with self.assertRaises(r.ReleaseError):
                r.prepare(output, **self.arguments())

    def test_cli_failure_is_fail_closed(self):
        proc = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/release/release.py"), "validate-manifest", str(self.base / "missing.json")], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("blocked", proc.stderr)

    def test_workflows_separate_readonly_prepare_and_manual_protected_publish(self):
        release = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        verify = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", release)
        self.assertIn("environment: release", release)
        self.assertIn("default: prepare", release)
        self.assertNotIn("PUBLICATION IS DISABLED", release)
        self.assertNotIn("contents: write", release + verify)
        self.assertNotIn("secrets.", release.split("  publish:")[0] + verify)
        self.assertIn("secrets.RELEASE_PUBLISH_TOKEN", release.split("  publish:")[1])
        self.assertIn("inputs.mode == 'publish'", release)
        self.assertIn("inputs.source_commit == github.sha", release)
        for unsafe in ("id-token: write", "gh release", "git push", "pull_request_target", "curl ", "wget "):
            self.assertNotIn(unsafe, release + verify)
        for workflow in (release, verify):
            for line in workflow.splitlines():
                if "uses:" in line:
                    self.assertRegex(line, r"@[0-9a-f]{40}(?:\s|$)")


if __name__ == "__main__":
    unittest.main()
