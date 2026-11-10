"""Actual freeze -> Plex preflight -> staging byte-binding integration only.

SyntheticBuild supplies explicitly INVALID synthetic ZIP/DEX and fabricated build
schemas. Never pass it to an MPP loader or resource/runtime path. Positive seams
use real request, archive and CURRENT catalog/provenance validators, without mocks.
"""
import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tf = load("freeze_integration_fixture", ROOT / "tests/test_freeze.py")
ts = load("staging_integration_fixture", ROOT / "tests/test_staging.py")
c = load("plex_integration_checker", ROOT / "tools/plex-check/final_bundle.py")
r, s = tf.r, tf.s


class FreezePlexIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="freeze-plex-schema-only-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.build = tf.SyntheticBuild(self.base)
        # Actual Morphe projection shape, not just a reduced one-ABI/null form.
        for patch in self.build.catalog["patches"]:
            app = patch["compatiblePackages"][0]
            app.update(formFactor="MOBILE", signatures=None, description=None,
                       name="Plex" if patch["name"] == "Premium unlock" else "Server Auditor",
                       appIconColor="#282A2D" if patch["name"] == "Premium unlock" else "#1A73E8")
            for target in app["targets"]:
                target.update(minSdk=None, description=None)
        self.build.save_catalog()
        self.build.save_report()
        args = self.build.args()
        args["now"] = tf.NOW.replace(hour=0, minute=0, second=0, microsecond=0)
        self.frozen = tf.f.freeze(**args)
        self.request_path = self.frozen / "request.json"
        self.bundle = self.frozen / "patches-0.1.0.mpp"
        self.catalog = self.frozen / "patches-list.json"
        self.raw = self.request_path.read_bytes()
        self.request = c.parse_json(self.raw)

    def preflight(self):
        tree, entries = r.source_tree(self.build.source)
        return c.preflight(self.request_path, self.bundle, self.catalog, tree, entries, r, s)

    def save_request(self, request):
        self.request_path.write_bytes(r.canonical(request))

    def staging_binding(self, raw):
        # These reports are deliberately FABRICATED schema fixtures, never
        # actual loader/Manager/runtime evidence. Only their byte binding is tested.
        fixture = ts.CollectionFixture.__new__(ts.CollectionFixture)
        fixture.req = c.parse_json(raw)
        fixture.catalog = c.parse_json(self.catalog.read_bytes())
        fixture.regenerate()
        def bind(value):
            if isinstance(value, dict):
                if "binding" in value:
                    value["binding"]["request_sha256"] = r.digest(raw)
                for child in value.values():
                    bind(child)
            elif isinstance(value, list):
                for child in value:
                    bind(child)
        bind(fixture.evidence)
        evidence = self.base / "fabricated-evidence-binding-only.json"
        evidence.write_bytes(r.canonical(fixture.evidence))
        result = s.validate(self.build.source, self.bundle, self.catalog, self.request_path, evidence, now=ts.NOW)
        self.assertEqual(result["summary"]["reported_new_observations"]["plex"]["runtime"]["status"], "not-observed")
        return result["summary"]["binding"]

    def test_actual_producer_bytes_pass_real_wrapper_preflight_and_staging_binding(self):
        raw, request = self.preflight()
        inventory, _ = r.read_json(self.frozen / "freeze.json")
        self.assertEqual(raw, self.raw)
        self.assertEqual(request, self.request)
        self.assertEqual(inventory["request_sha256"], r.digest(raw))
        self.assertEqual(self.staging_binding(raw)["request_sha256"], inventory["request_sha256"])
        self.assertIn(b"SYNTHETIC INVALID BODY; NOT LOADED", self.bundle.read_bytes())
        catalog = c.parse_json(self.catalog.read_bytes())
        for patch in catalog["patches"]:
            app = patch["compatiblePackages"][0]
            self.assertEqual(app["formFactor"], "MOBILE")
            if patch["name"] == "Premium unlock":
                self.assertEqual(app["targets"], [])
            else:
                self.assertEqual(app["targets"][0]["versionCodes"], {abi: 1008 for abi in r.ABI})
        with self.assertRaisesRegex(ValueError, "explicit targets"):
            r.catalog_patches(catalog, "0.1.0")  # Historical policy stays strict.

    def test_whitespace_bytes_preserved_not_reserialized_digest(self):
        raw = ("  " + json.dumps(self.request, indent=3) + "\n\n").encode()
        self.request_path.write_bytes(raw)
        accepted, _ = self.preflight()
        self.assertEqual(accepted, raw)
        self.assertNotEqual(r.digest(accepted), r.digest(r.canonical(self.request)))
        self.assertEqual(self.staging_binding(raw)["request_sha256"], r.digest(accepted))

    def test_old_standalone_contract_rejected(self):
        self.save_request(dict(schema="plex-final-bundle-request-v1", policy=c.POLICY, patcher_version="2.3.0",
                               defaults=c.DEFAULTS, **{k: self.request[k] for k in ("bundle_sha256", "catalog_sha256", "source_tree_sha256")}))
        with self.assertRaisesRegex(ValueError, "fields"):
            self.preflight()

    def test_schema_types_target_version_and_metadata_rejected(self):
        changes = [("schema", value) for value in (True, False, "2", 2.0, 1, 3)]
        changes += [("owner", "other"), ("repository", "other"), ("version", "0.2.0"), ("policy", s.POLICY),
                    ("created_at", "2026-11-09T00:00:00Z"), ("created_at", "2026-02-30T00:00:00"),
                    ("created_at", "2099-01-01T00:00:00"), ("description", "   "), ("description", "bad\ntext")]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                request = {**self.request, key: value}
                self.save_request(request)
                with self.assertRaises(ValueError):
                    self.preflight()
        for key in ("defaults", "patcher_version", "extra"):
            self.save_request({**self.request, key: True})
            with self.assertRaises(ValueError):
                self.preflight()

    def test_malformed_duplicate_and_nonfinite_json_rejected(self):
        for raw in (b"{", b"[]", b'NaN', b'{"schema":2,' + self.raw[1:], self.raw + b'{}'):
            self.request_path.write_bytes(raw)
            with self.subTest(raw=raw[:30]), self.assertRaises(ValueError):
                self.preflight()

    def test_wrong_digests_and_pinned_provenance_rejected(self):
        for key in ("bundle_sha256", "catalog_sha256", "source_tree_sha256"):
            for value in ("a" * 64, "A" * 64, 123, None):
                self.save_request({**self.request, key: value})
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    self.preflight()
        def revision(p):
            p["plex"]["revision"] = "a" * 40
        def original(p):
            p["termius"]["files"][0]["original_sha256"] = "a" * 64
        def migrated(p):
            p["plex"]["files"][0]["migrated_sha256"] = "a" * 64
        def adaptation(p):
            p["termius"]["adaptations"] = "mechanical-namespace-import-helper-isolation"
        for mutate in (revision, original, migrated, adaptation, lambda p: p["plex"]["files"].pop(), lambda p: p.update(extra={})):
            request = copy.deepcopy(self.request)
            mutate(request["provenance"])
            self.save_request(request)
            with self.subTest(mutation=mutate.__name__), self.assertRaises(ValueError):
                self.preflight()

    def test_mutation_after_freezing_rejected(self):
        for path in (self.bundle, self.catalog, self.build.source / "gradlew"):
            original = path.read_bytes()
            path.write_bytes(original + b"mutation")
            with self.subTest(path=path.name), self.assertRaises(ValueError):
                self.preflight()
            path.write_bytes(original)
        self.assertEqual(self.preflight()[0], self.raw)

    def test_real_shape_inventory_rejects_defaults_extras_constraints_abi_and_version(self):
        original = c.parse_json(self.catalog.read_bytes())
        def bad_abi(cat):
            cat["patches"][0]["compatiblePackages"][0]["targets"][0]["versionCodes"]["X86"] = 999
        def unknown_abi(cat):
            cat["patches"][0]["compatiblePackages"][0]["targets"][0]["versionCodes"]["OTHER"] = 1008
        def constraint(cat):
            cat["patches"][2]["compatiblePackages"][0]["targets"] = [dict(version="1.0", versionCodes={"X86": 1}, isExperimental=False)]
        mutations = [lambda cat: cat["patches"].append(copy.deepcopy(cat["patches"][0])),
                     lambda cat: cat.update(version="0.2.0"), bad_abi, unknown_abi, constraint]
        mutations += [lambda cat, i=i, value=value: cat["patches"][i].update(default=value) for i in range(3) for value in (False, 1)]
        for mutate in mutations:
            cat = copy.deepcopy(original)
            mutate(cat)
            self.catalog.write_bytes(r.canonical(cat))
            self.save_request({**self.request, "catalog_sha256": c.sha(self.catalog)})
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                self.preflight()

    def test_actual_bundle_metadata_patcher_and_version_not_request_defaults(self):
        for kwargs in (dict(patcher="2.2.0"), dict(version="0.2.0"), dict(author="other")):
            self.build.write_bundle(**kwargs)
            self.bundle.write_bytes(self.build.bundle.read_bytes())
            self.save_request({**self.request, "bundle_sha256": c.sha(self.bundle)})
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.preflight()

    def test_bad_request_fails_before_compiler_and_retains_failed_output(self):
        for index, schema in enumerate((True, "2", 1, "plex-final-bundle-request-v1")):
            self.save_request({**self.request, "schema": schema})
            args = argparse.Namespace(command="check", out=self.base / f"rejected-{index}", request=self.request_path,
                                      bundle=self.bundle, catalog=self.catalog, jdk=self.base, cache_root=self.base)
            with mock.patch.object(c.subprocess, "run") as child:
                report = c.execute(args, ROOT)
                child.assert_not_called()
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["phase"], "preflight")
            self.assertEqual(report["actual_definition"], "not_observed")
            self.assertEqual(report["resource_execution"], "not_observed")
            self.assertTrue((args.out / "checker.json").is_file())

    def test_compile_only_still_not_execution_evidence(self):
        with self.assertRaisesRegex(ValueError, "did not complete"):
            c.validate_native(dict(schema="plex-final-bundle-native-v1", status="compile_only_no_final_bundle_observation"),
                              self.base, r.digest(self.raw), self.request)


if __name__ == "__main__":
    unittest.main()
