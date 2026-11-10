"""Synthetic temp-only freeze contracts; no build/loader/device success claims.

Copies reviewed text sources into disposable fixtures. MPP body, driver report
and JUnit XML are fabricated schemas, not actually executed collection evidence.
Run: python -I -B -m unittest discover -s tests -p test_freeze.py
"""
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("freeze_under_test", ROOT / "tools/release/freeze.py")
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)
r, s = f.r, f.s
NOW = dt.datetime(2026, 11, 9, 12, 34, 56, 123456, tzinfo=r.UTC)


class SyntheticBuild:
    """Deliberately fictional successful build; never use outside these tests."""
    def __init__(self, base):
        self.base = base
        base.mkdir(parents=True, exist_ok=True)
        self.source, self.build = base / "pristine", base / "build-out"
        self.source.mkdir()
        self.build.mkdir()
        names = set(f.BUILD_CONFIG) | {"docs/termius-migration.json", "docs/plex-migration.json"}
        names |= f.configuration_paths(r.source_tree(ROOT)[1])
        names |= {s.MIGRATED + n for n in s.TERMIUS_MIGRATED}
        names |= {s.PLEX + n for n in s.PLEX_FILES}
        names |= {f.TEST_PREFIX + n.replace(".", "/") + ".kt" for n in f.TEST_CLASSES}
        for name in names:
            out = self.source / name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes((ROOT / name).read_bytes())
        self.bundle_rel = "artifacts/patches/build/libs/patches-0.1.0.mpp"
        self.bundle = self.build / self.bundle_rel
        self.bundle.parent.mkdir(parents=True)
        self.write_bundle()
        app = dict(packageName="com.server.auditor.ssh.client", apkFileType="APKM",
                   targets=[dict(version="8.0.1", versionCodes={abi: 1008 for abi in sorted(r.ABI)}, isExperimental=False)])
        self.catalog = {"version": "0.1.0", "patches": [dict(name=name, default=True, description="Synthetic schema fixture only", category=None,
                            compatiblePackages=[copy.deepcopy(app)], options=[]) for name in s.PATCHES]}
        plex = dict(packageName="com.plexapp.android", apkFileType="APKM", targets=[])
        self.catalog["patches"].append(dict(name="Premium unlock", default=True, description="Synthetic only", category=None, compatiblePackages=[plex], options=[]))
        self.catalog_path = self.build / "artifacts/patches-list.json"
        self.save_catalog()
        expected = f.expected_tests(self.source, r.source_tree(self.source)[1])
        self.xml_paths = []
        for name, methods in sorted(expected.items()):
            path = self.build / ("artifacts/patches/build/test-results/test/TEST-" + name + ".xml")
            path.parent.mkdir(parents=True, exist_ok=True)
            root = ET.Element("testsuite", name=name, tests=str(len(methods)), failures="0", errors="0", skipped="0")
            for method in sorted(methods):
                ET.SubElement(root, "testcase", classname=name, name=method, time="0.0")
            path.write_bytes(ET.tostring(root, encoding="utf-8", xml_declaration=True))
            self.xml_paths.append(path)
        self.report = dict(out=str(self.build), gradle_volume="synthetic-test-volume", offline=True,
                           image="synthetic-official-environment-identity:test-not-executed", tasks=[":patches:test", ":patches:buildAndroid"],
                           publication_repository=s.TARGET, requested_version="0.1.0", status="build_command_succeeded")
        self.archive()
        self.save_report()
        self.output = base / "frozen"

    def write_bundle(self, *, version="0.1.0", patcher="2.3.0", author="FISHYau"):
        with zipfile.ZipFile(self.bundle, "w") as z:
            z.writestr("classes.dex", b"dex\n039\0SYNTHETIC INVALID BODY; NOT LOADED")
            z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: " + author + "\r\nVersion: " + version + "\r\nPatcher-Version: " + patcher + "\r\n\r\n")

    def save_catalog(self):
        # Deliberately noncanonical whitespace, which freeze must preserve.
        self.catalog_path.write_bytes((json.dumps(self.catalog, indent=3) + "\n\n").encode())

    def archive(self, *, prefix="./", omit=None, extra=None):
        with tarfile.open(self.build / "source.tar", "w", format=tarfile.GNU_FORMAT) as tar:
            root = tarfile.TarInfo(".")
            root.type = tarfile.DIRTYPE
            tar.addfile(root)
            for name in sorted(r.source_tree(self.source)[1]):
                if name == omit:
                    continue
                data = (self.source / name).read_bytes()
                info = tarfile.TarInfo(prefix + name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            for info, data in (extra or []):
                tar.addfile(info, io.BytesIO(data))

    def save_report(self):
        paths = sorted(p.relative_to(self.build).as_posix() for p in (self.build / "artifacts").rglob("*") if p.is_file())
        hashes = {p: r.digest((self.build / p).read_bytes()) for p in paths}
        self.report["artifacts"] = paths
        self.report["sha256"] = hashes
        self.report["bundle"] = dict(path=self.bundle_rel, sha256=hashes[self.bundle_rel])
        self.report["catalog"] = dict(path="artifacts/patches-list.json", sha256=hashes["artifacts/patches-list.json"], version=self.catalog["version"])
        counts = dict(tests=0, failures=0, errors=0, skipped=0)
        reports = [p for p in paths if "/test-results/" in p and p.endswith(".xml")]
        for p in reports:
            root = ET.fromstring((self.build / p).read_bytes())
            for k in counts:
                counts[k] += int(root.get(k, "0"))
        self.report["tests"] = dict(**counts, reports=reports)
        (self.build / "final-mpp.sha256").write_text(hashes[self.bundle_rel] + "  /output/work/" + self.bundle_rel[len("artifacts/"):] + "\n", encoding="utf-8")
        self.report_bytes()

    def report_bytes(self):
        (self.build / "build.json").write_bytes(r.canonical(self.report))

    def args(self):
        return dict(output=self.output, source_root=self.source, build_report=self.build / "build.json",
                    bundle_path=self.bundle, catalog_path=self.catalog_path, description="Synthetic freeze only; not release evidence.", now=NOW)

    def freeze(self):
        return f.freeze(**self.args())

    def edit_xml(self, action, index=0):
        path = self.xml_paths[index]
        root = ET.fromstring(path.read_bytes())
        action(root)
        path.write_bytes(ET.tostring(root))
        self.save_report()


class FreezeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="freeze-synthetic-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.b = SyntheticBuild(self.base)

    def blocked(self, pattern=None):
        with self.assertRaisesRegex(r.ReleaseError, pattern or ".+"):
            self.b.freeze()
        self.assertFalse((self.b.output / "freeze.json").exists())

    def test_exact_bytes_schema_two_and_private_inventory_without_observations(self):
        out = self.b.freeze()
        self.assertEqual({p.name for p in out.iterdir()}, {"request.json", "freeze.json", "patches-list.json", "patches-0.1.0.mpp"})
        self.assertEqual((out / "patches-list.json").read_bytes(), self.b.catalog_path.read_bytes())
        self.assertEqual((out / "patches-0.1.0.mpp").read_bytes(), self.b.bundle.read_bytes())
        req, raw = r.read_json(out / "request.json")
        r.exact(req, "schema policy owner repository version created_at description bundle_sha256 catalog_sha256 source_tree_sha256 provenance", "schema2 request")
        self.assertEqual((req["schema"], req["policy"]), (2, s.COLLECTION_POLICY))
        self.assertEqual(req["created_at"], "2026-11-09T12:34:56.123456")
        self.assertEqual(r.local_time(req["created_at"]), NOW)
        self.assertEqual(req["source_tree_sha256"], r.source_tree(self.b.source)[0])
        s.collection_provenance(req["provenance"], r.source_tree(self.b.source)[1])
        inv, _ = r.read_json(out / "freeze.json")
        self.assertEqual(inv["status"], "frozen-inputs-not-observations")
        self.assertEqual(inv["request_sha256"], r.digest(raw))
        self.assertEqual(inv["build_identity"]["image"], self.b.report["image"])
        self.assertEqual(inv["source_files"], r.source_tree(self.b.source)[1])
        self.assertEqual(len(inv["test_cases"]), 6)
        self.assertGreater(inv["tests"]["tests"], 100)
        for key in ("inspection", "structural", "manager_import", "plex", "source_revision", "approval"):
            self.assertNotIn(key, req)
            self.assertNotIn(key, inv)
        self.assertIn("source.tar", inv["build_inputs"])
        self.assertEqual(inv["build_inputs"]["build.json"], r.digest((self.b.build / "build.json").read_bytes()))

    def test_no_overwrite_and_failed_outputs_retained(self):
        self.b.output.mkdir()
        marker = self.b.output / "untouched"
        marker.write_bytes(b"retained")
        self.blocked("new nonexistent")
        self.assertEqual(marker.read_bytes(), b"retained")

    def test_failed_or_aggregate_only_report_cannot_produce_request(self):
        self.b.report = {k: self.b.report[k] for k in ("out", "gradle_volume", "offline", "image", "tasks", "publication_repository", "requested_version")}
        self.b.report["status"] = "failed"
        self.b.report_bytes()
        self.blocked()
        self.assertFalse(self.b.output.exists())

    def test_status_target_version_and_image_gates(self):
        cases = (("status", "failed"), ("publication_repository", "other/project"), ("requested_version", "9.9.9"), ("image", ""), ("offline", 1))
        for key, value in cases:
            original = self.b.report[key]
            self.b.report[key] = value
            self.b.report_bytes()
            self.blocked()
            self.b.report[key] = original
        self.b.report_bytes()

    def test_allowlisted_task_order_exactly_once(self):
        for tasks in (["test"], ["buildAndroid", "test"], ["test", "test", "buildAndroid"], ["test", "buildAndroid", "publish"], ["clean", "buildAndroid", "test"], ["--init-script=x", "test", "buildAndroid"]):
            self.b.report["tasks"] = tasks
            self.b.report_bytes()
            self.blocked("tasks")
        self.b.report["tasks"] = ["clean", "test", "buildAndroid"]
        self.b.report_bytes()
        self.b.freeze()

    def test_bundle_metadata_pins_revalidated_not_report_status(self):
        for kwargs in (dict(version="9.0.0"), dict(patcher="2.4.0"), dict(author="other")):
            self.b.write_bundle(**kwargs)
            self.b.save_report()
            self.blocked("identity/version")

    def test_all_three_defaults_true_and_exact_three_names(self):
        for patch in self.b.catalog["patches"]:
            patch["default"] = False
            self.b.save_catalog()
            self.b.save_report()
            self.blocked("names/defaults")
            patch["default"] = True
        self.b.catalog["patches"].pop()
        self.b.save_catalog()
        self.b.save_report()
        self.blocked("exact three")

    def test_provenance_is_from_reviewed_records_not_invented(self):
        path = self.b.source / "docs/termius-migration.json"
        record, _ = r.read_json(path)
        record["entries"][0]["original_sha256"] = "a" * 64
        path.write_bytes(r.canonical(record))
        self.b.archive()
        self.blocked("original source")

    def test_plex_migration_record_original_and_migrated_pins(self):
        path = self.b.source / "docs/plex-migration.json"
        record, _ = r.read_json(path)
        record["files"][0]["original_sha256"] = "a" * 64
        path.write_bytes(r.canonical(record))
        self.b.archive()
        self.blocked("pinned Plex")

    def test_no_provenance_from_extra_or_duplicate_entries(self):
        path = self.b.source / "docs/termius-migration.json"
        record, _ = r.read_json(path)
        record["entries"].append(record["entries"][0])
        path.write_bytes(r.canonical(record))
        self.b.archive()
        self.blocked("duplicate Termius")

    def test_source_bytes_change_archive_cannot_bless_other_root(self):
        path = self.b.source / "new-public-source.txt"
        path.write_bytes(b"not included in build")
        self.blocked("archive differs")

    def test_partial_tar_rejected(self):
        self.b.archive(omit="gradlew")
        self.blocked("archive differs")

    def test_excluded_public_paths_cannot_be_hidden_even_empty(self):
        for name in (".gradle", "build", "local.properties", "nested/build", "nested/.git"):
            path = self.b.source / name
            path.mkdir(parents=True)
            self.blocked("driver-excluded")
            path.rmdir()

    def test_top_level_git_is_the_only_source_tree_exclusion(self):
        git = self.b.source / ".git"
        git.mkdir()
        (git / "private-metadata").write_bytes(b"not source, never frozen")
        self.assertNotIn(".git/private-metadata", r.source_tree(self.b.source)[1])
        self.b.freeze()

    def test_tar_path_aliases_duplicates_traversal_and_case_collisions(self):
        for name in ("../outside", "/absolute", "C:/drive", "././alias", "one//two", "one/../two", "one\\two", "./gradlew", "./GRADLEW"):
            info = tarfile.TarInfo(name)
            info.size = 1
            self.b.archive(extra=[(info, b"x")])
            self.blocked()

    def test_tar_directory_aliases_and_pax_overrides_rejected(self):
        for name in ("aliased//", "././aliased/", "aliased/../other/"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            self.b.archive(extra=[(info, b"")])
            self.blocked()
        with tarfile.open(self.b.build / "source.tar", "w", format=tarfile.PAX_FORMAT) as tar:
            info = tarfile.TarInfo("header")
            info.pax_headers = {"path": "override"}
            tar.addfile(info, io.BytesIO(b""))
        self.blocked("overrides")

    def test_tar_link_and_special_members_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            info = tarfile.TarInfo("bad-member")
            info.type = kind
            info.linkname = "gradlew"
            self.b.archive(extra=[(info, b"")])
            self.blocked("links/special")

    def test_tar_extension_chains_and_trailing_hidden_archive_rejected(self):
        info = tarfile.TarInfo("././@LongLink")
        info.type, info.size = tarfile.GNUTYPE_LONGNAME, 2
        self.b.archive(extra=[(info, b"a\x00"), (info, b"b\x00")])
        self.blocked("extended-header chain")
        self.b.archive()
        archive = self.b.build / "source.tar"
        archive.write_bytes(archive.read_bytes() + b"hidden trailing payload")
        self.blocked("terminator")

    def test_only_optional_single_dot_prefix_normalized(self):
        self.b.archive(prefix="")
        self.b.freeze()

    def test_source_archive_bound(self):
        with mock.patch.object(f, "MAX_SOURCE", 16):
            self.blocked("too large")

    def test_build_configuration_and_dependency_substitution_rejected(self):
        path = self.b.source / "gradle/libs.versions.toml"
        path.write_bytes(path.read_bytes().replace(b'"2.3.0"', b'"2.4.0"'))
        self.b.archive()
        self.blocked("unreviewed build configuration")

    def test_additional_init_or_gradle_build_script_rejected(self):
        (self.b.source / "substitution.gradle.kts").write_bytes(b"// synthetic substitution")
        self.b.archive()
        self.blocked("build configuration")

    def test_retained_hash_mismatch_and_unreported_artifact(self):
        self.b.bundle.write_bytes(self.b.bundle.read_bytes() + b"tampered")
        self.blocked("artifact hash mismatch")
        self.b.write_bundle()
        self.b.save_report()
        (self.b.build / "artifacts/unreported.jar").write_bytes(b"synthetic")
        self.blocked("artifacts differ")

    def test_additional_mpp_rejected_even_reported(self):
        (self.b.bundle.parent / "other.mpp").write_bytes(self.b.bundle.read_bytes())
        self.b.save_report()
        self.blocked("exact one MPP")

    def test_supplied_paths_must_be_exact_collected_inputs(self):
        alias = self.base / "same-bytes.mpp"
        alias.write_bytes(self.b.bundle.read_bytes())
        args = self.b.args()
        args["bundle_path"] = alias
        with self.assertRaisesRegex(r.ReleaseError, "exact retained"):
            f.freeze(**args)

    def test_final_mpp_hash_and_path_both_bound(self):
        record = self.b.build / "final-mpp.sha256"
        record.write_text("a" * 64 + "  /output/work/patches/build/libs/patches-0.1.0.mpp\n", encoding="utf-8")
        self.blocked("binding mismatch")
        self.b.save_report()
        record.write_bytes(record.read_bytes().replace(b"/output/work/patches/", b"/output/work/other/"))
        self.blocked("path mismatch")

    def test_junit_missing_class_rejected_even_positive_aggregate(self):
        self.b.xml_paths[0].unlink()
        self.b.save_report()
        self.blocked("six-class")

    def test_junit_missing_method_rejected_even_counts_agree(self):
        def remove(root):
            root.remove(root.findall("testcase")[0])
            root.set("tests", str(len(root.findall("testcase"))))
        self.b.edit_xml(remove)
        self.blocked("method coverage")

    def test_parameterized_every_label_required_not_just_base_method(self):
        index = next(i for i, p in enumerate(self.b.xml_paths) if "OfflineAutomation" in p.name)
        self.b.edit_xml(lambda root: root.findall("testcase")[0].set("name", "originalLayoutIsAccepted[0]"), index)
        self.blocked("method/class")

    def test_skips_failures_and_errors_rejected_despite_status(self):
        original = self.b.xml_paths[0].read_bytes()
        for tag in ("skipped", "failure", "error"):
            self.b.xml_paths[0].write_bytes(original)
            self.b.edit_xml(lambda root: ET.SubElement(root.findall("testcase")[0], tag))
            self.blocked("failed/errored/skipped")

    def test_duplicate_case_rejected_even_adjusted_count(self):
        def duplicate(root):
            root.append(copy.deepcopy(root.findall("testcase")[0]))
            root.set("tests", str(len(root.findall("testcase"))))
        self.b.edit_xml(duplicate)
        self.blocked("duplicate JUnit method")

    def test_suite_and_report_count_lies_rejected(self):
        self.b.edit_xml(lambda root: root.set("tests", str(int(root.get("tests")) + 1)))
        self.blocked("counts differ")
        self.b.edit_xml(lambda root: root.set("tests", str(len(root.findall("testcase")))))
        self.b.report["tests"]["tests"] += 1
        self.b.report_bytes()
        self.blocked("aggregate count")

    def test_duplicate_suite_and_xml_entity_rejected(self):
        self.b.xml_paths[1].write_bytes(self.b.xml_paths[0].read_bytes())
        self.b.save_report()
        self.blocked("duplicate JUnit suite")
        data = self.b.xml_paths[0].read_bytes()
        self.b.xml_paths[0].write_bytes(b'<!DOCTYPE testsuite [<!ENTITY x "bad">]>' + data)
        # Refresh hashes manually: parsing this fixture is the validator's job.
        self.b.report["sha256"][self.b.xml_paths[0].relative_to(self.b.build).as_posix()] = r.digest(self.b.xml_paths[0].read_bytes())
        self.b.report_bytes()
        self.blocked("unsafe JUnit")

    def test_source_test_new_method_requires_actual_case_and_ignore_is_blocked(self):
        name = f.TEST_PREFIX + f.TEST_CLASSES[0].replace(".", "/") + ".kt"
        path = self.b.source / name
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace("class CollectionInventoryTest {", "class CollectionInventoryTest {\n @Test fun newlyRequiredMethod() {}"), encoding="utf-8")
        self.b.archive()
        self.blocked("method coverage")
        path.write_text(original.replace("@Test fun", "@Ignore @Test fun", 1), encoding="utf-8")
        self.b.archive()
        self.blocked("ignored source")

    def test_reviewed_test_annotation_and_matching_xml_cannot_be_removed(self):
        name = f.TEST_CLASSES[0]
        method = "exactThreeRealDefinitionsDefaultsTypesAndDependencies"
        path = self.b.source / (f.TEST_PREFIX + name.replace(".", "/") + ".kt")
        text = path.read_text(encoding="utf-8")
        path.write_text(text.replace("@Test fun " + method, "fun " + method, 1), encoding="utf-8")
        self.b.archive()
        index = next(i for i, p in enumerate(self.b.xml_paths) if name in p.name)
        def remove(root):
            case = next(c for c in root.findall("testcase") if c.get("name") == method)
            root.remove(case)
            root.set("tests", str(len(root.findall("testcase"))))
        self.b.edit_xml(remove, index)
        self.blocked("reviewed minimum test inventory")

    def test_late_retained_artifact_addition_in_final_snapshot_is_rejected(self):
        original_snapshot, original_junit = f.snapshot, f.junit
        calls = 0
        def snapshot(*args):
            nonlocal calls
            calls += 1
            return original_snapshot(*args)
        def junit(*args):
            result = original_junit(*args)
            if calls == 4:
                (self.b.build / "artifacts/unreported.bin").write_bytes(b"fictional late artifact")
            return result
        with mock.patch.object(f, "snapshot", side_effect=snapshot), mock.patch.object(f, "junit", side_effect=junit):
            self.blocked("retained artifacts changed during snapshot")
        self.assertEqual(calls, 4)
        self.assertTrue((self.b.output / "freeze-failed.json").is_file())
        self.assertTrue((self.b.output / "freeze-incomplete.json").is_file())

    def test_unexpected_output_file_in_final_snapshot_is_rejected(self):
        original = f.snapshot
        calls = 0
        def snapshot(*args):
            nonlocal calls
            calls += 1
            result = original(*args)
            if calls == 4:
                (self.b.output / "unexpected.txt").write_bytes(b"fictional extra output")
            return result
        with mock.patch.object(f, "snapshot", side_effect=snapshot):
            self.blocked("exact four regular frozen output files")
        self.assertEqual(calls, 4)
        self.assertTrue((self.b.output / "freeze-failed.json").is_file())
        self.assertTrue((self.b.output / "freeze-incomplete.json").is_file())

    def test_ordinary_pristine_source_hardlink_is_rejected(self):
        path = self.b.source / "ordinary-source.txt"
        path.write_bytes(b"fictional ordinary source, not a selected configuration/input")
        os.link(path, self.base / "external-source-alias.txt")
        self.assertEqual(path.stat().st_nlink, 2)
        self.b.archive()
        self.blocked("hard-linked input forbidden")
        self.assertFalse(self.b.output.exists())

    def test_reviewed_floor_binds_every_method_identity_not_only_counts(self):
        paths = r.source_tree(self.b.source)[1]
        expected = f.expected_tests(self.b.source, paths)
        self.assertEqual([len(expected[n]) for n in f.TEST_CLASSES], [11, 39, 27, 9, 18, 17])
        self.assertEqual(sum(map(len, expected.values())), 121)
        for name, cases in expected.items():
            path = self.b.source / (f.TEST_PREFIX + name.replace(".", "/") + ".kt")
            original = path.read_text(encoding="utf-8")
            # Automation's 39 cases correspond to 13 independently required methods.
            methods = {case.split("[", 1)[0] for case in cases}
            for method in sorted(methods):
                with self.subTest(name=name, method=method):
                    changed = original.replace("@Test fun " + method + "(", "@Test fun renamedReviewedMethod(", 1)
                    self.assertNotEqual(changed, original)
                    path.write_text(changed, encoding="utf-8")
                    try:
                        with self.assertRaisesRegex(r.ReleaseError, "reviewed minimum test inventory"):
                            f.expected_tests(self.b.source, paths)
                    finally:
                        path.write_text(original, encoding="utf-8")

    def test_every_reviewed_case_including_each_automation_parameter_is_required(self):
        expected = f.expected_tests(self.b.source, r.source_tree(self.b.source)[1])
        checked = 0
        for path in self.b.xml_paths:
            original = path.read_bytes()
            for index, case in enumerate(ET.fromstring(original).findall("testcase")):
                with self.subTest(name=case.get("classname"), case=case.get("name")):
                    root = ET.fromstring(original)
                    root.remove(root.findall("testcase")[index])
                    root.set("tests", str(len(root.findall("testcase"))))
                    with self.assertRaisesRegex(r.ReleaseError, "method coverage"):
                        f.junit(ET.tostring(root), expected)
                    checked += 1
        self.assertEqual(checked, 121)

    def test_added_method_is_allowed_only_when_present_and_executed(self):
        name, method = f.TEST_CLASSES[0], "newlyRequiredMethod"
        path = self.b.source / (f.TEST_PREFIX + name.replace(".", "/") + ".kt")
        original = path.read_text(encoding="utf-8")
        path.write_text(original.replace("class CollectionInventoryTest {", "class CollectionInventoryTest {\n @Test fun " + method + "() {}"), encoding="utf-8")
        self.b.archive()
        self.blocked("method coverage")
        index = next(i for i, p in enumerate(self.b.xml_paths) if name in p.name)
        def add(root):
            ET.SubElement(root, "testcase", classname=name, name=method, time="0.0")
            root.set("tests", str(len(root.findall("testcase"))))
        self.b.edit_xml(add, index)
        out = self.b.freeze()
        inventory, _ = r.read_json(out / "freeze.json")
        self.assertEqual(inventory["tests"]["tests"], 122)
        self.assertIn(method, inventory["test_cases"][name])
        # An executed XML row alone must not invent a source declaration.
        path.write_text(original, encoding="utf-8")
        expected = f.expected_tests(self.b.source, r.source_tree(self.b.source)[1])
        with self.assertRaisesRegex(r.ReleaseError, "method/class"):
            f.junit(self.b.xml_paths[index].read_bytes(), expected)

    def test_empty_or_nested_output_directories_are_not_completed(self):
        for nested in (False, True):
            with self.subTest(nested=nested):
                b = SyntheticBuild(self.base / str(nested))
                original = f.snapshot
                calls = 0
                def snapshot(*args):
                    nonlocal calls
                    calls += 1
                    result = original(*args)
                    if calls == 4:
                        extra = b.output / "unexpected-directory"
                        extra.mkdir()
                        if nested:
                            (extra / "file.txt").write_bytes(b"fictional nested extra")
                    return result
                with mock.patch.object(f, "snapshot", side_effect=snapshot):
                    with self.assertRaisesRegex(r.ReleaseError, "exact four regular frozen output files"):
                        b.freeze()
                self.assertTrue((b.output / "freeze-failed.json").is_file())
                self.assertTrue((b.output / "freeze-incomplete.json").is_file())
                self.assertFalse((b.output / "freeze.json").exists())

    def test_disjoint_external_new_output_and_pristine_root(self):
        for output in (self.b.source / "out", self.b.build / "out", ROOT / "freeze-forbidden-synthetic"):
            self.b.output = output
            self.blocked()
            self.assertFalse(output.exists())
        args = self.b.args()
        args["source_root"] = self.b.build / "work"
        args["source_root"].mkdir()
        with self.assertRaises(r.ReleaseError):
            f.freeze(**args)

    def test_duplicate_json_keys_and_nested_property_substitution_rejected(self):
        report = self.b.build / "build.json"
        original = report.read_bytes()
        report.write_bytes(b'{"status":"failed",' + original[1:])
        self.blocked("duplicate JSON key")
        report.write_bytes(original)
        (self.b.source / "patches/gradle.properties").write_bytes(b"syntheticDependencyOverride=1\n")
        self.b.archive()
        self.blocked("build configuration")

    def test_mutation_late_in_single_snapshot_is_rehashed(self):
        path = self.b.source / "unrelated.txt"
        path.write_bytes(b"original")
        self.b.archive()
        original = f.junit
        def changed(*args):
            result = original(*args)
            path.write_bytes(b"mutated after initial tree hash")
            return result
        with mock.patch.object(f, "junit", side_effect=changed):
            self.blocked("source changed during snapshot")

    def test_frozen_output_mutation_is_failed_not_completed(self):
        original = f.snapshot
        calls = 0
        def changed(*args):
            nonlocal calls
            calls += 1
            result = original(*args)
            if calls == 3:
                (self.b.output / "request.json").write_bytes(b"changed")
            return result
        with mock.patch.object(f, "snapshot", side_effect=changed):
            with self.assertRaisesRegex(r.ReleaseError, "frozen output changed"):
                self.b.freeze()
        self.assertTrue((self.b.output / "freeze-failed.json").exists())
        self.assertFalse((self.b.output / "freeze.json").exists())

    def test_linked_ancestry_rejected_before_resolution(self):
        original = r.linked
        with mock.patch.object(r, "linked", side_effect=lambda p: Path(p) == self.base or original(p)):
            self.blocked("linked.*ancestry")

    def test_rehash_every_input_after_creation_rejects_mutation_retains_failure(self):
        targets = ("source", "report", "archive", "final", "bundle", "catalog", "xml")
        for target in targets:
            with self.subTest(target=target):
                b = SyntheticBuild(self.base / target)
                path = {"source": b.source / "gradlew", "report": b.build / "build.json", "archive": b.build / "source.tar", "final": b.build / "final-mpp.sha256", "bundle": b.bundle, "catalog": b.catalog_path, "xml": b.xml_paths[0]}[target]
                original = r.new_output
                def changed(*args):
                    out = original(*args)
                    path.write_bytes(path.read_bytes() + b"mutation")
                    return out
                with mock.patch.object(r, "new_output", side_effect=changed):
                    with self.assertRaises((r.ReleaseError, ValueError)):
                        b.freeze()
                self.assertTrue((b.output / "freeze-failed.json").is_file())
                self.assertTrue((b.output / "request.json").is_file())
                self.assertFalse((b.output / "freeze.json").exists())
                self.assertTrue(path.is_file())

    def test_postfreeze_mutation_records_explicit_failure_not_success(self):
        original = f.snapshot
        calls = 0
        def snapshot(*args):
            nonlocal calls
            calls += 1
            if calls == 4:
                self.b.bundle.write_bytes(self.b.bundle.read_bytes() + b"mutation")
            return original(*args)
        with mock.patch.object(f, "snapshot", side_effect=snapshot):
            with self.assertRaises(r.ReleaseError):
                self.b.freeze()
        self.assertTrue((self.b.output / "freeze-failed.json").exists())
        self.assertTrue((self.b.output / "freeze-incomplete.json").exists())
        self.assertFalse((self.b.output / "freeze.json").exists())

    def test_description_and_clock_rejected_before_writes(self):
        args = self.b.args()
        args["description"] = "   "
        with self.assertRaises(r.ReleaseError):
            f.freeze(**args)
        args["description"] = "Synthetic"
        args["now"] = NOW.replace(tzinfo=None)
        with self.assertRaises(r.ReleaseError):
            f.freeze(**args)
        self.assertFalse(self.b.output.exists())

    def test_cli_help_and_stdout_no_paths_or_observation_claims(self):
        script = ROOT / "tools/release/freeze.py"
        proc = subprocess.run([sys.executable, "-I", "-B", str(script), "--help"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("BEFORE", proc.stdout)
        args = self.b.args()
        cmd = [sys.executable, "-I", "-B", str(script)]
        for name in ("source_root", "build_report", "bundle_path", "catalog_path", "output", "description"):
            flag = name.removesuffix("_path").replace("_", "-")
            cmd += ["--" + flag, str(args[name])]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        result = json.loads(proc.stdout)
        self.assertEqual(set(result), {"status", "request_sha256", "bundle_sha256", "catalog_sha256", "source_tree_sha256"})
        self.assertNotIn(str(self.base), proc.stdout)


if __name__ == "__main__":
    unittest.main()
