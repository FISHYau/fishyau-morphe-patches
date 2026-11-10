"""Mocked gh only. No live GitHub calls, authentication or vendor APK inputs."""
import base64
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("publisher_under_test", ROOT / "tools/publish.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
SPEC = importlib.util.spec_from_file_location("publisher_synthetic_fixtures", ROOT / "tests/test_bundle_formats.py")
fixtures = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixtures)
f = p.f
VERSION = "0.2.7-test.1"
HEAD, BASE_TREE, BLOB, TREE, NEW, CONCURRENT = [str(i) * 40 for i in range(1, 7)]


class FakeGitHub:
    """Stateful API double: models upload readback and nonforce sibling conflicts."""
    def __init__(self, files, *, manifest_present=True):
        self.files = files
        self.calls = []
        self.head = HEAD
        self.tag = None
        self.release_exists = False
        self.upload_fail = False
        self.readback_fail = False
        self.readback_corrupt = False
        self.manifest_present = manifest_present
        self.advance_after_upload = False
        self.advance_before_cas = False
        self.blob_content = None
        self.asset_names = [f"patches-{VERSION}.mpp", "patches-list.json"]

    def upload(self, tag, paths):
        self.calls.append(("UPLOAD", tag, [path.name for path in paths]))
        if self.upload_fail:
            raise ValueError("synthetic upload failure")
        if self.advance_after_upload:
            self.head = CONCURRENT

    def api(self, path, method="GET", body=None, *, binary=False, limit=None):
        self.calls.append((method, path, body))
        if path == "/git/ref/heads/main":
            return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": self.head}}
        if path == "/git/commits/" + HEAD:
            return {"tree": {"sha": BASE_TREE}}
        if path == "/git/trees/" + BASE_TREE:
            return {"truncated": False, "tree": [
                {"path": p.MANIFEST, "type": "blob", "mode": "100644", "sha": "a" * 40}
            ] if self.manifest_present else []}
        if path.startswith("/git/matching-refs/tags/"):
            return [] if self.tag is None else [{"ref": "refs/tags/v" + VERSION, "object": {"type": "commit", "sha": self.tag}}]
        if path.startswith("/releases?"):
            return [{"tag_name": "v" + VERSION}] if self.release_exists else []
        if path == "/git/refs" and method == "POST":
            self.tag = body["sha"]
            return {"ref": body["ref"], "object": {"type": "commit", "sha": self.tag}}
        if path == "/releases" and method == "POST":
            return {"id": 7, "tag_name": "v" + VERSION, "draft": True, "assets": []}
        if path == "/releases/7/assets?per_page=100":
            return [{"id": index, "name": name, "state": "uploaded", "size": len(self.files[name])}
                    for index, name in enumerate(self.asset_names, 10)]
        if path.startswith("/releases/assets/"):
            if self.readback_fail:
                raise ValueError("synthetic readback failure")
            if self.readback_corrupt:
                return b"synthetic wrong uploaded bytes"
            self_test_limit = f.MAX_BUNDLE if path.endswith("10") else f.MAX_JSON
            if not binary or limit != self_test_limit:
                raise AssertionError("bounded binary asset download required")
            return self.files[self.asset_names[int(path.rsplit("/", 1)[1]) - 10]]
        if path == "/releases/7" and method == "PATCH":
            return {"id": 7, "tag_name": "v" + VERSION, "draft": False}
        if path == "/git/blobs" and method == "POST":
            self.blob_content = base64.b64decode(body["content"])
            return {"sha": BLOB}
        if path == "/git/trees" and method == "POST":
            if body != {"base_tree": BASE_TREE, "tree": [{"path": p.MANIFEST, "mode": "100644", "type": "blob", "sha": BLOB}]}:
                raise AssertionError("only manifest may change")
            return {"sha": TREE}
        if path == "/git/commits" and method == "POST":
            if body["parents"] != [HEAD] or body["tree"] != TREE:
                raise AssertionError("commit must have captured main as sole parent")
            return {"sha": NEW}
        if path == "/git/refs/heads/main" and method == "PATCH":
            if self.advance_before_cas:
                self.head = CONCURRENT
            if self.head != HEAD:
                raise ValueError("synthetic nonfastforward conflict")
            if body != {"sha": NEW, "force": False}:
                raise AssertionError("force updates forbidden")
            self.head = NEW
            return {"object": {"sha": NEW}}
        raise AssertionError(f"unexpected fake API operation: {method} {path}")


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="publish-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.bundle = self.base / "synthetic.mpp"
        self.catalog = self.base / "synthetic.json"
        self.bundle.write_bytes(fixtures.bundle_fixture())
        self.catalog.write_bytes(f.canonical(fixtures.catalog_fixture()))

    def prepare(self, out="prepared", **overrides):
        args = dict(repository="fixture-owner/fixture-repository", version=VERSION,
                    bundle=self.bundle, catalog=self.catalog, out=self.base / out,
                    created_at=fixtures.WHEN, description="Synthetic only")
        args.update(overrides)
        return p.prepare(**args)

    def assert_manifest_unchanged(self, gh):
        self.assertNotIn(("PATCH", "/git/refs/heads/main"), [(method, path) for method, path, _ in gh.calls])
        self.assertEqual(gh.head, HEAD if not gh.advance_after_upload else CONCURRENT)

    def test_dry_run_never_constructs_gh_or_calls_network(self):
        out = self.base / "dry"
        with mock.patch.object(p, "GitHub", side_effect=AssertionError("no gh in dry run")), mock.patch.object(p.subprocess, "run", side_effect=AssertionError("no commands")):
            result = p.main(["--repository", "fixture-owner/fixture-repository", "--version", VERSION,
                             "--bundle", str(self.bundle), "--catalog", str(self.catalog), "--out", str(out),
                             "--created-at", fixtures.WHEN])
        self.assertEqual(result, 0)
        self.assertEqual({item.name for item in out.iterdir()}, {f"patches-{VERSION}.mpp", "patches-list.json", p.MANIFEST})
        manifest, _ = f.read_json(out / p.MANIFEST)
        self.assertEqual(manifest["version"], VERSION)
        self.assertNotIn("public_key", manifest)

    def test_prepared_catalog_preserves_four_entry_default_on_tv_metadata(self):
        directory, _, _ = self.prepare()
        catalog, _ = f.read_json(directory / "patches-list.json")
        self.assertEqual({patch["name"]: patch["default"] for patch in catalog["patches"]}, {
            "Server Auditor Offline Automation": True, "Server Auditor Premium": True,
            "Premium unlock": True, "Disable Home previews": True})
        spotify = next(patch for patch in catalog["patches"] if patch["name"] == "Disable Home previews")
        app = spotify["compatiblePackages"][0]
        self.assertEqual((app["packageName"], app["apkFileType"], app["formFactor"]),
                         ("com.spotify.tv.android", "APKM_REQUIRED", "TV"))
        self.assertEqual(app["targets"][0]["versionCodes"], {abi: 147600562 for abi in f.ABI})

    def test_wrong_spotify_metadata_never_creates_prepared_output_or_network(self):
        for field, value in (("default", False), ("apkFileType", "APKM"), ("formFactor", "MOBILE"),
                             ("targets", []), ("packageName", "com.example.other")):
            catalog = fixtures.catalog_fixture()
            spotify = next(patch for patch in catalog["patches"] if patch["name"] == "Disable Home previews")
            (spotify if field == "default" else spotify["compatiblePackages"][0])[field] = value
            self.catalog.write_bytes(f.canonical(catalog))
            with self.subTest(field=field), mock.patch.object(p, "GitHub", side_effect=AssertionError("no network")):
                with self.assertRaises(ValueError):
                    self.prepare()
            self.assertFalse((self.base / "prepared").exists())

    def test_success_manifest_last_and_initial_absent_supported(self):
        for present in (True, False):
            with self.subTest(present=present):
                directory, manifest, files = self.prepare(out="present" if present else "absent")
                gh = FakeGitHub(files, manifest_present=present)
                self.assertEqual(p.publish(gh, directory, manifest, files), NEW)
                mutations = [(method, path) for method, path, _ in gh.calls if method != "GET"]
                self.assertEqual(mutations[-1], ("PATCH", "/git/refs/heads/main"))
                upload_index = next(i for i, call in enumerate(gh.calls) if call[0] == "UPLOAD")
                download_indices = [i for i, call in enumerate(gh.calls) if call[1].startswith("/releases/assets/")]
                release_index = next(i for i, call in enumerate(gh.calls) if call[:2] == ("PATCH", "/releases/7"))
                self.assertEqual(len(download_indices), 2)
                self.assertTrue(all(upload_index < i < release_index for i in download_indices))
                self.assertEqual(gh.blob_content, files[p.MANIFEST])
                commit_body = next(body for method, path, body in gh.calls
                                   if method == "POST" and path == "/git/commits")
                self.assertTrue(commit_body["message"].endswith(
                    "\n\nCo-Authored-By: Claude Code <noreply@anthropic.com>"))
                self.assertEqual(gh.calls[upload_index][2], [f"patches-{VERSION}.mpp", "patches-list.json"])

    def test_upload_and_readback_failures_do_not_advance_manifest(self):
        for failure in ("upload_fail", "readback_fail", "readback_corrupt"):
            directory, manifest, files = self.prepare(out=failure)
            gh = FakeGitHub(files)
            setattr(gh, failure, True)
            with self.subTest(failure=failure), self.assertRaises(ValueError):
                p.publish(gh, directory, manifest, files)
            self.assert_manifest_unchanged(gh)
            self.assertNotIn(("PATCH", "/releases/7"), [(method, path) for method, path, _ in gh.calls])
            self.assertTrue(directory.is_dir(), "failed outputs retained")

    def test_conflicting_existing_tag_or_release_has_no_writes(self):
        for conflict in ("tag", "release"):
            directory, manifest, files = self.prepare(out=conflict)
            gh = FakeGitHub(files)
            if conflict == "tag":
                gh.tag = HEAD
            else:
                gh.release_exists = True
            with self.assertRaises(ValueError):
                p.publish(gh, directory, manifest, files)
            self.assertTrue(all(method == "GET" for method, _, _ in gh.calls))

    def test_branch_change_after_upload_is_not_merged(self):
        directory, manifest, files = self.prepare()
        gh = FakeGitHub(files)
        gh.advance_after_upload = True
        with self.assertRaisesRegex(ValueError, "main changed"):
            p.publish(gh, directory, manifest, files)
        self.assert_manifest_unchanged(gh)

    def test_race_at_final_ref_update_is_nonforce_conflict_no_rollback(self):
        directory, manifest, files = self.prepare()
        gh = FakeGitHub(files)
        gh.advance_before_cas = True
        with self.assertRaisesRegex(ValueError, "nonfastforward"):
            p.publish(gh, directory, manifest, files)
        self.assertEqual(gh.head, CONCURRENT)
        mutations = [(method, path) for method, path, _ in gh.calls if method != "GET"]
        self.assertEqual(mutations[-1], ("PATCH", "/git/refs/heads/main"))
        self.assertEqual(mutations.count(("PATCH", "/git/refs/heads/main")), 1)
        self.assertFalse(any(method == "DELETE" for method, _, _ in gh.calls))

    def test_changed_prepared_asset_blocks_upload(self):
        directory, manifest, files = self.prepare()
        (directory / "patches-list.json").write_bytes(b"changed")
        gh = FakeGitHub(files)
        with self.assertRaisesRegex(ValueError, "prepared asset changed"):
            p.publish(gh, directory, manifest, files)
        self.assert_manifest_unchanged(gh)
        self.assertFalse(any(method == "UPLOAD" for method, _, _ in gh.calls))

    def test_bad_inputs_create_no_output_or_remote_calls(self):
        for key, value in (("repository", "--help"), ("repository", "owner/repo/extra"),
                           ("repository", "owner/--help"), ("version", "../../unsafe"),
                           ("version", "0.1.0"), ("created_at", fixtures.WHEN + "Z"),
                           ("description", "\nsecret")):
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.prepare(**{key: value})
            self.assertFalse((self.base / "prepared").exists())
        for wrong in (fixtures.bundle_fixture(manifest="Name: Wrong\nAuthor: FISHYau\nVersion: " + VERSION + "\nPatcher-Version: 2.3.0\n\n"),
                      fixtures.bundle_fixture(manifest="Name: FISHYau android patches\nAuthor: FISHYau\nVersion: " + VERSION + "\nPatcher-Version: 9.0.0\n\n"),
                      fixtures.bundle_fixture(extra=[("signature.sig", b"fixture")])):
            self.bundle.write_bytes(wrong)
            with self.assertRaises(ValueError):
                self.prepare()
            self.assertFalse((self.base / "prepared").exists())

    def test_output_new_and_external(self):
        self.prepare()
        with self.assertRaises(ValueError):
            self.prepare()
        with self.assertRaisesRegex(ValueError, "external"):
            self.prepare(out=ROOT / "forbidden-publish-output")
        self.assertFalse((ROOT / "forbidden-publish-output").exists())
        with self.assertRaisesRegex(ValueError, "filename#label"):
            self.prepare(out="unsupported#label")
        self.assertFalse((self.base / "unsupported#label").exists())

    def test_gh_argv_no_shell_no_clobber_and_redacted_errors(self):
        with mock.patch.object(p.shutil, "which", return_value="C:/installed/gh.exe"):
            gh = p.GitHub("fixture-owner/fixture-repository")
        captured = []
        def run(args, **kwargs):
            captured.append((args, kwargs))
            kwargs["stdout"].write(b'{}')
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(p.subprocess, "run", side_effect=run):
            gh.upload("v" + VERSION, [self.bundle])
            gh.api("/git/blobs", "POST", {"encoding": "base64", "content": "fixture"})
        argv, kwargs = captured[0]
        self.assertIsInstance(argv, list)
        self.assertNotIn("--clobber", argv)
        self.assertNotIn("shell", kwargs)
        self.assertEqual(argv[-1], "github.com/fixture-owner/fixture-repository")
        self.assertEqual(captured[1][1]["input"], f.canonical({"encoding": "base64", "content": "fixture"}))
        with mock.patch.object(p.subprocess, "run", side_effect=OSError("secret-token-synthetic")):
            with self.assertRaises(ValueError) as caught:
                gh.api("/git/ref/heads/main")
        self.assertNotIn("secret-token-synthetic", str(caught.exception))

    def test_gh_binary_and_failure_adapter(self):
        with mock.patch.object(p.shutil, "which", return_value="C:/installed/gh.exe"):
            gh = p.GitHub("fixture-owner/fixture-repository")
        payload = b"\x00\xffsynthetic-asset\r\n"
        def binary(args, **kwargs):
            self.assertIn("Accept: application/octet-stream", args)
            kwargs["stdout"].write(payload)
            return subprocess.CompletedProcess(args, 0)
        with mock.patch.object(p.subprocess, "run", side_effect=binary):
            self.assertEqual(gh.api("/releases/assets/1", binary=True), payload)
        def failed(args, **kwargs):
            kwargs["stderr"].write(b"synthetic-secret-not-for-errors")
            return subprocess.CompletedProcess(args, 1)
        for effect in (failed, subprocess.TimeoutExpired("synthetic-secret-not-for-errors", 180)):
            with mock.patch.object(p.subprocess, "run", side_effect=effect):
                with self.assertRaisesRegex(ValueError, "details redacted") as caught:
                    gh.api("/git/ref/heads/main")
                self.assertNotIn("synthetic-secret", str(caught.exception))
        with mock.patch.object(p.subprocess, "run", side_effect=binary):
            with self.assertRaisesRegex(ValueError, "too large"):
                gh.api("/releases/assets/1", binary=True, limit=2)


if __name__ == "__main__":
    unittest.main()
