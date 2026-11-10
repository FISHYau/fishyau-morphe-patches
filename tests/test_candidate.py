"""Synthetic offline producer tests. No Git init, real evidence, runner or upload."""
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


fmod = load("candidate_synthetic_fixtures", ROOT / "tests/test_staging.py")
c = load("candidate_under_test", ROOT / "tools/release/candidate.py")
r = c.r


class CandidateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="candidate-synthetic-")
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name)
        self.f = fmod.CollectionFixture(self.base)
        self.directory = self.f.stage()
        self.files, self.summary, self.seal = c.p.candidate(self.directory)
        self.output = self.base / "snapshot"

    def validate(self, **kwargs):
        return c.validate(self.directory, self.f.source, self.seal, **kwargs)

    def snapshot(self, **kwargs):
        return c.snapshot(self.directory, self.f.source, self.seal, self.output, **kwargs)

    def reseal(self):
        files = {name: (self.directory / name).read_bytes() for name in c.p.FILES if name != "SHA256SUMS"}
        sums = "".join(f"{r.digest(data)}  {name}\n" for name, data in sorted(files.items())).encode("ascii")
        (self.directory / "SHA256SUMS").write_bytes(sums)
        files["SHA256SUMS"] = sums
        self.seal = r.digest(r.canonical({name: r.digest(data) for name, data in files.items()}))

    def change_json(self, name, change):
        path = self.directory / name
        value = json.loads(path.read_bytes())
        change(value)
        path.write_bytes(r.canonical(value))
        self.reseal()

    def link(self, destination, target, directory=False):
        try:
            destination.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("platform cannot create test symlinks")

    def test_validate_is_readonly_and_snapshot_exact_five_frozen_bytes(self):
        before = r.source_tree(self.f.source)
        with mock.patch.object(r, "clean_revision") as clean:
            files, summary, seal = self.validate()
        clean.assert_not_called()
        self.assertEqual(seal, self.seal)
        self.assertEqual(dict(files), dict(self.files))
        self.assertFalse(summary["reported_new_observations"]["evidence_authenticated"])
        with self.assertRaises(TypeError):
            files["new"] = b"not mutable"
        self.assertFalse(self.output.exists())
        destination = self.snapshot()
        self.assertEqual({p.name for p in destination.iterdir()}, c.p.FILES)
        for name, data in self.files.items():
            self.assertEqual((destination / name).read_bytes(), data)
        self.assertEqual(r.source_tree(self.f.source), before)
        self.assertEqual(dict(c.p.candidate(self.directory)[0]), dict(self.files))
        self.assertFalse((self.f.source / ".git").exists())
        self.assertFalse((destination / "patches-bundle.json").exists())

    def test_snapshot_consumed_by_existing_transport_with_offline_http_only(self):
        destination = self.snapshot()
        g = load("candidate_offline_transport", ROOT / "tools/release/github_transport.py")
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            for path in sorted(destination.iterdir()):
                archive.writestr(path.name, path.read_bytes())
        data = buffer.getvalue()
        # Synthetic server identity only, not actual upload/action output evidence.
        binding = dict(target=c.s.TARGET, version="0.1.0", candidate_sha256=self.seal, artifact_run="101", artifact_id="202",
                       artifact_sha256=r.digest(data), source_commit="a" * 40)
        run = dict(id=101, head_sha=binding["source_commit"], head_branch="main", repository=dict(id=1, full_name=c.s.TARGET),
                   head_repository=dict(id=1, full_name=c.s.TARGET), event="workflow_dispatch", path=".github/workflows/verify.yml",
                   run_attempt=1, status="completed", conclusion="success")
        artifact = dict(id=202, name="release-candidate-0.1.0", expired=False, digest="sha256:" + binding["artifact_sha256"],
                        workflow_run=dict(id=101, head_sha=binding["source_commit"], head_branch="main", repository_id=1, head_repository_id=1))
        prefix = g.API + "/repos/" + c.s.TARGET
        responses = {prefix + "/actions/runs/101": r.canonical(run), prefix + "/actions/artifacts/202": r.canonical(artifact),
                     prefix + "/actions/artifacts/202/zip": data}
        calls = []
        def offline(method, url, headers, body):
            calls.append((method, url))
            self.assertEqual(method, "GET")
            self.assertIn(url, responses)
            return 200, {}, responses[url]
        with mock.patch.dict(os.environ, {"OFFLINE_CANDIDATE_TOKEN": "synthetic-not-real"}):
            transport = g.GitHubTransport("OFFLINE_CANDIDATE_TOKEN", request=offline)
            self.assertEqual(transport.verify_immutable_candidate(binding), dict(self.files))
        self.assertEqual(len(calls), 3)

    def test_optional_real_revision_exact_and_forwarded_each_recheck(self):
        revision = "a" * 40  # mock plumbing only; NEVER an emitted Git claim
        with mock.patch.object(r, "clean_revision") as clean:
            self.snapshot(source_revision=revision)
        self.assertGreaterEqual(clean.call_count, 4)
        paths = r.source_tree(self.f.source)[1]
        for call in clean.call_args_list:
            self.assertEqual(call.args, (self.f.source, revision, paths))
        for bad in ("", "main", "A" * 40, "a" * 39, "b" * 64):
            with self.subTest(bad=bad), self.assertRaises(r.ReleaseError):
                self.validate(source_revision=bad)
        with mock.patch.object(r, "clean_revision", side_effect=r.ReleaseError("not clean committed HEAD")):
            with self.assertRaisesRegex(r.ReleaseError, "committed HEAD"):
                self.validate(source_revision=revision)

    def test_wrong_seal_or_current_source_fails_before_output(self):
        for bad in ("0" * 64, "../escape", "A" * 64):
            with self.subTest(bad=bad), self.assertRaises(r.ReleaseError):
                c.snapshot(self.directory, self.f.source, bad, self.output)
        (self.f.source / "untracked.txt").write_text("changed current source")
        with self.assertRaisesRegex(r.ReleaseError, "current source tree"):
            self.snapshot()
        self.assertFalse(self.output.exists())

    def test_schema_defaults_names_and_metadata_are_not_weakened(self):
        cases = [
            ("patches-list.json", lambda v: v["patches"][0].update(default=False)),
            ("patches-list.json", lambda v: v["patches"][0].update(name="other")),
            ("verification-summary.json", lambda v: v.update(schema=1)),
            ("verification-summary.json", lambda v: v.update(target="other/repo")),
            ("verification-summary.json", lambda v: v["reported_new_observations"].update(evidence_authenticated=True)),
        ]
        # Keep bundle/catalog summary bindings coherent where needed, so tests
        # exercise semantic policy even when an attacker reauthors the seal.
        for name, change in cases:
            with self.subTest(name=name):
                for filename, data in self.files.items():
                    (self.directory / filename).write_bytes(data)
                self.change_json(name, change)
                if name == "patches-list.json":
                    digest = r.digest((self.directory / name).read_bytes())
                    self.change_json("verification-summary.json", lambda v: v["binding"].update(catalog_sha256=digest))
                with self.assertRaises(r.ReleaseError):
                    self.validate()
        for filename, data in self.files.items():
            (self.directory / filename).write_bytes(data)
        self.f.write_bundle(version="9.9.9")
        (self.directory / "patches-0.1.0.mpp").write_bytes(self.f.bundle.read_bytes())
        self.change_json("verification-summary.json", lambda v: v["binding"].update(bundle_sha256=r.digest(self.f.bundle.read_bytes())))
        with self.assertRaisesRegex(r.ReleaseError, "metadata"):
            self.validate()

    def test_exact_pinned_provenance_required(self):
        for family in ("termius", "plex"):
            with self.subTest(family=family):
                original = self.files["verification-summary.json"]
                (self.directory / "verification-summary.json").write_bytes(original)
                self.change_json("verification-summary.json", lambda v: v["inherited_behavior"][family]["files"][0].update(original_sha256="0" * 64))
                with self.assertRaises(r.ReleaseError):
                    self.validate()

    def test_unsanitized_summary_narratives_not_copied(self):
        for key, value in (("trust", "caller-authored private path"), ("remaining", ["approved by me"])):
            (self.directory / "verification-summary.json").write_bytes(self.files["verification-summary.json"])
            self.change_json("verification-summary.json", lambda v: v.update({key: value}))
            with self.assertRaisesRegex(r.ReleaseError, "sanitized"):
                self.snapshot()
            self.assertFalse(self.output.exists())

    def test_blocked_and_unobserved_plex_preserved_without_publication_claim(self):
        for status in ("blocked", "not-observed"):
            with self.subTest(status=status):
                self.change_json("verification-summary.json", lambda v: v["reported_new_observations"]["plex"]["runtime"].update(status=status))
                destination = self.base / ("snapshot-" + status)
                c.snapshot(self.directory, self.f.source, self.seal, destination)
                summary = json.loads((destination / "verification-summary.json").read_bytes())
                self.assertEqual(summary["status"], "staged-not-published")
                self.assertEqual(summary["reported_new_observations"]["plex"]["runtime"]["status"], status)
                self.assertFalse(summary["reported_new_observations"]["evidence_authenticated"])
                self.assertEqual((destination / "verification-summary.json").read_bytes(), (self.directory / "verification-summary.json").read_bytes())

    def test_missing_extra_and_changed_bytes_rejected(self):
        path = self.directory / "SHA256SUMS"
        original = path.read_bytes()
        path.unlink()
        with self.assertRaises(r.ReleaseError):
            self.validate()
        path.write_bytes(original)
        extra = self.directory / "private-log.txt"
        extra.write_text("synthetic raw evidence MUST NOT BE COPIED")
        with self.assertRaisesRegex(r.ReleaseError, "inventory"):
            self.snapshot()
        self.assertFalse(self.output.exists())
        extra.unlink()
        path.write_bytes(original + b"changed")
        with self.assertRaisesRegex(r.ReleaseError, "checksum"):
            self.validate()

    def test_candidate_mutation_between_validation_reads_is_rejected(self):
        original = c.p.candidate
        count = 0
        def change(directory):
            nonlocal count
            result = original(directory)
            count += 1
            if count == 1:
                path = self.directory / "patches-list.json"
                path.write_bytes(path.read_bytes() + b" ")
            return result
        with mock.patch.object(c.p, "candidate", side_effect=change):
            with self.assertRaisesRegex(r.ReleaseError, "checksum"):
                self.snapshot()
        self.assertFalse(self.output.exists())

    def test_post_validation_source_or_candidate_mutation_retains_failure_no_retry(self):
        original = r.new_output
        for target in ("source", "candidate"):
            with self.subTest(target=target):
                self.output = self.base / ("failed-" + target)
                path = self.f.source / "new.txt" if target == "source" else self.directory / "patches-list.json"
                original_bytes = path.read_bytes() if path.exists() else None
                def change(*args):
                    result = original(*args)
                    path.write_bytes(b"changed during snapshot")
                    return result
                with mock.patch.object(r, "new_output", side_effect=change):
                    with self.assertRaises(r.ReleaseError):
                        self.snapshot()
                self.assertTrue(self.output.is_dir())
                # Copy uses the frozen mapping, not a second read of changed input.
                self.assertEqual({p.name for p in self.output.iterdir()}, c.p.FILES)
                self.assertEqual((self.output / "patches-list.json").read_bytes(), self.files["patches-list.json"])
                if original_bytes is None:
                    path.unlink()
                else:
                    path.write_bytes(original_bytes)
                with self.assertRaisesRegex(r.ReleaseError, "new nonexistent"):
                    self.snapshot()

    def test_snapshot_readback_tampering_is_rejected_and_retained(self):
        original = c.validate
        def change(directory, *args, **kwargs):
            if Path(directory) == self.output:
                (self.output / "patches-0.1.0.mpp").write_bytes(b"tampered output")
            return original(directory, *args, **kwargs)
        with mock.patch.object(c, "validate", side_effect=change):
            with self.assertRaisesRegex(r.ReleaseError, "checksum"):
                self.snapshot()
        self.assertTrue(self.output.exists())

    def test_output_must_be_new_and_external_to_all_inputs(self):
        for output in (self.f.source / "snapshot", self.directory / "snapshot", self.directory.parent,
                       ROOT / "forbidden-candidate-output", self.base / "missing-parent/snapshot"):
            with self.subTest(output=output), self.assertRaises(r.ReleaseError):
                c.snapshot(self.directory, self.f.source, self.seal, output)
        self.output.mkdir()
        with self.assertRaisesRegex(r.ReleaseError, "new nonexistent"):
            self.snapshot()

    def test_input_source_and_output_symlink_ancestors_rejected(self):
        alias = self.base / "alias"
        self.link(alias, self.base, directory=True)
        for directory, source, output in (
            (alias / "staged", self.f.source, self.output),
            (self.directory, alias / "source", self.output),
            (self.directory, self.f.source, alias / "snapshot"),
        ):
            with self.subTest(directory=directory, source=source, output=output), self.assertRaisesRegex(r.ReleaseError, "linked"):
                c.snapshot(directory, source, self.seal, output)

    def test_symlink_and_hardlink_files_rejected(self):
        path = self.directory / "patches-list.json"
        path.unlink()
        self.link(path, self.base / "catalog.json")
        with self.assertRaisesRegex(r.ReleaseError, "linked"):
            self.validate()
        path.unlink()
        try:
            os.link(self.base / "catalog.json", path)
        except OSError:
            self.skipTest("platform cannot create test hardlinks")
        with self.assertRaisesRegex(r.ReleaseError, "unlinked"):
            self.validate()

    def test_internal_source_links_and_hardlinks_rejected(self):
        path = next(self.f.source.rglob("*.kt"))
        outside = self.base / "source-link-target"
        outside.write_bytes(path.read_bytes())
        path.unlink()
        self.link(path, outside)
        with self.assertRaisesRegex(r.ReleaseError, "symlinks/junctions"):
            self.validate()
        path.unlink()
        try:
            os.link(outside, path)
        except OSError:
            self.skipTest("platform cannot create test hardlinks")
        # Identical source bytes/tree digest cannot rescue linked inputs.
        with self.assertRaisesRegex(r.ReleaseError, "hard-linked source"):
            self.validate()

    def ci_environment(self):
        registry = self.base / "registry"
        registry.mkdir()
        self.directory.rename(registry / self.seal)
        self.directory = registry / self.seal
        temporary = self.base / "runner-temp"
        temporary.mkdir()
        output = self.base / "github-output"
        output.touch()
        return dict(GITHUB_ACTIONS="true", GITHUB_EVENT_NAME="workflow_dispatch", GITHUB_REPOSITORY=c.s.TARGET,
                    GITHUB_REF="refs/heads/main", GITHUB_WORKFLOW_REF=c.s.TARGET + "/.github/workflows/verify.yml@refs/heads/main",
                    GITHUB_JOB="candidate", GITHUB_RUN_ATTEMPT="1", PRODUCE_CANDIDATE="true", MORPHE_CANDIDATE_PRODUCER_READY="true",
                    GITHUB_SHA="a" * 40, GITHUB_WORKFLOW_SHA="a" * 40, CANDIDATE_SHA256=self.seal,
                    MORPHE_CANDIDATE_ROOT=str(registry), RUNNER_TEMP=str(temporary), GITHUB_WORKSPACE=str(self.f.source), GITHUB_OUTPUT=str(output))

    def test_ci_requires_actual_revision_forwards_exact_sha_and_exports_only_safe_outputs(self):
        env = self.ci_environment()
        with mock.patch.object(r, "clean_revision") as clean:
            result = c.ci(env)
        self.assertFalse(result["evidence_authenticated"])
        self.assertEqual(result["source_commit"], env["GITHUB_SHA"])
        self.assertTrue(clean.call_args_list)
        for call in clean.call_args_list:
            self.assertEqual(call.args[0:2], (self.f.source, env["GITHUB_SHA"]))
        outputs = dict(line.split("=", 1) for line in Path(env["GITHUB_OUTPUT"]).read_text().splitlines())
        self.assertEqual(set(outputs), {"path", "candidate_sha256", "source_commit"})
        self.assertTrue(Path(outputs["path"]).is_relative_to(Path(env["RUNNER_TEMP"])))
        self.assertEqual(outputs["candidate_sha256"], self.seal)
        self.assertEqual(dict(c.p.candidate(Path(outputs["path"]))[0]), dict(self.files))
        for invented in ("artifact_id", "artifact_run", "artifact_sha256", "passed"):
            self.assertNotIn(invented, result)

    def test_ci_context_guards_and_no_arbitrary_dispatch_path(self):
        env = self.ci_environment()
        attacks = {"GITHUB_ACTIONS": "false", "GITHUB_EVENT_NAME": "push", "GITHUB_REPOSITORY": "fork/repo",
                   "GITHUB_REF": "refs/heads/other", "GITHUB_WORKFLOW_REF": "untrusted", "GITHUB_JOB": "offline",
                   "GITHUB_RUN_ATTEMPT": "2", "PRODUCE_CANDIDATE": "false", "MORPHE_CANDIDATE_PRODUCER_READY": "false",
                   "GITHUB_SHA": "", "GITHUB_WORKFLOW_SHA": "b" * 40, "CANDIDATE_SHA256": "../elsewhere",
                   "MORPHE_CANDIDATE_ROOT": "", "RUNNER_TEMP": str(self.f.source), "GITHUB_OUTPUT": str(self.base / "injected\npath")}
        with mock.patch.object(r, "clean_revision") as clean:
            for key, value in attacks.items():
                with self.subTest(key=key), self.assertRaises(r.ReleaseError):
                    c.ci(dict(env, **{key: value}))
        clean.assert_not_called()
        self.assertEqual(list(Path(env["RUNNER_TEMP"]).iterdir()), [])
        self.assertEqual(Path(env["GITHUB_OUTPUT"]).read_bytes(), b"")

    def test_cli_readonly_no_revision_invention_and_fail_closed(self):
        command = [sys.executable, "-I", "-B", str(ROOT / "tools/release/candidate.py"), "validate",
                   "--candidate", str(self.directory), "--source-root", str(self.f.source), "--candidate-sha256", self.seal]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(result.stdout)
        self.assertIsNone(value["source_commit"])
        self.assertEqual(value["status"], "validated-not-published")
        result = subprocess.run(command + ["--source-revision", "main"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn(str(self.base), result.stderr)


class CandidateWorkflowTests(unittest.TestCase):
    def test_producer_is_separate_opt_in_protected_first_attempt_main_without_rebuild(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        candidate = workflow.split("\n  candidate:\n", 1)[1]
        before = workflow.split("\n  candidate:\n", 1)[0]
        self.assertIn("produce_candidate:", before)
        self.assertIn("type: boolean\n        default: false", before)
        self.assertIn("candidate_sha256:", before)
        for guard in ("github.repository == 'FISHYau/fishyau-morphe-patches'", "github.ref == 'refs/heads/main'",
                      "github.event_name == 'workflow_dispatch'", "github.workflow_sha == github.sha", "github.run_attempt == 1",
                      "inputs.produce_candidate == true", "vars.MORPHE_CANDIDATE_PRODUCER_READY == 'true'"):
            self.assertIn(guard, candidate)
        self.assertIn("runs-on: [self-hosted, linux, morphe-candidate]", candidate)
        self.assertIn("environment: candidate-staging", candidate)
        self.assertIn("needs: offline", candidate)
        self.assertNotIn("needs: collection", candidate)
        self.assertIn("MORPHE_CANDIDATE_ROOT: ${{ vars.MORPHE_CANDIDATE_ROOT }}", candidate)
        self.assertIn("ref: ${{ github.sha }}", candidate)
        self.assertIn("persist-credentials: false", candidate)
        self.assertIn("python3 -I -B tools/release/candidate.py ci", candidate)
        for forbidden in ("secrets.", "packages:", "GITHUB_TOKEN", "github.token", "contents: write", "gradle", "staging.py stage",
                          "workflow_dispatch:", "gh release", "gh workflow", "curl ", "wget ", "pull_request_target", "candidate_path"):
            self.assertNotIn(forbidden, candidate)
        self.assertIn("format('candidate-{0}', github.run_id)", before)
        self.assertIn("cancel-in-progress: ${{ !(github.event_name == 'workflow_dispatch' && inputs.produce_candidate) }}", before)
        # Original fork isolation and opt-in collection-build controls survive.
        self.assertIn("vars.MORPHE_PACKAGES_READ_READY == 'true'", before)
        self.assertIn("environment: collection-build", before)
        self.assertIn("python3 -I -B -m unittest discover -s tests -p 'test_*.py' -v", before)
        self.assertNotIn("actions/upload-artifact", before)

    def test_upload_exact_five_files_pin_and_actual_identity_outputs(self):
        workflow = (ROOT / ".github/workflows/verify.yml").read_text(encoding="utf-8")
        candidate = workflow.split("\n  candidate:\n", 1)[1]
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02", candidate)
        self.assertIn("actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683", candidate)
        self.assertIn("name: release-candidate-0.1.0", candidate)
        self.assertIn("overwrite: false", candidate)
        self.assertIn("if-no-files-found: error", candidate)
        self.assertIn("retention-days: 3", candidate)
        paths = candidate.split("          path: |\n", 1)[1].split("          overwrite:", 1)[0].splitlines()
        self.assertEqual({line.strip() for line in paths}, {"${{ steps.snapshot.outputs.path }}/" + name for name in c.p.FILES})
        for value in ("${{ github.run_id }}", "${{ steps.upload.outputs.artifact-id }}", "${{ steps.upload.outputs.artifact-digest }}",
                      "${{ steps.snapshot.outputs.candidate_sha256 }}", "${{ steps.snapshot.outputs.source_commit }}"):
            self.assertIn(value, candidate)
        self.assertIn("GITHUB_STEP_SUMMARY", candidate)
        self.assertNotIn("release.yml", candidate)


if __name__ == "__main__":
    unittest.main()
