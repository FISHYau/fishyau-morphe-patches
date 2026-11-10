"""Mock transport attacks only: no real publication, Git mutation or network calls."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
FIXSPEC = importlib.util.spec_from_file_location("staging_fixtures", ROOT / "tests/test_staging.py")
fmod = importlib.util.module_from_spec(FIXSPEC)
FIXSPEC.loader.exec_module(fmod)
SPEC = importlib.util.spec_from_file_location("publisher_under_test", ROOT / "tools/release/publisher.py")
p = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(p)
r = p.r


class MockTransport:
    """Intentionally fabricated trusted boundary; not GitHub authentication."""
    def __init__(self, binding, files):
        self.binding = dict(binding)
        self.files = dict(files)
        self.events = []
        self.head = binding["source_commit"]
        self.uploaded = {}
        self.fail = None
        self.hook = lambda name: None
        self.review = dict(binding=dict(binding), environment="release", reviewer="synthetic-reviewer", actor="synthetic-actor",
                           reviewed_at="2026-11-09T11:00:00", independent_review=True, prevent_self_review=True, main_only=True,
                           no_admin_bypass=True, evidence_authenticated=True)

    def verify_immutable_candidate(self, binding):
        self.events.append("artifact")
        if self.fail in ("missing-credentials", "missing-artifact", "wrong-run", "expired-artifact", "wrong-workflow"):
            raise r.ReleaseError(self.fail)
        if self.fail == "wrong-artifact":
            return {}
        return dict(self.files)

    def authenticate_protected_review(self, binding):
        self.events.append("review")
        if self.fail == "no-approval":
            raise r.ReleaseError("protected approval unavailable")
        return copy.deepcopy(self.review)

    def branch_head(self, target, branch):
        self.events.append("head")
        return self.head

    def create_immutable_release(self, target, version, source_commit):
        self.events.append("create")
        if self.fail == "existing-release":
            raise r.ReleaseError("immutable version already exists")
        return "synthetic-release"

    def upload_asset(self, release_id, name, data):
        self.events.append("upload:" + name)
        if self.fail == "upload":
            raise r.ReleaseError("synthetic upload failed")
        self.uploaded[name] = data
        return name

    def finalize_immutable_release(self, release_id, inventory):
        self.events.append("finalize")
        assert inventory == {name: r.digest(data) for name, data in self.uploaded.items()}
        return self.fail != "mutable-release"

    def download_asset(self, release_id, asset_id, name):
        self.events.append("download:" + name)
        self.hook(name)
        if self.fail == "readback":
            return self.uploaded[name] + b"changed remotely"
        return self.uploaded[name]

    def cas_manifest(self, target, branch, expected, name, data):
        self.events.append("cas")
        if self.fail == "cas-race":
            raise r.ReleaseError("nonforce CAS concurrent update")
        assert self.head == expected
        assert name == "patches-bundle.json"
        assert data == self.files["patches-bundle.candidate.json"]
        return "b" * 40


class PublisherTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="publisher-synthetic-")
        self.addCleanup(temp.cleanup)
        self.f = fmod.CollectionFixture(Path(temp.name))
        # Fabricated passing runtime schema solely to exercise publisher plumbing.
        # This is not a real Plex observation or an approval fixture for release.
        runtime_report = copy.deepcopy(self.f.evidence['plex']['resource'])
        runtime_report.update(kind='plex-runtime', platform='android',
                              checks={key: 'passed' for key in ('installation', 'launch', 'client_checks', 'limitations')},
                              artifacts=[dict(kind=key, sha256=fmod.H('synthetic ' + key)) for key in ('runtime-report', 'visual-review')])
        self.f.evidence['plex']['runtime'] = dict(status='observed', scope='Fabricated runtime schema for offline tests only.',
                                                artifacts=[runtime_report['artifacts'][0]], observation=runtime_report)
        self.f.save()
        self.directory = self.f.stage()
        files, _, seal = p.candidate(self.directory)
        self.binding = dict(target=p.s.TARGET, version="0.1.0", candidate_sha256=seal, artifact_run="100", artifact_id="200",
                            artifact_sha256=fmod.H("synthetic immutable archive"), source_commit="a" * 40)
        self.transport = MockTransport(self.binding, files)
        # Do not initialize Git in tests. This mock establishes ONLY test plumbing.
        self.clean = mock.patch.object(r, "clean_revision")
        self.clean.start()
        self.addCleanup(self.clean.stop)

    def publish(self, **kwargs):
        return p.publish(self.directory, self.f.source, self.binding, self.transport, now=fmod.NOW, **kwargs)

    def blocked(self, pattern="."):
        with self.assertRaisesRegex(r.ReleaseError, pattern):
            self.publish(mode="publish")
        self.assertNotIn("cas", self.transport.events)

    def test_unobserved_or_blocked_plex_runtime_cannot_publish(self):
        for status in ('not-observed', 'blocked'):
            with self.subTest(status=status), tempfile.TemporaryDirectory(prefix='publisher-runtime-gate-') as temporary:
                fixture = fmod.CollectionFixture(Path(temporary))
                fixture.evidence['plex']['runtime']['status'] = status
                fixture.save()
                directory = fixture.stage()
                files, _, seal = p.candidate(directory)
                binding = dict(self.binding, candidate_sha256=seal)
                transport = MockTransport(binding, files)
                result = p.publish(directory, fixture.source, binding, transport, now=fmod.NOW)
                self.assertEqual(result['status'], 'dry-run-not-published')
                transport.events.clear()
                with self.assertRaisesRegex(r.ReleaseError, 'Plex runtime acceptance'):
                    p.publish(directory, fixture.source, binding, transport, mode='publish', now=fmod.NOW)
                self.assertEqual(transport.events, [])

    def test_default_dry_run_reads_server_artifact_without_writes_or_readiness_claim(self):
        result = self.publish()
        self.assertEqual(self.transport.events, ['artifact'])
        self.assertTrue(result['remote_candidate_verified'])
        self.assertEqual(result["status"], "dry-run-not-published")
        self.assertFalse(result["remote_readiness"])
        self.assertFalse(result["authenticated_approval"])
        r.clean_revision.assert_not_called()

    def test_synthetic_manifest_last_and_all_readback_exact_bytes(self):
        result = self.publish(mode="publish")
        self.assertEqual(result["status"], "published")  # mock only, not real readiness
        events = self.transport.events
        self.assertEqual(events[-1], "cas")
        for name in p.FILES:
            self.assertLess(events.index("upload:" + name), events.index("finalize"))
            self.assertLess(events.index("finalize"), events.index("download:" + name))
            self.assertLess(events.index("download:" + name), events.index("cas"))
        self.assertEqual(events.count("review"), 2)
        self.assertEqual(events.count("head"), 2)
        self.assertEqual(r.clean_revision.call_count, 2)

    def test_missing_credentials_artifact_approval_and_transport_fail(self):
        for failure in ("missing-credentials", "missing-artifact", "wrong-run", "expired-artifact", "wrong-workflow", "wrong-artifact", "no-approval"):
            self.transport.fail = failure
            self.transport.events = []
            self.blocked()
            self.assertNotIn("create", self.transport.events)
        with self.assertRaisesRegex(r.ReleaseError, "transport required"):
            p.publish(self.directory, self.f.source, self.binding, None, mode="publish", now=fmod.NOW)

    def test_legacy_staging_cannot_publish_as_initial_collection(self):
        base = self.f.base / 'legacy'
        base.mkdir()
        legacy = fmod.Fixture(base)
        directory = legacy.stage()
        _, _, seal = p.candidate(directory)
        with self.assertRaisesRegex(r.ReleaseError, 'current three-patch policy'):
            p.publish(directory, legacy.source, dict(self.binding, candidate_sha256=seal), self.transport, now=fmod.NOW)
        self.assertEqual(self.transport.events, [])

    def test_local_approval_json_is_not_an_authenticator(self):
        (self.directory / "approval.json").write_text('{"approved":true,"reviewer":"human"}')
        self.blocked("inventory")
        self.assertEqual(self.transport.events, [])

    def test_every_approval_binding_field_and_self_review_rejected(self):
        original = copy.deepcopy(self.transport.review)
        for key in self.binding:
            self.transport.review = copy.deepcopy(original)
            self.transport.review["binding"][key] = "changed"
            self.blocked("stale protected")
        self.transport.review = copy.deepcopy(original)
        self.transport.review["reviewer"] = self.transport.review["actor"].upper()
        self.blocked("self-review")

    def test_environment_name_alone_not_protection(self):
        for key in ("independent_review", "prevent_self_review", "main_only", "no_admin_bypass", "evidence_authenticated"):
            for bad in (False, "true", 1):
                self.transport.review[key] = bad
                self.blocked("protection|evidence")
            self.transport.review[key] = True
        self.transport.review["environment"] = "unprotected"
        self.blocked("environment")

    def test_stale_future_approval_rejected(self):
        for when in ("2026-10-01T00:00:00", "2026-11-10T00:00:00"):
            self.transport.review["reviewed_at"] = when
            self.blocked("stale or future")

    def test_changed_candidate_and_source_fail_before_upload(self):
        path = self.directory / "patches-list.json"
        path.write_bytes(path.read_bytes() + b" ")
        self.blocked("checksum")
        self.assertEqual(self.transport.events, [])

    def test_wrong_dispatch_target_version_hash_or_artifact_id(self):
        original = dict(self.binding)
        for key, value in (("target", "other/repo"), ("version", "0.2.0"), ("candidate_sha256", fmod.H("wrong")),
                           ("artifact_id", "latest"), ("artifact_run", "0"), ("source_commit", "main"), ("artifact_sha256", "bad")):
            self.binding = dict(original, **{key: value})
            self.blocked()
        self.assertNotIn("create", self.transport.events)

    def test_dirty_or_uncommitted_source_rejected(self):
        r.clean_revision.side_effect = r.ReleaseError("clean committed Git required")
        self.blocked("committed")
        self.assertEqual(self.transport.events, [])

    def test_source_changed_before_publish_rejected(self):
        (self.f.source / "new.txt").write_text("changed")
        self.blocked("source tree")
        self.assertEqual(self.transport.events, [])

    def test_existing_release_upload_failure_and_readback_prevent_manifest(self):
        for failure in ("existing-release", "upload", "mutable-release", "readback"):
            self.transport.fail = failure
            self.transport.events = []
            self.blocked()
        # Failed uploads are not rolled back/reused by core; immutable adapter
        # refuses a retry at the same version. No deletion method is invoked.
        self.assertTrue(any(e.startswith("upload:") for e in self.transport.events))

    def test_branch_changed_before_upload(self):
        self.transport.head = "c" * 40
        self.blocked("branch")
        self.assertNotIn("create", self.transport.events)

    def test_branch_changed_after_upload_no_approval_rebase(self):
        self.transport.hook = lambda name: setattr(self.transport, "head", "c" * 40)
        self.blocked("concurrent branch")
        self.assertIn("create", self.transport.events)

    def test_race_inside_cas_propagates_without_retry_or_force(self):
        self.transport.fail = "cas-race"
        with self.assertRaisesRegex(r.ReleaseError, "nonforce CAS"):
            self.publish(mode="publish")
        self.assertEqual(self.transport.events.count("cas"), 1)
        self.assertEqual(self.transport.events[-1], "cas")

    def test_candidate_changed_during_upload_rejected(self):
        def change(name):
            path = self.directory / "verification-summary.json"
            path.write_bytes(path.read_bytes() + b" ")
        self.transport.hook = change
        self.blocked("checksum")

    def test_source_changed_during_upload_rejected(self):
        self.transport.hook = lambda name: (self.f.source / "new.txt").write_text("changed")
        self.blocked("source tree")

    def test_approval_changed_during_upload_rejected(self):
        self.transport.hook = lambda name: self.transport.review.update(reviewed_at="2026-11-09T11:30:00")
        self.blocked("approval changed")

    def test_artifact_remote_bytes_not_local_echo(self):
        self.transport.files["patches-0.1.0.mpp"] += b"changed"
        self.blocked("immutable artifact")
        self.assertNotIn("create", self.transport.events)

    def reseal_synthetic_candidate(self):
        files = {name: (self.directory / name).read_bytes() for name in p.FILES if name != "SHA256SUMS"}
        files["SHA256SUMS"] = "".join(f"{r.digest(data)}  {name}\n" for name, data in sorted(files.items())).encode("ascii")
        (self.directory / "SHA256SUMS").write_bytes(files["SHA256SUMS"])
        self.binding["candidate_sha256"] = r.digest(r.canonical({name: r.digest(data) for name, data in files.items()}))
        self.transport.files = files
        self.transport.review["binding"] = dict(self.binding)

    def test_stale_new_observations_not_rescued_by_fresh_approval(self):
        path = self.directory / "verification-summary.json"
        summary = json.loads(path.read_bytes())
        summary["reported_new_observations"]["jvm_inspection"]["observed_at"] = "2026-10-01T00:00:00"
        path.write_bytes(r.canonical(summary))
        self.reseal_synthetic_candidate()
        self.blocked("stale or future")
        self.assertEqual(self.transport.events, [])

    def test_protected_review_cannot_predate_final_observations(self):
        self.transport.review["reviewed_at"] = "2026-11-09T09:00:00"
        self.blocked("predates")
        self.assertNotIn("create", self.transport.events)

    def test_future_manifest_cannot_be_approved_into_readiness(self):
        path = self.directory / "patches-bundle.candidate.json"
        manifest = json.loads(path.read_bytes())
        manifest["created_at"] = "2026-11-10T00:00:00"
        path.write_bytes(r.canonical(manifest))
        self.reseal_synthetic_candidate()
        self.blocked("future candidate")

    def test_wrong_manifest_asset_url_rejected_even_when_checksums_reauthored(self):
        path = self.directory / "patches-bundle.candidate.json"
        manifest = json.loads(path.read_bytes())
        manifest["download_url"] = "https://example.invalid/other.mpp"
        path.write_bytes(r.canonical(manifest))
        self.reseal_synthetic_candidate()
        self.blocked("URL/artifact mismatch")

    def test_workflow_binding_parser_checks_context_without_shell_evaluation(self):
        spec = importlib.util.spec_from_file_location("workflow_handoff_under_test", ROOT / "tools/release/workflow_handoff.py")
        handoff = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(handoff)
        value = dict(self.binding, mode="prepare")
        self.assertEqual(handoff.validate_handoff(value, self.binding["source_commit"], self.binding["target"]), self.binding)
        # Module's dynamically imported ReleaseError differs in class identity;
        # all failures remain ValueError subclasses and are handled fail closed.
        for key, bad in (("target", "$(touch marker)"), ("artifact_id", "1; exit 0"), ("source_commit", "main"), ("mode", "auto")):
            with self.assertRaises(ValueError):
                handoff.validate_handoff(dict(value, **{key: bad}), self.binding["source_commit"], self.binding["target"])
        for commit, target in (("c" * 40, self.binding["target"]), (self.binding["source_commit"], "other/repo")):
            with self.assertRaises(ValueError):
                handoff.validate_handoff(value, commit, target)
        env = dict(os.environ, HANDOFF=json.dumps(value), GITHUB_SHA=self.binding["source_commit"], GITHUB_REPOSITORY=self.binding["target"], GITHUB_ACTIONS='false')
        result = subprocess.run([sys.executable, "-I", "-B", str(ROOT / "tools/release/workflow_handoff.py")], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('trusted manual main Actions context required', result.stderr)

    def test_cli_publish_rejects_missing_trusted_context_before_network(self):
        command = [sys.executable, "-I", "-B", str(ROOT / "tools/release/publisher.py"), "handoff", "--mode", "publish",
                   "--candidate", str(self.directory), "--source-root", str(self.f.source)]
        for key, value in self.binding.items():
            command += ["--" + key.replace("_", "-"), value]
        result = subprocess.run(command, env=dict(os.environ, GITHUB_ACTIONS='false'), capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('trusted Actions publish job required', result.stderr)

    def test_manual_workflow_real_protected_publish_default_readonly_prepare(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("default: prepare", workflow)
        self.assertIn("environment: release", workflow)
        self.assertNotIn('PUBLICATION IS DISABLED', workflow)
        self.assertIn('secrets.RELEASE_PUBLISH_TOKEN', workflow.split('  publish:')[1])
        self.assertNotIn('secrets.', workflow.split('  publish:')[0])
        self.assertNotIn('contents: write', workflow)
        self.assertIn('actions: read', workflow)
        self.assertIn('inputs.mode == \'publish\'', workflow)
        self.assertIn('inputs.source_commit == github.sha', workflow)
        for field in self.binding:
            self.assertIn(field + ':', workflow)
        for unsafe in ('id-token: write', 'pull_request_target', 'git push', 'gh release'):
            self.assertNotIn(unsafe, workflow)


GSPEC = importlib.util.spec_from_file_location('github_transport_under_test', ROOT / 'tools/release/github_transport.py')
g = importlib.util.module_from_spec(GSPEC)
GSPEC.loader.exec_module(g)


class OfflineGitHub:
    """Strict fake HTTP server: any unlisted call fails; NEVER real HTTP."""
    def __init__(self):
        self.routes = {}
        self.calls = []

    def add(self, method, path, value, status=200, headers=None):
        url = path if path.startswith('https://') else g.API + '/repos/' + g.TARGET + path
        self.routes[(method, url)] = (status, headers or {}, value if isinstance(value, bytes) else r.canonical(value))

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        if (method, url) not in self.routes:
            raise AssertionError('Unexpected offline request: ' + method + ' ' + url)
        return self.routes[(method, url)]


class GitHubTransportTests(unittest.TestCase):
    def setUp(self):
        import io
        import zipfile
        temp = tempfile.TemporaryDirectory(prefix='github-offline-')
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.fixture = fmod.CollectionFixture(self.root)
        files, _, seal = p.candidate(self.fixture.stage())
        self.files = dict(files)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            for name, data in files.items():
                z.writestr(name, data)
        self.archive = buffer.getvalue()
        self.binding = dict(target=g.TARGET, version='0.1.0', candidate_sha256=seal, artifact_run='100', artifact_id='200', artifact_sha256=r.digest(self.archive), source_commit='a' * 40)
        self.fake = OfflineGitHub()
        # This is a deliberately synthetic test credential, not a retrieved secret.
        patch = mock.patch.dict(os.environ, {'OFFLINE_TEST_TOKEN': 'synthetic-not-a-real-credential'})
        patch.start()
        self.addCleanup(patch.stop)
        self.transport = g.GitHubTransport('OFFLINE_TEST_TOKEN', request=self.fake)
        self.run = dict(id=100, head_sha='a' * 40, head_branch='main', repository=dict(id=1, full_name=g.TARGET), head_repository=dict(id=1, full_name=g.TARGET), event='workflow_dispatch', path='.github/workflows/verify.yml', run_attempt=1, status='completed', conclusion='success')
        self.artifact = dict(id=200, name='release-candidate-0.1.0', expired=False, digest='sha256:' + self.binding['artifact_sha256'], workflow_run=dict(id=100, head_sha='a' * 40, head_branch='main', repository_id=1, head_repository_id=1))
        self.seed_artifact()

    def seed_artifact(self):
        self.fake.add('GET', '/actions/runs/100', self.run)
        self.fake.add('GET', '/actions/artifacts/200', self.artifact)
        self.fake.add('GET', '/actions/artifacts/200/zip', self.archive)

    def test_prepare_really_checks_server_origin_archive_and_exact_files(self):
        self.assertEqual(self.transport.verify_immutable_candidate(self.binding), self.files)
        self.assertTrue(all(c[0] == 'GET' for c in self.fake.calls))
        self.assertTrue(all(c[2]['Authorization'] == 'Bearer synthetic-not-a-real-credential' for c in self.fake.calls))

    def test_every_server_origin_field_and_archive_digest_fail_closed(self):
        for target, key, bad in ((self.run, 'head_sha', 'b' * 40), (self.run, 'head_repository', {'full_name': 'fork/other'}), (self.run, 'event', 'pull_request'), (self.run, 'path', '.github/workflows/untrusted.yml'), (self.run, 'run_attempt', 2), (self.run, 'conclusion', 'failure'), (self.artifact, 'expired', True), (self.artifact, 'digest', None), (self.artifact, 'workflow_run', {'id': 101}), (self.artifact, 'name', 'latest')):
            original = copy.deepcopy(target[key])
            target[key] = bad
            self.seed_artifact()
            with self.assertRaises(ValueError):
                self.transport.verify_immutable_candidate(self.binding)
            target[key] = original
        self.seed_artifact()
        self.fake.add('GET', '/actions/artifacts/200/zip', self.archive + b'changed')
        with self.assertRaisesRegex(ValueError, 'archive digest'):
            self.transport.verify_immutable_candidate(self.binding)

    def test_archive_extra_path_duplicate_and_wrong_seal_rejected(self):
        import io
        import zipfile
        for badname in ('../escaped', 'executable.py', 'patches-list.json'):
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, 'w') as z:
                for name, data in self.files.items():
                    z.writestr(name, data)
                # Duplicate-name fixture deliberately tests archive rejection.
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', UserWarning)
                    z.writestr(badname, b'untrusted')
            self.archive = buffer.getvalue()
            self.binding['artifact_sha256'] = r.digest(self.archive)
            self.artifact['digest'] = 'sha256:' + self.binding['artifact_sha256']
            self.seed_artifact()
            with self.assertRaisesRegex(ValueError, 'inventory'):
                self.transport.verify_immutable_candidate(self.binding)
        self.binding['candidate_sha256'] = '0' * 64
        # Restore an archive with the exact inventory.
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as z:
            for name, data in self.files.items():
                z.writestr(name, data)
        self.archive = buffer.getvalue()
        self.binding['artifact_sha256'] = r.digest(self.archive)
        self.artifact['digest'] = 'sha256:' + self.binding['artifact_sha256']
        self.seed_artifact()
        with self.assertRaisesRegex(ValueError, 'candidate seal'):
            self.transport.verify_immutable_candidate(self.binding)

    def test_redirects_strip_credentials_and_reject_foreign_hosts(self):
        url = 'https://example.blob.core.windows.net/private/archive?synthetic=1'
        self.fake.add('GET', '/actions/artifacts/200/zip', b'', status=302, headers={'Location': url})
        self.fake.add('GET', url, self.archive)
        self.assertEqual(self.transport.verify_immutable_candidate(self.binding), self.files)
        self.assertNotIn('Authorization', self.fake.calls[-1][2])
        self.fake.add('GET', '/actions/artifacts/200/zip', b'', status=302, headers={'Location': 'https://evil.invalid/archive'})
        with self.assertRaisesRegex(ValueError, 'unsupported GitHub storage'):
            self.transport.verify_immutable_candidate(self.binding)

    def test_prepare_cannot_write_and_errors_redact_http_details(self):
        with self.assertRaisesRegex(ValueError, 'forbids remote writes'):
            self.transport.api('/releases', 'POST', {'draft': True})
        self.assertEqual(self.fake.calls, [])
        self.fake.add('GET', '/private', b'synthetic-not-a-real-credential sensitive error', status=403)
        with self.assertRaises(ValueError) as caught:
            self.transport.api('/private')
        self.assertNotIn('synthetic-not-a-real-credential', str(caught.exception))
        self.assertNotIn('sensitive', str(caught.exception))
        self.transport.request = lambda *args: (_ for _ in ()).throw(RuntimeError('synthetic-not-a-real-credential'))
        with self.assertRaises(ValueError) as caught:
            self.transport.api('/private')
        self.assertNotIn('synthetic-not-a-real-credential', str(caught.exception))

    def review_setup(self):
        event = dict(inputs=dict(self.binding, mode='publish'), repository=dict(full_name=g.TARGET), ref='refs/heads/main', sender=dict(login='initiator'))
        self.event_path = self.root / 'trusted-event.json'
        self.event_path.write_bytes(r.canonical(event))
        self.context = dict(GITHUB_ACTIONS='true', GITHUB_EVENT_NAME='workflow_dispatch', GITHUB_REPOSITORY=g.TARGET, GITHUB_REF='refs/heads/main', GITHUB_SHA='a' * 40, GITHUB_JOB='publish', GITHUB_RUN_ATTEMPT='1', GITHUB_WORKFLOW_REF=g.TARGET + '/.github/workflows/release.yml@refs/heads/main', GITHUB_WORKFLOW_SHA='a' * 40, GITHUB_EVENT_PATH=str(self.event_path), GITHUB_RUN_ID='300', GITHUB_ACTOR='initiator')
        self.transport.context = self.context
        self.publish_run = dict(self.run, id=300, path='.github/workflows/release.yml', status='in_progress', conclusion=None, actor=dict(login='initiator', type='User'), triggering_actor=dict(login='initiator', type='User'), run_started_at='2026-11-09T11:00:00Z')
        self.environment = dict(id=7, name='release', can_admins_bypass=False, deployment_branch_policy=dict(protected_branches=False, custom_branch_policies=True), protection_rules=[dict(type='required_reviewers', prevent_self_review=True, reviewers=[dict(type='User', reviewer=dict(login='reviewer', type='User'))]), dict(id=8, type='branch_policy')])
        self.branch_policy = dict(total_count=1, branch_policies=[dict(name='main', type='branch')])
        self.approvals = [dict(state='approved', environments=[dict(id=7, name='release')], user=dict(login='reviewer', type='User'), comment='evidence-policy-reviewed binding-sha256=' + r.digest(r.canonical(self.binding)))]
        self.seed_review()

    def seed_review(self):
        self.fake.add('GET', '/actions/runs/300', self.publish_run)
        self.fake.add('GET', '/environments/release', self.environment)
        self.fake.add('GET', '/environments/release/deployment-branch-policies?per_page=100', self.branch_policy)
        self.fake.add('GET', '/actions/runs/300/approvals?per_page=100', self.approvals)

    def test_real_review_requires_server_settings_review_and_exact_attestation(self):
        self.review_setup()
        review = self.transport.authenticate_protected_review(self.binding)
        self.assertEqual(review['binding'], self.binding)
        self.assertEqual(review['reviewer'], 'reviewer')
        self.assertTrue(review['prevent_self_review'])
        self.assertTrue(all(c[0] == 'GET' for c in self.fake.calls))

    def test_environment_protection_markers_are_exact_and_order_independent(self):
        self.review_setup()
        original = copy.deepcopy(self.environment['protection_rules'])
        self.environment['protection_rules'] = list(reversed(original))
        self.seed_review()
        self.assertEqual(self.transport.authenticate_protected_review(self.binding)['reviewer'], 'reviewer')
        for rules in (original[:1], original[1:], original + [dict(type='wait_timer')],
                      [original[0], original[0]], [original[1], original[1]],
                      [original[0], dict(type='custom')]):
            with self.subTest(rules=rules):
                self.environment['protection_rules'] = rules
                self.seed_review()
                with self.assertRaisesRegex(ValueError, 'environment protection rules'):
                    self.transport.authenticate_protected_review(self.binding)

    def test_environment_name_and_local_json_cannot_authenticate(self):
        self.review_setup()
        for target, key, value in ((self.context, 'GITHUB_JOB', 'prepare'), (self.context, 'GITHUB_WORKFLOW_SHA', 'b' * 40), (self.context, 'GITHUB_EVENT_NAME', 'push'), (self.environment, 'can_admins_bypass', True), (self.environment, 'protection_rules', []), (self.environment, 'deployment_branch_policy', {'protected_branches': True, 'custom_branch_policies': False}), (self.branch_policy, 'total_count', 2), (self.publish_run, 'event', 'push')):
            original = copy.deepcopy(target[key])
            target[key] = value
            self.seed_review()
            with self.assertRaises(ValueError):
                self.transport.authenticate_protected_review(self.binding)
            target[key] = original
        for key, value in (('state', 'rejected'), ('user', dict(login='initiator', type='User')), ('user', dict(login='reviewer', type='Bot')), ('comment', 'approved'), ('environments', [dict(id=8, name='release')])):
            original = copy.deepcopy(self.approvals[0][key])
            self.approvals[0][key] = value
            self.seed_review()
            with self.assertRaises(ValueError):
                self.transport.authenticate_protected_review(self.binding)
            self.approvals[0][key] = original
        self.seed_review()
        event = json.loads(self.event_path.read_bytes())
        event['inputs']['artifact_id'] = '201'
        self.event_path.write_bytes(r.canonical(event))
        with self.assertRaisesRegex(ValueError, 'dispatch binding'):
            self.transport.authenticate_protected_review(self.binding)

    def write_setup(self):
        self.transport.writable = True
        self.protection = dict(enforce_admins=dict(enabled=True), allow_force_pushes=dict(enabled=False), allow_deletions=dict(enabled=False))
        self.fake.add('GET', '/branches/main/protection', self.protection)
        self.fake.add('GET', '/git/ref/heads/main', dict(object=dict(type='commit', sha='a' * 40)))
        self.fake.add('GET', '/git/ref/tags/v0.1.0', {}, status=404)
        self.fake.add('GET', '/releases/tags/v0.1.0', {}, status=404)
        self.fake.add('GET', '/releases?per_page=100&page=1', [])
        self.fake.add('POST', '/git/refs', dict(ref='refs/tags/v0.1.0'))
        self.fake.add('POST', '/releases', dict(id=9, tag_name='v0.1.0', draft=True, assets=[]))

    def test_create_new_tag_and_empty_draft_and_never_reuse(self):
        self.write_setup()
        rid = self.transport.create_immutable_release(g.TARGET, '0.1.0', 'a' * 40)
        self.assertEqual(rid, 9)
        posts = [x for x in self.fake.calls if x[0] == 'POST']
        self.assertEqual(json.loads(posts[0][3]), dict(ref='refs/tags/v0.1.0', sha='a' * 40))
        self.assertTrue(json.loads(posts[1][3])['draft'])
        for endpoint, value in (('/git/ref/tags/v0.1.0', {'object': {'sha': 'a' * 40}}), ('/releases/tags/v0.1.0', {'id': 3}), ('/releases?per_page=100&page=1', [{'tag_name': 'v0.1.0', 'draft': True}])):
            self.write_setup()
            self.fake.add('GET', endpoint, value)
            self.fake.calls.clear()
            with self.assertRaisesRegex(ValueError, 'already exists'):
                self.transport.create_immutable_release(g.TARGET, '0.1.0', 'a' * 40)
            self.assertTrue(all(x[0] == 'GET' for x in self.fake.calls))

    def test_upload_freeze_and_public_download_never_overwrites(self):
        self.write_setup()
        rid = self.transport.create_immutable_release(g.TARGET, '0.1.0', 'a' * 40)
        ids = {}
        for index, (name, data) in enumerate(sorted(self.files.items()), 1):
            self.fake.add('POST', 'https://uploads.github.com/repos/' + g.TARGET + '/releases/9/assets?name=' + name, dict(id=index, name=name, state='uploaded', size=len(data)))
            ids[name] = self.transport.upload_asset(rid, name, data)
            with self.assertRaisesRegex(ValueError, 'never overwrite'):
                self.transport.upload_asset(rid, name, data)
        inventory = {name: r.digest(data) for name, data in self.files.items()}
        assets = [dict(name=name, id=ids[name], digest='sha256:' + sha) for name, sha in inventory.items()]
        draft = dict(id=9, draft=True, assets=assets)
        published = dict(id=9, draft=False, immutable=True, tag_name='v0.1.0', published_at='2026-11-09T12:00:00Z')
        self.fake.add('GET', '/releases/9', draft)
        original_request = self.fake.__call__
        def switch(method, url, headers, body):
            result = original_request(method, url, headers, body)
            if method == 'PATCH' and url.endswith('/releases/9'):
                self.fake.add('GET', '/releases/9', published)
            return result
        self.transport.request = switch
        self.fake.add('PATCH', '/releases/9', published)
        self.fake.add('GET', '/git/ref/tags/v0.1.0', dict(object=dict(type='commit', sha='a' * 40, url=g.API + '/repos/' + g.TARGET + '/git/commits/' + 'a' * 40)))
        self.assertTrue(self.transport.finalize_immutable_release(rid, inventory))
        for name, data in self.files.items():
            url = 'https://github.com/' + g.TARGET + '/releases/download/v0.1.0/' + name
            self.fake.add('GET', url, data)
            self.assertEqual(self.transport.download_asset(rid, ids[name], name), data)
            self.assertNotIn('Authorization', self.fake.calls[-1][2])
        published['immutable'] = False
        self.fake.add('GET', '/releases/9', draft)
        with self.assertRaisesRegex(ValueError, 'immutable releases not supported'):
            self.transport.finalize_immutable_release(rid, inventory)

    def test_git_data_manifest_last_whole_branch_cas_no_force_or_retry(self):
        self.write_setup()
        self.fake.add('GET', '/git/commits/' + 'a' * 40, dict(sha='a' * 40, tree=dict(sha='1' * 40)))
        self.fake.add('POST', '/git/blobs', dict(sha='2' * 40))
        self.fake.add('POST', '/git/trees', dict(sha='3' * 40))
        self.fake.add('POST', '/git/commits', dict(sha='b' * 40))
        self.fake.add('PATCH', '/git/refs/heads/main', dict(object=dict(sha='b' * 40)))
        result = self.transport.cas_manifest(g.TARGET, 'main', 'a' * 40, 'patches-bundle.json', b'exact-approved-manifest')
        self.assertEqual(result, 'b' * 40)
        writes = [x for x in self.fake.calls if x[0] != 'GET']
        self.assertEqual(json.loads(writes[-1][3]), dict(sha='b' * 40, force=False))
        self.assertEqual(json.loads(writes[-2][3])['parents'], ['a' * 40])
        tree = json.loads(writes[-3][3])
        self.assertEqual(tree['base_tree'], '1' * 40)
        self.assertEqual(tree['tree'], [dict(path='patches-bundle.json', mode='100644', type='blob', sha='2' * 40)])
        self.assertTrue(self.fake.calls[-1][1].endswith('/git/refs/heads/main'))
        self.fake.add('PATCH', '/git/refs/heads/main', b'conflict-private-body', status=422)
        self.fake.calls.clear()
        with self.assertRaisesRegex(ValueError, 'HTTP status 422'):
            self.transport.cas_manifest(g.TARGET, 'main', 'a' * 40, 'patches-bundle.json', b'exact-approved-manifest')
        self.assertEqual(len([c for c in self.fake.calls if c[0] == 'PATCH']), 1)
        self.fake.add('GET', '/git/ref/heads/main', dict(object=dict(type='commit', sha='c' * 40)))
        self.fake.calls.clear()
        with self.assertRaisesRegex(ValueError, 'concurrent branch'):
            self.transport.cas_manifest(g.TARGET, 'main', 'a' * 40, 'patches-bundle.json', b'exact-approved-manifest')
        self.assertTrue(all(x[0] == 'GET' for x in self.fake.calls))


if __name__ == "__main__":
    unittest.main()
