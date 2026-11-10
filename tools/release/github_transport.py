"""GitHub REST boundary. Constructors do no IO; HTTP is dependency-injected.

No retry, overwrite, force, credential printing or arbitrary API host support.
Only this module reads the named authentication environment variable. Prepare
uses a read-only Actions token; a write token is only supplied by the protected
publish job. HTTP errors never include response bodies, URLs or headers.

Prerequisites (NOT configured by this code): immutable releases; environment
release with individual required reviewers, prevent_self_review, no admin bypass,
custom main-only branch policy, no custom protection rules; main branch forbids
force pushes/deletion including admins. Publish credential is a protected-environment
secret with repository-scoped Contents:write, Actions:read and Administration:read;
prepare uses only the read-only Actions token. Teams, rulesets-only branch
protection and protected-branches-only environments are unsupported/fail closed. Review
attests the evidence policy, not mathematical proof of private observations.
Candidate producer is the trusted main verify.yml workflow (run_attempt=1),
with a NEW v4 immutable artifact named release-candidate-0.1.0 containing exactly
five staged files. That upload/evidence-producing integration is a prerequisite.
"""
from __future__ import annotations
import base64
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request
import zipfile

_spec = importlib.util.spec_from_file_location('github_release_rules', Path(__file__).with_name('release.py'))
r = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(r)
TARGET = 'FISHYau/fishyau-morphe-patches'
FILES = {'patches-0.1.0.mpp', 'patches-list.json', 'patches-bundle.candidate.json', 'verification-summary.json', 'SHA256SUMS'}
API = 'https://api.github.com'
MAX_ARCHIVE = r.MAX_BUNDLE + 4 * r.MAX_JSON


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def http(method, url, headers, body):
    """Bounded, no implicit redirect/retry. Never propagates exception details."""
    try:
        request = urllib.request.Request(url, data=body, headers=headers, method=method)
        opener = urllib.request.build_opener(NoRedirect())
        try:
            response = opener.open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            data = response.read(MAX_ARCHIVE + 1)
            r.require(len(data) <= MAX_ARCHIVE, 'HTTP response too large')
            return response.status, dict(response.headers), data
    except (OSError, ValueError) as exc:
        raise r.ReleaseError('GitHub HTTP request failed (details redacted)') from None


class GitHubTransport:
    def __init__(self, token_env='GITHUB_TOKEN', *, request=http, context=None, writable=False):
        r.require(re.fullmatch(r'[A-Z][A-Z0-9_]*', token_env) is not None, 'authentication environment NAME required')
        self.token_env, self.request, self.writable = token_env, request, writable
        keys = 'GITHUB_ACTIONS GITHUB_EVENT_NAME GITHUB_REPOSITORY GITHUB_REF GITHUB_SHA GITHUB_JOB GITHUB_RUN_ATTEMPT GITHUB_WORKFLOW_REF GITHUB_WORKFLOW_SHA GITHUB_EVENT_PATH GITHUB_RUN_ID GITHUB_ACTOR'.split()
        self.context = {k: os.environ.get(k) for k in keys} if context is None else dict(context)
        self.releases = {}

    def _request(self, method, url, body=None, *, auth=True, binary=False, absent=False, redirect=False):
        r.require(url.startswith((API + '/', 'https://uploads.github.com/')) if auth else url.startswith('https://'), 'unsupported HTTP origin')
        r.require(method == 'GET' or self.writable, 'prepare transport forbids remote writes')
        headers = {'Accept': 'application/octet-stream' if binary else 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': 'fishyau-protected-publisher'}
        if auth:
            token = os.environ.get(self.token_env)
            r.require(bool(token), 'authentication environment unavailable')
            headers['Authorization'] = 'Bearer ' + token
        if isinstance(body, dict):
            body = r.canonical(body)
            headers['Content-Type'] = 'application/json'
        elif body is not None:
            headers['Content-Type'] = 'application/octet-stream'
        try:
            status, response_headers, data = self.request(method, url, headers, body)
        except Exception:
            raise r.ReleaseError('GitHub HTTP transport failed (details redacted)') from None
        if absent and status == 404:
            return None
        if redirect and status in (301, 302, 303, 307, 308):
            location = next((v for k, v in response_headers.items() if k.lower() == 'location'), '')
            try:
                parsed = urllib.parse.urlsplit(location)
                valid = parsed.scheme == 'https' and parsed.hostname is not None and not parsed.username and not parsed.password and parsed.port in (None, 443)
            except (ValueError, TypeError):
                raise r.ReleaseError('invalid artifact redirect (details redacted)') from None
            # Private Actions archive redirects use signed object-storage URLs.
            # Never forward API credentials to them; no arbitrary redirect chain.
            r.require(valid, 'invalid artifact redirect')
            host = parsed.hostname
            r.require(host.endswith('.blob.core.windows.net') or host.endswith('.githubusercontent.com') or host in {'release-assets.githubusercontent.com', 'objects.githubusercontent.com'}, 'unsupported GitHub storage redirect')
            return self._request('GET', location, auth=False, binary=True)
        r.require(200 <= status < 300, 'GitHub HTTP status ' + str(status) + ' (details redacted)')
        if binary:
            r.require(type(data) is bytes and len(data) <= MAX_ARCHIVE, 'invalid HTTP bytes')
            return data
        try:
            return json.loads(data, object_pairs_hook=r.unique_pairs)
        except (ValueError, TypeError, UnicodeError):
            raise r.ReleaseError('invalid GitHub JSON response') from None

    def api(self, path, method='GET', body=None, **kwargs):
        return self._request(method, API + '/repos/' + TARGET + path, body, **kwargs)

    def _run(self, run_id, commit, workflow, *, completed):
        run = self.api('/actions/runs/' + str(run_id))
        r.require(str(run.get('id')) == str(run_id) and run.get('head_sha') == commit and run.get('head_branch') == 'main', 'run identity/source mismatch')
        r.require(run.get('repository', {}).get('full_name') == TARGET and run.get('head_repository', {}).get('full_name') == TARGET, 'fork/wrong run repository')
        r.require(run.get('event') in {'push', 'workflow_dispatch'} and run.get('path') == workflow and run.get('run_attempt') == 1, 'unsupported candidate run origin/retry/workflow')
        if completed:
            r.require(run.get('status') == 'completed' and run.get('conclusion') == 'success', 'candidate run not successful')
        return run

    def verify_immutable_candidate(self, binding):
        r.require(binding['target'] == TARGET and binding['version'] == '0.1.0', 'target/version mismatch')
        run = self._run(binding['artifact_run'], binding['source_commit'], '.github/workflows/verify.yml', completed=True)
        artifact = self.api('/actions/artifacts/' + binding['artifact_id'])
        origin = artifact.get('workflow_run', {})
        r.require(str(artifact.get('id')) == binding['artifact_id'] and artifact.get('name') == 'release-candidate-0.1.0' and artifact.get('expired') is False, 'artifact identity/expiry mismatch')
        r.require(str(origin.get('id')) == str(run['id']) and origin.get('head_sha') == binding['source_commit'] and origin.get('head_branch') == 'main' and origin.get('repository_id') == run['repository']['id'] and origin.get('head_repository_id') == run['repository']['id'], 'artifact server origin mismatch')
        # v4 immutable artifact digest is server-derived, never a caller-only hash.
        r.require(artifact.get('digest') == 'sha256:' + binding['artifact_sha256'], 'immutable server artifact digest missing/mismatch')
        archive = self.api('/actions/artifacts/' + binding['artifact_id'] + '/zip', binary=True, redirect=True)
        r.require(r.digest(archive) == binding['artifact_sha256'], 'artifact archive digest mismatch')
        try:
            with zipfile.ZipFile(io.BytesIO(archive)) as z:
                infos = z.infolist()
                r.require(len(infos) == len(FILES) and {i.filename for i in infos} == FILES, 'artifact exact staged inventory required')
                files = {}
                for item in infos:
                    limit = r.MAX_BUNDLE if item.filename.endswith('.mpp') else r.MAX_JSON
                    r.require(not item.flag_bits & 1 and (item.external_attr >> 16) & 0o170000 in (0, 0o100000) and item.file_size <= limit, 'artifact special/encrypted/oversized member')
                    files[item.filename] = z.read(item)
        except (zipfile.BadZipFile, RuntimeError, OSError):
            raise r.ReleaseError('invalid artifact ZIP') from None
        seal = r.digest(r.canonical({name: r.digest(data) for name, data in files.items()}))
        r.require(seal == binding['candidate_sha256'], 'artifact candidate seal mismatch')
        return files

    def authenticate_protected_review(self, binding):
        c = self.context
        r.require(c.get('GITHUB_ACTIONS') == 'true' and c.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and c.get('GITHUB_REPOSITORY') == TARGET and c.get('GITHUB_REF') == 'refs/heads/main' and c.get('GITHUB_SHA') == binding['source_commit'] and c.get('GITHUB_JOB') == 'publish' and c.get('GITHUB_RUN_ATTEMPT') == '1', 'trusted main manual publish context required')
        r.require(c.get('GITHUB_WORKFLOW_REF') == TARGET + '/.github/workflows/release.yml@refs/heads/main' and c.get('GITHUB_WORKFLOW_SHA') == binding['source_commit'], 'trusted publisher workflow identity required')
        event, _ = r.read_json(Path(c.get('GITHUB_EVENT_PATH', '')))
        r.require(event.get('inputs') == dict(binding, mode='publish') and event.get('repository', {}).get('full_name') == TARGET and event.get('ref') == 'refs/heads/main', 'approval run dispatch binding mismatch')
        r.require(c.get('GITHUB_RUN_ID', '').isdecimal(), 'current run id required')
        run = self._run(c['GITHUB_RUN_ID'], binding['source_commit'], '.github/workflows/release.yml', completed=False)
        r.require(run.get('event') == 'workflow_dispatch' and run.get('status') == 'in_progress', 'publish run not active/manual')
        actor = run.get('actor', {})
        triggering = run.get('triggering_actor', {})
        r.require(actor.get('type') == 'User' and triggering.get('login') == actor.get('login') and c.get('GITHUB_ACTOR') == actor.get('login') and event.get('sender', {}).get('login') == actor.get('login'), 'unsupported actor/rerun identity')
        env = self.api('/environments/release')
        r.require(env.get('name') == 'release' and env.get('can_admins_bypass') is False, 'release environment admin bypass unsupported')
        policy = env.get('deployment_branch_policy', {})
        r.require(policy == {'protected_branches': False, 'custom_branch_policies': True}, 'explicit main-only environment policy required')
        branches = self.api('/environments/release/deployment-branch-policies?per_page=100')
        rules = branches.get('branch_policies', [])
        r.require(branches.get('total_count') == 1 and len(rules) == 1 and rules[0].get('name') == 'main' and rules[0].get('type') == 'branch', 'main-only environment branch policy required')
        protections = env.get('protection_rules', [])
        r.require(len(protections) == 2 and {x.get('type') for x in protections} == {'required_reviewers', 'branch_policy'}, 'unsupported/missing environment protection rules')
        required = next(x for x in protections if x.get('type') == 'required_reviewers')
        r.require(required.get('prevent_self_review') is True, 'prevent_self_review required')
        reviewers = required.get('reviewers', [])
        r.require(reviewers and all(x.get('type') == 'User' and x.get('reviewer', {}).get('type') == 'User' for x in reviewers), 'only individual human reviewers supported')
        allowed = {x['reviewer']['login'].casefold() for x in reviewers}
        reviews = self.api('/actions/runs/' + c['GITHUB_RUN_ID'] + '/approvals?per_page=100')
        r.require(isinstance(reviews, list) and len(reviews) < 100, 'unsupported paginated review history')
        relevant = [x for x in reviews if any(e.get('id') == env.get('id') and e.get('name') == 'release' for e in x.get('environments', []))]
        r.require(len(relevant) == 1, 'exact single protected approval required; reject reruns/rejections')
        review = relevant[0]
        user = review.get('user', {})
        r.require(review.get('state') == 'approved' and user.get('type') == 'User' and user.get('login', '').casefold() in allowed and user.get('login', '').casefold() != actor['login'].casefold(), 'independent configured human approval required')
        # The exact same-run environment review covers immutable dispatch inputs.
        # Run start is a conservative lower bound: approval cannot predate it.
        # Require an explicit policy attestation; JSON cannot authenticate reports.
        seal = r.digest(r.canonical(binding))
        r.require(review.get('comment') == 'evidence-policy-reviewed binding-sha256=' + seal, 'human evidence-policy attestation missing or wrong binding')
        when = run.get('run_started_at', '')
        r.require(when.endswith('Z'), 'server run timestamp unavailable')
        return dict(binding=dict(binding), environment='release', reviewer=user['login'], actor=actor['login'], reviewed_at=when[:-1], independent_review=True, prevent_self_review=True, main_only=True, no_admin_bypass=True, evidence_authenticated=True)

    def branch_head(self, target, branch):
        r.require(target == TARGET and branch == 'main', 'main target required')
        ref = self.api('/git/ref/heads/main')
        r.require(ref.get('object', {}).get('type') == 'commit', 'branch commit required')
        sha = ref['object']['sha']
        r.revision(sha)
        return sha

    def _branch_protection(self):
        # Nonforce sibling-commit CAS relies on a branch that cannot be rewound
        # or deleted concurrently. Rulesets-only configurations are unsupported
        # here rather than being silently mistaken for this reviewed contract.
        protection = self.api('/branches/main/protection')
        r.require(protection.get('enforce_admins', {}).get('enabled') is True and protection.get('allow_force_pushes', {}).get('enabled') is False and protection.get('allow_deletions', {}).get('enabled') is False, 'protected main must forbid force updates/deletion including admins; unsupported protection settings')

    def create_immutable_release(self, target, version, source_commit):
        r.require(target == TARGET and version == '0.1.0', 'exact release target/version required')
        self._branch_protection()
        tag = 'v' + version
        r.require(self.api('/git/ref/tags/' + tag, absent=True) is None, 'tag already exists; never reuse')
        # Draft tags may not resolve through /releases/tags, so enumerate drafts too.
        r.require(self.api('/releases/tags/' + tag, absent=True) is None, 'release already exists; never reuse')
        page = 1
        while True:
            releases = self.api('/releases?per_page=100&page=' + str(page))
            r.require(isinstance(releases, list) and all(x.get('tag_name') != tag for x in releases), 'draft/release already exists; never reuse')
            if len(releases) < 100:
                break
            page += 1
            r.require(page <= 100, 'release inventory too large to verify')
        r.require(self.branch_head(target, 'main') == source_commit, 'branch changed before tag creation')
        self.api('/git/refs', 'POST', {'ref': 'refs/tags/' + tag, 'sha': source_commit})
        release = self.api('/releases', 'POST', {'tag_name': tag, 'target_commitish': source_commit, 'name': tag, 'draft': True, 'prerelease': False, 'generate_release_notes': False, 'body': 'Exact reviewed candidate; see verification-summary.json for bounded evidence and runtime limitations.'})
        r.require(release.get('draft') is True and release.get('tag_name') == tag and release.get('assets') == [] and type(release.get('id')) is int, 'new empty draft required')
        rid = release['id']
        self.releases[rid] = {'tag': tag, 'commit': source_commit, 'assets': {}}
        return rid

    def upload_asset(self, release_id, name, data):
        state = self.releases[release_id]
        r.require(name in FILES and name not in state['assets'], 'never overwrite/reuse asset')
        result = self._request('POST', 'https://uploads.github.com/repos/' + TARGET + '/releases/' + str(release_id) + '/assets?name=' + urllib.parse.quote(name, safe=''), data)
        r.require(result.get('name') == name and result.get('state') == 'uploaded' and result.get('size') == len(data) and type(result.get('id')) is int, 'asset upload identity mismatch')
        state['assets'][name] = result['id']
        return result['id']

    def finalize_immutable_release(self, release_id, inventory):
        state = self.releases[release_id]
        r.require(set(inventory) == FILES and set(state['assets']) == FILES, 'full release inventory required')
        draft = self.api('/releases/' + str(release_id))
        assets = draft.get('assets', [])
        r.require(draft.get('draft') is True and len(assets) == len(FILES) and {x.get('name'): x.get('id') for x in assets} == state['assets'], 'draft asset inventory changed')
        for asset in assets:
            r.require(asset.get('digest') == 'sha256:' + inventory[asset['name']], 'server asset digest missing/mismatch')
        self.api('/releases/' + str(release_id), 'PATCH', {'draft': False, 'make_latest': 'false'})
        published = self.api('/releases/' + str(release_id))
        r.require(published.get('draft') is False and published.get('immutable') is True and published.get('tag_name') == state['tag'] and published.get('published_at'), 'server-enforced immutable releases not supported/configured; manifest not advanced')
        tag = self.api('/git/ref/tags/' + state['tag'])
        r.require(tag.get('object') == {'type': 'commit', 'sha': state['commit'], 'url': API + '/repos/' + TARGET + '/git/commits/' + state['commit']}, 'immutable tag/source mismatch')
        return True

    def download_asset(self, release_id, asset_id, name):
        state = self.releases[release_id]
        r.require(state['assets'].get(name) == asset_id, 'asset identity mismatch')
        # Public canonical URL, NO auth. GitHub redirects to public release storage.
        url = 'https://github.com/' + TARGET + '/releases/download/' + state['tag'] + '/' + name
        return self._request('GET', url, auth=False, binary=True, redirect=True)

    def cas_manifest(self, target, branch, expected_head, filename, data):
        r.require(target == TARGET and branch == 'main' and filename == 'patches-bundle.json', 'exact manifest target required')
        self._branch_protection()
        r.require(self.branch_head(target, branch) == expected_head, 'concurrent branch change before CAS')
        source = self.api('/git/commits/' + expected_head)
        r.require(source.get('sha') == expected_head, 'source commit mismatch')
        blob = self.api('/git/blobs', 'POST', {'content': base64.b64encode(data).decode('ascii'), 'encoding': 'base64'})
        tree = self.api('/git/trees', 'POST', {'base_tree': source['tree']['sha'], 'tree': [{'path': filename, 'mode': '100644', 'type': 'blob', 'sha': blob['sha']}]})
        commit = self.api('/git/commits', 'POST', {'message': 'Publish reviewed patches 0.1.0 manifest\n\nCo-Authored-By: Claude Code <noreply@anthropic.com>', 'tree': tree['sha'], 'parents': [expected_head]})
        r.revision(commit['sha'])
        # A sibling commit is NOT a fast-forward of any concurrent descendant.
        # Never force, rebase, retry, or fall back to Contents file-SHA updates.
        result = self.api('/git/refs/heads/main', 'PATCH', {'sha': commit['sha'], 'force': False})
        r.require(result.get('object', {}).get('sha') == commit['sha'], 'manifest branch CAS response mismatch')
        return commit['sha']
