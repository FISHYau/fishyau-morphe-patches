#!/usr/bin/env python3
"""Protected publisher; default prepare reads/verifies but NEVER writes remotely.

CLI: python -I -B tools/release/publisher.py contract
     python -I -B tools/release/publisher.py handoff --mode prepare
       --candidate DIR --source-root ROOT --target FISHYau/fishyau-morphe-patches
       --version 0.1.0 --candidate-sha256 SHA --artifact-run ID --artifact-id ID
       --artifact-sha256 SHA --source-commit FULL_SHA --auth-env GITHUB_TOKEN

No rebuild. Real HTTP adapter in github_transport.py; all tests inject offline
HTTP. Publish requires trusted Actions context and actual protected human review.
No tests or syntax checks imply configured prerequisites or real publication.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
from types import MappingProxyType

_spec = importlib.util.spec_from_file_location("staging_v1", Path(__file__).with_name("staging.py"))
s = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(s)
r = s.r

CONTRACT = """protected-publish-handoff-v2 (real adapter; maintainer setup still required)
Dispatch binding exact fields: target, version, candidate_sha256,
artifact_run (positive decimal string), artifact_id (positive decimal string),
artifact_sha256 (exact immutable workflow artifact archive SHA256), source_commit
(full lowercase Git SHA). Explicit mode is prepare or publish; prepare is default.
Candidate SHA is SHA256(canonical({filename: SHA256(exact bytes)})), INCLUDING
SHA256SUMS, over exactly the five staged files. This is distinct from the workflow
artifact archive hash, and from bundle/catalog/request/evidence/source hashes.

Trusted injected transport API (no user-supplied JSON authentication):
verify_immutable_candidate(binding) -> mapping of exact staged filename -> bytes.
It MUST fetch the exact artifact run/id in this target repository, reject expired,
mutable, wrong-workflow/fork/untrusted-origin artifacts and verify the archive
SHA256, run success and source identity server-side. No latest/name-only lookup.
authenticate_protected_review(binding) -> record with exact fields:
binding, environment=release, reviewer, actor, reviewed_at, independent_review,
prevent_self_review, main_only, no_admin_bypass, evidence_authenticated.
It MUST verify GitHub's actual deployment review/run/environment settings and
server-authenticated independent human approval, bound to ALL dispatch fields,
including exact artifact archive and candidate hashes. It must verify the human
attested review of private evidence and migration provenance. This does not
mathematically authenticate those observations. No approval.json, unchecked
workflow input, environment name alone or bot actor establishes approval.
branch_head(target, branch) -> full SHA.
create_immutable_release(target, version, source_commit) -> opaque release id;
MUST refuse any preexisting version/tag/assets (never overwrite or reuse), reserve
a NEW draft release/tag pinned to source_commit, with no mutable asset URLs.
Despite the method name, do NOT lock a GitHub release before uploading its assets.
upload_asset(release_id, name, bytes) -> opaque asset id; never replace assets.
finalize_immutable_release(release_id, filename_to_sha256) -> exactly True only
when the release is published and server-enforced immutable (including tag and
assets). Refuse repositories without this real protection. This separate step
allows uploading draft assets before GitHub's immutable-release lock is enabled.
download_asset(release_id, asset_id, name) -> exact bytes fetched through the
published canonical public asset URL after finalization, not authenticated-only
draft bytes or a local echo/cache. Core compares ALL bytes/hashes for every asset.
cas_manifest(target, branch, expected_head, filename, bytes) -> new commit SHA;
MUST create a commit with sole parent expected_head changing ONLY the manifest,
and update main WITHOUT force. A concurrent divergent/descendant update rejects
this sibling commit: NEVER rebase/retry approval on a new head. Recheck head
immediately before this call; API must preserve the atomic nonforce semantics.
No writes after manifest update. Failed releases/assets remain failed evidence;
no cleanup, overwrite, rollback or force updates. Approval expires after 7 days.

Publish independently validates staged inventory/metadata/checksums, exact source
tree, clean committed root/HEAD, immutable remote package bytes and authenticated
review, then checks main == approved source commit. It uploads frozen approved
assets, downloads and byte-compares all, rechecks candidate/source/Git/approval
and branch, then advances patches-bundle.json LAST. No rebuild. The CLI uses the real HTTP adapter, defaulting to prepare with a
read-only token environment NAME. Prepare fetches and verifies server artifact
run/id/origin/digest and compares every staged byte with exact source provenance.
Publish is opt-in; the adapter verifies actual environment settings, run/review
APIs and trusted manual event context. The release review comment MUST be exactly:
evidence-policy-reviewed binding-sha256=<SHA256(canonical(dispatch binding))>
This attests human review under the evidence policy; it does not prove private
observations. Approval uses run start as its conservative server time lower bound,
so observations must precede dispatch. No teams, bypass, retries or unknown rules.
Maintainer prerequisites are not claimed configured: protected release environment,
immutable releases, read access to run/environment/review APIs, a main verify.yml
producer uploading immutable release-candidate-0.1.0 (five files, schema2 staging),
and a clean committed source revision. A candidate may truthfully stage with
Plex runtime not-observed/blocked, but publication requires its own fresh observed
Android runtime evidence as well as protected human review. No remote call is made
by importing code.
"""

FILES = {"patches-0.1.0.mpp", "patches-list.json", "patches-bundle.candidate.json", "verification-summary.json", "SHA256SUMS"}


def observation_times(summary, now=None):
    """Validate sanitized report structure; freshness is rechecked at promotion."""
    observed = summary["reported_new_observations"]
    current = summary["policy"] == s.COLLECTION_POLICY
    r.exact(observed, "jvm_inspection jvm_structural android_manager_local_import evidence_authenticated" + (" plex" if current else ""), "reported observations")
    r.require(observed["evidence_authenticated"] is False, "staging must not fabricate authentication")
    values = []
    for key, platform in (("jvm_inspection", "jvm"), ("android_manager_local_import", "android")):
        item = observed[key]
        r.exact(item, "platform status observed_at", "observation summary")
        r.require(item["platform"] == platform and item["status"] == "passed", "reported platform/status mismatch")
        values.append(item["observed_at"])
    structural = observed["jvm_structural"]
    r.require(isinstance(structural, list) and len(structural) == 3, "complete structural summaries required")
    selections = set()
    for item in structural:
        r.exact(item, "platform status selection observed_at scope_sha256", "structural summary")
        r.require(item["platform"] == "jvm" and item["status"] == "passed", "structural platform/status mismatch")
        selection = item["selection"]
        r.require(isinstance(selection, list) and all(isinstance(n, str) for n in selection) and selection == sorted(set(selection)), "structural summary selection required")
        selections.add(tuple(selection))
        r.sha(item["scope_sha256"])
        values.append(item["observed_at"])
    r.require(selections == {(name,) for name in s.PATCHES} | {tuple(sorted(s.PATCHES))}, "summary structural selection coverage mismatch")
    if current:
        plex = observed["plex"]
        r.exact(plex, "resource parser final_bundle runtime", "Plex summaries")
        for key in s.PLEX_REPORTS:
            item = plex[key]
            r.exact(item, "platform status observed_at", "Plex report summary")
            r.require(item["platform"] == "jvm" and item["status"] == "passed", "Plex report summary mismatch")
            values.append(item["observed_at"])
        runtime = plex["runtime"]
        r.require(runtime.get("status") in {"not-observed", "blocked", "observed"}, "Plex runtime status required")
        r.exact(runtime, "status scope_sha256" + (" observed_at" if runtime["status"] == "observed" else ""), "Plex runtime summary")
        r.sha(runtime["scope_sha256"])
        if runtime["status"] == "observed":
            values.append(runtime["observed_at"])
    return [r.fresh(value, now) if now is not None else r.local_time(value) for value in values]


def candidate(directory):
    directory = Path(directory)
    r.require(directory.is_dir() and not r.linked(directory), "candidate directory required")
    r.require({p.name for p in directory.iterdir()} == FILES, "candidate file inventory mismatch")
    files = {name: r.read_bytes(directory / name, r.MAX_BUNDLE if name.endswith(".mpp") else r.MAX_JSON) for name in sorted(FILES)}
    expected = "".join(f"{r.digest(data)}  {name}\n" for name, data in sorted(files.items()) if name != "SHA256SUMS").encode("ascii")
    r.require(files["SHA256SUMS"] == expected, "candidate checksum mismatch")
    summary = r.read_json(directory / "verification-summary.json")[0]
    r.exact(summary, "schema policy status target version binding evidence_sha256 inherited_behavior reported_new_observations trust remaining", "staged summary")
    r.require(type(summary["schema"]) is int and (summary["schema"], summary["policy"]) in {(1, s.POLICY), (2, s.COLLECTION_POLICY)} and summary["status"] == "staged-not-published", "accepted staging policy required")
    r.require(summary["target"] == s.TARGET and summary["version"] == "0.1.0", "candidate target/version mismatch")
    binding = summary["binding"]
    r.exact(binding, "policy request_sha256 bundle_sha256 catalog_sha256 source_tree_sha256", "staged binding")
    r.require(binding["policy"] == summary["policy"], "binding policy mismatch")
    for key in ("request_sha256", "bundle_sha256", "catalog_sha256", "source_tree_sha256"):
        r.sha(binding[key])
    r.sha(summary["evidence_sha256"])
    observation_times(summary)
    r.require(binding["bundle_sha256"] == r.digest(files["patches-0.1.0.mpp"]) and binding["catalog_sha256"] == r.digest(files["patches-list.json"]), "candidate bundle/catalog binding mismatch")
    catalog = r.read_json(directory / "patches-list.json")[0]
    s.inventory(catalog, "0.1.0", summary["policy"])
    meta = r.bundle_metadata(files["patches-0.1.0.mpp"])
    r.require(all(meta.get(k) == v for k, v in {"name": "FISHYau android patches", "author": "FISHYau", "version": "0.1.0", "patcher-version": "2.3.0"}.items()), "candidate metadata mismatch")
    manifest = r.read_json(directory / "patches-bundle.candidate.json")[0]
    r.validate_manifest(manifest, "FISHYau", "fishyau-morphe-patches", "0.1.0")
    r.require("public_key" not in manifest, "unsigned candidate must not advertise signing key")
    r.require(manifest.get("page_url") == "https://github.com/" + s.TARGET + "/releases/tag/v0.1.0", "candidate page URL mismatch")
    # Snapshot must equal the bytes parsed by read_json (defends in-process changes).
    for name in ("verification-summary.json", "patches-list.json", "patches-bundle.candidate.json"):
        r.require(r.read_bytes(directory / name, r.MAX_JSON) == files[name], "candidate changed during validation")
    seal = r.digest(r.canonical({name: r.digest(data) for name, data in files.items()}))
    return MappingProxyType(files), summary, seal


def dispatch(value):
    r.exact(value, "target version candidate_sha256 artifact_run artifact_id artifact_sha256 source_commit", "dispatch")
    r.require(value["target"] == s.TARGET and value["version"] == "0.1.0", "explicit accepted target/version required")
    for key in ("candidate_sha256", "artifact_sha256"):
        r.sha(value[key])
    r.revision(value["source_commit"])
    for key in ("artifact_run", "artifact_id"):
        r.require(isinstance(value[key], str) and value[key].isascii() and value[key].isdecimal() and int(value[key]) > 0, "immutable artifact run/id required")
    return MappingProxyType(dict(value))


def local_check(directory, source_root, binding, *, committed=False, now=None):
    files, summary, seal = candidate(directory)
    r.require(summary["policy"] == s.COLLECTION_POLICY, "publication requires current three-patch policy; legacy staging is not initial collection approval")
    observation_times(summary, now)
    if now is not None:
        manifest = json.loads(files["patches-bundle.candidate.json"])
        r.require(r.local_time(manifest["created_at"]) <= now, "future candidate creation date")
    r.require(seal == binding["candidate_sha256"], "stale candidate approval binding")
    tree, paths = r.source_tree(Path(source_root))
    r.require(tree == summary["binding"]["source_tree_sha256"], "approved source tree mismatch")
    (s.collection_provenance if summary["policy"] == s.COLLECTION_POLICY else s.provenance)(summary["inherited_behavior"], paths)
    if committed:
        r.clean_revision(source_root, binding["source_commit"], paths)
    return files


def protected_review(transport, binding, now, observed_times):
    # Only the transport authenticates this record against GitHub. There is no
    # --approval JSON option; a report is not an authentication credential.
    review = transport.authenticate_protected_review(dict(binding))
    r.exact(review, "binding environment reviewer actor reviewed_at independent_review prevent_self_review main_only no_admin_bypass evidence_authenticated", "authenticated protected review")
    r.require(r.canonical(review["binding"]) == r.canonical(dict(binding)), "stale protected approval")
    r.require(review["environment"] == "release", "release environment required")
    r.text(review["reviewer"], "authenticated reviewer")
    r.text(review["actor"], "authenticated actor")
    r.require(review["reviewer"].casefold() != review["actor"].casefold(), "self-review forbidden")
    r.require(all(review[k] is True for k in ("independent_review", "prevent_self_review", "main_only", "no_admin_bypass", "evidence_authenticated")), "unconfigured protection or unauthenticated evidence")
    r.require(r.fresh(review["reviewed_at"], now) >= max(observed_times), "protected review predates final observations")
    return r.digest(r.canonical(review))


def publish(directory, source_root, binding, transport, *, mode="prepare", now=None):
    """Pure orchestration with injected trusted remote boundary; default has no IO writes."""
    r.require(mode in {"prepare", "publish"}, "explicit prepare/publish mode required")
    binding = dispatch(binding)
    now_fn = (lambda: now) if now is not None else (lambda: dt.datetime.now(r.UTC))
    files = local_check(directory, source_root, binding, committed=mode == "publish", now=now_fn())
    summary = json.loads(files["verification-summary.json"])
    observed_times = observation_times(summary, now_fn())
    if mode == "publish":
        r.require(summary["reported_new_observations"]["plex"]["runtime"]["status"] == "observed",
                  "Plex runtime acceptance remains unobserved/blocked; staging is not publication approval")
    r.require(transport is not None, "authenticated GitHub transport required, including prepare")
    remote = transport.verify_immutable_candidate(dict(binding))
    r.require(isinstance(remote, dict) and set(remote) == set(files) and all(type(remote[n]) is bytes and remote[n] == files[n] for n in files), "immutable artifact bytes/identity mismatch")
    if mode == "prepare":
        return {"status": "dry-run-not-published", "candidate_sha256": binding["candidate_sha256"],
                "authenticated_approval": False, "remote_candidate_verified": True, "remote_readiness": False,
                "required_review_comment": "evidence-policy-reviewed binding-sha256=" + r.digest(r.canonical(dict(binding)))}
    approved = protected_review(transport, binding, now_fn(), observed_times)
    target, commit = binding["target"], binding["source_commit"]
    r.require(transport.branch_head(target, "main") == commit, "concurrent/stale branch head")
    release_id = transport.create_immutable_release(target, binding["version"], commit)
    # All five sanitized assets, including the clearly named candidate manifest,
    # are uploaded. The LIVE root manifest is only changed by the final CAS.
    asset_ids = {name: transport.upload_asset(release_id, name, data) for name, data in files.items()}
    r.require(transport.finalize_immutable_release(release_id, {name: r.digest(data) for name, data in files.items()}) is True,
              "release assets/tag not publicly immutable")
    for name, data in files.items():
        downloaded = transport.download_asset(release_id, asset_ids[name], name)
        r.require(type(downloaded) is bytes and downloaded == data and r.digest(downloaded) == r.digest(data), "uploaded asset readback mismatch")
    r.require(dict(local_check(directory, source_root, binding, committed=True, now=now_fn())) == dict(files), "candidate changed during publish")
    r.require(protected_review(transport, binding, now_fn(), observed_times) == approved, "approval changed during publish")
    r.require(transport.branch_head(target, "main") == commit, "concurrent branch change; approval cannot be rebased")
    new_commit = transport.cas_manifest(target, "main", commit, "patches-bundle.json", files["patches-bundle.candidate.json"])
    r.revision(new_commit)
    r.require(new_commit != commit, "manifest CAS did not advance commit")
    return {"status": "published", "source_commit": commit, "manifest_commit": new_commit,
            "candidate_sha256": binding["candidate_sha256"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("contract")
    cmd = sub.add_parser("handoff")
    cmd.add_argument("--mode", choices=("prepare", "publish"), default="prepare")
    cmd.add_argument("--candidate", type=Path, required=True)
    cmd.add_argument("--source-root", type=Path, required=True)
    cmd.add_argument("--auth-env", default="GITHUB_TOKEN", help="environment variable NAME only; never a token value")
    for key in ("target", "version", "candidate_sha256", "artifact_run", "artifact_id", "artifact_sha256", "source_commit"):
        cmd.add_argument("--" + key.replace("_", "-"), required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    try:
        if command == "contract":
            print(CONTRACT)
        else:
            binding = {k: args.pop(k) for k in ("target", "version", "candidate_sha256", "artifact_run", "artifact_id", "artifact_sha256", "source_commit")}
            spec = importlib.util.spec_from_file_location("github_publisher_transport", Path(__file__).with_name("github_transport.py"))
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            transport = module.GitHubTransport(args.pop("auth_env"), writable=args["mode"] == "publish")
            # Refuse missing trusted publish context BEFORE any credential/network
            # use. Actual authentication still requires all server checks.
            if args["mode"] == "publish":
                r.require(transport.context.get("GITHUB_ACTIONS") == "true" and transport.context.get("GITHUB_JOB") == "publish", "trusted Actions publish job required")
            print(publish(args.pop("candidate"), args.pop("source_root"), binding, transport, **args))
    except (r.ReleaseError, OSError, ValueError, TypeError, KeyError) as exc:
        print(f"Handoff blocked: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
