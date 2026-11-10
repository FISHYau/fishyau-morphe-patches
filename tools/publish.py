#!/usr/bin/env python3
"""Prepare public collection files locally; only --publish permits GitHub writes.

Run with installed Python -I -B. Dry runs never invoke gh or the network. An
explicit future publication uses gh's existing github.com login, never retrieves
credentials, and never overwrites a release/tag. Only the selected MPP and public
catalog are uploaded. Actual downloaded bytes must match before the ordinary
Manager manifest is advanced last. Failures retain local outputs and any partial
remote release; there is no retry, force update, cleanup or automatic rollback.

This is format validation, not DEX execution or runtime acceptance. The final
nonforce Git-ref update uses a commit whose sole parent is the captured main
head: concurrent forward changes conflict rather than being silently merged.
As with Git's nonforce semantics, an out-of-band force rewind/delete-and-recreate
between the head check and update cannot be made atomic by this client. Repos
must prohibit such concurrent operations; no administrative credential is used.
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

_spec = importlib.util.spec_from_file_location("publish_bundle_formats", Path(__file__).with_name("bundle_formats.py"))
f = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(f)
REPO_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "patches-bundle.json"


def git_sha(value):
    f.require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value), "invalid GitHub object SHA")
    return value


class GitHub:
    """Small gh CLI adapter; errors never disclose stderr, auth, URLs or bodies."""
    def __init__(self, repository):
        self.repository = repository
        self.executable = shutil.which("gh")
        f.require(self.executable is not None, "installed gh CLI required for --publish")

    def run(self, args, *, data=None, limit=f.MAX_JSON):
        env = dict(os.environ)
        env.pop("GH_DEBUG", None)
        env["GH_HOST"] = "github.com"
        env["GH_PROMPT_DISABLED"] = "1"
        try:
            # Spool CLI output outside the source tree, then read it boundedly.
            # Never echo gh stderr: it can contain credentials or signed URLs.
            with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
                result = subprocess.run([self.executable, *args], input=data, stdout=output,
                                        stderr=errors, env=env, timeout=180, check=False)
                f.require(result.returncode == 0, "gh operation failed; remote state may be partially changed (details redacted)")
                output.seek(0)
                value = output.read(limit + 1)
                f.require(len(value) <= limit, "gh response too large")
                return value
        except (OSError, subprocess.SubprocessError):
            raise ValueError("gh operation failed; remote state may be partially changed (details redacted)") from None

    def api(self, path, method="GET", body=None, *, binary=False, limit=f.MAX_JSON):
        args = ["api", "--hostname", "github.com", "--method", method,
                "repos/" + self.repository + path]
        if binary:
            args += ["--header", "Accept: application/octet-stream"]
        if body is not None:
            args += ["--input", "-"]
        value = self.run(args, data=None if body is None else f.canonical(body), limit=limit)
        if binary:
            return value
        try:
            return json.loads(value, object_pairs_hook=f.unique_pairs,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        except (ValueError, UnicodeError, RecursionError):
            raise ValueError("invalid gh JSON response") from None

    def upload(self, tag, paths):
        # Absolute paths cannot become flags. No shell and no --clobber.
        self.run(["release", "upload", tag, *[str(path.resolve()) for path in paths],
                  "--repo", "github.com/" + self.repository])


def new_output(path):
    path = Path(path).absolute()
    f.require("#" not in str(path), "--out cannot contain gh's filename#label separator")
    f.require(not path.exists() and not f.linked(path), "--out must be a NEW nonexistent directory")
    f.require(path.parent.is_dir(), "output parent must already exist")
    f.require(not any(f.linked(parent) for parent in (path.parent, *path.parent.parents)), "linked output parent unsupported")
    resolved = path.resolve()
    f.require(not resolved.is_relative_to(REPO_ROOT) and not REPO_ROOT.is_relative_to(resolved), "output must be external to repository")
    path.mkdir()
    return path


def prepare(repository, version, bundle, catalog, out, *, description=None, created_at=None):
    fields = repository.split("/")
    f.require(len(fields) == 2, "--repository must be explicit OWNER/REPO")
    owner, repo = fields
    manifest = f.make_manifest({"owner": owner, "repository": repo, "version": version,
                                "description": description if description is not None else f"Experimental patch collection {version}.",
                                "created_at": created_at if created_at is not None else dt.datetime.now(f.UTC).strftime("%Y-%m-%dT%H:%M:%S")})
    f.require(f.local_time(manifest["created_at"]) <= dt.datetime.now(f.UTC), "future creation date")
    f.require(Path(bundle).suffix == ".mpp", "explicit .mpp bundle required")
    bundle_bytes = f.read_bytes(bundle, f.MAX_BUNDLE)
    metadata = f.bundle_metadata(bundle_bytes)
    expected = {"name": "FISHYau android patches", "author": "FISHYau", "version": version, "patcher-version": "2.3.0"}
    f.require(all(metadata.get(key) == value for key, value in expected.items()), "bundle identity/version/patcher mismatch")
    inventory, catalog_bytes = f.read_json(catalog)
    f.collection_inventory(inventory, version)
    directory = new_output(out)
    files = {f"patches-{version}.mpp": bundle_bytes, "patches-list.json": catalog_bytes,
             MANIFEST: f.canonical(manifest)}
    for name, data in files.items():
        with (directory / name).open("xb") as stream:
            stream.write(data)
    return directory, manifest, files


def branch_head(gh):
    ref = gh.api("/git/ref/heads/main")
    f.require(isinstance(ref, dict) and ref.get("ref") == "refs/heads/main" and ref.get("object", {}).get("type") == "commit", "main branch commit required")
    return git_sha(ref["object"].get("sha"))


def unchanged(gh, expected):
    f.require(branch_head(gh) == expected, "main changed; manifest not advanced")


def check_tag(gh, tag, expected=None):
    refs = gh.api("/git/matching-refs/tags/" + tag)
    f.require(isinstance(refs, list), "invalid tag inventory")
    matches = [ref for ref in refs if ref.get("ref") == "refs/tags/" + tag]
    if expected is None:
        f.require(not matches, "tag already exists; never overwrite")
    else:
        f.require(len(matches) == 1 and matches[0].get("object", {}).get("type") == "commit"
                  and matches[0]["object"].get("sha") == expected, "release tag changed; manifest not advanced")


def publish(gh, directory, manifest, files):
    """Remote writes only. Inputs are the exact validated local preparation bytes."""
    version, tag = manifest["version"], "v" + manifest["version"]
    public = [f"patches-{version}.mpp", "patches-list.json"]
    for name in [*public, MANIFEST]:
        f.require(f.read_bytes(directory / name, f.MAX_BUNDLE if name.endswith(".mpp") else f.MAX_JSON) == files[name], "prepared asset changed before publication")
    # Capture the entire branch, not only the old manifest blob. An absent root
    # manifest works naturally: the Git tree operation creates it without a PUT.
    expected = branch_head(gh)
    commit = gh.api("/git/commits/" + expected)
    tree_sha = git_sha(commit.get("tree", {}).get("sha"))
    tree = gh.api("/git/trees/" + tree_sha)
    f.require(tree.get("truncated") is False and isinstance(tree.get("tree"), list), "complete main root tree required")
    prior = [item for item in tree["tree"] if item.get("path") == MANIFEST]
    f.require(len(prior) <= 1 and all(item.get("type") == "blob" and item.get("mode") == "100644" for item in prior), "existing manifest must be a regular file")
    check_tag(gh, tag)
    # Enumerate drafts as well; /releases/tags alone can miss unpublished drafts.
    for page in range(1, 101):
        releases = gh.api(f"/releases?per_page=100&page={page}")
        f.require(isinstance(releases, list) and all(item.get("tag_name") != tag for item in releases), "release already exists; never overwrite")
        if len(releases) < 100:
            break
    else:
        raise ValueError("release inventory too large")
    unchanged(gh, expected)
    gh.api("/git/refs", "POST", {"ref": "refs/tags/" + tag, "sha": expected})
    release = gh.api("/releases", "POST", {"tag_name": tag, "target_commitish": expected, "name": tag,
                                           "draft": True, "prerelease": True, "generate_release_notes": False,
                                           "body": manifest["description"]})
    f.require(type(release.get("id")) is int and release["id"] > 0 and release.get("draft") is True
              and release.get("tag_name") == tag and release.get("assets") == [], "new empty draft release required")
    rid = release["id"]
    gh.upload(tag, [directory / name for name in public])
    uploaded = gh.api(f"/releases/{rid}/assets?per_page=100")
    f.require(isinstance(uploaded, list) and len(uploaded) == 2 and {item.get("name") for item in uploaded} == set(public), "uploaded release asset inventory mismatch")
    ids = set()
    for item in uploaded:
        aid, name = item.get("id"), item["name"]
        f.require(type(aid) is int and aid > 0 and aid not in ids and item.get("state") == "uploaded"
                  and item.get("size") == len(files[name]), "uploaded asset identity/size mismatch")
        ids.add(aid)
        actual = gh.api(f"/releases/assets/{aid}", binary=True,
                        limit=f.MAX_BUNDLE if name.endswith(".mpp") else f.MAX_JSON)
        f.require(actual == files[name], "uploaded asset readback mismatch; manifest not advanced")
    unchanged(gh, expected)
    check_tag(gh, tag, expected)
    visible = gh.api(f"/releases/{rid}", "PATCH", {"draft": False})
    f.require(visible.get("id") == rid and visible.get("tag_name") == tag and visible.get("draft") is False, "release publication failed; manifest not advanced")
    blob = gh.api("/git/blobs", "POST", {"content": base64.b64encode(files[MANIFEST]).decode("ascii"), "encoding": "base64"})
    updated_tree = gh.api("/git/trees", "POST", {"base_tree": tree_sha, "tree": [
        {"path": MANIFEST, "mode": "100644", "type": "blob", "sha": git_sha(blob.get("sha"))}]})
    update = gh.api("/git/commits", "POST", {"message": f"Update patch collection to {version}\n\nCo-Authored-By: Claude Code <noreply@anthropic.com>",
                                           "tree": git_sha(updated_tree.get("sha")), "parents": [expected]})
    new_head = git_sha(update.get("sha"))
    unchanged(gh, expected)
    check_tag(gh, tag, expected)
    # Last remote mutation. A sibling commit cannot be fast-forwarded over a
    # concurrent main advance. Never force or retry on another parent.
    result = gh.api("/git/refs/heads/main", "PATCH", {"sha": new_head, "force": False})
    f.require(result.get("object", {}).get("sha") == new_head, "manifest ref update not confirmed")
    f.require(branch_head(gh) == new_head, "main changed after update; inspect remote state without rollback")
    return new_head


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("repository", "version"):
        parser.add_argument("--" + name, required=True)
    for name in ("bundle", "catalog", "out"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--description")
    parser.add_argument("--created-at", help="UTC LocalDateTime, without Z/offset; default: current UTC")
    parser.add_argument("--publish", action="store_true", help="write to the explicitly selected GitHub repository")
    args = vars(parser.parse_args(argv))
    remote = args.pop("publish")
    try:
        directory, manifest, files = prepare(**args)
        if remote:
            publish(GitHub(args["repository"]), directory, manifest, files)
            print(f"Published selected assets and advanced main/{MANIFEST}; local files: {directory}")
        else:
            print(f"Prepared locally: {directory}. No gh/network calls or remote writes; no runtime claim.")
    except (ValueError, OSError, TypeError, KeyError):
        # Never print exception text from gh or remote responses. Local output
        # and any partial remote writes are deliberately retained on failure.
        print("Publication/preparation failed. Outputs are retained; inspect inputs and remote state before a NEW attempt. No automatic rollback.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
