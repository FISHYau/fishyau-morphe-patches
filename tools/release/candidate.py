#!/usr/bin/env python3
"""Read-only validation / NEW external snapshot of an already staged candidate.

No build, donor execution, evidence creation, authentication, network or release.
CLI: candidate.py validate|snapshot --candidate DIR --source-root ROOT
       --candidate-sha256 SHA [--source-revision ACTUAL_FULL_COMMIT]
       [--output NEW_EXTERNAL_DIRECTORY]  # snapshot only
     candidate.py ci  # protected runner configuration + exact seal, no paths from dispatch

Report completeness and hashes are not authenticated observations. Original
private evidence is still required by staging and protected human review. Plex
runtime blocked/not-observed is preserved, never promoted to publication approval.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile

_spec = importlib.util.spec_from_file_location("candidate_publisher", Path(__file__).with_name("publisher.py"))
p = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(p)
s, r = p.s, p.r

# Only the sanitized, fixed narratives emitted by current staging are accepted.
# No caller-authored paths, review claims, logs or free-form evidence here.
TRUST = "Private report completeness and exact hash binding, not authenticated observations. Termius acceptance is not Plex runtime acceptance; unpinned package compatibility is not all-version proof."
REMAINING = ["actual clean source commit", "immutable approved candidate artifact", "authenticated protected human evidence review",
             "configured protected release environment", "real upload/download/rehash and manifest-last CAS", "live GitHub source discovery/update not hosted or observed"]


def unlinked(path):
    """Check lexical ancestors before resolving, including Windows junctions."""
    path = Path(path).absolute()
    r.require(all(not r.linked(part) for part in (path, *path.parents)), "linked path/ancestor forbidden")
    return path


def separate(left, right):
    left, right = Path(left).resolve(), Path(right).resolve()
    r.require(not left.is_relative_to(right) and not right.is_relative_to(left), "candidate/output must be external and disjoint from source, repository and inputs")


def inputs(directory, source_root):
    directory, source_root = unlinked(directory), unlinked(source_root)
    separate(directory, source_root)
    separate(directory, r.REPO_ROOT)
    # publisher rejects symlinks; also reject regular-file hard links.
    for name in p.FILES:
        path = directory / name
        r.require(not r.linked(path), "linked candidate input forbidden")
        r.require(path.is_file() and path.stat().st_nlink == 1, "unlinked regular candidate file required")
    return directory, source_root


def checked(directory, source_root, expected_seal, source_revision):
    directory, source_root = inputs(directory, source_root)
    files, summary, seal = p.candidate(directory)
    r.require(summary["schema"] == 2 and summary["policy"] == s.COLLECTION_POLICY, "current schema2 three-patch staging required")
    r.require(seal == expected_seal, "expected candidate seal mismatch")
    r.require(summary["trust"] == TRUST and summary["remaining"] == REMAINING, "sanitized staging narratives required")
    tree, paths = r.source_tree(source_root)
    r.require(tree == summary["binding"]["source_tree_sha256"], "same current source tree required")
    s.collection_provenance(summary["inherited_behavior"], paths)
    for name in paths:
        r.require((source_root / name).stat().st_nlink == 1, "hard-linked source input forbidden")
    if source_revision is not None:
        r.clean_revision(source_root, source_revision, paths)
    return files, summary, seal


def validate(directory, source_root, expected_seal, *, source_revision=None):
    """No writes; optional revision is a real expected HEAD, never synthesized."""
    r.sha(expected_seal)
    if source_revision is not None:
        r.revision(source_revision)
    frozen = checked(directory, source_root, expected_seal, source_revision)
    again = checked(directory, source_root, expected_seal, source_revision)
    r.require(dict(frozen[0]) == dict(again[0]), "candidate changed during validation")
    return frozen


def snapshot(directory, source_root, expected_seal, output, *, source_revision=None):
    """Copy only frozen validated bytes; failures stay in place, never reused."""
    files, _, seal = validate(directory, source_root, expected_seal, source_revision=source_revision)
    output = unlinked(output)
    separate(output, directory)
    # new_output also enforces nonexistent output and an existing unlinked parent.
    destination = r.new_output(output, source_root)
    for name, data in files.items():
        with (destination / name).open("xb") as handle:
            handle.write(data)
    after, _, _ = validate(directory, source_root, expected_seal, source_revision=source_revision)
    copied, _, copied_seal = validate(destination, source_root, expected_seal, source_revision=source_revision)
    r.require(dict(files) == dict(after) == dict(copied) and copied_seal == seal, "snapshot/source changed")
    return destination


def ci(environment=None):
    """Dispatch supplies only a seal. All paths are trusted runner configuration."""
    env = dict(os.environ if environment is None else environment)
    r.require(all(env.get(key) == value for key, value in {
        "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REPOSITORY": s.TARGET, "GITHUB_REF": "refs/heads/main",
        "GITHUB_WORKFLOW_REF": s.TARGET + "/.github/workflows/verify.yml@refs/heads/main",
        "GITHUB_JOB": "candidate", "GITHUB_RUN_ATTEMPT": "1",
        "PRODUCE_CANDIDATE": "true", "MORPHE_CANDIDATE_PRODUCER_READY": "true",
    }.items()), "trusted opt-in first-attempt main candidate context required")
    revision = env.get("GITHUB_SHA")
    r.revision(revision)
    r.require(env.get("GITHUB_WORKFLOW_SHA") == revision, "workflow/source revision mismatch")
    seal = r.sha(env.get("CANDIDATE_SHA256"))
    locations = {}
    for key in ("MORPHE_CANDIDATE_ROOT", "GITHUB_WORKSPACE", "RUNNER_TEMP", "GITHUB_OUTPUT"):
        value = r.text(env.get(key), "runner path")
        r.require(Path(value).is_absolute(), "absolute runner paths required")
        locations[key] = unlinked(value)
    root, source, temporary, output = (locations[k] for k in ("MORPHE_CANDIDATE_ROOT", "GITHUB_WORKSPACE", "RUNNER_TEMP", "GITHUB_OUTPUT"))
    r.require(root.is_dir() and temporary.is_dir(), "configured candidate root and runner temp required")
    for other in (source, r.REPO_ROOT, root):
        separate(temporary, other)
    separate(root, source)
    separate(root, r.REPO_ROOT)
    for other in (source, r.REPO_ROOT, root):
        separate(output, other)
    r.require(output.is_file() and output.stat().st_nlink == 1, "runner output file required")
    # Validate before allocating anything. No retry/fallback to a different seal.
    directory = root / seal
    validate(directory, source, seal, source_revision=revision)
    run = Path(tempfile.mkdtemp(prefix="morphe-candidate-", dir=temporary))
    destination = snapshot(directory, source, seal, run / "candidate", source_revision=revision)
    # GitHub's line protocol: fixed keys; path controls were rejected above and
    # tempfile suffix is generated locally, not interpreted from workflow inputs.
    r.text(str(destination), "snapshot output path")
    with output.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(f"path={destination}\ncandidate_sha256={seal}\nsource_commit={revision}\n")
    return {"status": "snapshotted-not-published", "candidate_sha256": seal, "source_commit": revision,
            "evidence_authenticated": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("ci")
    for name in ("validate", "snapshot"):
        command = commands.add_parser(name)
        command.add_argument("--candidate", type=Path, required=True)
        command.add_argument("--source-root", type=Path, required=True)
        command.add_argument("--candidate-sha256", required=True)
        command.add_argument("--source-revision")
        if name == "snapshot":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "ci":
            result = ci()
        else:
            kwargs = dict(source_revision=args.source_revision)
            if args.command == "snapshot":
                snapshot(args.candidate, args.source_root, args.candidate_sha256, args.output, **kwargs)
            else:
                validate(args.candidate, args.source_root, args.candidate_sha256, **kwargs)
            result = {"status": "snapshotted-not-published" if args.command == "snapshot" else "validated-not-published",
                      "candidate_sha256": args.candidate_sha256, "source_commit": args.source_revision,
                      "evidence_authenticated": False}
        print(json.dumps(result, sort_keys=True))
    except (r.ReleaseError, OSError, ValueError, TypeError, KeyError):
        # Do not echo private configured paths or arbitrary input content into CI.
        print("Candidate blocked: validation or snapshot failed; retain failed outputs, do not retry/reuse.", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
