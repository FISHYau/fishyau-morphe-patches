# Maintainer release handoff

This is an execution checklist, **not an approval, a staged candidate or a claim that the infrastructure exists**. The maintainer must supply the infrastructure and independent human review. Do not replace missing observations with caller-authored success fields. See [promotion policy](promotion.md), [verification](verification.md) and the [Manager source contract](source-contract.md).

## 1. Settle the source and input gates first

- Finish and independently review all source, tests, tooling and documentation changes. Pass Windows and Ubuntu/Linux tests without weakening identity, path, resource or publication checks.
- Preserve exact byte-pinned provenance records and legal files across checkout platforms. Check committed blobs and fresh checkouts, not only clean Git status.
- Confirm the actual release source is a clean, tracked-only committed `main` revision. A digest from a pre-Git tree is not a commit identity.
- Independently verify the authorized Plex archive/signer and exact selected APK set, actual platform eligibility and an observable client acceptance check. The existing TV input must not silently widen the collection's `MOBILE` compatibility. Unsupported input, installation-only evidence, or login-dependent checks without an authorized test arrangement leave runtime blocked.
- Keep the user's accepted Termius behavior separate from new bundle checks and Plex acceptance. Do not reopen that inherited acceptance or extend it to another app.

Do not start short-lived final evidence until the infrastructure below is ready: observations expire after **seven days**, and candidate workflow artifacts are retained for **three days**. Refresh by executing new observations, not by restamping old events.

## 2. Provision the trusted candidate producer

A maintainer, not an untrusted workflow or artifact, must configure:

1. A protected **`candidate-staging`** environment.
2. A dedicated trusted Linux runner with labels **`self-hosted`, `linux`, `morphe-candidate`**. Do not expose this runner to untrusted fork jobs or unrelated credentials/private data.
3. A sanitized registry outside the source checkout. Configure **`MORPHE_CANDIDATE_ROOT`** with its absolute directory and place a reviewed candidate under `ROOT/EXACT_SEAL/`.
4. Set **`MORPHE_CANDIDATE_PRODUCER_READY=true`** only after the runner, environment and registry are verified.

The registry entry must contain exactly these five reviewed files, no private originals:

```text
patches-0.1.0.mpp
patches-list.json
patches-bundle.candidate.json
verification-summary.json
SHA256SUMS
```

The candidate seal is `SHA256(canonical({filename: SHA256(exact bytes)}))` over **all five files, including `SHA256SUMS`**. It is not the MPP digest, source-tree digest, Git commit, private-evidence digest or uploaded artifact archive digest. Obtain it from validated staging; do not invent a placeholder receipt.

`MORPHE_PACKAGES_READ_READY` and the `collection-build` environment control an optional, separately protected collection build. They do not stage, approve or upload the candidate. Do not enable package access by assuming the default Actions token can read the pinned cross-repository packages.

## 3. Provision protected publication

The existing publisher requires actual GitHub settings, not merely an environment name in YAML:

- A **`release`** environment with individual authorized human reviewers, **prevent self-review**, **no administrator bypass**, and a custom deployment policy allowing **only branch `main`**. Unsupported reviewer/rule types fail closed.
- A genuinely independent human: the dispatch actor cannot supply their own approval. A second agent/session is not a second human.
- Supported classic `main` branch protection enforcing administrators and prohibiting force pushes/deletion. Rulesets alone are not supported by this transport. Protections must permit the reviewed publisher's nonforce, manifest-only compare-and-swap; do not disable protections or bypass a mandatory PR/status rule to make it work.
- A maintainer must independently confirm **server-enforced immutable releases** are configured before publication dispatch. Prepare does not verify this setting. The transport checks the release's server-reported `immutable=true` only after publishing the draft; a failure then retains the tag/release/assets as failed evidence and does not advance the discovery manifest.
- A maintainer-provisioned environment secret named **`RELEASE_PUBLISH_TOKEN`**, with repository-scoped **Contents:write**, **Actions:read**, and **Administration:read** access required by the transport. Never paste its value into a command, report, source file or handoff. The default workflow token remains read-only.

If the repository plan, permissions or available independent reviewer cannot satisfy these requirements, stop with the specific blocker. Do not substitute a local `approval.json` or a fabricated reviewer identity.

## 4. Produce fresh, exact-source evidence

Use installed pinned tools and NEW private external output directories throughout. Commands below show interfaces only; `ABS_*`, `NEW_*`, `FULL_COMMIT` and hash/ID placeholders are not real evidence.

1. Build the final clean tree with canonical `driver.py build` and `:patches:test :patches:buildAndroid`. Preserve its real `build.json`, `source.tar`, six collection JUnit suites and final artifacts. A JVM JAR or generic Gradle success log cannot replace an Android MPP/build report.
2. Use `tools/release/freeze.py` to retain the exact final MPP, same-byte catalog and original request. Do not rebuild during publication.
3. Run and recheck actual final-MPP observations, including the verified Termius selections and dedicated Plex checks. `observations.py` intentionally produces partial evidence; successful partial execution is not full staging readiness.
4. Obtain complete same-binding unchanged official Manager observations: local import, collection identity, patch names, untouched UI defaults, compatibility and explicit visual review.
5. Obtain Plex's own resource-aware baseline/patched Android client observations and visual review. Report input/platform/device scope and limitations honestly. Client checks do not grant or prove backend entitlements.
6. Assemble full schema2 evidence from original timed reports and retained bytes, never from a sanitized summary. Preserve historical failed/partial records.
7. Stage and validate the five sanitized files:

```text
python -I -B tools/release/staging.py stage --source-root ABS_CLEAN_SOURCE --bundle ABS_MPP --catalog ABS_CATALOG --request ABS_ORIGINAL_REQUEST --evidence ABS_COMPLETE_EVIDENCE --output NEW_EXTERNAL_CANDIDATE
python -I -B -c "import runpy,sys; p=runpy.run_path('tools/release/publisher.py'); print(p['candidate'](sys.argv[1])[2])" NEW_EXTERNAL_CANDIDATE
python -I -B tools/release/candidate.py validate --candidate ABS_CANDIDATE --source-root ABS_CLEAN_SOURCE --candidate-sha256 EXACT_SEAL --source-revision FULL_COMMIT
```

Use the seal printed by the middle command as `EXACT_SEAL` for the final validation command; `ABS_CANDIDATE` names that same `NEW_EXTERNAL_CANDIDATE` directory. Seal calculation validates the five-file candidate but is not approval or a substitute for committed-source validation.

An honestly blocked/not-observed Plex runtime can be represented where staging permits it, but **publication rejects it**. The current [original-evidence assembler](../tools/release/evidence.README.md) supports only those honest nonobserved Plex states, using unchanged partial observations and a complete original [Manager capture/review session](../tools/manager-check/README.md). It does not implement step 5's vendor runtime producer or a publishable observed-runtime adaptation; those require separately reviewed implementation and genuine new observations before release completion. Missing mandatory Manager/structural evidence still blocks staging itself. Inspect all five candidate files for public safety before copying them to the registry.

Do not edit source, tests, workflows or documentation after establishing the final binding. Any such change requires a new build/freeze/observation binding. Keep receipts/status outside the source tree. The publisher's final manifest-only commit is the intentional exception.

## 5. Produce an immutable candidate receipt

The maintainer dispatches `verify.yml` on exact `main`, **first attempt**, with:

```text
produce_candidate=true
candidate_sha256=EXACT_SEAL
```

The dispatch, workflow revision and clean checkout must all bind the same full source commit. The producer copies already staged bytes; it does not build or approve them.

Wait for the **whole run to succeed**, not merely the upload step. Retain the actual:

- `source_commit`
- `candidate_sha256`
- `artifact_run`
- `artifact_id`
- `artifact_sha256` (action-returned uploaded archive digest)

No latest/name-only artifact lookup, rerun, expired artifact, substitute archive or failed-run fallback is acceptable. Preserve failures; a separately reviewed attempt needs a fresh run rather than reusing the failed output.

## 6. Prepare, independently review, then publish

Use `release.yml` on exact `main` with the following binding; begin with **`mode=prepare`**:

```text
target=FISHYau/fishyau-morphe-patches
version=0.1.0
candidate_sha256=EXACT_SEAL
artifact_run=ACTUAL_SUCCESSFUL_RUN_ID
artifact_id=ACTUAL_ARTIFACT_ID
artifact_sha256=EXACT_UPLOADED_ARCHIVE_SHA256
source_commit=FULL_COMMIT
```

Prepare validates the real server artifact, origin, source and exact candidate bytes with read-only credentials. A successful prepare is **not** evidence authentication or proof that all remote publication prerequisites are configured.

The independent human reviews the original private evidence, migration provenance and exact dispatch binding. For the corresponding publish run, the environment approval comment must be exactly:

```text
evidence-policy-reviewed binding-sha256=EXACT_DISPATCH_BINDING_SHA256
```

Use the exact `required_review_comment` JSON field printed in the prepare job log, containing the dispatch-binding digest—not the candidate seal or archive digest. Dispatch **`mode=publish`** with the same exact binding and obtain the authenticated protected approval. Do not change source/artifacts/head or rebase an approval.

The existing publisher reserves a new release/tag, uploads the five approved files without rebuilding, finalizes server-enforced immutability, publicly downloads and compares every asset, rechecks source/candidate/review/head, then advances **`main/patches-bundle.json` last** with a nonforce manifest-only compare-and-swap. Conflicts and partial failures stop; do not overwrite, force, delete evidence, rollback automatically or point a manifest at an unavailable asset.

## 7. Verify actual hosted behavior

After successful hosting, separately observe unchanged official Manager discovering the ordinary GitHub source, downloading/loading the exact advertised bundle and handling updates. Local import, HTTP availability, compilation and installation alone do not establish this result.

## Keep private

Never upload vendor APK/APKM/DEX, signing material, account data, raw reports/logs/screenshots, machine paths or failed outputs. Only the reviewed sanitized five-file candidate and the final public discovery manifest belong in distribution. Authentication and provenance limitations must remain visible; hash consistency is not human approval.
