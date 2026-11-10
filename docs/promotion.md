# Verified preparation and publication

## Initial accepted sources

The first collection includes exactly:

- **Server Auditor Offline Automation**, default **on**.
- **Server Auditor Premium**, default **on**.
- **Premium unlock** (Plex), default **on**.

The two Server Auditor patches are limited to `com.server.auditor.ssh.client` **8.0.1/code1008**, APKM. The user confirmed both as **tested and working on 2026-11-09**. Treat that as accepted existing behavior; do not reopen it as an outstanding feature test. Do not represent it as a new observation for a different bundle, rewritten historical result, or authenticated GitHub reviewer approval.

The donor behavior migration preserves algorithms, guards, descriptions and compatibility, with focused namespace/helper adaptations. Separately, the user's explicit **2026-11-09** request enables both Termius patches by default: Premium changes false to true, while Offline Automation and Plex remain true. This default-only adaptation and current exact source hashes are recorded in [termius-migration.json](termius-migration.json). Algorithm changes or new compatibility require new review/acceptance. Offline Automation retains its **select-alone** recommendation; structural co-selection checks, if passed, do not establish combined feature behavior. No Universal or SpotifyTV patch belongs in this collection.

Plex retains the supplied **package-scoped version-unpinned** APKM compatibility for `com.plexapp.android`, with Hermes v96/function/signature checks at execution. This is not a Universal patch or evidence that every Plex version works. It is a raw-resource patch, with optional decoded-text manifest cleanup, so the generic bytecode-only apply/assembly path remains unsupported for it. Use dedicated resource/Hermes checks and the actual final collection bundle; do not present DEX-only verification as Plex verification.

The user's Termius confirmation **does not cover Plex**. Historical Plex notes are provenance, not new final-artifact runtime acceptance. Its source/tests may be included during preparation, but publication must not inherit a tested/working claim from the Termius patches or substitute the supplied prebuilt donor MPP for a fresh collection build. See [plex-migration.json](plex-migration.json).

## Separate the evidence

1. **Inherited behavior acceptance**: the user’s named confirmation, bound to original/migrated file hashes and the donor behavior migration record, with the separately documented user-requested default-only adaptation.
2. **New source/build evidence**: migrated validator and inventory tests, official `buildAndroid`, exact MPP/catalog metadata and dependency inspection.
3. **New target-patcher checks**: actual load/apply/emit/re-read and negative cases on that final bundle; report bounded method/class comparison scope accurately.
4. **New Android distribution evidence**: unchanged official Morphe Manager locally imports that same MPP and displays all three definitions, defaults, finite Termius compatibility and package-scoped unpinned Plex compatibility; private UI/log/image evidence reviewed explicitly.
5. **Protected publication review**: an authorized human authenticates evidence provenance and approves the exact source and immutable package.
6. **Hosted-source evidence**: actual GitHub-link discovery, download/load and update, only after separately authorized hosting.

A JVM loader result or DEX header is not Android import. A local import is not a remote-source test. Mock publication tests establish control flow, not successful hosting. All APK/DEX/MPP/build/cache/signing/private evidence stays outside the source checkout. Public summaries must not contain vendor code, account details, credentials, private screenshots or machine paths.

## Versioned staging, not invented release evidence

The original **release-v1** validator remains strict: exact committed source, fresh exact-artifact structural/runtime reports and protected reviewer input. Do not fabricate those fields to make an uncommitted checkout pass.

The separately versioned collection staging policy must support a truthful **`staged-not-published`** pre-Git candidate, with an explicit three-patch policy rather than silently widening release-v1's finite compatibility. It records accepted existing Termius behavior separately from measured final-artifact checks and Plex's own resource/runtime evidence. Current `initial-three-patch-collection-v2` requires exactly three defaults true and the reviewed default-adapted Premium hash/provenance. The older two-Termius staging contract deliberately retains its historical Premium=false default and is not sufficient for this collection. A staged package contains the same validated MPP/catalog bytes, candidate manifest, checksums and sanitized provenance/status. It must not invent a commit, reviewer, runtime success or live root discovery manifest.

See `tools/release/` contract/CLI documentation, [verification status](verification.md), and the [maintainer release handoff](release-handoff.md) for the implementation’s actual tested capabilities and outstanding prerequisites. Local file digests before Git initialization are not a clean release revision. Evidence freshness and bindings must be renewed if source/artifact/selection changes; do not combine one bundle’s result with another bundle’s hash.

## Existing-candidate producer (source-only integration)

`tools/release/candidate.py` closes only the transport-source gap: it validates an **already staged** current schema2 five-file candidate, and optionally freezes those exact bytes in a **NEW external directory**. It does not build, execute donor code, generate reports, authenticate observations, contact GitHub, sign, publish, or advance the live manifest. It reuses `publisher.candidate()`, current collection inventory/provenance policy, `release.source_tree()` and, when requested, `clean_revision()`; no existing publication gate is relaxed.

Local interfaces (run Python isolated, with bytecode caches disabled):

```text
python -I -B tools/release/candidate.py validate --candidate STAGED_DIR --source-root PRISTINE_ROOT --candidate-sha256 EXACT_SEAL
python -I -B tools/release/candidate.py snapshot --candidate STAGED_DIR --source-root PRISTINE_ROOT --candidate-sha256 EXACT_SEAL --output NEW_EXTERNAL_DIR
```

For an actual committed checkout, add `--source-revision ACTUAL_FULL_LOWERCASE_COMMIT`. Omission permits truthful pre-Git preparation and emits no invented revision; **CI always requires the actual `github.sha`, exact HEAD and a clean tracked-only Git root**. Validation checks the current source-tree digest, exact three names/defaults/compatibility, MPP metadata, sanitized summary, pinned provenance and exact seal. It rejects missing/extra files, linked inputs/ancestors, hard-linked source/candidate files and overlapping output/input/source/repository paths. Source and candidate are rehashed before and after copying; snapshot bytes are read back and compared. Only the frozen five existing files are copied, with exclusive creation. A failed/partial output is retained as failed evidence: do not overwrite, reuse it or rerun a failed Actions attempt. Allocate a new external destination for any separately reviewed subsequent operation.

The seal is `SHA256(canonical({filename: SHA256(exact bytes)}))`, **including `SHA256SUMS`**, using the canonical JSON encoding in `release.py`. `SHA256SUMS` itself lists the other four files. It is not the MPP digest, source-tree digest, Git revision, private-evidence digest or workflow archive digest. The expected seal must be supplied explicitly from reviewed staging; the producer never searches for a latest candidate or silently derives an approval from whatever happens to be present.

The `verify.yml` producer is a **separate opt-in `candidate` job**, depending only on offline tests, not the collection build. Ordinary pushes/PRs and the default manual dispatch cannot reach it. It requires all of:

- Exact `FISHYau/fishyau-morphe-patches` main `verify.yml` manual dispatch, `produce_candidate=true`, first run attempt, and workflow/source revision equality.
- Maintainer-configured `MORPHE_CANDIDATE_PRODUCER_READY=true`, a protected `candidate-staging` environment, and a dedicated trusted **self-hosted Linux `morphe-candidate`** runner. No runner or environment is created/configured by this source change. Do not assign this runner to untrusted fork jobs; isolate it and keep unrelated credentials/private material off it.
- A protected configuration variable `MORPHE_CANDIDATE_ROOT` holding an existing absolute **external** registry directory. Stage the reviewed sanitized candidate at `MORPHE_CANDIDATE_ROOT/EXACT_SEAL/`, exactly five root-level files. Do not store raw reports, APKs, screenshots, logs or credentials there. The dispatch accepts only the lowercase hex seal, never arbitrary paths, URLs or commands. Treat this registry and runner configuration as trusted maintainer inputs, not evidence authentication.
- A clean checkout pinned to `github.sha` with no persisted checkout credential. The job has only `contents:read`, no package/publish credential, no build steps and no automatic release dispatch. The existing independently gated collection job is unchanged; its optional build neither produces nor approves this candidate.

Python creates a fresh private snapshot under `RUNNER_TEMP`, outside checkout and candidate registry, and exports only its safe path, seal and real source commit through `GITHUB_OUTPUT`. The pinned `actions/upload-artifact` **v4.6.2** uploads exactly `patches-0.1.0.mpp`, `patches-list.json`, `patches-bundle.candidate.json`, `verification-summary.json`, and `SHA256SUMS` as **`release-candidate-0.1.0`**, with overwrite disabled, missing-files failure and three-day retention. Candidate dispatches use a distinct per-run concurrency group and cannot be cancelled by the ordinary workflow's cancel-in-progress policy. Reruns cannot run the candidate job. Failed/expired candidates are not fallback sources.

The successful upload step reports the **actual run ID, action-returned artifact ID and archive SHA256**, separately from the candidate seal and actual source commit, in job outputs and the run summary. There are no offline placeholder IDs/digests. Before handoff, require the **whole trusted verification run to finish successfully**; `github_transport` independently fetches and verifies run/artifact origin, first attempt, success, archive digest and exact candidate bytes. A producer upload alone is not publication or remote-source discovery/update verification.

**Candidate-producer status: implemented and synthetic-offline tested, not provisioned or observed live.** Source publication is recorded separately in [verification status](verification.md); a public source commit alone is not a release candidate. The final exact clean revision, protected runner/environment/configuration, complete original evidence, genuinely staged candidate and successful trusted artifact-producing run remain prerequisites. No actual candidate upload is claimed. Hash binding and report completeness are **not authenticated observations**. The producer does not reconstruct original request/evidence from a summary or renew observation timestamps; publication independently rechecks freshness. Original private evidence remains mandatory at staging/protected human review. Plex `blocked`/`not-observed` is preserved byte-for-byte and may be prepared, but publication still requires its own fresh observed Android runtime evidence and authenticated protected approval. Catalog/manifest descriptions are existing reviewed public content, not an automatic privacy classifier; maintainers must review all five staged files before placing them in the sanitized registry.

## Future publication handoff

Publication is a **separate authorized action**, not a side effect of this preparation task or a passing CI build. Ordinary pushes/PRs never publish. A safe manual handoff defaults to prepare/dry-run and requires:

- Explicit target **`FISHYau/fishyau-morphe-patches`**, version and publication mode.
- An immutable candidate artifact/run identifier and digest, exact clean source revision, and corresponding source availability.
- Authenticated protected human review of the original evidence and exact candidate. Caller-authored approval JSON is not authentication; naming an environment in YAML does not configure its protection.
- Least-privilege credentials confined to the trusted publication job; never fork PRs or `pull_request_target` code.
- No rebuild. Upload approved asset bytes, download and re-hash them, then advance `main/patches-bundle.json` **last**.
- Failure on changed source/artifacts/approval, an existing conflicting release or a concurrent branch change. No force updates, implicit approval rebasing or fallback to an older artifact.

The public source repository now exists; this does not provision the candidate/release infrastructure. The maintainer handoff still requires real protected environments/runner settings, appropriately scoped access and independent human review. Final source/artifact binding and every missing prerequisite must be verified explicitly, not encoded as a fake passing attestation.

The intended initial asset is `releases/download/v0.1.0/patches-0.1.0.mpp`; the ordinary discovery endpoint is `main/patches-bundle.json`. Do not expose an empty or unavailable asset through a placeholder live manifest. Unsigned MPPs must not advertise a signing key. See [source contract](source-contract.md) for the exact Manager manifest fields and offset-free UTC timestamp format.
