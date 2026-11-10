# Private official Manager import observations

`manager_import.py` is a bounded capture helper for unchanged **Morphe Manager 2.5.0**, not an app patcher, release approver or hosted-source test. Run trusted source with `python -I -B`. It reuses the canonical owned-emulator harness and installed tools. It downloads/provisions nothing and does not grant device/build permission. Review code and synthetic tests before execution; workspace standing permission, where applicable, remains scoped to NEW tooling-owned disposable runs.

## Explicit inputs

Use absolute canonical paths, NEW private external runtime/output roots, and the original schema2 frozen request, exact MPP and same-byte catalog. Never place APKs, captures, logs, signing material or private config in the source checkout. An input path, byte pin or report is not authenticated execution or approval.

The external JSON config has exactly:

```text
schema: manager-capture-config-v1
source_root: ABS_THIS_SOURCE_CHECKOUT
request: {path: ABS_ORIGINAL_REQUEST, sha256: EXACT_REQUEST_BYTES_HASH}
bundle: {path: ABS_MPP, sha256: EXACT_MPP_HASH}
catalog: {path: ABS_CATALOG, sha256: EXACT_CATALOG_HASH}
manager_apk: {path: ABS_OFFICIAL_MANAGER_APK, sha256: FIXED_MANAGER_HASH}
tools:
  sdk: {path: ABS_INSTALLED_SDK, inventory_sha256: EXACT_INVENTORY_HASH}
  jdk: {path: ABS_INSTALLED_JDK, inventory_sha256: EXACT_INVENTORY_HASH}
  python: {path: ABS_EXECUTING_PYTHON_BASE_PREFIX, inventory_sha256: EXACT_INVENTORY_HASH}
verification:
  aapt2: ABS_INSTALLED_AAPT2
  java: ABS_JDK_BIN_JAVA
  signer_jar: ABS_INSTALLED_APKSIGNER_JAR
image: system-images;android-30;google_apis;x86_64
```

This is a field template, not runnable JSON or real evidence. All tool paths must belong to their pinned closures; Python must match the executing runtime. Tool inventory is the relative POSIX file path map to `{size, sha256}` produced by `inventory(root)`. Its pin is `inventory_hash(map)`: SHA-256 of UTF-8 `json.dumps(map, sort_keys=True, separators=(',', ':'))`. Compute these from reviewed installed tools before config creation. No inventory may be replaced by a directory name or presence-only claim. SDK/JDK/Python files are rehashed across operations.

The fixed Manager APK SHA-256 is `681a1c179b9e8698c857a092df0ca9a91e294a103743107f4fe96da20cb42ddc`, package `app.morphe.manager`, version `2.5.0`, code `39909503`, certificate SHA-256 `0b6c9515afb195fac59601696ba0a7907a0b217ccf720b43148427ccf64343e7`. Provenance is the observed official HTTPS release identity, **not independently pre-established signer trust**. Fresh canonical APK signature/identity verification precedes installation; installed APK-byte readback remains unperformed.

## Operation sequence

Common flags precede the subcommand:

```text
python -I -B tools/manager-check/manager_import.py --root NEW_OR_OWNED_EXTERNAL_ROOT --config ABS_CONFIG --expect-config-sha256 CONFIG_HASH --label NEVER_REUSED_LABEL COMMAND
```

1. `init` validates source/input/tool binding and exclusively stages the exact bundle in a NEW root.
2. `create`, `start`, `isolate`, `install`, `push`, `launch` each use distinct evidence labels. The helper restricts the installed image and Manager identity; it does not choose/download alternatives.
3. Navigate the actual UI, capturing before/after states. `capture --purpose PURPOSE` uses one of `local-import`, `collection-identity`, `patch-names`, `defaults-untouched`, `compatibility`, `navigation`. Purpose labels describe intended evidence, not semantic proof.
4. File selection uses `picker-tap X Y` or `picker-key CODE` (23/66/160). Immediately after owned-device verification, these recheck the remote bundle hash and original/staged host bytes before the actual action. `navigate-key CODE` is restricted to nonactivation keys 4/19/20/21/22/61. There is no general unguarded tap/key or private activity-result injection.
5. `remote-check` and `final-check` retain bounded hash checks; they do not establish UI correctness. Run the terminal `final-check` after all captures and navigation, immediately before the stop/report phase. A missing or pre-capture final check does not establish a complete observation session.
6. `stop` uses canonical ownership/shutdown verification. Success requires the exact process exited and both owned console/transport ports released. No global cleanup, kill fallback or AVD deletion is implemented. Stop can use anchored session/tool paths after application/config input loss, but still rechecks all saved SDK/JDK/Python pins and original tool ancestry. This reduced closure is cleanup only, never release evidence. The single kill reservation follows successful ownership verification; after dispatched/uncertain shutdown, subsequent calls can only confirm the exact process and both ports read-only, never dispatch another kill.
7. `report` creates an original private report snapshot; without a separate original visual review, all UI checks remain pending. Reports are snapshots and do not rewrite original capture events.

Do not reuse a failed operation label or fresh-output directory. Retain failures, including cleanup failures, separately. If ownership or shutdown cannot be verified, stop and ask; never target shared/preexisting devices or emulator04.

## Original evidence and separate visual review

Each event retains actual UTC microsecond start/end times, monotonic duration, five-field request/MPP/catalog/source binding, source/tool closures, device identity and immutable file hashes. Post-operation closure/config checks also run on failure, retaining their errors separately from the original action error. Startup evidence hashes a bounded immutable log-prefix snapshot, not the growing emulator log. Captures retain actual PNG/XML bytes, hashes and `pending-separate-original-review`; no capture automatically passes defaults, compatibility or features.

A collected report requires the original ordered same-device lifecycle, install/verification artifacts, guarded actions, captures, final-check and confirmed shutdown. Purpose-only capture records or human checks without that graph are insufficient. `validate_graph()` exposes original lifecycle/capture time bounds; `recheck_report()` validates unchanged original snapshots, their referenced events and separate review bytes without regenerating a report. Older/incomplete record shapes fail closed rather than being migrated or restamped.

A separate external review uses `schema=manager-original-visual-review-v1`, exact `binding`, actual `reviewed_at`, a nonempty `reviewer_claim`, a `captures` map containing the exact producer-derived references, and a `checks` map with exactly:

- `local_import`
- `collection_identity`
- `patch_names`
- `defaults`
- `compatibility`
- `visual_inspection`

Each check has `{status, captures, notes}`. Status is `observed`, `not-observed` or `blocked`; notes must describe the bounded original observation. Observed checks require separately inspected original PNG/XML references and the appropriate purpose (notably `defaults-untouched` and `compatibility`). Verify untouched selection state and every advertised compatibility field in the actual UI; importing the bundle or observing patch titles does not establish either. Do not write an observed check without seeing the relevant images. The reviewer identity is explicitly an **unauthenticated local claim**, not protected GitHub approval.

Provide that exact review with `report --review ABS_REVIEW --expect-review-sha256 REVIEW_HASH`. `manager-report-v1` retains `complete_evidence:false`; even complete local claims yield only `originals-collected-not-release-approval`. `assembled_at` is report assembly time, **not a substitute for original observation/review times**. Original reports/captures/reviews must be revalidated by the separate release evidence adapter before staging.

## Scope and limits

Synthetic tests do not operate an emulator or execute Manager. This helper has not by itself established a new real Manager import. Original report consistency is not authenticated truth: source/config/report files remain locally author-controlled. No backend entitlements, app feature behavior, hosted discovery/download/update, persistence or broad device compatibility is inferred. A separate independent human must review original private evidence and the exact protected publication binding. See [verification status](../../docs/verification.md) and [maintainer handoff](../../docs/release-handoff.md).
