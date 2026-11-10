# Private JVM observation fragments

`observations.py` is a **partial**, guarded integration, not a release gate or an
evidence generator that accepts caller-authored “passed” flags. It does not change
`freeze.py`, `staging.py`, release/publisher contracts, or production patches.
Use installed Python with `-I -B`; all paths must be explicit and absolute. Keep
real runs in NEW private external `.android-morphe` directories. Inputs, source,
JDK, dependency cache and output must not overlap. Existing output paths, linked
ancestry/reparse points, hardlinks, escaping native references and mutated retained
files fail closed. A failed/partial output is consumed, retained and never reused.

## Supported partial orchestration

The following is a **template**, not a successful final-MPP observation:

```text
python -I -B tools/release/observations.py execute --request ABS_PREEXISTING_FROZEN_REQUEST --bundle ABS_GENUINE_FINAL_MPP --catalog ABS_MATCHING_CATALOG --jdk ABS_INSTALLED_JDK21 --cache-root ABS_PINNED_CACHE --output NEW_EXTERNAL_PRIVATE_DIRECTORY
python -I -B tools/release/observations.py recheck --output EXISTING_PRIVATE_DIRECTORY
```

Execution snapshots the original request bytes **before any observation**, retaining
whitespace and its original SHA-256. It calls the current Plex preflight/schema-2
validator against the actual source tree, metadata and catalog. Numeric schema `2`,
policy `initial-three-patch-collection-v2`, unchanged exact fields/provenance and all
three defaults **true** are mandatory. Legacy requests are not upgraded. A genuine
MPP must already have been built and frozen; this command cannot unblock a failed
Android build. Do not give synthetic MPPs to this CLI or to actual loaders.

The supported execution sequence is:

1. The existing `tools/termius-check/run_jvm_checks.py --scope collection` performs
   fresh uncached source compilation and measured JUnit execution, then compiles
   isolated inspection/Termius tools. The adapter independently revalidates the
   current exact 121 cases/95 source methods, including named parameter expansions,
   retained per-case measurements, five successful producing steps/logs, all
   compiled JARs and output files, selected source hashes, complete source/JDK and
   pinned compiler/runtime/test dependency snapshots. Old aggregate reports,
   Termius-only scope, skips, assumptions, missing/extra/duplicate cases and changed
   measurements do not qualify. Compiler/runtime/test paths must match the closure.
2. The freshly compiled **tools-only** checker runs `InspectBundleKt` against the
   exact final MPP/catalog. Parent classpaths exclude source definitions, tests and
   production patch helpers (the reviewed metadata-projection utilities remain).
   The adapter checks actual loaded, sorted complete patch and
   dependency DTOs, About identity, unsigned metadata and patcher `2.3.0`.
   `android_dex` means the producer's `classes.dex` **magic/unsigned ZIP structure
   check only**, not Android/ART loading, DEX execution or whole-bundle DEX validation.
3. The supported `tools/plex-check/final_bundle.py check` compiles its own tools-only
   checker and executes the exact final MPP. Adaptation requires successful actual
   native execution and invokes the existing `validate_native` against **all 23
   named retained cases**, records, expected/output bytes and rejection diagnostics.
   It additionally validates loaded DTOs, exact compiling/native commands, source
   and input inventories, classpath isolation, native/child/case/call intervals,
   retained paths and logs. Compile-only, failed, partial and aggregate-only results
   are never promoted into resource/final-bundle fragments.

The parser fragment is explicitly **source-tested** by measured
`HermesBytecodeTest` execution from `tests.jar`, **not a parser loaded from the final
MPP**. The final-bundle resource fragment has a different tool/report and covers
loaded `Premium unlock` execution on synthetic, noninstallable HBC96 resources.
That is neither Plex client acceptance nor APKM assembly/runtime support.

Observation timestamps come from actual source/native events and are converted to
**offset-free UTC**, not restamped at adaptation. Events must lie inside their
recorded executing children, be at most seven days old and not future. All five
binding fields are preserved. `staging.observation` is the authoritative fragment
DTO validator; passing a fragment validator is not passing the full staging gate.

## Optional bounded Termius integration

Absent `--termius-selection`, structural execution stays **blocked**, unchanged.
An explicit descriptor enables two additional children after the three above:
fresh canonical `driver.py verify-apks`, then `RuntimeCheckKt`. An invalid,
changed, unsuccessfully verified or stale selection fails the **whole run**, not
just the optional component. There is no policy override or supplied-report mode.

The external UTF-8 JSON descriptor has exactly these fields (all placeholders are
absolute external paths; this is a template, not executed evidence):

```json
{
  "schema": "termius-selected-inputs-v1",
  "archive": "C:/private-inputs/original.apkm",
  "members": [
    {"name": "base.apk", "apk": "C:/private-inputs/selected/base.apk"},
    {"name": "split_config.x86_64.apk", "apk": "C:/private-inputs/selected/split_config.x86_64.apk"},
    {"name": "split_config.mdpi.apk", "apk": "C:/private-inputs/selected/split_config.mdpi.apk"}
  ],
  "aapt2": "C:/reviewed-tools/aapt2.exe",
  "signer_jar": "C:/reviewed-tools/lib/apksigner.jar",
  "provenance": "C:/private-provenance/provenance.json",
  "certificate_dialog": "C:/private-provenance/apkmirror-certificate-dialog.yml"
}
```

`selected_identity.py` fixes the independently reviewed package/version/code,
signer, archive size/digest, exact three member sizes/digests/split identities,
selected Java/aapt2/apksigner payload digests, and the reviewed provenance and
certificate-dialog byte digests. The descriptor contains **paths only**, never
expected pins. Java is the same selected/inventoried JDK as source compilation;
it is not independently selected by this descriptor. Provenance remains an
APKMirror third-party HTTPS listing, **not first-party vendor attestation**.
Payload pins/full JDK consistency do not establish stronger JDK/tool authenticity
or authenticate Windows/system DLLs, the interpreter distribution, or execution.

The helper streams the bounded selected archive members with the canonical ZIP
validation API and requires exact extracted-APK correspondence, without extraction.
Fresh canonical verification consumes all three APK paths (not the APKM), with
fixed independent identity pins and explicit **x86_64/mdpi/en** selection. It must
create a **NEW report file**; RuntimeCheck must create a **nonexistent directory**.
The shared canonical manifest/topology API verifies declared ABI/density type
coverage; language/density selection is not resource/language completeness.

The private `identity-closure.json` binds descriptor/archive/member/APK,
provenance/certificate/tool bytes, complete source/JDK/dependency/interpreter
inventories, exact original request and copy, final MPP/catalog and tools-only
checker classpath. Before either new child, the baseline's file records must
match the already accepted frozen-input records, exact request bytes/copy,
retained checker inventory and inventoried runtime dependencies. A fresh baseline
cannot authorize a persistently replaced MPP, request, catalog or classpath file.
Independent post-use probes run in **finally** after both
children even on nonzero exit or timeout; primary and closure failures are
retained separately. Original ancestry is checked before resolution; case/short
names, dot aliases, hardlinks, duplicate inputs and all Windows reparse categories
are rejected. Inputs/output are not allowed to overlap.

One native validator is used for execution and recheck: exact **3/2/5** changed
method sets and patch-result multiplicity; all **nine distinct singleton negatives**
with expected failing patch/diagnostic and unchanged bounded snapshots; all **19**
deterministic emitted DEX inventories and exact manifest bytes; and the nine
fixture-to-maker/base-payload graph edges. It also checks loaded catalog/dependency
DTOs, explicit owner/prefix/method-data scope, consistent strict integer method
counts, true timing/invocation/classpath data and nonobserved Android fields.
Historical v2 reports, aggregates, PASS text and log summaries cannot qualify.
Output hashes are emitted-DEX-manifest hashes, **not patched APK hashes**.

The five RuntimeCheck arguments are unchanged. The third argument names only
semantic output. Patcher scratch is retained in the deterministic sibling
`termius-structural-work`, still **inside the same NEW external observation run**.
Both directories must be nonexistent before invocation. The native
`work_directory` must match that exact sibling; escaped, substituted or linked
paths fail. The semantic tree still rejects every unreferenced DEX/manifest/APK;
there is no `temporary`-path exclusion. The whole-run artifact index includes all
scratch files as well, and terminal recheck rejects their removal, mutation or
addition. Direct RuntimeCheck callers must retain/index both siblings; see the
[checker contract](../termius-check/README.md). Historical failed runs stay failed.

Its v3 envelope records real start/end/monotonic duration, invocation, work
directory and parent classpath on success/failure after output reservation.
Pre-output argument/path failures have only the parent
child record. **Python preflight is the sole exact-request2 authority**; Kotlin
makes no independent request-validation claim. Shared nine-case negatives are
not nine per selection or combined-negative coverage. Scope excludes debug/class
metadata/fields, whole-APK preservation and Android runtime.

## Deliberately unsupported / blocked

- **Official Manager local import and visual review are unobserved.** There is no
  empty Manager observation to splice into schema-2 evidence. A real unchanged
  official Manager import of the same MPP plus separate genuine visual review
  remains mandatory for staging.
- **Android/ART/Plex client runtime is unobserved.** This command does not provision
  tools, download, access credentials, sign, touch devices or create entitlements.
- No complete schema-2 evidence, staging-ready status, candidate, approval, Git
  operation or publication is emitted. Protected independent review remains
  necessary; source/tool/hash consistency is **not authentication**.

## Private output and rechecks

The terminal record is `partial.json`, schema
`private-jvm-observation-fragments-v1`, `complete_evidence: false`. Even a successful
supported sequence reports **`incomplete-private-fragments-not-staging-ready`**.
Its `fragments` contains inspection and Plex parser/resource/final_bundle pieces,
and optional bounded Termius structural pieces only after fresh verification;
`components` separately explains blocked structural and unobserved Manager/runtime work.
It is intentionally incompatible with full staging evidence. Exit code zero means
only that this supported **partial** sequence and terminal recheck completed.

The record includes actual child argv/start/end/duration/exit/log measurements,
complete input/source/tool snapshots and a private file index (size/SHA-256).
The complete retained output index excludes **only `partial.json` itself**, avoiding
recursive self-hashing. Reports referenced by fragments resolve to actual indexed
files. Before/after checks rehash source, full installed JDK, exact dependencies,
Python, frozen inputs and every previously retained file. Terminal recheck repeats
input preflight, measured-source/native adaptation and full index equality. It is
also available as a read-only CLI; it neither executes a child nor creates missing
evidence. A terminal recheck failure preserves the rejected record as
`partial-rejected.json` and writes a failed `partial.json`. Other failures clear
fragment claims while preserving generated outputs/logs and their private index.

The same-user filesystem is not a sandbox: before/after checks detect retained
changes, not substitutions restored byte-for-byte between endpoints. They do not
provide process/filesystem isolation or authenticate observations against a writer
able to replace every byte and report together. A timeout is failed/non-quiescent:
descendants may still write, so its terminal inventory is not stable-success evidence.
Retain the entire run and exact reviewed source/tools for
protected review, not just a copied JSON fragment. Later source changes correctly
invalidate a request/recheck; obtain a new genuine build/freeze rather than editing
the old request or substituting digests.

## Testing scope

`tests/test_observations.py`, `tests/test_selected_identity.py` and
`tests/test_structural_observations.py` use **synthetic schema files and mocked
children only**. Identity policy replacement occurs only in isolated test-process
monkeypatches, never through a production override. Tests cover descriptor/path/
identity mutation, canonical report topology, exact positive/negative rows, all
19 inventories and nine correspondence edges, finally postchecks, simultaneous
primary/closure failures, timeout consumption, terminal recheck and restored-byte
limitations. Their invalid synthetic MPP/JAR/APK/DEX/resource bytes are never
passed to real loaders.
Positive contract validation is not final-MPP execution. It covers exact request
byte binding, old/failed/aggregate reports, complete cases and loaded DTOs, classpath
contamination, times, mutated retained logs/JARs/DEX/native resources/inputs/tools,
escaping/linked/hardlinked paths, consumed outputs, partial-result honesty and
failure clearing. Existing freeze/Plex integration tests exercise real schema-2
preflight with explicitly synthetic inputs, stopping before any loader.

Real source compilation can separately exercise `verify_source_run`, but neither
that nor tools-only compilation substitutes for a genuine final-MPP run. At this
implementation checkpoint no genuine final Android MPP was available; no actual
inspection, Termius selection, final-MPP Plex native case, Manager import or Android
runtime observation has been made by this integration.
