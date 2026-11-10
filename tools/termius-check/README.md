# Scoped JVM tooling

The reviewed three-patch collection build/test and authorized final-bundle,
Manager and runtime checks have ongoing user approval recorded in the workspace
`CLAUDE.md` on **2026-11-09**. Earlier Plex compile/test and Termius test-JAR
rerun denials were respected and remain historical facts; that renewed scoped
approval supersedes them, not a new tool-enforced denial. Scope selection is not
permission. Git, publication, credential retrieval, unrelated apps and existing
devices are outside that approval.

## Current evidence (2026-11-10)

Official Android **build10** passed **121 Gradle cases**; **freeze06** retained the exact MPP and same-byte catalog. **Observations06** completed bounded final-MPP loading, 23 synthetic noninstallable Plex resource cases and Termius three-selection structural checks, but remain `complete_evidence:false` / `incomplete-private-fragments-not-staging-ready`. The later private workspace-relative `.android-morphe/manager-source-import-runtime-02/LOCAL-IMPORT-RESULT.md` records successful local import into unchanged official **Morphe Manager 2.5.0**: **FISHYau android patches**, version **0.1.0**, **3 patches**, **2 apps** and all three intended titles, with separately reviewed PNG/XML and byte bindings. This establishes local loading/inventory, not Manager patch execution, Android-UI selection defaults or app feature behavior. The generation-time observations06 import `not-observed` field remains unchanged. Hosted discovery/download/update, Plex Android acceptance, complete staging and protected release review remain incomplete; existing Termius acceptance stands.

Build10/freeze06 bind the prior exact tree, not this source update, which also includes a separate `.gitattributes` byte-preservation fix. No binary rebuild is required merely for source commit/push; do not certify the retained MPP as built from the updated tree. A future exact-tree release requires new matching build/freeze/observation bindings. See [verification](../../docs/verification.md) for hashes, qualifications and historical failures.

### Earlier checkpoints — historical where superseded above

**Historical collection JVM evidence:** outside `repo/`, workspace-relative
`.android-morphe/collection-readiness-jvm-06/jvm-checks.json` and `junit.log` record
uncached JVM17 compilation of the then-current definitions, tests and isolated
checker/catalog adapters, with **121 passing JUnit cases**: 39 Automation, 27
Premium, 9 Termius inventory, 18 Hermes parser, 17 Plex resource and 11 collection
inventory/projection. Independent review verified its 23 source hashes, three
JARs and pinned installed tools/dependencies at that checkpoint. The checker has
since changed; JVM-06 does not validate the current checker. Failed JVM attempts
01–05 remain failures; JVM-04's earlier Termius-only result is separate.

**Newer tools-only evidence:** the identity-before-use integration and four
review repairs were independently verified. In workspace-relative
`.android-morphe/termius-identity-final-review-lcfocc7n/`, tools-only JVM17 checker
compilation and **13 native synthetic snapshot/collection regressions** passed.
Checker SHA-256: `6635c2fd6846e59ab826318f8140d1d5ad1be366cf60bbb0b51e3a6053acd1ca`.
Python checks passed **359 repository tests**, canonical **464 run / 463 passed /
1 skipped**, **9 scaffold tests** and **136-file policy**. Counts overlap. These
results predate this documentation update; they are not a fresh collection JUnit
run, actual final-MPP check or Android runtime evidence.

**Historical actual-artifact checkpoint (then-pending gates):** official Android build04 passed 121 Gradle tests
and produced a genuine MPP and same-byte catalog; isolated inspection passed.
Its final-MPP Plex sequence failed one binary-manifest fixture case and remains
failed despite a separately reviewed fixture repair. Build05 failed during
settings-plugin application with a missing username provider; no new MPP,
catalog, JUnit XML, freeze02 or observations02 resulted. Earlier builds01–03
remain failures. Main's resumed pinned registry probe succeeded for only the
settings-plugin 2.1.0 marker and implementation POMs, without recording credential
values; it does not prove access to all build dependencies. A fresh build/freeze
of changed source and actual final-MPP checks are pending. Manager import,
vendor Android runtime and complete staging remain unobserved; partial evidence
remains `complete_evidence:false`. See [verification](../../docs/verification.md).

## Inventory and execution scopes

The final collection has exactly three independent, option-free definitions:

| Name | Default | Type | Compatibility |
| --- | --- | --- | --- |
| Server Auditor Offline Automation | true | BytecodePatch | `com.server.auditor.ssh.client`, APKM, 8.0.1 / version code 1008 for all four supported ABIs |
| Server Auditor Premium | true | BytecodePatch | same finite Termius target |
| Premium unlock | true | RawResourcePatch (RAW, not decoded resources) | `com.plexapp.android`, APKM, deliberately empty catalog targets / version-unpinned |

Both Termius defaults are true per the explicit **2026-11-09** user request.
Premium's false-to-true metadata adaptation is separate from donor behavior
migration; algorithms/guards/compatibility are unchanged. `verify_migration.py`
allows only that exact declaration change in Premium, in addition to the reviewed
namespace/import changes. Original hashes remain pinned; migrated hashes include
the adaptation. Default co-selection is not combined Android runtime acceptance.
Offline Automation's select-alone guidance still means explicitly deselecting
Premium for isolated testing.

Morphe2.3.0's actual `Compatibility` constructor defaults `formFactor` to
**MOBILE**, not null. Plex's omitted targets become exactly one default
`AppTarget(version = null)` sentinel in the loaded definition, not an empty
loaded list. Inventory validation checks that complete sentinel; the shared
`projectPatchDefinitions` normalizes **only that exact Plex sentinel** to public
catalog `targets=[]`, retaining `formFactor: "MOBILE"`. Constrained targets must
not be erased. Termius's scalar `versionCode = 1008` expands into all four
`SupportedAbi` entries, each with code **1008**; it is not a universal/null code
or a single-ABI constraint. These are constructor/projection semantics, not a
compatibility expansion or all-version success claim.

Plex is package-scoped, not a cross-package Universal patch. Its preserved
Hermes v96/signature guards still have to succeed. No Universal, Spotify, or
unrelated patch definition is allowed.

`requireCollectionInventory` validates the complete exact-three loader result,
including types, defaults, empty options/dependencies and compatibility policy.
`requireTermiusInventory` is only a strict two-definition source-test helper. It
must not validate or filter a collection MPP. The public catalog DTO has no
dependency field; catalog generation validates actual loader dependencies, and
inspection reports an explicit name-to-dependencies map for **all three**.
Catalog, inspection and Termius runtime checks share `projectPatchDefinitions`.

`RuntimeCheckKt` loads and validates all three definitions from the exact final
MPP and compares the complete catalog projection. Its application cases select
only Offline Automation, only Server Auditor Premium, or both on the Termius
base APK. It never applies Premium unlock. It remains a bounded Termius bytecode
checker, emitting unsigned/incomplete non-installable structural fixtures; it
neither supports nor broadens the generic resource pipeline for Plex. Loading
the collection initializes Plex-derived definitions even when only Termius is
selected; execution needs approval covering that scope.

## Optional final-MPP identity integration

`tools/release/observations.py execute --termius-selection ABS_EXTERNAL_DESCRIPTOR`
can freshly verify the independently pinned Termius selected set before invoking
this tools-only checker. See [the observation contract](../release/observations.README.md)
for the paths-only descriptor, fixed identity/provenance/tool policy, finally
closure checks and shared execution/recheck validator. Without that explicit
option, Termius structural execution stays blocked. Invalid or changed selections
fail the whole partial run and clear fragments.

RuntimeCheck's five arguments remain unchanged. The third argument is the NEW
**semantic output directory**, with an existing canonical, non-linked external
parent. The checker also consumes a NEW deterministic sibling named
`<output-name>-work` under that same parent, and records its absolute path as
`work_directory`. Both paths must be nonexistent and disjoint from source/inputs;
neither is cleaned on failure. Retain both. Patcher `temporaryFilesPath` belongs
only in the work sibling; emitted DEX, manifests and fixture APKs remain in the
semantic directory. This avoids classifying Patcher's retained `patched/dex` and
`patched/originalDex` working files as additional semantic outputs. It does not
exclude any DEX from the strict 19-inventory semantic graph.

The observation runner puts both directories inside its NEW external session and
indexes **all their retained files** by size/SHA-256. Terminal recheck rejects
missing, mutated or added scratch bytes just like any other retained evidence;
there is no native scratch-semantic or standalone whole-run-index claim. Direct
checker callers must retain/index both directories themselves. Existing failed
runs are not migrated, reclassified or made acceptable by this change.

Its native `termius-structural-check-v3` envelope records actual wall/monotonic
timing, invocation, work directory and parent classpath on success or failure
after output reservation. Python preflight alone is the exact-request2 authority; the checker does not
independently validate a request. Pre-output failures have parent child evidence
only. The three selections, shared nine singleton negatives, 19 emitted DEX
inventories and fixture correspondence remain bounded JVM structural checks,
not patched-APK, Manager, Android/ART or release-readiness evidence.

Compared input/emitted DEX collection rejects duplicate compared class and method
descriptors rather than overwriting them. Instruction snapshots include both
reference operands. Premium suffix preservation rebases branch, switch/payload
and exception targets relative to the original body entry after the approved
prefix; targets entering the omitted prefix are rejected.

`src/test/kotlin/RuntimeSnapshotRegression.kt` is a separate tools-only regression
entrypoint (`RuntimeSnapshotRegressionKt`). Compile it to a separate external
JAR against an independently reviewed checker JAR plus the pinned runtime closure,
then run with only those JARs/runtime dependencies. It uses in-memory dexlib
methods, self-authored raw DEX and synthetic output/work reservation cases in NEW
external Java temporary directories, not a vendor APK, patch loader or MPP.
Reservation cases check fresh siblings, preserved preexisting paths, source/input
overlap, missing parents and dot escapes. It is not part of the source runner's
121-case collection test inventory and does not change its compile-only checker
behavior. All compiler/test outputs must stay outside this repository. These
regressions are checker correctness tests, not final-artifact verification.

## Supported offline JVM compilation/tests

Invoke `run_jvm_checks.py` from trusted source with installed Python `-I -B`,
explicit installed JDK and pinned installed cache, and a **NEW external output
directory with an existing parent**. Nothing is downloaded. The runner's unchanged
historical docstring still says neither scope is authorized; the scoped renewed
approval and current evidence above supersede that status text, not its runtime
checks or any new permission denial. This invocation is a generic path template,
not a recorded command; replace every path with your reviewed installation and
NEW external output.

```powershell
& 'C:/approved-tools/python/python.exe' -I -B `
  'C:/source-checkout/tools/termius-check/run_jvm_checks.py' `
  --scope termius --jdk 'C:/approved-tools/jdk21' `
  --cache-root 'C:/approved-cache/caches/modules-2/files-2.1' --out 'C:/private-lab/termius-jvm-NEW'
```

There is **no default scope**. `--scope termius` compiles only the eight Termius
production files, two metadata adapter files, three Termius test files and
checker adapters. It excludes Plex and collection inventory tests; its status
explicitly says `termius_...`, never whole collection.

For the reviewed three-patch scope including Plex initialization/tests, use
`--scope collection` with a different NEW external output. That adds all three
Plex production files, Plex tests and `collection.CollectionInventoryTest`;
its status explicitly says `collection_...`. Both modes reject unknown
main/test/checker source files rather than silently expanding compilation.
Collection inventory tests cannot run against Termius-only definitions. All
JARs are JVM-only, not Android MPPs. The checker JAR includes adapters/projection,
not patch definitions.

### Retired PowerShell launcher

`.claude/skills/run-android-morphe/check-termius.ps1` is retired. `-Help` only
prints migration guidance; every normal invocation fails before path validation,
filesystem writes, Java or Gradle. Legacy parameter names are accepted solely
to give that error, never to forward execution. The obsolete launcher copied
only `RuntimeCheck.kt`, omitting shared helpers, and supplied three arguments
where the adapter requires five. Do not use it to build or check an MPP. Use the
scoped Python runner above, then the isolated exact-bundle adapter below.

## Exact existing MPP catalog and inspection

The metadata source files remain under `patches/src/main/kotlin/.../tools` for
shared reuse, but Gradle excludes them from `main` and compiles them in the
**tools-only `catalogTool` source set**, not into distributable production patch
classes. They expose no Patch-valued utility globals. The separate official
`test` / `buildAndroid` phase prepares the adapter classes. `generatePatchesList`
uses already compiled output paths and resolved dependency files, stripping
SourceSetOutput/runtimeClasspath task metadata; it has no compilation/build task
edges. It fails when adapter classes are absent rather than compiling them.
Build04 later completed the official collection tasks and same-byte catalog
generation; that historical success does not establish the task graph or output
binding for changed source.

In an authorized external working copy, first complete official `test` and
`buildAndroid` with the reviewed build driver. Then select exactly one built MPP:

```text
gradlew :patches:generatePatchesList -PcatalogBundle=ABS_EXACT_MPP -PcatalogOutput=NEW_EXTERNAL_JSON
```

Do not run Gradle in the publication checkout, use globs, rebuild during
cataloging, or substitute source definitions. Catalog/checker adapters reject
parent classpaths containing any of the three patch definition owners.

Use the exact `checker_runtime_classpath` string from a reviewed successful
runner report, with explicit installed Java. Never add `definitions-JVM-ONLY.jar`,
`tests.jar`, main runtimeClasspath or wildcard dependencies. The following are
invocation templates, **not executed final-MPP evidence**:

```text
ABS_JAVA -cp EXACT_CHECKER_RUNTIME_CLASSPATH io.github.fishyau.androidpatches.inspection.InspectBundleKt ABS_EXACT_MPP ABS_MATCHING_CATALOG NEW_EXTERNAL_REPORT ABS_REPO
ABS_JAVA -cp EXACT_CHECKER_RUNTIME_CLASSPATH RuntimeCheckKt ABS_EXACT_MPP ABS_TERMIUS_BASE_APK NEW_EXTERNAL_DIRECTORY ABS_MATCHING_CATALOG ABS_REPO
```

`RuntimeCheckKt` requires **exactly five positional arguments**, in that order:
(1) exact collection MPP, (2) independently verified Termius base APK, (3) NEW
external output directory, (4) matching exact-MPP catalog JSON, (5) source
repository root. Replace every placeholder with an explicit absolute path;
quote each path and the whole classpath in PowerShell, invoking Java with `&`.
Keep all outputs external and confirm applicable input/execution authorization.

Inspection validates actual exact-three metadata, catalog equality, all-three
dependencies and bounded unsigned ZIP/DEX structure on JVM. It does not apply
Plex, prove Android/ART loading, Manager import or device behavior. Dedicated
Plex resource checks and acceptance remain separate gates. JVM compilation of
these adapters is observed; successful final-MPP inspection/runtime execution
is not established by compilation or these examples.

## Safe static regression checks

`tests/test_collection_sources.py` uses only Python AST/text/file-policy checks,
recorded migration hashes, and synthetic source trees in external temporary
scratch. It never invokes a compiler, Gradle, JVM, donor code, network or device.
`tests/test_legacy_checker_entrypoint.py` additionally runs only the retired
launcher with an explicitly selected installed PowerShell in fresh external
scratch, checking harmless help and fail-closed behavior. Neither test suite is
Kotlin/Gradle validity or an actual final-bundle loader result.
