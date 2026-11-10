# Verification status

## Accepted behavior

- **2026-11-09:** the user confirmed Server Auditor Offline Automation and Server Auditor Premium tested and working.
- **2026-11-10:** the user confirmed Plex working on Android and Android TV and requested that observed-runtime reports not be a prerequisite to publication.

These are user confirmations, not newly executed assistant tests for every future artifact. Patch compatibility/defaults have not been widened: Termius remains 8.0.1/code 1008 APKM; Plex remains package-scoped/version-unpinned APKM with Hermes signature guards and declared MOBILE metadata.

## Historical executed checks

Before this tooling simplification:

- The official Android collection build completed `:patches:test :patches:buildAndroid` with **121 passing cases** and produced an Android MPP plus matching catalog.
- Bounded same-MPP checks passed actual loader/inventory checks, **23 synthetic Plex resource cases**, and Termius singleton/combined structural checks. Synthetic resource/DEX checks are not vendor Android runtime tests.
- Unchanged official **Morphe Manager 2.5.0** locally imported that MPP, showing **FISHYau android patches**, version **0.1.0**, **3 patches** and **2 apps**. This demonstrated local loading/inventory, not the hosted source flow or Manager patch execution.
- Windows/Linux offline tooling checks passed at earlier checkpoints. Those historical counts are not test results for later edited tooling.
- The self-authored standalone fixture passed baseline/patched UI checks. The bounded base/config split fixture passed whole-set assembly and resource/JNI checks for x86_64 and arm64-v8a on the installed Android30 x86_64 image/native bridge. ARM success proves that fixture/image combination, not arbitrary vendor compatibility.

Earlier failed builds, diagnostics and runtime runs remain failures. Their private output directories have not been deleted or rewritten. They are not prerequisites to future development or test-bundle delivery.

## Checks executed during tooling simplification — 2026-11-10

- New public-format tests: **8 passed**; new publisher tests: **11 passed**, using mocked GitHub calls only. A local-only preview also accepted the explicitly selected existing build-10 MPP/catalog without network calls or remote writes.
- Source collection checks: **22 passed**; historical/legal byte checks: **7 passed**; scaffold unit checks: **9 passed**; source file policy passed for **148 files**.
- Canonical offline Android tooling: **497 tests run, 496 passed, 1 opt-in integration skipped**; rerun during the final cleanup with the same result. Scaffold unit regressions were also rerun: **9 passed**. After the approved removal, source file policy passed for **122 files**, and `git diff --check` passed.
- Fresh collection compilation and ordinary JUnit execution with the installed pinned tools: **121 tests passed**. The tools-only isolated checker also compiled successfully.
- Fresh Plex checker compilation and execution against the explicitly selected existing build-10 Android MPP/catalog: actual three-definition loading/catalog comparison and **23 synthetic resource cases passed**.
- Separately compiled tools-only regressions: **20 snapshot/collection cases passed**, and **10 manifest-context cases passed**. These are bounded structural/resource-context tests, not Android app runtime proof.
- **Initial full repository discovery failed while removal was permission-blocked:** `Ran 430 tests in 186.569s`; `FAILED (failures=1, errors=90)`. The affected retired modules were `test_candidate`, `test_evidence`, `test_freeze_plex_integration`, `test_observations` and `test_structural_observations`; they expected the removed candidate CI job or old frozen-request/measured-report checker interfaces. This failed run remains a failure, not a result for the subsequent cleanup.
- **After the explicitly authorized removal, full remaining repository discovery passed:** `Ran 111 tests in 10.859s`; `OK`. The deleted tests belonged to the removed protocol; useful local source, identity, checker, format and mocked publisher tests remain in ordinary discovery.
- Final independent read-only cleanup review passed: no operational imports/links requiring the retired pipeline and no concrete correctness/safety defects in the canonical skill's replacement guidance were found. Patch implementation files remained unchanged.

Fresh diagnostics and compiled artifacts are retained outside this repository in the workspace's `.android-morphe/local-workflow-*` outputs. The earlier malformed-ZIP test fixture failed because Windows normalized its backslash before serialization; the fixture was corrected to alter the serialized member names, and the format suite then passed. No validation was weakened.

No new Android MPP build, vendor-APK structural application, device/runtime check, signing, Manager import or hosted-source check was performed during this simplification. Patch implementation files, defaults and compatibility were not changed. No commit, push or publication was performed.

## SpotifyTV Home-preview implementation — 2026-11-10

The implementation-stage source and tested artifacts described below added experimental **Disable Home previews**, default **off**, for `com.spotify.tv.android` **9.1.94.1926 / code 147600562**, **APKM_REQUIRED**, **TV**. The intended delta is precisely three same-width edits in two Home-preview methods, guarded by seven semantic and seven physical pins; the separate Home AutoNavigate timer, shared player/queue paths and authentication/session code must remain unchanged. Compatibility metadata alone does not establish trusted app identity or tested ABI support.

**Account authentication must always continue to work.** No login/authentication bypass, fake session or backend-entitlement modification is permitted. Acceptance includes normal sign-in, authenticated use/session refresh, sign-out and reauthentication, including device-link/redirect behavior where applicable. A changed signer must not be assumed compatible with authentication. Whole-map/synthetic sentinel preservation constrains code changes but does not prove live account flows.

Source, loader/DEX, actual Android MPP and runtime observations are separate checks. Original source-02 synthetic results are historical, not fresh proof for this integration; the retained SetSourceFile debug-item writer limitation is not silently stripped or declared solved. The inherited canonical snapshot format also does not distinguish absent nullable metadata from a literal `"null"` string, so exhaustive metadata-drift detection is not claimed. No successful strict-pin Spotify application, signed installable Spotify set, Manager execution or baseline/patched authentication/artwork/playback runtime result is established here. Independent input provenance, authorized account setup and separate Spotify-signing approval remain prerequisites for their respective vendor stages. Do not reuse fixture/Termius/Plex signing grants.

Fresh implementation-stage checks executed so far:

- Canonical offline Android tooling: **497 tests run, 496 passed, 1 opt-in integration skipped**. These exercise tooling, not live Spotify authentication or previews.
- Initial repository Python discovery: **120 passed**; after named-helper isolation regressions, **123 passed**, rerun after the generated-helper correction with **123 passed**. Scaffold unit tests: **9 passed**. These publication tests used mocked/local operations, not remote writes.
- Initial collection JVM compilation/JUnit: **138 passed**, including sixteen self-contained Spotify tests and synthetic sign-in/refresh/sign-out/reauthentication preservation sentinels; after named-helper isolation regressions, **142 passed**; final generated-helper/compiled-class-family coverage: **144 passed**. Deliberate Termius-only compilation/JUnit was rerun after the final correction: **75 passed**. These overlapping suites must not be summed as distinct coverage.
- The first offline Android collection build completed `:patches:test :patches:buildAndroid`: **138 tests, no failures/errors/skips**, producing version **0.1.1-dev.1** and its catalog from that exact MPP. Same-MPP isolated JVM inventory/catalog checks passed for four definitions/three apps, Spotify default-off, alongside **23 synthetic Plex resource cases**. These checks do not establish Manager import, ART execution or Spotify application. A subsequently identified helper-class isolation fix requires fresh artifact/checker verification before final handoff.
- The second offline Android build also passed: **142 tests, no failures/errors/skips**, version **0.1.1-dev.1**. It includes named-helper isolation but predates a further compiler-generated-helper guard correction identified by independent review; neither earlier build is represented as the final post-correction artifact.
- The final post-correction offline Android build passed **144 tests, no failures/errors/skips** and produced **0.1.1-dev.1**. Its exact MPP/catalog passed the fresh tools-only isolated inventory/catalog checker and all **23 synthetic Plex resource cases**. Four definitions/three app packages were verified; only Spotify is default-off. The compiled-class-family regression independently checks every emitted Spotify class, including generated helpers, against the isolation guard. This establishes JVM loading/metadata and synthetic resource behavior, not Manager import, ART execution or successful Spotify application.
- Read-only inspection of the pinned original base APK passed bounded inventory and the strict ZIP metadata preflight, with no case-alias families. The inspection's prehash bounds were corrected, **5 regression tests passed**, and inspection was repeated in a fresh output. This does not verify the selected split set, vendor identity/signature or successful assembly.
- Independent source review confirmed the exact selectors/pins/three-edit boundary; it identified a helper-only parent-classpath substitution gap in the checker and a mutable-debug representation mismatch in the expanded synthetic fixture. No production pin is relaxed to accommodate the fixture.
- After separating the independently specified mutable execution rows from full DEX-reader rows, the private source-03 replay passed: **10 structural positives / 2,450 expected rejections**, **14 loader/snapshot positives / 169 expected rejections**, and **1 canonical success / 17 expected rejections**. These overlapping bounded checks cover the private candidate, including edited-target try/debug preservation, preserved sparse/array payloads and fictional auth/session sentinels. They are not yet the final repository-source round-trip result. SetSourceFile writer type9 rejection remains an explicit expected limitation; no debug item was stripped.

Final exact-repository-source synthetic round-trip is **blocked and unexecuted**; post-correction Android MPP/catalog checks passed as scoped above. Canonical patch-build rejects repository-local Kotlin inputs. Permission enforcement previously denied the proposed byte-identical external staging change. A subsequent author/reviewer workflow also declined to proceed because it could not verify the post-denial confirmation from its delegated context; both stages reported no edits or command execution. Staging remains unimplemented, and no alternate execution route was used. The external harness received test-only mutable-debug/oracle repairs, but these repairs remain unexecuted and do not close the final-source round-trip gap. Direct repository-path compilation and exact-byte staged-source execution are not claimed. Existing Termius/Plex confirmations and historical counts above are unchanged. Runtime authentication and Spotify preview/artwork/playback remain unobserved.

## Requested Spotify default-on revision — 2026-11-10

The user requested that **Disable Home previews** apply by default, then stand by to test using the new TV emulator in AndroidLab. The source definition now sets `default = true`; the exact collection/catalog policies, regression expectations and current guidance are aligned. Incorrect Spotify `default = false` remains rejected. Only the selection default and its policy expectations change; mutation logic, original pins, compatibility, authentication/session code, loader isolation and canonical source admission are unchanged.

Default-on revision checks: **123 repository Python tests passed**, **144 collection JVM tests passed**, and the offline Android `:patches:test :patches:buildAndroid` build passed **144 tests with no failures/errors/skips**, producing **0.1.1-dev.2**. The exact new MPP/catalog passed the tools-only isolated JVM inventory/catalog adapter: four definitions/three packages, all four defaults true. Source policy passed for **128 files**, and `git diff --check` passed. These overlapping suites are not additive coverage or Android runtime proof. Earlier implementation-stage results above remain historical default-off results.

The new local artifact is `.android-morphe/spotify-preview-default-on-android-build-01/artifacts/patches/build/libs/patches-0.1.1-dev.2.mpp` relative to the private workspace, SHA-256 `09131cb778b39ac7dcc84317fd03f38e282f59ea6d3af769ef16573823bcbd46`. Its matching `artifacts/patches-list.json` SHA-256 is `a8024c904095e8cbb42b8452089ae4aa9105ec442b9a2a1deea63998e39d4833`. No artifact is stored in this repository. The same MPP/catalog also passed all **23 synthetic Plex resource cases** with unchanged inputs and exact four-definition metadata/catalog verification. These are noninstallable synthetic resource checks, not Spotify application, Manager/ART execution or runtime acceptance.

No AndroidLab/emulator operation, signing, vendor application, Manager import or publication was performed for this change. Stand by for the requested TV-emulator testing; preview/artwork/playback and normal authentication/session behavior remain unobserved, and the final exact-repository-source round-trip gap remains open. Historical private outputs and checkpoints were not modified.

## Current process

Run ordinary source/unit tests, the actual Android build and applicable local artifact checks. See [README](../README.md), [Termius checks](../tools/termius-check/README.md), [Plex checks](../tools/plex-check/README.md) and [canonical tooling](../.claude/skills/run-android-morphe/SKILL.md). Changes to the tooling must be verified directly; historical success does not establish that edited code passes.

The local checker/publisher entry points do not require source-tree attestation, frozen requests, mandatory private runtime reports, candidate/Actions receipts or protected independent-review approval. These are not Morphe requirements. Following explicit exact-scope user confirmation on 2026-11-10, the retired `tools/release/`, `tools/manager-check/`, `.github/workflows/release.yml`, unused measured-JUnit listener and their protocol-only tests/normalization fixture were removed (26 files). The canonical skill now describes ordinary local checks and explicitly requested GitHub delivery. Useful local build/apply records and owned-emulator state remain ordinary tooling outputs, not publication approvals.

**Hosted-source discovery/download/update has not been established by the historical local import.** Perform that check after the user requests publication and the real manifest/asset are available. Do not fabricate a live manifest before upload, or infer app/ART behavior from compilation or installation acceptance.

## Boundaries

- Outputs, app inputs, caches, signing material and private diagnostics stay outside this source repository.
- Independent app identity/signature checks and explicit supported packaging limits remain required for local app operations.
- Follow workspace authorization and owned-device shutdown/cleanup rules. Existing/unowned devices and emulator04 cleanup remain outside the grant.
- New downloads/licenses, credentials, signing, Git changes and publication retain their applicable authorization boundaries. A test pass is not a publication request.
- No clean-machine provisioning, arbitrary split/resource/native patch support, backend entitlements or universal device compatibility is claimed.
