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
