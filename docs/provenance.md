# Source provenance

## Scaffold references

- Official build/distribution reference: `MorpheApp/morphe-patches`, revision `8fa2c7a1a832498de8f179748998a3ca87e198eb`.
- Minimal template: `MorpheApp/morphe-patches-template`, revision `1c818c1cc78bacf57051cdad487d32d6d464dfeb`.
- Manager contract: `MorpheApp/morphe-manager`, revision `6bd844d99ef9a13fcae08b68742662ff5bd19f83`.

Scaffold adaptation dated 2026-11-08: distinct identity, minimal dependencies, no sample patches/extensions, no automatic publication or inherited notification/tracker jobs. Preserve LICENSE/NOTICE and source-level attribution.

Wrapper JAR retrieved from pinned template Git blob `9fa7f288283f81eec4952784c271abd7e0938dee`, with Git-object hash verified before copying. SHA-256: `3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98`. Gradle 9.8.2 distribution SHA-256 is pinned to `21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607`. The earlier collection-build denial was not bypassed. On 2026-11-08 the user explicitly authorized building/running official-template-derived code; actual execution/results are recorded in docs/verification.md.

LICENSE, NOTICE and POSIX wrapper match the pinned template blobs exactly. The Windows wrapper was fetched with its pinned blob hash and reviewed before copying. This verifies reference integrity, not build success.

## Local development origin

The preserved Termius donor is a separate dirty checkout of `rushiranpise/morphe-patches` at HEAD `92c0fca0ae103a419c7fc61f9c5b8b38b7d6b82a`. Its untracked source/tests are material work, not disposable files. No history migration is performed. Only **Server Auditor Offline Automation** and **Server Auditor Premium**, their finite compatibility, focused helper and validator tests are selected for this collection. Exact source-file hashes and mechanical namespace/helper adaptations are recorded in [termius-migration.json](termius-migration.json); the donor HEAD is not a substitute for those local-file hashes. The donor lab remains untouched. On **2026-11-09**, the user explicitly requested both Termius patches enabled by default. The sole additional production adaptation is Server Auditor Premium's default-selection metadata changing **false to true**; Offline Automation and Plex remain true. Donor algorithms, guards, descriptions and compatibility remain unchanged. The original Premium file hash is unchanged; the current migrated hash/source-set digest include this separately recorded adaptation. The earlier namespace-only private static review remains historical evidence, not a comparison of the newly adapted source. Default co-selection is not combined runtime acceptance.

On **2026-11-09**, the user confirmed both named patches as **tested and working**. This is inherited existing-behavior acceptance, not a newly observed runtime test of a migrated or final MPP. New compilation, target-patcher, Android Manager import and publication checks are reported separately. Historical records retain their original statuses.

Reusable Android tooling was developed in the enclosing workspace and relocated here on 2026-11-08. The Termius structural checker is adapted from the private lab's checker source, not copied application implementation. Lab-specific defaults must be replaced by explicit external inputs. No proprietary original/patched APK/DEX fixture is included.

## Plex source addition

On **2026-11-09**, the user requested the supplied **Premium unlock** patch as a third definition. Its donor `UnkyBadTouch/plex-morphe-patches` was clean at revision `38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f`. Only the patch, focused Hermes parser, package compatibility and corresponding synthetic tests are selected. Exact file hashes and namespace/testability/description adaptations are recorded in [plex-migration.json](plex-migration.json).

The current donor intentionally leaves versions unpinned for `com.plexapp.android`/APKM. This package-scoped policy is not a cross-package Universal patch and does not prove all-version or all-device support. Execution requires the Hermes v96/premium-check signatures. Conditional decoded-manifest cleanup is not a guarantee of installability or server-side entitlements.

Supplied Plex notes describe historical success and an older build method. They are neither newly observed final-collection evidence nor the user's Termius-only working-status confirmation. No donor MPP/APK/APKM, donor Git metadata or build infrastructure is copied into this source tree.

## Current execution provenance (2026-11-09)

Earlier Plex compile/test and Termius test-JAR rerun denials were respected and remain historical records. The user subsequently explicitly approved **“build and runtime as ongoing permissions”** for this reviewed three-patch collection; workspace `CLAUDE.md` records the scope and exclusions. That supersedes the earlier denials only within scope, never a new tool-enforced denial. It does not authorize Git, publication, credential retrieval, unrelated apps or existing/unowned devices.

The NEW external workspace run `.android-morphe/collection-readiness-jvm-06/jvm-checks.json` records current definitions/tests and isolated checker/catalog adapter compilation with pinned installed JDK21/Kotlin2.4.21/Morphe2.3.0, JVM17. Its `junit.log` reports **121 passing cases**: 39 Automation, 27 Premium, 9 Termius inventory, 18 Hermes parser, 17 Plex resource and 11 collection inventory/projection. Independent review verified all 23 recorded source hashes, three JAR hashes and pinned tool/dependency hashes. Earlier failed attempts01–05 are retained; neither inherited acceptance nor the historical Termius-only result substitutes for this measured scope. These JVM-only JARs are not Android MPPs.

The loaded Morphe2.3.0 compatibility constructor defaults to **MOBILE**. Plex's omitted targets become one exact default unconstrained `AppTarget(version = null)` sentinel; the shared catalog/inspection/checker projection normalizes only that complete Plex sentinel to **`targets=[]`**, retaining MOBILE. Termius's scalar version code **1008** expands to **all four supported ABI entries, each 1008**, for finite version8.0.1. This explains loaded-versus-public metadata without changing donor target policy or claiming all-version/runtime support.

Actual Android attempt01 failed source copying; after the reviewed copy fix, NEW `.android-morphe/collection-readiness-android-build-02` copied source and started Gradle9.8.2, then failed resolving pinned plugin `app.morphe.patches` **2.1.0**. Neither attempt produced collection task execution, JUnit XML or an MPP. Both remain failures. Main's canonical **460 run / 459 passed / 1 skipped** is tooling evidence only. No successful official MPP/catalog, same-MPP Termius/Plex checks, unchanged official Manager import or new vendor Android runtime result is established. Candidate/freeze/Plex-checker work remains separate and is not declared complete here.

The supported JVM/checker route is documented in [tools/termius-check/README.md](../tools/termius-check/README.md): explicit scoped `run_jvm_checks.py`, then isolated adapters against the exact MPP and matching catalog. `RuntimeCheckKt` requires exactly five arguments: MPP, Termius base APK, NEW external output directory, matching catalog JSON, source repository root. The legacy `check-termius.ps1` is retired; help is read-only and all normal invocations fail before writes, Java/Gradle or credential-environment changes. Its former incomplete source copy and three-argument invocation are not a supported execution path. Current Kotlin and scoped runner source hashes are preserved by this documentation/entry-point change.

## Publication provenance

Before release, record a clean committed source revision, canonical source-tree digest, exact bundle hash, patch catalog, tool versions, input identity/hashes and all required evidence. Before Git initialization is separately authorized, local file digests are useful development records but are not a release revision.

The intended source is `https://github.com/FISHYau/fishyau-morphe-patches`, initial collection version **0.1.0**. This identifies the publication target, not a live tested endpoint. No Git initialization, commit, push or publication is performed by this preparation task. Do not substitute donor release 1.23.1 metadata or URLs. Before hosting, use an external candidate manifest and distinguish local Manager import from actual remote discovery/download/update.
