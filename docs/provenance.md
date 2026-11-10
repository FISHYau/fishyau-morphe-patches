# Source provenance

## Build scaffold

- Official reference: `MorpheApp/morphe-patches`, revision `8fa2c7a1a832498de8f179748998a3ca87e198eb`.
- Template: `MorpheApp/morphe-patches-template`, revision `1c818c1cc78bacf57051cdad487d32d6d464dfeb`.
- Manager contract reference: `MorpheApp/morphe-manager`, revision `6bd844d99ef9a13fcae08b68742662ff5bd19f83`.

The scaffold was adapted on 2026-11-08 with a distinct identity, minimal dependencies and no sample patches, broad shared utilities or automatic publication. Preserve LICENSE/NOTICE and file attribution.

The wrapper JAR came from pinned template blob `9fa7f288283f81eec4952784c271abd7e0938dee`; SHA-256 `3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98`. Gradle 9.8.2 distribution SHA-256 remains `21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607`. Tool pins establish selected tool bytes, not patch correctness.

## Termius

The original private donor was a dirty `rushiranpise/morphe-patches` checkout at HEAD `92c0fca0ae103a419c7fc61f9c5b8b38b7d6b82a`. Its local untracked source/tests were material work, not disposable files. The collection selected only Server Auditor Offline Automation, Server Auditor Premium, focused helpers and tests. The donor lab remains untouched.

[termius-migration.json](termius-migration.json) records the original migration's file hashes and namespace/helper adaptations. On 2026-11-09 the user additionally requested both patches on by default; Premium's default changed false to true without changing its algorithm, guards, description or finite 8.0.1/code 1008 compatibility. Offline Automation's select-alone guidance still means deselecting Premium. Default co-selection alone is not combined runtime proof.

The user confirmed both Termius patches tested and working on 2026-11-09.

## Plex

The user requested Premium unlock on 2026-11-09 from clean `UnkyBadTouch/plex-morphe-patches` revision `38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f`. Only the patch, focused Hermes parser, package compatibility and corresponding tests were selected. [plex-migration.json](plex-migration.json) records the original file/legal-byte hashes and namespace/testability/description adaptations.

Versions intentionally remain unpinned for `com.plexapp.android`/APKM. Execution requires Hermes v96/function signatures. Conditional decoded-manifest cleanup does not guarantee universal sideload support or backend entitlements. The user confirmed working Android and Android TV behavior on 2026-11-10; that confirmation is not a new assistant-run test for every future MPP and does not change declared compatibility.

No donor MPP, vendor APK/APKM, extracted application code, donor Git metadata or unrelated build infrastructure is included.

## Ongoing development

Migration hashes describe the historical import; they are not immutable source approval requirements. Preserve legal notices and attribution while developing normally with unit/structural tests. Ordinary artifact/tool/input integrity checks remain useful; the custom whole-source digest and private report/reviewer system are removed.

Reusable Android tooling originated in the enclosing workspace and moved here on 2026-11-08. App-specific structural checker code is authored tooling, not copied vendor implementation. Use explicit external inputs and outputs. See [verification](verification.md) for bounded historical checks and [local delivery](release-handoff.md) for requested publication. No publication is performed by a test pass or this documentation change.
