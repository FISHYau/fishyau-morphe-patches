# Plex tools-only checks

`final_bundle.py` consumes the **unchanged exact bytes** of the preexisting
`tools/release/freeze.py` request. The canonical CURRENT contract is numeric
schema `2`, policy `initial-three-patch-collection-v2`, with exactly:

```
schema policy owner repository version created_at description
bundle_sha256 catalog_sha256 source_tree_sha256 provenance
```

The target is `FISHYau/fishyau-morphe-patches`, version `0.1.0`. `created_at`
is offset-free UTC, not a timestamp with `Z` or an offset. Provenance is the
reviewed migration closure enforced by `tools/release/staging.py`. No defaults
or patcher-version fields belong in the request. The old standalone
`plex-final-bundle-request-v1` contract is rejected, not upgraded or rewritten.

The wrapper shares staging/release target, timestamp, description and provenance
validation and uses actual source-tree entries. Both trusted validator modules
are hash-inventoried before import and checked again before execution and after
the run. Actual MPP metadata must supply patcher `2.3.0` and the request version.
The CURRENT three-patch catalog validator accepts intentional Plex `targets=[]`,
`MOBILE` form factors and the four Termius ABI code-1008 projections; historical
release-v1 finite-target validation is unchanged. Exact three defaults and the
loaded definition types/options/dependencies/compatibility remain actual-loader
checks, not assertions supplied in the request.

The native checker shares its request validator with the tools-only contract
probe. It independently checks strict JSON (including duplicate keys and numeric
schema type), target/metadata/digests, actual source-tree digest and provenance.
To avoid copying all original/migrated hash constants, it pins the exact reviewed
`docs/termius-migration.json` and `docs/plex-migration.json` byte hashes and derives
their provenance projections, checking the actual source/license closures. A
reviewed change to either migration record requires updating those native pins.
The wrapper passes the explicit source root as the final native argument.

## Offline commands

Use installed Python with `-I -B`, explicit installed JDK21 and the pinned local
cache closure, and a **NEW external** output directory. No Gradle or downloads:

```
python -I -B tools/plex-check/final_bundle.py compile-only --jdk ABS_JDK21 --cache-root ABS_CACHE --out NEW_EXTERNAL_DIR
python -I -B tools/plex-check/final_bundle.py check --jdk ABS_JDK21 --cache-root ABS_CACHE --out NEW_EXTERNAL_DIR --request FROZEN_REQUEST_JSON --bundle EXACT_FINAL_MPP --catalog EXACT_CATALOG_JSON
```

`compile-only` reports `compile_only_no_final_bundle_observation`; it is not
loader/resource/runtime evidence. `check` copies exact request bytes before any
child process, verifies the original and copy before native invocation and after
execution, and preserves failed outputs. It retains classpath isolation and all
23 named resource cases. Compilation or aggregate success cannot substitute for
those actual observations. These checks are not Plex app/ART/Manager acceptance.

The `manifest_actual_binary_decode` fixture explicitly prepares the real context
with the pinned JVM-visible `decodeResources$morphe_patcher(ResourceMode.FULL)`
API. Its noninstallable ZIP includes a genuine authored binary `resources.arsc`
table and binary manifest. Before executing a patch, the checker requires the
decoded manifest file and its expected package/application/extractNativeLibs=false
content, then snapshots the exact bytes. Only the false-to-true attribute edit is
allowed in the output. This is **FULL preparation**, not proof of lazy manifest
decoding in the production RAW path. Other staged missing/binary/empty/text cases
and all 23 final-MPP case names remain unchanged.

The retained workspace run `.android-morphe/collection-final-observations-01`
failed this fixture: direct `ctx.decode("AndroidManifest.xml")` on a directly
constructed, unprepared context did not materialize a decoded file; a later null
assertion failed after the patch returned without an exception. That failed run
and its frozen request are historical and must not be rewritten or rerun against
changed sources. These checker edits invalidate that request's source-tree
binding; a future actual final-MPP observation requires a separately authorized
fresh build/freeze/output, not updated old hashes or reports.

## Request integration tests and native probe

Run focused Python tests with the installed interpreter:

```
python -I -B -m unittest discover -s tests -p test_plex_final_bundle.py -v
python -I -B -m unittest discover -s tests -p test_freeze_plex_integration.py -v
```

`test_freeze_plex_integration.py` calls actual `freeze.freeze(...)` using the
trusted `test_freeze.SyntheticBuild` temporary external fixture and reviewed
current sources. Its MPP contains **invalid synthetic ZIP/DEX payloads** and its
build/evidence reports are fabricated schema fixtures. It stops at the actual
wrapper preflight and staging byte-binding validators. It never invokes the MPP
loader/resource cases. Whitespace is preserved and its exact SHA is compared
against staging's binding rather than a reserialized JSON digest. Mocked child
sequencing tests are separate and leave execution `failed`/`not_observed`.

`src/test/kotlin/FrozenRequestContractTest.kt` is an executable tools-only probe.
Compile it against the tools-only checker and the same pinned runtime closure,
then run `io.github.fishyau.androidpatches.plexcheck.FrozenRequestContractTestKt`
with the exact freeze-produced request path and its synthetic source root. It
calls the same validator as native main, exercises acceptance/rejections without
opening ANY MPP, and reports `request_contract_probe_only`. Do not confuse that
result with a final-MPP run or use the synthetic bundle in the loader path.

## Actual-context manifest fixture regression

`src/test/kotlin/ManifestFixtureTest.kt` is a separate tools-only executable.
After `compile-only`, compile it with the same pinned compiler/runtime closure,
`-no-stdlib -no-reflect -jvm-target 17`, the checker JAR on `-classpath` and
`-Xfriend-paths=ABS_CHECKER_JAR` (to test the shared internal fixture functions).
Write the test JAR to a NEW external directory. Run
`io.github.fishyau.androidpatches.plexcheck.ManifestFixtureTestKt` with that JAR,
the tools-only checker and the exact pinned runtime closure on the classpath,
passing one NEW external fixture directory. No production patch/helper source,
MPP, frozen request, loader or device is an input.

The ten checks execute the actual pinned resource context. They exercise the
shared final-checker setup with a **test-authored manifest-only callback**, prove
binary ZIP input plus FULL-prepared decoded output, reject unprepared/direct
`decode`/RAW preparation, reject missing/empty/binary/wrong decoded content before
execution, and retain intentional no-op/excessive-edit failures to prove the
exact manifest output assertion. The success marker is
`manifest_fixture_regression_only`, with final definition/resource/runtime
observations explicitly `not_observed`. This probe neither runs the 23 loaded
production-patch cases nor substitutes for their future final-MPP observations.
