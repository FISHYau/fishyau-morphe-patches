# Plex final-MPP resource checks

Use the explicit existing Android MPP and its matching catalog. No frozen request, source-tree digest, provenance approval or private runtime report is required.

```text
python -I -B tools/plex-check/final_bundle.py compile-only --jdk ABS_JDK21 --cache-root ABS_CACHE --out NEW_EXTERNAL_DIR
python -I -B tools/plex-check/final_bundle.py check --jdk ABS_JDK21 --cache-root ABS_CACHE --out NEW_EXTERNAL_DIR --bundle ABS_MPP --catalog ABS_CATALOG
```

Use installed JDK21 and the pinned local dependency closure. Every output directory must be NEW and external to the checkout. There is no Gradle resolution, download, vendor APK signing, device operation or publication in this checker.

`compile-only` compiles the tools-only adapter, not the patch definitions, and does not run final-MPP cases. `check` validates bundle metadata/version, the current three-patch catalog and the actual isolated loader result, then executes all **23 synthetic resource cases**. Plex's package-scoped version-unpinned `targets=[]` is intentional; finite Termius compatibility is preserved. Do not add source definitions or test JARs to the loader's parent classpath.

The cases cover Hermes comparison opcodes, moves, mixed pending edits, duplicate named functions, repeat application, malformed/wrong-version/signature rejection and manifest absence/binary/empty/decoded handling. Failed checks propagate failure and leave diagnostic outputs. Input-byte stability checks protect the selected MPP/catalog; they are not whole-source-tree attestations.

## Manifest fixture scope

The `manifest_actual_binary_decode` case uses a real self-authored binary resource table and manifest. It prepares the pinned resource context with `decodeResources$morphe_patcher(ResourceMode.FULL)`, requires the expected decoded content and permits only the intended `extractNativeLibs=false` to `true` change. FULL preparation is not proof of lazy manifest decoding in the production RAW path.

`src/test/kotlin/ManifestFixtureTest.kt` is a separate tools-only regression executable. Compile it against the checker plus the pinned runtime closure with `-no-stdlib -no-reflect -jvm-target 17` and `-Xfriend-paths=ABS_CHECKER_JAR`; write its JAR externally. Run `io.github.fishyau.androidpatches.plexcheck.ManifestFixtureTestKt` with one NEW external fixture directory. It exercises ten actual-context fixture checks with a test-authored callback, not the loaded production patch.

These are synthetic resource/loader checks, not Plex app/ART/Manager runtime tests. The user confirmed Android and Android TV behavior separately. Runtime proof is not a gate to requested test-bundle delivery; report the checks actually executed without inflating their scope.
