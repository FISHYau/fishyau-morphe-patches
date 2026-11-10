# Local JVM and Termius checks

Compile and test with explicit installed JDK21 and the pinned local dependency cache. Keep all outputs outside the checkout:

```text
python -I -B tools/termius-check/run_jvm_checks.py --scope collection --jdk ABS_JDK21 --cache-root ABS_CACHE --out NEW_EXTERNAL_DIR
```

`--scope` is required. `termius` compiles the Termius sources/tests and isolated tools; `collection` additionally compiles Plex and collection-inventory tests. Unknown main/test/checker sources are rejected rather than silently added. The resulting definition/test JARs are **JVM-only**, not Manager-ready MPPs. The checker JAR contains adapters/projection, not patch definitions. Use the official `buildAndroid` task for distribution.

The runner executes actual JUnit tests and propagates failures. Normal logs/results and an isolated `checker_runtime_classpath` are retained. There is no historical test-count approval floor, full source/JDK inventory, private measurement receipt or release attestation.

## Check an existing MPP

Use the exact `checker_runtime_classpath` from a successful runner invocation and explicit installed Java. Never add the definitions/test JARs, main runtimeClasspath or wildcard dependencies.

```text
ABS_JAVA -cp EXACT_CHECKER_RUNTIME_CLASSPATH io.github.fishyau.androidpatches.inspection.InspectBundleKt ABS_MPP ABS_CATALOG NEW_EXTERNAL_REPORT ABS_REPO
ABS_JAVA -cp EXACT_CHECKER_RUNTIME_CLASSPATH RuntimeCheckKt ABS_MPP ABS_VERIFIED_TERMIUS_BASE_APK NEW_EXTERNAL_DIRECTORY ABS_CATALOG ABS_REPO
```

Quote each path and the full classpath (PowerShell Java invocations use `&`). The RuntimeCheck adapter takes exactly **five arguments**, in that order. Select the Termius APK only after independently verifying package `com.server.auditor.ssh.client`, version **8.0.1**, code **1008**, signer and selected-set topology. `selected_identity.py` supports the local identity checks; no release observation orchestrator is needed.

Both adapters validate the complete three-patch loaded inventory and catalog. All defaults remain true. Termius has finite APKM compatibility; Plex has package-scoped, intentionally unpinned targets and MOBILE form-factor metadata. The public catalog's empty Plex target list represents the exact unconstrained loaded sentinel, not erased constraints. The catalog has no dependency field; the actual loader separately validates empty dependencies/options.

RuntimeCheck applies only the two Termius singletons and their combined selection. It retains negative cases, emitted-DEX rereads, bounded method/control-flow comparison and rejection of duplicate compared definitions. It never applies Plex; use the [Plex checker](../plex-check/README.md) for resource cases. Structural outputs are unsigned/non-installable test fixtures, not Android runtime proof.

The runtime adapter reserves a NEW external output and deterministic sibling `<output-name>-work`, with an existing non-linked parent and no source/input overlap. Preserve both on failure. Working DEX are distinct from semantic outputs; there is no mandatory whole-run evidence inventory.

`src/test/kotlin/RuntimeSnapshotRegression.kt` is a separate tools-only executable. Compile externally against the checker/pinned runtime closure and run `RuntimeSnapshotRegressionKt`. Its synthetic dexlib/raw-DEX and output-reservation cases test the checker, not a vendor app or Manager.

## Other local tools

- `verify_migration.py` is a historical source-migration audit, not a gate to ongoing patch edits or publication.
- `.claude/skills/run-android-morphe/check-termius.ps1` is retired: help prints guidance and normal invocations fail before writes or JVM execution. Use the scoped Python runner.
- Runtime/Manager tests use the canonical owned-emulator driver and applicable workspace authorization. APK inputs, keys, logs and screenshots stay private/external. No report/reviewer protocol is needed for requested GitHub delivery.
