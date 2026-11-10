# Third-party material

- **Morphe patch template/build and catalog generator**: source reference and modifications are recorded in `docs/provenance.md`; applicable GPLv3 and naming notice are preserved in `LICENSE` and `NOTICE`. Existing file-level copyright notices remain attached.
- **Gradle wrapper scripts and JAR**: copyright the original Gradle authors; Apache License 2.0, provided in `licenses/Apache-2.0.txt`. Wrapper source reference and hash pins are in `docs/provenance.md`. No local branding change modifies the wrapper's license.
- **Termius patch sources and validators**: migrated from the private `rushiranpise/morphe-patches` donor checkout; exact local-file provenance and mechanical adaptations are recorded in `docs/termius-migration.json`. The donor revision alone does not identify its untracked local patch implementations. These are patch implementations, not extracted vendor application source.
- **Focused bytecode return helper**: derived from Morphe’s `BytecodeUtils.kt`, itself forked from ReVanced. Its complete file-specific GPLv3 Section 7 notice is preserved in the derivative source. Retain the applicable notice and distinct FISHYau identity when redistributing.
- **Plex Premium unlock and Hermes parser**: migrated from `UnkyBadTouch/plex-morphe-patches`, clean donor revision `38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f`. Exact source hashes and adaptations are recorded in `docs/plex-migration.json`. Preserve the applicable GPLv3/Morphe notices and distinct collection identity. No Plex APK, JavaScript application bundle or prebuilt patch bundle is included.
- **Build dependencies** are resolved from their published registries rather than vendored here. A final binary release requires a dependency/license audit of the actual bundle, including any notices that its dependency licenses require.

No Android vendor application, extracted application implementation or app artwork is distributed as part of this source tree.
