# Contributing

Develop and inspect an app in a private lab **outside this publication root**. Obtain app inputs lawfully; do not redistribute those inputs, extracted implementation or app assets in this repository.

1. Record the original APK/APKM SHA-256, manifest package/version/code, split selection and vendor signer digests.
2. Inspect original DEX with exact method descriptors. Decompiled source is navigation, not authoritative bytecode.
3. Implement narrow fail-closed patches and synthetic positive/negative tests in the lab. Do not add unverified patch entry points here.
4. Build a candidate with the collection scaffold, run the real target-patcher round trip, inspect emitted DEX and test rejection-before-mutation cases.
5. Test the intended patched feature on a newly owned disposable emulator; drive it, inspect screenshot/UI/log evidence and record exact artifact hashes. Onboarding in an original app is not this check.
6. Promote reviewed source/tests only after all gates pass. Rebuild and recheck the exact final collection artifact; adding another patch invalidates prior final-bundle approval.
7. Prepare sanitized evidence/catalog/checksums. A protected human reviewer authenticates evidence provenance. Machine checks establish consistency, not that a self-authored report is truthful.

### Accepted existing Termius behavior

For the initial **Server Auditor Offline Automation** and **Server Auditor Premium** sources only, the user explicitly confirmed tested/working behavior on **2026-11-09**. Do not manufacture new runtime reports from this confirmation or alter historical evidence. The versioned staging policy records inherited behavior acceptance separately, with original/migrated file hashes and mechanical changes. It still requires new exact-artifact compilation/structural/Manager-import verification and authenticated protected review before publication. This is not a generic exemption for new patches, changed algorithms or arbitrary versions.

Preserve GPL notices and file-level attribution; identify modifications. Keep About name exactly `FISHYau android patches`. Extensions and broad shared utility imports need a demonstrated dependency, not template convenience.

Use the canonical `.claude/skills/run-android-morphe/` tooling. Outputs, tool installations and original/patched APKs belong outside this checkout. Use Python isolated mode (`-I`) for untrusted archives. Never run tools from extracted app directories.

No existing devices or app data are test targets. Target explicit emulator serial/private ADB server, verify AVD ownership before device actions, and never use shared `kill-server`, clear app data or uninstall from somebody else's device. Do not bypass a denied operation through a different tool.

PR verification does not publish. Publication, repository creation/configuration, commits and pushes require explicit maintainer authorization; a passing test or manual workflow dispatch is not blanket permission. No automatic stable releases from ordinary development pushes.
