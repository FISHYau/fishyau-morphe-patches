# Contributing

## Local development

1. Obtain authorized app inputs and independently verify package, version/code, signer and selected splits. Keep inputs and extracted material outside this checkout; do not redistribute vendor applications or assets.
2. Inspect exact DEX selectors or the relevant resource structure. Decompiled names and strings are navigation, not proof of a unique or correct patch target.
3. Implement narrow patches with positive and negative tests. Reject absent, ambiguous, incompatible and already-patched input before unwanted mutation.
4. Run local tests and build the Android MPP with the official `buildAndroid` task. Generate the catalog from that exact artifact. Use the local Termius/Plex checkers where applicable.
5. Test runtime behavior when useful, on authorized newly owned disposable emulators or through the user's requested on-device testing. Report what actually ran and what remains untested; do not manufacture passing reports.

Use the [canonical skill](.claude/skills/run-android-morphe/SKILL.md). Keep APK/DEX/MPP, build/cache outputs, signing material, logs and screenshots outside this checkout. Run Python with `-I -B` from trusted code, never from extracted app directories.

There is no whole-source-tree digest, freeze/request protocol, private runtime-report prerequisite, candidate receipt or protected independent-review approval. Historical migration records document origin; they are not immutable approval locks on future development. Preserve GPL notices, attribution and the collection's own About identity.

## Device and credential boundaries

Use only authorized owned disposable runs. Verify exact device ownership before actions and process exit plus both owned ports released before cleanup. Never operate on someone else's device/data, use global ADB cleanup or bypass a denied operation through another tool. Signing, new keys, downloads, licenses and credentials need their applicable authorization.

Never put secrets in source, command arguments, reports or briefs. Use existing authorized credentials through environment variables or normal authenticated tooling.

## Requested delivery

Passing tests or pushing source does not publish. When the user requests availability through the GitHub source link, follow [the local delivery instructions](docs/release-handoff.md): select the tested MPP, upload public assets, verify downloaded bytes and update the Manager manifest last. Do not publish automatically from PRs or development pushes. Do not force/clobber an existing release or bypass GitHub's configured permissions.

The user confirmed Termius working on 2026-11-09 and Plex Android/Android TV working on 2026-11-10. Preserve that acceptance without presenting it as a fresh assistant-run test of every later artifact.
