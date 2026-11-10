# FISHYau android patches

An independent Android patch collection **compatible with Morphe**. Not affiliated with or endorsed by the Morphe project.

## Included patches

| Patch | Default | Scope |
|---|---|---|
| **Server Auditor Offline Automation** | On | Local startup-snippet Automation without a Termius account. For isolated Automation, deselect Premium; global authentication and Pro state stay unchanged. Account-independent does not mean network-free SSH. |
| **Server Auditor Premium** | On | Optional legacy client Pro title/expiry override; does not change storage or server entitlements. |
| **Premium unlock** | On | Plex client-side premium-check edits in a Hermes v96 bundle, guarded by required function/signature checks. |
| **Disable Home previews** | **On** | Experimental SpotifyTV Home-preview-only edits, guarded by exact semantic/physical pins. Preserves static-artwork paths; does not disable the separate Home AutoNavigate timer. Vendor/runtime verification remains pending. |

The Server Auditor patches target `com.server.auditor.ssh.client` **8.0.1 / code 1008**, APKM. Plex targets `com.plexapp.android`, APKM, with intentionally unpinned versions; this is not a guarantee for every version or device. Plex also conditionally adjusts split-install attributes in a decoded text manifest. Neither patch provisions backend entitlements.

Both Termius defaults were requested on 2026-11-09; Plex is also selected by default. The user confirmed Termius working on 2026-11-09 and Plex working on Android and Android TV on 2026-11-10. These are user confirmations, not newly executed tests for every future bundle. Declared compatibility is unchanged.

The SpotifyTV patch declares only `com.spotify.tv.android` **9.1.94.1926 / code 147600562**, **APKM_REQUIRED**, **TV**, and is selected by default at the user's request on 2026-11-10. The default-on revision was built locally as **0.1.1-dev.2** and passed source/JVM tests plus exact-MPP JVM inventory/catalog verification; the earlier **0.1.1-dev.1** artifact was default-off. AndroidLab runtime testing remains pending. Its three same-width instruction edits are confined to two Home-preview methods; seven semantic and seven physical original-method pins reject drift before mutation. Declared compatibility is not independent input authentication, successful vendor application or runtime proof.

**Account authentication must remain functional.** Spotify sign-in, authenticated sessions/token refresh, sign-out and reauthentication must continue to work normally. This patch must never bypass, disable or fabricate authentication or backend entitlements. Full-map preservation and synthetic authentication-code sentinels constrain code changes, but do not prove working login. Authorized baseline/patched authentication and playback checks are required before claiming runtime completion; signing-related authentication failures are failures, not reasons to bypass authentication.

There are no Universal patches here. No vendor applications, full extracted vendor method dumps or patched APKs are distributed.

## Develop and test locally

Use **JDK 21**, Gradle **9.8.2**, Morphe settings plugin **2.1.0**, patcher **2.3.0**, and JVM **17** targets. The official **`:patches:buildAndroid`** task creates the Android MPP; a JVM development JAR is not a Manager artifact.

Keep all build outputs, caches, app inputs, keys and private device files **outside this checkout**. The [canonical tooling](.claude/skills/run-android-morphe/SKILL.md) builds in an external working copy:

```text
python -I -B .claude/skills/run-android-morphe/driver.py build --source ABS_REPO --image INSTALLED_JDK21_IMAGE --out NEW_EXTERNAL_DIR --version VERSION
```

The driver runs `:patches:test :patches:buildAndroid` and generates a catalog from the same MPP. It never pulls an image. Use `--offline` with an already populated approved dependency cache when appropriate. GitHub Packages may require existing authorized package-read access; pass credentials securely through the invoking environment, never through chat, argv or source files.

Offline tooling checks, from this repository root:

```text
python -I -B -m unittest discover -s tests -p "test_*.py" -v
python -I -B tools/test_scaffold.py
python -I -B tools/check_scaffold.py
python -I -B .claude/skills/run-android-morphe/test_all.py
```

For actual artifact checks, see [Termius JVM/DEX checks](tools/termius-check/README.md) and [Plex resource checks](tools/plex-check/README.md). Use the canonical owned-emulator tools for runtime testing when needed. Local diagnostics are useful; source-tree attestations, private runtime reports, candidate receipts and protected reviewer approval are **not** required to deliver a test bundle.

## Use this source in Morphe

The GitHub source link is:

`https://github.com/FISHYau/fishyau-morphe-patches`

Manager resolves it to:

`https://raw.githubusercontent.com/FISHYau/fishyau-morphe-patches/main/patches-bundle.json`

A source-code push alone does not make the bundle available. **Only when the user requests publication for on-device testing**, upload the selected MPP, verify the downloadable bytes, then update that manifest last. The local [delivery command and checklist](docs/release-handoff.md) does this without a candidate pipeline or protected approval service. Ordinary pushes and PRs never publish.

No placeholder live manifest is included. Hosted discovery/download/update must be tested after actual publication; local import or HTTP availability alone does not establish the full Manager flow. See [verification status](docs/verification.md) and the [Manager format contract](docs/source-contract.md).

## Layout and attribution

- `patches/`: four patch implementations, validator/Hermes/preview/inventory tests and isolated catalog tooling.
- `tools/`: local artifact-format, delivery and app-specific checking tools.
- `.claude/skills/run-android-morphe/`: inspection, build, assembly and owned-emulator tooling.
- `docs/`: operational instructions, compatibility and historical provenance.

See [CONTRIBUTING.md](CONTRIBUTING.md), [provenance](docs/provenance.md), [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md). Preserve applicable notices and the distinct **FISHYau android patches** identity.
