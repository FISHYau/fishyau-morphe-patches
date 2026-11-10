# FISHYau android patches

An independent Android patch collection **compatible with Morphe**. Not affiliated with or endorsed by the Morphe project.

## Included patches

The collection contains three patches. The two Server Auditor patches target **Termius / Server Auditor 8.0.1 (version code 1008)**, package `com.server.auditor.ssh.client`, APKM packaging.

| Patch | Selected by default | Scope |
|---|---|---|
| **Server Auditor Offline Automation** | Yes | Local startup-snippet Automation without a Termius account. Select alone; leaves global authentication and Pro state unchanged. Account-independent does not mean network-free SSH. |
| **Server Auditor Premium** | Yes | Optional legacy Pro title/expiry override. Does not enable account-free Automation or change storage/server entitlements. |
| **Premium unlock** | Yes | Plex client-side premium-check edits in the Hermes v96 bundle. Package `com.plexapp.android`, APKM; version-unpinned compatibility with required signatures, not a guarantee for every version or device. |

Both Termius patches are selected by default at the user's explicit request on **2026-11-09**; Plex remains selected by default. This is a default-selection metadata change only, recorded separately from donor behavior migration in [Termius provenance](docs/termius-migration.json). For isolated account-free Automation, the **select-alone** guidance means deselect Premium; it is not the collection default. Default co-selection does not establish combined Android runtime acceptance.

The Plex patch also conditionally removes split-install constraints from a decoded text manifest. It does not grant server-side entitlements or establish universal sideload support. See [Plex migration provenance](docs/plex-migration.json); supplied historical success notes are not fresh verification of this collection.

The user confirmed the **two Server Auditor patches** as **tested and working on 2026-11-09**. That confirmation does not cover Plex. This is accepted existing behavior, not a claim that a newly built collection MPP has passed Android execution or Manager import. Compilation, structural checks, local Manager import and hosted-source verification have separate statuses in [verification](docs/verification.md).

There are **no Universal patches** in this collection. No SpotifyTV patch is included or advertised. No vendor APKs, extracted application implementation or patched applications are distributed.

## Adding this source to Morphe

**Hosted-source discovery/download/update remains unverified.** The intended repository URL is:

`https://github.com/FISHYau/fishyau-morphe-patches`

After separately authorized bundle publication, Manager is intended to read:

`https://raw.githubusercontent.com/FISHYau/fishyau-morphe-patches/main/patches-bundle.json`

That manifest must point to the exact verified Android MPP. Pushing source alone or attaching an arbitrary release JAR is insufficient. No fake live manifest is included. Local MPP import was observed on 2026-11-10; it is not remote discovery/download/update proof.

## Build and verification

The collection targets JVM 17 using **JDK 21**, Gradle **9.8.2**, Morphe settings plugin **2.1.0** and patcher **2.3.0**. The required build is the official **`buildAndroid`** task; a JVM development JAR is not a Manager-ready MPP.

**Current status (2026-11-10):** official Android **build10** passed **121 Gradle cases**, and **freeze06** retained the exact MPP and same-byte catalog. Bounded final-MPP checks completed, and unchanged official **Morphe Manager 2.5.0** successfully imported that MPP on a NEW tooling-owned disposable emulator, displaying **FISHYau android patches**, version **0.1.0**, **3 patches** and **2 apps**. This proves local-source loading and displayed inventory, not Manager patch execution or app feature behavior. Partial observations remain `complete_evidence:false` and are not staging-ready. The frozen MPP binds the prior exact source tree; this source update, including documentation reconciliation and a separate `.gitattributes` byte-preservation fix, does not retroactively extend that whole-tree binding to the committed source. No binary rebuild is required merely for source commit/push, but the retained MPP must not be certified as built from the updated tree. Any future exact-tree release needs new matching build/freeze/observation bindings. The user's existing Termius acceptance stands; Plex Android acceptance, hosted discovery/download/update, complete staging and protected release review remain incomplete. Historical failures remain retained. See [verification](docs/verification.md) for evidence, exact bindings and qualifications.

Use the [canonical tooling](.claude/skills/run-android-morphe/SKILL.md) to build in an isolated external work copy and collect the exact bundle, catalog, hashes and test reports. All builds, caches, APK/DEX/MPP files, keys and private evidence stay **outside this source root**, even if ignored by Git. See [tooling notes](.claude/skills/run-android-morphe/NOTES.md) for invocation details and [verification status](docs/verification.md) for results and blockers.

The official GitHub Packages registry can require authenticated package-read access even for public packages. The Docker driver forwards existing `GITHUB_ACTOR` and `GITHUB_TOKEN` by **environment variable name**, not value, and does not mount user-level Gradle configuration. Provision credentials securely in the invoking process. **Never paste tokens into chat, put them on command lines or commit them.** Download approval alone does not supply package access. See [GitHub’s Gradle registry documentation](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-gradle-registry).

## Repository and release boundaries

- `patches/`: the three patch implementations, validator/Hermes/inventory tests and actual-loaded-definition catalog tooling.
- `tools/termius-check/`: source for bounded actual-patcher Termius structural verification, using explicit external input/tool/cache paths. The generic bytecode-only harness does not support Plex raw-resource edits.
- `tools/plex-check/`: isolated final-MPP Plex synthetic resource checker using the exact frozen schema-2 request; tools-only compilation and contract tests are not final-MPP or Android runtime observations.
- `tools/release/`: guarded exact-byte build freeze, validation, truthful pre-publication staging and protected publication handoff tooling.
- `.claude/skills/run-android-morphe/`: canonical inspection/build/emulator tools and regression tests.
- `docs/`: source contract, provenance, acceptance policy and measured verification results.

A staged candidate is **not published**. Git initialization, commits, pushes, repository/release creation and stable-manifest advancement are separate maintainer actions. A protected reviewer must authenticate the original evidence; self-authored JSON and matching hashes do not prove its truth. Publication must upload and re-download/hash approved assets **before** advancing the stable manifest, with no rebuild or stale approval reuse.

See [CONTRIBUTING.md](CONTRIBUTING.md), [source contract](docs/source-contract.md), [promotion policy](docs/promotion.md), [provenance](docs/provenance.md), [LICENSE](LICENSE), [NOTICE](NOTICE) and [THIRD_PARTY.md](THIRD_PARTY.md). Preserve applicable source notices and the distinct **FISHYau android patches** identity.
