# Local build and requested delivery

Develop and test locally. Publish through the GitHub source link **only when the user requests it**. No private runtime reports, candidate receipts, source-tree digests, expiry windows or second-reviewer infrastructure are required.

## 1. Build and check

Use the canonical `driver.py build` with an installed JDK21 Docker image and a NEW external output directory. Its default tasks are `:patches:test :patches:buildAndroid`, followed by same-artifact catalog generation. See [tooling notes](../.claude/skills/run-android-morphe/NOTES.md).

Select the resulting Android `.mpp` and matching `patches-list.json` explicitly. A JVM JAR is not an Android MPP. Run the applicable local [Termius](../tools/termius-check/README.md) and [Plex](../tools/plex-check/README.md) checks. Runtime testing can follow on-device delivery; do not require proof of the user's future device test before making its bundle available.

Report actual test results and limitations. The user has already confirmed Termius and Plex Android/Android TV behavior. Do not reopen that acceptance or misrepresent it as a new run.

## 2. Preview locally

From the repository root, with existing `gh` available for a later publish:

```text
python -I -B tools/publish.py --repository FISHYau/fishyau-morphe-patches --version VERSION --bundle ABS_MPP --catalog ABS_CATALOG --out NEW_EXTERNAL_DIR
```

Replace placeholders with explicit paths and a new version. Default mode validates locally and makes no remote writes. Use a different NEW output directory for the later publish invocation; do not reuse a failed/partial run.

The helper checks Android bundle metadata, unsigned bundle structure, version and current three-patch catalog, then generates the ordinary Manager manifest. It does not claim app runtime or hosted-source success. Do not advertise a public key for an unsigned bundle.

## 3. Publish when requested

After the user's explicit publication request, use the same command with **`--publish`** and a NEW external `--out`. Use normal existing `gh` authentication with necessary repository access. Do not paste or retrieve tokens, provision protected runners/environments, request administrative-read access or disable GitHub protections.

The publisher:

1. Checks the explicit repository and current `main` head; refuses conflicting tags/releases.
2. Uploads the selected public MPP/catalog without rebuilding or overwriting.
3. Downloads and compares their exact bytes.
4. Advances **`main/patches-bundle.json` last**, without a force update. Concurrent branch changes stop publication.

A failed operation is not success. Retain failed outputs; do not automatically delete remote assets, roll back or silently retry with different bytes. If an existing release or configured repository protection blocks the update, stop and report it.

Only public MPP/catalog/manifest content is delivered. Never upload app binaries, extracted vendor code, keys, account data, raw screenshots/logs or private build directories. Source commits/pushes remain separate requested Git operations; this cleanup does not execute either.

## 4. On-device testing

Add this source in unchanged official Morphe Manager:

`https://github.com/FISHYau/fishyau-morphe-patches`

Manager reads `main/patches-bundle.json`; see [the format contract](source-contract.md). Observe discovery, download/loading and the intended patch behavior on the user's device. An available URL or local MPP import alone is not proof of the full flow.

For optional local Manager tests, use the canonical owned-emulator driver to create/start a NEW run, verify/install the official Manager input, and drive its source/import UI. Prefer adding the hosted source after publication; a local MPP can also be selected through Manager's file picker. Use only recorded owned-run paths, capture diagnostics privately as needed, and confirm `stop` before cleanup. No separate Manager evidence assembler or visual-review JSON is required for delivery.
