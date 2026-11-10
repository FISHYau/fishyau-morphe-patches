# Requested test-bundle delivery

Use [local build and requested delivery](release-handoff.md) for the current workflow and [source compatibility](source-contract.md) for the Manager manifest format.

The collection remains Server Auditor Offline Automation, Server Auditor Premium and Plex Premium unlock, all enabled by default. Local compilation, unit tests and actual MPP/resource/DEX checks support development. The user confirmed Termius behavior on 2026-11-09 and Plex Android/Android TV behavior on 2026-11-10; do not portray those confirmations as new assistant-run checks of a later bundle.

There is no source-tree digest, frozen request, mandatory private runtime report, candidate receipt, protected reviewer or CI publication handoff. Historical migration records and private runs remain historical, not release gates.

Only publish through the GitHub source link when the user requests it. Ordinary pushes, PRs and verification runs never publish. Upload the selected checked MPP/catalog, compare downloadable bytes and update the ordinary discovery manifest last. Keep app binaries, keys and private diagnostics outside Git/public assets. Do not claim hosted discovery or runtime success before actually testing it.
