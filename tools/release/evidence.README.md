# Private original-evidence assembler

`evidence.py` adapts **unchanged original records**, not caller-authored pass flags.
It performs no build, child execution, device operation, signing, credential use,
network request, candidate creation, Git operation or publication. Import paths
are fixed to trusted modules in this checkout. Run with installed Python `-I -B`.

## Inputs and invocation

This is an invocation template, **not an observed successful run**. Every path must
be explicit, absolute, local and free of symlink/junction/reparse ancestry. All
original inputs and private output belong outside the publication checkout.

```text
python -I -B tools/release/evidence.py --request ABS_ORIGINAL_REQUEST --bundle ABS_ORIGINAL_MPP --catalog ABS_ORIGINAL_CATALOG --partial-root ABS_ORIGINAL_OBSERVATIONS_DIRECTORY --partial-sha256 SHA256_OF_ORIGINAL_PARTIAL_JSON --manager-root ABS_ORIGINAL_MANAGER_SESSION --manager-report ABS_ORIGINAL_MANAGER_REPORT --manager-report-sha256 SHA256_OF_ORIGINAL_MANAGER_REPORT --manager-config ABS_ORIGINAL_CAPTURE_CONFIG --manager-config-sha256 SHA256_OF_ORIGINAL_CONFIG --visual-review ABS_ORIGINAL_SEPARATE_REVIEW --visual-review-sha256 SHA256_OF_ORIGINAL_REVIEW --plex-status blocked --plex-scope "VERBATIM ORIGINAL BLOCKER AND EXPLICIT SCOPE" --output ABS_NEW_PRIVATE_EXTERNAL_DIRECTORY
```

The callable API is `assemble(...)` with the same underscore-separated keyword
names, plus an optional injected `now` clock for synthetic tests. It returns the
new output directory only after all validation and final original-byte checks.
There is no supplied-evidence, pass override, request regeneration, observed Plex
runtime, legacy-schema upgrade or publication option.

Required originals:

- The **exact original schema2 request bytes**, genuine final Android MPP and
  matching catalog. Preflight validates original identity, collection metadata,
  provenance and actual source closure. Binding includes all five fields: policy,
  original request SHA-256 (including whitespace), bundle SHA-256, catalog SHA-256
  and source-tree SHA-256. A summary is never used to reconstruct a request.
- A successful-but-explicitly-incomplete `observations.py` session, with the
  original `partial.json` hash pinned independently. `observations.recheck()`
  revalidates the complete retained inventory, source, selected inputs, tool
  closures, exact children/logs, measurements and fragments. The session must
  actually contain inspection, three bounded Termius structural selections and
  dedicated Plex resource/parser/final-bundle fragments. The partial producer's
  status, timestamps and nonobservation fields are **never changed**.
- A pinned original official Manager report, its original session/config and the
  pinned **separate** original visual review. The authoritative helper APIs
  `recheck_report()` and `validate_graph()` must exist; missing APIs are an explicit
  integration blocker, not permission to accept aggregate flags. The assembler
  independently reopens the session/config, rechecks live source/tool closure,
  reads original events/capture pairs and calls `visual_review()` as well.
- A complete successful Manager lifecycle through confirmed shutdown, with original
  final-check evidence. All six original visual checks must be `observed`, with
  helper-required purpose-specific original PNG/XML references. A capture's label
  or bytes alone never establishes UI truth. Report checks must equal the separate
  review's checks and retain the unauthenticated-human-claim caveat.

Manager report assembly time is **not device observation time**. Schema2 Manager
`observed_at` is the original measured `capture_ended_at` from the authoritative
lifecycle graph, converted to offset-free UTC. Original `reviewed_at` must follow
all capture measurements and precede original report assembly. Original assembly
must fall inside its producing report event. Freshness checks reject stale/future
records; no report, event or review is regenerated or restamped by this adapter.
The Manager fragment tool hash is the actual helper source SHA-256, bound through
the original source closure, not a caller-selected executable or DTO field.

### Immutable report snapshot handling

The original report's event inventory cannot include its own unfinished outer
`report` event. A later fresh read necessarily sees that event and may see later
reports. Each original snapshot entry must match the freshly read original event
record exactly, in the original inventory order. Only genuine successful **newer
report-only** events may be absent from the original snapshot. The original
producing event must bind the exact pinned report bytes. Later device captures,
inputs, lifecycle events, missing/changed original records, report events with
device actions and unbound auxiliary reports are rejected. Historical snapshots
are not “refreshed” to bless later device observations.

## Plex boundary: deliberately no runtime promotion

Only explicit `--plex-status blocked` or `not-observed` is supported, with nonempty
`--plex-scope`. The supplied original blocker/scope is preserved **verbatim** in
both evidence and private receipt, not paraphrased into a pass. Runtime artifacts
are empty because there is no reviewed runtime producer to bind them.

The current Plex vendor-input gate lacks an account-free meaningful acceptance
path and no reviewed runtime producer exists. This assembler cannot infer Plex
runtime acceptance from JVM resource fixtures, source parser tests, installation,
launch, historical notes, Termius acceptance or a hand-written runtime report.
The parser fragment remains source-tested, not loaded-final-MPP parser execution;
resource fragments remain noninstallable synthetic HBC96 checks. Structural DEX
checks are bounded and not whole-APK, ART or app feature-runtime acceptance.

`staging.validate()` is the authoritative final evidence validator. It is called
against the actual output evidence bytes and **the original request/MPP/catalog**
before success. Staging can accept honest blocked/not-observed Plex status, but
the unchanged publisher rejects publication without its own observed Plex runtime
evidence. This tool neither creates a staged candidate nor invokes the publisher.

## Output and failure handling

Output must be **NEW**, with an existing parent, outside and disjoint from source,
original input containers (not merely their files), original observation/Manager
roots, pinned tool roots and selected-input containers. Existing outputs are never
reused. Files and the directory are created exclusively; no original is rewritten.
Hard-linked files and linked/reparse ancestry fail closed.

Successful output contains only:

- `evidence.json`: schema2 inspection/structural/Manager/Plex evidence accepted by
  `staging.validate`, with Plex runtime still blocked/not-observed.
- `receipt.json`: **private**, original input hashes/paths, complete partial retained
  inventory, Manager report/config/session/owner/event/capture/review/source/tool
  snapshots, original graph times, evidence hash and trust limitations. This is
  not a sanitized public verification summary or authentication record.

Original reports, retained records, source and tool closures are checked before
output, immediately before and after authoritative validation, and after receipt
output. Output hashes are also rechecked. Failures are raised/return CLI exit 2;
any created directory/files remain consumed failed output and must not be reused
or promoted. A file's presence or receipt text alone is not a successful invocation.
There is no cleanup or retry that blesses failed material. JSON output uses the
helper's bounded writer (8 MiB per document); an oversized receipt fails rather
than dropping inventory entries. No original binary or capture is copied.

Adding or changing this adapter, its tests, the Manager helper or any other source
changes the source-tree binding. Previously frozen requests for an older tree do
not become valid by reserializing or updating their hashes. Genuine original
producer sessions must bind the settled source tree; this tool does not create
such sessions or repair historical evidence.

Hashes and local recorded intervals establish byte binding and bounded report
consistency, **not authentication**, protected approval, first-party tool trust,
UI truth, or immunity to same-user restored-byte races. Endpoint closure checking
is not a process/filesystem isolation guarantee. Private originals still require
independent protected human review; this assembler does not claim such a review
has been authenticated or that publication prerequisites are configured.

## Synthetic tests

`tests/test_evidence.py` is synthetic-only. It uses nonexecutable local bytes and
explicit native-child/tool seams, checks real retained-index and schema validators,
and prohibits child processes. It must not be used as runtime evidence. Tests must
be source-reviewed before execution. The reviewed synthetic suite passed on Windows
and Linux during the release repair; measured counts and platform skips are recorded
in [verification status](../../docs/verification.md). Those tests do not establish a
real invocation against new Manager originals, a current-tree build or runtime
acceptance.
