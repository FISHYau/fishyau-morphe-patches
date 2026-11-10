#!/usr/bin/env python3
"""Assemble PRIVATE schema2 evidence from unchanged, pinned original records.

No producer, child process, device operation, signing, candidate or publication.
Run this trusted repository script with Python -I -B; see evidence.README.md.
"""
from __future__ import annotations

import argparse
import copy
import datetime as dt
import importlib.util
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    # Only fixed paths in this checkout, never paths supplied by an input record.
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Trusted repository module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


o = load("evidence_observations", REPO / "tools/release/observations.py")
m = load("evidence_manager", REPO / "tools/manager-check/manager_import.py")
s, r = o.s, o.r
require = r.require
MANAGER_SOURCE = REPO / "tools/manager-check/manager_import.py"
CHECKS = "local_import collection_identity patch_names defaults compatibility visual_inspection"
REQUIRED_COMMANDS = {"init", "create", "start", "isolate", "install", "push", "launch", "final-check", "stop"}
TRUST = ("Local original byte bindings and measured times, not authentication. "
         "Separate human visual checks are unauthenticated claims, not tool measurements. "
         "No Android feature-runtime acceptance, candidate, approval or publication.")


def pinned(path, sha):
    path = m.external(path)
    m.require_hash(path, sha)
    return path


def original_inputs(request, bundle, catalog, current):
    """Preflight the exact original bytes, never a staging summary reconstruction."""
    request, bundle, catalog = map(m.external, (request, bundle, catalog))
    records = {str(path): m.file_record(path) for path in (request, bundle, catalog)}
    require(len(records) == 3, "Distinct frozen input files required")
    tree = o.f.pristine_tree(REPO)
    raw, req = o.p.preflight(request, bundle, catalog, *tree, r, s)
    require(r.local_time(req["created_at"]) <= current, "Future original request")
    bound = o.binding(req, raw)
    m.exact(bound, m.BINDING_KEYS, "five-field original binding")
    require(type(req["schema"]) is int and req["schema"] == 2
            and bound["policy"] == s.COLLECTION_POLICY, "Only original schema2 collection supported")
    require(records == {str(path): m.file_record(path) for path in (request, bundle, catalog)},
            "Frozen input changed during preflight")
    require(records[str(request)]["sha256"] == bound["request_sha256"]
            and records[str(bundle)]["sha256"] == bound["bundle_sha256"]
            and records[str(catalog)]["sha256"] == bound["catalog_sha256"], "Original input binding differs")
    return req, bound, records, tree


def partial_original(root, pin, paths, bound, current):
    root = m.external(root)
    terminal = root / "partial.json"
    before = m.file_record(pinned(terminal, pin))
    report = o.recheck(root, now=current)
    require(m.file_record(terminal) == before, "Partial original changed during recheck")
    require(report["binding"] == bound, "Partial five-field binding differs")
    require(all(report["inputs"][key] == str(path) for key, path in
                zip(("request_path", "bundle", "catalog"), paths)), "Partial names different original inputs")
    fragments = report["fragments"]
    r.exact(fragments, "inspection structural plex", "required original fragments")
    require(isinstance(fragments["structural"], list) and len(fragments["structural"]) == 3
            and report["components"]["structural"]["status"] == "bounded-jvm-observed",
            "Actual three-case structural originals required")
    r.exact(fragments["plex"], "resource parser final_bundle", "dedicated original Plex fragments")
    # recheck() independently derives every fragment from its retained producer;
    # full staging validation below remains authoritative over the final DTO.
    return report, before


def manager_original(*, root, report_path, report_sha256, config_path, config_sha256,
                     review_path, review_sha256, bound, paths, request, current):
    """Read/revalidate an ORIGINAL report. Never call manager_report()/restamp it."""
    root = m.external(root)
    report_path = pinned(report_path, report_sha256)
    config_path = pinned(config_path, config_sha256)
    review_path = pinned(review_path, review_sha256)
    require(report_path.name == "manager-report.json" and report_path.parent.parent == root / "evidence",
            "Manager report must be the original session report artifact")
    report_record = m.file_record(report_path)
    require(callable(getattr(m, "recheck_report", None)) and callable(getattr(m, "validate_graph", None)),
            "Manager integration blocked: authoritative recheck_report/validate_graph APIs unavailable")
    report = m.recheck_report(report_path, report_sha256, current=current)
    session, config = m.checked_session(root, config_path, config_sha256)
    graph = m.validate_graph(root, session, current, require_shutdown=True)
    require(session["binding"] == bound == m.binding(config), "Manager five-field binding differs")
    require(all(config[name]["path"] == str(path) for name, path in zip(("request", "bundle", "catalog"), paths)),
            "Manager names different original inputs")
    closure = m.closure(config)
    require(closure["source_tree_sha256"] == bound["source_tree_sha256"], "Manager source closure differs")
    captures, events = m.capture_events(root, session, current)
    review = m.visual_review(review_path, review_sha256, session, captures, current)
    m.exact(report, ("schema", "binding", "assembled_at", "lifecycle", "status", "complete_evidence", "manager",
                     "tool_measurements", "human_claims", "unsupported", "trust"), "original Manager report")
    require(report["lifecycle"] == graph, "Original Manager lifecycle graph differs")
    require(report["schema"] == m.REPORT_SCHEMA and report["binding"] == bound
            and report["complete_evidence"] is False
            and report["status"] == "originals-collected-not-release-approval", "Incomplete original Manager report")
    assembled = m.instant(report["assembled_at"], current)
    reviewed = m.instant(review["claims"]["reviewed_at"], current)
    created = r.local_time(request["created_at"])
    capture_start = m.instant(graph["capture_started_at"], current)
    capture_end = m.instant(graph["capture_ended_at"], current)
    require(created <= capture_start <= capture_end <= reviewed <= assembled,
            "Original capture/review/report chronology differs")
    expected_checks = {name: {**row, "basis": "human-claim-not-tool-measurement"}
                       for name, row in review["claims"]["checks"].items()}
    require(all(row["status"] == "observed" for row in expected_checks.values()),
            "All original Manager visual checks must be observed")
    require(report["human_claims"] == {"checks": expected_checks, "review": review},
            "Original Manager review/checks changed or substituted")
    identity = {"version": "2.5.0", "apk_sha256": m.APK_SHA256, "certificate_sha256": m.CERT, "origin": m.ORIGIN}
    require(report["manager"] == identity, "Official Manager identity differs")
    measurements = report["tool_measurements"]
    m.exact(measurements, ("session", "device_owner", "events", "captures"), "original Manager measurements")
    require(measurements["session"] == m.file_record(root / "session.json")
            and measurements["device_owner"] == m.file_record(root / "device-owner.json")
            and measurements["captures"] == captures, "Original Manager session/owner/captures changed")
    require(report["unsupported"] == {"feature_behavior": "not-observed; no app patching/runtime in this helper",
            "hosted_integration": "not-observed", "installed_apk_bytes": "not-read-back"}, "Manager unsupported scope changed")
    require(report["trust"] == "Local original byte bindings and measured times, not authentication. Pending capture records are never rewritten. Not schema2 staging evidence.",
            "Manager original trust caveat changed")

    # capture_events() now sees the outer report event, which the report's own
    # snapshot necessarily did NOT see. Compare original records, not counts or
    # regenerated snapshots. Only actual newer successful report-only events may
    # be absent; no later unbound device event (including a capture) is allowed.
    snapshot = measurements["events"]
    require(isinstance(snapshot, list), "Original report event snapshot required")
    ids = [row["event"]["path"] for row in snapshot]
    require(len(set(ids)) == len(ids), "Duplicate original report event")
    require(snapshot == [row for row in events if row["event"]["path"] in ids],
            "Original report snapshot event changed/missing/reordered")
    own_event = str(report_path.parent / "result.json")
    require(own_event not in ids, "Report cannot include its own unfinished outer event")
    require(own_event in {row["event"]["path"] for row in events}, "Original report producing event missing")
    commands = set()
    for event in events:
        record = event["event"]
        row = m.read_json(record["path"], record["sha256"])
        require(record == m.file_record(record["path"]), "Original Manager event changed")
        require(row["ok"] is True, "Failed Manager event cannot establish complete observations")
        window = m.interval(row, current)
        require(created <= window[0], "Manager event predates original request")
        if row["command"] != "stop":
            require(row["closure_before"] == row["closure_after"] == closure,
                    "Original Manager source/tool/interpreter closure differs")
        if row["command"] == "report":
            require(row.get("device") is None and row.get("actions") == []
                    and row.get("isolation_trace") == [] and row.get("closure_exemption") is None,
                    "Report-only event contains device actions or closure exemption")
        if record["path"] in ids:
            require(window[1] <= assembled, "Snapshot event occurs after original report assembly")
            commands.add(row["command"])
        else:
            require(row["command"] == "report" and window[1] >= assembled,
                    "Unbound later device event or older omitted event")
            original_report = Path(record["path"]).parent / "manager-report.json"
            require(row["result"] == {"manager_report": m.file_record(original_report)},
                    "Newer event is not a genuine report-only event")
            later = m.read_json(original_report, row["result"]["manager_report"]["sha256"])
            require(later["schema"] == m.REPORT_SCHEMA and later["binding"] == bound
                    and window[0] <= m.instant(later["assembled_at"], current) <= window[1],
                    "Report-only event has unbound report/time")
            if record["path"] == own_event:
                require(row["result"] == {"manager_report": report_record}
                        and window[0] <= assembled <= window[1], "Original report restamped/outside producer interval")
            else:
                require(window[0] >= assembled, "Omitted report event is not newer")
    require(REQUIRED_COMMANDS <= commands, "Original Manager lifecycle/import/final-check/shutdown events missing")
    require(m.closure(config) == closure and m.file_record(report_path) == report_record,
            "Manager originals/closure changed during revalidation")
    m.require_hash(config_path, config_sha256)
    m.require_hash(review_path, review_sha256)
    # Device observation time comes from the original measured capture graph.
    # Neither human reviewed_at nor report assembled_at is a device event clock.
    fragment = {"kind": "manager-import", "platform": "android", "binding": copy.deepcopy(bound),
                "observed_at": o.utc(graph["capture_ended_at"], current),
                "tool": {"name": "Official Manager original-capture adapter", "version": "1",
                         "sha256": m.file_record(MANAGER_SOURCE)["sha256"]},
                "status": "passed", "checks": {name: "passed" for name in CHECKS.split()},
                "artifacts": [{"kind": "manager-report", "sha256": report_sha256},
                              {"kind": "visual-review", "sha256": review_sha256}], "manager": identity}
    s.observation(fragment, "manager-import", "android", bound, CHECKS, {"manager-report", "visual-review"}, current, "manager")
    snapshot = {"report": report_record, "config": m.file_record(config_path), "session": measurements["session"],
                "device_owner": measurements["device_owner"], "events": events, "captures": captures,
                "review": review, "closure": closure, "graph": graph, "helper": m.file_record(MANAGER_SOURCE)}
    return fragment, snapshot, config


def output_roots(partial_root, partial, manager_root, config, explicit_files):
    """Protect input containers as well as individual bytes from output placement."""
    roots = [REPO, m.external(partial_root), m.external(manager_root)]
    files = list(explicit_files) + list(partial["inputs"]["files"])
    roots += [m.absolute(partial["inputs"][key]) for key in ("jdk", "cache_root")]
    if "termius_identity" in partial:
        files += list(partial["termius_identity"]["initial_selection"]["files"])
    files += [row["path"] for row in config["tools"].values()]
    files += [row["path"] for row in (config[name] for name in ("request", "bundle", "catalog", "manager_apk"))]
    files += list(config["verification"].values())
    for value in files:
        path = m.absolute(value)
        roots.append(path if path.is_dir() else path.parent)
    return roots


def assemble(*, request, bundle, catalog, partial_root, partial_sha256, manager_root,
             manager_report, manager_report_sha256, manager_config, manager_config_sha256,
             visual_review, visual_review_sha256, plex_status, plex_scope, output, now=None):
    current = now or dt.datetime.now(r.UTC)
    require(plex_status in {"blocked", "not-observed"}, "No reviewed Plex runtime producer; observed runtime unsupported")
    r.text(plex_scope, "Verbatim Plex runtime blocker/scope")
    out = m.external(output)
    require(not out.exists() and out.parent.is_dir(), "NEW output with existing parent required")
    paths = tuple(map(m.external, (request, bundle, catalog)))
    explicit = (*paths, m.external(manager_report), m.external(manager_config), m.external(visual_review))
    # Before even validating inputs, do not place output inside their containers.
    for path in (*explicit, m.external(partial_root), m.external(manager_root)):
        m.disjoint(out, path if path.is_dir() else path.parent)

    def originals():
        req, bound, records, tree = original_inputs(*paths, current)
        partial, terminal = partial_original(partial_root, partial_sha256, paths, bound, current)
        manager, measured, config = manager_original(root=manager_root, report_path=manager_report,
            report_sha256=manager_report_sha256, config_path=manager_config, config_sha256=manager_config_sha256,
            review_path=visual_review, review_sha256=visual_review_sha256, bound=bound, paths=paths,
            request=req, current=current)
        return req, bound, records, tree, partial, terminal, manager, measured, config

    initial = originals()
    req, bound, records, tree, partial, terminal, manager, measured, config = initial
    for root in output_roots(partial_root, partial, manager_root, config, explicit):
        m.disjoint(out, root)
    evidence = {"schema": 2, "inspection": copy.deepcopy(partial["fragments"]["inspection"]),
                "structural": copy.deepcopy(partial["fragments"]["structural"]), "manager_import": manager,
                "plex": {**copy.deepcopy(partial["fragments"]["plex"]),
                         "runtime": {"status": plex_status, "scope": plex_scope, "artifacts": []}}}
    require(originals() == initial, "Originals/source changed before output")
    out.mkdir(mode=0o700, exist_ok=False)
    # Failures intentionally leave this consumed directory and any written files.
    evidence_path = out / "evidence.json"
    m.write_new(evidence_path, evidence)
    evidence_record = m.file_record(evidence_path)
    require(originals() == initial, "Originals/source changed before final validation")
    validated = s.validate(REPO, paths[1], paths[2], paths[0], evidence_path, now=current)
    require(validated["request"] == req, "Validator returned a different original request")
    require(originals() == initial, "Originals/source changed after final validation")
    require(m.file_record(evidence_path) == evidence_record, "Evidence changed during final validation")
    receipt = {"schema": "private-original-evidence-receipt-v1", "status": "validated-private-evidence-not-publication",
               "assembled_at": m.stamp(current), "binding": bound, "evidence": evidence_record,
               "frozen_inputs": records, "partial_original": terminal,
               "partial_retained_inventory": partial["artifact_index"], "manager_originals": measured,
               "plex_runtime": copy.deepcopy(evidence["plex"]["runtime"]), "evidence_authenticated": False,
               "trust": TRUST}
    receipt_path = out / "receipt.json"
    m.write_new(receipt_path, receipt)
    receipt_record = m.file_record(receipt_path)
    require(originals() == initial, "Originals/source changed during receipt output")
    require(m.file_record(evidence_path) == evidence_record and m.file_record(receipt_path) == receipt_record,
            "Private evidence/receipt changed during output")
    require({path.name for path in out.iterdir()} == {"evidence.json", "receipt.json"}, "Unexpected output entry")
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("request", "bundle", "catalog", "partial-root", "partial-sha256", "manager-root",
                 "manager-report", "manager-report-sha256", "manager-config", "manager-config-sha256",
                 "visual-review", "visual-review-sha256", "plex-scope", "output"):
        # Keep raw spelling for original-ancestry/dot/reparse checks.
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--plex-status", choices=("blocked", "not-observed"), required=True)
    try:
        directory = assemble(**vars(parser.parse_args(argv)))
        print(directory)
        return 0
    except (OSError, ValueError, TypeError, KeyError, m.Failure) as exc:
        print("Evidence blocked: " + type(exc).__name__ + ": " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
