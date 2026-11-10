#!/usr/bin/env python3
"""PRIVATE, incomplete JVM observation fragments; never schema-2 complete evidence.

Execute only with a genuine final MPP and an unchanged preexisting freeze request.
Uses the supported source runner and Plex wrapper, not a second compiler pipeline.
Termius structural execution requires an explicit independently pinned selection.
No Manager, ART, signing, devices, approval, staging or publication is performed.
"""
from __future__ import annotations

import argparse
import datetime as dt
import importlib.util
import os
from pathlib import Path
import subprocess
import stat
import sys
import time

REPO = Path(__file__).resolve().parents[2]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Trusted repository code only. Never import a module from the evidence directory.
f = load("observations_freeze", Path(__file__).with_name("freeze.py"))
s, r = f.s, f.r
p = load("observations_plex", REPO / "tools/plex-check/final_bundle.py")
j = load("observations_source", REPO / "tools/termius-check/run_jvm_checks.py")
si = load("observations_selected_identity", REPO / "tools/termius-check/selected_identity.py")
require = r.require


def regular(path, limit=r.MAX_BUNDLE):
    return f.regular(Path(path), limit)


def read(path):
    return p.parse_json(regular(path, r.MAX_JSON))


def file_record(path):
    # Stream large installed JDK payloads (lib/modules can exceed MAX_BUNDLE).
    path = f.ancestry(path)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "regular unaliased file required")
    digest = j.digest(path)
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), "file changed while hashing")
    return {"size": after.st_size, "sha256": digest}


def inventory(root):
    root = f.ancestry(root)
    require(root.is_dir(), "inventory directory required")
    names = f.walk_files(root)
    require(len({name.casefold() for name in names}) == len(names), "case-aliased retained file names")
    result, identities = {}, set()
    for name in names:
        path = root / name
        info = path.stat()
        identity = (info.st_dev, info.st_ino)
        require(identity not in identities, "duplicate retained file identity")
        identities.add(identity)
        result[name] = file_record(path)
    return result


def utc(value, now):
    """Convert an actual recorded event, never stamp an adaptation time."""
    instant = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(instant.tzinfo is not None, "offset-aware producer event required")
    instant = instant.astimezone(r.UTC)
    result = instant.replace(tzinfo=None).isoformat(timespec="microseconds")
    r.fresh(result, now)
    return result


def interval(row, now, *, end="ended_at", duration="duration_ns", within=None):
    start, finish = utc(row["started_at"], now), utc(row[end], now)
    require(start <= finish and type(row[duration]) is int and row[duration] > 0,
            "invalid measured event interval")
    if within is not None:
        require(within[0] <= start <= finish <= within[1], "event outside its executing child")
    return start, finish


def binding(request, raw):
    return {**{k: request[k] for k in ("policy", "bundle_sha256", "catalog_sha256", "source_tree_sha256")},
            "request_sha256": r.digest(raw)}


def fragment(kind, checks, artifacts, tool, bound, event, now, **extra):
    result = dict(kind=kind, platform="jvm", binding=bound, observed_at=utc(event, now),
                  tool=tool, status="passed", checks={key: "passed" for key in checks.split()},
                  artifacts=artifacts, **extra)
    # The staging validator is authoritative for the DTO, not a parallel schema.
    s.observation(result, kind, "jvm", bound, checks, {a["kind"] for a in artifacts}, now,
                  " ".join(extra))
    return result


def artifact(kind, path):
    return {"kind": kind, "sha256": file_record(path)["sha256"]}


def tools(jdk, cache):
    jdk, cache = f.ancestry(jdk), f.ancestry(cache)
    require(jdk.is_dir() and cache.is_dir(), "explicit installed JDK/cache required")
    require('JAVA_VERSION="21.' in regular(jdk / "release").decode(), "installed JDK21 required")
    closure_path = REPO / ".claude/skills/run-android-morphe/templates/cache-closure.json"
    closure = read(closure_path)
    require((closure["patcher_version"], closure["compiler_version"]) == ("2.3.0", "2.4.21"), "wrong closure")
    compiler = [j.resolve(cache, *row) for row in closure["compiler"]]
    runtime = [j.resolve(cache, *row) for row in closure["runtime"]]
    tests = [j.resolve(cache, name) for name in ("junit:junit:4.13.2", "org.hamcrest:hamcrest-core:1.3")]
    deps = list(dict.fromkeys(compiler + runtime + tests))
    # Validate original path ancestry too; resolve() must not hide a linked cache directory.
    coordinates = [row[0] for row in closure["compiler"] + closure["runtime"]] + ["junit:junit:4.13.2", "org.hamcrest:hamcrest-core:1.3"]
    for coordinate in coordinates:
        group, name, version = coordinate.split(":")
        for candidate in (cache / group / name / version).glob(f"*/{name}-{version}.jar"):
            f.ancestry(candidate)
    for path in deps:
        file_record(path)
    return dict(jdk=jdk, cache=cache, java=jdk / "bin/java.exe", compiler=compiler, runtime=runtime,
                tests=tests, deps=deps, closure_sha256=file_record(closure_path)["sha256"])


def tool_snapshot(config):
    return {"jdk": inventory(config["jdk"]),
            "dependencies": {path.relative_to(config["cache"]).as_posix(): file_record(path) for path in config["deps"]},
            "python": file_record(Path(sys.executable))}


def isolated(paths):
    p.isolated_classpath(paths)
    # Also exclude *all* source Termius classes, not just the two definitions.
    import zipfile
    for path in paths:
        with zipfile.ZipFile(path) as jar:
            require(not any(name.startswith("io/github/fishyau/androidpatches/termius/")
                            for name in jar.namelist()), "Termius source classes contaminate parent loader")


def verify_source_run(root, config, before_tools, now, child_interval):
    """Strict current measured producer only; aggregate/old reports fail closed."""
    report = read(root / "jvm-checks.json")
    require(report.get("schema") == "scoped-jvm-checks-v3" and report.get("scope") == "collection"
            and report.get("status") == "collection_uncached_jvm_compilation_tests_passed", "fresh measured collection run required")
    require(report["source_root"] == str(REPO) and report["output_root"] == str(root), "source/output identity mismatch")
    producer_window = interval(report, now, within=child_interval)
    actual = inventory(root)
    del actual["jvm-checks.json"]
    require(actual == report["output_inventory"], "source retained output inventory mismatch")
    require(j.source_tree(REPO) == report["source_tree_before"] == report["source_tree_after"], "source measurement changed")
    ti = report["tool_inventory"]
    require(ti["jdk_root"] == str(config["jdk"]) and ti["dependency_root"] == str(config["cache"]), "tool root mismatch")
    for key, expected in (("jdk", before_tools["jdk"]), ("dependencies", before_tools["dependencies"])):
        require(ti[key + "_before"] == ti[key + "_after"] == expected, "tool inventory mismatch")
    for key, expected in (("compiler_classpath", config["compiler"]), ("runtime_classpath", config["runtime"]), ("test_classpath", config["tests"])):
        require(ti[key] == list(map(str, expected)), "classpath substitution")
    require(report["closure_sha256"] == config["closure_sha256"] and report["java_sha256"] == file_record(config["java"])["sha256"], "closure/Java mismatch")
    main, tests, _, checkers, classes = j.select_sources(REPO, "collection")
    selected = list(dict.fromkeys(main + tests + checkers + [REPO / "tools/termius-check/src/test/java/MeasuredJUnit.java", REPO / "tools/termius-check/run_jvm_checks.py"]))
    require(report["source_hashes"] == {path.relative_to(REPO).as_posix(): file_record(path)["sha256"] for path in selected}, "compiled source hashes mismatch")
    require(report["definition_count"] == 3 and report["excluded_main_sources"] == [] and report["test_classes"] == classes, "wrong compilation scope")
    require(report["test_artifacts"] == {str(path): file_record(path)["sha256"] for path in config["tests"]}, "test dependencies changed")
    measured = read(root / "junit-measurements.json")
    require(report["junit"] == measured, "retained measured JUnit differs")
    required = j.required_cases(REPO, classes)
    require(j.validate_junit(measured, classes, required) == report["executed_cases"] == 121, "complete current cases required")
    # Independently constrain the reviewed floor and source parameter expansion.
    _, entries = f.pristine_tree(REPO)
    expected = f.expected_tests(REPO, entries)
    require({(cls, method) for cls, method, _ in required} == {(cls, method) for cls, methods in expected.items() for method in methods}, "reviewed source case inventory differs")
    steps = report["steps"]
    require([row["step"] for row in steps] == ["compile-definitions", "compile-tests", "compile-junit-reporter", "junit", "compile-checker"], "missing/duplicate producer steps")
    for row in steps:
        require(row.get("exit_code") == 0 and not row.get("timed_out"), "failed child step")
        interval(row, now, within=producer_window)
        log = root / (row["step"] + ".log")
        require(row["log"] == {"path": str(log), **file_record(log)}, "step log changed")
    test_window = interval(steps[3], now)
    measured_window = interval(measured, now, within=test_window)
    for case in measured["cases"]:
        interval(case, now, within=measured_window)
    require(report["outputs"] == {name: file_record(root / name)["sha256"] for name in ("definitions-JVM-ONLY.jar", "tests.jar", "checker.jar")}, "compiled JAR changed")
    classpath = [root / "checker.jar", *config["runtime"]]
    require(report["checker_runtime_classpath"] == os.pathsep.join(map(str, classpath)), "source/test classpath contamination")
    isolated(classpath)
    return report, measured, classpath


def adapt_inspection(path, catalog, bound, checker, now, window):
    native = read(path)
    require(native.get("schema") == "termius-bundle-inspection-v1" and native.get("status") == "jvm_actual_loader_metadata_verified", "actual loader inspection required")
    require(native["bundle_sha256"] == bound["bundle_sha256"] and native["catalog_sha256"] == bound["catalog_sha256"], "inspection binding mismatch")
    require(native["loader"] == "app.morphe.patcher.patch.loadPatchesFromJar" and native["android_bundle_load"] == "not_observed"
            and native["dex_check"] == "classes.dex_magic_only_not_ART", "wrong inspection scope")
    event = utc(native["observed_at"], now)
    require(window[0] <= event <= window[1], "inspection event outside child")
    patches = s.collection_inventory(catalog, "0.1.0")
    require(native["patches"] == patches and native["dependencies"] == {name: [] for name in sorted(s.COLLECTION_PATCHES)}
            and list(native["dependencies"]) == sorted(s.COLLECTION_PATCHES), "loaded DTO/dependency mismatch")
    require(native["patcher_version"] == "2.3.0" and native["about"] == {"name": "FISHYau android patches", "author": "FISHYau"}
            and native["signing"] == "unsigned", "loaded identity mismatch")
    require(all(native["manifest"].get(k) == v for k, v in {"name": "FISHYau android patches", "author": "FISHYau", "version": "0.1.0", "patcher-version": "2.3.0"}.items()), "actual manifest mismatch")
    return fragment("bundle-inspection", "target_patcher_load actual_definitions metadata android_dex",
                    [artifact("loader-report", path)], {"name": "InspectBundle tools-only JVM", "version": "1", "sha256": file_record(checker)["sha256"]},
                    bound, native["observed_at"], now, **{key: native[key] for key in ("patcher_version", "patches", "dependencies", "about", "signing")})


def adapt_plex(root, request, bound, config, now, window, bundle, catalog):
    wrapper, native = read(root / "checker.json"), read(root / "native.json")
    inventory(root)  # Reject all linked/special/aliased retained files before native reads.
    require(wrapper.get("schema") == "plex-final-bundle-wrapper-v1" and wrapper.get("mode") == "check"
            and wrapper.get("status") == p.SUCCESS and wrapper.get("inputs_unchanged") is True, "compile-only/failed/partial is not native evidence")
    require(wrapper["request_sha256"] == bound["request_sha256"] and wrapper["source_root"] == str(REPO)
            and wrapper["source_tree_sha256"] == wrapper["source_tree_sha256_after"] == bound["source_tree_sha256"], "wrapper binding mismatch")
    wrapper_window = interval(wrapper, now, end="finished_at", duration="elapsed_ns", within=window)
    require(native["patches"] == s.collection_inventory(read(catalog), "0.1.0")
            and native["dependencies"] == {name: [] for name in sorted(s.COLLECTION_PATCHES)}
            and list(native["dependencies"]) == sorted(s.COLLECTION_PATCHES), "native loaded catalog/dependencies mismatch")
    require(wrapper["compiled_sources"] == [str(path.relative_to(REPO)) for path in p.select_sources(REPO)], "wrong Plex checker sources")
    checker = root / "checker-tools-only.jar"
    require(wrapper["checker_sha256"] == file_record(checker)["sha256"], "compiled Plex checker changed")
    cp = [checker, *config["runtime"]]
    isolated(cp)
    require(wrapper["parent_classpath_inventory"] == p.isolated_classpath(cp)
            and wrapper["parent_classpath"] == native["parent_classpath"] == os.pathsep.join(map(str, cp)), "Plex classpath contamination")
    require(wrapper["native_report"] == {"path": str(root / "native.json"), "sha256": file_record(root / "native.json")["sha256"]}, "native report changed")
    expected_inputs = list(dict.fromkeys([REPO / "tools/plex-check/final_bundle.py", REPO / "tools/release/release.py", REPO / "tools/release/staging.py",
        REPO / ".claude/skills/run-android-morphe/templates/cache-closure.json", config["java"], config["jdk"] / "release",
        config["jdk"] / "bin/server/jvm.dll", config["jdk"] / "lib/modules", *config["compiler"], *config["runtime"], *p.select_sources(REPO),
        root.parent / "frozen-request.json", bundle, catalog]))
    require(wrapper["input_sha256"] == {str(path): file_record(path)["sha256"] for path in expected_inputs}, "Plex retained inputs incomplete/changed")
    require(r.digest(regular(root / "frozen-request.json")) == bound["request_sha256"], "Plex exact request copy changed")
    expected_argv = [str(config["java"]), "-Djava.io.tmpdir=" + str(root / "tmp"), "-cp", os.pathsep.join(map(str, cp)),
        "io.github.fishyau.androidpatches.plexcheck.FinalBundleCheckKt", str(bundle), str(catalog), str(root / "frozen-request.json"),
        str(root / "native.json"), str(root / "cases"), bound["source_tree_sha256"], str(REPO)]
    commands = wrapper["commands"]
    require([row["step"] for row in commands] == ["java-version", "compile", "actual-final-bundle"], "native execution step missing/duplicate")
    compile_argv = list(map(str, [config["java"], "-Xmx1024m", "-Djava.io.tmpdir=" + str(root / "tmp"), "-cp", os.pathsep.join(map(str, config["compiler"])),
        "org.jetbrains.kotlin.cli.jvm.K2JVMCompiler", "-no-stdlib", "-no-reflect", "-jvm-target", "17", "-classpath",
        os.pathsep.join(map(str, config["runtime"])), "-d", checker, *p.select_sources(REPO)]))
    require(commands[0]["argv"] == [str(config["java"]), "-version"] and commands[1]["argv"] == compile_argv
            and commands[2]["argv"] == expected_argv, "unsupported/substituted native child command")
    for row in commands:
        require(row.get("exit_code") == 0 and row.get("status") != "timeout", "native command failed")
        interval(row, now, end="finished_at", duration="elapsed_ns", within=wrapper_window)
        log = root / (row["step"] + ".log")
        require(row["log"] == {"path": str(log), "sha256": file_record(log)["sha256"]}, "Plex log changed")
    native_window = interval(commands[-1], now, end="finished_at", duration="elapsed_ns")
    native_run_window = interval(native, now, end="finished_at", duration="elapsed_ns", within=native_window)
    for case in native["cases"]:
        case_window = interval(case, now, end="finished_at", duration="elapsed_ns", within=native_run_window)
        for call in case["execute_calls"]:
            interval(call, now, end="finished_at", duration="elapsed_ns", within=case_window)
        case_root = root / "cases" / case["name"]
        for key in ("fixture_zip", "input_bundle", "expected_bundle", "output_bundle", "input_manifest", "output_manifest", "unrelated_resource"):
            path = f.ancestry(case[key]["path"])
            require(path.is_relative_to(case_root), "retained native reference escapes case")
        for key, snapshot in (("working_bundle", "output_bundle"), ("working_manifest", "output_manifest")):
            path = f.ancestry(case[key])
            require(path.is_relative_to(case_root), "working native reference escapes case")
            # Context.close may clean working files. If retained, they must still
            # equal the producer's recorded final snapshot, not newly blessed bytes.
            if path.exists():
                require(case[snapshot]["exists"] is True and file_record(path) ==
                        {"size": case[snapshot]["bytes"], "sha256": case[snapshot]["sha256"]}, "working native file changed")
        if case["name"] == "idempotence":
            require(file_record(case_root / "first-output.bundle") ==
                    {"size": case["output_bundle"]["bytes"], "sha256": case["output_bundle"]["sha256"]}, "retained first execution changed")
    cases = p.validate_native(native, root, bound["request_sha256"], request)
    require(wrapper["cases"] == cases, "wrapper/native measured cases differ")
    tool = {"name": "Plex final-MPP tools-only JVM", "version": "1", "sha256": file_record(checker)["sha256"]}
    result = {}
    for key in ("resource", "final_bundle"):
        kind, checks, kinds = s.PLEX_REPORTS[key]
        result[key] = fragment(kind, checks, [artifact(k, root / "native.json") for k in sorted(kinds)], tool,
                               bound, native["finished_at"], now)
    return result


OFFLINE, PREMIUM = "Server Auditor Offline Automation", "Server Auditor Premium"
PRO = "Lcom/server/auditor/ssh/client/models/UserType$Pro;"
STORAGE = "Lcom/server/auditor/ssh/client/app/a;"
TERMINAL = "Lcom/crystalnix/termius/libtermius/wrappers/TerminalConnectionManager;"
LOCAL_EDITOR = "Lcom/server/auditor/ssh/client/fragments/editors/local/base/c;"
WIDGET = "Lcom/server/auditor/ssh/client/widget/editors/SnippetEditorLayout;"
PRESENTER = "Lcom/server/auditor/ssh/client/presenters/SshConfigEditorPresenter;"
OFFLINE_METHODS = sorted([WIDGET + "->setState(Lbs/h;)V", "Lci/w;->vb()V",
    TERMINAL + "->startConnection(Lcom/server/auditor/ssh/client/models/connections/Connection;Z)I"])
PREMIUM_METHODS = sorted(["Lcm/c;->c(Ljava/lang/String;)Lcom/server/auditor/ssh/client/models/UserType;", PRO + "->isExpired()Z"])
OWNERS = sorted(["Lcm/c;", PRO, STORAGE, TERMINAL, LOCAL_EDITOR, WIDGET, PRESENTER,
    "Lci/w;", "Lci/w$p;", "Lbs/i;", "Ltr/h0;", "Lgh/z;",
    "Lcom/server/auditor/ssh/client/fragments/editors/base/c;",
    "Lcom/server/auditor/ssh/client/database/DataLoadingHelper;",
    "Lcom/server/auditor/ssh/client/synchronization/api/models/user/AccountResponse;",
    "Lcom/server/auditor/ssh/client/onboarding/OnboardingActivity;"])
METHOD_DATA = "flags/registers/tries/instructions/operands/normalized-control-flow; excludes debug metadata, class metadata and fields"
DIGEST_FORMAT = "SHA-256 of metadataGson UTF-8 JSON: sorted method-key map of ordered bounded snapshot string arrays"
MANIFEST_FORMAT = "UTF-8; numeric contiguous DEX order; name TAB decimal-size TAB lowercase-sha256 LF"
# name -> expected diagnostic, already-patched flag, selected patch, fixture-maker DEX directory
NEGATIVES = {
    "repeat": ("snippet widget", True, OFFLINE, "dex"),
    "widget-only": ("snippet widget", True, OFFLINE, "widget-only/fixture-dex"),
    "ssh-only": ("SSH Automation", True, OFFLINE, "ssh-only/fixture-dex"),
    "terminal-only": ("terminal Automation", True, OFFLINE, "terminal-only/fixture-dex"),
    "wrong-widget-helper": ("snippet widget", False, OFFLINE, "wrong-widget-helper/fixture-dex"),
    "wrong-result-register": ("SSH Automation", True, OFFLINE, "wrong-result-register/fixture-dex"),
    "wrong-branch-target": ("terminal Automation", False, OFFLINE, "wrong-branch-target/fixture-dex"),
    "global-pro-override": ("storage Pro getter", True, OFFLINE, "global-pro-override/fixture-dex"),
    "premium-repeat": ("mapper", True, PREMIUM, "premium-dex"),
}
POSITIVES = [([OFFLINE], OFFLINE_METHODS, "dex"), ([PREMIUM], PREMIUM_METHODS, "premium-dex"),
             ([OFFLINE, PREMIUM], sorted(OFFLINE_METHODS + PREMIUM_METHODS), "combined-dex")]


def structural_work(root):
    # RuntimeCheck's deterministic retained sibling, inside this NEW session.
    # Never remove it from the whole-run artifact index or treat it as emitted DEX.
    return root.with_name(root.name + "-work")


def structural_argv(config, cp, bundle, base, root, catalog):
    return list(map(str, [config["java"], "-Djava.io.tmpdir=" + str(root.parent), "-cp", os.pathsep.join(map(str, cp)),
        "RuntimeCheckKt", bundle, base, root, catalog, REPO]))


def emitted_graph(root, native, base):
    """All 19 deterministic inventories and nine fixture-maker correspondence edges."""
    strict_tree_paths(root)
    indexed = inventory(root)
    directories = [row[2] for row in POSITIVES] + [name + "/rejected-dex" for name in NEGATIVES]
    directories += [name + "/fixture-dex" for name in NEGATIVES if name not in ("repeat", "premium-repeat")]
    rows = native["emitted_outputs"]
    require(type(rows) is list and len(rows) == len(directories) == 19, "complete 19-inventory graph required")
    by_directory = {}
    expected_files, expected_manifests = set(), set()
    for row in rows:
        require(type(row) is dict and set(row) == {"directory", "dex_inventory", "manifest_path", "output_sha256", "manifest_format"}, "exact emitted measurement required")
        directory = si.canonical(row["directory"])
        require(directory.is_relative_to(root), "emitted directory escape")
        name = directory.relative_to(root).as_posix()
        require(name in directories and name not in by_directory, "unexpected/duplicate emitted directory")
        by_directory[name] = row
        manifest = directory.parent / (directory.name + "-manifest.tsv")
        require(row["manifest_path"] == str(manifest) and row["manifest_format"] == MANIFEST_FORMAT, "manifest reference/format mismatch")
        actual = inventory(directory)
        ordered = si.canonical_driver().SPLITSET.canonical_dex(list(actual))
        measured = [{"name": item, **actual[item]} for item in ordered]
        require(all(type(item.get("size")) is int for item in row["dex_inventory"]) and row["dex_inventory"] == measured, "emitted DEX inventory changed")
        data = "".join(f"{item['name']}\t{item['size']}\t{item['sha256']}\n" for item in measured).encode("utf-8")
        require(regular(manifest) == data and row["output_sha256"] == r.digest(data), "exact DEX manifest bytes changed")
        expected_files.update((directory / item).relative_to(root).as_posix() for item in ordered)
        expected_manifests.add(manifest.relative_to(root).as_posix())
    require(set(by_directory) == set(directories), "missing emitted graph node")
    require({name for name in indexed if name.lower().endswith(".dex")} == expected_files
            and {name for name in indexed if name.lower().endswith(".tsv")} == expected_manifests, "unreferenced DEX/manifest output")
    require({name for name in indexed if name.lower().endswith(".apk")} ==
            {name + "/fixture-NOT-INSTALLABLE.apk" for name in NEGATIVES}, "unreferenced/missing fixture")

    def zip_inventory(path):
        driver = si.canonical_driver()
        budget = driver.Budget()
        archive = driver._validated_zip(path, budget)
        try:
            result = {}
            for member in archive.infolist():
                size, digest, _ = driver._read_member(archive, member, budget)
                result[member.filename] = {"size": size, "sha256": digest}
            return result
        finally:
            driver._close_zip(archive)

    original = zip_inventory(base)
    non_dex = {name: value for name, value in original.items() if not (name.startswith("classes") and name.endswith(".dex"))}
    for name, (_, _, _, maker) in NEGATIVES.items():
        expected = {**non_dex, **{row["name"]: {key: row[key] for key in ("size", "sha256")} for row in by_directory[maker]["dex_inventory"]}}
        require(zip_inventory(root / name / "fixture-NOT-INSTALLABLE.apk") == expected, "fixture-maker/base-payload correspondence mismatch")
    return by_directory


def adapt_structural(root, catalog, bound, base, cp, source, now, window, bundle):
    """One strict validator used both after execution and by terminal recheck.

    The parent preflight alone owns exact request2 validation. This does not infer
    execution from aggregates, logs, PASS strings, an exit code or old JSON.
    """
    root = si.canonical(root)
    path = root / "structural-check.json"
    native = read(path)
    require(native.get("schema") == "termius-structural-check-v3" and native.get("status") == "bounded_structural_checks_passed"
            and not (root / "structural-check-failed.json").exists(), "current successful measured structural report required")
    producer_window = interval(native, now, duration="elapsed_ns", within=window)
    require(native["observed_at"] == native["ended_at"] and native["invocation"] == list(map(str, [bundle, base, root, catalog, REPO]))
            and native["request_authority"] == "parent_exact_request2_preflight_only", "structural invocation/authority mismatch")
    isolated(cp)
    require(native["parent_classpath"] == os.pathsep.join(map(str, cp)), "structural parent classpath mismatch")
    work = si.canonical(structural_work(root))
    require(work.is_dir() and native["work_directory"] == str(work), "structural retained work directory mismatch")
    strict_tree_paths(work)  # Also reject empty linked/reparse scratch directories.
    require(native["bundle_sha256"] == bound["bundle_sha256"] and native["catalog_sha256"] == bound["catalog_sha256"]
            and native["input_base_sha256"] == file_record(base)["sha256"] == si.MEMBERS["base.apk"][1], "structural input binding mismatch")
    require(native["patches"] == s.collection_inventory(read(catalog), "0.1.0")
            and native["dependencies"] == {name: [] for name in sorted(s.COLLECTION_PATCHES)}
            and list(native["dependencies"]) == sorted(s.COLLECTION_PATCHES), "structural loaded metadata differs from catalog")
    for key, expected in {"patcher_version": "2.3.0", "definition_scope": "exact_three_collection_definitions",
            "application_scope": "Termius_only_singletons_and_combined", "plex_application": "not_supported_not_attempted",
            "snapshot_digest_format": DIGEST_FORMAT, "android_bundle_load": "not_observed", "manager_import": "not_observed",
            "device_behavior": "not_observed", "output_kind": "unsigned_incomplete_noninstallable_structural_fixtures"}.items():
        require(native[key] == expected, "structural scope/nonobserved field mismatch: " + key)
    scope = native["comparison_scope"]
    count = scope["methods"]
    require(type(count) is int and count > len(OFFLINE_METHODS + PREMIUM_METHODS), "invalid compared-method count")
    require(scope == {"kind": "selected_classes_only_not_whole_app", "methods": count, "explicit_owners": OWNERS,
            "nested_owner_prefixes": [LOCAL_EDITOR[:-1] + "$", PRESENTER[:-1] + "$"], "method_data": METHOD_DATA}, "comparison scope differs")
    outputs = emitted_graph(root, native, base)
    rows = native["selections"]
    require(type(rows) is list and len(rows) == 3, "three exact selections required")

    def results(row, names, rejected=False):
        actual = row["patch_results"]
        require(type(actual) is list and len(actual) == len(names) and all(type(item) is dict and set(item) == {"name", "error"} for item in actual)
                and sorted(item["name"] for item in actual) == names, "exact selected patch-result multiplicity required")
        require(all(isinstance(item["error"], str) and item["error"].strip() if rejected else item["error"] is None for item in actual), "patch result error semantics mismatch")
        return actual

    for row, (names, changed, directory) in zip(rows, POSITIVES):
        interval(row, now, duration="elapsed_ns", within=producer_window)
        require(row["selected"] == names and row["changed_methods"] == changed and type(row["changed_method_count"]) is int
                and row["changed_method_count"] == len(changed), "wrong exact selection/changed-method set")
        require(type(row["compared_methods"]) is int and row["compared_methods"] == count
                and row["status"] == "applied_emitted_reread_verified" and row["reread_verified"] is True
                and row["controlflow_verified"] is True and row["emitted"] == outputs[directory], "positive structural result mismatch")
        results(row, names)
    negatives = native["negative_measurements"]
    require(native["negative_cases"] == ["repeat", "premium-repeat", *[name for name in NEGATIVES if name not in ("repeat", "premium-repeat")]], "negative case declaration differs")
    require(type(negatives) is list and [row["name"] for row in negatives] == list(NEGATIVES), "nine distinct ordered negative cases required")
    for row in negatives:
        name = row["name"]
        diagnostic, already, selected, _ = NEGATIVES[name]
        interval(row, now, duration="elapsed_ns", within=producer_window)
        fixture = root / name / "fixture-NOT-INSTALLABLE.apk"
        require(row["selected"] == [selected] and row["expected_diagnostic"] == diagnostic
                and row["requires_already_patched"] is already and row["diagnostic_matched"] is True
                and row["status"] == "expected_rejection_unchanged_bounded_snapshot", "negative diagnostic/selection policy mismatch")
        actual = results(row, [selected], rejected=True)
        messages = row["rejection_diagnostic"]
        require(type(messages) is str and diagnostic in messages and (not already or "already patched" in messages)
                and all(line in actual[0]["error"] for line in messages.splitlines())
                and diagnostic in actual[0]["error"], "negative result/diagnostic mismatch")
        before = row["before_snapshot_sha256"]
        require(type(before) is str and len(before) == 64 and all(c in "0123456789abcdef" for c in before)
                and before == row["after_snapshot_sha256"] and row["snapshots_equal"] is True
                and type(row["compared_methods"]) is int and row["compared_methods"] == count, "negative bounded snapshot/count mismatch")
        require(row["fixture_path"] == str(fixture) and row["fixture_sha256"] == file_record(fixture)["sha256"]
                and row["emitted"] == outputs[name + "/rejected-dex"], "negative fixture/output mismatch")
    chronological = [rows[0], *negatives[:-1], rows[1], negatives[-1], rows[2]]
    previous = producer_window[0]
    for row in chronological:
        event_window = interval(row, now, duration="elapsed_ns", within=producer_window)
        require(event_window[0] >= previous, "structural measurements out of execution order")
        previous = event_window[1]
    scope_text = (f"selected_classes_only_not_whole_app; {count} compared methods; {METHOD_DATA}; "
        "shared nine singleton rejection cases (eight Offline, one Premium), NOT nine per selection or combined negative coverage; "
        "unsigned incomplete noninstallable emitted DEX, NOT whole APK/ART/Manager/device/runtime; parent exact-request2 authority only")
    tool = {"name": "RuntimeCheck tools-only JVM", "version": "3", "sha256": file_record(source / "checker.jar")["sha256"]}
    return [fragment("structural", "uncached_tests patcher_round_trip dex_control_flow negative_fixtures",
        [artifact("test-report", source / "junit-measurements.json"), artifact("dex-report", path)], tool, bound, row["ended_at"], now,
        selection=names, input_sha256=native["input_base_sha256"], output_sha256=row["emitted"]["output_sha256"], scope=scope_text)
        for row, (names, _, _) in zip(rows, POSITIVES)]


def strict_tree_paths(root):
    """Check all original spellings, including empty reparse directories."""
    si.canonical(root)
    def failed(exc):
        raise ValueError("cannot enumerate identity closure") from exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        if Path(directory) == REPO and ".git" in dirs:
            dirs.remove(".git")
        for name in dirs + files:
            si.canonical(Path(directory) / name)


def identity_closure(selection, config, cp, request_path, bundle, catalog, output, bound):
    """Attempt every independent closure category, retaining failures as measurements."""
    values = {"binding": bound, "errors": []}
    def source():
        strict_tree_paths(REPO)
        return f.pristine_tree(REPO)[1]
    def tools():
        strict_tree_paths(config["jdk"])
        for path in [Path(sys.executable), *config.get("deps", []), *config["runtime"], *config["compiler"]]:
            si.canonical(path)
        return tool_snapshot(config)
    probes = {"selection": lambda: si.snapshot_selection(selection), "source": source,
        "tools": tools, "files": lambda: {str(path): si.record(path) for path in
            (request_path, bundle, catalog, output / "frozen-request.json", *cp)}}
    for key, probe in probes.items():
        try:
            values[key] = probe()
        except Exception as exc:
            values["errors"].append(key + ": " + type(exc).__name__ + ": " + str(exc))
    return values


def guarded_identity_child(session, label, argv, measure, record):
    """Postchecks run in finally even after nonzero exit, timeout or report failure.

    Timeout does not establish descendant quiescence. Keep failure and closure
    failures separately; never retry, promote success or claim a stable inventory.
    """
    row = {"step": label, "started_at": p.utcnow()}
    record["checks"].append(row)
    primary = None
    tick = time.monotonic_ns()
    try:
        row["before"] = measure()
        require(not row["before"]["errors"] and row["before"] == record["baseline"], "identity pre-use closure mismatch")
        session.run(label, argv)
    except Exception as exc:
        primary = exc
        row["primary_error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        try:
            row["after"] = measure()
            require(not row["after"]["errors"] and row["after"] == record["baseline"], "identity post-use closure mismatch")
        except Exception as exc:
            row["closure_error"] = type(exc).__name__ + ": " + str(exc)
        timed_out = isinstance(primary, subprocess.TimeoutExpired) or any(command.get("timed_out") for command in getattr(session, "commands", []) if command["step"] == label)
        row["quiescence"] = "not-established" if timed_out else "child-returned-not-process-isolation"
        row["ended_at"] = p.utcnow()
        row["duration_ns"] = time.monotonic_ns() - tick
    if "closure_error" in row:
        raise ValueError((row.get("primary_error", "") + "; " + row["closure_error"]).lstrip("; ")) from primary
    if primary is not None:
        raise primary


class Session:
    """One consumed NEW private output; immutable inputs and monotonically retained files."""
    def __init__(self, output, inputs):
        self.output = f.ancestry(output)
        require(not self.output.exists() and self.output.parent.is_dir(), "NEW output with existing parent required")
        for path in [REPO, *inputs]:
            f.disjoint(self.output, f.ancestry(path))
        self.output.mkdir()
        self.retained = {}
        self.commands = []

    def retain(self):
        actual = inventory(self.output)
        require(all(actual.get(name) == row for name, row in self.retained.items()), "previously retained output mutated or removed")
        self.retained = actual

    def run(self, label, argv):
        self.retain()
        row = {"step": label, "argv": list(map(str, argv)), "started_at": p.utcnow()}
        self.commands.append(row)
        tick = time.monotonic_ns()
        log = self.output / (label + ".log")
        env = {key: value for key, value in os.environ.items() if key.upper() not in {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"}}
        payload = None
        try:
            child = subprocess.run(row["argv"], cwd=self.output, env=env, capture_output=True, timeout=900, check=False)
            row["exit_code"] = child.returncode
            payload = child.stdout + child.stderr
            require(child.returncode == 0, "child failed; output consumed and retained")
        except subprocess.TimeoutExpired as exc:
            row["timed_out"] = True
            row["quiescence"] = "not-established-descendants-may-still-write"
            payload = (exc.stdout or b"") + (exc.stderr or b"")
            raise
        finally:
            primary = sys.exception()
            row["ended_at"] = p.utcnow()
            row["duration_ns"] = time.monotonic_ns() - tick
            if primary is not None:
                row["error"] = type(primary).__name__ + ": " + str(primary)
            try:
                if payload is not None:
                    with log.open("xb") as stream:
                        stream.write(payload)
                if log.is_file():
                    row["log"] = {"path": str(log), **file_record(log)}
                self.retain()
            except Exception as exc:
                row["inventory_error"] = type(exc).__name__ + ": " + str(exc)
                if primary is None:
                    raise


def execute(*, request_path, bundle, catalog, jdk, cache_root, output, termius_selection=None):
    """Partial orchestrator only. There is deliberately no accept-report/pass override."""
    request_path, bundle, catalog, jdk, cache_root = map(Path, (request_path, bundle, catalog, jdk, cache_root))
    require(all(path.is_absolute() for path in (request_path, bundle, catalog, jdk, cache_root, Path(output))), "explicit absolute paths required")
    if termius_selection is not None:
        # Original spelling/ancestry must be checked before Session resolves paths.
        for path in (request_path, bundle, catalog, jdk, cache_root, output):
            si.canonical(path, missing=Path(path) == Path(output))
    session = Session(Path(output), [request_path.parent, bundle.parent, catalog.parent, jdk, cache_root])
    out = session.output
    result = {"schema": "private-jvm-observation-fragments-v1", "status": "failed", "complete_evidence": False,
              "fragments": {}, "commands": session.commands,
              "components": {"structural": {"status": "blocked", "reason": "No explicit Termius selection descriptor; RuntimeCheck is NOT invoked"},
                             "manager_import": {"status": "not-observed", "reason": "No genuine official Manager import or separate visual review"},
                             "plex_runtime": {"status": "not-observed", "reason": "No Android/Plex client execution"}},
              "limitations": ["Not schema2 evidence, not staging-ready; no Manager placeholder or Android runtime pass",
                              "android_dex means classes.dex magic/unsigned structure only, NOT ART",
                              "Parser is tested from current source tests.jar, NOT loaded from final MPP",
                              "Optional Termius structural scope is bounded selected methods, NOT whole APK",
                              "Hashes/source/tool consistency are NOT authentication; protected independent review required",
                              "Endpoint closure checks detect retained changes, not restored-byte same-user races; no process/filesystem isolation",
                              "Timeouts are failed/non-quiescent: descendants may still write; terminal index is not a stable-success claim",
                              "Identity policy is third-party listing provenance, not vendor attestation or stronger JDK/tool authenticity"]}
    try:
        # Preserve original whitespace and SHA before ANY source/native observation.
        raw = regular(request_path, 65536)
        with (out / "frozen-request.json").open("xb") as stream:
            stream.write(raw)
        session.retain()
        tree = f.pristine_tree(REPO)
        accepted, request = p.preflight(request_path, bundle, catalog, *tree, r, s)
        require(accepted == raw, "request changed during preflight")
        bound = binding(request, raw)
        result["binding"] = bound
        config = tools(jdk, cache_root)
        before_tools = tool_snapshot(config)
        selection = None
        if termius_selection is not None:
            result["components"]["structural"] = {"status": "failed", "reason": "Explicit selection must freshly verify before structural execution"}
            selection = si.load_selection(termius_selection, config["java"], p.parse_json)
            for path in selection["paths"].values():
                f.disjoint(out, path)
                for frozen in (request_path, bundle, catalog):
                    require(not path.samefile(frozen), "selection aliases a frozen input")
            result["termius_identity"] = {"descriptor": str(selection["paths"]["descriptor"]), "policy": si.POLICY,
                "initial_selection": si.snapshot_selection(selection), "checks": []}
        input_files = {str(path): file_record(path) for path in (request_path, bundle, catalog)}
        require(input_files[str(request_path)] == {"size": len(raw), "sha256": bound["request_sha256"]}
                and input_files[str(bundle)]["sha256"] == bound["bundle_sha256"]
                and input_files[str(catalog)]["sha256"] == bound["catalog_sha256"], "accepted frozen inputs changed")
        result["inputs"] = {"files": input_files, "source_files": tree[1], "tools": before_tools,
                            "request_path": str(request_path), "bundle": str(bundle), "catalog": str(catalog),
                            "jdk": str(jdk), "cache_root": str(cache_root)}

        def recheck_inputs():
            require(f.pristine_tree(REPO) == tree, "frozen source tree changed")
            require(tool_snapshot(config) == before_tools, "installed tools/dependencies changed")
            require({str(path): file_record(path) for path in (request_path, bundle, catalog)} == input_files, "frozen inputs changed")
            require(regular(out / "frozen-request.json") == raw, "exact request copy changed")
            session.retain()

        source = out / "source-jvm"
        recheck_inputs()
        session.run("source-jvm", [sys.executable, "-I", "-B", REPO / "tools/termius-check/run_jvm_checks.py", "--scope", "collection", "--jdk", jdk, "--cache-root", cache_root, "--out", source])
        recheck_inputs()
        now = dt.datetime.now(r.UTC)
        source_report, measured, cp = verify_source_run(source, config, before_tools, now, interval(session.commands[-1], now))
        if selection is not None:
            # Expectations come from previously accepted records, NOT a fresh
            # baseline measurement that could bless a persistent replacement.
            require(cp == [source / "checker.jar", *config["runtime"]], "unexpected checker classpath")
            expected_identity_files = {**input_files,
                str(out / "frozen-request.json"): {"size": len(raw), "sha256": bound["request_sha256"]},
                str(source / "checker.jar"): session.retained["source-jvm/checker.jar"],
                **{str(path): before_tools["dependencies"][path.relative_to(config["cache"]).as_posix()]
                   for path in config["runtime"]}}
        result["source_junit"] = {"scope": "source-tested, not final-MPP parser execution", "executed_cases": source_report["executed_cases"],
                                  "artifacts": [artifact("test-report", source / "junit-measurements.json")]}
        kind, checks, kinds = s.PLEX_REPORTS["parser"]
        result["fragments"]["plex"] = {"parser": fragment(kind, checks, [artifact("parser-report", source / "junit-measurements.json")],
            {"name": "MeasuredJUnit source parser tests", "version": "1", "sha256": file_record(source / "tests.jar")["sha256"]}, bound, measured["ended_at"], now)}
        inspection = out / "inspection"
        inspection.mkdir()
        recheck_inputs()
        session.run("inspection", [config["java"], "-Djava.io.tmpdir=" + str(inspection), "-cp", os.pathsep.join(map(str, cp)),
                                  "io.github.fishyau.androidpatches.inspection.InspectBundleKt", bundle, catalog, inspection / "native.json", REPO])
        recheck_inputs()
        now = dt.datetime.now(r.UTC)
        result["fragments"]["inspection"] = adapt_inspection(inspection / "native.json", read(catalog), bound, source / "checker.jar", now, interval(session.commands[-1], now))
        plex = out / "plex"
        recheck_inputs()
        session.run("plex", [sys.executable, "-I", "-B", REPO / "tools/plex-check/final_bundle.py", "check", "--jdk", jdk, "--cache-root", cache_root,
                             "--out", plex, "--request", out / "frozen-request.json", "--bundle", bundle, "--catalog", catalog])
        recheck_inputs()
        require(regular(plex / "frozen-request.json") == raw, "native wrapper request copy differs")
        now = dt.datetime.now(r.UTC)
        result["fragments"]["plex"].update(adapt_plex(plex, request, bound, config, now, interval(session.commands[-1], now), bundle, catalog))
        recheck_inputs()
        if selection is not None:
            identity = result["termius_identity"]
            measure = lambda: identity_closure(selection, config, cp, request_path, bundle, catalog, out, bound)
            identity["baseline"] = measure()
            require(not identity["baseline"]["errors"] and identity["baseline"]["selection"] == identity["initial_selection"]
                    and identity["baseline"]["source"] == tree[1] and identity["baseline"]["tools"] == before_tools
                    and identity["baseline"]["files"] == expected_identity_files,
                    "identity/source/tools/frozen files changed before verifier")
            verification = out / "selected-verification.json"
            require(not verification.exists(), "NEW verifier report required")
            guarded_identity_child(session, "termius-identity", si.verification_argv(selection, verification), measure, identity)
            si.validate_verification(read(verification), selection)
            root = out / "termius-structural"
            for directory in (root, structural_work(root)):
                si.canonical(directory, missing=True)
                require(not directory.exists(), "NEW nonexistent structural output/work directories required")
            guarded_identity_child(session, "termius-structural", structural_argv(config, cp, bundle, selection["members"]["base.apk"], root, catalog), measure, identity)
            now = dt.datetime.now(r.UTC)
            result["fragments"]["structural"] = adapt_structural(root, catalog, bound, selection["members"]["base.apk"], cp, source, now,
                interval(session.commands[-1], now), bundle)
            recheck_inputs()
            require(measure() == identity["baseline"], "late identity closure changed")
            result["components"]["structural"] = {"status": "bounded-jvm-observed", "reason": "Three bounded selections/shared nine singleton negatives; no Android runtime"}
        result["status"] = "incomplete-private-fragments-not-staging-ready"
    except Exception as exc:
        # Never expose previously accumulated fragments as successful after a later failure.
        result["fragments"] = {}
        result["error"] = type(exc).__name__ + ": " + str(exc)
        if termius_selection is not None:
            result["components"]["structural"] = {"status": "failed", "reason": "Explicit selection run failed; all fragments cleared"}
    finally:
        try:
            if "termius_identity" in result:
                with (out / "identity-closure.json").open("xb") as stream:
                    stream.write(r.canonical(result["termius_identity"]))
            session.retain()
            result["artifact_index"] = session.retained
        except Exception as exc:
            result["status"] = "failed"
            result["fragments"] = {}
            result["inventory_error"] = str(exc)
            if termius_selection is not None:
                result["components"]["structural"] = {"status": "failed", "reason": "Retained inventory failed; all fragments cleared"}
        # Deliberate nonrecursive index: this terminal record is the ONLY exclusion.
        result["artifact_index_excludes"] = ["partial.json"]
        with (out / "partial.json").open("xb") as stream:
            stream.write(r.canonical(result))
        if result["status"] == "incomplete-private-fragments-not-staging-ready":
            try:
                recheck(out)
            except Exception as exc:
                # Preserve the rejected terminal bytes; never overwrite a success marker in place.
                (out / "partial.json").rename(out / "partial-rejected.json")
                result["status"] = "failed"
                result["fragments"] = {}
                result["error"] = "terminal recheck: " + type(exc).__name__ + ": " + str(exc)
                if termius_selection is not None:
                    result["components"]["structural"] = {"status": "failed", "reason": "Terminal recheck failed; all fragments cleared"}
                result["artifact_index"] = inventory(out)
                with (out / "partial.json").open("xb") as stream:
                    stream.write(r.canonical(result))
    return result


def recheck(output, *, now=None):
    """Read-only, complete retained-index/input/component recheck; NOT authentication."""
    now = now or dt.datetime.now(r.UTC)
    output = f.ancestry(output)
    terminal = file_record(output / "partial.json")
    report = read(output / "partial.json")
    require(report.get("schema") == "private-jvm-observation-fragments-v1"
            and report.get("status") == "incomplete-private-fragments-not-staging-ready"
            and report.get("complete_evidence") is False, "only explicitly incomplete private fragments supported")
    require(report["artifact_index_excludes"] == ["partial.json"], "unexpected index exclusions")
    actual = inventory(output)
    del actual["partial.json"]
    require(actual == report["artifact_index"], "complete retained artifact inventory changed")
    inputs = report["inputs"]
    require(set(inputs["files"]) == {inputs[key] for key in ("request_path", "bundle", "catalog")}
            and all(file_record(Path(path)) == row for path, row in inputs["files"].items()), "retained input inventory incomplete/changed")
    tree = f.pristine_tree(REPO)
    require(tree[1] == inputs["source_files"], "source changed since observation")
    bundle, catalog = Path(inputs["bundle"]), Path(inputs["catalog"])
    raw, request = p.preflight(Path(inputs["request_path"]), bundle, catalog, *tree, r, s)
    require(regular(output / "frozen-request.json") == raw and report["binding"] == binding(request, raw), "original exact request/binding changed")
    config = tools(Path(inputs["jdk"]), Path(inputs["cache_root"]))
    require(tool_snapshot(config) == inputs["tools"], "installed tool payload changed")
    commands = report["commands"]
    selected = "termius_identity" in report
    require([row["step"] for row in commands] == ["source-jvm", "inspection", "plex"] + (["termius-identity", "termius-structural"] if selected else [])
            and all(row.get("exit_code") == 0 and not row.get("timed_out") for row in commands), "incomplete executing children")
    source = output / "source-jvm"
    source_report, measured, cp = verify_source_run(source, config, inputs["tools"], now, interval(commands[0], now))
    expected_commands = [
        [sys.executable, "-I", "-B", REPO / "tools/termius-check/run_jvm_checks.py", "--scope", "collection", "--jdk", inputs["jdk"], "--cache-root", inputs["cache_root"], "--out", source],
        [config["java"], "-Djava.io.tmpdir=" + str(output / "inspection"), "-cp", os.pathsep.join(map(str, cp)),
         "io.github.fishyau.androidpatches.inspection.InspectBundleKt", bundle, catalog, output / "inspection/native.json", REPO],
        [sys.executable, "-I", "-B", REPO / "tools/plex-check/final_bundle.py", "check", "--jdk", inputs["jdk"], "--cache-root", inputs["cache_root"],
         "--out", output / "plex", "--request", output / "frozen-request.json", "--bundle", bundle, "--catalog", catalog]]
    selection = None
    if selected:
        identity = report["termius_identity"]
        require(identity == read(output / "identity-closure.json") and set(identity) == {"descriptor", "policy", "initial_selection", "baseline", "checks"}
                and identity["policy"] == si.POLICY, "identity closure record mismatch")
        selection = si.load_selection(identity["descriptor"], config["java"], p.parse_json)
        closure = identity_closure(selection, config, cp, Path(inputs["request_path"]), bundle, catalog, output, report["binding"])
        require(not closure["errors"] and closure == identity["baseline"] and closure["selection"] == identity["initial_selection"]
                and closure["source"] == tree[1] and closure["tools"] == inputs["tools"], "identity closure changed/incomplete")
        checks = identity["checks"]
        require(type(checks) is list and [row["step"] for row in checks] == ["termius-identity", "termius-structural"], "identity child closure checks missing/duplicate")
        previous = request["created_at"]
        for check, command in zip(checks, commands[3:]):
            require(set(check) == {"step", "started_at", "ended_at", "duration_ns", "before", "after", "quiescence"}
                    and check["before"] == check["after"] == closure
                    and check["quiescence"] == "child-returned-not-process-isolation", "failed/non-quiescent identity child closure")
            guard_window = interval(check, now)
            interval(command, now, within=guard_window)
            require(guard_window[0] >= previous, "identity children out of order")
            previous = guard_window[1]
        si.validate_verification(read(output / "selected-verification.json"), selection)
        expected_commands += [si.verification_argv(selection, output / "selected-verification.json"),
            structural_argv(config, cp, bundle, selection["members"]["base.apk"], output / "termius-structural", catalog)]
    require(len(commands) == len(expected_commands), "unexpected outer command count")
    previous = request["created_at"]
    for row, argv in zip(commands, expected_commands):
        require(row["argv"] == list(map(str, argv)), "outer child command substituted")
        log = output / (row["step"] + ".log")
        require(row["log"] == {"path": str(log), **file_record(log)}, "outer child log changed")
        child_window = interval(row, now)
        require(child_window[0] >= previous, "observation predates request/previous child")
        previous = child_window[1]
    require(report["source_junit"] == {"scope": "source-tested, not final-MPP parser execution", "executed_cases": source_report["executed_cases"],
                                      "artifacts": [artifact("test-report", source / "junit-measurements.json")]}, "source-tested parser scope/measurement changed")
    kind, checks, _ = s.PLEX_REPORTS["parser"]
    expected = {"plex": {"parser": fragment(kind, checks, [artifact("parser-report", source / "junit-measurements.json")],
        {"name": "MeasuredJUnit source parser tests", "version": "1", "sha256": file_record(source / "tests.jar")["sha256"]},
        report["binding"], measured["ended_at"], now)}}
    expected["inspection"] = adapt_inspection(output / "inspection/native.json", read(catalog), report["binding"], source / "checker.jar", now, interval(commands[1], now))
    expected["plex"].update(adapt_plex(output / "plex", request, report["binding"], config, now, interval(commands[2], now), bundle, catalog))
    if selected:
        expected["structural"] = adapt_structural(output / "termius-structural", catalog, report["binding"], selection["members"]["base.apk"],
            cp, source, now, interval(commands[4], now), bundle)
    require(report["fragments"] == expected, "fragments changed or unsupported component promoted")
    require(set(report["components"]) == {"structural", "manager_import", "plex_runtime"}
            and report["components"]["structural"]["status"] == ("bounded-jvm-observed" if selected else "blocked")
            and all(report["components"][key]["status"] == "not-observed" for key in ("manager_import", "plex_runtime")), "unobserved component promoted")
    require(f.pristine_tree(REPO) == tree and tool_snapshot(config) == inputs["tools"]
            and all(file_record(Path(path)) == row for path, row in inputs["files"].items()), "source/tools/inputs changed during recheck")
    if selected:
        require(identity_closure(selection, config, cp, Path(inputs["request_path"]), bundle, catalog, output, report["binding"]) == closure,
                "identity closure changed during recheck")
    require(inventory(output) == {**actual, "partial.json": terminal}, "retained output changed during recheck")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    execute_parser = sub.add_parser("execute")
    for option in ("request", "bundle", "catalog", "jdk", "cache-root", "output"):
        execute_parser.add_argument("--" + option, type=Path, required=True)
    # Preserve descriptor spelling so canonical() can reject dot aliases before Path normalizes them.
    execute_parser.add_argument("--termius-selection")
    sub.add_parser("recheck").add_argument("--output", type=Path, required=True)
    args = vars(parser.parse_args(argv))
    command = args.pop("command")
    try:
        if command == "execute":
            args["request_path"] = args.pop("request")
            report = execute(**args)
        else:
            report = recheck(**args)
        print(report["status"])
        return 0 if report["status"] == "incomplete-private-fragments-not-staging-ready" else 2
    except (OSError, ValueError, TypeError, KeyError, r.ReleaseError) as exc:
        print("Observations blocked: " + type(exc).__name__, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
