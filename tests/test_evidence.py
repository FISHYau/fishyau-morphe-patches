"""Synthetic adapter contracts ONLY. No child, SDK, device, signing or network.

These fixtures invent nonexecutable producer records. Native-child/tool seams are
mocked explicitly; observations.recheck and staging.validate run as real validators.
No repository-tree mutation, loader execution or actual evidence is asserted.
"""
import copy
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("test_evidence_impl", REPO / "tools/release/evidence.py")
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
NOW = dt.datetime(2026, 11, 10, 12, tzinfo=dt.timezone.utc)
WHEN = "2026-11-10T08:30:00.000000"
ERRORS = (ValueError, KeyError, TypeError, OSError, e.m.Failure)


def save(path, value):
    path.write_bytes(e.r.canonical(value))


def times(start="2026-11-10T08:30:00.000000Z", end="2026-11-10T08:30:01.000000Z"):
    a = dt.datetime.fromisoformat(start.replace("Z", "+00:00"))
    b = dt.datetime.fromisoformat(end.replace("Z", "+00:00"))
    return {"started_at": start, "ended_at": end, "duration_ns": int((b - a).total_seconds() * 1e9)}


class Synthetic(unittest.TestCase):
    def patch(self, obj, name, **kwargs):
        patcher = mock.patch.object(obj, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="original-evidence-synthetic-")
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name).resolve()
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.bundle = self.inputs / "synthetic.mpp"
        with zipfile.ZipFile(self.bundle, "w") as archive:
            archive.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: FISHYau\r\nVersion: 0.1.0\r\nPatcher-Version: 2.3.0\r\n\r\n")
            archive.writestr("classes.dex", b"dex\n039\0SYNTHETIC INVALID DEX; NEVER EXECUTED")
        app = {"packageName": "com.server.auditor.ssh.client", "name": "Synthetic", "description": None,
               "apkFileType": "APKM", "appIconColor": None, "signatures": None, "formFactor": None,
               "targets": [{"version": "8.0.1", "versionCodes": {"ARM64_V8A": 1008},
                            "isExperimental": False, "minSdk": None, "description": None}]}
        patches = []
        for name, default in e.s.COLLECTION_PATCHES.items():
            compatible = copy.deepcopy(app)
            if name == "Premium unlock":
                compatible.update(packageName="com.plexapp.android", targets=[])
            patches.append(dict(name=name, default=default, description="Synthetic ONLY", category=None,
                                options=[], compatiblePackages=[compatible]))
        self.catalog = self.inputs / "catalog.json"
        save(self.catalog, {"version": "0.1.0", "patches": patches})
        original = {**e.s.ORIGINALS, "Compatibility.kt": "6fd9e5085ad9ae26d968ac8089f0c461c99c4ee2c5450d4a032d5c9e2259ed5f",
                    "BooleanReturn.kt": "0d4f024dbc9416a453ed30423b6c6487397c5d03d0ec0da8e478349b52583a65"}
        self.tree = e.o.f.pristine_tree(REPO)
        self.req = {"schema": 2, "policy": e.s.COLLECTION_POLICY, "owner": "FISHYau", "repository": "fishyau-morphe-patches",
                    "version": "0.1.0", "created_at": "2026-11-09T08:00:00", "description": "Synthetic ONLY",
                    "bundle_sha256": e.m.digest(self.bundle), "catalog_sha256": e.m.digest(self.catalog),
                    "source_tree_sha256": self.tree[0], "provenance": {
                        "termius": {"status": "accepted-existing-behavior", "basis": "user-confirmed-tested-working",
                                    "adaptations": e.s.TERMIUS_ADAPTATIONS,
                                    "files": [{"path": e.s.MIGRATED + n, "original_sha256": original[n], "migrated_sha256": h}
                                              for n, h in sorted(e.s.TERMIUS_MIGRATED.items())]},
                        "plex": {"repository": "https://github.com/UnkyBadTouch/plex-morphe-patches", "revision": e.s.PLEX_REVISION,
                                 "basis": "reviewed-source-migration-not-runtime-acceptance",
                                 "files": [{"path": e.s.PLEX + n, "original_sha256": h[0], "migrated_sha256": h[1]}
                                           for n, h in sorted(e.s.PLEX_FILES.items())]}}}
        self.request = self.inputs / "request.json"
        # Intentional whitespace: semantic reconstruction must change the binding.
        self.raw = ("  " + json.dumps(self.req, indent=3) + "\n\n").encode()
        self.request.write_bytes(self.raw)
        self.bound = e.o.binding(self.req, self.raw)
        self.sdk, self.jdk, self.python, self.cache = [self.base / name for name in ("sdk", "jdk", "python", "cache")]
        for root in (self.sdk, self.jdk, self.python, self.cache):
            (root / "bin").mkdir(parents=True)
        self.java = self.jdk / "bin" / ("java.exe" if os.name == "nt" else "java")
        self.exe = self.python / "bin" / ("python.exe" if os.name == "nt" else "python")
        self.java.write_bytes(b"SYNTHETIC NOT EXECUTABLE")
        self.exe.write_bytes(b"SYNTHETIC NOT EXECUTABLE PYTHON")
        (self.sdk / "aapt2").write_bytes(b"SYNTHETIC VERIFIER")
        (self.sdk / "apksigner.jar").write_bytes(b"SYNTHETIC VERIFIER")
        self.patch(e.m.sys, "executable", new=str(self.exe))
        self.patch(e.m.sys, "base_prefix", new=str(self.python))
        self.patch(e.o.subprocess, "run", side_effect=AssertionError("Real child prohibited"))
        self.patch(e.o.subprocess, "Popen", side_effect=AssertionError("Real process prohibited"))
        self.recheck = self.patch(e.o, "recheck", wraps=e.o.recheck)
        self.staging = self.patch(e.s, "validate", wraps=e.s.validate)
        self.partial_fixture(patches)

    def report(self, kind, checks, artifacts, **extra):
        return {"kind": kind, "platform": "jvm", "binding": copy.deepcopy(self.bound), "observed_at": WHEN,
                "tool": {"name": "SYNTHETIC NOT EXECUTED", "version": "1", "sha256": "a" * 64}, "status": "passed",
                "checks": {key: "passed" for key in checks.split()},
                "artifacts": [{"kind": key, "sha256": "b" * 64} for key in sorted(artifacts)], **extra}

    def partial_fixture(self, patches):
        o = e.o
        self.partial_root = self.base / "partial"
        self.partial_root.mkdir()
        (self.partial_root / "frozen-request.json").write_bytes(self.raw)
        source = self.partial_root / "source-jvm"
        source.mkdir()
        for name in ("checker.jar", "tests.jar", "junit-measurements.json"):
            (source / name).write_bytes(b"SYNTHETIC RETAINED CHILD OUTPUT; NEVER LOADED")
        for name in ("inspection", "plex", "termius-structural"):
            (self.partial_root / name).mkdir()
        descriptor = self.inputs / "selection.json"
        save(descriptor, {"synthetic": "not an actual selection"})
        base_apk = self.inputs / "selected-base.apk"
        base_apk.write_bytes(b"SYNTHETIC NOT AN APK")
        selection = {"members": {"base.apk": base_apk}, "paths": {"descriptor": descriptor}}
        initial_selection = {"policy": o.si.POLICY, "files": {str(descriptor): o.file_record(descriptor)}, "archive_members": {}}
        config = dict(jdk=self.jdk, cache=self.cache, java=self.java, runtime=[], compiler=[], deps=[])
        tool_snapshot = {"synthetic": "child/tool seam only"}
        self.patch(o, "tools", return_value=config)
        self.patch(o, "tool_snapshot", return_value=tool_snapshot)
        cp = [source / "checker.jar"]
        self.patch(o, "verify_source_run", return_value=({"executed_cases": 121}, {"ended_at": "2026-11-10T08:30:00Z"}, cp))
        inspection = self.report("bundle-inspection", "target_patcher_load actual_definitions metadata android_dex", {"loader-report"},
                                 patcher_version="2.3.0", patches=sorted(patches, key=lambda p: p["name"]),
                                 dependencies={name: [] for name in e.s.COLLECTION_PATCHES},
                                 about={"name": "FISHYau android patches", "author": "FISHYau"}, signing="unsigned")
        plex = {name: self.report(kind, checks, kinds) for name, (kind, checks, kinds) in e.s.PLEX_REPORTS.items()}
        structural = [self.report("structural", "uncached_tests patcher_round_trip dex_control_flow negative_fixtures",
                                 {"test-report", "dex-report"}, selection=names, input_sha256="c" * 64,
                                 output_sha256=e.r.digest(str(names).encode()), scope="Synthetic bounded DEX, not runtime")
                      for names in [[name] for name in e.s.PATCHES] + [sorted(e.s.PATCHES)]]
        # Only synthetic native child validators are substituted. The real
        # terminal recheck, retained inventory, bindings and command guards run.
        self.patch(o, "adapt_inspection", return_value=copy.deepcopy(inspection))
        self.patch(o, "adapt_plex", return_value=copy.deepcopy({k: plex[k] for k in ("resource", "final_bundle")}))
        self.patch(o, "adapt_structural", return_value=copy.deepcopy(structural))
        parser_kind, parser_checks, _ = e.s.PLEX_REPORTS["parser"]
        plex["parser"] = o.fragment(parser_kind, parser_checks, [o.artifact("parser-report", source / "junit-measurements.json")],
            {"name": "MeasuredJUnit source parser tests", "version": "1", "sha256": o.file_record(source / "tests.jar")["sha256"]},
            self.bound, "2026-11-10T08:30:00Z", NOW)
        files = {str(path): o.file_record(path) for path in (self.request, self.bundle, self.catalog)}
        closure = {"binding": self.bound, "errors": [], "selection": initial_selection, "source": self.tree[1],
                   "tools": tool_snapshot, "files": files}
        self.patch(o.si, "load_selection", return_value=selection)
        self.patch(o.si, "validate_verification", return_value=None)
        self.patch(o.si, "verification_argv", return_value=[str(self.java), "SYNTHETIC VERIFIER NO EXECUTION"])
        self.patch(o, "identity_closure", return_value=closure)
        commands = [
            [str(self.exe), "-I", "-B", REPO / "tools/termius-check/run_jvm_checks.py", "--scope", "collection", "--jdk", self.jdk, "--cache-root", self.cache, "--out", source],
            [self.java, "-Djava.io.tmpdir=" + str(self.partial_root / "inspection"), "-cp", str(source / "checker.jar"),
             "io.github.fishyau.androidpatches.inspection.InspectBundleKt", self.bundle, self.catalog, self.partial_root / "inspection/native.json", REPO],
            [str(self.exe), "-I", "-B", REPO / "tools/plex-check/final_bundle.py", "check", "--jdk", self.jdk, "--cache-root", self.cache,
             "--out", self.partial_root / "plex", "--request", self.partial_root / "frozen-request.json", "--bundle", self.bundle, "--catalog", self.catalog],
            o.si.verification_argv(selection, self.partial_root / "selected-verification.json"),
            o.structural_argv(config, cp, self.bundle, base_apk, self.partial_root / "termius-structural", self.catalog)]
        measured_commands = []
        guards = []
        for index, (name, argv) in enumerate(zip(("source-jvm", "inspection", "plex", "termius-identity", "termius-structural"), commands)):
            start = "2026-11-10T08:%02d:00.000000Z" % (30 + index)
            end = "2026-11-10T08:%02d:01.000000Z" % (30 + index)
            log = self.partial_root / (name + ".log")
            log.write_bytes(b"SYNTHETIC NO EXECUTION")
            measured_commands.append({"step": name, "argv": list(map(str, argv)), "exit_code": 0,
                                      "log": {"path": str(log), **o.file_record(log)}, **times(start, end)})
            if index >= 3:
                guards.append({"step": name, "before": closure, "after": closure,
                               "quiescence": "child-returned-not-process-isolation", **times(start, end)})
        identity = {"descriptor": str(descriptor), "policy": o.si.POLICY, "initial_selection": initial_selection,
                    "baseline": closure, "checks": guards}
        save(self.partial_root / "identity-closure.json", identity)
        save(self.partial_root / "selected-verification.json", {"synthetic": "never verified by a child"})
        self.partial = {"schema": "private-jvm-observation-fragments-v1", "status": "incomplete-private-fragments-not-staging-ready",
                        "complete_evidence": False, "binding": self.bound,
                        "inputs": {"files": files, "source_files": self.tree[1], "tools": tool_snapshot,
                                   "request_path": str(self.request), "bundle": str(self.bundle), "catalog": str(self.catalog),
                                   "jdk": str(self.jdk), "cache_root": str(self.cache)}, "termius_identity": identity,
                        "commands": measured_commands, "fragments": {"inspection": inspection, "structural": structural, "plex": plex},
                        "components": {"structural": {"status": "bounded-jvm-observed"}, "manager_import": {"status": "not-observed"},
                                       "plex_runtime": {"status": "not-observed"}},
                        "source_junit": {"scope": "source-tested, not final-MPP parser execution", "executed_cases": 121,
                                         "artifacts": [o.artifact("test-report", source / "junit-measurements.json")]},
                        "artifact_index_excludes": ["partial.json"], "artifact_index": o.inventory(self.partial_root)}
        save(self.partial_root / "partial.json", self.partial)
        self.partial_pin = e.m.digest(self.partial_root / "partial.json")

    def partial_check(self):
        return e.partial_original(self.partial_root, self.partial_pin, (self.request, self.bundle, self.catalog), self.bound, NOW)


class ManagerSynthetic(Synthetic):
    """Invent complete original helper records; never drive a real emulator."""
    def setUp(self):
        super().setUp()
        self.manager_root = self.base / "manager"
        self.manager_root.mkdir()
        (self.manager_root / "evidence").mkdir()
        self.device_run = self.manager_root / "device-run"
        self.device_run.mkdir()
        self.config_dir = self.base / "config"
        self.config_dir.mkdir()
        self.manager_config = self.config_dir / "config.json"
        self.manager_apk = self.inputs / "manager.apk"
        self.manager_apk.write_bytes(b"SYNTHETIC NOT A MANAGER APK")
        self.patch(e.m, "APK_SHA256", new=e.m.digest(self.manager_apk))
        self.patch(e.m, "now", return_value=NOW)
        self.config = {"schema": "manager-capture-config-v1", "source_root": str(REPO), "image": e.m.IMAGE,
                       "tools": {name: {"path": str(root), "inventory_sha256": e.m.inventory_hash(e.m.inventory(root))}
                                 for name, root in (("sdk", self.sdk), ("jdk", self.jdk), ("python", self.python))},
                       "verification": {"aapt2": str(self.sdk / "aapt2"), "signer_jar": str(self.sdk / "apksigner.jar"), "java": str(self.java)}}
        for name, path in (("request", self.request), ("bundle", self.bundle), ("catalog", self.catalog), ("manager_apk", self.manager_apk)):
            self.config[name] = {"path": str(path), "sha256": e.m.digest(path)}
        save(self.manager_config, self.config)
        self.config_pin = e.m.digest(self.manager_config)
        self.session = {"schema": "manager-capture-session-v1", "root": str(self.manager_root),
                        "config_path": str(self.manager_config), "config_sha256": self.config_pin,
                        "binding": copy.deepcopy(self.bound), "tools": self.config["tools"]}
        save(self.manager_root / "session.json", self.session)
        self.owner = {"owner": "d" * 32, "avd": "morphe_" + "d" * 32, "run": str(self.device_run), "sdk": str(self.sdk),
                      "avd_home": str(self.device_run / "avd"), "data_home": str(self.device_run / "android-user")}
        save(self.manager_root / "device-owner.json", self.owner)
        self.device = {**self.owner, "status": "running", "image": e.m.IMAGE, "pid": 12345, "serial": "emulator-5554",
                       "console_port": 5554, "server_port": 40401, "abi": "x86_64"}
        self.manager_closure = e.m.closure(self.config)
        self.remote = "/sdcard/Download/morphe_" + self.owner["owner"] + ".mpp"
        self.remote_record = {"path": self.remote, "sha256": self.bound["bundle_sha256"]}
        self.remote_argv = ["shell", "toybox", "sha256sum", self.remote]
        self.counter = 0
        self.events = {}
        self.lifecycle_fixture()
        captures, _ = e.m.capture_events(self.manager_root, self.session, NOW)
        purposes = {row["purpose"]: label for label, row in captures.items()}
        checks = {"local_import": "local-import", "collection_identity": "collection-identity", "patch_names": "patch-names",
                  "defaults": "defaults-untouched", "compatibility": "compatibility", "visual_inspection": "navigation"}
        self.review = {"schema": "manager-original-visual-review-v1", "binding": copy.deepcopy(self.bound),
                       "reviewed_at": "2026-11-10T10:00:00.000000Z", "reviewer_claim": "SYNTHETIC unverified reviewer claim",
                       "captures": captures, "checks": {name: {"status": "observed", "captures": [purposes[purpose]],
                                                              "notes": "SYNTHETIC ONLY; not an actual observation"}
                                                       for name, purpose in checks.items()}}
        self.review_path = self.config_dir / "review.json"
        save(self.review_path, self.review)
        self.review_pin = e.m.digest(self.review_path)
        self.original_report_fixture()
        self.graph_spy = self.patch(e.m, "validate_graph", wraps=e.m.validate_graph)
        self.manager_recheck = self.patch(e.m, "recheck_report", wraps=e.m.recheck_report)

    def event(self, command, result, argv=(), trace=(), *, label=None, capture=False):
        label = label or "%02d-%s" % (self.counter, command)
        second = self.counter
        self.counter += 1
        def stamp(fraction):
            return "2026-11-10T09:00:%02d.%06dZ" % (second, int(fraction * 1e6))
        actions = []
        for index, args in enumerate(argv):
            guard = ["canonical-owned-name"]
            if args[:1] == ["install"]:
                guard += ["canonical-install-bytes", "guest-isolation-readback", "official-apk-bytes"]
            elif args == self.remote_argv or args[:1] == ["push"] or command in ("picker-tap", "picker-key") and args[:2] == ["shell", "input"]:
                guard += ["callback-completed"]
            start = ([.11, .15, .19, .51][index] if capture else .01 + index * .02)
            actions.append({"argv": args, "status": "completed", "guards": guard, **times(stamp(start), stamp(start + .01))})
        device = None if command in ("init", "report") else copy.deepcopy(self.device)
        if command == "create":
            device["status"] = "created"
        if command == "stop":
            device["status"] = "stopped"
        closure = copy.deepcopy(self.manager_closure)
        if command == "stop":
            closure.pop("source_tree_sha256")
        row = {"schema": e.m.SCHEMA, "root": str(self.manager_root), "label": label, "binding": copy.deepcopy(self.bound),
               "ok": True, "command": command, "result": result, "closure_before": closure, "closure_after": copy.deepcopy(closure),
               "closure_exemption": "owned-shutdown-only-input-loss" if command == "stop" else None,
               "postcheck_errors": [], "device": device, "actions": actions, "isolation_trace": list(trace),
               **times(stamp(0), stamp(.9))}
        if capture:
            result["captures"] = {}
            for key, prefix, suffix, start, end in (("dump", "hierarchy-", ".xml", .1, .4), ("screenshot", "screenshot-", ".png", .5, .6)):
                path = self.device_run / (prefix + label + suffix)
                path.write_bytes(b"SYNTHETIC NOT REAL UI " + key.encode())
                result["captures"][key] = {**times(stamp(start), stamp(end)), "result": e.m.file_record(path)}
        folder = self.manager_root / "evidence" / label
        folder.mkdir()
        save(folder / "result.json", row)
        self.events[command if not capture else result["purpose"]] = (folder / "result.json", row)
        return folder / "result.json", row

    def isolation(self, command):
        commands = ["id -u"]
        if command == "isolate":
            commands += ["iptables -w 2 -I OUTPUT 1 -j DROP", "ip6tables -w 2 -I OUTPUT 1 -j DROP"]
        commands += ["iptables -w 2 -S OUTPUT", "ip6tables -w 2 -S OUTPUT"] * (2 if command == "install" else 1)
        trace, argv = [], []
        for cmd in commands:
            stdout = "0\n" if cmd == "id -u" else "-P OUTPUT ACCEPT\n-A OUTPUT -j DROP\n" if cmd.endswith("-S OUTPUT") else ""
            trace.append({"command": cmd, "mode": "adbd", "stdout": stdout + "\n__MORPHE_EXIT__=0\n"})
            script = cmd + '; rc=$?; printf "\\n__MORPHE_EXIT__=%s\\n" "$rc"; exit "$rc"'
            argv.append(["shell", "sh", "-c", "'" + script + "'"])
        return trace, argv

    def lifecycle_fixture(self):
        mapping = e.m.stage_bundle(self.manager_root, self.config)
        self.event("init", {"bundle_mapping": mapping})
        self.event("create", {"state": str(self.device_run / "emulator.json"), "avd": self.owner["avd"]})
        props = [["shell", "getprop", key] for key in e.m.PROPERTIES]
        log = self.device_run / "startup-log-snapshot.log"
        log.write_bytes(b"SYNTHETIC STARTUP SNAPSHOT")
        self.event("start", {"state": str(self.device_run / "emulator.json"), "serial": self.device["serial"], "log": str(log),
                             "artifacts": [e.m.file_record(log)], "snapshot": {"source_path": str(self.device_run / ("emulator-" + "f" * 32 + ".log")),
                             "prefix_bytes": log.stat().st_size, "limit_bytes": 8 * 1024 * 1024}},
                   [["shell", "getprop", "sys.boot_completed"], *props])
        isolation_result = {"boundary": "guest IPv4+IPv6 first OUTPUT DROP", "privilege": "adbd",
                            "limit": "Readback only; no connectivity probe or host isolation"}
        trace, argv = self.isolation("isolate")
        self.event("isolate", copy.deepcopy(isolation_result), argv, trace)
        stage = self.device_run / ("install-stage-" + "e" * 32)
        stage.mkdir()
        member = stage / "member-0.apk"
        member.write_bytes(self.manager_apk.read_bytes())
        trace, argv = self.isolation("install")
        canonical = {"state": str(self.device_run / "emulator.json"), "apks": [str(self.manager_apk)], "staged_apks": [str(member)],
                     "mapping": [{"original": str(self.manager_apk), "staged": str(member), "sha256": e.m.APK_SHA256}],
                     "stdout": str(stage / "install.txt"), "abi": "x86_64", "capabilities": {}, "verification": str(stage / "verification.json"),
                     "installed_paths": [], "installed_abi_evidence": {}, "limit": "SYNTHETIC"}
        save(stage / "verification.json", {"schema": 2, "status": "selected_split_set_verified",
             "expected": {"package": e.m.APP, "version_code": "39909503", "version_name": "2.5.0", "split": None, "signers_sha256": [e.m.CERT]},
             "selection": {"abi": "x86_64", "density": "nodpi", "languages": ["none"]},
             "apks": [{"path": str(member), "sha256": e.m.APK_SHA256, "signers_sha256": [e.m.CERT]}]})
        for name in ("install.txt", "package-paths.txt", "package-abi.txt"):
            (stage / name).write_bytes(b"SYNTHETIC RETAINED INSTALL EVIDENCE")
        save(stage / "installation.json", {k: v for k, v in canonical.items() if k != "state"})
        self.event("install", {"canonical": canonical, "artifacts": [e.m.file_record(p) for p in sorted(stage.iterdir())], "installed_byte_readback": "not-performed",
                               "signer_provenance": "observed official HTTPS release certificate, not independent prior signer trust"},
                   [*argv[:3], *props, *argv[3:], ["install", str(member)], ["shell", "pm", "path", e.m.APP], ["shell", "dumpsys", "package", e.m.APP]], trace)
        self.event("push", {"stdout": "SYNTHETIC", "remote": self.remote_record},
                   [["push", str(self.manager_root / "bundle-stage/collection.mpp"), self.remote], self.remote_argv])
        launch = self.device_run / "launch.txt"
        launch.write_bytes(b"SYNTHETIC LAUNCH LOG")
        component = e.m.APP + "/.MainActivity"
        trace, argv = self.isolation("launch")
        self.event("launch", {"component": component, "stdout": str(launch), "artifacts": [e.m.file_record(launch)]},
                   [*argv, ["shell", "cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.MAIN", "-c", "android.intent.category.LAUNCHER", e.m.APP],
                    ["shell", "am", "start", "-W", "-n", component]], trace)
        self.event("picker-key", {"stdout": "SYNTHETIC"}, [self.remote_argv, ["shell", "input", "keyevent", "66"]])
        for purpose in e.m.PURPOSES:
            remote_xml = "/data/local/tmp/morphe_" + self.owner["owner"] + ".xml"
            self.event("capture", {"purpose": purpose, "visual_review": "pending-separate-original-review"},
                       [["shell", "uiautomator", "dump", remote_xml], ["exec-out", "cat", remote_xml],
                        ["shell", "rm", "-f", remote_xml], ["exec-out", "screencap", "-p"]], capture=True)
        trace, argv = self.isolation("final-check")
        self.event("final-check", {"isolation": isolation_result, "remote": self.remote_record,
                                  "limit": "Not UI success, feature behavior, installed-byte proof or release approval"}, [*argv, self.remote_argv], trace)
        stop = {key: self.device[key] for key in (*self.owner, "pid", "serial", "console_port", "server_port")}
        stop.update(status="stopped", transport_port=5555, confirmation="read_only_process_exited_and_both_owned_ports_released")
        self.event("stop", stop)

    def original_report_fixture(self):
        with mock.patch.object(e.m, "now", return_value=dt.datetime(2026, 11, 10, 11, tzinfo=dt.timezone.utc)):
            self.report_value = e.m.manager_report(self.manager_root, self.session, self.review_path, self.review_pin)
        self.report_path = self.manager_root / "evidence/report-original/manager-report.json"
        self.report_path.parent.mkdir()
        save(self.report_path, self.report_value)
        self.report_pin = e.m.digest(self.report_path)
        closure = copy.deepcopy(self.manager_closure)
        row = {"schema": e.m.SCHEMA, "root": str(self.manager_root), "label": "report-original", "binding": self.bound,
               "ok": True, "command": "report", "result": {"manager_report": e.m.file_record(self.report_path)},
               "closure_before": closure, "closure_after": copy.deepcopy(closure), "closure_exemption": None,
               "postcheck_errors": [], "device": None, "actions": [], "isolation_trace": [],
               **times("2026-11-10T10:59:59.000000Z", "2026-11-10T11:00:01.000000Z")}
        save(self.report_path.parent / "result.json", row)

    def manager_check(self):
        return e.manager_original(root=self.manager_root, report_path=self.report_path, report_sha256=self.report_pin,
            config_path=self.manager_config, config_sha256=self.config_pin, review_path=self.review_path,
            review_sha256=self.review_pin, bound=self.bound, paths=(self.request, self.bundle, self.catalog), request=self.req, current=NOW)

    def args(self, output=None):
        return dict(request=self.request, bundle=self.bundle, catalog=self.catalog, partial_root=self.partial_root,
                    partial_sha256=self.partial_pin, manager_root=self.manager_root, manager_report=self.report_path,
                    manager_report_sha256=self.report_pin, manager_config=self.manager_config, manager_config_sha256=self.config_pin,
                    visual_review=self.review_path, visual_review_sha256=self.review_pin, plex_status="blocked",
                    plex_scope="Original blocker: no account-free meaningful Plex vendor acceptance; no reviewed runtime producer.",
                    output=output or self.base / "evidence-output", now=NOW)


class PartialContracts(Synthetic):
    def test_real_recheck_valid_synthetic_and_original_request_whitespace(self):
        result, _ = self.partial_check()
        self.assertEqual(result["fragments"], self.partial["fragments"])
        self.recheck.assert_called_once_with(self.partial_root, now=NOW)
        req, bound, _, _ = e.original_inputs(self.request, self.bundle, self.catalog, NOW)
        self.assertEqual(req, self.req)
        self.assertEqual(bound, self.bound)
        self.assertNotEqual(bound["request_sha256"], e.r.digest(e.r.canonical(req)))

    def test_missing_binding_or_changed_records_are_not_reconstructed(self):
        original = copy.deepcopy(self.partial)
        for mutate in (lambda x: x["binding"].pop("catalog_sha256"),
                       lambda x: x["binding"].update(request_sha256="0" * 64),
                       lambda x: x["fragments"].pop("structural"),
                       lambda x: x["fragments"]["structural"].pop(),
                       lambda x: x["fragments"]["plex"].pop("resource"),
                       lambda x: x["commands"][0].update(exit_code=7),
                       lambda x: x["commands"][0].update(argv=["not the original child"]),
                       lambda x: x["inputs"].update(source_files={})):
            value = copy.deepcopy(original)
            mutate(value)
            save(self.partial_root / "partial.json", value)
            self.partial_pin = e.m.digest(self.partial_root / "partial.json")
            with self.subTest(mutation=mutate), self.assertRaises(ERRORS):
                self.partial_check()
        save(self.partial_root / "partial.json", original)

    def test_original_partial_pin_and_retained_inventory_are_both_mandatory(self):
        terminal = self.partial_root / "partial.json"
        raw = terminal.read_bytes()
        terminal.write_bytes(raw + b" ")
        with self.assertRaises(ERRORS): self.partial_check()
        terminal.write_bytes(raw)
        for name in ("source-jvm/checker.jar", "identity-closure.json", "source-jvm.log"):
            path = self.partial_root / name
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(name=name), self.assertRaises(ERRORS): self.partial_check()
            path.write_bytes(original)

    def test_stale_future_and_out_of_order_original_children_rejected(self):
        original = copy.deepcopy(self.partial)
        for start, end in (("2026-11-01T08:30:00Z", "2026-11-01T08:30:01Z"),
                           ("2026-11-11T08:30:00Z", "2026-11-11T08:30:01Z"),
                           ("2026-11-09T07:30:00Z", "2026-11-09T07:30:01Z")):
            value = copy.deepcopy(original)
            value["commands"][0].update(**times(start, end))
            save(self.partial_root / "partial.json", value)
            self.partial_pin = e.m.digest(self.partial_root / "partial.json")
            with self.assertRaises(ERRORS): self.partial_check()

    def test_hardlinks_symlink_spelling_and_source_output_roots_rejected(self):
        target = self.partial_root / "source-jvm.log"
        alias = self.partial_root / "alias.log"
        os.link(target, alias)
        with self.assertRaises(ERRORS): self.partial_check()
        alias.unlink()
        original = Path.is_symlink
        with mock.patch.object(Path, "is_symlink", lambda p: p == self.partial_root or original(p)):
            with self.assertRaises(ERRORS): self.partial_check()
        for path in (REPO / "evidence-output", REPO.parent, self.inputs / "output", self.base):
            with self.subTest(path=path), self.assertRaises(ERRORS):
                out = e.m.external(path)
                e.m.disjoint(out, self.inputs)


class ManagerContracts(ManagerSynthetic):
    def test_valid_original_uses_capture_time_and_actual_helper_hash_no_regeneration(self):
        before = e.o.inventory(self.manager_root)
        with mock.patch.object(e.m, "manager_report", side_effect=AssertionError("Do not regenerate an original")):
            fragment, original, _ = self.manager_check()
        self.manager_recheck.assert_called()
        self.graph_spy.assert_called()
        self.assertEqual(fragment["observed_at"], e.o.utc(original["graph"]["capture_ended_at"], NOW))
        self.assertNotEqual(fragment["observed_at"], e.o.utc(self.review["reviewed_at"], NOW))
        self.assertNotEqual(fragment["observed_at"], e.o.utc(self.report_value["assembled_at"], NOW))
        self.assertEqual(fragment["tool"]["sha256"], e.m.digest(e.MANAGER_SOURCE))
        self.assertEqual(original["review"]["authentication"], "not-authenticated-local-human-claims")
        self.assertEqual(e.o.inventory(self.manager_root), before)
        self.assertFalse(self.report_value["complete_evidence"])

    def rewrite_report(self, mutate):
        value = copy.deepcopy(self.report_value)
        mutate(value)
        save(self.report_path, value)
        self.report_pin = e.m.digest(self.report_path)
        event_path = self.report_path.parent / "result.json"
        event = e.m.read_json(event_path)
        event["result"]["manager_report"] = e.m.file_record(self.report_path)
        save(event_path, event)

    def test_all_five_manager_bindings_and_original_record_pin_required(self):
        raw = self.report_path.read_bytes()
        self.report_path.write_bytes(raw + b" ")
        with self.assertRaises(ERRORS): self.manager_check()
        self.report_path.write_bytes(raw)
        for key in e.m.BINDING_KEYS:
            self.rewrite_report(lambda x, k=key: x["binding"].update({k: "changed" if k == "policy" else "0" * 64}))
            with self.subTest(key=key), self.assertRaises(ERRORS): self.manager_check()
        self.rewrite_report(lambda x: x["binding"].pop("request_sha256"))
        with self.assertRaises(ERRORS): self.manager_check()

    def test_review_captures_events_and_config_cannot_change_under_original_pins(self):
        capture = next(iter(self.review["captures"].values()))
        for path in (Path(capture["screenshot"]["path"]), Path(capture["hierarchy"]["path"]),
                     Path(capture["event"]["path"]), self.review_path, self.manager_config,
                     self.manager_root / "session.json", self.manager_root / "device-owner.json"):
            before = path.read_bytes()
            path.write_bytes(before + b"mutation")
            with self.subTest(path=path), self.assertRaises(ERRORS): self.manager_check()
            path.write_bytes(before)

    def test_pinned_tool_payloads_and_exact_original_frozen_bytes_rechecked(self):
        for path in (self.java, self.exe, self.sdk / "aapt2", self.request, self.bundle, self.catalog):
            original = path.read_bytes()
            path.write_bytes(original + b"changed original payload")
            with self.subTest(path=path), self.assertRaises(ERRORS): self.manager_check()
            path.write_bytes(original)

    def test_missing_original_capture_and_review_references_rejected(self):
        before = self.review_path.read_bytes()
        for mutate in (lambda x: x["captures"].pop(next(iter(x["captures"]))),
                       lambda x: x["captures"][next(iter(x["captures"]))]["screenshot"].update(sha256="0" * 64),
                       lambda x: x["checks"]["defaults"].update(captures=[])):
            value = copy.deepcopy(self.review)
            mutate(value)
            save(self.review_path, value)
            self.review_pin = e.m.digest(self.review_path)
            with self.assertRaises(ERRORS): self.manager_check()
        self.review_path.write_bytes(before)

    def test_nonobserved_or_dto_only_checks_do_not_qualify(self):
        for status in ("not-observed", "blocked", "passed", "pending-original-review"):
            self.rewrite_report(lambda x, v=status: x["human_claims"]["checks"]["defaults"].update(status=v))
            with self.subTest(status=status), self.assertRaises(ERRORS): self.manager_check()
        self.rewrite_report(lambda x: x.update(complete_evidence=True))
        with self.assertRaises(ERRORS): self.manager_check()

    def test_honest_original_nonobserved_review_is_valid_helper_data_but_not_complete_evidence(self):
        for status in ("not-observed", "blocked"):
            review = copy.deepcopy(self.review)
            review["checks"]["defaults"]["status"] = status
            save(self.review_path, review)
            self.review_pin = e.m.digest(self.review_path)
            review_record = {"original": e.m.file_record(self.review_path), "claims": review,
                             "authentication": "not-authenticated-local-human-claims"}
            def incomplete(value):
                value["human_claims"] = {"review": review_record, "checks": {
                    name: {**row, "basis": "human-claim-not-tool-measurement"} for name, row in review["checks"].items()}}
                value["status"] = "pending-original-visual-review"
            self.rewrite_report(incomplete)
            original = e.m.recheck_report(self.report_path, self.report_pin, current=NOW)
            self.assertEqual(original["status"], "pending-original-visual-review")
            with self.subTest(status=status), self.assertRaises(ERRORS): self.manager_check()

    def test_stale_future_or_restamped_assembly_and_review_times_rejected(self):
        for value in ("2026-11-01T11:00:00.000000Z", "2026-11-11T11:00:00.000000Z",
                      "2026-11-10T11:59:59.000000Z", "2026-11-10T08:59:00.000000Z"):
            self.rewrite_report(lambda x, v=value: x.update(assembled_at=v))
            with self.subTest(assembly=value), self.assertRaises(ERRORS): self.manager_check()
        # Keep original report bound while separately supplied review is altered.
        self.rewrite_report(lambda x: None)
        original = self.review_path.read_bytes()
        for value in ("2026-11-01T10:00:00.000000Z", "2026-11-11T10:00:00.000000Z", "2026-11-10T08:00:00.000000Z"):
            review = copy.deepcopy(self.review)
            review["reviewed_at"] = value
            save(self.review_path, review)
            self.review_pin = e.m.digest(self.review_path)
            with self.subTest(review=value), self.assertRaises(ERRORS): self.manager_check()
        self.review_path.write_bytes(original)

    def test_snapshot_own_report_event_is_allowed_but_later_device_event_is_not(self):
        # A genuine current report excludes its own successful outer event.
        self.manager_check()
        original = self.report_value["tool_measurements"]["events"]
        fresh = e.m.capture_events(self.manager_root, self.session, NOW)[1]
        self.assertEqual(len(fresh), len(original) + 1)
        self.assertNotIn(str(self.report_path.parent / "result.json"), [r["event"]["path"] for r in original])
        # Reuse an original measured navigation shape, with a genuinely later
        # interval. It remains forbidden to append device actions after shutdown.
        path, source = self.events["picker-key"]
        later = copy.deepcopy(source)
        later.update(label="later-device", **times("2026-11-10T11:10:00.000000Z", "2026-11-10T11:10:01.000000Z"))
        later["actions"] = []
        folder = self.manager_root / "evidence/later-device"
        folder.mkdir()
        save(folder / "result.json", later)
        with self.assertRaises(ERRORS): self.manager_check()

    def test_genuine_newer_report_only_event_allowed_without_rewriting_original(self):
        original_bytes = self.report_path.read_bytes()
        with mock.patch.object(e.m, "now", return_value=dt.datetime(2026, 11, 10, 11, 30, tzinfo=dt.timezone.utc)):
            later = e.m.manager_report(self.manager_root, self.session, self.review_path, self.review_pin)
        folder = self.manager_root / "evidence/report-later"
        folder.mkdir()
        path = folder / "manager-report.json"
        save(path, later)
        closure = copy.deepcopy(self.manager_closure)
        event = {"schema": e.m.SCHEMA, "root": str(self.manager_root), "label": "report-later", "binding": self.bound,
                 "ok": True, "command": "report", "result": {"manager_report": e.m.file_record(path)},
                 "closure_before": closure, "closure_after": copy.deepcopy(closure), "closure_exemption": None,
                 "postcheck_errors": [], "device": None, "actions": [], "isolation_trace": [],
                 **times("2026-11-10T11:29:59.000000Z", "2026-11-10T11:30:01.000000Z")}
        save(folder / "result.json", event)
        self.manager_check()
        self.assertEqual(self.report_path.read_bytes(), original_bytes)

    def test_missing_or_changed_snapshot_event_and_report_only_action_fail_closed(self):
        self.rewrite_report(lambda x: x["tool_measurements"]["events"].pop())
        with self.assertRaises(ERRORS): self.manager_check()
        self.rewrite_report(lambda x: x["tool_measurements"]["events"][0]["event"].update(sha256="0" * 64))
        with self.assertRaises(ERRORS): self.manager_check()
        self.rewrite_report(lambda x: None)
        event_path = self.report_path.parent / "result.json"
        event = e.m.read_json(event_path)
        event["device"] = copy.deepcopy(self.device)
        save(event_path, event)
        with self.assertRaises(ERRORS): self.manager_check()


class TerminalFinalCheckFixture(ManagerSynthetic):
    """Alter synthetic lifecycle construction before any report is assembled.

    Individual successful event/action records remain genuine helper-shaped
    records. Only terminal final-check presence/order is wrong; no validators,
    pinned snapshots or assembler pass flags are fabricated to hide the gap.
    """
    final_check_mode = None
    final_check_error = None

    def lifecycle_fixture(self):
        super().lifecycle_fixture()
        path, row = self.events["final-check"]
        if self.final_check_mode == "missing":
            # These are disposable synthetic fixture files, not real originals.
            path.unlink()
            path.parent.rmdir()
            return
        self.assertEqual(self.final_check_mode, "pre-capture")
        parse = lambda value: dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        stamp = lambda value: value.isoformat(timespec="microseconds").replace("+00:00", "Z")
        start = parse(self.events["launch"][1]["ended_at"]) + dt.timedelta(milliseconds=1)
        end = parse(self.events["picker-key"][1]["started_at"]) - dt.timedelta(milliseconds=1)
        delta = start - parse(row["started_at"])
        for action in row["actions"]:
            for key in ("started_at", "ended_at"):
                action[key] = stamp(parse(action[key]) + delta)
        row.update(**times(stamp(start), stamp(end)))
        save(path, row)
        # Real per-event validation proves the retained isolation trace, remote
        # readback, guard tags and nested timing are individually valid.
        e.m.validate_event(row, self.manager_root, self.session, NOW)

    def assert_terminal_final_check_rejected(self):
        captures, events = e.m.capture_events(self.manager_root, self.session, NOW)
        self.assertEqual(captures, self.review["captures"])
        self.assertTrue(all(item["ok"] for item in events))
        finals = [item for item in events if item["command"] == "final-check"]
        if self.final_check_mode == "missing":
            self.assertEqual(finals, [])
        else:
            self.assertEqual(len(finals), 1)
            first_capture = min(e.m.instant(item["started_at"], NOW)
                                for item in events if item["command"] == "capture")
            self.assertLess(e.m.instant(finals[0]["ended_at"], NOW), first_capture)
        with self.assertRaisesRegex(e.m.Failure, self.final_check_error):
            e.m.validate_graph(self.manager_root, self.session, NOW, require_shutdown=True)
        # The real report reader may retain honest incomplete original data;
        # this must not turn the fully observed visual claims into evidence.
        original = e.m.recheck_report(self.report_path, self.report_pin, current=NOW)
        self.assertEqual(original["lifecycle"], {"status": "incomplete", "error": self.final_check_error})
        self.assertEqual(original["status"], "pending-original-visual-review")
        self.assertTrue(all(row["status"] == "observed" for row in original["human_claims"]["checks"].values()))
        self.graph_spy.reset_mock()
        self.staging.reset_mock()
        args = self.args()
        with self.assertRaisesRegex(e.m.Failure, self.final_check_error):
            e.assemble(**args)
        self.graph_spy.assert_any_call(self.manager_root, self.session, NOW, require_shutdown=True)
        self.staging.assert_not_called()
        self.assertFalse(Path(args["output"]).exists())


class MissingTerminalFinalCheckContracts(TerminalFinalCheckFixture):
    final_check_mode = "missing"
    final_check_error = "Complete collection requires terminal final-check before shutdown"

    def test_missing_final_check_rejected_by_real_graph_and_assembler(self):
        self.assert_terminal_final_check_rejected()


class PreCaptureFinalCheckContracts(TerminalFinalCheckFixture):
    final_check_mode = "pre-capture"
    final_check_error = "Terminal final-check must follow all captures/device observations"

    def test_genuine_pre_capture_final_check_rejected_by_real_graph_and_assembler(self):
        self.assert_terminal_final_check_rejected()


class AssembleContracts(ManagerSynthetic):
    def test_valid_adaptation_real_authoritative_validators_and_verbatim_blocker(self):
        args = self.args()
        originals = (self.request.read_bytes(), (self.partial_root / "partial.json").read_bytes(),
                     self.report_path.read_bytes(), self.review_path.read_bytes())
        out = e.assemble(**args)
        self.assertEqual({p.name for p in out.iterdir()}, {"evidence.json", "receipt.json"})
        evidence, receipt = [e.m.read_json(out / name) for name in ("evidence.json", "receipt.json")]
        self.assertEqual(evidence["schema"], 2)
        self.assertEqual(evidence["plex"]["runtime"], {"status": "blocked", "scope": args["plex_scope"], "artifacts": []})
        self.assertEqual(receipt["plex_runtime"], evidence["plex"]["runtime"])
        self.assertFalse(receipt["evidence_authenticated"])
        self.assertGreaterEqual(self.recheck.call_count, 4)
        self.assertGreaterEqual(self.manager_recheck.call_count, 4)
        self.assertGreaterEqual(self.graph_spy.call_count, 4)
        self.staging.assert_called_once_with(REPO, self.bundle, self.catalog, self.request, out / "evidence.json", now=NOW)
        self.assertEqual(originals, (self.request.read_bytes(), (self.partial_root / "partial.json").read_bytes(),
                                    self.report_path.read_bytes(), self.review_path.read_bytes()))
        self.assertNotIn("manifest", receipt)
        self.assertNotIn("summary", receipt)

    def test_output_existing_input_container_and_ancestor_overlap_rejected(self):
        old = self.base / "existing"
        old.mkdir()
        (old / "keep").write_bytes(b"preserve")
        for output in (old, self.inputs / "new", self.config_dir / "new", self.partial_root / "new", self.manager_root / "new",
                       self.sdk / "new", self.jdk / "new", self.python / "new", self.cache / "new", REPO / "new", REPO.parent, self.base):
            with self.subTest(output=output), self.assertRaises(ERRORS): e.assemble(**self.args(output))
        self.assertEqual((old / "keep").read_bytes(), b"preserve")
        self.assertFalse((self.inputs / "new").exists())

    def test_no_observed_runtime_or_empty_scope_option(self):
        for status, scope in (("observed", "fabricated pass"), ("passed", "scope"), ("blocked", ""), ("not-observed", "   ")):
            args = self.args()
            args.update(plex_status=status, plex_scope=scope)
            with self.subTest(status=status, scope=scope), self.assertRaises(ERRORS): e.assemble(**args)
            self.assertFalse(Path(args["output"]).exists())
        args = self.args()
        args.update(plex_status="not-observed", plex_scope="No runtime producer; verbatim original blocker.")
        out = e.assemble(**args)
        self.assertEqual(e.m.read_json(out / "evidence.json")["plex"]["runtime"]["status"], "not-observed")

    def test_validator_failure_consumes_output_without_receipt_or_candidate(self):
        self.staging.side_effect = e.r.ReleaseError("Synthetic authoritative validation rejection")
        output = self.base / "failed-output"
        with self.assertRaisesRegex(ValueError, "authoritative"):
            e.assemble(**self.args(output))
        self.assertEqual({p.name for p in output.iterdir()}, {"evidence.json"})
        with self.assertRaises(ERRORS): e.assemble(**self.args(output))
        self.assertFalse((output / "receipt.json").exists())

    def test_late_changed_original_during_validation_is_not_blessed(self):
        # self.staging wraps the saved implementation, so avoid recursion here.
        actual = self.staging._mock_wraps
        def changed(*args, **kwargs):
            result = actual(*args, **kwargs)
            self.review_path.write_bytes(self.review_path.read_bytes() + b" ")
            return result
        self.staging.side_effect = changed
        out = self.base / "changed-during-validation"
        with self.assertRaises(ERRORS): e.assemble(**self.args(out))
        self.assertTrue((out / "evidence.json").exists())
        self.assertFalse((out / "receipt.json").exists())

    def test_publisher_boundary_still_rejects_blocked_and_unobserved_runtime(self):
        # Only the publisher's committed-candidate IO boundary is mocked here.
        # Its actual policy gate must reject before any remote method is called.
        publisher = e.load("evidence_test_publisher", REPO / "tools/release/publisher.py")
        out = e.assemble(**self.args())
        validated = self.staging._mock_wraps(REPO, self.bundle, self.catalog, self.request, out / "evidence.json", now=NOW)
        summary = validated["summary"]
        binding = {"target": e.s.TARGET, "version": "0.1.0", "candidate_sha256": "a" * 64,
                   "artifact_run": "1", "artifact_id": "2", "artifact_sha256": "b" * 64, "source_commit": "c" * 40}
        remote = mock.Mock()
        for status in ("blocked", "not-observed"):
            value = copy.deepcopy(summary)
            value["reported_new_observations"]["plex"]["runtime"]["status"] = status
            with mock.patch.object(publisher, "local_check", return_value={"verification-summary.json": e.r.canonical(value)}), \
                 self.assertRaisesRegex(ValueError, "Plex runtime acceptance"):
                publisher.publish(out, REPO, binding, remote, mode="publish", now=NOW)
        self.assertEqual(remote.mock_calls, [])


if __name__ == "__main__":
    unittest.main()
