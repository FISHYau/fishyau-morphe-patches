"""Synthetic Manager capture contracts. No SDK/device/APK/MPP execution.

Every child process, PID probe and port probe is blocked unless explicitly mocked.
Source review must precede execution. All invented bytes stay in external tempdirs.
"""
import contextlib
import copy
import datetime as dt
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("manager_import_tests", REPO / "tools/manager-check/manager_import.py")
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)
NOW = dt.datetime(2026, 11, 10, 12, tzinfo=dt.timezone.utc)
START = "2026-11-10T11:00:00.000000Z"
END = "2026-11-10T11:00:03.000000Z"


def times(start=START, end=END, duration=3_000_000_000):
    return {"started_at": start, "ended_at": end, "duration_ns": duration}


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="manager-synthetic-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        h.external(self.base)
        self.root = self.base / "runtime"
        self.root.mkdir()
        (self.root / "evidence").mkdir()
        self.inputs = self.base / "inputs"
        self.inputs.mkdir()
        self.config_dir = self.base / "config"
        self.config_dir.mkdir()
        self.config_path = self.config_dir / "capture.json"
        self.config = {"schema": "manager-capture-config-v1", "source_root": str(REPO), "image": h.IMAGE}
        for name, suffix in (("request", ".json"), ("bundle", ".mpp"), ("catalog", ".json"), ("manager_apk", ".apk")):
            path = self.inputs / (name + suffix)
            path.write_bytes(b"SYNTHETIC NONEXECUTABLE " + name.encode())
            self.config[name] = {"path": str(path), "sha256": h.digest(path)}
        self.patch(h, "APK_SHA256", new=self.config["manager_apk"]["sha256"])
        self.config["tools"] = {}
        for name in ("sdk", "jdk", "python"):
            directory = self.base / name
            (directory / "bin").mkdir(parents=True)
            (directory / "bin" / ("java.exe" if os.name == "nt" else "java")).write_bytes(b"not a program")
            self.config["tools"][name] = {"path": str(directory), "inventory_sha256": h.inventory_hash(h.inventory(directory))}
        sdk = Path(self.config["tools"]["sdk"]["path"])
        self.config["verification"] = {"aapt2": str(sdk / "bin" / ("java.exe" if os.name == "nt" else "java")),
                                       "signer_jar": str(sdk / "bin" / ("java.exe" if os.name == "nt" else "java")),
                                       "java": str(Path(self.config["tools"]["jdk"]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java"))}
        runtime = Path(self.config["tools"]["python"]["path"])
        self.patch(h.sys, "base_prefix", new=str(runtime))
        self.patch(h.sys, "executable", new=str(runtime / "bin" / ("java.exe" if os.name == "nt" else "java")))
        self.capture_sequence = 0
        self.request = {"schema": 2, "policy": h.s.COLLECTION_POLICY, "owner": "FISHYau", "repository": "fishyau-morphe-patches",
                        "version": "0.1.0", "created_at": "2026-11-10T10:00:00", "description": "Synthetic contract only",
                        "bundle_sha256": self.config["bundle"]["sha256"], "catalog_sha256": self.config["catalog"]["sha256"],
                        "source_tree_sha256": "a" * 64, "provenance": {}}
        self.update_request()
        self.write_config()
        self.bound = h.binding(self.config)
        self.session = {"schema": "manager-capture-session-v1", "root": str(self.root), "config_path": str(self.config_path),
                        "config_sha256": h.digest(self.config_path), "binding": self.bound, "tools": self.config["tools"]}
        h.write_new(self.root / "session.json", self.session)
        self.patch(h, "now", return_value=NOW)
        self.patch(h.canonical.subprocess, "run", side_effect=AssertionError("Real subprocess prohibited"))
        self.patch(h.canonical.subprocess, "Popen", side_effect=AssertionError("Real process prohibited"))
        self.patch(h.canonical, "process_exited", side_effect=AssertionError("Real PID probe prohibited"))
        self.patch(h.canonical, "endpoints_released", side_effect=AssertionError("Real port probe prohibited"))
        self.emu = h.ManagerEmulator(self.config, self.root / "device-run")
        self.emu.run.mkdir()
        self.emu.state = {"version": 1, "owner": "b" * 32, "avd": "morphe_" + "b" * 32,
                          "run": str(self.emu.run), "sdk": str(self.emu.sdk), "image": h.IMAGE, "status": "running",
                          "console_port": 5554, "server_port": 40401, "serial": "emulator-5554", "pid": 12345, "installs": []}
        (self.emu.run / ".owner").write_text("b" * 32, encoding="ascii")
        self.emu.save()
        h.write_new(self.root / "device-owner.json", h.owner_binding(self.emu))
        self.patch(self.emu, "tool", return_value=Path("mock-adb"))
        self.order = []
        self.owned = self.patch(self.emu, "_owned_name", side_effect=lambda *a: self.order.append("owned"))
        self.checked = self.patch(h.canonical, "checked", side_effect=self.respond)

    def patch(self, target, name, **kwargs):
        patcher = mock.patch.object(target, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def update_request(self):
        path = Path(self.config["request"]["path"])
        path.write_text(json.dumps(self.request), encoding="utf-8")
        self.config["request"]["sha256"] = h.digest(path)

    def write_config(self):
        self.config_path.write_text(json.dumps(self.config), encoding="utf-8")
        return h.digest(self.config_path)

    def respond(self, argv, env, timeout=30, binary=False, **kwargs):
        self.assertEqual(argv[1:5], ["-P", "40401", "-s", "emulator-5554"])
        args = tuple(map(str, argv[5:]))
        self.order.append(args)
        if args[:3] == ("shell", "toybox", "sha256sum"):
            return self.config["bundle"]["sha256"] + "  " + h.remote_path(self.emu) + "\n"
        if args[0] == "install":
            return "Success\n"
        if args[:3] == ("shell", "pm", "path"):
            return "package:/data/app/synthetic/base.apk\n"
        if args[:3] == ("shell", "dumpsys", "package"):
            return " primaryCpuAbi=x86_64\n"
        return ""

    def bundle(self):
        mapping = h.stage_bundle(self.root, self.config)
        return Path(mapping["original"]), Path(mapping["staged"])

    def stage_apk(self):
        stage = self.emu.run / ("install-stage-" + "c" * 32)
        stage.mkdir()
        target = stage / "member-0.apk"
        target.write_bytes(Path(self.config["manager_apk"]["path"]).read_bytes())
        return target

    def closure(self):
        tools = {}
        for name, row in self.config["tools"].items():
            tools[name] = {"root": row["path"], "files": h.inventory(row["path"]), "inventory_sha256": row["inventory_sha256"]}
        return {"source_tree_sha256": self.bound["source_tree_sha256"], "tools": tools,
                "python_executable": h.file_record(Path(self.config["tools"]["python"]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java"))}

    def event_row(self, command, label, result, start, actions=None, trace=None, device=None):
        closure = self.closure()
        if command == "stop":
            closure = {k: v for k, v in closure.items() if k != "source_tree_sha256"}
        return {"schema": h.SCHEMA, "root": str(self.root), "label": label, "binding": self.bound,
                **self.window(start, 0, 3), "ok": True, "command": command, "result": result,
                "closure_before": closure, "closure_after": closure, "postcheck_errors": [],
                "closure_exemption": "owned-shutdown-only-input-loss" if command == "stop" else None,
                "actions": actions or [], "isolation_trace": trace or [],
                "device": device if device is not None else (None if command in ("init", "report") else h.device_snapshot(self.emu))}

    def window(self, start, offset, end):
        return times(h.stamp(start + dt.timedelta(seconds=offset)), h.stamp(start + dt.timedelta(seconds=end)), int((end - offset) * 1e9))

    def action(self, argv, start, offset, guards=None):
        return {"argv": argv, "status": "completed", "guards": ["canonical-owned-name", *(guards or [])],
                **self.window(start, offset, offset + .02)}

    def emit(self, row):
        folder = h.label_directory(self.root, row["label"])
        h.write_new(folder / ("result.json" if row["ok"] else "failure.json"), row)
        return folder / ("result.json" if row["ok"] else "failure.json"), row

    def capture_event(self, label="observed", purpose="local-import"):
        start = NOW - dt.timedelta(minutes=50) + dt.timedelta(seconds=4 * self.capture_sequence)
        self.capture_sequence += 1
        result = {"purpose": purpose, "visual_review": "pending-separate-original-review", "captures": {}}
        for key, prefix, suffix in (("dump", "hierarchy-", ".xml"), ("screenshot", "screenshot-", ".png")):
            path = self.emu.run / (prefix + label + suffix)
            path.write_bytes(b"Synthetic capture bytes, not actual UI " + key.encode())
            bounds = (.1, .8) if key == "dump" else (1, 1.2)
            result["captures"][key] = {**self.window(start, *bounds), "result": h.file_record(path)}
        remote = "/data/local/tmp/morphe_" + self.emu.state["owner"] + ".xml"
        argv = [["shell", "uiautomator", "dump", remote], ["exec-out", "cat", remote],
                ["shell", "rm", "-f", remote], ["exec-out", "screencap", "-p"]]
        actions = [self.action(a, start, offset) for a, offset in zip(argv, (.2, .3, .4, 1.1))]
        return self.emit(self.event_row("capture", label, result, start, actions))

    def complete_graph(self):
        """Invented nonexecuting lifecycle for strict parser tests; returns captures.

        Requires this Fixture.setUp; child, PID and port operations stay blocked.
        Emits five purpose captures plus confirmed synthetic stop. No UI claim is
        made until a caller separately writes an explicitly synthetic review.
        """
        mapping = h.stage_bundle(self.root, self.config)
        base = NOW - dt.timedelta(hours=1)
        device = h.device_snapshot(self.emu)
        self.emit(self.event_row("init", "init", {"bundle_mapping": mapping}, base))
        created = {**device, "status": "created", "pid": None, "serial": None, "console_port": None, "server_port": None}
        self.emit(self.event_row("create", "create", {"state": str(self.emu.state_path), "avd": device["avd"]}, base + dt.timedelta(seconds=10), device=created))
        start = base + dt.timedelta(seconds=20)
        log = self.emu.run / ("emulator-" + "e" * 32 + ".log")
        log.write_bytes(b"Synthetic non-executable emulator log")
        snapshot = h.startup_snapshot(self.emu, log)
        boot = [["shell", "getprop", "sys.boot_completed"], *[["shell", "getprop", p] for p in h.PROPERTIES]]
        self.emit(self.event_row("start", "start", {"state": str(self.emu.state_path), "serial": device["serial"], **snapshot}, start,
                                 [self.action(a, start, .1 + i * .1) for i, a in enumerate(boot)]))

        def isolation(start, *, establish=False, repeats=1):
            commands = ["id -u"]
            if establish:
                commands += ["iptables -w 2 -I OUTPUT 1 -j DROP", "ip6tables -w 2 -I OUTPUT 1 -j DROP"]
            commands += ["iptables -w 2 -S OUTPUT", "ip6tables -w 2 -S OUTPUT"] * repeats
            trace, actions = [], []
            for i, command in enumerate(commands):
                content = "0\n" if command == "id -u" else "-P OUTPUT ACCEPT\n-A OUTPUT -j DROP\n" if "-S OUTPUT" in command else ""
                trace.append({"command": command, "mode": "adbd", "stdout": content + "\n__MORPHE_EXIT__=0\n"})
                script = command + '; rc=$?; printf "\\n__MORPHE_EXIT__=%s\\n" "$rc"; exit "$rc"'
                actions.append(self.action(["shell", "sh", "-c", "'" + script + "'"], start, .1 + i * .1))
            return trace, actions

        boundary = {"boundary": "guest IPv4+IPv6 first OUTPUT DROP", "privilege": "adbd",
                    "limit": "Readback only; no connectivity probe or host isolation"}
        start = base + dt.timedelta(seconds=30)
        trace, actions = isolation(start, establish=True)
        self.emit(self.event_row("isolate", "isolate", boundary, start, actions, trace))
        start = base + dt.timedelta(seconds=40)
        trace, checks = isolation(start, repeats=2)
        stage = self.stage_apk()
        expected = {"package": h.APP, "version_code": "39909503", "version_name": "2.5.0", "split": None, "signers_sha256": [h.CERT]}
        verification = {"schema": 2, "status": "selected_split_set_verified", "expected": expected,
                        "selection": {"abi": "x86_64", "density": "nodpi", "languages": ["none"]},
                        "apks": [{"path": str(stage), "sha256": h.APK_SHA256, "signers_sha256": [h.CERT]}]}
        h.write_new(stage.parent / "verification.json", verification)
        for name in ("install.txt", "package-paths.txt", "package-abi.txt"):
            (stage.parent / name).write_bytes(b"Synthetic package-manager acceptance; NOT actual runtime")
        record = {"apks": [self.config["manager_apk"]["path"]], "staged_apks": [str(stage)],
                  "mapping": [{"original": self.config["manager_apk"]["path"], "staged": str(stage), "sha256": h.APK_SHA256}],
                  "stdout": str(stage.parent / "install.txt"), "abi": {}, "capabilities": {},
                  "verification": str(stage.parent / "verification.json"), "installed_paths": ["/synthetic/base.apk"],
                  "installed_abi_evidence": [], "limit": "Synthetic acceptance only"}
        h.write_new(stage.parent / "installation.json", record)
        record = {"state": str(self.emu.state_path), **record}
        actions = checks[:3]
        actions += [self.action(["shell", "getprop", p], start, .5 + i * .05) for i, p in enumerate(h.PROPERTIES)]
        actions += [self.action(a["argv"], start, 1.1 + i * .1) for i, a in enumerate(checks[3:])]
        actions += [self.action(["install", str(stage)], start, 1.4, ["canonical-install-bytes", "guest-isolation-readback", "official-apk-bytes"]),
                    self.action(["shell", "pm", "path", h.APP], start, 1.5), self.action(["shell", "dumpsys", "package", h.APP], start, 1.6)]
        self.emit(self.event_row("install", "install", {"canonical": record, "artifacts": [h.file_record(p) for p in sorted(stage.parent.iterdir())],
                  "installed_byte_readback": "not-performed", "signer_provenance": "Synthetic; no signer authentication"}, start, actions, trace))
        start = base + dt.timedelta(seconds=50)
        remote = h.remote_path(self.emu)
        remote_result = {"path": remote, "sha256": self.config["bundle"]["sha256"]}
        remote_argv = ["shell", "toybox", "sha256sum", remote]
        actions = [self.action(["push", mapping["staged"], remote], start, .1, ["callback-completed"]),
                   self.action(remote_argv, start, .2, ["callback-completed"])]
        self.emit(self.event_row("push", "push", {"stdout": "Synthetic", "remote": remote_result}, start, actions))
        start = base + dt.timedelta(seconds=60)
        trace, actions = isolation(start)
        component = h.APP + "/.MainActivity"
        (self.emu.run / "launch.txt").write_bytes(b"Synthetic launch only")
        actions += [self.action(["shell", "cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.MAIN", "-c",
                                "android.intent.category.LAUNCHER", h.APP], start, .5),
                    self.action(["shell", "am", "start", "-W", "-n", component], start, .6)]
        self.emit(self.event_row("launch", "launch", {"component": component, "stdout": str(self.emu.run / "launch.txt"),
                                 "artifacts": [h.file_record(self.emu.run / "launch.txt")]}, start, actions, trace))
        for label, purpose in (("local_import", "local-import"), ("collection_identity", "collection-identity"),
                               ("patch_names", "patch-names"), ("defaults", "defaults-untouched"), ("compatibility", "compatibility")):
            self.capture_event(label, purpose)
        start = base + dt.timedelta(minutes=19)
        trace, actions = isolation(start)
        actions.append(self.action(remote_argv, start, .5, ["callback-completed"]))
        self.emit(self.event_row("final-check", "final-check", {"isolation": boundary, "remote": remote_result,
                                 "limit": "Synthetic check only; not acceptance"}, start, actions, trace))
        start = base + dt.timedelta(minutes=20)
        stop_device = {**device, "status": "stopped"}
        identity = {key: stop_device[key] for key in ("owner", "avd", "run", "sdk", "avd_home", "data_home", "pid", "serial", "console_port", "server_port")}
        result = {**identity, "transport_port": 5555, "status": "stopped", "confirmation": "process_exited_and_both_owned_ports_released",
                  "state": str(self.emu.state_path)}
        actions = [self.action(["emu", "kill"], start, .1, ["saved-tool-closure", "exclusive-stop-reservation", "persist-stopping-before-kill"])]
        self.emit(self.event_row("stop", "stop", result, start, actions, device=stop_device))
        return h.capture_events(self.root, self.session, NOW)[0]

    def review(self, captures):
        value = {"schema": "manager-original-visual-review-v1", "binding": self.bound,
                 "reviewed_at": "2026-11-10T11:30:00.000000Z", "reviewer_claim": "Synthetic reviewer; NOT an acceptance record",
                 "captures": captures, "checks": {key: {"status": "not-observed", "captures": [], "notes": "Synthetic unobserved check"} for key in h.CHECKS}}
        path = self.config_dir / "review.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path, value


class InputContracts(Fixture):
    def config_mocks(self):
        runtime = Path(self.config["tools"]["python"]["path"])
        self.patch(h.sys, "base_prefix", new=str(runtime))
        self.patch(h.sys, "executable", new=str(runtime / "bin" / ("java.exe" if os.name == "nt" else "java")))
        self.patch(h.s.r, "bundle_metadata", return_value={"name": "FISHYau android patches", "author": "FISHYau", "version": "0.1.0", "patcher-version": "2.3.0"})
        self.catalog = self.patch(h.s, "collection_inventory", return_value=[])
        Path(self.config["catalog"]["path"]).write_text("{}", encoding="utf-8")
        self.config["catalog"]["sha256"] = h.digest(self.config["catalog"]["path"])
        self.request["catalog_sha256"] = self.config["catalog"]["sha256"]
        self.update_request()

    def test_scope_config_and_all_five_original_bindings(self):
        self.config_mocks()
        pin = self.write_config()
        self.assertEqual(h.read_config(self.config_path, pin), self.config)
        bound = h.binding(self.config)
        self.assertEqual(set(bound), h.BINDING_KEYS)
        self.assertEqual(bound["request_sha256"], h.digest(self.config["request"]["path"]))
        for name in ("request", "bundle", "catalog", "manager_apk"):
            path = Path(self.config[name]["path"])
            original = path.read_bytes()
            path.write_bytes(original + b"mutation")
            with self.subTest(input=name), self.assertRaises(h.Failure):
                h.read_config(self.config_path, pin)
            path.write_bytes(original)

    def test_wrong_scope_schema_image_unknown_fields_and_identity_rejected(self):
        self.config_mocks()
        original = copy.deepcopy(self.config)
        for field, bad in (("schema", "other"), ("image", "system-images;android-31;google_apis;x86_64"), ("extra", True)):
            self.config = {**original, field: bad}
            with self.subTest(field=field), self.assertRaises(h.Failure):
                h.read_config(self.config_path, self.write_config())
        self.config = original
        self.request["bundle_sha256"] = "f" * 64
        self.update_request()
        with self.assertRaisesRegex(h.Failure, "binding mismatch"):
            h.read_config(self.config_path, self.write_config())
        self.request["bundle_sha256"] = self.config["bundle"]["sha256"]
        self.request["schema"] = 1
        self.update_request()
        with self.assertRaisesRegex(h.Failure, "schema2"):
            h.read_config(self.config_path, self.write_config())

    def test_hash_and_json_fail_closed(self):
        for bad in (True, None, "A" * 64, "f" * 63, "f" * 65, 123):
            with self.subTest(value=bad), self.assertRaises(h.Failure):
                h.expected_hash(bad)
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '[] trailing'):
            self.config_path.write_text(raw, encoding="utf-8")
            with self.subTest(raw=raw), self.assertRaises((h.Failure, ValueError)):
                h.read_json(self.config_path)

    def test_malformed_external_paths_and_nesting(self):
        for value in ("relative", "", 123, str(REPO / "private"), str(REPO.parent), str(self.base) + "/../escape",
                      str(self.base) + "/bad*", str(self.base) + "/bad?", str(self.base) + "/stream:ads",
                      str(self.base) + "/trailing.", str(self.base) + "/bad\x00", "//host/share"):
            with self.subTest(path=value), self.assertRaises(h.Failure):
                h.external(value)
        with self.assertRaises(h.Failure):
            h.disjoint(self.root, self.root / "nested")

    def test_linked_original_spelling_and_hardlinks_rejected_without_read(self):
        original = Path(self.config["bundle"]["path"])
        alias = self.inputs / "alias.mpp"
        # Mocking the filesystem predicate exercises original-spelling rejection
        # on Windows without needing symlink privilege or an actual link.
        is_symlink = Path.is_symlink
        with mock.patch.object(Path, "is_symlink", lambda p: p == alias or is_symlink(p)):
            with self.assertRaisesRegex(h.Failure, "Linked"):
                h.file_record(alias)
        before = original.stat()
        info = SimpleNamespace(st_mode=before.st_mode, st_nlink=2, st_size=before.st_size)
        with mock.patch.object(Path, "stat", return_value=info), mock.patch.object(h, "absolute", return_value=original):
            with self.assertRaisesRegex(h.Failure, "unaliased"):
                h.file_record(original)

    def test_source_and_tool_closure_mutations_rejected(self):
        source = self.patch(h.s.r, "source_tree", return_value=(self.request["source_tree_sha256"], {}))
        self.patch(h.s, "collection_provenance", return_value=None)
        exe = Path(self.config["tools"]["python"]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java")
        self.patch(h.sys, "executable", new=str(exe))
        baseline = h.closure(self.config)
        self.assertEqual(set(baseline["tools"]), {"sdk", "jdk", "python"})
        source.return_value = ("f" * 64, {})
        with self.assertRaisesRegex(h.Failure, "Source tree"):
            h.closure(self.config)
        source.return_value = (self.request["source_tree_sha256"], {})
        exe.write_bytes(b"changed runtime")
        with self.assertRaisesRegex(h.Failure, "Tool closure"):
            h.closure(self.config)

    def test_exact_config_byte_pin_and_tool_key_order(self):
        self.config_mocks()
        self.config["tools"] = dict(reversed(list(self.config["tools"].items())))
        pin = self.write_config()
        h.read_config(self.config_path, pin)
        self.config_path.write_bytes(self.config_path.read_bytes() + b" ")
        with self.assertRaises(h.Failure):
            h.read_config(self.config_path, pin)


class GuardContracts(Fixture):
    def test_inherited_jvm_injection_removed_for_canonical_environment(self):
        inherited = {name: "SYNTHETIC INJECTION NEVER EXECUTED" for name in
                     ("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "KOTLIN_HOME")}
        inherited["INTENTIONAL_EXPLICIT_CONFIG"] = "preserved"
        with mock.patch.dict(os.environ, inherited):
            emu = h.ManagerEmulator(self.config, self.base / "fresh-run")
        self.assertTrue(all(name not in emu.env for name in inherited if name != "INTENTIONAL_EXPLICIT_CONFIG"))
        self.assertEqual(emu.env["INTENTIONAL_EXPLICIT_CONFIG"], "preserved")
        self.assertEqual(emu.env["JAVA_HOME"], self.config["tools"]["jdk"]["path"])
        classpath = Path(self.config["tools"]["sdk"]["path"]) / "cmdline-tools/latest/lib/avdmanager-classpath.jar"
        classpath.parent.mkdir(parents=True)
        classpath.write_bytes(b"not a JVM archive")
        command = emu.manager_command()
        self.assertEqual(command[0], self.config["verification"]["java"])
        Path(command[0]).unlink()
        with self.assertRaises(OSError):
            emu.manager_command()  # No PATH Java fallback.
        self.checked.assert_not_called()

    def test_start_records_exclusive_bounded_snapshot_not_growing_log(self):
        log = self.emu.run / ("emulator-" + "d" * 32 + ".log")
        log.write_bytes(b"startup\n")
        self.patch(self.emu, "start", return_value={"state": str(self.emu.state_path), "serial": "emulator-5554", "log": str(log)})
        result = h.dispatch(SimpleNamespace(command="start"), self.root, self.config, self.emu)
        snapshot = result["artifacts"][0]
        log.write_bytes(log.read_bytes() + b"later appended output\n")
        self.assertNotEqual(result["log"], str(log))
        self.assertEqual(h.file_record(snapshot["path"]), snapshot)
        with self.assertRaises(FileExistsError):
            h.startup_snapshot(self.emu, log)
        self.checked.assert_not_called()

    def test_oversized_live_log_rejected_before_snapshot_creation(self):
        log = self.emu.run / ("emulator-" + "d" * 32 + ".log")
        with log.open("wb") as stream:
            stream.truncate(8 * 1024 * 1024 + 1)
        with self.assertRaisesRegex(h.Failure, "exceeds bound"):
            h.startup_snapshot(self.emu, log)
        self.assertFalse((self.emu.run / "startup-log-snapshot.log").exists())
        self.checked.assert_not_called()

    def test_stage_copy_new_and_no_input_mutation(self):
        original, staged = self.bundle()
        self.assertNotEqual(original, staged)
        self.assertEqual(h.digest(original), h.digest(staged))
        with self.assertRaises(FileExistsError):
            h.stage_bundle(self.root, self.config)

    def test_push_ownership_then_final_host_guard(self):
        original, staged = self.bundle()
        for target in (original, staged):
            before = target.read_bytes()
            self.owned.side_effect = lambda *a: target.write_bytes(b"changed during ownership")
            with self.subTest(path=target), self.assertRaisesRegex(h.Failure, "Pinned bytes"):
                h.push_bundle(self.emu, self.root, self.config)
            self.checked.assert_not_called()
            target.write_bytes(before)

    def test_picker_tap_and_all_activation_keys_guard_immediately_after_ownership(self):
        self.bundle()
        original_guard = h.bundle_guard
        def record_guard(*args):
            self.order.append("host-bytes")
            return original_guard(*args)
        self.patch(h, "bundle_guard", side_effect=record_guard)
        for command, kw, action in (("picker-tap", {"x": 1, "y": 2}, ("tap", "1", "2")),
                                     *[("picker-key", {"code": code}, ("keyevent", str(code))) for code in (23, 66, 160)]):
            with self.subTest(command=command, kw=kw):
                self.order.clear()
                h.dispatch(SimpleNamespace(command=command, **kw), self.root, self.config, self.emu)
                self.assertEqual(self.order, ["owned", "owned", "host-bytes",
                    ("shell", "toybox", "sha256sum", h.remote_path(self.emu)), "host-bytes", ("shell", "input", *action)])
                self.assertEqual(self.emu.actions[-1]["status"], "completed")
                self.assertIn("started_at", self.emu.actions[-1])

    def test_remote_mismatch_and_host_mutation_after_remote_never_activate(self):
        original, staged = self.bundle()
        for kind in ("remote", "original", "staged"):
            self.order.clear()
            target = original if kind == "original" else staged
            old = target.read_bytes()
            def response(argv, *a, **kw):
                output = self.respond(argv, *a, **kw)
                if "sha256sum" in argv:
                    if kind == "remote":
                        return "f" * 64 + output[64:]
                    target.write_bytes(b"changed after remote readback")
                return output
            self.checked.side_effect = response
            with self.subTest(kind=kind), self.assertRaises(h.Failure):
                h.dispatch(SimpleNamespace(command="picker-key", code=66), self.root, self.config, self.emu)
            self.assertFalse(any(isinstance(row, tuple) and "input" in row for row in self.order))
            self.assertEqual(self.emu.actions[-1]["status"], "blocked-before-action")
            self.assertNotIn("started_at", self.emu.actions[-1])
            target.write_bytes(old)

    def test_ownership_failure_never_runs_guard_or_action(self):
        guard = mock.Mock()
        self.owned.side_effect = h.Failure("wrong owned AVD name")
        with self.assertRaises(h.Failure):
            self.emu.adb(["shell", "input", "keyevent", "66"], before_action=guard)
        guard.assert_not_called()
        self.checked.assert_not_called()

    def test_exact_remote_hash_parser(self):
        remote, pin = h.remote_path(self.emu), self.config["bundle"]["sha256"]
        good = pin + "  " + remote + "\n"
        self.assertEqual(h.parse_remote_hash(good, remote, pin)["sha256"], pin)
        for bad in ("", good + good, good + "\n", " " + good, good.replace(remote, remote + ".extra"), good.replace("  ", " *"), good.upper()):
            with self.subTest(output=bad), self.assertRaises(h.Failure):
                h.parse_remote_hash(bad, remote, pin)

    def test_unguarded_activation_and_invalid_coordinates_are_unsupported(self):
        for command, kw in (("key", {"code": 66}), ("tap", {"x": 1, "y": 2}),
                            ("navigate-key", {"code": 66}), ("picker-key", {"code": 4}),
                            ("picker-key", {"code": True}), ("picker-tap", {"x": -1, "y": 2})):
            with self.subTest(command=command), self.assertRaises(h.Failure):
                h.dispatch(SimpleNamespace(command=command, **kw), self.root, self.config, self.emu)
        self.checked.assert_not_called()

    def test_install_callback_preserves_canonical_guard_isolation_and_fixed_bytes(self):
        stage = self.stage_apk()
        self.emu.install_isolation = lambda: self.order.append("isolation")
        digest_guard = h.require_hash
        def record_hash(*a):
            self.order.append("fixed-bytes")
            return digest_guard(*a)
        self.patch(h, "require_hash", side_effect=record_hash)
        self.emu.adb(["install", str(stage)], timeout=180, before_action=lambda: self.order.append("canonical-bytes"))
        self.assertEqual(self.order[:5], ["owned", "canonical-bytes", "isolation", "fixed-bytes", "fixed-bytes"])
        self.assertEqual(self.order[5][0], "install")

    def test_install_mutation_during_ownership_prevents_action(self):
        stage = self.stage_apk()
        self.emu.install_isolation = lambda: None
        for target in (Path(self.config["manager_apk"]["path"]), stage):
            old = target.read_bytes()
            self.owned.side_effect = lambda *a: target.write_bytes(b"changed APK")
            with self.subTest(target=target), self.assertRaises(h.Failure):
                self.emu.adb(["install", str(stage)], timeout=180, before_action=lambda: None)
            self.checked.assert_not_called()
            target.write_bytes(old)

    def test_install_unexpected_shape_and_callback_failure_fail_closed(self):
        stage = self.stage_apk()
        self.emu.install_isolation = mock.Mock()
        for argv in (["install-multiple", str(stage)], ["install", "-r", str(stage)], ["install", self.config["manager_apk"]["path"]]):
            with self.subTest(argv=argv), self.assertRaises(h.Failure):
                self.emu.adb(argv, timeout=180, before_action=lambda: None)
        self.owned.assert_not_called()
        self.checked.assert_not_called()
        with self.assertRaisesRegex(h.Failure, "canonical failed"):
            self.emu.adb(["install", str(stage)], timeout=180, before_action=mock.Mock(side_effect=h.Failure("canonical failed")))
        self.emu.install_isolation.assert_not_called()
        self.checked.assert_not_called()

    def test_real_canonical_install_verifies_fixed_identity_before_install(self):
        def verify(paths, out, **verification):
            self.order.append("fresh-identity")
            self.assertEqual(verification["expect_package"], h.APP)
            self.assertEqual(verification["expect_version_code"], "39909503")
            self.assertEqual(verification["expect_version_name"], "2.5.0")
            self.assertEqual(verification["expect_signer"], [h.CERT])
            self.assertEqual(verification["abi"], "x86_64")
            h.write_new(out, {"synthetic": True})
            return {"apks": [h.file_record(p) for p in paths], "expected": {"package": h.APP}}
        self.patch(self.emu.verifier, "verify_apks", side_effect=verify)
        self.patch(self.emu, "record_abi", side_effect=lambda: self.emu.state.update(abi={}))
        self.patch(self.emu, "_install_capabilities", return_value={"sdk": 30})
        isolation = self.patch(h.Isolation, "check", return_value={"synthetic": True})
        result = h.install_manager(self.emu, self.config)
        index = next(i for i, row in enumerate(self.order) if isinstance(row, tuple) and row[0] == "install")
        self.assertLess(self.order.index("fresh-identity"), index)
        self.assertEqual(isolation.call_count, 2)
        self.assertIsNone(self.emu.install_isolation)
        self.assertEqual(result["installed_byte_readback"], "not-performed")
        self.assertTrue(result["artifacts"])

    def test_isolation_requires_both_first_unconditional_rules_and_propagated_exit(self):
        def response(argv, env, **kw):
            script = argv[-1]
            if "id -u" in script:
                content = "0\n"
            elif "-S OUTPUT" in script:
                content = "-P OUTPUT ACCEPT\n-A OUTPUT -j DROP\n"
            else:
                content = ""
            return content + "\n__MORPHE_EXIT__=0\n"
        self.checked.side_effect = response
        h.Isolation(self.emu).establish()
        calls = [str(call.args[0][-1]) for call in self.checked.call_args_list]
        self.assertEqual(sum("-I OUTPUT 1 -j DROP" in item for item in calls), 2)
        self.assertEqual(sum("-S OUTPUT" in item for item in calls), 2)
        self.assertTrue(any("ip6tables" in item for item in calls))
        for bad in ("-P OUTPUT DROP\n", "-P OUTPUT DROP\n-A OUTPUT -o wlan0 -j DROP\n", "error\n-P OUTPUT ACCEPT\n-A OUTPUT -j DROP\n"):
            with self.subTest(output=bad), self.assertRaises(h.Failure):
                h.first_output_drop(bad)
        self.checked.side_effect = None
        self.checked.return_value = "0\n"  # No command exit marker.
        with self.assertRaises(h.Failure):
            h.Isolation(self.emu).check()


class EvidenceContracts(Fixture):
    def test_measured_capture_preserves_pending_and_unique_artifact_bytes(self):
        def capture(command, label):
            prefix, suffix = ("hierarchy-", ".xml") if command == "dump" else ("screenshot-", ".png")
            path = self.emu.run / (prefix + label + suffix)
            path.write_bytes(b"self-authored synthetic captured output")
            return {"path": str(path)}
        mocked = self.patch(self.emu, "capture", side_effect=capture)
        result = h.capture(self.emu, "unique", "defaults-untouched")
        self.assertEqual(result["visual_review"], "pending-separate-original-review")
        for item in result["captures"].values():
            h.interval(item, NOW)
            self.assertEqual(h.file_record(item["result"]["path"]), item["result"])
        with self.assertRaisesRegex(h.Failure, "already exists"):
            h.capture(self.emu, "unique", "defaults-untouched")
        self.assertEqual(mocked.call_count, 2)

    def observed_review(self, captures):
        path, review = self.review(captures)
        for name in h.CHECKS:
            label = "local_import" if name == "visual_inspection" else name
            review["checks"][name] = {"status": "observed", "captures": [label], "notes": "Invented parser test, not genuine runtime evidence"}
        path.write_text(json.dumps(review), encoding="utf-8")
        return path

    def save_report_event(self, label, report):
        folder = h.label_directory(self.root, label)
        path = folder / "manager-report.json"
        h.write_new(path, report)
        row = self.event_row("report", label, {"manager_report": h.file_record(path)}, NOW - dt.timedelta(seconds=3))
        h.write_new(folder / "result.json", row)
        return path

    def test_complete_synthetic_graph_requires_original_stop_and_returns_observation_intervals(self):
        captures = self.complete_graph()
        graph = h.validate_graph(self.root, self.session, NOW)
        self.assertEqual(graph["status"], "confirmed-terminal-shutdown")
        self.assertEqual(graph["started_at"], START)
        self.assertEqual(graph["capture_ended_at"], h.read_json(self.root / "evidence/compatibility/result.json")["result"]["captures"]["screenshot"]["ended_at"])
        review = self.observed_review(captures)
        report = h.manager_report(self.root, self.session, review, h.digest(review))
        self.assertEqual(report["status"], "originals-collected-not-release-approval")
        self.assertFalse(report["complete_evidence"])
        self.assertEqual(report["lifecycle"], graph)
        stop = self.root / "evidence/stop"
        moved = self.root / "temporarily-hidden-stop"
        stop.rename(moved)
        with self.assertRaisesRegex(h.Failure, "terminal shutdown"):
            h.validate_graph(self.root, self.session, NOW)
        self.assertEqual(h.manager_report(self.root, self.session, review, h.digest(review))["status"], "pending-original-visual-review")
        moved.rename(stop)
        self.checked.assert_not_called()

    def test_terminal_final_check_missing_early_or_followed_by_device_observation_never_collects(self):
        captures = self.complete_graph()
        review = self.observed_review(captures)
        final_folder = self.root / "evidence/final-check"
        final_path = final_folder / "result.json"
        original = h.read_json(final_path)

        def reject(message):
            # These remain structurally valid original events, not malformed
            # fixtures that merely fail before lifecycle ordering is checked.
            h.capture_events(self.root, self.session, NOW)
            with self.assertRaisesRegex(h.Failure, message):
                h.validate_graph(self.root, self.session, NOW)
            report = h.manager_report(self.root, self.session, review, h.digest(review))
            self.assertEqual(report["status"], "pending-original-visual-review")
            self.assertEqual(report["lifecycle"]["status"], "incomplete")

        hidden = self.root / "temporarily-hidden-final-check"
        final_folder.rename(hidden)
        reject("terminal final-check")
        hidden.rename(final_folder)
        early = copy.deepcopy(original)
        old_start = dt.datetime.fromisoformat(early["started_at"].replace("Z", "+00:00"))
        new_start = NOW - dt.timedelta(hours=1) + dt.timedelta(seconds=70)
        delta = new_start - old_start  # After launch, but genuinely before every capture.
        for item in [early, *early["actions"]]:
            for key in ("started_at", "ended_at"):
                item[key] = h.stamp(dt.datetime.fromisoformat(item[key].replace("Z", "+00:00")) + delta)
        final_path.write_text(json.dumps(early), encoding="utf-8")
        reject("Terminal final-check must follow all captures")
        final_path.write_text(json.dumps(original), encoding="utf-8")
        start = NOW - dt.timedelta(minutes=40, seconds=50)  # 11:19:10, after final-check.
        action = self.action(["shell", "input", "keyevent", "19"], start, .1)
        path, _ = self.emit(self.event_row("navigate-key", "late-navigation", {"stdout": "Synthetic"}, start, [action]))
        reject("Only stop/report may follow terminal final-check")
        path.unlink()
        path.parent.rmdir()
        self.assertEqual(h.validate_graph(self.root, self.session, NOW)["status"], "confirmed-terminal-shutdown")
        self.assertEqual(h.manager_report(self.root, self.session, review, h.digest(review))["status"], "originals-collected-not-release-approval")
        self.checked.assert_not_called()

    def test_repeated_terminal_final_checks_are_unsupported(self):
        self.complete_graph()
        original = h.read_json(self.root / "evidence/final-check/result.json")
        start = NOW - dt.timedelta(minutes=40, seconds=50)
        actions = [self.action(a["argv"], start, .1 + i * .1, a["guards"][1:]) for i, a in enumerate(original["actions"])]
        row = self.event_row("final-check", "duplicate-final-check", original["result"], start, actions, original["isolation_trace"])
        self.emit(row)
        h.capture_events(self.root, self.session, NOW)
        with self.assertRaisesRegex(h.Failure, "Only stop/report may follow terminal final-check"):
            h.validate_graph(self.root, self.session, NOW)

    def test_start_accepts_canonical_failed_or_blocked_partial_abi_retry_then_complete_final_reads(self):
        self.complete_graph()
        path = self.root / "evidence/start/result.json"
        original = h.read_json(path)
        start = dt.datetime.fromisoformat(original["started_at"].replace("Z", "+00:00"))
        boot = ["shell", "getprop", "sys.boot_completed"]
        props = [["shell", "getprop", p] for p in h.PROPERTIES]

        def make_actions(sequence):
            result = []
            for i, (argv, status) in enumerate(sequence):
                if status == "blocked-before-action":
                    action = {"argv": argv, "status": status, "guards": [], "error_type": "Failure"}
                else:
                    action = self.action(argv, start, .05 + i * .04)
                    if status == "failed":
                        action.update(status=status, error_type="Failure")
                result.append(action)
            return result

        final = [(boot, "completed"), *[(p, "completed") for p in props]]
        prefix = [(boot, "completed"), (props[0], "completed"), (props[1], "completed"), (props[2], "failed"),
                  (boot, "failed"), (boot, "completed"), (boot, "completed"), (props[0], "blocked-before-action")]
        for sequence in (final, [(boot, "blocked-before-action"), *final], [*prefix, *final]):
            row = {**original, "actions": make_actions(sequence)}
            h.validate_event(row, self.root, self.session, NOW)
            path.write_text(json.dumps(row), encoding="utf-8")
            self.assertEqual(h.validate_graph(self.root, self.session, NOW)["status"], "confirmed-terminal-shutdown")
        path.write_text(json.dumps(original), encoding="utf-8")

        invalid = {
            "reordered": [(boot, "completed"), *[(p, "completed") for p in reversed(props)]],
            "no_restart_after_property_failure": [(boot, "completed"), (props[0], "failed"), *[(p, "completed") for p in props[1:]]],
            "failed_final_poll": [*prefix, (boot, "completed"), (props[0], "completed"), (props[1], "completed"), (props[2], "failed"), (boot, "failed")],
            "failed_final_property": [*final[:-1], (props[-1], "failed")],
            "blocked_final_property": [*final[:-1], (props[-1], "blocked-before-action")],
            "failed_write": [(["shell", "input", "keyevent", "4"], "failed"), *final],
            "completed_write": [(["shell", "input", "keyevent", "4"], "completed"), *final],
            "complete_reads_then_extra_restart": [*final, *final],
            "property_without_successful_boot": [(boot, "failed"), *[(p, "completed") for p in props]],
        }
        for name, sequence in invalid.items():
            row = {**original, "actions": make_actions(sequence)}
            with self.subTest(sequence=name), self.assertRaises(h.Failure):
                h.validate_event(row, self.root, self.session, NOW)
        row = {**original, "actions": make_actions([*prefix, *final])}
        row["actions"][3]["error_type"] = "UnexpectedExceptionNotCaughtByCanonicalStart"
        with self.assertRaisesRegex(h.Failure, "Failed final ABI|Failure|ABI"):
            h.validate_event(row, self.root, self.session, NOW)
        self.checked.assert_not_called()

    def test_graph_rejects_changed_identity_missing_predecessor_actions_guards_and_overlaps(self):
        self.complete_graph()
        path = self.root / "evidence/local_import/result.json"
        original = h.read_json(path)
        for kind in ("identity", "actions", "overlap", "schema", "guard"):
            row = copy.deepcopy(original)
            if kind == "identity":
                row["device"]["pid"] += 1
            elif kind == "actions":
                row["actions"] = []
            elif kind == "overlap":
                row.update(times("2026-11-10T11:00:50.000000Z", "2026-11-10T11:00:53.000000Z"))
            elif kind == "schema":
                row["unsupported_extra"] = True
            else:
                row["actions"][0]["guards"] = []
            path.write_text(json.dumps(row), encoding="utf-8")
            with self.subTest(kind=kind), self.assertRaises(h.Failure):
                h.validate_graph(self.root, self.session, NOW)
        path.write_text(json.dumps(original), encoding="utf-8")
        launch = self.root / "evidence/launch"
        hidden = self.root / "temporarily-hidden-launch"
        launch.rename(hidden)
        with self.assertRaisesRegex(h.Failure, "predecessors"):
            h.validate_graph(self.root, self.session, NOW)
        hidden.rename(launch)

    def test_graph_rejects_duplicate_lifecycle_and_explicit_operation_failure(self):
        self.complete_graph()
        create = h.read_json(self.root / "evidence/create/result.json")
        duplicate = {**create, "label": "duplicate-create", **times("2026-11-10T11:00:13.000000Z", "2026-11-10T11:00:16.000000Z")}
        path, _ = self.emit(duplicate)
        with self.assertRaisesRegex(h.Failure, "duplicate"):
            h.validate_graph(self.root, self.session, NOW)
        path.unlink()
        path.parent.rmdir()
        row = self.event_row("navigate-key", "explicit-failure", {}, NOW - dt.timedelta(minutes=45))
        row.pop("result")
        row.update(ok=False, error="Synthetic failed action", error_type="Failure")
        self.emit(row)
        with self.assertRaisesRegex(h.Failure, "explicit failed"):
            h.validate_graph(self.root, self.session, NOW)
        self.assertEqual(h.manager_report(self.root, self.session)["lifecycle"]["status"], "incomplete")

    def test_original_report_recheck_is_read_only_and_revalidates_referenced_review_bytes(self):
        captures = self.complete_graph()
        review = self.observed_review(captures)
        report = h.manager_report(self.root, self.session, review, h.digest(review))
        path = self.save_report_event("snapshot", report)
        pin, raw = h.digest(path), path.read_bytes()
        with mock.patch.object(h, "manager_report", side_effect=AssertionError("No recursive report generation")):
            self.assertEqual(h.recheck_report(path, pin, current=NOW), report)
        self.assertEqual(path.read_bytes(), raw)
        # An older snapshot cannot be waved through merely because its own hash
        # is unchanged when the separately referenced original review changed.
        value = h.read_json(review)
        value["reviewer_claim"] += " changed"
        review.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(h.Failure):
            h.recheck_report(path, pin, current=NOW)
        with self.assertRaises(h.Failure):
            h.manager_report(self.root, self.session)
        self.assertEqual(path.read_bytes(), raw)
        self.checked.assert_not_called()

    def test_pending_report_never_promotes_ui_defaults_compatibility_or_features(self):
        self.capture_event()
        report = h.manager_report(self.root, self.session)
        self.assertEqual(report["schema"], "manager-report-v1")
        self.assertFalse(report["complete_evidence"])
        self.assertEqual(report["binding"], self.bound)
        self.assertEqual(report["status"], "pending-original-visual-review")
        self.assertTrue(all(row["status"] == "pending-original-review" for row in report["human_claims"]["checks"].values()))
        self.assertIn("not-observed", report["unsupported"]["feature_behavior"])
        self.checked.assert_not_called()

    def test_mutated_original_capture_event_binding_or_restamped_review_rejected(self):
        path, row = self.capture_event()
        screenshot = Path(row["result"]["captures"]["screenshot"]["result"]["path"])
        old = screenshot.read_bytes()
        screenshot.write_bytes(old + b"mutated")
        with self.assertRaisesRegex(h.Failure, "capture changed"):
            h.manager_report(self.root, self.session)
        screenshot.write_bytes(old)
        for replacement in ({"binding": {**self.bound, "bundle_sha256": "f" * 64}},
                            {"result": {**row["result"], "visual_review": "passed"}},
                            {"ended_at": "2026-11-10T12:00:01.000000Z"},
                            {"started_at": "2026-11-01T11:00:00.000000Z"}):
            path.write_text(json.dumps({**row, **replacement}), encoding="utf-8")
            with self.subTest(replacement=replacement), self.assertRaises(h.Failure):
                h.manager_report(self.root, self.session)
        path.write_text(json.dumps(row), encoding="utf-8")

    def test_changed_device_owner_and_missing_tool_closure_rejected(self):
        path, row = self.capture_event()
        changed = copy.deepcopy(row)
        changed["device"]["owner"] = "f" * 32
        path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaisesRegex(h.Failure, "owner differs"):
            h.manager_report(self.root, self.session)
        changed = copy.deepcopy(row)
        changed["closure_before"]["tools"] = {}
        changed["closure_after"] = changed["closure_before"]
        path.write_text(json.dumps(changed), encoding="utf-8")
        with self.assertRaises(h.Failure):
            h.manager_report(self.root, self.session)

    def test_intervals_reject_nested_future_stale_reversed_restamped_and_boolean(self):
        for row in (times(duration=True), times(duration=0), times(duration=90_000_000_000),
                    times(start=END, end=START), times(start="2026-11-01T11:00:00.000000Z"),
                    times(end="2026-11-10T12:00:01.000000Z"), times(start="2026-11-10T11:00:00")):
            with self.subTest(row=row), self.assertRaises(h.Failure):
                h.interval(row, NOW)
        with self.assertRaisesRegex(h.Failure, "enclosing"):
            h.interval(times(), NOW, within=(dt.datetime(2026, 11, 10, 11, 0, 1, tzinfo=h.UTC), NOW))

    def test_separate_review_requires_exact_original_references_and_purpose(self):
        self.capture_event()
        captures, _ = h.capture_events(self.root, self.session, NOW)
        path, review = self.review(captures)
        original = copy.deepcopy(review)
        report = h.manager_report(self.root, self.session, path, h.digest(path))
        self.assertEqual(report["human_claims"]["checks"]["defaults"]["status"], "not-observed")
        self.assertEqual(report["human_claims"]["review"]["authentication"], "not-authenticated-local-human-claims")
        review["checks"]["defaults"] = {"status": "observed", "captures": ["observed"], "notes": "Would falsely reuse an import screen"}
        path.write_text(json.dumps(review), encoding="utf-8")
        with self.assertRaisesRegex(h.Failure, "purpose-specific"):
            h.manager_report(self.root, self.session, path, h.digest(path))
        for alteration in ("binding", "capture", "before-capture", "unreviewed", "invented-pass"):
            review = copy.deepcopy(original)
            if alteration == "binding":
                review["binding"]["request_sha256"] = "f" * 64
            elif alteration == "capture":
                review["captures"]["observed"]["screenshot"]["sha256"] = "f" * 64
            elif alteration == "before-capture":
                review["reviewed_at"] = "2026-11-10T10:59:00.000000Z"
            elif alteration == "unreviewed":
                review["checks"]["local_import"] = {"status": "observed", "captures": ["not-reviewed"], "notes": "No original reviewed"}
            else:
                review["checks"]["local_import"] = {"status": "passed", "captures": ["observed"], "notes": "Invented flag"}
            path.write_text(json.dumps(review), encoding="utf-8")
            with self.subTest(alteration=alteration), self.assertRaises(h.Failure):
                h.manager_report(self.root, self.session, path, h.digest(path))

    def test_complete_original_claims_do_not_authenticate_or_rewrite_captures(self):
        purposes = {"local_import": "local-import", "collection_identity": "collection-identity", "patch_names": "patch-names",
                    "defaults": "defaults-untouched", "compatibility": "compatibility"}
        originals = {}
        for name, purpose in purposes.items():
            path, _ = self.capture_event(name, purpose)
            originals[path] = path.read_bytes()
        captures, _ = h.capture_events(self.root, self.session, NOW)
        path, review = self.review(captures)
        for name in h.CHECKS:
            label = "local_import" if name == "visual_inspection" else name
            review["checks"][name] = {"status": "observed", "captures": [label], "notes": "Synthetic claim only; no actual acceptance"}
        path.write_text(json.dumps(review), encoding="utf-8")
        report = h.manager_report(self.root, self.session, path, h.digest(path))
        self.assertEqual(report["status"], "pending-original-visual-review")
        self.assertEqual(report["lifecycle"]["status"], "incomplete")
        with self.assertRaisesRegex(h.Failure, "predecessors"):
            h.validate_graph(self.root, self.session, NOW)
        self.assertFalse(report["complete_evidence"])
        for source, raw in originals.items():
            self.assertEqual(source.read_bytes(), raw)
        with self.assertRaises(h.Failure):
            h.manager_report(self.root, self.session, path, "f" * 64)
        with self.assertRaises(h.Failure):
            h.manager_report(self.root, self.session, path, None)

    def test_evidence_labels_new_writes_and_incomplete_events_fail_closed(self):
        folder = h.label_directory(self.root, "incomplete")
        with self.assertRaisesRegex(h.Failure, "Incomplete"):
            h.manager_report(self.root, self.session)
        with self.assertRaises(FileExistsError):
            h.label_directory(self.root, "incomplete")
        for label in ("../escape", "spaces invalid", "", "x" * 65):
            with self.subTest(label=label), self.assertRaises(h.Failure):
                h.label_directory(self.root, label)
        h.write_new(folder / "failure.json", {"original": True})
        with self.assertRaises(FileExistsError):
            h.write_new(folder / "failure.json", {"overwritten": True})


class LifecycleContracts(Fixture):
    def test_canonical_load_and_session_owner_mismatch_fail_closed(self):
        baseline = dict(self.emu.state)
        for key, bad in (("owner", "f" * 32), ("run", str(self.base / "other")), ("sdk", str(self.base / "other-sdk"))):
            self.emu.state = {**baseline, key: bad}
            self.emu.save()
            with self.subTest(field=key), self.assertRaises(h.Failure):
                self.emu.load()
        self.emu.state = {**baseline, "owner": "f" * 32}
        with self.assertRaises(h.Failure):
            h.require_owner_binding(self.root, self.emu)
        self.checked.assert_not_called()

    def test_stop_probe_block_does_not_consume_kill_then_uncertain_dispatch_never_rekills(self):
        marker = self.root / "attempt-normal-stop"
        self.owned.side_effect = h.Failure("owned-name probe blocked")
        with self.assertRaisesRegex(h.Failure, "probe blocked"):
            h.shutdown(self.emu)
        self.assertFalse(marker.exists())
        self.assertEqual(self.emu.state["status"], "running")
        self.checked.assert_not_called()
        self.owned.side_effect = None
        self.checked.side_effect = h.Failure("kill dispatch timed out; outcome unknown")
        with self.assertRaisesRegex(h.Failure, "outcome unknown"):
            h.shutdown(self.emu)
        saved = h.read_json(marker)
        self.assertEqual(saved["state"], "dispatched-or-uncertain")
        self.assertEqual(saved["identity"]["pid"], 12345)
        self.assertEqual(h.read_json(self.emu.state_path)["status"], "stopping")
        self.assertEqual(self.checked.call_count, 1)
        self.patch(h.canonical, "process_exited", return_value=True)
        self.patch(h.canonical, "endpoints_released", return_value=True)
        self.emu.load()
        self.assertEqual(h.shutdown(self.emu)["status"], "stopped")
        self.assertEqual(self.checked.call_count, 1)
        self.assertEqual(marker.read_bytes(), (json.dumps(saved, indent=2) + "\n").encode())

    def test_old_stop_reservation_confirms_exact_identity_read_only_without_evidence_freshness(self):
        marker = self.root / "attempt-normal-stop"
        old = h.stamp(NOW - dt.timedelta(days=30))
        h.write_new(marker, {"schema": "manager-stop-dispatch-v1", "state": "dispatched-or-uncertain",
                             "identity": h.stop_identity(self.emu), "reserved_at": old})
        original = marker.read_bytes()
        exited = self.patch(h.canonical, "process_exited", return_value=True)
        released = self.patch(h.canonical, "endpoints_released", return_value=True)
        result = h.shutdown(self.emu)
        self.assertEqual(result["status"], "stopped")
        self.assertEqual(result["pid"], 12345)
        self.assertEqual(result["console_port"], 5554)
        self.assertEqual(result["transport_port"], 5555)
        exited.assert_called_once_with(12345)
        released.assert_called_once_with(5554)
        self.assertEqual(marker.read_bytes(), original)
        self.owned.assert_not_called()
        self.checked.assert_not_called()
        # Only cleanup reservations are age-exempt. Event/report timestamps
        # continue through the unchanged seven-day freshness gate.
        with self.assertRaisesRegex(h.Failure, "Stale or future event"):
            h.instant(old, NOW)
        with self.assertRaisesRegex(h.Failure, "Stale or future event"):
            h.interval(times(old, h.stamp(NOW - dt.timedelta(days=30) + dt.timedelta(seconds=3))), NOW)

    def test_malformed_or_future_stop_reservation_never_probes_or_rekills(self):
        marker = self.root / "attempt-normal-stop"
        reservation = {"schema": "manager-stop-dispatch-v1", "state": "dispatched-or-uncertain",
                       "identity": h.stop_identity(self.emu), "reserved_at": None}
        exited = self.patch(h.canonical, "process_exited", return_value=True)
        released = self.patch(h.canonical, "endpoints_released", return_value=True)
        for value in (True, "2026-11-10T11:00:00Z", "2026-11-10T11:00:00.000000+00:00",
                      "2026-11-31T11:00:00.000000Z", h.stamp(NOW + dt.timedelta(microseconds=1))):
            marker.write_text(json.dumps({**reservation, "reserved_at": value}), encoding="utf-8")
            with self.subTest(timestamp=value), self.assertRaises(h.Failure):
                h.shutdown(self.emu)
            self.assertEqual(self.emu.state["status"], "running")
        exited.assert_not_called()
        released.assert_not_called()
        self.owned.assert_not_called()
        self.checked.assert_not_called()

    def test_stop_persistence_failure_after_reservation_never_rekills(self):
        save = self.emu.save
        self.patch(self.emu, "save", side_effect=h.Failure("cannot persist stopping"))
        with self.assertRaisesRegex(h.Failure, "persist stopping"):
            h.shutdown(self.emu)
        self.assertTrue((self.root / "attempt-normal-stop").exists())
        self.checked.assert_not_called()
        self.emu.load()  # Saved canonical state is still running, marker is authoritative.
        with mock.patch.object(self.emu, "save", side_effect=save), \
                mock.patch.object(h.canonical, "process_exited", return_value=True), \
                mock.patch.object(h.canonical, "endpoints_released", return_value=True):
            h.shutdown(self.emu)
        self.checked.assert_not_called()

    def test_input_loss_exemption_still_requires_all_original_tool_pins(self):
        self.config_path.unlink()
        _, config = h.checked_session(self.root, self.config_path, self.session["config_sha256"], stopping=True)
        self.assertEqual(set(h.tool_closure(config)["tools"]), {"sdk", "jdk", "python"})
        for name in ("sdk", "jdk", "python"):
            tool = Path(config["tools"][name]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java")
            original = tool.read_bytes()
            tool.write_bytes(original + b"mutated tool")
            with self.subTest(tool=name), self.assertRaisesRegex(h.Failure, "Tool closure"):
                h.tool_closure(config)
            tool.unlink()
            with self.assertRaises(h.Failure):
                h.tool_closure(config)
            tool.write_bytes(original)
        self.checked.assert_not_called()

    def test_input_loss_still_rechecks_original_sdk_ancestry_before_child_action(self):
        self.config_path.unlink()
        sdk = Path(self.session["tools"]["sdk"]["path"])
        original = Path.is_symlink
        with mock.patch.object(Path, "is_symlink", lambda p: p == sdk or original(p)):
            with self.assertRaisesRegex(h.Failure, "Linked"):
                h.tool_closure({"tools": self.session["tools"]})
        self.checked.assert_not_called()

    def test_stop_final_guard_rechecks_tools_after_owned_name_without_consuming_kill(self):
        tool = Path(self.config["tools"]["sdk"]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java")
        self.owned.side_effect = lambda *a: tool.write_bytes(b"mutated during owned-name check")
        with self.assertRaisesRegex(h.Failure, "Tool closure"):
            h.shutdown(self.emu)
        self.assertFalse((self.root / "attempt-normal-stop").exists())
        self.checked.assert_not_called()

    def test_stop_keeps_anchor_after_config_input_loss(self):
        self.config_path.unlink()
        session, config = h.checked_session(self.root, self.config_path, self.session["config_sha256"], stopping=True)
        self.assertEqual(config, {"tools": self.session["tools"]})
        self.assertEqual(session, self.session)
        with self.assertRaises(h.Failure):
            h.checked_session(self.root, self.config_path, "f" * 64, stopping=True)

    def test_owned_shutdown_confirms_exact_pid_and_both_ports(self):
        self.emu.state["status"] = "stopped"
        exited = self.patch(h.canonical, "process_exited", return_value=True)
        released = self.patch(h.canonical, "endpoints_released", return_value=True)
        result = h.shutdown(self.emu)
        self.assertEqual(result["transport_port"], 5555)
        exited.assert_called_once_with(12345)
        released.assert_called_once_with(5554)
        self.checked.assert_not_called()
        for process_done, ports_free in ((False, False), (False, True), (True, False)):
            exited.return_value, released.return_value = process_done, ports_free
            exited.reset_mock()
            released.reset_mock()
            with self.subTest(process=process_done, ports=ports_free), self.assertRaises(h.Failure):
                h.shutdown(self.emu)
            exited.assert_called_once()
            released.assert_called_once()

    def test_stopping_confirms_without_kill_and_invalid_identity_never_probes(self):
        self.emu.state["status"] = "stopping"
        exited = self.patch(h.canonical, "process_exited", return_value=True)
        released = self.patch(h.canonical, "endpoints_released", return_value=True)
        result = h.shutdown(self.emu)
        self.assertEqual(result["confirmation"], "process_exited_and_both_owned_ports_released")
        self.checked.assert_not_called()
        exited.reset_mock()
        released.reset_mock()
        self.emu.state.update(status="stopped", serial="emulator-5556")
        with self.assertRaises(h.Failure):
            h.shutdown(self.emu)
        exited.assert_not_called()
        released.assert_not_called()

    def main_mocks(self):
        self.patch(h, "checked_session", return_value=(self.session, self.config))
        self.patch(h, "ManagerEmulator", return_value=self.emu)
        self.patch(h, "closure", return_value=self.closure())
        self.patch(self.emu, "load", side_effect=lambda: self.order.append(("load", (self.emu.run / ".command-lock").exists())))
        self.patch(h, "require_owner_binding", side_effect=lambda *a: self.order.append("binding"))

    def main_args(self, command, label):
        return ["--root", str(self.root), "--config", str(self.config_path), "--expect-config-sha256", h.digest(self.config_path),
                "--label", label, command]

    def test_main_load_lock_reload_before_dispatch_and_locked_event_finalization(self):
        self.main_mocks()
        def dispatch(*args):
            self.assertTrue((self.root / ".command-lock").is_file())
            self.assertTrue((self.emu.run / ".command-lock").is_file())
            self.order.append("dispatch")
            return {"synthetic": True}
        self.patch(h, "dispatch", side_effect=dispatch)
        writer = h.write_new
        def write(path, value):
            if path.name == "result.json":
                self.assertTrue((self.root / ".command-lock").is_file())
            return writer(path, value)
        self.patch(h, "write_new", side_effect=write)
        with contextlib.redirect_stdout(io.StringIO()):
            code = h.main(self.main_args("remote-check", "one"))
        self.assertEqual(code, 0)
        self.assertEqual(self.order, [("load", False), ("load", True), "binding", "dispatch"])
        self.assertFalse((self.root / ".command-lock").exists())
        self.assertFalse((self.emu.run / ".command-lock").exists())
        self.checked.assert_not_called()

    def test_main_serialized_interval_starts_after_session_lock_not_invocation(self):
        self.main_mocks()
        clock = {"wall": NOW - dt.timedelta(seconds=20), "ticks": 1_000_000_000}
        acquired = []
        real_locked = h.canonical.locked

        @contextlib.contextmanager
        def lock(run):
            with real_locked(run):
                if run == self.root:
                    # Model a pre-acquisition gap that contains the preceding
                    # serialized operation. No sleeping or process is involved.
                    clock["wall"] += dt.timedelta(seconds=10)
                    clock["ticks"] += 10_000_000_000
                    acquired.append(clock["wall"])
                yield

        self.patch(h.canonical, "locked", side_effect=lock)
        self.patch(h, "now", side_effect=lambda: clock["wall"])
        self.patch(h.time, "monotonic_ns", side_effect=lambda: clock["ticks"])
        for fail in (False, True):
            clock.update(wall=NOW - dt.timedelta(seconds=20), ticks=1_000_000_000)
            previous_end = clock["wall"] + dt.timedelta(seconds=9)
            def dispatch(*args):
                clock["wall"] += dt.timedelta(milliseconds=250)
                clock["ticks"] += 250_000_000
                if fail:
                    raise h.Failure("Synthetic serialized action failure")
                return {"synthetic": True}
            label = "clock-failure" if fail else "clock-success"
            with mock.patch.object(h, "dispatch", side_effect=dispatch), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(h.main(self.main_args("remote-check", label)), int(fail))
            path = self.root / "evidence" / label / ("failure.json" if fail else "result.json")
            row = h.read_json(path)
            self.assertEqual(row["started_at"], h.stamp(acquired[-1]))
            self.assertGreaterEqual(h.instant(row["started_at"], NOW), previous_end)
            self.assertEqual(row["duration_ns"], 250_000_000)
            h.interval(row, NOW)
            if fail:
                self.assertEqual(row["error"], "Synthetic serialized action failure")
        self.checked.assert_not_called()

    def test_pre_session_lock_failure_keeps_invocation_interval_and_primary_error(self):
        self.main_mocks()
        start = NOW - dt.timedelta(seconds=2)
        self.patch(h, "now", side_effect=[start, NOW])
        self.patch(h.time, "monotonic_ns", side_effect=[1_000_000_000, 3_000_000_000])
        self.patch(h.canonical, "locked", side_effect=h.Failure("Synthetic session lock unavailable"))
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.assertEqual(h.main(self.main_args("remote-check", "lock-denied")), 1)
        row = json.loads(output.getvalue())
        self.assertEqual(row["started_at"], h.stamp(start))
        self.assertEqual(row["duration_ns"], 2_000_000_000)
        self.assertEqual(row["error"], "Synthetic session lock unavailable")
        self.assertFalse((self.root / "evidence/lock-denied").exists())
        self.checked.assert_not_called()

    def test_main_retains_failed_primary_and_cleanup_as_separate_events(self):
        self.main_mocks()
        self.patch(h, "dispatch", side_effect=[h.Failure("primary install failure"), h.Failure("later shutdown failure")])
        for command, label in (("install", "primary"), ("stop", "cleanup")):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(h.main(self.main_args(command, label)), 1)
        primary = h.read_json(self.root / "evidence/primary/failure.json")
        cleanup = h.read_json(self.root / "evidence/cleanup/failure.json")
        self.assertEqual(primary["error"], "primary install failure")
        self.assertEqual(cleanup["error"], "later shutdown failure")
        self.checked.assert_not_called()

    def test_failed_action_finally_checks_closure_and_config_independently_preserving_primary(self):
        self.main_mocks()
        baseline = self.closure()
        closure = self.patch(h, "closure", side_effect=[baseline, h.Failure("changed tool closure")])
        def fail(*args):
            self.config_path.write_bytes(self.config_path.read_bytes() + b"mutation")
            raise h.Failure("primary action failure")
        dispatch = self.patch(h, "dispatch", side_effect=fail)
        argv = self.main_args("install", "finally-failed")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(h.main(argv), 1)
        row = h.read_json(self.root / "evidence/finally-failed/failure.json")
        self.assertEqual(row["error"], "primary action failure")
        self.assertEqual(row["closure_before"], baseline)
        self.assertIsNone(row["closure_after"])
        self.assertEqual([e["check"] for e in row["postcheck_errors"]], ["closure", "config"])
        self.assertEqual(closure.call_count, 2)
        dispatch.assert_called_once()
        self.checked.assert_not_called()

    def test_failed_action_retains_successful_independent_after_measurement(self):
        self.main_mocks()
        baseline = self.closure()
        self.patch(h, "dispatch", side_effect=h.Failure("primary capture failure"))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(h.main(self.main_args("capture", "after-kept") + ["--purpose", "local-import"]), 1)
        row = h.read_json(self.root / "evidence/after-kept/failure.json")
        self.assertEqual(row["closure_before"], baseline)
        self.assertEqual(row["closure_after"], baseline)
        self.assertEqual(row["postcheck_errors"], [])
        self.assertEqual(row["error"], "primary capture failure")

    def test_once_failures_not_replayed(self):
        h.once(self.root, "push")
        before = (self.root / "attempt-push").read_bytes()
        with self.assertRaises(FileExistsError):
            h.once(self.root, "push")
        self.assertEqual((self.root / "attempt-push").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
