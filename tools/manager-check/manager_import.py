#!/usr/bin/env python3
"""Private, bounded official Manager 2.5.0 local-import capture producer.

Run trusted source with Python -I -B. Configs/hashes bind bytes, not approval or
execution authenticity. No provisioning, private activity-result injection,
release approval, app patching, shared-device operations or global cleanup.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

REPO = Path(__file__).resolve().parents[2]
APK_SHA256 = "681a1c179b9e8698c857a092df0ca9a91e294a103743107f4fe96da20cb42ddc"
CERT = "0b6c9515afb195fac59601696ba0a7907a0b217ccf720b43148427ccf64343e7"
APP = "app.morphe.manager"
IMAGE = "system-images;android-30;google_apis;x86_64"
ORIGIN = "https://github.com/MorpheApp/morphe-manager/releases/tag/v2.5.0"
SCHEMA = "manager-capture-event-v1"
REPORT_SCHEMA = "manager-report-v1"
CHECKS = ("local_import", "collection_identity", "patch_names", "defaults", "compatibility", "visual_inspection")
PURPOSES = ("local-import", "collection-identity", "patch-names", "defaults-untouched", "compatibility", "navigation")
BINDING_KEYS = {"policy", "request_sha256", "bundle_sha256", "catalog_sha256", "source_tree_sha256"}
MAX_JSON = 8 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
UTC = dt.timezone.utc


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Trusted repository module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# Fixed trusted repository modules; never load code from config/input/output roots.
canonical = load("manager_owned_emulator", REPO / ".claude/skills/run-android-morphe/emulator.py")
s = load("manager_staging", REPO / "tools/release/staging.py")
Failure = canonical.Failure


def require(condition, message):
    if not condition:
        raise Failure(message)


def exact(value, keys, name):
    require(isinstance(value, dict) and set(value) == set(keys), "Invalid " + name + " fields")


def expected_hash(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "Expected lowercase SHA-256")
    return value


def absolute(value):
    require(isinstance(value, (str, Path)), "Explicit absolute path required")
    text = str(value)
    require(text and not text.startswith(("\\\\", "//")) and not any(ord(c) < 32 for c in text)
            and not any(c in text for c in "*?"), "Malformed or remote path")
    parts = re.split(r"[/\\]", text)
    require(not any(part in (".", "..") for part in parts), "Dot path components forbidden")
    require(all(not part.endswith((".", " ")) and (":" not in part or (i == 0 and re.fullmatch(r"[A-Za-z]:", part)))
                for i, part in enumerate(parts) if part), "Ambiguous or stream path forbidden")
    path = Path(text)
    require(path.is_absolute(), "Explicit absolute path required")
    # Inspect original ancestry BEFORE resolve, including Windows junctions.
    for parent in (path, *path.parents):
        require(not parent.is_symlink() and not getattr(parent, "is_junction", lambda: False)(), "Linked path ancestry forbidden")
        if parent.exists():
            require(not (getattr(parent.lstat(), "st_file_attributes", 0) & 0x400), "Reparse path forbidden")
    return path.resolve()


def disjoint(a, b):
    require(not a.is_relative_to(b) and not b.is_relative_to(a), "Paths must be disjoint")


def external(value):
    path = absolute(value)
    disjoint(path, REPO)
    return path


def file_record(value, limit=None):
    path = absolute(value)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1, "Regular unaliased file required")
    require(limit is None or before.st_size <= limit, "File exceeds byte limit")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    after = path.stat()
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
    require(all(getattr(before, key) == getattr(after, key) for key in fields), "File changed while hashing")
    return {"path": str(path), "size": after.st_size, "sha256": digest.hexdigest()}


def digest(path):
    return file_record(path)["sha256"]


def require_hash(path, expected):
    require(digest(path) == expected_hash(expected), "Pinned bytes differ: " + str(path))


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def read_json(path, expected=None):
    before = file_record(path, MAX_JSON)
    if expected is not None:
        require(before["sha256"] == expected_hash(expected), "Pinned JSON bytes differ")
    raw = Path(path).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == before["sha256"], "JSON changed during read")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates,
                       parse_constant=lambda _: require(False, "Nonfinite JSON forbidden"))
    require(file_record(path, MAX_JSON) == before, "JSON changed during parse")
    return value


def write_new(path, value):
    path = absolute(path)
    raw = (json.dumps(value, indent=2, allow_nan=False) + "\n").encode("utf-8")
    require(len(raw) <= MAX_JSON, "JSON evidence exceeds byte limit; bounded unsupported")
    with path.open("xb") as stream:
        stream.write(raw)


def inventory(root):
    root = absolute(root)
    require(root.is_dir(), "Installed tool directory required")
    result = {}
    def failed(exc):
        raise Failure("Cannot inventory tool closure") from exc
    for directory, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in dirs + files:
            absolute(Path(directory) / name)
        for name in files:
            record = file_record(Path(directory) / name)
            key = Path(record.pop("path")).relative_to(root).as_posix()
            result[key] = record
            require(len(result) <= 30000, "Tool inventory entry limit exceeded")
    require(result and len({k.casefold() for k in result}) == len(result), "Empty or case-aliased tool closure")
    return dict(sorted(result.items()))


def inventory_hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def now():
    return dt.datetime.now(UTC)


def stamp(value):
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def canonical_instant(value):
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}Z", value) is not None,
            "Canonical UTC microsecond timestamp required")
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise Failure("Invalid canonical UTC date") from exc


def instant(value, current):
    event = canonical_instant(value)
    require(current - dt.timedelta(days=7) <= event <= current, "Stale or future event")
    return event


def interval(row, current, within=None):
    start, end = instant(row["started_at"], current), instant(row["ended_at"], current)
    require(start <= end and type(row["duration_ns"]) is int and row["duration_ns"] > 0, "Invalid measured interval")
    # Independent clocks need not agree exactly, but cannot differ by a second.
    require(abs((end - start).total_seconds() - row["duration_ns"] / 1e9) < 1, "Wall/monotonic clock mismatch")
    if within is not None:
        require(within[0] <= start <= end <= within[1], "Event outside enclosing interval")
    return start, end


def measured(call):
    start, tick = now(), time.monotonic_ns()
    result = call()
    end, elapsed = now(), time.monotonic_ns() - tick
    row = {"started_at": stamp(start), "ended_at": stamp(end), "duration_ns": elapsed}
    interval(row, end)
    return {**row, "result": result}


def binding(config):
    req = read_json(config["request"]["path"], config["request"]["sha256"])
    return {**{k: req[k] for k in ("policy", "bundle_sha256", "catalog_sha256", "source_tree_sha256")},
            "request_sha256": config["request"]["sha256"]}


def read_config(path, expected):
    value = read_json(external(path), expected)
    exact(value, ("schema", "source_root", "request", "bundle", "catalog", "manager_apk", "tools", "verification", "image"), "config")
    require(value["schema"] == "manager-capture-config-v1" and value["image"] == IMAGE, "Unsupported config/image scope")
    require(absolute(value["source_root"]) == REPO, "Config must name this source checkout")
    paths = []
    for name in ("request", "bundle", "catalog", "manager_apk"):
        row = value[name]
        exact(row, ("path", "sha256"), name)
        p = external(row["path"])
        require(str(p) == row["path"], "Canonical input path required")
        file_record(p, MAX_FILE if name in ("bundle", "manager_apk") else MAX_JSON)
        require_hash(p, row["sha256"])
        paths.append(p)
    require(len(set(paths)) == 4, "Distinct inputs required")
    require(paths[1].suffix == ".mpp" and paths[3].suffix == ".apk", "MPP/APK extensions required")
    require(value["manager_apk"]["sha256"] == APK_SHA256, "Only official Manager 2.5.0 bytes supported")
    exact(value["tools"], ("sdk", "jdk", "python"), "tools")
    for row in value["tools"].values():
        exact(row, ("path", "inventory_sha256"), "tool root")
        require(absolute(row["path"]).is_dir(), "Explicit installed tool root required")
        disjoint(absolute(row["path"]), REPO)
        expected_hash(row["inventory_sha256"])
    roots = [absolute(value["tools"][name]["path"]) for name in ("sdk", "jdk", "python")]
    for i, root in enumerate(roots):
        for other in roots[i + 1:]:
            disjoint(root, other)
    require(absolute(value["tools"]["python"]["path"]) == absolute(sys.base_prefix), "Wrong executing Python runtime root")
    require(absolute(sys.executable).is_relative_to(roots[2]), "Interpreter outside pinned runtime")
    v = value["verification"]
    exact(v, ("aapt2", "java", "signer_jar"), "verification tools")
    for name, path_value in v.items():
        p = absolute(path_value)
        require(p.is_relative_to(roots[1] if name == "java" else roots[0]), "Verifier tool outside closure")
        file_record(p)
    java_name = "java.exe" if os.name == "nt" else "java"
    require(absolute(v["java"]) == roots[1] / "bin" / java_name, "Explicit JDK Java required")
    req = read_json(paths[0], value["request"]["sha256"])
    s.r.exact(req, "schema policy owner repository version created_at description bundle_sha256 catalog_sha256 source_tree_sha256 provenance", "request")
    require(type(req["schema"]) is int and req["schema"] == 2 and req["policy"] == s.COLLECTION_POLICY, "Only schema2 collection request supported")
    require(req["owner"] + "/" + req["repository"] == s.TARGET and req["version"] == "0.1.0", "Wrong collection identity")
    s.r.make_manifest(req)
    require(s.r.local_time(req["created_at"]) <= now(), "Future request")
    for name in ("bundle", "catalog"):
        require(req[name + "_sha256"] == value[name]["sha256"], "Request/input binding mismatch")
    expected_hash(req["source_tree_sha256"])
    meta = s.r.bundle_metadata(s.r.read_bytes(paths[1], s.r.MAX_BUNDLE))
    require(all(meta.get(k) == v for k, v in {"name": "FISHYau android patches", "author": "FISHYau", "version": req["version"], "patcher-version": "2.3.0"}.items()), "Wrong MPP metadata")
    s.collection_inventory(read_json(paths[2]), req["version"])
    require_hash(path, expected)
    return value


def tool_closure(config):
    """Recheck original path spellings and saved pins, even for input-loss stop."""
    exact(config["tools"], ("sdk", "jdk", "python"), "pinned tools")
    roots, tools = [], {}
    for name, row in config["tools"].items():
        exact(row, ("path", "inventory_sha256"), "pinned tool")
        root = absolute(row["path"])
        require(str(root) == row["path"], "Canonical original tool path required")
        disjoint(root, REPO)
        for other in roots:
            disjoint(root, other)
        roots.append(root)
        entries = inventory(root)
        require(inventory_hash(entries) == expected_hash(row["inventory_sha256"]), "Tool closure changed: " + name)
        tools[name] = {"root": row["path"], "files": entries, "inventory_sha256": row["inventory_sha256"]}
    runtime = absolute(config["tools"]["python"]["path"])
    require(absolute(sys.base_prefix) == runtime and absolute(sys.executable).is_relative_to(runtime),
            "Wrong executing Python runtime root")
    return {"tools": tools, "python_executable": file_record(sys.executable)}


def closure(config):
    tree, paths = s.r.source_tree(REPO)
    req = read_json(config["request"]["path"], config["request"]["sha256"])
    require(tree == req["source_tree_sha256"], "Source tree changed from original request")
    s.collection_provenance(req["provenance"], paths)
    tools = tool_closure(config)
    for name in ("request", "bundle", "catalog", "manager_apk"):
        require_hash(config[name]["path"], config[name]["sha256"])
    return {"source_tree_sha256": tree, **tools}


def bundle_paths(root, config):
    return Path(config["bundle"]["path"]), root / "bundle-stage" / "collection.mpp"


def bundle_guard(root, config):
    for path in bundle_paths(root, config):
        require_hash(path, config["bundle"]["sha256"])


def stage_bundle(root, config):
    stage = root / "bundle-stage"
    stage.mkdir(mode=0o700, exist_ok=False)
    original, target = bundle_paths(root, config)
    file_record(original, MAX_FILE)
    require_hash(original, config["bundle"]["sha256"])
    count = 0
    with original.open("rb") as source, target.open("xb") as dest:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            count += len(block)
            require(count <= MAX_FILE, "MPP staging byte limit exceeded")
            dest.write(block)
    bundle_guard(root, config)
    mapping = {"original": str(original), "staged": str(target), "sha256": config["bundle"]["sha256"]}
    write_new(stage / "mapping.json", mapping)
    return mapping


class ManagerEmulator(canonical.Emulator):
    """Compose guards without monkeypatching canonical code or bypassing adb()."""
    def __init__(self, config, run):
        sdk = absolute(config["tools"]["sdk"]["path"])
        jdk = absolute(config["tools"]["jdk"]["path"])
        super().__init__(sdk, absolute(run))
        self.config = config
        forbidden = {"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "KOTLIN_HOME"}
        self.env = {key: value for key, value in self.env.items() if key.upper() not in forbidden}
        self.env["JAVA_HOME"] = str(jdk)
        self.install_isolation = None
        self.actions = []
        self.helper_trace = []

    def manager_command(self):
        java = absolute(self.config["tools"]["jdk"]["path"]) / "bin" / ("java.exe" if os.name == "nt" else "java")
        file_record(java)  # Never let canonical's PATH fallback select another JDK.
        command = super().manager_command()
        require(absolute(command[0]) == java, "Unexpected Java executable")
        return command

    def adb(self, args, timeout=30, binary=False, before_action=None):
        args = list(args)
        guard = before_action
        guard_names = ["canonical-owned-name"]
        if args == ["emu", "kill"]:
            def stop_guard():
                if guard is not None:
                    guard()
                tool_closure(self.config)
                # Canonical adb has already verified the exact owned AVD name.
                # Persist the conservative dispatch intent before any kill bytes.
                write_new(self.run.parent / "attempt-normal-stop", {
                    "schema": "manager-stop-dispatch-v1", "state": "dispatched-or-uncertain",
                    "identity": stop_identity(self), "reserved_at": stamp(now())})
                self.state["status"] = "stopping"
                self.save()
            final_guard = stop_guard
            guard_names += ["saved-tool-closure", "exclusive-stop-reservation", "persist-stopping-before-kill"]
        elif args and args[0] in ("install", "install-multiple"):
            require(len(args) == 2 and args[0] == "install" and not binary and timeout == 180
                    and guard is not None and self.install_isolation is not None, "Unexpected Manager install context/shape")
            staged = absolute(args[1])
            require(staged.name == "member-0.apk" and staged.parent.parent == self.run
                    and re.fullmatch(r"install-stage-[0-9a-f]{32}", staged.parent.name), "Unexpected canonical APK stage")
            def install_guard():
                guard()
                self.install_isolation()
                require_hash(self.config["manager_apk"]["path"], APK_SHA256)
                require_hash(staged, APK_SHA256)
            final_guard = install_guard
            guard_names += ["canonical-install-bytes", "guest-isolation-readback", "official-apk-bytes"]
        else:
            final_guard = guard
            if guard is not None:
                guard_names += ["callback-completed"]
        row = {"argv": list(map(str, args)), "status": "blocked-before-action", "guards": []}
        tick = None
        def before():
            nonlocal tick
            if final_guard is not None:
                final_guard()
            row["guards"] = guard_names
            row["started_at"] = stamp(now())
            tick = time.monotonic_ns()  # After successful ownership and every byte guard.
        try:
            output = super().adb(args, timeout=timeout, binary=binary, before_action=before)
            row["status"] = "completed"
            return output
        except Exception as exc:
            row["error_type"] = type(exc).__name__
            if tick is not None:
                row["status"] = "failed"
            raise
        finally:
            if tick is not None:
                row.update(ended_at=stamp(now()), duration_ns=time.monotonic_ns() - tick)
            self.actions.append(row)


def parse_remote_hash(output, remote, expected):
    expected_hash(expected)
    require(re.fullmatch(re.escape(expected) + r"  " + re.escape(remote) + r"\r?\n?", output) is not None,
            "Remote SHA-256 missing, ambiguous, mismatched or wrong-path")
    return {"path": remote, "sha256": expected}


def remote_path(emu):
    owner = emu.state["owner"]
    require(isinstance(owner, str) and re.fullmatch(r"[0-9a-f]{32}", owner), "Invalid owner token")
    return "/sdcard/Download/morphe_" + owner + ".mpp"


def remote_check(emu, root, config):
    remote = remote_path(emu)
    output = emu.adb(["shell", "toybox", "sha256sum", remote],
                     before_action=lambda: bundle_guard(root, config))
    return parse_remote_hash(output, remote, config["bundle"]["sha256"])


def push_bundle(emu, root, config):
    _, staged = bundle_paths(root, config)
    output = emu.adb(["push", str(staged), remote_path(emu)], timeout=120,
                     before_action=lambda: bundle_guard(root, config))
    bundle_guard(root, config)
    return {"stdout": output, "remote": remote_check(emu, root, config)}


def picker_action(emu, root, config, action):
    def guard():
        # Nested readback also checks ownership. Nothing runs after final host
        # guard except timestamp measurement and the original canonical action.
        remote_check(emu, root, config)
        bundle_guard(root, config)
    return emu.adb(["shell", "input", *action], before_action=guard)


def first_output_drop(output):
    lines = output.splitlines()
    require(len(lines) >= 2 and re.fullmatch(r"-P OUTPUT (ACCEPT|DROP)", lines[0])
            and lines[1] == "-A OUTPUT -j DROP" and all(line.startswith("-A OUTPUT ") for line in lines[1:]),
            "No unconditional first-position OUTPUT DROP")


class Isolation:
    """Fixed guest-only commands. No adb-root/reconnect or host firewall fallback."""
    END = "__MORPHE_EXIT__="

    def __init__(self, emu):
        self.emu, self.mode = emu, None

    def command(self, command, mode):
        script = command + '; rc=$?; printf "\\n' + self.END + '%s\\n" "$rc"; exit "$rc"'
        args = ["shell"] + ([] if mode == "adbd" else ["su", "0"]) + ["sh", "-c", "'" + script + "'"]
        record = {"command": command, "mode": mode}
        self.emu.helper_trace.append(record)
        try:
            output = self.emu.adb(args, timeout=15)
        except Exception as exc:
            record["error"] = str(exc)
            raise
        record["stdout"] = output
        match = re.fullmatch(r"([\s\S]*)\n" + self.END + r"0\r?\n", output)
        require(match is not None and self.END not in match[1], "Guest command exit not confirmed")
        return match[1]

    def privilege(self):
        uid = self.command("id -u", "adbd")
        if uid in ("0\n", "0\r\n"):
            self.mode = "adbd"
        elif re.fullmatch(r"[1-9][0-9]*\r?\n", uid):
            require(self.command("id -u", "su") in ("0\n", "0\r\n"), "Installed su did not establish root")
            self.mode = "su"
        else:
            raise Failure("Unexpected guest uid")

    def check(self):
        if self.mode is None:
            self.privilege()
        for family in ("iptables", "ip6tables"):
            first_output_drop(self.command(family + " -w 2 -S OUTPUT", self.mode))
        return {"boundary": "guest IPv4+IPv6 first OUTPUT DROP", "privilege": self.mode,
                "limit": "Readback only; no connectivity probe or host isolation"}

    def establish(self):
        self.privilege()
        for family in ("iptables", "ip6tables"):
            self.command(family + " -w 2 -I OUTPUT 1 -j DROP", self.mode)
        return self.check()


def install_manager(emu, config):
    require_hash(config["manager_apk"]["path"], APK_SHA256)
    isolation = Isolation(emu)
    isolation.check()
    require(emu.install_isolation is None, "Install context already active")
    emu.install_isolation = isolation.check
    try:
        result = emu.install([config["manager_apk"]["path"]], verification={
            **config["verification"], "expect_package": APP, "expect_version_code": "39909503",
            "expect_version_name": "2.5.0", "expect_signer": [CERT],
            "abi": "x86_64", "density": "nodpi", "language": ["none"],
        })
    finally:
        emu.install_isolation = None
    require_hash(config["manager_apk"]["path"], APK_SHA256)
    require(len(result["mapping"]) == 1 and result["mapping"][0]["sha256"] == APK_SHA256, "Install mapping differs")
    stage = Path(result["mapping"][0]["staged"]).parent
    artifacts = [file_record(path) for path in sorted(stage.iterdir())]
    return {"canonical": result, "artifacts": artifacts, "installed_byte_readback": "not-performed",
            "signer_provenance": "observed official HTTPS release certificate, not independent prior signer trust"}


def capture(emu, label, purpose):
    require(purpose in PURPOSES and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label), "Invalid capture purpose/label")
    for prefix, suffix in (("hierarchy-", ".xml"), ("screenshot-", ".png")):
        require(not (emu.run / (prefix + label + suffix)).exists(), "Capture label already exists")
    captures = {}
    for command in ("dump", "screenshot"):
        captures[command] = measured(lambda: file_record(emu.capture(command, label=label)["path"], MAX_FILE))
    return {"purpose": purpose, "captures": captures, "visual_review": "pending-separate-original-review"}


def stop_identity(emu):
    console, pid = emu.state.get("console_port"), emu.state.get("pid")
    require(type(pid) is int and pid > 0 and type(console) is int and console in range(5554, 5683, 2)
            and emu.state.get("serial") == "emulator-%s" % console, "Invalid exact shutdown identity")
    emu.bind_server()
    return {**owner_binding(emu), "pid": pid, "serial": emu.state["serial"], "console_port": console,
            "transport_port": console + 1, "server_port": emu.state["server_port"]}


def shutdown(emu):
    identity = stop_identity(emu)
    reservation = emu.run.parent / "attempt-normal-stop"
    if reservation.exists():
        saved = read_json(reservation)
        exact(saved, ("schema", "state", "identity", "reserved_at"), "stop reservation")
        require(saved["schema"] == "manager-stop-dispatch-v1" and saved["state"] == "dispatched-or-uncertain"
                and saved["identity"] == identity, "Stop reservation identity differs")
        # An old reservation permanently consumes the kill attempt. Cleanup may
        # confirm this exact identity read-only even after evidence has expired.
        require(canonical_instant(saved["reserved_at"]) <= now(), "Future stop reservation")
        # Even a failure saving stopping or a timed-out kill must never re-kill.
        require(emu.state["status"] in ("starting", "running", "stopping", "stopped"), "Invalid reserved stop status")
        if emu.state["status"] != "stopped":
            emu.state["status"] = "stopping"
            emu.save()
    if emu.state["status"] in ("starting", "running", "stopping"):
        if emu.state["status"] != "stopping":
            tool_closure(emu.config)  # Pins before the canonical ownership probe too.
        result = emu.stop(timeout=120)
        return {**result, **identity}
    require(emu.state["status"] == "stopped", "No shutdown confirmation for this lifecycle")
    exited = canonical.process_exited(identity["pid"])
    released = canonical.endpoints_released(identity["console_port"])
    require(exited and released, "Already-exited shutdown unconfirmed; no fallback kill")
    return {**identity, "status": "stopped",
            "confirmation": "read_only_process_exited_and_both_owned_ports_released"}


def startup_snapshot(emu, source):
    """Copy the finite prefix observed at boot, never hash a still-growing log."""
    source = absolute(source)
    require(source.parent == emu.run and re.fullmatch(r"emulator-[0-9a-f]{32}\.log", source.name),
            "Unexpected live startup log")
    before = source.stat()
    limit = 8 * 1024 * 1024
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
            "Startup log snapshot exceeds bound or aliases a file")
    with source.open("rb") as stream:
        content = stream.read(before.st_size)
    after = source.stat()
    require(len(content) == before.st_size and after.st_size >= before.st_size
            and (before.st_dev, before.st_ino) == (after.st_dev, after.st_ino), "Startup log replaced or truncated")
    target = emu.run / "startup-log-snapshot.log"
    with target.open("xb") as stream:
        stream.write(content)
    return {"log": str(target), "artifacts": [file_record(target, limit)],
            "snapshot": {"source_path": str(source), "prefix_bytes": len(content), "limit_bytes": limit}}



def owner_binding(emu):
    return {"owner": emu.state["owner"], "avd": emu.state["avd"], "run": str(emu.run), "sdk": str(emu.sdk),
            "avd_home": str(emu.run / "avd"), "data_home": str(emu.run / "android-user")}


def device_snapshot(emu):
    return {**owner_binding(emu), **{key: emu.state.get(key) for key in
            ("status", "image", "pid", "serial", "console_port", "server_port", "abi")}}


def require_owner_binding(root, emu):
    require(read_json(root / "device-owner.json") == owner_binding(emu), "Session device ownership binding differs")


def once(root, command):
    with (root / ("attempt-" + command)).open("x", encoding="ascii") as stream:
        stream.write("attempt reserved; acceptance not implied\n")


def checked_session(root, config_path, config_hash, *, stopping=False):
    session = read_json(root / "session.json")
    exact(session, ("schema", "root", "config_path", "config_sha256", "binding", "tools"), "session")
    require(session["schema"] == "manager-capture-session-v1" and session["root"] == str(root)
            and session["config_path"] == str(absolute(config_path)) and session["config_sha256"] == config_hash,
            "Session/config binding differs")
    exact(session["binding"], BINDING_KEYS, "session five-field binding")
    require(session["binding"]["policy"] == s.COLLECTION_POLICY, "Wrong session policy")
    for key in BINDING_KEYS - {"policy"}:
        expected_hash(session["binding"][key])
    exact(session["tools"], ("sdk", "jdk", "python"), "session tools")
    for row in session["tools"].values():
        exact(row, ("path", "inventory_sha256"), "session tool root")
        absolute(row["path"])
        expected_hash(row["inventory_sha256"])
    if stopping:
        # No executable path substitution from a changed/deleted config during stop.
        return session, {"tools": session["tools"]}
    config = read_config(config_path, config_hash)
    require(binding(config) == session["binding"] and config["tools"] == session["tools"], "Session inputs differ")
    return session, config


def dispatch(args, root, config, emu):
    command = args.command
    if command in ("start", "isolate", "install", "push", "launch"):
        once(root, command)
    if command == "start":
        result = emu.start(300, "swiftshader_indirect")
        return {**result, **startup_snapshot(emu, result["log"])}
    if command == "isolate":
        return Isolation(emu).establish()
    if command == "install":
        return install_manager(emu, config)
    if command == "push":
        return push_bundle(emu, root, config)
    if command == "launch":
        Isolation(emu).check()
        require(not (emu.run / "launch.txt").exists(), "Launch evidence already exists")
        result = emu.launch(APP, None)
        return {**result, "artifacts": [file_record(result["stdout"])]}
    if command == "capture":
        return capture(emu, args.label, args.purpose)
    if command == "picker-tap":
        require(all(type(n) is int and 0 <= n <= 32767 for n in (args.x, args.y)), "Invalid tap coordinates")
        return {"stdout": picker_action(emu, root, config, ["tap", str(args.x), str(args.y)])}
    if command == "picker-key":
        require(type(args.code) is int and args.code in (23, 66, 160), "Only picker activation keys 23/66/160 supported")
        return {"stdout": picker_action(emu, root, config, ["keyevent", str(args.code)])}
    if command == "navigate-key":
        require(type(args.code) is int and args.code in (4, 19, 20, 21, 22, 61), "Only non-activation navigation keys supported")
        return {"stdout": emu.adb(["shell", "input", "keyevent", str(args.code)])}
    if command == "remote-check":
        return remote_check(emu, root, config)
    if command == "final-check":
        return {"isolation": Isolation(emu).check(), "remote": remote_check(emu, root, config),
                "limit": "Not UI success, feature behavior, installed-byte proof or release approval"}
    if command == "stop":
        return shutdown(emu)
    raise Failure("Unsupported command")


def capture_events(root, session, current, *, references=None, seen=None):
    """Read original observations; optionally recheck an older immutable subset."""
    captures, events = {}, []
    seen = {} if seen is None else seen
    folders = sorted((root / "evidence").iterdir()) if references is None else [Path(ref["event"]["path"]).parent for ref in references]
    require(len(folders) <= 256 and len(set(folders)) == len(folders), "Event count/uniqueness bound exceeded")
    for folder in folders:
        require(folder.parent == root / "evidence", "Event outside original evidence root")
        absolute(folder)
        require(folder.is_dir() and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", folder.name), "Unexpected evidence entry")
        names = {path.name for path in folder.iterdir()}
        require(len(names & {"result.json", "failure.json"}) == 1, "Incomplete or ambiguous event")
        for path in sorted(folder.iterdir()):
            if path.name == "manager-report.json":
                # An auxiliary snapshot is never an original device observation.
                file_record(path, MAX_JSON)
                continue
            require(path.name in ("result.json", "failure.json"), "Unexpected event file")
            row = read_json(path)
            validate_event(row, root, session, current)
            require((path.name == "result.json") == row["ok"], "Event outcome filename mismatch")
            require(row.get("schema") == SCHEMA and row.get("binding") == session["binding"], "Foreign event/binding")
            window = interval(row, current)
            require(row["label"] == folder.name and row["root"] == str(root), "Event path/label mismatch")
            if row.get("ok") is True and row["command"] != "stop":
                require(row["closure_before"] == row["closure_after"], "Event closure changed")
                require(row["closure_before"]["source_tree_sha256"] == session["binding"]["source_tree_sha256"], "Event source differs")
                exact(row["closure_before"]["tools"], ("sdk", "jdk", "python"), "event tool closure")
                for name, tool in row["closure_before"]["tools"].items():
                    require(tool["root"] == session["tools"][name]["path"]
                            and inventory_hash(tool["files"]) == tool["inventory_sha256"] == session["tools"][name]["inventory_sha256"], "Event tools differ")
            if row["command"] == "stop" and row.get("ok") is True:
                require(row["result"].get("status") == "stopped" and row["result"].get("confirmation") in
                        ("process_exited_and_both_owned_ports_released", "read_only_process_exited_and_both_owned_ports_released"),
                        "Unconfirmed shutdown event")
            if row["command"] in ("capture", "picker-tap", "picker-key") and row.get("ok") is True:
                device = row["device"]
                owner = read_json(root / "device-owner.json")
                require(all(device[k] == v for k, v in owner.items()), "Original capture/action owner differs")
                require(device["status"] == "running" and type(device["pid"]) is int and device["pid"] > 0
                        and type(device["console_port"]) is int and device["console_port"] in range(5554, 5683, 2)
                        and device["serial"] == "emulator-%s" % device["console_port"]
                        and type(device["server_port"]) is int and 1024 <= device["server_port"] <= 65535
                        and device["server_port"] != 5037, "Invalid original live device identity")
            for action in row.get("actions", []):
                require(action.get("status") in ("completed", "failed", "blocked-before-action"), "Invalid action status")
                if "started_at" in action:
                    interval(action, current, within=window)
                else:
                    require(action["status"] == "blocked-before-action", "Unmeasured action")
            if row.get("ok") is True:
                for artifact in row["result"].get("artifacts", []):
                    require(absolute(artifact["path"]).is_relative_to(root / "device-run"), "Artifact outside owned run")
                    require(artifact == file_record(artifact["path"]), "Original operation artifact changed")
                if row["command"] == "report":
                    ref = row["result"]["manager_report"]
                    require(ref == file_record(folder / "manager-report.json"), "Previous report changed")
                    recheck_report(ref["path"], ref["sha256"], current=current, _seen=seen, _snapshot=True)
            reference = file_record(path)
            events.append({"event": reference, "command": row["command"], "ok": row["ok"],
                           "started_at": row["started_at"], "ended_at": row["ended_at"], "duration_ns": row["duration_ns"]})
            if row["command"] != "capture" or row["ok"] is not True:
                continue
            result = row["result"]
            require(result["visual_review"] == "pending-separate-original-review" and result["purpose"] in PURPOSES, "Capture review was restamped")
            for key, prefix, suffix in (("dump", "hierarchy-", ".xml"), ("screenshot", "screenshot-", ".png")):
                item = result["captures"][key]
                interval(item, current, within=window)
                original = root / "device-run" / (prefix + row["label"] + suffix)
                require(item["result"] == file_record(original, MAX_FILE), "Original capture changed/substituted")
            captures[row["label"]] = {"event": reference, "purpose": result["purpose"], "ended_at": row["ended_at"],
                                     "screenshot": result["captures"]["screenshot"]["result"],
                                     "hierarchy": result["captures"]["dump"]["result"]}
    if references is not None:
        require(events == references, "Original report event references changed")
    return captures, events


COMMANDS = {"init", "create", "start", "isolate", "install", "push", "launch", "capture", "picker-tap",
            "picker-key", "navigate-key", "remote-check", "final-check", "stop", "report"}
EVENT_FIELDS = {"schema", "root", "label", "binding", "started_at", "ended_at", "duration_ns", "ok", "command",
                "closure_before", "closure_after", "closure_exemption", "postcheck_errors", "device", "actions", "isolation_trace"}
PROPERTIES = ("ro.build.version.sdk", "ro.product.cpu.abi", "ro.product.cpu.abilist", "ro.product.cpu.abilist32",
              "ro.product.cpu.abilist64", "ro.dalvik.vm.native.bridge", "ro.enable.native.bridge.exec",
              "ro.enable.native.bridge.exec64", "ro.dalvik.vm.isa.arm", "ro.dalvik.vm.isa.arm64")


def recorded_tools(value, session, *, full):
    exact(value, ("source_tree_sha256", "tools", "python_executable") if full else ("tools", "python_executable"), "measured closure")
    if full:
        require(value["source_tree_sha256"] == session["binding"]["source_tree_sha256"], "Event source differs")
    exact(value["tools"], ("sdk", "jdk", "python"), "event tool closure")
    for name, tool in value["tools"].items():
        exact(tool, ("root", "files", "inventory_sha256"), "measured tool")
        require(tool["root"] == session["tools"][name]["path"] and isinstance(tool["files"], dict)
                and 0 < len(tool["files"]) <= 30000, "Event tool root/inventory differs")
        for path, item in tool["files"].items():
            require(isinstance(path, str) and not path.startswith(("/", "\\")) and ":" not in path
                    and all(p not in ("", ".", "..") for p in re.split(r"[/\\]", path)), "Invalid inventory path")
            exact(item, ("size", "sha256"), "inventory member")
            require(type(item["size"]) is int and item["size"] >= 0, "Invalid inventory size")
            expected_hash(item["sha256"])
        require(inventory_hash(tool["files"]) == tool["inventory_sha256"] == session["tools"][name]["inventory_sha256"], "Event tools differ")
    file_ref(value["python_executable"])
    runtime = Path(session["tools"]["python"]["path"])
    require(Path(value["python_executable"]["path"]).is_relative_to(runtime), "Measured interpreter outside pinned runtime")
    key = Path(value["python_executable"]["path"]).relative_to(runtime).as_posix()
    require(value["tools"]["python"]["files"].get(key) == {k: value["python_executable"][k] for k in ("size", "sha256")},
            "Measured interpreter differs from tool closure")


def file_ref(value):
    exact(value, ("path", "size", "sha256"), "file reference")
    require(isinstance(value["path"], str) and type(value["size"]) is int and value["size"] >= 0, "Invalid file reference")
    expected_hash(value["sha256"])


def live_device(device, root, session, *, active=True):
    exact(device, ("owner", "avd", "run", "sdk", "avd_home", "data_home", "status", "image", "pid", "serial",
                   "console_port", "server_port", "abi"), "device snapshot")
    owner = read_json(root / "device-owner.json")
    exact(owner, ("owner", "avd", "run", "sdk", "avd_home", "data_home"), "device owner")
    require(all(device[k] == v for k, v in owner.items()), "Original capture/action owner differs")
    require(re.fullmatch(r"[0-9a-f]{32}", device["owner"]) and device["avd"] == "morphe_" + device["owner"]
            and device["run"] == str(root / "device-run") and device["sdk"] == session["tools"]["sdk"]["path"]
            and device["avd_home"] == str(root / "device-run/avd")
            and device["data_home"] == str(root / "device-run/android-user") and device["image"] == IMAGE,
            "Invalid device ownership paths/image")
    if active:
        require(device["status"] in ("running", "stopped") and type(device["pid"]) is int and device["pid"] > 0
                and type(device["console_port"]) is int and device["console_port"] in range(5554, 5683, 2)
                and device["serial"] == "emulator-%s" % device["console_port"]
                and type(device["server_port"]) is int and 1024 <= device["server_port"] <= 65535
                and device["server_port"] != 5037, "Invalid original live device identity")


def validate_event(row, root, session, current):
    require(isinstance(row, dict) and type(row.get("ok")) is bool and row.get("command") in COMMANDS, "Unsupported event/outcome")
    exact(row, EVENT_FIELDS | ({"result"} if row["ok"] else {"error", "error_type"}), "event")
    require(row["schema"] == SCHEMA and row["binding"] == session["binding"] and row["root"] == str(root), "Foreign event/binding")
    window = interval(row, current)
    require(isinstance(row["postcheck_errors"], list) and len(row["postcheck_errors"]) <= 3, "Invalid postcheck errors")
    for error in row["postcheck_errors"]:
        exact(error, ("check", "error_type", "error"), "postcheck error")
        require(error["check"] in ("closure", "config", "closure-equality") and all(isinstance(v, str) for v in error.values()), "Invalid postcheck error")
    stopping = row["command"] == "stop"
    require(row["closure_exemption"] == ("owned-shutdown-only-input-loss" if stopping else None), "Invalid closure exemption")
    for key in ("closure_before", "closure_after"):
        if row[key] is not None:
            recorded_tools(row[key], session, full=not stopping)
    if row["ok"]:
        require(row["closure_before"] is not None and row["closure_before"] == row["closure_after"]
                and not row["postcheck_errors"], "Successful event missing unchanged closure")
    else:
        require(isinstance(row["error"], str) and isinstance(row["error_type"], str) and row["error_type"], "Failure lacks primary error")
    require(isinstance(row["actions"], list) and len(row["actions"]) <= 2048 and isinstance(row["isolation_trace"], list)
            and len(row["isolation_trace"]) <= 16, "Event action/trace bound exceeded")
    previous = window[0]
    for action in row["actions"]:
        status = action.get("status")
        require(status in ("completed", "failed", "blocked-before-action"), "Invalid action status")
        measured_keys = {"started_at", "ended_at", "duration_ns"} if "started_at" in action else set()
        exact(action, {"argv", "status", "guards"} | measured_keys | ({"error_type"} if "error_type" in action else set()), "action")
        require(isinstance(action["argv"], list) and 0 < len(action["argv"]) <= 24
                and all(isinstance(v, str) and len(v) <= 8192 for v in action["argv"]), "Invalid action argv")
        require(isinstance(action["guards"], list) and len(set(action["guards"])) == len(action["guards"]), "Invalid guard evidence")
        if measured_keys:
            start, end = interval(action, current, window)
            require(previous <= start and action["guards"] and action["guards"][0] == "canonical-owned-name", "Overlapping/unowned action")
            previous = end
        else:
            require(status == "blocked-before-action" and not action["guards"], "Unmeasured action")
        require((status == "completed") == ("error_type" not in action), "Action error/status mismatch")
    if not row["ok"]:
        return
    validate_command(row, root, session, current)


def validate_start_actions(actions):
    """Parse only canonical start's bounded boot/ABI read retry grammar.

    A completed boot poll may report not-ready. A boot or property Failure may
    restart at boot, but properties always restart at the first ordered member.
    Only the final completed boot plus ten completed properties is terminal.
    """
    boot = ["shell", "getprop", "sys.boot_completed"]
    props = [["shell", "getprop", key] for key in PROPERTIES]
    require(11 <= len(actions) <= 2048, "Missing or excessive boot/ABI action sequence")
    index = 0
    while index < len(actions):
        poll = actions[index]
        require(poll["argv"] == boot, "Boot retry must restart with boot poll")
        index += 1
        if poll["status"] != "completed":
            require(poll.get("error_type") == "Failure" and index < len(actions), "No successful final boot observation")
            continue
        require(index < len(actions), "Missing complete final ABI observations")
        if actions[index]["argv"] == boot:
            continue  # A completed not-ready boot poll; no ABI read occurred.
        for prop in props:
            require(index < len(actions) and actions[index]["argv"] == prop, "Reordered or incomplete ABI observations")
            action = actions[index]
            index += 1
            if action["status"] != "completed":
                require(action.get("error_type") == "Failure" and index < len(actions), "Failed final ABI observation")
                break  # Canonical record_abi aborted; the next action must be boot.
        else:
            require(index == len(actions), "Actions after complete final ABI observations")
            return
    require(False, "Missing successful final boot/ABI observations")


def validate_command(row, root, session, current):
    command, result, actions = row["command"], row["result"], row["actions"]
    require(isinstance(result, dict), "Command result must be an object")
    fields = {
        "init": ("bundle_mapping",), "create": ("state", "avd"),
        "start": ("state", "serial", "log", "artifacts", "snapshot"),
        "isolate": ("boundary", "privilege", "limit"),
        "install": ("canonical", "artifacts", "installed_byte_readback", "signer_provenance"),
        "push": ("stdout", "remote"), "launch": ("component", "stdout", "artifacts"),
        "capture": ("purpose", "captures", "visual_review"), "picker-tap": ("stdout",), "picker-key": ("stdout",),
        "navigate-key": ("stdout",), "remote-check": ("path", "sha256"),
        "final-check": ("isolation", "remote", "limit"), "report": ("manager_report",),
    }
    if command == "stop":
        base = {"owner", "avd", "run", "sdk", "avd_home", "data_home", "pid", "serial", "console_port",
                "transport_port", "server_port", "status", "confirmation"}
        exact(result, base | ({"state"} if "state" in result else set()), "stop result")
    else:
        exact(result, fields[command], command + " result")
    if command in ("init", "report"):
        require(row["device"] is None and not actions and not row["isolation_trace"], "Offline event executed device actions")
        if command == "init":
            mapping = result["bundle_mapping"]
            exact(mapping, ("original", "staged", "sha256"), "bundle mapping")
            require(mapping["staged"] == str(root / "bundle-stage/collection.mpp")
                    and mapping["sha256"] == session["binding"]["bundle_sha256"], "Stage mapping differs")
        return
    device = row["device"]
    live_device(device, root, session, active=command != "create")
    require(device["status"] == ("created" if command == "create" else "stopped" if command == "stop" else "running"), "Unexpected command device status")
    remote = "/sdcard/Download/morphe_" + device["owner"] + ".mpp"
    remote_argv = ["shell", "toybox", "sha256sum", remote]
    props = [["shell", "getprop", key] for key in PROPERTIES]
    trace = row["isolation_trace"]
    trace_argv = []
    allowed_guest = {"id -u", "iptables -w 2 -S OUTPUT", "ip6tables -w 2 -S OUTPUT"}
    if command == "isolate":
        allowed_guest |= {"iptables -w 2 -I OUTPUT 1 -j DROP", "ip6tables -w 2 -I OUTPUT 1 -j DROP"}
    for item in trace:
        exact(item, ("command", "mode", "stdout"), "successful isolation trace")
        require(item["mode"] in ("adbd", "su") and item["command"] in allowed_guest, "Unsupported isolation command")
        body = re.fullmatch(r"([\s\S]*)\n__MORPHE_EXIT__=0\r?\n", item["stdout"])
        require(body is not None and "__MORPHE_EXIT__=" not in body[1], "Isolation exit not confirmed")
        if item["command"].endswith("-S OUTPUT"):
            first_output_drop(body[1])
        if item["command"] == "id -u":
            require(re.fullmatch(r"[0-9]+\r?\n", body[1]), "Invalid privilege result")
        script = item["command"] + '; rc=$?; printf "\\n__MORPHE_EXIT__=%s\\n" "$rc"; exit "$rc"'
        trace_argv.append(["shell"] + ([] if item["mode"] == "adbd" else ["su", "0"]) + ["sh", "-c", "'" + script + "'"])
    observed_trace = [a["argv"] for a in actions if a["argv"] in trace_argv]
    require(observed_trace == trace_argv, "Isolation trace/action mismatch")
    if command in ("isolate", "install", "launch", "final-check"):
        require(trace and trace[0]["command"] == "id -u" and trace[0]["mode"] == "adbd", "Missing privilege probe")
        privileged = trace[0]["stdout"].startswith("0\n") or trace[0]["stdout"].startswith("0\r\n")
        offset = 1 if privileged else 2
        mode = "adbd" if privileged else "su"
        if not privileged:
            require(len(trace) > 1 and trace[1]["command"] == "id -u" and trace[1]["mode"] == "su"
                    and trace[1]["stdout"] in ("0\n\n__MORPHE_EXIT__=0\n", "0\r\n\n__MORPHE_EXIT__=0\r\n"), "Missing root confirmation")
        expected = (["iptables -w 2 -I OUTPUT 1 -j DROP", "ip6tables -w 2 -I OUTPUT 1 -j DROP"] if command == "isolate" else [])
        expected += ["iptables -w 2 -S OUTPUT", "ip6tables -w 2 -S OUTPUT"] * (2 if command == "install" else 1)
        require([t["command"] for t in trace[offset:]] == expected and all(t["mode"] == mode for t in trace[offset:]), "Incomplete guest isolation evidence")
    else:
        require(not trace, "Unexpected isolation trace")
    nontrace = [a for a in actions if a["argv"] not in trace_argv]
    argv = [a["argv"] for a in nontrace]
    for action in actions:
        retry_read = command == "start" and action["argv"] in [["shell", "getprop", "sys.boot_completed"], *props]
        require(action["status"] == "completed" or retry_read, "Successful command contains failed action")
        if action["status"] == "blocked-before-action":
            # Canonical boot/ABI reads may restart; blocked reads never acquire
            # successful guards. The complete retry grammar is checked below.
            require(retry_read and not action["guards"], "Unexpected blocked action in successful command")
            continue
        expected_guards = ["canonical-owned-name"]
        if action["argv"][:1] == ["install"]:
            expected_guards += ["canonical-install-bytes", "guest-isolation-readback", "official-apk-bytes"]
        elif action["argv"] == ["emu", "kill"]:
            expected_guards += ["saved-tool-closure", "exclusive-stop-reservation", "persist-stopping-before-kill"]
        elif action["argv"] == remote_argv or action["argv"][:1] == ["push"] or command in ("picker-tap", "picker-key") and action["argv"][:2] == ["shell", "input"]:
            expected_guards += ["callback-completed"]
        require(action["guards"] == expected_guards, "Missing command-specific guard evidence")
    if command == "create":
        require(not actions and result == {"state": str(root / "device-run/emulator.json"), "avd": device["avd"]}, "Invalid create evidence")
    elif command == "start":
        validate_start_actions(nontrace)
        require(result["state"] == str(root / "device-run/emulator.json") and result["serial"] == device["serial"], "Start identity differs")
        source = Path(result["snapshot"]["source_path"])
        require(source.parent == root / "device-run" and re.fullmatch(r"emulator-[0-9a-f]{32}\.log", source.name), "Invalid live log origin")
        exact(result["snapshot"], ("source_path", "prefix_bytes", "limit_bytes"), "startup snapshot")
        require(result["log"] == str(root / "device-run/startup-log-snapshot.log") and len(result["artifacts"]) == 1
                and result["artifacts"][0]["path"] == result["log"]
                and result["snapshot"]["prefix_bytes"] == result["artifacts"][0]["size"]
                and result["snapshot"]["limit_bytes"] == 8 * 1024 * 1024
                and result["snapshot"]["prefix_bytes"] <= result["snapshot"]["limit_bytes"], "Mutable or invalid startup snapshot")
    elif command == "isolate":
        require(not nontrace and result["boundary"] == "guest IPv4+IPv6 first OUTPUT DROP", "Invalid isolation result")
    elif command == "install":
        record = result["canonical"]
        exact(record, ("state", "apks", "staged_apks", "mapping", "stdout", "abi", "capabilities", "verification", "installed_paths", "installed_abi_evidence", "limit"), "canonical install result")
        require(len(record["mapping"]) == 1, "Wrong Manager install mapping")
        member = record["mapping"][0]
        exact(member, ("original", "staged", "sha256"), "install member")
        stage = Path(member["staged"])
        require(stage.parent.parent == root / "device-run" and stage.name == "member-0.apk"
                and re.fullmatch(r"install-stage-[0-9a-f]{32}", stage.parent.name)
                and member["sha256"] == APK_SHA256, "Invalid official Manager stage")
        require(argv == props + [["install", str(stage)], ["shell", "pm", "path", APP], ["shell", "dumpsys", "package", APP]], "Invalid install action sequence")
        require(record["staged_apks"] == [str(stage)] and record["apks"] == [member["original"]], "Install set differs")
        require(result["installed_byte_readback"] == "not-performed", "Invented installed-byte proof")
        expected_files = {"member-0.apk", "verification.json", "install.txt", "package-paths.txt", "package-abi.txt", "installation.json"}
        require(len(result["artifacts"]) == len(expected_files)
                and {Path(a["path"]).name for a in result["artifacts"]} == expected_files
                and all(Path(a["path"]).parent == stage.parent for a in result["artifacts"]), "Missing original install evidence")
        require(record["verification"] == str(stage.parent / "verification.json")
                and record["stdout"] == str(stage.parent / "install.txt"), "Install evidence paths differ")
        verified = read_json(record["verification"])
        require(verified.get("schema") == 2 and verified.get("status") == "selected_split_set_verified"
                and verified.get("expected") == {"package": APP, "version_code": "39909503", "version_name": "2.5.0", "split": None, "signers_sha256": [CERT]}
                and verified.get("selection") == {"abi": "x86_64", "density": "nodpi", "languages": ["none"]}
                and len(verified.get("apks", [])) == 1 and verified["apks"][0].get("path") == str(stage)
                and verified["apks"][0].get("sha256") == APK_SHA256
                and verified["apks"][0].get("signers_sha256") == [CERT], "Original official APK verification differs")
        require(read_json(stage.parent / "installation.json") == {k: v for k, v in record.items() if k != "state"}, "Canonical install record differs")
        require_hash(stage, APK_SHA256)
        require([a["argv"] for a in actions] == trace_argv[:offset + 2] + props + trace_argv[offset + 2:] + argv[-3:], "Install isolation checks not immediately before action")
    elif command == "push":
        require(argv == [["push", str(root / "bundle-stage/collection.mpp"), remote], remote_argv], "Invalid push sequence")
    elif command == "launch":
        require(1 <= len(argv) - 1 <= 2 and argv[-1] == ["shell", "am", "start", "-W", "-n", result["component"]], "Invalid launch action")
        canonical.component(result["component"], APP)
        for i, action in enumerate(argv[:-1]):
            require(action == ["shell", "cmd", "package", "resolve-activity", "--brief", "-a", "android.intent.action.MAIN", "-c",
                               "android.intent.category." + ("LAUNCHER" if i == 0 else "LEANBACK_LAUNCHER"), APP], "Invalid launcher resolution")
    elif command == "capture":
        remote_xml = "/data/local/tmp/morphe_" + device["owner"] + ".xml"
        require(argv == [["shell", "uiautomator", "dump", remote_xml], ["exec-out", "cat", remote_xml],
                         ["shell", "rm", "-f", remote_xml], ["exec-out", "screencap", "-p"]], "Missing original capture actions")
        exact(result["captures"], ("dump", "screenshot"), "capture pair")
        previous = None
        for key in ("dump", "screenshot"):
            exact(result["captures"][key], ("started_at", "ended_at", "duration_ns", "result"), "capture interval")
            bounds = interval(result["captures"][key], current, interval(row, current))
            require(previous is None or previous <= bounds[0], "Overlapping capture intervals")
            previous = bounds[1]
        dump_window = interval(result["captures"]["dump"], current)
        screen_window = interval(result["captures"]["screenshot"], current)
        for action in actions[:3]:
            interval(action, current, dump_window)
        interval(actions[3], current, screen_window)
    elif command in ("picker-key", "picker-tap", "navigate-key"):
        activation = command != "navigate-key"
        require(len(argv) == (2 if activation else 1) and (not activation or argv[0] == remote_argv), "Missing activation remote readback")
        action = argv[-1]
        require(action[:2] == ["shell", "input"], "Unexpected input action")
        if command == "picker-tap":
            require(len(action) == 5 and action[2] == "tap" and all(re.fullmatch(r"0|[1-9][0-9]{0,4}", n) and int(n) <= 32767 for n in action[3:]), "Unsupported tap")
        else:
            require(len(action) == 4 and action[2] == "keyevent" and action[3] in
                    ({"23", "66", "160"} if activation else {"4", "19", "20", "21", "22", "61"}), "Unsupported key")
    elif command in ("remote-check", "final-check"):
        require(argv == [remote_argv], "Missing remote readback")
    elif command == "stop":
        require(argv in ([], [["emu", "kill"]]) and result["status"] == "stopped" and result["confirmation"] in
                ("process_exited_and_both_owned_ports_released", "read_only_process_exited_and_both_owned_ports_released"), "Unconfirmed stop")
        for key in ("owner", "avd", "run", "sdk", "avd_home", "data_home", "pid", "serial", "console_port", "server_port"):
            require(result[key] == device[key], "Stop identity differs")
        require(result["transport_port"] == device["console_port"] + 1, "Stop transport differs")
    if command in ("launch", "final-check"):
        require([a["argv"] for a in actions] == trace_argv + argv, "Isolation readback must precede command actions")
    if command in ("push", "remote-check", "final-check"):
        remote_result = result if command == "remote-check" else result["remote"]
        require(remote_result == {"path": remote, "sha256": session["binding"]["bundle_sha256"]}, "Remote result differs")


def validate_graph(root, session, current=None, *, require_shutdown=True, _events=None):
    """Authoritative lifecycle with one terminal final-check, then only stop/report.

    Repeated final-checks and later device observations are unsupported; use a
    fresh lifecycle rather than reinterpret an earlier check as terminal.
    """
    current = current or now()
    if _events is None:
        _, events = capture_events(root, session, current)
    else:
        events = _events
    rows = [read_json(item["event"]["path"], item["event"]["sha256"]) for item in events]
    rows.sort(key=lambda row: row["started_at"])
    previous = None
    required = ("init", "create", "start", "isolate", "install", "push", "launch")
    seen, identity, captures, stops, final_check = {}, None, [], [], None
    for row in rows:
        bounds = interval(row, current)
        require(previous is None or previous <= bounds[0], "Lifecycle events overlap")
        previous = bounds[1]
        command = row["command"]
        if command == "report":
            continue
        require(row["ok"], "Lifecycle contains explicit failed operation: " + command)
        require(final_check is None or command == "stop", "Only stop/report may follow terminal final-check")
        if command == "final-check":
            require(captures and not stops, "Terminal final-check must follow all captures/device observations")
            final_check = row
        if command == "stop":
            require(final_check is not None, "Complete collection requires terminal final-check before shutdown")
        if command in required:
            index = required.index(command)
            require(command not in seen and all(p in seen for p in required[:index]) and not captures and not stops,
                    "Missing, duplicate or out-of-order lifecycle predecessor: " + command)
            seen[command] = row
        else:
            require(all(p in seen for p in required), "Missing successful lifecycle predecessors")
            require(not stops or command == "stop", "Device observation after terminal shutdown")
        if command not in ("init", "create"):
            device = row["device"]
            current_identity = {key: device[key] for key in ("owner", "avd", "run", "sdk", "avd_home", "data_home", "pid", "serial", "console_port", "server_port", "image")}
            if identity is None:
                identity = current_identity
            require(current_identity == identity, "Lifecycle changed exact device identity")
        if command == "capture":
            captures.append(row)
        if command == "stop":
            stops.append(row)
    require(all(p in seen for p in required) and captures, "Incomplete lifecycle/capture graph")
    require(final_check is not None, "Complete collection requires terminal final-check")
    require(len(stops) <= 1, "Duplicate successful terminal stop")
    if require_shutdown:
        require(len(stops) == 1, "Complete collection requires confirmed terminal shutdown")
    first, last = captures[0]["result"]["captures"]["dump"], captures[-1]["result"]["captures"]["screenshot"]
    return {"status": "confirmed-terminal-shutdown" if stops else "observed-not-stopped",
            "started_at": seen["init"]["started_at"], "ended_at": (stops[-1] if stops else captures[-1])["ended_at"],
            "capture_started_at": first["started_at"], "capture_ended_at": last["ended_at"], "device": identity,
            "capture_labels": [row["label"] for row in captures]}


def visual_review(path, pin, session, captures, current):
    value = read_json(external(path), pin)
    exact(value, ("schema", "binding", "reviewed_at", "reviewer_claim", "captures", "checks"), "original visual review")
    require(value["schema"] == "manager-original-visual-review-v1" and value["binding"] == session["binding"], "Review binding/schema differs")
    reviewed = instant(value["reviewed_at"], current)
    require(isinstance(value["reviewer_claim"], str) and value["reviewer_claim"].strip(), "Explicit reviewer claim required (not authenticated)")
    require(isinstance(value["captures"], dict) and value["captures"], "Original capture references required")
    for label, ref in value["captures"].items():
        require(label in captures and ref == captures[label], "Unbound or changed original capture review")
        require(instant(ref["ended_at"], current) <= reviewed, "Review predates capture")
    exact(value["checks"], CHECKS, "visual checks")
    required_purpose = {"local_import": "local-import", "collection_identity": "collection-identity",
                        "patch_names": "patch-names", "defaults": "defaults-untouched", "compatibility": "compatibility"}
    for name, row in value["checks"].items():
        exact(row, ("status", "captures", "notes"), "human check")
        require(row["status"] in ("observed", "not-observed", "blocked") and isinstance(row["notes"], str) and row["notes"].strip(), "Explicit bounded human observation required")
        labels = row["captures"]
        require(isinstance(labels, list) and len(set(labels)) == len(labels) and all(label in value["captures"] for label in labels), "Invalid reviewed captures")
        if row["status"] == "observed":
            require(labels, "Observed check needs original PNG/XML review")
            if name in required_purpose:
                require(any(captures[label]["purpose"] == required_purpose[name] for label in labels), "Missing purpose-specific original capture")
    require_hash(path, pin)
    return {"original": file_record(path), "claims": value, "authentication": "not-authenticated-local-human-claims"}


def manager_report(root, session, review_path=None, review_hash=None):
    current = now()
    captures, events = capture_events(root, session, current)
    require(bool(review_path) == bool(review_hash), "Review path/hash must be supplied together")
    review = visual_review(review_path, review_hash, session, captures, current) if review_path else None
    checks = {name: {"status": "pending-original-review", "basis": "no supplied original visual review"} for name in CHECKS}
    if review:
        checks = {name: {**row, "basis": "human-claim-not-tool-measurement"} for name, row in review["claims"]["checks"].items()}
    try:
        graph = validate_graph(root, session, current, _events=events)
    except Failure as exc:
        graph = {"status": "incomplete", "error": str(exc)}
    return {"schema": REPORT_SCHEMA, "binding": session["binding"], "assembled_at": stamp(current),
            "lifecycle": graph,
            "status": "originals-collected-not-release-approval" if graph["status"] == "confirmed-terminal-shutdown" and review and all(row["status"] == "observed" for row in checks.values()) else "pending-original-visual-review",
            "complete_evidence": False, "manager": {"version": "2.5.0", "apk_sha256": APK_SHA256, "certificate_sha256": CERT, "origin": ORIGIN},
            "tool_measurements": {"session": file_record(root / "session.json"),
                                  "device_owner": file_record(root / "device-owner.json") if (root / "device-owner.json").exists() else None,
                                  "events": events, "captures": captures}, "human_claims": {"checks": checks, "review": review},
            "unsupported": {"feature_behavior": "not-observed; no app patching/runtime in this helper", "hosted_integration": "not-observed", "installed_apk_bytes": "not-read-back"},
            "trust": "Local original byte bindings and measured times, not authentication. Pending capture records are never rewritten. Not schema2 staging evidence."}


def recheck_report(path, expected_sha256, *, current=None, _seen=None, _snapshot=False):
    """Read-only original snapshot validation; never regenerate reports or times.

    The public API permits only newer report-only events. Historical snapshots
    encountered inside those events are checked against their original subsets.
    This is byte/structure validation, not execution or reviewer authentication.
    """
    current = current or now()
    path = external(path)
    value = read_json(path, expected_sha256)
    seen = {} if _seen is None else _seen
    key = (str(path), expected_sha256)
    if key in seen:
        require(seen[key] is not None, "Cyclic report reference")
        return seen[key]
    require(len(seen) < 64, "Report snapshot validation bound exceeded")
    seen[key] = None
    exact(value, ("schema", "binding", "assembled_at", "lifecycle", "status", "complete_evidence", "manager",
                  "tool_measurements", "human_claims", "unsupported", "trust"), "original report")
    require(value["schema"] == REPORT_SCHEMA and value["complete_evidence"] is False, "Unsupported original report")
    assembled = instant(value["assembled_at"], current)
    measurements = value["tool_measurements"]
    exact(measurements, ("session", "device_owner", "events", "captures"), "report measurements")
    for name in ("session", "device_owner"):
        ref = measurements[name]
        if ref is not None:
            file_ref(ref)
            require(file_record(ref["path"]) == ref, "Original report anchor changed")
    session = read_json(measurements["session"]["path"], measurements["session"]["sha256"])
    exact(session, ("schema", "root", "config_path", "config_sha256", "binding", "tools"), "original report session")
    root = external(session["root"])
    require(session["schema"] == "manager-capture-session-v1" and value["binding"] == session["binding"]
            and measurements["session"]["path"] == str(root / "session.json")
            and path.parent.parent == root / "evidence" and path.name == "manager-report.json", "Original report path/session differs")
    if measurements["device_owner"] is not None:
        require(measurements["device_owner"]["path"] == str(root / "device-owner.json"), "Wrong report device anchor")
    captures, events = capture_events(root, session, current, references=measurements["events"], seen=seen)
    require(captures == measurements["captures"] and all(instant(e["ended_at"], current) <= assembled for e in events),
            "Original report observation subset differs")
    try:
        graph = validate_graph(root, session, current, _events=events)
    except Failure as exc:
        graph = {"status": "incomplete", "error": str(exc)}
    require(value["lifecycle"] == graph, "Original report lifecycle differs")
    exact(value["human_claims"], ("checks", "review"), "report human claims")
    review = value["human_claims"]["review"]
    checks = {name: {"status": "pending-original-review", "basis": "no supplied original visual review"} for name in CHECKS}
    if review is not None:
        exact(review, ("original", "claims", "authentication"), "report review")
        file_ref(review["original"])
        require(file_record(review["original"]["path"]) == review["original"], "Original referenced review changed")
        original = visual_review(review["original"]["path"], review["original"]["sha256"], session, captures, current)
        require(original == review and instant(review["claims"]["reviewed_at"], current) <= assembled, "Original review snapshot differs")
        checks = {name: {**row, "basis": "human-claim-not-tool-measurement"} for name, row in review["claims"]["checks"].items()}
    require(value["human_claims"]["checks"] == checks, "Report claims changed")
    collected = graph["status"] == "confirmed-terminal-shutdown" and review and all(row["status"] == "observed" for row in checks.values())
    require(value["status"] == ("originals-collected-not-release-approval" if collected else "pending-original-visual-review"), "Report status overclaims originals")
    require(value["manager"] == {"version": "2.5.0", "apk_sha256": APK_SHA256, "certificate_sha256": CERT, "origin": ORIGIN}, "Report Manager identity differs")
    require(value["unsupported"] == {"feature_behavior": "not-observed; no app patching/runtime in this helper", "hosted_integration": "not-observed", "installed_apk_bytes": "not-read-back"}
            and value["trust"] == "Local original byte bindings and measured times, not authentication. Pending capture records are never rewritten. Not schema2 staging evidence.", "Unsupported report trust claims")
    # The original subset is now fully checked. A later report may legitimately
    # reference this snapshot; cache it before traversing those newer reports.
    seen[key] = value
    if not _snapshot:
        referenced = {item["event"]["path"] for item in events}
        folders = list((root / "evidence").iterdir())
        require(len(folders) <= 256, "Report event count bound exceeded")
        for folder in folders:
            absolute(folder)
            require(folder.is_dir() and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", folder.name), "Unexpected newer evidence entry")
            candidates = [p for p in folder.iterdir() if p.name in ("result.json", "failure.json")]
            require(len(candidates) == 1, "Incomplete or ambiguous newer event")
            event_path = candidates[0]
            if str(event_path) in referenced:
                continue
            row = read_json(event_path)
            validate_event(row, root, session, current)
            own_snapshot = row["command"] == "report" and row["ok"] and row["result"]["manager_report"]["path"] == str(path)
            require(row["ok"] and row["command"] == "report" and
                    (instant(row["started_at"], current) >= assembled or own_snapshot and interval(row, current)[0] <= assembled <= interval(row, current)[1]),
                    "Original report superseded by device/lifecycle observation")
            ref = row["result"]["manager_report"]
            require(ref == file_record(folder / "manager-report.json"), "Newer original report changed")
            if not own_snapshot:
                recheck_report(ref["path"], ref["sha256"], current=current, _seen=seen, _snapshot=True)
    require_hash(path, expected_sha256)
    seen[key] = value
    return value


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root", required=True, help="NEW external root at init; same owned root thereafter")
    p.add_argument("--config", required=True)
    p.add_argument("--expect-config-sha256", required=True)
    p.add_argument("--label", required=True, help="Never-reused evidence label")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("init", "create", "start", "isolate", "install", "push", "launch", "remote-check", "final-check", "stop"):
        sub.add_parser(name)
    sub.add_parser("capture").add_argument("--purpose", choices=PURPOSES, required=True)
    tap = sub.add_parser("picker-tap")
    tap.add_argument("x", type=int)
    tap.add_argument("y", type=int)
    for name in ("picker-key", "navigate-key"):
        sub.add_parser(name).add_argument("code", type=int)
    report = sub.add_parser("report")
    report.add_argument("--review")
    report.add_argument("--expect-review-sha256")
    return p


def label_directory(root, label):
    require(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label) is not None, "Invalid evidence label")
    path = root / "evidence" / label
    path.mkdir(mode=0o700, exist_ok=False)
    return path


def main(argv=None):
    args = parser().parse_args(argv)
    event, emu, session = None, None, None
    start, tick = now(), time.monotonic_ns()
    before, after = None, None
    postcheck_errors, postchecked = [], False

    def postcheck():
        nonlocal after, postchecked
        postchecked = True
        try:
            after = tool_closure(config) if args.command == "stop" else closure(config)
        except Exception as exc:
            postcheck_errors.append({"check": "closure", "error_type": type(exc).__name__, "error": str(exc)})
        if args.command != "stop":
            try:
                require_hash(config_path, pin)
            except Exception as exc:
                postcheck_errors.append({"check": "config", "error_type": type(exc).__name__, "error": str(exc)})
        if before is not None and after is not None and before != after:
            postcheck_errors.append({"check": "closure-equality", "error_type": "Failure", "error": "Closure changed across operation"})

    def operate(call):
        # Independent finally checks; never repeat an action or replace its error.
        try:
            return call()
        finally:
            postcheck()

    def finish(result):
        require(not postcheck_errors, "Post-operation checks failed")
        if args.command != "stop":
            require_hash(config_path, pin)
        row = {"schema": SCHEMA, "root": str(root), "label": args.label, "binding": session["binding"],
               "started_at": stamp(start), "ended_at": stamp(now()), "duration_ns": time.monotonic_ns() - tick,
               "ok": True, "command": args.command, "result": result,
               "closure_before": before, "closure_after": after, "postcheck_errors": postcheck_errors,
               "closure_exemption": "owned-shutdown-only-input-loss" if args.command == "stop" else None,
               "device": device_snapshot(emu) if emu and emu.state else None,
               "actions": emu.actions if emu else [], "isolation_trace": emu.helper_trace if emu else []}
        interval(row, now())
        write_new(event / "result.json", row)
        print(json.dumps({"ok": True, "event": file_record(event / "result.json")}))
        return 0

    try:
        root = external(args.root)
        config_path, pin = external(args.config), expected_hash(args.expect_config_sha256)
        if args.command == "init":
            config = read_config(config_path, pin)
            # No source/input/tool ancestors may become the disposable run root.
            for item in [config_path.parent, *[Path(config[k]["path"]).parent for k in ("request", "bundle", "catalog", "manager_apk")],
                         *[Path(row["path"]) for row in config["tools"].values()]]:
                disjoint(root, item)
            before = closure(config)
            root.mkdir(mode=0o700, exist_ok=False)
            (root / "evidence").mkdir(mode=0o700)
            event = label_directory(root, args.label)
            session = {"schema": "manager-capture-session-v1", "root": str(root), "config_path": str(config_path),
                       "config_sha256": pin, "binding": binding(config), "tools": config["tools"]}
            write_new(root / "session.json", session)
            result = operate(lambda: {"bundle_mapping": stage_bundle(root, config)})
            return finish(result)
        else:
            session, config = checked_session(root, config_path, pin, stopping=args.command == "stop")
            # Serialize the entire session, including create and offline reporting.
            with canonical.locked(root):
                # The event describes the serialized operation, not time queued
                # behind an earlier event. Pre-lock failures retain invocation time.
                start, tick = now(), time.monotonic_ns()
                session, config = checked_session(root, config_path, pin, stopping=args.command == "stop")
                before = tool_closure(config) if args.command == "stop" else closure(config)
                if args.command == "report":
                    # Assemble before reserving this event so it cannot read itself.
                    try:
                        result = operate(lambda: manager_report(root, session, args.review, args.expect_review_sha256))
                    except Exception as primary:
                        try:
                            event = label_directory(root, args.label)
                        except Exception as evidence_error:
                            primary.add_note("Failure event allocation also failed: " + type(evidence_error).__name__)
                        raise
                    event = label_directory(root, args.label)
                    write_new(event / "manager-report.json", result)
                else:
                    emu = ManagerEmulator(config, root / "device-run")
                    if args.command == "create":
                        event = label_directory(root, args.label)
                        once(root, "create")
                        def create_owned():
                            result = emu.create(config["image"])
                            write_new(root / "device-owner.json", owner_binding(emu))
                            return result
                        result = operate(create_owned)
                    else:
                        emu.load()
                        with canonical.locked(emu.run):
                            emu.load()
                            require_owner_binding(root, emu)
                            event = label_directory(root, args.label)
                            result = operate(lambda: dispatch(args, root, config, emu))
                if args.command == "report":
                    result = {"manager_report": file_record(event / "manager-report.json")}
                # Finalize under the session lock; another report must never see
                # an in-flight event and treat its missing result as success.
                return finish(result)
    except Exception as exc:
        if not postchecked and "config" in locals():
            postcheck()
        row = {"schema": SCHEMA, "root": str(root) if "root" in locals() else args.root, "label": args.label,
               "binding": session["binding"] if session else None,
               "started_at": stamp(start), "ended_at": stamp(now()), "duration_ns": time.monotonic_ns() - tick,
               "ok": False, "command": args.command, "error_type": type(exc).__name__, "error": str(exc),
               "closure_before": before, "closure_after": after, "postcheck_errors": postcheck_errors,
               "closure_exemption": "owned-shutdown-only-input-loss" if args.command == "stop" else None,
               "device": device_snapshot(emu) if emu and emu.state else None,
               "actions": emu.actions if emu else [], "isolation_trace": emu.helper_trace if emu else []}
        if event is not None:
            try:
                write_new(event / "failure.json", row)
            except Exception as evidence_error:
                row["evidence_error"] = str(evidence_error)
        print(json.dumps(row), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
