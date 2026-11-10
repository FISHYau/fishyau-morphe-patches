"""Disposable Android emulator CLI; no downloads, shared devices, or shared ADB server.

Run with ``py -I emulator.py --sdk SDK --run NEW_OR_OWNED_DIR COMMAND``.
An installed system image is required. Install performs pinned APK verification;
ABI/density/language completeness remains the caller's responsibility. Ownership
files are local safety guards, not a boundary against local file modification.
"""
import argparse
from contextlib import contextmanager
import errno
import hashlib
import importlib.util
import math
import json
import os
from pathlib import Path
import re
import socket
import shutil
import subprocess
import sys
import time
import uuid


class Failure(Exception):
    pass


def checked(argv, env, timeout=30, binary=False, input_text=None):
    try:
        result = subprocess.run(
            [str(x) for x in argv], env=env, capture_output=True,
            text=not binary, input=input_text, timeout=timeout, shell=False,
            encoding=None if binary else "utf-8", errors=None if binary else "replace",
        )
    except subprocess.TimeoutExpired as exc:
        raise Failure("Command timed out: " + str(argv[0])) from exc
    except OSError as exc:
        raise Failure("Cannot execute %s: %s" % (argv[0], exc)) from exc
    if result.returncode:
        detail = result.stderr or result.stdout
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", errors="replace")
        raise Failure("Command failed (%s): %s" % (result.returncode, detail[-4000:]))
    return result.stdout


def write_file(path, content):
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    created = False
    primary = None
    try:
        with temporary.open("xb") as stream:
            created = True
            stream.write(content if isinstance(content, bytes) else content.encode("utf-8"))
        # Retry only potentially transient Windows replacement denials, using the
        # same closed temporary. Never delete the destination or replay an action.
        for delay in (0.05, 0.1, 0.2, 0.4, None):
            try:
                os.replace(temporary, path)
                break
            except OSError as exc:
                if getattr(exc, "winerror", None) not in (5, 32, 33) or delay is None:
                    raise
                time.sleep(delay)
    except BaseException as exc:
        primary = exc
        raise
    finally:
        if created:
            try:
                temporary.unlink(missing_ok=True)
            except OSError as exc:
                if primary is None:
                    raise
                primary.add_note("Temporary file cleanup also failed: %s" % exc)


def write_json(path, value):
    write_file(path, json.dumps(value, indent=2) + "\n")


@contextmanager
def locked(run):
    path = run / ".command-lock"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise Failure("Run is locked; check for an active command before removing .command-lock") from exc
    try:
        os.close(fd)
        yield
    finally:
        path.unlink(missing_ok=True)


def package(value):
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+", value):
        raise Failure("Invalid package name")
    return value


def component(value, app):
    if not re.fullmatch(re.escape(app) + r"/(?:\.)?[A-Za-z_][A-Za-z0-9_.]*", value):
        raise Failure("Invalid component or component belongs to another package")
    return value


def ports():
    """Reserve console, adjacent transport, and private server until launch setup."""
    for console in range(5554, 5683, 2):
        reservations = []
        try:
            for port in (console, console + 1, 0):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                reservations.append(sock)
                # Exclusive binding on Windows; do not enable SO_REUSEADDR.
                if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                sock.bind(("127.0.0.1", port))
            return console, reservations[-1].getsockname()[1], reservations
        except OSError:
            for sock in reservations:
                sock.close()
    raise Failure("No unused even emulator console port available")


def driver_module():
    # Explicit sibling import works with Python -I; never import from caller cwd.
    spec = importlib.util.spec_from_file_location('_owned_apk_verifier', Path(__file__).with_name('driver.py'))
    if spec is None or spec.loader is None:
        raise Failure('Sibling APK verifier is missing')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def process_exited(pid):
    """Read-only wait probe. PID reuse conservatively blocks; never terminate by PID."""
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        kernel.OpenProcess.restype = wintypes.HANDLE
        kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel.WaitForSingleObject.restype = wintypes.DWORD
        kernel.CloseHandle.argtypes = [wintypes.HANDLE]
        handle = kernel.OpenProcess(0x00100000, False, pid)  # SYNCHRONIZE only
        if not handle:
            return ctypes.get_last_error() == 87  # ERROR_INVALID_PARAMETER: no such PID
        try:
            return kernel.WaitForSingleObject(handle, 0) == 0
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)  # existence probe only, never a termination signal
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    return False


def endpoints_released(console):
    """Both owned endpoint binds must be available; connection errors are not proof."""
    reservations = []
    try:
        for port in (console, console + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            reservations.append(sock)
            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE'):
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            sock.bind(('127.0.0.1', port))
        return True
    except OSError as exc:
        if exc.errno in (errno.EADDRINUSE, errno.EACCES) or getattr(exc, 'winerror', None) in (10048, 10013):
            return False
        raise Failure('Cannot confirm owned endpoint release') from exc
    finally:
        for sock in reservations:
            sock.close()


class Emulator:
    def __init__(self, sdk, run):
        self.sdk = Path(sdk).resolve()
        self.run = Path(run).resolve()
        self.state_path = self.run / "emulator.json"
        self.verifier = driver_module()
        self.state = None
        self.env = os.environ.copy()
        for key in ("ANDROID_SERIAL", "ADB_SERVER_SOCKET", "ANDROID_ADB_SERVER_PORT",
                    "ADB_SERVER_PORT", "ANDROID_SDK_HOME"):
            self.env.pop(key, None)
        self.env.update({
            "ANDROID_HOME": str(self.sdk), "ANDROID_SDK_ROOT": str(self.sdk),
            "ANDROID_USER_HOME": str(self.run / "android-user"),
            "ANDROID_EMULATOR_HOME": str(self.run / "android-user"),
            "ANDROID_AVD_HOME": str(self.run / "avd"),
        })

    def tool(self, name):
        relative = {
            "adb": "platform-tools/adb" + (".exe" if os.name == "nt" else ""),
            "emulator": "emulator/emulator" + (".exe" if os.name == "nt" else ""),
            "avdmanager": "cmdline-tools/latest/bin/avdmanager" + (".bat" if os.name == "nt" else ""),
        }[name]
        path = self.sdk / relative
        if not path.is_file():
            raise Failure("Missing SDK tool: " + str(path))
        return path

    def manager_command(self):
        # Launch the documented Java entry point directly. Killing a timed-out
        # .bat wrapper leaves Java holding capture pipes open indefinitely.
        home = self.env.get('JAVA_HOME')
        java = Path(home) / 'bin' / ('java.exe' if os.name == 'nt' else 'java') if home else None
        found = str(java) if java and java.is_file() else shutil.which('java', path=self.env.get('PATH'))
        classpath = self.sdk / 'cmdline-tools/latest/lib/avdmanager-classpath.jar'
        if not found or not classpath.is_file():
            raise Failure('JDK 21 and avdmanager-classpath.jar are required')
        # Preserve the SDK wrapper's required toolsdir property without running
        # the .bat wrapper (whose descendant lifetime cannot be bounded safely).
        toolsdir = self.sdk / 'cmdline-tools/latest'
        return [str(Path(found).resolve()), '-Dcom.android.sdkmanager.toolsdir=' + str(toolsdir),
                '-classpath', str(classpath), 'com.android.sdklib.tool.AvdManagerCli']

    def save(self):
        write_json(self.state_path, self.state)

    def external_run(self):
        if self.run.is_relative_to(Path(__file__).resolve().parents[3]):
            raise Failure('Run and evidence must stay outside the publication repository')

    def load(self):
        self.external_run()
        try:
            state = json.loads(self.state_path.read_text(encoding="utf-8"))
            token = (self.run / ".owner").read_text(encoding="ascii").strip()
            valid = (
                isinstance(state, dict) and re.fullmatch(r"[0-9a-f]{32}", token)
                and state.get("owner") == token and state.get("version") == 1
                and state.get("run") == str(self.run) and state.get("sdk") == str(self.sdk)
                and state.get("avd") == "morphe_" + token
                and state.get("status") in ("creating", "created", "starting", "running", "stopping", "stopped")
            )
            if not valid:
                raise ValueError("ownership mismatch")
        except (OSError, ValueError, TypeError) as exc:
            raise Failure("Not an owned emulator run: " + str(self.run)) from exc
        self.state = state

    def bind_server(self):
        port = self.state.get("server_port")
        if type(port) is not int or not 1024 <= port <= 65535 or port == 5037:
            raise Failure("Invalid owned ADB server port")
        self.env["ANDROID_ADB_SERVER_PORT"] = str(port)
        self.env["ADB_SERVER_SOCKET"] = "tcp:127.0.0.1:%s" % port
        return port

    def target(self):
        console = self.state.get("console_port")
        if (type(console) is not int or console not in range(5554, 5683, 2)
                or self.state.get("serial") != "emulator-%s" % console
                or self.state.get("status") not in ("starting", "running")
                or type(self.state.get("pid")) is not int or self.state["pid"] <= 0):
            raise Failure("Run has no owned active emulator serial")
        return self.state["serial"]

    def _probe_history(self, records):
        """Bounded private metadata, never raw console output, argv or environment."""
        self.external_run()
        path = self.run / 'ownership-probes.json'
        history = {'version': 1, 'pruned': 0, 'records': []}
        if path.exists():
            with path.open('rb') as stream:
                content = stream.read(65537)
            if len(content) > 65536:
                raise Failure('Ownership probe history exceeds byte limit')
            history = json.loads(content)
            fields = set(records[0])
            if (not isinstance(history, dict) or set(history) != {'version', 'pruned', 'records'}
                    or history['version'] != 1 or type(history['pruned']) is not int
                    or history['pruned'] < 0 or not isinstance(history['records'], list)
                    or len(history['records']) > 32):
                raise Failure('Invalid ownership probe history')
            for record in history['records']:
                if (not isinstance(record, dict) or set(record) != fields
                        or type(record['attempt']) is not int or record['attempt'] not in (1, 2, 3)
                        or record['outcome'] not in ('incomplete', 'deadline', 'timeout', 'exception',
                                                     'nonzero', 'stderr', 'empty', 'greeting', 'not_owned', 'owned')
                        or type(record['elapsed_seconds']) not in (int, float)
                        or not math.isfinite(record['elapsed_seconds']) or record['elapsed_seconds'] < 0
                        or any(type(record[key + '_bytes']) is not int or record[key + '_bytes'] < 0
                               or not isinstance(record[key + '_sha256'], str)
                               or not re.fullmatch(r'[0-9a-f]{64}', record[key + '_sha256'])
                               for key in ('stdout', 'stderr'))):
                    raise Failure('Invalid ownership probe history record')
        combined = history['records'] + records
        history['pruned'] += max(0, len(combined) - 32)
        history['records'] = combined[-32:]
        write_json(path, history)  # Existing atomic private-run writer; no append.

    def _owned_name(self, prefix, timeout):
        # This local deadline covers name probes/sleeps/evidence only, not the
        # action or the outer boot/record_abi/stop operations' overall deadlines.
        started = time.monotonic()
        deadline = started + min(5, timeout)
        records, lines = [], None

        def remaining():
            budget = deadline - time.monotonic()
            if budget <= 0:
                raise Failure('Ownership name probe deadline expired')
            return budget

        def metadata(attempt, outcome, stdout=None, stderr=None):
            record = {'attempt': attempt, 'outcome': outcome,
                      'elapsed_seconds': time.monotonic() - started}
            for key, value in (('stdout', stdout), ('stderr', stderr)):
                # Text-mode UTF-8 capture matches the existing name normalization;
                # byte metadata is over that capture (partial timeout output may be bytes).
                data = value.encode('utf-8') if isinstance(value, str) else (value or b'')
                record[key + '_bytes'] = len(data)
                record[key + '_sha256'] = hashlib.sha256(data).hexdigest()
            return record

        try:
            for attempt in range(1, 4):
                budget = remaining()  # No positive floor on expired budgets.
                if attempt > 1:
                    time.sleep(min(0.1, budget))
                    budget = remaining()
                record = metadata(attempt, 'incomplete')
                records.append(record)
                try:
                    result = subprocess.run(
                        [str(x) for x in prefix] + ['emu', 'avd', 'name'],
                        env=self.env, capture_output=True, text=True, timeout=remaining(),
                        shell=False, encoding='utf-8', errors='replace',
                    )
                except subprocess.TimeoutExpired as exc:
                    record.update(metadata(attempt, 'timeout', exc.stdout, exc.stderr))
                    raise Failure('Ownership name probe timed out') from exc
                except Exception:
                    record.update(metadata(attempt, 'exception'))
                    raise
                record.update(metadata(attempt, 'deadline', result.stdout, result.stderr))
                remaining()  # Even an exact result received too late cannot authorize action.
                if result.returncode:
                    record['outcome'] = 'nonzero'
                    raise Failure('Ownership name probe failed (nonzero exit)')
                if result.stderr != '':
                    record['outcome'] = 'stderr'
                    raise Failure('Ownership name probe returned stderr')
                empty = all(char in ' \t\n\r\v\f' for char in result.stdout)
                # Exact greeting-only capture from runtime-02 (53 UTF-8 bytes;
                # SHA256 ca2994852935b23c28146183f3c5c2422f318e83e63b0f2e0ae01d5004edd1e5).
                # It carries NO name: retry only the read-only probe, never authorize
                # an action from a greeting or strip it from a combined payload.
                greeting = result.stdout == "Android Console: type 'help' for a list of commands\n\n"
                if empty or greeting:
                    record['outcome'] = 'empty' if empty else 'greeting'
                    if attempt < 3:
                        continue
                    raise Failure('Ownership name probe incomplete after three attempts')
                lines = [line.strip() for line in result.stdout.splitlines()
                         if line.strip() and line.strip() != 'OK']
                if lines != [self.state['avd']]:
                    record['outcome'] = 'not_owned'
                    raise Failure('Refusing ADB action: emulator AVD name is not owned')
                record['outcome'] = 'owned'
                break
        except Exception:
            # Preserve the primary probe failure even if diagnostics cannot be saved.
            if records:
                try:
                    self._probe_history(records)
                    remaining()  # Check diagnostic time, but never mask the primary failure.
                except Exception:
                    pass
            raise
        if len(records) > 1:
            # On eventual success, evidence failure is fail-closed BEFORE the guard/action.
            self._probe_history(records)
        remaining()  # Includes all pre-action evidence work; first success writes nothing.
        if lines != [self.state['avd']]:
            raise Failure('Refusing ADB action: emulator AVD name is not owned')

    def adb(self, args, timeout=30, binary=False, before_action=None):
        serial = self.target()
        prefix = [self.tool("adb"), "-P", str(self.bind_server()), "-s", serial]
        action = prefix + list(args)
        self._owned_name(prefix, timeout)
        if before_action is not None:
            before_action()  # Final byte guard AFTER ownership/evidence, immediately before ADB.
        return checked(action, self.env, timeout=timeout, binary=binary)

    def create(self, image):
        self.external_run()
        if not re.fullmatch(r"system-images;android-[0-9]+(?:-ext[0-9]+)?;[A-Za-z0-9_.-]+;[A-Za-z0-9_.-]+", image):
            raise Failure("Specify an explicit installed system-images;android-N;tag;abi package")
        manager = self.manager_command()
        # Reject missing images up front; avdmanager must not be used to provision SDKs.
        image_dir = self.sdk.joinpath(*image.split(";"))
        if not any((image_dir / name).is_file() for name in ("package.xml", "source.properties")):
            raise Failure("System image is not installed; no downloads or license acceptance are performed")
        try:
            self.run.mkdir(parents=True, exist_ok=False)
        except FileExistsError as exc:
            raise Failure("create requires a NEW run directory") from exc
        with locked(self.run):
            token = uuid.uuid4().hex
            write_file(self.run / ".owner", token)
            for folder in ("android-user", "avd"):
                (self.run / folder).mkdir()
            self.state = {"version": 1, "owner": token, "run": str(self.run),
                          "sdk": str(self.sdk), "avd": "morphe_" + token,
                          "image": image, "status": "creating", "installs": []}
            self.save()
            output = checked(manager + ["create", "avd", "--name", self.state["avd"],
                              "--package", image], self.env, timeout=120, input_text="no\n")
            write_file(self.run / "create.txt", output)
            self.state["status"] = "created"
            self.save()
        return {"state": str(self.state_path), "avd": self.state["avd"]}

    def start(self, timeout, gpu):
        if self.state["status"] not in ("created", "stopped"):
            raise Failure("start requires a created or successfully stopped owned run")
        emulator = self.tool("emulator")
        adb = self.tool("adb")
        console, server, reservations = ports()
        try:
            self.state.update(console_port=console, server_port=server,
                              serial="emulator-%s" % console, status="starting")
            self.bind_server()
            # Release only the server reservation to start our private ADB server.
            reservations.pop().close()
            checked([adb, "-P", str(server), "start-server"], self.env)
            for sock in reservations:
                sock.close()
            flags = {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS} if os.name == "nt" else {"start_new_session": True}
            log = self.run / ("emulator-" + uuid.uuid4().hex + ".log")
            with log.open("xb") as stream:
                process = subprocess.Popen(
                    [str(emulator), "-avd", self.state["avd"], "-port", str(console),
                     "-no-window", "-no-audio", "-no-snapshot", "-gpu", gpu],
                    env=self.env, stdin=subprocess.DEVNULL, stdout=stream,
                    stderr=subprocess.STDOUT, shell=False, **flags,
                )
            self.state.update(pid=process.pid, emulator_log=str(log))
            self.save()  # Retain identity even if boot fails; stop can safely retry cleanup.
        finally:
            for sock in reservations:
                sock.close()
        deadline = time.monotonic() + timeout
        last_error = "boot incomplete"
        while time.monotonic() < deadline:
            if process.poll() is not None:
                # This exact owned Popen has exited; no PID guessing or ADB action.
                self.state['status'] = 'stopped'
                self.save()
                raise Failure("Emulator exited before boot; see " + str(log))
            try:
                budget = max(0.01, min(5, (deadline - time.monotonic()) / 3))
                if self.adb(["shell", "getprop", "sys.boot_completed"], timeout=budget).strip() == "1":
                    self.state["status"] = "running"
                    self.record_abi(timeout=max(0.01, min(5, (deadline - time.monotonic()) / 4)))
                    self.save()
                    return {"state": str(self.state_path), "serial": self.state["serial"], "log": str(log)}
            except Failure as exc:
                last_error = str(exc)
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(1, remaining))
        raise Failure("Boot timed out (%s); owned identity retained in %s; use stop to clean up" % (last_error, self.state_path))

    def record_abi(self, timeout=30):
        self.state["abi"] = {
            prop: self.adb(["shell", "getprop", prop], timeout=timeout).strip()
            for prop in ('ro.build.version.sdk', 'ro.product.cpu.abi',
                         'ro.product.cpu.abilist', 'ro.product.cpu.abilist32',
                         'ro.product.cpu.abilist64', 'ro.dalvik.vm.native.bridge',
                         'ro.enable.native.bridge.exec', 'ro.enable.native.bridge.exec64',
                         'ro.dalvik.vm.isa.arm', 'ro.dalvik.vm.isa.arm64')
        }

    def _install_capabilities(self, verified):
        live = self.state['abi']
        sdk = live['ro.build.version.sdk']
        if not re.fullmatch(r'[1-9][0-9]{0,2}', sdk):
            raise Failure('Invalid live SDK capability evidence')
        # Some valid API24+ images advertise legacy armeabi alongside v7a.
        # Record that live capability without adding it to verifier target ABIs.
        known32, known64 = {'armeabi', 'armeabi-v7a', 'x86'}, {'arm64-v8a', 'x86_64', 'riscv64'}
        def abi_list(prop, allowed, empty=False):
            value = live[prop]
            items = value.split(',') if value else []
            if ((not items and not empty) or len(set(items)) != len(items)
                    or any(item not in allowed for item in items)):
                raise Failure('Invalid live ABI capability evidence')
            return set(items)
        all_abis = abi_list('ro.product.cpu.abilist', known32 | known64)
        list32 = abi_list('ro.product.cpu.abilist32', known32, empty=True)
        list64 = abi_list('ro.product.cpu.abilist64', known64, empty=True)
        if (list32 | list64 != all_abis or live['ro.product.cpu.abi'] not in all_abis):
            raise Failure('Inconsistent live primary/32/64 ABI evidence')
        selected = verified['selection']['abi']
        if selected != 'none' and selected not in all_abis:
            raise Failure('Declared APK ABI is not supported by the owned emulator')
        if int(sdk) < verified['topology']['min_sdk']:
            raise Failure('APK minSDK exceeds live owned emulator SDK')
        return {'sdk': int(sdk), 'selected_abi': selected,
                'primary_abi': live['ro.product.cpu.abi'], 'properties': dict(live),
                'translation_or_jni_execution': 'not_proven'}

    def install(self, paths, verification=None):
        apks = [Path(value).resolve() for value in paths]
        if (not apks or len(apks) > 256 or len(set(apks)) != len(apks)
                or any(not path.is_file() or path.suffix.lower() != '.apk' for path in apks)
                or any(a.samefile(b) for i, a in enumerate(apks) for b in apks[i + 1:])):
            raise Failure('Supply explicit existing APK files, without duplicates')
        if verification is None:
            raise Failure('Pinned APK verification options are required before installation')
        self.target()
        self.bind_server()
        self.external_run()
        stage = self.run / ('install-stage-' + uuid.uuid4().hex)
        stage.mkdir(exist_ok=False)
        mapping, staged = [], []
        total = 0
        for index, source in enumerate(apks):
            if source.stat().st_size > self.verifier.MAX_ARCHIVE_BYTES:
                raise Failure('APK staging byte limit exceeded')
            before = self.verifier._hash_file(source)
            target = stage / ('member-' + str(index) + '.apk')
            with source.open('rb') as src, target.open('xb') as dst:
                while True:
                    block = src.read(self.verifier.CHUNK)
                    if not block:
                        break
                    total += len(block)
                    if total > self.verifier.MAX_BYTES:
                        raise Failure('APK staging aggregate byte limit exceeded')
                    dst.write(block)
            if before != self.verifier._hash_file(source) or before != self.verifier._hash_file(target):
                raise Failure('APK bytes changed during staging')
            mapping.append({'original': str(source), 'staged': str(target), 'sha256': before})
            staged.append(target)
        evidence = stage / 'verification.json'
        try:
            verified = self.verifier.verify_apks(staged, out=evidence, **verification)
        except self.verifier.DriverError as exc:
            raise Failure('APK pre-install verification failed: ' + str(exc)) from exc
        if ([r['path'] for r in verified['apks']] != [str(p) for p in staged]
                or [r['sha256'] for r in verified['apks']] != [m['sha256'] for m in mapping]):
            raise Failure('Verified APK bytes changed or staged set binding differs')

        def byte_guard():
            for member in mapping:
                for key in ('original', 'staged'):
                    if self.verifier._hash_file(Path(member[key])) != member['sha256']:
                        raise Failure('APK bytes changed after verification; refusing installation')

        byte_guard()
        # Every property read and install still uses the ownership-checked private ADB.
        self.record_abi()
        capabilities = self._install_capabilities(verified)
        output = self.adb(['install' if len(staged) == 1 else 'install-multiple'] + list(map(str, staged)),
                          timeout=180, before_action=byte_guard)
        byte_guard()
        if not re.search(r'(?m)^Success\s*$', output):
            raise Failure('ADB did not confirm installation success')
        log = stage / 'install.txt'
        write_file(log, output)
        app = package(verified['expected']['package'])
        installed = self.adb(['shell', 'pm', 'path', app])
        installed_paths = [line[8:] for line in installed.splitlines() if line.startswith('package:')]
        if (len(installed_paths) != len(staged) or len(set(installed_paths)) != len(installed_paths)
                or any(not p.startswith('/') or not p.endswith('.apk') or any(ord(c) < 32 for c in p)
                       for p in installed_paths)):
            raise Failure('Installed base/split path evidence is missing or ambiguous')
        # Package-manager output is evidence, not proof of runtime/JNI success.
        package_dump = self.adb(['shell', 'dumpsys', 'package', app])
        abi_evidence = [line.strip() for line in package_dump.splitlines()
                        if re.match(r'\s*(primaryCpuAbi|secondaryCpuAbi|nativeLibraryDir)=', line)]
        write_file(stage / 'package-paths.txt', installed)
        write_file(stage / 'package-abi.txt', '\n'.join(abi_evidence))
        byte_guard()
        record = {'apks': list(map(str, apks)), 'staged_apks': list(map(str, staged)),
                  'mapping': mapping, 'stdout': str(log), 'abi': self.state['abi'],
                  'capabilities': capabilities, 'verification': str(evidence),
                  'installed_paths': installed_paths, 'installed_abi_evidence': abi_evidence,
                  'limit': 'Staging/hash guards reduce pathname races; not a same-user mutation boundary. '
                           'Install acceptance does not prove JNI loading or translated execution.'}
        write_json(stage / 'installation.json', record)
        self.state['installs'].append(record)
        self.save()
        return {'state': str(self.state_path), **record}

    def launch(self, app, explicit):
        app = package(app)
        chosen = component(explicit, app) if explicit else None
        if chosen is None:
            for category in ("LAUNCHER", "LEANBACK_LAUNCHER"):
                output = self.adb(["shell", "cmd", "package", "resolve-activity", "--brief",
                                   "-a", "android.intent.action.MAIN", "-c",
                                   "android.intent.category." + category, app])
                for line in output.splitlines():
                    if line.strip().startswith(app + "/"):
                        chosen = component(line.strip(), app)
                        break
                if chosen:
                    break
        if not chosen:
            raise Failure("No normal or leanback launcher resolved; provide --component")
        output = self.adb(["shell", "am", "start", "-W", "-n", chosen], timeout=60)
        write_file(self.run / "launch.txt", output)
        if re.search(r"(?im)^\s*(Error(?:\s|:)|Exception|Status:\s*(?!ok\b)\S+)", output):
            raise Failure("Activity launch failed; see " + str(self.run / "launch.txt"))
        return {"component": chosen, "stdout": str(self.run / "launch.txt")}

    def capture(self, command, lines=200, label=None):
        if label is not None and not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", label):
            raise Failure("Invalid evidence label")
        suffix = "-" + label if label else ""
        if command == "screenshot":
            content = self.adb(["exec-out", "screencap", "-p"], binary=True)
            if not content.startswith(b"\x89PNG\r\n\x1a\n"):
                raise Failure("screencap did not return PNG data")
            path = self.run / ("screenshot" + suffix + ".png")
        elif command == "dump":
            remote = "/data/local/tmp/morphe_" + self.state["owner"] + ".xml"
            try:
                self.adb(["shell", "uiautomator", "dump", remote], timeout=60)
                content = self.adb(["exec-out", "cat", remote], binary=True)
            finally:
                # Re-verify identity even for cleanup; never remove another device's file.
                self.adb(["shell", "rm", "-f", remote])
            path = self.run / ("hierarchy" + suffix + ".xml")
        else:
            content = self.adb(["logcat", "-d", "-t", str(lines)], timeout=30)
            path = self.run / ("logcat" + suffix + ".txt")
        write_file(path, content)
        return {"path": str(path)}

    def stop(self, timeout=30):
        if not 1 <= timeout <= 120:
            raise Failure('Stop timeout must be 1..120 seconds')
        deadline = time.monotonic() + timeout
        if self.state['status'] != 'stopping':
            self.adb(['emu', 'kill'], timeout=min(10, timeout / 4))
            self.state['status'] = 'stopping'
            self.save()  # Acknowledgment is not proof of exit; retries only confirm.
        console, pid = self.state.get('console_port'), self.state.get('pid')
        if (type(console) is not int or console not in range(5554, 5683, 2)
                or self.state.get('serial') != 'emulator-%s' % console
                or type(pid) is not int or pid <= 0):
            raise Failure('Invalid owned stop identity')
        self.bind_server()
        while time.monotonic() < deadline:
            if process_exited(pid) and endpoints_released(console):
                self.state['status'] = 'stopped'
                self.state['stop_confirmation'] = 'process_exited_and_both_owned_ports_released'
                self.save()
                # Private server deliberately left alone. No PID termination fallback.
                return {'state': str(self.state_path), 'serial': self.state['serial'],
                        'status': 'stopped', 'confirmation': self.state['stop_confirmation']}
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(0.25, remaining))
        raise Failure('Owned stop unconfirmed before timeout; identity retained as stopping; no fallback kill performed')


def bounded(low, high):
    def parse(value):
        try:
            number = int(value)
        except ValueError as exc:
            raise argparse.ArgumentTypeError("Expected an integer") from exc
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("Expected %s..%s" % (low, high))
        return number
    return parse


def parser():
    root = argparse.ArgumentParser(description=__doc__)
    root.add_argument("--sdk", required=True)
    root.add_argument("--run", required=True, help="NEW directory for create; owned directory otherwise")
    commands = root.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create")
    create.add_argument("--image", required=True, help="Explicit, already installed system image package")
    start = commands.add_parser("start")
    start.add_argument("--timeout", type=bounded(1, 900), default=180)
    start.add_argument("--gpu", choices=("swiftshader_indirect", "swiftshader", "software"), default="swiftshader_indirect")
    install = commands.add_parser("install")
    install.add_argument('apks', nargs='+', help='Explicit base APK and selected splits; verification always runs before ADB')
    driver_module().verification_arguments(install)
    launch = commands.add_parser("launch")
    launch.add_argument("package")
    launch.add_argument("--component")
    commands.add_parser("dump").add_argument("--label")
    key = commands.add_parser("key")
    key.add_argument("code", type=bounded(0, 288))
    tap = commands.add_parser("tap")
    tap.add_argument("x", type=bounded(0, 32767))
    tap.add_argument("y", type=bounded(0, 32767))
    commands.add_parser("screenshot").add_argument("--label")
    logcat = commands.add_parser("logcat")
    logcat.add_argument("--lines", type=bounded(1, 2000), default=200)
    logcat.add_argument("--label")
    commands.add_parser('stop').add_argument('--timeout', type=bounded(1, 120), default=30)
    return root


def main(argv=None):
    args = parser().parse_args(argv)
    emulator = Emulator(args.sdk, args.run)
    try:
        if args.command == "create":
            report = emulator.create(args.image)
        else:
            emulator.load()
            with locked(emulator.run):
                emulator.load()
                if args.command == "start":
                    report = emulator.start(args.timeout, args.gpu)
                elif args.command == "install":
                    report = emulator.install(args.apks, emulator.verifier.verification_options(args))
                elif args.command == "launch":
                    report = emulator.launch(args.package, args.component)
                elif args.command in ("dump", "screenshot", "logcat"):
                    report = emulator.capture(args.command, getattr(args, "lines", 200), getattr(args, "label", None))
                elif args.command in ("key", "tap"):
                    action = ["keyevent", str(args.code)] if args.command == "key" else ["tap", str(args.x), str(args.y)]
                    emulator.adb(["shell", "input"] + action)
                    report = {"serial": emulator.state["serial"], "action": action}
                else:
                    report = emulator.stop(args.timeout)
        print(json.dumps({"ok": True, **report}))
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "run": str(emulator.run)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
