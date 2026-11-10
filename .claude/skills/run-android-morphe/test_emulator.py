"""Mock-only tests. Run: py -I -B test_emulator.py (no SDK or device required)."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("disposable_emulator", Path(__file__).with_name("emulator.py"))
emulator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(emulator)


class Clock:
    def __init__(self):
        self.now = 0.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class AtomicWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "emulator.json"

    @staticmethod
    def windows_error(code):
        error = PermissionError(emulator.errno.EACCES, "synthetic Windows denial")
        error.winerror = code
        return error

    def assert_no_temporaries(self):
        self.assertEqual(list(self.root.glob("emulator.json.*.tmp")), [])

    def test_immediate_success_preserves_payload_and_closes_before_replace(self):
        real_open, real_replace = Path.open, os.replace
        for content in (b"\x00\xff\r\n", "UTF-8: ☃\n", b"", ""):
            with self.subTest(content=content):
                streams = []
                expected = content if isinstance(content, bytes) else content.encode("utf-8")

                def opened(path, *args, **kwargs):
                    stream = real_open(path, *args, **kwargs)
                    if args == ("xb",):
                        streams.append(stream)
                    return stream

                def replace(source, destination):
                    self.assertEqual(len(streams), 1)
                    self.assertTrue(streams[0].closed)
                    self.assertEqual(source.parent, destination.parent)
                    self.assertEqual(source.read_bytes(), expected)
                    return real_replace(source, destination)

                with mock.patch.object(Path, "open", new=opened), \
                        mock.patch.object(emulator.os, "replace", side_effect=replace) as replacing, \
                        mock.patch.object(emulator.time, "sleep") as sleep:
                    emulator.write_file(self.path, content)
                replacing.assert_called_once()
                sleep.assert_not_called()
                self.assertEqual(self.path.read_bytes(), expected)
                self.assert_no_temporaries()

    def test_json_format_is_unchanged(self):
        value = {"status": "running", "count": 2}
        emulator.write_json(self.path, value)
        self.assertEqual(self.path.read_bytes(), (json.dumps(value, indent=2) + "\n").encode("utf-8"))
        self.assert_no_temporaries()

    def test_transient_windows_denials_retry_only_same_atomic_replacement(self):
        real_replace = os.replace
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                self.path.write_bytes(b"old state")
                attempts = []

                def replace(source, destination):
                    attempts.append((source, destination))
                    self.assertEqual(self.path.read_bytes(), b"old state")
                    self.assertEqual(source.read_bytes(), b"new state")
                    if len(attempts) <= 2:
                        raise self.windows_error(code)
                    return real_replace(source, destination)

                with mock.patch.object(emulator.os, "replace", side_effect=replace), \
                        mock.patch.object(emulator.time, "sleep") as sleep:
                    emulator.write_file(self.path, b"new state")
                self.assertEqual(len(attempts), 3)
                self.assertTrue(all(pair == attempts[0] for pair in attempts))
                self.assertEqual(sleep.call_args_list, [mock.call(0.05), mock.call(0.1)])
                self.assertEqual(self.path.read_bytes(), b"new state")
                self.assert_no_temporaries()

    def test_final_permitted_attempt_can_succeed(self):
        real_replace = os.replace
        attempts = []

        def replace(source, destination):
            attempts.append((source, destination))
            if len(attempts) < 5:
                raise self.windows_error(5)
            return real_replace(source, destination)

        with mock.patch.object(emulator.os, "replace", side_effect=replace), \
                mock.patch.object(emulator.time, "sleep") as sleep:
            emulator.write_file(self.path, b"state")
        self.assertEqual(len(attempts), 5)
        self.assertEqual(sleep.call_args_list, [mock.call(x) for x in (0.05, 0.1, 0.2, 0.4)])
        self.assertEqual(self.path.read_bytes(), b"state")
        self.assert_no_temporaries()

    def test_persistent_windows_denials_are_bounded_and_preserve_old_state(self):
        for code in (5, 32, 33):
            with self.subTest(winerror=code):
                self.path.write_bytes(b"old state")
                errors = [self.windows_error(code) for _ in range(5)]
                with mock.patch.object(emulator.os, "replace", side_effect=errors) as replacing, \
                        mock.patch.object(emulator.time, "sleep") as sleep:
                    with self.assertRaises(PermissionError) as caught:
                        emulator.write_file(self.path, b"new state")
                self.assertIs(caught.exception, errors[-1])
                self.assertEqual(replacing.call_count, 5)
                self.assertEqual(sleep.call_args_list, [mock.call(x) for x in (0.05, 0.1, 0.2, 0.4)])
                self.assertEqual(self.path.read_bytes(), b"old state")
                self.assert_no_temporaries()

    def test_unrelated_and_non_windows_errors_fail_without_retry(self):
        errors = [PermissionError(emulator.errno.EACCES, "no Windows code"),
                  OSError(emulator.errno.EIO, "I/O error"),
                  *[self.windows_error(code) for code in (2, 3, 87, 112)],
                  RuntimeError("not an OS error")]
        for error in errors:
            with self.subTest(error=repr(error), winerror=getattr(error, "winerror", None)):
                self.path.write_bytes(b"old state")
                with mock.patch.object(emulator.os, "replace", side_effect=error) as replacing, \
                        mock.patch.object(emulator.time, "sleep") as sleep:
                    with self.assertRaises(type(error)) as caught:
                        emulator.write_file(self.path, b"new state")
                self.assertIs(caught.exception, error)
                replacing.assert_called_once()
                sleep.assert_not_called()
                self.assertEqual(self.path.read_bytes(), b"old state")
                self.assert_no_temporaries()

    def test_temporary_creation_failure_is_not_retried(self):
        error = self.windows_error(5)
        with mock.patch.object(Path, "open", side_effect=error) as opening, \
                mock.patch.object(emulator.os, "replace") as replacing, \
                mock.patch.object(emulator.time, "sleep") as sleep:
            with self.assertRaises(PermissionError) as caught:
                emulator.write_file(self.path, b"state")
        self.assertIs(caught.exception, error)
        opening.assert_called_once()
        replacing.assert_not_called()
        sleep.assert_not_called()
        self.assert_no_temporaries()

    def test_exclusive_creation_collision_does_not_remove_existing_temporary(self):
        token = mock.Mock(hex="collision")
        temporary = self.root / "emulator.json.collision.tmp"
        temporary.write_bytes(b"not created by this call")
        with mock.patch.object(emulator.uuid, "uuid4", return_value=token), \
                mock.patch.object(emulator.os, "replace") as replacing, \
                mock.patch.object(emulator.time, "sleep") as sleep:
            with self.assertRaises(FileExistsError):
                emulator.write_file(self.path, b"state")
        self.assertEqual(temporary.read_bytes(), b"not created by this call")
        replacing.assert_not_called()
        sleep.assert_not_called()
        self.assertFalse(self.path.exists())

    def test_temporary_write_failure_is_not_retried_and_is_cleaned_up(self):
        real_open = Path.open
        error = self.windows_error(5)

        @contextlib.contextmanager
        def failed_write(path, mode):
            with real_open(path, mode) as stream:
                writer = mock.Mock(wraps=stream)
                writer.write.side_effect = error
                yield writer

        with mock.patch.object(Path, "open", new=failed_write), \
                mock.patch.object(emulator.os, "replace") as replacing, \
                mock.patch.object(emulator.time, "sleep") as sleep:
            with self.assertRaises(PermissionError) as caught:
                emulator.write_file(self.path, b"state")
        self.assertIs(caught.exception, error)
        replacing.assert_not_called()
        sleep.assert_not_called()
        self.assert_no_temporaries()
        self.assertFalse(self.path.exists())

    def test_cleanup_failure_does_not_mask_primary_replacement_error(self):
        primary = self.windows_error(5)
        cleanup = PermissionError("synthetic cleanup denial")
        with mock.patch.object(emulator.os, "replace", side_effect=primary) as replacing, \
                mock.patch.object(emulator.time, "sleep"), \
                mock.patch.object(Path, "unlink", side_effect=cleanup):
            with self.assertRaises(PermissionError) as caught:
                emulator.write_file(self.path, b"state")
        self.assertIs(caught.exception, primary)
        self.assertEqual(replacing.call_count, 5)
        self.assertTrue(any("Temporary file cleanup also failed" in note
                            for note in primary.__notes__))
        self.assertEqual(len(list(self.root.glob("emulator.json.*.tmp"))), 1)
        self.assertFalse(self.path.exists())

    def test_cleanup_failure_after_success_is_not_suppressed(self):
        cleanup = PermissionError("synthetic cleanup denial")
        with mock.patch.object(Path, "unlink", side_effect=cleanup):
            with self.assertRaises(PermissionError) as caught:
                emulator.write_file(self.path, b"state")
        self.assertIs(caught.exception, cleanup)
        self.assertEqual(self.path.read_bytes(), b"state")
        self.assert_no_temporaries()

    def test_cleanup_failure_is_not_suppressed_by_callers_handled_exception(self):
        ambient = ValueError("handled by caller, not raised by writer")
        cleanup = PermissionError("synthetic cleanup denial")
        try:
            raise ambient
        except ValueError:
            with mock.patch.object(Path, "unlink", side_effect=cleanup):
                with self.assertRaises(PermissionError) as caught:
                    emulator.write_file(self.path, b"state")
        self.assertIs(caught.exception, cleanup)
        self.assertFalse(hasattr(ambient, "__notes__"))
        self.assertEqual(self.path.read_bytes(), b"state")
        self.assert_no_temporaries()


class EmulatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sdk = self.root / "SDK with spaces"
        self.run = self.root / "owned run"
        self.emu = emulator.Emulator(self.sdk, self.run)
        self.image = "system-images;android-35;google_apis;x86_64"
        for name in ("adb", "emulator", "avdmanager"):
            with mock.patch.object(Path, "is_file", return_value=True):
                path = self.emu.tool(name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"")
        image_file = self.sdk.joinpath(*self.image.split(";")) / "package.xml"
        image_file.parent.mkdir(parents=True)
        image_file.write_text("<package/>", encoding="utf-8")
        self.manager_patcher = mock.patch.object(emulator.Emulator, 'manager_command', return_value=['fixture-avdmanager'])
        self.manager_patcher.start()
        self.calls = []
        self.runner = mock.patch.object(emulator.subprocess, "run", side_effect=self.respond).start()
        self.addCleanup(mock.patch.stopall)
        # Any unexpected real launch fails the test instead of running an emulator.
        self.popen = mock.patch.object(emulator.subprocess, "Popen", side_effect=AssertionError("Unexpected launch")).start()
        # Stop confirmation probes are mocked; never inspect a real PID or port.
        self.exited = mock.patch.object(emulator, 'process_exited', return_value=True).start()
        self.released = mock.patch.object(emulator, 'endpoints_released', return_value=True).start()

    def respond(self, args, **kwargs):
        self.calls.append((args, kwargs))
        self.assertFalse(kwargs["shell"])
        self.assertGreater(kwargs["timeout"], 0)
        output = ""
        if args[-3:] == ["emu", "avd", "name"]:
            output = self.emu.state["avd"] + "\nOK\n"
        elif args[-2:] == ["getprop", "sys.boot_completed"]:
            output = "1\n"
        elif "getprop" in args:
            output = {'ro.build.version.sdk': '35', 'ro.product.cpu.abi': 'x86_64',
                      'ro.product.cpu.abilist': 'x86_64,x86', 'ro.product.cpu.abilist32': 'x86',
                      'ro.product.cpu.abilist64': 'x86_64', 'ro.dalvik.vm.native.bridge': '0',
                      'ro.enable.native.bridge.exec': '0', 'ro.enable.native.bridge.exec64': '0',
                      'ro.dalvik.vm.isa.arm': '', 'ro.dalvik.vm.isa.arm64': ''}[args[-1]] + '\n'
        elif args[-4:-1] == ['shell', 'pm', 'path']:
            count = 1
            installs = [call for call, _ in self.calls if 'install-multiple' in call or 'install' in call]
            if installs:
                command = installs[-1]
                index = command.index('install-multiple' if 'install-multiple' in command else 'install')
                count = len(command) - index - 1
            output = 'package:/data/app/owned/base.apk\n' + ''.join(
                f'package:/data/app/owned/config_{i}.apk\n' for i in range(count - 1))
        elif args[-3:-1] == ['dumpsys', 'package']:
            output = '  primaryCpuAbi=x86_64\n  secondaryCpuAbi=null\n  nativeLibraryDir=/data/app/owned/lib/x86_64\n'
        elif "resolve-activity" in args:
            output = "com.example.app/.MainActivity\n"
        elif "screencap" in args:
            output = b"\x89PNG\r\n\x1a\n\x00\xff\r\n"
        elif "cat" in args:
            output = b"<?xml version='1.0'?><hierarchy/>"
        elif "install" in args or "install-multiple" in args:
            output = "Success\n"
        elif "start" in args:
            output = "Status: ok\n"
        if not kwargs["text"] and isinstance(output, str):
            output = output.encode("utf-8")
        return subprocess.CompletedProcess(args, 0, stdout=output, stderr="" if kwargs["text"] else b"")

    def create(self):
        self.emu.create(self.image)
        return self.emu

    def active(self):
        self.create()
        self.emu.state.update(status="running", console_port=5554, server_port=40401,
                              serial="emulator-5554", pid=12345)
        self.emu.save()
        self.calls.clear()
        return self.emu

    def invoke(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = emulator.main(["--sdk", str(self.sdk), "--run", str(self.run), *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def verification_report(self, paths, out, abi='x86_64', min_sdk=24, **kwargs):
        report = {'selection': {'abi': abi}, 'expected': {'package': 'org.example.app'},
                  'topology': {'min_sdk': min_sdk}, 'apks': [
                      {'path': str(p), 'sha256': self.emu.verifier._hash_file(p)} for p in paths]}
        out.write_text(json.dumps(report))
        return report

    def reservations(self):
        socks = [mock.Mock(), mock.Mock(), mock.Mock()]
        patch = mock.patch.object(emulator, "ports", return_value=(5556, 40402, socks))
        patch.start()
        return socks

    def test_create_scopes_homes_and_uses_exact_package_without_force(self):
        with mock.patch.dict(os.environ, {"ANDROID_SERIAL": "real-phone", "ADB_SERVER_SOCKET": "tcp:localhost:5037"}):
            self.emu = emulator.Emulator(self.sdk, self.run)
        self.create()
        args, kwargs = self.calls[0]
        self.assertEqual(args[1:], ["create", "avd", "--name", self.emu.state["avd"], "--package", self.image])
        self.assertEqual(kwargs["input"], "no\n")
        self.assertEqual(kwargs["env"]["ANDROID_AVD_HOME"], str(self.run / "avd"))
        self.assertEqual(kwargs["env"]["ANDROID_USER_HOME"], str(self.run / "android-user"))
        self.assertNotIn("ANDROID_SERIAL", kwargs["env"])
        self.assertNotIn("ADB_SERVER_SOCKET", kwargs["env"])
        self.emu.load()
        self.assertEqual(self.emu.state["status"], "created")
        self.assertFalse((self.run / ".command-lock").exists())

    def test_create_refuses_existing_directory_without_touching_it(self):
        self.run.mkdir()
        with self.assertRaisesRegex(emulator.Failure, "NEW"):
            self.create()
        self.runner.assert_not_called()
        self.assertEqual(list(self.run.iterdir()), [])

    def test_create_refuses_missing_or_unsafe_image(self):
        for image in ("system-images;android-99;google_apis;x86_64", self.image + " & evil", "default"):
            with self.subTest(image=image), self.assertRaises(emulator.Failure):
                self.emu.create(image)
        self.runner.assert_not_called()
        self.assertFalse(self.run.exists())

    def test_failed_creation_cannot_be_started(self):
        self.runner.side_effect = subprocess.TimeoutExpired("avdmanager", 120)
        with self.assertRaisesRegex(emulator.Failure, "timed out"):
            self.create()
        self.assertEqual(self.emu.state["status"], "creating")
        self.assertFalse((self.run / ".command-lock").exists())
        with self.assertRaisesRegex(emulator.Failure, "created"):
            self.emu.start(1, "swiftshader_indirect")
        self.popen.assert_not_called()

    def test_cli_refuses_unowned_run_without_adb(self):
        self.run.mkdir()
        code, _, error = self.invoke("stop")
        self.assertEqual(code, 1)
        self.assertIn("Not an owned", json.loads(error)["error"])
        self.runner.assert_not_called()

    def test_copied_run_and_sdk_mismatch_fail_ownership(self):
        self.create()
        self.emu.state["run"] = str(self.root / "different")
        self.emu.save()
        with self.assertRaisesRegex(emulator.Failure, "owned"):
            self.emu.load()
        self.emu.state["run"] = str(self.run)
        self.emu.state["sdk"] = str(self.root / "other-sdk")
        self.emu.save()
        with self.assertRaisesRegex(emulator.Failure, "owned"):
            self.emu.load()

    def test_refuse_physical_serial_bad_console_pid_and_server_before_adb(self):
        self.active()
        baseline = self.emu.state.copy()
        for field, bad in (("serial", "physical-device"), ("console_port", 5555),
                           ("pid", None), ("server_port", 503.7), ("server_port", 5037),
                           ("status", "stopped")):
            with self.subTest(field=field):
                self.emu.state = {**baseline, field: bad}
                with self.assertRaises(emulator.Failure):
                    self.emu.stop()
        self.assertEqual(self.calls, [])

    def test_refuse_mismatched_avd_before_mutation(self):
        self.active()
        self.runner.return_value = subprocess.CompletedProcess([], 0, "another-avd\nOK\n", "")
        self.runner.side_effect = None
        with self.assertRaisesRegex(emulator.Failure, "not owned"):
            self.emu.stop()
        self.assertEqual(self.runner.call_count, 2)  # create and name check, never kill
        self.assertEqual(self.runner.call_args.args[0][-3:], ["emu", "avd", "name"])
        self.assertEqual(self.emu.state["status"], "running")

    def probe_sequence(self, responses, on_probe=None):
        queued = list(responses)
        def respond(args, **kwargs):
            result = self.respond(args, **kwargs)
            if args[-3:] == ['emu', 'avd', 'name']:
                response = queued.pop(0)
                if on_probe is not None:
                    on_probe(len(responses) - len(queued), kwargs)
                if isinstance(response, Exception):
                    raise response
                if isinstance(response, tuple):
                    result.stdout, result.stderr, result.returncode = response
                else:
                    result.stdout = response
            return result
        self.runner.side_effect = respond
        return queued

    @contextlib.contextmanager
    def clocked(self, clock=None):
        clock = clock or Clock()
        with mock.patch.object(emulator.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(emulator.time, 'sleep', side_effect=clock.sleep) as sleep:
            yield clock, sleep

    def history(self):
        return json.loads((self.run / 'ownership-probes.json').read_text(encoding='utf-8'))

    def test_empty_probe_then_exact_has_one_guard_and_action_with_private_prefix(self):
        self.active()
        queued = self.probe_sequence([' \t\r\n\v\f', self.emu.state['avd'] + '\nOK\n'])
        events = []
        writer = emulator.write_json
        def write(path, value):
            events.append('evidence')
            writer(path, value)
        scripted = self.runner.side_effect
        def observe(args, **kwargs):
            if args[-3:] == ['shell', 'input', 'test-action']:
                events.append('action')
            return scripted(args, **kwargs)
        self.runner.side_effect = observe
        with self.clocked() as (_, sleep), mock.patch.object(emulator, 'write_json', side_effect=write):
            self.emu.adb(['shell', 'input', 'test-action'], before_action=lambda: events.append('guard'))
        self.assertEqual(queued, [])
        self.assertEqual(events, ['evidence', 'guard', 'action'])
        sleep.assert_called_once_with(0.1)
        self.assertEqual(len(self.calls), 3)
        for args, kwargs in self.calls:
            self.assertEqual(args[:5], [str(self.emu.tool('adb')), '-P', '40401', '-s', 'emulator-5554'])
            self.assertEqual(kwargs['env']['ADB_SERVER_SOCKET'], 'tcp:127.0.0.1:40401')
        self.assertEqual([r['outcome'] for r in self.history()['records']], ['empty', 'owned'])

    def test_first_exact_probe_writes_no_evidence(self):
        self.active()
        with self.clocked(), mock.patch.object(emulator, 'write_json') as writer:
            self.emu.adb(['shell', 'true'])
        writer.assert_not_called()
        self.assertFalse((self.run / 'ownership-probes.json').exists())
        self.assertEqual(len(self.calls), 2)

    def test_three_empty_probes_no_fourth_no_guard_or_action(self):
        self.active()
        queued = self.probe_sequence(['', '\t', '\r\n', self.emu.state['avd']])
        guard = mock.Mock()
        with self.clocked() as (_, sleep), self.assertRaisesRegex(emulator.Failure, 'three attempts'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_not_called()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(queued, [self.emu.state['avd']])
        self.assertEqual(sleep.call_args_list, [mock.call(0.1), mock.call(0.1)])
        self.assertEqual([r['attempt'] for r in self.history()['records']], [1, 2, 3])

    def test_empty_then_mismatch_does_not_consume_queued_valid_name(self):
        self.active()
        queued = self.probe_sequence(['', 'foreign\nOK\n', self.emu.state['avd']])
        guard = mock.Mock()
        with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'not owned'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_not_called()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(queued, [self.emu.state['avd']])

    def test_exact_recorded_greeting_is_incomplete_then_requires_fresh_owned_name(self):
        self.active()
        greeting = "Android Console: type 'help' for a list of commands\n\n"
        self.assertEqual(len(greeting.encode('utf-8')), 53)
        self.assertEqual(hashlib.sha256(greeting.encode('utf-8')).hexdigest(),
                         'ca2994852935b23c28146183f3c5c2422f318e83e63b0f2e0ae01d5004edd1e5')
        queued = self.probe_sequence([greeting, self.emu.state['avd'] + '\nOK\n'])
        events = []
        scripted = self.runner.side_effect
        def observe(args, **kwargs):
            if args[-2:] == ['shell', 'true']:
                events.append('action')
            return scripted(args, **kwargs)
        self.runner.side_effect = observe
        with self.clocked() as (_, sleep):
            self.emu.adb(['shell', 'true'], before_action=lambda: events.append('guard'))
        self.assertEqual(queued, [])
        self.assertEqual(events, ['guard', 'action'])
        self.assertEqual(len(self.calls), 3)
        sleep.assert_called_once_with(0.1)
        self.assertEqual([r['outcome'] for r in self.history()['records']], ['greeting', 'owned'])

    def test_three_exact_greetings_do_not_authorize_action(self):
        self.active()
        greeting = "Android Console: type 'help' for a list of commands\n\n"
        queued = self.probe_sequence([greeting, greeting, greeting, self.emu.state['avd']])
        guard = mock.Mock()
        with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'three attempts'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_not_called()
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(queued, [self.emu.state['avd']])
        self.assertEqual([r['outcome'] for r in self.history()['records']], ['greeting'] * 3)

    def test_greeting_with_other_payload_or_stderr_is_never_retried(self):
        self.active()
        greeting = "Android Console: type 'help' for a list of commands\n\n"
        exact = self.emu.state['avd']
        for response in (greeting + exact, greeting + 'foreign\n', greeting + 'KO: error\n',
                         greeting + ' ', (greeting, 'warning', 0)):
            with self.subTest(response=type(response).__name__):
                self.calls.clear()
                queued = self.probe_sequence([response, exact])
                guard = mock.Mock()
                with self.clocked() as (_, sleep), self.assertRaises(emulator.Failure):
                    self.emu.adb(['emu', 'kill'], before_action=guard)
                self.assertEqual(len(self.calls), 1)
                self.assertEqual(queued, [exact])
                sleep.assert_not_called()
                guard.assert_not_called()

    def test_greeting_retry_still_blocks_action_when_final_byte_guard_fails(self):
        self.active()
        greeting = "Android Console: type 'help' for a list of commands\n\n"
        self.probe_sequence([greeting, self.emu.state['avd'] + '\nOK\n'])
        guard = mock.Mock(side_effect=emulator.Failure('late mutation'))
        with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'late mutation'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_called_once_with()
        self.assertEqual(len(self.calls), 2)

    def test_nonretryable_probe_matrix_stops_immediately(self):
        self.active()
        exact = self.emu.state['avd']
        responses = ['OK\n', exact + '\n' + exact, exact + '\nextra\nOK\n',
                     'KO: error\n', exact + '_suffix', 'prefix_' + exact, '  \n',
                     ('', ' ', 0), (exact + '\nOK\n', 'warning', 0),
                     ('', '', 1), (exact, '', 1), OSError('cannot run'),
                     RuntimeError('unexpected failure'), subprocess.TimeoutExpired('adb', 1,
                         output=b'partial-sensitive', stderr=b'secret-stderr')]
        for response in responses:
            with self.subTest(response=type(response).__name__):
                self.calls.clear()
                queued = self.probe_sequence([response, exact])
                guard = mock.Mock()
                with self.clocked() as (_, sleep), self.assertRaises(Exception):
                    self.emu.adb(['emu', 'kill'], before_action=guard)
                self.assertEqual(len(self.calls), 1)
                self.assertEqual(queued, [exact])
                sleep.assert_not_called()
                guard.assert_not_called()
        encoded = (self.run / 'ownership-probes.json').read_text()
        self.assertNotIn('partial-sensitive', encoded)
        self.assertNotIn('secret-stderr', encoded)
        last = self.history()['records'][-1]
        self.assertEqual(last['outcome'], 'timeout')
        self.assertEqual(last['stdout_bytes'], len(b'partial-sensitive'))
        self.assertEqual(last['stdout_sha256'], hashlib.sha256(b'partial-sensitive').hexdigest())

    def test_deadline_before_first_probe_has_no_positive_floor(self):
        self.active()
        guard = mock.Mock()
        for timeout in (0, -1):
            with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'deadline'):
                self.emu.adb(['emu', 'kill'], timeout=timeout, before_action=guard)
        with mock.patch.object(emulator.time, 'monotonic', side_effect=[0, 5]), \
                self.assertRaisesRegex(emulator.Failure, 'deadline'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        self.assertEqual(self.calls, [])
        guard.assert_not_called()

    def test_deadline_before_next_attempt_blocks_sleep_and_queued_probe(self):
        self.active()
        exact = self.emu.state['avd']
        queued = self.probe_sequence(['', exact])
        ticks = iter([0] * 6)
        def monotonic():
            return next(ticks, 5)
        guard = mock.Mock()
        with mock.patch.object(emulator.time, 'monotonic', side_effect=monotonic), \
                mock.patch.object(emulator.time, 'sleep') as sleep, \
                self.assertRaisesRegex(emulator.Failure, 'deadline'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        self.assertEqual(queued, [exact])
        self.assertEqual(len(self.calls), 1)
        sleep.assert_not_called()
        guard.assert_not_called()
        self.assertEqual(self.history()['records'][-1]['outcome'], 'empty')

    def test_deadline_during_retry_sleep_blocks_next_probe(self):
        self.active()
        exact = self.emu.state['avd']
        queued = self.probe_sequence(['', exact])
        guard = mock.Mock()
        with self.clocked() as (_, sleep), self.assertRaisesRegex(emulator.Failure, 'deadline'):
            self.emu.adb(['emu', 'kill'], timeout=0.05, before_action=guard)
        self.assertEqual(queued, [exact])
        sleep.assert_called_once_with(0.05)
        guard.assert_not_called()
        self.assertEqual(len(self.history()['records']), 1)

    def test_deadline_after_result_blocks_even_exact_name(self):
        self.active()
        for value in ('', self.emu.state['avd']):
            with self.subTest(empty=not value):
                self.calls.clear()
                clock = Clock()
                queued = self.probe_sequence([value, self.emu.state['avd']],
                                            on_probe=lambda *args: setattr(clock, 'now', 5))
                guard = mock.Mock()
                with self.clocked(clock), self.assertRaisesRegex(emulator.Failure, 'deadline'):
                    self.emu.adb(['emu', 'kill'], before_action=guard)
                self.assertEqual(len(self.calls), 1)
                self.assertEqual(queued, [self.emu.state['avd']])
                guard.assert_not_called()
                self.assertEqual(self.history()['records'][-1]['outcome'], 'deadline')

    def test_shrinking_probe_budgets_use_minimum_of_five_and_caller(self):
        self.active()
        for timeout, initial in ((30, 5), (0.8, 0.8)):
            with self.subTest(timeout=timeout):
                self.calls.clear()
                clock = Clock()
                def work(*args):
                    clock.now += 0.1
                self.probe_sequence(['', '', self.emu.state['avd']], on_probe=work)
                with self.clocked(clock):
                    self.emu.adb(['shell', 'true'], timeout=timeout)
                budgets = [kw['timeout'] for args, kw in self.calls if args[-3:] == ['emu', 'avd', 'name']]
                for actual, expected in zip(budgets, (initial, initial - 0.2, initial - 0.4)):
                    self.assertAlmostEqual(actual, expected)
                self.assertEqual(len(budgets), 3)
                self.assertEqual(self.calls[-1][1]['timeout'], timeout)

    def test_deadline_before_next_attempt_after_diagnostics_is_fail_closed(self):
        self.active()
        guard = mock.Mock()
        clock = Clock()
        self.probe_sequence(['', self.emu.state['avd']])
        writer = emulator.write_json
        def slow_write(path, value):
            writer(path, value)
            clock.now = 5
        with self.clocked(clock), mock.patch.object(emulator, 'write_json', side_effect=slow_write), \
                self.assertRaisesRegex(emulator.Failure, 'deadline'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_not_called()
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([r['outcome'] for r in self.history()['records']], ['empty', 'owned'])

    def test_probe_evidence_write_failure_fail_closed_or_preserves_primary(self):
        self.active()
        for responses, expected in ((['', self.emu.state['avd']], OSError),
                                    (['foreign'], emulator.Failure)):
            with self.subTest(expected=expected):
                self.calls.clear()
                self.probe_sequence(responses)
                guard = mock.Mock()
                with self.clocked(), mock.patch.object(emulator, 'write_json', side_effect=OSError('disk full')), \
                        self.assertRaises(expected) as failure:
                    self.emu.adb(['emu', 'kill'], before_action=guard)
                if expected is emulator.Failure:
                    self.assertIn('not owned', str(failure.exception))
                guard.assert_not_called()
                self.assertEqual(len(self.calls), len(responses))

    def test_probe_history_retained_across_success_and_bounded_with_pruning(self):
        self.active()
        for _ in range(18):
            self.probe_sequence(['', self.emu.state['avd']])
            with self.clocked():
                self.emu.adb(['shell', 'never-serialize-this-action-or-credentials'])
        history = self.history()
        self.assertEqual(len(history['records']), 32)
        self.assertEqual(history['pruned'], 4)
        with self.clocked():
            self.runner.side_effect = self.respond
            self.emu.adb(['shell', 'true'])
        self.assertEqual(self.history(), history, 'first success must not overwrite prior failures')
        encoded = (self.run / 'ownership-probes.json').read_text()
        self.assertNotIn('never-serialize', encoded)
        self.assertNotIn(self.emu.state['avd'], encoded)
        self.assertLess(len(encoded), 65536)
        # A fresh object/call retains the on-disk bounded history, not an instance cache.
        other = emulator.Emulator(self.sdk, self.run)
        other.load()
        self.probe_sequence(['foreign'])
        with self.clocked(), self.assertRaises(emulator.Failure):
            other.adb(['emu', 'kill'])
        self.assertEqual(self.history()['pruned'], 5)
        self.assertEqual(self.history()['records'][-1]['outcome'], 'not_owned')

    def test_action_failure_or_timeout_is_one_invocation_without_retry(self):
        self.active()
        exact = self.emu.state['avd']
        for failure in ('exit', 'timeout'):
            self.calls.clear()
            self.probe_sequence(['', exact, exact])
            probes = self.runner.side_effect
            def run(args, **kwargs):
                if args[-2:] == ['emu', 'kill']:
                    self.calls.append((args, kwargs))
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired('adb', kwargs['timeout'])
                    return subprocess.CompletedProcess(args, 1, '', 'action failed')
                return probes(args, **kwargs)
            self.runner.side_effect = run
            guard = mock.Mock()
            with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'timed out|action failed'):
                self.emu.adb(['emu', 'kill'], before_action=guard)
            guard.assert_called_once_with()
            self.assertEqual(len(self.calls), 3)
            self.assertEqual(sum(args[-2:] == ['emu', 'kill'] for args, _ in self.calls), 1)

    def test_guard_exception_after_retry_blocks_action(self):
        self.active()
        self.probe_sequence(['', self.emu.state['avd']])
        guard = mock.Mock(side_effect=emulator.Failure('guard mutation'))
        with self.clocked(), self.assertRaisesRegex(emulator.Failure, 'guard mutation'):
            self.emu.adb(['emu', 'kill'], before_action=guard)
        guard.assert_called_once_with()
        self.assertEqual(len(self.calls), 2)

    def test_failed_stop_probe_preserves_persisted_state_without_confirmation(self):
        self.active()
        before = self.emu.state_path.read_bytes()
        self.probe_sequence(['', '', ''])
        with self.clocked(), self.assertRaises(emulator.Failure):
            self.emu.stop()
        self.assertEqual(self.emu.state_path.read_bytes(), before)
        self.emu.load()
        self.assertEqual(self.emu.state['status'], 'running')
        self.exited.assert_not_called()
        self.released.assert_not_called()
        self.assertEqual(len(self.calls), 3)

    def test_start_scoped_server_detached_process_and_boot(self):
        self.create()
        socks = self.reservations()
        process = mock.Mock(pid=777)
        process.poll.return_value = None
        self.popen.side_effect = None
        self.popen.return_value = process
        report = self.emu.start(10, "swiftshader")
        self.assertEqual(report["serial"], "emulator-5556")
        self.assertEqual(self.emu.state["pid"], 777)
        self.assertEqual(self.emu.state["abi"]["ro.product.cpu.abi"], "x86_64")
        args, kwargs = self.popen.call_args
        self.assertIn("-no-window", args[0])
        self.assertIn("-no-snapshot", args[0])
        self.assertIn("swiftshader", args[0])
        self.assertEqual(kwargs["env"]["ANDROID_ADB_SERVER_PORT"], "40402")
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertFalse(kwargs["shell"])
        if os.name == "nt":
            self.assertTrue(kwargs["creationflags"] & subprocess.CREATE_NEW_PROCESS_GROUP)
        else:
            self.assertTrue(kwargs["start_new_session"])
        for sock in socks:
            self.assertTrue(sock.close.called)
        server_calls = [call for call, _ in self.calls if "start-server" in call]
        self.assertEqual(server_calls[0][1:], ["-P", "40402", "start-server"])
        for call, _ in self.calls:
            if "-s" in call:
                self.assertEqual(call[1:5], ["-P", "40402", "-s", "emulator-5556"])

    def test_boot_timeout_keeps_identity_and_never_kills_process(self):
        self.create()
        self.reservations()
        process = mock.Mock(pid=777)
        process.poll.return_value = None
        self.popen.side_effect = None
        self.popen.return_value = process
        original = self.respond
        clock = Clock()
        def not_booted(args, **kwargs):
            result = original(args, **kwargs)
            if args[-2:] == ["getprop", "sys.boot_completed"]:
                result.stdout = "0\n"
                clock.now = 2
            return result
        self.runner.side_effect = not_booted
        with mock.patch.object(emulator.time, "monotonic", side_effect=clock.monotonic):
            with self.assertRaisesRegex(emulator.Failure, "Boot timed out"):
                self.emu.start(1, "software")
        self.emu.load()
        self.assertEqual(self.emu.state["serial"], "emulator-5556")
        self.assertEqual(self.emu.state["pid"], 777)
        self.assertEqual(self.emu.state["status"], "starting")
        process.kill.assert_not_called()
        process.terminate.assert_not_called()
        self.emu.stop()
        self.assertEqual(self.emu.state["status"], "stopped")

    def test_launch_failure_releases_reservations(self):
        self.create()
        socks = self.reservations()
        self.popen.side_effect = OSError("cannot launch")
        with self.assertRaises(OSError):
            self.emu.start(1, "software")
        for sock in socks:
            self.assertTrue(sock.close.called)
        self.assertEqual(self.emu.state.get("pid"), None)

    def test_manager_launches_java_not_batch_wrapper(self):
        self.manager_patcher.stop()
        java_home = self.root / 'jdk'
        java = java_home / 'bin' / ('java.exe' if os.name == 'nt' else 'java')
        java.parent.mkdir(parents=True)
        java.write_bytes(b'fixture')
        jar = self.sdk / 'cmdline-tools/latest/lib/avdmanager-classpath.jar'
        jar.parent.mkdir(parents=True)
        jar.write_bytes(b'fixture')
        self.emu.env['JAVA_HOME'] = str(java_home)
        self.assertEqual(self.emu.manager_command(), [str(java),
                         '-Dcom.android.sdkmanager.toolsdir=' + str(self.sdk / 'cmdline-tools/latest'),
                         '-classpath', str(jar), 'com.android.sdklib.tool.AvdManagerCli'])

    def test_boot_exit_is_persisted_as_stopped(self):
        self.create()
        self.reservations()
        process = mock.Mock(pid=777)
        process.poll.return_value = 1
        self.popen.side_effect = None
        self.popen.return_value = process
        with self.assertRaisesRegex(emulator.Failure, 'exited before boot'):
            self.emu.start(10, 'software')
        self.emu.load()
        self.assertEqual(self.emu.state['status'], 'stopped')
        process.kill.assert_not_called()

    def test_start_refuses_already_active_run(self):
        self.active()
        with self.assertRaisesRegex(emulator.Failure, "created"):
            self.emu.start(1, "software")
        self.popen.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_install_explicit_split_paths_records_stdout_and_abi(self):
        self.active()
        apks = [self.root / "base app.apk", self.root / "split_config.x86_64.apk"]
        for path in apks:
            path.write_bytes(b"test")
        def verify(paths, out, **kwargs):
            self.assertEqual(self.calls, [], 'verification must precede ALL device calls')
            self.assertNotEqual(paths, apks)
            self.assertTrue(all(p.is_relative_to(self.run) for p in paths))
            self.assertEqual([p.read_bytes() for p in paths], [p.read_bytes() for p in apks])
            return self.verification_report(paths, out)
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=verify) as verifier:
            report = self.emu.install([str(path) for path in apks], {'explicit': 'pins'})
        verifier.assert_called_once()
        self.assertTrue(Path(report['verification']).is_file())
        install_call = [call for call, _ in self.calls if "install-multiple" in call][0]
        self.assertEqual(install_call[-3:], ['install-multiple', *report['staged_apks']])
        self.assertEqual(report['capabilities']['sdk'], 35)
        self.assertEqual(len(report['installed_paths']), 2)
        self.assertIn('primaryCpuAbi=x86_64', report['installed_abi_evidence'])
        self.assertEqual(Path(report["stdout"]).read_text(), "Success\n")
        self.emu.load()
        self.assertEqual(self.emu.state["installs"][0]["apks"], list(map(str, apks)))
        for index, (call, _) in enumerate(self.calls):
            if "getprop" in call or "install-multiple" in call:
                self.assertEqual(self.calls[index - 1][0][-3:], ["emu", "avd", "name"])

    def test_install_refuses_implicit_missing_duplicate_paths(self):
        self.active()
        apk = self.root / "base.apk"
        apk.write_bytes(b"test")
        for paths in ([], [str(self.root / "*.apk")], [str(apk), str(apk)], [str(self.root)]):
            with self.subTest(paths=paths), self.assertRaises(emulator.Failure):
                self.emu.install(paths)
        self.assertEqual(self.calls, [])

    def test_install_requires_verification_and_failure_precedes_adb(self):
        self.active()
        apk = self.root / 'base.apk'
        apk.write_bytes(b'fixture')
        with self.assertRaisesRegex(emulator.Failure, 'verification'):
            self.emu.install([apk])
        with mock.patch.object(self.emu.verifier, 'verify_apks',
                side_effect=self.emu.verifier.DriverError('signer mismatch')):
            with self.assertRaisesRegex(emulator.Failure, 'signer mismatch'):
                self.emu.install([apk], {'explicit': 'pins'})
        self.assertEqual(self.calls, [])
        self.assertEqual(self.emu.state['installs'], [])

    def test_install_cli_requires_pins_and_explicit_split_selection(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
            self.invoke('install', 'base.apk')
        self.assertEqual(failure.exception.code, 2)
        self.runner.assert_not_called()

    def test_install_cli_forwards_same_verification_contract(self):
        self.active()
        with mock.patch.object(emulator.Emulator, 'install', return_value={'verified': True}) as install:
            code, _, error = self.invoke('install', 'base.apk', '--aapt2', 'aapt2', '--java', 'java',
                '--signer-jar', 'apksigner.jar', '--expect-package', 'org.example.app',
                '--expect-version-code', '7', '--expect-version-name', '1.2', '--expect-signer', 'a' * 64,
                '--abi', 'x86_64', '--density', 'nodpi', '--language', 'none')
        self.assertEqual(code, 0, error)
        options = install.call_args.args[1]
        self.assertEqual(options['expect_signer'], ['a' * 64])
        self.assertEqual(options['abi'], 'x86_64')
        self.assertEqual(options['language'], ['none'])
        self.assertEqual(self.calls, [])

    def test_install_detects_post_verification_mutation_before_install(self):
        self.active()
        apk = self.root / 'base.apk'
        apk.write_bytes(b'fixture')
        def verify(paths, out, **kwargs):
            report = self.verification_report(paths, out)
            apk.write_bytes(b'changed')
            return report
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=verify):
            with self.assertRaisesRegex(emulator.Failure, 'bytes changed'):
                self.emu.install([apk], {})
        self.assertFalse(any('install' in call or 'install-multiple' in call for call, _ in self.calls))

    def test_install_rejects_device_abi_mismatch(self):
        self.active()
        apk = self.root / 'base.apk'
        apk.write_bytes(b'fixture')
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=lambda paths, out, **kw:
                self.verification_report(paths, out, abi='arm64-v8a')):
            with self.assertRaisesRegex(emulator.Failure, 'ABI'):
                self.emu.install([apk], {})
        self.assertFalse(any('install' in call for call, _ in self.calls))

    def install_fixture(self):
        self.active()
        apk = self.root / 'original.apk'
        apk.write_bytes(b'fixture bytes')
        return apk

    def test_install_singleton_staging_and_post_install_evidence(self):
        apk = self.install_fixture()
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=self.verification_report):
            report = self.emu.install([apk], {})
        call = next(c for c, _ in self.calls if 'install' in c)
        self.assertEqual(call[-2:], ['install', report['staged_apks'][0]])
        self.assertNotEqual(call[-1], str(apk))
        self.assertEqual(report['mapping'][0]['original'], str(apk))
        self.assertEqual(report['capabilities']['translation_or_jni_execution'], 'not_proven')
        self.assertTrue((Path(report['stdout']).parent / 'installation.json').is_file())

    def test_live_sdk_and_32_64_inconsistency_stop_before_install(self):
        apk = self.install_fixture()
        original = self.respond
        for prop, value in [('ro.build.version.sdk', '23'), ('ro.build.version.sdk', 'bad'),
                            ('ro.product.cpu.abilist32', 'arm64-v8a'),
                            ('ro.product.cpu.abilist64', ''), ('ro.product.cpu.abi', 'armeabi-v7a')]:
            def respond(args, **kwargs):
                result = original(args, **kwargs)
                if args[-2:] == ['getprop', prop]:
                    result.stdout = value
                return result
            self.runner.side_effect = respond
            with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=self.verification_report):
                with self.subTest(prop=prop, value=value), self.assertRaises(emulator.Failure):
                    self.emu.install([apk], {})
            self.assertFalse(any('install' in c or 'install-multiple' in c for c, _ in self.calls))
        self.assertEqual(self.emu.state['installs'], [])

    def test_final_hash_guard_runs_after_install_ownership_probe(self):
        apk = self.install_fixture()
        original = self.respond
        def mutate_after_probe(args, **kwargs):
            result = original(args, **kwargs)
            if args[-3:] == ['emu', 'avd', 'name']:
                # Last property has completed; this is the install's name probe.
                if any(c[-2:] == ['getprop', 'ro.dalvik.vm.isa.arm64'] for c, _ in self.calls):
                    stage = next(self.run.glob('install-stage-*')) / 'member-0.apk'
                    stage.write_bytes(b'mutated after ownership probe')
            return result
        self.runner.side_effect = mutate_after_probe
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=self.verification_report):
            with self.assertRaisesRegex(emulator.Failure, 'bytes changed'):
                self.emu.install([apk], {})
        self.assertFalse(any('install' in c for c, _ in self.calls))
        self.assertEqual(self.emu.state['installs'], [])

    def test_retry_probe_mutation_of_original_or_staged_caught_by_final_install_guard(self):
        apk = self.install_fixture()
        for member in ('original', 'staged'):
            for moment in (1, 2):
                with self.subTest(member=member, probe=moment):
                    apk.write_bytes(b'fixture bytes')
                    self.calls.clear()
                    staged, probes = [], []
                    def verify(paths, out, **kwargs):
                        staged[:] = paths
                        return self.verification_report(paths, out)
                    def respond(args, **kwargs):
                        result = self.respond(args, **kwargs)
                        if (args[-3:] == ['emu', 'avd', 'name'] and any(
                                c[-2:] == ['getprop', 'ro.dalvik.vm.isa.arm64'] for c, _ in self.calls)):
                            probes.append(args)
                            if len(probes) == moment:
                                (apk if member == 'original' else staged[0]).write_bytes(b'mutated during retry')
                            if len(probes) == 1:
                                result.stdout = ''
                        return result
                    self.runner.side_effect = respond
                    with self.clocked(), mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=verify), \
                            self.assertRaisesRegex(emulator.Failure, 'bytes changed'):
                        self.emu.install([apk], {})
                    self.assertEqual(len(probes), 2)
                    self.assertFalse(any('install' in c or 'install-multiple' in c for c, _ in self.calls))
                    self.assertEqual(self.emu.state['installs'], [])

    def test_original_mutation_after_final_probe_and_ownership_loss_block_install(self):
        apk = self.install_fixture()
        original = self.respond
        for mode in ('original', 'ownership'):
            self.calls.clear()
            def respond(args, **kwargs):
                result = original(args, **kwargs)
                if (args[-3:] == ['emu', 'avd', 'name'] and any(
                        c[-2:] == ['getprop', 'ro.dalvik.vm.isa.arm64'] for c, _ in self.calls)):
                    if mode == 'original':
                        apk.write_bytes(b'original changed after final ownership probe')
                    else:
                        result.stdout = 'foreign-avd\nOK\n'
                return result
            self.runner.side_effect = respond
            with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=self.verification_report):
                with self.subTest(mode=mode), self.assertRaises(emulator.Failure):
                    self.emu.install([apk], {})
            self.assertFalse(any('install' in c or 'install-multiple' in c for c, _ in self.calls))
            self.assertEqual(self.emu.state['installs'], [])

    def test_post_install_mutation_and_path_count_do_not_emit_success(self):
        apk = self.install_fixture()
        original = self.respond
        for mode in ('mutate', 'paths'):
            def respond(args, **kwargs):
                result = original(args, **kwargs)
                if mode == 'mutate' and 'install' in args:
                    Path(args[-1]).write_bytes(b'changed during install')
                if mode == 'paths' and args[-4:-1] == ['shell', 'pm', 'path']:
                    result.stdout = 'package:/data/app/one.apk\npackage:/data/app/two.apk\n'
                return result
            self.runner.side_effect = respond
            with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=self.verification_report):
                with self.subTest(mode=mode), self.assertRaises(emulator.Failure):
                    self.emu.install([apk], {})
            self.assertEqual(self.emu.state['installs'], [])
            self.assertFalse(list(self.run.glob('install-stage-*/installation.json')))

    def test_staging_rejects_hardlink_aliases_and_substituted_member(self):
        apk = self.install_fixture()
        alias = self.root / 'alias.apk'
        os.link(apk, alias)
        with self.assertRaises(emulator.Failure):
            self.emu.install([apk, alias], {})
        self.assertEqual(self.calls, [])
        def substitute(paths, out, **kwargs):
            report = self.verification_report(paths, out)
            report['apks'][0]['path'] = str(apk)
            return report
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=substitute):
            with self.assertRaisesRegex(emulator.Failure, 'binding differs'):
                self.emu.install([apk], {})
        self.assertEqual(self.calls, [])

    def test_advertised_translated_abi_is_not_renamed_or_runtime_success(self):
        apk = self.install_fixture()
        original = self.respond
        values = {'ro.product.cpu.abilist': 'x86_64,x86,arm64-v8a,armeabi-v7a,armeabi',
                  'ro.product.cpu.abilist32': 'x86,armeabi-v7a,armeabi',
                  'ro.product.cpu.abilist64': 'x86_64,arm64-v8a',
                  'ro.dalvik.vm.native.bridge': 'libhoudini.so'}
        def respond(args, **kwargs):
            result = original(args, **kwargs)
            if 'getprop' in args and args[-1] in values:
                result.stdout = values[args[-1]]
            return result
        self.runner.side_effect = respond
        with mock.patch.object(self.emu.verifier, 'verify_apks', side_effect=lambda paths, out, **kw:
                self.verification_report(paths, out, abi='arm64-v8a')):
            report = self.emu.install([apk], {})
        self.assertEqual(report['capabilities']['selected_abi'], 'arm64-v8a')
        self.assertEqual(report['capabilities']['primary_abi'], 'x86_64')
        self.assertEqual(report['capabilities']['properties']['ro.product.cpu.abilist32'],
                         'x86,armeabi-v7a,armeabi')
        self.assertEqual(report['capabilities']['properties']['ro.dalvik.vm.native.bridge'], 'libhoudini.so')
        self.assertEqual(report['capabilities']['translation_or_jni_execution'], 'not_proven')

    def test_run_in_repository_refused_before_any_tool(self):
        self.emu.run = Path(__file__).resolve().parents[3] / 'forbidden-run'
        with self.assertRaisesRegex(emulator.Failure, 'outside'):
            self.emu.create(self.image)
        with self.assertRaisesRegex(emulator.Failure, 'outside'):
            self.emu.load()
        self.runner.assert_not_called()

    def test_launch_resolves_launcher_and_component(self):
        self.active()
        report = self.emu.launch("com.example.app", None)
        self.assertEqual(report["component"], "com.example.app/.MainActivity")
        self.assertEqual(self.calls[-1][0][-6:], ["shell", "am", "start", "-W", "-n", "com.example.app/.MainActivity"])

    def test_launch_leanback_fallback(self):
        self.active()
        original = self.respond
        def leanback(args, **kwargs):
            result = original(args, **kwargs)
            if "android.intent.category.LAUNCHER" in args:
                result.stdout = "No activity found\n"
            return result
        self.runner.side_effect = leanback
        self.emu.launch("com.example.app", None)
        self.assertTrue(any("android.intent.category.LEANBACK_LAUNCHER" in call for call, _ in self.calls))

    def test_reject_shell_injection_and_foreign_component_before_adb(self):
        self.active()
        for app, chosen in (("com.example.app;rm", None),
                            ("com.example.app", "com.other.app/.Main"),
                            ("com.example.app", "com.example.app/.Main;reboot"),
                            ("com.example.app", "com.example.app/.Main$HOME")):
            with self.subTest(app=app, chosen=chosen), self.assertRaises(emulator.Failure):
                self.emu.launch(app, chosen)
        self.assertEqual(self.calls, [])

    def test_launch_detects_am_error_even_with_zero_exit(self):
        self.active()
        original = self.respond
        def launch_error(args, **kwargs):
            result = original(args, **kwargs)
            if "start" in args:
                result.stdout = "Error type 3\nError: Activity does not exist\n"
            return result
        self.runner.side_effect = launch_error
        with self.assertRaisesRegex(emulator.Failure, "launch failed"):
            self.emu.launch("com.example.app", "com.example.app/.Main")
        self.assertTrue((self.run / "launch.txt").exists())

    def test_screenshot_preserves_binary_png(self):
        self.active()
        report = self.emu.capture("screenshot")
        self.assertEqual(Path(report["path"]).read_bytes(), b"\x89PNG\r\n\x1a\n\x00\xff\r\n")
        self.assertFalse(self.calls[-1][1]["text"])
        self.assertEqual(self.calls[-1][0][-3:], ["exec-out", "screencap", "-p"])

    def test_dump_uses_owned_remote_filename_and_verified_cleanup(self):
        self.active()
        report = self.emu.capture("dump")
        remote = "/data/local/tmp/morphe_" + self.emu.state["owner"] + ".xml"
        self.assertEqual(self.calls[1][0][-4:], ["shell", "uiautomator", "dump", remote])
        self.assertEqual(self.calls[3][0][-3:], ["exec-out", "cat", remote])
        self.assertEqual(self.calls[5][0][-4:], ["shell", "rm", "-f", remote])
        self.assertIn(b"hierarchy", Path(report["path"]).read_bytes())

    def test_dump_cleans_up_after_timeout(self):
        self.active()
        original = self.respond
        def timeout(args, **kwargs):
            if "uiautomator" in args:
                raise subprocess.TimeoutExpired(args, kwargs["timeout"])
            return original(args, **kwargs)
        self.runner.side_effect = timeout
        with self.assertRaisesRegex(emulator.Failure, "timed out"):
            self.emu.capture("dump")
        self.assertEqual(self.calls[-1][0][-4:-1], ["shell", "rm", "-f"])
        self.assertFalse((self.run / "hierarchy.xml").exists())

    def test_dump_cleanup_refuses_identity_change(self):
        self.active()
        original = self.respond
        name_count = 0
        def changed(args, **kwargs):
            nonlocal name_count
            result = original(args, **kwargs)
            if args[-3:] == ["emu", "avd", "name"]:
                name_count += 1
                if name_count >= 3:
                    result.stdout = "foreign-avd\nOK\n"
            return result
        self.runner.side_effect = changed
        with self.assertRaisesRegex(emulator.Failure, "not owned"):
            self.emu.capture("dump")
        self.assertFalse(any("rm" in call for call, _ in self.calls))

    def test_cli_key_tap_and_bounded_logcat(self):
        self.active()
        for args, expected in ((["key", "23"], ["shell", "input", "keyevent", "23"]),
                               (["tap", "20", "40"], ["shell", "input", "tap", "20", "40"]),
                               (["logcat", "--lines", "12"], ["logcat", "-d", "-t", "12"])):
            code, output, error = self.invoke(*args)
            self.assertEqual(code, 0, error)
            self.assertTrue(json.loads(output)["ok"])
            self.assertEqual(self.calls[-1][0][-len(expected):], expected)
        for args in (["key", "289"], ["tap", "-1", "0"], ["logcat", "--lines", "2001"], ["start", "--timeout", "0"]):
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                self.invoke(*args)
            self.assertEqual(caught.exception.code, 2)

    def test_stop_only_owned_serial_no_global_kill(self):
        self.active()
        report = self.emu.stop()
        self.assertEqual(report["status"], "stopped")
        self.assertEqual(self.calls[-1][0][1:], ["-P", "40401", "-s", "emulator-5554", "emu", "kill"])
        self.assertFalse(any("kill-server" in call or "-d" in call or "-e" in call or "wipe-data" in call for call, _ in self.calls))
        self.popen.assert_not_called()

    def test_stop_waits_for_process_exit_and_both_endpoints(self):
        self.active()
        self.exited.side_effect = [False, True, True]
        self.released.side_effect = [False, True]
        with mock.patch.object(emulator.time, 'sleep') as sleep:
            report = self.emu.stop(2)
        self.assertEqual(report['confirmation'], 'process_exited_and_both_owned_ports_released')
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(sum(call[-2:] == ['emu', 'kill'] for call, _ in self.calls), 1)
        self.exited.assert_called_with(12345)
        self.released.assert_called_with(5554)
        self.popen.assert_not_called()

    def test_stop_acknowledgement_without_exit_times_out_and_retry_only_confirms(self):
        self.active()
        self.exited.return_value = False
        clock = Clock()
        with mock.patch.object(emulator.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(emulator.time, 'sleep', side_effect=clock.sleep):
            with self.assertRaisesRegex(emulator.Failure, 'unconfirmed'):
                self.emu.stop(1)
        self.emu.load()
        self.assertEqual(self.emu.state['status'], 'stopping')
        with self.assertRaises(emulator.Failure):
            self.emu.start(1, 'software')
        calls = list(self.calls)
        self.exited.return_value = True
        self.emu.stop(1)
        self.assertEqual(self.calls, calls, 'retry must not kill a replacement at reused ports')
        self.assertEqual(self.emu.state['status'], 'stopped')
        self.popen.assert_not_called()

    def test_process_exit_without_endpoint_release_is_not_success(self):
        self.active()
        self.released.return_value = False
        clock = Clock()
        with mock.patch.object(emulator.time, 'monotonic', side_effect=clock.monotonic), \
                mock.patch.object(emulator.time, 'sleep', side_effect=clock.sleep):
            with self.assertRaisesRegex(emulator.Failure, 'unconfirmed'):
                self.emu.stop(1)
        self.assertEqual(self.emu.state['status'], 'stopping')
        self.assertNotIn('stop_confirmation', self.emu.state)

    def test_endpoint_confirmation_uses_both_binds_and_closes_them(self):
        # Call the real helper from a second explicit module, still with socket mocked.
        spec2 = importlib.util.spec_from_file_location('endpoint_fixture', Path(__file__).with_name('emulator.py'))
        module = importlib.util.module_from_spec(spec2)
        spec2.loader.exec_module(module)
        first, second = mock.Mock(), mock.Mock()
        with mock.patch.object(module.socket, 'socket', side_effect=[first, second]):
            self.assertTrue(module.endpoints_released(5556))
        first.bind.assert_called_once_with(('127.0.0.1', 5556))
        second.bind.assert_called_once_with(('127.0.0.1', 5557))
        first.close.assert_called_once()
        second.close.assert_called_once()
        second.bind.side_effect = OSError(emulator.errno.EADDRINUSE, 'busy')
        with mock.patch.object(module.socket, 'socket', side_effect=[first, second]):
            self.assertFalse(module.endpoints_released(5556))

    def test_failed_stop_keeps_retryable_identity_and_cli_unlocks(self):
        self.active()
        original = self.respond
        def fail(args, **kwargs):
            if args[-2:] == ["emu", "kill"]:
                return subprocess.CompletedProcess(args, 1, "", "offline")
            return original(args, **kwargs)
        self.runner.side_effect = fail
        code, _, error = self.invoke("stop")
        self.assertEqual(code, 1)
        self.assertIn("offline", json.loads(error)["error"])
        self.emu.load()
        self.assertEqual(self.emu.state["status"], "running")
        self.assertFalse((self.run / ".command-lock").exists())

    def test_command_lock_refuses_concurrent_operations(self):
        self.active()
        with emulator.locked(self.run):
            code, _, error = self.invoke("stop")
            self.assertEqual(code, 1)
            self.assertIn("locked", json.loads(error)["error"])
        self.assertEqual(self.calls, [])

    def test_port_selection_skips_busy_console_and_closes_failed_reservation(self):
        busy, console, transport, server = [mock.Mock() for _ in range(4)]
        busy.bind.side_effect = OSError("busy")
        server.getsockname.return_value = ("127.0.0.1", 40403)
        with mock.patch.object(emulator.socket, "socket", side_effect=[busy, console, transport, server]):
            port, adb_port, reservations = emulator.ports()
        self.assertEqual((port, adb_port), (5556, 40403))
        busy.close.assert_called_once()
        self.assertEqual(reservations, [console, transport, server])
        console.bind.assert_called_once_with(("127.0.0.1", 5556))
        transport.bind.assert_called_once_with(("127.0.0.1", 5557))


if __name__ == "__main__":
    unittest.main()
