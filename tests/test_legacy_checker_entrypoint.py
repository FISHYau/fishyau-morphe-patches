"""Retired entry-point checks: installed PowerShell only; no JVM/build/device work.

All subprocess working directories and test inputs are NEW external temporary
scratch. PowerShell is selected from explicit installed locations, never PATH.
On non-Windows hosts only the static contract test runs.
"""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
LAUNCHER = REPO / ".claude/skills/run-android-morphe/check-termius.ps1"


class LegacyCheckerStaticTests(unittest.TestCase):
    def test_retirement_points_to_scoped_runner_and_five_arguments(self):
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertIn("is retired", source)
        self.assertIn("tools/termius-check/run_jvm_checks.py", source)
        self.assertIn("--scope termius or --scope collection", source)
        self.assertIn("RuntimeCheckKt requires exactly five arguments", source)
        self.assertIn(
            "ABS_EXACT_MPP ABS_TERMIUS_BASE_APK NEW_EXTERNAL_DIRECTORY ABS_MATCHING_CATALOG ABS_REPO",
            source,
        )
        self.assertIn("throw $guidance", source)


@unittest.skipUnless(os.name == "nt", "Windows installed PowerShell checks")
class LegacyCheckerPowerShellTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidates = (
            Path("C:/Program Files/PowerShell/7/pwsh.exe"),
            Path.home() / "AppData/Local/Microsoft/WindowsApps/Microsoft.PowerShell_8wekyb3d8bbwe/pwsh.exe",
        )
        cls.pwsh = next((path for path in candidates if path.is_file()), None)
        if cls.pwsh is None:
            raise unittest.SkipTest("Explicit installed PowerShell 7+ required; no PATH fallback")

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="morphe-retired-checker-")
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name).resolve()
        self.assertNotIn(REPO, self.root.parents)
        self.assertNotEqual(REPO, self.root)

    def invoke(self, *args):
        return subprocess.run(
            [str(self.pwsh), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(LAUNCHER), *map(str, args)],
            cwd=self.root, capture_output=True, text=True, timeout=30, check=False,
        )

    def assert_retired(self, result):
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        output = result.stdout + result.stderr
        self.assertIn("is retired", output)
        self.assertIn("run_jvm_checks.py", output)
        self.assertIn("five arguments", output)
        self.assertIn("ABS_MATCHING_CATALOG", output)
        self.assertIn("ABS_REPO", output)

    def snapshot(self):
        return {str(path.relative_to(self.root)): path.read_bytes()
                for path in self.root.rglob("*") if path.is_file()}

    def test_help_is_successful_read_only_guidance(self):
        result = self.invoke("-Help")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("", result.stderr)
        self.assertIn("is retired", result.stdout)
        self.assertIn("--scope termius or --scope collection", result.stdout)
        self.assertIn("exactly five arguments", result.stdout)
        self.assertEqual([], list(self.root.iterdir()))

    def test_bare_invocation_fails_without_prompts_or_writes(self):
        self.assert_retired(self.invoke())
        self.assertEqual([], list(self.root.iterdir()))

    def test_legacy_arguments_fail_before_missing_input_validation_or_writes(self):
        output = self.root / "new output must not exist"
        self.assert_retired(self.invoke(
            "-Bundle", self.root / "missing.mpp", "-InputApk", self.root / "missing.apk",
            "-Out", output, "-JavaHome", self.root / "missing jdk",
            "-GradleHome", self.root / "missing cache",
        ))
        self.assertFalse(output.exists())
        self.assertEqual([], list(self.root.iterdir()))

    def test_existing_inputs_and_output_are_untouched(self):
        bundle = self.root / "placeholder.mpp"
        apk = self.root / "placeholder.apk"
        bundle.write_text("not an executable bundle", encoding="utf-8")
        apk.write_text("not an app", encoding="utf-8")
        output = self.root / "existing output"
        output.mkdir()
        (output / "preserve.txt").write_text("retain", encoding="utf-8")
        before = self.snapshot()
        self.assert_retired(self.invoke(
            "-Bundle", bundle, "-InputApk", apk, "-Out", output,
            "-JavaHome", self.root, "-GradleHome", self.root,
        ))
        self.assertEqual(before, self.snapshot())
        self.assertEqual({"placeholder.mpp", "placeholder.apk", "existing output", "existing output/preserve.txt"},
                         {path.relative_to(self.root).as_posix() for path in self.root.rglob("*")})

    def test_partial_legacy_arguments_also_fail_with_migration_guidance(self):
        self.assert_retired(self.invoke("-Out", self.root / "unused"))
        self.assertEqual([], list(self.root.iterdir()))

    def test_ast_has_no_commands_methods_functions_or_environment_access(self):
        # Parse without dot-sourcing. Reject execution mechanisms, not strings
        # mentioning the replacement Java/Gradle route in help/error guidance.
        command = r"""
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile('__LAUNCHER__', [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw 'Launcher parse error' }
$forbidden = @($ast.FindAll({ param($node)
    $node -is [System.Management.Automation.Language.CommandAst] -or
    $node -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -or
    ($node -is [System.Management.Automation.Language.VariableExpressionAst] -and
        $node.VariablePath.UserPath.Contains(':'))
}, $true))
if ($forbidden.Count) { throw 'Retired launcher contains executable operations or scoped variable access' }
'NO_EXECUTION_OPERATIONS'
""".replace("__LAUNCHER__", str(LAUNCHER).replace("'", "''"))
        result = subprocess.run(
            [str(self.pwsh), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command],
            cwd=self.root, capture_output=True, text=True, timeout=30, check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("NO_EXECUTION_OPERATIONS", result.stdout)
        self.assertEqual([], list(self.root.iterdir()))


if __name__ == "__main__":
    unittest.main()
