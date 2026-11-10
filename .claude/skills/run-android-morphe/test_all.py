"""Run the canonical offline tooling suites under Python -I -B.

No test discovery from caller-controlled directories, device actions, downloads,
Gradle builds, or signing keys. Real integration evidence is separate.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
SUITES = ('test_driver.py', 'test_emulator.py', 'test_bootstrap.py',
          'test_lab.py', 'test_patchdev.py', 'test_assembly.py', 'test_fixture_signing.py',
          'test_smoke.py', 'test_splitset.py', 'test_split_apply.py', 'test_split_smoke.py')


def main() -> int:
    suite = unittest.TestSuite()
    for filename in SUITES:
        path = HERE / filename
        if not path.is_file():
            print('Required offline suite is missing: ' + filename, file=sys.stderr)
            return 1
        name = '_canonical_suite_' + path.stem
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            print('Cannot load required offline suite', file=sys.stderr)
            return 1
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    return 0 if result.wasSuccessful() and result.testsRun else 1


if __name__ == '__main__':
    raise SystemExit(main())
