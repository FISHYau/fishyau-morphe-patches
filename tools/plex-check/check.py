"""Offline Plex-only production-source/JUnit check using pinned real APIs; not MPP/device proof.

Run with Python -I -B, explicit installed Windows --jdk/--cache-root and a NEW external --out.
This compiles/executes donor-derived code: the current session's attempt was denied.
Obtain explicit execution approval before using it; a script/flag/hash is not approval.
No dependency resolution, downloads, signing, devices or generic-apply changes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve(cache, coordinate, expected):
    group, artifact, version = coordinate.split(':')
    candidates = list((cache / group / artifact / version).glob(f'*/{artifact}-{version}.jar'))
    if len(candidates) != 1 or sha(candidates[0]) != expected:
        raise ValueError(f'missing, ambiguous or hash-mismatched dependency: {coordinate}')
    return candidates[0].resolve()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk', required=True, type=Path)
    parser.add_argument('--cache-root', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    out = args.out.resolve()
    if out == repo or repo in out.parents or out.exists() or not out.parent.is_dir():
        parser.error('--out must be NEW, external to repo, with an existing parent')
    java = args.jdk.resolve() / 'bin/java.exe'
    if not java.is_file():
        parser.error('--jdk must contain bin/java.exe')
    closure_file = repo / '.claude/skills/run-android-morphe/templates/cache-closure.json'
    closure = json.loads(closure_file.read_text(encoding='utf-8'))
    compiler = [resolve(args.cache_root, *entry) for entry in closure['compiler']]
    runtime = [resolve(args.cache_root, *entry) for entry in closure['runtime']]
    junit = [resolve(args.cache_root, coordinate, digest) for coordinate, digest in [
        ('junit:junit:4.13.2', '8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3'),
        ('org.hamcrest:hamcrest-core:1.3', '66fdef91e9739348df7a096aa384a5685f4e875584cce89386a7a47251c4d8e9'),
    ]]
    sources = sorted((repo / 'patches/src/main/kotlin/io/github/fishyau/androidpatches/plex').rglob('*.kt'))
    tests = sorted((repo / 'patches/src/test/kotlin/io/github/fishyau/androidpatches/plex').rglob('*.kt'))
    if len(sources) != 3 or not tests:
        raise ValueError('expected the three migrated production sources and nonempty tests')
    inputs = [Path(__file__).resolve(), closure_file, java, *compiler, *runtime, *junit, *sources, *tests]
    hashes = {str(path): sha(path) for path in inputs}
    out.mkdir()
    classes, scratch = out / 'classes', out / 'scratch'
    classes.mkdir()
    scratch.mkdir()
    report = {'schema': 1, 'status': 'failed', 'scope': 'Plex-only JVM17 compilation and synthetic real-resource-API tests, not MPP/Manager/vendor-runtime acceptance', 'input_sha256': hashes, 'commands': []}
    env = {k: v for k, v in os.environ.items() if k not in {'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH'}}
    def run(label, command):
        report['commands'].append(command)
        process = subprocess.run(command, cwd=out, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        (out / f'{label}.log').write_text(process.stdout, encoding='utf-8')
        print(process.stdout, end='')
        if process.returncode != 0:
            raise RuntimeError(f'{label} exited {process.returncode}; retained {out}')
    try:
        cp = os.pathsep.join(map(str, runtime + junit))
        run('compile', [str(java), '-Xmx1024m', '-cp', os.pathsep.join(map(str, compiler)), 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler', '-no-stdlib', '-no-reflect', '-jvm-target', '17', '-classpath', cp, '-d', str(classes), *map(str, sources + tests)])
        run('tests', [str(java), f'-Djava.io.tmpdir={scratch}', f'-Dplex.test.root={scratch}', '-cp', str(classes) + os.pathsep + cp, 'org.junit.runner.JUnitCore', 'io.github.fishyau.androidpatches.plex.HermesBytecodeTest', 'io.github.fishyau.androidpatches.plex.PremiumUnlockPatchTest'])
        if any(sha(path) != hashes[str(path)] for path in inputs):
            raise RuntimeError('inputs changed during the check')
        report['status'] = 'plex_compiled_synthetic_tests_passed'
    finally:
        (out / 'check.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
