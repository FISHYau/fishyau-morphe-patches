"""Check publication boundary and pinned scaffold without executing Gradle/app code.

This is a file-policy check, NOT a license, secret, proprietary-content or patch
correctness proof. Human source/content review is still required.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat

WRAPPER_SHA256 = '3b8a25775a69158b5ad2b1d17a80a88dc7b40a352a73eb27d06c612a7ce68e98'
DISTRIBUTION_SHA256 = '21bd5da2de49b642904077f38c0efdc7778e92b3ed0889392dca61b97e389607'
FORBIDDEN_DIRS = {'.android-morphe', '.android', '.gradle', '.cache', '__pycache__', 'build', 'extracted', 'inputs', 'evidence', 'labs', 'output', 'outputs', 'downloads', 'node_modules'}
FORBIDDEN_SUFFIXES = {'.apk', '.apkm', '.apks', '.aab', '.dex', '.mpp', '.mpe', '.so', '.dll', '.exe', '.zip', '.7z', '.jks', '.keystore', '.p12', '.pem', '.pyc', '.class'}


def check(root: Path) -> dict:
    if (root.is_symlink() or not root.is_dir()
            or getattr(root.lstat(), 'st_file_attributes', 0) & 0x400):
        raise ValueError('source root must be an existing real directory')
    root = root.resolve()
    count = 0
    def inaccessible(error):
        raise ValueError('publication tree could not be fully enumerated') from error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=inaccessible):
        relative_parent = Path(parent).relative_to(root)
        for name in dirs + files:
            path = Path(parent) / name
            mode = path.lstat()
            if stat.S_ISLNK(mode.st_mode) or getattr(mode, 'st_file_attributes', 0) & 0x400:
                raise ValueError('links/reparse points are forbidden in publication tree')
            lowered = name.casefold()
            if lowered == '.git':
                if relative_parent != Path('.') or name != '.git':
                    raise ValueError('nested or noncanonical Git metadata is forbidden')
                if name in dirs:
                    dirs.remove(name)
                continue
            if lowered in FORBIDDEN_DIRS:
                raise ValueError('generated/private directory in publication tree: ' + name)
            if lowered == 'local.properties' or lowered.startswith('.env'):
                raise ValueError('local configuration is forbidden')
        for name in files:
            path = Path(parent) / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError('special files are forbidden')
            relative = path.relative_to(root).as_posix()
            if name == '.git':
                continue
            if path.suffix.lower() in FORBIDDEN_SUFFIXES:
                raise ValueError('private/binary artifact is forbidden: ' + relative)
            if path.suffix.lower() == '.jar' and relative != 'gradle/wrapper/gradle-wrapper.jar':
                raise ValueError('only the reviewed Gradle wrapper JAR is allowed')
            count += 1
    wrapper = root / 'gradle/wrapper/gradle-wrapper.jar'
    if hashlib.sha256(wrapper.read_bytes()).hexdigest() != WRAPPER_SHA256:
        raise ValueError('Gradle wrapper JAR differs from pinned template reference')
    properties = (root / 'gradle/wrapper/gradle-wrapper.properties').read_text(encoding='utf-8')
    pins = {}
    for line in properties.splitlines():
        if not line.strip() or line.lstrip().startswith(('#', '!')):
            continue
        key, separator, value = line.partition('=')
        if key in ('distributionUrl', 'distributionSha256Sum'):
            if not separator or key in pins:
                raise ValueError('duplicate or invalid Gradle distribution pin')
            pins[key] = value
    if pins != {
        'distributionUrl': r'https\://services.gradle.org/distributions/gradle-9.8.2-bin.zip',
        'distributionSha256Sum': DISTRIBUTION_SHA256,
    }:
        raise ValueError('Gradle distribution pin mismatch')
    build = (root / 'patches/build.gradle.kts').read_text(encoding='utf-8')
    if 'name = "FISHYau android patches"' not in build or 'author = "FISHYau"' not in build:
        raise ValueError('collection identity mismatch')
    for name in ('LICENSE', 'NOTICE', 'README.md', 'CONTRIBUTING.md'):
        if not (root / name).is_file():
            raise ValueError('required publication document missing: ' + name)
    return {'status': 'scaffold_file_policy_passed', 'files': count,
            'wrapper_sha256': WRAPPER_SHA256,
            'note': 'No build, runtime, content-review or release approval is implied.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    try:
        print(json.dumps(check(args.source)))
    except (ValueError, OSError) as exc:
        parser.exit(1, str(exc) + '\n')


if __name__ == '__main__':
    main()
