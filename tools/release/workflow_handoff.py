#!/usr/bin/env python3
"""Manual Actions entrypoint. Inputs are data, never interpolated shell code.

Prepare is a real server-origin/archive/package/source check with read-only
credentials. Publish repeats all checks from the SAME frozen candidate and
requires actual protected environment APIs and review attestation. No executable
is ever taken from an artifact. Local staging uses a NEW external temp directory.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


p = load('publisher_handoff', 'publisher.py')
r = p.r


def validate_handoff(inputs, source_commit, target_repository):
    r.require(isinstance(inputs, dict) and inputs.get('mode') in {'prepare', 'publish'}, 'explicit mode required')
    binding = dict(inputs)
    binding.pop('mode')
    p.dispatch(binding)
    r.require(binding['source_commit'] == source_commit, 'dispatch must bind actual workflow source commit')
    r.require(binding['target'] == target_repository, 'dispatch must bind actual target repository')
    return binding


def main():
    try:
        inputs = json.loads(os.environ.get('HANDOFF', ''), object_pairs_hook=r.unique_pairs)
        binding = validate_handoff(inputs, os.environ.get('GITHUB_SHA'), os.environ.get('GITHUB_REPOSITORY'))
        r.require(os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('GITHUB_EVENT_NAME') == 'workflow_dispatch' and os.environ.get('GITHUB_REF') == 'refs/heads/main', 'trusted manual main Actions context required')
        mode = inputs['mode']
        r.require(os.environ.get('GITHUB_JOB') == ('publish' if mode == 'publish' else 'prepare'), 'mode/job identity mismatch')
        transport = load('handoff_transport', 'github_transport.py').GitHubTransport('GITHUB_TOKEN', writable=mode == 'publish')
        source = Path(os.environ['GITHUB_WORKSPACE'])
        # Ensure exact checkout before downloading. No Git mutation/rebuild.
        _, paths = r.source_tree(source)
        r.clean_revision(source, binding['source_commit'], paths)
        remote = transport.verify_immutable_candidate(binding)
        runner_temp = Path(os.environ['RUNNER_TEMP']).resolve()
        r.require(runner_temp.is_dir() and not runner_temp.is_relative_to(source.resolve()), 'external runner temp required')
        with tempfile.TemporaryDirectory(prefix='approved-candidate-', dir=runner_temp) as scratch:
            for name, data in remote.items():
                with (Path(scratch) / name).open('xb') as out:
                    out.write(data)
            result = p.publish(scratch, source, binding, transport, mode=mode)
        print(json.dumps(result, sort_keys=True))
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f'Handoff blocked: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())
