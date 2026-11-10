"""Disposable signing context for the self-authored smoke fixture ONLY.

The main smoke process creates a new key; no existing keystore is read. A random
password exists only in this process environment for the context's lifetime.
Only its variable NAME reaches keytool/apksigner argv. Neither the password nor
private key bytes are written to evidence, printed, or returned to an agent.
This is not key management for real applications or a publication identity.
"""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import sys

HERE = Path(__file__).resolve().parent


def _driver():
    name = '_fixture_signing_driver'
    spec = importlib.util.spec_from_file_location(name, HERE / 'driver.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@contextmanager
def fixture_key(java_home: Path, out: Path):
    """Yield public signing configuration, never a password or key contents."""
    driver = _driver()
    out = driver.external_output(Path(out))
    java_home = Path(java_home).resolve(strict=True)
    keytool = java_home / 'bin' / ('keytool.exe' if os.name == 'nt' else 'keytool')
    if not keytool.is_file():
        raise driver.DriverError('explicit JDK keytool is required')
    out.mkdir(parents=True, exist_ok=False)
    keystore, certificate = out / 'fixture-only.p12', out / 'fixture-certificate.der'
    variable = 'FISHY_FIXTURE_KS_' + secrets.token_hex(12).upper()
    os.environ[variable] = secrets.token_urlsafe(48)
    try:
        driver.run_tool([str(keytool), '-genkeypair', '-noprompt', '-storetype', 'PKCS12',
                         '-keystore', str(keystore), '-storepass:env', variable,
                         '-keypass:env', variable, '-alias', 'fixture', '-keyalg', 'RSA',
                         '-keysize', '2048', '-validity', '2',
                         '-dname', 'CN=Disposable self-authored fixture only'], timeout=60)
        driver.run_tool([str(keytool), '-exportcert', '-keystore', str(keystore),
                         '-storepass:env', variable, '-alias', 'fixture',
                         '-file', str(certificate)], timeout=30)
        if not keystore.is_file() or not 1 <= certificate.stat().st_size <= 16384:
            raise driver.DriverError('fixture key/certificate generation incomplete')
        digest = hashlib.sha256(certificate.read_bytes()).hexdigest()
        public = {'keystore': str(keystore), 'certificate': str(certificate),
                  'certificate_sha256': digest, 'key_alias': 'fixture',
                  'ks_pass_env': variable, 'fixture_only': True,
                  'password_retention': 'process_environment_only_until_context_exit'}
        with (out / 'public-signing.json').open('x', encoding='utf-8') as stream:
            json.dump(public, stream, indent=2)
            stream.write('\n')
        yield public
    finally:
        os.environ.pop(variable, None)
