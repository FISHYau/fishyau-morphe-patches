"""Synthetic public-format fixtures, not actual load/runtime/signature tests."""
import copy
import importlib.util
import io
import json
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("bundle_formats_under_test", ROOT / "tools/bundle_formats.py")
f = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f)
WHEN = "2026-11-09T10:00:00"


def catalog_fixture(version="0.2.7-test.1"):
    termius = {"packageName": "com.server.auditor.ssh.client", "name": "Server Auditor",
               "description": None, "apkFileType": "APKM", "appIconColor": None,
               "signatures": None, "formFactor": None, "targets": [
                   {"version": "8.0.1", "versionCodes": {"ARM64_V8A": 1008},
                    "isExperimental": False, "minSdk": None, "description": None}]}
    plex = dict(termius, packageName="com.plexapp.android", name="Plex", targets=[])
    return {"version": version, "patches": [
        {"name": name, "description": "Synthetic format fixture only", "default": True,
         "category": None, "compatiblePackages": [copy.deepcopy(plex if name == "Premium unlock" else termius)],
         "options": []} for name in f.COLLECTION_PATCHES]}


def bundle_fixture(version="0.2.7-test.1", *, extra=(), dex=b"dex\n039\0SYNTHETIC INVALID DEX BODY", manifest=None):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("META-INF/MANIFEST.MF", manifest if manifest is not None else
                         "Manifest-Version: 1.0\r\nName: FISHYau android patches\r\nAuthor: FISHYau\r\n"
                         f"Version: {version}\r\nPatcher-Version: 2.3.0\r\n\r\n")
        if dex is not None:
            archive.writestr("classes.dex", dex)
        for name, data in extra:
            archive.writestr(name, data)
    return output.getvalue()


class FormatTests(unittest.TestCase):
    def manifest(self, version="0.2.7-test.1"):
        return f.make_manifest({"owner": "fixture-owner", "repository": "fixture-repository",
                                "version": version, "created_at": WHEN, "description": "Synthetic only"})

    def test_source_normalization_preserved_cases(self):
        valid = [
            ("https://github.com/fixture-owner/fixture-repository", "https://raw.githubusercontent.com/fixture-owner/fixture-repository/main/patches-bundle.json"),
            ("https://github.com/fixture-owner/fixture-repository/", "https://raw.githubusercontent.com/fixture-owner/fixture-repository/main/patches-bundle.json"),
            ("https://example.invalid/source/patches-bundle.json", "https://example.invalid/source/patches-bundle.json"),
        ]
        invalid = [
            "http://github.com/fixture-owner/fixture-repository",
            "https://github.com/fixture-owner",
            "https://github.com/fixture-owner/fixture-repository/tree/main",
            "https://example.invalid/source/patches-bundle.txt",
            "https://example.invalid/source/patches-bundle.json?token=synthetic",
            "https://example.invalid/source/../patches-bundle.json",
            "https://fixture@example.invalid/patches-bundle.json",
            "https://example.invalid:443/source.json", "https://example.invalid/source%2ejson",
            "https://example.invalid/source.json#fragment", "https://example.invalid/source\\file.json",
        ]
        for source, expected in valid:
            self.assertEqual(f.normalize_source(source), expected)
        for source in invalid:
            with self.subTest(source=source), self.assertRaises(ValueError):
                f.normalize_source(source)

    def test_manifest_and_versions_not_fixed(self):
        for version in ("0.1.0", "2.4.10", "0.2.7-test.1"):
            value = self.manifest(version)
            f.validate_manifest(value, "fixture-owner", "fixture-repository", version)
            self.assertIn(f"/v{version}/patches-{version}.mpp", value["download_url"])
            self.assertNotIn("public_key", value)
        value = self.manifest()
        f.validate_manifest(dict(value, public_key=None, page_url=None))
        # Parsing the Manager schema may represent a key; the publisher never
        # generates one or purports to authenticate a signed bundle.
        f.validate_manifest(dict(value, public_key="synthetic-schema-only"))
        for key in ("version", "description", "download_url", "created_at"):
            for bad in (None, True, "", "\nsecret"):
                with self.subTest(key=key, bad=bad), self.assertRaises(ValueError):
                    f.validate_manifest(dict(value, **{key: bad}))
        for bad in ("v1.2.3", "--help", "../1.2.3", "1.2.3/asset"):
            with self.assertRaises(ValueError):
                self.manifest(bad)
        with self.assertRaises(ValueError):
            f.validate_manifest(value, "other", "fixture-repository", value["version"])
        with self.assertRaises(ValueError):
            f.make_manifest({})

    def test_local_datetime_calendar_and_precision(self):
        for value in (WHEN, WHEN + ".123456789", "2024-02-29T00:00:00"):
            self.assertEqual(f.local_time(value).tzinfo, f.UTC)
        for value in (WHEN + "Z", WHEN + "+00:00", "2026-02-30T00:00:00", "2026-11-09T24:00:00", WHEN + ".1234567890"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                f.local_time(value)

    def test_bounded_json_and_duplicates(self):
        with tempfile.TemporaryDirectory(prefix="bundle-formats-") as temp:
            path = Path(temp) / "value.json"
            for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'\xff', b'{'):
                path.write_bytes(data)
                with self.assertRaises(ValueError):
                    f.read_json(path)
            data = b'{"a":1}'
            path.write_bytes(data)
            self.assertEqual(f.read_json(path), ({"a": 1}, data))
            with self.assertRaises(ValueError):
                f.read_bytes(path, 2)
            with mock.patch.object(f, "MAX_JSON", 2), self.assertRaises(ValueError):
                f.read_json(path)

    def test_archive_metadata_lowercase_continuations_main_only(self):
        manifest = "Manifest-Version: 1.0\r\nName: FISHYau android\r\n patches\r\nVersion: 2.0.0\r\n\r\nName: spoof\r\nVersion: wrong\r\n"
        value = f.bundle_metadata(bundle_fixture(manifest=manifest))
        self.assertEqual(value["name"], "FISHYau androidpatches")
        self.assertEqual(value["version"], "2.0.0")
        self.assertNotIn("Version", value)

    def test_archive_unsigned_bounded_android_shape(self):
        self.assertEqual(f.bundle_metadata(bundle_fixture())["patcher-version"], "2.3.0")
        cases = [bundle_fixture(dex=None), bundle_fixture(dex=b"not DEX"),
                 b"envelope" + bundle_fixture(), bundle_fixture() + b"signature",
                 bundle_fixture(manifest="Version: 1\nversion: 2\n\n"),
                 bundle_fixture(manifest=" orphan\n\n"),
                 bundle_fixture(manifest="Signature-Version: 1.0\n\n")]
        for data in cases:
            with self.subTest(data=data[:15]), self.assertRaises(ValueError):
                f.bundle_metadata(data)
        for name in ("../unsafe", "CON", "raw.png", "app.apk", "META-INF/SIGNER.RSA", "signature", "signature.sig"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                f.bundle_metadata(bundle_fixture(extra=[(name, b"fixture")]))
        # Windows ZipInfo normalizes backslashes during fixture creation. Put
        # them into the actual local/central names afterward, not just argv.
        backslash = bundle_fixture(extra=[("x/y", b"fixture")]).replace(b"x/y", b"x\\y")
        with self.assertRaises(ValueError):
            f.bundle_metadata(backslash)
        with mock.patch.object(f, "MAX_MEMBER", 8), self.assertRaises(ValueError):
            f.bundle_metadata(bundle_fixture())
        with mock.patch.object(f, "MAX_BUNDLE", 8), self.assertRaises(ValueError):
            f.bundle_metadata(bundle_fixture())
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with self.assertRaises(ValueError):
                f.bundle_metadata(bundle_fixture(extra=[("classes.dex", b"duplicate")]))
        symlink = zipfile.ZipInfo("unsafe-link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        with self.assertRaises(ValueError):
            f.bundle_metadata(bundle_fixture(extra=[(symlink, b"target")]))
        zip64 = zipfile.ZipInfo("unsupported-zip64")
        zip64.extract_version = 45
        with self.assertRaises(ValueError):
            f.bundle_metadata(bundle_fixture(extra=[(zip64, b"fixture")]))
        for name in ("directory//", "CLASSES.DEX"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                f.bundle_metadata(bundle_fixture(extra=[(name, b"fixture")]))
        # Corrupt a stored payload without updating its CRC: every archive
        # member is checked, not only MANIFEST.MF and the DEX magic prefix.
        data = bundle_fixture(extra=[("payload.txt", b"UNIQUE SYNTHETIC PAYLOAD")])
        corrupt = data.replace(b"UNIQUE SYNTHETIC PAYLOAD", b"BROKEN SYNTHETIC PAYLOAD", 1)
        with self.assertRaises(ValueError):
            f.bundle_metadata(corrupt)
        zip64 = zipfile.ZipInfo("unsupported-extra-field")
        zip64.extra = b"\x01\x00\x00\x00"
        with self.assertRaises(ValueError):
            f.bundle_metadata(bundle_fixture(extra=[(zip64, b"fixture")]))
        data = bytearray(bundle_fixture())
        # EOCD disk/total counts must match the actual central inventory.
        data[-14:-12] = b"\x01\x00"
        data[-12:-10] = b"\x01\x00"
        with self.assertRaises(ValueError):
            f.bundle_metadata(bytes(data))

    def test_central_count_is_bounded_before_zipfile_allocation(self):
        mismatch = bytearray(bundle_fixture())
        mismatch[-14:-12] = b"\x01\x00"
        mismatch[-12:-10] = b"\x01\x00"
        oversized = bundle_fixture(extra=[(f"entry-{i}", b"") for i in range(4095)])
        truncated = bytearray(bundle_fixture())
        # Keep the envelope internally sized, but truncate a central header.
        central = truncated.index(b"PK\x01\x02")
        truncated[central + 28:central + 30] = b"\xff\xff"
        zip64_comment = zipfile.ZipInfo("zip64-comment")
        # ZipFile probes a ZIP64 locator immediately before EOCD, even if the
        # bytes belong to the last ordinary central entry's comment.
        zip64_comment.comment = b"PK\x06\x06" + b"\x00" * 52 + b"PK\x06\x07" + b"\x00" * 16
        locator = bundle_fixture(extra=[(zip64_comment, b"")])
        with mock.patch.object(f.zipfile, "ZipFile", side_effect=AssertionError("must preflight before ZipFile")):
            for data in (bytes(mismatch), oversized, bytes(truncated), locator):
                with self.subTest(size=len(data)), self.assertRaises(ValueError):
                    f.bundle_metadata(data)

    def test_collection_exact_defaults_and_compatibility(self):
        catalog = catalog_fixture()
        patches = f.collection_inventory(catalog, catalog["version"])
        self.assertEqual([patch["name"] for patch in patches], sorted(f.COLLECTION_PATCHES))
        self.assertEqual(patches[0]["compatiblePackages"][0]["targets"], [])
        for mutate in (
            lambda c: c.update(version="wrong"),
            lambda c: c["patches"].pop(),
            lambda c: c["patches"][0].update(default=False),
            lambda c: c["patches"][0].update(default=1),
            lambda c: c["patches"][0].update(options=[{}]),
            lambda c: c["patches"][0]["compatiblePackages"][0].update(targets=[]),
            lambda c: c["patches"][0]["compatiblePackages"][0]["targets"][0].update(isExperimental=True),
            lambda c: c["patches"][0]["compatiblePackages"][0]["targets"][0].update(versionCodes={"ARM64_V8A": True}),
            lambda c: c["patches"][2]["compatiblePackages"][0].update(targets=[{}]),
            lambda c: c["patches"][2]["compatiblePackages"][0].update(packageName="wrong.package"),
        ):
            bad = copy.deepcopy(catalog)
            mutate(bad)
            with self.subTest(catalog=bad), self.assertRaises(ValueError):
                f.collection_inventory(bad, catalog["version"])


if __name__ == "__main__":
    unittest.main()
