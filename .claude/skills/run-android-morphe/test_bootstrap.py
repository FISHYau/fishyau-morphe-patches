"""Offline bootstrap tests: py -I -B <absolute path to test_bootstrap.py>.

No real downloads, extraction, SDK tools, or device operations. Expected failures
are regression checks for confirmed path/namespace defects, not skipped tests.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import xml.etree.ElementTree as ET


# Also suppress bytecode when this file is invoked without -B.
sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "tested_android_bootstrap", Path(__file__).with_name("bootstrap.py"))
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)

PAYLOAD = b"offline archive fixture\x00\xff"
LICENSE = "  Fixture license & terms.\n  "
GENERIC_V2 = "http://schemas.android.com/repository/android/generic/02"
COMMON_V2 = "http://schemas.android.com/repository/android/common/02"


def record(package="platform-tools", algorithm="sha256", **changes):
    result = {
        "package": package,
        "url": "https://dl.google.com/android/repository/fixture.zip",
        "size": len(PAYLOAD),
        "checksum_type": algorithm,
        "checksum": hashlib.new(algorithm, PAYLOAD).hexdigest(),
        "license": "fixture-license",
        "revision": {"major": "1", "minor": "2"},
    }
    result.update(changes)
    return result


def repository(records=(), license_id="fixture-license", repo_prefix=False):
    """Small namespaced SDK repository with unqualified package child elements."""
    root = ET.Element("sdk:sdk-repository", {
        "xmlns:sdk": "http://schemas.android.com/sdk/android/repo/repository2/03",
        "xmlns:generic": "http://schemas.android.com/repository/android/generic/01",
        "xmlns:xsi": "http://www.w3.org/2001/XMLSchema-instance",
    })
    if repo_prefix:
        root.set("xmlns:repo", COMMON_V2)
    ET.SubElement(root, "license", {"id": license_id}).text = LICENSE
    for item in records:
        remote = ET.SubElement(root, "remotePackage", {"path": item["package"]})
        ET.SubElement(remote, "type-details", {"xsi:type": "generic:genericDetails"})
        revision = ET.SubElement(remote, "revision")
        for key, value in item["revision"].items():
            ET.SubElement(revision, key).text = value
        ET.SubElement(remote, "display-name").text = "Fixture tools"
        ET.SubElement(remote, "uses-license", {"ref": item["license"]})
        ET.SubElement(remote, "channelRef", {"ref": "channel-0"})
        archives = ET.SubElement(remote, "archives")
        for variant in item.get("variants", [{}]):
            archive = ET.SubElement(archives, "archive")
            if variant.get("host"):
                ET.SubElement(archive, "host-os").text = variant["host"]
            if variant.get("incomplete"):
                continue
            complete = ET.SubElement(archive, "complete")
            ET.SubElement(complete, "size").text = str(variant.get("size", item["size"]))
            attrs = {} if variant.get("default_sha1") else {"type": item["checksum_type"]}
            ET.SubElement(complete, "checksum", attrs).text = " \n" + item["checksum"] + " \n"
            ET.SubElement(complete, "url").text = variant.get("url", "fixture.zip")
    return ET.tostring(root, encoding="utf-8")


class BootstrapCase(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="bootstrap-offline-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.network = mock.patch.object(
            bootstrap.urllib.request, "urlopen",
            side_effect=AssertionError("Real network access is forbidden"))
        self.network_mock = self.network.start()
        self.addCleanup(self.network.stop)
        host = mock.patch.object(bootstrap.platform, "system", return_value="Windows")
        host.start()
        self.addCleanup(host.stop)
        output = contextlib.redirect_stdout(io.StringIO())
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def catalog_file(self, records=None, **changes):
        folder = self.root / "catalog"
        folder.mkdir(exist_ok=True)
        data = {"host": "windows", "packages": [record()] if records is None else records,
                "licenses": {"fixture-license": LICENSE}}
        data.update(changes)
        path = folder / "catalog.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def cached_archive(self, catalog, item, content=PAYLOAD):
        directory = catalog.parent / ("download-" + item["checksum"])
        directory.mkdir()
        path = directory / "package.zip"
        path.write_bytes(content)
        return path

    def metadata_fixture(self, records=None, **repository_options):
        records = [record()] if records is None else records
        catalog = self.catalog_file(records)
        (catalog.parent / "repository2-1.xml").write_bytes(
            repository(records, **repository_options))
        (catalog.parent / "sys-img2-3.xml").write_bytes(repository())
        sdk = self.root / "SDK fixture"
        sdk.mkdir()
        (sdk / "bootstrap-evidence.json").write_text(json.dumps(records), encoding="utf-8")
        for item in records:
            sdk.joinpath(*item["package"].split(";")).mkdir(parents=True, exist_ok=True)
        return catalog, sdk

    @contextlib.contextmanager
    def fake_driver(self, layout="directory"):
        """Intercept dynamic loading so no driver, archive code, or tools execute."""
        def extract(_archive, destination):
            destination.mkdir()
            if layout == "directory":
                (destination / "payload").mkdir()
                (destination / "payload" / "source.properties").write_text("fixture", encoding="utf-8")
            elif layout == "file":
                (destination / "not-a-directory").write_bytes(b"fixture")
            elif layout == "two":
                (destination / "one").mkdir()
                (destination / "two").mkdir()

        driver = types.SimpleNamespace(extract_archive=mock.Mock(side_effect=extract))
        loader = mock.Mock()
        spec = types.SimpleNamespace(name="android_morphe_driver", loader=loader)
        with mock.patch.dict(sys.modules), \
                mock.patch.object(bootstrap.importlib.util, "spec_from_file_location", return_value=spec), \
                mock.patch.object(bootstrap.importlib.util, "module_from_spec", return_value=driver):
            yield driver
            loader.exec_module.assert_called_once_with(driver)

    def install_record(self, **changes):
        # The archive and extracted files live only in this fresh temporary area.
        folder = self.root / "download-fixture"
        folder.mkdir(exist_ok=True)
        archive = folder / "package.zip"
        archive.write_bytes(PAYLOAD)
        return record(archive=str(archive), sha256=hashlib.sha256(PAYLOAD).hexdigest(), **changes)


class CatalogTests(BootstrapCase):
    def test_selects_host_preserves_order_checksums_revisions_and_used_licenses(self):
        tools = record(algorithm="sha1")
        tools["variants"] = [{"host": "linux"}, {"host": "windows", "incomplete": True},
                             {"host": "windows", "default_sha1": True}]
        image = record("system-images;android-30;google_apis;x86_64")
        image["variants"] = [{"url": "https://dl.google.com/android/repository/image.zip"}]
        out = self.root / "new-catalog"
        documents = [repository([tools]), repository([image])]
        with mock.patch.object(bootstrap, "get", side_effect=[io.BytesIO(x) for x in documents]) as get:
            bootstrap.catalog(out, [image["package"], tools["package"]])
        data = json.loads((out / "catalog.json").read_text(encoding="utf-8"))
        self.assertEqual(data["host"], "windows")
        self.assertEqual([x["package"] for x in data["packages"]], [image["package"], tools["package"]])
        for actual, original in zip(data["packages"], [image, tools]):
            self.assertEqual(actual["checksum"], original["checksum"])
            self.assertEqual(actual["checksum_type"], original["checksum_type"])
            self.assertEqual(actual["revision"], original["revision"])
            self.assertEqual(actual["size"], original["size"])
        self.assertEqual(data["packages"][0]["url"], image["variants"][0]["url"])
        self.assertEqual(data["packages"][1]["url"], tools["url"])
        self.assertEqual(data["licenses"], {"fixture-license": LICENSE})
        self.assertEqual((out / "fixture-license.txt").read_text(encoding="utf-8"), LICENSE)
        for url, document in zip(bootstrap.REPOSITORIES, documents):
            self.assertEqual((out / url.rsplit("/", 1)[-1]).read_bytes(), document)
        self.assertEqual(get.call_args_list, [mock.call(url) for url in bootstrap.REPOSITORIES])

    def test_missing_or_nonhost_package_does_not_publish_catalog(self):
        tools = record()
        tools["variants"] = [{"host": "linux"}]
        out = self.root / "catalog"
        with mock.patch.object(bootstrap, "get", side_effect=[io.BytesIO(repository([tools])), io.BytesIO(repository())]):
            with self.assertRaisesRegex(ValueError, "No matching official host archive"):
                bootstrap.catalog(out, [tools["package"]])
        self.assertFalse((out / "catalog.json").exists())

    def test_existing_output_is_not_overwritten(self):
        out = self.root / "existing"
        out.mkdir()
        marker = out / "keep.txt"
        marker.write_text("unchanged", encoding="utf-8")
        with mock.patch.object(bootstrap, "get") as get:
            with self.assertRaises(FileExistsError):
                bootstrap.catalog(out, ["platform-tools"])
        get.assert_not_called()
        self.assertEqual(marker.read_text(encoding="utf-8"), "unchanged")

    def test_repository_size_cap(self):
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * (20 * 1024 * 1024 + 1)
        out = self.root / "catalog"
        with mock.patch.object(bootstrap, "get", return_value=response):
            with self.assertRaisesRegex(ValueError, "Repository metadata too large"):
                bootstrap.catalog(out, ["platform-tools"])
        response.read.assert_called_once_with(20 * 1024 * 1024 + 1)
        self.assertEqual(list(out.iterdir()), [])

    def test_catalog_license_filename_cannot_escape_output(self):
        tools = record(license="../escaped-license")
        documents = [repository([tools], license_id=tools["license"]), repository()]
        with mock.patch.object(bootstrap, "get", side_effect=[io.BytesIO(x) for x in documents]):
            try:
                bootstrap.catalog(self.root / "catalog", [tools["package"]])
            except ValueError:
                pass
        self.assertFalse((self.root / "escaped-license.txt").exists(),
                         "Catalog license identifier wrote outside its output directory")


class DownloadTests(BootstrapCase):
    def test_url_guard_rejects_nonofficial_sources_before_opening(self):
        for url in ("http://dl.google.com/android/repository/a.zip", "https://example.invalid/a.zip",
                    "https://dl.google.com.evil.invalid/android/repository/a.zip",
                    "file:///fixture.zip"):
            with self.subTest(url=url), self.assertRaisesRegex(ValueError, "Only official"):
                bootstrap.get(url)
        self.network_mock.assert_not_called()

    def test_url_guard_opens_official_source_with_timeout(self):
        response = object()
        self.network_mock.side_effect = None
        self.network_mock.return_value = response
        url = record()["url"]
        self.assertIs(bootstrap.get(url), response)
        self.network_mock.assert_called_once_with(url, timeout=120)

    def test_download_validates_sha1_sha256_and_records_independent_sha256(self):
        for algorithm in ("sha1", "sha256"):
            with self.subTest(algorithm=algorithm):
                item = record(algorithm=algorithm)
                item["checksum"] = item["checksum"].upper()
                catalog = self.catalog_file([item])
                with mock.patch.object(bootstrap, "get", return_value=io.BytesIO(PAYLOAD)) as get:
                    records = bootstrap.fetch_archives(catalog)
                get.assert_called_once_with(item["url"])
                self.assertEqual(records[0]["sha256"], hashlib.sha256(PAYLOAD).hexdigest())
                self.assertEqual(Path(records[0]["archive"]).read_bytes(), PAYLOAD)
                self.assertEqual(records[0]["checksum"], item["checksum"])
                self.assertEqual(json.loads((catalog.parent / "downloads.json").read_text(encoding="utf-8")), records)

    def test_cached_archive_is_revalidated_without_network(self):
        item = record()
        catalog = self.catalog_file([item])
        archive = self.cached_archive(catalog, item)
        with mock.patch.object(bootstrap, "get") as get:
            result = bootstrap.fetch_archives(catalog)
        get.assert_not_called()
        self.assertEqual(result[0]["archive"], str(archive))

    def test_corrupt_or_wrong_size_cache_is_rejected_without_network(self):
        item = record()
        catalog = self.catalog_file([item])
        archive = self.cached_archive(catalog, item)
        for content in (b"!" * len(PAYLOAD), PAYLOAD[:-1], PAYLOAD + b"!"):
            with self.subTest(size=len(content)):
                archive.write_bytes(content)
                with mock.patch.object(bootstrap, "get") as get:
                    with self.assertRaisesRegex(ValueError, "Official checksum/size mismatch"):
                        bootstrap.fetch_archives(catalog)
                get.assert_not_called()
                self.assertFalse((catalog.parent / "downloads.json").exists())

    def test_short_or_same_size_corrupt_download_is_rejected(self):
        item = record()
        catalog = self.catalog_file([item])
        directory = catalog.parent / ("download-" + item["checksum"])
        for content in (PAYLOAD[:-1], b"!" * len(PAYLOAD)):
            with self.subTest(content=content):
                with mock.patch.object(bootstrap, "get", return_value=io.BytesIO(content)):
                    with self.assertRaisesRegex(ValueError, "Official checksum/size mismatch"):
                        bootstrap.fetch_archives(catalog)
                self.assertFalse((catalog.parent / "downloads.json").exists())
                (directory / "package.zip").unlink()
                directory.rmdir()

    def test_oversized_stream_stops_before_writing_excess_block(self):
        item = record()
        catalog = self.catalog_file([item])
        source = mock.MagicMock()
        source.__enter__.return_value = source
        source.read.side_effect = [PAYLOAD, b"excess", AssertionError("Read after overflow")]
        with mock.patch.object(bootstrap, "get", return_value=source):
            with self.assertRaisesRegex(ValueError, "exceeds official declared size"):
                bootstrap.fetch_archives(catalog)
        archive = catalog.parent / ("download-" + item["checksum"]) / "package.zip"
        self.assertEqual(archive.read_bytes(), PAYLOAD)
        self.assertEqual(source.read.call_count, 2)
        self.assertFalse((catalog.parent / "downloads.json").exists())

    def test_invalid_size_or_algorithm_rejected_before_io(self):
        for changes in ({"size": 0}, {"size": -1}, {"size": 5 * 1024**3 + 1},
                        {"checksum_type": "md5"}, {"checksum_type": "SHA256"}):
            with self.subTest(changes=changes):
                catalog = self.catalog_file([record(**changes)])
                with mock.patch.object(bootstrap, "get") as get:
                    with self.assertRaisesRegex(ValueError, "Invalid archive size/checksum"):
                        bootstrap.fetch_archives(catalog)
                get.assert_not_called()
                self.assertEqual(list(catalog.parent.iterdir()), [catalog])


class LicenseAndInstallTests(BootstrapCase):
    def test_install_requires_approval_before_reading_catalog_or_creating_sdk(self):
        sdk = self.root / "SDK"
        with mock.patch.object(bootstrap, "fetch_archives") as fetch, \
                mock.patch.object(bootstrap.importlib.util, "spec_from_file_location") as load:
            with self.assertRaisesRegex(ValueError, "obtain human approval"):
                bootstrap.install(self.root / "does-not-exist.json", sdk, False)
        fetch.assert_not_called()
        load.assert_not_called()
        self.assertFalse(sdk.exists())

    def test_fetch_cli_requires_explicit_approval(self):
        for accepted in (False, True):
            with self.subTest(accepted=accepted):
                catalog = self.root / "does-not-exist.json"
                argv = ["bootstrap.py", "fetch", "--catalog", str(catalog)]
                if accepted:
                    argv.append("--accept-licenses")
                with mock.patch.object(sys, "argv", argv), mock.patch.object(bootstrap, "fetch_archives") as fetch:
                    if accepted:
                        bootstrap.main()
                        fetch.assert_called_once_with(catalog.resolve())
                    else:
                        with self.assertRaisesRegex(ValueError, "Human license approval required"):
                            bootstrap.main()
                        fetch.assert_not_called()

    def test_host_mismatch_fails_before_sdk_creation_or_download(self):
        catalog = self.catalog_file(host="linux")
        sdk = self.root / "SDK"
        with mock.patch.object(bootstrap, "fetch_archives") as fetch:
            with self.assertRaisesRegex(ValueError, "Catalog host mismatch"):
                bootstrap.install(catalog, sdk, True)
        fetch.assert_not_called()
        self.assertFalse(sdk.exists())

    def test_existing_sdk_is_not_modified(self):
        catalog = self.catalog_file()
        sdk = self.root / "SDK"
        sdk.mkdir()
        marker = sdk / "keep.txt"
        marker.write_bytes(b"unchanged")
        with mock.patch.object(bootstrap, "fetch_archives") as fetch:
            with self.assertRaises(FileExistsError):
                bootstrap.install(catalog, sdk, True)
        fetch.assert_not_called()
        self.assertEqual(marker.read_bytes(), b"unchanged")
        self.assertEqual(list(sdk.iterdir()), [marker])

    def test_unsafe_package_paths_are_rejected_before_extraction(self):
        for index, name in enumerate(("", "..", ".", "..;escaped", "tools;;bin", ";tools",
                                      "tools;", "C:;tools", "/absolute", "tools/escape",
                                      "tools\\escape", "tools;bad name")):
            with self.subTest(package=name):
                item = self.install_record(package=name)
                catalog = self.catalog_file([item])
                with self.fake_driver() as driver, mock.patch.object(bootstrap, "fetch_archives", return_value=[item]):
                    with self.assertRaisesRegex(ValueError, "Unsafe SDK package path"):
                        bootstrap.install(catalog, self.root / ("SDK-" + str(index)), True)
                    driver.extract_archive.assert_not_called()

    def test_invalid_archive_root_layout_is_rejected(self):
        item = self.install_record()
        catalog = self.catalog_file([item])
        for layout in ("empty", "file", "two"):
            with self.subTest(layout=layout):
                sdk = self.root / ("SDK-" + layout)
                with self.fake_driver(layout), mock.patch.object(bootstrap, "fetch_archives", return_value=[item]):
                    with self.assertRaisesRegex(ValueError, "Unexpected SDK archive root layout"):
                        bootstrap.install(catalog, sdk, True)
                self.assertFalse((sdk / "platform-tools").exists())
                self.assertFalse((sdk / "bootstrap-evidence.json").exists())

    def test_install_copies_payload_hashes_license_and_registers_evidence(self):
        item = self.install_record(package="build-tools;36.0.0")
        catalog = self.catalog_file([item])
        sdk = self.root / "SDK with spaces"
        with self.fake_driver() as driver, \
                mock.patch.object(bootstrap, "fetch_archives", return_value=[item]), \
                mock.patch.object(bootstrap, "register_packages") as register:
            bootstrap.install(catalog, sdk, True)
            driver.extract_archive.assert_called_once()
            register.assert_called_once_with(catalog, sdk)
        destination = sdk / "build-tools" / "36.0.0"
        self.assertEqual((destination / "source.properties").read_text(encoding="utf-8"), "fixture")
        evidence = json.loads((sdk / "bootstrap-evidence.json").read_text(encoding="utf-8"))
        self.assertEqual(evidence, [{**item, "installed": str(destination)}])
        self.assertEqual((sdk / "licenses" / "fixture-license").read_text(encoding="ascii"),
                         hashlib.sha1(LICENSE.strip().encode()).hexdigest() + "\n")

    def test_license_identifier_cannot_escape_license_directory(self):
        catalog = self.catalog_file([], licenses={"../escaped": LICENSE})
        sdk = self.root / "SDK"
        with self.fake_driver(), mock.patch.object(bootstrap, "fetch_archives", return_value=[]), \
                mock.patch.object(bootstrap, "register_packages") as register:
            with self.assertRaisesRegex(ValueError, "Unsafe license identifier"):
                bootstrap.install(catalog, sdk, True)
            register.assert_not_called()
        self.assertFalse((sdk / "escaped").exists())
        self.assertFalse((sdk / "bootstrap-evidence.json").exists())


class RegistrationTests(BootstrapCase):
    def test_register_writes_local_metadata_with_license_and_normalized_namespace(self):
        item = record("build-tools;36.0.0")
        catalog, sdk = self.metadata_fixture([item])
        bootstrap.register_packages(catalog, sdk)
        path = sdk / "build-tools" / "36.0.0" / "package.xml"
        root = ET.parse(path).getroot()
        self.assertEqual(root.tag, "{" + COMMON_V2 + "}repository")
        self.assertEqual(root.find("license").attrib, {"id": "fixture-license", "type": "text"})
        self.assertEqual(root.findtext("license"), LICENSE)
        local = root.find("localPackage")
        self.assertEqual(local.attrib, {"path": item["package"], "obsolete": "false"})
        self.assertEqual(local.findtext("revision/major"), "1")
        self.assertEqual(local.findtext("display-name"), "Fixture tools")
        self.assertEqual(local.find("uses-license").get("ref"), "fixture-license")
        self.assertIsNone(local.find("archives"))
        self.assertIsNone(local.find("channelRef"))
        namespaces = dict(value for _, value in ET.iterparse(path, events=("start-ns",)))
        self.assertEqual(namespaces["generic"], GENERIC_V2)
        self.assertEqual(local.find("type-details").get("{http://www.w3.org/2001/XMLSchema-instance}type"),
                         "generic:genericDetails")
        # Registration must not mutate saved remote metadata.
        remote = ET.parse(catalog.parent / "repository2-1.xml").getroot().find("remotePackage")
        self.assertIsNotNone(remote.find("archives"))
        self.assertIsNotNone(remote.find("channelRef"))

    def test_register_finds_metadata_in_system_image_repository(self):
        item = record("system-images;android-30;google_apis;x86_64")
        catalog, sdk = self.metadata_fixture([item])
        (catalog.parent / "repository2-1.xml").write_bytes(repository())
        (catalog.parent / "sys-img2-3.xml").write_bytes(repository([item]))
        bootstrap.register_packages(catalog, sdk)
        self.assertEqual(ET.parse(sdk.joinpath(*item["package"].split(";")) / "package.xml")
                         .getroot().find("localPackage").get("path"), item["package"])

    def test_missing_mismatched_or_ambiguous_metadata_rejected_before_write(self):
        for mode in ("missing", "checksum", "duplicate"):
            with self.subTest(mode=mode):
                # A separate fixture per subtest avoids sharing stale package.xml files.
                with tempfile.TemporaryDirectory(dir=self.root) as folder:
                    old_root = self.root
                    self.root = Path(folder)
                    try:
                        catalog, sdk = self.metadata_fixture()
                        if mode == "missing":
                            (catalog.parent / "repository2-1.xml").write_bytes(repository())
                        elif mode == "checksum":
                            (catalog.parent / "repository2-1.xml").write_bytes(repository([record(checksum="0" * 64)]))
                        else:
                            (catalog.parent / "sys-img2-3.xml").write_bytes(repository([record()]))
                        with self.assertRaisesRegex(ValueError, "Ambiguous official metadata"):
                            bootstrap.register_packages(catalog, sdk)
                        self.assertFalse((sdk / "platform-tools" / "package.xml").exists())
                    finally:
                        self.root = old_root

    def test_register_rejects_package_path_traversal_from_evidence(self):
        item = record(package="..;escaped-package")
        catalog, sdk = self.metadata_fixture([item])
        # The helper creates only temporary directories, including this sibling.
        outside = self.root / "escaped-package" / "package.xml"
        try:
            bootstrap.register_packages(catalog, sdk)
        except ValueError:
            pass
        self.assertFalse(outside.exists(), "Registration wrote metadata outside the SDK")

    def test_register_preserves_valid_xml_when_repo_prefix_already_declared(self):
        catalog, sdk = self.metadata_fixture(repo_prefix=True)
        bootstrap.register_packages(catalog, sdk)
        # A valid source declaring xmlns:repo must not produce duplicate attributes.
        root = ET.parse(sdk / "platform-tools" / "package.xml").getroot()
        self.assertEqual(root.tag, "{" + COMMON_V2 + "}repository")


class PublicationBoundaryTests(BootstrapCase):
    def test_all_output_entry_points_refuse_publication_tree_before_io(self):
        path = bootstrap.TRUSTED.parents[2] / 'forbidden-output'
        for invoke in (lambda: bootstrap.catalog(path, ['platform-tools']),
                       lambda: bootstrap.fetch_archives(path / 'catalog.json'),
                       lambda: bootstrap.register_packages(self.root / 'catalog.json', path),
                       lambda: bootstrap.install(self.root / 'catalog.json', path, True)):
            with self.subTest(invoke=invoke), self.assertRaisesRegex(ValueError, 'outside'):
                invoke()
        self.network_mock.assert_not_called()
        self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
