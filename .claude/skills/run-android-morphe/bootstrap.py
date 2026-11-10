"""Scoped Android SDK provisioning from Google's checksummed repository catalog.

Catalog prints license text; installation requires the human's explicit license approval.
Never invokes downloaded code from the archive's directory. Python: use -I.
"""
import argparse
import hashlib
import html
import copy
import importlib.util
import io
import re
import json
import os
from pathlib import Path
import platform
import shutil
import sys
import urllib.request
import uuid
import xml.etree.ElementTree as ET

REPOSITORIES = (
    "https://dl.google.com/android/repository/repository2-1.xml",
    "https://dl.google.com/android/repository/sys-img/google_apis/sys-img2-3.xml",
)
DEFAULT_PACKAGES = ["platform-tools", "emulator", "cmdline-tools;latest", "platforms;android-36", "build-tools;36.0.0", "system-images;android-30;google_apis;x86_64"]
TRUSTED = Path(__file__).resolve().parent


def external_output(path):
    path = Path(path).resolve()
    if path.is_relative_to(TRUSTED.parents[2]):
        raise ValueError('SDK, downloads and evidence must stay outside the publication repository')
    return path


def license_key(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,127}', value):
        raise ValueError('Unsafe license identifier')
    return value


def package_parts(value):
    parts = value.split(';')
    for part in parts:
        stem = part.split('.')[0].upper()
        if (not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9_.-]{0,127}', part)
                or part.endswith('.') or stem in {'CON', 'PRN', 'AUX', 'NUL'}
                or re.fullmatch(r'(?:COM|LPT)[1-9]', stem)):
            raise ValueError('Unsafe SDK package path')
    return parts


def metadata_xml(data):
    if len(data) > 20 * 1024 * 1024:
        raise ValueError('Repository metadata too large')
    text = data.decode('utf-8-sig')
    if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('Repository XML declarations forbidden')
    return ET.fromstring(text)


def get(url):
    if not url.startswith("https://dl.google.com/android/repository/"):
        raise ValueError("Only official Android repository URLs permitted")
    return urllib.request.urlopen(url, timeout=120)


def catalog(out, packages):
    out = external_output(out)
    out.mkdir(parents=True, exist_ok=False)
    host = {"Windows": "windows", "Linux": "linux", "Darwin": "macosx"}[platform.system()]
    chosen, licenses = {}, {}
    for url in REPOSITORIES:
        with get(url) as response:
            data = response.read(20 * 1024 * 1024 + 1)
        if len(data) > 20 * 1024 * 1024:
            raise ValueError("Repository metadata too large")
        (out / url.rsplit("/", 1)[-1]).write_bytes(data)
        root = metadata_xml(data)
        for license in root.findall("license"):
            licenses[license_key(license.attrib["id"])] = license.text or ""
        for remote in root.findall("remotePackage"):
            key = remote.attrib["path"]
            if key not in packages:
                continue
            for archive in remote.findall("archives/archive"):
                os_tag = archive.findtext("host-os")
                if os_tag and os_tag != host:
                    continue
                complete = archive.find("complete")
                if complete is None:
                    continue
                checksum = complete.find("checksum")
                relative = complete.findtext("url")
                download_url = url.rsplit("/", 1)[0] + "/" + relative
                if relative.startswith("https://"):
                    download_url = relative
                package_parts(key)
                license_ref = remote.find("uses-license")
                chosen[key] = {
                    "package": key, "url": download_url,
                    "size": int(complete.findtext("size")),
                    "checksum_type": checksum.attrib.get("type", "sha1"),
                    "checksum": checksum.text.strip(),
                    "license": license_ref.attrib["ref"] if license_ref is not None else None,
                    "revision": {e.tag: e.text for e in remote.find("revision")},
                }
                break
    missing = set(packages) - chosen.keys()
    if missing:
        raise ValueError("No matching official host archive for: " + ", ".join(sorted(missing)))
    used = {r["license"] for r in chosen.values() if r["license"]}
    result = {"host": host, "packages": [chosen[p] for p in packages], "licenses": {k: licenses[k] for k in used}}
    (out / "catalog.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    for key in sorted(used):
        (out / (key + ".txt")).write_text(licenses[key], encoding="utf-8")
    print(json.dumps({"catalog": str(out / "catalog.json"), "download_bytes": sum(p["size"] for p in result["packages"]), "packages": result["packages"], "license_files": [str(out / (k + ".txt")) for k in sorted(used)]}, indent=2))


def fetch_archives(catalog_path):
    catalog_path = external_output(catalog_path)
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    records = []
    for record in data["packages"]:
        size = record["size"]
        algorithm = record["checksum_type"]
        if (type(size) is not int or not 0 < size <= 5 * 1024**3
                or algorithm not in ("sha1", "sha256")
                or not re.fullmatch(r'[0-9a-fA-F]{' + str(40 if algorithm == 'sha1' else 64) + '}', record['checksum'])):
            raise ValueError("Invalid archive size/checksum")
        package_parts(record['package'])
        download = catalog_path.parent / ("download-" + record["checksum"])
        archive = download / "package.zip"
        if not archive.exists():
            download.mkdir(exist_ok=False)
            print("Downloading " + record["package"], flush=True)
            with get(record["url"]) as source, archive.open("xb") as target:
                count = 0
                while block := source.read(1024 * 1024):
                    count += len(block)
                    if count > size:
                        raise ValueError("Download exceeds official declared size")
                    target.write(block)
        with archive.open("rb") as stream:
            actual = hashlib.file_digest(stream, algorithm).hexdigest()
        if archive.stat().st_size != size or actual.lower() != record["checksum"].lower():
            raise ValueError("Official checksum/size mismatch; inspect failed download " + str(download))
        with archive.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        records.append({**record, "archive": str(archive), "sha256": digest})
    (catalog_path.parent / "downloads.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
    return records


def register_packages(catalog_path, sdk):
    """avdmanager requires local package.xml, not merely ZIP source.properties."""
    sdk = external_output(sdk)
    records = json.loads((sdk / "bootstrap-evidence.json").read_text(encoding="utf-8"))
    metadata = []
    for name in ("repository2-1.xml", "sys-img2-3.xml"):
        source = catalog_path.parent / name
        with source.open('rb') as stream:
            data = stream.read(20 * 1024 * 1024 + 1)
        root = metadata_xml(data)
        namespaces = dict(value for _, value in ET.iterparse(io.BytesIO(data), events=("start-ns",)))
        metadata.append((root, namespaces))
    for record in records:
        destination = sdk.joinpath(*package_parts(record["package"])) / "package.xml"
        if not destination.resolve().is_relative_to(sdk.resolve()):
            raise ValueError('Unsafe SDK package path')
        matches = []
        for root, namespaces in metadata:
            for remote in root.findall("remotePackage"):
                if remote.get("path") != record["package"]:
                    continue
                if any(c.text.strip() == record["checksum"] for c in remote.findall("archives/archive/complete/checksum")):
                    matches.append((remote, namespaces))
        if len(matches) != 1:
            raise ValueError("Ambiguous official metadata for " + record["package"])
        remote, namespaces = matches[0]
        local = copy.deepcopy(remote)
        local.tag = "localPackage"
        local.set("obsolete", "false")
        namespaces = dict(namespaces)
        if "generic" in namespaces:
            namespaces["generic"] = "http://schemas.android.com/repository/android/generic/02"
        for child in list(local):
            if child.tag in ("archives", "channelRef"):
                local.remove(child)
        declarations = " ".join('xmlns:' + prefix + '="' + html.escape(uri, quote=True) + '"' for prefix, uri in namespaces.items() if prefix and prefix != 'repo')
        license_id = license_key(record["license"])
        license_node = ET.Element("license", {"id": license_id, "type": "text"})
        license_node.text = json.loads(catalog_path.read_text(encoding="utf-8"))["licenses"][license_id]
        xml = '<repo:repository xmlns:repo="http://schemas.android.com/repository/android/common/02" ' + declarations + '>' + ET.tostring(license_node, encoding="unicode") + ET.tostring(local, encoding="unicode") + '</repo:repository>'
        with destination.open("w", encoding="utf-8") as target:
            target.write(xml)
    print("Registered local SDK packages: " + str(sdk))


def install(catalog_path, sdk, accept):
    if not accept:
        raise ValueError("Read catalog license text and obtain human approval before --accept-licenses")
    sdk = external_output(sdk)
    external_output(catalog_path)
    data = json.loads(catalog_path.read_text(encoding="utf-8"))
    if data["host"] != {"Windows": "windows", "Linux": "linux", "Darwin": "macosx"}[platform.system()]:
        raise ValueError("Catalog host mismatch")
    # Only a new dedicated SDK; never overwrite the machine's existing SDK.
    sdk.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("android_morphe_driver", TRUSTED / "driver.py")
    driver = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = driver
    spec.loader.exec_module(driver)
    evidence = []
    for record in fetch_archives(catalog_path):
        parts = package_parts(record["package"])
        size = record["size"]
        if not 0 < size <= 5 * 1024**3 or record["checksum_type"] not in ("sha1", "sha256"):
            raise ValueError("Invalid size/checksum type")
        archive = Path(record["archive"])
        extracted = archive.parent / ("extracted-" + uuid.uuid4().hex)
        driver.extract_archive(archive, extracted)
        # Each official SDK archive has one top-level tool/platform/image directory.
        children = list(extracted.iterdir())
        if len(children) != 1 or not children[0].is_dir():
            raise ValueError("Unexpected SDK archive root layout")
        destination = sdk.joinpath(*parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            raise ValueError("SDK destination collision")
        shutil.copytree(children[0], destination)
        evidence.append({**record, "installed": str(destination)})
    license_dir = sdk / "licenses"
    license_dir.mkdir(exist_ok=True)
    for key, text in data["licenses"].items():
        license_key(key)
        (license_dir / key).write_text(hashlib.sha1(text.strip().encode()).hexdigest() + "\n", encoding="ascii")
    (sdk / "bootstrap-evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    register_packages(catalog_path, sdk)
    print("SDK installed: " + str(sdk))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    cat = sub.add_parser("catalog")
    cat.add_argument("--out", type=Path, required=True)
    cat.add_argument("--package", action="append")
    fetch = sub.add_parser("fetch")
    fetch.add_argument("--catalog", type=Path, required=True)
    fetch.add_argument("--accept-licenses", action="store_true")
    reg = sub.add_parser("register")
    reg.add_argument("--catalog", type=Path, required=True)
    reg.add_argument("--sdk", type=Path, required=True)
    inst = sub.add_parser("install")
    inst.add_argument("--catalog", type=Path, required=True)
    inst.add_argument("--sdk", type=Path, required=True)
    inst.add_argument("--accept-licenses", action="store_true")
    args = parser.parse_args()
    if args.command == "catalog":
        catalog(args.out.resolve(), args.package or DEFAULT_PACKAGES)
    elif args.command == "register":
        register_packages(args.catalog.resolve(), args.sdk.resolve())
    elif args.command == "fetch":
        if not args.accept_licenses:
            raise ValueError("Human license approval required before downloads")
        fetch_archives(args.catalog.resolve())
    else:
        install(args.catalog.resolve(), args.sdk.resolve(), args.accept_licenses)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, ET.ParseError) as error:
        raise SystemExit(str(error))
