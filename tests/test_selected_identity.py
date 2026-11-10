"""Synthetic identity contracts ONLY; no Android/tool process or real APK is used."""
import copy
from contextlib import ExitStack
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
import zipfile

REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("identity_contract_observations", REPO / "tools/release/observations.py")
o = importlib.util.module_from_spec(spec)
spec.loader.exec_module(o)
si = o.si


def save(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")


class IdentityFixture:
    """Test-only miniature independently fixed policy; NEVER a CLI override."""
    def __init__(self, root, stack):
        self.root = root
        self.java = root / "java.exe"
        self.paths = {key: root / name for key, name in dict(aapt2="aapt2.exe", signer_jar="apksigner.jar",
            provenance="provenance.json", certificate_dialog="certificate.yml").items()}
        for key, path in {"java": self.java, **self.paths}.items():
            path.write_bytes(("SYNTHETIC NONEXECUTABLE " + key).encode())
        self.members = {name: root / name for name in si.MEMBERS}
        for name, path in self.members.items():
            with zipfile.ZipFile(path, "w") as apk:
                apk.writestr("fixture-only.txt", b"NOT AN APK; NEVER EXECUTED")
                if name == "base.apk":
                    for number in range(1, 6):
                        apk.writestr("classes" + (str(number) if number > 1 else "") + ".dex", b"NOT DEX " + str(number).encode())
        self.archive = root / "archive.apkm"
        with zipfile.ZipFile(self.archive, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, path in self.members.items():
                archive.writestr(name, path.read_bytes())
            archive.writestr("unselected.txt", b"not completeness evidence")
        self.descriptor = root / "selection.json"
        self.value = dict(schema="termius-selected-inputs-v1", archive=str(self.archive),
            members=[dict(name=name, apk=str(path)) for name, path in self.members.items()],
            **{key: str(path) for key, path in self.paths.items()})
        save(self.descriptor, self.value)
        self.fixed_members = {name: (path.stat().st_size, si.record(path)["sha256"], si.MEMBERS[name][2]) for name, path in self.members.items()}
        self.fixed_payloads = {key: si.record(path)["sha256"] for key, path in {"java": self.java, **self.paths}.items()}
        stack.enter_context(mock.patch.object(si, "ARCHIVE", si.record(self.archive)))
        stack.enter_context(mock.patch.object(si, "MEMBERS", self.fixed_members))
        stack.enter_context(mock.patch.object(si, "PAYLOADS", self.fixed_payloads))
        self.selection = si.load_selection(self.descriptor, self.java, o.p.parse_json)

    def verification(self):
        # Typed synthetic raw manifest tree, then the real shared manifest/topology API.
        splitset = si.canonical_driver().SPLITSET
        rows = []
        for name, (_, digest, split) in si.MEMBERS.items():
            def attr(value, kind="string", resource=None):
                return dict(type=kind, value=value, raw=None, resource_id=resource)
            attrs = {"package": attr(si.PACKAGE), splitset.A + "versionCode": attr(1008, "integer", "0101021b")}
            if split is None:
                attrs[splitset.A + "versionName"] = attr(si.VERSION, resource="0101021c")
                attrs[splitset.A + "requiredSplitTypes"] = attr("base__abi,base__density", resource="0101064e")
            else:
                attrs["split"] = attr(split)
                attrs[splitset.A + "splitTypes"] = attr("base__abi" if split.endswith("x86_64") else "base__density", resource="0101064f")
            raw = dict(source="aapt2_xmltree", root=dict(tag="manifest", attributes=attrs, children=[dict(tag="application",
                attributes={splitset.A + "hasCode": attr(False, "boolean", "0101000c")} if split else {}, children=[])]))
            declarations = splitset.manifest_fields(raw)
            rows.append(dict(path=str(self.members[name]), sha256=digest, manifest=dict(package=si.PACKAGE, version_code=si.CODE,
                version_name=si.VERSION, split=split), raw_manifest=raw, manifest_declarations=declarations,
                dex_payloads=["classes.dex", "classes2.dex", "classes3.dex", "classes4.dex", "classes5.dex"] if split is None else [],
                native_abis=["x86_64"] if split == "config.x86_64" else [], native_libraries=[], signers_sha256=[si.SIGNER]))
        topology = si.canonical_driver().validate_split_set(rows, abi="x86_64", density="mdpi")
        return dict(schema=2, status="selected_split_set_verified", selection=copy.deepcopy(si.SELECTION),
            expected=dict(package=si.PACKAGE, version_code=si.CODE, version_name=si.VERSION, split=None, signers_sha256=[si.SIGNER]),
            apks=rows, topology=topology, split_set="base_config_set")


class FixedPolicyContracts(unittest.TestCase):
    def test_reviewed_identity_and_payload_pins_are_literal_not_fixture_derived(self):
        self.assertEqual(si.ARCHIVE, dict(size=46507753, sha256="01606bb969574c5140229d0e8b6c1e32cf759543f676e1488d2aa917dea252dc"))
        self.assertEqual(si.MEMBERS, {
            "base.apk": (56857170, "8d4150b0b97ea4f13820a6b5a36c28b9a2cea7fbe1a542428aaa2cbcdd30a2f7", None),
            "split_config.x86_64.apk": (13636978, "3866f68a693e989779e9a99a46ae138d4611ad5d12325a1c69d53d2b94c26aa8", "config.x86_64"),
            "split_config.mdpi.apk": (107680, "a1edd0ce716c1cdc428b6c22ed3ead697fdf11707c655c2cd9f4b50827f3ada8", "config.mdpi")})
        self.assertEqual(si.PAYLOADS, {
            "java": "f8dc082a7dedbfd2924c3562405a5a1fd12efd2641808c92e2de819c76a58b7e",
            "aapt2": "babf3122e515ddb954c5ac4669e085ce990536c035e3072de30127bddd6e3608",
            "signer_jar": "3716d9311e55d2b0918a2fd9d54ba9e406c5f6abeea700b287f11259bc163dec",
            "provenance": "2ce653b53dfa263a1b45ecf996ab8db03a5bddb5a0147da3050a15db4f88673e",
            "certificate_dialog": "eccf7896ce4678dc4ead1415104d7b70cd4a728b332b87f33e1166f806e19906"})
        self.assertEqual(si.SELECTION, dict(abi="x86_64", density="mdpi", languages=["en"]))


class IdentityContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="selected-identity-contract-ONLY-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.fixture = IdentityFixture(self.root, self.stack)

    def test_concrete_policy_is_separate_from_local_paths(self):
        # The miniature fixture's monkeypatches exist only inside this test process.
        self.assertEqual(si.POLICY, "termius-8.0.1-selected-identity-v1")
        self.assertEqual(si.SIGNER, "73071d4501b19a76b97367b5161f703f1e1d53d76a257a4b3d766d90833978f0")
        self.assertEqual((si.PACKAGE, si.CODE, si.VERSION), ("com.server.auditor.ssh.client", "1008", "8.0.1"))
        self.assertNotIn("expected", self.fixture.value)

    def test_minature_policy_snapshot_and_canonical_command(self):
        selection = self.fixture.selection
        before = si.snapshot_selection(selection)
        self.assertEqual(before, si.snapshot_selection(selection))
        self.assertEqual(list(before["archive_members"]), list(si.MEMBERS))
        argv = si.verification_argv(selection, self.root / "NEW-verification.json")
        self.assertEqual(argv[1:3], ["-I", "-B"])
        self.assertIn("verify-apks", argv)
        self.assertEqual(argv[argv.index("--java") + 1], str(self.fixture.java))
        self.assertEqual(argv[argv.index("--expect-signer") + 1], si.SIGNER)
        self.assertEqual(argv[argv.index("--abi") + 1:], ["x86_64", "--density", "mdpi", "--language", "en", "--out", str(self.root / "NEW-verification.json")])

    def test_descriptor_expected_pins_extra_fields_types_and_members_rejected(self):
        original = self.fixture.value
        for mutate in (lambda x: x.update(expected={"signer": "self-authority"}), lambda x: x.update(schema=1),
                       lambda x: x.update(java=str(self.fixture.java)), lambda x: x["members"].reverse(),
                       lambda x: x["members"].pop(), lambda x: x["members"][0].update(apk=7),
                       lambda x: x["members"][1].update(name="base.apk"), lambda x: x.update(archive="relative.apkm")):
            value = copy.deepcopy(original)
            mutate(value)
            save(self.fixture.descriptor, value)
            with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                si.load_selection(self.fixture.descriptor, self.fixture.java, o.p.parse_json)

    def test_cli_preserves_descriptor_spelling_for_alias_rejection(self):
        alias = str(self.root) + "/./selection.json"
        args = ["execute"]
        for option in ("request", "bundle", "catalog", "jdk", "cache-root", "output"):
            args += ["--" + option, str(self.root / option)]
        args += ["--termius-selection", alias]
        with mock.patch.object(o, "execute", return_value={"status": "incomplete-private-fragments-not-staging-ready"}) as execute:
            self.assertEqual(o.main(args), 0)
        self.assertEqual(execute.call_args.kwargs["termius_selection"], alias)
        with self.assertRaisesRegex(ValueError, "dot path"):
            si.load_selection(alias, self.fixture.java, o.p.parse_json)

    def test_duplicate_descriptor_json_keys_rejected(self):
        self.fixture.descriptor.write_text('{"schema":1,"schema":1}')
        with self.assertRaises(ValueError): si.load_selection(self.fixture.descriptor, self.fixture.java, o.p.parse_json)

    def test_all_payload_member_archive_and_descriptor_mutations_detected(self):
        selection = self.fixture.selection
        for path in selection["paths"].values():
            original = path.read_bytes()
            path.write_bytes(original + b"MUTATION")
            with self.subTest(name=path.name), self.assertRaises((ValueError, OSError)):
                si.snapshot_selection(selection)
            path.write_bytes(original)
        self.assertEqual(si.snapshot_selection(selection)["policy"], si.POLICY)

    def test_policy_replacement_cannot_be_blessed_by_descriptor(self):
        for key in si.PAYLOADS:
            with mock.patch.dict(si.PAYLOADS, {key: "0" * 64}), self.subTest(key=key), self.assertRaises(ValueError):
                si.snapshot_selection(self.fixture.selection)
        with mock.patch.object(si, "ARCHIVE", {"size": self.fixture.archive.stat().st_size + 1, "sha256": si.record(self.fixture.archive)["sha256"]}), self.assertRaises(ValueError):
            si.snapshot_selection(self.fixture.selection)
        for name in si.MEMBERS:
            wrong = dict(si.MEMBERS)
            size, digest, split = wrong[name]
            wrong[name] = (size, "0" * 64, split)
            with mock.patch.object(si, "MEMBERS", wrong), self.assertRaises(ValueError): si.snapshot_selection(self.fixture.selection)

    def test_archive_member_mismatch_even_if_archive_hash_is_consistent(self):
        with zipfile.ZipFile(self.fixture.archive, "w") as archive:
            for name, path in self.fixture.members.items(): archive.writestr(name, path.read_bytes() + b"ALTERED")
        with mock.patch.object(si, "ARCHIVE", si.record(self.fixture.archive)), self.assertRaises(ValueError): si.snapshot_selection(self.fixture.selection)

    def test_member_mapping_must_equal_archive_not_only_its_own_hash(self):
        first = self.fixture.value["members"][0]
        first["apk"] = str(self.fixture.members["split_config.mdpi.apk"])
        save(self.fixture.descriptor, self.fixture.value)
        with self.assertRaises(ValueError): si.load_selection(self.fixture.descriptor, self.fixture.java, o.p.parse_json)

    def test_hardlink_duplicate_paths_and_original_ancestry_rejected(self):
        alias = self.root / "hardlink.apk"
        os.link(self.fixture.members["base.apk"], alias)
        with self.assertRaises(ValueError): si.record(alias)
        alias.unlink()
        with self.assertRaises(ValueError): si.canonical(str(self.root / "absent" / ".." / "base.apk"))
        target = self.fixture.members["base.apk"]
        with self.assertRaises(ValueError): si.canonical(str(target.with_name("BASE.apk")))

    def test_all_reparse_categories_not_only_junction_are_rejected_before_resolve(self):
        original = Path.lstat
        def lstat(path, *args, **kwargs):
            result = original(path, *args, **kwargs)
            if path == self.root:
                class Reparse:
                    st_mode = stat.S_IFDIR
                    st_file_attributes = 0x400  # arbitrary Windows reparse tag
                return Reparse()
            return result
        with mock.patch.object(Path, "lstat", new=lstat), mock.patch.object(Path, "resolve", side_effect=AssertionError("must reject before resolution")):
            with self.assertRaises(ValueError): si.canonical(self.fixture.members["base.apk"])

    @unittest.skipUnless(os.name == "nt", "Windows short-name API")
    def test_supported_windows_short_name_alias_rejected(self):
        import ctypes
        long = self.root / "long unique input filename.txt"
        long.write_bytes(b"test")
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetShortPathNameW(str(long), buffer, len(buffer))
        if not length or buffer.value == str(long): self.skipTest("8.3 aliases disabled on this volume")
        with self.assertRaises(ValueError): si.canonical(buffer.value)

    def test_restored_bytes_are_explicitly_not_isolation(self):
        # A replacement restored between endpoints is intentionally undetectable.
        before = si.snapshot_selection(self.fixture.selection)
        path = self.fixture.paths["aapt2"]
        original = path.read_bytes()
        path.write_bytes(b"transient replacement")
        path.write_bytes(original)
        self.assertEqual(before, si.snapshot_selection(self.fixture.selection))

    def test_canonical_verification_contract_with_shared_topology(self):
        report = self.fixture.verification()
        self.assertEqual(si.validate_verification(report, self.fixture.selection), report)

    def test_wrong_exact_rows_identity_signers_selection_and_old_reports_rejected(self):
        original = self.fixture.verification()
        mutations = [lambda x: x.update(schema="2"), lambda x: x.update(schema=2.0), lambda x: x.update(schema=True),
            lambda x: x.update(status="PASS"), lambda x: x["apks"].reverse(), lambda x: x["apks"].append(x["apks"][0]),
            lambda x: x["apks"][0].update(signers_sha256=["0" * 64]), lambda x: x["apks"][0]["manifest"].update(package="other.pkg"),
            lambda x: x["apks"][0]["manifest"].update(version_code="1009"), lambda x: x["apks"][0]["manifest"].update(version_name="8.0.2"),
            lambda x: x["selection"].update(languages=["none"]), lambda x: x["expected"].update(signers_sha256=["0" * 64]),
            lambda x: x["topology"].update(coverage="all resources"), lambda x: x["apks"][0].update(path=str(self.root / "other.apk")),
            lambda x: x["apks"][0]["raw_manifest"]["root"]["attributes"]["package"].update(value="wrong.raw.package")]
        for mutate in mutations:
            report = copy.deepcopy(original)
            mutate(report)
            with self.subTest(mutation=mutate), self.assertRaises((ValueError, o.si.canonical_driver().DriverError)):
                si.validate_verification(report, self.fixture.selection)

    def test_required_types_must_be_real_canonical_topology_not_a_claim(self):
        report = self.fixture.verification()
        member = report["apks"][1]
        member["raw_manifest"]["root"]["attributes"].pop(si.canonical_driver().SPLITSET.A + "splitTypes")
        member["manifest_declarations"] = si.canonical_driver().SPLITSET.manifest_fields(member["raw_manifest"])
        with self.assertRaises(si.canonical_driver().DriverError): si.validate_verification(report, self.fixture.selection)


if __name__ == "__main__":
    unittest.main()
