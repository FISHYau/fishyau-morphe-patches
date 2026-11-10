"""Read-only migration/default-adaptation audit; outputs JSON, never edits the donor.

Use --emit to obtain provenance data for review; otherwise compare against the
checked-in docs/termius-migration.json. Python must be invoked with -I -B.
"""
import argparse
import hashlib
import json
from pathlib import Path

OLD = "app.template.patches.serverauditor.premium"
NEW = "io.github.fishyau.androidpatches.termius"
MAIN = ("ServerAuditorOfflineAutomationPatch.kt", "ServerAuditorPremiumPatch.kt", "Fingerprints.kt",
        "BytecodeLayout.kt", "OfflineAutomationValidation.kt", "PremiumPatchValidation.kt")
TESTS = ("OfflineAutomationValidationTest.kt", "PremiumPatchValidationTest.kt")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tree(entries, key):
    return sha(b"termius-migration-v1\0" + b"".join(
        (entry["migrated"] + "\0" + entry[key] + "\n").encode("utf-8") for entry in sorted(entries, key=lambda x: x["migrated"])))


def compare_source(original, migrated, source_set, name):
    """Allow namespace/import migration and only the reviewed Premium default adaptation."""
    text = original.decode("utf-8").replace("\r\n", "\n")
    expected = text.replace("package " + OLD, "package " + NEW)
    changes = ["package namespace only"]
    for statement in ("import app.template.patches.shared.Constants.SERVER_AUDITOR_COMPATIBILITY\n",
                      "import app.template.patches.shared.returnEarly\n"):
        if statement in expected:
            expected = expected.replace(statement, "")
            changes.append("remove shared import; use isolated same-package equivalent")
    if source_set == "main" and name == "ServerAuditorPremiumPatch.kt":
        declaration = ('val serverAuditorPremiumPatch = bytecodePatch(\n'
            '    name = "Server Auditor Premium",\n'
            '    description = "Optional legacy Pro title/expiry override for Termius 8.0.1. Does not enable account-free Automation or change storage/server entitlements.",\n'
            '    default = false,\n) {')
        if expected.count(declaration) != 1:
            raise ValueError("Premium donor default declaration differs from reviewed source")
        expected = expected.replace(declaration, declaration.replace("    default = false,", "    default = true,"), 1)
        changes.append("2026-11-09 explicit user request: Premium default false -> true only; algorithms/guards/compatibility unchanged")
    if expected != migrated.decode("utf-8").replace("\r\n", "\n"):
        raise ValueError(f"Nonmechanical migration difference: {name}")
    return changes


def build(repo, donor):
    entries = []
    for source_set, names in (("main", MAIN), ("test", TESTS)):
        for name in names:
            original_path = f"patches/src/{source_set}/kotlin/app/template/patches/serverauditor/premium/{name}"
            migrated_path = f"patches/src/{source_set}/kotlin/io/github/fishyau/androidpatches/termius/{name}"
            original = (donor / original_path).read_bytes()
            migrated = (repo / migrated_path).read_bytes()
            changes = compare_source(original, migrated, source_set, name)
            entries.append({"donor": original_path, "migrated": migrated_path,
                            "original_sha256": sha(original), "migrated_sha256": sha(migrated), "modifications": changes})
    constants_path = "patches/src/main/kotlin/app/template/patches/shared/Constants.kt"
    constant_bytes = (donor / constants_path).read_bytes()
    constant_text = constant_bytes.decode("utf-8").replace("\r\n", "\n")
    fragment = "val SERVER_AUDITOR_COMPATIBILITY = Compatibility(" + constant_text.split("val SERVER_AUDITOR_COMPATIBILITY = Compatibility(", 1)[1].split("\n    )", 1)[0] + "\n    )"
    compat_path = "patches/src/main/kotlin/io/github/fishyau/androidpatches/termius/Compatibility.kt"
    migrated = (repo / compat_path).read_bytes()
    if "internal " + fragment not in migrated.decode("utf-8").replace("\r\n", "\n"):
        raise ValueError("Compatibility extraction changed")
    entries.append({"donor": constants_path, "migrated": compat_path, "original_sha256": sha(constant_bytes),
                    "original_fragment_sha256": sha(fragment.encode()), "migrated_sha256": sha(migrated),
                    "modifications": ["extract only SERVER_AUDITOR_COMPATIBILITY", "package/import isolation and internal visibility; exact values unchanged"]})
    utility_path = "patches/src/main/kotlin/app/template/patches/shared/BytecodeUtils.kt"
    utility = (donor / utility_path).read_bytes()
    notice = utility.decode("utf-8").replace("\r\n", "\n").split(" */", 1)[0] + " */"
    boolean_path = "patches/src/main/kotlin/io/github/fishyau/androidpatches/termius/BooleanReturn.kt"
    boolean_bytes = (repo / boolean_path).read_bytes()
    if not boolean_bytes.decode("utf-8").replace("\r\n", "\n").startswith(notice):
        raise ValueError("Incomplete Morphe/ReVanced utility notice")
    entries.append({"donor": utility_path, "migrated": boolean_path, "original_sha256": sha(utility),
                    "original_notice_sha256": sha(notice.encode()), "migrated_sha256": sha(boolean_bytes),
                    "modifications": ["preserve complete applicable Morphe/ReVanced notice",
                                      "focused returnEarly(false): same Z type check and prepend const/4 v0,0 then return v0; no register growth",
                                      "reject unneeded true argument; remove unrelated overloads/helpers; namespace/import isolation"]})
    return {"schema": 1, "kind": "termius-source-migration", "namespace": NEW,
            "scope": "exactly the two Server Auditor patches; no donor registry or unrelated implementations",
            "entries": entries, "original_source_sha256": tree(entries, "original_sha256"),
            "migrated_source_sha256": tree(entries, "migrated_sha256"),
            "inherited_validator_cases": {"offline_automation": 39, "premium_storage": 27},
            "accepted_existing_behavior": {"basis": "User confirmed these two patches tested and working; not a new observation by this migration audit",
                "defaults_scope": "Original donor defaults before the separately recorded explicit user-requested default-selection adaptation",
                "patches": [{"name": "Server Auditor Offline Automation", "default": True},
                            {"name": "Server Auditor Premium", "default": False}],
                "compatibility": {"package": "com.server.auditor.ssh.client", "version": "8.0.1", "version_code": 1008, "container": "APKM"},
                "new_android_runtime_or_manager_import_claimed": False},
            "default_selection_adaptation": {"date": "2026-11-09", "basis": "explicit-user-request",
                "request": "Both Termius patches should be enabled by default.",
                "patch": "Server Auditor Premium", "original_default": False, "current_default": True,
                "scope": "Default-selection metadata only; donor algorithms, guards, descriptions and compatibility unchanged; Offline Automation remains true",
                "combined_android_runtime_acceptance_claimed": False},
            "hash_contract": "File SHA-256 is exact bytes. Source-set digests hash termius-migration-v1 NUL then sorted migrated-path NUL file-digest LF; original set uses full donor files, including extracted utilities.",
            "limitations": ["Mechanical equality check normalizes CRLF to LF; file hashes do not", "Helper equivalence requires source review and structural checks", "Not an MPP build, Android load, release approval or publication"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--donor-root", type=Path, required=True)
    parser.add_argument("--emit", action="store_true")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[2]
    value = build(repo, args.donor_root.resolve(strict=True))
    if not args.emit:
        expected = json.loads((repo / "docs/termius-migration.json").read_text(encoding="utf-8"))
        if expected != value:
            raise ValueError("Checked-in migration provenance does not match exact current sources")
    print(json.dumps(value, indent=2))


if __name__ == "__main__":
    main()
