"""Byte-level provenance and hermetic Git-filter regressions, not runtime evidence.

Source archives need no .git directory. Only the Git integration tests require
Git; every Git operation targets a fresh external temporary fixture, never this
checkout. No commits, hooks, external filters, downloads or Kotlin execution.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PLEX_RECORD = "docs/plex-migration.json"
RECORDS = ("docs/termius-migration.json", PLEX_RECORD)
PLEX_PREFIX = "patches/src/main/kotlin/io/github/fishyau/androidpatches/plex/"
LEGAL = ("LICENSE", "NOTICE", PLEX_PREFIX + "LICENSE", PLEX_PREFIX + "NOTICE")
BYTE_PRESERVED = (PLEX_RECORD,) + LEGAL
FIXTURE_PATHS = RECORDS + LEGAL


def sha(data):
    return hashlib.sha256(data).hexdigest()


class ProvenanceBytesTests(unittest.TestCase):
    def test_plex_record_normalization_is_not_byte_equivalence(self):
        original = (ROOT / PLEX_RECORD).read_bytes()
        normalized = original.replace(b"\r\n", b"\n")
        self.assertNotEqual(original, normalized, "Reviewed Plex record retains original CRLF bytes")
        self.assertEqual(json.loads(original), json.loads(normalized))
        self.assertNotEqual(sha(original), sha(normalized))

    def test_explicit_byte_preserving_attributes(self):
        lines = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
        rules = [line.split() for line in lines if line.strip() and not line.lstrip().startswith("#")]
        for path in BYTE_PRESERVED:
            with self.subTest(path=path):
                self.assertIn([path, "-text"], rules)

    def test_retained_plex_legal_bytes_match_provenance(self):
        record = json.loads((ROOT / PLEX_RECORD).read_bytes())
        entries = record["licenses"]
        self.assertEqual(["LICENSE", "NOTICE"], sorted(entry["original_path"] for entry in entries))
        self.assertEqual(sorted(PLEX_PREFIX + name for name in ("LICENSE", "NOTICE")),
                         sorted(entry["retained_path"] for entry in entries))
        for entry in entries:
            with self.subTest(path=entry["retained_path"]):
                self.assertEqual("verbatim", entry["transformation"])
                self.assertEqual(entry["sha256"], sha((ROOT / entry["retained_path"]).read_bytes()))


class GitProvenanceRoundTripTests(unittest.TestCase):
    """Use actual Git clean/checkout filters, independent of the source VCS state."""

    def setUp(self):
        self.git_executable = shutil.which("git")
        if self.git_executable is None:
            self.skipTest("Git executable unavailable; static provenance tests still apply")
        temporary = tempfile.TemporaryDirectory(prefix="provenance-byte-git-")
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name).resolve()
        self.assertFalse(self.scratch.is_relative_to(ROOT))
        self.fixture = self.scratch / "source"
        self.fixture.mkdir()
        self.empty = self.scratch / "empty"
        self.empty.mkdir()
        home = self.scratch / "home"
        home.mkdir()
        # Strip inherited repository/config/pathspec overrides. Do not inherit user
        # attributes, templates, hooks or external clean/smudge filters.
        self.env = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
        self.env.update(HOME=str(home), USERPROFILE=str(home), XDG_CONFIG_HOME=str(home),
                        GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_CONFIG_GLOBAL=os.devnull, GIT_ATTR_NOSYSTEM="1",
                        GIT_TERMINAL_PROMPT="0")
        self.original = {path: (ROOT / path).read_bytes() for path in FIXTURE_PATHS}
        for path, data in self.original.items():
            destination = self.fixture / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(data)
        self.attributes = (ROOT / ".gitattributes").read_bytes()
        (self.fixture / ".gitattributes").write_bytes(self.attributes)
        self.git("false", "init", "--template=" + str(self.empty), ".")

    def git(self, autocrlf, *arguments):
        # The -c settings affect only this process and this synthetic repository.
        command = [self.git_executable, "-c", "core.attributesFile=" + os.devnull,
                   "-c", "core.hooksPath=" + str(self.empty),
                   "-c", "core.autocrlf=" + autocrlf, "-c", "core.safecrlf=false",
                   *arguments]
        result = subprocess.run(command, cwd=self.fixture, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        self.assertEqual(0, result.returncode,
                         result.stderr.decode("utf-8", errors="replace"))
        return result.stdout

    def stage_tree(self, autocrlf):
        # Remove only the disposable index so every mode really runs clean filters.
        (self.fixture / ".git/index").unlink(missing_ok=True)
        self.git(autocrlf, "add", "--", ".gitattributes", *FIXTURE_PATHS)
        return self.git(autocrlf, "write-tree").decode("ascii").strip()

    def checkout(self, autocrlf, name):
        destination = self.scratch / name
        destination.mkdir()
        self.git(autocrlf, "checkout-index", "--all", "--prefix=" + destination.as_posix() + "/")
        return destination

    def test_effective_attributes_disable_text_conversion(self):
        output = self.git("true", "check-attr", "-z", "text", "filter", "working-tree-encoding",
                          "--", *BYTE_PRESERVED)
        fields = output.decode("utf-8").rstrip("\0").split("\0")
        self.assertEqual(len(BYTE_PRESERVED) * 9, len(fields))
        actual = {(fields[index], fields[index + 1]): fields[index + 2]
                  for index in range(0, len(fields), 3)}
        for path in BYTE_PRESERVED:
            with self.subTest(path=path):
                self.assertEqual("unset", actual[path, "text"])
                self.assertEqual("unspecified", actual[path, "filter"])
                self.assertEqual("unspecified", actual[path, "working-tree-encoding"])

    def test_original_bytes_survive_staging_blobs_and_fresh_checkouts(self):
        for clean_mode in ("false", "true", "input"):
            tree = self.stage_tree(clean_mode)
            for path, expected in self.original.items():
                with self.subTest(clean=clean_mode, blob=path):
                    self.assertEqual(expected, self.git(clean_mode, "cat-file", "blob", tree + ":" + path))
            for checkout_mode in ("false", "true", "input"):
                checkout = self.checkout(checkout_mode, f"checkout-{clean_mode}-{checkout_mode}")
                for path, expected in self.original.items():
                    with self.subTest(clean=clean_mode, checkout=checkout_mode, path=path):
                        self.assertEqual(expected, (checkout / path).read_bytes())

    def test_existing_normalized_index_can_be_repaired_without_rewriting_working_record(self):
        lines = self.attributes.splitlines(keepends=True)
        (self.fixture / ".gitattributes").write_bytes(b"".join(
            line for line in lines if line.split() != [PLEX_RECORD.encode(), b"-text"]))
        tree = self.stage_tree("false")
        original = self.original[PLEX_RECORD]
        self.assertNotEqual(original, self.git("false", "cat-file", "blob", tree + ":" + PLEX_RECORD))
        (self.fixture / ".gitattributes").write_bytes(self.attributes)
        # Reapply current attributes even if the file's stat cache looks unchanged.
        self.git("false", "add", "--", ".gitattributes")
        self.git("false", "add", "--renormalize", "--", PLEX_RECORD)
        repaired = self.git("false", "write-tree").decode("ascii").strip()
        self.assertEqual(original, self.git("false", "cat-file", "blob", repaired + ":" + PLEX_RECORD))
        self.assertEqual(original, (self.fixture / PLEX_RECORD).read_bytes())
        checkout = self.checkout("false", "checkout-repaired-index")
        self.assertEqual(original, (checkout / PLEX_RECORD).read_bytes())

    def test_missing_plex_override_changes_historical_record_bytes(self):
        # Negative control: JSON equivalence cannot detect the old clean-filter bug.
        lines = self.attributes.splitlines(keepends=True)
        removed = [line for line in lines if line.split() == [PLEX_RECORD.encode(), b"-text"]]
        self.assertEqual(1, len(removed))
        (self.fixture / ".gitattributes").write_bytes(b"".join(line for line in lines if line not in removed))
        tree = self.stage_tree("false")
        blob = self.git("false", "cat-file", "blob", tree + ":" + PLEX_RECORD)
        original = self.original[PLEX_RECORD]
        self.assertEqual(original.replace(b"\r\n", b"\n"), blob)
        self.assertNotEqual(original, blob)
        self.assertEqual(json.loads(original), json.loads(blob))
        expected = sha(original)
        self.assertEqual(expected, sha(original))
        self.assertNotEqual(expected, sha(blob))
        checkout = self.checkout("false", "checkout-broken-attributes")
        self.assertEqual(blob, (checkout / PLEX_RECORD).read_bytes())
        self.assertNotEqual(expected, sha((checkout / PLEX_RECORD).read_bytes()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
