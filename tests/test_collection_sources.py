"""Offline synthetic/static source-policy regressions; never compile/load Kotlin or run JVM/Gradle.

Only the Python runner's pure path-selection function is evaluated, extracted by
AST without importing its module or executing main/subprocess code. Synthetic
fixtures live in external OS temporary scratch; no binaries/live manifest written.
"""
import ast
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import tomllib
import unittest

REPO = Path(__file__).resolve().parents[1]
BASE = "io/github/fishyau/androidpatches"
MAIN = REPO / "patches/src/main/kotlin" / BASE
TEST = REPO / "patches/src/test/kotlin" / BASE
TOOLS = REPO / "tools/termius-check"
RUNNER = TOOLS / "run_jvm_checks.py"
EXPECTED_MAIN = {
    "termius/ServerAuditorOfflineAutomationPatch.kt", "termius/ServerAuditorPremiumPatch.kt",
    "termius/Compatibility.kt", "termius/BooleanReturn.kt", "termius/Fingerprints.kt",
    "termius/BytecodeLayout.kt", "termius/PremiumPatchValidation.kt", "termius/OfflineAutomationValidation.kt",
    "plex/PremiumUnlockPatch.kt", "plex/shared/Constants.kt", "plex/shared/HermesBytecode.kt",
    "tools/LoadedBundleMetadata.kt", "tools/PatchListGenerator.kt",
}
EXPECTED_DEFINITIONS = {
    "Server Auditor Offline Automation": ("bytecodePatch", True),
    "Server Auditor Premium": ("bytecodePatch", True),
    "Premium unlock": ("rawResourcePatch", True),
}


def read(path):
    return path.read_text(encoding="utf-8")


def uncomment(text):
    # These bounded files contain no comment markers inside compatibility strings.
    return re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)


def block(text, marker):
    start = text.index("{", text.index(marker))
    level = 1
    for index in range(start + 1, len(text)):
        level += (text[index] == "{") - (text[index] == "}")
        if not level:
            return text[start + 1:index]
    raise AssertionError("Unbalanced block: " + marker)


def source_selector():
    """Extract only literal allowlists and the reviewed pure path-policy function."""
    tree = ast.parse(read(RUNNER), filename=str(RUNNER))
    names = {"TERMIUS_MAIN", "PLEX_MAIN", "PROJECTION", "TERMIUS_TESTS", "PLEX_TESTS", "COLLECTION_TESTS"}
    namespace = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id in names:
            namespace[node.targets[0].id] = ast.literal_eval(node.value)
    function = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "select_sources")
    # No imports, subprocess/main or other runner functions enter this tiny module.
    calls = [node for node in ast.walk(function) if isinstance(node, ast.Call)]
    for node in calls:
        if isinstance(node.func, ast.Name):
            assert node.func.id in {"ValueError", "set", "sorted"}, ast.unparse(node.func)
        else:
            assert isinstance(node.func, ast.Attribute) and node.func.attr in {"rglob", "glob"}, ast.unparse(node.func)
    exec(compile(ast.Module(body=[function], type_ignores=[]), str(RUNNER), "exec"), namespace)
    return namespace["select_sources"], namespace


class CollectionSourcePolicyTests(unittest.TestCase):
    def test_exact_production_source_allowlist(self):
        self.assertEqual(EXPECTED_MAIN, {p.relative_to(MAIN).as_posix() for p in (REPO / "patches/src/main/kotlin").rglob("*.kt")})

    def test_exact_three_declarations_types_and_explicit_defaults(self):
        definitions = []
        for path in MAIN.rglob("*.kt"):
            text = read(path)
            for match in re.finditer(r"\bval\s+\w+\s*=\s*(bytecodePatch|rawResourcePatch|resourcePatch|patch)\s*\((.*?)\)\s*\{", text, re.S):
                kind, arguments = match.groups()
                name = re.search(r'\bname\s*=\s*"([^"]+)"', arguments)
                default = re.search(r"\bdefault\s*=\s*(true|false)\b", arguments)
                self.assertIsNotNone(name, path)
                self.assertIsNotNone(default, path)
                definitions.append((name.group(1), (kind, default.group(1) == "true")))
        self.assertEqual(3, len(definitions))
        self.assertEqual(EXPECTED_DEFINITIONS, dict(definitions))

    def test_term_compatibility_remains_finite_and_apkm(self):
        text = uncomment(read(MAIN / "termius/Compatibility.kt"))
        self.assertIn('packageName = "com.server.auditor.ssh.client"', text)
        self.assertIn("apkFileType = ApkFileType.APKM", text)
        self.assertRegex(text, r'targets\s*=\s*listOf\(AppTarget\(version = "8\.0\.1", versionCode = 1008\)\)')
        self.assertEqual(1, text.count("Compatibility("))

    def test_plex_compatibility_is_package_scoped_raw_and_unpinned(self):
        text = uncomment(read(MAIN / "plex/shared/Constants.kt"))
        self.assertIn('packageName = "com.plexapp.android"', text)
        self.assertIn("apkFileType = ApkFileType.APKM", text)
        self.assertNotRegex(text, r"\b(targets|version|versionCode)\s*=")
        self.assertEqual(1, text.count("Compatibility("))
        patch = read(MAIN / "plex/PremiumUnlockPatch.kt")
        self.assertIn("compatibleWith(COMPATIBILITY_PLEX)", patch)
        self.assertIn("val premiumUnlockPatch = rawResourcePatch(", patch)

    def test_production_and_migrated_validator_hashes_match_current_provenance(self):
        term = json.loads(read(REPO / "docs/termius-migration.json"))
        plex = json.loads(read(REPO / "docs/plex-migration.json"))
        entries = [(e["migrated"], e["migrated_sha256"]) for e in term["entries"]]
        entries += [(e["migrated_path"], e["migrated_sha256"]) for e in plex["files"]]
        entries += [(e["retained_path"], e["sha256"]) for e in plex["licenses"]]
        for name, expected in entries:
            with self.subTest(path=name):
                self.assertEqual(expected, hashlib.sha256((REPO / name).read_bytes()).hexdigest())

    def test_collection_validator_is_exact_not_subset(self):
        text = uncomment(read(MAIN / "tools/LoadedBundleMetadata.kt"))
        collection = block(text, "fun requireCollectionInventory(")
        found = re.findall(r'"([^"]+)"\s+to\s+(true|false)', collection)
        self.assertEqual({name: default for name, (_, default) in EXPECTED_DEFINITIONS.items()},
                         {name: value == "true" for name, value in found})
        self.assertIn("patches.size == defaults.size", text)
        self.assertIn("patches.map { it.name }.toSet() == defaults.keys", text)
        for policy in ("patch.dependencies.isEmpty()", "patch.options.isEmpty()", "patch is RawResourcePatch",
                       "patch is BytecodePatch", "compatibility.targets == listOf(AppTarget(version = null))", "compatibilities.size == 1",
                       "compatibility.apkFileType == ApkFileType.APKM", "compatibility.targets.size == 1",
                       "SupportedAbi.entries.associateWith { 1008 }", "compatibility.formFactor == FormFactor.MOBILE"):
            self.assertIn(policy, text)

    def test_catalog_inspection_and_runtime_validate_whole_collection(self):
        paths = (MAIN / "tools/PatchListGenerator.kt", TOOLS / "src/main/kotlin/InspectBundle.kt", TOOLS / "src/main/kotlin/RuntimeCheck.kt")
        for path in paths:
            with self.subTest(path=str(path)):
                text = uncomment(read(path))
                self.assertIn("requireCollectionInventory(loaded)", text)
                self.assertNotIn("requireTermiusInventory(", text)
                self.assertLess(text.index("requireIsolatedDefinitionLoader()"), text.index("loadPatchesFromJar(setOf(bundle))"))
                self.assertIn("projectPatchDefinitions(loaded)", text) if path.name != "PatchListGenerator.kt" else self.assertIn("generatePatchList(version, loaded)", text)
        generator = read(paths[0])
        self.assertIn("requireCollectionInventory(patches)", block(generator, "fun generatePatchList("))
        for path in paths[1:]:
            self.assertIn("projectDependencies(loaded)", read(path))

    def test_projection_keeps_intentional_empty_targets_and_actual_dependencies(self):
        generator = read(MAIN / "tools/PatchListGenerator.kt")
        self.assertIn('targets = (if (compat.packageName == "com.plexapp.android" &&', generator)
        self.assertIn('compat.targets == listOf(AppTarget(version = null))) emptyList() else compat.targets).map', generator)
        self.assertNotIn("targets.ifEmpty", generator)
        self.assertNotIn("targets.isNotEmpty", generator)
        metadata = read(MAIN / "tools/LoadedBundleMetadata.kt")
        self.assertIn("patch.dependencies.map", metadata)
        self.assertNotIn("filter", block(metadata, "private fun requireInventory("))

    def test_isolated_adapter_rejects_all_three_parent_definition_owners(self):
        text = block(read(MAIN / "tools/LoadedBundleMetadata.kt"), "fun requireIsolatedDefinitionLoader(")
        for owner in ("termius/ServerAuditorOfflineAutomationPatchKt", "termius/ServerAuditorPremiumPatchKt", "plex/PremiumUnlockPatchKt"):
            self.assertIn('"' + owner + '"', text)
        self.assertIn("parent.getResources(path).hasMoreElements()", text)

    def test_runtime_selections_never_apply_loaded_collection_or_plex(self):
        text = uncomment(read(TOOLS / "src/main/kotlin/RuntimeCheck.kt"))
        self.assertIn('loaded.single { it.name == "Server Auditor Offline Automation" }', text)
        self.assertIn('loaded.single { it.name == "Server Auditor Premium" }', text)
        self.assertNotIn('it.name == "Premium unlock"', text)
        self.assertEqual(["setOf(patch)", "selected", "setOf(makerPatch)", "setOf(premium)", "setOf(patch, premium)"],
                         re.findall(r"^\s*(?:patcher|rejected|maker|checkPremium|combined)\s*\+=\s*(.+)$", text, re.M))
        self.assertNotRegex(text, r"\b(rawResourcePatch|resourcePatch|ResourceMode)\b")
        self.assertIn('"plex_application" to "not_supported_not_attempted"', text)

    def test_catalog_has_no_explicit_or_implicit_compilation_edges(self):
        text = uncomment(read(REPO / "patches/build.gradle.kts"))
        task = block(text, 'tasks.register<JavaExec>("generatePatchesList")')
        self.assertNotRegex(task, r"\b(dependsOn|builtBy|runtimeClasspath|classesTaskName|compileKotlin|buildAndroid)\b")
        self.assertIn("files(catalogTool.output.files, configurations[catalogTool.runtimeClasspathConfigurationName].files)", task)
        self.assertIn("Catalog adapter must already be compiled", task)
        preparation = block(text, 'tasks.matching { it.name == "buildAndroid"')
        # The first block is the task selector; its configureEach dependency lives outside catalog.
        self.assertIn('it.name == "test"', preparation)
        self.assertIn("dependsOn(catalogTool.classesTaskName)", text[:text.index('tasks.register<JavaExec>("generatePatchesList")')])

    def test_arsclib_is_explicitly_pinned_on_test_classpath_only(self):
        catalog = tomllib.loads(read(REPO / "gradle/libs.versions.toml"))
        self.assertEqual("675bed2de3", catalog["versions"]["arsclib"])
        self.assertEqual({"module": "com.github.MorpheApp:ARSCLib", "version": {"ref": "arsclib"}},
                         catalog["libraries"]["arsclib"])
        coordinate = catalog["libraries"]["arsclib"]["module"] + ":" + catalog["versions"]["arsclib"]
        closure = json.loads(read(REPO / ".claude/skills/run-android-morphe/templates/cache-closure.json"))
        self.assertEqual([coordinate], [entry[0] for entry in closure["runtime"]
                                        if entry[0].startswith("com.github.MorpheApp:ARSCLib:")])
        build = uncomment(read(REPO / "patches/build.gradle.kts"))
        dependencies = block(build, "dependencies {")
        self.assertRegex(dependencies, r"(?m)^\s*testImplementation\(libs\.arsclib\)\s*$")
        # Exactly one reference in the entire build: no production/catalog scope or classpath wiring.
        self.assertEqual(["testImplementation(libs.arsclib)"],
                         [line.strip() for line in build.splitlines() if "libs.arsclib" in line])
        self.assertNotIn("com.github.MorpheApp:ARSCLib", build)

    def test_metadata_is_tools_only_not_distributable_patch_definitions(self):
        build = read(REPO / "patches/build.gradle.kts")
        self.assertIn('val catalogTool = sourceSets.create("catalogTool")', build)
        self.assertIn('kotlin.exclude("io/github/fishyau/androidpatches/tools/**")', block(build, 'kotlin.sourceSets.named("main")'))
        self.assertIn("testImplementation(catalogTool.output)", build)
        for path in (MAIN / "tools").glob("*.kt"):
            text = uncomment(read(path))
            self.assertNotRegex(text, r"\bval\s+\w+\s*:\s*(?:Patch|BytecodePatch|RawResourcePatch)\b")
            self.assertNotRegex(text, r"\b(?:bytecodePatch|rawResourcePatch|resourcePatch)\s*\(")

    def test_runner_scope_required_and_has_no_default(self):
        tree = ast.parse(read(RUNNER))
        argument = next(node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "add_argument" and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value == "--scope")
        keywords = {kw.arg: ast.literal_eval(kw.value) for kw in argument.keywords}
        self.assertIs(keywords["required"], True)
        self.assertEqual(("termius", "collection"), keywords["choices"])
        self.assertNotIn("default", keywords)
        self.assertIn('args.scope + "_uncached_jvm_compilation_tests_passed"', read(RUNNER))

    def test_runner_pure_source_selection_matches_each_scope(self):
        select, _ = source_selector()
        main, tests, projection, tools, classes = select(REPO, "termius")
        self.assertEqual(10, len(main))
        self.assertEqual(3, len(tests))
        self.assertEqual(2, len(projection))
        self.assertEqual(2, len(tools))
        self.assertFalse(any("plex" in str(p) or "collection" in str(p.relative_to(REPO)) for p in main + tests))
        self.assertTrue(all(".termius." in name for name in classes))
        main, tests, _, _, classes = select(REPO, "collection")
        self.assertEqual(EXPECTED_MAIN, {p.relative_to(MAIN).as_posix() for p in main})
        self.assertEqual(7, len(tests))
        self.assertEqual(6, len(classes))
        self.assertIn("io.github.fishyau.androidpatches.collection.CollectionInventoryTest", classes)
        with self.assertRaises(ValueError):
            select(REPO, "auto")

    def test_synthetic_extra_missing_or_unreviewed_sources_fail_closed(self):
        select, names = source_selector()
        with tempfile.TemporaryDirectory(prefix="collection-static-") as temporary:
            root = Path(temporary)
            self.assertFalse(root.is_relative_to(REPO))
            for source_set, entries in (("main", names["TERMIUS_MAIN"] + names["PLEX_MAIN"] + names["PROJECTION"]),
                                        ("test", names["TERMIUS_TESTS"] + names["PLEX_TESTS"] + names["COLLECTION_TESTS"])):
                for name in entries:
                    path = root / f"patches/src/{source_set}/kotlin" / BASE / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("// Synthetic filename-only source-policy fixture\n", encoding="utf-8")
            for name in ("InspectBundle.kt", "RuntimeCheck.kt"):
                path = root / "tools/termius-check/src/main/kotlin" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("// Synthetic fixture\n", encoding="utf-8")
            select(root, "collection")
            checker_root = root / "tools/termius-check/src/main/kotlin"
            for name in ("Unexpected.kt", "nested/Unexpected.kt", "nested/InspectBundle.kt"):
                with self.subTest(checker_source=name):
                    unexpected = checker_root / name
                    unexpected.parent.mkdir(parents=True, exist_ok=True)
                    unexpected.write_text("// Unreviewed filename-only fixture\n", encoding="utf-8")
                    for scope in ("termius", "collection"):
                        with self.assertRaises(ValueError):
                            select(root, scope)
                    unexpected.unlink()
            extra = root / "patches/src/main/kotlin" / BASE / "Universal.kt"
            extra.write_text("// Unsupported source\n", encoding="utf-8")
            for scope in ("termius", "collection"):
                with self.assertRaises(ValueError):
                    select(root, scope)
            extra.unlink()
            (root / "patches/src/main/kotlin" / BASE / names["PLEX_MAIN"][0]).unlink()
            with self.assertRaises(ValueError):
                select(root, "collection")

    def test_edited_kotlin_delimiters_balance_without_compilation(self):
        paths = [REPO / "patches/build.gradle.kts", TEST / "termius/PatchInventoryTest.kt", TEST / "collection/CollectionInventoryTest.kt"]
        paths += list((MAIN / "tools").glob("*.kt")) + list((TOOLS / "src/main/kotlin").glob("*.kt"))
        # Bounded lexical check only, not a Kotlin parser/typechecker or JVM execution.
        token = re.compile(r'""".*?"""|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|/\*.*?\*/|//[^\n]*', re.S)
        pairs = {")": "(", "]": "[", "}": "{"}
        for path in paths:
            with self.subTest(path=str(path)):
                stack = []
                for char in token.sub("", read(path)):
                    if char in "([{":
                        stack.append(char)
                    elif char in pairs:
                        self.assertTrue(stack, "Unexpected closing delimiter in " + str(path))
                        self.assertEqual(pairs[char], stack.pop())
                self.assertEqual([], stack)

    def test_authored_whole_collection_loader_and_mutation_tests_present_not_run(self):
        text = read(TEST / "collection/CollectionInventoryTest.kt")
        for fragment in ("premiumUnlockPatch", "loadPatchesFromJar(setOf(jar))", "requireCollectionInventory(loaded)",
                         "assertEquals(3, loaded.size)", "projectDependencies(loaded)", "resourcePatch(name =",
                         "dependency = true", "option = true", "default = !accepted[index].default", "compatibilities = emptyList()"):
            self.assertIn(fragment, text)
        narrow = read(TEST / "termius/PatchInventoryTest.kt")
        self.assertNotIn("loadPatchesFromJar", narrow)
        self.assertIn("termiusSubsetCannotBlessWholeCollectionOrCatalog", narrow)

    def test_no_fake_live_manifest_or_generated_app_binaries(self):
        self.assertFalse((REPO / "patches-bundle.json").exists())
        forbidden = {".apk", ".apkm", ".mpp", ".dex", ".so", ".aar", ".class", ".keystore", ".jks", ".p12"}
        unexpected = [p.relative_to(REPO).as_posix() for p in REPO.rglob("*") if p.is_file() and p.suffix.lower() in forbidden]
        self.assertEqual([], unexpected)
        jars = [p.relative_to(REPO).as_posix() for p in REPO.rglob("*.jar")]
        self.assertTrue(set(jars) <= {"gradle/wrapper/gradle-wrapper.jar"}, jars)


class TermiusDefaultAdaptationTests(unittest.TestCase):
    """Python text-only migration checks: never compile or execute donor/Kotlin code."""
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("migration_audit", TOOLS / "verify_migration.py")
        cls.audit = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.audit)
        cls.name = "ServerAuditorPremiumPatch.kt"
        cls.current = (MAIN / "termius" / cls.name).read_bytes()
        # Synthetic text donor, not donor code execution. Exact full-donor hashes remain separately pinned.
        cls.original = cls.current.replace(cls.audit.NEW.encode(), cls.audit.OLD.encode(), 1).replace(
            b'    default = true,', b'    default = false,', 1)

    def test_only_exact_premium_default_adaptation_is_accepted(self):
        changes = self.audit.compare_source(self.original, self.current, "main", self.name)
        record = json.loads(read(REPO / "docs/termius-migration.json"))
        premium = next(e for e in record["entries"] if e["migrated"].endswith("/" + self.name))
        self.assertEqual(premium["modifications"][-1], changes[-1])
        self.audit.compare_source(self.original.replace(b'\n', b'\r\n'), self.current, "main", self.name)
        with self.assertRaises(ValueError):
            self.audit.compare_source(self.original, self.current.replace(b'    default = true,', b'    default = false,'), "main", self.name)

    def test_default_allowance_does_not_mask_algorithm_guard_description_or_compatibility_edits(self):
        for before, after in ((b'USER_TYPE_PRO =', b'USER_TYPE_ALTERED ='),
                              (b'compatibleWith(SERVER_AUDITOR_COMPATIBILITY)', b'compatibleWith(OTHER)'),
                              (b'PremiumPatchValidation.requireMapperLayout(', b'PremiumPatchValidation.changedLayout('),
                              (b'Optional legacy Pro', b'Changed legacy Pro')):
            # Require each negative to actually change the source, not silently retest accepted bytes.
            self.assertIn(before, self.current)
            changed = self.current.replace(before, after, 1)
            self.assertNotEqual(self.current, changed)
            with self.subTest(edit=before), self.assertRaises(ValueError):
                self.audit.compare_source(self.original, changed, "main", self.name)

    def test_default_allowance_is_limited_to_named_production_declaration(self):
        for source_set, name in (("test", self.name), ("main", "ServerAuditorOfflineAutomationPatch.kt")):
            with self.subTest(source_set=source_set, name=name), self.assertRaises(ValueError):
                self.audit.compare_source(self.original, self.current, source_set, name)
        for original in (self.original.replace(b'    default = false,', b'    default = true,'), self.original + self.original):
            with self.assertRaisesRegex(ValueError, 'donor default declaration'):
                self.audit.compare_source(original, self.current, "main", self.name)
        # A second false default inside the same source must not be transformed.
        with self.assertRaises(ValueError):
            self.audit.compare_source(self.original + b'\nval other = false\n', self.current + b'\nval other = true\n', "main", self.name)

    def test_current_hashes_and_original_source_digest_are_separate_from_default_adaptation(self):
        record = json.loads(read(REPO / "docs/termius-migration.json"))
        for key in ("original_sha256", "migrated_sha256"):
            self.assertEqual(record[key.replace("_sha256", "_source_sha256")], self.audit.tree(record["entries"], key))
        self.assertEqual("9a1f72ff0ed5a666f3d2a136514880670cf0158e993f87da1164fcc11b035b60", record["original_source_sha256"])
        premium = next(e for e in record["entries"] if e["migrated"].endswith("/" + self.name))
        self.assertEqual("6b200733bc869e88fe959e19c98750bb4a3a3730264f8d6386df3fa30575f736", premium["original_sha256"])
        adaptation = record["default_selection_adaptation"]
        self.assertEqual("Both Termius patches should be enabled by default.", adaptation["request"])
        self.assertEqual("2026-11-09", adaptation["date"])
        self.assertIs(adaptation["original_default"], False)
        self.assertIs(adaptation["current_default"], True)
        self.assertIs(adaptation["combined_android_runtime_acceptance_claimed"], False)
        self.assertEqual([True, False], [p["default"] for p in record["accepted_existing_behavior"]["patches"]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
