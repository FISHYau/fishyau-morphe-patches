"""Offline synthetic/static source-policy regressions; never compile/load Kotlin or run JVM/Gradle.

Evaluates the Python runner's pure path-selection function (extracted by AST)
and public-format helpers, without running main/subprocess code. Synthetic
fixtures live in external OS temporary scratch; no binaries/live manifest written.
"""
import ast
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import tomllib
import unittest
from unittest import mock

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
    "spotify/HomePreviewPatch.kt", "spotify/HomePreviewSnapshots.kt", "spotify/HomePreviewValidation.kt", "spotify/Compatibility.kt",
    "tools/LoadedBundleMetadata.kt", "tools/PatchListGenerator.kt",
}
EXPECTED_DEFINITIONS = {
    "Server Auditor Offline Automation": ("bytecodePatch", True),
    "Server Auditor Premium": ("bytecodePatch", True),
    "Premium unlock": ("rawResourcePatch", True),
    "Disable Home previews": ("bytecodePatch", True),
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
    names = {"TERMIUS_MAIN", "PLEX_MAIN", "SPOTIFY_MAIN", "PROJECTION", "TERMIUS_TESTS", "PLEX_TESTS", "SPOTIFY_TESTS", "COLLECTION_TESTS"}
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

    def test_exact_four_declarations_types_and_explicit_defaults(self):
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
        self.assertEqual(4, len(definitions))
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

    def test_spotify_compatibility_is_finite_tv_required_container_and_default_on(self):
        text = uncomment(read(MAIN / "spotify/Compatibility.kt"))
        self.assertIn('packageName = "com.spotify.tv.android"', text)
        self.assertIn("apkFileType = ApkFileType.APKM_REQUIRED", text)
        self.assertIn("formFactor = FormFactor.TV", text)
        self.assertRegex(text, r'AppTarget\(\s*version\s*=\s*"9\.1\.94\.1926",\s*versionCode\s*=\s*147600562\s*,?\s*\)')
        self.assertEqual(1, text.count("Compatibility("))
        self.assertNotRegex(text, r"\b(signatures|options|dependsOn)\s*[(=]")
        patch = uncomment(read(MAIN / "spotify/HomePreviewPatch.kt"))
        self.assertRegex(patch, r"val\s+disableHomePreviewsPatch\s*=\s*bytecodePatch\(")
        self.assertRegex(patch, r"\bdefault\s*=\s*true\b")
        self.assertNotRegex(patch, r"\b(dependsOn|\w+Option)\s*\(")
        self.assertEqual({"HomePreviewPatch.kt", "HomePreviewSnapshots.kt", "HomePreviewValidation.kt", "Compatibility.kt"},
                         {p.name for p in (MAIN / "spotify").glob("*.kt")})
        self.assertEqual({"HomePreviewPatchTest.kt"}, {p.name for p in (TEST / "spotify").glob("*.kt")})

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
                       "SupportedAbi.entries.associateWith { 1008 }", "compatibility.formFactor == FormFactor.MOBILE",
                       "SupportedAbi.entries.associateWith { 147600562 }", "compatibility.formFactor == FormFactor.TV",
                       "compatibility.apkFileType == ApkFileType.APKM_REQUIRED", 'target.version == "9.1.94.1926"'):
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

    def test_isolated_adapter_rejects_all_four_parent_definition_owners(self):
        text = block(read(MAIN / "tools/LoadedBundleMetadata.kt"), "fun requireIsolatedDefinitionLoader(")
        for owner in ("termius/ServerAuditorOfflineAutomationPatchKt", "termius/ServerAuditorPremiumPatchKt", "plex/PremiumUnlockPatchKt", "spotify/HomePreviewPatchKt"):
            self.assertIn('"' + owner + '"', text)
        self.assertIn("parent.getResources(path).hasMoreElements()", text)
        self.assertIn("parent: ClassLoader = ClassLoader.getSystemClassLoader()",
                      read(MAIN / "tools/LoadedBundleMetadata.kt"))

    def test_isolated_adapter_covers_declared_spotify_owners_and_known_generated_helpers(self):
        # Source-only declaration coverage, NOT compiled class-family exhaustiveness.
        # The JVM regression inspects actual directory/JAR output and probes each class.
        # File facades exist for top-level properties/functions, not object-only files.
        declared = set()
        for path in (MAIN / "spotify").glob("*.kt"):
            source = uncomment(read(path))
            declared.update(re.findall(
                r"(?m)^(?:(?:internal|private|public|data|enum|sealed|open|abstract)\s+)*(?:class|object)\s+(\w+)", source))
            if re.search(r"(?m)^(?:(?:internal|private|public)\s+)*(?:val|var|fun)\s+", source):
                declared.add(path.stem + "Kt")
        # Nested declaration is outside the bounded top-level regex above.
        declared.add("PreviewExecution$Descriptor")
        generated = {
            "PreviewEdits$WhenMappings", "PreviewExecution$executeProduction$1",
            "CandidateSnapshots$annotations$lambda$0$$inlined$sortedBy$1",
            "CandidateSnapshots$method$lambda$0$$inlined$sortedBy$1",
            "CandidateSnapshots$WhenMappings",
        }
        self.assertTrue(declared.isdisjoint(generated))
        text = block(read(MAIN / "tools/LoadedBundleMetadata.kt"), "fun requireIsolatedDefinitionLoader(")
        guarded = {owner.replace(r"\$", "$") for owner in re.findall(r'"spotify/([^"\n]+)"', text)}
        self.assertEqual(declared, guarded - generated)
        self.assertTrue(generated <= guarded)
        self.assertTrue({"PreviewExecution", "CompatibilityKt", "CandidateSnapshots", "PreviewAssertions"} <= guarded)
        self.assertNotIn("Class.forName", text)
        self.assertNotIn("loadClass", text)
        self.assertNotRegex(read(MAIN / "tools/LoadedBundleMetadata.kt"), r"(?m)^import .*\.spotify\.")

    def test_authored_helper_only_loader_regressions_are_independent(self):
        text = read(TEST / "collection/CollectionInventoryTest.kt")
        for name, owner in (("helperOnlyPreviewExecutionParentIsRejectedBeforeLoading", "PreviewExecution"),
                            ("helperOnlyCompatibilityParentIsRejectedBeforeLoading", "CompatibilityKt")):
            case = block(text, "fun " + name + "(")
            self.assertIn('withIsolatedParentResource("spotify/' + owner + '")', case)
            self.assertIn("requireIsolatedDefinitionLoader(parent)", case)
            self.assertIn("assertThrows(IllegalArgumentException::class.java)", case)
        fixture = block(text, "fun withIsolatedParentResource(")
        self.assertIn("URLClassLoader(arrayOf(jar.toURI().toURL()), null)", fixture)
        self.assertIn('assertNull(parent.getResource("io/github/fishyau/androidpatches/spotify/"))', fixture)
        self.assertIn('assertNull(parent.getResource("io/github/fishyau/androidpatches/$definition.class"))', fixture)

    def test_runtime_selections_never_apply_loaded_collection_plex_or_spotify(self):
        text = uncomment(read(TOOLS / "src/main/kotlin/RuntimeCheck.kt"))
        self.assertIn('loaded.single { it.name == "Server Auditor Offline Automation" }', text)
        self.assertIn('loaded.single { it.name == "Server Auditor Premium" }', text)
        self.assertNotIn('it.name == "Premium unlock"', text)
        self.assertNotIn('it.name == "Disable Home previews"', text)
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
        self.assertFalse(any(part in str(p.relative_to(REPO)) for p in main + tests for part in ("plex", "spotify", "collection")))
        self.assertTrue(all(".termius." in name for name in classes))
        main, tests, _, _, classes = select(REPO, "collection")
        self.assertEqual(EXPECTED_MAIN, {p.relative_to(MAIN).as_posix() for p in main})
        self.assertEqual(8, len(tests))
        self.assertEqual(7, len(classes))
        self.assertIn("io.github.fishyau.androidpatches.spotify.HomePreviewPatchTest", classes)
        self.assertEqual({"spotify/HomePreviewPatchTest.kt"}, {p.relative_to(TEST).as_posix() for p in tests if "spotify" in p.parts})
        self.assertIn("io.github.fishyau.androidpatches.collection.CollectionInventoryTest", classes)
        with self.assertRaises(ValueError):
            select(REPO, "auto")

    def test_checker_compilation_and_parent_classpath_remain_tools_only(self):
        runner = read(RUNNER)
        self.assertIn('compile_kotlin("compile-checker", tool_sources + projection, tool, runtime)', runner)
        self.assertIn('os.pathsep.join(map(str, [tool] + runtime))', runner)
        build = read(REPO / "patches/build.gradle.kts")
        catalog = block(build, 'kotlin.sourceSets.named("catalogTool")')
        self.assertIn('kotlin.srcDir("src/main/kotlin/io/github/fishyau/androidpatches/tools")', catalog)
        self.assertNotIn("spotify", catalog)
        self.assertNotIn("termius", catalog)
        self.assertNotIn("plex", catalog)

    def test_synthetic_auth_session_preservation_is_not_runtime_proof(self):
        tests = read(TEST / "spotify/HomePreviewPatchTest.kt")
        self.assertIn("syntheticSignInRefreshSignOutAndReauthenticationSentinelsRemainByteForByteUntouched", tests)
        self.assertIn("NOT real authentication behavior", tests)
        for sentinel in ('"signIn"', '"tokenRefresh"', '"signOut"', '"reauthenticate"'):
            self.assertIn(sentinel, tests)

    def test_synthetic_extra_missing_or_unreviewed_sources_fail_closed(self):
        select, names = source_selector()
        with tempfile.TemporaryDirectory(prefix="collection-static-") as temporary:
            root = Path(temporary)
            self.assertFalse(root.is_relative_to(REPO))
            for source_set, entries in (("main", names["TERMIUS_MAIN"] + names["PLEX_MAIN"] + names["SPOTIFY_MAIN"] + names["PROJECTION"]),
                                        ("test", names["TERMIUS_TESTS"] + names["PLEX_TESTS"] + names["SPOTIFY_TESTS"] + names["COLLECTION_TESTS"])):
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
                         "assertEquals(4, loaded.size)", "disableHomePreviewsPatch", "projectDependencies(loaded)", "resourcePatch(name =",
                         "dependency = true", "option = true", "default = !accepted[index].default", "compatibilities = emptyList()"):
            self.assertIn(fragment, text)
        narrow = read(TEST / "termius/PatchInventoryTest.kt")
        self.assertNotIn("loadPatchesFromJar", narrow)
        self.assertIn("termiusSubsetCannotBlessWholeCollectionOrCatalog", narrow)

    def test_public_manifest_format_and_no_generated_app_binaries(self):
        # The manifest is absent before first publication. Once published, check
        # its ordinary public format offline; presence is not hosted-flow proof.
        manifest_path = REPO / "patches-bundle.json"
        if manifest_path.exists():
            spec = importlib.util.spec_from_file_location("source_public_formats", REPO / "tools/bundle_formats.py")
            formats = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(formats)
            manifest, _ = formats.read_json(manifest_path)
            formats.validate_manifest(manifest, "FISHYau", "fishyau-morphe-patches", manifest["version"])
            self.assertIsNone(manifest.get("public_key"), "current publisher supports unsigned bundles only")
        forbidden = {".apk", ".apkm", ".mpp", ".dex", ".so", ".aar", ".class", ".keystore", ".jks", ".p12"}
        unexpected = [p.relative_to(REPO).as_posix() for p in REPO.rglob("*") if p.is_file() and p.suffix.lower() in forbidden]
        self.assertEqual([], unexpected)
        jars = [p.relative_to(REPO).as_posix() for p in REPO.rglob("*.jar")]
        self.assertTrue(set(jars) <= {"gradle/wrapper/gradle-wrapper.jar"}, jars)

    def test_source_policy_handles_absent_valid_and_wrong_manifest_offline(self):
        with tempfile.TemporaryDirectory(prefix="source-manifest-synthetic-") as temporary:
            root = Path(temporary)
            (root / "tools").mkdir()
            (root / "tools/bundle_formats.py").write_bytes((REPO / "tools/bundle_formats.py").read_bytes())
            manifest = {
                "version": "0.0.0-test",
                "download_url": "https://github.com/FISHYau/fishyau-morphe-patches/releases/download/v0.0.0-test/patches-0.0.0-test.mpp",
                "created_at": "2026-11-10T00:00:00",
                "description": "Synthetic offline fixture, not a hosted release",
            }
            with mock.patch.dict(globals(), REPO=root):
                self.test_public_manifest_format_and_no_generated_app_binaries()
                path = root / "patches-bundle.json"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                self.test_public_manifest_format_and_no_generated_app_binaries()
                manifest["download_url"] = "https://example.invalid/wrong.mpp"
                path.write_text(json.dumps(manifest), encoding="utf-8")
                with self.assertRaises(ValueError):
                    self.test_public_manifest_format_and_no_generated_app_binaries()


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
