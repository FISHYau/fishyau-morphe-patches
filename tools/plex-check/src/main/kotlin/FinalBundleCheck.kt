@file:Suppress("DEPRECATION")
package io.github.fishyau.androidpatches.plexcheck

import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.RawResourcePatch
import app.morphe.patcher.patch.ResourcePatchContext
import app.morphe.patcher.patch.loadPatchesFromJar
import app.morphe.patcher.resource.ResourceMode
import com.reandroid.arsc.chunk.TableBlock
import com.google.gson.JsonParser
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.google.gson.JsonArray
import com.google.gson.JsonPrimitive
import com.google.gson.JsonNull
import com.google.gson.Strictness
import com.google.gson.stream.JsonReader
import com.google.gson.stream.JsonToken
import java.io.StringReader
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.time.LocalDateTime
import java.time.ZoneOffset
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock
import io.github.fishyau.androidpatches.tools.*
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.time.Instant
import java.security.MessageDigest
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

private val decoded = """<manifest android:requiredSplitTypes="base__abi" android:splitTypes="" keep="yes"><application android:extractNativeLibs="false" /></manifest>""".toByteArray()
private val cleaned = """<manifest keep="yes"><application android:extractNativeLibs="true" /></manifest>""".toByteArray()
private fun save(file: File, bytes: ByteArray) = Files.write(file.toPath(), bytes, CREATE_NEW, WRITE)
private fun record(file: File): Map<String, Any?> = mapOf("path" to file.canonicalPath, "exists" to file.isFile,
    "sha256" to if (file.isFile) sha256(file) else null, "bytes" to if (file.isFile) file.length() else null)
private fun same(expected: ByteArray, file: File) = check(file.isFile && expected.contentEquals(file.readBytes())) { "Exact byte assertion failed: $file" }

/** Fail before the loader if ANY production Plex helper could shadow bundle code. */
private fun isolated() {
    requireIsolatedDefinitionLoader()
    val parent = ClassLoader.getSystemClassLoader()
    listOf("HermesBundle", "HermesBundle\$Companion", "HermesFormatException", "Constants", "ConstantsKt").forEach {
        check(!parent.getResources("io/github/fishyau/androidpatches/plex/shared/$it.class").hasMoreElements()) {
            "Production Plex helper on parent classpath: $it"
        }
    }
}

/** A FULL-prepared fixture must already be decoded before any patch can run. */
internal fun decodedManifestSnapshot(file: File): ByteArray {
    check(file.isFile) { "FULL preparation did not materialize decoded manifest before patch execution: $file" }
    val bytes = file.readBytes()
    val text = bytes.toString(Charsets.UTF_8)
    check(text.trimStart().startsWith("<") && text.contains("<manifest") && text.contains("<application") &&
        text.contains("package=\"dev.fishyau.plexfixture\"") && text.contains("android:extractNativeLibs=\"false\"") &&
        '\u0000' !in text) { "FULL preparation did not produce expected decoded fixture manifest before patch execution: $file" }
    return bytes
}

internal fun exercise(patch: RawResourcePatch, root: File, name: String, fixture: FinalBundleFixtures.Fixture,
                     expected: ByteArray = FinalBundleFixtures.expected(fixture),
                     manifest: ByteArray? = null, manifestExpected: ByteArray? = manifest,
                     rejection: String? = null, repeat: Boolean = false, decode: Boolean = false): Map<String, Any?> {
    val start = Instant.now(); val nanos = System.nanoTime()
    val result = linkedMapOf<String, Any?>("name" to name, "status" to "failed", "started_at" to start.toString())
    val directory = root.resolve(name)
    check(directory.mkdir()) { "Case output must be NEW: $directory" }
    val input = directory.resolve("synthetic-noninstallable.zip")
    val before = directory.resolve("input.bundle"); save(before, fixture.bytes)
    val expect = directory.resolve("expected.bundle"); save(expect, expected)
    var ctx: ResourcePatchContext? = null
    var bundle: File? = null; var manifestFile: File? = null
    var beforeManifest: ByteArray? = null
    try {
        val binary = AndroidManifestBlock.empty().apply {
            setPackageName("dev.fishyau.plexfixture"); setVersionName("1.0"); setVersionCode(1)
            setExtractNativeLibs(false); refreshFull()
        }.bytes
        ZipOutputStream(Files.newOutputStream(input.toPath(), CREATE_NEW, WRITE)).use { zip ->
            for ((entry, bytes) in listOf("assets/index.android.bundle" to fixture.bytes, "AndroidManifest.xml" to binary,
                                         "assets/unrelated.bin" to byteArrayOf(9, 8, 7, 0, -1))) {
                zip.putNextEntry(ZipEntry(entry)); zip.write(bytes); zip.closeEntry()
            }
            if (decode) {
                // The direct context constructor bypasses Patcher preparation.
                // FULL decoding requires a genuine binary resource table as well
                // as the binary manifest; never stage text or fake package.json.
                val table = TableBlock().apply {
                    newPackage(0x7f, "dev.fishyau.plexfixture")
                        .getOrCreate("", "string", "fixture_label").setValueAsString("Fixture")
                    refreshFull()
                }
                zip.putNextEntry(ZipEntry("resources.arsc")); zip.write(table.bytes); zip.closeEntry()
            }
        }
        result["fixture_zip"] = record(input)
        val config = PatcherConfig(apkFile = input, temporaryFilesPath = directory.resolve("temporary"), fileWorkspacePath = directory.resolve("workspace"))
        ctx = ResourcePatchContext::class.java.getConstructor(PatcherConfig::class.java).newInstance(config)
        if (decode) {
            // Invoke the pinned JVM-visible preparation API, just as the source
            // test does. This is explicit FULL preparation, NOT RAW lazy decode.
            ResourcePatchContext::class.java.getMethod(
                "decodeResources\$morphe_patcher", ResourceMode::class.java
            ).invoke(ctx, ResourceMode.FULL)
        }
        bundle = ctx.get("assets/index.android.bundle")
        manifestFile = ctx.get("AndroidManifest.xml")
        if (!decode) {
            if (manifest == null) check(!manifestFile.exists() || manifestFile.delete())
            else { manifestFile.parentFile.mkdirs(); manifestFile.writeBytes(manifest) }
        }
        beforeManifest = if (decode) decodedManifestSnapshot(manifestFile)
                         else if (manifestFile.isFile) manifestFile.readBytes() else null
        // Compute the exact allowed edit before execute, after proving that the
        // real decoder has materialized the expected unpatched fixture content.
        val decodedExpected = if (decode) checkNotNull(beforeManifest).toString(Charsets.UTF_8)
            .replace("android:extractNativeLibs=\"false\"", "android:extractNativeLibs=\"true\"").toByteArray() else null
        if (beforeManifest != null) save(directory.resolve("input.manifest"), beforeManifest)
        same(fixture.bytes, bundle)
        val unrelated = ctx.get("assets/unrelated.bin")
        same(byteArrayOf(9, 8, 7, 0, -1), unrelated)
        val calls = mutableListOf<Map<String, Any?>>()
        result["execute_calls"] = calls
        for (call in 1..(if (repeat) 2 else 1)) {
            val callStart = Instant.now(); val callNanos = System.nanoTime()
            var caught: PatchException? = null
            try { patch.execute(ctx) } catch (e: PatchException) { caught = e }
            finally { calls.add(mapOf("index" to call, "started_at" to callStart.toString(),
                "finished_at" to Instant.now().toString(), "elapsed_ns" to System.nanoTime() - callNanos,
                "exception" to caught?.javaClass?.name, "message" to caught?.message)) }
            if (rejection != null) {
                check(caught != null && caught.message.orEmpty().contains(rejection)) { "Expected PatchException containing '$rejection', got $caught" }
            } else check(caught == null) { "Unexpected patch rejection: $caught" }
            same(expected, bundle)
            if (call == 1 && repeat) save(directory.resolve("first-output.bundle"), bundle.readBytes())
        }
        if (rejection != null) {
            same(fixture.bytes, bundle)
            if (beforeManifest == null) check(!manifestFile.exists()) else same(beforeManifest, manifestFile)
        } else {
            if (decode) {
                same(checkNotNull(decodedExpected), manifestFile)
            } else if (manifestExpected == null) check(!manifestFile.exists()) else same(manifestExpected, manifestFile)
            val after = bundle.readBytes()
            val footer = MessageDigest.getInstance("SHA-1").digest(after.copyOf(after.size - 20))
            check(footer.contentEquals(after.takeLast(20).toByteArray())) { "Independent SHA-1 footer mismatch" }
        }
        same(byteArrayOf(9, 8, 7, 0, -1), unrelated)
        val unrelatedSnapshot = directory.resolve("output.unrelated")
        save(unrelatedSnapshot, unrelated.readBytes())
        result["unrelated_resource"] = record(unrelatedSnapshot)
        check(sha256(input) == (result["fixture_zip"] as Map<*, *>)["sha256"]) { "Synthetic source ZIP changed" }
        result["expected_rejection"] = rejection
        result["status"] = if (rejection == null) "resource_bytes_verified" else "rejected_without_writes"
    } catch (e: Exception) {
        result["error"] = e.toString()
    } finally {
        try {
            if (bundle?.isFile == true) save(directory.resolve("output.bundle"), bundle.readBytes())
            if (manifestFile?.isFile == true) save(directory.resolve("output.manifest"), manifestFile.readBytes())
            result["input_bundle"] = record(before); result["expected_bundle"] = record(expect)
            result["output_bundle"] = record(directory.resolve("output.bundle"))
            result["input_manifest"] = record(directory.resolve("input.manifest"))
            result["output_manifest"] = record(directory.resolve("output.manifest"))
            result["retained_directory"] = directory.canonicalPath
            result["working_bundle"] = bundle?.canonicalPath
            result["working_manifest"] = manifestFile?.canonicalPath
        } finally {
            try { ctx?.close() } catch (e: Exception) { result["status"] = "failed"; result["close_error"] = e.toString() }
            result["finished_at"] = Instant.now().toString(); result["elapsed_ns"] = System.nanoTime() - nanos
            save(directory.resolve("case.json"), metadataGson.toJson(result).toByteArray())
        }
    }
    return result
}

/** Strict JSON, including duplicate keys and numeric token types, before observations. */
internal fun frozenJson(bytes: ByteArray): JsonElement {
    val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
    return JsonReader(StringReader(text)).use { reader ->
        reader.strictness = Strictness.STRICT
        fun read(depth: Int): JsonElement {
            require(depth < 64) { "JSON nesting limit" }
            return when (reader.peek()) {
                JsonToken.BEGIN_OBJECT -> JsonObject().apply {
                    reader.beginObject()
                    while (reader.hasNext()) {
                        val key = reader.nextName()
                        require(!has(key)) { "Duplicate JSON key: $key" }
                        add(key, read(depth + 1))
                    }
                    reader.endObject()
                }
                JsonToken.BEGIN_ARRAY -> JsonArray().apply {
                    reader.beginArray(); while (reader.hasNext()) add(read(depth + 1)); reader.endArray()
                }
                JsonToken.STRING -> JsonPrimitive(reader.nextString())
                JsonToken.NUMBER -> JsonParser.parseString(reader.nextString())
                JsonToken.BOOLEAN -> JsonPrimitive(reader.nextBoolean())
                JsonToken.NULL -> { reader.nextNull(); JsonNull.INSTANCE }
                else -> error("Invalid JSON token")
            }
        }
        read(0).also { require(reader.peek() == JsonToken.END_DOCUMENT) { "Trailing JSON" } }
    }
}

private fun JsonObject.string(key: String): String {
    val value = get(key)
    require(value != null && value.isJsonPrimitive && value.asJsonPrimitive.isString) { "String required: $key" }
    return value.asString
}

/** Hash the actual source entries with release.source_tree's exact byte contract. */
private fun frozenSource(root: File): Map<String, String> {
    require(root.isDirectory)
    return root.walkTopDown().onEnter { it != root.resolve(".git") }.mapNotNull { file ->
        require(!Files.isSymbolicLink(file.toPath())) { "Linked source" }
        if (file.isDirectory) null else {
            require(file.isFile)
            file.relativeTo(root).invariantSeparatorsPath to sha256(file)
        }
    }.toMap().toSortedMap()
}

/** Shared by native main and the tools-only probe; does not open/load any MPP. */
fun validateFrozenRequest(bytes: ByteArray, bundleHash: String, catalogHash: String,
                                   treeHash: String, sourceRoot: File): JsonObject {
    require(bytes.size <= 65536)
    val request = frozenJson(bytes).asJsonObject
    require(request.keySet() == setOf("schema", "policy", "owner", "repository", "version", "created_at",
        "description", "bundle_sha256", "catalog_sha256", "source_tree_sha256", "provenance")) { "Exact schema2 fields required" }
    val schema = request.get("schema")
    require(schema.isJsonPrimitive && schema.asJsonPrimitive.isNumber && schema.toString() == "2") { "Integer schema2 required" }
    require(request.string("policy") == "initial-three-patch-collection-v2")
    require(request.string("owner") == "FISHYau" && request.string("repository") == "fishyau-morphe-patches"
        && request.string("version") == "0.1.0") { "Target/version mismatch" }
    val created = request.string("created_at")
    require(created.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,9})?"))) { "Offset-free UTC timestamp required" }
    val whenCreated = LocalDateTime.parse(created)
    require(whenCreated.year in 1..9999 && !whenCreated.toInstant(ZoneOffset.UTC).isAfter(Instant.now())) { "Invalid/future creation date" }
    val description = request.string("description")
    require(description.any { !it.isWhitespace() } && description.none { it.code < 32 || it.code == 127 }) { "Invalid description" }
    for ((key, expected) in mapOf("bundle_sha256" to bundleHash, "catalog_sha256" to catalogHash, "source_tree_sha256" to treeHash)) {
        require(request.string(key).matches(Regex("[0-9a-f]{64}")) && request.string(key) == expected) { "Digest mismatch: $key" }
    }
    val paths = frozenSource(sourceRoot)
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update("release-tree-v1\u0000".toByteArray())
    paths.forEach { (path, hash) -> digest.update((path + "\u0000" + hash + "\n").toByteArray(Charsets.UTF_8)) }
    require(digest.digest().joinToString("") { "%02x".format(it) } == treeHash) { "Actual source tree mismatch" }

    // Pin the reviewed migration records, then derive their file projections rather
    // than maintaining another copy of every staging.py original/migrated hash.
    fun migration(name: String, hash: String): JsonObject {
        val file = sourceRoot.resolve("docs/$name-migration.json")
        require(sha256(file) == hash) { "Unreviewed $name migration record" }
        return frozenJson(file.readBytes()).asJsonObject
    }
    val termius = migration("termius", "5115547e2ac8a1109dcc180eff6e7cde311948f57f3df66e4291d31a25df2edd")
    val plex = migration("plex", "2f75ab3be4f8eba720d6480a7762881cc50aef63662e5e50bd7387b3c5442a11")
    val prefix = "patches/src/main/kotlin/io/github/fishyau/androidpatches/"
    fun fileRow(path: String, original: String, migrated: String): Map<String, String> {
        require(paths[path] == migrated) { "Migrated source mismatch: $path" }
        return mapOf("path" to path, "original_sha256" to original, "migrated_sha256" to migrated)
    }
    val tfiles = termius.getAsJsonArray("entries").map { it.asJsonObject }
        .filter { it.string("migrated").startsWith(prefix + "termius/") }
        .map { fileRow(it.string("migrated"), it.string("original_sha256"), it.string("migrated_sha256")) }.sortedBy { it.getValue("path") }
    val pfiles = (plex.getAsJsonArray("files").map { it.asJsonObject }.map {
        fileRow(it.string("migrated_path"), it.string("original_sha256"), it.string("migrated_sha256"))
    } + plex.getAsJsonArray("licenses").map { it.asJsonObject }.map {
        fileRow(it.string("retained_path"), it.string("sha256"), it.string("sha256"))
    }).sortedBy { it.getValue("path") }
    require(paths.keys.filter { it.startsWith(prefix + "termius/") && it.endsWith(".kt") }.toSet() == tfiles.map { it.getValue("path") }.toSet())
    require(paths.keys.filter { it.startsWith(prefix + "plex/") }.toSet() == pfiles.map { it.getValue("path") }.toSet())
    val expected = metadataGson.toJsonTree(mapOf(
        "termius" to mapOf("status" to "accepted-existing-behavior", "basis" to "user-confirmed-tested-working",
            "adaptations" to "mechanical-namespace-import-helper-isolation-user-requested-premium-default-on-2026-11-09", "files" to tfiles),
        "plex" to mapOf("repository" to "https://github.com/UnkyBadTouch/plex-morphe-patches",
            "revision" to "38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f", "basis" to "reviewed-source-migration-not-runtime-acceptance", "files" to pfiles)))
    val provenance = request.getAsJsonObject("provenance").deepCopy()
    // Staging accepts Termius file ordering independently of the request's byte hash.
    val actualTermius = provenance.getAsJsonObject("termius")
    actualTermius.add("files", JsonArray().apply {
        actualTermius.getAsJsonArray("files").sortedBy { it.asJsonObject.string("path") }.forEach { add(it) }
    })
    require(provenance == expected) { "Pinned collection provenance mismatch" }
    return request
}

/** Only an exact supplied FINAL Android MPP can reach the actual-loader/resource cases. */
fun main(args: Array<String>) {
    require(args.size == 7) { "bundle.mpp catalog.json frozen-request.json NEW-native-report.json NEW-cases-dir source-tree-sha256 source-root" }
    val bundle = File(args[0]).canonicalFile; val catalog = File(args[1]).canonicalFile
    val requestFile = File(args[2]).canonicalFile; val reportFile = File(args[3]).canonicalFile
    val casesRoot = File(args[4]).canonicalFile
    require(!reportFile.exists() && reportFile.parentFile.isDirectory && !casesRoot.exists())
    val report = linkedMapOf<String, Any?>("schema" to "plex-final-bundle-native-v1", "status" to "failed",
        "started_at" to Instant.now().toString(), "request_sha256" to sha256(requestFile),
        "source_tree_sha256" to args[5], "actual_definition" to "not_observed", "resource_execution" to "not_observed",
        "scope" to "Synthetic noninstallable HBC96 resource fixtures only; not APKM merge, signing, ART, Manager or Plex application acceptance")
    val start = System.nanoTime()
    val inputHashes = listOf(bundle, catalog, requestFile).associateWith { sha256(it) }
    try {
        val request = validateFrozenRequest(requestFile.readBytes(), inputHashes.getValue(bundle),
            inputHashes.getValue(catalog), args[5], File(args[6]).canonicalFile)
        check(sha256(requestFile) == report["request_sha256"]) { "Request changed before loader" }
        require(bundle.extension == "mpp" && bundle.length() in 22..(64L * 1024 * 1024))
        val version = JarFile(bundle).use { jar ->
            val names = jar.entries().asSequence().map { it.name }.toList()
            check(names.size == names.toSet().size)
            check(names.none { it.matches(Regex("(?i).*(\\.(sf|rsa|dsa|ec|sig)|(^|/)signature(\\.[^/]*)?)$")) })
            val dex = requireNotNull(jar.getEntry("classes.dex"))
            val magic = jar.getInputStream(dex).use { it.readNBytes(8) }
            check(String(magic, Charsets.ISO_8859_1).matches(Regex("dex\\n0(3[5-9]|4[01])\\u0000")))
            val attrs = requireNotNull(jar.manifest).mainAttributes
            check(attrs.getValue("Patcher-Version") == "2.3.0")
            check(attrs.getValue("Name") == "FISHYau android patches" && attrs.getValue("Author") == "FISHYau")
            requireNotNull(attrs.getValue("Version")).also { check(it == request.string("version")) { "Bundle/request version mismatch" } }
        }
        isolated()
        report["parent_classpath"] = System.getProperty("java.class.path")
        report["classpath_isolation"] = "definition_and_production_plex_helper_resources_absent"
        val loaded = loadPatchesFromJar(setOf(bundle))
        requireCollectionInventory(loaded)
        val definitions = projectPatchDefinitions(loaded)
        val parsedCatalog = frozenJson(catalog.readBytes()).asJsonObject
        check(parsedCatalog.get("version").asString == version && parsedCatalog.getAsJsonArray("patches") == definitions)
        val patch = loaded.single { it.name == "Premium unlock" } as RawResourcePatch
        report["actual_definition"] = "exact_three_loaded_metadata_catalog_verified"
        report["loader"] = "app.morphe.patcher.patch.loadPatchesFromJar"
        report["bundle_sha256"] = inputHashes.getValue(bundle); report["catalog_sha256"] = inputHashes.getValue(catalog)
        report["patches"] = definitions; report["dependencies"] = projectDependencies(loaded)
        report["executed_patch_names"] = listOf("Premium unlock")
        check(casesRoot.mkdir())
        val cases = mutableListOf<Map<String, Any?>>()
        report["cases"] = cases
        val f = FinalBundleFixtures
        f.forms.forEach { form ->
            val fixture = f.bundle(List(4) { f.code(form) })
            cases.add(exercise(patch, casesRoot, "flip_${form.name}", fixture, f.expected(fixture, form.to)))
        }
        val normal = f.bundle()
        cases.add(exercise(patch, casesRoot, "idempotence", normal, repeat = true))
        val mixed = f.bundle(listOf(f.code(patched = true), f.code(), f.code(), f.code()))
        cases.add(exercise(patch, casesRoot, "mixed_pending", mixed, f.expected(mixed, functions = listOf(1, 2))))
        val duplicate = f.bundle(List(5) { f.code() }, names = listOf(2, 3, 4, 5, 2))
        cases.add(exercise(patch, casesRoot, "duplicate_named_functions", duplicate, f.expected(duplicate, functions = listOf(0, 1, 2, 4))))
        for (move in 1..2) {
            val fixture = f.bundle(List(4) { f.code(moved = move) })
            cases.add(exercise(patch, casesRoot, "load_move_$move", fixture, f.expected(fixture, site = f.site(move))))
        }
        cases.add(exercise(patch, casesRoot, "manifest_missing", normal))
        cases.add(exercise(patch, casesRoot, "manifest_binary", normal, manifest = byteArrayOf(3, 0, 8, 0)))
        cases.add(exercise(patch, casesRoot, "manifest_empty", normal, manifest = byteArrayOf()))
        cases.add(exercise(patch, casesRoot, "manifest_decoded_cleanup", normal, manifest = decoded, manifestExpected = cleaned))
        cases.add(exercise(patch, casesRoot, "manifest_actual_binary_decode", normal, decode = true))
        fun negative(name: String, fixture: FinalBundleFixtures.Fixture, message: String) {
            cases.add(exercise(patch, casesRoot, name, fixture, fixture.bytes, decoded, decoded, rejection = message))
        }
        negative("missing_on_signature", f.bundle(values = listOf("xx") + f.strings.drop(1)), "string 'on'")
        negative("missing_function_signature", f.bundle(names = listOf(2, 3, 5, 5)), "useActiveSubscription: no function")
        negative("missing_comparison_signature", f.bundle(listOf(f.code(), f.code(), f.code(string = 1), f.code())), "none compares against 'on'")
        negative("wrong_magic", f.bundle().also { it.bytes[0] = 0 }, "not a Hermes")
        negative("wrong_version", f.bundle().also { f.put32(it.bytes, 8, 97) }, "expected 96")
        negative("malformed_instruction", f.bundle(listOf(f.code(), f.code(), byteArrayOf(-1), f.code())), "Could not read")
        // 'on' loaded then overwritten: the matcher must not accept the stale register.
        val clobbered = byteArrayOf(115, 1, 0, 0, 120, 1, 188.toByte(), 4, 2, 1, 92, 2)
        negative("clobbered_on_register", f.bundle(List(4) { clobbered }), "none compares against 'on'")
        check(cases.size == 23 && cases.all { it["status"] in setOf("resource_bytes_verified", "rejected_without_writes") }) { "One or more named cases failed" }
        check(inputHashes.all { (file, hash) -> sha256(file) == hash }) { "Inputs changed during execution" }
        report["resource_execution"] = "loaded_plex_raw_resource_patch_all_named_cases_verified"
        report["status"] = "final_bundle_plex_synthetic_resources_verified"
    } catch (e: Exception) {
        report["error"] = e.toString()
    } finally {
        if (inputHashes.any { (file, hash) -> !file.isFile || sha256(file) != hash }) {
            report["status"] = "failed"; report["input_mutation"] = true
        }
        report["finished_at"] = Instant.now().toString(); report["elapsed_ns"] = System.nanoTime() - start
        save(reportFile, metadataGson.toJson(report).toByteArray())
    }
    check(report["status"] == "final_bundle_plex_synthetic_resources_verified") { "Final checker failed; retained $reportFile" }
}
