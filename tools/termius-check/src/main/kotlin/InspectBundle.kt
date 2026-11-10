package io.github.fishyau.androidpatches.inspection

import app.morphe.patcher.patch.loadPatchesFromJar
import com.google.gson.JsonParser
import io.github.fishyau.androidpatches.tools.*
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.time.Instant
import java.util.jar.JarFile

/** JVM actual-loader inspection. This never claims Android/ART/Manager load success. */
fun main(args: Array<String>) {
    require(args.size == 4) { "Usage: exact.mpp exact-catalog.json NEW-report.json SOURCE_REPOSITORY_ROOT" }
    val bundle = File(args[0]).canonicalFile
    val catalog = File(args[1]).canonicalFile
    val output = File(args[2]).canonicalFile
    val source = File(args[3]).canonicalFile
    require(source.resolve("patches/build.gradle.kts").isFile)
    require(bundle.isFile && bundle.extension == "mpp" && catalog.isFile)
    require(output.parentFile.isDirectory && !output.exists() && !output.toPath().startsWith(source.toPath()))
    val bundleHash = sha256(bundle)
    val catalogHash = sha256(catalog)
    require(bundle.length() in 22..(64L * 1024 * 1024)) { "Bounded plain unsigned MPP required" }
    val bytes = bundle.readBytes()
    require(bytes.take(4) == listOf<Byte>(0x50, 0x4b, 3, 4))
    require(bytes.sliceArray(bytes.size - 22 until bytes.size - 18).contentEquals(byteArrayOf(0x50, 0x4b, 5, 6)))
    require(bytes.takeLast(2) == listOf<Byte>(0, 0)) { "ZIP comments/signature envelopes are unsupported" }
    val manifest = JarFile(bundle).use { jar ->
        val names = jar.entries().asSequence().map { it.name }.toList()
        require(names.size == names.toSet().size) { "Duplicate archive entries" }
        require(names.none { it.matches(Regex("(?i).*(\\.(sf|rsa|dsa|ec|sig)|(^|/)signature(\\.[^/]*)?)$")) })
        val dex = requireNotNull(jar.getEntry("classes.dex")) { "Android classes.dex required" }
        val magic = jar.getInputStream(dex).use { it.readNBytes(8) }
        require(String(magic, Charsets.ISO_8859_1).matches(Regex("dex\\n0(3[5-9]|4[01])\\u0000"))) { "Invalid DEX magic" }
        requireNotNull(jar.manifest).mainAttributes.entries.associate { it.key.toString().lowercase() to it.value.toString() }
    }
    require(manifest["patcher-version"] == "2.3.0")
    require(manifest["name"] == "FISHYau android patches" && manifest["author"] == "FISHYau")
    requireIsolatedDefinitionLoader()
    val loaded = loadPatchesFromJar(setOf(bundle))
    requireCollectionInventory(loaded)
    val parsed = JsonParser.parseString(catalog.readText()).asJsonObject
    require(parsed.get("version").asString == manifest["version"])
    val definitions = projectPatchDefinitions(loaded)
    require(parsed.getAsJsonArray("patches") == definitions) { "Catalog disagrees with actual loaded definitions" }
    require(sha256(bundle) == bundleHash && sha256(catalog) == catalogHash) { "Inputs changed during inspection" }
    val report = linkedMapOf<String, Any>(
        "schema" to "termius-bundle-inspection-v1",
        "status" to "jvm_actual_loader_metadata_verified",
        "observed_at" to Instant.now().toString(),
        "bundle_sha256" to bundleHash,
        "catalog_sha256" to catalogHash,
        "patcher_version" to "2.3.0",
        "loader" to "app.morphe.patcher.patch.loadPatchesFromJar",
        "android_bundle_load" to "not_observed",
        "dex_check" to "classes.dex_magic_only_not_ART",
        "patches" to definitions,
        "dependencies" to projectDependencies(loaded),
        "about" to mapOf("name" to manifest.getValue("name"), "author" to manifest.getValue("author")),
        "manifest" to manifest.toSortedMap(),
        "signing" to "unsigned",
        "limitations" to listOf("JVM loader is not Android/ART execution or Manager import", "Unsigned ZIP structure only; no signature verification", "No feature/runtime approval"),
    )
    Files.writeString(output.toPath(), metadataGson.toJson(report), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
    println("Verified exact four definitions, catalog, explicit dependencies and metadata on JVM; Android load, Plex application and Spotify application not observed")
}
