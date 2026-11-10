/*
 * Copyright 2025 Morphe.
 * https://github.com/MorpheApp/morphe-patches-template
 *
 * Modified for FISHYau android patches, 2026-11-08:
 * explicit single bundle, direct manifest read, unique names, new external output.
 * See LICENSE and NOTICE for applicable terms.
 */
package io.github.fishyau.androidpatches.tools

import app.morphe.patcher.patch.Patch
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.loadPatchesFromJar
import com.google.gson.JsonObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import java.util.jar.JarFile

fun main(args: Array<String>) {
    require(args.size == 3) { "Expected exact MPP path, new external catalog output, source repository root" }
    val bundle = File(args[0]).canonicalFile
    require(bundle.isFile && bundle.extension == "mpp") { "An explicit existing MPP is required" }
    val output = File(args[1]).canonicalFile.toPath()
    require(Files.isDirectory(output.parent) && !Files.exists(output)) { "Catalog output must be a new file" }
    val sourceRoot = File(args[2]).canonicalFile
    require(sourceRoot.resolve("patches/build.gradle.kts").isFile) { "Explicit source repository root required" }
    require(!output.startsWith(sourceRoot.toPath())) { "Catalog output must be outside the source repository" }
    val originalHash = sha256(bundle)
    val version = JarFile(bundle).use { jar ->
        requireNotNull(jar.manifest?.mainAttributes?.getValue("Version")) { "Missing bundle Version" }
    }
    requireIsolatedDefinitionLoader()
    val loaded = loadPatchesFromJar(setOf(bundle))
    val names = loaded.map { requireNotNull(it.name) { "Unnamed patches cannot be catalogued" } }
    require(names.size == names.toSet().size) { "Duplicate patch names are ambiguous" }
    requireCollectionInventory(loaded)
    val json = generatePatchList(version, loaded)
    check(sha256(bundle) == originalHash) { "Selected bundle changed during catalog generation" }
    Files.writeString(output, json, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
    println("Catalogued ${loaded.size} patches from ${bundle.name}")
}

fun generatePatchList(version: String, patches: Set<Patch>): String {
    requireCollectionInventory(patches)
    // The public catalog DTO has no dependency field. The actual loader policy
    // above checks every dependency; InspectBundle reports the explicit all-three map.
    return metadataGson.toJson(JsonObject().apply {
        addProperty("NOTE", "Generated from an exact MPP. Do not edit by hand; this catalog is not a release approval.")
        addProperty("version", version)
        add("patches", projectPatchDefinitions(patches))
    })
}

/** The single actual-loader projection used by the catalog and inspection adapter. */
@Suppress("DEPRECATION")
fun projectPatchDefinitions(patches: Collection<Patch>): com.google.gson.JsonArray {
    val entries = patches.sortedBy { it.name }.map { patch ->
        JsonPatch(
            name = patch.name!!,
            description = patch.description,
            default = patch.default,
            category = patch.category,
            compatiblePackages = patch.compatibility?.map { compat ->
                JsonCompatibility(
                    packageName = compat.packageName!!,
                    name = compat.name,
                    description = compat.description,
                    apkFileType = compat.apkFileType?.name,
                    appIconColor = compat.appIconColor?.let { "#%06X".format(it) },
                    signatures = compat.signatures,
                    formFactor = compat.formFactor?.name,
                    // Public catalog encodes the exact default unpinned Plex
                    // sentinel as targets=[]; never erase a constrained target.
                    targets = (if (compat.packageName == "com.plexapp.android" &&
                        compat.targets == listOf(AppTarget(version = null))) emptyList() else compat.targets).map { target ->
                        JsonCompatibility.Target(
                            version = target.version,
                            versionCodes = target.versionCodes?.mapKeys { it.key.name },
                            isExperimental = target.isExperimental,
                            minSdk = target.minSdk,
                            description = target.description,
                        )
                    },
                )
            },
            options = patch.options.values.map { option ->
                JsonPatch.Option(
                    key = option.key,
                    title = option.title,
                    description = option.description,
                    required = option.required,
                    type = option.type.toString(),
                    default = option.default,
                    values = option.values,
                )
            },
        )
    }
    return metadataGson.toJsonTree(entries).asJsonArray
}

@Suppress("unused")
private class JsonPatch(
    val name: String,
    val description: String?,
    val default: Boolean,
    val category: String?,
    val compatiblePackages: List<JsonCompatibility>?,
    val options: List<Option>,
) {
    class Option(
        val key: String,
        val title: String?,
        val description: String?,
        val required: Boolean,
        val type: String,
        val default: Any?,
        val values: Map<String, Any?>?,
    )
}

@Suppress("unused")
private class JsonCompatibility(
    val packageName: String,
    val name: String?,
    val description: String?,
    val apkFileType: String?,
    val appIconColor: String?,
    val signatures: Set<String>?,
    val formFactor: String?,
    val targets: List<Target>,
) {
    class Target(
        val version: String?,
        val versionCodes: Map<String, Int>?,
        val isExperimental: Boolean,
        val minSdk: Int?,
        val description: String?,
    )
}
