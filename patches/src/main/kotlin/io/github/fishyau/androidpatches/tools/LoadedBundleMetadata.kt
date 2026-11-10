package io.github.fishyau.androidpatches.tools

import app.morphe.patcher.patch.Patch
import app.morphe.patcher.patch.BytecodePatch
import app.morphe.patcher.patch.RawResourcePatch
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.FormFactor
import app.morphe.patcher.patch.SupportedAbi
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.Compatibility
import com.google.gson.GsonBuilder
import java.io.File
import java.security.MessageDigest

// No Patch-typed globals or factory getters here: these utilities are not patch definitions.
val metadataGson = GsonBuilder().serializeNulls().disableHtmlEscaping().setPrettyPrinting().create()

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(65536)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

/** Exact collection policy, not a subset selection or generic resource-runner permission. */
fun requireCollectionInventory(patches: Collection<Patch>) {
    requireInventory(patches, mapOf(
        "Server Auditor Offline Automation" to true,
        "Server Auditor Premium" to true,
        "Premium unlock" to true,
        "Disable Home previews" to true,
    ))
}

/** Only for deliberately Termius-only source tests/helpers; never validate a full MPP with this. */
fun requireTermiusInventory(patches: Collection<Patch>) {
    requireInventory(patches, mapOf("Server Auditor Offline Automation" to true, "Server Auditor Premium" to true))
}

@Suppress("DEPRECATION")
private fun requireInventory(patches: Collection<Patch>, defaults: Map<String, Boolean>) {
    require(patches.size == defaults.size && patches.map { it.name }.toSet() == defaults.keys) {
        "Exactly ${defaults.keys} required; no extra/unnamed/duplicate definitions: ${patches.map { it.name }}"
    }
    patches.forEach { patch ->
        require(patch.default == defaults.getValue(patch.name!!)) { "Wrong default for ${patch.name}" }
        require(patch.dependencies.isEmpty()) { "Dependencies are unsupported: ${patch.name}" }
        require(patch.options.isEmpty()) { "Options are unsupported: ${patch.name}" }
        val compatibilities = requireNotNull(patch.compatibility)
        require(compatibilities.size == 1) { "Exactly one package is required: ${patch.name}" }
        val compatibility = compatibilities.single()
        require(compatibility.signatures.isNullOrEmpty())
        if (patch.name == "Disable Home previews") {
            require(patch is BytecodePatch) { "Spotify preview patch must remain bytecode-only" }
            require(compatibility.apkFileType == ApkFileType.APKM_REQUIRED)
            require(compatibility.formFactor == FormFactor.TV)
            require(compatibility.packageName == "com.spotify.tv.android" && compatibility.name == "Spotify TV")
            require(compatibility.appIconColor == null)
            require(compatibility.targets.size == 1) { "Exactly one finite Spotify TV target is required" }
            val target = compatibility.targets.single()
            require(target.version == "9.1.94.1926" &&
                target.versionCodes == SupportedAbi.entries.associateWith { 147600562 })
            require(!target.isExperimental && target.minSdk == null && target.description == null)
        } else if (patch.name == "Premium unlock") {
            require(compatibility.apkFileType == ApkFileType.APKM)
            // Morphe 2.3.0's public constructor defaults to MOBILE, not null.
            require(compatibility.formFactor == FormFactor.MOBILE)
            require(patch is RawResourcePatch) { "Plex must remain RAW resource, not bytecode or decoded resources" }
            require(compatibility.packageName == "com.plexapp.android" && compatibility.name == "Plex")
            require(compatibility.appIconColor == 0x282A2D)
            // Omitted targets compile to exactly one unconstrained AppTarget in
            // Morphe 2.3.0. Validate every field, not merely a null version.
            require(compatibility.targets == listOf(AppTarget(version = null))) {
                "Plex must retain exactly the default version-unpinned target"
            }
        } else if (patch.name in setOf("Server Auditor Offline Automation", "Server Auditor Premium")) {
            require(patch is BytecodePatch) { "Termius must remain bytecode-only" }
            require(compatibility.apkFileType == ApkFileType.APKM)
            require(compatibility.formFactor == FormFactor.MOBILE)
            requireTermiusCompatibility(compatibility)
        } else {
            error("Unknown collection patch: ${patch.name}")
        }
    }
}

@Suppress("DEPRECATION")
private fun requireTermiusCompatibility(compatibility: Compatibility) {
    require(compatibility.packageName == "com.server.auditor.ssh.client" && compatibility.name == "Server Auditor")
    require(compatibility.appIconColor == 0x1A73E8)
    require(compatibility.targets.size == 1) { "Exactly one finite Termius target is required" }
    val target = compatibility.targets.single()
    // The scalar versionCode constructor expands to all supported ABIs.
    require(target.version == "8.0.1" && target.versionCodes == SupportedAbi.entries.associateWith { 1008 })
    require(!target.isExperimental && target.minSdk == null && target.description == null)
}

/** Fail before loading if parent-first resolution could substitute definitions or Spotify helpers. */
fun requireIsolatedDefinitionLoader(parent: ClassLoader = ClassLoader.getSystemClassLoader()) {
    // Probe exact class resources, not package directory entries: helper-only JARs
    // need not contain those entries. String names keep adapters/Termius-only tests
    // independent of Spotify implementation compilation or class initialization.
    listOf(
        "termius/ServerAuditorOfflineAutomationPatchKt",
        "termius/ServerAuditorPremiumPatchKt",
        "plex/PremiumUnlockPatchKt",
        "spotify/HomePreviewPatchKt",
        "spotify/CompatibilityKt",
        "spotify/PreviewExecution",
        "spotify/PreviewExecution\$executeProduction\$1",
        "spotify/PreviewExecution\$Descriptor",
        "spotify/PreviewSpec",
        "spotify/PreviewPins",
        "spotify/PreviewRole",
        "spotify/PreviewEdit",
        "spotify/PreviewEdits",
        "spotify/PreviewEdits\$WhenMappings",
        "spotify/CandidateSnapshots",
        "spotify/CandidateSnapshots\$annotations\$lambda\$0\$\$inlined\$sortedBy\$1",
        "spotify/CandidateSnapshots\$method\$lambda\$0\$\$inlined\$sortedBy\$1",
        "spotify/CandidateSnapshots\$WhenMappings",
        "spotify/PreviewAssertions",
    ).forEach { owner ->
        val path = "io/github/fishyau/androidpatches/$owner.class"
        require(!parent.getResources(path).hasMoreElements()) {
            "Patch definitions or production Spotify helpers are present on the parent classpath; run the isolated catalog/checker adapter, not main runtimeClasspath"
        }
    }
}

fun projectDependencies(patches: Collection<Patch>): Map<String, List<String>> =
    patches.sortedBy { it.name }.associate { patch ->
        requireNotNull(patch.name) to patch.dependencies.map { requireNotNull(it.name) }.sorted()
    }
