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
        require(compatibility.apkFileType == ApkFileType.APKM)
        require(compatibility.signatures.isNullOrEmpty())
        // Morphe 2.3.0's public constructor defaults to MOBILE, not null.
        require(compatibility.formFactor == FormFactor.MOBILE)
        if (patch.name == "Premium unlock") {
            require(patch is RawResourcePatch) { "Plex must remain RAW resource, not bytecode or decoded resources" }
            require(compatibility.packageName == "com.plexapp.android" && compatibility.name == "Plex")
            require(compatibility.appIconColor == 0x282A2D)
            // Omitted targets compile to exactly one unconstrained AppTarget in
            // Morphe 2.3.0. Validate every field, not merely a null version.
            require(compatibility.targets == listOf(AppTarget(version = null))) {
                "Plex must retain exactly the default version-unpinned target"
            }
        } else {
            require(patch is BytecodePatch) { "Termius must remain bytecode-only" }
            requireTermiusCompatibility(compatibility)
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

/** Fail before loading if parent-first resolution could substitute compiled source patches. */
fun requireIsolatedDefinitionLoader() {
    val parent = ClassLoader.getSystemClassLoader()
    listOf(
        "termius/ServerAuditorOfflineAutomationPatchKt",
        "termius/ServerAuditorPremiumPatchKt",
        "plex/PremiumUnlockPatchKt",
    ).forEach { definition ->
        val path = "io/github/fishyau/androidpatches/$definition.class"
        require(!parent.getResources(path).hasMoreElements()) {
            "Patch definitions are present on the parent classpath; run the isolated catalog/checker adapter, not main runtimeClasspath"
        }
    }
}

fun projectDependencies(patches: Collection<Patch>): Map<String, List<String>> =
    patches.sortedBy { it.name }.associate { patch ->
        requireNotNull(patch.name) to patch.dependencies.map { requireNotNull(it.name) }.sorted()
    }
