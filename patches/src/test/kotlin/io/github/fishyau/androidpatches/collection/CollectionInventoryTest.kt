@file:Suppress("DEPRECATION")

package io.github.fishyau.androidpatches.collection

import app.morphe.patcher.patch.*
import com.google.gson.JsonParser
import io.github.fishyau.androidpatches.plex.premiumUnlockPatch
import io.github.fishyau.androidpatches.spotify.disableHomePreviewsPatch
import io.github.fishyau.androidpatches.termius.serverAuditorOfflineAutomationPatch
import io.github.fishyau.androidpatches.termius.serverAuditorPremiumPatch
import io.github.fishyau.androidpatches.tools.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.net.URLClassLoader
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

/** Authored collection metadata tests; not Spotify account/authentication runtime proof. */
class CollectionInventoryTest {
    private val accepted get() = listOf(serverAuditorOfflineAutomationPatch, serverAuditorPremiumPatch, premiumUnlockPatch, disableHomePreviewsPatch)

    private fun reject(entries: Collection<Patch>) {
        assertThrows(IllegalArgumentException::class.java) { requireCollectionInventory(entries) }
    }

    private fun replaced(index: Int, patch: Patch) = accepted.mapIndexed { i, original -> if (i == index) patch else original }

    // Compatibility.copy is internal in Morphe 2.3.0. Preserve the public fields
    // through its public constructor so each negative changes only its named input.
    private fun Compatibility.withChanges(
        packageName: String = requireNotNull(this.packageName),
        apkFileType: ApkFileType? = this.apkFileType,
        signatures: Set<String>? = this.signatures,
        targets: List<AppTarget> = this.targets,
        formFactor: FormFactor? = this.formFactor,
        name: String = requireNotNull(this.name),
        appIconColor: Int? = this.appIconColor,
    ) = Compatibility(
        packageName = packageName, name = name, description = description,
        apkFileType = apkFileType, appIconColor = appIconColor, signatures = signatures,
        targets = targets, formFactor = formFactor,
    )

    private fun replacement(index: Int, default: Boolean = accepted[index].default,
        compatibilities: List<Compatibility> = accepted[index].compatibility!!.toList(),
        dependency: Boolean = false, option: Boolean = false): Patch {
        val name = accepted[index].name!!
        return if (index == 2) rawResourcePatch(name = name, default = default) {
            compatibleWith(*compatibilities.toTypedArray())
            if (dependency) dependsOn(serverAuditorOfflineAutomationPatch)
            if (option) booleanOption(key = "unexpected", default = false)
        } else bytecodePatch(name = name, default = default) {
            compatibleWith(*compatibilities.toTypedArray())
            if (dependency) dependsOn(premiumUnlockPatch)
            if (option) booleanOption(key = "unexpected", default = false)
        }
    }

    @Test fun exactFourRealDefinitionsDefaultsTypesAndDependencies() {
        requireCollectionInventory(accepted)
        assertEquals(mapOf("Server Auditor Offline Automation" to true, "Server Auditor Premium" to true,
            "Premium unlock" to true, "Disable Home previews" to true), accepted.associate { it.name!! to it.default })
        assertTrue(accepted.take(2).all { it is BytecodePatch })
        assertTrue(accepted[2] is RawResourcePatch)
        assertTrue(accepted[3] is BytecodePatch)
        assertEquals(mapOf("Server Auditor Offline Automation" to emptyList<String>(),
            "Server Auditor Premium" to emptyList<String>(), "Premium unlock" to emptyList<String>(),
            "Disable Home previews" to emptyList<String>()), projectDependencies(accepted))
        requireTermiusInventory(accepted.take(2))
        assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(accepted) }
    }

    @Test fun parentVisibleProductionOutputLoadsFourPatchMetadataSmoke() {
        // Ordinary parent-visible metadata smoke only, not an isolation proof.
        // Use definition owners, not anonymous patch implementation classes from patcher.jar.
        val locations = listOf("termius.ServerAuditorOfflineAutomationPatchKt", "termius.ServerAuditorPremiumPatchKt",
            "plex.PremiumUnlockPatchKt", "spotify.HomePreviewPatchKt").map { owner ->
            File(Class.forName("io.github.fishyau.androidpatches.$owner").protectionDomain.codeSource.location.toURI())
        }.distinct()
        assertEquals("All four production definitions must share the compiled output", 1, locations.size)
        val location = locations.single()
        val jar = if (location.isFile) location else {
            val target = Files.createTempDirectory("collection-inventory-").resolve("definitions.jar").toFile()
            JarOutputStream(target.outputStream()).use { out ->
                location.walkTopDown().filter { it.isFile && it.extension == "class" }.sortedBy { it.path }.forEach { file ->
                    out.putNextEntry(JarEntry(file.relativeTo(location).invariantSeparatorsPath))
                    file.inputStream().use { it.copyTo(out) }
                    out.closeEntry()
                }
            }
            target
        }
        val loaded = loadPatchesFromJar(setOf(jar))
        requireCollectionInventory(loaded)
        assertEquals(4, loaded.size)
        assertEquals(projectPatchDefinitions(accepted), projectPatchDefinitions(loaded))
        assertEquals(projectDependencies(accepted), projectDependencies(loaded))
    }

    private fun withIsolatedParentResource(owner: String, body: (ClassLoader) -> Unit) {
        val jar = Files.createTempFile("collection-parent-resource-", ".jar").toFile()
        val entry = "io/github/fishyau/androidpatches/$owner.class"
        try {
            // Inert resource only: no executable bytecode or ZIP directory entries.
            JarOutputStream(jar.outputStream()).use { out ->
                out.putNextEntry(JarEntry(entry))
                out.write("inert class resource, never loaded".toByteArray())
                out.closeEntry()
            }
            java.util.jar.JarFile(jar).use { archive ->
                assertEquals(listOf(entry), archive.entries().asSequence().map { it.name }.toList())
            }
            // Do not inherit this test suite's production definitions/helpers.
            URLClassLoader(arrayOf(jar.toURI().toURL()), null).use { parent ->
                assertNotNull(parent.getResource(entry))
                assertNull(parent.getResource("io/github/fishyau/androidpatches/spotify/"))
                for (definition in listOf("termius/ServerAuditorOfflineAutomationPatchKt",
                    "termius/ServerAuditorPremiumPatchKt", "plex/PremiumUnlockPatchKt", "spotify/HomePreviewPatchKt")) {
                    if ("io/github/fishyau/androidpatches/$definition.class" != entry) {
                        assertNull(parent.getResource("io/github/fishyau/androidpatches/$definition.class"))
                    }
                }
                body(parent)
            }
        } finally {
            Files.deleteIfExists(jar.toPath())
        }
    }

    @Test fun helperOnlyPreviewExecutionParentIsRejectedBeforeLoading() {
        withIsolatedParentResource("spotify/PreviewExecution") { parent ->
            assertThrows(IllegalArgumentException::class.java) { requireIsolatedDefinitionLoader(parent) }
        }
    }

    @Test fun helperOnlyCompatibilityParentIsRejectedBeforeLoading() {
        withIsolatedParentResource("spotify/CompatibilityKt") { parent ->
            assertThrows(IllegalArgumentException::class.java) { requireIsolatedDefinitionLoader(parent) }
        }
    }

    @Test fun everyOtherNamedSpotifyHelperOnlyParentIsRejectedBeforeLoading() {
        for (owner in listOf("CandidateSnapshots", "PreviewAssertions", "PreviewPins", "PreviewRole",
            "PreviewEdit", "PreviewEdits", "PreviewSpec", "PreviewExecution\$Descriptor")) {
            withIsolatedParentResource("spotify/$owner") { parent ->
                assertThrows(IllegalArgumentException::class.java) { requireIsolatedDefinitionLoader(parent) }
            }
        }
    }

    @Test fun generatedSpotifyHelperOnlyParentsAreRejectedBeforeLoading() {
        for (owner in listOf(
            "PreviewEdits\$WhenMappings",
            "PreviewExecution\$executeProduction\$1",
            "CandidateSnapshots\$annotations\$lambda\$0\$\$inlined\$sortedBy\$1",
            "CandidateSnapshots\$method\$lambda\$0\$\$inlined\$sortedBy\$1",
            "CandidateSnapshots\$WhenMappings",
        )) {
            withIsolatedParentResource("spotify/$owner") { parent ->
                assertThrows(IllegalArgumentException::class.java) { requireIsolatedDefinitionLoader(parent) }
            }
        }
    }

    @Test fun compiledSpotifyClassFamilyExactlyMatchesGuardedResources() {
        // Inspect real compiler output, including generated classes invisible to source regexes.
        val location = File(Class.forName("io.github.fishyau.androidpatches.spotify.HomePreviewPatchKt")
            .protectionDomain.codeSource.location.toURI())
        val prefix = "io/github/fishyau/androidpatches/spotify/"
        val resources = if (location.isDirectory) {
            location.walkTopDown().filter { it.isFile }.map { it.relativeTo(location).invariantSeparatorsPath }
                .filter { it.startsWith(prefix) && it.endsWith(".class") }.toSet()
        } else {
            assertTrue("Compiled production output must be a directory or JAR", location.isFile)
            java.util.jar.JarFile(location).use { archive ->
                archive.entries().asSequence().filter { !it.isDirectory }.map { it.name }
                    .filter { it.startsWith(prefix) && it.endsWith(".class") }.toSet()
            }
        }
        val guardedOwners = setOf(
            "CompatibilityKt", "PreviewPins", "PreviewRole", "PreviewEdit", "PreviewEdits",
            "PreviewEdits\$WhenMappings", "PreviewSpec", "PreviewExecution",
            "PreviewExecution\$executeProduction\$1", "PreviewExecution\$Descriptor", "HomePreviewPatchKt",
            "CandidateSnapshots", "CandidateSnapshots\$annotations\$lambda\$0\$\$inlined\$sortedBy\$1",
            "CandidateSnapshots\$method\$lambda\$0\$\$inlined\$sortedBy\$1",
            "CandidateSnapshots\$WhenMappings", "PreviewAssertions",
        )
        assertEquals("Update exact resource guards when the compiled Spotify class family changes",
            guardedOwners.map { "$prefix$it.class" }.toSet(), resources)
        // Every real compiled class must independently trigger the string-only guard,
        // with no sibling definition/helper resources or executable bytecode available.
        for (resource in resources.sorted()) {
            val owner = "spotify/" + resource.removePrefix(prefix).removeSuffix(".class")
            withIsolatedParentResource(owner) { parent ->
                assertThrows("Unguarded compiled class: $resource", IllegalArgumentException::class.java) {
                    requireIsolatedDefinitionLoader(parent)
                }
            }
        }
    }

    @Test fun toolsOnlyParentResourceIsAccepted() {
        withIsolatedParentResource("tools/HarmlessAdapter") { parent ->
            requireIsolatedDefinitionLoader(parent)
        }
    }

    @Test fun missingExtraUnnamedAndEveryDuplicateAreRejected() {
        reject(emptyList())
        accepted.indices.forEach { index ->
            reject(accepted.filterIndexed { i, _ -> i != index })
            reject(accepted + accepted[index])
            reject(replaced(index, accepted[(index + 1) % accepted.size]))
            reject(replaced(index, bytecodePatch(name = "Unrelated")))
            reject(replaced(index, bytecodePatch()))
        }
        reject(accepted + bytecodePatch(name = "Unrelated"))
        reject(accepted + bytecodePatch())
    }

    @Test fun everyWrongDefaultDependencyAndOptionIsRejected() {
        accepted.indices.forEach { index ->
            reject(replaced(index, replacement(index, default = !accepted[index].default)))
            reject(replaced(index, replacement(index, dependency = true)))
            reject(replaced(index, replacement(index, option = true)))
        }
    }

    @Test fun rawDecodedAndBytecodeTypesCannotBeSubstituted() {
        reject(replaced(2, bytecodePatch(name = "Premium unlock") { compatibleWith(*premiumUnlockPatch.compatibility!!.toTypedArray()) }))
        reject(replaced(2, resourcePatch(name = "Premium unlock") { compatibleWith(*premiumUnlockPatch.compatibility!!.toTypedArray()) }))
        for (index in listOf(0, 1, 3)) {
            reject(replaced(index, resourcePatch(name = accepted[index].name, default = accepted[index].default) {
                compatibleWith(*accepted[index].compatibility!!.toTypedArray())
            }))
            reject(replaced(index, rawResourcePatch(name = accepted[index].name, default = accepted[index].default) {
                compatibleWith(*accepted[index].compatibility!!.toTypedArray())
            }))
        }
    }

    @Test fun nullEmptyMultipleWrongPackageAndWrongContainerAreRejectedForEveryPatch() {
        accepted.indices.forEach { index ->
            val original = accepted[index].compatibility!!.single()
            reject(replaced(index, bytecodePatch(name = accepted[index].name, default = accepted[index].default)))
            reject(replaced(index, replacement(index, compatibilities = emptyList())))
            reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(packageName = "com.example.unrelated")))))
            reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(signatures = setOf("0".repeat(64)))))))
            reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(name = "Unexpected app")))))
            reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(appIconColor = 0xFFFFFF)))))
            for (wrong in listOf(null) + ApkFileType.entries.filter { it != original.apkFileType }) {
                reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(apkFileType = wrong)))))
            }
            reject(replaced(index, replacement(index, compatibilities = listOf(original, original.withChanges(packageName = "com.example.other")))))
        }
    }

    @Test fun finiteTermiusAndIntentionallyUnpinnedPlexPoliciesCannotBeExchanged() {
        for (index in 0..1) {
            val original = accepted[index].compatibility!!.single()
            // Morphe's public constructor rejects an empty target list before
            // it can enter the collection validator; preserve that rejection too.
            assertThrows(IllegalArgumentException::class.java) { original.withChanges(targets = emptyList()) }
            val targets = listOf(listOf(AppTarget(version = null)), listOf(AppTarget(version = "8.0.2", versionCode = 1008)),
                listOf(AppTarget(version = "8.0.1", versionCode = 1007)),
                listOf(AppTarget(version = "8.0.1", versionCodes = mapOf(SupportedAbi.X86 to 1008))),
                listOf(AppTarget(version = "8.0.1", versionCode = 1008, isExperimental = true)),
                listOf(AppTarget(version = "8.0.1", versionCode = 1008, minSdk = 24)))
            targets.forEach { reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(targets = it))))) }
        }
        val plex = premiumUnlockPatch.compatibility!!.single()
        assertEquals("com.plexapp.android", plex.packageName)
        assertEquals(ApkFileType.APKM, plex.apkFileType)
        assertEquals(listOf(AppTarget(version = null)), plex.targets)
        reject(replaced(2, replacement(2, compatibilities = listOf(plex.withChanges(targets = listOf(AppTarget(version = "1.0", versionCode = 1)))))))
    }

    @Test fun spotifyFiniteTargetCannotBeBroadenedOrSubstituted() {
        val original = disableHomePreviewsPatch.compatibility!!.single()
        assertEquals("com.spotify.tv.android", original.packageName)
        assertEquals(ApkFileType.APKM_REQUIRED, original.apkFileType)
        assertEquals(FormFactor.TV, original.formFactor)
        assertEquals(listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600562)), original.targets)
        assertThrows(IllegalArgumentException::class.java) { original.withChanges(targets = emptyList()) }
        val exact = original.targets.single()
        for (targets in listOf(
            listOf(AppTarget(version = null)),
            listOf(AppTarget(version = "9.1.94.1927", versionCode = 147600562)),
            listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600561)),
            listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600562, isExperimental = true)),
            listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600562, minSdk = 24)),
            listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600562, description = "unexpected")),
            listOf(exact, AppTarget(version = "9.1.94.1927", versionCode = 147600563)),
            accepted[0].compatibility!!.single().targets,
        )) {
            reject(replaced(3, replacement(3, compatibilities = listOf(original.withChanges(targets = targets)))))
        }
        for (index in 0..2) {
            val other = accepted[index].compatibility!!.single()
            reject(replaced(index, replacement(index, compatibilities = listOf(other.withChanges(targets = original.targets)))))
        }
    }

    @Test fun actualMorpheDefaultsAndEveryFormFactorMutationAreChecked() {
        accepted.forEachIndexed { index, patch ->
            val compatibility = patch.compatibility!!.single()
            assertEquals(if (index == 3) FormFactor.TV else FormFactor.MOBILE, compatibility.formFactor)
            for (wrong in listOf(null) + FormFactor.entries.filter { it != compatibility.formFactor }) {
                reject(replaced(index, replacement(index, compatibilities = listOf(compatibility.withChanges(formFactor = wrong)))))
            }
        }
    }

    @Test fun everyUnpinnedPlexSentinelFieldIsConstrained() {
        val plex = premiumUnlockPatch.compatibility!!.single()
        for (target in listOf(AppTarget(version = null, isExperimental = true),
            AppTarget(version = null, minSdk = 24), AppTarget(version = null, description = "unexpected"),
            AppTarget(version = null, versionCodes = emptyMap()))) {
            reject(replaced(2, replacement(2, compatibilities = listOf(plex.withChanges(targets = listOf(target))))))
            // Direct projection must not silently erase a nondefault sentinel.
            val projected = projectPatchDefinitions(listOf(replacement(2, compatibilities = listOf(plex.withChanges(targets = listOf(target))))))
            assertEquals(1, projected.single().asJsonObject.getAsJsonArray("compatiblePackages").single()
                .asJsonObject.getAsJsonArray("targets").size())
        }
    }

    @Test fun everyFiniteTargetAbiCodeIsRequiredAndProjectionRetainsActualMap() {
        for (index in listOf(0, 1, 3)) {
            val original = accepted[index].compatibility!!.single()
            val code = if (index == 3) 147600562 else 1008
            val expected = SupportedAbi.entries.associateWith { code }
            assertEquals(expected, original.targets.single().versionCodes)
            for (abi in SupportedAbi.entries) {
                for (codes in listOf(expected - abi, expected + (abi to (code - 1)))) {
                    val target = AppTarget(version = original.targets.single().version, versionCodes = codes)
                    reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(targets = listOf(target))))))
                }
            }
            val projected = projectPatchDefinitions(listOf(accepted[index])).single().asJsonObject
                .getAsJsonArray("compatiblePackages").single().asJsonObject.getAsJsonArray("targets").single()
                .asJsonObject.getAsJsonObject("versionCodes")
            assertEquals(SupportedAbi.entries.map { it.name }.toSet(), projected.keySet())
            assertTrue(projected.entrySet().all { it.value.asInt == code })
        }
    }

    @Test fun catalogAndInspectionProjectionPreserveEmptyPlexTargetsAndAllFourEntries() {
        val catalog = JsonParser.parseString(generatePatchList("0.1.0", accepted.toSet())).asJsonObject
        assertEquals(projectPatchDefinitions(accepted), catalog.getAsJsonArray("patches"))
        val plex = catalog.getAsJsonArray("patches").single { it.asJsonObject.get("name").asString == "Premium unlock" }.asJsonObject
        assertEquals(0, plex.getAsJsonArray("compatiblePackages").single().asJsonObject.getAsJsonArray("targets").size())
        assertThrows(IllegalArgumentException::class.java) { generatePatchList("0.1.0", accepted.take(2).toSet()) }
    }
}
