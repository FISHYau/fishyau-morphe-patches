@file:Suppress("DEPRECATION")

package io.github.fishyau.androidpatches.collection

import app.morphe.patcher.patch.*
import com.google.gson.JsonParser
import io.github.fishyau.androidpatches.plex.premiumUnlockPatch
import io.github.fishyau.androidpatches.termius.serverAuditorOfflineAutomationPatch
import io.github.fishyau.androidpatches.termius.serverAuditorPremiumPatch
import io.github.fishyau.androidpatches.tools.*
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream

/** Authored collection tests. Execution requires new explicit approval, including Plex initialization. */
class CollectionInventoryTest {
    private val accepted get() = listOf(serverAuditorOfflineAutomationPatch, serverAuditorPremiumPatch, premiumUnlockPatch)

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
    ) = Compatibility(
        packageName = packageName, name = requireNotNull(name), description = description,
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

    @Test fun exactThreeRealDefinitionsDefaultsTypesAndDependencies() {
        requireCollectionInventory(accepted)
        assertEquals(mapOf("Server Auditor Offline Automation" to true, "Server Auditor Premium" to true,
            "Premium unlock" to true), accepted.associate { it.name!! to it.default })
        assertTrue(accepted.take(2).all { it is BytecodePatch })
        assertTrue(accepted.last() is RawResourcePatch)
        assertEquals(mapOf("Server Auditor Offline Automation" to emptyList<String>(),
            "Server Auditor Premium" to emptyList<String>(), "Premium unlock" to emptyList<String>()), projectDependencies(accepted))
        assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(accepted) }
    }

    @Test fun actualLoaderFindsExactlyThreeInProductionOutputIncludingHelpers() {
        // Use definition owners, not anonymous patch implementation classes from patcher.jar.
        val locations = listOf("termius.ServerAuditorOfflineAutomationPatchKt", "termius.ServerAuditorPremiumPatchKt",
            "plex.PremiumUnlockPatchKt").map { owner ->
            File(Class.forName("io.github.fishyau.androidpatches.$owner").protectionDomain.codeSource.location.toURI())
        }.distinct()
        assertEquals("All three production definitions must share the compiled output", 1, locations.size)
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
        assertEquals(3, loaded.size)
        assertEquals(projectPatchDefinitions(accepted), projectPatchDefinitions(loaded))
        assertEquals(projectDependencies(accepted), projectDependencies(loaded))
    }

    @Test fun missingExtraUnnamedAndEveryDuplicateAreRejected() {
        reject(emptyList())
        accepted.indices.forEach { index ->
            reject(accepted.filterIndexed { i, _ -> i != index })
            reject(accepted + accepted[index])
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
        for (index in 0..1) {
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
            for (wrong in listOf(original.withChanges(packageName = "com.example.unrelated"), original.withChanges(apkFileType = ApkFileType.APK),
                original.withChanges(apkFileType = null), original.withChanges(signatures = setOf("0".repeat(64))))) {
                reject(replaced(index, replacement(index, compatibilities = listOf(wrong))))
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

    @Test fun actualMorpheDefaultsAndEveryFormFactorMutationAreChecked() {
        accepted.forEachIndexed { index, patch ->
            val compatibility = patch.compatibility!!.single()
            assertEquals(FormFactor.MOBILE, compatibility.formFactor)
            for (wrong in listOf(null, FormFactor.TV, FormFactor.WEARABLE, FormFactor.AUTOMOTIVE)) {
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

    @Test fun everyTermiusAbiCodeIsRequiredAndProjectionRetainsActualMap() {
        for (index in 0..1) {
            val original = accepted[index].compatibility!!.single()
            val expected = SupportedAbi.entries.associateWith { 1008 }
            assertEquals(expected, original.targets.single().versionCodes)
            for (abi in SupportedAbi.entries) {
                for (codes in listOf(expected - abi, expected + (abi to 1007))) {
                    val target = AppTarget(version = "8.0.1", versionCodes = codes)
                    reject(replaced(index, replacement(index, compatibilities = listOf(original.withChanges(targets = listOf(target))))))
                }
            }
            val projected = projectPatchDefinitions(listOf(accepted[index])).single().asJsonObject
                .getAsJsonArray("compatiblePackages").single().asJsonObject.getAsJsonArray("targets").single()
                .asJsonObject.getAsJsonObject("versionCodes")
            assertEquals(SupportedAbi.entries.map { it.name }.toSet(), projected.keySet())
            assertTrue(projected.entrySet().all { it.value.asInt == 1008 })
        }
    }

    @Test fun catalogAndInspectionProjectionPreserveEmptyPlexTargetsAndAllThreeEntries() {
        val catalog = JsonParser.parseString(generatePatchList("0.1.0", accepted.toSet())).asJsonObject
        assertEquals(projectPatchDefinitions(accepted), catalog.getAsJsonArray("patches"))
        val plex = catalog.getAsJsonArray("patches").single { it.asJsonObject.get("name").asString == "Premium unlock" }.asJsonObject
        assertEquals(0, plex.getAsJsonArray("compatiblePackages").single().asJsonObject.getAsJsonArray("targets").size())
        assertThrows(IllegalArgumentException::class.java) { generatePatchList("0.1.0", accepted.take(2).toSet()) }
    }
}
