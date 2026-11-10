package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.patch.*
import io.github.fishyau.androidpatches.tools.*
import org.junit.Assert.*
import org.junit.Test

class PatchInventoryTest {
    private val accepted get() = listOf(serverAuditorOfflineAutomationPatch, serverAuditorPremiumPatch)

    @Test fun exactInventoryDefaultsDependenciesAndOptions() {
        requireTermiusInventory(accepted)
        assertEquals(mapOf("Server Auditor Offline Automation" to emptyList<String>(),
            "Server Auditor Premium" to emptyList<String>()), projectDependencies(accepted))
    }

    @Test fun termiusSubsetCannotBlessWholeCollectionOrCatalog() {
        assertThrows(IllegalArgumentException::class.java) { requireCollectionInventory(accepted) }
        assertThrows(IllegalArgumentException::class.java) { generatePatchList("0.1.0", accepted.toSet()) }
    }

    @Test fun missingExtraUnnamedAndDuplicateEntriesAreRejected() {
        for (entries in listOf(emptyList(), accepted.take(1), accepted.drop(1), accepted + accepted.first(),
            accepted + bytecodePatch(name = "Unrelated"), accepted + bytecodePatch())) {
            assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(entries) }
        }
    }

    @Test fun wrongDefaultIsRejected() {
        val wrong = bytecodePatch(name = "Server Auditor Premium", default = false) {
            compatibleWith(SERVER_AUDITOR_COMPATIBILITY)
        }
        assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(listOf(accepted.first(), wrong)) }
    }

    @Test fun finiteApkmCompatibilityIsExact() {
        accepted.forEach { patch ->
            val compatibility = patch.compatibility!!.single()
            assertEquals("com.server.auditor.ssh.client", compatibility.packageName)
            assertEquals(ApkFileType.APKM, compatibility.apkFileType)
            val target = compatibility.targets.single()
            assertEquals("8.0.1", target.version)
            assertEquals(setOf(1008), target.versionCodes!!.values.toSet())
            assertFalse(target.isExperimental)
        }
    }

    @Test fun wildcardWrongVersionCodeAndApkOnlyAreRejected() {
        val compatibilities = listOf<Compatibility?>(null,
            Compatibility(packageName = "com.server.auditor.ssh.client", name = "Server Auditor", apkFileType = ApkFileType.APKM),
            Compatibility(packageName = "com.server.auditor.ssh.client", name = "Server Auditor", apkFileType = ApkFileType.APKM,
                targets = listOf(AppTarget(version = "8.0.1", versionCode = 1007))),
            Compatibility(packageName = "com.server.auditor.ssh.client", name = "Server Auditor", apkFileType = ApkFileType.APK,
                targets = listOf(AppTarget(version = "8.0.1", versionCode = 1008))))
        compatibilities.forEach { compatibility ->
            val wrong = bytecodePatch(name = "Server Auditor Premium", default = true) {
                if (compatibility != null) compatibleWith(compatibility)
            }
            assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(listOf(accepted.first(), wrong)) }
        }
    }

    @Test fun dependenciesAreRejectedRatherThanInferredFromCatalog() {
        val wrong = bytecodePatch(name = "Server Auditor Premium", default = true) {
            compatibleWith(SERVER_AUDITOR_COMPATIBILITY)
            dependsOn(serverAuditorOfflineAutomationPatch)
        }
        assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(listOf(accepted.first(), wrong)) }
    }

    @Test fun nonemptyOptionsAreRejected() {
        val wrong = bytecodePatch(name = "Server Auditor Premium", default = true) {
            compatibleWith(SERVER_AUDITOR_COMPATIBILITY)
            val option by booleanOption(key = "unexpected", default = false, title = "Unexpected", description = "Fixture")
        }
        assertThrows(IllegalArgumentException::class.java) { requireTermiusInventory(listOf(accepted.first(), wrong)) }
    }

    @Test fun narrowerProjectionContainsOnlyTermiusDefinitions() {
        assertEquals(accepted.map { it.name }.toSet(),
            projectPatchDefinitions(accepted).map { it.asJsonObject.get("name").asString }.toSet())
    }
}
