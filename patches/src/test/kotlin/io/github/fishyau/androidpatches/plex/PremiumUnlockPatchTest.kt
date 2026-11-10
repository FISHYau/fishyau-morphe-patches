@file:Suppress("DEPRECATION")

package io.github.fishyau.androidpatches.plex

import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.ResourcePatchContext
import app.morphe.patcher.resource.ResourceMode
import com.reandroid.arsc.chunk.TableBlock
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock
import io.github.fishyau.androidpatches.plex.shared.HermesBundle
import org.junit.Assert.*
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream

/** Executes the real production rawResourcePatch using Morphe's real resource context, no API stubs.
 * Synthetic ZIPs are intentionally not installable APKs. This bypasses loader/package validation;
 * metadata is asserted separately. It does not test APKM merging, signing, Manager or Android.
 */
class PremiumUnlockPatchTest {
    private fun context(data: ByteArray, manifest: ByteArray? = null, stageManifest: Boolean = true, body: (ResourcePatchContext, File, File) -> Unit) {
        val root = Path.of(System.getProperty("plex.test.root", System.getProperty("java.io.tmpdir")))
        val run = Files.createTempDirectory(root, "plex-resource-").toFile()
        val input = run.resolve("synthetic.zip")
        val binaryManifest = AndroidManifestBlock.empty().apply {
            setPackageName("dev.fishyau.plexfixture")
            setVersionName("1.0")
            setVersionCode(1)
            setExtractNativeLibs(false)
            refreshFull()
        }.bytes
        ZipOutputStream(input.outputStream()).use { zip ->
            zip.putNextEntry(ZipEntry("assets/index.android.bundle"))
            zip.write(data)
            zip.closeEntry()
            zip.putNextEntry(ZipEntry("AndroidManifest.xml"))
            zip.write(binaryManifest)
            zip.closeEntry()
            if (!stageManifest) {
                // FULL decoding expects a genuine resource package, not only a
                // manifest. Author a minimal binary table; never fake package.json.
                val table = TableBlock().apply {
                    newPackage(0x7f, "dev.fishyau.plexfixture")
                        .getOrCreate("", "string", "fixture_label").setValueAsString("Fixture")
                    refreshFull()
                }
                zip.putNextEntry(ZipEntry("resources.arsc"))
                zip.write(table.bytes)
                zip.closeEntry()
            }
        }
        val config = PatcherConfig(apkFile = input, temporaryFilesPath = run.resolve("temporary"), fileWorkspacePath = run.resolve("workspace"))
        // The real JVM constructor is public even if Kotlin metadata narrows it.
        // Reflection here avoids changing production visibility or supplying API stubs.
        ResourcePatchContext::class.java.getConstructor(PatcherConfig::class.java).newInstance(config).use { ctx ->
            if (!stageManifest) {
                // The direct constructor bypasses Patcher preparation. Invoke its
                // real JVM-visible FULL preparation, not a fake decoded manifest;
                // this does not claim lazy decoding in the production RAW path.
                ResourcePatchContext::class.java.getMethod(
                    "decodeResources\$morphe_patcher", ResourceMode::class.java
                ).invoke(ctx, ResourceMode.FULL)
            }
            val bundle = ctx.get("assets/index.android.bundle")
            val manifestFile = ctx.get("AndroidManifest.xml")
            // Explicitly simulate the donor's staged missing/binary/text branches;
            // this is guard coverage, not proof of APKM merge behavior.
            if (stageManifest) {
                if (manifest == null) {
                    check(!manifestFile.exists() || manifestFile.delete())
                } else {
                    manifestFile.parentFile.mkdirs()
                    manifestFile.writeBytes(manifest)
                }
            }
            body(ctx, bundle, manifestFile)
        }
    }

    private fun failure(data: ByteArray, contains: String) {
        context(data) { ctx, file, manifest ->
            val before = file.readBytes()
            val exception = assertThrows(PatchException::class.java) { premiumUnlockPatch.execute(ctx) }
            assertTrue(exception.message, exception.message.orEmpty().contains(contains))
            assertArrayEquals(before, file.readBytes())
            assertFalse(manifest.exists())
        }
    }

    @Test fun metadataKeepsExactNameDefaultAndPackageScopedUnpin() {
        assertEquals("Premium unlock", premiumUnlockPatch.name)
        assertTrue(premiumUnlockPatch.default)
        assertTrue(premiumUnlockPatch.dependencies.isEmpty())
        val c = premiumUnlockPatch.compatibility!!.single()
        assertEquals("Plex", c.name)
        assertEquals("com.plexapp.android", c.packageName)
        assertEquals(ApkFileType.APKM, c.apkFileType)
        assertEquals(listOf(AppTarget(version = null)), c.targets)
        assertEquals(0x282A2D, c.appIconColor)
        assertFalse(premiumUnlockPatch.description.orEmpty().contains("any device"))
    }

    @Test fun realContextExplicitlyDecodesSyntheticBinaryManifest() {
        context(SyntheticHermes.bundle().data, stageManifest = false) { ctx, file, manifest ->
            assertTrue(manifest.readText().contains("android:extractNativeLibs=\"false\""))
            premiumUnlockPatch.execute(ctx)
            assertTrue(manifest.readText().contains("android:extractNativeLibs=\"true\""))
            assertTrue(HermesBundle(file.readBytes()).footerValid())
        }
    }

    @Test fun actualProductionExecutionChangesOnlyThreeOpcodesAndFooter() {
        val f = SyntheticHermes.bundle()
        context(f.data) { ctx, file, _ ->
            premiumUnlockPatch.execute(ctx)
            val after = file.readBytes()
            val expected = f.data.copyOf()
            for (offset in f.offsets.take(3)) expected[offset + 4] = HermesBundle.opcode("JNotEqual").toByte()
            SyntheticHermes.footer(expected)
            assertArrayEquals(expected, after)
            assertTrue(HermesBundle(after).footerValid())
            assertArrayEquals(f.data.copyOfRange(f.offsets[3], f.offsets[3] + 10), after.copyOfRange(f.offsets[3], f.offsets[3] + 10))
        }
    }

    @Test fun actualProductionExecutionIsIdempotent() {
        context(SyntheticHermes.bundle().data) { ctx, file, _ ->
            premiumUnlockPatch.execute(ctx)
            val after = file.readBytes()
            premiumUnlockPatch.execute(ctx)
            assertArrayEquals(after, file.readBytes())
        }
    }

    @Test fun supportsEveryStrictFlipForm() {
        for ((from, to) in listOf("JStrictEqual" to "JNotEqual", "JStrictEqualLong" to "JNotEqualLong", "JStrictNotEqual" to "JEqual", "JStrictNotEqualLong" to "JEqualLong", "StrictEq" to "Neq", "StrictNeq" to "Eq")) {
            val f = SyntheticHermes.bundle(codes = List(4) { SyntheticHermes.check(from) })
            context(f.data) { ctx, file, _ ->
                premiumUnlockPatch.execute(ctx)
                val expected = f.data.copyOf()
                for (offset in f.offsets.take(3)) expected[offset + 4] = HermesBundle.opcode(to).toByte()
                SyntheticHermes.footer(expected)
                assertArrayEquals(from, expected, file.readBytes())
            }
        }
    }

    @Test fun mixedAlreadyPatchedAndPendingChangesOnlyPending() {
        val f = SyntheticHermes.bundle(codes = listOf(SyntheticHermes.check("JNotEqual"), SyntheticHermes.check(), SyntheticHermes.check(), SyntheticHermes.check()))
        context(f.data) { ctx, file, _ ->
            premiumUnlockPatch.execute(ctx)
            val expected = f.data.copyOf()
            for (offset in f.offsets.drop(1).take(2)) expected[offset + 4] = HermesBundle.opcode("JNotEqual").toByte()
            SyntheticHermes.footer(expected)
            assertArrayEquals(expected, file.readBytes())
        }
    }

    @Test fun followsShortAndLongMovesAndStringLoads() {
        for ((load, move) in listOf("LoadConstString" to "Mov", "LoadConstStringLongIndex" to "MovLong")) {
            val code = SyntheticHermes.insn(load, 1, 0) + SyntheticHermes.insn(move, 3, 1) + SyntheticHermes.insn("JStrictEqual", 4, 2, 3) + SyntheticHermes.insn("Ret", 2)
            val f = SyntheticHermes.bundle(codes = List(4) { code })
            context(f.data) { ctx, file, _ ->
                premiumUnlockPatch.execute(ctx)
                val expected = f.data.copyOf()
                val site = SyntheticHermes.insn(load, 1, 0).size + SyntheticHermes.insn(move, 3, 1).size
                for (offset in f.offsets.take(3)) expected[offset + site] = HermesBundle.opcode("JNotEqual").toByte()
                SyntheticHermes.footer(expected)
                assertArrayEquals(expected, file.readBytes())
            }
        }
    }

    @Test fun duplicateFunctionNamesPatchAllMatchingFunctions() {
        val f = SyntheticHermes.bundle(codes = List(5) { SyntheticHermes.check() }, functionNames = listOf(2, 3, 4, 5, 2))
        context(f.data) { ctx, file, _ ->
            premiumUnlockPatch.execute(ctx)
            val expected = f.data.copyOf()
            for (i in listOf(0, 1, 2, 4)) expected[f.offsets[i] + 4] = HermesBundle.opcode("JNotEqual").toByte()
            SyntheticHermes.footer(expected)
            assertArrayEquals(expected, file.readBytes())
        }
    }

    @Test fun rejectsMissingOnWithoutWrites() = failure(SyntheticHermes.bundle(values = listOf("xx") + SyntheticHermes.strings.drop(1)).data, "string 'on'")

    @Test fun rejectsMissingRequiredFunctionWithoutPartialWrites() = failure(SyntheticHermes.bundle(functionNames = listOf(2, 3, 5, 5)).data, "useActiveSubscription: no function")

    @Test fun rejectsNamedFunctionWithoutOnComparisonWithoutPartialWrites() = failure(SyntheticHermes.bundle(codes = listOf(SyntheticHermes.check(), SyntheticHermes.check(), SyntheticHermes.check(string = 1), SyntheticHermes.check())).data, "none compares against 'on'")

    @Test fun clearedConstantAndMoveRegistersDoNotMatch() {
        for (clobber in listOf(SyntheticHermes.insn("LoadConstString", 1, 1), SyntheticHermes.insn("Mov", 1, 2), SyntheticHermes.insn("LoadConstTrue", 1), SyntheticHermes.insn("IteratorNext", 1, 2, 3))) {
            val code = SyntheticHermes.insn("LoadConstString", 1, 0) + clobber + SyntheticHermes.insn("JStrictEqual", 4, 2, 1)
            failure(SyntheticHermes.bundle(codes = List(4) { code }).data, "none compares against 'on'")
        }
    }

    @Test fun rejectsWrongMagicVersionAndMalformedInstructionWithoutWrites() {
        val wrongMagic = SyntheticHermes.bundle().data.also { it[0] = 0 }
        failure(wrongMagic, "not a Hermes")
        val wrongVersion = SyntheticHermes.bundle().data.also { SyntheticHermes.put32(it, 8, 97) }
        failure(wrongVersion, "expected 96")
        val bad = SyntheticHermes.bundle(codes = listOf(SyntheticHermes.check(), SyntheticHermes.check(), byteArrayOf(-1), SyntheticHermes.check())).data
        failure(bad, "Could not read")
    }

    @Test fun skipsMissingBinaryAndEmptyManifest() {
        for (manifest in listOf(null, byteArrayOf(3, 0, 8, 0), byteArrayOf())) {
            context(SyntheticHermes.bundle().data, manifest) { ctx, file, manifestFile ->
                premiumUnlockPatch.execute(ctx)
                assertTrue(HermesBundle(file.readBytes()).footerValid())
                if (manifest == null) assertFalse(manifestFile.exists()) else assertArrayEquals(manifest, manifestFile.readBytes())
            }
        }
    }

    @Test fun cleansOnlyOptionalDecodedManifestConstraints() {
        val text = """<manifest android:requiredSplitTypes="base__abi" android:splitTypes="" keep="yes"><application android:extractNativeLibs="false" /></manifest>"""
        context(SyntheticHermes.bundle().data, text.toByteArray()) { ctx, _, manifest ->
            premiumUnlockPatch.execute(ctx)
            assertEquals("""<manifest keep="yes"><application android:extractNativeLibs="true" /></manifest>""", manifest.readText())
        }
    }

    @Test fun preflightFailureLeavesDecodedManifestAndBundleUnmodified() {
        val f = SyntheticHermes.bundle(functionNames = listOf(2, 3, 5, 5))
        val text = """<manifest android:splitTypes="" />""".toByteArray()
        context(f.data, text) { ctx, file, manifest ->
            assertThrows(PatchException::class.java) { premiumUnlockPatch.execute(ctx) }
            assertArrayEquals(f.data, file.readBytes())
            assertArrayEquals(text, manifest.readBytes())
        }
    }

    @Test fun documentsPreservedNoOriginalFooterValidation() {
        val f = SyntheticHermes.bundle(codes = List(4) { SyntheticHermes.check("JNotEqual") })
        f.data[f.data.lastIndex] = (f.data.last() + 1).toByte()
        context(f.data) { ctx, file, _ ->
            premiumUnlockPatch.execute(ctx)
            assertArrayEquals(f.data, file.readBytes())
            assertFalse(HermesBundle(file.readBytes()).footerValid())
        }
    }
}
