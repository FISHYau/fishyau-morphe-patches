@file:Suppress("DEPRECATION")
package io.github.fishyau.androidpatches.plexcheck

import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.patch.ResourcePatchContext
import app.morphe.patcher.patch.rawResourcePatch
import app.morphe.patcher.resource.ResourceMode
import io.github.fishyau.androidpatches.tools.metadataGson
import io.github.fishyau.androidpatches.tools.requireIsolatedDefinitionLoader
import java.io.File
import java.util.zip.ZipFile

/** Actual pinned-context fixture regression only. No MPP, production patch or helper is loaded. */
fun main(args: Array<String>) {
    require(args.size == 1) { "NEW external fixture-regression directory" }
    val root = File(args[0]).canonicalFile
    require(!root.exists() && root.parentFile.isDirectory)
    check(root.mkdir())
    requireIsolatedDefinitionLoader()
    val cases = mutableListOf<String>()
    val fixture = FinalBundleFixtures.bundle()
    var calls = 0
    val manifestEdit = rawResourcePatch(name = "Tools-only fixture manifest edit") {
        execute {
            calls++
            val file = get("AndroidManifest.xml")
            val before = decodedManifestSnapshot(file)
            file.writeBytes(before.toString(Charsets.UTF_8)
                .replace("android:extractNativeLibs=\"false\"", "android:extractNativeLibs=\"true\"").toByteArray())
        }
    }
    // Exercise the very same archive authoring, FULL preparation, pre-execute
    // guard, byte comparison and finally/close path used by final-bundle main.
    // Only a test-authored manifest edit executes; the HBC input is unchanged.
    val positive = exercise(manifestEdit, root, "full_prepared", fixture, expected = fixture.bytes, decode = true)
    check(positive["status"] == "resource_bytes_verified") { positive.toString() }
    check(calls == 1)
    val prepared = root.resolve("full_prepared")
    val input = prepared.resolve("synthetic-noninstallable.zip")
    ZipFile(input).use { zip ->
        check(zip.getEntry("resources.arsc") != null)
        val binary = zip.getInputStream(zip.getEntry("AndroidManifest.xml")).use { it.readBytes() }
        check(binary.take(4) == listOf<Byte>(3, 0, 8, 0)) { "Input manifest was not binary XML" }
    }
    val before = prepared.resolve("input.manifest").readBytes()
    check(before.toString(Charsets.UTF_8).contains("android:extractNativeLibs=\"false\""))
    check(prepared.resolve("output.manifest").readBytes().contentEquals(before.toString(Charsets.UTF_8)
        .replace("android:extractNativeLibs=\"false\"", "android:extractNativeLibs=\"true\"").toByteArray()))
    cases.add("shared_exercise_full_preparation_exact_manifest_edit")

    fun context(name: String, prepare: (ResourcePatchContext) -> Unit, body: (ResourcePatchContext) -> Unit) {
        val directory = root.resolve(name); check(directory.mkdir())
        val config = PatcherConfig(apkFile = input, temporaryFilesPath = directory.resolve("temporary"),
            fileWorkspacePath = directory.resolve("workspace"))
        ResourcePatchContext::class.java.getConstructor(PatcherConfig::class.java).newInstance(config).use { ctx ->
            prepare(ctx); body(ctx)
        }
        cases.add(name)
    }
    fun full(ctx: ResourcePatchContext) {
        ResourcePatchContext::class.java.getMethod("decodeResources\$morphe_patcher", ResourceMode::class.java)
            .invoke(ctx, ResourceMode.FULL)
    }
    fun guardRejects(file: File) {
        var executed = false
        val failure = try {
            decodedManifestSnapshot(file)
            executed = true // Represents reaching the patch callback after the guard.
            null
        } catch (e: IllegalStateException) { e }
        check(!executed && failure != null && failure.message.orEmpty().contains("before patch execution")) {
            "Invalid fixture reached execution: $file ($failure)"
        }
    }
    context("unprepared_context_rejected", {}) { ctx -> guardRejects(ctx.get("AndroidManifest.xml")) }
    context("direct_decode_does_not_prepare", { it.decode("AndroidManifest.xml") }) { ctx ->
        guardRejects(ctx.get("AndroidManifest.xml"))
    }
    context("raw_is_not_full_preparation", { ctx ->
        ResourcePatchContext::class.java.getMethod("decodeResources\$morphe_patcher", ResourceMode::class.java)
            .invoke(ctx, ResourceMode.RAW_ONLY)
    }) { ctx -> guardRejects(ctx.get("AndroidManifest.xml")) }
    context("missing_decoded_manifest_rejected", ::full) { ctx ->
        val file = ctx.get("AndroidManifest.xml")
        decodedManifestSnapshot(file)
        check(file.delete()); guardRejects(file)
    }
    for ((name, bytes) in listOf("empty_manifest_rejected" to byteArrayOf(),
        "binary_manifest_rejected" to byteArrayOf(3, 0, 8, 0),
        "wrong_decoded_content_rejected" to "<manifest><application /></manifest>".toByteArray())) {
        context(name, ::full) { ctx ->
            val file = ctx.get("AndroidManifest.xml")
            decodedManifestSnapshot(file)
            file.writeBytes(bytes); guardRejects(file)
        }
    }
    val noOp = rawResourcePatch(name = "Tools-only no-op") { execute { calls++ } }
    val unchanged = exercise(noOp, root, "no_op_rejected", fixture, expected = fixture.bytes, decode = true)
    check(unchanged["status"] == "failed" && unchanged["error"].toString().contains("Exact byte assertion failed"))
    check(calls == 2)
    cases.add("no_op_does_not_satisfy_exact_manifest_output")
    val extraEdit = rawResourcePatch(name = "Tools-only excessive edit") {
        execute {
            val file = get("AndroidManifest.xml")
            file.writeText(file.readText().replace("android:extractNativeLibs=\"false\"", "android:extractNativeLibs=\"true\"")
                .replace("dev.fishyau.plexfixture", "dev.fishyau.wrong"))
        }
    }
    val excessive = exercise(extraEdit, root, "extra_edit_rejected", fixture, expected = fixture.bytes, decode = true)
    check(excessive["status"] == "failed" && excessive["error"].toString().contains("Exact byte assertion failed"))
    cases.add("extra_manifest_edit_rejected")
    check(cases.size == 10)
    println(metadataGson.toJson(mapOf("status" to "manifest_fixture_regression_only", "cases" to cases,
        "actual_definition" to "not_observed", "resource_execution" to "not_observed", "runtime" to "not_observed",
        "scope" to "Actual pinned resource context and test-authored callbacks only; no final MPP or production patch execution")))
}
