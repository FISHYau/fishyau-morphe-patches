@file:Suppress("DEPRECATION")

import app.morphe.patcher.Patcher
import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.dex.BytecodeMode
import app.morphe.patcher.patch.*
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.iface.*
import com.android.tools.smali.dexlib2.iface.Annotation
import com.android.tools.smali.dexlib2.iface.debug.*
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload
import com.android.tools.smali.dexlib2.formatter.DexFormatter
import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import java.io.File
import java.lang.reflect.Modifier
import java.net.URLClassLoader
import java.security.MessageDigest
import java.util.jar.JarFile
import kotlin.system.exitProcess

private val json = GsonBuilder().serializeNulls().create()
private var phase = "request"
private val formatter = DexFormatter.INSTANCE
private fun sha(file: File) = MessageDigest.getInstance("SHA-256").let { digest ->
    file.inputStream().use { stream -> val buffer = ByteArray(65536); while (true) {
        val n = stream.read(buffer); if (n < 0) break; digest.update(buffer, 0, n)
    } }; digest.digest().joinToString("") { "%02x".format(it) }
}
private fun annotations(items: Set<Annotation>) = items.map { a ->
    "${a.visibility}:${a.type}:" + a.elements.sortedBy { it.name }.joinToString { "${it.name}=${formatter.getEncodedValue(it.value)}" }
}.sorted()
private fun Method.key() = formatter.getMethodDescriptor(this)

// Every method, not just a fingerprint subset. Pool indices and encoding widths
// are normalized; operands, control flow, handlers and debug semantics are not.
private fun Method.snapshot(): List<String> {
    val result = mutableListOf("flags=$accessFlags hidden=${hiddenApiRestrictions.sortedBy { it.name }} annotations=${annotations(annotations)}",
        "parameters=" + parameters.joinToString { "${it.type}:${it.name}:${it.signature}:${annotations(it.annotations)}" })
    val body = implementation ?: return result + "NO CODE"
    val instructions = body.instructions.toList()
    val offsets = mutableMapOf<Int, Int>(); var offset = 0
    instructions.forEachIndexed { index, instruction -> offsets[offset] = index; offset += instruction.codeUnits }
    offsets[offset] = instructions.size
    fun label(address: Int) = checkNotNull(offsets[address]) { "unsupported non-instruction address" }
    val switches = mutableMapOf<Int, Int>(); offset = 0
    for (instruction in instructions) {
        if (instruction.opcode == Opcode.PACKED_SWITCH || instruction.opcode == Opcode.SPARSE_SWITCH)
            check(switches.put(offset + (instruction as OffsetInstruction).codeOffset, offset) == null)
        offset += instruction.codeUnits
    }
    result += "registers=${body.registerCount}"
    for (region in body.tryBlocks) result += "try=${label(region.startCodeAddress)}..${label(region.startCodeAddress + region.codeUnitCount)} " +
        region.exceptionHandlers.joinToString { "${it.exceptionType}:${label(it.handlerCodeAddress)}" }
    for (debug in body.debugItems) {
        val extra = when (debug) {
            is StartLocal -> "${debug.register}:${debug.name}:${debug.type}:${debug.signature}"
            is EndLocal -> "${debug.register}:${debug.name}:${debug.type}:${debug.signature}"
            is RestartLocal -> "${debug.register}:${debug.name}:${debug.type}:${debug.signature}"
            is LineNumber -> "${debug.lineNumber}"
            is SetSourceFile -> "${debug.sourceFile}"
            is PrologueEnd, is EpilogueBegin -> ""
            else -> error("unsupported debug item")
        }
        result += "debug=${debug.debugItemType}:${label(debug.codeAddress)}:$extra"
    }
    offset = 0
    for (i in instructions) {
        check(i !is FieldOffsetInstruction && i !is InlineIndexInstruction && i !is VtableIndexInstruction && i !is VerificationErrorInstruction) {
            "optimized instructions unsupported"
        }
        val registers = when (i) {
            is RegisterRangeInstruction -> (i.startRegister until i.startRegister + i.registerCount).toList()
            is FiveRegisterInstruction -> listOf(i.registerC, i.registerD, i.registerE, i.registerF, i.registerG).take(i.registerCount)
            is ThreeRegisterInstruction -> listOf(i.registerA, i.registerB, i.registerC)
            is TwoRegisterInstruction -> listOf(i.registerA, i.registerB)
            is OneRegisterInstruction -> listOf(i.registerA)
            else -> emptyList()
        }
        val opcode = when (i.opcode) {
            Opcode.CONST_STRING_JUMBO -> Opcode.CONST_STRING
            Opcode.GOTO_16, Opcode.GOTO_32 -> Opcode.GOTO
            else -> i.opcode
        }
        var row = "$opcode $registers ref=${(i as? ReferenceInstruction)?.let { formatter.getReference(it.reference) }} " +
            "ref2=${(i as? DualReferenceInstruction)?.let { formatter.getReference(it.reference2) }} " +
            "literal=${(i as? WideLiteralInstruction)?.wideLiteral} target=${(i as? OffsetInstruction)?.let { label(offset + it.codeOffset) }}"
        if (i is SwitchPayload) { val owner = checkNotNull(switches[offset]); row += " switch=" + i.switchElements.joinToString { "${it.key}:${label(owner + it.offset)}" } }
        if (i is ArrayPayload) row += " array=${i.elementWidth}:${i.arrayElements}"
        result += row; offset += i.codeUnits
    }
    return result
}

private data class Snapshot(val methods: Map<String, List<String>>, val classes: Map<String, List<String>>)
private fun snapshot(classes: List<ClassDef>): Snapshot {
    val methods = sortedMapOf<String, List<String>>(); val metadata = sortedMapOf<String, List<String>>()
    for (c in classes) {
        check(c.type !in metadata) { "duplicate class" }
        metadata[c.type] = listOf("${c.accessFlags}:${c.superclass}:${c.interfaces}:${c.sourceFile}:${annotations(c.annotations)}") +
            c.fields.map { f -> "${formatter.getFieldDescriptor(f)}:${f.accessFlags}:${f.hiddenApiRestrictions.sortedBy { it.name }}:" +
                "${f.initialValue?.let { formatter.getEncodedValue(it) }}:${annotations(f.annotations)}" }.sorted()
        for (m in c.methods) check(methods.put(m.key(), m.snapshot()) == null) { "duplicate method" }
    }
    return Snapshot(methods, metadata)
}
private fun readApk(apk: File): Snapshot {
    val container = DexFileFactory.loadDexContainer(apk, Opcodes.forApi(36))
    return snapshot(container.dexEntryNames.flatMap { checkNotNull(container.getEntry(it)).dexFile.classes.toList() })
}
private fun readDex(files: List<File>) = snapshot(files.flatMap { DexFileFactory.loadDexFile(it, Opcodes.forApi(36)).classes.toList() })

private fun execute(request: File) = runBlocking {
    val r = json.fromJson(request.readText(), JsonObject::class.java)
    fun text(key: String) = r.get(key).asString
    val requestHash = sha(request)
    val mode = r.get("input_mode")?.asString ?: "standalone"
    check(mode in setOf("standalone", "base_config_set"))
    val split = mode == "base_config_set"
    val binding = if (split) r.getAsJsonObject("split_binding") else null
    fun checkRecord(record: JsonObject) {
        check(sha(File(record.get("path").asString).canonicalFile) == record.get("sha256").asString)
    }
    fun checkSet() {
        check(sha(request) == requestHash)
        if (split) {
            val sources = r.getAsJsonArray("source_hashes")
            check(sources.size() > 0)
            sources.forEach { checkRecord(it.asJsonObject) }
        }
        binding?.let { b ->
            check(b.get("input_mode").asString == mode)
            val container = b.getAsJsonObject("logical_container")
            check(container.get("type").asString == "APKM"); checkRecord(container)
            val originals = b.getAsJsonArray("apks")
            val mapping = b.getAsJsonArray("staged_apks")
            val topology = b.getAsJsonObject("staged_topology")
            check(originals.size() in 2..256 && mapping.size() == originals.size())
            check(topology.get("mode").asString == mode)
            val members = topology.getAsJsonArray("members")
            check(members.size() == mapping.size())
            val paths = mutableSetOf<String>()
            mapping.forEachIndexed { i, element ->
                val pair = element.asJsonObject
                check(pair.get("original") == originals[i])
                checkRecord(originals[i].asJsonObject)
                val staged = pair.getAsJsonObject("staged"); checkRecord(staged)
                check(paths.add(File(staged.get("path").asString).canonicalPath))
                check(staged.get("sha256") == originals[i].asJsonObject.get("sha256"))
                check(staged.get("path") == members[i].asJsonObject.get("path") &&
                    staged.get("sha256") == members[i].asJsonObject.get("sha256"))
            }
            val base = b.getAsJsonObject("base"); checkRecord(base)
            val basePair = mapping.single { it.asJsonObject.getAsJsonObject("original").let { original ->
                original.get("path") == base.get("path") && original.get("sha256") == base.get("sha256")
            } }.asJsonObject
            check(basePair.getAsJsonObject("staged").get("path").asString == text("input"))
            check(topology.get("base").asString == text("input") &&
                topology.get("base_sha256").asString == text("input_sha256"))
        }
    }
    checkSet()
    val bundle = File(text("bundle")).canonicalFile; val input = File(text("input")).canonicalFile
    val output = File(text("output")).canonicalFile
    check(!output.exists() && output.parentFile.isDirectory && output.mkdir())
    check(text("patcher_version") == "2.3.0")
    check(sha(bundle) == text("bundle_sha256") && sha(input) == text("input_sha256"))
    JarFile(bundle).use { check(it.manifest.mainAttributes.getValue("Patcher-Version") == "2.3.0") }
    val names = r.getAsJsonArray("patches").map { it.asString }
    check(names.isNotEmpty() && names.size == names.toSet().size)
    check(r.getAsJsonObject("options").size() == 0) { "options unsupported" }
    phase = "bundle loading"
    val loaded = loadPatchesFromJar(setOf(bundle))
    phase = "definition preflight"
    val selected = names.map { name -> loaded.filter { it.name == name }.single() }.toSet()
    val identity = r.getAsJsonObject("identity")
    val signers = identity.getAsJsonArray("signers_sha256").map { it.asString.lowercase() }.toSet()
    for (p in selected) {
        check(p is BytecodePatch && p.dependencies.isEmpty() && p.options.isEmpty()) { "only independent option-free bytecode patches supported" }
        val matches = checkNotNull(p.compatibility).filter { c ->
            c.packageName == identity.get("package").asString &&
                (if (split) c.apkFileType in setOf(ApkFileType.APKM, ApkFileType.APKM_REQUIRED)
                 else c.apkFileType in setOf(null, ApkFileType.APK, ApkFileType.APK_REQUIRED)) &&
                (c.signatures == null || c.signatures!!.map { it.lowercase() }.toSet() == signers) &&
                c.targets.any { t -> t.version == identity.get("version_name").asString &&
                    t.versionCodes != null && t.versionCodes!!.values.toSet() == setOf(identity.get("version_code").asInt) && !t.isExperimental }
        }
        check(matches.size == 1) { "explicit package/version/code/logical input compatibility required" }
    }
    val assertionClass = text("assertion_class")
    URLClassLoader(arrayOf(bundle.toURI().toURL()), Patcher::class.java.classLoader).use { loader ->
        val cls = Class.forName(assertionClass, false, loader)
        check(File(cls.protectionDomain.codeSource.location.toURI()).canonicalFile == bundle)
        val verify = cls.getMethod("verify", Map::class.java, Map::class.java)
        check(Modifier.isStatic(verify.modifiers) && verify.returnType == Void.TYPE)
        JarFile(bundle).use { jar ->
            val bytes = jar.getInputStream(checkNotNull(jar.getJarEntry(assertionClass.replace('.', '/') + ".class"))).use { it.readBytes() }
            val hash = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            check(hash == text("assertion_sha256"))
        }
        phase = "input snapshot"
        fun canonicalDex(names: List<String>): Set<String> {
            check(names.isNotEmpty() && names.size == names.toSet().size)
            val expected = (1..names.size).map { if (it == 1) "classes.dex" else "classes${it}.dex" }.toSet()
            check(names.toSet() == expected) { "complete contiguous canonical DEX required" }
            return expected
        }
        val originalDex = java.util.zip.ZipFile(input).use { archive ->
            canonicalDex(archive.entries().asSequence().map { it.name }.filter { it.lowercase().endsWith(".dex") }.toList())
        }
        checkSet()
        val before = readApk(input)
        phase = "patch execution"
        val config = PatcherConfig(apkFile = input, temporaryFilesPath = output.resolve("temporary"),
            useBytecodeMode = BytecodeMode.STRIP_SAFE, validate = true)
        val files = Patcher(config).use { patcher ->
            patcher += selected
            val results = patcher().toList()
            check(results.size == selected.size && results.map { it.patch }.toSet() == selected)
            check(results.none { it.exception != null }) { "patch execution failed" }
            phase = "DEX compilation"
            val result = patcher.get()
            phase = "resource output preflight"
            result.resources?.let { resources ->
                check(resources.resourcesApk?.exists() != true && resources.deleteResources.isEmpty() &&
                    resources.otherResources?.walkTopDown()?.none { it.isFile } != false) { "resource transformations unsupported" }
            }
            phase = "DEX emission"
            val dex = output.resolve("dex"); check(dex.mkdir())
            val namesSeen = mutableSetOf<String>()
            result.dexFiles.map { item ->
                check(item.name.matches(Regex("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")) && namesSeen.add(item.name))
                dex.resolve(item.name).also { file -> item.stream.use { stream -> file.outputStream().use { stream.copyTo(it) } } }
            }.also {
                val emitted = canonicalDex(it.map { file -> file.name })
                if (split && !binding!!.get("allow_dex_layout_change").asBoolean)
                    check(emitted == originalDex) { "DEX layout change requires explicit opt-in" }
            }
        }
        phase = "emitted snapshot"
        val after = readDex(files)
        phase = "preservation assertions"
        check(before.classes == after.classes && before.methods.keys == after.methods.keys) { "class/field/method preservation failed" }
        check(before.methods != after.methods) { "no code changed" }
        // Unmodifiable complete snapshots: trusted app-specific verify must reject
        // wrong edits, missing edits and any unexpected changed method/instruction.
        fun freeze(m: Map<String, List<String>>) = java.util.Collections.unmodifiableMap(m.mapValues { java.util.Collections.unmodifiableList(it.value) })
        phase = "app-specific assertions"
        verify.invoke(null, freeze(before.methods), freeze(after.methods))
        check(sha(bundle) == text("bundle_sha256") && sha(input) == text("input_sha256"))
        val report = mapOf("status" to "applied_structurally_verified", "structural_assertions" to mapOf("status" to "passed"),
            "changed_methods" to before.methods.keys.filter { before.methods[it] != after.methods[it] },
            "method_count" to before.methods.size, "patches" to names,
            "dex" to files.map { mapOf("name" to it.name, "path" to it.canonicalPath, "sha256" to sha(it)) })
        checkSet()
        val evidence = report.toMutableMap()
        if (split) evidence.putAll(mapOf("input_mode" to mode, "split_binding" to binding!!,
            "compatibility_mode" to "APKM", "request_sha256" to requestHash))
        output.resolve("runner.json").writeText(json.toJson(evidence))
    }
}

fun main(args: Array<String>) {
    try {
        check(args.size == 1)
        execute(File(args.single()))
        println("structural assertions passed")
    } catch (_: Throwable) {
        // Neither user code exceptions nor patcher diagnostics are an API/log channel.
        System.err.println("patch application or structural verification failed at $phase")
        exitProcess(2)
    }
}
