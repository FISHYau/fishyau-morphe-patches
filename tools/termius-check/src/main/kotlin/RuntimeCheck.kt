@file:Suppress("DEPRECATION")

import app.morphe.patcher.Patcher
import app.morphe.patcher.PatcherConfig
import app.morphe.patcher.dex.BytecodeMode
import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.patch.loadPatchesFromJar
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21t
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.iface.reference.TypeReference
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.StandardOpenOption
import io.github.fishyau.androidpatches.tools.*
import com.google.gson.JsonParser
import java.util.jar.JarFile
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

private const val PRO = "Lcom/server/auditor/ssh/client/models/UserType\$Pro;"
private const val STORAGE = "Lcom/server/auditor/ssh/client/app/a;"
private const val TERMINAL = "Lcom/crystalnix/termius/libtermius/wrappers/TerminalConnectionManager;"
private const val LOCAL_EDITOR = "Lcom/server/auditor/ssh/client/fragments/editors/local/base/c;"
private const val WIDGET = "Lcom/server/auditor/ssh/client/widget/editors/SnippetEditorLayout;"
private const val PRESENTER = "Lcom/server/auditor/ssh/client/presenters/SshConfigEditorPresenter;"
private const val MAPPER_KEY = "Lcm/c;->c(Ljava/lang/String;)Lcom/server/auditor/ssh/client/models/UserType;"
private const val EXPIRY_KEY = "$PRO->isExpired()Z"
private const val STORAGE_KEY = "$STORAGE->u0()Z"
private const val WIDGET_KEY = "$WIDGET->setState(Lbs/h;)V"
private const val SSH_KEY = "Lci/w;->vb()V"
private const val TERMINAL_KEY = "$TERMINAL->startConnection(Lcom/server/auditor/ssh/client/models/connections/Connection;Z)I"
private val offlineKeys = setOf(WIDGET_KEY, SSH_KEY, TERMINAL_KEY)

private fun Method.key() = "$definingClass->$name(${parameterTypes.joinToString("")})$returnType"

// Normalize pool indices/encoding widths, not operands or control-flow semantics.
// For approved prepends, index the suffix relative to its original entry. Rebase
// branch, payload, switch and exception targets; never silently allow a suffix
// target to enter the omitted prefix.
private fun Method.snapshot(ignoredPrefixInstructions: Int = 0): List<String> {
    val body = implementation ?: return listOf("flags=$accessFlags", "NO CODE")
    val instructions = body.instructions.toList()
    check(ignoredPrefixInstructions in 0..instructions.size)
    val offsets = mutableMapOf<Int, Int>()
    var offset = 0
    instructions.forEachIndexed { index, instruction -> offsets[offset] = index; offset += instruction.codeUnits }
    offsets[offset] = instructions.size
    fun label(address: Int): Int {
        val index = checkNotNull(offsets[address]) { "Bad instruction target $address in ${key()}" }
        check(index >= ignoredPrefixInstructions) { "Suffix target enters omitted prefix in ${key()}" }
        return index - ignoredPrefixInstructions
    }
    val switchOwners = mutableMapOf<Int, Int>()
    offset = 0
    for (instruction in instructions) {
        if (instruction.opcode in listOf(Opcode.PACKED_SWITCH, Opcode.SPARSE_SWITCH)) {
            switchOwners[offset + (instruction as OffsetInstruction).codeOffset] = offset
        }
        offset += instruction.codeUnits
    }
    val result = mutableListOf("flags=$accessFlags registers=${body.registerCount}")
    for (region in body.tryBlocks) {
        result += "try=${label(region.startCodeAddress)}..${label(region.startCodeAddress + region.codeUnitCount)} " +
            region.exceptionHandlers.joinToString { "${it.exceptionType}:${label(it.handlerCodeAddress)}" }
    }
    offset = instructions.take(ignoredPrefixInstructions).sumOf { it.codeUnits }
    for (instruction in instructions.drop(ignoredPrefixInstructions)) {
        val registers = when (instruction) {
            is RegisterRangeInstruction -> (instruction.startRegister until instruction.startRegister + instruction.registerCount).toList()
            is FiveRegisterInstruction -> listOf(instruction.registerC, instruction.registerD, instruction.registerE,
                instruction.registerF, instruction.registerG).take(instruction.registerCount)
            is ThreeRegisterInstruction -> listOf(instruction.registerA, instruction.registerB, instruction.registerC)
            is TwoRegisterInstruction -> listOf(instruction.registerA, instruction.registerB)
            is OneRegisterInstruction -> listOf(instruction.registerA)
            else -> emptyList()
        }
        val opcode = when (instruction.opcode) {
            Opcode.CONST_STRING_JUMBO -> Opcode.CONST_STRING
            Opcode.GOTO_16, Opcode.GOTO_32 -> Opcode.GOTO
            else -> instruction.opcode
        }
        var row = "$opcode $registers ref=${(instruction as? ReferenceInstruction)?.reference} " +
            "ref2=${(instruction as? DualReferenceInstruction)?.reference2} " +
            "literal=${(instruction as? WideLiteralInstruction)?.wideLiteral} " +
            "target=${(instruction as? OffsetInstruction)?.let { label(offset + it.codeOffset) }}"
        if (instruction is SwitchPayload) {
            val base = checkNotNull(switchOwners[offset])
            row += " switch=" + instruction.switchElements.joinToString { "${it.key}:${label(base + it.offset)}" }
        }
        if (instruction is ArrayPayload) row += " array=${instruction.elementWidth}:${instruction.arrayElements}"
        result += row
        offset += instruction.codeUnits
    }
    return result
}

private val comparedOwners = setOf(
    "Lcm/c;", PRO, STORAGE, TERMINAL, LOCAL_EDITOR, WIDGET, PRESENTER,
    "Lci/w;", "Lci/w\$p;", "Lbs/i;", "Ltr/h0;", "Lgh/z;",
    "Lcom/server/auditor/ssh/client/fragments/editors/base/c;",
    "Lcom/server/auditor/ssh/client/database/DataLoadingHelper;",
    "Lcom/server/auditor/ssh/client/synchronization/api/models/user/AccountResponse;",
    "Lcom/server/auditor/ssh/client/onboarding/OnboardingActivity;",
)
private fun isCompared(owner: String) = owner in comparedOwners ||
    owner.startsWith(LOCAL_EDITOR.dropLast(1) + "$" ) || owner.startsWith(PRESENTER.dropLast(1) + "$")

private fun collectCompared(classes: Sequence<ClassDef>): Map<String, Method> {
    val owners = mutableSetOf<String>()
    val methods = linkedMapOf<String, Method>()
    for (definition in classes.filter { isCompared(it.type) }) {
        check(owners.add(definition.type)) { "Duplicate compared class: ${definition.type}" }
        for (method in definition.methods) {
            check(methods.put(method.key(), method) == null) { "Duplicate compared method: ${method.key()}" }
        }
    }
    return methods
}
private fun readComparedMethods(apk: File): Map<String, Method> {
    val container = DexFileFactory.loadDexContainer(apk, Opcodes.forApi(36))
    return collectCompared(container.dexEntryNames.asSequence().flatMap { name ->
        checkNotNull(container.getEntry(name)).dexFile.classes.asSequence()
    })
}
private fun readEmitted(files: List<File>) = collectCompared(files.asSequence().flatMap {
    DexFileFactory.loadDexFile(it, Opcodes.forApi(36)).classes.asSequence()
})

private fun writeFixture(original: File, dexFiles: List<File>, target: File) {
    check(!target.exists())
    ZipFile(original).use { input ->
        ZipOutputStream(target.outputStream()).use { zip ->
            for (entry in input.entries()) {
                if (entry.name.matches(Regex("classes[0-9]*\\.dex"))) continue
                zip.putNextEntry(ZipEntry(entry.name))
                if (!entry.isDirectory) input.getInputStream(entry).use { it.copyTo(zip) }
                zip.closeEntry()
            }
            for (dex in dexFiles) {
                zip.putNextEntry(ZipEntry(dex.name))
                dex.inputStream().use { it.copyTo(zip) }
                zip.closeEntry()
            }
        }
    }
}
// Keep emitted-file checks local to this run; no separate receipt/manifest files.
private val emittedOutputs = mutableMapOf<File, List<Map<String, Any>>>()
private fun dexInventory(directory: File): List<Map<String, Any>> {
    val files = checkNotNull(directory.listFiles()).toList()
    check(files.isNotEmpty()) { "No emitted DEX" }
    val names = files.map { it.name }
    val canonical = (1..files.size).map { if (it == 1) "classes.dex" else "classes$it.dex" }
    check(names.toSet() == canonical.toSet() && names.size == names.toSet().size) { "Noncanonical DEX set: $names" }
    val ordered = canonical.map { directory.resolve(it) }
    ordered.forEachIndexed { i, file ->
        check(file.isFile && !Files.isSymbolicLink(file.toPath()) && file.canonicalFile == file.absoluteFile)
        check(ordered.take(i).none { Files.isSameFile(file.toPath(), it.toPath()) }) { "Aliased DEX" }
    }
    return ordered.map { mapOf("name" to it.name, "size" to it.length(), "sha256" to sha256(it)) }
}
private fun verifyEmitted(directory: File): List<Map<String, Any>> {
    val recorded = emittedOutputs.getValue(directory)
    check(dexInventory(directory) == recorded) { "Emitted DEX mutated: $directory" }
    return recorded
}
private fun emitDex(patcher: Patcher, directory: File): List<File> {
    check(directory.mkdir())
    val names = mutableSetOf<String>()
    val files = patcher.get().dexFiles.map { dex ->
        require(dex.name.matches(Regex("classes(?:[2-9]|[1-9][0-9]+)?\\.dex")) && names.add(dex.name)) {
            "Duplicate/aliased/noncanonical DEX name: ${dex.name}"
        }
        directory.resolve(dex.name).also { file ->
            dex.stream.use { stream -> Files.newOutputStream(file.toPath(), StandardOpenOption.CREATE_NEW).use { stream.copyTo(it) } }
        }
    }
    emittedOutputs[directory] = dexInventory(directory)
    verifyEmitted(directory)
    return files
}

private fun verifyMapper(method: Method) {
    val body = checkNotNull(method.implementation)
    check(body.registerCount == 5 && body.tryBlocks.isEmpty())
    val prefix = body.instructions.take(6)
    check(prefix.map { it.opcode } == listOf(Opcode.CONST_STRING, Opcode.CONST_4, Opcode.CONST_4,
        Opcode.NEW_INSTANCE, Opcode.INVOKE_DIRECT, Opcode.RETURN_OBJECT))
    check(((prefix[0] as ReferenceInstruction).reference as StringReference).string == "Premium")
    check((prefix[0] as OneRegisterInstruction).registerA == 4)
    for ((index, register) in listOf(1 to 1, 2 to 2)) {
        check((prefix[index] as NarrowLiteralInstruction).narrowLiteral == 0)
        check((prefix[index] as OneRegisterInstruction).registerA == register)
    }
    check(((prefix[3] as ReferenceInstruction).reference as TypeReference).type == PRO)
    check((prefix[3] as OneRegisterInstruction).registerA == 0)
    val call = prefix[4] as FiveRegisterInstruction
    check(call.registerCount == 4 && listOf(call.registerC, call.registerD, call.registerE, call.registerF) == listOf(0, 4, 1, 2))
    val constructor = (prefix[4] as ReferenceInstruction).reference as MethodReference
    check(constructor.definingClass == PRO && constructor.name == "<init>" && constructor.returnType == "V")
    check(constructor.parameterTypes.map { it.toString() } == listOf("Ljava/lang/String;", "Z",
        "Lcom/server/auditor/ssh/client/models/SubscriptionPeriod;"))
    check((prefix[5] as OneRegisterInstruction).registerA == 0)
}
private fun verifyExpiry(method: Method) {
    val prefix = checkNotNull(method.implementation).instructions.take(2)
    check(prefix.map { it.opcode } == listOf(Opcode.CONST_4, Opcode.RETURN))
    check((prefix[0] as NarrowLiteralInstruction).narrowLiteral == 0)
    check((prefix[0] as OneRegisterInstruction).registerA == (prefix[1] as OneRegisterInstruction).registerA)
}
private fun verifySingleEdit(original: Method, patched: Method, index: Int, register: Int, reference: String? = null) {
    val a = checkNotNull(original.implementation)
    val b = checkNotNull(patched.implementation)
    check(a.tryBlocks.isEmpty() && b.tryBlocks.isEmpty())
    val before = original.snapshot()
    val after = patched.snapshot()
    check(before.size == after.size)
    check(before.filterIndexed { n, _ -> n != index + 1 } == after.filterIndexed { n, _ -> n != index + 1 }) {
        "More than the approved instruction changed in ${patched.key()}"
    }
    val oldInstruction = a.instructions.toList()[index]
    val instruction = b.instructions.toList()[index]
    check(oldInstruction.codeUnits == instruction.codeUnits)
    if (reference != null) {
        check(instruction.opcode == Opcode.INVOKE_DIRECT)
        check((instruction as FiveRegisterInstruction).registerCount == 1 && instruction.registerC == register)
        check((instruction as ReferenceInstruction).reference.toString() == reference)
    } else {
        check(oldInstruction.opcode == Opcode.MOVE_RESULT && instruction.opcode == Opcode.CONST_4)
        check((instruction as OneRegisterInstruction).registerA == register)
        check((instruction as NarrowLiteralInstruction).narrowLiteral == 1)
    }
}
private fun fingerprint(key: String): Fingerprint = when (key) {
    WIDGET_KEY -> Fingerprint(definingClass = WIDGET, name = "setState", returnType = "V", parameters = listOf("Lbs/h;"))
    SSH_KEY -> Fingerprint(definingClass = "Lci/w;", name = "vb", returnType = "V", parameters = listOf())
    TERMINAL_KEY -> Fingerprint(definingClass = TERMINAL, name = "startConnection", returnType = "I",
        parameters = listOf("Lcom/server/auditor/ssh/client/models/connections/Connection;", "Z"))
    STORAGE_KEY -> Fingerprint(definingClass = STORAGE, name = "u0", returnType = "Z", parameters = listOf())
    else -> error("Unknown fixture target $key")
}

// Keep both output and patcher scratch directories, including on failure.
private fun reserveStructuralDirectories(requested: File, source: File, inputs: List<File>): Pair<File, File> {
    val output = requested.absoluteFile
    check(output.toPath() == output.toPath().normalize() && output == output.canonicalFile) { "Canonical output required" }
    val parent = output.parentFile
    check(parent.isDirectory) { "Existing output parent required" }
    var ancestor: File? = parent
    while (ancestor != null) {
        val attributes = Files.readAttributes(ancestor.toPath(), BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        check(!attributes.isSymbolicLink && !attributes.isOther && ancestor == ancestor.canonicalFile) { "Linked/special output ancestor" }
        ancestor = ancestor.parentFile
    }
    val work = parent.resolve(output.name + "-work")
    for (directory in listOf(output, work)) {
        check(!Files.exists(directory.toPath(), NOFOLLOW_LINKS)) { "NEW output and work directories required" }
        for (protected in listOf(source) + inputs) {
            val path = protected.canonicalFile.toPath()
            check(!directory.toPath().startsWith(path) && !path.startsWith(directory.toPath())) { "Output/work must be external and disjoint from inputs" }
        }
    }
    // Validate both before consuming either. A later failure never cleans either.
    Files.createDirectory(output.toPath())
    Files.createDirectory(work.toPath())
    return output to work
}

fun main(args: Array<String>) = runBlocking {
    require(args.size == 5) { "Usage: exact.mpp input-base.apk NEW_OUTPUT_DIRECTORY exact-catalog.json SOURCE_REPOSITORY_ROOT" }
    val bundle = File(args[0]).canonicalFile
    val input = File(args[1]).canonicalFile
    val catalog = File(args[3]).canonicalFile
    val source = File(args[4]).canonicalFile
    require(source.resolve("patches/build.gradle.kts").isFile)
    require(bundle.isFile && input.isFile && catalog.isFile)
    val bundleHash = sha256(bundle)
    val inputHash = sha256(input)
    val catalogHash = sha256(catalog)
    val (output, work) = reserveStructuralDirectories(File(args[2]), source, listOf(bundle, input, catalog))
    emittedOutputs.clear()
    val selections = mutableListOf<MutableMap<String, Any>>()
    val negativeResults = mutableListOf<MutableMap<String, Any>>()
    val negativeFixtures = mutableMapOf<File, String>()
    fun begin(names: List<String>, destination: MutableList<MutableMap<String, Any>>): MutableMap<String, Any> {
        val record = mutableMapOf<String, Any>("selected" to names.sorted(), "status" to "incomplete")
        destination += record
        return record
    }
    try {
    JarFile(bundle).use {
        val patcherVersion = it.manifest.mainAttributes.getValue("Patcher-Version")
        println("Bundle Patcher-Version: $patcherVersion")
        check(patcherVersion == "2.3.0") { "Bundle must target this checker's patcher 2.3.0" }
        check(it.getEntry("classes.dex") != null)
    }
    requireIsolatedDefinitionLoader()
    val loaded = loadPatchesFromJar(setOf(bundle))
    requireCollectionInventory(loaded)
    val patch = loaded.single { it.name == "Server Auditor Offline Automation" }
    val premium = loaded.single { it.name == "Server Auditor Premium" }
    val definitions = projectPatchDefinitions(loaded)
    val parsedCatalog = JsonParser.parseString(catalog.readText()).asJsonObject
    check(parsedCatalog.getAsJsonArray("patches") == definitions) { "Catalog differs from loaded definitions" }
    JarFile(bundle).use { check(parsedCatalog.get("version").asString == it.manifest.mainAttributes.getValue("Version")) }
    println("Validated exactly four default-on collection definitions; applying only the two Termius patches, alone and combined")
    println("Default co-selection is metadata, not combined Android runtime acceptance")
    println("Plex RAW-resource application is excluded; this bytecode checker does not support it")
    println("Runtime: morphe-patcher 2.3.0; base APK only, NOT an installable app")
    fun config(apk: File, directory: File): PatcherConfig {
        check(directory.toPath().startsWith(work.toPath()) && directory != work &&
            directory == directory.canonicalFile && !Files.exists(directory.toPath(), NOFOLLOW_LINKS)) { "NEW contained patcher work directory required" }
        return PatcherConfig(apkFile = apk, temporaryFilesPath = directory,
            useBytecodeMode = BytecodeMode.STRIP_SAFE, validate = true)
    }
    val originals = readComparedMethods(input)
    val originalSnapshots = originals.mapValues { it.value.snapshot() }
    val checks = mutableListOf<String>()
    fun report(message: String) { checks += message; output.resolve("verification.txt").appendText(message + "\n"); println(message) }
    fun recordSelection(record: MutableMap<String, Any>, changed: Set<String>, count: Int, directory: File) {
        verifyEmitted(directory)
        record.putAll(mapOf("status" to "applied_emitted_reread_verified",
            "changed_methods" to changed.sorted(), "compared_methods" to count))
    }
    fun patchResult(name: String?, exception: Throwable?) = mapOf("name" to name, "error" to exception?.let { failure ->
        generateSequence(failure) { it.cause }.joinToString("\n") { "${it.javaClass.name}: ${it.message}" }
    })
    fun verifyOffline(compared: Map<String, Method>) {
        verifySingleEdit(originals.getValue(WIDGET_KEY), compared.getValue(WIDGET_KEY), 4, 1, "$WIDGET->N()V")
        verifySingleEdit(originals.getValue(SSH_KEY), compared.getValue(SSH_KEY), 12, 1)
        verifySingleEdit(originals.getValue(TERMINAL_KEY), compared.getValue(TERMINAL_KEY), 31, 0)
    }
    fun verifyPremium(compared: Map<String, Method>) {
        verifyMapper(compared.getValue(MAPPER_KEY))
        verifyExpiry(compared.getValue(EXPIRY_KEY))
        for ((key, count) in listOf(MAPPER_KEY to 6, EXPIRY_KEY to 2)) {
            val before = originalSnapshots.getValue(key)
            val suffix = compared.getValue(key).snapshot(count)
            check(suffix == before) {
                "Premium must only prepend the approved prefix, preserving registers and complete original body: $key"
            }
        }
    }
    val offlineResult = begin(listOf(patch.name!!), selections)
    val compiled = Patcher(config(input, work.resolve("temporary"))).use { patcher ->
        patcher += setOf(patch)
        val results = patcher().toList()
        offlineResult["patch_results"] = results.map { patchResult(it.patch.name, it.exception) }
        check(results.size == 1 && results.single().patch.name == patch.name)
        results.forEach { it.exception?.let { failure -> throw failure } }
        val files = emitDex(patcher, output.resolve("dex"))
        val compared = readEmitted(files)
        check(compared.keys == originals.keys)
        val changed = compared.filter { (key, method) -> method.snapshot() != originalSnapshots[key] }.keys
        check(changed == offlineKeys) { "Unexpected changes: $changed" }
        check(changed.map { it.substringBefore("->") }.toSet().size == 3)
        verifyOffline(compared)
        recordSelection(offlineResult, changed, compared.size, output.resolve("dex"))
        report("PASS: standalone Offline Automation loads/applies/compiles/re-reads with patcher 2.3.0")
        report("PASS: exactly three single-instruction replacements in ${compared.size} compared methods")
        report("PASS: global Pro/auth getters, mapper/expiry, account/onboarding code and selection/save callbacks unchanged")
        report("PASS: permission-disabled widget branch, connection setup, original z branches/arguments and return preserved")
        report("NOT TESTED: ART, Manager UI/merge/sign, device behavior, account-free execution or repaired sign-in")
        files
    }

    suspend fun assertRejected(fixture: File, directory: File, diagnostic: String, already: Boolean,
        selected: Set<app.morphe.patcher.patch.Patch> = setOf(patch)) {
        val record = begin(selected.map { it.name!! }, negativeResults)
        record.putAll(mapOf("name" to directory.name, "expected_diagnostic" to diagnostic))
        val fixtureHash = sha256(fixture)
        negativeFixtures[fixture] = fixtureHash
        val before = readComparedMethods(fixture).mapValues { it.value.snapshot() }
        record["compared_methods"] = before.size
        Patcher(config(fixture, work.resolve(directory.name).resolve("temporary"))).use { rejected ->
            rejected += selected
            val results = rejected().toList()
            record["patch_results"] = results.map { patchResult(it.patch.name, it.exception) }
            check(selected.size == 1 && results.size == 1 && results.single().patch.name == selected.single().name) {
                "Negative requires the exact singleton selection/result"
            }
            val failures = results.mapNotNull { it.exception }
            check(failures.isNotEmpty()) { "Fixture unexpectedly accepted: ${directory.name}" }
            val messages = failures.flatMap { failure ->
                generateSequence(failure as Throwable) { it.cause }.map { it.message.orEmpty() }.toList()
            }.joinToString("\n")
            record["rejection_diagnostic"] = messages
            val matched = diagnostic in messages && (!already || "already patched" in messages)
            check(matched) { "Wrong rejection: $messages" }
            val after = readEmitted(emitDex(rejected, directory.resolve("rejected-dex"))).mapValues { it.value.snapshot() }
            verifyEmitted(directory.resolve("rejected-dex"))
            check(before == after) { "Preflight mutated code before rejection: ${directory.name}" }
            check(sha256(fixture) == fixtureHash) { "Fixture mutated" }
            record["status"] = "expected_rejection_unchanged_bounded_snapshot"
            report("PASS: ${directory.name} rejected by $diagnostic preflight before any compared method mutation")
        }
    }
    // All APKs below are unsigned/incomplete local fixtures; never install or distribute.
    val repeated = output.resolve("repeat").also { check(it.mkdir()) }
    val repeatedApk = repeated.resolve("fixture-NOT-INSTALLABLE.apk")
    writeFixture(input, compiled, repeatedApk)
    assertRejected(repeatedApk, repeated, "snippet widget", true)

    data class Fixture(val name: String, val key: String, val diagnostic: String, val already: Boolean)
    val fixtures = listOf(
        Fixture("widget-only", WIDGET_KEY, "snippet widget", true),
        Fixture("ssh-only", SSH_KEY, "SSH Automation", true),
        Fixture("terminal-only", TERMINAL_KEY, "terminal Automation", true),
        Fixture("wrong-widget-helper", WIDGET_KEY, "snippet widget", false),
        Fixture("wrong-result-register", SSH_KEY, "SSH Automation", true),
        Fixture("wrong-branch-target", TERMINAL_KEY, "terminal Automation", false),
        Fixture("global-pro-override", STORAGE_KEY, "storage Pro getter", true),
    )
    for (fixture in fixtures) {
        val directory = output.resolve(fixture.name).also { check(it.mkdir()) }
        val makerPatch = bytecodePatch(name = "Local fixture ${fixture.name}") {
            execute {
                val method = fingerprint(fixture.key).matchAllOrNull().orEmpty().single().method
                when (fixture.name) {
                    "widget-only" -> method.replaceInstruction(4, "invoke-direct {p0}, $WIDGET->N()V")
                    "ssh-only" -> method.replaceInstruction(12, "const/4 v1, 0x1")
                    "terminal-only" -> method.replaceInstruction(31, "const/4 v0, 0x1")
                    "wrong-widget-helper" -> method.replaceInstruction(4, "invoke-direct {p0}, $WIDGET->J()V")
                    "wrong-result-register" -> method.replaceInstruction(12, "const/4 v0, 0x1")
                    "wrong-branch-target" -> {
                        val body = checkNotNull(method.implementation)
                        body.replaceInstruction(32, BuilderInstruction21t(Opcode.IF_NEZ, 0, body.newLabelForIndex(body.instructions.lastIndex)))
                    }
                    "global-pro-override" -> method.addInstructions(0, "const/4 v0, 0x1\nreturn v0")
                }
            }
        }
        val apk = directory.resolve("fixture-NOT-INSTALLABLE.apk")
        Patcher(config(input, work.resolve(directory.name).resolve("maker-temporary"))).use { maker ->
            maker += setOf(makerPatch)
            maker().toList().forEach { it.exception?.let { failure -> throw failure } }
            writeFixture(input, emitDex(maker, directory.resolve("fixture-dex")), apk)
        }
        val changed = readComparedMethods(apk).filter { (key, method) -> method.snapshot() != originalSnapshots[key] }.keys
        check(changed == setOf(fixture.key)) { "Incorrect independent fixture: $changed" }
        assertRejected(apk, directory, fixture.diagnostic, fixture.already)
    }
    val premiumResult = begin(listOf(premium.name!!), selections)
    Patcher(config(input, work.resolve("premium-temporary"))).use { checkPremium ->
        checkPremium += setOf(premium)
        val results = checkPremium().toList()
        premiumResult["patch_results"] = results.map { patchResult(it.patch.name, it.exception) }
        check(results.size == 1 && results.single().patch.name == premium.name)
        results.forEach { it.exception?.let { failure -> throw failure } }
        val files = emitDex(checkPremium, output.resolve("premium-dex"))
        val compared = readEmitted(files)
        check(compared.keys == originals.keys)
        val changed = compared.filter { (key, method) -> method.snapshot() != originalSnapshots[key] }.keys
        check(changed == setOf(MAPPER_KEY, EXPIRY_KEY)) { "Unexpected Premium regression: $changed" }
        verifyPremium(compared)
        recordSelection(premiumResult, changed, compared.size, output.resolve("premium-dex"))
        report("PASS: Premium-only changes mapper/expiry only within bounded compared classes; storage Pro/auth and Automation unchanged")
        val directory = output.resolve("premium-repeat").also { check(it.mkdir()) }
        val repeatedPremium = directory.resolve("fixture-NOT-INSTALLABLE.apk")
        writeFixture(input, files, repeatedPremium)
        assertRejected(repeatedPremium, directory, "mapper", true, setOf(premium))
    }
    val combinedResult = begin(listOf(patch.name!!, premium.name!!), selections)
    Patcher(config(input, work.resolve("combined-temporary"))).use { combined ->
        combined += setOf(patch, premium)
        val results = combined().toList()
        combinedResult["patch_results"] = results.map { patchResult(it.patch.name, it.exception) }
        check(results.size == 2 && results.map { it.patch.name }.toSet() == setOf(patch.name, premium.name))
        results.forEach { it.exception?.let { failure -> throw failure } }
        val compared = readEmitted(emitDex(combined, output.resolve("combined-dex")))
        check(compared.keys == originals.keys)
        val changed = compared.filter { (key, method) -> method.snapshot() != originalSnapshots[key] }.keys
        check(changed == offlineKeys + setOf(MAPPER_KEY, EXPIRY_KEY)) { "Unexpected combined-selection changes: $changed" }
        verifyOffline(compared)
        verifyPremium(compared)
        recordSelection(combinedResult, changed, compared.size, output.resolve("combined-dex"))
        report("PASS: combined selection emits/rereads exactly the union of approved edits within bounded compared classes")
    }
    check(sha256(bundle) == bundleHash && sha256(input) == inputHash && sha256(catalog) == catalogHash) {
        "Inputs changed during structural checks"
    }
    emittedOutputs.keys.forEach { verifyEmitted(it) }
    negativeFixtures.forEach { (fixture, hash) -> check(sha256(fixture) == hash) { "Fixture mutated: $fixture" } }
    report("PASS: all required offline/preservation/negative/selection checks completed; no device accessed")
    val result = mapOf(
        "status" to "bounded_structural_checks_passed",
        "work_directory" to work.absolutePath,
        "bundle_sha256" to bundleHash, "catalog_sha256" to catalogHash, "input_base_sha256" to inputHash,
        "patcher_version" to "2.3.0", "patches" to definitions, "dependencies" to projectDependencies(loaded),
        "definition_scope" to "exact_four_collection_definitions",
        "application_scope" to "Termius_only_singletons_and_combined",
        "plex_application" to "not_supported_not_attempted",
        "spotify_application" to "not_supported_not_attempted",
        "selections" to selections, "negative_cases" to listOf("repeat", "premium-repeat") + fixtures.map { it.name },
        "negative_results" to negativeResults,
        "comparison_scope" to mapOf("kind" to "selected_classes_only_not_whole_app", "methods" to originals.size,
            "explicit_owners" to comparedOwners.sorted(), "nested_owner_prefixes" to listOf(LOCAL_EDITOR.dropLast(1) + "$", PRESENTER.dropLast(1) + "$"),
            "method_data" to "flags/registers/tries/instructions/operands/normalized-control-flow; excludes debug metadata, class metadata and fields"),
        "checks" to checks,
        "android_bundle_load" to "not_observed", "manager_import" to "not_observed", "device_behavior" to "not_observed",
        "output_kind" to "unsigned_incomplete_noninstallable_structural_fixtures",
    )
    Files.writeString(output.resolve("structural-check.json").toPath(), metadataGson.toJson(result), StandardOpenOption.CREATE_NEW)
    } catch (failure: Throwable) {
        val failed = mapOf("status" to "failed", "error" to "${failure.javaClass.name}: ${failure.message}",
            "work_directory" to work.absolutePath, "selections" to selections, "negative_results" to negativeResults)
        try {
            Files.writeString(output.resolve("structural-check-failed.json").toPath(), metadataGson.toJson(failed), StandardOpenOption.CREATE_NEW)
        } catch (reportFailure: Throwable) { failure.addSuppressed(reportFailure) }
        throw failure
    }
    Unit
}
