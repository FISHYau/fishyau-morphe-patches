@file:Suppress("DEPRECATION")

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.ClassDef
import com.android.tools.smali.dexlib2.iface.Method
import com.android.tools.smali.dexlib2.iface.instruction.Instruction
import com.android.tools.smali.dexlib2.immutable.ImmutableClassDef
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.instruction.*
import com.android.tools.smali.dexlib2.immutable.reference.*
import java.lang.reflect.InvocationTargetException

// Tools-only synthetic dexlib/path regression entrypoint. No patch loader, APK/MPP,
// device, compiler defaults or production patch definitions are exercised.
private const val OWNER = "Lcm/c;"
private fun method(instructions: List<Instruction>, owner: String = OWNER, name: String = "c") = ImmutableMethod(
    owner, name, emptyList(), "Ljava/lang/Object;", 1, emptySet(), emptySet(),
    ImmutableMethodImplementation(5, instructions, emptyList(), emptyList()))
private fun clazz(owner: String = OWNER, methods: List<Method> = emptyList()): ClassDef {
    val base = ImmutableClassDef(owner, 1, "Ljava/lang/Object;", emptyList(), null, emptySet(), emptyList(), methods)
    // Do not let immutable sorted-set construction deduplicate malformed methods
    // before the collector sees them.
    return object : ClassDef by base { override fun getMethods(): Iterable<Method> = methods }
}
private fun emittedDuplicate() {
    val directory = java.nio.file.Files.createTempDirectory("synthetic-duplicate-dex-").toFile()
    val files = listOf("classes.dex", "classes2.dex").mapIndexed { index, name ->
        directory.resolve(name).also { file ->
            val body = listOf(ImmutableInstruction11x(Opcode.RETURN_OBJECT, index))
            val dex = com.android.tools.smali.dexlib2.immutable.ImmutableDexFile(
                com.android.tools.smali.dexlib2.Opcodes.forDexVersion(35), listOf(clazz(methods=listOf(method(body)))))
            com.android.tools.smali.dexlib2.writer.pool.DexPool.writeTo(file.absolutePath, dex)
        }
    }
    rejected { invoke("readEmitted", files) }
}
private fun invoke(name: String, vararg args: Any): Any? {
    val target = Class.forName("RuntimeCheckKt").declaredMethods.single { it.name == name }
    target.isAccessible = true
    try { return target.invoke(null, *args) }
    catch (failure: InvocationTargetException) { throw failure.targetException }
}
@Suppress("UNCHECKED_CAST")
private fun snapshot(method: Method, prefix: Int = 0): List<String> {
    // Before the repair the one-argument function exposes the drop-only defect.
    val target = Class.forName("RuntimeCheckKt").declaredMethods.single { it.name == "snapshot" }
    target.isAccessible = true
    return if (target.parameterCount == 1) {
        val rows = target.invoke(null, method) as List<String>
        rows.take(1) + rows.drop(1 + prefix)
    } else invoke("snapshot", method, prefix) as List<String>
}
private fun collect(vararg classes: ClassDef) = invoke("collectCompared", classes.asSequence())
private fun rejected(block: () -> Unit) {
    try { block() } catch (_: IllegalStateException) { return }
    error("Expected duplicate/invalid-target rejection")
}
private fun structuralDirectories(mode: String) {
    val parent = java.nio.file.Files.createTempDirectory("synthetic-structural-paths-").toFile().canonicalFile
    val source = parent.resolve("source").also { check(it.mkdir()) }
    val input = parent.resolve("input").also { it.writeText("SYNTHETIC; NEVER EXECUTED") }
    val output = parent.resolve("semantic")
    val work = parent.resolve("semantic-work")
    fun reserve(path: java.io.File = output) = invoke("reserveStructuralDirectories", path, source, listOf(input))
    when (mode) {
        "fresh" -> {
            check(reserve() == (output to work))
            check(output.isDirectory && work.isDirectory && output.listFiles()!!.isEmpty() && work.listFiles()!!.isEmpty())
            rejected { reserve() }
        }
        "existing-work" -> {
            work.writeText("RETAIN EXISTING BYTES")
            rejected { reserve() }
            check(!output.exists() && work.readText() == "RETAIN EXISTING BYTES")
        }
        "existing-output" -> {
            check(output.mkdir())
            rejected { reserve() }
            check(!work.exists())
        }
        "source" -> { rejected { reserve(source.resolve("new")) }; check(!source.resolve("new").exists()) }
        "input" -> { rejected { reserve(input) }; check(input.readText() == "SYNTHETIC; NEVER EXECUTED") }
        "missing-parent" -> { rejected { reserve(parent.resolve("missing/new")) }; check(!parent.resolve("missing").exists()) }
        "dot-escape" -> { rejected { reserve(parent.resolve("unused/../escape")) }; check(!parent.resolve("escape").exists()) }
        else -> error("Unknown case")
    }
}
private val prefix = listOf(
    ImmutableInstruction21c(Opcode.CONST_STRING, 4, ImmutableStringReference("Premium")),
    ImmutableInstruction11n(Opcode.CONST_4, 1, 0), ImmutableInstruction11n(Opcode.CONST_4, 2, 0),
    ImmutableInstruction21c(Opcode.NEW_INSTANCE, 0, ImmutableTypeReference("Lcom/server/auditor/ssh/client/models/UserType\$Pro;")),
    ImmutableInstruction35c(Opcode.INVOKE_DIRECT, 4, 0, 4, 1, 2, 0, ImmutableMethodReference(
        "Lcom/server/auditor/ssh/client/models/UserType\$Pro;", "<init>", listOf("Ljava/lang/String;", "Z",
            "Lcom/server/auditor/ssh/client/models/SubscriptionPeriod;"), "V")),
    ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0))
private fun preserved(body: List<Instruction>) {
    check(snapshot(method(body)) == snapshot(method(prefix + body), 6)) { "Preserved suffix must rebase control flow" }
}

fun main() {
    val branch = listOf(ImmutableInstruction21t(Opcode.IF_EQZ, 0, 3),
        ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0), ImmutableInstruction11x(Opcode.RETURN_OBJECT, 1))
    val firstReference = ImmutableMethodReference("Ljava/lang/invoke/MethodHandle;", "invokeExact", emptyList(), "Ljava/lang/Object;")
    fun dual(returnType: String) = method(listOf(ImmutableInstruction45cc(Opcode.INVOKE_POLYMORPHIC,
        1, 0, 0, 0, 0, 0, firstReference, ImmutableMethodProtoReference(emptyList(), returnType)),
        ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0)))
    val cases = linkedMapOf<String, () -> Unit>(
        "fresh_disjoint_output_and_retained_work" to { structuralDirectories("fresh") },
        "preexisting_work_is_preserved_without_consuming_output" to { structuralDirectories("existing-work") },
        "preexisting_output_does_not_create_work" to { structuralDirectories("existing-output") },
        "output_cannot_enter_source" to { structuralDirectories("source") },
        "output_cannot_replace_input" to { structuralDirectories("input") },
        "output_requires_existing_parent" to { structuralDirectories("missing-parent") },
        "output_cannot_use_dot_escape" to { structuralDirectories("dot-escape") },
        "unchanged_branching_mapper_suffix" to { preserved(branch) },
        "unchanged_packed_switch_suffix" to { preserved(listOf(ImmutableInstruction31t(Opcode.PACKED_SWITCH, 0, 4),
            ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0), ImmutablePackedSwitchPayload(listOf(ImmutableSwitchElement(0, 3))))) },
        "unchanged_sparse_switch_suffix" to { preserved(listOf(ImmutableInstruction31t(Opcode.SPARSE_SWITCH, 0, 4),
            ImmutableInstruction11x(Opcode.RETURN_OBJECT, 0), ImmutableSparseSwitchPayload(listOf(ImmutableSwitchElement(10, 3))))) },
        "changed_branch_target_detected" to {
            check(snapshot(method(branch)) != snapshot(method(prefix + listOf(ImmutableInstruction21t(Opcode.IF_EQZ, 0, 2)) + branch.drop(1)), 6))
        },
        "suffix_cannot_branch_into_prefix" to { rejected {
            snapshot(method(prefix + listOf(ImmutableInstruction21t(Opcode.IF_EQZ, 0, -1)) + branch.drop(1)), 6)
        } },
        "second_prototype_reference_detected" to { check(snapshot(dual("Ljava/lang/String;")) != snapshot(dual("Ljava/lang/Object;"))) },
        "unchanged_second_reference_preserved" to { check(snapshot(dual("Ljava/lang/String;")) == snapshot(dual("Ljava/lang/String;"))) },
        "actual_raw_dex_reader_rejects_cross_dex_duplicate" to { emittedDuplicate() },
        "duplicate_empty_compared_classes_rejected" to { rejected { collect(clazz(), clazz()) } },
        "duplicate_nonempty_compared_classes_rejected" to { rejected { collect(clazz(methods=listOf(method(branch))), clazz(methods=listOf(method(branch)))) } },
        "duplicate_methods_with_different_bodies_rejected" to { rejected { collect(clazz(methods=listOf(method(branch), method(branch.reversed())))) } },
        "distinct_compared_classes_preserved" to { check((collect(clazz(methods=listOf(method(branch))),
            clazz("Lci/w;", listOf(method(branch, "Lci/w;")))) as Map<*, *>).size == 2) },
        "uncompared_duplicate_classes_remain_outside_scope" to { check((collect(clazz("Loutside;"), clazz("Loutside;")) as Map<*, *>).isEmpty()) }
    )
    var failures = 0
    for ((name, test) in cases) {
        try { test(); println("PASS $name") }
        catch (failure: Throwable) { failures++; println("FAIL $name: ${failure.javaClass.name}: ${failure.message}") }
    }
    println("Synthetic in-memory snapshot/collection cases: ${cases.size}; failures: $failures")
    check(failures == 0)
}
