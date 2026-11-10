package io.github.fishyau.androidpatches.spotify

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction20t
import com.android.tools.smali.dexlib2.builder.instruction.BuilderInstruction21s

// Exact original semantic/physical pins from the reviewed preview-only candidate.
// Structural guards are not identity/signature verification or Android runtime proof.
internal object PreviewPins {
    const val EXPANDED = "Lmud;->c(Landroid/net/Uri;Ltr8;Lsx5;I)V"
    const val COLLAPSED = "Ldg;->invoke()Ljava/lang/Object;"
    const val CALLER = "Ldg;-><init>(Ltx8;Ljd0;Lfr9;)V"
    const val MODEL = "Lct0;-><init>(Landroid/net/Uri;Lkt0;I)V"
    const val DISPATCH = "Lmud;->a(Ljt0;Ltr8;Lsx5;I)V"
    const val ARTWORK = "Lewd;->B(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;"
    const val ALPHA = "Ltt2;->invoke(Ljava/lang/Object;)Ljava/lang/Object;"
    val semantic: Map<String, String> = java.util.Collections.unmodifiableMap(mapOf(
        EXPANDED to "50d445dc6a664c4962c12448da9acf653fc1fff0448a15c78f001b9a8001b1f5",
        COLLAPSED to "71c28ce49b0b9be410fcbb8a529c06f431d2248045ff77f6a9a172089fdd4099",
        CALLER to "8dcabbe26a661b46006cec52eac175a557dfba860437c69fc0d4037026500d92",
        MODEL to "951b23b9e59e625b00b70624a64094416ed01ba30c95850abb3e55f1b4789ae6",
        DISPATCH to "6b32788f16956218545dd03a090db88f5f2b8fedb45ff1a9928fcb31ccfb3c31",
        ARTWORK to "c37639af396949e2a713a366f6fd7d55ef308fdf913e207c28153fb01fde319b",
        ALPHA to "573a615ee9766a0150b8a33f485adae6c7d75ee7f7488bcc0492fc8691ade282"))
    val physical: Map<String, String> = java.util.Collections.unmodifiableMap(mapOf(
        EXPANDED to "993c6728f0151b98c5501910242e3d5c92743f1e8a83ea8938e63fff0af532b5",
        COLLAPSED to "d59b86d8eb2ae4d3efbd958c216485296acb79ec75e15a41c89305845e2c14f5",
        CALLER to "302d71f5ab1a03938c4279b8fcc05fb5e12a71d0b0ec9d9c6aaa88fc4d0e4e7d",
        MODEL to "c06b9a39dc0b65ec7a82a9ec71392ade019ea3745b3fe421939971a563f2d575",
        DISPATCH to "7fc150411ebf20f03bf3c573d7c6de6f5ad6f64524b83ac47e6b739a6fb3c3ff",
        ARTWORK to "3960ac4426f88c006289799a81e1ae9dbf8f8389357979f2c1415ec7c0654696",
        ALPHA to "e394c1e4229e9734893032512d10226580eacff8a4ad0794597fdab4032b3afb"))
}

internal enum class PreviewRole { EXPANDED, COLLAPSED }
internal data class PreviewEdit(val index: Int, val rowIndex: Int, val original: String, val replacement: String, val target: Int?)

internal object PreviewEdits {
    private val instruction = Regex("^[A-Z_0-9]+ \\[.*")
    fun only(methods: List<MutableMethod>, key: String): MutableMethod {
        check(methods.size == 1) { "selector absent or ambiguous" }
        return methods.single().also { check(CandidateSnapshots.key(it) == key) }
    }
    fun original(method: MutableMethod, expected: String) {
        check(CandidateSnapshots.hash(CandidateSnapshots.original(method)) == expected) { "original snapshot drift or already patched" }
    }
    fun planRows(rows: List<String>, role: PreviewRole): List<PreviewEdit> {
        val rowIndices = rows.indices.filter { instruction.matches(rows[it]) }
        val ins = rowIndices.map { rows[it] }
        fun find(predicate: (String) -> Boolean) = ins.indices.filter { predicate(ins[it]) }.single()
        fun target(i: Int): Int = ins[i].substringAfterLast(" target=").toInt().also { check(it in ins.indices) }
        fun edit(i: Int, next: String, dest: Int? = null) = PreviewEdit(i, rowIndices[i], ins[i], next, dest)
        fun jump(i: Int): PreviewEdit {
            val t = target(i)
            return edit(i, "GOTO [] ref=null ref2=null literal=null target=$t", t)
        }
        return when (role) {
            PreviewRole.EXPANDED -> {
                val state = find { it == "INSTANCE_OF [8, 8] ref=Lhde; ref2=null literal=null target=null" }
                val alpha = state + 1
                check(ins[alpha].startsWith("IF_EQZ [8] ref=null ref2=null literal=null target="))
                val opaque = target(alpha)
                check(opaque == alpha + 3)
                check(ins[alpha + 1] == "CONST_4 [8] ref=null ref2=null literal=0 target=null")
                check(ins[opaque] == "CONST_HIGH16 [8] ref=null ref2=null literal=1065353216 target=null")
                check(ins[opaque + 1] == "CONST_16 [13] ref=null ref2=null literal=1000 target=null")
                check(target(alpha + 2) == opaque + 1)
                val preview = ins.indices.filter { n ->
                    ins[n].startsWith("IF_EQZ [0] ref=null ref2=null literal=null target=") &&
                        n + 1 < ins.size && ins[n + 1].startsWith("IF_NEZ [20] ref=null ref2=null literal=null target=")
                }.single()
                check(ins[preview - 1] == "CHECK_CAST [0] ref=Ljava/lang/String; ref2=null literal=null target=null")
                val alternate = target(preview)
                check(target(preview + 1) == alternate && alternate > preview + 1)
                val setup = listOf("MOVE_OBJECT [0, 4]", "MOVE [3, 5]", "MOVE_FROM16 [17, 12]", "MOVE_WIDE [1, 13]", "MOVE_OBJECT [14, 7]")
                setup.forEachIndexed { j, prefix -> check(ins[alternate + j] == "$prefix ref=null ref2=null literal=null target=null") }
                check(ins.subList(preview + 2, alternate).count { "ref=Lqh6;->q(" in it } == 1)
                // Existing alternate keeps Z/q group balance and reaches the common artwork tail.
                check(ins[alternate + 6] == "INVOKE_VIRTUAL [14, 4] ref=Lsx5;->Z(I)V ref2=null literal=null target=null")
                check(ins[alternate + 7] == "INVOKE_VIRTUAL [14, 3] ref=Lsx5;->q(Z)V ref2=null literal=null target=null")
                check(ins[alternate + 8] == "INVOKE_STATIC [14] ref=Lz24;->c(Lsx5;)Lab4; ref2=null literal=null target=null")
                listOf(jump(alpha), jump(preview))
            }
            PreviewRole.COLLAPSED -> {
                val call = find { it == "INVOKE_DIRECT [2, 1, 3, 7] ref=Lct0;-><init>(Landroid/net/Uri;Lkt0;I)V ref2=null literal=null target=null" }
                check(ins[call - 1] == "CONST_16 [7] ref=null ref2=null literal=28 target=null")
                check(ins[call - 2] == "SGET_OBJECT [3] ref=Lkt0;->u:Lkt0; ref2=null literal=null target=null")
                check(ins[call - 5] == "NEW_INSTANCE [2] ref=Lct0; ref2=null literal=null target=null")
                check(ins[call - 3] == "IGET_OBJECT [1, 1] ref=La66;->a:Landroid/net/Uri; ref2=null literal=null target=null")
                val switch = find { it.startsWith("PACKED_SWITCH_PAYLOAD [] ") }
                val home = ins[switch].substringAfter(" switch=").split(", ").single { it.startsWith("6:") }.substringAfter(':').toInt()
                check(home in 0 until call && ins[home] == "CHECK_CAST [7] ref=Ltx8; ref2=null literal=null target=null")
                listOf(edit(call - 1, "CONST_16 [7] ref=null ref2=null literal=60 target=null"))
            }
        }
    }
    fun changed(rows: List<String>, edits: List<PreviewEdit>): List<String> = rows.toMutableList().also { out ->
        check(edits.isNotEmpty() && edits.map { it.rowIndex }.toSet().size == edits.size)
        edits.forEach { check(out[it.rowIndex] == it.original); out[it.rowIndex] = it.replacement }
    }
    fun plan(method: MutableMethod, expected: String, role: PreviewRole): List<PreviewEdit> {
        original(method, expected)
        return planRows(CandidateSnapshots.method(method), role)
    }
    fun apply(method: MutableMethod, edits: List<PreviewEdit>) {
        val body = checkNotNull(method.implementation)
        val before = CandidateSnapshots.method(method)
        val expected = changed(before, edits)
        val widths = body.instructions.map { it.codeUnits }
        // Resolve targets by original instruction indices, not hardcoded code-unit offsets.
        val replacements = edits.map { edit ->
            check(widths[edit.index] == 2)
            if (edit.target != null) {
                check(edit.target in body.instructions.indices)
                BuilderInstruction20t(Opcode.GOTO_16, body.newLabelForIndex(edit.target))
            } else {
                check(edit.replacement == "CONST_16 [7] ref=null ref2=null literal=60 target=null")
                BuilderInstruction21s(Opcode.CONST_16, 7, 60)
            }
        }
        edits.zip(replacements).forEach { (edit, replacement) -> body.replaceInstruction(edit.index, replacement) }
        check(body.instructions.map { it.codeUnits } == widths)
        check(CandidateSnapshots.method(method) == expected) { "unintended delta or invalid destination" }
    }
}

// Defensive immutable copies. Synthetic tests create separate specs, never override production pins.
internal class PreviewSpec(semantic: Map<String, String>, physical: Map<String, String>, roles: Map<String, PreviewRole>) {
    val semantic: Map<String, String> = java.util.Collections.unmodifiableMap(LinkedHashMap(semantic))
    val physical: Map<String, String> = java.util.Collections.unmodifiableMap(LinkedHashMap(physical))
    val roles: Map<String, PreviewRole> = java.util.Collections.unmodifiableMap(LinkedHashMap(roles))
    init {
        check(this.semantic.keys == this.physical.keys && this.roles.isNotEmpty())
        check(this.physical.keys.containsAll(this.roles.keys))
        check((this.semantic.values + this.physical.values).all { it.matches(Regex("[0-9a-f]{64}")) })
    }
}

internal object PreviewExecution {
    // Fixed production entry point: no caller-supplied spec, option, setter or runtime pin override.
    fun executeProduction() = execute(productionSpec, ::select)
    data class Descriptor(val owner: String, val name: String, val parameters: List<String>, val result: String)
    fun descriptor(key: String): Descriptor {
        val objectType = "L[A-Za-z0-9_$/]+;"
        val valueType = "(?:\\[*$objectType|\\[*[ZBSCIJFD])"
        val head = Regex("^($objectType)->([A-Za-z0-9_$]+|<init>|<clinit>)\\((.*)\\)(.+)$").matchEntire(key)
            ?: error("invalid descriptor")
        val params = head.groupValues[3]
        val types = Regex(valueType).findAll(params).map { it.value }.toList()
        check(types.joinToString("") == params) { "invalid parameter descriptor" }
        val result = head.groupValues[4]
        check(result == "V" || Regex(valueType).matches(result)) { "invalid result descriptor" }
        check(head.groupValues[2] != "<init>" || result == "V")
        check(head.groupValues[2] != "<clinit>" || (result == "V" && types.isEmpty()))
        return Descriptor(head.groupValues[1], head.groupValues[2], types, result)
    }
    private fun select(key: String): MutableMethod {
        val d = descriptor(key)
        val matches = Fingerprint(definingClass = d.owner, name = d.name, parameters = d.parameters,
            returnType = d.result).matchAllOrNull().orEmpty().map { it.method }
        return PreviewEdits.only(matches, key)
    }
    // Package-internal engine seam for independently authored synthetic mutable-method tests.
    internal fun execute(spec: PreviewSpec, resolve: (String) -> MutableMethod) {
        val methods = spec.physical.keys.associateWith { key -> PreviewEdits.only(listOf(resolve(key)), key) }
        // ALL original semantic AND physical checks precede any plan/mutation.
        methods.forEach { (key, method) ->
            check(CandidateSnapshots.hash(CandidateSnapshots.method(method)) == spec.semantic.getValue(key)) { "semantic pin drift" }
            PreviewEdits.original(method, spec.physical.getValue(key))
        }
        val plans = spec.roles.map { (key, role) ->
            val method = methods.getValue(key)
            val edits = PreviewEdits.plan(method, spec.physical.getValue(key), role)
            // Physical feasibility is checked across ALL methods before the first write.
            val instructions = checkNotNull(method.implementation).instructions
            edits.forEach { edit ->
                check(edit.index in instructions.indices && instructions[edit.index].codeUnits == 2)
                if (edit.target != null) check(edit.target in instructions.indices)
                else check(edit.replacement == "CONST_16 [7] ref=null ref2=null literal=60 target=null")
            }
            method to edits
        }
        plans.forEach { (method, edits) -> PreviewEdits.apply(method, edits) }
    }
}

private val productionSpec = PreviewSpec(PreviewPins.semantic, PreviewPins.physical, mapOf(
    PreviewPins.EXPANDED to PreviewRole.EXPANDED, PreviewPins.COLLAPSED to PreviewRole.COLLAPSED))

/** Exactly three Home-preview edits. Account authentication/session handling must remain functional:
 * sign-in, token refresh, sign-out and reauthentication are not modified or bypassed.
 * Does not grant backend entitlements or alter global playback, mute, queue or AutoNavigate behavior.
 */
@Suppress("unused")
val disableHomePreviewsPatch = bytecodePatch(
    name = "Disable Home previews",
    description = "Disables Home previews on Spotify TV 9.1.94.1926. Leaves account authentication and session handling unchanged; does not grant backend entitlements.",
    default = true,
) {
    compatibleWith(SPOTIFY_TV_COMPATIBILITY)
    execute { PreviewExecution.executeProduction() }
}
