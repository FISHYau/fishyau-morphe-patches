package io.github.fishyau.androidpatches.spotify

import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.*
import com.android.tools.smali.dexlib2.iface.Annotation
import com.android.tools.smali.dexlib2.iface.debug.*
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.iface.instruction.formats.ArrayPayload
import com.android.tools.smali.dexlib2.formatter.DexFormatter
import java.security.MessageDigest

// Same complete snapshot contract as GenericPatchRunner; never loads application code.
internal object CandidateSnapshots {
    private val formatter = DexFormatter.INSTANCE
    fun key(m: Method): String = formatter.getMethodDescriptor(m)
    private fun annotations(items: Set<Annotation>) = items.map { a ->
        "${a.visibility}:${a.type}:" + a.elements.sortedBy { it.name }.joinToString { "${it.name}=${formatter.getEncodedValue(it.value)}" }
    }.sorted()
    fun method(m: Method): List<String> = with(m) {
        val result = mutableListOf("flags=$accessFlags hidden=${hiddenApiRestrictions.sortedBy { it.name }} annotations=${annotations(annotations)}",
            "parameters=" + parameters.joinToString { "${it.type}:${it.name}:${it.signature}:${annotations(it.annotations)}" })
        val body = implementation ?: return@with result + "NO CODE"
        val instructions = body.instructions.toList()
        val offsets = mutableMapOf<Int, Int>(); var offset = 0
        instructions.forEachIndexed { index, instruction -> offsets[offset] = index; offset += instruction.codeUnits }
        offsets[offset] = instructions.size
        fun label(address: Int) = checkNotNull(offsets[address]) { "non-instruction address" }
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
            check(i !is FieldOffsetInstruction && i !is InlineIndexInstruction && i !is VtableIndexInstruction && i !is VerificationErrorInstruction)
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
        result
    }
    // Length-prefixed UTF-8 rows avoid ambiguity even with unusual string literals.
    fun hash(rows: List<String>): String {
        val md = MessageDigest.getInstance("SHA-256")
        rows.forEach { row ->
            val bytes = row.toByteArray(Charsets.UTF_8)
            md.update(java.nio.ByteBuffer.allocate(4).putInt(bytes.size).array()); md.update(bytes)
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
    // Bind exact physical opcode/width as well as normalized semantic rows.
    fun original(m: Method): List<String> = method(m) + checkNotNull(m.implementation).instructions.map { "encoding=${it.opcode}:${it.codeUnits}" }
}
