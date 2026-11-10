package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.iface.instruction.*
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference
import com.android.tools.smali.dexlib2.iface.reference.StringReference
import com.android.tools.smali.dexlib2.iface.reference.TypeReference

// Mnemonic normalization shared with the DEX-independent preflight tests.
internal fun Instruction.opcodeKey() = opcode.name.uppercase().replace('-', '_').replace('/', '_')

/** Complete operands for these fixed-width, payload-free target methods. */
internal fun MutableMethod.captureInstructions(): List<ProModeInstruction> {
    var offset = 0
    return checkNotNull(implementation).instructions.map { instruction ->
        val registers = when (instruction) {
            is RegisterRangeInstruction ->
                (instruction.startRegister until instruction.startRegister + instruction.registerCount).toList()
            is FiveRegisterInstruction -> listOf(
                instruction.registerC, instruction.registerD, instruction.registerE,
                instruction.registerF, instruction.registerG,
            ).take(instruction.registerCount)
            is ThreeRegisterInstruction -> listOf(instruction.registerA, instruction.registerB, instruction.registerC)
            is TwoRegisterInstruction -> listOf(instruction.registerA, instruction.registerB)
            is OneRegisterInstruction -> listOf(instruction.registerA)
            else -> emptyList()
        }
        val reference = when (val ref = (instruction as? ReferenceInstruction)?.reference) {
            null -> null
            is FieldReference -> "${ref.definingClass}->${ref.name}:${ref.type}"
            is MethodReference -> "${ref.definingClass}->${ref.name}(${ref.parameterTypes.joinToString("")})${ref.returnType}"
            is TypeReference -> ref.type
            is StringReference -> ref.string
            else -> error("Unexpected reference in Termius preflight.")
        }
        ProModeInstruction(
            instruction.opcodeKey(), registers, reference,
            (instruction as? WideLiteralInstruction)?.wideLiteral,
            (instruction as? OffsetInstruction)?.let { offset + it.codeOffset },
        ).also { offset += instruction.codeUnits }
    }
}
