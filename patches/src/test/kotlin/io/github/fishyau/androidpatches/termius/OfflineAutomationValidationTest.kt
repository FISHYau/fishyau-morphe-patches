package io.github.fishyau.androidpatches.termius

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.Parameterized

/** Synthetic operand fixtures; integration separately validates the real original DEX. */
@RunWith(Parameterized::class)
class OfflineAutomationValidationTest(private val target: String) {
    companion object {
        @JvmStatic @Parameterized.Parameters(name = "{0}")
        fun targets() = listOf("snippet widget", "SSH Automation", "terminal Automation").map { arrayOf(it) }
    }
    private val original get() = OfflineAutomationValidation.expected(target)
    private val registers get() = if (target == "terminal Automation") 12 else 3
    private val flags get() = when (target) { "SSH Automation" -> 0x12; "terminal Automation" -> 0x0a; else -> 1 }
    private val editIndex get() = when (target) { "snippet widget" -> 4; "SSH Automation" -> 12; else -> 31 }
    private fun validate(body: List<ProModeInstruction> = original, regs: Int = registers, access: Int = flags, tries: Int = 0) =
        OfflineAutomationValidation.requireLayout(target, regs, access, tries, body)
    private fun reject(body: List<ProModeInstruction>) = assertThrows(IllegalStateException::class.java) { validate(body) }
    private fun mutate(index: Int, change: (ProModeInstruction) -> ProModeInstruction) =
        original.toMutableList().also { it[index] = change(it[index]) }

    @Test fun originalLayoutIsAccepted() { validate() }
    @Test fun missingAndAmbiguousTargetsAreRejected() {
        for (count in listOf(0, 2, 3)) assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireUniqueTarget(target, count)
        }
    }
    @Test fun changedRegisterCountsAreRejected() {
        for (count in listOf(0, registers - 1, registers + 1, 16)) {
            assertThrows(IllegalStateException::class.java) { validate(regs = count) }
        }
    }
    @Test fun changedAccessFlagsAreRejected() {
        for (access in listOf(flags xor 8, flags or 0x100, flags or 0x400, flags xor 0x10, 0)) {
            assertThrows(IllegalStateException::class.java) { validate(access = access) }
        }
    }
    @Test fun exceptionRegionsAreRejected() {
        assertThrows(IllegalStateException::class.java) { validate(tries = 1) }
    }
    @Test fun everyOpcodeIsChecked() {
        for (index in original.indices) reject(mutate(index) { it.copy(opcode = "NOP") })
    }
    @Test fun everyRegisterOperandIsChecked() {
        for ((index, row) in original.withIndex()) for (operand in row.registers.indices) {
            reject(mutate(index) {
                it.copy(registers = it.registers.toMutableList().also { regs -> regs[operand] = (regs[operand] + 1) % registers })
            })
        }
    }
    @Test fun everyReferenceIsChecked() {
        for ((index, row) in original.withIndex()) if (row.reference != null) {
            reject(mutate(index) { it.copy(reference = "Lunexpected/Target;->wrong()V") })
        }
    }
    @Test fun everyLiteralIsChecked() {
        for ((index, row) in original.withIndex()) if (row.literal != null) {
            reject(mutate(index) { it.copy(literal = row.literal + 1) })
        }
        reject(mutate(editIndex) { it.copy(literal = 1) })
    }
    @Test fun everyBranchTargetAndPolarityIsChecked() {
        for ((index, row) in original.withIndex()) if (row.branchTarget != null) {
            reject(mutate(index) { it.copy(branchTarget = row.branchTarget + 1) })
            reject(mutate(index) { it.copy(opcode = if (it.opcode == "IF_EQZ") "IF_NEZ" else "IF_EQZ") })
        }
    }
    @Test fun missingAndExtraInstructionsAreRejected() {
        for (index in original.indices) reject(original.filterIndexed { n, _ -> n != index })
        reject(original + ProModeInstruction("NOP", emptyList()))
    }
    @Test fun independentlyPatchedTargetIsRejected() {
        val failure = reject(mutate(editIndex) {
            if (target == "snippet widget") it.copy(reference = "$SNIPPET_WIDGET->N()V")
            else ProModeInstruction("CONST_4", it.registers, literal = 1)
        })
        assertTrue(failure.message.orEmpty().contains("already patched"))
    }
    @Test fun editSitesAndPermissionOrConnectionSemanticsAreExplicit() {
        when (target) {
            "snippet widget" -> {
                assertEquals("$SNIPPET_WIDGET->F()V", original[editIndex].reference)
                assertEquals("$SNIPPET_WIDGET->J()V", original[8].reference)
                assertEquals("Lbs/h\$b;", original[6].reference)
                assertEquals("$SNIPPET_WIDGET->N()V", original[12].reference)
            }
            else -> {
                assertEquals("MOVE_RESULT", original[editIndex].opcode)
                assertEquals("Lcom/server/auditor/ssh/client/app/a;->u0()Z", original[editIndex - 1].reference)
                assertEquals("IF_NEZ", original[editIndex + 1].opcode)
                assertEquals(original[editIndex].registers, original[editIndex + 1].registers)
                if (target == "terminal Automation") {
                    assertEquals(listOf(11), original[27].registers) // original z branch
                    assertEquals(listOf(9, 11), original[58].registers) // z copied into range call
                    assertEquals(listOf(4, 5, 6, 7, 8, 9), original[59].registers)
                }
            }
        }
    }
}
