package io.github.fishyau.androidpatches.termius

import org.junit.Assert.assertThrows
import org.junit.Test

class PremiumPatchValidationTest {
    private val constructorOpcodes = listOf("CONST_4", "INVOKE_DIRECT", "IPUT_OBJECT", "IPUT_BOOLEAN", "IPUT_OBJECT", "RETURN_VOID")
    private val fields = listOf("title:Ljava/lang/String;", "isExpired:Z", "subscriptionPeriod:Lcom/server/auditor/ssh/client/models/SubscriptionPeriod;")
    private val baseConstructor = "Lcom/server/auditor/ssh/client/models/UserType;-><init>(Lkotlin/jvm/internal/k;)V"

    @Test fun original801LayoutIsAccepted() {
        PremiumPatchValidation.requireUniqueTarget("mapper", 1)
        PremiumPatchValidation.requireMapperLayout(5, false, "IGET_OBJECT", 0)
        PremiumPatchValidation.requireConstructorLayout(constructorOpcodes, fields, baseConstructor)
        PremiumPatchValidation.requireExpiryLayout(listOf("IGET_BOOLEAN", "RETURN"), "isExpired:Z", 2)
    }

    @Test fun highestEncodableParameterRegisterIsAccepted() {
        PremiumPatchValidation.requireMapperLayout(16, false, "IGET_OBJECT", 0)
    }

    @Test fun insufficientLocalsAreRejected() {
        for (registers in 0..4) assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireMapperLayout(registers, false, "IGET_OBJECT", 0)
        }
    }

    @Test fun unencodableParameterRegisterIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireMapperLayout(17, false, "IGET_OBJECT", 0)
        }
    }

    @Test fun staticMapperIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireMapperLayout(5, true, "IGET_OBJECT", 0)
        }
    }

    @Test fun missingAndAmbiguousTargetsAreRejected() {
        for (count in listOf(0, 2, 3)) assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireUniqueTarget("mapper", count)
        }
    }

    @Test fun alreadyPatchedMapperIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireMapperLayout(5, false, "CONST_STRING", 0)
        }
    }

    @Test fun unexpectedTryRegionsAreRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireMapperLayout(5, false, "IGET_OBJECT", 1)
        }
    }

    @Test fun constructorWithAdditionalNullCheckIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireConstructorLayout(listOf("INVOKE_STATIC") + constructorOpcodes, fields, baseConstructor)
        }
    }

    @Test fun changedConstructorFieldsAreRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireConstructorLayout(constructorOpcodes, fields.reversed(), baseConstructor)
        }
    }

    @Test fun changedBaseConstructorIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireConstructorLayout(constructorOpcodes, fields, null)
        }
    }

    @Test fun alreadyPatchedExpiryIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireExpiryLayout(listOf("CONST_4", "RETURN"), null, 2)
        }
    }

    @Test fun incorrectExpiryFieldIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireExpiryLayout(listOf("IGET_BOOLEAN", "RETURN"), "isTrial:Z", 2)
        }
    }

    @Test fun expiryWithoutScratchLocalIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireExpiryLayout(listOf("IGET_BOOLEAN", "RETURN"), "isExpired:Z", 1)
        }
    }

    // Synthetic copy of the verified 8.0.1 getter; no proprietary DEX fixture in tests.
    private fun originalStorageGetter(): List<ProModeInstruction> {
        val field = "Lcom/server/auditor/ssh/client/app/a;->d:Landroidx/lifecycle/k0;"
        val get = "Landroidx/lifecycle/f0;->f()Ljava/lang/Object;"
        return listOf(
            ProModeInstruction("IGET_OBJECT", listOf(0, 1), field),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), get),
            ProModeInstruction("MOVE_RESULT_OBJECT", listOf(0)),
            ProModeInstruction("IF_EQZ", listOf(0), branchTarget = 24),
            ProModeInstruction("IGET_OBJECT", listOf(0, 1), field),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), get),
            ProModeInstruction("MOVE_RESULT_OBJECT", listOf(0)),
            ProModeInstruction("CHECK_CAST", listOf(0), "Ljava/lang/Boolean;"),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), "Ljava/lang/Boolean;->booleanValue()Z"),
            ProModeInstruction("MOVE_RESULT", listOf(0)),
            ProModeInstruction("IF_EQZ", listOf(0), branchTarget = 24),
            ProModeInstruction("CONST_4", listOf(0), literal = 1),
            ProModeInstruction("RETURN", listOf(0)),
            ProModeInstruction("CONST_4", listOf(0), literal = 0),
            ProModeInstruction("RETURN", listOf(0)),
        )
    }

    private fun rejectStorageMutation(index: Int, change: (ProModeInstruction) -> ProModeInstruction) {
        val body = originalStorageGetter().toMutableList()
        body[index] = change(body[index])
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireStorageProLayout(2, false, 0, body)
        }
    }

    @Test fun originalStorageProGetterIsAccepted() {
        PremiumPatchValidation.requireUniqueTarget("storage Pro getter", 1)
        PremiumPatchValidation.requireStorageProLayout(2, false, 0, originalStorageGetter())
    }

    @Test fun missingAndAmbiguousStorageTargetsAreRejected() {
        for (count in listOf(0, 2)) assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireUniqueTarget("storage Pro getter", count)
        }
    }

    @Test fun staticStorageGetterIsRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireStorageProLayout(2, true, 0, originalStorageGetter())
        }
    }

    @Test fun changedStorageRegisterCountIsRejected() {
        for (registers in listOf(0, 1, 3, 16)) assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireStorageProLayout(registers, false, 0, originalStorageGetter())
        }
    }

    @Test fun storageExceptionHandlersAreRejected() {
        assertThrows(IllegalStateException::class.java) {
            PremiumPatchValidation.requireStorageProLayout(2, false, 1, originalStorageGetter())
        }
    }

    @Test fun authenticationFieldIsRejected() {
        for (index in listOf(0, 4)) rejectStorageMutation(index) {
            it.copy(reference = "Lcom/server/auditor/ssh/client/app/a;->e:Landroidx/lifecycle/k0;")
        }
    }

    @Test fun changedStorageFieldOwnerOrTypeIsRejected() {
        rejectStorageMutation(0) { it.copy(reference = "Lother/Storage;->d:Landroidx/lifecycle/k0;") }
        rejectStorageMutation(4) { it.copy(reference = "Lcom/server/auditor/ssh/client/app/a;->d:Ljava/lang/Object;") }
    }

    @Test fun changedStorageMethodReferencesOrCastAreRejected() {
        for (index in listOf(1, 5, 7, 8)) rejectStorageMutation(index) {
            it.copy(reference = "Ljava/lang/Object;")
        }
    }

    @Test fun changedStorageBranchPolarityOrDestinationIsRejected() {
        for (index in listOf(3, 10)) {
            rejectStorageMutation(index) { it.copy(opcode = "IF_NEZ") }
            rejectStorageMutation(index) { it.copy(branchTarget = 22) }
        }
    }

    @Test fun aliasedStorageRegisterOperandsAreRejected() {
        for (index in originalStorageGetter().indices) rejectStorageMutation(index) {
            it.copy(registers = it.registers.map { register -> 1 - register })
        }
    }

    @Test fun changedStorageConstantsOrReturnsAreRejected() {
        rejectStorageMutation(11) { it.copy(literal = 0) }
        rejectStorageMutation(13) { it.copy(literal = 1) }
        rejectStorageMutation(12) { it.copy(opcode = "RETURN_OBJECT") }
    }

    @Test fun missingOrAdditionalStorageInstructionsAreRejected() {
        val original = originalStorageGetter()
        for (body in listOf(original.dropLast(1), original + original.last())) {
            assertThrows(IllegalStateException::class.java) {
                PremiumPatchValidation.requireStorageProLayout(2, false, 0, body)
            }
        }
    }

    @Test fun alreadyPatchedStorageGetterIsRejectedIndependentlyOfMapper() {
        val prefix = listOf(
            ProModeInstruction("CONST_4", listOf(0), literal = 1),
            ProModeInstruction("RETURN", listOf(0)),
        )
        for (body in listOf(prefix, prefix + originalStorageGetter())) {
            assertThrows(IllegalStateException::class.java) {
                PremiumPatchValidation.requireStorageProLayout(2, false, 0, body)
            }
        }
    }
}
