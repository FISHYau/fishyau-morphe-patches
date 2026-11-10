package io.github.fishyau.androidpatches.termius

/** DEX-independent instruction shape, with branch targets expressed in code units. */
internal data class ProModeInstruction(
    val opcode: String,
    val registers: List<Int>,
    val reference: String? = null,
    val literal: Long? = null,
    val branchTarget: Int? = null,
)

/** Pure preflight checks, shared by patch execution and synthetic layout tests. */
internal object PremiumPatchValidation {
    fun requireUniqueTarget(description: String, count: Int) {
        check(count == 1) {
            "Termius 8.0.1: $description matched $count methods; expected exactly one."
        }
    }

    fun requireMapperLayout(registerCount: Int, isStatic: Boolean, firstOpcode: String?, tryCount: Int) {
        check(!isStatic) { "Termius mapper must be an instance method." }
        // One String argument plus 'this': p0 = v(registerCount - 2), p1 = v(registerCount - 1).
        // v0..v2 must be locals, and short invoke-direct can encode only v0..v15.
        check(registerCount in 5..16) {
            "Unsupported Termius mapper register count $registerCount; need 3 locals and p1 <= v15."
        }
        check(firstOpcode == "IGET_OBJECT" && tryCount == 0) {
            "Termius mapper body is already patched or has an unsupported entry/try layout."
        }
    }

    fun requireConstructorLayout(opcodes: List<String>, fieldWrites: List<String>, baseConstructor: String?) {
        check(opcodes == listOf("CONST_4", "INVOKE_DIRECT", "IPUT_OBJECT", "IPUT_BOOLEAN", "IPUT_OBJECT", "RETURN_VOID")) {
            "Unsupported Termius Pro constructor body; nullable arguments are not verified."
        }
        check(fieldWrites == listOf("title:Ljava/lang/String;", "isExpired:Z", "subscriptionPeriod:Lcom/server/auditor/ssh/client/models/SubscriptionPeriod;")) {
            "Unsupported Termius Pro constructor field assignments."
        }
        check(baseConstructor == "Lcom/server/auditor/ssh/client/models/UserType;-><init>(Lkotlin/jvm/internal/k;)V") {
            "Unsupported Termius Pro base constructor."
        }
    }

    fun requireStorageProLayout(
        registerCount: Int,
        isStatic: Boolean,
        tryCount: Int,
        instructions: List<ProModeInstruction>,
    ) {
        check(!isStatic && registerCount == 2 && tryCount == 0) {
            "Unsupported Termius storage Pro getter registers, flags, or exception handlers."
        }
        check(instructions.firstOrNull()?.opcode != "CONST_4") {
            "Termius storage Pro getter is already patched."
        }
        val proField = "Lcom/server/auditor/ssh/client/app/a;->d:Landroidx/lifecycle/k0;"
        val readValue = "Landroidx/lifecycle/f0;->f()Ljava/lang/Object;"
        val expected = listOf(
            ProModeInstruction("IGET_OBJECT", listOf(0, 1), proField),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), readValue),
            ProModeInstruction("MOVE_RESULT_OBJECT", listOf(0)),
            ProModeInstruction("IF_EQZ", listOf(0), branchTarget = 0x18),
            ProModeInstruction("IGET_OBJECT", listOf(0, 1), proField),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), readValue),
            ProModeInstruction("MOVE_RESULT_OBJECT", listOf(0)),
            ProModeInstruction("CHECK_CAST", listOf(0), "Ljava/lang/Boolean;"),
            ProModeInstruction("INVOKE_VIRTUAL", listOf(0), "Ljava/lang/Boolean;->booleanValue()Z"),
            ProModeInstruction("MOVE_RESULT", listOf(0)),
            ProModeInstruction("IF_EQZ", listOf(0), branchTarget = 0x18),
            ProModeInstruction("CONST_4", listOf(0), literal = 1),
            ProModeInstruction("RETURN", listOf(0)),
            ProModeInstruction("CONST_4", listOf(0), literal = 0),
            ProModeInstruction("RETURN", listOf(0)),
        )
        check(instructions == expected) {
            "Unsupported Termius storage Pro getter body; expected original Pro field d and verified control flow."
        }
    }

    fun requireExpiryLayout(opcodes: List<String>, field: String?, registerCount: Int) {
        check(opcodes == listOf("IGET_BOOLEAN", "RETURN") && field == "isExpired:Z" && registerCount >= 2) {
            "Termius Pro expiry getter is already patched or has an unsupported body."
        }
    }
}
