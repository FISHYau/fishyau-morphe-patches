package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.addInstructions
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.AccessFlags
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.FieldReference
import com.android.tools.smali.dexlib2.iface.reference.MethodReference

internal const val USER_TYPE_PRO = "Lcom/server/auditor/ssh/client/models/UserType\$Pro;"

/**
 * Termius 8.0.1 / 1008 maps cached account state in cm/c.c(String).
 * The structural fingerprint deliberately does not depend on that obfuscated name.
 *
 * The inspected mapper reads account/subscription information and selects a UserType;
 * it does not write account state. The original Pro constructor accepts nullable
 * title/period values and stores its boolean argument directly as isExpired.
 *
 * Optional legacy account-presentation override, separate from Offline Automation.
 * Does not override storage Pro/auth state or provision backend entitlements.
 * Leave this patch unselected when testing account-free local Automation.
 */
@Suppress("unused")
val serverAuditorPremiumPatch = bytecodePatch(
    name = "Server Auditor Premium",
    description = "Optional legacy Pro title/expiry override for Termius 8.0.1. Does not enable account-free Automation or change storage/server entitlements.",
    default = true,
) {
    compatibleWith(SERVER_AUDITOR_COMPATIBILITY)

    execute {
        fun resolveUnique(fingerprint: Fingerprint, description: String): MutableMethod {
            val matches = fingerprint.matchAllOrNull().orEmpty()
            PremiumPatchValidation.requireUniqueTarget(description, matches.size)
            return matches.single().method
        }

        // Preflight every target before changing any method. A partially patched
        // or unsupported input must fail rather than produce a successful no-op.
        val mapper = resolveUnique(UserTypeMapperFingerprint, "UserType mapper")
        val constructor = resolveUnique(ProConstructorFingerprint, "Pro constructor")
        val expiry = resolveUnique(ProSubscriptionExpiredFingerprint, "Pro expiry getter")
        val mapperBody = checkNotNull(mapper.implementation) { "Termius mapper has no implementation." }
        val constructorInstructions = checkNotNull(constructor.implementation).instructions.toList()
        val expiryBody = checkNotNull(expiry.implementation)
        val expiryInstructions = expiryBody.instructions.toList()
        check(constructor.implementation!!.tryBlocks.isEmpty() && expiryBody.tryBlocks.isEmpty()) {
            "Unsupported exception handlers in Termius Pro constructor/expiry getter."
        }

        PremiumPatchValidation.requireMapperLayout(
            mapperBody.registerCount,
            AccessFlags.STATIC.isSet(mapper.accessFlags),
            mapperBody.instructions.firstOrNull()?.opcodeKey(),
            mapperBody.tryBlocks.size,
        )
        val constructorFields = constructorInstructions.mapNotNull {
            ((it as? ReferenceInstruction)?.reference as? FieldReference)?.let { field ->
                check(field.definingClass == USER_TYPE_PRO) { "Unexpected Pro constructor field owner." }
                "${field.name}:${field.type}"
            }
        }
        val constructorCalls = constructorInstructions.mapNotNull {
            (it as? ReferenceInstruction)?.reference as? MethodReference
        }
        val baseConstructor = constructorCalls.singleOrNull()?.let {
            "${it.definingClass}->${it.name}(${it.parameterTypes.joinToString("")})${it.returnType}"
        }
        PremiumPatchValidation.requireConstructorLayout(
            constructorInstructions.map { it.opcodeKey() }, constructorFields, baseConstructor,
        )
        val expiryField = expiryInstructions.mapNotNull {
            (it as? ReferenceInstruction)?.reference as? FieldReference
        }.singleOrNull()?.let {
            check(it.definingClass == USER_TYPE_PRO) { "Unexpected Pro expiry field owner." }
            "${it.name}:${it.type}"
        }
        PremiumPatchValidation.requireExpiryLayout(
            expiryInstructions.map { it.opcodeKey() }, expiryField, expiryBody.registerCount,
        )

        // No register growth or reflection: preflight proves v0..v2 are locals
        // and p1 fits the four-bit register field used by invoke-direct.
        mapper.addInstructions(
            0,
            """
            const-string p1, "Premium"
            const/4 v1, 0x0
            const/4 v2, 0x0
            new-instance v0, $USER_TYPE_PRO
            invoke-direct {v0, p1, v1, v2}, $USER_TYPE_PRO-><init>(Ljava/lang/String;ZLcom/server/auditor/ssh/client/models/SubscriptionPeriod;)V
            return-object v0
            """,
        )
        expiry.returnEarly(false)
    }
}
