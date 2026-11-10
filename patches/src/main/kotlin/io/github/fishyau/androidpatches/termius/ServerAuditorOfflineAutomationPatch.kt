package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.bytecodePatch
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.AccessFlags

/** Local startup-snippet decisions only; does not simulate an account or subscription. */
@Suppress("unused")
val serverAuditorOfflineAutomationPatch = bytecodePatch(
    name = "Server Auditor Offline Automation",
    description = "Enables local startup-snippet Automation without a Termius account in 8.0.1. Select alone; leaves global authentication and Pro state unchanged. Offline means account-independent, not network-free SSH.",
    default = true,
) {
    compatibleWith(SERVER_AUDITOR_COMPATIBILITY)
    execute {
        fun resolve(fingerprint: Fingerprint, label: String): MutableMethod {
            val matches = fingerprint.matchAllOrNull().orEmpty()
            PremiumPatchValidation.requireUniqueTarget(label, matches.size)
            return matches.single().method
        }
        val widget = resolve(OfflineSnippetWidgetFingerprint, "snippet widget")
        val ssh = resolve(OfflineSshAutomationFingerprint, "SSH Automation")
        val terminal = resolve(OfflineTerminalAutomationFingerprint, "terminal Automation")
        val storage = resolve(StorageProModeFingerprint, "storage Pro getter")
        val storageBody = checkNotNull(storage.implementation)
        // Reject the old global override instead of silently layering onto it.
        PremiumPatchValidation.requireStorageProLayout(
            storageBody.registerCount, AccessFlags.STATIC.isSet(storage.accessFlags),
            storageBody.tryBlocks.size, storage.captureInstructions(),
        )
        for ((label, method) in listOf("snippet widget" to widget, "SSH Automation" to ssh, "terminal Automation" to terminal)) {
            val body = checkNotNull(method.implementation) { "Termius $label has no implementation." }
            OfflineAutomationValidation.requireLayout(
                label, body.registerCount, method.accessFlags, body.tryBlocks.size, method.captureInstructions(),
            )
        }
        // ALL targets have passed preflight. Same-width replacements, no register growth.
        // Only this widget's upgrade state becomes enabled; h$b's disabled handler stays intact.
        widget.replaceInstruction(4, "invoke-direct {p0}, $SNIPPET_WIDGET->N()V")
        // Deliberately ignore these local Pro-query results; no change to the global getter.
        ssh.replaceInstruction(12, "const/4 v1, 0x1")
        terminal.replaceInstruction(31, "const/4 v0, 0x1")
    }
}
