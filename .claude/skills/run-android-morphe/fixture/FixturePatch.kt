import app.morphe.patcher.Fingerprint
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.patch.*
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.OneRegisterInstruction
import com.android.tools.smali.dexlib2.iface.instruction.ReferenceInstruction
import com.android.tools.smali.dexlib2.iface.reference.StringReference

// Trusted source example, not a semantic patch generator or collection plugin.
val fixtureLabelPatch = bytecodePatch(name = "Fixture label", default = false) {
    compatibleWith(Compatibility(packageName = "dev.morphe.fixture", name = "Local fixture", apkFileType = ApkFileType.APK,
        targets = listOf(AppTarget("1.0", 1))))
    execute {
        val method = Fingerprint(definingClass = "Ldev/morphe/fixture/MainActivity;", name = "label",
            parameters = emptyList(), returnType = "Ljava/lang/String;").matchAllOrNull().orEmpty().single().method
        val body = checkNotNull(method.implementation)
        val instructions = body.instructions.toList()
        check(body.registerCount == 1 && body.tryBlocks.isEmpty() && instructions.size == 2)
        check(instructions[0].opcode == Opcode.CONST_STRING && instructions[1].opcode == Opcode.RETURN_OBJECT)
        check((instructions[0] as OneRegisterInstruction).registerA == 0 && (instructions[1] as OneRegisterInstruction).registerA == 0)
        check(((instructions[0] as ReferenceInstruction).reference as StringReference).string == "BASELINE")
        method.replaceInstruction(0, "const-string v0, \"PATCHED\"")
    }
}
