import app.morphe.patcher.patch.*

// A separately compiled bundle, never present in the positive bundle.
// The actual loader MUST reject this definition before its execute block.
val apkOnlyPatch = bytecodePatch(name = "APK-only negative", default = false) {
    compatibleWith(Compatibility(packageName = "dev.morphe.splitfixture", name = "Incompatible APK-only fixture",
        apkFileType = ApkFileType.APK, targets = listOf(AppTarget("1.0", 1))))
    execute { error("APK_ONLY_EXECUTE_MUST_NOT_BE_REACHED") }
}
