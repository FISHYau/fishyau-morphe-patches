import app.morphe.patcher.patch.*

// Optional synthetic NEGATIVE bundles only; do not add to the normal patch build.
private fun fixtureTarget() = Compatibility(packageName = "dev.morphe.fixture", name = "Local fixture",
    apkFileType = ApkFileType.APK, targets = listOf(AppTarget("1.0", 1)))
val negativeDependency = bytecodePatch(name = "Negative dependency", default = false) {
    compatibleWith(fixtureTarget())
}
val negativeDependent = bytecodePatch(name = "Negative dependent", default = false) {
    compatibleWith(fixtureTarget()); dependsOn(negativeDependency)
}
val negativeResources = rawResourcePatch(name = "Negative resources", default = false) {
    compatibleWith(fixtureTarget())
}
val negativeOptions = bytecodePatch(name = "Negative options", default = false) {
    compatibleWith(fixtureTarget()); booleanOption(key = "unsupported", default = false)
}
val negativeDuplicateA = bytecodePatch(name = "Negative duplicate", default = false) { compatibleWith(fixtureTarget()) }
val negativeDuplicateB = bytecodePatch(name = "Negative duplicate", default = false) { compatibleWith(fixtureTarget()) }
val negativeIncompatible = bytecodePatch(name = "Negative incompatible", default = false) {
    compatibleWith(Compatibility(packageName = "dev.morphe.fixture", name = "Local fixture",
        apkFileType = ApkFileType.APK, targets = listOf(AppTarget("2.0", 2))))
}
object RejectingFixtureAssertions {
    @JvmStatic fun verify(before: Map<String, List<String>>, after: Map<String, List<String>>) {
        check(before.isEmpty() && after.isEmpty()) { "intentional assertion rejection" }
    }
}
