package io.github.fishyau.androidpatches.spotify

/** Whole-map adapter for GenericPatchRunner's static verify(Map, Map) contract.
 * Every unrelated method, including all authentication/session code, must be unchanged.
 * The runner separately requires identical full class/field metadata and method sets.
 * Snapshot checks alone do not prove successful sign-in, refresh, sign-out or reauthentication.
 */
object PreviewAssertions {
    @JvmStatic fun verify(before: Map<String, List<String>>, after: Map<String, List<String>>) {
        verifyDelta(before, after, PreviewPins.semantic, mapOf(
            PreviewPins.EXPANDED to PreviewRole.EXPANDED, PreviewPins.COLLAPSED to PreviewRole.COLLAPSED))
    }
    internal fun verifyDelta(before: Map<String, List<String>>, after: Map<String, List<String>>,
                             pins: Map<String, String>, roles: Map<String, PreviewRole>) {
        check(before.keys == after.keys)
        check(pins.keys.containsAll(roles.keys) && roles.isNotEmpty())
        pins.forEach { (key, hash) ->
            check(CandidateSnapshots.hash(checkNotNull(before[key])) == hash) { "unpinned original or already patched" }
        }
        val expected = before.mapValues { (key, rows) -> roles[key]?.let {
            PreviewEdits.changed(rows, PreviewEdits.planRows(rows, it))
        } ?: rows }
        check(expected != before)
        check(expected == after) { "missing, wrong or extra instruction/metadata delta" }
    }
}
