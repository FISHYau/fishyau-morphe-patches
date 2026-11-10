object SplitTests {
    @JvmStatic fun main(args: Array<String>) {
        val original = listOf("metadata", "registers=1", "CONST_STRING [0] ref=\"BASELINE\" ref2=null literal=null target=null",
            "RETURN_OBJECT [0] ref=null ref2=null literal=null target=null")
        val changed = original.map { it.replace("\"BASELINE\"", "\"PATCHED\"") }
        val before = mapOf(SplitAssertions.KEY to original, "untouched" to listOf("same"))
        val after = before + (SplitAssertions.KEY to changed)
        SplitAssertions.verify(before, after)
        fun reject(candidate: Map<String, List<String>>) {
            check(runCatching { SplitAssertions.verify(before, candidate) }.isFailure)
        }
        reject(before)
        reject(after - SplitAssertions.KEY)
        reject(after + ("untouched" to listOf("changed")))
        reject(after + (SplitAssertions.KEY to changed.map { it.replace("[0]", "[1]") }))
        reject(after + (SplitAssertions.KEY to changed.map { it.replace("PATCHED", "WRONG") }))
        reject(after + (SplitAssertions.KEY to (changed + "extra")))
        check(runCatching { SplitAssertions.verify(after, after) }.isFailure)
        check(runCatching { SplitAssertions.verify(emptyMap(), emptyMap()) }.isFailure)
        println("split assertion: positive and eight negative cases passed")
    }
}
