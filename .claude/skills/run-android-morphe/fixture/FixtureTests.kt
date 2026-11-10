object FixtureTests {
    @JvmStatic fun main(args: Array<String>) {
        val original = listOf("metadata", "registers=1", "CONST_STRING [0] ref=\"BASELINE\" ref2=null literal=null target=null",
            "RETURN_OBJECT [0] ref=null ref2=null literal=null target=null")
        val changed = original.map { it.replace("\"BASELINE\"", "\"PATCHED\"") }
        val before = mapOf(FixtureAssertions.KEY to original, "untouched" to listOf("same"))
        val after = before + (FixtureAssertions.KEY to changed)
        FixtureAssertions.verify(before, after)
        fun reject(candidate: Map<String, List<String>>) {
            check(runCatching { FixtureAssertions.verify(before, candidate) }.isFailure)
        }
        reject(before) // missing edit / repeat application
        reject(after - FixtureAssertions.KEY) // missing method
        reject(after + ("untouched" to listOf("changed"))) // preservation violation
        reject(after + (FixtureAssertions.KEY to changed.map { it.replace("[0]", "[1]") })) // register drift
        reject(after + (FixtureAssertions.KEY to changed.map { it.replace("PATCHED", "WRONG") })) // wrong value
        reject(after + (FixtureAssertions.KEY to (changed + "extra"))) // extra instruction
        println("fixture validator: positive and six negative tests passed")
    }
}
