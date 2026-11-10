object FixtureAssertions {
    const val KEY = "Ldev/morphe/fixture/MainActivity;->label()Ljava/lang/String;"

    @JvmStatic fun verify(before: Map<String, List<String>>, after: Map<String, List<String>>) {
        check(before.keys == after.keys && KEY in before)
        check(before.keys.filter { before[it] != after[it] }.toSet() == setOf(KEY))
        val a = before.getValue(KEY); val b = after.getValue(KEY)
        check(a.size == b.size)
        val index = a.indices.filter { a[it] != b[it] }.single()
        check(a[index] == "CONST_STRING [0] ref=\"BASELINE\" ref2=null literal=null target=null")
        check(b[index] == "CONST_STRING [0] ref=\"PATCHED\" ref2=null literal=null target=null")
        check(a.last() == "RETURN_OBJECT [0] ref=null ref2=null literal=null target=null")
        check(a.count { it.startsWith("CONST_STRING ") } == 1)
        check(a.contains("registers=1"))
    }
}
