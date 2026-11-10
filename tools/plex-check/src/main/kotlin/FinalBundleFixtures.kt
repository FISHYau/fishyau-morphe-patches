package io.github.fishyau.androidpatches.plexcheck

import java.security.MessageDigest

/** Self-authored, deliberately noninstallable HBC96 fixture grammar, not a Hermes parser.
 * Literal opcode IDs reviewed against the bounded v96 table; no production helpers
 * are compiled, imported or called to generate either inputs or expected outputs.
 */
internal object FinalBundleFixtures {
    data class Form(val name: String, val from: Int, val to: Int, val long: Boolean = false)
    val forms = listOf(
        Form("JStrictEqual", 188, 186), Form("JStrictEqualLong", 189, 187, true),
        Form("JStrictNotEqual", 190, 184), Form("JStrictNotEqualLong", 191, 185, true),
        Form("StrictEq", 15, 16), Form("StrictNeq", 17, 14),
    )
    val strings = listOf("on", "off", "useHasPlexPass", "getHasPlexPass", "useActiveSubscription", "decoy")
    data class Fixture(val bytes: ByteArray, val offsets: List<Int>)
    fun put32(bytes: ByteArray, offset: Int, value: Int) {
        for (i in 0..3) bytes[offset + i] = (value ushr (i * 8)).toByte()
    }
    fun footer(bytes: ByteArray) {
        MessageDigest.getInstance("SHA-1").digest(bytes.copyOf(bytes.size - 20)).copyInto(bytes, bytes.size - 20)
    }
    fun code(form: Form = forms.first(), string: Int = 0, moved: Int = 0, patched: Boolean = false): ByteArray {
        val load = if (moved == 2) byteArrayOf(116, 1, string.toByte(), 0, 0, 0)
                   else byteArrayOf(115, 1, string.toByte(), 0)
        val move = when (moved) {
            1 -> byteArrayOf(8, 3, 1)
            2 -> byteArrayOf(9, 3, 0, 0, 0, 1, 0, 0, 0)
            else -> byteArrayOf()
        }
        val reg = if (moved == 0) 1 else 3
        val op = (if (patched) form.to else form.from).toByte()
        val compare = if (form.long) byteArrayOf(op, 4, 0, 0, 0, 2, reg.toByte())
                      else byteArrayOf(op, 4, 2, reg.toByte())
        return load + move + compare + byteArrayOf(92, 2)
    }
    fun site(moved: Int = 0) = when (moved) { 1 -> 7; 2 -> 15; else -> 4 }
    fun bundle(codes: List<ByteArray> = List(4) { code() }, values: List<String> = strings,
               names: List<Int> = codes.indices.map { it + 2 }): Fixture {
        require(codes.size == names.size && codes.size in 1..8 && values.size == 6)
        val encoded = values.map { it.toByteArray(Charsets.ISO_8859_1) }
        require(encoded.all { it.size < 255 })
        val table = 128 + codes.size * 16
        val storage = table + values.size * 4
        val size = encoded.sumOf { it.size }
        var cursor = (storage + size + 3) and -4
        val offsets = codes.map { code -> cursor.also { cursor += code.size } }
        val bytes = ByteArray(cursor + 20)
        put32(bytes, 0, 0x03BC1FC6); put32(bytes, 4, 0x1F1903C1)
        put32(bytes, 8, 96); put32(bytes, 32, bytes.size)
        put32(bytes, 40, codes.size); put32(bytes, 52, values.size); put32(bytes, 60, size)
        var position = 0
        encoded.forEachIndexed { index, value ->
            put32(bytes, table + index * 4, (value.size shl 24) or (position shl 1))
            value.copyInto(bytes, storage + position); position += value.size
        }
        codes.forEachIndexed { index, value ->
            put32(bytes, 128 + index * 16, offsets[index])
            put32(bytes, 132 + index * 16, (names[index] shl 15) or value.size)
            value.copyInto(bytes, offsets[index])
        }
        footer(bytes)
        return Fixture(bytes, offsets)
    }
    fun expected(fixture: Fixture, to: Int = 186, functions: List<Int> = listOf(0, 1, 2), site: Int = 4): ByteArray =
        fixture.bytes.copyOf().also { bytes ->
            functions.forEach { bytes[fixture.offsets[it] + site] = to.toByte() }
            footer(bytes)
        }
}
