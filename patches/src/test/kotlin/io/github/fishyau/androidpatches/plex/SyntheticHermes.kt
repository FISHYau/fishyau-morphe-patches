package io.github.fishyau.androidpatches.plex

import io.github.fishyau.androidpatches.plex.shared.HermesBundle
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Self-authored HBC96 bytes, never copied from an app or a donor binary. */
internal object SyntheticHermes {
    val names = listOf("useHasPlexPass", "getHasPlexPass", "useActiveSubscription", "decoy")
    val strings = listOf("on", "off") + names

    fun put32(data: ByteArray, at: Int, value: Int) {
        for (i in 0..3) data[at + i] = (value ushr (8 * i)).toByte()
    }

    fun insn(name: String, vararg args: Int): ByteArray {
        val opcode = HermesBundle.opcode(name)
        val types = HermesBundle.OPCODE_OPERANDS[opcode]
        require(types.length == args.size)
        val out = ByteArrayOutputStream()
        out.write(opcode)
        for ((index, type) in types.withIndex()) {
            val size = when (type) { 's' -> 2; 'R', 'i', 'A', 'I' -> 4; 'd' -> 8; else -> 1 }
            for (i in 0 until size) out.write(if (i < 4) args[index] ushr (i * 8) else 0)
        }
        return out.toByteArray()
    }

    fun check(opcode: String = "JStrictEqual", string: Int = 0): ByteArray =
        insn("LoadConstString", 1, string) + insn(opcode, 4, 2, 1) + insn("Ret", 2)

    data class Fixture(val data: ByteArray, val offsets: List<Int>, val stringTable: Int, val overflowTable: Int, val storage: Int, val largeHeader: Int)

    fun bundle(
        codes: List<ByteArray> = List(4) { check() },
        values: List<String> = strings,
        functionNames: List<Int> = codes.indices.map { it + 2 },
        utf16: Set<Int> = emptySet(),
        overflow: Set<Int> = emptySet(),
        largeFunction: Int = -1,
    ): Fixture {
        require(functionNames.size == codes.size)
        val encoded = values.mapIndexed { id, s -> s.toByteArray(if (id in utf16) Charsets.UTF_16LE else Charsets.ISO_8859_1) }
        val table = 128 + codes.size * 16
        val overflowTable = table + values.size * 4
        val storage = overflowTable + overflow.size * 8
        val storageSize = encoded.sumOf { it.size }
        val largeHeader = (storage + storageSize + 3) and -4
        var cursor = largeHeader + if (largeFunction >= 0) 32 else 0
        val offsets = codes.map { code -> cursor.also { cursor += code.size } }
        val bytes = ByteArray(cursor + 20)
        put32(bytes, 0, 0x03BC1FC6)
        put32(bytes, 4, 0x1F1903C1)
        put32(bytes, 8, 96)
        put32(bytes, 32, bytes.size)
        put32(bytes, 40, codes.size)
        put32(bytes, 52, values.size)
        put32(bytes, 56, overflow.size)
        put32(bytes, 60, storageSize)
        var stringOffset = 0
        var overflowIndex = 0
        for (i in values.indices) {
            val isUtf16 = if (i in utf16) 1 else 0
            if (i in overflow) {
                put32(bytes, table + i * 4, (0xFF shl 24) or (overflowIndex shl 1) or isUtf16)
                put32(bytes, overflowTable + overflowIndex * 8, stringOffset)
                put32(bytes, overflowTable + overflowIndex * 8 + 4, values[i].length)
                overflowIndex++
            } else {
                require(values[i].length < 255)
                put32(bytes, table + i * 4, (values[i].length shl 24) or (stringOffset shl 1) or isUtf16)
            }
            encoded[i].copyInto(bytes, storage + stringOffset)
            stringOffset += encoded[i].size
        }
        for (i in codes.indices) {
            val at = 128 + i * 16
            if (i == largeFunction) {
                put32(bytes, at, largeHeader and 0xFFFF)
                put32(bytes, at + 8, largeHeader ushr 16)
                bytes[at + 15] = 0x20
                put32(bytes, largeHeader, offsets[i])
                put32(bytes, largeHeader + 8, codes[i].size)
                put32(bytes, largeHeader + 12, functionNames[i])
            } else {
                put32(bytes, at, offsets[i])
                put32(bytes, at + 4, (functionNames[i] shl 15) or codes[i].size)
            }
            codes[i].copyInto(bytes, offsets[i])
        }
        footer(bytes)
        return Fixture(bytes, offsets, table, overflowTable, storage, largeHeader)
    }

    fun footer(data: ByteArray) {
        MessageDigest.getInstance("SHA-1").digest(data.copyOf(data.size - 20)).copyInto(data, data.size - 20)
    }
}
