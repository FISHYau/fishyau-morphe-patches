package io.github.fishyau.androidpatches.plex

import io.github.fishyau.androidpatches.plex.shared.HermesBundle
import io.github.fishyau.androidpatches.plex.shared.HermesFormatException
import org.junit.Assert.*
import org.junit.Test

class HermesBytecodeTest {
    private fun rejected(message: String, block: () -> Unit) {
        val error = assertThrows(HermesFormatException::class.java) { block() }
        assertTrue(error.message, error.message.orEmpty().contains(message))
    }

    @Test fun readsVersionLengthAndCompactFunctions() {
        val f = SyntheticHermes.bundle()
        val b = HermesBundle(f.data)
        assertEquals(96, b.version)
        assertEquals(f.data.size, b.fileLength)
        assertEquals(f.offsets[1], b.function(1).offset)
        assertEquals(listOf(1), b.functionsNamed(b.findStringIds("getHasPlexPass")).map { it.id })
        assertTrue(b.functionsNamed(emptyList()).isEmpty())
    }

    @Test fun rejectsShortAndWrongMagic() {
        rejected("not a Hermes") { HermesBundle(ByteArray(147)) }
        val data = SyntheticHermes.bundle().data
        data[0] = 0
        rejected("not a Hermes") { HermesBundle(data) }
    }

    @Test fun rejectsUnsupportedVersion() {
        val data = SyntheticHermes.bundle().data
        SyntheticHermes.put32(data, 8, 95)
        rejected("expected 96") { HermesBundle(data) }
    }

    @Test fun rejectsInvalidFileLengths() {
        for (length in listOf(-1, 147, 100000)) {
            val data = SyntheticHermes.bundle().data
            SyntheticHermes.put32(data, 32, length)
            rejected("bad file length") { HermesBundle(data) }
        }
    }

    @Test fun rejectsNegativeOrOversizedCounts() {
        for (at in listOf(40, 44, 48, 52, 56, 60)) {
            for (value in listOf(-1, 100000)) {
                val data = SyntheticHermes.bundle().data
                SyntheticHermes.put32(data, at, value)
                rejected("bad header field") { HermesBundle(data) }
            }
        }
    }

    @Test fun rejectsSectionBounds() {
        val data = SyntheticHermes.bundle().data
        SyntheticHermes.put32(data, 40, data.size)
        rejected("string storage runs past") { HermesBundle(data) }
    }

    @Test fun readsAsciiUtf16OverflowAndDuplicateStrings() {
        val f = SyntheticHermes.bundle(values = SyntheticHermes.strings + listOf("λ中", "x".repeat(300), "on"), utf16 = setOf(6), overflow = setOf(7))
        val b = HermesBundle(f.data)
        assertEquals("λ中", b.stringAt(6))
        assertEquals("x".repeat(300), b.stringAt(7))
        assertEquals(listOf(0, 8), b.findStringIds("on"))
        assertTrue(b.findStringIds("missing").isEmpty())
    }

    @Test fun rejectsStringIdsAndOverflowIndex() {
        val f = SyntheticHermes.bundle()
        val b = HermesBundle(f.data)
        rejected("out of range") { b.stringAt(-1) }
        rejected("out of range") { b.stringAt(6) }
        SyntheticHermes.put32(f.data, f.stringTable, 0xFF000002.toInt())
        rejected("bad overflow string index") { b.stringAt(0) }
    }

    @Test fun rejectsStringStorageOverrun() {
        val f = SyntheticHermes.bundle()
        SyntheticHermes.put32(f.data, f.stringTable, (10 shl 24) or (0x7FFFFF shl 1))
        rejected("runs past string storage") { HermesBundle(f.data).stringAt(0) }
    }

    @Test fun rejectsNegativeOverflowStringFields() {
        for (delta in listOf(0, 4)) {
            val f = SyntheticHermes.bundle(overflow = setOf(0))
            SyntheticHermes.put32(f.data, f.overflowTable + delta, -1)
            rejected("runs past string storage") { HermesBundle(f.data).stringAt(0) }
        }
    }

    @Test fun readsLargeFunctionHeader() {
        val f = SyntheticHermes.bundle(largeFunction = 1)
        val b = HermesBundle(f.data)
        assertEquals(f.offsets[1], b.function(1).offset)
        assertEquals(3, b.function(1).nameId)
        assertEquals(listOf(1), b.functionsNamed(listOf(3)).map { it.id })
    }

    @Test fun rejectsFunctionIdsAndBytecodeBounds() {
        val f = SyntheticHermes.bundle()
        val b = HermesBundle(f.data)
        rejected("out of range") { b.function(-1) }
        rejected("out of range") { b.function(4) }
        SyntheticHermes.put32(f.data, 128, f.data.size)
        rejected("bytecode runs past") { b.function(0) }
    }

    @Test fun rejectsBadLargeFunctionHeaderAndSize() {
        val f = SyntheticHermes.bundle(largeFunction = 0)
        SyntheticHermes.put32(f.data, 128, f.data.size + 1)
        rejected("bad large header") { HermesBundle(f.data).function(0) }
        val g = SyntheticHermes.bundle(largeFunction = 0)
        SyntheticHermes.put32(g.data, g.largeHeader + 8, -1)
        rejected("bytecode runs past") { HermesBundle(g.data).function(0) }
    }

    @Test fun decodesAllOperandWidthsAndSignedAddresses() {
        val code = SyntheticHermes.insn("Jmp", -5) + SyntheticHermes.insn("MovLong", 70000, 80000) +
            SyntheticHermes.insn("LoadConstString", 2, 50000) + SyntheticHermes.insn("JmpLong", -123456) +
            SyntheticHermes.insn("LoadConstDouble", 3, 0) + SyntheticHermes.insn("Ret", 3)
        val f = SyntheticHermes.bundle(codes = listOf(code))
        val b = HermesBundle(f.data)
        val insns = b.instructions(b.function(0))
        assertEquals(6, insns.size)
        assertEquals(-5, insns[0].operands[0])
        assertArrayEquals(intArrayOf(70000, 80000), insns[1].operands)
        assertEquals(50000, insns[2].operands[1])
        assertEquals(-123456, insns[3].operands[0])
        assertEquals(10, insns[4].length)
        assertEquals("Ret", insns[5].name)
    }

    @Test fun stopsBeforeSwitchJumpTable() {
        val switch = SyntheticHermes.insn("SwitchImm", 0, 20, 0, 0, 0)
        assertEquals(18, switch.size)
        val f = SyntheticHermes.bundle(codes = listOf(switch + SyntheticHermes.insn("Ret", 0) + byteArrayOf(-1, -1, -1, -1)))
        val b = HermesBundle(f.data)
        assertEquals(listOf("SwitchImm", "Ret"), b.instructions(b.function(0)).map { it.name })
    }

    @Test fun rejectsUnknownOpcode() {
        val f = SyntheticHermes.bundle(codes = listOf(byteArrayOf(-1)))
        val b = HermesBundle(f.data)
        rejected("unknown opcode") { b.instructions(b.function(0)) }
    }

    @Test fun rejectsTruncatedInstruction() {
        val f = SyntheticHermes.bundle(codes = listOf(byteArrayOf(HermesBundle.opcode("Mov").toByte(), 1)))
        val b = HermesBundle(f.data)
        rejected("truncated instruction") { b.instructions(b.function(0)) }
    }

    @Test fun validatesAndRecomputesExactFooter() {
        val f = SyntheticHermes.bundle()
        val b = HermesBundle(f.data)
        assertTrue(b.footerValid())
        f.data[f.offsets[0]] = HermesBundle.opcode("LoadConstStringLongIndex").toByte()
        assertFalse(b.footerValid())
        val prefix = f.data.copyOf(f.data.size - 20)
        b.updateFooter()
        assertTrue(b.footerValid())
        assertArrayEquals(prefix, f.data.copyOf(f.data.size - 20))
    }
}
