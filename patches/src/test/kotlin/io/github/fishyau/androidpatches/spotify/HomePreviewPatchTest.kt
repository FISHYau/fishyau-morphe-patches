package io.github.fishyau.androidpatches.spotify

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.FormFactor
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.builder.BuilderInstruction
import com.android.tools.smali.dexlib2.builder.MethodImplementationBuilder
import com.android.tools.smali.dexlib2.builder.instruction.*
import com.android.tools.smali.dexlib2.iface.instruction.OffsetInstruction
import com.android.tools.smali.dexlib2.immutable.ImmutableMethod
import com.android.tools.smali.dexlib2.immutable.ImmutableMethodImplementation
import com.android.tools.smali.dexlib2.immutable.reference.*
import org.junit.Assert.*
import org.junit.Test
import java.lang.reflect.Modifier

/** Self-contained instruction-model tests, not verifier-valid Android programs or UI simulations.
 * No vendor method dumps, APKs, external snapshots, private paths, credentials or account access.
 * Auth/session sentinels below prove synthetic preservation only, NOT real authentication behavior.
 */
class HomePreviewPatchTest {
    private fun execute(methods: List<MutableMethod>, spec: PreviewSpec = Fixture.spec) =
        PreviewExecution.execute(spec) { key ->
            PreviewEdits.only(methods.filter { CandidateSnapshots.key(it) == key }, key)
        }
    private fun snapshots(methods: List<MutableMethod>) = methods.associate { CandidateSnapshots.key(it) to CandidateSnapshots.method(it) }
    private fun physical(methods: List<MutableMethod>) = methods.map { CandidateSnapshots.original(it) }
    private fun reject(block: () -> Unit) { assertThrows(RuntimeException::class.java) { block() } }
    private fun assertRejectedWithoutWrites(methods: List<MutableMethod>, spec: PreviewSpec = Fixture.spec) {
        val before = physical(methods)
        reject { execute(methods, spec) }
        assertEquals(before, physical(methods))
    }
    private fun validate(before: Map<String, List<String>>, after: Map<String, List<String>>) =
        PreviewAssertions.verifyDelta(before, after, Fixture.semantic, Fixture.roles)

    @Test fun exactDefinitionDefaultsCompatibilityAndFacadeOwner() {
        val p = disableHomePreviewsPatch
        assertEquals("Disable Home previews", p.name)
        assertTrue(p.default)
        assertTrue(p.options.isEmpty())
        assertTrue(p.dependencies.isEmpty())
        val c = p.compatibility!!.single()
        assertEquals("Spotify TV", c.name)
        assertEquals("com.spotify.tv.android", c.packageName)
        assertEquals(ApkFileType.APKM_REQUIRED, c.apkFileType)
        assertEquals(FormFactor.TV, c.formFactor)
        val t = c.targets.single()
        assertEquals("9.1.94.1926", t.version)
        assertEquals(setOf(147600562), t.versionCodes!!.values.toSet())
        assertFalse(t.isExperimental)
        val owner = Class.forName("io.github.fishyau.androidpatches.spotify.HomePreviewPatchKt")
        assertSame(p, owner.getDeclaredMethod("getDisableHomePreviewsPatch").invoke(null))
        assertTrue(p.description.orEmpty().contains("authentication"))
        assertTrue(p.description.orEmpty().contains("session"))
    }

    @Test fun allFourteenOriginalPinsAndSevenSelectorsRemainExactAndImmutable() {
        val expectedSemantic = linkedMapOf(
            "Lmud;->c(Landroid/net/Uri;Ltr8;Lsx5;I)V" to "50d445dc6a664c4962c12448da9acf653fc1fff0448a15c78f001b9a8001b1f5",
            "Ldg;->invoke()Ljava/lang/Object;" to "71c28ce49b0b9be410fcbb8a529c06f431d2248045ff77f6a9a172089fdd4099",
            "Ldg;-><init>(Ltx8;Ljd0;Lfr9;)V" to "8dcabbe26a661b46006cec52eac175a557dfba860437c69fc0d4037026500d92",
            "Lct0;-><init>(Landroid/net/Uri;Lkt0;I)V" to "951b23b9e59e625b00b70624a64094416ed01ba30c95850abb3e55f1b4789ae6",
            "Lmud;->a(Ljt0;Ltr8;Lsx5;I)V" to "6b32788f16956218545dd03a090db88f5f2b8fedb45ff1a9928fcb31ccfb3c31",
            "Lewd;->B(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;" to "c37639af396949e2a713a366f6fd7d55ef308fdf913e207c28153fb01fde319b",
            "Ltt2;->invoke(Ljava/lang/Object;)Ljava/lang/Object;" to "573a615ee9766a0150b8a33f485adae6c7d75ee7f7488bcc0492fc8691ade282")
        val expectedPhysical = expectedSemantic.keys.zip(listOf(
            "993c6728f0151b98c5501910242e3d5c92743f1e8a83ea8938e63fff0af532b5",
            "d59b86d8eb2ae4d3efbd958c216485296acb79ec75e15a41c89305845e2c14f5",
            "302d71f5ab1a03938c4279b8fcc05fb5e12a71d0b0ec9d9c6aaa88fc4d0e4e7d",
            "c06b9a39dc0b65ec7a82a9ec71392ade019ea3745b3fe421939971a563f2d575",
            "7fc150411ebf20f03bf3c573d7c6de6f5ad6f64524b83ac47e6b739a6fb3c3ff",
            "3960ac4426f88c006289799a81e1ae9dbf8f8389357979f2c1415ec7c0654696",
            "e394c1e4229e9734893032512d10226580eacff8a4ad0794597fdab4032b3afb")).toMap()
        assertEquals(expectedSemantic, PreviewPins.semantic)
        assertEquals(expectedPhysical, PreviewPins.physical)
        assertThrows(UnsupportedOperationException::class.java) { (PreviewPins.semantic as MutableMap<String, String>)[PreviewPins.EXPANDED] = "0".repeat(64) }
        assertThrows(UnsupportedOperationException::class.java) { (PreviewPins.physical as MutableMap<String, String>).clear() }
    }

    @Test fun syntheticSpecMakesDefensiveCopiesAndRejectsInvalidSpecs() {
        val semantics = Fixture.semantic.toMutableMap()
        val encodings = Fixture.physical.toMutableMap()
        val roles = Fixture.roles.toMutableMap()
        val spec = PreviewSpec(semantics, encodings, roles)
        semantics.clear(); encodings.clear(); roles.clear()
        assertEquals(Fixture.semantic, spec.semantic)
        assertEquals(Fixture.physical, spec.physical)
        assertEquals(Fixture.roles, spec.roles)
        assertThrows(UnsupportedOperationException::class.java) { (spec.roles as MutableMap<String, PreviewRole>).clear() }
        reject { PreviewSpec(Fixture.semantic - Fixture.G, Fixture.physical, Fixture.roles) }
        reject { PreviewSpec(Fixture.semantic, Fixture.physical, emptyMap()) }
        reject { PreviewSpec(Fixture.semantic, Fixture.physical, mapOf("missing" to PreviewRole.EXPANDED)) }
        reject { PreviewSpec(Fixture.semantic + (Fixture.E to "bad"), Fixture.physical, Fixture.roles) }
    }

    @Test fun descriptorsAreFullyTokenizedAndRejectPartialOrVoidParameters() {
        for (key in PreviewPins.semantic.keys) {
            val d = PreviewExecution.descriptor(key)
            assertEquals(key, "${d.owner}->${d.name}(${d.parameters.joinToString("")})${d.result}")
        }
        assertEquals(listOf("[I", "[[Ljava/lang/String;", "J"),
            PreviewExecution.descriptor("Lfixture/A;->x([I[[Ljava/lang/String;J)V").parameters)
        for (key in listOf("Lx;->x(V)V", "Lx;->x(Ijunk)V", "Lx;->x()Vjunk", "Lx;->x()[V",
            "Lx;-><init>()I", "Lx;-><clinit>(I)V", "Lx;->x()", "garbage")) {
            reject { PreviewExecution.descriptor(key) }
        }
    }

    @Test fun independentFixedFixtureRowsAndPhysicalEncodingsMatchActualBuilders() {
        val methods = Fixture.methods()
        assertEquals(Fixture.rows, snapshots(methods))
        for (method in methods.filter { CandidateSnapshots.key(it) in Fixture.physical }) {
            val key = CandidateSnapshots.key(method)
            assertEquals(Fixture.physical.getValue(key), CandidateSnapshots.hash(CandidateSnapshots.original(method)))
        }
    }

    @Test fun actualPlanningAndMutationProduceOnlyIndependentThreeSiteOracle() {
        val methods = Fixture.methods()
        val before = snapshots(methods)
        val widths = methods.map { it.implementation!!.instructions.map { i -> i.codeUnits } }
        val expanded = PreviewEdits.plan(methods[0], Fixture.physical.getValue(Fixture.E), PreviewRole.EXPANDED)
        val collapsed = PreviewEdits.plan(methods[1], Fixture.physical.getValue(Fixture.C), PreviewRole.COLLAPSED)
        assertEquals(listOf(1, 7), expanded.map { it.index })
        assertEquals(listOf(4, 11), expanded.map { it.target })
        assertEquals(listOf(7), collapsed.map { it.index })
        execute(methods)
        val after = snapshots(methods)
        assertEquals(Fixture.expected(), after) // Never uses planRows/changed to calculate expected output.
        validate(before, after)
        assertEquals(widths, methods.map { it.implementation!!.instructions.map { i -> i.codeUnits } })
        assertEquals(3, before.keys.sumOf { key -> before.getValue(key).zip(after.getValue(key)).count { it.first != it.second } })
        val body = methods[0].implementation!!.instructions
        for ((source, target) in listOf(1 to 4, 7 to 11)) {
            assertEquals(Opcode.GOTO_16, body[source].opcode)
            assertEquals(body.take(target).sumOf { it.codeUnits },
                body.take(source).sumOf { it.codeUnits } + (body[source] as OffsetInstruction).codeOffset)
        }
        assertEquals(Opcode.IF_NEZ, body[8].opcode)
        assertEquals(Opcode.INVOKE_DIRECT, methods[1].implementation!!.instructions[8].opcode)
        assertEquals(32, 28 xor 60)
        for (bit in listOf(4, 8, 16)) assertEquals(28 and bit, 60 and bit)
    }

    @Test fun helperApplyAlsoMatchesIndependentOracleAndRejectsRepeat() {
        val cases: List<Triple<PreviewRole, () -> MutableMethod, String>> = listOf(
            Triple(PreviewRole.EXPANDED, Fixture::expanded, Fixture.E),
            Triple(PreviewRole.COLLAPSED, { Fixture.collapsed() }, Fixture.C))
        for ((role, create, key) in cases) {
            val method = create()
            val edits = PreviewEdits.plan(method, Fixture.physical.getValue(key), role)
            PreviewEdits.apply(method, edits)
            assertEquals(Fixture.expected().getValue(key), CandidateSnapshots.method(method))
            reject { PreviewEdits.plan(method, Fixture.physical.getValue(key), role) }
            reject { PreviewEdits.apply(method, edits) }
        }
        val methods = Fixture.methods()
        execute(methods)
        assertRejectedWithoutWrites(methods)
    }

    @Test fun absentAmbiguousAndWrongSelectorsFailBeforeMutation() {
        for (key in Fixture.physical.keys) {
            assertRejectedWithoutWrites(Fixture.methods().filter { CandidateSnapshots.key(it) != key })
            val methods = Fixture.methods()
            val duplicate = Fixture.methods().single { CandidateSnapshots.key(it) == key }
            assertRejectedWithoutWrites(methods + duplicate)
        }
        reject { PreviewEdits.only(listOf(Fixture.expanded()), "Lwrong;->x()V") }
        val unique = Fixture.expanded()
        assertSame(unique, PreviewEdits.only(listOf(unique), Fixture.E))
    }

    @Test fun everyOriginalOpcodeWidthAndMetadataDriftIsRejectedBeforeWrites() {
        for (methodIndex in 0..1) {
            val count = Fixture.methods()[methodIndex].implementation!!.instructions.size
            for (i in 0 until count) {
                val methods = Fixture.methods()
                methods[methodIndex].implementation!!.replaceInstruction(i, BuilderInstruction10x(Opcode.NOP))
                // A malformed payload/branch may itself fail snapshotting; either way no patch write occurs.
                reject { execute(methods) }
            }
            val flags = Fixture.methods().also { it[methodIndex].accessFlags = 1 }
            assertRejectedWithoutWrites(flags)
            val extra = Fixture.methods().also { it[methodIndex].implementation!!.addInstruction(0, BuilderInstruction10x(Opcode.NOP)) }
            assertRejectedWithoutWrites(extra)
            val tries = Fixture.methods().also {
                val b = it[methodIndex].implementation!!
                b.addCatch(b.newLabelForIndex(0), b.newLabelForIndex(1), b.newLabelForIndex(2))
            }
            assertRejectedWithoutWrites(tries)
            val regs = Fixture.methods().toMutableList()
            val old = regs[methodIndex]
            val body = old.implementation!!
            regs[methodIndex] = MutableMethod(ImmutableMethod(old.definingClass, old.name, old.parameters, old.returnType,
                old.accessFlags, old.annotations, old.hiddenApiRestrictions,
                ImmutableMethodImplementation(body.registerCount + 1, body.instructions, body.tryBlocks, body.debugItems)))
            assertRejectedWithoutWrites(regs)
        }
    }

    @Test fun normalizedSameSemanticButDifferentPhysicalWidthIsRejected() {
        val methods = Fixture.methods()
        val b = methods[0].implementation!!
        b.replaceInstruction(3, BuilderInstruction20t(Opcode.GOTO_16, b.newLabelForIndex(5)))
        assertEquals(Fixture.expandedRows, CandidateSnapshots.method(methods[0]))
        assertNotEquals(Fixture.physical.getValue(Fixture.E), CandidateSnapshots.hash(CandidateSnapshots.original(methods[0])))
        assertRejectedWithoutWrites(methods)
    }

    @Test fun sameWidthReferenceRegisterLiteralAndBranchDriftIsRejected() {
        val changes: List<(List<MutableMethod>) -> Unit> = listOf(
            { it[0].implementation!!.replaceInstruction(0, BuilderInstruction22c(Opcode.INSTANCE_OF, 8, 8, ImmutableTypeReference("Lwrong;"))) },
            { val b = it[0].implementation!!; b.replaceInstruction(1, BuilderInstruction21t(Opcode.IF_EQZ, 7, b.newLabelForIndex(4))) },
            { val b = it[0].implementation!!; b.replaceInstruction(1, BuilderInstruction21t(Opcode.IF_EQZ, 8, b.newLabelForIndex(5))) },
            { it[0].implementation!!.replaceInstruction(4, BuilderInstruction21ih(Opcode.CONST_HIGH16, 8, 0)) },
            { it[1].implementation!!.replaceInstruction(7, BuilderInstruction21s(Opcode.CONST_16, 7, 29)) },
            { it[1].implementation!!.replaceInstruction(8, Fixture.invoke(Opcode.INVOKE_DIRECT, listOf(2, 1, 3, 7), "Lwrong;", "<init>", listOf("Landroid/net/Uri;", "Lkt0;", "I"), "V")) },
            { val b = it[1].implementation!!; b.replaceInstruction(10, BuilderPackedSwitchPayload(5, listOf(b.newLabelForIndex(2)))) })
        for (change in changes) {
            val methods = Fixture.methods(); change(methods)
            assertRejectedWithoutWrites(methods)
        }
    }

    @Test fun lastGuardPinAndLastPlanFailureCannotPartiallyMutateFirstTarget() {
        val guardDrift = Fixture.methods().also { it[2].accessFlags = 1 }
        assertRejectedWithoutWrites(guardDrift) // Last pinned method fails after earlier pins passed.
        val methods = Fixture.methods().toMutableList().also { it[1] = Fixture.collapsed(mask = 29) }
        // Pin this deliberately malformed SYNTHETIC layout from fixed rows, never the live method.
        // Both pin passes succeed; the second plan must still reject before the first plan is applied.
        val malformedRows = Fixture.collapsedRows.toMutableList().also { it[10] = Fixture.row("CONST_16", "[7]", lit = "29") }
        val semantic = Fixture.semantic + (Fixture.C to CandidateSnapshots.hash(malformedRows))
        val physical = Fixture.physical + (Fixture.C to CandidateSnapshots.hash(malformedRows + Fixture.encodings.getValue(Fixture.C).map { "encoding=$it" }))
        assertRejectedWithoutWrites(methods, PreviewSpec(semantic, physical, Fixture.roles))
    }

    @Test fun structuralPlannerIndependentlyRejectsAmbiguousSitesAndWrongRoles() {
        for ((rows, role) in listOf(Fixture.expandedRows to PreviewRole.EXPANDED, Fixture.collapsedRows to PreviewRole.COLLAPSED)) {
            reject { PreviewEdits.planRows(rows, if (role == PreviewRole.EXPANDED) PreviewRole.COLLAPSED else PreviewRole.EXPANDED) }
        }
        reject { PreviewEdits.planRows(Fixture.expandedRows + Fixture.expandedRows[3], PreviewRole.EXPANDED) }
        val malformed = listOf(
            Fixture.expandedRows.toMutableList().also { it[4] = Fixture.row("IF_EQZ", "[8]", dest = "5") },
            Fixture.expandedRows.toMutableList().also { it[5] = Fixture.row("CONST_4", "[8]", lit = "1") },
            Fixture.expandedRows.toMutableList().also { it[11] = Fixture.row("IF_NEZ", "[20]", dest = "12") },
            Fixture.expandedRows.toMutableList().also { it[12] = Fixture.row("NOP") })
        for (rows in malformed) reject { PreviewEdits.planRows(rows, PreviewRole.EXPANDED) }
        val wrongCase = Fixture.collapsedRows.toMutableList().also { it[13] = Fixture.row("PACKED_SWITCH_PAYLOAD") + " switch=5:2" }
        reject { PreviewEdits.planRows(wrongCase, PreviewRole.COLLAPSED) }
    }

    @Test fun wholeMapAssertionRejectsNoopMissingAddedAndUnrelatedChanges() {
        val before = Fixture.rows
        val after = Fixture.expected()
        validate(before, after)
        reject { validate(before, before) }
        reject { validate(after, after) }
        for (key in before.keys) reject { validate(before, after - key) }
        for (key in Fixture.semantic.keys) reject { validate(before - key, after - key) }
        reject { validate(before, after + ("Lother;->x()V" to Fixture.guardRows)) }
        reject { validate(before, after + (Fixture.G to listOf("changed"))) }
        reject { validate(before, after + (Fixture.E to (after.getValue(Fixture.E) + "extra"))) }
        for (key in Fixture.semantic.keys) for (i in before.getValue(key).indices) {
            val changed = before.getValue(key).toMutableList().also { it[i] += " drift" }
            reject { validate(before + (key to changed), after) }
        }
        for (key in after.keys) for (i in after.getValue(key).indices) {
            val changed = after.getValue(key).toMutableList().also { it[i] += " extra" }
            reject { validate(before, after + (key to changed)) }
        }
    }

    @Test fun syntheticSignInRefreshSignOutAndReauthenticationSentinelsRemainByteForByteUntouched() {
        val methods = Fixture.methods()
        val sentinels = methods.filter { CandidateSnapshots.key(it) in Fixture.sessionRows }
        val before = physical(sentinels)
        assertEquals(Fixture.sessionRows, snapshots(sentinels))
        execute(methods)
        assertEquals(before, physical(sentinels))
        val after = snapshots(methods)
        validate(Fixture.rows, after)
        // These are not pinned preview methods, so rejection demonstrates full-map preservation.
        for (key in Fixture.sessionRows.keys) {
            val tampered = after.getValue(key).toMutableList().also { it[3] = Fixture.row("CONST_16", "[0]", lit = "999") }
            reject { validate(Fixture.rows, after + (key to tampered)) }
        }
    }

    @Test fun productionStaticAdapterRejectsSyntheticInputsWithoutProductionPinOverride() {
        val verify = PreviewAssertions::class.java.getDeclaredMethod("verify", Map::class.java, Map::class.java)
        assertTrue(Modifier.isStatic(verify.modifiers))
        assertEquals(Void.TYPE, verify.returnType)
        reject { PreviewAssertions.verify(Fixture.rows, Fixture.expected()) }
        reject { PreviewAssertions.verify(emptyMap(), emptyMap()) }
    }
}

/** Test-only fixed oracle and independently authored mutable methods; never in the production MPP. */
private object Fixture {
    const val E = "Lpreviewfixture/Home;->expanded()V"
    const val C = "Lpreviewfixture/Home;->collapsed()V"
    const val G = "Lpreviewfixture/Home;->guard()V"
    fun row(op: String, regs: String = "[]", ref: String = "null", lit: String = "null", dest: String = "null") =
        "$op $regs ref=$ref ref2=null literal=$lit target=$dest"
    val expandedRows = listOf("flags=9 hidden=[] annotations=[]", "parameters=", "registers=30",
        row("INSTANCE_OF", "[8, 8]", "Lhde;"), row("IF_EQZ", "[8]", dest = "4"),
        row("CONST_4", "[8]", lit = "0"), row("GOTO", dest = "5"), row("CONST_HIGH16", "[8]", lit = "1065353216"),
        row("CONST_16", "[13]", lit = "1000"), row("CHECK_CAST", "[0]", "Ljava/lang/String;"),
        row("IF_EQZ", "[0]", dest = "11"), row("IF_NEZ", "[20]", dest = "11"),
        row("INVOKE_STATIC", ref = "Lqh6;->q()V"), row("GOTO", dest = "19"),
        row("MOVE_OBJECT", "[0, 4]"), row("MOVE", "[3, 5]"), row("MOVE_FROM16", "[17, 12]"),
        row("MOVE_WIDE", "[1, 13]"), row("MOVE_OBJECT", "[14, 7]"), row("CONST", "[4]", lit = "880077519"),
        row("INVOKE_VIRTUAL", "[14, 4]", "Lsx5;->Z(I)V"), row("INVOKE_VIRTUAL", "[14, 3]", "Lsx5;->q(Z)V"),
        row("INVOKE_STATIC", "[14]", "Lz24;->c(Lsx5;)Lab4;"), row("RETURN_VOID"))
    val collapsedRows = listOf("flags=9 hidden=[] annotations=[]", "parameters=", "registers=19",
        row("PACKED_SWITCH", "[1]", dest = "10"), row("RETURN_VOID"), row("CHECK_CAST", "[7]", "Ltx8;"),
        row("NEW_INSTANCE", "[2]", "Lct0;"), row("CHECK_CAST", "[1]", "La66;"),
        row("IGET_OBJECT", "[1, 1]", "La66;->a:Landroid/net/Uri;"), row("SGET_OBJECT", "[3]", "Lkt0;->u:Lkt0;"),
        row("CONST_16", "[7]", lit = "28"), row("INVOKE_DIRECT", "[2, 1, 3, 7]", "Lct0;-><init>(Landroid/net/Uri;Lkt0;I)V"),
        row("RETURN_VOID"), row("PACKED_SWITCH_PAYLOAD") + " switch=6:2")
    val guardRows = listOf("flags=9 hidden=[] annotations=[]", "parameters=", "registers=0", row("RETURN_VOID"))
    // Inert, independently authored auth/session labels: no real auth logic or credentials.
    private val sessions = linkedMapOf("signIn" to 101, "tokenRefresh" to 202, "signOut" to 303, "reauthenticate" to 404)
    val sessionRows = sessions.mapKeys { "Lpreviewfixture/Session;->${it.key}()I" }.mapValues { (_, value) ->
        listOf("flags=9 hidden=[] annotations=[]", "parameters=", "registers=1", row("CONST_16", "[0]", lit = "$value"), row("RETURN", "[0]"))
    }
    val rows = linkedMapOf(E to expandedRows, C to collapsedRows, G to guardRows) + sessionRows
    val encodings = mapOf(
        E to listOf("INSTANCE_OF:2", "IF_EQZ:2", "CONST_4:1", "GOTO:1", "CONST_HIGH16:2", "CONST_16:2", "CHECK_CAST:2", "IF_EQZ:2", "IF_NEZ:2", "INVOKE_STATIC:3", "GOTO:1", "MOVE_OBJECT:1", "MOVE:1", "MOVE_FROM16:2", "MOVE_WIDE:1", "MOVE_OBJECT:1", "CONST:3", "INVOKE_VIRTUAL:3", "INVOKE_VIRTUAL:3", "INVOKE_STATIC:3", "RETURN_VOID:1"),
        C to listOf("PACKED_SWITCH:3", "RETURN_VOID:1", "CHECK_CAST:2", "NEW_INSTANCE:2", "CHECK_CAST:2", "IGET_OBJECT:2", "SGET_OBJECT:2", "CONST_16:2", "INVOKE_DIRECT:3", "RETURN_VOID:1", "PACKED_SWITCH_PAYLOAD:6"),
        G to listOf("RETURN_VOID:1"))
    private val pinnedRows = rows.filterKeys { it in encodings }
    val semantic = pinnedRows.mapValues { CandidateSnapshots.hash(it.value) }
    val physical = pinnedRows.mapValues { (key, value) -> CandidateSnapshots.hash(value + encodings.getValue(key).map { "encoding=$it" }) }
    val roles = linkedMapOf(E to PreviewRole.EXPANDED, C to PreviewRole.COLLAPSED)
    val spec = PreviewSpec(semantic, physical, roles)
    // Independent expected output: fixed fixture positions, not the planner or its changed helper.
    fun expected() = rows + mapOf(
        E to expandedRows.toMutableList().also { it[4] = row("GOTO", dest = "4"); it[10] = row("GOTO", dest = "11") },
        C to collapsedRows.toMutableList().also { it[10] = row("CONST_16", "[7]", lit = "60") })

    private fun method(name: String, b: MethodImplementationBuilder, owner: String = "Lpreviewfixture/Home;", result: String = "V") =
        MutableMethod(ImmutableMethod(owner, name, emptyList(), result, 9, emptySet(), emptySet(), b.methodImplementation))
    fun invoke(op: Opcode, regs: List<Int>, owner: String, name: String, args: List<String>, ret: String): BuilderInstruction {
        val r = regs + List(5 - regs.size) { 0 }
        return BuilderInstruction35c(op, regs.size, r[0], r[1], r[2], r[3], r[4], ImmutableMethodReference(owner, name, args, ret))
    }
    fun expanded(): MutableMethod {
        val b = MethodImplementationBuilder(30)
        b.addInstruction(BuilderInstruction22c(Opcode.INSTANCE_OF, 8, 8, ImmutableTypeReference("Lhde;")))
        b.addInstruction(BuilderInstruction21t(Opcode.IF_EQZ, 8, b.getLabel("opaque")))
        b.addInstruction(BuilderInstruction11n(Opcode.CONST_4, 8, 0))
        b.addInstruction(BuilderInstruction10t(Opcode.GOTO, b.getLabel("after")))
        b.addLabel("opaque"); b.addInstruction(BuilderInstruction21ih(Opcode.CONST_HIGH16, 8, 1065353216))
        b.addLabel("after"); b.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 13, 1000))
        b.addInstruction(BuilderInstruction21c(Opcode.CHECK_CAST, 0, ImmutableTypeReference("Ljava/lang/String;")))
        b.addInstruction(BuilderInstruction21t(Opcode.IF_EQZ, 0, b.getLabel("alternate")))
        b.addInstruction(BuilderInstruction21t(Opcode.IF_NEZ, 20, b.getLabel("alternate")))
        b.addInstruction(invoke(Opcode.INVOKE_STATIC, emptyList(), "Lqh6;", "q", emptyList(), "V"))
        b.addInstruction(BuilderInstruction10t(Opcode.GOTO, b.getLabel("tail")))
        b.addLabel("alternate")
        b.addInstruction(BuilderInstruction12x(Opcode.MOVE_OBJECT, 0, 4))
        b.addInstruction(BuilderInstruction12x(Opcode.MOVE, 3, 5))
        b.addInstruction(BuilderInstruction22x(Opcode.MOVE_FROM16, 17, 12))
        b.addInstruction(BuilderInstruction12x(Opcode.MOVE_WIDE, 1, 13))
        b.addInstruction(BuilderInstruction12x(Opcode.MOVE_OBJECT, 14, 7))
        b.addInstruction(BuilderInstruction31i(Opcode.CONST, 4, 880077519))
        b.addInstruction(invoke(Opcode.INVOKE_VIRTUAL, listOf(14, 4), "Lsx5;", "Z", listOf("I"), "V"))
        b.addInstruction(invoke(Opcode.INVOKE_VIRTUAL, listOf(14, 3), "Lsx5;", "q", listOf("Z"), "V"))
        b.addLabel("tail")
        b.addInstruction(invoke(Opcode.INVOKE_STATIC, listOf(14), "Lz24;", "c", listOf("Lsx5;"), "Lab4;"))
        b.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
        return method("expanded", b)
    }
    fun collapsed(mask: Int = 28): MutableMethod {
        val b = MethodImplementationBuilder(19)
        b.addInstruction(BuilderInstruction31t(Opcode.PACKED_SWITCH, 1, b.getLabel("payload")))
        b.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
        b.addLabel("home"); b.addInstruction(BuilderInstruction21c(Opcode.CHECK_CAST, 7, ImmutableTypeReference("Ltx8;")))
        b.addInstruction(BuilderInstruction21c(Opcode.NEW_INSTANCE, 2, ImmutableTypeReference("Lct0;")))
        b.addInstruction(BuilderInstruction21c(Opcode.CHECK_CAST, 1, ImmutableTypeReference("La66;")))
        b.addInstruction(BuilderInstruction22c(Opcode.IGET_OBJECT, 1, 1, ImmutableFieldReference("La66;", "a", "Landroid/net/Uri;")))
        b.addInstruction(BuilderInstruction21c(Opcode.SGET_OBJECT, 3, ImmutableFieldReference("Lkt0;", "u", "Lkt0;")))
        b.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 7, mask))
        b.addInstruction(invoke(Opcode.INVOKE_DIRECT, listOf(2, 1, 3, 7), "Lct0;", "<init>", listOf("Landroid/net/Uri;", "Lkt0;", "I"), "V"))
        b.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID))
        b.addLabel("payload"); b.addInstruction(BuilderPackedSwitchPayload(6, listOf(b.getLabel("home"))))
        return method("collapsed", b)
    }
    fun methods(): List<MutableMethod> {
        val guard = MethodImplementationBuilder(0).also { it.addInstruction(BuilderInstruction10x(Opcode.RETURN_VOID)) }
        return listOf(expanded(), collapsed(), method("guard", guard)) + sessions.map { (name, value) ->
            val b = MethodImplementationBuilder(1)
            b.addInstruction(BuilderInstruction21s(Opcode.CONST_16, 0, value))
            b.addInstruction(BuilderInstruction11x(Opcode.RETURN, 0))
            method(name, b, "Lpreviewfixture/Session;", "I")
        }
    }
}
