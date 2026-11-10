package io.github.fishyau.androidpatches.termius

internal const val SNIPPET_WIDGET = "Lcom/server/auditor/ssh/client/widget/editors/SnippetEditorLayout;"
internal const val TERMINAL_MANAGER = "Lcom/crystalnix/termius/libtermius/wrappers/TerminalConnectionManager;"
private const val STORAGE = "Lcom/server/auditor/ssh/client/app/a;"
private const val CONNECTION = "Lcom/server/auditor/ssh/client/models/connections/Connection;"
private const val PROPERTIES = "Lcom/server/auditor/ssh/client/models/properties/ConnectionProperties;"
private const val SNIPPET = "Lcom/server/auditor/ssh/client/models/SnippetItem;"
private const val SESSION = "Lcom/crystalnix/termius/libtermius/wrappers/SessionManager;"

/** Exact 8.0.1 shapes. Opcodes fix instruction widths; branches use absolute code units. */
internal object OfflineAutomationValidation {
    private fun i(op: String, vararg regs: Int, ref: String? = null, lit: Long? = null, target: Int? = null) =
        ProModeInstruction(op, regs.toList(), ref, lit, target)

    internal val widget = listOf(
        i("CONST_STRING", 0, ref = "state"),
        i("INVOKE_STATIC", 2, 0, ref = "Lkotlin/jvm/internal/t;->g(Ljava/lang/Object;Ljava/lang/String;)V"),
        i("INSTANCE_OF", 0, 2, ref = "Lbs/h\$a;"),
        i("IF_EQZ", 0, target = 0x0d),
        i("INVOKE_DIRECT", 1, ref = "$SNIPPET_WIDGET->F()V"),
        i("RETURN_VOID"),
        i("INSTANCE_OF", 0, 2, ref = "Lbs/h\$b;"),
        i("IF_EQZ", 0, target = 0x15),
        i("INVOKE_DIRECT", 1, ref = "$SNIPPET_WIDGET->J()V"),
        i("RETURN_VOID"),
        i("INSTANCE_OF", 2, 2, ref = "Lbs/h\$c;"),
        i("IF_EQZ", 2, target = 0x1d),
        i("INVOKE_DIRECT", 1, ref = "$SNIPPET_WIDGET->N()V"),
        i("RETURN_VOID"),
        i("NEW_INSTANCE", 2, ref = "Lht/s;"),
        i("INVOKE_DIRECT", 2, ref = "Lht/s;-><init>()V"),
        i("THROW", 2),
    )
    internal val ssh = listOf(
        i("INVOKE_VIRTUAL", 2, ref = "Lci/c;->z1()Lih/m0;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("IGET_OBJECT", 0, 0, ref = "Lih/m0;->z:$SNIPPET_WIDGET"),
        i("INVOKE_DIRECT", 2, ref = "Lci/w;->rb()Lcom/server/auditor/ssh/client/widget/editors/SnippetEditorLayout\$c;"),
        i("MOVE_RESULT_OBJECT", 1),
        i("INVOKE_VIRTUAL", 0, 1, ref = "$SNIPPET_WIDGET->setOnSnippetEditorCallback(Lcom/server/auditor/ssh/client/widget/editors/SnippetEditorLayout\$c;)V"),
        i("INVOKE_VIRTUAL", 2, ref = "Lci/c;->g3()Ljava/util/ArrayList;"),
        i("MOVE_RESULT_OBJECT", 1),
        i("INVOKE_VIRTUAL", 1, 0, ref = "Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z"),
        i("INVOKE_STATIC", ref = "$STORAGE->N()$STORAGE"),
        i("MOVE_RESULT_OBJECT", 1),
        i("INVOKE_VIRTUAL", 1, ref = "$STORAGE->u0()Z"),
        i("MOVE_RESULT", 1),
        i("IF_NEZ", 1, target = 0x26),
        i("NEW_INSTANCE", 1, ref = "Lci/p;"),
        i("INVOKE_DIRECT", 1, ref = "Lci/p;-><init>()V"),
        i("INVOKE_VIRTUAL", 0, 1, ref = "Landroid/view/View;->setOnClickListener(Landroid/view/View\$OnClickListener;)V"),
        i("RETURN_VOID"),
    )
    internal val terminal = listOf(
        i("INVOKE_STATIC", ref = "Lcom/server/auditor/ssh/client/app/TermiusApplication;->G()Landroid/content/Context;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("INVOKE_VIRTUAL", 0, ref = "Landroid/content/Context;->getResources()Landroid/content/res/Resources;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("INVOKE_VIRTUAL", 0, ref = "Landroid/content/res/Resources;->getDisplayMetrics()Landroid/util/DisplayMetrics;"),
        i("MOVE_RESULT_OBJECT", 1),
        i("INVOKE_INTERFACE", 10, ref = "$CONNECTION->getId()J"),
        i("MOVE_RESULT_WIDE", 2),
        i("LONG_TO_INT", 7, 2),
        i("INVOKE_STATIC", ref = "$SESSION->getInstance()$SESSION"),
        i("MOVE_RESULT_OBJECT", 10),
        i("INVOKE_VIRTUAL", 10, 7, ref = "$SESSION->getActiveConnection(I)Lcom/server/auditor/ssh/client/models/ActiveConnection;"),
        i("MOVE_RESULT_OBJECT", 5),
        i("IF_EQZ", 5, target = 0x9a),
        i("NEW_INSTANCE", 6, ref = "Lfn/b;"),
        i("INVOKE_STATIC", ref = "$STORAGE->N()$STORAGE"),
        i("MOVE_RESULT_OBJECT", 10),
        i("INVOKE_VIRTUAL", 10, ref = "$STORAGE->M()Lzg/d;"),
        i("MOVE_RESULT_OBJECT", 10),
        i("INVOKE_VIRTUAL", 0, ref = "Landroid/content/res/Resources;->getAssets()Landroid/content/res/AssetManager;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("IGET", 1, 1, ref = "Landroid/util/DisplayMetrics;->scaledDensity:F"),
        i("INVOKE_DIRECT", 6, 10, 0, 5, 1, ref = "Lfn/b;-><init>(Lzg/d;Landroid/content/res/AssetManager;Lcom/server/auditor/ssh/client/models/connections/Connection;F)V"),
        i("INVOKE_VIRTUAL", 6, ref = "Lfn/b;->j()Ljava/lang/String;"),
        i("MOVE_RESULT_OBJECT", 10),
        i("INVOKE_INTERFACE", 5, 10, ref = "$CONNECTION->setColorScheme(Ljava/lang/String;)V"),
        i("CONST_4", 10, lit = 0),
        i("IF_NEZ", 11, target = 0x6e),
        i("INVOKE_STATIC", ref = "$STORAGE->N()$STORAGE"),
        i("MOVE_RESULT_OBJECT", 0),
        i("INVOKE_VIRTUAL", 0, ref = "$STORAGE->u0()Z"),
        i("MOVE_RESULT", 0),
        i("IF_NEZ", 0, target = 0x6e),
        i("INVOKE_INTERFACE", 5, ref = "$CONNECTION->getSshProperties()Lcom/server/auditor/ssh/client/models/properties/SshProperties;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("IF_EQZ", 0, target = 0x5f),
        i("INVOKE_VIRTUAL", 0, ref = "$PROPERTIES->getStartupSnippet()$SNIPPET"),
        i("MOVE_RESULT_OBJECT", 1),
        i("IF_EQZ", 1, target = 0x5f),
        i("INVOKE_VIRTUAL", 0, ref = "$PROPERTIES->getStartupSnippet()$SNIPPET"),
        i("MOVE_RESULT_OBJECT", 1),
        i("INVOKE_VIRTUAL", 1, ref = "$SNIPPET->getId()J"),
        i("MOVE_RESULT_WIDE", 1),
        i("CONST_WIDE_16", 3, lit = -1),
        i("CMP_LONG", 1, 1, 3),
        i("IF_EQZ", 1, target = 0x5f),
        i("INVOKE_VIRTUAL", 0, 10, ref = "$PROPERTIES->setStartupSnippet($SNIPPET)V"),
        i("INVOKE_INTERFACE", 5, ref = "$CONNECTION->getLocalProperties()Lcom/server/auditor/ssh/client/models/properties/LocalProperties;"),
        i("MOVE_RESULT_OBJECT", 0),
        i("IF_EQZ", 0, target = 0x6e),
        i("INVOKE_VIRTUAL", 0, ref = "$PROPERTIES->getStartupSnippet()$SNIPPET"),
        i("MOVE_RESULT_OBJECT", 1),
        i("IF_EQZ", 1, target = 0x6e),
        i("INVOKE_VIRTUAL", 0, 10, ref = "$PROPERTIES->setStartupSnippet($SNIPPET)V"),
        i("INVOKE_STATIC", ref = "$SESSION->getInstance()$SESSION"),
        i("MOVE_RESULT_OBJECT", 4),
        i("NEW_INSTANCE", 8, ref = "Lcom/crystalnix/termius/libtermius/wrappers/TerminalConnectionManager\$SessionCreatedListener;"),
        i("INVOKE_DIRECT", 8, 7, 11, 10, ref = "Lcom/crystalnix/termius/libtermius/wrappers/TerminalConnectionManager\$SessionCreatedListener;-><init>(IZLcom/crystalnix/termius/libtermius/wrappers/y;)V"),
        i("MOVE", 9, 11),
        i("INVOKE_VIRTUAL_RANGE", 4, 5, 6, 7, 8, 9, ref = "$SESSION->connectTerminalSession(Lcom/server/auditor/ssh/client/models/connections/Connection;Lfn/b;ILqm/b;Z)V"),
        i("INVOKE_INTERFACE", 5, ref = "$CONNECTION->getSshProperties()Lcom/server/auditor/ssh/client/models/properties/SshProperties;"),
        i("MOVE_RESULT_OBJECT", 10),
        i("IF_EQZ", 10, target = 0x9a),
        i("INVOKE_INTERFACE", 5, ref = "$CONNECTION->getSshProperties()Lcom/server/auditor/ssh/client/models/properties/SshProperties;"),
        i("MOVE_RESULT_OBJECT", 10),
        i("INVOKE_VIRTUAL", 10, ref = "$PROPERTIES->getStartupSnippet()$SNIPPET"),
        i("MOVE_RESULT_OBJECT", 10),
        i("IF_EQZ", 10, target = 0x9a),
        i("NEW_INSTANCE", 10, ref = "Lsm/f;"),
        i("INVOKE_DIRECT", 10, ref = "Lsm/f;-><init>()V"),
        i("INVOKE_VIRTUAL", 10, 7, ref = "Lsm/f;->c(I)V"),
        i("INVOKE_STATIC", ref = "$SESSION->getInstance()$SESSION"),
        i("MOVE_RESULT_OBJECT", 11),
        i("INVOKE_VIRTUAL", 11, 7, 10, ref = "$SESSION->putSnippetExecutionResult(ILsm/f;)V"),
        i("RETURN", 7),
    )

    internal fun expected(target: String): List<ProModeInstruction> = when (target) {
        "snippet widget" -> widget
        "SSH Automation" -> ssh
        "terminal Automation" -> terminal
        else -> error("Unknown Automation target $target")
    }

    fun requireLayout(target: String, registers: Int, flags: Int, tries: Int, body: List<ProModeInstruction>) {
        val expectedRegisters = if (target == "terminal Automation") 12 else 3
        val expectedFlags = when (target) {
            "SSH Automation" -> 0x12 // private final instance method
            "terminal Automation" -> 0x0a // private static; connection/z are v10/v11
            else -> 0x1 // public instance widget method
        }
        check(registers == expectedRegisters && flags == expectedFlags && tries == 0) {
            "Unsupported Termius $target registers, flags, or exception handlers."
        }
        val original = expected(target)
        val edit = when (target) { "snippet widget" -> 4; "SSH Automation" -> 12; else -> 31 }
        val patched = if (target == "snippet widget") body.getOrNull(edit)?.reference == "$SNIPPET_WIDGET->N()V"
            else body.getOrNull(edit)?.opcode == "CONST_4"
        check(!patched) { "Termius $target is already patched." }
        check(body == original) { "Unsupported Termius $target body; expected original 8.0.1 operands and control flow." }
    }
}
