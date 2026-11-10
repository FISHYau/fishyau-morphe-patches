package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.Fingerprint
import app.morphe.patcher.methodCall
import com.android.tools.smali.dexlib2.AccessFlags

/**
 * Termius 8.0.1: classes4.dex, cm/c.c(String):UserType, private final.
 * Match stable account accessor calls instead of the obfuscated class name.
 * Resolution is exhaustive and must find exactly one method before mutation.
 */
internal object UserTypeMapperFingerprint : Fingerprint(
    returnType = "Lcom/server/auditor/ssh/client/models/UserType;",
    accessFlags = listOf(AccessFlags.PRIVATE, AccessFlags.FINAL),
    parameters = listOf("Ljava/lang/String;"),
    filters = listOf(
        methodCall(
            definingClass = "Lcom/server/auditor/ssh/client/models/account/AccountAccessObject;",
            name = "getSubscriptionTitle",
            returnType = "Ljava/lang/String;",
            parameters = listOf(),
        ),
        methodCall(
            definingClass = "Lcom/server/auditor/ssh/client/models/account/AccountAccessObject;",
            name = "getSubscriptionPeriod",
            returnType = "Lcom/server/auditor/ssh/client/models/account/AccountSubscriptionPeriod;",
            parameters = listOf(),
        ),
    ),
)

/** Preflight-only target: validate the constructor before emitting an invocation. */
internal object ProConstructorFingerprint : Fingerprint(
    definingClass = USER_TYPE_PRO,
    name = "<init>",
    returnType = "V",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.CONSTRUCTOR),
    parameters = listOf(
        "Ljava/lang/String;",
        "Z",
        "Lcom/server/auditor/ssh/client/models/SubscriptionPeriod;",
    ),
)

/**
 * Exact 8.0.1 storage getter, intentionally not the similarly shaped auth getter r0().
 * Body validation additionally requires the Pro LiveData field d rather than auth field e.
 * Do not filter on the original body here: preflight must diagnose partial/repeat patches.
 */
internal object StorageProModeFingerprint : Fingerprint(
    definingClass = "Lcom/server/auditor/ssh/client/app/a;",
    name = "u0",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC),
    parameters = listOf(),
)

/** Locate independently of original instructions, so preflight catches partial/repeat inputs. */
internal object OfflineSnippetWidgetFingerprint : Fingerprint(
    definingClass = SNIPPET_WIDGET,
    name = "setState",
    returnType = "V",
    parameters = listOf("Lbs/h;"),
)

internal object OfflineSshAutomationFingerprint : Fingerprint(
    definingClass = "Lci/w;",
    name = "vb",
    returnType = "V",
    parameters = listOf(),
)

internal object OfflineTerminalAutomationFingerprint : Fingerprint(
    definingClass = TERMINAL_MANAGER,
    name = "startConnection",
    returnType = "I",
    parameters = listOf("Lcom/server/auditor/ssh/client/models/connections/Connection;", "Z"),
)

/** Termius 8.0.1: classes3.dex, public final Pro.isExpired():boolean. */
internal object ProSubscriptionExpiredFingerprint : Fingerprint(
    definingClass = USER_TYPE_PRO,
    name = "isExpired",
    returnType = "Z",
    accessFlags = listOf(AccessFlags.PUBLIC, AccessFlags.FINAL),
    parameters = listOf(),
)
