package io.github.fishyau.androidpatches.termius

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility

// Extracted without target changes from the donor shared/Constants.kt.
internal val SERVER_AUDITOR_COMPATIBILITY = Compatibility(
        name = "Server Auditor",
        packageName = "com.server.auditor.ssh.client",
        apkFileType = ApkFileType.APKM,
        appIconColor = 0x1A73E8,
        targets = listOf(AppTarget(version = "8.0.1", versionCode = 1008))
    )
