package io.github.fishyau.androidpatches.spotify

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.AppTarget
import app.morphe.patcher.patch.Compatibility
import app.morphe.patcher.patch.FormFactor

internal val SPOTIFY_TV_COMPATIBILITY = Compatibility(
    name = "Spotify TV",
    packageName = "com.spotify.tv.android",
    apkFileType = ApkFileType.APKM_REQUIRED,
    formFactor = FormFactor.TV,
    targets = listOf(AppTarget(version = "9.1.94.1926", versionCode = 147600562)),
)
