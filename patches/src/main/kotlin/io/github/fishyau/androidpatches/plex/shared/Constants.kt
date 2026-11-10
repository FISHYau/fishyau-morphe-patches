/*
 * Derived from UnkyBadTouch/plex-morphe-patches, revision
 * 38f05e52d57bdc68c55f9ca6ae0b0c7b1d08b06f. GPL-3.0; see LICENSE and NOTICE.
 * Modified 2026-11-09 for FISHYau android patches: namespace relocation and
 * provenance notice; PremiumUnlockPatch.kt also narrows the description only.
 * No warranty. See docs/plex-migration.json for the exact migration record.
 */
package io.github.fishyau.androidpatches.plex.shared

import app.morphe.patcher.patch.ApkFileType
import app.morphe.patcher.patch.Compatibility

object Constants {
    val COMPATIBILITY_PLEX = Compatibility(
        name = "Plex",
        packageName = "com.plexapp.android",
        apkFileType = ApkFileType.APKM,
        // Plex icon: dark charcoal background.
        appIconColor = 0x282A2D,
        // No version pin: the Premium unlock patch finds the Plex Pass checks by
        // signature, so it is not tied to a particular build. Compatibility defaults
        // to any version, and the patch fails with its own message if the bytecode
        // ever changes shape.
    )
}
