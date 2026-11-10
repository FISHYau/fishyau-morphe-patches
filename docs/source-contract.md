# Morphe source compatibility

Reference snapshot: patches `8fa2c7a1a832498de8f179748998a3ca87e198eb`; Manager `6bd844d99ef9a13fcae08b68742662ff5bd19f83`. Compatibility can change; test the actual target Manager version before releasing.

## Discovery

For a short GitHub repository URL, Manager constructs `https://raw.githubusercontent.com/OWNER/REPO/main/patches-bundle.json`. Thus the short URL needs `main` even if another branch is the repository default. Explicit HTTPS JSON endpoints are also supported. Ordinary sources use this manifest, not a scan of arbitrary GitHub release assets.

This collection’s intended repository is **`FISHYau/fishyau-morphe-patches`**, so its ordinary endpoint is `https://raw.githubusercontent.com/FISHYau/fishyau-morphe-patches/main/patches-bundle.json`. Initial version **0.1.0** should advertise `https://github.com/FISHYau/fishyau-morphe-patches/releases/download/v0.1.0/patches-0.1.0.mpp` only after those exact verified bytes are available. These are target URLs, not a claim of existing hosting or a successful remote import.

The Manager `ReleaseAsset` DTO requires strings `version`, `download_url`, `created_at`, `description`. Optional nullable fields: `public_key`, `page_url`. The timestamp represents UTC but is parsed with Java `LocalDateTime.parse`: emit a local ISO date/time without `Z` or a numeric offset. `signature_download_url` in some upstream manifests is not required by this ordinary-source DTO.

There is no mandatory root `patches.json`. `patches-list.json` is a generated compatibility/options catalog, not the source-update manifest. The MPP's internal metadata/patch definitions are a third, separate concern.

## Bundle

Build Android-loadable `.mpp` with the official plugin's `buildAndroid`, not a renamed JVM JAR. Manager checks the bundle and uses its `Patcher-Version` metadata. The scaffold follows plugin 2.1.0 / patcher 2.3.0, Gradle 9.8.2, JDK 21 and JVM 17 target. These are reference versions, not a claim about minimum supported versions.

About identity must be `FISHYau android patches`, author `FISHYau`, with collection-specific source/support links when actual hosting is configured. Do not retain donor branding or template version 1.23.1.

Signing is optional for a source with no pinned key. Advertised/pinned keys must match the signed bundle; an unsigned artifact must not advertise a key. Initial release preparation supports unsigned artifacts only unless actual signing verification has been implemented and reviewed.

## Stable update safety

Both main/dev manifests can participate in channel selection. Do not expose unverified candidates through either manifest. Upload and validate the exact approved MPP before advancing the stable manifest; never rebuild during publication and silently inherit approval.

No live discovery manifest is committed until an actual verified release exists. Schema/fixture tests do not prove remote add-source, download, loading or update behavior. Those are separately recorded end-to-end checks after authorized hosting.

## References

- https://github.com/MorpheApp/morphe-patches-template
- https://github.com/MorpheApp/morphe-patches/tree/8fa2c7a1a832498de8f179748998a3ca87e198eb
- https://github.com/MorpheApp/morphe-manager/blob/6bd844d99ef9a13fcae08b68742662ff5bd19f83/app/src/main/java/app/morphe/manager/network/dto/ReleaseAsset.kt
- https://github.com/MorpheApp/morphe-manager/blob/6bd844d99ef9a13fcae08b68742662ff5bd19f83/app/src/main/java/app/morphe/manager/domain/repository/PatchBundleRepository.kt
- https://github.com/MorpheApp/morphe-manager/blob/6bd844d99ef9a13fcae08b68742662ff5bd19f83/app/src/main/java/app/morphe/manager/domain/bundles/RemotePatchBundle.kt
