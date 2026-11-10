// Adapted from MorpheApp/morphe-patches-template (2026-11-08).
group = "io.github.fishyau.androidpatches"

val publicationRepository = providers.gradleProperty("publicationRepository").orElse("FISHYau/fishyau-morphe-patches")
val configuredRepository = publicationRepository.get()
require(configuredRepository.matches(Regex("[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9][A-Za-z0-9_.-]*"))) {
    "publicationRepository must be an explicit GitHub OWNER/REPO"
}

patches {
    about {
        name = "FISHYau android patches"
        description = "Independent Android patches compatible with Morphe"
        source = "https://github.com/$configuredRepository"
        author = "FISHYau"
        contact = ""
        website = "https://github.com/$configuredRepository"
        license = "GPLv3"
    }
}

java {
    toolchain.languageVersion.set(JavaLanguageVersion.of(21))
    sourceCompatibility = JavaVersion.VERSION_17
    targetCompatibility = JavaVersion.VERSION_17
}
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }

// Isolated adapter classes: the actual loader uses a parent-first URLClassLoader.
// Putting main patch classes on JavaExec's classpath would silently inspect those
// rather than the explicitly selected (possibly older) MPP's definitions.
val catalogTool = sourceSets.create("catalogTool")
kotlin.sourceSets.named("catalogTool") {
    kotlin.srcDir("src/main/kotlin/io/github/fishyau/androidpatches/tools")
}
kotlin.sourceSets.named("main") {
    kotlin.exclude("io/github/fishyau/androidpatches/tools/**")
}
dependencies {
    add(catalogTool.implementationConfigurationName, libs.morphe.patcher)
    add(catalogTool.implementationConfigurationName, libs.gson)
    testImplementation(libs.junit)
    testImplementation(libs.morphe.patcher)
    testImplementation(libs.arsclib)
    testImplementation(libs.gson)
    testImplementation(catalogTool.output)
}

// Prepare the tools-only adapter during the separately authorized build/test phase.
// It is excluded from main and therefore from the distributable patch definitions.
tasks.matching { it.name == "buildAndroid" || it.name == "test" }.configureEach {
    dependsOn(catalogTool.classesTaskName)
}

tasks.register<JavaExec>("generatePatchesList") {
    description = "Catalog an exact existing MPP using an already compiled isolated adapter; no build"
    // Snapshot plain File paths, NOT SourceSetOutput/runtimeClasspath task metadata.
    // Neither an explicit nor an implicit classes/buildAndroid edge belongs here.
    classpath = files(catalogTool.output.files, configurations[catalogTool.runtimeClasspathConfigurationName].files)
    mainClass.set("io.github.fishyau.androidpatches.tools.PatchListGeneratorKt")
    doFirst {
        require(catalogTool.output.classesDirs.files.any {
            it.resolve("io/github/fishyau/androidpatches/tools/PatchListGeneratorKt.class").isFile
        }) { "Catalog adapter must already be compiled by the separate build/test phase" }
        val bundle = providers.gradleProperty("catalogBundle").orNull
            ?: error("Set catalogBundle to the exact built MPP; first-glob selection is forbidden")
        val output = providers.gradleProperty("catalogOutput").orNull
            ?: error("Set catalogOutput to a new external output file")
        args(bundle, output, rootProject.projectDir.absolutePath)
    }
}
