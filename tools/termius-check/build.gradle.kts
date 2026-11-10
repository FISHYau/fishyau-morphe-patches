plugins {
    kotlin("jvm") version "2.4.21"
    application
}
repositories {
    mavenCentral()
    google()
    maven("https://jitpack.io") {
        content { includeGroup("com.github.MorpheApp.smali"); includeGroup("com.github.MorpheApp") }
    }
    maven("https://maven.pkg.github.com/MorpheApp/registry") {
        credentials {
            username = System.getenv("GITHUB_ACTOR")
            password = System.getenv("GITHUB_TOKEN")
        }
    }
}
dependencies {
    implementation("app.morphe:morphe-patcher:2.3.0")
    // Patcher publishes these as runtime dependencies, but the harness imports their APIs.
    implementation("com.github.MorpheApp.smali:smali:ac700e1942")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("com.google.code.gson:gson:2.14.0")
}
kotlin {
    jvmToolchain(21)
    compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) }
    // Share the exact catalog projection, not a second metadata implementation.
    sourceSets.main { kotlin.srcDir("../../patches/src/main/kotlin/io/github/fishyau/androidpatches/tools") }
}

tasks.register<JavaExec>("inspectBundle") {
    classpath = sourceSets["main"].runtimeClasspath
    mainClass.set("io.github.fishyau.androidpatches.inspection.InspectBundleKt")
    doFirst {
        args(
            providers.gradleProperty("inspectionBundle").get(),
            providers.gradleProperty("inspectionCatalog").get(),
            providers.gradleProperty("inspectionOutput").get(),
            rootProject.projectDir.resolve("../..").canonicalPath,
        )
    }
}
application {
    mainClass.set("RuntimeCheckKt")
    applicationDefaultJvmArgs = listOf("-Xmx3g")
}
