package io.github.fishyau.androidpatches.plexcheck

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.JsonPrimitive
import io.github.fishyau.androidpatches.tools.metadataGson
import io.github.fishyau.androidpatches.tools.sha256
import java.io.File

/** Executable tools-only contract probe: NEVER opens or loads an MPP. */
fun main(args: Array<String>) {
    require(args.size == 2) { "Exact freeze-produced request.json and its synthetic source root" }
    val file = File(args[0]); val root = File(args[1])
    val bytes = file.readBytes(); val originalHash = sha256(file)
    val baseline = JsonParser.parseString(bytes.toString(Charsets.UTF_8)).asJsonObject
    val bundle = baseline.get("bundle_sha256").asString
    val catalog = baseline.get("catalog_sha256").asString
    val tree = baseline.get("source_tree_sha256").asString
    val cases = mutableListOf<Map<String, String>>()
    fun accepted(name: String, input: ByteArray) {
        check(validateFrozenRequest(input, bundle, catalog, tree, root) == baseline)
        cases.add(mapOf("name" to name, "status" to "accepted_contract_only"))
    }
    fun rejected(name: String, input: ByteArray) {
        var failed = false
        try { validateFrozenRequest(input, bundle, catalog, tree, root) } catch (_: Exception) { failed = true }
        check(failed) { "Incorrectly accepted $name" }
        cases.add(mapOf("name" to name, "status" to "rejected_contract_only"))
    }
    fun mutation(name: String, change: (JsonObject) -> Unit) {
        val value = baseline.deepCopy(); change(value)
        rejected(name, metadataGson.toJson(value).toByteArray())
    }
    accepted("actual_freeze_exact_bytes", bytes)
    accepted("whitespace_semantic_equivalent", (" \n" + metadataGson.toJson(baseline) + "\n\n").toByteArray())
    for ((label, value) in listOf("boolean" to JsonPrimitive(true), "string" to JsonPrimitive("2"),
        "float" to JsonPrimitive(2.0), "legacy" to JsonPrimitive(1), "exponent" to JsonParser.parseString("2e0"))) {
        mutation("schema_$label") { it.add("schema", value) }
    }
    for (key in listOf("owner", "repository", "version", "policy", "bundle_sha256", "catalog_sha256", "source_tree_sha256")) {
        mutation("wrong_$key") { it.addProperty(key, if (key.endsWith("sha256")) "a".repeat(64) else "wrong") }
        mutation("wrong_type_$key") { it.addProperty(key, true) }
    }
    mutation("extra_field") { it.addProperty("defaults", true) }
    mutation("missing_field") { it.remove("description") }
    mutation("old_standalone") {
        it.addProperty("schema", "plex-final-bundle-request-v1"); it.addProperty("patcher_version", "2.3.0")
        it.add("defaults", JsonObject())
    }
    for (date in listOf("2026-11-09T00:00:00Z", "2026-11-09T00:00:00+00:00", "2026-02-30T00:00:00",
        "2026-11-09T24:00:00", "2099-01-01T00:00:00", "0000-01-01T00:00:00")) {
        mutation("bad_date_$date") { it.addProperty("created_at", date) }
    }
    mutation("blank_description") { it.addProperty("description", "  ") }
    mutation("control_description") { it.addProperty("description", "bad\ntext") }
    mutation("wrong_plex_revision") { it.getAsJsonObject("provenance").getAsJsonObject("plex").addProperty("revision", "a".repeat(40)) }
    mutation("wrong_termius_adaptation") { it.getAsJsonObject("provenance").getAsJsonObject("termius").addProperty("adaptations", "old") }
    for (section in listOf("termius", "plex")) {
        for (field in listOf("original_sha256", "migrated_sha256")) {
            mutation("wrong_${section}_$field") {
                it.getAsJsonObject("provenance").getAsJsonObject(section).getAsJsonArray("files")[0].asJsonObject.addProperty(field, "a".repeat(64))
            }
        }
        mutation("missing_${section}_file") { it.getAsJsonObject("provenance").getAsJsonObject(section).getAsJsonArray("files").remove(0) }
    }
    rejected("duplicate_key", ("{\"schema\":2," + bytes.toString(Charsets.UTF_8).trimStart().drop(1)).toByteArray())
    rejected("malformed", "{".toByteArray())
    rejected("nonfinite", "{\"schema\":NaN}".toByteArray())
    rejected("trailing_json", bytes + "{}".toByteArray())
    rejected("invalid_utf8", byteArrayOf(0xC3.toByte(), 0x28))
    check(file.readBytes().contentEquals(bytes) && sha256(file) == originalHash)
    println(metadataGson.toJson(mapOf("status" to "request_contract_probe_only", "request_sha256" to originalHash,
        "actual_definition" to "not_observed", "resource_execution" to "not_observed", "runtime" to "not_observed", "cases" to cases)))
}
