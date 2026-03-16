package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Register scope management tools using the Montoya Scope API.
 */
fun Server.registerScopeTools(api: MontoyaApi) {

    mcpTool<IsInScope>(
        "Check if a URL is in the current target scope."
    ) {
        val inScope = api.scope().isInScope(url)
        if (inScope) {
            "URL '$url' is IN SCOPE"
        } else {
            "URL '$url' is NOT in scope"
        }
    }

    mcpTool<AddToScope>(
        "Add a URL to the target scope. The URL will be used to derive scope rules."
    ) {
        api.scope().includeInScope(url)
        "Added '$url' to target scope"
    }

    mcpTool<RemoveFromScope>(
        "Remove a URL from the target scope (exclude it)."
    ) {
        api.scope().excludeFromScope(url)
        "Excluded '$url' from target scope"
    }

    mcpTool<CheckScopeMultiple>(
        "Check if multiple URLs are in scope. Returns a list of URLs with their scope status."
    ) {
        buildString {
            appendLine("Scope check results:")
            appendLine()
            urls.forEach { url ->
                val inScope = api.scope().isInScope(url)
                val status = if (inScope) "IN SCOPE" else "NOT in scope"
                appendLine("  $status: $url")
            }
        }
    }

    mcpTool<GetScopeRules>(
        "Get the current target scope rules (include and exclude lists) from Burp's project configuration."
    ) {
        try {
            val configJson = api.burpSuite().exportProjectOptionsAsJson()
            val config = Json.parseToJsonElement(configJson).jsonObject
            val scope = config["target"]?.jsonObject?.get("scope")?.jsonObject

            if (scope == null) {
                return@mcpTool "Could not read scope configuration"
            }

            val includeRules = scope["include"]?.jsonArray ?: emptyList()
            val excludeRules = scope["exclude"]?.jsonArray ?: emptyList()

            buildString {
                appendLine("=== Scope Rules ===")
                appendLine()
                appendLine("Include rules (${includeRules.size}):")
                if (includeRules.isEmpty()) {
                    appendLine("  (none)")
                } else {
                    includeRules.forEach { rule ->
                        val obj = rule.jsonObject
                        val enabled = obj["enabled"]?.jsonPrimitive?.content ?: "true"
                        val prefix = obj["prefix"]?.jsonPrimitive?.content ?: ""
                        val host = obj["host"]?.jsonPrimitive?.content ?: ""
                        val port = obj["port"]?.jsonPrimitive?.content ?: ""
                        val protocol = obj["protocol"]?.jsonPrimitive?.content ?: "any"
                        appendLine("  [${if (enabled == "true") "ON" else "OFF"}] $protocol://$host:$port$prefix")
                    }
                }
                appendLine()
                appendLine("Exclude rules (${excludeRules.size}):")
                if (excludeRules.isEmpty()) {
                    appendLine("  (none)")
                } else {
                    excludeRules.forEach { rule ->
                        val obj = rule.jsonObject
                        val enabled = obj["enabled"]?.jsonPrimitive?.content ?: "true"
                        val prefix = obj["prefix"]?.jsonPrimitive?.content ?: ""
                        val host = obj["host"]?.jsonPrimitive?.content ?: ""
                        val port = obj["port"]?.jsonPrimitive?.content ?: ""
                        val protocol = obj["protocol"]?.jsonPrimitive?.content ?: "any"
                        appendLine("  [${if (enabled == "true") "ON" else "OFF"}] $protocol://$host:$port$prefix")
                    }
                }
            }
        } catch (e: Exception) {
            "Error reading scope rules: ${e.message}"
        }
    }

    mcpTool<ImportScopeBulk>(
        "Add multiple URLs to scope in bulk. Each entry specifies a URL and whether to include or exclude it."
    ) {
        var successes = 0
        var failures = 0
        val errors = mutableListOf<String>()

        entries.forEach { entry ->
            try {
                when (entry.type.lowercase()) {
                    "include" -> {
                        api.scope().includeInScope(entry.url)
                        successes++
                    }
                    "exclude" -> {
                        api.scope().excludeFromScope(entry.url)
                        successes++
                    }
                    else -> {
                        failures++
                        errors.add("Invalid type '${entry.type}' for URL '${entry.url}' (must be 'include' or 'exclude')")
                    }
                }
            } catch (e: Exception) {
                failures++
                errors.add("Failed to process '${entry.url}': ${e.message}")
            }
        }

        buildString {
            appendLine("=== Bulk Scope Import ===")
            appendLine()
            appendLine("Processed: ${entries.size}")
            appendLine("Successes: $successes")
            appendLine("Failures: $failures")
            if (errors.isNotEmpty()) {
                appendLine()
                appendLine("Errors:")
                errors.forEach { appendLine("  - $it") }
            }
        }
    }

    mcpTool<ResetScope>(
        "Clear all scope rules (include and exclude). Requires confirm=true as a safety gate."
    ) {
        if (!confirm) {
            return@mcpTool "WARNING: This will clear ALL scope rules (include and exclude). " +
                "Call again with confirm=true to proceed."
        }

        try {
            // Read current scope to report what was cleared
            val configJson = api.burpSuite().exportProjectOptionsAsJson()
            val config = Json.parseToJsonElement(configJson).jsonObject
            val scope = config["target"]?.jsonObject?.get("scope")?.jsonObject

            val prevInclude = scope?.get("include")?.jsonArray?.size ?: 0
            val prevExclude = scope?.get("exclude")?.jsonArray?.size ?: 0

            // Import empty scope
            val emptyScope = """{"target":{"scope":{"advanced_mode":false,"exclude":[],"include":[]}}}"""
            api.burpSuite().importProjectOptionsFromJson(emptyScope)

            buildString {
                appendLine("Scope cleared successfully.")
                appendLine("  Previous include rules: $prevInclude")
                appendLine("  Previous exclude rules: $prevExclude")
            }
        } catch (e: Exception) {
            "Error resetting scope: ${e.message}"
        }
    }
}

// ============== Data Classes ==============

@Serializable
data class IsInScope(
    val url: String
)

@Serializable
data class AddToScope(
    val url: String
)

@Serializable
data class RemoveFromScope(
    val url: String
)

@Serializable
data class CheckScopeMultiple(
    val urls: List<String>
)

@Serializable
class GetScopeRules

@Serializable
data class ImportScopeBulk(
    val entries: List<ScopeBulkEntry>
)

@Serializable
data class ScopeBulkEntry(
    val url: String,
    val type: String // "include" or "exclude"
)

@Serializable
data class ResetScope(
    val confirm: Boolean = false
)
