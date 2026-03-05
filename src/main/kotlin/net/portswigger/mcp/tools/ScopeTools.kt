package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

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
