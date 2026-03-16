package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

/**
 * Register Burp Suite info tools for querying version, edition, and project details.
 */
fun Server.registerBurpInfoTools(api: MontoyaApi) {

    mcpTool<GetBurpInfo>(
        "Get Burp Suite version, edition, and current project information."
    ) {
        val version = api.burpSuite().version()
        val project = api.project()

        buildString {
            appendLine("=== Burp Suite Info ===")
            appendLine()
            @Suppress("DEPRECATION")
            appendLine("Version: ${version.name()} ${version.major()}.${version.minor()}.${version.build()}")
            appendLine("Edition: ${version.edition()}")
            appendLine("Project: ${project.name()}")
            appendLine("Project ID: ${project.id()}")
        }
    }
}

// ============== Data Classes ==============

@Serializable
class GetBurpInfo
