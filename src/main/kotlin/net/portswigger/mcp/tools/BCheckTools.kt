package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

/**
 * Register BCheck tools for importing and validating BCheck scripts.
 */
fun Server.registerBCheckTools(api: MontoyaApi) {

    // validate_bcheck is always available (no Professional gate)
    mcpTool<ValidateBcheck>(
        "Validate a BCheck script for prohibited patterns and basic structure. " +
        "Does not require Professional edition."
    ) {
        val warnings = mutableListOf<String>()

        // Size check
        if (script.length > 1_000_000) {
            warnings.add("Script exceeds 1MB size limit (${script.length} bytes)")
        }

        // Prohibited patterns
        val prohibited = listOf(
            "System.exit" to "System termination",
            "Runtime.getRuntime" to "Runtime access",
            "ProcessBuilder" to "Process execution",
            "exec(" to "Command execution",
            "java.lang.reflect" to "Reflection access",
            "java.io.File" to "File system access",
            "java.nio.file" to "NIO file access",
            "javax.script" to "Script engine access",
            "nashorn" to "Nashorn script engine",
            "rhino" to "Rhino script engine"
        )

        prohibited.forEach { (pattern, desc) ->
            if (script.contains(pattern, ignoreCase = true)) {
                warnings.add("Prohibited pattern found: '$pattern' ($desc)")
            }
        }

        // Basic structure checks
        val hasMetadata = script.contains("metadata") || script.contains("language")
        val hasGiven = script.contains("given", ignoreCase = true)
        val hasThen = script.contains("then", ignoreCase = true)

        if (!hasMetadata) {
            warnings.add("Missing metadata section")
        }
        if (!hasGiven) {
            warnings.add("Missing 'given' clause")
        }
        if (!hasThen) {
            warnings.add("Missing 'then' clause")
        }

        if (warnings.isEmpty()) {
            "BCheck validation PASSED: No issues found"
        } else {
            buildString {
                appendLine("BCheck validation completed with ${warnings.size} warning(s):")
                appendLine()
                warnings.forEach { warning ->
                    appendLine("  [!] $warning")
                }
            }
        }
    }

    // Professional-only tools
    if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
        api.logging().logToOutput("BCheck import tools not registered: requires Burp Suite Professional")
        return
    }

    mcpTool<ImportBcheck>(
        "Import a BCheck script into Burp Scanner. Requires Professional edition."
    ) {
        try {
            val result = api.scanner().bChecks().importBCheck(script, enabled)
            val errors = result.importErrors()

            buildString {
                appendLine("=== BCheck Import Result ===")
                appendLine()
                appendLine("Status: ${result.status()}")
                if (errors.isNotEmpty()) {
                    appendLine()
                    appendLine("Errors:")
                    errors.forEach { error ->
                        appendLine("  - $error")
                    }
                } else {
                    appendLine("Enabled: $enabled")
                }
            }
        } catch (e: Exception) {
            "Error importing BCheck: ${e.message}"
        }
    }
}

// ============== Data Classes ==============

@Serializable
data class ValidateBcheck(
    val script: String
)

@Serializable
data class ImportBcheck(
    val script: String,
    val enabled: Boolean = true
)
