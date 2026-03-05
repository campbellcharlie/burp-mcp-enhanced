package net.portswigger.mcp.tools

import com.github.difflib.DiffUtils
import com.github.difflib.UnifiedDiffUtils
import com.jayway.jsonpath.JsonPath
import com.jayway.jsonpath.PathNotFoundException
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import java.util.regex.Pattern

/**
 * Register response comparison and extraction tools.
 */
fun Server.registerDiffTools() {

    mcpTool<CompareResponses>(
        "Compare two HTTP responses and show differences. " +
        "Can ignore specified headers (like Date, Set-Cookie) for cleaner comparison. " +
        "Useful for identifying subtle differences in response behavior."
    ) {
        val defaultIgnore = listOf("Date", "Set-Cookie", "X-Request-Id", "X-Trace-Id", "CF-Ray")
        val headersToIgnore = (ignoreHeaders ?: defaultIgnore).map { it.lowercase() }.toSet()

        // Parse and normalize responses
        val resp1Lines = normalizeResponse(response1, headersToIgnore)
        val resp2Lines = normalizeResponse(response2, headersToIgnore)

        // Generate diff
        val patch = DiffUtils.diff(resp1Lines, resp2Lines)

        if (patch.deltas.isEmpty()) {
            return@mcpTool buildString {
                appendLine("=== Responses are identical ===")
                appendLine()
                appendLine("(After ignoring headers: ${headersToIgnore.joinToString()})")
            }
        }

        // Generate unified diff
        val unifiedDiff = UnifiedDiffUtils.generateUnifiedDiff(
            "Response 1",
            "Response 2",
            resp1Lines,
            patch,
            contextLines
        )

        buildString {
            appendLine("=== Response Comparison ===")
            appendLine()
            appendLine("Ignored headers: ${headersToIgnore.joinToString()}")
            appendLine("Differences found: ${patch.deltas.size}")
            appendLine()

            // Summary of changes
            val additions = patch.deltas.sumOf { it.target.lines.size }
            val deletions = patch.deltas.sumOf { it.source.lines.size }
            appendLine("Summary: +$additions lines, -$deletions lines")
            appendLine()

            appendLine("Unified Diff:")
            appendLine("-".repeat(60))
            unifiedDiff.forEach { appendLine(it) }
            appendLine("-".repeat(60))

            // Highlight key differences
            appendLine()
            appendLine("Key Differences:")
            patch.deltas.forEachIndexed { i, delta ->
                appendLine()
                appendLine("Change ${i + 1} (${delta.type}):")
                if (delta.source.lines.isNotEmpty()) {
                    appendLine("  - ${delta.source.lines.joinToString("\n  - ")}")
                }
                if (delta.target.lines.isNotEmpty()) {
                    appendLine("  + ${delta.target.lines.joinToString("\n  + ")}")
                }
            }
        }
    }

    mcpTool<ExtractRegex>(
        "Extract content from a response using a regex pattern. " +
        "Returns all matches or a specific capture group."
    ) {
        try {
            val compiledPattern = Pattern.compile(pattern, Pattern.MULTILINE or Pattern.DOTALL)
            val matcher = compiledPattern.matcher(content)

            val matches = mutableListOf<String>()
            while (matcher.find()) {
                val match = if (group != null && group > 0 && group <= matcher.groupCount()) {
                    matcher.group(group) ?: ""
                } else {
                    matcher.group()
                }
                matches.add(match)

                if (matches.size >= maxMatches) break
            }

            if (matches.isEmpty()) {
                "No matches found for pattern: $pattern"
            } else {
                buildString {
                    appendLine("=== Regex Extraction ===")
                    appendLine()
                    appendLine("Pattern: $pattern")
                    if (group != null && group > 0) {
                        appendLine("Capture group: $group")
                    }
                    appendLine("Matches found: ${matches.size}")
                    appendLine()
                    matches.forEachIndexed { i, match ->
                        appendLine("Match ${i + 1}:")
                        appendLine(match.take(500))
                        if (match.length > 500) appendLine("... (truncated)")
                        appendLine()
                    }
                }
            }
        } catch (e: Exception) {
            "Invalid regex pattern: ${e.message}"
        }
    }

    mcpTool<ExtractJsonPath>(
        "Extract data from JSON using JSONPath expressions. " +
        "Examples: \$.data[0].id, \$.users[*].email, \$..password"
    ) {
        try {
            val result = JsonPath.read<Any>(jsonContent, path)

            buildString {
                appendLine("=== JSONPath Extraction ===")
                appendLine()
                appendLine("Path: $path")
                appendLine()
                appendLine("Result:")
                when (result) {
                    is List<*> -> {
                        appendLine("Array with ${result.size} elements:")
                        result.forEachIndexed { i, item ->
                            appendLine("  [$i]: $item")
                        }
                    }
                    is Map<*, *> -> {
                        appendLine("Object:")
                        result.forEach { (k, v) ->
                            appendLine("  $k: $v")
                        }
                    }
                    else -> appendLine(result.toString())
                }
            }
        } catch (e: PathNotFoundException) {
            "JSONPath not found: $path"
        } catch (e: Exception) {
            "JSONPath error: ${e.message}"
        }
    }

    mcpTool<ExtractBetween>(
        "Extract content between two delimiter strings. " +
        "Useful for extracting tokens, CSRF values, or other embedded data."
    ) {
        val results = mutableListOf<String>()
        var searchStart = 0

        while (searchStart < content.length && results.size < maxMatches) {
            val startIdx = content.indexOf(startDelimiter, searchStart)
            if (startIdx == -1) break

            val contentStart = startIdx + startDelimiter.length
            val endIdx = content.indexOf(endDelimiter, contentStart)
            if (endIdx == -1) break

            results.add(content.substring(contentStart, endIdx))
            searchStart = endIdx + endDelimiter.length
        }

        if (results.isEmpty()) {
            "No content found between '$startDelimiter' and '$endDelimiter'"
        } else {
            buildString {
                appendLine("=== Extracted Content ===")
                appendLine()
                appendLine("Start: $startDelimiter")
                appendLine("End: $endDelimiter")
                appendLine("Found: ${results.size} matches")
                appendLine()
                results.forEachIndexed { i, match ->
                    appendLine("Match ${i + 1}:")
                    appendLine(match.take(500))
                    if (match.length > 500) appendLine("... (truncated)")
                    appendLine()
                }
            }
        }
    }

    mcpTool<AnalyzeResponse>(
        "Analyze an HTTP response for security-relevant information. " +
        "Extracts headers, cookies, tokens, and potential vulnerabilities."
    ) {
        buildString {
            appendLine("=== Response Analysis ===")
            appendLine()

            // Split headers and body
            val parts = response.split("\r\n\r\n", limit = 2)
            val headerSection = parts[0]
            val body = if (parts.size > 1) parts[1] else ""

            // Parse status line
            val lines = headerSection.split("\r\n")
            val statusLine = lines.firstOrNull() ?: ""
            appendLine("Status: $statusLine")
            appendLine()

            // Parse headers
            val headers = mutableMapOf<String, String>()
            lines.drop(1).forEach { line ->
                val colonIdx = line.indexOf(':')
                if (colonIdx > 0) {
                    val name = line.substring(0, colonIdx).trim()
                    val value = line.substring(colonIdx + 1).trim()
                    headers[name.lowercase()] = value
                }
            }

            // Security headers analysis
            appendLine("Security Headers:")
            val securityHeaders = listOf(
                "content-security-policy" to "CSP",
                "x-frame-options" to "Clickjacking protection",
                "x-content-type-options" to "MIME sniffing protection",
                "x-xss-protection" to "XSS filter",
                "strict-transport-security" to "HSTS",
                "referrer-policy" to "Referrer control",
                "permissions-policy" to "Permissions control"
            )

            securityHeaders.forEach { (header, desc) ->
                val value = headers[header]
                if (value != null) {
                    appendLine("  [+] $header: $value")
                } else {
                    appendLine("  [-] $header: MISSING ($desc)")
                }
            }
            appendLine()

            // Cookie analysis
            val cookies = headers.filter { it.key == "set-cookie" }
            if (cookies.isNotEmpty()) {
                appendLine("Cookies:")
                cookies.forEach { (_, value) ->
                    val cookieParts = value.split(";").map { it.trim() }
                    val nameValue = cookieParts.first()
                    val flags = cookieParts.drop(1).map { it.lowercase() }

                    appendLine("  $nameValue")
                    appendLine("    HttpOnly: ${flags.any { it == "httponly" }}")
                    appendLine("    Secure: ${flags.any { it == "secure" }}")
                    appendLine("    SameSite: ${flags.find { it.startsWith("samesite") } ?: "not set"}")
                }
                appendLine()
            }

            // Look for interesting patterns in body
            appendLine("Body Analysis:")
            appendLine("  Length: ${body.length} characters")

            // Token patterns
            val tokenPatterns = listOf(
                "CSRF/XSRF tokens" to """(?:csrf|xsrf|_token)["\s:=]+["']?([a-zA-Z0-9_-]{16,})""",
                "API keys" to """(?:api[_-]?key|apikey)["\s:=]+["']?([a-zA-Z0-9_-]{16,})""",
                "AWS keys" to """AKIA[0-9A-Z]{16}""",
                "JWT tokens" to """eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+""",
                "Secrets" to """(?:secret|password|passwd|pwd)["\s:=]+["']?([^"'\s]{8,})"""
            )

            tokenPatterns.forEach { (name, pattern) ->
                val matcher = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(body)
                val matches = mutableListOf<String>()
                while (matcher.find()) {
                    matches.add(matcher.group())
                }
                if (matches.isNotEmpty()) {
                    appendLine("  Found $name: ${matches.take(3).joinToString()}")
                }
            }

            // Check for common issues
            appendLine()
            appendLine("Potential Issues:")
            if (body.contains("stack trace", ignoreCase = true) ||
                body.contains("exception", ignoreCase = true)) {
                appendLine("  [!] May contain error/stack trace information")
            }
            if (body.contains("sql", ignoreCase = true) &&
                body.contains("error", ignoreCase = true)) {
                appendLine("  [!] May contain SQL error messages")
            }
            if (headers["x-powered-by"] != null) {
                appendLine("  [!] X-Powered-By header present: ${headers["x-powered-by"]}")
            }
            if (headers["server"] != null) {
                appendLine("  [!] Server header present: ${headers["server"]}")
            }
        }
    }
}

private fun normalizeResponse(response: String, ignoreHeaders: Set<String>): List<String> {
    val lines = response.split("\r\n", "\n").toMutableList()

    return lines.filter { line ->
        // Keep non-header lines
        if (!line.contains(":")) return@filter true

        // Check if this is a header we should ignore
        val headerName = line.substringBefore(":").trim().lowercase()
        !ignoreHeaders.contains(headerName)
    }
}

// ============== Data Classes ==============

@Serializable
data class CompareResponses(
    val response1: String,
    val response2: String,
    val ignoreHeaders: List<String>? = null,
    val contextLines: Int = 3
)

@Serializable
data class ExtractRegex(
    val content: String,
    val pattern: String,
    val group: Int? = null,
    val maxMatches: Int = 10
)

@Serializable
data class ExtractJsonPath(
    val jsonContent: String,
    val path: String
)

@Serializable
data class ExtractBetween(
    val content: String,
    val startDelimiter: String,
    val endDelimiter: String,
    val maxMatches: Int = 10
)

@Serializable
data class AnalyzeResponse(
    val response: String
)
