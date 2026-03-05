package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.scanner.AuditConfiguration
import burp.api.montoya.scanner.BuiltInAuditConfiguration
import burp.api.montoya.scanner.CrawlConfiguration
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.schema.toSerializableForm
import java.util.concurrent.ConcurrentHashMap

private val json = Json { prettyPrint = true }

// Track active scans for status queries - using Any since Crawl/Audit may vary by API version
private val activeScans = ConcurrentHashMap<String, Any>()

/**
 * Register scanner control tools (Professional Edition only).
 *
 * Note: Scanner API availability varies by Montoya API version and Burp edition.
 * Some methods may not be available in all configurations.
 */
fun Server.registerScannerTools(api: MontoyaApi) {
    // Only register if running Professional edition
    if (api.burpSuite().version().edition() != BurpSuiteEdition.PROFESSIONAL) {
        api.logging().logToOutput("Scanner tools not registered: requires Burp Suite Professional")
        return
    }

    mcpTool<StartActiveScan>(
        "Start an active scan (audit) on a request. Returns a scan ID for tracking. " +
        "Configuration options: 'active' (default - full active scan), 'passive' (passive checks only)."
    ) {
        if (host == null || requestContent == null) {
            return@mcpTool "Error: 'host' and 'requestContent' are required"
        }

        val scanId = "audit_${System.currentTimeMillis()}"

        try {
            val httpService = burp.api.montoya.http.HttpService.httpService(
                host,
                port ?: 443,
                usesHttps ?: true
            )
            val request = HttpRequest.httpRequest(httpService, requestContent.replace("\n", "\r\n"))

            // Start audit with the request
            // Note: LEGACY_ACTIVE_AUDIT_CHECKS is the full active scan
            //       LEGACY_PASSIVE_AUDIT_CHECKS is passive-only
            val auditConfig = when (configuration?.lowercase()) {
                "passive" -> BuiltInAuditConfiguration.LEGACY_PASSIVE_AUDIT_CHECKS
                else -> BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS
            }

            val audit = api.scanner().startAudit(
                AuditConfiguration.auditConfiguration(auditConfig)
            )

            activeScans[scanId] = audit

            buildString {
                appendLine("Started active scan:")
                appendLine("  Scan ID: $scanId")
                appendLine("  Configuration: ${configuration ?: "default"}")
                appendLine("  Target: $host:${port ?: 443}")
                appendLine()
                appendLine("Note: The scan runs asynchronously. Check scanner results in Burp UI.")
            }
        } catch (e: Exception) {
            "Error starting scan: ${e.message}"
        }
    }

    mcpTool<StartCrawl>(
        "Start a crawl from a seed URL. Returns a crawl ID for tracking."
    ) {
        val crawlId = "crawl_${System.currentTimeMillis()}"

        try {
            val crawl = api.scanner().startCrawl(
                CrawlConfiguration.crawlConfiguration(seedUrl)
            )

            activeScans[crawlId] = crawl

            buildString {
                appendLine("Started crawl:")
                appendLine("  Crawl ID: $crawlId")
                appendLine("  Seed URL: $seedUrl")
                appendLine()
                appendLine("Note: The crawl runs asynchronously. Check results in Burp UI Site map.")
            }
        } catch (e: Exception) {
            "Error starting crawl: ${e.message}"
        }
    }

    mcpTool<ListActiveScans>(
        "List all active scans and crawls that were started via MCP."
    ) {
        if (activeScans.isEmpty()) {
            "No active scans or crawls started via MCP"
        } else {
            buildString {
                appendLine("=== Active Scans (started via MCP) ===")
                appendLine()
                activeScans.keys.sorted().forEach { id ->
                    val type = if (id.startsWith("audit_")) "Audit" else "Crawl"
                    appendLine("  $id ($type)")
                }
                appendLine()
                appendLine("Note: Check Burp UI for detailed scan status and results.")
            }
        }
    }

    mcpTool<GetAllScannerIssues>(
        "Get all scanner issues from the sitemap (all scans, not just MCP-initiated)."
    ) {
        val issues = api.siteMap().issues()

        if (issues.isEmpty()) {
            "No scanner issues found"
        } else {
            // Filter by severity if specified
            val filtered = if (severityFilter != null) {
                issues.filter { it.severity().name.equals(severityFilter, ignoreCase = true) }
            } else {
                issues
            }

            if (filtered.isEmpty()) {
                "No scanner issues found matching filter: severity=$severityFilter"
            } else {
                buildString {
                    appendLine("Found ${filtered.size} scanner issues:")
                    appendLine()

                    filtered.take(limit).forEach { issue ->
                        appendLine("[${issue.severity()}/${issue.confidence()}] ${issue.name()}")
                        appendLine("  URL: ${issue.baseUrl()}")
                        issue.detail()?.let {
                            val detail = it.take(200)
                            appendLine("  Detail: $detail${if (it.length > 200) "..." else ""}")
                        }
                        appendLine()
                    }

                    if (filtered.size > limit) {
                        appendLine("... and ${filtered.size - limit} more (increase limit to see more)")
                    }
                }
            }
        }
    }

    mcpTool<GetScannerIssuesByHost>(
        "Get scanner issues for a specific host."
    ) {
        val issues = api.siteMap().issues()

        val filtered = issues.filter { issue ->
            issue.httpService()?.host()?.contains(host, ignoreCase = true) == true
        }

        if (filtered.isEmpty()) {
            "No scanner issues found for host: $host"
        } else {
            buildString {
                appendLine("Found ${filtered.size} scanner issues for host '$host':")
                appendLine()

                filtered.take(limit).forEach { issue ->
                    appendLine("[${issue.severity()}/${issue.confidence()}] ${issue.name()}")
                    appendLine("  URL: ${issue.baseUrl()}")
                    appendLine()
                }

                if (filtered.size > limit) {
                    appendLine("... and ${filtered.size - limit} more")
                }
            }
        }
    }

    mcpTool<ClearMcpScans>(
        "Clear the list of MCP-tracked scans (does not stop actual scans in Burp)."
    ) {
        val count = activeScans.size
        activeScans.clear()
        "Cleared $count MCP-tracked scan references"
    }
}

// ============== Data Classes ==============

@Serializable
data class StartActiveScan(
    val host: String? = null,
    val port: Int? = null,
    val usesHttps: Boolean? = null,
    val requestContent: String? = null,
    val configuration: String? = null // "active" (default), "passive"
)

@Serializable
data class StartCrawl(
    val seedUrl: String
)

@Serializable
data class ListActiveScans(
    val dummy: String = ""
)

@Serializable
data class GetAllScannerIssues(
    val severityFilter: String? = null, // "HIGH", "MEDIUM", "LOW", "INFORMATION"
    val limit: Int = 50
)

@Serializable
data class GetScannerIssuesByHost(
    val host: String,
    val limit: Int = 50
)

@Serializable
data class ClearMcpScans(
    val dummy: String = ""
)
