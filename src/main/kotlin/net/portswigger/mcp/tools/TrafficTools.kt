package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.SearchField
import net.portswigger.mcp.logging.TrafficLogger
import net.portswigger.mcp.security.HttpRequestSecurity
import kotlinx.coroutines.runBlocking

private val json = Json { prettyPrint = true }

/**
 * Register traffic search and analysis tools.
 */
fun Server.registerTrafficTools(db: DatabaseService, logger: TrafficLogger, api: MontoyaApi? = null, config: McpConfig? = null) {

    mcpTool<SearchTraffic>(
        "Search logged HTTP traffic using FTS5 full-text search. " +
        "Supports advanced query syntax: AND, OR, NOT, phrase matching with quotes, prefix matching with *."
    ) {
        // Flush pending traffic so search sees recently-captured data
        logger.flush()

        val results = db.searchTraffic(
            query = query,
            method = method?.uppercase(),
            host = host,
            statusCode = statusCode,
            toolSource = toolSource,
            limit = limit,
            offset = offset
        )

        if (results.isEmpty()) {
            "No results found for query: $query"
        } else {
            buildString {
                appendLine("Found ${results.size} results:")
                appendLine()
                results.forEachIndexed { i, r ->
                    appendLine("${i + 1}. [${r.id}] ${r.method} ${r.url}")
                    appendLine("   Host: ${r.host}:${r.port} | Status: ${r.statusCode ?: "pending"} | Tool: ${r.toolSource}")
                    appendLine("   Time: ${r.timestamp}")
                    if (r.contentType != null) appendLine("   Content-Type: ${r.contentType}")
                    appendLine()
                }
            }
        }
    }

    mcpTool<SearchTrafficRegex>(
        "Search logged HTTP traffic using regex pattern matching. " +
        "Can search in URL, request headers, request body, response headers, or response body."
    ) {
        val field = try {
            SearchField.valueOf(searchIn.uppercase())
        } catch (e: IllegalArgumentException) {
            return@mcpTool "Invalid searchIn field: $searchIn. Valid values: ${SearchField.entries.joinToString()}"
        }

        // Flush pending traffic so search sees recently-captured data
        logger.flush()

        val response = db.searchTrafficRegex(
            pattern = pattern,
            searchIn = field,
            host = host,
            limit = limit
        )

        if (response.results.isEmpty()) {
            buildString {
                append("No results found for regex: $pattern in $searchIn")
                if (response.scanLimitReached) {
                    append(" (scanned ${response.scannedRows} most recent rows — try narrowing with host filter)")
                }
            }
        } else {
            buildString {
                appendLine("Found ${response.results.size} results matching /$pattern/ in $searchIn:")
                if (response.scanLimitReached) {
                    appendLine("NOTE: Scan limit reached (${response.scannedRows} rows). Results may be incomplete — use host filter to narrow scope.")
                }
                appendLine()
                response.results.forEachIndexed { i, r ->
                    appendLine("${i + 1}. [${r.id}] ${r.method} ${r.url}")
                    appendLine("   Host: ${r.host}:${r.port} | Status: ${r.statusCode ?: "pending"}")
                    appendLine()
                }
            }
        }
    }

    mcpTool<GetTrafficById>(
        "Get full details of a specific traffic item by ID, including headers and body."
    ) {
        val detail = db.getTrafficById(id)
            ?: return@mcpTool "Traffic item with ID $id not found"

        buildString {
            appendLine("=== Traffic Item #${detail.id} ===")
            appendLine()
            appendLine("Timestamp: ${detail.timestamp}")
            appendLine("Tool: ${detail.toolSource}")
            appendLine("URL: ${detail.url}")
            appendLine("Host: ${detail.host}:${detail.port}")
            appendLine("HTTPS: ${detail.isHttps}")
            appendLine("Status: ${detail.statusCode ?: "pending"}")
            if (detail.contentType != null) appendLine("Content-Type: ${detail.contentType}")
            if (detail.contentLength != null) appendLine("Content-Length: ${detail.contentLength}")
            if (detail.sessionTag != null) appendLine("Session: ${detail.sessionTag}")
            if (detail.notes != null) appendLine("Notes: ${detail.notes}")
            appendLine()
            appendLine("=== Request ===")
            appendLine(detail.method + " " + detail.url)
            detail.requestHeaders?.let { appendLine(it) }
            if (detail.requestBody != null && detail.requestBody.isNotEmpty()) {
                appendLine()
                appendLine(truncateBody(detail.requestBody))
            }
            appendLine()
            if (detail.responseHeaders != null) {
                appendLine("=== Response ===")
                appendLine("HTTP/1.1 ${detail.statusCode}")
                appendLine(detail.responseHeaders)
                if (detail.responseBody != null && detail.responseBody.isNotEmpty()) {
                    appendLine()
                    appendLine(truncateBody(detail.responseBody))
                }
            }
        }
    }

    mcpTool(
        name = "get_traffic_stats",
        description = "Get traffic statistics including total requests, top hosts, method distribution, and status code distribution."
    ) {
        val stats = db.getStats()
        val loggerStats = logger.getStats()

        buildString {
            appendLine("=== Traffic Statistics ===")
            appendLine()
            appendLine("Total Requests: ${stats.totalRequests}")
            appendLine()
            appendLine("Queue Stats:")
            appendLine("  - Queue Size: ${loggerStats.queueStats.queueSize}")
            appendLine("  - Enqueued: ${loggerStats.queueStats.enqueued}")
            appendLine("  - Processed: ${loggerStats.queueStats.processed}")
            appendLine("  - Dropped: ${loggerStats.queueStats.dropped} (${String.format("%.2f", loggerStats.queueStats.dropRate)}%)")
            appendLine("  - Errors: ${loggerStats.queueStats.errors}")
            appendLine()
            appendLine("Pool Stats:")
            appendLine("  - Available Connections: ${stats.poolStats.availableConnections}")
            appendLine("  - Active Connections: ${stats.poolStats.activeConnections}")
            appendLine("  - Utilization: ${String.format("%.1f", stats.poolStats.utilizationPercent)}%")
            appendLine()
            appendLine("Top Hosts:")
            stats.topHosts.forEach { (host, count) ->
                appendLine("  - $host: $count")
            }
            appendLine()
            appendLine("Method Distribution:")
            stats.methodDistribution.forEach { (method, count) ->
                appendLine("  - $method: $count")
            }
            appendLine()
            appendLine("Status Distribution:")
            stats.statusDistribution.toSortedMap().forEach { (status, count) ->
                appendLine("  - $status: $count")
            }
        }
    }

    mcpTool<SetTrafficLogging>(
        "Enable or disable traffic logging, or configure which tools to log."
    ) {
        enabled?.let { logger.enabled = it }
        logProxy?.let { logger.logProxyTraffic = it }
        logRepeater?.let { logger.logRepeaterTraffic = it }
        logScanner?.let { logger.logScannerTraffic = it }
        logIntruder?.let { logger.logIntruderTraffic = it }
        logExtensions?.let { logger.logExtensionTraffic = it }

        buildString {
            appendLine("Traffic logging configuration updated:")
            appendLine("  - Enabled: ${logger.enabled}")
            appendLine("  - Log Proxy: ${logger.logProxyTraffic}")
            appendLine("  - Log Repeater: ${logger.logRepeaterTraffic}")
            appendLine("  - Log Scanner: ${logger.logScannerTraffic}")
            appendLine("  - Log Intruder: ${logger.logIntruderTraffic}")
            appendLine("  - Log Extensions: ${logger.logExtensionTraffic}")
        }
    }

    // ============== Traffic Analysis Tools ==============

    mcpTool<GetEndpoints>(
        "List unique endpoints (URL paths) discovered in traffic, grouped by host. " +
        "Useful for mapping the attack surface."
    ) {
        val results = db.getEndpoints(host = host, limit = limit)

        if (results.isEmpty()) {
            "No endpoints found${host?.let { " for host matching '$it'" } ?: ""}"
        } else {
            buildString {
                appendLine("Found ${results.size} unique endpoints:")
                appendLine()
                var currentHost = ""
                results.forEach { ep ->
                    if (ep.host != currentHost) {
                        currentHost = ep.host
                        appendLine("=== ${ep.host} ===")
                    }
                    appendLine("  ${ep.method.padEnd(7)} ${ep.url}")
                    appendLine("       Requests: ${ep.requestCount} | First: ${ep.firstSeen} | Last: ${ep.lastSeen}")
                }
            }
        }
    }

    mcpTool<GetParameters>(
        "Extract unique parameters from query strings and request bodies. " +
        "Useful for identifying injection points."
    ) {
        val results = db.getParameters(host = host, limit = limit)

        if (results.isEmpty()) {
            "No parameters found${host?.let { " for host matching '$it'" } ?: ""}"
        } else {
            buildString {
                appendLine("Found ${results.size} unique parameters:")
                appendLine()
                var currentHost = ""
                results.forEach { param ->
                    if (param.host != currentHost) {
                        currentHost = param.host
                        appendLine("=== ${param.host} ===")
                    }
                    appendLine("  ${param.name.padEnd(30)} [${param.location}] x${param.occurrences}")
                }
            }
        }
    }

    mcpTool<GetResponseTypes>(
        "Get response content-type distribution. Useful for identifying API endpoints (JSON/XML) vs web pages (HTML)."
    ) {
        val results = db.getResponseTypes(host = host)

        if (results.isEmpty()) {
            "No response types found${host?.let { " for host matching '$it'" } ?: ""}"
        } else {
            buildString {
                appendLine("Response Content-Type Distribution:")
                appendLine()
                results.forEach { rt ->
                    val pct = "%.1f%%".format(rt.count.toDouble() / results.sumOf { it.count } * 100)
                    appendLine("  ${rt.contentType.padEnd(50)} ${rt.count.toString().padStart(6)} ($pct)")
                }
            }
        }
    }

    mcpTool<GetStatusDistribution>(
        "Get HTTP status code distribution. Useful for finding error pages (4xx/5xx) or redirects (3xx)."
    ) {
        val results = db.getStatusDistribution(host = host)

        if (results.isEmpty()) {
            "No status codes found${host?.let { " for host matching '$it'" } ?: ""}"
        } else {
            buildString {
                appendLine("HTTP Status Code Distribution:")
                appendLine()
                results.forEach { sd ->
                    val category = when (sd.statusCode / 100) {
                        1 -> "Informational"
                        2 -> "Success"
                        3 -> "Redirect"
                        4 -> "Client Error"
                        5 -> "Server Error"
                        else -> "Unknown"
                    }
                    appendLine("  ${sd.statusCode} ($category): ${sd.count}")
                }
            }
        }
    }

    // ============== Traffic Tagging Tools ==============

    mcpTool<TagTraffic>(
        "Add a tag to a traffic item for later retrieval. Use tags like 'interesting', 'sqli', 'auth-bypass', etc."
    ) {
        val tagId = db.tagTraffic(trafficId, tag, note)
        "Tagged traffic item #$trafficId with '$tag' (tag ID: $tagId)"
    }

    mcpTool<GetTaggedTraffic>(
        "Get all traffic items with a specific tag."
    ) {
        val results = db.getTaggedTraffic(tag, limit)

        if (results.isEmpty()) {
            "No traffic found with tag '$tag'"
        } else {
            buildString {
                appendLine("Found ${results.size} items tagged '$tag':")
                appendLine()
                results.forEach { r ->
                    appendLine("[${r.trafficId}] ${r.method} ${r.url}")
                    appendLine("   Host: ${r.host}:${r.port} | Status: ${r.statusCode ?: "pending"}")
                    if (r.note != null) appendLine("   Note: ${r.note}")
                    appendLine()
                }
            }
        }
    }

    mcpTool<ListTags>(
        "List all tags and their usage counts."
    ) {
        val tags = db.listTags()

        if (tags.isEmpty()) {
            "No tags found"
        } else {
            buildString {
                appendLine("Tags:")
                appendLine()
                tags.forEach { t ->
                    appendLine("  ${t.tag.padEnd(30)} ${t.count} items | Last used: ${java.time.Instant.ofEpochMilli(t.lastUsed)}")  // tagCreatedAt is still epoch millis
                }
            }
        }
    }

    mcpTool<DeleteTrafficTag>(
        "Remove a tag from a traffic item."
    ) {
        val deleted = db.deleteTrafficTag(trafficId, tag)
        if (deleted) {
            "Removed tag '$tag' from traffic item #$trafficId"
        } else {
            "Tag '$tag' not found on traffic item #$trafficId"
        }
    }

    // ============== Traffic Replay & Comparison Tools ==============

    if (api != null && config != null) {
        mcpTool<ReplayFromDb>(
            "Replay a request from the traffic database. Optionally modify headers or body before sending."
        ) {
            val detail = db.getTrafficById(trafficId)
                ?: return@mcpTool "Traffic item with ID $trafficId not found"

            // Build the request from stored data
            val originalHeaders = detail.requestHeaders ?: ""
            val originalBody = detail.requestBody?.let { String(it, Charsets.UTF_8) } ?: ""

            // Apply modifications
            var modifiedHeaders = originalHeaders
            modifiedHeadersJson?.let { json ->
                val headerMods = Json.decodeFromString<Map<String, String>>(json)
                headerMods.forEach { (name, value) ->
                    // Replace or add header
                    val headerRegex = "(?i)^$name:.*$".toRegex(RegexOption.MULTILINE)
                    modifiedHeaders = if (headerRegex.containsMatchIn(modifiedHeaders)) {
                        modifiedHeaders.replace(headerRegex, "$name: $value")
                    } else {
                        "$modifiedHeaders\r\n$name: $value"
                    }
                }
            }

            val finalBody = modifiedBody ?: originalBody

            // Build full request
            val requestLine = "${detail.method} ${detail.url.substringAfter(detail.host).let { if (it.isEmpty()) "/" else if (it.startsWith(":")) it.substringAfter("/").let { p -> "/$p" } else it }} HTTP/1.1"
            val fullRequest = "$requestLine\r\n$modifiedHeaders\r\n\r\n$finalBody"

            // Security check
            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(detail.host, detail.port, config, fullRequest, api)
            }
            if (!allowed) {
                return@mcpTool "Replay request denied by security policy"
            }

            api.logging().logToOutput("MCP replay request from traffic #$trafficId to ${detail.host}:${detail.port}")

            val httpService = burp.api.montoya.http.HttpService.httpService(detail.host, detail.port, detail.isHttps)
            val request = HttpRequest.httpRequest(httpService, fullRequest.replace("\n", "\r\n"))
            val response = api.http().sendRequest(request, HttpMode.HTTP_1)

            response?.toString() ?: "<no response>"
        }
    }

    mcpTool<CompareTraffic>(
        "Compare two traffic items (request/response). Shows differences in headers and body."
    ) {
        val item1 = db.getTrafficById(id1)
            ?: return@mcpTool "Traffic item with ID $id1 not found"
        val item2 = db.getTrafficById(id2)
            ?: return@mcpTool "Traffic item with ID $id2 not found"

        buildString {
            appendLine("=== Comparison: Traffic #$id1 vs #$id2 ===")
            appendLine()

            // Basic info
            appendLine("URLs:")
            appendLine("  #$id1: ${item1.method} ${item1.url}")
            appendLine("  #$id2: ${item2.method} ${item2.url}")
            appendLine()

            if (compareRequests) {
                appendLine("=== Request Differences ===")
                val reqHeaders1 = item1.requestHeaders?.lines() ?: emptyList()
                val reqHeaders2 = item2.requestHeaders?.lines() ?: emptyList()
                appendLine(diffLines(reqHeaders1, reqHeaders2, "#$id1", "#$id2"))

                val reqBody1 = item1.requestBody?.let { String(it, Charsets.UTF_8) } ?: ""
                val reqBody2 = item2.requestBody?.let { String(it, Charsets.UTF_8) } ?: ""
                if (reqBody1 != reqBody2) {
                    appendLine("Request body differs:")
                    appendLine("  #$id1: ${reqBody1.take(200)}${if (reqBody1.length > 200) "..." else ""}")
                    appendLine("  #$id2: ${reqBody2.take(200)}${if (reqBody2.length > 200) "..." else ""}")
                }
                appendLine()
            }

            if (compareResponses) {
                appendLine("=== Response Differences ===")
                appendLine("Status: #$id1=${item1.statusCode}, #$id2=${item2.statusCode}")

                val resHeaders1 = item1.responseHeaders?.lines() ?: emptyList()
                val resHeaders2 = item2.responseHeaders?.lines() ?: emptyList()
                appendLine(diffLines(resHeaders1, resHeaders2, "#$id1", "#$id2"))

                val resBody1 = item1.responseBody?.let { String(it, Charsets.UTF_8) } ?: ""
                val resBody2 = item2.responseBody?.let { String(it, Charsets.UTF_8) } ?: ""
                if (resBody1 != resBody2) {
                    appendLine("Response body length: #$id1=${resBody1.length}, #$id2=${resBody2.length}")
                    if (resBody1.length < 1000 && resBody2.length < 1000) {
                        appendLine("Response body differs:")
                        appendLine("  #$id1: ${resBody1.take(500)}")
                        appendLine("  #$id2: ${resBody2.take(500)}")
                    }
                }
            }
        }
    }

    mcpTool<GenerateWordlist>(
        "Generate a wordlist from traffic data (paths, parameters). Useful for fuzzing."
    ) {
        val words = db.generateWordlist(host = host, includeParams = includeParams, includePaths = includePaths)

        if (words.isEmpty()) {
            "No words found${host?.let { " for host matching '$it'" } ?: ""}"
        } else {
            buildString {
                appendLine("Generated wordlist (${words.size} words):")
                appendLine()
                words.forEach { appendLine(it) }
            }
        }
    }
}

private fun diffLines(lines1: List<String>, lines2: List<String>, label1: String, label2: String): String {
    val set1 = lines1.toSet()
    val set2 = lines2.toSet()

    val onlyIn1 = set1 - set2
    val onlyIn2 = set2 - set1

    return buildString {
        if (onlyIn1.isNotEmpty()) {
            appendLine("Only in $label1:")
            onlyIn1.take(10).forEach { appendLine("  - $it") }
            if (onlyIn1.size > 10) appendLine("  ... and ${onlyIn1.size - 10} more")
        }
        if (onlyIn2.isNotEmpty()) {
            appendLine("Only in $label2:")
            onlyIn2.take(10).forEach { appendLine("  + $it") }
            if (onlyIn2.size > 10) appendLine("  ... and ${onlyIn2.size - 10} more")
        }
        if (onlyIn1.isEmpty() && onlyIn2.isEmpty()) {
            appendLine("No differences")
        }
    }
}

private fun truncateBody(body: ByteArray, maxLength: Int = 5000): String {
    val text = try {
        String(body, Charsets.UTF_8)
    } catch (e: Exception) {
        "<binary data: ${body.size} bytes>"
    }

    return if (text.length > maxLength) {
        text.take(maxLength) + "\n... (truncated, ${body.size} bytes total)"
    } else {
        text
    }
}

// ============== Data Classes ==============

@Serializable
data class SearchTraffic(
    val query: String,
    val method: String? = null,
    val host: String? = null,
    val statusCode: Int? = null,
    val toolSource: String? = null,
    val limit: Int = 100,
    val offset: Int = 0
)

@Serializable
data class SearchTrafficRegex(
    val pattern: String,
    val searchIn: String = "RESPONSE_BODY",
    val host: String? = null,
    val limit: Int = 100
)

@Serializable
data class GetTrafficById(val id: Long)

@Serializable
data class SetTrafficLogging(
    val enabled: Boolean? = null,
    val logProxy: Boolean? = null,
    val logRepeater: Boolean? = null,
    val logScanner: Boolean? = null,
    val logIntruder: Boolean? = null,
    val logExtensions: Boolean? = null
)

// ============== Traffic Analysis Data Classes ==============

@Serializable
data class GetEndpoints(
    val host: String? = null,
    val limit: Int = 500
)

@Serializable
data class GetParameters(
    val host: String? = null,
    val limit: Int = 500
)

@Serializable
data class GetResponseTypes(
    val host: String? = null
)

@Serializable
data class GetStatusDistribution(
    val host: String? = null
)

// ============== Traffic Tagging Data Classes ==============

@Serializable
data class TagTraffic(
    val trafficId: Long,
    val tag: String,
    val note: String? = null
)

@Serializable
data class GetTaggedTraffic(
    val tag: String,
    val limit: Int = 100
)

@Serializable
data class ListTags(
    val dummy: String = ""
)

@Serializable
data class DeleteTrafficTag(
    val trafficId: Long,
    val tag: String
)

// ============== Traffic Replay & Comparison Data Classes ==============

@Serializable
data class ReplayFromDb(
    val trafficId: Long,
    val modifiedHeadersJson: String? = null,
    val modifiedBody: String? = null
)

@Serializable
data class CompareTraffic(
    val id1: Long,
    val id2: Long,
    val compareRequests: Boolean = true,
    val compareResponses: Boolean = true
)

@Serializable
data class GenerateWordlist(
    val host: String? = null,
    val includeParams: Boolean = true,
    val includePaths: Boolean = true
)
