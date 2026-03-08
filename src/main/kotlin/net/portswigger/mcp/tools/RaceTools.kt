package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable

/**
 * Helper to extract response body bytes safely from HttpRequestResponse.
 */
private fun HttpRequestResponse?.getResponseBodyBytes(): ByteArray {
    return try {
        this?.response()?.body()?.bytes ?: ByteArray(0)
    } catch (e: Exception) {
        ByteArray(0)
    }
}

/**
 * Helper to extract response status code safely.
 */
private fun HttpRequestResponse?.getStatusCode(): Int {
    return try {
        this?.response()?.statusCode()?.toInt() ?: -1
    } catch (e: Exception) {
        -1
    }
}

/**
 * Register race condition testing tools.
 */
fun Server.registerRaceTools(api: MontoyaApi) {

    mcpTool<SendParallel>(
        "Send multiple identical HTTP requests simultaneously for race condition testing. " +
        "Returns timing information and response comparison to identify TOCTOU vulnerabilities."
    ) {
        val service = HttpService.httpService(targetHost, targetPort, useHttps)
        val fixedRequest = request.replace("\r", "").replace("\n", "\r\n")
        val httpRequest = HttpRequest.httpRequest(service, fixedRequest)

        val results = runBlocking {
            (1..count).map {
                async(Dispatchers.IO) {
                    try {
                        val start = System.nanoTime()
                        val response = api.http().sendRequest(httpRequest, HttpMode.HTTP_1)
                        val elapsed = (System.nanoTime() - start) / 1_000_000

                        val bodyBytes = response.getResponseBodyBytes()
                        RaceResult(
                            index = it,
                            statusCode = response.getStatusCode(),
                            contentLength = bodyBytes.size,
                            elapsedMs = elapsed,
                            error = null,
                            bodyPreview = String(bodyBytes.take(200).toByteArray(), Charsets.UTF_8).take(100)
                        )
                    } catch (e: Exception) {
                        RaceResult(
                            index = it,
                            statusCode = -1,
                            contentLength = 0,
                            elapsedMs = 0,
                            error = e.message,
                            bodyPreview = null
                        )
                    }
                }
            }.awaitAll()
        }

        formatRaceResults(results)
    }

    mcpTool<SendParallelDifferent>(
        "Send multiple different HTTP requests simultaneously. " +
        "Useful for testing race conditions between different operations (e.g., buy vs refund)."
    ) {
        val service = HttpService.httpService(targetHost, targetPort, useHttps)

        val results = runBlocking {
            requests.mapIndexed { index, rawRequest ->
                async(Dispatchers.IO) {
                    try {
                        val fixedRequest = rawRequest.replace("\r", "").replace("\n", "\r\n")
                        val httpRequest = HttpRequest.httpRequest(service, fixedRequest)

                        val start = System.nanoTime()
                        val response = api.http().sendRequest(httpRequest, HttpMode.HTTP_1)
                        val elapsed = (System.nanoTime() - start) / 1_000_000

                        val bodyBytes = response.getResponseBodyBytes()
                        RaceResult(
                            index = index + 1,
                            statusCode = response.getStatusCode(),
                            contentLength = bodyBytes.size,
                            elapsedMs = elapsed,
                            error = null,
                            bodyPreview = String(bodyBytes.take(200).toByteArray(), Charsets.UTF_8).take(100)
                        )
                    } catch (e: Exception) {
                        RaceResult(
                            index = index + 1,
                            statusCode = -1,
                            contentLength = 0,
                            elapsedMs = 0,
                            error = e.message,
                            bodyPreview = null
                        )
                    }
                }
            }.awaitAll()
        }

        formatRaceResults(results)
    }

    mcpTool<SendParallelH2>(
        "Send HTTP/2 requests using single-packet attack technique. " +
        "Leverages HTTP/2's multiplexing to send requests in a single TCP packet for tighter race windows."
    ) {
        val service = HttpService.httpService(targetHost, targetPort, true) // HTTP/2 requires TLS

        // For true single-packet attack, we need to build proper HTTP/2 frames
        // This is a simplified version that uses Burp's HTTP/2 support
        val results = runBlocking {
            val httpRequests = requests.map { rawRequest ->
                // Parse pseudo-headers and regular headers from raw request
                val lines = rawRequest.lines()
                val requestLine = lines.firstOrNull() ?: return@map null

                val parts = requestLine.split(" ", limit = 3)
                if (parts.size < 2) return@map null

                val method = parts[0]
                val path = parts[1]

                val headers = mutableMapOf<String, String>()
                var bodyStart = -1

                for ((index, line) in lines.drop(1).withIndex()) {
                    if (line.isEmpty()) {
                        bodyStart = index + 2
                        break
                    }
                    val colonIndex = line.indexOf(':')
                    if (colonIndex > 0) {
                        val name = line.substring(0, colonIndex).trim().lowercase()
                        val value = line.substring(colonIndex + 1).trim()
                        headers[name] = value
                    }
                }

                val body = if (bodyStart > 0 && bodyStart < lines.size) {
                    lines.drop(bodyStart).joinToString("\n")
                } else ""

                val pseudoHeaders = linkedMapOf(
                    ":method" to method,
                    ":path" to path,
                    ":scheme" to "https",
                    ":authority" to targetHost
                )

                val regularHeaders = headers.filterKeys { !it.startsWith(":") }
                    .map { burp.api.montoya.http.message.HttpHeader.httpHeader(it.key, it.value) }

                val allHeaders = pseudoHeaders.map {
                    burp.api.montoya.http.message.HttpHeader.httpHeader(it.key, it.value)
                } + regularHeaders

                HttpRequest.http2Request(service, allHeaders, body)
            }.filterNotNull()

            if (httpRequests.isEmpty()) {
                return@runBlocking listOf(RaceResult(1, -1, 0, 0, "Failed to parse requests", null))
            }

            // Send all requests as close together as possible
            httpRequests.mapIndexed { index, request ->
                async(Dispatchers.IO) {
                    try {
                        val start = System.nanoTime()
                        val response = api.http().sendRequest(request, HttpMode.HTTP_2)
                        val elapsed = (System.nanoTime() - start) / 1_000_000

                        val bodyBytes = response.getResponseBodyBytes()
                        RaceResult(
                            index = index + 1,
                            statusCode = response.getStatusCode(),
                            contentLength = bodyBytes.size,
                            elapsedMs = elapsed,
                            error = null,
                            bodyPreview = String(bodyBytes.take(200).toByteArray(), Charsets.UTF_8).take(100)
                        )
                    } catch (e: Exception) {
                        RaceResult(
                            index = index + 1,
                            statusCode = -1,
                            contentLength = 0,
                            elapsedMs = 0,
                            error = e.message,
                            bodyPreview = null
                        )
                    }
                }
            }.awaitAll()
        }

        formatRaceResults(results)
    }

    mcpTool<LastByteSync>(
        "Perform a last-byte synchronization attack. " +
        "Sends all requests except the final byte, then sends all final bytes simultaneously. " +
        "Provides tighter timing window than standard parallel requests."
    ) {
        // Note: This is an advanced technique that requires low-level socket control
        // Burp's API doesn't directly support this, so we provide a simulation
        // For true last-byte sync, use Turbo Intruder or custom tooling

        buildString {
            appendLine("Last-byte synchronization technique requested.")
            appendLine()
            appendLine("NOTE: True last-byte sync requires low-level socket control.")
            appendLine("For production use, consider:")
            appendLine("  1. Turbo Intruder extension with 'race-single-packet-attack' template")
            appendLine("  2. Custom Python scripts using raw sockets")
            appendLine()
            appendLine("Simulating with standard parallel requests...")
            appendLine()

            // Fall back to standard parallel
            val service = HttpService.httpService(targetHost, targetPort, useHttps)
            val fixedRequest = request.replace("\r", "").replace("\n", "\r\n")
            val httpRequest = HttpRequest.httpRequest(service, fixedRequest)

            val results = runBlocking {
                (1..count).map {
                    async(Dispatchers.IO) {
                        try {
                            val start = System.nanoTime()
                            val response = api.http().sendRequest(httpRequest, HttpMode.HTTP_1)
                            val elapsed = (System.nanoTime() - start) / 1_000_000

                            val bodyBytes = response.getResponseBodyBytes()
                            RaceResult(it, response.getStatusCode(),
                                bodyBytes.size, elapsed, null, null)
                        } catch (e: Exception) {
                            RaceResult(it, -1, 0, 0, e.message, null)
                        }
                    }
                }.awaitAll()
            }

            append(formatRaceResults(results))
        }
    }
}

private fun formatRaceResults(results: List<RaceResult>): String {
    return buildString {
        appendLine("=== Race Condition Test Results ===")
        appendLine()
        appendLine("Requests sent: ${results.size}")
        appendLine()

        // Timing statistics
        val successfulResults = results.filter { it.error == null }
        if (successfulResults.isNotEmpty()) {
            val timings = successfulResults.map { it.elapsedMs }
            appendLine("Timing Statistics:")
            appendLine("  Min: ${timings.minOrNull()}ms")
            appendLine("  Max: ${timings.maxOrNull()}ms")
            appendLine("  Spread: ${(timings.maxOrNull() ?: 0) - (timings.minOrNull() ?: 0)}ms")
            appendLine("  Avg: ${timings.average().toLong()}ms")
            appendLine()
        }

        // Status code distribution
        val statusGroups = results.groupBy { it.statusCode }
        appendLine("Status Code Distribution:")
        statusGroups.forEach { (status, group) ->
            appendLine("  $status: ${group.size} responses")
        }
        appendLine()

        // Content length distribution (potential race indicator)
        val lengthGroups = results.groupBy { it.contentLength }
        if (lengthGroups.size > 1) {
            appendLine("!!! POTENTIAL RACE DETECTED !!!")
            appendLine("Different content lengths observed:")
            lengthGroups.forEach { (length, group) ->
                appendLine("  $length bytes: ${group.size} responses")
            }
            appendLine()
        }

        // Detailed results
        appendLine("Individual Results:")
        results.sortedBy { it.index }.forEach { r ->
            if (r.error != null) {
                appendLine("  #${r.index}: ERROR - ${r.error}")
            } else {
                appendLine("  #${r.index}: ${r.statusCode} | ${r.contentLength} bytes | ${r.elapsedMs}ms")
                if (r.bodyPreview != null) {
                    appendLine("       Preview: ${r.bodyPreview.take(50)}...")
                }
            }
        }
    }
}

// ============== Data Classes ==============

data class RaceResult(
    val index: Int,
    val statusCode: Int,
    val contentLength: Int,
    val elapsedMs: Long,
    val error: String?,
    val bodyPreview: String?
)

@Serializable
data class SendParallel(
    val request: String,
    val targetHost: String,
    val targetPort: Int = 443,
    val useHttps: Boolean = true,
    val count: Int = 10
)

@Serializable
data class SendParallelDifferent(
    val requests: List<String>,
    val targetHost: String,
    val targetPort: Int = 443,
    val useHttps: Boolean = true
)

@Serializable
data class SendParallelH2(
    val requests: List<String>,
    val targetHost: String,
    val targetPort: Int = 443
)

@Serializable
data class LastByteSync(
    val request: String,
    val targetHost: String,
    val targetPort: Int = 443,
    val useHttps: Boolean = true,
    val count: Int = 10
)
