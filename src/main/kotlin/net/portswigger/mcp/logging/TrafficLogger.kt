package net.portswigger.mcp.logging

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.logging.Logging
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.TrafficItem
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Captures HTTP traffic from Burp and logs it to the database.
 *
 * CRITICAL DESIGN CONSTRAINTS:
 * 1. Handlers MUST return immediately - no blocking operations
 * 2. All database writes go through the async TrafficQueue
 * 3. Request/response correlation uses hash-based matching
 */
class TrafficLogger(
    private val api: MontoyaApi,
    private val db: DatabaseService,
    private val logging: Logging
) : AutoCloseable {

    private val queue = TrafficQueue(db, logging)
    private val registered = AtomicBoolean(false)

    // Track pending requests for response correlation
    private val pendingRequests = ConcurrentHashMap<String, Long>()

    // Configuration
    var enabled = true
    var logProxyTraffic = true
    var logRepeaterTraffic = true
    var logScannerTraffic = true
    var logIntruderTraffic = true
    var logExtensionTraffic = true

    /**
     * Register handlers with Burp. Call once during extension initialization.
     */
    fun register() {
        if (!registered.compareAndSet(false, true)) {
            logging.logToError("TrafficLogger already registered")
            return
        }

        // Register proxy handlers
        api.proxy().registerRequestHandler(ProxyRequestHandlerImpl())
        api.proxy().registerResponseHandler(ProxyResponseHandlerImpl())

        // Register HTTP handler for non-proxy traffic (Repeater, Scanner, etc.)
        api.http().registerHttpHandler(HttpHandlerImpl())

        logging.logToOutput("TrafficLogger registered")
    }

    /**
     * Proxy request handler - captures requests going through the proxy.
     */
    private inner class ProxyRequestHandlerImpl : ProxyRequestHandler {
        override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
            // Pass through on receive - we log on send
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }

        override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
            if (!enabled || !logProxyTraffic) {
                return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
            }

            try {
                val item = createTrafficItemFromInterceptedRequest(interceptedRequest, "proxy")
                queue.enqueueRequest(item)

                // Track for response correlation
                item.requestHash?.let { hash ->
                    pendingRequests[hash] = System.currentTimeMillis()
                }
            } catch (e: Exception) {
                logging.logToError("Error capturing proxy request: ${e.message}")
            }

            // MUST return immediately
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }
    }

    /**
     * Proxy response handler - captures responses coming through the proxy.
     */
    private inner class ProxyResponseHandlerImpl : ProxyResponseHandler {
        override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
            if (!enabled || !logProxyTraffic) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse)
            }

            try {
                val request = interceptedResponse.initiatingRequest()
                val requestHash = calculateRequestHash(request)

                // Only update if we have the corresponding request
                if (pendingRequests.remove(requestHash) != null) {
                    queue.enqueueResponseUpdate(
                        requestHash = requestHash,
                        statusCode = interceptedResponse.statusCode().toInt(),
                        responseHeaders = interceptedResponse.headers().joinToString("\r\n") {
                            "${it.name()}: ${it.value()}"
                        },
                        responseBody = interceptedResponse.body().bytes
                    )
                }
            } catch (e: Exception) {
                logging.logToError("Error capturing proxy response: ${e.message}")
            }

            // MUST return immediately
            return ProxyResponseReceivedAction.continueWith(interceptedResponse)
        }

        override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
            // Pass through on send
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
        }
    }

    /**
     * HTTP handler for non-proxy traffic (Repeater, Scanner, Intruder, Extensions).
     */
    private inner class HttpHandlerImpl : HttpHandler {
        override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
            if (!enabled) {
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }

            val toolSource = requestToBeSent.toolSource().toolType().toolName().lowercase()

            // Check if we should log this tool's traffic
            val shouldLog = when {
                toolSource.contains("repeater") -> logRepeaterTraffic
                toolSource.contains("scanner") -> logScannerTraffic
                toolSource.contains("intruder") -> logIntruderTraffic
                toolSource.contains("extension") -> logExtensionTraffic
                else -> true
            }

            if (!shouldLog) {
                return RequestToBeSentAction.continueWith(requestToBeSent)
            }

            try {
                val item = createTrafficItem(requestToBeSent, toolSource)
                queue.enqueueRequest(item)

                item.requestHash?.let { hash ->
                    pendingRequests[hash] = System.currentTimeMillis()
                }
            } catch (e: Exception) {
                logging.logToError("Error capturing HTTP request: ${e.message}")
            }

            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
            if (!enabled) {
                return ResponseReceivedAction.continueWith(responseReceived)
            }

            try {
                val request = responseReceived.initiatingRequest()
                val requestHash = calculateRequestHash(request)

                if (pendingRequests.remove(requestHash) != null) {
                    queue.enqueueResponseUpdate(
                        requestHash = requestHash,
                        statusCode = responseReceived.statusCode().toInt(),
                        responseHeaders = responseReceived.headers().joinToString("\r\n") {
                            "${it.name()}: ${it.value()}"
                        },
                        responseBody = responseReceived.body().bytes
                    )
                }
            } catch (e: Exception) {
                logging.logToError("Error capturing HTTP response: ${e.message}")
            }

            return ResponseReceivedAction.continueWith(responseReceived)
        }
    }

    private fun createTrafficItemFromInterceptedRequest(request: InterceptedRequest, toolSource: String): TrafficItem {
        val service = request.httpService()
        val requestHash = calculateRequestHashFromIntercepted(request)

        return TrafficItem(
            timestamp = System.currentTimeMillis(),
            toolSource = toolSource,
            method = request.method(),
            url = request.url(),
            host = service?.host() ?: "",
            port = service?.port() ?: 0,
            isHttps = service?.secure() ?: false,
            requestHash = requestHash,
            requestHeaders = request.headers().joinToString("\r\n") {
                "${it.name()}: ${it.value()}"
            },
            requestBody = request.body().bytes
        )
    }

    private fun createTrafficItem(request: HttpRequest, toolSource: String): TrafficItem {
        val service = request.httpService()
        val requestHash = calculateRequestHash(request)

        return TrafficItem(
            timestamp = System.currentTimeMillis(),
            toolSource = toolSource,
            method = request.method(),
            url = request.url(),
            host = service?.host() ?: "",
            port = service?.port() ?: 0,
            isHttps = service?.secure() ?: false,
            requestHash = requestHash,
            requestHeaders = request.headers().joinToString("\r\n") {
                "${it.name()}: ${it.value()}"
            },
            requestBody = request.body().bytes
        )
    }

    private fun calculateRequestHashFromIntercepted(request: InterceptedRequest): String {
        return db.calculateRequestHash(
            method = request.method(),
            url = request.url(),
            body = request.body().bytes
        )
    }

    private fun calculateRequestHash(request: HttpRequest): String {
        return db.calculateRequestHash(
            method = request.method(),
            url = request.url(),
            body = request.body().bytes
        )
    }

    /**
     * Get current statistics.
     */
    fun getStats(): LoggerStats {
        return LoggerStats(
            queueStats = queue.getStats(),
            pendingCorrelations = pendingRequests.size,
            enabled = enabled
        )
    }

    /**
     * Clean up stale pending requests (older than 5 minutes).
     */
    fun cleanupStalePending() {
        val cutoff = System.currentTimeMillis() - 300_000 // 5 minutes
        val stale = pendingRequests.entries.filter { it.value < cutoff }
        stale.forEach { pendingRequests.remove(it.key) }

        if (stale.isNotEmpty()) {
            logging.logToOutput("Cleaned up ${stale.size} stale pending request correlations")
        }
    }

    override fun close() {
        queue.close()
        pendingRequests.clear()
        logging.logToOutput("TrafficLogger closed")
    }
}

data class LoggerStats(
    val queueStats: QueueStats,
    val pendingCorrelations: Int,
    val enabled: Boolean
)
