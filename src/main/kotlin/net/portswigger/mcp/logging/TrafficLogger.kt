package net.portswigger.mcp.logging

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.logging.Logging
import net.portswigger.mcp.database.DatabaseService
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Captures HTTP traffic from Burp and logs it to the database.
 * Simplified to match sqlitedb_burp's approach: capture everything in handleHttpResponseReceived
 * using FieldExtractor for rich metadata extraction.
 */
class TrafficLogger(
    private val api: MontoyaApi,
    private val db: DatabaseService,
    private val logging: Logging
) : AutoCloseable {

    private val queue = TrafficQueue(db, logging)
    private val registered = AtomicBoolean(false)

    var enabled = true
    var logProxyTraffic = true
    var logRepeaterTraffic = true
    var logScannerTraffic = true
    var logIntruderTraffic = true
    var logExtensionTraffic = true

    fun register() {
        if (!registered.compareAndSet(false, true)) {
            logging.logToError("TrafficLogger already registered")
            return
        }

        // Single HttpHandler captures all traffic (proxy, repeater, scanner, etc.)
        // just like sqlitedb_burp's TrafficHttpHandler
        api.http().registerHttpHandler(HttpHandlerImpl())

        logging.logToOutput("TrafficLogger registered")
    }

    private inner class HttpHandlerImpl : HttpHandler {
        override fun handleHttpRequestToBeSent(requestToBeSent: HttpRequestToBeSent): RequestToBeSentAction {
            return RequestToBeSentAction.continueWith(requestToBeSent)
        }

        override fun handleHttpResponseReceived(responseReceived: HttpResponseReceived): ResponseReceivedAction {
            if (!enabled) {
                return ResponseReceivedAction.continueWith(responseReceived)
            }

            val toolSource = responseReceived.toolSource().toolType().toolName().lowercase()

            val shouldLog = when {
                toolSource.contains("proxy") -> logProxyTraffic
                toolSource.contains("repeater") -> logRepeaterTraffic
                toolSource.contains("scanner") -> logScannerTraffic
                toolSource.contains("intruder") -> logIntruderTraffic
                toolSource.contains("extension") -> logExtensionTraffic
                else -> true
            }

            if (shouldLog) {
                try {
                    val record = FieldExtractor.extract(responseReceived)
                    queue.enqueue(record)
                } catch (e: Exception) {
                    logging.logToError("Failed to extract traffic record: ${e.message}")
                }
            }

            return ResponseReceivedAction.continueWith(responseReceived)
        }
    }

    /**
     * Flush pending traffic to DB. Blocks until complete or timeout.
     * Call before searching to ensure recently-captured traffic is available.
     */
    fun flush(): Boolean = queue.flush()

    fun getStats(): LoggerStats {
        return LoggerStats(
            queueStats = queue.getStats(),
            enabled = enabled
        )
    }

    override fun close() {
        queue.close()
        logging.logToOutput("TrafficLogger closed")
    }
}

data class LoggerStats(
    val queueStats: QueueStats,
    val enabled: Boolean
)
