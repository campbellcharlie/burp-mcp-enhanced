package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.RawSocketItem
import net.portswigger.mcp.security.HttpRequestSecurity
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.io.ByteArrayOutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManager
import javax.net.ssl.X509TrustManager

private val json = Json { prettyPrint = true }

internal fun b64decode(s: String): ByteArray = Base64.getDecoder().decode(s.trim())
internal fun b64encode(b: ByteArray): String = Base64.getEncoder().encodeToString(b)

internal fun renderBytesPreview(bytes: ByteArray, maxLen: Int): String {
    val shown = bytes.take(maxLen)
    val sb = StringBuilder()
    for (b in shown) {
        val v = b.toInt() and 0xFF
        when (v) {
            0x0D -> sb.append("\\r")
            0x0A -> sb.append("\\n")
            0x09 -> sb.append("\\t")
            in 0x20..0x7E -> sb.append(v.toChar())
            else -> sb.append(String.format("\\x%02x", v))
        }
    }
    if (bytes.size > maxLen) sb.append("... (${bytes.size} bytes)")
    return sb.toString()
}

internal fun isValidWildcardMatch(hostname: String, domain: String): Boolean {
    if (domain.isEmpty() || domain.contains("*")) return false
    if (hostname.length <= domain.length) return false
    val expectedSuffix = ".$domain"
    if (!hostname.endsWith(expectedSuffix, ignoreCase = true)) return false

    val subdomain = hostname.substring(0, hostname.length - expectedSuffix.length)
    if (subdomain.isEmpty()) return false

    return subdomain.split(".").all { label ->
        label.isNotEmpty() && label.length <= 63 &&
            !label.startsWith("-") && !label.endsWith("-") &&
            label.matches(Regex("^[a-zA-Z0-9-]+$"))
    }
}

internal fun isTargetAllowed(hostname: String, port: Int, config: McpConfig): Boolean {
    val target = "$hostname:$port"
    val hostOnly = hostname
    val targets = config.getRawSocketAllowedTargetsList()

    return targets.any { approved ->
        when {
            approved.equals(target, ignoreCase = true) -> true
            approved.equals(hostOnly, ignoreCase = true) -> true
            approved.startsWith("*.") -> isValidWildcardMatch(hostname, approved.substring(2))
            else -> false
        }
    }
}

private data class SocketResult(
    val applicationProtocol: String? = null,
    val bytesRead: Int,
    val responseBase64: String,
    val responsePreview: String
)

internal fun readAllAvailable(
    socket: Socket,
    maxReadBytes: Int,
    readTimeoutMs: Int
): ByteArray {
    socket.soTimeout = readTimeoutMs
    val input = socket.getInputStream()
    val out = ByteArrayOutputStream()
    val buf = ByteArray(8192)

    while (out.size() < maxReadBytes) {
        val toRead = minOf(buf.size, maxReadBytes - out.size())
        try {
            val n = input.read(buf, 0, toRead)
            if (n <= 0) break
            out.write(buf, 0, n)
            // If the server hasn't sent more immediately, we'll rely on the timeout to end reads.
        } catch (_: SocketTimeoutException) {
            break
        }
    }

    return out.toByteArray()
}

private fun sendSegments(
    socket: Socket,
    segments: List<RawSegment>,
    flushEach: Boolean
) {
    val os = socket.getOutputStream()
    for (seg in segments) {
        val bytes = b64decode(seg.bytesBase64)
        os.write(bytes)
        if (flushEach) os.flush()
        if (seg.delayMs > 0) Thread.sleep(seg.delayMs.toLong())
    }
    os.flush()
}

internal fun buildInsecureSslContext(): SSLContext {
    val trustAll = arrayOf<TrustManager>(
        object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<java.security.cert.X509Certificate>, authType: String) {}
            override fun getAcceptedIssuers(): Array<java.security.cert.X509Certificate> = emptyArray()
        }
    )
    return SSLContext.getInstance("TLS").apply { init(null, trustAll, java.security.SecureRandom()) }
}

internal fun now(): String = Instant.now().atOffset(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT)

fun Server.registerRawSocketTools(api: MontoyaApi, config: McpConfig, db: DatabaseService? = null) {

    mcpTool<SendRawTcp>(
        "Send raw TCP bytes (base64) to a host/port with optional segmented writes and delays. " +
            "Intended for pause-based desync/smuggling research. Response is returned base64 + preview."
    ) {
        if (!config.rawSocketToolsEnabled) {
            return@mcpTool "Error: raw socket tools are disabled in Burp MCP settings."
        }
        if (!isTargetAllowed(targetHost, targetPort, config)) {
            return@mcpTool "Error: target not in raw socket allowlist."
        }
        if (segments.isEmpty()) {
            return@mcpTool "Error: segments must be non-empty."
        }
        if (segments.size > 200) {
            return@mcpTool "Error: too many segments (max 200)."
        }

        val preview = buildString {
            appendLine("RAW TCP send preview:")
            appendLine("Target: $targetHost:$targetPort")
            appendLine("Segments: ${segments.size}")
            appendLine()
            segments.take(5).forEachIndexed { idx, s ->
                val b = b64decode(s.bytesBase64)
                appendLine("seg#${idx + 1} bytes=${b.size} delayMs=${s.delayMs}")
                appendLine(renderBytesPreview(b, 200))
            }
            if (segments.size > 5) appendLine("... (${segments.size - 5} more segments)")
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHost, targetPort, config, preview, api)
        }
        if (!allowed) return@mcpTool "Send denied by Burp Suite."

        val sock = Socket()
        try {
            val startNs = System.nanoTime()
            sock.connect(InetSocketAddress(targetHost, targetPort), connectTimeoutMs)
            sendSegments(sock, segments, flushEach)
            val reqBytes = segments.flatMap { b64decode(it.bytesBase64).toList() }.toByteArray()
            val resp = readAllAvailable(sock, maxReadBytes, readTimeoutMs)
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
            val r = SocketResult(
                bytesRead = resp.size,
                responseBase64 = b64encode(resp),
                responsePreview = renderBytesPreview(resp, responsePreviewBytes)
            )

            db?.let {
                try {
                    it.insertRawSocketTraffic(RawSocketItem(
                        timestamp = now(), tool = "raw-socket-tcp",
                        targetHost = targetHost, targetPort = targetPort, protocol = "TCP",
                        requestBytes = reqBytes, responseBytes = resp,
                        requestPreview = renderBytesPreview(reqBytes, 2000),
                        responsePreview = r.responsePreview,
                        bytesSent = reqBytes.size, bytesReceived = resp.size,
                        elapsedMs = elapsedMs, segmentCount = segments.size
                    ))
                } catch (e: Exception) {
                    api.logging().logToError("Failed to log raw TCP traffic: ${e.message}")
                }
            }

            json.encodeToString(SocketResultResponse(
                applicationProtocol = r.applicationProtocol,
                bytesRead = r.bytesRead,
                responseBase64 = r.responseBase64,
                responsePreview = r.responsePreview
            ))
        } finally {
            try { sock.close() } catch (_: Exception) {}
        }
    }

    mcpTool<SendRawTls>(
        "Send raw TLS bytes (base64) with optional ALPN and segmented writes/delays. " +
            "Use for HTTP/2 frame-level experiments or pause-based attacks over TLS. " +
            "Response returned base64 + preview + negotiated ALPN."
    ) {
        if (!config.rawSocketToolsEnabled) {
            return@mcpTool "Error: raw socket tools are disabled in Burp MCP settings."
        }
        if (!isTargetAllowed(targetHost, targetPort, config)) {
            return@mcpTool "Error: target not in raw socket allowlist."
        }
        if (segments.isEmpty()) {
            return@mcpTool "Error: segments must be non-empty."
        }
        if (segments.size > 200) {
            return@mcpTool "Error: too many segments (max 200)."
        }

        val preview = buildString {
            appendLine("RAW TLS send preview:")
            appendLine("Target: $targetHost:$targetPort")
            appendLine("ALPN: ${alpnProtocols.joinToString(",")}")
            appendLine("InsecureSkipVerify: $insecureSkipVerify")
            appendLine("Segments: ${segments.size}")
            appendLine()
            segments.take(5).forEachIndexed { idx, s ->
                val b = b64decode(s.bytesBase64)
                appendLine("seg#${idx + 1} bytes=${b.size} delayMs=${s.delayMs}")
                appendLine(renderBytesPreview(b, 200))
            }
            if (segments.size > 5) appendLine("... (${segments.size - 5} more segments)")
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHost, targetPort, config, preview, api)
        }
        if (!allowed) return@mcpTool "Send denied by Burp Suite."

        val ctx = if (insecureSkipVerify) buildInsecureSslContext() else SSLContext.getDefault()
        val factory = ctx.socketFactory
        val raw = (factory.createSocket() as? SSLSocket)
            ?: return@mcpTool "Error: failed to create SSL socket"
        try {
            val startNs = System.nanoTime()
            raw.connect(InetSocketAddress(targetHost, targetPort), connectTimeoutMs)
            raw.sslParameters = raw.sslParameters.apply {
                if (alpnProtocols.isNotEmpty()) {
                    applicationProtocols = alpnProtocols.toTypedArray()
                }
            }
            raw.startHandshake()

            sendSegments(raw, segments, flushEach)
            val reqBytes = segments.flatMap { b64decode(it.bytesBase64).toList() }.toByteArray()
            val resp = readAllAvailable(raw, maxReadBytes, readTimeoutMs)
            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            val negotiatedAlpn = try { raw.applicationProtocol } catch (_: Exception) { null }
            val r = SocketResult(
                applicationProtocol = negotiatedAlpn,
                bytesRead = resp.size,
                responseBase64 = b64encode(resp),
                responsePreview = renderBytesPreview(resp, responsePreviewBytes)
            )

            db?.let {
                try {
                    it.insertRawSocketTraffic(RawSocketItem(
                        timestamp = now(), tool = "raw-socket-tls",
                        targetHost = targetHost, targetPort = targetPort, protocol = "TLS",
                        tlsAlpn = negotiatedAlpn ?: alpnProtocols.joinToString(",").ifEmpty { null },
                        requestBytes = reqBytes, responseBytes = resp,
                        requestPreview = renderBytesPreview(reqBytes, 2000),
                        responsePreview = r.responsePreview,
                        bytesSent = reqBytes.size, bytesReceived = resp.size,
                        elapsedMs = elapsedMs, segmentCount = segments.size
                    ))
                } catch (e: Exception) {
                    api.logging().logToError("Failed to log raw TLS traffic: ${e.message}")
                }
            }

            json.encodeToString(SocketResultResponse(
                applicationProtocol = r.applicationProtocol,
                bytesRead = r.bytesRead,
                responseBase64 = r.responseBase64,
                responsePreview = r.responsePreview
            ))
        } finally {
            try { raw.close() } catch (_: Exception) {}
        }
    }

    mcpTool<LastByteSyncRaw>(
        "True last-byte sync using raw TCP/TLS sockets. " +
            "Opens N connections, sends all-but-last byte, then releases the last byte simultaneously."
    ) {
        if (!config.rawSocketToolsEnabled) {
            return@mcpTool "Error: raw socket tools are disabled in Burp MCP settings."
        }
        if (!isTargetAllowed(targetHost, targetPort, config)) {
            return@mcpTool "Error: target not in raw socket allowlist."
        }
        if (count !in 2..50) {
            return@mcpTool "Error: count must be between 2 and 50."
        }

        val reqBytes = b64decode(requestBase64)
        if (reqBytes.size < 2) return@mcpTool "Error: request must be at least 2 bytes."
        if (reqBytes.size > 2_000_000) return@mcpTool "Error: request too large (max 2,000,000 bytes)."

        val preview = buildString {
            appendLine("Last-byte sync preview:")
            appendLine("Target: $targetHost:$targetPort tls=$useTls")
            appendLine("Count: $count")
            appendLine("Bytes: ${reqBytes.size}")
            appendLine()
            append(renderBytesPreview(reqBytes, 2000))
        }
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHost, targetPort, config, preview, api)
        }
        if (!allowed) return@mcpTool "Send denied by Burp Suite."

        val prefix = reqBytes.copyOf(reqBytes.size - 1)
        val last = byteArrayOf(reqBytes.last())

        val sockets = ArrayList<Socket>(count)
        val ctx = if (useTls) {
            if (insecureSkipVerify) buildInsecureSslContext() else SSLContext.getDefault()
        } else null

        try {
            // Connect + send prefix.
            repeat(count) {
                val s: Socket = if (useTls) {
                    val ssl = (ctx!!.socketFactory.createSocket() as? SSLSocket)
                        ?: throw RuntimeException("Failed to create SSL socket")
                    ssl.connect(InetSocketAddress(targetHost, targetPort), connectTimeoutMs)
                    ssl.sslParameters = ssl.sslParameters.apply {
                        if (alpnProtocols.isNotEmpty()) applicationProtocols = alpnProtocols.toTypedArray()
                    }
                    ssl.startHandshake()
                    ssl
                } else {
                    Socket().apply { connect(InetSocketAddress(targetHost, targetPort), connectTimeoutMs) }
                }
                s.soTimeout = readTimeoutMs
                s.getOutputStream().write(prefix)
                if (flushEach) s.getOutputStream().flush()
                sockets.add(s)
            }

            val ready = CountDownLatch(count)
            val go = CountDownLatch(1)
            val pool = Executors.newFixedThreadPool(count.coerceAtMost(16))

            val results = (0 until count).map { idx ->
                pool.submit<LastByteSyncResult> {
                    val s = sockets[idx]
                    ready.countDown()
                    go.await(5, TimeUnit.SECONDS)
                    val start = System.nanoTime()
                    s.getOutputStream().write(last)
                    s.getOutputStream().flush()
                    val resp = readAllAvailable(s, maxReadBytes, readTimeoutMs)
                    val elapsedMs = (System.nanoTime() - start) / 1_000_000
                    LastByteSyncResult(
                        index = idx + 1,
                        elapsedMs = elapsedMs,
                        bytesRead = resp.size,
                        responsePreview = renderBytesPreview(resp, responsePreviewBytes),
                        responseBase64 = if (includeResponseBase64) b64encode(resp) else null
                    )
                }
            }

            if (!ready.await(10, TimeUnit.SECONDS)) {
                pool.shutdownNow()
                return@mcpTool "Error: not all sockets became ready in time."
            }
            go.countDown()

            pool.shutdown()
            pool.awaitTermination((readTimeoutMs + 1000).toLong(), TimeUnit.MILLISECONDS)

            val out = results.map { it.get((readTimeoutMs + 3000).toLong(), TimeUnit.MILLISECONDS) }

            db?.let {
                try {
                    it.insertRawSocketTraffic(RawSocketItem(
                        timestamp = now(), tool = "raw-socket-lbs",
                        targetHost = targetHost, targetPort = targetPort,
                        protocol = if (useTls) "TLS" else "TCP",
                        tlsAlpn = if (useTls && alpnProtocols.isNotEmpty()) alpnProtocols.joinToString(",") else null,
                        requestBytes = reqBytes,
                        requestPreview = renderBytesPreview(reqBytes, 2000),
                        responsePreview = out.joinToString("\n") { "#${it.index}: ${it.responsePreview.take(200)}" },
                        bytesSent = reqBytes.size * count,
                        bytesReceived = out.sumOf { it.bytesRead },
                        elapsedMs = out.maxOfOrNull { it.elapsedMs },
                        connectionCount = count,
                        notes = "Last-byte sync: $count connections, spread=${out.maxOf { it.elapsedMs } - out.minOf { it.elapsedMs }}ms"
                    ))
                } catch (e: Exception) {
                    api.logging().logToError("Failed to log last-byte-sync traffic: ${e.message}")
                }
            }

            json.encodeToString(LastByteSyncResponse(out))
        } finally {
            sockets.forEach { s -> try { s.close() } catch (_: Exception) {} }
        }
    }
}

// ---------------- MCP Schemas ----------------

@Serializable
data class RawSegment(
    val bytesBase64: String,
    val delayMs: Int = 0
)

@Serializable
data class SendRawTcp(
    val targetHost: String,
    val targetPort: Int,
    val segments: List<RawSegment>,
    val connectTimeoutMs: Int = 5000,
    val readTimeoutMs: Int = 1500,
    val maxReadBytes: Int = 200_000,
    val responsePreviewBytes: Int = 2000,
    val flushEach: Boolean = true
)

@Serializable
data class SendRawTls(
    val targetHost: String,
    val targetPort: Int,
    val segments: List<RawSegment>,
    val alpnProtocols: List<String> = emptyList(),
    val insecureSkipVerify: Boolean = false,
    val connectTimeoutMs: Int = 5000,
    val readTimeoutMs: Int = 1500,
    val maxReadBytes: Int = 200_000,
    val responsePreviewBytes: Int = 2000,
    val flushEach: Boolean = true
)

@Serializable
data class SocketResultResponse(
    val applicationProtocol: String? = null,
    val bytesRead: Int,
    val responseBase64: String,
    val responsePreview: String
)

@Serializable
data class LastByteSyncRaw(
    val targetHost: String,
    val targetPort: Int,
    val useTls: Boolean = true,
    val alpnProtocols: List<String> = emptyList(),
    val insecureSkipVerify: Boolean = false,
    val requestBase64: String,
    val count: Int = 20,
    val connectTimeoutMs: Int = 5000,
    val readTimeoutMs: Int = 1500,
    val maxReadBytes: Int = 200_000,
    val responsePreviewBytes: Int = 500,
    val flushEach: Boolean = true,
    val includeResponseBase64: Boolean = false
)

@Serializable
data class LastByteSyncResult(
    val index: Int,
    val elapsedMs: Long,
    val bytesRead: Int,
    val responsePreview: String,
    val responseBase64: String? = null
)

@Serializable
data class LastByteSyncResponse(
    val results: List<LastByteSyncResult>
)
