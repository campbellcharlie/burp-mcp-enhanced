package net.portswigger.mcp.logging

import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.message.params.HttpParameter
import net.portswigger.mcp.database.TrafficItem
import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Extracts rich metadata from HTTP responses, matching sqlitedb_burp's FieldExtractor.
 * Captures both request and response data in a single pass during handleHttpResponseReceived.
 */
object FieldExtractor {

    private val TITLE_REGEX = Regex("<title[^>]*>([^<]*)</title>", RegexOption.IGNORE_CASE)
    private const val MAX_TITLE_LENGTH = 500
    private const val MAX_TITLE_SCAN_LENGTH = 8192
    private const val MAX_BODY_STORE_SIZE = 2_000_000 // 2MB cap for stored bodies
    private val ISO_FORMATTER = DateTimeFormatter.ISO_INSTANT
    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    fun extract(response: HttpResponseReceived): TrafficItem {
        val request = response.initiatingRequest()
        val httpService = request.httpService()
        val url = request.url()
        val now = Instant.now().atOffset(ZoneOffset.UTC).format(ISO_FORMATTER)

        val parsedUrl = parseUrl(url)
        val responseBodyBytes = tryOrNull { response.body()?.bytes }
        val requestBodyBytes = tryOrNull { request.body()?.bytes }

        // Cap stored body sizes to avoid memory/CPU issues with large responses
        val cappedResponseBody = responseBodyBytes?.let {
            if (it.size > MAX_BODY_STORE_SIZE) it.copyOf(MAX_BODY_STORE_SIZE) else it
        }
        val cappedRequestBody = requestBodyBytes?.let {
            if (it.size > MAX_BODY_STORE_SIZE) it.copyOf(MAX_BODY_STORE_SIZE) else it
        }

        val requestHeaders = tryOrNull {
            request.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        }
        val responseHeaders = tryOrNull {
            response.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" }
        }

        val method = request.method()
        val requestHash = calculateRequestHash(method, url, requestBodyBytes)

        // Extract content-type from headers (cheap - already parsed)
        val contentType = tryOrNull {
            response.headers().firstOrNull {
                it.name().equals("Content-Type", ignoreCase = true)
            }?.value()
        }

        // Only extract page title from HTML responses, not images/binaries
        val pageTitle = if (contentType?.contains("html", ignoreCase = true) == true) {
            extractPageTitle(responseBodyBytes)
        } else null

        return TrafficItem(
            timestamp = now,
            tool = response.toolSource().toolType().toolName(),
            method = method,
            host = httpService.host(),
            path = parsedUrl.path,
            query = parsedUrl.query,
            paramCount = tryOrNull { request.parameters()?.size },
            statusCode = tryOrNull { response.statusCode().toInt() },
            responseLength = responseBodyBytes?.size,
            requestTime = now,
            comment = tryOrNull { response.annotations()?.notes()?.ifEmpty { null } },
            protocol = if (httpService.secure()) "HTTPS" else "HTTP",
            port = httpService.port(),
            url = url,
            ipAddress = tryOrNull { httpService.ipAddress() },
            paramNames = tryOrNull { extractParamNames(request.parameters()) },
            mimeType = tryOrNull { response.mimeType()?.description() },
            extension = extractExtension(parsedUrl.path),
            pageTitle = pageTitle,
            responseTime = now,
            connectionId = tryOrNull { response.messageId().toString() },
            contentType = contentType,
            requestHash = requestHash,
            requestHeaders = requestHeaders,
            requestBody = cappedRequestBody,
            responseHeaders = responseHeaders,
            responseBody = cappedResponseBody
        )
    }

    /**
     * Extract page title from raw bytes — only scans first 8KB, avoids full body-to-string conversion.
     */
    internal fun extractPageTitle(bodyBytes: ByteArray?): String? {
        if (bodyBytes == null || bodyBytes.isEmpty()) return null
        val scanLen = minOf(bodyBytes.size, MAX_TITLE_SCAN_LENGTH)
        val scanRegion = String(bodyBytes, 0, scanLen, Charsets.UTF_8)
        val match = TITLE_REGEX.find(scanRegion) ?: return null
        val title = match.groupValues[1].trim()
        if (title.isEmpty()) return null
        return if (title.length > MAX_TITLE_LENGTH) title.substring(0, MAX_TITLE_LENGTH) else title
    }

    internal fun extractExtension(path: String?): String? {
        if (path.isNullOrEmpty()) return null
        val lastSegment = path.substringAfterLast('/')
        val dotIndex = lastSegment.lastIndexOf('.')
        if (dotIndex < 0 || dotIndex == lastSegment.length - 1) return null
        return lastSegment.substring(dotIndex + 1).lowercase()
    }

    private fun calculateRequestHash(method: String, url: String, body: ByteArray?): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(method.toByteArray())
        digest.update(url.toByteArray())
        body?.let { digest.update(it) }
        val hash = digest.digest()
        // Fast hex encoding — avoid String.format per byte
        val sb = StringBuilder(16)
        for (i in 0 until 8) {
            val b = hash[i].toInt()
            sb.append(HEX_CHARS[(b shr 4) and 0x0F])
            sb.append(HEX_CHARS[b and 0x0F])
        }
        return sb.toString()
    }

    private fun parseUrl(url: String): ParsedUrl {
        return try {
            val uri = java.net.URI(url)
            ParsedUrl(uri.path?.ifEmpty { "/" }, uri.query)
        } catch (_: Exception) {
            ParsedUrl(null, null)
        }
    }

    private fun extractParamNames(params: List<HttpParameter>?): String? {
        if (params.isNullOrEmpty()) return null
        val names = params.mapNotNull { tryOrNull { it.name() } }.distinct()
        return names.joinToString(",").ifEmpty { null }
    }

    private data class ParsedUrl(val path: String?, val query: String?)

    private inline fun <T> tryOrNull(block: () -> T?): T? {
        return try {
            block()
        } catch (_: Exception) {
            null
        }
    }
}
