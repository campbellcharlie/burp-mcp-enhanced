package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.core.ByteArray
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HistoryAccessSecurity
import net.portswigger.mcp.security.HistoryAccessType
import net.portswigger.mcp.security.HttpRequestSecurity
import java.awt.KeyboardFocusManager
import java.util.Base64
import java.util.regex.Pattern
import javax.swing.JTextArea

private suspend fun checkHistoryPermissionOrDeny(
    accessType: HistoryAccessType, config: McpConfig, api: MontoyaApi, logMessage: String
): Boolean {
    val allowed = HistoryAccessSecurity.checkHistoryAccessPermission(accessType, config)
    if (!allowed) {
        api.logging().logToOutput("MCP $logMessage access denied")
        return false
    }
    api.logging().logToOutput("MCP $logMessage access granted")
    return true
}

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun decodeBase64ToBytes(b64: String): kotlin.ByteArray =
    Base64.getDecoder().decode(b64.trim())

private fun renderBytesForDisplay(bytes: kotlin.ByteArray, maxLen: Int = 200): String {
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

fun Server.registerTools(api: MontoyaApi, config: McpConfig) {

    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")

        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")

        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp1RequestRaw>(
        "Issues an HTTP/1.1 request from base64-encoded raw bytes and returns the response. " +
            "Use this when you need byte-level control beyond the string-based send_http1_request."
    ) {
        val requestBytes = decodeBase64ToBytes(contentBase64)

        val allowed = runBlocking {
            val preview = buildString {
                appendLine("RAW HTTP/1.1 request bytes (base64 decoded):")
                appendLine("Target: $targetHostname:$targetPort")
                appendLine("Bytes: ${requestBytes.size}")
                appendLine()
                append(renderBytesForDisplay(requestBytes, maxLen = 2000))
            }
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, preview, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP RAW HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send RAW HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP RAW HTTP/1.1 request: $targetHostname:$targetPort")

        val request = HttpRequest.httpRequest(toMontoyaService(), ByteArray.byteArray(*requestBytes))
        val response = api.http().sendRequest(request)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) ->
                appendLine("$key: $value")
            }
            if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }

        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)

        response?.toString() ?: "<no response>"
    }

    mcpTool<SendHttp2RequestRaw>(
        "Issues an HTTP/2 request that supports raw (base64) header name/value bytes. " +
            "Useful for advanced HTTP/2 desync/request-tunnelling research where header bytes must be non-standard."
    ) {
        if (!usesHttps) {
            return@mcpTool "Error: HTTP/2 tool requires TLS (usesHttps=true) in this implementation."
        }

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")

        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) {
                    put(name, value)
                }
            }

            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) {
                    put(properKey, value)
                }
            }
        }

        val rawPseudoHeaderPairs = rawPseudoHeaders.map { h ->
            val nameBytes = decodeBase64ToBytes(h.nameBase64)
            val valueBytes = decodeBase64ToBytes(h.valueBase64)
            Triple(nameBytes, valueBytes, h)
        }

        // Any pseudo headers present in raw form should override their string equivalents.
        val rawPseudoHeaderNamesLower = rawPseudoHeaderPairs.map { (nameBytes, _, _) ->
            String(nameBytes, Charsets.ISO_8859_1).lowercase()
        }.toSet()

        val rawHeaderPairs = rawHeaders.map { h ->
            val nameBytes = decodeBase64ToBytes(h.nameBase64)
            val valueBytes = decodeBase64ToBytes(h.valueBase64)
            Triple(nameBytes, valueBytes, h)
        }

        // Compatibility: allow callers to provide pseudo headers via rawHeaders (tool schema may not expose
        // rawPseudoHeaders yet). We detect raw header names beginning with ":" and treat them as pseudo headers,
        // inserting them before regular headers and overriding any string pseudo headers with the same name.
        val (rawPseudoFromRawHeaders, rawRegularHeaders) = rawHeaderPairs.partition { (nameBytes, _, _) ->
            String(nameBytes, Charsets.ISO_8859_1).startsWith(":")
        }

        val effectiveRawPseudoHeaderPairs = rawPseudoHeaderPairs + rawPseudoFromRawHeaders
        val effectiveRawPseudoHeaderNamesLower = effectiveRawPseudoHeaderPairs.map { (nameBytes, _, _) ->
            String(nameBytes, Charsets.ISO_8859_1).lowercase()
        }.toSet()

        val http2RequestDisplay = buildString {
            // Display effective pseudo headers (raw pseudo headers override string ones).
            fixedPseudoHeaders.forEach { (k, v) ->
                if (!effectiveRawPseudoHeaderNamesLower.contains(k.lowercase())) {
                    appendLine("$k: $v")
                }
            }
            effectiveRawPseudoHeaderPairs.forEach { (nameBytes, valueBytes, _) ->
                appendLine("${renderBytesForDisplay(nameBytes)}: ${renderBytesForDisplay(valueBytes)}")
            }
            rawRegularHeaders.forEach { (nameBytes, valueBytes, _) ->
                appendLine("${renderBytesForDisplay(nameBytes)}: ${renderBytesForDisplay(valueBytes)}")
            }
            if (!requestBodyBase64.isNullOrBlank()) {
                val bodyBytes = decodeBase64ToBytes(requestBodyBase64)
                appendLine()
                append(renderBytesForDisplay(bodyBytes, maxLen = 2000))
            } else if (requestBody.isNotBlank()) {
                appendLine()
                append(requestBody)
            }
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP RAW HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send RAW HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP RAW HTTP/2 request: $targetHostname:$targetPort")

        val headerList = mutableListOf<HttpHeader>()

        // Pseudo headers: include raw pseudo headers first (if any), then fill in remaining from strings.
        effectiveRawPseudoHeaderPairs.forEach { (nameBytes, valueBytes, _) ->
            headerList.add(HttpHeader.httpHeader(nameBytes, valueBytes))
        }
        fixedPseudoHeaders.forEach { (k, v) ->
            if (!effectiveRawPseudoHeaderNamesLower.contains(k.lowercase())) {
                headerList.add(HttpHeader.httpHeader(k.lowercase(), v))
            }
        }

        // Raw regular headers.
        rawRegularHeaders.forEach { (nameBytes, valueBytes, _) ->
            headerList.add(HttpHeader.httpHeader(nameBytes, valueBytes))
        }

        val request = if (!requestBodyBase64.isNullOrBlank()) {
            val bodyBytes = decodeBase64ToBytes(requestBodyBase64)
            HttpRequest.http2Request(toMontoyaService(), headerList, ByteArray.byteArray(*bodyBytes))
        } else {
            HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        }

        val response = api.http().sendRequest(request, HttpMode.HTTP_2)
        response?.toString() ?: "<no response>"
    }

    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder with the specified HTTP request and optional tab name. Make sure to use carriage returns appropriately.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format. You can use this to determine the schema for available config options."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'user_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)

            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }


    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. This will be merged with existing configuration. Make sure to export before doing this, so you know what the schema is. Make sure the JSON has a top level 'project_options' object!") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)

            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }
    }

    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.HTTP_HISTORY, config, api, "HTTP history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking {
            checkHistoryPermissionOrDeny(HistoryAccessType.WEBSOCKET_HISTORY, config, api, "WebSocket history")
        }
        if (!allowed) {
            return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        }

        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED

        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) {
            api.proxy().enableIntercept()
        } else {
            api.proxy().disableIntercept()
        }

        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"

        if (!editor.isEditable) {
            return@mcpTool "<Current editor is not editable>"
        }

        editor.text = text

        "Editor text has been set"
    }
}

fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()

    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner

    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }

    return if (isInBurpWindow && permanentFocusOwner is JTextArea) {
        permanentFocusOwner
    } else {
        null
    }
}

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp1RequestRaw(
    val contentBase64: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class RawHeaderBase64(
    val nameBase64: String,
    val valueBase64: String
)

@Serializable
data class SendHttp2RequestRaw(
    val pseudoHeaders: Map<String, String>,
    // Optional raw pseudo headers (base64-encoded name/value bytes). Needed for request-tunnelling techniques
    // that require non-UTF8/CTL bytes in pseudo-header values (e.g., CRLF injection into :path).
    val rawPseudoHeaders: List<RawHeaderBase64> = emptyList(),
    val rawHeaders: List<RawHeaderBase64> = emptyList(),
    val requestBody: String = "",
    val requestBodyBase64: String? = null,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) :
    Paginated
