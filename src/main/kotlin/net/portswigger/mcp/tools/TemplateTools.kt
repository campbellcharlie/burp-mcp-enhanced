package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern

// ===== Result type for structured request results =====

data class RequestResult(val statusCode: Int, val filteredResponse: String)

// ===== Shared Utilities =====

private val VARIABLE_PATTERN = Regex("""\$\{([^}]+)}""")

private fun substituteVariables(template: String, variables: Map<String, String>, jsonEscape: Boolean = false): String {
    if (variables.isEmpty()) return template
    return VARIABLE_PATTERN.replace(template) { match ->
        val key = match.groupValues[1]
        val value = variables[key] ?: throw IllegalArgumentException("Unreplaced variable: $key")
        if (jsonEscape) jsonEscapeValue(value) else value
    }
}

private fun jsonEscapeValue(value: String): String {
    return value
        .replace("\\", "\\\\")
        .replace("\"", "\\\"")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
}

fun buildHttpRequest(
    method: String,
    path: String,
    headers: Map<String, String>,
    body: String?,
    hostname: String,
    port: Int,
    usesHttps: Boolean,
    injectSession: Boolean
): String {
    val sb = StringBuilder()

    // Request line
    sb.append("$method $path HTTP/1.1\r\n")

    // Host header (skip if user provides one)
    if (!headers.keys.any { it.equals("Host", ignoreCase = true) }) {
        val isStandardPort = (usesHttps && port == 443) || (!usesHttps && port == 80)
        val hostValue = if (isStandardPort) hostname else "$hostname:$port"
        sb.append("Host: $hostValue\r\n")
    }

    // Session injection (cookies and headers from active session)
    if (injectSession) {
        val session = SessionManager.getCurrentSession()
        if (session != null) {
            if (session.cookies.isNotEmpty()) {
                val cookieHeader = session.cookies.entries.joinToString("; ") { "${it.key}=${it.value}" }
                sb.append("Cookie: $cookieHeader\r\n")
            }
            session.headers.forEach { (k, v) ->
                sb.append("$k: $v\r\n")
            }
        }
    }

    // User-provided headers (added after session headers)
    headers.forEach { (k, v) ->
        sb.append("$k: $v\r\n")
    }

    // Body and Content-Length
    if (!body.isNullOrEmpty()) {
        val bodyBytes = body.toByteArray(Charsets.UTF_8)
        if (!headers.keys.any { it.equals("Content-Length", ignoreCase = true) }) {
            sb.append("Content-Length: ${bodyBytes.size}\r\n")
        }
        sb.append("\r\n")
        sb.append(body)
    } else {
        sb.append("\r\n")
    }

    return sb.toString()
}

fun filterResponse(
    rawResponse: String,
    extractRegex: String?,
    extractGroup: Int?,
    bodyOnly: Boolean?,
    statusCode: Int = 0
): String {
    var content = rawResponse

    // Strip response headers if bodyOnly
    if (bodyOnly == true) {
        val separatorIndex = content.indexOf("\r\n\r\n")
        content = if (separatorIndex >= 0) {
            content.substring(separatorIndex + 4)
        } else {
            val nlIndex = content.indexOf("\n\n")
            if (nlIndex >= 0) content.substring(nlIndex + 2) else content
        }
    }

    // Apply regex extraction
    if (!extractRegex.isNullOrEmpty()) {
        val pattern = Pattern.compile(extractRegex, Pattern.DOTALL)
        val matcher = pattern.matcher(content)
        content = if (matcher.find()) {
            val group = extractGroup ?: 0
            try {
                matcher.group(group) ?: "<no match>"
            } catch (_: IndexOutOfBoundsException) {
                "<extractGroup $group out of bounds (${matcher.groupCount()} groups available)>"
            }
        } else {
            val preview = content.take(200)
            "<no regex match in: \"$preview\">"
        }
    }

    // Prepend status code if available
    return if (statusCode > 0) "[$statusCode] $content" else content
}

// ===== Template Manager =====

data class RequestTemplate(
    val name: String,
    val method: String,
    val path: String,
    val headers: Map<String, String>,
    val body: String?,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean,
    val injectSession: Boolean,
    val extractRegex: String?,
    val extractGroup: Int?,
    val bodyOnly: Boolean?,
    val jsonEscapeVars: Boolean? = null
) {
    fun getVariables(): Set<String> {
        val vars = mutableSetOf<String>()
        VARIABLE_PATTERN.findAll(path).forEach { vars.add(it.groupValues[1]) }
        headers.values.forEach { v ->
            VARIABLE_PATTERN.findAll(v).forEach { vars.add(it.groupValues[1]) }
        }
        body?.let { b ->
            VARIABLE_PATTERN.findAll(b).forEach { vars.add(it.groupValues[1]) }
        }
        return vars
    }
}

object TemplateManager {
    private val templates = ConcurrentHashMap<String, RequestTemplate>()

    fun get(name: String): RequestTemplate? = templates[name]

    fun set(name: String, template: RequestTemplate) {
        templates[name] = template
    }

    fun remove(name: String): Boolean = templates.remove(name) != null

    fun list(): List<String> = templates.keys.toList().sorted()

    fun getAll(): Map<String, RequestTemplate> = templates.toMap()
}

private const val MAX_BATCH_SIZE = 50

// ===== Tool Registration =====

private val templateJson = Json {
    ignoreUnknownKeys = true
    prettyPrint = false
}

@Serializable
data class SerializableTemplate(
    val name: String,
    val method: String,
    val path: String,
    val headers: Map<String, String> = emptyMap(),
    val body: String? = null,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean,
    val injectSession: Boolean = false,
    val extractRegex: String? = null,
    val extractGroup: Int? = null,
    val bodyOnly: Boolean? = null,
    val jsonEscapeVars: Boolean? = null
) {
    fun toRequestTemplate() = RequestTemplate(
        name, method, path, headers, body,
        targetHostname, targetPort, usesHttps, injectSession,
        extractRegex, extractGroup, bodyOnly, jsonEscapeVars
    )
}

private fun RequestTemplate.toSerializable() = SerializableTemplate(
    name, method, path, headers, body,
    targetHostname, targetPort, usesHttps, injectSession,
    extractRegex, extractGroup, bodyOnly, jsonEscapeVars
)

fun Server.registerTemplateTools(api: MontoyaApi, config: McpConfig, db: DatabaseService? = null) {

    // Load persisted templates from DB on startup
    if (db != null) {
        try {
            val persisted = db.listTemplates()
            persisted.forEach { info ->
                try {
                    val st = templateJson.decodeFromString<SerializableTemplate>(info.templateJson)
                    TemplateManager.set(st.name, st.toRequestTemplate())
                } catch (_: Exception) {
                    // Skip malformed templates
                }
            }
            if (persisted.isNotEmpty()) {
                api.logging().logToOutput("Loaded ${persisted.size} templates from database")
            }
        } catch (_: Exception) {
            // Table might not exist yet on first run
        }
    }

    // Shared helper: send a single request and return a RequestResult
    fun executeRequest(
        method: String,
        path: String,
        headers: Map<String, String>,
        body: String?,
        hostname: String,
        port: Int,
        usesHttps: Boolean,
        injectSession: Boolean,
        extractRegex: String?,
        extractGroup: Int?,
        bodyOnly: Boolean?
    ): RequestResult {
        val rawRequest = buildHttpRequest(method, path, headers, body, hostname, port, usesHttps, injectSession)

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(hostname, port, config, rawRequest, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $hostname:$port")
            return RequestResult(0, "Send HTTP request denied by Burp Suite")
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $hostname:$port")

        val service = HttpService.httpService(hostname, port, usesHttps)
        val request = HttpRequest.httpRequest(service, rawRequest)
        val response = api.http().sendRequest(request, HttpMode.HTTP_1)

        val statusCode = response?.response()?.statusCode()?.toInt() ?: 0
        val rawResponse = response?.response()?.toString() ?: "<no response>"
        return RequestResult(statusCode, filterResponse(rawResponse, extractRegex, extractGroup, bodyOnly, statusCode))
    }

    // Shared helper: resolve template variables and execute
    fun executeFromTemplate(template: RequestTemplate, variables: Map<String, String>): RequestResult {
        val jsonEscape = template.jsonEscapeVars == true
        val resolvedPath = substituteVariables(template.path, variables)
        val resolvedHeaders = template.headers.mapValues { (_, v) -> substituteVariables(v, variables) }
        val resolvedBody = template.body?.let { substituteVariables(it, variables, jsonEscape) }

        return executeRequest(
            template.method, resolvedPath, resolvedHeaders, resolvedBody,
            template.targetHostname, template.targetPort, template.usesHttps,
            template.injectSession, template.extractRegex, template.extractGroup, template.bodyOnly
        )
    }

    // --- register_template ---
    mcpTool<RegisterTemplate>(
        "Register a named request template for reuse. Templates support ${'$'}{VAR} placeholders " +
        "in path, header values, and body. Use send_from_template to send requests, " +
        "send_template_batch for multiple variable sets, or send_template_sequence for multi-step chains. " +
        "Set jsonEscapeVars=true to auto-escape variable values for JSON bodies."
    ) {
        val template = RequestTemplate(
            name = name,
            method = method,
            path = path,
            headers = headers ?: emptyMap(),
            body = body,
            targetHostname = targetHostname,
            targetPort = targetPort,
            usesHttps = usesHttps,
            injectSession = injectSession ?: false,
            extractRegex = extractRegex,
            extractGroup = extractGroup,
            bodyOnly = bodyOnly,
            jsonEscapeVars = jsonEscapeVars
        )

        TemplateManager.set(name, template)

        // Persist to database
        if (db != null) {
            try {
                db.createTemplate(name, templateJson.encodeToString(template.toSerializable()))
            } catch (_: Exception) {
                // Non-fatal — template is still available in memory
            }
        }

        val vars = template.getVariables()

        buildString {
            appendLine("Template '$name' registered.")
            appendLine("  Method: $method")
            appendLine("  Path: $path")
            appendLine("  Target: $targetHostname:$targetPort (${if (usesHttps) "HTTPS" else "HTTP"})")
            if (headers?.isNotEmpty() == true) appendLine("  Headers: ${headers.size}")
            if (body != null) appendLine("  Body: ${body.length} chars")
            if (vars.isNotEmpty()) appendLine("  Variables: ${vars.joinToString(", ")}")
            if (injectSession == true) appendLine("  Session injection: enabled")
            if (extractRegex != null) appendLine("  Extract regex: $extractRegex (group ${extractGroup ?: 0})")
            if (bodyOnly == true) appendLine("  Body only: enabled")
            if (jsonEscapeVars == true) appendLine("  JSON escape variables: enabled")
        }
    }

    // --- send_from_template ---
    mcpTool<SendFromTemplate>(
        "Send a single HTTP request using a registered template. Variables in ${'$'}{VAR} placeholders " +
        "are replaced in path, header values, and body. All referenced variables must be provided."
    ) {
        val template = TemplateManager.get(templateName)
            ?: return@mcpTool "Template '$templateName' not found. Use list_templates to see available templates."

        executeFromTemplate(template, variables ?: emptyMap()).filteredResponse
    }

    // --- send_template_batch ---
    mcpTool<SendTemplateBatch>(
        "Send multiple requests using the same template with different variable sets. " +
        "Max $MAX_BATCH_SIZE requests per call. Returns all results with status summary."
    ) {
        val template = TemplateManager.get(templateName)
            ?: return@mcpTool "Template '$templateName' not found."

        if (variableSets.size > MAX_BATCH_SIZE) {
            return@mcpTool "Batch size ${variableSets.size} exceeds maximum of $MAX_BATCH_SIZE."
        }

        val requestResults = mutableListOf<RequestResult>()
        val output = StringBuilder()
        variableSets.forEachIndexed { index, vars ->
            output.appendLine("=== Request ${index + 1}/${variableSets.size} ===")
            try {
                val result = executeFromTemplate(template, vars)
                requestResults.add(result)
                output.appendLine(result.filteredResponse)
            } catch (e: Exception) {
                requestResults.add(RequestResult(0, "Error: ${e.message}"))
                output.appendLine("Error: ${e.message}")
            }
            if (index < variableSets.size - 1) output.appendLine()
        }

        // Prepend status summary
        val statusCounts = requestResults.groupingBy { it.statusCode }.eachCount()
            .toSortedMap()
            .entries.joinToString(", ") { "${it.key}x${it.value}" }
        "=== Summary: $statusCounts ===\n\n${output.toString().trimEnd()}"
    }

    // --- send_template_sequence ---
    mcpTool<SendTemplateSequence>(
        "Execute an ordered sequence of template requests. Each step specifies a template name " +
        "and optional variables. Max $MAX_BATCH_SIZE steps per call. Returns all results in order with status summary."
    ) {
        if (steps.size > MAX_BATCH_SIZE) {
            return@mcpTool "Sequence size ${steps.size} exceeds maximum of $MAX_BATCH_SIZE."
        }

        val requestResults = mutableListOf<RequestResult>()
        val output = StringBuilder()
        steps.forEachIndexed { index, step ->
            val template = TemplateManager.get(step.templateName)
            output.appendLine("=== Step ${index + 1}/${steps.size}: ${step.templateName} ===")
            if (template == null) {
                requestResults.add(RequestResult(0, "Error: Template '${step.templateName}' not found."))
                output.appendLine("Error: Template '${step.templateName}' not found.")
            } else {
                try {
                    val result = executeFromTemplate(template, step.variables ?: emptyMap())
                    requestResults.add(result)
                    output.appendLine(result.filteredResponse)
                } catch (e: Exception) {
                    requestResults.add(RequestResult(0, "Error: ${e.message}"))
                    output.appendLine("Error: ${e.message}")
                }
            }
            if (index < steps.size - 1) output.appendLine()
        }

        // Prepend status summary
        val statusCounts = requestResults.groupingBy { it.statusCode }.eachCount()
            .toSortedMap()
            .entries.joinToString(", ") { "${it.key}x${it.value}" }
        "=== Summary: $statusCounts ===\n\n${output.toString().trimEnd()}"
    }

    // --- list_templates ---
    mcpTool(
        name = "list_templates",
        description = "List all registered request templates with their configuration details."
    ) {
        val templates = TemplateManager.getAll()
        if (templates.isEmpty()) {
            "No templates registered. Use register_template to create one."
        } else {
            buildString {
                appendLine("=== Templates (${templates.size}) ===")
                appendLine()
                templates.toSortedMap().forEach { (name, t) ->
                    appendLine("$name:")
                    appendLine("  ${t.method} ${t.path}")
                    appendLine("  Target: ${t.targetHostname}:${t.targetPort} (${if (t.usesHttps) "HTTPS" else "HTTP"})")
                    if (t.headers.isNotEmpty()) appendLine("  Headers: ${t.headers.keys.joinToString(", ")}")
                    if (t.body != null) appendLine("  Body: ${t.body.length} chars")
                    val vars = t.getVariables()
                    if (vars.isNotEmpty()) appendLine("  Variables: ${vars.joinToString(", ")}")
                    if (t.injectSession) appendLine("  Session injection: enabled")
                    if (t.extractRegex != null) appendLine("  Extract: /${t.extractRegex}/ group ${t.extractGroup ?: 0}")
                    if (t.bodyOnly == true) appendLine("  Body only: enabled")
                    if (t.jsonEscapeVars == true) appendLine("  JSON escape variables: enabled")
                    appendLine()
                }
            }.trimEnd()
        }
    }

    // --- delete_template ---
    mcpTool<DeleteTemplate>(
        "Delete a registered request template by name."
    ) {
        val removed = TemplateManager.remove(name)
        if (db != null) {
            try { db.deleteTemplate(name) } catch (_: Exception) {}
        }
        if (removed) {
            "Template '$name' deleted."
        } else {
            "Template '$name' not found."
        }
    }
}

// ===== Data Classes =====

@Serializable
data class RegisterTemplate(
    val name: String,
    val method: String,
    val path: String,
    val headers: Map<String, String>? = null,
    val body: String? = null,
    val targetHostname: String,
    val targetPort: Int,
    val usesHttps: Boolean,
    val injectSession: Boolean? = null,
    val extractRegex: String? = null,
    val extractGroup: Int? = null,
    val bodyOnly: Boolean? = null,
    val jsonEscapeVars: Boolean? = null
)

@Serializable
data class SendFromTemplate(
    val templateName: String,
    val variables: Map<String, String>? = null
)

@Serializable
data class SendTemplateBatch(
    val templateName: String,
    val variableSets: List<Map<String, String>>
)

@Serializable
data class TemplateStep(
    val templateName: String,
    val variables: Map<String, String>? = null
)

@Serializable
data class SendTemplateSequence(
    val steps: List<TemplateStep>
)

@Serializable
data class DeleteTemplate(val name: String)
