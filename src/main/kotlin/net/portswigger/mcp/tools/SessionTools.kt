package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.database.DatabaseService
import java.util.concurrent.ConcurrentHashMap
import java.util.regex.Pattern

private val json = Json { prettyPrint = true }

/**
 * Active session manager for in-memory session state.
 */
object SessionManager {
    private val activeSessions = ConcurrentHashMap<String, ActiveSession>()
    var currentSession: String? = null

    fun getSession(name: String): ActiveSession? = activeSessions[name]

    fun setSession(name: String, session: ActiveSession) {
        activeSessions[name] = session
    }

    fun removeSession(name: String) {
        activeSessions.remove(name)
        if (currentSession == name) currentSession = null
    }

    fun listSessions(): List<String> = activeSessions.keys.toList()

    fun getCurrentSession(): ActiveSession? = currentSession?.let { activeSessions[it] }
}

data class ActiveSession(
    val name: String,
    val cookies: MutableMap<String, String> = mutableMapOf(),
    val headers: MutableMap<String, String> = mutableMapOf(),
    var csrfToken: String? = null,
    var csrfFieldName: String? = null
)

/**
 * Register session management tools.
 */
fun Server.registerSessionTools(db: DatabaseService) {

    mcpTool<SessionCreate>(
        "Create a new named session with optional cookies and headers. " +
        "Sessions can store authentication state for testing different user contexts."
    ) {
        val session = ActiveSession(
            name = name,
            cookies = cookies?.toMutableMap() ?: mutableMapOf(),
            headers = headers?.toMutableMap() ?: mutableMapOf()
        )

        SessionManager.setSession(name, session)

        // Also persist to database
        try {
            db.createSession(name, cookies, headers)
        } catch (e: Exception) {
            // Session might already exist in DB, that's OK
        }

        buildString {
            appendLine("=== Session Created ===")
            appendLine()
            appendLine("Name: $name")
            if (cookies?.isNotEmpty() == true) {
                appendLine("Cookies: ${cookies.size}")
                cookies.forEach { (k, v) ->
                    appendLine("  $k: ${v.take(50)}${if (v.length > 50) "..." else ""}")
                }
            }
            if (headers?.isNotEmpty() == true) {
                appendLine("Headers: ${headers.size}")
                headers.forEach { (k, v) ->
                    appendLine("  $k: ${v.take(50)}${if (v.length > 50) "..." else ""}")
                }
            }
        }
    }

    mcpTool<SessionSwitch>(
        "Switch to a different session context. " +
        "Subsequent requests will use this session's cookies and headers."
    ) {
        val session = SessionManager.getSession(name)
            ?: db.getSession(name)?.let { dbSession ->
                // Load from database into memory
                ActiveSession(
                    name = dbSession.name,
                    cookies = dbSession.cookies?.toMutableMap() ?: mutableMapOf(),
                    headers = dbSession.headers?.toMutableMap() ?: mutableMapOf()
                ).also { SessionManager.setSession(name, it) }
            }

        if (session == null) {
            "Session '$name' not found. Create it first with session_create."
        } else {
            SessionManager.currentSession = name

            buildString {
                appendLine("=== Session Switched ===")
                appendLine()
                appendLine("Active session: $name")
                appendLine("Cookies: ${session.cookies.size}")
                appendLine("Headers: ${session.headers.size}")
                if (session.csrfToken != null) {
                    appendLine("CSRF Token: ${session.csrfToken?.take(20)}...")
                }
            }
        }
    }

    mcpTool<SessionList>(
        "List all available sessions."
    ) {
        val memorySessions = SessionManager.listSessions()
        val dbSessions = db.listSessions()

        val allSessions = (memorySessions + dbSessions.map { it.name }).distinct()

        if (allSessions.isEmpty()) {
            "No sessions found. Create one with session_create."
        } else {
            buildString {
                appendLine("=== Sessions ===")
                appendLine()
                appendLine("Current: ${SessionManager.currentSession ?: "(none)"}")
                appendLine()
                allSessions.forEach { name ->
                    val inMemory = memorySessions.contains(name)
                    val isCurrent = name == SessionManager.currentSession
                    val marker = if (isCurrent) " [ACTIVE]" else ""
                    val location = if (inMemory) "(memory)" else "(database)"
                    appendLine("  - $name$marker $location")
                }
            }
        }
    }

    mcpTool<SessionDelete>(
        "Delete a session from memory and database."
    ) {
        SessionManager.removeSession(name)
        val deleted = db.deleteSession(name)

        if (deleted) {
            "Session '$name' deleted."
        } else {
            "Session '$name' not found or already deleted."
        }
    }

    mcpTool<SessionUpdateCookies>(
        "Update cookies for the current or specified session. " +
        "Can parse Set-Cookie headers or accept cookie=value pairs."
    ) {
        val sessionName = session ?: SessionManager.currentSession
            ?: return@mcpTool "No active session. Switch to a session first or specify session name."

        val activeSession = SessionManager.getSession(sessionName)
            ?: return@mcpTool "Session '$sessionName' not found."

        // Parse cookies (handles both "name=value" and "Set-Cookie: name=value; ..." formats)
        val parsedCookies = mutableMapOf<String, String>()

        cookies.forEach { cookie ->
            val cleaned = cookie
                .removePrefix("Set-Cookie:")
                .trim()
                .split(";")
                .first()
                .trim()

            val parts = cleaned.split("=", limit = 2)
            if (parts.size == 2) {
                parsedCookies[parts[0].trim()] = parts[1].trim()
            }
        }

        activeSession.cookies.putAll(parsedCookies)

        buildString {
            appendLine("=== Cookies Updated ===")
            appendLine()
            appendLine("Session: $sessionName")
            appendLine("Added/Updated: ${parsedCookies.size} cookies")
            appendLine()
            appendLine("Current cookies:")
            activeSession.cookies.forEach { (k, v) ->
                appendLine("  $k: ${v.take(50)}${if (v.length > 50) "..." else ""}")
            }
        }
    }

    mcpTool<CsrfExtract>(
        "Extract CSRF tokens from an HTTP response. " +
        "Tries common patterns and stores the token in the current session."
    ) {
        val patterns = if (customPatterns.isNullOrEmpty()) {
            listOf(
                """name=["']?csrf[_-]?token["']?\s+value=["']([^"']+)""",
                """name=["']?_token["']?\s+value=["']([^"']+)""",
                """name=["']?csrfmiddlewaretoken["']?\s+value=["']([^"']+)""",
                """name=["']?authenticity_token["']?\s+value=["']([^"']+)""",
                """value=["']([^"']+)["']\s+name=["']?csrf[_-]?token["']?""",
                """<meta\s+name=["']?csrf[_-]?token["']?\s+content=["']([^"']+)""",
                """"csrf[_-]?token"\s*:\s*"([^"]+)"""",
                """"_token"\s*:\s*"([^"]+)"""",
                """X-CSRF-TOKEN['":\s]+([a-zA-Z0-9_=-]+)""",
                """X-XSRF-TOKEN['":\s]+([a-zA-Z0-9_=-]+)"""
            )
        } else {
            customPatterns
        }

        val tokens = mutableListOf<Pair<String, String>>()

        patterns.forEach { pattern ->
            try {
                val matcher = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE).matcher(response)
                while (matcher.find()) {
                    val token = matcher.group(1)
                    if (token.length >= 16) { // Minimum viable token length
                        tokens.add(pattern to token)
                    }
                }
            } catch (e: Exception) {
                // Skip invalid patterns
            }
        }

        if (tokens.isEmpty()) {
            "No CSRF tokens found in response."
        } else {
            // Store first token in session if available
            val session = SessionManager.getCurrentSession()
            if (session != null) {
                session.csrfToken = tokens.first().second
            }

            buildString {
                appendLine("=== CSRF Tokens Found ===")
                appendLine()
                tokens.forEachIndexed { i, (pattern, token) ->
                    appendLine("Token ${i + 1}:")
                    appendLine("  Value: $token")
                    appendLine("  Pattern: ${pattern.take(50)}...")
                    appendLine()
                }

                if (session != null) {
                    appendLine("Stored in session: ${session.name}")
                } else {
                    appendLine("No active session - token not stored.")
                    appendLine("Use session_switch to activate a session.")
                }
            }
        }
    }

    mcpTool<SessionGetHeaders>(
        "Get the Cookie and other session headers for the current session, " +
        "ready to be added to requests."
    ) {
        val sessionName = session ?: SessionManager.currentSession
            ?: return@mcpTool "No active session."

        val activeSession = SessionManager.getSession(sessionName)
            ?: return@mcpTool "Session '$sessionName' not found."

        buildString {
            appendLine("=== Session Headers ===")
            appendLine()
            appendLine("Session: $sessionName")
            appendLine()

            // Cookie header
            if (activeSession.cookies.isNotEmpty()) {
                val cookieHeader = activeSession.cookies.entries.joinToString("; ") {
                    "${it.key}=${it.value}"
                }
                appendLine("Cookie: $cookieHeader")
            }

            // Other headers
            activeSession.headers.forEach { (k, v) ->
                appendLine("$k: $v")
            }

            // CSRF token
            if (activeSession.csrfToken != null) {
                appendLine()
                appendLine("CSRF Token: ${activeSession.csrfToken}")
                appendLine("(Use as X-CSRF-Token header or form parameter)")
            }
        }
    }
}

// ============== Data Classes ==============

@Serializable
data class SessionCreate(
    val name: String,
    val cookies: Map<String, String>? = null,
    val headers: Map<String, String>? = null
)

@Serializable
data class SessionSwitch(val name: String)

@Serializable
data class SessionList(val dummy: String = "")

@Serializable
data class SessionDelete(val name: String)

@Serializable
data class SessionUpdateCookies(
    val cookies: List<String>,
    val session: String? = null
)

@Serializable
data class CsrfExtract(
    val response: String,
    val customPatterns: List<String>? = null
)

@Serializable
data class SessionGetHeaders(
    val session: String? = null
)
