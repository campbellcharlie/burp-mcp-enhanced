package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/**
 * Register cookie jar tools for reading and writing Burp's native cookie jar.
 */
fun Server.registerCookieJarTools(api: MontoyaApi) {

    mcpTool<GetCookieJar>(
        "Get cookies from Burp's cookie jar, optionally filtered by domain."
    ) {
        val cookies = api.http().cookieJar().cookies()

        val filtered = if (domain != null) {
            cookies.filter { it.domain().contains(domain, ignoreCase = true) }
        } else {
            cookies
        }

        if (filtered.isEmpty()) {
            if (domain != null) {
                "No cookies found for domain: $domain"
            } else {
                "Cookie jar is empty"
            }
        } else {
            buildString {
                appendLine("=== Cookie Jar (${filtered.size} cookies) ===")
                appendLine()
                filtered.forEach { cookie ->
                    appendLine("  ${cookie.name()} = ${cookie.value()}")
                    appendLine("    Domain: ${cookie.domain()}")
                    appendLine("    Path: ${cookie.path()}")
                    val exp = cookie.expiration()
                    if (exp.isPresent) {
                        appendLine("    Expires: ${exp.get()}")
                    }
                    appendLine()
                }
            }
        }
    }

    mcpTool<SetCookie>(
        "Set a cookie in Burp's cookie jar."
    ) {
        val parsedExpiration = if (expiration != null) {
            try {
                ZonedDateTime.parse(expiration, DateTimeFormatter.ISO_ZONED_DATE_TIME)
            } catch (e: Exception) {
                return@mcpTool "Error parsing expiration date: ${e.message}. Use ISO 8601 format (e.g. 2026-12-31T23:59:59Z)"
            }
        } else {
            // Default to 1 year from now
            ZonedDateTime.now().plusYears(1)
        }

        api.http().cookieJar().setCookie(name, value, path, domain, parsedExpiration)

        buildString {
            appendLine("Cookie set successfully:")
            appendLine("  Name: $name")
            appendLine("  Value: $value")
            appendLine("  Domain: $domain")
            appendLine("  Path: $path")
            appendLine("  Expires: $parsedExpiration")
        }
    }
}

// ============== Data Classes ==============

@Serializable
data class GetCookieJar(
    val domain: String? = null
)

@Serializable
data class SetCookie(
    val name: String,
    val value: String,
    val domain: String,
    val path: String = "/",
    val expiration: String? = null
)
