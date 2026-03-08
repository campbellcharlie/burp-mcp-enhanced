package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.sitemap.SiteMapFilter
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.schema.toSerializableForm
import net.portswigger.mcp.security.HttpRequestSecurity
import java.util.regex.Pattern

private val json = Json { prettyPrint = true }

/**
 * Register sitemap enumeration tools using the Montoya SiteMap API.
 */
fun Server.registerSiteMapTools(api: MontoyaApi, config: McpConfig? = null) {

    mcpTool<GetSiteMapUrls>(
        "List all URLs discovered in the sitemap. Optionally filter by host prefix."
    ) {
        val items = if (urlPrefix != null) {
            api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix))
        } else {
            api.siteMap().requestResponses()
        }

        if (items.isEmpty()) {
            "No items found in sitemap${urlPrefix?.let { " matching '$it'" } ?: ""}"
        } else {
            val urls = items.mapNotNull { item ->
                item.request()?.let { req ->
                    val service = item.httpService()
                    val protocol = if (service?.secure() == true) "https" else "http"
                    val host = service?.host() ?: return@let null
                    val port = service.port()
                    val path = req.path() ?: "/"
                    val portSuffix = if ((protocol == "https" && port != 443) || (protocol == "http" && port != 80)) {
                        ":$port"
                    } else ""
                    "$protocol://$host$portSuffix$path"
                }
            }.distinct().take(limit)

            buildString {
                appendLine("Found ${urls.size} unique URLs in sitemap:")
                appendLine()
                urls.forEach { appendLine(it) }
                if (items.size > limit) {
                    appendLine()
                    appendLine("... and ${items.size - limit} more (use limit parameter to see more)")
                }
            }
        }
    }

    mcpTool<GetSiteMapItem>(
        "Get the full request/response for a specific URL from the sitemap."
    ) {
        val items = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(url))

        // Find exact match or closest match
        val item = items.firstOrNull { item ->
            val req = item.request() ?: return@firstOrNull false
            val service = item.httpService() ?: return@firstOrNull false
            val protocol = if (service.secure()) "https" else "http"
            val port = service.port()
            val portSuffix = if ((protocol == "https" && port != 443) || (protocol == "http" && port != 80)) {
                ":$port"
            } else ""
            val fullUrl = "$protocol://${service.host()}$portSuffix${req.path()}"
            fullUrl == url || fullUrl.startsWith(url)
        }

        if (item == null) {
            "No sitemap item found for URL: $url"
        } else {
            json.encodeToString(item.toSerializableForm())
        }
    }

    mcpTool<SearchSiteMap>(
        "Search sitemap for URLs matching a regex pattern."
    ) {
        val compiledPattern = try {
            Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)
        } catch (e: Exception) {
            return@mcpTool "Invalid regex pattern: ${e.message}"
        }

        val items = api.siteMap().requestResponses()

        val matches = items.mapNotNull { item ->
            val req = item.request() ?: return@mapNotNull null
            val service = item.httpService() ?: return@mapNotNull null
            val protocol = if (service.secure()) "https" else "http"
            val host = service.host()
            val port = service.port()
            val path = req.path() ?: "/"
            val portSuffix = if ((protocol == "https" && port != 443) || (protocol == "http" && port != 80)) {
                ":$port"
            } else ""
            val fullUrl = "$protocol://$host$portSuffix$path"

            if (compiledPattern.matcher(fullUrl).find()) {
                SiteMapMatch(
                    url = fullUrl,
                    method = req.method(),
                    statusCode = item.response()?.statusCode()?.toInt(),
                    contentType = item.response()?.headerValue("Content-Type"),
                    contentLength = item.response()?.body()?.length()
                )
            } else null
        }.distinctBy { it.url }.take(limit)

        if (matches.isEmpty()) {
            "No sitemap items found matching pattern: $pattern"
        } else {
            buildString {
                appendLine("Found ${matches.size} URLs matching /$pattern/:")
                appendLine()
                matches.forEach { m ->
                    appendLine("${m.method.padEnd(7)} ${m.url}")
                    appendLine("       Status: ${m.statusCode ?: "N/A"} | Type: ${m.contentType ?: "N/A"} | Size: ${m.contentLength ?: 0}")
                }
            }
        }
    }

    mcpTool<AddToSiteMap>(
        "Add a request/response to the sitemap manually. Useful for adding discovered endpoints."
    ) {
        val httpService = burp.api.montoya.http.HttpService.httpService(host, port, usesHttps)
        val request = HttpRequest.httpRequest(httpService, requestContent.replace("\n", "\r\n"))

        if (config != null) {
            val allowed = runBlocking {
                HttpRequestSecurity.checkHttpRequestPermission(host, port, config, requestContent, api)
            }
            if (!allowed) {
                return@mcpTool "Add to sitemap denied by security policy"
            }
        }

        val requestResponse = api.http().sendRequest(request, HttpMode.HTTP_1)

        api.siteMap().add(requestResponse)

        "Added request/response to sitemap: ${request.method()} ${request.path()}"
    }
}

// ============== Data Classes ==============

@Serializable
data class GetSiteMapUrls(
    val urlPrefix: String? = null,
    val limit: Int = 500
)

@Serializable
data class GetSiteMapItem(
    val url: String
)

@Serializable
data class SearchSiteMap(
    val pattern: String,
    val limit: Int = 100
)

@Serializable
data class AddToSiteMap(
    val host: String,
    val port: Int,
    val usesHttps: Boolean,
    val requestContent: String
)

// Internal data class for search results
private data class SiteMapMatch(
    val url: String,
    val method: String,
    val statusCode: Int?,
    val contentType: String?,
    val contentLength: Int?
)
