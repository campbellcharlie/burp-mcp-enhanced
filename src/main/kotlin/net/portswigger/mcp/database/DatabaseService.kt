package net.portswigger.mcp.database

import burp.api.montoya.logging.Logging
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.file.Path
import java.security.MessageDigest
import java.sql.Connection
import java.sql.PreparedStatement
import java.sql.Statement
import java.util.regex.Pattern

/**
 * Main database service for traffic logging and search.
 * Uses http_traffic + http_messages schema matching sqlitedb_burp.
 */
class DatabaseService(
    dbPath: Path,
    private val logging: Logging
) : AutoCloseable {

    val databasePath: Path = dbPath.toAbsolutePath()

    private val pool = ConnectionPool(
        dbPath = dbPath.toString(),
        logging = logging,
        minConnections = 1,
        maxConnections = 4
    )

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = false
    }

    init {
        pool.withConnection { conn ->
            Schema.initialize(conn)
        }
        logging.logToOutput("Database schema v${Schema.CURRENT_VERSION} ready at ${dbPath.toAbsolutePath()}")
    }

    // ============== Traffic Operations ==============

    fun insertTraffic(item: TrafficItem): Long {
        return pool.withTransaction { conn ->
            insertTrafficInternal(conn, item)
        }
    }

    fun insertTrafficBatch(items: List<TrafficItem>): List<Long> {
        if (items.isEmpty()) return emptyList()

        return pool.withTransaction { conn ->
            items.map { insertTrafficInternal(conn, it) }
        }.filter { it >= 0 }  // Exclude skipped duplicates
    }

    private fun insertTrafficInternal(conn: Connection, item: TrafficItem): Long {
        // 1. Insert main record into http_traffic (OR IGNORE to skip duplicate request_hash)
        val trafficId = conn.prepareStatement(
            """
            INSERT OR IGNORE INTO http_traffic (
                timestamp, tool, method, host, path, query, param_count,
                status_code, response_length, request_time, comment, protocol,
                port, url, ip_address, param_names, mime_type, extension,
                page_title, response_time, connection_id, content_type,
                request_hash, session_tag, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            Statement.RETURN_GENERATED_KEYS
        ).use { stmt ->
            stmt.setString(1, item.timestamp)
            stmt.setString(2, item.tool)
            stmt.setString(3, item.method)
            stmt.setString(4, item.host)
            setNullableString(stmt, 5, item.path)
            setNullableString(stmt, 6, item.query)
            setNullableInt(stmt, 7, item.paramCount)
            setNullableInt(stmt, 8, item.statusCode)
            setNullableInt(stmt, 9, item.responseLength)
            setNullableString(stmt, 10, item.requestTime)
            setNullableString(stmt, 11, item.comment)
            stmt.setString(12, item.protocol)
            stmt.setInt(13, item.port)
            stmt.setString(14, item.url)
            setNullableString(stmt, 15, item.ipAddress)
            setNullableString(stmt, 16, item.paramNames)
            setNullableString(stmt, 17, item.mimeType)
            setNullableString(stmt, 18, item.extension)
            setNullableString(stmt, 19, item.pageTitle)
            setNullableString(stmt, 20, item.responseTime)
            setNullableString(stmt, 21, item.connectionId)
            setNullableString(stmt, 22, item.contentType)
            setNullableString(stmt, 23, item.requestHash)
            setNullableString(stmt, 24, item.sessionTag)
            setNullableString(stmt, 25, item.notes)
            val rowsInserted = stmt.executeUpdate()

            if (rowsInserted == 0) return -1  // Duplicate request_hash, skip messages + FTS

            stmt.generatedKeys.use { rs ->
                if (rs.next()) rs.getLong(1)
                else throw RuntimeException("Failed to get generated ID")
            }
        }

        // 2. Insert messages into http_messages
        conn.prepareStatement(
            "INSERT INTO http_messages (request_id, request_headers, request_body, response_headers, response_body) VALUES (?, ?, ?, ?, ?)"
        ).use { stmt ->
            stmt.setLong(1, trafficId)
            setNullableString(stmt, 2, item.requestHeaders)
            setNullableBytes(stmt, 3, item.requestBody)
            setNullableString(stmt, 4, item.responseHeaders)
            setNullableBytes(stmt, 5, item.responseBody)
            stmt.executeUpdate()
        }

        // 3. Update FTS index (cap text size to avoid indexing huge binary blobs)
        conn.prepareStatement(
            """
            INSERT INTO traffic_fts (rowid, url, request_headers, request_body, response_headers, response_body)
            VALUES (?, ?, ?, ?, ?, ?)
            """.trimIndent()
        ).use { stmt ->
            stmt.setLong(1, trafficId)
            stmt.setString(2, item.url)
            stmt.setString(3, item.requestHeaders ?: "")
            stmt.setString(4, truncateForFts(item.requestBody))
            stmt.setString(5, item.responseHeaders ?: "")
            stmt.setString(6, truncateForFts(item.responseBody))
            stmt.executeUpdate()
        }

        return trafficId
    }

    private fun setNullableString(stmt: PreparedStatement, index: Int, value: String?) {
        if (value != null) stmt.setString(index, value)
        else stmt.setNull(index, java.sql.Types.VARCHAR)
    }

    private fun setNullableInt(stmt: PreparedStatement, index: Int, value: Int?) {
        if (value != null) stmt.setInt(index, value)
        else stmt.setNull(index, java.sql.Types.INTEGER)
    }

    private fun setNullableBytes(stmt: PreparedStatement, index: Int, value: ByteArray?) {
        if (value != null) stmt.setBytes(index, value)
        else stmt.setNull(index, java.sql.Types.BLOB)
    }

    // ============== Search Operations ==============

    fun searchTraffic(
        query: String,
        method: String? = null,
        host: String? = null,
        statusCode: Int? = null,
        toolSource: String? = null,
        limit: Int = 100,
        offset: Int = 0
    ): List<TrafficSearchResult> {
        return pool.withConnection { conn ->
            val conditions = mutableListOf<String>()
            val params = mutableListOf<Any>()

            if (query.isNotBlank()) {
                conditions.add("t.request_id IN (SELECT rowid FROM traffic_fts WHERE traffic_fts MATCH ?)")
                params.add(query)
            }

            if (method != null) {
                conditions.add("t.method = ?")
                params.add(method.uppercase())
            }

            if (host != null) {
                conditions.add("t.host LIKE ?")
                params.add("%$host%")
            }

            if (statusCode != null) {
                conditions.add("t.status_code = ?")
                params.add(statusCode)
            }

            if (toolSource != null) {
                conditions.add("t.tool = ?")
                params.add(toolSource)
            }

            val whereClause = if (conditions.isNotEmpty()) {
                "WHERE ${conditions.joinToString(" AND ")}"
            } else ""

            val sql = """
                SELECT t.request_id, t.timestamp, t.tool, t.method, t.url, t.host, t.port,
                       t.protocol, t.status_code, t.response_length, t.content_type, t.session_tag,
                       t.mime_type, t.path, t.extension, t.page_title
                FROM http_traffic t
                $whereClause
                ORDER BY t.timestamp DESC
                LIMIT ? OFFSET ?
            """.trimIndent()

            conn.prepareStatement(sql).use { stmt ->
                var paramIndex = 1
                params.forEach { param ->
                    when (param) {
                        is String -> stmt.setString(paramIndex++, param)
                        is Int -> stmt.setInt(paramIndex++, param)
                        else -> stmt.setObject(paramIndex++, param)
                    }
                }
                stmt.setInt(paramIndex++, limit)
                stmt.setInt(paramIndex, offset)

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<TrafficSearchResult>()
                    while (rs.next()) {
                        results.add(
                            TrafficSearchResult(
                                id = rs.getLong("request_id"),
                                timestamp = rs.getString("timestamp"),
                                toolSource = rs.getString("tool"),
                                method = rs.getString("method"),
                                url = rs.getString("url"),
                                host = rs.getString("host"),
                                port = rs.getInt("port"),
                                isHttps = rs.getString("protocol") == "HTTPS",
                                statusCode = rs.getObject("status_code") as? Int,
                                contentLength = rs.getObject("response_length") as? Int,
                                contentType = rs.getString("content_type"),
                                sessionTag = rs.getString("session_tag")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    fun searchTrafficRegex(
        pattern: String,
        searchIn: SearchField = SearchField.RESPONSE_BODY,
        limit: Int = 100,
        host: String? = null
    ): TrafficRegexSearchResponse {
        val compiledPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)

        return pool.withConnection { conn ->
            val (joinClause, column) = when (searchIn) {
                SearchField.URL -> "" to "t.url"
                SearchField.REQUEST_HEADERS -> "LEFT JOIN http_messages m ON t.request_id = m.request_id" to "m.request_headers"
                SearchField.REQUEST_BODY -> "LEFT JOIN http_messages m ON t.request_id = m.request_id" to "m.request_body"
                SearchField.RESPONSE_HEADERS -> "LEFT JOIN http_messages m ON t.request_id = m.request_id" to "m.response_headers"
                SearchField.RESPONSE_BODY -> "LEFT JOIN http_messages m ON t.request_id = m.request_id" to "m.response_body"
            }

            val hostFilter = if (host != null) "WHERE t.host LIKE ?" else ""

            val sql = """
                SELECT t.request_id, t.timestamp, t.tool, t.method, t.url, t.host, t.port,
                       t.protocol, t.status_code, t.response_length, t.content_type, t.session_tag,
                       $column as search_content
                FROM http_traffic t
                $joinClause
                $hostFilter
                ORDER BY t.timestamp DESC
                LIMIT $MAX_SCAN_ROWS
            """.trimIndent()

            conn.prepareStatement(sql).use { stmt ->
                if (host != null) stmt.setString(1, "%$host%")

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<TrafficSearchResult>()
                    var scannedRows = 0
                    while (rs.next() && results.size < limit) {
                        scannedRows++
                        val content = when (val raw = rs.getObject("search_content")) {
                            is ByteArray -> String(raw, Charsets.UTF_8)
                            is String -> raw
                            else -> ""
                        }

                        if (compiledPattern.matcher(content).find()) {
                            results.add(
                                TrafficSearchResult(
                                    id = rs.getLong("request_id"),
                                    timestamp = rs.getString("timestamp"),
                                    toolSource = rs.getString("tool"),
                                    method = rs.getString("method"),
                                    url = rs.getString("url"),
                                    host = rs.getString("host"),
                                    port = rs.getInt("port"),
                                    isHttps = rs.getString("protocol") == "HTTPS",
                                    statusCode = rs.getObject("status_code") as? Int,
                                    contentLength = rs.getObject("response_length") as? Int,
                                    contentType = rs.getString("content_type"),
                                    sessionTag = rs.getString("session_tag")
                                )
                            )
                        }
                    }
                    TrafficRegexSearchResponse(
                        results = results,
                        scannedRows = scannedRows,
                        scanLimitReached = scannedRows >= MAX_SCAN_ROWS && results.size < limit
                    )
                }
            }
        }
    }

    fun getTrafficById(id: Long): TrafficDetail? {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                SELECT t.*,
                       m.request_headers, m.request_body,
                       m.response_headers, m.response_body
                FROM http_traffic t
                LEFT JOIN http_messages m ON t.request_id = m.request_id
                WHERE t.request_id = ?
                """.trimIndent()
            ).use { stmt ->
                stmt.setLong(1, id)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) {
                        TrafficDetail(
                            id = rs.getLong("request_id"),
                            timestamp = rs.getString("timestamp"),
                            toolSource = rs.getString("tool"),
                            method = rs.getString("method"),
                            url = rs.getString("url"),
                            host = rs.getString("host"),
                            port = rs.getInt("port"),
                            isHttps = rs.getString("protocol") == "HTTPS",
                            statusCode = rs.getObject("status_code") as? Int,
                            contentLength = rs.getObject("response_length") as? Int,
                            contentType = rs.getString("content_type"),
                            sessionTag = rs.getString("session_tag"),
                            notes = rs.getString("notes"),
                            path = rs.getString("path"),
                            query = rs.getString("query"),
                            mimeType = rs.getString("mime_type"),
                            extension = rs.getString("extension"),
                            pageTitle = rs.getString("page_title"),
                            ipAddress = rs.getString("ip_address"),
                            paramNames = rs.getString("param_names"),
                            requestHeaders = rs.getString("request_headers"),
                            requestBody = rs.getBytes("request_body"),
                            responseHeaders = rs.getString("response_headers"),
                            responseBody = rs.getBytes("response_body")
                        )
                    } else null
                }
            }
        }
    }

    fun getStats(): TrafficStats {
        return pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                val totalCount = stmt.executeQuery("SELECT COUNT(*) FROM http_traffic").use { rs ->
                    if (rs.next()) rs.getLong(1) else 0
                }

                val hostCounts = mutableMapOf<String, Long>()
                stmt.executeQuery(
                    "SELECT host, COUNT(*) as cnt FROM http_traffic GROUP BY host ORDER BY cnt DESC LIMIT 10"
                ).use { rs ->
                    while (rs.next()) {
                        hostCounts[rs.getString("host")] = rs.getLong("cnt")
                    }
                }

                val methodCounts = mutableMapOf<String, Long>()
                stmt.executeQuery(
                    "SELECT method, COUNT(*) as cnt FROM http_traffic GROUP BY method"
                ).use { rs ->
                    while (rs.next()) {
                        methodCounts[rs.getString("method")] = rs.getLong("cnt")
                    }
                }

                val statusCounts = mutableMapOf<Int, Long>()
                stmt.executeQuery(
                    "SELECT status_code, COUNT(*) as cnt FROM http_traffic WHERE status_code IS NOT NULL GROUP BY status_code"
                ).use { rs ->
                    while (rs.next()) {
                        statusCounts[rs.getInt("status_code")] = rs.getLong("cnt")
                    }
                }

                TrafficStats(
                    totalRequests = totalCount,
                    topHosts = hostCounts,
                    methodDistribution = methodCounts,
                    statusDistribution = statusCounts,
                    poolStats = pool.getStats()
                )
            }
        }
    }

    // ============== Traffic Analysis Operations ==============

    fun getEndpoints(host: String? = null, limit: Int = 500): List<EndpointInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT host, url, method, COUNT(*) as request_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM http_traffic
                WHERE host LIKE ?
                GROUP BY host, url, method
                ORDER BY request_count DESC
                LIMIT ?
                """.trimIndent()
            } else {
                """
                SELECT host, url, method, COUNT(*) as request_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM http_traffic
                GROUP BY host, url, method
                ORDER BY request_count DESC
                LIMIT ?
                """.trimIndent()
            }

            conn.prepareStatement(sql).use { stmt ->
                var idx = 1
                if (host != null) stmt.setString(idx++, "%$host%")
                stmt.setInt(idx, limit)

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<EndpointInfo>()
                    while (rs.next()) {
                        results.add(
                            EndpointInfo(
                                host = rs.getString("host"),
                                url = rs.getString("url"),
                                method = rs.getString("method"),
                                requestCount = rs.getLong("request_count"),
                                firstSeen = rs.getString("first_seen"),
                                lastSeen = rs.getString("last_seen")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    fun getParameters(host: String? = null, limit: Int = 500): List<ParameterInfo> {
        return pool.withConnection { conn ->
            // Use the pre-extracted param_names column instead of loading request bodies.
            // FieldExtractor stores comma-separated param names during traffic capture.
            val hostFilter = if (host != null) "WHERE t.host LIKE ? AND t.param_names IS NOT NULL"
                else "WHERE t.param_names IS NOT NULL"

            val sql = """
                SELECT t.host, t.url, t.param_names
                FROM http_traffic t
                $hostFilter
                ORDER BY t.timestamp DESC
                LIMIT 50000
            """.trimIndent()

            conn.prepareStatement(sql).use { stmt ->
                if (host != null) stmt.setString(1, "%$host%")

                stmt.executeQuery().use { rs ->
                    val paramMap = mutableMapOf<Triple<String, String, String>, Int>()

                    while (rs.next()) {
                        val hostName = rs.getString("host")
                        val url = rs.getString("url")
                        val paramNames = rs.getString("param_names")

                        // Query params from URL
                        extractQueryParams(url).forEach { param ->
                            val key = Triple(hostName, param, "query")
                            paramMap[key] = paramMap.getOrDefault(key, 0) + 1
                        }

                        // Stored param names (from Burp's parameter parser — includes body params)
                        if (!paramNames.isNullOrBlank()) {
                            paramNames.split(",").filter { it.isNotBlank() }.forEach { param ->
                                val key = Triple(hostName, param.trim(), "parsed")
                                paramMap[key] = paramMap.getOrDefault(key, 0) + 1
                            }
                        }
                    }

                    paramMap.entries
                        .sortedByDescending { it.value }
                        .take(limit)
                        .map { (key, count) ->
                            ParameterInfo(
                                host = key.first,
                                name = key.second,
                                location = key.third,
                                occurrences = count
                            )
                        }
                }
            }
        }
    }

    private fun extractQueryParams(url: String): List<String> {
        val queryStart = url.indexOf('?')
        if (queryStart == -1) return emptyList()

        val query = url.substring(queryStart + 1).substringBefore('#')
        return query.split('&')
            .mapNotNull { it.split('=').firstOrNull()?.takeIf { p -> p.isNotBlank() } }
            .distinct()
    }

    fun getResponseTypes(host: String? = null): List<ResponseTypeInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT content_type, COUNT(*) as count
                FROM http_traffic
                WHERE host LIKE ? AND content_type IS NOT NULL
                GROUP BY content_type
                ORDER BY count DESC
                """.trimIndent()
            } else {
                """
                SELECT content_type, COUNT(*) as count
                FROM http_traffic
                WHERE content_type IS NOT NULL
                GROUP BY content_type
                ORDER BY count DESC
                """.trimIndent()
            }

            conn.prepareStatement(sql).use { stmt ->
                if (host != null) stmt.setString(1, "%$host%")

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<ResponseTypeInfo>()
                    while (rs.next()) {
                        results.add(
                            ResponseTypeInfo(
                                contentType = rs.getString("content_type"),
                                count = rs.getLong("count")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    fun getStatusDistribution(host: String? = null): List<StatusDistributionInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT status_code, COUNT(*) as count
                FROM http_traffic
                WHERE host LIKE ? AND status_code IS NOT NULL
                GROUP BY status_code
                ORDER BY status_code
                """.trimIndent()
            } else {
                """
                SELECT status_code, COUNT(*) as count
                FROM http_traffic
                WHERE status_code IS NOT NULL
                GROUP BY status_code
                ORDER BY status_code
                """.trimIndent()
            }

            conn.prepareStatement(sql).use { stmt ->
                if (host != null) stmt.setString(1, "%$host%")

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<StatusDistributionInfo>()
                    while (rs.next()) {
                        results.add(
                            StatusDistributionInfo(
                                statusCode = rs.getInt("status_code"),
                                count = rs.getLong("count")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    // ============== Traffic Tagging Operations ==============

    fun tagTraffic(trafficId: Long, tag: String, note: String? = null): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                "INSERT INTO traffic_tags (traffic_id, tag, note) VALUES (?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            ).use { stmt ->
                stmt.setLong(1, trafficId)
                stmt.setString(2, tag)
                stmt.setString(3, note)
                stmt.executeUpdate()

                stmt.generatedKeys.use { rs ->
                    if (rs.next()) rs.getLong(1)
                    else throw RuntimeException("Failed to create tag")
                }
            }
        }
    }

    fun getTaggedTraffic(tag: String, limit: Int = 100): List<TaggedTrafficResult> {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                SELECT t.request_id, t.timestamp, t.method, t.url, t.host, t.port, t.status_code,
                       tt.tag, tt.note, tt.created_at as tag_created_at
                FROM http_traffic t
                JOIN traffic_tags tt ON t.request_id = tt.traffic_id
                WHERE tt.tag = ?
                ORDER BY t.timestamp DESC
                LIMIT ?
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, tag)
                stmt.setInt(2, limit)

                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<TaggedTrafficResult>()
                    while (rs.next()) {
                        results.add(
                            TaggedTrafficResult(
                                trafficId = rs.getLong("request_id"),
                                timestamp = rs.getString("timestamp"),
                                method = rs.getString("method"),
                                url = rs.getString("url"),
                                host = rs.getString("host"),
                                port = rs.getInt("port"),
                                statusCode = rs.getObject("status_code") as? Int,
                                tag = rs.getString("tag"),
                                note = rs.getString("note"),
                                tagCreatedAt = rs.getLong("tag_created_at")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    fun listTags(): List<TagSummary> {
        return pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeQuery(
                    """
                    SELECT tag, COUNT(*) as count, MAX(created_at) as last_used
                    FROM traffic_tags
                    GROUP BY tag
                    ORDER BY count DESC
                    """.trimIndent()
                ).use { rs ->
                    val results = mutableListOf<TagSummary>()
                    while (rs.next()) {
                        results.add(
                            TagSummary(
                                tag = rs.getString("tag"),
                                count = rs.getLong("count"),
                                lastUsed = rs.getLong("last_used")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    fun deleteTrafficTag(trafficId: Long, tag: String): Boolean {
        return pool.withConnection { conn ->
            conn.prepareStatement("DELETE FROM traffic_tags WHERE traffic_id = ? AND tag = ?").use { stmt ->
                stmt.setLong(1, trafficId)
                stmt.setString(2, tag)
                stmt.executeUpdate() > 0
            }
        }
    }

    fun generateWordlist(host: String? = null, includeParams: Boolean = true, includePaths: Boolean = true): List<String> {
        val words = mutableSetOf<String>()

        pool.withConnection { conn ->
            if (includePaths) {
                val sql = if (host != null) {
                    "SELECT DISTINCT url FROM http_traffic WHERE host LIKE ?"
                } else {
                    "SELECT DISTINCT url FROM http_traffic"
                }

                conn.prepareStatement(sql).use { stmt ->
                    if (host != null) stmt.setString(1, "%$host%")

                    stmt.executeQuery().use { rs ->
                        while (rs.next()) {
                            val url = rs.getString("url")
                            val path = url.substringBefore('?').substringBefore('#')
                            path.split('/').filter { it.isNotBlank() }.forEach { words.add(it) }
                        }
                    }
                }
            }

            if (includeParams) {
                val hostFilter = if (host != null) "WHERE host LIKE ?" else ""
                val sql = """
                    SELECT url, param_names
                    FROM http_traffic
                    $hostFilter
                """.trimIndent()

                conn.prepareStatement(sql).use { stmt ->
                    if (host != null) stmt.setString(1, "%$host%")

                    stmt.executeQuery().use { rs ->
                        while (rs.next()) {
                            val url = rs.getString("url")
                            val paramNames = rs.getString("param_names")

                            words.addAll(extractQueryParams(url))
                            if (!paramNames.isNullOrBlank()) {
                                paramNames.split(",").filter { it.isNotBlank() }.forEach {
                                    words.add(it.trim())
                                }
                            }
                        }
                    }
                }
            }
        }

        return words.toList().sorted()
    }

    // ============== Session Operations ==============

    fun createSession(name: String, cookies: Map<String, String>? = null, headers: Map<String, String>? = null): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                "INSERT INTO sessions (name, created_at, cookies, headers) VALUES (?, ?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            ).use { stmt ->
                stmt.setString(1, name)
                stmt.setLong(2, System.currentTimeMillis())
                stmt.setString(3, cookies?.let { json.encodeToString(it) })
                stmt.setString(4, headers?.let { json.encodeToString(it) })
                stmt.executeUpdate()

                stmt.generatedKeys.use { rs ->
                    if (rs.next()) rs.getLong(1)
                    else throw RuntimeException("Failed to create session")
                }
            }
        }
    }

    fun getSession(name: String): SessionInfo? {
        return pool.withConnection { conn ->
            conn.prepareStatement("SELECT * FROM sessions WHERE name = ?").use { stmt ->
                stmt.setString(1, name)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) {
                        SessionInfo(
                            id = rs.getLong("id"),
                            name = rs.getString("name"),
                            createdAt = rs.getLong("created_at"),
                            cookies = rs.getString("cookies")?.let { json.decodeFromString<Map<String, String>>(it) },
                            headers = rs.getString("headers")?.let { json.decodeFromString<Map<String, String>>(it) },
                            notes = rs.getString("notes")
                        )
                    } else null
                }
            }
        }
    }

    fun listSessions(): List<SessionInfo> {
        return pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT * FROM sessions ORDER BY created_at DESC").use { rs ->
                    val sessions = mutableListOf<SessionInfo>()
                    while (rs.next()) {
                        sessions.add(
                            SessionInfo(
                                id = rs.getLong("id"),
                                name = rs.getString("name"),
                                createdAt = rs.getLong("created_at"),
                                cookies = rs.getString("cookies")?.let { json.decodeFromString<Map<String, String>>(it) },
                                headers = rs.getString("headers")?.let { json.decodeFromString<Map<String, String>>(it) },
                                notes = rs.getString("notes")
                            )
                        )
                    }
                    sessions
                }
            }
        }
    }

    fun deleteSession(name: String): Boolean {
        return pool.withConnection { conn ->
            conn.prepareStatement("DELETE FROM sessions WHERE name = ?").use { stmt ->
                stmt.setString(1, name)
                stmt.executeUpdate() > 0
            }
        }
    }

    // ============== Template Operations ==============

    fun createTemplate(name: String, templateJson: String): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                "INSERT OR REPLACE INTO templates (name, created_at, template_json) VALUES (?, ?, ?)",
                Statement.RETURN_GENERATED_KEYS
            ).use { stmt ->
                stmt.setString(1, name)
                stmt.setLong(2, System.currentTimeMillis())
                stmt.setString(3, templateJson)
                stmt.executeUpdate()

                stmt.generatedKeys.use { rs ->
                    if (rs.next()) rs.getLong(1)
                    else throw RuntimeException("Failed to create template")
                }
            }
        }
    }

    fun getTemplate(name: String): TemplateInfo? {
        return pool.withConnection { conn ->
            conn.prepareStatement("SELECT * FROM templates WHERE name = ?").use { stmt ->
                stmt.setString(1, name)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) {
                        TemplateInfo(
                            id = rs.getLong("id"),
                            name = rs.getString("name"),
                            createdAt = rs.getLong("created_at"),
                            templateJson = rs.getString("template_json")
                        )
                    } else null
                }
            }
        }
    }

    fun listTemplates(): List<TemplateInfo> {
        return pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT * FROM templates ORDER BY name").use { rs ->
                    val templates = mutableListOf<TemplateInfo>()
                    while (rs.next()) {
                        templates.add(
                            TemplateInfo(
                                id = rs.getLong("id"),
                                name = rs.getString("name"),
                                createdAt = rs.getLong("created_at"),
                                templateJson = rs.getString("template_json")
                            )
                        )
                    }
                    templates
                }
            }
        }
    }

    fun deleteTemplate(name: String): Boolean {
        return pool.withConnection { conn ->
            conn.prepareStatement("DELETE FROM templates WHERE name = ?").use { stmt ->
                stmt.setString(1, name)
                stmt.executeUpdate() > 0
            }
        }
    }

    // ============== Raw Socket Operations ==============

    fun insertRawSocketTraffic(item: RawSocketItem): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                INSERT INTO raw_socket_traffic (
                    timestamp, tool, target_host, target_port, protocol,
                    tls_alpn, request_bytes, response_bytes, request_preview,
                    response_preview, bytes_sent, bytes_received, elapsed_ms,
                    segment_count, connection_count, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                Statement.RETURN_GENERATED_KEYS
            ).use { stmt ->
                stmt.setString(1, item.timestamp)
                stmt.setString(2, item.tool)
                stmt.setString(3, item.targetHost)
                stmt.setInt(4, item.targetPort)
                stmt.setString(5, item.protocol)
                setNullableString(stmt, 6, item.tlsAlpn)
                setNullableBytes(stmt, 7, item.requestBytes)
                setNullableBytes(stmt, 8, item.responseBytes)
                setNullableString(stmt, 9, item.requestPreview)
                setNullableString(stmt, 10, item.responsePreview)
                setNullableInt(stmt, 11, item.bytesSent)
                setNullableInt(stmt, 12, item.bytesReceived)
                stmt.setObject(13, item.elapsedMs)
                setNullableInt(stmt, 14, item.segmentCount)
                setNullableInt(stmt, 15, item.connectionCount)
                setNullableString(stmt, 16, item.notes)
                stmt.executeUpdate()

                stmt.generatedKeys.use { rs ->
                    if (rs.next()) rs.getLong(1)
                    else throw RuntimeException("Failed to get generated ID")
                }
            }
        }
    }

    // ============== Collaborator Operations ==============

    fun insertCollaboratorEvent(event: CollaboratorEvent): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                INSERT INTO collaborator_events (
                    timestamp, event_type, client_id, payload_url, custom_data,
                    interaction_type, interaction_id, dns_query, dns_query_type,
                    http_protocol, smtp_protocol, server_address, notes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """.trimIndent(),
                Statement.RETURN_GENERATED_KEYS
            ).use { stmt ->
                stmt.setString(1, event.timestamp)
                stmt.setString(2, event.eventType)
                setNullableString(stmt, 3, event.clientId)
                setNullableString(stmt, 4, event.payloadUrl)
                setNullableString(stmt, 5, event.customData)
                setNullableString(stmt, 6, event.interactionType)
                setNullableString(stmt, 7, event.interactionId)
                setNullableString(stmt, 8, event.dnsQuery)
                setNullableString(stmt, 9, event.dnsQueryType)
                setNullableString(stmt, 10, event.httpProtocol)
                setNullableString(stmt, 11, event.smtpProtocol)
                setNullableString(stmt, 12, event.serverAddress)
                setNullableString(stmt, 13, event.notes)
                stmt.executeUpdate()

                stmt.generatedKeys.use { rs ->
                    if (rs.next()) rs.getLong(1)
                    else throw RuntimeException("Failed to get generated ID")
                }
            }
        }
    }

    fun insertCollaboratorEventBatch(events: List<CollaboratorEvent>) {
        if (events.isEmpty()) return
        pool.withTransaction { conn ->
            events.forEach { event ->
                conn.prepareStatement(
                    """
                    INSERT INTO collaborator_events (
                        timestamp, event_type, client_id, payload_url, custom_data,
                        interaction_type, interaction_id, dns_query, dns_query_type,
                        http_protocol, smtp_protocol, server_address, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """.trimIndent()
                ).use { stmt ->
                    stmt.setString(1, event.timestamp)
                    stmt.setString(2, event.eventType)
                    setNullableString(stmt, 3, event.clientId)
                    setNullableString(stmt, 4, event.payloadUrl)
                    setNullableString(stmt, 5, event.customData)
                    setNullableString(stmt, 6, event.interactionType)
                    setNullableString(stmt, 7, event.interactionId)
                    setNullableString(stmt, 8, event.dnsQuery)
                    setNullableString(stmt, 9, event.dnsQueryType)
                    setNullableString(stmt, 10, event.httpProtocol)
                    setNullableString(stmt, 11, event.smtpProtocol)
                    setNullableString(stmt, 12, event.serverAddress)
                    setNullableString(stmt, 13, event.notes)
                    stmt.executeUpdate()
                }
            }
        }
    }

    // ============== Utilities ==============

    private fun truncateForFts(body: ByteArray?): String {
        if (body == null || body.isEmpty()) return ""
        // Only index first 50KB of text for FTS — skip huge binary blobs
        val maxLen = minOf(body.size, 50_000)
        return String(body, 0, maxLen, Charsets.UTF_8)
    }

    fun calculateRequestHash(method: String, url: String, body: ByteArray?): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(method.toByteArray())
        digest.update(url.toByteArray())
        body?.let { digest.update(it) }
        return digest.digest().joinToString("") { "%02x".format(it) }.take(16)
    }

    override fun close() {
        pool.close()
        logging.logToOutput("Database service closed")
    }

    companion object {
        // Cap rows scanned during in-memory regex filtering to prevent OOM in large projects.
        // At 200-500k total rows, this bounds heap usage to ~100MB worst-case (50k × ~2KB avg body).
        private const val MAX_SCAN_ROWS = 50_000
    }
}

// ============== Data Classes ==============

data class TrafficItem(
    val timestamp: String,
    val tool: String,
    val method: String,
    val host: String,
    val path: String? = null,
    val query: String? = null,
    val paramCount: Int? = null,
    val statusCode: Int? = null,
    val responseLength: Int? = null,
    val requestTime: String? = null,
    val comment: String? = null,
    val protocol: String,
    val port: Int,
    val url: String,
    val ipAddress: String? = null,
    val paramNames: String? = null,
    val mimeType: String? = null,
    val extension: String? = null,
    val pageTitle: String? = null,
    val responseTime: String? = null,
    val connectionId: String? = null,
    val contentType: String? = null,
    val requestHash: String? = null,
    val sessionTag: String? = null,
    val notes: String? = null,
    val requestHeaders: String? = null,
    val requestBody: ByteArray? = null,
    val responseHeaders: String? = null,
    val responseBody: ByteArray? = null
)

@Serializable
data class TrafficSearchResult(
    val id: Long,
    val timestamp: String,
    val toolSource: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val isHttps: Boolean,
    val statusCode: Int? = null,
    val contentLength: Int? = null,
    val contentType: String? = null,
    val sessionTag: String? = null
)

data class TrafficRegexSearchResponse(
    val results: List<TrafficSearchResult>,
    val scannedRows: Int,
    val scanLimitReached: Boolean
)

data class TrafficDetail(
    val id: Long,
    val timestamp: String,
    val toolSource: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val isHttps: Boolean,
    val statusCode: Int? = null,
    val contentLength: Int? = null,
    val contentType: String? = null,
    val sessionTag: String? = null,
    val notes: String? = null,
    val path: String? = null,
    val query: String? = null,
    val mimeType: String? = null,
    val extension: String? = null,
    val pageTitle: String? = null,
    val ipAddress: String? = null,
    val paramNames: String? = null,
    val requestHeaders: String?,
    val requestBody: ByteArray?,
    val responseHeaders: String?,
    val responseBody: ByteArray?
)

@Serializable
data class SessionInfo(
    val id: Long,
    val name: String,
    val createdAt: Long,
    val cookies: Map<String, String>? = null,
    val headers: Map<String, String>? = null,
    val notes: String? = null
)

data class TemplateInfo(
    val id: Long,
    val name: String,
    val createdAt: Long,
    val templateJson: String
)

data class TrafficStats(
    val totalRequests: Long,
    val topHosts: Map<String, Long>,
    val methodDistribution: Map<String, Long>,
    val statusDistribution: Map<Int, Long>,
    val poolStats: PoolStats
)

enum class SearchField {
    URL,
    REQUEST_HEADERS,
    REQUEST_BODY,
    RESPONSE_HEADERS,
    RESPONSE_BODY
}

data class EndpointInfo(
    val host: String,
    val url: String,
    val method: String,
    val requestCount: Long,
    val firstSeen: String,
    val lastSeen: String
)

data class ParameterInfo(
    val host: String,
    val name: String,
    val location: String,
    val occurrences: Int
)

data class ResponseTypeInfo(
    val contentType: String,
    val count: Long
)

data class StatusDistributionInfo(
    val statusCode: Int,
    val count: Long
)

data class TaggedTrafficResult(
    val trafficId: Long,
    val timestamp: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val statusCode: Int?,
    val tag: String,
    val note: String?,
    val tagCreatedAt: Long
)

data class TagSummary(
    val tag: String,
    val count: Long,
    val lastUsed: Long
)

// ============== Raw Socket Data Classes ==============

data class RawSocketItem(
    val timestamp: String,
    val tool: String,
    val targetHost: String,
    val targetPort: Int,
    val protocol: String,
    val tlsAlpn: String? = null,
    val requestBytes: ByteArray? = null,
    val responseBytes: ByteArray? = null,
    val requestPreview: String? = null,
    val responsePreview: String? = null,
    val bytesSent: Int? = null,
    val bytesReceived: Int? = null,
    val elapsedMs: Long? = null,
    val segmentCount: Int? = null,
    val connectionCount: Int? = null,
    val notes: String? = null
)

// ============== Collaborator Data Classes ==============

data class CollaboratorEvent(
    val timestamp: String,
    val eventType: String,
    val clientId: String? = null,
    val payloadUrl: String? = null,
    val customData: String? = null,
    val interactionType: String? = null,
    val interactionId: String? = null,
    val dnsQuery: String? = null,
    val dnsQueryType: String? = null,
    val httpProtocol: String? = null,
    val smtpProtocol: String? = null,
    val serverAddress: String? = null,
    val notes: String? = null
)
