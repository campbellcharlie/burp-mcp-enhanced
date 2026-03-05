package net.portswigger.mcp.database

import burp.api.montoya.logging.Logging
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.nio.file.Path
import java.security.MessageDigest
import java.sql.Connection
import java.sql.Statement
import java.util.regex.Pattern

/**
 * Main database service for traffic logging and search.
 *
 * Thread-safety: Uses ConnectionPool for concurrent access.
 * WAL mode allows concurrent reads during writes.
 */
class DatabaseService(
    dbPath: Path,
    private val logging: Logging
) : AutoCloseable {

    private val pool = ConnectionPool(
        dbPath = dbPath.toString(),
        logging = logging,
        minConnections = 2,
        maxConnections = 10
    )

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = false
    }

    init {
        // Initialize schema
        pool.withConnection { conn ->
            Schema.initialize(conn)
        }
        logging.logToOutput("Database initialized at $dbPath (schema v${Schema.CURRENT_VERSION})")
    }

    // ============== Traffic Operations ==============

    /**
     * Insert a new traffic item. Returns the generated ID.
     */
    fun insertTraffic(item: TrafficItem): Long {
        return pool.withTransaction { conn ->
            insertTrafficInternal(conn, item)
        }
    }

    /**
     * Insert a batch of traffic items efficiently.
     */
    fun insertTrafficBatch(items: List<TrafficItem>): List<Long> {
        if (items.isEmpty()) return emptyList()

        return pool.withTransaction { conn ->
            items.map { insertTrafficInternal(conn, it) }
        }
    }

    private fun insertTrafficInternal(conn: Connection, item: TrafficItem): Long {
        // 1. Insert main record
        val trafficId = conn.prepareStatement(
            """
            INSERT INTO traffic (timestamp, tool_source, method, url, host, port,
                                is_https, status_code, content_length, content_type,
                                request_hash, session_tag, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """.trimIndent(),
            Statement.RETURN_GENERATED_KEYS
        ).use { stmt ->
            stmt.setLong(1, item.timestamp)
            stmt.setString(2, item.toolSource)
            stmt.setString(3, item.method)
            stmt.setString(4, item.url)
            stmt.setString(5, item.host)
            stmt.setInt(6, item.port)
            stmt.setInt(7, if (item.isHttps) 1 else 0)
            stmt.setObject(8, item.statusCode)
            stmt.setObject(9, item.contentLength)
            stmt.setString(10, item.contentType)
            stmt.setString(11, item.requestHash)
            stmt.setString(12, item.sessionTag)
            stmt.setString(13, item.notes)
            stmt.executeUpdate()

            stmt.generatedKeys.use { rs ->
                if (rs.next()) rs.getLong(1)
                else throw RuntimeException("Failed to get generated ID")
            }
        }

        // 2. Insert request data
        conn.prepareStatement(
            "INSERT INTO traffic_request_data (traffic_id, headers, body) VALUES (?, ?, ?)"
        ).use { stmt ->
            stmt.setLong(1, trafficId)
            stmt.setString(2, item.requestHeaders)
            stmt.setBytes(3, item.requestBody)
            stmt.executeUpdate()
        }

        // 3. Insert response data if present
        if (item.responseHeaders != null || item.responseBody != null) {
            conn.prepareStatement(
                "INSERT INTO traffic_response_data (traffic_id, headers, body) VALUES (?, ?, ?)"
            ).use { stmt ->
                stmt.setLong(1, trafficId)
                stmt.setString(2, item.responseHeaders)
                stmt.setBytes(3, item.responseBody)
                stmt.executeUpdate()
            }
        }

        // 4. Update FTS index
        conn.prepareStatement(
            """
            INSERT INTO traffic_fts (rowid, url, request_headers, request_body, response_headers, response_body)
            VALUES (?, ?, ?, ?, ?, ?)
            """.trimIndent()
        ).use { stmt ->
            stmt.setLong(1, trafficId)
            stmt.setString(2, item.url)
            stmt.setString(3, item.requestHeaders)
            stmt.setString(4, item.requestBody?.toString(Charsets.UTF_8) ?: "")
            stmt.setString(5, item.responseHeaders ?: "")
            stmt.setString(6, item.responseBody?.toString(Charsets.UTF_8) ?: "")
            stmt.executeUpdate()
        }

        return trafficId
    }

    /**
     * Update a traffic item with response data.
     */
    fun updateTrafficResponse(requestHash: String, statusCode: Int, headers: String, body: ByteArray?) {
        pool.withTransaction { conn ->
            // Get the traffic ID by hash
            val trafficId = conn.prepareStatement(
                "SELECT id FROM traffic WHERE request_hash = ?"
            ).use { stmt ->
                stmt.setString(1, requestHash)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) rs.getLong(1) else return@withTransaction
                }
            }

            // Update main record
            conn.prepareStatement(
                "UPDATE traffic SET status_code = ?, content_length = ? WHERE id = ?"
            ).use { stmt ->
                stmt.setInt(1, statusCode)
                stmt.setObject(2, body?.size)
                stmt.setLong(3, trafficId)
                stmt.executeUpdate()
            }

            // Insert or update response data
            conn.prepareStatement(
                """
                INSERT INTO traffic_response_data (traffic_id, headers, body)
                VALUES (?, ?, ?)
                ON CONFLICT(traffic_id) DO UPDATE SET headers = excluded.headers, body = excluded.body
                """.trimIndent()
            ).use { stmt ->
                stmt.setLong(1, trafficId)
                stmt.setString(2, headers)
                stmt.setBytes(3, body)
                stmt.executeUpdate()
            }

            // Update FTS
            conn.prepareStatement(
                """
                UPDATE traffic_fts SET response_headers = ?, response_body = ? WHERE rowid = ?
                """.trimIndent()
            ).use { stmt ->
                stmt.setString(1, headers)
                stmt.setString(2, body?.toString(Charsets.UTF_8) ?: "")
                stmt.setLong(3, trafficId)
                stmt.executeUpdate()
            }
        }
    }

    // ============== Search Operations ==============

    /**
     * Full-text search using FTS5.
     */
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

            // FTS5 query
            if (query.isNotBlank()) {
                conditions.add("t.id IN (SELECT rowid FROM traffic_fts WHERE traffic_fts MATCH ?)")
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
                conditions.add("t.tool_source = ?")
                params.add(toolSource)
            }

            val whereClause = if (conditions.isNotEmpty()) {
                "WHERE ${conditions.joinToString(" AND ")}"
            } else ""

            val sql = """
                SELECT t.id, t.timestamp, t.tool_source, t.method, t.url, t.host, t.port,
                       t.is_https, t.status_code, t.content_length, t.content_type, t.session_tag
                FROM traffic t
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
                                id = rs.getLong("id"),
                                timestamp = rs.getLong("timestamp"),
                                toolSource = rs.getString("tool_source"),
                                method = rs.getString("method"),
                                url = rs.getString("url"),
                                host = rs.getString("host"),
                                port = rs.getInt("port"),
                                isHttps = rs.getInt("is_https") == 1,
                                statusCode = rs.getObject("status_code") as? Int,
                                contentLength = rs.getObject("content_length") as? Int,
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

    /**
     * Search using regex pattern.
     */
    fun searchTrafficRegex(
        pattern: String,
        searchIn: SearchField = SearchField.RESPONSE_BODY,
        limit: Int = 100
    ): List<TrafficSearchResult> {
        val compiledPattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE)

        return pool.withConnection { conn ->
            val (table, column) = when (searchIn) {
                SearchField.URL -> "traffic" to "url"
                SearchField.REQUEST_HEADERS -> "traffic_request_data" to "headers"
                SearchField.REQUEST_BODY -> "traffic_request_data" to "body"
                SearchField.RESPONSE_HEADERS -> "traffic_response_data" to "headers"
                SearchField.RESPONSE_BODY -> "traffic_response_data" to "body"
            }

            val sql = if (table == "traffic") {
                """
                SELECT t.id, t.timestamp, t.tool_source, t.method, t.url, t.host, t.port,
                       t.is_https, t.status_code, t.content_length, t.content_type, t.session_tag,
                       t.$column as search_content
                FROM traffic t
                ORDER BY t.timestamp DESC
                """.trimIndent()
            } else {
                """
                SELECT t.id, t.timestamp, t.tool_source, t.method, t.url, t.host, t.port,
                       t.is_https, t.status_code, t.content_length, t.content_type, t.session_tag,
                       d.$column as search_content
                FROM traffic t
                LEFT JOIN $table d ON t.id = d.traffic_id
                ORDER BY t.timestamp DESC
                """.trimIndent()
            }

            conn.prepareStatement(sql).use { stmt ->
                stmt.executeQuery().use { rs ->
                    val results = mutableListOf<TrafficSearchResult>()
                    while (rs.next() && results.size < limit) {
                        val content = when (val raw = rs.getObject("search_content")) {
                            is ByteArray -> String(raw, Charsets.UTF_8)
                            is String -> raw
                            else -> ""
                        }

                        if (compiledPattern.matcher(content).find()) {
                            results.add(
                                TrafficSearchResult(
                                    id = rs.getLong("id"),
                                    timestamp = rs.getLong("timestamp"),
                                    toolSource = rs.getString("tool_source"),
                                    method = rs.getString("method"),
                                    url = rs.getString("url"),
                                    host = rs.getString("host"),
                                    port = rs.getInt("port"),
                                    isHttps = rs.getInt("is_https") == 1,
                                    statusCode = rs.getObject("status_code") as? Int,
                                    contentLength = rs.getObject("content_length") as? Int,
                                    contentType = rs.getString("content_type"),
                                    sessionTag = rs.getString("session_tag")
                                )
                            )
                        }
                    }
                    results
                }
            }
        }
    }

    /**
     * Get a specific traffic item by ID with full data.
     */
    fun getTrafficById(id: Long): TrafficDetail? {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                SELECT t.*,
                       req.headers as request_headers, req.body as request_body,
                       res.headers as response_headers, res.body as response_body
                FROM traffic t
                LEFT JOIN traffic_request_data req ON t.id = req.traffic_id
                LEFT JOIN traffic_response_data res ON t.id = res.traffic_id
                WHERE t.id = ?
                """.trimIndent()
            ).use { stmt ->
                stmt.setLong(1, id)
                stmt.executeQuery().use { rs ->
                    if (rs.next()) {
                        TrafficDetail(
                            id = rs.getLong("id"),
                            timestamp = rs.getLong("timestamp"),
                            toolSource = rs.getString("tool_source"),
                            method = rs.getString("method"),
                            url = rs.getString("url"),
                            host = rs.getString("host"),
                            port = rs.getInt("port"),
                            isHttps = rs.getInt("is_https") == 1,
                            statusCode = rs.getObject("status_code") as? Int,
                            contentLength = rs.getObject("content_length") as? Int,
                            contentType = rs.getString("content_type"),
                            sessionTag = rs.getString("session_tag"),
                            notes = rs.getString("notes"),
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

    /**
     * Get traffic statistics.
     */
    fun getStats(): TrafficStats {
        return pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                val totalCount = stmt.executeQuery("SELECT COUNT(*) FROM traffic").use { rs ->
                    if (rs.next()) rs.getLong(1) else 0
                }

                val hostCounts = mutableMapOf<String, Long>()
                stmt.executeQuery(
                    "SELECT host, COUNT(*) as cnt FROM traffic GROUP BY host ORDER BY cnt DESC LIMIT 10"
                ).use { rs ->
                    while (rs.next()) {
                        hostCounts[rs.getString("host")] = rs.getLong("cnt")
                    }
                }

                val methodCounts = mutableMapOf<String, Long>()
                stmt.executeQuery(
                    "SELECT method, COUNT(*) as cnt FROM traffic GROUP BY method"
                ).use { rs ->
                    while (rs.next()) {
                        methodCounts[rs.getString("method")] = rs.getLong("cnt")
                    }
                }

                val statusCounts = mutableMapOf<Int, Long>()
                stmt.executeQuery(
                    "SELECT status_code, COUNT(*) as cnt FROM traffic WHERE status_code IS NOT NULL GROUP BY status_code"
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

    /**
     * Get unique endpoints (URL paths) by host.
     */
    fun getEndpoints(host: String? = null, limit: Int = 500): List<EndpointInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT host, url, method, COUNT(*) as request_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM traffic
                WHERE host LIKE ?
                GROUP BY host, url, method
                ORDER BY request_count DESC
                LIMIT ?
                """.trimIndent()
            } else {
                """
                SELECT host, url, method, COUNT(*) as request_count,
                       MIN(timestamp) as first_seen, MAX(timestamp) as last_seen
                FROM traffic
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
                                firstSeen = rs.getLong("first_seen"),
                                lastSeen = rs.getLong("last_seen")
                            )
                        )
                    }
                    results
                }
            }
        }
    }

    /**
     * Extract unique parameters from query strings and request bodies.
     */
    fun getParameters(host: String? = null, limit: Int = 500): List<ParameterInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT t.host, t.url, req.body
                FROM traffic t
                LEFT JOIN traffic_request_data req ON t.id = req.traffic_id
                WHERE t.host LIKE ?
                ORDER BY t.timestamp DESC
                LIMIT 10000
                """.trimIndent()
            } else {
                """
                SELECT t.host, t.url, req.body
                FROM traffic t
                LEFT JOIN traffic_request_data req ON t.id = req.traffic_id
                ORDER BY t.timestamp DESC
                LIMIT 10000
                """.trimIndent()
            }

            conn.prepareStatement(sql).use { stmt ->
                if (host != null) stmt.setString(1, "%$host%")

                stmt.executeQuery().use { rs ->
                    val paramMap = mutableMapOf<Triple<String, String, String>, Int>()

                    while (rs.next()) {
                        val hostName = rs.getString("host")
                        val url = rs.getString("url")
                        val body = rs.getBytes("body")

                        // Extract query params from URL
                        extractQueryParams(url).forEach { param ->
                            val key = Triple(hostName, param, "query")
                            paramMap[key] = paramMap.getOrDefault(key, 0) + 1
                        }

                        // Extract body params (form data)
                        if (body != null) {
                            extractBodyParams(String(body, Charsets.UTF_8)).forEach { param ->
                                val key = Triple(hostName, param, "body")
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

    private fun extractBodyParams(body: String): List<String> {
        // Handle URL-encoded form data
        if (body.contains('=')) {
            return body.split('&')
                .mapNotNull { it.split('=').firstOrNull()?.takeIf { p -> p.isNotBlank() } }
                .distinct()
        }
        // Handle JSON (extract top-level keys)
        if (body.trimStart().startsWith('{')) {
            return try {
                val jsonRegex = """"([^"]+)":\s*""".toRegex()
                jsonRegex.findAll(body).map { it.groupValues[1] }.toList().distinct()
            } catch (e: Exception) {
                emptyList()
            }
        }
        return emptyList()
    }

    /**
     * Get response type distribution.
     */
    fun getResponseTypes(host: String? = null): List<ResponseTypeInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT content_type, COUNT(*) as count
                FROM traffic
                WHERE host LIKE ? AND content_type IS NOT NULL
                GROUP BY content_type
                ORDER BY count DESC
                """.trimIndent()
            } else {
                """
                SELECT content_type, COUNT(*) as count
                FROM traffic
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

    /**
     * Get status code distribution.
     */
    fun getStatusDistribution(host: String? = null): List<StatusDistributionInfo> {
        return pool.withConnection { conn ->
            val sql = if (host != null) {
                """
                SELECT status_code, COUNT(*) as count
                FROM traffic
                WHERE host LIKE ? AND status_code IS NOT NULL
                GROUP BY status_code
                ORDER BY status_code
                """.trimIndent()
            } else {
                """
                SELECT status_code, COUNT(*) as count
                FROM traffic
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

    /**
     * Add a tag to a traffic item.
     */
    fun tagTraffic(trafficId: Long, tag: String, note: String? = null): Long {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                "INSERT INTO traffic_tags (traffic_id, tag, note) VALUES (?, ?, ?)",
                java.sql.Statement.RETURN_GENERATED_KEYS
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

    /**
     * Get traffic items by tag.
     */
    fun getTaggedTraffic(tag: String, limit: Int = 100): List<TaggedTrafficResult> {
        return pool.withConnection { conn ->
            conn.prepareStatement(
                """
                SELECT t.id, t.timestamp, t.method, t.url, t.host, t.port, t.status_code,
                       tt.tag, tt.note, tt.created_at as tag_created_at
                FROM traffic t
                JOIN traffic_tags tt ON t.id = tt.traffic_id
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
                                trafficId = rs.getLong("id"),
                                timestamp = rs.getLong("timestamp"),
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

    /**
     * List all unique tags.
     */
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

    /**
     * Delete a tag from a traffic item.
     */
    fun deleteTrafficTag(trafficId: Long, tag: String): Boolean {
        return pool.withConnection { conn ->
            conn.prepareStatement("DELETE FROM traffic_tags WHERE traffic_id = ? AND tag = ?").use { stmt ->
                stmt.setLong(1, trafficId)
                stmt.setString(2, tag)
                stmt.executeUpdate() > 0
            }
        }
    }

    /**
     * Generate wordlist from traffic (paths, params, etc).
     */
    fun generateWordlist(host: String? = null, includeParams: Boolean = true, includePaths: Boolean = true): List<String> {
        val words = mutableSetOf<String>()

        pool.withConnection { conn ->
            if (includePaths) {
                val sql = if (host != null) {
                    "SELECT DISTINCT url FROM traffic WHERE host LIKE ?"
                } else {
                    "SELECT DISTINCT url FROM traffic"
                }

                conn.prepareStatement(sql).use { stmt ->
                    if (host != null) stmt.setString(1, "%$host%")

                    stmt.executeQuery().use { rs ->
                        while (rs.next()) {
                            val url = rs.getString("url")
                            // Extract path segments
                            val path = url.substringBefore('?').substringBefore('#')
                            path.split('/').filter { it.isNotBlank() }.forEach { words.add(it) }
                        }
                    }
                }
            }

            if (includeParams) {
                val sql = if (host != null) {
                    """
                    SELECT t.url, req.body
                    FROM traffic t
                    LEFT JOIN traffic_request_data req ON t.id = req.traffic_id
                    WHERE t.host LIKE ?
                    """.trimIndent()
                } else {
                    """
                    SELECT t.url, req.body
                    FROM traffic t
                    LEFT JOIN traffic_request_data req ON t.id = req.traffic_id
                    """.trimIndent()
                }

                conn.prepareStatement(sql).use { stmt ->
                    if (host != null) stmt.setString(1, "%$host%")

                    stmt.executeQuery().use { rs ->
                        while (rs.next()) {
                            val url = rs.getString("url")
                            val body = rs.getBytes("body")

                            words.addAll(extractQueryParams(url))
                            if (body != null) {
                                words.addAll(extractBodyParams(String(body, Charsets.UTF_8)))
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

    // ============== Utilities ==============

    /**
     * Calculate a hash for request deduplication.
     */
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
}

// ============== Data Classes ==============

data class TrafficItem(
    val timestamp: Long,
    val toolSource: String,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val isHttps: Boolean,
    val statusCode: Int? = null,
    val contentLength: Int? = null,
    val contentType: String? = null,
    val requestHash: String? = null,
    val sessionTag: String? = null,
    val notes: String? = null,
    val requestHeaders: String,
    val requestBody: ByteArray? = null,
    val responseHeaders: String? = null,
    val responseBody: ByteArray? = null
)

@Serializable
data class TrafficSearchResult(
    val id: Long,
    val timestamp: Long,
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

data class TrafficDetail(
    val id: Long,
    val timestamp: Long,
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

// ============== Traffic Analysis Data Classes ==============

data class EndpointInfo(
    val host: String,
    val url: String,
    val method: String,
    val requestCount: Long,
    val firstSeen: Long,
    val lastSeen: Long
)

data class ParameterInfo(
    val host: String,
    val name: String,
    val location: String, // "query" or "body"
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
    val timestamp: Long,
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
