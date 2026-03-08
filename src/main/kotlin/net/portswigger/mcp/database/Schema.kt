package net.portswigger.mcp.database

import java.sql.Connection

/**
 * Database schema matching sqlitedb_burp's structure with rich metadata fields,
 * plus additional MCP-specific tables (FTS5, sessions, tags).
 */
object Schema {

    const val CURRENT_VERSION = 4

    fun initialize(conn: Connection) {
        val currentVersion = getVersion(conn)

        // Migrate from old schema or fix broken state
        if (currentVersion in 1..2 || hasOldTables(conn)) {
            migrateFromV2(conn)
        }

        // v3 → v4: add templates table
        if (currentVersion == 3) {
            migrateV3toV4(conn)
        }

        conn.createStatement().use { stmt ->
            // Schema version tracking
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                )
            """.trimIndent())

            // Main traffic table - matches sqlitedb_burp's http_traffic with additional MCP fields
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS http_traffic (
                    request_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp     TEXT    NOT NULL,
                    tool          TEXT    NOT NULL,
                    method        TEXT    NOT NULL,
                    host          TEXT    NOT NULL,
                    path          TEXT,
                    query         TEXT,
                    param_count   INTEGER,
                    status_code   INTEGER,
                    response_length INTEGER,
                    request_time  TEXT,
                    comment       TEXT,
                    protocol      TEXT    NOT NULL,
                    port          INTEGER NOT NULL,
                    url           TEXT    NOT NULL,
                    ip_address    TEXT,
                    param_names   TEXT,
                    mime_type     TEXT,
                    extension     TEXT,
                    page_title    TEXT,
                    response_time TEXT,
                    connection_id TEXT,
                    content_type  TEXT,
                    request_hash  TEXT UNIQUE,
                    session_tag   TEXT,
                    notes         TEXT
                )
            """.trimIndent())

            // Messages table - matches sqlitedb_burp's http_messages
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS http_messages (
                    request_id       INTEGER PRIMARY KEY,
                    request_headers  TEXT,
                    request_body     BLOB,
                    response_headers TEXT,
                    response_body    BLOB,
                    FOREIGN KEY (request_id) REFERENCES http_traffic(request_id)
                )
            """.trimIndent())

            // FTS5 for full-text search
            stmt.execute("""
                CREATE VIRTUAL TABLE IF NOT EXISTS traffic_fts USING fts5(
                    url,
                    request_headers,
                    request_body,
                    response_headers,
                    response_body,
                    content=''
                )
            """.trimIndent())

            // Session management
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    cookies TEXT,
                    headers TEXT,
                    notes TEXT
                )
            """.trimIndent())

            // Template persistence
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    template_json TEXT NOT NULL
                )
            """.trimIndent())

            // Traffic tags table
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic_tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    traffic_id INTEGER NOT NULL,
                    tag TEXT NOT NULL,
                    note TEXT,
                    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
                    FOREIGN KEY (traffic_id) REFERENCES http_traffic(request_id) ON DELETE CASCADE
                )
            """.trimIndent())

            // Raw socket traffic (TCP/TLS requests that bypass Burp's HTTP layer)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS raw_socket_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    tool TEXT NOT NULL,
                    target_host TEXT NOT NULL,
                    target_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    tls_alpn TEXT,
                    request_bytes BLOB,
                    response_bytes BLOB,
                    request_preview TEXT,
                    response_preview TEXT,
                    bytes_sent INTEGER,
                    bytes_received INTEGER,
                    elapsed_ms INTEGER,
                    segment_count INTEGER,
                    connection_count INTEGER,
                    notes TEXT
                )
            """.trimIndent())

            // Collaborator events (payload generation and OOB interactions)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS collaborator_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    client_id TEXT,
                    payload_url TEXT,
                    custom_data TEXT,
                    interaction_type TEXT,
                    interaction_id TEXT,
                    dns_query TEXT,
                    dns_query_type TEXT,
                    http_protocol TEXT,
                    smtp_protocol TEXT,
                    server_address TEXT,
                    notes TEXT
                )
            """.trimIndent())

            // Indexes for raw socket traffic
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_raw_socket_timestamp ON raw_socket_traffic(timestamp)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_raw_socket_host ON raw_socket_traffic(target_host)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_raw_socket_tool ON raw_socket_traffic(tool)")

            // Indexes for collaborator events
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_collab_timestamp ON collaborator_events(timestamp)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_collab_client_id ON collaborator_events(client_id)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_collab_event_type ON collaborator_events(event_type)")

            // Indexes matching sqlitedb_burp
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON http_traffic(timestamp)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_host ON http_traffic(host)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_status_code ON http_traffic(status_code)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_tool ON http_traffic(tool)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_method ON http_traffic(method)")
            // Additional MCP indexes
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_host_timestamp ON http_traffic(host, timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_session ON http_traffic(session_tag, timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_method_url ON http_traffic(method, url)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_tags_tag ON traffic_tags(tag)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_tags_traffic_id ON traffic_tags(traffic_id)")

            // Record schema version
            stmt.execute("""
                INSERT OR IGNORE INTO schema_version (version, applied_at)
                VALUES ($CURRENT_VERSION, ${System.currentTimeMillis()})
            """.trimIndent())
        }
    }

    /**
     * v3 → v4: Add templates table for persistent template storage.
     */
    private fun migrateV3toV4(conn: Connection) {
        conn.createStatement().use { stmt ->
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at INTEGER NOT NULL,
                    template_json TEXT NOT NULL
                )
            """.trimIndent())

            stmt.execute("""
                INSERT OR IGNORE INTO schema_version (version, applied_at)
                VALUES ($CURRENT_VERSION, ${System.currentTimeMillis()})
            """.trimIndent())
        }
    }

    /**
     * Drop all old/incompatible tables and start fresh with v3 schema.
     * Handles both v2 tables (traffic, traffic_request_data, traffic_response_data)
     * and partially-created v3 tables from a failed previous migration.
     */
    private fun migrateFromV2(conn: Connection) {
        conn.createStatement().use { stmt ->
            // Drop everything - old v2 tables and any partially-created v3 tables
            stmt.execute("DROP TABLE IF EXISTS traffic_tags")
            stmt.execute("DROP TABLE IF EXISTS traffic_request_data")
            stmt.execute("DROP TABLE IF EXISTS traffic_response_data")
            stmt.execute("DROP TABLE IF EXISTS http_messages")
            stmt.execute("DROP TABLE IF EXISTS http_traffic")
            stmt.execute("DROP TABLE IF EXISTS traffic")
            stmt.execute("DROP TABLE IF EXISTS raw_socket_traffic")
            stmt.execute("DROP TABLE IF EXISTS collaborator_events")

            // FTS5 virtual tables
            stmt.execute("DROP TABLE IF EXISTS traffic_fts")
            stmt.execute("DROP TABLE IF EXISTS traffic_fts_data")
            stmt.execute("DROP TABLE IF EXISTS traffic_fts_idx")
            stmt.execute("DROP TABLE IF EXISTS traffic_fts_config")
            stmt.execute("DROP TABLE IF EXISTS traffic_fts_docsize")
            stmt.execute("DROP TABLE IF EXISTS traffic_fts_content")

            // Clear old version records so we can insert v3
            stmt.execute("DELETE FROM schema_version")
        }
    }

    /**
     * Check if old v2 tables exist (handles case where schema_version is missing/0
     * but old tables are present, or http_traffic exists with wrong columns).
     */
    private fun hasOldTables(conn: Connection): Boolean {
        return try {
            conn.createStatement().use { stmt ->
                // Check for old v2 'traffic' table
                val hasOldTraffic = stmt.executeQuery(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='traffic'"
                ).use { it.next() }

                // Check for old v2 split tables
                val hasOldRequestData = stmt.executeQuery(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='traffic_request_data'"
                ).use { it.next() }

                // Check if http_traffic exists but is missing expected columns (partial migration)
                val hasIncompleteHttpTraffic = try {
                    stmt.executeQuery("SELECT session_tag FROM http_traffic LIMIT 0")
                    false // column exists, table is fine
                } catch (_: Exception) {
                    // Either table doesn't exist (fine) or column is missing (needs rebuild)
                    stmt.executeQuery(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='http_traffic'"
                    ).use { it.next() } // only true if table exists with wrong columns
                }

                hasOldTraffic || hasOldRequestData || hasIncompleteHttpTraffic
            }
        } catch (_: Exception) {
            false
        }
    }

    fun getVersion(conn: Connection): Int {
        return try {
            conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT MAX(version) FROM schema_version").use { rs ->
                    if (rs.next()) rs.getInt(1) else 0
                }
            }
        } catch (e: Exception) {
            0
        }
    }
}
