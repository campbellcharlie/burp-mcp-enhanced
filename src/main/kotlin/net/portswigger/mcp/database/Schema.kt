package net.portswigger.mcp.database

import java.sql.Connection

/**
 * Database schema definitions and initialization.
 */
object Schema {

    const val CURRENT_VERSION = 2

    /**
     * Initialize the database schema.
     */
    fun initialize(conn: Connection) {
        conn.createStatement().use { stmt ->
            // Schema version tracking
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL
                )
            """.trimIndent())

            // Main traffic table (normalized for fast queries)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp INTEGER NOT NULL,
                    tool_source TEXT NOT NULL,
                    method TEXT NOT NULL,
                    url TEXT NOT NULL,
                    host TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    is_https INTEGER NOT NULL DEFAULT 0,
                    status_code INTEGER,
                    content_length INTEGER,
                    content_type TEXT,
                    request_hash TEXT UNIQUE,
                    session_tag TEXT,
                    notes TEXT
                )
            """.trimIndent())

            // Separate tables for large content (keeps main table fast)
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic_request_data (
                    traffic_id INTEGER PRIMARY KEY REFERENCES traffic(id) ON DELETE CASCADE,
                    headers TEXT NOT NULL,
                    body BLOB
                )
            """.trimIndent())

            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic_response_data (
                    traffic_id INTEGER PRIMARY KEY REFERENCES traffic(id) ON DELETE CASCADE,
                    headers TEXT,
                    body BLOB
                )
            """.trimIndent())

            // FTS5 for full-text search (contentless - we manage content manually)
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

            // Traffic tags table for user-defined tagging
            stmt.execute("""
                CREATE TABLE IF NOT EXISTS traffic_tags (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    traffic_id INTEGER NOT NULL,
                    tag TEXT NOT NULL,
                    note TEXT,
                    created_at INTEGER DEFAULT (strftime('%s', 'now') * 1000),
                    FOREIGN KEY (traffic_id) REFERENCES traffic(id) ON DELETE CASCADE
                )
            """.trimIndent())

            // Indexes for common queries
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic(timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_host ON traffic(host, timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_status ON traffic(status_code, timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_session ON traffic(session_tag, timestamp DESC)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_method_url ON traffic(method, url)")
            stmt.execute("CREATE INDEX IF NOT EXISTS idx_traffic_tool ON traffic(tool_source, timestamp DESC)")
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
     * Get the current schema version.
     */
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
