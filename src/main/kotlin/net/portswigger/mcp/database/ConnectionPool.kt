package net.portswigger.mcp.database

import burp.api.montoya.logging.Logging
import java.sql.Connection
import java.sql.DriverManager
import java.sql.SQLException
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * Non-blocking SQLite connection pool using Semaphore-based concurrency control.
 *
 * Key design decisions:
 * - Semaphore instead of synchronized block - no single-lock bottleneck
 * - Bounded pool with timeout - prevents resource exhaustion
 * - WAL mode for concurrent read during writes
 * - Validation before reuse - prevents stale connection errors
 */
class ConnectionPool(
    private val dbPath: String,
    private val logging: Logging,
    private val minConnections: Int = 2,
    private val maxConnections: Int = 10,
    private val acquireTimeout: Duration = 5.seconds,
    private val validationTimeout: Int = 1
) : AutoCloseable {

    companion object {
        // Explicitly load SQLite JDBC driver - required in Burp's classloader environment
        // where JDBC ServiceLoader doesn't automatically discover drivers from extension JARs
        init {
            try {
                Class.forName("org.sqlite.JDBC")
            } catch (e: ClassNotFoundException) {
                throw RuntimeException("SQLite JDBC driver not found in classpath", e)
            }
        }
    }

    private val permits = Semaphore(maxConnections)
    private val connections = ConcurrentLinkedQueue<Connection>()
    private val activeCount = AtomicInteger(0)
    private val closed = AtomicBoolean(false)

    init {
        // Pre-warm the pool with minimum connections
        repeat(minConnections) {
            try {
                connections.offer(createConnection())
                activeCount.incrementAndGet()
            } catch (e: SQLException) {
                logging.logToError("Failed to pre-warm connection pool: ${e.message}")
            }
        }
    }

    /**
     * Acquire a connection with timeout. Non-blocking - uses Semaphore.tryAcquire.
     */
    fun acquire(): Connection {
        if (closed.get()) {
            throw SQLException("Connection pool is closed")
        }

        if (!permits.tryAcquire(acquireTimeout.inWholeMilliseconds, TimeUnit.MILLISECONDS)) {
            throw SQLException("Connection pool exhausted (timeout after ${acquireTimeout})")
        }

        return try {
            getOrCreateConnection()
        } catch (e: Exception) {
            permits.release()
            throw e
        }
    }

    /**
     * Release a connection back to the pool.
     */
    fun release(connection: Connection) {
        if (closed.get()) {
            closeQuietly(connection)
            permits.release()
            return
        }

        try {
            if (connection.isValid(validationTimeout)) {
                connections.offer(connection)
            } else {
                closeQuietly(connection)
                activeCount.decrementAndGet()
            }
        } catch (e: SQLException) {
            closeQuietly(connection)
            activeCount.decrementAndGet()
        } finally {
            permits.release()
        }
    }

    /**
     * Execute a block with a connection, automatically releasing it after.
     */
    fun <T> withConnection(block: (Connection) -> T): T {
        val conn = acquire()
        return try {
            block(conn)
        } finally {
            release(conn)
        }
    }

    /**
     * Execute a block within a transaction.
     */
    fun <T> withTransaction(block: (Connection) -> T): T {
        return withConnection { conn ->
            val previousAutoCommit = conn.autoCommit
            conn.autoCommit = false
            try {
                val result = block(conn)
                conn.commit()
                result
            } catch (e: Exception) {
                try {
                    conn.rollback()
                } catch (rollbackEx: SQLException) {
                    logging.logToError("Rollback failed: ${rollbackEx.message}")
                }
                throw e
            } finally {
                conn.autoCommit = previousAutoCommit
            }
        }
    }

    private fun getOrCreateConnection(): Connection {
        // Try to get an existing connection from the pool
        var conn = connections.poll()

        while (conn != null) {
            try {
                if (conn.isValid(validationTimeout)) {
                    return conn
                }
            } catch (e: SQLException) {
                // Invalid connection, discard it
            }
            closeQuietly(conn)
            activeCount.decrementAndGet()
            conn = connections.poll()
        }

        // Create a new connection
        val newConn = createConnection()
        activeCount.incrementAndGet()
        return newConn
    }

    private fun createConnection(): Connection {
        val conn = DriverManager.getConnection("jdbc:sqlite:$dbPath")

        // Apply SQLite optimizations
        conn.createStatement().use { stmt ->
            // Performance PRAGMAs (tuned for extension use, not standalone server)
            stmt.execute("PRAGMA journal_mode = WAL")
            stmt.execute("PRAGMA synchronous = NORMAL")
            stmt.execute("PRAGMA cache_size = -8000")  // 8MB cache (matches sqlitedb_burp)
            stmt.execute("PRAGMA temp_store = MEMORY")

            // Reliability PRAGMAs
            stmt.execute("PRAGMA busy_timeout = 5000")
            stmt.execute("PRAGMA foreign_keys = ON")
        }

        return conn
    }

    private fun closeQuietly(conn: Connection) {
        try {
            if (!conn.isClosed) {
                conn.close()
            }
        } catch (e: SQLException) {
            logging.logToError("Error closing connection: ${e.message}")
        }
    }

    /**
     * Get pool statistics for monitoring.
     */
    fun getStats(): PoolStats {
        return PoolStats(
            availableConnections = connections.size,
            activeConnections = activeCount.get(),
            availablePermits = permits.availablePermits(),
            maxConnections = maxConnections
        )
    }

    override fun close() {
        if (closed.compareAndSet(false, true)) {
            var conn = connections.poll()
            while (conn != null) {
                closeQuietly(conn)
                conn = connections.poll()
            }
            activeCount.set(0)
        }
    }
}

data class PoolStats(
    val availableConnections: Int,
    val activeConnections: Int,
    val availablePermits: Int,
    val maxConnections: Int
) {
    val utilizationPercent: Double
        get() = ((maxConnections - availablePermits).toDouble() / maxConnections) * 100
}
