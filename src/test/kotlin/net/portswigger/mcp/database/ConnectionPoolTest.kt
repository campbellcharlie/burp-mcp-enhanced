package net.portswigger.mcp.database

import io.mockk.every
import io.mockk.mockk
import burp.api.montoya.logging.Logging
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Path
import java.sql.SQLException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConnectionPoolTest {

    @TempDir
    lateinit var tempDir: Path

    private lateinit var pool: ConnectionPool
    private lateinit var mockLogging: Logging

    @BeforeEach
    fun setup() {
        mockLogging = mockk(relaxed = true)
        every { mockLogging.logToOutput(any()) } returns Unit
        every { mockLogging.logToError(any<String>()) } returns Unit

        val dbPath = tempDir.resolve("test.db").toString()
        pool = ConnectionPool(
            dbPath = dbPath,
            logging = mockLogging,
            minConnections = 2,
            maxConnections = 5
        )
    }

    @AfterEach
    fun teardown() {
        pool.close()
    }

    @Test
    fun `acquire returns valid connection`() {
        val conn = pool.acquire()
        assertNotNull(conn)
        assertTrue(conn.isValid(1))
        pool.release(conn)
    }

    @Test
    fun `withConnection executes block and releases connection`() {
        val result = pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.execute("SELECT 1")
            }
            "success"
        }
        assertEquals("success", result)

        // Verify connection was released - we should be able to acquire max connections
        val connections = (1..5).map { pool.acquire() }
        assertEquals(5, connections.size)
        connections.forEach { pool.release(it) }
    }

    @Test
    fun `withTransaction commits on success`() {
        pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            }
        }

        pool.withTransaction { conn ->
            conn.prepareStatement("INSERT INTO test (value) VALUES (?)").use { stmt ->
                stmt.setString(1, "test_value")
                stmt.executeUpdate()
            }
        }

        val result = pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT value FROM test WHERE id = 1").use { rs ->
                    if (rs.next()) rs.getString("value") else null
                }
            }
        }
        assertEquals("test_value", result)
    }

    @Test
    fun `withTransaction rolls back on exception`() {
        pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.execute("CREATE TABLE test (id INTEGER PRIMARY KEY, value TEXT)")
            }
        }

        try {
            pool.withTransaction { conn ->
                conn.prepareStatement("INSERT INTO test (value) VALUES (?)").use { stmt ->
                    stmt.setString(1, "test_value")
                    stmt.executeUpdate()
                }
                throw RuntimeException("Simulated error")
            }
        } catch (e: RuntimeException) {
            // Expected
        }

        val count = pool.withConnection { conn ->
            conn.createStatement().use { stmt ->
                stmt.executeQuery("SELECT COUNT(*) FROM test").use { rs ->
                    if (rs.next()) rs.getInt(1) else -1
                }
            }
        }
        assertEquals(0, count) // Transaction should have been rolled back
    }

    @Test
    fun `concurrent access works correctly`() {
        val executor = Executors.newFixedThreadPool(10)
        val successCount = AtomicInteger(0)
        val errorCount = AtomicInteger(0)
        val latch = CountDownLatch(100)

        repeat(100) {
            executor.submit {
                try {
                    pool.withConnection { conn ->
                        conn.createStatement().use { stmt ->
                            stmt.execute("SELECT 1")
                        }
                        Thread.sleep(10) // Simulate work
                    }
                    successCount.incrementAndGet()
                } catch (e: Exception) {
                    errorCount.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }
        }

        latch.await(30, TimeUnit.SECONDS)
        executor.shutdown()

        // All operations should succeed (pool handles contention)
        assertEquals(100, successCount.get())
        assertEquals(0, errorCount.get())
    }

    @Test
    fun `pool stats are accurate`() {
        val stats1 = pool.getStats()
        assertTrue(stats1.availableConnections >= 2) // Pre-warmed

        val conn1 = pool.acquire()
        val conn2 = pool.acquire()

        val stats2 = pool.getStats()
        assertEquals(5, stats2.maxConnections)
        assertEquals(3, stats2.availablePermits) // 5 max - 2 acquired

        pool.release(conn1)
        pool.release(conn2)

        val stats3 = pool.getStats()
        assertEquals(5, stats3.availablePermits)
    }

    @Test
    fun `closed pool throws exception on acquire`() {
        pool.close()

        assertFailsWith<SQLException> {
            pool.acquire()
        }
    }
}
