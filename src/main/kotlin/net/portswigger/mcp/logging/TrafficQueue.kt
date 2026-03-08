package net.portswigger.mcp.logging

import burp.api.montoya.logging.Logging
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.TrafficItem
import java.util.concurrent.CountDownLatch
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * Non-blocking queue for traffic logging, matching sqlitedb_burp's DatabaseWriterThread.
 * Simple design: single item type, batch insert, daemon thread.
 */
class TrafficQueue(
    private val db: DatabaseService,
    private val logging: Logging,
    capacity: Int = QUEUE_CAPACITY
) : AutoCloseable {

    private val queue = LinkedBlockingQueue<TrafficItem>(capacity)

    private val enqueued = AtomicLong(0)
    private val dropped = AtomicLong(0)
    private val processed = AtomicLong(0)
    private val errors = AtomicLong(0)

    @Volatile
    private var running = true

    // When non-null, the writer thread will drain the queue and count down the latch.
    private val flushLatch = AtomicReference<CountDownLatch>(null)

    private val writerThread = thread(
        name = "mcp-traffic-writer",
        isDaemon = true,
        priority = Thread.MIN_PRIORITY
    ) {
        runWriterLoop()
    }

    fun enqueue(item: TrafficItem): Boolean {
        val offered = queue.offer(item)
        if (offered) {
            enqueued.incrementAndGet()
        } else {
            val count = dropped.incrementAndGet()
            if (count % DROP_LOG_INTERVAL == 0L) {
                logging.logToError("Traffic queue full - $count total records dropped")
            }
        }
        return offered
    }

    /**
     * Block until all currently queued items are written to the database.
     * Use before searching to ensure recently-sent traffic is available.
     */
    fun flush(timeoutMs: Long = FLUSH_TIMEOUT_MS): Boolean {
        if (queue.isEmpty()) return true
        val latch = CountDownLatch(1)
        flushLatch.set(latch)
        // Wake the writer if it's blocked on poll()
        writerThread.interrupt()
        return try {
            latch.await(timeoutMs, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun runWriterLoop() {
        while (running) {
            try {
                // Check for flush request
                val pendingFlush = flushLatch.getAndSet(null)
                if (pendingFlush != null) {
                    drainRemaining()
                    pendingFlush.countDown()
                    continue
                }

                val record = queue.poll(POLL_TIMEOUT_SECONDS, TimeUnit.SECONDS) ?: continue
                val batch = mutableListOf(record)
                queue.drainTo(batch, BATCH_SIZE - 1)
                flushBatch(batch)
            } catch (_: InterruptedException) {
                // Could be a flush wake-up or a shutdown — check both
                if (!running) {
                    Thread.currentThread().interrupt()
                    break
                }
                // Clear interrupt flag and check for flush
                val pendingFlush = flushLatch.getAndSet(null)
                if (pendingFlush != null) {
                    drainRemaining()
                    pendingFlush.countDown()
                }
            }
        }
        drainRemaining()
    }

    private fun flushBatch(batch: List<TrafficItem>) {
        if (batch.isEmpty()) return
        try {
            db.insertTrafficBatch(batch)
            processed.addAndGet(batch.size.toLong())
        } catch (e: Exception) {
            logging.logToError("Batch insert failed (${batch.size} records): ${e.message}")
            errors.addAndGet(batch.size.toLong())
        }
    }

    private fun drainRemaining() {
        val remaining = mutableListOf<TrafficItem>()
        queue.drainTo(remaining)
        if (remaining.isNotEmpty()) {
            logging.logToOutput("Flushing ${remaining.size} remaining traffic records...")
            flushBatch(remaining)
        }
    }

    fun getStats(): QueueStats {
        return QueueStats(
            queueSize = queue.size,
            enqueued = enqueued.get(),
            dropped = dropped.get(),
            processed = processed.get(),
            errors = errors.get()
        )
    }

    override fun close() {
        running = false
        try {
            writerThread.join(SHUTDOWN_TIMEOUT_MS)
            if (writerThread.isAlive) {
                logging.logToError("Traffic writer thread did not stop gracefully")
                writerThread.interrupt()
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
        logging.logToOutput("Traffic queue closed. Stats: ${getStats()}")
    }

    companion object {
        private const val QUEUE_CAPACITY = 50_000
        private const val BATCH_SIZE = 500
        private const val POLL_TIMEOUT_SECONDS = 2L
        private const val SHUTDOWN_TIMEOUT_MS = 10_000L
        private const val DROP_LOG_INTERVAL = 1000L
        private const val FLUSH_TIMEOUT_MS = 10_000L
    }
}

data class QueueStats(
    val queueSize: Int,
    val enqueued: Long,
    val dropped: Long,
    val processed: Long,
    val errors: Long
) {
    val dropRate: Double
        get() = if (enqueued > 0) (dropped.toDouble() / enqueued) * 100 else 0.0
}
