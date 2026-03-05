package net.portswigger.mcp.logging

import burp.api.montoya.logging.Logging
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.TrafficItem
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Non-blocking queue for traffic logging.
 *
 * CRITICAL: Burp's proxy threads must NEVER be blocked.
 * This queue uses offer() which returns immediately.
 *
 * Architecture:
 * - Burp proxy threads -> offer() to queue (non-blocking, < 1ms)
 * - Single writer thread -> drains queue in batches -> writes to SQLite
 */
class TrafficQueue(
    private val db: DatabaseService,
    private val logging: Logging,
    capacity: Int = 100_000
) : AutoCloseable {

    private val queue = ArrayBlockingQueue<QueueItem>(capacity)
    private val running = AtomicBoolean(true)

    // Metrics
    private val enqueued = AtomicLong(0)
    private val dropped = AtomicLong(0)
    private val processed = AtomicLong(0)
    private val errors = AtomicLong(0)

    private val writerThread = thread(
        name = "mcp-traffic-writer",
        isDaemon = true,
        priority = Thread.MIN_PRIORITY  // Low priority - don't compete with Burp
    ) {
        runWriterLoop()
    }

    /**
     * Enqueue a traffic request. Called from Burp proxy threads.
     * MUST NOT BLOCK - returns immediately.
     */
    fun enqueueRequest(item: TrafficItem): Boolean {
        val success = queue.offer(QueueItem.Request(item))
        if (success) {
            enqueued.incrementAndGet()
        } else {
            dropped.incrementAndGet()
            logDroppedIfNeeded()
        }
        return success
    }

    /**
     * Enqueue a response update. Called from Burp proxy threads.
     * MUST NOT BLOCK - returns immediately.
     */
    fun enqueueResponseUpdate(
        requestHash: String,
        statusCode: Int,
        responseHeaders: String,
        responseBody: ByteArray?
    ): Boolean {
        val success = queue.offer(
            QueueItem.ResponseUpdate(requestHash, statusCode, responseHeaders, responseBody)
        )
        if (success) {
            enqueued.incrementAndGet()
        } else {
            dropped.incrementAndGet()
            logDroppedIfNeeded()
        }
        return success
    }

    private fun logDroppedIfNeeded() {
        val droppedCount = dropped.get()
        if (droppedCount % 1000 == 0L) {
            logging.logToError("Traffic queue dropped $droppedCount items (queue full)")
        }
    }

    private fun runWriterLoop() {
        val batch = mutableListOf<QueueItem>()

        while (running.get() || queue.isNotEmpty()) {
            try {
                // Block on first item (saves CPU when idle)
                val first = queue.poll(1, java.util.concurrent.TimeUnit.SECONDS)
                if (first == null) continue

                batch.add(first)

                // Drain available items up to adaptive batch size
                val batchSize = calculateAdaptiveBatchSize()
                queue.drainTo(batch.toMutableList().also { batch.clear(); batch.addAll(it) }, batchSize - 1)

                // We need to re-add 'first' since drainTo doesn't include it
                val actualBatch = mutableListOf(first)
                repeat(minOf(batchSize - 1, queue.size)) {
                    queue.poll()?.let { actualBatch.add(it) }
                }

                processBatch(actualBatch)
                processed.addAndGet(actualBatch.size.toLong())
                actualBatch.clear()

            } catch (e: InterruptedException) {
                Thread.currentThread().interrupt()
                break
            } catch (e: Exception) {
                errors.incrementAndGet()
                logging.logToError("Traffic write error: ${e.message}")
                // Back off on error
                Thread.sleep(100)
            }
        }

        // Drain remaining items on shutdown
        drainRemaining()
    }

    private fun processBatch(batch: List<QueueItem>) {
        if (batch.isEmpty()) return

        // Separate requests and updates
        val requests = batch.filterIsInstance<QueueItem.Request>()
        val updates = batch.filterIsInstance<QueueItem.ResponseUpdate>()

        // Batch insert requests
        if (requests.isNotEmpty()) {
            try {
                db.insertTrafficBatch(requests.map { it.item })
            } catch (e: Exception) {
                logging.logToError("Failed to insert traffic batch: ${e.message}")
                errors.addAndGet(requests.size.toLong())
            }
        }

        // Process response updates
        updates.forEach { update ->
            try {
                db.updateTrafficResponse(
                    requestHash = update.requestHash,
                    statusCode = update.statusCode,
                    headers = update.responseHeaders,
                    body = update.responseBody
                )
            } catch (e: Exception) {
                logging.logToError("Failed to update response: ${e.message}")
                errors.incrementAndGet()
            }
        }
    }

    private fun calculateAdaptiveBatchSize(): Int {
        val queueSize = queue.size
        return when {
            queueSize < 10 -> 10
            queueSize < 100 -> 50
            queueSize < 1000 -> 100
            else -> 500
        }
    }

    private fun drainRemaining() {
        val remaining = mutableListOf<QueueItem>()
        queue.drainTo(remaining)

        if (remaining.isNotEmpty()) {
            logging.logToOutput("Draining ${remaining.size} remaining traffic items...")
            processBatch(remaining)
            processed.addAndGet(remaining.size.toLong())
        }
    }

    /**
     * Get queue statistics.
     */
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
        running.set(false)

        // Wait for writer thread to finish (with timeout)
        try {
            writerThread.join(5000)
            if (writerThread.isAlive) {
                logging.logToError("Traffic writer thread did not stop gracefully")
                writerThread.interrupt()
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
        }

        logging.logToOutput("Traffic queue closed. Stats: ${getStats()}")
    }
}

/**
 * Items that can be queued for processing.
 */
sealed class QueueItem {
    data class Request(val item: TrafficItem) : QueueItem()
    data class ResponseUpdate(
        val requestHash: String,
        val statusCode: Int,
        val responseHeaders: String,
        val responseBody: ByteArray?
    ) : QueueItem()
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
