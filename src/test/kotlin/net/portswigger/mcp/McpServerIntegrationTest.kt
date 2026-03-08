package net.portswigger.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.Preferences
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import net.portswigger.mcp.config.McpConfig
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.net.ServerSocket

class McpServerIntegrationTest {
    private val client = TestSseMcpClient()
    private val api = mockk<MontoyaApi>(relaxed = true)
    private val serverManager = KtorServerManager(api, null, null)
    private val testPort = findAvailablePort()
    private val preferences = mockk<Preferences>()
    private var serverStarted = false

    init {
        val storage = mutableMapOf<String, Any>()
        every { preferences.getBoolean(any()) } answers {
            val key = firstArg<String>()
            storage[key] as? Boolean ?: when (key) {
                "enabled" -> true
                else -> false
            }
        }
        every { preferences.getString(any()) } answers {
            val key = firstArg<String>()
            storage[key] as? String ?: "127.0.0.1"
        }
        every { preferences.getInteger(any()) } answers {
            val key = firstArg<String>()
            (storage[key] as? Int) ?: if (key == "port") testPort else 0
        }
        every { preferences.setBoolean(any(), any()) } answers {
            storage[firstArg<String>()] = secondArg<Boolean>()
        }
        every { preferences.setString(any(), any()) } answers {
            storage[firstArg<String>()] = secondArg<String>()
        }
        every { preferences.setInteger(any(), any()) } answers {
            storage[firstArg<String>()] = secondArg<Int>()
        }
    }

    private val mockLogging = mockk<Logging>().apply {
        every { logToError(any<String>()) } returns Unit
        every { logToOutput(any<String>()) } returns Unit
    }

    private val config = McpConfig(preferences, mockLogging)

    @BeforeEach
    fun setup() {
        serverManager.start(config) { state ->
            if (state is ServerState.Running) {
                serverStarted = true
            }
        }
        
        runBlocking {
            var attempts = 0
            while (!serverStarted && attempts < 10) {
                delay(100)
                attempts++
            }
            
            if (!serverStarted) {
                throw IllegalStateException("Server failed to start after timeout")
            }
        }
    }

    private fun findAvailablePort(): Int {
        return ServerSocket(0).use { it.localPort }
    }

    @AfterEach
    fun tearDown() {
        runBlocking {
            if (client.isConnected()) {
                client.close()
            }
        }
        serverManager.stop {}
    }

    @Test
    fun `server should accept connections and list tools`() = runBlocking {
        try {
            client.connectToServer("http://127.0.0.1:${testPort}")
            assertTrue(client.isConnected(), "Client should be connected to server")
            
            val tools = client.listTools()
            assertFalse(tools.isEmpty(), "Server should have registered tools")
            
            val toolNames = tools.map { it.name }
            assertTrue(toolNames.contains("output_project_options"), "Server should have output_project_options tool")
            assertTrue(toolNames.contains("output_user_options"), "Server should have output_user_options tool")
            
            val pingResult = client.ping()
            assertNotNull(pingResult, "Ping should return a result")
        } catch (e: Exception) {
            fail("Connection failed: ${e.message}")
        }
    }
}