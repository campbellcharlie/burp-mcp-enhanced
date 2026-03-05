package net.portswigger.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import net.portswigger.mcp.config.ConfigUi
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.logging.TrafficLogger
import net.portswigger.mcp.providers.ClaudeDesktopProvider
import net.portswigger.mcp.providers.ManualProxyInstallerProvider
import net.portswigger.mcp.providers.ProxyJarManager
import java.nio.file.Path
import java.nio.file.Paths

@Suppress("unused")
class ExtensionBase : BurpExtension {

    private var databaseService: DatabaseService? = null
    private var trafficLogger: TrafficLogger? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server (Enhanced)")

        val config = McpConfig(api.persistence().extensionData(), api.logging())

        // Initialize database if traffic logging is enabled
        if (config.trafficLoggingEnabled) {
            try {
                val dbPath = resolveDbPath(config, api)
                databaseService = DatabaseService(dbPath, api.logging())

                trafficLogger = TrafficLogger(api, databaseService!!, api.logging()).apply {
                    enabled = config.trafficLoggingEnabled
                    logProxyTraffic = config.logProxyTraffic
                    logRepeaterTraffic = config.logRepeaterTraffic
                    logScannerTraffic = config.logScannerTraffic
                    logIntruderTraffic = config.logIntruderTraffic
                    logExtensionTraffic = config.logExtensionTraffic
                    register()
                }

                api.logging().logToOutput("Traffic logging enabled: $dbPath")
            } catch (e: Exception) {
                api.logging().logToError("Failed to initialize database: ${e.message}")
                // Continue without database - core MCP functionality still works
            }
        }

        val serverManager = KtorServerManager(api, databaseService, trafficLogger)

        val proxyJarManager = ProxyJarManager(api.logging())

        val configUi = ConfigUi(
            config = config, providers = listOf(
                ClaudeDesktopProvider(api.logging(), proxyJarManager),
                ManualProxyInstallerProvider(api.logging(), proxyJarManager),
            )
        )

        configUi.onEnabledToggled { enabled ->
            configUi.getConfig()

            if (enabled) {
                serverManager.start(config) { state ->
                    configUi.updateServerState(state)
                }
            } else {
                serverManager.stop { state ->
                    configUi.updateServerState(state)
                }
            }
        }

        api.userInterface().registerSuiteTab("MCP", configUi.component)

        api.extension().registerUnloadingHandler {
            serverManager.shutdown()

            // Cleanup traffic logger and database
            trafficLogger?.close()
            databaseService?.close()

            configUi.cleanup()
            config.cleanup()
        }

        if (config.enabled) {
            serverManager.start(config) { state ->
                configUi.updateServerState(state)
            }
        }
    }

    private fun resolveDbPath(config: McpConfig, api: MontoyaApi): Path {
        val dbDir = if (config.databasePath.isNotBlank()) {
            Paths.get(config.databasePath)
        } else {
            val home = System.getProperty("user.home")
            Paths.get(home, ".burp-mcp")
        }
        dbDir.toFile().mkdirs()

        val projectName = detectProjectName(api)
        val fileName = "traffic_$projectName.db"
        return dbDir.resolve(fileName)
    }

    private fun detectProjectName(api: MontoyaApi): String {
        return try {
            val name = api.project().name()
            if (name.isNullOrBlank()) {
                "Temporary_project"
            } else {
                sanitizeForFileSystem(name)
            }
        } catch (e: Exception) {
            "unknown_project_${System.currentTimeMillis()}"
        }
    }

    private fun sanitizeForFileSystem(name: String): String {
        var sanitized = name
            .replace(Regex("[^a-zA-Z0-9\\-_ ]"), "_")
            .replace(Regex("\\s+"), "_")
            .replace(Regex("_{2,}"), "_")
            .trimStart('_').trimEnd('_')

        if (sanitized.isEmpty()) sanitized = "unnamed_project"
        if (sanitized.length > 100) sanitized = sanitized.substring(0, 100)

        return sanitized
    }
}