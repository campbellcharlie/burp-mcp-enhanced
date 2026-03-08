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
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import javax.swing.JFileChooser
import javax.swing.SwingUtilities

@Suppress("unused")
class ExtensionBase : BurpExtension {

    private var databaseService: DatabaseService? = null
    private var trafficLogger: TrafficLogger? = null

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("Burp MCP Server (Enhanced)")

        val config = McpConfig(api.persistence().preferences(), api.logging())

        // Initialize database if traffic logging is enabled
        if (config.trafficLoggingEnabled) {
            try {
                val dbPath = resolveDbPath(config, api)
                val usablePath = findUsableDbPath(dbPath, api)

                databaseService = DatabaseService(usablePath, api.logging())

                trafficLogger = TrafficLogger(api, databaseService!!, api.logging()).apply {
                    enabled = config.trafficLoggingEnabled
                    logProxyTraffic = config.logProxyTraffic
                    logRepeaterTraffic = config.logRepeaterTraffic
                    logScannerTraffic = config.logScannerTraffic
                    logIntruderTraffic = config.logIntruderTraffic
                    logExtensionTraffic = config.logExtensionTraffic
                    register()
                }

                api.logging().logToOutput("Database initialized at ${usablePath.toAbsolutePath()}")
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
        val preferences = api.persistence().preferences()
        val projectName = sanitizeForFileSystem(detectProjectName(api))
        val dbFilename = "$projectName.db"

        // 1. Check config UI path first
        if (config.databasePath.isNotBlank()) {
            val dir = Paths.get(config.databasePath)
            if (Files.isDirectory(dir)) {
                // Save to preferences for next session
                preferences.setString(PREF_DB_DIRECTORY, dir.toString())
                return dir.resolve(dbFilename)
            }
        }

        // 2. Check saved preference
        val savedDir = preferences.getString(PREF_DB_DIRECTORY)
        if (!savedDir.isNullOrEmpty()) {
            val dir = Paths.get(savedDir)
            if (Files.isDirectory(dir)) {
                return dir.resolve(dbFilename)
            }
        }

        // 3. Prompt for directory
        val chosenDir = promptForDirectory(api)
        if (chosenDir != null) {
            preferences.setString(PREF_DB_DIRECTORY, chosenDir.toString())
            config.databasePath = chosenDir.toString()
            return chosenDir.resolve(dbFilename)
        }

        // 4. Fallback
        val fallbackDir = Paths.get(System.getProperty("user.home"), FALLBACK_DIR)
        Files.createDirectories(fallbackDir)
        api.logging().logToOutput("No directory selected, using fallback: $fallbackDir")
        return fallbackDir.resolve(dbFilename)
    }

    private fun promptForDirectory(api: MontoyaApi): Path? {
        var result: Path? = null
        try {
            SwingUtilities.invokeAndWait {
                val chooser = JFileChooser()
                chooser.dialogTitle = "Select directory for SQLite traffic database"
                chooser.fileSelectionMode = JFileChooser.DIRECTORIES_ONLY
                chooser.currentDirectory = java.io.File(System.getProperty("user.home"))

                val choice = chooser.showOpenDialog(null)
                if (choice == JFileChooser.APPROVE_OPTION) {
                    result = chooser.selectedFile.toPath()
                }
            }
        } catch (e: Exception) {
            api.logging().logToError("Directory chooser failed: ${e.message}")
        }
        return result
    }

    /**
     * Try the primary DB path. If it exists and is locked or unwritable,
     * append a version suffix (.v2, .v3, ...) until we find a usable path.
     */
    private fun findUsableDbPath(primaryPath: Path, api: MontoyaApi): Path {
        // If file doesn't exist yet, parent dir must be writable
        if (!Files.exists(primaryPath)) {
            val parent = primaryPath.parent
            if (parent != null) Files.createDirectories(parent)
            return primaryPath
        }

        // File exists — try to open it
        if (isDbUsable(primaryPath)) {
            return primaryPath
        }

        // Locked or unwritable — try versioned alternatives
        val name = primaryPath.fileName.toString()
        val base = name.removeSuffix(".db")
        val dir = primaryPath.parent

        for (version in 2..MAX_DB_VERSIONS) {
            val candidate = dir.resolve("${base}.v${version}.db")
            if (!Files.exists(candidate) || isDbUsable(candidate)) {
                api.logging().logToOutput(
                    "Primary database $primaryPath is locked/unwritable, using ${candidate.toAbsolutePath()}"
                )
                return candidate
            }
        }

        // All versions exhausted — last resort with timestamp
        val fallback = dir.resolve("${base}.${System.currentTimeMillis()}.db")
        api.logging().logToOutput("All versioned DB paths exhausted, using ${fallback.toAbsolutePath()}")
        return fallback
    }

    private fun isDbUsable(path: Path): Boolean {
        return try {
            val conn = java.sql.DriverManager.getConnection("jdbc:sqlite:$path")
            conn.use { c ->
                c.createStatement().use { stmt ->
                    stmt.execute("PRAGMA journal_mode = WAL")
                    stmt.executeQuery("PRAGMA quick_check(1)").close()
                }
            }
            true
        } catch (_: Exception) {
            false
        }
    }

    private fun detectProjectName(api: MontoyaApi): String {
        return try {
            val name = api.project().name()
            if (name.isNullOrBlank()) {
                "Temporary_project"
            } else {
                name
            }
        } catch (e: Exception) {
            "unknown_project_${System.currentTimeMillis()}"
        }
    }

    private fun sanitizeForFileSystem(name: String): String {
        var sanitized = name
            .replace(Regex("[^a-zA-Z0-9._\\-]"), "_")
            .replace(Regex("_{2,}"), "_")
            .trimStart('_').trimEnd('_')

        if (sanitized.isEmpty()) sanitized = "burp_project"
        if (sanitized.length > 100) sanitized = sanitized.substring(0, 100)

        return sanitized
    }

    companion object {
        private const val PREF_DB_DIRECTORY = "db_directory"
        private const val FALLBACK_DIR = ".burp-sqlite-logs"
        private const val MAX_DB_VERSIONS = 10
    }
}
