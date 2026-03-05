package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.SecretKey
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import java.util.concurrent.ConcurrentHashMap

// Store active collaborator clients for polling
private val collaboratorClients = ConcurrentHashMap<String, CollaboratorClient>()

/**
 * Register Burp Collaborator tools for out-of-band testing.
 */
fun Server.registerCollaboratorTools(api: MontoyaApi) {

    mcpTool<CollaboratorStatus>(
        "Check if Burp Collaborator is available and get server address."
    ) {
        try {
            val client = api.collaborator().createClient()
            val server = client.server()

            buildString {
                appendLine("=== Burp Collaborator Status ===")
                appendLine()
                appendLine("Status: AVAILABLE")
                appendLine("Server Address: ${server.address()}")
                appendLine("Is Literal Address: ${server.isLiteralAddress()}")
            }
        } catch (e: IllegalStateException) {
            "Collaborator Status: UNAVAILABLE\nReason: ${e.message}\nNote: Burp Collaborator requires Burp Suite Professional"
        } catch (e: Exception) {
            "Collaborator Status: ERROR\nReason: ${e.message}"
        }
    }

    mcpTool<CollaboratorGeneratePayload>(
        "Generate a Burp Collaborator payload URL. Returns a unique subdomain that will " +
        "trigger DNS/HTTP callbacks when accessed. Use client_id to poll for interactions later."
    ) {
        try {
            // Create a new client for this session
            val client = api.collaborator().createClient()
            val payload = client.generatePayload()
            val clientId = payload.id().toString()

            // Store the client for later polling
            collaboratorClients[clientId] = client

            buildString {
                appendLine("=== Collaborator Payload Generated ===")
                appendLine()
                appendLine("Payload URL: ${payload.toString()}")
                appendLine("Interaction ID: $clientId")
                appendLine()
                appendLine("Usage:")
                appendLine("1. Use this URL in your exploit (e.g., SQL injection, SSRF, XXE)")
                appendLine("2. Call collaborator_poll_interactions with client_id=\"$clientId\" to check for callbacks")
                appendLine()
                appendLine("Example payloads:")
                appendLine("- HTTP: http://${payload}")
                appendLine("- DNS: ${payload}")
                appendLine("- For SQL injection OOB: Use database-specific DNS lookup with this domain")
            }
        } catch (e: IllegalStateException) {
            "Error: Burp Collaborator is not available. ${e.message}"
        } catch (e: Exception) {
            "Error generating payload: ${e.message}"
        }
    }

    mcpTool<CollaboratorGeneratePayloadWithData>(
        "Generate a Burp Collaborator payload with custom embedded data (max 16 alphanumeric chars). " +
        "The custom data helps identify which payload triggered an interaction."
    ) {
        try {
            if (customData.length > 16 || !customData.matches(Regex("^[a-zA-Z0-9]*$"))) {
                return@mcpTool "Error: custom_data must be max 16 alphanumeric characters"
            }

            val client = api.collaborator().createClient()
            val payload = client.generatePayload(customData)
            val clientId = payload.id().toString()

            collaboratorClients[clientId] = client

            buildString {
                appendLine("=== Collaborator Payload Generated (with custom data) ===")
                appendLine()
                appendLine("Payload URL: ${payload}")
                appendLine("Interaction ID: $clientId")
                appendLine("Custom Data: $customData")
                appendLine()
                appendLine("The custom data will appear in interaction details when polled.")
            }
        } catch (e: Exception) {
            "Error generating payload: ${e.message}"
        }
    }

    mcpTool<CollaboratorPollInteractions>(
        "Poll for Collaborator interactions. Returns any DNS, HTTP, or SMTP callbacks " +
        "received for the specified client_id. Call this after using a Collaborator payload."
    ) {
        try {
            val client = collaboratorClients[clientId]
                ?: return@mcpTool "Error: No client found for ID '$clientId'. Generate a new payload first."

            val interactions = client.getAllInteractions()

            if (interactions.isEmpty()) {
                return@mcpTool buildString {
                    appendLine("=== No Interactions Yet ===")
                    appendLine()
                    appendLine("No callbacks received for client ID: $clientId")
                    appendLine("The target may not have triggered the payload yet.")
                    appendLine()
                    appendLine("Tips:")
                    appendLine("- Ensure the payload was injected correctly")
                    appendLine("- Some payloads take time to execute (async operations)")
                    appendLine("- Check if the target can make outbound connections")
                }
            }

            buildString {
                appendLine("=== Collaborator Interactions Found: ${interactions.size} ===")
                appendLine()

                for ((index, interaction) in interactions.withIndex()) {
                    appendLine("--- Interaction ${index + 1} ---")
                    appendLine("Type: ${interaction.type()}")
                    appendLine("Timestamp: ${interaction.timeStamp()}")
                    appendLine("ID: ${interaction.id()}")

                    // DNS details
                    if (interaction.dnsDetails().isPresent) {
                        val dns = interaction.dnsDetails().get()
                        appendLine()
                        appendLine("DNS Details:")
                        appendLine("  Query: ${dns.query()}")
                        appendLine("  Query Type: ${dns.queryType()}")
                    }

                    // HTTP details
                    if (interaction.httpDetails().isPresent) {
                        val http = interaction.httpDetails().get()
                        appendLine()
                        appendLine("HTTP Details:")
                        appendLine("  Protocol: ${http.protocol()}")
                        // Note: Request/response methods vary by API version
                    }

                    // SMTP details
                    if (interaction.smtpDetails().isPresent) {
                        val smtp = interaction.smtpDetails().get()
                        appendLine()
                        appendLine("SMTP Details:")
                        appendLine("  Protocol: ${smtp.protocol()}")
                    }

                    // Custom data if present
                    interaction.customData().ifPresent { data ->
                        appendLine()
                        appendLine("Custom Data: $data")
                    }

                    appendLine()
                }
            }
        } catch (e: Exception) {
            "Error polling interactions: ${e.message}"
        }
    }

    mcpTool<CollaboratorRestoreClient>(
        "Restore a Collaborator client from a secret key. Use this to resume polling " +
        "for interactions from a previous session."
    ) {
        try {
            val key = SecretKey.secretKey(secretKey)
            val client = api.collaborator().restoreClient(key)

            // Generate a client ID for storage
            val testPayload = client.generatePayload()
            val clientId = testPayload.id().toString()
            collaboratorClients[clientId] = client

            val interactions = client.getAllInteractions()

            buildString {
                appendLine("=== Client Restored ===")
                appendLine()
                appendLine("New Client ID: $clientId")
                appendLine("Existing Interactions: ${interactions.size}")
                appendLine()
                appendLine("Use collaborator_poll_interactions with client_id=\"$clientId\" to get interactions.")
            }
        } catch (e: Exception) {
            "Error restoring client: ${e.message}"
        }
    }

    mcpTool<CollaboratorGetSecretKey>(
        "Get the secret key for a Collaborator client. Save this to restore the client later."
    ) {
        try {
            val client = collaboratorClients[clientId]
                ?: return@mcpTool "Error: No client found for ID '$clientId'."

            val secretKey = client.getSecretKey()

            buildString {
                appendLine("=== Collaborator Secret Key ===")
                appendLine()
                appendLine("Client ID: $clientId")
                appendLine("Secret Key: ${secretKey}")
                appendLine()
                appendLine("Save this key to restore the client later using collaborator_restore_client.")
            }
        } catch (e: Exception) {
            "Error getting secret key: ${e.message}"
        }
    }

    mcpTool<CollaboratorListClients>(
        "List all active Collaborator clients in this session."
    ) {
        if (collaboratorClients.isEmpty()) {
            return@mcpTool "No active Collaborator clients. Generate a payload to create one."
        }

        buildString {
            appendLine("=== Active Collaborator Clients: ${collaboratorClients.size} ===")
            appendLine()

            for ((clientId, client) in collaboratorClients) {
                try {
                    val interactions = client.getAllInteractions()
                    appendLine("Client ID: $clientId")
                    appendLine("  Interactions: ${interactions.size}")
                    appendLine("  Server: ${client.server().address()}")
                    appendLine()
                } catch (e: Exception) {
                    appendLine("Client ID: $clientId")
                    appendLine("  Error: ${e.message}")
                    appendLine()
                }
            }
        }
    }
}

// ============== Data Classes ==============

@Serializable
class CollaboratorStatus

@Serializable
class CollaboratorGeneratePayload

@Serializable
data class CollaboratorGeneratePayloadWithData(
    val customData: String
)

@Serializable
data class CollaboratorPollInteractions(
    val clientId: String
)

@Serializable
data class CollaboratorRestoreClient(
    val secretKey: String
)

@Serializable
data class CollaboratorGetSecretKey(
    val clientId: String
)

@Serializable
class CollaboratorListClients
