package net.portswigger.mcp.tools

import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable

/**
 * Register the help meta-tool for AI workflow guidance.
 */
fun Server.registerHelpTools() {

    mcpTool<Help>(
        "Get usage guidance, workflow examples, and tool chain documentation. " +
        "Topics: overview, mindset, workflows, http, traffic, collaborator, jwt, graphql, race, smuggling, " +
        "session, scope, scanner, raw-sockets, detection, payloads, lessons, access-control. " +
        "Call with topic='overview' to see all available categories."
    ) {
        val content = helpTopics[topic.lowercase()] ?: helpTopics["overview"]!!
        content
    }
}

@Serializable
data class Help(val topic: String = "overview")

private val helpTopics: Map<String, String> by lazy {
    val topics = listOf(
        "overview", "mindset", "workflows", "http", "traffic",
        "collaborator", "jwt", "graphql", "race", "smuggling",
        "session", "scope", "scanner", "raw-sockets",
        "detection", "payloads", "lessons", "access-control"
    )
    topics.associateWith { topic ->
        Help::class.java.getResourceAsStream("/help/$topic.txt")
            ?.bufferedReader()?.readText()
            ?: "Topic '$topic' not found. Available topics: ${topics.joinToString(", ")}"
    }
}
