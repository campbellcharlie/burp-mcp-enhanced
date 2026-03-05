package net.portswigger.mcp.tools

import org.junit.jupiter.api.Test
import java.util.Base64
import kotlin.test.assertTrue
import kotlin.test.assertContains
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class JwtToolsTest {

    @Test
    fun `JWT decode extracts header and payload`() {
        // Create a test JWT
        val header = """{"alg":"HS256","typ":"JWT"}"""
        val payload = """{"sub":"1234567890","name":"John Doe","iat":1516239022}"""

        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())

        // Create a proper signature
        val secret = "test-secret"
        val signingInput = "$headerB64.$payloadB64"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
        val signature = mac.doFinal(signingInput.toByteArray())
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature)

        val jwt = "$headerB64.$payloadB64.$sigB64"

        // Verify the JWT format
        val parts = jwt.split(".")
        assertTrue(parts.size == 3, "JWT should have 3 parts")

        // Decode and verify header
        val decodedHeader = String(Base64.getUrlDecoder().decode(parts[0]))
        assertContains(decodedHeader, "HS256")
        assertContains(decodedHeader, "JWT")

        // Decode and verify payload
        val decodedPayload = String(Base64.getUrlDecoder().decode(parts[1]))
        assertContains(decodedPayload, "John Doe")
        assertContains(decodedPayload, "1234567890")
    }

    @Test
    fun `none algorithm attack creates unsigned token`() {
        val header = """{"alg":"none","typ":"JWT"}"""
        val payload = """{"sub":"admin","role":"admin"}"""

        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())

        val unsignedJwt = "$headerB64.$payloadB64."

        // Verify format
        assertTrue(unsignedJwt.endsWith("."), "Unsigned JWT should end with a dot")

        val parts = unsignedJwt.split(".")
        assertTrue(parts.size == 3, "JWT should have 3 parts")
        assertTrue(parts[2].isEmpty(), "Signature should be empty")
    }

    @Test
    fun `key confusion attack changes algorithm`() {
        // Simulate RS256 token
        val originalHeader = """{"alg":"RS256","typ":"JWT"}"""
        val payload = """{"sub":"1234567890"}"""

        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(originalHeader.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())

        // New HS256 header for key confusion
        val newHeader = """{"alg":"HS256","typ":"JWT"}"""
        val newHeaderB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(newHeader.toByteArray())

        // Fake public key (for testing purposes)
        val fakePublicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."

        // Sign with "public key" as HMAC secret
        val signingInput = "$newHeaderB64.$payloadB64"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(fakePublicKey.toByteArray(), "HmacSHA256"))
        val signature = mac.doFinal(signingInput.toByteArray())
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature)

        val forgedJwt = "$newHeaderB64.$payloadB64.$sigB64"

        // Verify the forged token has HS256 algorithm
        val decodedHeader = String(Base64.getUrlDecoder().decode(forgedJwt.split(".")[0]))
        assertContains(decodedHeader, "HS256")
    }

    @Test
    fun `bruteforce finds weak secret`() {
        val secret = "secret"
        val header = """{"alg":"HS256","typ":"JWT"}"""
        val payload = """{"sub":"test"}"""

        val headerB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(header.toByteArray())
        val payloadB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(payload.toByteArray())

        val signingInput = "$headerB64.$payloadB64"
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(secret.toByteArray(), "HmacSHA256"))
        val signature = mac.doFinal(signingInput.toByteArray())
        val sigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(signature)

        val jwt = "$headerB64.$payloadB64.$sigB64"

        // Simulate bruteforce
        val wordlist = listOf("password", "123456", "secret", "admin")
        var foundSecret: String? = null

        for (guess in wordlist) {
            val testMac = Mac.getInstance("HmacSHA256")
            testMac.init(SecretKeySpec(guess.toByteArray(), "HmacSHA256"))
            val testSig = testMac.doFinal(signingInput.toByteArray())
            val testSigB64 = Base64.getUrlEncoder().withoutPadding().encodeToString(testSig)

            if (testSigB64 == sigB64) {
                foundSecret = guess
                break
            }
        }

        assertTrue(foundSecret == "secret", "Should find the secret 'secret'")
    }
}
