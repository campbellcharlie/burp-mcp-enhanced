package net.portswigger.mcp.tools

import burp.api.montoya.MontoyaApi
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import net.portswigger.mcp.config.McpConfig
import net.portswigger.mcp.database.DatabaseService
import net.portswigger.mcp.database.RawSocketItem
import net.portswigger.mcp.security.HttpRequestSecurity
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

private val json = Json { prettyPrint = true }

// =============================================================================
// HPACK Implementation (RFC 7541) - No dynamic table (SETTINGS_HEADER_TABLE_SIZE=0)
// =============================================================================

/**
 * RFC 7541 Appendix A: Static Table Definition.
 * 61 entries, 1-indexed.
 */
private val HPACK_STATIC_TABLE: List<Pair<String, String>> = listOf(
    ":authority" to "",            // 1
    ":method" to "GET",            // 2
    ":method" to "POST",           // 3
    ":path" to "/",                // 4
    ":path" to "/index.html",      // 5
    ":scheme" to "http",           // 6
    ":scheme" to "https",          // 7
    ":status" to "200",            // 8
    ":status" to "204",            // 9
    ":status" to "206",            // 10
    ":status" to "304",            // 11
    ":status" to "400",            // 12
    ":status" to "404",            // 13
    ":status" to "500",            // 14
    "accept-charset" to "",        // 15
    "accept-encoding" to "gzip, deflate", // 16
    "accept-language" to "",       // 17
    "accept-ranges" to "",         // 18
    "accept" to "",                // 19
    "access-control-allow-origin" to "", // 20
    "age" to "",                   // 21
    "allow" to "",                 // 22
    "authorization" to "",         // 23
    "cache-control" to "",         // 24
    "content-disposition" to "",   // 25
    "content-encoding" to "",      // 26
    "content-language" to "",      // 27
    "content-length" to "",        // 28
    "content-location" to "",      // 29
    "content-range" to "",         // 30
    "content-type" to "",          // 31
    "cookie" to "",                // 32
    "date" to "",                  // 33
    "etag" to "",                  // 34
    "expect" to "",                // 35
    "expires" to "",               // 36
    "from" to "",                  // 37
    "host" to "",                  // 38
    "if-match" to "",              // 39
    "if-modified-since" to "",     // 40
    "if-none-match" to "",         // 41
    "if-range" to "",              // 42
    "if-unmodified-since" to "",   // 43
    "last-modified" to "",         // 44
    "link" to "",                  // 45
    "location" to "",              // 46
    "max-forwards" to "",          // 47
    "proxy-authenticate" to "",    // 48
    "proxy-authorization" to "",   // 49
    "range" to "",                 // 50
    "referer" to "",               // 51
    "refresh" to "",               // 52
    "retry-after" to "",           // 53
    "server" to "",                // 54
    "set-cookie" to "",            // 55
    "strict-transport-security" to "", // 56
    "transfer-encoding" to "",     // 57
    "user-agent" to "",            // 58
    "vary" to "",                  // 59
    "via" to "",                   // 60
    "www-authenticate" to ""       // 61
)

// Pre-built lookup: name+value -> 1-based index (for exact match)
private val STATIC_EXACT_INDEX: Map<Pair<String, String>, Int> by lazy {
    val m = HashMap<Pair<String, String>, Int>()
    HPACK_STATIC_TABLE.forEachIndexed { i, entry -> m[entry] = i + 1 }
    m
}

// Pre-built lookup: name -> first 1-based index (for name-only match)
private val STATIC_NAME_INDEX: Map<String, Int> by lazy {
    val m = HashMap<String, Int>()
    HPACK_STATIC_TABLE.forEachIndexed { i, (name, _) ->
        m.putIfAbsent(name, i + 1)
    }
    m
}

/**
 * HPACK encoder. Produces bytes for a list of header name/value pairs.
 * Uses indexed representation for exact static table matches,
 * literal with indexed name for name-only matches,
 * and literal without indexing for others.
 * Does NOT use Huffman encoding on outgoing strings.
 * Does NOT update dynamic table (table size is 0).
 */
internal object HpackEncoder {

    fun encode(headers: List<Pair<String, String>>): ByteArray {
        val out = ByteArrayOutputStream()
        for ((name, value) in headers) {
            val exactIdx = STATIC_EXACT_INDEX[name to value]
            if (exactIdx != null) {
                // Indexed Header Field Representation (Section 6.1)
                // High bit set, 7-bit prefix
                encodeInteger(out, exactIdx, 7, 0x80)
            } else {
                val nameIdx = STATIC_NAME_INDEX[name]
                if (nameIdx != null) {
                    // Literal Header Field without Indexing - Indexed Name (Section 6.2.2)
                    // 4-bit prefix, high nibble = 0000
                    encodeInteger(out, nameIdx, 4, 0x00)
                    encodeString(out, value)
                } else {
                    // Literal Header Field without Indexing - New Name (Section 6.2.2)
                    out.write(0x00)
                    encodeString(out, name)
                    encodeString(out, value)
                }
            }
        }
        return out.toByteArray()
    }

    private fun encodeInteger(out: ByteArrayOutputStream, value: Int, prefixBits: Int, mask: Int) {
        val maxPrefix = (1 shl prefixBits) - 1
        if (value < maxPrefix) {
            out.write(mask or value)
        } else {
            out.write(mask or maxPrefix)
            var remaining = value - maxPrefix
            while (remaining >= 128) {
                out.write((remaining and 0x7F) or 0x80)
                remaining = remaining ushr 7
            }
            out.write(remaining)
        }
    }

    private fun encodeString(out: ByteArrayOutputStream, s: String) {
        val bytes = s.toByteArray(Charsets.UTF_8)
        // No Huffman: high bit of length byte is 0
        encodeInteger(out, bytes.size, 7, 0x00)
        out.write(bytes)
    }
}

// =============================================================================
// HPACK Huffman Decoder (RFC 7541 Appendix B)
// =============================================================================

/**
 * RFC 7541 Appendix B Huffman code table.
 * Each entry: (code as Int/Long bits, bitLength) for symbols 0..256.
 * Symbol 256 = EOS.
 *
 * Format: Pair(code, bitLength). Code is stored in an Int (all codes fit in 30 bits).
 */
private val HUFFMAN_TABLE: Array<Pair<Int, Int>> = arrayOf(
    0x1ff8 to 13,    // 0
    0x7fffd8 to 23,  // 1
    0xfffffe2 to 28, // 2
    0xfffffe3 to 28, // 3
    0xfffffe4 to 28, // 4
    0xfffffe5 to 28, // 5
    0xfffffe6 to 28, // 6
    0xfffffe7 to 28, // 7
    0xfffffe8 to 28, // 8
    0xffffea to 24,  // 9
    0x3ffffffc to 30, // 10
    0xfffffe9 to 28, // 11
    0xfffffea to 28, // 12
    0x3ffffffd to 30, // 13
    0xfffffeb to 28, // 14
    0xfffffec to 28, // 15
    0xfffffed to 28, // 16
    0xfffffee to 28, // 17
    0xfffffef to 28, // 18
    0xffffff0 to 28, // 19
    0xffffff1 to 28, // 20
    0xffffff2 to 28, // 21
    0x3ffffffe to 30, // 22
    0xffffff3 to 28, // 23
    0xffffff4 to 28, // 24
    0xffffff5 to 28, // 25
    0xffffff6 to 28, // 26
    0xffffff7 to 28, // 27
    0xffffff8 to 28, // 28
    0xffffff9 to 28, // 29
    0xffffffa to 28, // 30
    0xffffffb to 28, // 31
    0x14 to 6,       // 32 ' '
    0x3f8 to 10,     // 33 '!'
    0x3f9 to 10,     // 34 '"'
    0xffa to 12,     // 35 '#'
    0x1ff9 to 13,    // 36 '$'
    0x15 to 6,       // 37 '%'
    0xf8 to 8,       // 38 '&'
    0x7fa to 11,     // 39 '''
    0x3fa to 10,     // 40 '('
    0x3fb to 10,     // 41 ')'
    0xf9 to 8,       // 42 '*'
    0x7fb to 11,     // 43 '+'
    0xfa to 8,       // 44 ','
    0x16 to 6,       // 45 '-'
    0x17 to 6,       // 46 '.'
    0x18 to 6,       // 47 '/'
    0x0 to 5,        // 48 '0'
    0x1 to 5,        // 49 '1'
    0x2 to 5,        // 50 '2'
    0x19 to 6,       // 51 '3'
    0x1a to 6,       // 52 '4'
    0x1b to 6,       // 53 '5'
    0x1c to 6,       // 54 '6'
    0x1d to 6,       // 55 '7'
    0x1e to 6,       // 56 '8'
    0x1f to 6,       // 57 '9'
    0x5c to 7,       // 58 ':'
    0xfb to 8,       // 59 ';'
    0x7ffc to 15,    // 60 '<'
    0x20 to 6,       // 61 '='
    0xffb to 12,     // 62 '>'
    0x3fc to 10,     // 63 '?'
    0x1ffa to 13,    // 64 '@'
    0x21 to 6,       // 65 'A'
    0x5d to 7,       // 66 'B'
    0x5e to 7,       // 67 'C'
    0x5f to 7,       // 68 'D'
    0x60 to 7,       // 69 'E'
    0x61 to 7,       // 70 'F'
    0x62 to 7,       // 71 'G'
    0x63 to 7,       // 72 'H'
    0x64 to 7,       // 73 'I'
    0x65 to 7,       // 74 'J'
    0x66 to 7,       // 75 'K'
    0x67 to 7,       // 76 'L'
    0x68 to 7,       // 77 'M'
    0x69 to 7,       // 78 'N'
    0x6a to 7,       // 79 'O'
    0x6b to 7,       // 80 'P'
    0x6c to 7,       // 81 'Q'
    0x6d to 7,       // 82 'R'
    0x6e to 7,       // 83 'S'
    0x6f to 7,       // 84 'T'
    0x70 to 7,       // 85 'U'
    0x71 to 7,       // 86 'V'
    0x72 to 7,       // 87 'W'
    0xfc to 8,       // 88 'X'
    0x73 to 7,       // 89 'Y'
    0xfd to 8,       // 90 'Z'
    0x1ffb to 13,    // 91 '['
    0x7fff0 to 19,   // 92 '\'
    0x1ffc to 13,    // 93 ']'
    0x3ffc to 14,    // 94 '^'
    0x22 to 6,       // 95 '_'
    0x7ffd to 15,    // 96 '`'
    0x3 to 5,        // 97 'a'
    0x23 to 6,       // 98 'b'
    0x4 to 5,        // 99 'c'
    0x24 to 6,       // 100 'd'
    0x5 to 5,        // 101 'e'
    0x25 to 6,       // 102 'f'
    0x26 to 6,       // 103 'g'
    0x27 to 6,       // 104 'h'
    0x6 to 5,        // 105 'i'
    0x74 to 7,       // 106 'j'
    0x75 to 7,       // 107 'k'
    0x28 to 6,       // 108 'l'
    0x29 to 6,       // 109 'm'
    0x2a to 6,       // 110 'n'
    0x7 to 5,        // 111 'o'
    0x2b to 6,       // 112 'p'
    0x76 to 7,       // 113 'q'
    0x2c to 6,       // 114 'r'
    0x8 to 5,        // 115 's'
    0x9 to 5,        // 116 't'
    0x2d to 6,       // 117 'u'
    0x77 to 7,       // 118 'v'
    0x78 to 7,       // 119 'w'
    0x79 to 7,       // 120 'x'
    0x7a to 7,       // 121 'y'
    0x7b to 7,       // 122 'z'
    0x7fffe to 19,   // 123 '{'
    0x7fc to 11,     // 124 '|'
    0x3ffd to 14,    // 125 '}'
    0x1ffd to 13,    // 126 '~'
    0xffffffc to 28, // 127
    0xfffe6 to 20,   // 128
    0x3fffd2 to 22,  // 129
    0xfffe7 to 20,   // 130
    0xfffe8 to 20,   // 131
    0x3fffd3 to 22,  // 132
    0x3fffd4 to 22,  // 133
    0x3fffd5 to 22,  // 134
    0x7fffd9 to 23,  // 135
    0x3fffd6 to 22,  // 136
    0x7fffda to 23,  // 137
    0x7fffdb to 23,  // 138
    0x7fffdc to 23,  // 139
    0x7fffdd to 23,  // 140
    0x7fffde to 23,  // 141
    0xffffeb to 24,  // 142
    0x7fffdf to 23,  // 143
    0xffffec to 24,  // 144
    0xffffed to 24,  // 145
    0x3fffd7 to 22,  // 146
    0x7fffe0 to 23,  // 147
    0xffffee to 24,  // 148
    0x7fffe1 to 23,  // 149
    0x7fffe2 to 23,  // 150
    0x7fffe3 to 23,  // 151
    0x7fffe4 to 23,  // 152
    0x1fffdc to 21,  // 153
    0x3fffd8 to 22,  // 154
    0x7fffe5 to 23,  // 155
    0x3fffd9 to 22,  // 156
    0x7fffe6 to 23,  // 157
    0x7fffe7 to 23,  // 158
    0xffffef to 24,  // 159
    0x3fffda to 22,  // 160
    0x1fffdd to 21,  // 161
    0xfffe9 to 20,   // 162
    0x3fffdb to 22,  // 163
    0x3fffdc to 22,  // 164
    0x7fffe8 to 23,  // 165
    0x7fffe9 to 23,  // 166
    0x1fffde to 21,  // 167
    0x7fffea to 23,  // 168
    0x3fffdd to 22,  // 169
    0x3fffde to 22,  // 170
    0xfffff0 to 24,  // 171
    0x1fffdf to 21,  // 172
    0x3fffdf to 22,  // 173
    0x7fffeb to 23,  // 174
    0x7fffec to 23,  // 175
    0x1fffe0 to 21,  // 176
    0x1fffe1 to 21,  // 177
    0x3fffe0 to 22,  // 178
    0x1fffe2 to 21,  // 179
    0x7fffed to 23,  // 180
    0x3fffe1 to 22,  // 181
    0x7fffee to 23,  // 182
    0x7fffef to 23,  // 183
    0xfffea to 20,   // 184
    0x3fffe2 to 22,  // 185
    0x3fffe3 to 22,  // 186
    0x3fffe4 to 22,  // 187
    0x7ffff0 to 23,  // 188
    0x3fffe5 to 22,  // 189
    0x3fffe6 to 22,  // 190
    0x7ffff1 to 23,  // 191
    0x3ffffe0 to 26, // 192
    0x3ffffe1 to 26, // 193
    0xfffeb to 20,   // 194
    0x7fff1 to 19,   // 195
    0x3fffe7 to 22,  // 196
    0x7ffff2 to 23,  // 197
    0x3fffe8 to 22,  // 198
    0x1ffffec to 25, // 199
    0x3ffffe2 to 26, // 200
    0x3ffffe3 to 26, // 201
    0x3ffffe4 to 26, // 202
    0x7ffffde to 27, // 203
    0x7ffffdf to 27, // 204
    0x3ffffe5 to 26, // 205
    0xfffff1 to 24,  // 206
    0x1ffffed to 25, // 207
    0x7fff2 to 19,   // 208
    0x1fffe3 to 21,  // 209
    0x3ffffe6 to 26, // 210
    0x7ffffe0 to 27, // 211
    0x7ffffe1 to 27, // 212
    0x3ffffe7 to 26, // 213
    0x7ffffe2 to 27, // 214
    0xfffff2 to 24,  // 215
    0x1fffe4 to 21,  // 216
    0x1fffe5 to 21,  // 217
    0x3ffffe8 to 26, // 218
    0x3ffffe9 to 26, // 219
    0xffffffd to 28, // 220
    0x7ffffe3 to 27, // 221
    0x7ffffe4 to 27, // 222
    0x7ffffe5 to 27, // 223
    0xfffec to 20,   // 224
    0xfffff3 to 24,  // 225
    0xfffed to 20,   // 226
    0x1fffe6 to 21,  // 227
    0x3fffe9 to 22,  // 228
    0x1fffe7 to 21,  // 229
    0x1fffe8 to 21,  // 230
    0x7ffff3 to 23,  // 231
    0x3fffea to 22,  // 232
    0x3fffeb to 22,  // 233
    0x1ffffee to 25, // 234
    0x1ffffef to 25, // 235
    0xfffff4 to 24,  // 236
    0xfffff5 to 24,  // 237
    0x3ffffea to 26, // 238
    0x7ffff4 to 23,  // 239
    0x3ffffeb to 26, // 240
    0x7ffffe6 to 27, // 241
    0x3ffffec to 26, // 242
    0x3ffffed to 26, // 243
    0x7ffffe7 to 27, // 244
    0x7ffffe8 to 27, // 245
    0x7ffffe9 to 27, // 246
    0x7ffffea to 27, // 247
    0x7ffffeb to 27, // 248
    0xffffffe to 28, // 249
    0x7ffffec to 27, // 250
    0x7ffffed to 27, // 251
    0x7ffffee to 27, // 252
    0x7ffffef to 27, // 253
    0x7fffff0 to 27, // 254
    0x3ffffee to 26, // 255
    0x3fffffff to 30 // 256 EOS
)

/**
 * Tree node for Huffman decoding. Each node is either a leaf (symbol >= 0)
 * or an internal node with children[0] and children[1].
 */
private class HuffmanNode {
    var symbol: Int = -1 // -1 = internal node, 0..256 = leaf
    var children: Array<HuffmanNode?> = arrayOf(null, null)
}

private val HUFFMAN_ROOT: HuffmanNode by lazy {
    val root = HuffmanNode()
    for (sym in HUFFMAN_TABLE.indices) {
        val (code, bits) = HUFFMAN_TABLE[sym]
        var node = root
        // Walk bits from MSB to LSB
        for (i in bits - 1 downTo 0) {
            val bit = (code ushr i) and 1
            if (node.children[bit] == null) {
                node.children[bit] = HuffmanNode()
            }
            node = node.children[bit]!!
        }
        node.symbol = sym
    }
    root
}

/**
 * Decode a Huffman-encoded byte array to a plain string.
 * Uses bit-by-bit tree traversal per RFC 7541 Section 5.2.
 */
private fun huffmanDecode(data: ByteArray): String {
    val out = ByteArrayOutputStream()
    var node = HUFFMAN_ROOT
    var bitsLeft = 0 // number of valid trailing bits in padding check

    for (byte in data) {
        for (i in 7 downTo 0) {
            val bit = (byte.toInt() ushr i) and 1
            node = node.children[bit]
                ?: throw IllegalStateException("Invalid Huffman code in HPACK data")
            if (node.symbol >= 0) {
                if (node.symbol == 256) {
                    // EOS symbol - should only appear as padding, stop decoding
                    return out.toString(Charsets.UTF_8.name())
                }
                out.write(node.symbol)
                node = HUFFMAN_ROOT
            }
        }
    }
    // Remaining bits should be padding (all 1s up to byte boundary)
    // We don't strictly validate this - just return what we've decoded
    return out.toString(Charsets.UTF_8.name())
}

/**
 * HPACK decoder. Parses encoded bytes into header name/value pairs.
 * Supports Huffman-encoded strings (servers commonly use them).
 * Does NOT maintain a dynamic table (table size 0).
 */
internal object HpackDecoder {

    fun decode(data: ByteArray): List<Pair<String, String>> {
        val headers = mutableListOf<Pair<String, String>>()
        var pos = 0

        while (pos < data.size) {
            val b = data[pos].toInt() and 0xFF

            when {
                // Indexed Header Field (Section 6.1): high bit set
                b and 0x80 != 0 -> {
                    val (index, newPos) = decodeInteger(data, pos, 7)
                    pos = newPos
                    if (index in 1..HPACK_STATIC_TABLE.size) {
                        val (name, value) = HPACK_STATIC_TABLE[index - 1]
                        headers.add(name to value)
                    }
                    // Indices beyond static table would reference dynamic table (which we don't maintain)
                }

                // Literal with Incremental Indexing (Section 6.2.1): 01xxxxxx
                b and 0xC0 == 0x40 -> {
                    val (nameIndex, newPos) = decodeInteger(data, pos, 6)
                    pos = newPos
                    val name: String
                    if (nameIndex > 0) {
                        name = if (nameIndex <= HPACK_STATIC_TABLE.size) {
                            HPACK_STATIC_TABLE[nameIndex - 1].first
                        } else ""
                    } else {
                        val (n, p) = decodeString(data, pos)
                        name = n; pos = p
                    }
                    val (value, p2) = decodeString(data, pos)
                    pos = p2
                    headers.add(name to value)
                }

                // Dynamic Table Size Update (Section 6.3): 001xxxxx
                b and 0xE0 == 0x20 -> {
                    val (_, newPos) = decodeInteger(data, pos, 5)
                    pos = newPos
                    // We don't maintain a dynamic table, so just consume and ignore.
                }

                // Literal without Indexing (Section 6.2.2): 0000xxxx
                // Literal Never Indexed (Section 6.2.3): 0001xxxx
                else -> {
                    val prefixBits = if (b and 0xF0 == 0x10) 4 else 4
                    val (nameIndex, newPos) = decodeInteger(data, pos, prefixBits)
                    pos = newPos
                    val name: String
                    if (nameIndex > 0) {
                        name = if (nameIndex <= HPACK_STATIC_TABLE.size) {
                            HPACK_STATIC_TABLE[nameIndex - 1].first
                        } else ""
                    } else {
                        val (n, p) = decodeString(data, pos)
                        name = n; pos = p
                    }
                    val (value, p2) = decodeString(data, pos)
                    pos = p2
                    headers.add(name to value)
                }
            }
        }

        return headers
    }

    private fun decodeInteger(data: ByteArray, startPos: Int, prefixBits: Int): Pair<Int, Int> {
        val maxPrefix = (1 shl prefixBits) - 1
        var value = (data[startPos].toInt() and 0xFF) and maxPrefix
        var pos = startPos + 1

        if (value < maxPrefix) {
            return value to pos
        }

        var shift = 0
        while (pos < data.size) {
            val b = data[pos].toInt() and 0xFF
            pos++
            value += (b and 0x7F) shl shift
            if (b and 0x80 == 0) break
            shift += 7
        }
        return value to pos
    }

    private fun decodeString(data: ByteArray, startPos: Int): Pair<String, Int> {
        val huffmanEncoded = (data[startPos].toInt() and 0x80) != 0
        val (length, pos) = decodeInteger(data, startPos, 7)
        val end = pos + length

        val stringBytes = data.copyOfRange(pos, end.coerceAtMost(data.size))
        val str = if (huffmanEncoded) {
            huffmanDecode(stringBytes)
        } else {
            String(stringBytes, Charsets.UTF_8)
        }
        return str to end
    }
}

// =============================================================================
// HTTP/2 Frame Builder/Reader
// =============================================================================

// Frame types
private const val FRAME_DATA: Int = 0x0
private const val FRAME_HEADERS: Int = 0x1
private const val FRAME_SETTINGS: Int = 0x4
private const val FRAME_PING: Int = 0x6
private const val FRAME_GOAWAY: Int = 0x7
private const val FRAME_WINDOW_UPDATE: Int = 0x8
private const val FRAME_RST_STREAM: Int = 0x3

// Flags
private const val FLAG_END_STREAM: Int = 0x1
private const val FLAG_END_HEADERS: Int = 0x4
private const val FLAG_ACK: Int = 0x1  // For SETTINGS and PING

// Settings IDs
private const val SETTINGS_HEADER_TABLE_SIZE: Int = 0x1
private const val SETTINGS_ENABLE_PUSH: Int = 0x2
private const val SETTINGS_MAX_CONCURRENT_STREAMS: Int = 0x3
private const val SETTINGS_INITIAL_WINDOW_SIZE: Int = 0x4

private data class H2Frame(
    val type: Int,
    val flags: Int,
    val streamId: Int,
    val payload: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is H2Frame) return false
        return type == other.type && flags == other.flags &&
            streamId == other.streamId && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = type
        result = 31 * result + flags
        result = 31 * result + streamId
        result = 31 * result + payload.contentHashCode()
        return result
    }
}

/**
 * Build an HTTP/2 frame: 9-byte header + payload.
 * Length(3) + Type(1) + Flags(1) + Reserved(1 bit) + StreamID(31 bits).
 */
private fun buildFrame(type: Int, flags: Int, streamId: Int, payload: ByteArray = ByteArray(0)): ByteArray {
    val frame = ByteArray(9 + payload.size)
    // Length: 3 bytes big-endian
    frame[0] = ((payload.size ushr 16) and 0xFF).toByte()
    frame[1] = ((payload.size ushr 8) and 0xFF).toByte()
    frame[2] = (payload.size and 0xFF).toByte()
    // Type
    frame[3] = type.toByte()
    // Flags
    frame[4] = flags.toByte()
    // Stream ID: 4 bytes big-endian (high bit reserved, always 0 for client)
    frame[5] = ((streamId ushr 24) and 0x7F).toByte()
    frame[6] = ((streamId ushr 16) and 0xFF).toByte()
    frame[7] = ((streamId ushr 8) and 0xFF).toByte()
    frame[8] = (streamId and 0xFF).toByte()
    // Payload
    System.arraycopy(payload, 0, frame, 9, payload.size)
    return frame
}

/**
 * Read exactly [n] bytes from the input stream, or throw.
 */
private fun readExact(input: InputStream, n: Int): ByteArray {
    val buf = ByteArray(n)
    var off = 0
    while (off < n) {
        val r = input.read(buf, off, n - off)
        if (r <= 0) throw java.io.EOFException("Connection closed while reading frame (needed $n bytes, got $off)")
        off += r
    }
    return buf
}

/**
 * Read one HTTP/2 frame from the input stream.
 */
private fun readFrame(input: InputStream): H2Frame {
    val header = readExact(input, 9)
    val length = ((header[0].toInt() and 0xFF) shl 16) or
        ((header[1].toInt() and 0xFF) shl 8) or
        (header[2].toInt() and 0xFF)
    val type = header[3].toInt() and 0xFF
    val flags = header[4].toInt() and 0xFF
    val streamId = ((header[5].toInt() and 0x7F) shl 24) or
        ((header[6].toInt() and 0xFF) shl 16) or
        ((header[7].toInt() and 0xFF) shl 8) or
        (header[8].toInt() and 0xFF)

    val payload = if (length > 0) readExact(input, length) else ByteArray(0)
    return H2Frame(type, flags, streamId, payload)
}

/**
 * Build a SETTINGS frame payload from a map of setting ID -> value.
 * Each setting is 6 bytes: ID(2) + Value(4), all big-endian.
 */
private fun buildSettingsPayload(settings: Map<Int, Int>): ByteArray {
    val out = ByteArray(settings.size * 6)
    var off = 0
    for ((id, value) in settings) {
        out[off] = ((id ushr 8) and 0xFF).toByte()
        out[off + 1] = (id and 0xFF).toByte()
        out[off + 2] = ((value ushr 24) and 0xFF).toByte()
        out[off + 3] = ((value ushr 16) and 0xFF).toByte()
        out[off + 4] = ((value ushr 8) and 0xFF).toByte()
        out[off + 5] = (value and 0xFF).toByte()
        off += 6
    }
    return out
}

/**
 * Build a WINDOW_UPDATE frame payload (4 bytes big-endian increment).
 */
private fun buildWindowUpdatePayload(increment: Int): ByteArray {
    return byteArrayOf(
        ((increment ushr 24) and 0x7F).toByte(),
        ((increment ushr 16) and 0xFF).toByte(),
        ((increment ushr 8) and 0xFF).toByte(),
        (increment and 0xFF).toByte()
    )
}

// =============================================================================
// MCP Tool Data Classes
// =============================================================================

@Serializable
data class H2SequenceRequest(
    val method: String = "GET",
    val path: String = "/",
    val authority: String? = null,
    val scheme: String = "https",
    val headers: Map<String, String> = emptyMap(),
    val body: String = "",
    val bodyBase64: String? = null,
    val delayMs: Int = 0
)

@Serializable
data class SendHttp2Sequence(
    val requests: List<H2SequenceRequest>,
    val targetHostname: String,
    val targetPort: Int = 443,
    val insecureSkipVerify: Boolean = true,
    val ignoreAlpn: Boolean = false,
    val connectTimeoutMs: Int = 5000,
    val readTimeoutMs: Int = 3000,
    val maxReadBytes: Int = 500_000,
    val responsePreviewBytes: Int = 2000
)

@Serializable
data class H2SequenceResponse(
    val negotiatedProtocol: String?,
    val results: List<H2ResponseResult>
)

@Serializable
data class H2ResponseResult(
    val streamId: Int,
    val status: String?,
    val headers: Map<String, String>,
    val bodyPreview: String,
    val bodyBase64: String?,
    val bodySize: Int,
    val error: String? = null
)

// =============================================================================
// Internal per-stream accumulator
// =============================================================================

private class StreamAccumulator {
    val headers = mutableListOf<Pair<String, String>>()
    val dataChunks = ByteArrayOutputStream()
    var endStreamReceived = false
    var error: String? = null
}

// =============================================================================
// Tool Registration
// =============================================================================

fun Server.registerHttp2SequenceTools(api: MontoyaApi, config: McpConfig, db: DatabaseService? = null) {

    mcpTool<SendHttp2Sequence>(
        "Send multiple HTTP/2 requests sequentially on a single TLS connection. " +
            "Guarantees same-connection delivery for response queue poisoning, " +
            "connection state attacks, and other same-connection sequential attacks."
    ) {
        // --- Security checks (same pattern as send_raw_tls) ---
        if (!config.rawSocketToolsEnabled) {
            return@mcpTool "Error: raw socket tools are disabled in Burp MCP settings."
        }
        if (!isTargetAllowed(targetHostname, targetPort, config)) {
            return@mcpTool "Error: target not in raw socket allowlist."
        }
        if (requests.isEmpty()) {
            return@mcpTool "Error: requests must be non-empty."
        }
        if (requests.size > 100) {
            return@mcpTool "Error: too many requests (max 100)."
        }

        // Build a human-readable preview for the approval dialog
        val preview = buildString {
            appendLine("HTTP/2 Sequence preview:")
            appendLine("Target: $targetHostname:$targetPort")
            appendLine("Requests: ${requests.size}")
            appendLine()
            requests.take(5).forEachIndexed { idx, req ->
                appendLine("req#${idx + 1}: ${req.method} ${req.path}")
                if (req.headers.isNotEmpty()) {
                    req.headers.entries.take(5).forEach { (k, v) ->
                        appendLine("  $k: $v")
                    }
                }
                val bodyBytes = resolveBody(req)
                if (bodyBytes.isNotEmpty()) {
                    appendLine("  body: ${bodyBytes.size} bytes")
                }
            }
            if (requests.size > 5) appendLine("... (${requests.size - 5} more requests)")
        }

        val allowed = runBlocking {
            HttpRequestSecurity.checkHttpRequestPermission(
                targetHostname, targetPort, config, preview, api
            )
        }
        if (!allowed) return@mcpTool "Send denied by Burp Suite."

        // --- Open TLS connection ---
        val ctx = if (insecureSkipVerify) buildInsecureSslContext() else SSLContext.getDefault()
        val sslSocket = (ctx.socketFactory.createSocket() as? SSLSocket)
            ?: return@mcpTool "Error: failed to create SSL socket"

        try {
            val startNs = System.nanoTime()
            sslSocket.connect(InetSocketAddress(targetHostname, targetPort), connectTimeoutMs)
            sslSocket.soTimeout = readTimeoutMs
            sslSocket.sslParameters = sslSocket.sslParameters.apply {
                applicationProtocols = arrayOf("h2")
            }
            sslSocket.startHandshake()

            val negotiatedAlpn = try { sslSocket.applicationProtocol } catch (_: Exception) { null }

            // If ALPN didn't negotiate "h2" and we are not ignoring, bail
            if (!ignoreAlpn && negotiatedAlpn != "h2") {
                return@mcpTool "Error: server did not negotiate h2 via ALPN " +
                    "(got: ${negotiatedAlpn ?: "null"}). Set ignoreAlpn=true to proceed anyway."
            }

            val output = sslSocket.getOutputStream()
            val input = sslSocket.getInputStream()

            // --- HTTP/2 Connection Preface (Section 3.5) ---
            val preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".toByteArray(Charsets.US_ASCII)
            output.write(preface)

            // --- Send client SETTINGS ---
            val settingsPayload = buildSettingsPayload(mapOf(
                SETTINGS_HEADER_TABLE_SIZE to 0,
                SETTINGS_ENABLE_PUSH to 0,
                SETTINGS_MAX_CONCURRENT_STREAMS to 100,
                SETTINGS_INITIAL_WINDOW_SIZE to 65535
            ))
            output.write(buildFrame(FRAME_SETTINGS, 0, 0, settingsPayload))
            output.flush()

            // --- Read server's SETTINGS (and possibly other frames) ---
            // We need to read at least until we get the server's SETTINGS, then ACK it.
            var serverSettingsReceived = false
            var goawayReceived = false
            var goawayMessage = ""

            // Read frames until we get server SETTINGS (with a reasonable limit)
            for (attempt in 0 until 20) {
                val frame: H2Frame
                try {
                    frame = readFrame(input)
                } catch (e: SocketTimeoutException) {
                    break // no more frames pending
                } catch (e: java.io.EOFException) {
                    return@mcpTool "Error: connection closed during HTTP/2 handshake"
                }

                when (frame.type) {
                    FRAME_SETTINGS -> {
                        if (frame.flags and FLAG_ACK == 0) {
                            // Server's SETTINGS - send ACK
                            output.write(buildFrame(FRAME_SETTINGS, FLAG_ACK, 0))
                            output.flush()
                            serverSettingsReceived = true
                        }
                        // If ACK, that's the server acknowledging our SETTINGS - fine
                    }
                    FRAME_WINDOW_UPDATE -> { /* ignore */ }
                    FRAME_PING -> {
                        // Must ACK pings
                        output.write(buildFrame(FRAME_PING, FLAG_ACK, 0, frame.payload))
                        output.flush()
                    }
                    FRAME_GOAWAY -> {
                        goawayReceived = true
                        goawayMessage = if (frame.payload.size >= 8) {
                            val errorCode = ((frame.payload[4].toInt() and 0xFF) shl 24) or
                                ((frame.payload[5].toInt() and 0xFF) shl 16) or
                                ((frame.payload[6].toInt() and 0xFF) shl 8) or
                                (frame.payload[7].toInt() and 0xFF)
                            val debug = if (frame.payload.size > 8) {
                                String(frame.payload, 8, frame.payload.size - 8, Charsets.UTF_8)
                            } else ""
                            "GOAWAY error=$errorCode $debug"
                        } else "GOAWAY"
                        break
                    }
                }

                if (serverSettingsReceived) break
            }

            if (goawayReceived) {
                return@mcpTool "Error: server sent $goawayMessage during handshake"
            }

            // --- Send WINDOW_UPDATE on stream 0 to allow large responses ---
            // Increment by ~1GB (0x3FFFFFFF = 1073741823)
            output.write(buildFrame(FRAME_WINDOW_UPDATE, 0, 0,
                buildWindowUpdatePayload(0x3FFFFFFF)))
            output.flush()

            // --- Send requests, read responses one stream at a time ---
            val streams = mutableMapOf<Int, StreamAccumulator>()
            val results = mutableListOf<H2ResponseResult>()
            var nextStreamId = 1

            for (req in requests) {
                val streamId = nextStreamId
                nextStreamId += 2
                streams[streamId] = StreamAccumulator()

                // Build pseudo-headers + regular headers
                val authority = req.authority ?: targetHostname
                val headerList = mutableListOf<Pair<String, String>>()
                headerList.add(":method" to req.method)
                headerList.add(":path" to req.path)
                headerList.add(":scheme" to req.scheme)
                headerList.add(":authority" to authority)

                // Add regular headers (lowercase names for HTTP/2 compliance)
                for ((k, v) in req.headers) {
                    headerList.add(k.lowercase() to v)
                }

                val bodyBytes = resolveBody(req)

                // Encode headers via HPACK
                val hpackBytes = HpackEncoder.encode(headerList)

                // HEADERS frame flags
                var headersFlags = FLAG_END_HEADERS
                if (bodyBytes.isEmpty()) {
                    headersFlags = headersFlags or FLAG_END_STREAM
                }

                output.write(buildFrame(FRAME_HEADERS, headersFlags, streamId, hpackBytes))

                // DATA frame if body exists
                if (bodyBytes.isNotEmpty()) {
                    output.write(buildFrame(FRAME_DATA, FLAG_END_STREAM, streamId, bodyBytes))
                }

                output.flush()

                // Read response frames until this stream gets END_STREAM
                val acc = streams[streamId]!!
                readResponseFrames(input, output, streams, streamId, maxReadBytes, readTimeoutMs)

                // Build result for this stream
                val status = acc.headers.firstOrNull { it.first == ":status" }?.second
                val responseHeaders = LinkedHashMap<String, String>()
                for ((name, value) in acc.headers) {
                    if (!name.startsWith(":")) {
                        responseHeaders[name] = value
                    }
                }
                val responseBody = acc.dataChunks.toByteArray()

                results.add(H2ResponseResult(
                    streamId = streamId,
                    status = status,
                    headers = responseHeaders,
                    bodyPreview = renderBytesPreview(responseBody, responsePreviewBytes),
                    bodyBase64 = if (responseBody.isNotEmpty()) b64encode(responseBody) else null,
                    bodySize = responseBody.size,
                    error = acc.error
                ))

                // Delay before next request if specified
                if (req.delayMs > 0) {
                    Thread.sleep(req.delayMs.toLong())
                }
            }

            val elapsedMs = (System.nanoTime() - startNs) / 1_000_000

            val response = H2SequenceResponse(
                negotiatedProtocol = negotiatedAlpn,
                results = results
            )

            // --- DB logging ---
            db?.let {
                try {
                    val summaryPreview = results.joinToString("\n") { r ->
                        "stream=${r.streamId} status=${r.status ?: "?"} body=${r.bodySize}b"
                    }
                    it.insertRawSocketTraffic(RawSocketItem(
                        timestamp = now(),
                        tool = "http2-sequence",
                        targetHost = targetHostname,
                        targetPort = targetPort,
                        protocol = "TLS",
                        tlsAlpn = negotiatedAlpn ?: "h2",
                        responsePreview = summaryPreview.take(2000),
                        bytesSent = null, // individual frames make byte count less meaningful
                        bytesReceived = results.sumOf { r -> r.bodySize },
                        elapsedMs = elapsedMs,
                        segmentCount = requests.size,
                        notes = "HTTP/2 sequence: ${requests.size} requests, " +
                            "streams=${results.joinToString(",") { r -> r.streamId.toString() }}"
                    ))
                } catch (e: Exception) {
                    api.logging().logToError("Failed to log HTTP/2 sequence traffic: ${e.message}")
                }
            }

            json.encodeToString(response)
        } finally {
            try { sslSocket.close() } catch (_: Exception) {}
        }
    }
}

// =============================================================================
// Private Helpers
// =============================================================================

/**
 * Resolve the body bytes for a request, preferring bodyBase64 over body.
 */
private fun resolveBody(req: H2SequenceRequest): ByteArray {
    return when {
        req.bodyBase64 != null -> b64decode(req.bodyBase64)
        req.body.isNotEmpty() -> req.body.toByteArray(Charsets.UTF_8)
        else -> ByteArray(0)
    }
}

/**
 * Read frames from the connection until the target stream has received END_STREAM
 * or we hit a timeout/error. Handles control frames (PING ACK, SETTINGS ACK,
 * WINDOW_UPDATE, GOAWAY) on the side.
 */
private fun readResponseFrames(
    input: InputStream,
    output: java.io.OutputStream,
    streams: MutableMap<Int, StreamAccumulator>,
    targetStreamId: Int,
    maxReadBytes: Int,
    readTimeoutMs: Int
) {
    val acc = streams[targetStreamId] ?: return
    val deadline = System.currentTimeMillis() + readTimeoutMs + 5000L // generous deadline

    while (!acc.endStreamReceived && System.currentTimeMillis() < deadline) {
        val frame: H2Frame
        try {
            frame = readFrame(input)
        } catch (_: SocketTimeoutException) {
            acc.error = (acc.error ?: "") + "Timeout waiting for response. "
            break
        } catch (e: java.io.EOFException) {
            acc.error = (acc.error ?: "") + "Connection closed before END_STREAM. "
            break
        } catch (e: Exception) {
            acc.error = (acc.error ?: "") + "Read error: ${e.message}. "
            break
        }

        when (frame.type) {
            FRAME_HEADERS -> {
                // Decode HPACK headers and store in the appropriate stream
                val streamAcc = streams[frame.streamId]
                if (streamAcc != null) {
                    try {
                        val decoded = HpackDecoder.decode(frame.payload)
                        streamAcc.headers.addAll(decoded)
                    } catch (e: Exception) {
                        streamAcc.error = (streamAcc.error ?: "") + "HPACK decode error: ${e.message}. "
                    }
                    if (frame.flags and FLAG_END_STREAM != 0) {
                        streamAcc.endStreamReceived = true
                    }
                }
            }

            FRAME_DATA -> {
                val streamAcc = streams[frame.streamId]
                if (streamAcc != null) {
                    if (streamAcc.dataChunks.size() + frame.payload.size <= maxReadBytes) {
                        streamAcc.dataChunks.write(frame.payload)
                    }
                    if (frame.flags and FLAG_END_STREAM != 0) {
                        streamAcc.endStreamReceived = true
                    }
                }
                // Send WINDOW_UPDATE to keep flow control open (stream + connection level)
                if (frame.payload.isNotEmpty()) {
                    try {
                        output.write(buildFrame(FRAME_WINDOW_UPDATE, 0, 0,
                            buildWindowUpdatePayload(frame.payload.size)))
                        if (frame.streamId != 0) {
                            output.write(buildFrame(FRAME_WINDOW_UPDATE, 0, frame.streamId,
                                buildWindowUpdatePayload(frame.payload.size)))
                        }
                        output.flush()
                    } catch (_: Exception) { /* socket may be closing */ }
                }
            }

            FRAME_SETTINGS -> {
                if (frame.flags and FLAG_ACK == 0) {
                    // ACK any non-ACK SETTINGS
                    try {
                        output.write(buildFrame(FRAME_SETTINGS, FLAG_ACK, 0))
                        output.flush()
                    } catch (_: Exception) {}
                }
            }

            FRAME_PING -> {
                // ACK pings
                try {
                    output.write(buildFrame(FRAME_PING, FLAG_ACK, 0, frame.payload))
                    output.flush()
                } catch (_: Exception) {}
            }

            FRAME_GOAWAY -> {
                // Server is shutting down the connection
                val errorInfo = if (frame.payload.size >= 8) {
                    val errorCode = ((frame.payload[4].toInt() and 0xFF) shl 24) or
                        ((frame.payload[5].toInt() and 0xFF) shl 16) or
                        ((frame.payload[6].toInt() and 0xFF) shl 8) or
                        (frame.payload[7].toInt() and 0xFF)
                    "GOAWAY error=$errorCode"
                } else "GOAWAY"
                acc.error = (acc.error ?: "") + "$errorInfo. "
                // Mark all pending streams as errored
                for ((_, streamAcc) in streams) {
                    if (!streamAcc.endStreamReceived) {
                        streamAcc.error = (streamAcc.error ?: "") + "$errorInfo. "
                        streamAcc.endStreamReceived = true
                    }
                }
                return
            }

            FRAME_RST_STREAM -> {
                val streamAcc = streams[frame.streamId]
                if (streamAcc != null) {
                    val errorCode = if (frame.payload.size >= 4) {
                        ((frame.payload[0].toInt() and 0xFF) shl 24) or
                            ((frame.payload[1].toInt() and 0xFF) shl 16) or
                            ((frame.payload[2].toInt() and 0xFF) shl 8) or
                            (frame.payload[3].toInt() and 0xFF)
                    } else 0
                    streamAcc.error = (streamAcc.error ?: "") + "RST_STREAM error=$errorCode. "
                    streamAcc.endStreamReceived = true
                }
            }

            FRAME_WINDOW_UPDATE -> { /* ignore */ }

            else -> { /* unknown frame type, ignore */ }
        }
    }
}
