# Burp Suite MCP Server Extension (Enhanced)

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

This enhanced fork adds SQLite traffic logging with FTS5 search, race condition testing tools, JWT analysis, response diffing, session management, and GraphQL introspection.

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

### Core Features (from PortSwigger)
- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Comes with packaged Stdio MCP proxy server

### Enhanced Features (this fork)

#### SQLite Traffic Logging
- Automatic logging of all HTTP traffic to SQLite database
- FTS5 full-text search across requests and responses
- Configurable logging per tool (Proxy, Repeater, Scanner, Intruder, Extensions)
- Non-blocking queue architecture - zero impact on Burp performance

#### Security Testing Tools
- **Race Condition Testing**: `send_parallel`, `send_parallel_different`, `send_parallel_h2`
  - Send multiple identical or different requests simultaneously
  - HTTP/2 single-packet attack support
  - Timing analysis and response comparison

- **JWT Analysis**: `jwt_decode`, `jwt_forge`, `jwt_none_attack`, `jwt_key_confusion`, `jwt_bruteforce`
  - Decode and inspect JWT tokens
  - Forge tokens with custom claims
  - Perform none algorithm attack
  - Algorithm confusion (RS256 -> HS256)
  - Bruteforce weak secrets

- **Response Analysis**: `compare_responses`, `extract_regex`, `extract_json_path`, `extract_between`, `analyze_response`
  - Diff two responses with configurable header ignoring
  - Extract data with regex or JSONPath
  - Analyze responses for security issues

- **Session Management**: `session_create`, `session_switch`, `session_list`, `csrf_extract`
  - Named sessions with cookies and headers
  - CSRF token extraction and storage
  - Easy context switching between user sessions

- **GraphQL Tools**: `graphql_introspect`, `graphql_build_query`, `graphql_suggest_payloads`
  - Schema introspection with bypass techniques
  - Query builder from introspection results
  - Attack payload suggestions

- **Raw Socket Tools (dangerous)**: `send_raw_tcp`, `send_raw_tls`, `last_byte_sync_raw`
  - Byte-level TCP/TLS sending with segmented writes + delays
  - Useful for pause-based desync/smuggling research and frame-level experiments
  - Restricted by an explicit allowlist in the MCP tab

## New MCP Tools Reference

### Traffic Search Tools

| Tool | Description |
|------|-------------|
| `search_traffic` | FTS5 search across logged traffic. Supports AND, OR, NOT, phrases, prefix matching |
| `search_traffic_regex` | Regex search in specific fields (URL, headers, body) |
| `get_traffic_by_id` | Get full request/response details by ID |
| `get_traffic_stats` | View traffic statistics and queue health |
| `set_traffic_logging` | Enable/disable logging per tool |

### Race Condition Tools

| Tool | Description |
|------|-------------|
| `send_parallel` | Send N identical requests simultaneously |
| `send_parallel_different` | Send multiple different requests simultaneously |
| `send_parallel_h2` | HTTP/2 requests for tighter race windows |
| `last_byte_sync` | Last-byte synchronization attack (simulated) |

### JWT Tools

| Tool | Description |
|------|-------------|
| `jwt_decode` | Decode and display JWT header/payload |
| `jwt_forge` | Create JWT with custom claims and signing |
| `jwt_none_attack` | Generate unsigned tokens (alg:none) |
| `jwt_key_confusion` | RS256 -> HS256 algorithm confusion attack |
| `jwt_bruteforce` | Bruteforce HMAC secret from wordlist |

### Response Analysis Tools

| Tool | Description |
|------|-------------|
| `compare_responses` | Unified diff between two responses |
| `extract_regex` | Extract content using regex pattern |
| `extract_json_path` | Extract data using JSONPath expressions |
| `extract_between` | Extract content between delimiters |
| `analyze_response` | Security analysis of response headers/body |

### Session Tools

| Tool | Description |
|------|-------------|
| `session_create` | Create named session with cookies/headers |
| `session_switch` | Switch active session context |
| `session_list` | List all available sessions |
| `session_delete` | Delete a session |
| `session_update_cookies` | Update session cookies from Set-Cookie headers |
| `csrf_extract` | Extract and store CSRF tokens |
| `session_get_headers` | Get Cookie header for current session |

### GraphQL Tools

| Tool | Description |
|------|-------------|
| `graphql_introspect` | Discover GraphQL schema with bypass techniques |
| `graphql_build_query` | Build query from type/field specifications |
| `graphql_suggest_payloads` | Get attack payloads by category |

### Raw Socket Tools (dangerous)

| Tool | Description |
|------|-------------|
| `send_raw_tcp` | Send base64 raw TCP bytes in segments with delays; returns base64 response + preview |
| `send_raw_tls` | Send base64 raw TLS bytes with optional ALPN; returns base64 response + preview + negotiated ALPN |
| `last_byte_sync_raw` | True last-byte synchronization using raw sockets (TCP/TLS) |

## Installation

### Prerequisites

1. **Java**: Java 21+ required. Verify with `java --version`
2. **jar Command**: Required for build. Verify with `jar --version`

### Building the Extension

```bash
git clone https://github.com/campbellcharlie/burp-mcp-enhanced.git
cd burp-mcp-enhanced
./gradlew embedProxyJar
```

The built JAR is at `build/libs/burp-mcp-all.jar`.

### Loading into Burp Suite

1. Open Burp Suite
2. Navigate to Extensions > Add
3. Set Extension Type to Java
4. Select the built JAR file
5. Click Next to load

## Configuration

### MCP Tab Settings

- **Enabled**: Toggle MCP server on/off
- **Enable config editing**: Allow config modification tools
- **Host/Port**: Server binding (default: 127.0.0.1:9876)

### Traffic Logging Settings (new)

- **Traffic Logging Enabled**: Master toggle for logging
- **Database Directory**: Directory for database files (default: ~/.burp-mcp/). Files are named per Burp project: `traffic_<project_name>.db`
- **Log Proxy/Repeater/Scanner/Intruder/Extensions**: Per-tool logging

### Claude Desktop Client

Use the built-in installer or manually configure:

```json
{
  "mcpServers": {
    "burp": {
      "command": "/path/to/java",
      "args": [
        "-jar",
        "/path/to/mcp-proxy-all.jar",
        "--sse-url",
        "http://127.0.0.1:9876"
      ]
    }
  }
}
```

## Architecture

### Threading Model

```
Burp Proxy Thread                    Writer Thread              MCP Request Thread
      │                                   │                            │
      │ onRequest/onResponse              │                            │
      ▼                                   │                            │
 ┌─────────────┐                          │                            │
 │ TrafficQueue│ ─── offer() ───────────► │                            │
 │ (non-block) │    (returns immediately) │                            │
 └─────────────┘                          │                            │
      │                                   ▼                            │
      │                          ┌─────────────────┐                   │
      │                          │ Batch Processor │                   │
      │                          │ (single thread) │                   │
      │                          └────────┬────────┘                   │
      │                                   │                            │
      │                                   ▼                            │
      │                          ┌─────────────────┐                   │
      │                          │ SQLite (WAL)    │◄──── read queries │
      │                          │ Connection Pool │                   │
      │                          └─────────────────┘                   │
```

Key design decisions:
- **Non-blocking enqueue**: Proxy handlers return in <1ms
- **Single writer thread**: Respects SQLite's single-writer limitation
- **WAL mode**: Allows concurrent reads during writes
- **Connection pooling**: Semaphore-based, no lock contention

### Database Schema

```sql
-- Main traffic table
CREATE TABLE traffic (
    id INTEGER PRIMARY KEY,
    timestamp INTEGER,
    tool_source TEXT,
    method TEXT,
    url TEXT,
    host TEXT,
    port INTEGER,
    is_https INTEGER,
    status_code INTEGER,
    content_length INTEGER,
    content_type TEXT,
    request_hash TEXT UNIQUE,
    session_tag TEXT
);

-- FTS5 for full-text search
CREATE VIRTUAL TABLE traffic_fts USING fts5(
    url, request_headers, request_body,
    response_headers, response_body
);
```

## Usage Examples

### Search for API endpoints
```
search_traffic(query="api OR graphql", method="POST")
```

### Test for race conditions
```
send_parallel(request="POST /api/transfer...", count=20)
```

### Decode and attack JWT
```
jwt_decode(token="eyJ...")
jwt_none_attack(token="eyJ...")
```

### Compare two responses for differences
```
compare_responses(response1="...", response2="...", ignoreHeaders=["Date"])
```

### GraphQL introspection with bypass
```
graphql_introspect(endpoint="https://api.example.com/graphql", bypassTechnique="NEWLINE")
```

## Browser Automation Integration

Burp's embedded browser does not expose programmatic control through the Montoya API. However, you can achieve full browser automation while capturing all traffic through Burp by combining this extension with Chrome DevTools MCP.

### Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Claude Code / AI Client                           │
│                                                                             │
│  ┌─────────────────────────────┐      ┌─────────────────────────────────┐  │
│  │     Burp MCP Extension      │      │    Chrome DevTools MCP          │  │
│  │                             │      │                                 │  │
│  │  - search_traffic           │      │  - navigate_page                │  │
│  │  - send_parallel            │      │  - click, fill, hover           │  │
│  │  - jwt_decode               │      │  - take_screenshot              │  │
│  │  - graphql_introspect       │      │  - evaluate_script              │  │
│  └──────────────┬──────────────┘      └────────────────┬────────────────┘  │
│                 │                                      │                    │
└─────────────────┼──────────────────────────────────────┼────────────────────┘
                  │ MCP (SSE)                            │ CDP (WebSocket)
                  ▼                                      ▼
┌─────────────────────────────┐      ┌─────────────────────────────────────┐
│        Burp Suite           │      │     Chrome/Chromium Browser         │
│                             │◄─────│     --remote-debugging-port=9222    │
│  Proxy: 127.0.0.1:8080      │ HTTP │     --proxy-server=127.0.0.1:8080   │
│                             │      │                                     │
│  - Traffic Logging          │      │  All traffic flows through Burp    │
│  - Intercept & Modify       │      │                                     │
│  - Scanner                  │      │                                     │
└─────────────────────────────┘      └─────────────────────────────────────┘
```

### Setup Guide

#### Step 1: Launch Chrome with Remote Debugging and Burp Proxy

**macOS:**
```bash
/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome \
  --remote-debugging-port=9222 \
  --proxy-server=127.0.0.1:8080 \
  --ignore-certificate-errors \
  --user-data-dir=/tmp/chrome-burp-profile
```

**Linux:**
```bash
google-chrome \
  --remote-debugging-port=9222 \
  --proxy-server=127.0.0.1:8080 \
  --ignore-certificate-errors \
  --user-data-dir=/tmp/chrome-burp-profile
```

**Windows (PowerShell):**
```powershell
& "C:\Program Files\Google\Chrome\Application\chrome.exe" `
  --remote-debugging-port=9222 `
  --proxy-server=127.0.0.1:8080 `
  --ignore-certificate-errors `
  --user-data-dir=C:\Temp\chrome-burp-profile
```

#### Step 2: Configure Chrome DevTools MCP

Add to your Claude Desktop config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    },
    "chrome-devtools": {
      "command": "npx",
      "args": ["-y", "@anthropic/chrome-devtools-mcp@latest"]
    }
  }
}
```

Or for Claude Code (`~/.claude/settings.json`):

```json
{
  "mcpServers": {
    "burp": {
      "command": "java",
      "args": ["-jar", "/path/to/mcp-proxy-all.jar", "--sse-url", "http://127.0.0.1:9876"]
    },
    "chrome-devtools-mcp": {
      "command": "npx",
      "args": ["-y", "chrome-devtools-mcp@latest"]
    }
  }
}
```

#### Step 3: Verify Connection

1. Ensure Burp Suite is running with proxy on `127.0.0.1:8080`
2. Launch Chrome with the flags above
3. Start Claude Code or Claude Desktop
4. Both MCPs should connect successfully

### Usage Examples

#### Automated Web Testing with Traffic Capture

```
# Navigate to target (Chrome DevTools MCP)
navigate_page(url="https://example.com/login")

# Fill and submit login form
fill(uid="username-field", value="admin")
fill(uid="password-field", value="password123")
click(uid="login-button")

# Search captured traffic (Burp MCP)
search_traffic(query="login OR session", method="POST")

# Extract session token from response
extract_regex(content="...", pattern="session=([a-f0-9]+)")
```

#### Race Condition Testing with Visual Verification

```
# Take screenshot before
take_screenshot(name="before-transfer")

# Send parallel requests through Burp
send_parallel(
  request="POST /api/transfer HTTP/1.1\r\nHost: bank.com\r\n...",
  targetHost="bank.com",
  count=20
)

# Refresh page and screenshot after
navigate_page(type="reload")
take_screenshot(name="after-transfer")

# Check if balance changed unexpectedly
```

#### GraphQL Exploration with Browser Context

```
# Navigate to GraphQL endpoint
navigate_page(url="https://api.example.com/graphql")

# Introspect schema through Burp
graphql_introspect(
  endpoint="https://api.example.com/graphql",
  bypassTechnique="NEWLINE"
)

# Execute discovered queries in browser console
evaluate_script(function="() => fetch('/graphql', {...})")

# Analyze captured responses
search_traffic(query="__schema OR __type")
```

#### JWT Token Testing

```
# Login via browser
navigate_page(url="https://app.example.com/login")
fill(uid="email", value="test@example.com")
click(uid="submit")

# Extract JWT from traffic
search_traffic(query="authorization OR bearer")
get_traffic_by_id(id=123)

# Decode and analyze
jwt_decode(token="eyJ...")

# Try none attack
jwt_none_attack(token="eyJ...")

# Test forged token in browser
evaluate_script(function="() => { localStorage.setItem('token', '...'); }")
navigate_page(type="reload")
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| Chrome won't start with proxy | Ensure Burp is running first on port 8080 |
| CDP connection refused | Check `--remote-debugging-port` flag is set |
| SSL errors in Chrome | Add `--ignore-certificate-errors` flag |
| Traffic not appearing in Burp | Verify proxy settings: `chrome://settings/?search=proxy` |
| MCP timeout errors | Increase timeout in MCP server settings |

### Security Considerations

- Use `--user-data-dir` to isolate the testing browser profile
- `--ignore-certificate-errors` bypasses SSL validation - only use for testing
- The debugging port (9222) allows full browser control - don't expose externally
- Traffic logging captures sensitive data - secure the SQLite database

## License

GPL-3.0 (same as original PortSwigger MCP Server)

## Credits

- Original MCP Server: [PortSwigger](https://github.com/PortSwigger/mcp-server)
- Enhanced features: Security testing tools, SQLite logging, and more
