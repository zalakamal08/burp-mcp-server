# Burp MCP Server

A Burp Suite extension that exposes Burp tooling to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/).

> **🤖 Agent skill:** This repo ships a Claude Code skill that teaches AI agents how to use these tools *efficiently*. Install it globally with one line:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/install-skill.sh | bash
> ```
> Inside Claude Code you can also run `/install-burp-skill`. See [SKILLS.md](SKILLS.md) for details.

## Installation

### Download

Grab the latest JAR from the [Releases page](https://github.com/zalakamal08/burp-mcp-server/releases).

### Load into Burp Suite

1. Open Burp Suite → **Extensions** tab → **Add**
2. Set **Extension Type** to `Java`
3. Select the downloaded JAR → **Next**

The extension adds an **MCP** tab to Burp Suite.

---

## Configuration

In the **MCP** tab:

- **Enable/Disable toggle** — starts or stops the MCP server
- **Host / Port** — default is `0.0.0.0:9876`
- **Exposed Tools** — check/uncheck which tools are visible to the AI agent. Disable the extension first to edit. Use **Select All** / **Deselect All** for quick changes.

---

## Connecting an AI Client

The extension runs an SSE MCP server. Most desktop AI clients need a Stdio proxy to talk to it. Extract the proxy JAR from the **Installation** section of the MCP tab, then configure your client.

### Claude Code CLI (`~/.claude.json`)

```json
{
  "mcpServers": {
    "burp": {
      "command": "/usr/bin/java",
      "args": [
        "-jar",
        "/home/kali/mcp-proxy.jar",
        "--sse-url",
        "http://X.X.X.X:9876"
      ]
    }
  }
}
```

Replace `X.X.X.X` with your Burp machine's IP and `/home/kali/mcp-proxy.jar` with the path where you extracted the proxy JAR.

### Claude Desktop (`claude_desktop_config.json`)

| OS | Config file location |
|---|---|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "burp": {
      "command": "/usr/bin/java",
      "args": [
        "-jar",
        "/path/to/mcp-proxy.jar",
        "--sse-url",
        "http://X.X.X.X:9876"
      ]
    }
  }
}
```

The **Install for Claude Desktop** button in the MCP tab does this automatically.

### Direct SSE (clients that support SSE natively)

```
http://X.X.X.X:9876
```
or
```
http://X.X.X.X:9876/sse
```

---

## Available Tools

### Repeater

| Tool | Description |
|---|---|
| `create_repeater_tab` | Open a new Repeater tab with a given request |
| `list_repeater_tabs` | List all open Repeater tabs (index + name) |
| `get_repeater_tab` | Get the current request and last response from a tab |
| `set_repeater_tab_request` | Write new request text into a tab |
| `send_repeater_tab_request` | Send the tab's request through Burp's HTTP engine |
| `list_repeater_tab_history` | List all previously sent requests in a tab |
| `get_repeater_tab_history_item` | Get request + response for a specific history entry |

### Proxy

| Tool | Description |
|---|---|
| `get_proxy_http_history` | Paginated HTTP proxy history |
| `get_proxy_http_history_regex` | Filter HTTP history by URL regex |
| `get_proxy_http_history_item` | Get a single history item by index |
| `get_proxy_websocket_history` | Paginated WebSocket history |
| `get_proxy_websocket_history_regex` | Filter WebSocket history by regex |
| `set_proxy_intercept_state` | Turn proxy intercept on or off |
| `search_proxy_history` | Filter history by status code, method, Content-Type, or body keyword (AND logic) |

### HTTP

| Tool | Description |
|---|---|
| `send_http1_request` | Send an HTTP/1.1 request through Burp |
| `send_http2_request` | Send an HTTP/2 request through Burp |

### Scope

| Tool | Description |
|---|---|
| `is_in_scope` | Check if a URL is in scope |
| `add_to_scope` | Add a URL to scope |
| `remove_from_scope` | Remove a URL from scope |

### Site Map

| Tool | Description |
|---|---|
| `get_site_map` | Get the full site map |
| `get_site_map_for_url` | Get site map entries for a specific URL |

### Scanner *(Burp Suite Pro only)*

| Tool | Description |
|---|---|
| `get_scanner_issues` | List scanner findings |
| `start_active_scan` | Start an active scan |
| `start_passive_scan` | Start a passive scan |
| `generate_collaborator_payload` | Generate a Burp Collaborator payload |
| `get_collaborator_interactions` | Poll Collaborator for interactions |

### Intruder

| Tool | Description |
|---|---|
| `send_to_intruder` | Send a request to Intruder |

### Configuration

| Tool | Description |
|---|---|
| `output_project_options` | Export project options as JSON |
| `output_user_options` | Export user options as JSON |
| `set_project_options` | Set project options from JSON |
| `set_user_options` | Set user options from JSON |
| `set_task_execution_engine_state` | Pause or resume the task execution engine |

### Utilities

| Tool | Description |
|---|---|
| `url_encode` | URL-encode a string |
| `url_decode` | URL-decode a string |
| `base64_encode` | Base64-encode a string |
| `base64_decode` | Base64-decode a string |
| `generate_random_string` | Generate a random string |
| `extract_from_response` | Extract all regex matches from an HTTP response string (supports capture groups) |

### Editor

| Tool | Description |
|---|---|
| `get_active_editor_contents` | Read the active Burp message editor |
| `set_active_editor_contents` | Write to the active Burp message editor |

---

## Building from Source

```bash
git clone https://github.com/zalakamal08/burp-mcp-server.git
cd burp-mcp-server
./gradlew embedProxyJar
```

Output: `build/libs/burp-mcp-<version>-all.jar`

### Adding or Modifying Tools

- Tool logic: `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`
- Tool list (for the UI panel): `src/main/kotlin/net/portswigger/mcp/config/ToolDefinitions.kt`
- Implement a `@Serializable` data class for the parameters, register it inside `registerTools`, and add an entry to `ToolDefinitions`. Implement `Paginated` for auto-pagination support.
