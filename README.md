# Burp Suite MCP Server Extension

## Overview

Integrate Burp Suite with AI Clients using the Model Context Protocol (MCP).

For more information about the protocol visit: [modelcontextprotocol.io](https://modelcontextprotocol.io/)

## Features

- Connect Burp Suite to AI clients through MCP
- Automatic installation for Claude Desktop
- Per-tool enable/disable from the extension UI — expose only the tools you need to save agent tokens
- Comes with packaged Stdio MCP proxy server
- **Repeater tab tools** — list open Repeater tabs, read requests, and send them through Burp's HTTP engine
- **Response extraction** — pull regex matches (CSRF tokens, auth values, redirect URLs) from any response string
- **Proxy history search** — filter HTTP history by status code, method, Content-Type, or body keyword

## Available Tools

| Category | Tool | Description |
|---|---|---|
| Repeater | `create_repeater_tab` | Send a request to a new Repeater tab |
| Repeater | `list_repeater_tabs` | List all open Repeater tabs |
| Repeater | `get_repeater_tab_request` | Read the raw request from a Repeater tab |
| Repeater | `send_repeater_tab_request` | Send the request in a Repeater tab through Burp |
| Proxy | `get_proxy_http_history` | Get paginated HTTP proxy history |
| Proxy | `get_proxy_http_history_regex` | Filter HTTP history by regex |
| Proxy | `get_proxy_http_history_item` | Get a single history item by index |
| Proxy | `get_proxy_websocket_history` | Get paginated WebSocket history |
| Proxy | `get_proxy_websocket_history_regex` | Filter WebSocket history by regex |
| Proxy | `set_proxy_intercept_state` | Turn proxy intercept on/off |
| Proxy | `search_proxy_history` | Filter history by status code, method, Content-Type, or body keyword |
| HTTP | `send_http1_request` | Send an HTTP/1.1 request through Burp |
| HTTP | `send_http2_request` | Send an HTTP/2 request through Burp |
| Scope | `is_in_scope` | Check if a URL is in scope |
| Scope | `add_to_scope` | Add a URL to scope |
| Scope | `remove_from_scope` | Remove a URL from scope |
| Site Map | `get_site_map` | Get the full site map |
| Site Map | `get_site_map_for_url` | Get site map entries for a specific URL |
| Scanner (Pro) | `get_scanner_issues` | List scanner findings |
| Scanner (Pro) | `start_active_scan` | Start an active scan |
| Scanner (Pro) | `start_passive_scan` | Start a passive scan |
| Scanner (Pro) | `generate_collaborator_payload` | Generate a Burp Collaborator payload |
| Scanner (Pro) | `get_collaborator_interactions` | Get Collaborator interactions |
| Intruder | `send_to_intruder` | Send a request to Intruder |
| Configuration | `output_project_options` | Export project options JSON |
| Configuration | `output_user_options` | Export user options JSON |
| Configuration | `set_project_options` | Set project options |
| Configuration | `set_user_options` | Set user options |
| Configuration | `set_task_execution_engine_state` | Pause/resume the task engine |
| Utilities | `url_encode` | URL-encode a string |
| Utilities | `url_decode` | URL-decode a string |
| Utilities | `base64_encode` | Base64-encode a string |
| Utilities | `base64_decode` | Base64-decode a string |
| Utilities | `generate_random_string` | Generate a random string |
| Utilities | `extract_from_response` | Extract regex matches from an HTTP response string |
| Editor | `get_active_editor_contents` | Read the active Burp editor's contents |
| Editor | `set_active_editor_contents` | Write to the active Burp editor |

## Installation

### Download the Latest Release

The easiest way to install is to download the pre-built JAR from the [Releases page](https://github.com/zalakamal08/burp-mcp-server/releases).

### Building from Source

1. **Clone the Repository**
   ```
   git clone https://github.com/zalakamal08/burp-mcp-server.git
   ```

2. **Navigate to the Project Directory**
   ```
   cd burp-mcp-server
   ```

3. **Build the JAR File**
   ```
   ./gradlew embedProxyJar
   ```

   This produces `build/libs/burp-mcp-<version>-all.jar`.

### Loading the Extension into Burp Suite

1. Open Burp Suite and navigate to the **Extensions** tab.
2. Click **Add**.
3. Set **Extension Type** to `Java`.
4. Click **Select file...** and choose the JAR built above.
5. Click **Next** to load the extension.

The extension will appear as a new **MCP** tab in Burp Suite.

## Configuration

Configuration is done in the **MCP** tab within Burp Suite.

- **Toggle the MCP Server**: The `Enabled` toggle starts or stops the server.
- **Host / Port**: Configure the host and port. Default is `0.0.0.0:9876`.
- **Exposed Tools**: Choose which tools to expose to the AI agent. Disable the extension first, then check/uncheck tools. Disabled tools are never registered with the MCP server, saving agent tokens.

### Claude Desktop

1. **Run the installer from the extension UI** — this automatically adds Burp to Claude Desktop's config.

2. **Or manually edit** `~/Library/Application Support/Claude/claude_desktop_config.json`:
   ```json
   {
     "mcpServers": {
       "burp": {
         "command": "<path to Java executable>",
         "args": [
           "-jar",
           "/path/to/mcp-proxy-all.jar",
           "--sse-url",
           "http://localhost:9876"
         ]
       }
     }
   }
   ```

3. **Restart Claude Desktop** with Burp running and the extension loaded.

## Manual installations

### SSE MCP Server

Point your MCP client directly at the SSE server:

```
http://<burp-machine-ip>:9876
```
or
```
http://<burp-machine-ip>:9876/sse
```

### Stdio MCP Proxy Server

The extension comes packaged with a Stdio proxy for clients that only support Stdio MCP servers.

```
/path/to/java -jar /path/to/mcp-proxy-all.jar --sse-url http://<burp-machine-ip>:9876
```

Use the extension's installer to extract the proxy JAR.

## Creating / Modifying Tools

Tools are defined in `src/main/kotlin/net/portswigger/mcp/tools/Tools.kt`. Create a serializable data class with the tool's parameters, then register it inside `registerTools`. Tool names are auto-derived from the data class name.

To control which tools appear in the UI panel, add an entry to `src/main/kotlin/net/portswigger/mcp/config/ToolDefinitions.kt`.

Extend the `Paginated` interface to add auto-pagination support.
