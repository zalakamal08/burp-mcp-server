# Burp MCP Server

A Burp Suite extension that exposes Burp tooling to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io/).

> Forked from PortSwigger's official **[Burp MCP Server](https://github.com/PortSwigger/mcp-server)** and trimmed to a lean, testing-focused tool set. See [Credits & Attribution](#credits--attribution).

> **🤖 Agent skill:** This repo ships a Claude Code skill ([`SKILL.md`](SKILL.md)) that teaches AI agents how to use these tools *efficiently*. Install it into your Claude Code skills directory with one line:
> ```bash
> curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/install-skill.sh | bash
> ```
> The installer pulls `SKILL.md` from GitHub into `~/.claude/skills/burp-mcp/`. Once installed it auto-loads when you use the `mcp__burp__*` tools, or invoke it explicitly with `/burp-mcp`.

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

**13 tools across 3 categories.** This build is deliberately trimmed to the core proxy/Repeater testing loop — the raw HTTP-send, Scope, Site Map, Configuration, Intruder, Utilities, and Editor tool groups from upstream have been removed to keep the server lightweight and reduce the tool surface the AI has to reason about. (Utilities/Intruder/Editor functionality is planned to return once retested.)

### Repeater

| Tool | Description |
|---|---|
| `create_repeater_tab` | Open a new Repeater tab with a given request |
| `list_repeater_tabs` | List all open Repeater tabs (index + name) |
| `get_repeater_tab` | Get a tab's current request and target |
| `send_repeater_tab_request` | Send the tab's request and capture the response |

### Proxy

| Tool | Description |
|---|---|
| `get_proxy_http_history_regex` | Filter HTTP proxy history by regex |
| `get_proxy_http_history_item` | Get a single history item by index — see **original vs modified** below |
| `get_proxy_websocket_history` | Paginated WebSocket history |
| `get_proxy_websocket_history_regex` | Filter WebSocket history by regex |

> **Original vs modified traffic.** `get_proxy_http_history_item` takes two optional flags, `requestModified` and `responseModified` (both default `true`), giving four combinations:
> - `requestModified=true` → the final request Burp sent (after match/replace rules and manual Proxy edits); `false` → the request exactly as received from the client.
> - `responseModified=true` → the processed response; `false` → the original response received from the server.
>
> Burp's history API only retains the *modified* request, so the **original request is captured live** by the extension and is only available for traffic proxied while the extension is running — for older history the modified request is returned and a `variantNote` field explains it.

### Scanner *(Burp Suite Pro only)*

| Tool | Description |
|---|---|
| `get_scanner_issues` | List scanner findings |
| `start_active_scan` | Start an active scan |
| `start_passive_scan` | Start a passive scan |
| `generate_collaborator_payload` | Generate a Burp Collaborator payload |
| `get_collaborator_interactions` | Poll Collaborator for interactions |

---

## Why use this MCP server

- **Lean, focused tool set.** 13 tools centred on the request → modify → resend loop, instead of a sprawling surface. Fewer tools means the AI picks the right one faster and wastes fewer tokens deciding.
- **Original *and* modified proxy traffic.** Uniquely exposes the request as it left the client *and* the request Burp actually sent, plus original vs modified responses — so an agent can reason about exactly what match/replace rules and manual edits changed.
- **Ships with an agent skill.** The bundled [`SKILL.md`](SKILL.md) teaches AI agents the most token-efficient tool choices and the standard testing loop, so you get good behaviour out of the box rather than trial-and-error.
- **Approval-gated by design.** Sending requests and reading proxy history go through Burp's in-app approval prompts and an auto-approve allowlist, keeping a human in the loop for sensitive actions.
- **Works with any MCP client** over SSE, with a bundled Stdio proxy for Claude Desktop / Claude Code and other desktop clients.

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

---

## Credits & Attribution

This project is a fork of **[PortSwigger/mcp-server](https://github.com/PortSwigger/mcp-server)** — the official Burp Suite MCP Server extension by PortSwigger (Daniel S. and Daniel Allen). All of the original architecture, MCP server plumbing, Burp integration, and Stdio proxy come from that project; full credit to the PortSwigger team.

This fork adapts it for a leaner, testing-focused workflow: it trims the tool set (removing the HTTP-send, Scope, Site Map, Configuration, Intruder, Utilities, and Editor groups — Repeater, Proxy, and Scanner remain), adds original-vs-modified proxy traffic support, and ships an AI agent skill.

Licensed under **GPL-3.0**, inherited from the upstream project.
