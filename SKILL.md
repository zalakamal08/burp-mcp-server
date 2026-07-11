---
name: burp-mcp
description: Use when interacting with Burp Suite through its MCP server (zalakamal08/burp-mcp-server) to perform web security testing — replaying and modifying HTTP requests via Repeater tabs, reviewing proxy history (including original vs modified requests/responses), and running scans. Teaches the most token-efficient tool choices and the standard request→modify→resend testing loop.
---

# Burp Suite MCP — Efficient Usage Guide

This skill teaches an AI agent how to drive Burp Suite through the MCP server
([github.com/zalakamal08/burp-mcp-server](https://github.com/zalakamal08/burp-mcp-server))
**efficiently** — choosing the right tool, minimizing token spend, and following
proven web-pentest workflows.

This is a lean build focused on the request → modify → resend loop. It exposes
**13 tools** across Repeater, Proxy, and Scanner (Pro). There are intentionally
**no** raw HTTP-send, scope, site-map, config-editing, Intruder, utility
(encode/decode/regex-extract), or editor tools in this build — send requests
through Repeater instead.

All tools are prefixed `mcp__burp__` in Claude Code. Tool names below omit the prefix.

---

## Golden rules (read first)

1. **Read, then send.** Use `get_repeater_tab` to read a tab's request + target in one call, then `send_repeater_tab_request` (optionally with a modified `request`) to send it.
2. **Never dump full history when you can filter.** Use `get_proxy_http_history_regex` (or `get_proxy_websocket_history_regex`) instead of paging through unfiltered history. This saves enormous token volume.
3. **Always paginate.** History tools take `count` and `offset`. Start with a small `count` (e.g. 20) and page with `offset` only if needed.
4. **Discover indices before using them.** Repeater tools are index-based. Call `list_repeater_tabs` first; never guess an index.

---

## The core testing loop (Repeater)

This is the workhorse pattern for manual exploitation and fuzzing:

```
1. list_repeater_tabs                       → find the tab index you want (e.g. 0)
2. get_repeater_tab(tabIndex: 0)            → read the request the user set up + its target
3. send_repeater_tab_request(0, request: "<modified raw request>")
                                            → sends through Burp's engine; returns the response
   repeat 3 with new payloads, comparing responses by hand
```

- **Repeater tabs are your request source.** The user sets up requests in Repeater;
  you read them with `get_repeater_tab`, modify, and send. `get_repeater_tab` also
  auto-detects the target (host/port/HTTPS), so you don't have to specify it.
- **Modify + send in one call.** Pass the optional `request` field to
  `send_repeater_tab_request` to send a MODIFIED request (e.g. change `/user/1` to
  `/user/2` for an authorization test). Omit it to send the request already in the
  tab. The response is returned to you directly.
- **A real Repeater send.** By default `send_repeater_tab_request` issues the
  request through Repeater via its keyboard shortcut (Ctrl+Space), so the request
  and response render in the tab and are saved to its history — like a manual send.
- **Target overrides fall back to a direct send.** If you pass
  `targetHostname/targetPort/usesHttps` to hit a different host than the tab is
  configured for, the request is sent through Burp's engine directly — the response
  is returned to you but does NOT render in the tab. Omit overrides for the in-tab send.

Notes:
- The raw request is a full HTTP message: `METHOD path HTTP/1.1\r\nHost: ...\r\n\r\nbody`.
  The server normalizes line endings, so `\n` is accepted, but keep the blank line
  between headers and body. This applies to `create_repeater_tab` too.
- **HTTPS and port are auto-detected** from the tab's target label, an HTTPS
  toggle (older Burp), or — when neither is present — the request's protocol line
  (`HTTP/2` ⇒ HTTPS, port upgraded to 443) and the `Host` header. Detection is
  best-effort and can still be wrong. **If the target is wrong, override it** on
  `send_repeater_tab_request` (and `get_repeater_tab`):
  ```
  send_repeater_tab_request(tabIndex: 0, targetHostname: "api.example.com", targetPort: 443, usesHttps: true)
  ```
  The override always wins over auto-detection.
- **Responses are truncated** to `maxResponseChars` (default 50000) so a huge body
  (e.g. a CDN error page) cannot overflow the token limit. The status line and
  headers come first (preserved). Pass a larger `maxResponseChars` for more body.
- `create_repeater_tab` stages a brand-new request as a Repeater tab for the user
  to inspect or send manually. You must supply `targetHostname`, `targetPort`, and
  `usesHttps` explicitly for it — these are NOT auto-detected (unlike Repeater-tab sends).

---

## Choosing the right tool

### Sending / staging requests

| Goal | Tool |
|---|---|
| Replay/modify a request from a Repeater tab | `send_repeater_tab_request` (optional `request` to modify) |
| Open a fresh Repeater tab for the user to see | `create_repeater_tab` |

There is no raw one-off HTTP-send tool in this build — put the request in a Repeater
tab (`create_repeater_tab`) and send it with `send_repeater_tab_request`.

### Reviewing traffic

| Goal | Tool | Why |
|---|---|---|
| Find by URL/content pattern | `get_proxy_http_history_regex(regex, count, offset)` | Regex filter — cheapest |
| Look at one known item | `get_proxy_http_history_item(index, ...)` | Single item; see below |
| WebSocket traffic | `get_proxy_websocket_history[_regex]` | |

**Original vs modified traffic** — `get_proxy_http_history_item` takes two optional
booleans, `requestModified` and `responseModified` (both default `true`), giving four
combinations:

| Flag | `true` (default) | `false` |
|---|---|---|
| `requestModified` | final request Burp sent (after match/replace + manual edits) | request as received from the client (**original**) |
| `responseModified` | processed response | original response from the server |

Use `requestModified=false` / `responseModified=false` to see what Burp's rules or
manual edits changed. Caveat: the **original request** is captured live and is only
available for traffic proxied while the extension was running — for older history the
modified request is returned and a `variantNote` field says so.

### Scanning (Burp Suite **Pro** only)

| Goal | Tool |
|---|---|
| Active scan a request | `start_active_scan` |
| Passive scan a request | `start_passive_scan` |
| Read findings | `get_scanner_issues(count, offset)` |
| Out-of-band testing | `generate_collaborator_payload` → use in a request → `get_collaborator_interactions` |

If a scanner tool errors with an edition message, the user is on Community — fall
back to manual testing via Repeater.

---

## Worked examples

**Authorization test (IDOR) — change the id and compare:**
```
get_repeater_tab(0)                                          # read the /user/1 request + target
send_repeater_tab_request(0, request: "<same request with /user/2>")   # returns the response
```

**Find requests to the login endpoint in proxy history:**
```
get_proxy_http_history_regex(regex: "POST /login", count: 20, offset: 0)
```

**See what a match/replace rule changed on a proxied request:**
```
get_proxy_http_history_item(index: 5, requestModified: false)   # original request from the client
get_proxy_http_history_item(index: 5, requestModified: true)    # what Burp actually sent
```

---

## Efficiency checklist before each call

- Am I about to pull full history? → switch to `get_proxy_http_history_regex`.
- Am I reading a tab's request and response separately? → use `get_repeater_tab`.
- Did I guess an index? → list first.
- Big result expected? → set a small `count`, page only if needed.
- Scanning? → confirm Pro edition.
