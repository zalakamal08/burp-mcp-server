---
name: burp-mcp
description: Use when interacting with Burp Suite through its MCP server (zalakamal08/burp-mcp-server) to perform web security testing — sending/replaying HTTP requests, working with Repeater tabs and their send-history, searching proxy history, managing scope, running scans, and extracting values from responses. Teaches the most token-efficient tool choices and the standard request→modify→resend testing loop.
---

# Burp Suite MCP — Efficient Usage Guide

This skill teaches an AI agent how to drive Burp Suite through the MCP server
([github.com/zalakamal08/burp-mcp-server](https://github.com/zalakamal08/burp-mcp-server))
**efficiently** — choosing the right tool, minimizing token spend, and following
proven web-pentest workflows.

All tools are prefixed `mcp__burp__` in Claude Code. Tool names below omit the prefix.

---

## Golden rules (read first)

1. **Prefer one combined call over two.** Use `get_repeater_tab` (returns request **and** response) instead of separate request/response calls. There is intentionally no `get_repeater_tab_request`/`get_repeater_tab_response` — the combined tool covers both.
2. **Never dump full history when you can filter.** Use `search_proxy_history` (filter by status/method/content-type/body keyword) or `get_proxy_http_history_regex` instead of paging through `get_proxy_http_history`. This saves enormous token volume.
3. **Always paginate.** History/site-map tools take `count` and `offset`. Start with a small `count` (e.g. 20) and page with `offset` only if needed.
4. **Extract, don't re-read.** When you only need a token/CSRF value/redirect URL from a large response, pass the response to `extract_from_response` with a regex rather than re-emitting the whole body.
5. **Discover indices before using them.** Repeater tools are index-based. Call `list_repeater_tabs` / `list_repeater_tab_history` first; never guess an index.
6. **Respect scope.** Before scanning, confirm the target is in scope (`is_in_scope`) or add it (`add_to_scope`). Scans on out-of-scope hosts may be blocked or unwanted.

---

## The core testing loop (Repeater)

This is the workhorse pattern for manual exploitation and fuzzing:

```
1. list_repeater_tabs                       → find the tab index you want (e.g. 0)
2. get_repeater_tab(tabIndex: 0)            → read the current request (and the user's last UI response)
3. send_repeater_tab_request(0, request: "<modified raw request>")
                                            → sets the request AND sends it in ONE call; returns the response
4. (optional) extract_from_response(...)    → pull the value you care about
   repeat 3–4 with new payloads
```

- **A real Repeater send.** `send_repeater_tab_request` clicks the tab's actual
  Send button, so the request goes through Repeater just like a manual pentester
  action: the response appears in the tab and the send is saved to the tab's
  history. The response is also returned to you directly.
- **Modify + send in one call.** Pass the optional `request` field to replace the
  tab's request and send in a single step — the efficient fuzzing primitive (e.g.
  change `/user/1` to `/user/2` to test authorization). You rarely need a separate
  `set_repeater_tab_request` (that one stages a request WITHOUT sending, e.g.
  preparing an exploit for the user to review).
- **Target overrides switch to a direct send.** If you pass
  `targetHostname/targetPort/usesHttps` (to hit a different host than the tab is
  configured for), the request is sent through Burp's engine directly instead of
  the Send button — the response is returned to you but does NOT appear in the tab
  or its history. Omit the overrides to get the normal in-tab send.

Notes:
- The raw request is a full HTTP message: `METHOD path HTTP/1.1\r\nHost: ...\r\n\r\nbody`.
  The server normalizes line endings, so `\n` is accepted, but keep the blank line
  between headers and body. This applies to `create_repeater_tab`,
  `set_repeater_tab_request`, `send_to_intruder`, and the HTTP send tools.
- **HTTPS and port are auto-detected** from the tab's target label, an HTTPS
  toggle (older Burp), or — when neither is present — the request's protocol line
  (`HTTP/2` ⇒ HTTPS, port upgraded to 443) and the `Host` header. Detection is
  best-effort and can still be wrong. **If the target is wrong, override it** on
  `send_repeater_tab_request` (and `get_repeater_tab`):
  ```
  send_repeater_tab_request(tabIndex: 0, targetHostname: "api.example.com", targetPort: 443, usesHttps: true)
  ```
  The override always wins over auto-detection. You do not need to mutate Burp's UI.
- **Responses are truncated** to `maxResponseChars` (default 50000) so a huge body
  (e.g. a CDN error page) cannot overflow the token limit. The status line and
  headers are always preserved (they come first). Pass a larger `maxResponseChars`
  if you need more of the body.
- To compare every payload sent in a tab (your normal in-tab sends and the user's
  manual sends both appear here), use the **send history**:
  ```
  list_repeater_tab_history(0)              → ["0: https://.../login", "1: https://.../login", ...]
  get_repeater_tab_history_item(0, 2)       → full request + response for entry #2
  ```
  This is non-destructive — the tab is briefly navigated then restored.
  (Target-override/direct sends do not appear here.)

---

## Choosing the right tool

### Sending HTTP requests

| Goal | Tool |
|---|---|
| Replay/modify a request already in a Repeater tab | `set_repeater_tab_request` + `send_repeater_tab_request` |
| Send a brand-new one-off HTTP/1.1 request | `send_http1_request` (specify host/port/usesHttps) |
| Send an HTTP/2 request (pseudo-headers) | `send_http2_request` |
| Open a fresh Repeater tab for the user to see | `create_repeater_tab` |
| Hand a request to Intruder for the user | `send_to_intruder` |

For `send_http1_request` / `send_http2_request` / `create_repeater_tab`, you must
supply `targetHostname`, `targetPort`, and `usesHttps` explicitly — these are NOT
auto-detected (unlike Repeater-tab sends).

### Reviewing traffic

| Goal | Tool | Why |
|---|---|---|
| Find requests matching specific criteria | `search_proxy_history` (statusCode/method/contentType/bodyKeyword, AND logic) | Filters server-side — cheapest |
| Find by URL/content pattern | `get_proxy_http_history_regex` | Regex filter |
| Look at one known item | `get_proxy_http_history_item(index)` | Single item |
| Browse recent traffic | `get_proxy_http_history(count, offset)` | Use small count |
| WebSocket traffic | `get_proxy_websocket_history[_regex]` | |

`search_proxy_history` filters (all optional, combined with AND):
`statusCode` (exact int), `method` (case-insensitive), `contentType` (substring of
Content-Type header), `bodyKeyword` (case-insensitive substring in body). It also
paginates with `count`/`offset`.

### Scope & site map

| Goal | Tool |
|---|---|
| Is this URL in scope? | `is_in_scope(url)` |
| Add / remove scope | `add_to_scope(url)` / `remove_from_scope(url)` |
| Full site map (paginate!) | `get_site_map(count, offset)` |
| Site map under a URL prefix | `get_site_map_for_url(url, count, offset)` |

### Scanning (Burp Suite **Pro** only)

| Goal | Tool |
|---|---|
| Active scan a request | `start_active_scan` |
| Passive scan a request | `start_passive_scan` |
| Read findings | `get_scanner_issues(count, offset)` |
| Out-of-band testing | `generate_collaborator_payload` → use in a request → `get_collaborator_interactions` |

If a scanner tool errors with an edition message, the user is on Community — fall
back to manual testing via Repeater.

### Utilities (cheap, local — prefer over reasoning by hand)

| Goal | Tool |
|---|---|
| Extract regex matches from a response | `extract_from_response(response, regex, group)` |
| URL encode/decode | `url_encode` / `url_decode` |
| Base64 encode/decode | `base64_encode` / `base64_decode` |
| Random string (e.g. cache buster, nonce) | `generate_random_string(length, characterSet)` |

`extract_from_response`: `group=0` returns the whole match; `group=1+` returns that
capture group. Returns all matches, one per line. Use it for CSRF tokens, session
IDs, redirect `Location` values, anti-CSRF nonces, etc.

### Active editor & config

| Goal | Tool |
|---|---|
| Read what the user has open in an editor | `get_active_editor_contents` |
| Write into the active editor | `set_active_editor_contents` |
| Export/import Burp options (JSON) | `output_*_options` / `set_*_options` |
| Pause/resume task engine | `set_task_execution_engine_state` |
| Toggle proxy intercept | `set_proxy_intercept_state(intercepting)` |

---

## Worked examples

**Extract a CSRF token and reuse it:**
```
resp = get_repeater_tab(0)                       # see the login form response
token = extract_from_response(resp, 'name="csrf" value="([^"]+)"', 1)
set_repeater_tab_request(0, "POST /login HTTP/1.1\r\nHost: t\r\n...\r\n\r\ncsrf=<token>&user=admin&pass=x")
send_repeater_tab_request(0)
```

**Find every 500 error returned to a POST that mentions "exception":**
```
search_proxy_history(statusCode: 500, method: "POST", bodyKeyword: "exception", count: 20, offset: 0)
```

**Review all payloads tried in a fuzzing tab:**
```
list_repeater_tab_history(0)
# then for each interesting index:
get_repeater_tab_history_item(0, <i>)
```

**Find all JSON API responses in history:**
```
search_proxy_history(contentType: "json", count: 30, offset: 0)
```

---

## Efficiency checklist before each call

- Am I about to pull full history? → switch to `search_proxy_history` / regex.
- Am I reading a tab's request and response separately? → use `get_repeater_tab`.
- Am I re-reading a big response to find one value? → use `extract_from_response`.
- Did I guess an index? → list first.
- Big result expected? → set a small `count`, page only if needed.
- Scanning? → check scope first; confirm Pro edition.
