# Burp MCP — Agent Skill

This repo ships a **Claude Code skill** that teaches an AI agent how to use the
Burp MCP tools *efficiently* — the right tool for each job, minimal token spend,
and the standard web-pentest workflows.

- 📄 Skill content: [`SKILL.md`](SKILL.md)
- 🛠 Installer: [`install-skill.sh`](install-skill.sh)

The skill is **not** committed under a `.claude/` directory — it lives as a plain
`SKILL.md` at the repo root. You install it into your own Claude Code skills
directory with a single command that pulls it from GitHub.

---

## Install the skill (one command)

Installs to `~/.claude/skills/burp-mcp/SKILL.md` so it loads in **every** Claude
Code session:

```bash
curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/install-skill.sh | bash
```

Or, from a local clone:

```bash
./install-skill.sh
```

The installer simply downloads `SKILL.md` from GitHub and drops it into
`~/.claude/skills/burp-mcp/`.

---

## Using the skill

Once installed, Claude Code loads it automatically whenever you start working with
the `mcp__burp__*` tools. You can also invoke it explicitly:

```
/burp-mcp
```

---

## What the skill teaches

A condensed version of the golden rules (full detail in [`SKILL.md`](SKILL.md)):

1. **One call, not two** — use `get_repeater_tab` (request **and** response together).
2. **Filter, don't dump** — `search_proxy_history` / regex history over full history pulls.
3. **Always paginate** — `count` + `offset`, start small.
4. **Extract, don't re-read** — `extract_from_response` for tokens/IDs/redirects.
5. **List before indexing** — `list_repeater_tabs` / `list_repeater_tab_history` first.
6. **Respect scope & edition** — check scope before scanning; scanner tools need Burp Pro.

### The core testing loop

```
list_repeater_tabs                  → find tab index
get_repeater_tab(0)                 → read request + response
set_repeater_tab_request(0, "...")  → inject payload
send_repeater_tab_request(0)        → send (HTTPS/port auto-detected)
extract_from_response(...)          → pull the value you need
↳ repeat with new payloads; list_repeater_tab_history(0) to review all sends
```
