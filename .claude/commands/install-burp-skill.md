---
description: Install the burp-mcp skill globally into ~/.claude/skills so it loads in every Claude Code session
---

Install the **burp-mcp** skill into the user's personal Claude Code skills
directory so it is available across all projects.

Steps:

1. Run the installer to copy the skill globally:

   ```bash
   mkdir -p ~/.claude/skills/burp-mcp
   if [ -f .claude/skills/burp-mcp/SKILL.md ]; then
     cp .claude/skills/burp-mcp/SKILL.md ~/.claude/skills/burp-mcp/SKILL.md
   else
     curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/.claude/skills/burp-mcp/SKILL.md \
       -o ~/.claude/skills/burp-mcp/SKILL.md
   fi
   ```

2. Confirm the file exists at `~/.claude/skills/burp-mcp/SKILL.md` and report success.

3. Tell the user the skill is now installed globally and will auto-load whenever
   they use the Burp MCP tools, or they can invoke it explicitly with `/burp-mcp`.
