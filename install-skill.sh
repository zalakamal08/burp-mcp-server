#!/usr/bin/env bash
#
# Installs the burp-mcp skill into your personal Claude Code skills directory
# (~/.claude/skills/burp-mcp) so it is available in every Claude Code session.
#
# It pulls SKILL.md straight from GitHub, so no clone is required:
#   curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/install-skill.sh | bash
#
# If run from a local clone, it uses the local SKILL.md instead.
#
set -euo pipefail

SKILL_NAME="burp-mcp"
DEST="${HOME}/.claude/skills/${SKILL_NAME}"
RAW_URL="https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/SKILL.md"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
LOCAL_SKILL="${SCRIPT_DIR}/SKILL.md"

mkdir -p "${DEST}"

if [[ -f "${LOCAL_SKILL}" ]]; then
  cp "${LOCAL_SKILL}" "${DEST}/SKILL.md"
  echo "✔ Installed skill from local repo: ${LOCAL_SKILL}"
else
  echo "↓ Pulling SKILL.md from GitHub..."
  curl -fsSL "${RAW_URL}" -o "${DEST}/SKILL.md"
  echo "✔ Downloaded from ${RAW_URL}"
fi

echo "✔ Skill '${SKILL_NAME}' installed to ${DEST}/SKILL.md"
echo ""
echo "It loads automatically in Claude Code when you use the Burp MCP tools."
echo "Invoke it explicitly with:  /${SKILL_NAME}"
