#!/usr/bin/env bash
#
# Installs the burp-mcp skill into your personal Claude Code skills directory
# (~/.claude/skills/burp-mcp) so it is available in every Claude Code session,
# not just this repository.
#
# Usage:
#   ./install-skill.sh
#
# Or straight from GitHub (no clone needed):
#   curl -fsSL https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/install-skill.sh | bash
#
set -euo pipefail

SKILL_NAME="burp-mcp"
DEST="${HOME}/.claude/skills/${SKILL_NAME}"
RAW_URL="https://raw.githubusercontent.com/zalakamal08/burp-mcp-server/main/.claude/skills/${SKILL_NAME}/SKILL.md"

# Resolve the SKILL.md: prefer the local copy (when run from a clone),
# otherwise download it from GitHub.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || true)"
LOCAL_SKILL="${SCRIPT_DIR}/.claude/skills/${SKILL_NAME}/SKILL.md"

mkdir -p "${DEST}"

if [[ -f "${LOCAL_SKILL}" ]]; then
  cp "${LOCAL_SKILL}" "${DEST}/SKILL.md"
  echo "✔ Installed skill from local repo: ${LOCAL_SKILL}"
else
  echo "↓ Local skill not found — downloading from GitHub..."
  curl -fsSL "${RAW_URL}" -o "${DEST}/SKILL.md"
  echo "✔ Downloaded skill from ${RAW_URL}"
fi

echo "✔ Skill '${SKILL_NAME}' installed to ${DEST}/SKILL.md"
echo ""
echo "It will load automatically in Claude Code whenever you work with the Burp MCP tools."
echo "To use it explicitly, type:  /${SKILL_NAME}"
