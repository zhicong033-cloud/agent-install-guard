#!/bin/bash
#
# block-install-hook.sh - PreToolUse hook for install-guard (optional hard intercept layer)
#
# Intercepts package installation commands before the agent executes them.
# When blocked, the agent sees a message directing it to run /install-guard first.
#
# Setup (Claude Code):
#   Project scope  -> .claude/settings.json
#   Global scope   -> ~/.claude/settings.json
#
#   {
#     "hooks": {
#       "PreToolUse": [
#         {
#           "matcher": "Bash",
#           "hooks": [
#             {
#               "type": "command",
#               "command": "\"$CLAUDE_PROJECT_DIR\"/.claude/hooks/block-install-hook.sh"
#             }
#           ]
#         }
#       ]
#     }
#   }
#
# Without this hook configured, install-guard is a SOFT constraint:
# it relies on the agent voluntarily invoking it. With this hook, it
# becomes a HARD intercept: install commands cannot run until the audit passes.
#
# To allow an install after /install-guard has approved it, set an env var:
#   INSTALL_GUARD_APPROVED=1
# The hook checks for this and allows the command through.

INPUT=$(cat)

# Check jq availability - if missing, warn but do not silently allow
if ! command -v jq &>/dev/null; then
  echo "WARNING: install-guard hook requires jq but it is not installed. Install jq or remove this hook to avoid false sense of security." >&2
  # Fail safe: block when we cannot verify the command
  exit 2
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty' 2>/dev/null)

if [ -z "$COMMAND" ]; then
  exit 0
fi

# If the user has approved via install-guard, let it through
if [ "${INSTALL_GUARD_APPROVED:-0}" = "1" ]; then
  exit 0
fi

# --- Patterns that trigger the block ----------------------------------------
# Match install commands across ecosystems.
# Patterns use word boundaries or end-of-string ($) to handle both
# "npm install express" and bare "npm install" (no package argument).

DANGEROUS_PATTERNS=(
  # npm/yarn/pnpm install (with or without package name)
  'npm[[:space:]]+install([[:space:]]|$)'
  'npm[[:space:]]+i[[:space:]]'
  'yarn[[:space:]]+add([[:space:]]|$)'
  'pnpm[[:space:]]+add([[:space:]]|$)'
  'pnpm[[:space:]]+install([[:space:]]|$)'
  'npx[[:space:]]'
  'pnpm[[:space:]]+dlx[[:space:]]'
  # pip install (with or without package name)
  'pip[[:space:]]+install([[:space:]]|$)'
  'pip3[[:space:]]+install([[:space:]]|$)'
  'python[[:space:]]+-m[[:space:]]+pip[[:space:]]+install([[:space:]]|$)'
  'uv[[:space:]]+pip[[:space:]]+install([[:space:]]|$)'
  'poetry[[:space:]]+add([[:space:]]|$)'
  # cargo
  'cargo[[:space:]]+add([[:space:]]|$)'
  'cargo[[:space:]]+install([[:space:]]|$)'
  # gem
  'gem[[:space:]]+install([[:space:]]|$)'
  # brew
  'brew[[:space:]]+install([[:space:]]|$)'
  # go
  'go[[:space:]]+get([[:space:]]|$)'
  'go[[:space:]]+install([[:space:]]|$)'
  # dotnet
  'dotnet[[:space:]]+add[[:space:]]+package'
  'dotnet[[:space:]]+tool[[:space:]]+install'
  # system package managers
  'apt-get[[:space:]]+install'
  'apt[[:space:]]+install'
  'dnf[[:space:]]+install'
  'yum[[:space:]]+install'
  'pacman[[:space:]]+-S'
  'zypper[[:space:]]+install'
  # conda
  'conda[[:space:]]+install'
  'conda[[:space:]]+create'
  # deno
  'deno[[:space:]]+install'
  # nix
  'nix-env[[:space:]]+-i'
  'nix[[:space:]]+profile[[:space:]]+install'
  # rustup
  'rustup[[:space:]]+(component|toolchain)[[:space:]]+(add|install)'
  # java
  'mvn[[:space:]]+install'
  # git clone into skills/plugins/extensions directories (skill/plugin install)
  'git[[:space:]]+clone.*skills/'
  'git[[:space:]]+clone.*plugins/'
  'git[[:space:]]+clone.*extensions/'
)

for pattern in "${DANGEROUS_PATTERNS[@]}"; do
  if echo "$COMMAND" | grep -qE "$pattern"; then
    cat >&2 <<'BLOCKMSG'
BLOCKED: This command installs a third-party package/plugin.

install-guard has not been run for this target. The user requires a security audit before any installation.

Run /install-guard first to perform:
  1. Source & supply-chain verification
  2. Static code scan (deterministic, injection-proof)
  3. Prompt-injection detection (for skills/plugins/MCP)
  4. Risk scoring
  5. Human approval

After the user approves the audit, set INSTALL_GUARD_APPROVED=1 and retry.
BLOCKMSG
    exit 2
  fi
done

exit 0
