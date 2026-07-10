# install-guard

A pre-installation security gate skill for [Codex](https://github.com/openai/codex) / Claude Code agents. When the user asks to install, download, or add any third-party package, plugin, skill, or extension, install-guard intercepts and runs a full security audit **before** any install command executes.

## Why

AI agents can search for and install third-party packages on demand -- but that closed loop ("search → install → execute") hands partial machine control to unknown third parties. install-guard breaks that loop open by inserting a deterministic, prompt-injection-proof checkpoint.

## What it does

Runs an 8-step pipeline before any installation:

1. **Identify** target and ecosystem (npm / PyPI / cargo / gem / GitHub / Codex skill / Claude plugin / MCP server / VSCode / JetBrains)
2. **Source reconnaissance** -- GitHub API, npm registry, PyPI JSON, OpenSSF Scorecard (stars, maintainer age, typosquatting, LICENSE/README)
3. **Fetch source** to an isolated temp directory (never executes install scripts)
4. **Dependency audit** -- npm audit / pip-audit / cargo audit / bundler-audit for known vulnerabilities
5. **Deterministic static scan** -- pure grep script, 7 risk categories, output never passes through any LLM
6. **Prompt-injection detection** -- isolated sub-agent with cross-validation against script results
7. **Risk scoring** -- weighted algorithm with hard constraints (script high-severity = automatic red)
8. **Forced human approval** -- layered risk card with raw script output, agent analysis, and conflict flags

## Key design: the script is the anchor

Prompt injection can corrupt agent judgement. But it cannot corrupt a grep.

`scan-code.sh` is pure bash + grep. Its output never passes through any LLM. When the script and the agent disagree, **the script wins**. The user sees the raw script output directly, not filtered through an agent summary.

## Installation

```bash
# Clone into your skills directory
git clone https://github.com/<your-username>/install-guard.git ~/.Codex/skills/install-guard

# Make scripts executable
chmod +x ~/.Codex/skills/install-guard/scripts/*.sh
```

## Optional: hard intercept hook

Without the hook, install-guard is a **soft constraint** (relies on the agent invoking it). Configure the PreToolUse hook for a **hard intercept**:

```json
// ~/.claude/settings.json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "$HOME/.Codex/skills/install-guard/scripts/block-install-hook.sh"
          }
        ]
      }
    ]
  }
}
```

After the user approves an audit, set `INSTALL_GUARD_APPROVED=1` to let the install through.

## File structure

```
install-guard/
├── SKILL.md                      # Main orchestration (8-step flow, 2 confirmation points)
├── scripts/
│   ├── scan-code.sh              # Deterministic grep scanner (7 risk categories, JSON output)
│   └── block-install-hook.sh     # Optional PreToolUse hook (hard intercept)
├── rules/
│   └── detection-rules.md        # Full pattern table + risk scoring algorithm
├── cache/                        # Audit result cache (gitignored)
│   └── .gitkeep
└── .gitignore
```

## Requirements

- `bash` 4.0+
- `python3` (for JSON output formatting)
- `jq` (only required if using the block-install hook)
- `git` (for cloning source during audit)
- `curl` (for API calls during source reconnaissance)

## Honest limitations

- **Can catch**: obvious malicious scripts, typosquat packages, cold-start suspicious sources, prompt-injection text patterns
- **Cannot catch**: carefully designed logic bombs, concealed backdoors in legitimate code, runtime-triggered delayed attacks
- **grep limitation**: calls hidden via base64/hex/string concatenation cannot be detected. Script output is "suspicious pattern match", not "confirmed malicious behaviour"
- **Soft vs hard**: without the hook, a malicious or negligent agent could bypass the check. With the hook, install commands cannot execute until the audit passes

## License

MIT
