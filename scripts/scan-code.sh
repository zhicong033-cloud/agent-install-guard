#!/bin/bash
#
# scan-code.sh - Deterministic static security scanner for install-guard
#
# Pure grep for pattern matching. Output formatted via python3's json
# module for reliable escaping. The MATCHING engine is grep only - no LLM
# involved. This is the unmutable anchor of the install-guard assessment.
#
# Usage: scan-code.sh <source-directory>
# Output: JSON array of findings on stdout
#
# Each finding: {"category":"...","file":"...","line":N,"snippet":"...","severity":"high|medium|low"}
# On error:     {"error":"crash","message":"..."}

set -uo pipefail

SOURCE_DIR="${1:-}"
if [ -z "$SOURCE_DIR" ] || [ ! -d "$SOURCE_DIR" ]; then
  echo '{"error":"crash","message":"source directory not provided or does not exist"}'
  exit 0
fi

# Check python3 availability - needed for JSON output
if ! command -v python3 &>/dev/null; then
  echo '{"error":"crash","message":"python3 is required but not found in PATH"}'
  exit 0
fi

MAX_PER_CATEGORY=20

# --- Build the find command once (reused by each category) -----------------
emit_files() {
  find "$SOURCE_DIR" -type f \
    ! -path '*/.git/*' \
    ! -path '*/node_modules/*' \
    ! -path '*/__pycache__/*' \
    ! -path '*/vendor/*' \
    ! -path '*/target/*' \
    ! -path '*/.venv/*' \
    ! -path '*/venv/*' \
    ! -path '*/dist/*' \
    ! -path '*/build/*' \
    ! -path '*/test/*' \
    ! -path '*/tests/*' \
    ! -path '*/__tests__/*' \
    ! -path '*/spec/*' \
    ! -path '*/specs/*' \
    ! -path '*/examples/*' \
    ! -path '*/example/*' \
    ! -path '*/demo/*' \
    ! -path '*/fixtures/*' \
    ! -path '*/mocks/*' \
    ! -name '*.min.js' \
    ! -name '*.min.css' \
    ! -name '*.bundle.js' \
    ! -name '*.map' \
    ! -name '*.png' \
    ! -name '*.jpg' \
    ! -name '*.jpeg' \
    ! -name '*.gif' \
    ! -name '*.ico' \
    ! -name '*.woff' \
    ! -name '*.woff2' \
    ! -name '*.ttf' \
    ! -name '*.eot' \
    ! -name '*.pdf' \
    ! -name '*.zip' \
    ! -name '*.gz' \
    ! -name '*.tar' \
    -print0 2>/dev/null
}

# --- Scan one category: grep each file, emit raw delimited lines -----------
scan_category() {
  local category="$1"
  local severity="$2"
  local pattern="$3"

  while IFS= read -r -d '' file; do
    local rel="${file#$SOURCE_DIR/}"
    local matches
    matches=$(grep -nEI "$pattern" "$file" 2>/dev/null || true)
    if [ -z "$matches" ]; then
      continue
    fi
    while IFS= read -r match; do
      local lineno="${match%%:*}"
      local content="${match#*:}"
      if [ ${#content} -gt 200 ]; then
        content="${content:0:200}..."
      fi
      printf '%s\x1f%s\x1f%s\x1f%s\x1f%s\n' "$category" "$severity" "$rel" "$lineno" "$content"
    done <<< "$matches"
  done < <(emit_files)
}

# --- Run all 7 categories, collect raw output -------------------------------
#
# Pattern fixes (vs original):
# - sensitive_access: removed bare `.env` (matched process.env/os.environ);
#   now only matches .env as a file path or dotenv load, not as substring
# - dep_poisoning: removed `\*{2,}` (matched Markdown **bold**);
#   now uses targeted version-range patterns only
# - destructive: fixed fork bomb regex (was character class, now literal)
# - obfuscation: fixed hex pattern (was {20,} consecutive, now detects
#   repeated \xNN escape sequences)
{
  scan_category "remote_exec" "high" \
    'curl[[:space:]]+[^|]*\|[[:space:]]*(sh|bash|zsh)|wget[^>]*\|[[:space:]]*(sh|bash)|nc[[:space:]]+-e|/dev/tcp/|bash[[:space:]]+-i|/dev/udp/|mkfifo[[:space:]]+/tmp/.*\|[[:space:]]*sh|socat[[:space:]]+.*(EXEC|exec):'

  scan_category "dynamic_exec" "high" \
    '\beval[[:space:]]*\(|\bexec[[:space:]]*\(|\bFunction[[:space:]]*\(|os\.system[[:space:]]*\(|subprocess\.(call|run|Popen|check_output)[^)]*shell[[:space:]]*=[[:space:]]*True|child_process\.exec[[:space:]]*\(|vm\.runInNewContext|new[[:space:]]+Function[[:space:]]*\('

  scan_category "sensitive_access" "high" \
    '\.ssh/(id_rsa|id_dsa|config|authorized_keys)|\.aws/credentials|\.env[[:space:]]+(file|path)|dotenv.*load|id_rsa|id_dsa|\.gnupg/|\.npmrc|\.pypirc|\.docker/config\.json|credentials\.json|\.netrc|/etc/shadow|/etc/passwd|\.kube/config|\.git-credentials|\.ssh/id_'

  scan_category "data_exfil" "medium" \
    'requests\.(post|put)[[:space:]]*\(|fetch[[:space:]]*\(\s*["'"'"']https?://|axios\.(post|put)[[:space:]]*\(|XMLHttpRequest|\.send[[:space:]]*\(\s*[^)]*(password|token|secret|key|credential)|curl[[:space:]]+[^|]*-X[[:space:]]*POST|http\.Client|urllib\.request\.urlopen|dnspython|dns\.resolver|socket\.gethostbyname'

  scan_category "obfuscation" "medium" \
    'atob\(|btoa\(|base64decode|base64\.b64decode|binascii\.unhexlify|bytes\.fromhex|String\.fromCharCode|decodeURIComponent\(\s*["'"'"']%|eval\(\s*atob|eval\(\s*Buffer\.from|(\\x[0-9a-fA-F]{2}){10,}'

  scan_category "destructive" "high" \
    'rm[[:space:]]+-rf?[[:space:]]+/|rm[[:space:]]+-rf?[[:space:]]+~|rm[[:space:]]+-rf?[[:space:]]+\*|dd[[:space:]]+if=.*of=/dev/|mkfs|:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;|shred[[:space:]]+-f|truncate[[:space:]]+-s[[:space:]]+0|>+/dev/sda|chmod[[:space:]]+-R[[:space:]]+777[[:space:]]+/'

  scan_category "dep_poisoning" "medium" \
    'git\+https?://[^"]+|git\+ssh://|file:[/][/]|"[^"]*":[[:space:]]*"\*["'"'"']|https?://[^"]*(raw\.githubusercontent|gist\.githubusercontent|pastebin|ngrok|bitly|tinyurl)'
} | python3 -c "
import sys, json, collections

raw = sys.stdin.read()
findings = []
counts = collections.Counter()
UNIT = '\x1f'

for line in raw.split('\n'):
    if not line.strip():
        continue
    parts = line.split(UNIT)
    if len(parts) < 5:
        continue
    category, severity, filepath, lineno, snippet = parts[:5]
    counts[category] += 1
    if counts[category] <= $MAX_PER_CATEGORY:
        findings.append({
            'category': category,
            'file': filepath,
            'line': int(lineno),
            'snippet': snippet,
            'severity': severity
        })

for cat, total in sorted(counts.items()):
    if total > $MAX_PER_CATEGORY:
        findings.append({'truncated': True, 'category': cat, 'total': total})

print(json.dumps(findings, ensure_ascii=False))
"

exit 0
