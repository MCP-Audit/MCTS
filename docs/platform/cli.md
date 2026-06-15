# CLI Reference

> [Documentation](../index.md) → [Platform](README.md)

Complete reference for every MCTS command and flag. Use this when you need to look up a specific option or understand exit codes.

> **New to MCTS?** Start with [Getting Started](../get-started/getting-started.md) — you don't need this full reference yet.
> **Confused by two scores or CI gates?** [Scoring developer guide](../reporting/scoring-guide.md) — read before memorizing flags.
> **Choosing a scan mode?** See [Which scan mode should I use?](../scanning/README.md#which-scan-mode-should-i-use).
> **Unfamiliar with a term?** See the [Glossary](../glossary.md).

**On this page:** [scan](#mcts-scan) · [report](#mcts-report) · [inventory](#mcts-inventory) · [vet](#mcts-vet) · [pentest](#mcts-pentest) · [fuzz](#mcts-fuzz) · [readiness](#mcts-readiness) · [serve](#mcts-serve) · [exit codes](#exit-codes) · [environment variables](#environment-variables)

**Roadmap / GAP tables** (contributors only): [Planned CLI](../more/planned-cli.md)

**Global options**

| Option | Description |
|--------|-------------|
| `--version` | Print `mcts` version and exit |
| `--help` | Command-specific help |

**Prerequisites:** Python 3.11+. Prefer `uvx mcp-mcts`, `pipx install mcp-mcts`, or `uv tool install mcp-mcts` — do not install into your application venv unless isolated.

---

## `mcts doctor`

Read-only preflight checks before your first scan (no live probes).

```bash
mcts doctor .
mcts doctor /path/to/repo --deep
mcts doctor . --json -o doctor-report.json
```

| Flag | Description |
|------|-------------|
| `--deep` | Optional import dry-run for config servers |
| `--json` | Machine-readable output to stdout |
| `--output`, `-o` | Write doctor JSON report (default: `mcts_analysis/doctor-report.json`) |

Exit **0** when checks pass; **1** on failures; **2** on user error.

---

## `mcts snapshot`

Export live `tools/list` metadata to JSON for offline `mcts scan --snapshot`.

```bash
mcts snapshot . --config .mcp.json --server my-server \
  --i-understand-live-risk -o tools-snapshot.json
```

Requires `--i-understand-live-risk` (or `MCTS_LIVE_OK=1` in CI).

---

## `mcts scan`

Run a full security scan against an MCP server entrypoint or repository.

```bash
mcts scan <target> [options]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `target` | Path to server file, repository directory, or `.` when using `--config` |

### Output flags

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | — | Write report to file |
| `--format`, `-f` | `json` | `json`, `sarif`, or `raw` (envelope with `target` + `scan_results`) |

When `-o` is set, format determines serialization. SARIF uses `reporting/sarif.py` for GitHub Code Scanning compatibility.

### CI gate flags

| Flag | Default | Description |
|------|---------|-------------|
| `--findings-trust-mode` | `off` | Findings trust layer: `off`, `warn`, or `enforce`. **Enforce** caps overlap chain display severity and aligns gates, score basis, history, and CLI with display severity. **`warn` does not relax CI** — use `enforce` or `--ci-trust`. See [Findings trust Phase 0](../reporting/findings-trust-phase0.md). |
| `--ci-trust` | off | CI preset: `findings-trust-mode enforce`, `--fail-on-critical`, `--min-score 70`. |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` for this scan (CLI flags only). |
| `--fail-on-priority-min` | — | **Enforce only.** Exit 1 when `priority_score` ≥ threshold (use with `--min-evidence-strength strong` for Option B). |
| `--min-evidence-strength` | — | Filter for `--fail-on-priority-min`: `weak`, `moderate`, `strong`, or `verified`. |
| `--fail-on-critical` | false | Exit **1** if any critical finding |
| `--min-score` | — | Exit **1** if legacy `score.overall` < N (0–100) |
| `--max-critical` | — | Exit **1** if critical count > N (enforce: display counts) |
| `--max-high` | — | Exit **1** if high count > N (enforce: display counts; merges from `.mcts/policy.yaml`) |
| `--fail-on-category` | — | Repeatable. Format: `category:limit`. **Enforce:** display-aligned legacy tiles; **warn/off:** template |
| `--scoring` | `both` | `legacy`, `v2`, or `both` — enable multi-factor scoring |
| `--min-security-score` | — | Exit **1** if v2 benchmark security score < N (requires `--scoring v2` or `both`) |
| `--max-absolute-risk` | — | Exit **1** if v2 `absolute_risk` > N (requires `--scoring v2` or `both`) |
| `--max-risk-level` | — | Exit **1** if v2 `risk_level` exceeds band (`low` < `medium` < `high` < `critical`) |
| `--min-category-score-v2` | — | Repeatable. Format: `category:min`. Exit **1** when v2 OWASP tile score &lt; min (100=good) |
| `--weights` | `manual_v1` | v2 weights profile name |
| `--corpus-stats-path` | packaged default | Override corpus stats JSON for v2 percentile scoring |
| `--no-attack-chains` | false | Disable v2 **chain multiplier** only (`chain_factor_mode: disabled`). Under `--scoring v2\|both` the attack chains analyzer still runs for graph + meta-findings. Use `--scoring legacy` to omit chain meta-findings entirely. |

Valid **legacy** category keys: `permissions`, `injection`, `execution`, `data_leakage`, `attack_chains`, `shadowing`, `jailbreak`. Category gates apply to v1 tiles only — not `category_scores_v2`. See [Scoring developer guide](../reporting/scoring-guide.md).

### Terminal UI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--theme` | `cyber` | `cyber`, `minimal`, or `github` |
| `--no-progress` | false | Skip pre-report progress animation (CI-friendly) |

### Discovery flags

| Flag | Default | Description |
|------|---------|-------------|
| `--languages` | `python,typescript` | Comma-separated static discovery backends |
| `--live` | false | Connect to live stdio MCP server |
| `--url` | — | Remote MCP URL (streamable HTTP or SSE); implies live |
| `--transport` | `streamable-http` | Remote transport: `streamable-http` or `sse` |
| `--command` | — | Custom launch binary for live mode |
| `--args` | — | Comma-separated args for `--command` |
| `--config` | — | MCP client config JSON path (JSON5/comments supported) |
| `--server` | — | Server name inside `mcpServers` (requires `--config`) |
| `--expand-vars` | `auto` | Expand `$VAR` / `%VAR%` in config commands: `auto`, `linux`, `mac`, `windows`, `off` |
| `--snapshot` | — | Static JSON snapshot (`tools/list` export); no live connection |
| `--surfaces` | all four | Comma-separated: `tool`, `prompt`, `resource`, `instruction` |
| `--discover-instructions` | true | Discover markdown prompts/instructions (`SKILL.md`, `*prompt*.md`, `system_prompt.md`) in repo scans |
| `--instruction-glob` | — | Repeatable glob under TARGET for extra instruction markdown files |
| `--instruction-file` | — | Repeatable explicit markdown file to include as a prompt/instruction surface |
| `--skills-dir` | — | Repeatable skills directory to scan for `SKILL.md` files |
| `--surface-scoped-analyzers` | true | When `--surfaces` is a subset, run only analyzers relevant to those surfaces |
| `--resource-mime` | — | Comma-separated MIME allowlist for resource scanning (e.g. `text/plain`) |
| `--i-understand-live-risk` | false | Consent for live/remote probe (or `MCTS_LIVE_OK=1`) |
| `--stderr-file` | — | Capture live server stderr to file |

### Remote auth flags

| Flag | Description |
|------|-------------|
| `--bearer-token` | Bearer token for remote MCP |
| `--header` | Repeatable. `Name: Value` custom HTTP headers |

OAuth client credentials: set via config JSON or env (`oauth_token_url`, `oauth_client_id`, etc.). See [Remote Scanning](../scanning/remote-scanning.md).

### Advanced analysis flags

| Flag | Default | Description |
|------|---------|-------------|
| `--baseline` | — | Compare tool metadata against saved baseline JSON (rug-pull) |
| `--save-baseline` | — | Write current tool metadata snapshot to JSON |
| `--sigma-rules-path` | — | Directory with extra `MCTS-T-*/detection-rule.yml` Sigma rules |
| `--semantic-secrets` | false | Enable semantic credential detection (MCTS-T-1022 / MCTS-M-025) |
| `--runtime-events` | — | JSON file with probe/runtime telemetry rows |
| `--behavioral-probe` | false | Multi-turn MCTS-T-1026 events (auto-enabled with `--live` / `--url`) |
| `--pip-audit` | false | Run pip-audit on `requirements.txt` / `pyproject.toml` |
| `--npm-audit` | false | Run `npm audit` when `package.json` present |
| `--protocol-probe` | false | Active MCPS HTTP checks on `--url` |
| `--yara` | false | Enable YARA metadata analyzer (`uv sync --extra yara`) |
| `--llm-judge` | false | Opt-in LLM-as-judge (`MCTS_LLM_API_KEY`, `--extra llm`) |
| `--llm-triage` | false | LLM metadata triage: malicious/safe/suspect (`MCTS_LLM_API_KEY`, `--extra llm`) |
| `--semgrep` | false | Semgrep SAST adapter (`semgrep` CLI on PATH; `--extra semgrep`) |
| `--semgrep-rules` | — | Custom Semgrep rules file or directory (default: bundled MCP rule pack) |
| `--cloud-inspect` | false | Opt-in cloud ML API (`MCTS_CLOUD_API_KEY`) |
| `--virustotal` | false | VirusTotal hash lookup (`MCTS_VT_API_KEY`) |

### Filter and output flags

| Flag | Description |
|------|-------------|
| `--terminal-format` | `table`, `by_tool`, `by_analyzer`, `by_severity`, `summary` (instead of Rich dashboard) |
| `--tool-filter` | Comma-separated tool names |
| `--analyzer-filter` | Comma-separated analyzer keys |
| `--severity-filter` | Comma-separated severities |
| `--analyzers` | Run only listed analyzers (subset mode) |
| `--hide-safe` | Hide low-severity informational findings in terminal output |
| `--auto` | Auto-resolve scan target (entrypoint or config-static; static only) |
| `--auto-server` | Server name when `--auto` finds multiple MCP servers |
| `--machine-wide` | Scan all MCP servers in local client configs (TARGET optional) |
| `--html` | Write HTML report after scan (same as `mcts report`) |

`mcts scan .` runs a repository-wide static scan and prints MCP config hints when `.mcp.json` is present.

### Planned flags (not yet implemented)

| Flag | Purpose |
|------|---------|
| `--profile` | Policy profile: `strict`, `balanced`, `dev` |

### Scoring output

Default (`--scoring both`) prints legacy and v2 lines:

- **Overall Score** — legacy 0–100, higher is better (`100 × e^(-raw_risk/50)`)
- **Absolute risk / risk level** — v2 multi-factor integer and band (when `score_v2` present)
- **Security score (v2)** — corpus benchmark percentile when packaged stats available
- **Risk Index** — legacy 0–100, higher is worse (`min(100, raw_risk)`)
- **Scoring basis** — legacy severity counts; compliance excluded
- **Category breakdown** — legacy per-dimension risk bars; v2 OWASP tiles in JSON/HTML when enabled

### Examples

```bash
# Machine-wide audit (no explicit target)
mcts scan --machine-wide -o machine-scan-report.json

# Repo scan (Python + TypeScript)
mcts scan ./my-mcp-repo/ -o report.json

# Single file
mcts scan examples/vulnerable-mcp-server/server.py

# Live stdio probe
mcts scan ./server.py --live --i-understand-live-risk

# From Cursor config
mcts scan . --config ~/.cursor/mcp.json --server my-server \
  --live --i-understand-live-risk

# SARIF + CI gates
mcts scan ./server.py -o report.sarif --format sarif \
  --min-score 70 --max-critical 0 --fail-on-critical

# Category gates
mcts scan ./repo/ \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15

# Fuzz telemetry replay
mcts scan ./server.py --runtime-events fuzz.json

# Rug-pull baseline workflow
mcts scan ./server.py --save-baseline baseline.json
mcts scan ./server.py --baseline baseline.json

# TypeScript-only discovery
mcts scan ./node-server/ --languages typescript

# Sigma + semantic secrets
mcts scan ./repo/ \
  --sigma-rules-path ./custom-rules/ \
  --semantic-secrets

# Remote HTTP MCP server
mcts scan . --url https://mcp.example.com/mcp \
  --bearer-token "$TOKEN" --i-understand-live-risk

# Static JSON snapshot (air-gapped CI)
mcts scan . --snapshot ./artifacts/tools-list.json -o report.json

# All MCP surfaces + supply chain
mcts scan ./repo/ \
  --surfaces tool,prompt,resource,instruction \
  --pip-audit --npm-audit

# Table output with filters
mcts scan ./server.py --terminal-format by_severity \
  --severity-filter critical,high
```

---

## Surface subcommands

Targeted scans without passing `--surfaces`:

```bash
mcts scan-prompts <target> [-o report.json] [--no-progress] [--snapshot path.json]
mcts scan-resources <target> [-o report.json] [--no-progress] [--snapshot path.json] [--resource-mime text/plain]
mcts scan-instructions <target> [-o report.json] [--no-progress] [--snapshot path.json]
```

Each subcommand writes matching HTML and SARIF siblings derived from the JSON basename (for example `scan-prompts-report.json` → `.html` / `.sarif`).

For agent repos with prompts in markdown (not MCP `prompts/list`), repository discovery is enabled by default on static scans:

```bash
mcts scan . --surfaces prompt,instruction
mcts scan ./skills --surfaces prompt,instruction
mcts scan . --instruction-file src/agent/system_prompt.md
mcts inventory --skills --skills-dir ./skills
```

Discovered markdown becomes prompt/instruction surfaces for `prompt_injection`, `jailbreak`, `prompt_defense`, and `skill_md`. Surface subcommands skip repo-wide analyzers such as `supply_chain` unless `--no-surface-scoped-analyzers` is set.

---

## `mcts readiness`

Production readiness checks (separate from security score).

```bash
mcts readiness <target> [--output, -o] [--opa] [--llm-judge] [--findings-trust-mode off|warn|enforce] [--ignore-policy]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--findings-trust-mode` | `off` | Apply trust validator to readiness notes |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` |

See [Readiness Scanning](../scanning/readiness.md).

---

## `mcts serve`

Start the REST API server (requires `uv sync --extra api`).

```bash
mcts serve [--host 127.0.0.1] [--port 8080] [--reload]
```

See [REST API](rest-api.md).

---

## `mcts report`

Generate an HTML security dashboard from a JSON scan report.

```bash
mcts report <input.json> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--output`, `-o` | `security-report.html` | Output HTML path |
| `--theme` | `cyber` | Terminal theme for save notice only |

Input must be valid `ScanReport` JSON from `mcts scan -o`.

See [HTML Security Dashboard](../reporting/html-report.md).

---

## `mcts inventory`

Discover MCP servers configured on this machine.

```bash
mcts inventory [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--scan` | false | Static-scan each entrypoint for tool names |
| `--skills` | false | Discover and scan `SKILL.md` files in agent skill directories |
| `--findings-trust-mode` | unset (`off`) | Apply trust validator to inventory/toxic-flow findings. Omit to inherit from `.mcts/policy.yaml`; pass explicitly (including `off`) to override policy. |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` |
| `--output`, `-o` | — | Write inventory JSON |
| `--theme` | `cyber` | Terminal theme |

`--scan-all` runs a full security scan per discovered server and exits **1** on governance gate failures (same as `mcts scan`) or critical/high findings.

Clients: Cursor, Claude Desktop, VS Code, Windsurf. Exit **1** on critical/high cross-server shadow findings (default inventory path).

See [Config Inventory](../scanning/inventory.md).

---

## `mcts vet`

Pre-install vetting for PyPI, npm, and OCI package references before adding them to an agent or MCP server.

```bash
mcts vet pypi:requests@2.31.0
mcts vet pypi:fastapi==0.136.3
mcts vet npm:@modelcontextprotocol/sdk
mcts vet oci:ghcr.io/org/mcp-server:1.0.0
mcts vet pypi:fastmcp --json -o vet-report.json
```

PyPI specs accept npm-style `@` pins or standard PEP 508 `==` pins after the `pypi:` prefix.

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Print machine-readable report to stdout |
| `--output`, `-o` | — | Write vet report JSON |
| `--findings-trust-mode` | `off` | Apply trust validator to vet findings |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` |

Exit **0** when no high/critical findings; **1** on high/critical issues; **2** on parse or network errors.

Heuristics include typosquat detection, yanked PyPI releases, npm lifecycle scripts, suspicious metadata text, and unfamiliar OCI registries.

---

## `mcts-mcp`

MCP server mode for IDE agents. Requires the optional `mcp` extra (`uv sync --extra mcp`).

```bash
mcts-mcp
# or: uv run --extra mcp mcts-mcp
```

**Tools exposed over stdio:**

| Tool | Description |
|------|-------------|
| `scan_mcp_target` | Run a full MCTS scan on a server path or repo |
| `explain_finding` | Explain a finding from a scan report JSON by ID |
| `compare_baselines` | Compare two scan reports (score and finding deltas) |

Configure your MCP client to launch `mcts-mcp` as a stdio server.

---

## `mcts pentest`

Structured red-team orchestration: static recon, metadata/attack-chain review, and optional safe protocol fuzz.

```bash
mcts pentest examples/vulnerable-mcp-server/server.py
mcts pentest ./server.py --live --i-understand-live-risk --findings-trust-mode enforce
mcts pentest ./repo --json -o pentest-report.json
```

| Flag | Default | Description |
|------|---------|-------------|
| `--live` | false | Include safe protocol fuzz after static phases |
| `--i-understand-live-risk` | false | Consent for live fuzz phase |
| `--json` | false | Print report JSON to stdout |
| `--output`, `-o` | — | Write pentest report JSON |
| `--findings-trust-mode` | unset (`off`) | Apply trust validator to pentest findings. Omit to inherit policy; pass explicitly to override. **`warn`** uses display severity for verdict (aligned with fuzz/vet). **`enforce`** uses gate summary. |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` |

Exit **0** on pass/medium verdict; **1** on critical/high; **2** on errors.

When `--scoring v2` or `both` and `score_v2` is present under **`off`**, **verdict** may use v2 `risk_level`. Under **`warn`**, verdict follows display severity on security findings (overlap chains capped). Under **`enforce`**, verdict follows gate summary (display-aligned).

**Static-only coverage:** when static discovery finds **zero MCP tools** (e.g. prompt-only servers), the `attack_chains` phase is marked `skipped` in the JSON report. Check `pentest_limits.coverage` (`static-only` vs `full`) and `pentest_limits.attack_chains_available` to see what ran.

---

## `mcts fuzz`

Protocol-level probing against a live stdio MCP server.

```bash
mcts fuzz <target> [options]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--fuzz-level` | `safe` | `safe`, `standard`, or `aggressive` |
| `--command` | — | Custom server launch command |
| `--args` | — | Comma-separated launch args |
| `--config` | — | MCP client config JSON |
| `--server` | — | Server name in config |
| `--output`, `-o` | — | Write findings + `runtime_events` JSON |
| `--i-understand-live-risk` | false | Live subprocess consent |
| `--i-understand-fuzz-risk` | false | Required for **aggressive** level |
| `--findings-trust-mode` | `off` | Apply trust validator to fuzz findings |
| `--ignore-policy` | off | Skip merging `.mcts/policy.yaml` |
| `--theme` | `cyber` | Terminal theme |

Pipe to scan:

```bash
mcts fuzz ./server.py --i-understand-live-risk -o fuzz.json
mcts scan ./server.py --runtime-events fuzz.json
```

See [Protocol Fuzzing](../scanning/fuzzing.md).

---

## Exit codes

| Code | When |
|------|------|
| **0** | Success; all gates passed |
| **1** | Gate failure; or critical/high fuzz/inventory findings |
| **2** | Usage error, missing consent, probe/fuzz failure, invalid theme/format |

Gate failures (`scan` only): `--fail-on-critical`, `--min-score`, `--max-critical`, `--fail-on-category` (legacy); `--min-security-score`, `--max-absolute-risk`, `--max-risk-level`, `--min-category-score-v2` (v2, require `--scoring v2` or `both`).

---

## Environment variables

| Variable | Effect |
|----------|--------|
| `MCTS_LIVE_OK=1` | Grants live/fuzz/remote probe consent in CI |
| `MCTS_BEARER_TOKEN` | Default bearer token for `--url` scans |
| `MCTS_LLM_API_KEY` | LiteLLM provider key for `--llm-judge` and `--llm-triage` |
| `MCTS_LLM_MODEL` | LLM model ID (default `gpt-4o-mini`) |
| `MCTS_CLOUD_API_KEY` | Cloud inspect API key for `--cloud-inspect` |
| `MCTS_CLOUD_ENDPOINT` | Cloud inspect API URL |
| `MCTS_VT_API_KEY` / `VIRUSTOTAL_API_KEY` | VirusTotal API key for `--virustotal` |
| `MCTS_API_KEY` | When set, REST API (`mcts serve`) requires matching `X-API-Key` header |

---

## CI examples

```bash
# Static gate
mcts scan ./server.py --fail-on-critical --min-score 70 -o report.json

# SARIF upload pipeline
mcts scan ./server.py --format sarif -o report.sarif --max-critical 0

# Live on fixture (trusted only)
MCTS_LIVE_OK=1 mcts scan ./fixture/server.py --live --no-progress

# Full artifact chain
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

GitHub Action: [CI Integration](ci-integration.md) · [`action/action.yml`](../../action/action.yml)

---

## Related

- [Architecture](../analysis/architecture.md)
- [Live Scanning](../scanning/live-scanning.md)
- [Remote Scanning](../scanning/remote-scanning.md)
- [Static Snapshot](../scanning/static-snapshot.md)
- [REST API](rest-api.md)
- **[Scoring developer guide](../reporting/scoring-guide.md)**
- [Scoring Specification (legacy)](../reporting/scoring-spec.md)
- [Getting Started](../get-started/getting-started.md)
