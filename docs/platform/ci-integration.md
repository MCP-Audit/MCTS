# CI/CD Integration

> [Documentation](../index.md) → [Platform](README.md)

This guide shows how to run MCTS in your CI/CD pipeline — fail builds on security thresholds, upload SARIF to GitHub Code Scanning, and share HTML reports with your team.

> **Which CI flags should I use?** [Scoring developer guide](../reporting/scoring-guide.md#ci-gates--pick-one-strategy) — legacy vs v2 cheat sheet  
> **Quick legacy gate:** `mcts scan ./server.py --fail-on-critical --min-score 70`  
> **Quick v2 gate:** `mcts scan ./server.py --fail-on-critical --max-absolute-risk 500 --max-risk-level high`  
> **GitHub Action:** [below](#github-actions-published-action)

### Pick a CI strategy

| Strategy | When | Example |
|----------|------|---------|
| **A — Legacy only** | Existing pipelines; no policy change | `--fail-on-critical --min-score 70` |
| **B — v2 only** | New risk policies | `--max-absolute-risk 500 --max-risk-level high` |
| **C — Dual gates** | Transition period | `--min-score 70 --max-absolute-risk 500` |

Default `--scoring both` means v2 fields are always in JSON/SARIF/HTML even when you only gate on legacy metrics.

---

## In plain English

MCTS is designed to work in CI without a cloud account. The typical workflow:

1. **Scan** your MCP server on every pull request
2. **Fail the build** if critical findings exist or the score drops below your threshold
3. **Upload SARIF** so findings appear in GitHub's Security tab
4. **Save HTML** as a workflow artifact for human review

No API keys or external services required for standard scans.

---

## Integration patterns

| Pattern | When to use | Outputs |
|---------|-------------|---------|
| **Static gate** | Every PR touching MCP server code | JSON + exit code |
| **SARIF upload** | GitHub/GitLab/Azure code scanning | `.sarif` file |
| **HTML artifact** | Security review, executives | `security-report.html` |
| **Live probe** | Staging fixture validation | JSON with merged discovery |
| **Fuzz + scan** | Protocol hardening regression | `fuzz.json` → `--runtime-events` |
| **Inventory audit** | Self-hosted / developer machine | `inventory.json` |

---

## GitHub Actions (published action)

```yaml
name: MCP Security

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: MCP-Audit/MCTS@v1
        with:
          target: ./examples/vulnerable-mcp-server/server.py
          fail-on-critical: true
          min-score: "70"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

### What the action does

1. Installs MCTS with **`uv sync --frozen`** from the pinned action ref (lockfile-pinned deps; default extras `mcp`, `sast`)
2. Runs `mcts scan` on `target`
3. Writes `mcts-report.json` and `mcts-report.sarif`
4. Runs `mcts report` → `mcts-report.html`
5. Uploads JSON/HTML as workflow artifacts
6. Respects legacy gates (`fail-on-critical`, `min-score`) and optional v2 gates (`scoring`, `min-security-score`, `max-absolute-risk`, `max-risk-level`, `min-category-score-v2`)

Monorepo: `uses: ./action`
Full reference: [action/README.md](../../action/README.md)

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Scan target path |
| `fail-on-critical` | `true` | Fail workflow on critical findings |
| `min-score` | — | Fail if legacy overall score below threshold |
| `scoring` | `both` | `legacy`, `v2`, or `both` |
| `min-security-score` | — | v2 benchmark gate |
| `max-absolute-risk` | — | v2 absolute risk ceiling |
| `max-risk-level` | — | v2 band gate (`low` … `critical`) |
| `min-category-score-v2` | — | Comma-separated `category:min` for v2 OWASP tiles |
| `findings-trust-mode` | `off` | Trust layer: `off`, `warn`, or `enforce` (prefer `enforce` / `ci-trust` for CI) |
| `ci-trust` | `true` | Shorthand: enforce + aligned gates (same as `mcts --ci-trust`). Set `false` for template-mode scans. |
| `fail-on-priority-min` | — | Fail when priority ≥ threshold (**enforce** only) |
| `min-evidence-strength` | — | Optional filter for priority gate |
| `extras` | `mcp,sast` | Optional extras to install (`all` for full set) |

---

## Manual CI commands

### Fail on critical findings

```bash
mcts scan ./server.py --fail-on-critical -o report.json
```

### Score threshold

```bash
mcts scan ./repo/ --min-score 70 --max-critical 0 -o report.json
```

Recommended for MCP server repos: start with `--max-critical 0` and `--min-score 70`, tighten over time.

### Category gates

```bash
mcts scan ./repo/ \
  --min-score 70 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:15 \
  --fail-on-category execution:10
```

Category semantics: [Scoring Specification](../reporting/scoring-spec.md). Category gates apply to **legacy** v1 tiles only.

### Scoring v2 gates

Scans include `score_v2` by default (`scoring: both`). **Gates** on v2 fields are opt-in:

```bash
mcts scan ./server.py \
  --scoring v2 \
  --max-absolute-risk 500 \
  --max-risk-level high \
  --min-security-score 40 \
  -o report.json
```

| Flag | Metric |
|------|--------|
| `--scoring v2\|both` | Enables `score_v2` in report JSON |
| `--min-score` | Legacy `score.overall` only (unchanged) |
| `--min-security-score` | v2 benchmark percentile score |
| `--max-absolute-risk` | v2 stable integer risk sum |
| `--max-risk-level` | v2 band (`low` < `medium` < `high` < `critical`) |
| `--min-category-score-v2` | v2 OWASP tile minimum (100=good) |

GitHub Action equivalents: `scoring`, `min-security-score`, `max-absolute-risk`, `max-risk-level`, `min-category-score-v2` inputs.

**v2 Action example:**

```yaml
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
    max-absolute-risk: "500"
    max-risk-level: high
```

See [Scoring developer guide](../reporting/scoring-guide.md), [migration](../migration/scoring-v2.md), and [SARIF scoreV2](../reporting/sarif-score-v2.md).

### Findings trust mode in CI

Overlap-style attack chains can inflate template `critical` counts without a proven multi-step path. Use the findings trust layer when you want gates and SARIF to reflect **display** severity.

| Mode | CI gates (severity, priority, bronze) | Legacy score | Dashboard / SARIF |
|------|--------------------------------------|--------------|-------------------|
| `off` (default) | Template severity | Template | Template |
| `warn` | **Template** severity; priority/bronze gates **inactive** | Template | Display badges preview |
| `enforce` | **Display** severity; priority + bronze gates active | Display-aligned basis | Display |

```bash
# Recommended for MCP overlap noise (same as --ci-trust preset)
mcts scan ./server.py \
  --findings-trust-mode enforce \
  --fail-on-critical \
  --min-score 70
```

GitHub Action (default `ci-trust: true`; set `false` to opt out):

```yaml
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    ci-trust: true
    fail-on-critical: true
    min-score: "70"
```

Governance policy (`.mcts/policy.yaml`) can set trust fields when CLI omits them. Use **`--ignore-policy`** or explicit **`--findings-trust-mode off`** for one-off legacy scans when policy sets `enforce`.

**Integrators:** Gate on `display_summary` / `display_severity`, not `summary.critical` alone. SARIF `level` and rule `security-severity` follow display when trust fields are set; template severity remains in `properties.severity`.

See [Interpreting findings](../reporting/interpreting-findings.md) and [Findings trust (Phase 0)](../reporting/findings-trust-phase0.md).

### Scan history and trends

`mcts_analysis/history.json` records both template and display counts when trust is on:

| Field | Meaning |
|-------|---------|
| `critical` | Template severity count (always recorded) |
| `display_critical` | Display severity count (when trust enabled) |
| `findings_trust_mode` | `off`, `warn`, or `enforce` for that run |

When comparing trend lines across weeks, **filter by `findings_trust_mode`** or chart `display_critical` only. A drop from 3 → 0 critical may mean trust was enabled, not that vulnerabilities were fixed.

### SARIF for code scanning

```bash
mcts scan ./server.py --format sarif -o report.sarif
```

Upload with platform-specific actions:

| Platform | Upload step |
|----------|-------------|
| GitHub | `github/codeql-action/upload-sarif@v3` |
| GitLab | Ultimate SAST API or generic artifact |
| Azure DevOps | SARIF upload task |

**Note:** One `mcts scan` invocation writes one format to one `-o` path. For both JSON and SARIF in manual CI, run scan twice or use the GitHub Action.

### HTML artifact for reviewers

```bash
mcts scan ./server.py -o report.json
mcts report report.json -o security-report.html
```

Upload `security-report.html` as a workflow artifact for security team review without cloning the repo.

---

## Recommended workflow (manual install)

```yaml
jobs:
  mcts:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: astral-sh/setup-uv@v7
      - run: uv sync --all-extras

      - name: Static security scan
        run: |
          uv run mcts scan ./mcp-server/ \
            --no-progress \
            --min-score 75 \
            --max-critical 0 \
            --fail-on-critical \
            -o mcts-report.json

      - name: SARIF export
        if: always()
        run: |
          uv run mcts scan ./mcp-server/ \
            --no-progress \
            --format sarif \
            -o mcts-report.sarif

      - name: HTML dashboard
        if: always()
        run: uv run mcts report mcts-report.json -o mcts-report.html

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif

      - name: Upload reports
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: mcts-reports
          path: |
            mcts-report.json
            mcts-report.sarif
            mcts-report.html
```

---

## Live probing in CI

Live scans start a real MCP subprocess. **Only use on trusted fixtures or staging servers you control.**

```bash
export MCTS_LIVE_OK=1
uv sync --extra mcp

uv run mcts scan ./examples/live-mcp-server/server.py \
  --live \
  --no-progress \
  -o report.json \
  --min-score 70
```

Alternative: pass `--i-understand-live-risk` instead of env var.

### Fuzz in CI (safe level)

```bash
MCTS_LIVE_OK=1 uv run mcts fuzz ./server.py \
  --fuzz-level safe \
  --i-understand-live-risk \
  -o fuzz.json

MCTS_LIVE_OK=1 uv run mcts scan ./server.py \
  --runtime-events fuzz.json \
  --no-progress \
  --min-score 70
```

Never run **aggressive** fuzz in CI against shared infrastructure.

---

## Exit codes

| Code | Meaning | Typical CI action |
|------|---------|-------------------|
| **0** | Success; gates passed | Continue pipeline |
| **1** | Gate failure or high/critical fuzz/inventory | Fail job |
| **2** | Usage error, missing consent, probe failure | Fail job (misconfiguration) |

Configure CI to fail on codes 1 and 2.

---

## Inventory in CI

```bash
mcts inventory --scan -o inventory.json
```

Best on **self-hosted runners** or developer machines with MCP client configs installed. Ephemeral GitHub-hosted runners typically have no `~/.cursor/mcp.json` — inventory will return empty.

Use cases:

- Scheduled audit of engineering laptops
- Pre-release config hygiene check
- Detect cross-server tool shadowing before agent deployment

---

## Branch protection

Pair MCTS gates with required CI checks on `main`. See [CONTRIBUTING.md](../../CONTRIBUTING.md) for ruleset setup.

---

## Security considerations

| Topic | Guidance |
|-------|----------|
| Live/fuzz in CI | Trusted targets only; set `MCTS_LIVE_OK` explicitly |
| SARIF contents | May include file paths and finding snippets — treat as security data |
| HTML artifacts | Self-contained; no exfiltration, but contains full scan |
| Secrets in repos | MCTS may flag secrets in scanned source — rotate if leaked in CI logs |

### Fleet gates (`--machine-wide`, inventory `--scan-all`)

Per-server gates run via `collect_gate_violations()`. Fleet-wide v2 cap:

```bash
mcts scan --machine-wide --scoring both --max-worst-absolute-risk 500
mcts inventory --scan-all --scoring both --max-worst-absolute-risk 500
```

YAML: `max_worst_absolute_risk` in `.mcts/policy.yaml` (see `.mcts/policy.yaml.example`).

**Dual exit heuristic:** If no explicit gate fires, machine-wide and inventory scan-all may still exit 1 when any server has critical/high display counts (or v2 `risk_level` high/critical). Prefer explicit `--max-critical` / `--max-worst-absolute-risk` for predictable CI.

---

## Planned CI capabilities

From the gap backlog — planned for Phase 2–3:

| Capability | Status | GAP | Notes |
|------------|--------|-----|-------|
| Unified `--ci` preset bundle | Shipped | GAP-024 | Single flag for gates + format |
| Governance `--policy` YAML | Shipped | GAP-222 | Allowlist + min-score in CI |
| Machine-wide config audit | Shipped | GAP-006 | `mcts scan --machine-wide` |
| Git-diff scoped scan in PR | Planned | GAP-010 | `--diff-base` / `mcts diff` |
| PR comment markdown output | Planned | GAP-235 | PR comment format for CI |
| `--ignore-issues-codes` allowlist | Planned | GAP-025 | Suppress W001 etc. in CI |
| GitLab CI template | Planned | GAP-167 | Secondary to GitHub Action |
| Pre-commit hook installer | Planned | GAP-038 | `init-hooks` companion |

See [Planned CLI flags](../more/planned-cli.md) and [Roadmap Phase 2](../more/roadmap.md#phase-2--differentiation-in-progress).

---

## Related

- **[Scoring developer guide](../reporting/scoring-guide.md)** — gate cheat sheet (read first)
- [CLI Reference](cli.md)
- [GitHub Action](../../action/README.md)
- [Live Scanning](../scanning/live-scanning.md)
- [Roadmap — GitHub Action](../more/roadmap.md#2-github-action)
