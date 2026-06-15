# MCTS GitHub Action

Run MCTS security scans in your GitHub Actions workflow. The action scans your MCP server, generates JSON + SARIF + HTML reports, and can fail the build on security thresholds.

> **New to MCTS?** See [Getting Started](../docs/get-started/getting-started.md) first.
> **Full CI guide:** [CI Integration](../docs/platform/ci-integration.md)

---

## Quick start

Add this to your workflow file (`.github/workflows/mcp-security.yml`):

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
          target: ./server.py
          fail-on-critical: true
          min-score: "70"

      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: mcts-report.sarif
```

---

## What the action does

1. Installs MCTS with `uv sync --frozen` from the pinned action ref (reproducible lockfile; default extras: `mcp`, `sast`)
2. Runs `mcts scan` once on your target (JSON, SARIF, and HTML are derived from the same scan)
3. Writes `mcts-report.json`, `mcts-report.sarif`, and `mcts-report.html` to the workflow workspace
4. Uploads JSON, HTML, and SARIF as workflow artifacts
5. Fails the workflow on gate violations — legacy (`fail-on-critical`, `min-score`) and/or v2 (`max-absolute-risk`, `max-risk-level`, `min-security-score`, `min-category-score-v2`)

Upload SARIF to GitHub Code Scanning separately (see quick start) to show findings in the Security tab.

### v2 gate example

```yaml
- uses: MCP-Audit/MCTS@v1
  with:
    target: ./server.py
    fail-on-critical: true
    max-absolute-risk: "500"
    max-risk-level: high
    min-security-score: "40"
```

Scoring defaults to `both` — JSON and SARIF include `score_v2` without extra inputs. See [Scoring developer guide](../docs/reporting/scoring-guide.md#ci-gates--pick-one-strategy).

### Installed capabilities (default extras)

| Feature | Extra | Default action |
|---------|-------|----------------|
| Python / TS static scan | core | Yes |
| Live probe (`--live`) | `mcp` | Yes |
| Tree-sitter SAST (TS/Go/Rust) | `sast` | Yes |
| `--pip-audit` | `supplychain` | Opt-in via `extras` input |
| `--yara`, `--llm-judge`, `--semgrep` | respective extras | Opt-in via `extras` input |

---

## Usage (monorepo / local action)

If the action lives in your repo under `action/`:

```yaml
- uses: ./action
  with:
    target: ./server.py
    fail-on-critical: true
    min-score: "70"
```

---

## Inputs

| Input | Default | Description |
|-------|---------|-------------|
| `target` | `./server.py` | Path to MCP server entrypoint or repo directory |
| `fail-on-critical` | `true` | Fail workflow if any critical finding is detected |
| `min-score` | — | Fail if legacy overall score is below this threshold (0–100) |
| `scoring` | `both` | `legacy`, `v2`, or `both` — enable multi-factor scoring |
| `min-security-score` | — | Fail if v2 benchmark security score is below threshold (requires `scoring: v2` or `both`) |
| `max-absolute-risk` | — | Fail if v2 absolute risk exceeds threshold |
| `max-risk-level` | — | Fail if v2 risk level exceeds band (`low` / `medium` / `high` / `critical`) |
| `min-category-score-v2` | — | Comma-separated v2 OWASP minimums (`injection:80,privilege:70`; 100=good) |
| `weights-profile` | `manual_v1` | v2 weights profile when `scoring` is `v2` or `both` |
| `assets-path` | — | Optional `.mcts/assets.yaml` for v2 asset-value overrides |
| `findings-trust-mode` | `off` | Trust layer: `off`, `warn`, or `enforce` |
| `ci-trust` | `true` | Shorthand for enforce + aligned gates (same as `mcts --ci-trust`). Set `false` for template-mode scans. |
| `fail-on-priority-min` | — | Fail when any finding priority_score ≥ threshold (enforce only) |
| `min-evidence-strength` | — | With priority gate: minimum evidence strength |
| `max-high` | — | Fail when high findings exceed count (display under enforce) |
| `max-critical` | — | Fail when critical findings exceed count (display under enforce) |
| `ignore-policy` | `false` | Skip merging `.mcts/policy.yaml` for this run |
| `extras` | `mcp,sast` | Comma-separated optional extras (`all` installs every extra) |

---

## Outputs

| File | Format | Use |
|------|--------|-----|
| `mcts-report.json` | JSON | Full scan report — automation, archiving |
| `mcts-report.sarif` | SARIF | Upload to GitHub Code Scanning |
| `mcts-report.html` | HTML | Human review — download from workflow artifacts |

---

## Related

- [CI Integration](../docs/platform/ci-integration.md) — full CI patterns and gate examples
- [CLI Reference](../docs/platform/cli.md) — all scan flags available locally
- [Scoring developer guide](../docs/reporting/scoring-guide.md) — start here (CI flags, two scores)
- [Scoring spec v2](../docs/reporting/scoring-spec-v2.md) — technical reference
- [Documentation index](../docs/index.md)
