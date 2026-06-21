# Scoring Specification

> [Documentation](../index.md) → [Reporting](README.md)

This document is the **legacy** scoring reference (`score.overall`, 0–100). For the full picture (legacy + v2), read the **[Scoring developer guide](scoring-guide.md)** first.

> **CI gate on legacy score:** `--min-score 70 --fail-on-critical` · [CI Integration](../platform/ci-integration.md)  
> **v2 scoring:** [Scoring spec v2](scoring-spec-v2.md)

---

## In plain English

The **legacy overall score** is 0–100 where **higher is better**. It uses severity weights and exponential decay — see formulas below.

- **Risk index (0–100):** Higher is worse. Linear measure of total risk burden.
- **Default scans** also compute v2 (`score_v2`) — this doc does **not** cover v2. See [scoring guide](scoring-guide.md).

Every report includes `score.basis` showing which severities contributed. The scanner verifies the math on every run.

**Example:** `examples/vulnerable-mcp-server/server.py` scores approximately **1/100** legacy overall (v2 is separate — see [scoring guide](scoring-guide.md)).

Compliance findings (OWASP mapping) appear in reports but do **not** affect the score.

**Implementation:** `src/mcts/scoring/engine.py`

### Partitioned scores (MCP vs supply chain)

Reports may include `score_breakdown` with decomposed scores:

| Field | Meaning |
|-------|---------|
| `mcp_surface` | Tool/metadata analyzers (permissions, injection, chains, …) |
| `supply_chain` | CVE and dependency analyzers (`supply_chain`, `vulnerable_package`, `npm_audit`) |
| `dependency_hygiene` | Unpinned version findings |
| `composite` | Weighted blend: `0.6×mcp + 0.25×supply + 0.15×hygiene` |

`score.overall` remains the full finding set (backward compatible). `--min-score` gates on `score.overall`.

`scan_scope` on each report: `entrypoint`, `repository`, `config-static`, `live`, or `snapshot`.

**Implementation:** `src/mcts/scoring/partitions.py`, `src/mcts/scoring/categories.py`

---

## Design goals

1. **Deterministic** — same findings always produce the same score
2. **Auditable** — `score.basis` documents exact severity counts used
3. **CI-friendly** — legacy gates on overall score, critical count, and category thresholds; v2 gates documented in [scoring-spec-v2](scoring-spec-v2.md)
4. **Separated compliance** — OWASP meta-findings do not inflate risk score

The scanner calls `RiskScoringEngine.verify()` after scoring; mismatch raises `RuntimeError` (regression guard).

---

## Severity weights

| Severity | Raw risk points | Rationale |
|----------|-----------------|-----------|
| Critical | 25 | Immediate exploitation or catastrophic impact |
| High | 10 | Serious misuse or strong attack enabler |
| Medium | 3 | Meaningful weakness requiring attention |
| Low | 1 | Informational or defense-in-depth gap |

```python
raw_risk = critical×25 + high×10 + medium×3 + low×1
```

Constants: `RISK_WEIGHTS` in `scoring/engine.py`.

---

## Overall security score

Exponential decay — **higher is better**:

```
overall = round(100 × e^(-raw_risk / 50))
```

| Property | Value |
|----------|-------|
| `raw_risk == 0` | Score **100** (perfect) |
| Clamp range | `[0, 100]` |
| Decay scale | `RISK_DECAY_SCALE = 50` |

### Worked examples

| Findings | Raw risk | Overall score |
|----------|----------|---------------|
| None | 0 | 100 |
| 1 High | 10 | 82 |
| 3 Medium | 9 | 83 |
| 1 Critical + 2 High | 45 | 41 |
| 3 Critical + 7 High + 2 Medium | 151 | **5** |

Example servers: `examples/baseline-mcp-server/` (~100), `examples/medium-risk-mcp-server/` (~67), `examples/vulnerable-mcp-server/` (~5).

---

## Risk index

Linear cap on raw risk — **higher is worse**:

```
risk_index = min(100, raw_risk)
```

Use when dashboards should show "risk burden" without exponential inversion. A server with raw_risk 151 shows risk_index **100** (capped).

---

## Non-scoring findings

Findings where `analyzer == "compliance"` are excluded from score calculation:

```python
NON_SCORING_ANALYZERS = frozenset({"compliance"})
```

Compliance findings still appear in reports, HTML OWASP section, and SARIF — they inform governance but should not double-penalize already-scored issues.

`score.basis.excluded_non_scorable` counts excluded rows.

---

## JSON schema

```json
{
  "score": {
    "overall": 5,
    "risk_index": 100,
    "raw_risk": 151,
    "penalty": 151,
    "basis": {
      "critical": 3,
      "high": 7,
      "medium": 2,
      "low": 0,
      "scorable_total": 12,
      "excluded_non_scorable": 2
    }
  },
  "summary": {
    "critical": 3,
    "high": 7,
    "medium": 2,
    "low": 0,
    "total": 12
  }
}
```

Note: `summary` reflects scorable findings used for score; total finding count in `findings[]` may be higher when compliance rows exist.

`penalty` is a deprecated alias for `raw_risk` (backward compatibility).

---

## Category breakdown

Category scores power the **terminal dashboard**, **HTML radar chart**, and **`--fail-on-category`** gates.

Defined in `report/data.py` → `CATEGORY_DEFS`:

| Key | Label | Max points | Analyzers mapped |
|-----|-------|------------|------------------|
| `permissions` | Excessive Permissions | 20 | `permission_analyzer` |
| `injection` | Injection & Metadata | 20 | `prompt_injection`, `metadata_integrity`, `schema_surface` |
| `execution` | Execution & Path Risk | 15 | `command_execution`, `path_validation`, `tool_abuse` |
| `data_leakage` | Data Leakage Risk | 15 | `data_leakage` |
| `attack_chains` | Attack Chain Risk | 15 | `attack_chains` |
| `shadowing` | Cross-Server Shadowing | 5 | `cross_server` |
| `jailbreak` | Jailbreak Resistance | 10 | `jailbreak` |

### Per-category calculation

For each category:

1. Collect findings whose `analyzer` matches the category's analyzer list
2. Sum severity weights (same 25/10/3/1 table)
3. Category score = `min(maximum, weighted_sum)`

### Industry benchmark overlay

HTML radar chart compares your category scores to `INDUSTRY_BENCHMARK` defaults:

| Category | Benchmark |
|----------|-----------|
| permissions | 8 |
| injection | 6 |
| execution | 5 |
| data_leakage | 5 |
| attack_chains | 4 |
| shadowing | 2 |
| jailbreak | 3 |

Benchmarks are illustrative overlays — not pass/fail thresholds.

---

## CI gate semantics (legacy)

Exit code **1** when a gate fails; **2** for usage/consent errors.

| Flag | Fails when |
|------|------------|
| `--fail-on-critical` | `summary.critical > 0` (scorable findings) |
| `--min-score N` | `score.overall < N` |
| `--max-critical N` | `summary.critical > N` |
| `--fail-on-category KEY:LIMIT` | Legacy category score ≥ LIMIT |

Category gates are **inclusive** at the limit: `--fail-on-category permissions:10` fails when permissions category score is **10 or higher**. To require a zero-risk permissions category, use `permissions:1`; a limit of `permissions:0` fails even when the score is 0 because `0 >= 0`.

### v2 gates (shipped)

Requires `--scoring v2` or `both` (default). Canonical reference: [Scoring spec v2](scoring-spec-v2.md) · [Migration guide](../migration/scoring-v2.md).

| Flag | Fails when |
|------|------------|
| `--min-security-score N` | `score_v2.security_score < N` (needs corpus stats) |
| `--max-absolute-risk N` | `score_v2.absolute_risk > N` |
| `--max-risk-level LEVEL` | `score_v2.risk_level` exceeds band |
| `--min-category-score-v2 KEY:MIN` | v2 OWASP tile &lt; MIN (100=good) |

REST API returns `gate_violations` but does not change HTTP status — use CLI for CI exit codes.

### Recommended starter policy

```bash
mcts scan ./repo/ \
  --min-score 75 \
  --max-critical 0 \
  --fail-on-category permissions:10 \
  --fail-on-category injection:12 \
  --fail-on-category execution:10
```

Tune limits per team risk appetite. Start strict on `max-critical` and relax `min-score` as debt is burned down.

---

## Letter grades (HTML dashboard)

| Score range | Grade | Posture label |
|-------------|-------|---------------|
| 90–100 | A | Low risk |
| 80–89 | B | Moderate |
| 70–79 | C | Elevated |
| 60–69 | D | High |
| 0–59 | F | Critical |

Grades are derived from `score.overall` in `report/data.py`.

### Scoring modes

| Mode | Status | Notes |
|------|--------|-------|
| Legacy exponential (`--scoring legacy`) | Shipped | This document — `score.overall` |
| Multi-factor v2 (`--scoring v2\|both`) | Shipped (default `both`) | [Scoring spec v2](scoring-spec-v2.md) |
| AIVSS v2 (`--scoring aivss`) | Missing | GAP-060 |
| CVSS v4 vector per finding | Missing | GAP-061 |
| Runtime trust score (live/proxy) | Planned | L10-01 |

See [Feature Expansion Plan — Analyzer](../more/feature-expansion-plan.md#analyzer-47).

---

## Integrity check

```python
RiskScoringEngine.verify(findings, score)  # must return True
```

Called at end of `Scanner.run()`. Prevents:

- Stale cached scores in tests
- Manual score tampering in JSON
- Regression when weights change without test updates

---

## Related

- [CLI Reference — gate flags](../platform/cli.md#ci-gate-flags)
- [CI Integration](../platform/ci-integration.md)
- [HTML Security Dashboard](html-report.md)
- [Architecture — Scoring](../analysis/architecture.md#scoring-scoringenginepy)
