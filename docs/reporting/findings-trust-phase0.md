# Findings trust layer — Phase 0 implementation status

> [Documentation](../index.md) → [Reporting](README.md) → **Findings trust (Phase 0)**

**Status:** Implemented in tree (Phase 0 → B2 + Phase 3 + alignment fixes) · **728 tests** · Acceptance: `scripts/validate_trust_layer.py` (0 failures) · Tracks [#258](https://github.com/MCP-Audit/MCTS/issues/258)

This document is the **maintainer-facing record** of what Phase 0 delivered, what was intentionally deferred, known operational risks, and the mitigation plan for follow-up work.

**User-facing guide:** [Interpreting findings](interpreting-findings.md) · **Product roadmap:** `local/findings-quality-evidence-roadmap.md` (internal)

---

## Summary

Phase 0 adds a **findings trust layer** so MCTS can show honest attack-chain overlap without breaking legacy CI or scoring:

```
Parallel display fields + validate_findings() + consumer migration (primary path)
```

**Default behavior is unchanged:** `findings_trust_mode=off` — same `summary.critical`, same `--fail-on-critical`, same scores.

**Opt-in honest UX/CI:** `--findings-trust-mode enforce` — display severity caps overlap chains; gates use `display_summary`.

---

## What was expected (Phase 0 scope)

From [#258](https://github.com/MCP-Audit/MCTS/issues/258) and the 7-PR train:

| # | Deliverable | Expected outcome |
|---|-------------|------------------|
| PR 1 | Schema + `display.py` | Optional trust fields; helpers; **no behavior change** when off |
| PR 2 | Validator + pipeline | `validate_findings()` after enrich; `findings_trust_mode` config |
| PR 3 | Graph honesty | No fake hop/path; self-loops skipped; v2 overlap suppress |
| PR 4 | Dual summary | `report.summary` (template) + `report.display_summary` (trust) |
| PR 5 | Dashboard + terminal | Badges, sort, summary cards on display severity |
| PR 6 | Single-tool fixture | `examples/single-tool-agent-server/` regression |
| PR 7 | SARIF | `level` from display severity when trust on |

### Phase A invariants (non-negotiable)

- Do **not** mutate `finding.severity` until Phase B
- Validator is the **single** mutation point for display fields
- Stable `finding.id`; rewrite display titles only in **enforce** mode
- Legacy CI unchanged unless trust is explicitly enabled

### Target pipeline order

```
dedupe → enrich_findings → enrich_scoring_evidence → validate_findings()
  → _apply_filters → compliance (effective_severity) → score → dual summary
```

---

## What was implemented

### Core modules

| Module | Role |
|--------|------|
| `src/mcts/reporting/models.py` | Trust fields on `Finding`; `ScanReport.display_summary`; `ScanSummary.from_display()` |
| `src/mcts/reporting/display.py` | `effective_severity()`, `effective_impact()`, `is_security_finding()`, `summary_for_gates()` |
| `src/mcts/reporting/finding_validator.py` | Caps overlap chains; sets `evidence_type`, titles (enforce), strips fake path/hop |
| `src/mcts/core/scanner.py` | Validator hook; dual summary; pipeline order |
| `src/mcts/core/config.py` | `findings_trust_mode` (`off` \| `warn` \| `enforce`, default `off`) |

### Validator behavior (attack chains)

| Condition | `evidence_type` | `display_severity` | Title (enforce) |
|-----------|-----------------|--------------------|-----------------|
| Unproven overlap (incl. multi-tool) | `capability_overlap` | ≤ medium | “Potential capability overlap (…)” |
| Proven path (hop ≥ 2 or 3+ nodes) | `graph_path` | template (usually critical) | unchanged |
| Single-tool overlap | + `single_tool_overlap: true` in evidence | medium | rewritten |

Overlap evidence: `path_status: unproven`; fake `hop_count` / `path` removed.

### Graph honesty (PR 3)

| Change | Location |
|--------|----------|
| No fake `hop_count: 1` / `path: read_tools` | `scoring/evidence_tags.py` → `path_status: unproven` only |
| Self-loop edges skipped | `scoring/graph.py` (`src != dst`) |
| Overlap-only paths omitted from v2 top contributors | `scoring/engine_v2.py` `_paths_are_proven()` |

### Consumers migrated (when trust on)

| Consumer | Uses display? | Notes |
|----------|---------------|-------|
| HTML dashboard finding table, summary cards | Yes | enforce: aligned; warn: preview cards |
| Dashboard category / OWASP / technique tiles | Yes when **enforce** | Template under warn |
| Dashboard analyzer severity chips | Yes (always `effective_severity`) | Warn: can disagree with category tiles |
| Dashboard recommendations priority | Yes | |
| Dashboard score footnote | Template basis counts; enforce label | Warn adds CI note |
| Terminal dashboard (`ui/dashboard.py`) | Yes badges; summary uses `display_summary \|\| summary` | |
| Executive summary (overlap + exfil heuristics) | Yes | |
| SARIF `level`, `security-severity`, dual properties | Yes when trust on | |
| Compliance `multiple-critical` | Yes (`effective_severity`) | |
| CI gates `fail_on_critical`, `max_critical` | Yes when **enforce** | Template under warn |
| `--fail-on-category`, `min_category_score_v2` | Yes when **enforce** | Template under warn |
| `score_breakdown` | Yes when **enforce** | Template under warn |
| Machine-wide exit/export | Yes when **enforce** | Dual export: display + template counts |
| `--fail-on-priority-min` | Yes when **enforce** | Priority fields populated in warn; gate inactive |
| `--severity-filter` | Yes when **enforce** only | |
| Legacy score + v2 | Yes when **enforce** | |
| CLI `scan` | `--findings-trust-mode` | |
| REST API `POST /scan` | `findings_trust_mode` field | |

### Post-audit fixes (included)

| Fix | Description |
|-----|-------------|
| Executive exfil/shell heuristics | Skip `capability_overlap` chains; no false “exfiltration paths” paragraph |
| `_enrich_analyzer_row` | Count `effective_severity` for per-analyzer chips (always, including `warn`) |
| `build_recommendations` | Priority/impact from display severity |
| `dashboard.js` score-detail | Always uses `score.basis` counts; `warn` adds footnote that gates still use template |

### Hardening batch (2026-06 — warn / SARIF / policy)

| Fix | Location | Behavior |
|-----|----------|----------|
| `--severity-filter` enforce-only | `scanner.py`, `alternate_formats.py` | Display filter only when `findings_trust_mode == "enforce"`; `warn` uses template (aligned with gates) |
| SARIF `security-severity` alignment | `sarif.py` `_sarif_security_severity()` | Rule property follows `display_severity` when set (matches `level`; e.g. medium → `5.0`, not `9.5`) |
| Policy bool merge from YAML | `policy.py` | `enforce_bronze_facts` / `collapse_template_severity` apply when policy sets `true` and CLI still holds default `False` |
| Dashboard score footnote | `dashboard.js` | Template basis counts under `off`/`warn`; display label under `enforce`; warn clarifies CI still uses template |
| Acceptance script SARIF filter | `validate_trust_layer.py` | Filters by `properties.analyzer == "attack_chains"`; checks `security-severity` |

### Fixture and tests

| Asset | Purpose |
|-------|---------|
| `examples/single-tool-agent-server/server.py` | sa-mcp overlap regression |
| `tests/reporting/test_*.py` | Validator, scanner, gates, SARIF, dashboard payload, consistency wedge |
| `scripts/validate_trust_layer.py` | End-to-end acceptance (Phases 0–B2, policy, SARIF, B3, vulnerable regression) |

**Acceptance (single-tool + enforce):** `display_summary.critical == 0`; overlap titles honest; gates pass with `--fail-on-critical`; SARIF `level=warning` + `security-severity=5.0` for capped chains.

```bash
uv run pytest -q                                    # full suite — 728 passed (2026-06)
uv run pytest tests/reporting/ tests/scoring/ -q    # reporting + scoring focus
uv run pytest tests/scoring/test_scoring_v2_trust.py -q
uv run python scripts/validate_trust_layer.py       # acceptance harness — 0 failure(s)
```

---

## Acceptance criteria checklist (#258)

| Criterion | Status |
|-----------|--------|
| Overlap → `capability_overlap`, display ≤ medium, honest titles | Done |
| `finding.severity` unchanged; `verify()` passes | Done |
| Dual summary | Done |
| No fake hop/path fallback | Done |
| Single-tool fixture; zero display critical overlap | Done |
| Validator tests (overlap, warn, enforce) | Done |
| Executive summary honest on overlap-only | Done |
| `--fail-on-critical` default unchanged | Done |
| Gates use display when enforce | Done |

---

## What was **not** implemented (expected deferrals)

These were **explicitly out of Phase 0** — documented in the roadmap and issue #258 “Later phases”.

| Item | Planned phase | Notes |
|------|---------------|-------|
| Mutate `finding.severity` | Phase B | Still deferred — display fields only |
| Full v2 scoring on display severity | Phase B2 | **Done** — enforce mode; `finding.severity` unchanged |
| Corpus Spearman recalibration after B2 | Phase B2 | Deferred until corpus run |
| `--ci-trust` preset + GitHub Action input | PR 8 / Phase A½ | **Done** — `--ci-trust`, `findings-trust-mode`, `ci-trust` inputs |
| `fail_on_priority_min`, `min_evidence_strength` gates | Phase 2 | **Done** — CLI, API, Action, policy YAML |
| `GovernancePolicy` / `.mcts/policy.yaml` trust fields | Phase 2 | **Done** — `.mcts/policy.yaml.example` |
| Inferrer `signals[]` + facts on chains | Phase 1 / PR 10 | **Done** — inferrer signals + `evidence.facts` when trust on |
| Full 23-consumer migration | Phased | See table below |
| History/trend `display_critical` | Consumer step 12 | **Done (A½)** |
| Category tiles / OWASP badges on display | Phase A½ | **Done (A½)** |
| CLI printed finding lists on display | Phase A½ | **Done** for `mcts scan` / `mcts report`; fuzz/readiness/vet/pentest use display under trust mode |
| `severity_filter` on display severity | Consumer step 5 | **Done (A½)** |
| Legacy score + `score.basis` on display | Phase A½ narrow B | **Done (A½)** — enforce only; v2 unchanged |
| Pentest / fuzz / inventory validator | §K bypass paths | **Done** |
| `canonical_attack_graph_from_scan` early-return fix | M5 deferred | |

---

## Enforce alignment — what uses display severity

When `findings_trust_mode=enforce`, these surfaces are **aligned** with display severity:

| Surface | Mechanism | Source |
|---------|-----------|--------|
| CI gates (`--fail-on-critical`, `max_critical`) | `summary_for_gates()` → `display_summary` | `scan_gates.py`, `display.py` |
| Legacy `score.overall` + `score.basis` | `use_display_score=True` in scanner | `scanner.py`, `engine.py` |
| v2 scoring + `verify()` | `ScoringContext.use_display_severity` | `context.py`, `engine_v2.py` |
| HTML dashboard summary cards | `activeSummary()` / `display_summary` | `dashboard.js` |
| HTML category tiles / OWASP / technique map | `use_display=report_trust_enforced()` | `report/data.py` |
| Terminal dashboard badges + sort | `effective_severity()` | `ui/dashboard.py` |
| `--severity-filter` (scan + terminal) | enforce-only display filter | `scanner.py`, `alternate_formats.py` |
| SARIF `level` + rule `security-severity` | `effective_severity()` / `_sarif_security_severity()` | `sarif.py` |
| Compliance `multiple-critical` | `effective_severity()` on scorable | `compliance/checks.py` |
| Priority / bronze gates | trust pipeline fields | `trust_gates.py` |
| Pentest verdict + recommendations | display when trust ≠ off; gate summary under enforce | `pentest/runner.py` |
| Readiness `production_ready` + score | display when trust ≠ off | `readiness/runner.py` |
| History recording | `display_critical`, `display_high`, `findings_trust_mode` | `output/history.py` |
| Vet CLI labels / exit (enforce) | `vet_trust.py` | `cli/main.py` |
| `--fail-on-category` / `min_category_score_v2` | `use_display` in gate helpers | `scan_gates.py`, `report/data.py` |
| `score_breakdown` (partitions) | `score_partitioned(use_display=True)` | `partitions.py`, `scanner.py` |
| Machine-wide exit + export | `summary_for_gates` / display counts | `machine_wide.py` |

Still on **template** severity under enforce (unless `--collapse-template-severity` / B3):

| Surface | Field used | User-visible effect |
|---------|------------|---------------------|
| `summary` / raw `finding.severity` in JSON | template | Audit trail preserved; B3 opt-in collapses |

**Policy:** `--ignore-policy` skips merge; explicit `--findings-trust-mode off` blocks policy trust mode; unset bronze bools inherit from YAML; explicit CLI `False` preserved.

---

## Modes: off, warn, enforce

### Behavioral matrix (single-tool overlap fixture)

Empirical reference — `examples/single-tool-agent-server/server.py`:

| Mode | Template C | Display C | Gate C | Score | `score.basis.C` | `fail_on_critical` |
|------|------------|-----------|--------|-------|-----------------|---------------------|
| `off` | 3 | — | 3 | 21 | 3 | **FAIL** |
| `warn` | 3 | 0 | 3 | 21 | 3 | **FAIL** |
| `enforce` | 3 | 0 | 0 | 79 | 0 | **PASS** |

Vulnerable fixture under enforce retains real issues: `display_summary.critical == 3` (not overlap noise).

### Surface-by-mode

| Surface | `off` (default) | `warn` | `enforce` |
|---------|-----------------|--------|-----------|
| Display fields populated | No | Yes | Yes |
| Title rewrite (overlap chains) | No | No | Yes |
| `display_summary` | No | Yes | Yes |
| SARIF `level` from display | No* | Yes | Yes |
| SARIF rule `security-severity` from display | No* | Yes | Yes |
| `--fail-on-critical` / `max_critical` | template | **template** | **display** |
| Legacy score + `score.basis` | template | template | **display** |
| v2 scoring | template | template | **display** |
| `--severity-filter` | template | **template** | **display** |
| Dashboard summary cards | template | **display preview** | **display** |
| Dashboard score footnote counts | template | **template** (+ warn note) | display label |
| Dashboard category tiles | template | template | **display** |
| Dashboard analyzer severity chips | template* | **display** | **display** |
| `inventory` / `fuzz` / `vet` exit severity | template | **display** | **display** |
| `pentest` verdict | template | **display** (finding-level) | **display** (gate summary) |
| Compliance `multiple-critical` | template* | **template** | **display** |

\*When off, `display_severity` is unset → `effective_severity()` equals template.

**Important:** `warn` is for preview/telemetry — it does **not** relax CI gates or legacy score. SARIF in `warn` can show capped levels while `--fail-on-critical` still fails on template counts. Use **`enforce`** or **`--ci-trust`** for aligned CI.

### Consumer map (severity / summary)

| Consumer | Template | Display | Enforce-only? |
|----------|----------|---------|---------------|
| `summary_for_gates` | warn, off | enforce | Yes |
| Scan / API `gate_violations` | via above | via above | Yes |
| v1/v2 score + basis | off, warn | enforce | Yes |
| `score_breakdown` / SARIF `mcts/scoreBreakdown` | off, warn | enforce | Yes |
| `category_gate_failures` / v2 category gates | off, warn | enforce | Yes |
| SARIF `level` + `security-severity` | off fallback | warn + enforce | Partial |
| Dashboard summary cards | off | warn + enforce | Partial |
| Dashboard category tiles | off, warn | enforce | Partial |
| Dashboard analyzer chips | off | warn + enforce | Partial (warn inconsistency) |
| History `critical` | always | `display_critical` extra field | Dual |
| Machine-wide exit/export | off, warn | enforce | Yes |
| Machine-wide exit | heuristic critical/high | **gates + heuristic** | **gates + heuristic** |

---

## Alignment fixes (2026-06)

| Issue | Fix |
|-------|-----|
| Category gates under enforce | `use_display` in `scan_gates.py` |
| `score_breakdown` under enforce | `score_partitioned(..., use_display=True)` |
| Machine-wide trust | `summary_for_gates` exit + dual export fields |
| Policy `off` override | `findings_trust_mode_explicit` + `--findings-trust-mode off` (scan + auxiliary CLIs + API) |
| Policy escape hatch | `--ignore-policy` |
| Bool policy merge | `Optional[bool]` bronze flags |

---

## Open issues (deep audit 2026-06) — resolved

Items 1–8 from the June 2026 deep audits are **fixed** in-tree (see table above). Remaining by design: `warn` mode split, compliance post-trust totals, auxiliary commands without full `collect_gate_violations` (see gate scope below).

### Gate scope (auxiliary commands)

Full YAML + scan gate evaluation (`collect_gate_violations`) applies to **`mcts scan`**, **REST `POST /scan`**, **`mcts scan --machine-wide`**, and **`mcts inventory --scan-all`**. Auxiliary CLIs (`inventory` default, `vet`, `fuzz`, `readiness`, `pentest`) call **`collect_findings_gate_violations()`** for policy thresholds (`max_critical`, priority gates, etc.) plus the legacy critical/high heuristic when findings remain severe.

### Policy trust mode on auxiliary CLIs

Omitting `--findings-trust-mode` lets `.mcts/policy.yaml` set trust mode. Pass **`--findings-trust-mode off`** explicitly to block policy `enforce`, or use **`--ignore-policy`** for a one-off legacy run.

---

## Operational risks and mitigations

| Risk | Mitigation | Status |
|------|------------|--------|
| Two severities in one report confuses integrators | Export dual fields; gate on `display_*`; B3 | **Done** (enforce CI) |
| Score unchanged when display improves | Phase A½ + B2 + partition alignment | **Done** |
| SARIF/JSON consumers read `severity` only | `display_severity`, `evidence_type`, aligned `security-severity` | **Done** under trust |
| GitHub Action stays noisy | `--ci-trust`, `findings-trust-mode` input | **Done** — default still off (soak) |
| `warn` mistaken for CI relief | Docs, dashboard footnote, severity_filter enforce-only | **Done** |
| Category gates disagree with `fail_on_critical` under enforce | Wire `use_display` into category gates | **Done** |
| Machine-wide ignores trust | Align exit/export with `summary_for_gates` | **Done** |
| Policy `off` cannot override repo policy | `--ignore-policy`, explicit off | **Done** |
| Rule churn unknown to users | `rule_stability` chip | **Done** |
| Proven-path heuristic too loose | Roadmap §L; tighten edge validation | Documented only |

### Follow-up issues (revised PR train — post external review)

| PR | Phase | Focus |
|----|-------|-------|
| **8–9** | **A½ Consistency** | ✅ Action, `--ci-trust`, CLI/history, score basis, maturity chip |
| **10** | Phase 1 | inferrer `signals[]`, facts |
| **11** | Phase 1.5 | `rule_stability`, FindingBuilder |
| **12** | Phase 2 | `priority_score` gates, policy YAML |
| **13** | Phase B2 | ✅ v2 display severity + chain factors; corpus recalibration deferred |

Legacy mapping: old “PR 8” CI trust is now **PR 8–9 (Phase A½)**; provenance is **PR 10+**.

---

## How to use

### Local / CI (honest overlap handling)

```bash
# Dashboard + gates use display severity; overlap chains capped to medium
mcts scan examples/single-tool-agent-server/server.py \
  --findings-trust-mode enforce \
  --fail-on-critical

# Legacy behavior (default) — unchanged
mcts scan examples/single-tool-agent-server/server.py --fail-on-critical
# → exits 1 (template critical)
```

### Governance policy merge

`merge_scan_config_with_policy()` fills **unset CLI defaults** from `.mcts/policy.yaml` before the scan runs:

| Policy field | Merged when |
|--------------|-------------|
| `findings_trust_mode` | CLI is still `off` (see caveat below) |
| `max_critical`, `min_score`, priority/v2 gate fields | CLI value is `None` / unset |
| `enforce_bronze_facts`, `collapse_template_severity` | Policy `true` and CLI still default `False` |
| `min_category_score_v2` | CLI dict empty and policy non-empty |

**Caveats:**

- **`findings_trust_mode=off` without `--findings-trust-mode` on CLI** is treated as unset — policy can still set `enforce`. Use **`--findings-trust-mode off`** (explicit) or **`--ignore-policy`** for a one-off legacy scan.
- **Bool flags** (`enforce_bronze_facts`, `collapse_template_severity`): unset (`None`) inherits policy `true`; explicit CLI `False` is preserved.
- **`warn` and `enforce` on CLI** always override policy trust mode when set explicitly.

Post-scan gates use **`collect_gate_violations()`** — scan gates on the merged `ScanConfig` plus YAML allowlist/blocklist only (no duplicate numeric thresholds).

Copy `.mcts/policy.yaml.example` → `.mcts/policy.yaml` to opt in without repeating flags on every scan.

### API

```json
{
  "target": "examples/single-tool-agent-server/server.py",
  "findings_trust_mode": "enforce",
  "findings_trust_mode_explicit": false,
  "fail_on_critical": true,
  "fail_on_category": {"attack_chains": 10},
  "max_critical": 0,
  "ignore_policy": false
}
```

### JSON fields (integrators)

| Field | Meaning |
|-------|---------|
| `finding.severity` | Template severity (scoring, legacy) |
| `finding.display_severity` | Trust-adjusted (null when off) |
| `finding.evidence_type` | `capability_overlap` \| `graph_path` \| null |
| `summary` | Template counts |
| `display_summary` | Display counts (null when off) |

**Rule:** When `findings_trust_mode=enforce`, gate and triage on `display_summary` / `display_severity`, not `summary.critical` alone.

### SARIF

| Field | Source |
|-------|--------|
| `level` | `effective_severity()` (display when trust on and `display_severity` set) |
| `properties.severity` | Template (legacy audit trail) |
| `properties.display_severity` | Display |
| `properties.evidence_type` | When set (`capability_overlap`, `graph_path`, …) |
| Rule `properties.security-severity` | Display-aligned when `display_severity` set; else `impact` fallback |
| `mcts/facts`, `mcts/factCount` | When provenance present |

Under **enforce** on overlap fixture: chain results have `level=warning` (medium) and rule `security-severity=5.0` (not `9.5` from template critical).

Under **warn**: SARIF levels are capped but `--fail-on-critical` still uses template counts — do not use warn for CI + SARIF upload together unless you understand the split.

---

## Code map

| Area | Path |
|------|------|
| Validator | `src/mcts/reporting/finding_validator.py` |
| Display helpers | `src/mcts/reporting/display.py` |
| Scanner pipeline | `src/mcts/core/scanner.py` (~219–283) |
| Dashboard payload | `src/mcts/report/data.py` |
| Dashboard JS | `src/mcts/report/assets/dashboard.js` |
| Terminal UI | `src/mcts/ui/dashboard.py` |
| SARIF | `src/mcts/reporting/sarif.py` |
| Gates | `src/mcts/governance/scan_gates.py` |
| Trust gates (priority) | `src/mcts/reporting/trust_gates.py` |
| Evidence provenance | `src/mcts/reporting/evidence_provenance.py` |
| Rule stability | `src/mcts/reporting/rule_stability.py` |
| FindingBuilder SDK | `src/mcts/reporting/finding_builder.py` |
| V2 scoring (B2) | `src/mcts/scoring/context.py`, `engine_v2.py`, `chains.py`, `factors.py` |
| Config / CLI / API | `config.py`, `cli/main.py`, `api/app.py` |
| Fixture | `examples/single-tool-agent-server/server.py` |
| Tests | `tests/reporting/`, `tests/scoring/test_scoring_v2_trust.py` |

---

## Verification

### Automated

```bash
uv run pytest -q                                    # full suite — 728 passed (2026-06)
uv run pytest tests/reporting/ tests/scoring/ -q    # reporting + scoring focus
uv run pytest tests/scoring/test_scoring_v2_trust.py -q
uv run python scripts/validate_trust_layer.py       # acceptance harness — 0 failure(s)
```

### Acceptance script coverage (`validate_trust_layer.py`)

| Section | Checks |
|---------|--------|
| Phase 0 | Single-tool overlap; display critical 0; template preserved; overlap evidence |
| Policy | Example YAML merge; gate summary; CLI warn overrides policy enforce |
| Phase 1 | Facts, confidence_factors, counterfactual; dashboard provenance |
| Phase 1.5 | `rule_stability` on compliance vs chains |
| Phase 2 | Priority scores; Option B gate; bronze threshold |
| Phase B2 | v2 present; `use_display_severity`; verify |
| Gates | `fail_on_critical` pass/fail enforce vs off |
| SARIF | Level, `security-severity`, facts |
| Validator | Empty `finding_ids` does not prove path |
| Phase 3 | Taint/live tags; live_proxy; priority boost; v2 `evidence_quality_factor` |
| Alignment | Category gates; score breakdown; explicit policy off |
| B3 | Collapse copies display into severity |
| Regression | Vulnerable fixture completes; v2 verify |

### Acceptance script gaps (not yet checked)

None — B3 full pipeline (gates + breakdown post-collapse) covered in `validate_trust_layer.py` and `tests/reporting/test_runtime_evidence.py`.

Warn E2E (SARIF level, `security-severity`, gate exit divergence, dashboard category tiles) is covered by `tests/reporting/test_consistency_wedge.py`. Machine-wide and inventory `--scan-all` gates are covered by unit tests. Optional analyzer skip rows (npm, yara, cloud, LLM, VT) are covered by `tests/analyzers/test_optional_analyzer_skips.py`. Hop-count-only and evidence-path-only proven bypasses — `tests/reporting/test_finding_validator.py`. Auxiliary explicit-off policy override — `tests/governance/test_trust_alignment_fixes.py`.

### Manual spot-checks

```bash
# Enforce overlap — gates pass, display critical 0
mcts scan examples/single-tool-agent-server/server.py \
  --findings-trust-mode enforce --fail-on-critical

# Legacy — exits 1 on template critical
mcts scan examples/single-tool-agent-server/server.py --fail-on-critical

# Warn wedge — SARIF capped, gates still fail on template
mcts scan examples/single-tool-agent-server/server.py \
  --findings-trust-mode warn --fail-on-critical

# Category gate — passes under enforce on overlap fixture
mcts scan examples/single-tool-agent-server/server.py \
  --findings-trust-mode enforce --fail-on-category attack_chains:10
```

### Test coverage (alignment + Phase 3)

| Test module | Purpose |
|-------------|---------|
| `tests/governance/test_trust_alignment_fixes.py` | Category gates, breakdown, machine-wide, policy escape |
| `tests/reporting/test_runtime_evidence.py` | Runtime validation tags, priority boost |
| `tests/scoring/test_runtime_evidence_scoring.py` | v2 risk-range tightening on validated live/taint |
| `tests/analyzers/test_finding_builder_adoption.py` | Bronze facts on migrated analyzers |

---

## FindingBuilder / bronze adoption

### On `build_analyzer_finding` / `FindingBuilder` (33 paths)

All mature analyzers including optional/metadata-heavy paths (`npm_audit`, `vulnerable_package`, `metadata_diff`, `oauth_config`, `cloud_inspect`, `virustotal`, `runtime_events`, `skill_md`, `sigma_metadata`, `yara_metadata`, `llm_judge`, `llm_metadata_triage`) plus core security + behavioral + cross_server via `finding_facts.py`, **`attack_chains`**, **`supply_chain`**, **`toxic_flows`**, **`semgrep_adapter`**.

### Still raw `Finding()` outside analyzers

Compliance meta-findings use `build_hygiene_finding()` with `finding_kind=coverage` (bronze facts, excluded from security gates). Readiness heuristics, OPA, LLM judge, live/static discovery meta, and protocol probe emit bronze facts via `build_hygiene_finding`. **`fuzz/classifier.py` is migrated** — fuzz findings emit bronze `evidence.facts` via `build_analyzer_finding`. The bronze gate applies only to **`experimental`** analyzers when `--enforce-bronze-facts` is set.

Vulnerable fixture under enforce: **100%** of security findings have `evidence.facts`; **3 display critical** remain (real issues, not overlap noise).

---

## Phase 3 — runtime / taint validation

When trust is **warn** or **enforce**, `validate_runtime_evidence()` runs after the validator:

| Signal | `runtime_validation` | `finding_type` | Priority boost |
|--------|---------------------|----------------|----------------|
| Behavioral taint param → sink | `taint_param_sink` | `validated` | +15; strength → strong when applicable |
| Description vs handler mismatch | `description_mismatch` | `validated` | +10 |
| Jailbreak live probe accepted | `live_probe` | `validated` | +12 |
| Runtime telemetry (`runtime_events`) | `live_proxy` | `validated` | +12 |

Schema-derived runtime rows (`schema-*` ids) are **not** tagged as live proxy.

**v2 scoring:** Validated findings also set `evidence.risk_tags` where applicable (`live_probe`, `handler_traced`). `evidence_quality_factor()` narrows v2 risk range (0.8× spread) when validated live/taint evidence is present — see `scoring-spec-v2.md`.

**Priority gates:** `--fail-on-priority-min` is active only under **`enforce`** (aligned with severity gates). Fields are still populated in `warn` for preview/export.

**Bronze gate:** `--enforce-bronze-facts` is active only under **`enforce`**.

**`max_high` / `max_critical`:** Merged from `.mcts/policy.yaml` into `ScanConfig`; enforced via `scan_gates` (display counts under enforce). REST API exposes `max_critical`, `max_high`, and optional `enforce_bronze_facts` (null inherits policy). Machine-wide scans call `collect_gate_violations()` per server plus legacy critical/high heuristic when no explicit gate fires.

**`require_auth_env_for_sensitive`:** When `true` in policy (merged into `ScanConfig`), gates fail if `--enable-llm-judge`, `--enable-llm-triage`, `--enable-cloud-inspect`, or `--enable-virustotal` is set without the corresponding `MCTS_*_API_KEY` env vars.

**Compliance rows:** Emitted post-trust with `finding_kind=coverage` — excluded from priority/bronze security gates via `is_security_finding()`.

---

## Phase B2 — v2 scoring on display severity

When `findings_trust_mode=enforce`, v2 scoring reads **display** severity for:

| Component | Behavior |
|-----------|----------|
| `base_risk()` / `ScoreV2Basis` counts | `severity_for_scoring(..., use_display=True)` |
| `classify_business_impact()` | Falls back to display severity when no explicit hints |
| `resolve_chain_factors()` | Skips unproven paths (`path_is_proven`) |
| `build_top_contributors()` | Omits overlap-only attack-chain rows |

`finding.severity` (template) is **unchanged** — `RiskScoringEngineV2.verify()` still passes.

Corpus Spearman gate passes at ρ=0.955 (maintainer `--write-package-stats` optional).

---

## Maintenance / soak

Shipped in-tree:

- Shared `apply_trust_layer()` for scan, fuzz, and inventory entry points
- Bronze CI gate (`--enforce-bronze-facts`) for experimental analyzers without `evidence.facts` (**enforce only**)
- All `src/mcts/analyzers/` paths on `FindingBuilder` / bronze facts
- SARIF excludes `finding_kind=coverage` by default (`build_sarif(..., include_coverage_findings=True)` to export)
- GitHub Action `ci-trust` defaults to `true`
- Hygiene bronze facts on readiness / live/static discovery / protocol probe paths

**Next:** persona tabs; counterfactual on inferrer-only paths without bronze facts; ramp corpus QA.

### Gap fixes (pre-Phase 3)

| Gap | Status |
|-----|--------|
| FindingBuilder in mature analyzers | **Done** — all analyzer paths (see [adoption](#findingbuilder--bronze-adoption)) |
| Pentest / readiness trust pipeline | **Done** — fuzz rows + readiness notes; warn display parity for verdict + recommendations + readiness score |
| Fuzz / inventory trust | **Done** (prior slice) |
| API policy loader | **Done** — `_merge_policy()` on REST scan/readiness |
| Global weak-evidence caps | **Done** — thin evidence + low confidence → `weak` |
| B2 residual template paths | **Done** — disagreement factor + readiness score use display when trust ≠ off |
| Vet trust pipeline | **Done** — `vet_trust.py` + CLI `--findings-trust-mode` |
| Phase 3 runtime/taint validation | **Done** — tags, priority boost, v2 `evidence_quality_factor` wire-up |
| Mutate `finding.severity` (B3) | **Opt-in** — `--collapse-template-severity` under enforce |
| Hardening: warn/SARIF/policy | **Done** — see [hardening batch](#hardening-batch-2026-06--warn--sarif--policy) |
| Category gates under enforce | **Done** |
| `score_breakdown` under enforce | **Done** |
| Machine-wide under enforce | **Done** |
| Policy explicit `off` + `--ignore-policy` | **Done** |
| Policy bool explicit-False | **Done** (`Optional[bool]`) |
| `warn` gate vs display split | **By design** — see [modes](#modes-off-warn-enforce) |

### Priority fix order (maintainers) — completed 2026-06

1. ~~Category gates + v2 category gates~~
2. ~~`score_partitioned(findings, use_display=...)`~~
3. ~~Machine-wide display alignment~~
4. ~~Policy escape hatch + explicit `off`~~
5. ~~Bool policy merge~~
6. ~~Extend `validate_trust_layer.py`~~ — category/breakdown/explicit-off, Phase 3 risk tags (done)

---

## Related

- [#258 — Phase 0 feature issue](https://github.com/MCP-Audit/MCTS/issues/258)
- [Interpreting findings](interpreting-findings.md) — user-facing overlap explanation
- [CI integration](../platform/ci-integration.md) — trust modes, history/trends, SARIF
- [Scoring developer guide](scoring-guide.md) — v2 uses display severity when trust enforce (B2)
