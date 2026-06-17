# MCTS Feature Expansion Plan

> [Documentation](../index.md) → [More](README.md)

> **Using MCTS to scan servers?** This document is for **contributors and maintainers**. Start with [Getting started](../get-started/getting-started.md) instead.

This is the **detailed implementation guide** for evolving MCTS from an alpha scanner to a full MCP security platform.

**Related:** [Product Roadmap](roadmap.md) · [Architecture](../analysis/architecture.md) · [CLI Reference](../platform/cli.md)

### User documentation map

| Topic | Guide |
|-------|-------|
| Install and first scan | [getting-started.md](../get-started/getting-started.md) |
| Live probe, fuzz, inventory, TS discovery | [scanning/](../scanning/README.md) |
| Pipeline and analyzers | [analysis/architecture.md](../analysis/architecture.md) |
| Scoring, taxonomy, HTML dashboard | [reporting/](../reporting/README.md) |
| CLI and CI | [platform/](../platform/README.md) |
| Term definitions | [glossary.md](../glossary.md) |
| Full doc index | [index.md](../index.md) |

---

## Part 1 — Current State (Honest Inventory)

### Shipped and real

| Layer | Files | What actually works |
|-------|-------|---------------------|
| **Orchestration** | `core/scanner.py`, `core/config.py` | 20+ analyzers → compliance → scoring → `ScanReport` |
| **Discovery** | `discovery/*`, `mcp/client.py` | Multi-file Python + TypeScript static discovery; live stdio + HTTP/SSE merge |
| **Analyzers** | `analyzers/*.py` | Metadata, SAST, 20+ runtime sub-detectors, Sigma, OAuth, supply chain |
| **Attack graph v3** | `scoring/attack_graph_builder.py`, `scoring/templates/` | YAML template matcher + `GraphBuilder`; 12 chain templates; capability overlap fallbacks |
| **Scoring** | `scoring/engine.py`, `engine_v2.py`, `graph.py`, `chains.py` | Legacy exponential + v2 multi-factor (`absolute_risk`), corpus calibration, dual default `both` |
| **Compliance** | `compliance/checks.py` | OWASP LLM meta-findings |
| **CLI** | `cli/main.py` | `scan`, `report`, `inventory`, `fuzz`, `readiness`, `serve`, `vet`, `pentest`, `doctor`, `snapshot`, `scan-mcp`; `mcts-mcp` server mode |
| **Terminal UI** | `ui/*` | Rich themes, progress, report renderer, `--terminal-format` |
| **HTML dashboard** | `report/*`, `reporting/html.py` | Full executive UI from JSON |
| **REST API** | `api/app.py` | FastAPI — 10 endpoints (`--extra api`) |
| **Tests** | `tests/` | 350+ tests incl. technique regression (79 techniques) |
| **CI** | `action/action.yml`, `.github/workflows/ci.yml` | SARIF scan validation; Action `@v1` published |

### Remaining gaps (honest)

- `PromptInjectionAnalyzer` — heuristic metadata patterns; live payload injection not sent
- `JailbreakAnalyzer` — weighted manipulation score heuristic; not live agent red-teaming
- Scan history / HTML trend chart — **shipped** (`mcts_analysis/history.json`)
- Remote protocol fuzz — `mcts fuzz` is stdio-only; `--url` fuzz planned
- HTML Capability Matrix + Technique Map — planned dashboard sections
- Expanded behavioral eval corpus — growing; full 100+ handler parity still in progress
- Deep multi-language CFG/taint — tree-sitter today; full 10-language cross-file taint partial

### Architectural strengths to preserve

1. **Attack-chain-first threat model** — core differentiator
2. **Auditable exponential scoring** — extend with category gates
3. **HTML executive dashboard** — feed it better data
4. **Local-first, deterministic default** — no cloud API dependency
5. **Modular `BaseAnalyzer`** — natural extension point

---

## Part 2 — Industry Capabilities → MCTS Equivalents

| Industry capability | MCTS equivalent (original design) | Priority |
|----------------------|---------------------------------------|----------|
| Live MCP handshake | `ProbeSession` + `LiveDiscovery` | P0 |
| Client config discovery | `mcts inventory` | P1 |
| Multi-file / repo scan | `ScanTarget` (repo, not file) | P0 |
| Source-level SAST | `SourceAnalyzer` (AST, not regex-only) | P0 |
| Tool description poisoning | `MetadataIntegrityAnalyzer` | P0 |
| Schema poisoning (FSP) | `SchemaSurfaceAnalyzer` | P1 |
| Tool shadowing | `CrossServerAnalyzer` (config mode) | P1 |
| Toxic capability labels | `CapabilityProfile` per tool | P1 |
| Behavioral doc vs code mismatch | `ImplementationDriftAnalyzer` | P2 |
| Rug-pull / baseline diff | `ManifestBaselineStore` | P2 |
| Supply chain / deps | `DependencyPostureAnalyzer` | P2 |
| Package pre-install scan | `mcts vet <package>` | P0 — shipped |
| MCTS threat taxonomy | `technique_id` + `mitigation_ids` on `Finding` | P1 — shipped |
| SARIF / CI gates | `reporting/sarif.py` + published Action | P0 — shipped |
| REST API | `mcts serve` (optional) | P1 — shipped |
| MCP server mode | `mcts-mcp` stdio tools | P0 — shipped |
| LLM semantic review | `--llm-judge`, `--llm-triage` (opt-in) | P1 — shipped |
| Semgrep SAST + Java | `--semgrep` adapter | P0 — shipped |
| Skills scanning | `mcts inventory --skills` | P0 — shipped |
| Machine-wide scan | `mcts scan --machine-wide` | P0 — shipped |
| Fuzzing | `mcts fuzz` (protocol probes) | P2 — shipped |
| Config red-team | `mcts audit-config` (dry-run) | P2 |
| Benchmark corpus | `examples/` + `benchmarks/expected/` | P1 |
| Trend / history | `mcts_analysis/history.json` | Shipped in HTML |

---

## Part 3 — Target Architecture

Evolve from “single-file static parser” to a **three-layer pipeline**:

```
┌─────────────────────────────────────────────────────────────────┐
│                        ScanTarget                                │
│  (file | repo | config | live_command | remote_url)              │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Discovery Layer                              │
│  StaticDiscovery │ LiveDiscovery │ ConfigDiscovery             │
│  → MCPServerInfo (tools, prompts, resources, instructions, code) │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Analysis Layer                               │
│  Metadata │ Source │ Capability │ Chains │ Compliance │ Policy │
└────────────────────────────┬────────────────────────────────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Output Layer                                 │
│  ScanReport → JSON │ SARIF │ HTML │ Markdown │ CI gate           │
└─────────────────────────────────────────────────────────────────┘
```

### Extended core types

```python
# mcts/mcp/models.py — extend MCPServerInfo
class MCPTool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)
    source_file: str | None = None
    source_line: int | None = None
    handler_snippet: str | None = None
    capability: CapabilityProfile | None = None

class CapabilityProfile(BaseModel):
    reads_untrusted_input: bool = False
    accesses_sensitive_data: bool = False
    mutates_state: bool = False
    egresses_network: bool = False
    executes_commands: bool = False

class Finding(BaseModel):
    # ... existing fields ...
    technique_id: str | None = None      # e.g. "MCTS-T-1001"
    mitigation_ids: list[str] = []
    cwe_id: str | None = None
    confidence: float = 1.0
    location: SourceLocation | None = None
```

Use **`MCTS-T-*`** (MCTS Technique) as the taxonomy namespace — cross-referenced optionally to external frameworks in metadata, not copied dossiers.

---

## Part 4 — Phased Implementation

### Phase 0 — Foundation (2–3 weeks)

Fix structural limits before adding features.

#### 0.1 Multi-file repository scanning

**Why:** Serious scanners analyze repos, not one entrypoint.

**How:**

1. Add `ScanTarget` in `core/target.py` with `kind: file | directory | config | live`
2. Add `src/mcts/discovery/static.py` — walk repo, find `@tool` patterns
3. Discovery rules: files containing `@tool`, `mcp.tool`, `FastMCP`, `Server("mcp")`; skip `tests/`, `venv/`, `.git/`
4. Extend `ScanConfig` with `scope`, `include_globs`, `exclude_globs`, `max_file_bytes`
5. **CLI:** `mcts scan ./my-mcp-server/` (directory)

**Tests:** Fixture repo with tools in `handlers/tools.py` + entrypoint in `server.py`.

#### 0.2 Parse `input_schema` and source context

**How:**

1. AST extract function args + type hints → minimal JSON Schema
2. Store `handler_snippet` (capped 80 lines) for source analyzers
3. New **`SchemaSurfaceAnalyzer`** — suspicious defaults, credential param names, missing `required` on dangerous params → `MCTS-T-1001.002`

#### 0.3 Source-aware analyzers

**How:**

1. Add `SourceContext` to `MCPServerInfo` (`files: dict[str, str]`)
2. Refactor `DataLeakageAnalyzer` to scan all files with line-level `location`
3. Add **`CommandExecutionAnalyzer`** — AST for `subprocess`, `os.system`, `eval`; tie to nearest `@tool`
4. Add **`PathValidationAnalyzer`** — missing path canonicalization in file handlers
5. Static findings: `confidence: 0.7`; live-probed: `1.0`

#### 0.4 Fix placeholder analyzers

**PromptInjectionAnalyzer:** Unicode/hidden chars, instruction-like imperatives, description vs handler mismatch.

**JailbreakAnalyzer:** Weighted manipulation surface (tool count, executes_commands, missing schema, chain edges).

**Attack graph v3 (`GraphBuilder`):** Merge producer edges, apply policy edges, match YAML chain templates (read→exfil, SSRF resource staging, URL elicitation, etc.); store paths on `ScanReport.attack_graph`. Legacy capability-overlap findings remain as trust-capped fallbacks via `capability_overlap.py`.

---

### Phase 1 — Adoption & Live Probing (4–6 weeks)

#### 1.1 Live MCP discovery (`ProbeSession`)

**How:**

1. `src/mcts/probe/session.py` — async stdio connect, `list_tools`, `list_prompts`, `list_resources`, `get_instructions`
2. `LiveDiscovery` same interface as `StaticDiscovery`
3. **CLI:**
   ```bash
   mcts scan ./server.py                    # static (default)
   mcts scan --live --command uv --args run,server.py
   mcts scan --config ~/.cursor/mcp.json --server my-server
   ```
4. Consent gate + CI bypass: `--i-understand-live-risk`
5. Merge static + live in `Scanner`; live enriches schemas

#### 1.2 `mcts inventory`

**How:**

1. `src/mcts/inventory/discoverers/` — Cursor, Claude Desktop, VS Code
2. ```bash
   mcts inventory
   mcts inventory --scan
   mcts inventory --scan --server X
   ```
3. **`CrossServerAnalyzer`** — Levenshtein tool name collisions, cross-server description refs → `MCTS-T-1008`

#### 1.3 Capability profiles

**How:**

1. `src/mcts/capability/inferrer.py` — rule-based `CapabilityProfile` from name, description, schema, handler
2. Extend attack chains: `reads_untrusted_input + egresses_network` → CRITICAL
3. HTML dashboard: Capability Matrix page

#### 1.4 SARIF output

**How:**

1. `src/mcts/reporting/sarif.py` — SARIF 2.1.0 mapping
2. ```bash
   mcts scan ./server.py -o report.sarif --format sarif
   ```

#### 1.5 CI scorecard + gates

**How:**

1. `ScanConfig`: `min_score`, `max_critical`, `fail_on_categories`
2. Expose `CATEGORY_DEFS` scores in CLI
3. Publish GitHub Action (`uses: MCP-Audit/MCTS@v1`), upload SARIF + HTML

#### 1.6 MCTS technique taxonomy (`MCTS-T-*`)

**How:**

1. `src/mcts/taxonomy/techniques.yaml`
2. Analyzers assign `technique_id` on `Finding`
3. HTML: Technique Map section
4. Link to external frameworks in `evidence`, do not vendor third-party technique corpora

#### 1.7 Benchmark corpus

**How:**

1. Expand `examples/bench/` with technique-specific servers
2. `benchmarks/expected/<server>.json` with `required_findings`, `score_range`
3. `tests/test_benchmarks.py` regression suite
4. Document weights in `docs/reporting/scoring-spec.md`

---

### Phase 2 — Differentiation (6–10 weeks)

#### 2.1 `mcts fuzz`

- Read-only probes by default; `--fuzz-level safe|standard|aggressive`
- Malformed handshake, traversal tool names, oversized params
- Classify stack traces, path echoes, dangerous successes
- `analyzer: "fuzz"`

#### 2.2 `mcts audit-config`

- Parse `mcpServers` JSON; static checks (secrets in env, broad filesystem paths, `npx -y` risk)
- Optional `--probe` with consent; no LLM agent tool invocation

#### 2.3 Rug-pull baselines

```bash
mcts scan --record-baseline -o .mcts/baseline.json
mcts scan --check-baseline .mcts/baseline.json
```

#### 2.4 `ImplementationDriftAnalyzer`

- Compare description claims vs handler signals (subprocess, open, httpx)
- Optional `--llm-confirm` for mismatches only (opt-in)

#### 2.5 TypeScript / JavaScript static discovery

- `discovery/static_js.py` — `server.tool(`, `setRequestHandler` patterns
- `ScanConfig.languages: ["python", "typescript"]`

#### 2.6 Report history + trend

- Append scans to `mcts_analysis/history.json` (**shipped**)
- HTML trend sparkline + table (**shipped**)
- Standalone `mcts trend ./server.py` CLI — planned

---

### Phase 3 — Platform (10+ weeks)

| Feature | Command / module |
|---------|------------------|
| Package supply chain | `mcts vet pypi:…` / `npm:…` |
| Local REST API | `mcts serve` (FastAPI, optional extra) |
| MCP server mode | `mcts-mcp` — `scan_mcp_target`, `explain_finding`, `compare_baselines` |
| Opt-in LLM review | `mcts scan --llm-review` (never required for CI) |
| Security baselines | `mcts scan --profile strict\|balanced\|dev` |
| Certification badges | `mcts badge report.json -o mcts-badge.svg` |

---

## Part 5 — Module Layout (Additive)

```
src/mcts/
├── discovery/
│   ├── static.py
│   ├── static_js.py
│   ├── live.py
│   └── config.py
├── probe/
│   ├── session.py
│   ├── stdio.py
│   └── consent.py
├── inventory/
│   ├── runner.py
│   └── discoverers/
├── capability/
│   └── inferrer.py
├── analyzers/
│   ├── schema_surface.py
│   ├── metadata_integrity.py
│   ├── command_execution.py
│   ├── path_validation.py
│   ├── implementation_drift.py
│   ├── cross_server.py
│   └── dependency_posture.py
├── fuzz/
│   └── runner.py
├── taxonomy/
│   ├── techniques.yaml
│   └── mapper.py
├── policy/
│   └── profiles.yaml
├── reporting/
│   ├── sarif.py
│   └── markdown.py
├── baseline/
│   └── store.py
└── api/                    # optional extra
    └── server.py
```

---

## Part 6 — Documentation to Add/Update

| Doc | Status |
|-----|--------|
| `docs/reporting/scoring-spec.md` | Shipped |
| `docs/reporting/taxonomy.md` | Shipped |
| `docs/scanning/live-scanning.md` | Shipped |
| `docs/scanning/inventory.md` | Shipped |
| `docs/platform/ci-integration.md` | Shipped |
| `docs/more/product-positioning.md` | Shipped |
| `docs/more/external-frameworks.md` | Shipped |
| `docs/analysis/architecture.md` | Updated — discovery, probe, analyzer list |
| `docs/platform/cli.md` | Updated — all commands and flags |
| `docs/more/roadmap.md` | Aligned with Phases 0–3 |
| `docs/scanning/fuzzing.md` | Shipped |
| `docs/scanning/typescript-discovery.md` | Shipped |
| `docs/index.md` | Section hub and navigation |
| `action/README.md` | Shipped |

---

## Part 7 — Dependencies

| Extra | Packages | Used for |
|-------|----------|----------|
| `mcp` (existing) | `mcp>=1.27` | Live probe |
| `sarif` | `jsonschema` | SARIF validation |
| `fuzz` | stdlib + mcp | Protocol fuzz |
| `api` | `fastapi`, `uvicorn` | REST server |
| `js` | `tree-sitter-typescript` (optional) | TS discovery |

Keep **core install lean** — live/fuzz/api behind extras.

---

## Part 8 — What NOT to Build

| Feature | Why skip or defer |
|---------|-------------------|
| Cloud-only analysis API as default | Violates local-first; privacy |
| Agent Guard runtime hooks | Different product (runtime monitoring); partner with gateways |
| Gamification / closed-core scanner | Distraction from security depth |
| LLM red-team config narratives | Non-deterministic; use `audit-config` instead |
| 1,700-rule general SAST | Stay MCP-boundary focused |
| Content moderation rules | Noise for MCP security |
| Full external technique corpus vendoring | Link + map IDs only |
| Public trust registry as core product | Different product surface; optional OSS feed only |
| Runtime MCP gateway / ACL enforcement | Different layer — export SARIF + events instead |
| Full blast-radius control plane | Integrate AI-BOM export; don't rebuild fleet governance |

---

## Part 9 — Build Order

```
Week 1-2:  Phase 0.1–0.4 (repo scan, source analyzers, fix placeholders, attack graph)
Week 3-4:  Phase 1.4–1.5 (SARIF, CI gates, publish Action)
Week 5-6:  Phase 1.1 (live stdio probe)
Week 7-8:  Phase 1.2–1.3 (inventory, capability profiles, cross-server)
Week 9-10: Phase 1.6–1.7 (MCTS-T taxonomy, benchmarks)
Week 11+:  Phase 2 (fuzz, audit-config, baselines, drift, TS discovery)
```

**First PR bundle (highest impact, lowest risk):**

1. Repo-wide static discovery
2. Source-aware `DataLeakageAnalyzer` + `CommandExecutionAnalyzer`
3. SARIF + `--min-score`
4. Attack graph fix in `report/data.py`

---

## Part 10 — Success Criteria

- [x] CI can gate on score/SARIF without cloud APIs
- [x] Scan works on a **repo**, not one file
- [x] Live stdio + remote HTTP/SSE probe enriches tool schemas (optional, consented)
- [x] Config inventory detects cross-server shadowing
- [x] Findings carry `technique_id`, `location`, `confidence`
- [x] Attack chains use capability graph, not keyword hints
- [x] `--fail-on-category` category gates for CI
- [x] `mcts fuzz` safe read-only protocol probes (stdio)
- [x] REST API (`mcts serve`) with per-surface scan endpoints
- [x] HTML dashboard trend + capability matrix from real data
- [ ] Benchmark suite expanded beyond 79 technique fixtures
- [ ] `mcts audit-config` replaces stub with safe, deterministic behavior
- [ ] Remote protocol fuzz (`mcts fuzz --url`)
- [x] Semgrep SAST adapter + Java (`--semgrep` extra)
- [x] Skills / `SKILL.md` inventory scanning
- [x] Repository instruction discovery (`SKILL.md`, `*prompt*.md`, `system_prompt.md` on static scans)
- [x] MCP server mode (`mcts-mcp`) with `scan_mcp_target`, `explain_finding`
- [x] Package vetting (`mcts vet`)
- [x] Structured pentest (`mcts pentest`)
- [x] Machine-wide scan (`mcts scan --machine-wide`)
- [x] LLM metadata triage (`--llm-triage`)
- [x] Governance YAML policies (`--policy`)
- [ ] CycloneDX / AI-BOM export from inventory + findings
- [ ] Interactive attack-graph HTML dashboard
- [ ] Runtime stdio proxy with inline detectors (opt-in extra)
- [ ] Governance YAML policies beyond readiness OPA

---

## Part 11 — Prioritized backlog

Prioritized themes from the **240-item gap backlog** (213 actionable + 27 already shipped). Maintainers track detailed cross-tool mappings in a **local-only** audit (not published in this repo).

### P0 — Must close for core MCP scanner completeness

| ID theme | Deliverable | Status | Module / CLI |
|----------|-------------|--------|--------------|
| Per-technique MCTS-T scan | `--technique MCTS-T-xxxx` | Shipped | `cli/`, `taxonomy/technique_mode.py` |
| Semgrep taint backend | Optional `--semgrep`; Java rules included | Shipped | `analyzers/semgrep_adapter.py` |
| Skills scanning | `skill_md` on `mcts scan` + `mcts inventory --skills` | Shipped | `discovery/instruction_files.py`, `inventory/`, `analyzers/skill_md.py` |
| Repo instruction discovery | Markdown prompts/instructions under scan target | Shipped | `discovery/instruction_files.py`, `--discover-instructions` |
| Machine-wide scan | Default scan all well-known client configs | Shipped | `scan/machine_wide.py`, `cli/` |
| Pre-install vet | `mcts vet pypi:pkg` / `npm:pkg` / `oci:` | Shipped | `vet/` |
| MCP server mode | `mcts-mcp` stdio tools for IDE agents | Shipped | `mcp_server/` |
| Behavioral SAST depth | 10-language CFG + doc/code alignment | Partial | `analyzers/behavioral_static.py`, `sast/` |
| Prompt firewall / action gate | BLOCK/WARN on tool calls (MCP server or hook) | Missing | optional `guard/` |
| Fleet / Evo integration | Document defer or minimal upload API | Missing | `enterprise/` |

### P1 — Differentiation + enterprise readiness

| ID theme | Deliverable | Notes |
|----------|-------------|-------|
| CycloneDX AI-BOM | `mcts inventory --format cyclonedx` | SPDX / CycloneDX from inventory + findings |
| Attack graph UI | HTML force-directed graph from `ScanReport.attack_graph` | Interactive dashboard page |
| Cross-server hitting-set | Minimum server set to break all paths | Graph analytics on inventory |
| Git-aware config diff | `mcts diff` for MCP JSON + PR comment format | PR CI workflow |
| Governance YAML | Approved servers, score thresholds, custom rules | Beyond readiness OPA |
| IDE extension scan | VSIX / marketplace risk checks | Extension manifest audit |
| Shadow MCP discovery | Unknown servers vs allowlist | Fleet hygiene |
| OWASP MCP Top 10 10/10 | Full category map in SARIF + terminal | Complete category coverage |
| Runtime stdio proxy | Optional inline detectors on JSON-RPC | Opt-in extra |
| LLM review agent | `mcts review` / cr-agent | Dedicated review CLI |
| Expanded eval corpus | 100+ behavioral handlers | Regression depth |

### P2 — Platform depth

| Theme | Deliverable |
|-------|-------------|
| Continuous watch | Daemon re-scan on config change |
| Sigstore verify | `--verify-signatures` on packages |
| VEX triage | CWE-aware reachability on CVE findings |
| Container / IaC | OCI + Terraform/K8s posture (narrow MCP-relevant scope) |
| Remote manifest probe | Pre-connect `tools/list` scan |
| Auto-fix loop | Opt-in local agent with undo — not cloud-dependent |
| Nucleus / SIEM export | FlexConnect or OCSF alongside SARIF |

### What the backlog confirms we should **not** build in core OSS

| Feature | Rationale |
|---------|-----------|
| Cloud-only analysis API as default | Violates local-first principle |
| Full 1,700-rule general SAST | Stay MCP-boundary focused |
| Public trust registry as required dependency | Product surface; optional feed only |
| Runtime gateway replacing commercial ACL products | Different layer — integrate via SARIF/events |
| Vendoring third-party technique corpora wholesale | Link + map to MCTS-T only |

### MCTS moats to preserve through expansion

1. **Attack-chain-first** capability graph (BFS + category gates)
2. **Auditable exponential scoring** with `ScoreBasis`
3. **MCTS-T + bundled Sigma** in one scan pipeline
4. **Executive HTML dashboard** without a reporting server
5. **Readiness + OPA** for deploy-time policy
6. **YARA + line-jumping** metadata defenses
7. **Deterministic CI default** — LLM/cloud opt-in only

---

## Part 11 Appendix — Full GAP backlog (GAP-001–240)

Categorized index of **213 actionable gaps** (excluding already-shipped parity rows).

| Field | Meaning |
|-------|---------|
| **Status** | Missing · Partial · Weak · Stub |
| **P** | Priority P0–P3 |
| **Ph** | Suggested build phase 1–4 |

Maintainers track detailed cross-tool mappings in a **local-only** audit.


### Analyzer (47)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-045 | Behavioral SAST 10 langs | Weak | P0 | 3 | CFG + LLM alignment |
| GAP-046 | CFG + dataflow framework | Missing | P0 | 3 | Full static analysis stack |
| GAP-047 | LLM docstring alignment | Missing | P0 | 3 | LLM alignment pipeline |
| GAP-048 | Prompt firewall | Missing | P0 | 2 | BLOCK/WARN/LOG/ALLOW |
| GAP-049 | Pre-exec action gate | Missing | P0 | 2 | Block bash/docker/git |
| GAP-050 | Hallucinated packages | Missing | P0 | 2 | Bloom or API fallback |
| GAP-051 | 6-layer skill scanning | Missing | P0 | 3 | OpenClaw skill model |
| GAP-052 | Prompt defense 12 vectors | Weak | P1 | 1 | Multilingual per-vector |
| GAP-053 | VT 3-tier file selection | Weak | P1 | 3 | Magic bytes + upload |
| GAP-054 | Cloud inspect 8 rules | Partial | P1 | 2 | Expand cloud inspect rules |
| GAP-055 | LLM prompt library (6) | Missing | P1 | 3 | Schema + retries |
| GAP-056 | LLM input injection guard | Missing | P1 | 3 | SecurityError on poison |
| GAP-057 | server.json manifest walker | Missing | P1 | 1 | Registry manifest audit |
| GAP-058 | Known-tool Levenshtein | Partial | P1 | 1 | ≤2 vs ~40 names |
| GAP-059 | Priority hijacking manifest | Partial | P2 | 1 | Manifest phrases |
| GAP-060 | AIVSS v2 scoring | Missing | P1 | 4 | --scoring aivss |
| GAP-061 | CVSS v4 vectors | Missing | P2 | 4 | Per-finding CVSS |
| GAP-062 | 12-lang regex SAST | Partial | P2 | — | Integrate Semgrep |
| GAP-063 | CPG semantic analyzer | Partial | P2 | 3 | Logic bugs via CPG |
| GAP-064 | Cross-file project taint | Partial | P2 | 3 | Handler-focused today |
| GAP-065 | Package typosquatting | Partial | P1 | 2 | Package name similarity |
| GAP-066 | RAG KB corpus | Missing | P2 | 4 | PgVector enrichment |
| GAP-067 | Threat intel DDG/Arxiv/HN | Missing | P2 | 4 | Citation enrichment |
| GAP-068 | LLM metadata triage | Shipped | P1 | 3 | `--llm-triage` malicious/safe/suspect |
| GAP-069 | Cross-file LLM verdict | Partial | P1 | 3 | Staged HIGH/LOW pipeline |
| GAP-070 | Pre-LLM rule hints | Missing | P1 | 2 | Chunk-level hints |
| GAP-071 | LLM evidence-required review | Partial | P1 | 2 | file/lines/snippet |
| GAP-072 | --llm-review second pass | Missing | P1 | 2 | FP reduction |
| GAP-073 | 1,700 regex SAST rules | Partial | P2 | — | Don't vendor wholesale |
| GAP-074 | Auto-fix 165 templates | Missing | P1 | 4 | MCP subset only |
| GAP-075 | Framework FP suppression | Missing | P2 | 4 | Django/FastAPI context |
| GAP-076 | Skills E004–E006 | Missing | P0 | 3 | Skill injection/download |
| GAP-077 | Skills W007–W014 | Shipped | P1 | 3 | Skill credential checks |
| GAP-078 | Toxic flow W015–W020 | Partial | P1 | 2 | TF code taxonomy |
| GAP-079 | Cloud ML E001 poisoning | Partial | P1 | 3 | Cloud ML E001 poisoning detection |
| GAP-080 | Cross-server E002 | Partial | P1 | — | Inventory overlap |
| GAP-081 | YARA default-on | Partial | P1 | 2 | Enterprise defaults |
| GAP-082 | API inspect default-on | Partial | P1 | 2 | Configurable defaults |
| GAP-083 | Custom analyzer hook | Missing | P1 | 3 | Public SDK extension |
| GAP-084 | StaticAnalyzer SDK | Partial | P2 | 2 | Snapshot coordinator |
| GAP-085 | analyzed_functions inventory | Missing | P3 | — | Function-level report |
| GAP-086 | Fail-fast credential check | Partial | P2 | 2 | Better missing-key UX |
| GAP-087 | pip-audit --fix | Missing | P2 | 3 | Auto-remediation |
| GAP-088 | pip-audit OSV service | Missing | P2 | 3 | OSV backend |
| GAP-089 | pip-audit uvx fallback | Partial | P3 | — | uv tool run |
| GAP-229 | 5-LLM consensus panel | Partial | P2 | 4 | Opt-in multi-LLM consensus panel |
| GAP-240 | Cross-server hitting-set algorithm | Partial | P1 | 3 | Minimum servers to remove |

### Auth (5)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-090 | Full OAuth client flow | Weak | P0 | 3 | Redirect/callback |
| GAP-091 | MCP SDK OAuthClientProvider | Partial | P0 | 3 | Standard MCP OAuth |
| GAP-092 | Explicit Auth class | Partial | P1 | 3 | OAUTH/BEARER/APIKEY |
| GAP-093 | Per-request API auth object | Partial | P1 | 3 | OAuth in REST API |
| GAP-094 | API taxonomy hierarchy | Missing | P2 | 3 | Tree in API response |

### CI (8)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-170 | PyPI publish pipeline | Missing | P0 | 4 | uv tool install mcts |
| GAP-171 | 3-OS test matrix | Missing | P1 | 4 | Cross-platform CI |
| GAP-172 | Live malicious-server CI | Missing | P1 | 4 | API/LLM secret jobs |
| GAP-173 | Binary artifact CI tests | Missing | P2 | 4 | Test compiled binary |
| GAP-174 | LLM integration tests | Missing | P2 | 4 | Secret-gated jobs |
| GAP-178 | CircleCI + Slack alerts | Missing | P3 | — | Secondary CI |
| GAP-179 | Agent-discovery test scale | Partial | P1 | 3 | Discovery regression |
| GAP-180 | E2E guard + machine scan | Missing | P1 | 4 | Full machine E2E |

### CLI (20)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-026 | inspect subcommand | Missing | P1 | 2 | Read-only surface listing |
| GAP-027 | evo fleet push | Missing | P0 | 4 | Fleet upload API integration |
| GAP-028 | guard install/uninstall | Missing | P0 | 4 | Agent Guard hooks |
| GAP-029 | --skills / SKILL.md scan | Shipped | P0 | 3 | `mcts scan` + `inventory --skills`, `skill_md` |
| GAP-030 | Per-server consent | Partial | P1 | 2 | y/n per stdio server |
| GAP-031 | --control-server bootstrap | Missing | P0 | 4 | Fleet scan upload |
| GAP-032 | --full-toxic-flows | Shipped | P1 | 2 | W015–W020 / TF codes |
| GAP-033 | --mcp-oauth-tokens-path | Partial | P2 | 3 | File-backed OAuth tokens |
| GAP-034 | Traffic capture / stderr UX | Partial | P2 | 3 | Colored per-server stderr |
| GAP-035 | --analysis-url cloud ML | Partial | P1 | 3 | E/W/TF issue codes |
| GAP-036 | init client MCP setup | Missing | P1 | 4 | Auto-configure clients |
| GAP-037 | doctor diagnostics | Shipped | P1 | 4 | `mcts doctor` dep + extras check |
| GAP-038 | init-hooks pre-commit | Missing | P2 | 4 | Pre-commit installer |
| GAP-039 | benchmark harness | Partial | P2 | 4 | Precision metrics |
| GAP-040 | audit/harden OpenClaw | Missing | P3 | — | Niche ecosystem |
| GAP-041 | rules subcommand | Missing | P3 | — | Expose rule paths |
| GAP-042 | Global --analyzers | Partial | P2 | 2 | All subcommands |
| GAP-043 | Global --hide-safe | Partial | P2 | 2 | Severity filter global |
| GAP-044 | python-dotenv auto-load | Missing | P3 | — | .env on startup |
| GAP-217 | cr-agent LLM security review | Missing | P1 | 4 | Dedicated LLM security review CLI |

### Compliance (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-230 | OWASP MCP Top 10 full 10/10 map | Shipped | P1 | 2 | Compliance meta-findings |

### Data (4)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-147 | Behavioral eval 100+ handlers | Partial | P1 | 4 | Scale eval corpus |
| GAP-148 | Remote eval servers | Partial | P2 | 4 | Live integration set |
| GAP-149 | Skills test corpus | Missing | P1 | 3 | SKILL.md fixtures |
| GAP-150 | Hallucination bloom data | Missing | P1 | 2 | API fallback preferred |

### Discovery (13)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-095 | 12+ agent registry | Partial | P0 | 3 | Gemini, Codex, OpenClaw… |
| GAP-096 | VS Code workspaceStorage | Missing | P0 | 3 | Profiles/extensions |
| GAP-097 | Claude Code plugin globs | Missing | P1 | 3 | **/.mcp.json, **/skills |
| GAP-098 | AgentDiscoverer ABC | Missing | P1 | 3 | Phase A/B pipeline |
| GAP-099 | Skills dirs per client | Shipped | P0 | 3 | `.cursor/skills` etc |
| GAP-100 | Claude commands *.md | Missing | P2 | 3 | Command markdown scan |
| GAP-101 | macOS codesign trust | Missing | P2 | 3 | Stdio binary trust |
| GAP-102 | WSL profile merge | Missing | P2 | 3 | Windows+WSL configs |
| GAP-103 | Config size cap + safe walks | Partial | P2 | 3 | Multi-user traversal |
| GAP-104 | Bootstrap skip_servers | Missing | P2 | 4 | Runtime skip policy |
| GAP-105 | Multi-format config parsers | Partial | P1 | 2 | Claude/VSCode variants |
| GAP-221 | IDE extension security scanner | Missing | P1 | 3 | VSIX / marketplace vulns |
| GAP-231 | Shadow MCP server discovery | Missing | P1 | 2 | Unknown/unapproved servers |

### Docs (6)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-203 | Issue code reference E/W/X | Missing | P1 | 2 | CI contract docs |
| GAP-204 | LLM providers guide | Missing | P2 | 3 | 100+ LiteLLM providers |
| GAP-205 | Programmatic SDK docs | Partial | P2 | 3 | SDK adoption |
| GAP-206 | 50+ reference examples | Partial | P2 | 3 | OAuth/bearer/API E2E |
| GAP-207 | Internals 7-doc series | Partial | P3 | — | Deep internals |
| GAP-208 | MDM / Evo fleet setup | Missing | P0 | 4 | If fleet mode |

### Enterprise (13)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-115 | MCP server scan mode | Missing | P0 | 2 | Agents invoke scanner |
| GAP-116 | Fleet upload + retries | Missing | P0 | 4 | Control-server ingest |
| GAP-117 | Bootstrap fingerprint | Missing | P0 | 4 | Host/CI/container metadata |
| GAP-118 | Push key mint/revoke | Missing | P0 | 4 | PUSH_KEY tenant auth |
| GAP-119 | Agent Guard forwarding | Missing | P0 | 4 | Runtime hook → Evo |
| GAP-120 | SOC2/GDPR/AIUC-1 eval | Missing | P1 | 4 | Multi-framework compliance |
| GAP-121 | Compliance evidence bundles | Missing | P1 | 4 | Audit trail artifacts |
| GAP-122 | Runtime quarantine | Missing | P2 | — | Block MCP activity |
| GAP-123 | WebSocket activity feed | Missing | P2 | — | Live monitoring UX |
| GAP-124 | SNYK_TOKEN mandatory cloud | Missing | P3 | — | Intentional difference |
| GAP-220 | Nucleus FlexConnect export | Missing | P2 | 4 | VM platform ingest |
| GAP-237 | OpenSSF Scorecard on repos | Missing | P3 | 4 | AgentBOM maintainer risk |
| GAP-238 | EPSS / CISA KEV enrichment | Missing | P3 | 4 | AgentBOM CVE context |

### Fuzzing (4)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-186 | Aggressive JSON-RPC fuzz | Partial | P1 | 3 | Starts real processes |
| GAP-187 | WebSocket transport fuzz | Missing | P2 | 3 | WebSocket MCP |
| GAP-188 | Docker MCP detection | Missing | P2 | 3 | _analyze_docker_server |
| GAP-190 | Remote URL protocol fuzz | Missing | P2 | 3 | --url fuzz |

### Gamification (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-215 | Badges / streaks | Missing | P3 | — | Product docs only |

### Governance (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-222 | YAML governance policies + allowlist | Shipped | P1 | 2 | `--policy` + `.mcts/policy.yaml` |

### Integration (11)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-159 | MCP tool scan_mcp_server | Shipped | P0 | 2 | Via mcts-mcp |
| GAP-160 | MCP tool explain_finding | Shipped | P0 | 2 | Part of mcts-mcp |
| GAP-161 | MCP tool propose_mitigation_patch | Missing | P3 | — | MCP tool mitigation patch proposal |
| GAP-162 | MCP tool list_techniques | Shipped | P0 | 2 | Bundled taxonomy export |
| GAP-163 | MCP tool scanner_health | Missing | P1 | 2 | Engine diagnostics |
| GAP-164 | Claude Code plugin | Missing | P1 | 4 | 9 slash commands |
| GAP-165 | Smithery marketplace | Missing | P2 | 4 | Distribution channel |
| GAP-167 | GitLab CI template | Missing | P3 | 4 | Secondary CI |
| GAP-168 | VS Code fix provider | Missing | P3 | — | In-editor fixes |
| GAP-169 | OpenClaw ClawProof plugin | Missing | P3 | — | Niche ecosystem |
| GAP-239 | VS Code marketplace extension | Missing | P2 | 4 | VS Code marketplace extension |

### Packaging (3)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-209 | uv tool install one-liner | Missing | P1 | 4 | Post-PyPI |
| GAP-210 | Shiv .pyz distribution | Missing | P3 | 4 | Alt binary format |
| GAP-211 | All-in-one vs extras deps | Partial | P1 | 4 | Enterprise install story |

### REST API (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-213 | Per-request API knobs | Partial | P1 | 3 | Analyzers/format/severity |

### Remediation (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-226 | Interactive auto-fix agent loop | Missing | P2 | 4 | Diff/accept/undo fix loop |

### Reporting (10)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-125 | Auto-fix MCP findings | Missing | P1 | 4 | Top MCP rules |
| GAP-126 | Scan history / trend | Shipped | P2 | 4 | `mcts_analysis/history.json` + HTML chart |
| GAP-127 | E/W/X/TF issue codes | Partial | P2 | 2 | Dual taxonomy option |
| GAP-128 | Verbosity/token tiers | Missing | P1 | 2 | minimal/compact/full |
| GAP-129 | Pre-rendered API strings | Missing | P3 | — | String templates |
| GAP-130 | detect-secrets redaction | Missing | P2 | 3 | Before display/upload |
| GAP-131 | Path anonymization upload | Missing | P3 | — | Cloud upload only |
| GAP-136 | Failure taxonomy | Missing | P2 | 2 | user_declined, skipped |
| GAP-234 | Letter grade A–F on report | Partial | P2 | 2 | Map score → grade |
| GAP-235 | PR comment output format | Missing | P2 | 2 | CI markdown comments |

### Runtime (2)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-219 | Stdio MCP proxy w/ inline detectors | Missing | P1 | 4 | AgentBOM 7 detectors on JSON-RPC |
| GAP-224 | Continuous config watch daemon | Missing | P2 | 3 | Re-scan on config change |

### SDK (5)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-181 | Public Scanner/Config/Auth exports | Missing | P1 | 3 | Programmatic SDK |
| GAP-182 | ScannerFactory | Missing | P2 | 3 | Per-request analyzers |
| GAP-183 | set_log_level() | Missing | P3 | — | Package log API |
| GAP-184 | Typed MCP exceptions | Partial | P2 | 3 | SDK error taxonomy |
| GAP-185 | AnalyzerEnum | Missing | P2 | 2 | Composable analyzers |

### Scanning (29)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-001 | Per-technique scan mode | Shipped | P0 | 2 | `--technique MCTS-T-*` |
| GAP-002 | Semgrep taint backend | Shipped | P0 | 3 | `--semgrep`; bundled rules include Java |
| GAP-003 | Java SAST | Shipped | P0 | 3 | Part of Semgrep adapter |
| GAP-004 | Agentic multi-agent pentest | Shipped | P0 | 4 | `mcts pentest` structured phases |
| GAP-005 | Pre-install package vet | Shipped | P0 | 2 | `mcts vet pypi:` / `npm:` / `oci:` |
| GAP-006 | Machine-wide default scan | Shipped | P0 | 2 | `mcts scan --machine-wide` |
| GAP-007 | Batch config scan | Missing | P0 | 1 | All servers in MCP JSON |
| GAP-008 | known-configs scan all | Shipped | P0 | 1 | `mcts inventory --scan-all` |
| GAP-009 | GitHub URL scan target | Missing | P2 | 3 | Shallow clone / zip |
| GAP-010 | Git-diff scoped scan | Missing | P1 | 4 | --diff-base for PR CI |
| GAP-011 | Scoped file/line scan | Missing | P2 | 3 | File/selection/git-diff scopes |
| GAP-012 | Standalone behavioral cmd | Partial | P1 | 3 | Dedicated repo SAST entry |
| GAP-013 | Standalone virustotal cmd | Partial | P1 | 3 | Binary path without full scan |
| GAP-014 | Standalone vulnerable-package cmd | Partial | P1 | 3 | With --fix, OSV service |
| GAP-015 | Separate static JSON paths | Partial | P2 | 1 | Split tools/prompts/resources |
| GAP-016 | Remote dedicated subcommand | Partial | P2 | — | Default analyzers differ |
| GAP-017 | --stdio-timeout | Missing | P2 | 3 | Env + CLI stdio knob |
| GAP-018 | Flexible --stdio-arg | Partial | P2 | 1 | Repeated arg injection |
| GAP-019 | Direct package URIs | Partial | P1 | 2 | pypi:/npm:/oci: |
| GAP-020 | Positional multi-config scan | Partial | P1 | 2 | Multiple config paths |
| GAP-021 | --scan-all-users | Missing | P1 | 3 | Multi-home enumeration |
| GAP-022 | --checks-per-server | Missing | P3 | — | Per-server check toggles |
| GAP-023 | --skip-ssl-verify | Missing | P2 | 3 | Corp proxy / lab |
| GAP-024 | --ci gate bundle | Partial | P1 | 2 | Unified CI preset |
| GAP-025 | --ignore-issues-codes | Missing | P2 | 3 | CI allowlist W001 etc |
| GAP-225 | Remote manifest scan-mcp (pre-connect) | Partial | P2 | 2 | Pre-connect tools/list probe |
| GAP-232 | Container / OCI image scan | Missing | P2 | 4 | AgentBOM native OCI |
| GAP-233 | IaC scan (TF/K8s/Helm) | Missing | P2 | 4 | AgentBOM breadth |
| GAP-236 | Config-only fast checks (12 rules) | Partial | P2 | 1 | Chaitanya MCP001–012 |

### Script (6)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-151 | run_determinism_benchmark.py | Missing | P1 | 4 | LLM reproducibility |
| GAP-152 | run_scans.sh batch | Missing | P2 | 2 | Batch MCTS-T scans |
| GAP-153 | Makefile ci/binary/publish | Missing | P2 | 4 | Packaging automation |
| GAP-154 | Pre-commit hook template | Missing | P2 | 4 | init-hooks companion |
| GAP-155 | build_bloom_filters | Missing | P1 | 2 | Hallucination data build |
| GAP-156 | PyInstaller macOS binary | Missing | P1 | 4 | Standalone distribution |

### Supply Chain (9)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-106 | CycloneDX SBOM | Missing | P1 | 3 | mcts sbom cmd |
| GAP-107 | OSV.dev CVE | Missing | P1 | 3 | Beyond pip/npm audit |
| GAP-108 | SBOM diff baseline | Partial | P1 | 3 | Supply-chain drift |
| GAP-109 | SBOM hallucination check | Missing | P1 | 3 | Invented deps in SBOM |
| GAP-110 | SBOM HTML report | Missing | P2 | 3 | SBOM-specific report |
| GAP-111 | Typosquat engine | Missing | P1 | 2 | Dep confusion |
| GAP-223 | Sigstore attestation verify | Missing | P2 | 3 | `[attestation]` extra |
| GAP-227 | VEX reachability triage | Missing | P2 | 4 | AgentBOM CWE-aware VEX |
| GAP-228 | Public trust registry integration | Missing | P3 | 4 | Public trust registry feed integration |

### Taxonomy (8)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-137 | 73 Sigma rules | Partial | P1 | 1 | Bundled metadata rule corpus |
| GAP-138 | 53 mitigation docs | Partial | P2 | 1 | Effectiveness ratings |
| GAP-139 | 73 test-logs regression | Partial | P1 | 1 | Scale harness |
| GAP-140 | 73 technique READMEs | Partial | P2 | 1 | Narrative dossiers |
| GAP-141 | Uncovered technique crosswalk | Partial | P1 | 1 | See gap analysis |
| GAP-142 | Technique YAML + schema | Missing | P2 | 2 | Portable technique packs |
| GAP-145 | LLM prompts (6 files) | Missing | P1 | 3 | Prompt library |
| GAP-146 | Readiness LLM judge prompt | Partial | P2 | 3 | Engineered prompt |

### Utility (4)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-199 | file_magic.py | Missing | P1 | 3 | VT tiering |
| GAP-200 | path_safety.py | Missing | P2 | 3 | Symlink-safe walks |
| GAP-201 | truststore corp CA | Missing | P2 | 3 | ZScaler/corp SSL |
| GAP-202 | Analysis daemon + LRU | Missing | P2 | 4 | Large repo perf |

### Visualization (1)

| GAP | Feature | Status | P | Ph | Notes |
|:----|:--------|:-------|:--|:---|:------|
| GAP-218 | Interactive attack graph dashboard | Missing | P1 | 3 | D3 force-directed attack graph page |

---

## Part 11 Appendix B — Ecosystem layer gaps (L1–L10)

**74** layer features where MCTS is missing or planned in the 156-row ecosystem matrix.

| ID | Feature | MCTS | Notes |
|:---|:--------|:-----|:------|
| L1-02 | Data-flow / taint analysis | P | MCTS tree-sitter taint + optional `--semgrep` backend |
| L1-03 | Java SAST | P | `--semgrep` bundled Java rules |
| L1-08 | SQL injection (code) | P | Partial via SAST patterns |
| L1-13 | Malicious package / hallucinated pkg | P | GAP in MCTS for npm hallucination |
| L1-14 | License compliance | N | — |
| L1-15 | Abandoned dep / maintainer risk | N | — |
| L1-17 | Cross-file analysis | P | GAP-064 cross-file taint |
| L1-20 | Semgrep rule pack | P | Bundled `sast/semgrep/rules/mcts-mcp.yaml` |
| L1-22 | Container / image scan | N | GAP — OCI scan |
| L1-23 | IaC scan (TF/K8s/Helm) | N | GAP — IaC posture |
| L1-24 | GPU / ML artifact scan | N | Niche ML artifact scan |
| L1-25 | Instruction file SAST (.cursorrules) | Partial | Repo markdown discovery shipped; `.cursorrules` not yet in default globs |
| L2-03 | ANSI / control-char smuggling | P | Partial metadata checks |
| L2-20 | Per-technique MCTS-T scan mode | P | `--technique` shipped (GAP-001) |
| L3-01 | Agent config / harness discovery | P | inventory + `--machine-wide` (GAP-006) |
| L3-02 | Skills / SKILL.md scanning | Shipped | `mcts scan`, `inventory --skills` (GAP-029) |
| L3-05 | Multi-agent red-team pentest | P | `mcts pentest` structured phases (GAP-004) |
| L3-06 | Agent hook / guard install | N | GAP-028 guard.py |
| L3-07 | Fleet / Evo push telemetry | N | GAP-027 |
| L3-08 | Managed agent misconfig (ASI) | N | ASI-03–07 class checks |
| L3-09 | Multi-agent trust graph | N | Planned Layer 10 |
| L3-10 | Goal hijacking / autonomy scoring | N | — |
| L3-12 | OpenClaw / niche agent audit | N | GAP-040 |
| L4-03 | Tool argument inspection | P | Partial via live probe |
| L4-04 | Session / user identity tracking | N | Enterprise gap |
| L4-09 | Prompt injection attempt detect (RT) | N | Runtime proxy detectors |
| L4-12 | Rate-limit / abuse detection | N | — |
| L4-13 | eBPF / sandbox monitoring | N | Research-only niche |
| L4-14 | Continuous config watch | N | GAP — `mcts watch` |
| L5-01 | SBOM generation (CycloneDX/SPDX) | N | GAP — AI-BOM export |
| L5-03 | VEX / reachability triage | N | GAP — VEX triage |
| L5-04 | Sigstore / attestation verify | N | GAP — `--verify-signatures` |
| L5-05 | Package provenance / SLSA | N | GAP — attestation verify |
| L5-06 | Public trust registry | N | GAP — optional feed |
| L5-07 | Publisher trust / reputation score | N | Community reputation signals |
| L5-08 | Security badge embed | N | — |
| L5-09 | Pre-install package vet (`npm:`/`pypi:`) | P | `mcts vet` (GAP-005) |
| L5-10 | Registry ID resolution (official MCP) | N | GAP — registry ID lookup |
| L5-12 | Maintainer / repo takeover signals | N | — |
| L5-13 | OpenSSF Scorecard integration | N | GAP — Scorecard enrichment |
| L5-14 | EPSS / CISA KEV enrichment | N | GAP — threat intel enrichment |
| L6-04 | MITRE ATLAS mapping | N | — |
| L6-08 | Immutable audit logs | N | Enterprise gap |
| L6-09 | Exception / risk acceptance workflow | N | GAP — shadow allowlist |
| L6-10 | Compliance evidence ZIP bundle | N | GAP — evidence export |
| L7-04 | Interactive attack graph UI | P | MCTS HTML dashboard planned |
| L7-07 | Credential flow graph | N | Gap |
| L7-11 | Trend / historical dashboard | Shipped | HTML sparkline + `history.json` |
| L8-03 | Interactive fix agent / loop | N | GAP — fix agent loop |
| L8-04 | Auto-generated PR | Pln | Roadmap |
| L8-05 | Auto-apply patch / undo | N | GAP — patch undo flow |
| L8-06 | Pre-commit hook installer | N | GAP-038 |
| L8-08 | Git-diff scoped scan | N | GAP-010 |
| L8-09 | PR comment output | N | GAP — PR comment format |
| L8-10 | Remediation MCP tools | N | GAP — remediation tools |
| L9-03 | MCP server mode (scan as tool) | N | GAP — `mcts-mcp` |
| L9-05 | Multi-tenant / RBAC | N | — |
| L9-06 | SSO / SCIM | N | — |
| L9-07 | Webhooks / alerts | N | — |
| L9-08 | Nucleus / VM platform export | N | GAP — FlexConnect export |
| L9-09 | Splunk / Sentinel SIEM | N | GAP — OCSF export |
| L9-10 | VS Code extension | N | GAP — IDE extension |
| L9-11 | Claude Desktop plugin | N | GAP — Claude plugin |
| L9-12 | Fleet merge / asset prefix | N | GAP-116 asset prefix |
| L10-01 | Runtime trust score | Pln | High — combine probe + runtime_events |
| L10-02 | Global MCP reputation network | N | High — needs community data |
| L10-05 | Auto-remediation PRs | Pln | Medium — SARIF + patch bot |
| L10-06 | Security benchmarking network | N | Medium — percentile vs corpus |
| L10-07 | Tool reputation graph | N | High |
| L10-08 | Predictive maintainer risk | N | Low priority |
| L10-09 | Attack simulation / red-team sim | Pln | `mcts pentest` + corpus |
| L10-11 | Signed MCP server attestation | N | Medium |
| L10-12 | MCP-native SBOM standard | N | CycloneDX AI component |
| L10-13 | Security copilot / threat modeling | N | Medium |
---

## How to Contribute

Pick a phase item, read the implementation notes above, and open a [feature request](https://github.com/MCP-Audit/MCTS/issues/new?template=feature_request.yml) or [Discussion](https://github.com/MCP-Audit/MCTS/discussions) to align on design before opening a PR.

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for development setup.
