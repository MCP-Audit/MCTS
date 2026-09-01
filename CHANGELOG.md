# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Broaden secret detection for AI/provider tokens, modern GitHub tokens, package registry tokens, private keys, and common JSON/YAML assignments; redact matched credentials from finding evidence and ignore explicit copy-paste placeholders.

## [0.1.4] - 2026-06-12

### Security

- HTML dashboard metrics headline no longer assigns report JSON to `innerHTML`; values are rendered via `textContent` and text nodes to prevent DOM XSS (CodeQL `js/xss-through-dom`, alert #38)

## [0.1.3] - 2026-06-12

### Added

- **Scoring v2 (multi-factor risk)** — parallel `score_v2.absolute_risk` with factor classifiers, attack-chain multipliers, corpus-calibrated `security_score`, and explainable `top_contributors`; legacy `score.overall` unchanged (invariant I1)
- **Default dual scoring** — `--scoring both` is the default in CLI, API, and GitHub Action; opt out with `--scoring legacy`
- **v2 CI gates** — `--min-security-score`, `--max-absolute-risk`, `--max-risk-level`, `--min-category-score-v2`; API returns `gate_violations` and echoed `scoring_mode`
- **Dashboard v2** — absolute risk header, factor-axis radar, OWASP `category_scores_v2` tiles, dual-score glossary when `both`
- **Dashboard overview** — hero snapshot, issues/risk priority grid, quick-jump nav, plain-language zones (actions, risk breakdown, coverage, trends), and collapsible “How to read this report” guide for v2 and legacy scans
- **Scan history trend table** — dynamic columns (date, absolute risk, risk level, security score, issues, critical, high, legacy score) from `history.json`; records severity counts per run
- **SARIF `mcts/scoreV2`** — optional run properties; see [sarif-score-v2.md](docs/reporting/sarif-score-v2.md) for Code Scanning adoption
- **Calibration** — 11-server corpus, Spearman gate (ρ ≥ 0.80), `scripts/calibrate_scoring_weights.py`, packaged `scoring_v2_corpus_stats.json`
- **Docs** — [ADR-003](docs/analysis/adr-003-scoring-v2.md), [scoring-spec-v2](docs/reporting/scoring-spec-v2.md), [migration guide](docs/migration/scoring-v2.md)
- **Pentest** — `verdict` follows `score_v2.risk_level` when v2 scoring is enabled
- **CI** — `scoring-v2` workflow required on main CI (`ci.yml`) with Spearman ρ ≥ 0.80 gate

### Fixed

- Pentest marks `attack_chains` as `skipped` (not `complete`) when zero MCP tools are discovered; `pentest_limits` on `PentestReport` records coverage (`static-only` vs `full`) ([#215](https://github.com/MCP-Audit/MCTS/issues/215), thanks [@sachinML](https://github.com/sachinML) — [PR #255](https://github.com/MCP-Audit/MCTS/pull/255))
- Legacy security score card and gauge hidden when v2 scoring is active so the overview shows a single primary risk model
- v2 dimension radar uses relative normalization so spoke scale reflects dominant factors on each scan (not absolute corpus scale)
- Reject invalid `--snapshot` JSON such as scan-report artifacts, empty tool lists, or tool rows without names before scan analysis starts.
- Validate governance `--policy` files before scan execution so missing or invalid policy files fail before reports are written.
- Fail `--auto` with a clear error when multiple MCP config files or entrypoint candidates are found instead of silently scanning the repo root.
- Warn in `mcts readiness` when `--opa` or `--llm-judge` is requested but optional dependencies are missing.
- Surface a clear skip reason when `--semgrep` is enabled but the Semgrep CLI is unavailable or the scan fails before producing results.
- Return exit code 2 with a clear message when `mcts snapshot` cannot resolve a live launch configuration.
- Log when `--pip-audit` is skipped (missing CLI or dependency manifest) and keep CVE findings when the audit runs successfully.
- Allow `mcts scan --url https://host/mcp` without an explicit TARGET positional argument.
- Fail `mcts readiness` when zero MCP tools are discovered instead of reporting production-ready with `tools_checked: 0`.
- Suppress misleading OWASP MCP Top 10 coverage-gap meta-findings when zero MCP tools were discovered.
- Write distinct HTML and SARIF artifacts for `scan-prompts`, `scan-resources`, and `scan-instructions` instead of overwriting `scan-report.html`.
- Document PEP 508 `pypi:package==version` syntax for `mcts vet` alongside existing `@` pin form.
- Parse `pyproject.toml` dependencies with structured TOML instead of line heuristics so Poetry metadata and tool config are not flagged as unpinned packages (#155, #160).
- Skip unpinned-range findings for packages pinned in adjacent `poetry.lock`, `uv.lock`, or `Pipfile.lock` (#151).
- Ignore PEP 621 `requires-python` metadata in supply-chain dependency findings (#192).
- Add `-o` / `--output` to `mcts doctor` and surface scan subcommands for CI artifact paths (#156, #157).
- Accept `--no-progress` on `readiness`, `fuzz`, `scan-mcp`, and surface scan subcommands for shared CI scripts (#158).
- Explain when `mcts doctor --deep` import checks are skipped (no MCP config or no `-m` module in launch args).
- Scope OAuth HTTP findings to OAuth config keys and skip fixture/data JSON during repo scans (#164).
- Classify SQL database tools separately from filesystem tools so names like `read_query` are not flagged for path traversal (#165).
- Exclude design prompt markdown under `docs/prompts/` from default instruction discovery (#162).
- Scope `mcts scan-resources` to MCP resources only by disabling instruction-file discovery on resource-only surface scans (#221).

### Changed

- **HTML dashboard layout** — equal-height side-by-side panels across overview, risk breakdown, and trends; scrollable overflow (280px cap) for trend history, risk contributors, and category health; overview issue/pass lists capped at six rows
- **Brand assets** — canonical `Logo 2.jpg` for terminal headers, HTML sidebar, and exports (replaces separate PNG/report variants)
- **Trend sparkline** — chart width follows container size with resize handling
- **Documentation** — added [Scoring developer guide](docs/reporting/scoring-guide.md) as single entry point; simplified glossary, getting started, and migration doc; synced architecture, CI, and [html-report](docs/reporting/html-report.md) docs for the reorganized dashboard
- Print MCP Surface / Supply Chain / Dependency Hygiene breakdown when `--min-score` or `--ci` gate fails.
- Validate resolvable live launch configuration before the consent gate on `mcts snapshot` and `mcts fuzz`.
- **Doctor + MCP server startup hints** — `mcts doctor` now reports whether the optional `[mcp]` extra is installed, and `mcts-mcp` prints a direct install hint instead of a bare import failure when the extra is missing (#219).
- **GitHub issue templates** — structured bug, feature, security, and documentation forms aligned with `type:*` / `priority:P*` label taxonomy
- **Branch rulesets** — `main` + `main_*` release branches (maintainer merge) and admin-only `develop` integration branch

## [0.1.2] - 2026-06-10

### Added

- **Repository instruction discovery** — auto-discovers `SKILL.md`, `*prompt*.md`, and `system_prompt.md` from repo markdown during static scans; feeds prompt/instruction analyzers and `skill_md`
- **Surface-scoped analyzers** — `--surface-scoped-analyzers` (default on) limits analyzers to selected `--surfaces` (e.g. `scan-prompts` no longer runs supply-chain on `pyproject.toml`)
- **CLI flags** — `--instruction-file`, `--instruction-glob`, `--skills-dir`, `--discover-instructions` / `--no-discover-instructions`
- **Documentation** — instruction discovery, surface-scoped analyzers, and repo skills paths documented in architecture, security-checks, glossary, and README

## [0.1.1] - 2026-06-09

### Added

- **Semgrep SAST adapter** — `--semgrep` runs bundled MCP rule pack (Python, JS/TS, Java) via `semgrep` CLI; optional `--semgrep-rules`; `semgrep` extra in `pyproject.toml`
- **LLM metadata triage** — `--llm-triage` classifies MCP surfaces as malicious/safe/suspect (`llm_metadata_triage` analyzer; requires `MCTS_LLM_API_KEY`)
- **Package vetting** — `mcts vet pypi:` / `npm:` / `oci:` pre-install checks
- **MCP server mode** — `mcts-mcp` stdio tools: `scan_mcp_target`, `scan_mcp_server`, `list_techniques`, `explain_finding`, `compare_baselines`
- **Structured pentest** — `mcts pentest` static recon, attack-chain review, optional safe fuzz
- **Machine-wide scan** — `mcts scan --machine-wide` scans all MCP servers in local client configs
- **Skills scanning** — `mcts inventory --skills` with W007–W014 issue codes on `SKILL.md`
- **Toxic flows** — W015–W020 cross-server toxic flow codes; `--full-toxic-flows`
- **Governance policies** — `--policy` YAML allowlist and min-score gates
- **Per-technique mode** — `--technique MCTS-T-*` filter
- **CI preset** — `--ci` unified gate bundle
- **Remote manifest probe** — `mcts scan-mcp <url>` pre-connect tools/list check
- **Inventory batch scan** — `mcts inventory --scan-all`
- **Expanded client registry** — 12+ agent clients (Gemini, Codex, OpenClaw, …)
- **Runtime detectors** — T1042–T1079 wired; sigma rules S-1305…S-2105 promoted to runtime techniques
- **Regression coverage** — 79/79 MCTS-T techniques in harness (≥80% accuracy gate)
- **Preflight UX** — `mcts doctor`, `mcts snapshot`, `mcts scan --auto`, partitioned score breakdown, analysis output dir (`.mcts/` or `mcts_analysis/`)

### Changed

- **Docs** — synced README, CLI, architecture, security-checks, roadmap, and feature-expansion-plan with shipped Semgrep, LLM triage, vet, pentest, mcts-mcp, machine-wide, and skills features
- **Test suite** — 350+ pytest cases (354 passing at last full run)

### Added (prior unreleased)

- **IFD UX improvements** — `mcts scan .` repo scan with MCP config hints; `mcts doctor`; `mcts snapshot`; `mcts scan --auto`; partitioned MCP/supply-chain scores; live startup diagnostics; config-static disclaimers; zero-tools static notice; actionable `mcts report` errors; venv install warning

### Changed

- **`[all]` optional extra** — no longer includes `litellm`; install `mcp-mcts[llm]` separately when using `--llm-judge`
- **Docs** — `uvx`/`pipx` first install guidance; CLI reference for doctor/snapshot/auto
- **PyPI distribution** — publish as `mcp-mcts` on PyPI (`pip install mcp-mcts`); import package remains `mcts`
- **Public Python API** — `from mcts import Scanner, ScanConfig`
- **Packaging** — dynamic version from `src/mcts/__init__.py`, `MANIFEST.in`, `uv` dependency groups for dev tooling, CI wheel smoke tests + `twine check`; GitHub Action installs from pinned ref (not PyPI)
- **Multi-surface scanning** — analyze tools, prompts, resources, and server instructions (`--surfaces`); `SurfaceMetadataAnalyzer`, `PromptDefenseAnalyzer`
- **Remote MCP transport** — `--url` with streamable HTTP and SSE; Bearer tokens, custom headers, OAuth client credentials (`probe/http_session.py`, `probe/auth.py`)
- **Static JSON snapshot** — air-gapped scan from exported `tools/list` JSON (`--snapshot`)
- **Env var expansion** — `--expand-vars` for `$VAR` / `%VAR%` in IDE MCP configs
- **JSON5 config parsing** — commented JSON in Cursor/VS Code configs
- **Supply chain CVE scanning** — `--pip-audit`, `--npm-audit`
- **Behavioral static SAST** — description vs Python handler mismatch (`BehavioralStaticAnalyzer`)
- **Protocol security probes** — `--protocol-probe` for MCPS-style HTTP checks
- **Optional analyzers** — `--yara`, `--llm-judge`, `--cloud-inspect`, `--virustotal` (all opt-in)
- **Readiness command** — `mcts readiness` for production heuristics (excluded from security score)
- **REST API** — `mcts serve` with 10 endpoints: `/health`, `/scan`, `/scan-tool`, `/scan-all-tools`, `/scan-prompt`, `/scan-all-prompts`, `/scan-resource`, `/scan-all-resources`, `/scan-instructions`, `/readiness` (`--extra api`; optional `MCTS_API_KEY` auth)
- **Terminal output formats** — `--terminal-format table|by_tool|by_analyzer|by_severity|summary`
- **Scan filters** — `--tool-filter`, `--analyzer-filter`, `--severity-filter`, `--analyzers`
- **Taxonomy crosswalk** — AITech IDs in finding evidence (`taxonomy/crosswalk.json`)
- **Stderr capture** — `--stderr-file` for live stdio server debugging
- Docs: [Remote Scanning](docs/scanning/remote-scanning.md), [Static Snapshot](docs/scanning/static-snapshot.md), [Readiness](docs/scanning/readiness.md), [REST API](docs/platform/rest-api.md)
- **Repository scanning** — `mcts scan ./repo/` walks Python files, discovers `@tool` handlers across the project (skips `tests/`, venv, `.git`)
- **Static discovery layer** — `discovery/static.py` parses `input_schema`, handler snippets, source locations, and capability profiles
- **Source-aware analyzers** — `CommandExecutionAnalyzer`, `PathValidationAnalyzer`, `SchemaSurfaceAnalyzer`; `DataLeakageAnalyzer` scans source files with line-level locations
- **Capability-graph attack chains** — attack chain detection uses per-tool capability profiles instead of keyword hints; real graph stored on `ScanReport.attack_graph`
- **SARIF output** — `mcts scan -o report.sarif --format sarif` for CI and GitHub Advanced Security integration
- **CI score gates** — `--min-score`, `--max-critical` exit codes for pipeline enforcement
- **Finding metadata** — `technique_id`, `location`, `confidence` on findings; `MCTS-T-*` technique IDs on new analyzers
- Benchmark fixture: `examples/bench/multi-file-server/` for multi-file discovery tests
- **`mcts inventory`** — discover MCP servers in Cursor, Claude, VS Code, Windsurf configs
- **Cross-server shadowing** — `CrossServerAnalyzer` detects tool name collisions (`MCTS-T-1008`)
- **Metadata integrity analyzer** — description poisoning and line-jumping patterns
- **MCTS-T taxonomy** — `techniques.json` with CWE/OWASP mapping; auto-enriched on findings
- **GitHub Action** — JSON + SARIF + HTML artifacts, `--min-score` input, Code Scanning upload
- Docs: [Product Positioning](docs/more/product-positioning.md)
- **Live stdio probing** — `mcts scan --live --i-understand-live-risk` connects via MCP protocol; merges live schemas with static analysis
- **Config-based live scan** — `mcts scan --config ~/.cursor/mcp.json --server NAME --live --i-understand-live-risk`
- Example: `examples/live-mcp-server/server.py` for probe integration tests
- **`mcts fuzz`** — safe read-only protocol fuzzing (`--fuzz-level safe|standard|aggressive`); aggressive requires `--i-understand-fuzz-risk`
- **TypeScript/JavaScript static discovery** — `discovery/static_js.py` finds `registerTool`, `server.tool`, and `setRequestHandler` patterns; `ScanConfig.languages` defaults to `python` + `typescript`
- Benchmark fixture: `examples/bench/multi-file-ts-server/` for TS discovery tests
- **HTML security dashboard** — `mcts report` renders a self-contained, dark-themed executive dashboard (score gauge, letter grade, severity cards, posture summary, category breakdown + radar chart, findings table, attack chain graph, OWASP mapping, in-browser JSON/HTML/PDF export)
- **Terminal UI** — Rich-based CLI with themes (`cyber`, `minimal`, `github`), scan progress animation, aligned metrics panels, and brand PNG logo on supported terminals (ASCII fallback elsewhere)
- **Exponential risk scoring** — Security score `round(100 × e^(-raw_risk/50))`, risk index, and auditable `ScoreBasis` on every report (compliance meta-findings excluded)
- Example servers: `examples/baseline-mcp-server/`, `examples/medium-risk-mcp-server/` for scoring regression bands
- Brand assets in `src/mcts/brand/` (canonical logo + HTML-optimized embed)
- Docs: [HTML Security Dashboard](docs/reporting/html-report.md), [CLI](docs/platform/cli.md), [Getting Started](docs/get-started/getting-started.md), [Architecture](docs/analysis/architecture.md), and README

### Fixed

- GitHub Action and CI smoke tests use absolute output paths after `mcts_analysis/` routing
- `mcts report report.json` resolves scan JSON under `mcts_analysis/` when run from project root
- `CrossServerAnalyzer` no longer counted in "analyzers run" when inventory is empty (was a silent no-op during `mcts scan`)
- Docs: updated `setup-uv` version from `@v4` to `@v7` in CI integration guide

### Changed

- **Documentation** — synced planning and operational docs with the gap backlog (213 GAP rows + 74 ecosystem layer gaps): Part 11 appendix in [Feature Expansion Plan](docs/more/feature-expansion-plan.md), roadmap gaps in [Product Positioning](docs/more/product-positioning.md), planned CLI/CI/reporting/discovery sections in [platform](docs/platform/), [scanning](docs/scanning/), [analysis/security-checks](docs/analysis/security-checks.md), [getting-started](docs/get-started/getting-started.md), [action](action/README.md)
- `PromptInjectionAnalyzer` and `JailbreakAnalyzer` use heuristics beyond keyword/tool-count placeholders
- HTML attack graph no longer synthesizes fake "related" edges when no chains exist
- Renamed project and repository to **MCTS** (Model Context Threat Scanner): `mcts` package and CLI, GitHub repo `MCP-Audit/MCTS` (formerly MCPAudit / `mcpaudit` / `MCP-Audit/MCPAudit`)
- `mcts report` now delegates to the premium dashboard generator (replaces minimal inline HTML template)

## [0.1.0] - 2026-06-03

### Added

- Initial project scaffold with `uv`, `src/` layout, and `pyproject.toml`
- CLI: `mcts scan`, `mcts report`, `mcts fuzz`, `mcts pentest` (stubs)
- Analyzers: permissions, prompt injection, tool abuse, data leakage, jailbreak, attack chains
- Risk scoring engine and basic HTML report generation
- Example vulnerable MCP server and pytest suite
- GitHub Actions CI, pre-commit, and OSS community files
- Alpha release: static analysis scanner for Python MCP servers
