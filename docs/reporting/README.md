# Reporting

> [Documentation](../index.md) → **Reporting**

How MCTS **presents** scan results — scores, exports, and shareable reports.

> **Confused by two scores?** Read **[Scoring — developer guide](scoring-guide.md)** first (5 min). Everything else links from there.

---

## Output formats

| Format | Command | Best for |
|--------|---------|----------|
| **Terminal** | `mcts scan ./server.py` | Quick feedback while coding |
| **JSON** | `mcts scan … -o report.json` | Automation, HTML input, CI |
| **SARIF** | `mcts scan … -f sarif -o report.sarif` | GitHub / GitLab Code Scanning |
| **HTML** | `mcts report report.json -o report.html` | Leadership and security reviews |

---

## Scoring docs (read in this order)

| Order | Doc | Who it's for |
|-------|-----|--------------|
| **1** | **[Scoring developer guide](scoring-guide.md)** | Everyone — mental model, CI cheat sheet, JSON fields |
| 2 | [Scoring spec (legacy)](scoring-spec.md) | Legacy formula and `--min-score` gates |
| 3 | [Scoring spec v2](scoring-spec-v2.md) | v2 factors, chains, calibration |
| 4 | [Migration & policy](migration/scoring-v2.md) | YAML policy, assets, history |
| 5 | [SARIF scoreV2](sarif-score-v2.md) | Code Scanning integration |

---

## Other guides

| Page | When to read |
|------|--------------|
| [Interpreting findings](interpreting-findings.md) | Why attack chains / overlap look alarming; trust mode |
| **[Findings trust — Phase 0 status](findings-trust-phase0.md)** | **Maintainers:** what shipped, what’s missing, CI/API fields |
| [HTML dashboard](html-report.md) | Layout of the executive report |
| [Threat taxonomy](taxonomy.md) | MCTS-T technique IDs on findings |

---

## Related

- [Getting started](../get-started/getting-started.md)
- [CI integration](../platform/ci-integration.md)
- [Glossary](../glossary.md)
