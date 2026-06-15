/* MCTS HTML Security Dashboard */
(function () {
  "use strict";

  function readJsonScript(id) {
    const el = document.getElementById(id);
    if (!el) return null;
    try {
      return JSON.parse(el.textContent || "{}");
    } catch (err) {
      console.error("MCTS: failed to parse", id, err);
      return null;
    }
  }

  const DATA = readJsonScript("mcts-report-data");
  const ICONS = readJsonScript("mcts-icons-data") || {};

  if (!DATA) {
    console.error("MCTS: report data missing");
    return;
  }

  const MIN_GAUGE_ARC = 8;

  const COLORS = {
    critical: "#ef4444",
    high: "#f97316",
    medium: "#facc15",
    low: "#22c55e",
    primary: "#2563eb",
    muted: "#64748b",
    grid: "rgba(255,255,255,0.06)",
    text: "#94a3b8",
  };

  function icon(name, className) {
    const svg = ICONS[name] || "";
    return `<span class="severity-icon ${className || ""}" aria-hidden="true">${svg}</span>`;
  }

  function scoreGaugeColor(score) {
    if (score <= 25) return COLORS.critical;
    if (score <= 50) return COLORS.high;
    if (score <= 75) return COLORS.yellow;
    return COLORS.low;
  }

  function fillBanners() {
    const toolBanner = document.getElementById("tool-discovery-banner");
    const td = DATA.tool_discovery;
    if (toolBanner && td && td.show_banner) {
      toolBanner.hidden = false;
      toolBanner.textContent = td.message || "Tool discovery unavailable in static mode.";
    }
    const notesBanner = document.getElementById("scan-notes-banner");
    const notes = DATA.scan_notes || [];
    if (notesBanner && notes.length) {
      notesBanner.hidden = false;
      notesBanner.innerHTML = notes.map((n) => `<p>${escapeHtml(n)}</p>`).join("");
    }
  }

  const BREAKDOWN_HINTS = {
    "MCP Surface": "Permissions, injection, and execution risks on your MCP tools",
    "Supply Chain": "Integrity of server code and packages",
    "Dependency Hygiene": "Known vulnerable dependencies",
    Composite: "Weighted blend of the area scores above",
  };

  const SEVERITY_MEANINGS = {
    critical: "Fix immediately — severe exploit risk",
    high: "Fix soon — significant risk",
    medium: "Schedule a fix — moderate risk",
    low: "Lower priority — minor risk",
  };

  function findingSeverity(f) {
    return f.display_severity || f.severity;
  }

  const EVIDENCE_MATURITY_LABELS = {
    graph_path: "Proven path",
    capability_overlap: "Overlap",
  };

  function evidenceMaturityChip(f) {
    if (!f.evidence_type) return "";
    const label = EVIDENCE_MATURITY_LABELS[f.evidence_type] || f.evidence_type.replace(/_/g, " ");
    return `<span class="evidence-maturity-chip evidence-maturity-${escapeHtml(f.evidence_type)}" title="Evidence maturity">${escapeHtml(label)}</span>`;
  }

  function ruleStabilityChip(f) {
    if (!f.rule_stability) return "";
    const label = String(f.rule_stability);
    return `<span class="rule-stability-chip rule-stability-${escapeHtml(label)}" title="Rule stability">${escapeHtml(label)}</span>`;
  }

  function trustEnforced() {
    return (DATA.meta && DATA.meta.findings_trust_mode === "enforce") || false;
  }

  function activeSummary() {
    return DATA.display_summary || DATA.summary || {};
  }

  function scorePtsHtml(value) {
    return `<span class="score-pts-value">${value}</span><span class="score-pts-suffix"> / 100 pts</span>`;
  }

  const V2_DIMENSION_LABELS = {
    exploitability: "Exploitability",
    reachability: "Reachability",
    exposure: "Exposure",
    blast_radius: "Blast radius",
    business_impact: "Business impact",
    asset_value: "Asset value",
    attack_preconditions: "Preconditions",
    threat_maturity: "Threat maturity",
  };

  const V2_FACTOR_LABELS = {
    exploitability: "easy to exploit",
    reachability: "reachable by attackers",
    exposure: "exposed to users",
    blast_radius: "wide blast radius",
    business_impact: "high business impact",
    asset_value: "valuable asset",
    attack_preconditions: "few preconditions",
    threat_maturity: "known attack pattern",
    chain_factor: "part of attack chain",
  };

  function applyScoringMode() {
    const isV2 = Boolean(DATA.score_v2);
    const legacyCard = document.getElementById("score-card");
    const v2Panel = document.getElementById("v2-score-section");
    const zoneRiskDetail = document.getElementById("zone-risk-detail");
    const legacyBreakdown = document.getElementById("legacy-breakdown-card");
    const scoreBreakdown = document.getElementById("score-breakdown-section");
    const legendV2 = document.getElementById("legend-v2-block");
    const legendScores = document.getElementById("legend-scores-block");
    const heroTitle = document.getElementById("hero-title");
    const trendTitle = document.getElementById("trend-card-title");
    const trendHint = document.getElementById("trend-card-hint");
    const riskGuideTitle = document.getElementById("risk-guide-title");
    const riskGuideHint = document.getElementById("risk-guide-hint");
    const trendIntro = document.getElementById("trend-zone-intro");

    if (legacyCard) legacyCard.hidden = isV2;
    if (v2Panel) v2Panel.hidden = !isV2;
    if (zoneRiskDetail && !isV2) zoneRiskDetail.hidden = true;
    if (legacyBreakdown) legacyBreakdown.hidden = isV2;
    if (scoreBreakdown && isV2) scoreBreakdown.hidden = true;
    if (legendV2) legendV2.hidden = !isV2;
    if (legendScores && isV2) {
      legendScores.querySelector("strong").textContent = "Benchmark score (0–100 points)";
      const p = legendScores.querySelector("p");
      if (p) {
        p.textContent =
          "How this server compares to others in the benchmark corpus. Higher = better — separate from absolute risk.";
      }
    }
    if (heroTitle && isV2) {
      const level = String(DATA.score_v2.risk_level || "low");
      heroTitle.textContent =
        level === "critical" || level === "high"
          ? "Action needed — elevated risk"
          : "Review recommended";
    }
    if (trendTitle && isV2) {
      trendTitle.textContent = "Risk over time";
      if (trendHint) trendHint.textContent = "Absolute risk per scan — lower is better.";
      if (trendIntro) {
        trendIntro.textContent = "Compare absolute risk across scans and see which band you are in.";
      }
    }
    if (riskGuideTitle && isV2) {
      riskGuideTitle.textContent = "Absolute risk bands";
      if (riskGuideHint) riskGuideHint.textContent = "Higher numbers mean more overall danger.";
    }
  }

  function fillHero() {
    const statsEl = document.getElementById("hero-stats");
    const eyebrow = document.getElementById("hero-eyebrow");
    if (!statsEl) return;

    const s = activeSummary();
    const cs = DATA.checks_summary || {};
    const tools = DATA.meta?.tools_discovered || 0;
    const v2 = DATA.score_v2;
    const score = DATA.score?.overall ?? 0;

    if (eyebrow) {
      const target = DATA.meta?.target;
      eyebrow.textContent = target ? `Scanned ${target}` : "Scan complete";
    }

    const stats = [];
    if (v2) {
      stats.push({
        cls: "hero-stat--risk",
        value: String(v2.absolute_risk),
        label: `${String(v2.risk_level || "low").toUpperCase()} risk`,
      });
      if (v2.security_score != null) {
        stats.push({
          cls: "",
          value: `${v2.security_score}/100`,
          label: "Benchmark score",
        });
      }
    } else {
      stats.push({
        cls: "hero-stat--risk",
        value: `${score}/100`,
        label: `${DATA.risk?.level || "risk"} rating`,
      });
    }
    stats.push({
      cls: "hero-stat--issues",
      value: String(s.total || 0),
      label: `issue${s.total === 1 ? "" : "s"} found`,
    });
    if (cs.analyzers_run) {
      stats.push({
        cls: "hero-stat--ok",
        value: `${cs.analyzers_passed}/${cs.analyzers_run}`,
        label: "checks passed",
      });
    }
    stats.push({
      cls: "",
      value: String(tools),
      label: `MCP tool${tools === 1 ? "" : "s"}`,
    });

    statsEl.innerHTML = stats
      .map(
        (row) =>
          `<div class="hero-stat ${row.cls}"><span class="hero-stat-value">${escapeHtml(row.value)}</span><span class="hero-stat-label">${escapeHtml(row.label)}</span></div>`
      )
      .join("");
  }

  function fillScoreV2() {
    const v2 = DATA.score_v2;
    const section = document.getElementById("v2-score-section");
    if (!section || !v2) return;
    section.hidden = false;

    const absEl = document.getElementById("v2-absolute-risk");
    const pill = document.getElementById("v2-risk-pill");
    const rangeEl = document.getElementById("v2-risk-range");
    const secEl = document.getElementById("v2-security-score");
    const confEl = document.getElementById("v2-confidence");
    const pctEl = document.getElementById("v2-percentile");
    const intro = document.getElementById("v2-metrics-intro");
    if (absEl) absEl.textContent = String(v2.absolute_risk);
    if (pill) {
      pill.textContent = `${String(v2.risk_level || "low").toUpperCase()} RISK`;
      pill.className = `risk-pill ${v2.risk_level || "low"}`;
    }
    if (rangeEl && Array.isArray(v2.risk_range)) {
      const rangeConf = v2.risk_range_confidence != null ? String(v2.risk_range_confidence) : "—";
      rangeEl.textContent = `Likely range ${v2.risk_range[0]}–${v2.risk_range[1]} (confidence ${rangeConf}%)`;
    }
    if (secEl) {
      secEl.textContent = v2.security_score != null ? `${v2.security_score} / 100` : "—";
    }
    if (confEl) {
      confEl.textContent = v2.confidence_score != null ? `${v2.confidence_score}%` : "—";
    }
    if (pctEl) {
      pctEl.textContent = v2.risk_percentile != null ? `${v2.risk_percentile}th percentile` : "—";
    }
    if (intro) {
      intro.textContent =
        "These are the findings and OWASP categories contributing most to your absolute risk score.";
    }

    const contributors = v2.top_contributors || [];
    const categories = DATA.category_scores_v2 || [];
    fillV2Contributors(contributors);
    fillV2Categories(categories);
    initV2DimensionRadar(v2.dimension_scores || {});
    initV2BenchmarkGauge(v2);
    const zoneRiskDetail = document.getElementById("zone-risk-detail");
    if (zoneRiskDetail) {
      zoneRiskDetail.hidden = !contributors.length && !categories.length;
    }
    applyScoringMode();
  }

  function fillV2Categories(categories) {
    const list = document.getElementById("v2-category-list");
    const card = document.getElementById("v2-categories-card");
    if (!list || !card) return;
    if (!categories.length) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    list.innerHTML = categories
      .map((c) => {
        const pct = Math.max(0, Math.min(100, Number(c.score) || 0));
        const benchmark = Math.max(0, Math.min(100, Number(c.benchmark) || 0));
        const barColor = pct >= 80 ? COLORS.low : pct >= 50 ? COLORS.medium : COLORS.critical;
        const benchHint = benchmark ? ` · corpus ~${benchmark}` : "";
        return `<li class="category-item">
          <div class="category-item-header">
            <span class="name">${escapeHtml(c.label)}</span>
            <span class="score-val">${escapeHtml(c.display)}${escapeHtml(benchHint)}</span>
          </div>
          <div class="category-bar"><span style="width:${pct}%;background:${barColor}"></span></div>
          ${
            benchmark
              ? `<div class="category-benchmark-hint" style="font-size:11px;color:var(--muted);margin-top:4px">Benchmark reference: ${benchmark}/100 health</div>`
              : ""
          }
        </li>`;
      })
      .join("");
  }

  function initV2BenchmarkGauge(v2) {
    const wrap = document.getElementById("v2-benchmark-gauge-wrap");
    const canvas = document.getElementById("v2-gauge-chart");
    const valueEl = document.getElementById("v2-gauge-score-value");
    if (!wrap || !canvas || typeof Chart === "undefined") return;
    if (v2.security_score == null) {
      wrap.hidden = true;
      return;
    }
    wrap.hidden = false;
    const score = Number(v2.security_score);
    if (valueEl) valueEl.textContent = String(score);
    const color = scoreGaugeColor(score);
    const visualScore = Math.max(score, MIN_GAUGE_ARC);
    const remainder = Math.max(0, 100 - visualScore);
    const gradient = canvas.getContext("2d");
    let fillColor = color;
    if (gradient) {
      const g = gradient.createLinearGradient(0, 0, 0, canvas.height);
      g.addColorStop(0, color);
      g.addColorStop(1, "rgba(239,68,68,0.25)");
      fillColor = g;
    }
    new Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [visualScore, remainder],
            backgroundColor: [fillColor, "rgba(255,255,255,0.05)"],
            borderWidth: 0,
            borderRadius: 6,
            circumference: 180,
            rotation: 270,
            spacing: 2,
          },
        ],
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        cutout: "58%",
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { duration: 600 },
      },
    });
  }

  function fillV2Contributors(contributors) {
    const tbody = document.getElementById("v2-contributors-body");
    const card = document.getElementById("v2-contributors-card");
    if (!tbody || !card) return;
    if (!contributors.length) {
      card.hidden = true;
      return;
    }
    card.hidden = false;
    const findingById = Object.fromEntries((DATA.findings || []).map((f) => [f.id, f]));
    tbody.innerHTML = contributors
      .map((row) => {
        const finding = row.finding_id ? findingById[row.finding_id] : null;
        const title = finding ? finding.title : row.type === "attack_chain" ? "Attack path" : row.finding_id || "—";
        const tool = finding ? finding.tool : row.nodes ? row.nodes.join(" → ") : "—";
        const factors = row.factors
          ? Object.entries(row.factors)
              .filter(([, v]) => Number(v) > 0)
              .map(([k, v]) => `${V2_FACTOR_LABELS[k] || k.replace(/_/g, " ")} (${v})`)
              .join("; ")
          : row.hop_count != null
            ? `${row.hop_count}-step attack path`
            : "—";
        return `<tr>
          <td>${escapeHtml(title)}</td>
          <td>${escapeHtml(tool || "—")}</td>
          <td>${escapeHtml(String(row.risk_contribution ?? "—"))}</td>
          <td>${escapeHtml(factors)}</td>
        </tr>`;
      })
      .join("");
  }

  function initV2DimensionRadar(dimensions) {
    const canvas = document.getElementById("v2-dimension-radar");
    if (!canvas || typeof Chart === "undefined") return;
    const keys = Object.keys(V2_DIMENSION_LABELS).filter((k) => k in dimensions);
    if (!keys.length) return;
    const labels = keys.map((k) => V2_DIMENSION_LABELS[k]);
    const values = keys.map((k) => Number(dimensions[k]) || 0);
    new Chart(canvas, {
      type: "radar",
      data: {
        labels,
        datasets: [
          {
            label: "Factor load",
            data: values,
            borderColor: COLORS.high,
            backgroundColor: "rgba(249,115,22,0.15)",
            borderWidth: 2,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            beginAtZero: true,
            max: 100,
            ticks: { display: false, stepSize: 25 },
            grid: { color: COLORS.grid },
            angleLines: { color: COLORS.grid },
            pointLabels: { color: COLORS.text, font: { size: 10 } },
          },
        },
        plugins: { legend: { display: false } },
      },
    });
  }

  function fillScoreBreakdown() {
    const section = document.getElementById("score-breakdown-section");
    const row = document.getElementById("score-breakdown-row");
    const b = DATA.score && DATA.score.breakdown;
    if (!section || !row || !b) return;
    section.hidden = false;
    if (DATA.score_v2) {
      const intro = section.querySelector(".metrics-section-intro");
      if (intro) {
        intro.textContent +=
          " Partition scores use the legacy v1 formula and may shift when attack chains run.";
      }
    }
    const cards = [
      ["MCP Surface", b.mcp_surface],
      ["Supply Chain", b.supply_chain],
      ["Dependency Hygiene", b.dependency_hygiene],
      ["Composite", b.composite],
    ];
    row.innerHTML = cards
      .map(
        ([label, value]) =>
          `<div class="breakdown-score-card card-interactive" data-card-action="scroll:breakdown-row" tabindex="0" role="button" aria-label="View ${escapeHtml(label)} in category breakdown">
            <span class="card-cta">Categories →</span>
            <h4>${escapeHtml(label)}</h4>
            <div class="value">${scorePtsHtml(value)}</div>
            <p class="breakdown-caption">${escapeHtml(BREAKDOWN_HINTS[label] || "")}</p>
            <p class="breakdown-not-pct">Security points · not a %</p>
          </div>`
      )
      .join("");
  }

  function fillScanMeta() {
    const m = DATA.meta;
    const map = {
      "meta-target": m.target,
      "meta-scope": m.scan_scope_label || m.scan_scope || "—",
      "meta-date": m.scan_date,
      "meta-time": m.scan_time,
      "meta-tools": String(m.tools_discovered),
      "meta-analyzers": String(m.analyzers_run),
    };
    Object.entries(map).forEach(([id, val]) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val;
    });
    const legacyCard = document.getElementById("score-card");
    if (DATA.score_v2 && legacyCard) {
      legacyCard.hidden = true;
      return;
    }
    const pill = document.getElementById("risk-pill");
    const gaugeScore = document.getElementById("gauge-score-value");
    const gradeEl = document.getElementById("security-grade");
    const v2 = DATA.score_v2;
    const useV2Primary = v2 && DATA.scoring_version === "v2";
    const scoreText = useV2Primary && v2.security_score != null
      ? String(v2.security_score)
      : String(DATA.score.overall);

    if (pill && !useV2Primary) {
      pill.textContent = DATA.risk.badge;
      pill.className = `risk-pill ${DATA.risk.level}`;
    } else if (pill && useV2Primary) {
      pill.textContent = `${String(v2.risk_level || "low").toUpperCase()} RISK`;
      pill.className = `risk-pill ${v2.risk_level || "low"}`;
    }
    if (gaugeScore) gaugeScore.textContent = scoreText;

    const grade = DATA.score.grade || {};
    if (gradeEl) {
      gradeEl.textContent = grade.letter || "—";
      gradeEl.className = `grade-badge grade-${(grade.letter || "f").toLowerCase()}`;
    }
    const briefEl = document.getElementById("score-brief");
    if (briefEl) {
      briefEl.textContent = useV2Primary
        ? `Absolute risk ${v2.absolute_risk} — see v2 section below`
        : DATA.risk.brief || DATA.risk.description || "—";
    }

    const detailEl = document.getElementById("score-detail");
    const basis = DATA.score?.basis;
    if (detailEl && basis) {
      const counts = basis;
      const countLabel = trustEnforced()
        ? "display severity"
        : DATA.meta?.findings_trust_mode === "warn"
          ? "template severity"
          : "severity";
      detailEl.textContent =
        `Calculated from ${basis.scorable_total} finding(s) by ${countLabel} — ` +
        `${counts.critical ?? 0} critical, ${counts.high ?? 0} high, ${counts.medium ?? 0} medium, ${counts.low ?? 0} low. ` +
        (DATA.meta?.findings_trust_mode === "warn"
          ? "Legacy score uses template counts; summary cards preview display severity. Use enforce for aligned CI. "
          : "") +
        `This is a security rating, not a pass rate.`;
    }
  }

  function appendTextNode(parent, text) {
    parent.appendChild(document.createTextNode(String(text)));
  }

  function appendStrongText(parent, text) {
    const strong = document.createElement("strong");
    strong.textContent = String(text);
    parent.appendChild(strong);
  }

  function fillMetricsHeadline() {
    const el = document.getElementById("metrics-headline");
    if (!el) return;
    const s = activeSummary();
    const score = DATA.score?.overall ?? 0;
    const tools = DATA.meta?.tools_discovered || 0;
    const cs = DATA.checks_summary || {};
    const totalIssues = Number(s.total) || 0;
    const toolCount = Number(tools) || 0;
    const parts = [
      s.critical ? `${s.critical} critical` : null,
      s.high ? `${s.high} high` : null,
      s.medium ? `${s.medium} medium` : null,
      s.low ? `${s.low} low` : null,
    ].filter(Boolean);
    const breakdown = parts.length ? ` — ${parts.join(", ")}` : "";
    const issueWord = totalIssues === 1 ? "" : "s";
    const toolWord = toolCount === 1 ? "" : "s";

    el.replaceChildren();
    if (DATA.score_v2) {
      const v2 = DATA.score_v2;
      appendTextNode(el, "MCTS found ");
      appendStrongText(el, totalIssues);
      appendTextNode(el, ` security issue${issueWord} across `);
      appendStrongText(el, toolCount);
      appendTextNode(el, ` tool${toolWord}${breakdown}. Overall absolute risk is `);
      appendStrongText(el, v2.absolute_risk);
      appendTextNode(el, ` (${v2.risk_level}).`);
      if (v2.security_score != null) {
        appendTextNode(el, " Benchmark score: ");
        appendStrongText(el, `${v2.security_score}/100`);
        appendTextNode(el, ".");
      }
    } else {
      appendTextNode(el, "MCTS found ");
      appendStrongText(el, totalIssues);
      appendTextNode(el, ` issue${issueWord} across `);
      appendStrongText(el, toolCount);
      appendTextNode(el, ` tool${toolWord}${breakdown}. Security rating: `);
      appendStrongText(el, `${score}/100`);
      appendTextNode(el, " (higher is better, not a percentage).");
    }
    if (cs.analyzers_run) {
      appendTextNode(el, ` ${cs.analyzers_passed} of ${cs.analyzers_run} checks passed.`);
    }
  }

  function fillIssuesSummary() {
    const s = activeSummary();
    const totalEl = document.getElementById("issues-total");
    const totalFoot = document.getElementById("issues-table-total");
    const tbody = document.getElementById("issues-table-body");
    const toolsStat = document.getElementById("tools-stat");
    if (!tbody) return;

    const rows = [
      ["critical", s.critical],
      ["high", s.high],
      ["medium", s.medium],
      ["low", s.low],
    ];
    tbody.innerHTML = rows
      .map(([sev, count]) => {
        const interactive =
          count > 0
            ? ` class="card-interactive" data-card-action="filter-severity:${sev}" tabindex="0" role="button" aria-label="Show ${count} ${sev} issues"`
            : "";
        return `
      <tr${interactive}>
        <td><span class="sev-badge ${sev}">${sev}</span></td>
        <td class="issues-count">${count}</td>
        <td class="issues-meaning">${escapeHtml(SEVERITY_MEANINGS[sev])}${count > 0 ? ' <span class="row-cta">View →</span>' : ""}</td>
      </tr>`;
      })
      .join("");

    const total = s.total || 0;
    if (totalEl) totalEl.textContent = String(total);
    if (totalFoot) {
      totalFoot.replaceChildren();
      const strong = document.createElement("strong");
      strong.textContent = String(total);
      totalFoot.appendChild(strong);
    }
    if (toolsStat) {
      const tools = DATA.meta?.tools_discovered || 0;
      toolsStat.textContent = `${tools} MCP tool${tools === 1 ? "" : "s"} discovered and analyzed (not an issue count)`;
    }
  }

  function categoryBarColor(pct) {
    if (pct >= 0.9) return COLORS.critical;
    if (pct >= 0.65) return COLORS.orange;
    if (pct >= 0.35) return COLORS.yellow;
    return COLORS.low;
  }

  function fillScoreTooltip() {
    const tooltip = document.getElementById("score-tooltip");
    const help = DATA.score_help;
    if (!tooltip || !help) return;
    const lead =
      "<p><strong>0–100 security points</strong> (not a percentage). 100 = best, 0 = worst. Derived from finding severities.</p>";
    const items = (help.items || [])
      .map((item) => `<li>${escapeHtml(item)}</li>`)
      .join("");
    tooltip.innerHTML = `${lead}<strong>${escapeHtml(help.title || "Score derived from:")}</strong><ul>${items}</ul>`;
  }

  function fillExecutiveSummary() {
    const summary = DATA.executive_summary || {};
    const paras = document.getElementById("exec-paragraphs");
    const actions = document.getElementById("exec-actions");
    if (paras) {
      paras.innerHTML = (summary.paragraphs || [])
        .map((p) => `<p>${escapeHtml(p)}</p>`)
        .join("");
    }
    if (actions) {
      const recs = (DATA.recommendations || []).slice(0, 3);
      if (!recs.length && summary.recommended) {
        actions.innerHTML = summary.recommended
          .map(
            (item, idx) => `
          <div class="exec-action-item card-interactive" data-card-action="goto:recommendations" tabindex="0" role="button">
            <span class="priority-badge p2">P2 Recommended</span>
            <p>${escapeHtml(item)} <span class="row-cta">→</span></p>
          </div>`
          )
          .join("");
      } else {
        actions.innerHTML = recs
          .map(
            (r) => `
          <div class="exec-action-item card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(r.title)}" tabindex="0" role="button">
            <span class="priority-badge ${r.priority.toLowerCase()}">${r.priority} ${escapeHtml(r.impact)}</span>
            <p>${escapeHtml(r.recommendation)} <span class="row-cta">→</span></p>
          </div>`
          )
          .join("");
      }
    }
  }

  function fillSeverityCards() {
    /* Replaced by fillIssuesSummary — kept for compatibility with older cached HTML */
  }

  function navigateToSection(sectionId) {
    const sections = document.querySelectorAll(".page-section");
    const navItems = document.querySelectorAll(".nav-item");
    sections.forEach((s) => s.classList.toggle("active", s.id === sectionId));
    navItems.forEach((n) => n.classList.toggle("active", n.dataset.section === sectionId));
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function scrollToBlock(blockId) {
    const el = document.getElementById(blockId);
    if (!el) return;
    el.scrollIntoView({ behavior: "smooth", block: "start" });
    el.classList.add("card-flash");
    window.setTimeout(() => el.classList.remove("card-flash"), 1200);
  }

  function afterSectionSwitch(callback) {
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(callback);
    });
  }

  function findAnalyzer(name) {
    return (DATA.analyzers || []).find((row) => row.name === name);
  }

  function closeAnalyzerModal() {
    const modal = document.getElementById("analyzer-modal");
    const backdrop = document.getElementById("analyzer-modal-backdrop");
    if (modal) {
      modal.hidden = true;
      modal.setAttribute("aria-hidden", "true");
    }
    if (backdrop) {
      backdrop.hidden = true;
      backdrop.setAttribute("aria-hidden", "true");
    }
    document.body.classList.remove("modal-open");
  }

  function showAnalyzerModal(name) {
    const analyzer = findAnalyzer(name);
    const modal = document.getElementById("analyzer-modal");
    const backdrop = document.getElementById("analyzer-modal-backdrop");
    const content = document.getElementById("analyzer-modal-content");
    if (!analyzer || !modal || !backdrop || !content) return;

    const isPassed = analyzer.status === "passed";
    content.innerHTML = `
      <div class="analyzer-modal-head">
        <div>
          <h2 id="analyzer-modal-title">${escapeHtml(analyzer.label)}</h2>
          <p class="analyzer-modal-subtitle">${escapeHtml(analyzer.summary || "")}</p>
        </div>
        <span class="${isPassed ? "passed-pill" : "issues-pill"}">${isPassed ? "✓ Passed" : `${analyzer.finding_count} finding(s)`}</span>
      </div>
      ${
        !isPassed
          ? `<div class="analyzer-stats analyzer-modal-stats">
        ${Object.entries(analyzer.severity_counts || {})
          .filter(([, n]) => n > 0)
          .map(([s, n]) => `<span class="sev-badge ${s}">${s}: ${n}</span>`)
          .join("")}
      </div>`
          : ""
      }
      ${analyzerKnowledgeHtml(analyzer)}
    `;

    modal.hidden = false;
    modal.setAttribute("aria-hidden", "false");
    backdrop.hidden = false;
    backdrop.setAttribute("aria-hidden", "false");
    document.body.classList.add("modal-open");
    document.getElementById("analyzer-modal-close")?.focus();
  }

  function setupAnalyzerModal() {
    document.getElementById("analyzer-modal-close")?.addEventListener("click", closeAnalyzerModal);
    document.getElementById("analyzer-modal-backdrop")?.addEventListener("click", closeAnalyzerModal);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !document.getElementById("analyzer-modal")?.hidden) {
        closeAnalyzerModal();
      }
    });
  }

  function focusAnalyzer(analyzerName) {
    if (!analyzerName) return;
    const cardId = `analyzer-card-${analyzerName}`;
    const analyzersSection = document.getElementById("analyzers");
    const wasActive = analyzersSection?.classList.contains("active");
    if (!wasActive) {
      navigateToSection("analyzers");
    }
    const reveal = () => {
      const passedSection = document.getElementById("analyzer-passed-section");
      if (passedSection) passedSection.hidden = false;
      scrollToBlock(cardId);
      showAnalyzerModal(analyzerName);
    };
    if (wasActive) {
      reveal();
    } else {
      window.setTimeout(() => afterSectionSwitch(reveal), 120);
    }
  }

  function applyFindingsFilter({ severity, search } = {}) {
    const filterEl = document.getElementById("findings-filter");
    const searchEl = document.getElementById("findings-search");
    if (severity && filterEl) filterEl.value = severity;
    if (search !== undefined && searchEl) searchEl.value = search;
    renderFindingsTable();
    navigateToSection("findings");
    window.setTimeout(() => document.getElementById("findings-table")?.scrollIntoView({ behavior: "smooth" }), 80);
  }

  function handleCardAction(el) {
    const action = el?.dataset?.cardAction;
    if (!action) return;
    const idx = action.indexOf(":");
    const type = idx >= 0 ? action.slice(0, idx) : action;
    const inlineValue = idx >= 0 ? action.slice(idx + 1) : "";
    const value = el.dataset.cardValue || inlineValue;

    switch (type) {
      case "goto":
        if (value === "analyzers-passed" || value === "analyzers-issues") {
          navigateToSection("analyzers");
          window.setTimeout(
            () =>
              afterSectionSwitch(() =>
                scrollToBlock(
                  value === "analyzers-passed" ? "analyzer-passed-section" : "analyzer-issues-section"
                )
              ),
            120
          );
          return;
        }
        navigateToSection(value);
        break;
      case "focus-analyzer":
        if (value) focusAnalyzer(value);
        break;
      case "show-analyzer":
        if (value) showAnalyzerModal(value);
        break;
      case "filter-severity":
        if (value) applyFindingsFilter({ severity: value });
        break;
      case "filter-search":
        applyFindingsFilter({ search: value });
        break;
      case "scroll":
        navigateToSection("overview");
        window.setTimeout(() => scrollToBlock(value), 80);
        break;
      default:
        break;
    }
  }

  function setupInteractiveCards() {
    document.querySelectorAll("[data-card-action]").forEach((el) => {
      el.classList.add("card-interactive");
      if (!el.hasAttribute("tabindex")) el.setAttribute("tabindex", "0");
      if (!el.getAttribute("role")) el.setAttribute("role", "button");
    });

    document.addEventListener("click", (e) => {
      if (e.target.closest(".analyzer-view-findings")) {
        const el = e.target.closest("[data-card-action]");
        if (el) {
          e.preventDefault();
          e.stopPropagation();
          closeAnalyzerModal();
          handleCardAction(el);
        }
        return;
      }
      if (e.target.closest("a, button, input, select, textarea, .score-info-wrap")) return;
      const el = e.target.closest("[data-card-action]");
      if (!el) return;
      e.preventDefault();
      handleCardAction(el);
    });

    document.addEventListener("keydown", (e) => {
      if (e.key !== "Enter" && e.key !== " ") return;
      const el = e.target.closest("[data-card-action]");
      if (!el || e.target.closest("a, button, input, select, textarea")) return;
      e.preventDefault();
      handleCardAction(el);
    });

    document.querySelectorAll("[data-goto]").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const dest = btn.dataset.goto;
        if (dest === "analyzers-passed" || dest === "analyzers-issues") {
          handleCardAction({ dataset: { cardAction: `goto:${dest}` } });
        } else {
          navigateToSection(dest);
        }
      });
    });
  }

  function fillReportGuide() {
    const lead = document.getElementById("report-guide-lead");
    const steps = document.getElementById("report-guide-steps");
    const quick = document.getElementById("quick-jump");
    if (!lead || !steps || !quick) return;

    const s = activeSummary();
    const cs = DATA.checks_summary || {};
    const score = DATA.score?.overall ?? 0;
    const total = s.total || 0;
    const tools = DATA.meta?.tools_discovered || 0;

    let scoreLine;
    const v2 = DATA.score_v2;
    if (v2) {
      const band = String(v2.risk_level || "low");
      scoreLine =
        band === "low" || band === "medium"
          ? `Absolute risk ${v2.absolute_risk} (${band}) — review findings and harden before production.`
          : `Absolute risk ${v2.absolute_risk} (${band}) — treat Critical and High findings as urgent.`;
      if (v2.security_score != null) {
        scoreLine += ` Benchmark security score: ${v2.security_score}/100.`;
      }
    } else {
      scoreLine =
        score >= 80
          ? `Security rating: ${score}/100 points — strong posture with ${total} issue(s) to review (not a %).`
          : score >= 50
            ? `Security rating: ${score}/100 points — moderate risk (not a %). Address High findings to improve.`
            : `Security rating: ${score}/100 points — serious risk (not a %). Treat Critical and High findings as urgent.`;
    }

    lead.textContent = `MCTS scanned ${tools} tool(s), ran ${cs.analyzers_run || "—"} checks, and counted ${total} issue(s). ${scoreLine}`;

    const stepsList = DATA.score_v2
      ? [
          "<strong>Snapshot</strong> — absolute risk, issue counts, and which checks passed.",
          "<strong>What to do next</strong> — urgent findings and recommended fixes on this page.",
          "<strong>Issues to Fix</strong> — every finding with severity, location, and remediation.",
          "<strong>All Checks</strong> — what each analyzer inspected and whether it passed.",
          "<strong>How to Fix</strong> — prioritized steps (P1 = most urgent).",
        ]
      : [
          "<strong>Snapshot</strong> — security score, issue counts, and which checks passed.",
          "<strong>What to do next</strong> — urgent findings and recommended fixes on this page.",
          "<strong>Issues to Fix</strong> — every finding with severity, location, and remediation.",
          "<strong>All Checks</strong> — what each analyzer inspected and whether it passed.",
          "<strong>How to Fix</strong> — prioritized steps (P1 = most urgent).",
        ];
    steps.innerHTML = stepsList.map((line) => `<li>${line}</li>`).join("");

    const jumps = [
      ["findings", `${total} issue${total === 1 ? "" : "s"} to fix`, total > 0],
      ["analyzers", `${cs.analyzers_passed || 0} checks passed`, (cs.analyzers_passed || 0) > 0],
      ["recommendations", `${(DATA.recommendations || []).length} fix steps`, (DATA.recommendations || []).length > 0],
      ["attack-chains", "Attack paths", (DATA.attack_graph?.edges || []).length > 0],
    ];
    quick.innerHTML = jumps
      .filter(([, , show]) => show)
      .map(
        ([section, label]) =>
          `<button type="button" class="quick-jump-btn" data-goto="${section}">${escapeHtml(label)}</button>`
      )
      .join("");
    quick.querySelectorAll("[data-goto]").forEach((btn) => {
      btn.addEventListener("click", () => navigateToSection(btn.dataset.goto));
    });
  }

  function fillNavBadges() {
    const s = activeSummary();
    const cs = DATA.checks_summary || {};
    const findingsBadge = document.getElementById("nav-badge-findings");
    const analyzersBadge = document.getElementById("nav-badge-analyzers");
    const recsBadge = document.getElementById("nav-badge-recs");
    if (findingsBadge && s.total > 0) {
      findingsBadge.hidden = false;
      findingsBadge.textContent = String(s.total);
    }
    if (analyzersBadge && cs.analyzers_passed > 0) {
      analyzersBadge.hidden = false;
      analyzersBadge.textContent = `${cs.analyzers_passed}✓`;
    }
    if (recsBadge && DATA.recommendations?.length) {
      recsBadge.hidden = false;
      recsBadge.textContent = String(DATA.recommendations.length);
    }
  }

  function fillOverviewPanels() {
    const split = document.getElementById("overview-split");
    const topList = document.getElementById("overview-top-findings");
    const passedList = document.getElementById("overview-passed-list");
    if (!split || !topList || !passedList) return;

    const severityRank = { critical: 0, high: 1, medium: 2, low: 3 };
    const topFindings = [...(DATA.findings || [])]
      .sort((a, b) => (severityRank[findingSeverity(a)] ?? 9) - (severityRank[findingSeverity(b)] ?? 9))
      .slice(0, 6);
    const passed = (DATA.analyzers || []).filter((a) => a.status === "passed").slice(0, 6);

    if (!topFindings.length && !passed.length) {
      split.hidden = true;
    } else {
      split.hidden = false;
    }

    topList.innerHTML = topFindings.length
      ? topFindings
          .map(
            (f) => `
        <li class="card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(f.title)}" tabindex="0" role="button" aria-label="View finding: ${escapeHtml(f.title)}">
          <span class="sev-badge ${findingSeverity(f)}">${findingSeverity(f)}</span>${evidenceMaturityChip(f)}
          <span class="overview-list-text">${escapeHtml(f.title)} <span class="row-cta">→</span></span>
        </li>`
          )
          .join("")
      : `<li class="overview-empty">No issues found — great job.</li>`;

    passedList.innerHTML = passed.length
      ? passed
          .map(
            (a) =>
              `<li class="card-interactive overview-passed-item" data-card-action="show-analyzer" data-card-value="${escapeHtml(a.name)}" tabindex="0" role="button" aria-label="View ${escapeHtml(a.label)} check details">
                <div class="overview-passed-row">
                  <span class="passed-dot">✓</span>
                  <div class="overview-passed-text">
                    <strong>${escapeHtml(a.label)}</strong>
                    <span class="overview-list-summary">${escapeHtml(a.summary || "")}</span>
                  </div>
                  <span class="row-cta">→</span>
                </div>
              </li>`
          )
          .join("")
      : `<li class="overview-empty">No analyzers passed on this scan.</li>`;
  }

  function fillChecksSummary() {
    const section = document.getElementById("checks-section");
    const row = document.getElementById("checks-summary-row");
    const cs = DATA.checks_summary;
    if (!section || !row || !cs || !cs.analyzers_run) return;
    section.hidden = false;
    row.innerHTML = `
      <div class="checks-card neutral checks-card--wide card-interactive" data-card-action="goto:analyzers" tabindex="0" role="button" aria-label="View all security checks">
        <span class="card-cta">All checks →</span>
        <div class="checks-value checks-count">${cs.analyzers_run}</div>
        <div class="checks-label">Checks run <span class="checks-type-tag">count</span></div>
        <p class="checks-sublabel">How many analyzers executed — not a score out of 100</p>
      </div>
      <div class="checks-card passed card-interactive" data-card-action="goto:analyzers-passed" tabindex="0" role="button" aria-label="View passed checks">
        <span class="card-cta">Passed →</span>
        <div class="checks-value checks-count">${cs.analyzers_passed}</div>
        <div class="checks-label">Passed (no issues) <span class="checks-type-tag">count</span></div>
        <p class="checks-sublabel">${cs.analyzers_passed} of ${cs.analyzers_run} checks found nothing</p>
      </div>
      <div class="checks-card issues card-interactive" data-card-action="goto:analyzers-issues" tabindex="0" role="button" aria-label="View checks with findings">
        <span class="card-cta">With issues →</span>
        <div class="checks-value checks-count">${cs.analyzers_with_findings}</div>
        <div class="checks-label">Found issues <span class="checks-type-tag">count</span></div>
        <p class="checks-sublabel">${cs.analyzers_with_findings} of ${cs.analyzers_run} checks reported findings</p>
      </div>
      <div class="checks-card neutral card-interactive" data-card-action="scroll:breakdown-row" tabindex="0" role="button" aria-label="View risk categories">
        <span class="card-cta">Categories →</span>
        <div class="checks-value checks-count">${cs.categories_passed}/${cs.categories_total}</div>
        <div class="checks-label">Risk areas clear <span class="checks-type-tag">count</span></div>
        <p class="checks-sublabel">${cs.categories_passed} of ${cs.categories_total} grouped categories had zero findings</p>
      </div>`;
  }

  function fillCategories() {
    const list = document.getElementById("category-list");
    if (!list) return;
    list.innerHTML = DATA.categories
      .map((c) => {
        if (c.passed) {
          return `
        <li class="category-item category-item--passed card-interactive" data-card-action="goto:analyzers-passed" tabindex="0" role="button" aria-label="View passed checks for ${escapeHtml(c.label)}">
          <div class="category-item-header">
            <span class="name">${escapeHtml(c.label)}</span>
            <span class="score-val passed-badge">✓ Passed <span class="row-cta">→</span></span>
          </div>
          <div class="category-bar category-bar--passed"><span style="width:100%"></span></div>
        </li>`;
        }
        const pct = c.maximum > 0 ? c.score / c.maximum : 0;
        const barColor = categoryBarColor(pct);
        const width = Math.round(pct * 100);
        return `
        <li class="category-item card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(c.label)}" tabindex="0" role="button" aria-label="View findings for ${escapeHtml(c.label)}">
          <div class="category-item-header">
            <span class="name">${escapeHtml(c.label)}</span>
            <span class="score-val">${escapeHtml(c.display)} <span class="row-cta">→</span></span>
          </div>
          <div class="category-bar"><span style="width:${width}%;background:${barColor}"></span></div>
        </li>`;
      })
      .join("");
  }

  function initGaugeChart() {
    const canvas = document.getElementById("gauge-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const v2 = DATA.score_v2;
    const score =
      v2 && v2.security_score != null
        ? v2.security_score
        : DATA.score.overall;
    if (v2 && v2.security_score == null) return;

    const color = scoreGaugeColor(score);
    const visualScore = Math.max(score, MIN_GAUGE_ARC);
    const remainder = Math.max(0, 100 - visualScore);

    const gradient = canvas.getContext("2d");
    let fillColor = color;
    if (gradient) {
      const g = gradient.createLinearGradient(0, 0, 0, canvas.height);
      g.addColorStop(0, color);
      g.addColorStop(1, "rgba(239,68,68,0.25)");
      fillColor = g;
    }

    new Chart(canvas, {
      type: "doughnut",
      data: {
        datasets: [
          {
            data: [visualScore, remainder],
            backgroundColor: [fillColor, "rgba(255,255,255,0.05)"],
            borderWidth: 0,
            borderRadius: 6,
            circumference: 180,
            rotation: 270,
            spacing: 2,
          },
        ],
      },
      options: {
        responsive: false,
        maintainAspectRatio: false,
        cutout: "58%",
        plugins: { legend: { display: false }, tooltip: { enabled: false } },
        animation: { duration: 600 },
      },
    });
  }

  function initRadarChart() {
    const canvas = document.getElementById("radar-chart");
    if (!canvas || typeof Chart === "undefined") return;

    const labels = DATA.categories.map((c) => c.label.replace(" Risk", "").replace(" Resistance", ""));
    const yourScores = DATA.categories.map((c) => (c.score / c.maximum) * 100);
    const industry = DATA.categories.map((c) => (c.benchmark / c.maximum) * 100);

    new Chart(canvas, {
      type: "radar",
      data: {
        labels,
        datasets: [
          {
            label: "Your Score",
            data: yourScores,
            borderColor: COLORS.critical,
            backgroundColor: "rgba(239,68,68,0.15)",
            borderWidth: 2,
            pointRadius: 3,
          },
          {
            label: "Industry Average",
            data: industry,
            borderColor: COLORS.muted,
            backgroundColor: "rgba(100,116,139,0.1)",
            borderWidth: 2,
            pointRadius: 3,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        scales: {
          r: {
            beginAtZero: true,
            max: 100,
            ticks: { display: false, stepSize: 25 },
            grid: { color: COLORS.grid },
            angleLines: { color: COLORS.grid },
            pointLabels: { color: COLORS.text, font: { size: 11 } },
          },
        },
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: COLORS.text, boxWidth: 12, padding: 16 },
          },
        },
      },
    });
  }

  function trendSeriesKey() {
    return (DATA.trend_meta && DATA.trend_meta.series_key) || "score";
  }

  function trendValue(point) {
    if (point.trend_value != null) return Number(point.trend_value);
    const key = trendSeriesKey();
    if (key === "absolute_risk") return Number(point.absolute_risk) || 0;
    if (key === "security_score") return Number(point.security_score) || 0;
    return Number(point.score) || 0;
  }

  function trendValueLabel(value) {
    const key = trendSeriesKey();
    if (key === "absolute_risk") return `${value} risk`;
    return `${value} / 100 pts`;
  }

  function trendTableColumns(points) {
    const hasV2Risk = points.some((point) => point.absolute_risk != null);
    const hasRiskLevel = points.some((point) => point.risk_level);
    const hasSecurityScore = points.some((point) => point.security_score != null);
    const hasIssues = points.some((point) => point.findings_total != null);
    const hasCritical = points.some((point) => point.critical != null);
    const hasHigh = points.some((point) => point.high != null);
    const hasLegacyScore = points.some(
      (point) => point.scoring_version === "legacy" || (!hasV2Risk && point.score != null)
    );
    const columns = [{ key: "date", label: "Date" }];
    if (hasV2Risk) columns.push({ key: "absolute_risk", label: "Absolute risk", num: true });
    if (hasRiskLevel) columns.push({ key: "risk_level", label: "Risk level" });
    if (hasSecurityScore) columns.push({ key: "security_score", label: "Security score", num: true });
    if (hasIssues) columns.push({ key: "findings_total", label: "Issues", num: true });
    if (hasCritical) columns.push({ key: "critical", label: "Critical", num: true });
    if (hasHigh) columns.push({ key: "high", label: "High", num: true });
    if (hasLegacyScore) columns.push({ key: "score", label: "Legacy score", num: true });
    return columns;
  }

  function trendTableCell(point, column) {
    if (column.key === "date") return escapeHtml(point.date || "—");
    if (column.key === "risk_level") {
      const level = point.risk_level ? String(point.risk_level).toLowerCase() : "";
      if (!level) return "—";
      return `<span class="sev-badge ${escapeHtml(level)}">${escapeHtml(level)}</span>`;
    }
    const value = point[column.key];
    if (value == null || value === "") return "—";
    if (column.key === "absolute_risk") return escapeHtml(String(value));
    if (column.key === "security_score" || column.key === "score") return escapeHtml(`${value} / 100`);
    return escapeHtml(String(value));
  }

  function renderTrendTable(points) {
    const wrap = document.getElementById("trend-table-wrap");
    if (!wrap || !points.length) return;
    wrap.hidden = false;
    const columns = trendTableColumns(points);
    const header = columns
      .map((column) => `<th${column.num ? ' class="num"' : ""}>${escapeHtml(column.label)}</th>`)
      .join("");
    const rows = points
      .map((point) => {
        const cells = columns
          .map(
            (column) =>
              `<td${column.num ? ' class="num"' : ""}>${trendTableCell(point, column)}</td>`
          )
          .join("");
        return `<tr>${cells}</tr>`;
      })
      .join("");
    wrap.innerHTML = `<table class="trend-table" aria-label="Scan history"><thead><tr>${header}</tr></thead><tbody>${rows}</tbody></table>`;
  }

  function trendYRange(values) {
    if (!values.length) return { min: 0, max: 100 };
    const minVal = Math.min(...values);
    const maxVal = Math.max(...values);
    const isLegacyScore = trendSeriesKey() === "score" || trendSeriesKey() === "security_score";
    if (minVal === maxVal) {
      if (isLegacyScore) {
        if (minVal <= 5) return { min: 0, max: 25 };
        if (minVal >= 95) return { min: 75, max: 100 };
      }
      const pad = Math.max(8, Math.round(Math.max(minVal * 0.15, 10)));
      return {
        min: Math.max(0, minVal - pad),
        max: isLegacyScore ? Math.min(100, maxVal + pad) : maxVal + pad,
      };
    }
    const pad = Math.max(4, Math.round((maxVal - minVal) * 0.12));
    return {
      min: Math.max(0, minVal - pad),
      max: isLegacyScore ? Math.min(100, maxVal + pad) : maxVal + pad,
    };
  }

  function trendChartWidth(wrap) {
    wrap.hidden = false;
    wrap.setAttribute("aria-hidden", "false");
    let w = wrap.clientWidth;
    if (w < 2 && wrap.parentElement) {
      w = wrap.parentElement.clientWidth;
    }
    return Math.max(320, Math.round(w) || 640);
  }

  function renderTrendSparkline(points) {
    const wrap = document.getElementById("trend-chart-wrap");
    if (!wrap || !points.length) return;

    const values = points.map((p) => trendValue(p));
    const { min: yMin, max: yMax } = trendYRange(values);
    const width = trendChartWidth(wrap);
    const height = 160;
    const pad = { top: 18, right: 20, bottom: 36, left: 44 };
    const innerW = width - pad.left - pad.right;
    const innerH = height - pad.top - pad.bottom;
    const count = points.length;
    const allSame = values.every((v) => v === values[0]);

    const xAt = (index) =>
      count === 1
        ? pad.left + innerW / 2
        : pad.left + (index / (count - 1)) * innerW;
    const yAt = (score) => {
      const span = Math.max(1, yMax - yMin);
      const norm = (score - yMin) / span;
      return pad.top + innerH - norm * innerH;
    };

    const coords = values.map((score, index) => ({ x: xAt(index), y: yAt(score) }));
    const linePath =
      coords.length >= 2
        ? coords
            .map((pt, index) => `${index === 0 ? "M" : "L"}${pt.x.toFixed(1)},${pt.y.toFixed(1)}`)
            .join(" ")
        : "";
    const areaPath =
      coords.length >= 2
        ? `${linePath} L${coords[coords.length - 1].x.toFixed(1)},${(pad.top + innerH).toFixed(1)} L${coords[0].x.toFixed(1)},${(pad.top + innerH).toFixed(1)} Z`
        : "";
    const dots = coords
      .map(
        (pt, index) =>
          `<circle class="trend-dot" cx="${pt.x.toFixed(1)}" cy="${pt.y.toFixed(1)}" r="${count === 1 ? 7 : 5}" tabindex="0"><title>${escapeHtml(points[index].date)}: ${escapeHtml(trendValueLabel(values[index]))}</title></circle>`
      )
      .join("");
    const gridLines = [0, 0.5, 1]
      .map((frac) => {
        const y = pad.top + innerH * (1 - frac);
        const label = Math.round(yMin + (yMax - yMin) * frac);
        return `<line class="trend-grid-line" x1="${pad.left}" y1="${y.toFixed(1)}" x2="${(pad.left + innerW).toFixed(1)}" y2="${y.toFixed(1)}"/><text class="trend-axis-label" x="${pad.left - 8}" y="${(y + 4).toFixed(1)}" text-anchor="end">${label}</text>`;
      })
      .join("");
    const xLabels =
      count <= 6
        ? points
            .map(
              (point, index) =>
                `<text class="trend-axis-label" x="${xAt(index).toFixed(1)}" y="${(height - 10).toFixed(1)}" text-anchor="middle">${escapeHtml(point.date)}</text>`
            )
            .join("")
        : `<text class="trend-axis-label" x="${pad.left.toFixed(1)}" y="${(height - 10).toFixed(1)}" text-anchor="start">${escapeHtml(points[0].date)}</text><text class="trend-axis-label" x="${(pad.left + innerW).toFixed(1)}" y="${(height - 10).toFixed(1)}" text-anchor="end">${escapeHtml(points[count - 1].date)}</text>`;
    const flatLabel =
      allSame && count > 1
        ? `<text class="trend-flat-label" x="${(pad.left + innerW / 2).toFixed(1)}" y="${(pad.top + 14).toFixed(1)}" text-anchor="middle">Flat at ${escapeHtml(trendValueLabel(values[0]))} across ${count} scans</text>`
        : "";

    wrap.innerHTML = `<svg class="trend-sparkline" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Security score trend over ${count} scans">${gridLines}${areaPath ? `<path d="${areaPath}" fill="rgba(239,68,68,0.12)" stroke="none"/>` : ""}${linePath ? `<path class="trend-line" d="${linePath}"/>` : ""}${dots}${xLabels}${flatLabel}</svg>`;
  }

  let trendResizeTimer = null;
  function scheduleTrendSparklineResize() {
    if (trendResizeTimer) window.clearTimeout(trendResizeTimer);
    trendResizeTimer = window.setTimeout(() => {
      const points = DATA.trend || [];
      if (points.length) renderTrendSparkline(points);
    }, 120);
  }

  function fillTrendNote() {
    const note = document.getElementById("trend-note");
    const meta = DATA.trend_meta || {};
    const points = DATA.trend || [];
    if (!note) return;
    if (points.length === 1) {
      note.hidden = false;
      note.textContent =
        "1 scan recorded — run mcts scan again from the same project folder to compare over time.";
      return;
    }
    if (meta.mixed_metrics) {
      note.hidden = false;
      note.textContent =
        "History mixes legacy and v2 scoring — chart shows legacy security score only. Re-scan with a consistent --scoring mode for comparable trends.";
      return;
    }
    if (meta.score_unchanged && points.length > 1) {
      note.hidden = false;
      const suffix = meta.series_label ? ` (${meta.series_label})` : "";
      note.textContent = `${meta.runs} scans recorded — value unchanged at ${trendValueLabel(meta.latest_score)}${suffix}.`;
      return;
    }
    if (meta.runs >= 2) {
      note.hidden = false;
      const suffix = meta.series_label ? ` ${meta.series_label}` : "";
      note.textContent = `${meta.runs} scans recorded for this target.${suffix}`;
      return;
    }
    note.hidden = true;
  }

  function initTrendChart() {
    const chartWrap = document.getElementById("trend-chart-wrap");
    const empty = document.getElementById("trend-empty");
    const emptyTitle = document.getElementById("trend-empty-title");
    const emptyText = document.getElementById("trend-empty-text");
    const tableWrap = document.getElementById("trend-table-wrap");
    const points = DATA.trend || [];

    if (!points.length) {
      if (chartWrap) {
        chartWrap.hidden = true;
        chartWrap.setAttribute("aria-hidden", "true");
        chartWrap.innerHTML = "";
      }
      if (tableWrap) tableWrap.hidden = true;
      if (empty) {
        empty.hidden = false;
        empty.classList.add("visible");
        if (emptyTitle) emptyTitle.textContent = "No scan history yet";
        if (emptyText) {
          emptyText.innerHTML =
            "Each <code>mcts scan</code> appends to <code>mcts_analysis/history.json</code> in your project folder. Run at least two scans from the same directory, then open <code>mcts_analysis/scan-report.html</code>.";
        }
      }
      return;
    }

    fillTrendNote();
    renderTrendSparkline(points);
    renderTrendTable(points);
    window.requestAnimationFrame(() => {
      window.requestAnimationFrame(() => renderTrendSparkline(points));
    });

    if (empty) {
      empty.hidden = true;
      empty.classList.remove("visible");
    }
  }

  function fillRiskGuide() {
    const container = document.getElementById("risk-guide");
    if (!container) return;
    if (DATA.score_v2) {
      const bands = [
        ["low", "0 – 99", COLORS.low],
        ["medium", "100 – 249", COLORS.medium],
        ["high", "250 – 499", COLORS.high],
        ["critical", "500+", COLORS.critical],
      ];
      const active = String(DATA.score_v2.risk_level || "low").toLowerCase();
      container.innerHTML = bands
        .map(([key, range, color]) => {
          const isActive = key === active;
          return `<div class="guide-card${isActive ? " active" : ""}">
            <h4>${escapeHtml(key.toUpperCase())}</h4>
            <div class="range">Absolute risk ${escapeHtml(range)}</div>
            <div class="guide-badge" style="color:${color}">${isActive ? "Current band" : ""}</div>
            <p>v2 multi-factor sum — higher = worse.</p>
          </div>`;
        })
        .join("");
      return;
    }
    const score = DATA.score.overall;
    const iconMap = {
      critical: "critical",
      high: "high",
      medium: "medium",
      low: "low",
    };
    container.innerHTML = DATA.risk_guide
      .map((g) => {
        const parts = g.range.replace("–", "-").split("-").map(Number);
        const min = parts[0] ?? 0;
        const max = parts[1] ?? 100;
        const active = score >= min && score <= max;
        const fill = active ? 100 : Math.max(12, 40 - Math.abs(score - (min + max) / 2) * 0.5);
        const iconName = iconMap[g.key] || "shield";
        return `
        <div class="guide-card card-interactive${active ? " active" : ""}" data-card-action="scroll:score-card" tabindex="0" role="button" aria-label="View security score for ${escapeHtml(g.label)} range">
          <span class="card-cta">Score →</span>
          <div class="guide-card-top" style="background:${g.color}"></div>
          <div class="guide-card-icon">${icon(iconName, iconName)}</div>
          <h4>${escapeHtml(g.label)}</h4>
          <div class="range">Score ${escapeHtml(g.range)} pts</div>
          <div class="guide-badge" style="color:${g.color}">${escapeHtml(g.badge)}</div>
          <p>${escapeHtml(g.description)}</p>
          <div class="guide-progress"><span style="width:${fill}%;background:${g.color}"></span></div>
        </div>`;
      })
      .join("");
  }

  function formatMitigationLinks(links) {
    if (!links || !links.length) return "";
    return links
      .map(
        (link) =>
          `<a href="${escapeHtml(link.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.id)}</a>`
      )
      .join(" · ");
  }

  function formatFactsTable(facts) {
    if (!facts || !facts.length) return "";
    const rows = facts
      .map(
        (fact) => `
        <tr>
          <td><code>${escapeHtml(fact.rule_id || "—")}</code></td>
          <td>${escapeHtml(fact.tool || "—")}</td>
          <td>${escapeHtml(fact.field || "—")}</td>
          <td><code>${escapeHtml(fact.match || "—")}</code></td>
          <td>${escapeHtml(fact.file || "—")}${fact.line ? `:${fact.line}` : ""}</td>
        </tr>
        ${fact.snippet ? `<tr class="finding-fact-snippet"><td colspan="5"><pre>${escapeHtml(fact.snippet)}</pre></td></tr>` : ""}`
      )
      .join("");
    return `
      <table class="finding-facts-table">
        <thead><tr><th>Rule</th><th>Tool</th><th>Field</th><th>Match</th><th>Location</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>`;
  }

  function formatEvidenceBlock(finding) {
    const evidence = finding.evidence || {};
    const facts = finding.facts || evidence.facts || [];
    const factors = finding.confidence_factors || evidence.confidence_factors || [];
    const interpretation = finding.interpretation || evidence.interpretation;
    if (!Object.keys(evidence).length && !facts.length) {
      return '<p class="finding-evidence-empty">No structured evidence recorded.</p>';
    }
    let html = "";
    if (facts.length) {
      html += `<div class="finding-evidence-section"><strong>Matched signals</strong>${formatFactsTable(facts)}</div>`;
    }
    if (factors.length) {
      html += `<div class="finding-evidence-section"><strong>Confidence factors</strong><ul class="finding-confidence-list">${factors
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul></div>`;
    }
    if (interpretation && interpretation.mcp_context) {
      const ctx = interpretation.mcp_context;
      html += `<div class="finding-evidence-section"><strong>MCP context</strong><p class="finding-mcp-context">${escapeHtml(
        Object.entries(ctx)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(", ") : value}`)
          .join(" · ")
      )}</p></div>`;
    }
    const counterfactual = evidence.counterfactual_remediation || finding.counterfactual_remediation;
    if (counterfactual && (counterfactual.triggered_by || counterfactual.actions)) {
      const triggers = counterfactual.triggered_by || [];
      const actions = counterfactual.actions || [];
      html += `<div class="finding-evidence-section"><strong>What triggered this</strong><ul class="finding-confidence-list">${triggers
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul>`;
      if (actions.length) {
        html += `<strong>Remediation options</strong><ul class="finding-confidence-list">${actions
          .map((row) => `<li>${escapeHtml(row.action || row.removes || "")}</li>`)
          .join("")}</ul>`;
      }
      if (counterfactual.removing_any_one_eliminates_finding) {
        html += `<p class="finding-mcp-context">Removing any one signal may clear this finding.</p>`;
      }
      html += `</div>`;
    }
    const fpConditions = finding.false_positive_conditions || evidence.false_positive_conditions;
    if (fpConditions && fpConditions.length) {
      html += `<div class="finding-evidence-section"><strong>False positive when</strong><ul class="finding-confidence-list">${fpConditions
        .map((item) => `<li>${escapeHtml(item)}</li>`)
        .join("")}</ul></div>`;
    }
    if (finding.evidence_tier || evidence.evidence_tier) {
      html += `<p class="finding-mcp-context">Evidence tier: ${escapeHtml(
        finding.evidence_tier || evidence.evidence_tier
      )}</p>`;
    }
    html += `<details class="finding-evidence-raw"><summary>Raw evidence JSON</summary><pre class="finding-evidence-json">${escapeHtml(
      JSON.stringify(evidence, null, 2)
    )}</pre></details>`;
    return html;
  }

  function renderFindingsTable() {
    const tbody = document.getElementById("findings-body");
    if (!tbody) return;

    let rows = [...DATA.findings];
    const search = (document.getElementById("findings-search")?.value || "").toLowerCase();
    const filter = document.getElementById("findings-filter")?.value || "all";

    if (search) {
      rows = rows.filter(
        (f) =>
          f.title.toLowerCase().includes(search) ||
          f.category.toLowerCase().includes(search) ||
          f.tool.toLowerCase().includes(search) ||
          (f.location || "").toLowerCase().includes(search) ||
          (f.technique_id || "").toLowerCase().includes(search) ||
          (f.cwe_id || "").toLowerCase().includes(search) ||
          (f.evidence_summary || "").toLowerCase().includes(search)
      );
    }
    if (filter !== "all") {
      rows = rows.filter((f) => findingSeverity(f) === filter);
    }

    tbody.innerHTML = rows
      .map(
        (f) => `
      <tr class="finding-row${f.has_evidence || f.has_provenance ? " finding-row--expandable" : ""}" data-finding-id="${escapeHtml(f.id)}"${f.has_evidence || f.has_provenance ? ' tabindex="0" role="button" aria-expanded="false"' : ""}>
        <td><span class="sev-badge ${findingSeverity(f)}">${findingSeverity(f)}</span>${evidenceMaturityChip(f)}${ruleStabilityChip(f)}</td>
        <td><strong>${escapeHtml(f.title)}</strong><br><span style="color:var(--muted);font-size:12px">${escapeHtml(f.description)}</span>${
          f.has_evidence || f.has_provenance
            ? `<div class="finding-expand-hint">${escapeHtml(f.evidence_summary || "View evidence")} <span class="row-cta">Details ↓</span></div>`
            : ""
        }</td>
        <td class="findings-location">${escapeHtml(f.location || "—")}</td>
        <td class="findings-technique">${
          f.technique_url
            ? `<a href="${escapeHtml(f.technique_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(
                f.technique_id
              )}</a>`
            : escapeHtml(f.technique_id || "—")
        }</td>
        <td>${escapeHtml(f.cwe_id || "—")}</td>
        <td>${escapeHtml(f.category)}</td>
        <td>${escapeHtml(f.owasp)}</td>
        <td>${escapeHtml(f.tool)}</td>
        <td><span class="confidence-badge" title="Analyzer confidence">${escapeHtml(f.confidence_display || "—")}</span></td>
        <td>${escapeHtml(f.recommendation)}${
          f.mitigation_links && f.mitigation_links.length
            ? `<div style="margin-top:6px;font-size:12px">MCTS mitigations: ${formatMitigationLinks(
                f.mitigation_links
              )}</div>`
            : ""
        }</td>
      </tr>${
        f.has_evidence || f.has_provenance
          ? `<tr class="finding-detail-row" data-detail-for="${escapeHtml(f.id)}" hidden>
        <td colspan="10">
          <div class="finding-detail-panel">
            <strong>Evidence</strong> · confidence ${escapeHtml(f.confidence_display || "—")}
            ${formatEvidenceBlock(f)}
          </div>
        </td>
      </tr>`
          : ""
      }`
      )
      .join("");

    tbody.querySelectorAll(".finding-row--expandable").forEach((row) => {
      row.addEventListener("click", (event) => {
        if (event.target.closest("a")) return;
        toggleFindingDetail(row);
      });
      row.addEventListener("keydown", (event) => {
        if (event.key !== "Enter" && event.key !== " ") return;
        if (event.target.closest("a")) return;
        event.preventDefault();
        toggleFindingDetail(row);
      });
    });
  }

  function toggleFindingDetail(row) {
    const id = row.dataset.findingId;
    const detail = document.querySelector(`tr.finding-detail-row[data-detail-for="${CSS.escape(id)}"]`);
    if (!detail) return;
    const open = detail.hidden;
    detail.hidden = !open;
    row.setAttribute("aria-expanded", open ? "true" : "false");
    row.classList.toggle("finding-row--open", open);
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  let sortKey = "severity";
  let sortAsc = true;

  function sortFindings(key) {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    if (sortKey === key) sortAsc = !sortAsc;
    else {
      sortKey = key;
      sortAsc = true;
    }
    DATA.findings.sort((a, b) => {
      let cmp = 0;
      if (key === "severity") cmp = (order[findingSeverity(a)] ?? 9) - (order[findingSeverity(b)] ?? 9);
      else cmp = String(a[key] || "").localeCompare(String(b[key] || ""));
      return sortAsc ? cmp : -cmp;
    });
    renderFindingsTable();
  }

  function renderOwaspCard(o, { gap = false } = {}) {
    if (gap || o.status === "gap") {
      return `
      <div class="card owasp-card owasp-card--gap card-interactive" tabindex="0" role="button" aria-label="Coverage gap for ${escapeHtml(o.id)}">
        <span class="owasp-gap-badge">Coverage gap</span>
        <h4>${escapeHtml(o.id)} — ${escapeHtml(o.label)}</h4>
        <p style="color:var(--muted);font-size:13px;margin:0">No findings from analyzers mapped to this LLM category. Enable additional checks or expand scan scope for full Top 10 coverage.</p>
      </div>`;
    }
    return `
      <div class="card owasp-card card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(o.id)}" tabindex="0" role="button" aria-label="View findings for ${escapeHtml(o.id)}">
        <span class="card-cta">View issues →</span>
        <h4>${escapeHtml(o.id)} — ${escapeHtml(o.label)}</h4>
        <div class="meta-row">
          <span>Findings: <strong>${o.finding_count}</strong></span>
          <span>Risk: <span class="sev-badge ${o.risk_level}">${o.risk_level}</span></span>
        </div>
        <div class="owasp-tools">Affected tools: ${o.affected_tools.length ? escapeHtml(o.affected_tools.join(", ")) : "—"}</div>
      </div>`;
  }

  function renderOwasp() {
    const grid = document.getElementById("owasp-grid");
    const lead = document.getElementById("owasp-llm-lead");
    const llm = DATA.owasp || {};
    const categories = llm.categories || (Array.isArray(DATA.owasp) ? DATA.owasp : []);
    if (!grid) return;

    if (lead && llm.gap_count > 0) {
      lead.textContent = `${llm.gap_count} LLM categor${llm.gap_count === 1 ? "y has" : "ies have"} coverage gaps — no findings from mapped analyzers (mirrors compliance meta-checks).`;
    } else if (lead && categories.length) {
      lead.textContent = "Industry-standard LLM application security categories mapped from analyzer findings.";
    }

    if (!categories.length) {
      grid.innerHTML =
        '<p style="color:var(--muted)">No OWASP LLM mappings for this scan — run a scan with scorable findings to populate coverage.</p>';
      return;
    }

    grid.innerHTML = categories.map((o) => renderOwaspCard(o)).join("");
  }

  let techniqueFilter = "all";

  function renderTechniqueCard(t) {
    const detectedRow = t.finding_count > 0;
    return `
      <div class="card technique-card${detectedRow ? " technique-card--detected" : " technique-card--clear"} card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(t.id)}" tabindex="0" role="button">
        <span class="card-cta">${detectedRow ? "View issues →" : "Clear"}</span>
        <h4>${
          t.technique_url
            ? `<a href="${escapeHtml(t.technique_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(t.id)}</a>`
            : escapeHtml(t.id)
        }</h4>
        <p class="technique-name">${escapeHtml(t.name || t.id)}</p>
        <div class="meta-row">
          <span>Findings: <strong>${t.finding_count || 0}</strong></span>
          ${
            t.risk_level
              ? `<span>Risk: <span class="sev-badge ${t.risk_level}">${t.risk_level}</span></span>`
              : `<span>Status: <strong>Clear</strong></span>`
          }
        </div>
        ${t.tactic ? `<div class="technique-meta">Tactic: ${escapeHtml(t.tactic)}</div>` : ""}
        ${t.cwe ? `<div class="technique-meta">CWE: ${escapeHtml(t.cwe)}</div>` : ""}
      </div>`;
  }

  function renderTechniqueMap() {
    const grid = document.getElementById("technique-grid");
    const lead = document.getElementById("technique-map-lead");
    const toolbar = document.getElementById("technique-toolbar");
    const map = DATA.technique_map || {};
    const rows = map.techniques || (Array.isArray(DATA.technique_map) ? DATA.technique_map : []);
    if (!grid) return;

    const detected = rows.filter((r) => r.finding_count > 0);
    const clear = rows.filter((r) => !r.finding_count);
    if (lead) {
      const total = map.total || rows.length;
      lead.textContent = `${detected.length} of ${total} MCTS-T technique(s) triggered in this scan (${clear.length} clear). Full regression catalog shown below.`;
    }

    let visible = rows;
    if (techniqueFilter === "detected") visible = detected;
    else if (techniqueFilter === "clear") visible = clear;

    if (!visible.length) {
      grid.innerHTML = `<p style="color:var(--muted)">No techniques match the “${escapeHtml(techniqueFilter)}” filter.</p>`;
    } else {
      grid.innerHTML = visible.map(renderTechniqueCard).join("");
    }

    if (toolbar && !toolbar.dataset.bound) {
      toolbar.dataset.bound = "1";
      toolbar.querySelectorAll(".technique-filter").forEach((btn) => {
        btn.addEventListener("click", () => {
          techniqueFilter = btn.dataset.filter || "all";
          toolbar.querySelectorAll(".technique-filter").forEach((el) => {
            el.classList.toggle("active", el === btn);
          });
          renderTechniqueMap();
        });
      });
    }
  }

  function renderCapabilityMatrix() {
    const wrap = document.getElementById("capability-matrix");
    const lead = document.getElementById("capability-matrix-lead");
    const matrix = DATA.capability_matrix || {};
    const tools = matrix.tools || [];
    const dims = matrix.dimensions || [];
    if (!wrap) return;

    if (lead) {
      lead.textContent = tools.length
        ? `${tools.length} tool(s) × ${dims.length} inferred capability dimensions.`
        : "No tools discovered — capability matrix requires tool metadata from the scan.";
    }

    if (!tools.length || !dims.length) {
      wrap.innerHTML = '<p style="color:var(--muted)">No capability data for this scan.</p>';
      return;
    }

    const head = dims.map((d) => `<th>${escapeHtml(d.label)}</th>`).join("");
    const body = tools
      .map(
        (tool) => `
      <tr>
        <th scope="row" class="cap-tool-name">${escapeHtml(tool.name)}</th>
        ${dims
          .map((d) => {
            const on = tool.flags && tool.flags[d.key];
            return `<td class="cap-cell${on ? " cap-cell--on" : ""}" aria-label="${escapeHtml(tool.name)} ${escapeHtml(d.label)}: ${on ? "yes" : "no"}">${on ? "●" : "—"}</td>`;
          })
          .join("")}
      </tr>`
      )
      .join("");

    wrap.innerHTML = `<div class="capability-table-wrap"><table class="capability-table" aria-label="Tool capability matrix"><thead><tr><th>Tool</th>${head}</tr></thead><tbody>${body}</tbody></table></div>`;
  }

  function renderOwaspMcp() {
    const grid = document.getElementById("owasp-mcp-grid");
    const lead = document.getElementById("owasp-mcp-lead");
    const mcp = DATA.owasp_mcp || {};
    const categories = mcp.categories || [];
    if (!grid) return;

    if (lead && mcp.gap_count > 0) {
      lead.textContent = `${mcp.gap_count} MCP categor${mcp.gap_count === 1 ? "y has" : "ies have"} coverage gaps — no findings from mapped analyzers (mirrors compliance meta-checks).`;
    } else if (lead && categories.length) {
      lead.textContent = "MCP-specific risk categories mapped from analyzer findings.";
    }

    if (!categories.length) {
      grid.innerHTML =
        '<p style="color:var(--muted)">No OWASP MCP mappings for this scan — run a scan with scorable findings to populate coverage.</p>';
      return;
    }

    grid.innerHTML = categories
      .map((o) => {
        if (o.status === "gap") {
          return `
      <div class="card owasp-card owasp-card--gap card-interactive" data-card-action="goto:owasp" tabindex="0" role="button" aria-label="Coverage gap for ${escapeHtml(o.id)}">
        <span class="owasp-gap-badge">Coverage gap</span>
        <h4>${escapeHtml(o.id)} — ${escapeHtml(o.label)}</h4>
        <p style="color:var(--muted);font-size:13px;margin:0">No findings from analyzers mapped to this MCP category. Enable additional checks or expand scan scope for full Top 10 coverage.</p>
      </div>`;
        }
        return `
      <div class="card owasp-card card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(o.id)}" tabindex="0" role="button" aria-label="View findings for ${escapeHtml(o.id)}">
        <span class="card-cta">View issues →</span>
        <h4>${escapeHtml(o.id)} — ${escapeHtml(o.label)}</h4>
        <div class="meta-row">
          <span>Findings: <strong>${o.finding_count}</strong></span>
          <span>Risk: <span class="sev-badge ${o.risk_level}">${o.risk_level}</span></span>
        </div>
        <div class="owasp-tools">Affected tools: ${o.affected_tools.length ? escapeHtml(o.affected_tools.join(", ")) : "—"}</div>
      </div>`;
      })
      .join("");
  }

  function renderRecommendations() {
    const list = document.getElementById("rec-list");
    if (!list) return;
    if (!DATA.recommendations.length) {
      list.innerHTML = '<p style="color:var(--muted)">No recommendations — scan passed cleanly.</p>';
      return;
    }
    list.innerHTML = DATA.recommendations
      .map(
        (r) => `
      <div class="card rec-card card-interactive" data-card-action="filter-search" data-card-value="${escapeHtml(r.title)}" tabindex="0" role="button" aria-label="View related finding: ${escapeHtml(r.title)}">
        <span class="card-cta">Related issue →</span>
        <div class="rec-priority">Priority ${r.priority}</div>
        <h4>${escapeHtml(r.title)}</h4>
        <p style="color:var(--muted);margin:0 0 10px">${escapeHtml(r.recommendation)}</p>
        ${
          r.mitigation_links && r.mitigation_links.length
            ? `<p style="font-size:12px;margin:0 0 10px">MCTS mitigations: ${formatMitigationLinks(
                r.mitigation_links
              )}</p>`
            : ""
        }
        <div class="rec-meta">
          <span>Impact: <strong>${escapeHtml(r.impact)}</strong></span>
          <span>Effort: <strong>${escapeHtml(r.effort)}</strong></span>
        </div>
      </div>`
      )
      .join("");
  }

  function analyzerKnowledgeHtml(a, { compact = false } = {}) {
    const owaspParts = [];
    if (a.owasp_llm) owaspParts.push(`LLM ${a.owasp_llm}`);
    if (a.owasp_mcp) owaspParts.push(`MCP ${a.owasp_mcp}`);
    const techniqueLinks = (a.technique_urls || [])
      .map(
        (t) =>
          `<a href="${escapeHtml(t.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(t.id)}</a>`
      )
      .join(" · ");
    const findingList =
      a.finding_titles && a.finding_titles.length
        ? `<ul class="analyzer-finding-list">${a.finding_titles
            .map((title) => `<li>${escapeHtml(title)}</li>`)
            .join("")}${a.finding_count > a.finding_titles.length ? `<li>…and ${a.finding_count - a.finding_titles.length} more</li>` : ""}</ul>`
        : "";
    if (compact) {
      return `
        <div class="analyzer-knowledge analyzer-knowledge--compact">
          <p class="analyzer-knowledge-summary">${escapeHtml(a.summary || "")}</p>
        </div>`;
    }
    return `
      <div class="analyzer-knowledge">
        <p class="analyzer-knowledge-label">What this check does</p>
        <p class="analyzer-knowledge-summary">${escapeHtml(a.summary || "")}</p>
        <p class="analyzer-knowledge-label">Looks for</p>
        <p class="analyzer-knowledge-body">${escapeHtml(a.looks_for || "")}</p>
        ${
          a.status === "passed" && a.passed_note
            ? `<p class="analyzer-knowledge-label">What “passed” means</p><p class="analyzer-knowledge-body analyzer-knowledge-note">${escapeHtml(a.passed_note)}</p>`
            : ""
        }
        ${
          owaspParts.length
            ? `<p class="analyzer-knowledge-label">Framework mapping</p><p class="analyzer-knowledge-body">${escapeHtml(owaspParts.join(" · "))}</p>`
            : ""
        }
        ${
          techniqueLinks
            ? `<p class="analyzer-knowledge-label">Related techniques</p><p class="analyzer-knowledge-body">${techniqueLinks}</p>`
            : ""
        }
        ${
          findingList
            ? `<p class="analyzer-knowledge-label">Findings from this check</p>${findingList}<button type="button" class="analyzer-view-findings" data-card-action="filter-search" data-card-value="${escapeHtml(a.label)}">View all in Issues →</button>`
            : ""
        }
        <p class="analyzer-knowledge-id"><code>${escapeHtml(a.name)}</code></p>
      </div>`;
  }

  function analyzerCardHtml(a) {
    const isPassed = a.status === "passed";
    return `
      <div id="analyzer-card-${escapeHtml(a.name)}" class="card analyzer-card analyzer-card--${isPassed ? "passed" : "issues"} card-interactive" data-card-action="show-analyzer" data-card-value="${escapeHtml(a.name)}" tabindex="0" role="button" aria-label="${isPassed ? "Passed" : "Issues"} check: ${escapeHtml(a.label)}">
        <div class="analyzer-card-head">
          <h4>${escapeHtml(a.label)}</h4>
          <span class="${isPassed ? "passed-pill" : "issues-pill"}">${isPassed ? "✓ Passed" : `${a.finding_count} finding(s)`}</span>
        </div>
        ${analyzerKnowledgeHtml(a, { compact: true })}
        ${
          !isPassed
            ? `<div class="analyzer-stats">
          ${Object.entries(a.severity_counts || {})
            .filter(([, n]) => n > 0)
            .map(([s, n]) => `<span class="sev-badge ${s}">${s}: ${n}</span>`)
            .join("")}
        </div>`
            : ""
        }
      </div>`;
  }

  function renderAnalyzers() {
    const passedGrid = document.getElementById("analyzer-passed-grid");
    const issuesGrid = document.getElementById("analyzer-issues-grid");
    const passedSection = document.getElementById("analyzer-passed-section");
    const issuesSection = document.getElementById("analyzer-issues-section");
    const lead = document.getElementById("analyzer-section-lead");
    if (!passedGrid || !issuesGrid) return;

    const passed = (DATA.analyzers || []).filter((a) => a.status === "passed");
    const issues = (DATA.analyzers || []).filter((a) => a.status !== "passed");
    const cs = DATA.checks_summary || {};

    if (lead && cs.analyzers_run) {
      lead.textContent = `${cs.analyzers_passed} passed, ${cs.analyzers_with_findings} with findings (${cs.analyzers_run} total).`;
    }

    if (passed.length) {
      passedSection.hidden = false;
      passedGrid.innerHTML = passed.map(analyzerCardHtml).join("");
    }
    if (issues.length) {
      issuesSection.hidden = false;
      issuesGrid.innerHTML = issues.map(analyzerCardHtml).join("");
    }
    if (!passed.length && !issues.length) {
      issuesSection.hidden = false;
      issuesGrid.innerHTML =
        '<p style="color:var(--muted)">No analyzer metadata in this report.</p>';
    }
  }

  function renderAttackGraph() {
    const svg = document.getElementById("attack-graph");
    if (!svg) return;
    const { nodes, edges } = DATA.attack_graph;
    if (!nodes.length) {
      svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#94a3b8">No attack chain data</text>';
      return;
    }

    const width = svg.clientWidth || 800;
    const height = 400;
    const cx = width / 2;
    const cy = height / 2;
    const radius = Math.min(width, height) * 0.32;
    const positions = {};

    nodes.forEach((n, i) => {
      const angle = (i / nodes.length) * Math.PI * 2 - Math.PI / 2;
      positions[n.id] = {
        x: cx + radius * Math.cos(angle),
        y: cy + radius * Math.sin(angle),
      };
    });

    let markup = `<defs><marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto"><polygon points="0 0, 8 3, 0 6" fill="rgba(59,130,246,0.7)"/></marker></defs>`;

    edges.forEach((e) => {
      const from = positions[e.from];
      const to = positions[e.to];
      if (!from || !to) return;
      markup += `<line class="graph-edge" x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" marker-end="url(#arrowhead)"/>`;
    });

    nodes.forEach((n) => {
      const p = positions[n.id];
      if (!p) return;
      const label = n.label.length > 14 ? n.label.slice(0, 12) + "…" : n.label;
      markup += `
        <g class="graph-node" transform="translate(${p.x},${p.y})">
          <circle r="28"/>
          <text text-anchor="middle" dy="4">${escapeHtml(label)}</text>
        </g>`;
    });

    svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
    svg.innerHTML = markup;
  }

  function renderAppendix() {
    const pre = document.getElementById("appendix-json");
    if (pre) pre.textContent = JSON.stringify(DATA.raw_report, null, 2);
  }

  function setupNav() {
    const navItems = document.querySelectorAll(".nav-item");
    navItems.forEach((btn) => {
      btn.addEventListener("click", () => navigateToSection(btn.dataset.section));
    });
    navigateToSection("overview");
  }

  function setupExport() {
    const menu = document.getElementById("export-menu");
    const toggle = document.getElementById("export-toggle");
    const downloadJson = document.getElementById("download-json");
    const downloadJsonSide = document.getElementById("download-json-side");

    function blobDownload(filename, content, type) {
      const blob = new Blob([content], { type });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      URL.revokeObjectURL(url);
    }

    function exportJson() {
      blobDownload("mcts-report.json", JSON.stringify(DATA.raw_report, null, 2), "application/json");
    }

    function exportHtml() {
      blobDownload("mcts-report.html", document.documentElement.outerHTML, "text/html");
    }

    function exportPdf() {
      window.print();
    }

    if (toggle && menu) {
      toggle.addEventListener("click", (e) => {
        e.stopPropagation();
        menu.classList.toggle("open");
      });
      document.addEventListener("click", () => menu.classList.remove("open"));
    }

    document.getElementById("export-json")?.addEventListener("click", exportJson);
    document.getElementById("export-html")?.addEventListener("click", exportHtml);
    document.getElementById("export-pdf")?.addEventListener("click", exportPdf);
    downloadJson?.addEventListener("click", exportJson);
    downloadJsonSide?.addEventListener("click", exportJson);
  }

  function setupFindings() {
    document.getElementById("findings-search")?.addEventListener("input", renderFindingsTable);
    document.getElementById("findings-filter")?.addEventListener("change", renderFindingsTable);
    document.querySelectorAll("#findings-table th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => sortFindings(th.dataset.sort));
    });
  }

  function init() {
    fillBanners();
    fillHero();
    fillMetricsHeadline();
    fillReportGuide();
    fillNavBadges();
    fillIssuesSummary();
    applyScoringMode();
    fillScoreBreakdown();
    fillScoreV2();
    fillChecksSummary();
    fillOverviewPanels();
    fillScanMeta();
    fillScoreTooltip();
    fillExecutiveSummary();
    fillSeverityCards();
    fillCategories();
    fillRiskGuide();
    renderFindingsTable();
    renderTechniqueMap();
    renderCapabilityMatrix();
    renderOwasp();
    renderOwaspMcp();
    renderRecommendations();
    renderAnalyzers();
    renderAttackGraph();
    renderAppendix();
    setupNav();
    setupExport();
    setupFindings();
    setupAnalyzerModal();
    setupInteractiveCards();
    initGaugeChart();
    initRadarChart();
    initTrendChart();
    window.addEventListener("resize", scheduleTrendSparklineResize);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
