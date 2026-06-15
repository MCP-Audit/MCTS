"""Append-only scan history for HTML trend charts."""

from __future__ import annotations

import contextlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from mcts.output.analysis_dir import analysis_path, workspace_root
from mcts.reporting.models import ScanReport

HISTORY_FILENAME = "history.json"
MAX_TREND_POINTS = 50

__all__ = [
    "HISTORY_FILENAME",
    "MAX_TREND_POINTS",
    "normalize_target",
    "record_scan_run",
    "runs_for_target",
    "trend_points_for_target",
    "workspace_history_root",
]


def _history_path(root: Path | None = None) -> Path:
    return analysis_path(HISTORY_FILENAME, root=root)


def normalize_target(target: str) -> str:
    return str(Path(target).expanduser().resolve())


def _target_match_keys(target: str) -> set[str]:
    """Return normalized path keys used to match history rows."""
    raw = Path(target).expanduser()
    keys: set[str] = set()
    with contextlib.suppress(OSError):
        keys.add(str(raw.resolve()))
    keys.add(str(raw))
    keys.add(normalize_target(target))
    return keys


def _row_target_keys(row_target: str) -> set[str]:
    raw = Path(row_target).expanduser()
    keys: set[str] = {row_target}
    with contextlib.suppress(OSError):
        keys.add(str(raw.resolve()))
    return keys


def _load_store(root: Path | None = None) -> dict[str, Any]:
    path = _history_path(root)
    if not path.is_file():
        return {"version": 1, "runs": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"version": 1, "runs": []}
    if not isinstance(data, dict):
        return {"version": 1, "runs": []}
    data.setdefault("version", 1)
    data.setdefault("runs", [])
    return data


def _save_store(store: dict[str, Any], root: Path | None = None) -> None:
    path = _history_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(store, indent=2), encoding="utf-8")


def record_scan_run(report: ScanReport, root: Path | None = None) -> None:
    """Append a scan result to ``mcts_analysis/history.json``."""
    store = _load_store(root)
    runs: list[dict[str, Any]] = store["runs"]
    key = normalize_target(report.target)
    entry: dict[str, Any] = {
        "scanned_at": report.scanned_at.astimezone(UTC).isoformat(),
        "target": key,
        "scoring_version": report.scoring_version,
        "score": report.score.overall,
        "findings_total": report.summary.total,
        "critical": report.summary.critical,
        "high": report.summary.high,
        "findings_trust_mode": report.findings_trust_mode,
    }
    if report.display_summary is not None:
        entry["display_critical"] = report.display_summary.critical
        entry["display_high"] = report.display_summary.high
    if report.score_v2 is not None:
        entry["absolute_risk"] = report.score_v2.absolute_risk
        entry["security_score"] = report.score_v2.security_score
        entry["risk_level"] = report.score_v2.risk_level
    if runs and runs[-1].get("scanned_at") == entry["scanned_at"] and runs[-1].get("target") == key:
        runs[-1] = entry
    else:
        runs.append(entry)
    store["runs"] = runs[-500:]
    _save_store(store, root)


def runs_for_target(target: str, root: Path | None = None) -> list[dict[str, Any]]:
    query_keys = _target_match_keys(target)
    store = _load_store(root)
    matched = [
        row for row in store["runs"] if query_keys.intersection(_row_target_keys(str(row.get("target", ""))))
    ]
    matched.sort(key=lambda row: row.get("scanned_at", ""))
    return matched[-MAX_TREND_POINTS:]


def _trend_label(scanned_at: datetime, day_counts: dict[str, int]) -> str:
    day_key = scanned_at.strftime("%Y-%m-%d")
    day_counts[day_key] = day_counts.get(day_key, 0) + 1
    if day_counts[day_key] > 1:
        return scanned_at.strftime("%b %d %H:%M")
    return scanned_at.strftime("%b %d")


def trend_points_for_target(target: str, root: Path | None = None) -> list[dict[str, Any]]:
    """Return Chart.js-ready trend rows for a target from scan history."""
    rows = runs_for_target(target, root=root)
    day_counts: dict[str, int] = {}
    points: list[dict[str, Any]] = []
    for row in rows:
        raw = row.get("scanned_at")
        if not raw:
            continue
        scanned_at = datetime.fromisoformat(str(raw))
        if scanned_at.tzinfo is None:
            scanned_at = scanned_at.replace(tzinfo=UTC)
        point: dict[str, Any] = {
            "date": _trend_label(scanned_at, day_counts),
            "score": int(row.get("score", 0)),
            "scanned_at": scanned_at.isoformat(),
            "scoring_version": row.get("scoring_version", "legacy"),
        }
        if "absolute_risk" in row:
            point["absolute_risk"] = int(row["absolute_risk"])
        if row.get("security_score") is not None:
            point["security_score"] = int(row["security_score"])
        if row.get("risk_level"):
            point["risk_level"] = str(row["risk_level"])
        if "findings_total" in row:
            point["findings_total"] = int(row["findings_total"])
        if "critical" in row:
            point["critical"] = int(row["critical"])
        if "high" in row:
            point["high"] = int(row["high"])
        if "display_critical" in row:
            point["display_critical"] = int(row["display_critical"])
        if "display_high" in row:
            point["display_high"] = int(row["display_high"])
        if row.get("findings_trust_mode"):
            point["findings_trust_mode"] = str(row["findings_trust_mode"])
        points.append(point)
    return points


def workspace_history_root() -> Path:
    return workspace_root()
