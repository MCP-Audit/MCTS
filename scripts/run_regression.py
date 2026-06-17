#!/usr/bin/env python3
"""Phase 1–2 security regression runner (R-01–R-25)."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from mcts.core.config import ScanConfig
from mcts.core.scanner import Scanner

_ROOT = Path(__file__).resolve().parents[1]
_FIXTURES = _ROOT / "tests" / "fixtures" / "regression"
_BUNDLED = _ROOT / "tests" / "fixtures" / "monorepo-mini"
_DEFAULT_SERVERS = Path(
    os.environ.get(
        "MCTS_SERVERS_ROOT",
        "/Users/arghyadeep_nfal/CODE_ARGS/servers",
    )
)


def _rule_ids(findings) -> set[str]:
    out: set[str] = set()
    for finding in findings:
        evidence = finding.evidence or {}
        if rid := evidence.get("rule_id"):
            out.add(str(rid))
        for fact in evidence.get("facts") or []:
            if rid := fact.get("rule_id"):
                out.add(str(rid))
    return out


def _load_fixture(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_corpus_root(explicit: Path) -> tuple[Path, str]:
    if explicit.exists():
        return explicit, "servers"
    if _BUNDLED.exists():
        return _BUNDLED, "bundled"
    return explicit, "missing"


def _resolve_target(corpus_root: Path, spec: dict) -> Path:
    rel = spec.get("servers_path") or spec.get("target")
    if not rel:
        raise ValueError(f"Fixture {spec.get('id')} missing servers_path/target")
    target = Path(rel)
    if target.is_absolute():
        return target
    return corpus_root / target


def _scan_target(target: Path, spec: dict):
    cfg = ScanConfig(
        target=str(target),
        monorepo=bool(spec.get("monorepo")),
        surface_depth=spec.get("surface_depth", "full"),
        package_depth=spec.get("package_depth", "full"),
        aggregate=bool(spec.get("aggregate")),
        languages=spec.get("languages", ["python", "typescript"]),
    )
    return Scanner(cfg).run()


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Phase 1–2 security regression fixtures")
    parser.add_argument(
        "--servers-root",
        type=Path,
        default=_DEFAULT_SERVERS,
        help="Root of modelcontextprotocol/servers checkout (falls back to bundled mini corpus)",
    )
    parser.add_argument(
        "--fixture",
        action="append",
        dest="fixtures",
        help="Fixture directory name under tests/fixtures/regression (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 when required rule IDs are missing or no corpus is available",
    )
    args = parser.parse_args()

    fixture_dirs = args.fixtures or [
        "R-01-net-fetch",
        "R-02-dual-fetch",
        "R-03-pois-fetch-desc",
        "R-04-git-scoping",
        "R-05-git-log",
        "R-06-transport-everything",
        "R-07-get-env",
        "R-08-gzip-net",
        "R-09-toctou-test",
        "R-10-symlink-listing",
        "R-11-memory-readme",
        "R-12-get-env-ann",
        "R-13-time-docker",
        "R-14-fetch-cli",
        "R-15-gzip-resource",
        "R-16-tasks-research",
        "R-17-subscriptions",
        "R-18-read-multiple",
        "R-19-memory-poison",
        "R-20-git-readme",
        "R-22-streamable-get-env",
        "R-23-elicitation-phish",
        "R-24-read-exec",
        "R-25-cred-theft",
        "MCTS-T-monorepo-servers",
    ]

    corpus_root, corpus_kind = _resolve_corpus_root(args.servers_root)
    if corpus_kind == "missing":
        msg = f"No regression corpus found (tried {args.servers_root} and {_BUNDLED})"
        if args.strict:
            print(msg, file=sys.stderr)
            return 1
        print(f"warning: {msg} — skipping", file=sys.stderr)
        return 0

    rows: list[dict] = []
    failures: list[str] = []

    for name in fixture_dirs:
        fixture_dir = _FIXTURES / name
        expected_path = fixture_dir / "expected.json"
        if not expected_path.exists():
            failures.append(f"{name}: missing expected.json")
            continue
        spec = _load_fixture(expected_path)
        spec["id"] = name
        try:
            target = _resolve_target(corpus_root, spec)
        except ValueError as exc:
            failures.append(f"{name}: {exc}")
            continue
        if not target.exists():
            failures.append(f"{name}: target missing {target}")
            continue

        report = _scan_target(target, spec)
        found = _rule_ids(report.findings)
        analyzers = {f.analyzer for f in report.findings}
        required = set(spec.get("required_rule_ids") or [])
        forbidden = set(spec.get("forbidden_rule_ids") or [])
        missing = required - found
        forbidden_hits = sorted(forbidden & found)
        score = report.score.overall if report.score else None
        max_score = spec.get("max_score")
        score_ok = max_score is None or (score is not None and score <= max_score)

        tool_count = len(report.server.tools)
        source_count = len(report.server.source_files)
        min_tools = spec.get("min_tools")
        min_source_files = spec.get("min_source_files")
        monorepo_ok = True
        if min_tools is not None and tool_count < min_tools:
            monorepo_ok = False
            failures.append(f"{name}: tools {tool_count} < min {min_tools}")
        if min_source_files is not None and source_count < min_source_files:
            monorepo_ok = False
            failures.append(f"{name}: source_files {source_count} < min {min_source_files}")
        required_analyzers = spec.get("required_analyzers_any") or []
        if required_analyzers and not any(a in analyzers for a in required_analyzers):
            monorepo_ok = False
            failures.append(f"{name}: none of analyzers {required_analyzers} in {sorted(analyzers)}")

        status = "pass"
        if missing or forbidden_hits or not score_ok or not monorepo_ok:
            status = "fail"

        row = {
            "fixture": name,
            "corpus": corpus_kind,
            "target": str(target),
            "required_rule_ids": sorted(required),
            "forbidden_rule_ids": sorted(forbidden),
            "found_rule_ids": sorted(found),
            "missing_rule_ids": sorted(missing),
            "forbidden_hits": forbidden_hits,
            "score": score,
            "score_ok": score_ok,
            "finding_count": len(report.findings),
            "status": status,
        }
        rows.append(row)
        if missing:
            failures.append(f"{name}: missing rules {sorted(missing)}")
        if forbidden_hits:
            failures.append(f"{name}: forbidden rules present {forbidden_hits}")
        if not score_ok:
            failures.append(f"{name}: score {score} exceeds max {max_score}")

    if args.json:
        print(json.dumps({"corpus": corpus_kind, "fixtures": rows, "failures": failures}, indent=2))
    else:
        print(f"Corpus: {corpus_kind} ({corpus_root})")
        for row in rows:
            mark = "PASS" if row["status"] == "pass" else "FAIL"
            print(
                f"[{mark}] {row['fixture']} score={row['score']} missing={row['missing_rule_ids'] or 'none'}"
            )
        if failures:
            print("\nFailures:", file=sys.stderr)
            for item in failures:
                print(f"  - {item}", file=sys.stderr)

    if failures and args.strict:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
