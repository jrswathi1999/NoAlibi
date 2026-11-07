"""Render findings + claims + events into one self-contained report.html.

CLI:  python -m report.render --run-dir data/runs/<run_id>
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from contracts.models import Claims, Events, Findings, load_model
from engine.rules import human_bytes

log = logging.getLogger("report.render")

TEMPLATE_DIR = Path(__file__).resolve().parent
SEVERITY_RANK = {"red": 0, "amber": 1, "info": 2}


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=select_autoescape(["html"]),
        undefined=StrictUndefined,
    )
    env.filters["human_bytes"] = human_bytes
    return env


def worst_severity(findings: Findings, attr: str) -> dict[str, str]:
    """Map each claim/event id to the most severe finding that references it."""
    out: dict[str, str] = {}
    for f in findings.findings:
        for ref in getattr(f, attr):
            if ref not in out or SEVERITY_RANK[f.severity] < SEVERITY_RANK[out[ref]]:
                out[ref] = f.severity
    return out


def count_outbound_queries(run_dir: Path) -> int | None:
    """Lines in outbound_queries.log (written by behavior/ and claims/), or None if absent."""
    log_file = run_dir / "outbound_queries.log"
    if not log_file.exists():
        return None
    return sum(1 for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip())


def render_html(claims: Claims, events: Events, findings: Findings, run_dir: Path) -> str:
    red = sum(f.severity == "red" for f in findings.findings)
    amber = sum(f.severity == "amber" for f in findings.findings)
    return (
        _env()
        .get_template("template.html")
        .render(
            run_id=findings.run_id,
            app=claims.app,
            model=claims.model,
            run_time=events.capture.start.strftime("%Y-%m-%d %H:%M UTC"),
            claims=claims.claims,
            events=sorted(events.events, key=lambda e: e.t),
            user_actions=events.user_actions,
            findings=findings.findings,
            scorecard=findings.scorecard,
            summary=findings.summary,
            evidence_sha256=findings.evidence_sha256,
            red_count=red,
            amber_count=amber,
            claim_sev=worst_severity(findings, "claim_ids"),
            event_sev=worst_severity(findings, "event_ids"),
            outbound_count=count_outbound_queries(run_dir),
        )
    )


def render(run_dir: str | Path) -> Path:
    """Read the three JSON files in run_dir and write run_dir/report.html."""
    run_dir = Path(run_dir)
    claims = load_model(run_dir / "claims.json", Claims)
    events = load_model(run_dir / "events.json", Events)
    findings = load_model(run_dir / "findings.json", Findings)
    out = run_dir / "report.html"
    out.write_text(render_html(claims, events, findings, run_dir), encoding="utf-8")
    log.info("wrote %s", out)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Render report.html for a run.")
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        render(args.run_dir)
    except ValueError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
