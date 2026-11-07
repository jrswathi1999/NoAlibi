"""Run all rules, number findings f1..., build the scorecard and write findings.json.

CLI:  python -m engine.compare --run-dir data/runs/<run_id>
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from contracts.models import (
    CLAIM_TYPES,
    RUN_ID_PATTERN,
    Claims,
    ClaimValue,
    Events,
    Finding,
    Findings,
    load_model,
    save_model,
)
from engine.hashlog import evidence_sha256
from engine.rules import ALL_RULES

log = logging.getLogger("engine.compare")

SEVERITY_ORDER = {"red": 0, "amber": 1, "info": 2}


def build_findings(claims: Claims, events: Events) -> list[Finding]:
    """Run every rule, sort red -> amber -> info (rule order inside), then number f1, f2, ...

    A rule that raises is logged and skipped so one bug never kills the whole report.
    """
    found: list[Finding] = []
    for rule in ALL_RULES:
        try:
            found.extend(rule(claims, events))
        except Exception as exc:  # noqa: BLE001 - keep the pipeline alive
            log.error("rule %s failed: %s", rule.__name__, exc)
    found.sort(key=lambda f: (SEVERITY_ORDER[f.severity], f.rule))  # sort is stable
    return [f.model_copy(update={"id": f"f{i}"}) for i, f in enumerate(found, start=1)]


def build_scorecard(claims: Claims) -> dict[str, ClaimValue]:
    """One value per claim type. Missing types count as 'unclear'.

    If several claims share a type, the first definite answer (yes/no) wins.
    """
    card: dict[str, ClaimValue] = {}
    for claim_type in CLAIM_TYPES:
        values = [c.value for c in claims.claims if c.type == claim_type and c.validated]
        definite = [v for v in values if v != "unclear"]
        card[claim_type] = definite[0] if definite else "unclear"
    return card


def fallback_summary(app_name: str, findings: list[Finding]) -> str:
    """Plain summary built from finding titles only. Used when the Ollama summary is off or fails."""
    red = [f for f in findings if f.severity == "red"]
    amber = [f for f in findings if f.severity == "amber"]
    if not red and not amber:
        return (
            f"Nothing {app_name} did during the audit contradicts its privacy policy. "
            "Its connections went to its own servers or to ordinary services, and none were flagged."
        )
    head = (
        f"No Alibi found {len(red)} contradiction(s) and {len(amber)} suspicious pattern(s) "
        f"for {app_name}."
    )
    parts = [head]
    parts += [f.title.rstrip(".") + "." for f in (red + amber)[:3]]
    return " ".join(parts)


def pick_run_id(run_dir: Path, claims: Claims, events: Events) -> str:
    """Prefer the run folder name; warn if the two input files disagree."""
    if claims.run_id != events.run_id:
        log.warning("run_id mismatch: claims=%s events=%s", claims.run_id, events.run_id)
    if RUN_ID_PATTERN.match(run_dir.name):
        return run_dir.name
    return claims.run_id


def compare(run_dir: Path) -> Findings:
    """Load claims.json + events.json from run_dir and return validated Findings."""
    claims = load_model(run_dir / "claims.json", Claims)
    events = load_model(run_dir / "events.json", Events)
    findings = build_findings(claims, events)
    return Findings(
        run_id=pick_run_id(run_dir, claims, events),
        findings=findings,
        scorecard=build_scorecard(claims),
        summary=fallback_summary(claims.app.name, findings),
        evidence_sha256=evidence_sha256(run_dir),
    )


def run_compare(run_dir: str | Path) -> Path:
    """Write run_dir/findings.json and return its path."""
    run_dir = Path(run_dir)
    result = compare(run_dir)
    out = save_model(run_dir / "findings.json", result)
    counts = {s: sum(f.severity == s for f in result.findings) for s in SEVERITY_ORDER}
    log.info(
        "wrote %s (%d red, %d amber, %d info)", out, counts["red"], counts["amber"], counts["info"]
    )
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare claims with behavior.")
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        run_compare(args.run_dir)
    except ValueError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
