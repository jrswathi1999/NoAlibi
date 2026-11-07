"""Verdict rules and the evidence-strength guard (no red finding on a shared CDN address alone)."""

from pathlib import Path

from app.audit import apply_evidence_strength, verdict_for
from contracts.models import Findings, load_model

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


def _findings() -> Findings:
    return load_model(FIXTURES / "findings.sample.json", Findings)


def _flows(confidence: str) -> dict:
    return {
        "flows": [{"domain": "api.openai.com", "ip": "162.159.140.245", "confidence": confidence}],
        "_events": [{"id": "e4", "domain": "api.openai.com", "ip": "162.159.140.245"}],
    }


def test_unconfirmed_findings_never_count():
    out = apply_evidence_strength(_findings(), _flows("possible"))
    for fid in ("f1", "f2", "f4", "f5"):  # every finding that rests on api.openai.com
        f = next(f for f in out.findings if f.id == fid)
        assert f.severity == "info" and f.title.endswith("(not confirmed)")


def test_red_kept_when_confirmed():
    out = apply_evidence_strength(_findings(), _flows("confirmed"))
    assert next(f for f in out.findings if f.id == "f1").severity == "red"


def test_verdicts():
    f = _findings()
    assert verdict_for(f)["verdict"] == "NO_ALIBI"
    amber_only = f.model_copy(update={"findings": [x for x in f.findings if x.severity != "red"]})
    assert verdict_for(amber_only)["verdict"] == "QUESTIONABLE"
    empty = f.model_copy(update={"findings": []})
    assert verdict_for(empty)["verdict"] == "ALIBI_HOLDS"
