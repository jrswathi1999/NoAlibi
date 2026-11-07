"""Each fixture loads into its contract model, and the models reject bad input."""

import json
from pathlib import Path

import pytest

from contracts.models import (
    CLAIM_TYPES,
    Claims,
    Events,
    Findings,
    load_model,
    save_model,
)

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


@pytest.mark.parametrize(
    ("name", "model"),
    [("claims", Claims), ("events", Events), ("findings", Findings)],
)
def test_fixture_loads(name: str, model: type) -> None:
    obj = load_model(FIXTURES / f"{name}.sample.json", model)
    assert obj.run_id == "20261107-201500-notesapp"


def test_fixtures_cover_all_cases() -> None:
    claims = load_model(FIXTURES / "claims.sample.json", Claims)
    events = load_model(FIXTURES / "events.sample.json", Events)
    findings = load_model(FIXTURES / "findings.sample.json", Findings)

    assert {c.type for c in claims.claims} == set(CLAIM_TYPES)
    assert all(c.validated for c in claims.claims)
    assert any(e.category == "unknown" and e.lookup for e in events.events)
    severities = {f.severity for f in findings.findings}
    assert {"red", "amber"} <= severities


def test_round_trip(tmp_path: Path) -> None:
    events = load_model(FIXTURES / "events.sample.json", Events)
    out = save_model(tmp_path / "events.json", events)
    again = load_model(out, Events)
    assert again == events
    assert json.loads(out.read_text())["capture"]["start"].endswith("Z")


def test_bad_claim_type_rejected(tmp_path: Path) -> None:
    data = json.loads((FIXTURES / "claims.sample.json").read_text())
    data["claims"][0]["type"] = "sells_your_soul"
    bad = tmp_path / "claims.json"
    bad.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="claims.json"):
        load_model(bad, Claims)


def test_bad_run_id_rejected() -> None:
    data = json.loads((FIXTURES / "findings.sample.json").read_text())
    data["run_id"] = "notesapp"
    with pytest.raises(ValueError):
        Findings.model_validate(data)


def test_missing_file_is_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not found"):
        load_model(tmp_path / "nope.json", Events)
