"""Each fixture loads into its contract, and bad data is rejected with a clear error."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from contracts.models import (
    CLAIM_TYPES,
    Claims,
    Events,
    Findings,
    load_model,
    make_run_id,
    save_model,
    slugify,
)

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


@pytest.mark.parametrize(
    ("name", "model"), [("claims", Claims), ("events", Events), ("findings", Findings)]
)
def test_fixture_loads(name: str, model: type) -> None:
    obj = load_model(FIXTURES / f"{name}.sample.json", model)
    assert obj.run_id == "20261107-201500-notesapp"


def test_fixtures_cover_red_amber_and_unknown() -> None:
    findings = load_model(FIXTURES / "findings.sample.json", Findings)
    events = load_model(FIXTURES / "events.sample.json", Events)
    severities = {f.severity for f in findings.findings}
    assert {"red", "amber", "info"} <= severities
    assert any(e.category == "unknown" and e.lookup for e in events.events)


def test_claims_only_six_types() -> None:
    claims = load_model(FIXTURES / "claims.sample.json", Claims)
    assert {c.type for c in claims.claims} <= set(CLAIM_TYPES)
    assert len(CLAIM_TYPES) == 6


def test_bad_claim_type_rejected(tmp_path: Path) -> None:
    data = json.loads((FIXTURES / "claims.sample.json").read_text(encoding="utf-8"))
    data["claims"][0]["type"] = "made_up_type"
    bad = tmp_path / "claims.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="claims.json"):
        load_model(bad, Claims)


def test_bad_run_id_rejected(tmp_path: Path) -> None:
    data = json.loads((FIXTURES / "events.sample.json").read_text(encoding="utf-8"))
    data["run_id"] = "notes app run 1"
    bad = tmp_path / "events.json"
    bad.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="YYYYMMDD-HHMMSS"):
        load_model(bad, Events)


def test_missing_file_is_clear_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="not found"):
        load_model(tmp_path / "nope.json", Claims)


def test_save_roundtrip_keeps_utc(tmp_path: Path) -> None:
    events = load_model(FIXTURES / "events.sample.json", Events)
    out = save_model(tmp_path / "events.json", events)
    saved = json.loads(out.read_text(encoding="utf-8"))
    assert saved["capture"]["start"].endswith("Z")
    assert load_model(out, Events) == events


def test_run_id_helpers() -> None:
    assert slugify("Notes App 2!") == "notes-app-2"
    when = datetime(2026, 11, 7, 20, 15, 0, tzinfo=UTC)
    assert make_run_id("NotesApp", when) == "20261107-201500-notesapp"
