"""One test per rule using the contract fixtures, plus compare end to end."""

import json
import shutil
from pathlib import Path

import pytest

from contracts.models import Claims, Events, Findings, load_model
from engine import rules
from engine.compare import build_findings, build_scorecard, run_compare

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


@pytest.fixture
def claims() -> Claims:
    return load_model(FIXTURES / "claims.sample.json", Claims)


@pytest.fixture
def events() -> Events:
    return load_model(FIXTURES / "events.sample.json", Events)


def _set_claim(claims: Claims, claim_type: str, **changes) -> Claims:
    new = [c.model_copy(update=changes) if c.type == claim_type else c for c in claims.claims]
    return claims.model_copy(update={"claims": new})


# ---------------------------------------------------------------- R1


def test_r1_flags_unnamed_ai_provider(claims, events):
    out = rules.r1_undisclosed_ai_provider(claims, events)
    assert len(out) == 1
    f = out[0]
    assert f.severity == "red"
    assert f.title == "Policy never names OpenAI, but the app sent 12 KB to api.openai.com"
    assert f.claim_ids == ["c1"] and f.event_ids == ["e4"]


def test_r1_quiet_when_provider_named(claims, events):
    named = _set_claim(claims, "names_ai_provider", value="yes", providers=["OpenAI, L.L.C."])
    assert rules.r1_undisclosed_ai_provider(named, events) == []


def test_r1_alias_match():
    assert rules.provider_is_named("Microsoft", ["Azure OpenAI Service"])
    assert rules.provider_is_named("Amazon Web Services", ["AWS Bedrock"])
    assert not rules.provider_is_named("OpenAI", ["Anthropic"])
    assert not rules.provider_is_named("OpenAI", ["AI"])


# ---------------------------------------------------------------- R2


def test_r2_flags_upload_despite_local_promise(claims, events):
    out = rules.r2_local_promise_broken(claims, events)
    assert [f.event_ids for f in out] == [["e4"]]
    assert out[0].severity == "red" and out[0].claim_ids == ["c2"]


def test_r2_quiet_without_local_promise(claims, events):
    no_promise = _set_claim(claims, "data_stays_local", value="no")
    assert rules.r2_local_promise_broken(no_promise, events) == []


def test_r2_ignores_first_party_and_small(claims, events):
    # e5 (first_party) and anything <= 2048 bytes are never flagged
    out = rules.r2_local_promise_broken(claims, events)
    flagged = {eid for f in out for eid in f.event_ids}
    assert "e5" not in flagged


# ---------------------------------------------------------------- R3


def test_r3_flags_periodic_idle_traffic(claims, events):
    out = rules.r3_background_telemetry(claims, events)
    assert len(out) == 1
    assert out[0].severity == "amber"
    assert out[0].event_ids == ["e6", "e7", "e8", "e9"]
    assert "about every 10 s" in out[0].title


def test_r3_quiet_for_irregular_gaps(claims, events):
    from datetime import timedelta

    jittered = []
    shifts = {"e7": 1, "e8": 14, "e9": 2}  # gaps become 11, 23, 0.05 + ...
    for e in events.events:
        if e.id in shifts:
            e = e.model_copy(update={"t": e.t + timedelta(seconds=shifts[e.id])})
        jittered.append(e)
    assert (
        rules.r3_background_telemetry(claims, events.model_copy(update={"events": jittered})) == []
    )


# ---------------------------------------------------------------- R4


def test_r4_flags_big_upload_after_action(claims, events):
    out = rules.r4_content_upload_suspicion(claims, events)
    assert [f.event_ids for f in out] == [["e4"]]
    assert out[0].title == "12 KB left for api.openai.com within 5 s of a user action"


def test_r4_uses_action_window_when_phase_missing(claims, events):
    # Same bytes but labelled idle: still within 5 s of the marked action, so still flagged.
    relabelled = [e.model_copy(update={"phase": "idle"}) for e in events.events]
    out = rules.r4_content_upload_suspicion(
        claims, events.model_copy(update={"events": relabelled})
    )
    assert any(f.event_ids == ["e4"] for f in out)


# ---------------------------------------------------------------- R5


def test_r5_flags_unclear_training(claims, events):
    out = rules.r5_silent_on_training(claims, events)
    assert len(out) == 1 and out[0].claim_ids == ["c3"] and out[0].event_ids == ["e4"]


def test_r5_flags_missing_training_claim(claims, events):
    no_training = claims.model_copy(
        update={"claims": [c for c in claims.claims if c.type != "trains_on_user_data"]}
    )
    out = rules.r5_silent_on_training(no_training, events)
    assert len(out) == 1 and "never says" in out[0].title


def test_r5_quiet_when_training_stated(claims, events):
    stated = _set_claim(claims, "trains_on_user_data", value="no")
    assert rules.r5_silent_on_training(stated, events) == []


# ---------------------------------------------------------------- R6


def test_r6_reports_unknown_with_lookup(claims, events):
    out = rules.r6_unknown_recipient(claims, events)
    assert len(out) == 1 and out[0].severity == "info"
    assert out[0].title.startswith("Unknown recipient cdn.xyz-metrics.io: XYZ Metrics")


def test_r6_without_lookup(claims, events):
    no_lookup = [e.model_copy(update={"lookup": None}) for e in events.events]
    out = rules.r6_unknown_recipient(claims, events.model_copy(update={"events": no_lookup}))
    assert out[0].title.endswith("(no lookup result)")


# ---------------------------------------------------------------- compare


def test_findings_match_fixture(claims, events):
    expected = load_model(FIXTURES / "findings.sample.json", Findings)
    assert build_findings(claims, events) == expected.findings
    assert build_scorecard(claims) == expected.scorecard


def test_empty_inputs_give_no_findings(claims, events):
    empty_claims = claims.model_copy(update={"claims": []})
    empty_events = events.model_copy(update={"events": [], "user_actions": []})
    assert build_findings(empty_claims, empty_events) == []
    assert set(build_scorecard(empty_claims).values()) == {"unclear"}


def test_broken_rule_does_not_crash(claims, events, monkeypatch):
    def boom(*_):
        raise RuntimeError("bug")

    monkeypatch.setattr(rules, "ALL_RULES", [boom, rules.r6_unknown_recipient])
    monkeypatch.setattr("engine.compare.ALL_RULES", rules.ALL_RULES)
    assert [f.rule for f in build_findings(claims, events)] == ["R6_unknown_recipient"]


def test_run_compare_writes_valid_file(tmp_path):
    run_dir = tmp_path / "20261107-201500-notesapp"
    run_dir.mkdir()
    shutil.copy(FIXTURES / "claims.sample.json", run_dir / "claims.json")
    shutil.copy(FIXTURES / "events.sample.json", run_dir / "events.json")
    out = run_compare(run_dir)
    findings = load_model(out, Findings)
    assert [f.id for f in findings.findings] == ["f1", "f2", "f3", "f4", "f5", "f6"]
    assert findings.summary
    assert json.loads(out.read_text())["run_id"] == "20261107-201500-notesapp"


def test_run_compare_missing_input(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        run_compare(tmp_path)


def test_run_compare_stamps_evidence_hash(tmp_path):
    from engine.hashlog import evidence_sha256

    run_dir = tmp_path / "20261107-201500-notesapp"
    run_dir.mkdir()
    shutil.copy(FIXTURES / "claims.sample.json", run_dir / "claims.json")
    shutil.copy(FIXTURES / "events.sample.json", run_dir / "events.json")
    findings = load_model(run_compare(run_dir), Findings)
    assert findings.evidence_sha256 == evidence_sha256(run_dir)
    assert len(findings.evidence_sha256) == 64
