"""Summary step: only findings go to the model, invented names are rejected, failures fall back."""

import json
import shutil
from pathlib import Path

import pytest
import requests

from contracts.models import Findings, load_model
from engine import summarize as summ

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"
GOOD = (
    "The policy says your notes stay on your device and never names an AI company. "
    "But the app sent 12 KB to api.openai.com right after a user action. "
    "It also contacted api.mixpanel.com about every 10 s while idle."
)


@pytest.fixture
def findings() -> Findings:
    return load_model(FIXTURES / "findings.sample.json", Findings)


class FakeResp:
    def __init__(self, content: str):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": self._content}}


def test_payload_has_only_findings_and_scorecard(findings):
    payload = summ.build_payload(findings)
    assert set(payload) == {"findings", "what_the_policy_says"}
    assert "The policy promises your data stays on your device." in payload["what_the_policy_says"]
    assert "evidence_sha256" not in json.dumps(payload)


def test_good_summary_passes(findings):
    assert summ.summary_problems(GOOD, findings) == []


def test_invented_company_rejected(findings):
    bad = GOOD + " Google also received your data."
    assert any("Google" in p for p in summ.summary_problems(bad, findings))


def test_invented_domain_rejected(findings):
    bad = "The app sent data to evil-tracker.net. That is bad. Very bad."
    assert any("evil-tracker.net" in p for p in summ.summary_problems(bad, findings))


def test_sentence_count_enforced(findings):
    assert summ.summary_problems("Too short.", findings)


def test_retries_then_accepts(findings, monkeypatch):
    replies = iter(
        [
            json.dumps({"summary": "Anthropic got everything. Yes. Really."}),
            json.dumps({"sentences": GOOD.split(". ")}),
        ]
    )
    sent = []

    def fake_post(url, json, timeout):
        sent.append(json)
        return FakeResp(next(replies))

    monkeypatch.setattr(summ.requests, "post", fake_post)
    assert summ.summarize(findings, model="m", host="http://x") == GOOD
    assert len(sent) == 2
    assert sent[0]["format"] == "json" and sent[0]["options"]["temperature"] == 0
    assert "Anthropic" in sent[1]["messages"][-1]["content"]  # retry explains the problem


def test_ollama_down_returns_none(findings, monkeypatch):
    def down(*a, **k):
        raise requests.ConnectionError("refused")

    monkeypatch.setattr(summ.requests, "post", down)
    assert summ.summarize(findings, model="m", host="http://x") is None


def test_bad_json_retries_and_gives_up(findings, monkeypatch):
    monkeypatch.setattr(summ.requests, "post", lambda *a, **k: FakeResp("not json"))
    assert summ.summarize(findings, model="m", host="http://x") is None


def test_run_summarize_keeps_plain_summary_on_failure(tmp_path, findings, monkeypatch):
    shutil.copy(FIXTURES / "findings.sample.json", tmp_path / "findings.json")
    monkeypatch.setattr(summ, "summarize", lambda *a, **k: None)
    summ.run_summarize(tmp_path)
    assert load_model(tmp_path / "findings.json", Findings).summary == findings.summary


def test_run_summarize_writes_model_summary(tmp_path, monkeypatch):
    shutil.copy(FIXTURES / "findings.sample.json", tmp_path / "findings.json")
    monkeypatch.setattr(summ, "summarize", lambda *a, **k: GOOD)
    summ.run_summarize(tmp_path)
    assert load_model(tmp_path / "findings.json", Findings).summary == GOOD


def test_false_local_promise_rejected(findings):
    no_local = findings.model_copy(
        update={"scorecard": {**findings.scorecard, "data_stays_local": "no"}}
    )
    bad = "The policy promises your data stays on your device. But 12 KB went to api.openai.com. That is a lot."
    assert any("stays on the device" in p for p in summ.summary_problems(bad, no_local))
    ok = "The policy does not promise your data stays on your device. 12 KB went to api.openai.com. Noted."
    assert not any("stays on the device" in p for p in summ.summary_problems(ok, no_local))
