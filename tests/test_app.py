"""Web UI flow with a fake recorder: start -> mark -> stop -> results. No real capture."""

import json
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as web
from behavior.mark import ActionMarker
from contracts.models import Events, load_model

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


class FakeRecorder:
    def __init__(self, run_dir, cmd=None, proc_names=None, interface="Wi-Fi", max_seconds=120):
        if not cmd and not proc_names:
            raise ValueError("give a launch command and/or a process name")
        self.run_dir, self.max_seconds, self.interface = Path(run_dir), max_seconds, interface
        self.marker = ActionMarker()
        self.started_at = self.ended_at = None

    @property
    def recording(self):
        return self.started_at is not None and self.ended_at is None

    def start(self):
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.started_at = datetime.now(UTC)

    def stop(self):
        self.ended_at = self.ended_at or datetime.now(UTC)

    def mark(self, label=""):
        return self.marker.add(label)

    def elapsed(self):
        return 1.0

    def process_names(self):
        return ["opera.exe"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    fixture_events = load_model(FIXTURES / "events.sample.json", Events)

    def fake_events_from_run_dir(run_dir, first_party, update, offline):
        return fixture_events.model_copy(update={"run_id": run_dir.name}), ["a warning"]

    monkeypatch.setattr(web, "RUNS_DIR", tmp_path)
    monkeypatch.setattr(web, "LIVE_REFRESH_SECONDS", 0.05)
    monkeypatch.setattr(web, "Recorder", FakeRecorder)
    monkeypatch.setattr(web, "preview_events", lambda rec, fp, up: [{"id": "e1"}])
    monkeypatch.setattr(web, "events_from_run_dir", fake_events_from_run_dir)
    web.SESSIONS.clear()
    return TestClient(web.app)


def wait_for(client, run_id, state, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        s = client.get(f"/api/run/{run_id}").json()
        if s["state"] == state:
            return s
        time.sleep(0.05)
    raise AssertionError(f"state never became {state}: {s}")


def test_home_page(client) -> None:
    r = client.get("/")
    assert r.status_code == 200 and "Start audit" in r.text


def test_full_flow(client, tmp_path) -> None:
    r = client.post(
        "/audit",
        data={"app_name": "Opera", "proc_names": "opera.exe", "first_party": "opera.com"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    run_id = r.headers["location"].rsplit("/", 1)[1]
    assert run_id.endswith("-opera")
    assert client.get(f"/run/{run_id}").status_code == 200

    s = client.get(f"/api/run/{run_id}").json()
    assert s["state"] == "recording" and s["processes"] == ["opera.exe"]
    assert client.post(f"/api/run/{run_id}/mark", json={}).status_code == 200
    assert len(client.get(f"/api/run/{run_id}").json()["marks"]) == 1

    client.post(f"/api/run/{run_id}/stop")
    done = wait_for(client, run_id, "done")
    assert len(done["events"]) == 8 and done["warnings"] == ["a warning"]
    assert (tmp_path / run_id / "events.json").exists()
    assert json.loads((tmp_path / run_id / "audit.json").read_text(encoding="utf-8"))["app_name"]
    assert client.post(f"/api/run/{run_id}/mark", json={}).status_code == 409  # stopped
    assert run_id in client.get("/").text  # listed under past runs


def test_start_error_shown_on_form(client) -> None:
    r = client.post("/audit", data={"app_name": "Nothing"})
    assert r.status_code == 400 and "process name" in r.text


def test_bad_run_id_is_404(client) -> None:
    assert client.get("/run/..%2F..%2Fetc").status_code == 404
    assert client.get("/api/run/not-a-run").status_code == 404


def test_app_name_is_escaped(client) -> None:
    r = client.post("/audit", data={"app_name": "<script>x</script>"})
    assert "<script>x</script>" not in r.text and "&lt;script&gt;" in r.text
