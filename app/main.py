"""Local web UI: start an audit, mark the moment you use the AI feature, stop, see what it did.

Run (then open http://127.0.0.1:8000):
    .\\.venv\\Scripts\\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from behavior.recorder import Recorder
from behavior.run_behavior import events_from_run_dir, preview_events
from contracts.models import RUN_ID_RE, Events, load_model, make_run_id, save_model
from settings import REPO_ROOT

RUNS_DIR = REPO_ROOT / "data" / "runs"
LIVE_REFRESH_SECONDS = 2.5

app = FastAPI(title="No Alibi", docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def _split(text: str) -> list[str]:
    return [x.strip() for x in (text or "").replace(";", ",").split(",") if x.strip()]


@dataclass
class Session:
    run_id: str
    app_name: str
    recorder: Recorder
    first_party: list[str]
    update: list[str] = field(default_factory=list)
    state: str = "recording"  # recording -> analyzing -> done | error
    error: str | None = None
    live: list[dict] = field(default_factory=list)
    live_error: str | None = None
    warnings: list[str] = field(default_factory=list)

    @property
    def run_dir(self) -> Path:
        return RUNS_DIR / self.run_id


SESSIONS: dict[str, Session] = {}


def _watch(session: Session) -> None:
    """Background thread: refresh the live view while recording, then analyze once stopped."""
    rec = session.recorder
    while rec.recording:
        time.sleep(LIVE_REFRESH_SECONDS)
        try:
            session.live = preview_events(rec, session.first_party, session.update)
            session.live_error = None
        except Exception as exc:  # noqa: BLE001 - the live view is best effort
            session.live_error = str(exc)
    session.state = "analyzing"
    try:
        events, warnings = events_from_run_dir(
            session.run_dir, session.first_party, session.update, offline=False
        )
        save_model(session.run_dir / "events.json", events)
        session.warnings = warnings
        session.state = "done"
    except Exception as exc:  # noqa: BLE001 - show the error on the page, never crash the server
        session.error = f"{type(exc).__name__}: {exc}"
        session.state = "error"


def _check_run_id(run_id: str) -> None:
    if not RUN_ID_RE.match(run_id):
        raise HTTPException(404, "unknown run")


def _past_runs(limit: int = 10) -> list[dict]:
    if not RUNS_DIR.exists():
        return []
    runs = []
    for d in sorted(RUNS_DIR.iterdir(), reverse=True):
        if d.is_dir() and RUN_ID_RE.match(d.name) and (d / "events.json").exists():
            meta = d / "audit.json"
            name = json.loads(meta.read_text(encoding="utf-8"))["app_name"] if meta.exists() else ""
            runs.append({"run_id": d.name, "app_name": name})
        if len(runs) >= limit:
            break
    return runs


@app.get("/", response_class=HTMLResponse)
def home(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request, "home.html", {"runs": _past_runs(), "error": None, "form": {}}
    )


@app.post("/audit")
def start_audit(
    request: Request,
    app_name: str = Form(...),
    cmd: str = Form(""),
    proc_names: str = Form(""),
    first_party: str = Form(""),
    seconds: int = Form(120),
    interface: str = Form("Wi-Fi"),
):
    form = {
        "app_name": app_name,
        "cmd": cmd,
        "proc_names": proc_names,
        "first_party": first_party,
        "seconds": seconds,
        "interface": interface,
    }
    run_id = make_run_id(app_name)
    run_dir = RUNS_DIR / run_id
    try:
        rec = Recorder(
            run_dir,
            cmd=cmd.strip() or None,
            proc_names=_split(proc_names),
            interface=interface.strip() or "Wi-Fi",
            max_seconds=max(10, min(seconds, 900)),
        )
        rec.start()
    except Exception as exc:  # noqa: BLE001 - show it on the form
        return templates.TemplateResponse(
            request,
            "home.html",
            {"runs": _past_runs(), "error": str(exc), "form": form},
            status_code=400,
        )
    (run_dir / "audit.json").write_text(json.dumps(form, indent=2) + "\n", encoding="utf-8")
    session = Session(run_id, app_name, rec, _split(first_party))
    SESSIONS[run_id] = session
    threading.Thread(target=_watch, args=(session,), daemon=True).start()
    return RedirectResponse(f"/run/{run_id}", status_code=303)


@app.get("/run/{run_id}", response_class=HTMLResponse)
def run_page(request: Request, run_id: str) -> HTMLResponse:
    _check_run_id(run_id)
    if run_id not in SESSIONS and not (RUNS_DIR / run_id / "events.json").exists():
        raise HTTPException(404, "unknown run")
    return templates.TemplateResponse(request, "run.html", {"run_id": run_id})


@app.get("/api/run/{run_id}")
def run_status(run_id: str) -> JSONResponse:
    _check_run_id(run_id)
    session = SESSIONS.get(run_id)
    if session is None:  # a finished run from an earlier server session
        path = RUNS_DIR / run_id / "events.json"
        if not path.exists():
            raise HTTPException(404, "unknown run")
        events = load_model(path, Events)
        meta = RUNS_DIR / run_id / "audit.json"
        name = json.loads(meta.read_text(encoding="utf-8"))["app_name"] if meta.exists() else ""
        return JSONResponse(_done_payload(run_id, name, events, [], []))
    rec = session.recorder
    if session.state == "done":
        events = load_model(session.run_dir / "events.json", Events)
        return JSONResponse(
            _done_payload(run_id, session.app_name, events, rec.process_names(), session.warnings)
        )
    return JSONResponse(
        {
            "run_id": run_id,
            "app_name": session.app_name,
            "state": session.state,
            "error": session.error,
            "elapsed": round(rec.elapsed(), 1),
            "max_seconds": rec.max_seconds,
            "marks": [{"t": a["t"].isoformat(), "label": a["label"]} for a in rec.marker.actions],
            "processes": rec.process_names(),
            "events": session.live,
            "live_error": session.live_error,
            "warnings": session.warnings,
        }
    )


def _done_payload(run_id, app_name, events: Events, processes, warnings) -> dict:
    start, end = events.capture.start, events.capture.end
    return {
        "run_id": run_id,
        "app_name": app_name,
        "state": "done",
        "error": None,
        "elapsed": round((end - start).total_seconds(), 1),
        "max_seconds": None,
        "marks": [{"t": a.t.isoformat(), "label": a.label} for a in events.user_actions],
        "processes": processes,
        "events": [e.model_dump(mode="json") for e in events.events],
        "live_error": None,
        "warnings": warnings,
    }


@app.post("/api/run/{run_id}/mark")
async def mark(run_id: str, request: Request) -> JSONResponse:
    _check_run_id(run_id)
    session = SESSIONS.get(run_id)
    if session is None or not session.recorder.recording:
        raise HTTPException(409, "not recording")
    try:
        body = await request.json()
    except ValueError:
        body = {}
    action = session.recorder.mark(str(body.get("label", ""))[:120])
    return JSONResponse({"t": action["t"].isoformat(), "label": action["label"]})


@app.post("/api/run/{run_id}/stop")
def stop(run_id: str) -> JSONResponse:
    _check_run_id(run_id)
    session = SESSIONS.get(run_id)
    if session is None:
        raise HTTPException(404, "unknown run")
    threading.Thread(target=session.recorder.stop, daemon=True).start()  # idempotent
    return JSONResponse({"ok": True})
