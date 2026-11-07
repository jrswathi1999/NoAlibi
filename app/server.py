"""Local web server for the No Alibi UI. Binds to 127.0.0.1 only; nothing is served to the network.

GET  /                               the app (web/index.html)
GET  /api/health                     what's available: nettop, Ollama model, Tavily
GET  /api/apps                       installed apps (+ known policy URL, running?)
GET  /api/apps/{bundle_id}/icon      app icon as PNG
POST /api/audits                     start {bundle_id, policy_url?, fresh_launch, cert_probe}
POST /api/audits/{run_id}/mark       "I just used the AI feature"
POST /api/audits/{run_id}/stop       stop and judge
GET  /api/audits/{run_id}/stream     live server-sent events
GET  /api/runs                       past verdicts
GET  /api/runs/{run_id}              everything the verdict screen needs
GET  /api/runs/{run_id}/report.html  printable one-page report
GET  /api/runs/{run_id}/evidence.zip sealed evidence bundle
DELETE /api/runs/{run_id}            delete a run (it's your data)
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import sys
import threading
from pathlib import Path

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.audit import Audit, list_runs, run_path
from intel import lookup as domain_lookup
from intel.policy import known_app
from sensor.procs import hosts_self, list_apps, list_processes

log = logging.getLogger("app.server")

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "web"
ICON_CACHE = ROOT / "data" / "cache" / "icons"

app = FastAPI(title="No Alibi", version="0.2.0", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=WEB), name="static")

AUDITS: dict[str, Audit] = {}
_lock = threading.Lock()


class StartRequest(BaseModel):
    bundle_id: str
    policy_url: str | None = None
    fresh_launch: bool = True
    cert_probe: bool = True


class MarkRequest(BaseModel):
    label: str = ""


def _app_by_id(bundle_id: str):
    for a in list_apps():
        if a.bundle_id == bundle_id:
            return a
    raise HTTPException(404, f"app {bundle_id} is not installed")


def _audit(run_id: str) -> Audit:
    audit = AUDITS.get(run_id)
    if not audit:
        raise HTTPException(404, "no live audit with that id")
    return audit


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB / "index.html", headers={"Cache-Control": "no-store"})


@app.get("/api/health")
def health() -> dict:
    model = os.environ.get("OLLAMA_MODEL", "qwen2.5:7b")
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    try:
        tags = requests.get(f"{host}/api/tags", timeout=2).json()
        models = [m["name"] for m in tags.get("models", [])]
        ollama = {"ok": model in models, "model": model, "installed": models}
    except (requests.RequestException, ValueError):
        ollama = {"ok": False, "model": model, "installed": []}
    return {
        "platform": sys.platform,
        "nettop": shutil.which("nettop") is not None,
        "ollama": ollama,
        "search": domain_lookup.available(),
        "busy": any(a.state in ("starting", "capturing", "judging") for a in AUDITS.values()),
    }


@app.get("/api/apps")
def apps() -> list[dict]:
    procs = list_processes()
    commands = [p.command for p in procs.values()]
    out = []
    for a in list_apps():
        prefix = a.bundle_path.rstrip("/") + "/"
        out.append(
            {
                "name": a.name.strip("‎"),
                "bundle_id": a.bundle_id,
                "version": a.version,
                "policy_url": known_app(a.bundle_id).get("policy_url"),
                "running": any(c.startswith(prefix) for c in commands),
                "hosts_self": hosts_self(a.bundle_path, procs),
                "icon": f"/api/apps/{a.bundle_id}/icon" if a.icon_path else None,
            }
        )
    return out


@app.get("/api/apps/{bundle_id}/icon")
def app_icon(bundle_id: str) -> FileResponse:
    from sensor.procs import icon_png

    png = icon_png(_app_by_id(bundle_id), ICON_CACHE)
    if not png:
        raise HTTPException(404, "no icon")
    return FileResponse(png, media_type="image/png", headers={"Cache-Control": "max-age=86400"})


@app.post("/api/audits", status_code=202)
def start_audit(req: StartRequest) -> dict:
    with _lock:
        if any(a.state in ("starting", "capturing", "judging") for a in AUDITS.values()):
            raise HTTPException(409, "an audit is already running; stop it first")
        target = _app_by_id(req.bundle_id)
        if req.fresh_launch and hosts_self(target.bundle_path):
            raise HTTPException(
                409,
                f"No Alibi is running inside {target.name.strip()}, so it can't quit and reopen it. "
                "Turn off Cold start to watch it while it runs.",
            )
        policy = (req.policy_url or "").strip() or None
        audit = Audit(target, policy, fresh_launch=req.fresh_launch, cert_probe=req.cert_probe)
        AUDITS[audit.run_id] = audit
    threading.Thread(target=_safe_start, args=(audit,), daemon=True).start()
    return {"run_id": audit.run_id, "policy_url": audit.policy_url}


def _safe_start(audit: Audit) -> None:
    try:
        audit.start()
    except Exception as exc:
        log.exception("start failed")
        audit.state, audit.error = "error", str(exc)
        audit.feed.publish({"type": "error", "text": f"Could not start: {exc}"})


@app.post("/api/audits/{run_id}/mark")
def mark(run_id: str, req: MarkRequest) -> dict:
    audit = _audit(run_id)
    if audit.state != "capturing":
        raise HTTPException(409, "not capturing")
    audit.mark(req.label)
    return {"ok": True}


@app.post("/api/audits/{run_id}/stop", status_code=202)
def stop(run_id: str) -> dict:
    audit = _audit(run_id)
    if audit.state not in ("capturing", "starting"):
        raise HTTPException(409, f"audit is {audit.state}")
    audit.state = "judging"
    threading.Thread(target=audit.stop, daemon=True).start()
    return {"ok": True}


@app.get("/api/audits/{run_id}/stream")
def stream(run_id: str, request: Request, since: int = 0) -> StreamingResponse:
    audit = _audit(run_id)

    def gen():
        seq = since
        yield "retry: 1000\n\n"
        while True:
            items = audit.feed.since(seq, timeout=10)
            if not items:
                yield ": keepalive\n\n"
                if audit.state in ("done", "error"):
                    return
                continue
            for item in items:
                seq = item["seq"] + 1
                yield f"id: {item['seq']}\ndata: {json.dumps(item)}\n\n"

    return StreamingResponse(
        gen(), media_type="text/event-stream", headers={"Cache-Control": "no-store"}
    )


@app.get("/api/runs")
def runs() -> list[dict]:
    return list_runs()


def _read(run_dir: Path, name: str):
    p = run_dir / name
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8")
    return json.loads(text) if name.endswith(".json") else text


@app.get("/api/runs/{run_id}")
def run_detail(run_id: str) -> dict:
    try:
        d = run_path(run_id)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not (d / "findings.json").exists():
        raise HTTPException(404, "no finished audit with that id")
    egress = []
    log_text = _read(d, "outbound_queries.log") or ""
    for line in log_text.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            egress.append({"t": float(parts[0]), "kind": parts[1], "sent": parts[2]})
    return {
        name.split(".")[0]: _read(d, name)
        for name in (
            "run.json",
            "claims.json",
            "events.json",
            "findings.json",
            "verdict.json",
            "flows.json",
            "timeline.json",
            "self_audit.json",
            "dropped_claims.json",
            "manifest.json",
        )
    } | {"egress": egress}


@app.get("/api/runs/{run_id}/report.html")
def run_report(run_id: str) -> FileResponse:
    p = run_path(run_id) / "report.html"
    if not p.exists():
        raise HTTPException(404, "report not ready")
    return FileResponse(p, media_type="text/html")


@app.get("/api/runs/{run_id}/evidence.zip")
def run_evidence(run_id: str) -> FileResponse:
    p = run_path(run_id) / "evidence.zip"
    if not p.exists():
        raise HTTPException(404, "evidence not ready")
    return FileResponse(p, media_type="application/zip", filename=f"no-alibi-{run_id}.zip")


@app.delete("/api/runs/{run_id}")
def delete_run(run_id: str) -> dict:
    d = run_path(run_id)
    if run_id in AUDITS and AUDITS[run_id].state in ("starting", "capturing", "judging"):
        raise HTTPException(409, "audit still running")
    if d.exists():
        shutil.rmtree(d)
    AUDITS.pop(run_id, None)
    return {"ok": True}
