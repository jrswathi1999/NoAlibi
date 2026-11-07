"""Run one audit end to end: capture + policy reading in parallel, then the verdict.

start  -> prime the identifier, launch the app, start the capture and (in parallel) fetch the
          policy and extract claims with the local model
mark   -> the user says "I just used the AI feature"
stop   -> write events, look up unknown domains (optional), compare, apply evidence strength,
          summarize locally, render the report, hash and bundle the evidence
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import threading
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from contracts.models import (
    RUN_ID_PATTERN,
    Claims,
    Events,
    Findings,
    Lookup,
    load_model,
    save_model,
)
from contracts.models import (
    AppInfo as ClaimsApp,
)
from engine.compare import run_compare
from engine.hashlog import evidence_sha256
from engine.summarize import run_summarize
from intel import lookup as domain_lookup
from intel.claims import extract_claims
from intel.policy import PolicyError, fetch_policy, guess_first_party, known_app
from report.render import render
from sensor.egress import EgressLedger
from sensor.identify import CONFIDENCE_RANK, Identifier
from sensor.procs import AppInfo
from sensor.session import AuditSession, Feed

log = logging.getLogger("app.audit")

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_FILES = [
    "claims.json",
    "events.json",
    "findings.json",
    "verdict.json",
    "flows.json",
    "timeline.json",
    "self_audit.json",
    "outbound_queries.log",
    "sensor.log",
    "policy.txt",
    "dropped_claims.json",
    "report.html",
]


def runs_dir() -> Path:
    return Path(os.environ.get("NOALIBI_DATA_DIR", ROOT / "data" / "runs"))


def make_run_id(app_name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", app_name.lower()).strip("-") or "app"
    return f"{datetime.now(UTC):%Y%m%d-%H%M%S}-{slug}"


def run_path(run_id: str) -> Path:
    if not RUN_ID_PATTERN.match(run_id):
        raise ValueError(f"bad run id {run_id!r}")
    return runs_dir() / run_id


def verdict_for(findings: Findings) -> dict:
    red = [f for f in findings.findings if f.severity == "red"]
    amber = [f for f in findings.findings if f.severity == "amber"]
    info = [f for f in findings.findings if f.severity == "info"]
    if red:
        verdict, line = "NO_ALIBI", red[0].title
    elif amber:
        verdict, line = "QUESTIONABLE", amber[0].title
    else:
        verdict, line = "ALIBI_HOLDS", "Nothing it did contradicts what its policy says."
    return {
        "verdict": verdict,
        "red": len(red),
        "amber": len(amber),
        "info": len(info),
        "one_liner": line,
    }


def apply_evidence_strength(findings: Findings, flows: dict) -> Findings:
    """A red finding resting only on 'possible'/'weak' identifications becomes amber, labelled.

    Fairness: we never accuse on a shared CDN address alone.
    """
    conf_by_domain: dict[str, int] = {}
    for f in flows.get("flows", []):
        key = f.get("domain") or f.get("ip")
        rank = CONFIDENCE_RANK.get(f.get("confidence", "unknown"), 0)
        conf_by_domain[key] = max(conf_by_domain.get(key, 0), rank)
    events = {e["id"]: e for e in flows.get("_events", [])}
    out = []
    for f in findings.findings:
        if f.severity == "red" and f.event_ids:
            ranks = [
                conf_by_domain.get(
                    events.get(eid, {}).get("domain") or events.get(eid, {}).get("ip"), 0
                )
                for eid in f.event_ids
            ]
            if ranks and max(ranks) < CONFIDENCE_RANK["likely"]:
                f = f.model_copy(
                    update={
                        "severity": "amber",
                        "title": f.title + " (shared CDN address, not confirmed)",
                    }
                )
        out.append(f)
    return findings.model_copy(update={"findings": out})


class Audit:
    def __init__(
        self,
        app: AppInfo,
        policy_url: str | None,
        fresh_launch: bool = True,
        cert_probe: bool = True,
        offline_policy: bool = False,
    ):
        self.app = app
        self.run_id = make_run_id(app.name)
        self.run_dir = run_path(self.run_id)
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.policy_url = policy_url or known_app(app.bundle_id).get("policy_url")
        self.feed = Feed()
        self.ledger = EgressLedger(self.run_dir / "outbound_queries.log")
        self.identifier = Identifier(
            first_party=guess_first_party(app.bundle_id, self.policy_url),
            app_name=app.name,
            cert_probe=cert_probe,
            on_egress=self.ledger,
        )
        self.session = AuditSession(app, self.run_dir, self.identifier, fresh_launch, self.feed)
        self.offline_policy = offline_policy
        self.claims: Claims | None = None
        self.policy_error: str | None = None
        self.state = "created"
        self.error: str | None = None
        self._intel_thread = threading.Thread(target=self._read_policy, name="intel", daemon=True)
        self.meta = {
            "run_id": self.run_id,
            "app": {
                "name": app.name,
                "bundle_id": app.bundle_id,
                "version": app.version,
                "bundle_path": app.bundle_path,
            },
            "policy_url": self.policy_url,
            "fresh_launch": fresh_launch,
            "cert_probe": cert_probe,
            "started_at": time.time(),
        }

    # ------------------------------------------------------------ lifecycle

    def _status(self, text: str, step: str | None = None) -> None:
        self.feed.publish({"type": "status", "text": text, "step": step or self.state})

    def start(self) -> None:
        self.state = "starting"
        self._dump("run.json", self.meta)
        self._intel_thread.start()
        self._status("Learning where known AI and analytics companies live on the internet")
        n = self.identifier.prime(guess_first_party(self.app.bundle_id, self.policy_url))
        self._status(f"Ready to recognise {n} server addresses")
        self.session.start()
        self.state = "capturing"

    def mark(self, label: str = "") -> None:
        self.session.mark(label)

    def stop(self) -> None:
        """Finish the capture and build the verdict. Runs in a worker thread (takes ~10-60 s)."""
        try:
            self.state = "judging"
            self.session.stop()
            self._status("Capture stopped. Writing evidence", "evidence")
            self.session.write(self.run_id)
            if self._intel_thread.is_alive():
                self._status("Waiting for the local model to finish reading the policy", "policy")
                self._intel_thread.join(timeout=300)
            self._save_claims()
            self._lookups()
            self._status("Comparing promises with behavior", "compare")
            run_compare(self.run_dir)
            flows = json.loads((self.run_dir / "flows.json").read_text(encoding="utf-8"))
            flows["_events"] = json.loads(
                (self.run_dir / "events.json").read_text(encoding="utf-8")
            )["events"]
            findings = apply_evidence_strength(
                load_model(self.run_dir / "findings.json", Findings), flows
            )
            save_model(self.run_dir / "findings.json", findings)
            if findings.findings:
                self._status("Writing a plain-English summary with the local model", "summary")
                run_summarize(self.run_dir)
            findings = load_model(self.run_dir / "findings.json", Findings)
            findings = findings.model_copy(
                update={"evidence_sha256": evidence_sha256(self.run_dir)}
            )
            save_model(self.run_dir / "findings.json", findings)
            self._dump("verdict.json", verdict_for(findings))
            self._status("Rendering the report and sealing the evidence", "report")
            render(self.run_dir)
            self.meta["ended_at"] = time.time()
            self._dump("run.json", self.meta)
            self.bundle()
            self.state = "done"
            self.feed.publish({"type": "done", "run_id": self.run_id, **verdict_for(findings)})
        except Exception as exc:
            log.exception("audit failed")
            self.state = "error"
            self.error = str(exc)
            self.feed.publish({"type": "error", "text": str(exc)})

    # ------------------------------------------------------------ steps

    def _read_policy(self) -> None:
        if not self.policy_url:
            self.policy_error = "No privacy policy URL given"
            self.feed.publish({"type": "policy_error", "text": self.policy_error})
            return
        try:
            self.feed.publish(
                {
                    "type": "policy",
                    "text": "Fetching the public privacy policy",
                    "url": self.policy_url,
                }
            )
            doc = fetch_policy(self.policy_url, ledger=self.ledger, offline=self.offline_policy)
            (self.run_dir / "policy.txt").write_text(doc.text, encoding="utf-8")
            self.feed.publish(
                {
                    "type": "policy",
                    "text": f"Read {len(doc.text):,} characters. The local model is reading it now",
                    "url": doc.url,
                }
            )
            self.claims = extract_claims(
                self.run_id,
                self.app.name,
                doc,
                on_claim=lambda c: self.feed.publish(
                    {"type": "claim", "claim": json.loads(c.model_dump_json())}
                ),
                on_progress=lambda text: self.feed.publish({"type": "policy", "text": text}),
                dropped_path=self.run_dir / "dropped_claims.json",
            )
            self.feed.publish(
                {
                    "type": "policy",
                    "text": f"{len(self.claims.claims)} promises found and verified",
                    "done": True,
                }
            )
        except (PolicyError, OSError, ValueError) as exc:
            self.policy_error = str(exc)
            self.feed.publish({"type": "policy_error", "text": str(exc)})

    def _save_claims(self) -> None:
        if self.claims is None:  # policy failed: an empty, honest claims file
            self.claims = Claims(
                run_id=self.run_id,
                app=ClaimsApp(
                    name=self.app.name,
                    policy_url=self.policy_url or "",
                    fetched_at=datetime.now(UTC),
                    policy_sha256="",
                ),
                model=os.environ.get("OLLAMA_MODEL", "qwen2.5:7b"),
                claims=[],
            )
        save_model(self.run_dir / "claims.json", self.claims)

    def _lookups(self) -> None:
        if not domain_lookup.available():
            return
        events = load_model(self.run_dir / "events.json", Events)
        unknown = sorted(
            {
                e.domain
                for e in events.events
                if e.category == "unknown" and e.domain and not e.lookup
            }
        )
        if not unknown:
            return
        self._status(
            f"Asking Tavily who is behind {len(unknown)} unknown domains (domain names only)",
            "lookup",
        )
        found = {d: domain_lookup.lookup(d, self.ledger) for d in unknown}
        patched = [
            e.model_copy(
                update={
                    "lookup": Lookup(**{k: v for k, v in found[e.domain].items() if k != "cached"})
                }
            )
            if found.get(e.domain)
            else e
            for e in events.events
        ]
        save_model(self.run_dir / "events.json", events.model_copy(update={"events": patched}))

    def bundle(self) -> Path:
        """evidence.zip with every file plus manifest.json of SHA-256 hashes."""
        manifest = {"run_id": self.run_id, "created_at": datetime.now(UTC).isoformat(), "files": {}}
        for name in EVIDENCE_FILES:
            p = self.run_dir / name
            if p.exists():
                manifest["files"][name] = hashlib.sha256(p.read_bytes()).hexdigest()
        findings = load_model(self.run_dir / "findings.json", Findings)
        manifest["evidence_sha256"] = findings.evidence_sha256
        manifest["verify"] = "cat claims.json events.json sensor.log | shasum -a 256"
        self._dump("manifest.json", manifest)
        out = self.run_dir / "evidence.zip"
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in [*manifest["files"], "manifest.json"]:
                zf.write(self.run_dir / name, arcname=f"{self.run_id}/{name}")
        return out

    def _dump(self, name: str, data: dict) -> None:
        (self.run_dir / name).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")


def list_runs() -> list[dict]:
    """Finished audits, newest first, for the registry."""
    out = []
    root = runs_dir()
    if not root.is_dir():
        return out
    for d in sorted(root.iterdir(), reverse=True):
        verdict, meta = d / "verdict.json", d / "run.json"
        if not (verdict.exists() and meta.exists()):
            continue
        try:
            out.append({**json.loads(meta.read_text()), **json.loads(verdict.read_text())})
        except ValueError:
            continue
    return out
