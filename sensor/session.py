"""One audit capture: watch the target app's processes, record bursts, publish a live feed.

Events are *activity bursts*: a run of consecutive 1-second samples in which one connection of the
target moved bytes. A long-lived connection that idles and then uploads 12 KB right after you click
"summarize" therefore yields a separate event at the moment of the click, which is what the rules
need. All bytes come from the kernel's per-socket counters (nettop); nothing is decrypted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from contracts.models import CaptureInfo, Event, Events, Lookup, UserAction, save_model
from sensor.identify import Identifier, Identity, is_public
from sensor.nettop import Conn, NettopStream, Sample
from sensor.procs import (
    AppInfo,
    hosts_self,
    launch_app,
    launched_pids,
    list_processes,
    quit_app,
    self_pids,
    target_pids,
)

log = logging.getLogger("sensor.session")

STARTUP_S = 10.0
ACTION_WINDOW_S = 5.0
SAMPLE_S = 1.0
TLS_PORTS = {443, 8443, 993, 995, 5223, 853}


def iso(t: float) -> str:
    return datetime.fromtimestamp(t, UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Burst:
    start: float
    end: float
    bytes_out: int = 0
    bytes_in: int = 0


@dataclass
class Flow:
    id: str
    conn: Conn
    first_seen: float
    preexisting: bool
    base_out: int
    base_in: int
    last_out: int
    last_in: int
    identity: Identity | None = None
    bursts: list[Burst] = field(default_factory=list)
    last_active: float = 0.0

    @property
    def bytes_out(self) -> int:
        return self.last_out - self.base_out

    @property
    def bytes_in(self) -> int:
        return self.last_in - self.base_in


class Feed:
    """Append-only message list with blocking reads, for the live UI (server-sent events)."""

    def __init__(self) -> None:
        self.items: list[dict] = []
        self.cond = threading.Condition()

    def publish(self, msg: dict) -> None:
        with self.cond:
            msg = {**msg, "seq": len(self.items)}
            self.items.append(msg)
            self.cond.notify_all()

    def since(self, seq: int, timeout: float = 15.0) -> list[dict]:
        with self.cond:
            if len(self.items) <= seq:
                self.cond.wait(timeout)
            return self.items[seq:]


class AuditSession:
    """Lifecycle: start() -> mark() any number of times -> stop() -> write(run_dir)."""

    def __init__(
        self,
        app: AppInfo,
        run_dir: Path,
        identifier: Identifier,
        fresh_launch: bool = True,
        feed: Feed | None = None,
    ):
        self.app = app
        self.run_dir = run_dir
        self.identifier = identifier
        self.fresh_launch = fresh_launch
        self.feed = feed or Feed()
        self.flows: dict[tuple, Flow] = {}
        self.self_flows: dict[tuple, dict] = {}
        self.launched: dict[str, dict] = {}  # separate programs started inside the app
        self._launched_seen: dict[tuple, tuple[int, int]] = {}
        self._launched_last: dict[tuple, tuple[int, int]] = {}
        self.actions: list[UserAction] = []
        self.ticks: list[dict] = []
        self.t_start = 0.0
        self.t0 = 0.0  # launch time (fresh) or start time (attach)
        self.t_end = 0.0
        self.state = "idle"
        self.warnings: list[str] = []
        self._prev_t = 0.0
        self._first_sample = True
        self._lock = threading.Lock()
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="identify")
        self._pending: list[Future] = []
        self._stream = NettopStream(self._on_sample, raw_log=str(run_dir / "sensor.log"))
        self._self = self_pids()

    # ------------------------------------------------------------ lifecycle

    def start(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.t_start = time.time()
        self.state = "starting"
        if self.fresh_launch and hosts_self(self.app.bundle_path):
            self.fresh_launch = False  # never quit the app we are running inside
            self.warnings.append(
                f"No Alibi runs inside {self.app.name}; watched it without restarting"
            )
        if self.fresh_launch:
            self.feed.publish(
                {"type": "status", "text": f"Quitting {self.app.name} for a cold start"}
            )
            quit_app(self.app)
            deadline = time.time() + 12
            while target_pids(self.app.bundle_path) - self._self and time.time() < deadline:
                time.sleep(0.5)
            if target_pids(self.app.bundle_path) - self._self:
                self.warnings.append(f"{self.app.name} did not quit; this is not a cold start")
        self._stream.start()
        time.sleep(1.2)  # let nettop take its first sample before the app opens
        if self.fresh_launch:
            self.feed.publish({"type": "status", "text": f"Launching {self.app.name}"})
            try:
                launch_app(self.app)
            except Exception as exc:  # noqa: BLE001
                self.warnings.append(f"could not launch the app: {exc}")
        self.t0 = time.time()
        self.state = "capturing"
        self.feed.publish({"type": "started", "t0": self.t0, "fresh": self.fresh_launch})

    def mark(self, label: str = "") -> UserAction:
        action = UserAction(
            t=datetime.fromtimestamp(time.time(), UTC), label=label or "user action"
        )
        with self._lock:
            self.actions.append(action)
        self.feed.publish(
            {
                "type": "mark",
                "t": action.t.timestamp(),
                "rel": action.t.timestamp() - self.t0,
                "label": action.label,
            }
        )
        return action

    def stop(self) -> None:
        self.state = "stopping"
        self._stream.stop()
        self.t_end = time.time()
        for fut in self._pending:
            try:
                fut.result(timeout=10)
            except Exception as exc:  # noqa: BLE001 - identification failure leaves identity None
                log.debug("identification failed: %s", exc)
        self._pool.shutdown(wait=False, cancel_futures=True)
        if self._stream.error:
            self.warnings.append(self._stream.error)
        self.state = "stopped"
        self.feed.publish({"type": "stopped", "t": self.t_end})

    # ------------------------------------------------------------ sampling

    def phase_at(self, t: float) -> str:
        for a in self.actions:
            at = a.t.timestamp()
            if at - SAMPLE_S <= t <= at + ACTION_WINDOW_S:
                return "user_action"
        if self.fresh_launch and t - self.t0 < STARTUP_S:
            return "startup"
        return "idle"

    def _identify(self, flow: Flow) -> None:
        flow.identity = self.identifier.identify(flow.conn.remote_ip, flow.conn.remote_port)
        if flow.identity is not None:
            self.feed.publish({"type": "flow", "flow": self.flow_view(flow)})

    def _on_sample(self, sample: Sample) -> None:
        procs = list_processes()
        mine = self._self | self_pids(procs)
        targets = target_pids(self.app.bundle_path, procs) - mine
        launched = {
            pid: name
            for pid, name in launched_pids(self.app.bundle_path, procs).items()
            if pid not in mine
        }
        t = sample.t
        interval_start = self._prev_t or (t - SAMPLE_S)
        up = down = 0
        new_flows: list[Flow] = []
        with self._lock:
            for c in sample.conns:
                if c.pid in mine:
                    self._track_self(c)
                    continue
                if c.pid in launched and is_public(c.remote_ip):
                    self._track_launched(launched[c.pid], c)
                    continue
                if c.pid not in targets or not is_public(c.remote_ip):
                    continue  # other apps, and the app talking to itself over localhost/LAN
                flow = self.flows.get(c.key)
                if flow is None:
                    pre = self._first_sample
                    flow = Flow(
                        id=f"c{len(self.flows) + 1}",
                        conn=c,
                        first_seen=interval_start,
                        preexisting=pre,
                        base_out=c.bytes_out if pre else 0,
                        base_in=c.bytes_in if pre else 0,
                        last_out=c.bytes_out if pre else 0,
                        last_in=c.bytes_in if pre else 0,
                    )
                    self.flows[c.key] = flow
                    new_flows.append(flow)
                d_out = max(0, c.bytes_out - flow.last_out)
                d_in = max(0, c.bytes_in - flow.last_in)
                flow.last_out, flow.last_in = (
                    max(flow.last_out, c.bytes_out),
                    max(flow.last_in, c.bytes_in),
                )
                if d_out or d_in:
                    gap = interval_start - flow.last_active
                    if flow.bursts and gap <= SAMPLE_S * 1.5:
                        b = flow.bursts[-1]
                        b.end, b.bytes_out, b.bytes_in = t, b.bytes_out + d_out, b.bytes_in + d_in
                    else:
                        flow.bursts.append(Burst(interval_start, t, d_out, d_in))
                    flow.last_active = t
                    up += d_out
                    down += d_in
            self._first_sample = False
            self._prev_t = t
            tick = {"t": t, "rel": t - self.t0 if self.t0 else 0.0, "up": up, "down": down}
            self.ticks.append(tick)
        for flow in new_flows:
            self._pending.append(self._pool.submit(self._identify, flow))
        active = [self.flow_view(f) for f in self.flows.values() if f.last_active == t]
        self.feed.publish(
            {
                "type": "tick",
                **tick,
                "phase": self.phase_at(interval_start) if self.t0 else "starting",
                "total_up": sum(f.bytes_out for f in self.flows.values()),
                "total_down": sum(f.bytes_in for f in self.flows.values()),
                "flows": len(self.flows),
                "active": active,
                "self_up": sum(v["bytes_out"] for v in self.self_flows.values()),
            }
        )

    def _track_launched(self, name: str, c: Conn) -> None:
        """Traffic of separate programs started inside the app (e.g. `claude` in its terminal)."""
        key = (c.pid, c.proto, c.local_port, c.remote_ip, c.remote_port)
        first = key not in self._launched_seen
        base = self._launched_seen.setdefault(
            key, (c.bytes_out, c.bytes_in) if self._first_sample else (0, 0)
        )
        entry = self.launched.setdefault(
            name, {"program": name, "bytes_out": 0, "bytes_in": 0, "servers": set()}
        )
        prev = self._launched_last.get(key, base)
        entry["bytes_out"] += max(0, c.bytes_out - prev[0])
        entry["bytes_in"] += max(0, c.bytes_in - prev[1])
        entry["servers"].add(c.remote_ip)
        self._launched_last[key] = (c.bytes_out, c.bytes_in)
        if first:
            log.info("not counted against the app: %s -> %s", name, c.remote_ip)

    def _track_self(self, c: Conn) -> None:
        if not is_public(c.remote_ip):
            return
        key = (c.proto, c.local_port, c.remote_ip, c.remote_port)
        entry = self.self_flows.setdefault(
            key,
            {
                "remote": f"{c.remote_ip}:{c.remote_port}",
                "proc": c.proc,
                "base_out": c.bytes_out if self._first_sample else 0,
                "bytes_out": 0,
                "bytes_in": 0,
            },
        )
        entry["bytes_out"] = c.bytes_out - entry["base_out"]
        entry["bytes_in"] = c.bytes_in

    # ------------------------------------------------------------ views and output

    def flow_view(self, f: Flow) -> dict:
        ident = f.identity
        return {
            "id": f.id,
            "proc": f.conn.proc,
            "pid": f.conn.pid,
            "proto": f.conn.proto,
            "ip": f.conn.remote_ip,
            "port": f.conn.remote_port,
            "domain": ident.domain if ident else None,
            "owner": ident.owner if ident else None,
            "category": ident.raw_category if ident else "identifying",
            "confidence": ident.confidence if ident else "unknown",
            "source": ident.source if ident else None,
            "note": ident.note if ident else None,
            "bytes_out": f.bytes_out,
            "bytes_in": f.bytes_in,
            "first_rel": f.first_seen - self.t0 if self.t0 else 0.0,
            "preexisting": f.preexisting,
        }

    def build_events(self, run_id: str, log_sha256: str) -> tuple[Events, dict[str, str]]:
        """Contract events (one per burst, public destinations only) + event_id -> flow_id map."""
        events: list[Event] = []
        event_flow: dict[str, str] = {}
        bursts = [
            (b, f)
            for f in self.flows.values()
            if f.identity is not None  # None = local/private address, not reported
            for b in f.bursts
        ]
        for b, f in sorted(bursts, key=lambda x: x[0].start):
            ident = f.identity
            assert ident is not None
            lookup = None
            if ident.category == "unknown" and (ident.owner or ident.note):
                summary = ": ".join(x for x in (ident.owner, ident.note) if x)
                lookup = Lookup(source="catalog", summary=summary, url="")
            eid = f"e{len(events) + 1}"
            events.append(
                Event(
                    id=eid,
                    t=datetime.fromtimestamp(b.start, UTC),
                    t_rel_s=round(b.start - self.t0, 2),
                    domain=ident.domain,
                    ip=f.conn.remote_ip,
                    port=f.conn.remote_port,
                    bytes_out=b.bytes_out,
                    bytes_in=b.bytes_in,
                    tls=f.conn.remote_port in TLS_PORTS,
                    phase=self.phase_at(b.start),  # type: ignore[arg-type]
                    category=ident.category,  # type: ignore[arg-type]
                    owner=ident.owner,
                    lookup=lookup,
                )
            )
            event_flow[eid] = f.id
        capture = CaptureInfo(
            start=datetime.fromtimestamp(self.t_start, UTC),
            end=datetime.fromtimestamp(self.t_end or time.time(), UTC),
            interface="nettop (per-process socket counters, 1 s)",
            pcap_sha256=log_sha256,
        )
        return Events(
            run_id=run_id, capture=capture, user_actions=self.actions, events=events
        ), event_flow

    def write(self, run_id: str) -> Path:
        """Write events.json, flows.json, timeline.json and self_audit.json into run_dir."""
        log_path = self.run_dir / "sensor.log"
        log_sha = hashlib.sha256(log_path.read_bytes()).hexdigest() if log_path.exists() else ""
        events, event_flow = self.build_events(run_id, log_sha)
        out = save_model(self.run_dir / "events.json", events)

        flows = [
            {**self.flow_view(f), "bursts": [b.__dict__ for b in f.bursts]}
            for f in self.flows.values()
            if f.identity is not None
        ]
        launched = [
            {**{k: v for k, v in e.items() if k != "servers"}, "servers": len(e["servers"])}
            for e in self.launched.values()
            if e["bytes_out"] or e["bytes_in"]
        ]
        self._dump(
            "flows.json",
            {"t0": self.t0, "event_flow": event_flow, "flows": flows, "launched": launched},
        )

        by_cat: dict[str, list[float]] = defaultdict(list)
        series = []
        for f in self.flows.values():
            if f.identity is None:
                continue
            for b in f.bursts:
                series.append(
                    {
                        "rel": round(b.start - self.t0, 2),
                        "dur": round(b.end - b.start, 2),
                        "out": b.bytes_out,
                        "in": b.bytes_in,
                        "flow": f.id,
                        "domain": f.identity.domain or f.conn.remote_ip,
                        "category": f.identity.raw_category,
                    }
                )
                by_cat[f.identity.raw_category].append(b.bytes_out)
        self._dump(
            "timeline.json",
            {
                "t0": self.t0,
                "duration": round((self.t_end or time.time()) - self.t0, 2),
                "fresh_launch": self.fresh_launch,
                "startup_s": STARTUP_S if self.fresh_launch else 0,
                "action_window_s": ACTION_WINDOW_S,
                "actions": [
                    {"rel": a.t.timestamp() - self.t0, "label": a.label} for a in self.actions
                ],
                "bursts": sorted(series, key=lambda x: x["rel"]),
                "ticks": [
                    {"rel": round(t["rel"], 2), "up": t["up"], "down": t["down"]}
                    for t in self.ticks
                ],
                "warnings": self.warnings,
            },
        )
        self._dump(
            "self_audit.json",
            {
                "pids": sorted(self._self),
                "connections": [
                    {k: v for k, v in e.items() if k != "base_out"}
                    for e in self.self_flows.values()
                ],
            },
        )
        return out

    def _dump(self, name: str, data: dict) -> None:
        (self.run_dir / name).write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
