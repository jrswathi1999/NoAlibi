"""CLI: run the app, record only its own connections, write events.json. No sandbox.

    python -m behavior.run_behavior --cmd "C:\\Path\\App.exe" --proc-name App.exe \\
        --run-dir data/runs/<run_id> --seconds 90 --first-party app.com

Press Enter each time you use the app's AI feature. Ctrl+C stops early.
Re-parse a saved capture without running the app:  --from-pcap
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from behavior.capture import Capture, CaptureError, sha256_file
from behavior.categorize import categorize, load_endpoints
from behavior.domain_lookup import lookup_domains
from behavior.mark import ActionMarker, load_actions, phase_for
from behavior.parse_pcap import Flow, build_flows, read_packets
from behavior.procwatch import SocketWatcher, local_ips, wait_for_processes
from contracts.models import RUN_ID_RE, CaptureInfo, Event, Events, Lookup, UserAction, save_model

SPLIT_GAP_SECONDS = 5.0  # a pause this long starts a new event on the same connection
MIN_EVENT_BYTES = 120  # drop bare TCP keep-alive ACKs


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ts(t: float) -> datetime:
    return datetime.fromtimestamp(t, UTC)


# ---------------------------------------------------------------- flows -> events


def split_flow(flow: Flow, start: datetime, actions: list[datetime]) -> list[dict]:
    """Cut one flow into pieces: a new piece when the phase changes or after a 5 s pause."""
    pieces: list[dict] = []
    current: dict | None = None
    last_t = None
    for t, out, inn in flow.samples:
        phase = phase_for(_ts(t), start, actions)
        new_piece = current is None or phase != current["phase"] or (t - last_t) > SPLIT_GAP_SECONDS
        if new_piece:
            current = {"t": t, "phase": phase, "out": 0, "in": 0}
            pieces.append(current)
        current["out"] += out
        current["in"] += inn
        last_t = t
    return [p for p in pieces if p["out"] + p["in"] >= MIN_EVENT_BYTES]


def build_events(
    run_id: str,
    flows: list[Flow],
    capture: CaptureInfo,
    actions: list[dict],
    first_party: list[str],
    update: list[str],
    lookups: dict[str, dict | None] | None = None,
) -> Events:
    endpoints = load_endpoints()
    action_times = [a["t"] for a in actions]
    rows = []
    for flow in flows:
        category, owner = categorize(flow.domain, endpoints, first_party, update)
        for piece in split_flow(flow, capture.start, action_times):
            rows.append((piece, flow, category, owner))
    rows.sort(key=lambda r: r[0]["t"])
    events = []
    for i, (piece, flow, category, owner) in enumerate(rows, start=1):
        found = (lookups or {}).get(flow.domain or "") if category == "unknown" else None
        events.append(
            Event(
                id=f"e{i}",
                t=_ts(piece["t"]),
                t_rel_s=round(max(0.0, piece["t"] - capture.start.timestamp()), 1),
                domain=flow.domain,
                ip=flow.ip,
                port=flow.port,
                bytes_out=piece["out"],
                bytes_in=piece["in"],
                tls=flow.tls,
                phase=piece["phase"],
                category=category,
                owner=owner,
                lookup=Lookup(**found) if found else None,
            )
        )
    return Events(
        run_id=run_id,
        capture=capture,
        user_actions=[UserAction(t=a["t"], label=a["label"]) for a in actions],
        events=events,
    )


# ---------------------------------------------------------------- live recording


def record(
    run_dir: Path,
    cmd: str | None,
    proc_names: list[str],
    seconds: int,
    interface: str,
    auto_mark: float | None = None,
    interactive: bool = True,
) -> None:
    """Capture while the app runs. Writes run.pcap, capture.json, actions.json, sockets.json."""
    if not cmd and not proc_names:
        raise ValueError("give --cmd (launch the app) and/or --proc-name (attach by process name)")
    pcap = run_dir / "run.pcap"
    capture = Capture(interface, pcap, max_seconds=seconds + 120)
    marker = ActionMarker()
    watcher: SocketWatcher | None = None
    start = end = datetime.now(UTC)
    try:
        capture.start()
        start = datetime.now(UTC)
        root_pid = None
        if cmd:
            flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
            root_pid = subprocess.Popen(cmd, shell=True, creationflags=flags).pid
        watcher = SocketWatcher(root_pid=root_pid, proc_names=proc_names)
        watcher.start()
        if not cmd and not wait_for_processes(watcher, timeout=30):
            raise CaptureError(f"no running process named {proc_names} within 30 s")
        if interactive:
            marker.listen()
        print(f"Recording {seconds} s on {interface}. Press Enter when you use the AI feature.")
        began = time.monotonic()
        marked = False
        try:
            while time.monotonic() - began < seconds:
                if auto_mark is not None and not marked and time.monotonic() - began >= auto_mark:
                    marker.add("auto mark")
                    marked = True
                time.sleep(0.2)
        except KeyboardInterrupt:
            print("Stopped early.")
    finally:
        end = datetime.now(UTC)
        if watcher:
            watcher.stop()
        capture.stop()  # always, even after a crash
    marker.save(run_dir / "actions.json")
    sockets = sorted(watcher.sockets) if watcher else []
    (run_dir / "sockets.json").write_text(
        json.dumps(
            {
                "sockets": sockets,
                "processes": sorted(watcher.process_names) if watcher else [],
                "my_ips": sorted(local_ips()),
                "errors": watcher.errors if watcher else [],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    info = {"start": iso(start), "end": iso(end), "interface": interface}
    (run_dir / "capture.json").write_text(json.dumps(info, indent=2) + "\n", encoding="utf-8")


def events_from_run_dir(
    run_dir: Path, first_party: list[str], update: list[str], offline: bool
) -> tuple[Events, list[str]]:
    """Parse run.pcap + the side files into Events. Returns (events, warnings)."""
    warnings: list[str] = []
    pcap = run_dir / "run.pcap"
    if not pcap.exists():
        raise ValueError(f"{pcap} not found")
    meta = json.loads((run_dir / "capture.json").read_text(encoding="utf-8"))
    side = json.loads((run_dir / "sockets.json").read_text(encoding="utf-8"))
    app_sockets = {(p, int(port)) for p, port in side["sockets"]}
    if not app_sockets:
        warnings.append("no connections were seen for the app's processes (check --proc-name)")
    flows = build_flows(read_packets(pcap), set(side["my_ips"]) | local_ips(), app_sockets)
    capture = CaptureInfo(
        start=meta["start"],
        end=meta["end"],
        interface=meta["interface"],
        pcap_sha256=sha256_file(pcap),
    )
    actions = load_actions(run_dir / "actions.json")
    events = build_events(run_dir.name, flows, capture, actions, first_party, update)
    unknown = sorted({e.domain for e in events.events if e.category == "unknown" and e.domain})
    if unknown and not offline:
        lookups, errors = lookup_domains(unknown, run_dir)
        warnings += errors
        events = build_events(run_dir.name, flows, capture, actions, first_party, update, lookups)
    return events, warnings


def run_behavior(
    run_dir: Path,
    cmd: str | None = None,
    proc_names: list[str] | None = None,
    seconds: int = 90,
    interface: str = "Wi-Fi",
    first_party: list[str] | None = None,
    update_domains: list[str] | None = None,
    auto_mark: float | None = None,
    offline: bool = False,
    from_pcap: bool = False,
    interactive: bool = True,
) -> Path:
    """Record (unless from_pcap) and write run_dir/events.json. Returns its path."""
    run_dir = Path(run_dir)
    if not RUN_ID_RE.match(run_dir.name):
        raise ValueError(f"run folder name {run_dir.name!r} must look like YYYYMMDD-HHMMSS-<app>")
    run_dir.mkdir(parents=True, exist_ok=True)
    if not from_pcap:
        record(run_dir, cmd, proc_names or [], seconds, interface, auto_mark, interactive)
    events, warnings = events_from_run_dir(
        run_dir, first_party or [], update_domains or [], offline
    )
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    return save_model(run_dir / "events.json", events)


def summarize(events: Events) -> str:
    lines = [f"{len(events.events)} events:"]
    for e in events.events:
        lines.append(
            f"  {e.id:>4} +{e.t_rel_s:>5.1f}s {e.phase:<11} {e.category:<15} "
            f"{(e.domain or e.ip):<40} out {e.bytes_out:>7} B  in {e.bytes_in:>7} B"
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("--run-dir", required=True, type=Path)
    p.add_argument("--cmd", help="command that launches the app")
    p.add_argument(
        "--proc-name", action="append", default=[], help="app process name, e.g. Notion.exe"
    )
    p.add_argument("--seconds", type=int, default=90)
    p.add_argument("--interface", default="Wi-Fi", help="see: tshark -D")
    p.add_argument("--first-party", action="append", default=[], help="the app's own domain")
    p.add_argument("--update-domain", action="append", default=[])
    p.add_argument("--auto-mark", type=float, help="mark an action N seconds in (for tests)")
    p.add_argument("--offline", action="store_true", help="skip Tavily/Exa domain lookups")
    p.add_argument("--from-pcap", action="store_true", help="re-parse run.pcap, do not record")
    a = p.parse_args(argv)
    try:
        path = run_behavior(
            a.run_dir,
            cmd=a.cmd,
            proc_names=a.proc_name,
            seconds=a.seconds,
            interface=a.interface,
            first_party=a.first_party,
            update_domains=a.update_domain,
            auto_mark=a.auto_mark,
            offline=a.offline,
            from_pcap=a.from_pcap,
        )
    except (ValueError, CaptureError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    from contracts.models import load_model

    print(summarize(load_model(path, Events)))
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
