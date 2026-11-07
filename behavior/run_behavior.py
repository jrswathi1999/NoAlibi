"""CLI: sandbox up, capture, run app, mark, parse, write events.json, sandbox down.

Live run (Linux, needs root; -E keeps DISPLAY/XAUTHORITY for GUI apps):
    sudo -E .venv/bin/python -m behavior.run_behavior --cmd "notesapp" \
        --run-dir data/runs/20261107-201500-notesapp --seconds 90 \
        --app-name NotesApp --first-party notesapp.com

Re-parse an existing capture (no root, no network namespace):
    python -m behavior.run_behavior --from-pcap --run-dir data/runs/<id> ...

While capturing, press Enter (optionally type a label first) to mark a user action.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

from behavior.capture import CaptureError, sha256_file, start_capture, stop_capture
from behavior.domain_lookup import categorize, load_endpoints
from behavior.mark import ActionMarker, iso, phase_for
from behavior.parse_pcap import Flow, ParseError, parse_pcap

try:  # Prefer the shared contract once Shri's contracts/models.py exists.
    from contracts.models import Events  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - fallback until CP0 lands
    from behavior.schema import Events

SANDBOX = Path(__file__).with_name("sandbox.sh")


class BehaviorError(RuntimeError):
    pass


def _iso_to_epoch(s: str) -> float:
    from datetime import datetime

    return datetime.fromisoformat(s).timestamp()  # 3.11+ accepts "Z"


def flow_phase(f: Flow, start: float, actions: list[float]) -> tuple[str, float]:
    """Pick the phase where the flow sent the most bytes, and the time it started sending then.

    A connection opened at startup and reused after a click (HTTP/2 keep-alive)
    is labelled by where its upload actually happened, not when it was opened.
    """
    if not f.out_bytes_by_t:
        return phase_for(f.first_t, start, actions), f.first_t
    by_phase: dict[str, int] = {}
    first_t: dict[str, float] = {}
    for t, n in f.out_bytes_by_t:
        ph = phase_for(t, start, actions)
        by_phase[ph] = by_phase.get(ph, 0) + n
        first_t.setdefault(ph, t)
    best = max(by_phase, key=lambda ph: (by_phase[ph], -first_t[ph]))
    return best, first_t[best]


def build_events(
    run_id: str,
    flows: list[Flow],
    capture: dict,
    actions: list[dict],
    app_name: str | None = None,
    first_party: list[str] | None = None,
    update: list[str] | None = None,
) -> dict:
    start = _iso_to_epoch(capture["start"])
    action_ts = [_iso_to_epoch(a["t"]) for a in actions]
    endpoints = load_endpoints()
    rows = []
    for f in flows:
        phase, t = flow_phase(f, start, action_ts)
        category, owner = categorize(f.domain, endpoints, first_party, update, app_name)
        rows.append(
            {
                "t": iso(t),
                "t_rel_s": round(t - start, 1),
                "domain": f.domain,
                "ip": f.ip,
                "port": f.port,
                "bytes_out": f.bytes_out,
                "bytes_in": f.bytes_in,
                "tls": f.tls,
                "phase": phase,
                "category": category,
                "owner": owner,
                "lookup": None,
                "_sort": t,
            }
        )
    rows.sort(key=lambda r: r.pop("_sort"))
    for i, r in enumerate(rows, 1):
        r["id"] = f"e{i}"
    doc = {
        "run_id": run_id,
        "capture": capture,
        "user_actions": actions,
        "events": rows,
    }
    return Events.model_validate(doc).model_dump(mode="json")


def _chown_to_sudo_user(path: Path) -> None:
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if os.geteuid() != 0 or not uid or not gid:
        return
    for p in [path, *path.rglob("*")]:
        os.chown(p, int(uid), int(gid))


def _sandbox(*args: str) -> None:
    res = subprocess.run(
        [str(SANDBOX), *args], check=False, capture_output=True, text=True
    )
    if res.returncode != 0:
        raise BehaviorError(f"sandbox.sh {args[0]} failed: {res.stderr.strip()}")


def live_capture(
    cmd: str,
    run_dir: Path,
    seconds: float,
    interface: str = "veth-host",
    auto_marks: list[float] | None = None,
) -> tuple[dict, list[dict], list[str]]:
    """Run `cmd` in the sandbox for `seconds` while capturing. Always tears the sandbox down."""
    if os.geteuid() != 0:
        raise BehaviorError(
            "live capture needs root: sudo -E .venv/bin/python -m behavior.run_behavior ..."
        )
    pcap = run_dir / "run.pcap"
    marker = ActionMarker()
    warnings: list[str] = []
    tcpdump = app = None
    # SIGTERM/SIGHUP -> SystemExit, so the finally block still tears everything down.
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda *_: sys.exit(130))
    try:
        _sandbox("down")  # clear leftovers from a crashed run
        _sandbox("up")
        tcpdump = start_capture(pcap, interface)
        start = time.time()
        app = subprocess.Popen([str(SANDBOX), "run", cmd], start_new_session=True)
        print(
            f"capturing for {seconds:.0f}s. Press Enter to mark a user action, Ctrl+C to stop early."
        )
        marker.listen()
        pending = sorted(auto_marks or [])
        try:
            while time.time() - start < seconds:
                while pending and time.time() - start >= pending[0]:
                    marker.add(f"auto mark at +{pending.pop(0):.0f}s")
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("stopping early (Ctrl+C)")
        end = time.time()
    finally:
        marker.stop()
        if app is not None and app.poll() is None:
            try:
                os.killpg(app.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
        if tcpdump is not None:
            warnings += stop_capture(tcpdump)
        try:
            _sandbox("down")  # also kills anything left inside the netns
        except BehaviorError as e:
            warnings.append(str(e))
    capture = {
        "start": iso(start),
        "end": iso(end),
        "interface": interface,
        "pcap_sha256": sha256_file(pcap),
    }
    return capture, marker.as_contract(), warnings


def run_behavior(
    run_dir: Path,
    cmd: str | None = None,
    seconds: float = 90,
    app_name: str | None = None,
    first_party: list[str] | None = None,
    update: list[str] | None = None,
    from_pcap: bool = False,
    interface: str = "veth-host",
    auto_marks: list[float] | None = None,
) -> Path:
    """Produce run_dir/events.json. Returns its path. Raises BehaviorError with a clear message."""
    run_dir.mkdir(parents=True, exist_ok=True)
    pcap = run_dir / "run.pcap"
    if from_pcap:
        try:
            capture = json.loads((run_dir / "capture.json").read_text())
            actions = json.loads((run_dir / "actions.json").read_text())
        except FileNotFoundError as e:
            raise BehaviorError(
                f"--from-pcap needs capture.json and actions.json: {e}"
            ) from e
        capture["pcap_sha256"] = sha256_file(pcap)
        warnings: list[str] = []
    else:
        if not cmd:
            raise BehaviorError("--cmd is required for a live capture")
        capture, actions, warnings = live_capture(
            cmd, run_dir, seconds, interface, auto_marks
        )
        (run_dir / "capture.json").write_text(json.dumps(capture, indent=2))
        (run_dir / "actions.json").write_text(json.dumps(actions, indent=2))

    flows = parse_pcap(pcap)
    doc = build_events(
        run_dir.name, flows, capture, actions, app_name, first_party, update
    )
    out = run_dir / "events.json"
    out.write_text(json.dumps(doc, indent=2))
    _chown_to_sudo_user(run_dir)
    for w in warnings:
        print(f"warning: {w}", file=sys.stderr)
    _print_summary(doc)
    return out


def _print_summary(doc: dict) -> None:
    ev = doc["events"]
    print(f"\n{len(ev)} connections, {len(doc['user_actions'])} marked actions")
    for e in ev:
        print(
            f"  +{e['t_rel_s']:>6.1f}s {e['phase']:<11} {e['category']:<15} "
            f"{e['domain'][:40]:<40} out {e['bytes_out']:>7} in {e['bytes_in']:>8}"
        )


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--cmd", help="command that launches the target app")
    ap.add_argument("--run-dir", required=True, type=Path)
    ap.add_argument("--seconds", type=float, default=90)
    ap.add_argument("--app-name", help="used as owner for first-party/update domains")
    ap.add_argument(
        "--first-party",
        action="append",
        default=[],
        help="app's own domain (repeatable)",
    )
    ap.add_argument(
        "--update-domain",
        action="append",
        default=[],
        help="app's update domain (repeatable)",
    )
    ap.add_argument(
        "--auto-mark",
        action="append",
        type=float,
        default=[],
        help="mark an action at +N s",
    )
    ap.add_argument(
        "--from-pcap", action="store_true", help="re-parse run-dir/run.pcap, no capture"
    )
    ap.add_argument("--interface", default="veth-host")
    a = ap.parse_args(argv)
    try:
        run_behavior(
            a.run_dir,
            a.cmd,
            a.seconds,
            a.app_name,
            a.first_party,
            a.update_domain,
            a.from_pcap,
            a.interface,
            a.auto_mark,
        )
    except (BehaviorError, CaptureError, ParseError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
