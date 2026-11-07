"""A recording session you can start, mark and stop (used by the CLI and the web UI)."""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from behavior.capture import Capture, CaptureError
from behavior.mark import ActionMarker
from behavior.procwatch import SocketWatcher, local_ips, wait_for_processes


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")


class Recorder:
    """Record one app: start() launches/attaches, mark() logs an action, stop() saves files.

    Files written into run_dir: run.pcap, capture.json, actions.json, sockets.json.
    """

    def __init__(
        self,
        run_dir: Path,
        cmd: str | None = None,
        proc_names: list[str] | None = None,
        interface: str = "Wi-Fi",
        max_seconds: int = 300,
    ) -> None:
        if not cmd and not proc_names:
            raise ValueError("give a launch command and/or a process name (e.g. Opera.exe)")
        self.run_dir = Path(run_dir)
        self.cmd = cmd
        self.proc_names = proc_names or []
        self.interface = interface
        self.max_seconds = max_seconds
        self.capture = Capture(interface, self.run_dir / "run.pcap", max_seconds=max_seconds + 120)
        self.marker = ActionMarker()
        self.watcher: SocketWatcher | None = None
        self.started_at: datetime | None = None
        self.ended_at: datetime | None = None
        self._began = 0.0
        self._stop_lock = threading.Lock()
        self._timer: threading.Timer | None = None

    @property
    def recording(self) -> bool:
        return self.started_at is not None and self.ended_at is None

    def elapsed(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.ended_at.timestamp() if self.ended_at else time.time()
        return max(0.0, end - self.started_at.timestamp())

    def start(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.capture.start()
        try:
            self.started_at = datetime.now(UTC)
            root_pid = None
            if self.cmd:
                flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
                root_pid = subprocess.Popen(self.cmd, shell=True, creationflags=flags).pid
            self.watcher = SocketWatcher(root_pid=root_pid, proc_names=self.proc_names)
            self.watcher.start()
            if not self.cmd and not wait_for_processes(self.watcher, timeout=30):
                raise CaptureError(
                    f"no running process named {', '.join(self.proc_names)} within 30 s"
                )
        except Exception:
            self.stop()
            raise
        self._timer = threading.Timer(self.max_seconds, self.stop)  # hard stop
        self._timer.daemon = True
        self._timer.start()

    def mark(self, label: str = "") -> dict:
        return self.marker.add(label)

    def stop(self) -> None:
        """Stop recording and write the side files. Safe to call twice, from any thread."""
        with self._stop_lock:
            if self.ended_at is not None or self.started_at is None:
                self.capture.stop()
                return
            self.ended_at = datetime.now(UTC)
            if self._timer:
                self._timer.cancel()
            if self.watcher:
                self.watcher.stop()
            self.capture.stop()  # always, even after a crash
            self.save_side_files()

    def save_side_files(self) -> None:
        self.marker.save(self.run_dir / "actions.json")
        w = self.watcher
        side = {
            "sockets": sorted(w.sockets) if w else [],
            "processes": sorted(w.process_names) if w else [],
            "my_ips": sorted(local_ips()),
            "errors": w.errors if w else [],
        }
        (self.run_dir / "sockets.json").write_text(
            json.dumps(side, indent=2) + "\n", encoding="utf-8"
        )
        info = {
            "start": iso(self.started_at or datetime.now(UTC)),
            "end": iso(self.ended_at or datetime.now(UTC)),
            "interface": self.interface,
        }
        (self.run_dir / "capture.json").write_text(
            json.dumps(info, indent=2) + "\n", encoding="utf-8"
        )

    def app_sockets(self) -> set[tuple[str, int]]:
        return set(self.watcher.sockets) if self.watcher else set()

    def process_names(self) -> list[str]:
        return sorted(self.watcher.process_names) if self.watcher else []
