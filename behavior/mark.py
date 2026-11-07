"""Press Enter during a capture to log a user action. Also decides each event's phase."""

from __future__ import annotations

import json
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

STARTUP_S = 10.0  # "startup" = first 10 s of the capture
ACTION_WINDOW_S = 5.0  # "user_action" = within 5 s after a marked action


def iso(t: float) -> str:
    """Epoch seconds -> ISO 8601 UTC with milliseconds, e.g. 2026-11-07T20:16:42.120Z."""
    dt = datetime.fromtimestamp(t, tz=UTC)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class ActionMarker:
    """Collects {t, label} marks. Enter on stdin marks; typing a label first is optional."""

    def __init__(self) -> None:
        self.actions: list[dict] = []  # {"t": epoch float, "label": str}
        self._lock = threading.Lock()
        self._stopped = threading.Event()

    def add(self, label: str = "", t: float | None = None) -> dict:
        mark = {"t": time.time() if t is None else t, "label": label.strip()}
        with self._lock:
            self.actions.append(mark)
        return mark

    def listen(self, stream: TextIO = sys.stdin) -> threading.Thread | None:
        """Read lines from `stream` in a background thread. No-op if stdin is not a terminal."""
        if stream is sys.stdin and not sys.stdin.isatty():
            return None

        def loop() -> None:
            for line in stream:
                if self._stopped.is_set():
                    break
                mark = self.add(line)
                label = mark["label"] or "(no label)"
                print(f"  marked user action at {iso(mark['t'])}: {label}", flush=True)

        th = threading.Thread(target=loop, daemon=True)
        th.start()
        return th

    def stop(self) -> None:
        self._stopped.set()

    def as_contract(self) -> list[dict]:
        with self._lock:
            return [
                {"t": iso(a["t"]), "label": a["label"]}
                for a in sorted(self.actions, key=lambda a: a["t"])
            ]

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(self.as_contract(), indent=2))


def phase_for(t: float, capture_start: float, action_times: list[float]) -> str:
    """Phase of a moment: user_action beats startup (it is the more specific signal)."""
    if any(0.0 <= t - a <= ACTION_WINDOW_S for a in action_times):
        return "user_action"
    if t - capture_start < STARTUP_S:
        return "startup"
    return "idle"
