"""Mark user actions during a capture (press Enter) and label each event's phase."""

from __future__ import annotations

import json
import sys
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path

STARTUP_SECONDS = 10
ACTION_WINDOW_SECONDS = 5


def phase_for(t: datetime, start: datetime, actions: list[datetime]) -> str:
    """user_action within 5 s after a mark, startup in the first 10 s, otherwise idle."""
    for action in actions:
        if action <= t <= action + timedelta(seconds=ACTION_WINDOW_SECONDS):
            return "user_action"
    if t < start + timedelta(seconds=STARTUP_SECONDS):
        return "startup"
    return "idle"


class ActionMarker:
    """Each Enter on stdin logs {t, label}. Type a label before Enter to name the action."""

    def __init__(self, default_label: str = "used the AI feature") -> None:
        self.default_label = default_label
        self.actions: list[dict] = []
        self._lock = threading.Lock()

    def add(self, label: str = "", t: datetime | None = None) -> dict:
        label = label.replace("﻿", "").strip()  # PowerShell pipes can add a BOM
        action = {"t": t or datetime.now(UTC), "label": label or self.default_label}
        with self._lock:
            self.actions.append(action)
        return action

    def listen(self) -> bool:
        """Read Enter presses in a background thread. Only in a real terminal (not a pipe)."""
        if not sys.stdin or not sys.stdin.isatty():
            return False

        def loop() -> None:
            for line in sys.stdin:
                action = self.add(line)
                print(f"  marked: {action['label']} at {action['t']:%H:%M:%S}", flush=True)

        threading.Thread(target=loop, daemon=True).start()
        return True

    def save(self, path: Path) -> Path:
        with self._lock:
            data = [
                {"t": a["t"].isoformat().replace("+00:00", "Z"), "label": a["label"]}
                for a in self.actions
            ]
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
        return path


def load_actions(path: Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [{"t": datetime.fromisoformat(a["t"]), "label": a["label"]} for a in data]
