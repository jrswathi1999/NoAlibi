"""No Alibi's own outbound ledger: every network action the tool itself takes, one line each.

Written to runs/<id>/outbound_queries.log and shown in the report, so a judge can see exactly
what left the machine (domain names, our own TLS handshakes, the public policy URL), and nothing else.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path


class EgressLedger:
    def __init__(self, path: Path | None = None):
        self.path = path
        self.entries: list[dict] = []
        self._lock = threading.Lock()

    def __call__(self, kind: str, what: str) -> None:
        self.record(kind, what)

    def record(self, kind: str, what: str) -> None:
        entry = {"t": time.time(), "kind": kind, "sent": what}
        with self._lock:
            self.entries.append(entry)
            if self.path:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(f"{entry['t']:.3f}\t{kind}\t{what}\n")

    def counts(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for e in self.entries:
            out[e["kind"]] = out.get(e["kind"], 0) + 1
        return out
