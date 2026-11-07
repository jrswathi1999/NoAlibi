"""Record packets on one network interface with Wireshark's dumpcap. Record only, never decrypt."""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

WIRESHARK_DIRS = [Path(r"C:\Program Files\Wireshark"), Path(r"C:\Program Files (x86)\Wireshark")]
PCAP_HEADER_BYTES = 24


class CaptureError(RuntimeError):
    """Capture could not start or stop. The message says what to fix."""


def find_tool(name: str) -> str:
    """Find dumpcap or tshark: next to $TSHARK, then on PATH, then in the Wireshark folder."""
    env = os.environ.get("TSHARK", "").strip().strip('"')
    if env:
        candidate = Path(env).with_name(f"{name}.exe")
        if candidate.exists():
            return str(candidate)
    found = shutil.which(name)
    if found:
        return found
    for folder in WIRESHARK_DIRS:
        candidate = folder / f"{name}.exe"
        if candidate.exists():
            return str(candidate)
    raise CaptureError(
        f"{name} not found. Install Wireshark (with Npcap), or set TSHARK in .env "
        "to the full path of tshark.exe."
    )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


class Capture:
    """dumpcap running in the background, writing a classic .pcap file."""

    def __init__(self, interface: str, pcap_path: Path, max_seconds: int = 3600) -> None:
        self.interface = interface
        self.pcap_path = Path(pcap_path)
        self.max_seconds = max_seconds
        self.proc: subprocess.Popen | None = None

    def start(self, timeout: float = 10.0) -> None:
        self.pcap_path.parent.mkdir(parents=True, exist_ok=True)
        self.pcap_path.unlink(missing_ok=True)
        cmd = [
            find_tool("dumpcap"),
            "-i", self.interface,
            "-P",  # classic pcap format
            "-q",
            "-a", f"duration:{self.max_seconds}",  # safety stop if we crash
            "-w", str(self.pcap_path),
        ]  # fmt: skip
        flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=flags,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                err = (self.proc.stderr.read() if self.proc.stderr else "").strip()
                raise CaptureError(
                    f"dumpcap exited on interface {self.interface!r}: {err or 'no output'}. "
                    "List interfaces with: tshark -D"
                )
            if self.pcap_path.exists() and self.pcap_path.stat().st_size >= PCAP_HEADER_BYTES:
                return
            time.sleep(0.1)
        self.stop()
        raise CaptureError(f"dumpcap did not start recording within {timeout:.0f} s")

    def stop(self) -> None:
        """Stop cleanly (Ctrl+Break lets dumpcap flush), then force if needed. Safe to repeat."""
        proc, self.proc = self.proc, None
        if proc is None or proc.poll() is not None:
            return
        try:
            if sys.platform == "win32":
                proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                proc.send_signal(signal.SIGINT)
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            proc.kill()
            proc.wait(timeout=5)
