"""Start and stop tcpdump on veth-host; hash the pcap.

Record only: tcpdump never blocks or alters traffic, and we never decrypt it.
"""

from __future__ import annotations

import hashlib
import shutil
import signal
import subprocess
import time
from pathlib import Path


class CaptureError(RuntimeError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def start_capture(
    pcap: Path, interface: str = "veth-host", ready_timeout: float = 5.0
) -> subprocess.Popen:
    """Start tcpdump writing to `pcap`. Returns once tcpdump is actually listening.

    Notes:
    - `-Z root`: Ubuntu's tcpdump otherwise drops to the `tcpdump` user and
      cannot write into the user's run folder.
    - The file must end in `.pcap`: Ubuntu's AppArmor profile for tcpdump only
      allows writing files with that extension.
    - `-U` flushes each packet so a crash still leaves a readable file.
    """
    if shutil.which("tcpdump") is None:
        raise CaptureError("tcpdump not installed: sudo apt install -y tcpdump")
    if pcap.suffix != ".pcap":
        raise CaptureError(f"pcap path must end in .pcap (AppArmor): {pcap}")
    pcap.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["tcpdump", "-i", interface, "-n", "-U", "-Z", "root", "-w", str(pcap)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + ready_timeout
    assert proc.stderr is not None
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            err = proc.stderr.read().strip()
            raise CaptureError(f"tcpdump exited early: {err or 'no message'}")
        line = proc.stderr.readline()
        if "listening on" in line:
            return proc
    stop_capture(proc)
    raise CaptureError(f"tcpdump did not start listening on {interface} within {ready_timeout}s")


def stop_capture(proc: subprocess.Popen, timeout: float = 5.0) -> list[str]:
    """Stop tcpdump cleanly (SIGINT flushes the file). Returns warnings."""
    warnings: list[str] = []
    if proc.poll() is not None:
        return warnings
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        warnings.append("tcpdump did not stop on SIGINT; killed (last packets may be lost)")
    return warnings
