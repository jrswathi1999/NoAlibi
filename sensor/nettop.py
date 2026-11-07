"""Stream per-process, per-connection byte counters from macOS `nettop` (no root needed).

`nettop -L 0 -s 1 -n -x -J bytes_in,bytes_out` prints one CSV table per second:

    ,bytes_in,bytes_out,                                    <- header starts a sample
    Claude Helper.37106,8257156,609474,                     <- process line: name.pid, totals
    tcp4 10.0.0.5:62332<->162.159.140.245:443,7276,31697,   <- connection line, cumulative
    udp6 fe80::1%en0.5353<->*.*,,,                          <- listener, ignored

Counters are cumulative for the life of the socket, so the session computes deltas. We never see
packet contents: only who talked to whom and how many bytes.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass

log = logging.getLogger("sensor.nettop")

NETTOP_CMD = ["nettop", "-L", "0", "-s", "1", "-n", "-x", "-J", "bytes_in,bytes_out"]


@dataclass(frozen=True)
class Conn:
    """One socket of one process at one sample."""

    pid: int
    proc: str
    proto: str  # tcp4 | tcp6 | udp4 | udp6
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    bytes_in: int
    bytes_out: int

    @property
    def key(self) -> tuple:
        return (
            self.pid,
            self.proto,
            self.local_ip,
            self.local_port,
            self.remote_ip,
            self.remote_port,
        )


@dataclass
class Sample:
    t: float  # unix epoch seconds when the sample was read
    conns: list[Conn]


_PROC_RE = re.compile(r"^(?P<name>.+)\.(?P<pid>\d+),(?P<bin>\d*),(?P<bout>\d*),?$")
_CONN_RE = re.compile(
    r"^(?P<proto>(tcp|udp)[46]) (?P<local>\S+)<->(?P<remote>\S+?),(?P<bin>\d*),(?P<bout>\d*),?$"
)


def split_endpoint(text: str, proto: str) -> tuple[str, int] | None:
    """'1.2.3.4:443' (v4) or 'fe80::1%en0.443' (v6) -> (ip, port). Wildcards -> None."""
    sep = ":" if proto.endswith("4") else "."
    if sep not in text:
        return None
    ip, _, port = text.rpartition(sep)
    if not port.isdigit() or ip in ("*", ""):
        return None
    return ip.split("%", 1)[0], int(port)


def parse_lines(lines: list[str], t: float) -> Sample:
    """Parse one table (without its header) into a Sample. Unparseable lines are skipped."""
    conns: list[Conn] = []
    proc, pid = "", -1
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        m = _CONN_RE.match(line)
        if m:
            if pid < 0:
                continue
            proto = m.group("proto")
            local = split_endpoint(m.group("local"), proto)
            remote = split_endpoint(m.group("remote"), proto)
            if not local or not remote:
                continue  # listening socket
            conns.append(
                Conn(
                    pid=pid,
                    proc=proc,
                    proto=proto,
                    local_ip=local[0],
                    local_port=local[1],
                    remote_ip=remote[0],
                    remote_port=remote[1],
                    bytes_in=int(m.group("bin") or 0),
                    bytes_out=int(m.group("bout") or 0),
                )
            )
            continue
        m = _PROC_RE.match(line)
        if m:
            proc, pid = m.group("name"), int(m.group("pid"))
    return Sample(t=t, conns=conns)


def iter_samples(stream: Iterator[str], clock: Callable[[], float] = time.time) -> Iterator[Sample]:
    """Group a nettop text stream into Samples. A header line closes the previous sample."""
    buf: list[str] = []
    started = False
    for line in stream:
        if line.startswith(",bytes_in"):
            if started:
                yield parse_lines(buf, clock())
            buf, started = [], True
        elif started:
            buf.append(line)
    if started and buf:
        yield parse_lines(buf, clock())


class NettopStream:
    """Runs nettop in the background and calls on_sample(Sample) about once a second.

    The raw text is also appended to raw_log (the evidence file hashed in the report).
    """

    def __init__(self, on_sample: Callable[[Sample], None], raw_log: str | None = None):
        self.on_sample = on_sample
        self.raw_log = raw_log
        self._proc: subprocess.Popen | None = None
        self._thread: threading.Thread | None = None
        self.error: str | None = None

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                NETTOP_CMD,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
        except OSError as exc:
            self.error = f"could not start nettop: {exc}"
            raise RuntimeError(self.error) from exc
        self._thread = threading.Thread(target=self._pump, name="nettop", daemon=True)
        self._thread.start()

    def _lines(self) -> Iterator[str]:
        assert self._proc and self._proc.stdout
        log_path = self.raw_log or os.devnull
        with open(log_path, "a", encoding="utf-8") as log_fh:
            for line in self._proc.stdout:
                log_fh.write(line)
                log_fh.flush()
                yield line.rstrip("\n")

    def _pump(self) -> None:
        try:
            for sample in iter_samples(self._lines()):
                try:
                    self.on_sample(sample)
                except Exception:  # one bad sample must not stop the capture
                    log.exception("sample handler failed")
        except Exception as exc:  # noqa: BLE001
            self.error = f"nettop stream failed: {exc}"
            log.error(self.error)

    def stop(self) -> None:
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._thread:
            self._thread.join(timeout=5)
