"""Fallback when a GUI app will not open inside the netns (plan §9 H2).

Run the app normally, capture on every interface, and poll `ss` to learn which
sockets belong to the app's processes. Only packets on those sockets become
events. Limitation: a connection that opens and closes between two polls is
missed, so we poll every 0.2 s.
"""

from __future__ import annotations

import os
import re
import subprocess
import threading
from pathlib import Path

POLL_S = 0.2
_USERS_RE = re.compile(r"pid=(\d+)")


def local_ips() -> set[str]:
    out = subprocess.run(["ip", "-o", "addr"], check=False, capture_output=True, text=True).stdout
    ips = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] in ("inet", "inet6"):
            ips.add(parts[3].split("/")[0])
    return ips


def process_tree(root_pids: set[int], name_match: str | None = None) -> set[int]:
    """root_pids plus all their descendants, plus any process whose command line contains
    `name_match` (catches apps whose launcher forks and exits, e.g. Electron)."""
    children: dict[int, list[int]] = {}
    cmdlines: dict[int, str] = {}
    for d in Path("/proc").iterdir():
        if not d.name.isdigit():
            continue
        try:
            stat = (d / "stat").read_text()
            ppid = int(stat.rsplit(")", 1)[1].split()[1])
            children.setdefault(ppid, []).append(int(d.name))
            if name_match:
                cmdlines[int(d.name)] = (
                    (d / "cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
                )
        except (OSError, ValueError, IndexError):
            continue
    found, stack = set(), list(root_pids)
    if name_match:
        stack += [pid for pid, cmd in cmdlines.items() if name_match in cmd and pid != os.getpid()]
    while stack:
        pid = stack.pop()
        if pid in found:
            continue
        found.add(pid)
        stack.extend(children.get(pid, []))
    return found


def _split_hostport(s: str) -> tuple[str, int] | None:
    host, _, port = s.rpartition(":")
    host = host.strip("[]").split("%")[0]
    try:
        return host, int(port)
    except ValueError:
        return None


def parse_ss(output: str, pids: set[int]) -> set[tuple[str, int, str, int]]:
    """Lines of `ss -tunapH` -> {(local_ip, local_port, remote_ip, remote_port)} owned by pids."""
    socks = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        owners = {int(p) for p in _USERS_RE.findall(line)}
        if not owners & pids:
            continue
        local, remote = _split_hostport(parts[4]), _split_hostport(parts[5])
        if local and remote and remote[0] not in ("*", "0.0.0.0", "::"):
            socks.add((local[0], local[1], remote[0], remote[1]))
    return socks


class SocketWatcher:
    """Polls `ss` in the background and remembers every socket the app ever had."""

    def __init__(self, root_pid: int, name_match: str | None = None) -> None:
        self.root_pid = root_pid
        self.name_match = name_match
        self.sockets: set[tuple[str, int, str, int]] = set()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self) -> None:
        while not self._stop.is_set():
            pids = process_tree({self.root_pid}, self.name_match)
            out = subprocess.run(
                ["ss", "-tunapH"], check=False, capture_output=True, text=True
            ).stdout
            self.sockets |= parse_ss(out, pids)
            self._stop.wait(POLL_S)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)


def launch_as_user(cmd: str) -> subprocess.Popen:
    """Start the app as the invoking user (not root), keeping the GUI session variables."""
    user = os.environ.get("SUDO_USER") or os.environ.get("NOALIBI_RUN_AS") or "root"
    return subprocess.Popen(["sudo", "-E", "-u", user, "bash", "-c", cmd], start_new_session=True)
