"""Find the audited app's own connections by polling the OS connection table (replaces a sandbox).

Every poll we list the app's processes (the launched process, its children, and any process
whose name matches) and record their local ports. Later only packets on those ports are kept,
so other apps' traffic is dropped. A connection that opens and closes between two polls is
missed; apps keep their API connections open, so in practice that is rare.
"""

from __future__ import annotations

import socket
import threading
import time

import psutil

LocalSocket = tuple[str, int]  # ("tcp" | "udp", local_port)


def local_ips() -> set[str]:
    """Every IP address of this machine (all interfaces, IPv4 and IPv6)."""
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family in (socket.AF_INET, socket.AF_INET6):
                ips.add(addr.address.split("%")[0])
    return ips


class SocketWatcher(threading.Thread):
    """Background thread that collects the local ports used by the app's processes."""

    def __init__(
        self,
        root_pid: int | None = None,
        proc_names: list[str] | None = None,
        interval: float = 0.2,
    ) -> None:
        super().__init__(daemon=True)
        self.root_pid = root_pid
        self.proc_names = {n.lower() for n in (proc_names or [])}
        self.interval = interval
        self.sockets: set[LocalSocket] = set()
        self.process_names: set[str] = set()
        self.errors: list[str] = []
        self._stop_event = threading.Event()

    def app_pids(self) -> set[int]:
        roots: list[psutil.Process] = []
        if self.root_pid:
            try:
                roots.append(psutil.Process(self.root_pid))
            except psutil.Error:
                pass
        if self.proc_names:
            for proc in psutil.process_iter(["name"]):
                if (proc.info.get("name") or "").lower() in self.proc_names:
                    roots.append(proc)
        pids: set[int] = set()
        for root in roots:
            try:
                family = [root, *root.children(recursive=True)]
            except psutil.Error:
                family = [root]
            for proc in family:
                pids.add(proc.pid)
                try:
                    self.process_names.add(proc.name())
                except psutil.Error:
                    pass
        return pids

    def poll(self) -> None:
        pids = self.app_pids()
        if not pids:
            return
        for conn in psutil.net_connections("inet"):
            if conn.pid in pids and conn.laddr:
                proto = "tcp" if conn.type == socket.SOCK_STREAM else "udp"
                self.sockets.add((proto, conn.laddr.port))

    def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                self.poll()
            except Exception as exc:  # noqa: BLE001 - keep watching; report at the end
                if len(self.errors) < 5:
                    self.errors.append(f"{type(exc).__name__}: {exc}")
            self._stop_event.wait(self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        if self.is_alive():
            self.join(timeout=5)
        try:
            self.poll()  # one last look
        except Exception:  # noqa: BLE001, S110 - best effort; the thread already collected ports
            pass


def wait_for_processes(watcher: SocketWatcher, timeout: float) -> bool:
    """True once at least one app process exists (used when attaching by name)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if watcher.app_pids():
            return True
        time.sleep(0.2)
    return False
