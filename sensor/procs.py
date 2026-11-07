"""Find installed apps and the processes that belong to one of them.

Attribution is by executable path: a process belongs to the target if its executable lives inside
the app bundle (e.g. /Applications/Claude.app/Contents/Frameworks/Claude Helper.app/...), or if it
is a child of such a process. That catches Electron helpers and XPC services without a sandbox.
"""

from __future__ import annotations

import logging
import os
import plistlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger("sensor.procs")

APP_DIRS = [Path("/Applications"), Path.home() / "Applications"]


@dataclass(frozen=True)
class AppInfo:
    """An installed app bundle."""

    name: str
    bundle_path: str
    bundle_id: str
    version: str
    icon_path: str | None
    executable: str


@dataclass
class Proc:
    pid: int
    ppid: int
    command: str  # full executable path + args, as ps prints it
    children: list[int] = field(default_factory=list)


def _read_plist(bundle: Path) -> dict:
    try:
        with (bundle / "Contents" / "Info.plist").open("rb") as fh:
            return plistlib.load(fh)
    except (OSError, plistlib.InvalidFileException, ValueError):
        return {}


def app_info(bundle: Path) -> AppInfo | None:
    """Read an .app bundle's Info.plist. Returns None if it isn't a usable app."""
    info = _read_plist(bundle)
    if not info:
        return None
    name = info.get("CFBundleDisplayName") or info.get("CFBundleName") or bundle.stem
    icon = info.get("CFBundleIconFile") or info.get("CFBundleIconName")
    icon_path = None
    if icon:
        candidate = bundle / "Contents" / "Resources" / icon
        if not candidate.suffix:
            candidate = candidate.with_suffix(".icns")
        if candidate.exists():
            icon_path = str(candidate)
    return AppInfo(
        name=str(name),
        bundle_path=str(bundle),
        bundle_id=str(info.get("CFBundleIdentifier", "")),
        version=str(info.get("CFBundleShortVersionString", "")),
        icon_path=icon_path,
        executable=str(info.get("CFBundleExecutable", bundle.stem)),
    )


def list_apps() -> list[AppInfo]:
    """Installed apps in /Applications and ~/Applications (one level deep), sorted by name."""
    apps: dict[str, AppInfo] = {}
    for root in APP_DIRS:
        if not root.is_dir():
            continue
        for bundle in sorted(root.glob("*.app")) + sorted(root.glob("*/*.app")):
            info = app_info(bundle)
            if info and info.bundle_id and info.bundle_id not in apps:
                apps[info.bundle_id] = info
    return sorted(apps.values(), key=lambda a: a.name.lower())


def list_processes() -> dict[int, Proc]:
    """All processes visible to this user, with parent links."""
    try:
        out = subprocess.run(
            ["ps", "-axww", "-o", "pid=,ppid=,command="],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        log.error("ps failed: %s", exc)
        return {}
    procs: dict[int, Proc] = {}
    for line in out.splitlines():
        m = re.match(r"\s*(\d+)\s+(\d+)\s+(.*)", line)
        if m:
            pid, ppid = int(m.group(1)), int(m.group(2))
            procs[pid] = Proc(pid=pid, ppid=ppid, command=m.group(3))
    for p in procs.values():
        if p.ppid in procs:
            procs[p.ppid].children.append(p.pid)
    return procs


def target_pids(bundle_path: str, procs: dict[int, Proc] | None = None) -> set[int]:
    """PIDs whose executable lives inside bundle_path: the app and its own helpers.

    Children that run a program from *outside* the bundle (a terminal shell, `claude`, `git`, an
    extension's tool) are separate programs and are deliberately not counted; see launched_pids().
    """
    procs = procs if procs is not None else list_processes()
    prefix = bundle_path.rstrip("/") + "/"
    return {pid for pid, p in procs.items() if p.command.startswith(prefix)}


def program_name(command: str) -> str:
    """'/opt/homebrew/bin/claude --print hi' -> 'claude'. Handles executable paths with spaces."""
    parts = command.split(" ")
    exe = parts[0]
    for i in range(len(parts), 0, -1):  # longest prefix that is a real file
        candidate = " ".join(parts[:i])
        if candidate.startswith("/") and os.path.isfile(candidate):
            exe = candidate
            break
    return exe.rsplit("/", 1)[-1] or exe


def launched_pids(bundle_path: str, procs: dict[int, Proc] | None = None) -> dict[int, str]:
    """Programs started from inside the app that live outside its bundle: pid -> program name.

    Reported separately ("started from inside the app") so nothing is hidden, but never blamed on it.
    """
    procs = procs if procs is not None else list_processes()
    own = target_pids(bundle_path, procs)
    found: dict[int, str] = {}
    stack = list(own)
    while stack:
        for child in procs[stack.pop()].children:
            if child in own or child in found:
                continue
            found[child] = program_name(procs[child].command)
            stack.append(child)
    return found


def self_pids(procs: dict[int, Proc] | None = None) -> set[int]:
    """This process and its children: used to audit No Alibi's own traffic."""
    import os

    procs = procs if procs is not None else list_processes()
    me = os.getpid()
    found = {me}
    stack = [me]
    while stack:
        p = procs.get(stack.pop())
        for child in p.children if p else []:
            if child not in found:
                found.add(child)
                stack.append(child)
    return found


def hosts_self(bundle_path: str, procs: dict[int, Proc] | None = None) -> bool:
    """True if No Alibi runs inside this app (e.g. launched from a terminal inside it).

    Quitting such an app would kill the audit itself, so cold starts are refused for it.
    """
    import os

    procs = procs if procs is not None else list_processes()
    prefix = bundle_path.rstrip("/") + "/"
    pid = os.getpid()
    seen: set[int] = set()
    while pid in procs and pid not in seen:
        seen.add(pid)
        if procs[pid].command.startswith(prefix):
            return True
        pid = procs[pid].ppid
    return False


def icon_png(app: AppInfo, cache_dir: Path, size: int = 128) -> Path | None:
    """Convert the app's .icns to a PNG once (macOS `sips`). Returns None if unavailable."""
    if not app.icon_path or sys.platform != "darwin":
        return None
    cache_dir.mkdir(parents=True, exist_ok=True)
    out = cache_dir / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', app.bundle_id)}.png"
    if out.exists():
        return out
    try:
        subprocess.run(
            ["sips", "-s", "format", "png", "-Z", str(size), app.icon_path, "--out", str(out)],
            capture_output=True,
            check=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("icon for %s failed: %s", app.name, exc)
        return None
    return out if out.exists() else None


def quit_app(app: AppInfo) -> None:
    """Ask the app to quit politely (AppleScript), like the user choosing Quit."""
    subprocess.run(
        ["osascript", "-e", f'tell application id "{app.bundle_id}" to quit'],
        capture_output=True,
        timeout=15,
        check=False,
    )


def launch_app(app: AppInfo) -> None:
    """Launch the app as the logged-in user, exactly as a double-click would."""
    subprocess.run(["open", "-a", app.bundle_path], capture_output=True, timeout=15, check=True)
