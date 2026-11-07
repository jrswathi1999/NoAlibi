"""Shared settings: read .env and make HTTPS use the Windows certificate store."""

from __future__ import annotations

import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
_ssl_ready = False


def load_env(path: Path | None = None) -> None:
    """Copy KEY=value lines from .env into os.environ (existing variables win)."""
    path = path or REPO_ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip().strip('"').strip("'")
        if value:
            os.environ.setdefault(key.strip(), value)


def use_system_certificates() -> None:
    """Trust the OS certificate store, so HTTPS works when antivirus intercepts TLS."""
    global _ssl_ready
    if _ssl_ready:
        return
    try:
        import truststore

        truststore.inject_into_ssl()
    except Exception:  # noqa: BLE001, S110 - fall back to certifi; the request may still work
        pass
    _ssl_ready = True
