"""Label each domain: AI provider, tracker, analytics, error reporting, first party, update, unknown."""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path

ENDPOINTS_FILE = Path(__file__).with_name("endpoints.json")


def load_endpoints(path: Path = ENDPOINTS_FILE) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _matches(domain: str, base: str) -> bool:
    """'api.notesapp.com' belongs to 'notesapp.com'."""
    base = base.lower().strip(".")
    return domain == base or domain.endswith("." + base)


def categorize(
    domain: str | None,
    endpoints: list[dict],
    first_party: list[str] | None = None,
    update: list[str] | None = None,
) -> tuple[str, str | None]:
    """Return (category, owner). Update and first-party domains are checked first."""
    if not domain:
        return "unknown", None
    domain = domain.lower().rstrip(".")
    if any(_matches(domain, d) for d in update or []):
        return "update", None
    if any(_matches(domain, d) for d in first_party or []):
        return "first_party", None
    for entry in endpoints:
        if fnmatch(domain, entry["pattern"].lower()):
            return entry["category"], entry.get("owner")
    return "unknown", None
