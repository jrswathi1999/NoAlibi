"""Categorize domains with endpoints.json; look up unknown ones via Tavily/Exa."""

from __future__ import annotations

import fnmatch
import ipaddress
import json
from pathlib import Path

ENDPOINTS_PATH = Path(__file__).with_name("endpoints.json")


def load_endpoints(path: Path = ENDPOINTS_PATH) -> list[dict]:
    with open(path) as f:
        return json.load(f)


def _matches(domain: str, pattern: str) -> bool:
    pattern = pattern.lower()
    if pattern.startswith("*."):
        base = pattern[2:]
        # "*.sentry.io" matches sentry.io and every subdomain, but not "evilsentry.io".
        if domain == base or domain.endswith("." + base):
            return True
        if "*" not in base:
            return False
    return fnmatch.fnmatchcase(domain, pattern)


def _is_under(domain: str, base: str) -> bool:
    base = base.lower().strip(".")
    return domain == base or domain.endswith("." + base)


def categorize(
    domain: str,
    endpoints: list[dict] | None = None,
    first_party: list[str] | None = None,
    update: list[str] | None = None,
    app_name: str | None = None,
) -> tuple[str, str | None]:
    """Return (category, owner) for a domain. Anything not matched is "unknown"."""
    d = domain.lower().rstrip(".")
    for base in update or []:
        if _is_under(d, base):
            return "update", app_name
    for base in first_party or []:
        if _is_under(d, base):
            return "first_party", app_name
    for ep in endpoints if endpoints is not None else load_endpoints():
        if _matches(d, ep["pattern"]):
            return ep["category"], ep.get("owner")
    return "unknown", None


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
