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


# ---------------------------------------------------------------------------
# Unknown-domain lookup (Tavily first, Exa fallback). Only a domain name ever
# leaves the machine, and every query is logged to outbound_queries.log.
# ---------------------------------------------------------------------------

LOCAL_SUFFIXES = (
    ".local",
    ".lan",
    ".internal",
    ".home.arpa",
    ".localhost",
    ".localdomain",
)
MULTI_PART_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "co.in",
    "co.kr",
    "com.br",
    "com.cn",
    "com.mx",
    "co.nz",
    "com.sg",
    "com.tr",
    "co.za",
}
SUMMARY_MAX = 200
LOOKUP_TIMEOUT_S = 12


def registrable_domain(domain: str) -> str:
    """api.foo.example.co.uk -> example.co.uk. Subdomains can carry user or tenant IDs,
    so we only ever send the registrable part."""
    parts = domain.lower().rstrip(".").split(".")
    n = 3 if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_PART_SUFFIXES else 2
    return ".".join(parts[-n:])


def is_lookup_candidate(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return "." in d and not is_ip(d) and not d.endswith(LOCAL_SUFFIXES)


def _load_env_key(name: str) -> str | None:
    import os

    if os.environ.get(name):
        return os.environ[name]
    for env in (Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"):
        if env.exists():
            for line in env.read_text().splitlines():
                k, _, v = line.partition("=")
                if k.strip() == name and v.strip():
                    return v.strip().strip('"').strip("'")
    return None


def _shorten(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= SUMMARY_MAX else text[: SUMMARY_MAX - 1].rstrip() + "…"


def _tavily(query: str) -> dict | None:
    key = _load_env_key("TAVILY_API_KEY")
    if not key:
        return None
    from tavily import TavilyClient

    res = TavilyClient(api_key=key).search(
        query=query, max_results=3, include_answer=True, search_depth="basic"
    )
    results = res.get("results") or []
    summary = res.get("answer") or (results[0].get("content") if results else "")
    if not summary:
        return None
    url = results[0].get("url", "") if results else ""
    return {"source": "tavily", "summary": _shorten(summary), "url": url}


def _exa(query: str) -> dict | None:
    key = _load_env_key("EXA_API_KEY")
    if not key:
        return None
    try:
        from exa_py import Exa
    except ImportError:
        return None
    res = Exa(api_key=key).search_and_contents(query, num_results=1, text=True)
    if not res.results:
        return None
    top = res.results[0]
    return {
        "source": "exa",
        "summary": _shorten(top.text or top.title or ""),
        "url": top.url,
    }


def default_providers() -> list[tuple[str, object]]:
    """Providers we can actually call (key present), in priority order."""
    providers: list[tuple[str, object]] = []
    if _load_env_key("TAVILY_API_KEY"):
        providers.append(("tavily", _tavily))
    if _load_env_key("EXA_API_KEY"):
        providers.append(("exa", _exa))
    return providers


def lookup_domains(
    domains: list[str],
    run_dir: Path,
    providers: list[tuple[str, object]] | None = None,
) -> dict[str, dict | None]:
    """Look up each domain once (by registrable domain). Returns {domain: lookup or None}.

    Cached per run in lookups.json. Every query is appended to
    outbound_queries.log right before it is sent, so the log is exactly what
    left the machine. Failures and timeouts give None; this never raises.
    """
    from concurrent.futures import ThreadPoolExecutor, wait
    from datetime import UTC, datetime

    providers = default_providers() if providers is None else providers
    cache_path = run_dir / "lookups.json"
    log_path = run_dir / "outbound_queries.log"
    cache: dict[str, dict | None] = (
        json.loads(cache_path.read_text()) if cache_path.exists() else {}
    )
    wanted = sorted({registrable_domain(d) for d in domains if is_lookup_candidate(d)})
    todo = [r for r in wanted if r not in cache] if providers else []

    def one(reg: str) -> dict | None:
        query = f"{reg} company what is it used for"
        for name, fn in providers:
            with open(log_path, "a") as log:
                log.write(f"{datetime.now(UTC).isoformat()}\t{name}\t{query}\n")
            try:
                found = fn(query)
            except Exception:  # noqa: BLE001 - network/auth/quota: degrade, never crash
                found = None
            if found and found.get("summary"):
                found["summary"] = _shorten(found["summary"])  # contract: max 200 chars
                found.setdefault("url", "")
                return found
        return None

    if todo:
        pool = ThreadPoolExecutor(max_workers=5)
        futures = {reg: pool.submit(one, reg) for reg in todo}
        wait(futures.values(), timeout=LOOKUP_TIMEOUT_S)
        for reg, fut in futures.items():
            cache[reg] = fut.result() if fut.done() and not fut.exception() else None
        pool.shutdown(wait=False, cancel_futures=True)
        cache_path.write_text(json.dumps(cache, indent=2))

    return {
        d: (cache.get(registrable_domain(d)) if is_lookup_candidate(d) else None)
        for d in domains
    }
