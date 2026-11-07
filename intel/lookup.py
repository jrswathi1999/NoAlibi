"""Ask Tavily (Exa as fallback) who is behind a domain we couldn't identify. Optional.

Only the registrable domain name is sent (e.g. "xyz-metrics.io"), never an IP, URL path, byte
count or anything about the user. Each query is written to the egress ledger and cached in
data/cache/lookups.json, so a repeat audit makes no calls at all. Without API keys this is skipped.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path

from sensor.egress import EgressLedger
from sensor.identify import registrable

log = logging.getLogger("intel.lookup")

CACHE = Path(__file__).resolve().parent.parent / "data" / "cache" / "lookups.json"
_lock = threading.Lock()


def _load_cache() -> dict:
    try:
        return json.loads(CACHE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_cache(cache: dict) -> None:
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(cache, indent=1) + "\n", encoding="utf-8")


def available() -> bool:
    return bool(os.environ.get("TAVILY_API_KEY") or os.environ.get("EXA_API_KEY"))


def _tavily(domain: str) -> dict | None:
    from tavily import TavilyClient

    client = TavilyClient(api_key=os.environ["TAVILY_API_KEY"])
    res = client.search(
        f"{domain} company: what is this domain used for (analytics, tracking, AI API, CDN)?",
        search_depth="basic",
        include_answer=True,
        max_results=3,
    )
    answer = (res.get("answer") or "").strip()
    results = res.get("results") or []
    if not answer and results:
        answer = (results[0].get("content") or "").strip()
    if not answer:
        return None
    return {
        "source": "tavily",
        "summary": answer[:200],
        "url": results[0]["url"] if results else "",
    }


def _exa(domain: str) -> dict | None:
    from exa_py import Exa

    res = Exa(api_key=os.environ["EXA_API_KEY"]).search_and_contents(
        f"{domain} company what is it used for", num_results=1, text={"max_characters": 400}
    )
    if not res.results:
        return None
    r = res.results[0]
    return {"source": "exa", "summary": (r.text or r.title or "")[:200], "url": r.url}


def lookup(domain: str, ledger: EgressLedger | None = None) -> dict | None:
    """{source, summary, url} for a domain, from cache or search. None if unknown or no keys."""
    reg = registrable(domain)
    with _lock:
        cache = _load_cache()
        if reg in cache:
            return {**cache[reg], "cached": True}
    result = None
    for name, fn, key in (("tavily", _tavily, "TAVILY_API_KEY"), ("exa", _exa, "EXA_API_KEY")):
        if not os.environ.get(key):
            continue
        if ledger:
            ledger(f"{name}-search", reg)
        try:
            result = fn(reg)
        except Exception as exc:  # noqa: BLE001 - search is best-effort, never fatal
            log.warning("%s lookup for %s failed: %s", name, reg, exc)
        if result:
            break
    if result:
        with _lock:
            cache = _load_cache()
            cache[reg] = result
            _save_cache(cache)
    return result
