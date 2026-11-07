"""Ask Tavily (Exa as fallback) what an unknown domain is. Only the domain name is sent.

Every outbound query is appended to outbound_queries.log first, so we can show exactly what
left the laptop. Results are cached per run in lookups.json.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from pathlib import Path

from settings import load_env, use_system_certificates

SUMMARY_MAX = 200
Searcher = Callable[[str], dict | None]  # query -> {"source", "summary", "url"} or None


def query_for(domain: str) -> str:
    return f"{domain} company what is it used for"


def _clip(text: str) -> str:
    """One clean line of at most 200 characters (search results often contain markdown)."""
    text = re.sub(r"[#*`>|]+", " ", text or "")
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # [label](link) -> label
    text = " ".join(text.split())
    return text if len(text) <= SUMMARY_MAX else text[: SUMMARY_MAX - 1].rstrip() + "…"


def tavily_search(query: str) -> dict | None:
    key = os.environ.get("TAVILY_API_KEY")
    if not key:
        return None
    from tavily import TavilyClient

    results = TavilyClient(api_key=key).search(query, max_results=3).get("results") or []
    if not results:
        return None
    top = results[0]
    return {"source": "tavily", "summary": _clip(top.get("content", "")), "url": top.get("url", "")}


def exa_search(query: str) -> dict | None:
    key = os.environ.get("EXA_API_KEY")
    if not key:
        return None
    from exa_py import Exa

    results = Exa(api_key=key).search_and_contents(query, num_results=1, text=True).results
    if not results:
        return None
    top = results[0]
    return {"source": "exa", "summary": _clip(getattr(top, "text", "") or ""), "url": top.url}


def lookup_domains(
    domains: list[str],
    run_dir: Path,
    searchers: list[Searcher] | None = None,
) -> tuple[dict[str, dict | None], list[str]]:
    """Return ({domain: lookup or None}, errors). Never raises."""
    load_env()
    use_system_certificates()
    if searchers is None:  # only services with a key, so the log lists only real requests
        searchers = [
            s
            for s, key in ((tavily_search, "TAVILY_API_KEY"), (exa_search, "EXA_API_KEY"))
            if os.environ.get(key)
        ]
        if not searchers and domains:
            return {d: None for d in domains}, ["no TAVILY_API_KEY / EXA_API_KEY: lookups skipped"]
    cache_path = run_dir / "lookups.json"
    log_path = run_dir / "outbound_queries.log"
    try:
        cache = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    except ValueError:
        cache = {}
    errors: list[str] = []
    out: dict[str, dict | None] = {}
    for domain in sorted(set(domains)):
        if domain in cache:
            out[domain] = cache[domain]
            continue
        query = query_for(domain)
        result = None
        for search in searchers:
            with log_path.open("a", encoding="utf-8") as log:
                log.write(query + "\n")
            try:
                result = search(query)
            except Exception as exc:  # noqa: BLE001 - one failed lookup must not stop the run
                errors.append(f"{getattr(search, '__name__', 'search')} failed for {domain}: {exc}")
                result = None
            if result:
                break
        out[domain] = cache[domain] = result
    cache_path.write_text(json.dumps(cache, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out, errors
