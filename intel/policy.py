"""Fetch a public privacy policy and reduce it to clean text.

The only thing sent is an ordinary HTTPS GET for the policy's public URL (logged in the egress
ledger). Fetched text is cached in data/cache/policies/ so a second audit works offline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse

import requests

from sensor.egress import EgressLedger

log = logging.getLogger("intel.policy")

ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = ROOT / "data" / "cache" / "policies"
KNOWN_APPS = Path(__file__).resolve().parent / "known_apps.json"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_0) NoAlibi/0.2 (privacy audit; policy fetch)"
)
SKIP_TAGS = {"script", "style", "noscript", "svg", "template", "iframe", "head", "button", "form"}
BLOCK_TAGS = {
    "p",
    "div",
    "li",
    "br",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "tr",
    "section",
    "article",
    "td",
    "dd",
    "dt",
}
MIN_TEXT_CHARS = 1500


class PolicyError(RuntimeError):
    pass


@dataclass
class PolicyDoc:
    url: str
    text: str
    sha256: str
    fetched_at: datetime
    from_cache: bool = False


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag in SKIP_TAGS:
            self._skip += 1
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in SKIP_TAGS and self._skip:
            self._skip -= 1
        elif tag in BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self._skip:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    """Visible text with one paragraph per line and normalized whitespace."""
    parser = _TextExtractor()
    parser.feed(html)
    raw = "".join(parser.parts)
    lines = [re.sub(r"[ \t ]+", " ", line).strip() for line in raw.splitlines()]
    text = "\n".join(line for line in lines if line)
    return re.sub(r"\n{3,}", "\n\n", text)


def known_app(bundle_id: str) -> dict:
    try:
        return json.loads(KNOWN_APPS.read_text(encoding="utf-8"))["apps"].get(bundle_id, {})
    except (OSError, ValueError, KeyError):
        return {}


def guess_first_party(bundle_id: str, policy_url: str | None) -> list[str]:
    """First-party domains: known list, the policy's own domain, and the reversed bundle id."""
    out = list(known_app(bundle_id).get("first_party", []))
    if policy_url:
        host = urlparse(policy_url).hostname or ""
        if host:
            out.append(host)
    parts = bundle_id.split(".")
    if len(parts) >= 2 and parts[0] in {"com", "dev", "io", "net", "org", "us", "ai", "app", "co"}:
        out.append(f"{parts[1]}.{parts[0]}")
    return list(dict.fromkeys(d.lower() for d in out if d))


def _cache_path(url: str) -> Path:
    return CACHE_DIR / (hashlib.sha256(url.encode()).hexdigest()[:24] + ".json")


def fetch_policy(url: str, ledger: EgressLedger | None = None, offline: bool = False) -> PolicyDoc:
    """Fetch (or load cached) policy text. Raises PolicyError with a readable message."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise PolicyError(f"not a web address: {url!r}")
    cache = _cache_path(url)
    if offline:
        if not cache.exists():
            raise PolicyError("offline, and this policy was never fetched before")
        data = json.loads(cache.read_text(encoding="utf-8"))
        return PolicyDoc(
            url=data["url"],
            text=data["text"],
            sha256=data["sha256"],
            fetched_at=datetime.fromisoformat(data["fetched_at"]),
            from_cache=True,
        )
    if ledger:
        ledger("policy-fetch", url)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=20)
        resp.raise_for_status()
    except requests.RequestException as exc:
        if cache.exists():
            log.warning("fetch failed (%s); using cached copy", exc)
            return fetch_policy(url, offline=True)
        raise PolicyError(f"could not fetch the policy: {exc}") from exc
    text = (
        html_to_text(resp.text) if "html" in resp.headers.get("content-type", "html") else resp.text
    )
    if len(text) < MIN_TEXT_CHARS:
        raise PolicyError(
            f"the page has only {len(text)} characters of text; it may need JavaScript. "
            "Paste a direct link to the policy text instead."
        )
    doc = PolicyDoc(
        url=resp.url,
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        fetched_at=datetime.now(UTC),
    )
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    cache.write_text(
        json.dumps(
            {
                "url": doc.url,
                "text": doc.text,
                "sha256": doc.sha256,
                "fetched_at": doc.fetched_at.isoformat(),
            }
        ),
        encoding="utf-8",
    )
    return doc
