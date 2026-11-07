"""Refresh sensor/cdn_ranges.json from the CDN providers' own published IP lists.

Run before an event so the audit itself needs no internet for this:
    python scripts/update_cdn_ranges.py
"""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import requests

OUT = Path(__file__).resolve().parent.parent / "sensor" / "cdn_ranges.json"
TIMEOUT = 20


def aws_cloudfront() -> list[str]:
    data = requests.get("https://ip-ranges.amazonaws.com/ip-ranges.json", timeout=TIMEOUT).json()
    v4 = [p["ip_prefix"] for p in data["prefixes"] if p["service"] == "CLOUDFRONT"]
    v6 = [p["ipv6_prefix"] for p in data["ipv6_prefixes"] if p["service"] == "CLOUDFRONT"]
    return sorted(set(v4)) + sorted(set(v6))


def cloudflare() -> list[str]:
    out: list[str] = []
    for url in ("https://www.cloudflare.com/ips-v4", "https://www.cloudflare.com/ips-v6"):
        out += [x.strip() for x in requests.get(url, timeout=TIMEOUT).text.split() if x.strip()]
    return out


def fastly() -> list[str]:
    data = requests.get("https://api.fastly.com/public-ip-list", timeout=TIMEOUT).json()
    return data.get("addresses", []) + data.get("ipv6_addresses", [])


def main() -> int:
    providers = {}
    for name, fn in (
        ("Amazon CloudFront", aws_cloudfront),
        ("Cloudflare", cloudflare),
        ("Fastly", fastly),
    ):
        try:
            providers[name] = fn()
            print(f"{name}: {len(providers[name])} prefixes")
        except (requests.RequestException, ValueError, KeyError) as exc:
            print(f"{name}: failed ({exc})", file=sys.stderr)
    if not providers:
        return 1
    OUT.write_text(
        json.dumps({"fetched_at": datetime.now(UTC).isoformat(), "providers": providers}, indent=1)
        + "\n",
        encoding="utf-8",
    )
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
