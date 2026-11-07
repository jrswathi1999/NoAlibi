"""Turn a remote IP into a domain, owner and category, without root and without decryption.

Sources (each result records its `source` and a `confidence` honestly):
  "dns+cert"  confirmed: the IP is one we resolved for a known domain AND the certificate the server
              presents covers that domain.
  "dns-match" likely:    the IP is one we resolved at audit start, no certificate to confirm it
              (e.g. Cloudflare refuses handshakes without a name). Shared CDN IPs make this weaker,
              which is why the certificate check overrides it when they disagree.
  "cert"      likely:    opt-in. Our own TLS handshake to the same IP:443 shows the server's
              certificate. No data is sent and nothing is decrypted.
  "ptr"       weak:      reverse DNS, usually a cloud host name.
  "none"      unknown:   we say we don't know.

Every outbound lookup is reported through on_egress so the self-audit can list it.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import logging
import socket
import ssl
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger("sensor.identify")

CATALOG_PATH = Path(__file__).resolve().parent / "catalog.json"
CONTRACT_CATEGORIES = {
    "ai_provider",
    "tracker",
    "analytics",
    "error_reporting",
    "first_party",
    "update",
}
EXPLAIN = {
    "cdn": "content delivery network or cloud host; the company behind the content can't be "
    "identified from the network alone",
    "platform": "operating-system service used by the app",
}
DNS_TIMEOUT_S = 4.0
CERT_TIMEOUT_S = 3.0

Egress = Callable[[str, str], None]  # (kind, what was sent)


@dataclass(frozen=True)
class Identity:
    domain: str | None
    source: str  # dns+cert | dns-match | cert | ptr | none
    category: str  # contract category (unknown for cdn/platform/unmatched)
    raw_category: str  # catalog category, including cdn/platform
    owner: str | None
    note: str | None = None
    confidence: str = "unknown"  # confirmed | likely | possible | weak | unknown


CONFIDENCE = {"dns+cert": "confirmed", "dns-match": "likely", "cert": "likely", "ptr": "weak"}
CONFIDENCE_RANK = {"confirmed": 4, "likely": 3, "possible": 2, "weak": 1, "unknown": 0}
CDN_RANGES_PATH = Path(__file__).resolve().parent / "cdn_ranges.json"
_cdn_nets: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] | None = None


def cdn_provider(ip: str) -> str | None:
    """Name of the CDN whose published ranges contain ip (bundled cdn_ranges.json), else None."""
    global _cdn_nets
    if _cdn_nets is None:
        try:
            data = json.loads(CDN_RANGES_PATH.read_text(encoding="utf-8"))
            _cdn_nets = [
                (name, ipaddress.ip_network(prefix, strict=False))
                for name, prefixes in data["providers"].items()
                for prefix in prefixes
            ]
        except (OSError, ValueError, KeyError):
            _cdn_nets = []
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    for name, net in _cdn_nets:
        if addr.version == net.version and addr in net:
            return name
    return None


def cert_covers(domain: str, names: list[str]) -> bool:
    """True if a certificate name equals domain or is a one-label wildcard for it."""
    d = domain.lower()
    for n in names:
        n = n.lower()
        if n == d:
            return True
        if n.startswith("*.") and d.endswith(n[1:]) and d.count(".") == n.count("."):
            return True
    return False


@dataclass(frozen=True)
class CatalogEntry:
    pattern: str
    category: str
    owner: str
    resolve: bool = False


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def registrable(domain: str) -> str:
    """Rough eTLD+1: 'api.foo.co.uk' -> 'foo.co.uk', 'a.b.example.com' -> 'example.com'."""
    parts = domain.lower().strip(".").split(".")
    if (
        len(parts) >= 3
        and parts[-2] in {"co", "com", "org", "net", "ac", "gov"}
        and len(parts[-1]) == 2
    ):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class Catalog:
    def __init__(self, entries: list[CatalogEntry]):
        self.entries = entries

    @classmethod
    def load(cls, path: Path = CATALOG_PATH) -> Catalog:
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls([CatalogEntry(**e) for e in data["entries"]])

    def match(self, domain: str) -> CatalogEntry | None:
        """Exact pattern first, then the most specific wildcard."""
        d = domain.lower().rstrip(".")
        best: CatalogEntry | None = None
        for e in self.entries:
            if e.pattern == d:
                return e
            specific = best is None or len(e.pattern) > len(best.pattern)
            if "*" in e.pattern and specific and fnmatch.fnmatch(d, e.pattern):
                best = e
        return best

    def resolvable(self) -> list[str]:
        return [e.pattern for e in self.entries if e.resolve and "*" not in e.pattern]


def cert_names(ip: str, port: int = 443, timeout: float = CERT_TIMEOUT_S) -> list[str]:
    """Names on the certificate the server presents to a handshake without SNI. [] on failure."""
    from cryptography import x509
    from cryptography.x509.oid import NameOID

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with (
            socket.create_connection((ip, port), timeout=timeout) as sock,
            ctx.wrap_socket(sock) as tls,
        ):
            der = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError, ValueError):
        return []
    if not der:
        return []
    try:
        cert = x509.load_der_x509_certificate(der)
        names: list[str] = []
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            names += san.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            if isinstance(attr.value, str) and attr.value not in names:
                names.append(attr.value)
        return names
    except ValueError:
        return []


def useful_names(names: list[str]) -> list[str]:
    """Drop placeholder certificate names (e.g. "invalid2.invalid") that say nothing."""
    return [n for n in names if n and not n.lower().endswith((".invalid", ".local", "localhost"))]


class Identifier:
    """Thread-safe IP -> Identity with caching. Call prime() once before the capture starts."""

    def __init__(
        self,
        catalog: Catalog | None = None,
        first_party: list[str] | None = None,
        app_name: str = "",
        cert_probe: bool = True,
        on_egress: Egress | None = None,
    ):
        self.catalog = catalog or Catalog.load()
        self.first_party = sorted({registrable(d) for d in (first_party or []) if d})
        self.app_name = app_name
        self.cert_probe = cert_probe
        self.on_egress = on_egress or (lambda kind, what: None)
        self.ip_to_domain: dict[str, str] = {}
        self._cache: dict[tuple[str, int], Identity] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------ priming

    def _resolve_one(self, domain: str) -> tuple[str, set[str]]:
        self.on_egress("dns", domain)
        try:
            infos = socket.getaddrinfo(domain, 443, proto=socket.IPPROTO_TCP)
        except (OSError, UnicodeError):
            return domain, set()
        return domain, {info[4][0] for info in infos}

    def prime(self, extra_domains: list[str] | None = None) -> int:
        """Resolve catalog + first-party domains so their IPs are recognised. Returns IP count."""
        domains = list(dict.fromkeys(self.catalog.resolvable() + (extra_domains or [])))
        pool = ThreadPoolExecutor(max_workers=24)
        futures = [pool.submit(self._resolve_one, d) for d in domains]
        done, _ = wait(futures, timeout=DNS_TIMEOUT_S * 2)
        pool.shutdown(wait=False, cancel_futures=True)
        with self._lock:
            for f in done:
                domain, ips = f.result()
                for ip in ips:
                    self.ip_to_domain.setdefault(ip, domain)
        log.info("primed %d IPs from %d domains", len(self.ip_to_domain), len(domains))
        return len(self.ip_to_domain)

    # ------------------------------------------------------------ classification

    def classify(self, domain: str | None, source: str) -> Identity:
        ident = self._classify(domain, source)
        return Identity(**{**ident.__dict__, "confidence": CONFIDENCE.get(ident.source, "unknown")})

    def _classify(self, domain: str | None, source: str) -> Identity:
        if not domain:
            return Identity(None, "none", "unknown", "unknown", None, "no name could be found")
        d = domain.lower().lstrip("*.").rstrip(".")
        reg = registrable(d)
        if reg in self.first_party:
            cat = (
                "update"
                if any(k in d for k in ("update", "release", "download"))
                else "first_party"
            )
            return Identity(d, source, cat, cat, self.app_name or reg)
        entry = self.catalog.match(d) or self.catalog.match("x." + d)
        if entry is None:
            return Identity(d, source, "unknown", "unknown", None)
        if entry.category in CONTRACT_CATEGORIES:
            return Identity(d, source, entry.category, entry.category, entry.owner)
        return Identity(
            d, source, "unknown", entry.category, entry.owner, EXPLAIN.get(entry.category)
        )

    def _best_cert_name(self, names: list[str]) -> str | None:
        if not names:
            return None
        for n in names:  # prefer a name the catalog or first-party list knows
            ident = self.classify(n, "cert")
            if ident.raw_category != "unknown":
                return n
        concrete = [n for n in names if not n.startswith("*")]
        return (concrete or names)[0]

    def _cdn_ptr(self, ip: str) -> str | None:
        """Reverse-DNS name if it belongs to a CDN/cloud host in the catalog, else None."""
        if not self.cert_probe:  # PTR is also an outbound lookup; same opt-in
            return None
        self.on_egress("ptr", ip)
        try:
            ptr = socket.gethostbyaddr(ip)[0]
        except (OSError, UnicodeError):
            return None
        entry = self.catalog.match(ptr)
        return ptr if entry and entry.category == "cdn" else None

    def identify(self, ip: str, port: int) -> Identity | None:
        """None for local/private addresses (not reported). Cached per (ip, port)."""
        if not is_public(ip):
            return None
        key = (ip, port)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            domain = self.ip_to_domain.get(ip)
        names: list[str] = []
        if self.cert_probe and port == 443:
            self.on_egress("tls-cert", f"{ip}:443")
            names = useful_names(cert_names(ip))
        ident = None
        if domain and names and cert_covers(domain, names):
            ident = self.classify(domain, "dns+cert")
        elif names:
            # The certificate disagrees with (or replaces) the DNS guess: trust the certificate.
            name = self._best_cert_name(names)
            ident = self.classify(name, "cert") if name else None
        elif domain:
            ident = self.classify(domain, "dns-match")
            cdn = cdn_provider(ip) or self._cdn_ptr(ip)
            if cdn and ident.raw_category not in ("cdn", "first_party", "update"):
                # Shared CDN address: the DNS match is real but other companies may sit behind it.
                ident = Identity(
                    **{
                        **ident.__dict__,
                        "confidence": "possible",
                        "note": f"shared {cdn} address that {domain} resolves to; "
                        "other sites can use it too",
                    }
                )
        if ident is None:
            self.on_egress("ptr", ip)
            try:
                ptr = socket.gethostbyaddr(ip)[0]
            except (OSError, UnicodeError):
                ptr = None
            ident = self.classify(ptr, "ptr") if ptr else self.classify(None, "none")
        with self._lock:
            self._cache[key] = ident
        return ident
