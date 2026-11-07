"""Turn a pcap into flows with tshark: who the app talked to, how much, and when.

Domains come from the TLS/QUIC ClientHello server name (SNI) first, DNS answers second,
never reverse lookup. Nothing is decrypted.
"""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from behavior.capture import CaptureError, find_tool

FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "frame.len",
    "tls.handshake.type",
    "tls.handshake.extensions_server_name",
    "dns.flags.response",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
    "quic.version",
]
# Local-network chatter that is never "the app sending data out".
IGNORED_PORTS = {53, 67, 68, 137, 138, 1900, 5353, 5355}


@dataclass
class Packet:
    t: float
    src: str
    dst: str
    proto: str  # "tcp" | "udp"
    sport: int
    dport: int
    length: int
    sni: str | None = None
    client_hello: bool = False
    tls: bool = False
    dns_name: str | None = None
    dns_answers: list[str] = field(default_factory=list)


@dataclass
class Flow:
    """All of the app's traffic to one destination IP, port and domain."""

    ip: str
    port: int
    proto: str
    domain: str | None
    first_seen: float
    last_seen: float
    bytes_out: int = 0
    bytes_in: int = 0
    tls: bool = False
    samples: list[tuple[float, int, int]] = field(default_factory=list)  # (t, bytes_out, bytes_in)


def _first(value: str) -> str:
    return value.split(",")[0].strip() if value else ""


def parse_rows(text: str) -> list[Packet]:
    """Parse tshark -T fields output (tab separated, multiple values joined by commas)."""
    packets = []
    for line in text.splitlines():
        cols = line.split("\t")
        if len(cols) < len(FIELDS):
            cols += [""] * (len(FIELDS) - len(cols))
        row = dict(zip(FIELDS, cols, strict=False))
        src = _first(row["ip.src"]) or _first(row["ipv6.src"])
        dst = _first(row["ip.dst"]) or _first(row["ipv6.dst"])
        if row["tcp.srcport"]:
            proto, sport, dport = "tcp", row["tcp.srcport"], row["tcp.dstport"]
        elif row["udp.srcport"]:
            proto, sport, dport = "udp", row["udp.srcport"], row["udp.dstport"]
        else:
            continue
        try:
            pkt = Packet(
                t=float(row["frame.time_epoch"]),
                src=src,
                dst=dst,
                proto=proto,
                sport=int(_first(sport)),
                dport=int(_first(dport)),
                length=int(row["frame.len"] or 0),
            )
        except ValueError:
            continue
        hs_types = {x.strip() for x in row["tls.handshake.type"].split(",") if x.strip()}
        pkt.client_hello = "1" in hs_types
        pkt.tls = bool(hs_types) or bool(row["quic.version"])
        pkt.sni = _first(row["tls.handshake.extensions_server_name"]).lower() or None
        if row["dns.flags.response"] in ("1", "True", "true") and row["dns.qry.name"]:
            pkt.dns_name = _first(row["dns.qry.name"]).lower().rstrip(".")
            answers = f"{row['dns.a']},{row['dns.aaaa']}"
            pkt.dns_answers = [a.strip() for a in answers.split(",") if a.strip()]
        packets.append(pkt)
    return packets


def read_packets(pcap: str | Path) -> list[Packet]:
    cmd = [find_tool("tshark"), "-r", str(pcap), "-n", "-T", "fields"]
    cmd += ["-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for name in FIELDS:
        cmd += ["-e", name]
    try:
        out = subprocess.run(  # exit code checked below: tshark warns on truncated captures
            cmd, capture_output=True, text=True, encoding="utf-8", timeout=120, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise CaptureError("tshark took over 120 s to read the capture") from exc
    if out.returncode != 0 and not out.stdout:
        raise CaptureError(f"tshark could not read {pcap}: {out.stderr.strip()}")
    return parse_rows(out.stdout)


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


def build_flows(
    packets: list[Packet],
    my_ips: set[str],
    app_sockets: set[tuple[str, int]] | None = None,
) -> list[Flow]:
    """Group the app's packets into flows. app_sockets=None keeps every process's traffic."""
    dns: dict[str, str] = {}
    for pkt in packets:  # DNS is answered to the OS resolver, so map it before filtering
        for answer in pkt.dns_answers:
            dns.setdefault(answer, pkt.dns_name or "")

    # 1) one connection = (proto, local port, remote ip, remote port)
    conns: dict[tuple, dict] = {}
    for pkt in sorted(packets, key=lambda p: p.t):
        if pkt.src in my_ips:
            outbound, local_port, remote, remote_port = True, pkt.sport, pkt.dst, pkt.dport
        elif pkt.dst in my_ips:
            outbound, local_port, remote, remote_port = False, pkt.dport, pkt.src, pkt.sport
        else:
            continue
        if remote_port in IGNORED_PORTS or local_port in IGNORED_PORTS or not is_public(remote):
            continue
        if app_sockets is not None and (pkt.proto, local_port) not in app_sockets:
            continue
        key = (pkt.proto, local_port, remote, remote_port)
        conn = conns.setdefault(
            key,
            {"sni": None, "first": pkt.t, "last": pkt.t, "out": 0, "in": 0, "tls": False, "s": []},
        )
        conn["last"] = pkt.t
        conn["tls"] = conn["tls"] or pkt.tls or (pkt.proto == "udp" and remote_port == 443)
        if outbound:
            conn["out"] += pkt.length
            conn["s"].append((pkt.t, pkt.length, 0))
            if pkt.client_hello and pkt.sni and not conn["sni"]:
                conn["sni"] = pkt.sni
        else:
            conn["in"] += pkt.length
            conn["s"].append((pkt.t, 0, pkt.length))

    # 2) one flow = all connections to the same remote ip, port and domain
    flows: dict[tuple, Flow] = {}
    for (proto, _lport, remote, rport), conn in conns.items():
        domain = conn["sni"] or dns.get(remote) or None
        key = (remote, rport, proto, domain)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = Flow(
                ip=remote,
                port=rport,
                proto=proto,
                domain=domain,
                first_seen=conn["first"],
                last_seen=conn["last"],
            )
        flow.first_seen = min(flow.first_seen, conn["first"])
        flow.last_seen = max(flow.last_seen, conn["last"])
        flow.bytes_out += conn["out"]
        flow.bytes_in += conn["in"]
        flow.tls = flow.tls or conn["tls"]
        flow.samples.extend(conn["s"])
    for flow in flows.values():
        flow.samples.sort()
    return sorted(flows.values(), key=lambda f: f.first_seen)
