"""Turn run.pcap into flows using tshark.

One flow = one remote (IP, port). The domain comes from the TLS SNI first,
then from DNS answers seen in the capture. We never do reverse lookups.
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

SANDBOX_IP = "10.200.0.2"

# Order matters: parse_row reads by position.
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
    "tcp.len",
    "udp.length",
    "tls.handshake.extensions_server_name",  # also QUIC Initial ClientHello
    "tls.handshake.type",
    "dns.qry.name",
    "dns.a",
    "dns.aaaa",
]

# Not app destinations: DNS, mDNS, LLMNR, DHCP, NTP.
IGNORED_PORTS = {53, 5353, 5355, 67, 68, 123}


class ParseError(RuntimeError):
    pass


@dataclass
class Packet:
    t: float
    src: str
    dst: str
    sport: int | None
    dport: int | None
    proto: str  # "tcp" | "udp" | ""
    payload: int
    sni: str
    tls_handshake: bool
    dns_name: str
    dns_ips: list[str]


@dataclass
class Flow:
    ip: str
    port: int
    proto: str
    first_t: float
    last_t: float
    bytes_out: int = 0
    bytes_in: int = 0
    tls: bool = False
    sni: str = ""
    domain: str = ""
    domain_source: str = "none"  # sni | dns | none
    out_times: list[float] = field(
        default_factory=list
    )  # packets with payload, outbound
    out_bytes_by_t: list[tuple[float, int]] = field(default_factory=list)


def _first(value: str) -> str:
    return value.split(",")[0] if value else ""


def _int(value: str) -> int | None:
    v = _first(value)
    try:
        return int(v)
    except ValueError:
        return None


def parse_row(line: str) -> Packet | None:
    cols = line.rstrip("\n").split("\t")
    if len(cols) < len(FIELDS):
        cols += [""] * (len(FIELDS) - len(cols))
    (
        t,
        ip_src,
        ip_dst,
        v6_src,
        v6_dst,
        tsp,
        tdp,
        usp,
        udp_,
        tlen,
        ulen,
        sni,
        hs,
        qn,
        a,
        aaaa,
    ) = cols[: len(FIELDS)]
    try:
        ts = float(t)
    except ValueError:
        return None
    src = _first(ip_src) or _first(v6_src)
    dst = _first(ip_dst) or _first(v6_dst)
    if not src or not dst:
        return None
    if tsp or tdp:
        proto, sport, dport = "tcp", _int(tsp), _int(tdp)
        payload = _int(tlen) or 0
    elif usp or udp_:
        proto, sport, dport = "udp", _int(usp), _int(udp_)
        payload = max((_int(ulen) or 8) - 8, 0)
    else:
        proto, sport, dport, payload = "", None, None, 0
    ips = [x for x in (a.split(",") + aaaa.split(",")) if x]
    return Packet(
        t=ts,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        proto=proto,
        payload=payload,
        sni=_first(sni),
        tls_handshake=bool(hs),
        dns_name=_first(qn),
        dns_ips=ips,
    )


def build_flows(packets: list[Packet], local_ips: set[str] | None = None) -> list[Flow]:
    """Group packets into flows keyed by remote (IP, port)."""
    local = local_ips or {SANDBOX_IP}
    ip_to_domain: dict[str, str] = {}
    flows: dict[tuple[str, int], Flow] = {}

    for p in sorted(packets, key=lambda x: x.t):
        if p.dns_name and p.dns_ips:
            for ip in p.dns_ips:
                ip_to_domain[ip] = p.dns_name.rstrip(".").lower()
        if p.src in local:
            outbound, remote, rport = True, p.dst, p.dport
        elif p.dst in local:
            outbound, remote, rport = False, p.src, p.sport
        else:
            continue
        if not p.proto or rport is None or rport in IGNORED_PORTS:
            continue
        key = (remote, rport)
        f = flows.get(key)
        if f is None:
            f = flows[key] = Flow(
                ip=remote, port=rport, proto=p.proto, first_t=p.t, last_t=p.t
            )
        f.last_t = p.t
        if outbound:
            f.bytes_out += p.payload
            if p.payload:
                f.out_times.append(p.t)
                f.out_bytes_by_t.append((p.t, p.payload))
        else:
            f.bytes_in += p.payload
        if p.sni and not f.sni:
            f.sni = p.sni.lower()
        if p.tls_handshake or p.sni or (p.proto == "udp" and rport == 443):
            f.tls = True

    for f in flows.values():
        if f.sni:
            f.domain, f.domain_source = f.sni, "sni"
        elif f.ip in ip_to_domain:
            f.domain, f.domain_source = ip_to_domain[f.ip], "dns"
        else:
            f.domain, f.domain_source = f.ip, "none"
    return sorted(flows.values(), key=lambda f: f.first_t)


def run_tshark(pcap: Path) -> list[str]:
    if shutil.which("tshark") is None:
        raise ParseError("tshark not installed: sudo apt install -y tshark")
    if not pcap.exists():
        raise ParseError(f"pcap not found: {pcap}")
    cmd = ["tshark", "-r", str(pcap), "-n", "-T", "fields"]
    cmd += ["-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,"]
    for f in FIELDS:
        cmd += ["-e", f]
    res = subprocess.run(cmd, check=False, capture_output=True, text=True)
    if res.returncode != 0:
        raise ParseError(f"tshark failed: {res.stderr.strip()[:300]}")
    return res.stdout.splitlines()


def parse_pcap(pcap: Path, local_ips: set[str] | None = None) -> list[Flow]:
    rows = run_tshark(pcap)
    packets = [p for p in (parse_row(r) for r in rows) if p is not None]
    return build_flows(packets, local_ips)


BURST_GAP_S = 0.3  # outbound packets closer than this belong to the same upload burst


def domain_bursts(flows: list[Flow]) -> dict[str, list[tuple[float, int]]]:
    """Per domain, the upload bursts (start time, bytes) across all its connections.

    events.json has one event per connection, so a heartbeat sent over one
    kept-alive connection is a single event. These bursts expose the rhythm
    that the periodic-telemetry rule needs.
    """
    packets: dict[str, list[tuple[float, int]]] = {}
    for f in flows:
        packets.setdefault(f.domain, []).extend(f.out_bytes_by_t)
    out: dict[str, list[tuple[float, int]]] = {}
    for domain, pk in packets.items():
        bursts: list[list[float]] = []  # [start, last, bytes]
        for t, n in sorted(pk):
            if bursts and t - bursts[-1][1] < BURST_GAP_S:
                bursts[-1][1] = t
                bursts[-1][2] += n
            else:
                bursts.append([t, t, n])
        out[domain] = [(b[0], int(b[2])) for b in bursts]
    return out
