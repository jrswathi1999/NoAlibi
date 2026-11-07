"""Tests for the behavior pipeline. Run with: pytest tests/test_behavior.py"""

from __future__ import annotations

import subprocess
from pathlib import Path

from behavior.parse_pcap import FIELDS, build_flows, parse_row

ROOT = Path(__file__).resolve().parents[1]
NS = "10.200.0.2"


def row(**kw: str) -> str:
    """Build one tshark TSV line from field-name keyword args (dots -> underscores)."""
    vals = {f: "" for f in FIELDS}
    for k, v in kw.items():
        vals[k.replace("__", ".")] = v
    return "\t".join(vals[f] for f in FIELDS)


def tcp(t, src, dst, sp, dp, n=0, sni="", hs=""):
    return row(
        frame__time_epoch=str(t),
        ip__src=src,
        ip__dst=dst,
        tcp__srcport=str(sp),
        tcp__dstport=str(dp),
        tcp__len=str(n),
        tls__handshake__extensions_server_name=sni,
        tls__handshake__type=hs,
    )


def dns_answer(t, name, ips):
    return row(
        frame__time_epoch=str(t),
        ip__src="1.1.1.1",
        ip__dst=NS,
        udp__srcport="53",
        udp__dstport="40000",
        udp__length="100",
        dns__qry__name=name,
        dns__a=",".join(ips),
    )


def flows_from(lines):
    return build_flows([p for p in (parse_row(x) for x in lines) if p])


def test_sandbox_script_syntax():
    subprocess.run(["bash", "-n", str(ROOT / "behavior" / "sandbox.sh")], check=True)


def test_three_curls_make_three_flows():
    lines = [
        dns_answer(99.0, "neverssl.com", ["34.223.124.45"]),
        tcp(100.0, NS, "172.66.147.243", 50000, 443, 517, sni="example.com", hs="1"),
        tcp(100.1, "172.66.147.243", NS, 443, 50000, 4000),
        tcp(
            101.0,
            NS,
            "208.80.153.224",
            50001,
            443,
            520,
            sni="www.wikipedia.org",
            hs="1",
        ),
        tcp(101.2, "208.80.153.224", NS, 443, 50001, 9000),
        tcp(102.0, NS, "34.223.124.45", 50002, 80, 75),
        tcp(102.1, "34.223.124.45", NS, 80, 50002, 4261),
    ]
    flows = flows_from(lines)
    assert [(f.domain, f.domain_source, f.port, f.tls) for f in flows] == [
        ("example.com", "sni", 443, True),
        ("www.wikipedia.org", "sni", 443, True),
        ("neverssl.com", "dns", 80, False),
    ]
    assert flows[0].bytes_out == 517 and flows[0].bytes_in == 4000


def test_sni_wins_over_dns_and_unknown_ip_stays_ip():
    lines = [
        dns_answer(1.0, "cdn.example.net", ["9.9.9.9"]),
        tcp(2.0, NS, "9.9.9.9", 50000, 443, 500, sni="api.openai.com", hs="1"),
        tcp(3.0, NS, "8.8.4.4", 50001, 443, 100),
    ]
    flows = flows_from(lines)
    assert flows[0].domain == "api.openai.com"
    assert (flows[1].domain, flows[1].domain_source) == ("8.8.4.4", "none")


def test_dns_and_pure_acks_are_not_events_or_bytes():
    lines = [
        dns_answer(1.0, "x.com", ["5.5.5.5"]),
        tcp(2.0, NS, "5.5.5.5", 50000, 443, 0),  # pure ACK
        tcp(2.1, NS, "5.5.5.5", 50000, 443, 300),
    ]
    flows = flows_from(lines)
    assert len(flows) == 1
    assert flows[0].bytes_out == 300
    assert flows[0].out_times == [2.1]


def test_quic_counts_as_tls_and_udp_payload_excludes_header():
    lines = [
        row(
            frame__time_epoch="5.0",
            ip__src=NS,
            ip__dst="142.250.1.1",
            udp__srcport="51000",
            udp__dstport="443",
            udp__length="1208",
            tls__handshake__extensions_server_name="www.google.com",
        )
    ]
    (f,) = flows_from(lines)
    assert f.tls and f.domain == "www.google.com" and f.bytes_out == 1200


def test_endpoint_matcher_maps_sample_domains():
    from behavior.domain_lookup import categorize

    fp = ["notesapp.com"]
    cases = {
        "api.openai.com": ("ai_provider", "OpenAI"),
        "myco.openai.azure.com": ("ai_provider", "Microsoft Azure OpenAI"),
        "us-central1-aiplatform.googleapis.com": ("ai_provider", "Google Vertex AI"),
        "bedrock-runtime.us-east-1.amazonaws.com": ("ai_provider", "Amazon Bedrock"),
        "api.segment.io": ("analytics", "Segment (Twilio)"),
        "o123.ingest.sentry.io": ("error_reporting", "Sentry"),
        "sync.notesapp.com": ("first_party", "NotesApp"),
        "evilsentry.io": ("unknown", None),
        "random-cdn.example": ("unknown", None),
    }
    for domain, want in cases.items():
        assert categorize(domain, first_party=fp, app_name="NotesApp") == want, domain


def test_update_domain_wins_over_first_party():
    from behavior.domain_lookup import categorize

    got = categorize(
        "updates.notesapp.com",
        first_party=["notesapp.com"],
        update=["updates.notesapp.com"],
        app_name="NotesApp",
    )
    assert got == ("update", "NotesApp")
