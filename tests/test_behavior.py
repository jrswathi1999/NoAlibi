"""Behavior pipeline on synthetic tshark output: no real capture needed."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from behavior import capture as capture_mod
from behavior.capture import CaptureError, find_tool
from behavior.categorize import categorize, load_endpoints
from behavior.domain_lookup import lookup_domains, query_for
from behavior.mark import phase_for
from behavior.parse_pcap import FIELDS, Flow, build_flows, parse_rows
from behavior.run_behavior import build_events, split_flow
from contracts.models import CaptureInfo, Events

ME = "192.168.1.20"
T0 = 1_794_082_560.0  # 2026-11-07T20:16:00Z
START = datetime.fromtimestamp(T0, UTC)


def row(t, src, dst, sport, dport, length, proto="tcp", hs="", sni="", dns_name="", dns_a=""):
    values = dict.fromkeys(FIELDS, "")
    values.update(
        {
            "frame.time_epoch": str(t),
            "ip.src": src,
            "ip.dst": dst,
            "frame.len": str(length),
            "tls.handshake.type": hs,
            "tls.handshake.extensions_server_name": sni,
        }
    )
    values[f"{proto}.srcport"] = str(sport)
    values[f"{proto}.dstport"] = str(dport)
    if dns_name:
        values.update({"dns.flags.response": "1", "dns.qry.name": dns_name, "dns.a": dns_a})
    return "\t".join(values[f] for f in FIELDS)


def sample_packets():
    lines = [
        # DNS answer: api.mixpanel.com -> 130.211.34.183 (seen by the OS resolver)
        row(T0, "192.168.1.1", ME, 53, 61000, 120, "udp", dns_name="api.mixpanel.com",
            dns_a="130.211.34.183"),
        # App connection 1: TLS to api.openai.com (SNI in ClientHello)
        row(T0 + 1, ME, "162.159.140.245", 50001, 443, 600, hs="1", sni="api.openai.com"),
        row(T0 + 1.2, "162.159.140.245", ME, 443, 50001, 3000, hs="2"),
        row(T0 + 1.3, ME, "162.159.140.245", 50001, 443, 9000),
        # App connection 2: no SNI seen, domain from DNS
        row(T0 + 2, ME, "130.211.34.183", 50002, 443, 800),
        # Another app (port 50999 is not the audited app's socket)
        row(T0 + 3, ME, "142.250.80.4", 50999, 443, 5000, hs="1", sni="www.google.com"),
        # LAN traffic is never "leaving the machine"
        row(T0 + 4, ME, "192.168.1.50", 50003, 8009, 400),
    ]  # fmt: skip
    return parse_rows("\n".join(lines))


APP_SOCKETS = {("tcp", 50001), ("tcp", 50002), ("tcp", 50003)}


def test_parse_rows_reads_sni_and_dns() -> None:
    packets = sample_packets()
    assert packets[0].dns_name == "api.mixpanel.com"
    assert packets[0].dns_answers == ["130.211.34.183"]
    assert packets[1].client_hello and packets[1].sni == "api.openai.com" and packets[1].tls


def test_build_flows_keeps_only_app_traffic() -> None:
    flows = build_flows(sample_packets(), {ME}, APP_SOCKETS)
    by_domain = {f.domain: f for f in flows}
    assert set(by_domain) == {"api.openai.com", "api.mixpanel.com"}  # no google, no LAN, no DNS
    openai = by_domain["api.openai.com"]
    assert (openai.bytes_out, openai.bytes_in, openai.tls) == (9600, 3000, True)
    assert by_domain["api.mixpanel.com"].ip == "130.211.34.183"


def test_build_flows_without_filter_keeps_everyone() -> None:
    flows = build_flows(sample_packets(), {ME}, None)
    assert "www.google.com" in {f.domain for f in flows}


def test_categorize_five_domains() -> None:
    eps = load_endpoints()
    assert categorize("api.openai.com", eps) == ("ai_provider", "OpenAI")
    assert categorize("myres.openai.azure.com", eps)[0] == "ai_provider"
    assert categorize("o123.ingest.sentry.io", eps) == ("error_reporting", "Sentry")
    assert categorize("api.notesapp.com", eps, first_party=["notesapp.com"])[0] == "first_party"
    assert categorize("cdn.xyz-metrics.io", eps) == ("unknown", None)
    assert categorize("dl.notesapp.com", eps, ["notesapp.com"], ["dl.notesapp.com"])[0] == "update"


def test_phase_for() -> None:
    action = START + timedelta(seconds=40)
    assert phase_for(START + timedelta(seconds=3), START, [action]) == "startup"
    assert phase_for(START + timedelta(seconds=42), START, [action]) == "user_action"
    assert phase_for(START + timedelta(seconds=50), START, [action]) == "idle"


def test_split_flow_on_phase_change_and_pause() -> None:
    flow = Flow("1.2.3.4", 443, "tcp", "api.openai.com", T0 + 1, T0 + 70)
    flow.samples = [
        (T0 + 1, 500, 0),  # startup
        (T0 + 41, 12000, 0),  # user_action (mark at +40)
        (T0 + 41.5, 0, 3000),
        (T0 + 60, 400, 100),  # idle
        (T0 + 70, 400, 100),  # idle, after a 10 s pause -> separate piece
        (T0 + 80, 54, 0),  # bare ACK, dropped
    ]
    pieces = split_flow(flow, START, [START + timedelta(seconds=40)])
    assert [(p["phase"], p["out"], p["in"]) for p in pieces] == [
        ("startup", 500, 0),
        ("user_action", 12000, 3000),
        ("idle", 400, 100),
        ("idle", 400, 100),
    ]


def test_build_events_matches_contract() -> None:
    flows = build_flows(sample_packets(), {ME}, APP_SOCKETS)
    capture = CaptureInfo(
        start=START, end=START + timedelta(seconds=90), interface="Wi-Fi", pcap_sha256="x" * 64
    )
    lookups = {"api.mixpanel.com": {"source": "tavily", "summary": "unused", "url": "u"}}
    events = build_events("20261107-201600-notesapp", flows, capture, [], [], [], lookups)
    Events.model_validate(events.model_dump())  # valid contract
    assert [e.id for e in events.events] == ["e1", "e2"]
    first = events.events[0]
    assert (first.domain, first.category, first.owner, first.phase) == (
        "api.openai.com",
        "ai_provider",
        "OpenAI",
        "startup",
    )
    assert events.events[1].lookup is None  # mixpanel is known analytics, so no lookup used


def test_lookup_sends_only_domain_and_logs_it(tmp_path: Path) -> None:
    sent: list[str] = []

    def fake(query: str) -> dict:
        sent.append(query)
        return {"source": "tavily", "summary": "An analytics vendor.", "url": "https://x"}

    out, errors = lookup_domains(["cdn.xyz-metrics.io"], tmp_path, [fake])
    assert sent == [query_for("cdn.xyz-metrics.io")] and not errors
    assert out["cdn.xyz-metrics.io"]["summary"] == "An analytics vendor."
    log = (tmp_path / "outbound_queries.log").read_text(encoding="utf-8")
    assert log == "cdn.xyz-metrics.io company what is it used for\n"
    lookup_domains(["cdn.xyz-metrics.io"], tmp_path, [fake])  # cached: no second request
    assert len(sent) == 1


def test_lookup_failure_does_not_crash(tmp_path: Path) -> None:
    def broken(query: str) -> dict:
        raise TimeoutError("network down")

    out, errors = lookup_domains(["weird.example"], tmp_path, [broken])
    assert out == {"weird.example": None} and "network down" in errors[0]


def test_find_tool_missing_is_clear(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TSHARK", raising=False)
    monkeypatch.setattr(capture_mod.shutil, "which", lambda name: None)
    monkeypatch.setattr(capture_mod, "WIRESHARK_DIRS", [])
    with pytest.raises(CaptureError, match="Install Wireshark"):
        find_tool("tshark")
