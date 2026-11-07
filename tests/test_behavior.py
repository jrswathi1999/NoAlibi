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


def test_marker_reads_enter_presses_and_saves(tmp_path):
    import io

    from behavior.mark import ActionMarker

    m = ActionMarker()
    th = m.listen(io.StringIO("used AI summarize\n\n"))
    th.join(timeout=2)
    m.save(tmp_path / "actions.json")
    saved = __import__("json").loads((tmp_path / "actions.json").read_text())
    assert [a["label"] for a in saved] == ["used AI summarize", ""]
    assert saved[0]["t"].endswith("Z")


def test_phase_rules():
    from behavior.mark import phase_for

    start, actions = 1000.0, [1040.0]
    assert phase_for(1002.0, start, actions) == "startup"
    assert phase_for(1042.0, start, actions) == "user_action"
    assert phase_for(1045.0, start, actions) == "user_action"
    assert phase_for(1045.1, start, actions) == "idle"
    assert phase_for(1039.9, start, actions) == "idle"  # before the click is not caused by it
    assert phase_for(1005.0, start, [1003.0]) == "user_action"


def test_build_events_matches_contract_and_labels_reused_connection():
    from behavior.mark import iso
    from behavior.parse_pcap import Flow
    from behavior.run_behavior import build_events

    start = 1794100000.0  # capture start
    capture = {
        "start": iso(start),
        "end": iso(start + 90),
        "interface": "veth-host",
        "pcap_sha256": "ab" * 32,
    }
    actions = [{"t": iso(start + 40), "label": "used AI"}]  # +40 s
    # Connection opened at startup (+2 s, small), then reused right after the click (+42 s, 12 KB).
    reused = Flow(
        ip="162.159.140.245",
        port=443,
        proto="tcp",
        first_t=start + 2,
        last_t=start + 43,
    )
    reused.domain, reused.tls, reused.bytes_out = "api.openai.com", True, 12534
    reused.out_bytes_by_t = [(start + 2, 500), (start + 42.1, 12034)]
    idle = Flow(ip="5.5.5.5", port=443, proto="tcp", first_t=start + 60, last_t=start + 61)
    idle.domain, idle.tls, idle.bytes_out = "mystery.example", True, 300
    idle.out_bytes_by_t = [(start + 60, 300)]

    doc = build_events("20261107-154640-notesapp", [idle, reused], capture, actions, "NotesApp")
    e1, e2 = doc["events"]
    assert (e1["id"], e1["domain"], e1["phase"], e1["category"], e1["owner"]) == (
        "e1",
        "api.openai.com",
        "user_action",
        "ai_provider",
        "OpenAI",
    )
    assert e1["t_rel_s"] == 42.1
    assert (e2["phase"], e2["category"], e2["lookup"]) == ("idle", "unknown", None)


def test_lookup_sends_only_registrable_domains_and_logs_them(tmp_path):
    from behavior.domain_lookup import lookup_domains

    sent = []

    def fake_tavily(query):
        sent.append(query)
        return {"source": "tavily", "summary": "x" * 500, "url": "https://example.org"}

    domains = [
        "user-8812.tenant.cdp-example.net",
        "8.8.4.4",
        "printer.local",
        "api.foo.co.uk",
    ]
    got = lookup_domains(domains, tmp_path, [("tavily", fake_tavily)])
    assert sorted(sent) == [
        "cdp-example.net company what is it used for",
        "foo.co.uk company what is it used for",
    ]
    assert got["8.8.4.4"] is None and got["printer.local"] is None
    assert len(got["user-8812.tenant.cdp-example.net"]["summary"]) <= 200
    log = (tmp_path / "outbound_queries.log").read_text()
    assert "user-8812" not in log and "8.8.4.4" not in log and log.count("\n") == 2

    lookup_domains(domains, tmp_path, [("tavily", fake_tavily)])  # cached: no new queries
    assert len(sent) == 2


def test_lookup_falls_back_to_exa_and_never_raises(tmp_path):
    from behavior.domain_lookup import lookup_domains

    def broken(query):
        raise ConnectionError("no network")

    def exa(query):
        return {"source": "exa", "summary": "Analytics vendor.", "url": "https://e.x"}

    got = lookup_domains(["a.mystery.io"], tmp_path, [("tavily", broken), ("exa", exa)])
    assert got["a.mystery.io"]["source"] == "exa"
    got = lookup_domains(["b.other.io"], tmp_path, [("tavily", broken)])
    assert got["b.other.io"] is None


def test_no_keys_means_no_queries_and_no_log(tmp_path, monkeypatch):
    from behavior import domain_lookup

    monkeypatch.setattr(domain_lookup, "_load_env_key", lambda name: None)
    got = domain_lookup.lookup_domains(["x.example.com"], tmp_path)
    assert got == {"x.example.com": None}
    assert not (tmp_path / "outbound_queries.log").exists()


def test_heartbeat_on_one_kept_alive_connection_shows_in_timing():
    from behavior.mark import iso
    from behavior.parse_pcap import Flow
    from behavior.run_behavior import build_timing

    start = 1794100000.0
    f = Flow(ip="1.2.3.4", port=443, proto="tcp", first_t=start + 1, last_t=start + 80)
    f.domain = "events.cdp-example.net"
    # handshake at +1 s, then 3 heartbeats ~20 s apart (each split over 2 packets), all one connection
    f.out_bytes_by_t = [(start + 1, 517)]
    for t in (20.0, 40.2, 59.9):
        f.out_bytes_by_t += [(start + t, 300), (start + t + 0.05, 110)]
    capture = {
        "start": iso(start),
        "end": iso(start + 90),
        "interface": "veth-host",
        "pcap_sha256": "0" * 64,
    }
    tm = build_timing([f], capture, [])["events.cdp-example.net"]
    assert tm["idle_bursts"] == 3
    assert [b["bytes_out"] for b in tm["bursts"]] == [517, 410, 410, 410]
    assert tm["mean_gap_s"] == 19.95 and tm["cv"] < 0.05


def test_ss_parsing_keeps_only_app_sockets():
    from behavior.host_capture import parse_ss

    lines = [
        'tcp ESTAB 0 0 192.168.64.5:51234 162.159.140.245:443 users:(("notesapp",pid=4312,fd=31))',
        'tcp ESTAB 0 0 192.168.64.5:51240 142.250.1.1:443 users:(("firefox",pid=999,fd=12))',
        'udp UNCONN 0 0 0.0.0.0:5353 0.0.0.0:* users:(("notesapp",pid=4312,fd=40))',
        'tcp ESTAB 0 0 [::ffff:192.168.64.5]:51300 [::ffff:3.3.3.3]:443 users:(("notesapp",pid=4400,fd=9))',
    ]
    assert parse_ss("\n".join(lines), {4312, 4400}) == {
        ("192.168.64.5", 51234, "162.159.140.245", 443),
        ("::ffff:192.168.64.5", 51300, "::ffff:3.3.3.3", 443),
    }


def test_host_mode_filters_packets_to_app_sockets():
    host = "192.168.64.5"
    lines = [
        tcp(1.0, host, "162.159.140.245", 51234, 443, 900, sni="api.openai.com", hs="1"),
        tcp(1.1, host, "142.250.1.1", 51240, 443, 700, sni="www.google.com", hs="1"),  # browser
    ]
    pk = [p for p in (parse_row(x) for x in lines) if p]
    flows = build_flows(pk, {host}, {(host, 51234, "::ffff:162.159.140.245", 443)})
    assert [f.domain for f in flows] == ["api.openai.com"]
