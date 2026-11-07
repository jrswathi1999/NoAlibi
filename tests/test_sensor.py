"""Sensor: nettop parsing, destination identification and burst/phase logic.

Inputs are small strings in nettop's real output format, not recorded traffic.
"""

from datetime import UTC, datetime
from pathlib import Path

import pytest

from contracts.models import Events, UserAction
from sensor.identify import Catalog, Identifier, cdn_provider, cert_covers, is_public, registrable
from sensor.nettop import iter_samples, parse_lines, split_endpoint
from sensor.procs import Proc, target_pids

TABLE = """,bytes_in,bytes_out,
Some App Helper.4312,7276,31697,
tcp4 10.0.0.5:62332<->162.159.140.245:443,7276,31697,
udp6 fe80::1%en0.5353<->*.*,,,
tcp6 *.3306<->*.*,,,
otherd.99,10,10,
tcp4 127.0.0.1:5000<->127.0.0.1:6000,10,10,
,bytes_in,bytes_out,
Some App Helper.4312,8000,40000,
tcp4 10.0.0.5:62332<->162.159.140.245:443,8000,40000,
"""


def test_split_endpoint_v4_v6_and_wildcards():
    assert split_endpoint("1.2.3.4:443", "tcp4") == ("1.2.3.4", 443)
    assert split_endpoint("fe80::1%en0.5353", "udp6") == ("fe80::1", 5353)
    assert split_endpoint("*:*", "tcp4") is None
    assert split_endpoint("*.*", "tcp6") is None


def test_parse_table_attributes_connections_to_processes():
    sample = parse_lines(TABLE.splitlines()[1:7], t=1.0)
    assert [(c.pid, c.proc, c.remote_ip, c.bytes_out) for c in sample.conns] == [
        (4312, "Some App Helper", "162.159.140.245", 31697),
        (99, "otherd", "127.0.0.1", 10),
    ]


def test_iter_samples_splits_on_header():
    samples = list(iter_samples(iter(TABLE.splitlines()), clock=lambda: 5.0))
    assert len(samples) == 2
    assert samples[1].conns[0].bytes_out == 40000


def test_target_pids_follows_bundle_path_and_children():
    procs = {
        1: Proc(1, 0, "/sbin/launchd"),
        10: Proc(10, 1, "/Applications/Notes AI.app/Contents/MacOS/Notes AI"),
        11: Proc(11, 10, "/Applications/Notes AI.app/Contents/Frameworks/Helper.app/Helper"),
        12: Proc(12, 11, "/usr/bin/curl https://example.com"),
        20: Proc(20, 1, "/Applications/Other.app/Contents/MacOS/Other"),
    }
    for p in procs.values():
        if p.ppid in procs:
            procs[p.ppid].children.append(p.pid)
    assert target_pids("/Applications/Notes AI.app", procs) == {10, 11, 12}


def test_public_and_registrable():
    assert is_public("162.159.140.245")
    assert not is_public("10.0.0.5") and not is_public("127.0.0.1") and not is_public("fe80::1")
    assert registrable("api.foo.co.uk") == "foo.co.uk"
    assert registrable("a.b.example.com") == "example.com"


def test_cert_covers_one_label_wildcards_only():
    assert cert_covers("api.openai.com", ["*.openai.com"])
    assert cert_covers("api.openai.com", ["api.openai.com"])
    assert not cert_covers("a.b.openai.com", ["*.openai.com"])
    assert not cert_covers("api.openai.com", ["*.anthropic.com"])


def test_catalog_prefers_exact_then_most_specific():
    cat = Catalog.load()
    assert cat.match("api.openai.com").owner == "OpenAI"
    assert cat.match("o12345.ingest.us.sentry.io").category == "error_reporting"
    assert cat.match("d1234.cloudfront.net").category == "cdn"
    assert cat.match("example.org") is None


def test_classify_first_party_and_cdn():
    idf = Identifier(first_party=["notes.example"], app_name="Notes", cert_probe=False)
    assert idf.classify("api.notes.example", "dns-match").category == "first_party"
    assert idf.classify("updates.notes.example", "dns-match").category == "update"
    cdn = idf.classify("d1234.cloudfront.net", "ptr")
    assert cdn.category == "unknown" and cdn.raw_category == "cdn" and cdn.confidence == "weak"
    assert idf.classify(None, "none").confidence == "unknown"


def test_cdn_ranges_bundle_is_real_and_used():
    # Cloudflare's published range 162.158.0.0/15 contains this address.
    assert cdn_provider("162.159.140.245") == "Cloudflare"
    assert cdn_provider("10.0.0.1") is None


def test_identify_marks_shared_cdn_dns_match_as_possible():
    idf = Identifier(cert_probe=False)
    idf.ip_to_domain["162.159.140.245"] = "api.openai.com"
    ident = idf.identify("162.159.140.245", 443)
    assert ident.domain == "api.openai.com" and ident.category == "ai_provider"
    assert ident.confidence == "possible" and "Cloudflare" in ident.note
    assert idf.identify("10.0.0.9", 443) is None  # private addresses are never reported


# ---------------------------------------------------------------- session bursts and phases


class _App:
    name = "Notes"
    bundle_path = "/Applications/Notes.app"


def _session(tmp_path: Path, monkeypatch):
    from sensor import session as sess

    monkeypatch.setattr(sess, "self_pids", lambda procs=None: set())
    monkeypatch.setattr(sess, "list_processes", dict)
    monkeypatch.setattr(sess, "target_pids", lambda bundle, procs=None: {4312})
    idf = Identifier(cert_probe=False)
    idf.ip_to_domain["160.79.104.10"] = "api.anthropic.com"
    s = sess.AuditSession(_App(), tmp_path / "20261107-120000-notes", idf, fresh_launch=False)
    s.t0 = s.t_start = 1000.0
    s._pool = _InlinePool()
    return s


class _InlinePool:
    def submit(self, fn, *args):
        fn(*args)

        class _Done:
            def result(self, timeout=None):
                return None

        return _Done()

    def shutdown(self, **_):
        pass


def _conn_line(out_bytes: int) -> list[str]:
    return ["Notes Helper.4312,0,0,", f"tcp4 10.0.0.5:5000<->160.79.104.10:443,100,{out_bytes},"]


def test_bursts_split_on_quiet_seconds_and_follow_the_click(tmp_path, monkeypatch):
    s = _session(tmp_path, monkeypatch)
    feed = [
        (1001.0, 500),
        (1002.0, 500),
        (1003.0, 900),
        (1004.0, 900),
        (1020.0, 900),
        (1021.0, 13000),
    ]
    s.actions.append(UserAction(t=datetime.fromtimestamp(1020.5, UTC), label="summarize"))
    for t, out in feed:
        s._on_sample(parse_lines(_conn_line(out), t))
    flow = next(iter(s.flows.values()))
    assert flow.preexisting and flow.bytes_out == 12500  # baseline 500 at the first sample
    assert [(b.bytes_out) for b in flow.bursts] == [400, 12100]
    s.t_end = 1022.0
    events, _ = s.build_events("20261107-120000-notes", "abc")
    assert isinstance(events, Events)
    assert [e.phase for e in events.events] == ["idle", "user_action"]
    assert events.events[1].domain == "api.anthropic.com"
    assert events.events[1].category == "ai_provider"


def test_write_produces_contract_files(tmp_path, monkeypatch):
    s = _session(tmp_path, monkeypatch)
    s.run_dir.mkdir(parents=True)
    for t, out in [(1001.0, 0), (1002.0, 3000)]:
        s._on_sample(parse_lines(_conn_line(out), t))
    s.t_end = 1003.0
    s.write("20261107-120000-notes")
    for name in ("events.json", "flows.json", "timeline.json", "self_audit.json"):
        assert (s.run_dir / name).exists()


@pytest.mark.parametrize(
    "t,expected", [(1003.0, "startup"), (1030.0, "idle"), (1041.0, "user_action")]
)
def test_phase_rules(tmp_path, monkeypatch, t, expected):
    s = _session(tmp_path, monkeypatch)
    s.fresh_launch = True
    s.actions.append(UserAction(t=datetime.fromtimestamp(1040.0, UTC)))
    assert s.phase_at(t) == expected


def test_local_traffic_is_ignored(tmp_path, monkeypatch):
    """Electron apps move hundreds of MB between their own processes over localhost; not internet."""
    s = _session(tmp_path, monkeypatch)
    lines = ["Notes Helper.4312,0,0,", "tcp4 127.0.0.1:5000<->127.0.0.1:6000,900000000,900000000,"]
    for t in (1001.0, 1002.0):
        s._on_sample(parse_lines(lines, t))
    assert s.flows == {}
