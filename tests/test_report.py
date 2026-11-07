"""The fixtures render into a report that links findings to claims and events."""

import shutil
from pathlib import Path

import pytest

from report.render import render

FIXTURES = Path(__file__).resolve().parent.parent / "contracts" / "fixtures"


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "20261107-201500-notesapp"
    d.mkdir()
    for name in ("claims", "events", "findings"):
        shutil.copy(FIXTURES / f"{name}.sample.json", d / f"{name}.json")
    return d


def test_render_fixture(run_dir: Path) -> None:
    html = render(run_dir).read_text(encoding="utf-8")
    assert "<h1>NotesApp</h1>" in html
    assert "2 red · 3 amber" in html
    assert "Policy never names OpenAI, but the app sent 12 KB to api.openai.com" in html
    assert 'id="claim-c1"' in html and 'id="event-e4"' in html
    assert 'data-claims="c1" data-events="e4"' in html
    assert "We may share information with trusted service providers." in html
    assert "Only domain names left this machine." in html  # no log -> no count


def test_red_wins_over_amber_for_highlight(run_dir: Path) -> None:
    html = render(run_dir).read_text(encoding="utf-8")
    # e4 is referenced by red and amber findings; the row must be red.
    assert '<tr id="event-e4" class="sev-red">' in html
    assert '<tr id="event-e6" class="sev-amber">' in html


def test_outbound_count_in_footer(run_dir: Path) -> None:
    (run_dir / "outbound_queries.log").write_text(
        "NotesApp privacy policy\ncdn.xyz-metrics.io\n", encoding="utf-8"
    )
    html = render(run_dir).read_text(encoding="utf-8")
    assert "(2 outbound queries)" in html


def test_html_is_escaped(run_dir: Path) -> None:
    claims = run_dir / "claims.json"
    claims.write_text(
        claims.read_text(encoding="utf-8").replace(
            "trusted service providers", "<script>x</script>"
        ),
        encoding="utf-8",
    )
    html = render(run_dir).read_text(encoding="utf-8")
    assert "<script>x</script>" not in html


def test_missing_findings_is_clear_error(run_dir: Path) -> None:
    (run_dir / "findings.json").unlink()
    with pytest.raises(ValueError, match="findings.json"):
        render(run_dir)
