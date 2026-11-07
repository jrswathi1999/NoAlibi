"""Evidence hash is SHA-256 over claims.json + events.json + run.pcap, in that order."""

import hashlib
from pathlib import Path

import pytest

from engine.hashlog import evidence_sha256


def _write(d: Path, pcap: bytes | None = b"\xd4\xc3\xb2\xa1pcap") -> None:
    (d / "claims.json").write_bytes(b'{"c": 1}')
    (d / "events.json").write_bytes(b'{"e": 2}')
    if pcap is not None:
        (d / "run.pcap").write_bytes(pcap)


def test_hash_matches_concatenation(tmp_path: Path) -> None:
    _write(tmp_path)
    expected = hashlib.sha256(b'{"c": 1}' + b'{"e": 2}' + b"\xd4\xc3\xb2\xa1pcap").hexdigest()
    assert evidence_sha256(tmp_path) == expected


def test_hash_changes_when_evidence_changes(tmp_path: Path) -> None:
    _write(tmp_path)
    before = evidence_sha256(tmp_path)
    (tmp_path / "events.json").write_bytes(b'{"e": 3}')
    assert evidence_sha256(tmp_path) != before


def test_missing_pcap_is_allowed(tmp_path: Path) -> None:
    _write(tmp_path, pcap=None)
    assert evidence_sha256(tmp_path) == hashlib.sha256(b'{"c": 1}{"e": 2}').hexdigest()


def test_missing_claims_is_error(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="claims.json"):
        evidence_sha256(tmp_path)
