"""SHA-256 over the evidence files: claims.json, events.json, run.pcap and sensor.log, in that order.

run.pcap comes from the sandbox capture and sensor.log from the no-sandbox per-process sensor;
whichever exists is included.

Anyone holding the same three files can recompute the hash shown in the report footer.

CLI:  python -m engine.hashlog --run-dir data/runs/<run_id>
"""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

log = logging.getLogger("engine.hashlog")

EVIDENCE_FILES = ("claims.json", "events.json", "run.pcap", "sensor.log")
REQUIRED = {"claims.json", "events.json"}
CHUNK = 1 << 20


def evidence_sha256(run_dir: str | Path) -> str:
    """Hash the evidence files in order. run.pcap / sensor.log may be missing; that is logged.

    Raises ValueError if claims.json or events.json is missing.
    """
    run_dir = Path(run_dir)
    digest = hashlib.sha256()
    for name in EVIDENCE_FILES:
        path = run_dir / name
        if not path.exists():
            if name in REQUIRED:
                raise ValueError(f"{path} not found, cannot hash evidence")
            log.info("%s missing, hashing without it", path)
            continue
        with path.open("rb") as fh:
            while chunk := fh.read(CHUNK):
                digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the evidence SHA-256 for a run.")
    parser.add_argument("--run-dir", required=True, type=Path)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    try:
        print(evidence_sha256(args.run_dir))
    except ValueError as exc:
        log.error("%s", exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
