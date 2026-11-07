"""Start No Alibi:  python -m app   (opens http://127.0.0.1:5050)."""

from __future__ import annotations

import argparse
import logging
import os
import threading
import webbrowser
from pathlib import Path


def load_env(path: Path) -> None:
    """Minimal .env loader (KEY=VALUE lines) so API keys never need to be exported by hand."""
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            if value.strip():
                os.environ.setdefault(key.strip(), value.strip())


def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="No Alibi local UI")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    load_env(Path(__file__).resolve().parent.parent / ".env")
    logging.basicConfig(level=logging.INFO, format="%(name)s: %(message)s")
    url = f"http://127.0.0.1:{args.port}"
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
    print(f"No Alibi is running at {url}  (local only; Ctrl+C to quit)")
    uvicorn.run("app.server:app", host="127.0.0.1", port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
