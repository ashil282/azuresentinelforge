#!/usr/bin/env python3
"""Read recent Linux auth-log lines and ingest normalized events locally."""
import argparse
from collections import deque
from pathlib import Path
import socket
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.db import init_db
from backend.app.runtime import parse_linux_auth_line
from backend.app.siem import ingest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--path", default="/var/log/auth.log")
    parser.add_argument("--limit", type=int, default=1000, help="maximum recent lines to inspect")
    args = parser.parse_args()
    if not 1 <= args.limit <= 100000:
        parser.error("--limit must be between 1 and 100000")
    path = Path(args.path)
    if not path.is_file():
        raise SystemExit(f"Auth log not found: {path}; on some systems use /var/log/secure")

    init_db()
    host = socket.gethostname()
    events = 0
    with path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in deque(stream, maxlen=args.limit):
            event = parse_linux_auth_line(line, host=host)
            if event:
                result = ingest(event)
                events += int(not result.get("duplicate", False))
    print(f"Ingested {events} normalized events from {path} into the local SQLite database.")


if __name__ == "__main__":
    main()
