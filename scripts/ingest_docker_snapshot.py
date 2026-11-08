#!/usr/bin/env python3
"""Inspect running Docker containers (read-only) and alert on privileged ones."""
import json
from pathlib import Path
import socket
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from backend.app.db import init_db
from backend.app.runtime import privileged_container_event
from backend.app.siem import ingest


def main():
    ids = subprocess.run(["docker", "ps", "-q"], capture_output=True, text=True, check=False)
    if ids.returncode:
        raise SystemExit(ids.stderr.strip() or "Docker CLI/daemon unavailable; no data collected.")
    container_ids = [item for item in ids.stdout.splitlines() if item.strip()]
    if not container_ids:
        print("No running Docker containers; nothing to inspect.")
        return

    inspected = subprocess.run(
        ["docker", "inspect", *container_ids], capture_output=True, text=True, check=False
    )
    if inspected.returncode:
        raise SystemExit(inspected.stderr.strip() or "docker inspect failed; no data ingested.")
    try:
        containers = json.loads(inspected.stdout)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"docker inspect returned invalid JSON: {exc}") from exc

    init_db()
    count = 0
    for container in containers:
        event = privileged_container_event(container, host=socket.gethostname())
        if event:
            result = ingest(event)
            count += int(not result.get("duplicate", False))
    print(f"Inspected {len(containers)} running containers; ingested {count} privileged-container events.")


if __name__ == "__main__":
    main()
