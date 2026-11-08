import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from backend.app.db import connect, init_db
from backend.app.posture import evaluate_assets
from backend.app.siem import ingest


def main():
    init_db()
    inventory = json.loads((ROOT / "fixtures/azure_inventory.json").read_text(encoding="utf-8"))
    assets = inventory["assets"]
    if inventory.get("data_label") != "synthetic" or any(asset.get("source") != "synthetic" for asset in assets):
        raise SystemExit("Refusing to load fixtures that are not explicitly labelled synthetic.")

    findings = evaluate_assets(assets)
    with connect() as connection:
        for finding in findings:
            connection.execute(
                """INSERT OR REPLACE INTO findings
                (id,asset_id,title,severity,category,description,recommendation,evidence,
                 source,created_at,policy_id,resource_type,control_ids)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                tuple(finding[key] for key in (
                    "id", "asset_id", "title", "severity", "category", "description",
                    "recommendation", "evidence", "source", "created_at", "policy_id",
                    "resource_type", "control_ids",
                )),
            )

    ingested = duplicates = alert_count = 0
    fixture_events = ROOT / "fixtures/security_events.jsonl"
    for line in fixture_events.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        result = ingest(json.loads(line))
        duplicates += int(result.get("duplicate", False))
        ingested += int(not result.get("duplicate", False))
        alert_count += len(result["alerts"])

    print(
        f"Loaded {len(assets)} synthetic assets; stored {len(findings)} posture findings; "
        f"ingested {ingested} events ({duplicates} duplicate fixture IDs skipped); "
        f"created {alert_count} alerts."
    )


if __name__ == "__main__":
    main()
