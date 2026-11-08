from datetime import datetime, timezone
import json
import uuid

from .db import connect

PLAYBOOKS = {
    "triage-suspicious-login": {
        "name": "Triage suspicious login",
        "steps": [
            "Collect sign-in context",
            "Review MFA and geography",
            "Prepare analyst checklist",
        ],
    },
    "containment-preview": {
        "name": "Containment preview",
        "steps": [
            "Preview host isolation request",
            "Preview token revocation request",
            "Require operator action outside this tool",
        ],
    },
}


def run(playbook_id, approved=False, dry_run=True, db_path=None):
    if playbook_id not in PLAYBOOKS:
        raise KeyError(playbook_id)
    if not dry_run:
        raise ValueError("Only dry_run=true is supported; no remediation executor exists.")

    playbook = PLAYBOOKS[playbook_id]
    result = {
        "name": playbook["name"],
        "steps": playbook["steps"],
        "execution": "not_implemented",
        "notice": "Simulation only. No external action was performed.",
    }
    run_id = str(uuid.uuid4())
    status = "approved_preview" if approved else "awaiting_approval"
    created_at = datetime.now(timezone.utc).isoformat()

    with connect(db_path) as connection:
        connection.execute(
            "INSERT INTO soar_runs VALUES (?,?,?,?,?,?,?)",
            (run_id, playbook_id, status, int(approved), 1, json.dumps(result), created_at),
        )

    return {
        "id": run_id,
        "playbook_id": playbook_id,
        "status": status,
        "approved": approved,
        "dry_run": True,
        "result": result,
    }
