import sqlite3
from contextlib import contextmanager
from pathlib import Path

from .config import DB


@contextmanager
def connect(path=None):
    database = Path(path or DB)
    database.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _columns(connection, table):
    return {row["name"] for row in connection.execute(f"PRAGMA table_info({table})")}


def init_db(path=None):
    """Create the local schema and apply small, backwards-compatible migrations."""
    with connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS findings(
                id TEXT PRIMARY KEY, asset_id TEXT, title TEXT, severity TEXT,
                category TEXT, description TEXT, recommendation TEXT,
                evidence TEXT, source TEXT, created_at TEXT,
                policy_id TEXT, resource_type TEXT,
                control_ids TEXT NOT NULL DEFAULT '[]'
            );
            CREATE TABLE IF NOT EXISTS events(
                id TEXT PRIMARY KEY, timestamp TEXT, source TEXT, event_type TEXT,
                severity TEXT, host TEXT, actor TEXT, message TEXT, raw_json TEXT,
                ingested_at TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts(
                id TEXT PRIMARY KEY, rule_id TEXT, title TEXT, severity TEXT,
                event_id TEXT, mitre TEXT, created_at TEXT,
                context TEXT NOT NULL DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS incidents(
                id TEXT PRIMARY KEY, title TEXT, severity TEXT, status TEXT,
                alert_ids TEXT, created_at TEXT
            );
            CREATE TABLE IF NOT EXISTS soar_runs(
                id TEXT PRIMARY KEY, playbook_id TEXT, status TEXT,
                approved INTEGER, dry_run INTEGER, result TEXT, created_at TEXT
            );
            """
        )

        # Existing 0.1 databases predate these fields. Keep them usable in place.
        finding_columns = _columns(connection, "findings")
        if "policy_id" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN policy_id TEXT")
        if "resource_type" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN resource_type TEXT")
        if "control_ids" not in finding_columns:
            connection.execute("ALTER TABLE findings ADD COLUMN control_ids TEXT NOT NULL DEFAULT '[]'")

        event_columns = _columns(connection, "events")
        if "ingested_at" not in event_columns:
            connection.execute("ALTER TABLE events ADD COLUMN ingested_at TEXT")
        connection.execute(
            "UPDATE events SET ingested_at=timestamp WHERE ingested_at IS NULL OR ingested_at=''"
        )

        alert_columns = _columns(connection, "alerts")
        if "context" not in alert_columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN context TEXT NOT NULL DEFAULT '{}' ")

        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_events_ingested_at ON events(ingested_at);
            CREATE INDEX IF NOT EXISTS idx_alerts_rule_created ON alerts(rule_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_findings_created ON findings(created_at);
            """
        )
