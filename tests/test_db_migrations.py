import sqlite3
import tempfile
import unittest
from pathlib import Path

from backend.app.db import connect, init_db


class MigrationTests(unittest.TestCase):
    def test_legacy_findings_table_gets_policy_metadata_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy-findings.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE findings(
                    id TEXT PRIMARY KEY,asset_id TEXT,title TEXT,severity TEXT,
                    category TEXT,description TEXT,recommendation TEXT,evidence TEXT,
                    source TEXT,created_at TEXT
                );
                INSERT INTO findings VALUES('old-finding','asset','Old','low','test','desc','fix','{}','fixture','2026-11-07T10:00:00+00:00');
                """
            )
            connection.commit()
            connection.close()
            init_db(path)
            with connect(path) as migrated:
                row = migrated.execute("SELECT * FROM findings WHERE id='old-finding'").fetchone()
                self.assertEqual(row["policy_id"], None)
                self.assertEqual(row["resource_type"], None)
                self.assertEqual(row["control_ids"], "[]")
                self.assertEqual(migrated.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 1)

    def test_legacy_01_database_is_migrated_without_losing_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            connection = sqlite3.connect(path)
            connection.executescript(
                """
                CREATE TABLE events(
                    id TEXT PRIMARY KEY,timestamp TEXT,source TEXT,event_type TEXT,
                    severity TEXT,host TEXT,actor TEXT,message TEXT,raw_json TEXT
                );
                CREATE TABLE alerts(
                    id TEXT PRIMARY KEY,rule_id TEXT,title TEXT,severity TEXT,
                    event_id TEXT,mitre TEXT,created_at TEXT
                );
                INSERT INTO events VALUES('old-event','2026-11-07T10:00:00+00:00','fixture','test','low',NULL,NULL,'old row','{}');
                INSERT INTO alerts VALUES('old-alert','old-rule','Old alert','low','old-event','[]','2026-11-07T10:00:01+00:00');
                """
            )
            connection.commit()
            connection.close()

            init_db(path)
            with connect(path) as migrated:
                event = migrated.execute("SELECT * FROM events WHERE id='old-event'").fetchone()
                alert = migrated.execute("SELECT * FROM alerts WHERE id='old-alert'").fetchone()
                self.assertEqual(event["ingested_at"], event["timestamp"])
                self.assertEqual(alert["context"], "{}")
                self.assertEqual(migrated.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
