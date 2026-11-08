import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from backend.app.db import connect, init_db
from backend.app.posture import evaluate_assets
from backend.app.runtime import parse_linux_auth_line, privileged_container_event
from backend.app.siem import ingest, rules
from backend.app.soar import run


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "x.db"
        init_db(self.db)

    def tearDown(self):
        self.tmp.cleanup()

    def test_storage_rules(self):
        findings = evaluate_assets([
            {"id": "s", "type": "storage", "public_access": True, "https_only": False}
        ])
        self.assertEqual({item["severity"] for item in findings}, {"critical", "high"})

    def test_nsg_rule(self):
        findings = evaluate_assets([{
            "id": "n", "type": "network_security_group",
            "inbound_rules": [{"source": "*", "port": "3389"}],
        }])
        self.assertEqual(findings[0]["severity"], "high")

    def test_siem_alert_incident(self):
        result = ingest({"id": "evt", "event_type": "cloud_credential_access", "message": "fixture"}, self.db)
        self.assertEqual(result["alerts"][0]["severity"], "critical")
        with connect(self.db) as connection:
            self.assertEqual(connection.execute("select count(*) from incidents").fetchone()[0], 1)

    def test_no_alert_for_benign(self):
        result = ingest({"id": "benign", "event_type": "normal", "message": "ok"}, self.db)
        self.assertEqual(result["alerts"], [])

    def test_duplicate_event_is_idempotent(self):
        payload = {"id": "once", "event_type": "cloud_credential_access", "message": "fixture"}
        first = ingest(payload, self.db)
        second = ingest(payload, self.db)
        self.assertEqual(len(first["alerts"]), 1)
        self.assertTrue(second["duplicate"])
        self.assertEqual(second["alerts"], [])
        with connect(self.db) as connection:
            self.assertEqual(connection.execute("select count(*) from alerts").fetchone()[0], 1)

    def test_invalid_event_rejected(self):
        with self.assertRaisesRegex(ValueError, "severity"):
            ingest({"event_type": "test", "severity": "urgent", "message": "bad"}, self.db)
        with self.assertRaisesRegex(ValueError, "ISO-8601"):
            ingest({"event_type": "test", "timestamp": "yesterday", "message": "bad"}, self.db)

    def test_ssh_correlation_threshold_and_suppression(self):
        start = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        for index in range(4):
            result = ingest({
                "id": f"ssh-{index}", "event_type": "authentication_failure",
                "actor": "sshd", "host": "node-a", "message": "failed password",
            }, self.db, now=start.replace(second=index))
            self.assertFalse(any(item["rule_id"] == "ssh_brute_force" for item in result["alerts"]))
        fifth = ingest({
            "id": "ssh-4", "event_type": "authentication_failure", "actor": "sshd",
            "host": "node-a", "message": "failed password",
        }, self.db, now=start.replace(second=4))
        correlated = [item for item in fifth["alerts"] if item["rule_id"] == "ssh_brute_force"]
        self.assertEqual(len(correlated), 1)
        self.assertEqual(correlated[0]["context"]["match_count"], 5)
        sixth = ingest({
            "id": "ssh-5", "event_type": "authentication_failure", "actor": "sshd",
            "host": "node-a", "message": "failed password",
        }, self.db, now=start.replace(second=5))
        self.assertFalse(any(item["rule_id"] == "ssh_brute_force" for item in sixth["alerts"]))

    def test_ssh_correlation_is_grouped_by_host(self):
        start = datetime(2026, 11, 8, 9, 0, tzinfo=timezone.utc)
        for index in range(5):
            ingest({
                "id": f"host-a-{index}", "event_type": "authentication_failure",
                "actor": "sshd", "host": "node-a", "message": "failed",
            }, self.db, now=start.replace(second=index))
        result = ingest({
            "id": "host-b-1", "event_type": "authentication_failure", "actor": "sshd",
            "host": "node-b", "message": "failed",
        }, self.db, now=start.replace(second=6))
        self.assertFalse(any(item["rule_id"] == "ssh_brute_force" for item in result["alerts"]))

    def test_rule_files_load_and_validate(self):
        self.assertIn("ssh_brute_force", {rule["id"] for rule in rules()})

    def test_linux_auth_parser(self):
        event = parse_linux_auth_line(
            "Nov  8 09:00:00 lab sshd[123]: Failed password for invalid user admin from 203.0.113.8 port 22 ssh2",
            host="lab",
        )
        self.assertEqual(event["event_type"], "authentication_failure")
        self.assertEqual(event["attributes"]["source_ip"], "203.0.113.8")
        self.assertIsNone(parse_linux_auth_line("Nov  8 09:00:00 lab systemd: Started session"))

    def test_privileged_container_parser(self):
        event = privileged_container_event({
            "Id": "abc", "Name": "/demo", "HostConfig": {"Privileged": True},
            "Config": {"Image": "demo:latest"},
        }, host="docker-host")
        self.assertEqual(event["event_type"], "container_started_privileged")
        self.assertIsNone(privileged_container_event({"HostConfig": {"Privileged": False}}))

    def test_soar_dry_run_and_gate(self):
        result = run("containment-preview", db_path=self.db)
        self.assertEqual(result["status"], "awaiting_approval")
        self.assertTrue(result["dry_run"])

    def test_soar_approval_records_preview_only(self):
        result = run("containment-preview", approved=True, db_path=self.db)
        self.assertEqual(result["status"], "approved_preview")
        self.assertEqual(result["result"]["execution"], "not_implemented")
        self.assertIn("No external action", result["result"]["notice"])

    def test_soar_rejects_live_action(self):
        with self.assertRaises(ValueError):
            run("containment-preview", approved=True, dry_run=False, db_path=self.db)


if __name__ == "__main__":
    unittest.main()
