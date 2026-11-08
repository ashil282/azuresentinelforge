import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from backend.app import main, siem, soar
from backend.app.db import connect, init_db


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "api.db"
        init_db(self.db)
        self.patches = [
            patch.object(main, "init_db", lambda: init_db(self.db)),
            patch.object(main, "connect", lambda path=None: connect(self.db)),
            patch.object(siem, "connect", lambda path=None: connect(self.db)),
            patch.object(soar, "connect", lambda path=None: connect(self.db)),
        ]
        for item in self.patches:
            item.start()
        self.client = TestClient(main.app)

    def tearDown(self):
        self.client.close()
        for item in reversed(self.patches):
            item.stop()
        self.tmp.cleanup()

    def test_health_rules_and_summary(self):
        self.assertEqual(self.client.get("/health").json()["status"], "ok")
        self.assertGreaterEqual(len(self.client.get("/api/v1/rules").json()), 1)
        self.assertEqual(self.client.get("/api/v1/summary").json()["events"], 0)

    def test_posture_policy_catalog_and_evaluation(self):
        catalog = self.client.get("/api/v1/posture/policies")
        self.assertEqual(catalog.status_code, 200)
        self.assertGreaterEqual(len(catalog.json()), 18)
        response = self.client.post("/api/v1/posture/evaluate", json={
            "assets": [{
                "id": "api-kv", "type": "key_vault", "source": "synthetic",
                "public_network_access_enabled": True,
            }]
        })
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["data_label"], "synthetic")
        self.assertEqual(body["finding_count"], 1)
        self.assertEqual(body["findings"][0]["policy_id"], "key_vault_public_network")
        stored = self.client.get("/api/v1/findings").json()
        self.assertEqual(stored[0]["evidence"], {"public_network_access_enabled": True})

    def test_posture_evaluation_rejects_too_many_assets(self):
        response = self.client.post("/api/v1/posture/evaluate", json={"assets": [{}] * 10001})
        self.assertEqual(response.status_code, 422)

    def test_event_ingestion_and_duplicate(self):
        payload = {
            "id": "api-event", "event_type": "cloud_credential_access",
            "severity": "critical", "message": "synthetic API test",
        }
        first = self.client.post("/api/v1/events", json=payload)
        second = self.client.post("/api/v1/events", json=payload)
        self.assertEqual(first.status_code, 200)
        self.assertEqual(len(first.json()["alerts"]), 1)
        self.assertTrue(second.json()["duplicate"])
        self.assertEqual(len(self.client.get("/api/v1/alerts").json()), 1)

    def test_event_schema_rejects_invalid_severity(self):
        response = self.client.post("/api/v1/events", json={
            "event_type": "test", "severity": "emergency", "message": "bad"
        })
        self.assertEqual(response.status_code, 422)

    def test_live_soar_execution_is_rejected(self):
        response = self.client.post("/api/v1/soar/run", json={
            "playbook_id": "containment-preview", "approved": True, "dry_run": False
        })
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
