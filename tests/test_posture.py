import unittest

from backend.app.posture import evaluate_assets, policy_catalog


class PosturePolicyTests(unittest.TestCase):
    def test_catalog_has_unique_policy_ids(self):
        catalog = policy_catalog()
        ids = [item["id"] for item in catalog]
        self.assertGreaterEqual(len(ids), 18)
        self.assertEqual(len(ids), len(set(ids)))

    def test_key_vault_policies_emit_individual_evidence(self):
        findings = evaluate_assets([{
            "id": "kv-1", "type": "key_vault", "source": "synthetic",
            "public_network_access_enabled": True,
            "soft_delete_enabled": False,
            "purge_protection_enabled": False,
            "firewall_default_action": "Allow",
        }])
        by_id = {item["policy_id"]: item for item in findings}
        self.assertEqual(set(by_id), {
            "key_vault_public_network", "key_vault_soft_delete_disabled",
            "key_vault_purge_protection_disabled", "key_vault_firewall_allow_all",
        })
        self.assertEqual(by_id["key_vault_public_network"]["severity"], "high")
        self.assertIn('"public_network_access_enabled": true', by_id["key_vault_public_network"]["evidence"])

    def test_sql_and_aks_checks(self):
        assets = [
            {"id": "sql", "type": "sql_server", "public_network_access_enabled": True,
             "minimum_tls_version": "TLS1_0", "aad_only_authentication": False},
            {"id": "db", "type": "sql_database", "transparent_data_encryption_enabled": False},
            {"id": "aks", "type": "aks_cluster", "private_cluster_enabled": False,
             "local_accounts_enabled": True, "network_policy": "none"},
        ]
        findings = evaluate_assets(assets)
        policy_ids = {item["policy_id"] for item in findings}
        self.assertTrue({
            "sql_server_public_network", "sql_server_weak_tls",
            "sql_server_aad_only_auth_disabled", "sql_database_tde_disabled",
            "aks_api_server_public", "aks_local_accounts_enabled",
            "aks_network_policy_missing",
        }.issubset(policy_ids))

    def test_nsg_only_flags_inbound_allow_from_public_source(self):
        findings = evaluate_assets([{
            "id": "nsg", "type": "network_security_group", "inbound_rules": [
                {"direction": "Outbound", "access": "Allow", "source": "*", "port": "22"},
                {"direction": "Inbound", "access": "Deny", "source": "*", "port": "3389"},
                {"direction": "Inbound", "access": "Allow", "source": "10.0.0.0/8", "port": "22"},
                {"direction": "Inbound", "access": "Allow", "source": "::/0", "port": "5985"},
            ],
        }])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["policy_id"], "nsg_broad_admin_ingress")

    def test_storage_tls_firewall_disk_vm_and_app_service(self):
        assets = [
            {"id": "storage", "type": "storage", "minimum_tls_version": "TLS1_0",
             "public_network_access_enabled": True, "network_default_action": "Allow"},
            {"id": "disk", "type": "managed_disk", "encryption_enabled": False},
            {"id": "vm", "type": "virtual_machine", "managed_identity_enabled": False},
            {"id": "app", "type": "app_service", "https_only": False,
             "minimum_tls_version": "1.1"},
        ]
        findings = evaluate_assets(assets)
        ids = {item["policy_id"] for item in findings}
        self.assertEqual(ids, {
            "storage_weak_tls", "storage_public_network_firewall",
            "disk_encryption_disabled", "vm_no_managed_identity",
            "app_service_https_only", "app_service_weak_tls",
        })
        severities = {item["policy_id"]: item["severity"] for item in findings}
        self.assertEqual(severities["disk_encryption_disabled"], "high")
        self.assertEqual(severities["storage_public_network_firewall"], "medium")

    def test_missing_values_are_unknown_not_findings(self):
        assets = [
            {"id": "storage-unknown", "type": "storage"},
            {"id": "kv-unknown", "type": "key_vault"},
            {"id": "vm-unknown", "type": "virtual_machine"},
        ]
        self.assertEqual(evaluate_assets(assets), [])

    def test_resource_graph_type_alias_is_supported(self):
        findings = evaluate_assets([{
            "id": "/subscriptions/demo/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/a",
            "type": "Microsoft.Storage/storageAccounts",
            "public_access": True,
            "source": "azure_resource_graph",
        }])
        self.assertEqual(findings[0]["resource_type"], "storage")
        self.assertEqual(findings[0]["source"], "azure_resource_graph")

    def test_ids_are_stable_for_asset_and_policy(self):
        asset = {"id": "stable", "type": "storage", "public_access": True}
        first = evaluate_assets([asset])[0]["id"]
        second = evaluate_assets([asset])[0]["id"]
        self.assertEqual(first, second)


if __name__ == "__main__":
    unittest.main()
