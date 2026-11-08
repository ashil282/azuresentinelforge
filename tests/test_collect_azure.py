import unittest

from scripts.collect_azure import normalize_inventory, normalize_resource


class AzureNormalizerTests(unittest.TestCase):
    def test_storage_resource_maps_policy_inputs(self):
        asset = normalize_resource({
            "id": "/subscriptions/x/storageAccounts/demo",
            "name": "demo", "type": "Microsoft.Storage/storageAccounts",
            "location": "eastus", "subscriptionId": "x",
            "properties": {
                "allowBlobPublicAccess": True,
                "supportsHttpsTrafficOnly": False,
                "minimumTlsVersion": "TLS1_0",
                "publicNetworkAccess": "Enabled",
                "networkAcls": {"defaultAction": "Allow"},
            },
        })
        self.assertEqual(asset["type"], "storage")
        self.assertTrue(asset["public_access"])
        self.assertFalse(asset["https_only"])
        self.assertEqual(asset["minimum_tls_version"], "TLS1_0")
        self.assertTrue(asset["public_network_access_enabled"])

    def test_nsg_only_keeps_inbound_allow_rules(self):
        asset = normalize_resource({
            "id": "nsg", "type": "Microsoft.Network/networkSecurityGroups",
            "properties": {"securityRules": [
                {"name": "ssh", "direction": "Inbound", "access": "Allow",
                 "sourceAddressPrefix": "Internet", "destinationPortRange": "22"},
                {"name": "out", "direction": "Outbound", "access": "Allow",
                 "sourceAddressPrefix": "*", "destinationPortRange": "*"},
            ]},
        })
        self.assertEqual(len(asset["inbound_rules"]), 1)
        self.assertEqual(asset["inbound_rules"][0]["source"], "Internet")

    def test_aks_boolean_mapping_handles_string_values(self):
        asset = normalize_resource({
            "id": "aks", "type": "Microsoft.ContainerService/managedClusters",
            "properties": {
                "apiServerAccessProfile": {"enablePrivateCluster": "false"},
                "disableLocalAccounts": "false",
                "networkProfile": {"networkPolicy": "none"},
            },
        })
        self.assertFalse(asset["private_cluster_enabled"])
        self.assertTrue(asset["local_accounts_enabled"])
        self.assertFalse(asset["network_policy_enabled"])

    def test_unknown_resource_is_counted_as_skipped(self):
        result = normalize_inventory([{"id": "x", "type": "Microsoft.Compute/snapshots"}])
        self.assertEqual(result["count"], 0)
        self.assertEqual(result["skipped_unmapped_resources"], 1)
        self.assertEqual(result["data_label"], "live_read_only")

    def test_vm_null_identity_is_explicitly_no_managed_identity(self):
        asset = normalize_resource({
            "id": "vm", "type": "Microsoft.Compute/virtualMachines", "identity": None,
        })
        self.assertFalse(asset["managed_identity_enabled"])

    def test_sql_tde_child_resource_maps_state(self):
        asset = normalize_resource({
            "id": "sql/db/default", "type": "Microsoft.Sql/servers/databases/transparentDataEncryption",
            "properties": {"state": "Disabled"},
        })
        self.assertEqual(asset["type"], "sql_database")
        self.assertFalse(asset["transparent_data_encryption_enabled"])

    def test_absent_property_stays_unknown(self):
        asset = normalize_resource({"id": "kv", "type": "Microsoft.KeyVault/vaults", "properties": {}})
        self.assertIsNone(asset["public_network_access_enabled"])
        self.assertIsNone(asset["soft_delete_enabled"])


if __name__ == "__main__":
    unittest.main()
