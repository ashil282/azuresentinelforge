#!/usr/bin/env python3
"""Collect and normalize Azure Resource Graph inventory using read-only queries.

The optional Azure SDK is imported only when the collector is executed. The
normalizer is dependency-free so its mapping can be tested with fixtures.
"""
import argparse
import json
import os
from pathlib import Path


def _get(mapping, *path):
    current = mapping
    for key in path:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _enabled(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"enabled", "true", "yes", "on"}:
            return True
        if normalized in {"disabled", "false", "no", "off"}:
            return False
    return None


def _normalize_nsg_rules(properties):
    output = []
    for rule in properties.get("securityRules") or []:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("direction", "")).lower() != "inbound":
            continue
        if str(rule.get("access", "")).lower() != "allow":
            continue
        output.append({
            "name": rule.get("name"),
            "direction": rule.get("direction"),
            "access": rule.get("access"),
            "source": rule.get("sourceAddressPrefixes") or rule.get("sourceAddressPrefix"),
            "port": rule.get("destinationPortRanges") or rule.get("destinationPortRange"),
        })
    return output


def normalize_resource(resource):
    """Map a Resource Graph resource to the CSPM's canonical asset shape.

    Returns None for resource types not yet covered. Unknown properties remain
    None so posture checks never infer a secure or insecure state from absence.
    """
    if not isinstance(resource, dict):
        return None
    resource_type = str(resource.get("type") or "").lower()
    properties = resource.get("properties") or {}
    if not isinstance(properties, dict):
        properties = {}
    identity = resource.get("identity") or {}
    if not isinstance(identity, dict):
        identity = {}
    asset = {
        "id": resource.get("id") or resource.get("name") or "unknown",
        "name": resource.get("name"),
        "type": None,
        "location": resource.get("location"),
        "subscription_id": resource.get("subscriptionId"),
        "source": "azure_resource_graph",
    }

    if resource_type == "microsoft.storage/storageaccounts":
        asset.update({
            "type": "storage",
            "public_access": properties.get("allowBlobPublicAccess"),
            "https_only": properties.get("supportsHttpsTrafficOnly"),
            "minimum_tls_version": properties.get("minimumTlsVersion"),
            "public_network_access_enabled": _enabled(properties.get("publicNetworkAccess")),
            "network_default_action": _get(properties, "networkAcls", "defaultAction"),
        })
    elif resource_type == "microsoft.network/networksecuritygroups":
        asset.update({"type": "network_security_group", "inbound_rules": _normalize_nsg_rules(properties)})
    elif resource_type == "microsoft.compute/disks":
        encryption_type = _get(properties, "encryption", "type")
        encryption_settings = _get(properties, "encryptionSettingsCollection", "enabled")
        encrypted = True if encryption_type else _enabled(encryption_settings)
        asset.update({"type": "managed_disk", "encryption_enabled": encrypted})
    elif resource_type == "microsoft.compute/virtualmachines":
        identity_type = identity.get("type")
        if "identity" not in resource:
            managed_identity = None
        else:
            managed_identity = bool(identity_type and str(identity_type).strip().lower() not in {"", "none"})
        asset.update({"type": "virtual_machine", "managed_identity_enabled": managed_identity})
    elif resource_type == "microsoft.keyvault/vaults":
        asset.update({
            "type": "key_vault",
            "public_network_access_enabled": _enabled(properties.get("publicNetworkAccess")),
            "soft_delete_enabled": _enabled(properties.get("enableSoftDelete")),
            "purge_protection_enabled": _enabled(properties.get("enablePurgeProtection")),
            "rbac_authorization_enabled": _enabled(properties.get("enableRbacAuthorization")),
            "firewall_default_action": _get(properties, "networkAcls", "defaultAction"),
        })
    elif resource_type == "microsoft.sql/servers":
        asset.update({
            "type": "sql_server",
            "public_network_access_enabled": _enabled(properties.get("publicNetworkAccess")),
            "minimum_tls_version": properties.get("minimalTlsVersion"),
            "aad_only_authentication": _enabled(_get(properties, "administrators", "azureADOnlyAuthentication")),
        })
    elif resource_type in {
        "microsoft.sql/servers/databases",
        "microsoft.sql/servers/databases/transparentdataencryption",
    }:
        tde_state = _get(properties, "transparentDataEncryption", "state")
        if tde_state is None and resource_type.endswith("/transparentdataencryption"):
            tde_state = properties.get("state")
        tde_enabled = None if tde_state is None else str(tde_state).lower() == "enabled"
        asset.update({"type": "sql_database", "transparent_data_encryption_enabled": tde_enabled})
    elif resource_type == "microsoft.containerservice/managedclusters":
        private_cluster = _get(properties, "apiServerAccessProfile", "enablePrivateCluster")
        disable_local = _enabled(properties.get("disableLocalAccounts"))
        network_policy = _get(properties, "networkProfile", "networkPolicy")
        asset.update({
            "type": "aks_cluster",
            "private_cluster_enabled": _enabled(private_cluster),
            "local_accounts_enabled": None if disable_local is None else not disable_local,
            "network_policy": network_policy,
            "network_policy_enabled": None if network_policy is None else str(network_policy).lower() not in {"", "none", "disabled"},
        })
    elif resource_type == "microsoft.web/sites":
        asset.update({
            "type": "app_service",
            "https_only": _enabled(properties.get("httpsOnly")),
            "minimum_tls_version": _get(properties, "siteConfig", "minTlsVersion"),
            "public_network_access_enabled": _enabled(properties.get("publicNetworkAccess")),
        })
    else:
        return None
    return asset


def normalize_inventory(resources):
    assets = []
    skipped = 0
    for resource in resources:
        asset = normalize_resource(resource)
        if asset is None:
            skipped += 1
        else:
            assets.append(asset)
    return {
        "data_label": "live_read_only",
        "count": len(assets),
        "skipped_unmapped_resources": skipped,
        "assets": assets,
        "query_scope": "Azure Resource Graph read-only inventory; no resource writes",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=500, help="maximum Resource Graph rows (1-1000)")
    parser.add_argument("--output", type=Path, help="write normalized JSON inventory to this local file")
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")

    subscription = os.getenv("AZURE_SUBSCRIPTION_ID")
    if not subscription:
        raise SystemExit("Set AZURE_SUBSCRIPTION_ID after az login; no Azure query was made.")

    try:
        from azure.identity import DefaultAzureCredential
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest
    except ImportError as exc:
        raise SystemExit(
            "Azure SDK dependencies are optional. Install with: "
            "pip install -r backend/requirements-azure.txt"
        ) from exc

    client = ResourceGraphClient(DefaultAzureCredential())
    query = (
        "Resources | project id,name,type,location,subscriptionId,properties,identity "
        f"| limit {args.limit}"
    )
    request = QueryRequest(subscriptions=[subscription], query=query)
    response = client.resources(request)
    result = normalize_inventory(response.data or [])
    result["subscription_id"] = subscription
    result["query_limit"] = args.limit
    rendered = json.dumps(result, default=str, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {result['count']} normalized live assets to {args.output}; "
              f"skipped {result['skipped_unmapped_resources']} unmapped resources.")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
