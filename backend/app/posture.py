"""Evidence-backed, conservative Azure CSPM checks.

The evaluator only raises a finding when a risky setting is explicitly present.
Missing fields are treated as unknown, not compliant or non-compliant.
"""
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re


TYPE_ALIASES = {
    "storage": "storage",
    "microsoft.storage/storageaccounts": "storage",
    "network_security_group": "network_security_group",
    "microsoft.network/networksecuritygroups": "network_security_group",
    "managed_disk": "managed_disk",
    "microsoft.compute/disks": "managed_disk",
    "virtual_machine": "virtual_machine",
    "microsoft.compute/virtualmachines": "virtual_machine",
    "key_vault": "key_vault",
    "microsoft.keyvault/vaults": "key_vault",
    "sql_server": "sql_server",
    "microsoft.sql/servers": "sql_server",
    "sql_database": "sql_database",
    "microsoft.sql/servers/databases": "sql_database",
    "aks_cluster": "aks_cluster",
    "microsoft.containerservice/managedclusters": "aks_cluster",
    "app_service": "app_service",
    "microsoft.web/sites": "app_service",
}


def _bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "enabled", "on", "1"}:
            return True
        if normalized in {"false", "no", "disabled", "off", "0"}:
            return False
    return None


def _enabled(value):
    parsed = _bool(value)
    if parsed is not None:
        return parsed
    if isinstance(value, str):
        return value.strip().lower() in {"enabled", "allow", "allowed"}
    return None


def _tls_below_12(value):
    if not isinstance(value, str) or not value.strip():
        return False
    match = re.search(r"(\d+)\s*[._]\s*(\d+)", value.lower().replace("tls", ""))
    if not match:
        return False
    return (int(match.group(1)), int(match.group(2))) < (1, 2)


def _values(value):
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [] if value is None else [str(value)]


def _is_public_source(value):
    for item in _values(value):
        normalized = item.strip().lower()
        if normalized in {"*", "internet", "any", "0.0.0.0/0", "::/0"}:
            return True
        try:
            if ipaddress.ip_network(normalized, strict=False).prefixlen == 0:
                return True
        except ValueError:
            continue
    return False


ADMIN_PORTS = {"22", "3389", "1433", "3306", "5432", "5985", "5986", "2375", "2376", "6443"}


def _exposes_admin_port(value):
    for item in _values(value):
        normalized = item.strip().lower()
        if normalized in {"*", "any", "0-65535", "1-65535"}:
            return True
        if normalized in ADMIN_PORTS:
            return True
        match = re.fullmatch(r"(\d+)\s*-\s*(\d+)", normalized)
        if match:
            low, high = map(int, match.groups())
            if any(low <= int(port) <= high for port in ADMIN_PORTS):
                return True
    return False


def _nsg_exposure(asset):
    for rule in asset.get("inbound_rules") or []:
        if not isinstance(rule, dict):
            continue
        direction = str(rule.get("direction", "Inbound")).lower()
        access = str(rule.get("access", "Allow")).lower()
        if direction != "inbound" or access != "allow":
            continue
        source = rule.get("source")
        if source is None:
            source = rule.get("source_address_prefix", rule.get("sourceAddressPrefix"))
        if source is None:
            source = rule.get("sourceAddressPrefixes") or rule.get("source_address_prefixes")
        port = rule.get("port")
        if port is None:
            port = rule.get("destination_port_range", rule.get("destinationPortRange"))
        if port is None:
            port = rule.get("destinationPortRanges") or rule.get("destination_port_ranges")
        if _is_public_source(source) and _exposes_admin_port(port):
            return {
                "rule_name": rule.get("name"),
                "source": source,
                "destination_port": port,
                "direction": direction,
                "access": access,
            }
    return None


def _canonical_type(asset):
    raw = asset.get("type") or asset.get("resource_type") or "unknown"
    return TYPE_ALIASES.get(str(raw).strip().lower(), str(raw).strip().lower())


# The catalog is intentionally explicit. Control-framework crosswalks are left
# empty until each mapping can be checked against a pinned benchmark revision.
POLICIES = [
    {
        "id": "storage_public_blob_access",
        "title": "Storage permits public blob access",
        "resource_types": ["storage"],
        "severity": "critical",
        "category": "storage",
        "description": "Anonymous public blob access is enabled at the storage-account level.",
        "recommendation": "Disable public blob access unless a documented exception requires it; review containers for unintended exposure.",
        "framework_mappings": [],
    },
    {
        "id": "storage_https_only",
        "title": "Storage does not require HTTPS",
        "resource_types": ["storage"],
        "severity": "high",
        "category": "transport",
        "description": "Secure transfer is not required for the storage account.",
        "recommendation": "Enable secure transfer required and verify clients use TLS.",
        "framework_mappings": [],
    },
    {
        "id": "storage_weak_tls",
        "title": "Storage permits TLS below 1.2",
        "resource_types": ["storage"],
        "severity": "high",
        "category": "transport",
        "description": "The configured minimum TLS version is lower than TLS 1.2.",
        "recommendation": "Set the minimum TLS version to TLS 1.2 or newer and validate client compatibility.",
        "framework_mappings": [],
    },
    {
        "id": "storage_public_network_firewall",
        "title": "Storage public network access has an allow-all default",
        "resource_types": ["storage"],
        "severity": "medium",
        "category": "network",
        "description": "Public network access is enabled while the storage firewall default action is Allow.",
        "recommendation": "Disable public network access or change the network default action to Deny and add required trusted networks.",
        "framework_mappings": [],
    },
    {
        "id": "nsg_broad_admin_ingress",
        "title": "Administrative port exposed to the internet",
        "resource_types": ["network_security_group"],
        "severity": "high",
        "category": "network",
        "description": "An inbound allow rule exposes a common administrative or database port to any IPv4/IPv6 source.",
        "recommendation": "Restrict source ranges, remove unused rules and prefer private access or a managed bastion.",
        "framework_mappings": [],
    },
    {
        "id": "disk_encryption_disabled",
        "title": "Managed disk encryption is reported disabled",
        "resource_types": ["managed_disk"],
        "severity": "high",
        "category": "encryption",
        "description": "The inventory explicitly reports that disk encryption is disabled.",
        "recommendation": "Verify the disk encryption configuration and enable supported platform or customer-managed encryption.",
        "framework_mappings": [],
    },
    {
        "id": "vm_no_managed_identity",
        "title": "Virtual machine has no managed identity",
        "resource_types": ["virtual_machine"],
        "severity": "medium",
        "category": "identity",
        "description": "The inventory explicitly reports no system- or user-assigned managed identity.",
        "recommendation": "Prefer a managed identity for Azure service access instead of embedded credentials where supported.",
        "framework_mappings": [],
    },
    {
        "id": "key_vault_public_network",
        "title": "Key Vault public network access is enabled",
        "resource_types": ["key_vault"],
        "severity": "high",
        "category": "network",
        "description": "The Key Vault accepts public network connectivity.",
        "recommendation": "Disable public network access or enforce a deny-by-default firewall with approved private connectivity.",
        "framework_mappings": [],
    },
    {
        "id": "key_vault_soft_delete_disabled",
        "title": "Key Vault soft delete is disabled",
        "resource_types": ["key_vault"],
        "severity": "high",
        "category": "resilience",
        "description": "The inventory explicitly reports Key Vault soft delete disabled.",
        "recommendation": "Enable soft delete and validate retention requirements before changing vault settings.",
        "framework_mappings": [],
    },
    {
        "id": "key_vault_purge_protection_disabled",
        "title": "Key Vault purge protection is disabled",
        "resource_types": ["key_vault"],
        "severity": "medium",
        "category": "resilience",
        "description": "The inventory explicitly reports purge protection disabled.",
        "recommendation": "Enable purge protection to reduce the risk of permanent deletion during the retention period.",
        "framework_mappings": [],
    },
    {
        "id": "key_vault_firewall_allow_all",
        "title": "Key Vault firewall default action is Allow",
        "resource_types": ["key_vault"],
        "severity": "medium",
        "category": "network",
        "description": "The Key Vault has public network access enabled and its firewall default action is Allow.",
        "recommendation": "Use a deny-by-default network ACL and explicitly allow required trusted networks.",
        "framework_mappings": [],
    },
    {
        "id": "sql_server_public_network",
        "title": "SQL server public network access is enabled",
        "resource_types": ["sql_server"],
        "severity": "high",
        "category": "network",
        "description": "The Azure SQL logical server accepts public network connectivity.",
        "recommendation": "Disable public network access where possible and use private endpoints with tightly scoped access.",
        "framework_mappings": [],
    },
    {
        "id": "sql_server_weak_tls",
        "title": "SQL server permits TLS below 1.2",
        "resource_types": ["sql_server"],
        "severity": "high",
        "category": "transport",
        "description": "The configured minimum TLS version is lower than TLS 1.2.",
        "recommendation": "Set the minimum TLS version to 1.2 and verify application compatibility.",
        "framework_mappings": [],
    },
    {
        "id": "sql_server_aad_only_auth_disabled",
        "title": "SQL server does not enforce Microsoft Entra-only authentication",
        "resource_types": ["sql_server"],
        "severity": "medium",
        "category": "identity",
        "description": "The inventory explicitly reports SQL authentication is not restricted to Microsoft Entra-only authentication.",
        "recommendation": "Assess application compatibility and consider enabling Microsoft Entra-only authentication.",
        "framework_mappings": [],
    },
    {
        "id": "sql_database_tde_disabled",
        "title": "SQL database transparent data encryption is disabled",
        "resource_types": ["sql_database"],
        "severity": "critical",
        "category": "encryption",
        "description": "The inventory explicitly reports transparent data encryption disabled for the database.",
        "recommendation": "Enable transparent data encryption and verify key-management and recovery requirements.",
        "framework_mappings": [],
    },
    {
        "id": "aks_api_server_public",
        "title": "AKS API server is not configured as a private cluster",
        "resource_types": ["aks_cluster"],
        "severity": "medium",
        "category": "network",
        "description": "The inventory explicitly reports private cluster mode disabled.",
        "recommendation": "Evaluate private cluster mode and restrict API-server authorized IP ranges if public access is required.",
        "framework_mappings": [],
    },
    {
        "id": "aks_local_accounts_enabled",
        "title": "AKS local accounts are enabled",
        "resource_types": ["aks_cluster"],
        "severity": "medium",
        "category": "identity",
        "description": "Local Kubernetes accounts are enabled on the cluster.",
        "recommendation": "Disable local accounts where operationally feasible and use Microsoft Entra integration.",
        "framework_mappings": [],
    },
    {
        "id": "aks_network_policy_missing",
        "title": "AKS network policy is not configured",
        "resource_types": ["aks_cluster"],
        "severity": "medium",
        "category": "network",
        "description": "The inventory explicitly reports no Kubernetes network policy provider.",
        "recommendation": "Configure a supported network policy provider and define namespace-level traffic controls.",
        "framework_mappings": [],
    },
    {
        "id": "app_service_https_only",
        "title": "App Service does not enforce HTTPS",
        "resource_types": ["app_service"],
        "severity": "high",
        "category": "transport",
        "description": "HTTPS-only access is disabled for the App Service site.",
        "recommendation": "Enable HTTPS-only and validate redirect and certificate behavior.",
        "framework_mappings": [],
    },
    {
        "id": "app_service_weak_tls",
        "title": "App Service permits TLS below 1.2",
        "resource_types": ["app_service"],
        "severity": "high",
        "category": "transport",
        "description": "The configured minimum TLS version is lower than TLS 1.2.",
        "recommendation": "Set the site minimum TLS version to 1.2 or newer.",
        "framework_mappings": [],
    },
]


def policy_catalog():
    """Return safe-to-display policy metadata without executable predicates."""
    return [
        {
            key: value
            for key, value in policy.items()
            if key != "check"
        }
        for policy in POLICIES
    ]


def _check(policy_id, asset):
    if policy_id == "storage_public_blob_access":
        value = _bool(asset.get("public_access"))
        return {"public_access": asset.get("public_access")} if value is True else None
    if policy_id in {"storage_https_only", "app_service_https_only"}:
        value = _bool(asset.get("https_only"))
        return {"https_only": asset.get("https_only")} if value is False else None
    if policy_id in {"storage_weak_tls", "sql_server_weak_tls", "app_service_weak_tls"}:
        value = asset.get("minimum_tls_version")
        return {"minimum_tls_version": value} if _tls_below_12(value) else None
    if policy_id in {"storage_public_network_firewall", "key_vault_firewall_allow_all"}:
        public = _enabled(asset.get("public_network_access_enabled"))
        action = str(asset.get("network_default_action", asset.get("firewall_default_action", ""))).lower()
        return {
            "public_network_access_enabled": asset.get("public_network_access_enabled"),
            "network_default_action": action,
        } if public is True and action == "allow" else None
    if policy_id == "nsg_broad_admin_ingress":
        return _nsg_exposure(asset)
    if policy_id == "disk_encryption_disabled":
        value = _bool(asset.get("encryption_enabled"))
        return {"encryption_enabled": asset.get("encryption_enabled")} if value is False else None
    if policy_id == "vm_no_managed_identity":
        value = _bool(asset.get("managed_identity_enabled"))
        return {"managed_identity_enabled": asset.get("managed_identity_enabled")} if value is False else None
    if policy_id == "key_vault_public_network":
        value = _enabled(asset.get("public_network_access_enabled"))
        return {"public_network_access_enabled": asset.get("public_network_access_enabled")} if value is True else None
    if policy_id in {"key_vault_soft_delete_disabled", "key_vault_purge_protection_disabled"}:
        field = "soft_delete_enabled" if policy_id.endswith("soft_delete_disabled") else "purge_protection_enabled"
        value = _bool(asset.get(field))
        return {field: asset.get(field)} if value is False else None
    if policy_id == "sql_server_public_network":
        value = _enabled(asset.get("public_network_access_enabled"))
        return {"public_network_access_enabled": asset.get("public_network_access_enabled")} if value is True else None
    if policy_id == "sql_server_aad_only_auth_disabled":
        value = _bool(asset.get("aad_only_authentication"))
        return {"aad_only_authentication": asset.get("aad_only_authentication")} if value is False else None
    if policy_id == "sql_database_tde_disabled":
        value = _bool(asset.get("transparent_data_encryption_enabled"))
        return {"transparent_data_encryption_enabled": asset.get("transparent_data_encryption_enabled")} if value is False else None
    if policy_id == "aks_api_server_public":
        value = _bool(asset.get("private_cluster_enabled"))
        return {"private_cluster_enabled": asset.get("private_cluster_enabled")} if value is False else None
    if policy_id == "aks_local_accounts_enabled":
        value = _bool(asset.get("local_accounts_enabled"))
        return {"local_accounts_enabled": asset.get("local_accounts_enabled")} if value is True else None
    if policy_id == "aks_network_policy_missing":
        value = asset.get("network_policy_enabled")
        if value is None:
            provider = asset.get("network_policy")
            value = None if provider is None else str(provider).lower() not in {"", "none", "disabled"}
        parsed = _bool(value)
        return {"network_policy_enabled": value, "network_policy": asset.get("network_policy")} if parsed is False else None
    return None


def evaluate_assets(assets):
    """Evaluate known asset types; unknown or absent properties remain unknown."""
    output = []
    now = datetime.now(timezone.utc).isoformat()
    for asset in assets:
        asset_type = _canonical_type(asset)
        asset_id = str(asset.get("id") or asset.get("resource_id") or asset.get("name") or "unknown")
        for policy in POLICIES:
            if asset_type not in policy["resource_types"]:
                continue
            evidence = _check(policy["id"], asset)
            if evidence is None:
                continue
            digest = hashlib.sha256(f"{asset_id}:{policy['id']}".encode()).hexdigest()[:16]
            output.append({
                "id": digest,
                "asset_id": asset_id,
                "policy_id": policy["id"],
                "resource_type": asset_type,
                "title": policy["title"],
                "severity": policy["severity"],
                "category": policy["category"],
                "description": policy["description"],
                "recommendation": policy["recommendation"],
                "evidence": json.dumps(evidence, sort_keys=True, default=str),
                "control_ids": json.dumps(policy.get("framework_mappings", [])),
                "source": asset.get("source", "unknown"),
                "created_at": now,
            })
    return output
