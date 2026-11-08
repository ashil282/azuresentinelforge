# Roadmap

## Delivered in 0.3

- Preserved the 0.2 FastAPI/SQLite, YAML SIEM correlation, Linux/Docker adapters and dry-run SOAR workflow.
- Expanded CSPM from starter checks to a catalog covering Storage, NSGs, managed disks, VMs, Key Vault, Azure SQL, AKS and App Service.
- Added stable policy IDs, severity/category metadata and observed evidence to findings.
- Missing configuration values remain unknown; the evaluator does not treat absent data as compliant or non-compliant.
- Added backwards-compatible SQLite migration for policy ID, resource type and control metadata.
- Added a dependency-free Azure Resource Graph normalizer for supported resource types and a `--output` option for local inventory exports.
- Added policy catalog API and dashboard view.
- Added synthetic fixture coverage for Key Vault, SQL, AKS and App Service.

## Next milestones

1. Add inventory persistence and refresh provenance (collection time, subscription scope, skipped-resource diagnostics) without storing secrets.
2. Add deeper NSG/route/PE exposure context and Azure identity inventory through separately scoped read-only Graph permissions; clearly separate Resource Graph from directory API access.
3. Add durable event normalization for journald/auditd and Docker lifecycle streams, with safe rate limits and retention controls.
4. Integrate optional Trivy image scan output ingestion without requiring paid services; preserve scan provenance and severity mapping.
5. Add incident lifecycle, suppression controls, retention/cleanup, and stronger query/index performance.
6. Add compliance mappings (CIS Azure Foundations, Azure Security Benchmark, NIST CSF, MITRE ATT&CK) only after pinning benchmark versions and validating each mapping against source controls.
7. Add API authentication/authorization before any non-local deployment; keep SOAR simulated until a separately reviewed execution boundary exists.
8. Verify frontend deployment configuration and optional GitHub Pages publishing; keep FastAPI/SQLite local unless a genuinely free, suitable API host is verified.

## Explicitly out of scope for the zero-cost default

Paid Microsoft Sentinel/Defender for Cloud services, paid threat-intelligence APIs, cloud-hosted databases, automatic remediation, always-on privileged host agents and GPU workloads.
