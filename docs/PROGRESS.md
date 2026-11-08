# Progress log

## 2026-11-08 — 0.2 SIEM correlation and runtime adapters

- Preserved the 0.1 monorepo and applied in-place SQLite migrations for ingestion timestamps and alert correlation context.
- Added event validation, duplicate-ID idempotency, YAML rule validation, grouped threshold correlation and alert suppression.
- Added an SSH brute-force rule: five authentication failures per host in 300 seconds.
- Added read-only Linux auth-log and Docker inspect snapshot ingestors plus parser tests.
- Expanded FastAPI list endpoints and dashboard navigation for posture, telemetry, detections and SOAR previews.
- Added API integration coverage and setup/security documentation.
- Verification for this milestone is recorded in `BUILD_VERIFICATION.txt` and regenerated with the source bundle.

## 2026-11-08 — 0.1 foundation

- Established FastAPI/SQLite, starter CSPM checks, YAML SIEM rules, SOAR dry-run, synthetic fixtures, optional Azure Resource Graph collection, dashboard shell and CI.

## 2026-11-08 — 0.3 CSPM coverage and Azure normalization

- Expanded the policy catalog to 20 explicit checks across Storage, NSGs, disks, VMs, Key Vault, Azure SQL, AKS and App Service.
- Findings now carry stable policy IDs, canonical resource types and observed JSON evidence; absent properties remain unknown.
- Added backwards-compatible SQLite migration for policy metadata and tests that preserve legacy finding rows.
- Added tested Resource Graph normalization for supported ARM types and a local JSON export option; unmapped resources are counted.
- Added policy catalog API/dashboard view and expanded labelled synthetic fixtures.
- Verification results are recorded in `BUILD_VERIFICATION.txt` after the run's checks.
