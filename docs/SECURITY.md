# Security

## Safe defaults

- Bind the API to localhost (`127.0.0.1`) and do not publish it directly to the internet. Authentication, authorization and tenant isolation are not implemented.
- Use Azure Reader at the narrowest intended subscription/resource scope. The Resource Graph adapter performs read-only inventory queries; it does not provision, mutate or delete Azure resources.
- The Azure collector uses `DefaultAzureCredential`; review the active credential source and scope before running it. Do not export credentials or access tokens.
- Never commit `.env`, credentials, access tokens, Azure exports, customer logs, database files or production telemetry.
- Treat findings as heuristics requiring analyst validation. A finding is not proof of compromise or compliance. Missing inventory properties are unknown; they are not silently treated as passing checks.
- Framework mappings are pending control-by-control validation. Do not use the current catalog as a compliance attestation.
- SOAR only records local dry-run/approval state. `dry_run=false` is rejected; there is no cloud, account, IP or host remediation executor.
- Linux and Docker adapters read existing data. Docker socket access is highly privileged on many hosts; run only when you already trust the operator and environment.

## Data handling

Events, raw payload JSON, alerts, incidents, findings and SOAR preview records are stored in local SQLite. Azure inventory exports may include subscription IDs, resource IDs, names and topology metadata. The database and exported JSON may contain usernames, hostnames, IP addresses, process names or other sensitive metadata. Restrict filesystem permissions, use a dedicated local data directory where appropriate, and delete the database/exports when no longer needed. Do not upload them to public issue trackers.

## Reporting

For a vulnerability report, include the affected version, reproducible steps and impact without including live secrets or tenant data. Do not test against Azure resources or hosts you do not own or administer.
