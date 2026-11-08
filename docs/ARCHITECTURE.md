# Architecture

AzureSentinelForge is a local-first monorepo. FastAPI exposes a localhost API; SQLite stores findings, normalized events, alerts, incidents and SOAR preview records. React/TypeScript/Vite provides a dashboard and calls the local API.

## Data flow

1. Synthetic JSON fixtures populate the default demo. Optional Azure Resource Graph, Linux auth-log and Docker inspect adapters are read-only.
2. The Azure normalizer maps a bounded set of ARM resource types into canonical asset objects. Unknown resource types are counted as skipped; missing properties remain `null`.
3. CSPM policies evaluate only explicit risky values. Findings carry stable policy IDs, resource types, source labels and JSON evidence.
4. SIEM ingestion validates and normalizes events, applies YAML detections and bounded threshold correlation, then stores alerts/incidents.
5. SOAR playbooks create local preview/audit records only. Approval does not execute remediation.

## Trust boundaries

- The default fixture path is synthetic and requires no cloud credentials.
- Live Azure collection requires a subscription and read-only permissions. Resource Graph does not provide Entra directory inventory in this implementation.
- The API has no authentication or tenant isolation; keep it bound to localhost.
- No cloud resource writes or destructive host actions are implemented.
- Microsoft Sentinel and Defender for Cloud are separate products and may incur charges; this project does not emulate their paid services.
