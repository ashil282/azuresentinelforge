# AzureSentinelForge 0.3

Local-first Azure posture, workload telemetry, SIEM correlation and safe SOAR lab.

**Cost truth:** the default demo is local and synthetic; it needs no Azure subscription, paid account, API key, GPU or cloud VM. This is not Microsoft Sentinel or paid Defender for Cloud. Those Microsoft services may incur charges. Live Azure inventory requires your own subscription and appropriately scoped read-only permissions. No Azure resources are provisioned or modified.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python scripts/load_demo.py
uvicorn backend.app.main:app --reload --host 127.0.0.1
```

API docs: <http://127.0.0.1:8000/docs>

Dashboard, in a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The dashboard reads the local API at `127.0.0.1:8000`. GitHub Pages can host the static frontend; it does not host FastAPI or SQLite.

## CSPM coverage in 0.3

The policy catalog currently includes checks for:

- Storage public blob access, HTTPS-only, minimum TLS and public firewall defaults.
- NSG inbound exposure of common administrative/database ports to Internet or any-address sources.
- Managed disk encryption and VM managed identity when explicitly present in inventory.
- Key Vault public network access, soft delete, purge protection and firewall defaults.
- Azure SQL server public network access, minimum TLS and Entra-only authentication; database TDE.
- AKS private API endpoint, local accounts and network policy.
- App Service HTTPS-only and minimum TLS.

The evaluator is deliberately conservative: **missing properties are unknown**, not automatically secure or insecure. Findings include a stable policy ID and the observed evidence. The framework crosswalk is intentionally marked pending validation rather than inventing benchmark control mappings.

## Optional Azure read-only collector

```bash
pip install -r backend/requirements-azure.txt
az login
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
python scripts/collect_azure.py --limit 500 --output data/azure-inventory-live.json
```

The Resource Graph query is read-only. The collector normalizes supported resource types to the CSPM asset schema and reports how many returned resources were not yet mapped. It does not query Entra directory objects or write to Azure. Use the narrowest practical Reader role. Keep exported inventory local and out of Git.

To evaluate a normalized inventory through the API, post its `assets` array to `POST /api/v1/posture/evaluate`. `GET /api/v1/posture/policies` returns the implemented policy catalog.

## SIEM, runtime and SOAR boundaries

- Local SIEM ingestion validates events, rejects duplicate IDs, evaluates YAML rules and performs bounded correlation.
- Linux auth-log and Docker inspect adapters are read-only snapshots; they are not privileged always-on sensors.
- SOAR playbooks only create local dry-run/approval audit records. `dry_run=false` is rejected; no external remediation executor exists.

## Tests

```bash
pip install -r backend/requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q backend scripts tests
```

See `docs/SETUP.md`, `docs/ARCHITECTURE.md`, `docs/SECURITY.md`, `docs/ROADMAP.md` and `docs/PROGRESS.md`.
