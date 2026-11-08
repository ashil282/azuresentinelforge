# Setup guide

## Requirements

- Python 3.10 or newer for the API, collectors and tests.
- Node.js 18+ and npm for the React dashboard.
- Docker CLI/daemon only for the optional Docker snapshot adapter.
- Azure CLI and optional Azure SDK dependencies only for live inventory collection.

## Local demo

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements-dev.txt
python scripts/load_demo.py
uvicorn backend.app.main:app --reload --host 127.0.0.1
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev
```

The synthetic inventory includes Storage, NSG, disk, VM, Key Vault, Azure SQL, AKS and App Service examples. It is labelled synthetic and is not evidence about a real tenant.

## Optional collectors

```bash
# Linux auth log: adjust the path for your distribution
python scripts/ingest_linux_auth.py --path /var/log/auth.log --limit 1000

# Running Docker containers (read-only list + inspect)
python scripts/ingest_docker_snapshot.py

# Azure Resource Graph inventory (read-only)
pip install -r backend/requirements-azure.txt
az login
export AZURE_SUBSCRIPTION_ID="<subscription-id>"
python scripts/collect_azure.py --limit 500 --output data/azure-inventory-live.json
```

The Azure collector currently normalizes Storage Accounts, NSGs, managed disks, VMs, Key Vaults, SQL servers/databases, AKS clusters and App Service sites. Other Resource Graph resource types are counted as skipped, not silently treated as covered. Entra directory users/service principals are not collected by this Resource Graph adapter.

## API posture workflow

- `GET /api/v1/posture/policies` lists implemented checks.
- `POST /api/v1/posture/evaluate` accepts `{"assets": [...]}` and returns findings, severity counts and a data label.
- `GET /api/v1/findings` returns stored findings with decoded evidence.

## Tests

```bash
pip install -r backend/requirements-dev.txt
python -m unittest discover -s tests -v
python -m compileall -q backend scripts tests
```

The default demo needs no Azure account or cloud resource. Real Azure data does require a subscription and appropriate read-only permissions. Microsoft Sentinel and Defender for Cloud are separate Microsoft services and may incur charges.
