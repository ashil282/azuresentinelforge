import json
from typing import Any, Literal

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from .db import connect, init_db
from .posture import evaluate_assets, policy_catalog
from .siem import ingest, rules
from .soar import PLAYBOOKS, run

app = FastAPI(
    title="AzureSentinelForge API",
    version="0.3.0",
    description="Local-first CSPM, runtime telemetry, SIEM detections and safe SOAR previews.",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class Event(BaseModel):
    id: str | None = Field(default=None, max_length=256)
    timestamp: str | None = Field(default=None, max_length=64)
    source: str = Field(default="manual", max_length=256)
    event_type: str = Field(min_length=1, max_length=128)
    severity: Literal["critical", "high", "medium", "low", "info"] = "low"
    host: str | None = Field(default=None, max_length=256)
    actor: str | None = Field(default=None, max_length=256)
    message: str = Field(min_length=1, max_length=8192)
    attributes: dict[str, Any] = Field(default_factory=dict)


class Playbook(BaseModel):
    playbook_id: str = Field(min_length=1, max_length=128)
    approved: bool = False
    dry_run: bool = True


class PostureRequest(BaseModel):
    assets: list[dict[str, Any]] = Field(default_factory=list, max_length=10000)


@app.on_event("startup")
def startup():
    init_db()


@app.get("/health")
def health():
    return {"status": "ok", "mode": "local-first", "version": app.version}


@app.get("/api/v1/summary")
def summary():
    with connect() as connection:
        return {
            table: connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("findings", "events", "alerts", "incidents", "soar_runs")
        }


@app.get("/api/v1/posture/policies")
def posture_policies():
    return policy_catalog()


@app.post("/api/v1/posture/evaluate")
def posture(body: PostureRequest):
    assets = body.assets
    findings = evaluate_assets(assets)
    with connect() as connection:
        for finding in findings:
            connection.execute(
                """INSERT OR REPLACE INTO findings
                (id,asset_id,title,severity,category,description,recommendation,evidence,
                 source,created_at,policy_id,resource_type,control_ids)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                tuple(
                    finding[key]
                    for key in (
                        "id", "asset_id", "title", "severity", "category", "description",
                        "recommendation", "evidence", "source", "created_at", "policy_id",
                        "resource_type", "control_ids",
                    )
                ),
            )
    if assets and all(asset.get("source") == "synthetic" for asset in assets):
        label = "synthetic"
    elif assets and all(asset.get("source") == "azure_resource_graph" for asset in assets):
        label = "live_read_only"
    elif any(asset.get("source") == "synthetic" for asset in assets):
        label = "mixed_or_unknown"
    else:
        label = "unknown_or_mixed"
    counts = {severity: sum(item["severity"] == severity for item in findings)
              for severity in ("critical", "high", "medium", "low", "info")}
    return {
        "evaluated_assets": len(assets),
        "policies_available": len(policy_catalog()),
        "finding_count": len(findings),
        "counts_by_severity": counts,
        "findings": findings,
        "data_label": label,
    }

@app.get("/api/v1/findings")
def findings(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM findings ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        try:
            item["evidence"] = json.loads(item.get("evidence") or "{}")
        except json.JSONDecodeError:
            item["evidence"] = {"raw": item.get("evidence")}
        try:
            item["control_ids"] = json.loads(item.get("control_ids") or "[]")
        except json.JSONDecodeError:
            item["control_ids"] = []
        output.append(item)
    return output


@app.get("/api/v1/rules")
def detection_rules():
    try:
        return rules()
    except ValueError as exc:
        raise HTTPException(500, f"Detection rule configuration error: {exc}") from exc


@app.post("/api/v1/events")
def event(payload: Event):
    try:
        return ingest(payload.model_dump())
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


@app.get("/api/v1/events")
def events(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT id,timestamp,source,event_type,severity,host,actor,message,ingested_at "
                "FROM events ORDER BY ingested_at DESC LIMIT ?",
                (limit,),
            )
        ]


@app.get("/api/v1/alerts")
def alerts(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["mitre"] = json.loads(item["mitre"] or "[]")
        item["context"] = json.loads(item.get("context") or "{}")
        output.append(item)
    return output


@app.get("/api/v1/incidents")
def incidents(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as connection:
        return [
            dict(row)
            for row in connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)
            )
        ]


@app.get("/api/v1/soar/playbooks")
def playbooks():
    return [{"id": key, **value} for key, value in PLAYBOOKS.items()]


@app.get("/api/v1/soar/runs")
def soar_runs(limit: int = Query(default=100, ge=1, le=500)):
    with connect() as connection:
        rows = connection.execute(
            "SELECT * FROM soar_runs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    output = []
    for row in rows:
        item = dict(row)
        item["result"] = json.loads(item["result"] or "{}")
        output.append(item)
    return output


@app.post("/api/v1/soar/run")
def soar(request: Playbook):
    try:
        return run(request.playbook_id, request.approved, request.dry_run)
    except KeyError as exc:
        raise HTTPException(404, "Unknown playbook") from exc
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
