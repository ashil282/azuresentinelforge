from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import re
import uuid

import yaml

from .config import RULES
from .db import connect

SEVERITIES = {"critical", "high", "medium", "low", "info"}
MATCH_FIELDS = {"event_type", "severity", "source", "host", "actor"}
GROUP_FIELDS = {"host", "actor", "source"}


def _parse_time(value):
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("timestamp must be an ISO-8601 datetime") from exc
    else:
        raise ValueError("timestamp must be an ISO-8601 datetime")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def validate_event(payload):
    if not isinstance(payload, dict):
        raise ValueError("event must be an object")
    event_type = payload.get("event_type")
    message = payload.get("message")
    if not isinstance(event_type, str) or not event_type.strip() or len(event_type) > 128:
        raise ValueError("event_type must be a non-empty string of at most 128 characters")
    if not isinstance(message, str) or not message.strip() or len(message) > 8192:
        raise ValueError("message must be a non-empty string of at most 8192 characters")
    severity = str(payload.get("severity", "low")).lower()
    if severity not in SEVERITIES:
        raise ValueError(f"severity must be one of: {', '.join(sorted(SEVERITIES))}")
    for field in ("id", "source", "host", "actor"):
        value = payload.get(field)
        if value is not None and (not isinstance(value, str) or len(value) > 256):
            raise ValueError(f"{field} must be a string of at most 256 characters")
    attributes = payload.get("attributes", {})
    if not isinstance(attributes, dict):
        raise ValueError("attributes must be an object")
    try:
        json.dumps(payload)
    except (TypeError, ValueError) as exc:
        raise ValueError("event must contain JSON-serializable values") from exc
    return severity


def rules(rules_dir=None):
    """Load and validate YAML detections; fail closed on malformed rule files."""
    directory = Path(rules_dir or RULES)
    loaded = []
    seen_ids = set()
    for path in sorted(directory.glob("*.y*ml")):
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValueError(f"Could not load rule file {path.name}: {exc}") from exc
        if not isinstance(document, dict) or not isinstance(document.get("rules", []), list):
            raise ValueError(f"{path.name}: expected a top-level rules list")
        for rule in document.get("rules", []):
            if not isinstance(rule, dict):
                raise ValueError(f"{path.name}: each rule must be an object")
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,80}", rule_id):
                raise ValueError(f"{path.name}: rule id is missing or invalid")
            if rule_id in seen_ids:
                raise ValueError(f"{path.name}: duplicate rule id {rule_id}")
            if not isinstance(rule.get("title"), str) or not rule["title"].strip():
                raise ValueError(f"{path.name}: rule {rule_id} needs a title")
            if str(rule.get("severity", "")).lower() not in SEVERITIES:
                raise ValueError(f"{path.name}: rule {rule_id} has an invalid severity")
            match = rule.get("match")
            if not isinstance(match, dict) or not match or not set(match).issubset(MATCH_FIELDS):
                raise ValueError(f"{path.name}: rule {rule_id} has invalid match fields")
            threshold = rule.get("threshold", 1)
            window = rule.get("window_seconds", 300)
            group_by = rule.get("group_by")
            if not isinstance(threshold, int) or isinstance(threshold, bool) or not 1 <= threshold <= 10000:
                raise ValueError(f"{path.name}: rule {rule_id} threshold must be between 1 and 10000")
            if not isinstance(window, int) or isinstance(window, bool) or not 1 <= window <= 86400:
                raise ValueError(f"{path.name}: rule {rule_id} window_seconds must be between 1 and 86400")
            if group_by is not None and group_by not in GROUP_FIELDS:
                raise ValueError(f"{path.name}: rule {rule_id} has an invalid group_by field")
            mitre = rule.get("mitre", [])
            if not isinstance(mitre, list) or not all(isinstance(item, str) for item in mitre):
                raise ValueError(f"{path.name}: rule {rule_id} mitre must be a list of strings")
            normalized = dict(rule)
            normalized["severity"] = str(rule["severity"]).lower()
            normalized["threshold"] = threshold
            normalized["window_seconds"] = window
            loaded.append(normalized)
            seen_ids.add(rule_id)
    return loaded


def _rule_matches(event, rule):
    return all(event.get(field) == value for field, value in rule["match"].items())


def _correlation_count(connection, rule, event, cutoff):
    group_by = rule.get("group_by")
    group_value = event.get(group_by) if group_by else None
    if group_by and (group_value is None or group_value == ""):
        return 0, group_value

    rows = connection.execute(
        "SELECT event_type,severity,source,host,actor FROM events WHERE ingested_at >= ? AND ingested_at <= ?",
        (cutoff.isoformat(), event["ingested_at"]),
    ).fetchall()
    count = 0
    for row in rows:
        candidate = dict(row)
        if _rule_matches(candidate, rule) and (not group_by or candidate.get(group_by) == group_value):
            count += 1
    return count, group_value


def _already_alerted(connection, rule_id, cutoff, group_by, group_value):
    if group_by:
        query = (
            "SELECT 1 FROM alerts a JOIN events e ON e.id=a.event_id "
            f"WHERE a.rule_id=? AND a.created_at>=? AND e.{group_by} IS ? LIMIT 1"
        )
        return connection.execute(query, (rule_id, cutoff.isoformat(), group_value)).fetchone() is not None
    return connection.execute(
        "SELECT 1 FROM alerts WHERE rule_id=? AND created_at>=? LIMIT 1",
        (rule_id, cutoff.isoformat()),
    ).fetchone() is not None


def ingest(payload, db_path=None, rules_dir=None, now=None):
    severity = validate_event(payload)
    received_at = _parse_time(now or datetime.now(timezone.utc))
    event_time = _parse_time(payload.get("timestamp") or received_at)
    event = {
        "id": payload.get("id") or str(uuid.uuid4()),
        "timestamp": event_time.isoformat(),
        "source": payload.get("source", "manual"),
        "event_type": payload["event_type"].strip(),
        "severity": severity,
        "host": payload.get("host"),
        "actor": payload.get("actor"),
        "message": payload["message"].strip(),
        "raw_json": json.dumps(payload, sort_keys=True),
        "ingested_at": received_at.isoformat(),
    }

    loaded_rules = rules(rules_dir)
    matches = []
    with connect(db_path) as connection:
        cursor = connection.execute(
            """INSERT OR IGNORE INTO events
               (id,timestamp,source,event_type,severity,host,actor,message,raw_json,ingested_at)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            tuple(event[key] for key in (
                "id", "timestamp", "source", "event_type", "severity", "host", "actor",
                "message", "raw_json", "ingested_at"
            )),
        )
        if cursor.rowcount == 0:
            return {"event": event, "alerts": [], "duplicate": True}

        for rule in loaded_rules:
            if not _rule_matches(event, rule):
                continue
            threshold = rule["threshold"]
            window = rule["window_seconds"]
            cutoff = received_at - timedelta(seconds=window)
            count, group_value = _correlation_count(connection, rule, event, cutoff)
            if count < threshold:
                continue
            group_by = rule.get("group_by")
            if threshold > 1 and _already_alerted(
                connection, rule["id"], cutoff, group_by, group_value
            ):
                continue

            alert = {
                "id": str(uuid.uuid4()),
                "rule_id": rule["id"],
                "title": rule["title"],
                "severity": rule["severity"],
                "event_id": event["id"],
                "mitre": rule.get("mitre", []),
                "context": {
                    "match_count": count,
                    "threshold": threshold,
                    "window_seconds": window,
                    "group_by": group_by,
                    "group_value": group_value,
                },
            }
            connection.execute(
                "INSERT INTO alerts (id,rule_id,title,severity,event_id,mitre,created_at,context) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    alert["id"], alert["rule_id"], alert["title"], alert["severity"],
                    alert["event_id"], json.dumps(alert["mitre"]), received_at.isoformat(),
                    json.dumps(alert["context"], sort_keys=True),
                ),
            )
            matches.append(alert)

        if matches:
            rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            top = max(matches, key=lambda item: rank.get(item["severity"], 0))
            connection.execute(
                "INSERT INTO incidents VALUES (?,?,?,?,?,?)",
                (
                    str(uuid.uuid4()), top["title"], top["severity"], "open",
                    json.dumps([item["id"] for item in matches]), received_at.isoformat(),
                ),
            )

    return {"event": event, "alerts": matches, "duplicate": False}
