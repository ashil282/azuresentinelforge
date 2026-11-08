"""Pure parsers for read-only host and Docker runtime snapshots."""
import re
import uuid


def parse_linux_auth_line(line, host=None):
    text = line.strip()
    if not text:
        return None

    failed = "Failed password" in text or "authentication failure" in text
    accepted = "Accepted password" in text or "Accepted publickey" in text
    if failed or accepted:
        actor = "sshd"
        event_type = "authentication_failure" if failed else "authentication_success"
        severity = "medium" if failed else "info"
        username_match = re.search(r"(?:for (?:invalid user )?|user=)([A-Za-z0-9_.@-]+)", text)
        ip_match = re.search(r"\bfrom ([0-9a-fA-F:.]+)(?:\s|$)", text)
        attributes = {}
        if username_match:
            attributes["username"] = username_match.group(1)
        if ip_match:
            attributes["source_ip"] = ip_match.group(1)
        return {
            "id": str(uuid.uuid4()),
            "source": "linux_auth_log",
            "event_type": event_type,
            "severity": severity,
            "host": host,
            "actor": actor,
            "message": text[:8192],
            "attributes": attributes,
        }

    if "sudo:" in text and "COMMAND=" in text:
        actor_match = re.search(r"sudo:\s+([^ :]+)", text)
        return {
            "id": str(uuid.uuid4()),
            "source": "linux_auth_log",
            "event_type": "privilege_command",
            "severity": "medium",
            "host": host,
            "actor": actor_match.group(1) if actor_match else "sudo",
            "message": text[:8192],
            "attributes": {"command_present": True},
        }
    return None


def privileged_container_event(container, host=None):
    """Return a normalized event for a running container configured privileged."""
    host_config = container.get("HostConfig") or {}
    if host_config.get("Privileged") is not True:
        return None
    config = container.get("Config") or {}
    name = str(container.get("Name") or "").lstrip("/")
    return {
        "id": str(uuid.uuid4()),
        "source": "docker_inspect",
        "event_type": "container_started_privileged",
        "severity": "high",
        "host": host,
        "actor": "docker",
        "message": f"Running privileged container detected: {name or container.get('Id', 'unknown')}",
        "attributes": {
            "container_id": container.get("Id"),
            "container_name": name,
            "image": config.get("Image"),
            "privileged": True,
        },
    }
