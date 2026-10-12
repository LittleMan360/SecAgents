def get_severity_label(level):
    """Returns the severity label to be readable."""
    if level <= 6:
        return "Low"
    elif level <= 11:
        return "Medium"
    elif level <= 14:
        return "High"
    else:
        return "Critical"

def normalize_alert(event):
    """Normalizes the Wazuh alert to a standard format."""

    alert = event.get("alert", {})
    agent = alert.get("agent", {})
    rule = alert.get("rule", {})
    mitre = rule.get("mitre", {})
    data = alert.get("data") or {}

    severity = rule.get("level", 0)

    source_ip = (
        alert.get("srcip")
        or data.get("srcip")
        or data.get("src_ip")
    )

    normalized = {
        "event_id": event.get("document_id"),
        "event_index": event.get("index"),
        "timestamp": alert.get("@timestamp"),
        "hostname": agent.get("name"),
        "agent_ip": agent.get("ip"),
        "source_ip": source_ip,
        "severity": severity,
        "severity_label": get_severity_label(severity),
        "rule_id": rule.get("id"),
        "description": rule.get("description"),
        "mitre_ids": mitre.get("id", []),
        "event_type": None,
        "details": {}
    }

    if "syscheck" in alert:
        syscheck = alert["syscheck"]

        normalized["event_type"] = "file_integrity"

        normalized["details"] = {
            "file_path": syscheck.get("path"),
            "file_action": syscheck.get("event"),
            "changed_attributes": syscheck.get("changed_attributes", []),
            "process": syscheck.get("audit", {}).get("process", {}).get("name")
        }

    return normalized