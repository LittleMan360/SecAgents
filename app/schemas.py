"""Data validation for Wazuh events and AI analysis results."""


class SchemaValidationError(ValueError):
    """Raised when event or AI response data is invalid."""


def validate_event(event):
    """Validate an event produced by the Wazuh normalizer."""

    if not isinstance(event, dict):
        raise SchemaValidationError("Event must be a dictionary.")

    required_fields = {
        "event_id": str,
        "timestamp": str,
        "hostname": str,
        "severity": int,
        "severity_label": str,
        "rule_id": str,
        "description": str,
    }

    for field, expected_type in required_fields.items():
        value = event.get(field)

        if not isinstance(value, expected_type):
            raise SchemaValidationError(
                f"Invalid or missing event field: {field}"
            )

    if isinstance(event["severity"], bool):
        raise SchemaValidationError("Severity must be an integer.")

    if not 0 <= event["severity"] <= 16:
        raise SchemaValidationError(
            "Wazuh severity must be between 0 and 16."
        )

    if event["severity_label"] not in {
        "Low", "Medium", "High", "Critical"
    }:
        raise SchemaValidationError("Invalid severity label.")

    if not isinstance(event.get("mitre_ids"), list):
        raise SchemaValidationError("mitre_ids must be a list.")

    if not all(isinstance(item, str) for item in event["mitre_ids"]):
        raise SchemaValidationError("MITRE IDs must be strings.")

    if not isinstance(event.get("details"), dict):
        raise SchemaValidationError("Event details must be a dictionary.")

    # Check the original Wazuh index when available.
    event_index = event.get("event_index")

    if event_index is not None and not isinstance(event_index, str):
        raise SchemaValidationError(
            "event_index must be a string or null."
        )

    # Source IP is optional because not every alert contains one.
    source_ip = event.get("source_ip")

    if source_ip is not None and not isinstance(source_ip, str):
        raise SchemaValidationError(
            "source_ip must be a string or null."
        )

    return event

def validate_ai_response(response):
    """Validate the structured analysis returned by the AI model."""

    if not isinstance(response, dict):
        raise SchemaValidationError("AI response must be a dictionary.")

    required_fields = {
        "event_id": str,
        "event_index": str,
        "summary": str,
        "source_context": str,
        "classification": str,
        "confidence": (int, float),
        "uncertainty": str,
        "recommended_actions": list,
        "evidence": list,
    }

    for field, expected_type in required_fields.items():
        value = response.get(field)

        if not isinstance(value, expected_type):
            raise SchemaValidationError(
                f"Invalid or missing AI response field: {field}"
            )

    # MITRE information may not exist for every alert.
    mitre_explanation = response.get("mitre_explanation")

    if mitre_explanation is not None and not isinstance(mitre_explanation, str):
        raise SchemaValidationError(
            "mitre_explanation must be a string or null."
        )

    if isinstance(response["confidence"], bool):
        raise SchemaValidationError("Confidence must be numeric.")

    if not 0 <= response["confidence"] <= 1:
        raise SchemaValidationError(
            "Confidence must be between 0 and 1."
        )

    if response["classification"] not in {
        "benign", "suspicious", "malicious", "unknown"
    }:
        raise SchemaValidationError("Invalid AI classification.")


    for field in ("recommended_actions", "evidence"):
        if not all(isinstance(item, str) for item in response[field]):
            raise SchemaValidationError(
                f"{field} must contain strings."
            )

    return response