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

    return event


def validate_ai_response(response):
    """Validate a structured response from the AI model."""

    if not isinstance(response, dict):
        raise SchemaValidationError("AI response must be a dictionary.")

    required_fields = {
        "summary": str,
        "classification": str,
        "confidence": (int, float),
        "recommended_actions": list,
        "evidence": list,
    }

    for field, expected_type in required_fields.items():
        value = response.get(field)

        if not isinstance(value, expected_type):
            raise SchemaValidationError(
                f"Invalid or missing AI response field: {field}"
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