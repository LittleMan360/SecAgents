import unittest

from app.schemas import (
    SchemaValidationError,
    validate_event,
    validate_ai_response,
)

class TestSchemas(unittest.TestCase):

    def setUp(self):
        """Create sample data for each test."""

        self.valid_event = {
            "event_id": "test-001",
            "timestamp": "2026-10-08T16:57:36.956Z",
            "hostname": "test-server",
            "agent_ip": "192.0.2.10",
            "severity": 7,
            "severity_label": "Medium",
            "rule_id": "550",
            "description": "Integrity checksum changed.",
            "mitre_ids": ["T1565.001"],
            "event_type": "file_integrity",
            "details": {
                "file_path": "/etc/example/test.conf",
                "file_action": "modified"
            }
        }

        self.valid_ai_response = {
            "event_id": "test-001",
            "event_index": "wazuh-alerts-example",
            "summary": "A monitored configuration file was modified.",
            "source_context": "The change was detected on test-server.",
            "classification": "unknown",
            "confidence": 0.65,
            "uncertainty": "The alert does not establish whether the change was authorized.",
            "mitre_explanation": "The alert references MITRE ATT&CK technique T1565.001.",
            "recommended_actions": [
                "Review the file modification history.",
                "Verify whether the change was authorized."
            ],
                "evidence": [
                "Wazuh rule 550 detected a file integrity change."
            ]
        }

    def test_valid_event(self):
        """A correctly formatted Wazuh event should pass."""
        result = validate_event(self.valid_event)

        self.assertEqual(result, self.valid_event)

    def test_missing_event_field(self):
        """An event missing a required field should fail."""
        event = self.valid_event.copy()
        del event["event_id"]

        with self.assertRaises(SchemaValidationError):
            validate_event(event)

    def test_invalid_severity(self):
        """Wazuh severity must be between 0 and 16."""
        event = self.valid_event.copy()
        event["severity"] = 20

        with self.assertRaises(SchemaValidationError):
            validate_event(event)

    def test_invalid_mitre_ids(self):
        """MITRE IDs must be provided as a list."""
        event = self.valid_event.copy()
        event["mitre_ids"] = "T1565.001"

        with self.assertRaises(SchemaValidationError):
            validate_event(event)

    def test_valid_ai_response(self):
        """A correctly formatted AI response should pass."""
        result = validate_ai_response(self.valid_ai_response)

        self.assertEqual(result, self.valid_ai_response)

    def test_missing_ai_field(self):
        """An AI response missing required information should fail."""
        response = self.valid_ai_response.copy()
        del response["summary"]

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_invalid_confidence(self):
        """AI confidence must be between 0 and 1."""
        response = self.valid_ai_response.copy()
        response["confidence"] = 1.5

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_invalid_classification(self):
        """AI classification must use an approved category."""
        response = self.valid_ai_response.copy()
        response["classification"] = "definitely_hacked"

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_invalid_recommended_actions(self):
        """Recommended actions must contain strings."""
        response = self.valid_ai_response.copy()
        response["recommended_actions"] = [123, 456]

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_missing_source_context(self):
        response = self.valid_ai_response.copy()
        del response["source_context"]

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_missing_uncertainty(self):
        """AI responses must explain uncertainty."""
        response = self.valid_ai_response.copy()
        del response["uncertainty"]

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_missing_event_reference(self):
        """AI responses must reference the original Wazuh event."""
        response = self.valid_ai_response.copy()
        del response["event_id"]

        with self.assertRaises(SchemaValidationError):
            validate_ai_response(response)

    def test_optional_mitre_explanation(self):
        """MITRE explanations can be null when no technique is available."""
        response = self.valid_ai_response.copy()
        response["mitre_explanation"] = None

        result = validate_ai_response(response)

        self.assertIsNone(result["mitre_explanation"])

    def test_invalid_source_ip(self):
        """Reject source IP values that are not strings or null."""
        event = self.valid_event.copy()
        event["source_ip"] = 12345

        with self.assertRaises(SchemaValidationError):
            validate_event(event)

    def test_invalid_event_index(self):
        """Reject event index values that are not strings or null."""
        event = self.valid_event.copy()
        event["event_index"] = 12345

        with self.assertRaises(SchemaValidationError):
            validate_event(event)


if __name__ == "__main__":
    unittest.main()