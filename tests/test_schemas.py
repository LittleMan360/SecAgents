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
            "summary": "A monitored configuration file was modified.",
            "classification": "unknown",
            "confidence": 0.65,
            "recommended_actions": [
                "Review the file modification history."
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


if __name__ == "__main__":
    unittest.main()