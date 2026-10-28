"""
Unit tests for the SecAgents AI Gateway.

Uses a simulated Ollama client so tests can run
without connecting to the AI server.
"""

import json
import unittest

from unittest.mock import Mock
from app.gateway import AIGateway
from app.schemas import SchemaValidationError

class TestAIGateway(unittest.TestCase):

    def setUp(self):
        # Safe example alert using Alex's Wazuh export format.
        self.raw_event = {
            "index": "wazuh-alerts-4.x-2026.10.24",
            "document_id": "test-event-001",
            "alert": {
                "@timestamp": "2026-10-24T12:00:00Z",
                "agent": {
                    "name": "test-linux-host",
                    "ip": "192.0.2.10"
                },
                "rule": {
                    "id": "100001",
                    "level": 12,
                    "description": "Multiple failed SSH login attempts"
                },
                "data": {
                    "srcip": "192.0.2.50"
                }
            }
        }

        self.ai_response = {
            "summary": "Multiple failed SSH login attempts were detected.",
            "source_context": "Activity was observed on test-linux-host.",
            "classification": "suspicious",
            "confidence": 0.85,
            "uncertainty": "The alert does not confirm successful access.",
            "recommended_actions": [
                "Review SSH authentication logs.",
                "Investigate the source IP."
            ],
            "evidence": [
                "Wazuh reported multiple failed SSH login attempts."
            ],
            "mitre_explanation": None
        }
        self.mock_client = Mock()
        self.mock_client.generate.return_value = json.dumps(
            self.ai_response
        )
        self.gateway = AIGateway(client=self.mock_client)

    def test_successful_gateway_processing(self):

        result = self.gateway.process_alert(self.raw_event)
        self.assertEqual(
            result["event_id"],
            "test-event-001"
        )

        self.assertEqual(
            result["event_index"],
            "wazuh-alerts-4.x-2026.10.24"
        )

        self.assertEqual(
            result["classification"],
            "suspicious"
        )

        self.assertEqual(
            result["confidence"],
            0.85
        )
        self.mock_client.generate.assert_called_once()

    def test_original_event_not_modified(self):
        original = json.dumps(self.raw_event, sort_keys=True)
        self.gateway.process_alert(self.raw_event)
        self.assertEqual(
            json.dumps(self.raw_event, sort_keys=True),
            original
        )

    def test_invalid_ai_json(self):
        self.mock_client.generate.return_value = "not valid json"
        with self.assertRaises(json.JSONDecodeError):
            self.gateway.process_alert(self.raw_event)

    def test_missing_ai_fields(self):
        self.mock_client.generate.return_value = json.dumps({
            "summary": "Incomplete response"
        })
        with self.assertRaises(SchemaValidationError):
            self.gateway.process_alert(self.raw_event)

    def test_invalid_ai_classification(self):
        invalid_response = self.ai_response.copy()
        invalid_response["classification"] = "dangerous"
        self.mock_client.generate.return_value = json.dumps(
            invalid_response
        )
        with self.assertRaises(SchemaValidationError):
            self.gateway.process_alert(self.raw_event)

    def test_invalid_input(self):
        with self.assertRaises((SchemaValidationError, ValueError, TypeError)):
            self.gateway.process_alert(None)
        self.mock_client.generate.assert_not_called()

    def test_prompt_excludes_unrestricted_details(self):
        self.gateway.process_alert(self.raw_event)
        prompt = self.mock_client.generate.call_args.args[0]
        self.assertIn("Multiple failed SSH login attempts", prompt)
        self.assertNotIn('"details":', prompt)

if __name__ == "__main__":
    unittest.main()