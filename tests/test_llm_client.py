"""
Unit tests for the Ollama API client

These tests are designed to simulate various responses
without running the ai server.
"""

import json
import unittest
import urllib.error

from unittest.mock import patch, MagicMock
from app.llm_client import OllamaClient, OllamaClientError

class TestOllamaClient(unittest.TestCase):

    def setUp(self):
        self.client = OllamaClient(
            base_url="http://127.0.0.1:11434",
            model="qwen3.5:9b",
            timeout=120
        )

    @patch("urllib.request.urlopen")
    def test_successful_response(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "model": "qwen3.5:9b",
            "response": '{"summary": "Test alert detected"}',
            "done": True
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response
        result = self.client.generate(
            "Analyze this security alert."
        )

        self.assertEqual(
            result,
            '{"summary": "Test alert detected"}'
        )

        request = mock_urlopen.call_args.args[0]
        payload = json.loads(request.data.decode("utf-8"))
        self.assertEqual(payload["model"], "qwen3.5:9b")
        self.assertEqual(payload["format"], "json")
        self.assertFalse(payload["stream"])
        self.assertFalse(payload["think"])

    @patch("urllib.request.urlopen")
    def test_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = urllib.error.URLError(
            "Connection refused"
        )
        with self.assertRaises(OllamaClientError):
            self.client.generate("Test prompt")

    @patch("urllib.request.urlopen")
    def test_request_timeout(self, mock_urlopen):
        mock_urlopen.side_effect = TimeoutError(
            "Request timed out"
        )
        with self.assertRaises(OllamaClientError):
            self.client.generate("Test prompt")

    @patch("urllib.request.urlopen")
    def test_invalid_api_json(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = b"not valid json"
        mock_urlopen.return_value.__enter__.return_value = mock_response
        with self.assertRaises(OllamaClientError):
            self.client.generate("Test prompt")

    @patch("urllib.request.urlopen")
    def test_missing_response_field(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "model": "qwen3.5:9b",
            "done": True
        }).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_response
        with self.assertRaises(OllamaClientError):
            self.client.generate("Test prompt")

if __name__ == "__main__":
    unittest.main()