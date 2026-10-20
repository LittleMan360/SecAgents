"""Offline tests for local Ollama integration."""
import io
import socket
import unittest
from unittest.mock import patch
from urllib.error import URLError
from app.llm_client import OllamaClient, OllamaError

class FakeResponse:
    def __init__(self, payload):
        self.stream = io.BytesIO(payload)
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def read(self, size):
        return self.stream.read(size)

class TestOllamaClient(unittest.TestCase):
    def setUp(self):
        self.client = OllamaClient(model="qwen3.5:9b")
    @patch("app.llm_client.urlopen")
    def test_success(self, opener):
        opener.return_value = FakeResponse(b'{"response":"test"}')
        self.assertEqual(self.client.generate("Synthetic alert"), "test")
        request = opener.call_args.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:11434/api/generate")
        self.assertIn(b'"stream": false', request.data)
    @patch("app.llm_client.urlopen", side_effect=URLError("refused"))
    def test_connection_failure(self, _):
        with self.assertRaises(OllamaError) as error:
            self.client.generate("Test")
        self.assertEqual(error.exception.code, "MODEL_UNAVAILABLE")
    @patch("app.llm_client.urlopen", side_effect=socket.timeout("timeout"))
    def test_timeout(self, _):
        with self.assertRaises(OllamaError) as error:
            self.client.generate("Test")
        self.assertEqual(error.exception.code, "MODEL_TIMEOUT")
    @patch("app.llm_client.urlopen")
    def test_invalid_response(self, opener):
        opener.return_value = FakeResponse(b'not-json')
        with self.assertRaises(OllamaError) as error:
            self.client.generate("Test")
        self.assertEqual(error.exception.code, "INVALID_AI_RESPONSE")
    def test_empty_prompt(self):
        with self.assertRaises(OllamaError) as error:
            self.client.generate(" ")
        self.assertEqual(error.exception.code, "INVALID_INPUT")
    def test_external_address_rejected(self):
        with self.assertRaises(ValueError):
            OllamaClient(base_url="http://example.com:11434")

if __name__ == "__main__":
    unittest.main()
