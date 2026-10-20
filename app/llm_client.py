"""Client for the isolated SecAgents Ollama model."""

import json
import os
import socket
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class OllamaError(Exception):
    """Controlled model failure with a stable code."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class OllamaClient:
    """Synchronous, tool-free communication with local Ollama."""

    def __init__(self, base_url=None, model=None, timeout=120):
        self.base_url = (base_url or os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen3.5:9b")
        if not (self.base_url.startswith("http://127.0.0.1:") or self.base_url.startswith("http://localhost:")):
            raise ValueError("Ollama endpoint must be on localhost.")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError("timeout must be a positive number")
        self.timeout = timeout

    def generate(self, prompt):
        """Return Ollama response text; callers validate its JSON schema."""
        if not isinstance(prompt, str) or not prompt.strip():
            raise OllamaError("INVALID_INPUT", "Prompt must be nonempty text.")
        payload = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "format": "json",
        }).encode("utf-8")
        request = Request(
            f"{self.base_url}/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout) as response:
                body = response.read(1024 * 1024 + 1)
            if len(body) > 1024 * 1024:
                raise OllamaError("INVALID_AI_RESPONSE", "Model response exceeded size limit.")
            result = json.loads(body)
            answer = result.get("response") if isinstance(result, dict) else None
            if not isinstance(answer, str) or not answer.strip():
                raise OllamaError("INVALID_AI_RESPONSE", "Model returned no response text.")
            return answer
        except HTTPError as exc:
            raise OllamaError("MODEL_UNAVAILABLE", f"Ollama returned HTTP {exc.code}.") from exc
        except (TimeoutError, socket.timeout) as exc:
            raise OllamaError("MODEL_TIMEOUT", "Ollama did not respond before the timeout.") from exc
        except URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise OllamaError("MODEL_TIMEOUT", "Ollama did not respond before the timeout.") from exc
            raise OllamaError("MODEL_UNAVAILABLE", "Cannot connect to local Ollama.") from exc
        except (ValueError, UnicodeDecodeError) as exc:
            raise OllamaError("INVALID_AI_RESPONSE", "Ollama returned invalid JSON.") from exc
