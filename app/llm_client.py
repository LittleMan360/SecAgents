"""
Ollama api client for SecAgents

Handles communication with the Ollama API.
Qwen language model locally hosted.
"""

import json
import urllib.request
import urllib.error


class OllamaClientError(Exception):
    """Raised when an error occurs while communicating with the Ollama API."""


class OllamaClient:

    def __init__(
        self,
        base_url="http://127.0.0.1:11434",
        model="qwen3.5:9b",
        timeout=120
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def generate(self, prompt):
        """
        Send a prompt to Ollama and return the generated response
        """

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "think": False,
            "format": "json"
        }


        request = urllib.request.Request(
            url=f"{self.base_url}/api/generate",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )

        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout
            ) as response:
                result = json.loads(
                    response.read().decode("utf-8")
                )
                if not isinstance(result, dict):
                    raise OllamaClientError(
                        "Invalid response from Ollama"
                    )
                generated_text = result.get("response")

                if not isinstance(generated_text, str):
                    raise OllamaClientError(
                        "Ollama response is missing generated text"
                    )

                return generated_text


        except urllib.error.HTTPError as error:
            raise OllamaClientError(
                f"Ollama HTTP error: {error.code}"
            ) from error

        except urllib.error.URLError as error:
            raise OllamaClientError(
                "Unable to connect to Ollama"
            ) from error

        except TimeoutError as error:
            raise OllamaClientError(
                "Ollama request timed out"
            ) from error

        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise OllamaClientError(
                "Ollama returned invalid API response"
            ) from error