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