"""
LLM Integration Test Suite — GenAI Summarization Edge Cases.

Validates behaviour of the ThreatAnalyzer's executive summary generation
across four scenarios:
  1. A successful NVIDIA NIM API call returns a well-formed summary.
  2. A rate-limit / network exception falls back to the heuristic summary.
  3. An empty / blocked API response falls back to the heuristic summary.
  4. No API key is configured — GenAI is skipped entirely.

All external HTTP calls are mocked so these tests run fully offline.
"""

import os
import json
import unittest
from unittest.mock import patch, MagicMock

from core.analyzer import ThreatAnalyzer


class TestLLMSummarizationScenarios(unittest.TestCase):
    """Tests the executive summary generation path under varied LLM conditions."""

    def setUp(self):
        self.vendor = "Mandiant / Google Cloud"
        self.threat_actor = {
            "name": "APT29",
            "origin": "Russian Federation (SVR)",
            "motivation": "Espionage",
        }
        self.malware = ["Cobalt Strike", "MagicWeb"]
        self.mitre = [{"id": "T1078", "name": "Valid Accounts"}]
        self.iocs = [{"type": "ipv4", "value": "198.51.100.1"}]
        self.severity = "CRITICAL"
        self.full_text = (
            "APT29 compromised legacy testing accounts in Microsoft 365. "
            "The group minted OAuth bearer tokens to establish persistent, "
            "silent access to diplomatic communications."
        )

    # ------------------------------------------------------------------
    # Scenario 1: NVIDIA NIM call succeeds
    # ------------------------------------------------------------------
    def test_nvidia_api_success(self):
        """When NVIDIA_API_KEY is set and the API responds 200, the LLM summary is returned."""
        mock_response_body = json.dumps({
            "choices": [{"message": {"content": "LLM-generated CISO briefing."}}]
        }).encode("utf-8")

        mock_http_response = MagicMock()
        mock_http_response.__enter__ = lambda s: s
        mock_http_response.__exit__ = MagicMock(return_value=False)
        mock_http_response.status = 200
        mock_http_response.read.return_value = mock_response_body

        with patch("urllib.request.urlopen", return_value=mock_http_response):
            analyzer = ThreatAnalyzer(api_key="nvapi-fakekey123")
            summary = analyzer._generate_executive_summary(
                self.vendor, self.threat_actor, self.malware,
                self.mitre, self.iocs, self.severity, self.full_text
            )

        self.assertEqual(summary, "LLM-generated CISO briefing.")

    # ------------------------------------------------------------------
    # Scenario 2: NVIDIA NIM call raises a network / rate-limit exception
    # ------------------------------------------------------------------
    def test_nvidia_api_exception_falls_back_to_heuristic(self):
        """A network error or rate-limit exception falls back to the deterministic heuristic summary."""
        with patch("urllib.request.urlopen", side_effect=Exception("Connection refused")):
            analyzer = ThreatAnalyzer(api_key="nvapi-fakekey123")
            summary = analyzer._generate_executive_summary(
                self.vendor, self.threat_actor, self.malware,
                self.mitre, self.iocs, self.severity, self.full_text
            )

        # Heuristic summary always contains the vendor and actor name
        self.assertIn("Mandiant", summary)
        self.assertIn("APT29", summary)

    # ------------------------------------------------------------------
    # Scenario 3: Gemini client raises exception — heuristic fallback
    # ------------------------------------------------------------------
    def test_gemini_exception_falls_back_to_heuristic(self):
        """If the Gemini client raises any exception, the heuristic summary is returned."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("Quota exceeded")

        analyzer = ThreatAnalyzer.__new__(ThreatAnalyzer)
        analyzer.api_key = "AIza-fake-gemini-key"
        analyzer._gemini_client = mock_client

        summary = analyzer._generate_executive_summary(
            self.vendor, self.threat_actor, self.malware,
            self.mitre, self.iocs, self.severity, self.full_text
        )

        self.assertIn("Mandiant", summary)
        self.assertIn("APT29", summary)

    # ------------------------------------------------------------------
    # Scenario 4: No API key — GenAI is bypassed entirely
    # ------------------------------------------------------------------
    def test_no_api_key_uses_heuristic_only(self):
        """When no API key is present, the analyzer produces a heuristic summary without any API call."""
        # Strip all known API key environment variables for this test
        env_overrides = {
            "NVIDIA_API_KEY": "",
            "GEMINI_API_KEY": "",
            "OPENAI_API_KEY": "",
        }
        with patch.dict(os.environ, env_overrides):
            analyzer = ThreatAnalyzer(api_key=None)
            self.assertIsNone(analyzer._gemini_client)

            summary = analyzer._generate_executive_summary(
                self.vendor, self.threat_actor, self.malware,
                self.mitre, self.iocs, self.severity, self.full_text
            )

        self.assertIn("Mandiant", summary)
        self.assertIn("APT29", summary)
        self.assertGreater(len(summary), 50)


if __name__ == "__main__":
    unittest.main(verbosity=2)
