import os
import unittest
from unittest.mock import patch, MagicMock

from core.analyzer import ThreatAnalyzer

class TestGeminiScenarios(unittest.TestCase):
    def setUp(self):
        self.vendor = "TestVendor"
        self.threat_actor = {"name": "TestActor", "origin": "TestOrigin"}
        self.malware = ["Malware1"]
        self.mitre = [{"id": "T1000", "name": "Test Technique"}]
        self.iocs = [{"type": "ipv4", "value": "1.1.1.1"}]
        self.severity = "CRITICAL"
        self.full_text = "This is a very long PDF report text..."

    @patch('core.analyzer.genai')
    @patch.dict(os.environ, {'GEMINI_API_KEY': 'fake_key'})
    def test_successful_gemini_call(self, mock_genai):
        # Setup mock
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "This is a brilliantly generated AI summary."
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        analyzer = ThreatAnalyzer(api_key="fake_key")
        summary = analyzer._generate_executive_summary(
            self.vendor, self.threat_actor, self.malware, self.mitre, self.iocs, self.severity, self.full_text
        )
        self.assertEqual(summary, "This is a brilliantly generated AI summary.")
        mock_model.generate_content.assert_called_once()

    @patch('core.analyzer.genai')
    @patch.dict(os.environ, {'GEMINI_API_KEY': 'fake_key'})
    def test_api_exception_fallback(self, mock_genai):
        # Setup mock to raise Exception
        mock_model = MagicMock()
        mock_model.generate_content.side_effect = Exception("API Rate Limit Exceeded")
        mock_genai.GenerativeModel.return_value = mock_model
        
        analyzer = ThreatAnalyzer(api_key="fake_key")
        summary = analyzer._generate_executive_summary(
            self.vendor, self.threat_actor, self.malware, self.mitre, self.iocs, self.severity, self.full_text
        )
        # Should fallback to heuristic summary
        self.assertIn("This threat intelligence advisory from TestVendor", summary)
        self.assertIn("TestActor", summary)

    @patch('core.analyzer.genai')
    @patch.dict(os.environ, {'GEMINI_API_KEY': 'fake_key'})
    def test_empty_response_fallback(self, mock_genai):
        # Setup mock to return blocked response (no text)
        mock_model = MagicMock()
        mock_response = MagicMock()
        mock_response.text = None
        mock_model.generate_content.return_value = mock_response
        mock_genai.GenerativeModel.return_value = mock_model
        
        analyzer = ThreatAnalyzer(api_key="fake_key")
        summary = analyzer._generate_executive_summary(
            self.vendor, self.threat_actor, self.malware, self.mitre, self.iocs, self.severity, self.full_text
        )
        # Should fallback
        self.assertIn("This threat intelligence advisory from TestVendor", summary)

    @patch('core.analyzer.genai')
    def test_no_api_key_fallback(self, mock_genai):
        # Ensure no api key is present
        if 'GEMINI_API_KEY' in os.environ:
            del os.environ['GEMINI_API_KEY']
        if 'OPENAI_API_KEY' in os.environ:
            del os.environ['OPENAI_API_KEY']

        analyzer = ThreatAnalyzer(api_key=None)
        summary = analyzer._generate_executive_summary(
            self.vendor, self.threat_actor, self.malware, self.mitre, self.iocs, self.severity, self.full_text
        )
        self.assertIn("This threat intelligence advisory from TestVendor", summary)
        mock_genai.GenerativeModel.assert_not_called()

if __name__ == '__main__':
    unittest.main()
