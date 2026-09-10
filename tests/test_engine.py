"""
Comprehensive Automated Unit Test Suite for Threat Intel Engine.
Tests extraction, defanging/refanging, multi-page PDF parsing,
STIX 2.1 JSON validation, and firewall rule synthesis.
"""

import os
import unittest
from core.extractor import IoCExtractor
from core.pdf_parser import ThreatReportParser
from core.analyzer import ThreatAnalyzer
from exporters.stix_generator import STIX21Generator
from exporters.firewall_rules import FirewallRuleGenerator


class TestThreatIntelEngine(unittest.TestCase):

    def setUp(self):
        self.extractor = IoCExtractor()
        self.pdf_parser = ThreatReportParser()
        self.analyzer = ThreatAnalyzer()
        self.stix_gen = STIX21Generator()
        self.firewall_gen = FirewallRuleGenerator()

        # Path to sample reports
        self.samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples", "reports"))
        self.cisa_sample = os.path.join(self.samples_dir, "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf")

    def test_refang_and_defang(self):
        """Tests refanging of obscured threat indicators and defanging."""
        raw_defanged = "hxxps://malicious-domain[.]com/drop/bin?ip=192[.]0[.]2[.]1&mail=bad[@]phish[.]net"
        refanged = IoCExtractor.refang(raw_defanged)
        self.assertEqual(refanged, "https://malicious-domain.com/drop/bin?ip=192.0.2.1&mail=bad@phish.net")

        # Test defanging
        self.assertEqual(IoCExtractor.defang("198.51.100.1", "ipv4"), "198[.]51[.]100[.]1")
        self.assertEqual(IoCExtractor.defang("https://bad.org", "url"), "hxxps://bad[.]org")
        self.assertEqual(IoCExtractor.defang("evil@phish.com", "email"), "evil[@]phish[.]com")

    def test_ioc_extraction(self):
        """Tests regex and rule-based extraction across all supported IoC types."""
        sample_text = """
        The threat actor connected to C2 node 198.51.100.45 and secondary IP 203.0.113.19.
        Malicious beaconing observed to domain vpn-telemetry-sync.com and URL hxxp://vpn-telemetry-sync[.]com/api/v1/health.
        Stage-1 binary hash is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 (SHA-256).
        Legacy implant md5 is d41d8cd98f00b204e9800998ecf8427e.
        Persistence was configured via HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\VoltSvc.
        The attackers exploited CVE-2023-46805 and CVE-2024-21887 using PowerShell T1059.001.
        Phishing email sender was admin@attacker-lure.org.
        The Windows path C:\\Users\\Public\\Downloads\\VoltSvc.exe was dropped to disk.
        """
        iocs = self.extractor.extract_from_text(sample_text, page_num=1)
        ioc_types = {ioc["type"] for ioc in iocs}

        self.assertIn("ipv4", ioc_types)
        self.assertIn("domain", ioc_types)
        self.assertIn("url", ioc_types)
        self.assertIn("sha256", ioc_types)
        self.assertIn("md5", ioc_types)
        self.assertIn("registry", ioc_types)
        self.assertIn("cve", ioc_types)
        self.assertIn("mitre", ioc_types)
        self.assertIn("email", ioc_types)
        self.assertIn("file_path", ioc_types)

        # Value specific checks
        extracted_ips = [i["value"] for i in iocs if i["type"] == "ipv4"]
        self.assertIn("198.51.100.45", extracted_ips)

        extracted_cves = [i["value"] for i in iocs if i["type"] == "cve"]
        self.assertIn("CVE-2023-46805", extracted_cves)

        extracted_keys = [i["value"] for i in iocs if i["type"] == "registry"]
        self.assertIn("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\VoltSvc", extracted_keys)

        file_paths = [i["value"] for i in iocs if i["type"] == "file_path"]
        self.assertIn(r"C:\Users\Public\Downloads\VoltSvc.exe", file_paths)

        normalized = [i for i in iocs if i["type"] == "domain" and i["value"] == "vpn-telemetry-sync.com"]
        self.assertTrue(normalized)
        self.assertIn("normalized_value", normalized[0])
        self.assertIn("defanged_value", normalized[0])
        self.assertIn("validation_status", normalized[0])
        self.assertIn("source_page", normalized[0])
        self.assertIn("source_text", normalized[0])
        self.assertIn("operational_role", normalized[0])

    def test_ioc_validation_and_normalization(self):
        """Ensures normalized IoCs are validated and deduplicated consistently."""
        text = """
        The malware reached 192[.]168[.]1[.]10 and evil[.]com. Another reference to evil.com appears on page 3.
        Malicious hash 5d41402abc4b2a76b9719d911017c592 and CVE-2024-12345 were seen.
        """
        iocs = self.extractor.extract_from_text(text, page_num=2)
        domains = [ioc for ioc in iocs if ioc["type"] == "domain"]
        private_ips = [ioc for ioc in iocs if ioc["type"] == "ipv4"]

        self.assertTrue(any(ioc["normalized_value"] == "evil.com" for ioc in domains))
        self.assertTrue(any(ioc["defanged_value"] == "evil.com" for ioc in domains))
        self.assertTrue(any(ioc["validation_status"] == "PRIVATE" for ioc in private_ips))
        self.assertTrue(any(ioc["validation_status"] in {"VALID", "SUSPICIOUS"} for ioc in domains))

    def test_ioc_phase3_provenance_and_enforcement_status(self):
        """Private, malformed, and repeated indicators retain safe provenance semantics."""
        text = "Private 192.168.1.10 and malformed 999.1.1.1; evil[.]com evil.com."
        page_two = self.extractor.extract_from_text(text, page_num=2)
        page_three = self.extractor.extract_from_text(text, page_num=3)
        iocs = self.extractor.deduplicate_iocs(page_two + page_three)

        private_ip = next(i for i in iocs if i["normalized_value"] == "192.168.1.10")
        malformed_ip = next(i for i in iocs if i["normalized_value"] == "999.1.1.1")
        domain = next(i for i in iocs if i["normalized_value"] == "evil.com")

        self.assertEqual(private_ip["validation_status"], "PRIVATE")
        self.assertEqual(malformed_ip["validation_status"], "INVALID")
        self.assertEqual(domain["occurrences"], 4)
        self.assertEqual(domain["source_pages"], [2, 3])

        rules = self.firewall_gen.generate_all(iocs, "Test Actor")
        self.assertNotIn("192.168.1.10", rules["iptables"])
        self.assertNotIn("999.1.1.1", rules["iptables"])

    def test_pdf_parsing_on_sample(self):
        """Tests parsing of multi-page CISA Volt Typhoon PDF report."""
        self.assertTrue(os.path.exists(self.cisa_sample), f"Sample report not found at {self.cisa_sample}")

        doc = self.pdf_parser.parse_pdf(self.cisa_sample)
        self.assertGreater(doc["total_pages"], 1, "Report should be multi-page")
        self.assertEqual(doc["vendor"], "CISA", "Vendor should be detected as CISA")
        self.assertIn("Volt Typhoon", doc["full_text"])

    def test_threat_analysis_pipeline(self):
        """Tests synthesis of attack methodology, MITRE ATT&CK mapping, and severity scoring."""
        doc = self.pdf_parser.parse_pdf(self.cisa_sample)

        all_iocs = []
        for p in doc["pages"]:
            all_iocs.extend(self.extractor.extract_from_text(p["text"], page_num=p["page_number"]))

        # Deduplicate
        unique_iocs = []
        seen = set()
        for i in all_iocs:
            k = (i["type"], i["value"].lower())
            if k not in seen:
                seen.add(k)
                unique_iocs.append(i)

        analysis = self.analyzer.analyze(doc, unique_iocs)

        self.assertIn(analysis["analysis_status"], {"completed", "unavailable"})
        self.assertIn("threat_actor", analysis)
        self.assertIn("targeted_sectors", analysis)
        self.assertIn("severity", analysis)
        self.assertIn("mitre_attack", analysis)
        self.assertIn("recommended_soc_actions", analysis)

    def test_structured_genai_response_normalization(self):
        """Provider JSON is normalized to the existing dashboard contract."""
        result = self.analyzer._normalize_genai_analysis({
            "executive_summary": "Evidence-based summary",
            "threat_actor": {"name": "Example Group", "aliases": ["Alias"], "confidence": 80},
            "malware_tools": ["Example Tool"],
            "vulnerabilities": [{"id": "CVE-2024-0001"}],
            "targeted_sectors": ["Energy"],
            "attack_methodology": "Initial access followed by persistence",
            "kill_chain": [{"phase": "Initial Access", "evidence": ["Report evidence"]}],
            "mitre_attack": [{"id": "T1190", "name": "Exploit Public-Facing Application"}],
            "severity": {"level": "HIGH", "score": 120, "rationale": "Evidence"},
            "recommended_soc_actions": [{"category": "Triage", "action": "Investigate", "priority": "P1"}],
        }, "Test Vendor", "Test Report", [])
        self.assertEqual(result["threat_actor"]["name"], "Example Group")
        self.assertEqual(result["risk_score"], 100)
        self.assertEqual(result["kill_chain"][0]["phase"], "Initial Access")

    def test_dynamic_mitre_and_risk_scoring(self):
        """ATT&CK metadata and score are derived from explicit evidence."""
        report = {"full_text": "", "vendor": "Test", "metadata": {"title": "Test"}}
        iocs = [{
            "type": "mitre", "value": "T1190", "normalized_value": "T1190",
            "source_page": 4, "source_text": "The exposed edge appliance was exploited.",
            "validation_status": "VALID"
        }]
        result = self.analyzer._normalize_genai_analysis({
            "mitre_attack": [{"id": "T1190", "evidence": "Exposed edge appliance", "source_page": 2}],
            "severity": {"level": "CRITICAL", "score": 100},
            "threat_actor": {"confidence": 0},
        }, "Test", "Test", iocs)
        result["mitre_attack"] = self.analyzer._normalize_mitre_techniques(result["mitre_attack"], report, iocs)
        result["severity"], result["risk_score"], result["risk_factors"] = self.analyzer._calculate_dynamic_risk(result, iocs)
        technique = result["mitre_attack"][0]
        self.assertEqual(technique["source_page"], 2)
        self.assertTrue(technique["evidence"])
        self.assertTrue(technique["mitigation"])
        self.assertEqual(result["risk_score"], 6)

    def test_stix21_bundle_generation(self):
        """Tests generation and schema compliance of OASIS STIX 2.1 JSON bundle."""
        doc = self.pdf_parser.parse_pdf(self.cisa_sample)
        iocs = self.extractor.extract_from_text(doc["full_text"], page_num=1)
        analysis = self.analyzer.analyze(doc, iocs)

        bundle = self.stix_gen.build_bundle(analysis, iocs)

        self.assertEqual(bundle["type"], "bundle")
        self.assertTrue(bundle["id"].startswith("bundle--"))
        self.assertIsInstance(bundle["objects"], list)
        self.assertGreater(len(bundle["objects"]), 0)

        # Check for core STIX 2.1 SDO types
        types_in_bundle = {obj["type"] for obj in bundle["objects"]}
        self.assertIn("identity", types_in_bundle)
        self.assertIn("threat-actor", types_in_bundle)
        self.assertIn("indicator", types_in_bundle)
        self.assertIn("report", types_in_bundle)
        self.assertIn("vulnerability", types_in_bundle)
        if analysis.get("analysis_status") == "completed":
            self.assertIn("attack-pattern", types_in_bundle)
        self.assertIn("relationship", types_in_bundle)
        validation = self.stix_gen.validate_bundle(bundle)
        self.assertTrue(validation["valid"], validation["errors"])

        # Check STIX 2.1 Pattern Language formatting
        indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
        for ind in indicators:
            self.assertEqual(ind["pattern_version"], "2.1")
            self.assertEqual(ind["pattern_type"], "stix")
            self.assertTrue(ind["pattern"].startswith("[") and ind["pattern"].endswith("]"))

    def test_stix_bundle_validation_rejects_broken_reference(self):
        """Validation must block bundles with unresolved relationship references."""
        validation = self.stix_gen.validate_bundle({
            "type": "bundle",
            "id": "bundle--00000000-0000-0000-0000-000000000000",
            "objects": [{
                "type": "relationship",
                "spec_version": "2.1",
                "id": "relationship--00000000-0000-0000-0000-000000000000",
                "created": "2026-01-01T00:00:00.000Z",
                "modified": "2026-01-01T00:00:00.000Z",
                "relationship_type": "uses",
                "source_ref": "threat-actor--00000000-0000-0000-0000-000000000001",
                "target_ref": "malware--00000000-0000-0000-0000-000000000002"
            }]
        })
        self.assertFalse(validation["valid"])
        self.assertTrue(any("does not resolve" in error for error in validation["errors"]))

    def test_firewall_rule_generation(self):
        """Tests generation of firewall rules for Palo Alto, Fortigate, Cisco, and Suricata."""
        iocs = [
            {"type": "ipv4", "value": "198.51.100.45", "role": "C2 Server", "confidence": "High"},
            {"type": "domain", "value": "vpn-telemetry-sync.com", "role": "C2 Domain", "confidence": "High"},
            {"type": "url", "value": "http://vpn-telemetry-sync.com/api/v1/health", "role": "Beacon", "confidence": "High"},
            {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "role": "Payload", "confidence": "High"}
        ]
        rules = self.firewall_gen.generate_all(iocs, "Volt Typhoon")

        self.assertIn("Suricata", rules["suricata"])
        self.assertIn("drop ip any any", rules["suricata"])
        self.assertIn("198.51.100.45", rules["suricata"])

        self.assertIn("Palo Alto", rules["palo_alto"])
        self.assertIn("set address", rules["palo_alto"])

        self.assertIn("Fortinet FortiGate", rules["fortigate"])
        self.assertIn("config firewall address", rules["fortigate"])

        self.assertIn("Cisco ASA", rules["cisco_asa"])
        self.assertIn("network-object host 198.51.100.45", rules["cisco_asa"])

        self.assertIn("iptables", rules["iptables"])
        self.assertIn("Intel::ADDR", rules["zeek"])
        self.assertIn("indicator,type", rules["siem_csv"])

    def test_taxii_collection_objects(self):
        """Tests TAXII 2.1 collection objects format and response."""
        from app.main import get_or_create_default_taxii_bundle
        bundle = get_or_create_default_taxii_bundle()
        self.assertEqual(bundle.get("type"), "bundle")
        self.assertGreater(len(bundle.get("objects", [])), 0)
        types = {o["type"] for o in bundle.get("objects", [])}
        self.assertIn("indicator", types)
        self.assertIn("threat-actor", types)


if __name__ == "__main__":
    unittest.main()
