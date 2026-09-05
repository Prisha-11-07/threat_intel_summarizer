"""
Headless Command-Line Interface (CLI) for Threat Intelligence Automation.
Enables headless SOC batch processing, SOAR integration, and automated CI/CD runs.
"""

import os
import sys
import json
import argparse
from typing import List, Dict, Any

# Ensure parent directory is in path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from core.pdf_parser import ThreatReportParser
from core.extractor import IoCExtractor
from core.analyzer import ThreatAnalyzer
from exporters.stix_generator import STIX21Generator
from exporters.firewall_rules import FirewallRuleGenerator


def run_pipeline(pdf_path: str, verbose: bool = False) -> Dict[str, Any]:
    """Executes the full parsing, extraction, and synthesis pipeline on a given PDF."""
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"PDF report not found at: {pdf_path}")

    parser = ThreatReportParser()
    extractor = IoCExtractor()
    analyzer = ThreatAnalyzer()
    stix_gen = STIX21Generator()
    fw_gen = FirewallRuleGenerator()

    if verbose:
        print(f"[*] Reading and sanitizing PDF document: {pdf_path}")
    doc = parser.parse_pdf(pdf_path)

    if verbose:
        print(f"[*] Extracting indicators across {doc['total_pages']} page(s)...")
    all_iocs: List[Dict[str, Any]] = []
    for page in doc["pages"]:
        page_iocs = extractor.extract_from_text(page["text"], page_num=page["page_number"])
        all_iocs.extend(page_iocs)

    # Deduplicate indicators
    unique_iocs: List[Dict[str, Any]] = []
    seen = set()
    for i in all_iocs:
        key = (i["type"], i["value"].lower())
        if key not in seen:
            seen.add(key)
            unique_iocs.append(i)

    if verbose:
        print(f"[*] Synthesizing adversary methodology, Kill Chain, and MITRE mapping...")
    analysis = analyzer.analyze(doc, unique_iocs)

    if verbose:
        print(f"[*] Building OASIS STIX 2.1 bundle...")
    stix_bundle = stix_gen.build_bundle(analysis, unique_iocs)

    actor_name = analysis.get("threat_actor", {}).get("name", "Adversary")
    if verbose:
        print(f"[*] Synthesizing firewall configurations for: {actor_name}...")
    firewall_configs = fw_gen.generate_all(unique_iocs, actor_name)

    return {
        "doc": doc,
        "analysis": analysis,
        "iocs": unique_iocs,
        "stix_bundle": stix_bundle,
        "firewall_rules": firewall_configs
    }


def print_cli_summary(results: Dict[str, Any]):
    """Prints a structured ASCII terminal dashboard of the analysis."""
    analysis = results["analysis"]
    actor = analysis.get("threat_actor", {})
    iocs = results["iocs"]

    print("\n" + "=" * 76)
    print(" CYBERSENTINEL // SOC THREAT INTELLIGENCE ANALYSIS REPORT")
    print("=" * 76)
    print(f" Source Document:   {results['doc']['metadata'].get('title', 'Advisory')}")
    print(f" Reporting Vendor:  {results['doc']['vendor']} | TLP: {results['doc']['tlp']}")
    print(f" Total Pages:       {results['doc']['total_pages']}")
    print("-" * 76)
    print(f" Threat Actor:      {actor.get('name', 'Unknown')} ({actor.get('origin', 'N/A')})")
    print(f" Aliases:           {', '.join(actor.get('aliases', [])) or 'None'}")
    print(f" Motivation:        {actor.get('motivation', 'N/A')}")
    print(f" SOC Severity:      {analysis.get('severity', 'HIGH')} (Risk Score: {analysis.get('risk_score', 'N/A')}/100)")
    print(f" Targeted Sectors:  {', '.join(analysis.get('targeted_sectors', []))}")
    print(f" Malware / Tools:   {', '.join(analysis.get('malware_families', []))}")
    print("-" * 76)
    print(f" Total IoCs:        {len(iocs)} indicators extracted & verified")

    # Counts by type
    counts: Dict[str, int] = {}
    for i in iocs:
        counts[i["type"]] = counts.get(i["type"], 0) + 1
    type_str = " | ".join([f"{k.upper()}: {v}" for k, v in counts.items()])
    print(f" Breakdown:         {type_str}")

    print("\n[+] EXECUTIVE BRIEFING:")
    print(f"    {analysis.get('executive_summary', 'N/A')}")

    print("\n[+] MITRE ATT&CK TECHNIQUES DETECTED:")
    for t in analysis.get("mitre_attack", [])[:6]:
        print(f"    - {t['id']:<10} {t['name']:<32} [{t['tactic']}]")

    print("\n[+] SAMPLE INDICATORS OF COMPROMISE (DEFANGED):")
    for i in iocs[:8]:
        print(f"    - {i['type'].upper():<10} {i.get('defanged', i['value']):<36} ({i.get('role', 'Indicator')})")

    if len(iocs) > 8:
        print(f"      ... and {len(iocs) - 8} more indicators.")
    print("=" * 76 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="CyberSentinel: Headless Threat Intelligence Parser, STIX 2.1 & Firewall Exporter."
    )
    parser.add_argument("pdf_path", help="Path to threat intelligence PDF report")
    parser.add_argument("--stix", help="Path to write output STIX 2.1 JSON bundle (e.g. output_stix.json)")
    parser.add_argument("--firewall-dir", help="Directory to export firewall configurations into")
    parser.add_argument("--summary", action="store_true", default=True, help="Print terminal summary report")
    parser.add_argument("--quiet", action="store_true", help="Suppress terminal banner output")

    args = parser.parse_args()

    try:
        results = run_pipeline(args.pdf_path, verbose=not args.quiet)

        if args.summary and not args.quiet:
            print_cli_summary(results)

        # Export STIX 2.1 JSON
        if args.stix:
            stix_file = os.path.abspath(args.stix)
            os.makedirs(os.path.dirname(stix_file) or ".", exist_ok=True)
            with open(stix_file, "w", encoding="utf-8") as f:
                json.dump(results["stix_bundle"], f, indent=2)
            print(f"[OK] Exported OASIS STIX 2.1 JSON bundle -> {stix_file}")

        # Export Firewall configs
        if args.firewall_dir:
            fw_dir = os.path.abspath(args.firewall_dir)
            os.makedirs(fw_dir, exist_ok=True)
            rules = results["firewall_rules"]

            ext_map = {
                "suricata": "suricata.rules",
                "palo_alto": "palo_alto_commands.txt",
                "fortigate": "fortigate_policy.txt",
                "cisco_asa": "cisco_asa_acl.txt",
                "iptables": "iptables.sh",
                "zeek": "zeek_intel.dat",
                "siem_csv": "siem_lookup.csv",
                "edr_hashes": "edr_hashes.csv"
            }

            for rule_type, rule_content in rules.items():
                out_name = ext_map.get(rule_type, f"{rule_type}.txt")
                out_file = os.path.join(fw_dir, out_name)
                with open(out_file, "w", encoding="utf-8") as f:
                    f.write(rule_content)

            print(f"[OK] Exported {len(rules)} firewall/SIEM configurations -> {fw_dir}")

    except Exception as e:
        print(f"[!] Error: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
