"""
Educational TAXII 2.1 / STIX Ingestion Client for Students & SOC Analysts.
Demonstrates how automated firewall scripts or SIEM connectors consume
threat intelligence feeds from CyberSentinel's TAXII 2.1 server.
"""

import sys
import json
import urllib.request
from typing import Dict, Any, List


def test_taxii_client(taxii_base_url: str = "http://127.0.0.1:8000/taxii2/"):
    print("=" * 70)
    print(" TAXII 2.1 Threat Ingestion Client Demo")
    print(f" Target Server: {taxii_base_url}")
    print("=" * 70)

    # 1. TAXII Server Discovery
    print("\n[Step 1] Polling TAXII 2.1 Server Discovery...")
    req = urllib.request.Request(taxii_base_url, headers={"Accept": "application/taxii+json;version=2.1"})
    try:
        with urllib.request.urlopen(req) as resp:
            discovery = json.loads(resp.read().decode())
            print(f"  [OK] Connected: {discovery.get('title')}")
            print(f"  [OK] Default API Root: {discovery.get('default')}")
    except Exception as e:
        print(f"  [!] Failed to connect to TAXII server: {e}")
        print("  Make sure the CyberSentinel server is running (python run.py)")
        return

    # 2. Get Collections
    api_root = discovery.get("default", "/taxii2/api1/")
    collections_url = f"http://127.0.0.1:8000{api_root}collections/"
    print(f"\n[Step 2] Fetching Intelligence Collections from: {collections_url}")
    req = urllib.request.Request(collections_url, headers={"Accept": "application/taxii+json;version=2.1"})
    with urllib.request.urlopen(req) as resp:
        collections = json.loads(resp.read().decode()).get("collections", [])
        for c in collections:
            print(f"  - Collection ID: {c['id']}")
            print(f"    Title:         {c['title']}")
            print(f"    Can Read:      {c['can_read']}")

    if not collections:
        print("  [!] No collections found.")
        return

    target_collection = collections[0]["id"]

    # 3. Pull STIX 2.1 Objects from Collection
    objects_url = f"http://127.0.0.1:8000{api_root}collections/{target_collection}/objects/"
    print(f"\n[Step 3] Polling STIX 2.1 Bundle from: {objects_url}")
    req = urllib.request.Request(objects_url, headers={"Accept": "application/taxii+json;version=2.1"})
    with urllib.request.urlopen(req) as resp:
        stix_bundle = json.loads(resp.read().decode())
        objects = stix_bundle.get("objects", [])
        print(f"  [OK] Received STIX 2.1 Bundle: {stix_bundle.get('id')}")
        print(f"  [OK] Total SDO/SRO Objects:    {len(objects)}")

    # 4. Filter Indicators and Simulate Firewall Ingestion
    print("\n[Step 4] Simulating Automated Perimeter Firewall Rule Ingestion...")
    indicators: List[Dict[str, Any]] = [o for o in objects if o.get("type") == "indicator"]
    threat_actors: List[Dict[str, Any]] = [o for o in objects if o.get("type") == "threat-actor"]
    actor_name = threat_actors[0].get("name", "Adversary") if threat_actors else "Adversary"

    print(f"  Attributed Threat Actor: {actor_name}")
    print(f"  Total Indicators to Ingest: {len(indicators)}")
    print("\n  --> Generated Automated Firewall Drop Policy:")
    for ind in indicators[:6]:
        pattern = ind.get("pattern", "")
        # Extract observable value from pattern e.g. [ipv4-addr:value = '198.51.100.45']
        val = pattern.split("'")[1] if "'" in pattern else pattern
        name = ind.get("name", "Indicator")
        print(f"      [FIREWALL ACTION: DROP]  {name:<36}  Pattern: {pattern}")

    print("\n[OK] TAXII 2.1 synchronization completed successfully.")
    print("=" * 70)


if __name__ == "__main__":
    test_taxii_client()
