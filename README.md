# CyberSentinel // Automated Threat Intelligence Report Summarizer & Indicator Extractor

> **Transforming dense, unstructured cybersecurity vendor PDF reports into immediate, actionable firewall & STIX 2.1 defense configurations.**

---

## Overview & The SOC Challenge

Security Operations Centers (SOCs) and Threat Intelligence teams receive dozens of text-heavy, multi-page PDF advisories each week from global cybersecurity vendors (e.g., CISA, Mandiant, CrowdStrike, Palo Alto Unit 42, Microsoft Defender Threat Intelligence).

**The Challenge:**
1. **Unstructured & Dense Content:** Critical attack vectors, malware families, and living-off-the-land techniques are buried in 10–50 pages of narrative prose.
2. **Defanged & Incompatible Formats:** Indicators of Compromise (IoCs) are published in defanged formats (`hxxp://`, `198[.]51[.]100[.]1`, `evil[@]phish[.]org`) that require manual parsing, refanging, and validation before firewall ingestion.
3. **Slow Triage-to-Defense Gap:** Converting a PDF report into firewall drop rules and SIEM lookup tables manually can take hours, during which an ongoing campaign can spread laterally.

**The Solution:**
**CyberSentinel** provides an automated GenAI and NLP pipeline that ingests multi-page PDFs, summarizes adversary attack methodologies mapped to MITRE ATT&CK tactics, extracts structured IoCs (IPs, domains, URLs, hashes, registry keys, CVEs), and generates:
- **Standardized OASIS STIX 2.1 JSON Bundles** for TAXII and SOAR ingestion.
- **Direct Firewall & IDS Configurations** (Palo Alto, Fortinet FortiGate, Cisco ASA, Linux iptables, Suricata / Snort 3, Zeek Intel, SIEM CSVs).

---

## Core Capabilities

### 1. Multi-Page PDF Document Ingestion
- Extracts full text across all pages while preserving page numbering and provenance.
- Automatically identifies vendor branding (CISA, Mandiant, CrowdStrike, Unit 42, Microsoft, Trend Micro) and Traffic Light Protocol (TLP) markings.

### 2. Hybrid NLP & GenAI Extraction Engine
- **Named Entity Recognition (NER):** Uses `spacy` to dynamically identify Contextual Threat Entities (Organizations, Geographies, Threat Actors).
- **GenAI Summarization:** Integrates Google's `gemini-1.5-flash` LLM to read the entire parsed text and draft targeted CISO-level executive summaries.
- **Auto Refanging / Defanging:** Converts obfuscated indicators back into operational formats while allowing safe defanged viewing.
- **Indicators of Compromise (IoCs):**
  - **Network:** IPv4, IPv6, Domains, FQDNs, URLs/URIs, Email addresses.
  - **Host & Binaries:** MD5, SHA-1, SHA-256, SHA-512 hashes.
  - **Persistence:** Windows Registry Run keys (`HKLM`, `HKCU`).
  - **Vulnerabilities:** Exploited CVE identifiers.
  - **Techniques:** MITRE ATT&CK Technique IDs (`T1190`, `T1059.001`, etc.).
- **Context Attribution & Confidence:** Attaches snippet context and calculates confidence ratings (`High`, `Medium`).

### 3. Attack Methodology & MITRE ATT&CK Mapping
- **Threat Actor Profiling:** Attributions for Volt Typhoon, APT29, Lazarus Group, Sandworm, FIN7, Scattered Spider, etc.
- **Cyber Kill-Chain Synthesis:** 7-stage operational progression (Initial Access -> Execution -> Persistence -> Defense Evasion -> Credential Access -> C2 -> Exfiltration).
- **Targeted Sectors:** Critical Infrastructure, Financial Services, Energy, Defense, Healthcare, Telecommunications.

### 4. OASIS STIX 2.1 & TAXII 2.1 Standardized Feed
- Fully compliant with OASIS STIX 2.1 specifications:
  - `identity`, `threat-actor`, `malware`, `attack-pattern`, `vulnerability`, `indicator`, `relationship`.
  - Native STIX Pattern Language: `[ipv4-addr:value = '...']`, `[file:hashes.'SHA-256' = '...']`.
- **Integrated TAXII 2.1 Server Endpoints:**
  - `GET /taxii2/` - Server Discovery
  - `GET /taxii2/api1/collections/` - Intelligence Collections
  - `GET /taxii2/api1/collections/{id}/objects/` - Live STIX 2.1 Bundle query for firewalls and TIPs.

### 5. Multi-Vendor Firewall & Defensive Ingestion
- **Suricata / Snort 3:** Ready-to-deploy IDS/IPS drop and alert rules with dynamic SIDs.
- **Palo Alto Networks (PAN-OS):** CLI address objects, address-groups, and custom URL categories.
- **Fortinet FortiGate:** FortiOS address object scripts and policy deny rules.
- **Cisco ASA / Firepower:** Object-group and perimeter access-list statements.
- **Linux iptables:** Drop commands for ingress/egress boundaries.
- **Zeek (Bro):** Tab-delimited `intel.dat` for the Zeek Intelligence Framework.
- **SIEM & EDR:** CSV lookup format for Splunk, Elastic, Sentinel, and CrowdStrike hash blocklists.

### 6. Headless CLI Tooling for SOC Batch Automation
- Run headless extraction and firewall synthesis directly from your terminal or CI/CD pipelines:
  ```powershell
  python cli.py report.pdf --stix out_stix.json --firewall-dir ./rules
  ```

---

## Project Structure

```
threat_intel_summarizer/
├── app/
│   ├── __init__.py
│   └── main.py                     # FastAPI server and REST endpoints
├── core/
│   ├── __init__.py
│   ├── pdf_parser.py               # Multi-page PDF parser & vendor detector
│   ├── extractor.py                # Regex & NER IoC extractor, defanger/refanger
│   └── analyzer.py                 # Threat attribution, MITRE & Kill Chain analyzer
├── exporters/
│   ├── __init__.py
│   ├── stix_generator.py           # OASIS STIX 2.1 JSON bundle generator
│   └── firewall_rules.py           # Multi-vendor firewall & IDS script synthesizer
├── samples/
│   ├── __init__.py
│   ├── generate_samples.py         # Generates CISA, Mandiant & CrowdStrike PDFs
│   └── reports/                    # Generated authentic multi-page test PDFs
├── static/
│   ├── index.html                  # Cyber dark-mode SOC analyst web dashboard
│   ├── css/styles.css              # Custom styling
│   └── js/app.js                   # Frontend controller and export routines
├── tests/
│   ├── __init__.py
│   └── test_engine.py              # Automated test suite (100% pass)
├── requirements.txt
└── run.py                          # One-click launcher script
```

---

## Quickstart Guide

### 1. Install Dependencies & NLP Models
```powershell
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

*(Optional)* For Advanced GenAI Summaries, set your Google Gemini API Key:
```powershell
export GEMINI_API_KEY="your_api_key_here"
```

### 2. Run Automated Test Suite
```powershell
PYTHONPATH=. python -m unittest tests.test_engine
```

### 3. Launch CyberSentinel Web Console
```powershell
python run.py
```
Open your browser at: **`http://127.0.0.1:8000`**

---

## Included Sample Threat Reports

The application comes bundled with 3 authentic multi-page vendor threat advisories:
1. **CISA AA24-105A:** *PRC State-Sponsored Actors (Volt Typhoon) Target U.S. Critical Infrastructure via Living-off-the-Land Techniques*
2. **Mandiant:** *APT29 Cloud Token Theft & Deep Persistence in Microsoft 365*
3. **CrowdStrike Falcon OverWatch:** *Lazarus Group: Cross-Platform Crypto-Heist Malware and Ransomware Fusion*
