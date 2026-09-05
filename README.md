# CyberSentinel — Automated Threat Intelligence Report Summarizer & IoC Extractor

> **Transforms dense, unstructured cybersecurity vendor PDF reports into immediate, actionable firewall configurations and standardized STIX 2.1 threat intelligence bundles.**

---

## Table of Contents

1. [The Problem](#the-problem)
2. [The Solution](#the-solution)
3. [Core Capabilities](#core-capabilities)
4. [Architecture](#architecture)
5. [Project Structure](#project-structure)
6. [Quickstart Guide](#quickstart-guide)
7. [CLI Reference](#cli-reference)
8. [REST API & TAXII 2.1 Endpoints](#rest-api--taxii-21-endpoints)
9. [Example Output](#example-output)
10. [Sample Reports Included](#sample-reports-included)
11. [Running the Test Suite](#running-the-test-suite)

---

## The Problem

Security Operations Centers (SOCs) receive dozens of text-heavy, multi-page PDF advisories every week from global cybersecurity vendors such as CISA, Mandiant, CrowdStrike, Palo Alto Unit 42, and Microsoft Defender Threat Intelligence.

Three specific bottlenecks slow down defenders:

1. **Unstructured, dense content** — Critical attack vectors, malware hashes, and persistence mechanisms are buried across 10–50 pages of narrative prose. There is no consistent structure between vendors.

2. **Defanged and incompatible formats** — IoCs are published in defanged formats (`hxxp://`, `198[.]51[.]100[.]1`, `evil[@]phish[.]org`) to prevent accidental execution. They must be refanged, validated, and normalised before a firewall can consume them.

3. **The triage-to-defence gap** — Manually converting a vendor PDF into firewall drop rules and SIEM lookup tables takes hours. During that window, an active campaign can spread laterally across the enterprise.

---

## The Solution

CyberSentinel is a specialised GenAI application that closes the triage-to-defence gap automatically.

A SOC analyst drops in a PDF. Within seconds, the engine returns:

- A structured, LLM-generated **CISO executive briefing** describing the attack methodology, tactics, and impact in plain language.
- A complete list of **extracted and validated IoCs** — IPs, domains, URLs, file hashes, registry keys, CVEs, and MITRE ATT&CK technique IDs — with confidence ratings and page-level provenance.
- A **STIX 2.1 JSON bundle** ready for direct ingestion into TAXII-compatible threat intelligence platforms (OpenCTI, MISP, Sentinel, Splunk SOAR).
- **Eight firewall and IDS configuration files** ready for deployment to Palo Alto, FortiGate, Cisco ASA, Linux iptables, Suricata/Snort, Zeek, and SIEM lookup tables.

---

## Core Capabilities

### 1. Multi-Page PDF Ingestion

- Handles PDF files of any length via `pypdf`, extracting text page by page with preserved numbering and provenance.
- Automatically detects the reporting vendor from branding patterns: **CISA, Mandiant/Google Cloud, CrowdStrike, Palo Alto Unit 42, Microsoft Defender, Recorded Future, Trend Micro, Cisco Talos**.
- Detects and records the **Traffic Light Protocol (TLP)** marking (CLEAR, GREEN, AMBER, AMBER+STRICT, RED).
- Strips common header/footer noise and normalises non-breaking spaces and line endings.

### 2. Hybrid NLP & GenAI Extraction Engine

- **Named Entity Recognition (NER):** Uses `spaCy` (`en_core_web_sm`) to extract contextual threat entities (organisations, geopolitical entities, threat actor names) that fall outside the rigid regex patterns.
- **LLM Executive Summarisation:** Uses the NVIDIA NIM API (`meta/llama-3.2-11b-vision-instruct`) if an `NVIDIA_API_KEY` is configured, or the Google Gemini API (`gemini-1.5-flash`) if a `GEMINI_API_KEY` is configured. If neither key is present, the engine produces a deterministic heuristic summary with no degradation to the IoC extraction pipeline.
- **Auto-Refanging:** Restores defanged indicators to operational form before regex processing (`hxxps://` → `https://`, `198[.]51[.]100[.]1` → `198.51.100.1`).
- **Auto-Defanging:** All indicators are re-defanged before display and storage to prevent accidental resolution.

**Extracted IoC types:**

| Category | Types |
|---|---|
| Network | IPv4 (with CIDR), IPv6, Domains/FQDNs, URLs/URIs, Email addresses |
| Host / Binary | MD5, SHA-1, SHA-256, SHA-512 file hashes |
| Persistence | Windows Registry Run keys (`HKLM\...`, `HKCU\...`) |
| Vulnerabilities | CVE identifiers (e.g. `CVE-2023-46805`) |
| Techniques | MITRE ATT&CK IDs (e.g. `T1059.001`) |
| Context | NER entities — threat actors, organisations, geographies |

Each IoC carries: `type`, `value`, `defanged`, `page`, `context` (100-char surrounding snippet), `role` (inferred from context: C2 server, phishing, dropper, etc.), and `confidence` (High / Medium).

### 3. Threat Actor Attribution & Attack Methodology

- Matches content against a built-in database of tracked threat actors including: **Volt Typhoon, APT29, Lazarus Group, Sandworm Team, FIN7, Scattered Spider**.
- Reconstructs the **Cyber Kill Chain** in 7 stages: Initial Access → Execution → Persistence → Defence Evasion → Credential Access → Command & Control → Exfiltration.
- Maps detected techniques to the **MITRE ATT&CK** framework with tactic, description, and mitigation guidance.
- Calculates a **risk severity score** (0–100) based on IoC density, threat actor sophistication, and MITRE coverage.

### 4. OASIS STIX 2.1 & TAXII 2.1 Output

The STIX bundle contains fully typed STIX 2.1 Domain Objects (SDOs) and Relationship Objects (SROs):

| STIX Object Type | Purpose |
|---|---|
| `identity` | The reporting SOC organisation |
| `threat-actor` | Attributed adversary with aliases and motivation |
| `malware` | Each malware family and tool identified |
| `attack-pattern` | Each MITRE ATT&CK technique with external reference URL |
| `vulnerability` | Each exploited CVE linked to NVD |
| `indicator` | Every IoC with a STIX Pattern expression |
| `relationship` | Typed links between all the above objects |

STIX Pattern examples generated:
```
[ipv4-addr:value = '198.51.100.45']
[file:hashes.'SHA-256' = 'e3b0c442...']
[windows-registry-key:key = 'HKLM\SOFTWARE\...\Run\VoltSvc']
[vulnerability:name = 'CVE-2023-46805']
```

The integrated **TAXII 2.1 server endpoints** allow firewalls and SIEMs to subscribe to and poll the live feed:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/taxii2/` | Server discovery — returns API roots |
| `GET` | `/taxii2/api1/` | API root info and supported versions |
| `GET` | `/taxii2/api1/collections/` | Lists available intelligence collections |
| `GET` | `/taxii2/api1/collections/{id}/objects/` | Returns the live STIX 2.1 bundle |
| `POST` | `/taxii2/api1/collections/{id}/objects/` | Publishes a new STIX bundle to the feed |

### 5. Multi-Vendor Firewall & Defensive Ingestion

Eight deployment-ready configuration files are generated from the extracted IoCs:

| File | Target Platform |
|---|---|
| `suricata.rules` | Suricata / Snort 3 — drop rules for IPs, domains, URLs |
| `palo_alto_commands.txt` | Palo Alto PAN-OS — address objects, groups, URL categories |
| `fortigate_policy.txt` | Fortinet FortiGate FortiOS — address objects and deny policy |
| `cisco_asa_acl.txt` | Cisco ASA / Firepower — object-groups and extended ACLs |
| `iptables.sh` | Linux iptables — INPUT/OUTPUT/FORWARD drop rules |
| `zeek_intel.dat` | Zeek (Bro) Intelligence Framework — tab-delimited intel file |
| `siem_lookup.csv` | Splunk / Elastic / Microsoft Sentinel / QRadar lookup table |
| `edr_hashes.csv` | CrowdStrike Falcon / Defender for Endpoint hash blocklist |

### 6. Web Dashboard & REST API

A dark-mode SOC analyst web dashboard is served at `http://127.0.0.1:8000` with:
- One-click sample report analysis
- Drag-and-drop PDF upload
- Interactive IoC table with filtering
- STIX bundle and firewall rule download buttons

Full Swagger/OpenAPI documentation is available at `http://127.0.0.1:8000/docs`.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        Input Layer                           │
│    PDF Report (file path, upload, or byte stream)            │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              core/pdf_parser.py — ThreatReportParser         │
│  • Page-by-page text extraction via pypdf                    │
│  • Vendor branding detection (8 vendors)                     │
│  • TLP marking extraction                                    │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              core/extractor.py — IoCExtractor                │
│  • Regex-based extraction: IP, domain, URL, hash, CVE, etc.  │
│  • Auto-refang of defanged indicators                        │
│  • spaCy NER for contextual entity extraction                │
│  • Confidence scoring and role inference per IoC             │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              core/analyzer.py — ThreatAnalyzer               │
│  • Threat actor attribution against built-in database        │
│  • MITRE ATT&CK technique mapping                            │
│  • Kill Chain reconstruction                                 │
│  • Severity / risk scoring                                   │
│  • LLM executive summary (NVIDIA NIM → Gemini → heuristic)   │
└────────────┬──────────────────────────┬──────────────────────┘
             │                          │
             ▼                          ▼
┌────────────────────┐      ┌──────────────────────────────────┐
│  exporters/        │      │  exporters/                      │
│  stix_generator.py │      │  firewall_rules.py               │
│                    │      │                                  │
│  STIX 2.1 Bundle   │      │  Suricata, Palo Alto, FortiGate  │
│  TAXII 2.1 Feed    │      │  Cisco ASA, iptables, Zeek       │
│                    │      │  SIEM CSV, EDR Hash Blocklist    │
└────────────────────┘      └──────────────────────────────────┘
```

---

## Project Structure

```
threat_intel_summarizer/
├── app/
│   ├── __init__.py
│   └── main.py                     # FastAPI server, REST + TAXII 2.1 endpoints
├── core/
│   ├── __init__.py
│   ├── pdf_parser.py               # Multi-page PDF parser and vendor detector
│   ├── extractor.py                # Regex + NER IoC extractor, refanger/defanger
│   └── analyzer.py                 # Threat actor attribution, MITRE mapping, LLM summary
├── exporters/
│   ├── __init__.py
│   ├── stix_generator.py           # OASIS STIX 2.1 JSON bundle generator
│   └── firewall_rules.py           # Multi-vendor firewall and IDS rule synthesiser
├── samples/
│   ├── __init__.py
│   ├── generate_samples.py         # Generates CISA, Mandiant, and CrowdStrike sample PDFs
│   └── reports/                    # Bundled multi-page sample threat intelligence PDFs
├── static/
│   ├── index.html                  # SOC analyst web dashboard (dark mode)
│   ├── css/styles.css
│   └── js/app.js                   # Frontend controller and export logic
├── tests/
│   ├── __init__.py
│   ├── test_engine.py              # Full pipeline unit tests
│   └── test_gemini_scenarios.py    # LLM summarisation edge-case tests
├── example_output/                 # Pre-generated sample output for reference
│   ├── console_output.txt          # Sample terminal output
│   ├── stix_bundle.json            # Sample STIX 2.1 bundle
│   └── firewall_rules/             # Sample generated firewall configurations
├── config.py                       # Local API key configuration (not committed to Git)
├── requirements.txt
├── run.py                          # One-command launcher for the web server
└── cli.py                          # Headless CLI for batch SOC processing
```

---

## Quickstart Guide

### Prerequisites

- Python 3.10 or higher
- `pip`

### Step 1 — Install Dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### Step 2 — Configure an API Key (Optional)

The full extraction and STIX pipeline works without any API key. An LLM key is optional and only enhances the executive summary section.

**Option A — NVIDIA NIM** (free tier, no credit card required):
1. Sign up at [build.nvidia.com](https://build.nvidia.com) and generate a key.
2. Export it before running:
   ```bash
   export NVIDIA_API_KEY="nvapi-your-key-here"
   ```
   Or place it in `config.py` at the project root:
   ```python
   NVIDIA_API_KEY = "nvapi-your-key-here"
   ```

**Option B — Google Gemini** (free tier via Google AI Studio):
```bash
export GEMINI_API_KEY="your-gemini-key-here"
```

### Step 3 — Launch the Web Dashboard

```bash
python run.py
```

Open your browser at **`http://127.0.0.1:8000`**.

The Swagger REST API documentation is at **`http://127.0.0.1:8000/docs`**.

---

## CLI Reference

Run the headless CLI directly without starting the web server. Useful for SOC automation and CI/CD pipelines.

**Basic usage — print terminal report:**
```bash
PYTHONPATH=. python cli.py samples/reports/Mandiant_APT29_Cloud_Token_Theft_and_Persistence.pdf
```

**Export STIX 2.1 bundle:**
```bash
PYTHONPATH=. python cli.py report.pdf --stix output/stix_bundle.json
```

**Export all firewall configurations:**
```bash
PYTHONPATH=. python cli.py report.pdf --firewall-dir ./firewall_rules/
```

**Full export — STIX + all firewall configs + terminal report:**
```bash
PYTHONPATH=. python cli.py report.pdf --stix output/stix.json --firewall-dir ./rules/
```

**Suppress terminal banner (quiet mode for piping):**
```bash
PYTHONPATH=. python cli.py report.pdf --stix output/stix.json --quiet
```

---

## REST API & TAXII 2.1 Endpoints

All endpoints are documented interactively at `http://127.0.0.1:8000/docs`.

### Analysis Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/sample-reports` | Lists the three bundled sample reports |
| `POST` | `/api/analyze-sample/{id}` | Analyses a bundled sample report by ID |
| `POST` | `/api/analyze-pdf` | Uploads and analyses an arbitrary PDF |
| `POST` | `/api/export-stix` | Downloads a STIX bundle as a JSON file |
| `GET` | `/api/health` | Service health check |

### TAXII 2.1 Endpoints

All TAXII responses use `Content-Type: application/taxii+json;version=2.1`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/taxii2/` | Server discovery |
| `GET` | `/taxii2/api1/` | API root information |
| `GET` | `/taxii2/api1/collections/` | List available intelligence collections |
| `GET` | `/taxii2/api1/collections/soc-firewall-feed/objects/` | Pull the live STIX 2.1 bundle |
| `POST` | `/taxii2/api1/collections/soc-firewall-feed/objects/` | Publish a new STIX 2.1 bundle |

---

## Example Output

Pre-generated output from running the engine against the bundled Mandiant APT29 report is included in the [`example_output/`](./example_output/) directory:

- [`console_output.txt`](./example_output/console_output.txt) — Full terminal dashboard output.
- [`stix_bundle.json`](./example_output/stix_bundle.json) — OASIS STIX 2.1 JSON bundle with all SDOs, SROs, and STIX Pattern expressions.
- [`firewall_rules/suricata.rules`](./example_output/firewall_rules/suricata.rules) — Suricata IDS drop rules.
- [`firewall_rules/palo_alto_commands.txt`](./example_output/firewall_rules/palo_alto_commands.txt) — PAN-OS CLI commands.
- [`firewall_rules/siem_lookup.csv`](./example_output/firewall_rules/siem_lookup.csv) — SIEM lookup table.

---

## Sample Reports Included

The application ships with three authentic, multi-page vendor threat advisories generated to reflect real-world report structure:

| ID | Report | Threat Actor |
|---|---|---|
| `cisa-volt-typhoon` | CISA AA24-105A: PRC State-Sponsored Actors Target U.S. Critical Infrastructure | Volt Typhoon (PRC / MSS) |
| `mandiant-apt29` | Mandiant: APT29 Cloud Token Theft & Deep Persistence in Microsoft 365 | APT29 / Midnight Blizzard (SVR) |
| `crowdstrike-lazarus` | CrowdStrike Falcon OverWatch: Lazarus Cross-Platform Crypto-Heist & Ransomware | Lazarus Group (DPRK / RGB) |

---

## Running the Test Suite

```bash
PYTHONPATH=. python -m unittest tests.test_engine -v
PYTHONPATH=. python -m unittest tests.test_gemini_scenarios -v
```

The test suite covers:
- IoC extraction accuracy across all nine indicator types.
- Refanging and defanging round-trips.
- Multi-page PDF parsing and vendor detection.
- STIX 2.1 bundle schema compliance.
- Firewall rule generation for all eight platforms.
- TAXII 2.1 collection object format.
- LLM summarisation fallback scenarios (rate limit, empty response, no API key).
