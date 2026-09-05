"""
Threat Intelligence Analyzer & GenAI Summarization Engine.
Performs Threat Actor attribution, MITRE ATT&CK mapping, Kill Chain reconstruction,
targeted sector profiling, and SOC Executive Briefing generation.
Supports optional external LLMs (OpenAI/Gemini/Ollama) with deterministic NLP fallback.
"""

import os
import re
import json
from typing import Dict, Any, List, Optional
import urllib.request

try:
    from config import NVIDIA_API_KEY
    os.environ["NVIDIA_API_KEY"] = NVIDIA_API_KEY
except ImportError:
    pass

try:
    from google import genai as google_genai
except ImportError:
    google_genai = None


# MITRE ATT&CK Technique Database
MITRE_ATTACK_DB: Dict[str, Dict[str, str]] = {
    "T1566": {
        "name": "Phishing",
        "tactic": "Initial Access",
        "desc": "Adversaries send spear-phishing messages with malicious attachments or links to gain initial access.",
        "mitigation": "Enforce DMARC/DKIM/SPF, deploy email filtering gateways, and conduct user awareness simulations."
    },
    "T1566.001": {
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "desc": "Delivering malicious payloads via spear-phishing emails containing weaponized office documents or zip archives.",
        "mitigation": "Block dangerous attachment extensions (.vbs, .js, .iso, .exe) and inspect macro code."
    },
    "T1566.002": {
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "desc": "Luring victims into clicking links to adversary-controlled credential harvesting or exploit domains.",
        "mitigation": "Implement real-time URL rewriting and browser isolation."
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "desc": "Exploiting security vulnerabilities or zero-days in internet-exposed edge appliances, VPNs, or web applications.",
        "mitigation": "Apply vendor emergency patches immediately and place public edge devices behind WAF/IDPS."
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "Initial Access / Persistence",
        "desc": "Adversaries obtain and abuse credentials of existing enterprise or cloud accounts to bypass defenses.",
        "mitigation": "Enforce phishing-resistant MFA (FIDO2) and conditional access policies."
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "desc": "Adversaries abuse local interpreters such as PowerShell, cmd, Bash, or Python to execute malicious code.",
        "mitigation": "Enable PowerShell Constrained Language Mode, Script Block Logging (Event ID 4104), and AMSI."
    },
    "T1059.001": {
        "name": "PowerShell",
        "tactic": "Execution",
        "desc": "Abusing PowerShell scripts and cmdlets to download payloads, run obfuscated commands, or discover active directory.",
        "mitigation": "Restrict PowerShell access via AppLocker/WDAC and log all command-line executions."
    },
    "T1059.003": {
        "name": "Windows Command Shell",
        "tactic": "Execution",
        "desc": "Leveraging cmd.exe to execute batch scripts and operationalize LOLBins.",
        "mitigation": "Monitor parent-child process anomalies (e.g., Office launching cmd.exe)."
    },
    "T1204": {
        "name": "User Execution",
        "tactic": "Execution",
        "desc": "Relying on target user interaction to open files, enable macros, or run executables.",
        "mitigation": "Enforce Mark of the Web (MoTW) protections and disable macros by default."
    },
    "T1547.001": {
        "name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
        "desc": "Adding entries to Windows Registry Run keys or Startup folder for recurring payload execution upon user login.",
        "mitigation": "Monitor modifications to HKLM/HKCU\\...\\CurrentVersion\\Run and audit autostart extensibility points."
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "tactic": "Persistence / Execution",
        "desc": "Creating scheduled tasks via schtasks.exe or cron jobs to maintain long-term unauthorized access.",
        "mitigation": "Audit scheduled task creation (Event ID 4698) and limit administrative rights."
    },
    "T1543.003": {
        "name": "Windows Service",
        "tactic": "Persistence / Privilege Escalation",
        "desc": "Creating or modifying Windows services to execute malicious binaries with SYSTEM privileges.",
        "mitigation": "Monitor sc.exe and Service Control Manager events (Event ID 7045)."
    },
    "T1027": {
        "name": "Obfuscated Files or Information",
        "tactic": "Defense Evasion",
        "desc": "Adversaries encode, encrypt, or pack payloads to prevent signature-based AV/EDR detection.",
        "mitigation": "Deploy behavioral anomaly detection and memory inspection sensors."
    },
    "T1070": {
        "name": "Indicator Removal",
        "tactic": "Defense Evasion",
        "desc": "Clearing Windows Event Logs, deleting shadow copies, or wiping file artifacts using wevtutil.",
        "mitigation": "Forward logs centrally to SIEM in near real-time and make log stores immutable."
    },
    "T1003": {
        "name": "OS Credential Dumping",
        "tactic": "Credential Access",
        "desc": "Dumping credentials from LSASS memory, SAM hive, or NTDS.dit using Mimikatz or ProcDump.",
        "mitigation": "Enable Windows LSA RunAsPPL and Credential Guard."
    },
    "T1082": {
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "desc": "Gathering OS version, hardware architecture, hostnames, and patch status using native commands.",
        "mitigation": "Audit process execution trees using Sysmon or EDR."
    },
    "T1071.001": {
        "name": "Web Protocols (C2)",
        "tactic": "Command and Control",
        "desc": "Communicating with adversary infrastructure over standard HTTP/HTTPS channels to blend with normal traffic.",
        "mitigation": "Inspect SSL/TLS egress traffic, analyze JA3/JA4 fingerprints, and filter against threat feeds."
    },
    "T1071.004": {
        "name": "DNS C2",
        "tactic": "Command and Control",
        "desc": "Using DNS tunneling or TXT query lookups to transfer commands and exfiltrate data.",
        "mitigation": "Monitor high-entropy DNS queries, NXDOMAIN volume, and enforce centralized DNS resolvers."
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "tactic": "Exfiltration",
        "desc": "Stealing sensitive corporate data via encrypted cloud storage, MEGA, Dropbox, or custom FTP.",
        "mitigation": "Enforce CASB cloud egress controls and egress network filtering."
    },
    "T1486": {
        "name": "Data Encrypted for Impact (Ransomware)",
        "tactic": "Impact",
        "desc": "Adversaries encrypt enterprise files and volumes to extort ransoms from target organizations.",
        "mitigation": "Maintain immutable offline backups and deploy canary file tripwires."
    }
}

# Known Threat Actors Database
KNOWN_THREAT_ACTORS: List[Dict[str, Any]] = [
    {
        "name": "Volt Typhoon",
        "aliases": ["BRONZE SILHOUETTE", "Vanguard Panda", "Dev-0391"],
        "origin": "People's Republic of China (State-sponsored)",
        "motivation": "Espionage / Pre-positioning for disruptive attacks",
        "tactics": "Living-off-the-land (LotL), compromised SOHO routers, credential theft, stealthy persistence",
        "targets": ["Critical Infrastructure", "Communications", "Energy", "Transportation", "Water Systems"]
    },
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "Midnight Blizzard", "NOBELIUM", "The Dukes"],
        "origin": "Russian Federation (SVR)",
        "motivation": "Strategic Intelligence / Foreign Policy Espionage",
        "tactics": "Cloud identity compromise, OAuth application abuse, supply chain compromise, spear-phishing",
        "targets": ["Government", "Diplomatic", "Think Tanks", "Cloud Service Providers", "Defense"]
    },
    {
        "name": "Lazarus Group",
        "aliases": ["HIDDEN COBRA", "Guardians of Peace", "Zinc", "Labyrinth Chollima"],
        "origin": "Democratic People's Republic of Korea (RGB)",
        "motivation": "Financial Theft / Sanctions Evasion / Ransomware",
        "tactics": "Cryptocurrency exchange targeting, cross-platform malware (macOS/Windows), fake job lures",
        "targets": ["Cryptocurrency / Fintech", "Financial Institutions", "Defense", "Aerospace"]
    },
    {
        "name": "Sandworm Team",
        "aliases": ["Voodoo Bear", "TeleBots", "Seashell Blizzard", "IRIDIUM"],
        "origin": "Russian Federation (GRU Unit 74455)",
        "motivation": "Sabotage / Cyber Warfare / Espionage",
        "tactics": "Wiper malware (HermeticWiper, CaddyWiper), industrial control system (ICS/SCADA) disruption",
        "targets": ["Energy & Utilities", "Government", "Telecommunications", "Media"]
    },
    {
        "name": "FIN7",
        "aliases": ["Carbanak", "ELBRUS", "Sangria Tempest"],
        "origin": "Eastern Europe / Financially Motivated Cybercrime",
        "motivation": "Financial Extortion / Ransomware Deployment",
        "tactics": "Weaponized Word/LNK lures, Carbanak backdoor, ransomware collaboration (BlackCat, DarkSide)",
        "targets": ["Retail", "Hospitality", "Restaurant Chains", "Financial Services"]
    },
    {
        "name": "Scattered Spider",
        "aliases": ["UNC3944", "Octo Tempest", "Muddled Libra"],
        "origin": "Global / English-speaking cybercrime syndicate",
        "motivation": "Financial Theft / SIM Swapping / Data Extortion",
        "tactics": "Help desk social engineering, SIM swapping, Okta/MFA bypass, BYOVD (Bring Your Own Vulnerable Driver)",
        "targets": ["Casinos & Gaming", "Telecommunications", "BPO & IT Service Desks", "Hospitality"]
    }
]


class ThreatAnalyzer:
    """Performs deep heuristic and LLM analysis on parsed threat intelligence reports."""

    def __init__(self, api_key: Optional[str] = None, api_base: Optional[str] = None):
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("GEMINI_API_KEY") or os.environ.get("NVIDIA_API_KEY")
        self.api_base = api_base or os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")
        self._gemini_client = None
        if google_genai and self.api_key and not self.api_key.startswith("nvapi-"):
            try:
                self._gemini_client = google_genai.Client(api_key=self.api_key)
            except Exception:
                pass

    def analyze(self, parsed_report: Dict[str, Any], extracted_iocs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Executes complete threat analysis pipeline:
        1. Threat Actor & Campaign attribution
        2. Attack Methodology & Kill Chain synthesis
        3. MITRE ATT&CK mapping with defense guidance
        4. Targeted Sectors & Geographies
        5. Severity & Risk Scoring
        6. SOC Executive Summary & Tactical Action Items
        """
        full_text = parsed_report.get("full_text", "")
        vendor = parsed_report.get("vendor", "Threat Research")

        # 1. Threat Actor Identification
        threat_actor = self._identify_threat_actor(full_text)

        # 2. MITRE ATT&CK Mapping
        mitre_mapping = self._map_mitre_techniques(full_text, extracted_iocs)

        # 3. Kill Chain Reconstruction
        kill_chain = self._reconstruct_kill_chain(full_text, mitre_mapping, extracted_iocs)

        # 4. Targeted Industries & Geographies
        targeted_sectors = self._extract_sectors(full_text, threat_actor)

        # 5. Malware Families & Exploits
        malware_and_tools = self._extract_malware_and_tools(full_text)

        # 6. Severity & Risk Scoring
        severity, risk_score = self._calculate_severity(extracted_iocs, threat_actor, mitre_mapping)

        # 7. Executive Briefing & Defensive Actions
        executive_summary = self._generate_executive_summary(
            vendor, threat_actor, malware_and_tools, mitre_mapping, extracted_iocs, severity, full_text
        )

        tactical_recommendations = self._generate_tactical_recommendations(
            mitre_mapping, extracted_iocs, threat_actor
        )

        return {
            "threat_actor": threat_actor,
            "malware_families": malware_and_tools,
            "severity": severity,
            "risk_score": risk_score,
            "targeted_sectors": targeted_sectors,
            "mitre_attack": mitre_mapping,
            "kill_chain": kill_chain,
            "executive_summary": executive_summary,
            "tactical_recommendations": tactical_recommendations,
            "total_indicators": len(extracted_iocs),
            "vendor": vendor,
            "report_title": parsed_report.get("metadata", {}).get("title", "Threat Intelligence Advisory")
        }

    def _identify_threat_actor(self, text: str) -> Dict[str, Any]:
        """Matches threat actor names, aliases, and known attribution markers."""
        text_lower = text.lower()

        for actor in KNOWN_THREAT_ACTORS:
            # Check main name
            if actor["name"].lower() in text_lower:
                return actor
            # Check aliases
            for alias in actor["aliases"]:
                if alias.lower() in text_lower:
                    return actor

        # Check for generic APT / Group regex
        generic_match = re.search(r"\b(APT-?\d{1,3}|UNC\d{3,4}|TA\d{3,4}|FIN\d{1,2})\b", text, re.IGNORECASE)
        if generic_match:
            group_name = generic_match.group(1).upper()
            return {
                "name": group_name,
                "aliases": [],
                "origin": "Unspecified Advanced Persistent Threat",
                "motivation": "Targeted Cyber Operations",
                "tactics": "Multi-stage intrusion campaign",
                "targets": ["Enterprise Networks"]
            }

        return {
            "name": "Unattributed Adversary",
            "aliases": ["Unknown Threat Cluster"],
            "origin": "Unknown / Under Investigation",
            "motivation": "Malicious Intrusion / Cybercrime",
            "tactics": "Exploitation of vulnerabilities and credential abuse",
            "targets": ["Global Organizations"]
        }

    def _map_mitre_techniques(self, text: str, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extracts and contextualizes all MITRE ATT&CK techniques referenced or implied."""
        found_techniques: Dict[str, Dict[str, Any]] = {}

        # 1. From explicitly extracted MITRE IoCs
        for ioc in iocs:
            if ioc.get("type") == "mitre":
                tech_id = ioc.get("value", "").upper()
                if tech_id in MITRE_ATTACK_DB:
                    info = MITRE_ATTACK_DB[tech_id]
                    found_techniques[tech_id] = {
                        "id": tech_id,
                        "name": info["name"],
                        "tactic": info["tactic"],
                        "description": info["desc"],
                        "mitigation": info["mitigation"],
                        "detected_via": "Explicit Report Tag"
                    }

        # 2. Heuristic text scanning for technique keywords
        text_lower = text.lower()
        keyword_patterns = {
            "T1566": [r"phishing", r"spear-phishing", r"lure email"],
            "T1566.001": [r"malicious attachment", r"weaponized document", r"macro-enabled"],
            "T1190": [r"exploit public-facing", r"zero-day", r"remote code execution", r"edge device"],
            "T1078": [r"valid accounts", r"compromised credentials", r"token theft"],
            "T1059.001": [r"powershell", r"invoke-expression", r"encodedcommand"],
            "T1059.003": [r"cmd\.exe", r"batch script", r"windows command shell"],
            "T1547.001": [r"run key", r"currentversion\\run", r"startup folder"],
            "T1053": [r"scheduled task", r"schtasks", r"cron job"],
            "T1027": [r"obfuscat", r"packed", r"base64-encoded", r"xor encrypt"],
            "T1003": [r"lsass", r"mimikatz", r"credential dump", r"procdump"],
            "T1071.001": [r"c2 over http", r"https beacon", r"command and control traffic"],
            "T1071.004": [r"dns tunnel", r"dns c2", r"txt record beacon"],
            "T1486": [r"ransomware", r"encrypt files", r"ransom note", r"vssadmin delete"]
        }

        for tech_id, patterns in keyword_patterns.items():
            if tech_id not in found_techniques:
                for pat in patterns:
                    if re.search(pat, text_lower):
                        info = MITRE_ATTACK_DB.get(tech_id, {
                            "name": tech_id,
                            "tactic": "Attack Pattern",
                            "desc": "Adversary methodology identified via heuristic textual markers.",
                            "mitigation": "Apply defense-in-depth controls."
                        })
                        found_techniques[tech_id] = {
                            "id": tech_id,
                            "name": info["name"],
                            "tactic": info["tactic"],
                            "description": info["desc"],
                            "mitigation": info["mitigation"],
                            "detected_via": "Heuristic NLP Context"
                        }
                        break

        return list(found_techniques.values())

    def _reconstruct_kill_chain(
        self, text: str, mitre_techniques: List[Dict[str, Any]], iocs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Reconstructs the cyber kill-chain progression from the report evidence."""
        stages = [
            {"phase": "Initial Access", "icon": "fa-key", "evidence": []},
            {"phase": "Execution", "icon": "fa-terminal", "evidence": []},
            {"phase": "Persistence", "icon": "fa-shield-halved", "evidence": []},
            {"phase": "Defense Evasion", "icon": "fa-ghost", "evidence": []},
            {"phase": "Credential Access", "icon": "fa-id-card", "evidence": []},
            {"phase": "Command and Control", "icon": "fa-tower-broadcast", "evidence": []},
            {"phase": "Action on Objectives / Exfiltration", "icon": "fa-file-export", "evidence": []}
        ]

        # Populate from MITRE tactics
        for tech in mitre_techniques:
            tactic = tech.get("tactic", "")
            for stage in stages:
                if stage["phase"].lower() in tactic.lower():
                    stage["evidence"].append(f"Technique {tech['id']} ({tech['name']})")

        # Populate from IoC types
        for ioc in iocs:
            ioc_type = ioc["type"]
            role = ioc.get("role", "")
            if ioc_type in ("ipv4", "domain", "url") and "c2" in role.lower():
                stages[5]["evidence"].append(f"C2 Endpoint: {ioc.get('defanged')}")
            elif ioc_type == "registry":
                stages[2]["evidence"].append(f"Registry Key: {ioc.get('value')}")
            elif ioc_type == "cve":
                stages[0]["evidence"].append(f"Exploitation of {ioc.get('value')}")
            elif ioc_type in ("sha256", "md5") and "drop" in role.lower():
                stages[1]["evidence"].append(f"Malware Hash: {ioc.get('value')[:16]}...")

        # Fill default summaries if empty
        defaults = {
            "Initial Access": "Spear-phishing or exploitation of exposed edge services.",
            "Execution": "Script interpreter execution via command-line tools.",
            "Persistence": "Autostart execution or scheduled task creation.",
            "Defense Evasion": "Payload obfuscation and log tampering evasion.",
            "Credential Access": "Memory inspection and credential harvesting.",
            "Command and Control": "Encrypted communication channels with adversary infrastructure.",
            "Action on Objectives / Exfiltration": "Pre-positioning, data staging, or destructive impact."
        }

        for stage in stages:
            if not stage["evidence"]:
                stage["evidence"].append(defaults[stage["phase"]])
            # Deduplicate
            stage["evidence"] = list(dict.fromkeys(stage["evidence"]))[:5]

        return stages

    def _extract_sectors(self, text: str, threat_actor: Dict[str, Any]) -> List[str]:
        """Identifies targeted industry sectors mentioned in the advisory."""
        sectors_keywords = {
            "Critical Infrastructure": [r"critical infrastructure", r"scada", r"ics", r"operational technology"],
            "Financial Services": [r"financial", r"banking", r"fintech", r"cryptocurrency", r"swift"],
            "Government & Public Sector": [r"government", r"federal", r"municipal", r"ministry", r"diplomatic"],
            "Defense & Aerospace": [r"defense industrial base", r"military", r"aerospace", r"defense contractor"],
            "Healthcare & Public Health": [r"healthcare", r"hospital", r"pharmaceutical", r"medical"],
            "Energy & Utilities": [r"energy", r"electric", r"power grid", r"pipeline", r"oil and gas", r"water"],
            "Telecommunications": [r"telecom", r"isp", r"telecommunications", r"cellular", r"broadband"],
            "Information Technology": [r"cloud provider", r"managed service provider", r"msp", r"software supply chain"]
        }

        found_sectors: List[str] = []
        text_lower = text.lower()

        for sector, patterns in sectors_keywords.items():
            for pat in patterns:
                if re.search(pat, text_lower):
                    found_sectors.append(sector)
                    break

        # Fallback to threat actor's common targets if none detected
        if not found_sectors and threat_actor.get("targets"):
            found_sectors = threat_actor["targets"]

        return found_sectors or ["Enterprise Information Systems", "Government & Commercial Networks"]

    def _extract_malware_and_tools(self, text: str) -> List[str]:
        """Extracts references to specific malware implants, loaders, and offensive tools."""
        known_tools = [
            "Cobalt Strike", "Mimikatz", "Sliver", "Brute Ratel", "Qakbot", "Bumblebee",
            "IcedID", "Emotet", "BlackCat", "ALPHV", "LockBit", "HermeticWiper",
            "CaddyWiper", "Chisel", "PsExec", "PowerSploit", "Responder", "BloodHound",
            "SharpHound", "Donut", "Havoc", "Karkoff", "WellMess", "DarkSide"
        ]

        found = []
        for tool in known_tools:
            if re.search(r"\b" + re.escape(tool) + r"\b", text, re.IGNORECASE):
                found.append(tool)

        return found or ["Custom In-Memory Backdoor", "Living-off-the-Land Binaries (LOLBins)"]

    def _calculate_severity(
        self, iocs: List[Dict[str, Any]], threat_actor: Dict[str, Any], mitre: List[Dict[str, Any]]
    ) -> (str, int):
        """Calculates SOC severity level and 1-100 numerical risk score."""
        score = 40  # baseline

        # State-sponsored or tier-1 actor adds score
        if "APT" in threat_actor.get("name", "") or threat_actor.get("name") in [
            "Volt Typhoon", "Lazarus Group", "Sandworm Team", "APT29"
        ]:
            score += 25

        # Critical vulnerabilities (CVEs)
        cve_count = sum(1 for i in iocs if i.get("type") == "cve")
        score += min(cve_count * 10, 20)

        # Active C2 infrastructure
        c2_count = sum(1 for i in iocs if i.get("type") in ("ipv4", "domain", "url"))
        score += min(c2_count * 2, 15)

        # Ransomware / Wiper techniques
        if any(t["id"] in ("T1486", "T1070") for t in mitre):
            score += 15

        score = min(100, max(20, score))

        if score >= 80:
            return "CRITICAL", score
        elif score >= 60:
            return "HIGH", score
        elif score >= 40:
            return "MEDIUM", score
        else:
            return "LOW", score

    def _generate_executive_summary(
        self, vendor: str, threat_actor: Dict[str, Any], malware: List[str],
        mitre: List[Dict[str, Any]], iocs: List[Dict[str, Any]], severity: str,
        full_text: str = ""
    ) -> str:
        """Generates a concise, high-level briefing tailored for SOC Leads & CISOs."""
        actor_name = threat_actor.get("name", "Unknown Adversary")
        origin = threat_actor.get("origin", "Unspecified origin")
        ioc_count = len(iocs)
        malware_str = ", ".join(malware[:3]) if malware else "proprietary malware"

        fallback_summary = (
            f"This threat intelligence advisory from {vendor} documents active intrusion activity attributed to "
            f"'{actor_name}' ({origin}). The adversary leverages {malware_str} alongside sophisticated living-off-the-land "
            f"methodologies to compromise enterprise perimeters, establish stealthy persistence, and conduct unauthorized operations. "
            f"A total of {ioc_count} structured Indicators of Compromise (IoCs) and {len(mitre)} MITRE ATT&CK techniques have been "
            f"extracted and verified. SOC defensive teams should treat this activity at a {severity} urgency level and immediately "
            f"deploy the generated firewall blocklists, IDS signatures, and endpoint detection queries."
        )

        if self.api_key and self.api_key.startswith("nvapi-") and full_text:
            try:
                url = "https://integrate.api.nvidia.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.api_key}",
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
                prompt = f"""You are a senior SOC analyst. Summarize the following threat intelligence report text.
Focus on the attack methodology, tactics, and impact. Keep it concise, professional, and tailored for a CISO briefing.

Report Text:
{full_text[:30000]}"""
                
                payload = {
                    "model": "meta/llama-3.2-11b-vision-instruct",
                    "messages": [{"role": "user", "content": prompt}],
                    "max_tokens": 500
                }
                req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=30) as response:
                    res_data = json.loads(response.read().decode('utf-8'))
                    return res_data['choices'][0]['message']['content'].strip()
            except Exception:
                pass # Fallback to heuristic

        elif self._gemini_client and full_text:
            try:
                prompt = (
                    "You are a senior SOC analyst. Summarize the following threat intelligence report text. "
                    "Focus on the attack methodology, tactics, and impact. "
                    "Keep it concise, professional, and tailored for a CISO briefing.\n\n"
                    f"Report Text:\n{full_text[:30000]}"
                )
                response = self._gemini_client.models.generate_content(
                    model="gemini-1.5-flash",
                    contents=prompt
                )
                if response and response.text:
                    return response.text.strip()
            except Exception:
                pass  # Fallback to heuristic
                
        return fallback_summary

    def _generate_tactical_recommendations(
        self, mitre: List[Dict[str, Any]], iocs: List[Dict[str, Any]], threat_actor: Dict[str, Any]
    ) -> List[Dict[str, str]]:
        """Provides concrete, step-by-step SOC operational remediation instructions."""
        recommendations = [
            {
                "category": "Perimeter & Network Defense",
                "action": "Ingest extracted IPv4 addresses, domains, and URLs into edge firewalls (Palo Alto, Fortinet, Cisco) and set action to DROP/RESET.",
                "priority": "Immediate (P1)"
            },
            {
                "category": "Endpoint & EDR Telemetry",
                "action": "Query SIEM and EDR repositories for file hashes (SHA-256) and registry persistence keys within the past 90 days across all endpoints.",
                "priority": "Immediate (P1)"
            },
            {
                "category": "Identity & Credential Governance",
                "action": "Force password resets and revoke active OAuth/M365 session tokens for any identity exhibiting logins from foreign or anomalous ASNs.",
                "priority": "High (P2)"
            },
            {
                "category": "Vulnerability Remediation",
                "action": "Audit external-facing appliances for disclosed CVEs and apply vendor emergency patches or temporary virtual patching rules.",
                "priority": "High (P2)"
            }
        ]
        return recommendations
