"""
Core Indicator of Compromise (IoC) Extractor and Sanitizer.
Handles defanging, refanging, regex pattern matching, context extraction,
and confidence calculation for threat intelligence reports.
"""

import re
import ipaddress
from typing import List, Dict, Any, Set, Tuple, Optional


class IoCExtractor:
    """Extracts, validates, deduplicates, and defangs/refangs cyber threat indicators."""

    # Common non-domain file extensions to exclude from domain matching
    EXCLUDED_EXTENSIONS = {
        "exe", "dll", "pdf", "docx", "xlsx", "pptx", "zip", "rar", "7z", "tar", "gz",
        "py", "ps1", "sh", "bat", "cmd", "vbs", "js", "bin", "sys", "log", "txt", "cfg",
        "ini", "tmp", "bak", "dat", "iso", "img", "json", "xml", "csv", "html", "htm",
        "png", "jpg", "jpeg", "gif", "svg", "ico"
    }

    # Known Valid Top Level Domains (representative subset for filtering)
    VALID_TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "ru", "cn",
        "ir", "kp", "xyz", "top", "online", "site", "live", "store", "tech", "club",
        "vip", "work", "shop", "icu", "click", "cc", "me", "biz", "info", "pro", "mobi",
        "app", "dev", "cloud", "us", "uk", "ca", "de", "fr", "jp", "au", "in", "br", "nl"
    }

    def __init__(self):
        self._compile_regexes()

    def _compile_regexes(self):
        # IPv4 pattern (with optional CIDR)
        self.ipv4_regex = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?\b"
        )

        # IPv6 pattern
        self.ipv6_regex = re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
            r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
            r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
        )

        # URLs (handles http, https, ftp, sftp)
        self.url_regex = re.compile(
            r"\bhttps?:\/\/(?:[a-zA-Z0-9_\-\.\:\@]+@)?[a-zA-Z0-9\.\-]+(?::\d+)?(?:\/[^\s\"'<>\[\]{}|\^`\\]*)?",
            re.IGNORECASE
        )

        # Generic domain pattern (validated against TLD list and file extensions)
        self.domain_regex = re.compile(
            r"\b(?!(?:https?:\/\/))([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63})\b",
            re.IGNORECASE
        )

        # File Hashes
        self.md5_regex = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self.sha1_regex = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self.sha256_regex = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self.sha512_regex = re.compile(r"\b[a-fA-F0-9]{128}\b")

        # Windows Registry Keys
        self.registry_regex = re.compile(
            r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|"
            r"HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)"
            r"(?:\\[a-zA-Z0-9_\-\. ]+){1,15}\b",
            re.IGNORECASE
        )

        # CVEs
        self.cve_regex = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

        # MITRE ATT&CK Technique IDs (e.g., T1059, T1059.001)
        self.mitre_regex = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")

        # Email addresses
        self.email_regex = re.compile(
            r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b"
        )

    @staticmethod
    def refang(text: str) -> str:
        """
        Converts defanged indicators back to their functional forms for analysis & firewall export.
        e.g. hxxp[s]:// -> http[s]://
             192[.]168[.]1[.]1 -> 192.168.1.1
             evil[@]phish[.]com -> evil@phish.com
        """
        if not text:
            return ""

        s = text
        # Protocol defanging
        s = re.sub(r"\bh[xX]{2}p(s)?://", r"http\1://", s)
        s = re.sub(r"\bf[xX]p://", r"ftp://", s)

        # Dot defanging: [.], (.), {.}, [[.]]
        s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[\[\.\]\]", ".", s)
        s = re.sub(r"\[dot\]|\(dot\)|\{dot\}", ".", s, flags=re.IGNORECASE)

        # Colon defanging: [:]
        s = re.sub(r"\[:\]|\(:\)", ":", s)

        # At defanging: [@], [at]
        s = re.sub(r"\[@\]|\(@\)|\[at\]|\(at\)", "@", s, flags=re.IGNORECASE)

        # Slash defanging: [/]
        s = re.sub(r"\[\/\]|\(\/\)", "/", s)

        return s

    @staticmethod
    def defang(value: str, ioc_type: str) -> str:
        """
        Safely defangs an indicator so it cannot be inadvertently clicked or resolved.
        """
        if not value:
            return ""

        v = value
        if ioc_type in ("ipv4", "ipv6", "domain"):
            v = v.replace(".", "[.]")
        elif ioc_type == "url":
            v = re.sub(r"^https?://", lambda m: m.group(0).replace("tt", "xx"), v)
            v = v.replace(".", "[.]")
        elif ioc_type == "email":
            v = v.replace("@", "[@]").replace(".", "[.]")

        return v

    def extract_from_text(self, text: str, page_num: int = 1) -> List[Dict[str, Any]]:
        """
        Extracts all structured IoCs from raw text, auto-refangs patterns,
        evaluates context snippets, deduplicates, and calculates confidence.
        """
        refanged_text = self.refang(text)
        results: List[Dict[str, Any]] = []
        seen_keys: Set[Tuple[str, str]] = set()

        # 1. URLs
        for match in self.url_regex.finditer(refanged_text):
            url_str = match.group(0).rstrip(".,;)>'\"")
            key = ("url", url_str.lower())
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "url",
                    "value": url_str,
                    "defanged": self.defang(url_str, "url"),
                    "page": page_num,
                    "context": context,
                    "role": self._infer_ioc_role(context, "url"),
                    "confidence": self._calculate_confidence(url_str, "url", context)
                })

        # 2. IPv4 Addresses
        for match in self.ipv4_regex.finditer(refanged_text):
            ip_str = match.group(0)
            if self._is_valid_ipv4(ip_str):
                key = ("ipv4", ip_str)
                if key not in seen_keys:
                    seen_keys.add(key)
                    context = self._get_context_snippet(refanged_text, match.start(), match.end())
                    results.append({
                        "type": "ipv4",
                        "value": ip_str,
                        "defanged": self.defang(ip_str, "ipv4"),
                        "page": page_num,
                        "context": context,
                        "role": self._infer_ioc_role(context, "ipv4"),
                        "confidence": self._calculate_confidence(ip_str, "ipv4", context)
                    })

        # 3. IPv6 Addresses
        for match in self.ipv6_regex.finditer(refanged_text):
            ip_str = match.group(0)
            if self._is_valid_ipv6(ip_str):
                key = ("ipv6", ip_str.lower())
                if key not in seen_keys:
                    seen_keys.add(key)
                    context = self._get_context_snippet(refanged_text, match.start(), match.end())
                    results.append({
                        "type": "ipv6",
                        "value": ip_str,
                        "defanged": self.defang(ip_str, "ipv6"),
                        "page": page_num,
                        "context": context,
                        "role": self._infer_ioc_role(context, "ipv6"),
                        "confidence": self._calculate_confidence(ip_str, "ipv6", context)
                    })

        # 4. Domains (excluding URLs already captured and file extensions)
        for match in self.domain_regex.finditer(refanged_text):
            domain_str = match.group(0).rstrip(".,;)>'\"").lower()
            tld = match.group(2).lower()

            if tld in self.EXCLUDED_EXTENSIONS:
                continue
            if tld not in self.VALID_TLDS and len(tld) > 4:
                continue
            if domain_str.startswith("http://") or domain_str.startswith("https://"):
                continue

            # Don't capture IP addresses mistakenly
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_str):
                continue

            key = ("domain", domain_str)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "domain",
                    "value": domain_str,
                    "defanged": self.defang(domain_str, "domain"),
                    "page": page_num,
                    "context": context,
                    "role": self._infer_ioc_role(context, "domain"),
                    "confidence": self._calculate_confidence(domain_str, "domain", context)
                })

        # 5. Hashes (Prioritize SHA-256 > SHA-1 > MD5 to avoid sub-hash collisions)
        for match in self.sha256_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            key = ("sha256", hash_val)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "sha256",
                    "value": hash_val,
                    "defanged": hash_val,
                    "page": page_num,
                    "context": context,
                    "role": self._infer_ioc_role(context, "hash"),
                    "confidence": self._calculate_confidence(hash_val, "sha256", context)
                })

        for match in self.sha1_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            if any(hash_val in sha[1] for sha in seen_keys if sha[0] == "sha256"):
                continue
            key = ("sha1", hash_val)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "sha1",
                    "value": hash_val,
                    "defanged": hash_val,
                    "page": page_num,
                    "context": context,
                    "role": self._infer_ioc_role(context, "hash"),
                    "confidence": self._calculate_confidence(hash_val, "sha1", context)
                })

        for match in self.md5_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            if any(hash_val in s[1] for s in seen_keys if s[0] in ("sha256", "sha1")):
                continue
            key = ("md5", hash_val)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "md5",
                    "value": hash_val,
                    "defanged": hash_val,
                    "page": page_num,
                    "context": context,
                    "role": self._infer_ioc_role(context, "hash"),
                    "confidence": self._calculate_confidence(hash_val, "md5", context)
                })

        # 6. Windows Registry Keys
        for match in self.registry_regex.finditer(refanged_text):
            reg_key = match.group(0).strip()
            key = ("registry", reg_key.upper())
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "registry",
                    "value": reg_key,
                    "defanged": reg_key,
                    "page": page_num,
                    "context": context,
                    "role": "Persistence / Execution Key",
                    "confidence": "High"
                })

        # 7. CVEs
        for match in self.cve_regex.finditer(refanged_text):
            cve_str = match.group(0).upper()
            key = ("cve", cve_str)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "cve",
                    "value": cve_str,
                    "defanged": cve_str,
                    "page": page_num,
                    "context": context,
                    "role": "Exploited Vulnerability",
                    "confidence": "High"
                })

        # 8. MITRE ATT&CK IDs
        for match in self.mitre_regex.finditer(refanged_text):
            mitre_id = match.group(0).upper()
            key = ("mitre", mitre_id)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "mitre",
                    "value": mitre_id,
                    "defanged": mitre_id,
                    "page": page_num,
                    "context": context,
                    "role": "Adversary Technique",
                    "confidence": "High"
                })

        # 9. Email Addresses
        for match in self.email_regex.finditer(refanged_text):
            email_str = match.group(0).lower()
            key = ("email", email_str)
            if key not in seen_keys:
                seen_keys.add(key)
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append({
                    "type": "email",
                    "value": email_str,
                    "defanged": self.defang(email_str, "email"),
                    "page": page_num,
                    "context": context,
                    "role": "Spear-phishing / Lure Sender",
                    "confidence": "High"
                })

        return results

    def _get_context_snippet(self, text: str, start: int, end: int, window: int = 100) -> str:
        snippet_start = max(0, start - window)
        snippet_end = min(len(text), end + window)
        snippet = text[snippet_start:snippet_end].replace("\n", " ").replace("\r", " ")
        snippet = re.sub(r"\s+", " ", snippet).strip()
        if snippet_start > 0:
            snippet = "..." + snippet
        if snippet_end < len(text):
            snippet = snippet + "..."
        return snippet

    def _infer_ioc_role(self, context: str, ioc_type: str) -> str:
        ctx = context.lower()
        if any(w in ctx for w in ["c2", "command and control", "beacon", "callback", "listener"]):
            return "Command & Control (C2) Server"
        if any(w in ctx for w in ["phish", "lure", "spear", "credential", "harvest"]):
            return "Phishing / Credential Harvesting"
        if any(w in ctx for w in ["drop", "payload", "stager", "backdoor", "implant", "downloader"]):
            return "Payload Delivery / Dropper"
        if any(w in ctx for w in ["exfil", "upload", "ftp", "leak", "transfer"]):
            return "Data Exfiltration Endpoint"
        if any(w in ctx for w in ["persist", "run key", "autorun", "scheduled task", "service"]):
            return "Persistence Mechanism"
        if any(w in ctx for w in ["exploit", "vulnerability", "rce", "cve"]):
            return "Exploitation Infrastructure"

        if ioc_type in ("ipv4", "domain"):
            return "Suspicious Infrastructure"
        if ioc_type == "url":
            return "Malicious URL / Host"
        if ioc_type in ("sha256", "sha1", "md5", "hash"):
            return "Malicious Binary / Artifact"
        return "Observed Indicator"

    def _calculate_confidence(self, value: str, ioc_type: str, context: str) -> str:
        ctx = context.lower()
        security_terms = [
            "malicious", "threat", "actor", "c2", "trojan", "malware", "ransomware",
            "backdoor", "apt", "compromise", "exploit", "beacon", "ioc", "indicator"
        ]
        term_matches = sum(1 for term in security_terms if term in ctx)

        if term_matches >= 2:
            return "High"
        elif term_matches == 1:
            return "Medium"
        else:
            if ioc_type in ("sha256", "sha1", "cve", "registry"):
                return "High"
            return "Medium"

    def _is_valid_ipv4(self, ip_str: str) -> bool:
        try:
            clean_ip = ip_str.split("/")[0]
            obj = ipaddress.IPv4Address(clean_ip)
            if obj.is_loopback or obj.is_unspecified or obj.is_multicast:
                return False
            if clean_ip in ("0.0.0.0", "255.255.255.255"):
                return False
            return True
        except ValueError:
            return False

    def _is_valid_ipv6(self, ip_str: str) -> bool:
        try:
            obj = ipaddress.IPv6Address(ip_str)
            if obj.is_loopback or obj.is_unspecified:
                return False
            return True
        except ValueError:
            return False
