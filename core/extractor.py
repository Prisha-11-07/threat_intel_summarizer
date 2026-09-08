"""
Core Indicator of Compromise (IoC) Extractor and Sanitizer.
Handles defanging, refanging, regex pattern matching, context extraction,
and confidence calculation for threat intelligence reports.
"""

import ipaddress
import re
from typing import Any, Dict, List, Set, Tuple
from urllib.parse import urlparse

import spacy


class IoCExtractor:
    """Extracts, validates, deduplicates, and defangs/refangs cyber threat indicators."""

    EXCLUDED_EXTENSIONS = {
        "exe", "dll", "pdf", "docx", "xlsx", "pptx", "zip", "rar", "7z", "tar", "gz",
        "py", "ps1", "sh", "bat", "cmd", "vbs", "js", "bin", "sys", "log", "txt", "cfg",
        "ini", "tmp", "bak", "dat", "iso", "img", "json", "xml", "csv", "html", "htm",
        "png", "jpg", "jpeg", "gif", "svg", "ico"
    }

    VALID_TLDS = {
        "com", "org", "net", "edu", "gov", "mil", "int", "io", "co", "ai", "ru", "cn",
        "ir", "kp", "xyz", "top", "online", "site", "live", "store", "tech", "club",
        "vip", "work", "shop", "icu", "click", "cc", "me", "biz", "info", "pro", "mobi",
        "app", "dev", "cloud", "us", "uk", "ca", "de", "fr", "jp", "au", "in", "br", "nl"
    }

    def __init__(self):
        self._compile_regexes()
        try:
            self.nlp = spacy.load("en_core_web_sm")
        except Exception:
            self.nlp = None

    def _compile_regexes(self):
        self.ipv4_regex = re.compile(
            r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
            r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\/(?:3[0-2]|[12]?[0-9]))?\b"
        )
        self.ipv4_candidate_regex = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

        self.ipv6_regex = re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
            r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?::[0-9a-fA-F]{1,4}){1,7}\b|"
            r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
        )

        self.url_regex = re.compile(
            r'\bhttps?://(?:[A-Za-z0-9_\-\.:\@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?(?:/[^\s"\'<>]*)?',
            re.IGNORECASE,
        )

        self.domain_regex = re.compile(
            r"\b(?!(?:https?:\/\/))([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,63})\b",
            re.IGNORECASE,
        )

        self.md5_regex = re.compile(r"\b[a-fA-F0-9]{32}\b")
        self.sha1_regex = re.compile(r"\b[a-fA-F0-9]{40}\b")
        self.sha256_regex = re.compile(r"\b[a-fA-F0-9]{64}\b")
        self.sha512_regex = re.compile(r"\b[a-fA-F0-9]{128}\b")

        self.registry_regex = re.compile(
            r"\b(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKEY_CLASSES_ROOT|HKEY_USERS|"
            r"HKEY_CURRENT_CONFIG|HKLM|HKCU|HKCR|HKU)"
            r"(?:\\[a-zA-Z0-9_\-\. ]+){1,15}\b",
            re.IGNORECASE,
        )

        self.cve_regex = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
        self.mitre_regex = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
        self.email_regex = re.compile(r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b")
        self.file_path_regex = re.compile(
            r"(?:[A-Za-z]:\\(?:[^\\\s\"'<>]+\\)*[A-Za-z0-9_. -]+(?:\.[A-Za-z0-9]{1,10})+|\\\\[^\\\s\"'<>]+(?:\\\\[^\\\s\"'<>]+)*\\[A-Za-z0-9_. -]+(?:\.[A-Za-z0-9]{1,10})+|(?:[A-Za-z]:)?(?:/|\\\\)[A-Za-z0-9_. -]+(?:[\\/][A-Za-z0-9_. -]+)*(?:\.[A-Za-z0-9]{1,10})+)",
            re.IGNORECASE,
        )

    @staticmethod
    def refang(text: str) -> str:
        if not text:
            return ""
        s = text
        s = re.sub(r"\bh[xX]{2}p(s)?://", r"http\1://", s)
        s = re.sub(r"\bf[xX]p://", r"ftp://", s)
        s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[\[\.\]\]", ".", s)
        s = re.sub(r"\[dot\]|\(dot\)|\{dot\}", ".", s, flags=re.IGNORECASE)
        s = re.sub(r"\[:\]|\(:\)", ":", s)
        s = re.sub(r"\[@\]|\(@\)|\[at\]|\(at\)", "@", s, flags=re.IGNORECASE)
        s = re.sub(r"\[\/\]|\(\/\)", "/", s)
        return s

    @staticmethod
    def defang(value: str, ioc_type: str) -> str:
        if not value:
            return ""
        v = value.strip()
        if ioc_type in ("ipv4", "ipv6"):
            v = v.replace(".", "[.]")
        elif ioc_type == "domain":
            return v
        elif ioc_type == "url":
            v = re.sub(r"^https?://", lambda m: m.group(0).replace("tt", "xx"), v)
            v = v.replace(".", "[.]")
        elif ioc_type == "email":
            v = v.replace("@", "[@]").replace(".", "[.]")
        return v

    @staticmethod
    def normalize_value(value: str, ioc_type: str) -> str:
        if not value:
            return ""
        val = value.strip().strip("\"'[](){}<> ")
        if ioc_type in ("ipv4", "ipv6"):
            try:
                return str(ipaddress.ip_address(val.split("/")[0]))
            except ValueError:
                return val.replace("[.]", ".")
        if ioc_type == "domain":
            return val.lower().replace("[.]", ".").rstrip(".")
        if ioc_type == "url":
            return IoCExtractor.refang(val)
        if ioc_type == "cve":
            return val.upper()
        if ioc_type in ("sha256", "sha1", "md5"):
            return val.lower()
        if ioc_type == "email":
            return val.lower()
        if ioc_type == "registry":
            return val
        if ioc_type == "file_path":
            return val.replace("/", "\\")
        return val

    def validate_ioc(self, ioc_type: str, value: str) -> str:
        normalized = self.normalize_value(value, ioc_type)

        if ioc_type == "ipv4":
            try:
                ip_obj = ipaddress.ip_address(normalized)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return "PRIVATE"
                if ip_obj.is_multicast or ip_obj.is_reserved:
                    return "SUSPICIOUS"
                return "VALID"
            except ValueError:
                return "INVALID"

        if ioc_type == "ipv6":
            try:
                ip_obj = ipaddress.ip_address(normalized)
                if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                    return "PRIVATE"
                if ip_obj.is_multicast or ip_obj.is_reserved:
                    return "SUSPICIOUS"
                return "VALID"
            except ValueError:
                return "INVALID"

        if ioc_type == "domain":
            sanitized = normalized.lower()
            if not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", sanitized):
                return "INVALID"
            if sanitized.endswith(".local") or sanitized in {"localhost", "localdomain"}:
                return "PRIVATE"
            if any(token in sanitized for token in ["internal", "corp", "local"]):
                return "SUSPICIOUS"
            return "VALID"

        if ioc_type == "url":
            parsed = urlparse(normalized)
            hostname = (parsed.hostname or "").lower()
            try:
                host_ip = ipaddress.ip_address(hostname)
            except ValueError:
                host_ip = None
            if hostname in {"localhost", "localdomain"} or (host_ip and (
                host_ip.is_private or host_ip.is_loopback or host_ip.is_link_local or
                host_ip.is_reserved or host_ip.is_unspecified
            )):
                return "PRIVATE"
            if parsed.scheme.lower() in {"http", "https"} and parsed.hostname:
                return "VALID"
            return "INVALID"

        if ioc_type in ("md5", "sha1", "sha256"):
            length = {"md5": 32, "sha1": 40, "sha256": 64}[ioc_type]
            return "VALID" if re.fullmatch(r"[a-fA-F0-9]{%d}" % length, normalized) else "INVALID"

        if ioc_type == "cve":
            return "VALID" if re.fullmatch(r"CVE-\d{4}-\d{4,7}", normalized, re.IGNORECASE) else "INVALID"

        if ioc_type == "registry":
            return "VALID" if re.search(r"(?:HKLM|HKCU|HKEY_[A-Z_]+)\\", normalized, re.IGNORECASE) else "INVALID"

        if ioc_type == "email":
            return "VALID" if re.fullmatch(r"[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+", normalized) else "INVALID"

        if ioc_type == "file_path":
            if any(normalized.lower().endswith(ext) for ext in (".exe", ".dll", ".bat", ".ps1", ".cmd", ".js", ".vbs")):
                return "SUSPICIOUS"
            if re.match(r"(?:[A-Za-z]:)?(?:\\\\|/)(?:Windows|Program Files|Users|Temp|AppData|ProgramData)", normalized, re.IGNORECASE):
                return "VALID"
            return "UNKNOWN"

        if ioc_type in ("mitre", "entity", "malware", "threat_actor"):
            return "VALID"

        return "UNKNOWN"

    def _confidence_label(self, score: int) -> str:
        if score >= 80:
            return "High"
        if score >= 60:
            return "Medium"
        return "Low"

    def _calculate_confidence_score(self, context: str, ioc_type: str) -> int:
        ctx = (context or "").lower()
        score = 45
        security_terms = [
            "malicious", "threat", "actor", "c2", "trojan", "malware", "ransomware",
            "backdoor", "apt", "compromise", "exploit", "beacon", "ioc", "indicator",
            "stealer", "dropper", "credential", "vulnerability"
        ]
        score += 10 * sum(1 for term in security_terms if term in ctx)
        if ioc_type in ("sha256", "sha1", "md5", "cve", "registry"):
            score += 20
        if any(word in ctx for word in ["command and control", "beacon", "payload", "dropped", "persistent"]):
            score += 10
        return max(20, min(99, score))

    def _build_normalized_record(self, ioc_type: str, raw_value: str, page_num: int, context: str, role: str) -> Dict[str, Any]:
        normalized = self.normalize_value(raw_value, ioc_type)
        defanged = self.defang(normalized, ioc_type)
        conf_score = self._calculate_confidence_score(context, ioc_type)
        status = self.validate_ioc(ioc_type, normalized)
        record = {
            "type": ioc_type,
            "value": raw_value,
            "normalized_value": normalized,
            "defanged_value": defanged,
            "confidence": self._confidence_label(conf_score),
            "confidence_score": conf_score,
            "source_page": int(page_num),
            "source_text": context,
            "operational_role": role,
            "validation_status": status,
            "page": int(page_num),
            "context": context,
            "role": role,
            "defanged": defanged,
            "page_number": int(page_num),
            "confidence_label": self._confidence_label(conf_score),
        }
        if ioc_type in ("sha256", "sha1", "md5"):
            record["value"] = normalized.lower()
            record["defanged_value"] = normalized.lower()
        return record

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

    def deduplicate_iocs(self, iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        grouped: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for ioc in iocs:
            ioc_type = str(ioc.get("type") or "unknown").strip().lower()
            norm = str(ioc.get("normalized_value") or ioc.get("value") or "").strip()
            if not norm:
                continue
            key = (ioc_type, norm.lower())
            if key not in grouped:
                rec = dict(ioc)
                rec["occurrences"] = 1
                rec["source_pages"] = [int(ioc.get("source_page") or ioc.get("page") or 1)]
                rec["source_texts"] = [str(ioc.get("source_text") or ioc.get("context") or "")]
                grouped[key] = rec
            else:
                rec = grouped[key]
                rec["occurrences"] = int(rec.get("occurrences", 1)) + 1
                if int(ioc.get("confidence_score") or 0) > int(rec.get("confidence_score") or 0):
                    rec["confidence_score"] = ioc.get("confidence_score")
                    rec["confidence"] = ioc.get("confidence", rec.get("confidence"))
                    rec["confidence_label"] = ioc.get("confidence_label", rec.get("confidence_label"))
                page = int(ioc.get("source_page") or ioc.get("page") or 1)
                if page not in rec.get("source_pages", []):
                    rec.setdefault("source_pages", []).append(page)
                text = str(ioc.get("source_text") or ioc.get("context") or "")
                if text and text not in rec.get("source_texts", []):
                    rec.setdefault("source_texts", []).append(text)
        return list(grouped.values())

    def extract_contextual_entities(self, text: str, page_num: int = 1) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        refanged_text = self.refang(text)
        pattern_strings = [
            r"\b(?:APT|UNC|FIN|TA|UAC|NOBELIUM|Cozy Bear|Volt Typhoon|Lazarus|APT29)[^\n,;]{0,80}",
            r"\b(?:[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s*(?:malware|implant|trojan|backdoor|loader|dropper|rat|ransomware|wiper)\b",
        ]
        seen: Set[Tuple[str, str]] = set()
        for pattern in pattern_strings:
            for match in re.finditer(pattern, refanged_text, re.IGNORECASE):
                value = match.group(0).strip()
                if len(value) < 3 or len(value) > 120:
                    continue
                lower_value = value.lower()
                if lower_value in seen:
                    continue
                seen.add(("context", lower_value))
                if re.search(r"\b(?:APT|UNC|FIN|TA)\b", value, re.IGNORECASE):
                    ioc_type = "threat_actor"
                    role = "Threat Actor / Campaign Attribution"
                elif re.search(r"\b(?:malware|implant|trojan|backdoor|loader|dropper|rat|ransomware|wiper)\b", value, re.IGNORECASE):
                    ioc_type = "malware"
                    role = "Malware / Tooling"
                else:
                    ioc_type = "entity"
                    role = "Contextual Entity"
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                results.append(self._build_normalized_record(ioc_type, value, page_num, context, role))

        if self.nlp:
            doc = self.nlp(refanged_text[:120000])
            for ent in doc.ents:
                label = ent.label_
                value = ent.text.strip()
                if len(value) < 3 or len(value) > 80 or "\n" in value:
                    continue
                if label in {"ORG", "PERSON", "NORP", "GPE"}:
                    if re.search(r"\b(?:APT|UNC|FIN|TA|Lazarus|Volt|Typhoon|APT29|Cozy|Bear|NOBELIUM)\b", value, re.IGNORECASE):
                        ioc_type = "threat_actor"
                        role = "Threat Actor / Campaign Attribution"
                    elif re.search(r"\b(?:malware|implant|trojan|backdoor|loader|dropper|ransomware|wiper|rat)\b", value, re.IGNORECASE):
                        ioc_type = "malware"
                        role = "Malware / Tooling"
                    else:
                        ioc_type = "entity"
                        role = "Contextual Entity"
                    key = (ioc_type, value.lower())
                    if key not in seen:
                        seen.add(key)
                        context = self._get_context_snippet(refanged_text, ent.start_char, ent.end_char)
                        results.append(self._build_normalized_record(ioc_type, value, page_num, context, role))

        return results

    def extract_from_text(self, text: str, page_num: int = 1) -> List[Dict[str, Any]]:
        refanged_text = self.refang(text)
        results: List[Dict[str, Any]] = []

        def add_record(ioc_type: str, raw_value: str, context: str, role: str) -> None:
            results.append(self._build_normalized_record(ioc_type, raw_value, page_num, context, role))

        for match in self.url_regex.finditer(refanged_text):
            url_str = match.group(0).rstrip(".,;)>'\"")
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("url", url_str, context, self._infer_ioc_role(context, "url"))

        for match in self.ipv4_regex.finditer(refanged_text):
            ip_str = match.group(0)
            if self._is_valid_ipv4(ip_str):
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                add_record("ipv4", ip_str, context, self._infer_ioc_role(context, "ipv4"))

        # Preserve malformed IPv4-like strings for analyst review instead of silently dropping them.
        valid_ipv4_spans = {match.span() for match in self.ipv4_regex.finditer(refanged_text)}
        for match in self.ipv4_candidate_regex.finditer(refanged_text):
            if any(match.start() >= start and match.end() <= end for start, end in valid_ipv4_spans):
                continue
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("ipv4", match.group(0), context, "Malformed / Unvalidated Indicator")

        for match in self.ipv6_regex.finditer(refanged_text):
            ip_str = match.group(0)
            if self._is_valid_ipv6(ip_str):
                context = self._get_context_snippet(refanged_text, match.start(), match.end())
                add_record("ipv6", ip_str, context, self._infer_ioc_role(context, "ipv6"))

        for match in self.domain_regex.finditer(refanged_text):
            domain_str = match.group(0).rstrip(".,;)>'\"").lower()
            tld = match.group(2).lower()
            if tld in self.EXCLUDED_EXTENSIONS:
                continue
            if tld not in self.VALID_TLDS and len(tld) > 4:
                continue
            if domain_str.startswith("http://") or domain_str.startswith("https://"):
                continue
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain_str):
                continue
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("domain", domain_str, context, self._infer_ioc_role(context, "domain"))

        for match in self.sha256_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("sha256", hash_val, context, self._infer_ioc_role(context, "sha256"))

        for match in self.sha1_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            if hash_val in {rec["normalized_value"] for rec in results if rec["type"] == "sha256"}:
                continue
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("sha1", hash_val, context, self._infer_ioc_role(context, "sha1"))

        for match in self.md5_regex.finditer(refanged_text):
            hash_val = match.group(0).lower()
            if hash_val in {rec["normalized_value"] for rec in results if rec["type"] in {"sha256", "sha1"}}:
                continue
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("md5", hash_val, context, self._infer_ioc_role(context, "md5"))

        for match in self.registry_regex.finditer(refanged_text):
            reg_key = match.group(0).strip()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("registry", reg_key, context, "Persistence / Execution Key")

        for match in self.cve_regex.finditer(refanged_text):
            cve_val = match.group(0).upper()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("cve", cve_val, context, "Exploited Vulnerability")

        for match in self.mitre_regex.finditer(refanged_text):
            mitre_val = match.group(0).upper()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("mitre", mitre_val, context, "Adversary Technique")

        for match in self.email_regex.finditer(refanged_text):
            email_val = match.group(0).lower()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("email", email_val, context, "Spear-phishing / Lure Sender")

        for match in self.file_path_regex.finditer(refanged_text):
            file_val = match.group(0).strip()
            context = self._get_context_snippet(refanged_text, match.start(), match.end())
            add_record("file_path", file_val, context, "Dropped Artifact / File Path")

        if self.nlp:
            doc = self.nlp(refanged_text[:100000])
            for ent in doc.ents:
                ent_str = ent.text.strip()
                if len(ent_str) < 3 or len(ent_str) > 80 or "\n" in ent_str:
                    continue
                if ent.label_ in {"ORG", "GPE", "PERSON", "NORP"}:
                    if re.search(r"\b(?:APT|UNC|FIN|TA|Lazarus|Volt|Typhoon|APT29|Cozy|Bear|NOBELIUM)\b", ent_str, re.IGNORECASE):
                        ioc_type = "threat_actor"
                        role = "Threat Actor / Campaign Attribution"
                    elif re.search(r"\b(?:malware|implant|trojan|backdoor|loader|dropper|ransomware|wiper|rat)\b", ent_str, re.IGNORECASE):
                        ioc_type = "malware"
                        role = "Malware / Tooling"
                    else:
                        ioc_type = "entity"
                        role = "Contextual Entity"
                    context = self._get_context_snippet(refanged_text, ent.start_char, ent.end_char)
                    add_record(ioc_type, ent_str, context, role)

        return results
