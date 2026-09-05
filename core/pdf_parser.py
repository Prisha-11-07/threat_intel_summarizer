"""
Multi-page PDF Threat Intelligence Report Parser.
Extracts structured text per page, document metadata, and vendor signatures.
"""

import io
import re
from typing import Dict, Any, List, Optional, Union
from pypdf import PdfReader


class ThreatReportParser:
    """Parses multi-page PDF cybersecurity reports and sanitizes layout noise."""

    KNOWN_VENDORS = {
        "CISA": [r"cybersecurity and infrastructure security agency", r"cisa alert", r"aa\d{2}-\d{3}[a-z]?"],
        "Mandiant / Google Cloud": [r"mandiant", r"google cloud threat intelligence", r"fireeye"],
        "CrowdStrike": [r"crowdstrike", r"falcon overwat(?:ch)?", r"adversary intelligence"],
        "Palo Alto Networks Unit 42": [r"unit 42", r"palo alto networks"],
        "Microsoft Defender Threat Intelligence": [r"microsoft threat intelligence", r"msti", r"microsoft defender"],
        "Recorded Future": [r"recorded future", r"insikt group"],
        "Trend Micro": [r"trend micro", r"trend micro research"],
        "Cisco Talos": [r"cisco talos", r"talos intelligence"]
    }

    def __init__(self):
        pass

    def parse_pdf(self, source: Union[str, bytes, io.BytesIO]) -> Dict[str, Any]:
        """
        Parses a PDF file path, raw bytes, or BytesIO stream.
        Returns document metadata, page-level structured content, and full sanitized text.
        """
        if isinstance(source, str):
            reader = PdfReader(source)
        elif isinstance(source, bytes):
            reader = PdfReader(io.BytesIO(source))
        elif isinstance(source, io.BytesIO):
            reader = PdfReader(source)
        else:
            raise ValueError("Unsupported source type for PDF parsing.")

        # 1. Metadata extraction
        raw_meta = reader.metadata or {}
        metadata = {
            "title": str(raw_meta.get("/Title") or raw_meta.get("title") or "Threat Intelligence Advisory"),
            "author": str(raw_meta.get("/Author") or raw_meta.get("author") or "Threat Research Team"),
            "subject": str(raw_meta.get("/Subject") or raw_meta.get("subject") or ""),
            "creator": str(raw_meta.get("/Creator") or raw_meta.get("creator") or ""),
            "total_pages": len(reader.pages)
        }

        # 2. Extract text per page
        pages: List[Dict[str, Any]] = []
        full_text_list: List[str] = []

        for idx, page in enumerate(reader.pages):
            page_num = idx + 1
            raw_text = page.extract_text() or ""
            cleaned_text = self._clean_page_text(raw_text)

            pages.append({
                "page_number": page_num,
                "text": cleaned_text,
                "raw_text": raw_text,
                "word_count": len(cleaned_text.split()),
                "char_count": len(cleaned_text)
            })
            full_text_list.append(cleaned_text)

        full_text = "\n\n--- [Page Break] ---\n\n".join(full_text_list)

        # 3. Detect vendor
        detected_vendor = self._detect_vendor(full_text, metadata)

        # 4. Extract TLP (Traffic Light Protocol) marking if present
        tlp = self._detect_tlp(full_text)

        return {
            "metadata": metadata,
            "vendor": detected_vendor,
            "tlp": tlp,
            "total_pages": len(reader.pages),
            "pages": pages,
            "full_text": full_text
        }

    def _clean_page_text(self, text: str) -> str:
        """Removes common header/footer boilerplate and layout artifacts."""
        lines = text.splitlines()
        cleaned_lines: List[str] = []

        for line in lines:
            stripped = line.strip()
            # Remove isolated page numbers like "Page 1 of 8" or "- 3 -"
            if re.match(r"^(?:page\s+\d+(\s+of\s+\d+)?|-?\s*\d+\s*-?)$", stripped, re.IGNORECASE):
                continue
            cleaned_lines.append(line)

        # Recombine and normalize carriage returns
        result = "\n".join(cleaned_lines)
        result = re.sub(r"\r\n|\r", "\n", result)
        # Normalize non-breaking spaces
        result = result.replace("\u00a0", " ")
        return result

    def _detect_vendor(self, full_text: str, metadata: Dict[str, Any]) -> str:
        """Identifies the cybersecurity research vendor responsible for the report."""
        search_corpus = f"{metadata.get('title', '')} {metadata.get('author', '')} {full_text[:3000]}".lower()

        for vendor_name, patterns in self.KNOWN_VENDORS.items():
            for pattern in patterns:
                if re.search(pattern, search_corpus, re.IGNORECASE):
                    return vendor_name

        return "Independent Threat Advisory"

    def _detect_tlp(self, text: str) -> str:
        """Detects FIRST / CISA Traffic Light Protocol (TLP) designation."""
        m = re.search(r"\bTLP:(CLEAR|GREEN|AMBER\+STRICT|AMBER|RED)\b", text, re.IGNORECASE)
        if m:
            return f"TLP:{m.group(1).upper()}"
        return "TLP:CLEAR"
