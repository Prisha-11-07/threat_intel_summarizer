"""
STIX 2.1 JSON Bundle & TAXII 2.1 Exporter.
Fully compliant with OASIS STIX 2.1 Specification (OASIS Open Standard).
Generates standardized Threat Actor, Malware, Attack Pattern, Vulnerability,
Indicator, and Relationship SDOs/SROs.
"""

import uuid
import datetime
import re
from typing import Dict, Any, List


class STIX21Generator:
    """Produces standardized OASIS STIX 2.1 bundles for TAXII and SOAR ingestion."""

    def __init__(self, org_name: str = "SOC Threat Intelligence Automation Platform"):
        self.org_name = org_name
        self.namespace = uuid.NAMESPACE_DNS

    def _generate_deterministic_id(self, sdo_type: str, seed: str) -> str:
        """Creates reproducible STIX 2.1 IDs using UUIDv5."""
        uid = uuid.uuid5(self.namespace, f"{sdo_type}:{seed}")
        return f"{sdo_type}--{uid}"

    def _get_timestamp(self) -> str:
        """Returns ISO 8601 formatted UTC timestamp with millisecond precision and Z suffix."""
        return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

    def build_bundle(
        self,
        analysis: Dict[str, Any],
        iocs: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Builds a complete, valid STIX 2.1 Bundle dictionary.
        """
        now = self._get_timestamp()
        iocs = self._deduplicate_iocs(iocs)
        objects: List[Dict[str, Any]] = []

        # 1. Identity SDO (Reporting Organization / SOC)
        identity_id = self._generate_deterministic_id("identity", self.org_name)
        identity_obj = {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": self.org_name,
            "identity_class": "organization",
            "sectors": ["defense", "technology"],
            "contact_information": "soc-intel-feed@enterprise-defense.local"
        }
        objects.append(identity_obj)

        # 2. Threat Actor SDO
        threat_actor_data = analysis.get("threat_actor", {})
        actor_name = threat_actor_data.get("name", "Unattributed Threat Actor")
        actor_id = self._generate_deterministic_id("threat-actor", actor_name)

        actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": actor_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": actor_name,
            "aliases": threat_actor_data.get("aliases", []),
            "threat_actor_types": ["nation-state" if "state" in threat_actor_data.get("origin", "").lower() else "cybercrime"],
            "sophistication": "advanced",
            "resource_level": "government" if "state" in threat_actor_data.get("origin", "").lower() else "organization",
            "primary_motivation": "espionage" if "espionage" in threat_actor_data.get("motivation", "").lower() else "financial-gain",
            "description": f"Threat actor tracked as {actor_name}. Origin: {threat_actor_data.get('origin')}. Tactics: {threat_actor_data.get('tactics')}."
        }
        objects.append(actor_obj)

        # 3. Malware SDOs
        malware_refs = []
        for m_name in analysis.get("malware_families", []):
            m_id = self._generate_deterministic_id("malware", m_name)
            malware_obj = {
                "type": "malware",
                "spec_version": "2.1",
                "id": m_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": m_name,
                "is_family": True,
                "malware_types": ["backdoor", "trojan"],
                "description": f"Malware family or tool '{m_name}' leveraged during intrusion operations."
            }
            objects.append(malware_obj)
            malware_refs.append(m_id)

            # Relationship: Threat Actor -> uses -> Malware
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": self._generate_deterministic_id("relationship", f"{actor_id}-uses-{m_id}"),
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": m_id
            })

        # 4. Attack Pattern SDOs (MITRE ATT&CK)
        mitre_list = analysis.get("mitre_attack", [])
        for tech in mitre_list:
            tech_id = tech.get("id")
            ap_id = self._generate_deterministic_id("attack-pattern", tech_id)
            ap_obj = {
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": ap_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": tech.get("name", tech_id),
                "description": tech.get("description", ""),
                "external_references": [
                    {
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                    }
                ]
            }
            objects.append(ap_obj)

            # Relationship: Threat Actor -> uses -> Attack Pattern
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": self._generate_deterministic_id("relationship", f"{actor_id}-uses-{ap_id}"),
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "relationship_type": "uses",
                "source_ref": actor_id,
                "target_ref": ap_id
            })

        # 5. Vulnerability SDOs (CVEs)
        for ioc in iocs:
            if ioc["type"] == "cve":
                cve_id_val = ioc["value"]
                vuln_id = self._generate_deterministic_id("vulnerability", cve_id_val)
                vuln_obj = {
                    "type": "vulnerability",
                    "spec_version": "2.1",
                    "id": vuln_id,
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "name": cve_id_val,
                    "description": f"Vulnerability {cve_id_val} exploited by {actor_name} for initial access.",
                    "external_references": [
                        {
                            "source_name": "cve",
                            "external_id": cve_id_val,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id_val}"
                        }
                    ]
                }
                objects.append(vuln_obj)

                # Relationship: Threat Actor -> targets / exploits -> Vulnerability
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": self._generate_deterministic_id("relationship", f"{actor_id}-targets-{vuln_id}"),
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "targets",
                    "source_ref": actor_id,
                    "target_ref": vuln_id
                })

        # 6. Indicator SDOs with STIX 2.1 Pattern Language
        for ioc in iocs:
            if str(ioc.get("validation_status", "VALID")).upper() != "VALID":
                continue
            pattern = self._build_stix_pattern(ioc)
            if not pattern:
                continue

            ind_id = self._generate_deterministic_id("indicator", f"{ioc['type']}:{ioc['value']}")
            ind_type_label = self._map_indicator_type(ioc["type"])
            confidence_val = 85 if ioc.get("confidence") == "High" else 60

            ind_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ind_id,
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "name": f"Validated {ioc['type'].upper()}: {ioc.get('defanged_value', ioc.get('defanged'))}",
                "description": f"Indicator associated with {actor_name}. Role: {ioc.get('role')}. Source context: {ioc.get('context')}",
                "indicator_types": [ind_type_label],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": now,
                "confidence": confidence_val
            }
            objects.append(ind_obj)

            # Relationship: Indicator -> indicates -> Threat Actor
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": self._generate_deterministic_id("relationship", f"{ind_id}-indicates-{actor_id}"),
                "created_by_ref": identity_id,
                "created": now,
                "modified": now,
                "relationship_type": "indicates",
                "source_ref": ind_id,
                "target_ref": actor_id
            })

            # If malware is present, link Indicator -> indicates -> Primary Malware
            if malware_refs:
                primary_malware = malware_refs[0]
                objects.append({
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": self._generate_deterministic_id("relationship", f"{ind_id}-indicates-{primary_malware}"),
                    "created_by_ref": identity_id,
                    "created": now,
                    "modified": now,
                    "relationship_type": "indicates",
                    "source_ref": ind_id,
                    "target_ref": primary_malware
                })

        # 7. Report SDO ties the generated intelligence to the source advisory.
        report_title = analysis.get("report_title") or "Threat Intelligence Report"
        report_id = self._generate_deterministic_id("report", report_title)
        report_refs = [identity_id, actor_id]
        report_refs.extend(malware_refs)
        report_refs.extend(
            obj["id"] for obj in objects
            if obj.get("type") in {"indicator", "vulnerability", "attack-pattern"}
        )
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created_by_ref": identity_id,
            "created": now,
            "modified": now,
            "name": str(report_title),
            "description": str(analysis.get("executive_summary") or "Generated from extracted report intelligence."),
            "report_types": ["threat-report"],
            "published": now,
            "object_refs": report_refs,
        })

        # 7. Final STIX 2.1 Bundle Container
        bundle_id = f"bundle--{uuid.uuid4()}"
        bundle = {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects
        }

        return bundle

    def validate_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        """Validate the generated bundle without accepting static or incomplete objects."""
        errors: List[str] = []
        if bundle.get("type") != "bundle":
            errors.append("Bundle type must be 'bundle'.")
        if not re.fullmatch(r"bundle--[0-9a-f-]{36}", str(bundle.get("id", ""))):
            errors.append("Bundle ID is not a UUID-based STIX ID.")

        objects = bundle.get("objects")
        if not isinstance(objects, list) or not objects:
            errors.append("Bundle must contain objects.")
            return {"valid": False, "errors": errors, "object_count": 0}

        object_ids = set()
        supported_types = {"identity", "threat-actor", "malware", "indicator", "vulnerability", "attack-pattern", "report", "relationship"}
        for index, obj in enumerate(objects):
            prefix = f"objects[{index}]"
            if not isinstance(obj, dict):
                errors.append(f"{prefix} is not an object.")
                continue
            obj_type = obj.get("type")
            obj_id = str(obj.get("id", ""))
            if obj_type not in supported_types:
                errors.append(f"{prefix} has unsupported type {obj_type!r}.")
            if not re.fullmatch(rf"{re.escape(str(obj_type))}--[0-9a-f-]{{36}}", obj_id):
                errors.append(f"{prefix} has an invalid STIX ID.")
            if obj_id in object_ids:
                errors.append(f"{prefix} duplicates ID {obj_id}.")
            object_ids.add(obj_id)
            if obj.get("spec_version") != "2.1":
                errors.append(f"{prefix} is missing STIX 2.1 spec_version.")
            for timestamp_field in ("created", "modified"):
                if not self._valid_timestamp(obj.get(timestamp_field)):
                    errors.append(f"{prefix}.{timestamp_field} is not an ISO-8601 UTC timestamp.")
            if obj_type in {"threat-actor", "malware", "indicator", "vulnerability", "attack-pattern", "report"}:
                if not obj.get("created_by_ref") or obj["created_by_ref"] not in object_ids and obj["created_by_ref"] != objects[0].get("id"):
                    errors.append(f"{prefix}.created_by_ref does not reference an identity.")
            if obj_type == "indicator":
                if obj.get("pattern_type") != "stix" or obj.get("pattern_version") != "2.1":
                    errors.append(f"{prefix} is missing STIX 2.1 indicator metadata.")
                if not self._valid_stix_pattern(obj.get("pattern")):
                    errors.append(f"{prefix}.pattern is not a supported STIX pattern.")
                if not isinstance(obj.get("valid_from"), str) or not self._valid_timestamp(obj["valid_from"]):
                    errors.append(f"{prefix}.valid_from is invalid.")
            if obj_type == "report" and not obj.get("object_refs"):
                errors.append(f"{prefix}.object_refs must not be empty.")

        for index, obj in enumerate(objects):
            if obj.get("type") == "relationship":
                for ref_field in ("source_ref", "target_ref"):
                    if obj.get(ref_field) not in object_ids:
                        errors.append(f"objects[{index}].{ref_field} does not resolve.")
            if obj.get("type") == "report":
                for ref in obj.get("object_refs", []):
                    if ref not in object_ids:
                        errors.append(f"Report object reference {ref} does not resolve.")

        return {"valid": not errors, "errors": errors, "object_count": len(objects)}

    @staticmethod
    def _valid_timestamp(value: Any) -> bool:
        if not isinstance(value, str) or not value.endswith("Z"):
            return False
        try:
            datetime.datetime.fromisoformat(value[:-1] + "+00:00")
            return True
        except ValueError:
            return False

    @staticmethod
    def _valid_stix_pattern(pattern: Any) -> bool:
        if not isinstance(pattern, str) or not pattern.startswith("[") or not pattern.endswith("]"):
            return False
        return ":" in pattern and "=" in pattern

    @staticmethod
    def _deduplicate_iocs(iocs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        unique: Dict[tuple[str, str], Dict[str, Any]] = {}
        for ioc in iocs:
            ioc_type = str(ioc.get("type") or "").lower()
            value = str(ioc.get("normalized_value") or ioc.get("value") or "").lower()
            if ioc_type and value and (ioc_type, value) not in unique:
                unique[(ioc_type, value)] = ioc
        return list(unique.values())

    def _build_stix_pattern(self, ioc: Dict[str, Any]) -> str:
        """Constructs valid STIX 2.1 pattern language expressions."""
        ioc_type = ioc["type"]
        val = ioc["value"]

        # Escape single quotes in value
        safe_val = val.replace("'", "\\'")

        if ioc_type == "ipv4":
            return f"[ipv4-addr:value = '{safe_val}']"
        elif ioc_type == "ipv6":
            return f"[ipv6-addr:value = '{safe_val}']"
        elif ioc_type == "domain":
            return f"[domain-name:value = '{safe_val}']"
        elif ioc_type == "url":
            return f"[url:value = '{safe_val}']"
        elif ioc_type == "sha256":
            return f"[file:hashes.'SHA-256' = '{safe_val}']"
        elif ioc_type == "sha1":
            return f"[file:hashes.'SHA-1' = '{safe_val}']"
        elif ioc_type == "md5":
            return f"[file:hashes.'MD5' = '{safe_val}']"
        elif ioc_type == "registry":
            return f"[windows-registry-key:key = '{safe_val}']"
        elif ioc_type == "email":
            return f"[email-addr:value = '{safe_val}']"
        elif ioc_type == "cve":
            return f"[vulnerability:name = '{safe_val}']"
        elif ioc_type == "mitre":
            return f"[attack-pattern:external_references[*].external_id = '{safe_val}']"

        return ""

    def _map_indicator_type(self, ioc_type: str) -> str:
        """Maps IoC type to standard STIX 2.1 indicator-type-ov open vocabulary."""
        mapping = {
            "ipv4": "malicious-activity",
            "ipv6": "malicious-activity",
            "domain": "malicious-activity",
            "url": "malicious-activity",
            "sha256": "malicious-activity",
            "sha1": "malicious-activity",
            "md5": "malicious-activity",
            "registry": "anomalous-activity",
            "email": "malicious-activity"
        }
        return mapping.get(ioc_type, "unknown")
