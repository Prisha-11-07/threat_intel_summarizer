"""
Firewall & Defensive Countermeasures Rule Generator.
Transforms extracted threat indicators into immediate, deployable rules for
Palo Alto Networks, Fortinet FortiGate, Cisco ASA, Linux iptables,
Suricata / Snort 3 IDS/IPS, Zeek Intel, and SIEM CSV lookup tables.
"""

from typing import List, Dict, Any


class FirewallRuleGenerator:
    """Generates enterprise firewall, IDS, and EDR configuration scripts."""

    def __init__(self):
        pass

    @staticmethod
    def _enforceable(ioc: Dict[str, Any]) -> bool:
        """Only validated indicators enter automatic blocking configurations."""
        status = str(ioc.get("validation_status", "VALID")).upper()
        return status == "VALID"

    def generate_all(self, iocs: List[Dict[str, Any]], threat_actor: str = "Adversary") -> Dict[str, str]:
        """Generates configuration artifacts across all supported defense platforms."""
        return {
            "suricata": self.to_suricata(iocs, threat_actor),
            "palo_alto": self.to_palo_alto(iocs, threat_actor),
            "fortigate": self.to_fortigate(iocs, threat_actor),
            "cisco_asa": self.to_cisco_asa(iocs, threat_actor),
            "iptables": self.to_iptables(iocs, threat_actor),
            "zeek": self.to_zeek_intel(iocs, threat_actor),
            "siem_csv": self.to_siem_csv(iocs, threat_actor),
            "edr_hashes": self.to_edr_hashes(iocs, threat_actor)
        }

    def to_suricata(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Suricata / Snort 3 IDS/IPS drop and alert rules."""
        rules: List[str] = [
            f"# ========================================================",
            f"# Suricata / Snort 3 Threat Ingestion Rules",
            f"# Attribution: {threat_actor}",
            f"# Generated via Automated Threat Intelligence Engine",
            f"# ========================================================\n"
        ]

        sid_counter = 3001000

        # IP drop rules
        for ioc in iocs:
            if ioc["type"] == "ipv4" and self._enforceable(ioc):
                ip = ioc["value"]
                rule = (
                    f'drop ip any any <> {ip} any ('
                    f'msg:"SOC-BLOCK {threat_actor} - Outbound/Inbound C2 Communication [{ip}]"; '
                    f'classtype:trojan-activity; sid:{sid_counter}; rev:1;)'
                )
                rules.append(rule)
                sid_counter += 1

        # Domain DNS inspection rules
        for ioc in iocs:
            if ioc["type"] == "domain" and self._enforceable(ioc):
                domain = ioc["value"]
                rule = (
                    f'drop dns any any -> any 53 ('
                    f'msg:"SOC-BLOCK {threat_actor} - DNS Query to Malicious Domain [{domain}]"; '
                    f'dns.query; content:"{domain}"; nocase; endswith; '
                    f'classtype:bad-unknown; sid:{sid_counter}; rev:1;)'
                )
                rules.append(rule)
                sid_counter += 1

        # HTTP / TLS Host rules
        for ioc in iocs:
            if ioc["type"] == "url" and self._enforceable(ioc):
                url = ioc["value"]
                rule = (
                    f'drop http any any -> any any ('
                    f'msg:"SOC-BLOCK {threat_actor} - Malicious HTTP Request [{url[:40]}...]"; '
                    f'http.uri; content:"{url[:30]}"; nocase; '
                    f'classtype:web-application-attack; sid:{sid_counter}; rev:1;)'
                )
                rules.append(rule)
                sid_counter += 1

        return "\n".join(rules)

    def to_palo_alto(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates PAN-OS CLI configuration and External Dynamic List (EDL) text."""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4" and self._enforceable(i)]
        domains = [i["value"] for i in iocs if i["type"] == "domain" and self._enforceable(i)]
        urls = [i["value"] for i in iocs if i["type"] == "url" and self._enforceable(i)]

        lines = [
            f"# Palo Alto Networks PAN-OS Configuration Commands",
            f"# Threat Campaign: {threat_actor}",
            f"# Apply in configure mode\n",
            "configure"
        ]

        # Address objects
        for ip in ips:
            clean_name = f"IOC_IP_{ip.replace('.', '_')}"
            lines.append(f"set address {clean_name} ip-netmask {ip}/32 description \"Threat Intel: {threat_actor}\"")

        if ips:
            group_members = " ".join([f"IOC_IP_{ip.replace('.', '_')}" for ip in ips])
            lines.append(f"set address-group AG_THREAT_INTEL_{threat_actor.replace(' ', '_')} static [ {group_members} ]")

        # Custom URL Category for Domains / URLs
        block_items = domains + urls
        if block_items:
            items_str = " ".join([f'"{item}"' for item in block_items[:30]])
            lines.append(f"set profiles custom-url-category URL_BLOCK_{threat_actor.replace(' ', '_')} list [ {items_str} ]")

        # Security rule
        lines.append(
            f"set rulebase security rules BLOCK_{threat_actor.replace(' ', '_')}_EGRESS "
            f"from trust to untrust source any destination [ AG_THREAT_INTEL_{threat_actor.replace(' ', '_')} ] "
            f"service any application any action drop log-end yes"
        )
        lines.append("commit")
        lines.append("exit")

        return "\n".join(lines)

    def to_fortigate(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Fortinet FortiGate FortiOS CLI configuration script."""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4" and self._enforceable(i)]
        domains = [i["value"] for i in iocs if i["type"] == "domain" and self._enforceable(i)]

        lines = [
            f"# Fortinet FortiGate FortiOS Configuration",
            f"# Threat Actor: {threat_actor}\n",
            "config firewall address"
        ]

        addr_names = []
        for ip in ips:
            name = f"IOC_{ip.replace('.', '_')}"
            addr_names.append(name)
            lines.extend([
                f'  edit "{name}"',
                f'    set subnet {ip} 255.255.255.255',
                f'    set comment "Threat Intel - {threat_actor}"',
                "  next"
            ])

        for dom in domains:
            name = f"IOC_FQDN_{dom.replace('.', '_')[:24]}"
            addr_names.append(name)
            lines.extend([
                f'  edit "{name}"',
                f'    set type fqdn',
                f'    set fqdn "{dom}"',
                f'    set comment "Threat Intel - {threat_actor}"',
                "  next"
            ])
        lines.append("end\n")

        # Address group
        if addr_names:
            group_name = f"GRP_BLOCK_{threat_actor.replace(' ', '_')[:20]}"
            members_str = " ".join([f'"{n}"' for n in addr_names[:40]])
            lines.extend([
                "config firewall addrgrp",
                f'  edit "{group_name}"',
                f'    set member {members_str}',
                "  next",
                "end\n"
            ])

            # Drop policy
            lines.extend([
                "config firewall policy",
                "  edit 0",
                f'    set name "BLOCK_{threat_actor.replace(" ", "_")[:15]}"',
                '    set srcintf "any"',
                '    set dstintf "any"',
                '    set srcaddr "all"',
                f'    set dstaddr "{group_name}"',
                '    set action deny',
                '    set schedule "always"',
                '    set service "ALL"',
                '    set logtraffic all',
                "  next",
                "end"
            ])

        return "\n".join(lines)

    def to_cisco_asa(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Cisco ASA / Firepower access-list and object-group configuration."""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4" and self._enforceable(i)]
        group_name = f"OG_BLOCK_{threat_actor.replace(' ', '_')[:16]}"

        lines = [
            f"! Cisco ASA / Firepower CLI Ingestion",
            f"! Threat Campaign: {threat_actor}\n",
            f"object-group network {group_name}"
        ]

        for ip in ips:
            lines.append(f" network-object host {ip}")

        lines.extend([
            "exit\n",
            f"! Apply Deny ACE to Perimeter Access List",
            f"access-list OUTSIDE_IN line 1 extended deny ip object-group {group_name} any log interval 300",
            f"access-list OUTSIDE_IN line 2 extended deny ip any object-group {group_name} log interval 300",
            f"access-list INSIDE_OUT line 1 extended deny ip any object-group {group_name} log interval 300"
        ])

        return "\n".join(lines)

    def to_iptables(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Linux iptables / nftables shell commands for Linux gateways."""
        ips = [i["value"] for i in iocs if i["type"] == "ipv4" and self._enforceable(i)]

        lines = [
            f"#!/usr/bin/env bash",
            f"# Linux iptables Threat Feed Enforcement",
            f"# Target: {threat_actor}\n",
            f"echo '[+] Applying iptables drop rules for {threat_actor}...'"
        ]

        for ip in ips:
            lines.append(f"iptables -I INPUT 1 -s {ip} -m comment --comment \"SOC Threat Intel: {threat_actor}\" -j DROP")
            lines.append(f"iptables -I OUTPUT 1 -d {ip} -m comment --comment \"SOC Threat Intel: {threat_actor}\" -j DROP")
            lines.append(f"iptables -I FORWARD 1 -d {ip} -m comment --comment \"SOC Threat Intel: {threat_actor}\" -j DROP")

        lines.append(f"echo '[✓] Enforced {len(ips)} IP block rules successfully.'")
        return "\n".join(lines)

    def to_zeek_intel(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Zeek (Bro) Intelligence Framework tab-delimited file (intel.dat)."""
        lines = [
            "#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.confidence"
        ]

        for ioc in iocs:
            if not self._enforceable(ioc):
                continue
            ioc_type = ioc["type"]
            val = ioc["value"]
            conf = ioc.get("confidence", "High")
            desc = f"{threat_actor}_{ioc.get('role', 'malicious')}".replace(" ", "_")

            if ioc_type == "ipv4":
                lines.append(f"{val}\tIntel::ADDR\tThreatIntelApp\t{desc}\t{conf}")
            elif ioc_type == "domain":
                lines.append(f"{val}\tIntel::DOMAIN\tThreatIntelApp\t{desc}\t{conf}")
            elif ioc_type == "url":
                lines.append(f"{val}\tIntel::URL\tThreatIntelApp\t{desc}\t{conf}")
            elif ioc_type == "sha256":
                lines.append(f"{val}\tIntel::FILE_HASH\tThreatIntelApp\t{desc}\t{conf}")
            elif ioc_type == "email":
                lines.append(f"{val}\tIntel::EMAIL\tThreatIntelApp\t{desc}\t{conf}")

        return "\n".join(lines)

    def to_siem_csv(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates standard CSV lookup table for Splunk, Elastic, Sentinel, and QRadar."""
        lines = ["indicator,type,defanged,threat_actor,role,confidence,action"]
        for ioc in iocs:
            val = f'"{ioc["value"]}"'
            defanged = f'"{ioc.get("defanged", ioc["value"])}"'
            role = f'"{ioc.get("role", "Indicator")}"'
            action = "BLOCK" if self._enforceable(ioc) else "REVIEW"
            lines.append(f"{val},{ioc['type']},{defanged},\"{threat_actor}\",{role},{ioc.get('confidence', 'High')},{action}")

        return "\n".join(lines)

    def to_edr_hashes(self, iocs: List[Dict[str, Any]], threat_actor: str) -> str:
        """Generates Hash Blocklist CSV for CrowdStrike Falcon, Carbon Black, Defender for Endpoint."""
        lines = ["hash,hash_type,threat_actor,policy_action,comment"]
        for ioc in iocs:
            if ioc["type"] in ("sha256", "sha1", "md5") and self._enforceable(ioc):
                lines.append(f"{ioc['value']},{ioc['type'].upper()},\"{threat_actor}\",ALWAYS_BLOCK,\"Threat Intel Ingestion: {threat_actor}\"")

        return "\n".join(lines)
