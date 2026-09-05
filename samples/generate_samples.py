"""
Generates authentic multi-page PDF threat intelligence advisories from
prominent cybersecurity vendors (CISA, Mandiant, CrowdStrike) for evaluation.
"""

import os
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfgen import canvas


class NumberedCanvas(canvas.Canvas):
    """Adds professional running header and footer with page numbers and TLP markings."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Header
        self.drawString(54, 750, "CYBERSECURITY ADVISORY | THREAT INTELLIGENCE OPERATIONS")
        self.drawRightString(558, 750, "TLP:CLEAR")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 744, 558, 744)

        # Footer
        self.line(54, 48, 558, 48)
        self.drawString(54, 36, "FOR OFFICIAL SECURITY OPERATIONS & DEFENSE USE")
        self.drawRightString(558, 36, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def create_cisa_report(output_path: str):
    """Creates multi-page CISA Joint Cybersecurity Advisory on Volt Typhoon."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=60, bottomMargin=60
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        'CISATitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6
    )
    subtitle_style = ParagraphStyle(
        'CISASubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#334155"),
        spaceAfter=12
    )
    heading2_style = ParagraphStyle(
        'CISAHeading2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=colors.HexColor("#1e3a8a"),
        spaceBefore=10,
        spaceAfter=4
    )
    body_style = ParagraphStyle(
        'CISABody',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1e293b"),
        spaceAfter=8
    )
    callout_style = ParagraphStyle(
        'CISACallout',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#0369a1")
    )
    table_cell = ParagraphStyle(
        'TableCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0f172a")
    )
    table_header = ParagraphStyle(
        'TableHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white
    )

    story = []

    # Title & Metadata Banner
    story.append(Paragraph("CYBERSECURITY AND INFRASTRUCTURE SECURITY AGENCY (CISA)", ParagraphStyle('MetaHead', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor("#0284c7"))))
    story.append(Paragraph("Joint Cybersecurity Advisory | Alert Code: AA24-105A", ParagraphStyle('MetaCode', fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor("#64748b"))))
    story.append(Spacer(1, 4))
    story.append(Paragraph("PRC State-Sponsored Actors (Volt Typhoon) Target U.S. Critical Infrastructure via Living-off-the-Land Techniques", title_style))
    story.append(Paragraph("Release Date: February 2024 | Dissemination: TLP:CLEAR | Target Sectors: Energy, Water, Transportation, Defense", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=10))

    # Executive Summary
    story.append(Paragraph("EXECUTIVE SUMMARY", heading2_style))
    story.append(Paragraph(
        "The Cybersecurity and Infrastructure Security Agency (CISA), National Security Agency (NSA), and Federal Bureau of Investigation (FBI) "
        "are releasing this joint Cybersecurity Advisory (CSA) to warn critical infrastructure organizations of ongoing malicious activity "
        "attributed to the People's Republic of China (PRC) state-sponsored cyber group known as <b>Volt Typhoon</b> (also tracked as BRONZE SILHOUETTE and Vanguard Panda). "
        "Volt Typhoon targets critical infrastructure networks across the United States, including communications, energy, transportation systems, and water facilities. "
        "The adversary's choice of targets and pattern of behavior indicates that Volt Typhoon is pre-positioning access to disrupt operational technology (OT) "
        "and critical IT assets in the event of major geopolitical conflicts.",
        body_style
    ))

    # Alert Box
    alert_data = [[
        Paragraph("<b>CRITICAL ACTION REQUIRED:</b> Network defenders are strongly urged to review internet-facing edge appliances, enforce phishing-resistant MFA, and immediately ingest the Indicators of Compromise (IoCs) in Appendix A into enterprise perimeter blocklists.", callout_style)
    ]]
    alert_table = Table(alert_data, colWidths=[500])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f0f9ff")),
        ('BORDER', (0, 0), (-1, -1), 1, colors.HexColor("#38bdf8")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 10),
        ('RIGHTPADDING', (0, 0), (-1, -1), 10),
    ]))
    story.append(alert_table)
    story.append(Spacer(1, 10))

    # Technical Details: Initial Access & Exploitation
    story.append(Paragraph("TECHNICAL ANALYSIS: INITIAL ACCESS & EDGE EXPLOITATION", heading2_style))
    story.append(Paragraph(
        "Volt Typhoon gains initial access primarily by exploiting zero-day and public-facing vulnerabilities in enterprise edge gateways and SOHO network appliances. "
        "Recent intrusions demonstrated weaponization of <b>CVE-2023-46805</b> (authentication bypass) and <b>CVE-2024-21887</b> (command injection) affecting Ivanti Connect Secure VPNs, "
        "as well as vulnerabilities in Fortinet FortiOS and Cisco RV320/RV325 routers. "
        "Upon perimeter compromise, the actors establish web shells and deploy Fast Reverse Proxy (FRP) tooling to tunnel malicious traffic through a vast covert operational network "
        "composed of compromised customer-premises equipment (CPE) across multiple global telecommunications providers.",
        body_style
    ))

    # Page Break for Multi-page demonstration
    story.append(PageBreak())

    # Attack Methodology & Living-off-the-land
    story.append(Paragraph("ATTACK METHODOLOGY & PERSISTENCE (LIVING-OFF-THE-LAND)", heading2_style))
    story.append(Paragraph(
        "A hallmark of Volt Typhoon operations is the strict reliance on built-in administrative utilities—commonly termed <b>Living-off-the-Land (LotL)</b>—to avoid detection by endpoint detection and response (EDR) sensors. "
        "Rather than deploying customary malware implants, the group abuses native Windows binaries such as <code>wmic.exe</code>, <code>powershell.exe</code>, <code>netsh.exe</code>, and <code>nltest.exe</code>. "
        "To establish persistent administrative access, the adversary modifies Windows registry run keys and schedules proxy services under the following paths:<br/>"
        "• <code>HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\VoltSvc</code><br/>"
        "• <code>HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\PortProxy</code><br/>"
        "The actors routinely utilize <code>netsh interface portproxy</code> commands to relay port traffic across segmented subnets, disguising lateral traversal as legitimate internal telemetry.",
        body_style
    ))

    # MITRE ATT&CK Mapping Section
    story.append(Paragraph("MITRE ATT&CK MAPPING", heading2_style))
    mitre_rows = [
        [Paragraph("Tactic", table_header), Paragraph("Technique ID", table_header), Paragraph("Technique Name", table_header), Paragraph("Adversary Implementation", table_header)],
        [Paragraph("Initial Access", table_cell), Paragraph("T1190", table_cell), Paragraph("Exploit Public-Facing Application", table_cell), Paragraph("Exploitation of CVE-2023-46805 & CVE-2024-21887 on VPNs", table_cell)],
        [Paragraph("Execution", table_cell), Paragraph("T1059.001", table_cell), Paragraph("PowerShell", table_cell), Paragraph("Execution of encoded recon scripts and staging commands", table_cell)],
        [Paragraph("Persistence", table_cell), Paragraph("T1547.001", table_cell), Paragraph("Registry Run Keys / Startup", table_cell), Paragraph("Autostart entry in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", table_cell)],
        [Paragraph("Defense Evasion", table_cell), Paragraph("T1070", table_cell), Paragraph("Indicator Removal on Host", table_cell), Paragraph("Deletion of shadow copies and clearing security event logs via wevtutil", table_cell)],
        [Paragraph("Command and Control", table_cell), Paragraph("T1071.001", table_cell), Paragraph("Web Protocols", table_cell), Paragraph("HTTP/HTTPS beaconing through compromised SOHO proxy nodes", table_cell)],
    ]
    mitre_table = Table(mitre_rows, colWidths=[80, 75, 140, 205])
    mitre_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#0f766e")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(mitre_table)
    story.append(Spacer(1, 10))

    # Page Break to Appendix (IoCs)
    story.append(PageBreak())

    # Appendix: Structured Indicators of Compromise (IoCs)
    story.append(Paragraph("APPENDIX A: INDICATORS OF COMPROMISE (IoCs)", heading2_style))
    story.append(Paragraph(
        "All network and host-based indicators listed below have been confirmed in active intrusions. Indicators are defanged to prevent accidental resolution. "
        "Firewall engineers and SOC analysts should refang and block immediately across boundary inspection systems.",
        body_style
    ))

    ioc_rows = [
        [Paragraph("Indicator Type", table_header), Paragraph("Observed Indicator (Defanged)", table_header), Paragraph("Role / Association", table_header), Paragraph("Severity", table_header)],
        [Paragraph("IPv4", table_cell), Paragraph("198[.]51[.]100[.]45", table_cell), Paragraph("C2 Operational Proxy Node (Volt Typhoon)", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("203[.]0[.]113[.]19", table_cell), Paragraph("Compromised SOHO Router Egress Node", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("192[.]0[.]2[.]88", table_cell), Paragraph("Staging & Exfiltration Relay", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("198[.]18[.]0[.]14", table_cell), Paragraph("Reverse Proxy Listener", table_cell), Paragraph("Medium", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("vpn-telemetry-sync[.]com", table_cell), Paragraph("Adversary C2 Callback Domain", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("cloud-gateway-update[.]net", table_cell), Paragraph("Dynamic DNS Resolver Host", table_cell), Paragraph("High", table_cell)],
        [Paragraph("URL", table_cell), Paragraph("hxxp://vpn-telemetry-sync[.]com/api/v1/health", table_cell), Paragraph("Heartbeat Beacon Endpoint", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", table_cell), Paragraph("Webshell / Dropper Utility", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", table_cell), Paragraph("Fast Reverse Proxy (FRP) binary", table_cell), Paragraph("High", table_cell)],
        [Paragraph("MD5", table_cell), Paragraph("d41d8cd98f00b204e9800998ecf8427e", table_cell), Paragraph("Staging payload hash", table_cell), Paragraph("Medium", table_cell)],
        [Paragraph("Registry Key", table_cell), Paragraph("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\VoltSvc", table_cell), Paragraph("Adversary Persistence Mechanism", table_cell), Paragraph("High", table_cell)],
        [Paragraph("CVE", table_cell), Paragraph("CVE-2023-46805", table_cell), Paragraph("Ivanti ICS Auth Bypass Zero-Day", table_cell), Paragraph("Critical", table_cell)],
        [Paragraph("CVE", table_cell), Paragraph("CVE-2024-21887", table_cell), Paragraph("Ivanti ICS Web Command Injection", table_cell), Paragraph("Critical", table_cell)],
    ]
    ioc_table = Table(ioc_rows, colWidths=[70, 180, 190, 60])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1e3a8a")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(ioc_table)

    doc.build(story, canvasmaker=NumberedCanvas)


def create_mandiant_report(output_path: str):
    """Creates multi-page Mandiant / Google Cloud report on APT29."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=60, bottomMargin=60
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('MandiantTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, leading=22, textColor=colors.HexColor("#831843"), spaceAfter=6)
    subtitle_style = ParagraphStyle('MandiantSub', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor("#475569"), spaceAfter=12)
    heading2_style = ParagraphStyle('MandiantH2', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=colors.HexColor("#9f1239"), spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle('MandiantBody', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor("#1e293b"), spaceAfter=8)
    table_cell = ParagraphStyle('TableCell', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=10, textColor=colors.HexColor("#0f172a"))
    table_header = ParagraphStyle('TableHeader', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white)

    story = []

    story.append(Paragraph("MANDIANT / GOOGLE CLOUD THREAT INTELLIGENCE", ParagraphStyle('MHead', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor("#be123c"))))
    story.append(Paragraph("Special Intelligence Report: APT29 Cloud Token Theft and Deep Persistence", title_style))
    story.append(Paragraph("Published: January 2024 | Author: Mandiant Advanced Practices | TLP:CLEAR", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#be123c"), spaceAfter=10))

    story.append(Paragraph("EXECUTIVE BRIEFING", heading2_style))
    story.append(Paragraph(
        "Mandiant has tracked unprecedented espionage campaigns orchestrated by <b>APT29</b> (also known as Midnight Blizzard, Cozy Bear, NOBELIUM), "
        "a premier cyber espionage group affiliated with the Russian Foreign Intelligence Service (SVR). "
        "Recent investigations uncover advanced techniques targeting Microsoft 365 and Entra ID cloud tenants. "
        "By compromising non-production legacy testing accounts lacking multi-factor authentication, the adversary granted illicit application permissions "
        "and minted custom OAuth bearer tokens to achieve persistent, silent access to diplomatic and defense communications.",
        body_style
    ))

    story.append(PageBreak())

    story.append(Paragraph("MALWARE IMPLANTS & PERSISTENCE MECHANISMS", heading2_style))
    story.append(Paragraph(
        "In hybrid cloud environments, APT29 deployed specialized backdoor utilities, notably MagicWeb and FoggyWeb, "
        "to subvert Active Directory Federation Services (AD FS) and forge authentication SAML tokens. "
        "On corporate Windows workstations, APT29 configured persistence via scheduled tasks and the following registry run keys:<br/>"
        "• <code>HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EdgeUpdater</code><br/>"
        "The actors also weaponized <b>CVE-2023-38831</b> (WinRAR code execution vulnerability) and <b>CVE-2024-21413</b> (Microsoft Outlook RCE) "
        "to deliver Cobalt Strike and custom loader payloads to foreign ministry personnel.",
        body_style
    ))

    story.append(Spacer(1, 10))
    story.append(Paragraph("INDICATORS OF COMPROMISE (IoCs)", heading2_style))

    ioc_rows = [
        [Paragraph("Type", table_header), Paragraph("Defanged Indicator", table_header), Paragraph("Description", table_header), Paragraph("Confidence", table_header)],
        [Paragraph("Domain", table_cell), Paragraph("auth-azure-sync[.]com", table_cell), Paragraph("Fake Entra ID Login / Token C2", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("login-microsoftonline-verify[.]net", table_cell), Paragraph("Credential Harvesting Endpoint", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("graph-api-telemetry[.]org", table_cell), Paragraph("Data Exfiltration Relay", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("185[.]220[.]101[.]5", table_cell), Paragraph("AD FS Token Extraction C2", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("45[.]154[.]255[.]89", table_cell), Paragraph("Cobalt Strike Team Server", table_cell), Paragraph("High", table_cell)],
        [Paragraph("URL", table_cell), Paragraph("hxxps://auth-azure-sync[.]com/oauth/token/v2", table_cell), Paragraph("Malicious Token Endpoint", table_cell), Paragraph("High", table_cell)],
        [Paragraph("URL", table_cell), Paragraph("hxxp://login-microsoftonline-verify[.]net/payload/loader.bin", table_cell), Paragraph("Stage-2 Dropper URL", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("a3c1031d77a83d47a4697ff3f81e3a2c416805bb2f61e8ec5d91361b78292851", table_cell), Paragraph("MagicWeb AD FS DLL Implant", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("d54f5905186ff946d8c8e88e895744883bb379b329ebc0e9565e381b16d96570", table_cell), Paragraph("FoggyWeb Loader Binary", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Registry", table_cell), Paragraph("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\EdgeUpdater", table_cell), Paragraph("Persistence Key for Stage 1", table_cell), Paragraph("High", table_cell)],
        [Paragraph("CVE", table_cell), Paragraph("CVE-2023-38831", table_cell), Paragraph("WinRAR Remote Code Execution", table_cell), Paragraph("Critical", table_cell)],
        [Paragraph("CVE", table_cell), Paragraph("CVE-2024-21413", table_cell), Paragraph("Microsoft Outlook NTLM Leak RCE", table_cell), Paragraph("Critical", table_cell)],
        [Paragraph("Email", table_cell), Paragraph("admin[@]embassy-support-desk[.]org", table_cell), Paragraph("Spear-phishing Lure Sender", table_cell), Paragraph("High", table_cell)],
    ]
    ioc_table = Table(ioc_rows, colWidths=[65, 185, 195, 55])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#9f1239")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(ioc_table)

    doc.build(story, canvasmaker=NumberedCanvas)


def create_crowdstrike_report(output_path: str):
    """Creates multi-page CrowdStrike report on Lazarus Group."""
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        leftMargin=54, rightMargin=54,
        topMargin=60, bottomMargin=60
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CSTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=18, leading=22, textColor=colors.HexColor("#b91c1c"), spaceAfter=6)
    subtitle_style = ParagraphStyle('CSSub', parent=styles['Normal'], fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor("#475569"), spaceAfter=12)
    heading2_style = ParagraphStyle('CSH2', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=12, leading=16, textColor=colors.HexColor("#991b1b"), spaceBefore=10, spaceAfter=4)
    body_style = ParagraphStyle('CSBody', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor("#1e293b"), spaceAfter=8)
    table_cell = ParagraphStyle('TableCell', parent=styles['Normal'], fontName='Helvetica', fontSize=8, leading=10, textColor=colors.HexColor("#0f172a"))
    table_header = ParagraphStyle('TableHeader', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.white)

    story = []

    story.append(Paragraph("CROWDSTRIKE FALCON OVERWATCH THREAT INTELLIGENCE", ParagraphStyle('CSHead', fontName='Helvetica-Bold', fontSize=10, textColor=colors.HexColor("#dc2626"))))
    story.append(Paragraph("Lazarus Group (Zinc): Cross-Platform Crypto-Heist Malware and Ransomware Fusion", title_style))
    story.append(Paragraph("Adversary Dossier: LABYRINTH CHOLLIMA | DPRK Reconnaissance General Bureau | TLP:CLEAR", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#dc2626"), spaceAfter=10))

    story.append(Paragraph("OVERVIEW & CAMPAIGN ANALYSIS", heading2_style))
    story.append(Paragraph(
        "CrowdStrike Falcon OverWatch has uncovered a sophisticated cyber campaign operated by <b>Lazarus Group</b> "
        "(also tracked by CrowdStrike as LABYRINTH CHOLLIMA, Zinc, and HIDDEN COBRA), an elite nation-state cyber unit operating on behalf of the Democratic People's Republic of Korea (DPRK). "
        "The operation blends financial theft targeting decentralized finance (DeFi) protocols with corporate ransomware extortion. "
        "Targeting is conducted via weaponized PDF job lure documents (MITRE Technique T1566.001) distributed to engineers on LinkedIn, deploying Rust-based implants (RustBucket) and KandyKorn backdoors.",
        body_style
    ))

    story.append(PageBreak())

    story.append(Paragraph("HOST PERSISTENCE & TECHNICAL INDICATORS", heading2_style))
    story.append(Paragraph(
        "Upon successful execution, the loader registers persistence on Windows hosts by creating an autorun policy under:<br/>"
        "• <code>HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\LzStartup</code><br/>"
        "The malware family connects to command and control nodes operating over HTTPS, staging memory-only Cobalt Strike beacons and Mimikatz credential-harvesting tools (T1003). "
        "Defenders are advised to enforce immediate ingress and egress filtering on the IP addresses and domains enumerated below.",
        body_style
    ))

    story.append(Spacer(1, 10))
    story.append(Paragraph("INDICATORS OF COMPROMISE (IoCs)", heading2_style))

    ioc_rows = [
        [Paragraph("Type", table_header), Paragraph("Observed Indicator", table_header), Paragraph("Association / Role", table_header), Paragraph("Confidence", table_header)],
        [Paragraph("IPv4", table_cell), Paragraph("45[.]142[.]214[.]9", table_cell), Paragraph("Lazarus C2 Primary Node", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("185[.]220[.]101[.]55", table_cell), Paragraph("Crypto Wallet Drainer Proxy", table_cell), Paragraph("High", table_cell)],
        [Paragraph("IPv4", table_cell), Paragraph("91[.]215[.]85[.]17", table_cell), Paragraph("Staging Server for RustBucket", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("cryptotrade-validator[.]xyz", table_cell), Paragraph("Phishing & Exploit Landing Page", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("blockchain-node-sync[.]io", table_cell), Paragraph("C2 Command Dispatch Domain", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Domain", table_cell), Paragraph("binance-airdrop-claim[.]net", table_cell), Paragraph("Credential Harvest Lure", table_cell), Paragraph("High", table_cell)],
        [Paragraph("URL", table_cell), Paragraph("hxxps://cryptotrade-validator[.]xyz/connect/wallet.php", table_cell), Paragraph("Malicious Wallet Drainer URI", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("8f4e2b027d928373b5a761e05d0452f360980590fa143c7b328a6d4e4e93f663", table_cell), Paragraph("RustBucket macOS/Win Loader", table_cell), Paragraph("High", table_cell)],
        [Paragraph("SHA-256", table_cell), Paragraph("f1d2d2f924e986ac86fdf7b36c94bcdf32beec15defc16260b30d47710273b56", table_cell), Paragraph("KandyKorn Memory Implant", table_cell), Paragraph("High", table_cell)],
        [Paragraph("MD5", table_cell), Paragraph("5d41402abc4b2a76b9719d911017c592", table_cell), Paragraph("Stage 1 Encrypted Payload", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Registry", table_cell), Paragraph("HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\LzStartup", table_cell), Paragraph("Persistence Autorun Key", table_cell), Paragraph("High", table_cell)],
        [Paragraph("Email", table_cell), Paragraph("recruiter[@]crypto-careers-global[.]com", table_cell), Paragraph("Spear-phishing Social Engineering", table_cell), Paragraph("High", table_cell)],
    ]
    ioc_table = Table(ioc_rows, colWidths=[65, 185, 195, 55])
    ioc_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#991b1b")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(ioc_table)

    doc.build(story, canvasmaker=NumberedCanvas)


def generate_all_samples(target_dir: str):
    """Generates all 3 sample reports inside the target directory."""
    os.makedirs(target_dir, exist_ok=True)

    r1 = os.path.join(target_dir, "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf")
    r2 = os.path.join(target_dir, "Mandiant_APT29_Cloud_Token_Theft_and_Persistence.pdf")
    r3 = os.path.join(target_dir, "CrowdStrike_Lazarus_Crypto_Heist_Ransomware.pdf")

    print(f"Generating CISA Report -> {r1}")
    create_cisa_report(r1)

    print(f"Generating Mandiant Report -> {r2}")
    create_mandiant_report(r2)

    print(f"Generating CrowdStrike Report -> {r3}")
    create_crowdstrike_report(r3)

    print("All sample threat intelligence PDF reports successfully generated.")


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    reports_dir = os.path.join(current_dir, "reports")
    generate_all_samples(reports_dir)
