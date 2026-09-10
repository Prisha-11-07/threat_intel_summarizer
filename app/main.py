"""
FastAPI Threat Intelligence Ingestion, Summarization & IoC Extraction Service.
Exposes REST endpoints for PDF report processing, STIX 2.1 generation,
and firewall ingestion export.
"""

import os
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, File, UploadFile, HTTPException, Query, Body
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from core.pdf_parser import ThreatReportParser
from core.extractor import IoCExtractor
from core.analyzer import ThreatAnalyzer
from exporters.stix_generator import STIX21Generator
from exporters.firewall_rules import FirewallRuleGenerator

app = FastAPI(
    title="CyberSentinel - Automated Threat Intelligence Engine",
    description="Parses unstructured multi-page threat intelligence PDFs, maps attack methodologies, extracts structured IoCs, and exports STIX 2.1 & firewall ingestion rules.",
    version="2.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Base directories
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(BASE_DIR, "static")
SAMPLES_DIR = os.path.join(BASE_DIR, "samples", "reports")

# Initialize core services
pdf_parser = ThreatReportParser()
ioc_extractor = IoCExtractor()
threat_analyzer = ThreatAnalyzer()
stix_generator = STIX21Generator()
firewall_generator = FirewallRuleGenerator()

# Mount static files
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


def process_report_pipeline(doc_data: Dict[str, Any]) -> Dict[str, Any]:
    """Runs complete end-to-end extraction, analysis, STIX, and firewall generation."""
    # 1. Extract IoCs page by page with provenance
    all_iocs = []
    for page in doc_data["pages"]:
        page_iocs = ioc_extractor.extract_from_text(page["text"], page_num=page["page_number"])
        all_iocs.extend(page_iocs)

    # 2. Canonical deduplication merges occurrences and page provenance.
    unique_iocs = ioc_extractor.deduplicate_iocs(all_iocs)

    # 3. Analyze attack methodology & MITRE mapping
    analysis = threat_analyzer.analyze(doc_data, unique_iocs)

    # 4. Generate STIX 2.1 OASIS bundle
    stix_bundle = stix_generator.build_bundle(analysis, unique_iocs)

    # 5. Generate firewall & IDS/EDR ingestion configurations
    actor_name = analysis.get("threat_actor", {}).get("name", "Adversary")
    firewall_configs = firewall_generator.generate_all(unique_iocs, actor_name)

    # Count IoC breakdown
    ioc_breakdown = {}
    for ioc in unique_iocs:
        ioc_breakdown[ioc["type"]] = ioc_breakdown.get(ioc["type"], 0) + 1

    return {
        "status": "success",
        "metadata": doc_data["metadata"],
        "vendor": doc_data["vendor"],
        "tlp": doc_data["tlp"],
        "total_pages": doc_data["total_pages"],
        "analysis": analysis,
        "iocs": unique_iocs,
        "ioc_breakdown": ioc_breakdown,
        "stix_bundle": stix_bundle,
        "stix_validation": stix_generator.validate_bundle(stix_bundle),
        "firewall_rules": firewall_configs
    }


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serves the interactive SOC analyst web application."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>CyberSentinel Threat Intelligence Engine is running. Static UI loading...</h1>")


@app.get("/api/sample-reports")
async def list_sample_reports():
    """Returns available realistic multi-page cybersecurity vendor sample reports."""
    samples = [
        {
            "id": "cisa-volt-typhoon",
            "title": "CISA AA24-105A: Volt Typhoon Target Critical Infrastructure",
            "vendor": "Cybersecurity & Infrastructure Security Agency (CISA)",
            "threat_actor": "Volt Typhoon (PRC)",
            "filename": "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf",
            "description": "Living-off-the-land techniques, compromised edge devices (CVE-2023-46805), C2 SOHO routers, and registry persistence."
        },
        {
            "id": "mandiant-apt29",
            "title": "Mandiant: APT29 Cloud Token Theft & Deep Persistence",
            "vendor": "Mandiant / Google Cloud Threat Intelligence",
            "threat_actor": "APT29 / Midnight Blizzard (SVR)",
            "filename": "Mandiant_APT29_Cloud_Token_Theft_and_Persistence.pdf",
            "description": "Microsoft 365 OAuth token compromise, MagicWeb/FoggyWeb backdoors, malicious domains, and diplomatic targeting."
        },
        {
            "id": "crowdstrike-lazarus",
            "title": "CrowdStrike: Lazarus Cross-Platform Crypto-Heist & Ransomware",
            "vendor": "CrowdStrike Falcon OverWatch Intelligence",
            "threat_actor": "Lazarus Group (DPRK)",
            "filename": "CrowdStrike_Lazarus_Crypto_Heist_Ransomware.pdf",
            "description": "DeFi cryptocurrency theft, weaponized PDF job lures, RustBucket macOS/Windows implants, and wallet drainer C2s."
        }
    ]
    return JSONResponse(content={"samples": samples})


@app.post("/api/analyze-sample/{sample_id}")
async def analyze_sample(sample_id: str):
    """Processes one of the preloaded vendor sample reports."""
    mapping = {
        "cisa-volt-typhoon": "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf",
        "mandiant-apt29": "Mandiant_APT29_Cloud_Token_Theft_and_Persistence.pdf",
        "crowdstrike-lazarus": "CrowdStrike_Lazarus_Crypto_Heist_Ransomware.pdf"
    }

    filename = mapping.get(sample_id)
    if not filename:
        raise HTTPException(status_code=404, detail="Sample report not found")

    file_path = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(file_path):
        # Auto-generate if missing
        from samples.generate_samples import generate_all_samples
        generate_all_samples(SAMPLES_DIR)

    if not os.path.exists(file_path):
        raise HTTPException(status_code=500, detail=f"Sample report file could not be generated at {file_path}")

    doc_data = pdf_parser.parse_pdf(file_path)
    result = process_report_pipeline(doc_data)
    result["filename"] = filename
    return JSONResponse(content=result)


@app.post("/api/analyze-pdf")
async def analyze_pdf_upload(file: UploadFile = File(...)):
    """Uploads and analyzes an arbitrary multi-page threat intelligence PDF report."""
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF document files are accepted.")

    content = await file.read()
    if len(content) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        doc_data = pdf_parser.parse_pdf(content)
        result = process_report_pipeline(doc_data)
        result["filename"] = file.filename
        return JSONResponse(content=result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to parse PDF document: {str(e)}")


@app.post("/api/export-stix")
async def export_stix_bundle(payload: Dict[str, Any] = Body(...)):
    """Exports and formats STIX 2.1 bundle for direct download."""
    stix_bundle = payload.get("stix_bundle")
    if not stix_bundle:
        raise HTTPException(status_code=400, detail="Missing stix_bundle payload.")

    validation = stix_generator.validate_bundle(stix_bundle)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail={"message": "STIX bundle failed validation.", "errors": validation["errors"]})

    return JSONResponse(
        content=stix_bundle,
        headers={"Content-Disposition": 'attachment; filename="threat_intel_stix2.1.json"'}
    )


# ----------------------------------------------------------------------
# OASIS TAXII 2.1 Standard Server Endpoints
# Enables firewalls, SIEMs (Sentinel/Elastic), and TIPs (OpenCTI/MISP)
# to poll and subscribe to STIX 2.1 feeds.
# ----------------------------------------------------------------------

# In-memory storage for active TAXII collection feed
active_taxii_feed: Dict[str, Any] = {}

def get_or_create_default_taxii_bundle() -> Dict[str, Any]:
    """Ensures a baseline STIX 2.1 bundle exists in the TAXII feed."""
    global active_taxii_feed
    if not active_taxii_feed:
        cisa_path = os.path.join(SAMPLES_DIR, "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf")
        if os.path.exists(cisa_path):
            doc_data = pdf_parser.parse_pdf(cisa_path)
            res = process_report_pipeline(doc_data)
            active_taxii_feed = res["stix_bundle"]
    return active_taxii_feed or {"type": "bundle", "id": "bundle--empty", "objects": []}


@app.get("/taxii2/", response_class=JSONResponse)
async def taxii_server_discovery():
    """TAXII 2.1 Server Discovery Endpoint."""
    return JSONResponse(
        content={
            "title": "CyberSentinel TAXII 2.1 Server",
            "description": "Standardized STIX 2.1 Threat Feed for Automated Firewall & SIEM Ingestion",
            "contact": "soc-intel@enterprise-defense.local",
            "default": "/taxii2/api1/",
            "api_roots": ["/taxii2/api1/"]
        },
        headers={"Content-Type": "application/taxii+json;version=2.1"}
    )


@app.get("/taxii2/api1/", response_class=JSONResponse)
async def taxii_api_root():
    """TAXII 2.1 API Root Information Endpoint."""
    return JSONResponse(
        content={
            "title": "SOC Threat Intelligence Feed API Root",
            "description": "Perimeter firewall and SOAR automated defense ingestion feed",
            "versions": ["application/taxii+json;version=2.1"],
            "max_content_length": 10485760
        },
        headers={"Content-Type": "application/taxii+json;version=2.1"}
    )


@app.get("/taxii2/api1/collections/", response_class=JSONResponse)
async def taxii_list_collections():
    """Lists available TAXII 2.1 intelligence collections."""
    return JSONResponse(
        content={
            "collections": [
                {
                    "id": "soc-firewall-feed",
                    "title": "Automated Firewall & Edge Defense Feed",
                    "description": "Validated IoCs and STIX 2.1 indicators ready for firewall and EDR automated ingestion",
                    "can_read": true,
                    "can_write": true,
                    "media_types": ["application/stix+json;version=2.1"]
                }
            ]
        },
        headers={"Content-Type": "application/taxii+json;version=2.1"}
    )


@app.get("/taxii2/api1/collections/{collection_id}/objects/", response_class=JSONResponse)
async def taxii_get_collection_objects(collection_id: str):
    """
    TAXII 2.1 Get Objects Endpoint.
    Returns the STIX 2.1 JSON bundle for the collection.
    Firewalls and SIEMs query this URL to synchronize blocklists.
    """
    bundle = get_or_create_default_taxii_bundle()
    return JSONResponse(
        content=bundle,
        headers={"Content-Type": "application/taxii+json;version=2.1"}
    )


@app.post("/taxii2/api1/collections/{collection_id}/objects/", response_class=JSONResponse)
async def taxii_post_collection_objects(collection_id: str, payload: Dict[str, Any] = Body(...)):
    """
    TAXII 2.1 Ingest Objects Endpoint.
    Accepts new STIX 2.1 bundles to add to the firewall ingestion feed.
    """
    global active_taxii_feed
    active_taxii_feed = payload
    return JSONResponse(
        content={
            "status": "success",
            "message": f"Successfully published STIX 2.1 bundle with {len(payload.get('objects', []))} objects to {collection_id}."
        },
        headers={"Content-Type": "application/taxii+json;version=2.1"}
    )


@app.get("/api/health")
async def health_check():
    """Healthcheck endpoint."""
    return {"status": "healthy", "service": "CyberSentinel Threat Intelligence Engine", "stix_version": "2.1", "taxii_version": "2.1"}
