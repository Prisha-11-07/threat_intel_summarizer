"""
CyberSentinel Application Launcher.
Ensures sample reports are generated and starts the FastAPI/Uvicorn server.
"""

import os
import sys
import uvicorn

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(BASE_DIR)
if PARENT_DIR not in sys.path:
    sys.path.insert(0, PARENT_DIR)

from threat_intel_summarizer.samples.generate_samples import generate_all_samples


def main():
    print("=" * 70)
    print(" CYBERSENTINEL // Threat Intelligence Ingestion & Defense Engine")
    print("=" * 70)

    # Verify or generate sample reports
    reports_dir = os.path.join(BASE_DIR, "samples", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    cisa_sample = os.path.join(reports_dir, "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf")

    if not os.path.exists(cisa_sample):
        print("[*] Generating multi-page sample threat intelligence vendor PDFs...")
        generate_all_samples(reports_dir)
        print("[✓] Sample advisories created.")
    else:
        print("[✓] Sample threat reports verified in", reports_dir)

    print("\n[+] Starting CyberSentinel Web Service & REST API...")
    print("    • Web Dashboard:     http://127.0.0.1:8000")
    print("    • Swagger REST API:  http://127.0.0.1:8000/docs")
    print("    • STIX 2.1 Engine:   Active")
    print("    • Press Ctrl+C to terminate the server.\n")

    uvicorn.run(
        "threat_intel_summarizer.app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()
