"""
CyberSentinel — Application Entry Point.

Generates the bundled sample threat intelligence reports if they are absent,
then launches the FastAPI/Uvicorn web server on localhost:8000.

Run with:
    python run.py
"""

import os
import sys
import uvicorn

# Add the project root to sys.path so all package imports resolve correctly
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from samples.generate_samples import generate_all_samples  # noqa: E402


def main():
    print("=" * 70)
    print(" CYBERSENTINEL // Threat Intelligence Ingestion & Defense Engine")
    print("=" * 70)

    # Verify or generate the bundled sample reports on first run
    reports_dir = os.path.join(BASE_DIR, "samples", "reports")
    os.makedirs(reports_dir, exist_ok=True)
    cisa_sample = os.path.join(reports_dir, "CISA_AA24-105A_Volt_Typhoon_Critical_Infrastructure.pdf")

    if not os.path.exists(cisa_sample):
        print("[*] Generating bundled sample threat intelligence vendor PDFs...")
        generate_all_samples(reports_dir)
        print("[✓] Sample advisories created successfully.")
    else:
        print("[✓] Sample threat reports found at:", reports_dir)

    print("\n[+] Starting CyberSentinel Web Service & REST API...")
    print("    •  Web Dashboard:        http://127.0.0.1:8000")
    print("    •  Swagger REST API:     http://127.0.0.1:8000/docs")
    print("    •  TAXII 2.1 Feed:       http://127.0.0.1:8000/taxii2/")
    print("    •  STIX 2.1 Engine:      Active")
    print("    •  Press Ctrl+C to terminate the server.\n")

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="info"
    )


if __name__ == "__main__":
    main()
