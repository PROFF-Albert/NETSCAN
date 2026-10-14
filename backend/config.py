from pathlib import Path
import os
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATABASE_URL = os.getenv("NETWATCH_DATABASE_URL", "sqlite:///database/netwatch.db")
HOST = os.getenv("NETWATCH_HOST", "127.0.0.1")
PORT = int(os.getenv("NETWATCH_PORT", "8000"))
LOG_LEVEL = os.getenv("NETWATCH_LOG_LEVEL", "INFO").upper()
RATE_LIMIT_PER_MINUTE = int(os.getenv("NETWATCH_RATE_LIMIT_PER_MINUTE", "60"))
REPORTS_DIR = ROOT / "reports"
SCANS_DIR = ROOT / "scans"
# Optional: NVD accepts unauthenticated requests at a lower rate.  This value is
# deliberately read only from the environment and is never returned by the API.
NVD_API_KEY = os.getenv("NETSCAN_NVD_API_KEY", "").strip() or None
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_TIMEOUT_SECONDS = float(os.getenv("NETSCAN_NVD_TIMEOUT_SECONDS", "8"))
MAX_SCAN_CONCURRENCY = int(os.getenv("NETSCAN_MAX_SCAN_CONCURRENCY", "128"))
