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
