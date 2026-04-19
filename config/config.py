"""Central configuration constants for Aegis-SOC."""
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

LOW = "LOW"
MEDIUM = "MEDIUM"
HIGH = "HIGH"
CRITICAL = "CRITICAL"

ABUSEIPDB_MIN_CONFIDENCE_SCORE = 20
FAILED_LOGIN_HIGH_SEVERITY_THRESHOLD = 10

REPORTS_OUTPUT_FOLDER = "reports"
