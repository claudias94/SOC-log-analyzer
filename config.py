"""
config.py

Central configuration file for the SOC Log Analyzer.
"""

from pathlib import Path

# ============================
# Project Directories
# ============================

BASE_DIR = Path(__file__).resolve().parent

LOG_DIR = BASE_DIR / "logs"

REPORT_DIR = BASE_DIR / "reports"

TEMPLATE_DIR = BASE_DIR / "templates"

SCREENSHOT_DIR = BASE_DIR / "screenshots"

DOCS_DIR = BASE_DIR / "docs"

TEST_DIR = BASE_DIR / "tests"

# Create directories automatically if they don't exist

for directory in [
    LOG_DIR,
    REPORT_DIR,
    TEMPLATE_DIR,
    SCREENSHOT_DIR,
    DOCS_DIR,
    TEST_DIR
]:
    directory.mkdir(exist_ok=True)

# ============================
# Detection Thresholds
# ============================

FAILED_LOGIN_THRESHOLD = 5

HIGH_SEVERITY_THRESHOLD = 10

CRITICAL_SEVERITY_THRESHOLD = 20

# ============================
# Report Files
# ============================

HTML_REPORT = REPORT_DIR / "report.html"

JSON_REPORT = REPORT_DIR / "alerts.json"

CSV_REPORT = REPORT_DIR / "alerts.csv"

# ============================
# Logging
# ============================

LOG_FILE = REPORT_DIR / "soc_analyzer.log"

LOG_LEVEL = "INFO"

# ============================
# Application Information
# ============================

APP_NAME = "SOC Log Analyzer"

APP_VERSION = "2.1"

AUTHOR = "Claudias Musavini"
