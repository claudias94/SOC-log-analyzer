"""
config.py

Central configuration file for the Claus SOC Toolkit.

This module stores all configurable values used throughout the
SOC Log Analyzer, including project paths, detection thresholds,
logging options, report locations, and application metadata.
"""

from pathlib import Path

# ==========================================================
# Project Information
# ==========================================================

APP_NAME = "SOC Log Analyzer"
APP_VERSION = "3.0"
AUTHOR = "Claudias Musavini"

# ==========================================================
# Project Directories
# ==========================================================

BASE_DIR = Path(__file__).resolve().parent

LOG_DIR = BASE_DIR / "logs"
REPORT_DIR = BASE_DIR / "reports"
TEMPLATE_DIR = BASE_DIR / "templates"
SCREENSHOT_DIR = BASE_DIR / "screenshots"
DOCS_DIR = BASE_DIR / "docs"
TEST_DIR = BASE_DIR / "tests"

# Automatically create project directories
for directory in (
    LOG_DIR,
    REPORT_DIR,
    TEMPLATE_DIR,
    SCREENSHOT_DIR,
    DOCS_DIR,
    TEST_DIR,
):
    directory.mkdir(exist_ok=True)

# ==========================================================
# Default Files
# ==========================================================

AUTH_LOG = LOG_DIR / "auth.log"

HTML_REPORT = REPORT_DIR / "report.html"
JSON_REPORT = REPORT_DIR / "report.json"
CSV_REPORT = REPORT_DIR / "report.csv"

LOG_FILE = REPORT_DIR / "soc_analyzer.log"

# ==========================================================
# Logging
# ==========================================================

LOG_LEVEL = "INFO"

# ==========================================================
# Detection Thresholds
# ==========================================================

# Failed logins from one IP before brute-force is suspected
FAILED_LOGIN_THRESHOLD = 5

# Number of different usernames tried from one IP
PASSWORD_SPRAY_THRESHOLD = 5

# Invalid usernames attempted from one IP
INVALID_USER_THRESHOLD = 3

# Number of different IPs attacking the same account
DISTRIBUTED_ATTACK_THRESHOLD = 3

# Failed attempts before a later successful login is suspicious
SUSPICIOUS_LOGIN_THRESHOLD = 3

# ==========================================================
# Severity Thresholds
# ==========================================================

HIGH_SEVERITY_THRESHOLD = 10
CRITICAL_SEVERITY_THRESHOLD = 20

# ==========================================================
# Risk Score Weights
# ==========================================================

FAILED_LOGIN_WEIGHT = 2
INVALID_USER_WEIGHT = 5
BRUTE_FORCE_WEIGHT = 25
PASSWORD_SPRAY_WEIGHT = 20
DISTRIBUTED_ATTACK_WEIGHT = 20
SUSPICIOUS_LOGIN_WEIGHT = 30

MAX_RISK_SCORE = 100

# ==========================================================
# Threat Levels
# ==========================================================

LOW_RISK_MAX = 20
MEDIUM_RISK_MAX = 40
HIGH_RISK_MAX = 70

# ==========================================================
# MITRE ATT&CK Techniques
# ==========================================================

MITRE_BRUTE_FORCE = "T1110.001"
MITRE_PASSWORD_SPRAY = "T1110.003"
MITRE_VALID_ACCOUNTS = "T1078"
MITRE_ACCOUNT_DISCOVERY = "T1087"

# ==========================================================
# Supported Event Types
# ==========================================================

FAILED_LOGIN = "FAILED_LOGIN"
SUCCESSFUL_LOGIN = "SUCCESSFUL_LOGIN"
INVALID_USER = "INVALID_USER"
