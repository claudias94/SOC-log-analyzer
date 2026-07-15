# SOC Log Analyzer

![Python](https://img.shields.io/badge/Python-3.10+-blue.svg)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

A Python-based Security Operations Center (SOC) log analysis tool that automates the detection of suspicious authentication events, brute-force attacks, and indicators of compromise (IOCs) from Linux system logs.

This project demonstrates practical SOC analyst skills including log parsing, threat detection, reporting, automation, and cybersecurity-focused software development.

---

# Features

- Parse Linux authentication logs
- Detect brute-force attacks
- Identify repeated failed logins
- Detect suspicious usernames
- Extract attacker IP addresses
- Assign threat severity
- Export findings to HTML
- Export findings to JSON
- Export findings to CSV
- MITRE ATT&CK Mapping
- Colored terminal output
- Progress bars
- Logging support

---

# Technologies

- Python
- Regular Expressions
- JSON
- CSV
- HTML
- Logging
- Rich
- tqdm
- Docker
- GitHub Actions

---

# Project Structure

```text
SOC-log-analyzer/
│
├── analyzer.py
├── parser.py
├── detector.py
├── exporter.py
├── report.py
├── mitre.py
├── config.py
├── logger.py
├── utils.py
│
├── sample_logs/
├── reports/
├── tests/
├── screenshots/
├── docs/
│
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/claudias94/SOC-log-analyzer.git
```

Move into the project directory

```bash
cd SOC-log-analyzer
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

Basic analysis

```bash
python analyzer.py sample_logs/auth.log
```

Generate HTML report

```bash
python analyzer.py sample_logs/auth.log --html
```

Export JSON

```bash
python analyzer.py sample_logs/auth.log --json
```

Export CSV

```bash
python analyzer.py sample_logs/auth.log --csv
```

Generate all reports

```bash
python analyzer.py sample_logs/auth.log --html --json --csv
```

---

# Example Output

```text
=================================================

SOC LOG ANALYZER REPORT

=================================================

Failed Login Attempts : 34

Successful Logins     : 8

Unique IP Addresses   : 6

Brute Force Alerts    : 2

Threat Severity       : HIGH

MITRE Technique       : T1110

=================================================
```

---

# MITRE ATT&CK Mapping

| Detection | Technique |
|-----------|-----------|
| Brute Force | T1110 |
| Valid Accounts | T1078 |
| Remote Services | T1021 |
| Account Discovery | T1087 |

---

# Roadmap

- Live Log Monitoring
- Flask Dashboard
- SQLite Database
- Email Alerts
- Slack Alerts
- VirusTotal Integration
- AbuseIPDB Integration
- GeoIP Lookup
- Sigma Rules
- YARA Rules
- Docker Support
- REST API

---

# Skills Demonstrated

- Python Programming
- Cybersecurity
- Linux
- Threat Detection
- Log Parsing
- Secure Coding
- Automation
- Regular Expressions
- MITRE ATT&CK
- Incident Response

---

# Screenshots

## Terminal

*(Add screenshot here)*

## HTML Report

*(Add screenshot here)*

## Dashboard

*(Coming Soon)*

---

# Author

## Claudias Musavini

Bachelor of Science in Computer Security & Forensics

GitHub

https://github.com/claudias94

---

# License

MIT License
