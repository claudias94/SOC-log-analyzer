# SOC Log Analyzer

A Python-based Security Operations Center (SOC) log analysis tool that detects suspicious activity from system and authentication logs. The project automates the identification of common security events, helping analysts quickly identify potential threats without manually reviewing thousands of log entries.

---

## Features

- Analyze Linux authentication logs
- Detect multiple failed login attempts
- Identify brute-force attack patterns
- Extract source IP addresses
- Generate security alerts
- Produce human-readable reports
- Simple command-line interface

---

## Technologies

- Python 3
- Regular Expressions
- File Handling
- Logging
- JSON
- Git
- Linux

---

## Project Structure

```
SOC-log-analyzer/
│
├── analyzer.py
├── sample_logs/
├── reports/
├── requirements.txt
├── README.md
└── screenshots/
```

---

## Installation

Clone the repository

```bash
git clone https://github.com/claudias94/SOC-log-analyzer.git
cd SOC-log-analyzer
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

Analyze a log file

```bash
python analyzer.py sample_logs/auth.log
```

Example Output

```
=================================
SOC LOG ANALYSIS REPORT
=================================

Failed Login Attempts: 37

Brute Force Alert:
IP Address: 192.168.1.10
Attempts: 14

Suspicious Users
----------------
root
admin
ubuntu

Report saved successfully.
```

---

## Detection Capabilities

- Failed SSH logins
- Brute-force attacks
- Suspicious authentication attempts
- Repeated login failures
- Basic IOC extraction

---

## Future Improvements

- MITRE ATT&CK Mapping
- Sigma Rule Support
- YARA Integration
- Threat Intelligence API
- Splunk Export
- ELK Stack Integration
- Web Dashboard
- Email Alerts
- Machine Learning Anomaly Detection

---

## Skills Demonstrated

- Python Programming
- Cybersecurity
- SOC Operations
- Log Analysis
- Threat Detection
- Linux
- Regular Expressions
- Secure Coding
- Automation

---

## Author

**Claudias Musavini**

Computer Security & Forensics Graduate

GitHub: https://github.com/claudias94
LinkedIn:www.linkedin.com/in/claudias-musavini-3b0918116
