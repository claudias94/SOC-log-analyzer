# AI Log Analyzer - SOC with MITRE ATT&CK Mapping
# Project: Claus Project 2026

import re
from collections import Counter
from datetime import datetime

LOG_FILE = "logs/auth.log"
REPORT_FILE = "reports/soc_incident_report.txt"

ip_pattern = r"(\d+\.\d+\.\d+\.\d+)"

failed_logs = []
failed_ips = []
root_sessions = 0

with open(LOG_FILE, "r") as f:
    for line in f:
        if "Failed password" in line:
            failed_logs.append(line.strip())
            match = re.search(ip_pattern, line)
            if match:
                failed_ips.append(match.group(1))
        elif "session opened for user root" in line:
            root_sessions += 1

ip_counter = Counter(failed_ips)

# ================= SOC ANALYSIS =================

incident_detected = len(failed_logs) > 0
incident_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

if not incident_detected:
    severity = "NONE"
    attack_type = "No malicious activity detected"
    mitre_attack = "N/A"
else:
    max_attempts = max(ip_counter.values())
    if max_attempts >= 10:
        severity = "HIGH"
    elif max_attempts >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    attack_type = "SSH Brute Force Attack (Credential Access)"
    mitre_attack = "T1110 - Brute Force"

# ================= OUTPUT TO TERMINAL =================

print("\n=== SOC AUTH LOG SUMMARY ===")
print(f"Root sessions detected      : {root_sessions}")
print(f"Total failed login attempts : {len(failed_logs)}")

if incident_detected:
    print(f"STATUS: ⚠️ {attack_type}")
else:
    print("STATUS: ✅ No brute-force activity detected.")

print("\n=== ATTACKER IP ANALYSIS ===")
for ip, count in ip_counter.items():
    print(f"IP: {ip} | Attempts: {count}")

print("\n=== MITRE ATT&CK MAPPING ===")
print(f"Attack Type: {attack_type}")
print(f"MITRE ATT&CK Technique: {mitre_attack}")

# ================= REPORT GENERATION =================

with open(REPORT_FILE, "w") as report:
    report.write("=== SECURITY OPERATIONS CENTER (SOC) INCIDENT REPORT ===\n\n")
    report.write(f"Incident ID        : SOC-{datetime.now().strftime('%Y%m%d%H%M%S')}\n")
    report.write(f"Detection Time     : {incident_time}\n")
    report.write(f"Attack Type        : {attack_type}\n")
    report.write(f"MITRE ATT&CK       : {mitre_attack}\n")
    report.write(f"Affected System    : Linux Authentication Service (SSHD)\n")
    report.write(f"Severity Level     : {severity}\n\n")

    if incident_detected:
        report.write("Attacker IP Summary:\n")
        for ip, count in ip_counter.items():
            report.write(f" - {ip} : {count} failed attempts\n")

        report.write("\nEvidence (Sample Logs):\n")
        for log in failed_logs[:5]:
            report.write(log + "\n")

        report.write("\nAnalyst Assessment:\n")
        report.write(
            "Multiple failed authentication attempts from the same IP address indicate a potential SSH brute-force attack.\n"
            "This aligns with MITRE ATT&CK technique T1110 (Brute Force), which involves repeated attempts to gain access by guessing credentials.\n"
        )

        report.write("\nRecommended Actions:\n")
        report.write(
            "- Block attacker IPs at the firewall\n"
            "- Enforce strong password policies and key-based authentication\n"
            "- Deploy intrusion prevention tools like Fail2Ban\n"
            "- Continue monitoring authentication logs for suspicious activity\n"
        )
    else:
        report.write("No malicious authentication activity detected during analysis.\n")

print(f"\n📄 SOC Incident Report saved to: {REPORT_FILE}")


