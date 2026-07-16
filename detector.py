"""
detector.py

Detection engine for the SOC Log Analyzer.
"""

from collections import Counter

from logger import logger
from config import (
    FAILED_LOGIN_THRESHOLD,
    HIGH_SEVERITY_THRESHOLD,
    CRITICAL_SEVERITY_THRESHOLD,
)


class DetectionEngine:
    """
    Detection engine for authentication events.
    """

    def __init__(self, events):
        self.events = events

    def analyze(self):
        failed = []
        successful = []
        invalid_users = []

        # Separate authentication events
        for event in self.events:

            if event["type"] == "FAILED_LOGIN":
                failed.append(event)

            elif event["type"] == "SUCCESSFUL_LOGIN":
                successful.append(event)

            elif event["type"] == "INVALID_USER":
                invalid_users.append(event)

        # Count failed logins by IP
        ip_counter = Counter(event["ip"] for event in failed)

        brute_force = []

        for ip, attempts in ip_counter.items():

            if attempts >= FAILED_LOGIN_THRESHOLD:

                brute_force.append(
                    {
                        "ip": ip,
                        "attempts": attempts,
                        "severity": self.get_severity(attempts),
                        "mitre": "T1110",
                    }
                )

        # Determine overall threat level
        threat_level = "LOW"

        if brute_force:

            highest = max(alert["attempts"] for alert in brute_force)

            if highest >= CRITICAL_SEVERITY_THRESHOLD:
                threat_level = "CRITICAL"

            elif highest >= HIGH_SEVERITY_THRESHOLD:
                threat_level = "HIGH"

            else:
                threat_level = "MEDIUM"

        # Increase threat level if invalid users were targeted
        if invalid_users and threat_level == "LOW":
            threat_level = "MEDIUM"

        # Identify top attacking IP
        top_attacker = None
        top_attempts = 0

        if ip_counter:
            top_attacker, top_attempts = ip_counter.most_common(1)[0]

        summary = {
            "failed_logins": len(failed),
            "invalid_user_attempts": len(invalid_users),
            "successful_logins": len(successful),
            "unique_ips": len(ip_counter),
            "threat_level": threat_level,
            "top_attacker": top_attacker,
            "top_attempts": top_attempts,
            "brute_force_alerts": brute_force,
        }

        logger.info("Detection completed.")

        return summary

    def get_severity(self, attempts):

        if attempts >= CRITICAL_SEVERITY_THRESHOLD:
            return "CRITICAL"

        if attempts >= HIGH_SEVERITY_THRESHOLD:
            return "HIGH"

        if attempts >= FAILED_LOGIN_THRESHOLD:
            return "MEDIUM"

        return "LOW"
