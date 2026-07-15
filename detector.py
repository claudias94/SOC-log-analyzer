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

    def __init__(self, events):
        self.events = events

    def analyze(self):

        failed = []
        successful = []

        for event in self.events:

            if event["type"] == "FAILED_LOGIN":
                failed.append(event)

            elif event["type"] == "SUCCESSFUL_LOGIN":
                successful.append(event)

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

        summary = {

            "failed_logins": len(failed),

            "successful_logins": len(successful),

            "unique_ips": len(ip_counter),

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
