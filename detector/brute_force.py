"""
brute_force.py

Brute-force attack detection.

Detects repeated failed logins originating from the same
IP address.

MITRE ATT&CK
------------
Technique:
    T1110.001 - Password Guessing
"""

from collections import Counter

from config import (
    FAILED_LOGIN_THRESHOLD,
    HIGH_SEVERITY_THRESHOLD,
    CRITICAL_SEVERITY_THRESHOLD,
    MITRE_BRUTE_FORCE,
)


def get_severity(attempts):
    """
    Determine severity based on the number of attempts.
    """

    if attempts >= CRITICAL_SEVERITY_THRESHOLD:
        return "CRITICAL"

    if attempts >= HIGH_SEVERITY_THRESHOLD:
        return "HIGH"

    if attempts >= FAILED_LOGIN_THRESHOLD:
        return "MEDIUM"

    return "LOW"


def detect_brute_force(events):
    """
    Detect brute-force attacks.

    Parameters
    ----------
    events : list

        Failed login events.

    Returns
    -------
    list

        List of brute-force alerts.
    """

    ip_counter = Counter()

    for event in events:

        ip_counter[event["ip"]] += 1

    alerts = []

    for ip, attempts in ip_counter.items():

        if attempts < FAILED_LOGIN_THRESHOLD:
            continue

        alerts.append(
            {
                "type": "BRUTE_FORCE",

                "ip": ip,

                "attempts": attempts,

                "severity": get_severity(attempts),

                "mitre": MITRE_BRUTE_FORCE,

                "description":
                    (
                        f"{attempts} failed login attempts "
                        f"were detected from {ip}."
                    ),
            }
        )

    alerts.sort(
        key=lambda alert: alert["attempts"],
        reverse=True,
    )

    return alerts
