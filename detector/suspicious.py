"""
suspicious.py

Suspicious Login Detection

Detects successful logins that occur shortly after
multiple failed login attempts from the same IP address.

MITRE ATT&CK
------------
Technique:
    T1078 - Valid Accounts
"""

from collections import Counter

from config import (
    SUSPICIOUS_LOGIN_THRESHOLD,
    MITRE_VALID_ACCOUNTS,
)


def get_severity(previous_failures):
    """
    Determine alert severity.
    """

    if previous_failures >= 10:
        return "CRITICAL"

    if previous_failures >= 6:
        return "HIGH"

    return "MEDIUM"


def detect_suspicious_logins(failed_events, successful_events):
    """
    Detect suspicious successful logins.

    Parameters
    ----------
    failed_events : list
        Failed login events.

    successful_events : list
        Successful login events.

    Returns
    -------
    list
        Suspicious login alerts.
    """

    failed_counter = Counter()

    for event in failed_events:
        failed_counter[event["ip"]] += 1

    alerts = []

    for event in successful_events:

        ip = event["ip"]

        previous_failures = failed_counter.get(ip, 0)

        if previous_failures < SUSPICIOUS_LOGIN_THRESHOLD:
            continue

        alerts.append(
            {
                "type": "SUSPICIOUS_LOGIN",

                "ip": ip,

                "username": event["username"],

                "previous_failures": previous_failures,

                "severity": get_severity(previous_failures),

                "mitre": MITRE_VALID_ACCOUNTS,

                "description":
                    (
                        f"Successful login for "
                        f"'{event['username']}' "
                        f"after {previous_failures} "
                        f"failed login attempts "
                        f"from {ip}."
                    ),
            }
        )

    alerts.sort(
        key=lambda alert: alert["previous_failures"],
        reverse=True,
    )

    return alerts
