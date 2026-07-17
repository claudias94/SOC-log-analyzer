"""
enumeration.py

Username Enumeration Detection

Detects attackers attempting to discover valid user accounts
by repeatedly trying invalid usernames.

MITRE ATT&CK
------------
Technique:
    T1087 - Account Discovery
"""

from collections import defaultdict

from config import (
    INVALID_USER_THRESHOLD,
    MITRE_ACCOUNT_DISCOVERY,
)


def get_severity(attempts):
    """
    Determine severity for username enumeration.
    """

    if attempts >= 10:
        return "CRITICAL"

    if attempts >= 6:
        return "HIGH"

    return "MEDIUM"


def detect_username_enumeration(events):
    """
    Detect username enumeration attacks.

    Parameters
    ----------
    events : list
        List of INVALID_USER events.

    Returns
    -------
    list
        Username enumeration alerts.
    """

    ip_counter = defaultdict(int)
    usernames = defaultdict(set)

    for event in events:

        ip = event["ip"]
        username = event["username"]

        ip_counter[ip] += 1
        usernames[ip].add(username)

    alerts = []

    for ip in ip_counter:

        attempts = ip_counter[ip]

        if attempts < INVALID_USER_THRESHOLD:
            continue

        alerts.append(
            {
                "type": "USERNAME_ENUMERATION",
                "ip": ip,
                "attempts": attempts,
                "unique_usernames": len(usernames[ip]),
                "usernames": sorted(usernames[ip]),
                "severity": get_severity(attempts),
                "mitre": MITRE_ACCOUNT_DISCOVERY,
                "description": (
                    f"{ip} attempted {attempts} invalid logins using "
                    f"{len(usernames[ip])} different usernames."
                ),
            }
        )

    alerts.sort(
        key=lambda alert: alert["attempts"],
        reverse=True,
    )

    return alerts
