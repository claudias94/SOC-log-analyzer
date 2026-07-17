"""
password_spray.py

Password spraying detection.

Detects when one IP attempts to authenticate against
multiple usernames.

MITRE ATT&CK
------------
Technique:
    T1110.003 - Password Spraying
"""

from collections import defaultdict

from config import (
    PASSWORD_SPRAY_THRESHOLD,
    HIGH_SEVERITY_THRESHOLD,
    CRITICAL_SEVERITY_THRESHOLD,
    MITRE_PASSWORD_SPRAY,
)


def get_severity(username_count):
    """
    Determine alert severity based on the number of
    usernames targeted.
    """

    if username_count >= CRITICAL_SEVERITY_THRESHOLD:
        return "CRITICAL"

    if username_count >= HIGH_SEVERITY_THRESHOLD:
        return "HIGH"

    if username_count >= PASSWORD_SPRAY_THRESHOLD:
        return "MEDIUM"

    return "LOW"


def detect_password_spraying(events):
    """
    Detect password spraying attacks.

    A password spraying attack is when one IP attempts
    to log in to many different user accounts.

    Parameters
    ----------
    events : list
        Failed login events.

    Returns
    -------
    list
        Password spraying alerts.
    """

    ip_users = defaultdict(set)

    for event in events:

        ip = event["ip"]
        username = event["username"]

        ip_users[ip].add(username)

    alerts = []

    for ip, usernames in ip_users.items():

        username_count = len(usernames)

        if username_count < PASSWORD_SPRAY_THRESHOLD:
            continue

        alerts.append(
            {
                "type": "PASSWORD_SPRAY",

                "ip": ip,

                "usernames": sorted(usernames),

                "username_count": username_count,

                "severity": get_severity(username_count),

                "mitre": MITRE_PASSWORD_SPRAY,

                "description":
                    (
                        f"{ip} attempted authentication "
                        f"against {username_count} "
                        f"different user accounts."
                    ),
            }
        )

    alerts.sort(
        key=lambda alert: alert["username_count"],
        reverse=True,
    )

    return alerts
