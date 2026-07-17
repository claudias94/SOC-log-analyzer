"""
distributed.py

Distributed Attack Detection

Detects multiple source IP addresses targeting the same
user account.

MITRE ATT&CK
------------
Technique:
    T1110 - Brute Force
"""

from collections import defaultdict

from config import (
    DISTRIBUTED_ATTACK_THRESHOLD,
    MITRE_BRUTE_FORCE,
)


def get_severity(ip_count):
    """
    Determine alert severity.
    """

    if ip_count >= 10:
        return "CRITICAL"

    if ip_count >= 6:
        return "HIGH"

    return "MEDIUM"


def detect_distributed_attack(events):
    """
    Detect distributed brute-force attacks.

    Parameters
    ----------
    events : list
        Failed login events.

    Returns
    -------
    list
        Distributed attack alerts.
    """

    user_ips = defaultdict(set)
    user_attempts = defaultdict(int)

    for event in events:

        username = event["username"]
        ip = event["ip"]

        user_ips[username].add(ip)
        user_attempts[username] += 1

    alerts = []

    for username, ips in user_ips.items():

        ip_count = len(ips)

        if ip_count < DISTRIBUTED_ATTACK_THRESHOLD:
            continue

        alerts.append(
            {
                "type": "DISTRIBUTED_ATTACK",

                "target_user": username,

                "attempts": user_attempts[username],

                "source_ip_count": ip_count,

                "source_ips": sorted(ips),

                "severity": get_severity(ip_count),

                "mitre": MITRE_BRUTE_FORCE,

                "description":
                    (
                        f"User '{username}' was targeted "
                        f"by {ip_count} different IP "
                        f"addresses."
                    ),
            }
        )

    alerts.sort(
        key=lambda alert: alert["source_ip_count"],
        reverse=True,
    )

    return alerts
