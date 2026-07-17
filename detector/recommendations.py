"""
recommendations.py

Security recommendations for the Claus SOC Toolkit.

Generates human-readable recommendations based on the
detections produced by the detection engine.
"""


def generate_recommendations(
    threat_level,
    brute_force,
    password_spraying,
    username_enumeration,
    distributed_attack,
    suspicious_logins,
):
    """
    Generate security recommendations.

    Parameters
    ----------
    threat_level : str

    brute_force : list

    password_spraying : list

    username_enumeration : list

    distributed_attack : list

    suspicious_logins : list

    Returns
    -------
    list
        List of recommendations.
    """

    recommendations = []

    # -----------------------------
    # Overall Threat Level
    # -----------------------------

    if threat_level == "LOW":

        recommendations.append(
            "Continue monitoring authentication logs."
        )

    elif threat_level == "MEDIUM":

        recommendations.append(
            "Investigate unusual authentication activity."
        )

    elif threat_level == "HIGH":

        recommendations.append(
            "Immediate investigation is recommended."
        )

    elif threat_level == "CRITICAL":

        recommendations.append(
            "Activate the incident response process immediately."
        )

    # -----------------------------
    # Brute Force
    # -----------------------------

    if brute_force:

        recommendations.append(
            "Block or rate-limit offending IP addresses."
        )

        recommendations.append(
            "Enable Multi-Factor Authentication (MFA)."
        )

        recommendations.append(
            "Review firewall and IDS/IPS logs."
        )

    # -----------------------------
    # Password Spraying
    # -----------------------------

    if password_spraying:

        recommendations.append(
            "Review password policy and enforce strong passwords."
        )

        recommendations.append(
            "Check for compromised user accounts."
        )

    # -----------------------------
    # Username Enumeration
    # -----------------------------

    if username_enumeration:

        recommendations.append(
            "Disable unnecessary user accounts."
        )

        recommendations.append(
            "Avoid revealing whether usernames exist."
        )

    # -----------------------------
    # Distributed Attack
    # -----------------------------

    if distributed_attack:

        recommendations.append(
            "Investigate coordinated attacks from multiple IPs."
        )

        recommendations.append(
            "Consider geolocation-based filtering."
        )

    # -----------------------------
    # Suspicious Login
    # -----------------------------

    if suspicious_logins:

        recommendations.append(
            "Verify successful logins after repeated failures."
        )

        recommendations.append(
            "Force password resets for affected accounts."
        )

    # -----------------------------
    # Remove duplicates
    # -----------------------------

    recommendations = list(dict.fromkeys(recommendations))

    return recommendations
