"""
scoring.py

Risk scoring and threat level calculation
for the Claus SOC Toolkit.

Combines outputs from all detection modules into
a single risk score and overall threat level.
"""

from config import (
    FAILED_LOGIN_WEIGHT,
    INVALID_USER_WEIGHT,
    BRUTE_FORCE_WEIGHT,
    PASSWORD_SPRAY_WEIGHT,
    DISTRIBUTED_ATTACK_WEIGHT,
    SUSPICIOUS_LOGIN_WEIGHT,
    MAX_RISK_SCORE,
    LOW_RISK_MAX,
    MEDIUM_RISK_MAX,
    HIGH_RISK_MAX,
)


def calculate_risk_score(
    failed_events,
    invalid_events,
    brute_force,
    password_spraying,
    distributed_attack,
    suspicious_logins,
):
    """
    Calculate an overall risk score.

    Returns
    -------
    int
        Risk score between 0 and MAX_RISK_SCORE.
    """

    score = 0

    # Basic authentication activity
    score += len(failed_events) * FAILED_LOGIN_WEIGHT
    score += len(invalid_events) * INVALID_USER_WEIGHT

    # High-confidence detections
    score += len(brute_force) * BRUTE_FORCE_WEIGHT
    score += len(password_spraying) * PASSWORD_SPRAY_WEIGHT
    score += len(distributed_attack) * DISTRIBUTED_ATTACK_WEIGHT
    score += len(suspicious_logins) * SUSPICIOUS_LOGIN_WEIGHT

    # Cap the score
    return min(score, MAX_RISK_SCORE)


def determine_threat_level(risk_score):
    """
    Convert a numeric risk score into
    an overall threat level.

    Parameters
    ----------
    risk_score : int

    Returns
    -------
    str
    """

    if risk_score <= LOW_RISK_MAX:
        return "LOW"

    if risk_score <= MEDIUM_RISK_MAX:
        return "MEDIUM"

    if risk_score <= HIGH_RISK_MAX:
        return "HIGH"

    return "CRITICAL"
