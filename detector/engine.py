"""
engine.py

Central Detection Engine

Coordinates all detection modules and returns
a unified analysis result.
"""

from .utils import (
    filter_events,
    count_unique_ips,
    top_attacker,
)

from .brute_force import detect_brute_force
from .password_spray import detect_password_spraying
from .enumeration import detect_username_enumeration
from .distributed import detect_distributed_attack
from .suspicious import detect_suspicious_logins

from .scoring import (
    calculate_risk_score,
    determine_threat_level,
)

from .recommendations import (
    generate_recommendations,
)

from logger import logger


class DetectionEngine:
    """
    Main detection engine.

    This class coordinates all detection modules and
    combines their outputs into a single analysis result.
    """

    def __init__(self, events):
        self.events = events

    def analyze(self):
        """
        Perform complete analysis.

        Returns
        -------
        dict
        """

        logger.info("Starting detection engine...")

        # ------------------------------------
        # Split events by type
        # ------------------------------------

        failed_events = filter_events(
            self.events,
            "FAILED_LOGIN",
        )

        successful_events = filter_events(
            self.events,
            "SUCCESSFUL_LOGIN",
        )

        invalid_events = filter_events(
            self.events,
            "INVALID_USER",
        )

        # ------------------------------------
        # Execute detection modules
        # ------------------------------------

        brute_force = detect_brute_force(
            failed_events
        )

        password_spraying = detect_password_spraying(
            failed_events
        )

        username_enumeration = detect_username_enumeration(
            invalid_events
        )

        distributed_attack = detect_distributed_attack(
            failed_events
        )

        suspicious_logins = detect_suspicious_logins(
            failed_events,
            successful_events,
        )

        # ------------------------------------
        # Risk Scoring
        # ------------------------------------

        risk_score = calculate_risk_score(
            failed_events,
            invalid_events,
            brute_force,
            password_spraying,
            distributed_attack,
            suspicious_logins,
        )

        threat_level = determine_threat_level(
            risk_score
        )

        # ------------------------------------
        # Recommendations
        # ------------------------------------

        recommendations = generate_recommendations(
            threat_level,
            brute_force,
            password_spraying,
            username_enumeration,
            distributed_attack,
            suspicious_logins,
        )

        # ------------------------------------
        # Statistics
        # ------------------------------------

        top_ip, top_attempts = top_attacker(
            failed_events
        )

        results = {

            # Statistics
            "failed_logins": len(failed_events),
            "successful_logins": len(successful_events),
            "invalid_user_attempts": len(invalid_events),
            "unique_ips": count_unique_ips(failed_events),

            # Risk
            "risk_score": risk_score,
            "threat_level": threat_level,

            # Top attacker
            "top_attacker": top_ip,
            "top_attempts": top_attempts,

            # Alerts
            "brute_force_alerts": brute_force,
            "password_spraying_alerts": password_spraying,
            "username_enumeration_alerts": username_enumeration,
            "distributed_attack_alerts": distributed_attack,
            "suspicious_login_alerts": suspicious_logins,

            # Recommendations
            "recommendations": recommendations,
        }

        logger.info("Detection completed successfully.")

        return results
