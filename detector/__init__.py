"""
detector

Detection package for the Claus SOC Toolkit.

Exports all major detection modules.
"""

from .engine import DetectionEngine

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

__all__ = [
    "DetectionEngine",
    "detect_brute_force",
    "detect_password_spraying",
    "detect_username_enumeration",
    "detect_distributed_attack",
    "detect_suspicious_logins",
    "calculate_risk_score",
    "determine_threat_level",
    "generate_recommendations",
]
