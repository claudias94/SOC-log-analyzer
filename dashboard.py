"""
dashboard.py

Rich terminal dashboard for the Claus SOC Toolkit.

Displays:
- Authentication summary
- Threat assessment
- Detection summary
- MITRE ATT&CK
- Recommendations
"""

from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

from config import APP_NAME, APP_VERSION, AUTHOR

console = Console()


# ==========================================================
# Helper Functions
# ==========================================================

def threat_color(level):
    """
    Return Rich color for threat level.
    """

    colors = {
        "LOW": "green",
        "MEDIUM": "yellow",
        "HIGH": "orange3",
        "CRITICAL": "red",
    }

    return colors.get(level.upper(), "white")


def make_title():
    """
    Project banner.
    """

    title = Text()

    title.append(
        f"{APP_NAME}\n",
        style="bold cyan",
    )

    title.append(
        f"Version {APP_VERSION}\n",
        style="bold white",
    )

    title.append(
        "Claus SOC Toolkit",
        style="bold green",
    )

    return Panel(
        title,
        box=box.DOUBLE,
        border_style="cyan",
    )


# ==========================================================
# Authentication Summary
# ==========================================================

def authentication_table(results):
    """
    Authentication statistics.
    """

    table = Table(
        title="Authentication Summary",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column(
        "Metric",
        style="cyan",
    )

    table.add_column(
        "Value",
        justify="center",
        style="green",
    )

    table.add_row(
        "Failed Logins",
        str(results["failed_logins"]),
    )

    table.add_row(
        "Invalid User Attempts",
        str(results["invalid_user_attempts"]),
    )

    table.add_row(
        "Successful Logins",
        str(results["successful_logins"]),
    )

    table.add_row(
        "Unique IP Addresses",
        str(results["unique_ips"]),
    )

    return table


# ==========================================================
# Threat Assessment
# ==========================================================

def threat_table(results):
    """
    Threat information.
    """

    table = Table(
        title="Threat Assessment",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column(
        "Metric",
        style="cyan",
    )

    table.add_column(
        "Value",
        justify="center",
    )

    table.add_row(
        "Risk Score",
        f"{results['risk_score']} / 100",
    )

    color = threat_color(
        results["threat_level"]
    )

    table.add_row(
        "Threat Level",
        f"[{color}]{results['threat_level']}[/{color}]",
    )

    table.add_row(
        "Top Attacker",
        results["top_attacker"] or "N/A",
    )

    table.add_row(
        "Top Attempts",
        str(results["top_attempts"]),
    )

    return table
# ==========================================================
# Detection Summary
# ==========================================================

def detection_table(results):
    """
    Display detection statistics.
    """

    table = Table(
        title="Detection Summary",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column(
        "Detection",
        style="cyan",
    )

    table.add_column(
        "Alerts",
        justify="center",
        style="magenta",
    )

    table.add_row(
        "Brute Force",
        str(len(results["brute_force_alerts"])),
    )

    table.add_row(
        "Password Spraying",
        str(len(results["password_spraying_alerts"])),
    )

    table.add_row(
        "Username Enumeration",
        str(len(results["username_enumeration_alerts"])),
    )

    table.add_row(
        "Distributed Attack",
        str(len(results["distributed_attack_alerts"])),
    )

    table.add_row(
        "Suspicious Login",
        str(len(results["suspicious_login_alerts"])),
    )

    return table


# ==========================================================
# MITRE ATT&CK Mapping
# ==========================================================

def mitre_table(results):
    """
    Display MITRE ATT&CK techniques detected.
    """

    table = Table(
        title="MITRE ATT&CK",
        box=box.ROUNDED,
    )

    table.add_column(
        "Technique",
        style="cyan",
    )

    table.add_column(
        "Description",
        style="green",
    )

    added = set()

    alert_groups = [
        results["brute_force_alerts"],
        results["password_spraying_alerts"],
        results["username_enumeration_alerts"],
        results["distributed_attack_alerts"],
        results["suspicious_login_alerts"],
    ]

    for group in alert_groups:

        for alert in group:

            technique = alert.get("mitre")

            if not technique:
                continue

            if technique in added:
                continue

            added.add(technique)

            table.add_row(
                technique,
                alert.get("description", "Detection"),
            )

    if not added:

        table.add_row(
            "-",
            "No MITRE techniques triggered",
        )

    return table


# ==========================================================
# Recommendations
# ==========================================================

def recommendations_panel(results):
    """
    Analyst recommendations.
    """

    recommendations = results.get(
        "recommendations",
        [],
    )

    if not recommendations:

        recommendations = [
            "Continue monitoring authentication activity."
        ]

    text = ""

    for item in recommendations:

        text += f"• {item}\n"

    return Panel(
        text.rstrip(),
        title="Recommendations",
        border_style="green",
    )


# ==========================================================
# Project Information
# ==========================================================

def info_panel(results):
    """
    Project information.
    """

    text = f"""
Application : {APP_NAME}
Version     : {APP_VERSION}
Author      : {AUTHOR}
Generated   : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
"""

    return Panel(
        text.strip(),
        title="Project Information",
        border_style="cyan",
    )
# ==========================================================
# Main Dashboard
# ==========================================================

def display_dashboard(results):
    """
    Display the complete SOC dashboard.
    """

    console.clear()

    # Banner
    console.print(make_title())
    console.print()

    # Main Tables
    console.print(authentication_table(results))
    console.print()

    console.print(threat_table(results))
    console.print()

    console.print(detection_table(results))
    console.print()

    console.print(mitre_table(results))
    console.print()

    console.print(recommendations_panel(results))
    console.print()

    console.print(info_panel(results))


# ==========================================================
# Backward Compatibility
# ==========================================================

def display_summary(results):
    """
    Legacy wrapper.

    Existing code that calls display_summary()
    will continue to work while using the new
    dashboard internally.
    """

    display_dashboard(results)


def display_alerts(results):
    """
    Legacy wrapper.

    Alerts are now integrated into the
    dashboard, so this function intentionally
    does nothing to maintain compatibility.
    """

    return
