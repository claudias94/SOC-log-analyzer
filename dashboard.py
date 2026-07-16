"""
dashboard.py

Rich terminal dashboard for the SOC Log Analyzer.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def get_threat_style(level):
    """
    Return Rich color markup based on threat level.
    """

    colors = {
        "LOW": "[green]LOW[/green]",
        "MEDIUM": "[yellow]MEDIUM[/yellow]",
        "HIGH": "[bold red]HIGH[/bold red]",
        "CRITICAL": "[bold white on red]CRITICAL[/bold white on red]",
    }

    return colors.get(level, level)


def display_summary(results):
    """
    Display the analysis summary.
    """

    table = Table(
        title="SOC Log Analyzer v2.2",
        box=box.ROUNDED,
        show_lines=True,
    )

    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="center")

    table.add_row(
        "Failed Logins",
        str(results["failed_logins"])
    )

    table.add_row(
        "Invalid User Attempts",
        str(results["invalid_user_attempts"])
    )

    table.add_row(
        "Successful Logins",
        str(results["successful_logins"])
    )

    table.add_row(
        "Unique IPs",
        str(results["unique_ips"])
    )

    table.add_row(
        "Threat Level",
        get_threat_style(results["threat_level"])
    )

    table.add_row(
        "Top Attacker",
        results["top_attacker"] or "N/A"
    )

    table.add_row(
        "Top Attempts",
        str(results["top_attempts"])
    )

    console.print(table)


def display_alerts(results):
    """
    Display brute-force alerts.
    """

    alerts = results["brute_force_alerts"]

    if not alerts:

        console.print(
            Panel.fit(
                "[bold green]No brute-force attacks detected.[/bold green]",
                title="Status",
                border_style="green",
            )
        )

        return

    for alert in alerts:

        console.print(
            Panel.fit(
                f"""[bold red]HIGH ALERT[/bold red]

IP Address : {alert['ip']}
Attempts   : {alert['attempts']}
Severity   : {alert['severity']}
MITRE      : {alert['mitre']}
""",
                title="Threat Detection",
                border_style="red",
            )
        )
