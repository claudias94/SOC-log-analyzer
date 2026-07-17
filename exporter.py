"""
exporter.py

Export detection results into multiple formats.

Supported formats
-----------------
- JSON
- CSV
- Markdown
"""

import csv
import json
from pathlib import Path

from config import REPORT_DIR
from logger import logger


class Exporter:
    """
    Export detection results.
    """

    def __init__(self, results):

        self.results = results

        self.output_dir = REPORT_DIR

        self.output_dir.mkdir(exist_ok=True)

    # ======================================================
    # JSON Export
    # ======================================================

    def export_json(self, filename="report.json"):
        """
        Export results to JSON.
        """

        filepath = self.output_dir / filename

        with open(
            filepath,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                self.results,
                file,
                indent=4,
            )

        logger.info(f"JSON report saved to {filepath}")

        return filepath

    # ======================================================
    # CSV Export
    # ======================================================

    def export_csv(self, filename="report.csv"):
        """
        Export summary to CSV.
        """

        filepath = self.output_dir / filename

        with open(
            filepath,
            "w",
            newline="",
            encoding="utf-8",
        ) as file:

            writer = csv.writer(file)

            writer.writerow(["Metric", "Value"])

            for key, value in self.results.items():

                if isinstance(value, (list, dict)):
                    continue

                writer.writerow([key, value])

        logger.info(f"CSV report saved to {filepath}")

        return filepath
    # ======================================================
    # Markdown Export
    # ======================================================

    def export_markdown(self, filename="report.md"):
        """
        Export results as a Markdown report.
        """

        filepath = self.output_dir / filename

        lines = []

        lines.append("# SOC Log Analyzer Report")
        lines.append("")

        lines.append("## Summary")
        lines.append("")

        for key, value in self.results.items():

            if isinstance(value, (list, dict)):
                continue

            lines.append(f"- **{key.replace('_', ' ').title()}**: {value}")

        lines.append("")

        lines.append("## Detection Details")
        lines.append("")

        detection_keys = [
            "brute_force_alerts",
            "password_spraying_alerts",
            "username_enumeration_alerts",
            "distributed_attack_alerts",
            "suspicious_login_alerts",
        ]

        found = False

        for key in detection_keys:

            alerts = self.results.get(key, [])

            if not alerts:
                continue

            found = True

            lines.append(f"### {key.replace('_', ' ').title()}")

            for alert in alerts:

                lines.append(f"- {alert}")

            lines.append("")

        if not found:

            lines.append("No detections found.")
            lines.append("")

        with open(
            filepath,
            "w",
            encoding="utf-8",
        ) as file:

            file.write("\n".join(lines))

        logger.info(f"Markdown report saved to {filepath}")

        return filepath

    # ======================================================
    # Export Everything
    # ======================================================

    def export_all(self):
        """
        Export all supported formats.
        """

        logger.info("Exporting all report formats...")

        exports = {
            "json": self.export_json(),
            "csv": self.export_csv(),
            "markdown": self.export_markdown(),
        }

        logger.info("All exports completed successfully.")

        return exports

    # ======================================================
    # Export Summary
    # ======================================================

    def summary(self):
        """
        Return a summary of available export formats.
        """

        return {
            "JSON": "report.json",
            "CSV": "report.csv",
            "Markdown": "report.md",
        }
# ==========================================================
# Legacy Compatibility Function
# ==========================================================

def export_results(results):
    """
    Legacy compatibility wrapper.

    Exports all report formats using the Exporter class.
    """

    exporter = Exporter(results)

    return exporter.export_all()
