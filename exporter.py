"""
exporter.py

Exports detection results to JSON and CSV.
"""

import csv
import json
from pathlib import Path

from logger import logger


class Exporter:
    """
    Export detection results to different formats.
    """

    def __init__(self):
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)

    def export_json(self, results):
        """
        Export results as JSON.
        """
        output_file = self.output_dir / "report.json"

        logger.info("Generating JSON report...")

        with open(output_file, "w", encoding="utf-8") as file:
            json.dump(results, file, indent=4)

        logger.info(f"JSON report saved to {output_file}")

        return output_file

    def export_csv(self, results):
        """
        Export summary results as CSV.
        """
        output_file = self.output_dir / "report.csv"

        logger.info("Generating CSV report...")

        with open(output_file, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow(["Metric", "Value"])
            writer.writerow(["Failed Logins", results["failed_logins"]])
            writer.writerow(["Successful Logins", results["successful_logins"]])
            writer.writerow(["Unique IPs", results["unique_ips"]])
            writer.writerow(["Threat Level", results["threat_level"]])
            writer.writerow(["Top Attacker", results["top_attacker"]])
            writer.writerow(["Top Attempts", results["top_attempts"]])

        logger.info(f"CSV report saved to {output_file}")

        return output_file
