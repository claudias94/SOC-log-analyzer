"""
analyzer.py

Main entry point for the SOC Log Analyzer.

Workflow

1. Parse authentication logs
2. Run the detection engine
3. Display terminal dashboard
4. Generate HTML report
5. Export JSON, CSV and Markdown reports
"""

from parser import LogParser
from detector import DetectionEngine
from dashboard import display_summary, display_alerts
from report import ReportGenerator
from exporter import Exporter
from logger import logger


LOG_FILE = "logs/auth.log"


def analyze():
    """
    Execute the complete SOC analysis workflow.
    """

    logger.info("=" * 60)
    logger.info("Starting SOC Log Analyzer")
    logger.info("=" * 60)

    # -------------------------------------------------
    # Parse Logs
    # -------------------------------------------------

    parser = LogParser(LOG_FILE)

    events = parser.parse_auth_log()

    logger.info(f"Events parsed: {len(events)}")

    # -------------------------------------------------
    # Detection Engine
    # -------------------------------------------------

    engine = DetectionEngine(events)

    results = engine.analyze()

    logger.info("Detection engine completed.")

    # -------------------------------------------------
    # Dashboard
    # -------------------------------------------------

    display_summary(results)

    display_alerts(results)

    # -------------------------------------------------
    # HTML Report
    # -------------------------------------------------

    report = ReportGenerator(results)

    html_report = report.generate_html()

    logger.info(f"HTML report: {html_report}")

    # -------------------------------------------------
    # Export Reports
    # -------------------------------------------------

    exporter = Exporter(results)

    exported = exporter.export_all()

    logger.info("Export completed.")

    # -------------------------------------------------
    # Summary
    # -------------------------------------------------

    print("\n")
    print("=" * 65)
    print("SOC LOG ANALYZER COMPLETED SUCCESSFULLY")
    print("=" * 65)

    print(f"HTML Report : {html_report}")

    for fmt, path in exported.items():
        print(f"{fmt.upper():10}: {path}")

    print("=" * 65)

    return results


def main():
    """
    Program entry point.
    """

    analyze()


if __name__ == "__main__":
    main()
