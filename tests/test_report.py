"""
tests/test_report.py

Test the ReportGenerator module.
"""

from parser import LogParser
from detector import DetectionEngine
from report import ReportGenerator


def main():
    """
    Generate an HTML report from sample logs.
    """

    # Parse logs
    parser = LogParser("logs/auth.log")
    events = parser.parse_auth_log()

    # Run detection
    engine = DetectionEngine(events)
    results = engine.analyze()

    # Generate report
    report = ReportGenerator(results)

    output = report.generate_html()

    print("\n====================================")
    print("Report generated successfully!")
    print("====================================")
    print(output)


if __name__ == "__main__":
    main()
