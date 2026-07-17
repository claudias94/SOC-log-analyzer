"""
tests/test_exporter.py

Test the Exporter module.
"""

from parser import LogParser
from detector import DetectionEngine
from exporter import Exporter


def main():
    """
    Test all exporter formats.
    """

    parser = LogParser("logs/auth.log")
    events = parser.parse_auth_log()

    engine = DetectionEngine(events)
    results = engine.analyze()

    exporter = Exporter(results)

    outputs = exporter.export_all()

    print("\n====================================")
    print("Export completed successfully!")
    print("====================================")

    for fmt, path in outputs.items():
        print(f"{fmt.upper():10} -> {path}")


if __name__ == "__main__":
    main()
