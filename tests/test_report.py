from parser import LogParser
from detector import DetectionEngine
from report import ReportGenerator

# Parse logs
parser = LogParser("logs/auth.log")
events = parser.parse_auth_log()

# Run detection
engine = DetectionEngine(events)
results = engine.analyze()

# Generate report
report = ReportGenerator()

output = report.generate_html(results)

print(f"\nReport generated successfully:\n{output}")
