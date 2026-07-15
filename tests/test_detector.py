from parser import LogParser
from detector import DetectionEngine
from dashboard import display_summary, display_alerts

# Parse log file
parser = LogParser("logs/auth.log")
events = parser.parse_auth_log()

# Run detections
engine = DetectionEngine(events)
results = engine.analyze()

# Display results
display_summary(results)
display_alerts(results)
