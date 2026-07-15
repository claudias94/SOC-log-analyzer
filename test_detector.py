from parser import LogParser
from detector import DetectionEngine
from dashboard import display_summary, display_alerts

parser = LogParser("logs/auth.log")

events = parser.parse_auth_log()

engine = DetectionEngine(events)

results = engine.analyze()

display_summary(results)

display_alerts(results)
