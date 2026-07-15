from parser import LogParser
from detector import DetectionEngine
from exporter import Exporter

parser = LogParser("logs/auth.log")
events = parser.parse_auth_log()

engine = DetectionEngine(events)
results = engine.analyze()

exporter = Exporter()

json_file = exporter.export_json(results)
csv_file = exporter.export_csv(results)

print("\nReports generated successfully:\n")
print(json_file)
print(csv_file)
