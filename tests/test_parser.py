from parser import LogParser

parser = LogParser("logs/auth.log")

events = parser.parse_auth_log()

print("\n========== Parsed Events ==========\n")

for event in events:
    print(event)

print(f"\nTotal Events Parsed: {len(events)}")
