"""
parser.py

Parses different log formats and returns structured events.
"""

import re
from pathlib import Path

from logger import logger


class LogParser:
    """
    Generic log parser supporting multiple log formats.
    """

    def __init__(self, logfile):
        self.logfile = Path(logfile)

    def read_lines(self):
        """
        Read all lines from the log file.
        """
        if not self.logfile.exists():
            logger.error(f"File not found: {self.logfile}")
            raise FileNotFoundError(self.logfile)

        logger.info(f"Reading log file: {self.logfile}")

        with open(self.logfile, "r", encoding="utf-8", errors="ignore") as file:
            return file.readlines()

    def parse_auth_log(self):
        """
        Parse Linux auth.log.
        """

        lines = self.read_lines()

        events = []

        failed_regex = re.compile(
            r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )

        success_regex = re.compile(
            r"Accepted password for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
        )

        for line in lines:

            failed = failed_regex.search(line)

            if failed:

                event_type = (
                    "INVALID_USER"
                    if failed.group("invalid")
                    else "FAILED_LOGIN"
                )

                events.append(
                    {
                        "type": event_type,
                        "username": failed.group("user"),
                        "ip": failed.group("ip"),
                        "raw": line.strip(),
                    }
                )

                continue

            success = success_regex.search(line)

            if success:

                events.append(
                    {
                        "type": "SUCCESSFUL_LOGIN",
                        "username": success.group("user"),
                        "ip": success.group("ip"),
                        "raw": line.strip(),
                    }
                )

        logger.info(f"Parsed {len(events)} events")

        return events
