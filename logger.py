"""
logger.py

Logging configuration.
"""

import logging

from config import LOG_FILE, LOG_LEVEL

logger = logging.getLogger("SOCAnalyzer")

logger.setLevel(getattr(logging, LOG_LEVEL))

formatter = logging.Formatter(
    "%(asctime)s | %(levelname)s | %(message)s"
)

file_handler = logging.FileHandler(LOG_FILE)

file_handler.setFormatter(formatter)

console_handler = logging.StreamHandler()

console_handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
