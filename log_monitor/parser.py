"""Log parsing helpers.

This module contains functions to parse common server log formats using regular expressions.
"""

import re
from datetime import datetime
from typing import Dict, Optional

# Regular expression patterns for common log formats
APACHE_COMMON_LOG_REGEX = re.compile(
    r"(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+\"(?P<request>[A-Z]+\s+[^\s]+\s+HTTP/[^\s]+)\"\s+"  # noqa: E501
    r"(?P<status>\d{3})\s+(?P<size>\S+)"
)

SYSLOG_REGEX = re.compile(
    r"(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-\/\.]+)(?:\[\d+\])?:\s+(?P<message>.*)"
)

MONTH_MAP = {
    "Jan": 1,
    "Feb": 2,
    "Mar": 3,
    "Apr": 4,
    "May": 5,
    "Jun": 6,
    "Jul": 7,
    "Aug": 8,
    "Sep": 9,
    "Oct": 10,
    "Nov": 11,
    "Dec": 12,
}


def parse_apache_log_line(line: str) -> Optional[Dict]:
    """Parse a single line from an Apache access log.

    Returns a dict with parsed fields or None if the line doesn't match.
    """

    match = APACHE_COMMON_LOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()

    # Convert timestamp to a Python datetime
    try:
        timestamp = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        # Some logs might omit timezone; assume UTC
        timestamp = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S")

    return {
        "source": "apache",
        "raw": line.strip(),
        "timestamp": timestamp.isoformat(),
        "ip": data["ip"],
        "request": data["request"],
        "status": int(data["status"]),
        "size": None if data["size"] == "-" else int(data["size"]),
    }


def parse_syslog_line(line: str, year: Optional[int] = None) -> Optional[Dict]:
    """Parse a single line from a classic syslog file.

    Some syslog formats omit the year, so it is possible to pass it in.
    """

    match = SYSLOG_REGEX.match(line)
    if not match:
        return None

    data = match.groupdict()
    year = year or datetime.utcnow().year

    try:
        timestamp = datetime(
            year,
            MONTH_MAP.get(data["month"], 1),
            int(data["day"]),
            *map(int, data["time"].split(":")),
        )
    except Exception:
        return None

    return {
        "source": "syslog",
        "raw": line.strip(),
        "timestamp": timestamp.isoformat(),
        "host": data["host"],
        "process": data["process"],
        "message": data["message"],
    }
