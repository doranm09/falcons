from __future__ import annotations

import re
from datetime import datetime
from typing import Dict, Optional

SYSLOG_RE = re.compile(
    r"^<(?P<pri>\d+)>\s*(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<message>.*)$"
)

RFC3339_RE = re.compile(
    r"^<(?P<pri>\d+)>\s*(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z)\s+(?P<host>\S+)\s+(?P<message>.*)$"
)


def parse_syslog_line(line: str) -> Dict[str, Optional[str]]:
    line = line.strip()
    if not line:
        return {"message": ""}

    match = RFC3339_RE.match(line) or SYSLOG_RE.match(line)
    if not match:
        return {"message": line}

    data = match.groupdict()
    return {
        "pri": data.get("pri"),
        "timestamp": data.get("timestamp"),
        "host": data.get("host"),
        "message": data.get("message"),
    }


def syslog_to_event(line: str) -> Dict[str, str]:
    parsed = parse_syslog_line(line)
    message = parsed.get("message") or line
    timestamp = parsed.get("timestamp")
    if timestamp and len(timestamp.split()) == 3:
        # RFC3164 timestamps do not include year; drop to allow server to set ingest time.
        timestamp = None
    event = {
        "event_type": "syslog.message",
        "source": "syslog",
        "timestamp": timestamp,
        "message": message,
        "asset_id": parsed.get("host"),
        "asset_ip": None,
        "raw": {"syslog": line},
    }
    return event
