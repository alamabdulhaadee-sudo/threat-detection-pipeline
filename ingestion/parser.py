import re
import json
import csv
from io import StringIO
from datetime import datetime
from typing import TypedDict, Optional


class Event(TypedDict):
    timestamp: str      # ISO-8601
    source_ip: str
    username: str
    action: str         # failed_login | sudo_failure | su_failure | login_success | process_exec | network_conn
    process: str
    port: int
    raw: str
    source_file: str


def parse_line(line: str, source_file: str) -> Optional[Event]:
    """Try each parser in order, return first match or None."""
    line = line.strip()
    if not line:
        return None
    for parser in (_parse_auth_log, _parse_json_line, _parse_csv_line):
        result = parser(line)
        if result is not None:
            result["source_file"] = source_file
            result["raw"] = line
            return result
    return None


def _parse_auth_log(line: str) -> Optional[dict]:
    # Match syslog prefix: "Jan  1 00:00:00 hostname service[pid]: message"
    prefix_re = re.compile(
        r'^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+\S+[:\s]+(.*)'
    )
    m = prefix_re.match(line)
    if not m:
        return None

    ts_str, message = m.group(1), m.group(2)
    try:
        ts = datetime.strptime(f"{datetime.now().year} {ts_str.strip()}", "%Y %b %d %H:%M:%S")
        timestamp = ts.isoformat()
    except ValueError:
        timestamp = ts_str.strip()

    event = {
        "timestamp": timestamp,
        "source_ip": "",
        "username": "",
        "action": "",
        "process": "",
        "port": 0,
    }

    # Failed password
    m2 = re.search(r'Failed password for (?:invalid user )?(\S+) from ([\d.]+)', message)
    if m2:
        event["username"] = m2.group(1)
        event["source_ip"] = m2.group(2)
        event["action"] = "failed_login"
        return event

    # Accepted login
    m2 = re.search(r'Accepted (?:password|publickey) for (\S+) from ([\d.]+)', message)
    if m2:
        event["username"] = m2.group(1)
        event["source_ip"] = m2.group(2)
        event["action"] = "login_success"
        return event

    # sudo failure
    if "sudo" in message.lower() and ("authentication failure" in message.lower() or "incorrect password" in message.lower()):
        m2 = re.search(r'user=(\S+)', message)
        if m2:
            event["username"] = m2.group(1)
        m2 = re.search(r'rhost=([\d.]+)', message)
        if m2:
            event["source_ip"] = m2.group(1)
        event["action"] = "sudo_failure"
        return event

    # su failure
    if "su:" in line.lower() and "failed" in message.lower():
        m2 = re.search(r'for (\S+)', message)
        if m2:
            event["username"] = m2.group(1)
        event["action"] = "su_failure"
        return event

    return None


def _parse_json_line(line: str) -> Optional[dict]:
    try:
        data = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None

    action_map = {
        "failed_login": "failed_login",
        "auth_failure": "failed_login",
        "login_success": "login_success",
        "sudo_failure": "sudo_failure",
        "su_failure": "su_failure",
        "process_exec": "process_exec",
        "network_conn": "network_conn",
    }

    raw_action = data.get("event_type", data.get("action", ""))
    return {
        "timestamp": data.get("timestamp", datetime.utcnow().isoformat()),
        "source_ip": data.get("src_ip", data.get("source_ip", "")),
        "username": data.get("username", data.get("user", "")),
        "action": action_map.get(raw_action, raw_action),
        "process": data.get("process", ""),
        "port": int(data.get("port", 0)),
    }


def _parse_csv_line(line: str) -> Optional[dict]:
    try:
        reader = csv.reader(StringIO(line))
        row = next(reader)
    except (StopIteration, csv.Error):
        return None

    if len(row) < 4:
        return None

    # Expected columns: timestamp, src_ip, action, process, port
    try:
        # Skip header row
        if not any(c.isdigit() for c in row[0]):
            return None
        return {
            "timestamp": row[0].strip(),
            "source_ip": row[1].strip() if len(row) > 1 else "",
            "action": row[2].strip() if len(row) > 2 else "",
            "username": "",
            "process": row[3].strip() if len(row) > 3 else "",
            "port": int(row[4].strip()) if len(row) > 4 and row[4].strip().isdigit() else 0,
        }
    except (IndexError, ValueError):
        return None
