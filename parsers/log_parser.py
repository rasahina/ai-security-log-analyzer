import re
from datetime import datetime


COMMON_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+)'
)

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

def parse_common_access_log_line(line: str):
    match = COMMON_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("timestamp"),
        "%d/%b/%Y:%H:%M:%S %z"
    ).isoformat()

    return {
        "timestamp": timestamp,
        "ip": match.group("ip"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status")),
        "user_agent": None,
        "error_message": None,
    }

def parse_combined_access_log_line(line: str):
    match = COMBINED_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp = datetime.strptime(
        match.group("timestamp"),
        "%d/%b/%Y:%H:%M:%S %z"
    ).isoformat()

    return {
        "timestamp": timestamp,
        "ip": match.group("ip"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status")),
        "user_agent": match.group("user_agent"),
        "error_message": None,
    }

def detect_log_format(line: str) -> str:
    line = line.strip()

    if not line or line.startswith("#"):
        return "ignore"
    
    if COMBINED_LOG_PATTERN.match(line):
        return "combined_access"
    
    if COMMON_LOG_PATTERN.match(line):
        return "common_access"
    


    parts = line.split()

    if len(parts) == 5:
        return "simple_access"

    if "error" in line.lower() or "warn" in line.lower():
        return "error_log"
    

    return "unknown"


def parse_access_log_line(line: str):
    line = line.strip()

    if not line or line.startswith("#"):
        return None

    parts = line.split()

    if len(parts) != 5:
        return None

    return {
        "timestamp": parts[0],
        "ip": parts[1],
        "method": parts[2],
        "url": parts[3],
        "status": int(parts[4]) if parts[4].isdigit() else None,
        "user_agent": None,
        "error_message": None,
    }

def parse_log_lines(lines):
    parsed = []

    for line in lines:
        fmt = detect_log_format(line)

        if fmt == "simple_access":
            result = parse_access_log_line(line)
        elif fmt == "common_access":
            result = parse_common_access_log_line(line)
        elif fmt == "combined_access":
            result = parse_combined_access_log_line(line)
        else:
            result = None

        if result:
            parsed.append(result)

    return parsed