import re
from datetime import datetime


COMMON_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3})(?: (?P<size>\S+))?'
)

COMBINED_LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<url>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"'
)

ERROR_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}) '
    r'\[(?P<level>\w+)\] .*? (?P<message>.*)'
)

CLIENT_IP_PATTERN = re.compile(r"client: (?P<ip>\d+\.\d+\.\d+\.\d+)")

REQUEST_PATTERN = re.compile(r'request: "(?P<method>\S+) (?P<url>\S+) [^"]+"')

def parse_timestamp(value: str):
    formats = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt).isoformat()
        except ValueError:
            pass

    try:
        return datetime.fromisoformat(value).isoformat()
    except ValueError:
        return value


def get_timestamp_warnings(value: str):
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return ["malformed_timestamp"]

    if timestamp.tzinfo is None:
        return ["timezone_missing"]

    return []
    

def parse_error_log_line(line: str):
    match = ERROR_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp = parse_timestamp(match.group("timestamp"))

    message = match.group("message")
    ip_match = CLIENT_IP_PATTERN.search(message)
    request_match = REQUEST_PATTERN.search(message)

    ip = ip_match.group("ip") if ip_match else None
    method = request_match.group("method") if request_match else None
    url = request_match.group("url") if request_match else None
    parser_warnings = get_timestamp_warnings(timestamp)

    if not (ip and method and url):
        parser_warnings.append("partial_error_request_extraction")

    return {
        "timestamp": timestamp,
        "ip": ip,
        "method": method,
        "url": url,
        "status": None,
        "user_agent": None,
        "error_message": message,
        "log_type": "error",
        "level": match.group("level"),
        "parser_warnings": parser_warnings,
    }

def parse_common_access_log_line(line: str):
    match = COMMON_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp = parse_timestamp(match.group("timestamp"))

    return {
        "timestamp": timestamp,
        "ip": match.group("ip"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status")),
        "user_agent": None,
        "error_message": None,
        "log_type": "access",
        "level": None,
        "parser_warnings": get_timestamp_warnings(timestamp),
    }

def parse_combined_access_log_line(line: str):
    match = COMBINED_LOG_PATTERN.match(line.strip())

    if not match:
        return None

    timestamp = parse_timestamp(match.group("timestamp"))

    return {
        "timestamp": timestamp,
        "ip": match.group("ip"),
        "method": match.group("method"),
        "url": match.group("url"),
        "status": int(match.group("status")),
        "user_agent": match.group("user_agent"),
        "error_message": None,
        "log_type": "access",
        "level": None,
        "parser_warnings": get_timestamp_warnings(timestamp),
    }

def detect_log_format(line: str) -> str:
    line = line.strip()

    if not line or line.startswith("#"):
        return "ignore"
    
    if COMBINED_LOG_PATTERN.match(line):
        return "combined_access"
    
    if COMMON_LOG_PATTERN.match(line):
        return "common_access"
    
    if ERROR_LOG_PATTERN.match(line):
        return "error_log"


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

    parser_warnings = get_timestamp_warnings(parts[0])

    if not parts[4].isdigit():
        parser_warnings.append("malformed_status")

    return {
        "timestamp": parts[0],
        "ip": parts[1],
        "method": parts[2],
        "url": parts[3],
        "status": int(parts[4]) if parts[4].isdigit() else None,
        "user_agent": None,
        "error_message": None,
        "log_type": "access",
        "level": None,
        "parser_warnings": parser_warnings,
    }

def parse_log_lines(lines):
    records = []
    skipped = []

    for line_number, line in enumerate(lines, start=1):
        fmt = detect_log_format(line)

        if fmt == "ignore":
            result = {
                "line_number": line_number,
                "parse_status": "ignored",
                "parser_warnings": [],
            }
        elif fmt == "unknown":
            result = {
                "line_number": line_number,
                "parse_status": "failed",
                "parser_warnings": [],
            }
        elif fmt == "simple_access":
            result = parse_access_log_line(line)
        elif fmt == "common_access":
            result = parse_common_access_log_line(line)
        elif fmt == "combined_access":
            result = parse_combined_access_log_line(line)
        elif fmt == "error_log":
            result = parse_error_log_line(line)
        else:
            result = None

        if result:
            result.setdefault("line_number", line_number)
            result.setdefault("parse_status", "parsed")
            result.setdefault("parser_warnings", [])
            records.append(result)
        else:
            result = {
                "line_number": line_number,
                "parse_status": "failed",
                "parser_warnings": [],
            }
            records.append(result)
            skipped.append(result)

    return records, skipped
