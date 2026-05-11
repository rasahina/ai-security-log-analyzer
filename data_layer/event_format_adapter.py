from datetime import datetime, timezone

from data_layer.database import get_raw_logs_by_run


def _parse_runtime_timestamp(value: str):
    timestamp = datetime.fromisoformat(value)

    if timestamp.tzinfo is None:
        return None

    return timestamp.astimezone(timezone.utc)


def get_runtime_eligibility(row: dict) -> dict:
    if row.get("parse_status") != "parsed":
        return {
            "is_runtime_eligible": False,
            "runtime_exclusion_reason": "parse_status_not_parsed",
        }

    if not row.get("timestamp"):
        return {
            "is_runtime_eligible": False,
            "runtime_exclusion_reason": "timestamp_missing",
        }

    try:
        timestamp = _parse_runtime_timestamp(row["timestamp"])
    except Exception:
        return {
            "is_runtime_eligible": False,
            "runtime_exclusion_reason": "timestamp_malformed",
        }

    if timestamp is None:
        return {
            "is_runtime_eligible": False,
            "runtime_exclusion_reason": "timezone_missing",
        }

    if not row.get("ip"):
        return {
            "is_runtime_eligible": False,
            "runtime_exclusion_reason": "source_ip_missing",
        }

    return {
        "is_runtime_eligible": True,
        "runtime_exclusion_reason": None,
    }


def get_ip_events(run_id: int):
    rows = get_raw_logs_by_run(run_id)
    events_by_ip = {}

    for row in rows:
        eligibility = get_runtime_eligibility(row)
        if not eligibility["is_runtime_eligible"]:
            continue

        timestamp = _parse_runtime_timestamp(row["timestamp"])
        ip = row["ip"]

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append({
            "timestamp": timestamp,
            "method": row["method"],
            "url": row["url"],
            "status": row["status"],
            "log_type": row["log_type"],
            "line_number": row["line_number"],
            "parser_warnings": row.get("parser_warnings", []),
            "error_message": row["error_message"],
        })

    return events_by_ip
