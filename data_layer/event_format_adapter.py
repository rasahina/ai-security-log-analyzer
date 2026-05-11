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


def build_canonical_runtime_event(row: dict) -> dict | None:
    try:
        timestamp = _parse_runtime_timestamp(row["timestamp"])
    except Exception:
        return None

    if timestamp is None:
        return None

    if not row.get("ip") or not row.get("log_type"):
        return None

    event = {
        "timestamp": timestamp,
        "ip": row["ip"],
        "log_type": row["log_type"],
    }

    optional_fields = (
        "method",
        "url",
        "status",
        "error_message",
        "user_agent",
        "line_number",
        "parser_warnings",
    )

    for field in optional_fields:
        if field in row:
            event[field] = row[field]

    return event


def get_ip_events(run_id: int):
    rows = get_raw_logs_by_run(run_id)
    events_by_ip = {}

    for row in rows:
        eligibility = get_runtime_eligibility(row)
        if not eligibility["is_runtime_eligible"]:
            continue

        event = build_canonical_runtime_event(row)
        if event is None:
            continue

        ip = event["ip"]

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append(event)

    return events_by_ip
