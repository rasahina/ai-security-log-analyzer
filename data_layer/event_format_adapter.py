from datetime import datetime, timezone

from data_layer.database import get_raw_logs_by_run


def _parse_runtime_timestamp(value: str):
    timestamp = datetime.fromisoformat(value)

    if timestamp.tzinfo is None:
        return None

    return timestamp.astimezone(timezone.utc)


def get_ip_events(run_id: int):
    rows = get_raw_logs_by_run(run_id)
    events_by_ip = {}

    for row in rows:
        try:
            timestamp = _parse_runtime_timestamp(row["timestamp"])
        except Exception:
            continue

        if timestamp is None:
            continue

        ip = row["ip"]

        if ip not in events_by_ip:
            events_by_ip[ip] = []

        events_by_ip[ip].append({
            "timestamp": timestamp,
            "method": row["method"],
            "url": row["url"],
            "status": row["status"],
            "log_type": row["log_type"],
            "error_message": row["error_message"],
        })

    return events_by_ip
