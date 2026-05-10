from datetime import datetime

from data_layer.database import get_raw_logs_by_run


def get_ip_events(run_id: int):
    rows = get_raw_logs_by_run(run_id)
    events_by_ip = {}

    for row in rows:
        try:
            timestamp = datetime.fromisoformat(row["timestamp"])
            if timestamp.tzinfo is not None:
                timestamp = timestamp.replace(tzinfo=None)
        except Exception:
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
