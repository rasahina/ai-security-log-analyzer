from datetime import datetime, timedelta


def correlate_logs(parsed_logs, time_window_seconds=60):
    correlations = []

    # access と error 分離
    access_logs = [l for l in parsed_logs if l.get("log_type") == "access"]
    error_logs = [l for l in parsed_logs if l.get("log_type") == "error"]

    for a in access_logs:
        if not a.get("ip") or not a.get("url"):
            continue

        a_time = datetime.fromisoformat(a["timestamp"])

        for e in error_logs:
            if e.get("ip") != a["ip"]:
                continue

            if e.get("url") != a["url"]:
                continue

            e_time = datetime.fromisoformat(e["timestamp"])

            if abs((e_time - a_time).total_seconds()) <= time_window_seconds:
                correlations.append({
                    "ip": a["ip"],
                    "url": a["url"],
                    "access_time": a_time,
                    "error_time": e_time,
                    "error_message": e.get("error_message"),
                })

    return correlations