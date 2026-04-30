import pandas as pd


def create_time_series(df: pd.DataFrame, interval: str = "5min") -> pd.DataFrame:
    """
    Create time-series aggregated security log data.

    Parameters:
        df: log dataframe
        interval: aggregation interval, e.g. "1min", "5min", "1h"

    Returns:
        aggregated dataframe by time bucket and IP
    """

    if df.empty:
        return pd.DataFrame()

    df = df.copy()

    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df = df.dropna(subset=["timestamp"])

    df["time_bucket"] = df["timestamp"].dt.floor(interval)

    grouped = (
        df.groupby(["time_bucket", "ip"])
        .agg(
            access_count=("ip", "count"),
            failed_count=("status", lambda x: x.isin([401, 403, 404]).sum()),
            auth_failed_count=("status", lambda x: x.isin([401, 403]).sum()),
            not_found_count=("status", lambda x: (x == 404).sum()),
            admin_access_count=("url", lambda x: x.astype(str).str.contains("admin", case=False, na=False).sum()),
            suspicious_path_count=("url", lambda x: x.astype(str).str.contains(
                "wp-admin|phpmyadmin|\\.env|config|backup",
                case=False,
                na=False,
                regex=True
            ).sum()),
        )
        .reset_index()
    )

    grouped["risk_signal_count"] = (
        grouped["failed_count"]
        + grouped["admin_access_count"]
        + grouped["suspicious_path_count"]
    )

    grouped["failure_rate"] = (
        grouped["failed_count"] / grouped["access_count"]
    ).fillna(0)

    grouped["is_anomaly"] = (
        (grouped["failure_rate"] > 0.5) |
        (grouped["risk_signal_count"] >= 3)
    )

    def get_anomaly_reason(row):
        reasons = []

        if row["failure_rate"] > 0.5:
            rate_percent = int(row["failure_rate"] * 100)
            reasons.append(f"High failure rate ({rate_percent}%)")

        if row["risk_signal_count"] >= 3:
            reasons.append("Multiple suspicious activities detected")

        return " / ".join(reasons)

    grouped["anomaly_reason"] = grouped.apply(get_anomaly_reason, axis=1)


    return grouped


#For Debug
if __name__ == "__main__":
    sample_data = [
        {"timestamp": "2026-04-27 00:01:00", "ip": "10.0.0.5", "url": "/admin", "status": 401},
        {"timestamp": "2026-04-27 00:02:00", "ip": "10.0.0.5", "url": "/admin", "status": 401},
        {"timestamp": "2026-04-27 00:03:00", "ip": "10.0.0.5", "url": "/wp-admin", "status": 404},
        {"timestamp": "2026-04-27 00:07:00", "ip": "192.168.1.3", "url": "/login", "status": 403},
    ]

    df = pd.DataFrame(sample_data)
    result = create_time_series(df, interval="5min")
    print(result.to_string(index=False))
