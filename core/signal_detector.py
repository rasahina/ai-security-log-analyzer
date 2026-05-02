# core/signal_detector.py

def detect_signals(stat, timestamps, rules):
    """
    Detect factual signals from IP-level stats and timestamps.

    This layer must only detect observable facts.
    It must not decide attack types.
    """
    signals = set()

    signal_rules = rules.get("signals", {})
    paths = rules.get("paths", {})

    for signal_name, config in signal_rules.items():
        if _match_signal(signal_name, config, stat, timestamps, paths):
            signals.add(signal_name)

    return signals


def _match_signal(signal_name, config, stat, timestamps, paths):
    if signal_name == "repeated_login":
        threshold = config.get("threshold", config.get("min_failed_count", 0))
        return stat.get("login_access_count", stat.get("failed_count", 0)) >= threshold

    if signal_name == "failed_login_count":
        threshold = config.get("threshold", config.get("min_failed_count", 0))
        return stat.get("failed_login_count", stat.get("failed_count", 0)) >= threshold

    if signal_name == "high_failure_rate":
        access_count = stat.get("access_count", 0)
        failure_rate = stat.get("failure_rate", 0)

        minimum_count = config.get("minimum_count", config.get("min_access_count", 0))
        threshold = config.get("threshold", config.get("failure_rate", 0))

        return access_count >= minimum_count and failure_rate >= threshold

    if signal_name == "login_success_after_failures":
        threshold = config.get("threshold", 0)
        return stat.get("login_success_after_failures_count", 0) >= threshold

    if signal_name == "multiple_suspicious_paths":
        threshold = config.get("threshold", config.get("min_count", 0))
        return stat.get("suspicious_path_count", 0) >= threshold

    if signal_name == "many_404":
        threshold = config.get("threshold", config.get("min_count", 0))
        return stat.get("not_found_count", 0) >= threshold

    if signal_name == "admin_access":
        threshold = config.get("threshold", config.get("min_count", 1))
        return stat.get("admin_path_count", 0) >= threshold

    if signal_name == "burst_access":
        seconds = config.get("window_seconds", config.get("seconds", 60))
        threshold = config.get("threshold", 5)

        return _detect_burst_access(
            timestamps,
            seconds=seconds,
            threshold=threshold,
        )

    if signal_name == "night_access":
        start_hour = config.get("start_hour", 0)
        end_hour = config.get("end_hour", 5)

        return _detect_night_access(
            timestamps,
            start_hour=start_hour,
            end_hour=end_hour,
        )

    if signal_name == "access_error_correlation":
        threshold = config.get(
            "error_threshold",
            config.get("threshold", config.get("min_count", 1)),
        )

        return stat.get("access_error_correlation_count", 0) >= threshold

    return False


def _detect_burst_access(timestamps, seconds, threshold):
    timestamps = sorted(timestamps)

    left = 0

    for right in range(len(timestamps)):
        while (timestamps[right] - timestamps[left]).total_seconds() > seconds:
            left += 1

        if right - left + 1 >= threshold:
            return True

    return False


def _detect_night_access(timestamps, start_hour, end_hour):
    return any(start_hour <= t.hour < end_hour for t in timestamps)