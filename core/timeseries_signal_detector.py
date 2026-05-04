from datetime import timedelta


def detect_timeseries_signals(events, rules):
    paths = rules.get("paths", {})
    signals = set()
    signal_rules = rules.get("signals", {})

    if _is_signal_enabled(signal_rules, "burst_access"):
        if _match_burst_access(events, signal_rules):
            signals.add("burst_access")

    if _is_signal_enabled(signal_rules, "many_404"):
        if _match_many_404(events, signal_rules):
            signals.add("many_404")

    if _is_signal_enabled(signal_rules, "failed_login_count"):
        if _match_failed_login(events, signal_rules):
            signals.add("failed_login_count")

    if _is_signal_enabled(signal_rules, "admin_access"):
        if _match_admin_access(events, signal_rules, paths):
            signals.add("admin_access")

    return signals


def _match_burst_access(events, signal_rules):
    config = signal_rules.get("burst_access", {})

    timestamps = _extract_timestamps(events)

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", config.get("seconds", 60)),
        threshold=config.get("threshold", 5),
    )


def _match_many_404(events, signal_rules):
    config = signal_rules.get("many_404", {})

    timestamps = _extract_timestamps(
        events,
        lambda event: event.get("status") == 404,
    )

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 60),
        threshold=config.get("threshold", 5),
    )


def _extract_timestamps(events, condition=None):
    timestamps = []

    for event in events:
        if event.get("timestamp") is None:
            continue

        if condition is not None and not condition(event):
            continue

        timestamps.append(event["timestamp"])

    return sorted(timestamps)


def _detect_event_burst(timestamps, window_seconds, threshold):
    if not timestamps:
        return False

    left = 0
    window = timedelta(seconds=window_seconds)

    for right in range(len(timestamps)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        if right - left + 1 >= threshold:
            return True

    return False

def _match_failed_login(events, signal_rules):
    config = signal_rules.get("failed_login_count", {})

    timestamps = _extract_timestamps(
        events,
        lambda event: event.get("status") in (401, 403),
    )

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 60),
        threshold=config.get("threshold", 5),
    )

def _match_admin_access(events, signal_rules, paths):
    config = signal_rules.get("admin_access", {})

    admin_paths = set(paths.get("admin", []))

    timestamps = _extract_timestamps(
        events,
        lambda event: event.get("url") in admin_paths,
    )

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 300),
        threshold=config.get("threshold", 1),
    )


def _is_signal_enabled(signal_rules, signal_name):
    return signal_rules.get(signal_name, {}).get("enabled", True)