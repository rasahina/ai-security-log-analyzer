from datetime import timedelta


def _is_signal_enabled(signal_rules, signal_name):
    return signal_rules.get(signal_name, {}).get("enabled", True)


def detect_timeseries_signals(events, rules):
    """
    Detect factual signals from raw time-series log events.

    This layer must only detect observable facts.
    It must not decide attack types.
    """
    signals = set()

    signal_rules = rules.get("signals", {})
    paths = rules.get("paths", {})

    detectors = {
        "burst_access": lambda: _match_burst_access(events, signal_rules),
        "many_404": lambda: _match_many_404(events, signal_rules),
        "failed_login_count": lambda: _match_failed_login(events, signal_rules),
        "admin_access": lambda: _match_admin_access(events, signal_rules, paths),
        "high_failure_rate": lambda: _match_high_failure_rate(events, signal_rules),
    }

    for signal_name, detector in detectors.items():
        if not _is_signal_enabled(signal_rules, signal_name):
            continue

        if detector():
            signals.add(signal_name)

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

def _match_high_failure_rate(events, signal_rules):
    config = signal_rules.get("high_failure_rate", {})

    window_seconds = config.get("window_seconds", 300)
    threshold = config.get("threshold", 0.5)
    minimum_count = config.get("minimum_count", 5)

    from datetime import timedelta

    timestamps = sorted(
        event["timestamp"]
        for event in events
        if event.get("timestamp") is not None
    )

    if not timestamps:
        return False

    left = 0
    window = timedelta(seconds=window_seconds)

    for right in range(len(events)):
        while timestamps[right] - timestamps[left] > window:
            left += 1

        window_events = events[left:right+1]

        total = len(window_events)
        if total < minimum_count:
            continue

        failed = sum(
            1 for e in window_events
            if e.get("status") in (401, 403)
        )

        if failed / total >= threshold:
            return True

    return False

