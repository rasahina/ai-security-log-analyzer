from datetime import timedelta


def _is_signal_enabled(signal_rules, signal_name):
    return signal_rules.get(signal_name, {}).get("enabled", True)

def _filter_events(events, filter_config, paths):
    if not filter_config:
        return events

    def match(event):
        # any
        if filter_config.get("any"):
            return True

        # status
        if "status" in filter_config:
            if event.get("status") != filter_config["status"]:
                return False

        # status_in
        if "status_in" in filter_config:
            if event.get("status") not in filter_config["status_in"]:
                return False

        # path_group
        if "path_group" in filter_config:
            group = filter_config["path_group"]
            allowed_paths = set(paths.get(group, []))
            if event.get("url") not in allowed_paths:
                return False

        return True

    return [e for e in events if match(e)]

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
        "burst_access": lambda: _match_count_signal(
            events,
            signal_rules["burst_access"],
            paths,
        ),
        "many_404": lambda: _match_count_signal(
            events,
            signal_rules["many_404"],
            paths,
        ),
        "failed_login_count": lambda: _match_count_signal(
            events,
            signal_rules["failed_login_count"],
            paths,
        ),
        "admin_access": lambda: _match_count_signal(
            events,
            signal_rules["admin_access"],
            paths,
        ),
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


def _match_many_404(events, signal_rules, paths):
    config = signal_rules.get("many_404", {})

    # 👇 filterがあれば使う
    if "filter" in config:
        filtered = _filter_events(events, config["filter"], paths)
        timestamps = _extract_timestamps(filtered)
    else:
        # 👇 旧ロジック（互換性維持）
        timestamps = _extract_timestamps(
            events,
            lambda e: e.get("status") == 404
        )

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 300),
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

def _match_failed_login(events, signal_rules, paths):
    config = signal_rules.get("failed_login_count", {})

    if "filter" in config:
        filtered = _filter_events(events, config["filter"], paths)
        timestamps = _extract_timestamps(filtered)
    else:
        timestamps = _extract_timestamps(
            events,
            lambda e: e.get("status") in (401, 403)
        )

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 300),
        threshold=config.get("threshold", 5),
    )

def _match_admin_access(events, signal_rules, paths):
    config = signal_rules.get("admin_access", {})

    if "filter" in config:
        filtered = _filter_events(events, config["filter"], paths)
        timestamps = _extract_timestamps(filtered)
    else:
        admin_paths = set(paths.get("admin", []))
        timestamps = _extract_timestamps(
            events,
            lambda e: e.get("url") in admin_paths
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

def _match_count_signal(events, config, paths):
    filtered = _filter_events(
        events,
        config.get("filter", {}),
        paths,
    )

    timestamps = _extract_timestamps(filtered)

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 300),
        threshold=config.get("threshold", 5),
    )