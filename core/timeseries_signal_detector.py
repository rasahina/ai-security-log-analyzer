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
    signals = set()

    signal_rules = rules.get("signals", {})
    paths = rules.get("paths", {})

    for signal_name, config in signal_rules.items():
        if not config.get("enabled", True):
            continue

        signal_type = config.get("type", "count")

        if signal_type == "ratio":
            matched = _match_ratio_signal(events, config, paths)
        else:
            matched = _match_count_signal(events, config, paths)

        if matched:
            signals.add(signal_name)

    return signals

# def detect_timeseries_signals(events, rules):
#     """
#     Detect factual signals from raw time-series log events.

#     This layer must only detect observable facts.
#     It must not decide attack types.
#     """
#     signals = set()

#     signal_rules = rules.get("signals", {})
#     paths = rules.get("paths", {})

#     detectors = {
#         "burst_access": lambda: _match_count_signal(
#             events, signal_rules.get("burst_access", {}), paths
#         ),
#         "many_404": lambda: _match_count_signal(
#             events, signal_rules.get("many_404", {}), paths
#         ),
#         "failed_login_count": lambda: _match_count_signal(
#             events, signal_rules.get("failed_login_count", {}), paths
#         ),
#         "admin_access": lambda: _match_count_signal(
#             events, signal_rules.get("admin_access", {}), paths
#         ),
#         "high_failure_rate": lambda: _match_high_failure_rate(events, signal_rules),
#     }

#     for signal_name, detector in detectors.items():
#         if not _is_signal_enabled(signal_rules, signal_name):
#             continue

#         if detector():
#             signals.add(signal_name)

#     return signals





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



def _match_count_signal(events, config, paths):
    filter_config = config.get("filter")

    if filter_config is None:
        return False

    filtered = _filter_events(
        events,
        filter_config,
        paths,
    )

    timestamps = _extract_timestamps(filtered)

    return _detect_event_burst(
        timestamps=timestamps,
        window_seconds=config.get("window_seconds", 300),
        threshold=config.get("threshold", 5),
    )


def _detect_ratio_in_window(
    events,
    numerator_filter,
    paths,
    window_seconds,
    minimum_count,
    threshold,
):
    if not events:
        return False

    events = sorted(
        [e for e in events if e.get("timestamp") is not None],
        key=lambda e: e["timestamp"],
    )

    left = 0
    window = timedelta(seconds=window_seconds)

    for right in range(len(events)):
        while events[right]["timestamp"] - events[left]["timestamp"] > window:
            left += 1

        window_events = events[left:right + 1]
        total = len(window_events)

        if total < minimum_count:
            continue

        numerator_events = _filter_events(
            window_events,
            numerator_filter,
            paths,
        )

        ratio = len(numerator_events) / total

        if ratio >= threshold:
            return True

    return False


def _match_ratio_signal(events, config, paths):
    numerator_filter = config.get("numerator_filter")
    denominator_filter = config.get("denominator_filter")

    if numerator_filter is None or denominator_filter is None:
        return False

    denominator_events = _filter_events(events, denominator_filter, paths)

    return _detect_ratio_in_window(
        events=denominator_events,
        numerator_filter=numerator_filter,
        paths=paths,
        window_seconds=config.get("window_seconds", 300),
        minimum_count=config.get("minimum_count", 5),
        threshold=config.get("threshold", 0.5),
    )

