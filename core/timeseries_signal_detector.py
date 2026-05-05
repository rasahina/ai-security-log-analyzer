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
    findings = detect_timeseries_signal_findings(events, rules)
    return {finding["name"] for finding in findings}

def detect_timeseries_signal_findings(events, rules):
    findings = []

    signal_rules = rules.get("signals", {})
    paths = rules.get("paths", {})

    for signal_name, config in signal_rules.items():
        if not config.get("enabled", True):
            continue

        signal_type = config.get("type", "count")

        if signal_type == "ratio":
            findings.extend(
                _find_ratio_signal_windows(signal_name, events, config, paths)
            )
        else:
            findings.extend(
                _find_count_signal_windows(signal_name, events, config, paths)
            )

    return findings


def _find_count_signal_windows(signal_name, events, config, paths):
    filter_config = config.get("filter")

    if filter_config is None:
        return []

    filtered = _filter_events(events, filter_config, paths)
    filtered = sorted(
        [e for e in filtered if e.get("timestamp") is not None],
        key=lambda e: e["timestamp"],
    )

    window_seconds = config.get("window_seconds", 300)
    threshold = config.get("threshold", 5)
    window = timedelta(seconds=window_seconds)

    findings = []
    left = 0

    for right in range(len(filtered)):
        while filtered[right]["timestamp"] - filtered[left]["timestamp"] > window:
            left += 1

        window_events = filtered[left:right + 1]

        if len(window_events) >= threshold:
            findings.append(
                _build_count_finding(
                    signal_name=signal_name,
                    window_events=window_events,
                    threshold=threshold,
                    window_seconds=window_seconds,
                )
            )
            left = right + 1  # ←ここが重要
    return findings

# def _build_count_finding(signal_name, window_events, threshold):
#     paths = [
#         e.get("url")
#         for e in window_events
#         if e.get("url")
#     ]

#     statuses = [
#         e.get("status")
#         for e in window_events
#         if e.get("status") is not None
#     ]

#     return {
#         "name": signal_name,
#         "window_start": window_events[0]["timestamp"],
#         "window_end": window_events[-1]["timestamp"],
#         "value": len(window_events),
#         "threshold": threshold,
#         "details": {
#             "sample_paths": list(dict.fromkeys(paths))[:5],
#             "unique_path_count": len(set(paths)),
#             "status_counts": {
#                 status: statuses.count(status)
#                 for status in sorted(set(statuses))
#             },
#         },
#     }

def _build_count_finding(signal_name, window_events, threshold, window_seconds):
    paths = [
        e.get("url")
        for e in window_events
        if e.get("url")
    ]

    statuses = [
        e.get("status")
        for e in window_events
        if e.get("status") is not None
    ]

    value = len(window_events)
    matched_start = window_events[0]["timestamp"]
    matched_end = window_events[-1]["timestamp"]

    return {
        "name": signal_name,

        # 新ライン用
        "matched_start": matched_start,
        "matched_end": matched_end,
        "frequency": value / window_seconds,

        # 旧互換
        "window_start": matched_start,
        "window_end": matched_end,

        "value": value,
        "threshold": threshold,
        "details": {
            "metric_type": "count",
            "sample_paths": list(dict.fromkeys(paths))[:5],
            "unique_path_count": len(set(paths)),
            "status_counts": {
                status: statuses.count(status)
                for status in sorted(set(statuses))
            },
        },
    }

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


def _find_ratio_signal_windows(signal_name, events, config, paths):
    numerator_filter = config.get("numerator_filter")
    denominator_filter = config.get("denominator_filter")

    if numerator_filter is None or denominator_filter is None:
        return []

    filtered = _filter_events(events, denominator_filter, paths)

    filtered = sorted(
        [e for e in filtered if e.get("timestamp") is not None],
        key=lambda e: e["timestamp"],
    )

    window_seconds = config.get("window_seconds", 300)
    minimum_count = config.get("minimum_count", 5)
    threshold = config.get("threshold", 0.5)

    window = timedelta(seconds=window_seconds)

    findings = []
    left = 0

    for right in range(len(filtered)):
        while filtered[right]["timestamp"] - filtered[left]["timestamp"] > window:
            left += 1

        window_events = filtered[left:right + 1]
        total = len(window_events)

        if total < minimum_count:
            continue

        numerator_events = _filter_events(
            window_events,
            numerator_filter,
            paths,
        )

        numerator_count = len(numerator_events)
        ratio = numerator_count / total

        if ratio >= threshold:
            matched_start = window_events[0]["timestamp"]
            matched_end = window_events[-1]["timestamp"]

            findings.append({
                "name": signal_name,

                # 新ライン用
                "matched_start": matched_start,
                "matched_end": matched_end,
                "frequency": ratio,

                # 旧互換
                "window_start": matched_start,
                "window_end": matched_end,

                "value": ratio,
                "threshold": threshold,
                "details": {
                    "metric_type": "ratio",
                    "numerator_count": numerator_count,
                    "denominator_count": total,
                },
            })

            left = right + 1

    return findings
# def _find_ratio_signal_windows(signal_name, events, config, paths):
#     numerator_filter = config.get("numerator_filter")
#     denominator_filter = config.get("denominator_filter")

#     if numerator_filter is None or denominator_filter is None:
#         return []

#     # denominatorでフィルタ
#     filtered = _filter_events(events, denominator_filter, paths)

#     filtered = sorted(
#         [e for e in filtered if e.get("timestamp") is not None],
#         key=lambda e: e["timestamp"],
#     )

#     window_seconds = config.get("window_seconds", 300)
#     minimum_count = config.get("minimum_count", 5)
#     threshold = config.get("threshold", 0.5)

#     window = timedelta(seconds=window_seconds)

#     findings = []
#     left = 0

#     for right in range(len(filtered)):
#         while filtered[right]["timestamp"] - filtered[left]["timestamp"] > window:
#             left += 1

#         window_events = filtered[left:right + 1]
#         total = len(window_events)

#         if total < minimum_count:
#             continue

#         numerator_events = _filter_events(
#             window_events,
#             numerator_filter,
#             paths,
#         )

#         numerator_count = len(numerator_events)
#         ratio = numerator_count / total

#         if ratio >= threshold:
#             findings.append({
#                 "name": signal_name,
#                 "window_start": window_events[0]["timestamp"],
#                 "window_end": window_events[-1]["timestamp"],
#                 "value": ratio,
#                 "threshold": threshold,
#                 "details": {
#                     "numerator_count": numerator_count,
#                     "denominator_count": total,
#                 },
#             })
#             left = right + 1

#     return findings