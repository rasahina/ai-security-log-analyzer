import itertools


def build_signal_clusters(signal_findings_by_ip: dict, rules: dict) -> dict:
    clusters_by_ip = {}
    cluster_rules = rules.get("signal_clusters", {})

    for ip, findings in signal_findings_by_ip.items():
        clusters = []

        for cluster_name, config in cluster_rules.items():
            if not config.get("enabled", True):
                continue

            required = config.get("required", [])
            optional = config.get("optional", [])

            matched_required_sets = _find_required_signal_sets(
                findings=findings,
                required=required,
                tolerance_seconds=config.get("tolerance_seconds", 300),
            )

            for matched_required in matched_required_sets:
                optional_matches = _find_optional_signals(
                    findings=findings,
                    optional=optional,
                    required_signals=matched_required,
                    tolerance_seconds=config.get("tolerance_seconds", 300),
                )

                cluster = _build_cluster(
                    ip=ip,
                    cluster_name=cluster_name,
                    matched_signals=matched_required,
                    optional_signals=optional_matches,
                    config=config,
                )

                clusters.append(cluster)

        clusters_by_ip[ip] = clusters

    return clusters_by_ip


def _find_required_signal_sets(findings, required, tolerance_seconds):
    candidate_lists = []

    for signal_name in required:
        candidates = [
            f for f in findings
            if f["name"] == signal_name
        ]

        if not candidates:
            return []

        candidate_lists.append(candidates)

    matched_sets = []

    for combination in itertools.product(*candidate_lists):
        if _all_time_related(combination, tolerance_seconds):
            matched_sets.append(list(combination))

    return matched_sets


def _find_optional_signals(findings, optional, required_signals, tolerance_seconds):
    matched = []

    for signal_name in optional:
        candidates = [
            f for f in findings if f["name"] == signal_name
        ]

        for c in candidates:
            if all(
                _time_distance(c, r) <= tolerance_seconds
                for r in required_signals
            ):
                matched.append(c)
                break  # 1つあればOK

    return matched


def _all_time_related(signals, tolerance_seconds):
    for i in range(len(signals)):
        for j in range(i + 1, len(signals)):
            if _time_distance(signals[i], signals[j]) > tolerance_seconds:
                return False

    return True


def _time_distance(a, b):
    a_start = a["matched_start"]
    a_end = a["matched_end"]
    b_start = b["matched_start"]
    b_end = b["matched_end"]

    if a_start <= b_end and b_start <= a_end:
        return 0

    return min(
        abs((a_start - b_end).total_seconds()),
        abs((b_start - a_end).total_seconds()),
    )


def _build_cluster(ip, cluster_name, matched_signals, optional_signals, config):
    intensity_scale = config.get("intensity_scale", 1.0)
    base_confidence = config.get("base_confidence", 0.5)
    default_lift = config.get("default_optional_lift", 0.2)

    all_signals = matched_signals + optional_signals

    intensities = [
        s["frequency"] / intensity_scale
        for s in all_signals
        if s.get("details", {}).get("metric_type") == "count"
    ]

    intensity = max(intensities) if intensities else 0

    confidence = base_confidence

    for _ in optional_signals:
        confidence = confidence + (1 - confidence) * default_lift

    attack_start = min(s["matched_start"] for s in all_signals)
    attack_end = max(s["matched_end"] for s in all_signals)

    return {
        "source_ip": ip,
        "cluster_name": cluster_name,
        "intensity": intensity,
        "confidence": confidence,
        "attack_start": attack_start,
        "attack_end": attack_end,
        "evidence_signals": [
            {
                "signal_name": s["name"],
                "matched_start": s["matched_start"],
                "matched_end": s["matched_end"],
                "value": s["value"],
                "frequency": s["frequency"],
            }
            for s in all_signals
        ],
    }