def resolve_signal_clusters(clusters_by_ip: dict, rules: dict) -> dict:
    resolved_by_ip = {}

    attack_source_clusters = _get_attack_source_clusters(rules)

    for ip, clusters in clusters_by_ip.items():
        resolved_clusters = []

        for cluster in clusters:
            cluster_name = cluster.get("cluster_name")

            if cluster_name in attack_source_clusters:
                resolved_clusters.append({
                    **cluster,
                    "relation": "primary",
                    "absorbed_by": None,
                    "absorbed_clusters": [],
                })
                continue

            absorber = _find_absorbing_cluster(
                cluster=cluster,
                clusters=clusters,
                attack_source_clusters=attack_source_clusters,
            )

            if absorber:
                resolved_clusters.append({
                    **cluster,
                    "relation": "absorbed",
                    "absorbed_by": absorber.get("cluster_name"),
                    "absorbed_clusters": [],
                })
            else:
                absorbed_clusters = _find_absorbed_suspicious_activity_clusters(
                    cluster=cluster,
                    clusters=clusters,
                    attack_source_clusters=attack_source_clusters,
                )

                resolved_clusters.append(
                    _build_suspicious_activity_candidate_cluster(
                        cluster=cluster,
                        absorbed_clusters=absorbed_clusters,
                        rules=rules,
                    )
                )

        resolved_by_ip[ip] = resolved_clusters

    return resolved_by_ip


def _get_attack_source_clusters(rules: dict) -> set:
    source_clusters = set()

    for _, config in rules.get("attacks", {}).items():
        if not config.get("enabled", True):
            continue

        if config.get("fallback"):
            continue

        source_cluster = config.get("source_cluster")
        if source_cluster:
            source_clusters.add(source_cluster)

    return source_clusters


def _get_suspicious_activity_relation_config(rules: dict) -> dict:
    return (
        rules.get("cluster_relation", {})
        .get("suspicious_activity", {})
    )


def _find_absorbing_cluster(
    cluster: dict,
    clusters: list[dict],
    attack_source_clusters: set,
):
    for candidate in clusters:
        if candidate is cluster:
            continue

        if not _clusters_overlap(cluster, candidate):
            continue

        if candidate.get("cluster_name") in attack_source_clusters:
            return candidate

        if _is_stronger_suspicious_activity_candidate(candidate, cluster):
            return candidate

    return None


def _find_absorbed_suspicious_activity_clusters(
    cluster: dict,
    clusters: list[dict],
    attack_source_clusters: set,
) -> list[dict]:
    absorbed = []

    for candidate in clusters:
        if candidate is cluster:
            continue

        if candidate.get("cluster_name") in attack_source_clusters:
            continue

        if not _clusters_overlap(cluster, candidate):
            continue

        if _is_stronger_suspicious_activity_candidate(cluster, candidate):
            absorbed.append({
                "cluster_name": candidate.get("cluster_name"),
                "intensity": candidate.get("intensity", 0),
                "confidence": candidate.get("confidence", 0),
                "attack_start": candidate.get("attack_start"),
                "attack_end": candidate.get("attack_end"),
                "evidence_signals": candidate.get("evidence_signals", []),
            })

    return absorbed


def _build_suspicious_activity_candidate_cluster(
    cluster: dict,
    absorbed_clusters: list[dict],
    rules: dict,
) -> dict:
    adjusted_confidence = _adjust_suspicious_activity_confidence(
        base_confidence=cluster.get("confidence", 0),
        absorbed_count=len(absorbed_clusters),
        rules=rules,
    )

    return {
        **cluster,
        "relation": "fallback_candidate",
        "absorbed_by": None,
        "absorbed_clusters": absorbed_clusters,
        "confidence": adjusted_confidence,
    }


def _adjust_suspicious_activity_confidence(
    base_confidence: float,
    absorbed_count: int,
    rules: dict,
) -> float:
    config = _get_suspicious_activity_relation_config(rules)
    lift = config.get("absorb_lift", 0.15)

    confidence = base_confidence

    for _ in range(absorbed_count):
        confidence = confidence + (1 - confidence) * lift

    return min(confidence, 1.0)


def _is_stronger_suspicious_activity_candidate(candidate: dict, cluster: dict) -> bool:
    candidate_confidence = candidate.get("confidence", 0)
    cluster_confidence = cluster.get("confidence", 0)

    if candidate_confidence > cluster_confidence:
        return True

    if candidate_confidence < cluster_confidence:
        return False

    return candidate.get("intensity", 0) >= cluster.get("intensity", 0)


def _clusters_overlap(a: dict, b: dict) -> bool:
    a_start = a.get("attack_start")
    a_end = a.get("attack_end")
    b_start = b.get("attack_start")
    b_end = b.get("attack_end")

    if None in (a_start, a_end, b_start, b_end):
        return False

    return a_start <= b_end and b_start <= a_end