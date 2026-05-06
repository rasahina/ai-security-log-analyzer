def resolve_signal_clusters(clusters_by_ip: dict, rules: dict) -> dict:
    resolved_by_ip = {}

    attack_source_clusters = _get_attack_source_clusters(rules)

    for ip, clusters in clusters_by_ip.items():
        primary_clusters = [
            cluster
            for cluster in clusters
            if cluster.get("cluster_name") in attack_source_clusters
        ]

        resolved_clusters = []

        for cluster in clusters:
            cluster_name = cluster.get("cluster_name")

            if cluster_name in attack_source_clusters:
                resolved_clusters.append({
                    **cluster,
                    "relation": "primary",
                    "absorbed_by": None,
                })
                continue

            absorber = _find_absorbing_cluster(
                cluster=cluster,
                primary_clusters=primary_clusters,
            )

            if absorber:
                resolved_clusters.append({
                    **cluster,
                    "relation": "absorbed",
                    "absorbed_by": absorber.get("cluster_name"),
                })
            else:
                resolved_clusters.append({
                    **cluster,
                    "relation": "fallback_candidate",
                    "absorbed_by": None,
                })

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


def _find_absorbing_cluster(cluster: dict, primary_clusters: list[dict]):
    for primary in primary_clusters:
        if primary is cluster:
            continue

        if _clusters_overlap(cluster, primary):
            return primary

    return None


def _clusters_overlap(a: dict, b: dict) -> bool:
    a_start = a.get("attack_start")
    a_end = a.get("attack_end")
    b_start = b.get("attack_start")
    b_end = b.get("attack_end")

    if None in (a_start, a_end, b_start, b_end):
        return False

    return a_start <= b_end and b_start <= a_end