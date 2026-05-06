def build_attack_findings(clusters_by_ip, rules):
    attacks_by_ip = {}

    attack_rules = rules.get("attacks", {})

    for ip, clusters in clusters_by_ip.items():
        attacks = []

        for cluster in clusters:
            relation = cluster.get("relation")

            if relation == "absorbed":
                continue

            matched = False

            for attack_type, config in attack_rules.items():
                if not config.get("enabled", True):
                    continue

                if config.get("fallback"):
                    continue

                if cluster["cluster_name"] != config.get("source_cluster"):
                    continue

                attacks.append(
                    _build_attack(
                        ip=ip,
                        attack_type=attack_type,
                        cluster=cluster,
                        config=config,
                    )
                )

                matched = True

            if not matched and relation == "fallback_candidate":
                fallback_attack = _build_fallback_attack(
                    ip=ip,
                    cluster=cluster,
                    attack_rules=attack_rules,
                )

                if fallback_attack:
                    attacks.append(fallback_attack)

        attacks_by_ip[ip] = attacks

    return attacks_by_ip


def _build_attack(ip, attack_type, cluster, config):
    return {
        "source_ip": ip,
        "attack_type": attack_type,
        "intensity": cluster["intensity"],
        "confidence": cluster["confidence"],
        "attack_start": cluster["attack_start"],
        "attack_end": cluster["attack_end"],
        "base_score": config.get("base_score", 1),
        "score_cap_ratio_override": config.get("score_cap_ratio_override"),
        "intensity_cap_override": config.get("intensity_cap_override"),
        "evidence_signals": cluster["evidence_signals"],
    }


def _build_fallback_attack(ip, cluster, attack_rules):
    fallback_config = _get_fallback_config(attack_rules)

    if not fallback_config:
        return None

    return {
        "source_ip": ip,
        "attack_type": fallback_config["attack_type"],
        "intensity": cluster["intensity"],
        "confidence": cluster["confidence"],
        "attack_start": cluster["attack_start"],
        "attack_end": cluster["attack_end"],
        "base_score": fallback_config["config"].get("base_score", 1),
        "score_cap_ratio_override": fallback_config["config"].get("score_cap_ratio_override"),
        "intensity_cap_override": fallback_config["config"].get("intensity_cap_override"),
        "evidence_signals": cluster["evidence_signals"],
    }


def _get_fallback_config(attack_rules):
    for attack_type, config in attack_rules.items():
        if not config.get("enabled", True):
            continue

        if not config.get("fallback"):
            continue

        return {
            "attack_type": attack_type,
            "config": config,
        }

    return None