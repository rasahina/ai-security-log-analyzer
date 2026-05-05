def build_attack_findings(clusters_by_ip, rules):
    attacks_by_ip = {}

    attack_rules = rules.get("attacks", {})

    for ip, clusters in clusters_by_ip.items():
        attacks = []

        for cluster in clusters:
            for attack_type, config in attack_rules.items():
                if not config.get("enabled", True):
                    continue

                if config.get("fallback"):
                    continue

                if cluster["cluster_name"] != config.get("source_cluster"):
                    continue

                attacks.append({
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
                })

        attacks_by_ip[ip] = attacks

    return attacks_by_ip